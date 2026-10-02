use std::{fmt, fs, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    pub upstream: Upstream,
    #[serde(default)]
    pub process_patterns: Vec<String>,
    #[serde(default)]
    pub bypass_patterns: Vec<String>,

    /// 哪些**目标端口**要进入透明重定向：`"all"`（默认）或 `"80,443"` 这样的列表。
    ///
    /// 只有 macOS 后端用得到。Windows 那边由 NetFilter 驱动内部做端口判断，
    /// 这里保留字段只是为了让同一份 JSON 在两个平台上都能解析。
    #[serde(default)]
    #[cfg_attr(windows, allow(dead_code))]
    pub redirect_ports: RedirectPorts,

    /// 是否把 IPv6 的 TCP 连接也纳入透明重定向（默认开）。
    ///
    /// 关掉它就是**静默泄漏**：目标应用一旦走 IPv6（比如目标域名有 AAAA 记录），
    /// 连接会绕过代理直连出去。留这个开关只是为了在 IPv6 出问题时能快速降级排查，
    /// 正常部署应当保持开启。
    #[serde(default = "default_redirect_ipv6")]
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub redirect_ipv6: bool,

    /// Windows 专用：放置 `Redirector.bin` / `nfapi.dll` / `nfdriver.sys` 的目录。
    #[serde(default = "default_redirector_dir")]
    #[cfg_attr(not(windows), allow(dead_code))]
    pub redirector_dir: PathBuf,

    /// Windows 专用：内核驱动服务名。
    #[serde(default = "default_driver_name")]
    #[cfg_attr(not(windows), allow(dead_code))]
    pub driver_name: String,

    #[serde(default = "default_sniff_timeout_ms")]
    pub sniff_timeout_ms: u64,
    #[serde(default = "default_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_max_sniff_bytes")]
    pub max_sniff_bytes: usize,
    #[serde(default = "default_require_hostname")]
    pub require_hostname: bool,
    /// Enable per-process UDP forwarding through SOCKS5 UDP ASSOCIATE.
    #[serde(default = "default_redirect_udp")]
    pub redirect_udp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Upstream {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

/// 透明重定向覆盖哪些目标端口。
///
/// 在 JSON 里写成字符串：`"all"` 或 `"80,443"`。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub enum RedirectPorts {
    /// 所有 TCP 端口。
    ///
    /// 注意：因为 pf 无法按进程匹配，`all` 意味着**整机所有非 root 的 TCP 连接**
    /// 都会先经过本进程，再由本进程按可执行路径决定是代理还是直连。这既带来
    /// 一点延迟，也意味着本进程异常退出时必须立刻撤销 pf 规则（见 `pf` 模块的
    /// 死人开关），否则整机 TCP 会全部失败。
    #[default]
    All,
    /// 明确列出的端口集合。
    List(Vec<u16>),
}

impl RedirectPorts {
    pub fn parse(value: &str) -> Result<Self> {
        let trimmed = value.trim();
        if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("all") {
            return Ok(Self::All);
        }
        let mut ports: Vec<u16> = Vec::new();
        for piece in trimmed.split(',') {
            let piece = piece.trim();
            if piece.is_empty() {
                continue;
            }
            let port: u16 = piece
                .parse()
                .with_context(|| format!("invalid port {piece:?} in redirectPorts"))?;
            if port == 0 {
                bail!("redirectPorts must not contain port 0");
            }
            if !ports.contains(&port) {
                ports.push(port);
            }
        }
        if ports.is_empty() {
            bail!("redirectPorts must be \"all\" or a non-empty port list");
        }
        ports.sort_unstable();
        Ok(Self::List(ports))
    }

    /// 这个端口是否会被重定向。
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    pub fn covers(&self, port: u16) -> bool {
        match self {
            Self::All => true,
            Self::List(ports) => ports.contains(&port),
        }
    }
}

impl fmt::Display for RedirectPorts {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => formatter.write_str("all"),
            Self::List(ports) => {
                let list = ports
                    .iter()
                    .map(u16::to_string)
                    .collect::<Vec<_>>()
                    .join(",");
                formatter.write_str(&list)
            }
        }
    }
}

impl TryFrom<String> for RedirectPorts {
    type Error = anyhow::Error;

    fn try_from(value: String) -> Result<Self> {
        Self::parse(&value)
    }
}

impl From<RedirectPorts> for String {
    fn from(value: RedirectPorts) -> Self {
        value.to_string()
    }
}

impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let bytes =
            fs::read(path).with_context(|| format!("failed to read config {}", path.display()))?;
        let mut config: Self = serde_json::from_slice(&bytes)
            .with_context(|| format!("failed to parse config {}", path.display()))?;
        if config.redirector_dir.is_relative() {
            let base = path.parent().unwrap_or_else(|| std::path::Path::new("."));
            config.redirector_dir = base.join(&config.redirector_dir);
        }
        config.validate_bridge()?;
        Ok(config)
    }

    pub fn validate_bridge(&self) -> Result<()> {
        if !self.listen.ip().is_loopback() {
            bail!(
                "listen must be a loopback address; refusing to expose an unauthenticated SOCKS listener"
            );
        }
        if self.listen.port() == 0 {
            bail!("listen port must not be zero");
        }
        if self.upstream.host.trim().is_empty() || self.upstream.port == 0 {
            bail!("upstream host and port are required");
        }
        if self.sniff_timeout_ms == 0 || self.connect_timeout_ms == 0 {
            bail!("timeouts must be greater than zero");
        }
        if !(1024..=1024 * 1024).contains(&self.max_sniff_bytes) {
            bail!("maxSniffBytes must be between 1024 and 1048576");
        }
        match (&self.upstream.username, &self.upstream.password) {
            (Some(user), Some(password)) => {
                if user.is_empty() || password.is_empty() {
                    bail!("SOCKS5 username and password must not be empty");
                }
                if user.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
                    bail!("SOCKS5 username and password must each fit in 255 bytes");
                }
            }
            (None, None) => {}
            _ => bail!("upstream username and password must be supplied together"),
        }
        Ok(())
    }

    /// 校验「重定向后端」这一侧。两个平台的后端完全不同，所以分开校验。
    pub fn validate_redirector(&self) -> Result<()> {
        if self.process_patterns.is_empty() {
            bail!("processPatterns must contain at least one process rule");
        }
        self.validate_redirector_settings()
    }

    /// The menu bar editor may save an inactive profile with no selected apps.
    /// Starting interception still requires validate_redirector above.
    pub fn validate_redirector_settings(&self) -> Result<()> {
        #[cfg(windows)]
        {
            if self.driver_name.trim().is_empty() {
                bail!("driverName must not be empty");
            }
            if self.driver_name != "netfilter2" {
                bail!("this redirector runtime requires driverName to be 'netfilter2'");
            }
            crate::native::verify_bundle(&self.redirector_dir)?;
        }

        #[cfg(target_os = "macos")]
        {
            if !self.listen.is_ipv4() {
                bail!(
                    "macOS transparent redirection requires an IPv4 loopback listen address; \
                     redirectIpv6 adds a separate [::1] listener on the same port"
                );
            }
            if let RedirectPorts::List(ports) = &self.redirect_ports
                && ports.is_empty()
            {
                bail!("redirectPorts must be \"all\" or a non-empty port list");
            }
            // 规则模式先编译一遍，别等真接到连接才发现正则写错。
            crate::rules::RuleSet::compile(&self.process_patterns, &self.bypass_patterns)?;
        }

        Ok(())
    }

    pub fn example() -> Self {
        #[cfg(windows)]
        let (process_patterns, bypass_patterns) = (
            vec!["curl.exe".to_string()],
            vec![r"(?i)(^|[/\\])procsocks\.exe$".to_string()],
        );
        #[cfg(not(windows))]
        let (process_patterns, bypass_patterns) = (
            vec![
                "/usr/bin/curl".to_string(),
                "/Applications/ChatGPT.app".to_string(),
            ],
            vec!["(^|/)procsocks$".to_string()],
        );

        Self {
            listen: default_listen(),
            upstream: Upstream {
                host: "127.0.0.1".to_string(),
                port: 7890,
                username: None,
                password: None,
            },
            process_patterns,
            bypass_patterns,
            redirect_ports: RedirectPorts::default(),
            redirect_ipv6: default_redirect_ipv6(),
            redirector_dir: default_redirector_dir(),
            driver_name: default_driver_name(),
            sniff_timeout_ms: default_sniff_timeout_ms(),
            connect_timeout_ms: default_connect_timeout_ms(),
            max_sniff_bytes: default_max_sniff_bytes(),
            require_hostname: default_require_hostname(),
            redirect_udp: default_redirect_udp(),
        }
    }
}

fn default_listen() -> SocketAddr {
    "127.0.0.1:7891".parse().expect("static socket address")
}

fn default_redirector_dir() -> PathBuf {
    PathBuf::from("driver")
}

fn default_driver_name() -> String {
    "netfilter2".to_string()
}

fn default_sniff_timeout_ms() -> u64 {
    2_000
}

fn default_connect_timeout_ms() -> u64 {
    15_000
}

fn default_max_sniff_bytes() -> usize {
    64 * 1024
}

fn default_require_hostname() -> bool {
    true
}

fn default_redirect_ipv6() -> bool {
    true
}

fn default_redirect_udp() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::{Config, RedirectPorts};

    #[test]
    fn accepts_custom_upstream_socks_endpoint() {
        let config: Config = serde_json::from_str(
            r#"{
                "upstream": {
                    "host": "proxy.example.invalid",
                    "port": 1080,
                    "username": "example-user",
                    "password": "example-password"
                }
            }"#,
        )
        .expect("custom upstream config should parse");

        config
            .validate_bridge()
            .expect("custom upstream config should validate");
        assert_eq!(config.upstream.host, "proxy.example.invalid");
        assert_eq!(config.upstream.port, 1080);
        assert_eq!(config.upstream.username.as_deref(), Some("example-user"));
        assert_eq!(
            config.upstream.password.as_deref(),
            Some("example-password")
        );
    }

    #[test]
    fn rejects_partial_upstream_credentials() {
        let config: Config = serde_json::from_str(
            r#"{
                "upstream": {
                    "host": "127.0.0.1",
                    "port": 7890,
                    "username": "example-user"
                }
            }"#,
        )
        .expect("config should parse before validation");

        let error = config
            .validate_bridge()
            .expect_err("partial credentials must be rejected");
        assert!(
            error
                .to_string()
                .contains("username and password must be supplied together")
        );
    }

    #[test]
    fn rejects_empty_or_oversized_upstream_credentials() {
        for (username, password) in [
            (String::new(), "password".to_string()),
            ("user".to_string(), String::new()),
            ("ü".repeat(128), "password".to_string()),
            ("user".to_string(), "x".repeat(256)),
        ] {
            let mut config = Config::example();
            config.upstream.username = Some(username);
            config.upstream.password = Some(password);
            assert!(config.validate_bridge().is_err());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ipv6_listen_is_valid_for_bridge_but_not_transparent_redirection() {
        let config = Config {
            listen: "[::1]:7891".parse().unwrap(),
            ..Config::example()
        };
        config.validate_bridge().unwrap();
        let error = config.validate_redirector().unwrap_err();
        assert!(error.to_string().contains("IPv4 loopback"));
    }

    #[test]
    fn ipv6_can_be_disabled_explicitly() {
        let mut config = Config::example();
        config.redirect_ipv6 = false;
        let json = serde_json::to_string(&config).unwrap();
        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert!(!parsed.redirect_ipv6);
    }

    #[test]
    fn redirect_ports_defaults_to_all() {
        let config: Config =
            serde_json::from_str(r#"{ "upstream": { "host": "127.0.0.1", "port": 7890 } }"#)
                .expect("minimal config should parse");
        assert_eq!(config.redirect_ports, RedirectPorts::All);
        assert!(config.redirect_ports.covers(22));
        assert!(config.redirect_ports.covers(65535));
        // IPv6 默认必须开：关掉就是静默泄漏。
        assert!(config.redirect_ipv6);
    }

    #[test]
    fn redirect_ports_accepts_a_string_list() {
        let config: Config = serde_json::from_str(
            r#"{
                "upstream": { "host": "127.0.0.1", "port": 7890 },
                "redirectPorts": "443,80,443"
            }"#,
        )
        .expect("port list should parse");

        assert_eq!(config.redirect_ports, RedirectPorts::List(vec![80, 443]));
        assert!(config.redirect_ports.covers(80));
        assert!(!config.redirect_ports.covers(22));
        assert_eq!(config.redirect_ports.to_string(), "80,443");
    }

    #[test]
    fn redirect_ports_accepts_the_keyword_all() {
        assert_eq!(RedirectPorts::parse("all").unwrap(), RedirectPorts::All);
        assert_eq!(RedirectPorts::parse("ALL").unwrap(), RedirectPorts::All);
        assert_eq!(RedirectPorts::parse("").unwrap(), RedirectPorts::All);
    }

    #[test]
    fn redirect_ports_rejects_junk() {
        assert!(RedirectPorts::parse("http").is_err());
        assert!(RedirectPorts::parse("0").is_err());
        assert!(RedirectPorts::parse("70000").is_err());
        assert!(RedirectPorts::parse(",").is_err());
    }

    #[test]
    fn redirect_ports_round_trips_through_json() {
        let config = Config {
            redirect_ports: RedirectPorts::List(vec![443, 8443]),
            ..Config::example()
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains(r#""redirectPorts":"443,8443""#), "{json}");
        let parsed: Config = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.redirect_ports, RedirectPorts::List(vec![443, 8443]));
    }
}
