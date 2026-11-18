use std::{fs, net::SocketAddr, path::PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    #[serde(default = "default_listen")]
    pub listen: SocketAddr,
    /// Single upstream (legacy form). Mutually exclusive-ish with `upstreams`:
    /// when `upstreams` is non-empty it takes priority.
    #[serde(default)]
    pub upstream: Option<Upstream>,
    /// Ordered failover list. Each entry is tried in order until one connects.
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default)]
    pub process_patterns: Vec<String>,
    #[serde(default)]
    pub bypass_patterns: Vec<String>,
    #[serde(default = "default_redirector_dir")]
    pub redirector_dir: PathBuf,
    #[serde(default = "default_driver_name")]
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

impl Config {
    /// Effective failover list: `upstreams` when provided, else the legacy
    /// single `upstream`. Always non-empty after successful validation.
    pub fn effective_upstreams(&self) -> &[Upstream] {
        if !self.upstreams.is_empty() {
            &self.upstreams
        } else if let Some(up) = self.upstream.as_ref() {
            std::slice::from_ref(up)
        } else {
            &[]
        }
    }

    /// First effective upstream, used for UDP ASSOCIATE and shared code.
    pub fn primary_upstream(&self) -> &Upstream {
        self.effective_upstreams()
            .first()
            .expect("validated configs always have at least one upstream")
    }

    /// Test-only hook shared with `shared/udp.rs` tests: rewrites the port of
    /// the first effective upstream.
    pub fn set_upstream_port_for_test(&mut self, port: u16) {
        if !self.upstreams.is_empty() {
            self.upstreams[0].port = port;
        } else if let Some(up) = self.upstream.as_mut() {
            up.port = port;
        }
    }

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
        if self.effective_upstreams().is_empty() {
            bail!("at least one upstream (or upstreams list) is required");
        }
        for up in self.effective_upstreams() {
            if up.host.trim().is_empty() || up.port == 0 {
                bail!("upstream host and port are required");
            }
        }
        if self.sniff_timeout_ms == 0 || self.connect_timeout_ms == 0 {
            bail!("timeouts must be greater than zero");
        }
        if !(1024..=1024 * 1024).contains(&self.max_sniff_bytes) {
            bail!("maxSniffBytes must be between 1024 and 1048576");
        }
        for up in self.effective_upstreams() {
            match (&up.username, &up.password) {
                (Some(user), Some(password)) => {
                    if user.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
                        bail!("SOCKS5 username and password must each fit in 255 bytes");
                    }
                }
                (None, None) => {}
                _ => bail!("upstream username and password must be supplied together"),
            }
        }
        Ok(())
    }

    pub fn validate_redirector(&self) -> Result<()> {
        if self.process_patterns.is_empty() {
            bail!("processPatterns must contain at least one process rule");
        }
        if self.driver_name.trim().is_empty() {
            bail!("driverName must not be empty");
        }
        if self.driver_name != "netfilter2" {
            bail!("this redirector runtime requires driverName to be 'netfilter2'");
        }
        crate::native::verify_bundle(&self.redirector_dir)?;
        Ok(())
    }

    pub fn example() -> Self {
        Self {
            listen: default_listen(),
            upstream: Some(Upstream {
                host: "127.0.0.1".to_string(),
                port: 7890,
                username: None,
                password: None,
            }),
            upstreams: vec![
                Upstream {
                    host: "127.0.0.1".to_string(),
                    port: 7890,
                    username: None,
                    password: None,
                },
                Upstream {
                    host: "192.168.0.112".to_string(),
                    port: 7890,
                    username: None,
                    password: None,
                },
            ],
            process_patterns: vec!["curl.exe".to_string()],
            bypass_patterns: vec!["procsocks.exe".to_string()],
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

fn default_redirect_udp() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::Config;

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
        let upstream = config.upstream.as_ref().expect("legacy upstream present");
        assert_eq!(upstream.host, "proxy.example.invalid");
        assert_eq!(upstream.port, 1080);
        assert_eq!(upstream.username.as_deref(), Some("example-user"));
        assert_eq!(upstream.password.as_deref(), Some("example-password"));
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
    fn rejects_partial_credentials_inside_upstreams_list() {
        let config: Config = serde_json::from_str(
            r#"{
                "upstreams": [
                    {"host": "192.168.0.112", "port": 7890, "username": "user"}
                ]
            }"#,
        )
        .expect("list config should parse before validation");

        let error = config
            .validate_bridge()
            .expect_err("partial credentials in list must be rejected");
        assert!(
            error
                .to_string()
                .contains("username and password must be supplied together")
        );
    }

    #[test]
    fn accepts_upstreams_failover_list() {
        let config: Config = serde_json::from_str(
            r#"{
                "upstreams": [
                    {"host": "192.168.0.112", "port": 7890},
                    {"host": "127.0.0.1", "port": 7890}
                ]
            }"#,
        )
        .expect("upstreams list config should parse");

        config
            .validate_bridge()
            .expect("upstreams list config should validate");
        assert_eq!(config.effective_upstreams().len(), 2);
        assert_eq!(config.effective_upstreams()[0].host, "192.168.0.112");
        assert_eq!(config.effective_upstreams()[1].port, 7890);
    }

    #[test]
    fn upstreams_list_takes_priority_over_legacy_field() {
        let config: Config = serde_json::from_str(
            r#"{
                "upstream": {"host": "10.0.0.1", "port": 1080},
                "upstreams": [{"host": "10.0.0.2", "port": 1080}]
            }"#,
        )
        .expect("mixed config should parse");

        assert_eq!(config.effective_upstreams().len(), 1);
        assert_eq!(config.effective_upstreams()[0].host, "10.0.0.2");
    }

    #[test]
    fn rejects_config_without_any_upstream() {
        let config: Config = serde_json::from_str(r#"{}"#)
            .expect("empty config should parse before validation");

        let error = config
            .validate_bridge()
            .expect_err("missing upstream must be rejected");
        assert!(error.to_string().contains("at least one upstream"));
    }
}
