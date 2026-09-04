use std::{fs, net::SocketAddr, path::PathBuf};

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
                if user.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
                    bail!("SOCKS5 username and password must each fit in 255 bytes");
                }
            }
            (None, None) => {}
            _ => bail!("upstream username and password must be supplied together"),
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
            upstream: Upstream {
                host: "127.0.0.1".to_string(),
                port: 7890,
                username: None,
                password: None,
            },
            process_patterns: vec!["curl.exe".to_string()],
            bypass_patterns: vec!["procsocks.exe".to_string()],
            redirector_dir: default_redirector_dir(),
            driver_name: default_driver_name(),
            sniff_timeout_ms: default_sniff_timeout_ms(),
            connect_timeout_ms: default_connect_timeout_ms(),
            max_sniff_bytes: default_max_sniff_bytes(),
            require_hostname: default_require_hostname(),
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
