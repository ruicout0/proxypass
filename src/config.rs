use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    pub proxy: ProxyConfig,
    pub auth: AuthConfig,
    pub pac: PacConfig,
    pub log: LogConfig,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ProxyConfig {
    /// PAC URL (mutually exclusive with proxy)
    pub pac: Option<String>,
    /// Direct upstream proxy host:port (mutually exclusive with pac)
    pub proxy: Option<String>,
    pub port: u16,
    pub listen: String,
    pub no_proxy: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AuthConfig {
    pub username: Option<String>,
    pub method: AuthMethod,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMethod {
    Auto,
    Negotiate,
    Ntlm,
    Basic,
    None,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PacConfig {
    pub cache_ttl: u64,
    pub reload_on_network_change: bool,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LogConfig {
    pub level: String,
    pub file: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            proxy: ProxyConfig {
                pac: None,
                proxy: None,
                port: 3128,
                listen: "127.0.0.1".to_string(),
                no_proxy: vec![
                    "localhost".to_string(),
                    "127.0.0.1".to_string(),
                    "*.local".to_string(),
                ],
            },
            auth: AuthConfig {
                username: None,
                method: AuthMethod::Negotiate,
            },
            pac: PacConfig {
                cache_ttl: 300,
                reload_on_network_change: true,
            },
            log: LogConfig {
                level: "info".to_string(),
                file: Some("/tmp/proxypass.log".to_string()),
            },
        }
    }
}

/// Returns the path to the config file.
///
/// On macOS, uses `~/Library/Application Support/proxypass/proxypass.toml`
/// to follow the platform convention. On other platforms, uses
/// `$XDG_CONFIG_HOME/proxypass/proxypass.toml` (typically `~/.config/…`).
pub fn config_path() -> PathBuf {
    let base = if cfg!(target_os = "macos") {
        dirs::data_dir()
    } else {
        dirs::config_dir()
    };
    base.unwrap_or_else(|| {
        let home = std::env::var("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|_| PathBuf::from("~"));
        if cfg!(target_os = "macos") {
            home.join("Library/Application Support")
        } else {
            home.join(".config")
        }
    })
    .join("proxypass")
    .join("proxypass.toml")
}

pub fn load() -> Result<Config> {
    let path = config_path();
    let content = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config: {}", path.display()))?;
    toml::from_str(&content)
        .with_context(|| format!("Failed to parse config: {}", path.display()))
}

pub fn save(cfg: &Config) -> Result<()> {
    let path = config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let content = toml::to_string_pretty(cfg)?;
    std::fs::write(&path, content)?;
    Ok(())
}
