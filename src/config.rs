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
    pub pac: String,
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
                pac: String::new(),
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
                method: AuthMethod::Auto,
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

pub fn config_path() -> PathBuf {
    dirs::config_dir()
        .unwrap_or_else(|| PathBuf::from("~/.config"))
        .join("proxypass")
        .join("proxypass.toml")
}

pub fn load() -> Result<Config> {
    let path = config_path();
    if !path.exists() {
        let cfg = Config::default();
        save(&cfg)?;
        return Ok(cfg);
    }
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
