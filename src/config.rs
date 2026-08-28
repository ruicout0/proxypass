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
    let toml_str = toml::to_string_pretty(cfg)?;
    let content = format_toml_literal_strings(&toml_str);
    std::fs::write(&path, content)?;
    Ok(())
}

/// Formats TOML string values with single quotes (literal strings) where safe.
/// Literal strings in TOML (`'...'`) do not interpret backslashes as escape sequences,
/// preventing syntax errors when Windows domain usernames (e.g. `DOMAIN\user`) are used.
pub fn format_toml_literal_strings(toml_str: &str) -> String {
    let mut out = String::with_capacity(toml_str.len());
    for line in toml_str.lines() {
        let trimmed = line.trim_start();
        // Skip comments and table headers
        if trimmed.starts_with('#') || (trimmed.starts_with('[') && trimmed.ends_with(']')) {
            out.push_str(line);
            out.push('\n');
            continue;
        }

        let mut result = String::new();
        let chars: Vec<char> = line.chars().collect();
        let mut idx = 0;

        while idx < chars.len() {
            if chars[idx] == '"' {
                // Look ahead for closing double quote
                let mut end = idx + 1;
                let mut escaped = false;
                let mut raw_val = String::new();
                let mut valid_literal = true;

                while end < chars.len() {
                    let ch = chars[end];
                    if escaped {
                        match ch {
                            '"' => raw_val.push('"'),
                            '\\' => raw_val.push('\\'),
                            'n' => raw_val.push('\n'),
                            'r' => raw_val.push('\r'),
                            't' => raw_val.push('\t'),
                            other => {
                                raw_val.push('\\');
                                raw_val.push(other);
                            }
                        }
                        escaped = false;
                    } else if ch == '\\' {
                        escaped = true;
                    } else if ch == '"' {
                        break;
                    } else {
                        if ch == '\'' || ch == '\n' || ch == '\r' {
                            valid_literal = false;
                        }
                        raw_val.push(ch);
                    }
                    end += 1;
                }

                if end < chars.len() && chars[end] == '"' && valid_literal && !raw_val.contains('\n') {
                    result.push('\'');
                    result.push_str(&raw_val);
                    result.push('\'');
                    idx = end + 1;
                    continue;
                }
            }
            result.push(chars[idx]);
            idx += 1;
        }

        out.push_str(&result);
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_toml_literal_strings() {
        let mut cfg = Config::default();
        cfg.auth.username = Some(r"MUC\q632688".to_string());
        cfg.proxy.pac = Some("http://muc.proxy-pac.bmwgroup.net/proxy.pac".to_string());
        let toml_str = toml::to_string_pretty(&cfg).unwrap();
        let formatted = format_toml_literal_strings(&toml_str);

        assert!(formatted.contains("username = 'MUC\\q632688'"));
        assert!(formatted.contains("pac = 'http://muc.proxy-pac.bmwgroup.net/proxy.pac'"));
        assert!(formatted.contains("listen = '127.0.0.1'"));
        assert!(formatted.contains("'localhost'"));

        // Roundtrip verification: parse the generated TOML back into Config
        let parsed: Config = toml::from_str(&formatted).expect("Failed to parse single-quoted TOML");
        assert_eq!(parsed.auth.username, Some(r"MUC\q632688".to_string()));
        assert_eq!(parsed.proxy.pac, Some("http://muc.proxy-pac.bmwgroup.net/proxy.pac".to_string()));
        assert_eq!(parsed.proxy.port, 3128);
        assert_eq!(parsed.proxy.listen, "127.0.0.1");
        assert_eq!(parsed.proxy.no_proxy, vec!["localhost", "127.0.0.1", "*.local"]);
        assert_eq!(parsed.auth.method, AuthMethod::Negotiate);
    }
}
