/// Windows auth stub — libgssapi doesn't support Windows (use SSPI instead).
/// This module provides the same public API as auth.rs so the rest of the
/// code compiles, but Negotiate always returns an error. Basic auth still
/// works via OS keychain credentials.
use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub enum AuthScheme {
    Negotiate,
    Basic,
    None,
}

/// Dummy context — never constructed on Windows since negotiate_init fails.
pub struct NegotiateContext;

pub fn detect_scheme(proxy_authenticate: &str) -> AuthScheme {
    let lower = proxy_authenticate.to_lowercase();
    if lower.contains("negotiate") || lower.contains("kerberos") {
        AuthScheme::Negotiate
    } else if lower.contains("basic") {
        AuthScheme::Basic
    } else {
        AuthScheme::None
    }
}

pub fn negotiate_init(_proxy_host: &str, _proxy_port: u16) -> Result<(String, NegotiateContext)> {
    bail!(
        "Negotiate/Kerberos auth is not supported on Windows. \
         libgssapi does not support Windows — use SSPI or configure Basic auth instead."
    )
}

pub fn negotiate_step(_ctx: &mut NegotiateContext, _challenge: &[u8]) -> Result<Option<String>> {
    bail!("Negotiate step called but negotiate_init should have failed on Windows")
}

pub fn basic_token(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    format!("Basic {}", BASE64.encode(credentials.as_bytes()))
}

// ── SPNEGO token cache ─────────────────────────────────────────────────────────

pub(crate) struct SpnegoCache {
    token: Mutex<Option<(String, Instant)>>,
    ttl: Duration,
}

impl SpnegoCache {
    fn new() -> Self {
        Self {
            token: Mutex::new(None),
            ttl: Duration::from_secs(3600),
        }
    }

    pub fn get(&self) -> Option<String> {
        let guard = self.token.lock().unwrap();
        guard.as_ref().and_then(|(t, ts)| {
            if ts.elapsed() < self.ttl {
                Some(t.clone())
            } else {
                None
            }
        })
    }

    pub fn set(&self, token: String) {
        *self.token.lock().unwrap() = Some((token, Instant::now()));
    }

    pub fn clear(&self) {
        *self.token.lock().unwrap() = None;
    }
}

pub fn spnego_cache() -> &'static SpnegoCache {
    static CACHE: OnceLock<SpnegoCache> = OnceLock::new();
    CACHE.get_or_init(|| SpnegoCache::new())
}

// ── Auth header helpers ────────────────────────────────────────────────────────

pub fn extract_proxy_authenticate(response: &str) -> String {
    response
        .lines()
        .find(|l| l.to_lowercase().starts_with("proxy-authenticate:"))
        .map(|l| l[19..].trim().to_string())
        .unwrap_or_default()
}

pub fn extract_negotiate_challenge(header: &str) -> String {
    let lower = header.to_lowercase();
    if lower.starts_with("negotiate") {
        header.get(10..).map(|s| s.trim().to_string()).unwrap_or_default()
    } else if lower.starts_with("kerberos") {
        header.get(8..).map(|s| s.trim().to_string()).unwrap_or_default()
    } else {
        String::new()
    }
}

pub fn resolve_basic_credentials(
    username: Option<&str>,
    get_password: impl FnOnce(&str) -> anyhow::Result<String>,
) -> anyhow::Result<(String, String)> {
    match username {
        Some(user) => match get_password(user) {
            Ok(pass) => Ok((user.to_string(), pass)),
            Err(e) => anyhow::bail!("No keychain password for {}: {}", user, e),
        },
        None => anyhow::bail!("No username configured"),
    }
}

/// Resolve Basic credentials from username + password string directly.
/// Use when the password was already resolved (e.g., via async keychain access).
pub fn resolve_basic_credentials_from_password(
    username: Option<&str>,
    password: &str,
) -> anyhow::Result<(String, String)> {
    match username {
        Some(user) => Ok((user.to_string(), password.to_string())),
        None => anyhow::bail!("No username configured"),
    }
}

pub fn build_forward_auth_header(
    _proxy_authenticate: &str,
    _upstream_host: &str,
    _upstream_port: u16,
    username: Option<&str>,
    get_password: impl FnOnce(&str) -> anyhow::Result<String>,
) -> anyhow::Result<Option<String>> {
    // Negotiate not supported on Windows — try Basic
    Ok(resolve_basic_auth(username, get_password))
}

fn resolve_basic_auth(
    username: Option<&str>,
    get_password: impl FnOnce(&str) -> anyhow::Result<String>,
) -> Option<String> {
    resolve_basic_credentials(username, get_password)
        .ok()
        .map(|(u, p)| basic_token(&u, &p))
}

pub fn negotiate_round2(
    _proxy_authenticate: &str,
    _upstream_host: &str,
    _upstream_port: u16,
) -> anyhow::Result<Option<String>> {
    Ok(None)
}
