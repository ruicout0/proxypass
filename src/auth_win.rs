/// Windows auth stub — libgssapi doesn't support Windows (use SSPI instead).
/// This module provides the same public API as auth.rs so the rest of the
/// code compiles, but Negotiate always returns an error. Basic auth still
/// works via OS keychain credentials.
use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

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