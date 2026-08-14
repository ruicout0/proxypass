use anyhow::{bail, Result};
use libgssapi::{
    context::{ClientCtx, CtxFlags},
    name::Name,
    oid::{Oid, GSS_MECH_KRB5, GSS_MECH_SPNEGO, GSS_NT_HOSTBASED_SERVICE},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub enum AuthScheme {
    Negotiate,
    Basic,
    None,
}

/// Tracks a multi-step Negotiate handshake. Each 407 response may carry a
/// challenge token that must be fed back into the GSSAPI context.
pub struct NegotiateContext {
    ctx: ClientCtx,
}

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

/// Try to determine which mechanism works. macOS Heimdal doesn't support
/// SPNEGO, so we fall back to raw Kerberos which works with most corporate
/// proxies that accept RFC 4559 Negotiate (Kerberos, not SPNEGO).
///
/// Result is cached — GSS mechanism discovery is expensive and the answer
/// won't change during the process lifetime.
fn select_mech() -> &'static Result<(Oid<'static>, &'static str)> {
    static MECH: OnceLock<Result<(Oid<'static>, &'static str)>> = OnceLock::new();
    MECH.get_or_init(|| {
        // Try SPNEGO first — test with a real gss_init_sec_context attempt.
        // Cred::acquire can succeed on macOS Heimdal even though
        // gss_init_sec_context will fail with GSS_S_BAD_MECH.
        let name = Name::new(b"HTTP@localhost", Some(GSS_NT_HOSTBASED_SERVICE));
        if let Ok(name) = name {
            let mut spnego_ctx = ClientCtx::new(
                None, // let GSSAPI pick the default credential
                name,
                CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG,
                Some(GSS_MECH_SPNEGO.clone()),
            );
            if spnego_ctx.step(None, None).is_ok() {
                return Ok((GSS_MECH_SPNEGO.clone(), "SPNEGO"));
            }
        }
        // Try raw Kerberos — gss_init_sec_context with None cred lets
        // GSSAPI pick the default credential from the system cache.
        let name = Name::new(b"HTTP@localhost", Some(GSS_NT_HOSTBASED_SERVICE));
        if let Ok(name) = name {
            let mut krb5_ctx = ClientCtx::new(
                None,
                name,
                CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG,
                Some(GSS_MECH_KRB5.clone()),
            );
            if krb5_ctx.step(None, None).is_ok() {
                return Ok((GSS_MECH_KRB5.clone(), "Kerberos"));
            }
        }
        Err(anyhow::anyhow!(
            "No GSSAPI mechanism available: both SPNEGO and Kerberos gss_init_sec_context failed. \
             Check that krb5.conf is configured and a valid TGT is present (klist)."
        ))
    })
}

/// Build a fresh Negotiate context and return the initial token.
/// Call `negotiate_step()` for subsequent challenge/response rounds.
pub fn negotiate_init(proxy_host: &str, proxy_port: u16) -> Result<(String, NegotiateContext)> {
    let service_name = format!("HTTP@{}:{}", proxy_host, proxy_port);
    let name = Name::new(service_name.as_bytes(), Some(GSS_NT_HOSTBASED_SERVICE))
        .map_err(|e| anyhow::anyhow!("GSSAPI name error: {:?}", e))?;

    let (mech_ref, mech_name) = select_mech().as_ref().map_err(|e| anyhow::anyhow!("GSSAPI credential error: {}", e))?;
    let mech = mech_ref.clone();
    tracing::info!("Using GSS mechanism: {}", mech_name);

    let mut ctx = ClientCtx::new(
        None,
        name,
        CtxFlags::GSS_C_MUTUAL_FLAG | CtxFlags::GSS_C_SEQUENCE_FLAG,
        Some(mech),
    );

    let token = ctx.step(None, None)
        .map_err(|e| anyhow::anyhow!("GSSAPI step error ({}): {:?}", mech_name, e))?;

    match token {
        Some(t) => Ok((
            format!("Negotiate {}", BASE64.encode(&*t)),
            NegotiateContext { ctx },
        )),
        None => bail!("GSSAPI returned no token ({})", mech_name),
    }
}

/// Feed a server challenge token into the ongoing SPNEGO handshake.
/// Returns `Some(auth_header)` if another round is needed, or `None` when
/// the handshake is complete (mutual auth succeeded).
pub fn negotiate_step(ctx: &mut NegotiateContext, challenge: &[u8]) -> Result<Option<String>> {
    let token = ctx.ctx.step(Some(challenge), None)
        .map_err(|e| anyhow::anyhow!("GSSAPI step error: {:?}", e))?;

    match token {
        Some(t) => Ok(Some(format!("Negotiate {}", BASE64.encode(&*t)))),
        None => Ok(None),
    }
}

pub fn basic_token(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    format!("Basic {}", BASE64.encode(credentials.as_bytes()))
}

// ── SPNEGO token cache ─────────────────────────────────────────────────────────

/// Cached SPNEGO token for reuse across connections to the same upstream proxy.
/// Avoids repeating the GSSAPI handshake on every request, which causes
/// JetBrains IDE "proxy authentication failed" errors under load.
pub(crate) struct SpnegoCache {
    token: Mutex<Option<(String, Instant)>>,
    ttl: Duration,
}

impl SpnegoCache {
    fn new() -> Self {
        Self {
            token: Mutex::new(None),
            ttl: Duration::from_secs(3600), // 1 hour
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

/// Extract the value of the Proxy-Authenticate header from a raw HTTP response.
pub fn extract_proxy_authenticate(response: &str) -> String {
    response
        .lines()
        .find(|l| l.to_lowercase().starts_with("proxy-authenticate:"))
        .map(|l| l[19..].trim().to_string())
        .unwrap_or_default()
}

/// Extract the base64 challenge token from a Negotiate or Kerberos
/// Proxy-Authenticate header value.
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

/// Resolve username + keychain password for Basic auth.
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

/// Build a Proxy-Authorization header for forwarded (non-CONNECT) requests.
pub fn build_forward_auth_header(
    proxy_authenticate: &str,
    upstream_host: &str,
    upstream_port: u16,
    username: Option<&str>,
    get_password: impl FnOnce(&str) -> anyhow::Result<String>,
) -> anyhow::Result<Option<String>> {
    match detect_scheme(proxy_authenticate) {
        AuthScheme::Negotiate => {
            match negotiate_init(upstream_host, upstream_port) {
                Ok((token, _ctx)) => Ok(Some(token)),
                Err(e) => {
                    tracing::warn!("Negotiate init failed: {}, falling back to Basic", e);
                    Ok(resolve_basic_auth(username, get_password))
                }
            }
        }
        AuthScheme::Basic => Ok(resolve_basic_auth(username, get_password)),
        AuthScheme::None => Ok(None),
    }
}

fn resolve_basic_auth(
    username: Option<&str>,
    get_password: impl FnOnce(&str) -> anyhow::Result<String>,
) -> Option<String> {
    resolve_basic_credentials(username, get_password)
        .ok()
        .map(|(u, p)| basic_token(&u, &p))
}

/// Attempt a second Negotiate round if the server sent a challenge token in
/// the 407. Returns a new auth header value if successful.
pub fn negotiate_round2(
    proxy_authenticate: &str,
    upstream_host: &str,
    upstream_port: u16,
) -> anyhow::Result<Option<String>> {
    let challenge = extract_negotiate_challenge(proxy_authenticate);
    if challenge.is_empty() {
        return Ok(None);
    }
    let decoded = match BASE64.decode(&challenge) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!("Negotiate round2 base64 decode failed: {}", e);
            return Ok(None);
        }
    };
    // Re-init and immediately step with the challenge
    let (_initial, mut ctx) = match negotiate_init(upstream_host, upstream_port) {
        Ok(result) => result,
        Err(e) => {
            tracing::warn!("Negotiate round2 init failed: {}", e);
            return Ok(None);
        }
    };
    match negotiate_step(&mut ctx, &decoded) {
        Ok(t) => Ok(t),
        Err(e) => {
            tracing::warn!("Negotiate round2 step failed: {}", e);
            Ok(None)
        }
    }
}
