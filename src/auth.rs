use anyhow::{bail, Result};
use libgssapi::{
    context::{ClientCtx, CtxFlags},
    name::Name,
    oid::{Oid, GSS_MECH_KRB5, GSS_MECH_SPNEGO, GSS_NT_HOSTBASED_SERVICE},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

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
    use std::sync::OnceLock;
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

    // Don't pre-acquire a credential — on macOS Heimdal, credentials
    // acquired for a specific mechanism OID set can fail at
    // gss_init_sec_context time even when gss_acquire_cred succeeds.
    // Passing None lets GSSAPI pick the default credential, which is
    // what curl does and what works with Heimdal.
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
