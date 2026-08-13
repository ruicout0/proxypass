use anyhow::{bail, Result};
use libgssapi::{
    context::{ClientCtx, CtxFlags},
    credential::{Cred, CredUsage},
    name::Name,
    oid::{Oid, OidSet, GSS_MECH_KRB5, GSS_MECH_SPNEGO, GSS_NT_HOSTBASED_SERVICE},
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
fn select_mech() -> (Oid<'static>, &'static str) {
    use std::sync::OnceLock;
    static MECH: OnceLock<(Oid<'static>, &'static str)> = OnceLock::new();
    MECH.get_or_init(|| {
        // Try SPNEGO first — it's the standard approach
        let mut oids = OidSet::new();
        if oids.add(GSS_MECH_SPNEGO.clone()).is_ok() {
            let cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&oids));
            if cred.is_ok() {
                return (GSS_MECH_SPNEGO.clone(), "SPNEGO");
            }
        }
        // Fall back to raw Kerberos
        (GSS_MECH_KRB5.clone(), "Kerberos")
    }).clone()
}

/// Build a fresh Negotiate context and return the initial token.
/// Call `negotiate_step()` for subsequent challenge/response rounds.
pub fn negotiate_init(proxy_host: &str, proxy_port: u16) -> Result<(String, NegotiateContext)> {
    let service_name = format!("HTTP@{}:{}", proxy_host, proxy_port);
    let name = Name::new(service_name.as_bytes(), Some(GSS_NT_HOSTBASED_SERVICE))
        .map_err(|e| anyhow::anyhow!("GSSAPI name error: {:?}", e))?;

    let (mech, mech_name) = select_mech();
    tracing::info!("Using GSS mechanism: {}", mech_name);

    let mut oids = OidSet::new();
    oids.add(mech.clone()).map_err(|e| anyhow::anyhow!("OidSet add error: {}", e))?;

    let cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&oids))
        .map_err(|e| anyhow::anyhow!("GSSAPI credential error for {}: {:?}", mech_name, e))?;

    let mut ctx = ClientCtx::new(
        Some(cred),
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
