use anyhow::{bail, Result};
use libgssapi::{
    context::{ClientCtx, CtxFlags},
    credential::{Cred, CredUsage},
    name::Name,
    oid::{OidSet, GSS_MECH_KRB5, GSS_NT_HOSTBASED_SERVICE},
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};

pub enum AuthScheme {
    Negotiate,
    Basic,
    None,
}

/// Detect what auth the upstream proxy is asking for
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

/// Build a Negotiate (Kerberos) token for the given proxy host
pub fn negotiate_token(proxy_host: &str) -> Result<String> {
    let service_name = format!("HTTP@{}", proxy_host);
    let name = Name::new(service_name.as_bytes(), Some(&GSS_NT_HOSTBASED_SERVICE))
        .map_err(|e| anyhow::anyhow!("GSSAPI name error: {:?}", e))?;

    let mut oids = OidSet::new().map_err(|e| anyhow::anyhow!("OidSet error: {:?}", e))?;
    oids.add(&GSS_MECH_KRB5).map_err(|e| anyhow::anyhow!("OidSet add error: {:?}", e))?;

    let cred = Cred::acquire(None, None, CredUsage::Initiate, Some(&oids))
        .map_err(|e| anyhow::anyhow!("GSSAPI credential error: {:?}", e))?;

    let mut ctx = ClientCtx::new(
        Some(cred),
        name,
        CtxFlags::GSS_C_MUTUAL_FLAG,
        Some(&GSS_MECH_KRB5),
    );

    let token = ctx.step(None, None)
        .map_err(|e| anyhow::anyhow!("GSSAPI step error: {:?}", e))?;

    match token {
        Some(t) => Ok(format!("Negotiate {}", BASE64.encode(&*t))),
        None => bail!("GSSAPI returned no token"),
    }
}

/// Build a Basic auth header
pub fn basic_token(username: &str, password: &str) -> String {
    let credentials = format!("{}:{}", username, password);
    format!("Basic {}", BASE64.encode(credentials.as_bytes()))
}
