use anyhow::{bail, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine};
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::auth::{basic_token, detect_scheme, negotiate_init, negotiate_step, AuthScheme};
use crate::config::{AuthMethod, Config};
use crate::keychain;
use crate::pac::{parse_pac_result, PacEngine, ProxyDirective};

pub async fn run(cfg: Config) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", cfg.proxy.listen, cfg.proxy.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("proxypass listening on {}", addr);

    let pac = PacEngine::new(&cfg);
    let cfg = std::sync::Arc::new(cfg);

    loop {
        let (stream, peer) = listener.accept().await?;
        debug!("Connection from {}", peer);
        let pac = pac.clone();
        let cfg = cfg.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(stream, pac, cfg).await {
                error!("Connection error: {}", e);
            }
        });
    }
}

async fn handle_connection(
    stream: TcpStream,
    pac: PacEngine,
    cfg: std::sync::Arc<Config>,
) -> Result<()> {
    let io = TokioIo::new(stream);
    hyper::server::conn::http1::Builder::new()
        .serve_connection(
            io,
            hyper::service::service_fn(move |req| {
                let pac = pac.clone();
                let cfg = cfg.clone();
                async move { handle_request(req, pac, cfg).await }
            }),
        )
        .with_upgrades()
        .await?;
    Ok(())
}

async fn handle_request(
    req: Request<Incoming>,
    pac: PacEngine,
    cfg: std::sync::Arc<Config>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let host = extract_host(&req);
    let url = format!(
        "{}://{}{}",
        if req.method() == Method::CONNECT { "https" } else { "http" },
        host,
        req.uri().path()
    );

    if is_no_proxy(&host, &cfg.proxy.no_proxy) {
        debug!("DIRECT (no_proxy): {}", host);
        return forward_direct(req).await;
    }

    let pac_result = pac.find_proxy(&url, &host).await
        .unwrap_or_else(|_| "DIRECT".to_string());
    debug!("PAC result for {}: {}", host, pac_result);

    match parse_pac_result(&pac_result) {
        ProxyDirective::Direct => forward_direct(req).await,
        ProxyDirective::Proxy(upstream) => {
            if req.method() == Method::CONNECT {
                tunnel(req, &upstream, &cfg).await
            } else {
                forward_via_proxy(req, &upstream, &cfg).await
            }
        }
    }
}

async fn tunnel(
    req: Request<Incoming>,
    upstream: &str,
    cfg: &Config,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let target = req.uri().to_string();
    let host_only = req.uri().host().unwrap_or("").to_string();
    let upstream_host = upstream.split(':').next().unwrap_or(upstream);
    let upstream_port: u16 = upstream.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(3128);

    let mut upstream_stream = match TcpStream::connect(upstream).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to upstream {}: {}", upstream, e);
            return Ok(error_response(StatusCode::BAD_GATEWAY, "Upstream connection failed"));
        }
    };

    // Initial CONNECT (no auth)
    let connect_req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", target, target);
    tokio::io::AsyncWriteExt::write_all(&mut upstream_stream, connect_req.as_bytes()).await?;

    let mut buf = [0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut upstream_stream, &mut buf).await?;
    let response_str = String::from_utf8_lossy(&buf[..n]).to_string();

    // Multi-step 407/Negotiate handshake — loop up to 5 times
    if response_str.contains("407") {
        if let Err(e) = handle_407_handshake(
            &mut upstream_stream,
            &mut buf,
            &response_str,
            &target,
            &host_only,
            upstream_host,
            upstream_port,
            cfg,
        ).await {
            warn!("Auth handshake failed: {}", e);
            return Ok(error_response(StatusCode::PROXY_AUTHENTICATION_REQUIRED, "Auth failed"));
        }
    } else if !response_str.contains("200") {
        return Ok(error_response(StatusCode::BAD_GATEWAY, "Upstream CONNECT failed"));
    }

    tokio::task::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                let mut upgraded = TokioIo::new(upgraded);
                if let Err(e) = tokio::io::copy_bidirectional(&mut upgraded, &mut upstream_stream).await {
                    debug!("Tunnel closed: {}", e);
                }
            }
            Err(e) => error!("Upgrade error: {}", e),
        }
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .body(empty_body())
        .unwrap())
}

/// Handle the multi-step 407/Negotiate handshake with the upstream proxy.
/// Loops up to 5 times, feeding challenge tokens back into the GSSAPI context,
/// until we get a 200 or an unrecoverable error.
async fn handle_407_handshake(
    stream: &mut TcpStream,
    buf: &mut [u8],
    initial_response: &str,
    target: &str,
    _host_only: &str,
    upstream_host: &str,
    upstream_port: u16,
    cfg: &Config,
) -> Result<()> {
    let proxy_auth_header = extract_proxy_authenticate(initial_response);
    let scheme = detect_scheme(&proxy_auth_header);

    match scheme {
        AuthScheme::Negotiate => {
            if cfg.auth.method == AuthMethod::None {
                warn!("Proxy requires Negotiate but auth is disabled — giving up");
                bail!("Negotiate required but auth is disabled");
            }

            info!("Starting Negotiate authentication to upstream proxy");
            let challenge = extract_negotiate_challenge(&proxy_auth_header);

            let (auth_header, mut neg_ctx) = if challenge.is_empty() {
                negotiate_init(upstream_host, upstream_port)
                    .map_err(|e| anyhow::anyhow!("Negotiate init: {}", e))?
            } else {
                let (_initial, mut ctx) = negotiate_init(upstream_host, upstream_port)
                    .map_err(|e| anyhow::anyhow!("Negotiate init: {}", e))?;
                let decoded = BASE64_STANDARD.decode(&challenge)
                    .map_err(|e| anyhow::anyhow!("base64 decode: {}", e))?;
                match negotiate_step(&mut ctx, &decoded)
                    .map_err(|e| anyhow::anyhow!("Negotiate step: {}", e))? {
                    Some(t) => (t, ctx),
                    None => bail!("Negotiate handshake completed with no token"),
                }
            };

            // Send the auth'd CONNECT
            let mut req = format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
                target, target, auth_header
            );
            tokio::io::AsyncWriteExt::write_all(&mut *stream, req.as_bytes()).await?;
            let n = tokio::io::AsyncReadExt::read(&mut *stream, buf).await?;
            let mut response_str = String::from_utf8_lossy(&buf[..n]).to_string();

            // Loop for additional 407 challenges (Negotiate multi-round, up to 4 more)
            for round in 0..4 {
                if response_str.contains("200") {
                    info!("✓ Negotiate authenticated after {} round(s)", round + 1);
                    return Ok(());
                }
                if !response_str.contains("407") {
                    bail!("Unexpected response: {}", response_str.lines().next().unwrap_or(""));
                }

                let challenge = extract_negotiate_challenge(&extract_proxy_authenticate(&response_str));
                if challenge.is_empty() {
                    info!("Negotiate failed — no more challenges, trying Basic fallback");
                    return negotiate_fallback_to_basic(stream, buf, target).await;
                }

                let decoded = BASE64_STANDARD.decode(&challenge)
                    .map_err(|e| anyhow::anyhow!("base64 decode: {}", e))?;
                let next_token = match negotiate_step(&mut neg_ctx, &decoded)
                    .map_err(|e| anyhow::anyhow!("Negotiate step: {}", e))? {
                    Some(t) => t,
                    None => {
                        info!("Negotiate handshake complete, verifying...");
                        break; // Context says done, check final response
                    }
                };

                info!("  Negotiate round {} — sending response token", round + 2);
                req = format!(
                    "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
                    target, target, next_token
                );
                tokio::io::AsyncWriteExt::write_all(&mut *stream, req.as_bytes()).await?;
                let n = tokio::io::AsyncReadExt::read(&mut *stream, buf).await?;
                response_str = String::from_utf8_lossy(&buf[..n]).to_string();
            }

            if response_str.contains("200") {
                info!("✓ Negotiate authenticated successfully");
                Ok(())
            } else {
                info!("Negotiate handshake incomplete — trying Basic fallback");
                negotiate_fallback_to_basic(stream, buf, target).await
            }
        }
        AuthScheme::Basic => {
            info!("Attempting Basic authentication");
            let (user, pass) = resolve_basic_credentials(cfg)?;
            let token = basic_token(&user, &pass);
            let req = format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
                target, target, token
            );
            tokio::io::AsyncWriteExt::write_all(&mut *stream, req.as_bytes()).await?;
            let n = tokio::io::AsyncReadExt::read(&mut *stream, buf).await?;
            let response_str = String::from_utf8_lossy(&buf[..n]);
            if response_str.contains("200") {
                info!("✓ Basic authentication succeeded");
                Ok(())
            } else {
                warn!("Basic authentication rejected");
                bail!("Basic auth rejected");
            }
        }
        AuthScheme::None => {
            bail!("407 received but no supported auth scheme");
        }
    }
}

fn extract_proxy_authenticate(response: &str) -> String {
    response
        .lines()
        .find(|l| l.to_lowercase().starts_with("proxy-authenticate:"))
        .map(|l| l[19..].trim().to_string())
        .unwrap_or_default()
}

fn extract_negotiate_challenge(header: &str) -> String {
    let lower = header.to_lowercase();
    if lower.starts_with("negotiate") {
        header.get(10..).map(|s| s.trim().to_string()).unwrap_or_default()
    } else if lower.starts_with("kerberos") {
        header.get(8..).map(|s| s.trim().to_string()).unwrap_or_default()
    } else {
        String::new()
    }
}

/// Fall back from failed Negotiate to Basic on a new connection.
async fn negotiate_fallback_to_basic(
    stream: &mut TcpStream,
    buf: &mut [u8],
    target: &str,
) -> Result<()> {
    let cfg = crate::config::load().ok();
    let (user, pass) = match cfg.as_ref().and_then(|c| c.auth.username.as_ref()) {
        Some(user) => match crate::keychain::get_password(user) {
            Ok(pass) => {
                warn!("Negotiate failed, falling back to Basic auth for {}", user);
                (user.clone(), pass)
            }
            Err(e) => {
                warn!("Negotiate failed and no Basic password available: {}", e);
                bail!("Negotiate failed, no Basic fallback credentials");
            }
        },
        None => {
            warn!("Negotiate failed and no username configured for Basic fallback");
            bail!("Negotiate failed, no Basic fallback configured");
        }
    };

    let token = basic_token(&user, &pass);
    let req = format!(
        "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
        target, target, token
    );
    // Reconnect — the Negotiate connection is in an unknown state
    let addr = stream.peer_addr().ok();
    let mut new_stream = TcpStream::connect(addr.unwrap()).await?;
    tokio::io::AsyncWriteExt::write_all(&mut new_stream, req.as_bytes()).await?;
    let n = tokio::io::AsyncReadExt::read(&mut new_stream, buf).await?;
    let response_str = String::from_utf8_lossy(&buf[..n]);
    if response_str.contains("200") {
        info!("✓ Basic auth (Negotiate fallback) succeeded");
        *stream = new_stream;
        Ok(())
    } else {
        warn!("Basic auth fallback also failed");
        bail!("Basic auth fallback rejected");
    }
}

async fn forward_via_proxy(
    req: Request<Incoming>,
    upstream: &str,
    cfg: &Config,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let upstream_host = upstream.split(':').next().unwrap_or(upstream);
    let upstream_port: u16 = upstream.split(':').nth(1).and_then(|p| p.parse().ok()).unwrap_or(3128);

    let stream = TcpStream::connect(upstream).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io).await?;
    tokio::spawn(async move { let _ = conn.await; });

    let target_uri = req.uri().clone();
    let (parts, body) = req.into_parts();
    let body_bytes = body.collect().await?.to_bytes();

    // Try unauth request first
    let mut req = Request::from_parts(parts.clone(), Full::new(body_bytes.clone()));
    *req.uri_mut() = target_uri.clone();

    let resp = sender.send_request(req).await?;

    // If 407, add auth and retry
    if resp.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        let proxy_auth = resp.headers()
            .get("proxy-authenticate")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        let auth_header = build_forward_auth_header(proxy_auth, upstream_host, upstream_port, cfg)?;

        if let Some(auth_value) = auth_header {
            // Close old connection and open a fresh one
            let stream = TcpStream::connect(upstream).await?;
            let io = TokioIo::new(stream);
            let (mut sender, conn) = hyper::client::conn::http1::handshake::<_, Full<Bytes>>(io).await?;
            tokio::spawn(async move { let _ = conn.await; });

            let mut req = Request::from_parts(parts, Full::new(body_bytes));
            *req.uri_mut() = target_uri;
            req.headers_mut().insert(
                hyper::header::PROXY_AUTHORIZATION,
                auth_value.parse().unwrap(),
            );

            let resp = sender.send_request(req).await?;
            // If still 407 and Negotiate, try one more Negotiate round with challenge
            if resp.status() == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
                let challenge = resp.headers()
                    .get("proxy-authenticate")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or("");
                if let Some(_auth_token) = negotiate_round2(challenge, upstream_host, upstream_port)? {
                    // Full multi-round reconnection would require saving the body;
                    // for now log and return whatever the server sent.
                    warn!("Multi-round Negotiate required for forwarded request — auth may not complete");
                }
            }

            let (resp_parts, body) = resp.into_parts();
            return Ok(Response::from_parts(resp_parts, body.map_err(|e| e).boxed()));
        }
    }

    let (resp_parts, body) = resp.into_parts();
    Ok(Response::from_parts(resp_parts, body.map_err(|e| e).boxed()))
}

/// Build a Proxy-Authorization header for forwarded (non-CONNECT) requests.
fn build_forward_auth_header(
    proxy_authenticate: &str,
    upstream_host: &str,
    upstream_port: u16,
    cfg: &Config,
) -> Result<Option<String>> {
    match detect_scheme(proxy_authenticate) {
        AuthScheme::Negotiate => {
            if cfg.auth.method == AuthMethod::None {
                return Ok(None);
            }
            match negotiate_init(upstream_host, upstream_port) {
                Ok((token, _ctx)) => Ok(Some(token)),
                Err(e) => {
                    warn!("Negotiate init failed: {}, falling back to Basic", e);
                    resolve_basic_auth(cfg)
                }
            }
        }
        AuthScheme::Basic => resolve_basic_auth(cfg),
        AuthScheme::None => Ok(None),
    }
}

fn resolve_basic_auth(cfg: &Config) -> Result<Option<String>> {
    let (user, pass) = resolve_basic_credentials(cfg)?;
    Ok(Some(basic_token(&user, &pass)))
}

fn resolve_basic_credentials(cfg: &Config) -> Result<(String, String)> {
    match &cfg.auth.username {
        Some(user) => match keychain::get_password(user) {
            Ok(pass) => Ok((user.clone(), pass)),
            Err(e) => bail!("No keychain password for {}: {}", user, e),
        },
        None => bail!("No username configured"),
    }
}

async fn forward_direct(
    req: Request<Incoming>,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let host = extract_host(&req);
    if req.method() == Method::CONNECT {
        let stream = match TcpStream::connect(&host).await {
            Ok(s) => s,
            Err(e) => {
                warn!("Direct connect failed to {}: {}", host, e);
                return Ok(error_response(StatusCode::BAD_GATEWAY, "Direct connection failed"));
            }
        };
        tokio::spawn(async move {
            match hyper::upgrade::on(req).await {
                Ok(upgraded) => {
                    let mut upgraded = TokioIo::new(upgraded);
                    let mut stream = stream;
                    let _ = tokio::io::copy_bidirectional(&mut upgraded, &mut stream).await;
                }
                Err(e) => error!("Direct upgrade error: {}", e),
            }
        });
        Ok(Response::builder().status(StatusCode::OK).body(empty_body()).unwrap())
    } else {
        Ok(error_response(StatusCode::NOT_IMPLEMENTED, "Direct HTTP not supported"))
    }
}

/// Attempt a second Negotiate round if the server sent a challenge token in
/// the 407. Returns a new auth header value if successful.
fn negotiate_round2(
    proxy_authenticate: &str,
    upstream_host: &str,
    upstream_port: u16,
) -> Result<Option<String>> {
    let challenge = extract_negotiate_challenge(proxy_authenticate);
    if challenge.is_empty() {
        return Ok(None);
    }
    let decoded = BASE64_STANDARD.decode(&challenge)
        .map_err(|e| anyhow::anyhow!("base64 decode: {}", e))?;
    // Re-init and immediately step with the challenge
    let (_initial, mut ctx) = negotiate_init(upstream_host, upstream_port)?;
    negotiate_step(&mut ctx, &decoded)
}

/// Stub: old single-step auth builder, kept for reference but no longer used.
#[allow(dead_code)]
fn build_auth_header(
    response: &str,
    host: &str,
    port: u16,
    cfg: &Config,
) -> Result<Option<String>> {
    let proxy_auth_header = extract_proxy_authenticate(response);
    build_forward_auth_header(&proxy_auth_header, host, port, cfg)
}

fn extract_host(req: &Request<Incoming>) -> String {
    if let Some(auth) = req.uri().authority() {
        let host = auth.host();
        let port = auth.port_u16().unwrap_or(
            if req.method() == Method::CONNECT { 443 } else { 80 }
        );
        format!("{}:{}", host, port)
    } else if let Some(host) = req.headers().get("host") {
        host.to_str().unwrap_or("").to_string()
    } else {
        String::new()
    }
}

fn is_no_proxy(host: &str, no_proxy: &[String]) -> bool {
    let host_only = host.split(':').next().unwrap_or(host);
    for pattern in no_proxy {
        if pattern == host_only { return true; }
        if let Some(suffix) = pattern.strip_prefix("*.") {
            if host_only.ends_with(suffix) || host_only == suffix { return true; }
        }
        if pattern.ends_with(".*") {
            let prefix = &pattern[..pattern.len() - 2];
            if host_only.starts_with(prefix) { return true; }
        }
    }
    false
}

fn empty_body() -> BoxBody<Bytes, hyper::Error> {
    Empty::<Bytes>::new().map_err(|e| match e {}).boxed()
}

fn error_response(status: StatusCode, msg: &'static str) -> Response<BoxBody<Bytes, hyper::Error>> {
    Response::builder()
        .status(status)
        .body(Full::new(Bytes::from(msg)).map_err(|e| match e {}).boxed())
        .unwrap()
}
