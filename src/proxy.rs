use anyhow::Result;
use bytes::Bytes;
use http_body_util::{combinators::BoxBody, BodyExt, Empty, Full};
use hyper::{body::Incoming, Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::auth::{basic_token, detect_scheme, negotiate_token, AuthScheme};
use crate::config::{AuthMethod, Config};
use crate::keychain;
use crate::pac::{parse_pac_result, PacEngine, ProxyDirective};

pub async fn run(cfg: Config) -> Result<()> {
    let addr: SocketAddr = format!("{}:{}", cfg.proxy.listen, cfg.proxy.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("proxypass listening on {}", addr);

    let pac = PacEngine::new(&cfg.proxy.pac, cfg.pac.cache_ttl);
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

    // Check no_proxy
    if is_no_proxy(&host, &cfg.proxy.no_proxy) {
        debug!("DIRECT (no_proxy): {}", host);
        return forward_direct(req).await;
    }

    // Evaluate PAC
    let pac_result = pac.find_proxy(&url, &host).await.unwrap_or_else(|_| "DIRECT".to_string());
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

/// HTTPS CONNECT tunnel through upstream proxy
async fn tunnel(
    req: Request<Incoming>,
    upstream: &str,
    cfg: &Config,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    let host = req.uri().authority().map(|a| a.host().to_string()).unwrap_or_default();
    let target = req.uri().to_string();

    // Connect to upstream proxy
    let mut upstream_stream = match TcpStream::connect(upstream).await {
        Ok(s) => s,
        Err(e) => {
            error!("Failed to connect to upstream {}: {}", upstream, e);
            return Ok(error_response(StatusCode::BAD_GATEWAY, "Upstream connection failed"));
        }
    };

    // Send CONNECT to upstream
    let connect_req = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n", target, host);
    tokio::io::AsyncWriteExt::write_all(&mut upstream_stream, connect_req.as_bytes()).await?;

    // Read upstream response
    let mut buf = [0u8; 4096];
    let n = tokio::io::AsyncReadExt::read(&mut upstream_stream, &mut buf).await?;
    let response_str = String::from_utf8_lossy(&buf[..n]);

    // Handle 407 Proxy Auth Required
    if response_str.contains("407") {
        let auth_header = build_auth_header(&response_str, &host, cfg)?;
        if let Some(auth) = auth_header {
            let connect_req = format!(
                "CONNECT {} HTTP/1.1\r\nHost: {}\r\nProxy-Authorization: {}\r\n\r\n",
                target, host, auth
            );
            tokio::io::AsyncWriteExt::write_all(&mut upstream_stream, connect_req.as_bytes()).await?;
            let n = tokio::io::AsyncReadExt::read(&mut upstream_stream, &mut buf).await?;
            let response_str = String::from_utf8_lossy(&buf[..n]);
            if !response_str.contains("200") {
                return Ok(error_response(StatusCode::PROXY_AUTHENTICATION_REQUIRED, "Auth failed"));
            }
        }
    } else if !response_str.contains("200") {
        return Ok(error_response(StatusCode::BAD_GATEWAY, "Upstream CONNECT failed"));
    }

    // Upgrade the client connection and splice
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

/// Forward plain HTTP request via upstream proxy
async fn forward_via_proxy(
    req: Request<Incoming>,
    upstream: &str,
    cfg: &Config,
) -> Result<Response<BoxBody<Bytes, hyper::Error>>> {
    // Simple TCP forward for HTTP
    let stream = TcpStream::connect(upstream).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let (parts, body) = req.into_parts();
    let body = body.collect().await?.to_bytes();
    let req = Request::from_parts(parts, Full::new(body).map_err(|e| match e {}).boxed());

    let resp = sender.send_request(req).await?;
    let (parts, body) = resp.into_parts();
    Ok(Response::from_parts(parts, body.map_err(|e| e).boxed()))
}

/// Connect directly without upstream proxy
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

fn build_auth_header(response: &str, host: &str, cfg: &Config) -> Result<Option<String>> {
    let proxy_auth_header = response
        .lines()
        .find(|l| l.to_lowercase().starts_with("proxy-authenticate:"))
        .map(|l| l[19..].trim().to_string())
        .unwrap_or_default();

    match detect_scheme(&proxy_auth_header) {
        AuthScheme::Negotiate => {
            if cfg.auth.method == AuthMethod::None {
                return Ok(None);
            }
            match negotiate_token(host) {
                Ok(token) => Ok(Some(token)),
                Err(e) => {
                    warn!("Kerberos failed: {}, falling back to Basic", e);
                    basic_auth_header(cfg)
                }
            }
        }
        AuthScheme::Basic => basic_auth_header(cfg),
        AuthScheme::None => Ok(None),
    }
}

fn basic_auth_header(cfg: &Config) -> Result<Option<String>> {
    if let Some(username) = &cfg.auth.username {
        match keychain::get_password(username) {
            Ok(password) => Ok(Some(basic_token(username, &password))),
            Err(e) => {
                warn!("No password in keychain: {}", e);
                Ok(None)
            }
        }
    } else {
        Ok(None)
    }
}

fn extract_host(req: &Request<Incoming>) -> String {
    if let Some(auth) = req.uri().authority() {
        let host = auth.host();
        let port = auth.port_u16().unwrap_or(if req.method() == Method::CONNECT { 443 } else { 80 });
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
        if pattern == host_only {
            return true;
        }
        if let Some(suffix) = pattern.strip_prefix("*.") {
            if host_only.ends_with(suffix) || host_only == suffix {
                return true;
            }
        }
        if pattern.ends_with(".*") {
            let prefix = &pattern[..pattern.len() - 2];
            if host_only.starts_with(prefix) {
                return true;
            }
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
