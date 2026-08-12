use anyhow::{Context, Result};
use rquickjs::{Context as JsContext, Runtime};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use crate::config::Config;

#[derive(Clone)]
pub struct PacEngine {
    inner: Arc<Mutex<PacInner>>,
}

struct PacInner {
    pac_url: Option<String>,
    direct_proxy: Option<String>,
    script: Option<String>,
    fetched_at: Option<Instant>,
    cache_ttl: Duration,
}

impl PacEngine {
    pub fn new(cfg: &Config) -> Self {
        Self {
            inner: Arc::new(Mutex::new(PacInner {
                pac_url: cfg.proxy.pac.clone(),
                direct_proxy: cfg.proxy.proxy.clone(),
                script: None,
                fetched_at: None,
                cache_ttl: Duration::from_secs(cfg.pac.cache_ttl),
            })),
        }
    }

    pub async fn find_proxy(&self, url: &str, host: &str) -> Result<String> {
        // Direct proxy mode — no PAC needed
        {
            let inner = self.inner.lock().unwrap();
            if let Some(ref upstream) = inner.direct_proxy {
                return Ok(format!("PROXY {}", upstream));
            }
        }

        self.ensure_loaded().await?;

        let script = {
            let inner = self.inner.lock().unwrap();
            inner.script.clone().unwrap_or_default()
        };

        evaluate_pac(&script, url, host)
    }

    async fn ensure_loaded(&self) -> Result<()> {
        let (needs_fetch, pac_url) = {
            let inner = self.inner.lock().unwrap();
            let stale = inner.fetched_at
                .map(|t| t.elapsed() > inner.cache_ttl)
                .unwrap_or(true);
            (stale || inner.script.is_none(), inner.pac_url.clone())
        };

        if needs_fetch {
            if let Some(url) = pac_url {
                match fetch_pac(&url).await {
                    Ok(script) => {
                        let mut inner = self.inner.lock().unwrap();
                        inner.script = Some(script);
                        inner.fetched_at = Some(Instant::now());
                        debug!("PAC script loaded from {}", url);
                    }
                    Err(e) => {
                        warn!("Failed to reload PAC: {}, using cached version", e);
                    }
                }
            }
        }
        Ok(())
    }
}

async fn fetch_pac(url: &str) -> Result<String> {
    let client = reqwest::Client::builder()
        .tls_built_in_native_certs(true)
        .timeout(Duration::from_secs(10))
        .build()?;
    let body = client.get(url).send().await?.text().await?;
    Ok(body)
}

fn evaluate_pac(script: &str, url: &str, host: &str) -> Result<String> {
    let rt = Runtime::new().context("Failed to create JS runtime")?;
    let ctx = JsContext::full(&rt).context("Failed to create JS context")?;

    ctx.with(|ctx| {
        ctx.eval::<(), _>(pac_helpers()).ok();
        ctx.eval::<(), _>(script.to_string())
            .context("Failed to evaluate PAC script")?;
        let call = format!("FindProxyForURL({:?}, {:?})", url, host);
        let result: String = ctx.eval(call)
            .context("Failed to call FindProxyForURL")?;
        Ok(result)
    })
}

pub fn parse_pac_result(result: &str) -> ProxyDirective {
    for directive in result.split(';') {
        let directive = directive.trim();
        if directive.eq_ignore_ascii_case("DIRECT") {
            return ProxyDirective::Direct;
        }
        if let Some(addr) = directive.strip_prefix("PROXY ")
            .or_else(|| directive.strip_prefix("proxy "))
            .or_else(|| directive.strip_prefix("HTTPS "))
            .or_else(|| directive.strip_prefix("https "))
        {
            return ProxyDirective::Proxy(addr.trim().to_string());
        }
    }
    ProxyDirective::Direct
}

pub enum ProxyDirective {
    Direct,
    Proxy(String),
}

fn pac_helpers() -> &'static str {
    r#"
function isPlainHostName(host) { return host.indexOf('.') === -1; }
function dnsDomainIs(host, domain) {
    return host.length >= domain.length &&
        host.substring(host.length - domain.length) === domain;
}
function shExpMatch(str, shexp) {
    var re = new RegExp('^' + shexp.replace(/\./g, '\\.').replace(/\*/g, '.*').replace(/\?/g, '.') + '$', 'i');
    return re.test(str);
}
function isInNet(host, pattern, mask) { return false; }
function myIpAddress() { return "127.0.0.1"; }
function dnsResolve(host) { return ""; }
function localHostOrDomainIs(host, hostdom) {
    return host === hostdom ||
        (host + '.') === hostdom.substring(0, hostdom.indexOf('.') + 1);
}
function isResolvable(host) { return true; }
function dnsDomainLevels(host) { return host.split('.').length - 1; }
function weekdayRange(wd1, wd2, gmt) { return true; }
function dateRange() { return true; }
function timeRange() { return true; }
"#
}
