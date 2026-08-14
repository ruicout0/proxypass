use anyhow::{Context, Result};
use rquickjs::{Context as JsContext, Runtime};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

use crate::config::Config;

#[derive(Clone)]
pub struct PacEngine {
    inner: Arc<Mutex<PacInner>>,
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum PacState {
    /// PAC script is loaded and valid (VPN is up).
    Healthy,
    /// PAC URL is unreachable — always use DIRECT.
    /// Both initial load and refresh attempts failed.
    Unreachable,
}

struct PacInner {
    pac_url: Option<String>,
    direct_proxy: Option<String>,
    script: Option<String>,
    fetched_at: Option<Instant>,
    cache_ttl: Duration,
    state: PacState,
    /// Track the last known network interface set to detect VPN changes.
    last_ifaddrs_hash: u64,
    /// Per-host PAC result cache to avoid re-evaluating the JS runtime
    /// for the same host on every request.
    host_cache: HashMap<String, (String, Instant)>,
}

impl PacEngine {
    pub fn new(cfg: &Config) -> Self {
        let hash = hash_network_interfaces();
        Self {
            inner: Arc::new(Mutex::new(PacInner {
                pac_url: cfg.proxy.pac.clone(),
                direct_proxy: cfg.proxy.proxy.clone(),
                script: None,
                fetched_at: None,
                cache_ttl: Duration::from_secs(cfg.pac.cache_ttl),
                state: PacState::Healthy,
                last_ifaddrs_hash: hash,
                host_cache: HashMap::new(),
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

        // Detect network changes — force re-check PAC when interfaces change.
        self.detect_network_change();

        let _ = self.ensure_loaded().await;

        {
            let inner = self.inner.lock().unwrap();
            if inner.state == PacState::Unreachable {
                debug!("PAC unreachable, DIRECT for: {}", host);
                return Ok("DIRECT".to_string());
            }
        }

        // Check per-host cache before evaluating PAC
        {
            let inner = self.inner.lock().unwrap();
            if let Some((result, ts)) = inner.host_cache.get(host) {
                if ts.elapsed() < inner.cache_ttl {
                    debug!("PAC cache hit for: {}", host);
                    return Ok(result.clone());
                }
            }
        }

        let script = {
            let inner = self.inner.lock().unwrap();
            inner.script.clone().unwrap_or_default()
        };

        let result = evaluate_pac(&script, url, host)?;

        // Cache the result per host
        {
            let mut inner = self.inner.lock().unwrap();
            inner.host_cache.insert(host.to_string(), (result.clone(), Instant::now()));
        }

        Ok(result)
    }

    /// Check if network interfaces changed (e.g. VPN connected/disconnected).
    /// If so, clear the stale/unreachable state and force a PAC refresh.
    fn detect_network_change(&self) {
        let new_hash = hash_network_interfaces();
        let mut inner = self.inner.lock().unwrap();
        if new_hash != inner.last_ifaddrs_hash {
            info!(
                "Network interfaces changed — resetting PAC state (was {:?})",
                inner.state
            );
            inner.state = PacState::Healthy;
            inner.fetched_at = None; // force refresh
            inner.host_cache.clear(); // invalidate all cached results
            inner.last_ifaddrs_hash = new_hash;
        }
    }

    async fn ensure_loaded(&self) -> Result<()> {
        let (needs_fetch, pac_url) = {
            let inner = self.inner.lock().unwrap();
            let expired = inner.fetched_at
                .map(|t| t.elapsed() > inner.cache_ttl)
                .unwrap_or(true);
            let needs = expired || inner.script.is_none() || inner.state == PacState::Healthy;
            (needs, inner.pac_url.clone())
        };

        if needs_fetch {
            if let Some(url) = pac_url {
                match fetch_pac(&url).await {
                    Ok(script) => {
                        let mut inner = self.inner.lock().unwrap();
                        inner.script = Some(script);
                        inner.fetched_at = Some(Instant::now());
                        inner.host_cache.clear(); // new script, invalidate cache
                        if inner.state == PacState::Unreachable {
                            info!("PAC URL reachable again — VPN connected, resuming proxying");
                        }
                        inner.state = PacState::Healthy;
                        debug!("PAC script loaded from {}", url);
                    }
                    Err(e) => {
                        let mut inner = self.inner.lock().unwrap();
                        if inner.state != PacState::Unreachable {
                            warn!(
                                "PAC URL unreachable ({}) — falling back to DIRECT for all traffic. \
                                 Will auto-recover when VPN reconnects.",
                                e
                            );
                        }
                        inner.state = PacState::Unreachable;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Build a simple hash of active non-loopback network interfaces.
fn hash_network_interfaces() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();

    match network_interface_names() {
        Ok(mut names) => {
            names.sort();
            names.hash(&mut hasher);
        }
        Err(_) => {
            hasher.write_u8(0);
        }
    }
    hasher.finish()
}

#[cfg(any(target_os = "macos", target_os = "linux"))]
fn network_interface_names() -> Result<Vec<String>> {
    use std::ffi::CStr;
    unsafe {
        let mut ifap: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifap) != 0 {
            return Err(anyhow::anyhow!("getifaddrs failed"));
        }
        let mut names = Vec::new();
        let mut ptr = ifap;
        while !ptr.is_null() {
            let addr = (*ptr).ifa_addr;
            let name = CStr::from_ptr((*ptr).ifa_name).to_string_lossy().to_string();
            if !name.starts_with("lo") && !name.starts_with("llw") && !name.starts_with("anpi")
                && !name.starts_with("utun") && !name.starts_with("gif")
                && !name.starts_with("stf")
            {
                let is_link_local = !addr.is_null()
                    && (*addr).sa_family == libc::AF_INET6 as libc::sa_family_t;
                if !is_link_local {
                    names.push(name);
                }
            }
            ptr = (*ptr).ifa_next;
        }
        libc::freeifaddrs(ifap);
        Ok(names)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn network_interface_names() -> Result<Vec<String>> {
    Ok(Vec::new())
}

/// Reusable reqwest client for PAC fetching — avoids creating a new
/// client + TLS config on every PAC refresh.
fn pac_http_client() -> &'static reqwest::Client {
    use std::sync::OnceLock;
    static CLIENT: OnceLock<reqwest::Client> = OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .tls_built_in_root_certs(true)
            .timeout(Duration::from_secs(5))
            .build()
            .expect("Failed to build PAC HTTP client")
    })
}

async fn fetch_pac(url: &str) -> Result<String> {
    let body = pac_http_client().get(url).send().await?.text().await?;
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
