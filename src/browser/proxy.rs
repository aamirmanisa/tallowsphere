//! Proxy rotation with residential/mobile/Tor/datacenter fallback chain.
//!
//! Supports sticky sessions per domain, health checking, geographic targeting,
//! and automatic IP rotation via airplane mode on mobile proxies.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// Proxy intelligence engine: ASN trust scores, per-domain strategy, learned
// block/success history, and diversity enforcement. Declared here (rather than
// in browser::mod, which is a sibling file we do not modify) so the
// intelligence-driven tier selector can be consulted from the live request
// path while keeping the static best-to-worst chain as the fallback.
#[path = "proxy_intelligence.rs"]
mod proxy_intelligence;
use self::proxy_intelligence::ProxyIntelligence;

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

/// Proxy quality tier — tried in order from best to worst.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ProxyTier {
    /// Mobile carrier IPs (T-Mobile, AT&T, Verizon). Highest trust.
    Mobile,
    /// Residential IPs from real home ISPs. High trust.
    Residential,
    /// ISP proxies — datacenter speed, residential ASN.
    Isp,
    /// Standard datacenter proxies. Low trust but fast.
    Datacenter,
    /// Tor exit nodes. Free but often blocked.
    Tor,
    /// Direct connection — no proxy.
    Direct,
}

impl ProxyTier {
    pub fn name(&self) -> &'static str {
        match self {
            ProxyTier::Mobile => "mobile",
            ProxyTier::Residential => "residential",
            ProxyTier::Isp => "isp",
            ProxyTier::Datacenter => "datacenter",
            ProxyTier::Tor => "tor",
            ProxyTier::Direct => "direct",
        }
    }

    /// All tiers in fallback order.
    ///
    /// `Direct` is terminal and opt-in only (F-3): egress selection refuses
    /// to hand back a Direct entry unless direct egress was explicitly opted
    /// in (`ProxyPool::allow_direct_egress`, or a caller's `tier:"direct"`).
    /// The chain member is kept for ordering/status reporting; selection is
    /// where the fail-open is closed.
    pub fn fallback_chain() -> &'static [ProxyTier] {
        &[
            ProxyTier::Mobile,
            ProxyTier::Residential,
            ProxyTier::Isp,
            ProxyTier::Datacenter,
            ProxyTier::Tor,
            ProxyTier::Direct,
        ]
    }
}

/// A proxy endpoint.
#[derive(Debug, Clone)]
pub struct ProxyEntry {
    /// URL: socks5://host:port, http://host:port, https://host:port
    pub url: String,
    /// Quality tier.
    pub tier: ProxyTier,
    /// Optional country code (e.g., "US", "GB", "DE").
    pub country: Option<String>,
    /// Optional label for identification.
    pub label: String,
    /// Optional proxy-authentication username (RFC 1929 for SOCKS5, Basic for HTTP).
    ///
    /// Commercial residential/mobile gateways (Bright Data, Oxylabs, IPRoyal,
    /// Smartproxy, Webshare) all use a single user:pass gateway where the
    /// username encodes country/ASN/session. Without this field those tiers
    /// are unusable — the old code silently did no-auth handshakes only.
    pub username: Option<String>,
    /// Optional proxy-authentication password.
    pub password: Option<String>,
}

impl ProxyEntry {
    /// Construct a proxy entry without authentication.
    pub fn new(url: &str, tier: ProxyTier) -> Self {
        Self {
            url: url.to_string(),
            tier,
            country: None,
            label: String::new(),
            username: None,
            password: None,
        }
    }

    /// Construct an authenticated proxy entry (residential/mobile/ISP gateways).
    pub fn with_auth(url: &str, tier: ProxyTier, username: &str, password: &str) -> Self {
        Self {
            url: url.to_string(),
            tier,
            country: None,
            label: String::new(),
            username: Some(username.to_string()),
            password: Some(password.to_string()),
        }
    }

    /// The host:port component (URL without the scheme prefix).
    pub fn addr(&self) -> String {
        let l = self.url.to_lowercase();
        for prefix in ["socks5://", "http://", "https://", "socks5h://"] {
            if let Some(rest) = l.strip_prefix(prefix) {
                return rest.to_string();
            }
        }
        self.url.clone()
    }

    /// Whether this proxy requires authentication.
    pub fn has_auth(&self) -> bool {
        self.username.is_some()
    }
}

/// Health status of a proxy.
#[derive(Debug, Clone)]
pub struct ProxyHealth {
    pub alive: bool,
    pub last_check: Instant,
    pub avg_latency_ms: f64,
    pub success_count: u64,
    pub fail_count: u64,
    pub consecutive_fail: u32,
    /// Domains that have blocked this IP.
    pub banned_domains: HashSet<String>,
}

impl ProxyHealth {
    pub fn new() -> Self {
        Self {
            alive: true,
            last_check: Instant::now(),
            avg_latency_ms: 0.0,
            success_count: 0,
            fail_count: 0,
            consecutive_fail: 0,
            banned_domains: HashSet::new(),
        }
    }

    pub fn success_rate(&self) -> f64 {
        let total = self.success_count + self.fail_count;
        if total == 0 { return 1.0; }
        self.success_count as f64 / total as f64
    }

    pub fn score(&self) -> f64 {
        let rate = self.success_rate();
        let latency_score = 1.0 - (self.avg_latency_ms / 10000.0).min(1.0);
        let fresh = if self.last_check.elapsed() < Duration::from_secs(120) { 1.0 } else { 0.5 };
        rate * 0.6 + latency_score * 0.3 + fresh * 0.1
    }

    pub fn record_success(&mut self, latency_ms: f64) {
        self.alive = true;
        self.success_count += 1;
        self.consecutive_fail = 0;
        self.last_check = Instant::now();
        // Exponential moving average
        self.avg_latency_ms = self.avg_latency_ms * 0.8 + latency_ms * 0.2;
    }

    pub fn record_failure(&mut self, domain: Option<&str>) {
        self.fail_count += 1;
        self.consecutive_fail += 1;
        self.last_check = Instant::now();
        if self.consecutive_fail >= 5 {
            self.alive = false;
        }
        if let Some(d) = domain {
            self.banned_domains.insert(d.to_string());
        }
    }
}

/// A sticky session — same proxy for a domain during a time window.
#[derive(Debug, Clone)]
pub struct StickySession {
    pub proxy_index: usize,
    pub domain: String,
    pub started: Instant,
    pub duration: Duration,
    pub request_count: u32,
}

impl StickySession {
    pub fn is_valid(&self) -> bool {
        self.started.elapsed() < self.duration
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Proxy Pool
// ─────────────────────────────────────────────────────────────────────────────

/// Multi-tier proxy pool with fallback, health checking, and sticky sessions.
#[derive(Debug)]
pub struct ProxyPool {
    pub(crate) proxies: Vec<ProxyEntry>,
    pub(crate) health: Vec<ProxyHealth>,
    /// Sticky sessions per domain.
    pub(crate) sticky: HashMap<String, StickySession>,
    /// Round-robin index per tier.
    robin_index: HashMap<ProxyTier, AtomicUsize>,
    /// Cooldown: (domain, proxy_index) → last used time.
    domain_cooldown: HashMap<(String, usize), Instant>,
    /// Default sticky session duration.
    pub sticky_duration: Duration,
    /// Per-domain cooldown before reusing same proxy.
    pub domain_cooldown_secs: u64,
    /// Total requests routed.
    pub total_requests: AtomicU64,
    /// Proxy intelligence engine: ASN trust, per-domain strategy, and learned
    /// block/success history used to guide egress selection (consulted before
    /// the static fallback chain).
    intelligence: Arc<Mutex<ProxyIntelligence>>,
    /// Per-domain risk-escalation level (0 = none, 1 = residential+, 2 = mobile+).
    /// Raised on a block signal so the domain's tier escalates DC->residential->mobile.
    domain_escalation: HashMap<String, u8>,
    /// Explicit direct-egress opt-in (F-3). `false` (default): egress
    /// selection for a domain REFUSES (`None`) rather than handing back a
    /// `ProxyTier::Direct` entry when no higher tier can serve — the
    /// unknown-domain default fails closed instead of silently egressing
    /// from the box IP. `true`: the caller explicitly chose direct egress.
    pub allow_direct_egress: bool,
}

impl ProxyPool {
    pub fn new() -> Self {
        Self {
            proxies: Vec::new(),
            health: Vec::new(),
            sticky: HashMap::new(),
            robin_index: HashMap::new(),
            domain_cooldown: HashMap::new(),
            sticky_duration: Duration::from_secs(300), // 5 min default
            domain_cooldown_secs: 1800,                // 30 min default
            total_requests: AtomicU64::new(0),
            intelligence: Arc::new(Mutex::new(ProxyIntelligence::new())),
            domain_escalation: HashMap::new(),
            allow_direct_egress: false,
        }
    }

    /// Add a proxy to the pool.
    pub fn add(&mut self, entry: ProxyEntry) {
        let tier = entry.tier;
        let country = entry.country.clone();
        self.proxies.push(entry);
        self.health.push(ProxyHealth::new());
        self.robin_index.entry(tier).or_insert_with(|| AtomicUsize::new(0));

        // Register ASN metadata (inferred from tier when the real ASN is unknown)
        // so the intelligence engine can score this proxy during selection.
        let idx = self.proxies.len() - 1;
        if let Ok(mut eng) = self.intelligence.lock() {
            eng.register_proxy_from_tier(idx, tier, country.as_deref());
        }
    }

    /// Add multiple proxies from a list of URL strings with a given tier.
    pub fn add_list(&mut self, urls: &[&str], tier: ProxyTier) {
        for url in urls {
            self.add(ProxyEntry::new(url, tier));
        }
    }

    /// Add Tor SOCKS proxies (auto-generated from instance count).
    pub fn add_tor_instances(&mut self, count: usize, base_port: u16) {
        for i in 0..count {
            let port = base_port + (i as u16) * 2;
            self.add(ProxyEntry::new(
                &format!("socks5://127.0.0.1:{port}"),
                ProxyTier::Tor,
            ));
            if let Some(last) = self.proxies.last_mut() {
                last.label = format!("tor-{i}");
            }
        }
    }

    /// Total proxies in pool.
    pub fn len(&self) -> usize {
        self.proxies.len()
    }

    pub fn is_empty(&self) -> bool {
        self.proxies.is_empty()
    }

    /// Get proxies by tier.
    pub fn by_tier(&self, tier: ProxyTier) -> Vec<(usize, &ProxyEntry)> {
        self.proxies.iter().enumerate()
            .filter(|(_, p)| p.tier == tier)
            .collect()
    }

    /// Get the best proxy for a domain, using sticky sessions and fallback.
    ///
    /// Consults the proxy-intelligence tier selector first (ASN trust, per-domain
    /// strategy, learned block/success history, diversity enforcement), then falls
    /// back to the static best-to-worst tier chain when the engine cannot decide.
    pub fn get_proxy(&mut self, domain: &str) -> Option<&ProxyEntry> {
        self.total_requests.fetch_add(1, Ordering::Relaxed);
        self.select_egress_for_domain(domain)
    }

    /// Intelligence-aware egress selection for a domain.
    ///
    /// 1. Reuse a valid sticky session for the domain if one exists.
    /// 2. Ask `ProxyIntelligence::select_best` for the highest-scoring proxy
    ///    given the domain's strategy (required ASN type, min trust, known
    ///    blocked ASNs, diversity) — this is the smarter selector that was
    ///    previously referenced only from tests.
    /// 3. Fall back to the static best-to-worst tier chain (respecting the
    ///    per-domain risk-escalation level) when the engine finds nothing.
    ///
    /// F-3 default-refuse: a `ProxyTier::Direct` entry is never returned
    /// unless `allow_direct_egress` was explicitly opted in. When every
    /// non-direct tier is exhausted the selector refuses (`None`) instead of
    /// silently degrading to a direct, box-IP egress.
    pub fn select_egress_for_domain(&mut self, domain: &str) -> Option<&ProxyEntry> {
        // 1. Valid sticky session — same proxy for the domain during the window.
        if let Some(session) = self.sticky.get(domain) {
            if session.is_valid() {
                let idx = session.proxy_index;
                if self.health[idx].alive
                    && !self.health[idx].banned_domains.contains(domain)
                    // F-3: a sticky binding must not hand back a Direct entry
                    // unless the explicit opt-in is set.
                    && (self.allow_direct_egress || self.proxies[idx].tier != ProxyTier::Direct)
                {
                    return Some(&self.proxies[idx]);
                }
            }
        }

        // 2. Intelligence-guided selection (ASN trust, per-domain strategy,
        //    learned block/success history, diversity). Filter out dead/banned.
        let best = self
            .intelligence
            .lock()
            .ok()
            .and_then(|eng| {
                eng.select_best(self, domain).filter(|i| {
                    // F-3: Direct entries are opt-in only, also from the
                    // intelligence selector.
                    self.health[*i].alive
                        && !self.health[*i].banned_domains.contains(domain)
                        && (self.allow_direct_egress
                            || self.proxies[*i].tier != ProxyTier::Direct)
                })
            });

        if let Some(proxy_idx) = best {
            self.sticky.insert(
                domain.to_string(),
                StickySession {
                    proxy_index: proxy_idx,
                    domain: domain.to_string(),
                    started: Instant::now(),
                    duration: self.sticky_duration,
                    request_count: 0,
                },
            );
            return Some(&self.proxies[proxy_idx]);
        }

        // 3. Static best-to-worst tier chain as fallback, honouring the
        //    per-domain risk-escalation level (DC -> residential -> mobile).
        self.select_fallback_chain(domain)
    }

    /// Static best-to-worst tier fallback, filtered by the domain's risk
    /// escalation level so a blocked domain stops using low-trust tiers.
    fn select_fallback_chain(&mut self, domain: &str) -> Option<&ProxyEntry> {
        // Risk-adaptive escalation floor: level 1 excludes datacenter/Tor/direct,
        // level 2 additionally excludes ISP proxies.
        let level = self.domain_escalation.get(domain).copied().unwrap_or(0);

        for tier in ProxyTier::fallback_chain() {
            let too_low = match level {
                0 => false,
                1 => matches!(
                    tier,
                    ProxyTier::Datacenter | ProxyTier::Tor | ProxyTier::Direct
                ),
                2 => matches!(
                    tier,
                    ProxyTier::Isp
                        | ProxyTier::Datacenter
                        | ProxyTier::Tor
                        | ProxyTier::Direct
                ),
                _ => false,
            };
            if too_low {
                continue;
            }
            // F-3 default-refuse: the unknown-domain path must fail closed —
            // never select a Direct entry unless direct egress was explicitly
            // opted in. (The chain member stays for ordering/status; the
            // refusal happens here, upstream of `--proxy-server` wiring.)
            if *tier == ProxyTier::Direct && !self.allow_direct_egress {
                continue;
            }

            let candidates: Vec<usize> = self.proxies.iter().enumerate()
                .filter(|(i, p)| {
                    p.tier == *tier
                    && self.health[*i].alive
                    && !self.health[*i].banned_domains.contains(domain)
                    && self.health[*i].score() > 0.3
                })
                .map(|(i, _)| i)
                .collect();

            if candidates.is_empty() {
                continue;
            }

            // Round-robin within tier
            let robin = self.robin_index.entry(*tier).or_insert_with(|| AtomicUsize::new(0));
            let idx_in_tier = robin.fetch_add(1, Ordering::Relaxed) % candidates.len();
            let proxy_idx = candidates[idx_in_tier];

            // Create sticky session
            self.sticky.insert(domain.to_string(), StickySession {
                proxy_index: proxy_idx,
                domain: domain.to_string(),
                started: Instant::now(),
                duration: self.sticky_duration,
                request_count: 0,
            });

            return Some(&self.proxies[proxy_idx]);
        }

        None // All tiers exhausted
    }

    /// Get proxy for a domain with geographic preference.
    pub fn get_proxy_geo(&mut self, domain: &str, country: &str) -> Option<&ProxyEntry> {
        // Try geo-matched first
        for tier in ProxyTier::fallback_chain() {
            let geo_match: Vec<usize> = self.proxies.iter().enumerate()
                .filter(|(i, p)| {
                    p.tier == *tier
                    && self.health[*i].alive
                    && p.country.as_deref() == Some(country)
                })
                .map(|(i, _)| i)
                .collect();

            if !geo_match.is_empty() {
                let idx = geo_match[0]; // Simple first-match for geo
                return Some(&self.proxies[idx]);
            }
        }

        // Fall back to any proxy
        self.get_proxy(domain)
    }

    /// Report a successful request through a proxy.
    pub fn report_success(&mut self, proxy_url: &str, latency_ms: f64) {
        if let Some(idx) = self.proxies.iter().position(|p| p.url == proxy_url) {
            self.health[idx].record_success(latency_ms);
        }
    }

    /// Report a failed/blocked request through a proxy.
    pub fn report_failure(&mut self, proxy_url: &str, domain: &str) {
        if let Some(idx) = self.proxies.iter().position(|p| p.url == proxy_url) {
            self.health[idx].record_failure(Some(domain));

            // If proxy is dead, invalidate sticky sessions using it
            if !self.health[idx].alive {
                self.sticky.retain(|_, s| s.proxy_index != idx);
            }
        }
    }

    /// Report a *blocked* request (403 / CAPTCHA / challenge / WAF detection).
    ///
    /// In addition to the health failure bookkeeping in `report_failure`, this
    /// triggers risk-adaptive escalation: the domain's tier is promoted
    /// DC -> residential -> mobile for subsequent requests, so a hard target
    /// stops being routed through low-trust datacenter/ISP proxies. Both the
    /// static fallback chain and the intelligence engine honour the new level.
    pub fn report_blocked(&mut self, proxy_url: &str, domain: &str) {
        if let Some(idx) = self.proxies.iter().position(|p| p.url == proxy_url) {
            self.health[idx].record_failure(Some(domain));
            if !self.health[idx].alive {
                self.sticky.retain(|_, s| s.proxy_index != idx);
            }
        }

        // Escalate DC -> residential -> mobile (levels 0 -> 1 -> 2).
        let escalated = {
            let level = self.domain_escalation.entry(domain.to_string()).or_insert(0);
            if *level < 2 {
                *level += 1;
                true
            } else {
                false
            }
        };
        // Mirror the escalation into the intelligence engine so `select_best`
        // also enforces the higher-tier floor for this domain.
        if escalated {
            if let Ok(mut eng) = self.intelligence.lock() {
                eng.escalate_domain(domain);
            }
        }
    }

    /// Get health summary for all proxies.
    pub fn health_summary(&self) -> Vec<(&ProxyEntry, &ProxyHealth)> {
        self.proxies.iter().zip(self.health.iter()).collect()
    }

    /// Count alive proxies per tier.
    pub fn alive_by_tier(&self) -> HashMap<ProxyTier, usize> {
        let mut counts = HashMap::new();
        for (i, p) in self.proxies.iter().enumerate() {
            if self.health[i].alive {
                *counts.entry(p.tier).or_insert(0) += 1;
            }
        }
        counts
    }

    /// Expire old sticky sessions and domain cooldowns.
    pub fn cleanup(&mut self) {
        self.sticky.retain(|_, s| s.is_valid());
        let cutoff = Duration::from_secs(self.domain_cooldown_secs);
        self.domain_cooldown.retain(|_, t| t.elapsed() < cutoff);
    }

    /// Reset health for a specific proxy (e.g., after IP rotation).
    pub fn reset_health(&mut self, proxy_url: &str) {
        if let Some(idx) = self.proxies.iter().position(|p| p.url == proxy_url) {
            self.health[idx] = ProxyHealth::new();
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Background Health Checker
// ─────────────────────────────────────────────────────────────────────────────

/// Build the RFC 7617 `Basic` credential value (`Basic base64(user:pass)`)
/// used for HTTP-proxy authentication, or `None` when the proxy carries no
/// credentials. The same `user:pass` pair is used for the RFC 1929 SOCKS5
/// username/password handshake.
fn basic_auth_value(username: Option<&str>, password: Option<&str>) -> Option<String> {
    match (username, password) {
        (Some(u), Some(p)) => {
            use base64::Engine as _;
            let creds = format!("{u}:{p}");
            Some(format!(
                "Basic {}",
                base64::engine::general_purpose::STANDARD.encode(creds.as_bytes())
            ))
        }
        _ => None,
    }
}

/// The full CRLF-terminated `Proxy-Authorization` header line to send to an
/// HTTP proxy, or an empty string when the proxy needs no credentials.
///
/// The trailing CRLF is required: the caller appends the next header
/// (`Connection: close`) directly after this string, so without it the two
/// headers would be glued onto one line and the request would be malformed.
fn proxy_auth_header_line(basic_auth: &Option<String>) -> String {
    match basic_auth {
        Some(a) => format!("Proxy-Authorization: {a}\r\n"),
        None => String::new(),
    }
}

/// Check a single proxy by making a lightweight HTTP request through it.
///
/// For SOCKS5 proxies, connects via SOCKS5 handshake then sends HTTP.
/// For HTTP proxies, sends a CONNECT-style request.
/// Returns `Ok(latency_ms)` on success, `Err(reason)` on failure.
async fn check_proxy_health(
    proxy_url: &str,
    username: Option<&str>,
    password: Option<&str>,
) -> Result<f64, String> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let start = Instant::now();
    let timeout = Duration::from_secs(10);

    // Basic auth header for HTTP proxies, and RFC 1929 credentials for SOCKS5.
    let basic_auth: Option<String> = basic_auth_value(username, password);

    // Parse proxy URL: socks5h://host:port (remote DNS), socks5://host:port,
    // or http(s)://host:port. SOCKS5h resolves the target hostname remotely
    // (the health probe already sends the domain name via ATYP=3), which is
    // required for .onion / DNS-at-the-exit routing.
    let url_lower = proxy_url.to_lowercase();
    let (is_socks5, addr) = if let Some(rest) = url_lower.strip_prefix("socks5h://") {
        (true, rest.to_string())
    } else if let Some(rest) = url_lower.strip_prefix("socks5://") {
        (true, rest.to_string())
    } else if let Some(rest) = url_lower.strip_prefix("http://") {
        (false, rest.to_string())
    } else if let Some(rest) = url_lower.strip_prefix("https://") {
        (false, rest.to_string())
    } else {
        return Err(format!("unsupported proxy scheme: {proxy_url}"));
    };

    // Connect to proxy with timeout
    let stream = tokio::time::timeout(timeout, TcpStream::connect(&addr))
        .await
        .map_err(|_| "connection timeout".to_string())?
        .map_err(|e| format!("connect failed: {e}"))?;

    if is_socks5 {
        // SOCKS5 handshake (RFC 1929 user/pass auth when credentials provided)
        let mut stream = stream;

        // Greeting: VER=5, NMETHODS, METHODS. Offer no-auth (0x00) and
        // username/password (0x02) when credentials are present.
        let methods: &[u8] = if basic_auth.is_some() { &[0x00, 0x02] } else { &[0x00] };
        let mut greeting = vec![0x05, methods.len() as u8];
        greeting.extend_from_slice(methods);
        stream.write_all(&greeting).await
            .map_err(|e| format!("socks5 greeting write: {e}"))?;

        let mut buf = [0u8; 2];
        stream.read_exact(&mut buf).await
            .map_err(|e| format!("socks5 greeting read: {e}"))?;
        if buf[0] != 0x05 {
            return Err(format!("socks5 greeting bad ver: {:02x}", buf[0]));
        }

        // If the server selected user/pass (0x02), perform RFC 1929 auth.
        if buf[1] == 0x02 {
            let (u, p) = (username.unwrap_or(""), password.unwrap_or(""));
            if u.len() > 255 || p.len() > 255 {
                return Err("socks5 credentials too long".to_string());
            }
            let mut auth = vec![0x01, u.len() as u8];
            auth.extend_from_slice(u.as_bytes());
            auth.push(p.len() as u8);
            auth.extend_from_slice(p.as_bytes());
            stream.write_all(&auth).await
                .map_err(|e| format!("socks5 auth write: {e}"))?;
            let mut abuf = [0u8; 2];
            stream.read_exact(&mut abuf).await
                .map_err(|e| format!("socks5 auth read: {e}"))?;
            if abuf[0] != 0x01 || abuf[1] != 0x00 {
                return Err(format!("socks5 auth rejected: status={}", abuf[1]));
            }
        } else if buf[1] != 0x00 {
            return Err(format!("socks5 auth method rejected: {:02x}", buf[1]));
        }

        // Connect request to httpbin.org:80
        // VER=5, CMD=1(connect), RSV=0, ATYP=3(domain)
        let target_host = b"httpbin.org";
        let target_port: u16 = 80;
        let mut req = vec![0x05, 0x01, 0x00, 0x03, target_host.len() as u8];
        req.extend_from_slice(target_host);
        req.push((target_port >> 8) as u8);
        req.push((target_port & 0xff) as u8);

        stream.write_all(&req).await
            .map_err(|e| format!("socks5 connect write: {e}"))?;

        // Read SOCKS5 reply (at least 10 bytes for IPv4 bind address)
        let mut reply = [0u8; 10];
        stream.read_exact(&mut reply).await
            .map_err(|e| format!("socks5 connect read: {e}"))?;
        if reply[1] != 0x00 {
            return Err(format!("socks5 connect failed: status={}", reply[1]));
        }

        // Send a minimal HTTP request through the tunnel
        let http_req = b"GET /ip HTTP/1.1\r\nHost: httpbin.org\r\nConnection: close\r\n\r\n";
        stream.write_all(http_req).await
            .map_err(|e| format!("http write: {e}"))?;

        // Read response (just enough to confirm it works)
        let mut resp_buf = vec![0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(8), stream.read(&mut resp_buf))
            .await
            .map_err(|_| "http read timeout".to_string())?
            .map_err(|e| format!("http read: {e}"))?;

        if n == 0 {
            return Err("empty response".to_string());
        }
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        if !resp_str.contains("200") && !resp_str.contains("HTTP/1.") {
            return Err(format!("unexpected response: {}", &resp_str[..resp_str.len().min(80)]));
        }
    } else {
        // HTTP proxy: use CONNECT-style or plain GET
        let mut stream = stream;
        // Send the REAL computed credentials (RFC 7617 Basic). A previous
        // version of this line used a format string with no `{}` placeholder
        // (`format!("Proxy-Authorization: ***")`), which put the literal
        // `Proxy-Authorization: ***` on the wire — with no trailing CRLF the
        // following `Connection:` header was glued onto the same line — so
        // every authenticated HTTP proxy (IPRoyal/Oxylabs/BrightData style)
        // failed the health check and got marked dead.
        let auth_header = proxy_auth_header_line(&basic_auth);
        let http_req = format!(
            "GET http://httpbin.org/ip HTTP/1.1\r\nHost: httpbin.org\r\n{auth_header}Connection: close\r\n\r\n"
        );
        stream.write_all(http_req.as_bytes()).await
            .map_err(|e| format!("http write: {e}"))?;

        let mut resp_buf = vec![0u8; 512];
        let n = tokio::time::timeout(Duration::from_secs(8), stream.read(&mut resp_buf))
            .await
            .map_err(|_| "http read timeout".to_string())?
            .map_err(|e| format!("http read: {e}"))?;

        if n == 0 {
            return Err("empty response".to_string());
        }
        let resp_str = String::from_utf8_lossy(&resp_buf[..n]);
        if !resp_str.contains("200") && !resp_str.contains("HTTP/1.") {
            return Err(format!("unexpected response: {}", &resp_str[..resp_str.len().min(80)]));
        }
    }

    let latency = start.elapsed().as_secs_f64() * 1000.0;
    Ok(latency)
}

impl ProxyPool {
    /// Spawn a background tokio task that periodically health-checks all proxies.
    ///
    /// Every `interval_secs`, each proxy is tested with a lightweight HTTP request
    /// through the proxy tunnel. Health scores are updated based on response time
    /// and success/failure. Proxies with >80% failure rate are marked dead and
    /// removed from the active pool.
    ///
    /// The pool must be wrapped in `Arc<Mutex<ProxyPool>>` for shared access.
    /// Returns a `JoinHandle` that can be used to abort the background task.
    pub fn start_health_check(
        pool: Arc<Mutex<ProxyPool>>,
        interval_secs: u64,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;

                // Snapshot the proxy URLs + credentials and indices to check
                let proxies_to_check: Vec<(usize, String, Option<String>, Option<String>)> = {
                    let pool_guard = pool.lock().unwrap();
                    pool_guard.proxies.iter().enumerate()
                        .map(|(i, p)| (i, p.url.clone(), p.username.clone(), p.password.clone()))
                        .collect()
                };

                if proxies_to_check.is_empty() {
                    continue;
                }

                // Check each proxy concurrently (up to 20 at a time)
                let semaphore = Arc::new(tokio::sync::Semaphore::new(20));
                let results: Arc<Mutex<Vec<(usize, Result<f64, String>)>>> =
                    Arc::new(Mutex::new(Vec::new()));

                let mut handles = Vec::new();
                for (idx, proxy_url, username, password) in proxies_to_check {
                    let sem = semaphore.clone();
                    let res = results.clone();
                    let url = proxy_url.clone();
                    let uname = username.clone();
                    let pword = password.clone();

                    let handle = tokio::spawn(async move {
                        let _permit = sem.acquire().await.unwrap();
                        let result = check_proxy_health(&url, uname.as_deref(), pword.as_deref()).await;
                        res.lock().unwrap().push((idx, result));
                    });
                    handles.push(handle);
                }

                // Wait for all checks to complete
                for handle in handles {
                    let _ = handle.await;
                }

                // Apply results to the pool
                let check_results: Vec<(usize, Result<f64, String>)> = {
                    let guard = results.lock().unwrap();
                    guard.clone()
                };

                let mut pool_guard = pool.lock().unwrap();

                // Track indices to remove (dead proxies)
                let mut dead_indices: Vec<usize> = Vec::new();

                for (idx, result) in &check_results {
                    let idx = *idx;
                    if idx >= pool_guard.health.len() {
                        continue;
                    }

                    match result {
                        Ok(latency_ms) => {
                            pool_guard.health[idx].record_success(*latency_ms);
                            // Probe-before-crawl: screen the proxy's IP against
                            // the external reputation feed (IPQS/ipinfo). Fail-
                            // open — on lookup error a neutral record is stored
                            // and no trust change happens, so the pool survives.
                            if idx < pool_guard.proxies.len() {
                                let addr = pool_guard.proxies[idx].addr();
                                if let Some(host) = addr.split(':').next().map(str::to_string) {
                                    if !host.is_empty() {
                                        if let Ok(mut eng) = pool_guard.intelligence.lock() {
                                            eng.refresh_reputation(idx, &host, 0);
                                        }
                                    }
                                }
                            }
                        }
                        Err(_) => {
                            pool_guard.health[idx].record_failure(None);
                        }
                    }

                    // Check if proxy has >80% failure rate and mark dead
                    let health = &pool_guard.health[idx];
                    let total = health.success_count + health.fail_count;
                    if total >= 5 {
                        let failure_rate = health.fail_count as f64 / total as f64;
                        if failure_rate > 0.80 {
                            pool_guard.health[idx].alive = false;
                            dead_indices.push(idx);
                        }
                    }
                }

                // Remove dead proxies from the pool (iterate in reverse to preserve indices)
                dead_indices.sort_unstable();
                dead_indices.dedup();
                for &idx in dead_indices.iter().rev() {
                    if idx < pool_guard.proxies.len() {
                        let removed_url = pool_guard.proxies[idx].url.clone();
                        pool_guard.proxies.remove(idx);
                        pool_guard.health.remove(idx);

                        // Keep the intelligence engine's proxy_asn vector
                        // index-aligned with the pool.
                        if let Ok(mut eng) = pool_guard.intelligence.lock() {
                            if idx < eng.proxy_asn.len() {
                                eng.proxy_asn.remove(idx);
                            }
                            if idx < eng.external_reputation.len() {
                                eng.external_reputation.remove(idx);
                            }
                        }

                        // Invalidate sticky sessions that reference this or later indices
                        pool_guard.sticky.retain(|_, s| {
                            if s.proxy_index == idx {
                                return false;
                            }
                            // Adjust indices for entries after the removed one
                            if s.proxy_index > idx {
                                // Note: we can't mutate through retain, so we just
                                // invalidate sessions with shifted indices to be safe
                                return false;
                            }
                            true
                        });

                        eprintln!(
                            "[tallow] proxy health: removed dead proxy {} (>80% failure rate)",
                            removed_url
                        );
                    }
                }

                // Also run periodic cleanup of expired sticky sessions
                pool_guard.cleanup();
            }
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Mobile proxy IP rotation helper
// ─────────────────────────────────────────────────────────────────────────────

/// Instructions for rotating mobile proxy IP via airplane mode.
/// This is used when the mobile proxy is controlled via ADB.
pub struct MobileRotation;

impl MobileRotation {
    /// ADB command to toggle airplane mode for IP rotation.
    pub fn adb_rotation_commands() -> Vec<&'static str> {
        vec![
            "adb shell cmd connectivity airplane-mode enable",
            "sleep 3",
            "adb shell cmd connectivity airplane-mode disable",
            "sleep 8", // Wait for reconnect + new IP assignment
        ]
    }

    /// Estimated time for a full airplane mode rotation cycle.
    pub fn rotation_duration() -> Duration {
        Duration::from_secs(11) // 3s off + 8s reconnect
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Free proxy list scraper
// ─────────────────────────────────────────────────────────────────────────────

/// Known free proxy list sources.
pub const FREE_PROXY_SOURCES: &[&str] = &[
    "https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=5000&country=all",
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
];

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_pool_basic() {
        let mut pool = ProxyPool::new();
        pool.add(ProxyEntry {
            url: "socks5://10.0.0.1:1080".into(),
            tier: ProxyTier::Residential,
            country: Some("US".into()),
            label: "res-1".into(),
            username: None,
            password: None,
        });
        pool.add(ProxyEntry {
            url: "socks5://10.0.0.2:1080".into(),
            tier: ProxyTier::Datacenter,
            country: Some("US".into()),
            label: "dc-1".into(),
            username: None,
            password: None,
        });

        assert_eq!(pool.len(), 2);
        assert!(!pool.is_empty());

        // Should prefer residential
        let proxy = pool.get_proxy("example.com").unwrap();
        assert_eq!(proxy.tier, ProxyTier::Residential);
    }

    #[test]
    fn proxy_fallback_on_failure() {
        let mut pool = ProxyPool::new();
        pool.add(ProxyEntry {
            url: "socks5://10.0.0.1:1080".into(),
            tier: ProxyTier::Residential,
            country: None,
            label: "res-1".into(),
            username: None,
            password: None,
        });
        pool.add(ProxyEntry {
            url: "socks5://10.0.0.2:1080".into(),
            tier: ProxyTier::Datacenter,
            country: None,
            label: "dc-1".into(),
            username: None,
            password: None,
        });

        // Kill residential proxy
        for _ in 0..6 {
            pool.report_failure("socks5://10.0.0.1:1080", "amazon.com");
        }

        // Should fall back to datacenter
        let proxy = pool.get_proxy("amazon.com").unwrap();
        assert_eq!(proxy.tier, ProxyTier::Datacenter);
    }

    #[test]
    fn sticky_session() {
        let mut pool = ProxyPool::new();
        pool.add(ProxyEntry {
            url: "socks5://10.0.0.1:1080".into(),
            tier: ProxyTier::Residential,
            country: None,
            label: "res-1".into(),
            username: None,
            password: None,
        });
        pool.add(ProxyEntry {
            url: "socks5://10.0.0.2:1080".into(),
            tier: ProxyTier::Residential,
            country: None,
            label: "res-2".into(),
            username: None,
            password: None,
        });

        let first = pool.get_proxy("walmart.com").unwrap().url.clone();
        let second = pool.get_proxy("walmart.com").unwrap().url.clone();

        // Sticky session: same proxy for same domain
        assert_eq!(first, second);
    }

    #[test]
    fn health_scoring() {
        let mut h = ProxyHealth::new();
        assert!(h.score() > 0.8);

        for _ in 0..10 {
            h.record_success(100.0);
        }
        assert!(h.score() > 0.8);

        for _ in 0..50 {
            h.record_failure(None);
        }
        assert!(h.score() < 0.5);
    }

    #[test]
    fn tor_instances() {
        let mut pool = ProxyPool::new();
        pool.add_tor_instances(3, 9050);
        assert_eq!(pool.len(), 3);

        let tor_proxies = pool.by_tier(ProxyTier::Tor);
        assert_eq!(tor_proxies.len(), 3);
        assert_eq!(tor_proxies[0].1.url, "socks5://127.0.0.1:9050");
        assert_eq!(tor_proxies[1].1.url, "socks5://127.0.0.1:9052");
        assert_eq!(tor_proxies[2].1.url, "socks5://127.0.0.1:9054");
    }

    #[test]
    fn alive_by_tier() {
        let mut pool = ProxyPool::new();
        pool.add_list(&["socks5://a:1", "socks5://b:1"], ProxyTier::Residential);
        pool.add_list(&["socks5://c:1"], ProxyTier::Datacenter);

        let counts = pool.alive_by_tier();
        assert_eq!(counts[&ProxyTier::Residential], 2);
        assert_eq!(counts[&ProxyTier::Datacenter], 1);
    }

    #[test]
    fn fallback_chain_order() {
        let chain = ProxyTier::fallback_chain();
        assert_eq!(chain[0], ProxyTier::Mobile);
        assert_eq!(chain[1], ProxyTier::Residential);
        assert_eq!(chain[5], ProxyTier::Direct);
    }

    #[test]
    fn unknown_domain_refuses_direct_by_default() {
        // F-3: the fallback chain must not hand back a Direct entry for an
        // unknown domain while `allow_direct_egress` is off (default) — the
        // selector refuses (`None`) instead of silently egressing from the
        // box IP. The explicit opt-in restores Direct selection.
        let mut pool = ProxyPool::new();
        pool.add(ProxyEntry::new("direct://box-ip", ProxyTier::Direct));

        assert!(
            pool.get_proxy("unknown-domain.example").is_none(),
            "default must refuse Direct instead of degrading to it"
        );

        pool.allow_direct_egress = true;
        assert_eq!(
            pool.get_proxy("unknown-domain.example").unwrap().tier,
            ProxyTier::Direct
        );
    }

    #[test]
    fn http_proxy_auth_header_emits_real_credentials() {
        // Regression: the health-check HTTP request previously rendered the
        // literal `Proxy-Authorization: ***` (a format string without a
        // `{}` placeholder) with no trailing CRLF, so every authenticated
        // HTTP proxy (IPRoyal/Oxylabs/BrightData style) failed the probe and
        // was marked dead. The header must carry the real RFC 7617 Basic
        // value and terminate its own line so the following `Connection:`
        // header is not glued onto it.
        let basic = basic_auth_value(Some("user"), Some("pass"));
        assert_eq!(basic.as_deref(), Some("Basic dXNlcjpwYXNz"));

        let line = proxy_auth_header_line(&basic);
        assert_eq!(line, "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n");
        assert!(!line.contains("***"), "credentials must not be redacted");
        assert!(line.ends_with("\r\n"), "header line must be CRLF-terminated");

        // The wire request the health checker sends must parse as clean
        // header lines (no glued headers).
        let request = format!(
            "GET http://httpbin.org/ip HTTP/1.1\r\nHost: httpbin.org\r\n{}Connection: close\r\n\r\n",
            proxy_auth_header_line(&basic)
        );
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
        assert!(request.contains("\r\nConnection: close\r\n"));
        assert!(!request.contains("***Connection"));

        // No credentials → no auth header line at all, request stays valid.
        let none_line = proxy_auth_header_line(&None);
        assert_eq!(none_line, "");
        assert!(basic_auth_value(None, Some("x")).is_none());
        assert!(basic_auth_value(Some("x"), None).is_none());
        assert!(basic_auth_value(None, None).is_none());
    }

    #[test]
    fn proxy_pool_failover_skips_dead_and_ban_listed() {
        // After enough failures a proxy must be skipped for the domain that
        // blocked it (banned_domains) and excluded once dead, with the pool
        // failing over to a live entry of the same tier.
        let mut pool = ProxyPool::new();
        pool.add_list(&["socks5://10.0.0.1:1080", "socks5://10.0.0.2:1080"], ProxyTier::Residential);

        // 10.0.0.1 fails for example.com only.
        for _ in 0..3 {
            pool.report_failure("socks5://10.0.0.1:1080", "example.com");
        }
        // Still alive overall, but ban-listed for example.com.
        assert!(pool.health[0].alive);
        assert!(pool.health[0].banned_domains.contains("example.com"));

        let proxy = pool.get_proxy("example.com").unwrap();
        assert_eq!(proxy.url, "socks5://10.0.0.2:1080", "banned proxy must be skipped");

        // Different domain can still be routed to proxy 0.
        let proxy2 = pool.get_proxy("other.org").unwrap();
        assert!(proxy2.url == "socks5://10.0.0.1:1080" || proxy2.url == "socks5://10.0.0.2:1080");

        // Kill proxy 0 outright (5 consecutive failures) → excluded everywhere.
        for _ in 0..6 {
            pool.report_failure("socks5://10.0.0.1:1080", "other.org");
        }
        assert!(!pool.health[0].alive);
        let proxy3 = pool.get_proxy("third.net").unwrap();
        assert_eq!(proxy3.url, "socks5://10.0.0.2:1080", "dead proxy must be excluded");
    }
}
