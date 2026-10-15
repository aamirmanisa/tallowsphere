//! Cookie farm — generates and manages anti-bot cookies (Akamai _abck,
//! Cloudflare cf_clearance, etc.) using real Chrome instances.
//!
//! Architecture: Pool of Chrome instances generate valid cookies, which are
//! shared with lightweight HTTP clients for high-volume scraping.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use serde_json::json;

use super::error::BrowserError;
use super::page::{Page, WaitUntil};

// ─────────────────────────────────────────────────────────────────────────────
// Cookie types
// ─────────────────────────────────────────────────────────────────────────────

/// Anti-bot cookie with metadata.
#[derive(Debug, Clone)]
pub struct AntiBotCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub path: String,
    pub secure: bool,
    pub http_only: bool,
    /// When this cookie was generated.
    pub generated_at: Instant,
    /// How long this cookie is valid.
    pub ttl: Duration,
    /// Which proxy IP generated this cookie (must reuse same IP).
    pub source_proxy: Option<String>,
    /// Which User-Agent generated this cookie (must reuse same UA).
    pub source_ua: String,
}

impl AntiBotCookie {
    /// Check if cookie is still valid.
    pub fn is_valid(&self) -> bool {
        self.generated_at.elapsed() < self.ttl
    }

    /// Time remaining before expiry.
    pub fn remaining(&self) -> Duration {
        self.ttl.saturating_sub(self.generated_at.elapsed())
    }

    /// Should refresh proactively (< 20% TTL remaining).
    pub fn needs_refresh(&self) -> bool {
        self.remaining() < self.ttl / 5
    }
}

/// Known anti-bot cookie names and their properties.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CookieType {
    /// Akamai Bot Manager.
    Akamai,
    /// Cloudflare.
    Cloudflare,
    /// PerimeterX / HUMAN.
    PerimeterX,
    /// DataDome.
    DataDome,
    /// Kasada.
    Kasada,
    /// Generic session cookie.
    Session,
}

impl CookieType {
    /// Cookie names associated with each anti-bot system.
    pub fn cookie_names(&self) -> &'static [&'static str] {
        match self {
            CookieType::Akamai => &["_abck", "ak_bmsc", "bm_sv", "bm_sz"],
            CookieType::Cloudflare => &["cf_clearance", "__cf_bm"],
            CookieType::PerimeterX => &["_px3", "_pxvid", "_pxde"],
            CookieType::DataDome => &["datadome"],
            CookieType::Kasada => &[], // Kasada uses headers, not cookies
            CookieType::Session => &[],
        }
    }

    /// Typical TTL for cookies from this system.
    pub fn typical_ttl(&self) -> Duration {
        match self {
            CookieType::Akamai => Duration::from_secs(300),     // 5 min effective
            CookieType::Cloudflare => Duration::from_secs(1800), // 30 min
            CookieType::PerimeterX => Duration::from_secs(900),  // 15 min
            CookieType::DataDome => Duration::from_secs(600),    // 10 min
            CookieType::Kasada => Duration::from_secs(300),      // 5 min
            CookieType::Session => Duration::from_secs(3600),    // 1 hour
        }
    }

    /// Detect which anti-bot system a domain uses based on cookie names.
    pub fn detect_from_cookies(cookie_names: &[&str]) -> Option<CookieType> {
        if cookie_names.iter().any(|n| *n == "_abck" || *n == "ak_bmsc") {
            return Some(CookieType::Akamai);
        }
        if cookie_names.iter().any(|n| *n == "cf_clearance" || *n == "__cf_bm") {
            return Some(CookieType::Cloudflare);
        }
        if cookie_names.iter().any(|n| n.starts_with("_px")) {
            return Some(CookieType::PerimeterX);
        }
        if cookie_names.iter().any(|n| *n == "datadome") {
            return Some(CookieType::DataDome);
        }
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cookie Jar (per-domain)
// ─────────────────────────────────────────────────────────────────────────────

/// A managed cookie jar for a single domain.
#[derive(Debug, Clone)]
pub struct DomainCookieJar {
    /// Domain this jar belongs to.
    pub domain: String,
    /// All cookies in this jar.
    pub cookies: Vec<AntiBotCookie>,
    /// Detected anti-bot system.
    pub antibot_type: Option<CookieType>,
    /// Last time cookies were refreshed.
    pub last_refresh: Instant,
    /// Number of refresh cycles.
    pub refresh_count: u32,
    /// Proxy that generated these cookies.
    pub proxy_url: Option<String>,
    /// User-Agent that generated these cookies.
    pub user_agent: String,
}

impl DomainCookieJar {
    pub fn new(domain: &str, user_agent: &str) -> Self {
        Self {
            domain: domain.to_string(),
            cookies: Vec::new(),
            antibot_type: None,
            last_refresh: Instant::now(),
            refresh_count: 0,
            proxy_url: None,
            user_agent: user_agent.to_string(),
        }
    }

    /// Add or update a cookie.
    pub fn set_cookie(&mut self, cookie: AntiBotCookie) {
        if let Some(existing) = self.cookies.iter_mut().find(|c| c.name == cookie.name) {
            *existing = cookie;
        } else {
            self.cookies.push(cookie);
        }
    }

    /// Get a cookie by name.
    pub fn get(&self, name: &str) -> Option<&AntiBotCookie> {
        self.cookies.iter().find(|c| c.name == name)
    }

    /// Check if any critical cookies need refresh.
    pub fn needs_refresh(&self) -> bool {
        // If we have anti-bot cookies, check if any are expiring
        if let Some(ab_type) = self.antibot_type {
            for name in ab_type.cookie_names() {
                if let Some(cookie) = self.get(name) {
                    if cookie.needs_refresh() {
                        return true;
                    }
                } else {
                    return true; // Missing critical cookie
                }
            }
        }

        // If no cookies at all, definitely need refresh
        self.cookies.is_empty()
    }

    /// Check if Akamai _abck cookie has valid verdict.
    pub fn has_valid_abck(&self) -> bool {
        if let Some(cookie) = self.get("_abck") {
            cookie.is_valid() && cookie.value.contains("~0~")
        } else {
            false
        }
    }

    /// Build Cookie header string for HTTP requests.
    pub fn cookie_header(&self) -> String {
        self.cookies.iter()
            .filter(|c| c.is_valid())
            .map(|c| format!("{}={}", c.name, c.value))
            .collect::<Vec<_>>()
            .join("; ")
    }

    /// All valid cookies as name=value pairs.
    pub fn valid_cookies(&self) -> Vec<(&str, &str)> {
        self.cookies.iter()
            .filter(|c| c.is_valid())
            .map(|c| (c.name.as_str(), c.value.as_str()))
            .collect()
    }

    /// Remove expired cookies.
    pub fn cleanup(&mut self) {
        self.cookies.retain(|c| c.is_valid());
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cookie Farm
// ────��────────────────────────────────────────────────────────────────────────

/// Manages cookie generation and distribution across domains.
pub struct CookieFarm {
    /// Per-domain cookie jars.
    jars: HashMap<String, DomainCookieJar>,
    /// Default User-Agent for new jars.
    default_ua: String,
}

impl CookieFarm {
    pub fn new(default_ua: &str) -> Self {
        Self {
            jars: HashMap::new(),
            default_ua: default_ua.to_string(),
        }
    }

    /// Get or create a cookie jar for a domain.
    pub fn jar(&mut self, domain: &str) -> &mut DomainCookieJar {
        let ua = self.default_ua.clone();
        self.jars.entry(domain.to_string())
            .or_insert_with(|| DomainCookieJar::new(domain, &ua))
    }

    /// Get cookie jar immutably.
    pub fn get_jar(&self, domain: &str) -> Option<&DomainCookieJar> {
        self.jars.get(domain)
    }

    /// List all domains with cookie jars.
    pub fn domains(&self) -> Vec<&str> {
        self.jars.keys().map(|s| s.as_str()).collect()
    }

    /// List domains that need cookie refresh.
    pub fn domains_needing_refresh(&self) -> Vec<&str> {
        self.jars.iter()
            .filter(|(_, jar)| jar.needs_refresh())
            .map(|(domain, _)| domain.as_str())
            .collect()
    }

    /// Clean up expired cookies in all jars.
    pub fn cleanup_all(&mut self) {
        for jar in self.jars.values_mut() {
            jar.cleanup();
        }
    }

    /// Remove a domain's jar entirely.
    pub fn remove(&mut self, domain: &str) {
        self.jars.remove(domain);
    }

    /// Summary of all jars.
    pub fn summary(&self) -> Vec<(String, usize, bool, Option<CookieType>)> {
        self.jars.iter()
            .map(|(domain, jar)| {
                (
                    domain.clone(),
                    jar.cookies.len(),
                    jar.needs_refresh(),
                    jar.antibot_type,
                )
            })
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cookie generation execution engine
// ─────────────────────────────────────────────────────────────────────────────

/// Navigate to a domain, wait for anti-bot JS to execute, then extract
/// the relevant cookies via CDP `Network.getCookies`.
///
/// Different anti-bot systems need different wait times:
/// - Akamai: 10-15s for `_abck` generation via sensor data collection
/// - Cloudflare: 5-10s for challenge solving
/// - PerimeterX: 8-12s for `_px3` generation
/// - DataDome: 5-8s for `datadome` cookie
///
/// The function scrolls slightly and moves the cursor to trigger
/// behavioral sensors that some anti-bot systems require.
pub async fn generate_cookies(
    page: &Page,
    domain: &str,
    cookie_type: &CookieType,
    proxy_url: Option<&str>,
) -> Result<Vec<AntiBotCookie>, BrowserError> {
    let url = format!("https://{domain}");

    eprintln!("[cookie-farm] generating {cookie_type:?} cookies for {domain}");

    // ── Navigate to the domain ──────────────────────────────────────────
    page.navigate(&url, WaitUntil::Load).await?;

    // ── Determine wait time based on anti-bot system ────────────────────
    let wait_secs = match cookie_type {
        CookieType::Akamai => 12,
        CookieType::Cloudflare => 8,
        CookieType::PerimeterX => 10,
        CookieType::DataDome => 7,
        CookieType::Kasada => 10,
        CookieType::Session => 4,
    };

    // ── Simulate human activity while JS sensors collect data ───────────
    // Anti-bot scripts look for mouse movement, scroll, and timing patterns.
    // We break the wait into segments with activity between them.
    let segment = Duration::from_secs(wait_secs / 3);

    // Phase 1: initial page load settling
    tokio::time::sleep(segment).await;

    // Phase 2: scroll down slightly (triggers Akamai sensor events)
    let _ = page.scroll_by(0.0, 150.0).await;
    tokio::time::sleep(segment).await;

    // Phase 3: scroll a bit more, simulating reading
    let _ = page.scroll_by(0.0, 200.0).await;
    tokio::time::sleep(segment).await;

    // ── Extra wait for Akamai _abck to achieve valid verdict ────────────
    // The _abck cookie is set quickly but needs sensor data submissions
    // before the value contains "~0~" (valid verdict).
    if *cookie_type == CookieType::Akamai {
        // Trigger more sensor events
        let _ = page.evaluate_expression("window.scrollTo(0, 0)").await;
        tokio::time::sleep(Duration::from_secs(3)).await;
    }

    // ── Extract cookies via CDP Network.getCookies ──────────────────────
    let result = page
        .client
        .send_command_with_session(
            "Network.getCookies",
            Some(json!({ "urls": [url] })),
            &page.session_id,
        )
        .await?;

    let target_names = cookie_type.cookie_names();
    let ttl = cookie_type.typical_ttl();
    let now = Instant::now();

    // Determine the user-agent in use (from page JS)
    let ua = page
        .evaluate_expression("navigator.userAgent")
        .await
        .ok()
        .and_then(|v| v.as_str().map(|s| s.to_string()))
        .unwrap_or_else(|| "unknown".to_string());

    let mut cookies = Vec::new();

    if let Some(cdp_cookies) = result.get("cookies").and_then(|v| v.as_array()) {
        for c in cdp_cookies {
            let name = c.get("name").and_then(|v| v.as_str()).unwrap_or("");

            // For Session type, collect all cookies; otherwise filter by known names
            let include = if target_names.is_empty() {
                // Session / Kasada: collect everything from this domain
                true
            } else {
                target_names.contains(&name)
            };

            if !include {
                continue;
            }

            let cookie = AntiBotCookie {
                name: name.to_string(),
                value: c
                    .get("value")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string(),
                domain: c
                    .get("domain")
                    .and_then(|v| v.as_str())
                    .unwrap_or(domain)
                    .to_string(),
                path: c
                    .get("path")
                    .and_then(|v| v.as_str())
                    .unwrap_or("/")
                    .to_string(),
                secure: c.get("secure").and_then(|v| v.as_bool()).unwrap_or(false),
                http_only: c
                    .get("httpOnly")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false),
                generated_at: now,
                ttl,
                // Bind this cookie to the ACTIVE egress proxy actually in use, so
                // replay validation can guarantee it is never sent over a
                // different IP (a _abck/_px3 bound to another egress IP is an
                // instant bot flag).
                source_proxy: proxy_url.map(|p| p.to_string()),
                source_ua: ua.clone(),
            };

            cookies.push(cookie);
        }
    }

    eprintln!("[cookie-farm] generated {} cookies for {domain}", cookies.len());

    Ok(cookies)
}

impl CookieFarm {
    /// Generate fresh cookies for a domain using a live browser page.
    ///
    /// Detects the anti-bot system (or uses the provided type), navigates
    /// to the domain, waits for cookie generation, and stores the result
    /// in the farm's jar for the domain.
    pub async fn generate_for_domain(
        &mut self,
        page: &Page,
        domain: &str,
        cookie_type: Option<CookieType>,
        proxy_url: Option<&str>,
    ) -> Result<Vec<AntiBotCookie>, BrowserError> {
        // Auto-detect anti-bot type if not provided
        let types = cookie_type
            .map(|t| vec![t])
            .unwrap_or_else(|| RetailerAntiBot::detect(domain));

        let primary_type = types.first().copied().unwrap_or(CookieType::Session);

        let cookies = generate_cookies(page, domain, &primary_type, proxy_url).await?;

        // Store in jar, recording the proxy/UA affinity used to generate them.
        let jar = self.jar(domain);
        jar.antibot_type = Some(primary_type);
        jar.proxy_url = proxy_url.map(|p| p.to_string());
        for cookie in &cookies {
            jar.set_cookie(cookie.clone());
        }
        jar.last_refresh = Instant::now();
        jar.refresh_count += 1;

        Ok(cookies)
    }

    /// Proactively refresh cookies that are at 80% of their TTL.
    ///
    /// Iterates all jars, identifies domains where cookies are near expiry
    /// (remaining lifetime < 20% of TTL), and regenerates them using the
    /// provided browser page.
    ///
    /// Returns a list of domains that were refreshed.
    pub async fn refresh_cookies(
        &mut self,
        page: &Page,
    ) -> Vec<String> {
        // Collect domains needing refresh (80% TTL threshold), carrying the
        // proxy each jar is bound to so regenerated cookies keep affinity.
        let domains_to_refresh: Vec<(String, CookieType, Option<String>)> = self
            .jars
            .iter()
            .filter_map(|(domain, jar)| {
                if jar.needs_refresh() {
                    let ct = jar.antibot_type.unwrap_or(CookieType::Session);
                    Some((domain.clone(), ct, jar.proxy_url.clone()))
                } else {
                    None
                }
            })
            .collect();

        if domains_to_refresh.is_empty() {
            return Vec::new();
        }

        eprintln!(
            "[cookie-farm] refreshing cookies for {} domains at 80%+ TTL",
            domains_to_refresh.len()
        );

        let mut refreshed = Vec::new();

        for (domain, cookie_type, proxy_url) in domains_to_refresh {
            match generate_cookies(page, &domain, &cookie_type, proxy_url.as_deref()).await {
                Ok(cookies) => {
                    let jar = self.jar(&domain);
                    jar.antibot_type = Some(cookie_type);
                    jar.proxy_url = proxy_url;
                    for cookie in &cookies {
                        jar.set_cookie(cookie.clone());
                    }
                    jar.last_refresh = Instant::now();
                    jar.refresh_count += 1;

                    eprintln!("[cookie-farm] refreshed {} cookies for {domain}", cookies.len());
                    refreshed.push(domain);
                }
                Err(e) => {
                    eprintln!("[cookie-farm] refresh failed for {domain}: {e}");
                }
            }
        }

        refreshed
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Cookie replay with TTL + proxy/UA affinity validation
// ─────────────────────────────────────────────────────────────────────────────

/// Outcome of a cookie-jar replay into a live page.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReplayResult {
    /// Number of cookies that passed validation and were injected.
    pub replayed: usize,
    /// Number of cookies skipped (expired or bound to a different proxy/UA).
    pub skipped: usize,
}

impl ReplayResult {
    /// Total cookies examined.
    pub fn total(&self) -> usize {
        self.replayed + self.skipped
    }
}

/// Whether a cookie can be safely replayed over the active proxy/UA session.
///
/// A cookie may be replayed only if:
/// - its TTL has not expired, and
/// - it is not bound to a *different* proxy than the active session, and
/// - it is not bound to a *different* User-Agent than the active session.
///
/// An unbound cookie (`source_proxy == None`) passes the proxy-affinity check so
/// legacy cookies remain compatible, but a cookie bound to a specific proxy only
/// passes for that exact proxy (never a foreign egress IP).
pub fn cookie_valid_for_proxy(
    cookie: &AntiBotCookie,
    proxy_url: Option<&str>,
    ua: Option<&str>,
) -> bool {
    // TTL gate: never replay an expired cookie.
    if !cookie.is_valid() {
        return false;
    }
    // Proxy affinity: a bound cookie must match the active proxy exactly.
    if let Some(bound_proxy) = &cookie.source_proxy {
        match proxy_url {
            Some(active) if active == bound_proxy => {}
            _ => return false, // bound to a proxy we are not currently using
        }
    }
    // UA affinity: `source_ua` is always populated, so require an exact match
    // when the active UA is known.
    if let Some(active_ua) = ua {
        if active_ua != cookie.source_ua {
            return false;
        }
    }
    true
}

/// Validate-and-inject a cookie jar into a live page.
///
/// Only cookies that pass [`cookie_valid_for_proxy`] (TTL valid AND proxy/UA
/// affinity matching the active session) are injected via CDP `Network.setCookie`.
/// Cookies that are expired or bound to a different proxy/UA are **skipped** —
/// the caller should regenerate them with `generate_for_domain` rather than
/// replay a stale or foreign cookie. Cookie fidelity (domain/path/secure/httpOnly)
/// is preserved instead of force-rewriting attributes.
pub async fn replay_cookie_jar(
    page: &Page,
    jar: &DomainCookieJar,
    proxy_url: Option<&str>,
    ua: Option<&str>,
) -> Result<ReplayResult, BrowserError> {
    let mut result = ReplayResult::default();

    for cookie in &jar.cookies {
        if !cookie_valid_for_proxy(cookie, proxy_url, ua) {
            result.skipped += 1;
            continue;
        }

        let params = json!({
            "name": cookie.name,
            "value": cookie.value,
            "domain": cookie.domain,
            "path": cookie.path,
            "httpOnly": cookie.http_only,
            "secure": cookie.secure,
            // AntiBotCookie models expiry via an Instant-based TTL (validated on
            // each replay), so we inject as a session cookie and rely on TTL gate.
        });

        page.client
            .send_command_with_session("Network.setCookie", Some(params), &page.session_id)
            .await?;

        result.replayed += 1;
    }

    Ok(result)
}

// ─────────────────────────────────────────────────────────────────────────────
// Known retailer anti-bot configurations
// ─────────────────────────────────────────────────────────────────────────────

/// Retailer anti-bot detection matrix.
pub struct RetailerAntiBot;

impl RetailerAntiBot {
    /// Get the anti-bot type for a known retailer domain.
    pub fn detect(domain: &str) -> Vec<CookieType> {
        match domain {
            d if d.contains("amazon.com") => vec![CookieType::Session], // Custom AWS WAF
            d if d.contains("shop-a.example") => vec![CookieType::Akamai, CookieType::PerimeterX],
            d if d.contains("shop-b.example") => vec![CookieType::Akamai],
            d if d.contains("shop-c.example") => vec![CookieType::Akamai, CookieType::Kasada],
            d if d.contains("nike.com") => vec![CookieType::Akamai],
            d if d.contains("adidas.com") => vec![CookieType::Akamai, CookieType::DataDome],
            d if d.contains("footlocker.com") => vec![CookieType::Akamai, CookieType::PerimeterX],
            d if d.contains("nordstrom.com") => vec![CookieType::Akamai],
            d if d.contains("macys.com") => vec![CookieType::Akamai],
            d if d.contains("asos.com") => vec![CookieType::Kasada],
            d if d.contains("zara.com") => vec![CookieType::Akamai, CookieType::DataDome],
            d if d.contains("hm.com") => vec![CookieType::Akamai],
            d if d.contains("fashionnova.com") => vec![CookieType::Cloudflare],
            d if d.contains("shein.com") => vec![CookieType::Session], // Custom
            _ => vec![],
        }
    }

    /// Is this domain known to use aggressive anti-bot?
    pub fn is_high_security(domain: &str) -> bool {
        let types = Self::detect(domain);
        types.contains(&CookieType::Kasada)
            || types.len() >= 2
            || domain.contains("shop-c.example")
            || domain.contains("adidas.com")
    }

    /// Recommended approach for a domain.
    pub fn recommended_approach(domain: &str) -> &'static str {
        match domain {
            d if d.contains("shop-c.example") => "Use official API at developer.shop-c.example (free, 5 req/sec)",
            d if d.contains("shop-a.example") => "Use Walmart Affiliate API (free, 20 req/sec)",
            d if d.contains("shop-b.example") => "Use Redsky API (semi-public, extract key from JS)",
            d if d.contains("amazon.com") => "Real Chrome + stealth + residential proxy",
            d if d.contains("fashionnova.com") => "Shopify /products.json endpoint (often open)",
            d if d.contains("asos.com") => "Real Chrome only (Kasada proof-of-work)",
            _ => "Real Chrome + stealth + adaptive rate limiting",
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cookie_validity() {
        let cookie = AntiBotCookie {
            name: "_abck".into(),
            value: "test~0~valid".into(),
            domain: ".shop-a.example".into(),
            path: "/".into(),
            secure: true,
            http_only: true,
            generated_at: Instant::now(),
            ttl: Duration::from_secs(300),
            source_proxy: None,
            source_ua: "Chrome/131".into(),
        };

        assert!(cookie.is_valid());
        assert!(!cookie.needs_refresh());
    }

    #[test]
    fn cookie_jar_basics() {
        let mut jar = DomainCookieJar::new("shop-a.example", "Chrome/131");

        jar.set_cookie(AntiBotCookie {
            name: "_abck".into(),
            value: "abc~0~def".into(),
            domain: ".shop-a.example".into(),
            path: "/".into(),
            secure: true,
            http_only: true,
            generated_at: Instant::now(),
            ttl: Duration::from_secs(300),
            source_proxy: None,
            source_ua: "Chrome/131".into(),
        });

        for name in &["bm_sv", "ak_bmsc", "bm_sz"] {
            jar.set_cookie(AntiBotCookie {
                name: (*name).into(),
                value: "someval".into(),
                domain: ".shop-a.example".into(),
                path: "/".into(),
                secure: true,
                http_only: true,
                generated_at: Instant::now(),
                ttl: Duration::from_secs(300),
                source_proxy: None,
                source_ua: "Chrome/131".into(),
            });
        }

        jar.antibot_type = Some(CookieType::Akamai);

        assert!(jar.has_valid_abck());
        assert!(!jar.needs_refresh());
        assert!(jar.cookie_header().contains("_abck=abc~0~def"));
    }

    #[test]
    fn cookie_replay_affinity_validation() {
        // Build a cookie bound to a specific proxy/UA with a live TTL.
        let cookie = AntiBotCookie {
            name: "_abck".into(),
            value: "abc~0~def".into(),
            domain: ".shop-a.example".into(),
            path: "/".into(),
            secure: true,
            http_only: true,
            generated_at: Instant::now(),
            ttl: Duration::from_secs(300),
            source_proxy: Some("res-us-texas:9000".into()),
            source_ua: "Chrome/131".into(),
        };

        // Valid TTL + matching proxy + matching UA → replayable.
        assert!(cookie_valid_for_proxy(
            &cookie,
            Some("res-us-texas:9000"),
            Some("Chrome/131")
        ));

        // Wrong proxy → must be rejected (never replay a bound cookie over a
        // different egress IP).
        assert!(!cookie_valid_for_proxy(
            &cookie,
            Some("res-de-berlin:9000"),
            Some("Chrome/131")
        ));

        // Wrong UA → must be rejected.
        assert!(!cookie_valid_for_proxy(
            &cookie,
            Some("res-us-texas:9000"),
            Some("Firefox/135")
        ));

        // Missing proxy in the active session → bound cookie must not replay.
        assert!(!cookie_valid_for_proxy(&cookie, None, Some("Chrome/131")));

        // Unbound legacy cookie (source_proxy None) is compatible with any proxy.
        let unbound = AntiBotCookie {
            source_proxy: None,
            ..cookie.clone()
        };
        assert!(cookie_valid_for_proxy(
            &unbound,
            Some("some-other-proxy:9000"),
            Some("Chrome/131")
        ));

        // Expired cookie → rejected regardless of affinity.
        let expired = AntiBotCookie {
            ttl: Duration::from_millis(1),
            ..cookie
        };
        std::thread::sleep(Duration::from_millis(5));
        assert!(!cookie_valid_for_proxy(
            &expired,
            Some("res-us-texas:9000"),
            Some("Chrome/131")
        ));
    }

    #[test]
    fn cookie_farm_basics() {
        let mut farm = CookieFarm::new("Chrome/131");

        farm.jar("shop-a.example");
        farm.jar("amazon.com");

        assert_eq!(farm.domains().len(), 2);
        assert_eq!(farm.domains_needing_refresh().len(), 2); // Empty jars need refresh
    }

    #[test]
    fn retailer_detection() {
        let types = RetailerAntiBot::detect("www.shop-a.example");
        assert!(types.contains(&CookieType::Akamai));

        assert!(RetailerAntiBot::is_high_security("www.shop-c.example"));
        assert!(!RetailerAntiBot::is_high_security("www.fashionnova.com"));
    }

    #[test]
    fn cookie_type_detection() {
        let detected = CookieType::detect_from_cookies(&["_abck", "session-id"]);
        assert_eq!(detected, Some(CookieType::Akamai));

        let detected = CookieType::detect_from_cookies(&["cf_clearance", "__cf_bm"]);
        assert_eq!(detected, Some(CookieType::Cloudflare));

        let detected = CookieType::detect_from_cookies(&["_px3", "_pxvid"]);
        assert_eq!(detected, Some(CookieType::PerimeterX));
    }
}
