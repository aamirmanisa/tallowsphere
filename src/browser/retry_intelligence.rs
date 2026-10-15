//! Retry Intelligence — learns from DLQ failures to improve future success.
//!
//! Tracks per-domain and per-proxy failure patterns, time-of-day success rates,
//! and anti-bot classification to automatically recommend optimal retry strategies.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::browser::dlq::{DeadLetter, FailureCategory};

// ── Smart Failure Classification ───────────────────────────────────────────

/// Fine-grained failure classification beyond the 9 basic DLQ categories.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SmartFailureType {
    // Rate limiting patterns
    /// 429 with Retry-After header — respect the delay
    RateLimitSoft,
    /// IP banned, no retry header — change proxy immediately
    RateLimitHard,
    /// All proxies rate limited — back off entirely
    RateLimitGlobal,

    // Anti-bot challenge patterns
    /// Cloudflare Turnstile / Under Attack Mode
    ChallengeCloudflare,
    /// Akamai Bot Manager (_abck cookie)
    ChallengeAkamai,
    /// PerimeterX / HUMAN Security
    ChallengePerimeterX,
    /// DataDome bot protection
    ChallengeDataDome,
    /// Kasada bot mitigation
    ChallengeKasada,
    /// Unknown challenge page
    ChallengeGeneric,

    // Technical failures
    /// TLS fingerprint rejected by server
    TlsHandshakeFail,
    /// HTTP/2 fingerprint mismatch
    H2Mismatch,
    /// DNS resolution failed
    DnsFailure,
    /// TCP RST — possible DPI or firewall
    ConnectionReset,

    // Content issues
    /// Page structure changed — selectors broken
    ContentChanged,
    /// IP geolocation doesn't match required region
    GeoBlocked,
    /// Login/auth wall encountered
    AuthRequired,

    // Proxy issues
    /// Proxy not responding at all
    ProxyDead,
    /// Proxy IP is blocked by target site
    ProxyBanned,
    /// Proxy works but latency is degrading over time
    ProxySlowLeak,

    // Server-side
    /// Server returned 5xx error
    ServerError,
    /// Request timed out
    Timeout,
    /// Generic network error
    NetworkError,
    /// Could not classify
    Unknown,
}

impl SmartFailureType {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RateLimitSoft => "RateLimitSoft",
            Self::RateLimitHard => "RateLimitHard",
            Self::RateLimitGlobal => "RateLimitGlobal",
            Self::ChallengeCloudflare => "ChallengeCloudflare",
            Self::ChallengeAkamai => "ChallengeAkamai",
            Self::ChallengePerimeterX => "ChallengePerimeterX",
            Self::ChallengeDataDome => "ChallengeDataDome",
            Self::ChallengeKasada => "ChallengeKasada",
            Self::ChallengeGeneric => "ChallengeGeneric",
            Self::TlsHandshakeFail => "TlsHandshakeFail",
            Self::H2Mismatch => "H2Mismatch",
            Self::DnsFailure => "DnsFailure",
            Self::ConnectionReset => "ConnectionReset",
            Self::ContentChanged => "ContentChanged",
            Self::GeoBlocked => "GeoBlocked",
            Self::AuthRequired => "AuthRequired",
            Self::ProxyDead => "ProxyDead",
            Self::ProxyBanned => "ProxyBanned",
            Self::ProxySlowLeak => "ProxySlowLeak",
            Self::ServerError => "ServerError",
            Self::Timeout => "Timeout",
            Self::NetworkError => "NetworkError",
            Self::Unknown => "Unknown",
        }
    }

    /// Whether this failure type is worth retrying at all.
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::RateLimitSoft => true,
            Self::RateLimitHard => true,
            Self::RateLimitGlobal => true,
            Self::ChallengeCloudflare => true,
            Self::ChallengeAkamai => true,
            Self::ChallengePerimeterX => true,
            Self::ChallengeDataDome => true,
            Self::ChallengeKasada => true,
            Self::ChallengeGeneric => true,
            Self::TlsHandshakeFail => true,
            Self::H2Mismatch => true,
            Self::DnsFailure => false, // usually permanent
            Self::ConnectionReset => true,
            Self::ContentChanged => false, // needs schema regen, not retry
            Self::GeoBlocked => true,      // can retry with different proxy region
            Self::AuthRequired => false,   // needs credentials
            Self::ProxyDead => true,       // switch proxy
            Self::ProxyBanned => true,     // switch proxy
            Self::ProxySlowLeak => true,   // switch proxy
            Self::ServerError => true,
            Self::Timeout => true,
            Self::NetworkError => true,
            Self::Unknown => true,
        }
    }

    /// Whether this failure suggests we need to escalate to a browser.
    pub fn needs_browser_escalation(&self) -> bool {
        matches!(
            self,
            Self::ChallengeCloudflare
                | Self::ChallengeAkamai
                | Self::ChallengePerimeterX
                | Self::ChallengeDataDome
                | Self::ChallengeKasada
                | Self::ChallengeGeneric
        )
    }

    /// Whether this failure suggests we need a different proxy.
    pub fn needs_proxy_change(&self) -> bool {
        matches!(
            self,
            Self::RateLimitHard
                | Self::ProxyDead
                | Self::ProxyBanned
                | Self::ProxySlowLeak
                | Self::GeoBlocked
                | Self::ConnectionReset
        )
    }

    /// Whether this failure suggests the version-accurate JA4 / HTTP-2
    /// fingerprint has gone stale and needs re-capturing.
    ///
    /// TLS-handshake failures and HTTP/2 mismatches are the classic signals
    /// that a browser release changed its fingerprint and Tallow's impersonation
    /// profile no longer matches (G1 §4). When this is `true`, callers should
    /// surface `http2_fingerprint::fingerprint_version_refresh_due(...)` so CI
    /// can re-capture the current fingerprint from a live browser.
    pub fn suggests_fingerprint_refresh(&self) -> bool {
        matches!(self, Self::TlsHandshakeFail | Self::H2Mismatch)
    }
}

// ── Domain Failure Pattern ─────────────────────────────────────────────────

/// Accumulated failure/success patterns for a single domain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainFailurePattern {
    pub domain: String,
    pub total_attempts: u64,
    pub total_successes: u64,
    pub failure_by_category: HashMap<String, u64>,
    pub avg_success_latency_ms: f64,
    /// Which proxy tier works best for this domain
    pub best_proxy_tier: Option<String>,
    /// Hour (0-23) with highest success rate
    pub best_time_of_day: Option<u8>,
    /// Learned: HTTP requests always fail, need full browser
    pub requires_browser: bool,
    /// Learned: domain requires pre-warmed cookies
    pub requires_cookies: bool,
    /// Learned: max requests/second before rate limiting kicks in
    pub rate_limit_threshold: Option<f64>,
    /// Minimum delay between requests in ms to avoid detection
    pub min_delay_between_requests_ms: u64,
    /// Last user-agent string that succeeded
    pub last_successful_ua: Option<String>,
    /// Last proxy address that succeeded
    pub last_successful_proxy: Option<String>,
    /// Success count per hour (for best_time_of_day calculation)
    hourly_successes: [u64; 24],
    /// Attempt count per hour
    hourly_attempts: [u64; 24],
    /// Success count per proxy tier
    tier_successes: HashMap<String, u64>,
    /// Attempt count per proxy tier
    tier_attempts: HashMap<String, u64>,
    /// Count of consecutive failures (resets on success)
    pub consecutive_failures: u64,
    /// Timestamp of last successful request (epoch secs)
    pub last_success_epoch: Option<i64>,
    /// Timestamp of last failure (epoch secs)
    pub last_failure_epoch: Option<i64>,
    /// Running sum of success latencies for averaging
    total_success_latency_ms: u64,
}

impl DomainFailurePattern {
    pub fn new(domain: &str) -> Self {
        Self {
            domain: domain.to_string(),
            total_attempts: 0,
            total_successes: 0,
            failure_by_category: HashMap::new(),
            avg_success_latency_ms: 0.0,
            best_proxy_tier: None,
            best_time_of_day: None,
            requires_browser: false,
            requires_cookies: false,
            rate_limit_threshold: None,
            min_delay_between_requests_ms: 0,
            last_successful_ua: None,
            last_successful_proxy: None,
            hourly_successes: [0; 24],
            hourly_attempts: [0; 24],
            tier_successes: HashMap::new(),
            tier_attempts: HashMap::new(),
            consecutive_failures: 0,
            last_success_epoch: None,
            last_failure_epoch: None,
            total_success_latency_ms: 0,
        }
    }

    /// Success rate as a fraction 0.0 - 1.0.
    pub fn success_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            return 0.0;
        }
        self.total_successes as f64 / self.total_attempts as f64
    }

    /// Recalculate derived fields from raw counters.
    fn recalculate(&mut self) {
        // Best time of day
        let mut best_hour = 0u8;
        let mut best_rate = 0.0f64;
        for h in 0..24usize {
            if self.hourly_attempts[h] >= 5 {
                let rate = self.hourly_successes[h] as f64 / self.hourly_attempts[h] as f64;
                if rate > best_rate {
                    best_rate = rate;
                    best_hour = h as u8;
                }
            }
        }
        if best_rate > 0.0 {
            self.best_time_of_day = Some(best_hour);
        }

        // Best proxy tier
        let mut best_tier: Option<String> = None;
        let mut best_tier_rate = 0.0f64;
        for (tier, successes) in &self.tier_successes {
            let attempts = self.tier_attempts.get(tier).copied().unwrap_or(1);
            if attempts >= 3 {
                let rate = *successes as f64 / attempts as f64;
                if rate > best_tier_rate {
                    best_tier_rate = rate;
                    best_tier = Some(tier.clone());
                }
            }
        }
        self.best_proxy_tier = best_tier;

        // Average success latency
        if self.total_successes > 0 {
            self.avg_success_latency_ms =
                self.total_success_latency_ms as f64 / self.total_successes as f64;
        }

        // Detect if domain requires browser (>80% of failures are anti-bot challenges)
        let challenge_count: u64 = [
            "ChallengeCloudflare",
            "ChallengeAkamai",
            "ChallengePerimeterX",
            "ChallengeDataDome",
            "ChallengeKasada",
            "ChallengeGeneric",
        ]
        .iter()
        .filter_map(|k| self.failure_by_category.get(*k))
        .sum();
        let total_failures = self.total_attempts.saturating_sub(self.total_successes);
        if total_failures >= 5 && challenge_count as f64 / total_failures as f64 > 0.8 {
            self.requires_browser = true;
        }

        // Detect if domain requires cookies (>50% of failures are challenge-related)
        if total_failures >= 3 && challenge_count as f64 / total_failures as f64 > 0.5 {
            self.requires_cookies = true;
        }

        // Estimate rate limit threshold from rate-limit failures
        let rl_count = self
            .failure_by_category
            .get("RateLimitSoft")
            .copied()
            .unwrap_or(0)
            + self
                .failure_by_category
                .get("RateLimitHard")
                .copied()
                .unwrap_or(0);
        if rl_count >= 3 && self.min_delay_between_requests_ms > 0 {
            self.rate_limit_threshold = Some(1000.0 / self.min_delay_between_requests_ms as f64);
        }
    }
}

// ── Proxy Failure Pattern ──────────────────────────────────────────────────

/// Accumulated failure/success patterns for a single proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyFailurePattern {
    pub proxy: String,
    pub total_attempts: u64,
    pub total_successes: u64,
    pub failure_by_category: HashMap<String, u64>,
    pub avg_latency_ms: f64,
    /// Domains this proxy works well with
    pub good_domains: Vec<String>,
    /// Domains this proxy is banned from
    pub banned_domains: Vec<String>,
    /// Whether latency is trending upward (slow leak)
    pub latency_trending_up: bool,
    /// Count of consecutive failures
    pub consecutive_failures: u64,
    /// Last seen working (epoch secs)
    pub last_success_epoch: Option<i64>,
    /// Running latency samples (last 20)
    recent_latencies: Vec<u64>,
    total_latency_ms: u64,
}

impl ProxyFailurePattern {
    pub fn new(proxy: &str) -> Self {
        Self {
            proxy: proxy.to_string(),
            total_attempts: 0,
            total_successes: 0,
            failure_by_category: HashMap::new(),
            avg_latency_ms: 0.0,
            good_domains: Vec::new(),
            banned_domains: Vec::new(),
            latency_trending_up: false,
            consecutive_failures: 0,
            last_success_epoch: None,
            recent_latencies: Vec::new(),
            total_latency_ms: 0,
        }
    }

    pub fn success_rate(&self) -> f64 {
        if self.total_attempts == 0 {
            return 0.0;
        }
        self.total_successes as f64 / self.total_attempts as f64
    }

    /// Check if this proxy is effectively dead (>20 consecutive failures).
    pub fn is_dead(&self) -> bool {
        self.consecutive_failures >= 20
    }

    fn recalculate(&mut self) {
        if self.total_successes > 0 {
            self.avg_latency_ms = self.total_latency_ms as f64 / self.total_successes as f64;
        }

        // Detect slow leak: compare first half of recent latencies to second half
        if self.recent_latencies.len() >= 10 {
            let mid = self.recent_latencies.len() / 2;
            let first_avg: f64 =
                self.recent_latencies[..mid].iter().sum::<u64>() as f64 / mid as f64;
            let second_avg: f64 = self.recent_latencies[mid..].iter().sum::<u64>() as f64
                / (self.recent_latencies.len() - mid) as f64;
            self.latency_trending_up = second_avg > first_avg * 1.5;
        }
    }
}

// ── Retry Recommendation ───────────────────────────────────────────────────

/// The intelligence system's recommendation for how to retry a failed request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryRecommendation {
    /// Whether retrying is worthwhile at all
    pub should_retry: bool,
    /// Recommended delay before retry in milliseconds
    pub delay_ms: u64,
    /// Switch to a different proxy
    pub change_proxy: bool,
    /// Escalate from HTTP-only to full browser
    pub upgrade_tier: bool,
    /// Specific proxy tier to use (e.g., "residential", "datacenter")
    pub new_proxy_tier: Option<String>,
    /// Switch user-agent string
    pub change_ua: bool,
    /// Pre-warm cookies via cookie farm before retrying
    pub use_cookie_farm: bool,
    /// Human-readable reason for the recommendation
    pub reason: String,
    /// Confidence in this recommendation (0.0 - 1.0)
    pub confidence: f64,
    /// Suggested max retries for this particular scenario
    pub suggested_max_retries: u32,
    /// If rate-limited, the exact Retry-After value parsed from headers
    pub retry_after_ms: Option<u64>,
}

impl Default for RetryRecommendation {
    fn default() -> Self {
        Self {
            should_retry: true,
            delay_ms: 1000,
            change_proxy: false,
            upgrade_tier: false,
            new_proxy_tier: None,
            change_ua: false,
            use_cookie_farm: false,
            reason: String::new(),
            confidence: 0.5,
            suggested_max_retries: 3,
            retry_after_ms: None,
        }
    }
}

/// Strategy recommendations for a domain we haven't seen before.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitialStrategy {
    /// Start with browser or HTTP-only?
    pub use_browser: bool,
    /// Pre-warm cookies?
    pub use_cookie_farm: bool,
    /// Recommended proxy tier
    pub proxy_tier: String,
    /// Initial delay between requests in ms
    pub initial_delay_ms: u64,
    /// Max concurrent requests
    pub max_concurrency: u32,
    /// Confidence (based on how similar known domains are)
    pub confidence: f64,
    pub reason: String,
}

// ── Retry Intelligence ─────────────────────────────────────────────────────

/// Core intelligence engine that learns from failures and successes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryIntelligence {
    /// Per-domain failure/success patterns
    domain_patterns: HashMap<String, DomainFailurePattern>,
    /// Per-proxy failure/success patterns
    proxy_patterns: HashMap<String, ProxyFailurePattern>,
    /// Success rate per hour of day (0-23), averaged across all domains
    hourly_success: [f64; 24],
    /// Success rate per day of week (0=Mon, 6=Sun)
    daily_success: [f64; 7],
    /// Total requests tracked
    total_tracked: u64,
    /// Global hourly attempt/success counters for rate calculation
    hourly_attempts: [u64; 24],
    hourly_successes: [u64; 24],
    daily_attempts: [u64; 7],
    daily_successes: [u64; 7],
}

impl RetryIntelligence {
    pub fn new() -> Self {
        Self {
            domain_patterns: HashMap::new(),
            proxy_patterns: HashMap::new(),
            hourly_success: [0.0; 24],
            daily_success: [0.0; 7],
            total_tracked: 0,
            hourly_attempts: [0; 24],
            hourly_successes: [0; 24],
            daily_attempts: [0; 7],
            daily_successes: [0; 7],
        }
    }

    /// Get the domain pattern for a given domain, if we have data.
    pub fn domain_pattern(&self, domain: &str) -> Option<&DomainFailurePattern> {
        self.domain_patterns.get(domain)
    }

    /// Get the proxy pattern for a given proxy, if we have data.
    pub fn proxy_pattern(&self, proxy: &str) -> Option<&ProxyFailurePattern> {
        self.proxy_patterns.get(proxy)
    }

    /// Number of domains we have data for.
    pub fn known_domain_count(&self) -> usize {
        self.domain_patterns.len()
    }

    /// Number of proxies we have data for.
    pub fn known_proxy_count(&self) -> usize {
        self.proxy_patterns.len()
    }

    // ── Classification ─────────────────────────────────────────────────

    /// Classify a failure into a SmartFailureType from response data.
    pub fn classify_failure(
        &self,
        status: Option<u16>,
        headers: &HashMap<String, String>,
        body_snippet: &str,
        error: &str,
    ) -> SmartFailureType {
        let lower_body = body_snippet.to_lowercase();
        let lower_err = error.to_lowercase();

        // Check headers for specific anti-bot signatures
        let server = headers
            .get("server")
            .or_else(|| headers.get("Server"))
            .map(|s| s.to_lowercase())
            .unwrap_or_default();

        // DataDome detection (header-based)
        if headers
            .keys()
            .any(|k| k.to_lowercase().starts_with("x-datadome"))
        {
            return SmartFailureType::ChallengeDataDome;
        }

        // Status-code based classification
        if let Some(s) = status {
            match s {
                429 => {
                    // Check for Retry-After header
                    if headers.contains_key("retry-after") || headers.contains_key("Retry-After") {
                        return SmartFailureType::RateLimitSoft;
                    }
                    return SmartFailureType::RateLimitHard;
                }
                403 => {
                    // Cloudflare detection
                    if server.contains("cloudflare")
                        || lower_body.contains("cf-browser-verification")
                        || lower_body.contains("cf_chl_opt")
                        || lower_body.contains("cloudflare")
                        || lower_body.contains("turnstile")
                        || lower_body.contains("challenge-platform")
                    {
                        return SmartFailureType::ChallengeCloudflare;
                    }

                    // Akamai detection
                    if lower_body.contains("_abck")
                        || lower_body.contains("akamai")
                        || lower_body.contains("ak_bmsc")
                        || headers.keys().any(|k| k.to_lowercase().contains("akamai"))
                    {
                        return SmartFailureType::ChallengeAkamai;
                    }

                    // PerimeterX / HUMAN detection
                    if lower_body.contains("perimeterx")
                        || lower_body.contains("_pxhd")
                        || lower_body.contains("px-captcha")
                        || lower_body.contains("human challenge")
                    {
                        return SmartFailureType::ChallengePerimeterX;
                    }

                    // Kasada detection
                    if lower_body.contains("kasada")
                        || lower_body.contains("cd.js")
                        || lower_body.contains("ips.js")
                    {
                        return SmartFailureType::ChallengeKasada;
                    }

                    // Generic CAPTCHA / challenge
                    if lower_body.contains("captcha")
                        || lower_body.contains("verify you are human")
                        || lower_body.contains("bot detection")
                        || lower_body.contains("access denied")
                    {
                        return SmartFailureType::ChallengeGeneric;
                    }

                    // Geo-blocking patterns
                    if lower_body.contains("not available in your")
                        || lower_body.contains("geo")
                        || lower_body.contains("region")
                        || lower_body.contains("country")
                    {
                        return SmartFailureType::GeoBlocked;
                    }

                    // Auth required
                    if lower_body.contains("login")
                        || lower_body.contains("sign in")
                        || lower_body.contains("authenticate")
                    {
                        return SmartFailureType::AuthRequired;
                    }

                    // Proxy banned (403 + no challenge page = IP block)
                    return SmartFailureType::ProxyBanned;
                }
                401 => return SmartFailureType::AuthRequired,
                407 => return SmartFailureType::ProxyDead,
                451 => return SmartFailureType::GeoBlocked,
                503 => {
                    // Cloudflare 503 "checking your browser"
                    if server.contains("cloudflare")
                        || lower_body.contains("cloudflare")
                        || lower_body.contains("checking your browser")
                    {
                        return SmartFailureType::ChallengeCloudflare;
                    }
                    return SmartFailureType::ServerError;
                }
                502 | 504 => return SmartFailureType::ServerError,
                s if (500..600).contains(&s) => return SmartFailureType::ServerError,
                _ => {}
            }
        }

        // Error-string based classification
        if lower_err.contains("tls")
            || lower_err.contains("ssl")
            || lower_err.contains("handshake")
            || lower_err.contains("certificate")
        {
            return SmartFailureType::TlsHandshakeFail;
        }

        if lower_err.contains("h2")
            || lower_err.contains("http2")
            || lower_err.contains("protocol error")
        {
            return SmartFailureType::H2Mismatch;
        }

        if lower_err.contains("dns")
            || lower_err.contains("resolve")
            || lower_err.contains("no such host")
            || lower_err.contains("name resolution")
        {
            return SmartFailureType::DnsFailure;
        }

        if lower_err.contains("reset")
            || lower_err.contains("rst")
            || lower_err.contains("connection reset")
        {
            return SmartFailureType::ConnectionReset;
        }

        if lower_err.contains("timeout") || lower_err.contains("timed out") {
            return SmartFailureType::Timeout;
        }

        if lower_err.contains("connection")
            || lower_err.contains("refused")
            || lower_err.contains("broken pipe")
        {
            return SmartFailureType::NetworkError;
        }

        if lower_err.contains("proxy")
            || lower_err.contains("socks")
            || lower_err.contains("tunnel")
        {
            return SmartFailureType::ProxyDead;
        }

        if lower_err.contains("selector")
            || lower_err.contains("no fields")
            || lower_err.contains("empty extraction")
            || lower_err.contains("schema")
        {
            return SmartFailureType::ContentChanged;
        }

        // Body-based detection without a telling status code
        if !lower_body.is_empty() {
            if lower_body.contains("cloudflare") || lower_body.contains("cf-") {
                return SmartFailureType::ChallengeCloudflare;
            }
            if lower_body.contains("captcha") || lower_body.contains("recaptcha") {
                return SmartFailureType::ChallengeGeneric;
            }
        }

        SmartFailureType::Unknown
    }

    /// Classify a DeadLetter into a SmartFailureType.
    pub fn classify_dead_letter(&self, dl: &DeadLetter) -> SmartFailureType {
        self.classify_failure(
            dl.last_http_status,
            &dl.response_headers,
            &dl.response_body_snippet,
            &dl.final_error,
        )
    }

    // ── Learning ───────────────────────────────────────────────────────

    /// Record a successful request for pattern learning.
    pub fn record_success(
        &mut self,
        domain: &str,
        proxy: &str,
        latency_ms: u64,
        proxy_tier: &str,
        user_agent: Option<&str>,
    ) {
        let now = epoch_secs();
        let hour = current_hour();
        let dow = current_day_of_week();
        let normalized_proxy_tier = normalize_proxy_tier_key(proxy_tier);

        self.total_tracked += 1;
        self.hourly_attempts[hour] += 1;
        self.hourly_successes[hour] += 1;
        self.daily_attempts[dow] += 1;
        self.daily_successes[dow] += 1;
        self.recalculate_global_rates();

        // Domain pattern
        let dp = self
            .domain_patterns
            .entry(domain.to_string())
            .or_insert_with(|| DomainFailurePattern::new(domain));
        dp.total_attempts += 1;
        dp.total_successes += 1;
        dp.consecutive_failures = 0;
        dp.last_success_epoch = Some(now);
        dp.total_success_latency_ms += latency_ms;
        dp.hourly_attempts[hour] += 1;
        dp.hourly_successes[hour] += 1;
        *dp.tier_successes
            .entry(normalized_proxy_tier.clone())
            .or_insert(0) += 1;
        *dp.tier_attempts.entry(normalized_proxy_tier).or_insert(0) += 1;
        dp.last_successful_proxy = Some(proxy.to_string());
        if let Some(ua) = user_agent {
            dp.last_successful_ua = Some(ua.to_string());
        }
        dp.recalculate();

        // Proxy pattern
        let pp = self
            .proxy_patterns
            .entry(proxy.to_string())
            .or_insert_with(|| ProxyFailurePattern::new(proxy));
        pp.total_attempts += 1;
        pp.total_successes += 1;
        pp.consecutive_failures = 0;
        pp.last_success_epoch = Some(now);
        pp.total_latency_ms += latency_ms;
        pp.recent_latencies.push(latency_ms);
        if pp.recent_latencies.len() > 20 {
            pp.recent_latencies.remove(0);
        }
        // Track good domains for this proxy
        if !pp.good_domains.contains(&domain.to_string()) && pp.good_domains.len() < 100 {
            pp.good_domains.push(domain.to_string());
        }
        pp.recalculate();
    }

    /// Record a failed request for pattern learning.
    pub fn record_failure(&mut self, dead_letter: &DeadLetter) {
        let now = epoch_secs();
        let hour = current_hour();
        let dow = current_day_of_week();

        let smart_type = self.classify_dead_letter(dead_letter);
        let type_str = smart_type.as_str().to_string();

        self.total_tracked += 1;
        self.hourly_attempts[hour] += 1;
        self.daily_attempts[dow] += 1;
        self.recalculate_global_rates();

        // Extract domain from URL
        let domain = extract_domain(&dead_letter.url);

        // Domain pattern
        let dp = self
            .domain_patterns
            .entry(domain.clone())
            .or_insert_with(|| DomainFailurePattern::new(&domain));
        dp.total_attempts += 1;
        dp.consecutive_failures += 1;
        dp.last_failure_epoch = Some(now);
        dp.hourly_attempts[hour] += 1;
        *dp.failure_by_category.entry(type_str.clone()).or_insert(0) += 1;

        // If we see rate limiting, increase the min delay
        if matches!(
            smart_type,
            SmartFailureType::RateLimitSoft | SmartFailureType::RateLimitHard
        ) {
            dp.min_delay_between_requests_ms = (dp.min_delay_between_requests_ms + 500).min(30_000);
        }

        dp.recalculate();

        // Proxy pattern — extract proxy from dead letter headers or target
        let proxy_key = dead_letter
            .response_headers
            .get("x-proxy-used")
            .or_else(|| dead_letter.response_headers.get("X-Proxy-Used"))
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());

        if proxy_key != "unknown" {
            let pp = self
                .proxy_patterns
                .entry(proxy_key.clone())
                .or_insert_with(|| ProxyFailurePattern::new(&proxy_key));
            pp.total_attempts += 1;
            pp.consecutive_failures += 1;
            *pp.failure_by_category.entry(type_str).or_insert(0) += 1;

            // Track banned domains
            if matches!(smart_type, SmartFailureType::ProxyBanned)
                && !pp.banned_domains.contains(&domain)
                && pp.banned_domains.len() < 100
            {
                pp.banned_domains.push(domain);
            }
            pp.recalculate();
        }
    }

    /// Learn from a batch of DLQ entries.
    pub fn learn_from_dlq(&mut self, entries: &[DeadLetter]) {
        for entry in entries {
            self.record_failure(entry);
        }
    }

    // ── Recommendations ────────────────────────────────────────────────

    /// Determine the optimal retry strategy for a failed request.
    pub fn recommend_retry(&self, dead_letter: &DeadLetter) -> RetryRecommendation {
        let smart_type = self.classify_dead_letter(dead_letter);
        let domain = extract_domain(&dead_letter.url);
        let domain_data = self.domain_patterns.get(&domain);

        // Base recommendation from failure type
        let mut rec = match &smart_type {
            SmartFailureType::RateLimitSoft => {
                let retry_after = parse_retry_after(&dead_letter.response_headers);
                RetryRecommendation {
                    should_retry: true,
                    delay_ms: retry_after.unwrap_or(5_000),
                    change_proxy: false,
                    reason: "Soft rate limit — respecting Retry-After".to_string(),
                    confidence: 0.9,
                    suggested_max_retries: 3,
                    retry_after_ms: retry_after,
                    ..Default::default()
                }
            }
            SmartFailureType::RateLimitHard => RetryRecommendation {
                should_retry: true,
                delay_ms: 10_000,
                change_proxy: true,
                reason: "Hard rate limit — IP banned, switching proxy".to_string(),
                confidence: 0.7,
                suggested_max_retries: 2,
                ..Default::default()
            },
            SmartFailureType::RateLimitGlobal => RetryRecommendation {
                should_retry: true,
                delay_ms: 60_000,
                change_proxy: true,
                reason: "Global rate limit — all proxies limited, long backoff".to_string(),
                confidence: 0.4,
                suggested_max_retries: 1,
                ..Default::default()
            },
            SmartFailureType::ChallengeCloudflare => RetryRecommendation {
                should_retry: true,
                delay_ms: 2_000,
                change_proxy: true,
                upgrade_tier: true,
                use_cookie_farm: true,
                reason: "Cloudflare challenge — need cookie farm + browser".to_string(),
                confidence: 0.6,
                suggested_max_retries: 2,
                ..Default::default()
            },
            SmartFailureType::ChallengeAkamai => RetryRecommendation {
                should_retry: true,
                delay_ms: 2_000,
                change_proxy: true,
                use_cookie_farm: true,
                reason: "Akamai Bot Manager — need cookie farm with _abck".to_string(),
                confidence: 0.5,
                suggested_max_retries: 2,
                ..Default::default()
            },
            SmartFailureType::ChallengePerimeterX => RetryRecommendation {
                should_retry: true,
                delay_ms: 3_000,
                upgrade_tier: true,
                use_cookie_farm: true,
                reason: "PerimeterX — need browser + cookie farm".to_string(),
                confidence: 0.5,
                suggested_max_retries: 2,
                ..Default::default()
            },
            SmartFailureType::ChallengeDataDome => RetryRecommendation {
                should_retry: true,
                delay_ms: 5_000,
                change_proxy: true,
                upgrade_tier: true,
                use_cookie_farm: true,
                new_proxy_tier: Some("residential".to_string()),
                reason: "DataDome — need residential proxy + browser + cookies".to_string(),
                confidence: 0.4,
                suggested_max_retries: 2,
                ..Default::default()
            },
            SmartFailureType::ChallengeKasada => RetryRecommendation {
                should_retry: true,
                delay_ms: 5_000,
                upgrade_tier: true,
                use_cookie_farm: true,
                change_proxy: true,
                reason: "Kasada — need stealth browser with full JS execution".to_string(),
                confidence: 0.3,
                suggested_max_retries: 1,
                ..Default::default()
            },
            SmartFailureType::ChallengeGeneric => RetryRecommendation {
                should_retry: true,
                delay_ms: 3_000,
                upgrade_tier: true,
                use_cookie_farm: true,
                reason: "Unknown challenge — escalating to browser + cookies".to_string(),
                confidence: 0.4,
                suggested_max_retries: 2,
                ..Default::default()
            },
            SmartFailureType::TlsHandshakeFail => RetryRecommendation {
                should_retry: true,
                delay_ms: 1_000,
                change_ua: true,
                reason: "TLS fingerprint rejected — changing TLS profile".to_string(),
                confidence: 0.6,
                suggested_max_retries: 3,
                ..Default::default()
            },
            SmartFailureType::H2Mismatch => RetryRecommendation {
                should_retry: true,
                delay_ms: 1_000,
                change_ua: true,
                reason: "HTTP/2 fingerprint mismatch — changing H2 profile".to_string(),
                confidence: 0.6,
                suggested_max_retries: 2,
                ..Default::default()
            },
            SmartFailureType::DnsFailure => RetryRecommendation {
                should_retry: false,
                delay_ms: 0,
                reason: "DNS resolution failed — domain may not exist".to_string(),
                confidence: 0.9,
                ..Default::default()
            },
            SmartFailureType::ConnectionReset => RetryRecommendation {
                should_retry: true,
                delay_ms: 2_000,
                change_proxy: true,
                reason: "Connection reset — possible DPI, trying different proxy".to_string(),
                confidence: 0.5,
                suggested_max_retries: 3,
                ..Default::default()
            },
            SmartFailureType::ContentChanged => RetryRecommendation {
                should_retry: false,
                delay_ms: 0,
                reason: "Page structure changed — selectors need regeneration".to_string(),
                confidence: 0.8,
                ..Default::default()
            },
            SmartFailureType::GeoBlocked => RetryRecommendation {
                should_retry: true,
                delay_ms: 1_000,
                change_proxy: true,
                new_proxy_tier: Some("residential".to_string()),
                reason: "Geo-blocked — need proxy in target region".to_string(),
                confidence: 0.6,
                suggested_max_retries: 2,
                ..Default::default()
            },
            SmartFailureType::AuthRequired => RetryRecommendation {
                should_retry: false,
                delay_ms: 0,
                reason: "Authentication required — need credentials".to_string(),
                confidence: 0.9,
                ..Default::default()
            },
            SmartFailureType::ProxyDead => RetryRecommendation {
                should_retry: true,
                delay_ms: 500,
                change_proxy: true,
                reason: "Proxy is dead — switching to different proxy".to_string(),
                confidence: 0.8,
                suggested_max_retries: 3,
                ..Default::default()
            },
            SmartFailureType::ProxyBanned => RetryRecommendation {
                should_retry: true,
                delay_ms: 1_000,
                change_proxy: true,
                reason: "Proxy IP banned by target — switching proxy".to_string(),
                confidence: 0.7,
                suggested_max_retries: 3,
                ..Default::default()
            },
            SmartFailureType::ProxySlowLeak => RetryRecommendation {
                should_retry: true,
                delay_ms: 500,
                change_proxy: true,
                reason: "Proxy degrading — switching to fresh proxy".to_string(),
                confidence: 0.7,
                suggested_max_retries: 3,
                ..Default::default()
            },
            SmartFailureType::ServerError => RetryRecommendation {
                should_retry: true,
                delay_ms: 3_000,
                reason: "Server error — retrying with backoff".to_string(),
                confidence: 0.5,
                suggested_max_retries: 3,
                ..Default::default()
            },
            SmartFailureType::Timeout => RetryRecommendation {
                should_retry: true,
                delay_ms: 2_000,
                reason: "Timeout — retrying with backoff".to_string(),
                confidence: 0.6,
                suggested_max_retries: 3,
                ..Default::default()
            },
            SmartFailureType::NetworkError => RetryRecommendation {
                should_retry: true,
                delay_ms: 1_000,
                change_proxy: true,
                reason: "Network error — switching proxy and retrying".to_string(),
                confidence: 0.5,
                suggested_max_retries: 3,
                ..Default::default()
            },
            SmartFailureType::Unknown => RetryRecommendation {
                should_retry: true,
                delay_ms: 2_000,
                reason: "Unknown failure — generic retry with backoff".to_string(),
                confidence: 0.3,
                suggested_max_retries: 2,
                ..Default::default()
            },
        };

        // Refine with domain-specific knowledge
        if let Some(dp) = domain_data {
            // If we know the domain requires browser, always escalate
            if dp.requires_browser && !rec.upgrade_tier {
                rec.upgrade_tier = true;
                rec.confidence = (rec.confidence + 0.1).min(1.0);
                rec.reason = format!("{} (domain requires browser)", rec.reason);
            }

            // If we know the domain requires cookies, always use farm
            if dp.requires_cookies && !rec.use_cookie_farm {
                rec.use_cookie_farm = true;
                rec.reason = format!("{} (domain requires cookies)", rec.reason);
            }

            // If we know the best proxy tier, suggest it
            if let Some(ref best_tier) = dp.best_proxy_tier {
                if rec.new_proxy_tier.is_none() {
                    rec.new_proxy_tier = Some(best_tier.clone());
                }
            }

            // If the domain has a known rate limit, respect it
            if dp.min_delay_between_requests_ms > 0 {
                rec.delay_ms = rec.delay_ms.max(dp.min_delay_between_requests_ms);
            }

            // If we've had many consecutive failures, reduce confidence
            if dp.consecutive_failures > 10 {
                rec.confidence *= 0.5;
                rec.reason = format!(
                    "{} (WARNING: {} consecutive failures)",
                    rec.reason, dp.consecutive_failures
                );
            }

            // If success rate is very low, reconsider retrying
            if dp.total_attempts > 20 && dp.success_rate() < 0.05 {
                rec.should_retry = false;
                rec.confidence = 0.8;
                rec.reason = format!(
                    "Domain success rate too low ({:.1}%) — recommend manual investigation",
                    dp.success_rate() * 100.0
                );
            }

            // If we have a known good UA, suggest using it
            if dp.last_successful_ua.is_some() && rec.change_ua {
                rec.confidence = (rec.confidence + 0.1).min(1.0);
            }
        }

        // Factor in attempt count — diminishing returns
        if dead_letter.attempts > 5 {
            rec.confidence *= 0.7;
        }
        if dead_letter.attempts > 10 {
            rec.should_retry = false;
            rec.reason = format!("{} (exceeded 10 attempts — giving up)", rec.reason);
        }

        rec
    }

    /// Recommend an initial strategy for a domain we haven't tried yet.
    pub fn recommend_initial_strategy(&self, domain: &str) -> InitialStrategy {
        // Check if we already have data for this exact domain
        if let Some(dp) = self.domain_patterns.get(domain) {
            return InitialStrategy {
                use_browser: dp.requires_browser,
                use_cookie_farm: dp.requires_cookies,
                proxy_tier: dp
                    .best_proxy_tier
                    .clone()
                    .unwrap_or_else(|| "datacenter".to_string()),
                initial_delay_ms: dp.min_delay_between_requests_ms.max(100),
                max_concurrency: if dp.requires_browser { 5 } else { 20 },
                confidence: 0.9,
                reason: format!(
                    "Known domain — {:.0}% success rate over {} attempts",
                    dp.success_rate() * 100.0,
                    dp.total_attempts
                ),
            };
        }

        // Check for parent domain match (e.g., api.example.com -> example.com)
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() > 2 {
            let parent = parts[parts.len() - 2..].join(".");
            for (known_domain, dp) in &self.domain_patterns {
                if known_domain.ends_with(&parent) {
                    return InitialStrategy {
                        use_browser: dp.requires_browser,
                        use_cookie_farm: dp.requires_cookies,
                        proxy_tier: dp
                            .best_proxy_tier
                            .clone()
                            .unwrap_or_else(|| "datacenter".to_string()),
                        initial_delay_ms: dp.min_delay_between_requests_ms.max(200),
                        max_concurrency: if dp.requires_browser { 5 } else { 15 },
                        confidence: 0.6,
                        reason: format!(
                            "Similar domain {} — applying learned patterns",
                            known_domain
                        ),
                    };
                }
            }
        }

        // Default conservative strategy
        InitialStrategy {
            use_browser: false,
            use_cookie_farm: false,
            proxy_tier: "datacenter".to_string(),
            initial_delay_ms: 500,
            max_concurrency: 10,
            confidence: 0.3,
            reason: "Unknown domain — using conservative defaults".to_string(),
        }
    }

    // ── Persistence ────────────────────────────────────────────────────

    /// Save learned patterns to disk as JSON.
    pub fn save(&self, path: &Path) -> Result<(), String> {
        let json = serde_json::to_string_pretty(self).map_err(|e| e.to_string())?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        std::fs::write(path, json).map_err(|e| e.to_string())
    }

    /// Load learned patterns from disk.
    pub fn load(path: &Path) -> Result<Self, String> {
        let content = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
        serde_json::from_str(&content).map_err(|e| e.to_string())
    }

    /// Merge another intelligence database into this one.
    /// Combines counters and keeps the best-performing proxy/UA data.
    pub fn merge(&mut self, other: &RetryIntelligence) {
        self.total_tracked += other.total_tracked;

        for i in 0..24 {
            self.hourly_attempts[i] += other.hourly_attempts[i];
            self.hourly_successes[i] += other.hourly_successes[i];
        }
        for i in 0..7 {
            self.daily_attempts[i] += other.daily_attempts[i];
            self.daily_successes[i] += other.daily_successes[i];
        }
        self.recalculate_global_rates();

        // Merge domain patterns
        for (domain, other_dp) in &other.domain_patterns {
            let dp = self
                .domain_patterns
                .entry(domain.clone())
                .or_insert_with(|| DomainFailurePattern::new(domain));
            dp.total_attempts += other_dp.total_attempts;
            dp.total_successes += other_dp.total_successes;
            dp.total_success_latency_ms += other_dp.total_success_latency_ms;
            for (cat, count) in &other_dp.failure_by_category {
                *dp.failure_by_category.entry(cat.clone()).or_insert(0) += count;
            }
            for i in 0..24 {
                dp.hourly_attempts[i] += other_dp.hourly_attempts[i];
                dp.hourly_successes[i] += other_dp.hourly_successes[i];
            }
            for (tier, count) in &other_dp.tier_successes {
                *dp.tier_successes.entry(tier.clone()).or_insert(0) += count;
            }
            for (tier, count) in &other_dp.tier_attempts {
                *dp.tier_attempts.entry(tier.clone()).or_insert(0) += count;
            }
            // Keep the most recent successful data
            if other_dp.last_success_epoch > dp.last_success_epoch {
                dp.last_successful_ua = other_dp.last_successful_ua.clone();
                dp.last_successful_proxy = other_dp.last_successful_proxy.clone();
                dp.last_success_epoch = other_dp.last_success_epoch;
            }
            dp.recalculate();
        }

        // Merge proxy patterns
        for (proxy, other_pp) in &other.proxy_patterns {
            let pp = self
                .proxy_patterns
                .entry(proxy.clone())
                .or_insert_with(|| ProxyFailurePattern::new(proxy));
            pp.total_attempts += other_pp.total_attempts;
            pp.total_successes += other_pp.total_successes;
            pp.total_latency_ms += other_pp.total_latency_ms;
            for (cat, count) in &other_pp.failure_by_category {
                *pp.failure_by_category.entry(cat.clone()).or_insert(0) += count;
            }
            for d in &other_pp.good_domains {
                if !pp.good_domains.contains(d) && pp.good_domains.len() < 100 {
                    pp.good_domains.push(d.clone());
                }
            }
            for d in &other_pp.banned_domains {
                if !pp.banned_domains.contains(d) && pp.banned_domains.len() < 100 {
                    pp.banned_domains.push(d.clone());
                }
            }
            if other_pp.last_success_epoch > pp.last_success_epoch {
                pp.last_success_epoch = other_pp.last_success_epoch;
            }
            pp.recalculate();
        }
    }

    // ── Internal ───────────────────────────────────────────────────────

    fn recalculate_global_rates(&mut self) {
        for i in 0..24 {
            if self.hourly_attempts[i] > 0 {
                self.hourly_success[i] =
                    self.hourly_successes[i] as f64 / self.hourly_attempts[i] as f64;
            }
        }
        for i in 0..7 {
            if self.daily_attempts[i] > 0 {
                self.daily_success[i] =
                    self.daily_successes[i] as f64 / self.daily_attempts[i] as f64;
            }
        }
    }
}

impl Default for RetryIntelligence {
    fn default() -> Self {
        Self::new()
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

/// Extract domain from a URL string.
fn extract_domain(url: &str) -> String {
    let without_scheme = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .split(':')
        .next()
        .unwrap_or(without_scheme)
        .to_string()
}

fn normalize_proxy_tier_key(proxy_tier: &str) -> String {
    let tier = proxy_tier.trim();
    if tier.is_empty() {
        return "unknown".to_string();
    }

    match tier.to_ascii_lowercase().as_str() {
        // Defensive fallback: this value should be proxy tier, not scrape level.
        "l1quick" | "l2standard" | "l3deep" | "l4complete" | "l5extreme" => "unknown".to_string(),
        normalized => normalized.to_string(),
    }
}

/// Parse the Retry-After header value into milliseconds.
fn parse_retry_after(headers: &HashMap<String, String>) -> Option<u64> {
    let value = headers
        .get("retry-after")
        .or_else(|| headers.get("Retry-After"))
        .or_else(|| headers.get("retry-After"))?;

    // Try parsing as seconds (integer)
    if let Ok(secs) = value.trim().parse::<u64>() {
        return Some(secs * 1000);
    }

    // Try parsing as HTTP-date (we just extract a reasonable delay)
    // For simplicity, if it's a date string, default to 5 seconds
    if value.contains(',') || value.contains("GMT") {
        return Some(5_000);
    }

    None
}

/// Get current hour (0-23) in UTC.
fn current_hour() -> usize {
    let secs = epoch_secs();
    ((secs % 86400) / 3600) as usize
}

/// Get current day of week (0=Mon, 6=Sun).
fn current_day_of_week() -> usize {
    let secs = epoch_secs();
    // 1970-01-01 was a Thursday (day 3 if Mon=0)
    let days = secs / 86400;
    ((days + 3) % 7) as usize
}

/// Get current epoch seconds.
fn epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_headers(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    fn make_dead_letter(
        url: &str,
        status: Option<u16>,
        error: &str,
        body: &str,
        headers: HashMap<String, String>,
    ) -> DeadLetter {
        DeadLetter {
            id: "test-1".to_string(),
            job_type: "scrape".to_string(),
            target: "test".to_string(),
            url: url.to_string(),
            attempts: 3,
            final_error: error.to_string(),
            last_http_status: status,
            response_body_snippet: body.to_string(),
            response_headers: headers,
            failed_at: 1_000_000,
            reason_category: FailureCategory::Unknown,
        }
    }

    // ── Classification tests ───────────────────────────────────────────

    #[test]
    fn classify_cloudflare_403() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(
            Some(403),
            &make_headers(&[("server", "cloudflare")]),
            "",
            "",
        );
        assert_eq!(ft, SmartFailureType::ChallengeCloudflare);
    }

    #[test]
    fn classify_cloudflare_503() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(
            Some(503),
            &make_headers(&[("server", "cloudflare")]),
            "checking your browser",
            "",
        );
        assert_eq!(ft, SmartFailureType::ChallengeCloudflare);
    }

    #[test]
    fn classify_akamai() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(Some(403), &HashMap::new(), "var _abck = 'sensor_data'", "");
        assert_eq!(ft, SmartFailureType::ChallengeAkamai);
    }

    #[test]
    fn classify_perimeterx() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(Some(403), &HashMap::new(), "px-captcha block", "");
        assert_eq!(ft, SmartFailureType::ChallengePerimeterX);
    }

    #[test]
    fn classify_datadome() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(
            Some(403),
            &make_headers(&[("x-datadome-cid", "abc123")]),
            "",
            "",
        );
        assert_eq!(ft, SmartFailureType::ChallengeDataDome);
    }

    #[test]
    fn classify_kasada() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(Some(403), &HashMap::new(), "kasada bot detection", "");
        assert_eq!(ft, SmartFailureType::ChallengeKasada);
    }

    #[test]
    fn classify_rate_limit_soft() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(Some(429), &make_headers(&[("Retry-After", "30")]), "", "");
        assert_eq!(ft, SmartFailureType::RateLimitSoft);
    }

    #[test]
    fn classify_rate_limit_hard() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(Some(429), &HashMap::new(), "", "");
        assert_eq!(ft, SmartFailureType::RateLimitHard);
    }

    #[test]
    fn classify_tls_failure() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(None, &HashMap::new(), "", "tls handshake failed");
        assert_eq!(ft, SmartFailureType::TlsHandshakeFail);
    }

    #[test]
    fn classify_dns_failure() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(None, &HashMap::new(), "", "dns resolve failed");
        assert_eq!(ft, SmartFailureType::DnsFailure);
    }

    #[test]
    fn classify_connection_reset() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(None, &HashMap::new(), "", "connection reset by peer");
        assert_eq!(ft, SmartFailureType::ConnectionReset);
    }

    #[test]
    fn classify_auth_required() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(Some(401), &HashMap::new(), "", "");
        assert_eq!(ft, SmartFailureType::AuthRequired);
    }

    #[test]
    fn classify_geo_blocked() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(Some(451), &HashMap::new(), "", "");
        assert_eq!(ft, SmartFailureType::GeoBlocked);
    }

    #[test]
    fn classify_server_error() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(Some(500), &HashMap::new(), "", "");
        assert_eq!(ft, SmartFailureType::ServerError);
    }

    #[test]
    fn classify_content_changed() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(
            None,
            &HashMap::new(),
            "",
            "empty extraction — no fields found",
        );
        assert_eq!(ft, SmartFailureType::ContentChanged);
    }

    #[test]
    fn classify_h2_mismatch() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(None, &HashMap::new(), "", "http2 protocol error");
        assert_eq!(ft, SmartFailureType::H2Mismatch);
    }

    #[test]
    fn classify_proxy_dead() {
        let ri = RetryIntelligence::new();
        let ft = ri.classify_failure(None, &HashMap::new(), "", "proxy connection refused");
        assert_eq!(ft, SmartFailureType::NetworkError);
    }

    // ── Retryable tests ────────────────────────────────────────────────

    #[test]
    fn smart_failure_retryable() {
        assert!(SmartFailureType::RateLimitSoft.is_retryable());
        assert!(SmartFailureType::ChallengeCloudflare.is_retryable());
        assert!(SmartFailureType::ProxyDead.is_retryable());
        assert!(!SmartFailureType::DnsFailure.is_retryable());
        assert!(!SmartFailureType::AuthRequired.is_retryable());
        assert!(!SmartFailureType::ContentChanged.is_retryable());
    }

    #[test]
    fn smart_failure_needs_browser() {
        assert!(SmartFailureType::ChallengeCloudflare.needs_browser_escalation());
        assert!(SmartFailureType::ChallengeDataDome.needs_browser_escalation());
        assert!(!SmartFailureType::RateLimitSoft.needs_browser_escalation());
        assert!(!SmartFailureType::ProxyDead.needs_browser_escalation());
    }

    #[test]
    fn smart_failure_needs_proxy_change() {
        assert!(SmartFailureType::RateLimitHard.needs_proxy_change());
        assert!(SmartFailureType::ProxyDead.needs_proxy_change());
        assert!(SmartFailureType::ProxyBanned.needs_proxy_change());
        assert!(!SmartFailureType::ChallengeCloudflare.needs_proxy_change());
        assert!(!SmartFailureType::DnsFailure.needs_proxy_change());
    }

    // ── Learning tests ─────────────────────────────────────────────────

    #[test]
    fn record_success_updates_domain() {
        let mut ri = RetryIntelligence::new();
        ri.record_success(
            "example.com",
            "proxy1:8080",
            150,
            "datacenter",
            Some("Mozilla/5.0"),
        );
        ri.record_success("example.com", "proxy2:8080", 200, "datacenter", None);

        let dp = ri.domain_pattern("example.com").unwrap();
        assert_eq!(dp.total_attempts, 2);
        assert_eq!(dp.total_successes, 2);
        assert_eq!(dp.consecutive_failures, 0);
        assert!(dp.avg_success_latency_ms > 0.0);
        assert_eq!(dp.last_successful_proxy, Some("proxy2:8080".to_string()));
    }

    #[test]
    fn record_success_normalizes_level_id_tier_key() {
        let mut ri = RetryIntelligence::new();
        ri.record_success("example.com", "proxy1:8080", 150, "L5Extreme", None);

        let dp = ri.domain_pattern("example.com").unwrap();
        assert_eq!(dp.best_proxy_tier.as_deref(), None);
    }

    #[test]
    fn record_failure_updates_domain() {
        let mut ri = RetryIntelligence::new();
        let dl = make_dead_letter(
            "https://example.com/page",
            Some(429),
            "rate limited",
            "",
            make_headers(&[("Retry-After", "30")]),
        );
        ri.record_failure(&dl);

        let dp = ri.domain_pattern("example.com").unwrap();
        assert_eq!(dp.total_attempts, 1);
        assert_eq!(dp.total_successes, 0);
        assert_eq!(dp.consecutive_failures, 1);
        assert!(dp.failure_by_category.contains_key("RateLimitSoft"));
    }

    #[test]
    fn consecutive_failures_reset_on_success() {
        let mut ri = RetryIntelligence::new();
        let dl = make_dead_letter(
            "https://example.com/page",
            Some(500),
            "server error",
            "",
            HashMap::new(),
        );
        ri.record_failure(&dl);
        ri.record_failure(&dl);
        ri.record_failure(&dl);

        let dp = ri.domain_pattern("example.com").unwrap();
        assert_eq!(dp.consecutive_failures, 3);

        ri.record_success("example.com", "proxy1", 100, "datacenter", None);
        let dp = ri.domain_pattern("example.com").unwrap();
        assert_eq!(dp.consecutive_failures, 0);
    }

    #[test]
    fn learn_browser_requirement() {
        let mut ri = RetryIntelligence::new();
        // Simulate 10 Cloudflare challenge failures
        for _ in 0..10 {
            let dl = make_dead_letter(
                "https://protected.com/data",
                Some(403),
                "",
                "cf_chl_opt cloudflare challenge",
                make_headers(&[("server", "cloudflare")]),
            );
            ri.record_failure(&dl);
        }

        let dp = ri.domain_pattern("protected.com").unwrap();
        assert!(dp.requires_browser);
        assert!(dp.requires_cookies);
    }

    // ── Recommendation tests ───────────────────────────────────────────

    #[test]
    fn recommend_retry_for_rate_limit() {
        let ri = RetryIntelligence::new();
        let dl = make_dead_letter(
            "https://example.com/api",
            Some(429),
            "",
            "",
            make_headers(&[("Retry-After", "10")]),
        );
        let rec = ri.recommend_retry(&dl);
        assert!(rec.should_retry);
        assert_eq!(rec.delay_ms, 10_000); // 10 seconds from Retry-After
        assert!(!rec.change_proxy); // soft limit, don't change proxy
        assert!(rec.confidence > 0.8);
    }

    #[test]
    fn recommend_retry_for_cloudflare() {
        let ri = RetryIntelligence::new();
        let dl = make_dead_letter(
            "https://example.com/",
            Some(403),
            "",
            "cloudflare turnstile",
            make_headers(&[("server", "cloudflare")]),
        );
        let rec = ri.recommend_retry(&dl);
        assert!(rec.should_retry);
        assert!(rec.upgrade_tier);
        assert!(rec.use_cookie_farm);
        assert!(rec.change_proxy);
    }

    #[test]
    fn recommend_no_retry_for_dns_failure() {
        let ri = RetryIntelligence::new();
        let dl = make_dead_letter(
            "https://nonexistent.example/",
            None,
            "dns resolve failed: no such host",
            "",
            HashMap::new(),
        );
        let rec = ri.recommend_retry(&dl);
        assert!(!rec.should_retry);
    }

    #[test]
    fn recommend_no_retry_after_too_many_attempts() {
        let ri = RetryIntelligence::new();
        let mut dl = make_dead_letter(
            "https://example.com/page",
            Some(500),
            "server error",
            "",
            HashMap::new(),
        );
        dl.attempts = 11;
        let rec = ri.recommend_retry(&dl);
        assert!(!rec.should_retry);
        assert!(rec.reason.contains("exceeded 10 attempts"));
    }

    #[test]
    fn recommend_uses_learned_patterns() {
        let mut ri = RetryIntelligence::new();

        // Teach it that example.com requires browser
        for _ in 0..10 {
            let dl = make_dead_letter(
                "https://example.com/data",
                Some(403),
                "",
                "cf_chl_opt cloudflare",
                make_headers(&[("server", "cloudflare")]),
            );
            ri.record_failure(&dl);
        }

        // Now a generic 403 should still recommend browser escalation
        let dl = make_dead_letter(
            "https://example.com/other",
            Some(403),
            "",
            "access denied",
            HashMap::new(),
        );
        let rec = ri.recommend_retry(&dl);
        assert!(
            rec.upgrade_tier,
            "should recommend browser since domain learned it"
        );
    }

    // ── Initial strategy tests ─────────────────────────────────────────

    #[test]
    fn initial_strategy_unknown_domain() {
        let ri = RetryIntelligence::new();
        let strat = ri.recommend_initial_strategy("brand-new-domain.com");
        assert!(!strat.use_browser);
        assert!(!strat.use_cookie_farm);
        assert_eq!(strat.proxy_tier, "datacenter");
        assert!(strat.confidence < 0.5);
    }

    #[test]
    fn initial_strategy_known_domain() {
        let mut ri = RetryIntelligence::new();
        ri.record_success("known.com", "proxy1", 100, "residential", None);
        ri.record_success("known.com", "proxy2", 120, "residential", None);

        let strat = ri.recommend_initial_strategy("known.com");
        assert!(strat.confidence > 0.8);
    }

    #[test]
    fn initial_strategy_parent_domain_match() {
        let mut ri = RetryIntelligence::new();
        // Train on api.example.com
        for _ in 0..10 {
            let dl = make_dead_letter(
                "https://api.example.com/v1/data",
                Some(403),
                "",
                "cloudflare challenge cf_chl_opt",
                make_headers(&[("server", "cloudflare")]),
            );
            ri.record_failure(&dl);
        }

        // Query for www.example.com — should inherit from api.example.com
        let strat = ri.recommend_initial_strategy("www.example.com");
        assert!(strat.use_browser || strat.use_cookie_farm);
        assert!(strat.confidence > 0.5);
    }

    // ── Persistence tests ──────────────────────────────────────────────

    #[test]
    fn save_and_load_roundtrip() {
        let mut ri = RetryIntelligence::new();
        ri.record_success(
            "example.com",
            "proxy1",
            100,
            "datacenter",
            Some("Mozilla/5.0"),
        );
        let dl = make_dead_letter(
            "https://blocked.com/page",
            Some(403),
            "",
            "cloudflare",
            make_headers(&[("server", "cloudflare")]),
        );
        ri.record_failure(&dl);

        let dir = std::env::temp_dir().join("tallow_ri_test");
        let path = dir.join("intelligence.json");

        ri.save(&path).expect("save failed");
        let loaded = RetryIntelligence::load(&path).expect("load failed");

        assert_eq!(loaded.total_tracked, ri.total_tracked);
        assert_eq!(loaded.known_domain_count(), ri.known_domain_count());
        assert!(loaded.domain_pattern("example.com").is_some());
        assert!(loaded.domain_pattern("blocked.com").is_some());

        // Cleanup
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ── Merge tests ────────────────────────────────────────────────────

    #[test]
    fn merge_combines_data() {
        let mut ri1 = RetryIntelligence::new();
        ri1.record_success("a.com", "p1", 100, "dc", None);

        let mut ri2 = RetryIntelligence::new();
        ri2.record_success("b.com", "p2", 200, "dc", None);
        ri2.record_success("a.com", "p3", 150, "res", None);

        ri1.merge(&ri2);

        assert_eq!(ri1.total_tracked, 3);
        assert_eq!(ri1.known_domain_count(), 2);
        let dp = ri1.domain_pattern("a.com").unwrap();
        assert_eq!(dp.total_attempts, 2);
        assert_eq!(dp.total_successes, 2);
    }

    // ── Helper tests ───────────────────────────────────────────────────

    #[test]
    fn extract_domain_works() {
        assert_eq!(extract_domain("https://example.com/path"), "example.com");
        assert_eq!(
            extract_domain("http://api.example.com:8080/v1"),
            "api.example.com"
        );
        assert_eq!(extract_domain("https://example.com"), "example.com");
        assert_eq!(extract_domain("example.com/path"), "example.com");
    }

    #[test]
    fn parse_retry_after_seconds() {
        let headers = make_headers(&[("Retry-After", "30")]);
        assert_eq!(parse_retry_after(&headers), Some(30_000));
    }

    #[test]
    fn parse_retry_after_date() {
        let headers = make_headers(&[("Retry-After", "Wed, 21 Oct 2026 07:28:00 GMT")]);
        assert_eq!(parse_retry_after(&headers), Some(5_000)); // fallback
    }

    #[test]
    fn parse_retry_after_missing() {
        let headers: HashMap<String, String> = HashMap::new();
        assert_eq!(parse_retry_after(&headers), None);
    }

    // ── Proxy pattern tests ────────────────────────────────────────────

    #[test]
    fn proxy_dead_detection() {
        let mut pp = ProxyFailurePattern::new("dead-proxy:8080");
        pp.consecutive_failures = 20;
        assert!(pp.is_dead());

        pp.consecutive_failures = 19;
        assert!(!pp.is_dead());
    }

    #[test]
    fn proxy_slow_leak_detection() {
        let mut pp = ProxyFailurePattern::new("slow-proxy:8080");
        // First 5 samples: fast
        for _ in 0..5 {
            pp.recent_latencies.push(100);
        }
        // Last 5 samples: much slower
        for _ in 0..5 {
            pp.recent_latencies.push(300);
        }
        pp.recalculate();
        assert!(pp.latency_trending_up);
    }
}
