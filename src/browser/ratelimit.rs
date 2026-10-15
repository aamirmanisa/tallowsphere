//! Adaptive rate limiting with per-domain tracking, time-of-day awareness,
//! and circuit breaker pattern.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::browser::circuit_breaker::CircuitBreaker;
use crate::browser::error::BrowserError;

// ─────────────────────────────────────────────────────────────────────────────
// Adaptive Rate Limiter
// ─────────────────────────────────────────────────────────────────────────────

/// Per-domain adaptive rate limiter.
#[derive(Debug, Clone)]
pub struct AdaptiveRateLimiter {
    /// Current tokens available.
    tokens: f64,
    /// Maximum bucket capacity.
    max_tokens: f64,
    /// Current refill rate (tokens per second) — adapts over time.
    refill_rate: f64,
    /// Starting rate.
    base_rate: f64,
    /// Minimum rate floor (never go slower than this).
    min_rate: f64,
    /// Maximum rate ceiling.
    max_rate: f64,
    /// Last time tokens were refilled.
    last_refill: Instant,
    /// Consecutive successful requests.
    consecutive_success: u32,
    /// Consecutive failures (403, 429, CAPTCHA).
    consecutive_failure: u32,
    /// Total CAPTCHAs encountered.
    captcha_count: u32,
    /// Circuit breaker: domain is paused until this time.
    circuit_break_until: Option<Instant>,
    /// Total requests sent.
    total_requests: u64,
    /// Total successful responses.
    total_success: u64,
}

impl AdaptiveRateLimiter {
    /// Create a new limiter with the given base rate (requests per second).
    pub fn new(base_rate: f64) -> Self {
        Self {
            tokens: base_rate,
            max_tokens: base_rate * 2.0,
            refill_rate: base_rate,
            base_rate,
            min_rate: 0.05, // 1 request per 20 seconds minimum
            max_rate: base_rate * 5.0,
            last_refill: Instant::now(),
            consecutive_success: 0,
            consecutive_failure: 0,
            captcha_count: 0,
            circuit_break_until: None,
            total_requests: 0,
            total_success: 0,
        }
    }

    /// Refill tokens based on elapsed time.
    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.effective_rate())
            .min(self.max_tokens);
        self.last_refill = now;
    }

    /// Effective rate after time-of-day multiplier.
    fn effective_rate(&self) -> f64 {
        self.refill_rate * Self::time_of_day_multiplier()
    }

    /// Time-of-day multiplier: lower during business hours, higher at night.
    fn time_of_day_multiplier() -> f64 {
        use chrono::Timelike;
        let hour = chrono::Local::now().hour();
        match hour {
            0..=5 => 1.5,   // Late night — less monitoring
            6..=8 => 0.8,   // Morning ramp-up
            9..=16 => 0.6,  // Peak business hours — highest scrutiny
            17..=20 => 0.8, // Evening
            21..=23 => 1.2, // Late evening
            _ => 1.0,
        }
    }

    /// Check if the circuit breaker is active.
    pub fn is_circuit_broken(&self) -> bool {
        if let Some(until) = self.circuit_break_until {
            Instant::now() < until
        } else {
            false
        }
    }

    /// Try to acquire a token. Returns true if allowed, false if rate-limited.
    pub fn try_acquire(&mut self) -> bool {
        if self.is_circuit_broken() {
            return false;
        }

        self.refill();

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            self.total_requests += 1;
            true
        } else {
            false
        }
    }

    /// How long to wait before next request is allowed.
    pub fn wait_duration(&mut self) -> Duration {
        if self.is_circuit_broken() {
            if let Some(until) = self.circuit_break_until {
                return until.duration_since(Instant::now());
            }
        }

        self.refill();

        if self.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let needed = 1.0 - self.tokens;
            let rate = self.effective_rate().max(self.min_rate);
            Duration::from_secs_f64(needed / rate)
        }
    }

    /// Report a successful request (200, 301, 302).
    pub fn report_success(&mut self) {
        self.consecutive_success += 1;
        self.consecutive_failure = 0;
        self.total_success += 1;

        // Gradual speed-up
        if self.consecutive_success >= 50 {
            self.refill_rate = (self.refill_rate * 1.2).min(self.max_rate);
        } else if self.consecutive_success >= 10 {
            self.refill_rate = (self.refill_rate * 1.1).min(self.max_rate);
        }
    }

    /// Report a soft block (403, 429, CAPTCHA detected).
    pub fn report_soft_block(&mut self) {
        self.consecutive_success = 0;
        self.consecutive_failure += 1;
        self.captcha_count += 1;

        // Exponential backoff
        let factor = 2.0_f64.powi(self.consecutive_failure.min(6) as i32);
        self.refill_rate = (self.refill_rate / factor).max(self.min_rate);

        // Circuit breaker after 5 consecutive failures
        if self.consecutive_failure >= 5 {
            let pause = Duration::from_secs(60 * self.consecutive_failure.min(10) as u64);
            self.circuit_break_until = Some(Instant::now() + pause);
        }
    }

    /// Report a hard block (IP ban, extended denial).
    pub fn report_hard_block(&mut self) {
        self.consecutive_success = 0;
        self.consecutive_failure += 1;
        self.refill_rate = self.min_rate;

        // Long circuit break: 5-30 minutes
        let pause = Duration::from_secs(300 + 60 * self.consecutive_failure.min(25) as u64);
        self.circuit_break_until = Some(Instant::now() + pause);
    }

    /// Reset the circuit breaker.
    pub fn reset_circuit(&mut self) {
        self.circuit_break_until = None;
    }

    /// Reset to base rate (e.g., after IP rotation).
    pub fn reset(&mut self) {
        self.refill_rate = self.base_rate;
        self.tokens = self.base_rate;
        self.consecutive_success = 0;
        self.consecutive_failure = 0;
        self.circuit_break_until = None;
    }

    /// Current effective rate.
    pub fn current_rate(&self) -> f64 {
        self.refill_rate
    }

    /// Success rate percentage.
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 { return 100.0; }
        (self.total_success as f64 / self.total_requests as f64) * 100.0
    }

    /// Summary string.
    pub fn summary(&self) -> String {
        format!(
            "rate={:.2}/s success={:.0}% total={} captchas={} circuit={}",
            self.refill_rate,
            self.success_rate(),
            self.total_requests,
            self.captcha_count,
            if self.is_circuit_broken() { "OPEN" } else { "closed" },
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain Rate Manager
// ─────────────────────────────────────────────────────────────────────────────

/// Manages rate limiters across multiple domains with domain-group awareness.
pub struct DomainRateManager {
    /// Per-domain rate limiters.
    limiters: HashMap<String, AdaptiveRateLimiter>,
    /// Default base rate for new domains.
    default_rate: f64,
    /// Domain groups (e.g., all Shopify sites share rate state).
    groups: HashMap<String, Vec<String>>,
}

impl DomainRateManager {
    pub fn new(default_rate: f64) -> Self {
        Self {
            limiters: HashMap::new(),
            default_rate,
            groups: Self::default_groups(),
        }
    }

    /// Pre-configured domain groups that share anti-bot infrastructure.
    fn default_groups() -> HashMap<String, Vec<String>> {
        let mut groups = HashMap::new();
        groups.insert("shopify".into(), vec!["myshopify.com".into()]);
        groups
    }

    /// Get or create a rate limiter for a domain.
    pub fn get_limiter(&mut self, domain: &str) -> &mut AdaptiveRateLimiter {
        let rate = self.rate_for_domain(domain);
        self.limiters.entry(domain.to_string())
            .or_insert_with(|| AdaptiveRateLimiter::new(rate))
    }

    /// Recommended base rate for known domains.
    fn rate_for_domain(&self, domain: &str) -> f64 {
        match domain {
            d if d.contains("amazon.com") => 0.33,       // 1 req per 3s
            d if d.contains("walmart.com") => 0.5,       // 1 req per 2s
            d if d.contains("target.com") => 0.5,        // 1 req per 2s
            d if d.contains("bestbuy.com") => 0.33,      // 1 req per 3s
            d if d.contains("nike.com") => 0.33,          // 1 req per 3s
            d if d.contains("adidas.com") => 0.25,        // 1 req per 4s (double layer)
            d if d.contains("ebay.com") => 0.5,           // 1 req per 2s
            d if d.contains("google.com") => 0.1,         // 1 req per 10s
            d if d.contains("x.com") || d.contains("twitter.com") => 0.33,
            d if d.contains("reddit.com") => 0.5,
            d if d.contains("slickdeals.net") => 1.0,     // Light protection
            d if d.contains("myshopify.com") => 1.0,      // Shopify is lenient
            _ => self.default_rate,
        }
    }

    /// Try to acquire a token for a domain.
    pub fn try_acquire(&mut self, domain: &str) -> bool {
        self.get_limiter(domain).try_acquire()
    }

    /// Get wait duration for a domain.
    pub fn wait_duration(&mut self, domain: &str) -> Duration {
        self.get_limiter(domain).wait_duration()
    }

    /// Report success for a domain.
    pub fn report_success(&mut self, domain: &str) {
        self.get_limiter(domain).report_success();
    }

    /// Report soft block for a domain.
    pub fn report_soft_block(&mut self, domain: &str) {
        self.get_limiter(domain).report_soft_block();

        // Cross-domain penalty for domain groups
        if let Some(group) = self.find_group(domain) {
            for peer in group {
                if peer != domain {
                    if let Some(limiter) = self.limiters.get_mut(&peer) {
                        limiter.refill_rate = (limiter.refill_rate * 0.5).max(limiter.min_rate);
                    }
                }
            }
        }
    }

    /// Report hard block for a domain.
    pub fn report_hard_block(&mut self, domain: &str) {
        self.get_limiter(domain).report_hard_block();
    }

    /// Find the domain group for a domain.
    fn find_group(&self, domain: &str) -> Option<Vec<String>> {
        for (_group_name, patterns) in &self.groups {
            for pattern in patterns {
                if domain.contains(pattern.as_str()) {
                    // Return all domains in our limiters that match this group
                    let peers: Vec<String> = self.limiters.keys()
                        .filter(|d| d.contains(pattern.as_str()))
                        .cloned()
                        .collect();
                    if !peers.is_empty() {
                        return Some(peers);
                    }
                }
            }
        }
        None
    }

    /// Summary of all domains.
    pub fn summary(&self) -> Vec<(String, String)> {
        self.limiters.iter()
            .map(|(domain, limiter)| (domain.clone(), limiter.summary()))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Response classification
// ─────────────────────────────────────────────────────────────────────────────

/// Classify an HTTP response for rate limiting purposes.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ResponseClass {
    /// Successful response (200, 301, 302).
    Success,
    /// Soft block — CAPTCHA, rate limited, temporarily denied.
    SoftBlock,
    /// Hard block — IP ban, extended denial.
    HardBlock,
    /// Error unrelated to blocking (DNS failure, timeout, server error).
    TransientError,
}

impl ResponseClass {
    /// Classify an HTTP status code.
    pub fn from_status(status: u16) -> Self {
        match status {
            200 | 201 | 301 | 302 | 304 => ResponseClass::Success,
            429 => ResponseClass::SoftBlock,
            403 => ResponseClass::SoftBlock, // Could be hard block — check body
            503 => ResponseClass::SoftBlock, // Often anti-bot interstitial
            500 | 502 | 504 => ResponseClass::TransientError,
            _ => ResponseClass::TransientError,
        }
    }

    /// Check if response body indicates a CAPTCHA/block page.
    pub fn from_body(body: &str) -> Self {
        let lower = body.to_lowercase();
        if lower.contains("captcha")
            || lower.contains("unusual traffic")
            || lower.contains("are you a robot")
            || lower.contains("verify you are a human")
            || lower.contains("access denied")
            || lower.contains("please complete the challenge")
            || lower.contains("enable javascript and cookies")
            || lower.contains("pardon our interruption")
            || lower.contains("automated access")
            || lower.contains("bot detection")
        {
            return ResponseClass::SoftBlock;
        }

        if lower.contains("your ip has been blocked")
            || lower.contains("permanently banned")
            || lower.contains("your access has been restricted")
        {
            return ResponseClass::HardBlock;
        }

        ResponseClass::Success
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain Governor — single place that composes a domain's pacing
// ─────────────────────────────────────────────────────────────────────────────

/// One per-domain governor composing the rate limiter (token bucket), the
/// circuit breaker, an AutoThrottle-style adaptive concurrency limiter, and the
/// robots.txt Crawl-delay politeness floor.
///
/// This is the **canonical** domain-pacing path. It deduplicates the legacy
/// token-bucket in `robots.rs::RateLimiter` (which is kept for back-compat but
/// should be routed through here) so a domain's rate, circuit-break, adaptive
/// concurrency, and Crawl-delay are all governed in one place.
#[derive(Debug, Clone)]
pub struct DomainGovernor {
    /// Token-bucket rate limiter with soft/hard block + circuit-break signals.
    limiter: AdaptiveRateLimiter,
    /// Per-target circuit breaker (trips on sustained failures).
    breaker: CircuitBreaker,
    /// Robots.txt Crawl-delay enforced between requests (politeness floor).
    crawl_delay: Option<Duration>,
    /// Timestamp of the last request — used to enforce Crawl-delay.
    last_request: Option<Instant>,
    // ── Adaptive concurrency (AutoThrottle-equivalent) ──
    /// Current concurrency limit (adjusts by observed latency).
    concurrency_current: u32,
    /// Minimum concurrency floor.
    concurrency_min: u32,
    /// Maximum concurrency ceiling.
    concurrency_max: u32,
    /// Latency (ms) at/below which concurrency may increase.
    target_latency_ms: u64,
    /// Additive increase step when under target latency.
    increase_step: u32,
    /// Multiplicative decrease factor when over target latency.
    decrease_factor: f64,
}

impl DomainGovernor {
    /// Create a governor for a domain at the given base request rate (per sec).
    pub fn new(domain: &str, base_rate: f64) -> Self {
        Self {
            limiter: AdaptiveRateLimiter::new(base_rate),
            breaker: CircuitBreaker::new(domain),
            crawl_delay: None,
            last_request: None,
            concurrency_current: 1,
            concurrency_min: 1,
            concurrency_max: 8,
            target_latency_ms: 1000,
            increase_step: 1,
            decrease_factor: 0.75,
        }
    }

    /// Set the robots.txt Crawl-delay politeness floor for this domain.
    pub fn with_crawl_delay(mut self, delay: Duration) -> Self {
        self.crawl_delay = Some(delay);
        self
    }

    /// Configure the adaptive-concurrency bounds and latency target.
    pub fn with_concurrency_bounds(
        mut self,
        min: u32,
        max: u32,
        target_latency_ms: u64,
    ) -> Self {
        self.concurrency_min = min.max(1);
        self.concurrency_max = max.max(min);
        self.concurrency_current = self.concurrency_current.clamp(self.concurrency_min, self.concurrency_max);
        self.target_latency_ms = target_latency_ms;
        self
    }

    /// Whether the circuit breaker is currently open (requests blocked).
    pub fn is_circuit_broken(&self) -> bool {
        matches!(
            self.breaker.state,
            crate::browser::circuit_breaker::CircuitState::Open(_)
        )
    }

    /// Async blocking acquire: honors robots Crawl-delay, the circuit breaker,
    /// and the adaptive token bucket. Returns `Err(RateLimitExceeded)` when the
    /// circuit is open or the token bucket is exhausted.
    pub async fn acquire(&mut self, domain: &str) -> Result<(), BrowserError> {
        // 1. robots.txt Crawl-delay politeness floor.
        if let Some(last) = self.last_request {
            if let Some(delay) = self.crawl_delay {
                let elapsed = last.elapsed();
                if elapsed < delay {
                    tokio::time::sleep(delay - elapsed).await;
                }
            }
        }

        // 2. Circuit breaker.
        if !self.breaker.should_allow() {
            return Err(BrowserError::RateLimitExceeded(domain.to_string()));
        }

        // 3. Adaptive token bucket — wait for a token.
        let wait = self.limiter.wait_duration();
        if !wait.is_zero() {
            tokio::time::sleep(wait).await;
        }
        if !self.limiter.try_acquire() {
            return Err(BrowserError::RateLimitExceeded(domain.to_string()));
        }
        self.last_request = Some(Instant::now());
        Ok(())
    }

    /// Record a request result: feed the circuit breaker, the adaptive
    /// concurrency limiter, and (on success) the rate limiter.
    pub fn record_result(&mut self, ok: bool, response_time_ms: u64) {
        self.adjust_concurrency(response_time_ms);
        if ok {
            self.breaker.on_success();
            self.limiter.report_success();
        } else {
            self.breaker.on_failure();
        }
    }

    /// Report a domain-level soft block (429 / anti-bot challenge): back the
    /// token bucket off and trip the breaker on repeated failure.
    pub fn report_soft_block(&mut self) {
        self.limiter.report_soft_block();
        self.breaker.on_failure();
    }

    /// Report a hard block (IP ban): long backoff + circuit break.
    pub fn report_hard_block(&mut self) {
        self.limiter.report_hard_block();
        self.breaker.on_failure();
    }

    /// Report a clean success (also used by the fetch loop on 2xx).
    pub fn report_success(&mut self) {
        self.limiter.report_success();
        self.breaker.on_success();
    }

    /// AutoThrottle adjustment: increase concurrency when under the latency
    /// target, decrease it (multiplicatively) when over.
    pub fn adjust_concurrency(&mut self, response_time_ms: u64) {
        if response_time_ms <= self.target_latency_ms {
            self.concurrency_current = self
                .concurrency_current
                .saturating_add(self.increase_step)
                .min(self.concurrency_max);
        } else {
            let next = (self.concurrency_current as f64 * self.decrease_factor) as u32;
            self.concurrency_current = next.max(self.concurrency_min);
        }
    }

    /// Current adaptive concurrency limit.
    pub fn current_concurrency(&self) -> u32 {
        self.concurrency_current
    }

    /// Current effective request rate (req/sec).
    pub fn current_rate(&self) -> f64 {
        self.limiter.current_rate()
    }

    /// Human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "rate={:.2}/s concurrency={} circuit={} crawldelay={}",
            self.limiter.current_rate(),
            self.concurrency_current,
            if self.is_circuit_broken() { "OPEN" } else { "closed" },
            self.crawl_delay
                .map(|d| format!("{:?}", d))
                .unwrap_or_else(|| "none".into()),
        )
    }
}

/// Registry of per-domain [`DomainGovernor`]s with a shared default rate and
/// optional default Crawl-delay.
pub struct DomainGovernorRegistry {
    governors: HashMap<String, DomainGovernor>,
    default_rate: f64,
    default_crawl_delay: Option<Duration>,
}

impl DomainGovernorRegistry {
    pub fn new(default_rate: f64) -> Self {
        Self {
            governors: HashMap::new(),
            default_rate,
            default_crawl_delay: None,
        }
    }

    /// Set a default robots Crawl-delay applied to new governors.
    pub fn set_default_crawl_delay(&mut self, delay: Duration) {
        self.default_crawl_delay = Some(delay);
    }

    /// Get or create the governor for a domain.
    pub fn get_or_create(&mut self, domain: &str) -> &mut DomainGovernor {
        self.governors.entry(domain.to_string()).or_insert_with(|| {
            let mut g = DomainGovernor::new(domain, self.default_rate);
            if let Some(d) = self.default_crawl_delay {
                g.crawl_delay = Some(d);
            }
            g
        })
    }

    /// Async blocking acquire for a domain (honors Crawl-delay + breaker + bucket).
    pub async fn acquire_async(&mut self, domain: &str) -> Result<(), BrowserError> {
        self.get_or_create(domain).acquire(domain).await
    }

    /// Report a soft block for a domain to its governor.
    pub fn report_soft_block(&mut self, domain: &str) {
        self.get_or_create(domain).report_soft_block();
    }

    /// Report a hard block for a domain to its governor.
    pub fn report_hard_block(&mut self, domain: &str) {
        self.get_or_create(domain).report_hard_block();
    }

    /// Record a request result for a domain.
    pub fn record_result(&mut self, domain: &str, ok: bool, response_time_ms: u64) {
        self.get_or_create(domain).record_result(ok, response_time_ms);
    }

    /// Summary of all governed domains.
    pub fn summary(&self) -> Vec<(String, String)> {
        self.governors
            .iter()
            .map(|(domain, gov)| (domain.clone(), gov.summary()))
            .collect()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adaptive_basic() {
        let mut limiter = AdaptiveRateLimiter::new(2.0);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        // Bucket should be near empty now
    }

    #[test]
    fn adaptive_speedup() {
        let mut limiter = AdaptiveRateLimiter::new(1.0);
        let initial_rate = limiter.current_rate();

        for _ in 0..50 {
            limiter.report_success();
        }

        assert!(limiter.current_rate() > initial_rate);
    }

    #[test]
    fn adaptive_backoff() {
        let mut limiter = AdaptiveRateLimiter::new(2.0);
        let initial_rate = limiter.current_rate();

        limiter.report_soft_block();
        assert!(limiter.current_rate() < initial_rate);

        limiter.report_soft_block();
        assert!(limiter.current_rate() < initial_rate / 2.0);
    }

    #[test]
    fn circuit_breaker() {
        let mut limiter = AdaptiveRateLimiter::new(2.0);

        for _ in 0..5 {
            limiter.report_soft_block();
        }

        assert!(limiter.is_circuit_broken());
        assert!(!limiter.try_acquire());
    }

    #[test]
    fn hard_block() {
        let mut limiter = AdaptiveRateLimiter::new(2.0);
        limiter.report_hard_block();
        assert!(limiter.is_circuit_broken());
        assert_eq!(limiter.current_rate(), limiter.min_rate);
    }

    #[test]
    fn domain_rate_manager() {
        let mut mgr = DomainRateManager::new(1.0);

        // Amazon should get slower default rate
        let wait = mgr.wait_duration("www.amazon.com");
        assert!(wait <= Duration::from_secs(5));

        // Slickdeals should be faster
        let _ = mgr.get_limiter("slickdeals.net");
    }

    #[test]
    fn response_classification() {
        assert_eq!(ResponseClass::from_status(200), ResponseClass::Success);
        assert_eq!(ResponseClass::from_status(429), ResponseClass::SoftBlock);
        assert_eq!(ResponseClass::from_status(403), ResponseClass::SoftBlock);
        assert_eq!(ResponseClass::from_status(500), ResponseClass::TransientError);

        assert_eq!(
            ResponseClass::from_body("Please complete the CAPTCHA"),
            ResponseClass::SoftBlock
        );
        assert_eq!(
            ResponseClass::from_body("Product details page"),
            ResponseClass::Success
        );
    }

    #[test]
    fn reset_rate() {
        let mut limiter = AdaptiveRateLimiter::new(2.0);
        for _ in 0..5 {
            limiter.report_soft_block();
        }
        assert!(limiter.is_circuit_broken());

        limiter.reset();
        assert!(!limiter.is_circuit_broken());
        assert_eq!(limiter.current_rate(), 2.0);
    }
}
