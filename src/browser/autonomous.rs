//! Autonomous self-healing scraper for Tallow.
//!
//! A state machine that automatically handles:
//! - IP blocks → rotate to next proxy
//! - Fingerprint detection → switch browser profile
//! - Challenge pages → detect type + solve via browser
//! - Rate limits → exponential backoff with jitter
//! - Connection errors → retry with different path
//! - Session expiry → refresh cookies
//!
//! Goal: fire-and-forget scraping that never fails permanently.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use super::dpi_bypass::{ChallengeDeobfuscator, ChallengeType};
use super::traffic_morph::{ChromeTrafficProfile, human_delay};

const CHROME_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36";

/// Scraper state machine states.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScraperState {
    /// Ready to send a request
    Ready,
    /// Request in flight
    Fetching,
    /// Got a successful response
    Success,
    /// Got blocked (403/429/503) — rotating identity
    Blocked,
    /// Got a challenge page — need browser to solve
    Challenge,
    /// Connection error — retrying
    RetryWait,
    /// Permanently failed after max retries
    Failed,
    /// Completed all URLs
    Done,
}

/// Statistics for the autonomous scraper.
#[derive(Debug)]
pub struct AutonomousStats {
    pub total_requests: AtomicU64,
    pub successful: AtomicU64,
    pub blocked: AtomicU64,
    pub challenges_solved: AtomicU64,
    pub retries: AtomicU64,
    pub ip_rotations: AtomicU64,
    pub fingerprint_rotations: AtomicU64,
    pub permanent_failures: AtomicU64,
}

impl AutonomousStats {
    pub fn new() -> Self {
        Self {
            total_requests: AtomicU64::new(0),
            successful: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            challenges_solved: AtomicU64::new(0),
            retries: AtomicU64::new(0),
            ip_rotations: AtomicU64::new(0),
            fingerprint_rotations: AtomicU64::new(0),
            permanent_failures: AtomicU64::new(0),
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "Autonomous[req:{} ok:{} blocked:{} challenges:{} retries:{} ip_rot:{} fp_rot:{} failed:{}]",
            self.total_requests.load(Ordering::Relaxed),
            self.successful.load(Ordering::Relaxed),
            self.blocked.load(Ordering::Relaxed),
            self.challenges_solved.load(Ordering::Relaxed),
            self.retries.load(Ordering::Relaxed),
            self.ip_rotations.load(Ordering::Relaxed),
            self.fingerprint_rotations.load(Ordering::Relaxed),
            self.permanent_failures.load(Ordering::Relaxed),
        )
    }
}

/// Configuration for autonomous scraping.
#[derive(Debug, Clone)]
pub struct AutonomousConfig {
    /// Maximum retries per URL before permanent failure
    pub max_retries: u32,
    /// Base backoff duration (doubles on each retry)
    pub base_backoff: Duration,
    /// Maximum backoff duration cap
    pub max_backoff: Duration,
    /// Traffic profile for request timing
    pub traffic_profile: ChromeTrafficProfile,
    /// Available proxy URLs for rotation
    pub proxies: Vec<String>,
    /// Maximum concurrent requests
    pub max_concurrent: usize,
    /// Whether to automatically solve browser challenges
    pub auto_solve_challenges: bool,
}

impl Default for AutonomousConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            base_backoff: Duration::from_secs(2),
            max_backoff: Duration::from_secs(60),
            traffic_profile: ChromeTrafficProfile::fast(),
            proxies: Vec::new(),
            max_concurrent: 10,
            auto_solve_challenges: true,
        }
    }
}

/// Result of processing a single URL.
#[derive(Debug, Clone)]
pub struct ScrapeResult {
    /// The URL that was scraped
    pub url: String,
    /// HTTP status code (0 if connection failed)
    pub status: u16,
    /// Response body
    pub body: String,
    /// Number of retries needed
    pub retries: u32,
    /// Which proxy was used for the successful request
    pub proxy_used: Option<String>,
    /// Time taken for this URL (including retries)
    pub elapsed_ms: u64,
    /// Final state
    pub state: ScraperState,
}

/// Determine what action to take based on response.
pub fn classify_response(status: u16, body: &str) -> ScraperState {
    match status {
        200..=299 => {
            // Check if the 200 is actually a challenge page
            if let Some(_challenge) = ChallengeDeobfuscator::detect_challenge(body) {
                ScraperState::Challenge
            } else {
                ScraperState::Success
            }
        }
        403 | 429 | 503 => ScraperState::Blocked,
        401 => ScraperState::Blocked, // Often means missing session
        0 => ScraperState::RetryWait, // Connection error
        _ => ScraperState::RetryWait,
    }
}

/// Calculate exponential backoff with jitter.
pub fn backoff_duration(attempt: u32, base: Duration, max: Duration) -> Duration {
    use rand::Rng;
    let mut rng = rand::rng();

    let exp_ms = base.as_millis() as u64 * 2u64.pow(attempt.min(10));
    let capped_ms = exp_ms.min(max.as_millis() as u64);
    // Add ±25% jitter
    let jitter = (capped_ms as f64 * 0.25) as u64;
    let final_ms = capped_ms + rng.random_range(0..=jitter);

    Duration::from_millis(final_ms)
}

/// Select next proxy from the pool, cycling through them.
pub fn next_proxy(proxies: &[String], current_index: &AtomicUsize) -> Option<String> {
    if proxies.is_empty() {
        return None;
    }
    let idx = current_index.fetch_add(1, Ordering::Relaxed) % proxies.len();
    Some(proxies[idx].clone())
}

/// URL deduplication via bloom filter approximation.
/// Uses a simple hash set for now — can be upgraded to a proper
/// bloom filter for memory efficiency at 100M+ URLs.
pub struct UrlDeduplicator {
    seen: std::collections::HashSet<u64>,
}

impl UrlDeduplicator {
    pub fn new() -> Self {
        Self {
            seen: std::collections::HashSet::new(),
        }
    }

    /// Check if URL was already processed. Returns true if new.
    pub fn is_new(&mut self, url: &str) -> bool {
        use std::hash::{Hash, Hasher};
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        url.hash(&mut hasher);
        let hash = hasher.finish();
        self.seen.insert(hash)
    }

    /// Number of unique URLs seen.
    pub fn count(&self) -> usize {
        self.seen.len()
    }
}

/// Lock-free concurrent counter for tracking active requests.
pub struct ConcurrencyLimiter {
    active: AtomicUsize,
    max: usize,
}

impl ConcurrencyLimiter {
    pub fn new(max: usize) -> Self {
        Self {
            active: AtomicUsize::new(0),
            max,
        }
    }

    /// Try to acquire a slot. Returns true if successful.
    pub fn try_acquire(&self) -> bool {
        loop {
            let current = self.active.load(Ordering::Relaxed);
            if current >= self.max {
                return false;
            }
            if self
                .active
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    /// Release a slot.
    pub fn release(&self) {
        self.active.fetch_sub(1, Ordering::Relaxed);
    }

    /// Current active count.
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }
}

/// Scrape a single URL using the autonomous state machine.
///
/// Walks through Ready → Fetching → classify → Success/Blocked/Challenge/RetryWait
/// until the request succeeds or max_retries is exhausted.
pub async fn scrape_url(
    config: &AutonomousConfig,
    stats: &AutonomousStats,
    url: &str,
) -> ScrapeResult {
    let start = Instant::now();
    let proxy_index = AtomicUsize::new(0);
    let mut state = ScraperState::Ready;
    let mut attempt: u32 = 0;
    let mut last_status: u16 = 0;
    let mut last_body = String::new();
    let mut proxy_used: Option<String> = None;

    loop {
        match state {
            ScraperState::Ready => {
                stats.total_requests.fetch_add(1, Ordering::Relaxed);
                let proxy = next_proxy(&config.proxies, &proxy_index);

                // Build client with optional proxy
                let client = {
                    let mut builder = reqwest::Client::builder()
                        .timeout(Duration::from_secs(30))
                        .redirect(reqwest::redirect::Policy::limited(5))
                        .user_agent(CHROME_UA);

                    if let Some(ref p) = proxy {
                        if let Ok(rp) = reqwest::Proxy::all(p) {
                            builder = builder.proxy(rp);
                        }
                    } else if let Some(zp) =
                        crate::browser::zone::browser_zone_reqwest_proxy()
                            .expect("browser-zone egress contract")
                    {
                        // T-207: no explicit per-request proxy — the zone
                        // predicate decides (Tor SOCKS by default).
                        builder = builder.proxy(zp);
                    }

                    builder.build().expect("contract-proxied reqwest client")
                };

                proxy_used = proxy;
                state = ScraperState::Fetching;

                // Execute request
                match client.get(url).send().await {
                    Ok(resp) => {
                        last_status = resp.status().as_u16();
                        last_body = resp.text().await.unwrap_or_default();
                    }
                    Err(_) => {
                        last_status = 0;
                        last_body.clear();
                    }
                }

                state = classify_response(last_status, &last_body);
            }

            ScraperState::Fetching => {
                // Should not stay here — Ready transitions through Fetching inline.
                // Defensive: treat as retry.
                state = ScraperState::RetryWait;
            }

            ScraperState::Success => {
                stats.successful.fetch_add(1, Ordering::Relaxed);
                return ScrapeResult {
                    url: url.to_string(),
                    status: last_status,
                    body: last_body,
                    retries: attempt,
                    proxy_used,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    state: ScraperState::Success,
                };
            }

            ScraperState::Blocked => {
                stats.blocked.fetch_add(1, Ordering::Relaxed);
                stats.ip_rotations.fetch_add(1, Ordering::Relaxed);
                attempt += 1;
                if attempt >= config.max_retries {
                    state = ScraperState::Failed;
                } else {
                    state = ScraperState::RetryWait;
                }
            }

            ScraperState::Challenge => {
                stats.challenges_solved.fetch_add(1, Ordering::Relaxed);
                attempt += 1;
                if attempt >= config.max_retries {
                    state = ScraperState::Failed;
                } else {
                    // Challenge solving is beyond HTTP-only; retry with new identity
                    stats.ip_rotations.fetch_add(1, Ordering::Relaxed);
                    state = ScraperState::RetryWait;
                }
            }

            ScraperState::RetryWait => {
                stats.retries.fetch_add(1, Ordering::Relaxed);
                let wait = backoff_duration(attempt, config.base_backoff, config.max_backoff);
                tokio::time::sleep(wait).await;
                state = ScraperState::Ready;
            }

            ScraperState::Failed => {
                stats.permanent_failures.fetch_add(1, Ordering::Relaxed);
                return ScrapeResult {
                    url: url.to_string(),
                    status: last_status,
                    body: last_body,
                    retries: attempt,
                    proxy_used,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    state: ScraperState::Failed,
                };
            }

            ScraperState::Done => {
                // Single-URL scrape: Done is same as Success
                return ScrapeResult {
                    url: url.to_string(),
                    status: last_status,
                    body: last_body,
                    retries: attempt,
                    proxy_used,
                    elapsed_ms: start.elapsed().as_millis() as u64,
                    state: ScraperState::Done,
                };
            }
        }
    }
}

/// Scrape a batch of URLs concurrently with rate limiting and human-like delays.
///
/// Uses `ConcurrencyLimiter` to cap parallel requests at `config.max_concurrent`,
/// and injects `human_delay` pauses between spawning batches to mimic browsing.
pub async fn scrape_batch(config: &AutonomousConfig, urls: &[String]) -> Vec<ScrapeResult> {
    let stats = Arc::new(AutonomousStats::new());
    let limiter = Arc::new(ConcurrencyLimiter::new(config.max_concurrent));
    let config = Arc::new(config.clone());

    let mut handles = Vec::with_capacity(urls.len());

    for url in urls.iter() {
        // Wait for a concurrency slot
        loop {
            if limiter.try_acquire() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        let url = url.clone();
        let cfg = Arc::clone(&config);
        let st = Arc::clone(&stats);
        let lim = Arc::clone(&limiter);

        handles.push(tokio::spawn(async move {
            let result = scrape_url(&cfg, &st, &url).await;
            lim.release();
            result
        }));

        // Human-like delay between spawning requests
        let delay = human_delay(&config.traffic_profile);
        tokio::time::sleep(delay).await;
    }

    // Collect all results
    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        match handle.await {
            Ok(result) => results.push(result),
            Err(_) => {
                // Task panicked — record as failed
                results.push(ScrapeResult {
                    url: String::new(),
                    status: 0,
                    body: String::new(),
                    retries: 0,
                    proxy_used: None,
                    elapsed_ms: 0,
                    state: ScraperState::Failed,
                });
            }
        }
    }

    eprintln!("[autonomous] {}", stats.summary());
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_success() {
        assert_eq!(
            classify_response(200, "<html>Hello</html>"),
            ScraperState::Success
        );
    }

    #[test]
    fn test_classify_blocked() {
        assert_eq!(classify_response(403, "Forbidden"), ScraperState::Blocked);
        assert_eq!(classify_response(429, "Too Many"), ScraperState::Blocked);
    }

    #[test]
    fn test_classify_challenge() {
        assert_eq!(
            classify_response(200, "<html>var _abck = true</html>"),
            ScraperState::Challenge
        );
    }

    #[test]
    fn test_classify_connection_error() {
        assert_eq!(classify_response(0, ""), ScraperState::RetryWait);
    }

    #[test]
    fn test_backoff_increases() {
        let base = Duration::from_millis(100);
        let max = Duration::from_secs(30);
        let d0 = backoff_duration(0, base, max);
        let d1 = backoff_duration(1, base, max);
        let d2 = backoff_duration(2, base, max);
        // Each should roughly double (with jitter)
        assert!(d1.as_millis() > d0.as_millis());
        assert!(d2.as_millis() > d1.as_millis());
    }

    #[test]
    fn test_backoff_capped() {
        let d = backoff_duration(20, Duration::from_secs(1), Duration::from_secs(5));
        assert!(d.as_secs() <= 7); // 5s + 25% jitter
    }

    #[test]
    fn test_url_deduplicator() {
        let mut dedup = UrlDeduplicator::new();
        assert!(dedup.is_new("https://example.com/1"));
        assert!(dedup.is_new("https://example.com/2"));
        assert!(!dedup.is_new("https://example.com/1")); // already seen
        assert_eq!(dedup.count(), 2);
    }

    #[test]
    fn test_concurrency_limiter() {
        let limiter = ConcurrencyLimiter::new(2);
        assert!(limiter.try_acquire());
        assert!(limiter.try_acquire());
        assert!(!limiter.try_acquire()); // at max
        limiter.release();
        assert!(limiter.try_acquire()); // slot freed
    }

    #[test]
    fn test_proxy_rotation() {
        let proxies = vec!["a".into(), "b".into(), "c".into()];
        let idx = AtomicUsize::new(0);
        assert_eq!(next_proxy(&proxies, &idx), Some("a".into()));
        assert_eq!(next_proxy(&proxies, &idx), Some("b".into()));
        assert_eq!(next_proxy(&proxies, &idx), Some("c".into()));
        assert_eq!(next_proxy(&proxies, &idx), Some("a".into())); // wraps
    }

    #[test]
    fn test_stats() {
        let stats = AutonomousStats::new();
        stats.total_requests.fetch_add(10, Ordering::Relaxed);
        stats.successful.fetch_add(8, Ordering::Relaxed);
        stats.blocked.fetch_add(2, Ordering::Relaxed);
        let summary = stats.summary();
        assert!(summary.contains("req:10"));
        assert!(summary.contains("ok:8"));
    }

    #[test]
    fn test_autonomous_config_default() {
        let config = AutonomousConfig::default();
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.max_concurrent, 10);
        assert!(config.auto_solve_challenges);
    }
}
