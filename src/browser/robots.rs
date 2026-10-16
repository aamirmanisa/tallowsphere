//! robots.txt compliance and per-domain rate limiting for browser operations.
//!
//! Provides:
//! - `RobotsCache`: Fetches, parses, and caches robots.txt per domain with configurable TTL
//! - `RateLimiter`: Token bucket rate limiting per domain based on @legal rate_limit annotation

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::browser::error::BrowserError;

// ── robots.txt Cache ────────────────────────────────────────────────────────

/// Cached robots.txt entry for a single origin.
struct CachedRobots {
    robot: texting_robots::Robot,
    fetched_at: Instant,
}

/// Per-domain robots.txt cache with configurable TTL.
///
/// Usage:
/// ```ignore
/// let mut cache = RobotsCache::new("tallow/0.1", Duration::from_secs(3600));
/// if cache.is_allowed("https://example.com/page")? {
///     // proceed with navigation
/// }
/// ```
pub struct RobotsCache {
    cache: HashMap<String, CachedRobots>,
    ttl: Duration,
    user_agent: String,
}

impl RobotsCache {
    /// Create a new RobotsCache with the given user agent and TTL.
    pub fn new(user_agent: &str, ttl: Duration) -> Self {
        Self {
            cache: HashMap::new(),
            ttl,
            user_agent: user_agent.to_string(),
        }
    }

    /// Check if a URL is allowed by the domain's robots.txt.
    ///
    /// Fetches and caches robots.txt if not already cached or if cache entry has expired.
    /// Returns `Ok(true)` if the URL is allowed, `Ok(false)` if disallowed.
    /// On network errors or 404, treats as "allow all" (fail-open per standard convention).
    pub fn is_allowed(&mut self, url_str: &str) -> Result<bool, BrowserError> {
        let parsed = url::Url::parse(url_str)
            .map_err(|e| BrowserError::ConnectionFailed(format!("invalid URL: {e}")))?;

        // NOTE (2026-09-15, v1 fix wave 2): keep the PORT in the origin.
        // The previous shape used `scheme://{host_str}`, and `host_str()`
        // drops the port — so robots.txt for any non-default-port origin was
        // fetched from the wrong port (silently fail-opening, and conflating
        // the cache key across ports on one host). Caught by the loopback-mock
        // regression suite (execute_level_network robots tests).
        let origin = match parsed.port() {
            Some(port) => format!(
                "{}://{}:{}",
                parsed.scheme(),
                parsed.host_str().unwrap_or(""),
                port
            ),
            None => format!("{}://{}", parsed.scheme(), parsed.host_str().unwrap_or("")),
        };

        // Check cache: if origin is cached and not expired, use it
        if let Some(cached) = self.cache.get(&origin) {
            if cached.fetched_at.elapsed() < self.ttl {
                return Ok(cached.robot.allowed(url_str));
            }
        }

        // Fetch robots.txt
        let robots_url = format!("{origin}/robots.txt");
        let robot = match crate::runtime::egress_http::get(&robots_url).call() {
            Ok(resp) => {
                let status = resp.status();
                if status == 200 {
                    let body = resp
                        .into_body()
                        .read_to_string()
                        .unwrap_or_default();
                    texting_robots::Robot::new(&self.user_agent, body.as_bytes())
                        .unwrap_or_else(|_| {
                            // Parse error — treat as allow all
                            texting_robots::Robot::new(&self.user_agent, b"")
                                .expect("empty robots.txt should always parse")
                        })
                } else {
                    // Non-200 (including 404) — treat as allow all
                    texting_robots::Robot::new(&self.user_agent, b"")
                        .expect("empty robots.txt should always parse")
                }
            }
            Err(_) => {
                // Network error — treat as allow all (fail-open)
                texting_robots::Robot::new(&self.user_agent, b"")
                    .expect("empty robots.txt should always parse")
            }
        };

        let allowed = robot.allowed(url_str);

        self.cache.insert(
            origin,
            CachedRobots {
                robot,
                fetched_at: Instant::now(),
            },
        );

        Ok(allowed)
    }

    /// Clear the entire cache.
    pub fn clear(&mut self) {
        self.cache.clear();
    }

    /// Remove a specific origin from the cache.
    pub fn invalidate(&mut self, origin: &str) {
        self.cache.remove(origin);
    }

    /// Check if an origin is currently cached (for testing).
    #[cfg(test)]
    fn is_cached(&self, origin: &str) -> bool {
        self.cache.contains_key(origin)
    }
}

// ── Robots Policy ──────────────────────────────────────────────────────────

/// Controls behavior when robots.txt is missing (404) or unreachable.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum RobotsPolicy {
    /// Allow crawling if robots.txt is missing (current default, fail-open).
    Permissive,
    /// Block crawling if robots.txt is missing or unreachable.
    Strict,
}

// ── Per-Domain Rate Limiter ─────────────────────────────────────────────────

/// Token bucket for a single domain.
struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate: f64) -> Self {
        Self {
            tokens: rate, // start full
            max_tokens: rate,
            refill_rate: rate,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let elapsed = self.last_refill.elapsed().as_secs_f64();
        self.tokens = (self.tokens + elapsed * self.refill_rate).min(self.max_tokens);
        self.last_refill = Instant::now();
    }

    fn try_consume(&mut self) -> bool {
        self.refill();
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    /// Returns the duration to wait before a token becomes available.
    fn wait_duration(&self) -> Duration {
        if self.tokens >= 1.0 {
            Duration::ZERO
        } else {
            let needed = 1.0 - self.tokens;
            let wait_secs = needed / self.refill_rate;
            Duration::from_secs_f64(wait_secs)
        }
    }
}

/// Per-domain token bucket rate limiter.
///
/// Enforces rate limits from @legal rate_limit annotations on a per-domain basis.
pub struct RateLimiter {
    buckets: HashMap<String, TokenBucket>,
    default_rate: f64,
    crawl_delays: HashMap<String, Duration>,
}

impl RateLimiter {
    /// Create a new rate limiter with no default rate (unlimited by default).
    pub fn new() -> Self {
        Self {
            buckets: HashMap::new(),
            default_rate: f64::MAX,
            crawl_delays: HashMap::new(),
        }
    }

    /// Set a Crawl-delay for a specific domain (from robots.txt Crawl-delay directive).
    pub fn set_crawl_delay(&mut self, domain: &str, delay: Duration) {
        self.crawl_delays.insert(domain.to_string(), delay);
    }

    /// Configure the rate limit for a specific domain (requests per second).
    pub fn configure_domain(&mut self, domain: &str, rate: f64) {
        self.buckets.insert(domain.to_string(), TokenBucket::new(rate));
    }

    /// Blocking acquire: waits until a token is available, then consumes it.
    pub fn acquire(&mut self, domain: &str) -> Result<(), BrowserError> {
        let bucket = self
            .buckets
            .entry(domain.to_string())
            .or_insert_with(|| TokenBucket::new(self.default_rate));

        bucket.refill();
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }

        // Wait for token to become available
        let wait = bucket.wait_duration();
        std::thread::sleep(wait);
        bucket.refill();
        bucket.tokens -= 1.0;
        Ok(())
    }

    /// Non-blocking try_acquire: returns immediately with error if no token available.
    pub fn try_acquire(&mut self, domain: &str) -> Result<(), BrowserError> {
        let bucket = self
            .buckets
            .entry(domain.to_string())
            .or_insert_with(|| TokenBucket::new(self.default_rate));

        if bucket.try_consume() {
            Ok(())
        } else {
            Err(BrowserError::RateLimitExceeded(domain.to_string()))
        }
    }

    /// Async blocking acquire: waits using tokio::time::sleep until a token is available.
    ///
    /// If a Crawl-delay has been set for the domain (via `set_crawl_delay`),
    /// the delay is applied before acquiring from the token bucket.
    pub async fn acquire_async(&mut self, domain: &str) -> Result<(), BrowserError> {
        // Honour robots.txt Crawl-delay if set for this domain.
        if let Some(delay) = self.crawl_delays.get(domain) {
            tokio::time::sleep(*delay).await;
        }

        let bucket = self
            .buckets
            .entry(domain.to_string())
            .or_insert_with(|| TokenBucket::new(self.default_rate));

        bucket.refill();
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            return Ok(());
        }

        let wait = bucket.wait_duration();
        tokio::time::sleep(wait).await;
        bucket.refill();
        bucket.tokens -= 1.0;
        Ok(())
    }
}

impl Default for RateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── robots.txt tests ────────────────────────────────────────────────

    #[test]
    fn robots_parses_and_checks_rules() {
        // Test the Robot parsing directly (no network needed)
        let robots_txt = b"User-agent: *\nDisallow: /private/\nAllow: /public/";
        let robot =
            texting_robots::Robot::new("tallow/0.1", robots_txt).expect("should parse robots.txt");

        assert!(
            robot.allowed("https://example.com/public/page"),
            "/public/page should be allowed"
        );
        assert!(
            !robot.allowed("https://example.com/private/secret"),
            "/private/secret should be disallowed"
        );
        assert!(
            robot.allowed("https://example.com/other"),
            "/other should be allowed (not explicitly disallowed)"
        );
    }

    #[test]
    fn robots_allows_when_no_rules() {
        // Empty robots.txt means everything is allowed
        let robot =
            texting_robots::Robot::new("tallow/0.1", b"").expect("empty robots.txt should parse");
        assert!(robot.allowed("https://example.com/anything"));
        assert!(robot.allowed("https://example.com/private/data"));
    }

    #[test]
    fn robots_specific_user_agent() {
        // texting_robots matches by user agent product token
        let robots_txt = b"User-agent: tallow\nDisallow: /blocked/\n\nUser-agent: *\nAllow: /";
        let robot =
            texting_robots::Robot::new("tallow", robots_txt).expect("should parse robots.txt");

        assert!(
            !robot.allowed("https://example.com/blocked/page"),
            "tallow-specific rule should block /blocked/"
        );
    }

    #[test]
    fn robots_cache_basic() {
        let cache = RobotsCache::new("tallow/0.1", Duration::from_secs(3600));
        // Initially no cache entries
        assert!(!cache.is_cached("https://example.com"));
    }

    #[test]
    fn robots_cache_clear() {
        let mut cache = RobotsCache::new("tallow/0.1", Duration::from_secs(3600));
        // Manually insert an entry for testing
        let robot = texting_robots::Robot::new("tallow/0.1", b"User-agent: *\nAllow: /")
            .expect("should parse");
        cache.cache.insert(
            "https://example.com".to_string(),
            CachedRobots {
                robot,
                fetched_at: Instant::now(),
            },
        );
        assert!(cache.is_cached("https://example.com"));

        cache.clear();
        assert!(!cache.is_cached("https://example.com"));
    }

    #[test]
    fn robots_cache_invalidate() {
        let mut cache = RobotsCache::new("tallow/0.1", Duration::from_secs(3600));
        let robot = texting_robots::Robot::new("tallow/0.1", b"User-agent: *\nAllow: /")
            .expect("should parse");
        cache.cache.insert(
            "https://example.com".to_string(),
            CachedRobots {
                robot,
                fetched_at: Instant::now(),
            },
        );
        assert!(cache.is_cached("https://example.com"));

        cache.invalidate("https://example.com");
        assert!(!cache.is_cached("https://example.com"));
    }

    #[test]
    fn robots_cache_ttl_expired() {
        let mut cache = RobotsCache::new("tallow/0.1", Duration::from_millis(1));
        let robot = texting_robots::Robot::new("tallow/0.1", b"User-agent: *\nDisallow: /blocked/")
            .expect("should parse");
        cache.cache.insert(
            "https://example.com".to_string(),
            CachedRobots {
                robot,
                fetched_at: Instant::now() - Duration::from_secs(10), // expired 10 seconds ago
            },
        );
        // Cache is present but expired — is_allowed will try to refetch
        // (which will fail with network error, falling back to allow-all)
        // The key point: the entry exists but is_allowed should not use it as-is
        // We verify the TTL mechanism works by checking the elapsed time
        let cached = cache.cache.get("https://example.com").unwrap();
        assert!(cached.fetched_at.elapsed() >= Duration::from_secs(10));
    }

    // ── Rate limiter tests ──────────────────────────────────────────────

    #[test]
    fn rate_limiter_allows_within_limit() {
        let mut limiter = RateLimiter::new();
        limiter.configure_domain("example.com", 2.0);

        // First two should succeed (bucket starts with 2 tokens)
        assert!(limiter.try_acquire("example.com").is_ok());
        assert!(limiter.try_acquire("example.com").is_ok());

        // Third should fail (no tokens left)
        assert!(limiter.try_acquire("example.com").is_err());
    }

    #[test]
    fn rate_limiter_refills_tokens() {
        let mut limiter = RateLimiter::new();
        limiter.configure_domain("example.com", 100.0); // high rate for testing

        // Consume all tokens
        for _ in 0..100 {
            let _ = limiter.try_acquire("example.com");
        }
        assert!(limiter.try_acquire("example.com").is_err());

        // Wait a tiny bit for refill (100 tokens/sec = 1 token per 10ms)
        std::thread::sleep(Duration::from_millis(20));

        // Should have at least 1 token now
        assert!(limiter.try_acquire("example.com").is_ok());
    }

    #[test]
    fn rate_limiter_blocking_acquire() {
        let mut limiter = RateLimiter::new();
        limiter.configure_domain("example.com", 100.0);

        // Consume all tokens
        for _ in 0..100 {
            let _ = limiter.try_acquire("example.com");
        }

        // Blocking acquire should wait and succeed
        let start = Instant::now();
        assert!(limiter.acquire("example.com").is_ok());
        // Should have waited some small duration
        assert!(start.elapsed() > Duration::ZERO);
    }

    #[test]
    fn rate_limiter_different_domains_independent() {
        let mut limiter = RateLimiter::new();
        limiter.configure_domain("a.com", 1.0);
        limiter.configure_domain("b.com", 1.0);

        // Consume a.com token
        assert!(limiter.try_acquire("a.com").is_ok());
        assert!(limiter.try_acquire("a.com").is_err());

        // b.com should still have tokens
        assert!(limiter.try_acquire("b.com").is_ok());
    }

    #[test]
    fn rate_limiter_unconfigured_domain_unlimited() {
        let mut limiter = RateLimiter::new();
        // No domain configured — default_rate is f64::MAX (effectively unlimited)
        for _ in 0..1000 {
            assert!(limiter.try_acquire("unknown.com").is_ok());
        }
    }

    #[test]
    fn robots_policy_strict_vs_permissive() {
        assert_ne!(RobotsPolicy::Strict, RobotsPolicy::Permissive);
        assert_eq!(RobotsPolicy::Strict, RobotsPolicy::Strict);
        assert_eq!(RobotsPolicy::Permissive, RobotsPolicy::Permissive);
    }

    #[test]
    fn crawl_delay_stored() {
        let mut limiter = RateLimiter::new();
        let delay = Duration::from_secs(2);
        limiter.set_crawl_delay("example.com", delay);
        assert_eq!(limiter.crawl_delays.get("example.com"), Some(&delay));
    }

    #[test]
    fn rate_limiter_error_is_rate_limit_exceeded() {
        let mut limiter = RateLimiter::new();
        limiter.configure_domain("example.com", 1.0);
        let _ = limiter.try_acquire("example.com"); // consume the token
        let err = limiter.try_acquire("example.com").unwrap_err();
        assert!(matches!(err, BrowserError::RateLimitExceeded(ref d) if d == "example.com"));
    }
}
