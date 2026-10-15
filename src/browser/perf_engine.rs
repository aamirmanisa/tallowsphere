//! High-performance engine utilities for the Tallow browser runtime.
//!
//! Provides connection warming, Bloom-filter URL deduplication,
//! adaptive (AIMD) concurrency control, and a reusable buffer pool.

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use crossbeam::queue::ArrayQueue;
use dashmap::DashMap;
use fastbloom::AtomicBloomFilter;

/// Explicit throughput profile used by turbo crawler and related engines.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThroughputMode {
    /// Safer defaults with stronger backpressure.
    Balanced,
    /// High-throughput profile with elevated but bounded limits.
    Turbo,
}

impl ThroughputMode {
    pub const fn is_turbo(self) -> bool {
        matches!(self, Self::Turbo)
    }
}

/// Hard guardrails that prevent unbounded fan-out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConcurrencyGuardrails {
    pub max_http_concurrency: usize,
    pub max_browser_tabs: usize,
    pub max_batch_size: usize,
    pub max_http_batch_size: usize,
    pub max_browser_queue: usize,
}

impl ConcurrencyGuardrails {
    pub const BALANCED: Self = Self {
        max_http_concurrency: 512,
        max_browser_tabs: 32,
        max_batch_size: 2_000,
        max_http_batch_size: 512,
        max_browser_queue: 256,
    };

    pub const TURBO: Self = Self {
        max_http_concurrency: 2_000,
        max_browser_tabs: 128,
        max_batch_size: 10_000,
        max_http_batch_size: 2_000,
        max_browser_queue: 1_000,
    };

    pub const fn for_mode(mode: ThroughputMode) -> Self {
        match mode {
            ThroughputMode::Balanced => Self::BALANCED,
            ThroughputMode::Turbo => Self::TURBO,
        }
    }

    pub fn clamp_http_concurrent(&self, requested: usize) -> usize {
        requested.clamp(1, self.max_http_concurrency)
    }

    pub fn clamp_browser_tabs(&self, requested: usize) -> usize {
        requested.clamp(1, self.max_browser_tabs)
    }

    pub fn clamp_batch_size(&self, requested: usize) -> usize {
        requested.clamp(1, self.max_batch_size)
    }

    pub fn clamp_http_batch_size(&self, requested: usize) -> usize {
        requested.clamp(1, self.max_http_batch_size)
    }

    pub fn clamp_browser_queue(&self, requested: usize) -> usize {
        requested.clamp(1, self.max_browser_queue)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Connection Warmer
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-establishes TLS connections so the first real request to a domain
/// skips the handshake latency (typically 50-150 ms).
pub struct ConnectionWarmer {
    warmed_domains: DashMap<String, Instant>,
    client: reqwest::Client,
    /// How long a warmed connection is considered valid.
    ttl: Duration,
}

impl ConnectionWarmer {
    /// Create a new warmer with the given TTL (default: 5 minutes).
    pub fn new(ttl: Duration) -> Self {
        Self {
            warmed_domains: DashMap::new(),
            client: {
                let mut builder = reqwest::Client::builder().pool_idle_timeout(Some(ttl));
                if let Some(zp) = crate::browser::zone::browser_zone_reqwest_proxy()
                    .expect("browser-zone egress contract")
                {
                    builder = builder.proxy(zp);
                }
                builder.build().expect("reqwest client")
            },
            ttl,
        }
    }

    /// Pre-establish a TLS connection to `domain` (scheme + host, e.g. "https://example.com").
    pub async fn warm(&self, domain: &str) -> Result<(), reqwest::Error> {
        // A HEAD request is the lightest way to force a TLS handshake.
        let url = if domain.starts_with("http") {
            domain.to_string()
        } else {
            format!("https://{domain}")
        };
        self.client
            .head(&url)
            .timeout(Duration::from_secs(10))
            .send()
            .await?;
        self.warmed_domains
            .insert(domain.to_string(), Instant::now());
        Ok(())
    }

    /// Warm multiple domains concurrently.
    pub async fn warm_batch(&self, domains: &[&str]) -> Vec<Result<(), reqwest::Error>> {
        let futs: Vec<_> = domains.iter().map(|d| self.warm(d)).collect();
        futures_util::future::join_all(futs).await
    }

    /// Returns `true` if the domain was warmed within the TTL window.
    pub fn is_warm(&self, domain: &str) -> bool {
        self.warmed_domains
            .get(domain)
            .map(|entry| entry.elapsed() < self.ttl)
            .unwrap_or(false)
    }

    /// Remove stale entries older than the TTL.
    pub fn evict_stale(&self) {
        self.warmed_domains.retain(|_, ts| ts.elapsed() < self.ttl);
    }
}

impl Default for ConnectionWarmer {
    fn default() -> Self {
        Self::new(Duration::from_secs(300))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// URL Deduplicator (Bloom filter)
// ─────────────────────────────────────────────────────────────────────────────

/// Space-efficient URL deduplication using an atomic Bloom filter.
///
/// For 1 million URLs at 1% FP rate this uses ~1.2 MB of memory,
/// compared to ~64 MB for a `HashSet<String>`.
pub struct UrlDedup {
    bloom: AtomicBloomFilter,
    exact_count: AtomicU64,
    false_positive_rate: f64,
}

impl UrlDedup {
    /// Create a deduplicator sized for `expected_items` with the given
    /// false-positive rate (e.g. 0.01 = 1%).
    pub fn new(expected_items: usize, fp_rate: f64) -> Self {
        let bloom = AtomicBloomFilter::with_false_pos(fp_rate).expected_items(expected_items);
        Self {
            bloom,
            exact_count: AtomicU64::new(0),
            false_positive_rate: fp_rate,
        }
    }

    /// Check whether `url` was already seen **and** mark it as seen.
    ///
    /// Returns `true` if the URL was (probably) already inserted,
    /// `false` if it is new.
    pub fn check_and_mark(&self, url: &str) -> bool {
        let already = self.bloom.contains(url);
        if !already {
            self.bloom.insert(url);
            self.exact_count.fetch_add(1, Ordering::Relaxed);
        }
        already
    }

    /// Number of unique items inserted (exact).
    pub fn count(&self) -> u64 {
        self.exact_count.load(Ordering::Relaxed)
    }

    /// Configured false-positive rate.
    pub fn false_positive_rate(&self) -> f64 {
        self.false_positive_rate
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Adaptive Concurrency (AIMD)
// ─────────────────────────────────────────────────────────────────────────────

/// AIMD (Additive Increase / Multiplicative Decrease) concurrency controller.
///
/// When response times are below the target, concurrency increases linearly.
/// When they exceed the target, concurrency is cut by `decrease_factor`.
pub struct AdaptiveConcurrency {
    current: AtomicU32,
    min: u32,
    max: u32,
    target_latency_ms: u64,
    increase_step: u32,
    decrease_factor: f64,
}

impl AdaptiveConcurrency {
    pub fn new(min: u32, max: u32, target_latency_ms: u64) -> Self {
        Self {
            current: AtomicU32::new(min),
            min,
            max,
            target_latency_ms,
            increase_step: 1,
            decrease_factor: 0.75,
        }
    }

    /// Set the additive-increase step (default 1).
    pub fn with_increase_step(mut self, step: u32) -> Self {
        self.increase_step = step;
        self
    }

    /// Set the multiplicative-decrease factor (default 0.75 = drop 25%).
    pub fn with_decrease_factor(mut self, factor: f64) -> Self {
        self.decrease_factor = factor;
        self
    }

    /// Record an observed response time and adjust the concurrency limit.
    pub fn adjust(&self, response_time_ms: u64) {
        if response_time_ms <= self.target_latency_ms {
            // Additive increase
            let _ = self
                .current
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                    Some(c.saturating_add(self.increase_step).min(self.max))
                });
        } else {
            // Multiplicative decrease
            let _ = self
                .current
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |c| {
                    let next = (c as f64 * self.decrease_factor) as u32;
                    Some(next.max(self.min))
                });
        }
    }

    /// Current concurrency limit.
    pub fn current(&self) -> u32 {
        self.current.load(Ordering::Relaxed)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Buffer Pool
// ─────────────────────────────────────────────────────────────────────────────

/// Lock-free pool of reusable `BytesMut` buffers.
///
/// Avoids repeated allocation/deallocation in hot loops that read HTTP bodies.
pub struct BufferPool {
    pool: ArrayQueue<BytesMut>,
    buf_size: usize,
}

impl BufferPool {
    /// Create a pool holding up to `capacity` buffers, each pre-allocated to
    /// `buf_size` bytes.
    pub fn new(capacity: usize, buf_size: usize) -> Self {
        let pool = ArrayQueue::new(capacity);
        for _ in 0..capacity {
            let _ = pool.push(BytesMut::with_capacity(buf_size));
        }
        Self { pool, buf_size }
    }

    /// Take a buffer from the pool, or allocate a fresh one if the pool is
    /// empty.
    pub fn get(&self) -> BytesMut {
        self.pool
            .pop()
            .map(|mut b| {
                b.clear();
                b
            })
            .unwrap_or_else(|| BytesMut::with_capacity(self.buf_size))
    }

    /// Return a buffer to the pool for reuse. If the pool is full the buffer
    /// is simply dropped.
    pub fn put(&self, buf: BytesMut) {
        let _ = self.pool.push(buf);
    }

    /// Number of buffers currently available in the pool.
    pub fn available(&self) -> usize {
        self.pool.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn url_dedup_basic() {
        let dedup = UrlDedup::new(1000, 0.01);
        assert!(!dedup.check_and_mark("https://example.com/a"));
        assert!(dedup.check_and_mark("https://example.com/a")); // already seen
        assert!(!dedup.check_and_mark("https://example.com/b"));
        assert_eq!(dedup.count(), 2);
    }

    #[test]
    fn adaptive_concurrency_aimd() {
        let ac = AdaptiveConcurrency::new(1, 100, 200);
        assert_eq!(ac.current(), 1);

        // Fast responses -> increase
        for _ in 0..10 {
            ac.adjust(50);
        }
        assert!(ac.current() > 1);

        // Slow response -> decrease
        let before = ac.current();
        ac.adjust(500);
        assert!(ac.current() < before);
    }

    #[test]
    fn buffer_pool_reuse() {
        let pool = BufferPool::new(4, 1024);
        assert_eq!(pool.available(), 4);

        let b1 = pool.get();
        assert_eq!(pool.available(), 3);
        assert!(b1.capacity() >= 1024);

        pool.put(b1);
        assert_eq!(pool.available(), 4);
    }

    #[test]
    fn throughput_guardrails_enforce_bounds() {
        let balanced = ConcurrencyGuardrails::for_mode(ThroughputMode::Balanced);
        let turbo = ConcurrencyGuardrails::for_mode(ThroughputMode::Turbo);

        assert!(!ThroughputMode::Balanced.is_turbo());
        assert!(ThroughputMode::Turbo.is_turbo());
        assert!(turbo.max_http_concurrency > balanced.max_http_concurrency);
        assert!(turbo.max_batch_size > balanced.max_batch_size);

        assert_eq!(balanced.clamp_http_concurrent(0), 1);
        assert_eq!(
            balanced.clamp_http_concurrent(usize::MAX),
            balanced.max_http_concurrency
        );
        assert_eq!(balanced.clamp_browser_tabs(0), 1);
        assert_eq!(
            balanced.clamp_browser_tabs(usize::MAX),
            balanced.max_browser_tabs
        );
        assert_eq!(balanced.clamp_batch_size(0), 1);
        assert_eq!(
            balanced.clamp_batch_size(usize::MAX),
            balanced.max_batch_size
        );
        assert_eq!(balanced.clamp_http_batch_size(0), 1);
        assert_eq!(
            balanced.clamp_http_batch_size(usize::MAX),
            balanced.max_http_batch_size
        );
        assert_eq!(balanced.clamp_browser_queue(0), 1);
        assert_eq!(
            balanced.clamp_browser_queue(usize::MAX),
            balanced.max_browser_queue
        );
    }
}
