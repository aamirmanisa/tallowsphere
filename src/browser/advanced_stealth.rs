//! Advanced stealth techniques for Tallow.
//!
//! Bloom filter dedup, connection warming, malleable traffic profiles,
//! REALITY protocol config, and Brutal congestion control.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Bloom filter for memory-efficient URL deduplication.
/// 114MB for 100M URLs at 1% false positive rate
/// vs 12GB for a HashSet<String>.
pub struct BloomDedup {
    filter: fastbloom::BloomFilter,
    count: AtomicU64,
}

impl BloomDedup {
    /// Create a bloom filter for the expected number of URLs.
    /// `fp_rate`: false positive rate (0.01 = 1%)
    pub fn new(expected_items: usize, fp_rate: f64) -> Self {
        let filter = fastbloom::BloomFilter::with_false_pos(fp_rate).expected_items(expected_items);
        Self {
            filter,
            count: AtomicU64::new(0),
        }
    }

    /// Check if URL is new (not seen before). Returns true if new.
    /// Automatically adds it to the filter.
    pub fn check_and_add(&mut self, url: &str) -> bool {
        if self.filter.contains(url) {
            false // probably seen before
        } else {
            self.filter.insert(url);
            self.count.fetch_add(1, Ordering::Relaxed);
            true // definitely new
        }
    }

    /// Check without adding.
    pub fn contains(&self, url: &str) -> bool {
        self.filter.contains(url)
    }

    /// Number of unique URLs added.
    pub fn count(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    /// Estimated memory usage in bytes.
    pub fn memory_bytes(&self) -> usize {
        self.filter.num_bits() / 8
    }
}

/// Connection pool warmer.
/// Pre-establishes TLS connections to all target domains before scraping.
/// Saves 50-150ms per domain (TLS 1.3 handshake time).
pub struct ConnectionWarmer {
    /// Domains that have been warmed
    pub warmed: Vec<String>,
    /// Total handshake time saved (estimated)
    pub time_saved_ms: AtomicU64,
}

impl ConnectionWarmer {
    pub fn new() -> Self {
        Self {
            warmed: Vec::new(),
            time_saved_ms: AtomicU64::new(0),
        }
    }

    /// Warm connections to a list of domains.
    /// Sends HEAD /robots.txt to establish TLS + HTTP/2 SETTINGS.
    pub async fn warm(&mut self, domains: &[String], client: &reqwest::Client) {
        let start = Instant::now();
        let mut handles = Vec::new();

        for domain in domains {
            let c = client.clone();
            let url = format!("https://{}/robots.txt", domain);
            handles.push(tokio::spawn(async move {
                let _ = c.head(&url).timeout(Duration::from_secs(5)).send().await;
            }));
        }

        for h in handles {
            let _ = h.await;
        }

        let elapsed = start.elapsed().as_millis() as u64;
        // Each domain would have cost ~100ms if not warmed
        let saved = domains.len() as u64 * 100;
        self.time_saved_ms.fetch_add(saved, Ordering::Relaxed);
        self.warmed.extend(domains.iter().cloned());
    }

    /// Number of warmed domains.
    pub fn warmed_count(&self) -> usize {
        self.warmed.len()
    }
}

/// Malleable traffic profile — make scraping look like specific legitimate traffic.
/// Based on Cobalt Strike's malleable C2 profiles concept.
#[derive(Debug, Clone)]
pub struct MalleableProfile {
    /// Profile name
    pub name: String,
    /// User-Agent string
    pub user_agent: String,
    /// Accept header
    pub accept: String,
    /// Accept-Language
    pub accept_language: String,
    /// Accept-Encoding
    pub accept_encoding: String,
    /// Referer pattern
    pub referer: String,
    /// Additional headers specific to this profile
    pub extra_headers: Vec<(String, String)>,
    /// Request timing: mean delay between requests (ms)
    pub timing_mean_ms: u64,
    /// Request timing: jitter range (ms)
    pub timing_jitter_ms: u64,
}

impl MalleableProfile {
    /// Profile mimicking Bing search crawler.
    pub fn bing_bot() -> Self {
        Self {
            name: "BingBot".into(),
            user_agent: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm) Chrome/116.0.0.0 Safari/537.36".into(),
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8".into(),
            accept_language: "en-US".into(),
            accept_encoding: "gzip, deflate, br".into(),
            referer: "https://www.bing.com/".into(),
            extra_headers: vec![],
            timing_mean_ms: 5000,
            timing_jitter_ms: 3000,
        }
    }

    /// Profile mimicking Office 365 background sync.
    pub fn office365() -> Self {
        Self {
            name: "Office365".into(),
            user_agent:
                "Microsoft Office/16.0 (Windows NT 10.0; Microsoft Outlook 16.0.17928; Pro)".into(),
            accept: "application/json, text/plain, */*".into(),
            accept_language: "en-US,en;q=0.9".into(),
            accept_encoding: "gzip, deflate, br".into(),
            referer: "https://outlook.office365.com/".into(),
            extra_headers: vec![(
                "X-ClientId".into(),
                "d3590ed6-52b3-4102-aeff-aad2292ab01c".into(),
            )],
            timing_mean_ms: 30000,
            timing_jitter_ms: 15000,
        }
    }

    /// Profile mimicking Amazon shopping browsing.
    pub fn amazon_shopper() -> Self {
        Self {
            name: "AmazonShopper".into(),
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36".into(),
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8".into(),
            accept_language: "en-US,en;q=0.9".into(),
            accept_encoding: "gzip, deflate, br, zstd".into(),
            referer: "https://shop-06.example/".into(),
            extra_headers: vec![
                ("Sec-Fetch-Dest".into(), "document".into()),
                ("Sec-Fetch-Mode".into(), "navigate".into()),
                ("Sec-Fetch-Site".into(), "same-origin".into()),
                ("Sec-Fetch-User".into(), "?1".into()),
                ("Upgrade-Insecure-Requests".into(), "1".into()),
            ],
            timing_mean_ms: 3000,
            timing_jitter_ms: 2000,
        }
    }

    /// Profile mimicking Google Chrome on mobile.
    pub fn chrome_mobile() -> Self {
        Self {
            name: "ChromeMobile".into(),
            user_agent: "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.6778.69 Mobile Safari/537.36".into(),
            accept: "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8".into(),
            accept_language: "en-US,en;q=0.9".into(),
            accept_encoding: "gzip, deflate, br".into(),
            referer: "https://www.google.com/".into(),
            extra_headers: vec![
                ("Sec-CH-UA-Mobile".into(), "?1".into()),
                ("Sec-CH-UA-Platform".into(), "\"Android\"".into()),
            ],
            timing_mean_ms: 4000,
            timing_jitter_ms: 2500,
        }
    }

    /// Get all headers for this profile.
    pub fn headers(&self) -> Vec<(String, String)> {
        let mut h = vec![
            ("User-Agent".into(), self.user_agent.clone()),
            ("Accept".into(), self.accept.clone()),
            ("Accept-Language".into(), self.accept_language.clone()),
            ("Accept-Encoding".into(), self.accept_encoding.clone()),
            ("Referer".into(), self.referer.clone()),
        ];
        h.extend(self.extra_headers.clone());
        h
    }
}

/// REALITY protocol configuration.
/// Impersonates a real website's TLS certificate during handshake.
/// Network observers see a connection to (e.g.) microsoft.com,
/// but it's actually your proxy server.
#[derive(Debug, Clone)]
pub struct RealityConfig {
    /// The "steal from" domain (whose cert to impersonate)
    pub target_domain: String,
    /// Server address (your actual proxy)
    pub server_addr: String,
    /// Shared secret (hex string, typically 32 chars)
    pub private_key: String,
    /// Short ID for client authentication
    pub short_id: String,
    /// Spider X pattern (URL path fingerprint)
    pub spider_x: String,
}

impl RealityConfig {
    /// Create a REALITY config impersonating Microsoft.
    pub fn microsoft(server_addr: &str, key: &str) -> Self {
        Self {
            target_domain: "www.microsoft.com".into(),
            server_addr: server_addr.into(),
            private_key: key.into(),
            short_id: "0123456789abcdef".into(),
            spider_x: "/en-us".into(),
        }
    }

    /// Create a REALITY config impersonating Google.
    pub fn google(server_addr: &str, key: &str) -> Self {
        Self {
            target_domain: "www.google.com".into(),
            server_addr: server_addr.into(),
            private_key: key.into(),
            short_id: "fedcba9876543210".into(),
            spider_x: "/".into(),
        }
    }

    /// Create a REALITY config impersonating Cloudflare.
    pub fn cloudflare(server_addr: &str, key: &str) -> Self {
        Self {
            target_domain: "www.cloudflare.com".into(),
            server_addr: server_addr.into(),
            private_key: key.into(),
            short_id: "abcdef0123456789".into(),
            spider_x: "/".into(),
        }
    }
}

/// Brutal congestion control config for QUIC (Hysteria2).
/// Ignores packet loss signals and sends at a fixed rate.
/// Designed to punch through hostile networks.
#[derive(Debug, Clone)]
pub struct BrutalCongestionConfig {
    /// Target send rate in Mbps
    pub target_mbps: u32,
    /// Whether to ignore packet loss (true = Brutal mode)
    pub ignore_loss: bool,
    /// Maximum burst size in packets
    pub max_burst: u32,
}

impl Default for BrutalCongestionConfig {
    fn default() -> Self {
        Self {
            target_mbps: 100,
            ignore_loss: true,
            max_burst: 64,
        }
    }
}

impl BrutalCongestionConfig {
    /// Conservative: 50 Mbps, respect some loss signals.
    pub fn conservative() -> Self {
        Self {
            target_mbps: 50,
            ignore_loss: false,
            max_burst: 32,
        }
    }

    /// Maximum: 500 Mbps, ignore all loss.
    pub fn maximum() -> Self {
        Self {
            target_mbps: 500,
            ignore_loss: true,
            max_burst: 128,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bloom_dedup() {
        let mut bloom = BloomDedup::new(1000, 0.01);
        assert!(bloom.check_and_add("https://example.com/1"));
        assert!(bloom.check_and_add("https://example.com/2"));
        assert!(!bloom.check_and_add("https://example.com/1")); // already seen
        assert_eq!(bloom.count(), 2);
    }

    #[test]
    fn test_bloom_contains() {
        let mut bloom = BloomDedup::new(100, 0.01);
        bloom.check_and_add("https://test.com");
        assert!(bloom.contains("https://test.com"));
        assert!(!bloom.contains("https://other.com"));
    }

    #[test]
    fn test_malleable_bing() {
        let p = MalleableProfile::bing_bot();
        assert!(p.user_agent.contains("bingbot"));
        let headers = p.headers();
        assert!(headers.iter().any(|(k, _)| k == "User-Agent"));
    }

    #[test]
    fn test_malleable_office365() {
        let p = MalleableProfile::office365();
        assert!(p.user_agent.contains("Microsoft Office"));
        assert!(p.extra_headers.iter().any(|(k, _)| k == "X-ClientId"));
    }

    #[test]
    fn test_malleable_amazon() {
        let p = MalleableProfile::amazon_shopper();
        assert!(p.user_agent.contains("Chrome/136"));
        let headers = p.headers();
        assert!(headers.len() >= 5);
    }

    #[test]
    fn test_malleable_mobile() {
        let p = MalleableProfile::chrome_mobile();
        assert!(p.user_agent.contains("Android"));
        assert!(p.user_agent.contains("Mobile"));
    }

    #[test]
    fn test_reality_config() {
        let r = RealityConfig::microsoft("1.2.3.4:443", "secret123");
        assert_eq!(r.target_domain, "www.microsoft.com");
        assert_eq!(r.server_addr, "1.2.3.4:443");
    }

    #[test]
    fn test_brutal_config() {
        let b = BrutalCongestionConfig::default();
        assert_eq!(b.target_mbps, 100);
        assert!(b.ignore_loss);
        let c = BrutalCongestionConfig::conservative();
        assert!(!c.ignore_loss);
    }

    #[test]
    fn test_connection_warmer() {
        let w = ConnectionWarmer::new();
        assert_eq!(w.warmed_count(), 0);
    }
}
