//! Free proxy list integration for Tallow.
//!
//! Fetches SOCKS5 proxy lists from GitHub sources, validates them,
//! and provides a ready-to-use pool for stealth_fetch_proxied.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Sources of free SOCKS5 proxies (updated hourly on GitHub).
pub const PROXY_SOURCES: &[&str] = &[
    "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    "https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt",
    "https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt",
    "https://raw.githubusercontent.com/ShiftyTR/Proxy-List/master/socks5.txt",
    "https://raw.githubusercontent.com/ErcinDedeworken/proxies/main/proxies/socks5.txt",
];

/// A validated proxy entry.
#[derive(Debug, Clone)]
pub struct FreeProxy {
    /// SOCKS5 address (ip:port)
    pub addr: String,
    /// Response time in milliseconds
    pub latency_ms: u64,
    /// Whether this proxy passed validation
    pub alive: bool,
}

/// Fetch proxy lists from all GitHub sources.
///
/// Returns raw proxy strings in "ip:port" format.
pub async fn fetch_proxy_lists() -> Vec<String> {
    // T-207: fetching proxy lists is WAN egress — ride the zone contract.
    let mut builder = reqwest::Client::builder().timeout(Duration::from_secs(10));
    match crate::browser::zone::browser_zone_reqwest_proxy() {
        Ok(Some(zp)) => builder = builder.proxy(zp),
        Ok(None) => {}
        Err(reason) => {
            // Refuse rather than fetch proxy lists from the box IP (N3).
            eprintln!("[browser-zone] {reason}");
            return Vec::new();
        }
    }
    let client = builder.build().expect("reqwest client");

    let mut all_proxies = std::collections::HashSet::new();

    for source in PROXY_SOURCES {
        match client.get(*source).send().await {
            Ok(resp) => {
                if let Ok(text) = resp.text().await {
                    for line in text.lines() {
                        let trimmed = line.trim();
                        // Validate format: ip:port
                        if trimmed.contains(':') && !trimmed.starts_with('#') {
                            let parts: Vec<&str> = trimmed.split(':').collect();
                            if parts.len() == 2 {
                                if let Ok(_port) = parts[1].parse::<u16>() {
                                    all_proxies.insert(trimmed.to_string());
                                }
                            }
                        }
                    }
                }
            }
            Err(_) => continue,
        }
    }

    all_proxies.into_iter().collect()
}

/// Validate proxies by testing connectivity.
///
/// Tests each proxy by connecting through it to httpbin.org.
/// Returns only working proxies sorted by latency.
pub async fn validate_proxies(
    proxies: &[String],
    max_concurrent: usize,
    timeout: Duration,
) -> Vec<FreeProxy> {
    let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(max_concurrent));
    let mut handles = Vec::new();

    for proxy_addr in proxies {
        let addr = proxy_addr.clone();
        let sem = semaphore.clone();
        let timeout = timeout;

        handles.push(tokio::spawn(async move {
            let _permit = sem.acquire().await.ok()?;
            let start = Instant::now();

            let proxy = reqwest::Proxy::all(format!("socks5://{}", addr)).ok()?;
            let client = reqwest::Client::builder()
                .proxy(proxy)
                .timeout(timeout)
                .build()
                .ok()?;

            match client.get("https://httpbin.org/ip").send().await {
                Ok(resp) if resp.status().is_success() => {
                    let latency = start.elapsed().as_millis() as u64;
                    Some(FreeProxy {
                        addr,
                        latency_ms: latency,
                        alive: true,
                    })
                }
                _ => None,
            }
        }));
    }

    let mut valid = Vec::new();
    for handle in handles {
        if let Ok(Some(proxy)) = handle.await {
            valid.push(proxy);
        }
    }

    // Sort by latency (fastest first)
    valid.sort_by_key(|p| p.latency_ms);
    valid
}

/// Fetch and validate free proxies in one call.
///
/// Returns the top N fastest working SOCKS5 proxies.
pub async fn get_working_proxies(max_count: usize) -> Vec<String> {
    let raw = fetch_proxy_lists().await;
    eprintln!(
        "  [tallow] fetched {} raw proxies from {} sources",
        raw.len(),
        PROXY_SOURCES.len()
    );

    let valid = validate_proxies(&raw, 50, Duration::from_secs(5)).await;
    eprintln!(
        "  [tallow] {} proxies alive (tested {} total)",
        valid.len(),
        raw.len()
    );

    valid
        .into_iter()
        .take(max_count)
        .map(|p| format!("socks5://{}", p.addr))
        .collect()
}

/// A proxy pool with automatic background refresh.
///
/// Wraps validated proxies and re-fetches them when stale
/// (older than `refresh_interval_secs`).
pub struct ProxyPool {
    proxies: Arc<tokio::sync::RwLock<Vec<FreeProxy>>>,
    last_refresh: Arc<AtomicU64>,
    refresh_interval_secs: u64,
    max_proxies: usize,
}

impl ProxyPool {
    /// Create a new pool, fetching and validating up to `max_proxies` proxies.
    ///
    /// Default refresh interval is 10 minutes.
    pub async fn new(max_proxies: usize) -> Self {
        let initial = Self::fetch_and_validate(max_proxies).await;
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            proxies: Arc::new(tokio::sync::RwLock::new(initial)),
            last_refresh: Arc::new(AtomicU64::new(now_secs)),
            refresh_interval_secs: 600, // 10 minutes
            max_proxies,
        }
    }

    /// Create a pool with a custom refresh interval.
    pub async fn with_refresh_interval(max_proxies: usize, refresh_interval_secs: u64) -> Self {
        let mut pool = Self::new(max_proxies).await;
        pool.refresh_interval_secs = refresh_interval_secs;
        pool
    }

    /// Return a proxy (round-robin by index), triggering a background refresh
    /// if the pool is stale.
    pub async fn get_proxy(&self) -> Option<FreeProxy> {
        // Check staleness and maybe kick off background refresh.
        let now_secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let last = self.last_refresh.load(Ordering::Relaxed);
        if now_secs.saturating_sub(last) >= self.refresh_interval_secs {
            // Spawn a background refresh (non-blocking).
            let proxies = Arc::clone(&self.proxies);
            let last_refresh = Arc::clone(&self.last_refresh);
            let max_proxies = self.max_proxies;
            tokio::spawn(async move {
                let fresh = Self::fetch_and_validate(max_proxies).await;
                if !fresh.is_empty() {
                    let mut guard = proxies.write().await;
                    *guard = fresh;
                }
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                last_refresh.store(ts, Ordering::Relaxed);
            });
        }

        let guard = self.proxies.read().await;
        if guard.is_empty() {
            return None;
        }
        // Pick a random proxy to spread load.
        let idx = (now_secs as usize) % guard.len();
        Some(guard[idx].clone())
    }

    /// Force a refresh — re-fetches and re-validates, updating the internal list.
    pub async fn refresh(&self) {
        let fresh = Self::fetch_and_validate(self.max_proxies).await;
        if !fresh.is_empty() {
            let mut guard = self.proxies.write().await;
            *guard = fresh;
        }
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.last_refresh.store(ts, Ordering::Relaxed);
    }

    /// Number of currently healthy (alive) proxies in the pool.
    pub async fn healthy_count(&self) -> usize {
        let guard = self.proxies.read().await;
        guard.iter().filter(|p| p.alive).count()
    }

    /// Internal helper: fetch raw lists and validate, returning top N.
    async fn fetch_and_validate(max_proxies: usize) -> Vec<FreeProxy> {
        let raw = fetch_proxy_lists().await;
        let valid = validate_proxies(&raw, 50, Duration::from_secs(5)).await;
        valid.into_iter().take(max_proxies).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_proxy_sources_not_empty() {
        assert!(!PROXY_SOURCES.is_empty());
    }

    #[test]
    fn test_free_proxy_struct() {
        let p = FreeProxy {
            addr: "1.2.3.4:1080".to_string(),
            latency_ms: 150,
            alive: true,
        };
        assert!(p.alive);
        assert_eq!(p.latency_ms, 150);
    }
}
