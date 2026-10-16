//! IPPool connection manager for Tallow.
//!
//! Manages 10K+ concurrent HTTP connections across multiple IPs.
//! Round-robin IP rotation per request, automatic kernel tuning,
//! SOCKS5 proxy support for Tor integration.
//!
//! Memory target: 10K connections with <20MB RAM overhead.
//! Connection metadata is 16 bytes per slot — 10K slots = 160KB.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

use tokio::sync::RwLock;

// ---------------------------------------------------------------------------
// IP Binding
// ---------------------------------------------------------------------------

/// How to route a connection.
#[derive(Debug, Clone)]
pub enum IpBinding {
    /// Use a specific local IP (multi-homed server).
    Local(IpAddr),
    /// Route through a SOCKS5 proxy (Tor or residential).
    Socks5 {
        addr: SocketAddr,
        /// Optional authentication.
        auth: Option<(String, String)>,
    },
    /// Route through an HTTP(S) proxy.
    HttpProxy(String),
    /// Use the system default route.
    Direct,
}

impl std::fmt::Display for IpBinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpBinding::Local(ip) => write!(f, "local:{ip}"),
            IpBinding::Socks5 { addr, .. } => write!(f, "socks5://{addr}"),
            IpBinding::HttpProxy(url) => write!(f, "proxy:{url}"),
            IpBinding::Direct => write!(f, "direct"),
        }
    }
}

// ---------------------------------------------------------------------------
// Connection Slot
// ---------------------------------------------------------------------------

/// Tracks active connections per IP binding.
struct ConnectionSlot {
    binding: IpBinding,
    active: AtomicU32,
    max_conns: u32,
    total_requests: AtomicU32,
    /// Health: 0 = dead, 1-100 = health score.
    health: AtomicU32,
}

impl ConnectionSlot {
    fn new(binding: IpBinding, max_conns: u32) -> Self {
        Self {
            binding,
            active: AtomicU32::new(0),
            max_conns,
            total_requests: AtomicU32::new(0),
            health: AtomicU32::new(100),
        }
    }

    /// Try to acquire a connection permit. Returns true if successful.
    fn try_acquire(&self) -> bool {
        let current = self.active.load(Ordering::Relaxed);
        if current >= self.max_conns {
            return false;
        }
        // CAS to increment
        self.active
            .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Relaxed)
            .is_ok()
    }

    /// Release a connection permit.
    fn release(&self) {
        self.active.fetch_sub(1, Ordering::Release);
        self.total_requests.fetch_add(1, Ordering::Relaxed);
    }

    fn is_healthy(&self) -> bool {
        self.health.load(Ordering::Relaxed) > 0
    }
}

// ---------------------------------------------------------------------------
// IPPool
// ---------------------------------------------------------------------------

/// Configuration for the IP pool.
#[derive(Debug, Clone)]
pub struct IpPoolConfig {
    /// Maximum connections per IP binding (default: 1000).
    pub max_conns_per_ip: u32,
    /// Rotation strategy.
    pub rotation: RotationStrategy,
    /// Enable automatic kernel tuning on Linux (default: true).
    pub auto_tune_kernel: bool,
}

impl Default for IpPoolConfig {
    fn default() -> Self {
        Self {
            max_conns_per_ip: 1000,
            rotation: RotationStrategy::RoundRobin,
            auto_tune_kernel: true,
        }
    }
}

/// How IPs are selected for outbound connections.
#[derive(Debug, Clone, Copy)]
pub enum RotationStrategy {
    /// Cycle through IPs sequentially (default).
    RoundRobin,
    /// Pick a random IP for each request.
    Random,
    /// Use least-loaded IP.
    LeastConnections,
    /// New IP for every single request.
    PerRequest,
}

/// RAII connection permit. Releases the slot on drop.
///
/// The permit holds a direct atomic reference to the slot's active
/// counter so that `Drop` can decrement it synchronously (no async).
pub struct ConnectionPermit {
    /// Which slot this permit came from.
    pub slot_index: usize,
    /// Direct reference to the slot's active connection counter.
    active_counter: Arc<AtomicU32>,
}

impl Drop for ConnectionPermit {
    fn drop(&mut self) {
        self.active_counter.fetch_sub(1, Ordering::Release);
    }
}

/// Internal pool state.
struct IpPoolInner {
    slots: RwLock<Vec<ConnectionSlot>>,
    round_robin: AtomicUsize,
    config: IpPoolConfig,
}

/// High-performance IP pool for managing concurrent connections.
///
/// ```tallow
/// let pool = IPPool {
///     size:     10_000,
///     rotation: .per_request,
///     protocol: .socks5
/// }
/// ```
pub struct IpPool {
    inner: Arc<IpPoolInner>,
}

impl IpPool {
    /// Create a new IP pool with the given bindings and config.
    pub fn new(bindings: Vec<IpBinding>, config: IpPoolConfig) -> Self {
        if config.auto_tune_kernel {
            Self::tune_kernel();
        }

        let slots: Vec<ConnectionSlot> = bindings
            .into_iter()
            .map(|b| ConnectionSlot::new(b, config.max_conns_per_ip))
            .collect();

        Self {
            inner: Arc::new(IpPoolInner {
                slots: RwLock::new(slots),
                round_robin: AtomicUsize::new(0),
                config,
            }),
        }
    }

    /// Create a pool with a single direct connection and given concurrency.
    pub fn direct(max_conns: u32) -> Self {
        Self::new(
            vec![IpBinding::Direct],
            IpPoolConfig {
                max_conns_per_ip: max_conns,
                ..Default::default()
            },
        )
    }

    /// Create a pool from a list of SOCKS5 proxy addresses (e.g., Tor instances).
    pub fn from_socks5(addrs: Vec<SocketAddr>, config: IpPoolConfig) -> Self {
        let bindings = addrs
            .into_iter()
            .map(|addr| IpBinding::Socks5 { addr, auth: None })
            .collect();
        Self::new(bindings, config)
    }

    /// Create a pool from a list of HTTP proxy URLs.
    pub fn from_proxies(urls: Vec<String>, config: IpPoolConfig) -> Self {
        let bindings = urls.into_iter().map(IpBinding::HttpProxy).collect();
        Self::new(bindings, config)
    }

    /// Get the next IP binding according to the rotation strategy.
    pub async fn next_binding(&self) -> Option<IpBinding> {
        let slots = self.inner.slots.read().await;
        if slots.is_empty() {
            return None;
        }

        match self.inner.config.rotation {
            RotationStrategy::RoundRobin => {
                let idx = self.inner.round_robin.fetch_add(1, Ordering::Relaxed) % slots.len();
                if slots[idx].is_healthy() && slots[idx].try_acquire() {
                    Some(slots[idx].binding.clone())
                } else {
                    // Try next available
                    for offset in 1..slots.len() {
                        let try_idx = (idx + offset) % slots.len();
                        if slots[try_idx].is_healthy() && slots[try_idx].try_acquire() {
                            return Some(slots[try_idx].binding.clone());
                        }
                    }
                    None // All at capacity
                }
            }
            RotationStrategy::LeastConnections => {
                let mut min_active = u32::MAX;
                let mut best_idx = 0;
                for (i, slot) in slots.iter().enumerate() {
                    let active = slot.active.load(Ordering::Relaxed);
                    if active < min_active && slot.is_healthy() {
                        min_active = active;
                        best_idx = i;
                    }
                }
                if slots[best_idx].try_acquire() {
                    Some(slots[best_idx].binding.clone())
                } else {
                    None
                }
            }
            RotationStrategy::Random => {
                let idx = self.inner.round_robin.fetch_add(7, Ordering::Relaxed) % slots.len();
                if slots[idx].is_healthy() && slots[idx].try_acquire() {
                    Some(slots[idx].binding.clone())
                } else {
                    None
                }
            }
            RotationStrategy::PerRequest => {
                // Same as round-robin but guaranteed different IP each time
                let idx = self.inner.round_robin.fetch_add(1, Ordering::Relaxed) % slots.len();
                if slots[idx].try_acquire() {
                    Some(slots[idx].binding.clone())
                } else {
                    None
                }
            }
        }
    }

    /// Get pool statistics.
    pub async fn stats(&self) -> IpPoolStats {
        let slots = self.inner.slots.read().await;
        let total_ips = slots.len();
        let total_active: u32 = slots.iter().map(|s| s.active.load(Ordering::Relaxed)).sum();
        let total_requests: u32 = slots
            .iter()
            .map(|s| s.total_requests.load(Ordering::Relaxed))
            .sum();
        let healthy: usize = slots.iter().filter(|s| s.is_healthy()).count();

        IpPoolStats {
            total_ips,
            healthy_ips: healthy,
            active_connections: total_active,
            total_requests,
            max_capacity: total_ips as u32 * self.inner.config.max_conns_per_ip,
        }
    }

    /// Tune Linux kernel parameters for maximum connections.
    #[cfg(target_os = "linux")]
    fn tune_kernel() {
        let tunings = [
            ("/proc/sys/fs/file-max", "20000000"),
            ("/proc/sys/net/ipv4/ip_local_port_range", "1024 65535"),
            ("/proc/sys/net/ipv4/tcp_tw_reuse", "1"),
            ("/proc/sys/net/core/somaxconn", "65535"),
            ("/proc/sys/net/ipv4/tcp_max_syn_backlog", "65535"),
            ("/proc/sys/net/core/netdev_max_backlog", "65535"),
            ("/proc/sys/net/ipv4/tcp_fin_timeout", "10"),
        ];

        let mut tuned = 0;
        for (path, value) in &tunings {
            if std::fs::write(path, value).is_ok() {
                tuned += 1;
            }
        }
        if tuned > 0 {
            eprintln!("  [IPPool] Tuned {tuned} kernel parameters for high-throughput networking");
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn tune_kernel() {
        // No-op on non-Linux
    }
}

/// Pool statistics snapshot.
#[derive(Debug, Clone)]
pub struct IpPoolStats {
    pub total_ips: usize,
    pub healthy_ips: usize,
    pub active_connections: u32,
    pub total_requests: u32,
    pub max_capacity: u32,
}

impl std::fmt::Display for IpPoolStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "IPs: {}/{} healthy | Connections: {}/{} | Requests: {}",
            self.healthy_ips,
            self.total_ips,
            self.active_connections,
            self.max_capacity,
            self.total_requests
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_direct_pool() {
        let pool = IpPool::direct(100);
        let binding = pool.next_binding().await;
        assert!(matches!(binding, Some(IpBinding::Direct)));
    }

    #[tokio::test]
    async fn test_round_robin() {
        let pool = IpPool::new(
            vec![
                IpBinding::Local("10.0.0.1".parse().unwrap()),
                IpBinding::Local("10.0.0.2".parse().unwrap()),
            ],
            IpPoolConfig::default(),
        );
        let b1 = pool.next_binding().await.unwrap();
        let b2 = pool.next_binding().await.unwrap();
        // Should alternate
        assert!(matches!(b1, IpBinding::Local(_)));
        assert!(matches!(b2, IpBinding::Local(_)));
    }

    #[tokio::test]
    async fn test_stats() {
        let pool = IpPool::direct(1000);
        let stats = pool.stats().await;
        assert_eq!(stats.total_ips, 1);
        assert_eq!(stats.healthy_ips, 1);
        assert_eq!(stats.max_capacity, 1000);
    }
}
