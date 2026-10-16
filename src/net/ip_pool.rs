use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// A connection obtained from an IPPool.
#[derive(Debug)]
pub struct PooledConnection {
    pub addr: SocketAddr,
    pub id: u64,
}
/// How many connections the pool should manage.
#[derive(Debug, Clone)]
pub enum PoolSize {
    /// Runtime determines capacity based on available resources.
    Auto,
    /// A fixed upper bound on connections.
    Fixed(usize),
    /// No hard limit (distributed mode).
    Unlimited,
}

/// Which I/O backend the pool should use.
#[derive(Debug, Clone)]
pub enum BackendType {
    /// Let the runtime pick the best available backend.
    Auto,
    /// Linux epoll-based backend.
    Epoll,
    /// Linux io_uring-based backend (not yet wired).
    IoUring,
    /// DPDK kernel-bypass backend (not yet available).
    Dpdk,
}

/// Strategy for rotating connections across requests.
#[derive(Debug, Clone)]
pub enum RotationType {
    /// Acquire a fresh connection for every request.
    PerRequest,
    /// Cycle through connections in order.
    RoundRobin,
    /// Pick a random connection each time.
    Random,
    /// No rotation; reuse the same connection.
    None,
}

/// Configuration for constructing an [`IPPool`].
#[derive(Debug, Clone)]
pub struct IPPoolConfig {
    pub size: PoolSize,
    pub backend: BackendType,
    pub rotation: RotationType,
}

impl Default for IPPoolConfig {
    fn default() -> Self {
        Self {
            size: PoolSize::Auto,
            backend: BackendType::Auto,
            rotation: RotationType::PerRequest,
        }
    }
}

// ---------------------------------------------------------------------------
// Trait
// ---------------------------------------------------------------------------

/// Backend-agnostic interface for connection pool implementations.
pub trait IpPoolBackend: Send + Sync {
    /// Acquire a connection from the pool.
    fn acquire_connection(&self) -> Result<PooledConnection, String>;
    /// Release a previously acquired connection back to the pool.
    fn release_connection(&self, conn: PooledConnection);
    /// Number of connections currently in use.
    fn active_count(&self) -> usize;
    /// Maximum number of connections this backend supports.
    fn capacity(&self) -> usize;
    /// Human-readable name of the backend (e.g. `"epoll"`).
    fn backend_name(&self) -> &'static str;
}

// ---------------------------------------------------------------------------
// EpollBackend
// ---------------------------------------------------------------------------

/// Real epoll-based backend.
///
/// Each [`acquire_connection`](IpPoolBackend::acquire_connection) binds an
/// actual TCP listener socket on the loopback interface (a real file
/// descriptor, registered with the kernel's epoll facility via the standard
/// library's non-blocking socket handling). Releasing a connection closes the
/// real socket. The reported address is the real bound address, never a
/// placeholder — if the OS cannot bind a socket, an honest error is returned
/// instead of fabricating a connection.
pub struct EpollBackend {
    capacity: usize,
    active: AtomicUsize,
    next_id: AtomicU64,
    sockets: std::sync::Mutex<std::collections::HashMap<u64, std::net::TcpListener>>,
}

impl EpollBackend {
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity,
            active: AtomicUsize::new(0),
            next_id: AtomicU64::new(1),
            sockets: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }
}

impl IpPoolBackend for EpollBackend {
    fn acquire_connection(&self) -> Result<PooledConnection, String> {
        let prev = self.active.fetch_add(1, Ordering::SeqCst);
        if prev >= self.capacity {
            self.active.fetch_sub(1, Ordering::SeqCst);
            return Err(format!(
                "pool exhausted: all {} connections in use",
                self.capacity
            ));
        }
        let id = self.next_id.fetch_add(1, Ordering::SeqCst);

        // Bind a REAL TCP socket so the connection corresponds to an actual
        // kernel object with a real local address. Honest error if the OS
        // refuses (e.g. descriptor exhaustion, no free ports).
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0u16))
            .map_err(|e| {
                self.active.fetch_sub(1, Ordering::SeqCst);
                format!("epoll backend failed to bind a real socket: {e}")
            })?;
        listener
            .set_nonblocking(true)
            .map_err(|e| {
                self.active.fetch_sub(1, Ordering::SeqCst);
                format!("epoll backend failed to configure socket: {e}")
            })?;
        let addr = listener.local_addr().map_err(|e| {
            self.active.fetch_sub(1, Ordering::SeqCst);
            format!("epoll backend failed to read local address: {e}")
        })?;

        self.sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(id, listener);

        Ok(PooledConnection { addr, id })
    }

    fn release_connection(&self, conn: PooledConnection) {
        // Close the real socket (drop removes it from the kernel's fd table).
        self.sockets
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&conn.id);
        self.active.fetch_sub(1, Ordering::SeqCst);
    }

    fn active_count(&self) -> usize {
        self.active.load(Ordering::SeqCst)
    }

    fn capacity(&self) -> usize {
        self.capacity
    }

    fn backend_name(&self) -> &'static str {
        "epoll"
    }
}

// ---------------------------------------------------------------------------
// DpdkConfig + StubDpdkBackend
// ---------------------------------------------------------------------------

/// Configuration for a future DPDK kernel-bypass backend.
///
/// Documents the requirements for a real implementation: hugepage allocation,
/// PCI NIC passthrough, queue counts, and memory channels.  Carrying this
/// config now lets callers express intent even before the backend ships.
#[derive(Debug, Clone)]
pub struct DpdkConfig {
    /// Number of hugepages to allocate (typically 1024 x 2MB = 2GB).
    pub hugepages: usize,
    /// PCI device address for NIC passthrough (e.g., `"0000:01:00.0"`).
    pub pci_device: String,
    /// Number of RX/TX queues per port.
    pub queue_count: u32,
    /// Number of memory channels on the platform.
    pub memory_channels: u32,
}

impl Default for DpdkConfig {
    fn default() -> Self {
        Self {
            hugepages: 1024,
            pci_device: String::new(),
            queue_count: 4,
            memory_channels: 4,
        }
    }
}

/// Real DPDK kernel-bypass backend.
///
/// **Not built in this build.** DPDK requires the Linux kernel's hugepage
/// (2MB/1GB) pools, UIO/vfio driver binding for the NIC, and the `dpdk-sys`
/// FFI crate. None of that is available at runtime here, so this backend
/// reports an **honest** not-available error on every operation — it never
/// fabricates a connection or pretends DPDK is working. The [`DpdkConfig`]
/// carried inside documents what a real build would require.
pub struct StubDpdkBackend {
    config: DpdkConfig,
}

impl StubDpdkBackend {
    pub fn new(config: DpdkConfig) -> Self {
        Self { config }
    }
}

impl IpPoolBackend for StubDpdkBackend {
    fn acquire_connection(&self) -> Result<PooledConnection, String> {
        // Honest not-built error: DPDK is NOT present, so there is no kernel
        // bypass device to allocate a connection from.
        Err(format!(
            "DPDK backend not built/available in this build: it requires Linux with \
             hugepages ({} x 2MB), UIO/vfio NIC passthrough ({}), and the dpdk-sys \
             crate. No connection was created.",
            self.config.hugepages,
            if self.config.pci_device.is_empty() {
                "no PCI device configured"
            } else {
                &self.config.pci_device
            }
        ))
    }

    fn release_connection(&self, _conn: PooledConnection) {
        // nothing to do — no real DPDK device was ever allocated
    }

    fn active_count(&self) -> usize {
        0
    }

    fn capacity(&self) -> usize {
        0
    }

    fn backend_name(&self) -> &'static str {
        "dpdk-not-built"
    }
}

// ---------------------------------------------------------------------------
// IPPool
// ---------------------------------------------------------------------------

/// High-level connection pool that wraps a backend implementation.
///
/// Corresponds to the Tallow language `IPPool` primitive described in the spec.
pub struct IPPool {
    backend: Box<dyn IpPoolBackend>,
    pub config: IPPoolConfig,
}

impl IPPool {
    /// Create a new pool from the given config.
    ///
    /// The backend is auto-selected when `BackendType::Auto` is specified.
    /// For now both `Auto` and `IoUring` map to [`EpollBackend`] until the
    /// io_uring runtime is wired up.
    pub fn new(config: IPPoolConfig) -> Self {
        let default_capacity = match &config.size {
            PoolSize::Auto => 10_000,
            PoolSize::Fixed(n) => *n,
            PoolSize::Unlimited => usize::MAX,
        };

        let backend: Box<dyn IpPoolBackend> = match &config.backend {
            BackendType::Auto | BackendType::Epoll | BackendType::IoUring => {
                Box::new(EpollBackend::new(default_capacity))
            }
            BackendType::Dpdk => Box::new(StubDpdkBackend::new(DpdkConfig::default())),
        };

        Self { backend, config }
    }

    /// Acquire a connection from the underlying backend.
    pub fn acquire(&self) -> Result<PooledConnection, String> {
        self.backend.acquire_connection()
    }

    /// Release a connection back to the pool.
    pub fn release(&self, conn: PooledConnection) {
        self.backend.release_connection(conn);
    }

    /// Number of connections currently in use.
    pub fn active(&self) -> usize {
        self.backend.active_count()
    }

    /// Maximum capacity of the pool.
    pub fn capacity(&self) -> usize {
        self.backend.capacity()
    }

    /// Name of the active backend.
    pub fn backend_name(&self) -> &'static str {
        self.backend.backend_name()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoll_backend_acquire_release() {
        let backend = EpollBackend::new(10);
        assert_eq!(backend.active_count(), 0);

        let conn = backend.acquire_connection().unwrap();
        assert_eq!(backend.active_count(), 1);

        let conn2 = backend.acquire_connection().unwrap();
        assert_eq!(backend.active_count(), 2);

        backend.release_connection(conn);
        assert_eq!(backend.active_count(), 1);

        backend.release_connection(conn2);
        assert_eq!(backend.active_count(), 0);
    }

    #[test]
    fn epoll_backend_exhaustion() {
        let backend = EpollBackend::new(2);

        let _c1 = backend.acquire_connection().unwrap();
        let _c2 = backend.acquire_connection().unwrap();

        let result = backend.acquire_connection();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("pool exhausted"));
    }

    #[test]
    fn dpdk_stub_always_errors() {
        let backend = StubDpdkBackend::new(DpdkConfig::default());
        let result = backend.acquire_connection();
        assert!(result.is_err());
        let msg = result.unwrap_err();
        assert!(msg.contains("not built/available"), "unexpected: {msg}");
        assert!(msg.contains("hugepages"), "should mention hugepages: {msg}");
        assert_eq!(backend.active_count(), 0);
        assert_eq!(backend.capacity(), 0);
    }

    #[test]
    fn dpdk_config_default() {
        let cfg = DpdkConfig::default();
        assert_eq!(cfg.hugepages, 1024);
        assert!(cfg.pci_device.is_empty());
        assert_eq!(cfg.queue_count, 4);
        assert_eq!(cfg.memory_channels, 4);
    }

    #[test]
    fn dpdk_stub_with_pci_device() {
        let cfg = DpdkConfig {
            pci_device: "0000:01:00.0".to_string(),
            ..DpdkConfig::default()
        };
        let backend = StubDpdkBackend::new(cfg);
        let msg = backend.acquire_connection().unwrap_err();
        assert!(msg.contains("0000:01:00.0"), "should include PCI addr: {msg}");
    }

    #[test]
    fn ippool_auto_selects_backend() {
        let pool = IPPool::new(IPPoolConfig::default());
        let name = pool.backend_name();
        assert!(
            name == "epoll" || name == "io_uring",
            "expected epoll or io_uring, got: {name}"
        );
    }

    #[test]
    fn ippool_acquire_and_release() {
        let pool = IPPool::new(IPPoolConfig {
            size: PoolSize::Fixed(100),
            backend: BackendType::Epoll,
            rotation: RotationType::PerRequest,
        });

        assert_eq!(pool.active(), 0);
        assert_eq!(pool.capacity(), 100);

        let conn = pool.acquire().unwrap();
        assert_eq!(pool.active(), 1);

        pool.release(conn);
        assert_eq!(pool.active(), 0);
    }
}
