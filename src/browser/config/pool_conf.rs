//! Browser pool configuration (pool.toml).

use serde::{Deserialize, Serialize};

/// Browser pool management and proxy rotation.
///
/// ```toml
/// # pool.toml
/// max_size = 4                   # Max concurrent browser instances
/// max_tasks_per_instance = 100   # Recycle browser after N tasks
/// recycle_on_release = true      # Clear cookies/storage between tasks
///
/// # Proxy rotation (round-robin across pool instances)
/// proxies = []
/// # proxies = [
/// #     "socks5://proxy1:1080",
/// #     "socks5://proxy2:1080",
/// #     "http://proxy3:8080",
/// # ]
///
/// [distributed]
/// enabled = false
/// nodes = []                     # ["10.0.0.1:9222", "10.0.0.2:9222"]
/// discovery = "manual"           # "manual" | "mdns" | "hybrid"
/// coordination = "gossip"        # "gossip" | "leader"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PoolToml {
    /// Maximum concurrent browser instances.
    pub max_size: usize,
    /// Recycle a browser instance after this many tasks.
    pub max_tasks_per_instance: u32,
    /// Clear cookies/localStorage when returning to pool.
    pub recycle_on_release: bool,
    /// Proxy URLs for round-robin rotation.
    pub proxies: Vec<String>,
    /// Distributed pool settings.
    pub distributed: DistributedPoolToml,
}

impl Default for PoolToml {
    fn default() -> Self {
        Self {
            max_size: 4,
            max_tasks_per_instance: 100,
            recycle_on_release: true,
            proxies: vec![],
            distributed: DistributedPoolToml::default(),
        }
    }
}

/// Distributed browser pool across multiple nodes.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DistributedPoolToml {
    /// Enable distributed mode.
    pub enabled: bool,
    /// Node addresses (host:port).
    pub nodes: Vec<String>,
    /// Discovery method: "manual", "mdns", "hybrid".
    pub discovery: String,
    /// Coordination protocol: "gossip", "leader".
    pub coordination: String,
}

impl Default for DistributedPoolToml {
    fn default() -> Self {
        Self {
            enabled: false,
            nodes: vec![],
            discovery: "manual".into(),
            coordination: "gossip".into(),
        }
    }
}
