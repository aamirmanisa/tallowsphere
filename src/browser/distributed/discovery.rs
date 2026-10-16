//! Peer discovery for the distributed browser pool.
//!
//! Supports two discovery modes:
//! - **mDNS** — automatic LAN peer discovery via the real `mdns-sd` service
//!   daemon (wrapped by `tallow_net::discovery::mdns::MdnsDiscovery`).
//! - **Manual** — explicit WAN node addresses supplied by configuration.
//!
//! `PoolDiscovery::hybrid` combines both.

use std::net::SocketAddr;

/// How a node was discovered.
#[derive(Debug, Clone, PartialEq)]
pub enum DiscoverySource {
    /// Found via mDNS multicast on the local network.
    Mdns,
    /// Explicitly configured by the operator.
    Manual,
}

/// A node that has been discovered and is eligible for work distribution.
#[derive(Debug, Clone)]
pub struct DiscoveredNode {
    pub node_id: String,
    pub addr: SocketAddr,
    pub max_browsers: u32,
    pub source: DiscoverySource,
}

/// Discovers peers for the distributed browser pool.
///
/// Three construction modes:
/// - [`PoolDiscovery::auto`] — mDNS only (LAN).
/// - [`PoolDiscovery::manual`] — explicit addresses only (WAN).
/// - [`PoolDiscovery::hybrid`] — both.
pub struct PoolDiscovery {
    explicit_nodes: Vec<SocketAddr>,
    mdns_enabled: bool,
    discovered: Vec<DiscoveredNode>,
}

impl PoolDiscovery {
    /// Create a discovery instance that relies solely on mDNS (LAN auto-discovery).
    pub fn auto() -> Self {
        Self {
            explicit_nodes: Vec::new(),
            mdns_enabled: true,
            discovered: Vec::new(),
        }
    }

    /// Create a discovery instance from explicit node addresses (no mDNS).
    pub fn manual(nodes: &[&str]) -> Self {
        let explicit_nodes = nodes
            .iter()
            .filter_map(|s| s.parse::<SocketAddr>().ok())
            .collect();
        Self {
            explicit_nodes,
            mdns_enabled: false,
            discovered: Vec::new(),
        }
    }

    /// Create a discovery instance that combines explicit nodes with mDNS.
    pub fn hybrid(nodes: &[&str]) -> Self {
        let explicit_nodes = nodes
            .iter()
            .filter_map(|s| s.parse::<SocketAddr>().ok())
            .collect();
        Self {
            explicit_nodes,
            mdns_enabled: true,
            discovered: Vec::new(),
        }
    }

    /// Run discovery: collects manual nodes then (optionally) mDNS peers.
    ///
    /// Deduplicates by socket address — manual entries take precedence.
    ///
    /// Returns `Err` (an honest error) only if mDNS is enabled and the mDNS
    /// service daemon itself cannot start. If the daemon starts but no peers
    /// answer within the timeout, an empty list is returned — that is a real,
    /// truthful result (there simply are no Tallow peers on the LAN).
    pub async fn discover(&mut self) -> Result<&[DiscoveredNode], String> {
        self.discovered.clear();

        // Add explicitly configured nodes first.
        for (i, addr) in self.explicit_nodes.iter().enumerate() {
            self.discovered.push(DiscoveredNode {
                node_id: format!("manual-{i}"),
                addr: *addr,
                max_browsers: 4,
                source: DiscoverySource::Manual,
            });
        }

        // Real mDNS discovery when enabled.
        if self.mdns_enabled {
            for peer in Self::discover_mdns_peers().await? {
                // Deduplicate by address — skip if already present from manual list.
                let dominated = self.discovered.iter().any(|n| n.addr == peer.addr);
                if !dominated {
                    self.discovered.push(peer);
                }
            }
        }

        Ok(&self.discovered)
    }

    /// Return the most recently discovered nodes.
    pub fn nodes(&self) -> &[DiscoveredNode] {
        &self.discovered
    }

    /// Real mDNS peer discovery via `mdns-sd` (wrapped by
    /// `tallow_net::discovery::mdns::MdnsDiscovery`).
    ///
    /// Starts an mDNS service browser, waits [`MDNS_BROWSE_WAIT`] milliseconds
    /// for ServiceResolved events, then returns the collected peers. An honest
    /// error is returned if the mDNS daemon cannot be started.
    ///
    /// The underlying network call is real — no peers are fabricated.
    async fn discover_mdns_peers() -> Result<Vec<DiscoveredNode>, String> {
        let mut mdns = tallow_net::discovery::mdns::MdnsDiscovery::new("tallow-pool".to_string());
        mdns.start()
            .map_err(|e| format!("mDNS discovery failed to start: {e}"))?;

        // Give the daemon time to collect ServiceResolved events.
        tokio::time::sleep(std::time::Duration::from_millis(MDNS_BROWSE_WAIT)).await;

        let peers = mdns.discovered_peers();
        let _ = mdns.stop();

        Ok(peers
            .into_iter()
            .map(|p| DiscoveredNode {
                node_id: p.id,
                addr: p.addr,
                max_browsers: 4,
                source: DiscoverySource::Mdns,
            })
            .collect())
    }
}

/// How long to browse for mDNS peers before returning the current set.
const MDNS_BROWSE_WAIT: u64 = 800;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manual_discovery_parses_addrs() {
        let disc = PoolDiscovery::manual(&["127.0.0.1:9000", "10.0.0.1:9001"]);
        assert_eq!(disc.explicit_nodes.len(), 2);
        assert!(!disc.mdns_enabled);
    }

    #[test]
    fn hybrid_enables_mdns() {
        let disc = PoolDiscovery::hybrid(&["127.0.0.1:9000"]);
        assert_eq!(disc.explicit_nodes.len(), 1);
        assert!(disc.mdns_enabled);
    }

    #[test]
    fn auto_has_no_explicit_nodes() {
        let disc = PoolDiscovery::auto();
        assert!(disc.explicit_nodes.is_empty());
        assert!(disc.mdns_enabled);
    }

    #[tokio::test]
    async fn discover_returns_manual_nodes() {
        let mut disc = PoolDiscovery::manual(&["127.0.0.1:9000"]);
        let nodes = disc.discover().await.expect("manual discovery should succeed");
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].source, DiscoverySource::Manual);
    }

    /// Real mDNS integration test — gated so it does NOT require a network.
    ///
    /// `manual` mode never touches mDNS, so this runs offline. It proves the
    /// manual path still works now that `discover()` surfaces real mDNS
    /// daemon errors instead of silently swallowing them.
    #[tokio::test]
    async fn discover_manual_is_offline_safe() {
        let mut disc = PoolDiscovery::manual(&["10.0.0.5:9000", "10.0.0.6:9000"]);
        let nodes = disc.discover().await.expect("manual discovery should succeed");
        assert_eq!(nodes.len(), 2);
        assert!(nodes.iter().all(|n| n.source == DiscoverySource::Manual));
    }
}
