//! Gossip-based node coordination for the distributed browser pool.
//!
//! Each node periodically sends heartbeats containing its [`NodeInfo`].
//! The [`ClusterState`] tracks every known node and expires those that
//! miss too many heartbeats.  [`NodeCoordinator`] wraps the state behind
//! a tokio `Mutex` so it can be shared across async tasks.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

// ---------------------------------------------------------------------------
// NodeInfo
// ---------------------------------------------------------------------------

/// Snapshot of a single node's capacity.
#[derive(Debug, Clone)]
pub struct NodeInfo {
    pub node_id: String,
    pub addr: SocketAddr,
    pub active_browsers: u32,
    pub idle_slots: u32,
    pub max_browsers: u32,
}

// ---------------------------------------------------------------------------
// ClusterState
// ---------------------------------------------------------------------------

/// Aggregate view of every node in the cluster.
#[derive(Debug, Clone)]
pub struct ClusterState {
    pub nodes: HashMap<String, NodeInfo>,
    pub last_heartbeat: HashMap<String, Instant>,
}

impl ClusterState {
    pub fn new() -> Self {
        Self {
            nodes: HashMap::new(),
            last_heartbeat: HashMap::new(),
        }
    }

    /// Insert or update a node and record its heartbeat timestamp.
    pub fn update_heartbeat(&mut self, info: NodeInfo) {
        let id = info.node_id.clone();
        self.nodes.insert(id.clone(), info);
        self.last_heartbeat.insert(id, Instant::now());
    }

    /// Remove nodes whose last heartbeat is older than `threshold`.
    /// Returns the IDs of removed nodes.
    pub fn remove_dead_nodes(&mut self, threshold: Duration) -> Vec<String> {
        let now = Instant::now();
        let dead: Vec<String> = self
            .last_heartbeat
            .iter()
            .filter(|(_, ts)| now.duration_since(**ts) > threshold)
            .map(|(id, _)| id.clone())
            .collect();

        for id in &dead {
            self.nodes.remove(id);
            self.last_heartbeat.remove(id);
        }

        dead
    }

    /// Return the node with the most idle slots (must be > 0).
    pub fn best_node(&self) -> Option<&NodeInfo> {
        self.nodes
            .values()
            .filter(|n| n.idle_slots > 0)
            .max_by_key(|n| n.idle_slots)
    }

    /// Sum of all idle slots across the cluster.
    pub fn total_idle(&self) -> u32 {
        self.nodes.values().map(|n| n.idle_slots).sum()
    }

    /// Sum of all active browsers across the cluster.
    pub fn total_active(&self) -> u32 {
        self.nodes.values().map(|n| n.active_browsers).sum()
    }
}

// ---------------------------------------------------------------------------
// NodeCoordinator
// ---------------------------------------------------------------------------

/// Async-safe coordinator that wraps [`ClusterState`] for use across tasks.
pub struct NodeCoordinator {
    pub node_id: String,
    pub addr: SocketAddr,
    pub state: Arc<Mutex<ClusterState>>,
    pub heartbeat_interval: Duration,
    pub dead_threshold: Duration,
}

impl NodeCoordinator {
    pub fn new(node_id: String, addr: SocketAddr) -> Self {
        Self {
            node_id,
            addr,
            state: Arc::new(Mutex::new(ClusterState::new())),
            heartbeat_interval: Duration::from_secs(5),
            dead_threshold: Duration::from_secs(15),
        }
    }

    /// Return a snapshot (clone) of the current cluster state.
    pub async fn state(&self) -> ClusterState {
        self.state.lock().await.clone()
    }

    /// Process an incoming heartbeat from a peer node.
    pub async fn receive_heartbeat(&self, info: NodeInfo) {
        self.state.lock().await.update_heartbeat(info);
    }

    /// Remove nodes that have missed too many heartbeats.
    pub async fn gc_dead_nodes(&self) -> Vec<String> {
        self.state.lock().await.remove_dead_nodes(self.dead_threshold)
    }

    /// Build a [`NodeInfo`] describing this node's current capacity.
    pub fn self_info(&self, active: u32, idle: u32, max: u32) -> NodeInfo {
        NodeInfo {
            node_id: self.node_id.clone(),
            addr: self.addr,
            active_browsers: active,
            idle_slots: idle,
            max_browsers: max,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn cluster_state_best_node() {
        let mut state = ClusterState::new();

        state.update_heartbeat(NodeInfo {
            node_id: "n1".into(),
            addr: addr(5000),
            active_browsers: 5,
            idle_slots: 3,
            max_browsers: 8,
        });

        state.update_heartbeat(NodeInfo {
            node_id: "n2".into(),
            addr: addr(5001),
            active_browsers: 2,
            idle_slots: 6,
            max_browsers: 8,
        });

        let best = state.best_node().expect("should have a best node");
        assert_eq!(best.node_id, "n2");
    }

    #[test]
    fn cluster_state_remove_dead() {
        let mut state = ClusterState::new();

        state.update_heartbeat(NodeInfo {
            node_id: "n1".into(),
            addr: addr(5000),
            active_browsers: 1,
            idle_slots: 4,
            max_browsers: 5,
        });

        // Backdate the heartbeat to 20 seconds ago.
        state
            .last_heartbeat
            .insert("n1".into(), Instant::now() - Duration::from_secs(20));

        let removed = state.remove_dead_nodes(Duration::from_secs(15));
        assert_eq!(removed, vec!["n1".to_string()]);
        assert!(state.nodes.is_empty());
    }

    #[test]
    fn total_idle_sums_correctly() {
        let mut state = ClusterState::new();

        state.update_heartbeat(NodeInfo {
            node_id: "n1".into(),
            addr: addr(5000),
            active_browsers: 3,
            idle_slots: 5,
            max_browsers: 8,
        });

        state.update_heartbeat(NodeInfo {
            node_id: "n2".into(),
            addr: addr(5001),
            active_browsers: 7,
            idle_slots: 1,
            max_browsers: 8,
        });

        assert_eq!(state.total_idle(), 6);
        assert_eq!(state.total_active(), 10);
    }
}
