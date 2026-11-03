//! Egress nodes and fan-out scheduling.
//!
//! A node is anything a request can leave the host through: the direct path,
//! an HTTP proxy, or a SOCKS5 proxy. [`NodePool`] hands out leases with a
//! per-node in-flight cap so one saturated exit cannot absorb the whole
//! transfer, and prefers the least-loaded node so the aggregate ceiling is
//! `nodes × per-node`, not `nodes × slowest`.

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// Where a request leaves the host.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeKind {
    /// Host's own route (no proxy).
    Direct,
    /// `http://host:port` proxy.
    Http(String),
    /// `socks5://host:port` proxy, including a Tor SOCKS endpoint.
    Socks5(String),
}

/// Static description of one egress node.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EgressNode {
    /// Stable identifier used in reports.
    pub id: String,
    /// How to reach it.
    pub kind: NodeKind,
    /// Maximum concurrent leases this node accepts.
    pub max_inflight: usize,
}

impl EgressNode {
    /// Direct-route node with a given concurrency cap.
    pub fn direct(id: impl Into<String>, max_inflight: usize) -> Self {
        Self {
            id: id.into(),
            kind: NodeKind::Direct,
            max_inflight: max_inflight.max(1),
        }
    }

    /// SOCKS5 node (e.g. `socks5://127.0.0.1:9050` for Tor).
    pub fn socks5(id: impl Into<String>, url: impl Into<String>, max_inflight: usize) -> Self {
        Self {
            id: id.into(),
            kind: NodeKind::Socks5(url.into()),
            max_inflight: max_inflight.max(1),
        }
    }
}

/// Live counters for one node.
#[derive(Debug)]
pub struct NodeState {
    info: EgressNode,
    inflight: AtomicUsize,
    successes: AtomicU64,
    failures: AtomicU64,
}

impl NodeState {
    fn new(info: EgressNode) -> Self {
        Self {
            info,
            inflight: AtomicUsize::new(0),
            successes: AtomicU64::new(0),
            failures: AtomicU64::new(0),
        }
    }

    /// Node description.
    pub fn info(&self) -> &EgressNode {
        &self.info
    }

    /// Leases currently outstanding.
    pub fn inflight(&self) -> usize {
        self.inflight.load(Ordering::Relaxed)
    }

    /// Completed shards on this node.
    pub fn successes(&self) -> u64 {
        self.successes.load(Ordering::Relaxed)
    }

    /// Failed shard attempts on this node.
    pub fn failures(&self) -> u64 {
        self.failures.load(Ordering::Relaxed)
    }
}

/// Snapshot for reporting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeStat {
    /// Node id.
    pub id: String,
    /// Node kind.
    pub kind: NodeKind,
    /// Leases outstanding at snapshot time.
    pub inflight: usize,
    /// Completed shards.
    pub successes: u64,
    /// Failed attempts.
    pub failures: u64,
}

/// A pool of egress nodes with per-node concurrency caps.
#[derive(Debug)]
pub struct NodePool {
    states: Vec<Arc<NodeState>>,
}

impl NodePool {
    /// Build a pool. An empty vector is legal but [`NodePool::acquire`] will
    /// always return `None`, which the caller must treat as a hard error rather
    /// than a reason to go direct.
    pub fn new(nodes: Vec<EgressNode>) -> Self {
        Self {
            states: nodes
                .into_iter()
                .map(|n| Arc::new(NodeState::new(n)))
                .collect(),
        }
    }

    /// Number of nodes.
    pub fn len(&self) -> usize {
        self.states.len()
    }

    /// True when the pool holds no nodes.
    pub fn is_empty(&self) -> bool {
        self.states.is_empty()
    }

    /// All node states, for reporting or for building per-node clients.
    pub fn nodes(&self) -> &[Arc<NodeState>] {
        &self.states
    }

    /// Total concurrent capacity across the pool.
    pub fn capacity(&self) -> usize {
        self.states.iter().map(|s| s.info.max_inflight).sum()
    }

    /// Lease the least-loaded node that still has capacity.
    ///
    /// Ordering is `(inflight, failures)`: a node that keeps failing sinks below
    /// an idle one without being removed, so a recovered node climbs back on its
    /// own. Returns `None` when every node is at its cap.
    pub fn acquire(&self) -> Option<Reservation> {
        loop {
            let mut best: Option<&Arc<NodeState>> = None;
            for state in &self.states {
                let inflight = state.inflight.load(Ordering::Relaxed);
                if inflight >= state.info.max_inflight {
                    continue;
                }
                best = match best {
                    None => Some(state),
                    Some(current) => {
                        let cur_key = (
                            current.inflight.load(Ordering::Relaxed),
                            current.failures.load(Ordering::Relaxed),
                        );
                        let cand_key = (inflight, state.failures.load(Ordering::Relaxed));
                        if cand_key < cur_key {
                            Some(state)
                        } else {
                            Some(current)
                        }
                    }
                };
            }

            let chosen = best?;
            let before = chosen.inflight.load(Ordering::Relaxed);
            if before >= chosen.info.max_inflight {
                continue;
            }
            if chosen
                .inflight
                .compare_exchange(before, before + 1, Ordering::AcqRel, Ordering::Relaxed)
                .is_ok()
            {
                return Some(Reservation {
                    state: Arc::clone(chosen),
                });
            }
        }
    }

    /// Record a failed attempt against `id`. Unknown ids are ignored.
    pub fn record_failure(&self, id: &str) {
        if let Some(state) = self.states.iter().find(|s| s.info.id == id) {
            state.failures.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Snapshot every node's counters.
    pub fn stats(&self) -> Vec<NodeStat> {
        self.states
            .iter()
            .map(|s| NodeStat {
                id: s.info.id.clone(),
                kind: s.info.kind.clone(),
                inflight: s.inflight(),
                successes: s.successes(),
                failures: s.failures(),
            })
            .collect()
    }
}

/// An outstanding lease. Dropping it returns the slot to the pool.
#[derive(Debug)]
pub struct Reservation {
    state: Arc<NodeState>,
}

impl Reservation {
    /// Node id held by this lease.
    pub fn id(&self) -> &str {
        &self.state.info.id
    }

    /// Node kind held by this lease.
    pub fn kind(&self) -> &NodeKind {
        &self.state.info.kind
    }

    /// Record that the work done under this lease succeeded.
    pub fn success(&self) {
        self.state.successes.fetch_add(1, Ordering::Relaxed);
    }

    /// Record that the work done under this lease failed (in addition to the
    /// pool-level counter, which the scheduler reads).
    pub fn failure(&self) {
        self.state.failures.fetch_add(1, Ordering::Relaxed);
    }
}

impl Drop for Reservation {
    fn drop(&mut self) {
        self.state.inflight.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool(n: usize, cap: usize) -> NodePool {
        NodePool::new(
            (0..n)
                .map(|i| EgressNode::direct(format!("node-{i}"), cap))
                .collect(),
        )
    }

    #[test]
    fn leases_spread_across_nodes() {
        let pool = pool(4, 1);
        let a = pool.acquire().expect("a");
        let b = pool.acquire().expect("b");
        assert_ne!(a.id(), b.id());
        assert_eq!(pool.capacity(), 4);
    }

    #[test]
    fn drops_return_the_slot() {
        let pool = pool(1, 1);
        {
            let lease = pool.acquire().expect("first");
            assert_eq!(lease.id(), "node-0");
            assert!(pool.acquire().is_none());
        }
        assert!(pool.acquire().is_some());
    }

    #[test]
    fn empty_pool_refuses_rather_than_going_direct() {
        let pool = NodePool::new(Vec::new());
        assert!(pool.is_empty());
        assert!(pool.acquire().is_none());
    }

    #[test]
    fn failing_node_sinks_below_a_healthy_one() {
        let pool = pool(2, 4);
        pool.record_failure("node-0");
        pool.record_failure("node-0");
        let lease = pool.acquire().expect("lease");
        assert_eq!(lease.id(), "node-1");
    }
}
