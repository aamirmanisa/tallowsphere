//! Work distribution for distributed browser pool.
//!
//! Domain-affine: shards work by hashing each URL's **domain** onto a consistent
//! hash ring, so all requests/sessions/cookies for a domain stay pinned to one
//! node (this is what keeps proxy/profile pinning intact). Idle-slot balancing is
//! preserved implicitly by virtual nodes (vnodes) per real node.

use std::collections::BTreeMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use super::coordinator::ClusterState;

/// Distributes work across cluster nodes.
pub struct WorkDistributor {
    self_node_id: String,
    /// Number of virtual nodes placed on the hash ring per real node. More vnodes
    /// = smoother load balance; fewer = fewer ring entries.
    vnodes: u32,
}

impl WorkDistributor {
    pub fn new(node_id: String) -> Self {
        Self {
            self_node_id: node_id,
            vnodes: 100,
        }
    }

    /// Set the number of virtual nodes per real node on the hash ring.
    pub fn with_ring_vnodes(mut self, vnodes: u32) -> Self {
        self.vnodes = vnodes.max(1);
        self
    }

    /// Shard URLs to nodes by **domain** using consistent hashing. Returns
    /// contiguous runs of `(url_slice, node_id)` assignments. URLs sharing a
    /// domain always map to the same node, pinning that domain's requests,
    /// sessions, and cookies to a single worker (proxy/profile pinning).
    pub fn shard_work<'a>(&self, urls: &'a [String], state: &ClusterState) -> Vec<(&'a [String], String)> {
        if urls.is_empty() {
            return Vec::new();
        }
        let ring = build_ring(&state.nodes.keys().cloned().collect::<Vec<_>>(), self.vnodes);
        let mut assignments: Vec<(&'a [String], String)> = Vec::new();
        let mut current_node: Option<String> = None;
        let mut start = 0usize;
        for (i, url) in urls.iter().enumerate() {
            let node = self.assign(&ring, url);
            match &current_node {
                Some(n) if *n == node => {}
                _ => {
                    if let Some(prev) = current_node.take() {
                        assignments.push((&urls[start..i], prev));
                    }
                    current_node = Some(node.clone());
                    start = i;
                }
            }
        }
        if let Some(prev) = current_node {
            assignments.push((&urls[start..], prev));
        }
        assignments
    }

    /// Map a single URL to a node by hashing its domain onto the ring.
    fn assign(&self, ring: &BTreeMap<u64, String>, url: &str) -> String {
        if ring.is_empty() {
            return self.self_node_id.clone();
        }
        let domain = extract_domain(url);
        let mut h = DefaultHasher::new();
        domain.hash(&mut h);
        let key = h.finish();
        // First ring entry with key >= domain hash (wrap to the smallest).
        match ring.range(key..).next() {
            Some((_, node)) => node.clone(),
            None => ring
                .iter()
                .next()
                .map(|(_, node)| node.clone())
                .unwrap_or_else(|| self.self_node_id.clone()),
        }
    }
}

/// Build a consistent-hash ring: `vnodes` positions per real node, keyed by a
/// stable hash of `"<node>:<v>"`. Node churn only remaps the domains that fall
/// between the removed/added ring points (minimal disruption).
fn build_ring(node_ids: &[String], vnodes: u32) -> BTreeMap<u64, String> {
    let mut ring = BTreeMap::new();
    for node in node_ids {
        for v in 0..vnodes {
            let mut h = DefaultHasher::new();
            format!("{node}:{v}").hash(&mut h);
            ring.entry(h.finish()).or_insert_with(|| node.clone());
        }
    }
    ring
}

/// Extract the lowercase host/domain (with port stripped) from a URL.
fn extract_domain(url: &str) -> String {
    let without_scheme = url
        .find("://")
        .map(|i| &url[i + 3..])
        .unwrap_or(url);
    let host = without_scheme
        .find('/')
        .map(|i| &without_scheme[..i])
        .unwrap_or(without_scheme);
    let domain = host
        .rfind(':')
        .and_then(|i| {
            if host[i + 1..].chars().all(|c| c.is_ascii_digit()) {
                Some(&host[..i])
            } else {
                None
            }
        })
        .unwrap_or(host);
    domain.to_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::coordinator::NodeInfo;
    use std::net::SocketAddr;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn two_node_state() -> ClusterState {
        let mut state = ClusterState::new();
        state.update_heartbeat(NodeInfo {
            node_id: "n1".into(),
            addr: addr(5000),
            active_browsers: 3,
            idle_slots: 2,
            max_browsers: 5,
        });
        state.update_heartbeat(NodeInfo {
            node_id: "n2".into(),
            addr: addr(5001),
            active_browsers: 3,
            idle_slots: 2,
            max_browsers: 5,
        });
        state
    }

    #[test]
    fn shard_work_assigns_all_urls() {
        let state = two_node_state();
        let urls: Vec<String> = (0..10).map(|i| format!("https://example.com/{i}")).collect();
        let dist = WorkDistributor::new("n1".into());
        let assignments = dist.shard_work(&urls, &state);

        // All URLs should be assigned exactly once.
        let total_assigned: usize = assignments.iter().map(|(slice, _)| slice.len()).sum();
        assert_eq!(total_assigned, 10);
    }

    #[test]
    fn shard_work_pins_domain_to_one_node() {
        let state = two_node_state();
        let mut urls: Vec<String> = Vec::new();
        for i in 0..6 {
            urls.push(format!("https://example.com/path/{i}"));
        }
        let dist = WorkDistributor::new("n1".into());
        let assignments = dist.shard_work(&urls, &state);

        // All same-domain URLs must go to a single node (proxy/profile pinning).
        assert_eq!(assignments.len(), 1, "domain should map to exactly one node");
        assert_eq!(assignments[0].0.len(), 6);
    }

    #[test]
    fn shard_work_splits_different_domains() {
        let state = two_node_state();
        let urls: Vec<String> = (0..8)
            .map(|i| format!("https://site{}.com/path/{i}", i % 4))
            .collect();
        let dist = WorkDistributor::new("n1".into());
        let assignments = dist.shard_work(&urls, &state);

        // All URLs assigned exactly once.
        let total: usize = assignments.iter().map(|(s, _)| s.len()).sum();
        assert_eq!(total, 8);

        // Domain pinning: every domain maps to exactly one node across the whole
        // shard (multiple domains may share a node, but a domain never splits).
        let mut domain_node: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        for (slice, node) in &assignments {
            for u in slice.iter() {
                let d = extract_domain(u);
                match domain_node.get(&d) {
                    Some(n) => assert_eq!(n, node, "domain {d} must stay pinned to one node"),
                    None => {
                        domain_node.insert(d, node.clone());
                    }
                }
            }
        }
    }

    #[test]
    fn shard_work_empty_cluster_assigns_to_self() {
        let state = ClusterState::new();
        let urls = vec!["https://example.com".to_string()];
        let dist = WorkDistributor::new("self-node".into());
        let assignments = dist.shard_work(&urls, &state);

        assert_eq!(assignments.len(), 1);
        assert_eq!(assignments[0].0.len(), 1);
        assert_eq!(assignments[0].1, "self-node");
    }

    #[test]
    fn consistent_hashing_is_stable_across_calls() {
        let state = two_node_state();
        let dist = WorkDistributor::new("n1".into());
        let urls: Vec<String> = (0..20)
            .map(|i| format!("https://mix{}.com/x/{i}", i % 6))
            .collect();
        let a = dist.shard_work(&urls, &state);
        let b = dist.shard_work(&urls, &state);
        // Re-sharding the same URLs yields the identical node mapping (stability).
        let map = |assign: &[(&[String], String)]| -> Vec<String> {
            assign.iter().flat_map(|(s, n)| s.iter().map(move |_| n.clone())).collect()
        };
        assert_eq!(map(&a), map(&b));
    }
}
