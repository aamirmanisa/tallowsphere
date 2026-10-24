//! Membership from signed heartbeats.
//!
//! The topology plane was an in-process map that reported `simulated: true` on
//! every node. This module is the first real half of replacing it: a peer table
//! fed only by `heartbeat` frames that verify against a known node key, expire
//! after `3 × interval`, and — the honesty rule — flip a node out of `simulated`
//! only once it has both handshaken **and** committed a task.
//!
//! It is deliberately transport-free: [`Membership::observe`] takes an already
//! decoded [`Envelope`], so the same table can be fed by a socket loop in tests
//! and by `mesh worker` in production without a second implementation.
//!
//! Two refusals define the plane:
//!
//! * A heartbeat for a node that never completed a handshake is refused — the
//!   table is built from keys the operator allowed, not from claims on the wire.
//! * A heartbeat whose `nonce` does not advance is refused — a replayed frame
//!   must not keep a dead node alive.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use super::wire::{Envelope, Trust};

/// Frame kind for liveness.
pub const HEARTBEAT: &str = "heartbeat";

/// How long a node may be silent before it leaves the table, as a multiple of
/// the heartbeat interval. Three intervals tolerate two lost frames.
pub const EXPIRY_INTERVALS: u32 = 3;

#[derive(Debug, Clone)]
struct Peer {
    last_seq: u64,
    last_seen: Instant,
    handshaken: bool,
    committed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MembershipError {
    /// The frame was not a heartbeat.
    NotAHeartbeat(String),
    /// The signature did not verify against the allowed key for that node.
    Untrusted(String),
    /// The node never completed the handshake the trust table requires.
    NoHandshake(String),
    /// A frame with this exact nonce was already accepted — a replay.
    Replay { node: String, nonce: u64 },
    /// A nonce that went backwards without repeating — reordering or an old
    /// frame re-signed. Either way it must not refresh liveness.
    StaleNonce { node: String, seen: u64, got: u64 },
}

impl std::fmt::Display for MembershipError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MembershipError::NotAHeartbeat(kind) => {
                write!(f, "membership: expected a '{HEARTBEAT}' frame, got '{kind}'")
            }
            MembershipError::Untrusted(node) => {
                write!(f, "membership: frame from '{node}' did not verify against its allowed key")
            }
            MembershipError::NoHandshake(node) => {
                write!(f, "membership: '{node}' heartbeat arrived before any handshake")
            }
            MembershipError::Replay { node, nonce } => write!(
                f,
                "membership: '{node}' nonce {nonce} was already accepted — replayed frame"
            ),
            MembershipError::StaleNonce { node, seen, got } => write!(
                f,
                "membership: '{node}' nonce did not advance ({got} <= {seen}) — replayed frame"
            ),
        }
    }
}

/// The peer table. One per node; fed by whatever owns the socket.
pub struct Membership {
    interval: Duration,
    peers: HashMap<String, Peer>,
    trust: Trust,
}

impl Membership {
    pub fn new(interval: Duration, trust: Trust) -> Self {
        assert!(!interval.is_zero(), "membership interval must be non-zero");
        Membership {
            interval,
            peers: HashMap::new(),
            trust,
        }
    }

    pub fn interval(&self) -> Duration {
        self.interval
    }

    /// Record that `node` completed its handshake (a signed `hello`/`welcome`
    /// exchange, verified elsewhere). Until this is called, heartbeats from that
    /// node are refused.
    pub fn handshaken(&mut self, node: &str, now: Instant) {
        self.peers
            .entry(node.to_string())
            .and_modify(|p| p.handshaken = true)
            .or_insert(Peer {
                last_seq: 0,
                last_seen: now,
                handshaken: true,
                committed: false,
            });
    }

    /// Record that `node` committed at least one task. This is what makes a node
    /// real rather than merely present.
    pub fn committed(&mut self, node: &str) {
        if let Some(p) = self.peers.get_mut(node) {
            p.committed = true;
        }
    }

    /// Accept a heartbeat. Verifies the frame kind, the signature against the
    /// node's allowed key, the handshake precondition, and monotonicity.
    pub fn observe(&mut self, env: &Envelope, now: Instant) -> Result<(), MembershipError> {
        if env.kind != HEARTBEAT {
            return Err(MembershipError::NotAHeartbeat(env.kind.clone()));
        }
        if let Err(reason) = self.trust.accept_node(env) {
            // Two different refusals hide behind one `Err` in `Trust`: a bad
            // signature, and the replay guard rejecting an already-seen nonce.
            // Verify the signature separately so the caller is told which.
            let signed_ok = self
                .trust
                .node(&env.node)
                .map(|vk| env.verify(vk))
                .unwrap_or(false);
            if signed_ok {
                return Err(MembershipError::Replay {
                    node: env.node.clone(),
                    nonce: env.nonce,
                });
            }
            let _ = reason;
            return Err(MembershipError::Untrusted(env.node.clone()));
        }

        let peer = self
            .peers
            .get_mut(&env.node)
            .ok_or_else(|| MembershipError::NoHandshake(env.node.clone()))?;
        if !peer.handshaken {
            return Err(MembershipError::NoHandshake(env.node.clone()));
        }
        if env.nonce <= peer.last_seq {
            return Err(MembershipError::StaleNonce {
                node: env.node.clone(),
                seen: peer.last_seq,
                got: env.nonce,
            });
        }
        peer.last_seq = env.nonce;
        peer.last_seen = now;
        Ok(())
    }

    /// Nodes seen within `EXPIRY_INTERVALS × interval`, in name order so the
    /// result is deterministic.
    pub fn live(&self, now: Instant) -> Vec<String> {
        let horizon = self.interval * EXPIRY_INTERVALS;
        let mut out: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, p)| p.handshaken && now.saturating_duration_since(p.last_seen) <= horizon)
            .map(|(n, _)| n.clone())
            .collect();
        out.sort();
        out
    }

    /// Whether a node should be reported as simulated. False — real — only when
    /// it is live, has completed a handshake and has committed a task.
    pub fn is_simulated(&self, node: &str, now: Instant) -> bool {
        let horizon = self.interval * EXPIRY_INTERVALS;
        match self.peers.get(node) {
            Some(p) => {
                !(p.handshaken
                    && p.committed
                    && now.saturating_duration_since(p.last_seen) <= horizon)
            }
            None => true,
        }
    }

    /// Drop nodes past the horizon. Returns the removed names.
    pub fn expire(&mut self, now: Instant) -> Vec<String> {
        let horizon = self.interval * EXPIRY_INTERVALS;
        let dead: Vec<String> = self
            .peers
            .iter()
            .filter(|(_, p)| now.saturating_duration_since(p.last_seen) > horizon)
            .map(|(n, _)| n.clone())
            .collect();
        for n in &dead {
            self.peers.remove(n);
        }
        let mut dead = dead;
        dead.sort();
        dead
    }

    pub fn len(&self) -> usize {
        self.peers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::wire::{Envelope, Trust};
    use ed25519_dalek::SigningKey;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn beat(node: &str, nonce: u64, sk: &SigningKey) -> Envelope {
        let mut env = Envelope::new(HEARTBEAT, "run-1", 0, node, nonce, serde_json::json!({}));
        env.sign(sk);
        env
    }

    fn table() -> (Membership, SigningKey) {
        let sk = key(7);
        let trust = Trust::new().allow_node("n1", sk.verifying_key());
        (Membership::new(Duration::from_millis(100), trust), sk)
    }

    #[test]
    fn a_handshaken_node_with_advancing_nonces_stays_live_and_becomes_real_after_a_commit() {
        let (mut m, sk) = table();
        let t0 = Instant::now();
        m.handshaken("n1", t0);
        assert_eq!(m.live(t0), vec!["n1".to_string()]);
        // Handshake alone is not enough to claim reality.
        assert!(m.is_simulated("n1", t0), "no commit yet — must still report simulated");

        m.observe(&beat("n1", 1, &sk), t0).expect("heartbeat");
        assert!(m.is_simulated("n1", t0), "presence is not a commit");

        m.committed("n1");
        assert!(!m.is_simulated("n1", t0), "handshake + commit = real");
    }

    #[test]
    fn a_silent_node_leaves_the_table_after_three_intervals() {
        let (mut m, sk) = table();
        let t0 = Instant::now();
        m.handshaken("n1", t0);
        m.observe(&beat("n1", 1, &sk), t0).unwrap();
        m.committed("n1");

        assert_eq!(m.live(t0 + Duration::from_millis(299)), vec!["n1".to_string()]);
        assert!(m.live(t0 + Duration::from_millis(301)).is_empty(), "expired");
        assert_eq!(m.expire(t0 + Duration::from_millis(301)), vec!["n1".to_string()]);
        assert_eq!(m.len(), 0);
        assert!(m.is_simulated("n1", t0 + Duration::from_millis(301)));
    }

    #[test]
    fn a_replayed_heartbeat_is_refused_and_does_not_refresh_liveness() {
        let (mut m, sk) = table();
        let t0 = Instant::now();
        m.handshaken("n1", t0);
        m.observe(&beat("n1", 5, &sk), t0).unwrap();
        let err = m
            .observe(&beat("n1", 5, &sk), t0 + Duration::from_millis(50))
            .unwrap_err();
        assert!(matches!(err, MembershipError::Replay { .. }), "{err}");
        // The table still believes the node is at t0, so it expires on schedule.
        assert!(m.live(t0 + Duration::from_millis(320)).is_empty());
    }

    #[test]
    fn an_out_of_order_nonce_is_refused_even_though_it_was_never_seen() {
        let (mut m, sk) = table();
        let t0 = Instant::now();
        m.handshaken("n1", t0);
        m.observe(&beat("n1", 5, &sk), t0).unwrap();
        let err = m
            .observe(&beat("n1", 4, &sk), t0 + Duration::from_millis(10))
            .unwrap_err();
        assert!(matches!(err, MembershipError::StaleNonce { .. }), "{err}");
    }

    #[test]
    fn a_heartbeat_before_handshake_or_from_an_unknown_key_is_refused() {
        let (mut m, sk) = table();
        let t0 = Instant::now();
        let err = m.observe(&beat("n1", 1, &sk), t0).unwrap_err();
        assert!(matches!(err, MembershipError::NoHandshake(_)), "{err}");

        m.handshaken("n1", t0);
        let stranger = key(9);
        let err = m.observe(&beat("n1", 1, &stranger), t0).unwrap_err();
        assert!(matches!(err, MembershipError::Untrusted(_)), "{err}");
    }

    #[test]
    fn a_non_heartbeat_frame_is_not_membership_input() {
        let (mut m, sk) = table();
        let t0 = Instant::now();
        m.handshaken("n1", t0);
        let mut env = Envelope::new("task_result", "run-1", 0, "n1", 1, serde_json::json!({}));
        env.sign(&sk);
        let err = m.observe(&env, t0).unwrap_err();
        assert!(matches!(err, MembershipError::NotAHeartbeat(_)), "{err}");
    }
}
