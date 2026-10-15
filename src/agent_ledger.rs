//! Agent Ledger — append-only, hash-chained event log core (task A1.1.2).
//!
//! The ledger is the durable backbone of an investigation run: every
//! [`EventEnvelope`] produced (plan, fetch, parse, …, verdict) is appended
//! exactly once and linked to its predecessor by hash. `append` is O(1) and
//! enforces the single structural invariant that makes the chain meaningful —
//! `ev.prev_hash` must equal the current head hash (`"GENESIS"` while empty).
//! Integrity is verified on demand by [`Ledger::verify_chain`], which
//! recomputes every link from scratch using the shared hashing primitives in
//! [`crate::ledger_events`] — this module never re-implements hashing.
//!
//! Persistence sits behind the [`LedgerBackend`] trait: the in-memory
//! implementation ([`MemoryLedger`]) ships here; the durable SQLite backend
//! ([`crate::agent_ledger_sqlite::SqliteLedger`]) and its single-writer
//! service ([`crate::agent_ledger_sqlite::CoordinatedLedger`], built on the
//! `StoreCoordinator` pattern from `agent_store.rs`) live in
//! `agent_ledger_sqlite.rs`.
//!
//! ## Live emission (task A1.1.4)
//! [`Recorder`] is the emission handle the live agent path uses: an
//! `@agent_task` runtime attaches one when `TALLOW_LEDGER_PATH` names a ledger
//! file, and every audit event that runtime queues (plus the interpreter's
//! direct-to-store lifecycle events: `checkpoint`, `shutdown`, `recovered`)
//! is appended through
//! [`crate::agent_observability::emit_agent_event`] as an `agent_step` entry —
//! the same chain `tallow verify-ledger <path>` reads back. With no opt-in
//! nothing is written and behavior is unchanged.

use crate::ledger_events::{EventEnvelope, GENESIS, canonical_bytes, chain_next, compute_hash};
use serde::{Deserialize, Serialize};

/// Errors from ledger operations.
///
/// `PrevHashMismatch` is an ingest-time rejection (the event does not link to
/// the current head); `Tampered` reports the first index where the stored
/// chain fails to re-hash or link, found by [`Ledger::verify_chain`].
#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    /// `ev.prev_hash` did not match the ledger's current head hash.
    #[error("prev_hash mismatch: expected {expected}, got {got}")]
    PrevHashMismatch { expected: String, got: String },
    /// Chain verification failed at event index `at`.
    #[error("chain tampered at index {at}")]
    Tampered { at: usize },
    /// Any other backend/IO failure (e.g. a durable backend's error).
    #[error("{0}")]
    Other(String),
}

/// Cheap, serializable summary of a ledger's state.
///
/// Used as a checkpoint/comparison primitive (e.g. by replication): two
/// ledgers with equal snapshots are at the same chain position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerSnapshot {
    pub head_hash: String,
    pub count: usize,
    pub last_ts_ms: i64,
}

/// Append-only, hash-chained event log (in memory).
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct Ledger {
    events: Vec<EventEnvelope>,
}

#[allow(dead_code)]
impl Ledger {
    /// Create an empty ledger.
    pub fn new() -> Self {
        Ledger { events: Vec::new() }
    }

    /// Append `ev`, enforcing the chain-head invariant.
    ///
    /// Rejects the event when `ev.prev_hash` differs from the current
    /// [`head_hash`](Self::head_hash) (`"GENESIS"` while empty) with
    /// [`LedgerError::PrevHashMismatch`]. This is deliberately the only check
    /// performed at ingest: link hashes are recomputed — never re-implemented
    /// here — by [`verify_chain`](Self::verify_chain), which is the single
    /// authority on chain integrity.
    pub fn append(&mut self, ev: EventEnvelope) -> Result<(), LedgerError> {
        let expected = self.head_hash();
        if ev.prev_hash != expected {
            return Err(LedgerError::PrevHashMismatch {
                expected,
                got: ev.prev_hash,
            });
        }
        self.events.push(ev);
        Ok(())
    }

    /// Recompute every link of the chain from the shared hashing primitives.
    ///
    /// For each event (in order): (a) its `prev_hash` must equal the previous
    /// event's stored `hash` (`"GENESIS"` for the first), and (b) re-hashing
    /// the event with [`canonical_bytes`] + [`compute_hash`] must reproduce
    /// its stored `hash` exactly. The first violation is reported as
    /// [`LedgerError::Tampered`] with the offending index.
    pub fn verify_chain(&self) -> Result<(), LedgerError> {
        let mut expected_prev = GENESIS.to_string();
        for (at, ev) in self.events.iter().enumerate() {
            if ev.prev_hash != expected_prev {
                return Err(LedgerError::Tampered { at });
            }
            let recomputed = compute_hash(&ev.prev_hash, &canonical_bytes(ev));
            if recomputed != ev.hash {
                return Err(LedgerError::Tampered { at });
            }
            expected_prev = ev.hash.clone();
        }
        Ok(())
    }

    /// Number of events in the ledger.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the ledger holds no events.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Iterate events in append order.
    pub fn iter(&self) -> impl Iterator<Item = &EventEnvelope> {
        self.events.iter()
    }

    /// The current chain head — the event the next `append` must extend.
    /// `None` while empty. Hand this to `ledger_events::chain_next` as `prev`.
    pub fn head(&self) -> Option<&EventEnvelope> {
        self.events.last()
    }

    /// Hash of the latest event, or `"GENESIS"` when empty.
    pub fn head_hash(&self) -> String {
        match self.events.last() {
            Some(ev) => ev.hash.clone(),
            None => GENESIS.to_string(),
        }
    }

    /// Point-in-time summary (head hash, count, last event timestamp).
    /// `last_ts_ms` is 0 while empty (no event timestamps exist yet).
    pub fn snapshot(&self) -> LedgerSnapshot {
        LedgerSnapshot {
            head_hash: self.head_hash(),
            count: self.events.len(),
            last_ts_ms: self.events.last().map(|ev| ev.ts_ms).unwrap_or(0),
        }
    }
}

/// Persistence seam for the append-only log.
///
/// Implementations must enforce the same chain-head invariant as
/// [`Ledger::append`] (reject `ev.prev_hash != head`) and return events in
/// append order from `read_all`.
#[allow(dead_code)]
pub trait LedgerBackend {
    /// Append one event, rejecting it unless it links to the current head.
    fn append(&mut self, ev: &EventEnvelope) -> Result<(), LedgerError>;
    /// Read the whole chain back, oldest first.
    fn read_all(&self) -> Result<Vec<EventEnvelope>, LedgerError>;

    /// Hash of the current chain head (`"GENESIS"` while empty).
    ///
    /// Default derives it from [`read_all`](Self::read_all) — backends with
    /// a cheaper head read (e.g. SQLite) should override.
    fn head_hash(&self) -> Result<String, LedgerError> {
        Ok(self
            .read_all()?
            .last()
            .map(|ev| ev.hash.clone())
            .unwrap_or_else(|| GENESIS.to_string()))
    }
}

/// In-memory [`LedgerBackend`] — the reference implementation, used for tests
/// and short-lived runs. Durable backends (SQLite) land later behind the same
/// trait and must not change call sites.
#[derive(Debug, Default)]
#[allow(dead_code)]
pub struct MemoryLedger {
    inner: Ledger,
}

#[allow(dead_code)]
impl MemoryLedger {
    /// Create an empty in-memory backend.
    pub fn new() -> Self {
        MemoryLedger {
            inner: Ledger::new(),
        }
    }

    /// Read-only view of the underlying ledger (head/len/verify without
    /// taking ownership or cloning the chain).
    pub fn ledger(&self) -> &Ledger {
        &self.inner
    }
}

impl LedgerBackend for MemoryLedger {
    fn append(&mut self, ev: &EventEnvelope) -> Result<(), LedgerError> {
        self.inner.append(ev.clone())
    }

    fn read_all(&self) -> Result<Vec<EventEnvelope>, LedgerError> {
        Ok(self.inner.iter().cloned().collect())
    }

    fn head_hash(&self) -> Result<String, LedgerError> {
        Ok(self.inner.head_hash())
    }
}

// ── Emission (A1.1.4) ────────────────────────────────────────────────────────

/// Emission helper: append chain-linked events for one investigation run
/// through any [`LedgerBackend`].
///
/// Keeps the chain head (the last appended envelope) in memory, so `record`
/// is O(1) per event and never rescans the chain; construction reads the
/// current head once, so a recorder attached to a durable backend **resumes
/// an existing chain across process restarts**.
///
/// `actor` and `run_id` must be non-blank ([`LedgerError::Other`]
/// otherwise). Every recorded event gets a fresh uuid v4 and a wall-clock
/// `ts_ms` from [`chain_next`].
pub struct Recorder<B: LedgerBackend> {
    backend: B,
    actor: String,
    run_id: String,
    last: Option<EventEnvelope>,
}

impl<B: LedgerBackend> std::fmt::Debug for Recorder<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Recorder(actor={:?}, run_id={:?}, head={})",
            self.actor,
            self.run_id,
            self.head_hash()
        )
    }
}

impl<B: LedgerBackend> Recorder<B> {
    /// Attach a recorder to `backend` for `(actor, run_id)`, resuming from
    /// the backend's current head when one exists.
    pub fn new(
        backend: B,
        actor: impl Into<String>,
        run_id: impl Into<String>,
    ) -> Result<Self, LedgerError> {
        let actor = actor.into();
        let run_id = run_id.into();
        if actor.trim().is_empty() {
            return Err(LedgerError::Other("recorder: empty actor".to_string()));
        }
        if run_id.trim().is_empty() {
            return Err(LedgerError::Other("recorder: empty run_id".to_string()));
        }
        let last = backend.read_all()?.last().cloned();
        Ok(Recorder {
            backend,
            actor,
            run_id,
            last,
        })
    }

    /// Record one subsystem event (`kind` + `payload_json`) onto the chain.
    /// Returns the sealed envelope.
    pub fn record(
        &mut self,
        kind: crate::ledger_events::EventKind,
        payload_json: &str,
    ) -> Result<EventEnvelope, LedgerError> {
        let ev = chain_next(self.last.as_ref(), kind, &self.actor, &self.run_id, payload_json);
        self.backend.append(&ev)?;
        self.last = Some(ev.clone());
        Ok(ev)
    }

    /// Current head hash (`"GENESIS"` while empty).
    pub fn head_hash(&self) -> String {
        self.last
            .as_ref()
            .map(|ev| ev.hash.clone())
            .unwrap_or_else(|| GENESIS.to_string())
    }

    /// Read-only view of the underlying backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// Consume the recorder, returning the backend.
    pub fn into_backend(self) -> B {
        self.backend
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger_events::{EventKind, chain_next};

    /// Build a clean, `chain_next`-linked ledger of `n` events.
    fn build_chain(n: usize) -> Ledger {
        let mut l = Ledger::new();
        for i in 0..n {
            let kind = match i % 8 {
                0 => EventKind::Plan,
                1 => EventKind::Fetch,
                2 => EventKind::Parse,
                3 => EventKind::Graph,
                4 => EventKind::Grade,
                5 => EventKind::Artifact,
                6 => EventKind::AgentStep,
                _ => EventKind::Verdict,
            };
            let ev = chain_next(l.head(), kind, "agent:test", "run-1", &format!("{{\"i\":{i}}}"));
            l.append(ev).unwrap();
        }
        l
    }

    #[test]
    fn empty_ledger_head_is_genesis() {
        let l = Ledger::new();
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
        assert!(l.head().is_none());
        assert_eq!(l.head_hash(), "GENESIS");
        let s = l.snapshot();
        assert_eq!(s.count, 0);
        assert_eq!(s.head_hash, "GENESIS");
        assert_eq!(s.last_ts_ms, 0);
        // The empty chain is trivially valid.
        l.verify_chain().unwrap();
    }

    #[test]
    fn append_ok_and_chain_links() {
        let l = build_chain(3);
        assert_eq!(l.len(), 3);
        assert!(!l.is_empty());
        l.verify_chain().unwrap();

        let events: Vec<&EventEnvelope> = l.iter().collect();
        // Genesis event references "GENESIS"; every later event references
        // its predecessor's hash, and the head hash is the last stored hash.
        assert_eq!(events[0].prev_hash, "GENESIS");
        assert_eq!(events[1].prev_hash, events[0].hash);
        assert_eq!(events[2].prev_hash, events[1].hash);
        assert_eq!(l.head_hash(), events[2].hash);
    }

    #[test]
    fn append_rejects_wrong_prev_hash() {
        // Genesis case: wrong prev_hash on an empty ledger.
        let mut l = Ledger::new();
        let mut bad = chain_next(None, EventKind::Plan, "agent:test", "run-1", "{\"a\":1}");
        bad.prev_hash = "not-genesis".to_string();
        match l.append(bad) {
            Err(LedgerError::PrevHashMismatch { expected, got }) => {
                assert_eq!(expected, "GENESIS");
                assert_eq!(got, "not-genesis");
            }
            other => panic!("expected PrevHashMismatch, got {other:?}"),
        }
        assert!(l.is_empty(), "rejected event must not be stored");

        // Mid-chain case: stale prev_hash (genesis) against a non-empty head.
        let mut l2 = build_chain(2);
        let head_before = l2.head_hash();
        let mut stale = chain_next(l2.head(), EventKind::Fetch, "agent:test", "run-1", "{\"b\":2}");
        stale.prev_hash = "GENESIS".to_string();
        match l2.append(stale) {
            Err(LedgerError::PrevHashMismatch { expected, got }) => {
                assert_eq!(expected, head_before);
                assert_eq!(got, "GENESIS");
            }
            other => panic!("expected PrevHashMismatch, got {other:?}"),
        }
        assert_eq!(l2.len(), 2, "rejected event must not be stored");
    }

    #[test]
    fn verify_chain_catches_mid_chain_tamper() {
        let mut l = build_chain(4);
        l.verify_chain().unwrap();

        // Flip a payload byte at index 1: linkage still holds (prev_hash
        // unchanged) but the recomputed hash no longer matches the stored one.
        l.events[1].payload = "{\"evil\":true}".to_string();
        match l.verify_chain() {
            Err(LedgerError::Tampered { at }) => assert_eq!(at, 1),
            other => panic!("expected Tampered at 1, got {other:?}"),
        }
    }

    #[test]
    fn verify_chain_catches_hash_and_relink_tamper() {
        // Corrupt a stored hash field directly.
        let mut l = build_chain(3);
        l.events[2].hash = "0".repeat(64);
        match l.verify_chain() {
            Err(LedgerError::Tampered { at }) => assert_eq!(at, 2),
            other => panic!("expected Tampered at 2, got {other:?}"),
        }

        // An attacker who rewrites an event's prev_hash to the wrong link is
        // caught by the linkage check…
        let mut l2 = build_chain(3);
        l2.events[2].prev_hash = "deadbeef".to_string();
        match l2.verify_chain() {
            Err(LedgerError::Tampered { at }) => assert_eq!(at, 2),
            other => panic!("expected Tampered at 2, got {other:?}"),
        }

        // …and one who *fixes* the link (so prev_hash matches again) still
        // fails: the stored hash cannot be re-derived from the altered bytes.
        let mut l3 = build_chain(3);
        let prev_ok = l3.events[1].hash.clone();
        l3.events[2].prev_hash = prev_ok;
        l3.events[2].payload = "{\"rewritten\":true}".to_string();
        match l3.verify_chain() {
            Err(LedgerError::Tampered { at }) => assert_eq!(at, 2),
            other => panic!("expected Tampered at 2, got {other:?}"),
        }
    }

    #[test]
    fn snapshot_reflects_n_appends() {
        let l = build_chain(5);
        let head = l.head().unwrap();
        let s = l.snapshot();
        assert_eq!(s.count, 5);
        assert_eq!(s.count, l.len());
        assert_eq!(s.head_hash, head.hash);
        assert_eq!(s.last_ts_ms, head.ts_ms);
    }

    #[test]
    fn snapshot_serde_round_trip() {
        let l = build_chain(3);
        let s = l.snapshot();
        let json = serde_json::to_string(&s).unwrap();
        // Field names are part of the persisted contract.
        assert!(json.contains("\"head_hash\""));
        assert!(json.contains("\"count\""));
        assert!(json.contains("\"last_ts_ms\""));
        let back: LedgerSnapshot = serde_json::from_str(&json).unwrap();
        assert_eq!(s, back);
    }

    #[test]
    fn memory_ledger_backend_appends_and_reads_all() {
        let l = build_chain(3);
        let mut m = MemoryLedger::new();
        for ev in l.iter() {
            m.append(ev).unwrap();
        }
        let all = m.read_all().unwrap();
        assert_eq!(all.len(), 3);
        for (a, b) in all.iter().zip(l.iter()) {
            assert_eq!(a.hash, b.hash);
            assert_eq!(a.prev_hash, b.prev_hash);
            assert_eq!(a.ts_ms, b.ts_ms);
        }
        // The backend enforces the same head invariant as Ledger::append.
        let mut bad = chain_next(m.ledger().head(), EventKind::Verdict, "agent:test", "run-9", "{}");
        bad.prev_hash = "GENESIS".to_string();
        assert!(matches!(
            m.append(&bad),
            Err(LedgerError::PrevHashMismatch { .. })
        ));
        assert_eq!(m.read_all().unwrap().len(), 3);
    }

    // ── Recorder (A1.1.4 emission) ─────────────────────────────────────────

    #[test]
    fn recorder_emits_every_subsystem_kind_and_chain_verifies() {
        let mut rec = Recorder::new(MemoryLedger::new(), "agent:test", "run-42").unwrap();
        assert_eq!(rec.head_hash(), "GENESIS");
        let kinds = [
            EventKind::Plan,
            EventKind::Fetch,
            EventKind::Parse,
            EventKind::Graph,
            EventKind::Grade,
            EventKind::Artifact,
            EventKind::AgentStep,
            EventKind::Verdict,
        ];
        let mut events = Vec::new();
        for (i, kind) in kinds.iter().enumerate() {
            let ev = rec.record(*kind, &format!("{{\"step\":{i}}}")).unwrap();
            assert_eq!(ev.kind, *kind);
            events.push(ev);
        }
        // Chain links hold; the whole emission verifies end to end.
        assert_eq!(events[0].prev_hash, "GENESIS");
        for w in events.windows(2) {
            assert_eq!(w[1].prev_hash, w[0].hash);
        }
        let mut l = Ledger::new();
        for ev in &events {
            l.append(ev.clone()).unwrap();
        }
        l.verify_chain().unwrap();
        assert_eq!(l.head_hash(), rec.head_hash());
    }

    #[test]
    fn recorder_refuses_blank_actor_and_run_id() {
        assert!(Recorder::new(MemoryLedger::new(), "", "run").is_err());
        assert!(Recorder::new(MemoryLedger::new(), "agent", "  ").is_err());
    }

    #[test]
    fn recorder_resumes_existing_chain_after_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("ledger.sqlite");
        let head_after_first;
        {
            let mut rec =
                Recorder::new(crate::agent_ledger_sqlite::SqliteLedger::open(&path).unwrap(), "agent:test", "run-7")
                    .unwrap();
            rec.record(EventKind::Plan, "{\"a\":1}").unwrap();
            head_after_first = rec.record(EventKind::Fetch, "{\"b\":2}").unwrap().hash;
        }
        // Reopen: the recorder resumes the persisted head and keeps linking.
        let mut rec =
            Recorder::new(crate::agent_ledger_sqlite::SqliteLedger::open(&path).unwrap(), "agent:test", "run-7")
                .unwrap();
        assert_eq!(rec.head_hash(), head_after_first);
        let ev = rec.record(EventKind::Parse, "{\"c\":3}").unwrap();
        assert_eq!(ev.prev_hash, head_after_first);
        let all = rec.into_backend().read_all().unwrap();
        assert_eq!(all.len(), 3);
        let mut l = Ledger::new();
        for e in &all {
            l.append(e.clone()).unwrap();
        }
        l.verify_chain().unwrap();
    }
}
