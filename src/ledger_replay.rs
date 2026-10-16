//! Ledger replay — deterministic projection harness (task A1.1.5, frozen
//! interface §2, `artifacts/tallow_intel_uplift_2026-09-11/impl/B02_INTERFACES.md`).
//!
//! [`replay`] rebuilds a minimal, deterministic "view" of a ledger chain: it
//! first re-verifies the chain from scratch, then folds every event into a
//! [`ProjectionState`] (`counts` per kind + `last_ts_ms` + `head_hash`).
//!
//! **Determinism contract:** for identical input slices the returned state is
//! byte-identical (equal `BTreeMap`, ts, hash) — the fold is a pure function
//! of the event stream, and counts are keyed by the stable
//! [`EventKind::as_str`](crate::ledger_events::EventKind::as_str) wire names,
//! so the serialized projection is stable too.
//!
//! **Chain check (self-contained, first failure wins):** this module
//! deliberately re-implements the verification loop over
//! [`canonical_bytes`] / [`compute_hash`] and does NOT import
//! `ledger_verify`, so the two implementations are independent (a bug in one
//! cannot mask a bug in the other). Checks in order: (1) link — the first
//! `prev_hash` must be [`GENESIS`] and every later one must equal its
//! predecessor's stored hash; (2) recompute —
//! `compute_hash(prev_hash, canonical_bytes(ev)) == ev.hash`. Any violation
//! yields `Err("chain invalid at index N: reason")`.
//!
//! Reality note: envelopes carry no `seq` field, so "gap" detection reduces
//! to restart/broken-link detection — a non-first `GENESIS` link or any other
//! mismatch fails the link check at that index.
//!
//! The projection is intentionally this simple ("rebuilt view"); new fields
//! (e.g. per-actor tallies) can be added later without changing the fold
//! contract for existing callers.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ledger_events::{EventEnvelope, GENESIS, canonical_bytes, compute_hash};

/// Rebuilt, serializable view of a replayed ledger chain.
///
/// Field names are part of the persisted contract (serde). `counts` is a
/// `BTreeMap` so iteration/serialization order is deterministic regardless of
/// insertion order; `last_ts_ms` is `0` and `head_hash` is [`GENESIS`] for an
/// empty chain.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectionState {
    /// Event counts keyed by `EventKind::as_str()` (stable wire names).
    pub counts: BTreeMap<String, usize>,
    /// `ts_ms` of the last event, or `0` when the chain is empty.
    pub last_ts_ms: i64,
    /// Hash of the last event, or `"GENESIS"` when the chain is empty.
    pub head_hash: String,
}

/// Verify `events` as a chain, then fold them into a [`ProjectionState`].
///
/// Returns `Err("chain invalid at index {N}: {reason}")` on the FIRST
/// failing event (link mismatch / mid-chain restart / hash recompute
/// mismatch) — no partial projection is produced for an invalid chain.
///
/// Deterministic: identical input (same order, same bytes) yields an equal
/// [`ProjectionState`], and `serde_json::to_string` of two runs is
/// byte-identical.
#[allow(dead_code)]
pub fn replay(events: &[EventEnvelope]) -> Result<ProjectionState, String> {
    // ── (a) self-contained chain verification ──────────────────────────────
    let mut expected_prev = GENESIS.to_string();
    for (index, ev) in events.iter().enumerate() {
        if ev.prev_hash != expected_prev {
            let reason = if index > 0 && ev.prev_hash == GENESIS {
                // A restart/gap: the chain begins again mid-stream.
                format!("gap/restart (prev_hash is {GENESIS}, expected {expected_prev})")
            } else {
                format!(
                    "link mismatch (expected prev_hash {expected_prev}, got {})",
                    ev.prev_hash
                )
            };
            return Err(format!("chain invalid at index {index}: {reason}"));
        }
        let recomputed = compute_hash(&ev.prev_hash, &canonical_bytes(ev));
        if recomputed != ev.hash {
            return Err(format!(
                "chain invalid at index {index}: hash mismatch (stored {}, recomputed {recomputed})",
                ev.hash
            ));
        }
        expected_prev = ev.hash.clone();
    }

    // ── (b) deterministic fold ─────────────────────────────────────────────
    let mut counts: BTreeMap<String, usize> = BTreeMap::new();
    for ev in events {
        *counts.entry(ev.kind.as_str().to_string()).or_insert(0) += 1;
    }
    let last_ts_ms = events.last().map(|ev| ev.ts_ms).unwrap_or(0);
    let head_hash = events
        .last()
        .map(|ev| ev.hash.clone())
        .unwrap_or_else(|| GENESIS.to_string());

    Ok(ProjectionState {
        counts,
        last_ts_ms,
        head_hash,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger_events::{EventKind, chain_next};

    /// Build a chain of fixed-field envelopes (deterministic hashes, no
    /// clock/uuid dependence at replay time).
    fn build_chain(kinds: &[EventKind]) -> Vec<EventEnvelope> {
        let mut out: Vec<EventEnvelope> = Vec::new();
        for (i, &kind) in kinds.iter().enumerate() {
            let prev_hash = out
                .last()
                .map(|e: &EventEnvelope| e.hash.clone())
                .unwrap_or_else(|| GENESIS.to_string());
            let mut ev = EventEnvelope {
                id: format!("00000000-0000-4000-8000-{i:012}"),
                ts_ms: 1_700_000_000_000 + (i as i64) * 1_000,
                actor: "agent:replay".to_string(),
                run_id: "run-replay".to_string(),
                kind,
                payload: format!("{{\"i\":{i}}}"),
                prev_hash,
                hash: String::new(),
            };
            let canonical = canonical_bytes(&ev);
            ev.hash = compute_hash(&ev.prev_hash, &canonical);
            out.push(ev);
        }
        out
    }

    fn expect_err_at(result: Result<ProjectionState, String>, index: usize) -> String {
        match result {
            Err(msg) => {
                assert!(
                    msg.starts_with(&format!("chain invalid at index {index}:")),
                    "expected failure at index {index}, got: {msg}"
                );
                msg
            }
            Ok(state) => panic!("expected Err, got Ok({state:?})"),
        }
    }

    #[test]
    fn replay_is_deterministic_same_input_twice() {
        let events = build_chain(&[
            EventKind::Plan,
            EventKind::Fetch,
            EventKind::Fetch,
            EventKind::Parse,
        ]);

        // Same slice, replayed twice: identical state.
        let a = replay(&events).unwrap();
        let b = replay(&events).unwrap();
        assert_eq!(a, b);

        // Two runs across separate Vec clones: byte-identical serialization.
        let c = replay(&events.clone()).unwrap();
        assert_eq!(
            serde_json::to_string(&a).unwrap(),
            serde_json::to_string(&c).unwrap(),
            "projection must serialize byte-identically across clones"
        );
    }

    #[test]
    fn tampered_event_is_rejected_with_index() {
        // (a) payload tamper at index 1: link intact, recomputed hash differs.
        let mut events = build_chain(&[EventKind::Plan, EventKind::Fetch, EventKind::Parse]);
        events[1].payload = "{\"evil\":true}".to_string();
        let msg = expect_err_at(replay(&events), 1);
        assert!(msg.contains("hash mismatch"), "reason: {msg}");

        // (b) broken link at index 2 (prev_hash rewired to junk).
        let mut events = build_chain(&[EventKind::Plan, EventKind::Fetch, EventKind::Parse]);
        events[2].prev_hash = "deadbeef".to_string();
        expect_err_at(replay(&events), 2);

        // (c) restart/gap: a non-first event links to GENESIS again.
        let mut events = build_chain(&[EventKind::Plan, EventKind::Fetch, EventKind::Parse]);
        events[1].prev_hash = GENESIS.to_string();
        let msg = expect_err_at(replay(&events), 1);
        assert!(msg.contains("gap/restart"), "reason: {msg}");

        // (d) corrupt stored hash at index 0.
        let mut events = build_chain(&[EventKind::Plan, EventKind::Fetch]);
        events[0].hash = "0".repeat(64);
        expect_err_at(replay(&events), 0);
    }

    #[test]
    fn empty_chain_yields_defaults() {
        let state = replay(&[]).unwrap();
        assert!(state.counts.is_empty());
        assert_eq!(state.last_ts_ms, 0);
        assert_eq!(state.head_hash, "GENESIS");
        assert_eq!(state.head_hash, GENESIS);
    }

    #[test]
    fn mixed_kind_counts_fold_correctly() {
        let events = build_chain(&[
            EventKind::Plan,   // 0
            EventKind::Fetch,  // 1
            EventKind::Fetch,  // 2
            EventKind::Parse,  // 3
            EventKind::Fetch,  // 4
            EventKind::Plan,   // 5
            EventKind::Verdict,// 6
        ]);
        let state = replay(&events).unwrap();

        let mut expected: BTreeMap<String, usize> = BTreeMap::new();
        expected.insert("plan".to_string(), 2);
        expected.insert("fetch".to_string(), 3);
        expected.insert("parse".to_string(), 1);
        expected.insert("verdict".to_string(), 1);
        assert_eq!(state.counts, expected);
        assert_eq!(state.counts.values().sum::<usize>(), events.len());
        assert_eq!(state.counts.keys().len(), 4);

        // last_ts_ms = last event ts; head_hash = last event hash.
        let last = events.last().unwrap();
        assert_eq!(state.last_ts_ms, last.ts_ms);
        assert_eq!(state.head_hash, last.hash);

        // Folding is order-stable: same kinds in a different order give the
        // same counts map (BTreeMap canonicalizes iteration order).
        let reordered = build_chain(&[
            EventKind::Verdict,
            EventKind::Fetch,
            EventKind::Plan,
            EventKind::Fetch,
            EventKind::Plan,
            EventKind::Fetch,
            EventKind::Parse,
        ]);
        let state2 = replay(&reordered).unwrap();
        assert_eq!(state.counts, state2.counts);
    }

    #[test]
    fn projection_serde_round_trip_keeps_field_names() {
        let events = build_chain(&[EventKind::AgentStep, EventKind::AgentStep, EventKind::Grade]);
        let state = replay(&events).unwrap();
        let json = serde_json::to_string(&state).unwrap();
        assert!(json.contains("\"counts\""));
        assert!(json.contains("\"last_ts_ms\""));
        assert!(json.contains("\"head_hash\""));
        assert!(json.contains("\"agent_step\":2"));
        let back: ProjectionState = serde_json::from_str(&json).unwrap();
        assert_eq!(state, back);
    }

    #[test]
    fn chain_next_built_chain_replays_and_refuses_after_tamper() {
        // Interop with the real builder: a live chain_next chain replays
        // cleanly; flipping a byte afterwards is refused.
        let mut events: Vec<EventEnvelope> = Vec::new();
        let mut prev: Option<EventEnvelope> = None;
        for i in 0..4 {
            let ev = chain_next(
                prev.as_ref(),
                EventKind::Fetch,
                "agent:test",
                "run-live",
                &format!("{{\"i\":{i}}}"),
            );
            prev = Some(ev.clone());
            events.push(ev);
        }
        let state = replay(&events).unwrap();
        assert_eq!(state.counts.get("fetch").copied(), Some(4));
        assert_eq!(state.head_hash, events.last().unwrap().hash);

        events[2].ts_ms += 1;
        expect_err_at(replay(&events), 2);
    }
}
