//! Shred → ledger adoption — erasure tombstones enter the hash-chained ledger
//! (task A2.1.1/A2.1.2 adoption · frozen interface §3).
//!
//! `crate::shred` produces [`crate::shred::ErasureEvent`] tombstones when a
//! crypto-shredding key is destroyed; `crate::ledger_events` owns the
//! hash-chained [`crate::ledger_events::EventEnvelope`]. This module joins the
//! two without editing either:
//!
//! * [`erasure_to_event`] — a tombstone becomes a chain-ready, genesis-linked
//!   envelope (sealed via `ledger_events::chain_next` semantics).
//! * [`append_erasure`] — link a tombstone onto an existing chain, fail-closed
//!   on a head-hash mismatch, and return the new head hash.
//! * [`verify_chain`] — recompute every seal and every link per
//!   `ledger_events` semantics; any edit to any field of any record verifies
//!   `false`.
//! * [`encrypt_artifact`] / [`decrypt_artifact`] — keyring-backed adoption
//!   hooks so artifact encryption always flows through the in-memory
//!   [`crate::shred::ShredKeyring`] (call-site adoption is the parent's
//!   integration step; this module provides the sanctioned entry points).
//!
//! # Mapping decisions (judgment calls — argued in the batch report)
//!
//! * **Kind**: [`ERASURE_KIND`] = [`crate::ledger_events::EventKind::Artifact`].
//!   The frozen taxonomy (`plan|fetch|parse|graph|grade|artifact|agent_step|
//!   verdict`) has no `erasure` variant, and kind words are hash-committed —
//!   inventing one locally would fork the wire format. An erasure is a
//!   lifecycle event of an artifact's keying, so `artifact` is the closest
//!   stable mapping. If the taxonomy ever grows an `erasure` kind, that is a
//!   versioned migration, not a local rename.
//! * **Actor**: [`ERASURE_ACTOR`] = `"system:shred"` — the keyring is a
//!   mechanism, not a persona; no user/agent identity exists at destroy time.
//! * **Run id**: the tombstone's `investigation` — erasures group with the
//!   investigation they belong to.
//! * **Payload**: serde JSON of the tombstone (`key_id`, `investigation`,
//!   `at_ms`). `chain_next` canonicalizes it, so the stored payload is
//!   byte-stable and fully hash-committed.
//!
//! # `append_erasure` head-link rule (documented)
//!
//! The caller passes the head hash it believes in. `append_erasure` refuses
//! (`LinkMismatch`) unless that equals `chain.last().hash` (or
//! [`GENESIS`] for an empty chain). Appending under a stale/wrong head would
//! silently fork the chain, so the operation is fail-closed; a rejected append
//! never mutates the chain.
//!
//! # Determinism
//!
//! Like `ledger_events::chain_next`, envelope `id` is a fresh uuid v4 and
//! `ts_ms` is wall-clock append time, so two appends of the same tombstone
//! differ in exactly those two non-committed-to-others fields. Everything
//! else is deterministic: same tombstone ⇒ same payload bytes, and for a fixed
//! `(id, ts_ms)` the seal `compute_hash(prev_hash, canonical_bytes(ev))` is
//! reproducible. `verify_chain` is a pure function of chain contents.

use crate::ledger_events::{
    canonical_bytes, chain_next, compute_hash, EventEnvelope, EventKind, GENESIS,
};
use crate::shred::{ErasureEvent, ShredError, ShredKeyring};
use serde_json::json;
use std::fmt;

/// Ledger kind used for erasure tombstones (see module docs — closest stable
/// mapping in the frozen `EventKind` taxonomy).
pub const ERASURE_KIND: EventKind = EventKind::Artifact;

/// Ledger actor recorded for erasures: the shredding mechanism itself.
pub const ERASURE_ACTOR: &str = "system:shred";

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors from ledger-adoption operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShredLedgerError {
    /// Keyring operation failed (unknown key, already destroyed, AEAD
    /// failure). Wrapped verbatim so callers keep `shred`'s exact semantics.
    Shred(ShredError),
    /// The caller's expected head hash does not match the chain's actual head
    /// (or `GENESIS` for an empty chain). Fail-closed: nothing is appended.
    LinkMismatch {
        /// What the chain head actually is (`GENESIS` for an empty chain).
        expected: String,
        /// What the caller passed.
        got: String,
    },
}

impl fmt::Display for ShredLedgerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ShredLedgerError::Shred(e) => write!(f, "shred-ledger: {e}"),
            ShredLedgerError::LinkMismatch { expected, got } => write!(
                f,
                "shred-ledger: head link mismatch (expected '{expected}', got '{got}')"
            ),
        }
    }
}

impl std::error::Error for ShredLedgerError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ShredLedgerError::Shred(e) => Some(e),
            ShredLedgerError::LinkMismatch { .. } => None,
        }
    }
}

impl From<ShredError> for ShredLedgerError {
    fn from(e: ShredError) -> Self {
        ShredLedgerError::Shred(e)
    }
}

// ---------------------------------------------------------------------------
// Tombstone → ledger envelope
// ---------------------------------------------------------------------------

/// Deterministic JSON body for the tombstone payload.
///
/// `json!`-built (infallible for `String`/`i64` fields); key order here is
/// irrelevant to the sealed hash because `chain_next`/`canonical_bytes`
/// re-canonicalize with their own sorted writer.
fn erasure_payload(ev: &ErasureEvent) -> String {
    json!({
        "at_ms": ev.at_ms,
        "investigation": ev.investigation,
        "key_id": ev.key_id
    })
    .to_string()
}

/// Build the chain-ready envelope for an erasure tombstone.
///
/// Genesis-linked (`prev_hash == "GENESIS"`) so it is directly appendable to
/// an empty chain and independently verifiable as a chain of one. To append
/// onto an existing chain (re-link to its head) use [`append_erasure`], which
/// seals with the correct `prev_hash`.
///
/// `id` (uuid v4) and `ts_ms` (wall clock) follow `ledger_events::chain_next`
/// semantics; every other field is derived from the tombstone.
pub fn erasure_to_event(ev: &ErasureEvent) -> EventEnvelope {
    chain_next(
        None,
        ERASURE_KIND,
        ERASURE_ACTOR,
        &ev.investigation,
        &erasure_payload(ev),
    )
}

/// Build + append a tombstone event to `chain`, returning the new head hash.
///
/// `prev_hash` must be the chain's actual head hash, or [`GENESIS`] when
/// `chain` is empty; anything else is refused with
/// [`ShredLedgerError::LinkMismatch`] and the chain is left untouched
/// (fail-closed — see module docs). On success the appended envelope is
/// `chain_next`-sealed and `verify_chain` still holds for the whole chain.
pub fn append_erasure(
    chain: &mut Vec<EventEnvelope>,
    prev_hash: &str,
    ev: &ErasureEvent,
) -> Result<String, ShredLedgerError> {
    let expected = chain
        .last()
        .map(|e| e.hash.as_str())
        .unwrap_or(GENESIS);
    if prev_hash != expected {
        return Err(ShredLedgerError::LinkMismatch {
            expected: expected.to_string(),
            got: prev_hash.to_string(),
        });
    }

    let next = chain_next(
        chain.last(),
        ERASURE_KIND,
        ERASURE_ACTOR,
        &ev.investigation,
        &erasure_payload(ev),
    );
    let head = next.hash.clone();
    chain.push(next);
    Ok(head)
}

/// Verify a chain per `ledger_events` semantics. Pure function; no state.
///
/// For every envelope, in order:
/// 1. **Seal**: `compute_hash(ev.prev_hash, canonical_bytes(ev)) == ev.hash`
///    (recomputed — any field edit is detected).
/// 2. **Link**: the first envelope must carry `prev_hash == "GENESIS"`; every
///    later envelope must carry `prev_hash == previous.hash`.
///
/// An empty chain verifies `true` (vacuously intact, documented). A suffix
/// window that does not start at a genesis event verifies `false` — the first
/// element must anchor the chain.
pub fn verify_chain(chain: &[EventEnvelope]) -> bool {
    let mut prev: Option<&EventEnvelope> = None;
    for ev in chain {
        if compute_hash(&ev.prev_hash, &canonical_bytes(ev)) != ev.hash {
            return false;
        }
        match prev {
            None => {
                if ev.prev_hash != GENESIS {
                    return false;
                }
            }
            Some(p) => {
                if ev.prev_hash != p.hash {
                    return false;
                }
            }
        }
        prev = Some(ev);
    }
    true
}

// ---------------------------------------------------------------------------
// Keyring-backed artifact encryption (adoption hooks)
// ---------------------------------------------------------------------------

/// Encrypt an artifact under `key_id` via the crypto-shredding keyring.
///
/// Adoption hook: artifact call sites (raw/derived stores, replication
/// payloads) should route through this so every blob is bound to a key whose
/// destruction is ledger-recorded. Error semantics are `shred`'s, wrapped.
pub fn encrypt_artifact(
    keyring: &ShredKeyring,
    key_id: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, ShredLedgerError> {
    keyring.encrypt(key_id, plaintext).map_err(Into::into)
}

/// Decrypt an artifact produced by [`encrypt_artifact`]; a destroyed key
/// yields [`ShredLedgerError::Shred`]`(`[`ShredError::AlreadyDestroyed`]`)` —
/// the ciphertext survives, readability does not.
pub fn decrypt_artifact(
    keyring: &ShredKeyring,
    key_id: &str,
    blob: &[u8],
) -> Result<Vec<u8>, ShredLedgerError> {
    keyring.decrypt(key_id, blob).map_err(Into::into)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    /// Fixed-field envelope for determinism checks (mirrors the
    /// `ledger_events` test-fixture style: identical fields ⇒ identical seal).
    fn fixed_event(ev: &ErasureEvent) -> EventEnvelope {
        let mut env = EventEnvelope {
            id: "00000000-0000-4000-8000-0000000000a3".to_string(),
            ts_ms: 1_700_000_000_000,
            actor: ERASURE_ACTOR.to_string(),
            run_id: ev.investigation.clone(),
            kind: ERASURE_KIND,
            payload: erasure_payload(ev),
            prev_hash: GENESIS.to_string(),
            hash: String::new(),
        };
        let canonical = canonical_bytes(&env);
        env.hash = compute_hash(&env.prev_hash, &canonical);
        env
    }

    fn recompute(ev: &EventEnvelope) -> String {
        compute_hash(&ev.prev_hash, &canonical_bytes(ev))
    }

    /// Allocate a key in `investigation` and destroy it, yielding its tombstone.
    fn tombstone(keyring: &mut ShredKeyring, investigation: &str, at_ms: i64) -> ErasureEvent {
        let k = keyring.new_key(investigation, at_ms - 1_000);
        keyring.destroy(&k, at_ms).unwrap()
    }

    // ── erasure_to_event ────────────────────────────────────────────────────

    #[test]
    fn erasure_to_event_maps_tombstone_fields() {
        let mut ring = ShredKeyring::new();
        let ev = tombstone(&mut ring, "inv-7", 5_000);

        let env = erasure_to_event(&ev);
        assert_eq!(env.kind, EventKind::Artifact, "pinned kind mapping");
        assert_eq!(env.kind, ERASURE_KIND);
        assert_eq!(env.actor, ERASURE_ACTOR);
        assert_eq!(env.run_id, "inv-7");
        assert_eq!(env.prev_hash, GENESIS);
        assert!(uuid::Uuid::parse_str(&env.id).is_ok(), "id must be a uuid");
        assert_eq!(env.hash.len(), 64);
        assert!(env.hash.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(recompute(&env), env.hash, "genesis envelope seals cleanly");

        // Tombstone fields survive: payload round-trips to the exact event.
        let back: ErasureEvent = serde_json::from_str(&env.payload).unwrap();
        assert_eq!(back, ev);
        let v: Value = serde_json::from_str(&env.payload).unwrap();
        assert_eq!(v["key_id"], Value::String(ev.key_id.clone()));
        assert_eq!(v["investigation"], Value::String("inv-7".to_string()));
        assert_eq!(v["at_ms"], json!(5_000));
    }

    // ── append + verify (the headline property) ─────────────────────────────

    #[test]
    fn erasure_append_chain_verifies_true() {
        let mut ring = ShredKeyring::new();
        let ev1 = tombstone(&mut ring, "inv-a", 1_000);
        let ev2 = tombstone(&mut ring, "inv-b", 2_000);

        let mut chain: Vec<EventEnvelope> = Vec::new();
        let h1 = append_erasure(&mut chain, GENESIS, &ev1).unwrap();
        assert_eq!(chain.len(), 1);
        assert_eq!(chain[0].hash, h1);
        assert!(verify_chain(&chain), "genesis append must verify");

        let h2 = append_erasure(&mut chain, &h1, &ev2).unwrap();
        assert_eq!(chain.len(), 2);
        assert_eq!(chain[1].prev_hash, h1, "second event links to first");
        assert_eq!(chain[1].hash, h2);
        assert_ne!(h1, h2);
        assert!(verify_chain(&chain), "chain must verify true after erasure");

        // Tombstones survive the chain round-trip, field for field.
        let back1: ErasureEvent = serde_json::from_str(&chain[0].payload).unwrap();
        let back2: ErasureEvent = serde_json::from_str(&chain[1].payload).unwrap();
        assert_eq!(back1, ev1);
        assert_eq!(back2, ev2);
        assert_eq!(back2.key_id, ev2.key_id);
        assert_eq!(back2.investigation, "inv-b");
        assert_eq!(back2.at_ms, 2_000);

        // Appending preserved every earlier seal.
        assert_eq!(recompute(&chain[0]), chain[0].hash);
        assert_eq!(recompute(&chain[1]), chain[1].hash);
    }

    #[test]
    fn append_rejects_wrong_prev_hash_and_leaves_chain_unchanged() {
        let mut ring = ShredKeyring::new();
        let ev1 = tombstone(&mut ring, "inv-a", 1_000);
        let ev2 = tombstone(&mut ring, "inv-b", 2_000);

        // Empty chain accepts only GENESIS.
        let mut chain: Vec<EventEnvelope> = Vec::new();
        match append_erasure(&mut chain, "deadbeef", &ev1) {
            Err(ShredLedgerError::LinkMismatch { expected, got }) => {
                assert_eq!(expected, GENESIS);
                assert_eq!(got, "deadbeef");
            }
            other => panic!("expected LinkMismatch, got {other:?}"),
        }
        assert!(chain.is_empty(), "rejected append must not mutate");
        assert!(verify_chain(&chain));

        // Non-empty chain accepts only its current head.
        let h1 = append_erasure(&mut chain, GENESIS, &ev1).unwrap();
        match append_erasure(&mut chain, GENESIS, &ev2) {
            Err(ShredLedgerError::LinkMismatch { expected, got }) => {
                assert_eq!(expected, h1);
                assert_eq!(got, GENESIS);
            }
            other => panic!("expected LinkMismatch, got {other:?}"),
        }
        assert_eq!(chain.len(), 1, "rejected append must not mutate");
        assert!(verify_chain(&chain));
    }

    // ── verify_chain ────────────────────────────────────────────────────────

    #[test]
    fn verify_chain_detects_tampering_reordering_and_splicing() {
        let mut ring = ShredKeyring::new();
        let mut chain: Vec<EventEnvelope> = Vec::new();
        let mut head = GENESIS.to_string();
        for i in 0..3 {
            let ev = tombstone(&mut ring, &format!("inv-{i}"), 1_000 * (i + 1) as i64);
            head = append_erasure(&mut chain, &head, &ev).unwrap();
        }
        assert!(verify_chain(&chain), "clean 3-event chain verifies");

        // (a) payload edit inside one record.
        let mut t = chain.clone();
        let pos = t[1].payload.find("shred-").expect("key_id present") + "shred-".len();
        let ch = t[1].payload.as_bytes()[pos];
        let repl = if ch == b'0' { "1" } else { "0" };
        t[1].payload.replace_range(pos..pos + 1, repl);
        assert!(!verify_chain(&t), "edited payload must fail verification");

        // (b) seal edit.
        let mut t = chain.clone();
        t[1].hash = "0".repeat(64);
        assert!(!verify_chain(&t), "edited hash must fail verification");

        // (c) history rewrite via prev_hash.
        let mut t = chain.clone();
        t[1].prev_hash = "f".repeat(64);
        assert!(!verify_chain(&t), "rewritten link must fail verification");

        // (d) reorder = splice.
        let mut t = chain.clone();
        t.swap(0, 1);
        assert!(!verify_chain(&t), "reordered chain must fail verification");

        // (e) foreign (even validly sealed) envelope prepended.
        let mut t = chain.clone();
        let alien = fixed_event(&tombstone(&mut ring, "inv-x", 9_999));
        t.insert(0, alien);
        assert!(!verify_chain(&t), "spliced head must fail verification");

        // Untouched chain still verifies (verification keeps no state).
        assert!(verify_chain(&chain));
        assert!(verify_chain(&chain.clone()));
    }

    #[test]
    fn empty_chain_verifies_true_and_first_element_must_anchor_genesis() {
        assert!(verify_chain(&[]), "empty chain is vacuously intact");
        let mut ring = ShredKeyring::new();
        let ev = tombstone(&mut ring, "inv-1", 1_000);

        let mut chain = vec![erasure_to_event(&ev)];
        assert!(verify_chain(&chain), "single genesis-linked event verifies");

        // Re-pointing the anchor away from GENESIS breaks the seal and the
        // genesis rule simultaneously.
        chain[0].prev_hash = "a".repeat(64);
        assert!(!verify_chain(&chain));
    }

    // ── keyring-backed artifact hooks ───────────────────────────────────────

    #[test]
    fn destroyed_key_makes_decrypt_artifact_fail() {
        let mut ring = ShredKeyring::new();
        let k = ring.new_key("inv-1", 1_000);
        let blob = encrypt_artifact(&ring, &k, b"artifact bytes").unwrap();
        assert_eq!(decrypt_artifact(&ring, &k, &blob).unwrap(), b"artifact bytes");

        let ev = ring.destroy(&k, 5_000).unwrap();
        // The ciphertext survives; readability dies with the key.
        match decrypt_artifact(&ring, &k, &blob) {
            Err(ShredLedgerError::Shred(ShredError::AlreadyDestroyed { key_id })) => {
                assert_eq!(key_id, k)
            }
            other => panic!("expected AlreadyDestroyed, got {other:?}"),
        }
        assert!(matches!(
            encrypt_artifact(&ring, &k, b"more"),
            Err(ShredLedgerError::Shred(ShredError::AlreadyDestroyed { .. }))
        ));
        assert!(matches!(
            encrypt_artifact(&ring, "nope", b"x"),
            Err(ShredLedgerError::Shred(ShredError::UnknownKey { .. }))
        ));
        assert!(matches!(
            decrypt_artifact(&ring, "nope", &blob),
            Err(ShredLedgerError::Shred(ShredError::UnknownKey { .. }))
        ));

        // ...and the erasure itself still lands in a verifying chain.
        let mut chain: Vec<EventEnvelope> = Vec::new();
        let h = append_erasure(&mut chain, GENESIS, &ev).unwrap();
        assert_eq!(chain[0].hash, h);
        assert!(verify_chain(&chain));
    }

    #[test]
    fn wrong_key_and_tampered_blob_map_to_crypto_errors() {
        let mut ring = ShredKeyring::new();
        let a = ring.new_key("inv-a", 1_000);
        let b = ring.new_key("inv-b", 1_000);
        let mut blob = encrypt_artifact(&ring, &a, b"for a only").unwrap();
        assert!(matches!(
            decrypt_artifact(&ring, &b, &blob),
            Err(ShredLedgerError::Shred(ShredError::Crypto(_)))
        ));
        let last = blob.len() - 1;
        blob[last] ^= 0x01;
        assert!(matches!(
            decrypt_artifact(&ring, &a, &blob),
            Err(ShredLedgerError::Shred(ShredError::Crypto(_)))
        ));

        // Binary + empty payloads round-trip through the hooks.
        let binary: Vec<u8> = (0u8..=255).collect();
        let blob = encrypt_artifact(&ring, &a, &binary).unwrap();
        assert_eq!(decrypt_artifact(&ring, &a, &blob).unwrap(), binary);
        let blob = encrypt_artifact(&ring, &a, b"").unwrap();
        assert_eq!(decrypt_artifact(&ring, &a, &blob).unwrap(), b"");
    }

    // ── determinism ─────────────────────────────────────────────────────────

    #[test]
    fn determinism_of_payloads_fixed_seals_and_verification() {
        let mut ring = ShredKeyring::new();
        let ev = tombstone(&mut ring, "inv-det", 4_242);

        // Same tombstone ⇒ same payload bytes and mapping across calls.
        let e1 = erasure_to_event(&ev);
        let e2 = erasure_to_event(&ev);
        assert_eq!(e1.payload, e2.payload);
        assert_eq!(e1.kind, e2.kind);
        assert_eq!(e1.actor, e2.actor);
        assert_eq!(e1.run_id, e2.run_id);
        assert_eq!(e1.prev_hash, e2.prev_hash);
        assert!(uuid::Uuid::parse_str(&e1.id).is_ok());
        assert!(uuid::Uuid::parse_str(&e2.id).is_ok());

        // Fixed (id, ts_ms) ⇒ fully deterministic seal.
        let f1 = fixed_event(&ev);
        let f2 = fixed_event(&ev);
        assert_eq!(f1, f2);
        assert_eq!(canonical_bytes(&f1), canonical_bytes(&f2));
        assert_eq!(recompute(&f1), f1.hash);
        assert_eq!(recompute(&f1), recompute(&f2));

        // Verification is a pure function of chain contents.
        let mut chain: Vec<EventEnvelope> = Vec::new();
        let head = append_erasure(&mut chain, GENESIS, &ev).unwrap();
        assert_eq!(chain[0].hash, head);
        assert!(verify_chain(&chain));
        assert_eq!(verify_chain(&chain), verify_chain(&chain.clone()));
    }

    // ── error surface ───────────────────────────────────────────────────────

    #[test]
    fn error_display_and_source_wrap_shred_errors() {
        let err = ShredLedgerError::from(ShredError::UnknownKey {
            key_id: "shred-00000001-deadbeef".to_string(),
        });
        let msg = err.to_string();
        assert!(msg.contains("unknown key"), "got: {msg}");
        assert!(msg.contains("shred-00000001-deadbeef"), "got: {msg}");
        assert!(
            std::error::Error::source(&err).is_some(),
            "Shred source chain must be preserved"
        );

        let lm = ShredLedgerError::LinkMismatch {
            expected: "aa".to_string(),
            got: "bb".to_string(),
        };
        let msg = lm.to_string();
        assert!(msg.contains("aa") && msg.contains("bb"), "got: {msg}");
        assert!(std::error::Error::source(&lm).is_none());
    }
}
