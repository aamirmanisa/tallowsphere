//! Ledger event envelope — canonical, hash-chained events for the agent ledger.
//!
//! Task A1.1.1 (frozen interface §1, `artifacts/.../impl/A1_INTERFACES.md`).
//! Every ledger entry is an [`EventEnvelope`] whose `hash` commits to all of
//! its other fields plus the previous envelope's hash, forming a tamper-evident
//! chain: editing any field of any record is detectable by recomputation.
//!
//! ## Hashing rule (frozen)
//! ```text
//! canonical_bytes(ev) = canonical JSON object of every field EXCEPT `hash`
//!                       — object keys in lexicographic order, no whitespace,
//!                       payload re-canonicalized when it is valid JSON
//! compute_hash(prev_hash, canonical)
//!                     = hex( sha256( prev_hash_utf8 || 0x1F || canonical ) )
//! ```
//! `0x1F` (ASCII unit separator) is a domain separator so splices of
//! `prev_hash` and canonical bytes can never be confused across the boundary.
//! `prev_hash == "GENESIS"` marks the first envelope of a chain.
//!
//! Design notes: hashing never fails — a payload that is not valid JSON is
//! embedded verbatim as a JSON string (see [`canonical_bytes`]). The hashing
//! preimage is intentionally independent of `serde_json`'s map feature flags
//! (`preserve_order`): keys are always sorted by this module's own canonical
//! writer, so hashes are byte-identical across feature-unification outcomes.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Sentinel `prev_hash` for the first envelope of a chain.
#[allow(dead_code)]
pub const GENESIS: &str = "GENESIS";

/// A single hash-chained ledger event.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EventEnvelope {
    /// uuid v4
    pub id: String,
    /// unix ms
    pub ts_ms: i64,
    /// e.g. "agent:collector-1" | "parent" | "user"
    pub actor: String,
    /// investigation/run grouping
    pub run_id: String,
    pub kind: EventKind,
    /// canonical JSON
    pub payload: String,
    /// previous envelope hash, or "GENESIS" for the first
    pub prev_hash: String,
    /// sha256 hex over canonical bytes of all fields EXCEPT hash
    pub hash: String,
}

/// Event taxonomy — what happened in the investigation pipeline.
#[allow(dead_code)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EventKind {
    Plan,
    Fetch,
    Parse,
    Graph,
    Grade,
    Artifact,
    AgentStep,
    Verdict,
}

impl EventKind {
    /// Stable lowercase wire name recorded in the hashing preimage.
    ///
    /// These strings are part of every envelope hash — never rename without a
    /// versioned migration of existing ledgers (see spec, compat notes).
    #[allow(dead_code)]
    pub fn as_str(&self) -> &'static str {
        match self {
            EventKind::Plan => "plan",
            EventKind::Fetch => "fetch",
            EventKind::Parse => "parse",
            EventKind::Graph => "graph",
            EventKind::Grade => "grade",
            EventKind::Artifact => "artifact",
            EventKind::AgentStep => "agent_step",
            EventKind::Verdict => "verdict",
        }
    }
}

/// Deterministic hashing preimage: canonical JSON of every envelope field
/// EXCEPT `hash`.
///
/// Guarantees (all covered by tests):
/// - stable field order — object keys sorted lexicographically, recursively;
/// - no insignificant whitespace;
/// - payloads that differ only in key order canonicalize identically;
/// - total — a payload that does not parse as JSON is embedded verbatim as a
///   JSON string, so hashing never fails on malformed input.
#[allow(dead_code)]
pub fn canonical_bytes(ev: &EventEnvelope) -> Vec<u8> {
    let payload = match serde_json::from_str::<Value>(&ev.payload) {
        Ok(v) => v,
        // Not JSON: embed the raw text as a JSON string. Deterministic and
        // unambiguous (the string is quoted/escaped by the canonical writer).
        Err(_) => Value::String(ev.payload.clone()),
    };
    let mut obj = serde_json::Map::new();
    obj.insert("actor".to_string(), Value::String(ev.actor.clone()));
    obj.insert("id".to_string(), Value::String(ev.id.clone()));
    obj.insert(
        "kind".to_string(),
        Value::String(ev.kind.as_str().to_string()),
    );
    obj.insert("payload".to_string(), payload);
    obj.insert("prev_hash".to_string(), Value::String(ev.prev_hash.clone()));
    obj.insert("run_id".to_string(), Value::String(ev.run_id.clone()));
    obj.insert(
        "ts_ms".to_string(),
        Value::Number(serde_json::Number::from(ev.ts_ms)),
    );
    let mut out = String::new();
    write_canonical(&Value::Object(obj), &mut out);
    out.into_bytes()
}

/// `sha256(prev_hash || 0x1F || canonical)`, lowercase hex.
///
/// `prev_hash` is hashed as its UTF-8 bytes; callers pass `"GENESIS"` for the
/// first envelope (or the previous envelope's `hash` field otherwise).
#[allow(dead_code)]
pub fn compute_hash(prev_hash: &str, canonical: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(prev_hash.as_bytes());
    hasher.update([0x1F_u8]);
    hasher.update(canonical);
    to_hex(&hasher.finalize())
}

/// Build the next envelope in a chain: fills id/ts, normalizes the payload to
/// canonical JSON (when parseable), links `prev_hash` (or `GENESIS` when
/// `prev` is `None`), and seals `hash`.
#[allow(dead_code)]
pub fn chain_next(
    prev: Option<&EventEnvelope>,
    kind: EventKind,
    actor: &str,
    run_id: &str,
    payload_json: &str,
) -> EventEnvelope {
    let prev_hash = prev
        .map(|e| e.hash.clone())
        .unwrap_or_else(|| GENESIS.to_string());
    let mut ev = EventEnvelope {
        id: uuid::Uuid::new_v4().to_string(),
        ts_ms: now_ms(),
        actor: actor.to_string(),
        run_id: run_id.to_string(),
        kind,
        payload: canonical_payload(payload_json),
        prev_hash,
        hash: String::new(),
    };
    let canonical = canonical_bytes(&ev);
    ev.hash = compute_hash(&ev.prev_hash, &canonical);
    ev
}

// ── internal helpers ────────────────────────────────────────────────────────

/// Normalize a payload string to canonical JSON when it parses; keep it
/// verbatim otherwise. Idempotent: canonicalizing canonical input is a no-op.
fn canonical_payload(payload_json: &str) -> String {
    match serde_json::from_str::<Value>(payload_json) {
        Ok(v) => {
            let mut s = String::new();
            write_canonical(&v, &mut s);
            s
        }
        Err(_) => payload_json.to_string(),
    }
}

/// Canonical JSON writer: no insignificant whitespace, object keys sorted
/// lexicographically (recursively), strings escaped via `serde_json`'s
/// serializer. This is the single source of ordering for [`canonical_bytes`].
fn write_canonical(v: &Value, out: &mut String) {
    match v {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(n) => out.push_str(&n.to_string()),
        Value::String(s) => {
            // Serializing a Rust string can never fail (it is always UTF-8).
            match serde_json::to_string(s) {
                Ok(escaped) => out.push_str(&escaped),
                Err(_) => out.push_str("\"\""),
            }
        }
        Value::Array(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                write_canonical(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            for (i, k) in keys.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                match serde_json::to_string(k.as_str()) {
                    Ok(escaped) => out.push_str(&escaped),
                    Err(_) => out.push_str("\"\""),
                }
                out.push(':');
                write_canonical(&map[k.as_str()], out);
            }
            out.push('}');
        }
    }
}

/// Current unix time in milliseconds (0 if the clock is before the epoch).
fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Lowercase hex encoding (local because the `hex` crate is not a dependency).
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0x0F) as usize] as char);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed-field envelope so hashes are comparable across constructions.
    fn fixed_envelope(payload: &str) -> EventEnvelope {
        let mut ev = EventEnvelope {
            id: "00000000-0000-4000-8000-000000000001".to_string(),
            ts_ms: 1_700_000_000_000,
            actor: "agent:collector-1".to_string(),
            run_id: "run-42".to_string(),
            kind: EventKind::Fetch,
            payload: payload.to_string(),
            prev_hash: GENESIS.to_string(),
            hash: String::new(),
        };
        let canonical = canonical_bytes(&ev);
        ev.hash = compute_hash(&ev.prev_hash, &canonical);
        ev
    }

    fn recompute(ev: &EventEnvelope) -> String {
        compute_hash(&ev.prev_hash, &canonical_bytes(ev))
    }

    #[test]
    fn hash_stability_same_envelope_same_hash() {
        let ev = fixed_envelope(r#"{"url":"https://example.com","status":200}"#);
        // Repeat calls are byte-identical.
        assert_eq!(canonical_bytes(&ev), canonical_bytes(&ev));
        assert_eq!(recompute(&ev), ev.hash);
        assert_eq!(compute_hash(&ev.prev_hash, &canonical_bytes(&ev)), ev.hash);
        // Two envelopes with identical fields hash identically.
        let ev2 = fixed_envelope(r#"{"url":"https://example.com","status":200}"#);
        assert_eq!(ev2.hash, ev.hash);
        // Hash shape: 64 lowercase hex chars.
        assert_eq!(ev.hash.len(), 64);
        assert!(ev.hash.bytes().all(|b| b.is_ascii_hexdigit()));
        assert_eq!(ev.hash, ev.hash.to_lowercase());
    }

    #[test]
    fn genesis_marker_and_link_chaining() {
        let first = chain_next(
            None,
            EventKind::Plan,
            "parent",
            "run-1",
            r#"{"steps":["fetch","parse"]}"#,
        );
        assert_eq!(first.prev_hash, "GENESIS");
        assert_eq!(first.prev_hash, GENESIS);
        assert!(uuid::Uuid::parse_str(&first.id).is_ok(), "id must be a uuid");
        assert_eq!(first.hash, recompute(&first));

        let second = chain_next(
            Some(&first),
            EventKind::Fetch,
            "agent:collector-1",
            "run-1",
            r#"{"url":"https://example.com"}"#,
        );
        assert_eq!(second.prev_hash, first.hash);
        assert_ne!(second.id, first.id, "ids are uuid v4, fresh per call");
        // Both links verify by recomputation.
        assert_eq!(recompute(&first), first.hash);
        assert_eq!(recompute(&second), second.hash);
    }

    #[test]
    fn tamper_flip_byte_detected() {
        let ev = fixed_envelope(r#"{"note":"alpha","n":1}"#);

        // (a) raw byte flip in the canonical preimage.
        let mut canonical = canonical_bytes(&ev);
        let last = canonical.len() - 1;
        canonical[last] ^= 0x01;
        assert_ne!(
            compute_hash(&ev.prev_hash, &canonical),
            ev.hash,
            "flipping one preimage byte must change the hash"
        );

        // (b) single-byte edit inside the payload, re-derived through
        // canonical_bytes: 'alpha' -> 'blpha'.
        let mut tampered = ev.clone();
        let pos = tampered.payload.find("alpha").unwrap();
        tampered.payload.replace_range(pos..pos + 1, "b");
        assert_ne!(tampered.payload, ev.payload);
        assert_ne!(recompute(&tampered), ev.hash);
        // The stored link itself is unchanged — only the hash catches it.
        assert_eq!(tampered.prev_hash, ev.prev_hash);
    }

    #[test]
    fn canonical_key_order_determinism() {
        // Top-level key order does not affect canonical bytes or hash.
        let a = fixed_envelope(r#"{"beta":2,"alpha":1}"#);
        let b = fixed_envelope(r#"{"alpha":1,"beta":2}"#);
        assert_eq!(canonical_bytes(&a), canonical_bytes(&b));
        assert_eq!(a.hash, b.hash);

        // Nested objects and arrays-of-objects are also order-independent.
        let n1 = fixed_envelope(r#"{"outer":{"z":1,"a":[{"y":2,"x":1}]}}"#);
        let n2 = fixed_envelope(r#"{"outer":{"a":[{"x":1,"y":2}],"z":1}}"#);
        assert_eq!(canonical_bytes(&n1), canonical_bytes(&n2));
        assert_eq!(n1.hash, n2.hash);

        // Array order IS significant (it is data, not a map).
        let arr1 = fixed_envelope(r#"{"xs":[1,2]}"#);
        let arr2 = fixed_envelope(r#"{"xs":[2,1]}"#);
        assert_ne!(arr1.hash, arr2.hash);

        // chain_next stores payload already canonicalized.
        let ev = chain_next(None, EventKind::Grade, "parent", "r", r#"{"b":2,"a":1}"#);
        assert_eq!(ev.payload, r#"{"a":1,"b":2}"#);
        assert_eq!(ev.payload, canonical_payload(&ev.payload), "idempotent");
    }

    #[test]
    fn every_field_except_hash_is_committed() {
        let base = fixed_envelope(r#"{"k":"v"}"#);
        let base_hash = base.hash.clone();

        let mut m = base.clone();
        m.actor = "user".to_string();
        assert_ne!(recompute(&m), base_hash, "actor must be committed");

        let mut m = base.clone();
        m.run_id = "other-run".to_string();
        assert_ne!(recompute(&m), base_hash, "run_id must be committed");

        let mut m = base.clone();
        m.kind = EventKind::Plan;
        assert_ne!(recompute(&m), base_hash, "kind must be committed");

        let mut m = base.clone();
        m.ts_ms += 1;
        assert_ne!(recompute(&m), base_hash, "ts_ms must be committed");

        let mut m = base.clone();
        m.id = "00000000-0000-4000-8000-000000000002".to_string();
        assert_ne!(recompute(&m), base_hash, "id must be committed");

        let mut m = base.clone();
        m.prev_hash = "f".repeat(64);
        assert_ne!(recompute(&m), base_hash, "prev_hash must be committed");
    }

    #[test]
    fn hash_field_is_not_in_the_preimage() {
        let ev = fixed_envelope(r#"{"k":"v"}"#);
        let canonical = canonical_bytes(&ev);
        let mut m = ev.clone();
        m.hash = "deadbeef".to_string();
        assert_eq!(
            canonical_bytes(&m),
            canonical,
            "the hash field must be excluded from its own preimage"
        );
    }

    #[test]
    fn kind_as_str_is_stable() {
        assert_eq!(EventKind::Plan.as_str(), "plan");
        assert_eq!(EventKind::Fetch.as_str(), "fetch");
        assert_eq!(EventKind::Parse.as_str(), "parse");
        assert_eq!(EventKind::Graph.as_str(), "graph");
        assert_eq!(EventKind::Grade.as_str(), "grade");
        assert_eq!(EventKind::Artifact.as_str(), "artifact");
        assert_eq!(EventKind::AgentStep.as_str(), "agent_step");
        assert_eq!(EventKind::Verdict.as_str(), "verdict");
    }
}
