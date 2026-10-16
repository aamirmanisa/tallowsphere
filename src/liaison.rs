//! Logged cross-cell liaison handoffs (task AGT-103 · B1.3.2, frozen
//! interface §3).
//!
//! Append-only, deterministic handoff log for traffic between cells that are
//! **not** in an ancestor↔descendant relation. The sibling module
//! `src/spawn_isolation.rs` (§2) routes those pairs as `Route::ViaLiaison`
//! (siblings, cousins, unrelated cells); this log is the *logged liaison
//! path* such a route is required to go through. There is deliberately **no
//! cross-import**: §2 documents the link, this module stands alone.
//!
//! # Documented rules
//!
//! * **Append-only**: [`LiaisonLog::record`] only ever pushes; entries are
//!   never rewritten, removed or reordered by this module —
//!   [`LiaisonLog::verify`] exists precisely to detect out-of-band tampering
//!   with the log.
//! * **Deterministic id**: `ho-<seq:04>` where `seq` is the 1-based position
//!   of the entry, so the first record is `ho-0001`. Ids do not depend on
//!   wall-clock or any caller input: replaying the same records in the same
//!   order yields the same ids. Refused records do not consume a sequence
//!   number.
//! * **Empty-field check**, in argument order: `from_cell`, then `to_cell`,
//!   then `liaison`; a value that is blank *after trimming* counts as empty
//!   ⇒ [`LiaisonError::EmptyField`] carrying the field name. Non-empty values
//!   are stored **exactly as passed** (no normalization).
//! * **Digest check**: `payload_digest` must be exactly 64 characters of
//!   lowercase hex (`[0-9a-f]`) — the content-address convention used across
//!   this workspace; anything else (uppercase, wrong length, non-hex, empty)
//!   ⇒ [`LiaisonError::BadDigest`]. The payload text itself is never stored.
//! * **Chain check**: [`LiaisonLog::verify`] requires the ids to run exactly
//!   `ho-0001, ho-0002, …` in slice order; a gap (entry removed) or a splice
//!   (forged/rewritten id, mid-log insertion) ⇒ [`LiaisonError::BadChain`].
//! * **Filter order**: [`LiaisonLog::for_cell`] / [`LiaisonLog::between`]
//!   return entries sorted by `at_ms`, ties broken by `id` (ids are unique,
//!   so the order is total and independent of insertion order).
//! * **Serde scope** (same reading as the sibling `vouch_policy` §8): only
//!   [`Handoff`], [`HandoffKind`] and [`LiaisonError`] are annotated `serde`
//!   in the frozen interface — the wire record is the individual [`Handoff`],
//!   so `LiaisonLog` itself is deliberately not. [`HandoffKind`] serializes
//!   snake_case (`"request"` / `"response"` / `"transfer"` / `"notice"`).
//!   [`LiaisonError`] derives `Serialize` but *not* `Deserialize`: an
//!   `EmptyField(&'static str)` payload cannot be deserialized into a
//!   `'static` lifetime (in-repo precedent: `vouching`, `gap_register`,
//!   `link_chain`, `decoy_flags`, `requirements`, `ingest`, `vouch_policy`).

use serde::{Deserialize, Serialize};
use std::fmt;

/// The kind of cross-cell handoff recorded in the log.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HandoffKind {
    /// A cell asks another for something (data, a decision, a run).
    Request,
    /// Answer to a prior [`HandoffKind::Request`].
    Response,
    /// One-way movement of material from one cell to another.
    Transfer,
    /// One-way announcement that expects no reply.
    Notice,
}

/// One logged handoff: `from_cell` → `to_cell`, carried by `liaison`.
///
/// This is the wire record; the payload itself is never stored — only its
/// 64-char lowercase-hex digest.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Handoff {
    /// Deterministic entry id, `ho-<seq:04>` (`ho-0001` first).
    pub id: String,
    /// Sending cell.
    pub from_cell: String,
    /// Receiving cell.
    pub to_cell: String,
    /// The liaison that carried the handoff.
    pub liaison: String,
    /// What kind of handoff this is.
    pub kind: HandoffKind,
    /// 64-char lowercase-hex content digest of the payload (payload text is
    /// never stored here).
    pub payload_digest: String,
    /// Caller-supplied timestamp (ms); never rewritten.
    pub at_ms: i64,
}

/// Append-only cross-cell handoff log — see the module docs for the rules.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LiaisonLog {
    entries: Vec<Handoff>,
}

impl LiaisonLog {
    /// An empty log (same as [`LiaisonLog::default`]).
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append one handoff and return a reference to the stored entry.
    ///
    /// Validation (module docs): blank-after-trim `from` / `to` / `liaison`
    /// ⇒ [`LiaisonError::EmptyField`] (checked in that order);
    /// `payload_digest` not exactly 64 lowercase hex chars ⇒
    /// [`LiaisonError::BadDigest`]. The id is `ho-<seq:04>` with `seq` =
    /// entry position; refused records are not appended and do not consume a
    /// sequence number.
    pub fn record(
        &mut self,
        from: &str,
        to: &str,
        liaison: &str,
        kind: HandoffKind,
        payload_digest: &str,
        at_ms: i64,
    ) -> Result<&Handoff, LiaisonError> {
        if from.trim().is_empty() {
            return Err(LiaisonError::EmptyField("from_cell"));
        }
        if to.trim().is_empty() {
            return Err(LiaisonError::EmptyField("to_cell"));
        }
        if liaison.trim().is_empty() {
            return Err(LiaisonError::EmptyField("liaison"));
        }
        if !is_digest_64(payload_digest) {
            return Err(LiaisonError::BadDigest);
        }
        let seq = self.entries.len() + 1;
        self.entries.push(Handoff {
            id: format!("ho-{seq:04}"),
            from_cell: from.to_string(),
            to_cell: to.to_string(),
            liaison: liaison.to_string(),
            kind,
            payload_digest: payload_digest.to_string(),
            at_ms,
        });
        Ok(self.entries.last().expect("entry was just pushed"))
    }

    /// Entries involving `cell` (as sender **or** receiver), sorted by
    /// `at_ms`, ties by `id`.
    pub fn for_cell(&self, cell: &str) -> Vec<&Handoff> {
        let mut out: Vec<&Handoff> = self
            .entries
            .iter()
            .filter(|h| h.from_cell == cell || h.to_cell == cell)
            .collect();
        sort_handoffs(&mut out);
        out
    }

    /// Entries exchanged between `a` and `b` in **either** direction, sorted
    /// by `at_ms`, ties by `id`.
    pub fn between(&self, a: &str, b: &str) -> Vec<&Handoff> {
        let mut out: Vec<&Handoff> = self
            .entries
            .iter()
            .filter(|h| {
                (h.from_cell == a && h.to_cell == b) || (h.from_cell == b && h.to_cell == a)
            })
            .collect();
        sort_handoffs(&mut out);
        out
    }

    /// Number of recorded handoffs.
    pub fn count(&self) -> usize {
        self.entries.len()
    }

    /// Chain integrity: ids must run exactly `ho-0001, ho-0002, …` in slice
    /// order. A gap or splice ⇒ [`LiaisonError::BadChain`].
    pub fn verify(&self) -> Result<(), LiaisonError> {
        for (i, h) in self.entries.iter().enumerate() {
            if h.id != format!("ho-{:04}", i + 1) {
                return Err(LiaisonError::BadChain);
            }
        }
        Ok(())
    }
}

/// Refusals from [`LiaisonLog::record`] / [`LiaisonLog::verify`].
///
/// `Serialize` only: [`LiaisonError::EmptyField`] carries a `&'static str`,
/// which serde cannot `Deserialize` generically (in-repo precedent, see
/// module docs). `Display` / `Error` are hand-rolled, mirroring the sibling
/// modules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum LiaisonError {
    /// A required field was blank after trimming; carries the field name.
    EmptyField(&'static str),
    /// `payload_digest` was not exactly 64 lowercase hex characters.
    BadDigest,
    /// The log's ids are not sequential from `ho-0001` (gap or splice).
    BadChain,
}

impl fmt::Display for LiaisonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LiaisonError::EmptyField(field) => write!(f, "empty required field: {field}"),
            LiaisonError::BadDigest => {
                write!(f, "payload digest must be 64 lowercase hex characters")
            }
            LiaisonError::BadChain => {
                write!(
                    f,
                    "handoff chain broken: ids must be sequential ho-0001, ho-0002, ... with no gaps"
                )
            }
        }
    }
}

impl std::error::Error for LiaisonError {}

/// `true` iff `s` is exactly 64 lowercase hex characters (`[0-9a-f]`).
fn is_digest_64(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Sorted by `at_ms`, ties by `id` (total order: ids are unique).
fn sort_handoffs(v: &mut [&Handoff]) {
    v.sort_by(|a, b| a.at_ms.cmp(&b.at_ms).then_with(|| a.id.cmp(&b.id)));
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// 64 chars of one lowercase hex digit (a format-valid digest).
    fn d(c: char) -> String {
        std::iter::repeat(c).take(64).collect()
    }

    /// `n` recorded a→b handoffs: liaison "lia", Request, digest 'a',
    /// at_ms = 1000 + i.
    fn seeded(n: usize) -> LiaisonLog {
        let mut log = LiaisonLog::new();
        for i in 0..n {
            log.record(
                "cell-a",
                "cell-b",
                "lia",
                HandoffKind::Request,
                &d('a'),
                1000 + i as i64,
            )
            .unwrap();
        }
        log
    }

    #[test]
    fn empty_log_baseline() {
        let log = LiaisonLog::new();
        assert_eq!(log.count(), 0);
        assert!(log.for_cell("cell-a").is_empty());
        assert!(log.between("cell-a", "cell-b").is_empty());
        assert!(log.verify().is_ok());
        assert_eq!(log, LiaisonLog::default());
    }

    #[test]
    fn record_roundtrip_and_fields_echoed() {
        let mut log = LiaisonLog::new();
        let h = log
            .record("cell-a", "cell-b", "lia-7", HandoffKind::Transfer, &d('9'), 42)
            .unwrap();
        assert_eq!(h.id, "ho-0001");
        assert_eq!(h.from_cell, "cell-a");
        assert_eq!(h.to_cell, "cell-b");
        assert_eq!(h.liaison, "lia-7");
        assert_eq!(h.kind, HandoffKind::Transfer);
        assert_eq!(h.payload_digest, d('9'));
        assert_eq!(h.at_ms, 42);
        assert_eq!(log.count(), 1);
        // The returned reference is the freshly appended (last) entry.
        assert_eq!(log.entries.last().unwrap().id, "ho-0001");
        // Non-empty values are stored exactly as passed (no normalization).
        let h2 = log
            .record("  padded  ", "cell-b", "lia", HandoffKind::Notice, &d('0'), 0)
            .unwrap();
        assert_eq!(h2.from_cell, "  padded  ");
        assert_eq!(h2.id, "ho-0002");
    }

    #[test]
    fn record_rejects_empty_fields_in_argument_order() {
        let mut log = LiaisonLog::new();
        // `from` is checked first even when all three are blank.
        assert_eq!(
            log.record("", "", "", HandoffKind::Request, &d('a'), 0),
            Err(LiaisonError::EmptyField("from_cell"))
        );
        assert_eq!(
            log.record("cell-a", "", "", HandoffKind::Request, &d('a'), 0),
            Err(LiaisonError::EmptyField("to_cell"))
        );
        assert_eq!(
            log.record("cell-a", "cell-b", "", HandoffKind::Request, &d('a'), 0),
            Err(LiaisonError::EmptyField("liaison"))
        );
        // Refusals are not recorded (and burn no sequence number).
        assert_eq!(log.count(), 0);
        assert!(log.verify().is_ok());
        assert_eq!(
            log.record("cell-a", "cell-b", "lia", HandoffKind::Request, &d('a'), 0)
                .unwrap()
                .id,
            "ho-0001"
        );
    }

    #[test]
    fn record_rejects_whitespace_only_fields() {
        let mut log = LiaisonLog::new();
        assert_eq!(
            log.record("   ", "cell-b", "lia", HandoffKind::Request, &d('a'), 1),
            Err(LiaisonError::EmptyField("from_cell"))
        );
        assert_eq!(
            log.record("cell-a", "\t\n", "lia", HandoffKind::Request, &d('a'), 1),
            Err(LiaisonError::EmptyField("to_cell"))
        );
        assert_eq!(
            log.record("cell-a", "cell-b", " ", HandoffKind::Request, &d('a'), 1),
            Err(LiaisonError::EmptyField("liaison"))
        );
        assert_eq!(log.count(), 0);
    }

    #[test]
    fn record_rejects_bad_digest_formats() {
        let mut log = LiaisonLog::new();
        let ok = "0123456789abcdef".repeat(4); // 64 lowercase hex
        assert_eq!(ok.len(), 64);
        assert!(
            log.record("a", "b", "l", HandoffKind::Request, &ok, 0)
                .is_ok()
        );

        let upper = ok.to_uppercase();
        let short = &ok[..63];
        let long = format!("{ok}0");
        let non_hex = format!("{}g", &ok[..63]);
        for bad in [upper.as_str(), short, long.as_str(), non_hex.as_str(), ""] {
            assert_eq!(
                log.record("a", "b", "l", HandoffKind::Request, bad, 0),
                Err(LiaisonError::BadDigest),
                "digest should be rejected: {bad:?}"
            );
        }
        assert_eq!(log.count(), 1, "only the valid record landed");
        // Failed digests burn no sequence number: next id is still ho-0002.
        assert_eq!(
            log.record("a", "b", "l", HandoffKind::Request, &d('f'), 0)
                .unwrap()
                .id,
            "ho-0002"
        );
        assert!(log.verify().is_ok());
    }

    #[test]
    fn id_sequence_and_verify_ok() {
        let log = seeded(3);
        let ids: Vec<&str> = log.entries.iter().map(|h| h.id.as_str()).collect();
        assert_eq!(ids, ["ho-0001", "ho-0002", "ho-0003"]);
        assert!(log.verify().is_ok());
        assert_eq!(log.count(), 3);
    }

    #[test]
    fn verify_catches_gap() {
        let mut log = seeded(3);
        assert!(log.verify().is_ok());
        log.entries.remove(1); // ids now ho-0001, ho-0003 — a gap
        assert_eq!(log.verify(), Err(LiaisonError::BadChain));
    }

    #[test]
    fn verify_catches_splice() {
        // (a) forged entry inserted mid-log (id out of position).
        let mut log = seeded(2);
        let forged = Handoff {
            id: "ho-0003".to_string(),
            from_cell: "cell-x".to_string(),
            to_cell: "cell-y".to_string(),
            liaison: "lia".to_string(),
            kind: HandoffKind::Notice,
            payload_digest: d('f'),
            at_ms: 5,
        };
        log.entries.insert(1, forged);
        assert_eq!(log.verify(), Err(LiaisonError::BadChain));

        // (b) id rewritten on an otherwise intact log.
        let mut log = seeded(3);
        log.entries[2].id = "ho-0009".to_string();
        assert_eq!(log.verify(), Err(LiaisonError::BadChain));

        // (c) leading entry replaced (the chain must start at ho-0001).
        let mut log = seeded(1);
        log.entries[0].id = "ho-0002".to_string();
        assert_eq!(log.verify(), Err(LiaisonError::BadChain));
    }

    #[test]
    fn for_cell_sorted_by_at_ms_then_id() {
        let mut log = LiaisonLog::new();
        log.record("cell-a", "cell-b", "lia", HandoffKind::Request, &d('a'), 300)
            .unwrap(); // ho-0001
        log.record("cell-b", "cell-a", "lia", HandoffKind::Response, &d('b'), 100)
            .unwrap(); // ho-0002
        log.record("cell-c", "cell-a", "lia", HandoffKind::Transfer, &d('c'), 200)
            .unwrap(); // ho-0003
        log.record("cell-a", "cell-b", "lia", HandoffKind::Notice, &d('d'), 100)
            .unwrap(); // ho-0004

        let ids = |v: Vec<&Handoff>| -> Vec<String> {
            v.into_iter().map(|h| h.id.clone()).collect()
        };

        // from OR to; sorted at_ms, ties by id (ho-0002 before ho-0004 @100).
        assert_eq!(
            ids(log.for_cell("cell-a")),
            ["ho-0002", "ho-0004", "ho-0003", "ho-0001"]
        );
        assert_eq!(ids(log.for_cell("cell-c")), ["ho-0003"]);
        assert!(log.for_cell("cell-z").is_empty());
    }

    #[test]
    fn between_either_direction_sorted() {
        let mut log = LiaisonLog::new();
        log.record("cell-a", "cell-b", "lia", HandoffKind::Request, &d('a'), 300)
            .unwrap(); // ho-0001
        log.record("cell-b", "cell-a", "lia", HandoffKind::Response, &d('b'), 100)
            .unwrap(); // ho-0002
        log.record("cell-c", "cell-a", "lia", HandoffKind::Transfer, &d('c'), 200)
            .unwrap(); // ho-0003 — not a↔b
        log.record("cell-a", "cell-b", "lia", HandoffKind::Notice, &d('d'), 100)
            .unwrap(); // ho-0004

        let fwd: Vec<String> = log
            .between("cell-a", "cell-b")
            .into_iter()
            .map(|h| h.id.clone())
            .collect();
        assert_eq!(fwd, ["ho-0002", "ho-0004", "ho-0001"]);
        // Direction-agnostic: (b, a) gives the same result.
        let rev: Vec<String> = log
            .between("cell-b", "cell-a")
            .into_iter()
            .map(|h| h.id.clone())
            .collect();
        assert_eq!(rev, fwd);
        // Unrelated / same-cell pairs: empty.
        assert!(log.between("cell-b", "cell-c").is_empty());
        assert!(log.between("cell-a", "cell-a").is_empty());
    }

    #[test]
    fn serde_handoff_roundtrip_and_field_names() {
        let mut log = LiaisonLog::new();
        log.record("cell-a", "cell-b", "lia-1", HandoffKind::Transfer, &d('c'), 7)
            .unwrap();
        let h = &log.entries[0];
        let json = serde_json::to_string(h).unwrap();
        let back: Handoff = serde_json::from_str(&json).unwrap();
        assert_eq!(&back, h);

        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["id"], serde_json::json!("ho-0001"));
        assert_eq!(v["from_cell"], serde_json::json!("cell-a"));
        assert_eq!(v["to_cell"], serde_json::json!("cell-b"));
        assert_eq!(v["liaison"], serde_json::json!("lia-1"));
        assert_eq!(v["kind"], serde_json::json!("transfer"));
        assert_eq!(v["payload_digest"], serde_json::json!(d('c')));
        assert_eq!(v["at_ms"], serde_json::json!(7));
    }

    #[test]
    fn handoff_kind_serde_is_snake_case() {
        let cases = [
            (HandoffKind::Request, "request"),
            (HandoffKind::Response, "response"),
            (HandoffKind::Transfer, "transfer"),
            (HandoffKind::Notice, "notice"),
        ];
        for (kind, name) in cases {
            assert_eq!(serde_json::to_value(kind).unwrap(), serde_json::json!(name));
            let back: HandoffKind = serde_json::from_value(serde_json::json!(name)).unwrap();
            assert_eq!(back, kind);
        }
    }

    #[test]
    fn liaison_error_serialize_and_display() {
        assert_eq!(
            LiaisonError::EmptyField("from_cell").to_string(),
            "empty required field: from_cell"
        );
        assert_eq!(
            LiaisonError::BadDigest.to_string(),
            "payload digest must be 64 lowercase hex characters"
        );
        assert_eq!(
            LiaisonError::BadChain.to_string(),
            "handoff chain broken: ids must be sequential ho-0001, ho-0002, ... with no gaps"
        );
        // Wire form (Serialize-only; Deserialize is impossible for
        // EmptyField(&'static str) — in-repo precedent, see module docs).
        assert_eq!(
            serde_json::to_value(LiaisonError::EmptyField("to_cell")).unwrap(),
            serde_json::json!({"EmptyField": "to_cell"})
        );
        assert_eq!(
            serde_json::to_value(LiaisonError::BadDigest).unwrap(),
            serde_json::json!("BadDigest")
        );
        assert_eq!(
            serde_json::to_value(LiaisonError::BadChain).unwrap(),
            serde_json::json!("BadChain")
        );
        // std::error::Error is implemented.
        let dyn_err: &dyn std::error::Error = &LiaisonError::BadDigest;
        assert_eq!(
            dyn_err.to_string(),
            "payload digest must be 64 lowercase hex characters"
        );
    }

    #[test]
    fn determinism_replay_identical() {
        fn build() -> LiaisonLog {
            let mut log = LiaisonLog::new();
            for (i, kind) in [
                HandoffKind::Request,
                HandoffKind::Response,
                HandoffKind::Notice,
            ]
            .into_iter()
            .enumerate()
            {
                log.record("cell-a", "cell-b", "lia", kind, &d('e'), 500 - i as i64)
                    .unwrap();
            }
            log
        }
        let a = build();
        let b = build();
        assert_eq!(a.entries, b.entries);
        assert_eq!(
            serde_json::to_string(&a.entries).unwrap(),
            serde_json::to_string(&b.entries).unwrap()
        );
        assert!(a.verify().is_ok() && b.verify().is_ok());
    }
}
