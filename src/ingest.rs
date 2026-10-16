//! Ingest — source-vs-item assessment separation at ingest time
//! (task A3.1.1 adoption, AGT-94; frozen interface §4).
//!
//! # The separation discipline
//! Every collected item enters the pipeline as one [`IngestRecord`] carrying
//! **two structurally distinct assessments**, both always present:
//!
//! * [`SourceAssessment`] — the SOURCE-level judgment: *which* source the
//!   item was collected from, how this ingest moves our view of that
//!   source's reliability (`reliability_delta`, a signed adjustment stored
//!   verbatim), and why.
//! * [`ItemAssessment`] — the ITEM-level judgment: the claim's typed class
//!   ([`crate::claim_typing::type_claim`] over the payload), the item's own
//!   Admiralty credibility ([`crate::source_registry::ItemCredibility`],
//!   digit `1`–`6`), and why.
//!
//! The two axes are graded from different evidence and on different scales,
//! and downstream regrade/corroboration flows must be able to revisit one
//! without rewriting the other. Fusing them into a single "grade + note"
//! blob at capture is exactly the failure mode this separation exists to
//! prevent; here the split is enforced structurally: no field carries both
//! judgments, and [`assess`] has no code path that produces one assessment
//! without the other.
//!
//! # Purity and determinism
//! [`assess`] is pure: no clock (the caller supplies `now_ms`, stored as
//! [`IngestRecord::ingest_ms`] verbatim), no IO, no randomness. Identical
//! inputs produce identical records (pinned by test), keeping ingest
//! replayable.
//!
//! # Refusals
//! `source_id` and `payload` must be non-blank after trimming (the same
//! convention as `vouch_policy`'s `EmptyField` refusals). `source_id` is
//! checked **first**, so a blank source never reaches payload hashing.
//! `note` may be empty — the assessments' `note` fields are still present.
//!
//! # Content address
//! `item_sha256` is the sha256 (lowercase hex, exactly 64 chars) of the
//! payload **exactly as passed** — no trimming or other normalization — so
//! the record's item identity lines up byte-for-byte with what a raw store
//! addresses.
//!
//! # Persistence mapping ([`persist`])
//! [`crate::raw_store::RawStore`] exposes a content-addressed, write-once
//! byte-append surface ([`crate::raw_store::RawStore::put_bytes`], which
//! needs only `&self`). The record is therefore stored as its canonical
//! JSON ([`to_store_json`]) and the store derives that JSON's own content
//! address. The two hashes are deliberately different things: the store
//! address covers the *record*, while `item_sha256` covers the original
//! *payload* (which the pipeline may store separately under its own
//! address). The frozen `&mut` receiver is accepted exactly as specified
//! and auto-reborrowed into `put_bytes`; the write is idempotent by content
//! addressing. Store failures surface as [`IngestError::Store`] carrying
//! the underlying error's `Display` text.
//!
//! # Serde
//! [`IngestRecord`] and both assessment structs round-trip through serde in
//! both directions. [`IngestError`] derives **`Serialize` only**:
//! [`IngestError::EmptyField`] carries `&'static str`, which cannot be
//! `Deserialize`d into an arbitrary caller lifetime — the same precedent as
//! `compartment::CompartmentError`, `vouch_policy::VouchPolicyError`, and
//! `decoy_flags::DecoyError`. Its wire form is pinned by test:
//! `{"EmptyField":"…"}` / `{"Store":"…"}`.
//!
//! # Wiring
//! No call site is wired here; the parent integrates the module (A3.1.1).


use std::fmt;

use serde::{Deserialize, Serialize};

// ── Assessments ─────────────────────────────────────────────────────────────

/// SOURCE-level judgment recorded at ingest.
///
/// Distinct from [`ItemAssessment`] on purpose (the §4 separation
/// invariant): this struct describes the *source*, never the item's content.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceAssessment {
    /// Registry id of the source the item was collected from.
    pub source_id: String,
    /// Signed adjustment to the source's reliability view as judged by this
    /// ingest. Stored verbatim (no clamping, no scale interpretation here);
    /// by convention positive moves the source's Admiralty grade one step
    /// more reliable. Regrade flows own the interpretation.
    pub reliability_delta: i8,
    /// Free-text rationale for the source-level judgment.
    pub note: String,
}

/// ITEM-level judgment recorded at ingest.
///
/// Distinct from [`SourceAssessment`] on purpose: claim class and
/// credibility describe *this item*, not the source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemAssessment {
    /// Typed claim class of the payload, via
    /// [`crate::claim_typing::type_claim`].
    pub claim: crate::claim_typing::ClaimType,
    /// The item's own Admiralty credibility digit (`1`–`6`).
    pub credibility: crate::source_registry::ItemCredibility,
    /// Free-text rationale for the item-level judgment.
    pub note: String,
}

/// One ingest event: the item's content address plus BOTH assessments.
///
/// Both assessment fields are mandatory (`IngestRecord` has no constructor
/// that omits either one), which is the structural half of the separation
/// invariant — source and item judgments travel together but never fused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IngestRecord {
    /// Registry id of the source the item was collected from.
    pub source_id: String,
    /// sha256 of the payload bytes (lowercase hex, 64 chars).
    pub item_sha256: String,
    /// SOURCE-level judgment.
    pub source_assessment: SourceAssessment,
    /// ITEM-level judgment.
    pub item_assessment: ItemAssessment,
    /// Epoch ms of the ingest, caller-supplied (pure function).
    pub ingest_ms: i64,
}

// ── Ingest ──────────────────────────────────────────────────────────────────

/// Assess one collected item at ingest: both judgments, one record.
///
/// * Blank (`trim`-empty) `source_id` → [`IngestError::EmptyField`]`("source_id")`,
///   checked before the payload.
/// * Blank (`trim`-empty) `payload` → [`IngestError::EmptyField`]`("payload")`.
/// * Otherwise: `claim` is [`crate::claim_typing::type_claim`]`(payload)`,
///   `item_sha256` is the sha256 of the payload exactly as passed, and both
///   [`SourceAssessment`] and [`ItemAssessment`] are constructed — always,
///   as distinct structs. The single caller-supplied `note` is recorded
///   verbatim on **both** sides (each struct mandates a `note`); callers
///   wanting distinct rationales per side can build the structs directly.
///
/// Pure and deterministic: no clock, no IO, no randomness.
pub fn assess(
    source_id: &str,
    payload: &str,
    delta: i8,
    credibility: crate::source_registry::ItemCredibility,
    note: &str,
    now_ms: i64,
) -> Result<IngestRecord, IngestError> {
    if source_id.trim().is_empty() {
        return Err(IngestError::EmptyField("source_id"));
    }
    if payload.trim().is_empty() {
        return Err(IngestError::EmptyField("payload"));
    }
    Ok(IngestRecord {
        source_id: source_id.to_string(),
        item_sha256: sha256_hex(payload.as_bytes()),
        source_assessment: SourceAssessment {
            source_id: source_id.to_string(),
            reliability_delta: delta,
            note: note.to_string(),
        },
        item_assessment: ItemAssessment {
            claim: crate::claim_typing::type_claim(payload),
            credibility,
            note: note.to_string(),
        },
        ingest_ms: now_ms,
    })
}

/// Canonical store payload for `rec`: the record serialized as compact JSON
/// (field order as declared in [`IngestRecord`], so the encoding is stable
/// for a given record). This is the exact byte payload [`persist`] appends.
///
/// Infallible in practice: every field of [`IngestRecord`] has a plain
/// string/number/unit-enum JSON form.
pub fn to_store_json(rec: &IngestRecord) -> String {
    serde_json::to_string(rec).expect("IngestRecord serialization cannot fail")
}

/// Persist `rec` into the raw store, mapping store errors to
/// [`IngestError::Store`].
///
/// Mapping (documented per §4): the stored object is [`to_store_json`]`(rec)`
/// and its content address is that JSON's sha256 — *not* `rec.item_sha256`,
/// which addresses the original payload (the pipeline may store the payload
/// separately under its own address). The frozen `&mut` receiver is accepted
/// as specified; `put_bytes` takes `&self` and is write-once/idempotent, so
/// re-persisting the same record re-verifies the existing object.
pub fn persist(
    store: &mut crate::raw_store::RawStore,
    rec: &IngestRecord,
) -> Result<(), IngestError> {
    let json = to_store_json(rec);
    store
        .put_bytes(json.as_bytes())
        .map_err(|e| IngestError::Store(e.to_string()))?;
    Ok(())
}

/// Pre-persist review gate for an intake batch (B5.5.3 adoption — the
/// large-intake CI review checkpoint wired into the ingest batch gate).
///
/// Fail-closed: builds the [`crate::intake_review::BatchIntake`] descriptor
/// and defers every rule to [`crate::intake_review::gate_check`] — red flags,
/// sampling rate, then canary coverage (first match wins). `batch` labels the
/// batch under review (e.g. the source scope or a run id).
pub fn gate_intake(
    batch: &str,
    items: usize,
    sampled: usize,
    flags: Vec<u16>,
    canary_missing: usize,
    min_rate_pct: u8,
    canary_required: bool,
) -> Result<(), crate::intake_review::GateError> {
    let intake = crate::intake_review::BatchIntake {
        batch: batch.to_string(),
        items,
        sampled,
        flags,
        canary_missing,
    };
    crate::intake_review::gate_check(&intake, min_rate_pct, canary_required)
}

/// [`persist_gated`] refusal: either the review gate rejected the batch (and
/// nothing was written) or the store append failed after the gate passed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum GatedIngestError {
    /// The review gate refused the batch — fail-closed, no write performed.
    Gate(crate::intake_review::GateError),
    /// The gate passed and the store append failed.
    Ingest(IngestError),
}

impl fmt::Display for GatedIngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GatedIngestError::Gate(e) => write!(f, "intake review gate: {e}"),
            GatedIngestError::Ingest(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for GatedIngestError {}

/// Gate first, then persist — the adoptable batch-gate composition.
///
/// On a gate refusal nothing reaches the store (fail-closed); on success the
/// record is appended exactly like [`persist`].
#[allow(clippy::too_many_arguments)]
pub fn persist_gated(
    store: &mut crate::raw_store::RawStore,
    rec: &IngestRecord,
    batch: &str,
    items: usize,
    sampled: usize,
    flags: Vec<u16>,
    canary_missing: usize,
    min_rate_pct: u8,
    canary_required: bool,
) -> Result<(), GatedIngestError> {
    gate_intake(
        batch,
        items,
        sampled,
        flags,
        canary_missing,
        min_rate_pct,
        canary_required,
    )
    .map_err(GatedIngestError::Gate)?;
    persist(store, rec).map_err(GatedIngestError::Ingest)
}

// ── Errors ──────────────────────────────────────────────────────────────────

/// Refusals from [`assess`] / [`persist`].
///
/// `Serialize` only (see module-level serde note); `Display` / `Error` are
/// hand-rolled, mirroring the sibling modules.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum IngestError {
    /// A required field was blank after trimming; carries the field name.
    EmptyField(&'static str),
    /// The raw store append failed; carries the underlying error's
    /// `Display` text.
    Store(String),
}

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngestError::EmptyField(field) => write!(f, "empty required field: {field}"),
            IngestError::Store(msg) => write!(f, "raw store: {msg}"),
        }
    }
}

impl std::error::Error for IngestError {}

// ── Hashing ─────────────────────────────────────────────────────────────────

/// sha256 of `bytes`, lowercase hex (64 chars). Local helper — same
/// convention as the raw store's content addresses.
fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    let digest = h.finalize();
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(64);
    for b in digest {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::claim_typing::ClaimType;
    use crate::source_registry::ItemCredibility;

    /// Unique temp root without extra dev-deps (harness-friendly).
    fn tmp_root(tag: &str) -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() * 1_000_000_000 + d.subsec_nanos() as u64)
            .unwrap_or(0);
        std::env::temp_dir().join(format!(
            "nixe_ingest_{tag}_{}_{}",
            std::process::id(),
            nanos + SEQ.fetch_add(1, Ordering::Relaxed)
        ))
    }

    #[test]
    fn separation_source_vs_item_fields_are_distinct() {
        // Direct construction with deliberately different values on each
        // side: the two assessments are independent structs, an item
        // judgment does not live inside the source judgment and vice versa.
        let source = SourceAssessment {
            source_id: "example.com".to_string(),
            reliability_delta: -2,
            note: "source honoured the last three claims".to_string(),
        };
        let item = ItemAssessment {
            claim: ClaimType::Legend,
            credibility: ItemCredibility::Doubtful,
            note: "founding narrative matches folklore markers".to_string(),
        };
        let rec = IngestRecord {
            source_id: "example.com".to_string(),
            item_sha256: sha256_hex(b"payload"),
            source_assessment: source.clone(),
            item_assessment: item.clone(),
            ingest_ms: 1_700_000_000_000,
        };
        assert_eq!(rec.source_assessment, source);
        assert_eq!(rec.item_assessment, item);
        // The judgments are carried in distinct fields with distinct values.
        assert_ne!(rec.source_assessment.note, rec.item_assessment.note);
        assert_eq!(rec.source_assessment.reliability_delta, -2);
        assert_eq!(rec.item_assessment.credibility, ItemCredibility::Doubtful);
        assert_eq!(rec.item_assessment.claim, ClaimType::Legend);
    }

    #[test]
    fn assess_returns_both_assessments_always() {
        let rec = assess(
            "example.com",
            "the charter is documented in the archive",
            -1,
            ItemCredibility::ProbablyTrue,
            "first capture from this feed",
            1_700_000_000_123,
        )
        .unwrap();
        // Both sides present, each populated with this call's inputs.
        assert_eq!(rec.source_id, "example.com");
        assert_eq!(rec.source_assessment.source_id, "example.com");
        assert_eq!(rec.source_assessment.reliability_delta, -1);
        assert_eq!(rec.item_assessment.claim, ClaimType::Documented);
        assert_eq!(rec.item_assessment.credibility, ItemCredibility::ProbablyTrue);
        // The single caller note lands on both sides verbatim.
        assert_eq!(rec.source_assessment.note, "first capture from this feed");
        assert_eq!(rec.item_assessment.note, "first capture from this feed");
        assert_eq!(rec.ingest_ms, 1_700_000_000_123);
    }

    #[test]
    fn item_sha256_is_lowercase_hex_sha256_of_payload() {
        // Known vector: sha256("abc").
        let rec = assess(
            "s",
            "abc",
            0,
            ItemCredibility::Confirmed,
            "n",
            7,
        )
        .unwrap();
        assert_eq!(
            rec.item_sha256,
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(rec.item_sha256.len(), 64);
        assert!(
            rec.item_sha256
                .bytes()
                .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')),
            "hash must be lowercase hex: {}",
            rec.item_sha256
        );
        // Payload bytes are used exactly as passed — no trimming.
        let padded = assess("s", " abc ", 0, ItemCredibility::Confirmed, "n", 7).unwrap();
        assert_eq!(padded.item_sha256, sha256_hex(b" abc "));
        assert_ne!(padded.item_sha256, rec.item_sha256);
    }

    #[test]
    fn claim_typing_is_wired_to_claim_typing_module() {
        // Pinned against the actual `claim_typing` behaviour (the §4 note
        // "a question → Question" predates the shipped ClaimType value
        // space; this workspace has no `Question` class).
        let case = |payload: &str| {
            assess("s", payload, 0, ItemCredibility::PossiblyTrue, "n", 1)
                .unwrap()
                .item_assessment
                .claim
        };
        assert_eq!(case("Is the meeting still on?"), ClaimType::Documented);
        assert_eq!(case("the company's origins are pure folklore"), ClaimType::Legend);
        assert_eq!(case("the chart was later disproven"), ClaimType::Debunked);
        assert_eq!(case("the route was reportedly changed"), ClaimType::Attributed);
        assert_eq!(
            case("the shipment is documented in the ledger"),
            ClaimType::Documented
        );
        assert_eq!(case("a contested claim"), ClaimType::Disputed);
        // Precedence: first marker class in TYPE_MARKERS order wins.
        assert_eq!(case("a debunked legend"), ClaimType::Debunked);
        // Substring quirk pinned by claim_typing: "mythology" trips "myth".
        assert_eq!(case("the founding mythology"), ClaimType::Legend);
    }

    #[test]
    fn blank_source_is_refused_first() {
        for blank in ["", "   ", "\t\n"] {
            let err = assess(blank, "payload", 0, ItemCredibility::Confirmed, "n", 1)
                .unwrap_err();
            assert_eq!(err, IngestError::EmptyField("source_id"));
        }
        // Blank source is diagnosed before a blank payload too.
        assert_eq!(
            assess("", "", 0, ItemCredibility::Confirmed, "n", 1).unwrap_err(),
            IngestError::EmptyField("source_id")
        );
    }

    #[test]
    fn blank_payload_is_refused() {
        for blank in ["", "   ", " \t \n "] {
            let err = assess("s", blank, 0, ItemCredibility::Confirmed, "n", 1).unwrap_err();
            assert_eq!(err, IngestError::EmptyField("payload"));
        }
    }

    #[test]
    fn assess_is_deterministic() {
        let a = assess(
            "example.com",
            "the shipment is documented in the ledger",
            1,
            ItemCredibility::PossiblyTrue,
            "weekly sweep",
            1_700_000_000_999,
        )
        .unwrap();
        let b = assess(
            "example.com",
            "the shipment is documented in the ledger",
            1,
            ItemCredibility::PossiblyTrue,
            "weekly sweep",
            1_700_000_000_999,
        )
        .unwrap();
        assert_eq!(a, b);
        assert_eq!(to_store_json(&a), to_store_json(&b));
    }

    #[test]
    fn ingest_record_serde_roundtrip() {
        let rec = assess(
            "example.com",
            "a contested founding myth",
            i8::MIN,
            ItemCredibility::CannotBeJudged,
            "roundtrip",
            i64::MAX,
        )
        .unwrap();
        let json = to_store_json(&rec);
        let back: IngestRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, rec);
        // Both assessments are always present in the serialized form.
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(v.get("source_assessment").is_some());
        assert!(v.get("item_assessment").is_some());
        assert_eq!(v["item_assessment"]["claim"], serde_json::json!("legend"));
        assert_eq!(
            v["item_assessment"]["credibility"],
            serde_json::json!("CannotBeJudged")
        );
        assert_eq!(v["source_assessment"]["reliability_delta"], serde_json::json!(-128));
        assert_eq!(v["ingest_ms"], serde_json::json!(i64::MAX));
    }

    #[test]
    fn ingest_error_display_and_serde() {
        // Display strings (pinned).
        assert_eq!(
            IngestError::EmptyField("source_id").to_string(),
            "empty required field: source_id"
        );
        assert_eq!(
            IngestError::Store("disk full".to_string()).to_string(),
            "raw store: disk full"
        );
        // Wire form (Serialize-only; Deserialize is impossible for
        // EmptyField(&'static str) — same precedent as sibling modules).
        assert_eq!(
            serde_json::to_value(IngestError::EmptyField("payload")).unwrap(),
            serde_json::json!({"EmptyField": "payload"})
        );
        assert_eq!(
            serde_json::to_value(IngestError::Store("boom".to_string())).unwrap(),
            serde_json::json!({"Store": "boom"})
        );
        // std::error::Error is implemented.
        let dyn_err: &dyn std::error::Error = &IngestError::EmptyField("x");
        assert_eq!(dyn_err.to_string(), "empty required field: x");
    }

    #[test]
    fn persist_stores_record_json_under_its_content_address() {
        let root = tmp_root("persist_ok");
        let mut store = crate::raw_store::RawStore::open(&root).unwrap();
        let rec = assess(
            "example.com",
            "reportedly the deal closed on Friday",
            -1,
            ItemCredibility::ProbablyTrue,
            "nightly ingest",
            1_700_000_111_000,
        )
        .unwrap();
        persist(&mut store, &rec).unwrap();

        // The stored object is the canonical record JSON, addressable by
        // its own sha256 (distinct from item_sha256, which addresses the
        // original payload).
        let json = to_store_json(&rec);
        let addr = sha256_hex(json.as_bytes());
        assert_ne!(addr, rec.item_sha256);
        assert!(store.exists(&addr));
        let stored = store.get(&addr).unwrap();
        assert_eq!(stored, json.as_bytes());
        // And it round-trips back to the same record.
        let back: IngestRecord = serde_json::from_slice(&stored).unwrap();
        assert_eq!(back, rec);
        // Re-persist is idempotent (write-once content addressing).
        persist(&mut store, &rec).unwrap();
        assert_eq!(store.get(&addr).unwrap(), json.as_bytes());

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn persist_maps_store_io_errors_to_store_variant() {
        let root = tmp_root("persist_err");
        let mut store = crate::raw_store::RawStore::open(&root).unwrap();
        let rec = assess("s", "payload", 0, ItemCredibility::Confirmed, "n", 1).unwrap();

        // Block the record's shard directory with a file: `put_bytes` must
        // fail creating `root/<ab>/<cd>`, and `persist` must surface that
        // as `IngestError::Store`.
        let json = to_store_json(&rec);
        let addr = sha256_hex(json.as_bytes());
        std::fs::write(root.join(&addr[..2]), b"file blocks shard dir").unwrap();

        let err = persist(&mut store, &rec).unwrap_err();
        assert!(
            matches!(err, IngestError::Store(_)),
            "expected Store variant, got {err:?}"
        );
        assert!(err.to_string().starts_with("raw store: "));

        let _ = std::fs::remove_dir_all(&root);
    }

    // ── B5.5.3 batch-gate adoption ──────────────────────────────────

    #[test]
    fn gate_intake_passes_clean_batch() {
        gate_intake("batch A", 100, 40, vec![], 0, 40, true).unwrap();
    }

    #[test]
    fn gate_intake_refuses_red_flags_first() {
        let err = gate_intake("batch A", 100, 40, vec![3, 7], 2, 40, true).unwrap_err();
        assert!(matches!(
            err,
            crate::intake_review::GateError::RedFlagsRaised(2)
        ));
    }

    #[test]
    fn gate_intake_refuses_under_sampled() {
        let err = gate_intake("batch A", 100, 10, vec![], 0, 40, false).unwrap_err();
        match err {
            crate::intake_review::GateError::UnderSampled { needed, got } => {
                assert_eq!(needed, 40);
                assert_eq!(got, 10);
            }
            other => panic!("expected UnderSampled, got {other:?}"),
        }
    }

    #[test]
    fn gate_intake_refuses_missing_canaries_when_required() {
        let err = gate_intake("batch A", 100, 40, vec![], 3, 40, true).unwrap_err();
        assert!(matches!(
            err,
            crate::intake_review::GateError::CanaryMissing(3)
        ));
    }

    #[test]
    fn persist_gated_refuses_before_any_write() {
        let root = tmp_root("gated_refuse");
        let mut store = crate::raw_store::RawStore::open(&root).unwrap();
        let rec = assess("s", "payload", 0, ItemCredibility::Confirmed, "n", 1).unwrap();
        let json = to_store_json(&rec);
        let addr = sha256_hex(json.as_bytes());

        let err = persist_gated(&mut store, &rec, "batch A", 100, 0, vec![9], 0, 40, false)
            .unwrap_err();
        assert!(matches!(err, GatedIngestError::Gate(_)), "got {err:?}");
        assert!(!store.exists(&addr), "fail-closed gate must not write");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn persist_gated_persists_after_passing_gate() {
        let root = tmp_root("gated_ok");
        let mut store = crate::raw_store::RawStore::open(&root).unwrap();
        let rec = assess("s", "payload", 0, ItemCredibility::Confirmed, "n", 2).unwrap();
        let json = to_store_json(&rec);
        let addr = sha256_hex(json.as_bytes());

        persist_gated(&mut store, &rec, "batch A", 10, 5, vec![], 0, 50, false).unwrap();
        assert!(store.exists(&addr), "gated persist must write on pass");

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn gated_ingest_error_display_and_serde() {
        let e = GatedIngestError::Ingest(IngestError::EmptyField("source_id"));
        assert!(e.to_string().contains("empty required field"));
        let g = GatedIngestError::Gate(crate::intake_review::GateError::CanaryMissing(1));
        assert!(g.to_string().contains("intake review gate"));
        let s = serde_json::to_string(&g).unwrap();
        assert!(
            s.contains("gate") || s.contains("Gate"),
            "serde variant: {s}"
        );
    }
}
