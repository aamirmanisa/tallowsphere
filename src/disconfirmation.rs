//! Disconfirmation protocol — competing hypotheses + falsifier registration
//! (task A4.2.2, dossier E9; interface §8).
//!
//! Wave A4 ("judgment quality") makes Tallow's analytic judgments auditable.
//! E9 is the **disconfirmation protocol**: before any high-credibility
//! commitment or dissemination, the strongest competing hypothesis must be
//! on record and a "what would change my mind" falsifier must be registered
//! as a `would_refute` edge. The method lineage is Heuer's Analysis of
//! Competing Hypotheses (seek to refute, not confirm) plus the
//! prospective-hindsight pre-mortem (Kahneman/Klein; dossier E9, `raw/06`,
//! `raw/07`, `raw/10`).
//!
//! This module is the record + guard layer only:
//!
//! * [`HypothesisRecord`] — one competing hypothesis: a stable `id`, the
//!   `statement` under test, and its [`Falsifier`] list (`would_refute`
//!   edges). Competing hypotheses are simply records that coexist as
//!   alternatives; each one's falsifiers say what evidence would kill it.
//! * [`flag_missing_falsifiers`] — the guard from the frozen interface:
//!   given a batch of records, return the ids with **zero** falsifiers.
//!   Callers (pre-mortem gate, dissemination path) refuse the write while
//!   the list is non-empty — "every high-credibility write carries a
//!   falsifier" (checklist exit criterion for wave A4).
//! * [`DisconfirmationStore`] — in-memory reference registry; `register`
//!   enforces unique write-once ids and `attach_falsifier` adds edges later
//!   (the pre-mortem flow commonly registers the competing hypothesis first
//!   and attaches its falsifier in the same review).
//!
//! # Guard semantics
//! Registration deliberately does **not** require falsifiers: the guard
//! lives at the *commit* boundary ([`flag_missing_falsifiers`], or the
//! hard-fail form [`DisconfirmationStore::require_falsifier`]) so a
//! half-formed competing hypothesis can be recorded and completed within
//! the review instead of being lost. What is forbidden is committing a
//! high-credibility product while any record still has zero falsifiers.
//!
//! # Provenance discipline
//! Falsifier attachment is **additive only** — there is no detach/remove
//! API. A falsifier is provenance: it fixes, at review time, what would
//! have refuted the hypothesis, so it cannot be quietly edited away after
//! the outcome is known. To supersede a hypothesis, register a new id; the
//! rejected alternative stays on record as a first-class competitor
//! (dossier E9: "rejected alternatives kept as first-class provenance").
//!
//! # Serde
//! Serde derive is a plain wire decoder and does not validate. Call
//! [`HypothesisRecord::validate`] / [`Falsifier::validate`] after ingesting
//! untrusted JSON. The wire form is `"would_refute": [{"statement": "..."}]`
//! (pinned by tests).


use std::collections::HashSet;

use serde::{Deserialize, Serialize};

/// One "what would change my mind" statement — the payload of a
/// `would_refute` edge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Falsifier {
    /// The observation/outcome that would refute the hypothesis. Non-empty
    /// (enforced by [`Falsifier::validate`] on attach).
    pub statement: String,
}

impl Falsifier {
    /// Build a falsifier from any statement-shaped string.
    pub fn new(statement: impl Into<String>) -> Self {
        Falsifier {
            statement: statement.into(),
        }
    }

    /// `statement` must be non-empty; an empty string is not a falsifier.
    pub fn validate(&self) -> Result<(), DiscError> {
        if self.statement.is_empty() {
            return Err(DiscError::EmptyFalsifier);
        }
        Ok(())
    }

    /// The statement, verbatim.
    pub fn statement(&self) -> &str {
        &self.statement
    }
}

impl From<&str> for Falsifier {
    fn from(s: &str) -> Self {
        Falsifier::new(s)
    }
}

impl From<String> for Falsifier {
    fn from(s: String) -> Self {
        Falsifier::new(s)
    }
}

/// One competing hypothesis as tracked by the disconfirmation protocol.
///
/// Fields are frozen by interface §8: `id`, `statement`, `would_refute`.
/// `would_refute` may be empty at registration time (see **Guard
/// semantics** in the module doc); the guard refuses *commits* while it is.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HypothesisRecord {
    /// Stable record id. Unique within a store (write-once); non-empty.
    pub id: String,
    /// The claim under test, in refutable form. Non-empty.
    pub statement: String,
    /// Registered falsifiers ("would_refute" edges): observations that
    /// would refute this hypothesis. Additive-only; no removal API.
    pub would_refute: Vec<Falsifier>,
}

impl HypothesisRecord {
    /// New record with no falsifiers yet — i.e. the state the guard flags.
    pub fn new(id: impl Into<String>, statement: impl Into<String>) -> Self {
        HypothesisRecord {
            id: id.into(),
            statement: statement.into(),
            would_refute: Vec::new(),
        }
    }

    /// Re-check all record invariants: non-empty `id`, non-empty
    /// `statement`, and every falsifier non-empty. Cheap; call it after
    /// deserializing untrusted JSON (serde does not validate on the way in).
    pub fn validate(&self) -> Result<(), DiscError> {
        if self.id.is_empty() {
            return Err(DiscError::EmptyId);
        }
        if self.statement.is_empty() {
            return Err(DiscError::EmptyStatement);
        }
        for f in &self.would_refute {
            f.validate()?;
        }
        Ok(())
    }

    /// `true` once at least one falsifier is registered — the per-record
    /// form of the wave-A4 exit criterion.
    pub fn has_falsifier(&self) -> bool {
        !self.would_refute.is_empty()
    }

    /// Attach one more falsifier (additive only; it is never removed).
    ///
    /// # Errors
    /// [`DiscError::EmptyFalsifier`] if `f.statement` is empty.
    pub fn attach(&mut self, f: Falsifier) -> Result<(), DiscError> {
        f.validate()?;
        self.would_refute.push(f);
        Ok(())
    }
}

/// Validation / registry errors for the disconfirmation protocol.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DiscError {
    /// `id` was empty.
    #[error("hypothesis id must not be empty")]
    EmptyId,
    /// `statement` was empty.
    #[error("hypothesis statement must not be empty")]
    EmptyStatement,
    /// A falsifier with an empty statement was attached; that refutes
    /// nothing, so it is refused rather than stored as a false guard pass.
    #[error("falsifier statement must not be empty (a falsifier must say what would refute)")]
    EmptyFalsifier,
    /// Second registration for an existing id (ids are write-once).
    #[error("hypothesis {0} already exists (ids are write-once)")]
    DuplicateId(String),
    /// Lookup/attach on an id that was never registered.
    #[error("hypothesis {0} is unknown (register it first)")]
    UnknownId(String),
    /// The guard fired: the hypothesis has zero falsifiers, so committing a
    /// high-credibility write that relies on it is refused.
    #[error(
        "hypothesis {0} has no registered falsifier (would_refute must not be empty \
         before a high-credibility write)"
    )]
    MissingFalsifier(String),
}

/// The frozen-interface guard: ids of `records` that carry **zero**
/// falsifiers, in first-appearance order.
///
/// Repeated ids are reported once (ids are unique by construction; dedupe is
/// defensive so a malformed batch cannot double-flag). Callers refuse the
/// high-credibility write while this list is non-empty.
pub fn flag_missing_falsifiers(records: &[HypothesisRecord]) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut flagged = Vec::new();
    for rec in records {
        if rec.would_refute.is_empty() && seen.insert(rec.id.as_str()) {
            flagged.push(rec.id.clone());
        }
    }
    flagged
}

/// In-memory reference registry for competing hypotheses and their
/// falsifiers. Persistence is out of scope here; the invariants a durable
/// store must keep are:
///
/// 1. **Ids are write-once.** [`register`](Self::register) refuses an id
///    already present; a competing hypothesis is superseded under a *new*
///    id, never by overwriting the old record.
/// 2. **Falsifiers are additive.** [`attach_falsifier`](Self::attach_falsifier)
///    appends edges only; nothing edits or removes a registered falsifier.
/// 3. **The guard is checked at the commit boundary**, not at registration
///    (see module doc) — [`missing_falsifiers`](Self::missing_falsifiers) /
///    [`require_falsifier`](Self::require_falsifier).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct DisconfirmationStore {
    records: Vec<HypothesisRecord>,
}

impl DisconfirmationStore {
    /// Empty store.
    pub fn new() -> Self {
        DisconfirmationStore {
            records: Vec::new(),
        }
    }

    /// Register a competing hypothesis. Validates first; rejects ids already
    /// present. Records with zero falsifiers **are** accepted here — the
    /// guard fires at commit time (module doc, "Guard semantics").
    ///
    /// # Errors
    /// [`DiscError::EmptyId`] / [`DiscError::EmptyStatement`] /
    /// [`DiscError::EmptyFalsifier`] from validation, or
    /// [`DiscError::DuplicateId`] if the id exists.
    pub fn register(&mut self, rec: HypothesisRecord) -> Result<(), DiscError> {
        rec.validate()?;
        if self.get(&rec.id).is_some() {
            return Err(DiscError::DuplicateId(rec.id));
        }
        self.records.push(rec);
        Ok(())
    }

    /// Attach one falsifier to the record for `id` (additive only).
    ///
    /// # Errors
    /// [`DiscError::UnknownId`] if `id` was never registered,
    /// [`DiscError::EmptyFalsifier`] if `f.statement` is empty (checked
    /// before lookup so an invalid falsifier can never consume a lookup).
    pub fn attach_falsifier(&mut self, id: &str, f: Falsifier) -> Result<(), DiscError> {
        f.validate()?;
        let Some(rec) = self.records.iter_mut().find(|r| r.id == id) else {
            return Err(DiscError::UnknownId(id.to_string()));
        };
        rec.would_refute.push(f);
        Ok(())
    }

    /// The record for `id`, or `None` if unknown.
    pub fn get(&self, id: &str) -> Option<&HypothesisRecord> {
        self.records.iter().find(|r| r.id == id)
    }

    /// Ids with zero falsifiers (convenience wrapper over
    /// [`flag_missing_falsifiers`] for the whole store).
    pub fn missing_falsifiers(&self) -> Vec<String> {
        flag_missing_falsifiers(&self.records)
    }

    /// Hard-fail form of the guard: `Ok` only when `id` is registered **and**
    /// carries at least one falsifier. The dissemination path calls this
    /// before committing a high-credibility write.
    ///
    /// # Errors
    /// [`DiscError::UnknownId`] if `id` was never registered;
    /// [`DiscError::MissingFalsifier`] if it has zero falsifiers.
    pub fn require_falsifier(&self, id: &str) -> Result<(), DiscError> {
        let Some(rec) = self.get(id) else {
            return Err(DiscError::UnknownId(id.to_string()));
        };
        if !rec.has_falsifier() {
            return Err(DiscError::MissingFalsifier(id.to_string()));
        }
        Ok(())
    }

    /// All records, in registration order (the competing set).
    pub fn records(&self) -> &[HypothesisRecord] {
        &self.records
    }

    /// Number of registered hypotheses.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` when nothing was registered.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(id: &str, statement: &str) -> HypothesisRecord {
        HypothesisRecord::new(id, statement)
    }

    /// A record with one registered falsifier.
    fn with_falsifier(id: &str, statement: &str) -> HypothesisRecord {
        let mut r = rec(id, statement);
        r.attach(Falsifier::new("sampler shows the opposite by 2026-10-01"))
            .unwrap();
        r
    }

    // --- flag_missing_falsifiers: the guard --------------------------------

    #[test]
    fn missing_falsifiers_are_flagged_in_first_appearance_order() {
        let records = vec![
            rec("h-1", "route A is the exfil path"),
            with_falsifier("h-2", "route B is the exfil path"),
            rec("h-3", "route C is the exfil path"),
        ];
        assert_eq!(
            flag_missing_falsifiers(&records),
            vec!["h-1".to_string(), "h-3".to_string()]
        );
    }

    #[test]
    fn a_registered_falsifier_clears_the_flag() {
        let mut store = DisconfirmationStore::new();
        store
            .register(rec("h-1", "the outage was a fiber cut"))
            .unwrap();
        assert_eq!(store.missing_falsifiers(), vec!["h-1".to_string()]);

        store
            .attach_falsifier(
                "h-1",
                Falsifier::new("carrier confirms scheduled maintenance instead"),
            )
            .unwrap();

        assert!(store.missing_falsifiers().is_empty());
        assert!(store.get("h-1").unwrap().has_falsifier());
        assert!(store.require_falsifier("h-1").is_ok());
    }

    #[test]
    fn flagging_dedupes_repeated_ids_defensively() {
        let records = vec![rec("h-1", "a"), with_falsifier("h-2", "b"), rec("h-1", "a")];
        assert_eq!(flag_missing_falsifiers(&records), vec!["h-1".to_string()]);
    }

    #[test]
    fn flagging_empty_and_fully_falsified_batches() {
        assert!(flag_missing_falsifiers(&[]).is_empty());

        let all_covered = vec![
            with_falsifier("h-1", "a"),
            with_falsifier("h-2", "b"),
        ];
        assert!(flag_missing_falsifiers(&all_covered).is_empty());
    }

    // --- attach_falsifier ---------------------------------------------------

    #[test]
    fn attach_to_unknown_id_is_refused() {
        let mut store = DisconfirmationStore::new();
        let err = store
            .attach_falsifier("nope", Falsifier::new("x"))
            .expect_err("unknown id must be refused");
        assert_eq!(err, DiscError::UnknownId("nope".to_string()));
        assert!(store.is_empty());
    }

    #[test]
    fn attach_rejects_empty_falsifier_and_does_not_write() {
        let mut store = DisconfirmationStore::new();
        store.register(rec("h-1", "a")).unwrap();
        let err = store
            .attach_falsifier("h-1", Falsifier::new(""))
            .expect_err("empty falsifier must be refused");
        assert_eq!(err, DiscError::EmptyFalsifier);
        // The record still has zero falsifiers — the guard keeps firing.
        assert_eq!(store.missing_falsifiers(), vec!["h-1".to_string()]);
    }

    #[test]
    fn attach_is_additive_and_never_removes() {
        let mut store = DisconfirmationStore::new();
        store.register(rec("h-1", "a")).unwrap();
        store.attach_falsifier("h-1", Falsifier::new("f1")).unwrap();
        store.attach_falsifier("h-1", Falsifier::new("f2")).unwrap();
        let rec = store.get("h-1").unwrap();
        assert_eq!(rec.would_refute.len(), 2);
        assert_eq!(rec.would_refute[0].statement, "f1");
        assert_eq!(rec.would_refute[1].statement, "f2");
    }

    // --- register: unique write-once ids -----------------------------------

    #[test]
    fn duplicate_id_is_refused_and_original_is_kept() {
        let mut store = DisconfirmationStore::new();
        store.register(rec("h-1", "original")).unwrap();

        let mut replacement = rec("h-1", "rewritten after the fact");
        replacement.attach(Falsifier::new("too late")).unwrap();
        let err = store
            .register(replacement)
            .expect_err("write-once ids: re-register must fail");
        assert_eq!(err, DiscError::DuplicateId("h-1".to_string()));

        // Nothing was overwritten or merged: the original record (still
        // falsifier-less, still the original statement) is untouched.
        assert_eq!(store.len(), 1);
        let kept = store.get("h-1").unwrap();
        assert_eq!(kept.statement, "original");
        assert!(!kept.has_falsifier());
    }

    #[test]
    fn register_validates_before_inserting() {
        let mut store = DisconfirmationStore::new();
        assert_eq!(
            store.register(rec("", "s")),
            Err(DiscError::EmptyId)
        );
        assert_eq!(
            store.register(rec("h", "")),
            Err(DiscError::EmptyStatement)
        );

        let mut bad = rec("h", "s");
        bad.would_refute.push(Falsifier::new(""));
        assert_eq!(store.register(bad), Err(DiscError::EmptyFalsifier));
        assert!(store.is_empty());
    }

    #[test]
    fn competing_hypotheses_coexist() {
        let mut store = DisconfirmationStore::new();
        for (id, stmt) in [
            ("h-a", "the spike is organic traffic"),
            ("h-b", "the spike is a scraping campaign"),
            ("h-c", "the spike is a measurement artifact"),
        ] {
            store.register(with_falsifier(id, stmt)).unwrap();
        }
        assert_eq!(store.len(), 3);
        assert!(store.missing_falsifiers().is_empty());
        assert_eq!(store.records()[1].id, "h-b");
        assert!(store.get("h-z").is_none());
    }

    // --- require_falsifier: hard-fail guard --------------------------------

    #[test]
    fn require_falsifier_hard_fails_while_missing() {
        let mut store = DisconfirmationStore::new();
        assert_eq!(
            store.require_falsifier("h-1"),
            Err(DiscError::UnknownId("h-1".to_string()))
        );

        store.register(rec("h-1", "a")).unwrap();
        assert_eq!(
            store.require_falsifier("h-1"),
            Err(DiscError::MissingFalsifier("h-1".to_string()))
        );

        store.attach_falsifier("h-1", Falsifier::new("f")).unwrap();
        assert_eq!(store.require_falsifier("h-1"), Ok(()));
    }

    // --- serde --------------------------------------------------------------

    #[test]
    fn serde_round_trip_pins_wire_form() {
        let r = with_falsifier("h-1", "route A is the exfil path");
        let json = serde_json::to_string(&r).unwrap();
        assert_eq!(
            json,
            r#"{"id":"h-1","statement":"route A is the exfil path","would_refute":[{"statement":"sampler shows the opposite by 2026-10-01"}]}"#,
            "wire form pinned: {json}"
        );
        let back: HypothesisRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
        assert!(back.has_falsifier());
    }

    #[test]
    fn serde_round_trip_store_snapshot_and_validation_after_ingest() {
        let mut store = DisconfirmationStore::new();
        store
            .register(with_falsifier("h-1", "the outage was a fiber cut"))
            .unwrap();
        store.register(rec("h-2", "the outage was a router bug")).unwrap();

        let json = serde_json::to_string(store.records()).unwrap();
        let back: Vec<HypothesisRecord> = serde_json::from_str(&json).unwrap();
        assert_eq!(back.as_slice(), store.records());
        // serde is a plain decoder: an empty id deserializes structurally and
        // is caught by validate(), not by serde.
        let hostile: HypothesisRecord =
            serde_json::from_str(r#"{"id":"","statement":"s","would_refute":[]}"#).unwrap();
        assert_eq!(hostile.validate(), Err(DiscError::EmptyId));
    }
}
