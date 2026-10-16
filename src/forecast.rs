//! Forecast ledger — hypothesis records, validation, and scoring primitives
//! (task A4.1.1, interface §8).
//!
//! Wave A4 ("judgment quality") makes Tallow's *own* predictive calls
//! auditable. The documented dominant failure mode of analytic judgment is
//! overconfidence, and the E8 design answer is borrowed from the Good
//! Judgment Project / IARPA ACE lineage: a prediction is only improvable if
//! it was written down as a probability *before* the outcome was known, with
//! explicit resolution criteria so it cannot be reinterpreted after the fact.
//!
//! A [`Hypothesis`] is exactly that record: a statement, a stated
//! `probability` in `0.0..=1.0`, the `resolution_criteria` that will decide
//! it, a `deadline_ms` after which it can be forced to resolution, provenance
//! `evidence_links`, and a lifecycle [`HypothesisState`]:
//!
//! ```text
//! Open -> Resolved { outcome }
//! ```
//!
//! Resolution scoring is task A4.1.2 (resolution job + calibration curves);
//! this module deliberately ships only the record layer, its validation, and
//! the trivial [`brier`] scoring primitive so the later job builds on one
//! canonical representation.
//!
//! # Validation
//! [`Hypothesis::new`] and [`Hypothesis::validate`] enforce:
//! * `probability` is finite and within `0.0..=1.0` (NaN/infinity included
//!   in the rejection — `NaN` must never be storable, it poisons every
//!   downstream calibration statistic);
//! * `id`, `statement`, and `resolution_criteria` are non-empty.
//!
//! `deadline_ms` is *not* range-checked here (`0` may be used as "no fixed
//! deadline"); callers that require a live deadline check it themselves.
//! Deserialization does not validate (serde derive is a plain wire decoder) —
//! call [`Hypothesis::validate`] after ingesting untrusted JSON.
//!
//! # Store notes (append-only, for later)
//! Persistence for this ledger is deliberately out of scope for this starter.
//! The invariants the eventual store must keep, recorded here so the later
//! task cannot drift:
//! 1. **Append-only.** A hypothesis is written once; *resolution never edits
//!    the original record*, it appends a successor record carrying the new
//!    state. History is therefore replayable and a probability cannot be
//!    quietly rewritten after the fact.
//! 2. **Ids are write-once.** The first record for an id fixes it; re-append
//!    with the same id is an error, not an overwrite.
//! 3. **Ledger-integrated later.** When durable storage lands it should emit
//!    through `crate::ledger_events` / `crate::agent_ledger` so every
//!    resolution is an audit-grade event (the hash chain is the tamper
//!    evidence for the calibration record).
//!
//! [`HypothesisStore`] below is the in-memory *reference behavior* for those
//! invariants: append, resolve (append successor), read current state.

use serde::{Deserialize, Serialize};

/// Lifecycle state of a [`Hypothesis`].
///
/// Wire form (serde, snake_case): `"open"`, or
/// `{"resolved": {"outcome": true}}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HypothesisState {
    /// Stated but not yet decided.
    Open,
    /// Decided. `outcome`: `true` = the stated event occurred / the claim
    /// held; `false` = it did not. Binary outcomes are what Brier/calibration
    /// scoring needs (GJP/ACE practice); probabilistic resolutions would
    /// generalize `brier` to `outcome ∈ [0.0, 1.0]` later if ever required.
    Resolved { outcome: bool },
}

/// One predictive call, frozen at the time it was made.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hypothesis {
    /// Stable record id. Write-once in the store; non-empty.
    pub id: String,
    /// What is claimed, in falsifiable form. Non-empty.
    pub statement: String,
    /// Stated probability of the claim holding, in `0.0..=1.0`. Validated.
    pub probability: f64,
    /// What observable evidence will decide resolution *before* it is known.
    /// Non-empty.
    pub resolution_criteria: String,
    /// Resolution deadline, Unix epoch milliseconds. Not range-checked here.
    pub deadline_ms: i64,
    /// Provenance: links to the evidence the probability was assessed on.
    pub evidence_links: Vec<String>,
    /// Current lifecycle state.
    pub state: HypothesisState,
}

/// Validation / store errors for forecast records.
#[allow(dead_code)]
#[derive(Debug, Clone, PartialEq, thiserror::Error)]
pub enum ForecastError {
    /// `probability` was NaN, infinite, or outside `0.0..=1.0`.
    #[error("probability {probability} out of bounds: must be finite and within 0.0..=1.0")]
    ProbabilityOutOfBounds {
        /// The rejected value (careful: NaN never compares equal to itself).
        probability: f64,
    },
    /// `id` was empty.
    #[error("hypothesis id must not be empty")]
    EmptyId,
    /// `statement` was empty.
    #[error("hypothesis statement must not be empty")]
    EmptyStatement,
    /// `resolution_criteria` was empty.
    #[error("resolution_criteria must not be empty")]
    EmptyCriteria,
    /// Lookup/transition on an id that was never appended.
    #[error("hypothesis {0} is unknown")]
    UnknownId(String),
    /// Second append for an existing id (ids are write-once).
    #[error("hypothesis {0} already exists (append-only: ids are write-once)")]
    DuplicateId(String),
    /// Resolution attempted on an already-resolved hypothesis.
    #[error("hypothesis {0} is already resolved")]
    AlreadyResolved(String),
}

impl Hypothesis {
    /// Build and validate a new `Open` hypothesis.
    ///
    /// # Errors
    /// See [`Hypothesis::validate`].
    pub fn new(
        id: impl Into<String>,
        statement: impl Into<String>,
        probability: f64,
        resolution_criteria: impl Into<String>,
        deadline_ms: i64,
        evidence_links: Vec<String>,
    ) -> Result<Self, ForecastError> {
        let h = Hypothesis {
            id: id.into(),
            statement: statement.into(),
            probability,
            resolution_criteria: resolution_criteria.into(),
            deadline_ms,
            evidence_links,
            state: HypothesisState::Open,
        };
        h.validate()?;
        Ok(h)
    }

    /// Re-check all record invariants. Cheap; call it after deserializing
    /// untrusted JSON (serde does not validate on the way in).
    pub fn validate(&self) -> Result<(), ForecastError> {
        // `!(0.0..=1.0).contains(..)` also rejects NaN: every comparison
        // against NaN is false, so the membership test fails. ±inf are out too.
        if !(0.0..=1.0).contains(&self.probability) {
            return Err(ForecastError::ProbabilityOutOfBounds {
                probability: self.probability,
            });
        }
        if self.id.is_empty() {
            return Err(ForecastError::EmptyId);
        }
        if self.statement.is_empty() {
            return Err(ForecastError::EmptyStatement);
        }
        if self.resolution_criteria.is_empty() {
            return Err(ForecastError::EmptyCriteria);
        }
        Ok(())
    }

    /// `true` while the hypothesis is undecided.
    pub fn is_open(&self) -> bool {
        matches!(self.state, HypothesisState::Open)
    }

    /// `true` once resolved.
    pub fn is_resolved(&self) -> bool {
        matches!(self.state, HypothesisState::Resolved { .. })
    }

    /// Transition `Open -> Resolved { outcome }` in place.
    ///
    /// # Errors
    /// [`ForecastError::AlreadyResolved`] if the hypothesis was already
    /// resolved — a resolution is a one-shot fact, never amended in place
    /// (append a successor record instead; see store notes in the module doc).
    pub fn resolve(&mut self, outcome: bool) -> Result<(), ForecastError> {
        if self.is_resolved() {
            return Err(ForecastError::AlreadyResolved(self.id.clone()));
        }
        self.state = HypothesisState::Resolved { outcome };
        Ok(())
    }

    /// Brier score of this hypothesis, or `None` while it is still `Open`.
    ///
    /// Convenience wrapper over [`brier`].
    pub fn brier(&self) -> Option<f64> {
        match self.state {
            HypothesisState::Resolved { outcome } => Some(brier(self.probability, outcome)),
            HypothesisState::Open => None,
        }
    }
}

/// Brier score for a stated `probability` against a binary `outcome`:
/// `(probability - o)^2` with `o = 1.0` if the event occurred, else `0.0`.
///
/// Pure and total for any inputs; `probability` is expected to already be
/// within `0.0..=1.0` (records enforce this via [`Hypothesis::validate`]).
/// Best possible score is `0.0`; worst is `1.0` for a certain-but-wrong call.
pub fn brier(probability: f64, outcome: bool) -> f64 {
    let o = if outcome { 1.0 } else { 0.0 };
    (probability - o) * (probability - o)
}

/// In-memory append-only reference store (see **Store notes** in the module
/// doc). Durable/persistent storage is later work; this encodes the exact
/// invariants it must keep:
/// * [`append`](Self::append) validates and enforces write-once ids;
/// * [`resolve`](Self::resolve) never rewrites anything — it appends a
///   successor record with the resolved state;
/// * [`current`](Self::current) is the newest record for an id; the full
///   [`records`](Self::records) slice is the history.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct HypothesisStore {
    records: Vec<Hypothesis>,
}

impl HypothesisStore {
    /// Empty store.
    pub fn new() -> Self {
        HypothesisStore {
            records: Vec::new(),
        }
    }

    /// Append a new record. Validates first; rejects ids already present.
    pub fn append(&mut self, hypothesis: Hypothesis) -> Result<(), ForecastError> {
        hypothesis.validate()?;
        if self.current(&hypothesis.id).is_some() {
            return Err(ForecastError::DuplicateId(hypothesis.id));
        }
        self.records.push(hypothesis);
        Ok(())
    }

    /// Resolve `id` by appending a successor record; the original record is
    /// left byte-for-byte unchanged (append-only).
    ///
    /// # Errors
    /// [`ForecastError::UnknownId`] if the id was never appended,
    /// [`ForecastError::AlreadyResolved`] if it is already resolved.
    pub fn resolve(&mut self, id: &str, outcome: bool) -> Result<(), ForecastError> {
        let Some(latest) = self.current(id) else {
            return Err(ForecastError::UnknownId(id.to_string()));
        };
        let mut next = latest.clone();
        next.resolve(outcome)?;
        self.records.push(next);
        Ok(())
    }

    /// Newest record for `id`, or `None` if unknown.
    pub fn current(&self, id: &str) -> Option<&Hypothesis> {
        self.records.iter().rev().find(|h| h.id == id)
    }

    /// Full append-only history, in insertion order.
    pub fn records(&self) -> &[Hypothesis] {
        &self.records
    }

    /// Number of records (not distinct ids) held.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` when no records were appended.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_sample() -> Hypothesis {
        Hypothesis::new(
            "h-001",
            "Route 7 traffic drops below 50 req/s by 2026-10-01",
            0.7,
            "continuous sampler: 7-day mean < 50 req/s",
            1_790_000_000_000,
            vec!["https://example.org/sampler".to_string()],
        )
        .expect("valid sample")
    }

    fn assert_close(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-12, "expected {b}, got {a}");
    }

    // --- validation: probability bounds -----------------------------------

    #[test]
    fn probability_bounds_are_enforced() {
        for (p, expect_ok) in [
            (-0.001, false),
            (-1.0, false),
            (0.0, true),
            (1.0, true),
            (1.000_001, false),
            (42.0, false),
        ] {
            let result = Hypothesis::new("h", "s", p, "c", 1, Vec::new());
            assert_eq!(result.is_ok(), expect_ok, "probability {p}");
            if let Err(e) = result {
                assert!(matches!(
                    e,
                    ForecastError::ProbabilityOutOfBounds { .. }
                ));
            }
        }
    }

    #[test]
    fn probability_nan_and_infinity_are_rejected() {
        for p in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY] {
            let err = Hypothesis::new("h", "s", p, "c", 1, Vec::new())
                .expect_err("non-finite probabilities must never be storable");
            assert!(
                matches!(err, ForecastError::ProbabilityOutOfBounds { .. }),
                "got {err:?} for {p}"
            );
        }
    }

    #[test]
    fn empty_identity_fields_are_rejected() {
        assert_eq!(
            Hypothesis::new("", "s", 0.5, "c", 1, Vec::new()),
            Err(ForecastError::EmptyId)
        );
        assert_eq!(
            Hypothesis::new("h", "", 0.5, "c", 1, Vec::new()),
            Err(ForecastError::EmptyStatement)
        );
        assert_eq!(
            Hypothesis::new("h", "s", 0.5, "", 1, Vec::new()),
            Err(ForecastError::EmptyCriteria)
        );
    }

    #[test]
    fn validate_catches_out_of_bounds_after_deserialization() {
        // serde is a plain decoder: it will happily ingest a hostile value.
        let json = r#"{
            "id": "h-bad",
            "statement": "the coin lands heads",
            "probability": 7.5,
            "resolution_criteria": "observe flip",
            "deadline_ms": 1800000000000,
            "evidence_links": [],
            "state": "open"
        }"#;
        let h: Hypothesis = serde_json::from_str(json).expect("decodes structurally");
        assert_eq!(
            h.validate(),
            Err(ForecastError::ProbabilityOutOfBounds { probability: 7.5 })
        );
    }

    // --- serde round-trip --------------------------------------------------

    #[test]
    fn serde_round_trip_open() {
        let h = ok_sample();
        let json = serde_json::to_string(&h).unwrap();
        assert!(json.contains(r#""state":"open""#), "wire form pinned: {json}");
        let back: Hypothesis = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
    }

    #[test]
    fn serde_round_trip_resolved() {
        let mut h = ok_sample();
        h.resolve(false).unwrap();
        let json = serde_json::to_string(&h).unwrap();
        assert!(
            json.contains(r#""state":{"resolved":{"outcome":false}}"#),
            "wire form pinned: {json}"
        );
        let back: Hypothesis = serde_json::from_str(&json).unwrap();
        assert_eq!(back, h);
        assert_eq!(back.state, HypothesisState::Resolved { outcome: false });
    }

    #[test]
    fn state_enum_serde_units() {
        assert_eq!(serde_json::to_string(&HypothesisState::Open).unwrap(), r#""open""#);
        assert_eq!(
            serde_json::to_string(&HypothesisState::Resolved { outcome: true }).unwrap(),
            r#"{"resolved":{"outcome":true}}"#
        );
    }

    // --- state transitions -------------------------------------------------

    #[test]
    fn resolve_transitions_open_to_resolved() {
        let mut h = ok_sample();
        assert!(h.is_open() && !h.is_resolved());
        h.resolve(true).unwrap();
        assert!(h.is_resolved() && !h.is_open());
        assert_eq!(h.state, HypothesisState::Resolved { outcome: true });
        // The stated probability is part of the frozen record; it must not
        // move when the outcome lands.
        assert_close(h.probability, 0.7);
    }

    #[test]
    fn double_resolve_is_rejected_and_state_is_unchanged() {
        let mut h = ok_sample();
        h.resolve(true).unwrap();
        let err = h.resolve(false).expect_err("second resolution must fail");
        assert_eq!(err, ForecastError::AlreadyResolved("h-001".to_string()));
        assert_eq!(h.state, HypothesisState::Resolved { outcome: true });
    }

    // --- brier -------------------------------------------------------------

    #[test]
    fn brier_scores_known_values() {
        assert_close(brier(0.9, true), 0.01);
        assert_close(brier(0.1, false), 0.01);
        assert_close(brier(0.5, true), 0.25);
        assert_close(brier(1.0, false), 1.0);
        assert_close(brier(0.0, false), 0.0);
        // Symmetry: confidently wrong either way costs the same.
        assert_close(brier(0.9, false), brier(0.1, true));
    }

    #[test]
    fn brier_is_none_while_open_some_after_resolution() {
        let mut h = ok_sample();
        assert_eq!(h.brier(), None);
        h.resolve(true).unwrap();
        assert_close(h.brier().unwrap(), 0.09);
    }

    // --- append-only store -------------------------------------------------

    #[test]
    fn store_append_read_and_duplicate_rejection() {
        let mut store = HypothesisStore::new();
        assert!(store.is_empty());
        store.append(ok_sample()).unwrap();
        assert_eq!(store.len(), 1);
        assert_eq!(store.current("h-001").unwrap().probability, 0.7);
        assert!(store.current("nope").is_none());

        let err = store
            .append(ok_sample())
            .expect_err("write-once ids: re-append must fail");
        assert_eq!(err, ForecastError::DuplicateId("h-001".to_string()));
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_append_validates_first() {
        let mut store = HypothesisStore::new();
        let bad: Hypothesis = serde_json::from_str(
            r#"{"id":"h-bad","statement":"s","probability":-3.0,
                "resolution_criteria":"c","deadline_ms":1,
                "evidence_links":[],"state":"open"}"#,
        )
        .unwrap();
        assert_eq!(
            store.append(bad),
            Err(ForecastError::ProbabilityOutOfBounds { probability: -3.0 })
        );
        assert!(store.is_empty());
    }

    #[test]
    fn store_resolve_appends_history_instead_of_rewriting() {
        let mut store = HypothesisStore::new();
        store.append(ok_sample()).unwrap();
        store.resolve("h-001", true).unwrap();

        // Append-only: two records, the first one still Open and byte-equal
        // to what was appended.
        assert_eq!(store.len(), 2);
        assert_eq!(store.records()[0], ok_sample());
        assert!(store.records()[0].is_open());
        assert_eq!(
            store.current("h-001").unwrap().state,
            HypothesisState::Resolved { outcome: true }
        );

        // Transitions on unknown / already-resolved ids are refused.
        assert_eq!(
            store.resolve("nope", true),
            Err(ForecastError::UnknownId("nope".to_string()))
        );
        assert_eq!(
            store.resolve("h-001", false),
            Err(ForecastError::AlreadyResolved("h-001".to_string()))
        );
        assert_eq!(store.len(), 2);
    }
}
