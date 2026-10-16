//! Calibration **resolution job runner + dashboard** (task A4.1.2 remainder,
//! frozen interface §5).
//!
//! `calibration.rs` (the A4.1.2 core) is a pure scoring layer:
//! [`resolve_batch`](crate::calibration::resolve_batch) commits `(id, outcome)`
//! decisions into a [`HypothesisStore`], and
//! [`brier_score`](crate::calibration::brier_score) /
//! [`calibration_curve`](crate::calibration::calibration_curve) /
//! [`overconfidence`](crate::calibration::overconfidence) /
//! [`overdue_open`](crate::calibration::overdue_open) turn a record slice into
//! judgment-quality numbers. This module is the **job** wrapper around that:
//! one call that (1) commits the resolution decisions carried by the caller's
//! record list through the real `resolve_batch`, (2) scores the committed
//! history, (3) sweeps what is still overdue, and (4) packages it as a
//! [`Dashboard`] with a deterministic one-line summary.
//!
//! # Input contract — adaptation of §5's sketch to `resolve_batch`'s real API
//! The frozen interface sketches `run(records: &mut Vec<Hypothesis>, …)`, while
//! the real [`resolve_batch`](crate::calibration::resolve_batch) takes a
//! `&mut HypothesisStore` plus an explicit `&[(String, bool)]` batch. `run`
//! therefore accepts the **append-only history form** the store itself produces
//! (what [`HypothesisStore::records`] returns):
//! * an **`Open` record** is a live hypothesis (pending decision);
//! * a **`Resolved { outcome }` record** is a *resolution decision* for its id:
//!   the decisions are extracted **in order** into the batch handed to
//!   [`resolve_batch`](crate::calibration::resolve_batch), which commits them
//!   through the store's one-shot `Open -> Resolved` transition. A duplicated
//!   id inside one batch succeeds once and then fails `already resolved`; the
//!   failures are returned (and, via [`resolve_due_batch`], surfaced) in the
//!   [`ResolveSummary`](crate::calibration::ResolveSummary) — nothing is
//!   silently dropped, and no outcome is ever invented.
//!
//! After the job, `records` is **rewritten in place** to the committed
//! append-only history (originals + committed successors) — the canonical slice
//! the scorers in `calibration.rs` are documented to consume. Re-running the
//! job over its own output is content-stable: decisions commit only where the
//! rebuilt store was still open, and successors regenerate deterministically.
//!
//! # Dashboard semantics
//! * `brier` / `overconfidence` / `curve` are computed over the committed
//!   history; `Open` originals are ignored by the scorers (see `calibration.rs`
//!   notes), so an empty or decision-less input yields `None` / empty
//!   collections, never a fake `0.0`.
//! * `overdue` is computed over the **current per-id view** (newest record per
//!   id), not the raw history: once a hypothesis is decided, its still-`Open`
//!   historical original must not keep the id on the actionable overdue list.
//!   Ordering is [`overdue_open`](crate::calibration::overdue_open)'s —
//!   ascending by `(deadline_ms, id)`.
//! * `summary` is a deterministic one-liner:
//!   `brier=<x|none> overconfidence=<y|none> overdue=<n>`, scores at 3 decimals.
//!
//! Never panics. `bucket_count == 0` is [`RunnerError::BadConfig`]; a record
//! that fails store validation aborts the job with [`RunnerError::Calibration`]
//! (an append-only duplicate by id is history, not an error — see
//! [`resolve_due_batch`]).


use serde::{Deserialize, Serialize};

use crate::calibration::{self, ResolveSummary};
use crate::forecast::{ForecastError, Hypothesis, HypothesisState, HypothesisStore};

/// Knobs for a [`run`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RunnerConfig {
    /// Number of equal-width buckets for the calibration curve. Must be > 0;
    /// `0` is rejected with [`RunnerError::BadConfig`] (the underlying
    /// `calibration_curve` would silently return an empty vector for it — a
    /// runner must not accept a config that produces no curve).
    pub bucket_count: usize,
}

/// One dashboard snapshot produced by [`run`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Dashboard {
    /// Mean Brier score over the resolved records; `None` when nothing is
    /// resolved (an empty mean is not a score of `0.0`).
    pub brier: Option<f64>,
    /// Mean `predicted - observed` over resolved records (positive =
    /// overconfident); `None` when nothing is resolved.
    pub overconfidence: Option<f64>,
    /// Calibration curve over resolved records (non-empty buckets only,
    /// ascending by `lower`).
    pub curve: Vec<calibration::CalibrationBucket>,
    /// Ids still awaiting a decision past their deadline, ascending by
    /// `(deadline_ms, id)` — the actionable residue after the job.
    pub overdue: Vec<String>,
    /// Deterministic one-liner; exact format documented at module level.
    pub summary: String,
}

/// Errors a [`run`] can fail with.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, thiserror::Error)]
pub enum RunnerError {
    /// [`RunnerConfig::bucket_count`] was `0`.
    #[error("runner config invalid: bucket_count must be > 0")]
    BadConfig,
    /// The calibration layer refused a record (store validation error on a
    /// job input). Carries the underlying reason.
    #[error("calibration layer error: {0}")]
    Calibration(String),
}

/// Format one optional score for the summary line (3 decimals; `none` when
/// absent; `-0.0` normalized so the string never depends on the zero's sign).
fn fmt_score(v: Option<f64>) -> String {
    match v {
        Some(x) if x == 0.0 => "0.000".to_string(),
        Some(x) => format!("{x:.3}"),
        None => "none".to_string(),
    }
}

/// Newest record per id — "what is currently true / still pending". Used for
/// the overdue sweep; ordering is irrelevant because `overdue_open` sorts.
fn current_view(records: &[Hypothesis]) -> Vec<Hypothesis> {
    records
        .iter()
        .enumerate()
        .filter(|(i, h)| !records[i + 1..].iter().any(|later| later.id == h.id))
        .map(|(_, h)| h.clone())
        .collect()
}

/// Commit the batch of resolution decisions carried by `records`.
///
/// The list is read in the append-only history form (see module docs): `Open`
/// records rebuild the store; `Resolved` records are the in-order
/// `(id, outcome)` batch handed to the real
/// [`resolve_batch`](crate::calibration::resolve_batch). On return `records`
/// holds the committed history (originals + successors). A repeated record for
/// an id already carried by the store is history (the append-only successor
/// form) and is skipped during the rebuild.
///
/// # Errors
/// [`RunnerError::Calibration`] when a record fails store validation
/// (`ForecastError` other than the append-only duplicate case).
pub fn resolve_due_batch(records: &mut Vec<Hypothesis>) -> Result<ResolveSummary, RunnerError> {
    let mut store = HypothesisStore::new();
    for h in records.iter() {
        match store.append(h.clone()) {
            Ok(()) => {}
            // Append-only successor/history duplicate: the id is already
            // carried by the store; the duplicate record adds nothing new.
            Err(ForecastError::DuplicateId(_)) => {}
            // Anything else (invalid record) is a job input error, surfaced.
            Err(e) => return Err(RunnerError::Calibration(e.to_string())),
        }
    }
    let batch: Vec<(String, bool)> = records
        .iter()
        .filter_map(|h| match &h.state {
            HypothesisState::Resolved { outcome } => Some((h.id.clone(), *outcome)),
            HypothesisState::Open => None,
        })
        .collect();
    let summary = calibration::resolve_batch(&mut store, &batch);
    *records = store.records().to_vec();
    Ok(summary)
}

/// Run the resolution job over `records` and return the [`Dashboard`].
///
/// Sequence: commit the embedded resolution batch first (see
/// [`resolve_due_batch`]), then score the committed history (Brier /
/// calibration curve / over-confidence) and sweep the still-overdue ids.
/// Empty input is valid: the dashboard is all-`None`/empty with
/// `summary = "brier=none overconfidence=none overdue=0"`.
///
/// # Errors
/// [`RunnerError::BadConfig`] for `bucket_count == 0` (checked before any
/// mutation); [`RunnerError::Calibration`] per [`resolve_due_batch`].
pub fn run(
    records: &mut Vec<Hypothesis>,
    now_ms: i64,
    cfg: &RunnerConfig,
) -> Result<Dashboard, RunnerError> {
    if cfg.bucket_count == 0 {
        return Err(RunnerError::BadConfig);
    }
    // 1. Resolution job first: commit the decision batch, rewrite history.
    let _resolution_summary = resolve_due_batch(records)?;
    // 2. Score the committed history (open originals are ignored by the
    //    scorers, per calibration.rs; the history slice is their documented
    //    input).
    let brier = calibration::brier_score(records);
    let overconfidence = calibration::overconfidence(records);
    let curve = calibration::calibration_curve(records, cfg.bucket_count);
    // 3. Overdue over the current per-id view: a decided hypothesis is no
    //    longer actionable.
    let view = current_view(records);
    let overdue = calibration::overdue_open(&view, now_ms);
    let summary = format!(
        "brier={} overconfidence={} overdue={}",
        fmt_score(brier),
        fmt_score(overconfidence),
        overdue.len()
    );
    Ok(Dashboard {
        brier,
        overconfidence,
        curve,
        overdue,
        summary,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;

    fn hyp(id: &str, p: f64, deadline_ms: i64) -> Hypothesis {
        Hypothesis::new(
            id,
            format!("statement {id}"),
            p,
            format!("criteria {id}"),
            deadline_ms,
            Vec::new(),
        )
        .expect("valid test hypothesis")
    }

    /// A properly-formed successor record — the append-only "decision" form.
    fn decided(id: &str, p: f64, outcome: bool, deadline_ms: i64) -> Hypothesis {
        let mut h = hyp(id, p, deadline_ms);
        h.resolve(outcome).unwrap();
        h
    }

    fn cfg(n: usize) -> RunnerConfig {
        RunnerConfig { bucket_count: n }
    }

    fn close(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-12, "expected {b}, got {a}");
    }

    /// Field-wise dashboard comparison: floats by tolerance (serde_json's
    /// default float parser is not bit-exact — `float_roundtrip` is off in
    /// the default feature set), everything else exactly.
    fn dashboards_close(a: &Dashboard, b: &Dashboard) {
        match (a.brier, b.brier) {
            (Some(x), Some(y)) => close(x, y),
            (None, None) => {}
            _ => panic!("brier mismatch: {a:?} vs {b:?}"),
        }
        match (a.overconfidence, b.overconfidence) {
            (Some(x), Some(y)) => close(x, y),
            (None, None) => {}
            _ => panic!("overconfidence mismatch: {a:?} vs {b:?}"),
        }
        assert_eq!(a.curve.len(), b.curve.len());
        for (x, y) in a.curve.iter().zip(b.curve.iter()) {
            close(x.lower, y.lower);
            close(x.upper, y.upper);
            assert_eq!(x.n, y.n);
            close(x.mean_predicted, y.mean_predicted);
            close(x.observed_rate, y.observed_rate);
        }
        assert_eq!(a.overdue, b.overdue);
        assert_eq!(a.summary, b.summary);
    }

    // --- run: synthetic resolve -> score end-to-end -------------------------

    #[test]
    fn synthetic_resolve_to_score_end_to_end() {
        // A due hypothesis whose decision was adjudicated upstream (history
        // form: original + successor) plus an open one with a future deadline.
        // The job must commit the decision, then score exactly it.
        let mut records = vec![
            hyp("a", 0.9, NOW - 10),
            decided("a", 0.9, true, NOW - 10),
            hyp("b", 0.7, NOW + 5_000),
        ];
        let dash = run(&mut records, NOW, &cfg(4)).unwrap();

        // Committed in place: originals first (input order), committed
        // successors appended after — the store's canonical history order.
        assert_eq!(records.len(), 3);
        assert!(records[0].is_open() && records[1].is_open());
        let a_succ = records
            .iter()
            .find(|h| h.id == "a" && h.is_resolved())
            .expect("a committed successor for a");
        assert_eq!(
            a_succ.state,
            HypothesisState::Resolved { outcome: true }
        );

        // Scoring sees exactly the one resolved call: (0.9-1.0)^2 = 0.01.
        close(dash.brier.unwrap(), 0.01);
        close(dash.overconfidence.unwrap(), -0.1);
        assert_eq!(dash.curve.len(), 1);
        assert_eq!(dash.curve[0].n, 1);
        close(dash.curve[0].mean_predicted, 0.9);
        close(dash.curve[0].observed_rate, 1.0);

        // a is decided -> not overdue; b is future -> not overdue.
        assert!(dash.overdue.is_empty());
        assert_eq!(dash.summary, "brier=0.010 overconfidence=-0.100 overdue=0");
    }

    #[test]
    fn decision_commits_through_real_resolve_batch_and_writes_back_history() {
        let mut records = vec![hyp("a", 0.4, NOW - 1), decided("a", 0.4, false, NOW - 1)];
        let summary = resolve_due_batch(&mut records).unwrap();
        assert_eq!(summary.resolved, 1);
        assert!(summary.failures.is_empty());
        // Committed append-only history: original (Open) + successor.
        assert_eq!(records.len(), 2);
        assert!(records[0].is_open());
        assert_eq!(
            records[1].state,
            HypothesisState::Resolved { outcome: false }
        );
    }

    #[test]
    fn repeated_decisions_commit_once_then_fail_already_resolved() {
        // One-shot transition preserved: the duplicated id succeeds once and
        // then fails — exactly resolve_batch's documented batch semantics.
        let mut records = vec![
            hyp("a", 0.5, NOW - 1),
            decided("a", 0.5, true, NOW - 1),
            decided("a", 0.5, false, NOW - 1),
        ];
        let summary = resolve_due_batch(&mut records).unwrap();
        assert_eq!(summary.resolved, 1);
        assert_eq!(summary.failures.len(), 1);
        assert_eq!(summary.failures[0].0, "a");
        assert!(
            summary.failures[0].1.contains("already resolved"),
            "failure carries the store's reason: {}",
            summary.failures[0].1
        );
        // One committed successor only; the first decision's outcome holds.
        assert_eq!(records.len(), 2);
        assert_eq!(
            records[1].state,
            HypothesisState::Resolved { outcome: true }
        );
    }

    #[test]
    fn decision_without_original_is_kept_and_scores() {
        // A decision record with no separate original: the rebuilt store takes
        // it at face value (it IS the committed state) and it must score.
        let mut records = vec![decided("x", 0.2, true, NOW - 1)];
        let summary = resolve_due_batch(&mut records).unwrap();
        // Reported as already-resolved rather than silently dropped (one-shot).
        assert_eq!(summary.resolved, 0);
        assert_eq!(summary.failures.len(), 1);
        assert!(summary.failures[0].1.contains("already resolved"));

        let dash = run(&mut records, NOW, &cfg(4)).unwrap();
        close(dash.brier.unwrap(), 0.64); // (0.2 - 1.0)^2
    }

    // --- empty / decision-less input safety ---------------------------------

    #[test]
    fn empty_input_is_safe_all_none_empty() {
        let mut records: Vec<Hypothesis> = Vec::new();
        let dash = run(&mut records, NOW, &cfg(10)).unwrap();
        assert_eq!(dash.brier, None);
        assert_eq!(dash.overconfidence, None);
        assert!(dash.curve.is_empty());
        assert!(dash.overdue.is_empty());
        assert_eq!(dash.summary, "brier=none overconfidence=none overdue=0");
        assert!(records.is_empty());
    }

    #[test]
    fn opens_without_decisions_yield_no_scores_and_report_overdue() {
        let mut records = vec![hyp("late", 0.5, NOW - 100), hyp("future", 0.5, NOW + 1)];
        let dash = run(&mut records, NOW, &cfg(4)).unwrap();
        assert_eq!(dash.brier, None);
        assert_eq!(dash.overconfidence, None);
        assert!(dash.curve.is_empty());
        assert_eq!(dash.overdue, vec!["late".to_string()]);
        assert_eq!(dash.summary, "brier=none overconfidence=none overdue=1");
    }

    // --- config --------------------------------------------------------------

    #[test]
    fn bucket_count_zero_is_bad_config() {
        let mut records = vec![hyp("a", 0.5, NOW)];
        assert_eq!(run(&mut records, NOW, &cfg(0)), Err(RunnerError::BadConfig));
        // Rejected before any mutation.
        assert_eq!(records.len(), 1);
        assert!(records[0].is_open());
    }

    // --- curve respects the configured bucket count --------------------------

    #[test]
    fn curve_respects_bucket_count_and_matches_library() {
        let mut records = vec![
            decided("a", 0.10, true, NOW - 1),
            decided("b", 0.30, false, NOW - 1),
            decided("c", 0.95, true, NOW - 1),
        ];
        let dash = run(&mut records, NOW, &cfg(5)).unwrap();
        // Same curve the library computes over the committed history.
        assert_eq!(dash.curve, calibration::calibration_curve(&records, 5));
        // Edges i/5: 0.10 -> bucket 0, 0.30 -> bucket 1, 0.95 -> bucket 4.
        let lowers: Vec<f64> = dash.curve.iter().map(|b| b.lower).collect();
        assert_eq!(lowers, vec![0.0, 0.2, 0.8]);
        assert!(dash.curve.len() <= 5);

        // A different count (2) is respected for the same data.
        let mut records2 = vec![
            decided("a", 0.10, true, NOW - 1),
            decided("c", 0.95, true, NOW - 1),
        ];
        let dash2 = run(&mut records2, NOW, &cfg(2)).unwrap();
        assert_eq!(dash2.curve.len(), 2);
        assert_eq!(dash2.curve[0].lower, 0.0);
        assert_eq!(dash2.curve[1].lower, 0.5);
    }

    // --- overdue ordering -----------------------------------------------------

    #[test]
    fn overdue_is_ascending_by_deadline_then_id_and_excludes_decided() {
        let mut records = vec![
            hyp("z", 0.5, NOW - 50),               // due, later deadline
            hyp("b", 0.5, NOW - 100),              // due
            hyp("a", 0.5, NOW - 100),              // due, ties with b: id order
            hyp("future", 0.5, NOW + 50),          // not due
            decided("done", 0.5, true, NOW - 100), // decided: never actionable
        ];
        let dash = run(&mut records, NOW, &cfg(4)).unwrap();
        assert_eq!(
            dash.overdue,
            vec!["a".to_string(), "b".to_string(), "z".to_string()]
        );
    }

    // --- summary format pin ----------------------------------------------------

    #[test]
    fn summary_format_is_pinned() {
        let mut records = vec![
            decided("a", 0.8, true, NOW - 10),  // brier 0.04
            decided("b", 0.6, false, NOW - 10), // brier 0.36  -> mean 0.2
            hyp("c", 0.5, NOW - 10),            // open past deadline -> overdue
        ];
        let dash = run(&mut records, NOW, &cfg(4)).unwrap();
        // overconfidence: ((0.8-1) + (0.6-0)) / 2 = 0.2
        assert_eq!(dash.summary, "brier=0.200 overconfidence=0.200 overdue=1");
        assert_eq!(dash.overdue, vec!["c".to_string()]);
    }

    // --- determinism -----------------------------------------------------------

    #[test]
    fn run_is_deterministic_and_stable_across_reruns() {
        let build = || {
            vec![
                hyp("a", 0.9, NOW - 10),
                decided("a", 0.9, true, NOW - 10),
                hyp("b", 0.4, NOW - 5),
                decided("b", 0.4, false, NOW - 5),
                hyp("c", 0.5, NOW + 100),
            ]
        };
        let mut r1 = build();
        let mut r2 = build();
        let d1 = run(&mut r1, NOW, &cfg(4)).unwrap();
        let d2 = run(&mut r2, NOW, &cfg(4)).unwrap();
        assert_eq!(d1, d2);
        assert_eq!(r1, r2);
        // Re-running over the job's own output is content-stable.
        let mut r3 = r1.clone();
        let d3 = run(&mut r3, NOW, &cfg(4)).unwrap();
        assert_eq!(d3, d1);
        assert_eq!(r3, r1);
    }

    // --- serde / error surface --------------------------------------------------

    #[test]
    fn dashboard_and_error_serde_round_trip() {
        let mut records = vec![decided("a", 0.9, true, NOW - 10)];
        let dash = run(&mut records, NOW, &cfg(4)).unwrap();
        let back: Dashboard =
            serde_json::from_str(&serde_json::to_string(&dash).unwrap()).unwrap();
        dashboards_close(&back, &dash);

        let err = RunnerError::Calibration("boom".to_string());
        let back: RunnerError =
            serde_json::from_str(&serde_json::to_string(&err).unwrap()).unwrap();
        assert_eq!(back, err);
        assert_eq!(
            serde_json::to_string(&RunnerError::BadConfig).unwrap(),
            "\"BadConfig\""
        );
        // Display comes from thiserror (Error impl included).
        assert_eq!(
            RunnerError::BadConfig.to_string(),
            "runner config invalid: bucket_count must be > 0"
        );
        assert!(err.to_string().contains("boom"));
    }

    #[test]
    fn invalid_record_is_a_calibration_error_not_a_panic() {
        let mut bad = hyp("a", 0.5, NOW);
        bad.probability = f64::NAN; // store validation must reject this
        let mut records = vec![bad];
        assert!(matches!(
            run(&mut records, NOW, &cfg(4)),
            Err(RunnerError::Calibration(_))
        ));
    }
}
