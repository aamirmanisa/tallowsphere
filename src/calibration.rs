//! Calibration job — batch resolution, overdue sweep, Brier score, and
//! calibration curves (task A4.1.2 core, interface §9).
//!
//! Wave A4 ("judgment quality") records every predictive call as a
//! [`Hypothesis`](crate::forecast::Hypothesis) *before* the outcome is
//! known. This module is the second half of that pipeline: the **resolution
//! job** that drives a [`HypothesisStore`] through its one-shot
//! `Open -> Resolved { outcome }` transition, the **overdue sweep** that
//! surfaces hypotheses past their deadline, and the **scoring layer**
//! (Brier, calibration curve, overconfidence) that turns the frozen
//! probability/outcome pairs into an auditable judgment-quality record.
//!
//! Everything here is a thin, pure layer over the canonical representation
//! in [`crate::forecast`] — the store shape, the validation rules, and the
//! per-record [`brier`](crate::forecast::brier) primitive are all re-used,
//! never re-implemented (single canonical representation; see the store
//! notes in `forecast.rs`).
//!
//! # Semantics
//! * [`resolve_batch`] applies `(id, outcome)` pairs **in order** against a
//!   store. A failure (unknown id, or an id already resolved) is recorded
//!   as an entry in [`ResolveSummary::failures`] and processing continues;
//!   the function never panics. Each success is one `resolved` count.
//!   Because resolutions apply in order, a duplicated id in one batch
//!   succeeds once and then fails with `already resolved` — the store's
//!   append-only, one-shot invariant is preserved exactly.
//! * [`overdue_open`] returns ids of `Open` records whose
//!   `deadline_ms <= now_ms`. The boundary is **inclusive** (a deadline
//!   exactly at `now_ms` is overdue); output is ascending by
//!   `(deadline_ms, id)` so it is deterministic under ties.
//! * [`brier_score`] is the arithmetic mean of the per-record Brier scores
//!   of the **resolved** records in the given slice (`Open` records are
//!   skipped, they have no outcome). `None` when no record is resolved —
//!   an empty mean is not a score of `0.0` (that would read as a perfect
//!   forecaster).
//! * [`calibration_curve`] bins resolved records into `bucket_count`
//!   equal-width buckets over `[0, 1]`. Buckets are half-open `[lo, hi)`,
//!   **except the last one which is closed** so `p = 1.0` lands in the
//!   final bucket; `p = 0.0` lands in the first. Only non-empty buckets
//!   are returned (empty buckets carry no information and would invite
//!   accidental mean-over-buckets bugs), ascending by `lower`.
//!   `bucket_count == 0` returns an empty vector (avoids division by
//!   zero).
//! * [`overconfidence`] is the mean of `predicted - observed` over the
//!   resolved records: **positive means overconfident** (claims were
//!   stated above their realized frequency). `None` when none resolved.
//!
//! Records are expected to be validated (`probability` finite in
//! `0.0..=1.0`); scoring skips nothing silently — the append-only store
//! guarantees at most one resolved record per id, so scoring over the full
//! history slice is the correct input (the `Open` originals are ignored).
//!
//! # Serde
//! All output types derive serde; the wire form is a plain decoder with no
//! validation on ingest, same discipline as `forecast.rs`.


use serde::{Deserialize, Serialize};

use crate::forecast::{Hypothesis, HypothesisState, HypothesisStore};

/// Outcome of applying a batch of resolutions to a [`HypothesisStore`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolveSummary {
    /// Number of resolutions that applied successfully.
    pub resolved: usize,
    /// `(id, error)` for each resolution that did not apply, in input
    /// order (error = the `ForecastError` display string: unknown id, or
    /// already resolved).
    pub failures: Vec<(String, String)>,
}

/// Apply `(id, outcome)` resolutions to `store` **in order**.
///
/// Each pair is dispatched through [`HypothesisStore::resolve`], which
/// appends a successor record (append-only: the original `Open` record is
/// left untouched) or refuses the transition. Refusals are collected into
/// [`ResolveSummary::failures`] instead of aborting the batch — a
/// resolution job over heterogeneous sources must not lose the valid
/// resolutions because one id was stale.
///
/// Never panics; failures carry the store's own error string.
pub fn resolve_batch(
    store: &mut HypothesisStore,
    resolutions: &[(String, bool)],
) -> ResolveSummary {
    let mut summary = ResolveSummary {
        resolved: 0,
        failures: Vec::new(),
    };
    for (id, outcome) in resolutions {
        match store.resolve(id, *outcome) {
            Ok(()) => summary.resolved += 1,
            Err(e) => summary.failures.push((id.clone(), e.to_string())),
        }
    }
    summary
}

/// Ids of still-`Open` records whose deadline has arrived.
///
/// `deadline_ms <= now_ms` is **inclusive**: a record whose deadline is
/// exactly `now_ms` is overdue (the deadline marks the first instant it can
/// be forced to resolution). Ascending by `(deadline_ms, id)` — deterministic
/// when deadlines tie. Resolved records are never reported.
pub fn overdue_open(records: &[Hypothesis], now_ms: i64) -> Vec<String> {
    let mut due: Vec<&Hypothesis> = records
        .iter()
        .filter(|h| h.is_open() && h.deadline_ms <= now_ms)
        .collect();
    due.sort_by(|a, b| {
        a.deadline_ms
            .cmp(&b.deadline_ms)
            .then_with(|| a.id.cmp(&b.id))
    });
    due.into_iter().map(|h| h.id.clone()).collect()
}

/// Mean Brier score over the resolved records in `records`.
///
/// `None` when no record is resolved. `Open` records contribute nothing.
pub fn brier_score(records: &[Hypothesis]) -> Option<f64> {
    let mut sum = 0.0;
    let mut n = 0usize;
    for h in records {
        if let Some(b) = h.brier() {
            sum += b;
            n += 1;
        }
    }
    (n > 0).then(|| sum / n as f64)
}

/// One equal-width bin of a [`calibration_curve`].
///
/// Interval is `[lower, upper)`, except the final bucket which is closed
/// (`p = 1.0` lands there).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CalibrationBucket {
    /// Lower edge, `i / bucket_count`.
    pub lower: f64,
    /// Upper edge, `(i + 1) / bucket_count`.
    pub upper: f64,
    /// Resolved records in this bucket.
    pub n: usize,
    /// Mean stated probability of the bucket's records.
    pub mean_predicted: f64,
    /// Mean outcome (`1.0` occurred, `0.0` did not) of the bucket's records.
    pub observed_rate: f64,
}

/// Bin resolved records into `bucket_count` equal-width buckets over `[0, 1]`.
///
/// Placement: `index = floor(p * bucket_count)`, clamped into range, so
/// `p = 1.0` lands in the last bucket and `p = 0.0` in the first. Only
/// non-empty buckets are returned, ascending by `lower`. `bucket_count == 0`
/// yields an empty vector; `Open` records are ignored.
pub fn calibration_curve(records: &[Hypothesis], bucket_count: usize) -> Vec<CalibrationBucket> {
    if bucket_count == 0 {
        return Vec::new();
    }
    // Per-bucket accumulators: (n, sum_predicted, sum_observed).
    let mut acc: Vec<(usize, f64, f64)> = vec![(0, 0.0, 0.0); bucket_count];
    for h in records {
        if let HypothesisState::Resolved { outcome } = h.state {
            // Float->int casts saturate in Rust, so NaN/out-of-range inputs
            // (unvalidated records) can never panic here; validated records
            // always land in a sensible bucket.
            let idx = ((h.probability * bucket_count as f64) as usize).min(bucket_count - 1);
            acc[idx].0 += 1;
            acc[idx].1 += h.probability;
            acc[idx].2 += if outcome { 1.0 } else { 0.0 };
        }
    }
    let mut buckets = Vec::new();
    for (i, (n, sum_p, sum_o)) in acc.into_iter().enumerate() {
        if n == 0 {
            continue;
        }
        buckets.push(CalibrationBucket {
            lower: i as f64 / bucket_count as f64,
            upper: (i + 1) as f64 / bucket_count as f64,
            n,
            mean_predicted: sum_p / n as f64,
            observed_rate: sum_o / n as f64,
        });
    }
    buckets
}

/// Mean `predicted - observed` over resolved records.
///
/// Positive = overconfident (stated probabilities ran ahead of what
/// actually happened); negative = underconfident. `None` when no record is
/// resolved.
pub fn overconfidence(records: &[Hypothesis]) -> Option<f64> {
    let mut sum = 0.0;
    let mut n = 0usize;
    for h in records {
        if let HypothesisState::Resolved { outcome } = h.state {
            let observed = if outcome { 1.0 } else { 0.0 };
            sum += h.probability - observed;
            n += 1;
        }
    }
    (n > 0).then(|| sum / n as f64)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hyp(id: &str, p: f64, deadline_ms: i64) -> Hypothesis {
        Hypothesis::new(id, format!("statement {id}"), p, format!("criteria {id}"), deadline_ms, Vec::new())
            .expect("valid test hypothesis")
    }

    fn resolved(id: &str, p: f64, outcome: bool, deadline_ms: i64) -> Hypothesis {
        let mut h = hyp(id, p, deadline_ms);
        h.resolve(outcome).unwrap();
        h
    }

    fn assert_close(a: f64, b: f64) {
        assert!((a - b).abs() < 1e-12, "expected {b}, got {a}");
    }

    // --- resolve_batch ------------------------------------------------------

    #[test]
    fn resolve_batch_happy_path_applies_in_order() {
        let mut store = HypothesisStore::new();
        store.append(hyp("a", 0.3, 1)).unwrap();
        store.append(hyp("b", 0.7, 2)).unwrap();
        store.append(hyp("c", 0.9, 3)).unwrap();

        let summary = resolve_batch(
            &mut store,
            &[
                ("c".to_string(), true),
                ("a".to_string(), false),
                ("b".to_string(), true),
            ],
        );
        assert_eq!(summary.resolved, 3);
        assert!(summary.failures.is_empty());
        // Append-only: 3 originals + 3 successors.
        assert_eq!(store.len(), 6);
        assert_eq!(
            store.current("a").unwrap().state,
            HypothesisState::Resolved { outcome: false }
        );
        assert_eq!(
            store.current("b").unwrap().state,
            HypothesisState::Resolved { outcome: true }
        );
        assert_eq!(
            store.current("c").unwrap().state,
            HypothesisState::Resolved { outcome: true }
        );
    }

    #[test]
    fn resolve_batch_records_unknown_id_and_continues() {
        let mut store = HypothesisStore::new();
        store.append(hyp("a", 0.5, 1)).unwrap();

        let summary = resolve_batch(
            &mut store,
            &[
                ("ghost".to_string(), true),
                ("a".to_string(), true),
            ],
        );
        assert_eq!(summary.resolved, 1);
        assert_eq!(summary.failures.len(), 1);
        assert_eq!(summary.failures[0].0, "ghost");
        assert!(
            summary.failures[0].1.contains("unknown"),
            "error string carries the store's reason: {}",
            summary.failures[0].1
        );
    }

    #[test]
    fn resolve_batch_double_resolve_fails_second_time() {
        let mut store = HypothesisStore::new();
        store.append(hyp("a", 0.5, 1)).unwrap();

        let summary = resolve_batch(
            &mut store,
            &[("a".to_string(), true), ("a".to_string(), false)],
        );
        assert_eq!(summary.resolved, 1);
        assert_eq!(summary.failures.len(), 1);
        assert_eq!(summary.failures[0].0, "a");
        assert!(summary.failures[0].1.contains("already resolved"));
        // One-shot resolution held: still one successor, outcome from first.
        assert_eq!(store.len(), 2);
        assert_eq!(
            store.current("a").unwrap().state,
            HypothesisState::Resolved { outcome: true }
        );
    }

    // --- overdue_open -------------------------------------------------------

    #[test]
    fn overdue_boundary_is_inclusive_and_output_ascending() {
        let now = 1_000_000i64;
        let records = vec![
            hyp("late", 0.5, now + 1),        // not yet due
            hyp("exact", 0.5, now),           // due: boundary inclusive
            resolved("done", 0.5, true, now - 10), // resolved: never reported
            hyp("past", 0.5, now - 500),      // due
            hyp("earlier", 0.5, now - 500),   // due, same deadline: id tiebreak
        ];
        assert_eq!(
            overdue_open(&records, now),
            vec![
                "earlier".to_string(),
                "past".to_string(),
                "exact".to_string(),
            ]
        );
    }

    #[test]
    fn overdue_open_empty_and_none_due() {
        assert!(overdue_open(&[], 10).is_empty());
        let records = vec![hyp("future", 0.5, 100)];
        assert!(overdue_open(&records, 99).is_empty());
        assert_eq!(overdue_open(&records, 100), vec!["future".to_string()]);
    }

    // --- brier_score --------------------------------------------------------

    #[test]
    fn brier_mean_over_mixed_outcomes_skips_open() {
        let records = vec![
            resolved("a", 0.9, true, 1),   // 0.01
            resolved("b", 0.1, false, 1),  // 0.01
            resolved("c", 0.5, true, 1),   // 0.25
            hyp("open", 0.9, 1),           // no outcome -> skipped
        ];
        assert_close(brier_score(&records).unwrap(), (0.01 + 0.01 + 0.25) / 3.0);
    }

    #[test]
    fn brier_score_none_without_resolutions() {
        assert_eq!(brier_score(&[]), None);
        let records = vec![hyp("a", 0.5, 1), hyp("b", 0.9, 1)];
        assert_eq!(brier_score(&records), None);
    }

    #[test]
    fn brier_score_reads_append_only_history_correctly() {
        // The natural input is `store.records()`: the Open original plus the
        // resolved successor. Only the successor may count.
        let mut store = HypothesisStore::new();
        store.append(hyp("a", 0.9, 1)).unwrap();
        store.resolve("a", true).unwrap();
        assert_close(brier_score(store.records()).unwrap(), 0.01);
    }

    // --- calibration_curve --------------------------------------------------

    #[test]
    fn curve_places_boundaries_and_omits_empty_buckets() {
        // bucket_count = 4: [0,.25) [.25,.5) [.5,.75) [.75,1.0]
        let records = vec![
            resolved("p0", 0.0, false, 1),   // bucket 0
            resolved("p1", 1.0, true, 1),    // bucket 3 (last bucket closed)
            resolved("p25", 0.25, false, 1), // bucket 1 (half-open: .25 excluded from 0)
            resolved("p85", 0.85, true, 1),  // bucket 3
            hyp("open", 0.99, 1),            // ignored
        ];
        let curve = calibration_curve(&records, 4);
        assert_eq!(curve.len(), 3, "bucket 2 is empty and omitted");

        // Ascending, non-empty only, with pinned edges.
        assert_eq!(curve[0].lower, 0.0);
        assert_eq!(curve[0].upper, 0.25);
        assert_eq!(curve[0].n, 1);
        assert_close(curve[0].mean_predicted, 0.0);
        assert_close(curve[0].observed_rate, 0.0);

        assert_eq!(curve[1].lower, 0.25);
        assert_eq!(curve[1].n, 1);
        assert_close(curve[1].mean_predicted, 0.25);
        assert_close(curve[1].observed_rate, 0.0);

        // Last bucket carries both 0.85 and 1.0, and its interval is closed.
        assert_eq!(curve[2].lower, 0.75);
        assert_eq!(curve[2].upper, 1.0);
        assert_eq!(curve[2].n, 2);
        assert_close(curve[2].mean_predicted, (0.85 + 1.0) / 2.0);
        assert_close(curve[2].observed_rate, 1.0);
    }

    #[test]
    fn curve_mean_and_rate_aggregate_within_a_bucket() {
        let records = vec![
            resolved("a", 0.1, true, 1),
            resolved("b", 0.2, false, 1),
        ];
        let curve = calibration_curve(&records, 5); // both in [0.0, 0.2) ... 0.2 -> bucket 1
        // 0.1 -> bucket 0; 0.2 -> bucket 1. Two non-empty buckets.
        assert_eq!(curve.len(), 2);
        assert_eq!(curve[0].n, 1);
        assert_close(curve[0].observed_rate, 1.0);
        assert_eq!(curve[1].n, 1);
        assert_close(curve[1].observed_rate, 0.0);
    }

    #[test]
    fn curve_edge_inputs() {
        assert!(calibration_curve(&[], 5).is_empty());
        assert!(calibration_curve(&[resolved("a", 0.5, true, 1)], 0).is_empty());
        // All-open: nothing resolved -> no buckets.
        assert!(calibration_curve(&[hyp("a", 0.5, 1)], 5).is_empty());
        // Single bucket swallows [0,1] with p=1.0 landing in it.
        let curve = calibration_curve(&[resolved("a", 1.0, true, 1)], 1);
        assert_eq!(curve.len(), 1);
        assert_eq!(curve[0].lower, 0.0);
        assert_eq!(curve[0].upper, 1.0);
        assert_eq!(curve[0].n, 1);
    }

    // --- overconfidence -----------------------------------------------------

    #[test]
    fn overconfidence_sign() {
        // Overconfident: says 0.8, never happens -> +0.8.
        let over = vec![
            resolved("a", 0.8, false, 1),
            resolved("b", 0.8, false, 1),
        ];
        assert_close(overconfidence(&over).unwrap(), 0.8);

        // Mixed: mean predicted 0.8, observed rate 0.5 -> +0.3.
        let mixed = vec![
            resolved("a", 0.8, true, 1),
            resolved("b", 0.8, false, 1),
        ];
        assert_close(overconfidence(&mixed).unwrap(), 0.3);

        // Underconfident: says 0.2, always happens -> -0.8.
        let under = vec![resolved("a", 0.2, true, 1)];
        assert_close(overconfidence(&under).unwrap(), -0.8);

        // Perfectly calibrated single call.
        assert_close(overconfidence(&[resolved("a", 1.0, true, 1)]).unwrap(), 0.0);

        assert_eq!(overconfidence(&[]), None);
        assert_eq!(overconfidence(&[hyp("a", 0.5, 1)]), None);
    }

    // --- serde ---------------------------------------------------------------

    #[test]
    fn outputs_serde_round_trip() {
        let summary = ResolveSummary {
            resolved: 2,
            failures: vec![("ghost".to_string(), "hypothesis ghost is unknown".to_string())],
        };
        let back: ResolveSummary =
            serde_json::from_str(&serde_json::to_string(&summary).unwrap()).unwrap();
        assert_eq!(back, summary);

        let bucket = CalibrationBucket {
            lower: 0.0,
            upper: 0.25,
            n: 3,
            mean_predicted: 0.1,
            observed_rate: 0.0,
        };
        let back: CalibrationBucket =
            serde_json::from_str(&serde_json::to_string(&bucket).unwrap()).unwrap();
        assert_eq!(back, bucket);
    }

    // --- determinism --------------------------------------------------------

    #[test]
    fn scoring_is_deterministic() {
        let records = vec![
            resolved("a", 0.1, false, 1),
            resolved("b", 0.9, true, 1),
            resolved("c", 0.5, false, 1),
            hyp("open", 0.6, 1),
        ];
        assert_eq!(brier_score(&records), brier_score(&records));
        assert_eq!(overconfidence(&records), overconfidence(&records));
        assert_eq!(
            calibration_curve(&records, 5),
            calibration_curve(&records, 5)
        );
        assert_eq!(overdue_open(&records, 1), overdue_open(&records, 1));

        // resolve_batch determinism: identical stores -> identical summaries.
        let mut s1 = HypothesisStore::new();
        let mut s2 = HypothesisStore::new();
        for h in [hyp("a", 0.5, 1), hyp("b", 0.5, 1)] {
            s1.append(h.clone()).unwrap();
            s2.append(h).unwrap();
        }
        let pairs = vec![
            ("a".to_string(), true),
            ("b".to_string(), false),
            ("ghost".to_string(), true),
        ];
        assert_eq!(resolve_batch(&mut s1, &pairs), resolve_batch(&mut s2, &pairs));
    }
}
