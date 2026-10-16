//! Degraded-state detectors + irreversible-op gate (task A7.1.1 / spec E17).
//!
//! The agent loop must notice when *it* is degrading — before it spends the
//! rest of a run retrying a broken op, and before a wrecked state can trigger
//! an irreversible action (delete, send, publish, spend). This module is the
//! pure, testable core of that governor:
//!
//! * [`detect`] classifies a slice of ordered [`AttemptOutcome`]s into
//!   [`DegradedReason`]s — failure **streak**, retry **spiral**, error
//!   **storm**.
//! * [`detect_feedback`] classifies ordered [`FeedbackEvent`]s into the
//!   fourth E17 detector class — **anomalous tool feedback** (success
//!   reported without evidence, repeated per tool).
//! * [`gate_op`] decides whether an operation may proceed given those
//!   reasons. **Irreversible ops are blocked while any reason is present**;
//!   low-risk (reversible / read-only) ops proceed, with the reasons echoed
//!   for observability.
//!
//! # Purity contract
//! Both functions are **pure and deterministic**: no clock, no IO, no
//! randomness. "Now" is the `ts_ms` of the **last** attempt in the slice; the
//! caller passes the observations it already recorded. The slice is assumed
//! to be **ordered oldest → newest**: slice order is authoritative for
//! streaks, `ts_ms` selects the trailing window.
//!
//! # Detector semantics
//! Let `now = attempts.last().ts_ms` and `W = thresholds.error_rate_window_ms`
//! (trailing window `[now - W, now]`, **inclusive** on both ends).
//!
//! ```text
//! FailureStreak { len }   trailing run of consecutive ok == false (slice
//!                         order, across all ops) with len >= failure_streak
//! RetrySpiral { op, len } some op class inside the window has a run of
//!                         len >= retry_spiral consecutive same-op failures
//!                         (a success breaks the run; longest run per op)
//! ErrorStorm { rate }     failures / attempts over the window >= error_rate
//! ```
//!
//! Disabling convention: a count threshold of `0`, a rate `<= 0.0`, or a
//! window `<= 0` disables that detector. Disabled detectors failing open is
//! deliberate — the thresholds are the operator's policy knobs.
//!
//! Reasons are emitted in a stable order: `FailureStreak` first, then
//! `RetrySpiral`s sorted by op name, then `ErrorStorm`. Multiple reasons may
//! fire together.
//!
//! # Defaults (documented per interface §5)
//! [`Thresholds::default`]: `failure_streak = 5`, `retry_spiral = 5`,
//! `error_rate_window_ms = 60_000` (one minute), `error_rate = 0.5`. These
//! are policy breakpoints — five straight failures is past bad luck, five
//! same-op failures inside a minute is a loop, half a window failing is a
//! storm — not physics.
//!
//! # Anomalous feedback (4th detector, interface §1)
//! [`detect_feedback`] scans [`FeedbackEvent`]s in slice order. A streak is a
//! maximal run of consecutive events **for one tool** with `reported_ok &&
//! !evidence_nonempty`; any other event for that tool resets it, while other
//! tools' events do not interrupt it. When a tool's longest streak reaches
//! [`FeedbackThresholds::min_streak`] (default 3; `0` disables the detector),
//! one [`DegradedReason::AnomalousFeedback`] is emitted for that tool, and the
//! output is ordered by each tool's first offending streak in input order.
//!
//! # Wiring
//! No call site is wired here; the parent integrates this gate (A7.1.1).
//!
//! ```text
//! let reasons = detect(&attempts, &Thresholds::default());
//! let verdict = gate_op(/* irreversible = */ true, &reasons);
//! if !verdict.allowed { /* report + stop the irreversible op */ }
//! ```

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// One recorded attempt outcome — the observation input to [`detect`].
///
/// `kind` is the **op class** (e.g. `"http.fetch"`, `"db.write"`): the unit
/// the retry-spiral detector groups by. `ts_ms` is caller-supplied wall-clock
/// milliseconds; this module never reads a clock.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AttemptOutcome {
    /// Whether the attempt succeeded.
    pub ok: bool,
    /// Op class the attempt belongs to.
    pub kind: String,
    /// Caller's timestamp in milliseconds (ordering key for the window).
    pub ts_ms: i64,
}

/// Detector thresholds. See the module docs for defaults and the disable
/// convention (`0` counts, `<= 0.0` rate, `<= 0` window disable a detector).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Thresholds {
    /// Consecutive trailing failures that constitute a streak.
    pub failure_streak: usize,
    /// Consecutive same-op failures inside the window that constitute a spiral.
    pub retry_spiral: usize,
    /// Trailing window length in milliseconds (shared by spiral + storm).
    pub error_rate_window_ms: i64,
    /// Failure-rate threshold over the window, inclusive (`0.0 ..= 1.0`).
    pub error_rate: f64,
}

impl Default for Thresholds {
    fn default() -> Self {
        Self {
            failure_streak: 5,
            retry_spiral: 5,
            error_rate_window_ms: 60_000,
            error_rate: 0.5,
        }
    }
}

/// One recorded tool-feedback event — the observation input to
/// [`detect_feedback`] (task A7.1.1 / spec E17, anomalous tool feedback).
///
/// The anomaly this detector watches for: a tool **reports success but
/// carries no evidence** (`reported_ok && !evidence_nonempty`) on consecutive
/// events. `ts_ms` is caller-supplied wall-clock milliseconds, recorded for
/// audit; slice order is the authoritative ordering, never the clock.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedbackEvent {
    /// Tool name — the unit streaks are grouped by.
    pub tool: String,
    /// Whether the tool reported success for this event.
    pub reported_ok: bool,
    /// Whether the event carried non-empty evidence backing the report.
    pub evidence_nonempty: bool,
    /// Caller's timestamp in milliseconds (audit field; not an ordering key).
    pub ts_ms: i64,
}

/// Thresholds for [`detect_feedback`] (the 4th E17 detector). Disable
/// convention: `min_streak == 0` disables the detector, matching the
/// module-wide convention for count thresholds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FeedbackThresholds {
    /// Consecutive anomalous feedback events (for one tool) that constitute a
    /// streak. `0` disables the detector.
    pub min_streak: usize,
}

impl Default for FeedbackThresholds {
    /// Documented default: `min_streak = 3` — three consecutive
    /// success-without-evidence reports from the same tool is past
    /// coincidence, not physics (same policy-breakpoint style as
    /// [`Thresholds`]).
    fn default() -> Self {
        Self { min_streak: 3 }
    }
}

/// Why the run is considered degraded. Serde-serializable for audit records.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DegradedReason {
    /// `len` consecutive trailing failures, across all ops (slice order).
    FailureStreak { len: usize },
    /// Op class `op` failed `len` times in a row inside the trailing window.
    RetrySpiral { op: String, len: usize },
    /// Failure rate `rate` over the trailing window is at/above threshold.
    ErrorStorm { rate: f64 },
    /// Tool `tool` reported success without evidence `len` consecutive times
    /// (longest anomalous streak for that tool; see [`detect_feedback`]).
    AnomalousFeedback { tool: String, len: usize },
}

impl std::fmt::Display for DegradedReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DegradedReason::FailureStreak { len } => {
                write!(f, "failure streak: {len} consecutive failures")
            }
            DegradedReason::RetrySpiral { op, len } => write!(
                f,
                "retry spiral: op `{op}` failed {len} times in a row in the window"
            ),
            DegradedReason::ErrorStorm { rate } => {
                write!(f, "error storm: failure rate {rate:.3} over the trailing window")
            }
            DegradedReason::AnomalousFeedback { tool, len } => {
                write!(
                    f,
                    "anomalous tool feedback: {tool} x{len} (success reported without evidence)"
                )
            }
        }
    }
}

/// Pure detector: classify ordered attempt outcomes into degraded reasons.
///
/// See the module docs for the exact detector conditions, the trailing-window
/// anchor (last attempt's `ts_ms`, inclusive bounds), and the stable output
/// order. Empty input yields no reasons. Same input always yields the same
/// output.
pub fn detect(attempts: &[AttemptOutcome], t: &Thresholds) -> Vec<DegradedReason> {
    let mut reasons = Vec::new();
    if attempts.is_empty() {
        return reasons;
    }

    // ── STREAK: trailing consecutive failures, slice order, all ops. ────────
    if t.failure_streak > 0 {
        let len = attempts.iter().rev().take_while(|a| !a.ok).count();
        if len >= t.failure_streak {
            reasons.push(DegradedReason::FailureStreak { len });
        }
    }

    // ── Window-based detectors (spiral + storm) ─────────────────────────────
    let window_ms = t.error_rate_window_ms;
    if window_ms <= 0 {
        return reasons;
    }
    let last_ts = attempts[attempts.len() - 1].ts_ms;
    let since = last_ts.saturating_sub(window_ms); // inclusive lower bound

    // Group in-window attempts by op class, preserving slice order per op.
    // BTreeMap keeps op iteration deterministic (lexicographic by name).
    let mut by_op: BTreeMap<&str, Vec<bool>> = BTreeMap::new();
    let mut win_total: usize = 0;
    let mut win_fail: usize = 0;
    for a in attempts.iter().filter(|a| a.ts_ms >= since) {
        win_total += 1;
        if !a.ok {
            win_fail += 1;
        }
        by_op.entry(a.kind.as_str()).or_default().push(a.ok);
    }

    // ── SPIRAL: longest same-op failure run inside the window. ──────────────
    if t.retry_spiral > 0 {
        for (op, oks) in &by_op {
            let mut best = 0usize;
            let mut run = 0usize;
            for ok in oks {
                if *ok {
                    run = 0; // a success breaks the retry run
                } else {
                    run += 1;
                    best = best.max(run);
                }
            }
            if best >= t.retry_spiral {
                reasons.push(DegradedReason::RetrySpiral { op: (*op).to_string(), len: best });
            }
        }
    }

    // ── STORM: failure rate over the window. ────────────────────────────────
    if t.error_rate > 0.0 && win_total > 0 {
        let rate = win_fail as f64 / win_total as f64;
        if rate >= t.error_rate {
            reasons.push(DegradedReason::ErrorStorm { rate });
        }
    }

    reasons
}

/// Pure detector: classify ordered feedback events into degraded reasons —
/// **anomalous tool feedback** (success reported without evidence, repeated).
///
/// See the module docs for the exact streak semantics, the per-tool reset
/// rule, the disable convention (`min_streak == 0`), and the stable output
/// order. Empty input yields no reasons; same input always yields the same
/// output; never panics.
pub fn detect_feedback(events: &[FeedbackEvent], t: &FeedbackThresholds) -> Vec<DegradedReason> {
    if events.is_empty() || t.min_streak == 0 {
        return Vec::new();
    }

    // Per-tool streak-tracking state for the single left-to-right scan.
    #[derive(Default)]
    struct Streak {
        run_len: usize,                        // length of the currently open run
        run_start: usize,                      // input index where that run began
        best_len: usize,                       // longest maximal streak so far
        first_offending_start: Option<usize>,  // first run to reach min_streak
    }

    let mut by_tool: BTreeMap<&str, Streak> = BTreeMap::new();
    for (i, e) in events.iter().enumerate() {
        let s = by_tool.entry(e.tool.as_str()).or_default();
        if e.reported_ok && !e.evidence_nonempty {
            if s.run_len == 0 {
                s.run_start = i;
            }
            s.run_len += 1;
            if s.first_offending_start.is_none() && s.run_len >= t.min_streak {
                s.first_offending_start = Some(s.run_start);
            }
            if s.run_len > s.best_len {
                s.best_len = s.run_len;
            }
        } else {
            s.run_len = 0; // any other event for this tool resets its streak
        }
    }

    // One reason per tool whose longest streak reached the threshold, anchored
    // at the tool's first offending streak; sorting by that input index puts
    // the output in input order (indices are unique, so this is total).
    let mut found: Vec<(usize, DegradedReason)> = by_tool
        .into_iter()
        .filter(|(_, s)| s.best_len >= t.min_streak)
        .map(|(tool, s)| {
            let order_key = s.first_offending_start.unwrap_or(usize::MAX);
            (
                order_key,
                DegradedReason::AnomalousFeedback { tool: tool.to_string(), len: s.best_len },
            )
        })
        .collect();
    found.sort_by_key(|(order_key, _)| *order_key);
    found.into_iter().map(|(_, reason)| reason).collect()
}

/// Verdict for one operation produced by [`gate_op`].
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GateVerdict {
    /// Whether the operation may proceed.
    pub allowed: bool,
    /// The degraded-state reasons considered (empty = healthy). Echoed on
    /// both allow and block so callers can log the rationale.
    pub reasons: Vec<DegradedReason>,
}

/// Gate policy: an **irreversible** op is blocked while ANY degraded reason is
/// present; a healthy run allows it. Low-risk (reversible / read-only) ops are
/// always allowed — the reasons are still echoed for observability.
pub fn gate_op(irreversible: bool, reasons: &[DegradedReason]) -> GateVerdict {
    let allowed = !irreversible || reasons.is_empty();
    GateVerdict { allowed, reasons: reasons.to_vec() }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn att(ok: bool, kind: &str, ts_ms: i64) -> AttemptOutcome {
        AttemptOutcome { ok, kind: kind.to_string(), ts_ms }
    }

    /// Thresholds with every detector disabled — each test enables exactly
    /// what it probes, so fired reasons are unambiguous.
    fn quiet() -> Thresholds {
        Thresholds {
            failure_streak: 0,
            retry_spiral: 0,
            error_rate_window_ms: 1_000,
            error_rate: 0.0,
        }
    }

    #[test]
    fn empty_input_yields_no_reasons() {
        assert!(detect(&[], &Thresholds::default()).is_empty());
    }

    #[test]
    fn default_thresholds_are_the_documented_values() {
        assert_eq!(
            Thresholds::default(),
            Thresholds {
                failure_streak: 5,
                retry_spiral: 5,
                error_rate_window_ms: 60_000,
                error_rate: 0.5,
            }
        );
    }

    #[test]
    fn streak_fires_at_threshold_with_len() {
        let t = Thresholds { failure_streak: 3, ..quiet() };
        let attempts = [
            att(true, "a", 1),
            att(false, "a", 2),
            att(false, "b", 3),
            att(false, "a", 4),
        ];
        assert_eq!(detect(&attempts, &t), vec![DegradedReason::FailureStreak { len: 3 }]);
    }

    #[test]
    fn streak_below_threshold_is_silent() {
        let t = Thresholds { failure_streak: 3, ..quiet() };
        let attempts = [att(true, "a", 1), att(true, "a", 2), att(false, "a", 3), att(false, "a", 4)];
        assert!(detect(&attempts, &t).is_empty(), "streak of 2 must not fire at threshold 3");
    }

    #[test]
    fn streak_resets_after_success_and_counts_only_the_trailing_run() {
        let t = Thresholds { failure_streak: 3, ..quiet() };
        // A success after three failures resets the streak to zero.
        let reset = [att(false, "a", 1), att(false, "a", 2), att(false, "a", 3), att(true, "a", 4)];
        assert!(detect(&reset, &t).is_empty(), "trailing success must reset the streak");

        // Only the TRAILING run is reported (3), not the whole failure count (5).
        let trailing = [
            att(false, "a", 1),
            att(false, "a", 2),
            att(true, "a", 3),
            att(false, "a", 4),
            att(false, "a", 5),
            att(false, "a", 6),
        ];
        assert_eq!(detect(&trailing, &t), vec![DegradedReason::FailureStreak { len: 3 }]);
    }

    #[test]
    fn streak_disabled_when_threshold_zero() {
        let t = quiet(); // failure_streak == 0
        let attempts = [att(false, "a", 1), att(false, "a", 2), att(false, "a", 3)];
        assert!(
            !detect(&attempts, &t)
                .iter()
                .any(|r| matches!(r, DegradedReason::FailureStreak { .. })),
            "threshold 0 must disable streak detection"
        );
    }

    #[test]
    fn spiral_fires_on_same_op_failure_cluster() {
        let t = Thresholds { retry_spiral: 3, ..quiet() };
        let attempts = [
            att(false, "db.write", 9_400),
            att(false, "db.write", 9_600),
            att(false, "db.write", 9_800),
            att(false, "db.write", 10_000),
        ];
        assert_eq!(
            detect(&attempts, &t),
            vec![DegradedReason::RetrySpiral { op: "db.write".to_string(), len: 4 }],
            "four same-op failures in a row must spiral"
        );
    }

    #[test]
    fn spiral_run_is_broken_by_a_success() {
        let t = Thresholds { retry_spiral: 3, ..quiet() };
        // f, ok, f, f -> runs of 1 and 2, no run reaches 3.
        let broken = [
            att(false, "x", 9_700),
            att(true, "x", 9_800),
            att(false, "x", 9_850),
            att(false, "x", 9_900),
        ];
        assert!(detect(&broken, &t).is_empty(), "a success breaks the retry run");

        // f, f, f -> run of 3 fires.
        let run = [att(false, "x", 9_700), att(false, "x", 9_800), att(false, "x", 9_900)];
        assert_eq!(detect(&run, &t), vec![DegradedReason::RetrySpiral { op: "x".to_string(), len: 3 }]);
    }

    #[test]
    fn spiral_window_boundary_is_inclusive_and_excludes_older_attempts() {
        let t = Thresholds { retry_spiral: 3, ..quiet() }; // window 1000ms
        let attempts = [
            att(false, "x", 8_999),  // outside: now - 1000 = 9000
            att(false, "x", 9_000),  // boundary: included
            att(false, "x", 9_500),
            att(false, "x", 10_000), // now
        ];
        assert_eq!(
            detect(&attempts, &t),
            vec![DegradedReason::RetrySpiral { op: "x".to_string(), len: 3 }],
            "len must be 3, not 4: the 8_999 failure is outside [9000, 10000]"
        );

        // Only old failures -> nothing to report.
        let old_only = [
            att(false, "svc", 1_000),
            att(false, "svc", 1_100),
            att(false, "svc", 1_200),
            att(false, "svc", 1_300),
            att(true, "svc", 9_900),
            att(true, "svc", 10_000),
        ];
        assert!(detect(&old_only, &t).is_empty(), "failures before the window must not spiral");
    }

    #[test]
    fn interleaved_ops_do_not_merge_into_a_spiral() {
        // Global trailing streak fires, but per-op runs (2 each) are below the
        // spiral threshold — the two detectors must stay distinct.
        let t = Thresholds { failure_streak: 4, retry_spiral: 3, ..quiet() };
        let attempts = [
            att(false, "a", 9_700),
            att(false, "b", 9_800),
            att(false, "a", 9_900),
            att(false, "b", 10_000),
        ];
        assert_eq!(detect(&attempts, &t), vec![DegradedReason::FailureStreak { len: 4 }]);
    }

    #[test]
    fn storm_fires_at_or_above_rate() {
        let t = Thresholds { error_rate: 0.5, ..quiet() };
        // Below: 1/3.
        let below = [att(true, "a", 9_500), att(false, "a", 9_700), att(true, "a", 9_900)];
        assert!(detect(&below, &t).is_empty(), "1/3 < 0.5 must not storm");

        // Exactly at threshold: 1/2 fires (inclusive >=).
        let at = [att(true, "a", 9_800), att(false, "a", 10_000)];
        assert_eq!(detect(&at, &t), vec![DegradedReason::ErrorStorm { rate: 0.5 }]);

        // Above: 3/4.
        let above = [
            att(false, "a", 9_400),
            att(false, "a", 9_600),
            att(false, "a", 9_800),
            att(true, "a", 10_000),
        ];
        assert_eq!(detect(&above, &t), vec![DegradedReason::ErrorStorm { rate: 0.75 }]);
    }

    #[test]
    fn storm_window_excludes_older_attempts() {
        let t = Thresholds { error_rate: 0.75, ..quiet() }; // window 1000ms
        let attempts = [
            att(false, "a", 8_999), // outside [9000, 10000] — would make 3/4 >= 0.75
            att(false, "a", 9_000), // boundary: included
            att(true, "a", 9_500),
            att(false, "a", 10_000),
        ];
        assert!(
            detect(&attempts, &t).is_empty(),
            "in-window rate is 2/3 < 0.75; the 8_999 failure must be excluded"
        );

        // Boundary attempt alone pushes it over: 3/3.
        let with_boundary = [
            att(false, "a", 9_000),
            att(false, "a", 9_500),
            att(false, "a", 10_000),
        ];
        assert_eq!(detect(&with_boundary, &t), vec![DegradedReason::ErrorStorm { rate: 1.0 }]);
    }

    #[test]
    fn storm_disabled_when_rate_threshold_is_zero() {
        let t = Thresholds { error_rate: 0.0, ..quiet() };
        let attempts = [att(false, "a", 9_900), att(false, "a", 10_000)];
        assert!(
            !detect(&attempts, &t)
                .iter()
                .any(|r| matches!(r, DegradedReason::ErrorStorm { .. })),
            "rate 0.0 must disable storm detection"
        );
    }

    #[test]
    fn non_positive_window_disables_window_detectors_but_not_streak() {
        let t = Thresholds {
            failure_streak: 3,
            retry_spiral: 3,
            error_rate_window_ms: 0,
            error_rate: 0.5,
        };
        let attempts = [att(false, "x", 1), att(false, "x", 2), att(false, "x", 3)];
        assert_eq!(
            detect(&attempts, &t),
            vec![DegradedReason::FailureStreak { len: 3 }],
            "window 0 disables spiral + storm; streak is order-based and still fires"
        );

        let negative = Thresholds { error_rate_window_ms: -5, ..t.clone() };
        assert_eq!(detect(&attempts, &negative), vec![DegradedReason::FailureStreak { len: 3 }]);
    }

    #[test]
    fn all_reasons_fire_together_in_stable_order() {
        let t = Thresholds { failure_streak: 3, retry_spiral: 3, ..quiet() };
        let t = Thresholds { error_rate: 0.5, ..t };
        let attempts = [
            att(false, "x", 9_400),
            att(false, "x", 9_600),
            att(false, "x", 9_800),
            att(false, "x", 10_000),
        ];
        assert_eq!(
            detect(&attempts, &t),
            vec![
                DegradedReason::FailureStreak { len: 4 },
                DegradedReason::RetrySpiral { op: "x".to_string(), len: 4 },
                DegradedReason::ErrorStorm { rate: 1.0 },
            ],
            "order: streak, spirals by op, storm"
        );

        // Two spiraling ops are reported in deterministic (lexicographic) order.
        let t2 = Thresholds { failure_streak: 0, error_rate: 0.0, ..t };
        let two_ops = [
            att(false, "b.op", 9_700),
            att(false, "a.op", 9_750),
            att(false, "b.op", 9_800),
            att(false, "a.op", 9_850),
            att(false, "b.op", 9_900),
            att(false, "a.op", 9_950),
        ];
        assert_eq!(
            detect(&two_ops, &t2),
            vec![
                DegradedReason::RetrySpiral { op: "a.op".to_string(), len: 3 },
                DegradedReason::RetrySpiral { op: "b.op".to_string(), len: 3 },
            ]
        );
    }

    #[test]
    fn detect_is_deterministic() {
        let t = Thresholds { failure_streak: 3, retry_spiral: 2, error_rate: 0.4, ..quiet() };
        let attempts = [
            att(false, "x", 9_400),
            att(true, "y", 9_500),
            att(false, "x", 9_600),
            att(false, "y", 9_700),
            att(false, "x", 9_800),
            att(false, "x", 10_000),
        ];
        assert_eq!(detect(&attempts, &t), detect(&attempts, &t));
    }

    #[test]
    fn gate_blocks_irreversible_while_degraded_and_allows_low_risk() {
        let reasons = vec![DegradedReason::FailureStreak { len: 5 }];

        let blocked = gate_op(true, &reasons);
        assert!(!blocked.allowed, "irreversible op must be blocked while degraded");
        assert_eq!(blocked.reasons, reasons, "reasons echoed on block");

        let low_risk = gate_op(false, &reasons);
        assert!(low_risk.allowed, "low-risk op proceeds despite degraded state");
        assert_eq!(low_risk.reasons, reasons, "reasons echoed for observability");
    }

    #[test]
    fn gate_allows_irreversible_when_healthy() {
        let verdict = gate_op(true, &[]);
        assert!(verdict.allowed);
        assert!(verdict.reasons.is_empty());
    }

    #[test]
    fn serde_round_trip_all_types() {
        let a = att(true, "http.fetch", 1_700_000_000_000);
        let json = serde_json::to_string(&a).unwrap();
        let back: AttemptOutcome = serde_json::from_str(&json).unwrap();
        assert_eq!(back, a);

        let t = Thresholds::default();
        let json = serde_json::to_string(&t).unwrap();
        let back: Thresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);

        let reasons = [
            DegradedReason::FailureStreak { len: 3 },
            DegradedReason::RetrySpiral { op: "x".to_string(), len: 2 },
            DegradedReason::ErrorStorm { rate: 0.75 },
        ];
        for r in &reasons {
            let json = serde_json::to_string(r).unwrap();
            let back: DegradedReason = serde_json::from_str(&json).unwrap();
            assert_eq!(back, *r);
        }

        // Pin the externally-tagged wire shape used by audit records.
        assert_eq!(
            serde_json::to_string(&DegradedReason::FailureStreak { len: 3 }).unwrap(),
            r#"{"FailureStreak":{"len":3}}"#
        );

        let v = GateVerdict { allowed: false, reasons: reasons.to_vec() };
        let json = serde_json::to_string(&v).unwrap();
        let back: GateVerdict = serde_json::from_str(&json).unwrap();
        assert_eq!(back, v);

        // Offline: reconstructing a reason from an audit record works.
        let r: DegradedReason =
            serde_json::from_str(r#"{"RetrySpiral":{"op":"db.write","len":5}}"#).unwrap();
        assert_eq!(r, DegradedReason::RetrySpiral { op: "db.write".to_string(), len: 5 });
    }

    // ── FeedbackEvent / detect_feedback (4th E17 detector, interface §1) ───

    fn fb(tool: &str, reported_ok: bool, evidence_nonempty: bool, ts_ms: i64) -> FeedbackEvent {
        FeedbackEvent { tool: tool.to_string(), reported_ok, evidence_nonempty, ts_ms }
    }

    /// Shorthand: the anomalous shape — success reported, no evidence.
    fn fb_anom(tool: &str, ts_ms: i64) -> FeedbackEvent {
        fb(tool, true, false, ts_ms)
    }

    #[test]
    fn feedback_default_thresholds_are_the_documented_values() {
        assert_eq!(FeedbackThresholds::default(), FeedbackThresholds { min_streak: 3 });
    }

    #[test]
    fn feedback_streak_at_threshold_fires_once_with_len() {
        let t = FeedbackThresholds { min_streak: 3 };
        let events = [fb_anom("web.search", 1), fb_anom("web.search", 2), fb_anom("web.search", 3)];
        assert_eq!(
            detect_feedback(&events, &t),
            vec![DegradedReason::AnomalousFeedback { tool: "web.search".to_string(), len: 3 }],
            "exactly one reason once the streak reaches the threshold"
        );
    }

    #[test]
    fn feedback_above_threshold_reports_the_longest_streak() {
        let t = FeedbackThresholds { min_streak: 3 };
        let events: Vec<FeedbackEvent> = (0..5).map(|i| fb_anom("shell.exec", i)).collect();
        assert_eq!(
            detect_feedback(&events, &t),
            vec![DegradedReason::AnomalousFeedback { tool: "shell.exec".to_string(), len: 5 }],
            "one reason per tool, for its longest streak"
        );
    }

    #[test]
    fn feedback_below_threshold_is_silent() {
        let t = FeedbackThresholds { min_streak: 3 };
        let events = [fb_anom("x", 1), fb_anom("x", 2)];
        assert!(
            detect_feedback(&events, &t).is_empty(),
            "streak of 2 must not fire at threshold 3"
        );
    }

    #[test]
    fn feedback_streak_resets_on_any_other_event_for_that_tool() {
        let t = FeedbackThresholds { min_streak: 3 };
        // A reported failure resets the run: a, a, FAIL, a, a -> longest run 2.
        let by_failure = [
            fb_anom("t", 1),
            fb_anom("t", 2),
            fb("t", false, false, 3),
            fb_anom("t", 4),
            fb_anom("t", 5),
        ];
        assert!(detect_feedback(&by_failure, &t).is_empty(), "a failure must reset the streak");

        // A success WITH evidence is also "any other event" -> it resets too.
        let by_evidence = [
            fb_anom("t", 1),
            fb_anom("t", 2),
            fb("t", true, true, 3),
            fb_anom("t", 4),
            fb_anom("t", 5),
        ];
        assert!(
            detect_feedback(&by_evidence, &t).is_empty(),
            "an evidenced success resets the streak"
        );
    }

    #[test]
    fn feedback_events_of_other_tools_do_not_interrupt_a_streak() {
        let t = FeedbackThresholds { min_streak: 3 };
        let events = [
            fb_anom("a", 1),
            fb_anom("b", 2),
            fb_anom("a", 3),
            fb_anom("b", 4),
            fb_anom("a", 5),
            fb_anom("b", 6),
        ];
        assert_eq!(
            detect_feedback(&events, &t),
            vec![
                DegradedReason::AnomalousFeedback { tool: "a".to_string(), len: 3 },
                DegradedReason::AnomalousFeedback { tool: "b".to_string(), len: 3 },
            ],
            "per-tool streaks survive interleaving; output follows input order"
        );
    }

    #[test]
    fn feedback_multiple_tools_are_independent() {
        let t = FeedbackThresholds { min_streak: 3 };
        // b's streak reaches 3; a's longest run is 2 -> only b fires.
        let events = [
            fb_anom("b", 1),
            fb_anom("a", 2),
            fb_anom("b", 3),
            fb("a", false, false, 4),
            fb_anom("b", 5),
            fb_anom("a", 6),
            fb_anom("a", 7),
        ];
        assert_eq!(
            detect_feedback(&events, &t),
            vec![DegradedReason::AnomalousFeedback { tool: "b".to_string(), len: 3 }],
            "tools are tracked independently"
        );
    }

    #[test]
    fn feedback_output_order_follows_input_not_tool_name() {
        let t = FeedbackThresholds { min_streak: 2 };
        // `z` offends first (index 0), `a` later (index 3): input order wins
        // over the lexicographic op order used by the spiral detector.
        let events = [
            fb_anom("z", 1),
            fb_anom("z", 2),
            fb("z", false, false, 3),
            fb_anom("a", 4),
            fb_anom("a", 5),
        ];
        assert_eq!(
            detect_feedback(&events, &t),
            vec![
                DegradedReason::AnomalousFeedback { tool: "z".to_string(), len: 2 },
                DegradedReason::AnomalousFeedback { tool: "a".to_string(), len: 2 },
            ]
        );
    }

    #[test]
    fn feedback_disabled_when_min_streak_is_zero() {
        let t = FeedbackThresholds { min_streak: 0 };
        let events = [fb_anom("x", 1), fb_anom("x", 2), fb_anom("x", 3), fb_anom("x", 4)];
        assert!(detect_feedback(&events, &t).is_empty(), "min_streak 0 disables the detector");
        assert!(detect_feedback(&[], &FeedbackThresholds::default()).is_empty());
    }

    #[test]
    fn feedback_detector_is_deterministic() {
        let t = FeedbackThresholds { min_streak: 2 };
        let events = [
            fb_anom("b", 1),
            fb("a", true, true, 2),
            fb_anom("b", 3),
            fb_anom("a", 4),
            fb_anom("a", 5),
            fb_anom("b", 6),
        ];
        assert_eq!(detect_feedback(&events, &t), detect_feedback(&events, &t));
    }

    #[test]
    fn feedback_display_text_is_the_documented_phrase() {
        let r = DegradedReason::AnomalousFeedback { tool: "web.search".to_string(), len: 3 };
        assert_eq!(
            r.to_string(),
            "anomalous tool feedback: web.search x3 (success reported without evidence)"
        );
    }

    #[test]
    fn feedback_serde_round_trip_and_wire_shape() {
        let e = fb("web.search", true, false, 1_700_000_000_000);
        let json = serde_json::to_string(&e).unwrap();
        let back: FeedbackEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(back, e);

        let t = FeedbackThresholds::default();
        let json = serde_json::to_string(&t).unwrap();
        let back: FeedbackThresholds = serde_json::from_str(&json).unwrap();
        assert_eq!(back, t);

        let r = DegradedReason::AnomalousFeedback { tool: "x".to_string(), len: 4 };
        let json = serde_json::to_string(&r).unwrap();
        let back: DegradedReason = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
        // Pin the externally-tagged wire shape used by audit records.
        assert_eq!(json, r#"{"AnomalousFeedback":{"tool":"x","len":4}}"#);
    }
}
