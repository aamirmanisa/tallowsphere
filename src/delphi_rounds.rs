//! Delphi elicitation rounds (tasks B4.3.1–B4.3.3, frozen interface §9).
//!
//! A Delphi round collects one numeric estimate per agent, aggregates it into
//! an ordinal summary the facilitator can feed back, and tracks successive
//! rounds until the panel settles. Three rules drive everything here:
//!
//! 1. **Aggregation is order-independent and total.** [`aggregate`] sorts by
//!    [`f64::total_cmp`] before computing anything, so the summary depends on
//!    the *multiset* of estimates, never on submission order — and the sort is
//!    total even across `-0.0` / `+0.0`, so there is no unstable-key hazard.
//! 2. **Feedback is anonymized by construction.** [`next_round_packet`] and
//!    [`ConvergenceLog::render`] accept only [`Aggregate`] / [`RoundRecord`],
//!    which carry no agent identity and no raw value list; there is no field
//!    through which an id or an individual estimate could leak.
//! 3. **Convergence is judged on the *final* transition.** [`ConvergenceLog::converged`]
//!    looks at the last two rounds only: the median must have stopped moving
//!    (|Δmedian| ≤ tol) and the spread must not have widened
//!    ((q3 − q1)ₖ ≤ (q3 − q1)ₖ₋₁). Earlier history never rescues a log whose
//!    latest step regressed.
//!
//! # Quartiles = Tukey hinges (exact rule, pinned in tests)
//!
//! Quartiles are **Tukey hinges**: `q1` is the median of the lower half, `q3`
//! the median of the upper half, with halves taken as:
//!
//! * even `n`: split at the middle — lower = `values[..n/2]`,
//!   upper = `values[n/2..]` (each half holds exactly `n/2` values);
//! * odd `n`: **the overall median is excluded from both halves** — lower =
//!   `values[..n/2]`, upper = `values[n/2 + 1..]` (each half holds `(n−1)/2`
//!   values). So for `n = 5` over `[10, 20, 30, 40, 50]`: median `30`,
//!   `q1 = median([10, 20]) = 15`, `q3 = median([40, 50]) = 45`.
//!
//! Degenerate halves: for `n = 1` both halves are empty and the hinges
//! collapse to the single value (`q1 = q3 = median`); for `n = 2` the halves
//! are the two singletons (`q1 = min`, `q3 = max`). Tests pin only
//! exactly-representable inputs so every expected value is an exact `f64`
//! equality, never an epsilon guess.
//!
//! # Validation order
//!
//! [`aggregate`] checks **empty first, then values**: an empty slice is
//! [`DelphiError::NoEstimates`] regardless of anything else; with at least one
//! estimate, the first non-finite value (NaN, ±∞) is
//! [`DelphiError::BadValue`]. [`ConvergenceLog::converged`] rejects a negative
//! tolerance with [`DelphiError::BadTolerance`] *before* consulting the log
//! (so it also applies to logs with fewer than two rounds). NaN tolerance is
//! unspecified by §9; this module hardens it to `BadTolerance` rather than
//! letting IEEE comparisons silently answer `false` forever (documented
//! deviation, argued in the AGT-109 report).
//!
//! # Signature note
//!
//! §9 writes `converged(...) -> bool` yet pins "tol < 0 ⇒ BadTolerance" —
//! impossible in a bare `bool`. The implementation therefore returns
//! `Result<bool, DelphiError>` (`Ok(false)` for fewer than two rounds). This
//! is the minimal reading that keeps the error reachable; argued in the
//! AGT-109 report.
//!
//! # Serde conventions
//!
//! §9 annotates `Estimate`, `Aggregate`, `RoundRecord` and `DelphiError` with
//! `(serde)`; all four derive `Serialize + Deserialize`. No `rename_all` is
//! specified, so wire tokens are the variant names verbatim
//! (`"NoEstimates"`, `"BadValue"`, `"BadTolerance"`), pinned in tests.
//! `ConvergenceLog` is deliberately **not** serde, matching the §9 annotation
//! set (and the in-repo precedent for private-field containers): serialize
//! `RoundRecord`s when a wire form of the log is needed.
//!
//! [`push`](ConvergenceLog::push) trusts its input: it does not re-validate
//! statistics a caller assembled by hand. Build aggregates through
//! [`aggregate`] and the invariant (finite stats) always holds.

use serde::{Deserialize, Serialize};
use std::fmt;

/// One agent's numeric estimate in a Delphi round.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Estimate {
    /// Agent identifier. Never echoed into any feedback artifact (see
    /// [`next_round_packet`]).
    pub agent: String,
    /// The estimate. Must be finite for [`aggregate`]; NaN and ±∞ are refused.
    pub value: f64,
}

/// Ordinal summary of one Delphi round: count, median, Tukey hinges.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Aggregate {
    /// Number of estimates that produced this summary.
    pub n: usize,
    /// Median (middle value; mean of the two middle values for even `n`).
    pub median: f64,
    /// Lower Tukey hinge (median of the lower half; see module docs).
    pub q1: f64,
    /// Upper Tukey hinge (median of the upper half; see module docs).
    pub q3: f64,
}

/// Median of an already-ascending slice; `None` for the empty slice.
fn median_sorted(sorted: &[f64]) -> Option<f64> {
    let m = sorted.len();
    if m == 0 {
        return None;
    }
    let mid = m / 2;
    if m % 2 == 1 {
        Some(sorted[mid])
    } else {
        // Sum of two finite f64s: cannot overflow to a non-finite value in a
        // way that changes this module's contract; exact for representable
        // inputs (the pinned test values are small).
        Some((sorted[mid - 1] + sorted[mid]) / 2.0)
    }
}

/// Aggregate one round of estimates into a median + Tukey hinges summary.
///
/// Checks **empty first, then values**: `[]` ⇒ [`DelphiError::NoEstimates`];
/// any non-finite value (NaN, ±∞) ⇒ [`DelphiError::BadValue`]. Order-independent
/// (input is sorted via [`f64::total_cmp`]) and deterministic.
pub fn aggregate(estimates: &[Estimate]) -> Result<Aggregate, DelphiError> {
    if estimates.is_empty() {
        return Err(DelphiError::NoEstimates);
    }
    if estimates.iter().any(|e| !e.value.is_finite()) {
        return Err(DelphiError::BadValue);
    }
    let mut values: Vec<f64> = estimates.iter().map(|e| e.value).collect();
    values.sort_by(f64::total_cmp);

    let n = values.len();
    let median = median_sorted(&values).expect("non-empty by the check above");
    let half = n / 2;
    // Odd n: `values[n/2]` (the median itself) is excluded from both slices.
    // Small-n edges: an empty half collapses to the median (n = 1 only).
    let q1 = median_sorted(&values[..half]).unwrap_or(median);
    let q3 = median_sorted(&values[n - half..]).unwrap_or(median);

    Ok(Aggregate { n, median, q1, q3 })
}

/// Anonymized feedback for the next round: aggregate statistics only.
///
/// Contains `n`, `median`, `q1`, `q3` — nothing else. The parameter is an
/// [`Aggregate`], which has no agent field and no raw-value list, so neither
/// agent identities nor individual estimates *can* appear. Deterministic:
/// identical aggregates render identical bytes (pinned in tests).
pub fn next_round_packet(agg: &Aggregate) -> String {
    let mut out = String::new();
    out.push_str("DELPHI NEXT-ROUND PACKET (ANONYMIZED)\n");
    out.push_str(&format!("n = {}\n", agg.n));
    out.push_str(&format!("median = {}\n", agg.median));
    out.push_str(&format!("q1 = {}\n", agg.q1));
    out.push_str(&format!("q3 = {}\n", agg.q3));
    out.push_str("Only aggregate statistics are shared; individual estimates are never disclosed.\n");
    out
}

/// One recorded round: its 1-based number and the round's aggregate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoundRecord {
    /// Round number, starting at 1 (see [`ConvergenceLog::push`]).
    pub round: usize,
    /// The round's aggregate summary.
    pub aggregate: Aggregate,
}

/// Append-only log of successive Delphi rounds.
///
/// Deliberately not `serde` (§9 annotates only [`RoundRecord`]; serialize the
/// records if a wire form is needed). Round numbering is assigned by the log,
/// starting at 1; entries are never rewritten or pruned.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ConvergenceLog {
    rounds: Vec<RoundRecord>,
}

impl ConvergenceLog {
    /// An empty log; the next [`push`](ConvergenceLog::push) is round 1.
    pub fn new() -> Self {
        Self { rounds: Vec::new() }
    }

    /// Append a round's aggregate; returns the stored record (round numbering
    /// starts at 1 and is contiguous). The aggregate is trusted as given —
    /// build it via [`aggregate`].
    pub fn push(&mut self, aggregate: Aggregate) -> RoundRecord {
        let record = RoundRecord {
            round: self.rounds.len() + 1,
            aggregate,
        };
        self.rounds.push(record.clone());
        record
    }

    /// Deterministic rendering: one line per round, statistics only
    /// (`round <r>: n=<n> median=<m> q1=<q1> q3=<q3>`), each line newline-
    /// terminated. An empty log renders the empty string.
    pub fn render(&self) -> String {
        let mut out = String::new();
        for r in &self.rounds {
            out.push_str(&format!(
                "round {}: n={} median={} q1={} q3={}\n",
                r.round, r.aggregate.n, r.aggregate.median, r.aggregate.q1, r.aggregate.q3
            ));
        }
        out
    }

    /// Has the final transition settled? Requires **at least two rounds**;
    /// fewer ⇒ `Ok(false)`.
    ///
    /// Compares the last two rounds: `true` iff
    /// `|medianₖ − medianₖ₋₁| ≤ tol` **and** `(q3 − q1)ₖ ≤ (q3 − q1)ₖ₋₁`
    /// (spread must not widen; equality counts). A negative tolerance ⇒
    /// [`DelphiError::BadTolerance`] — checked first, so it also applies to
    /// short logs. NaN tolerance is also `BadTolerance` (hardening of an
    /// unspecified case; see module docs).
    pub fn converged(&self, tol: f64) -> Result<bool, DelphiError> {
        if tol.is_nan() || tol < 0.0 {
            return Err(DelphiError::BadTolerance);
        }
        let n = self.rounds.len();
        if n < 2 {
            return Ok(false);
        }
        let prev = &self.rounds[n - 2].aggregate;
        let cur = &self.rounds[n - 1].aggregate;
        let median_settled = (cur.median - prev.median).abs() <= tol;
        let spread_shrank = (cur.q3 - cur.q1) <= (prev.q3 - prev.q1);
        Ok(median_settled && spread_shrank)
    }
}

/// Errors from Delphi aggregation and convergence checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DelphiError {
    /// No estimates supplied — an empty round cannot be aggregated.
    NoEstimates,
    /// An estimate value was NaN or infinite; summaries require finite input.
    BadValue,
    /// The convergence tolerance was negative (or NaN); it must be a
    /// non-negative number.
    BadTolerance,
}

impl fmt::Display for DelphiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DelphiError::NoEstimates => {
                f.write_str("no estimates supplied; an empty round cannot be aggregated")
            }
            DelphiError::BadValue => {
                f.write_str("estimate value is not finite (NaN or infinite)")
            }
            DelphiError::BadTolerance => {
                f.write_str("convergence tolerance must be a non-negative number")
            }
        }
    }
}

impl std::error::Error for DelphiError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn est(agent: &str, value: f64) -> Estimate {
        Estimate {
            agent: agent.to_string(),
            value,
        }
    }

    /// Shorthand for a hand-built aggregate (fields are public).
    fn agg(n: usize, median: f64, q1: f64, q3: f64) -> Aggregate {
        Aggregate { n, median, q1, q3 }
    }

    fn values(estimates: &[Estimate]) -> Vec<f64> {
        estimates.iter().map(|e| e.value).collect()
    }

    // ---------------------------------------------------------------- aggregate

    #[test]
    fn aggregate_empty_slice_is_no_estimates() {
        assert_eq!(aggregate(&[]), Err(DelphiError::NoEstimates));
        // Distinguish from BadValue: emptiness is checked first, and there are
        // no values to inspect anyway.
        assert_ne!(aggregate(&[]), Err(DelphiError::BadValue));
    }

    #[test]
    fn aggregate_rejects_non_finite_values() {
        let cases = [
            est("a", f64::NAN),
            est("a", f64::INFINITY),
            est("a", f64::NEG_INFINITY),
            est("a", 1.0),
        ];
        // Non-finite anywhere in the slice is refused, not just first position.
        for poison in 0..3usize {
            let mut round = cases.to_vec();
            round[poison].value = match poison {
                0 => f64::NAN,
                1 => f64::INFINITY,
                _ => f64::NEG_INFINITY,
            };
            assert_eq!(aggregate(&round), Err(DelphiError::BadValue));
        }
        // And a lone NaN still hits BadValue, not NoEstimates (check order).
        assert_eq!(aggregate(&[est("a", f64::NAN)]), Err(DelphiError::BadValue));
    }

    #[test]
    fn aggregate_odd_n_excludes_the_median_from_tukey_hinges() {
        // n = 5: median 30; hinges are medians of the two 2-value halves
        // (median 30 excluded from both).
        let five = [10.0, 20.0, 30.0, 40.0, 50.0];
        let a = aggregate(&five.map(|v| est("x", v))).unwrap();
        assert_eq!(a, agg(5, 30.0, 15.0, 45.0));

        // n = 3: lower = [10], upper = [30] (the median 20 excluded).
        let three = [10.0, 20.0, 30.0];
        let b = aggregate(&three.map(|v| est("x", v))).unwrap();
        assert_eq!(b, agg(3, 20.0, 10.0, 30.0));

        // n = 7: lower = [1,2,3] → 2, upper = [5,6,7] → 6, median 4.
        let seven: Vec<Estimate> = (1..=7).map(|v| est("x", v as f64)).collect();
        let c = aggregate(&seven).unwrap();
        assert_eq!(c, agg(7, 4.0, 2.0, 6.0));
    }

    #[test]
    fn aggregate_even_n_splits_halves_at_the_middle() {
        let four = [10.0, 20.0, 30.0, 40.0];
        let a = aggregate(&four.map(|v| est("x", v))).unwrap();
        assert_eq!(a, agg(4, 25.0, 15.0, 35.0));

        let six = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0];
        let b = aggregate(&six.map(|v| est("x", v))).unwrap();
        assert_eq!(b, agg(6, 35.0, 20.0, 50.0));

        // n = 2: halves are the two singletons.
        let two = [10.0, 20.0];
        let c = aggregate(&two.map(|v| est("x", v))).unwrap();
        assert_eq!(c, agg(2, 15.0, 10.0, 20.0));
    }

    #[test]
    fn aggregate_small_n_edges_collapse_hinges_to_the_value() {
        let one = aggregate(&[est("solo", 42.0)]).unwrap();
        assert_eq!(one, agg(1, 42.0, 42.0, 42.0));
    }

    #[test]
    fn aggregate_is_order_independent_and_deterministic() {
        let ascending: Vec<Estimate> = [10.0, 20.0, 30.0, 40.0, 50.0]
            .map(|v| est("x", v))
            .to_vec();
        let descending: Vec<Estimate> = [50.0, 40.0, 30.0, 20.0, 10.0]
            .map(|v| est("x", v))
            .to_vec();
        let shuffled = vec![
            est("c", 30.0),
            est("a", 10.0),
            est("e", 50.0),
            est("b", 20.0),
            est("d", 40.0),
        ];
        let expected = agg(5, 30.0, 15.0, 45.0);
        assert_eq!(aggregate(&ascending).unwrap(), expected);
        assert_eq!(aggregate(&descending).unwrap(), expected);
        assert_eq!(aggregate(&shuffled).unwrap(), expected);
        // Repeated runs are identical.
        for _ in 0..8 {
            assert_eq!(aggregate(&shuffled).unwrap(), expected);
        }
    }

    #[test]
    fn aggregate_hinges_duplicates_after_sorting() {
        // Duplicates and unsorted input: [50,10,50,10,30] → [10,10,30,50,50].
        let round = vec![
            est("a", 50.0),
            est("b", 10.0),
            est("c", 50.0),
            est("d", 10.0),
            est("e", 30.0),
        ];
        assert_eq!(aggregate(&round).unwrap(), agg(5, 30.0, 10.0, 50.0));
    }

    // ------------------------------------------------------------ next_round_packet

    #[test]
    fn packet_pins_exact_anonymized_shape() {
        let packet = next_round_packet(&agg(4, 25.0, 15.0, 35.0));
        let expected = "DELPHI NEXT-ROUND PACKET (ANONYMIZED)\n\
                        n = 4\n\
                        median = 25\n\
                        q1 = 15\n\
                        q3 = 35\n\
                        Only aggregate statistics are shared; individual estimates are never disclosed.\n";
        assert_eq!(packet, expected);
        // Half-values render their decimal form, not an integer rounding.
        let half = next_round_packet(&agg(2, 25.5, 10.0, 41.5));
        assert!(half.contains("median = 25.5"));
        assert!(half.contains("q3 = 41.5"));
    }

    #[test]
    fn packet_is_deterministic_across_calls() {
        let a = agg(5, 30.0, 15.0, 45.0);
        let first = next_round_packet(&a);
        for _ in 0..5 {
            assert_eq!(next_round_packet(&a), first);
        }
    }

    #[test]
    fn packet_never_leaks_agent_identifiers() {
        let round = vec![
            est("agent-zephyr-9", 10.0),
            est("agent-quill-3", 20.0),
            est("agent-marble-7", 30.0),
            est("agent-gossamer-1", 40.0),
            est("agent-ember-5", 50.0),
        ];
        let packet = next_round_packet(&aggregate(&round).unwrap());
        for name in ["zephyr", "quill", "marble", "gossamer", "ember", "agent-"] {
            assert!(!packet.contains(name), "packet leaked {name:?}:\n{packet}");
        }
        // No raw value list either: a value that is not one of the four
        // reported statistics must not appear (60 is absent from n/median/
        // q1/q3 for this round; the reported stats live in the exact-shape
        // pin above).
        let round2: Vec<Estimate> = [10.0, 20.0, 30.0, 40.0, 50.0, 60.0]
            .map(|v| est("x", v))
            .to_vec();
        let packet2 = next_round_packet(&aggregate(&round2).unwrap());
        let value_lines: Vec<&str> = packet2.lines().filter(|l| l.contains("60.0")).collect();
        assert!(
            value_lines.is_empty(),
            "packet seemingly enumerated a raw value: {value_lines:?}"
        );
    }

    // ------------------------------------------------------------------ log

    #[test]
    fn log_numbering_starts_at_one_and_push_returns_the_record() {
        let mut log = ConvergenceLog::new();
        let r1 = log.push(agg(4, 25.0, 15.0, 35.0));
        let r2 = log.push(agg(4, 26.0, 16.0, 36.0));
        assert_eq!(r1.round, 1);
        assert_eq!(r1.aggregate, agg(4, 25.0, 15.0, 35.0));
        assert_eq!(r2.round, 2);
        assert_eq!(r2.aggregate, agg(4, 26.0, 16.0, 36.0));
        // The returned record matches what render will show.
        assert!(log.render().starts_with("round 1: n=4 median=25 q1=15 q3=35\n"));
        assert!(log.render().ends_with("round 2: n=4 median=26 q1=16 q3=36\n"));
    }

    #[test]
    fn log_render_is_exact_deterministic_and_stats_only() {
        assert_eq!(ConvergenceLog::new().render(), "");
        let mut log = ConvergenceLog::default();
        log.push(agg(4, 25.0, 15.0, 35.0));
        log.push(agg(6, 35.0, 20.0, 50.0));
        let expected = "round 1: n=4 median=25 q1=15 q3=35\n\
                        round 2: n=6 median=35 q1=20 q3=50\n";
        assert_eq!(log.render(), expected);
        for _ in 0..5 {
            assert_eq!(log.render(), expected);
        }
        for name in ["zephyr", "agent-", "quill"] {
            assert!(!log.render().contains(name));
        }
    }

    #[test]
    fn log_render_never_leaks_agent_identifiers() {
        let round = vec![
            est("agent-zephyr-9", 10.0),
            est("agent-quill-3", 20.0),
            est("agent-marble-7", 30.0),
        ];
        let mut log = ConvergenceLog::new();
        log.push(aggregate(&round).unwrap());
        let rendered = log.render();
        for name in ["zephyr", "quill", "marble", "agent-"] {
            assert!(!rendered.contains(name), "render leaked {name:?}:\n{rendered}");
        }
    }

    // --------------------------------------------------------------- convergence

    #[test]
    fn converged_requires_at_least_two_rounds() {
        let mut log = ConvergenceLog::new();
        assert_eq!(log.converged(1.0), Ok(false));
        log.push(agg(4, 25.0, 15.0, 35.0));
        assert_eq!(log.converged(1.0), Ok(false));
    }

    #[test]
    fn converged_true_when_final_step_settles() {
        let mut log = ConvergenceLog::new();
        log.push(agg(4, 25.0, 15.0, 35.0)); // spread 20
        log.push(agg(4, 27.0, 17.0, 35.0)); // |Δmedian| = 2, spread 18
        assert_eq!(log.converged(2.5), Ok(true));
        // Tolerance just too tight for the same step.
        assert_eq!(log.converged(1.5), Ok(false));
    }

    #[test]
    fn converged_false_when_median_moves_or_spread_grows() {
        // Median moved beyond tolerance even though spread shrank.
        let mut moved = ConvergenceLog::new();
        moved.push(agg(4, 25.0, 15.0, 35.0)); // spread 20
        moved.push(agg(4, 30.0, 25.0, 35.0)); // spread 10, |Δ| = 5
        assert_eq!(moved.converged(1.0), Ok(false));

        // Median identical but spread widened.
        let mut widened = ConvergenceLog::new();
        widened.push(agg(4, 25.0, 15.0, 35.0)); // spread 20
        widened.push(agg(4, 25.0, 5.0, 45.0)); // spread 40, |Δ| = 0
        assert_eq!(widened.converged(0.0), Ok(false));
    }

    #[test]
    fn converged_checks_only_the_final_transition() {
        // r1→r2 settles; r2→r3 regresses: a settled past does not rescue it.
        let mut regressed = ConvergenceLog::new();
        regressed.push(agg(4, 25.0, 15.0, 35.0));
        regressed.push(agg(4, 26.0, 16.0, 36.0));
        regressed.push(agg(4, 40.0, 30.0, 50.0));
        assert_eq!(regressed.converged(2.0), Ok(false));

        // r1→r2 moves; r2→r3 settles: only the last step matters.
        let mut settled = ConvergenceLog::new();
        settled.push(agg(4, 25.0, 15.0, 35.0));
        settled.push(agg(4, 40.0, 30.0, 50.0));
        settled.push(agg(4, 41.0, 31.0, 51.0));
        assert_eq!(settled.converged(2.0), Ok(true));
    }

    #[test]
    fn converged_boundary_equality_counts() {
        // |Δmedian| exactly == tol, spread exactly equal: both conditions use
        // ≤, so this is converged.
        let mut log = ConvergenceLog::new();
        log.push(agg(4, 25.0, 15.0, 35.0));
        log.push(agg(4, 27.0, 16.0, 36.0));
        assert_eq!(log.converged(2.0), Ok(true));
        assert_eq!(log.converged(0.0), Ok(false));

        // tol = 0 with an identical final step: settled and no widening.
        let mut still = ConvergenceLog::new();
        still.push(agg(3, 20.0, 10.0, 30.0));
        still.push(agg(3, 20.0, 10.0, 30.0));
        assert_eq!(still.converged(0.0), Ok(true));
        // Widening by one unit (10 → 11) with tol 0 breaks it.
        still.push(agg(3, 20.0, 10.0, 31.0));
        assert_eq!(still.converged(0.0), Ok(false));
    }

    #[test]
    fn converged_negative_tolerance_is_bad_tolerance() {
        let mut log = ConvergenceLog::new();
        assert_eq!(log.converged(-0.001), Err(DelphiError::BadTolerance));
        log.push(agg(1, 1.0, 1.0, 1.0));
        log.push(agg(1, 1.0, 1.0, 1.0));
        assert_eq!(log.converged(-1.0), Err(DelphiError::BadTolerance));
        // NaN tolerance is hardened to the same error (unspecified by §9).
        assert_eq!(log.converged(f64::NAN), Err(DelphiError::BadTolerance));
        // +∞ is a valid (vacuous) tolerance; a perfect repeat converges.
        assert_eq!(log.converged(f64::INFINITY), Ok(true));
    }

    // ------------------------------------------------------------------- serde

    #[test]
    fn serde_round_trips_and_wire_tokens() {
        // Estimate
        let e = est("a", 3.0);
        let e_json = serde_json::to_string(&e).unwrap();
        assert_eq!(e_json, r#"{"agent":"a","value":3.0}"#);
        assert_eq!(serde_json::from_str::<Estimate>(&e_json).unwrap(), e);

        // Aggregate
        let a = agg(4, 25.0, 15.0, 35.0);
        let a_json = serde_json::to_string(&a).unwrap();
        assert_eq!(a_json, r#"{"n":4,"median":25.0,"q1":15.0,"q3":35.0}"#);
        assert_eq!(serde_json::from_str::<Aggregate>(&a_json).unwrap(), a);

        // RoundRecord (nested aggregate)
        let r = RoundRecord {
            round: 2,
            aggregate: a.clone(),
        };
        let r_json = serde_json::to_string(&r).unwrap();
        assert_eq!(
            r_json,
            r#"{"round":2,"aggregate":{"n":4,"median":25.0,"q1":15.0,"q3":35.0}}"#
        );
        assert_eq!(serde_json::from_str::<RoundRecord>(&r_json).unwrap(), r);

        // DelphiError: variant names verbatim (no rename_all specified).
        assert_eq!(
            serde_json::to_string(&DelphiError::NoEstimates).unwrap(),
            r#""NoEstimates""#
        );
        assert_eq!(
            serde_json::to_string(&DelphiError::BadValue).unwrap(),
            r#""BadValue""#
        );
        assert_eq!(
            serde_json::to_string(&DelphiError::BadTolerance).unwrap(),
            r#""BadTolerance""#
        );
        assert_eq!(
            serde_json::from_str::<DelphiError>(r#""BadValue""#).unwrap(),
            DelphiError::BadValue
        );
    }

    #[test]
    fn serde_outputs_carry_no_agent_identifiers() {
        let round = vec![
            est("agent-zephyr-9", 10.0),
            est("agent-quill-3", 20.0),
            est("agent-marble-7", 30.0),
        ];
        let a = aggregate(&round).unwrap();
        let mut log = ConvergenceLog::new();
        let record = log.push(a.clone());

        let mut wire = serde_json::to_string(&a).unwrap();
        wire.push('\n');
        wire.push_str(&serde_json::to_string(&record).unwrap());
        for name in ["zephyr", "quill", "marble", "agent-"] {
            assert!(
                !wire.contains(name),
                "serde output leaked {name:?}:\n{wire}"
            );
        }
        // The values themselves (10/20/30) only appear if they equal one of
        // the four reported statistics; here median 20 is legitimately a
        // statistic, so pin the shape count instead: exactly the four
        // numeric fields with no extras.
        let parsed: serde_json::Value = serde_json::from_str(&serde_json::to_string(&a).unwrap()).unwrap();
        let obj = parsed.as_object().unwrap();
        assert_eq!(obj.len(), 4);
        for key in ["n", "median", "q1", "q3"] {
            assert!(obj.contains_key(key), "missing stat {key}");
        }
        // Sanity: the fixture really holds distinct raw values.
        assert_eq!(values(&round), vec![10.0, 20.0, 30.0]);
    }

    #[test]
    fn errors_display_and_box_as_std_error() {
        assert!(DelphiError::NoEstimates.to_string().contains("empty"));
        assert!(DelphiError::BadValue.to_string().contains("finite"));
        assert!(DelphiError::BadTolerance.to_string().contains("non-negative"));

        let boxed: Box<dyn std::error::Error> = Box::new(DelphiError::BadValue);
        assert!(boxed.to_string().contains("finite"));
        // Errors are Copy + Eq, usable in matches without ceremony.
        let err = DelphiError::NoEstimates;
        match err {
            DelphiError::NoEstimates => {}
            other => panic!("wrong variant: {other:?}"),
        }
    }
}
