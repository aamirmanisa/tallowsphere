//! Finite-power planning — what a bounded collector may do with a limited
//! retry budget (B3.4.1–B3.4.3, frozen interface §3).
//!
//! The doctrine: force is finite. A collection plan gets so many attempts
//! ([`Budget::max_attempts`]) and so much wall time ([`Budget::max_wall_ms`]),
//! and when the budget is spent the plan is *refused* — not retried forever.
//! Three behaviours are pinned here:
//!
//! 1. **Partial-success classification** ([`classify`]) — a run that made
//!    *any* progress is [`Outcome::Partial`], never a failure; a run that made
//!    no progress with budget left over is also `Partial{0, attempted}` (more
//!    attempts are still affordable, so the plan is not yet refused); a run
//!    that made no progress and is out of budget is [`Outcome::Refused`].
//! 2. **Budget exhaustion** ([`budget_exhausted`]) — the budget is spent when
//!    either the attempt count reaches `max_attempts` *or* the wall span from
//!    the first to the last attempt reaches `max_wall_ms` (both `>=`, both
//!    boundaries inclusive).
//! 3. **Backoff-as-persuasion** ([`backoff_delay_ms`]) — patience, not
//!    pressure: retries wait `base × 2^(n-1)` ms, saturating and capped. The
//!    wait grows so a marginal target may yield on its own terms, but it can
//!    never grow unbounded: the cap is the ceiling of persuasion.
//!
//! The fourth rule closes the loop: **refuse-coercion**
//! ([`escalate_allowed`]) — once the budget produced a [`Outcome::Refused`],
//! escalation is not allowed. The budget's no means no: exhausting a finite
//! budget is not a mandate to switch to unbounded means. `Full` and `Partial`
//! outcomes may escalate (there is legitimate work left to fund); `Refused`
//! may not.
//!
//! Every function is **pure** — a function of its arguments only, no clock
//! reads, no randomness — so a plan replays identically for the same inputs.

use serde::{Deserialize, Serialize};

/// A finite retry budget: attempt count and wall-clock span.
///
/// Invariant (frozen §3): `max_attempts == 0` or `max_wall_ms <= 0` is a
/// [`FinitePowerError::BadBudget`] — a budget of nothing can authorise
/// nothing. [`budget_exhausted`] is a plain predicate and does not validate;
/// [`classify`] is the Result-returning entry point that enforces the
/// invariant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Budget {
    /// Maximum number of attempts (`>= 1`).
    pub max_attempts: u32,
    /// Maximum wall span from first to last attempt, in ms (`>= 1`).
    pub max_wall_ms: i64,
}

/// One recorded attempt in a run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attempt {
    /// 1-based attempt number as recorded by the planner.
    pub n: u32,
    /// Whether the attempt succeeded.
    pub ok: bool,
    /// Wall-clock instant of the attempt (ms, caller's clock).
    pub at_ms: i64,
}

/// Classification of an attempt run (frozen §3 branch table).
///
/// Serde `snake_case`: `"full"`, `{"partial": {...}}`, `{"refused": {...}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Every attempt succeeded.
    Full,
    /// Some (`completed > 0`) or currently none, but budget remains
    /// (`completed == 0`, not exhausted) — the run made what progress it
    /// could and may continue.
    Partial {
        /// Attempts that succeeded.
        completed: usize,
        /// Attempts made in total.
        attempted: usize,
    },
    /// No attempt succeeded and the budget is spent. The budget is the
    /// authority: this outcome is terminal for the plan.
    Refused {
        /// Fixed, deterministic reason string (`"attempts exhausted"`).
        reason: String,
    },
}

/// Errors from finite-power planning.
///
/// `Serialize` is derived but not `Deserialize`: the [`BadInput`]
/// `&'static str` payload cannot be deserialized into a `'static` lifetime.
/// This mirrors the in-repo precedent (`clearness_gate::ClearnessError`,
/// `unknowns`, `vouching::VouchError`).
///
/// [`BadInput`]: FinitePowerError::BadInput
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum FinitePowerError {
    /// [`classify`] was called with an empty attempt slice; a run with no
    /// attempts has no classification.
    NoAttempts,
    /// The budget is not usable: `max_attempts == 0` or `max_wall_ms <= 0`.
    BadBudget,
    /// A required input was malformed; carries the field name (`"n"`,
    /// `"base_ms"`, `"cap_ms"`).
    BadInput(&'static str),
}

impl std::fmt::Display for FinitePowerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FinitePowerError::NoAttempts => {
                write!(f, "cannot classify a run with no attempts")
            }
            FinitePowerError::BadBudget => {
                write!(f, "invalid budget: max_attempts must be >= 1 and max_wall_ms must be > 0")
            }
            FinitePowerError::BadInput(field) => {
                write!(f, "invalid input: {field}")
            }
        }
    }
}

impl std::error::Error for FinitePowerError {}

/// True iff the budget is usable: `max_attempts >= 1` and `max_wall_ms >= 1`.
fn budget_usable(budget: &Budget) -> bool {
    budget.max_attempts > 0 && budget.max_wall_ms > 0
}

/// Is the budget spent for this run?
///
/// Spent when `attempts.len() >= budget.max_attempts` OR the wall span
/// `last.at_ms - first.at_ms >= budget.max_wall_ms` (frozen §3; both bounds
/// inclusive). An empty slice has no first/last attempt, so only the count
/// clause can fire (it does when `max_attempts == 0`, i.e. under an invalid
/// budget — [`classify`] rejects those before consulting this predicate).
///
/// The span subtraction is saturating: an adversarial pair such as
/// `i64::MIN`/`i64::MAX` cannot overflow, it simply reports the span as
/// maximal (exhausted). This function is a pure predicate and performs no
/// validation; callers that need a trustworthy answer validate the budget
/// first.
pub fn budget_exhausted(attempts: &[Attempt], budget: &Budget) -> bool {
    if attempts.len() >= budget.max_attempts as usize {
        return true;
    }
    match (attempts.first(), attempts.last()) {
        (Some(first), Some(last)) => {
            last.at_ms.saturating_sub(first.at_ms) >= budget.max_wall_ms
        }
        _ => false,
    }
}

/// Classify a run against its budget (frozen §3 branch table, first match
/// wins):
///
/// 1. empty `attempts` ⇒ [`FinitePowerError::NoAttempts`];
/// 2. unusable budget (non-empty run) ⇒ [`FinitePowerError::BadBudget`] —
///    validated up front so a misconfigured budget can never be silently
///    classified as `Full`/`Partial` (fail closed; see module docs);
/// 3. every attempt ok ⇒ [`Outcome::Full`];
/// 4. some ok ⇒ [`Outcome::Partial`] with exact counts — **even if the budget
///    is spent**: progress with a spent budget is still progress, never
///    `Refused`;
/// 5. none ok and [`budget_exhausted`] ⇒ [`Outcome::Refused`] with the fixed
///    reason `"attempts exhausted"`;
/// 6. none ok and budget remains ⇒ [`Outcome::Partial { completed: 0,
///    attempted }`] — the plan may keep trying.
pub fn classify(attempts: &[Attempt], budget: &Budget) -> Result<Outcome, FinitePowerError> {
    if attempts.is_empty() {
        return Err(FinitePowerError::NoAttempts);
    }
    if !budget_usable(budget) {
        return Err(FinitePowerError::BadBudget);
    }
    let attempted = attempts.len();
    let completed = attempts.iter().filter(|a| a.ok).count();
    if completed == attempted {
        return Ok(Outcome::Full);
    }
    if completed > 0 {
        return Ok(Outcome::Partial { completed, attempted });
    }
    if budget_exhausted(attempts, budget) {
        return Ok(Outcome::Refused { reason: "attempts exhausted".to_string() });
    }
    Ok(Outcome::Partial { completed: 0, attempted })
}

/// Backoff-as-persuasion: how long attempt `n` (1-based) waits before being
/// made, given `base_ms` and a ceiling `cap_ms`.
///
/// `delay = min(base_ms × 2^(n-1), cap_ms)` — the multiplication saturates at
/// [`i64::MAX`] instead of overflowing, and the cap is applied unconditionally
/// (so `base_ms > cap_ms` yields `cap_ms` even for `n = 1`). The wait grows
/// between attempts so a marginal target may yield on its own terms, but never
/// without bound: infinite patience is still infinite force (frozen §3).
///
/// Errors ([`FinitePowerError::BadInput`], field-named): `n == 0`
/// (`"n"` — attempts are 1-based), `base_ms <= 0` (`"base_ms"`),
/// `cap_ms <= 0` (`"cap_ms"`).
pub fn backoff_delay_ms(n: u32, base_ms: i64, cap_ms: i64) -> Result<i64, FinitePowerError> {
    if n == 0 {
        return Err(FinitePowerError::BadInput("n"));
    }
    if base_ms <= 0 {
        return Err(FinitePowerError::BadInput("base_ms"));
    }
    if cap_ms <= 0 {
        return Err(FinitePowerError::BadInput("cap_ms"));
    }
    let shift = n - 1;
    // `2^shift` as a positive i64, saturating at i64::MAX (shift 63 would
    // otherwise produce i64::MIN; shift >= 64 would panic under `<<`).
    let factor = 1i64
        .checked_shl(shift)
        .filter(|v| *v > 0)
        .unwrap_or(i64::MAX);
    Ok(base_ms.saturating_mul(factor).min(cap_ms))
}

/// Refuse-coercion gate: may the plan escalate beyond its budget?
///
/// `false` for [`Outcome::Refused`] — the budget's no means no; a spent
/// budget is not a licence to switch to unbounded means. `true` for
/// [`Outcome::Full`] and [`Outcome::Partial`] (there is legitimate work left
/// to fund). Frozen §3.
pub fn escalate_allowed(outcome: &Outcome) -> bool {
    match outcome {
        Outcome::Full | Outcome::Partial { .. } => true,
        Outcome::Refused { .. } => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- fixtures -----------------------------------------------------------

    fn valid_budget() -> Budget {
        Budget { max_attempts: 5, max_wall_ms: 1_000 }
    }

    fn att(n: u32, ok: bool, at_ms: i64) -> Attempt {
        Attempt { n, ok, at_ms }
    }

    // --- B3.4.1 budget exhaustion: count AND wall span ----------------------

    #[test]
    fn exhaustion_by_count_boundary_is_inclusive() {
        let b = Budget { max_attempts: 3, max_wall_ms: 1_000 };
        let two = [att(1, false, 0), att(2, false, 10)];
        let three = [att(1, false, 0), att(2, false, 10), att(3, false, 20)];
        assert_eq!(budget_exhausted(&two, &b), false, "len 2 < max_attempts 3");
        assert_eq!(budget_exhausted(&three, &b), true, "len 3 >= max_attempts 3");
    }

    #[test]
    fn exhaustion_by_wall_span_boundary_is_inclusive() {
        let b = Budget { max_attempts: 100, max_wall_ms: 500 };
        let under = [att(1, false, 0), att(2, false, 499)];
        let exact = [att(1, false, 0), att(2, false, 500)];
        let over = [att(1, false, 0), att(2, false, 501)];
        assert_eq!(budget_exhausted(&under, &b), false, "span 499 < 500");
        assert_eq!(budget_exhausted(&exact, &b), true, "span 500 >= 500");
        assert_eq!(budget_exhausted(&over, &b), true, "span 501 >= 500");
    }

    #[test]
    fn exhaustion_single_attempt_span_is_zero() {
        let b = Budget { max_attempts: 5, max_wall_ms: 1 };
        let one = [att(1, false, 42)];
        // span = last - first = 0 < max_wall_ms = 1; count 1 < 5
        assert_eq!(budget_exhausted(&one, &b), false);
    }

    #[test]
    fn exhaustion_depends_on_first_and_last_only() {
        // middle attempts' timestamps are irrelevant: span = last - first
        let b = Budget { max_attempts: 100, max_wall_ms: 100 };
        let gappy = [att(1, false, 0), att(2, false, -10_000), att(3, false, 100)];
        assert_eq!(budget_exhausted(&gappy, &b), true);
    }

    #[test]
    fn exhaustion_empty_slice_only_fires_on_zero_count_budget() {
        // empty slice: no first/last ⇒ span clause cannot fire; only the
        // count clause (0 >= max_attempts) applies.
        let valid = valid_budget();
        assert_eq!(budget_exhausted(&[], &valid), false);
        let zero_count = Budget { max_attempts: 0, max_wall_ms: 1_000 };
        assert_eq!(budget_exhausted(&[], &zero_count), true);
    }

    #[test]
    fn exhaustion_span_saturates_without_overflow() {
        let b = Budget { max_attempts: 100, max_wall_ms: i64::MAX };
        let extreme = [att(1, false, i64::MIN), att(2, false, i64::MAX)];
        // i64::MAX - i64::MIN would overflow; saturating span == i64::MAX,
        // which meets the (also maximal) budget ⇒ exhausted.
        assert_eq!(budget_exhausted(&extreme, &b), true);
    }

    // --- B3.4.1 classification matrix (4 branches pinned) -------------------

    #[test]
    fn classify_empty_is_no_attempts() {
        assert_eq!(classify(&[], &valid_budget()), Err(FinitePowerError::NoAttempts));
        // the empty pin precedes budget validation (documented order)
        let bad = Budget { max_attempts: 0, max_wall_ms: 0 };
        assert_eq!(classify(&[], &bad), Err(FinitePowerError::NoAttempts));
    }

    #[test]
    fn classify_all_ok_is_full() {
        let run = [att(1, true, 0), att(2, true, 50), att(3, true, 300)];
        assert_eq!(classify(&run, &valid_budget()), Ok(Outcome::Full));
    }

    #[test]
    fn classify_full_even_when_budget_spent() {
        // all attempts ok, but the run would count as exhausted: still Full —
        // exhaustion only matters when nothing succeeded.
        let b = Budget { max_attempts: 2, max_wall_ms: 10 };
        let run = [att(1, true, 0), att(2, true, 500)];
        assert_eq!(budget_exhausted(&run, &b), true);
        assert_eq!(classify(&run, &b), Ok(Outcome::Full));
    }

    #[test]
    fn classify_some_ok_is_partial_with_exact_counts() {
        let run = [att(1, true, 0), att(2, false, 10), att(3, true, 20), att(4, false, 30)];
        assert_eq!(
            classify(&run, &valid_budget()),
            Ok(Outcome::Partial { completed: 2, attempted: 4 })
        );
    }

    #[test]
    fn classify_partial_outranks_exhaustion() {
        // budget fully spent (4 >= 4) but one attempt succeeded ⇒ Partial,
        // never Refused. progress with a spent budget is still progress.
        let b = Budget { max_attempts: 4, max_wall_ms: 10_000 };
        let run = [att(1, false, 0), att(2, false, 1), att(3, true, 2), att(4, false, 3)];
        assert_eq!(budget_exhausted(&run, &b), true);
        assert_eq!(
            classify(&run, &b),
            Ok(Outcome::Partial { completed: 1, attempted: 4 })
        );
    }

    #[test]
    fn classify_none_ok_exhausted_is_refused() {
        let b = Budget { max_attempts: 3, max_wall_ms: 10_000 };
        let run = [att(1, false, 0), att(2, false, 1), att(3, false, 2)];
        assert_eq!(
            classify(&run, &b),
            Ok(Outcome::Refused { reason: "attempts exhausted".to_string() })
        );
    }

    #[test]
    fn classify_none_ok_exhausted_by_wall_span_is_refused() {
        let b = Budget { max_attempts: 10, max_wall_ms: 100 };
        let run = [att(1, false, 0), att(2, false, 100)];
        assert_eq!(
            classify(&run, &b),
            Ok(Outcome::Refused { reason: "attempts exhausted".to_string() })
        );
    }

    #[test]
    fn classify_none_ok_not_exhausted_is_partial_zero() {
        let run = [att(1, false, 0), att(2, false, 10)];
        assert_eq!(
            classify(&run, &valid_budget()),
            Ok(Outcome::Partial { completed: 0, attempted: 2 })
        );
    }

    #[test]
    fn classify_matrix_four_branches_in_one_table() {
        let b = Budget { max_attempts: 2, max_wall_ms: 1_000 };
        let cases: [(&[Attempt], Outcome); 4] = [
            (&[att(1, true, 0), att(2, true, 1)], Outcome::Full),
            (&[att(1, true, 0), att(2, false, 1)], Outcome::Partial { completed: 1, attempted: 2 }),
            (
                &[att(1, false, 0), att(2, false, 1)],
                Outcome::Refused { reason: "attempts exhausted".to_string() },
            ),
            (&[att(1, false, 0)], Outcome::Partial { completed: 0, attempted: 1 }),
        ];
        for (run, want) in cases {
            assert_eq!(classify(run, &b), Ok(want.clone()), "run {run:?}");
        }
    }

    #[test]
    fn classify_rejects_bad_budget() {
        let run = [att(1, true, 0)];
        assert_eq!(
            classify(&run, &Budget { max_attempts: 0, max_wall_ms: 1_000 }),
            Err(FinitePowerError::BadBudget)
        );
        assert_eq!(
            classify(&run, &Budget { max_attempts: 5, max_wall_ms: 0 }),
            Err(FinitePowerError::BadBudget)
        );
        assert_eq!(
            classify(&run, &Budget { max_attempts: 0, max_wall_ms: -1 }),
            Err(FinitePowerError::BadBudget)
        );
    }

    // --- B3.4.2 backoff-as-persuasion ---------------------------------------

    #[test]
    fn backoff_first_three_pins() {
        assert_eq!(backoff_delay_ms(1, 100, 10_000), Ok(100));
        assert_eq!(backoff_delay_ms(2, 100, 10_000), Ok(200));
        assert_eq!(backoff_delay_ms(3, 100, 10_000), Ok(400));
    }

    #[test]
    fn backoff_cap_pin() {
        // n=5 ⇒ 1600 but cap is 1000
        assert_eq!(backoff_delay_ms(5, 100, 1_000), Ok(1_000));
        // cap below base applies even at n=1
        assert_eq!(backoff_delay_ms(1, 5_000, 1_000), Ok(1_000));
        // cap equals delay at n=4 (800 < 1000) stays uncapped
        assert_eq!(backoff_delay_ms(4, 100, 1_000), Ok(800));
    }

    #[test]
    fn backoff_saturates_for_extreme_n() {
        for n in [63, 64, 65, 1_000, u32::MAX] {
            assert_eq!(backoff_delay_ms(n, 100, 60_000), Ok(60_000), "n={n}");
        }
        // saturation without cap: result is i64::MAX, no overflow/panic
        assert_eq!(backoff_delay_ms(u32::MAX, 7, i64::MAX), Ok(i64::MAX));
    }

    #[test]
    fn backoff_is_non_decreasing_and_capped() {
        let cap = 10_000;
        let mut prev = 0;
        for n in 1..=40 {
            let d = backoff_delay_ms(n, 1, cap).unwrap();
            assert!(d <= cap, "n={n} d={d} exceeds cap");
            assert!(d >= prev, "n={n} d={d} < prev {prev}");
            prev = d;
        }
        assert_eq!(prev, cap, "must reach the cap by n=40");
    }

    #[test]
    fn backoff_input_errors_are_field_named() {
        assert_eq!(backoff_delay_ms(0, 100, 1_000), Err(FinitePowerError::BadInput("n")));
        assert_eq!(backoff_delay_ms(1, 0, 1_000), Err(FinitePowerError::BadInput("base_ms")));
        assert_eq!(backoff_delay_ms(1, -5, 1_000), Err(FinitePowerError::BadInput("base_ms")));
        assert_eq!(backoff_delay_ms(1, 100, 0), Err(FinitePowerError::BadInput("cap_ms")));
        assert_eq!(backoff_delay_ms(1, 100, -1), Err(FinitePowerError::BadInput("cap_ms")));
        // n checked before base/cap
        assert_eq!(backoff_delay_ms(0, 0, 0), Err(FinitePowerError::BadInput("n")));
    }

    // --- B3.4.3 refuse-coercion escalate gate --------------------------------

    #[test]
    fn escalate_refused_is_false() {
        let refused = Outcome::Refused { reason: "attempts exhausted".to_string() };
        assert_eq!(escalate_allowed(&refused), false);
        // the gate keys on the variant, not the reason string
        assert_eq!(escalate_allowed(&Outcome::Refused { reason: "x".to_string() }), false);
    }

    #[test]
    fn escalate_full_and_partial_are_true() {
        assert_eq!(escalate_allowed(&Outcome::Full), true);
        assert_eq!(
            escalate_allowed(&Outcome::Partial { completed: 1, attempted: 3 }),
            true
        );
        assert_eq!(
            escalate_allowed(&Outcome::Partial { completed: 0, attempted: 1 }),
            true
        );
    }

    #[test]
    fn refuse_coercion_end_to_end() {
        // exhausted run → Refused → escalation denied: the budget's no is
        // final, even though a fresh budget would be a legal new plan.
        let b = Budget { max_attempts: 2, max_wall_ms: 100 };
        let run = [att(1, false, 0), att(2, false, 100)];
        let o = classify(&run, &b).unwrap();
        assert!(!escalate_allowed(&o));
    }

    // --- errors -------------------------------------------------------------

    #[test]
    fn error_display_and_std_error() {
        let e: &dyn std::error::Error = &FinitePowerError::NoAttempts;
        assert_eq!(e.to_string(), "cannot classify a run with no attempts");
        assert_eq!(
            FinitePowerError::BadBudget.to_string(),
            "invalid budget: max_attempts must be >= 1 and max_wall_ms must be > 0"
        );
        assert_eq!(FinitePowerError::BadInput("n").to_string(), "invalid input: n");
    }

    // --- determinism --------------------------------------------------------

    #[test]
    fn determinism_replays_identically() {
        let b = valid_budget();
        let mix = [att(1, false, 0), att(2, true, 10), att(3, false, 20)];
        let none = [att(1, false, 0), att(2, false, 10)];
        for _ in 0..3 {
            assert_eq!(classify(&mix, &b), classify(&mix, &b));
            assert_eq!(classify(&none, &b), classify(&none, &b));
            assert_eq!(budget_exhausted(&mix, &b), budget_exhausted(&mix, &b));
            assert_eq!(backoff_delay_ms(7, 13, 5_000), backoff_delay_ms(7, 13, 5_000));
        }
    }

    // --- serde --------------------------------------------------------------

    #[test]
    fn serde_budget_and_attempt_roundtrip() {
        let b = Budget { max_attempts: 3, max_wall_ms: 1_500 };
        let j = serde_json::to_string(&b).unwrap();
        assert_eq!(j, r#"{"max_attempts":3,"max_wall_ms":1500}"#);
        assert_eq!(serde_json::from_str::<Budget>(&j).unwrap(), b);
        let a = att(2, true, 99);
        let ja = serde_json::to_string(&a).unwrap();
        assert_eq!(ja, r#"{"n":2,"ok":true,"at_ms":99}"#);
        assert_eq!(serde_json::from_str::<Attempt>(&ja).unwrap(), a);
    }

    #[test]
    fn serde_outcome_snake_case_tags() {
        assert_eq!(serde_json::to_string(&Outcome::Full).unwrap(), r#""full""#);
        let p = Outcome::Partial { completed: 1, attempted: 3 };
        assert_eq!(
            serde_json::to_string(&p).unwrap(),
            r#"{"partial":{"completed":1,"attempted":3}}"#
        );
        let r = Outcome::Refused { reason: "attempts exhausted".to_string() };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"refused":{"reason":"attempts exhausted"}}"#
        );
        for o in [Outcome::Full, p, r] {
            let j = serde_json::to_string(&o).unwrap();
            assert_eq!(serde_json::from_str::<Outcome>(&j).unwrap(), o);
        }
    }

    #[test]
    fn serde_error_serializes_serialize_only() {
        // §3 annotates snake_case only for Outcome; the error enum keeps
        // serde defaults (PascalCase variant tags).
        assert_eq!(
            serde_json::to_string(&FinitePowerError::NoAttempts).unwrap(),
            r#""NoAttempts""#
        );
        assert_eq!(
            serde_json::to_string(&FinitePowerError::BadBudget).unwrap(),
            r#""BadBudget""#
        );
        assert_eq!(
            serde_json::to_string(&FinitePowerError::BadInput("cap_ms")).unwrap(),
            r#"{"BadInput":"cap_ms"}"#
        );
    }
}
