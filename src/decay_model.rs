//! Impermanence & decay model (task B3.5 · frozen interface §4 · B3.5.1–B3.5.3).
//!
//! Intelligence does not stay true because it was once true. This module is
//! the deterministic time model the rest of the intel stack uses to let
//! grades, stamps, and adapter trust FADE instead of silently aging into
//! fiction:
//!
//! * [`DecaySchedule`] + [`decayed_confidence`] — half-life decay of a
//!   confidence value (B3.5.1). Confidence only ever moves DOWN: the result is
//!   clamped to `[0, initial]` and is monotone non-increasing in `elapsed_ms`
//!   — the mirror image of [`crate::regrade`], whose digits can only move up.
//! * [`AsOfStamp`] + [`newer_of`] + [`is_stale`] — as-of provenance stamps
//!   and the freshness gate (B3.5.2). Boundary semantics echo
//!   [`crate::retention`]: transitions happen exactly at the pinned
//!   millisecond — `now - as_of > max_age` is STRICT, so
//!   `now - as_of == max_age` is still fresh.
//! * [`AdapterPhase`], [`AdapterLiveness`], [`sunset_due`],
//!   [`effective_phase`] — the adapter liveness/sunset workflow (B3.5.3):
//!   every adapter is `Live` until it goes quiet beyond its grace window
//!   (then `Degraded`), and `Retired` once its announced sunset has arrived.
//!
//! # Documented edge rules (spec silent; conservative reading chosen)
//!
//! * [`decayed_confidence`] is TOTAL — the frozen signature returns `f64`, so
//!   it has no channel for [`DecayError`]. An unusable schedule
//!   (`half_life_ms <= 0`, reachable because the struct's fields are public
//!   and serde-round-trippable) therefore decays to `0.0` — fail-tight: a
//!   broken schedule must never PRESERVE confidence. `BadInput` is surfaced
//!   at construction time by [`DecaySchedule::new`] /
//!   [`DecaySchedule::validate`] instead.
//! * `elapsed_ms <= 0` ⇒ `initial` verbatim, checked FIRST — even for an
//!   invalid schedule (no time has passed, so nothing may decay).
//! * `initial` is expected to be a confidence in `[0, 1]`. The clamp ceiling
//!   is `initial.max(0.0)`, and a non-finite decayed product collapses to
//!   `0.0`, so degenerate inputs fail tight rather than inflating.
//! * [`newer_of`] ties (equal `as_of_ms`) return `a` — deterministic, and the
//!   two stamps are interchangeable by value anyway.
//! * [`is_stale`] takes `max_age_ms` literally, including negative values
//!   (formula-exact); the subtraction saturates so extreme stamps cannot
//!   overflow-panic.
//! * Sunset boundary: an adapter with `sunset_at_ms = t` is due AT `t`
//!   (`now >= t`) — the same at-the-pinned-ms convention as the exclusive end
//!   of [`crate::retention::embargo_active`].
//! * [`effective_phase`] ladder is pinned: sunset first (`Retired` wins even
//!   if the adapter was seen this very instant), then never-seen ⇒
//!   `Degraded`, then quiet-beyond-grace ⇒ `Degraded`
//!   (`now - last_seen > grace_ms`, STRICT: exactly at grace the adapter is
//!   still `Live`), else `Live`.
//!
//! Nothing here touches the clock, the filesystem, or global state: identical
//! inputs always produce identical outputs.

use std::fmt;

use serde::{Deserialize, Serialize};

// ── Decay schedule + half-life decay (B3.5.1) ────────────────────────────────

/// Half-life decay schedule for a confidence value.
///
/// A valid schedule has `half_life_ms > 0`: every `half_life_ms` of elapsed
/// time halves the confidence. Unusable values (`<= 0`) are refused by
/// [`DecaySchedule::new`] / [`DecaySchedule::validate`] with
/// [`DecayError::BadInput`]; [`decayed_confidence`] treats them fail-tight
/// (see module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecaySchedule {
    /// Milliseconds per halving of the confidence value. Must be `> 0`.
    pub half_life_ms: i64,
}

impl DecaySchedule {
    /// Checked constructor: `half_life_ms <= 0` ⇒
    /// `Err(BadInput("half_life_ms"))`.
    pub fn new(half_life_ms: i64) -> Result<Self, DecayError> {
        let schedule = Self { half_life_ms };
        schedule.validate()?;
        Ok(schedule)
    }

    /// Is the schedule usable (`half_life_ms > 0`)?
    pub fn is_valid(&self) -> bool {
        self.half_life_ms > 0
    }

    /// Validate the schedule: `half_life_ms <= 0` ⇒
    /// `Err(BadInput("half_life_ms"))`, else `Ok(())`.
    pub fn validate(&self) -> Result<(), DecayError> {
        if self.half_life_ms > 0 {
            Ok(())
        } else {
            Err(DecayError::BadInput("half_life_ms"))
        }
    }
}

/// Decay `initial` confidence by `elapsed_ms` under `schedule`:
/// `initial × 0.5^(elapsed_ms / half_life_ms)`.
///
/// * `elapsed_ms <= 0` ⇒ `initial` (checked first — no time, no decay).
/// * An invalid schedule (`half_life_ms <= 0`) ⇒ `0.0` (fail-tight; see
///   module docs — the frozen signature has no error channel).
/// * Otherwise: monotone non-increasing in `elapsed_ms`, clamped to
///   `[0, initial]`; a non-finite product collapses to `0.0`.
///
/// Exact halves are float-exact: half-life 1000 ⇒ elapsed 1000 → 0.5,
/// 2000 → 0.25, 3000 → 0.125. Never panics.
pub fn decayed_confidence(initial: f64, schedule: &DecaySchedule, elapsed_ms: i64) -> f64 {
    if elapsed_ms <= 0 {
        return initial;
    }
    if schedule.half_life_ms <= 0 {
        return 0.0;
    }
    let halvings = elapsed_ms as f64 / schedule.half_life_ms as f64;
    let decayed = initial * 0.5f64.powf(halvings);
    if !decayed.is_finite() {
        return 0.0;
    }
    decayed.clamp(0.0, initial.max(0.0))
}

// ── As-of stamps (B3.5.2) ────────────────────────────────────────────────────

/// A provenance stamp: the observation time the companion claim is valid
/// **as of** (Unix-epoch milliseconds, consistent with the ledger family).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AsOfStamp {
    /// Unix-epoch milliseconds the claim is stamped as-of.
    pub as_of_ms: i64,
}

/// The newer of two stamps; ties (equal `as_of_ms`) return `a`.
pub fn newer_of(a: &AsOfStamp, b: &AsOfStamp) -> AsOfStamp {
    if b.as_of_ms > a.as_of_ms {
        *b
    } else {
        *a
    }
}

/// Is `stamp` stale at `now_ms` given `max_age_ms`?
///
/// STRICT boundary (pinned): `now_ms - as_of_ms > max_age_ms` is stale, so
/// `now - as_of == max_age` is still fresh and `now == as_of` is never stale
/// for `max_age_ms >= 0`. A future stamp (`as_of > now`) is not stale.
/// The subtraction saturates — extreme values cannot overflow-panic.
pub fn is_stale(stamp: &AsOfStamp, now_ms: i64, max_age_ms: i64) -> bool {
    now_ms.saturating_sub(stamp.as_of_ms) > max_age_ms
}

// ── Adapter liveness / sunset workflow (B3.5.3) ──────────────────────────────

/// Lifecycle phase of an adapter, derived from its liveness record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AdapterPhase {
    /// Seen within the grace window; safe to rely on.
    Live,
    /// Quiet beyond grace, or never seen at all. Usable, with caution.
    Degraded,
    /// Its announced sunset has arrived; do not plan new work on it.
    Retired,
}

/// Liveness record for one adapter.
///
/// * `last_seen_ms` — when the adapter last proved itself; `None` = never
///   seen since registration.
/// * `sunset_at_ms` — announced end of life; `None` = no sunset announced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdapterLiveness {
    /// Adapter name (stable identifier).
    pub adapter: String,
    /// Unix-epoch milliseconds of the last successful contact; `None` =
    /// never seen.
    pub last_seen_ms: Option<i64>,
    /// Unix-epoch milliseconds at which the adapter sunsets (end of life is
    /// due AT this ms); `None` = no sunset announced.
    pub sunset_at_ms: Option<i64>,
}

/// Is the announced sunset due at `now_ms`?
///
/// `Some(at) => now_ms >= at` — due AT the pinned millisecond (the same
/// at-the-pinned-ms convention as [`crate::retention::embargo_active`]'s
/// exclusive end). `None => false` (no sunset announced, never due).
pub fn sunset_due(l: &AdapterLiveness, now_ms: i64) -> bool {
    match l.sunset_at_ms {
        Some(at) => now_ms >= at,
        None => false,
    }
}

/// Effective phase ladder (first match wins, pinned):
///
/// 1. sunset due ⇒ [`AdapterPhase::Retired`] (wins even if seen this
///    instant — an announced end of life is not outrun by a heartbeat);
/// 2. never seen (`last_seen_ms: None`) ⇒ [`AdapterPhase::Degraded`];
/// 3. quiet beyond grace (`now - last_seen > grace_ms`, STRICT: exactly at
///    grace it is still `Live`) ⇒ [`AdapterPhase::Degraded`];
/// 4. otherwise ⇒ [`AdapterPhase::Live`].
///
/// Never panics.
pub fn effective_phase(l: &AdapterLiveness, now_ms: i64, grace_ms: i64) -> AdapterPhase {
    if sunset_due(l, now_ms) {
        return AdapterPhase::Retired;
    }
    match l.last_seen_ms {
        None => AdapterPhase::Degraded,
        Some(last) => {
            if now_ms.saturating_sub(last) > grace_ms {
                AdapterPhase::Degraded
            } else {
                AdapterPhase::Live
            }
        }
    }
}

// ── Error type ───────────────────────────────────────────────────────────────

/// Why a decay-model operation was refused. One variant per rule so callers
/// can aggregate by cause.
///
/// `Serialize` is derived; `Deserialize` is not — the `BadInput(&'static str)`
/// payload cannot be deserialized into a `'static` lifetime (same documented
/// choice as the sibling gate modules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
pub enum DecayError {
    /// A named input was missing or outside its valid domain.
    BadInput(&'static str),
}

impl fmt::Display for DecayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecayError::BadInput(reason) => write!(f, "invalid input: {reason}"),
        }
    }
}

impl std::error::Error for DecayError {}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Epsilon comparator for the in-between decay points.
    fn close(a: f64, b: f64, eps: f64) -> bool {
        (a - b).abs() <= eps
    }

    fn schedule(half_life_ms: i64) -> DecaySchedule {
        DecaySchedule { half_life_ms }
    }

    fn stamp(as_of_ms: i64) -> AsOfStamp {
        AsOfStamp { as_of_ms }
    }

    fn adapter(
        name: &str,
        last_seen_ms: Option<i64>,
        sunset_at_ms: Option<i64>,
    ) -> AdapterLiveness {
        AdapterLiveness {
            adapter: name.to_string(),
            last_seen_ms,
            sunset_at_ms,
        }
    }

    // B3.5.1 — schedule validation.

    #[test]
    fn schedule_new_requires_positive_half_life() {
        assert_eq!(DecaySchedule::new(1000), Ok(schedule(1000)));
        assert_eq!(
            DecaySchedule::new(0),
            Err(DecayError::BadInput("half_life_ms"))
        );
        assert_eq!(
            DecaySchedule::new(-1),
            Err(DecayError::BadInput("half_life_ms"))
        );
        assert_eq!(
            DecaySchedule::new(i64::MIN),
            Err(DecayError::BadInput("half_life_ms"))
        );
        assert!(schedule(1).is_valid());
        assert!(!schedule(0).is_valid());
        assert!(!schedule(-9).is_valid());
        assert_eq!(schedule(5).validate(), Ok(()));
        assert_eq!(
            schedule(-5).validate(),
            Err(DecayError::BadInput("half_life_ms"))
        );
    }

    // B3.5.1 — decay pins.

    #[test]
    fn decay_exact_halves_are_pinned() {
        let s = schedule(1000);
        assert_eq!(decayed_confidence(1.0, &s, 0), 1.0);
        assert_eq!(decayed_confidence(1.0, &s, 1000), 0.5);
        assert_eq!(decayed_confidence(1.0, &s, 2000), 0.25);
        assert_eq!(decayed_confidence(1.0, &s, 3000), 0.125);
        assert_eq!(decayed_confidence(1.0, &s, 4000), 0.0625);
        // Scaled initial: halving × 0.5 is exponent-only, float-exact.
        let s2 = schedule(500);
        assert_eq!(decayed_confidence(0.8, &s2, 500), 0.4);
        assert_eq!(decayed_confidence(0.8, &s2, 1000), 0.2);
    }

    #[test]
    fn decay_in_between_point_epsilon_compare() {
        let s = schedule(1000);
        // 0.5^0.5 = 1/sqrt(2).
        let half_half = decayed_confidence(1.0, &s, 500);
        assert!(close(half_half, 0.707_106_781_186_547_6, 1e-12));
        // 0.5^1.5.
        let one_half = decayed_confidence(1.0, &s, 1500);
        assert!(close(one_half, 0.353_553_390_593_273_73, 1e-12));
    }

    #[test]
    fn decay_elapsed_nonpositive_returns_initial() {
        let s = schedule(1000);
        assert_eq!(decayed_confidence(1.0, &s, 0), 1.0);
        assert_eq!(decayed_confidence(1.0, &s, -1), 1.0);
        assert_eq!(decayed_confidence(0.42, &s, -999_999), 0.42);
        // Even an invalid schedule: no time, no decay (elapsed rule first).
        let bad = schedule(0);
        assert_eq!(decayed_confidence(0.7, &bad, 0), 0.7);
        assert_eq!(decayed_confidence(0.7, &bad, -3), 0.7);
    }

    #[test]
    fn decay_is_monotone_non_increasing() {
        let s = schedule(1000);
        let samples = [0_i64, 1, 100, 499, 500, 999, 1000, 1500, 2000, 5000, 60_000];
        let mut prev = f64::INFINITY;
        for &t in &samples {
            let v = decayed_confidence(1.0, &s, t);
            assert!(v <= prev, "decay increased at elapsed={t}: {v} > {prev}");
            assert!((0.0..=1.0).contains(&v));
            prev = v;
        }
        // Dense sweep: never increases anywhere.
        let mut last = decayed_confidence(0.9, &s, 0);
        for t in (0..=5_000).step_by(137) {
            let v = decayed_confidence(0.9, &s, t);
            assert!(v <= last);
            assert!((0.0..=0.9).contains(&v));
            last = v;
        }
    }

    #[test]
    fn decay_clamped_to_bounds_and_fail_tight() {
        let s = schedule(1000);
        // Huge elapsed underflows to 0.0, never negative.
        assert_eq!(decayed_confidence(1.0, &s, i64::MAX), 0.0);
        assert_eq!(decayed_confidence(0.0, &s, 1000), 0.0);
        // Degenerate negatives collapse to the lower clamp after decay.
        assert_eq!(decayed_confidence(-3.0, &s, 1000), 0.0);
        // Non-finite initial collapses to 0.0 (documented fail-tight).
        assert_eq!(decayed_confidence(f64::NAN, &s, 1000), 0.0);
        assert_eq!(decayed_confidence(f64::INFINITY, &s, 1000), 0.0);
    }

    #[test]
    fn decay_invalid_schedule_fails_tight() {
        for half in [0_i64, -1, -1000, i64::MIN] {
            let bad = schedule(half);
            assert!(!bad.is_valid());
            assert_eq!(
                decayed_confidence(1.0, &bad, 1),
                0.0,
                "half_life_ms={half} must decay to 0.0"
            );
            assert_eq!(decayed_confidence(0.5, &bad, i64::MAX), 0.0);
        }
    }

    // B3.5.2 — as-of stamps.

    #[test]
    fn newer_of_picks_newer_and_tie_returns_a() {
        let a = stamp(100);
        let b = stamp(200);
        assert_eq!(newer_of(&a, &b), stamp(200));
        assert_eq!(newer_of(&b, &a), stamp(200));
        // Tie: deterministic, returns `a` (values interchangeable).
        assert_eq!(newer_of(&a, &stamp(100)), a);
        assert_eq!(newer_of(&stamp(100), &a), a);
        // Negative timestamps (pre-epoch) still order correctly.
        assert_eq!(newer_of(&stamp(-50), &stamp(-10)), stamp(-10));
    }

    #[test]
    fn is_stale_boundary_is_strict() {
        let s = stamp(1000);
        // now - as_of == max_age ⇒ NOT stale (pinned boundary).
        assert!(!is_stale(&s, 1100, 100));
        // One past the boundary ⇒ stale.
        assert!(is_stale(&s, 1101, 100));
        // Same instant ⇒ fresh.
        assert!(!is_stale(&s, 1000, 0));
        assert!(is_stale(&s, 1001, 0));
        // Future stamp ⇒ not stale for non-negative max_age.
        assert!(!is_stale(&s, 999, 10));
        assert!(!is_stale(&s, 0, i64::MAX));
        // Formula-exact for a big window.
        assert!(!is_stale(&s, 1000 + 86_400_000, 86_400_000));
        assert!(is_stale(&s, 1000 + 86_400_001, 86_400_000));
    }

    // B3.5.3 — adapter liveness / sunset workflow.

    #[test]
    fn sunset_due_boundary_is_at_the_pinned_ms() {
        assert!(!sunset_due(&adapter("a", None, None), i64::MAX));
        let a = adapter("a", Some(9_000), Some(10_000));
        assert!(!sunset_due(&a, 9_999));
        assert!(sunset_due(&a, 10_000)); // due AT the pinned ms
        assert!(sunset_due(&a, 10_001));
        // A past sunset is due at any later now, including far future.
        assert!(sunset_due(&adapter("b", None, Some(0)), i64::MAX));
    }

    #[test]
    fn adapter_phase_matrix_four_cases() {
        // Live: seen within grace, no sunset.
        assert_eq!(
            effective_phase(&adapter("live", Some(9_500), None), 10_000, 1_000),
            AdapterPhase::Live
        );
        // Degraded (stale): quiet beyond grace.
        assert_eq!(
            effective_phase(&adapter("stale", Some(8_000), None), 10_000, 1_000),
            AdapterPhase::Degraded
        );
        // Degraded (never seen).
        assert_eq!(
            effective_phase(&adapter("never", None, None), 10_000, 1_000),
            AdapterPhase::Degraded
        );
        // Retired: sunset due (even though seen this instant).
        assert_eq!(
            effective_phase(&adapter("gone", Some(10_000), Some(10_000)), 10_000, 1_000),
            AdapterPhase::Retired
        );
    }

    #[test]
    fn adapter_phase_ladder_precedence_and_boundaries() {
        // Grace boundary is strict: exactly at grace ⇒ still Live.
        assert_eq!(
            effective_phase(&adapter("edge", Some(9_000), None), 10_000, 1_000),
            AdapterPhase::Live
        );
        // One ms past grace ⇒ Degraded.
        assert_eq!(
            effective_phase(&adapter("edge", Some(8_999), None), 10_000, 1_000),
            AdapterPhase::Degraded
        );
        // Sunset wins over a perfectly fresh heartbeat.
        assert_eq!(
            effective_phase(&adapter("wound", Some(10_000), Some(9_999)), 10_000, 1_000),
            AdapterPhase::Retired
        );
        // Sunset not yet due + stale seen ⇒ Degraded (fall through the ladder).
        assert_eq!(
            effective_phase(&adapter("soon", Some(1_000), Some(99_999)), 10_000, 1_000),
            AdapterPhase::Degraded
        );
        // Sunset not yet due + never seen ⇒ Degraded.
        assert_eq!(
            effective_phase(&adapter("new", None, Some(99_999)), 10_000, 1_000),
            AdapterPhase::Degraded
        );
    }

    // Determinism + serde.

    #[test]
    fn determinism_repeated_calls_are_identical() {
        let s = schedule(1_234);
        for t in [0_i64, 1, 617, 1_234, 9_999, -1] {
            assert_eq!(
                decayed_confidence(0.66, &s, t),
                decayed_confidence(0.66, &s, t)
            );
        }
        let l = adapter("det", Some(5_000), Some(50_000));
        for now in [0_i64, 5_000, 6_000, 49_999, 50_000] {
            assert_eq!(effective_phase(&l, now, 1_000), effective_phase(&l, now, 1_000));
        }
        assert_eq!(newer_of(&stamp(3), &stamp(7)), newer_of(&stamp(3), &stamp(7)));
    }

    #[test]
    fn serde_shapes_and_roundtrips() {
        // Field-by-field JSON shapes are pinned.
        assert_eq!(
            serde_json::to_string(&schedule(1_000)).unwrap(),
            r#"{"half_life_ms":1000}"#
        );
        assert_eq!(
            serde_json::to_string(&stamp(7)).unwrap(),
            r#"{"as_of_ms":7}"#
        );
        assert_eq!(serde_json::to_string(&AdapterPhase::Live).unwrap(), r#""Live""#);
        assert_eq!(
            serde_json::to_string(&AdapterPhase::Degraded).unwrap(),
            r#""Degraded""#
        );
        assert_eq!(
            serde_json::to_string(&AdapterPhase::Retired).unwrap(),
            r#""Retired""#
        );
        assert_eq!(
            serde_json::to_string(&adapter("x", None, None)).unwrap(),
            r#"{"adapter":"x","last_seen_ms":null,"sunset_at_ms":null}"#
        );

        // Round-trips.
        let s: DecaySchedule = serde_json::from_str(r#"{"half_life_ms":250}"#).unwrap();
        assert_eq!(s, schedule(250));
        let st: AsOfStamp = serde_json::from_str(r#"{"as_of_ms":123}"#).unwrap();
        assert_eq!(st, stamp(123));
        let l: AdapterLiveness =
            serde_json::from_str(r#"{"adapter":"y","last_seen_ms":42,"sunset_at_ms":null}"#)
                .unwrap();
        assert_eq!(l, adapter("y", Some(42), None));
        assert_eq!(
            serde_json::to_string(&l).unwrap(),
            r#"{"adapter":"y","last_seen_ms":42,"sunset_at_ms":null}"#
        );

        // Error: Serialize-only (pinned shape), Display renders the reason.
        assert_eq!(
            serde_json::to_string(&DecayError::BadInput("half_life_ms")).unwrap(),
            r#"{"BadInput":"half_life_ms"}"#
        );
        assert_eq!(
            DecayError::BadInput("half_life_ms").to_string(),
            "invalid input: half_life_ms"
        );
    }
}
