//! Large-intake CI review checkpoint (task B5.5 · frozen interface §3 ·
//! B5.5.1–B5.5.3).
//!
//! Bulk material is the normal failure mode of large collections: it arrives
//! faster than it can be read, and review pressure silently degrades into
//! acceptance. This module is the deterministic checkpoint between "material
//! arrived" and "material entered the pipeline":
//!
//! * [`red_flag_checklist`] (B5.5.1) — a fixed, structured list of generic
//!   red-flag lessons with the concrete check to run for each. The text is
//!   deliberately doctrine-level (patterns, not people): no item names or
//!   accuses a real person, source, or organisation, and the list is a
//!   `'static` constant so every reviewer and every CI run sees the same
//!   bytes.
//! * [`sample_indices`] (B5.5.2) — deterministic sampled re-verification:
//!   given an intake of `total` items, a sampling rate, and a seed, produce
//!   the exact set of indices to re-verify. The same `(total, rate, seed)`
//!   always yields the identical sorted, deduplicated index set, so an audit
//!   can re-derive the sample from the seed alone.
//! * [`canary_report`] + [`gate_check`] (B5.5.3) — the canary accounting and
//!   the fail-closed acceptance gate: an intake with red flags, an
//!   undersized sample, or (when required) missing canaries is REJECTED, and
//!   the first matching failure is returned in a pinned order.
//!
//! # Documented edge rules (spec silent; conservative reading chosen)
//!
//! * [`sample_indices`] rejects `rate_pct > 100` with `BadInput("rate")` —
//!   a rate above 100 is not a sampling instruction, it is a broken caller.
//!   `rate_pct == 0` is legal and yields the empty sample (nothing is
//!   re-verified); `total == 0` yields the empty sample for every rate.
//! * `size = ceil(total × rate_pct / 100)` is computed in `u128`, so even a
//!   `usize::MAX`-scale intake cannot overflow; `rate_pct == 100` (or any
//!   rate whose ceiling reaches `total`) returns all indices in order.
//! * [`red_flag_checklist`] returns the same slice on every call
//!   (`LazyLock`-initialised `'static` data). Items are pinned: 10 items,
//!   ids `1..=10`, ids strictly ascending.
//! * [`canary_report`] lists missing items in lexicographic order and does
//!   NOT deduplicate: the frozen text says "items with `!present`, sorted",
//!   and elsewhere the interface writes "sorted + deduped" when both are
//!   meant. A repeated missing item is repeated in the report, so a
//!   malformed check list cannot hide behind deduplication.
//! * [`gate_check`] takes `min_rate_pct` literally with no extra validation:
//!   a nonsensical minimum above 100 can never be met (`needed > items`), so
//!   the gate fails closed with `UnderSampled` rather than opening.
//! * [`gate_check`] trusts `BatchIntake::sampled` as reported; a `sampled`
//!   count larger than `items` is not itself a failure (the fail-closed
//!   concerns are undersampling and missing canaries, which are checked
//!   unconditionally). The field is a report of what was already done, not
//!   an instruction — nothing in this module samples on the caller's behalf.
//! * The only `BadInput` raised by [`gate_check`] is `BadInput("items")` for
//!   an empty intake, and it is checked FIRST: no other verdict about a
//!   zero-item intake is meaningful.
//!
//! # Sampling algorithm, pinned (B5.5.2)
//!
//! A 64-bit linear congruential generator with the Knuth MMIX constants
//! (full period `2^64`):
//!
//! ```text
//! state₀ = seed
//! stateₙ₊₁ = stateₙ × 6364136223846793005 + 1442695040888963407  (mod 2^64)
//! ```
//!
//! For an intake of `total` items and a computed `size`:
//!
//! 1. If `rate_pct == 0 || total == 0`: return `[]`.
//! 2. Otherwise draw one value per index: for `i in 0..total`, advance the
//!    generator once and assign the drawn value as the priority of index
//!    `i` (so index `i` gets `stateₙ₊₁` of step `i + 1`).
//! 3. Select the `size` smallest `(priority, index)` pairs — ties on
//!    priority are broken by the smaller index, so the selection is a total
//!    order and cannot be ambiguous.
//! 4. Return the selected indices sorted ascending.
//!
//! Same `(total, rate_pct, seed)` ⇒ identical output, on every platform and
//! every run. There is no global state, no clock read, and no randomness
//! beyond the caller's seed.
//!
//! Nothing here touches the clock, the filesystem, the network, or global
//! state: identical inputs always produce identical outputs.

use std::fmt;
use std::sync::LazyLock;

use serde::{Deserialize, Serialize};

// ── B5.5.1 · Red-flag checklist ──────────────────────────────────────────────

/// One structured red-flag lesson: the generic pattern to watch for
/// (`lesson`) and the concrete step a reviewer runs when it is suspected
/// (`check`).
///
/// The text is doctrine-level — it describes patterns, never real people,
/// sources, or organisations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RedFlag {
    /// Stable identifier (pinned: `1..=10`, ascending).
    pub id: u16,
    /// The generic lesson: what the pattern tends to mean.
    pub lesson: String,
    /// The check to run: what the reviewer actually does about it.
    pub check: String,
}

/// Build one checklist item.
fn flag(id: u16, lesson: &str, check: &str) -> RedFlag {
    RedFlag {
        id,
        lesson: lesson.to_string(),
        check: check.to_string(),
    }
}

/// The pinned red-flag checklist (≥ 8 items; exactly 10).
///
/// Returned by [`red_flag_checklist`] and built once, process-wide.
static RED_FLAG_CHECKLIST: LazyLock<Vec<RedFlag>> = LazyLock::new(|| {
    vec![
        flag(
            1,
            "Access or privilege grows beyond what the stated task explains.",
            "Compare every granted access against the task's stated need; growth requires a written justification before acceptance.",
        ),
        flag(
            2,
            "Nested citing chains let claims look sourced while nothing stands on primary evidence.",
            "Walk each claim to its root; a chain that terminates in another citation instead of evidence is a finding.",
        ),
        flag(
            3,
            "Urgency pressure is applied to skip or shorten review procedures.",
            "Hold the review clock against the urgency: unverified material stays unverified regardless of deadlines.",
        ),
        flag(
            4,
            "Bulk material arrives from a single channel with no independent cross-check.",
            "Require at least one independent channel to corroborate a fresh sample before bulk acceptance.",
        ),
        flag(
            5,
            "Provenance is too clean: no contradictions, no gaps, no uncertainty.",
            "Actively look for the messiness real collection produces — missing fields, format drift, outliers — before trusting it.",
        ),
        flag(
            6,
            "Material with no counter-evidence section argues only one direction.",
            "Require an explicit counter-evidence or disconfirming section; its absence is itself a finding.",
        ),
        flag(
            7,
            "Access patterns are atypical for the claimed collection method.",
            "Profile timing, volume, and breadth, and compare against how the claimed method normally behaves.",
        ),
        flag(
            8,
            "Sourcing resists follow-up questions and refuses provenance detail.",
            "Ask the pointed follow-ups; refusal to answer provenance questions counts against acceptance.",
        ),
        flag(
            9,
            "Supposedly independent items share a uniform voice or formatting.",
            "Sample across the intake for identical phrasing, templates, or metadata; uniformity across claimed-independent sources is a flag.",
        ),
        flag(
            10,
            "Completeness claims carefully exclude the known-hard cases.",
            "Spot-check that the hard cases are handled rather than quietly omitted, before accepting a completeness claim.",
        ),
    ]
});

/// The structured red-flag checklist for large-intake review (B5.5.1).
///
/// Returns the same `'static` slice on every call. All items are generic
/// lessons with no real-person claims; ids are unique and ascending.
pub fn red_flag_checklist() -> &'static [RedFlag] {
    RED_FLAG_CHECKLIST.as_slice()
}

// ── B5.5.2 · Deterministic sampled re-verification ───────────────────────────

/// One LCG step: `state × 6364136223846793005 + 1442695040888963407 (mod 2^64)`
/// (Knuth MMIX constants; full period `2^64`).
///
/// The constants and the draw-per-index scheme are part of the module's
/// frozen algorithm: changing either changes every pinned sample.
fn lcg_next(state: u64) -> u64 {
    state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407)
}

/// Deterministic sampled re-verification (B5.5.2).
///
/// Returns the indices of the items to re-verify for an intake of `total`
/// items at `rate_pct` percent, selected with the seed-pinned LCG scheme
/// documented at module level.
///
/// * `rate_pct > 100` → [`GateError::BadInput`]`("rate")`.
/// * `rate_pct == 0` or `total == 0` → empty sample.
/// * otherwise the sample has exactly `ceil(total × rate_pct / 100)`
///   indices, all distinct, strictly ascending, and each `< total` (when the
///   ceiling reaches `total`, the sample is simply all indices).
///
/// Same `(total, rate_pct, seed)` ⇒ identical output.
pub fn sample_indices(total: usize, rate_pct: u8, seed: u64) -> Result<Vec<usize>, GateError> {
    if rate_pct > 100 {
        return Err(GateError::BadInput("rate"));
    }
    if rate_pct == 0 || total == 0 {
        return Ok(Vec::new());
    }
    // ceil(total × rate / 100), in u128 so no usize scale can overflow.
    let size = ((total as u128 * rate_pct as u128).div_ceil(100)) as usize;
    if size >= total {
        return Ok((0..total).collect());
    }
    // Draw one priority per index, then keep the `size` smallest
    // (priority, index) pairs; the tuple order breaks ties by index.
    let mut state = seed;
    let mut ranked: Vec<(u64, usize)> = Vec::with_capacity(total);
    for i in 0..total {
        state = lcg_next(state);
        ranked.push((state, i));
    }
    ranked.sort_unstable();
    let mut out: Vec<usize> = ranked[..size].iter().map(|&(_, i)| i).collect();
    out.sort_unstable();
    Ok(out)
}

// ── B5.5.3 · Canary report + fail-closed gate ────────────────────────────────

/// One canary verification result: whether canary `canary_id` planted for
/// `item` was found present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryCheck {
    /// The intake item the canary was planted for.
    pub item: String,
    /// The canary token/id that was looked for.
    pub canary_id: String,
    /// Whether the canary was observed.
    pub present: bool,
}

/// Accounting over a set of canary checks.
///
/// `missing` lists the `item`s whose canary was absent, in lexicographic
/// order (duplicates are kept — see the module-level edge rules);
/// `verified` counts the checks that were present.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanaryReport {
    /// Number of checks with `present == true`.
    pub verified: usize,
    /// Items with `present == false`, sorted; **not** deduplicated.
    pub missing: Vec<String>,
}

/// Build the canary accounting for a batch of checks (B5.5.3).
///
/// Empty input → `verified == 0`, `missing == []`.
pub fn canary_report(checks: &[CanaryCheck]) -> CanaryReport {
    let verified = checks.iter().filter(|c| c.present).count();
    let mut missing: Vec<String> = checks
        .iter()
        .filter(|c| !c.present)
        .map(|c| c.item.clone())
        .collect();
    missing.sort();
    CanaryReport { verified, missing }
}

/// The already-collected facts about one large-intake batch, as reported by
/// the intake pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchIntake {
    /// Batch identifier (for the rejection record).
    pub batch: String,
    /// Total items in the batch.
    pub items: usize,
    /// Items actually re-verified.
    pub sampled: usize,
    /// Red-flag ids ([`RedFlag::id`]) raised for this batch.
    pub flags: Vec<u16>,
    /// Number of required canaries that were not found.
    pub canary_missing: usize,
}

/// Fail-closed gate over an intake batch (B5.5.3).
///
/// Returns `Ok(())` only when the batch is clean, adequately sampled, and
/// canary-complete as required. Failures are returned FIRST-MATCH in this
/// pinned order:
///
/// 1. `items == 0` → [`GateError::BadInput`]`("items")` (before everything
///    else — no other verdict about an empty intake is meaningful);
/// 2. non-empty `flags` → [`GateError::RedFlagsRaised`] (the batch already
///    failed review; its sampling numbers no longer matter);
/// 3. `sampled < ceil(items × min_rate_pct / 100)` →
///    [`GateError::UnderSampled`] `{ needed, got: sampled }`;
/// 4. `canary_required && canary_missing > 0` → [`GateError::CanaryMissing`];
/// 5. otherwise `Ok(())`.
///
/// `min_rate_pct` is taken literally (no range validation): a value above
/// 100 can never be met and therefore fails closed with `UnderSampled`.
pub fn gate_check(
    intake: &BatchIntake,
    min_rate_pct: u8,
    canary_required: bool,
) -> Result<(), GateError> {
    if intake.items == 0 {
        return Err(GateError::BadInput("items"));
    }
    if !intake.flags.is_empty() {
        return Err(GateError::RedFlagsRaised(intake.flags.len()));
    }
    let needed = ((intake.items as u128 * min_rate_pct as u128).div_ceil(100)) as usize;
    if intake.sampled < needed {
        return Err(GateError::UnderSampled {
            needed,
            got: intake.sampled,
        });
    }
    if canary_required && intake.canary_missing > 0 {
        return Err(GateError::CanaryMissing(intake.canary_missing));
    }
    Ok(())
}

/// Why a batch was refused by [`gate_check`] (or why a sampling request was
/// rejected by [`sample_indices`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum GateError {
    /// A named input was missing or outside its valid domain.
    BadInput(&'static str),
    /// The sample is below the required minimum: `needed` indices were
    /// required, `got` were reported.
    UnderSampled { needed: usize, got: usize },
    /// `n` required canaries were not found.
    CanaryMissing(usize),
    /// `n` red flags were raised for the batch.
    RedFlagsRaised(usize),
}

impl fmt::Display for GateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GateError::BadInput(reason) => write!(f, "invalid input: {reason}"),
            GateError::UnderSampled { needed, got } => {
                write!(f, "under-sampled: needed {needed}, got {got}")
            }
            GateError::CanaryMissing(n) => write!(f, "canary missing: {n}"),
            GateError::RedFlagsRaised(n) => write!(f, "red flags raised: {n}"),
        }
    }
}

impl std::error::Error for GateError {}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn intake(items: usize, sampled: usize, flags: Vec<u16>, canary_missing: usize) -> BatchIntake {
        BatchIntake {
            batch: "batch-x".to_string(),
            items,
            sampled,
            flags,
            canary_missing,
        }
    }

    fn check(item: &str, canary_id: &str, present: bool) -> CanaryCheck {
        CanaryCheck {
            item: item.to_string(),
            canary_id: canary_id.to_string(),
            present,
        }
    }

    // ── B5.5.1 · checklist ───────────────────────────────────────────────────

    #[test]
    fn checklist_has_at_least_eight_unique_nonempty_items() {
        let list = red_flag_checklist();
        assert!(list.len() >= 8, "checklist must have at least 8 items");
        let mut ids: Vec<u16> = list.iter().map(|f| f.id).collect();
        let before = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), before, "ids must be unique");
        for f in list {
            assert!(!f.lesson.trim().is_empty(), "lesson {} empty", f.id);
            assert!(!f.check.trim().is_empty(), "check {} empty", f.id);
        }
    }

    #[test]
    fn checklist_ids_are_pinned_and_ascending() {
        let ids: Vec<u16> = red_flag_checklist().iter().map(|f| f.id).collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "declaration order is ascending");
    }

    #[test]
    fn checklist_is_stable_across_calls() {
        let a = red_flag_checklist();
        let b = red_flag_checklist();
        assert!(std::ptr::eq(a, b), "same 'static slice every call");
        assert_eq!(a, b);
    }

    #[test]
    fn checklist_covers_the_named_lesson_families() {
        // The eight lesson families named by the interface must each be
        // recognizable somewhere in the pinned doctrine text.
        let hay: Vec<String> = red_flag_checklist()
            .iter()
            .map(|f| format!("{} {}", f.lesson, f.check).to_lowercase())
            .collect();
        for needle in [
            "privilege",
            "citing",
            "urgency",
            "single channel",
            "provenance",
            "counter-evidence",
            "access pattern",
            "refus",
        ] {
            assert!(
                hay.iter().any(|h| h.contains(needle)),
                "no checklist item covers {:?}",
                needle
            );
        }
    }

    #[test]
    fn checklist_is_generic_no_real_person_claims() {
        // Doctrine-level phrasing only: no capitalised-name style targeting.
        for f in red_flag_checklist() {
            let text = format!("{} {}", f.lesson, f.check);
            for banned in ["Agent ", "Mr ", "Ms ", "Dr "] {
                assert!(
                    !text.contains(banned),
                    "item {} looks like a person claim: {:?}",
                    f.id,
                    banned
                );
            }
        }
    }

    // ── B5.5.2 · sampling ────────────────────────────────────────────────────

    #[test]
    fn sampling_rejects_rate_above_100() {
        assert_eq!(sample_indices(10, 101, 1), Err(GateError::BadInput("rate")));
        assert_eq!(
            sample_indices(10, 255, 1),
            Err(GateError::BadInput("rate"))
        );
        assert!(sample_indices(0, 101, 1).is_err(), "rate checked before total");
        assert!(sample_indices(10, 100, 1).is_ok());
    }

    #[test]
    fn sampling_rate_zero_is_empty() {
        assert_eq!(sample_indices(10, 0, 42).unwrap(), Vec::<usize>::new());
        assert_eq!(sample_indices(0, 0, 42).unwrap(), Vec::<usize>::new());
        assert_eq!(sample_indices(1, 0, 0).unwrap(), Vec::<usize>::new());
    }

    #[test]
    fn sampling_total_zero_is_empty_for_every_rate() {
        for rate in [0u8, 1, 50, 99, 100] {
            assert_eq!(sample_indices(0, rate, 7).unwrap(), Vec::<usize>::new());
        }
    }

    #[test]
    fn sampling_rate_100_returns_all_indices() {
        assert_eq!(sample_indices(7, 100, 0).unwrap(), (0..7).collect::<Vec<usize>>());
        assert_eq!(
            sample_indices(5, 100, 99).unwrap(),
            (0..5).collect::<Vec<usize>>()
        );
        // Rate 100 = all, exactly once, in order.
        assert_eq!(sample_indices(3, 100, 5).unwrap(), vec![0, 1, 2]);
    }

    #[test]
    fn sampling_size_is_ceiling_of_rate() {
        // ceil(total × rate / 100) — rounded UP.
        assert_eq!(sample_indices(10, 1, 1).unwrap().len(), 1); // 0.1 → 1
        assert_eq!(sample_indices(10, 15, 7).unwrap().len(), 2); // 1.5 → 2
        assert_eq!(sample_indices(7, 50, 123).unwrap().len(), 4); // 3.5 → 4
        assert_eq!(sample_indices(1, 50, 3).unwrap().len(), 1); // 0.5 → 1
        assert_eq!(sample_indices(13, 77, 12345).unwrap().len(), 11); // 10.01 → 11
        assert_eq!(sample_indices(100, 25, 1).unwrap().len(), 25); // exact
        // Ceiling that reaches total collapses to all.
        assert_eq!(sample_indices(10, 99, 1).unwrap().len(), 10);
    }

    #[test]
    fn sampling_pinned_expected_sets() {
        // Pinned vectors produced by the module's own LCG scheme
        // (documented at module level; constants frozen).
        assert_eq!(sample_indices(10, 40, 42).unwrap(), vec![5, 6, 7, 9]);
        assert_eq!(sample_indices(8, 25, 7).unwrap(), vec![4, 5]);
        assert_eq!(sample_indices(6, 1, 0).unwrap(), vec![0]);
        assert_eq!(
            sample_indices(13, 77, 12345).unwrap(),
            vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 12]
        );
        assert_eq!(sample_indices(10, 15, 8).unwrap(), vec![5, 7]);
    }

    #[test]
    fn sampling_is_deterministic_for_same_seed() {
        for (total, rate, seed) in [(10usize, 40u8, 42u64), (50, 10, 7), (13, 77, 12345)] {
            let a = sample_indices(total, rate, seed).unwrap();
            let b = sample_indices(total, rate, seed).unwrap();
            assert_eq!(a, b);
        }
        // Different seeds select different sets (for a pinned pair).
        assert_ne!(
            sample_indices(10, 15, 7).unwrap(),
            sample_indices(10, 15, 8).unwrap()
        );
    }

    #[test]
    fn sampling_output_is_sorted_deduped_and_in_bounds() {
        for (total, rate, seed) in [
            (1usize, 1u8, 0u64),
            (2, 50, 1),
            (10, 40, 42),
            (37, 33, 9),
            (64, 50, 1234),
            (100, 99, 5),
        ] {
            let out = sample_indices(total, rate, seed).unwrap();
            assert!(out.windows(2).all(|w| w[0] < w[1]), "strictly ascending");
            assert!(
                out.iter().all(|&i| i < total),
                "every index in bounds for ({total}, {rate}, {seed})"
            );
            let mut sorted = out.clone();
            sorted.sort_unstable();
            sorted.dedup();
            assert_eq!(out, sorted, "already sorted and deduped");
        }
    }

    #[test]
    fn sampling_boundary_totals_agree_with_ceiling_rule() {
        // size == total is fine (ceiling reached); size == 0 only via rate 0.
        let out = sample_indices(2, 50, 1).unwrap();
        assert_eq!(out.len(), 1);
        let out = sample_indices(1, 1, 0).unwrap();
        assert_eq!(out, vec![0]);
    }

    // ── B5.5.3 · canary report ───────────────────────────────────────────────

    #[test]
    fn canary_report_counts_present_and_sorts_missing() {
        let checks = vec![
            check("zeta", "TLW-URL-a", false),
            check("alpha", "TLW-URL-b", true),
            check("mid", "TLW-URL-c", true),
            check("beta", "TLW-URL-d", false),
        ];
        let report = canary_report(&checks);
        assert_eq!(report.verified, 2);
        assert_eq!(report.missing, vec!["beta".to_string(), "zeta".to_string()]);
    }

    #[test]
    fn canary_report_empty_input() {
        let report = canary_report(&[]);
        assert_eq!(report.verified, 0);
        assert!(report.missing.is_empty());
    }

    #[test]
    fn canary_report_all_present_has_no_missing() {
        let checks = vec![check("a", "c1", true), check("b", "c2", true)];
        let report = canary_report(&checks);
        assert_eq!(report.verified, 2);
        assert!(report.missing.is_empty());
    }

    #[test]
    fn canary_report_duplicate_missing_items_are_listed_verbatim() {
        // Documented literal reading: sorted, NOT deduplicated.
        let checks = vec![
            check("dup", "c1", false),
            check("other", "c2", false),
            check("dup", "c3", false),
        ];
        let report = canary_report(&checks);
        assert_eq!(report.verified, 0);
        assert_eq!(
            report.missing,
            vec!["dup".to_string(), "dup".to_string(), "other".to_string()]
        );
    }

    // ── B5.5.3 · gate ────────────────────────────────────────────────────────

    #[test]
    fn gate_rejects_zero_items_first() {
        // Even with flags, missing canaries, and a min rate, items == 0 wins.
        let b = intake(0, 0, vec![1, 2], 5);
        assert_eq!(gate_check(&b, 50, true), Err(GateError::BadInput("items")));
        let b = intake(0, 0, vec![], 0);
        assert_eq!(gate_check(&b, 0, false), Err(GateError::BadInput("items")));
    }

    #[test]
    fn gate_red_flags_beat_everything_else() {
        // Flags non-empty AND undersampled AND canary-missing.
        let b = intake(100, 1, vec![3, 7], 4);
        assert_eq!(gate_check(&b, 50, true), Err(GateError::RedFlagsRaised(2)));
        let b = intake(10, 0, vec![9], 1);
        assert_eq!(gate_check(&b, 100, true), Err(GateError::RedFlagsRaised(1)));
    }

    #[test]
    fn gate_undersampled_reports_needed_and_got() {
        let b = intake(100, 24, vec![], 0);
        assert_eq!(
            gate_check(&b, 25, false),
            Err(GateError::UnderSampled { needed: 25, got: 24 })
        );
        // Ceiling, not floor: 10 × 15% = 1.5 → needed 2.
        let b = intake(10, 1, vec![], 0);
        assert_eq!(
            gate_check(&b, 15, false),
            Err(GateError::UnderSampled { needed: 2, got: 1 })
        );
    }

    #[test]
    fn gate_undersampled_boundary_passes() {
        // sampled == needed is accepted.
        let b = intake(100, 25, vec![], 0);
        assert_eq!(gate_check(&b, 25, false), Ok(()));
        let b = intake(10, 2, vec![], 0);
        assert_eq!(gate_check(&b, 15, false), Ok(()));
    }

    #[test]
    fn gate_min_rate_zero_needs_no_sample() {
        let b = intake(1000, 0, vec![], 0);
        assert_eq!(gate_check(&b, 0, false), Ok(()));
    }

    #[test]
    fn gate_canary_missing_only_when_required() {
        let b = intake(10, 10, vec![], 3);
        assert_eq!(gate_check(&b, 50, true), Err(GateError::CanaryMissing(3)));
        // Not required → missing canaries do not fail the gate on their own.
        assert_eq!(gate_check(&b, 50, false), Ok(()));
    }

    #[test]
    fn gate_check_order_undersampled_before_canary() {
        let b = intake(10, 1, vec![], 4);
        assert_eq!(
            gate_check(&b, 50, true),
            Err(GateError::UnderSampled { needed: 5, got: 1 })
        );
    }

    #[test]
    fn gate_pass_matrix() {
        // Full pass: no flags, adequate sample, canaries present.
        assert_eq!(gate_check(&intake(100, 20, vec![], 0), 20, true), Ok(()));
        // Pass with canaries not required though missing.
        assert_eq!(gate_check(&intake(100, 20, vec![], 7), 20, false), Ok(()));
        // Pass when canary required and all present.
        assert_eq!(gate_check(&intake(7, 7, vec![], 0), 100, true), Ok(()));
    }

    #[test]
    fn gate_min_rate_above_100_fails_closed() {
        // Taken literally: needed = ceil(items × min_rate / 100) > items, so
        // the gate can never pass — failed closed, not opened.
        let b = intake(10, 10, vec![], 0);
        assert_eq!(
            gate_check(&b, 200, false),
            Err(GateError::UnderSampled { needed: 20, got: 10 })
        );
        // u8::MAX is the extreme of the same rule, with no overflow.
        let b = intake(3, 3, vec![], 0);
        assert_eq!(
            gate_check(&b, 255, false),
            Err(GateError::UnderSampled { needed: 8, got: 3 })
        );
    }

    #[test]
    fn gate_check_is_pure_and_repeatable() {
        let b = intake(50, 10, vec![], 1);
        let first = gate_check(&b, 25, true);
        let second = gate_check(&b, 25, true);
        assert_eq!(first, second);
        assert_eq!(first, Err(GateError::UnderSampled { needed: 13, got: 10 }));
    }

    // ── errors + serde ───────────────────────────────────────────────────────

    #[test]
    fn gate_error_display_messages() {
        assert_eq!(
            GateError::BadInput("rate").to_string(),
            "invalid input: rate"
        );
        assert_eq!(
            GateError::UnderSampled { needed: 25, got: 4 }.to_string(),
            "under-sampled: needed 25, got 4"
        );
        assert_eq!(GateError::CanaryMissing(3).to_string(), "canary missing: 3");
        assert_eq!(
            GateError::RedFlagsRaised(2).to_string(),
            "red flags raised: 2"
        );
    }

    #[test]
    fn gate_error_implements_std_error() {
        let e: Box<dyn std::error::Error> = Box::new(GateError::CanaryMissing(1));
        assert_eq!(e.to_string(), "canary missing: 1");
    }

    #[test]
    fn serde_shapes_and_roundtrips() {
        // BatchIntake: exact shape + round-trip.
        let b = intake(100, 25, vec![1, 4], 2);
        assert_eq!(
            serde_json::to_string(&b).unwrap(),
            r#"{"batch":"batch-x","items":100,"sampled":25,"flags":[1,4],"canary_missing":2}"#
        );
        let back: BatchIntake = serde_json::from_str(
            r#"{"batch":"b2","items":9,"sampled":0,"flags":[],"canary_missing":0}"#,
        )
        .unwrap();
        assert_eq!(back.batch, "b2");
        assert_eq!(back.items, 9);
        assert_eq!(back.sampled, 0);
        assert!(back.flags.is_empty());
        assert_eq!(back.canary_missing, 0);

        // GateError: Serialize-only (pinned shapes) — `BadInput(&'static str)`
        // cannot deserialize into `'static`.
        assert_eq!(
            serde_json::to_string(&GateError::BadInput("items")).unwrap(),
            r#"{"BadInput":"items"}"#
        );
        assert_eq!(
            serde_json::to_string(&GateError::UnderSampled { needed: 25, got: 4 }).unwrap(),
            r#"{"UnderSampled":{"needed":25,"got":4}}"#
        );
        assert_eq!(
            serde_json::to_string(&GateError::CanaryMissing(3)).unwrap(),
            r#"{"CanaryMissing":3}"#
        );
        assert_eq!(
            serde_json::to_string(&GateError::RedFlagsRaised(2)).unwrap(),
            r#"{"RedFlagsRaised":2}"#
        );
    }
}
