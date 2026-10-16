//! Adversarial futures — scenario matrix, stealth-plan run harness, loss reports.
//!
//! Frozen interface §5 (B4.1.1–B4.1.3). This module stress-tests *collection
//! plans* against a pinned 2×2 space of adversarial futures and classifies how
//! each plan would end:
//!
//! 1. **B4.1.1 — the 2×2 scenario matrix** ([`standard_matrix`]): detector
//!    capability (`Weak` / `Strong`) × economic pressure (`Low` / `High`),
//!    exactly four scenarios in a fixed order so every run of the suite covers
//!    the same futures. Ids are stable (`weak-low` · `weak-high` ·
//!    `strong-low` · `strong-high`).
//! 2. **B4.1.2 — stealth-plan run harness** ([`CollectionPlan`],
//!    [`StealthProfile`], [`run_matrix`]): each plan declares its daily volume,
//!    yield uniqueness, and stealth posture (pseudonym rotation, pacing,
//!    stream isolation); [`run_matrix`] evaluates the cross product
//!    scenarios × plans in deterministic order.
//! 3. **B4.1.3 — loss reports** ([`evaluate`], [`LossReport`], [`summarize`]):
//!    a pinned heuristic ladder classifies every (scenario, plan) pair into one
//!    [`LossKind`] — `Sustained`, `Burned`, `PricedOut`, or `UnderCollected` —
//!    with a deterministic note; [`summarize`] aggregates counts per kind.
//!
//! The ladder is **first match wins**, ordered by severity of loss
//! (account destruction before economics before yield floor):
//!
//! 1. `Strong` detector with rotation off **or** volume above 10/day ⇒
//!    [`LossKind::Burned`] — exposure the persona cannot survive.
//! 2. `High` pressure with volume above 5/day **or** no stream isolation ⇒
//!    [`LossKind::PricedOut`] — the ask attracts costly countermeasures.
//! 3. uniqueness below 30 ⇒ [`LossKind::UnderCollected`] — the material would
//!    not clear the yield floor even if it survived collection.
//! 4. otherwise ⇒ [`LossKind::Sustained`].
//!
//! `StealthProfile::pacing_ms` is carried as plan metadata (B4.1.2) but the
//! pinned ladder does not branch on it — pacing slows the burn without
//! changing the outcomes above, and the frozen interface defines the ladder
//! without a pacing term.
//!
//! Every function is **pure** — a function of its arguments only, no clock
//! reads, no randomness — so a plan set replays to the same reports and
//! summary for the same inputs.

use serde::{Deserialize, Serialize};

/// Volumes above this many items/day burn a persona under a `Strong` detector
/// even with pseudonym rotation on (ladder rung ①).
const BURN_VOLUME_CEILING: u32 = 10;

/// Volumes above this many items/day attract pricing countermeasures under
/// `High` economic pressure (ladder rung ②).
const PRICE_VOLUME_CEILING: u32 = 5;

/// Minimum uniqueness (in the plan's own units, 0–255) for collected material
/// to count; below this the plan is classed `UnderCollected` (rung ③).
const UNIQUENESS_FLOOR: u8 = 30;

/// How capable the detecting adversary is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DetectorCapability {
    /// Cheap or blind detection — survivable with modest stealth.
    Weak,
    /// Resourced detection — only a careful posture survives.
    Strong,
}

/// How much economic pressure the environment applies to collection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EconomicPressure {
    /// Collecting is cheap; volume rarely triggers countermeasures.
    Low,
    /// Collecting invites countermeasures as volume rises.
    High,
}

/// One cell of the 2×2 adversarial-futures matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scenario {
    /// Stable id, e.g. `weak-low`.
    pub id: String,
    /// Human-readable label (deterministic).
    pub label: String,
    /// Detector capability axis.
    pub detector: DetectorCapability,
    /// Economic pressure axis.
    pub pressure: EconomicPressure,
}

/// The pinned 2×2 matrix: ids `weak-low`, `weak-high`, `strong-low`,
/// `strong-high` — in that order, every combination exactly once.
///
/// The order is part of the interface: [`run_matrix`] emits scenarios in this
/// order, so reports are reproducible across runs.
pub fn standard_matrix() -> Vec<Scenario> {
    vec![
        Scenario {
            id: "weak-low".to_string(),
            label: "weak detector, low economic pressure".to_string(),
            detector: DetectorCapability::Weak,
            pressure: EconomicPressure::Low,
        },
        Scenario {
            id: "weak-high".to_string(),
            label: "weak detector, high economic pressure".to_string(),
            detector: DetectorCapability::Weak,
            pressure: EconomicPressure::High,
        },
        Scenario {
            id: "strong-low".to_string(),
            label: "strong detector, low economic pressure".to_string(),
            detector: DetectorCapability::Strong,
            pressure: EconomicPressure::Low,
        },
        Scenario {
            id: "strong-high".to_string(),
            label: "strong detector, high economic pressure".to_string(),
            detector: DetectorCapability::Strong,
            pressure: EconomicPressure::High,
        },
    ]
}

/// Stealth posture of a collection plan.
///
/// `pacing_ms` is carried for the plan record; the pinned ladder does not
/// branch on it (see module docs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthProfile {
    /// Whether the plan rotates pseudonyms across collection.
    pub pseudonym_rotation: bool,
    /// Inter-request pacing in milliseconds (metadata; no ladder branch).
    pub pacing_ms: i64,
    /// Whether collection streams are isolated from each other.
    pub stream_isolation: bool,
}

/// A candidate collection plan to stress-test against the matrix.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CollectionPlan {
    /// Plan name; copied into every [`LossReport::plan`].
    pub name: String,
    /// Items collected per day.
    pub volume_per_day: u32,
    /// Yield uniqueness (0–255); below 30 the plan is `UnderCollected`.
    pub uniqueness: u8,
    /// The plan's stealth posture.
    pub profile: StealthProfile,
}

/// How a plan ends in a scenario. Declaration order is the [`summarize`]
/// order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LossKind {
    /// Plan clears the ladder — collection continues.
    Sustained,
    /// Persona burned by a strong detector.
    Burned,
    /// Priced out by high economic pressure.
    PricedOut,
    /// Survives, but below the uniqueness floor.
    UnderCollected,
}

/// One (scenario, plan) loss verdict with a deterministic note.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LossReport {
    /// Id of the scenario evaluated (from [`Scenario::id`]).
    pub scenario: String,
    /// Name of the plan evaluated (from [`CollectionPlan::name`]).
    pub plan: String,
    /// The verdict.
    pub loss: LossKind,
    /// Deterministic, human-readable reason (one template per ladder rung).
    pub note: String,
}

/// Evaluate one plan in one scenario via the pinned ladder (first match wins):
///
/// 1. `Strong && (!rotation || volume > 10)` ⇒ [`LossKind::Burned`].
/// 2. `High && (volume > 5 || !isolation)` ⇒ [`LossKind::PricedOut`].
/// 3. `uniqueness < 30` ⇒ [`LossKind::UnderCollected`].
/// 4. otherwise ⇒ [`LossKind::Sustained`].
///
/// Never fails; the note is one deterministic template per rung.
pub fn evaluate(scenario: &Scenario, plan: &CollectionPlan) -> LossReport {
    let loss = if scenario.detector == DetectorCapability::Strong
        && (!plan.profile.pseudonym_rotation || plan.volume_per_day > BURN_VOLUME_CEILING)
    {
        LossKind::Burned
    } else if scenario.pressure == EconomicPressure::High
        && (plan.volume_per_day > PRICE_VOLUME_CEILING || !plan.profile.stream_isolation)
    {
        LossKind::PricedOut
    } else if plan.uniqueness < UNIQUENESS_FLOOR {
        LossKind::UnderCollected
    } else {
        LossKind::Sustained
    };
    LossReport {
        scenario: scenario.id.clone(),
        plan: plan.name.clone(),
        loss,
        note: note_for(loss, plan),
    }
}

/// The note template for a ladder rung — deterministic per rule.
fn note_for(loss: LossKind, plan: &CollectionPlan) -> String {
    match loss {
        LossKind::Burned => format!(
            "strong detector burns the persona: pseudonym_rotation={}, volume_per_day={}",
            plan.profile.pseudonym_rotation, plan.volume_per_day
        ),
        LossKind::PricedOut => format!(
            "high economic pressure prices the plan out: volume_per_day={}, stream_isolation={}",
            plan.volume_per_day, plan.profile.stream_isolation
        ),
        LossKind::UnderCollected => {
            format!("uniqueness {} below floor {UNIQUENESS_FLOOR}", plan.uniqueness)
        }
        LossKind::Sustained => {
            "sustained: plan clears detector and pressure fences above the uniqueness floor"
                .to_string()
        }
    }
}

/// Run every plan against every scenario in [`standard_matrix`] order.
///
/// Reports are scenario-major: all plans for `weak-low`, then all plans for
/// `weak-high`, etc. Empty `plans` is [`MatrixError::BadInput`] (a run of
/// nothing is a mis-programmed call, not an empty result).
pub fn run_matrix(plans: &[CollectionPlan]) -> Result<Vec<LossReport>, MatrixError> {
    if plans.is_empty() {
        return Err(MatrixError::BadInput("plans"));
    }
    let scenarios = standard_matrix();
    let mut reports = Vec::with_capacity(scenarios.len() * plans.len());
    for scenario in &scenarios {
        for plan in plans {
            reports.push(evaluate(scenario, plan));
        }
    }
    Ok(reports)
}

/// Count reports per [`LossKind`] **in declaration order** —
/// `Sustained, Burned, PricedOut, UnderCollected` — with all four kinds
/// always present (zero counts included).
pub fn summarize(reports: &[LossReport]) -> Vec<(LossKind, usize)> {
    const ORDER: [LossKind; 4] = [
        LossKind::Sustained,
        LossKind::Burned,
        LossKind::PricedOut,
        LossKind::UnderCollected,
    ];
    ORDER
        .iter()
        .map(|kind| (*kind, reports.iter().filter(|r| r.loss == *kind).count()))
        .collect()
}

/// Errors from the run harness.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MatrixError {
    /// A named input was empty/invalid; payload is the field name. The wire
    /// form is `{"BadInput":"plans"}`; because the payload is `&'static str`,
    /// deserialization is only possible from `'static` input (literals).
    BadInput(&'static str),
}

impl std::fmt::Display for MatrixError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatrixError::BadInput(field) => {
                write!(f, "invalid scenario-matrix input: `{field}` must not be empty")
            }
        }
    }
}

impl std::error::Error for MatrixError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience builder for test plans (rotation/isolation explicit, pacing
    /// fixed — the ladder never reads pacing).
    fn plan(name: &str, volume: u32, uniqueness: u8, rotation: bool, isolation: bool) -> CollectionPlan {
        CollectionPlan {
            name: name.to_string(),
            volume_per_day: volume,
            uniqueness,
            profile: StealthProfile {
                pseudonym_rotation: rotation,
                pacing_ms: 1200,
                stream_isolation: isolation,
            },
        }
    }

    /// Look up one matrix scenario by id.
    fn scenario(id: &str) -> Scenario {
        standard_matrix()
            .into_iter()
            .find(|s| s.id == id)
            .expect("scenario id from standard_matrix")
    }

    #[test]
    fn matrix_shape_ids_and_all_combos() {
        let m = standard_matrix();
        assert_eq!(m.len(), 4, "exactly the 2x2");
        let ids: Vec<&str> = m.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, ["weak-low", "weak-high", "strong-low", "strong-high"]);
        for s in &m {
            assert!(!s.label.is_empty(), "labels are non-empty");
        }
        // Every (detector, pressure) combination appears exactly once, in order.
        let combos: Vec<(&str, DetectorCapability, EconomicPressure)> =
            m.iter().map(|s| (s.id.as_str(), s.detector, s.pressure)).collect();
        assert_eq!(
            combos,
            vec![
                ("weak-low", DetectorCapability::Weak, EconomicPressure::Low),
                ("weak-high", DetectorCapability::Weak, EconomicPressure::High),
                ("strong-low", DetectorCapability::Strong, EconomicPressure::Low),
                ("strong-high", DetectorCapability::Strong, EconomicPressure::High),
            ]
        );
        // Labels are deterministic and distinct.
        let labels: Vec<&str> = m.iter().map(|s| s.label.as_str()).collect();
        assert_eq!(labels.len(), 4);
        for i in 0..labels.len() {
            for j in (i + 1)..labels.len() {
                assert_ne!(labels[i], labels[j]);
            }
        }
        assert_eq!(scenario("weak-low").label, "weak detector, low economic pressure");
    }

    #[test]
    fn standard_matrix_is_deterministic() {
        assert_eq!(standard_matrix(), standard_matrix());
    }

    #[test]
    fn ladder_rung1_burned_by_rotation_off() {
        // Strong detector, rotation off — burned even at trivial volume.
        let r = evaluate(
            &scenario("strong-low"),
            &plan("quiet", 1, 50, false, true),
        );
        assert_eq!(r.loss, LossKind::Burned);
        assert_eq!(
            r.note,
            "strong detector burns the persona: pseudonym_rotation=false, volume_per_day=1"
        );
    }

    #[test]
    fn ladder_rung1_burned_by_volume_11() {
        // Strong detector, rotation on, volume above the ceiling — burned.
        let r = evaluate(
            &scenario("strong-low"),
            &plan("pusher", 11, 50, true, true),
        );
        assert_eq!(r.loss, LossKind::Burned);
        assert_eq!(
            r.note,
            "strong detector burns the persona: pseudonym_rotation=true, volume_per_day=11"
        );
    }

    #[test]
    fn boundary_volume_10_vs_11_strong_detector() {
        // Pinned boundary: > 10 burns; exactly 10 survives rung ①.
        let lower = evaluate(&scenario("strong-low"), &plan("edge", 10, 50, true, true));
        assert_eq!(lower.loss, LossKind::Sustained);
        let upper = evaluate(&scenario("strong-low"), &plan("edge", 11, 50, true, true));
        assert_eq!(upper.loss, LossKind::Burned);
    }

    #[test]
    fn ladder_rung2_priced_out_by_volume() {
        // High pressure, volume above 5 — priced out (weak detector: rung ① skipped).
        let r = evaluate(
            &scenario("weak-high"),
            &plan("pusher", 6, 50, true, true),
        );
        assert_eq!(r.loss, LossKind::PricedOut);
        assert_eq!(
            r.note,
            "high economic pressure prices the plan out: volume_per_day=6, stream_isolation=true"
        );
    }

    #[test]
    fn boundary_volume_5_vs_6_high_pressure() {
        // Pinned boundary: > 5 prices out; exactly 5 rides.
        let lower = evaluate(&scenario("weak-high"), &plan("edge", 5, 50, true, true));
        assert_eq!(lower.loss, LossKind::Sustained);
        let upper = evaluate(&scenario("weak-high"), &plan("edge", 6, 50, true, true));
        assert_eq!(upper.loss, LossKind::PricedOut);
    }

    #[test]
    fn ladder_rung2_priced_out_by_missing_isolation() {
        // High pressure, tiny volume, but no stream isolation — priced out.
        let r = evaluate(
            &scenario("weak-high"),
            &plan("leaky", 1, 50, true, false),
        );
        assert_eq!(r.loss, LossKind::PricedOut);
        assert_eq!(
            r.note,
            "high economic pressure prices the plan out: volume_per_day=1, stream_isolation=false"
        );
    }

    #[test]
    fn ladder_rung3_under_collected() {
        // Low pressure, weak detector, but uniqueness below the floor.
        let r = evaluate(
            &scenario("weak-low"),
            &plan("thin", 1, 29, true, true),
        );
        assert_eq!(r.loss, LossKind::UnderCollected);
        assert_eq!(r.note, "uniqueness 29 below floor 30");
    }

    #[test]
    fn boundary_uniqueness_29_vs_30() {
        // Pinned boundary: < 30 under-collects; exactly 30 sustains.
        let below = evaluate(&scenario("weak-low"), &plan("edge", 1, 29, true, true));
        assert_eq!(below.loss, LossKind::UnderCollected);
        let at = evaluate(&scenario("weak-low"), &plan("edge", 1, 30, true, true));
        assert_eq!(at.loss, LossKind::Sustained);
        assert_eq!(
            at.note,
            "sustained: plan clears detector and pressure fences above the uniqueness floor"
        );
    }

    #[test]
    fn ladder_rung4_sustained() {
        // Clears every rung: modest volume, rotation on, isolated, unique.
        let r = evaluate(
            &scenario("strong-high"),
            &plan("careful", 5, 30, true, true),
        );
        assert_eq!(r.loss, LossKind::Sustained);
    }

    #[test]
    fn ladder_first_match_wins_burn_over_price() {
        // Matches rungs ① and ②; ① wins (severity order).
        let r = evaluate(
            &scenario("strong-high"),
            &plan("double", 6, 50, false, true),
        );
        assert_eq!(r.loss, LossKind::Burned);
    }

    #[test]
    fn ladder_first_match_wins_price_over_under_collected() {
        // Matches rungs ② and ③; ② wins.
        let r = evaluate(
            &scenario("weak-high"),
            &plan("double", 6, 1, true, true),
        );
        assert_eq!(r.loss, LossKind::PricedOut);
    }

    #[test]
    fn evaluate_copies_scenario_and_plan_identity() {
        let s = scenario("strong-high");
        let p = plan("alpha", 1, 50, true, true);
        let r = evaluate(&s, &p);
        assert_eq!(r.scenario, "strong-high");
        assert_eq!(r.plan, "alpha");
    }

    #[test]
    fn run_matrix_4xn_order() {
        let plans = [
            plan("a", 1, 50, true, true),
            plan("b", 1, 50, false, true),
            plan("c", 6, 50, true, true),
        ];
        let reports = run_matrix(&plans).expect("non-empty plans");
        assert_eq!(reports.len(), 4 * plans.len());
        let matrix = standard_matrix();
        for i in 0..matrix.len() {
            for j in 0..plans.len() {
                let r = &reports[i * plans.len() + j];
                assert_eq!(r.scenario, matrix[i].id, "scenario-major order");
                assert_eq!(r.plan, plans[j].name, "plan order preserved");
            }
        }
    }

    #[test]
    fn run_matrix_single_plan_scenario_order() {
        let plans = [plan("solo", 1, 50, true, true)];
        let reports = run_matrix(&plans).unwrap();
        assert_eq!(reports.len(), 4);
        let ids: Vec<&str> = reports.iter().map(|r| r.scenario.as_str()).collect();
        assert_eq!(ids, ["weak-low", "weak-high", "strong-low", "strong-high"]);
        // Single full-stealth plan survives all four futures.
        assert!(reports.iter().all(|r| r.loss == LossKind::Sustained));
    }

    #[test]
    fn run_matrix_empty_plans_err() {
        let err = run_matrix(&[]).unwrap_err();
        assert_eq!(err, MatrixError::BadInput("plans"));
        assert!(err.to_string().contains("plans"));
    }

    #[test]
    fn summarize_counts_all_kinds_in_declaration_order() {
        // One report per kind, shuffled input.
        let reports = vec![
            LossReport { scenario: "s".into(), plan: "p".into(), loss: LossKind::UnderCollected, note: "n".into() },
            LossReport { scenario: "s".into(), plan: "p".into(), loss: LossKind::Sustained, note: "n".into() },
            LossReport { scenario: "s".into(), plan: "p".into(), loss: LossKind::Burned, note: "n".into() },
            LossReport { scenario: "s".into(), plan: "p".into(), loss: LossKind::PricedOut, note: "n".into() },
            LossReport { scenario: "s".into(), plan: "p".into(), loss: LossKind::Sustained, note: "n".into() },
        ];
        assert_eq!(
            summarize(&reports),
            vec![
                (LossKind::Sustained, 2),
                (LossKind::Burned, 1),
                (LossKind::PricedOut, 1),
                (LossKind::UnderCollected, 1),
            ]
        );
    }

    #[test]
    fn summarize_empty_reports_all_zero() {
        assert_eq!(
            summarize(&[]),
            vec![
                (LossKind::Sustained, 0),
                (LossKind::Burned, 0),
                (LossKind::PricedOut, 0),
                (LossKind::UnderCollected, 0),
            ]
        );
    }

    #[test]
    fn worked_example_run_and_summary() {
        // Four plans designed to hit all four verdicts across the matrix.
        let plans = [
            plan("cautious", 1, 45, true, true),   // Sustained x4
            plan("burner", 1, 45, false, true),    // Burned under strong (x2)
            plan("pusher", 6, 45, true, true),     // PricedOut under high (x2)
            plan("thin", 1, 10, true, true),       // UnderCollected x4
        ];
        let reports = run_matrix(&plans).unwrap();
        assert_eq!(reports.len(), 16);
        assert_eq!(
            summarize(&reports),
            vec![
                (LossKind::Sustained, 8),
                (LossKind::Burned, 2),
                (LossKind::PricedOut, 2),
                (LossKind::UnderCollected, 4),
            ]
        );
        // Spot-check the burner in the weak-low cell it survives.
        let burner_weak_low = reports
            .iter()
            .find(|r| r.scenario == "weak-low" && r.plan == "burner")
            .unwrap();
        assert_eq!(burner_weak_low.loss, LossKind::Sustained);
        let burner_strong_high = reports
            .iter()
            .find(|r| r.scenario == "strong-high" && r.plan == "burner")
            .unwrap();
        assert_eq!(burner_strong_high.loss, LossKind::Burned);
    }

    #[test]
    fn determinism_repeated_runs() {
        let plans = [
            plan("a", 10, 30, true, true),
            plan("b", 11, 29, false, false),
        ];
        let first = run_matrix(&plans).unwrap();
        let second = run_matrix(&plans).unwrap();
        assert_eq!(first, second);
        let s = scenario("strong-high");
        assert_eq!(evaluate(&s, &plans[0]), evaluate(&s, &plans[0]));
        assert_eq!(summarize(&first), summarize(&second));
    }

    #[test]
    fn serde_roundtrips_and_shapes() {
        // Enum wire shapes: variant names as declared (no renames in §5).
        assert_eq!(serde_json::to_string(&DetectorCapability::Weak).unwrap(), "\"Weak\"");
        assert_eq!(serde_json::to_string(&EconomicPressure::High).unwrap(), "\"High\"");
        assert_eq!(serde_json::to_string(&LossKind::PricedOut).unwrap(), "\"PricedOut\"");
        assert_eq!(serde_json::to_string(&LossKind::UnderCollected).unwrap(), "\"UnderCollected\"");

        // Full matrix round-trips as an array.
        let matrix_json = serde_json::to_string(&standard_matrix()).unwrap();
        assert!(matrix_json.starts_with('['));
        let back: Vec<Scenario> = serde_json::from_str(&matrix_json).unwrap();
        assert_eq!(back, standard_matrix());

        // Plan round-trip (pacing included).
        let p = plan("round", 10, 29, true, false);
        let p_json = serde_json::to_string(&p).unwrap();
        let p_back: CollectionPlan = serde_json::from_str(&p_json).unwrap();
        assert_eq!(p_back, p);

        // Report round-trip + object shape.
        let r = evaluate(&scenario("weak-high"), &p);
        let r_json = serde_json::to_string(&r).unwrap();
        assert!(r_json.contains("\"scenario\""));
        assert!(r_json.contains("\"plan\""));
        assert!(r_json.contains("\"loss\""));
        assert!(r_json.contains("\"note\""));
        let r_back: LossReport = serde_json::from_str(&r_json).unwrap();
        assert_eq!(r_back, r);

        // Error round-trip from static input (wire form is {"BadInput":"…"}).
        // The payload is `&'static str`, so deserialization is only possible
        // from `'static` input — the wire form round-trips from literals.
        let e = MatrixError::BadInput("plans");
        let e_json = serde_json::to_string(&e).unwrap();
        assert_eq!(e_json, "{\"BadInput\":\"plans\"}");
        let e_static: MatrixError = serde_json::from_str(r#"{"BadInput":"plans"}"#).unwrap();
        assert_eq!(e_static, e);
    }

    #[test]
    fn display_and_error_impls() {
        let e = MatrixError::BadInput("plans");
        assert!(e.to_string().contains("plans"));
        let boxed: Box<dyn std::error::Error> = Box::new(e);
        assert!(!boxed.to_string().is_empty());
    }
}
