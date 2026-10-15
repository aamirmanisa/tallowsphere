//! Format-migration policy — monitoring, planning, and application.
//!
//! Frozen interface §6 (B6.2.1–B6.2.3). This module is the pure decision layer
//! for format drift across an artifact corpus: it compares each artifact's
//! current format against a chosen target, emits migration plans for the
//! records that have drifted, and models the application of a plan under one
//! hard policy invariant — **originals are always kept**.
//!
//! 1. **B6.2.1 — monitoring** ([`monitor`]): a [`FormatRecord`] plus a target
//!    [`FormatRef`] yields a [`Verdict`] — [`Verdict::Current`] when the record
//!    already sits at `format`/`version` equality, [`Verdict::Migrate`] (with
//!    the target attached) otherwise. Direction is irrelevant: a version bump
//!    and a version rollback both read `Migrate`. A [`FormatRef`] whose
//!    `format` name is empty is refused (`BadInput("format")`) on either side
//!    of the comparison — an unnamed format can never be a migration target.
//! 2. **B6.2.2 — planning** ([`plan`]): folds a record slice through
//!    [`monitor`] and returns one [`MigrationPlan`] per drifting record —
//!    already-current records are filtered out — sorted by `artifact` so the
//!    plan is reproducible. Refusal is **atomic**: a single invalid record
//!    refuses the whole request, no partial plan is returned. Ties (duplicate
//!    artifact names) keep input order (stable sort).
//! 3. **B6.2.3 — application** ([`apply`]): total function from a
//!    [`MigrationPlan`] to a [`MigrationResult`]. The migrated record's
//!    `current` becomes the plan target and its `migrated_from` is stamped
//!    with the plan source, so the record itself carries its provenance.
//!
//! # Originals-kept invariant (policy, pinned)
//!
//! [`apply`] **never** expresses destruction of the source artifact:
//! `MigrationResult::original_retained` is **always `true`** — a constant of
//! the policy, not an input-dependent flag. Migration produces a copy in the
//! target format; the original stays as the fixity/audit anchor. Do not add a
//! branch that can set it `false`; see `docs/ops/format_policy.md`.
//!
//! # Invariants
//!
//! - **Pure & deterministic**: functions of their arguments only — no clock,
//!   no randomness, no I/O, no globals. Same inputs ⇒ byte-identical outputs
//!   (pinned).
//! - **Wire names are verbatim variant names** (`"Current"`, `"Migrate"`,
//!   `"BadInput"`); the interface pins no renames here.
//! - **Scope**: pure in-memory policy. Not wired into `lib.rs` yet (the parent
//!   does that). No `crate::` dependencies beyond `serde`/`serde_json` (tests).

use serde::{Deserialize, Serialize};

/// A format name at a version — the unit format policy compares and migrates
/// between.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatRef {
    /// Format name, e.g. `"tallow-blob"`. Must be non-empty to be used as a
    /// comparison or migration target ([`monitor`] refuses otherwise).
    pub format: String,
    /// Format version. Monotonicity is *not* assumed: `monitor` reports drift
    /// in both directions.
    pub version: u32,
}

/// One artifact's format state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FormatRecord {
    /// Artifact identity (the thing the format applies to).
    pub artifact: String,
    /// The format the artifact is currently stored in.
    pub current: FormatRef,
    /// The format this artifact was migrated from, if it has been migrated
    /// before. Carried for provenance; it does **not** influence monitoring.
    pub migrated_from: Option<FormatRef>,
}

/// Result of monitoring one record against a target format.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Verdict {
    /// The record's current format already equals the target.
    Current,
    /// The record has drifted; it should be migrated to `target`.
    Migrate {
        /// The format to migrate to (a copy of the monitored target).
        target: FormatRef,
    },
}

/// Monitor one record against a target format (B6.2.1).
///
/// Pinned semantics:
/// - `rec.current.format` empty ⇒ `BadInput("format")` (checked first);
/// - `target.format` empty ⇒ `BadInput("format")`;
/// - `rec.current == target` (format **and** version equal) ⇒ [`Verdict::Current`];
/// - otherwise ⇒ [`Verdict::Migrate`] carrying a clone of `target` — a
///   version bump and a version rollback are treated identically.
///
/// `rec.migrated_from` is provenance only and never affects the verdict.
pub fn monitor(rec: &FormatRecord, target: &FormatRef) -> Result<Verdict, FormatError> {
    if rec.current.format.is_empty() {
        return Err(FormatError::BadInput("format"));
    }
    if target.format.is_empty() {
        return Err(FormatError::BadInput("format"));
    }
    if &rec.current == target {
        Ok(Verdict::Current)
    } else {
        Ok(Verdict::Migrate {
            target: target.clone(),
        })
    }
}

/// A single artifact's migration work item: take `artifact` from `from` to
/// `to`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationPlan {
    /// Artifact to migrate.
    pub artifact: String,
    /// The format it is migrating from (the record's `current` at plan time).
    pub from: FormatRef,
    /// The format it is migrating to (the monitored target).
    pub to: FormatRef,
}

/// Build the migration plan for a corpus (B6.2.2).
///
/// - Runs [`monitor`] on every record against `target`; only
///   [`Verdict::Migrate`] records become [`MigrationPlan`]s.
/// - Output is **sorted by `artifact`** (stable: duplicate artifact names keep
///   input order).
/// - Refusal is **atomic**: any record (or the target) with an empty `format`
///   refuses the whole request with `BadInput("format")` — no partial plan is
///   returned. An empty input slice yields an empty plan (provably nothing to
///   do).
pub fn plan(recs: &[FormatRecord], target: &FormatRef) -> Result<Vec<MigrationPlan>, FormatError> {
    // Validate the target up front — a plan request against an unnamed format
    // is refused regardless of corpus size (corpus-independent, fail-closed).
    if target.format.is_empty() {
        return Err(FormatError::BadInput("format"));
    }
    let mut plans = Vec::new();
    for rec in recs {
        match monitor(rec, target)? {
            Verdict::Current => {}
            Verdict::Migrate { target } => plans.push(MigrationPlan {
                artifact: rec.artifact.clone(),
                from: rec.current.clone(),
                to: target,
            }),
        }
    }
    plans.sort_by(|a, b| a.artifact.cmp(&b.artifact));
    Ok(plans)
}

/// Outcome of applying one [`MigrationPlan`] (B6.2.3).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationResult {
    /// The artifact that was migrated (copied into the target format).
    pub artifact: String,
    /// The artifact's record after migration: `current` = plan target,
    /// `migrated_from` = the plan source.
    pub migrated: FormatRecord,
    /// **Always `true`** — the originals-kept policy invariant. The source
    /// artifact is retained; migration produces a copy, never a replacement.
    pub original_retained: bool,
}

/// Apply a migration plan (B6.2.3).
///
/// Total and pure — there is no failure mode here: a [`MigrationPlan`] is the
/// validated output of [`plan`]. The returned record describes the **migrated
/// copy**: `current` = `plan.to`, `migrated_from` = `Some(plan.from)`, and the
/// artifact name is carried over unchanged.
///
/// The originals-kept invariant is expressed unconditionally:
/// `original_retained` is `true` for every plan, including degenerate ones
/// (`from == to`, or empty names — nothing here re-validates). Applying the
/// same plan twice yields equal results; the plan is not consumed or mutated.
pub fn apply(plan: &MigrationPlan) -> MigrationResult {
    MigrationResult {
        artifact: plan.artifact.clone(),
        migrated: FormatRecord {
            artifact: plan.artifact.clone(),
            current: plan.to.clone(),
            migrated_from: Some(plan.from.clone()),
        },
        original_retained: true,
    }
}

/// Errors from format-policy operations.
///
/// `Serialize` and `Deserialize` are both derived (recent house precedent,
/// `scenario_matrix`); because the payload is `&'static str`, deserialization
/// is only possible from `'static` input (string literals) — the wire form is
/// e.g. `{"BadInput":"format"}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FormatError {
    /// A required input was empty/invalid; payload is the field/reason name
    /// (`"format"` today).
    BadInput(&'static str),
}

impl std::fmt::Display for FormatError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FormatError::BadInput(field) => {
                write!(f, "invalid format-policy input: `{field}` must not be empty")
            }
        }
    }
}

impl std::error::Error for FormatError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn fref(format: &str, version: u32) -> FormatRef {
        FormatRef {
            format: format.to_string(),
            version,
        }
    }

    fn rec(artifact: &str, format: &str, version: u32) -> FormatRecord {
        FormatRecord {
            artifact: artifact.to_string(),
            current: fref(format, version),
            migrated_from: None,
        }
    }

    // ---------- B6.2.1 · monitor matrix ----------

    #[test]
    fn monitor_current_when_refs_equal() {
        // Exactly equal format + version ⇒ Current.
        let r = rec("a1", "tallow-blob", 3);
        assert_eq!(monitor(&r, &fref("tallow-blob", 3)), Ok(Verdict::Current));
        // Equality is decided on the full ref: version-only or format-only
        // differences are NOT equal (covered below).
    }

    #[test]
    fn monitor_migrates_on_version_change_both_directions() {
        // Up: 3 → 4.
        let r = rec("a1", "tallow-blob", 3);
        assert_eq!(
            monitor(&r, &fref("tallow-blob", 4)),
            Ok(Verdict::Migrate {
                target: fref("tallow-blob", 4)
            })
        );
        // Down: 4 → 3 is also drift — policy monitors, it does not judge
        // direction (the operator decides the target).
        let r = rec("a1", "tallow-blob", 4);
        assert_eq!(
            monitor(&r, &fref("tallow-blob", 3)),
            Ok(Verdict::Migrate {
                target: fref("tallow-blob", 3)
            })
        );
    }

    #[test]
    fn monitor_migrates_on_format_change() {
        let r = rec("a1", "tallow-blob", 2);
        assert_eq!(
            monitor(&r, &fref("tallow-arrow", 2)),
            Ok(Verdict::Migrate {
                target: fref("tallow-arrow", 2)
            })
        );
    }

    #[test]
    fn monitor_ignores_migrated_from_history() {
        // A record that was already migrated before still reads Current when
        // its current ref equals the target; the history field is provenance.
        let r = FormatRecord {
            artifact: "a1".to_string(),
            current: fref("tallow-blob", 3),
            migrated_from: Some(fref("tallow-blob", 2)),
        };
        assert_eq!(monitor(&r, &fref("tallow-blob", 3)), Ok(Verdict::Current));
    }

    #[test]
    fn monitor_refuses_empty_format_on_either_side() {
        let good = rec("a1", "tallow-blob", 1);
        // Empty current.format.
        let bad = rec("a1", "", 1);
        assert_eq!(monitor(&bad, &fref("tallow-blob", 1)), Err(FormatError::BadInput("format")));
        // Empty target.format.
        assert_eq!(monitor(&good, &fref("", 1)), Err(FormatError::BadInput("format")));
        // Both empty: still refused (emptiness beats equality).
        let both = rec("a1", "", 1);
        assert_eq!(monitor(&both, &fref("", 1)), Err(FormatError::BadInput("format")));
    }

    // ---------- B6.2.2 · plan filter + order ----------

    #[test]
    fn plan_filters_current_and_sorts_by_artifact() {
        // Input deliberately unsorted, mixed current/migrating, with one
        // multi-hop history record that must not affect the outcome.
        let mut zeta = rec("zeta", "tallow-blob", 1);
        zeta.migrated_from = Some(fref("tallow-blob", 0));
        let recs = vec![
            zeta,
            rec("alpha", "tallow-blob", 3), // already current w.r.t. target
            rec("mid", "tallow-blob", 1),
            rec("beta", "tallow-arrow", 2),
        ];
        let target = fref("tallow-blob", 3);
        let got = plan(&recs, &target).unwrap();
        assert_eq!(
            got,
            vec![
                MigrationPlan {
                    artifact: "beta".to_string(),
                    from: fref("tallow-arrow", 2),
                    to: target.clone(),
                },
                MigrationPlan {
                    artifact: "mid".to_string(),
                    from: fref("tallow-blob", 1),
                    to: target.clone(),
                },
                MigrationPlan {
                    artifact: "zeta".to_string(),
                    from: fref("tallow-blob", 1),
                    to: target.clone(),
                },
            ]
        );
    }

    #[test]
    fn plan_keeps_duplicate_artifacts_in_stable_input_order() {
        // Same artifact name twice (allowed here; artifact identity is policed
        // by the index modules) — stable sort keeps input order.
        let recs = vec![
            rec("dup", "tallow-blob", 2), // newer variant listed first
            rec("dup", "tallow-blob", 1),
        ];
        let target = fref("tallow-blob", 9);
        let got = plan(&recs, &target).unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].from.version, 2);
        assert_eq!(got[1].from.version, 1);
    }

    #[test]
    fn plan_empty_input_yields_empty_plan() {
        assert_eq!(plan(&[], &fref("tallow-blob", 1)), Ok(vec![]));
        // All-current input also yields an empty plan.
        let recs = vec![rec("a1", "tallow-blob", 1), rec("a2", "tallow-blob", 1)];
        assert_eq!(plan(&recs, &fref("tallow-blob", 1)), Ok(vec![]));
    }

    #[test]
    fn plan_refuses_any_invalid_record_atomically() {
        // One bad record anywhere refuses the whole request — even though the
        // earlier records were valid and would have produced plans.
        let recs = vec![
            rec("alpha", "tallow-blob", 1), // valid, drifts
            rec("beta", "", 1),             // invalid
            rec("gamma", "tallow-blob", 1), // valid, drifts
        ];
        assert_eq!(
            plan(&recs, &fref("tallow-blob", 3)),
            Err(FormatError::BadInput("format"))
        );
        // Empty target refuses even an empty record slice.
        assert_eq!(plan(&[], &fref("", 1)), Err(FormatError::BadInput("format")));
    }

    // ---------- B6.2.3 · apply semantics + retained invariant ----------

    #[test]
    fn apply_stamps_migrated_record() {
        let p = MigrationPlan {
            artifact: "alpha".to_string(),
            from: fref("tallow-blob", 1),
            to: fref("tallow-blob", 3),
        };
        let out = apply(&p);
        assert_eq!(out.artifact, "alpha");
        assert_eq!(out.migrated.artifact, "alpha");
        assert_eq!(out.migrated.current, fref("tallow-blob", 3));
        assert_eq!(out.migrated.migrated_from, Some(fref("tallow-blob", 1)));
    }

    #[test]
    fn apply_originals_kept_invariant_always_true() {
        // Policy: original_retained is true for EVERY plan shape, including
        // degenerate ones (from == to, empty names).
        let cases = [
            MigrationPlan {
                artifact: "a".to_string(),
                from: fref("tallow-blob", 1),
                to: fref("tallow-blob", 2),
            },
            MigrationPlan {
                artifact: "b".to_string(),
                from: fref("x", 9),
                to: fref("x", 9), // degenerate no-op
            },
            MigrationPlan {
                artifact: String::new(),
                from: fref("", 0),
                to: fref("", 0),
            },
        ];
        for p in &cases {
            assert!(apply(p).original_retained, "originals-kept invariant breached");
        }
        // Purity: plan untouched, repeat application identical.
        let p = &cases[0];
        let before = p.clone();
        assert_eq!(apply(p), apply(p));
        assert_eq!(*p, before);
    }

    #[test]
    fn apply_round_trips_through_plan() {
        // End-to-end: monitor → plan → apply produces a record whose current
        // ref equals the target and whose history names the source.
        let recs = vec![rec("alpha", "tallow-arrow", 2)];
        let target = fref("tallow-blob", 3);
        let plans = plan(&recs, &target).unwrap();
        assert_eq!(plans.len(), 1);
        let out = apply(&plans[0]);
        assert_eq!(out.migrated.current, target);
        assert_eq!(out.migrated.migrated_from, Some(fref("tallow-arrow", 2)));
        assert!(out.original_retained);
        // The migrated record monitors clean against the same target.
        assert_eq!(monitor(&out.migrated, &target), Ok(Verdict::Current));
    }

    // ---------- determinism ----------

    #[test]
    fn pipeline_is_deterministic_across_runs() {
        let recs = vec![
            rec("zeta", "tallow-blob", 1),
            rec("alpha", "tallow-arrow", 2),
            rec("mid", "tallow-blob", 3),
        ];
        let target = fref("tallow-blob", 3);
        let run = || {
            let plans = plan(&recs, &target).unwrap();
            let applied: Vec<MigrationResult> = plans.iter().map(apply).collect();
            serde_json::to_string(&applied).unwrap()
        };
        assert_eq!(run(), run());
        // And stable across differently-ordered input (sort by artifact).
        let shuffled = vec![recs[1].clone(), recs[2].clone(), recs[0].clone()];
        let a = plan(&recs, &target).unwrap();
        let b = plan(&shuffled, &target).unwrap();
        assert_eq!(a, b);
    }

    // ---------- serde ----------

    #[test]
    fn serde_wire_shapes_pinned() {
        assert_eq!(
            serde_json::to_string(&fref("tallow-blob", 3)).unwrap(),
            r#"{"format":"tallow-blob","version":3}"#
        );
        assert_eq!(
            serde_json::to_string(&Verdict::Current).unwrap(),
            r#""Current""#
        );
        assert_eq!(
            serde_json::to_string(&Verdict::Migrate {
                target: fref("tallow-blob", 4)
            })
            .unwrap(),
            r#"{"Migrate":{"target":{"format":"tallow-blob","version":4}}}"#
        );
        let r = rec("a1", "tallow-blob", 2);
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"artifact":"a1","current":{"format":"tallow-blob","version":2},"migrated_from":null}"#
        );
        let p = MigrationPlan {
            artifact: "a1".to_string(),
            from: fref("tallow-blob", 2),
            to: fref("tallow-blob", 3),
        };
        assert_eq!(
            serde_json::to_string(&p).unwrap(),
            r#"{"artifact":"a1","from":{"format":"tallow-blob","version":2},"to":{"format":"tallow-blob","version":3}}"#
        );
        assert_eq!(
            serde_json::to_string(&apply(&p)).unwrap(),
            r#"{"artifact":"a1","migrated":{"artifact":"a1","current":{"format":"tallow-blob","version":3},"migrated_from":{"format":"tallow-blob","version":2}},"original_retained":true}"#
        );
        assert_eq!(
            serde_json::to_string(&FormatError::BadInput("format")).unwrap(),
            r#"{"BadInput":"format"}"#
        );
    }

    #[test]
    fn serde_round_trips_data_types_and_error_literal() {
        let verdict = Verdict::Migrate {
            target: fref("tallow-blob", 7),
        };
        let json = serde_json::to_string(&verdict).unwrap();
        assert_eq!(serde_json::from_str::<Verdict>(&json).unwrap(), verdict);
        assert_eq!(
            serde_json::from_str::<Verdict>(r#""Current""#).unwrap(),
            Verdict::Current
        );

        let mut history = rec("a1", "tallow-blob", 3);
        history.migrated_from = Some(fref("tallow-arrow", 2));
        let json = serde_json::to_string(&history).unwrap();
        assert_eq!(
            serde_json::from_str::<FormatRecord>(&json).unwrap(),
            history.clone()
        );

        let plan = MigrationPlan {
            artifact: "a1".to_string(),
            from: fref("tallow-arrow", 2),
            to: fref("tallow-blob", 3),
        };
        let json = serde_json::to_string(&plan).unwrap();
        assert_eq!(serde_json::from_str::<MigrationPlan>(&json).unwrap(), plan);
        let out = apply(&MigrationPlan {
            artifact: "a1".to_string(),
            from: fref("tallow-arrow", 2),
            to: fref("tallow-blob", 3),
        });
        let json = serde_json::to_string(&out).unwrap();
        assert_eq!(serde_json::from_str::<MigrationResult>(&json).unwrap(), out);

        // `FormatError`'s payload is `&'static str`, so deserialization is
        // only possible from `'static` input (a literal here).
        assert_eq!(
            serde_json::from_str::<FormatError>(r#"{"BadInput":"format"}"#).unwrap(),
            FormatError::BadInput("format")
        );
    }

    #[test]
    fn display_message_is_stable() {
        assert_eq!(
            FormatError::BadInput("format").to_string(),
            "invalid format-policy input: `format` must not be empty"
        );
    }
}
