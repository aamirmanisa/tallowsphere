//! Export-gate matrix — A2.2.4. Full 4 (class) × 4 (audience) × 2 (embargo)
//! = 32-cell agreement matrix between the two committed policy surfaces:
//!
//! - [`tallow::access_class`] — the pure A2.2.1 policy core
//!   ([`check_export`] / [`may_export`], [`check_read`] / [`may_read`]);
//! - [`tallow::redaction::export_gate`] — the A2.2.2 release-pipeline view,
//!   a pass-through of `check_export` that maps `DenyReason` →
//!   `RedactError::Denied(code)` with the deny's stable machine code.
//!
//! Every cell is **pinned** in a table-driven assertion (expected decision
//! derived from the two modules' docs and the trust ordering of
//! [`Audience::trust_rank`]), and both APIs must agree cell-by-cell. This
//! test is read-only: neither module is edited by it.
//!
//! # Pinned rules (derivation)
//! From `access_class` module docs (the frozen A2.2.1 starter policy) and
//! `check_export`/`check_read` bodies:
//! - class tightness ascends `Open < Research < Restricted < Sealed`;
//!   audience trust ascends `Public < ThirdParty < Teammate < Operator`
//!   (= `trust_rank() 0..3`, the derived `Ord`).
//! - **Export, no embargo**: `Open` → everyone; `Research` → `Teammate`+ only
//!   (`required = Teammate`); `Restricted` → no export path at all
//!   (`deny.no-export-path`); `Sealed` → nobody (`deny.sealed`).
//! - **Export, embargo active**: EVERY cell denies with
//!   `deny.embargo-active`, including `Open`/`Public` — the class says how
//!   sensitive, the embargo says *when*; both must clear.
//! - **Read**: `Open` → everyone; `Research` → `Teammate`+;
//!   `Restricted` → `Operator` only; `Sealed` → nobody.
//! - **Relation (documented)**: export is never more permissive than read
//!   for the same `(class, audience)`; the only non-embargo cell where read
//!   passes and export refuses is `(Restricted, Operator)`
//!   (`Restricted` has read access for the operator but no export path
//!   pending A2.2.2/A2.2.3 release review) — pinned below.
//! - **Default-to-tightest**: `AccessClass::default()` = `Sealed`, so
//!   unclassified/unknown material denies every cell of both gates.

use tallow::access_class::{
    check_export, check_read, may_export, may_read, AccessClass, Audience, DenyReason, GateAction,
};
use tallow::redaction::{export_gate, RedactError};

// ── Expected-decision type + pinned tables ──────────────────────────────────

/// Pinned outcome of one gate cell: `Ok(())` = admitted, `Err(code)` =
/// refused with the deny's stable machine code (`DenyReason::code()`).
type Exp = Result<(), &'static str>;

/// Export with NO active embargo — rows in `AccessClass::ALL` order, columns
/// in `Audience::ALL` order (`Public, ThirdParty, Teammate, Operator`).
const EXPORT_NO_EMBARGO: [[Exp; 4]; 4] = [
    // Open — publishable; exports to everyone.
    [Ok(()), Ok(()), Ok(()), Ok(())],
    // Research — in-operation only; below Teammate refuses.
    [
        Err("deny.audience-not-admitted"),
        Err("deny.audience-not-admitted"),
        Ok(()),
        Ok(()),
    ],
    // Restricted — no export path exists (release review/downgrade required).
    [
        Err("deny.no-export-path"),
        Err("deny.no-export-path"),
        Err("deny.no-export-path"),
        Err("deny.no-export-path"),
    ],
    // Sealed — the ordinary gate admits no audience, period.
    [
        Err("deny.sealed"),
        Err("deny.sealed"),
        Err("deny.sealed"),
        Err("deny.sealed"),
    ],
];

/// Export WITH an active embargo — embargo vetoes every class × audience.
const EXPORT_EMBARGOED: [[Exp; 4]; 4] = [[Err("deny.embargo-active"); 4]; 4];

/// Read — rows in `AccessClass::ALL` order, columns in `Audience::ALL` order.
const READ_MATRIX: [[Exp; 4]; 4] = [
    // Open — everyone.
    [Ok(()), Ok(()), Ok(()), Ok(())],
    // Research — shareable inside the operation (Teammate+).
    [
        Err("deny.audience-not-admitted"),
        Err("deny.audience-not-admitted"),
        Ok(()),
        Ok(()),
    ],
    // Restricted — originator (Operator) only.
    [
        Err("deny.audience-not-admitted"),
        Err("deny.audience-not-admitted"),
        Err("deny.audience-not-admitted"),
        Ok(()),
    ],
    // Sealed — no read path through the ordinary gate.
    [
        Err("deny.sealed"),
        Err("deny.sealed"),
        Err("deny.sealed"),
        Err("deny.sealed"),
    ],
];

// ── Helpers: collapse a gate result to its pinned `Exp` form ────────────────

/// Row index of a class, by position in `AccessClass::ALL` (never assumes
/// discriminants).
fn class_idx(class: AccessClass) -> usize {
    AccessClass::ALL.iter().position(|c| *c == class).expect("class in ALL")
}

/// Column index of an audience, by position in `Audience::ALL`.
fn audience_idx(audience: Audience) -> usize {
    Audience::ALL.iter().position(|a| *a == audience).expect("audience in ALL")
}

fn export_exp(class: AccessClass, audience: Audience, embargo: bool) -> Exp {
    if embargo {
        EXPORT_EMBARGOED[class_idx(class)][audience_idx(audience)]
    } else {
        EXPORT_NO_EMBARGO[class_idx(class)][audience_idx(audience)]
    }
}

fn read_exp(class: AccessClass, audience: Audience) -> Exp {
    READ_MATRIX[class_idx(class)][audience_idx(audience)]
}

/// `check_export`/`check_read` result → `Exp` via the stable deny code.
fn as_exp(r: Result<(), DenyReason>) -> Exp {
    r.map_err(|reason| reason.code())
}

// ── Export matrix: 4 × 4 × 2 = 32 cells ─────────────────────────────────────

#[test]
fn export_matrix_all_32_cells_pinned_and_agreeing() {
    let mut checked = 0usize;
    let mut allowed = 0usize;
    for class in AccessClass::ALL {
        for audience in Audience::ALL {
            for embargo in [false, true] {
                let expected = export_exp(class, audience, embargo);
                let cell = format!("{class:?}/{audience:?}/embargo={embargo}");

                // Pin 1: check_export returns exactly the expected decision.
                assert_eq!(as_exp(check_export(class, audience, embargo)), expected, "check_export {cell}");

                // Pin 2: may_export agrees with check_export (bool view).
                assert_eq!(
                    may_export(class, audience, embargo),
                    expected.is_ok(),
                    "may_export {cell}"
                );

                // Pin 3: redaction::export_gate mirrors check_export exactly,
                // DenyReason → RedactError::Denied(code), Ok → Ok.
                let mapped = check_export(class, audience, embargo)
                    .map_err(|reason| RedactError::Denied(reason.code().to_string()));
                assert_eq!(export_gate(class, audience, embargo), mapped, "export_gate {cell}");

                // Pin 4: the two APIs agree on admission for every cell.
                assert_eq!(
                    export_gate(class, audience, embargo).is_ok(),
                    expected.is_ok(),
                    "agreement {cell}"
                );
                if let Err(expected_code) = expected {
                    match export_gate(class, audience, embargo) {
                        Err(RedactError::Denied(code)) => {
                            assert_eq!(code, expected_code, "redact code {cell}")
                        }
                        other => panic!("export_gate({cell}) = {other:?}, want Denied({expected_code})"),
                    }
                }

                checked += 1;
                if expected.is_ok() {
                    allowed += 1;
                }
            }
        }
    }
    // Aggregate pins: all 32 cells exercised; exactly 6 admitted without
    // embargo (Open×4 + Research×2), zero with embargo active.
    assert_eq!(checked, 32, "matrix must cover the full 4×4×2");
    assert_eq!(allowed, 6, "admitted export cells (no-embargo) changed");
}

#[test]
fn export_denial_variants_are_cell_specific() {
    // Pin the DenyReason *variant* (not just the code) per cell class, so a
    // future rule change that keeps the code but changes the shape is caught.
    for class in AccessClass::ALL {
        for audience in Audience::ALL {
            // Embargo beats every class/audience combination.
            assert_eq!(
                check_export(class, audience, true),
                Err(DenyReason::EmbargoActive { audience }),
                "embargo {class:?}/{audience:?}"
            );

            let expected = match class {
                AccessClass::Open => Ok(()),
                AccessClass::Research if audience >= Audience::Teammate => Ok(()),
                AccessClass::Research => Err(DenyReason::AudienceNotAdmitted {
                    action: GateAction::Export,
                    class,
                    audience,
                    required: Audience::Teammate,
                }),
                AccessClass::Restricted => Err(DenyReason::NoExportPath { class }),
                AccessClass::Sealed => Err(DenyReason::SealedMaterial {
                    action: GateAction::Export,
                }),
            };
            assert_eq!(check_export(class, audience, false), expected, "no-embargo {class:?}/{audience:?}");
        }
    }
}

// ── Read matrix: 4 × 4 = 16 cells ───────────────────────────────────────────

#[test]
fn read_matrix_all_16_cells_pinned_with_variants() {
    let mut checked = 0usize;
    let mut allowed = 0usize;
    for class in AccessClass::ALL {
        for audience in Audience::ALL {
            let expected = read_exp(class, audience);
            let cell = format!("{class:?}/{audience:?}");

            assert_eq!(as_exp(check_read(class, audience)), expected, "check_read {cell}");
            assert_eq!(may_read(class, audience), expected.is_ok(), "may_read {cell}");

            // Variant-level pin: required-audience fields are load-bearing
            // for audit aggregation, so check them explicitly.
            let expected_reason = match class {
                AccessClass::Open => Ok(()),
                AccessClass::Research if audience >= Audience::Teammate => Ok(()),
                AccessClass::Research => Err(DenyReason::AudienceNotAdmitted {
                    action: GateAction::Read,
                    class,
                    audience,
                    required: Audience::Teammate,
                }),
                AccessClass::Restricted if audience >= Audience::Operator => Ok(()),
                AccessClass::Restricted => Err(DenyReason::AudienceNotAdmitted {
                    action: GateAction::Read,
                    class,
                    audience,
                    required: Audience::Operator,
                }),
                AccessClass::Sealed => Err(DenyReason::SealedMaterial {
                    action: GateAction::Read,
                }),
            };
            assert_eq!(check_read(class, audience), expected_reason, "variant {cell}");

            checked += 1;
            if expected.is_ok() {
                allowed += 1;
            }
        }
    }
    // Aggregate pins: 16 read cells; exactly 7 admitted
    // (Open×4 + Research×2 + Restricted×1).
    assert_eq!(checked, 16, "read matrix must cover 4×4");
    assert_eq!(allowed, 7, "admitted read cells changed");
}

#[test]
fn read_superset_relation_with_non_embargo_export() {
    // Documented invariant: export is never more permissive than read
    // (`export_never_exceeds_read_admission` in access_class), and with no
    // embargo the ONLY read-ok / export-denied cell is (Restricted, Operator)
    // — restricted material is readable by the originator but has no export
    // path until a release review/downgrade (A2.2.2/A2.2.3).
    let mut read_ok_export_denied: Vec<(AccessClass, Audience)> = Vec::new();
    for class in AccessClass::ALL {
        for audience in Audience::ALL {
            if may_export(class, audience, false) {
                assert!(
                    may_read(class, audience),
                    "export admitted but read denied for {class:?}/{audience:?}"
                );
            }
            if may_read(class, audience) && !may_export(class, audience, false) {
                read_ok_export_denied.push((class, audience));
            }
        }
    }
    assert_eq!(
        read_ok_export_denied,
        vec![(AccessClass::Restricted, Audience::Operator)],
        "the read↔export difference set changed"
    );

    // Row-level equality for the classes where the gates coincide:
    // Open, Research, and Sealed admit the same audiences on read and on
    // (non-embargo) export; Restricted is the sole divergence (its export
    // denial is `deny.no-export-path` for every audience).
    for class in [AccessClass::Open, AccessClass::Research, AccessClass::Sealed] {
        for audience in Audience::ALL {
            assert_eq!(
                may_read(class, audience),
                may_export(class, audience, false),
                "row mismatch {class:?}/{audience:?}"
            );
        }
    }
    for audience in Audience::ALL {
        assert_eq!(
            as_exp(check_export(AccessClass::Restricted, audience, false)),
            Err("deny.no-export-path"),
            "Restricted must have no export path"
        );
    }
}

// ── Default-to-tightest: the deny-by-default anchor row ─────────────────────

#[test]
fn default_to_tightest_denies_every_cell_of_both_gates() {
    assert_eq!(AccessClass::default_to_tightest(), AccessClass::Sealed);
    assert_eq!(AccessClass::default(), AccessClass::Sealed);
    let default_class = AccessClass::default();
    for audience in Audience::ALL {
        // Read: nobody.
        assert_eq!(
            as_exp(check_read(default_class, audience)),
            Err("deny.sealed"),
            "default read {audience:?}"
        );
        // Export: nobody, embargo or not. Pinned precedence (check_export
        // checks the embargo FIRST, before the class rules): an active
        // embargo reports `deny.embargo-active`, otherwise the sealed class
        // reports `deny.sealed`. Either way the cell denies.
        for embargo in [false, true] {
            let expected = if embargo { "deny.embargo-active" } else { "deny.sealed" };
            assert_eq!(
                as_exp(check_export(default_class, audience, embargo)),
                Err(expected),
                "default export {audience:?}/embargo={embargo}"
            );
            assert_eq!(
                redact_gate_is_denied(default_class, audience, embargo),
                expected,
                "default redact gate {audience:?}/embargo={embargo}"
            );
        }
    }
}

/// Code carried by `redaction::export_gate` when it refuses; panics if the
/// gate unexpectedly admits (used only on pinned-deny cells).
fn redact_gate_is_denied(class: AccessClass, audience: Audience, embargo: bool) -> String {
    match export_gate(class, audience, embargo) {
        Err(RedactError::Denied(code)) => code,
        other => panic!("expected Denied, got {other:?} for {class:?}/{audience:?}/embargo={embargo}"),
    }
}

// ── Cross-surface sanity: the same code vocabulary everywhere ───────────────

#[test]
fn deny_code_vocabulary_is_stable_across_all_32_cells() {
    // Every refusal the gate can produce in the full matrix uses one of the
    // four stable `deny.*` codes; nothing else may leak through either API.
    const VOCAB: [&str; 4] = [
        "deny.sealed",
        "deny.audience-not-admitted",
        "deny.no-export-path",
        "deny.embargo-active",
    ];
    for class in AccessClass::ALL {
        for audience in Audience::ALL {
            for embargo in [false, true] {
                if let Err(code) = as_exp(check_export(class, audience, embargo)) {
                    assert!(VOCAB.contains(&code), "unexpected check_export code {code}");
                }
                if let Err(RedactError::Denied(code)) = export_gate(class, audience, embargo) {
                    assert!(VOCAB.contains(&code.as_str()), "unexpected redact code {code}");
                }
            }
        }
    }
    // Human audit lines surface the refusal verb (used by ledger records).
    let sample = check_export(AccessClass::Restricted, Audience::Public, false).unwrap_err();
    assert!(sample.to_string().contains("denied"), "display: {sample}");
    assert_eq!(sample.code(), "deny.no-export-path");
    assert_eq!(
        sample.to_string(),
        "export denied: restricted material has no export path (release review/downgrade required)"
    );
}
