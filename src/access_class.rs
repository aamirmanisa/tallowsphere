//! Release-governance access classes + deny-by-default read/export gates.
//!
//! Task A2.2.1 (dossier E3 — release governance). This module is the *pure
//! policy core*: it classifies collected material into four access classes,
//! models whom a read or an export is being performed *for* (the audience),
//! and answers exactly two questions:
//!
//! - may this audience **read** material of this class? [`may_read`] /
//!   [`check_read`]
//! - may this audience take material of this class **out of the vault** (a
//!   release/export), at this moment? [`may_export`] / [`check_export`]
//!
//! # Deny-by-default
//! Every gate is a policy *allowlist*: an audience is admitted only where a
//! rule below explicitly admits it; anything not explicitly allowed is
//! denied. The default classification is the tightest class
//! ([`AccessClass::default_to_tightest`] → `Sealed`), which admits nobody
//! through either gate — so unclassified, legacy, or unknown artifacts are
//! never readable or exportable by accident. Denials return a [`DenyReason`]
//! (not a bare `false`) so every refusal can be written to the audit ledger
//! with *why* it happened.
//!
//! # The matrix (frozen starter policy — A2.2.1)
//! Class tightness ascends `Open < Research < Restricted < Sealed`; audience
//! trust ascends `Public < ThirdParty < Teammate < Operator`. The derived
//! `Ord` of both enums encodes exactly those orders (declaration order).
//!
//! | class      | `may_read`          | `may_export` (no embargo) |
//! |------------|---------------------|---------------------------|
//! | Open       | everyone            | everyone                  |
//! | Research   | Operator, Teammate  | Operator, Teammate        |
//! | Restricted | Operator            | nobody — no export path   |
//! | Sealed     | nobody              | nobody                    |
//!
//! Rationale for the rows that could go either way:
//!
//! - **`Sealed` admits nobody through the ordinary gate** — reading sealed
//!   material requires an explicit unsealing ceremony (a separate, logged
//!   flow; A2.2.2 territory), which is deliberately not expressible here.
//!   Deny-by-default means the gate itself can never be the unsealing path.
//! - **`Restricted` has no export path** — releasing restricted material
//!   requires redaction-at-export / downgrade review (A2.2.2) or an explicit
//!   originator/role release caveat (A2.2.3). Those flows re-enter the gate
//!   with the class that *results* from the release decision; the gate itself
//!   never quietly allows a restricted export.
//! - **An active embargo vetoes every export**, even `Open` — the class says
//!   how sensitive the material is, the embargo says *when* it may leave;
//!   both must clear. Embargo never affects reads.
//! - **`Research` and `Restricted` are distinguished on read**: research-tier
//!   material is shareable with the operation's own members; restricted
//!   material stays with the originator (the operator) until a caveat grants
//!   a wider role (A2.2.3).
//! - Export is never more permissive than read for the same `(class,
//!   audience)` — enforced by the `export_never_exceeds_read_admission` test.
//!
//! # Scope / integration
//! Pure functions only: no I/O, no global state, no clock. Declared in
//! `lib.rs`; consumed through [`crate::enforcement`] and
//! [`crate::vault::access`] (read paths wired 2026-09-28). Downstream
//! consumers: the export/release pipeline and audit logging (`DenyReason` is
//! serde-round-trippable for ledger records). A2.2.2/A2.2.3/A2.2.4 build on
//! this file; nothing here should need to change for them.

use std::fmt;

use serde::{Deserialize, Serialize};

// ── Access classes ───────────────────────────────────────────────────────────

/// How tightly held a piece of collected material is.
///
/// Ordering (`Ord`) is **tightness ascending**: `Open < Research <
/// Restricted < Sealed`. Merge two classifications with [`AccessClass::tightest_of`]
/// (a bundle is as tight as its tightest member).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AccessClass {
    /// Publishable: collected from open/public sources with no third-party
    /// exposure issue; release is unencumbered (subject to embargo timing).
    Open,
    /// Working research material: shareable inside the operation
    /// (operator + teammates), not with external parties or the public.
    Research,
    /// Need-to-know material: the originator (operator) only, pending an
    /// explicit release review/caveat.
    Restricted,
    /// Closed/dark-archive material: no read or export path through the
    /// ordinary gate. Unsealing is a separate, logged ceremony.
    Sealed,
}

impl AccessClass {
    /// Every class, tightest last (tightness-ascending order).
    pub const ALL: [AccessClass; 4] = [
        AccessClass::Open,
        AccessClass::Research,
        AccessClass::Restricted,
        AccessClass::Sealed,
    ];

    /// The tightest class — the classification to fall back to whenever
    /// material is unclassified, upgraded from an unknown value, or in doubt.
    /// Deny-by-default depends on this: `Sealed` admits nobody through either
    /// gate.
    pub fn default_to_tightest() -> Self {
        AccessClass::Sealed
    }

    /// The tighter (more restrictive) of two classifications. Use when
    /// merging metadata so a container is never classified looser than its
    /// tightest member.
    pub fn tightest_of(a: AccessClass, b: AccessClass) -> Self {
        a.max(b)
    }

    /// Stable lowercase token for audit lines and markings; serde uses the
    /// variant name (`"Open"`, `"Research"`, …).
    pub fn as_str(&self) -> &'static str {
        match self {
            AccessClass::Open => "open",
            AccessClass::Research => "research",
            AccessClass::Restricted => "restricted",
            AccessClass::Sealed => "sealed",
        }
    }
}

/// Default = tightest. `AccessClass::default()` is `Sealed`, never `Open`.
impl Default for AccessClass {
    fn default() -> Self {
        AccessClass::default_to_tightest()
    }
}

impl fmt::Display for AccessClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Audience model ───────────────────────────────────────────────────────────

/// Whom a read/export is being performed *for*.
///
/// Ordering (`Ord`) is **trust ascending**: `Public < ThirdParty < Teammate <
/// Operator`. Trust is about the relationship to the originator's operation,
/// not clearance paperwork: `Teammate` is inside the operation's trust
/// boundary, `ThirdParty` is outside it, `Public` is unrestricted release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Audience {
    /// Unrestricted release: anyone.
    Public,
    /// A recipient outside the operation's trust boundary (client, external
    /// partner, counterparty).
    ThirdParty,
    /// A member of the same operation/compartment as the originator.
    Teammate,
    /// The originator itself (the operator's own workspace/console).
    Operator,
}

impl Audience {
    /// Every audience, lowest trust first.
    pub const ALL: [Audience; 4] = [
        Audience::Public,
        Audience::ThirdParty,
        Audience::Teammate,
        Audience::Operator,
    ];

    /// Trust rank, `0` (Public) … `3` (Operator). Equal to the derived `Ord`.
    pub fn trust_rank(&self) -> u8 {
        match self {
            Audience::Public => 0,
            Audience::ThirdParty => 1,
            Audience::Teammate => 2,
            Audience::Operator => 3,
        }
    }

    /// Stable lowercase token for audit lines; serde uses the variant name.
    pub fn as_str(&self) -> &'static str {
        match self {
            Audience::Public => "public",
            Audience::ThirdParty => "third-party",
            Audience::Teammate => "teammate",
            Audience::Operator => "operator",
        }
    }
}

impl fmt::Display for Audience {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

// ── Denial reasons (audit) ───────────────────────────────────────────────────

/// Which gate produced a denial — lets audit tooling distinguish read
/// refusals from export refusals without parsing message text.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum GateAction {
    /// A vault/read-path access.
    Read,
    /// A release/export out of the vault.
    Export,
}

impl GateAction {
    /// Stable lowercase token for audit lines.
    pub fn as_str(&self) -> &'static str {
        match self {
            GateAction::Read => "read",
            GateAction::Export => "export",
        }
    }
}

impl fmt::Display for GateAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a gate refused an operation. One variant per policy rule so audit
/// records can aggregate refusals by cause; serde-round-trippable for ledger
/// payloads. `Display` renders a human audit line.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DenyReason {
    /// Sealed material: the ordinary gate admits no audience for this action.
    SealedMaterial {
        /// Gate that refused.
        action: GateAction,
    },
    /// The audience's trust rank is below the minimum this class requires
    /// for this action.
    AudienceNotAdmitted {
        /// Gate that refused.
        action: GateAction,
        /// Class of the material.
        class: AccessClass,
        /// Audience that was refused.
        audience: Audience,
        /// Lowest audience that would have been admitted.
        required: Audience,
    },
    /// No export path exists for this class; release requires review or an
    /// explicit downgrade (redaction-at-export / caveats — A2.2.2/A2.2.3).
    NoExportPath {
        /// Class of the material.
        class: AccessClass,
    },
    /// An embargo window is active; no export may leave until it clears.
    EmbargoActive {
        /// Audience the export was attempted for.
        audience: Audience,
    },
}

impl DenyReason {
    /// Stable machine code for audit aggregation (never localized).
    pub fn code(&self) -> &'static str {
        match self {
            DenyReason::SealedMaterial { .. } => "deny.sealed",
            DenyReason::AudienceNotAdmitted { .. } => "deny.audience-not-admitted",
            DenyReason::NoExportPath { .. } => "deny.no-export-path",
            DenyReason::EmbargoActive { .. } => "deny.embargo-active",
        }
    }
}

impl fmt::Display for DenyReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DenyReason::SealedMaterial { action } => write!(
                f,
                "{action} denied: sealed material never passes the ordinary gate"
            ),
            DenyReason::AudienceNotAdmitted {
                action,
                class,
                audience,
                required,
            } => write!(
                f,
                "{action} denied: audience '{audience}' is not admitted to {class} material (requires '{required}' or above)"
            ),
            DenyReason::NoExportPath { class } => write!(
                f,
                "export denied: {class} material has no export path (release review/downgrade required)"
            ),
            DenyReason::EmbargoActive { audience } => write!(
                f,
                "export denied: embargo active for audience '{audience}'"
            ),
        }
    }
}

// ── Gates (pure, deny-by-default) ────────────────────────────────────────────

/// Lowest audience admitted to *read* `class`; `None` = no audience passes.
fn read_min(class: AccessClass) -> Option<Audience> {
    match class {
        AccessClass::Open => Some(Audience::Public),
        AccessClass::Research => Some(Audience::Teammate),
        AccessClass::Restricted => Some(Audience::Operator),
        AccessClass::Sealed => None,
    }
}

/// May `audience` read material of `class`? Deny-by-default: only the
/// explicit admittances in [`read_min`] pass, everything else refuses.
pub fn may_read(class: AccessClass, audience: Audience) -> bool {
    check_read(class, audience).is_ok()
}

/// [`may_read`] with the reason: `Ok(())` = admissible, `Err(reason)` = a
/// [`DenyReason`] suitable for the audit record.
pub fn check_read(class: AccessClass, audience: Audience) -> Result<(), DenyReason> {
    match read_min(class) {
        Some(required) if audience >= required => Ok(()),
        Some(required) => Err(DenyReason::AudienceNotAdmitted {
            action: GateAction::Read,
            class,
            audience,
            required,
        }),
        None => Err(DenyReason::SealedMaterial {
            action: GateAction::Read,
        }),
    }
}

/// May `audience` export/release material of `class` while `embargo_active`?
///
/// Deny-by-default, and export is never more permissive than read:
/// - an active embargo refuses every export, including `Open`;
/// - `Open` exports to everyone;
/// - `Research` exports inside the operation only (`Teammate`+);
/// - `Restricted` and `Sealed` have no export path at all.
pub fn may_export(class: AccessClass, audience: Audience, embargo_active: bool) -> bool {
    check_export(class, audience, embargo_active).is_ok()
}

/// [`may_export`] with the reason: `Ok(())` = release may proceed,
/// `Err(reason)` = a [`DenyReason`] suitable for the audit record.
pub fn check_export(
    class: AccessClass,
    audience: Audience,
    embargo_active: bool,
) -> Result<(), DenyReason> {
    if embargo_active {
        return Err(DenyReason::EmbargoActive { audience });
    }
    match class {
        AccessClass::Open => Ok(()),
        AccessClass::Research => {
            if audience >= Audience::Teammate {
                Ok(())
            } else {
                Err(DenyReason::AudienceNotAdmitted {
                    action: GateAction::Export,
                    class,
                    audience,
                    required: Audience::Teammate,
                })
            }
        }
        AccessClass::Restricted => Err(DenyReason::NoExportPath { class }),
        AccessClass::Sealed => Err(DenyReason::SealedMaterial {
            action: GateAction::Export,
        }),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const CLASSES: [AccessClass; 4] = AccessClass::ALL;
    const AUDIENCES: [Audience; 4] = Audience::ALL;

    #[test]
    fn access_class_ordering_is_tightness_ascending() {
        assert!(AccessClass::Open < AccessClass::Research);
        assert!(AccessClass::Research < AccessClass::Restricted);
        assert!(AccessClass::Restricted < AccessClass::Sealed);
        let mut shuffled = vec![
            AccessClass::Sealed,
            AccessClass::Open,
            AccessClass::Restricted,
            AccessClass::Research,
        ];
        shuffled.sort();
        assert_eq!(shuffled, CLASSES.to_vec());
        assert_eq!(CLASSES.to_vec().into_iter().max(), Some(AccessClass::Sealed));
        assert_eq!(CLASSES.to_vec().into_iter().min(), Some(AccessClass::Open));
    }

    #[test]
    fn audience_ordering_is_trust_ascending() {
        assert!(Audience::Public < Audience::ThirdParty);
        assert!(Audience::ThirdParty < Audience::Teammate);
        assert!(Audience::Teammate < Audience::Operator);
        let mut shuffled = vec![
            Audience::Teammate,
            Audience::Public,
            Audience::Operator,
            Audience::ThirdParty,
        ];
        shuffled.sort();
        assert_eq!(shuffled, AUDIENCES.to_vec());
        for (rank, a) in AUDIENCES.iter().enumerate() {
            assert_eq!(a.trust_rank(), rank as u8, "rank mismatch for {a}");
            assert_eq!(a.as_str(), format!("{a}"));
        }
    }

    #[test]
    fn default_to_tightest_is_sealed_and_is_deny_all() {
        assert_eq!(AccessClass::default_to_tightest(), AccessClass::Sealed);
        assert_eq!(AccessClass::default(), AccessClass::Sealed);
        // Deny-by-default behavior: the default class admits nobody.
        let default_class = AccessClass::default();
        for audience in AUDIENCES {
            assert!(!may_read(default_class, audience), "{audience} read {default_class}");
            assert!(!may_export(default_class, audience, false), "{audience} exported {default_class}");
            assert!(!may_export(default_class, audience, true));
        }
    }

    #[test]
    fn tightest_of_takes_the_tighter_class() {
        assert_eq!(
            AccessClass::tightest_of(AccessClass::Open, AccessClass::Restricted),
            AccessClass::Restricted
        );
        assert_eq!(
            AccessClass::tightest_of(AccessClass::Sealed, AccessClass::Open),
            AccessClass::Sealed
        );
        assert_eq!(
            AccessClass::tightest_of(AccessClass::Research, AccessClass::Research),
            AccessClass::Research
        );
        for a in CLASSES {
            for b in CLASSES {
                let joined = AccessClass::tightest_of(a, b);
                assert_eq!(joined, a.max(b), "join({a},{b})");
                assert_eq!(joined, AccessClass::tightest_of(b, a), "commutative");
                assert!(joined >= a && joined >= b, "join never loosens");
            }
        }
    }

    #[test]
    fn read_matrix_rows() {
        use AccessClass::*;
        use Audience::*;
        let table: [(AccessClass, &[Audience]); 4] = [
            (Open, &[Public, ThirdParty, Teammate, Operator]),
            (Research, &[Teammate, Operator]),
            (Restricted, &[Operator]),
            (Sealed, &[]),
        ];
        for (class, allowed) in table {
            for audience in AUDIENCES {
                let expected = allowed.contains(&audience);
                assert_eq!(
                    may_read(class, audience),
                    expected,
                    "may_read({class}, {audience}) should be {expected}"
                );
                assert_eq!(check_read(class, audience).is_ok(), expected);
            }
        }
    }

    #[test]
    fn export_matrix_rows_without_embargo() {
        use AccessClass::*;
        use Audience::*;
        let table: [(AccessClass, &[Audience]); 4] = [
            (Open, &[Public, ThirdParty, Teammate, Operator]),
            (Research, &[Teammate, Operator]),
            (Restricted, &[]),
            (Sealed, &[]),
        ];
        for (class, allowed) in table {
            for audience in AUDIENCES {
                let expected = allowed.contains(&audience);
                assert_eq!(
                    may_export(class, audience, false),
                    expected,
                    "may_export({class}, {audience}, no embargo) should be {expected}"
                );
            }
        }
    }

    #[test]
    fn embargo_vetoes_every_export_even_open() {
        for class in CLASSES {
            for audience in AUDIENCES {
                assert!(
                    !may_export(class, audience, true),
                    "embargoed export of {class} to {audience} was allowed"
                );
                assert_eq!(
                    check_export(class, audience, true),
                    Err(DenyReason::EmbargoActive { audience })
                );
            }
        }
    }

    #[test]
    fn export_never_exceeds_read_admission() {
        for class in CLASSES {
            for audience in AUDIENCES {
                for embargo in [false, true] {
                    if may_export(class, audience, embargo) {
                        assert!(
                            may_read(class, audience),
                            "export of {class} to {audience} allowed but read denied"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn denial_reasons_are_specific_and_auditable() {
        use AccessClass::*;
        use Audience::*;
        // Representative deny rows, one per reason variant.
        assert_eq!(
            check_read(Sealed, Operator),
            Err(DenyReason::SealedMaterial {
                action: GateAction::Read
            })
        );
        assert_eq!(
            check_read(Research, Public),
            Err(DenyReason::AudienceNotAdmitted {
                action: GateAction::Read,
                class: Research,
                audience: Public,
                required: Teammate,
            })
        );
        assert_eq!(
            check_read(Restricted, Teammate),
            Err(DenyReason::AudienceNotAdmitted {
                action: GateAction::Read,
                class: Restricted,
                audience: Teammate,
                required: Operator,
            })
        );
        assert_eq!(
            check_export(Restricted, Operator, false),
            Err(DenyReason::NoExportPath { class: Restricted })
        );
        assert_eq!(
            check_export(Sealed, Operator, false),
            Err(DenyReason::SealedMaterial {
                action: GateAction::Export
            })
        );
        assert_eq!(
            check_export(Open, Operator, true),
            Err(DenyReason::EmbargoActive { audience: Operator })
        );
        // Representative allow rows return Ok, not just a truthy bool.
        assert_eq!(check_read(Restricted, Operator), Ok(()));
        assert_eq!(check_read(Open, Public), Ok(()));
        assert_eq!(check_export(Open, Public, false), Ok(()));
        assert_eq!(check_export(Research, Teammate, false), Ok(()));
        // Audit surfacing: stable code + human line.
        for reason in [
            DenyReason::SealedMaterial {
                action: GateAction::Read,
            },
            DenyReason::AudienceNotAdmitted {
                action: GateAction::Export,
                class: Research,
                audience: Public,
                required: Teammate,
            },
            DenyReason::NoExportPath { class: Restricted },
            DenyReason::EmbargoActive { audience: Operator },
        ] {
            assert!(reason.code().starts_with("deny."), "code: {}", reason.code());
            let line = reason.to_string();
            assert!(!line.is_empty() && line.contains("denied"), "display: {line}");
        }
    }

    #[test]
    fn bool_helpers_agree_with_check_helpers() {
        for class in CLASSES {
            for audience in AUDIENCES {
                assert_eq!(may_read(class, audience), check_read(class, audience).is_ok());
                for embargo in [false, true] {
                    assert_eq!(
                        may_export(class, audience, embargo),
                        check_export(class, audience, embargo).is_ok()
                    );
                }
            }
        }
    }

    #[test]
    fn serde_round_trip_access_class() {
        for class in CLASSES {
            let json = serde_json::to_string(&class).unwrap();
            let back: AccessClass = serde_json::from_str(&json).unwrap();
            assert_eq!(back, class);
        }
        // Wire form is the variant name (stable for audit records).
        assert_eq!(serde_json::to_string(&AccessClass::Sealed).unwrap(), "\"Sealed\"");
        let all_json = serde_json::to_string(&CLASSES).unwrap();
        let back: [AccessClass; 4] = serde_json::from_str(&all_json).unwrap();
        assert_eq!(back, CLASSES);
    }

    #[test]
    fn serde_round_trip_audience_and_deny_reason() {
        use AccessClass::*;
        use Audience::*;
        for audience in AUDIENCES {
            let json = serde_json::to_string(&audience).unwrap();
            let back: Audience = serde_json::from_str(&json).unwrap();
            assert_eq!(back, audience);
        }
        assert_eq!(
            serde_json::to_string(&Audience::ThirdParty).unwrap(),
            "\"ThirdParty\""
        );
        let reasons = [
            DenyReason::SealedMaterial {
                action: GateAction::Read,
            },
            DenyReason::AudienceNotAdmitted {
                action: GateAction::Export,
                class: Research,
                audience: Public,
                required: Teammate,
            },
            DenyReason::NoExportPath {
                class: Restricted,
            },
            DenyReason::EmbargoActive {
                audience: Operator,
            },
        ];
        for reason in reasons {
            let json = serde_json::to_string(&reason).unwrap();
            let back: DenyReason = serde_json::from_str(&json).unwrap();
            assert_eq!(back, reason);
        }
        // An audit record for one refusal, end to end.
        let denial = check_export(AccessClass::Restricted, Audience::ThirdParty, false).unwrap_err();
        let record = serde_json::json!({
            "event": "export_denied",
            "class": AccessClass::Restricted,
            "audience": Audience::ThirdParty,
            "reason_code": denial.code(),
            "reason": denial.to_string(),
        });
        assert_eq!(record["reason_code"], "deny.no-export-path");
        assert_eq!(record["class"], "Restricted");
    }
}
