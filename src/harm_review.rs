//! Harm-review gate for collection plans — pre-collection checklist
//! (A7.2.1), proportionality note (A7.2.2), and the combined gate (A7.2.3).
//!
//! Collection that touches third parties or their infrastructure only
//! proceeds when one explicit artifact — a harm review — clears two bars:
//!
//! 1. **Checklist** ([`HarmChecklist`], A7.2.1): four booleans that must each
//!    be affirmatively true (minimal footprint, third-party non-harm,
//!    robots/ToS posture, redaction at rest) plus a non-empty legal basis.
//!    A missing boolean is never defaulted; the error names the exact item
//!    so the fix is mechanical.
//! 2. **Proportionality note** ([`HarmNote`], A7.2.2): who could be affected
//!    and why the collection is proportionate, both non-empty. The note is
//!    the human half of the review; the checklist is the mechanical half.
//!
//! [`gate`] requires **both** artifacts for a collection plan (A7.2.3):
//! absence of either is treated as `Unchecked` ([`HarmError`] mapping is
//! documented on each function) — an absent artifact cannot silently read
//! as a passing one.
//!
//! [`attach_note`] embeds a note under `"harm_note"` in a manifest JSON
//! object so the review travels with the plan (round-trip tested).
//!
//! Everything here is pure: no I/O, no clock — `created_ms` is supplied by
//! the caller so tests and replays are deterministic.
//!
//! Policy rationale lives in `impl/HARM_POLICY.md` (proportionality,
//! third-party non-harm, robots-ToS posture, redaction-at-rest defaults,
//! audit sampling). Not wired into `lib.rs` yet (the parent does that).

use std::fmt;

use serde::{Deserialize, Serialize};

// ── Checklist (A7.2.1) ──────────────────────────────────────────────────────

/// Pre-collection harm checklist. Every boolean must be affirmatively `true`
/// — there is no `Default` impl on purpose: a checklist that was never
/// filled in must not look like a passed one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarmChecklist {
    /// Collection is scoped to the minimum needed for the question at hand.
    pub minimal_footprint: bool,
    /// No third party is harmed, burdened, or exposed by the collection.
    pub third_party_non_harm: bool,
    /// Robots directives and terms-of-service posture were reviewed.
    pub robots_tos_posture: bool,
    /// Material is redacted at rest by default.
    pub redaction_at_rest: bool,
    /// Legal basis for the collection (warrant, consent, legitimate interest,
    /// …); required, non-empty after trimming.
    pub legal_basis: String,
}

/// Errors from harm review — checklist, note, and gate all share this one
/// shape so callers have a single error type to render.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HarmError {
    /// The checklist's `legal_basis` is empty (or whitespace only).
    MissingLegalBasis,
    /// One named review item is not affirmatively satisfied. `item` is the
    /// field name (`"minimal_footprint"`, …) or an artifact marker
    /// (`"checklist"` / `"harm_note"` when [`gate`] receives an absent
    /// artifact).
    Unchecked { item: String },
}

impl fmt::Display for HarmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HarmError::MissingLegalBasis => {
                write!(f, "harm review is missing a legal basis")
            }
            HarmError::Unchecked { item } => {
                write!(f, "harm-review item `{item}` is not checked")
            }
        }
    }
}

impl std::error::Error for HarmError {}

/// Validate a checklist (A7.2.1).
///
/// Precedence (documented): the four booleans are checked in declaration
/// order — `minimal_footprint`, `third_party_non_harm`, `robots_tos_posture`,
/// `redaction_at_rest` — and only then `legal_basis` is required non-empty
/// after trimming. The first failure is returned; the error names the exact
/// item.
pub fn validate(c: &HarmChecklist) -> Result<(), HarmError> {
    let items: [(&str, bool); 4] = [
        ("minimal_footprint", c.minimal_footprint),
        ("third_party_non_harm", c.third_party_non_harm),
        ("robots_tos_posture", c.robots_tos_posture),
        ("redaction_at_rest", c.redaction_at_rest),
    ];
    for (name, checked) in items {
        if !checked {
            return Err(HarmError::Unchecked {
                item: name.to_string(),
            });
        }
    }
    if c.legal_basis.trim().is_empty() {
        return Err(HarmError::MissingLegalBasis);
    }
    Ok(())
}

// ── Proportionality note (A7.2.2) ───────────────────────────────────────────

/// Human half of the harm review: who could be affected and why the
/// collection is still proportionate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HarmNote {
    /// Who (people, groups, operators) could be affected by this collection.
    pub who_could_be_affected: String,
    /// Why the collection is proportionate given those effects.
    pub why_proportionate: String,
    /// What is collected, as a list of short descriptors. May be empty —
    /// the note's binding fields are the two prose sections.
    pub collected: Vec<String>,
    /// Caller-supplied timestamp (ms since epoch); this module never reads
    /// the clock.
    pub created_ms: i64,
}

/// Validate a proportionality note (A7.2.2).
///
/// Reuses [`HarmError`] (documented mapping): an empty (or whitespace-only)
/// `who_could_be_affected` → `Unchecked { item: "who_could_be_affected" }`;
/// an empty `why_proportionate` → `Unchecked { item: "why_proportionate" }`.
/// Precedence: `who_could_be_affected` first. `collected` may be empty and
/// `created_ms` is not range-checked here (it is a caller guarantee).
pub fn validate_note(n: &HarmNote) -> Result<(), HarmError> {
    if n.who_could_be_affected.trim().is_empty() {
        return Err(HarmError::Unchecked {
            item: "who_could_be_affected".to_string(),
        });
    }
    if n.why_proportionate.trim().is_empty() {
        return Err(HarmError::Unchecked {
            item: "why_proportionate".to_string(),
        });
    }
    Ok(())
}

// ── Manifest attachment (A7.2.2) ────────────────────────────────────────────

/// One-word kind label for a JSON value, for error messages.
fn json_kind(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

/// Attach `note` to a manifest JSON object under the `"harm_note"` key.
///
/// The manifest must be a JSON object; anything else returns an `Err` whose
/// message names the actual kind (no silent no-op). An existing `"harm_note"`
/// key is overwritten — the function is "make the manifest carry THIS note",
/// so it is idempotent for a given note. Does **not** validate the note;
/// call [`validate_note`] first when validation is wanted (kept separate so
/// the attachment stays a pure structural operation).
pub fn attach_note(manifest_json: &mut serde_json::Value, note: &HarmNote) -> Result<(), String> {
    let serde_json::Value::Object(map) = manifest_json else {
        return Err(format!(
            "harm note can only attach to a JSON object manifest (got {})",
            json_kind(manifest_json)
        ));
    };
    let value = serde_json::to_value(note)
        .map_err(|e| format!("failed to serialize harm note: {e}"))?;
    map.insert("harm_note".to_string(), value);
    Ok(())
}

// ── Gate (A7.2.3) ───────────────────────────────────────────────────────────

/// The A7.2.3 gate: a collection plan proceeds only with **both** a valid
/// checklist and a valid proportionality note.
///
/// Mapping for absent artifacts (documented): for gating purposes an absent
/// artifact is indistinguishable from an unsatisfied one, so
/// `None` checklist → `Unchecked { item: "checklist" }` and `None` note →
/// `Unchecked { item: "harm_note" }` — the [`HarmError`] enum stays minimal
/// and every failure names what is missing. Precedence: checklist before
/// note; within each, [`validate`] / [`validate_note`] order applies.
/// Never panics.
pub fn gate(checklist: Option<&HarmChecklist>, note: Option<&HarmNote>) -> Result<(), HarmError> {
    match checklist {
        Some(c) => validate(c)?,
        None => {
            return Err(HarmError::Unchecked {
                item: "checklist".to_string(),
            })
        }
    }
    match note {
        Some(n) => validate_note(n),
        None => Err(HarmError::Unchecked {
            item: "harm_note".to_string(),
        }),
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn checked() -> HarmChecklist {
        HarmChecklist {
            minimal_footprint: true,
            third_party_non_harm: true,
            robots_tos_posture: true,
            redaction_at_rest: true,
            legal_basis: "warrant 2026-114".to_string(),
        }
    }

    fn good_note() -> HarmNote {
        HarmNote {
            who_could_be_affected: "site operators and logged-in users".to_string(),
            why_proportionate: "public endpoints only; no accounts touched".to_string(),
            collected: vec!["public incident reports".to_string()],
            created_ms: 1_760_000_000_000,
        }
    }

    // ── Checklist ───────────────────────────────────────────────────────────

    #[test]
    fn happy_path_validates() {
        assert_eq!(validate(&checked()), Ok(()));
    }

    #[test]
    fn each_unchecked_item_names_itself() {
        let cases: [(&str, fn(&mut HarmChecklist)); 4] = [
            ("minimal_footprint", |c| c.minimal_footprint = false),
            ("third_party_non_harm", |c| c.third_party_non_harm = false),
            ("robots_tos_posture", |c| c.robots_tos_posture = false),
            ("redaction_at_rest", |c| c.redaction_at_rest = false),
        ];
        for (name, flip) in cases {
            let mut c = checked();
            flip(&mut c);
            let err = validate(&c).unwrap_err();
            assert_eq!(
                err,
                HarmError::Unchecked {
                    item: name.to_string()
                }
            );
            // The Display rendering carries the item name too.
            assert!(err.to_string().contains(name), "display: {err}");
        }
    }

    #[test]
    fn unchecked_precedence_is_declaration_order() {
        let all_off = HarmChecklist {
            minimal_footprint: false,
            third_party_non_harm: false,
            robots_tos_posture: false,
            redaction_at_rest: false,
            legal_basis: String::new(),
        };
        // Booleans are checked before legal_basis; first in declaration order.
        assert_eq!(
            validate(&all_off),
            Err(HarmError::Unchecked {
                item: "minimal_footprint".to_string()
            })
        );
        let mut c = all_off;
        c.minimal_footprint = true;
        assert_eq!(
            validate(&c),
            Err(HarmError::Unchecked {
                item: "third_party_non_harm".to_string()
            })
        );
    }

    #[test]
    fn missing_legal_basis() {
        let mut c = checked();
        c.legal_basis = String::new();
        assert_eq!(validate(&c), Err(HarmError::MissingLegalBasis));

        c.legal_basis = "   \t\n  ".to_string();
        assert_eq!(validate(&c), Err(HarmError::MissingLegalBasis));

        // Whitespace around real content is fine (trimmed-non-empty rule).
        c.legal_basis = "  warrant 2026-114  ".to_string();
        assert_eq!(validate(&c), Ok(()));
    }

    // ── Note ────────────────────────────────────────────────────────────────

    #[test]
    fn note_happy_path() {
        assert_eq!(validate_note(&good_note()), Ok(()));
    }

    #[test]
    fn note_empty_fields_name_themselves() {
        let mut n = good_note();
        n.who_could_be_affected = "  ".to_string();
        assert_eq!(
            validate_note(&n),
            Err(HarmError::Unchecked {
                item: "who_could_be_affected".to_string()
            })
        );

        let mut n = good_note();
        n.why_proportionate = String::new();
        assert_eq!(
            validate_note(&n),
            Err(HarmError::Unchecked {
                item: "why_proportionate".to_string()
            })
        );
    }

    #[test]
    fn note_precedence_and_empty_collected_allowed() {
        let n = HarmNote {
            who_could_be_affected: String::new(),
            why_proportionate: String::new(),
            collected: vec![],
            created_ms: 0,
        };
        // who_could_be_affected wins when both are empty.
        assert_eq!(
            validate_note(&n),
            Err(HarmError::Unchecked {
                item: "who_could_be_affected".to_string()
            })
        );
        // Empty `collected` and created_ms = 0 are not invalid by themselves.
        let ok = HarmNote {
            who_could_be_affected: "nobody beyond the operator".to_string(),
            why_proportionate: "self-collection of own logs".to_string(),
            collected: vec![],
            created_ms: 0,
        };
        assert_eq!(validate_note(&ok), Ok(()));
    }

    // ── attach_note ─────────────────────────────────────────────────────────

    #[test]
    fn attach_note_round_trip() {
        let mut manifest = json!({"plan": "wave-7", "approved": false});
        attach_note(&mut manifest, &good_note()).unwrap();
        let attached = manifest.get("harm_note").expect("harm_note present");
        assert_eq!(attached["who_could_be_affected"], "site operators and logged-in users");
        assert_eq!(attached["why_proportionate"], "public endpoints only; no accounts touched");
        assert_eq!(attached["collected"][0], "public incident reports");
        assert_eq!(attached["created_ms"], 1_760_000_000_000i64);
        // Sibling keys untouched, and the embedded note deserializes back.
        assert_eq!(manifest["plan"], "wave-7");
        let back: HarmNote = serde_json::from_value(attached.clone()).unwrap();
        assert_eq!(back, good_note());
    }

    #[test]
    fn attach_note_overwrites_existing() {
        let mut manifest = json!({"harm_note": {"stale": true}});
        attach_note(&mut manifest, &good_note()).unwrap();
        assert_eq!(manifest["harm_note"]["stale"].is_null(), true);
        let back: HarmNote = serde_json::from_value(manifest["harm_note"].clone()).unwrap();
        assert_eq!(back, good_note());
    }

    #[test]
    fn attach_note_non_object_err() {
        for bad in [json!(null), json!([1, 2]), json!("nope"), json!(7), json!(true)] {
            let mut v = bad.clone();
            let err = attach_note(&mut v, &good_note()).unwrap_err();
            assert!(err.contains("JSON object"), "message: {err}");
            assert_eq!(v, bad, "input value must be untouched on error");
        }
    }

    // ── Gate ────────────────────────────────────────────────────────────────

    #[test]
    fn gate_requires_both_artifacts() {
        let c = checked();
        let n = good_note();
        assert_eq!(gate(Some(&c), Some(&n)), Ok(()));

        assert_eq!(
            gate(None, Some(&n)),
            Err(HarmError::Unchecked {
                item: "checklist".to_string()
            })
        );
        assert_eq!(
            gate(Some(&c), None),
            Err(HarmError::Unchecked {
                item: "harm_note".to_string()
            })
        );
        assert_eq!(
            gate(None, None),
            Err(HarmError::Unchecked {
                item: "checklist".to_string()
            })
        );
    }

    #[test]
    fn gate_propagates_inner_failures() {
        let mut bad_c = checked();
        bad_c.redaction_at_rest = false;
        let n = good_note();
        assert_eq!(
            gate(Some(&bad_c), Some(&n)),
            Err(HarmError::Unchecked {
                item: "redaction_at_rest".to_string()
            })
        );

        let c = checked();
        let mut bad_n = good_note();
        bad_n.why_proportionate = "  ".to_string();
        assert_eq!(
            gate(Some(&c), Some(&bad_n)),
            Err(HarmError::Unchecked {
                item: "why_proportionate".to_string()
            })
        );

        // Checklist failure precedes note failure when both are bad.
        assert_eq!(
            gate(Some(&bad_c), Some(&bad_n)),
            Err(HarmError::Unchecked {
                item: "redaction_at_rest".to_string()
            })
        );
    }

    // ── Determinism & serde ─────────────────────────────────────────────────

    #[test]
    fn determinism() {
        let c = checked();
        assert_eq!(validate(&c), validate(&c));
        let n = good_note();
        assert_eq!(validate_note(&n), validate_note(&n));
        assert_eq!(gate(Some(&c), Some(&n)), gate(Some(&c), Some(&n)));

        let mut m1 = json!({"plan": "x"});
        let mut m2 = json!({"plan": "x"});
        attach_note(&mut m1, &n).unwrap();
        attach_note(&mut m2, &n).unwrap();
        assert_eq!(m1, m2);
    }

    #[test]
    fn serde_round_trips() {
        let c = checked();
        let c_json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<HarmChecklist>(&c_json).unwrap(), c);

        let n = good_note();
        let n_json = serde_json::to_string(&n).unwrap();
        assert_eq!(serde_json::from_str::<HarmNote>(&n_json).unwrap(), n);

        for e in [
            HarmError::MissingLegalBasis,
            HarmError::Unchecked {
                item: "robots_tos_posture".to_string(),
            },
        ] {
            let e_json = serde_json::to_string(&e).unwrap();
            assert_eq!(serde_json::from_str::<HarmError>(&e_json).unwrap(), e);
        }
    }

    #[test]
    fn error_is_std_error() {
        fn as_err(_: &dyn std::error::Error) {}
        as_err(&HarmError::MissingLegalBasis);
    }
}
