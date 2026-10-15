//! Redaction + release bundles — released derivative, sealed original,
//! hash-audited (task A2.2.2 core, frozen interface §10).
//!
//! A2.2.1 ([`crate::access_class`]) answers *whether* material may leave the
//! vault. This module answers *what exactly leaves*: given an original
//! document and a list of field rules, [`produce_release`] builds a released
//! derivative plus a [`ReleaseAudit`] that pins both sides by sha256 — the
//! original stays sealed (never mutated, never copied out) and the release is
//! auditable and tamper-evident ([`verify_release`]).
//!
//! # Modes
//! - [`RedactMode::Remove`] drops the key from the released object entirely
//!   (the field's existence is withheld, not just its value).
//! - [`RedactMode::Mask`] keeps the field with `keep_prefix` leading and
//!   `keep_suffix` trailing characters (counted in Unicode scalar values) and
//!   replaces the hidden middle with `*`. If `keep_prefix + keep_suffix >=`
//!   char count there is nothing left to hide and the value is unchanged. On
//!   a non-string value the whole value becomes the string `"[REDACTED]"`
//!   (length-based trimming cannot be meaningful for numbers, arrays, …).
//! - [`RedactMode::Hash`] replaces the value with the sha256 hex of its
//!   serialized JSON bytes (deterministic; joinable against other hashes).
//!
//! # Hashing convention
//! sha256, lowercase hex, 64 chars — the same shape as `crate::raw_store`
//! content addresses. The released side and the original side are each hashed
//! over their canonical compact `serde_json::to_vec` bytes.
//!
//! Redaction itself is pure: no I/O, no clock — `now_ms` is supplied by the
//! caller so releases are reproducible in tests and replayable from audit
//! records. [`export_gate`] re-exports the A2.2.1 export decision in this
//! module's error type, so a release pipeline has one gate call and one error
//! shape (`DenyReason::code()` → [`RedactError::Denied`]).
//!
//! Declared in `lib.rs`; the export/release wiring through
//! [`crate::vault::access`] lands in the R1 wave (2026-09-28).

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::access_class::{check_export, AccessClass, Audience};

// ── Rules ────────────────────────────────────────────────────────────────────

/// How one field is redacted in the released copy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedactMode {
    /// Drop the key from the released object entirely.
    Remove,
    /// Keep `keep_prefix` leading and `keep_suffix` trailing characters
    /// (Unicode scalar values), replacing the middle with `*`. If
    /// `keep_prefix + keep_suffix >= char count`, the value is unchanged
    /// (documented: nothing left to hide). Non-string values become the
    /// string `"[REDACTED]"`.
    Mask {
        /// Characters kept at the start of a string value.
        keep_prefix: usize,
        /// Characters kept at the end of a string value.
        keep_suffix: usize,
    },
    /// Replace the value with the sha256 hex (64 lowercase chars) of its
    /// serialized JSON bytes.
    Hash,
}

/// One field-level redaction rule. `field` is a **top-level JSON object
/// key**; a rule whose field is absent from the document is a no-op.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionRule {
    /// Top-level object key the rule applies to.
    pub field: String,
    /// How the matched field is redacted.
    pub mode: RedactMode,
}

/// Errors from the redaction/release pipeline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedactError {
    /// The input document is not a JSON object (top-level redaction is
    /// object-keyed).
    NonObject,
    /// A rule carries an empty `field` name (malformed rule, not a no-op).
    EmptyField,
    /// The export gate refused; carries the stable [`crate::access_class`]
    /// deny code (e.g. `"deny.sealed"`).
    Denied(String),
}

impl fmt::Display for RedactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RedactError::NonObject => write!(f, "redaction input must be a JSON object"),
            RedactError::EmptyField => write!(f, "redaction rule has an empty field name"),
            RedactError::Denied(code) => write!(f, "export denied: {code}"),
        }
    }
}

impl std::error::Error for RedactError {}

// ── Hashing helpers (raw_store conventions) ─────────────────────────────────

/// sha256 of `bytes`, lowercase hex (64 chars) — same shape as
/// `crate::raw_store` content addresses.
fn hash_of(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    to_hex(h.finalize().as_slice())
}

/// Lowercase hex encoding — local helper, no extra dependency.
fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

/// Canonical serialized bytes of a JSON value for hashing: compact
/// `serde_json::to_vec` (no whitespace). On a `Value` this is infallible in
/// practice (object keys are always strings); the fallback keeps the
/// pipeline panic-free.
fn canonical_bytes(v: &serde_json::Value) -> Vec<u8> {
    serde_json::to_vec(v).unwrap_or_else(|_| v.to_string().into_bytes())
}

// ── Redaction ────────────────────────────────────────────────────────────────

/// Apply `rules` to a top-level JSON object and return a **new** value; the
/// original is never mutated.
///
/// Semantics (frozen §10):
/// - missing field → no-op (rule silently does nothing);
/// - empty `field` on any rule → [`RedactError::EmptyField`] (validated
///   before anything is applied);
/// - non-object document → [`RedactError::NonObject`];
/// - rules are applied in order; when two rules target the same field the
///   last one that still finds the field wins (a `Remove` makes later rules
///   for that field no-ops).
pub fn redact_value(
    doc: &serde_json::Value,
    rules: &[RedactionRule],
) -> Result<serde_json::Value, RedactError> {
    let obj = doc.as_object().ok_or(RedactError::NonObject)?;
    if rules.iter().any(|r| r.field.is_empty()) {
        return Err(RedactError::EmptyField);
    }
    let mut out = obj.clone();
    for rule in rules {
        // Missing field = no-op. Clone the current value so the map can be
        // mutated while the rule is being applied.
        let Some(current) = out.get(&rule.field).cloned() else {
            continue;
        };
        match &rule.mode {
            RedactMode::Remove => {
                out.remove(&rule.field);
            }
            RedactMode::Mask {
                keep_prefix,
                keep_suffix,
            } => {
                out.insert(
                    rule.field.clone(),
                    mask_value(&current, *keep_prefix, *keep_suffix),
                );
            }
            RedactMode::Hash => {
                out.insert(
                    rule.field.clone(),
                    serde_json::Value::String(hash_of(&canonical_bytes(&current))),
                );
            }
        }
    }
    Ok(serde_json::Value::Object(out))
}

/// Masked rendering of one value (see [`RedactMode::Mask`]).
fn mask_value(v: &serde_json::Value, keep_prefix: usize, keep_suffix: usize) -> serde_json::Value {
    match v.as_str() {
        Some(s) => serde_json::Value::String(mask_string(s, keep_prefix, keep_suffix)),
        None => serde_json::Value::String("[REDACTED]".to_string()),
    }
}

/// Keep `keep_prefix`/`keep_suffix` chars, `*` the middle. Too short (or
/// `keep_prefix + keep_suffix >= len`) → unchanged. Char-counted so Unicode
/// values are masked per visible character, not per byte.
fn mask_string(s: &str, keep_prefix: usize, keep_suffix: usize) -> String {
    let chars: Vec<char> = s.chars().collect();
    let n = chars.len();
    // saturating: hostile rule values can't overflow the comparison.
    if keep_prefix.saturating_add(keep_suffix) >= n {
        return s.to_string();
    }
    let prefix: String = chars[..keep_prefix].iter().collect();
    let suffix: String = chars[n - keep_suffix..].iter().collect();
    let hidden = n - keep_prefix - keep_suffix;
    format!("{prefix}{}{suffix}", "*".repeat(hidden))
}

// ── Release bundles ──────────────────────────────────────────────────────────

/// Hash-audited record of one release operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseAudit {
    /// sha256 hex of the released derivative.
    pub released_hash: String,
    /// sha256 hex of the sealed original document.
    pub original_hash: String,
    /// Rule spec strings in application order (all rules processed, matched
    /// or not), format: `"field:remove"` · `"field:mask(keep_prefix,keep_suffix)"`
    /// · `"field:hash"`. Re-running the specs reproduces the release.
    pub rules_applied: Vec<String>,
    /// Fields the rules actually matched (present in the original),
    /// ascending, deduplicated.
    pub redacted_fields: Vec<String>,
    /// Caller-supplied release time (unix ms).
    pub created_ms: i64,
}

/// A released derivative together with its audit trail.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReleaseBundle {
    /// The redacted derivative — safe for the approved audience.
    pub released: serde_json::Value,
    /// sha256 hex of `released` (also mirrored in `audit`).
    pub released_hash: String,
    /// sha256 hex of the sealed original (audit claim — the original bytes
    /// are not part of the bundle and cannot be re-verified from it alone).
    pub original_hash: String,
    /// The audit record for this release.
    pub audit: ReleaseAudit,
}

/// Redact `original` and seal both sides with hashes. `now_ms` is taken from
/// the caller (pure function; no clock reads).
///
/// Hashes are sha256 hex over the canonical compact `serde_json::to_vec` of
/// each side. `redacted_fields` lists matched fields ascending;
/// `rules_applied` lists every rule in application order.
pub fn produce_release(
    original: &serde_json::Value,
    rules: &[RedactionRule],
    now_ms: i64,
) -> Result<ReleaseBundle, RedactError> {
    let obj = original.as_object().ok_or(RedactError::NonObject)?;
    let released = redact_value(original, rules)?;
    let original_hash = hash_of(&canonical_bytes(original));
    let released_hash = hash_of(&canonical_bytes(&released));

    let mut redacted_fields: Vec<String> = rules
        .iter()
        .filter(|r| obj.contains_key(&r.field))
        .map(|r| r.field.clone())
        .collect();
    redacted_fields.sort();
    redacted_fields.dedup();

    let rules_applied: Vec<String> = rules.iter().map(rule_spec).collect();

    let audit = ReleaseAudit {
        released_hash: released_hash.clone(),
        original_hash: original_hash.clone(),
        rules_applied,
        redacted_fields,
        created_ms: now_ms,
    };
    Ok(ReleaseBundle {
        released,
        released_hash,
        original_hash,
        audit,
    })
}

/// Stable one-line spec for the audit record.
fn rule_spec(rule: &RedactionRule) -> String {
    match &rule.mode {
        RedactMode::Remove => format!("{}:remove", rule.field),
        RedactMode::Mask {
            keep_prefix,
            keep_suffix,
        } => format!("{}:mask({},{})", rule.field, keep_prefix, keep_suffix),
        RedactMode::Hash => format!("{}:hash", rule.field),
    }
}

/// Recompute the released side's hash and compare it against the recorded
/// value in the bundle *and* the audit mirror. `false` on any tamper of
/// `released` or either `released_hash` copy. (The original cannot be
/// re-verified from the bundle alone — its bytes are sealed elsewhere;
/// `original_hash` is the ledger-chaining claim.)
pub fn verify_release(bundle: &ReleaseBundle) -> bool {
    let recomputed = hash_of(&canonical_bytes(&bundle.released));
    recomputed == bundle.released_hash && bundle.audit.released_hash == bundle.released_hash
}

/// Export gate for a release: pass-through to [`crate::access_class::check_export`],
/// mapping `DenyReason` → [`RedactError::Denied`] with the deny's stable
/// machine code (`"deny.sealed"`, `"deny.audience-not-admitted"`,
/// `"deny.no-export-path"`, `"deny.embargo-active"`).
pub fn export_gate(
    class: AccessClass,
    audience: Audience,
    embargo_active: bool,
) -> Result<(), RedactError> {
    check_export(class, audience, embargo_active)
        .map_err(|reason| RedactError::Denied(reason.code().to_string()))
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Externally computed constants (printf … | sha256sum) so the hashing
    // convention is grounded outside this module's own code path.
    const SHA256_JSON_A1: &str = "015abd7f5cc57a2dd94b7590f04ad8084273905ee33ec5cebeae62276a97f862"; // sha256('{"a":1}')
    const SHA256_QUOTED_TOPSECRET: &str =
        "0d4904d11a1be80f5a7c2890f208144a524787a6231eab0d6d73bc283b53ebb2"; // sha256('"topsecret"')
    const SHA256_1234: &str =
        "03ac674216f3e15c761ee1a5e255f067953623c8b388b4459e13f978d7c846f4"; // sha256('1234')

    fn rule(field: &str, mode: RedactMode) -> RedactionRule {
        RedactionRule {
            field: field.to_string(),
            mode,
        }
    }

    #[test]
    fn remove_drops_the_key_entirely() {
        let doc = json!({"ssn": "123-45-6789", "id": 7});
        let out = redact_value(&doc, &[rule("ssn", RedactMode::Remove)]).unwrap();
        assert_eq!(out, json!({"id": 7}));
        assert!(out.get("ssn").is_none());
    }

    #[test]
    fn mask_keeps_prefix_suffix_and_stars_the_middle() {
        let doc = json!({"card": "4111222233334444"});
        let out = redact_value(
            &doc,
            &[rule("card", RedactMode::Mask { keep_prefix: 4, keep_suffix: 4 })],
        )
        .unwrap();
        assert_eq!(out["card"], json!("4111********4444"));
        assert_eq!(out["card"].as_str().unwrap().chars().count(), 16);
    }

    #[test]
    fn mask_edges_are_documented() {
        // keep_prefix + keep_suffix >= char count → unchanged.
        let doc = json!({"a": "ab", "b": "ab", "c": "", "d": "xy"});
        let out = redact_value(
            &doc,
            &[
                rule("a", RedactMode::Mask { keep_prefix: 1, keep_suffix: 1 }),
                rule("b", RedactMode::Mask { keep_prefix: usize::MAX, keep_suffix: 1 }),
                rule("c", RedactMode::Mask { keep_prefix: 0, keep_suffix: 0 }),
                rule("d", RedactMode::Mask { keep_prefix: 2, keep_suffix: 0 }),
            ],
        )
        .unwrap();
        assert_eq!(out["a"], json!("ab"));
        assert_eq!(out["b"], json!("ab"));
        assert_eq!(out["c"], json!(""));
        assert_eq!(out["d"], json!("xy"));
        // Zero-width keep on a longer string masks everything.
        let doc = json!({"p": "secret"});
        let out = redact_value(&doc, &[rule("p", RedactMode::Mask { keep_prefix: 0, keep_suffix: 0 })])
            .unwrap();
        assert_eq!(out["p"], json!("******"));
    }

    #[test]
    fn mask_counts_unicode_chars_not_bytes() {
        let doc = json!({"name": "αβγδεζη"});
        let out = redact_value(
            &doc,
            &[rule("name", RedactMode::Mask { keep_prefix: 2, keep_suffix: 2 })],
        )
        .unwrap();
        assert_eq!(out["name"], json!("αβ***ζη"));
    }

    #[test]
    fn mask_on_non_string_becomes_redacted_marker() {
        let doc = json!({"n": 42, "arr": [1, 2], "b": true, "z": null, "o": {"k": "v"}});
        let rules: Vec<RedactionRule> = ["n", "arr", "b", "z", "o"]
            .iter()
            .map(|f| rule(f, RedactMode::Mask { keep_prefix: 2, keep_suffix: 2 }))
            .collect();
        let out = redact_value(&doc, &rules).unwrap();
        for f in ["n", "arr", "b", "z", "o"] {
            assert_eq!(out[f], json!("[REDACTED]"), "field {f}");
        }
    }

    #[test]
    fn hash_replaces_with_sha256_hex_of_serialized_value() {
        let doc = json!({"token": "topsecret", "pin": 1234});
        let out = redact_value(
            &doc,
            &[rule("token", RedactMode::Hash), rule("pin", RedactMode::Hash)],
        )
        .unwrap();
        assert_eq!(out["token"], json!(SHA256_QUOTED_TOPSECRET));
        assert_eq!(out["pin"], json!(SHA256_1234));
        // Deterministic across calls and independent instances.
        let again = redact_value(&doc, &[rule("token", RedactMode::Hash)]).unwrap();
        assert_eq!(out["token"], again["token"]);
    }

    #[test]
    fn canonical_bytes_are_compact_to_vec() {
        assert_eq!(canonical_bytes(&json!({"a": 1})), b"{\"a\":1}".to_vec());
        assert_eq!(hash_of(&canonical_bytes(&json!({"a": 1}))), SHA256_JSON_A1);
    }

    #[test]
    fn missing_field_is_a_noop() {
        let doc = json!({"a": 1});
        let out = redact_value(&doc, &[rule("absent", RedactMode::Remove)]).unwrap();
        assert_eq!(out, doc);
        let b = produce_release(&doc, &[rule("absent", RedactMode::Remove)], 5).unwrap();
        assert!(b.audit.redacted_fields.is_empty());
    }

    #[test]
    fn empty_field_rule_is_an_error() {
        let doc = json!({"a": 1});
        assert_eq!(
            redact_value(&doc, &[rule("", RedactMode::Remove)]),
            Err(RedactError::EmptyField)
        );
        assert_eq!(
            produce_release(&doc, &[rule("", RedactMode::Hash)], 0),
            Err(RedactError::EmptyField)
        );
    }

    #[test]
    fn non_object_document_is_an_error() {
        for doc in [json!("str"), json!([1, 2]), json!(7), json!(null), json!(true)] {
            assert_eq!(
                redact_value(&doc, &[rule("a", RedactMode::Remove)]),
                Err(RedactError::NonObject),
                "doc {doc}"
            );
            assert_eq!(
                produce_release(&doc, &[], 0),
                Err(RedactError::NonObject),
                "doc {doc}"
            );
        }
    }

    #[test]
    fn original_is_untouched_and_hash_is_stable() {
        let orig = json!({"a": 1, "ssn": "123-45-6789"});
        let snapshot = orig.clone();
        let b1 = produce_release(&orig, &[rule("ssn", RedactMode::Remove)], 1).unwrap();
        let b2 = produce_release(&orig, &[rule("ssn", RedactMode::Remove)], 2).unwrap();
        assert_eq!(orig, snapshot, "original mutated");
        assert_eq!(b1.original_hash, b2.original_hash);
        assert_eq!(
            b1.original_hash,
            recompute_hash(&json!({"a": 1, "ssn": "123-45-6789"}))
        );
        assert!(b1.released.get("ssn").is_none());
    }

    /// Independent recomputation helper for test grounding (same convention,
    /// separate call site).
    fn recompute_hash(v: &serde_json::Value) -> String {
        let bytes = serde_json::to_vec(v).unwrap();
        let mut h = Sha256::new();
        h.update(&bytes);
        to_hex(h.finalize().as_slice())
    }

    #[test]
    fn verify_release_passes_and_flips_on_tamper() {
        let orig = json!({"ssn": "123-45-6789", "v": 3});
        let mut bundle = produce_release(&orig, &[rule("ssn", RedactMode::Remove)], 42).unwrap();
        assert!(verify_release(&bundle));

        // Tamper the released value.
        bundle.released["v"] = json!(999);
        assert!(!verify_release(&bundle));
        bundle.released["v"] = json!(3);
        assert!(verify_release(&bundle));

        // Tamper the recorded hash.
        bundle.released_hash = "deadbeef".to_string();
        assert!(!verify_release(&bundle));
        bundle.released_hash = hash_of(&canonical_bytes(&bundle.released));
        assert!(verify_release(&bundle));

        // Tamper the audit mirror.
        bundle.audit.released_hash = "0".repeat(64);
        assert!(!verify_release(&bundle));
    }

    #[test]
    fn audit_contents_are_exact() {
        let orig = json!({"z": "1", "a": "2", "m": "3"});
        let rules = vec![
            rule("z", RedactMode::Hash),
            rule("a", RedactMode::Remove),
            rule("m", RedactMode::Mask { keep_prefix: 1, keep_suffix: 0 }),
            rule("absent", RedactMode::Remove),
        ];
        let b = produce_release(&orig, &rules, 1_700_000_000_000).unwrap();
        assert_eq!(
            b.audit.rules_applied,
            vec!["z:hash", "a:remove", "m:mask(1,0)", "absent:remove"]
        );
        assert_eq!(b.audit.redacted_fields, vec!["a", "m", "z"]);
        assert_eq!(b.audit.created_ms, 1_700_000_000_000);
        assert_eq!(b.audit.released_hash, b.released_hash);
        assert_eq!(b.audit.original_hash, b.original_hash);
        assert!(verify_release(&b));
    }

    #[test]
    fn export_gate_mirrors_check_export_and_carries_stable_codes() {
        for class in AccessClass::ALL {
            for audience in Audience::ALL {
                for embargo in [false, true] {
                    let expected = match check_export(class, audience, embargo) {
                        Ok(()) => Ok(()),
                        Err(reason) => Err(RedactError::Denied(reason.code().to_string())),
                    };
                    assert_eq!(
                        export_gate(class, audience, embargo),
                        expected,
                        "{class:?} / {audience:?} / embargo={embargo}"
                    );
                }
            }
        }
        assert_eq!(
            export_gate(AccessClass::Sealed, Audience::Public, false),
            Err(RedactError::Denied("deny.sealed".to_string()))
        );
        assert_eq!(
            export_gate(AccessClass::Restricted, Audience::Operator, false),
            Err(RedactError::Denied("deny.no-export-path".to_string()))
        );
        assert_eq!(
            export_gate(AccessClass::Open, Audience::Public, true),
            Err(RedactError::Denied("deny.embargo-active".to_string()))
        );
        assert_eq!(export_gate(AccessClass::Open, Audience::Public, false), Ok(()));
        assert_eq!(
            export_gate(AccessClass::Research, Audience::Teammate, false),
            Ok(())
        );
    }

    #[test]
    fn error_display_is_stable() {
        assert_eq!(
            RedactError::NonObject.to_string(),
            "redaction input must be a JSON object"
        );
        assert_eq!(
            RedactError::EmptyField.to_string(),
            "redaction rule has an empty field name"
        );
        assert_eq!(
            RedactError::Denied("deny.sealed".to_string()).to_string(),
            "export denied: deny.sealed"
        );
        let _: &dyn std::error::Error = &RedactError::NonObject;
    }

    #[test]
    fn serde_round_trips() {
        let r = rule("ssn", RedactMode::Mask { keep_prefix: 3, keep_suffix: 2 });
        let s = serde_json::to_string(&r).unwrap();
        assert_eq!(serde_json::from_str::<RedactionRule>(&s).unwrap(), r);

        for m in [
            RedactMode::Remove,
            RedactMode::Mask { keep_prefix: 0, keep_suffix: 0 },
            RedactMode::Hash,
        ] {
            let s = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<RedactMode>(&s).unwrap(), m);
        }

        let orig = json!({"ssn": "123-45-6789", "id": 7});
        let bundle = produce_release(&orig, &[rule("ssn", RedactMode::Mask { keep_prefix: 3, keep_suffix: 2 })], 9)
            .unwrap();
        let s = serde_json::to_string(&bundle).unwrap();
        let back: ReleaseBundle = serde_json::from_str(&s).unwrap();
        assert_eq!(back, bundle);
        assert_eq!(back.audit, bundle.audit);
        assert!(verify_release(&back));

        let e = serde_json::to_string(&RedactError::Denied("deny.sealed".to_string())).unwrap();
        assert_eq!(
            serde_json::from_str::<RedactError>(&e).unwrap(),
            RedactError::Denied("deny.sealed".to_string())
        );
    }

    #[test]
    fn same_field_last_rule_wins_remove_blocks_later_rules() {
        let doc = json!({"x": "abc"});
        // Later rule sees the field removed → no-op.
        let out = redact_value(
            &doc,
            &[
                rule("x", RedactMode::Remove),
                rule("x", RedactMode::Hash),
            ],
        )
        .unwrap();
        assert_eq!(out, json!({}));
        // Without the remove, hash applies.
        let out = redact_value(&doc, &[rule("x", RedactMode::Hash)]).unwrap();
        assert_eq!(out["x"].as_str().unwrap().len(), 64);
    }
}
