//! Post-wave retrospective + rejected-alternatives ledger (task A4.2.3;
//! interface §6).
//!
//! Wave A4 ("judgment quality") requires that each completed collection wave
//! is *retrospected*: what the wave concluded, which alternatives were
//! considered and **why they were rejected**, and what was learned. The
//! rejected-alternatives record is the point of the artifact — an unchecked
//! "we looked at the other options" claim is unfalsifiable, so the protocol
//! forces at least [`MIN_REJECTED`] rejected alternative to be named, each
//! with a reason, before a retro can be recorded.
//!
//! * [`RejectedAlternative`] — one considered-and-rejected option + why.
//! * [`RetroRecord`] — one wave's retro: outcome, rejected alternatives,
//!   lessons, `created_ms`.
//! * [`validate`] — structural validation; see "Semantics" below.
//! * [`RetroLedger`] — the store: at most one record per `wave_id`.
//!
//! # Semantics (frozen by interface §6)
//!
//! [`validate`] reports the **first** failure in this documented order:
//!
//! 1. `wave_id` empty/whitespace-only → [`RetroError::MissingWave`].
//! 2. `outcome` empty/whitespace-only → [`RetroError::EmptyField`] with
//!    `field = "outcome"`.
//! 3. Per-alternative emptiness, in vector order, `option` before
//!    `why_rejected`: an empty/whitespace-only `option` →
//!    [`RetroError::EmptyField`] with `field = "rejected[].option"`; an
//!    empty/whitespace-only `why_rejected` →
//!    [`RetroError::EmptyField`] with `field = "rejected[].why_rejected"`.
//! 4. Count of **distinct** rejected alternatives (trim-first,
//!    case-insensitive dedupe of `option`) must be ≥ [`MIN_REJECTED`];
//!    otherwise [`RetroError::TooFewRejected`] where `have` is the
//!    **deduped** count and `need = MIN_REJECTED`.
//!
//! Dedupe runs before counting, so padding the list with
//! `"social graph"` / `"Social Graph"` / `" social graph "` counts as one
//! alternative, not three. `lessons` may be empty (the interface grants
//! that explicitly) and is otherwise unvalidated; empty strings inside it
//! are accepted.
//!
//! Note on step 3 vs. the letter of §6: §6 names only `why_rejected` as a
//! per-alternative requirement. A rejected alternative with **no option
//! named** is not a record of anything, so this module additionally
//! rejects it via `EmptyField { field: "rejected[].option" }` — a strict
//! superset of the frozen checks, documented here and in the report.
//!
//! # `RetroLedger`
//!
//! Backed by a `BTreeMap<String, RetroRecord>`, which gives the "one record
//! per `wave_id`" rule and the ascending-`wave_id` iteration order for free
//! (`String` ordering = bytewise lexicographic).
//!
//! [`RetroLedger::add`] validates first, then checks for a duplicate
//! `wave_id`: a malformed record is rejected on its own terms before the
//! ledger's uniqueness rule is consulted. On `Err` the record is not
//! stored (the record is moved in, so the caller must clone if it wants to
//! retry after fixing).
//!
//! [`RetroLedger::summary`] emits one line per wave, ascending `wave_id`,
//! lines joined by `\n`, **no trailing newline**; empty ledger → empty
//! string. Line format (pinned by the tests):
//!
//! ```text
//! <wave_id> | <outcome> | rejected=<distinct> | lessons=<count>
//! ```
//!
//! `rejected=` is the deduped count (consistent with [`validate`]);
//! `lessons=` is the raw vector length. Any `\n`/`\r` inside `wave_id` or
//! `outcome` is collapsed to a single space so the one-line-per-wave
//! invariant holds even for hand-edited JSON.
//!
//! # Serde
//! Serde derive is a plain wire decoder and does not validate. Call
//! [`validate`] / [`RetroLedger::add`] after ingesting untrusted JSON. The
//! wire shape is pinned by the serde round-trip tests.


use std::collections::{BTreeMap, HashSet};

use serde::{Deserialize, Serialize};

/// Minimum number of **distinct** rejected alternatives a retro must record
/// (frozen by interface §6). "Distinct" = `option` compared trim-first,
/// case-insensitively (Unicode lowercasing).
pub const MIN_REJECTED: usize = 1;

/// One alternative that was considered and rejected during the wave.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RejectedAlternative {
    /// The rejected option / approach. Non-empty (trimmed), enforced by
    /// [`validate`].
    pub option: String,
    /// Why it was rejected. Non-empty (trimmed), enforced by [`validate`].
    pub why_rejected: String,
}

/// One post-wave retrospective record. Fields are frozen by interface §6;
/// serde derive is provided, but structs deserialized from untrusted JSON
/// must still be run through [`validate`] / [`RetroLedger::add`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetroRecord {
    /// The collection wave this retro closes (e.g. `"w-2026-09-11-a"`).
    /// Non-empty (trimmed) and unique within a [`RetroLedger`]; enforced by
    /// [`validate`] / [`RetroLedger::add`].
    pub wave_id: String,
    /// What the wave concluded. Non-empty (trimmed), enforced by
    /// [`validate`].
    pub outcome: String,
    /// Alternatives considered and rejected. At least [`MIN_REJECTED`]
    /// distinct entries (trim + case-insensitive dedupe of `option`), each
    /// with non-empty `option` and `why_rejected`; enforced by [`validate`].
    pub rejected: Vec<RejectedAlternative>,
    /// Lessons carried forward. May be empty; not otherwise validated.
    pub lessons: Vec<String>,
    /// Creation time, Unix epoch milliseconds. Not validated here (clock
    /// provenance is the caller's concern).
    pub created_ms: i64,
}

/// Validation / ledger errors for the retro protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
pub enum RetroError {
    /// `wave_id` was empty or whitespace-only.
    #[error("retro record must name its wave (wave_id is empty)")]
    MissingWave,
    /// Fewer than `need` distinct rejected alternatives after trim +
    /// case-insensitive dedupe; `have` is the deduped count.
    #[error("retro needs at least {need} rejected alternative(s) after dedupe, found {have}")]
    TooFewRejected { have: usize, need: usize },
    /// A required string field was empty or whitespace-only. `field` names
    /// it: `"outcome"`, `"rejected[].option"`, or `"rejected[].why_rejected"`.
    #[error("retro field `{field}` must not be empty")]
    EmptyField { field: String },
    /// A record for this `wave_id` already exists in the ledger.
    #[error("a retro record for wave `{wave_id}` already exists")]
    DuplicateWave { wave_id: String },
}

/// `true` when `s` is empty or whitespace-only.
fn blank(s: &str) -> bool {
    s.trim().is_empty()
}

/// Number of **distinct** rejected alternatives in `r`: trim-first,
/// case-insensitively deduped on `option`.
fn distinct_rejected_count(r: &RetroRecord) -> usize {
    let mut seen: HashSet<String> = HashSet::new();
    for a in &r.rejected {
        seen.insert(a.option.trim().to_lowercase());
    }
    seen.len()
}

/// Collapse `\n`/`\r` so a value cannot break the one-line-per-wave summary
/// invariant.
fn one_line(s: &str) -> String {
    s.replace(['\n', '\r'], " ")
}

/// Validate a retro record. First failure wins, in the documented order:
/// `wave_id` → `outcome` → per-alternative (`option`, then `why_rejected`,
/// in vector order) → distinct-rejected count.
pub fn validate(r: &RetroRecord) -> Result<(), RetroError> {
    if blank(&r.wave_id) {
        return Err(RetroError::MissingWave);
    }
    if blank(&r.outcome) {
        return Err(RetroError::EmptyField {
            field: "outcome".to_string(),
        });
    }
    for a in &r.rejected {
        if blank(&a.option) {
            return Err(RetroError::EmptyField {
                field: "rejected[].option".to_string(),
            });
        }
        if blank(&a.why_rejected) {
            return Err(RetroError::EmptyField {
                field: "rejected[].why_rejected".to_string(),
            });
        }
    }
    let have = distinct_rejected_count(r);
    if have < MIN_REJECTED {
        return Err(RetroError::TooFewRejected {
            have,
            need: MIN_REJECTED,
        });
    }
    Ok(())
}

/// The wave-retro store: at most one [`RetroRecord`] per `wave_id`,
/// iterated ascending by `wave_id`.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetroLedger {
    records: BTreeMap<String, RetroRecord>,
}

impl RetroLedger {
    /// An empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validate `r` and store it. Fails with [`RetroError::DuplicateWave`]
    /// when a record for the same `wave_id` already exists (validation runs
    /// first; see module docs). On `Err` nothing is stored.
    pub fn add(&mut self, r: RetroRecord) -> Result<(), RetroError> {
        validate(&r)?;
        if self.records.contains_key(&r.wave_id) {
            return Err(RetroError::DuplicateWave {
                wave_id: r.wave_id,
            });
        }
        self.records.insert(r.wave_id.clone(), r);
        Ok(())
    }

    /// The record for `wave_id`, if any.
    pub fn get(&self, wave_id: &str) -> Option<&RetroRecord> {
        self.records.get(wave_id)
    }

    /// Number of stored records.
    pub fn len(&self) -> usize {
        self.records.len()
    }

    /// `true` when no records are stored.
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// One line per wave, ascending `wave_id`, lines joined by `\n` with no
    /// trailing newline; empty ledger → `""`. Line format:
    /// `<wave_id> | <outcome> | rejected=<distinct> | lessons=<count>`
    /// (`rejected` = deduped count; `lessons` = raw vector length).
    pub fn summary(&self) -> String {
        let mut lines: Vec<String> = Vec::with_capacity(self.records.len());
        for r in self.records.values() {
            lines.push(format!(
                "{} | {} | rejected={} | lessons={}",
                one_line(&r.wave_id),
                one_line(&r.outcome),
                distinct_rejected_count(r),
                r.lessons.len(),
            ));
        }
        lines.join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alt(option: &str, why_rejected: &str) -> RejectedAlternative {
        RejectedAlternative {
            option: option.to_string(),
            why_rejected: why_rejected.to_string(),
        }
    }

    fn rec(wave: &str) -> RetroRecord {
        RetroRecord {
            wave_id: wave.to_string(),
            outcome: "wave closed: target profile confirmed".to_string(),
            rejected: vec![alt("passive-only collection", "misses time-bounded signal")],
            lessons: vec!["deadline pressure skewed source mix".to_string()],
            created_ms: 1_780_000_000_000,
        }
    }

    // -- validate -----------------------------------------------------------

    #[test]
    fn min_rejected_is_one() {
        assert_eq!(MIN_REJECTED, 1);
    }

    #[test]
    fn validate_happy_path() {
        assert_eq!(validate(&rec("w-1")), Ok(()));
    }

    #[test]
    fn validate_missing_wave_empty_and_whitespace() {
        let mut r = rec("w-1");
        r.wave_id = String::new();
        assert_eq!(validate(&r), Err(RetroError::MissingWave));
        r.wave_id = "  \t ".to_string();
        assert_eq!(validate(&r), Err(RetroError::MissingWave));
    }

    #[test]
    fn validate_empty_outcome() {
        let mut r = rec("w-1");
        r.outcome = " \n ".to_string();
        assert_eq!(
            validate(&r),
            Err(RetroError::EmptyField {
                field: "outcome".to_string()
            })
        );
    }

    #[test]
    fn validate_zero_rejected_is_too_few_with_deduped_have() {
        let mut r = rec("w-1");
        r.rejected = Vec::new();
        assert_eq!(
            validate(&r),
            Err(RetroError::TooFewRejected {
                have: 0,
                need: MIN_REJECTED
            })
        );
    }

    #[test]
    fn validate_empty_option_names_the_field() {
        let mut r = rec("w-1");
        r.rejected = vec![alt("   ", "no evidence path")];
        assert_eq!(
            validate(&r),
            Err(RetroError::EmptyField {
                field: "rejected[].option".to_string()
            })
        );
    }

    #[test]
    fn validate_empty_why_rejected_names_the_field() {
        let mut r = rec("w-1");
        r.rejected = vec![alt("passive-only", "  ")];
        assert_eq!(
            validate(&r),
            Err(RetroError::EmptyField {
                field: "rejected[].why_rejected".to_string()
            })
        );
    }

    #[test]
    fn validate_first_failure_wins_in_documented_order() {
        // wave missing + everything else broken → MissingWave.
        let mut r = rec("  ");
        r.outcome = String::new();
        r.rejected = Vec::new();
        assert_eq!(validate(&r), Err(RetroError::MissingWave));
        // wave ok, outcome missing + rejected broken → EmptyField(outcome).
        let mut r = rec("w-1");
        r.outcome = String::new();
        r.rejected = vec![alt("x", "")];
        assert_eq!(
            validate(&r),
            Err(RetroError::EmptyField {
                field: "outcome".to_string()
            })
        );
        // outcome ok, first alternative bad → that alternative's field.
        let mut r = rec("w-1");
        r.rejected = vec![alt("ok", "reason"), alt("", "reason2")];
        assert_eq!(
            validate(&r),
            Err(RetroError::EmptyField {
                field: "rejected[].option".to_string()
            })
        );
    }

    // -- dedupe counting ----------------------------------------------------

    #[test]
    fn distinct_count_trims_and_case_folds() {
        let mut r = rec("w-1");
        r.rejected = vec![
            alt("Social Graph", "low yield"),
            alt(" social graph ", "low yield"),
            alt("SOCIAL GRAPH", "low yield"),
            alt("Signal crawl", "covered by partner feed"),
        ];
        assert_eq!(distinct_rejected_count(&r), 2);
    }

    #[test]
    fn validate_dedupes_before_counting() {
        // Two spellings of the same option = ONE alternative; still ≥ MIN.
        let mut r = rec("w-1");
        r.rejected = vec![
            alt("Recon sweep", "tasking conflict"),
            alt("recon sweep", "tasking conflict"),
        ];
        assert_eq!(validate(&r), Ok(()));
        assert_eq!(distinct_rejected_count(&r), 1);
    }

    #[test]
    fn lessons_may_be_empty() {
        let mut r = rec("w-1");
        r.lessons = Vec::new();
        assert_eq!(validate(&r), Ok(()));
    }

    // -- ledger -------------------------------------------------------------

    #[test]
    fn ledger_add_get_len_is_empty() {
        let mut l = RetroLedger::new();
        assert!(l.is_empty());
        assert_eq!(l.len(), 0);
        assert_eq!(l.get("w-1"), None);
        l.add(rec("w-1")).unwrap();
        assert!(!l.is_empty());
        assert_eq!(l.len(), 1);
        assert_eq!(l.get("w-1").unwrap().wave_id, "w-1");
        assert_eq!(l.get("w-x"), None);
    }

    #[test]
    fn ledger_duplicate_wave_rejected_and_not_stored_twice() {
        let mut l = RetroLedger::new();
        l.add(rec("w-1")).unwrap();
        let mut second = rec("w-1");
        second.outcome = "different outcome".to_string();
        assert_eq!(
            l.add(second),
            Err(RetroError::DuplicateWave {
                wave_id: "w-1".to_string()
            })
        );
        assert_eq!(l.len(), 1);
        assert_eq!(l.get("w-1").unwrap().outcome, rec("w-1").outcome);
    }

    #[test]
    fn ledger_add_invalid_leaves_ledger_unchanged() {
        let mut l = RetroLedger::new();
        let mut bad = rec("w-2");
        bad.rejected = Vec::new();
        assert_eq!(
            l.add(bad),
            Err(RetroError::TooFewRejected {
                have: 0,
                need: MIN_REJECTED
            })
        );
        assert!(l.is_empty());
    }

    #[test]
    fn ledger_validates_before_duplicate_check() {
        let mut l = RetroLedger::new();
        l.add(rec("w-1")).unwrap();
        // Same wave id AND malformed: validation error wins (documented).
        let mut bad = rec("w-1");
        bad.outcome = String::new();
        assert_eq!(
            l.add(bad),
            Err(RetroError::EmptyField {
                field: "outcome".to_string()
            })
        );
    }

    // -- summary ------------------------------------------------------------

    #[test]
    fn summary_empty_ledger_is_empty_string() {
        assert_eq!(RetroLedger::new().summary(), "");
    }

    #[test]
    fn summary_one_line_per_wave_ascending() {
        let mut l = RetroLedger::new();
        // Added out of order on purpose.
        l.add(rec("w-b")).unwrap();
        let mut a = rec("w-a");
        a.outcome = "closed early".to_string();
        l.add(a).unwrap();
        assert_eq!(
            l.summary(),
            "w-a | closed early | rejected=1 | lessons=1\n\
             w-b | wave closed: target profile confirmed | rejected=1 | lessons=1"
        );
    }

    #[test]
    fn summary_deduped_rejected_count_and_lesson_count() {
        let mut l = RetroLedger::new();
        let mut r = rec("w-1");
        r.rejected = vec![
            alt("A", "why a"),
            alt("a", "why a"),
            alt("B", "why b"),
        ];
        r.lessons = vec!["l1".to_string(), "l2".to_string()];
        l.add(r).unwrap();
        assert!(l.summary().contains("rejected=2 | lessons=2"));
    }

    #[test]
    fn summary_collapses_newlines_to_keep_one_line_per_wave() {
        let mut l = RetroLedger::new();
        let mut r = rec("w-1");
        r.outcome = "line one\nline two\r\nline three".to_string();
        l.add(r).unwrap();
        let s = l.summary();
        assert_eq!(s.lines().count(), 1);
        assert!(s.contains("line one line two  line three"));
    }

    #[test]
    fn summary_is_deterministic() {
        let mut a = RetroLedger::new();
        a.add(rec("w-b")).unwrap();
        a.add(rec("w-a")).unwrap();
        let mut b = RetroLedger::new();
        b.add(rec("w-a")).unwrap();
        b.add(rec("w-b")).unwrap();
        assert_eq!(a.summary(), a.summary());
        assert_eq!(a, b);
        assert_eq!(a.summary(), b.summary());
    }

    // -- serde / Display ----------------------------------------------------

    #[test]
    fn serde_roundtrip_record() {
        let r = rec("w-1");
        let j = serde_json::to_string(&r).unwrap();
        let back: RetroRecord = serde_json::from_str(&j).unwrap();
        assert_eq!(back, r);
        assert_eq!(back.rejected[0].option, "passive-only collection");
        assert_eq!(back.created_ms, 1_780_000_000_000);
    }

    #[test]
    fn serde_roundtrip_rejected_alternative() {
        let a = alt("option x", "reason y");
        let j = serde_json::to_string(&a).unwrap();
        let back: RejectedAlternative = serde_json::from_str(&j).unwrap();
        assert_eq!(back, a);
    }

    #[test]
    fn serde_roundtrip_error_variants() {
        let errs = vec![
            RetroError::MissingWave,
            RetroError::TooFewRejected { have: 0, need: 1 },
            RetroError::EmptyField {
                field: "outcome".to_string(),
            },
            RetroError::DuplicateWave {
                wave_id: "w-1".to_string(),
            },
        ];
        for e in errs {
            let j = serde_json::to_string(&e).unwrap();
            let back: RetroError = serde_json::from_str(&j).unwrap();
            assert_eq!(back, e);
            assert!(!format!("{e}").is_empty()); // Display reachable
        }
    }

    #[test]
    fn serde_roundtrip_ledger() {
        let mut l = RetroLedger::new();
        l.add(rec("w-b")).unwrap();
        l.add(rec("w-a")).unwrap();
        let j = serde_json::to_string(&l).unwrap();
        let back: RetroLedger = serde_json::from_str(&j).unwrap();
        assert_eq!(back, l);
        assert_eq!(back.summary(), l.summary());
    }
}
