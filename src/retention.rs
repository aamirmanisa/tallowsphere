//! Embargo / staged-open retention fields + release gate (A2.1.3).
//!
//! Every accession carries an [`Embargo`] record: an optional time-boxed
//! embargo window ([`embargo_until_ms`](Embargo::embargo_until_ms)), a
//! staged-open flag that records whether the deliberate "open the cage"
//! step has been taken, and free-form operator notes. The release gate
//! ([`release_gate`]) is deny-by-default and applies **embargo first, then
//! staged-open** precedence: while an embargo window is active the material
//! is locked even if it was already staged open; with no active embargo the
//! material still stays locked until the staged-open step has been taken.
//!
//! Time is Unix-epoch **milliseconds** (`now_ms`), consistent with the rest
//! of the ledger family. All functions are pure except [`stage_open`] and
//! [`annotate`], which mutate their argument; neither panics.

use std::fmt;

use serde::{Deserialize, Serialize};

// ── Embargo record ───────────────────────────────────────────────────────────

/// Embargo / staged-open retention state for one accession.
///
/// * `embargo_until_ms` — `Some(until)` = the material is embargoed until the
///   Unix-epoch millisecond `until` (exclusive end: at exactly `until` the
///   embargo is over); `None` = no embargo window at all.
/// * `staged_open` — `true` once the staged-open step has been taken. Releasing
///   additionally requires this to be set (see [`release_gate`]).
/// * `notes` — free-form operator notes (empty by default).
///
/// [`Default`] is documented as: **no embargo, closed** — i.e.
/// `embargo_until_ms: None`, `staged_open: false`, `notes: String::new()`.
/// The default state therefore still fails [`release_gate`] with
/// [`RetentionDenied::StagedClosed`]: absence of an embargo is not permission.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Embargo {
    /// Unix-epoch milliseconds until which the material is embargoed;
    /// `None` = no embargo window. End is exclusive (active iff `now < until`).
    pub embargo_until_ms: Option<i64>,
    /// Whether the staged-open step has been taken (idempotent once set).
    pub staged_open: bool,
    /// Free-form operator notes.
    pub notes: String,
}

impl Default for Embargo {
    /// Documented default: **no embargo, closed**.
    fn default() -> Self {
        Self {
            embargo_until_ms: None,
            staged_open: false,
            notes: String::new(),
        }
    }
}

// ── Denial reason ────────────────────────────────────────────────────────────

/// Why a retention/staging operation was refused. One variant per rule so
/// audit records can aggregate refusals by cause; serde-round-trippable for
/// ledger payloads. `Display` renders a human audit line and [`code`](Self::code)
/// a stable machine token (same pattern as the sibling gate modules).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RetentionDenied {
    /// An embargo window is still active; no release until it clears.
    Embargoed {
        /// Unix-epoch milliseconds at which the embargo ends (exclusive).
        until_ms: i64,
    },
    /// No embargo is active, but the staged-open step has not been taken.
    StagedClosed,
}

impl RetentionDenied {
    /// Stable machine code for audit aggregation (never localized).
    pub fn code(&self) -> &'static str {
        match self {
            RetentionDenied::Embargoed { .. } => "deny.embargoed",
            RetentionDenied::StagedClosed => "deny.staged-closed",
        }
    }
}

impl fmt::Display for RetentionDenied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RetentionDenied::Embargoed { until_ms } => {
                write!(f, "release denied: embargo active until {until_ms} ms")
            }
            RetentionDenied::StagedClosed => {
                f.write_str("release denied: staged-open step not yet taken")
            }
        }
    }
}

impl std::error::Error for RetentionDenied {}

// ── Gates (pure, deny-by-default) ────────────────────────────────────────────

/// Is an embargo window active for `e` at `now_ms`?
///
/// `Some(until)` and `now_ms < until` → `true`; `None` → `false`. Boundary is
/// **exclusive**: at exactly `until` the embargo is over (`now_ms == until`
/// → `false`), so a record created with `embargo_until_ms = now + d` is
/// active for exactly `d` milliseconds of wall time.
pub fn embargo_active(e: &Embargo, now_ms: i64) -> bool {
    match e.embargo_until_ms {
        Some(until) => now_ms < until,
        None => false,
    }
}

/// Take the staged-open step: refuse while the embargo is active, otherwise
/// set [`Embargo::staged_open`] and succeed.
///
/// * `Err(Embargoed { until_ms })` — an embargo window is active; nothing is
///   mutated.
/// * `Ok(())` — no active embargo; `staged_open` is set to `true`.
///
/// Idempotent: calling this on an already staged-open record returns `Ok(())`
/// without observable change (re-staging is a no-op, not an error — replaying
/// a staging event must not fail).
pub fn stage_open(e: &mut Embargo, now_ms: i64) -> Result<(), RetentionDenied> {
    if let Some(until) = e.embargo_until_ms {
        // `until` exists by the `Some` arm; shared boundary with `embargo_active`.
        if now_ms < until {
            return Err(RetentionDenied::Embargoed { until_ms: until });
        }
    }
    e.staged_open = true;
    Ok(())
}

/// Release gate: may the material leave at `now_ms`?
///
/// Precedence, documented: the embargo is checked **first**, so a material
/// that is both still embargoed and not yet staged open is refused as
/// [`RetentionDenied::Embargoed`] (the embargo is the stronger, time-boxed
/// reason an operator can act on). Only when no embargo is active does an
/// unset [`Embargo::staged_open`] yield [`RetentionDenied::StagedClosed`].
/// `Ok(())` requires: no active embargo AND `staged_open == true`.
pub fn release_gate(e: &Embargo, now_ms: i64) -> Result<(), RetentionDenied> {
    if let Some(until) = e.embargo_until_ms {
        if now_ms < until {
            return Err(RetentionDenied::Embargoed { until_ms: until });
        }
    }
    if !e.staged_open {
        return Err(RetentionDenied::StagedClosed);
    }
    Ok(())
}

// ── Accession annotation ─────────────────────────────────────────────────────

/// Human-readable JSON kind for error messages.
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

/// Annotate an accession JSON object in place with the retention fields:
/// `embargo_until_ms` (`null` when [`Embargo::embargo_until_ms`] is `None`),
/// `staged_open`, and `notes`. Any pre-existing values for those three keys
/// are overwritten; all other keys are preserved untouched.
///
/// The input must be a JSON **object**; anything else → `Err` whose message
/// names the actual JSON kind (never panics). Serialize the annotated value
/// to persist; deserializing it back into an [`Embargo`] is not lossless for
/// foreign keys but the three retention fields round-trip exactly.
pub fn annotate(accession_json: &mut serde_json::Value, e: &Embargo) -> Result<(), String> {
    let kind = json_kind(accession_json);
    let Some(obj) = accession_json.as_object_mut() else {
        return Err(format!(
            "retention::annotate: accession JSON must be a JSON object, found {kind}"
        ));
    };
    obj.insert(
        "embargo_until_ms".to_string(),
        match e.embargo_until_ms {
            Some(until) => serde_json::Value::from(until),
            None => serde_json::Value::Null,
        },
    );
    obj.insert(
        "staged_open".to_string(),
        serde_json::Value::Bool(e.staged_open),
    );
    obj.insert(
        "notes".to_string(),
        serde_json::Value::String(e.notes.clone()),
    );
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn embargo(until: Option<i64>) -> Embargo {
        Embargo {
            embargo_until_ms: until,
            staged_open: false,
            notes: "test".to_string(),
        }
    }

    #[test]
    fn default_is_no_embargo_and_closed() {
        let d = Embargo::default();
        assert_eq!(d.embargo_until_ms, None);
        assert!(!d.staged_open);
        assert!(d.notes.is_empty());
        // Documented: default still fails the release gate (absence of an
        // embargo is not permission).
        assert_eq!(release_gate(&d, 0), Err(RetentionDenied::StagedClosed));
    }

    #[test]
    fn embargo_active_boundary() {
        let e = embargo(Some(1_000));
        assert!(embargo_active(&e, 999), "t-1 must still be active");
        assert!(!embargo_active(&e, 1_000), "t itself is over (exclusive end)");
        assert!(!embargo_active(&e, 1_001));
        // Any `now` before the end is active — including the far past.
        assert!(embargo_active(&e, i64::MIN));
        // A window that already elapsed behaves as over.
        assert!(!embargo_active(&e, 5_000));
        let long = embargo(Some(i64::MAX));
        assert!(embargo_active(&long, i64::MAX - 1));
    }

    #[test]
    fn embargo_active_none_path() {
        let e = embargo(None);
        assert!(!embargo_active(&e, 0));
        assert!(!embargo_active(&e, i64::MAX));
        assert!(!embargo_active(&e, i64::MIN));
    }

    #[test]
    fn stage_open_refused_during_embargo() {
        let mut e = embargo(Some(500));
        assert_eq!(
            stage_open(&mut e, 499),
            Err(RetentionDenied::Embargoed { until_ms: 500 })
        );
        assert!(!e.staged_open, "refused staging must not mutate");
        // At the boundary the embargo is over → staging allowed.
        assert_eq!(stage_open(&mut e, 500), Ok(()));
        assert!(e.staged_open);
    }

    #[test]
    fn stage_open_ok_and_idempotent() {
        let mut e = embargo(None);
        assert_eq!(stage_open(&mut e, 10), Ok(()));
        assert!(e.staged_open);
        // Idempotent: re-staging an open record is a no-op success.
        assert_eq!(stage_open(&mut e, 10), Ok(()));
        assert!(e.staged_open);
        // A window created after staging still blocks a *release*.
        let mut e2 = embargo(Some(100));
        assert_eq!(stage_open(&mut e2, 0), Err(RetentionDenied::Embargoed { until_ms: 100 }));
    }

    #[test]
    fn release_gate_three_way_matrix() {
        // (1) embargo active → Embargoed, regardless of staged_open.
        let mut e = embargo(Some(100));
        assert_eq!(
            release_gate(&e, 50),
            Err(RetentionDenied::Embargoed { until_ms: 100 })
        );
        e.staged_open = true;
        assert_eq!(
            release_gate(&e, 50),
            Err(RetentionDenied::Embargoed { until_ms: 100 }),
            "precedence: embargo reason wins over staged state"
        );
        // (2) no active embargo + not staged → StagedClosed.
        let closed = embargo(None);
        assert_eq!(release_gate(&closed, 50), Err(RetentionDenied::StagedClosed));
        // Window that has already elapsed behaves like no window.
        let elapsed = embargo(Some(100));
        assert_eq!(release_gate(&elapsed, 100), Err(RetentionDenied::StagedClosed));
        // (3) no active embargo + staged_open → Ok.
        let open = Embargo {
            embargo_until_ms: None,
            staged_open: true,
            notes: String::new(),
        };
        assert_eq!(release_gate(&open, 50), Ok(()));
        // Both conditions met after expiry → Ok.
        let mut after = embargo(Some(100));
        after.staged_open = true;
        assert_eq!(release_gate(&after, 100), Ok(()));
        assert_eq!(release_gate(&after, 101), Ok(()));
    }

    #[test]
    fn release_gate_precedence_both_blocking() {
        // Active embargo AND closed staging → Embargoed (embargo first).
        let e = embargo(Some(10_000));
        assert_eq!(
            release_gate(&e, 0),
            Err(RetentionDenied::Embargoed { until_ms: 10_000 })
        );
    }

    #[test]
    fn annotate_sets_fields_and_preserves_others() {
        let mut v = json!({"accession": "A-1", "notes": "old", "extra": [1, 2]});
        let e = Embargo {
            embargo_until_ms: Some(42),
            staged_open: true,
            notes: "new".to_string(),
        };
        assert_eq!(annotate(&mut v, &e), Ok(()));
        assert_eq!(v["embargo_until_ms"], json!(42));
        assert_eq!(v["staged_open"], json!(true));
        assert_eq!(v["notes"], json!("new"));
        // Foreign keys preserved.
        assert_eq!(v["accession"], json!("A-1"));
        assert_eq!(v["extra"], json!([1, 2]));
    }

    #[test]
    fn annotate_none_writes_null() {
        let mut v = json!({});
        assert_eq!(annotate(&mut v, &embargo(None)), Ok(()));
        assert!(v["embargo_until_ms"].is_null());
        assert_eq!(v["staged_open"], json!(false));
    }

    #[test]
    fn annotate_round_trip() {
        let e = Embargo {
            embargo_until_ms: Some(123_456),
            staged_open: false,
            notes: "hold for review".to_string(),
        };
        let mut v = json!({"accession": "A-2"});
        annotate(&mut v, &e).unwrap();
        // The three retention fields round-trip back exactly.
        assert_eq!(v["embargo_until_ms"].as_i64(), e.embargo_until_ms);
        assert_eq!(v["staged_open"].as_bool(), Some(e.staged_open));
        assert_eq!(v["notes"].as_str(), Some(e.notes.as_str()));
        // And the annotated JSON survives a serde_json text round trip.
        let text = serde_json::to_string(&v).unwrap();
        let back: serde_json::Value = serde_json::from_str(&text).unwrap();
        assert_eq!(back, v);
    }

    #[test]
    fn annotate_non_object_errors() {
        for bad in [json!(null), json!(7), json!("x"), json!([1]), json!(true)] {
            let mut v = bad.clone();
            let err = annotate(&mut v, &Embargo::default()).unwrap_err();
            assert!(err.contains("object"), "message names expectation: {err}");
            // Input untouched on error.
            assert_eq!(v, bad);
        }
    }

    #[test]
    fn serde_round_trip() {
        let e = Embargo {
            embargo_until_ms: Some(9),
            staged_open: true,
            notes: "n".to_string(),
        };
        let text = serde_json::to_string(&e).unwrap();
        let back: Embargo = serde_json::from_str(&text).unwrap();
        assert_eq!(back, e);

        for d in [
            RetentionDenied::Embargoed { until_ms: 5 },
            RetentionDenied::StagedClosed,
        ] {
            let t = serde_json::to_string(&d).unwrap();
            let b: RetentionDenied = serde_json::from_str(&t).unwrap();
            assert_eq!(b, d);
        }
    }

    #[test]
    fn display_and_codes() {
        let emb = RetentionDenied::Embargoed { until_ms: 77 };
        assert_eq!(emb.code(), "deny.embargoed");
        assert_eq!(emb.to_string(), "release denied: embargo active until 77 ms");
        assert_eq!(RetentionDenied::StagedClosed.code(), "deny.staged-closed");
        assert_eq!(
            RetentionDenied::StagedClosed.to_string(),
            "release denied: staged-open step not yet taken"
        );
        // std::error::Error is implemented (usable with `?` in anyhow contexts).
        let _: &dyn std::error::Error = &RetentionDenied::StagedClosed;
    }

    #[test]
    fn determinism() {
        let e = embargo(Some(1_000));
        for now in [0, 999, 1_000, 5_000, i64::MIN, i64::MAX] {
            assert_eq!(embargo_active(&e, now), embargo_active(&e, now));
            assert_eq!(release_gate(&e, now), release_gate(&e, now));
        }
        let mut a = json!({"x": 1});
        let mut b = json!({"x": 1});
        assert_eq!(annotate(&mut a, &e), annotate(&mut b, &e));
        assert_eq!(a, b);
        let mut s1 = embargo(Some(1_000));
        let mut s2 = embargo(Some(1_000));
        assert_eq!(stage_open(&mut s1, 0), stage_open(&mut s2, 0));
        assert_eq!(s1, s2);
    }
}
