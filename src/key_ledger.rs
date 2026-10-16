//! Key-use ledger — reuse detection + rotation enforcement model
//! (task A6.1.2 · frozen interface §5).
//!
//! The ledger is an **append-only log** of key usages. It answers the three
//! operational questions around key hygiene:
//!
//! * *Has one logical key been seen somewhere it does not belong?* —
//!   [`KeyUseLedger::reuse_findings`] reports every `key_id` whose usage
//!   history deviates from the first use recorded for it.
//! * *May this key be used again, here?* — [`KeyUseLedger::check_reuse`] is
//!   the hard-fail gate: it denies a use when the key was first recorded in a
//!   different context.
//! * *Which keys are past their rotation window?* —
//!   [`KeyUseLedger::rotation_due`] applies a [`RotationPolicy`] (maximum age
//!   and/or maximum number of uses).
//!
//! Everything here is deterministic and clock-free: callers pass `now_ms`
//! explicitly, and identical inputs produce identical outputs (verdicts are
//! compared between runs).
//!
//! # Documented edge rules (spec silent; conservative reading chosen)
//!
//! * **Baseline = first recorded use.** For each `key_id`, the first use in
//!   append order establishes the reference `(context, fingerprint)`. A later
//!   use is a *reuse event* when its context differs from the baseline
//!   context **or** its fingerprint differs from the baseline fingerprint —
//!   i.e. "the same `key_id` seen in a different context, or with different
//!   key material". A third use reverting to the baseline values is not a new
//!   event (the finding's `count` already records the incident, and append
//!   order stays the single source of truth). Rationale: append-order
//!   stability — findings are identical for identical logs, with no hidden
//!   state.
//! * **Recording never fails on reuse.** Reuse is evidence, not a recording
//!   error: the use is appended and reported by `reuse_findings`.
//!   `record_key_use` returns `Err` only for invalid input
//!   ([`KeyError::EmptyField`] — empty/blank `key_id`, `context`, or
//!   `fingerprint`), and a rejected use is **not** appended (the log is
//!   unchanged). `operation` is descriptive-only and may be empty.
//! * **Findings are derived, never stored.** `reuse_findings` recomputes from
//!   the log on each call, so a finding cannot drift from the recorded uses.
//!   Only keys with at least one reuse event are reported; `contexts` lists
//!   the key's distinct contexts in ascending order; `count` is the number of
//!   *event uses* (deviating uses), not the key's total use count; findings
//!   are ordered by `key_id`.
//! * **`check_reuse` is context-only** (its signature carries no fingerprint):
//!   it compares the offered context against the key's baseline context.
//!   Unknown keys pass — there is nothing to conflict with. Fingerprint
//!   deviations are surfaced through `reuse_findings`.
//! * **Rotation.** Age is measured from the key's *earliest recorded use*
//!   (the closest proxy the ledger has to key age — keys rotate from
//!   creation, and the ledger stores uses, not issuance). Both thresholds are
//!   inclusive: due when `now_ms - first_use >= max_age_ms` or
//!   `uses >= max_uses`. A threshold `<= 0` (age) / `== 0` (uses) disables
//!   that criterion; both disabled means nothing is ever due. Timestamps in
//!   the future saturate (no arithmetic underflow). Output is ascending by
//!   `key_id`.
//! * **Canonical serde.** Uses are grouped in a `BTreeMap`, so the
//!   serialized form is canonical regardless of insertion order.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

// ---------------------------------------------------------------------------
// Data model
// ---------------------------------------------------------------------------

/// One recorded use of a key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUse {
    /// Logical key identity. Equal ids denote the same key; the ledger never
    /// rekeys or renames — it records what it is told.
    pub key_id: String,
    /// Where the key was used (agent, tool, session, trust boundary, …).
    /// Reuse across *different* contexts is the primary red flag.
    pub context: String,
    /// When the use happened (Unix milliseconds, caller-supplied). The
    /// earliest `ts_ms` per key is the baseline for the age rotation rule.
    pub ts_ms: i64,
    /// What the key did (sign/verify/encrypt/…). Descriptive-only: it does not
    /// participate in reuse or rotation decisions, and may be empty.
    pub operation: String,
    /// Fingerprint of the key material presented (hash/id — format is the
    /// caller's choice). A changed fingerprint under one `key_id` means the
    /// material behind a stable name changed, which is itself suspicious.
    pub fingerprint: String,
}

/// Ledger error: input validation ([`KeyError::EmptyField`]) and the
/// hard-fail reuse verdict ([`KeyError::ReuseDetected`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyError {
    /// A mandatory identity field was empty (or blank). Nothing was recorded.
    /// The payload names the offending field (`"key_id"`, `"context"`, or
    /// `"fingerprint"`).
    EmptyField(String),
    /// Hard-fail verdict from [`KeyUseLedger::check_reuse`]: `key_id` was
    /// first recorded in `first_context` and is now offered for a different
    /// `new_context`.
    ReuseDetected {
        /// The key that was seen in conflicting contexts.
        key_id: String,
        /// Context accepted as the key's baseline (its first recorded use).
        first_context: String,
        /// Context the caller is offering — the reuse side of the conflict.
        new_context: String,
    },
}

impl std::fmt::Display for KeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyError::EmptyField(field) => {
                write!(f, "required field is empty: {field}")
            }
            KeyError::ReuseDetected {
                key_id,
                first_context,
                new_context,
            } => write!(
                f,
                "key reuse detected: key_id {key_id:?} was first used in context \
                 {first_context:?} but is offered for {new_context:?}"
            ),
        }
    }
}

impl std::error::Error for KeyError {}

/// Rotation limits applied by [`KeyUseLedger::rotation_due`]. A criterion is
/// disabled by its zero threshold (documented module-level).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RotationPolicy {
    /// Maximum key age in milliseconds, measured from the key's earliest
    /// recorded use. `<= 0` disables the age criterion.
    pub max_age_ms: i64,
    /// Maximum number of uses per key. `0` disables the use-count criterion.
    pub max_uses: u32,
}

/// Derived report: one `key_id` whose usage history deviates from its
/// baseline (first recorded use).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReuseFinding {
    /// The key seen reused / rematerialised.
    pub key_id: String,
    /// The key's distinct contexts, ascending (deduplicated).
    pub contexts: Vec<String>,
    /// Number of reuse *events*: uses deviating from the baseline
    /// `(context, fingerprint)`. Not the key's total use count.
    pub count: usize,
}

/// Append-only key-use ledger: every recorded [`KeyUse`], grouped by
/// `key_id`. `BTreeMap` keeps iteration and serialization canonical.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyUseLedger {
    /// Recorded uses per key, in append order within each key.
    uses: BTreeMap<String, Vec<KeyUse>>,
}

// ---------------------------------------------------------------------------
// Ledger operations
// ---------------------------------------------------------------------------

impl KeyUseLedger {
    /// Empty ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Append one use. Append-only: nothing is ever rewritten or removed.
    ///
    /// Returns `Err(`[`KeyError::EmptyField`]`)` — and records nothing — when
    /// `key_id`, `context`, or `fingerprint` is empty/blank. A *reuse* is not
    /// an error here: the use is appended and surfaced by
    /// [`KeyUseLedger::reuse_findings`] (reuse is evidence, not invalid
    /// input). Use [`KeyUseLedger::check_reuse`] for the hard-fail gate.
    pub fn record_key_use(&mut self, u: KeyUse) -> Result<(), KeyError> {
        if u.key_id.trim().is_empty() {
            return Err(KeyError::EmptyField("key_id".to_string()));
        }
        if u.context.trim().is_empty() {
            return Err(KeyError::EmptyField("context".to_string()));
        }
        if u.fingerprint.trim().is_empty() {
            return Err(KeyError::EmptyField("fingerprint".to_string()));
        }
        self.uses.entry(u.key_id.clone()).or_default().push(u);
        Ok(())
    }

    /// Derive reuse findings from the log (see module docs for the exact
    /// rule). Only keys with at least one reuse event appear; findings are
    /// ordered by `key_id`.
    pub fn reuse_findings(&self) -> Vec<ReuseFinding> {
        let mut findings = Vec::new();
        for (key_id, log) in &self.uses {
            let Some(first) = log.first() else {
                continue; // unreachable: a group exists only after a push
            };
            let count = log
                .iter()
                .filter(|u| u.context != first.context || u.fingerprint != first.fingerprint)
                .count();
            if count == 0 {
                continue;
            }
            let contexts: BTreeSet<&str> = log.iter().map(|u| u.context.as_str()).collect();
            findings.push(ReuseFinding {
                key_id: key_id.clone(),
                contexts: contexts.into_iter().map(str::to_owned).collect(),
                count,
            });
        }
        findings
    }

    /// Hard-fail reuse gate: `Ok(())` when `key_id` was never recorded, or
    /// was first recorded in exactly `context`; `Err(`
    /// [`KeyError::ReuseDetected`]`)` when it was first recorded in a
    /// different context. Context-only by signature (no fingerprint
    /// argument); see module docs.
    pub fn check_reuse(&self, key_id: &str, context: &str) -> Result<(), KeyError> {
        if let Some(first) = self.uses.get(key_id).and_then(|log| log.first()) {
            if first.context != context {
                return Err(KeyError::ReuseDetected {
                    key_id: key_id.to_string(),
                    first_context: first.context.clone(),
                    new_context: context.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Keys past their rotation window under `policy` at `now_ms`, ascending
    /// by `key_id` (see module docs for the inclusive boundaries).
    pub fn rotation_due(&self, policy: &RotationPolicy, now_ms: i64) -> Vec<String> {
        let age_enabled = policy.max_age_ms > 0;
        let uses_enabled = policy.max_uses > 0;
        let mut due = Vec::new();
        for (key_id, log) in &self.uses {
            let Some(first) = log.first() else {
                continue;
            };
            let age_due =
                age_enabled && now_ms.saturating_sub(first.ts_ms) >= policy.max_age_ms;
            let uses_due = uses_enabled && log.len() as u64 >= u64::from(policy.max_uses);
            if age_due || uses_due {
                due.push(key_id.clone());
            }
        }
        due
    }

    /// Recorded uses for one key, in append order. Empty slice for unknown
    /// keys.
    pub fn uses_for(&self, key_id: &str) -> &[KeyUse] {
        self.uses.get(key_id).map(Vec::as_slice).unwrap_or(&[])
    }

    /// Total number of recorded uses across all keys.
    pub fn len(&self) -> usize {
        self.uses.values().map(Vec::len).sum()
    }

    /// True when no use has been recorded.
    pub fn is_empty(&self) -> bool {
        self.uses.is_empty()
    }

    /// Number of distinct keys in the ledger.
    pub fn key_count(&self) -> usize {
        self.uses.len()
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ku(key_id: &str, context: &str, ts_ms: i64, operation: &str, fingerprint: &str) -> KeyUse {
        KeyUse {
            key_id: key_id.to_string(),
            context: context.to_string(),
            ts_ms,
            operation: operation.to_string(),
            fingerprint: fingerprint.to_string(),
        }
    }

    // --- recording ---------------------------------------------------------

    #[test]
    fn record_appends_in_order_and_is_queryable() {
        let mut led = KeyUseLedger::new();
        assert!(led.is_empty());
        led.record_key_use(ku("k1", "ctx-a", 10, "sign", "fpA")).unwrap();
        led.record_key_use(ku("k1", "ctx-a", 20, "sign", "fpA")).unwrap();
        assert_eq!(led.len(), 2);
        assert_eq!(led.key_count(), 1);
        let log = led.uses_for("k1");
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].ts_ms, 10);
        assert_eq!(log[1].ts_ms, 20);
        assert_eq!(log[0].operation, "sign");
        assert!(led.uses_for("nope").is_empty());
        assert!(led.reuse_findings().is_empty(), "routine repeats are clean");
    }

    #[test]
    fn empty_identity_fields_are_rejected_and_not_recorded() {
        let mut led = KeyUseLedger::new();
        let err = led.record_key_use(ku("", "ctx-a", 1, "sign", "fpA")).unwrap_err();
        assert_eq!(err, KeyError::EmptyField("key_id".to_string()));
        let err = led.record_key_use(ku("   ", "ctx-a", 1, "sign", "fpA")).unwrap_err();
        assert_eq!(err, KeyError::EmptyField("key_id".to_string()));
        let err = led.record_key_use(ku("k1", "", 1, "sign", "fpA")).unwrap_err();
        assert_eq!(err, KeyError::EmptyField("context".to_string()));
        let err = led.record_key_use(ku("k1", "ctx-a", 1, "sign", "")).unwrap_err();
        assert_eq!(err, KeyError::EmptyField("fingerprint".to_string()));
        assert!(led.is_empty(), "rejected uses must not be appended");
    }

    // --- reuse detection ---------------------------------------------------

    #[test]
    fn seeded_reuse_cross_context_is_caught() {
        let mut led = KeyUseLedger::new();
        led.record_key_use(ku("k1", "ctx-a", 10, "sign", "fpA")).unwrap(); // baseline
        led.record_key_use(ku("k1", "ctx-b", 20, "verify", "fpA")).unwrap(); // reuse
        led.record_key_use(ku("k1", "ctx-b", 30, "verify", "fpA")).unwrap(); // reuse again
        led.record_key_use(ku("k2", "ctx-a", 40, "sign", "fpB")).unwrap(); // clean key
        let findings = led.reuse_findings();
        assert_eq!(findings.len(), 1, "only k1 deviates");
        assert_eq!(findings[0].key_id, "k1");
        assert_eq!(
            findings[0].contexts,
            vec!["ctx-a".to_string(), "ctx-b".to_string()]
        );
        assert_eq!(findings[0].count, 2);
    }

    #[test]
    fn seeded_reuse_fingerprint_change_same_context_is_caught() {
        let mut led = KeyUseLedger::new();
        led.record_key_use(ku("k1", "ctx-a", 10, "sign", "fpA")).unwrap();
        led.record_key_use(ku("k1", "ctx-a", 20, "sign", "fpB")).unwrap(); // material changed
        let findings = led.reuse_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].key_id, "k1");
        assert_eq!(findings[0].contexts, vec!["ctx-a".to_string()]);
        assert_eq!(findings[0].count, 1);
    }

    #[test]
    fn fingerprint_reverting_to_baseline_is_not_a_new_event() {
        let mut led = KeyUseLedger::new();
        led.record_key_use(ku("k1", "ctx-a", 1, "sign", "fpA")).unwrap();
        led.record_key_use(ku("k1", "ctx-a", 2, "sign", "fpB")).unwrap(); // event
        led.record_key_use(ku("k1", "ctx-a", 3, "sign", "fpA")).unwrap(); // matches baseline
        let findings = led.reuse_findings();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].count, 1);
    }

    #[test]
    fn distinct_context_ok() {
        // Distinct keys in distinct contexts, each used repeatedly in its own
        // context, are all clean — no seeded reuse.
        let mut led = KeyUseLedger::new();
        for ts in [10, 20, 30] {
            led.record_key_use(ku("k1", "ctx-a", ts, "sign", "fpA")).unwrap();
            led.record_key_use(ku("k2", "ctx-b", ts, "sign", "fpB")).unwrap();
        }
        assert!(led.reuse_findings().is_empty());
        assert!(led.check_reuse("k1", "ctx-a").is_ok());
        assert!(led.check_reuse("k2", "ctx-b").is_ok());
    }

    #[test]
    fn check_reuse_hard_fails_on_cross_context() {
        let mut led = KeyUseLedger::new();
        led.record_key_use(ku("k1", "ctx-a", 10, "sign", "fpA")).unwrap();
        assert!(led.check_reuse("k1", "ctx-a").is_ok());
        let err = led.check_reuse("k1", "ctx-b").unwrap_err();
        assert_eq!(
            err,
            KeyError::ReuseDetected {
                key_id: "k1".to_string(),
                first_context: "ctx-a".to_string(),
                new_context: "ctx-b".to_string(),
            }
        );
        // Hard-fail form: the denied use never degrades into Ok.
        assert!(matches!(
            led.check_reuse("k1", "ctx-b"),
            Err(KeyError::ReuseDetected { .. })
        ));
        // Unknown key: nothing to conflict with.
        assert!(led.check_reuse("k9", "anywhere").is_ok());
    }

    // --- rotation ----------------------------------------------------------

    #[test]
    fn rotation_due_by_age_boundary_is_inclusive() {
        let mut led = KeyUseLedger::new();
        led.record_key_use(ku("k-old", "ctx-a", 1_000, "sign", "fpA")).unwrap();
        let policy = RotationPolicy {
            max_age_ms: 500,
            max_uses: 0, // uses criterion disabled
        };
        assert!(led.rotation_due(&policy, 1_499).is_empty());
        assert_eq!(led.rotation_due(&policy, 1_500), vec!["k-old".to_string()]);
        assert_eq!(led.rotation_due(&policy, 9_999), vec!["k-old".to_string()]);
        // Timestamp in the future: saturating arithmetic, still not due.
        let mut led = KeyUseLedger::new();
        led.record_key_use(ku("k-future", "ctx-a", 5_000, "sign", "fpA")).unwrap();
        assert!(led.rotation_due(&policy, 100).is_empty());
    }

    #[test]
    fn rotation_due_by_uses_boundary_is_inclusive() {
        let mut led = KeyUseLedger::new();
        let policy = RotationPolicy {
            max_age_ms: 0, // age criterion disabled
            max_uses: 3,
        };
        led.record_key_use(ku("k1", "ctx-a", 1, "sign", "fpA")).unwrap();
        led.record_key_use(ku("k1", "ctx-a", 2, "sign", "fpA")).unwrap();
        assert!(led.rotation_due(&policy, 100).is_empty(), "2 < 3 uses");
        led.record_key_use(ku("k1", "ctx-a", 3, "sign", "fpA")).unwrap();
        assert_eq!(led.rotation_due(&policy, 100), vec!["k1".to_string()]);
    }

    #[test]
    fn rotation_zero_policy_disables_both_criteria() {
        let mut led = KeyUseLedger::new();
        for ts in 0..10 {
            led.record_key_use(ku("k1", "ctx-a", ts, "sign", "fpA")).unwrap();
        }
        let policy = RotationPolicy {
            max_age_ms: 0,
            max_uses: 0,
        };
        assert!(led.rotation_due(&policy, i64::MAX).is_empty());
    }

    #[test]
    fn rotation_due_reports_each_due_key_once_ascending() {
        let mut led = KeyUseLedger::new();
        led.record_key_use(ku("zz", "ctx-a", 0, "sign", "fpA")).unwrap();
        led.record_key_use(ku("aa", "ctx-a", 0, "sign", "fpA")).unwrap();
        led.record_key_use(ku("mm", "ctx-a", 5_000, "sign", "fpA")).unwrap(); // fresh
        let policy = RotationPolicy {
            max_age_ms: 1_000,
            max_uses: 0,
        };
        assert_eq!(
            led.rotation_due(&policy, 1_000),
            vec!["aa".to_string(), "zz".to_string()]
        );
    }

    // --- serde -------------------------------------------------------------

    #[test]
    fn serde_round_trip_ledger_preserves_findings_and_rotation() {
        let mut led = KeyUseLedger::new();
        led.record_key_use(ku("k1", "ctx-a", 10, "sign", "fpA")).unwrap();
        led.record_key_use(ku("k1", "ctx-b", 20, "verify", "fpA")).unwrap();
        led.record_key_use(ku("k2", "ctx-c", 30, "sign", "fpB")).unwrap();
        let json = serde_json::to_string(&led).unwrap();
        let back: KeyUseLedger = serde_json::from_str(&json).unwrap();
        assert_eq!(back, led);
        assert_eq!(back.reuse_findings(), led.reuse_findings());
        let policy = RotationPolicy {
            max_age_ms: 25,
            max_uses: 0,
        };
        assert_eq!(back.rotation_due(&policy, 40), led.rotation_due(&policy, 40));
        // BTreeMap grouping: the encoding is canonical.
        assert_eq!(serde_json::to_string(&back).unwrap(), json);
    }

    #[test]
    fn serde_round_trip_individual_types() {
        let u = ku("k1", "ctx-a", 10, "sign", "fpA");
        let round: KeyUse = serde_json::from_str(&serde_json::to_string(&u).unwrap()).unwrap();
        assert_eq!(round, u);

        let p = RotationPolicy {
            max_age_ms: 60_000,
            max_uses: 100,
        };
        let round: RotationPolicy =
            serde_json::from_str(&serde_json::to_string(&p).unwrap()).unwrap();
        assert_eq!(round, p);

        let f = ReuseFinding {
            key_id: "k1".to_string(),
            contexts: vec!["a".to_string(), "b".to_string()],
            count: 2,
        };
        let round: ReuseFinding =
            serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(round, f);

        let e = KeyError::ReuseDetected {
            key_id: "k1".to_string(),
            first_context: "a".to_string(),
            new_context: "b".to_string(),
        };
        let round: KeyError = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(round, e);

        let e = KeyError::EmptyField("key_id".to_string());
        let round: KeyError = serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(round, e);
    }

    #[test]
    fn serialization_is_canonical_regardless_of_insertion_order() {
        let mut a = KeyUseLedger::new();
        a.record_key_use(ku("k2", "ctx-b", 1, "sign", "fpB")).unwrap();
        a.record_key_use(ku("k1", "ctx-a", 1, "sign", "fpA")).unwrap();
        let mut b = KeyUseLedger::new();
        b.record_key_use(ku("k1", "ctx-a", 1, "sign", "fpA")).unwrap();
        b.record_key_use(ku("k2", "ctx-b", 1, "sign", "fpB")).unwrap();
        assert_eq!(a, b);
        assert_eq!(serde_json::to_string(&a).unwrap(), serde_json::to_string(&b).unwrap());
    }

    // --- error surface -----------------------------------------------------

    #[test]
    fn error_display_is_informative() {
        let e = KeyError::ReuseDetected {
            key_id: "k1".to_string(),
            first_context: "a".to_string(),
            new_context: "b".to_string(),
        };
        let msg = e.to_string();
        assert!(msg.contains("k1") && msg.contains("\"a\"") && msg.contains("\"b\""));
        let msg = KeyError::EmptyField("context".to_string()).to_string();
        assert!(msg.contains("context"));
        let _: &dyn std::error::Error = &e; // Error impl is present
    }
}
