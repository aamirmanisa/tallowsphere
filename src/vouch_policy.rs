//! N-voucher grant policy + revocation + audit view (tasks B1.2.2 / B1.2.3,
//! frozen interface §8). Layers a *decision* over [`crate::vouching`]'s pure
//! edge model: edges say who vouched; policy says whether that is enough, and
//! whether a revocation has since withdrawn the standing.
//!
//! # Documented rules (spec silent where noted; conservative reading)
//!
//! * **Precedence**: a revocation naming the subject overrides *everything* —
//!   including a vacuous `required == 0` grant. Revocation is a withdrawal of
//!   standing, not another input to the count.
//! * **Latest wins**: when several revocations name the same subject, the one
//!   with the greatest `at_ms` decides. Ties (identical `at_ms`) are broken by
//!   slice order — the **later** record wins — so replaying an append-only log
//!   in the order it was written is the only ordering needed; verdicts do not
//!   depend on anything outside the inputs.
//! * **Vacuous threshold**: `required == 0` grants every subject, *including
//!   unknown ones*, with `vouchers` equal to the (possibly empty) distinct
//!   voucher list. This inherits [`crate::vouching::meets_threshold`]'s
//!   documented vacuous-truth semantics; argued here because "granted with no
//!   endorsements" is surprising on first read — needing zero endorsements is
//!   no requirement at all.
//! * **Granted voucher list**: sorted, deduplicated (via
//!   [`crate::vouching::VouchGraph::vouchers_of`], which already guarantees
//!   this), so the status is independent of insertion order — determinism is a
//!   security property here as in `vouching`.
//! * **`revoke` is an append-only log**: it always pushes; re-revoking an
//!   already-revoked subject is allowed (later entries simply win), and the
//!   log is never rewritten or pruned. Empty (`trim`-blank) `subject` / `by`
//!   are refused with [`VouchPolicyError::EmptyField`], `subject` checked
//!   before `by` (mirrors `vouching`'s field-check order). Stored strings are
//!   kept **exactly as passed**.
//! * **Audit view** (B1.2.3): one row per *distinct* subject, sorted
//!   ascending; caller-supplied duplicates collapse (an audit lists subjects
//!   under policy, not call multiplicity). Empty input yields an empty view.
//! * `GrantPolicy` is deliberately **not** `serde` — §8 annotates only
//!   [`GrantStatus`] and [`Revocation`]; the policy is runtime configuration.
//!
//! [`VouchPolicyError`] derives `Serialize` but not `Deserialize` — the
//! `&'static str` payload cannot be deserialized into a `'static` lifetime.
//! This mirrors the in-repo precedent (`vouching::VouchError` and siblings
//! `gap_register` / `link_chain` / `decoy_flags` / `requirements`).

use crate::vouching::{meets_threshold, VouchGraph};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

/// How many distinct vouchers a subject needs for a grant.
///
/// Checked at query time, never stored on the graph; `required == 0` is
/// vacuous (see module docs).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantPolicy {
    /// Minimum number of distinct vouchers for [`GrantStatus::Granted`].
    pub required: usize,
}

/// Verdict for one subject under a [`GrantPolicy`], given the vouching graph
/// and the revocation log.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum GrantStatus {
    /// Threshold met and not revoked. `vouchers` is the sorted, deduplicated
    /// list of distinct put vouchers (empty for a vacuous `required == 0`
    /// grant).
    Granted { vouchers: Vec<String> },
    /// Threshold not met and not revoked: `have` distinct vouchers so far,
    /// `need` = policy `required` (so `need > have` always holds here).
    Pending { have: usize, need: usize },
    /// Withdrawn by `by` at `at_ms` (latest matching revocation, see module
    /// docs). Overrides any count.
    Revoked { by: String, at_ms: i64 },
}

/// One revocation record: `by` withdraws standing for `subject` at `at_ms`
/// (caller clock, stored unchanged; this module never reads the clock).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Revocation {
    /// The subject whose standing is withdrawn.
    pub subject: String,
    /// The revoking party.
    pub by: String,
    /// Caller-supplied timestamp (ms); never rewritten.
    pub at_ms: i64,
}

/// Errors refusing a revocation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum VouchPolicyError {
    /// A required field was empty after trimming; carries the field name.
    EmptyField(&'static str),
}

impl fmt::Display for VouchPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VouchPolicyError::EmptyField(field) => {
                write!(f, "empty required field: {field}")
            }
        }
    }
}

impl std::error::Error for VouchPolicyError {}

/// Verdict for `subject`: latest revocation for the subject (if any) decides
/// [`GrantStatus::Revoked`]; otherwise the distinct-voucher count is compared
/// with `policy.required` → [`GrantStatus::Granted`] / [`GrantStatus::Pending`].
///
/// Pure function of its inputs; see the module docs for revocation precedence,
/// the vacuous `required == 0` rule, and the equal-`at_ms` tie-break.
pub fn grant_status(
    g: &VouchGraph,
    policy: &GrantPolicy,
    subject: &str,
    revocations: &[Revocation],
) -> GrantStatus {
    // Latest matching revocation; among equal `at_ms`, the later slice entry
    // wins (it replaces `latest` too, since `cur.at_ms > r.at_ms` is strict).
    let mut latest: Option<&Revocation> = None;
    for r in revocations.iter().filter(|r| r.subject == subject) {
        match latest {
            Some(cur) if cur.at_ms > r.at_ms => {}
            _ => latest = Some(r),
        }
    }
    if let Some(rev) = latest {
        return GrantStatus::Revoked {
            by: rev.by.clone(),
            at_ms: rev.at_ms,
        };
    }

    let vouchers: Vec<String> = g
        .vouchers_of(subject)
        .into_iter()
        .map(str::to_string)
        .collect();
    if meets_threshold(g, subject, policy.required) {
        GrantStatus::Granted { vouchers }
    } else {
        GrantStatus::Pending {
            have: vouchers.len(),
            need: policy.required,
        }
    }
}

/// Append a revocation of `subject` by `by` at `at_ms` (stored unchanged).
///
/// Blank `subject` / `by` (after trimming) → [`VouchPolicyError::EmptyField`];
/// `subject` is checked before `by`. The log is append-only: this function
/// never merges or edits existing entries — re-revocation is legal and the
/// later entry wins at query time.
pub fn revoke(
    revocations: &mut Vec<Revocation>,
    subject: &str,
    by: &str,
    at_ms: i64,
) -> Result<(), VouchPolicyError> {
    if subject.trim().is_empty() {
        return Err(VouchPolicyError::EmptyField("subject"));
    }
    if by.trim().is_empty() {
        return Err(VouchPolicyError::EmptyField("by"));
    }
    revocations.push(Revocation {
        subject: subject.to_string(),
        by: by.to_string(),
        at_ms,
    });
    Ok(())
}

/// B1.2.3 audit view: status of every distinct subject in `subjects`, sorted
/// ascending by subject, one row per subject (input duplicates collapse).
///
/// Sorted by `String`'s natural (`Ord`) order. Pure function; deterministic
/// across runs for equal inputs.
pub fn audit_view(
    g: &VouchGraph,
    subjects: &[String],
    policy: &GrantPolicy,
    revocations: &[Revocation],
) -> Vec<(String, GrantStatus)> {
    subjects
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .map(|s| {
            let status = grant_status(g, policy, &s, revocations);
            (s, status)
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vouching::VouchGraph;

    /// alice, bob, carol all vouch for `claim-1`.
    fn sample_graph() -> VouchGraph {
        let mut g = VouchGraph::new();
        g.add("alice", "claim-1", 10).unwrap();
        g.add("bob", "claim-1", 20).unwrap();
        g.add("carol", "claim-1", 30).unwrap();
        g
    }

    fn names(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn grant_matrix_zero_one_required_more() {
        let g = sample_graph();

        // 0 vouchers: unknown subject pends.
        assert_eq!(
            grant_status(&g, &GrantPolicy { required: 2 }, "unknown", &[]),
            GrantStatus::Pending { have: 0, need: 2 }
        );

        // 1 voucher: still pending below a 2-voucher policy.
        let mut one = VouchGraph::new();
        one.add("alice", "s", 1).unwrap();
        assert_eq!(
            grant_status(&one, &GrantPolicy { required: 2 }, "s", &[]),
            GrantStatus::Pending { have: 1, need: 2 }
        );

        // N >= required: granted, voucher list exact (sorted distinct).
        assert_eq!(
            grant_status(&g, &GrantPolicy { required: 2 }, "claim-1", &[]),
            GrantStatus::Granted {
                vouchers: names(&["alice", "bob", "carol"])
            }
        );
        assert_eq!(
            grant_status(&g, &GrantPolicy { required: 3 }, "claim-1", &[]),
            GrantStatus::Granted {
                vouchers: names(&["alice", "bob", "carol"])
            }
        );
        // N < required: pending with exact counts.
        assert_eq!(
            grant_status(&g, &GrantPolicy { required: 4 }, "claim-1", &[]),
            GrantStatus::Pending { have: 3, need: 4 }
        );
    }

    #[test]
    fn granted_vouchers_sorted_distinct_regardless_of_insertion() {
        let mut g = VouchGraph::new();
        g.add("carol", "s", 1).unwrap();
        g.add("alice", "s", 2).unwrap();
        g.add("bob", "s", 3).unwrap();
        assert_eq!(
            grant_status(&g, &GrantPolicy { required: 2 }, "s", &[]),
            GrantStatus::Granted {
                vouchers: names(&["alice", "bob", "carol"])
            }
        );
    }

    #[test]
    fn revocation_overrides_granted() {
        let g = sample_graph(); // 3 vouchers — would be Granted at required 1
        let revs = vec![Revocation {
            subject: "claim-1".into(),
            by: "auditor".into(),
            at_ms: 100,
        }];
        assert_eq!(
            grant_status(&g, &GrantPolicy { required: 1 }, "claim-1", &revs),
            GrantStatus::Revoked {
                by: "auditor".into(),
                at_ms: 100
            }
        );
    }

    #[test]
    fn latest_revocation_wins_and_others_untouched() {
        let g = sample_graph();
        let revs = vec![
            Revocation {
                subject: "claim-1".into(),
                by: "first".into(),
                at_ms: 10,
            },
            Revocation {
                subject: "claim-1".into(),
                by: "second".into(),
                at_ms: 20,
            },
            Revocation {
                subject: "claim-1".into(),
                by: "earliest".into(),
                at_ms: 5,
            },
        ];
        assert_eq!(
            grant_status(&g, &GrantPolicy { required: 1 }, "claim-1", &revs),
            GrantStatus::Revoked {
                by: "second".into(),
                at_ms: 20
            }
        );
        // A revocation of a different subject does not leak across.
        let other = vec![Revocation {
            subject: "unrelated".into(),
            by: "mod".into(),
            at_ms: 999,
        }];
        assert_eq!(
            grant_status(&g, &GrantPolicy { required: 1 }, "claim-1", &other),
            GrantStatus::Granted {
                vouchers: names(&["alice", "bob", "carol"])
            }
        );
    }

    #[test]
    fn revocation_tie_later_slice_entry_wins() {
        let revs = vec![
            Revocation {
                subject: "s".into(),
                by: "a".into(),
                at_ms: 7,
            },
            Revocation {
                subject: "s".into(),
                by: "b".into(),
                at_ms: 7,
            },
        ];
        assert_eq!(
            grant_status(&VouchGraph::new(), &GrantPolicy { required: 0 }, "s", &revs),
            GrantStatus::Revoked {
                by: "b".into(),
                at_ms: 7
            }
        );
    }

    #[test]
    fn zero_required_policy_is_vacuous_but_revocation_still_wins() {
        let g = VouchGraph::new();
        // Vacuous truth: unknown subject granted, empty voucher list.
        assert_eq!(
            grant_status(&g, &GrantPolicy { required: 0 }, "nobody", &[]),
            GrantStatus::Granted { vouchers: vec![] }
        );
        let revs = vec![Revocation {
            subject: "nobody".into(),
            by: "mod".into(),
            at_ms: 1,
        }];
        assert_eq!(
            grant_status(&g, &GrantPolicy { required: 0 }, "nobody", &revs),
            GrantStatus::Revoked {
                by: "mod".into(),
                at_ms: 1
            }
        );
    }

    #[test]
    fn revoke_appends_log_and_validates_fields() {
        let mut revs: Vec<Revocation> = Vec::new();
        revoke(&mut revs, "s", "mod", 1).unwrap();
        // Re-revocation is legal: append-only, later wins at query time.
        revoke(&mut revs, "s", "mod2", 2).unwrap();
        assert_eq!(revs.len(), 2);
        assert_eq!(revs[0].by, "mod");
        assert_eq!(revs[1].by, "mod2");
        assert_eq!(revs[0].at_ms, 1);

        // Blank fields refused; subject checked before by.
        assert_eq!(
            revoke(&mut revs, "", "mod", 3),
            Err(VouchPolicyError::EmptyField("subject"))
        );
        assert_eq!(
            revoke(&mut revs, "   ", "mod", 3),
            Err(VouchPolicyError::EmptyField("subject"))
        );
        assert_eq!(
            revoke(&mut revs, "s", "", 3),
            Err(VouchPolicyError::EmptyField("by"))
        );
        assert_eq!(
            revoke(&mut revs, "s", "\t", 3),
            Err(VouchPolicyError::EmptyField("by"))
        );
        assert_eq!(
            revoke(&mut revs, "", "", 3),
            Err(VouchPolicyError::EmptyField("subject"))
        );
        assert_eq!(revs.len(), 2, "refused revocations must not be logged");
    }

    #[test]
    fn audit_view_sorted_complete_and_deduped() {
        let g = sample_graph();
        let subjects = vec![
            "zeta".to_string(),
            "claim-1".to_string(),
            "alpha".to_string(),
            "claim-1".to_string(), // duplicate collapses
        ];
        let revs = vec![Revocation {
            subject: "zeta".into(),
            by: "mod".into(),
            at_ms: 9,
        }];
        let rows = audit_view(&g, &subjects, &GrantPolicy { required: 3 }, &revs);
        assert_eq!(rows.len(), 3, "one row per distinct subject");
        assert_eq!(
            rows.iter().map(|(s, _)| s.as_str()).collect::<Vec<_>>(),
            vec!["alpha", "claim-1", "zeta"]
        );
        assert_eq!(rows[0].1, GrantStatus::Pending { have: 0, need: 3 });
        assert_eq!(
            rows[1].1,
            GrantStatus::Granted {
                vouchers: names(&["alice", "bob", "carol"])
            }
        );
        assert_eq!(
            rows[2].1,
            GrantStatus::Revoked {
                by: "mod".into(),
                at_ms: 9
            }
        );
        // Empty input: empty view, no panic.
        assert!(audit_view(&g, &[], &GrantPolicy { required: 1 }, &[]).is_empty());
    }

    #[test]
    fn serde_shapes_and_roundtrips() {
        let granted = GrantStatus::Granted {
            vouchers: names(&["a", "b"]),
        };
        assert_eq!(
            serde_json::to_string(&granted).unwrap(),
            r#"{"Granted":{"vouchers":["a","b"]}}"#
        );
        let pending = GrantStatus::Pending { have: 1, need: 2 };
        assert_eq!(
            serde_json::to_string(&pending).unwrap(),
            r#"{"Pending":{"have":1,"need":2}}"#
        );
        let revoked = GrantStatus::Revoked {
            by: "mod".into(),
            at_ms: 42,
        };
        assert_eq!(
            serde_json::to_string(&revoked).unwrap(),
            r#"{"Revoked":{"by":"mod","at_ms":42}}"#
        );
        for st in [granted, pending, revoked.clone()] {
            let j = serde_json::to_string(&st).unwrap();
            let back: GrantStatus = serde_json::from_str(&j).unwrap();
            assert_eq!(st, back);
        }

        let rev = Revocation {
            subject: "s".into(),
            by: "mod".into(),
            at_ms: 7,
        };
        let j = serde_json::to_string(&rev).unwrap();
        assert_eq!(serde_json::from_str::<Revocation>(&j).unwrap(), rev);

        // Serialize-only error (mirrors `vouching::VouchError`).
        assert_eq!(
            serde_json::to_string(&VouchPolicyError::EmptyField("by")).unwrap(),
            r#"{"EmptyField":"by"}"#
        );
    }

    #[test]
    fn error_display() {
        assert_eq!(
            VouchPolicyError::EmptyField("subject").to_string(),
            "empty required field: subject"
        );
        assert_eq!(
            VouchPolicyError::EmptyField("by").to_string(),
            "empty required field: by"
        );
    }

    #[test]
    fn determinism_repeated_calls_identical() {
        let g = sample_graph();
        let policy = GrantPolicy { required: 2 };
        let revs = vec![Revocation {
            subject: "claim-1".into(),
            by: "mod".into(),
            at_ms: 1,
        }];
        let subjects = vec!["claim-1".to_string(), "beta".to_string()];
        for _ in 0..5 {
            assert_eq!(
                grant_status(&g, &policy, "claim-1", &revs),
                grant_status(&g, &policy, "claim-1", &revs)
            );
            assert_eq!(
                audit_view(&g, &subjects, &policy, &revs),
                audit_view(&g, &subjects, &policy, &revs)
            );
        }
    }
}
