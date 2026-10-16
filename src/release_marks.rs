//! Release marks on findings (task B1.4.1: release-mark model on findings).
//!
//! [`crate::caveats`] (A2.2.3) answers *under which caveat codes* material may
//! travel and renders the canonical marking tokens (`NO-THIRD-PARTY`, `ORCON`,
//! `REL-<role>`). This module answers a third, per-finding question: *is this
//! specific finding releasable at all, and to whom*. A [`ReleaseMark`] attached
//! to a [`Finding`] carries a [`Releasability`] level, the named audiences the
//! finding is releasable to, and the caveat codes that travel with it.
//!
//! # Releasability ladder (tightest-highest)
//! `Open (0) < NeedToShare (1) < Restricted (2) < Sealed (3)` — [`Releasability::rank`]
//! returns exactly those values, so "tighter" is "higher rank". An **unmarked**
//! finding is treated as tighter than any mark: deny-by-default means nothing
//! releases until a mark says so ([`check_release`] → [`MarkError::Unmarked`]).
//!
//! # No-downgrade rule (frozen)
//! [`apply_marks`] is the *only* way a mark should be attached or changed, and
//! it **only ever tightens**: applying a mark whose rank is lower than the
//! existing mark's rank is refused with [`MarkError::Downgrade`] and the
//! finding is left untouched. Same-rank (lateral refresh) and higher-rank
//! (tightening) applications succeed and replace the mark. On any `Err`,
//! nothing about the finding changes.
//!
//! # Mark shape
//! `releasable_to` and `caveats` are normalised on apply: entries are trimmed,
//! empty entries dropped, then sorted and deduped — so two marks built from
//! the same set in different orders are identical (deterministic for any input
//! ordering). `NeedToShare` and `Restricted` marks must name at least one
//! audience (after normalisation) → otherwise [`MarkError::EmptyAudience`].
//! The applied mark's `marked_ms` is stamped from the caller's `now_ms` (the
//! time of application; any timestamp carried on the incoming mark is
//! ignored). Caveat strings are carried verbatim (trimmed) using the canonical
//! vocabulary of [`crate::caveats`] (`NO-THIRD-PARTY`, `ORCON`, `REL-<role>`) —
//! this module does not compile against `caveats`, it only shares its tokens;
//! spell caveats with [`crate::caveats::Caveat::code`] before marking.
//!
//! # Release check (pure, deny-by-default)
//! [`check_release`] is the pre-release gate for one audience:
//!
//! - unmarked → [`MarkError::Unmarked`] (never releases);
//! - [`Releasability::Open`] → `Ok` for every audience (the mark carries no
//!   audience restriction);
//! - [`Releasability::NeedToShare`] → the audience (trimmed, compared exactly
//!   against the trimmed stored entries) must be named in `releasable_to`; an
//!   empty/whitespace-only audience is refused as [`MarkError::EmptyAudience`]
//!   and a named-but-unlisted audience as [`MarkError::Restricted`];
//! - [`Releasability::Restricted`] and [`Releasability::Sealed`] → every
//!   audience is refused with [`MarkError::Restricted`] (frozen interface:
//!   these levels have no release path through this gate; unsealing/handling
//!   is a separate, logged flow).
//!
//! # Scope / integration
//! Pure functions: no I/O, no clock (callers stamp `now_ms`), no globals.
//! Declared in `lib.rs`; consumed by the release/export pipeline once the R1
//! export wiring lands (2026-09-28 wave) — after [`crate::access_class`] and
//! [`crate::caveats`] admit the material — and by audit logging ([`MarkError`]
//! is serde-round-trippable so refusals can be written to the ledger with a
//! stable variant name.

use std::fmt;

use serde::{Deserialize, Serialize};

// ── Releasability ladder ─────────────────────────────────────────────────────

/// How far a finding may travel; ordering is **tightest-highest**
/// (`Open < NeedToShare < Restricted < Sealed`), identical to the values
/// returned by [`Releasability::rank`].
///
/// Serde wire form is snake_case (`"open"`, `"need_to_share"`, `"restricted"`,
/// `"sealed"`) — stable for manifests and ledger records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Releasability {
    /// Publishable: the mark itself imposes no audience restriction.
    Open,
    /// Shareable with the named audiences only (`releasable_to` must name at
    /// least one after normalisation).
    NeedToShare,
    /// Held to the originator/operation: no release through this gate, but the
    /// scoping audiences must still be named (`releasable_to` non-empty).
    Restricted,
    /// Closed: no release path at all through [`check_release`].
    Sealed,
}

impl Releasability {
    /// Every level, tightest last (rank-ascending order).
    pub const ALL: [Releasability; 4] = [
        Releasability::Open,
        Releasability::NeedToShare,
        Releasability::Restricted,
        Releasability::Sealed,
    ];

    /// Tightness rank, `0..=3` with tightest highest: `Open = 0`,
    /// `NeedToShare = 1`, `Restricted = 2`, `Sealed = 3`. Loosening a mark
    /// means applying a candidate whose rank is lower than the existing
    /// mark's — exactly what the no-downgrade rule refuses.
    pub fn rank(self) -> u8 {
        match self {
            Releasability::Open => 0,
            Releasability::NeedToShare => 1,
            Releasability::Restricted => 2,
            Releasability::Sealed => 3,
        }
    }
}

// ── Mark + finding ───────────────────────────────────────────────────────────

/// A release mark attached to a [`Finding`]: the releasability level, the
/// named audiences, the caveat codes that travel with it, and when it was
/// applied. Treat all fields as read-only metadata; mutate through
/// [`apply_marks`] so the no-downgrade and normalisation rules hold.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleaseMark {
    /// How far the finding may travel (tightest-highest).
    pub level: Releasability,
    /// Named audiences this finding is releasable to, normalised by
    /// [`apply_marks`] (trimmed, empties dropped, sorted, deduped). Must be
    /// non-empty for `NeedToShare`/`Restricted` marks.
    pub releasable_to: Vec<String>,
    /// Caveat codes accompanying the finding — canonical `crate::caveats`
    /// vocabulary (`NO-THIRD-PARTY`, `ORCON`, `REL-<role>`), normalised like
    /// `releasable_to` (trimmed, empties dropped, sorted, deduped).
    pub caveats: Vec<String>,
    /// When the mark was applied, stamped from the caller's `now_ms`.
    pub marked_ms: i64,
}

/// A finding of an investigation, with an optional release mark.
///
/// `mark: None` means **unmarked** — an unmarked finding is never releasable
/// (`check_release` → [`MarkError::Unmarked`]); marking is a deliberate,
/// logged act ([`apply_marks`]).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Finding {
    /// Stable finding id.
    pub id: String,
    /// The finding text.
    pub body: String,
    /// The release mark, if any. A missing field deserialises to `None`.
    #[serde(default)]
    pub mark: Option<ReleaseMark>,
}

// ── Refusals (audit) ─────────────────────────────────────────────────────────

/// Why a mark application or a release check was refused.
///
/// Serde-round-trippable for ledger payloads (wire form is the variant name);
/// `Display` renders a human audit line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MarkError {
    /// [`check_release`] on an unmarked finding: nothing releases without a
    /// mark (deny-by-default).
    Unmarked,
    /// [`apply_marks`] tried to loosen an existing mark: the no-downgrade
    /// rule forbids replacing a tighter-or-equal mark with a looser one. The
    /// finding was left untouched.
    Downgrade,
    /// No audience named: a `NeedToShare`/`Restricted` mark was applied with
    /// an empty `releasable_to` (after normalisation), or a release was
    /// checked for an empty/whitespace-only audience.
    EmptyAudience,
    /// The level/audience pair is not releasable through this gate:
    /// a `NeedToShare` audience not named in `releasable_to`, or any audience
    /// for `Restricted`/`Sealed`.
    Restricted,
}

impl fmt::Display for MarkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MarkError::Unmarked => {
                f.write_str("release refused: the finding carries no release mark")
            }
            MarkError::Downgrade => f.write_str(
                "mark refused: no-downgrade rule forbids loosening a tighter-or-equal mark",
            ),
            MarkError::EmptyAudience => {
                f.write_str("mark refused: no audience named (empty releasable_to)")
            }
            MarkError::Restricted => {
                f.write_str("release refused: the finding is not releasable to this audience")
            }
        }
    }
}

impl std::error::Error for MarkError {}

// ── Normalisation (private) ──────────────────────────────────────────────────

/// Trim entries, drop empties, sort, dedupe — deterministic for any input
/// order. Applied by [`apply_marks`] to both `releasable_to` and `caveats`.
fn normalize(items: &[String]) -> Vec<String> {
    let mut out: Vec<String> = items
        .iter()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    out.sort();
    out.dedup();
    out
}

// ── Apply (no-downgrade) ─────────────────────────────────────────────────────

/// Attach or tighten `f`'s release mark.
///
/// Rules, in evaluation order (frozen):
///
/// 1. **Shape first** — `releasable_to` and `caveats` are normalised (trimmed,
///    empties dropped, sorted, deduped). A `NeedToShare` or `Restricted` mark
///    whose normalised `releasable_to` is empty is refused with
///    [`MarkError::EmptyAudience`].
/// 2. **No-downgrade** — if `f` is already marked and `mark.level.rank() <
///    existing.level.rank()`, the application is refused with
///    [`MarkError::Downgrade`]. Same-rank (lateral refresh) and higher-rank
///    (tightening) applications are allowed.
/// 3. The candidate's `marked_ms` is stamped from `now_ms` and the mark
///    replaces any existing one.
///
/// On any `Err` the finding is not modified. `Open`/`Sealed` tolerate an empty
/// `releasable_to` (it carries no audience restriction / admits nobody).
pub fn apply_marks(f: &mut Finding, mark: ReleaseMark, now_ms: i64) -> Result<(), MarkError> {
    let mut candidate = mark;
    candidate.releasable_to = normalize(&candidate.releasable_to);
    candidate.caveats = normalize(&candidate.caveats);

    // 1. Shape: NeedToShare/Restricted must name at least one audience.
    if matches!(
        candidate.level,
        Releasability::NeedToShare | Releasability::Restricted
    ) && candidate.releasable_to.is_empty()
    {
        return Err(MarkError::EmptyAudience);
    }

    // 2. No-downgrade: a looser mark may never replace a tighter-or-equal one.
    if let Some(existing) = &f.mark {
        if candidate.level.rank() < existing.level.rank() {
            return Err(MarkError::Downgrade);
        }
    }

    // 3. Stamp the application time and commit.
    candidate.marked_ms = now_ms;
    f.mark = Some(candidate);
    Ok(())
}

// ── Release check (pure, deny-by-default) ────────────────────────────────────

/// May `f` be released to `audience`?
///
/// `Ok(())` = the finding's mark admits this audience. `Err` = the first
/// refusal: unmarked → [`MarkError::Unmarked`]; `Open` → always `Ok`;
/// `NeedToShare` → `Ok` iff the trimmed audience is named in `releasable_to`
/// (trimmed, exact), empty/whitespace-only audience →
/// [`MarkError::EmptyAudience`], named-but-unlisted → [`MarkError::Restricted`];
/// `Restricted`/`Sealed` → every audience refused with
/// [`MarkError::Restricted`]. Never panics.
pub fn check_release(f: &Finding, audience: &str) -> Result<(), MarkError> {
    let mark = f.mark.as_ref().ok_or(MarkError::Unmarked)?;

    match mark.level {
        Releasability::Open => Ok(()),
        Releasability::NeedToShare => {
            let audience = audience.trim();
            if audience.is_empty() {
                return Err(MarkError::EmptyAudience);
            }
            if mark.releasable_to.iter().any(|a| a.trim() == audience) {
                Ok(())
            } else {
                Err(MarkError::Restricted)
            }
        }
        Releasability::Restricted | Releasability::Sealed => Err(MarkError::Restricted),
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn finding(id: &str) -> Finding {
        Finding {
            id: id.to_string(),
            body: format!("body of {id}"),
            mark: None,
        }
    }

    fn mark(level: Releasability, to: &[&str], caveats: &[&str], ms: i64) -> ReleaseMark {
        ReleaseMark {
            level,
            releasable_to: to.iter().map(|s| s.to_string()).collect(),
            caveats: caveats.iter().map(|s| s.to_string()).collect(),
            marked_ms: ms,
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    // ── rank ─────────────────────────────────────────────────────────────────

    #[test]
    fn rank_is_tightest_highest_and_all_covers_the_ladder() {
        assert_eq!(Releasability::Open.rank(), 0);
        assert_eq!(Releasability::NeedToShare.rank(), 1);
        assert_eq!(Releasability::Restricted.rank(), 2);
        assert_eq!(Releasability::Sealed.rank(), 3);
        // ALL is exactly the ladder, tightest last; rank ascends across it.
        assert_eq!(Releasability::ALL.len(), 4);
        for pair in Releasability::ALL.windows(2) {
            assert!(pair[0].rank() < pair[1].rank(), "{:?} !< {:?}", pair[0], pair[1]);
        }
        // Derived Ord agrees with rank (declaration order == tightness order).
        for a in Releasability::ALL {
            for b in Releasability::ALL {
                assert_eq!(a < b, a.rank() < b.rank(), "{a:?} vs {b:?}");
            }
        }
    }

    // ── apply / read roundtrip ───────────────────────────────────────────────

    #[test]
    fn apply_then_read_roundtrip() {
        let mut f = finding("f-1");
        let now = 1_700_000_000_000_i64;
        // Deliberately unsorted/duplicated/padded input; input timestamp 999
        // is ignored in favour of now_ms.
        apply_marks(
            &mut f,
            mark(
                Releasability::NeedToShare,
                &["beta", " alpha ", "beta", "", "   "],
                &[" ORCON ", "NO-THIRD-PARTY", "ORCON"],
                999,
            ),
            now,
        )
        .unwrap();

        let stored = f.mark.as_ref().unwrap();
        assert_eq!(stored.level, Releasability::NeedToShare);
        assert_eq!(stored.releasable_to, strings(&["alpha", "beta"]));
        assert_eq!(stored.caveats, strings(&["NO-THIRD-PARTY", "ORCON"]));
        assert_eq!(stored.marked_ms, now, "marked_ms is stamped from now_ms");

        // The stored mark satisfies check_release for its named audiences.
        assert!(check_release(&f, "alpha").is_ok());
        assert!(check_release(&f, "  beta  ").is_ok());
        assert_eq!(check_release(&f, "gamma"), Err(MarkError::Restricted));
    }

    #[test]
    fn apply_replaces_the_whole_mark_not_merges_it() {
        let mut f = finding("f-2");
        apply_marks(
            &mut f,
            mark(Releasability::NeedToShare, &["alpha"], &["ORCON"], 10),
            10,
        )
        .unwrap();
        apply_marks(
            &mut f,
            mark(Releasability::NeedToShare, &["beta"], &["REL-x"], 20),
            20,
        )
        .unwrap();
        let stored = f.mark.unwrap();
        assert_eq!(stored.releasable_to, strings(&["beta"]));
        assert_eq!(stored.caveats, strings(&["REL-x"]));
        assert_eq!(stored.marked_ms, 20);
    }

    // ── no-downgrade / upgrade ───────────────────────────────────────────────

    #[test]
    fn downgrade_matrix_refused_upgrade_matrix_allowed_and_state_untouched() {
        for existing in Releasability::ALL {
            for incoming in Releasability::ALL {
                let mut f = finding("matrix");
                let seed = mark(existing, &["alpha"], &[], 1);
                apply_marks(&mut f, seed.clone(), 1).unwrap();

                let candidate = mark(incoming, &["alpha", "beta"], &["X"], 2);
                let result = apply_marks(&mut f, candidate, 2);

                if incoming.rank() < existing.rank() {
                    assert_eq!(
                        result,
                        Err(MarkError::Downgrade),
                        "loosening {existing:?} -> {incoming:?} must be refused"
                    );
                    assert_eq!(
                        f.mark,
                        Some(seed),
                        "a refused downgrade must leave the finding untouched"
                    );
                } else {
                    assert!(
                        result.is_ok(),
                        "same-or-tighter {existing:?} -> {incoming:?} must be allowed"
                    );
                    let stored = f.mark.unwrap();
                    assert_eq!(stored.level, incoming);
                    assert_eq!(stored.marked_ms, 2);
                    assert_eq!(stored.releasable_to, strings(&["alpha", "beta"]));
                }
            }
        }
    }

    #[test]
    fn refused_downgrade_does_not_consume_the_candidate() {
        let mut f = finding("f-3");
        apply_marks(
            &mut f,
            mark(Releasability::Sealed, &["alpha"], &[], 5),
            5,
        )
        .unwrap();
        let attempt = mark(Releasability::Open, &[], &[], 6);
        assert_eq!(
            apply_marks(&mut f, attempt, 6),
            Err(MarkError::Downgrade)
        );
        assert_eq!(f.mark.as_ref().unwrap().level, Releasability::Sealed);
        assert_eq!(f.mark.as_ref().unwrap().marked_ms, 5, "timestamp unchanged");
        // A valid tightening right after still works.
        apply_marks(&mut f, mark(Releasability::Sealed, &["beta"], &[], 7), 7).unwrap();
        assert_eq!(f.mark.unwrap().releasable_to, strings(&["beta"]));
    }

    // ── audience matrix ──────────────────────────────────────────────────────

    #[test]
    fn check_release_audience_matrix() {
        let audiences = ["", "   ", "alpha", "beta", "stranger"];

        // Unmarked: refused for every audience.
        let unmarked = finding("u");
        for a in audiences {
            assert_eq!(check_release(&unmarked, a), Err(MarkError::Unmarked), "{a:?}");
        }

        // Open: Ok for every audience, even an empty one (the mark carries no
        // audience restriction of its own).
        let mut open = finding("o");
        apply_marks(&mut open, mark(Releasability::Open, &[], &[], 7), 7).unwrap();
        for a in audiences {
            assert!(check_release(&open, a).is_ok(), "open must admit {a:?}");
        }

        // NeedToShare: named audiences (trimmed, exact) only.
        let mut nts = finding("n");
        apply_marks(
            &mut nts,
            mark(Releasability::NeedToShare, &[" alpha ", "beta"], &[], 8),
            8,
        )
        .unwrap();
        assert!(check_release(&nts, "alpha").is_ok());
        assert!(check_release(&nts, "  alpha  ").is_ok());
        assert!(check_release(&nts, "beta").is_ok());
        assert_eq!(check_release(&nts, "stranger"), Err(MarkError::Restricted));
        assert_eq!(check_release(&nts, "alph"), Err(MarkError::Restricted));
        assert_eq!(check_release(&nts, ""), Err(MarkError::EmptyAudience));
        assert_eq!(check_release(&nts, "   "), Err(MarkError::EmptyAudience));

        // Restricted / Sealed: refuse every audience, listed or not.
        for level in [Releasability::Restricted, Releasability::Sealed] {
            let mut f = finding("r");
            apply_marks(&mut f, mark(level, &["alpha"], &[], 9), 9).unwrap();
            for a in audiences {
                assert_eq!(
                    check_release(&f, a),
                    Err(MarkError::Restricted),
                    "{level:?} must refuse {a:?}"
                );
            }
        }

        // A hand-built NeedToShare mark with an empty list (bypassing
        // apply_marks) refuses every named audience as Restricted.
        let hand_built = Finding {
            id: "h".into(),
            body: "b".into(),
            mark: Some(mark(Releasability::NeedToShare, &[], &[], 1)),
        };
        assert_eq!(
            check_release(&hand_built, "alpha"),
            Err(MarkError::Restricted)
        );
        assert_eq!(
            check_release(&hand_built, ""),
            Err(MarkError::EmptyAudience)
        );
    }

    // ── empty-audience errors ────────────────────────────────────────────────

    #[test]
    fn empty_audience_marks_are_refused() {
        let empty_lists: [Vec<&str>; 4] = [vec![], vec![""], vec!["   "], vec!["", "  "]];
        for level in [Releasability::NeedToShare, Releasability::Restricted] {
            for to in &empty_lists {
                let mut f = finding("e");
                let result = apply_marks(&mut f, mark(level, to, &[], 1), 1);
                assert_eq!(
                    result,
                    Err(MarkError::EmptyAudience),
                    "{level:?} with {to:?}"
                );
                assert!(f.mark.is_none(), "a refused apply must not mark the finding");
            }
        }
        // Open and Sealed tolerate an empty audience list.
        for level in [Releasability::Open, Releasability::Sealed] {
            let mut f = finding("ok");
            apply_marks(&mut f, mark(level, &[], &[], 1), 1).unwrap();
            assert_eq!(f.mark.unwrap().level, level);
        }
    }

    // ── normalisation ────────────────────────────────────────────────────────

    #[test]
    fn audiences_and_caveats_are_trimmed_sorted_deduped() {
        let mut f = finding("s");
        apply_marks(
            &mut f,
            mark(
                Releasability::NeedToShare,
                &[" zeta ", "alpha", "alpha", " beta", "gamma "],
                &["ORCON", " NO-THIRD-PARTY ", "ORCON", "REL-x"],
                5,
            ),
            5,
        )
        .unwrap();
        let stored = f.mark.unwrap();
        assert_eq!(
            stored.releasable_to,
            strings(&["alpha", "beta", "gamma", "zeta"])
        );
        assert_eq!(stored.caveats, strings(&["NO-THIRD-PARTY", "ORCON", "REL-x"]));
    }

    #[test]
    fn normalisation_is_order_independent() {
        let orderings: [Vec<&str>; 4] = [
            vec!["beta", "alpha", "gamma"],
            vec!["gamma", "beta", "alpha"],
            vec!["alpha", "gamma", "beta"],
            vec!["beta", "alpha", "gamma", "gamma", "alpha"],
        ];
        let mut first: Option<ReleaseMark> = None;
        for to in &orderings {
            let mut f = finding("det");
            apply_marks(
                &mut f,
                ReleaseMark {
                    level: Releasability::NeedToShare,
                    releasable_to: strings(to),
                    caveats: strings(&to.iter().rev().copied().collect::<Vec<_>>()),
                    marked_ms: 42,
                },
                42,
            )
            .unwrap();
            let stored = f.mark.unwrap();
            match &first {
                None => first = Some(stored),
                Some(prev) => assert_eq!(&stored, prev, "order {to:?} must normalise identically"),
            }
        }
    }

    // ── unmarked ─────────────────────────────────────────────────────────────

    #[test]
    fn unmarked_finding_is_refused_until_marked() {
        let mut f = finding("u2");
        for a in ["alpha", "", "public"] {
            assert_eq!(check_release(&f, a), Err(MarkError::Unmarked));
        }
        apply_marks(&mut f, mark(Releasability::Open, &[], &[], 3), 3).unwrap();
        assert!(check_release(&f, "alpha").is_ok());
        assert!(check_release(&f, "").is_ok());
    }

    // ── serde ────────────────────────────────────────────────────────────────

    #[test]
    fn serde_wire_tokens_and_round_trips() {
        // Releasability: snake_case, pinned.
        assert_eq!(serde_json::to_string(&Releasability::Open).unwrap(), "\"open\"");
        assert_eq!(
            serde_json::to_string(&Releasability::NeedToShare).unwrap(),
            "\"need_to_share\""
        );
        assert_eq!(
            serde_json::to_string(&Releasability::Restricted).unwrap(),
            "\"restricted\""
        );
        assert_eq!(
            serde_json::to_string(&Releasability::Sealed).unwrap(),
            "\"sealed\""
        );
        for level in Releasability::ALL {
            let json = serde_json::to_string(&level).unwrap();
            let back: Releasability = serde_json::from_str(&json).unwrap();
            assert_eq!(back, level);
        }

        // ReleaseMark round trip, field names pinned.
        let m = ReleaseMark {
            level: Releasability::NeedToShare,
            releasable_to: strings(&["alpha", "beta"]),
            caveats: strings(&["ORCON"]),
            marked_ms: 12_345,
        };
        let value = serde_json::json!({
            "level": "need_to_share",
            "releasable_to": ["alpha", "beta"],
            "caveats": ["ORCON"],
            "marked_ms": 12345,
        });
        assert_eq!(serde_json::to_value(&m).unwrap(), value);
        let back: ReleaseMark = serde_json::from_value(value).unwrap();
        assert_eq!(back, m);

        // Finding round trip; missing/null mark deserialises to None.
        let with_mark = Finding {
            id: "f-9".into(),
            body: "b".into(),
            mark: Some(m.clone()),
        };
        let back: Finding = serde_json::from_str(&serde_json::to_string(&with_mark).unwrap()).unwrap();
        assert_eq!(back, with_mark);
        let bare: Finding =
            serde_json::from_value(serde_json::json!({"id": "f-0", "body": "b"})).unwrap();
        assert!(bare.mark.is_none());
        let nulled: Finding =
            serde_json::from_value(serde_json::json!({"id": "f-0", "body": "b", "mark": null}))
                .unwrap();
        assert!(nulled.mark.is_none());

        // MarkError round trips on the variant name (stable for the ledger).
        for e in [
            MarkError::Unmarked,
            MarkError::Downgrade,
            MarkError::EmptyAudience,
            MarkError::Restricted,
        ] {
            let json = serde_json::to_string(&e).unwrap();
            let back: MarkError = serde_json::from_str(&json).unwrap();
            assert_eq!(back, e);
        }
        assert_eq!(
            serde_json::to_string(&MarkError::Downgrade).unwrap(),
            "\"Downgrade\""
        );
    }

    // ── errors: display + audit usability ────────────────────────────────────

    #[test]
    fn errors_display_and_box_as_std_error() {
        let cases = [
            (MarkError::Unmarked, "no release mark"),
            (MarkError::Downgrade, "no-downgrade"),
            (MarkError::EmptyAudience, "no audience"),
            (MarkError::Restricted, "not releasable"),
        ];
        for (err, needle) in cases {
            let line = err.to_string();
            assert!(line.contains(needle), "{err:?} display: {line}");
            let boxed: Box<dyn std::error::Error> = Box::new(err);
            assert!(!boxed.to_string().is_empty());
        }
    }

    // ── determinism ──────────────────────────────────────────────────────────

    #[test]
    fn full_ladder_check_matrix_is_deterministic() {
        let building_blocks: [Vec<ReleaseMark>; 4] = [
            vec![mark(Releasability::Open, &[], &[], 1)],
            vec![
                mark(Releasability::NeedToShare, &["alpha"], &[], 1),
                mark(Releasability::NeedToShare, &["alpha", "beta"], &["ORCON"], 2),
            ],
            vec![mark(Releasability::Restricted, &["alpha"], &[], 1)],
            vec![mark(Releasability::Sealed, &[], &[], 1)],
        ];
        let audiences = ["", "alpha", "beta", "stranger"];
        let mut first_answers: Option<Vec<bool>> = None;
        for _ in 0..16 {
            let mut answers = Vec::new();
            for seeds in &building_blocks {
                for seed in seeds {
                    let mut f = finding("det");
                    if apply_marks(&mut f, seed.clone(), seed.marked_ms).is_ok() {
                        for a in audiences {
                            answers.push(check_release(&f, a).is_ok());
                        }
                    }
                }
            }
            match &first_answers {
                None => first_answers = Some(answers),
                Some(prev) => assert_eq!(&answers, prev, "release answers must be deterministic"),
            }
        }
    }

    #[test]
    fn apply_is_deterministic_for_identical_inputs() {
        let inputs = [
            mark(Releasability::NeedToShare, &["b", "a", "a"], &["Y", "X"], 3),
            mark(Releasability::NeedToShare, &["a", "b"], &["X", "Y"], 3),
        ];
        for _ in 0..16 {
            let mut a = finding("d1");
            let mut b = finding("d2");
            apply_marks(&mut a, inputs[0].clone(), 9).unwrap();
            apply_marks(&mut b, inputs[1].clone(), 9).unwrap();
            assert_eq!(a.mark, b.mark);
            assert!(check_release(&a, "a").is_ok());
            assert!(check_release(&b, "a").is_ok());
        }
    }
}
