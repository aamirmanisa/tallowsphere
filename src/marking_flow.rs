//! Graded-findings release flow (tasks B1.4.2 + B1.4.3).
//!
//! [`crate::source_registry`] grades a SOURCE (`A`–`F`, Admiralty reliability);
//! [`crate::release_marks`] answers *whether* one finding may travel and to
//! whom. This module joins the two into a single, deliberate flow for one
//! graded finding:
//!
//! 1. [`default_level`] maps the source grade onto a **default posture** —
//!    the documented policy table (`A`/`B` ⇒ [`Releasability::Open`],
//!    `C` ⇒ [`Releasability::NeedToShare`], `D`/`E` ⇒
//!    [`Releasability::Restricted`], `F` ⇒ [`Releasability::Sealed`]) — so an
//!    un-graded release decision can never be made by omission.
//! 2. [`build_mark`] turns a level + audiences + caveats into a normalised
//!    [`ReleaseMark`] (trimmed, empties dropped, sorted, deduped — identical
//!    semantics to `release_marks`' private normaliser).
//! 3. [`apply_flow`] attaches that default-posture mark through
//!    [`crate::release_marks::apply_marks`], so the module's **no-downgrade**
//!    rule holds end to end: a tighter mark already on the finding (an
//!    explicit operator decision) always wins over the posture default, and a
//!    refused application leaves the finding untouched.
//! 4. [`enforce_share`] is the pre-release gate for one audience:
//!    **raw identity material is blocked first, unconditionally**, and only
//!    then is the mark consulted ([`crate::release_marks::check_release`]).
//!    [`share_batch`] runs that gate over a batch and aborts on the first
//!    denial.
//! 5. [`enforce_share_reviewed`] (B2.1.2 adoption) makes a **cleared
//!    clearness review a required step for high-risk releases**: at or above
//!    a caller-set [`Releasability`] floor, the audience gate runs only
//!    after [`crate::clearness_gate::ClearnessSession::can_disseminate`]
//!    passes (identity block still first, unconditionally).
//!
//! # Raw identity material NEVER leaves (B1.4.3)
//! A [`GradedFinding`] may carry an `identity_ref` — a reference to raw
//! identity material (a name, handle, account id, …). Whenever it is
//! `Some(..)` — even `Some("")` — [`enforce_share`] refuses with
//! [`FlowError::IdentityBlocked`] **regardless of the mark**: not `Open`,
//! not a named audience, not a deliberate tightening changes that. This check
//! runs before the mark is even consulted, so an identity-bearing finding is
//! blocked even when it is *unmarked* (`IdentityBlocked` wins over
//! `Mark(Unmarked)`). Sanitising the finding (dropping/processing the
//! identity reference) is a separate, logged flow outside this gate.
//!
//! # Default posture is a policy default, explicit tighter marks win
//! [`default_level`] never *loosens* a finding: it is the level
//! [`apply_flow`] offers to [`apply_marks`], which refuses any application
//! looser than the existing mark ([`MarkError::Downgrade`], surfaced as
//! [`FlowError::Mark`]). A finding a caller deliberately marked tighter
//! (say `Sealed`) stays tighter even when the flow is re-run on a better
//! grade; re-running the flow at the *same* rank is a lateral refresh
//! (allowed, as in `release_marks`), and a tighter posture (grade worsens)
//! is applied.
//!
//! # Documented judgment calls (per frozen interface §4)
//! * `Sealed` **ignores audiences**: the list is not required (an empty one
//!   is accepted, no [`FlowError::EmptyAudience`]) and it admits nobody —
//!   but when provided it is still normalised and carried as inert scope
//!   metadata, mirroring `release_marks::apply_marks`, which tolerates and
//!   does not strip `releasable_to` at `Sealed`. Dropping caller data would
//!   silently diverge from the sibling module's normalisation contract.
//! * [`FlowError::EmptyAudience`]'s payload is the level's canonical
//!   snake_case word (`"need_to_share"`, `"restricted"`, …) — the same token
//!   serde emits for [`Releasability`], so refusals are ledger-stable.
//! * [`FlowError::Mark`] carries the underlying `release_marks` audit line
//!   verbatim (`MarkError`'s `Display`), so the two refusal phases remain
//!   distinguishable in a ledger.
//! * Caveat strings are carried as given (only trimmed/sorted/deduped);
//!   spell them with [`crate::caveats::Caveat::code`] (`NO-THIRD-PARTY`,
//!   `ORCON`, `REL-<role>`) so the vocabulary stays canonical. This module
//!   does not compile against `caveats`.
//!
//! # Scope / integration
//! Pure functions: no I/O, no clock (callers stamp `now_ms`), no globals.
//! Wired into `lib.rs` (`pub mod marking_flow;`). Intended consumers: the release/export pipeline
//! (after [`crate::access_class`] and [`crate::caveats`] admit the material)
//! and the audit ledger ([`FlowError`] is serde-round-trippable with stable
//! variant names). Expected tests: `cargo test --lib marking_flow`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::clearness_gate::ClearnessSession;
use crate::release_marks::{self, Finding, Releasability, ReleaseMark};
use crate::source_registry::ReliabilityGrade;

// ── Graded finding ───────────────────────────────────────────────────────────

/// One finding of an investigation together with the reliability grade of its
/// source and an optional reference to raw identity material.
///
/// `identity_ref` is an *opaque reference* (never the raw material itself in
/// practice); its mere presence blocks release in [`enforce_share`]. A missing
/// `identity_ref` deserialises to `None`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GradedFinding {
    /// The finding (with its optional release mark — mutated only through
    /// `release_marks::apply_marks`, here via [`apply_flow`]).
    pub finding: Finding,
    /// Reliability grade of the finding's source (`A`–`F`, Admiralty).
    pub grade: ReliabilityGrade,
    /// Reference to raw identity material borne by this finding, if any.
    /// `Some(..)` — even `Some("")` — makes the finding unshareable through
    /// [`enforce_share`].
    #[serde(default)]
    pub identity_ref: Option<String>,
}

// ── Refusals (audit) ─────────────────────────────────────────────────────────

/// Why the graded-findings flow refused. Serde-round-trippable (wire form is
/// the variant name, payloads are strings) so refusals can be written to the
/// ledger; `Display` renders a human audit line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FlowError {
    /// A `NeedToShare`/`Restricted` mark was built with no audience after
    /// normalisation (trimmed, empties dropped, sorted, deduped). The payload
    /// is the level's canonical snake_case word.
    EmptyAudience(String),
    /// The finding carries raw identity material (`identity_ref` is `Some`).
    /// The payload is the identity reference. This refusal is unconditional:
    /// no mark, audience, or level ever unblocks it.
    IdentityBlocked(String),
    /// A `release_marks` refusal, mapped with its audit line (`MarkError`'s
    /// `Display`): unmarked, downgrade, empty audience, or not releasable.
    Mark(String),
    /// A clearness-review refusal (B2.1.2 adoption): the high-risk release
    /// seam was reached without a cleared review — either no session was
    /// supplied or [`ClearnessSession::can_disseminate`] failed. The payload
    /// is the review audit line.
    Clearness(String),
}

impl fmt::Display for FlowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FlowError::EmptyAudience(level) => write!(
                f,
                "mark refused: level `{level}` names no audience (empty releasable_to)"
            ),
            FlowError::IdentityBlocked(id) => write!(
                f,
                "release refused: raw identity material (`{id}`) must never leave, whatever the mark"
            ),
            // Passthrough: the underlying release_marks audit line already
            // names the specific refusal (unmarked/downgrade/empty/restricted).
            FlowError::Mark(msg) => f.write_str(msg),
            // B2.1.2 adoption: the review refusal carries its own audit line
            // (no session supplied, or `can_disseminate` failed).
            FlowError::Clearness(msg) => write!(
                f,
                "release refused: high-risk release requires a cleared review ({msg})"
            ),
        }
    }
}

impl std::error::Error for FlowError {}

// ── Helpers (private) ────────────────────────────────────────────────────────

/// Canonical snake_case word for a level — byte-identical to
/// [`Releasability`]'s serde form (pinned in tests) and the payload token of
/// [`FlowError::EmptyAudience`].
fn level_word(level: Releasability) -> &'static str {
    match level {
        Releasability::Open => "open",
        Releasability::NeedToShare => "need_to_share",
        Releasability::Restricted => "restricted",
        Releasability::Sealed => "sealed",
    }
}

/// Trim entries, drop empties, sort, dedupe. Deliberately identical semantics
/// to `release_marks`' private `normalize` (not exported there), so marks
/// built here normalise exactly like marks applied there.
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

// ── Default posture (policy table) ──────────────────────────────────────────

/// The documented **default posture** for a source grade:
///
/// | grade | default level |
/// |-------|---------------|
/// | `A`, `B` | [`Releasability::Open`] |
/// | `C` | [`Releasability::NeedToShare`] |
/// | `D`, `E` | [`Releasability::Restricted`] |
/// | `F` | [`Releasability::Sealed`] |
///
/// Worser grades are never *looser* (rank is non-decreasing as the grade
/// worsens). This is a policy default only: an explicit tighter mark on the
/// finding always wins through [`apply_flow`]'s no-downgrade path.
pub fn default_level(grade: &ReliabilityGrade) -> Releasability {
    match grade {
        ReliabilityGrade::A | ReliabilityGrade::B => Releasability::Open,
        ReliabilityGrade::C => Releasability::NeedToShare,
        ReliabilityGrade::D | ReliabilityGrade::E => Releasability::Restricted,
        ReliabilityGrade::F => Releasability::Sealed,
    }
}

// ── Mark construction ────────────────────────────────────────────────────────

/// Build a normalised [`ReleaseMark`] for `level`.
///
/// * `audiences` and `caveats` are trimmed, emptied, sorted and deduped.
/// * `NeedToShare` and `Restricted` with no audience left after
///   normalisation are refused with [`FlowError::EmptyAudience`].
/// * `Open` and `Sealed` tolerate an empty audience list; `Sealed` ignores
///   audiences for admission and validation, but a provided list is still
///   normalised and carried (see module docs, judgment calls).
/// * `marked_ms` is stamped from `now_ms` (any timestamp the caller carries
///   elsewhere is irrelevant — this function takes no candidate timestamp).
pub fn build_mark(
    level: Releasability,
    audiences: &[String],
    caveats: &[String],
    now_ms: i64,
) -> Result<ReleaseMark, FlowError> {
    let releasable_to = normalize(audiences);
    if matches!(
        level,
        Releasability::NeedToShare | Releasability::Restricted
    ) && releasable_to.is_empty()
    {
        return Err(FlowError::EmptyAudience(level_word(level).to_string()));
    }
    Ok(ReleaseMark {
        level,
        releasable_to,
        caveats: normalize(caveats),
        marked_ms: now_ms,
    })
}

// ── Flow ─────────────────────────────────────────────────────────────────────

/// Mark `gf` with its **default posture** for its grade, audiences and
/// caveats, through [`release_marks::apply_marks`] so the no-downgrade rule
/// and the shape rules hold end to end.
///
/// On `Err` the finding is not modified. Refusals: [`FlowError::EmptyAudience`]
/// from [`build_mark`] (the finding stays untouched), or [`FlowError::Mark`]
/// carrying the `release_marks` audit line (downgrade, or empty audience on a
/// hand-built path).
pub fn apply_flow(
    gf: &mut GradedFinding,
    audiences: &[String],
    caveats: &[String],
    now_ms: i64,
) -> Result<(), FlowError> {
    let level = default_level(&gf.grade);
    let mark = build_mark(level, audiences, caveats, now_ms)?;
    release_marks::apply_marks(&mut gf.finding, mark, now_ms).map_err(|e| FlowError::Mark(e.to_string()))
}

/// May `gf` be released to `audience`?
///
/// **Raw identity material is checked first and blocked unconditionally**:
/// `identity_ref.is_some()` ⇒ [`FlowError::IdentityBlocked`], regardless of
/// the mark — even `Open`, even for a named audience, even when the finding
/// is unmarked. Otherwise the finding's mark is consulted via
/// [`release_marks::check_release`] and any refusal is mapped to
/// [`FlowError::Mark`] with the audit line.
pub fn enforce_share(gf: &GradedFinding, audience: &str) -> Result<(), FlowError> {
    if let Some(id) = &gf.identity_ref {
        return Err(FlowError::IdentityBlocked(id.clone()));
    }
    release_marks::check_release(&gf.finding, audience).map_err(|e| FlowError::Mark(e.to_string()))
}

/// [`enforce_share`] **with the B2.1.2 clearness step**: a cleared review is
/// a required step for high-risk releases.
///
/// Effective risk is the finding's mark level; an **unmarked** finding is
/// treated as highest risk (assume worst — it is also never releasable, so
/// the demand is moot but never wrong). When the effective rank is at or
/// above `floor`:
///
/// 1. raw identity material is still blocked first
///    ([`FlowError::IdentityBlocked`], exactly as in [`enforce_share`]);
/// 2. a cleared [`ClearnessSession`] is **required** — `None`, or a failed
///    [`ClearnessSession::can_disseminate`], refuses with
///    [`FlowError::Clearness`];
/// 3. only then does the mark gate run (same call as [`enforce_share`], so
///    the unmarked/downgrade/audience rules read identically).
///
/// Below the floor no review is demanded and the call degenerates to
/// [`enforce_share`]'s mark gate. `floor` is caller policy; passing
/// [`Releasability::NeedToShare`] requires a review for everything beyond a
/// plain `Open` release.
pub fn enforce_share_reviewed(
    gf: &GradedFinding,
    audience: &str,
    clearance: Option<&ClearnessSession>,
    floor: Releasability,
) -> Result<(), FlowError> {
    if let Some(id) = &gf.identity_ref {
        return Err(FlowError::IdentityBlocked(id.clone()));
    }
    let risk = gf
        .finding
        .mark
        .as_ref()
        .map(|m| m.level.rank())
        .unwrap_or(u8::MAX);
    if risk >= floor.rank() {
        match clearance {
            None => {
                return Err(FlowError::Clearness(
                    "no cleared review session supplied".to_string(),
                ));
            }
            Some(session) => {
                session
                    .can_disseminate()
                    .map_err(|e| FlowError::Clearness(e.to_string()))?;
            }
        }
    }
    release_marks::check_release(&gf.finding, audience).map_err(|e| FlowError::Mark(e.to_string()))
}

/// Enforce [`enforce_share`] over a batch for one audience; returns the
/// number of findings released.
///
/// Non-mutating. The **first denial aborts** the batch: a `Err` means *no
/// release decision was taken for the batch after the denial* (and nothing in
/// `gfs` was modified). An empty batch releases `Ok(0)`.
pub fn share_batch(gfs: &[GradedFinding], audience: &str) -> Result<usize, FlowError> {
    let mut released = 0usize;
    for gf in gfs {
        enforce_share(gf, audience)?;
        released += 1;
    }
    Ok(released)
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;

    fn gf(id: &str, grade: ReliabilityGrade) -> GradedFinding {
        GradedFinding {
            finding: Finding {
                id: id.to_string(),
                body: format!("body of {id}"),
                mark: None,
            },
            grade,
            identity_ref: None,
        }
    }

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    /// Assert an `enforce_share` refusal is `FlowError::Mark` whose audit line
    /// contains `needle`.
    fn mark_err_needle(result: Result<(), FlowError>, needle: &str, ctx: &str) {
        match result {
            Err(FlowError::Mark(msg)) => {
                assert!(msg.contains(needle), "{ctx}: `{msg}` must contain `{needle}`")
            }
            other => panic!("{ctx}: expected FlowError::Mark containing `{needle}`, got {other:?}"),
        }
    }

    // ── default posture table ────────────────────────────────────────────────

    #[test]
    fn default_level_pins_the_posture_table() {
        let cases = [
            (ReliabilityGrade::A, Releasability::Open),
            (ReliabilityGrade::B, Releasability::Open),
            (ReliabilityGrade::C, Releasability::NeedToShare),
            (ReliabilityGrade::D, Releasability::Restricted),
            (ReliabilityGrade::E, Releasability::Restricted),
            (ReliabilityGrade::F, Releasability::Sealed),
        ];
        for (grade, level) in cases {
            assert_eq!(default_level(&grade), level, "grade {grade:?}");
        }
        // Posture is monotone in the grade: a worser grade is never looser.
        for (better, better_level) in cases {
            for (worse, worse_level) in cases {
                if better.rank() < worse.rank() {
                    assert!(
                        better_level.rank() <= worse_level.rank(),
                        "{better:?}→{better_level:?} looser than {worse:?}→{worse_level:?}"
                    );
                }
            }
        }
    }

    // ── build_mark: normalisation, stamping, empty audiences ────────────────

    #[test]
    fn build_mark_normalizes_and_stamps_application_time() {
        let m = build_mark(
            Releasability::NeedToShare,
            &strings(&["beta", " alpha ", "beta", "", "   "]),
            &strings(&[" ORCON ", "NO-THIRD-PARTY", "ORCON"]),
            NOW,
        )
        .unwrap();
        assert_eq!(m.level, Releasability::NeedToShare);
        assert_eq!(m.releasable_to, strings(&["alpha", "beta"]));
        assert_eq!(m.caveats, strings(&["NO-THIRD-PARTY", "ORCON"]));
        assert_eq!(m.marked_ms, NOW, "marked_ms is stamped from now_ms");

        // Open normalises too, and keeps a provided (inert) audience list.
        let o = build_mark(Releasability::Open, &strings(&[" z ", "a", "a"]), &[], 5).unwrap();
        assert_eq!(o.releasable_to, strings(&["a", "z"]));
        assert_eq!(o.caveats, strings(&[]));
        assert_eq!(o.marked_ms, 5);
    }

    #[test]
    fn build_mark_empty_audience_matrix() {
        let empties: [Vec<&str>; 4] = [vec![], vec![""], vec!["   "], vec!["", "  "]];
        for level in [Releasability::NeedToShare, Releasability::Restricted] {
            let word = match level {
                Releasability::NeedToShare => "need_to_share",
                Releasability::Restricted => "restricted",
                other => panic!("unexpected level {other:?}"),
            };
            for to in &empties {
                assert_eq!(
                    build_mark(level, &strings(to), &[], 1),
                    Err(FlowError::EmptyAudience(word.to_string())),
                    "{level:?} with {to:?}"
                );
            }
        }
        // Open and Sealed tolerate every empty spelling.
        for level in [Releasability::Open, Releasability::Sealed] {
            for to in &empties {
                let m = build_mark(level, &strings(to), &[], 1).unwrap();
                assert_eq!(m.releasable_to, strings(&[]));
            }
        }
    }

    #[test]
    fn sealed_ignores_audience_requirement_and_retains_normalised_scope() {
        // No EmptyAudience, empty list stored.
        let bare = build_mark(Releasability::Sealed, &[], &[], 7).unwrap();
        assert_eq!(bare.releasable_to, strings(&[]));
        // A provided list is not required but is normalised and carried
        // (judgment call documented in the module docs; nothing is admitted).
        let scoped = build_mark(
            Releasability::Sealed,
            &strings(&[" z ", "a", "a"]),
            &strings(&["ORCON"]),
            7,
        )
        .unwrap();
        assert_eq!(scoped.level, Releasability::Sealed);
        assert_eq!(scoped.releasable_to, strings(&["a", "z"]));
        assert_eq!(scoped.caveats, strings(&["ORCON"]));
    }

    // ── the deny/allow matrix (B1.4.3) ──────────────────────────────────────

    #[test]
    fn apply_flow_posture_matrix_allow_and_deny() {
        // A/B → Open: flow with no audiences succeeds; every audience —
        // even the empty one — releases (the mark carries no restriction).
        for grade in [ReliabilityGrade::A, ReliabilityGrade::B] {
            let mut g = gf("open", grade);
            apply_flow(&mut g, &[], &[], NOW).unwrap();
            assert_eq!(g.finding.mark.as_ref().unwrap().level, Releasability::Open);
            for a in ["", "   ", "alpha", "anyone"] {
                assert!(enforce_share(&g, a).is_ok(), "{grade:?} must admit {a:?}");
            }
        }

        // C → NeedToShare: empty audiences refused (level word in payload);
        // a named audience allows exactly that audience, denies others.
        let mut c = gf("nts", ReliabilityGrade::C);
        assert_eq!(
            apply_flow(&mut c, &[], &[], NOW),
            Err(FlowError::EmptyAudience("need_to_share".into()))
        );
        assert!(c.finding.mark.is_none(), "a refused flow must not mark");
        apply_flow(&mut c, &strings(&["alpha"]), &[], NOW).unwrap();
        enforce_share(&c, "alpha").unwrap();
        enforce_share(&c, "  alpha  ").unwrap();
        mark_err_needle(enforce_share(&c, "beta"), "not releasable", "cross-audience");
        mark_err_needle(enforce_share(&c, ""), "no audience", "empty audience");

        // D/E → Restricted: empty audiences refused; even a listed audience
        // is denied (no release path at this level).
        for grade in [ReliabilityGrade::D, ReliabilityGrade::E] {
            let mut g = gf("restr", grade);
            assert_eq!(
                apply_flow(&mut g, &strings(&["   "]), &[], NOW),
                Err(FlowError::EmptyAudience("restricted".into()))
            );
            assert!(g.finding.mark.is_none());
            apply_flow(&mut g, &strings(&["alpha"]), &[], NOW).unwrap();
            assert_eq!(
                g.finding.mark.as_ref().unwrap().level,
                Releasability::Restricted
            );
            for a in ["", "alpha", "beta", "stranger"] {
                mark_err_needle(enforce_share(&g, a), "not releasable", "restricted");
            }
        }

        // F → Sealed: empty audiences accepted; every audience denied.
        let mut f = gf("sealed", ReliabilityGrade::F);
        apply_flow(&mut f, &[], &[], NOW).unwrap();
        assert_eq!(f.finding.mark.as_ref().unwrap().level, Releasability::Sealed);
        for a in ["", "alpha", "stranger"] {
            mark_err_needle(enforce_share(&f, a), "not releasable", "sealed");
        }
    }

    #[test]
    fn apply_flow_share_roundtrip_allows_named_audience() {
        let mut g = gf("f-c", ReliabilityGrade::C);
        apply_flow(
            &mut g,
            &strings(&["beta", " alpha ", "beta", ""]),
            &strings(&[" ORCON ", "NO-THIRD-PARTY"]),
            NOW,
        )
        .unwrap();
        let m = g.finding.mark.as_ref().unwrap();
        assert_eq!(m.level, Releasability::NeedToShare);
        assert_eq!(m.releasable_to, strings(&["alpha", "beta"]));
        assert_eq!(m.caveats, strings(&["NO-THIRD-PARTY", "ORCON"]));
        assert_eq!(m.marked_ms, NOW);
        enforce_share(&g, "alpha").unwrap();
        enforce_share(&g, "beta").unwrap();
    }

    // ── raw identity material is blocked, unconditionally ───────────────────

    #[test]
    fn identity_ref_blocks_release_even_when_open_and_named() {
        // Open posture, named audience — still blocked.
        let mut g = gf("id-open", ReliabilityGrade::A);
        g.identity_ref = Some("rel-7".to_string());
        apply_flow(&mut g, &[], &[], NOW).unwrap();
        assert_eq!(
            enforce_share(&g, "anyone"),
            Err(FlowError::IdentityBlocked("rel-7".into()))
        );
        assert_eq!(
            enforce_share(&g, ""),
            Err(FlowError::IdentityBlocked("rel-7".into()))
        );

        // Identity beats the mark even after a deliberate tightening.
        release_marks::apply_marks(
            &mut g.finding,
            build_mark(Releasability::NeedToShare, &strings(&["alpha"]), &[], NOW).unwrap(),
            NOW,
        )
        .unwrap();
        assert_eq!(
            enforce_share(&g, "alpha"),
            Err(FlowError::IdentityBlocked("rel-7".into()))
        );

        // Identity beats Unmarked too: the identity check runs first.
        let mut unmarked = gf("id-unmarked", ReliabilityGrade::A);
        unmarked.identity_ref = Some("raw".to_string());
        assert_eq!(
            enforce_share(&unmarked, "alpha"),
            Err(FlowError::IdentityBlocked("raw".into()))
        );

        // Even an empty-string reference is identity material.
        let mut empty_ref = gf("id-empty", ReliabilityGrade::F);
        empty_ref.identity_ref = Some(String::new());
        apply_flow(&mut empty_ref, &[], &[], NOW).unwrap();
        assert_eq!(
            enforce_share(&empty_ref, "alpha"),
            Err(FlowError::IdentityBlocked(String::new()))
        );
    }

    // ── no-downgrade through the flow ───────────────────────────────────────

    #[test]
    fn apply_flow_preserves_no_downgrade_and_allows_tightening() {
        // A deliberately tighter mark (operator decision) survives the flow.
        let mut g = gf("nd", ReliabilityGrade::A);
        release_marks::apply_marks(
            &mut g.finding,
            build_mark(Releasability::Sealed, &[], &[], 5).unwrap(),
            5,
        )
        .unwrap();
        let err = apply_flow(&mut g, &strings(&["alpha", "beta"]), &[], 99).unwrap_err();
        match err {
            FlowError::Mark(msg) => assert!(msg.contains("no-downgrade"), "got `{msg}`"),
            other => panic!("expected FlowError::Mark, got {other:?}"),
        }
        let kept = g.finding.mark.as_ref().unwrap();
        assert_eq!(kept.level, Releasability::Sealed);
        assert_eq!(kept.marked_ms, 5, "a refused flow leaves the mark untouched");

        // Lateral refresh at the same rank is allowed.
        let mut lat = gf("lat", ReliabilityGrade::C);
        apply_flow(&mut lat, &strings(&["alpha"]), &[], 1).unwrap();
        apply_flow(&mut lat, &strings(&["beta"]), &strings(&["ORCON"]), 2).unwrap();
        let lat_mark = lat.finding.mark.unwrap();
        assert_eq!(lat_mark.releasable_to, strings(&["beta"]));
        assert_eq!(lat_mark.marked_ms, 2);

        // Tightening through the flow (grade worsens) is applied...
        let mut up = gf("up", ReliabilityGrade::C);
        apply_flow(&mut up, &strings(&["alpha"]), &[], 1).unwrap();
        up.grade = ReliabilityGrade::D;
        apply_flow(&mut up, &strings(&["alpha"]), &[], 2).unwrap();
        assert_eq!(up.finding.mark.as_ref().unwrap().level, Releasability::Restricted);
        // ...and loosening back down (D→C) is refused, mark kept.
        up.grade = ReliabilityGrade::C;
        let err = apply_flow(&mut up, &strings(&["alpha"]), &[], 3).unwrap_err();
        assert!(matches!(err, FlowError::Mark(_)));
        let kept = up.finding.mark.as_ref().unwrap();
        assert_eq!(kept.level, Releasability::Restricted);
        assert_eq!(kept.marked_ms, 2);
    }

    // ── batch ───────────────────────────────────────────────────────────────

    #[test]
    fn share_batch_counts_released_and_aborts_on_first_denial() {
        let mut a = gf("b-a", ReliabilityGrade::A);
        apply_flow(&mut a, &[], &[], NOW).unwrap();
        let mut b = gf("b-b", ReliabilityGrade::A);
        apply_flow(&mut b, &[], &[], NOW).unwrap();
        let a_before = a.clone();

        assert_eq!(share_batch(&[], "anyone"), Ok(0));
        assert_eq!(share_batch(&[a.clone()], "anyone"), Ok(1));
        assert_eq!(share_batch(&[a.clone(), b.clone()], "anyone"), Ok(2));
        assert_eq!(a, a_before, "a batch releases nothing stateful");

        // Denial in the tail aborts.
        let mut bad = gf("b-c", ReliabilityGrade::A);
        bad.identity_ref = Some("raw".to_string());
        assert_eq!(
            share_batch(&[a.clone(), b.clone(), bad.clone(), a.clone()], "anyone"),
            Err(FlowError::IdentityBlocked("raw".into()))
        );

        // Denial in the middle aborts: a cross-audience NeedToShare.
        let mut nts = gf("b-d", ReliabilityGrade::C);
        apply_flow(&mut nts, &strings(&["alpha"]), &[], NOW).unwrap();
        match share_batch(&[a.clone(), nts.clone(), b.clone()], "beta") {
            Err(FlowError::Mark(msg)) => {
                assert!(msg.contains("not releasable"), "batch mid-denial: `{msg}`")
            }
            other => panic!("batch mid-denial: expected FlowError::Mark, got {other:?}"),
        }
        // The same batch passes for the named audience.
        assert_eq!(share_batch(&[a.clone(), nts.clone(), b.clone()], "alpha"), Ok(3));
    }

    // ── serde ───────────────────────────────────────────────────────────────

    #[test]
    fn serde_wire_shapes_and_round_trips() {
        let mut g = gf("f-9", ReliabilityGrade::C);
        apply_flow(&mut g, &strings(&["alpha"]), &strings(&["ORCON"]), NOW).unwrap();

        let back: GradedFinding =
            serde_json::from_str(&serde_json::to_string(&g).unwrap()).unwrap();
        assert_eq!(back, g);
        let v = serde_json::to_value(&g).unwrap();
        assert_eq!(v["grade"], serde_json::json!("C"));
        assert_eq!(v["identity_ref"], serde_json::json!(null));
        assert_eq!(v["finding"]["mark"]["level"], serde_json::json!("need_to_share"));
        assert_eq!(
            v["finding"]["mark"]["releasable_to"],
            serde_json::json!(["alpha"])
        );

        // Missing identity_ref (and a bare finding) deserialise cleanly.
        let bare: GradedFinding = serde_json::from_value(serde_json::json!({
            "finding": {"id": "f-0", "body": "b"},
            "grade": "A",
        }))
        .unwrap();
        assert_eq!(bare.identity_ref, None);
        assert!(bare.finding.mark.is_none());

        // Identity-bearing finding round-trips, Some("") included.
        let mut e = gf("f-e", ReliabilityGrade::F);
        e.identity_ref = Some(String::new());
        let back: GradedFinding =
            serde_json::from_str(&serde_json::to_string(&e).unwrap()).unwrap();
        assert_eq!(back, e);

        // FlowError: variant-name wire form, payload pinned.
        assert_eq!(
            serde_json::to_string(&FlowError::EmptyAudience("need_to_share".into())).unwrap(),
            "{\"EmptyAudience\":\"need_to_share\"}"
        );
        assert_eq!(
            serde_json::to_string(&FlowError::IdentityBlocked("raw".into())).unwrap(),
            "{\"IdentityBlocked\":\"raw\"}"
        );
        for err in [
            FlowError::EmptyAudience("restricted".into()),
            FlowError::IdentityBlocked("id-1".into()),
            FlowError::Mark("release refused: the finding carries no release mark".into()),
        ] {
            let json = serde_json::to_string(&err).unwrap();
            let back: FlowError = serde_json::from_str(&json).unwrap();
            assert_eq!(back, err);
        }
    }

    // ── errors: display + audit usability ──────────────────────────────────

    #[test]
    fn errors_display_as_audit_lines_and_box_as_std_error() {
        let cases = [
            (FlowError::EmptyAudience("need_to_share".into()), "no audience"),
            (FlowError::IdentityBlocked("rel-7".into()), "identity"),
            (
                FlowError::Mark("release refused: no-downgrade rule".into()),
                "no-downgrade",
            ),
        ];
        for (err, needle) in cases {
            let line = err.to_string();
            assert!(line.contains(needle), "{err:?} display: {line}");
            let boxed: Box<dyn std::error::Error> = Box::new(err);
            assert!(!boxed.to_string().is_empty());
        }
    }

    // ── determinism ────────────────────────────────────────────────────────

    #[test]
    fn ordering_is_irrelevant_and_answers_are_deterministic() {
        let orderings: [Vec<&str>; 4] = [
            vec!["beta", "alpha", "gamma"],
            vec!["gamma", "beta", "alpha"],
            vec!["alpha", "gamma", "beta"],
            vec!["beta", "alpha", "gamma", "gamma", "alpha"],
        ];
        // build_mark is order-independent.
        let mut first: Option<ReleaseMark> = None;
        for to in &orderings {
            let reversed: Vec<String> = to.iter().rev().map(|s| s.to_string()).collect();
            let m = build_mark(Releasability::NeedToShare, &strings(to), &reversed, 42).unwrap();
            match &first {
                None => first = Some(m),
                Some(prev) => assert_eq!(&m, prev, "order {to:?} must normalise identically"),
            }
        }
        // The whole flow (apply + enforce) answers identically on every run.
        let audiences = ["", "alpha", "beta", "gamma", "delta"];
        let mut first_answers: Option<Vec<bool>> = None;
        for _ in 0..16 {
            let mut answers = Vec::new();
            for to in &orderings {
                let mut g = gf("det", ReliabilityGrade::C);
                if apply_flow(&mut g, &strings(to), &strings(&["ORCON"]), NOW).is_ok() {
                    for a in audiences {
                        answers.push(enforce_share(&g, a).is_ok());
                    }
                }
            }
            match &first_answers {
                None => first_answers = Some(answers),
                Some(prev) => assert_eq!(&answers, prev, "flow answers must be deterministic"),
            }
        }
    }

    // ── B2.1.2 adoption: reviewed release seam ─────────────────────────────

    /// A fully cleared session (B2.1.1 shape): two reviewers, each with a
    /// question, everything answered — `can_disseminate` passes.
    fn cleared_session() -> ClearnessSession {
        let mut s =
            ClearnessSession::open(vec!["rev-a".to_string(), "rev-b".to_string()]).unwrap();
        let qa = s.ask("rev-a", "any unresolved caveats?").unwrap().id.clone();
        s.answer(&qa, "none — cleared").unwrap();
        let qb = s.ask("rev-b", "sources cross-checked?").unwrap().id.clone();
        s.answer(&qb, "cross-checked").unwrap();
        s
    }

    #[test]
    fn reviewed_requires_a_cleared_session_at_or_above_the_floor() {
        let mut g = gf("rev", ReliabilityGrade::C); // NeedToShare default
        apply_flow(&mut g, &strings(&["team"]), &[], NOW).unwrap();

        // At the floor without a session: refused, review required.
        let err = enforce_share_reviewed(&g, "team", None, Releasability::NeedToShare).unwrap_err();
        assert!(matches!(err, FlowError::Clearness(_)), "got {err:?}");

        // Cleared session: the mark gate then admits the named audience.
        let s = cleared_session();
        enforce_share_reviewed(&g, "team", Some(&s), Releasability::NeedToShare).unwrap();

        // Below the floor the review is not demanded (mark gate alone).
        enforce_share_reviewed(&g, "team", None, Releasability::Restricted).unwrap();
    }

    #[test]
    fn reviewed_session_with_open_questions_refuses() {
        let mut s = ClearnessSession::open(vec!["a".to_string(), "b".to_string()]).unwrap();
        let qa = s.ask("a", "first question?").unwrap().id.clone();
        s.ask("b", "second question?").unwrap();
        s.answer(&qa, "answered").unwrap();
        let mut g = gf("rev2", ReliabilityGrade::C);
        apply_flow(&mut g, &strings(&["team"]), &[], NOW).unwrap();
        let err = enforce_share_reviewed(&g, "team", Some(&s), Releasability::NeedToShare)
            .unwrap_err();
        match err {
            FlowError::Clearness(msg) => assert!(!msg.is_empty()),
            other => panic!("expected Clearness, got {other:?}"),
        }
    }

    #[test]
    fn reviewed_identity_block_beats_the_clearness_demand() {
        let mut g = gf("idrev", ReliabilityGrade::C);
        apply_flow(&mut g, &strings(&["team"]), &[], NOW).unwrap();
        g.identity_ref = Some("raw-name".to_string());
        let err = enforce_share_reviewed(&g, "team", None, Releasability::Sealed).unwrap_err();
        assert!(matches!(err, FlowError::IdentityBlocked(_)), "got {err:?}");
    }

    #[test]
    fn reviewed_unmarked_assumes_worst_risk() {
        let g = gf("unmarked", ReliabilityGrade::A); // no mark applied
        let err =
            enforce_share_reviewed(&g, "team", None, Releasability::NeedToShare).unwrap_err();
        assert!(matches!(err, FlowError::Clearness(_)), "got {err:?}");
    }

    #[test]
    fn reviewed_display_and_serde_stay_audit_stable() {
        let err = FlowError::Clearness("no cleared review session supplied".into());
        assert!(err.to_string().contains("cleared review"), "{err}");
        let json = serde_json::to_string(&err).unwrap();
        assert!(json.contains("Clearness"), "{json}");
        let back: FlowError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, err);
    }
}
