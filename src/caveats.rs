//! Dissemination caveats + summary markings (task A2.2.3, dossier E3).
//!
//! [`crate::access_class`] (A2.2.1) answers *whether* material of a class may
//! be read or taken out of the vault for an audience. This module answers
//! *how far* an otherwise-admissible release may travel: each [`Caveat`] is a
//! free-standing dissemination restriction attached to material (or to a
//! release plan), checked by [`release_check`] just before anything leaves,
//! and rendered into header/log markings by [`summary_marking`].
//!
//! # Deny-by-default, default to tightest
//! [`default_to_tightest`] returns [`Caveat::NoThirdParty`]: when a plan
//! omits caveats, the safe default is "not to outsiders". A release with an
//! *empty* caveat list is unconstrained by this module — caveats only ever
//! restrict what the class/export gate already admitted; they can never
//! widen it.
//!
//! # Rule precedence (frozen, documented)
//! [`release_check`] evaluates the three caveat classes in this fixed order,
//! **independent of the order caveats appear in the slice**:
//!
//! 1. [`Caveat::NoThirdParty`] — deny [`Audience::Public`] and
//!    [`Audience::ThirdParty`]; `Teammate`/`Operator` pass.
//! 2. [`Caveat::OriginatorControlled`] — deny *every* audience unless
//!    `originator_approved`. (No audience is exempt.)
//! 3. [`Caveat::RoleReleasable`] — for `Public`/`ThirdParty`/`Teammate`,
//!    deny unless the released `role` equals the caveat's role; `Operator`
//!    is exempt from the role check.
//!
//! Within one class the first refusal in evaluation order is reported (the
//! caller's slice order, for multiple caveats of the same class); the first
//! phase that refuses wins across classes. Role comparison is on trimmed
//! strings and is exact: a caveat whose own role is empty once trimmed can
//! never release to a non-operator audience, and an empty released role is
//! never a release. All functions are pure: no I/O, no clock, no globals.
//!
//! # Markings
//! [`summary_marking`] renders the canonical codes — `NO-THIRD-PARTY`,
//! `ORCON`, `REL-<role>` — joined by `/`: fixed class order, then roles
//! ascending, duplicates collapsed; an empty caveat list marks `NONE`.
//! The role in a marking is trimmed before rendering, so padded spellings
//! collapse to one code; a caveat with an empty trimmed role renders bare
//! `REL-` (it restricts non-operator audiences but names nobody).
//!
//! # Scope / integration
//! Not wired into `lib.rs` yet (the parent does that). Intended consumers:
//! the release/export pipeline (after [`crate::access_class::check_export`]),
//! and marking headers for released artifacts. [`CaveatError`] is
//! serde-round-trippable so refusals can be written to the audit ledger with
//! a stable `code()`.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::access_class::Audience;

// ── Canonical marking codes ──────────────────────────────────────────────────

const CODE_NO_THIRD_PARTY: &str = "NO-THIRD-PARTY";
const CODE_ORCON: &str = "ORCON";
const CODE_NONE: &str = "NONE";
const REL_PREFIX: &str = "REL-";

// ── Caveats ──────────────────────────────────────────────────────────────────

/// A dissemination restriction attached to material or to a release plan.
///
/// Serde wire form is the variant name (`"NoThirdParty"`,
/// `"OriginatorControlled"`, `{"RoleReleasable":{"role":"…"}}`) — stable for
/// manifests and ledger records. Validation rule: a [`Caveat::RoleReleasable`]
/// role must be non-empty once trimmed ([`Caveat::is_valid`]); such a caveat
/// can then only release to operators.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Caveat {
    /// No release to anyone outside the operation: denies `Public` and
    /// `ThirdParty`; `Teammate`/`Operator` are unaffected.
    NoThirdParty,
    /// Originator-controlled: no release to any audience without the
    /// originator's explicit approval.
    OriginatorControlled,
    /// Role-releasable: outside/teammate audiences are denied unless the
    /// release names exactly this `role` (operators are exempt).
    RoleReleasable {
        /// The role a release must be made `for` to unlock this caveat.
        role: String,
    },
}

impl Caveat {
    /// The tightest caveat — the one to fall back to whenever a plan omits
    /// caveats or a value is unknown. Deny-by-default depends on this:
    /// `NoThirdParty` withholds the material from every outside audience.
    pub fn default_to_tightest() -> Self {
        Caveat::NoThirdParty
    }

    /// Canonical marking code: `NO-THIRD-PARTY`, `ORCON`, or `REL-<role>`
    /// (role trimmed). Same token [`DeniedBy`](CaveatError::DeniedBy) carries
    /// and [`summary_marking`] emits.
    pub fn code(&self) -> String {
        match self {
            Caveat::NoThirdParty => CODE_NO_THIRD_PARTY.to_string(),
            Caveat::OriginatorControlled => CODE_ORCON.to_string(),
            Caveat::RoleReleasable { role } => format!("{REL_PREFIX}{}", role.trim()),
        }
    }

    /// Validation: every caveat is valid except `RoleReleasable` with a role
    /// that is empty once trimmed — such a caveat can never be satisfied by a
    /// release and only restricts (see [`release_check`]).
    pub fn is_valid(&self) -> bool {
        match self {
            Caveat::NoThirdParty | Caveat::OriginatorControlled => true,
            Caveat::RoleReleasable { role } => !role.trim().is_empty(),
        }
    }
}

/// Default = tightest. `Caveat::default()` is `NoThirdParty`, never an
/// unconstrained marking.
impl Default for Caveat {
    fn default() -> Self {
        Caveat::default_to_tightest()
    }
}

/// Module-level twin of [`Caveat::default_to_tightest`] (the frozen A2.2.3
/// signature): the caveat to apply whenever none are supplied.
pub fn default_to_tightest() -> Caveat {
    Caveat::default_to_tightest()
}

impl fmt::Display for Caveat {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.code())
    }
}

// ── Refusals (audit) ─────────────────────────────────────────────────────────

/// Why a release was refused by a caveat. Serde-round-trippable for ledger
/// payloads; `Display` renders a human audit line; [`code`](CaveatError::code)
/// is the stable machine code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaveatError {
    /// A caveat refused this audience. `caveat` is the offending caveat's
    /// canonical code (`NO-THIRD-PARTY` / `ORCON` / `REL-<role>`); `audience`
    /// is the audience's stable lowercase token.
    DeniedBy {
        /// Canonical code of the caveat that refused.
        caveat: String,
        /// Stable lowercase token of the refused audience.
        audience: String,
    },
}

impl CaveatError {
    /// Stable machine code for audit aggregation (never localized).
    pub fn code(&self) -> &'static str {
        match self {
            CaveatError::DeniedBy { .. } => "deny.caveat",
        }
    }
}

impl fmt::Display for CaveatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CaveatError::DeniedBy { caveat, audience } => write!(
                f,
                "release denied: caveat '{caveat}' refuses audience '{audience}'"
            ),
        }
    }
}

impl std::error::Error for CaveatError {}

// ── Release check (pure, deny-by-default) ────────────────────────────────────

fn denied(caveat: &Caveat, audience: Audience) -> CaveatError {
    CaveatError::DeniedBy {
        caveat: caveat.code(),
        audience: audience.as_str().to_string(),
    }
}

/// May `caveats` be satisfied for a release to `audience`?
///
/// Arguments: the attached caveats; the release audience; `role` — the role
/// the release is being made *for*, if any; `originator_approved` — explicit
/// originator approval for this release.
///
/// `Ok(())` = no caveat refuses (an empty list never restricts). `Err` = the
/// first refusal in documented evaluation order: `NoThirdParty` →
/// `OriginatorControlled` → `RoleReleasable`, the caller's slice order within
/// a class. Never panics.
///
/// - `NoThirdParty`: refuses `Public`/`ThirdParty`; never refuses
///   `Teammate`/`Operator`.
/// - `OriginatorControlled`: refuses every audience unless
///   `originator_approved`.
/// - `RoleReleasable { role }`: for `Public`/`ThirdParty`/`Teammate` refuses
///   unless `role == Some(role)` after trimming; refuses when the caveat's
///   own role is empty once trimmed; `Operator` is exempt.
pub fn release_check(
    caveats: &[Caveat],
    audience: Audience,
    role: Option<&str>,
    originator_approved: bool,
) -> Result<(), CaveatError> {
    // Phase 1: NoThirdParty — outside audiences are never admitted, whatever
    // the approval flag or released role says.
    for caveat in caveats {
        if matches!(caveat, Caveat::NoThirdParty)
            && matches!(audience, Audience::Public | Audience::ThirdParty)
        {
            return Err(denied(caveat, audience));
        }
    }

    // Phase 2: OriginatorControlled — approval gates every audience.
    if !originator_approved {
        for caveat in caveats {
            if matches!(caveat, Caveat::OriginatorControlled) {
                return Err(denied(caveat, audience));
            }
        }
    }

    // Phase 3: RoleReleasable — operators are exempt; everyone else needs an
    // exact, non-empty trimmed role match.
    for caveat in caveats {
        if let Caveat::RoleReleasable { role: required } = caveat {
            if audience == Audience::Operator {
                continue;
            }
            let required = required.trim();
            let released = role.map(str::trim).filter(|r| !r.is_empty());
            if required.is_empty() || released != Some(required) {
                return Err(denied(caveat, audience));
            }
        }
    }

    Ok(())
}

// ── Summary markings ─────────────────────────────────────────────────────────

/// Canonical dissemination marking for a caveat set: codes joined by `/` in
/// fixed class order (`NO-THIRD-PARTY`, `ORCON`, then `REL-<role>` with roles
/// ascending), duplicates collapsed; an empty list marks `NONE`.
///
/// Deterministic for any input ordering; roles are trimmed before rendering
/// (an empty-trimmed role renders bare `REL-`).
pub fn summary_marking(caveats: &[Caveat]) -> String {
    let mut parts: Vec<String> = Vec::new();

    if caveats.iter().any(|c| matches!(c, Caveat::NoThirdParty)) {
        parts.push(CODE_NO_THIRD_PARTY.to_string());
    }
    if caveats
        .iter()
        .any(|c| matches!(c, Caveat::OriginatorControlled))
    {
        parts.push(CODE_ORCON.to_string());
    }

    let mut roles: Vec<String> = caveats
        .iter()
        .filter_map(|c| match c {
            Caveat::RoleReleasable { role } => Some(role.trim().to_string()),
            _ => None,
        })
        .collect();
    roles.sort();
    roles.dedup();
    for role in roles {
        parts.push(format!("{REL_PREFIX}{role}"));
    }

    if parts.is_empty() {
        CODE_NONE.to_string()
    } else {
        parts.join("/")
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::access_class::Audience;

    const AUDIENCES: [Audience; 4] = Audience::ALL;

    fn rel(role: &str) -> Caveat {
        Caveat::RoleReleasable {
            role: role.to_string(),
        }
    }

    fn denied_code(err: CaveatError) -> String {
        match err {
            CaveatError::DeniedBy { caveat, .. } => caveat,
        }
    }

    #[test]
    fn default_to_tightest_is_no_third_party() {
        assert_eq!(default_to_tightest(), Caveat::NoThirdParty);
        assert_eq!(Caveat::default_to_tightest(), Caveat::NoThirdParty);
        assert_eq!(Caveat::default(), Caveat::NoThirdParty);
        // Applying the default denies the two outside audiences and nothing else.
        for audience in AUDIENCES {
            let expected = !matches!(audience, Audience::Public | Audience::ThirdParty);
            assert_eq!(
                release_check(&[default_to_tightest()], audience, None, false).is_ok(),
                expected,
                "default-to-tightest for {audience}"
            );
        }
    }

    #[test]
    fn no_third_party_rule_allow_and_deny() {
        let caveats = [Caveat::NoThirdParty];
        let table = [
            (Audience::Public, false),
            (Audience::ThirdParty, false),
            (Audience::Teammate, true),
            (Audience::Operator, true),
        ];
        for (audience, allowed) in table {
            let result = release_check(&caveats, audience, None, false);
            assert_eq!(result.is_ok(), allowed, "NoThirdParty for {audience}: {result:?}");
            if let Err(e) = result {
                assert_eq!(
                    e,
                    CaveatError::DeniedBy {
                        caveat: "NO-THIRD-PARTY".into(),
                        audience: audience.as_str().into(),
                    }
                );
            }
        }
        // Approval and released roles never unlock NoThirdParty for outsiders.
        assert!(release_check(&caveats, Audience::Public, Some("anything"), true).is_err());
        assert!(release_check(&caveats, Audience::ThirdParty, Some("anything"), true).is_err());
    }

    #[test]
    fn originator_controlled_rule_allow_and_deny() {
        let caveats = [Caveat::OriginatorControlled];
        for audience in AUDIENCES {
            let refused = release_check(&caveats, audience, None, false);
            assert!(refused.is_err(), "ORCON must deny {audience} without approval");
            assert_eq!(
                refused.unwrap_err(),
                CaveatError::DeniedBy {
                    caveat: "ORCON".into(),
                    audience: audience.as_str().into(),
                }
            );
            // Approval unlocks every audience (subject to other caveats).
            assert!(
                release_check(&caveats, audience, None, true).is_ok(),
                "ORCON approved must allow {audience}"
            );
        }
    }

    #[test]
    fn role_releasable_rule_allow_and_deny() {
        let caveats = [rel("alpha")];
        for audience in [Audience::Public, Audience::ThirdParty, Audience::Teammate] {
            assert!(
                release_check(&caveats, audience, None, true).is_err(),
                "no role released for {audience}"
            );
            assert!(
                release_check(&caveats, audience, Some("beta"), true).is_err(),
                "wrong role for {audience}"
            );
            assert!(
                release_check(&caveats, audience, Some("alpha"), false).is_ok(),
                "exact role for {audience}"
            );
        }
        // Operator is exempt from the role check.
        assert!(release_check(&caveats, Audience::Operator, None, false).is_ok());
        assert!(release_check(&caveats, Audience::Operator, Some("nobody"), false).is_ok());
        // The refusal names the required role.
        assert_eq!(
            release_check(&caveats, Audience::ThirdParty, None, true).unwrap_err(),
            CaveatError::DeniedBy {
                caveat: "REL-alpha".into(),
                audience: "third-party".into(),
            }
        );
    }

    #[test]
    fn precedence_is_fixed_not_slice_order() {
        // NoThirdParty outranks RoleReleasable even when listed second and the
        // role WAS released: outsiders stay denied.
        let caveats = [rel("alpha"), Caveat::NoThirdParty];
        assert_eq!(
            denied_code(release_check(&caveats, Audience::Public, Some("alpha"), true).unwrap_err()),
            "NO-THIRD-PARTY"
        );
        let flipped = [Caveat::NoThirdParty, rel("alpha")];
        assert_eq!(
            denied_code(release_check(&flipped, Audience::Public, Some("alpha"), true).unwrap_err()),
            "NO-THIRD-PARTY"
        );

        // OriginatorControlled outranks RoleReleasable.
        let both = [rel("alpha"), Caveat::OriginatorControlled];
        assert_eq!(
            denied_code(release_check(&both, Audience::Teammate, Some("alpha"), false).unwrap_err()),
            "ORCON"
        );
        // With approval + release the pair passes...
        assert!(release_check(&both, Audience::Teammate, Some("alpha"), true).is_ok());
        // ...and with approval but no release, RoleReleasable is the refuser.
        assert_eq!(
            denied_code(release_check(&both, Audience::Teammate, None, true).unwrap_err()),
            "REL-alpha"
        );
    }

    #[test]
    fn within_a_class_first_refusal_in_slice_order_wins() {
        let caveats = [rel("alpha"), rel("beta")];
        // alpha is evaluated first and is unreleased, so it is the reported
        // refusal even though beta was released.
        assert_eq!(
            denied_code(
                release_check(&caveats, Audience::Teammate, Some("beta"), false).unwrap_err()
            ),
            "REL-alpha"
        );
        let released = [rel("alpha"), rel("beta")];
        assert!(release_check(&released, Audience::Teammate, Some("alpha"), false).is_err());
    }

    #[test]
    fn empty_caveats_never_restrict() {
        for audience in AUDIENCES {
            for role in [None, Some("alpha"), Some("")] {
                for approved in [false, true] {
                    assert!(
                        release_check(&[], audience, role, approved).is_ok(),
                        "no caveats must not restrict {audience}"
                    );
                }
            }
        }
    }

    #[test]
    fn role_matching_is_trimmed_and_exact() {
        let caveats = [rel("alpha")];
        // Released role is trimmed before comparison...
        assert!(release_check(&caveats, Audience::Public, Some("  alpha  "), false).is_ok());
        // ...but the comparison is exact (no prefix/containment)...
        assert!(release_check(&caveats, Audience::Public, Some("alphabet"), false).is_err());
        assert!(release_check(&caveats, Audience::Public, Some("alp"), false).is_err());
        // ...and an empty released role is never a release.
        assert!(release_check(&caveats, Audience::Public, Some(""), false).is_err());
        assert!(release_check(&caveats, Audience::Public, Some("   "), false).is_err());
        // The caveat's own role is likewise trimmed when matching.
        assert!(release_check(&[rel(" gamma ")], Audience::Public, Some("gamma"), false).is_ok());
    }

    #[test]
    fn empty_role_caveat_never_releases_but_operators_are_exempt() {
        let invalid = rel("   ");
        assert!(!invalid.is_valid());
        for audience in [Audience::Public, Audience::ThirdParty, Audience::Teammate] {
            assert!(
                release_check(&[invalid.clone()], audience, Some(""), false).is_err(),
                "empty-role caveat must not release to {audience}"
            );
            assert!(release_check(&[invalid.clone()], audience, Some("   "), true).is_err());
            assert!(release_check(&[invalid.clone()], audience, None, true).is_err());
        }
        // Operator stays exempt, consistent with the role rule.
        assert!(release_check(&[invalid.clone()], Audience::Operator, None, false).is_ok());
        // Other caveats report valid.
        assert!(Caveat::NoThirdParty.is_valid());
        assert!(Caveat::OriginatorControlled.is_valid());
        assert!(rel("alpha").is_valid());
        assert!(rel(" gamma ").is_valid());
    }

    #[test]
    fn marking_codes_order_and_empty() {
        assert_eq!(summary_marking(&[]), "NONE");
        assert_eq!(summary_marking(&[Caveat::NoThirdParty]), "NO-THIRD-PARTY");
        assert_eq!(summary_marking(&[Caveat::OriginatorControlled]), "ORCON");
        assert_eq!(summary_marking(&[rel("alpha")]), "REL-alpha");
        // Fixed class order, roles ascending — independent of input order.
        let expected = "NO-THIRD-PARTY/ORCON/REL-alpha/REL-zeta";
        let shuffles = [
            vec![rel("zeta"), Caveat::OriginatorControlled, rel("alpha"), Caveat::NoThirdParty],
            vec![Caveat::NoThirdParty, Caveat::OriginatorControlled, rel("alpha"), rel("zeta")],
            vec![rel("alpha"), rel("zeta"), Caveat::OriginatorControlled, Caveat::NoThirdParty],
        ];
        for set in shuffles {
            assert_eq!(summary_marking(&set), expected);
        }
    }

    #[test]
    fn marking_dedupes_and_shares_codes_with_caveat_code() {
        let dupes = [
            Caveat::NoThirdParty,
            Caveat::NoThirdParty,
            rel("alpha"),
            rel("alpha"),
        ];
        assert_eq!(summary_marking(&dupes), "NO-THIRD-PARTY/REL-alpha");
        // The per-caveat code is the token used in the marking.
        for c in [Caveat::NoThirdParty, Caveat::OriginatorControlled, rel("alpha")] {
            assert!(summary_marking(std::slice::from_ref(&c)).contains(&c.code()));
        }
        // Padded role spellings collapse to one code.
        assert_eq!(summary_marking(&[rel(" alpha "), rel("alpha")]), "REL-alpha");
        // A caveat with an empty-trimmed role renders bare REL- (restricts,
        // names nobody) and does not vanish from the marking.
        assert_eq!(summary_marking(&[rel("   ")]), "REL-");
    }

    #[test]
    fn marking_is_deterministic() {
        let set = [
            rel("zeta"),
            Caveat::NoThirdParty,
            rel("alpha"),
            Caveat::OriginatorControlled,
        ];
        let first = summary_marking(&set);
        for _ in 0..64 {
            assert_eq!(summary_marking(&set), first);
        }
    }

    #[test]
    fn serde_round_trip_caveats() {
        let all = [Caveat::NoThirdParty, Caveat::OriginatorControlled, rel("alpha")];
        for c in &all {
            let json = serde_json::to_string(c).unwrap();
            let back: Caveat = serde_json::from_str(&json).unwrap();
            assert_eq!(&back, c);
        }
        // Wire form is the variant name (stable for manifests/headers).
        assert_eq!(
            serde_json::to_string(&Caveat::NoThirdParty).unwrap(),
            "\"NoThirdParty\""
        );
        assert_eq!(
            serde_json::to_string(&Caveat::OriginatorControlled).unwrap(),
            "\"OriginatorControlled\""
        );
        assert_eq!(
            serde_json::to_value(rel("alpha")).unwrap(),
            serde_json::json!({"RoleReleasable": {"role": "alpha"}})
        );
        let list = serde_json::to_string(&all).unwrap();
        let back: Vec<Caveat> = serde_json::from_str(&list).unwrap();
        assert_eq!(back, all.to_vec());
    }

    #[test]
    fn serde_round_trip_denial_and_audit_record() {
        let err = release_check(&[Caveat::NoThirdParty], Audience::Public, None, false).unwrap_err();
        let json = serde_json::to_string(&err).unwrap();
        let back: CaveatError = serde_json::from_str(&json).unwrap();
        assert_eq!(back, err);

        let CaveatError::DeniedBy { caveat, audience } = &back;
        assert_eq!(caveat.as_str(), "NO-THIRD-PARTY");
        assert_eq!(audience.as_str(), "public");

        // An audit record for one refusal, end to end.
        let record = serde_json::json!({
            "event": "release_denied",
            "reason_code": back.code(),
            "caveat": caveat,
            "audience": audience,
            "message": back.to_string(),
        });
        assert_eq!(record["reason_code"], "deny.caveat");
        assert_eq!(record["caveat"], "NO-THIRD-PARTY");
    }

    #[test]
    fn denial_display_and_code_are_auditable() {
        let err = release_check(&[Caveat::OriginatorControlled], Audience::ThirdParty, None, false)
            .unwrap_err();
        assert_eq!(err.code(), "deny.caveat");
        let line = err.to_string();
        assert!(
            line.contains("denied") && line.contains("ORCON") && line.contains("third-party"),
            "display: {line}"
        );
        // Usable as a boxed std error.
        let boxed: Box<dyn std::error::Error> = Box::new(err);
        assert!(boxed.to_string().contains("ORCON"));
    }

    #[test]
    fn works_with_access_class_export_gate() {
        use crate::access_class::{check_export, AccessClass};
        // Class/export gate admits Open material to Public — but ORCON still
        // holds it back until the originator approves.
        assert!(check_export(AccessClass::Open, Audience::Public, false).is_ok());
        assert!(release_check(&[Caveat::OriginatorControlled], Audience::Public, None, false).is_err());
        assert!(release_check(&[Caveat::OriginatorControlled], Audience::Public, None, true).is_ok());
        // Caveats never widen what the class gate refused.
        assert!(check_export(AccessClass::Sealed, Audience::Public, false).is_err());
        assert!(release_check(&[], Audience::Public, None, true).is_ok());
    }

    #[test]
    fn full_matrix_is_deterministic() {
        let sets: Vec<Vec<Caveat>> = vec![
            vec![],
            vec![Caveat::NoThirdParty],
            vec![Caveat::OriginatorControlled],
            vec![rel("alpha")],
            vec![Caveat::NoThirdParty, Caveat::OriginatorControlled, rel("alpha")],
        ];
        let roles = [None, Some("alpha"), Some("beta"), Some("")];
        let approvals = [false, true];
        let mut answers: Vec<(usize, usize, usize, usize, bool)> = Vec::new();
        let mut empty_all_ok = true;
        for (si, set) in sets.iter().enumerate() {
            for (ai, audience) in AUDIENCES.iter().enumerate() {
                for (ri, role) in roles.iter().enumerate() {
                    for (pi, approved) in approvals.iter().enumerate() {
                        let ok = release_check(set, *audience, *role, *approved).is_ok();
                        if si == 0 {
                            empty_all_ok &= ok;
                        }
                        answers.push((si, ai, ri, pi, ok));
                    }
                }
            }
        }
        for (si, ai, ri, pi, ok) in &answers {
            let again =
                release_check(&sets[*si], AUDIENCES[*ai], roles[*ri], approvals[*pi]).is_ok();
            assert_eq!(
                *ok, again,
                "nondeterministic at set={si} audience={ai} role={ri} approved={pi}"
            );
        }
        assert!(empty_all_ok, "an empty caveat list must never refuse");
    }
}
