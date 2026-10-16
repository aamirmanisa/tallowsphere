//! Compile-time `@tier` gate engine (task B1.1.2; spec `docs/tiers/TIER_GATE.md` §2).
//!
//! This module is the **engine + contract** for the `@tier` build gate. A build
//! unit (program / profile) declares its competence tier with `@tier(scout)` …
//! `@tier(vault_admin)` (first declaration wins); the gate checks the module
//! references collected for the unit against [`crate::tiers::module_allowed`]
//! and reports a deterministic [`GateReport`]. The pass hook that calls
//! [`check_build`] lives in [`crate::tier_gate_pass`] — the per-file annotation
//! pass plus the build-level runner (T-123) — and is wired into the compiler
//! pipeline at entry-file scope (Phases 28b/28c, `src/main.rs`); multi-file
//! import-graph collection and a ledger-backed waiver record store are the
//! remaining follow-ups. The engine itself stays pure: no I/O, no clock
//! (callers stamp `now_ms`), no globals; the parent declares the module.
//!
//! # Gate rule (TIER_GATE.md §2.2)
//! - [`parse_tier_word`] accepts exactly the four `Tier::word()` values; any
//!   other declaration word (or none) is **default-tightest**: a missing
//!   `@tier` behaves as [`crate::tiers::Tier::Scout`] (fewest modules) and an
//!   *invalid* word is a hard error ([`CODE_BAD_TIER_DECLARATION`], `E6003`)
//!   that also falls back to Scout for the remainder of the check.
//! - Every referenced module is resolved against the `TIER_MODULES` table:
//!   a module in **no** tier slice (typo, removed, not-yet-classified) is an
//!   error ([`CODE_UNKNOWN_MODULE`], `E6002`) — **no fallback allow**, exact
//!   match, case- and whitespace-sensitive (mirrors `module_allowed`).
//! - A known module the declared tier may not use is an error
//!   ([`CODE_MODULE_NOT_PERMITTED`], `E6001`) naming the module, the tier that
//!   would minimally permit it, the declared tier, and the remediation options
//!   (drop the module, split the build unit, or obtain a recorded escape hatch).
//! - A recorded waiver in force — `build_unit` matches, the module is listed,
//!   and `expires_ms > now_ms` (§3.3: expiry is a hard boundary, evaluated
//!   *at or after* `expires_at` ⇒ deny) — admits the reference and emits the
//!   waiver warning [`CODE_WAIVER_IN_USE`] (`W6001`): no build uses an
//!   exception silently.
//! - A `claimed_waiver_id` with **no** record, or only expired records, is an
//!   error ([`CODE_WAIVER_RECORD_MISSING`], `E6005`, "record missing or
//!   expired") — the trail-or-deny posture of §3.6: absence of a grant is
//!   denial, never an allow.
//!
//! # Waiver model
//! A [`Waiver`] is the *gate-visible projection* of a granted escape hatch
//! (policy in TIER_GATE.md §3): id, exactly one build unit, the module set it
//! raises, and a mandatory expiry. There are no perpetual waivers; the record
//! system is the source of truth and the gate honors only a live, complete,
//! matching grant. This module does **not** model review, renewal caps, or the
//! refusal log — that is ledger/policy territory; the gate consumes the grant.
//!
//! # Diagnostic codes (free `E6xxx`/`W6xxx` range, verified free at assignment)
//! | code | kind | meaning |
//! |---|---|---|
//! | `E6001` | error | module not permitted at the declared tier (no waiver in force) |
//! | `E6002` | error | module not in any tier slice — unknown, no fallback allow |
//! | `E6003` | error | invalid `@tier` declaration word (check falls back to Scout) |
//! | `E6004` | — | *reserved* (unused in this revision; keeps the block contiguous) |
//! | `E6005` | error | claimed waiver record missing or expired |
//! | `W6001` | warning | module admitted by a recorded waiver that is in force |
//!
//! Diagnostics are emitted sorted by `(module, then code)` and deduplicated on
//! `(module, code, message)`, so the report is deterministic for any input
//! ordering. Declaration-level diagnostics (E6003, E6005) carry an empty
//! `module` field and therefore sort first; the detail lives in `message`.
//! `GateReport::ok` is exactly `errors.is_empty()` — warnings never block a
//! build, but they are never silent either.
//!
//! # Relation to the other gates
//! This gate decides which sensitive modules *exist* for a build/profile; it
//! complements — does not replace — the per-function `@legal` (`E0100`),
//! `@stealth` (`E0400–E0404`), and `@cra_class` (`W1900`/`E1900–E1903`) gates.
//! Runtime tier checks keep [`crate::tiers::module_allowed`] as the single
//! authorization query (defense in depth; no runtime call site is wired yet):
//! a compile-time pass never authorizes a runtime call whose tier check fails.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::tiers::{module_allowed, Tier};

/// `E6001` — a referenced module is not permitted at the declared tier and no
/// waiver in force covers it. Remediation is named in the message.
pub const CODE_MODULE_NOT_PERMITTED: &str = "E6001";

/// `E6002` — a referenced module appears in no tier slice: unknown module
/// (typo, removed, not-yet-classified). Denied; never allowed by fallback.
pub const CODE_UNKNOWN_MODULE: &str = "E6002";

/// `E6003` — the `@tier` declaration word is not one of `Tier::word()`'s.
/// The check continues at Scout (default-tightest) after emitting this.
pub const CODE_BAD_TIER_DECLARATION: &str = "E6003";

/// `E6005` — a `@tier_waiver(id: …)` claim whose record is missing, or exists
/// only in expired form ("record missing or expired"). Absence of a grant is
/// denial (§3.6).
pub const CODE_WAIVER_RECORD_MISSING: &str = "E6005";

/// `W6001` — a reference was admitted by a recorded waiver that is in force;
/// emitted per admitted module so no build uses an exception silently (§3.5).
pub const CODE_WAIVER_IN_USE: &str = "W6001";

/// Resolve a `@tier` declaration word to a tier — **exact match** against
/// [`Tier::word`] (`"scout"`, `"analyst"`, `"operator"`, `"vault_admin"`).
///
/// Case- and whitespace-sensitive: `"VaultAdmin"`, `"vault_admin "`, `"sco"`,
/// and `""` all return `None`. Callers treat `None` as default-tightest
/// (`Tier::Scout`) — see [`check_build`].
pub fn parse_tier_word(w: &str) -> Option<Tier> {
    Tier::ALL.iter().copied().find(|t| t.word() == w)
}

/// The lowest tier whose slice contains `module` — the tier that would
/// *minimally permit* it, derived from [`crate::tiers::TIER_MODULES`].
///
/// `None` iff `module` appears in no tier slice (unknown module: denied with
/// no fallback allow).
pub fn min_tier_for(module: &str) -> Option<Tier> {
    // Slices are cumulative and listed in ascending rank, so the first hit is
    // the minimal permitting tier.
    Tier::ALL
        .iter()
        .copied()
        .find(|t| module_allowed(*t, module))
}

/// Is `module` classified in any tier slice? Exact match; `false` ⇒ the gate
/// denies it with `E6002`.
pub fn is_known_module(module: &str) -> bool {
    min_tier_for(module).is_some()
}

/// Gate-visible projection of a granted tier waiver (policy: `TIER_GATE.md` §3).
///
/// `build_unit` is the single build unit the grant is scoped to (§3.1: scope is
/// exactly one build unit); `modules` is the module set the grant raises;
/// `expires_ms` is the mandatory expiry stamp (monotonic ledger-derived in the
/// full policy model; the gate compares it against the caller's `now_ms`).
/// There is no perpetual waiver: an expired record is indistinguishable from
/// no record at the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Waiver {
    /// Grant id as recorded (`@tier_waiver(id: …)` claims reference this).
    pub id: String,
    /// The one build unit this grant is scoped to.
    pub build_unit: String,
    /// Modules the grant raises. Empty ⇒ covers nothing (deny).
    pub modules: Vec<String>,
    /// Mandatory expiry (ms). `expires_ms > now_ms` ⇔ live; at/after ⇒ denied.
    pub expires_ms: i64,
}

impl Waiver {
    /// Is the grant live at `now_ms`? Hard boundary: expiry at or after
    /// `expires_ms` denies (missing/stale record ⇒ absence of grant ⇒ deny).
    pub fn is_live(&self, now_ms: i64) -> bool {
        self.expires_ms > now_ms
    }

    /// Does this live grant cover `module` for `build_unit`? Requires the
    /// live record, an exact build-unit match, and the module listed.
    pub fn covers(&self, build_unit: &str, module: &str, now_ms: i64) -> bool {
        self.is_live(now_ms)
            && self.build_unit == build_unit
            && self.modules.iter().any(|m| m == module)
    }
}

/// One gate diagnostic: `code` (`E6xxx`/`W6xxx`), the `module` it concerns
/// (empty for declaration-level diagnostics), and a human `message` naming the
/// facts and the remediation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TierDiagnostic {
    /// Diagnostic code (`E6001`/`E6002`/`E6003`/`E6005`/`W6001`).
    pub code: String,
    /// The module concerned; `""` for build-unit/declaration-level diagnostics.
    pub module: String,
    /// Human-readable detail (names tier, minimal permitting tier, waiver id…).
    pub message: String,
}

impl fmt::Display for TierDiagnostic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.module.is_empty() {
            write!(f, "{}: {}", self.code, self.message)
        } else {
            write!(f, "{} [{}]: {}", self.code, self.module, self.message)
        }
    }
}

/// The gate's verdict for one build unit: `ok` iff no errors; the resolved
/// `tier` (missing/invalid declaration ⇒ Scout); sorted, deduplicated
/// `errors` and `warnings`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateReport {
    /// `true` iff `errors` is empty — warnings never block a build.
    pub ok: bool,
    /// The tier the check ran at (default-tightest on missing/invalid input).
    pub tier: Tier,
    /// Blocking diagnostics, sorted by `(module, code)`.
    pub errors: Vec<TierDiagnostic>,
    /// Non-blocking diagnostics (waiver use), sorted by `(module, code)`.
    pub warnings: Vec<TierDiagnostic>,
}

impl GateReport {
    /// Deterministic multi-line rendering for the compile log. Header first,
    /// then errors, then warnings, each sorted as stored. No timestamps.
    pub fn render(&self) -> String {
        let mut out = format!(
            "tier={} ok={} errors={} warnings={}\n",
            self.tier.word(),
            self.ok,
            self.errors.len(),
            self.warnings.len()
        );
        for d in &self.errors {
            out.push_str(&format!("error {d}\n"));
        }
        for d in &self.warnings {
            out.push_str(&format!("warning {d}\n"));
        }
        out
    }
}

impl fmt::Display for GateReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

fn diag(code: &str, module: &str, message: String) -> TierDiagnostic {
    TierDiagnostic {
        code: code.to_string(),
        module: module.to_string(),
        message,
    }
}

/// Sort by `(module, code)` (message as final tiebreak so dedup is total) and
/// drop exact duplicates. Deterministic for any input ordering.
fn sort_and_dedupe(mut v: Vec<TierDiagnostic>) -> Vec<TierDiagnostic> {
    v.sort_by(|a, b| {
        (&a.module, &a.code, &a.message).cmp(&(&b.module, &b.code, &b.message))
    });
    v.dedup();
    v
}

/// Run the `@tier` gate for one build unit (TIER_GATE.md §2.2).
///
/// - `declared` — the `@tier(…)` word, or `None` when the build carries no
///   declaration (⇒ Scout, default-tightest).
/// - `referenced_modules` — every static reference into a gated module.
/// - `waivers` — the recorded grants visible to this build (the gate honors
///   only live, build-unit-matching, module-listing records).
/// - `claimed_waiver_ids` — ids claimed by `@tier_waiver(id: …)` annotations;
///   each must resolve to a live record, else `E6005`.
///
/// Returns a [`GateReport`] with `ok = errors.is_empty()`. Pure and
/// deterministic: same inputs ⇒ identical report, in any input ordering.
pub fn check_build(
    build_unit: &str,
    declared: Option<&str>,
    referenced_modules: &[&str],
    waivers: &[Waiver],
    claimed_waiver_ids: &[String],
    now_ms: i64,
) -> GateReport {
    let mut errors: Vec<TierDiagnostic> = Vec::new();
    let mut warnings: Vec<TierDiagnostic> = Vec::new();

    // 1 · Resolve the declaration. Missing ⇒ Scout. Invalid ⇒ E6003 + Scout
    //     (an unusable declaration can never widen anything).
    let tier = match declared {
        None => Tier::Scout,
        Some(word) => match parse_tier_word(word) {
            Some(t) => t,
            None => {
                errors.push(diag(
                    CODE_BAD_TIER_DECLARATION,
                    "",
                    format!(
                        "build unit {:?}: invalid @tier word {:?} (expected one of \
                         scout|analyst|operator|vault_admin, matching Tier::word()); \
                         defaulting to scout (tightest)",
                        build_unit, word
                    ),
                ));
                Tier::Scout
            }
        },
    };

    // 2 · Audit every claimed waiver id: each must resolve to a live record.
    //     Dedupe claims so a repeated id yields one diagnostic.
    let mut seen: Vec<&str> = Vec::new();
    for id in claimed_waiver_ids {
        if seen.contains(&id.as_str()) {
            continue;
        }
        seen.push(id.as_str());
        let live = waivers
            .iter()
            .any(|w| w.id == *id && w.is_live(now_ms));
        if !live {
            errors.push(diag(
                CODE_WAIVER_RECORD_MISSING,
                "",
                format!(
                    "build unit {:?}: claimed waiver {:?}: record missing or expired",
                    build_unit, id
                ),
            ));
        }
    }

    // 3 · Check every referenced module.
    for m in referenced_modules {
        let Some(min) = min_tier_for(m) else {
            errors.push(diag(
                CODE_UNKNOWN_MODULE,
                m,
                format!(
                    "module {:?} appears in no tier slice (TIER_MODULES): unknown modules \
                     are denied with no fallback allow — check the spelling or classify \
                     it in TIER_MODULES",
                    m
                ),
            ));
            continue;
        };
        if module_allowed(tier, m) {
            continue; // permitted at the declared tier
        }
        match waivers.iter().find(|w| w.covers(build_unit, m, now_ms)) {
            Some(w) => warnings.push(diag(
                CODE_WAIVER_IN_USE,
                m,
                format!(
                    "module {:?} is not permitted at tier {} but is admitted for build \
                     unit {:?} by recorded waiver {:?} (expires {} ms) — the build \
                     carries its exception loudly",
                    m,
                    tier.word(),
                    build_unit,
                    w.id,
                    w.expires_ms
                ),
            )),
            None => errors.push(diag(
                CODE_MODULE_NOT_PERMITTED,
                m,
                format!(
                    "module {:?} is not permitted at tier {} (minimal permitting tier: \
                     {}) — drop the module, split the build unit, or obtain a recorded \
                     tier waiver (see docs/tiers/TIER_GATE.md §3)",
                    m,
                    tier.word(),
                    min.word()
                ),
            )),
        }
    }

    let errors = sort_and_dedupe(errors);
    let warnings = sort_and_dedupe(warnings);
    let ok = errors.is_empty();
    GateReport {
        ok,
        tier,
        errors,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tiers::{modules_for, Tier};

    const SCOUT_SLICE: [&str; 5] = [
        "caveats",
        "injection_scan",
        "ledger_events",
        "raw_store",
        "source_registry",
    ];
    const ANALYST_ONLY: [&str; 14] = [
        "access_class",
        "calibration",
        "claim_typing",
        "corroboration",
        "degraded_gate",
        "derived_store",
        "disconfirmation",
        "forecast",
        "gap_register",
        "link_chain",
        "premortem",
        "regrade",
        "requirements",
        "retention",
    ];
    const OPERATOR_ONLY: [&str; 19] = [
        "agent_ledger",
        "agent_ledger_sqlite",
        "canary_monitor",
        "canary_tokens",
        "decoy_flags",
        "fixity",
        "fixity_job",
        "harm_review",
        "hndl",
        "ledger_replay",
        "ledger_verify",
        "ops_gate",
        "opsec_gates",
        "persona",
        "redaction",
        "replication",
        "replication_plan",
        "retro",
        "shred",
    ];

    fn codes(ds: &[TierDiagnostic]) -> Vec<&str> {
        ds.iter().map(|d| d.code.as_str()).collect()
    }

    fn modules(ds: &[TierDiagnostic]) -> Vec<&str> {
        ds.iter().map(|d| d.module.as_str()).collect()
    }

    fn live_waiver(id: &str, unit: &str, mods: &[&str], expires_ms: i64) -> Waiver {
        Waiver {
            id: id.to_string(),
            build_unit: unit.to_string(),
            modules: mods.iter().map(|s| s.to_string()).collect(),
            expires_ms,
        }
    }

    // ---- parse_tier_word -------------------------------------------------

    #[test]
    fn parse_tier_word_pins_all_four_words() {
        assert_eq!(parse_tier_word("scout"), Some(Tier::Scout));
        assert_eq!(parse_tier_word("analyst"), Some(Tier::Analyst));
        assert_eq!(parse_tier_word("operator"), Some(Tier::Operator));
        assert_eq!(parse_tier_word("vault_admin"), Some(Tier::VaultAdmin));
        // parse_tier_word is exactly the Tier::word() inverse over Tier::ALL.
        for t in Tier::ALL {
            assert_eq!(parse_tier_word(t.word()), Some(t));
        }
    }

    #[test]
    fn parse_tier_word_rejects_typos_case_and_whitespace() {
        for bad in [
            "",
            " scout",
            "scout ",
            "Scout",
            "SCOUT",
            "VaultAdmin",
            "vaultadmin",
            "vault-admin",
            "vault admin",
            "sco",
            "admin",
            "boss",
            "scout\n",
        ] {
            assert_eq!(parse_tier_word(bad), None, "{bad:?} must not parse");
        }
    }

    #[test]
    fn min_tier_for_pins_minimal_permitting_tiers() {
        for m in SCOUT_SLICE {
            assert_eq!(min_tier_for(m), Some(Tier::Scout), "{m}");
        }
        for m in ANALYST_ONLY {
            assert_eq!(min_tier_for(m), Some(Tier::Analyst), "{m}");
        }
        for m in OPERATOR_ONLY {
            assert_eq!(min_tier_for(m), Some(Tier::Operator), "{m}");
        }
        assert_eq!(min_tier_for("vault"), Some(Tier::VaultAdmin));
        assert_eq!(min_tier_for("key_ledger"), Some(Tier::VaultAdmin));
        assert_eq!(min_tier_for("personna"), None);
        assert_eq!(min_tier_for("Vault"), None);
        assert_eq!(min_tier_for("vault "), None);
        assert_eq!(min_tier_for(""), None);
    }

    // ---- acceptance pins (TIER_GATE.md §2.3) -----------------------------

    #[test]
    fn scout_build_compiles_exactly_the_five_module_slice() {
        let r = check_build("b-scout", Some("scout"), &SCOUT_SLICE, &[], &[], 1_000);
        assert!(r.ok, "errors: {:?}", r.errors);
        assert!(r.errors.is_empty());
        assert!(r.warnings.is_empty());
        assert_eq!(r.tier, Tier::Scout);
        assert_eq!(modules_for(Tier::Scout).len(), 5, "Scout slice pinned at 5");
    }

    #[test]
    fn scout_build_errors_on_analyst_only_refs() {
        let r = check_build(
            "b-scout",
            Some("scout"),
            &["raw_store", "forecast", "access_class"],
            &[],
            &[],
            1_000,
        );
        assert!(!r.ok);
        assert_eq!(codes(&r.errors), vec![CODE_MODULE_NOT_PERMITTED; 2]);
        assert_eq!(modules(&r.errors), vec!["access_class", "forecast"]);
        // E6001 names the minimal permitting tier and the declared tier.
        for d in &r.errors {
            assert!(d.message.contains("analyst"), "{}", d.message);
            assert!(d.message.contains("scout"), "{}", d.message);
            assert!(d.message.contains("drop the module"), "{}", d.message);
        }
    }

    #[test]
    fn rung_19_analyst_full_slice_compiles_and_operator_ref_errors() {
        let slice = modules_for(Tier::Analyst);
        assert_eq!(slice.len(), 19, "Analyst cumulative slice pinned at 19");
        let r = check_build("b-a", Some("analyst"), slice, &[], &[], 0);
        assert!(r.ok, "errors: {:?}", r.errors);
        assert_eq!(r.tier, Tier::Analyst);

        let r = check_build("b-a", Some("analyst"), &["persona"], &[], &[], 0);
        assert!(!r.ok);
        assert_eq!(codes(&r.errors), vec![CODE_MODULE_NOT_PERMITTED]);
        assert_eq!(modules(&r.errors), vec!["persona"]);
        assert!(r.errors[0].message.contains("operator"), "{}", r.errors[0].message);
    }

    #[test]
    fn rung_38_operator_full_slice_compiles_and_vault_ref_errors() {
        let slice = modules_for(Tier::Operator);
        assert_eq!(slice.len(), 38, "Operator cumulative slice pinned at 38");
        let r = check_build("b-o", Some("operator"), slice, &[], &[], 0);
        assert!(r.ok, "errors: {:?}", r.errors);
        assert_eq!(r.tier, Tier::Operator);

        let r = check_build("b-o", Some("operator"), &["vault", "key_ledger"], &[], &[], 0);
        assert!(!r.ok);
        assert_eq!(modules(&r.errors), vec!["key_ledger", "vault"]);
        for d in &r.errors {
            assert!(d.message.contains("vault_admin"), "{}", d.message);
        }
    }

    #[test]
    fn rung_40_vault_admin_full_slice_compiles() {
        let slice = modules_for(Tier::VaultAdmin);
        assert_eq!(slice.len(), 40, "VaultAdmin cumulative slice pinned at 40");
        let r = check_build("b-v", Some("vault_admin"), slice, &[], &[], 0);
        assert!(r.ok, "errors: {:?}", r.errors);
        assert!(r.errors.is_empty() && r.warnings.is_empty());
        assert_eq!(r.tier, Tier::VaultAdmin);
    }

    #[test]
    fn vault_and_key_ledger_are_vault_admin_only() {
        for m in ["vault", "key_ledger"] {
            let ok = check_build("b-v", Some("vault_admin"), &[m], &[], &[], 0);
            assert!(ok.ok, "{m} must compile at vault_admin: {:?}", ok.errors);
            for lower in ["scout", "analyst", "operator"] {
                let r = check_build("b-l", Some(lower), &[m], &[], &[], 0);
                assert!(!r.ok, "{lower} must be denied {m}");
                assert_eq!(codes(&r.errors), vec![CODE_MODULE_NOT_PERMITTED]);
                assert_eq!(modules(&r.errors), vec![m]);
                assert!(r.errors[0].message.contains("vault_admin"));
            }
        }
    }

    #[test]
    fn missing_declaration_is_scout() {
        let r = check_build("b-none", None, &SCOUT_SLICE, &[], &[], 0);
        assert!(r.ok);
        assert_eq!(r.tier, Tier::Scout, "missing @tier ⇒ Scout (tightest)");
        // …and Scout's slice is exactly what a declaration-less build gets.
        let denied = check_build("b-none", None, &["forecast"], &[], &[], 0);
        assert!(!denied.ok);
        assert_eq!(codes(&denied.errors), vec![CODE_MODULE_NOT_PERMITTED]);
        assert_eq!(denied.tier, Tier::Scout);
    }

    #[test]
    fn invalid_tier_word_errors_e6003_and_checks_at_scout() {
        let r = check_build("b-bad", Some("boss"), &SCOUT_SLICE, &[], &[], 0);
        assert!(!r.ok);
        assert_eq!(r.tier, Tier::Scout, "invalid word falls back tightest");
        assert_eq!(codes(&r.errors), vec![CODE_BAD_TIER_DECLARATION]);
        assert_eq!(r.errors[0].module, "", "declaration-level diagnostic");
        assert!(r.errors[0].message.contains("boss"));
        assert!(r.errors[0].message.contains("scout"));

        // A Scout-legal reference stays legal under the fallback; an
        // Analyst-only one stays denied (an unusable word widens nothing).
        let mixed = check_build("b-bad", Some("analystt"), &["raw_store", "forecast"], &[], &[], 0);
        assert!(!mixed.ok);
        assert_eq!(
            codes(&mixed.errors),
            vec![CODE_BAD_TIER_DECLARATION, CODE_MODULE_NOT_PERMITTED]
        );
        assert_eq!(modules(&mixed.errors), vec!["", "forecast"]);
    }

    #[test]
    fn unknown_module_errors_with_no_fallback_allow() {
        for bad in ["personna", "Persona", "vault ", " vault", "Vault", "definitely_not_a_module", ""] {
            let r = check_build("b-u", Some("vault_admin"), &[bad], &[], &[], 0);
            assert!(!r.ok, "{bad:?} must be denied even at vault_admin");
            assert_eq!(codes(&r.errors), vec![CODE_UNKNOWN_MODULE], "{bad:?}");
            assert_eq!(modules(&r.errors), vec![bad]);
            assert!(r.errors[0].message.contains("no fallback allow"));
        }
    }

    // ---- waiver model ----------------------------------------------------

    #[test]
    fn waiver_in_force_compiles_and_warns_w6001() {
        let w = live_waiver("w-1", "b-stealth", &["persona"], 2_000);
        let r = check_build(
            "b-stealth",
            Some("scout"),
            &["raw_store", "persona"],
            &[w],
            &["w-1".to_string()],
            1_000,
        );
        assert!(r.ok, "errors: {:?}", r.errors);
        assert!(r.errors.is_empty());
        assert_eq!(codes(&r.warnings), vec![CODE_WAIVER_IN_USE]);
        assert_eq!(modules(&r.warnings), vec!["persona"]);
        assert!(r.warnings[0].message.contains("w-1"));
    }

    #[test]
    fn waiver_expiry_boundary_is_at_or_after_deny() {
        let expires = 2_000;
        // now < expires ⇒ live ⇒ admitted + W6001.
        let before = check_build(
            "b-w",
            Some("scout"),
            &["persona"],
            &[live_waiver("w-1", "b-w", &["persona"], expires)],
            &[],
            expires - 1,
        );
        assert!(before.ok, "errors: {:?}", before.errors);
        assert_eq!(codes(&before.warnings), vec![CODE_WAIVER_IN_USE]);
        // now == expires ⇒ expired (hard boundary) ⇒ E6001, no warning.
        let at = check_build(
            "b-w",
            Some("scout"),
            &["persona"],
            &[live_waiver("w-1", "b-w", &["persona"], expires)],
            &[],
            expires,
        );
        assert!(!at.ok);
        assert_eq!(codes(&at.errors), vec![CODE_MODULE_NOT_PERMITTED]);
        assert!(at.warnings.is_empty());
        // now > expires ⇒ same denial.
        let after = check_build(
            "b-w",
            Some("scout"),
            &["persona"],
            &[live_waiver("w-1", "b-w", &["persona"], expires)],
            &[],
            expires + 1,
        );
        assert!(!after.ok);
        assert_eq!(codes(&after.errors), vec![CODE_MODULE_NOT_PERMITTED]);
    }

    #[test]
    fn waiver_scoped_to_another_build_unit_does_not_cover() {
        let w = live_waiver("w-1", "b-other", &["persona"], 10_000);
        let r = check_build("b-mine", Some("scout"), &["persona"], &[w], &[], 1_000);
        assert!(!r.ok, "scope is exactly one build unit");
        assert_eq!(codes(&r.errors), vec![CODE_MODULE_NOT_PERMITTED]);
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn waiver_not_listing_the_module_does_not_cover() {
        let w = live_waiver("w-1", "b-mine", &["shred"], 10_000);
        let r = check_build("b-mine", Some("scout"), &["persona"], &[w], &[], 1_000);
        assert!(!r.ok);
        assert_eq!(codes(&r.errors), vec![CODE_MODULE_NOT_PERMITTED]);
    }

    #[test]
    fn waiver_never_admits_an_unknown_module() {
        let w = live_waiver("w-1", "b-mine", &["personna"], 10_000);
        let r = check_build("b-mine", Some("scout"), &["personna"], &[w], &[], 1_000);
        assert!(!r.ok, "unknown stays unknown: a waiver raises grants, not classifications");
        assert_eq!(codes(&r.errors), vec![CODE_UNKNOWN_MODULE]);
        assert!(r.warnings.is_empty());
    }

    #[test]
    fn claimed_waiver_live_record_is_clean() {
        let w = live_waiver("w-1", "b-mine", &["persona"], 10_000);
        let r = check_build(
            "b-mine",
            Some("scout"),
            &["persona"],
            &[w],
            &["w-1".to_string(), "w-1".to_string()],
            1_000,
        );
        assert!(r.ok);
        assert!(r.errors.is_empty(), "repeated claim deduped, live record: {:?}", r.errors);
        assert_eq!(codes(&r.warnings), vec![CODE_WAIVER_IN_USE]);
    }

    #[test]
    fn claimed_waiver_missing_or_expired_errors_e6005() {
        // No record at all.
        let missing = check_build(
            "b-mine",
            Some("scout"),
            &[],
            &[],
            &["w-9".to_string()],
            1_000,
        );
        assert!(!missing.ok);
        assert_eq!(codes(&missing.errors), vec![CODE_WAIVER_RECORD_MISSING]);
        assert_eq!(missing.errors[0].module, "");
        assert!(missing.errors[0].message.contains("record missing or expired"));
        assert!(missing.errors[0].message.contains("w-9"));

        // Only an expired record.
        let expired = check_build(
            "b-mine",
            Some("scout"),
            &[],
            &[live_waiver("w-9", "b-mine", &["persona"], 1_000)],
            &["w-9".to_string()],
            1_000,
        );
        assert!(!expired.ok);
        assert_eq!(codes(&expired.errors), vec![CODE_WAIVER_RECORD_MISSING]);
        assert!(expired.errors[0].message.contains("record missing or expired"));

        // A live record for the same id clears it.
        let live = check_build(
            "b-mine",
            Some("scout"),
            &[],
            &[live_waiver("w-9", "b-mine", &["persona"], 2_000)],
            &["w-9".to_string()],
            1_000,
        );
        assert!(live.ok, "errors: {:?}", live.errors);
        assert!(live.warnings.is_empty(), "no reference ⇒ no W6001");
    }

    // ---- shape / determinism / serde ------------------------------------

    #[test]
    fn diagnostics_sorted_by_module_then_code() {
        let r = check_build(
            "b-s",
            Some("scout"),
            &["persona", "zzz_unknown", "forecast", "aaa_unknown"],
            &[],
            &["w-b".to_string(), "w-a".to_string()],
            0,
        );
        assert!(!r.ok);
        // E6005 claims carry module "" and sort first, by message.
        let sorted: Vec<(&str, &str)> = r
            .errors
            .iter()
            .map(|d| (d.module.as_str(), d.code.as_str()))
            .collect();
        let mut expect = sorted.clone();
        expect.sort();
        assert_eq!(sorted, expect, "errors must be (module, code)-sorted");
        assert_eq!(
            sorted,
            vec![
                ("", CODE_WAIVER_RECORD_MISSING),
                ("", CODE_WAIVER_RECORD_MISSING),
                ("aaa_unknown", CODE_UNKNOWN_MODULE),
                ("forecast", CODE_MODULE_NOT_PERMITTED),
                ("persona", CODE_MODULE_NOT_PERMITTED),
                ("zzz_unknown", CODE_UNKNOWN_MODULE),
            ]
        );
    }

    #[test]
    fn determinism_and_input_order_invariance() {
        let waivers = [live_waiver("w-1", "b-d", &["persona"], 5_000)];
        let base = check_build(
            "b-d",
            Some("operator"),
            &["persona", "vault", "raw_store", "nope"],
            &waivers,
            &[],
            1_000,
        );
        let again = check_build(
            "b-d",
            Some("operator"),
            &["persona", "vault", "raw_store", "nope"],
            &waivers,
            &[],
            1_000,
        );
        assert_eq!(base, again, "same inputs ⇒ identical report");
        // Persona is allowed at operator; vault denied; nope unknown.
        assert_eq!(modules(&base.errors), vec!["nope", "vault"]);

        let permuted = check_build(
            "b-d",
            Some("operator"),
            &["nope", "vault", "raw_store", "persona"],
            &waivers,
            &[],
            1_000,
        );
        assert_eq!(base, permuted, "report is invariant to reference order");
        assert_eq!(base.render(), permuted.render());

        // render() is deterministic and mentions the counts.
        let text = base.render();
        assert!(text.starts_with("tier=operator ok=false errors=2 warnings=0\n"));
        assert_eq!(text, base.render());
    }

    #[test]
    fn serde_roundtrips_pin_words_and_codes() {
        let w = live_waiver("w-1", "b-mine", &["persona"], 2_000);
        let json = serde_json::to_string(&w).unwrap();
        assert!(json.contains("\"id\":\"w-1\""), "{json}");
        assert!(json.contains("\"build_unit\":\"b-mine\""), "{json}");
        assert!(json.contains("\"expires_ms\":2000"), "{json}");
        assert_eq!(serde_json::from_str::<Waiver>(&json).unwrap(), w);

        let d = TierDiagnostic {
            code: CODE_MODULE_NOT_PERMITTED.to_string(),
            module: "persona".to_string(),
            message: "not permitted at tier scout".to_string(),
        };
        let json = serde_json::to_string(&d).unwrap();
        assert!(json.contains("\"code\":\"E6001\""), "{json}");
        assert_eq!(serde_json::from_str::<TierDiagnostic>(&json).unwrap(), d);

        let r = check_build("b-mine", Some("scout"), &["persona"], &[w], &[], 1_000);
        assert!(r.ok);
        let json = serde_json::to_string(&r).unwrap();
        assert!(json.contains("\"tier\":\"scout\""), "tier uses Tier serde words: {json}");
        assert!(json.contains("\"ok\":true"), "{json}");
        assert!(json.contains("\"code\":\"W6001\""), "{json}");
        let back: GateReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn waiver_helpers_pin_liveness_and_coverage() {
        let w = live_waiver("w-1", "b-x", &["persona", "vault"], 1_000);
        assert!(w.is_live(999));
        assert!(!w.is_live(1_000), "hard boundary: at expires_ms ⇒ not live");
        assert!(!w.is_live(1_001));
        assert!(w.covers("b-x", "persona", 999));
        assert!(w.covers("b-x", "vault", 999));
        assert!(!w.covers("b-y", "persona", 999), "build-unit scope is exact");
        assert!(!w.covers("b-x", "personna", 999), "module match is exact");
        assert!(!w.covers("b-x", "persona", 1_000), "expired ⇒ covers nothing");
    }

    #[test]
    fn empty_reference_list_is_ok_at_every_rung() {
        for t in Tier::ALL {
            let r = check_build("b-empty", Some(t.word()), &[], &[], &[], -1);
            assert!(r.ok);
            assert_eq!(r.tier, t);
            assert!(r.errors.is_empty() && r.warnings.is_empty());
        }
    }

    #[test]
    fn known_module_helper_agrees_with_slices() {
        for t in Tier::ALL {
            for m in modules_for(t) {
                assert!(is_known_module(m), "{m} is classified");
                assert_eq!(min_tier_for(m).map(|t| t.rank()).unwrap_or(9) <= t.rank(), true);
            }
        }
        assert!(!is_known_module("personna"));
        assert!(!is_known_module(""));
    }

    #[test]
    fn diagnostic_display_is_readable_and_stable() {
        let d = TierDiagnostic {
            code: CODE_UNKNOWN_MODULE.to_string(),
            module: "personna".to_string(),
            message: "denied".to_string(),
        };
        assert_eq!(d.to_string(), "E6002 [personna]: denied");
        let decl = TierDiagnostic {
            code: CODE_BAD_TIER_DECLARATION.to_string(),
            module: String::new(),
            message: "invalid word".to_string(),
        };
        assert_eq!(decl.to_string(), "E6003: invalid word");
    }
}
