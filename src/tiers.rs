//! Competence-tier model and module mapping (task B1.1.1, frozen interface §8).
//!
//! Tallow agents operate at one of four competence tiers. The tiers form a
//! strictly monotone ladder of authority:
//!
//! ```text
//! rank 0  Scout       observe  — collect and read raw material
//! rank 1  Analyst     assess   — derive, grade, corroborate, forecast
//! rank 2  Operator    act      — personas, replication, disposal, gates
//! rank 3  VaultAdmin  custody  — vault contents and key material
//! ```
//!
//! [`TIER_MODULES`] maps each tier to the modules it may use. Each tier's
//! slice **includes every module of all lower tiers** (ladder monotonicity),
//! so a promotion never removes an affordance and a demotion never leaves a
//! module reachable above its tier. The invariant is enforced by
//! `tests::ladder_is_monotone`.
//!
//! # Default-tightest
//! [`module_allowed`] is the single authorization query. It returns `true`
//! iff the module appears in the requesting tier's slice; an unknown module
//! (typo, removed, or not-yet-classified) is **denied** — never an error,
//! never an allow. Callers must not fall back to a broader rule on a miss.
//! Matching is exact (case- and whitespace-sensitive).
//!
//! # Secrets
//! Vault and key-custody modules (`vault`, `key_ledger`) are reachable only
//! by [`Tier::VaultAdmin`]; every lower tier is denied (pinned by test).
//!
//! Pure, deterministic, no I/O. No call site is wired here (parent wires).

use std::fmt;

use serde::{Deserialize, Serialize};

/// Competence tier — the ordered ladder an agent's authority is graded on.
///
/// `rank()` is dense (`0..=3`), total, and stable. Serde renders the
/// snake_case words (`"scout"`, `"analyst"`, `"operator"`, `"vault_admin"`);
/// the natural `Ord` follows declaration order, which matches rank order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Tier {
    /// Observation only: collect and read raw material.
    Scout,
    /// Adds analysis: derive, grade, corroborate, forecast.
    Analyst,
    /// Adds active operations: personas, replication, disposal, gates.
    Operator,
    /// Adds custody of secrets: vault contents and key material.
    VaultAdmin,
}

impl Tier {
    /// Every tier in ascending rank order — `ALL[i].rank() == i`.
    pub const ALL: [Tier; 4] = [
        Tier::Scout,
        Tier::Analyst,
        Tier::Operator,
        Tier::VaultAdmin,
    ];

    /// Dense rank `0..=3` (`Scout` = 0 … `VaultAdmin` = 3). Total and stable.
    pub fn rank(self) -> u8 {
        match self {
            Tier::Scout => 0,
            Tier::Analyst => 1,
            Tier::Operator => 2,
            Tier::VaultAdmin => 3,
        }
    }

    /// Canonical snake_case word — same spelling as serde and `Display`.
    pub fn word(self) -> &'static str {
        match self {
            Tier::Scout => "scout",
            Tier::Analyst => "analyst",
            Tier::Operator => "operator",
            Tier::VaultAdmin => "vault_admin",
        }
    }
}

impl fmt::Display for Tier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.word())
    }
}

/// Tier → permitted-modules mapping (frozen interface §8).
///
/// Each entry's slice is the **full cumulative set** for that tier, i.e. it
/// contains every module of all lower tiers (ladder monotonicity, enforced by
/// test). Entries are listed in ascending rank; lists are ASCII-sorted so the
/// cumulative relationship is checkable by eye. Modules each tier *adds*:
///
/// - `Scout`: `caveats`, `injection_scan`, `ledger_events`, `raw_store`,
///   `source_registry` — read-only observation of collected material.
/// - `Analyst` adds: `access_class`, `calibration`, `claim_typing`,
///   `corroboration`, `degraded_gate`, `derived_store`, `disconfirmation`,
///   `forecast`, `gap_register`, `link_chain`, `premortem`, `regrade`,
///   `requirements`, `retention` — assessment and grading.
/// - `Operator` adds: `agent_ledger`, `agent_ledger_sqlite`, `canary_monitor`,
///   `canary_tokens`, `decoy_flags`, `fixity`, `fixity_job`, `harm_review`,
///   `hndl`, `ledger_replay`, `ledger_verify`, `opsec_gates`, `ops_gate`,
///   `persona`, `redaction`, `replication`, `replication_plan`, `retro`,
///   `shred` — active operations, disposal, and gates.
/// - `VaultAdmin` adds: `key_ledger`, `vault` — custody of secrets.
pub const TIER_MODULES: &[(Tier, &[&str])] = &[
    (
        Tier::Scout,
        &[
            "caveats",
            "injection_scan",
            "ledger_events",
            "raw_store",
            "source_registry",
        ],
    ),
    (
        Tier::Analyst,
        &[
            "access_class",
            "calibration",
            "caveats",
            "claim_typing",
            "corroboration",
            "degraded_gate",
            "derived_store",
            "disconfirmation",
            "forecast",
            "gap_register",
            "injection_scan",
            "ledger_events",
            "link_chain",
            "premortem",
            "raw_store",
            "regrade",
            "requirements",
            "retention",
            "source_registry",
        ],
    ),
    (
        Tier::Operator,
        &[
            "access_class",
            "agent_ledger",
            "agent_ledger_sqlite",
            "calibration",
            "canary_monitor",
            "canary_tokens",
            "caveats",
            "claim_typing",
            "corroboration",
            "decoy_flags",
            "degraded_gate",
            "derived_store",
            "disconfirmation",
            "fixity",
            "fixity_job",
            "forecast",
            "gap_register",
            "harm_review",
            "hndl",
            "injection_scan",
            "ledger_events",
            "ledger_replay",
            "ledger_verify",
            "link_chain",
            "ops_gate",
            "opsec_gates",
            "persona",
            "premortem",
            "raw_store",
            "redaction",
            "regrade",
            "replication",
            "replication_plan",
            "requirements",
            "retention",
            "retro",
            "shred",
            "source_registry",
        ],
    ),
    (
        Tier::VaultAdmin,
        &[
            "access_class",
            "agent_ledger",
            "agent_ledger_sqlite",
            "calibration",
            "canary_monitor",
            "canary_tokens",
            "caveats",
            "claim_typing",
            "corroboration",
            "decoy_flags",
            "degraded_gate",
            "derived_store",
            "disconfirmation",
            "fixity",
            "fixity_job",
            "forecast",
            "gap_register",
            "harm_review",
            "hndl",
            "injection_scan",
            "key_ledger",
            "ledger_events",
            "ledger_replay",
            "ledger_verify",
            "link_chain",
            "ops_gate",
            "opsec_gates",
            "persona",
            "premortem",
            "raw_store",
            "redaction",
            "regrade",
            "replication",
            "replication_plan",
            "requirements",
            "retention",
            "retro",
            "shred",
            "source_registry",
            "vault",
        ],
    ),
];

/// Permitted modules for `tier` — the tier's slice of [`TIER_MODULES`].
///
/// Returns the empty slice for a tier absent from the table (cannot happen
/// for a valid [`Tier`]; kept fail-tight rather than panicking).
pub fn modules_for(tier: Tier) -> &'static [&'static str] {
    match TIER_MODULES.iter().find(|(t, _)| *t == tier) {
        Some((_, modules)) => modules,
        None => &[],
    }
}

/// Default-tightest authorization query: may `tier` use `module`?
///
/// `true` iff `module` appears in [`modules_for(tier)`](modules_for); an
/// unknown module is denied (`false`) — never an error, never an allow.
/// Exact match: case- and whitespace-sensitive.
pub fn module_allowed(tier: Tier, module: &str) -> bool {
    modules_for(tier).contains(&module)
}

/// Free-function form of [`Tier::rank`] — dense `0..=3`.
pub fn rank_of(tier: Tier) -> u8 {
    tier.rank()
}

/// Is `tier` at or above `floor` on the ladder? Inclusive: equal tiers pass.
/// Pure rank comparison — `tier.rank() >= floor.rank()`.
pub fn is_at_least(tier: Tier, floor: Tier) -> bool {
    tier.rank() >= floor.rank()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn ladder_is_monotone() {
        // Every higher tier's slice contains every module of the tier below.
        for w in Tier::ALL.windows(2) {
            let (lower, higher) = (w[0], w[1]);
            for m in modules_for(lower) {
                assert!(
                    modules_for(higher).contains(m),
                    "tier {higher:?} must include lower-tier module {m:?} (from {lower:?})"
                );
            }
        }
        // Strictly monotone: each step adds at least one module.
        for w in Tier::ALL.windows(2) {
            assert!(
                modules_for(w[1]).len() > modules_for(w[0]).len(),
                "tier {:?} must strictly extend {:?}",
                w[1],
                w[0]
            );
        }
    }

    #[test]
    fn tables_non_empty_and_wellformed() {
        assert_eq!(TIER_MODULES.len(), Tier::ALL.len());
        for (i, (t, modules)) in TIER_MODULES.iter().enumerate() {
            assert_eq!(*t, Tier::ALL[i], "table entry {i} must be tier rank {i}");
            assert_eq!(t.rank() as usize, i);
            assert!(!modules.is_empty(), "tier {t:?} table must be non-empty");
            let mut seen = BTreeSet::new();
            for m in *modules {
                assert!(!m.is_empty(), "module names must be non-empty");
                assert!(seen.insert(*m), "duplicate module {m:?} in tier {t:?}");
            }
        }
    }

    #[test]
    fn vault_secrets_are_vault_admin_only() {
        for secret in ["vault", "key_ledger"] {
            assert!(
                module_allowed(Tier::VaultAdmin, secret),
                "VaultAdmin must reach {secret:?}"
            );
            for lower in [Tier::Scout, Tier::Analyst, Tier::Operator] {
                assert!(
                    !module_allowed(lower, secret),
                    "{lower:?} must be denied {secret:?}"
                );
            }
        }
    }

    #[test]
    fn unknown_module_denied_default_tightest() {
        for tier in Tier::ALL {
            for unknown in [
                "",
                "definitely_not_a_module",
                "Vault",
                "vault ",
                " vault",
                "vaultx",
                "Key_Ledger",
            ] {
                assert!(
                    !module_allowed(tier, unknown),
                    "{tier:?} + {unknown:?} must deny"
                );
            }
        }
    }

    #[test]
    fn rank_order_is_dense_and_ascending() {
        assert_eq!(Tier::ALL.len(), 4);
        for (i, t) in Tier::ALL.iter().enumerate() {
            assert_eq!(t.rank(), i as u8);
            assert_eq!(rank_of(*t), t.rank());
        }
        for w in Tier::ALL.windows(2) {
            assert!(w[0].rank() < w[1].rank());
            assert!(w[0] < w[1], "derived Ord must follow ladder order");
        }
    }

    #[test]
    fn is_at_least_matches_rank_total_order() {
        for a in Tier::ALL {
            for b in Tier::ALL {
                assert_eq!(is_at_least(a, b), a.rank() >= b.rank());
            }
            assert!(is_at_least(a, a), "floor is inclusive");
        }
        assert!(is_at_least(Tier::VaultAdmin, Tier::Scout));
        assert!(!is_at_least(Tier::Scout, Tier::VaultAdmin));
        assert!(is_at_least(Tier::Operator, Tier::Analyst));
        assert!(!is_at_least(Tier::Analyst, Tier::Operator));
    }

    #[test]
    fn module_allowed_agrees_with_table() {
        for t in Tier::ALL {
            for m in modules_for(t) {
                assert!(module_allowed(t, *m), "{t:?} must allow table member {m:?}");
            }
            // Ladder closure: any module allowed at t is allowed at every higher tier.
            for higher in Tier::ALL.iter().filter(|h| h.rank() > t.rank()) {
                for m in modules_for(t) {
                    assert!(module_allowed(*higher, m));
                }
            }
        }
        // Pinned sample: persona is Operator-and-above only.
        assert!(!module_allowed(Tier::Scout, "persona"));
        assert!(!module_allowed(Tier::Analyst, "persona"));
        assert!(module_allowed(Tier::Operator, "persona"));
        assert!(module_allowed(Tier::VaultAdmin, "persona"));
    }

    #[test]
    fn serde_and_display_words_pinned() {
        let pinned = [
            (Tier::Scout, "scout"),
            (Tier::Analyst, "analyst"),
            (Tier::Operator, "operator"),
            (Tier::VaultAdmin, "vault_admin"),
        ];
        for (t, word) in pinned {
            let s = serde_json::to_string(&t).unwrap();
            assert_eq!(s, format!("\"{word}\""));
            let back: Tier = serde_json::from_str(&s).unwrap();
            assert_eq!(back, t);
            assert_eq!(t.word(), word);
            assert_eq!(t.to_string(), word);
        }
    }

    #[test]
    fn determinism() {
        for t in Tier::ALL {
            // Static slices: same pointer on every call.
            assert_eq!(modules_for(t).as_ptr(), modules_for(t).as_ptr());
            for m in modules_for(t) {
                assert!(module_allowed(t, m));
                assert!(module_allowed(t, m));
            }
        }
        for (i, (t, _)) in TIER_MODULES.iter().enumerate() {
            let (t2, _) = TIER_MODULES[i];
            assert_eq!(*t, t2);
        }
    }
}
