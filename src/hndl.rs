//! HNDL (harvest-now, decrypt-later) lifetime classification and the
//! **no-silent-downgrade** crypto-profile rule (A6.1.4).
//!
//! Adversaries who record traffic today can decrypt it once a
//! cryptographically-relevant quantum computer exists. Whether that matters
//! depends on a single question: **does the data still need to be
//! confidential when that machine arrives?** This module answers it in three
//! pieces:
//!
//! 1. [`classify`] maps a retention window (in days) to a
//!    [`DataLifetimeClass`] — `Ephemeral` (≤ 1 day), `ShortTerm` (≤ 90 days),
//!    `LongTerm` (≤ 3650 days ≈ 10 years), `Decades` (anything longer).
//! 2. [`quantum_relevant`] says which classes must survive a future quantum
//!    adversary: every class except `Ephemeral` is quantum-relevant (even
//!    short-term secrets can outlive the machine if it lands soon enough).
//! 3. [`enforce_profile`] is the guardrail: moving a data class **down** from
//!    [`CryptoProfile::HybridPqc`] to [`CryptoProfile::Classical`] is never
//!    silent. It is refused outright for quantum-relevant classes — an
//!    explicit operator flag cannot authorise it — and for the remaining
//!    (`Ephemeral`) class it still requires the explicit
//!    `explicit_downgrade_ok` flag. Upgrades and no-ops always pass.
//!
//! All functions are pure and deterministic; none panic.
//! [`policy_line`] renders the per-class rule as one deterministic sentence
//! for manifests and `doctor` output.

use std::fmt;

use serde::{Deserialize, Serialize};

// ── Lifetime class ───────────────────────────────────────────────────────────

/// How long data must stay confidential, bucketed by retention window.
///
/// Classified by [`classify`] from a retention window in days:
///
/// | class        | retention (days) | HNDL posture                        |
/// |--------------|------------------|-------------------------------------|
/// | `Ephemeral`  | `0..=1`          | not quantum-relevant; downgradeable |
/// | `ShortTerm`  | `2..=90`         | quantum-relevant; PQC required      |
/// | `LongTerm`   | `91..=3650`      | quantum-relevant; PQC required      |
/// | `Decades`    | `> 3650`         | quantum-relevant; PQC required      |
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum DataLifetimeClass {
    /// Retention window ≤ 1 day — data dies before a future quantum
    /// adversary would plausibly get to it. The only downgradeable class.
    Ephemeral,
    /// Retention window ≤ 90 days — quantum-relevant (a machine could exist
    /// within the confidentiality window).
    ShortTerm,
    /// Retention window ≤ 3650 days (~10 years) — quantum-relevant.
    LongTerm,
    /// Retention window > 3650 days — quantum-relevant; the canonical
    /// harvest-now-decrypt-later target.
    Decades,
}

impl DataLifetimeClass {
    /// Stable lower-case identifier for logs, manifests and CLI output.
    pub fn as_str(&self) -> &'static str {
        match self {
            DataLifetimeClass::Ephemeral => "ephemeral",
            DataLifetimeClass::ShortTerm => "short-term",
            DataLifetimeClass::LongTerm => "long-term",
            DataLifetimeClass::Decades => "decades",
        }
    }
}

impl fmt::Display for DataLifetimeClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Classify a retention window (in days) into a [`DataLifetimeClass`].
///
/// Documented boundaries (inclusive, checked in order):
///
/// * `retention_days <= 1` → [`DataLifetimeClass::Ephemeral`]
/// * `retention_days <= 90` → [`DataLifetimeClass::ShortTerm`]
/// * `retention_days <= 3650` → [`DataLifetimeClass::LongTerm`]
/// * otherwise → [`DataLifetimeClass::Decades`]
///
/// Deterministic and total: every `u32` maps to exactly one class.
pub fn classify(retention_days: u32) -> DataLifetimeClass {
    if retention_days <= 1 {
        DataLifetimeClass::Ephemeral
    } else if retention_days <= 90 {
        DataLifetimeClass::ShortTerm
    } else if retention_days <= 3650 {
        DataLifetimeClass::LongTerm
    } else {
        DataLifetimeClass::Decades
    }
}

// ── Crypto profile ───────────────────────────────────────────────────────────

/// Which cryptographic profile guards a data class at rest / in transit.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum CryptoProfile {
    /// Pre-quantum cryptography only (classical ECDH/RSA/...).
    Classical,
    /// Classical **plus** post-quantum hybrid key establishment (the
    /// no-silent-downgrade floor for quantum-relevant classes).
    HybridPqc,
}

impl CryptoProfile {
    /// Stable lower-case identifier for logs, manifests and CLI output.
    pub fn as_str(&self) -> &'static str {
        match self {
            CryptoProfile::Classical => "classical",
            CryptoProfile::HybridPqc => "hybrid-pqc",
        }
    }

    /// `true` for [`CryptoProfile::HybridPqc`] — convenience for callers that
    /// only need to know whether post-quantum protection is present.
    pub fn is_pqc(&self) -> bool {
        matches!(self, CryptoProfile::HybridPqc)
    }
}

impl fmt::Display for CryptoProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Is this lifetime class exposed to harvest-now / decrypt-later?
///
/// **Documented rule: every class except `Ephemeral` is quantum-relevant.**
/// Even a `ShortTerm` window is long enough for a recorded ciphertext to
/// still matter when a cryptographically-relevant quantum computer lands, so
/// the default posture is PQC from `ShortTerm` and up. `Ephemeral` (≤ 1 day)
/// is the only class exempt.
pub fn quantum_relevant(class: DataLifetimeClass) -> bool {
    !matches!(class, DataLifetimeClass::Ephemeral)
}

// ── Errors ───────────────────────────────────────────────────────────────────

/// Refusals produced by [`enforce_profile`] / [`parse_profile`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HndlError {
    /// A `HybridPqc → Classical` downgrade was attempted but refused. Raised
    /// when the downgrade was not explicitly authorised, **and always**
    /// raised for quantum-relevant classes (where no flag can authorise it).
    SilentDowngrade {
        from: CryptoProfile,
        to: CryptoProfile,
    },
    /// Malformed input (e.g. an unknown profile name). Reserved for callers
    /// that parse profile names out of manifests/CLI.
    Invalid { message: String },
}

impl fmt::Display for HndlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HndlError::SilentDowngrade { from, to } => write!(
                f,
                "refused crypto-profile downgrade {} -> {} (no-silent-downgrade policy)",
                from, to
            ),
            HndlError::Invalid { message } => write!(f, "invalid HNDL input: {}", message),
        }
    }
}

impl std::error::Error for HndlError {}

// ── Enforcement ──────────────────────────────────────────────────────────────

/// Decide whether `existing` may be replaced by `requested` for a data class,
/// and return the effective profile. Documented precedence:
///
/// 1. **Upgrade** (`Classical → HybridPqc`): always allowed, returns
///    `HybridPqc`.
/// 2. **No-op** (same profile): always allowed, returns it.
/// 3. **Downgrade** (`HybridPqc → Classical`):
///    * quantum-relevant class (anything but `Ephemeral`) → **always
///      refused** with [`HndlError::SilentDowngrade`], even when
///      `explicit_downgrade_ok` is `true` — the no-silent-downgrade floor;
///    * `Ephemeral` class → allowed **only** when `explicit_downgrade_ok` is
///      `true` (an explicit, auditable operator decision); otherwise refused
///      with [`HndlError::SilentDowngrade`].
///
/// Never panics.
pub fn enforce_profile(
    existing: CryptoProfile,
    requested: CryptoProfile,
    explicit_downgrade_ok: bool,
    class: DataLifetimeClass,
) -> Result<CryptoProfile, HndlError> {
    match (existing, requested) {
        // Upgrade: PQC is always permitted.
        (CryptoProfile::Classical, CryptoProfile::HybridPqc) => Ok(CryptoProfile::HybridPqc),
        // No-op: nothing changes, nothing to authorise.
        (CryptoProfile::Classical, CryptoProfile::Classical) => Ok(CryptoProfile::Classical),
        (CryptoProfile::HybridPqc, CryptoProfile::HybridPqc) => Ok(CryptoProfile::HybridPqc),
        // Downgrade: refused unless explicitly authorised AND the class
        // permits it; quantum-relevant classes never permit it.
        (CryptoProfile::HybridPqc, CryptoProfile::Classical) => {
            if !quantum_relevant(class) && explicit_downgrade_ok {
                Ok(CryptoProfile::Classical)
            } else {
                Err(HndlError::SilentDowngrade {
                    from: CryptoProfile::HybridPqc,
                    to: CryptoProfile::Classical,
                })
            }
        }
        // The arms above cover every combination of the two current variants;
        // adding a third profile variant will break this match at compile time,
        // forcing an explicit policy decision rather than a silent default.
    }
}

/// Parse a [`CryptoProfile`] from its stable name (`"classical"` /
/// `"hybrid-pqc"`), e.g. from manifests or CLI arguments. Unknown names →
/// [`HndlError::Invalid`]. Case-insensitive; surrounding whitespace ignored.
pub fn parse_profile(name: &str) -> Result<CryptoProfile, HndlError> {
    match name.trim().to_ascii_lowercase().as_str() {
        "classical" => Ok(CryptoProfile::Classical),
        "hybrid-pqc" | "hybrid_pqc" | "hybridpqc" => Ok(CryptoProfile::HybridPqc),
        other => Err(HndlError::Invalid {
            message: format!("unknown crypto profile {:?}", other),
        }),
    }
}

// ── Policy lines ─────────────────────────────────────────────────────────────

/// One deterministic sentence per class, for manifests and `doctor` output.
/// Each line states the retention boundary and the crypto posture; the four
/// lines are pairwise distinct.
pub fn policy_line(class: DataLifetimeClass) -> &'static str {
    match class {
        DataLifetimeClass::Ephemeral => {
            "HNDL: ephemeral data (retention <= 1 day) is not quantum-relevant; \
             Classical is acceptable and a downgrade only with an explicit operator flag."
        }
        DataLifetimeClass::ShortTerm => {
            "HNDL: short-term data (retention <= 90 days) is quantum-relevant; \
             HybridPqc is required and a downgrade is refused even with an explicit flag."
        }
        DataLifetimeClass::LongTerm => {
            "HNDL: long-term data (retention <= 3650 days) is quantum-relevant; \
             HybridPqc is required and a downgrade is refused even with an explicit flag."
        }
        DataLifetimeClass::Decades => {
            "HNDL: decades-spanning data (retention > 3650 days) is quantum-relevant; \
             HybridPqc is required and a downgrade is refused even with an explicit flag."
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // -- classification boundaries ------------------------------------------

    #[test]
    fn classify_boundaries() {
        // ≤ 1 → Ephemeral
        assert_eq!(classify(0), DataLifetimeClass::Ephemeral);
        assert_eq!(classify(1), DataLifetimeClass::Ephemeral);
        // 2..=90 → ShortTerm
        assert_eq!(classify(2), DataLifetimeClass::ShortTerm);
        assert_eq!(classify(90), DataLifetimeClass::ShortTerm);
        // 91..=3650 → LongTerm
        assert_eq!(classify(91), DataLifetimeClass::LongTerm);
        assert_eq!(classify(3650), DataLifetimeClass::LongTerm);
        // > 3650 → Decades
        assert_eq!(classify(3651), DataLifetimeClass::Decades);
        assert_eq!(classify(u32::MAX), DataLifetimeClass::Decades);
    }

    #[test]
    fn classify_is_deterministic() {
        for d in 0..=4000u32 {
            assert_eq!(classify(d), classify(d));
        }
    }

    // -- quantum relevance ---------------------------------------------------

    #[test]
    fn quantum_relevant_set() {
        assert!(!quantum_relevant(DataLifetimeClass::Ephemeral));
        assert!(quantum_relevant(DataLifetimeClass::ShortTerm));
        assert!(quantum_relevant(DataLifetimeClass::LongTerm));
        assert!(quantum_relevant(DataLifetimeClass::Decades));
    }

    #[test]
    fn quantum_relevant_agrees_with_classification() {
        // ShortTerm and above are quantum-relevant; only ≤ 1 day is exempt.
        for d in 0..=4000u32 {
            assert_eq!(
                quantum_relevant(classify(d)),
                d > 1,
                "retention_days={}",
                d
            );
        }
    }

    // -- enforce_profile: downgrade matrix ----------------------------------

    #[test]
    fn upgrade_is_always_allowed() {
        for class in [
            DataLifetimeClass::Ephemeral,
            DataLifetimeClass::ShortTerm,
            DataLifetimeClass::LongTerm,
            DataLifetimeClass::Decades,
        ] {
            for flag in [false, true] {
                assert_eq!(
                    enforce_profile(CryptoProfile::Classical, CryptoProfile::HybridPqc, flag, class),
                    Ok(CryptoProfile::HybridPqc),
                    "class={:?} flag={}",
                    class,
                    flag
                );
            }
        }
    }

    #[test]
    fn same_profile_is_allowed() {
        for class in [
            DataLifetimeClass::Ephemeral,
            DataLifetimeClass::ShortTerm,
            DataLifetimeClass::LongTerm,
            DataLifetimeClass::Decades,
        ] {
            assert_eq!(
                enforce_profile(CryptoProfile::Classical, CryptoProfile::Classical, false, class),
                Ok(CryptoProfile::Classical)
            );
            assert_eq!(
                enforce_profile(CryptoProfile::HybridPqc, CryptoProfile::HybridPqc, false, class),
                Ok(CryptoProfile::HybridPqc)
            );
        }
    }

    #[test]
    fn silent_downgrade_refused_without_flag() {
        for class in [
            DataLifetimeClass::Ephemeral,
            DataLifetimeClass::ShortTerm,
            DataLifetimeClass::LongTerm,
            DataLifetimeClass::Decades,
        ] {
            assert_eq!(
                enforce_profile(CryptoProfile::HybridPqc, CryptoProfile::Classical, false, class),
                Err(HndlError::SilentDowngrade {
                    from: CryptoProfile::HybridPqc,
                    to: CryptoProfile::Classical,
                }),
                "class={:?}",
                class
            );
        }
    }

    #[test]
    fn flagged_downgrade_refused_for_quantum_relevant_classes() {
        // No-silent-downgrade floor: an explicit flag cannot authorise a
        // downgrade for quantum-relevant classes.
        for class in [
            DataLifetimeClass::ShortTerm,
            DataLifetimeClass::LongTerm,
            DataLifetimeClass::Decades,
        ] {
            assert_eq!(
                enforce_profile(CryptoProfile::HybridPqc, CryptoProfile::Classical, true, class),
                Err(HndlError::SilentDowngrade {
                    from: CryptoProfile::HybridPqc,
                    to: CryptoProfile::Classical,
                }),
                "class={:?}",
                class
            );
        }
    }

    #[test]
    fn flagged_downgrade_allowed_only_for_ephemeral() {
        assert_eq!(
            enforce_profile(
                CryptoProfile::HybridPqc,
                CryptoProfile::Classical,
                true,
                DataLifetimeClass::Ephemeral
            ),
            Ok(CryptoProfile::Classical)
        );
    }

    // -- policy lines --------------------------------------------------------

    #[test]
    fn policy_lines_are_distinct_and_class_specific() {
        let classes = [
            DataLifetimeClass::Ephemeral,
            DataLifetimeClass::ShortTerm,
            DataLifetimeClass::LongTerm,
            DataLifetimeClass::Decades,
        ];
        let mut lines: Vec<&str> = classes.iter().map(|c| policy_line(*c)).collect();
        lines.sort_unstable();
        lines.dedup();
        assert_eq!(lines.len(), 4, "policy lines must be pairwise distinct");
        for c in classes {
            let line = policy_line(c);
            assert!(line.starts_with("HNDL:"), "line={}", line);
            assert!(!line.is_empty());
        }
        // Deterministic: same class → same line.
        assert_eq!(
            policy_line(DataLifetimeClass::Ephemeral),
            policy_line(DataLifetimeClass::Ephemeral)
        );
    }

    // -- Display / parsing ---------------------------------------------------

    #[test]
    fn display_and_as_str_agree() {
        assert_eq!(DataLifetimeClass::Ephemeral.to_string(), "ephemeral");
        assert_eq!(DataLifetimeClass::ShortTerm.to_string(), "short-term");
        assert_eq!(DataLifetimeClass::LongTerm.to_string(), "long-term");
        assert_eq!(DataLifetimeClass::Decades.to_string(), "decades");
        assert_eq!(CryptoProfile::Classical.to_string(), "classical");
        assert_eq!(CryptoProfile::HybridPqc.to_string(), "hybrid-pqc");
        assert!(CryptoProfile::HybridPqc.is_pqc());
        assert!(!CryptoProfile::Classical.is_pqc());
    }

    #[test]
    fn parse_profile_round_trips_names() {
        for p in [CryptoProfile::Classical, CryptoProfile::HybridPqc] {
            assert_eq!(parse_profile(p.as_str()), Ok(p));
        }
        assert_eq!(parse_profile("  Hybrid-PQC "), Ok(CryptoProfile::HybridPqc));
        match parse_profile("rot13") {
            Err(HndlError::Invalid { message }) => assert!(message.contains("rot13")),
            other => panic!("expected Invalid, got {:?}", other),
        }
    }

    // -- serde round-trips ---------------------------------------------------

    #[test]
    fn serde_round_trips() {
        for class in [
            DataLifetimeClass::Ephemeral,
            DataLifetimeClass::ShortTerm,
            DataLifetimeClass::LongTerm,
            DataLifetimeClass::Decades,
        ] {
            let j = serde_json::to_string(&class).unwrap();
            let back: DataLifetimeClass = serde_json::from_str(&j).unwrap();
            assert_eq!(back, class);
        }
        for p in [CryptoProfile::Classical, CryptoProfile::HybridPqc] {
            let j = serde_json::to_string(&p).unwrap();
            let back: CryptoProfile = serde_json::from_str(&j).unwrap();
            assert_eq!(back, p);
        }
        let err = HndlError::SilentDowngrade {
            from: CryptoProfile::HybridPqc,
            to: CryptoProfile::Classical,
        };
        let j = serde_json::to_string(&err).unwrap();
        let back: HndlError = serde_json::from_str(&j).unwrap();
        assert_eq!(back, err);
    }

    #[test]
    fn error_display_mentions_transition() {
        let e = HndlError::SilentDowngrade {
            from: CryptoProfile::HybridPqc,
            to: CryptoProfile::Classical,
        };
        let s = e.to_string();
        assert!(s.contains("hybrid-pqc") && s.contains("classical"), "s={}", s);
        let inv = HndlError::Invalid {
            message: "boom".to_string(),
        };
        assert!(inv.to_string().contains("boom"));
    }

    // -- end-to-end determinism ---------------------------------------------

    #[test]
    fn enforcement_is_deterministic() {
        for p in [
            (CryptoProfile::HybridPqc, CryptoProfile::Classical),
            (CryptoProfile::Classical, CryptoProfile::HybridPqc),
            (CryptoProfile::Classical, CryptoProfile::Classical),
        ] {
            for d in [0u32, 1, 2, 90, 91, 3650, 3651, u32::MAX] {
                let class = classify(d);
                for flag in [false, true] {
                    assert_eq!(
                        enforce_profile(p.0, p.1, flag, class),
                        enforce_profile(p.0, p.1, flag, class),
                        "profile={:?}->{:?} days={} flag={}",
                        p.0,
                        p.1,
                        d,
                        flag
                    );
                }
            }
        }
    }
}
