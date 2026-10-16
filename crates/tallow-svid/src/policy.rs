//! `policy` — W3 SVID issuance policy (owner: U-211).
//!
//! Numeric policy for the SVID fabric, taken from the parent decision **D1**
//! (GOVERNANCE.md, resolved from U-201 Q-1) and the report's TTL table
//! (§5.4).  This module owns the raw constants; `crate::model::SvidKind`
//! exposes them as per-kind TTL bands (`TtlBand`).
//!
//! **D1 — two-cert TTL split (2026-09-12):**
//! - node identity cert: 30–90 d (fleet/self-root, KT-pinned),
//! - SVID-issuer intermediate: **≤ 7 d**, renewed by the daemon,
//! - workload leaf: 1–24 h, default 4–8 h band, **re-issue at T/2**.
//!
//! Also in scope here: the registered service-name set (issuance allowlist,
//! report G-01 "registered-svc allowlist"), the node-id pinning check
//! (ATK-2.10/2.12: an SVID must be pinned to the node that issued it), and the
//! re-issue-at-T/2 helper consumed by the rotation driver (R-5.10).
//!
//! Deliberately no I/O, no crypto, no clocks: everything is a pure function of
//! its arguments so callers (daemon issuer, doctor probes) can test policy
//! without a live daemon.

use std::collections::BTreeSet;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::model::{self, SpiffeId, SvidKind};

// ---------------------------------------------------------------------------
// TTL constants (D1 / report §5.4)
// ---------------------------------------------------------------------------

/// Seconds per hour.
pub const HOUR: u64 = 60 * 60;
/// Seconds per day.
pub const DAY: u64 = 24 * HOUR;

/// Node identity cert minimum TTL (D1): 30 days.
pub const NODE_IDENTITY_TTL_MIN_SECS: u64 = 30 * DAY;
/// Node identity cert maximum TTL (D1): 90 days.
pub const NODE_IDENTITY_TTL_MAX_SECS: u64 = 90 * DAY;
/// Default node identity cert TTL: 60 days (mid-band).
pub const NODE_IDENTITY_DEFAULT_TTL_SECS: u64 = 60 * DAY;

/// SVID-issuer intermediate **hard cap** (D1, ATK-2.2 compensation 1): 7 days.
pub const ISSUER_INTERMEDIATE_TTL_MAX_SECS: u64 = 7 * DAY;
/// SVID-issuer intermediate minimum TTL: 1 hour (avoids renewal churn; the
/// security-relevant bound is the 7-day cap).
pub const ISSUER_INTERMEDIATE_TTL_MIN_SECS: u64 = HOUR;
/// Default SVID-issuer intermediate TTL: 24 h (daemon renews daily, well under
/// the 7-day cap).
pub const ISSUER_INTERMEDIATE_DEFAULT_TTL_SECS: u64 = DAY;

/// Workload leaf minimum TTL (report §5.4: 1–24 h).
pub const WORKLOAD_TTL_MIN_SECS: u64 = HOUR;
/// Workload leaf maximum TTL (report §5.4: 1–24 h).
pub const WORKLOAD_TTL_MAX_SECS: u64 = 24 * HOUR;
/// Workload default band lower edge (D1): 4 h.
pub const WORKLOAD_DEFAULT_BAND_MIN_SECS: u64 = 4 * HOUR;
/// Workload default band upper edge (D1): 8 h.
pub const WORKLOAD_DEFAULT_BAND_MAX_SECS: u64 = 8 * HOUR;
/// Workload default TTL when the caller does not request one: 6 h (mid-band).
pub const WORKLOAD_DEFAULT_TTL_SECS: u64 = 6 * HOUR;

/// Revocation-list freshness cap for *new* sessions, ATK-2.3 mitigation 1:
/// list age must be `≤ min(TTL/2, 6 h)` else fail closed.
pub const REVOCATION_FRESHNESS_CAP_SECS: u64 = 6 * HOUR;

/// Join-token maximum lifetime (report §5.4/§5.6): single-use, ≤ 10 min.
pub const JOIN_TOKEN_TTL_MAX_SECS: u64 = 10 * 60;

// ---------------------------------------------------------------------------
// TTL validation
// ---------------------------------------------------------------------------

/// Policy violations. All variants are fail-closed: an SVID that does not
/// satisfy policy must not be issued.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PolicyError {
    /// TTL of zero (or a sub-second duration that rounds to zero).
    #[error("ttl must be greater than zero")]
    ZeroTtl,
    /// TTL outside the hard band for the artifact kind (D1).
    #[error(
        "ttl {requested_secs}s for {kind} is outside the permitted band {min_secs}..={max_secs}s"
    )]
    TtlOutOfBand {
        /// Artifact kind the TTL was requested for.
        kind: SvidKind,
        /// Requested TTL in seconds.
        requested_secs: u64,
        /// Band minimum in seconds.
        min_secs: u64,
        /// Band maximum in seconds.
        max_secs: u64,
    },
    /// Service name not in the registered set.
    #[error("service name {0:?} is not registered")]
    ServiceNotRegistered(String),
    /// Service name cannot be added: malformed.
    #[error("invalid service name {name:?}: {reason}")]
    InvalidServiceName {
        /// The offending name.
        name: String,
        /// Why it is invalid.
        reason: String,
    },
    /// Service name is reserved for infrastructure and cannot be registered as
    /// a workload identity.
    #[error("service name {0:?} is reserved")]
    ReservedServiceName(String),
    /// Duplicate registration attempt.
    #[error("service name {0:?} is already registered")]
    DuplicateServiceName(String),
    /// The SVID's node id does not match the pinned node.
    #[error("node-id pin mismatch: pinned {pinned:?}, observed {observed:?}")]
    NodePinMismatch {
        /// Pinned node id.
        pinned: String,
        /// Node id carried by the presented SVID.
        observed: String,
    },
    /// The pin itself is malformed.
    #[error("invalid node-id pin {pinned:?}: {reason}")]
    InvalidNodePin {
        /// The offending pin value.
        pinned: String,
        /// Why it is invalid.
        reason: String,
    },
    /// Join-token TTL exceeds the ≤10 min cap.
    #[error("join token ttl {requested_secs}s exceeds cap {max_secs}s")]
    JoinTokenTtlTooLong {
        /// Requested TTL in seconds.
        requested_secs: u64,
        /// Cap in seconds.
        max_secs: u64,
    },
}

/// Validate a TTL against the hard band for `kind` (D1).
pub fn validate_ttl(kind: SvidKind, ttl: Duration) -> Result<(), PolicyError> {
    validate_ttl_secs(kind, ttl.as_secs())
}

/// Validate a TTL in whole seconds against the hard band for `kind` (D1).
pub fn validate_ttl_secs(kind: SvidKind, secs: u64) -> Result<(), PolicyError> {
    if secs == 0 {
        return Err(PolicyError::ZeroTtl);
    }
    let band = kind.ttl_band();
    if !band.contains_secs(secs) {
        return Err(PolicyError::TtlOutOfBand {
            kind,
            requested_secs: secs,
            min_secs: band.min_secs(),
            max_secs: band.max_secs(),
        });
    }
    Ok(())
}

/// Resolve the effective TTL: `None` yields the kind's default; `Some(ttl)`
/// is validated and returned (fail-closed — never clamped silently).
pub fn effective_ttl(kind: SvidKind, requested: Option<Duration>) -> Result<Duration, PolicyError> {
    match requested {
        None => Ok(kind.default_ttl()),
        Some(ttl) => {
            validate_ttl(kind, ttl)?;
            Ok(Duration::from_secs(ttl.as_secs()))
        }
    }
}

/// True iff `ttl` falls inside the workload **default** band (4–8 h, D1). This
/// is the band the daemon will pick when no TTL is requested; TTLs outside it
/// but inside the hard 1–24 h band remain legal (report §5.4).
pub fn in_workload_default_band(ttl: Duration) -> bool {
    let secs = ttl.as_secs();
    (WORKLOAD_DEFAULT_BAND_MIN_SECS..=WORKLOAD_DEFAULT_BAND_MAX_SECS).contains(&secs)
}

/// Validate a join-token TTL: single-use token, `≤ 10 min` (report §5.4/§5.6).
pub fn validate_join_token_ttl(ttl: Duration) -> Result<(), PolicyError> {
    let secs = ttl.as_secs();
    if secs == 0 {
        return Err(PolicyError::ZeroTtl);
    }
    if secs > JOIN_TOKEN_TTL_MAX_SECS {
        return Err(PolicyError::JoinTokenTtlTooLong {
            requested_secs: secs,
            max_secs: JOIN_TOKEN_TTL_MAX_SECS,
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Re-issue at T/2 (R-5.10)
// ---------------------------------------------------------------------------

/// Deadline at which a credential with lifetime `[not_before, not_after]`
/// must be re-issued: **T/2** after `not_before` (D1 / report §5.4).
///
/// Returns `None` for a degenerate lifetime (`not_after <= not_before`); such
/// a credential is already invalid and must not be in the rotation set.
pub fn reissue_deadline_secs(not_before: i64, not_after: i64) -> Option<i64> {
    let span = not_after.checked_sub(not_before)?;
    if span <= 0 {
        return None;
    }
    Some(not_before + span / 2)
}

/// True iff re-issue is due at `now` (deadline inclusive: `now >= T/2`).
pub fn reissue_due(not_before: i64, not_after: i64, now: i64) -> bool {
    matches!(reissue_deadline_secs(not_before, not_after), Some(d) if now >= d)
}

/// Revocation-list freshness gate for **new** sessions: list age must be
/// `≤ min(TTL/2, 6 h)`, else fail closed (ATK-2.3 mitigation 1).
pub fn revocation_freshness_gate_secs(ttl_secs: u64) -> u64 {
    (ttl_secs / 2).min(REVOCATION_FRESHNESS_CAP_SECS)
}

// ---------------------------------------------------------------------------
// Registered service-name set (issuance allowlist, G-01)
// ---------------------------------------------------------------------------

/// Built-in service names for the processes enumerated in the report (§5.3
/// workload row / R-5.1): daemon control plane, job workers, browser pool,
/// reader, vault service, pkg runner, mesh node, CLI client.
pub const BUILTIN_SERVICE_NAMES: &[&str] = &[
    "daemon",
    "job-worker",
    "browser-pool",
    "reader",
    "vault",
    "pkg-runner",
    "mesh-node",
    "cli",
];

/// True for names reserved for infrastructure — these can never be registered
/// as workload identities (currently only the SVID-issuer SAN service name).
pub fn is_reserved_service_name(name: &str) -> bool {
    model::is_reserved_service_name(name)
}

/// The allowlist of service names that may appear in issued workload SVIDs.
///
/// The set is operator-tunable in a later wave (U-201 Q-9 proposes config-kernel
/// wiring); this wave ships the builtin set plus explicit register/unregister.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServiceRegistry {
    names: BTreeSet<String>,
}

impl ServiceRegistry {
    /// Empty registry (nothing may be issued).
    pub fn empty() -> Self {
        Self {
            names: BTreeSet::new(),
        }
    }

    /// Registry pre-populated with [`BUILTIN_SERVICE_NAMES`].
    pub fn builtin() -> Self {
        let mut reg = Self::empty();
        for name in BUILTIN_SERVICE_NAMES {
            // Builtins are compile-time literals; a failure here is a bug, not
            // runtime input. Still fail closed rather than panic.
            let _ = reg.register(name);
        }
        reg
    }

    /// True iff `name` may be issued as a workload service name.
    pub fn contains(&self, name: &str) -> bool {
        self.names.contains(name)
    }

    /// Fail-closed check: error when `name` is not registered.
    pub fn require_registered(&self, name: &str) -> Result<(), PolicyError> {
        if self.contains(name) {
            Ok(())
        } else {
            Err(PolicyError::ServiceNotRegistered(name.to_string()))
        }
    }

    /// Register a service name. Rejects malformed names, reserved names, and
    /// (deliberately, non-idempotently) duplicates so double-registration is
    /// visible to the caller.
    pub fn register(&mut self, name: &str) -> Result<(), PolicyError> {
        if is_reserved_service_name(name) {
            return Err(PolicyError::ReservedServiceName(name.to_string()));
        }
        model::validate_service_name(name).map_err(|e| PolicyError::InvalidServiceName {
            name: name.to_string(),
            reason: e.to_string(),
        })?;
        if self.names.contains(name) {
            return Err(PolicyError::DuplicateServiceName(name.to_string()));
        }
        self.names.insert(name.to_string());
        Ok(())
    }

    /// Remove a service name; returns whether it was present.
    pub fn unregister(&mut self, name: &str) -> bool {
        self.names.remove(name)
    }

    /// Number of registered names.
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// True iff no names are registered.
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Registered names in deterministic (lexicographic) order.
    pub fn names(&self) -> impl Iterator<Item = &str> {
        self.names.iter().map(|s| s.as_str())
    }
}

// ---------------------------------------------------------------------------
// Node-id pinning (ATK-2.10/2.12)
// ---------------------------------------------------------------------------

/// A pinned node id: SVIDs presented to this node must carry exactly this
/// node segment (`spiffe://tallow/<pinned>/svc/<name>`), so a credential
/// minted for another node cannot be replayed here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodePin {
    node_id: String,
}

impl NodePin {
    /// Build a pin, validating the node-id segment.
    pub fn new(node_id: &str) -> Result<Self, PolicyError> {
        model::validate_node_id(node_id).map_err(|e| PolicyError::InvalidNodePin {
            pinned: node_id.to_string(),
            reason: e.to_string(),
        })?;
        Ok(Self {
            node_id: node_id.to_string(),
        })
    }

    /// The pinned node id.
    pub fn as_str(&self) -> &str {
        &self.node_id
    }

    /// Fail-closed pin check against a parsed SVID.
    pub fn check(&self, id: &SpiffeId) -> Result<(), PolicyError> {
        check_node_pin(&self.node_id, id)
    }

    /// Boolean convenience form of [`NodePin::check`].
    pub fn matches(&self, id: &SpiffeId) -> bool {
        self.check(id).is_ok()
    }
}

/// Fail-closed node-id pin comparison: `id.node_id()` must equal
/// `pinned_node_id` (which must itself be a valid node-id segment).
pub fn check_node_pin(pinned_node_id: &str, id: &SpiffeId) -> Result<(), PolicyError> {
    model::validate_node_id(pinned_node_id).map_err(|e| PolicyError::InvalidNodePin {
        pinned: pinned_node_id.to_string(),
        reason: e.to_string(),
    })?;
    if id.node_id() == pinned_node_id {
        Ok(())
    } else {
        Err(PolicyError::NodePinMismatch {
            pinned: pinned_node_id.to_string(),
            observed: id.node_id().to_string(),
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: u64 = 60;

    fn id(node: &str, svc: &str) -> SpiffeId {
        SpiffeId::new(node, svc).expect("test id")
    }

    #[test]
    fn workload_ttl_band_boundaries() {
        let k = SvidKind::WorkloadLeaf;
        assert!(validate_ttl_secs(k, WORKLOAD_TTL_MIN_SECS).is_ok(), "1h ok");
        assert!(
            validate_ttl_secs(k, WORKLOAD_TTL_MAX_SECS).is_ok(),
            "24h ok"
        );
        assert_eq!(
            validate_ttl_secs(k, WORKLOAD_TTL_MIN_SECS - 1),
            Err(PolicyError::TtlOutOfBand {
                kind: k,
                requested_secs: WORKLOAD_TTL_MIN_SECS - 1,
                min_secs: WORKLOAD_TTL_MIN_SECS,
                max_secs: WORKLOAD_TTL_MAX_SECS,
            })
        );
        assert!(validate_ttl_secs(k, WORKLOAD_TTL_MAX_SECS + 1).is_err());
        assert_eq!(validate_ttl_secs(k, 0), Err(PolicyError::ZeroTtl));
        assert!(validate_ttl(k, Duration::from_secs(6 * HOUR)).is_ok());
    }

    #[test]
    fn node_identity_ttl_boundaries() {
        let k = SvidKind::NodeIdentity;
        assert!(validate_ttl_secs(k, 30 * DAY).is_ok());
        assert!(validate_ttl_secs(k, 90 * DAY).is_ok());
        assert!(validate_ttl_secs(k, 30 * DAY - 1).is_err());
        assert!(validate_ttl_secs(k, 90 * DAY + 1).is_err());
        assert!(
            validate_ttl_secs(k, 7 * DAY).is_err(),
            "issuer TTL is not a node TTL"
        );
        assert!(validate_ttl_secs(k, 0).is_err());
    }

    #[test]
    fn issuer_intermediate_cap_is_seven_days() {
        let k = SvidKind::IssuerIntermediate;
        assert!(validate_ttl_secs(k, ISSUER_INTERMEDIATE_TTL_MAX_SECS).is_ok());
        assert!(
            validate_ttl_secs(k, ISSUER_INTERMEDIATE_TTL_MAX_SECS + 1).is_err(),
            "≤7d is a hard cap (D1)"
        );
        assert!(validate_ttl_secs(k, ISSUER_INTERMEDIATE_TTL_MIN_SECS).is_ok());
        assert!(validate_ttl_secs(k, ISSUER_INTERMEDIATE_TTL_MIN_SECS - 1).is_err());
        assert!(k.default_ttl().as_secs() <= ISSUER_INTERMEDIATE_TTL_MAX_SECS);
    }

    #[test]
    fn effective_ttl_resolution() {
        for kind in SvidKind::ALL {
            let default = effective_ttl(kind, None).expect("default resolves");
            assert_eq!(default, kind.default_ttl());
            assert!(
                kind.ttl_band().contains(default),
                "{kind}: default inside band"
            );
        }
        let w = SvidKind::WorkloadLeaf;
        assert_eq!(
            effective_ttl(w, Some(Duration::from_secs(2 * HOUR))).unwrap(),
            Duration::from_secs(2 * HOUR)
        );
        assert!(effective_ttl(w, Some(Duration::from_secs(7 * DAY))).is_err());
        assert!(effective_ttl(w, Some(Duration::ZERO)).is_err());
        // The default TTL sits inside the 4–8 h default band (D1).
        assert!(in_workload_default_band(Duration::from_secs(
            WORKLOAD_DEFAULT_TTL_SECS
        )));
        assert!(in_workload_default_band(Duration::from_secs(
            WORKLOAD_DEFAULT_BAND_MIN_SECS
        )));
        assert!(in_workload_default_band(Duration::from_secs(
            WORKLOAD_DEFAULT_BAND_MAX_SECS
        )));
        assert!(!in_workload_default_band(Duration::from_secs(
            WORKLOAD_DEFAULT_BAND_MAX_SECS + 1
        )));
    }

    #[test]
    fn constants_are_ordered_sanely() {
        assert!(NODE_IDENTITY_TTL_MIN_SECS < NODE_IDENTITY_DEFAULT_TTL_SECS);
        assert!(NODE_IDENTITY_DEFAULT_TTL_SECS < NODE_IDENTITY_TTL_MAX_SECS);
        assert!(ISSUER_INTERMEDIATE_TTL_MIN_SECS < ISSUER_INTERMEDIATE_DEFAULT_TTL_SECS);
        assert!(ISSUER_INTERMEDIATE_DEFAULT_TTL_SECS < ISSUER_INTERMEDIATE_TTL_MAX_SECS);
        assert!(ISSUER_INTERMEDIATE_TTL_MAX_SECS < NODE_IDENTITY_TTL_MIN_SECS);
        assert!(WORKLOAD_TTL_MIN_SECS < WORKLOAD_DEFAULT_BAND_MIN_SECS);
        assert!(WORKLOAD_DEFAULT_BAND_MIN_SECS <= WORKLOAD_DEFAULT_TTL_SECS);
        assert!(WORKLOAD_DEFAULT_TTL_SECS <= WORKLOAD_DEFAULT_BAND_MAX_SECS);
        assert!(WORKLOAD_DEFAULT_BAND_MAX_SECS < WORKLOAD_TTL_MAX_SECS);
    }

    #[test]
    fn registry_builtin_names() {
        let reg = ServiceRegistry::builtin();
        assert_eq!(reg.len(), BUILTIN_SERVICE_NAMES.len());
        for name in BUILTIN_SERVICE_NAMES {
            assert!(reg.contains(name), "{name} registered");
        }
        assert!(
            !reg.contains(model::ISSUER_SERVICE_NAME),
            "reserved name is not a workload"
        );
        // deterministic ordering
        let names: Vec<&str> = reg.names().collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted);
        assert!(ServiceRegistry::empty().is_empty());
    }

    #[test]
    fn registry_register_rules() {
        let mut reg = ServiceRegistry::empty();
        assert!(reg.register("custom-svc").is_ok());
        assert!(reg.contains("custom-svc"));
        assert_eq!(
            reg.register("custom-svc"),
            Err(PolicyError::DuplicateServiceName("custom-svc".into()))
        );
        assert_eq!(
            reg.register(model::ISSUER_SERVICE_NAME),
            Err(PolicyError::ReservedServiceName(
                model::ISSUER_SERVICE_NAME.into()
            ))
        );
        for bad in [
            "", "Upper", "-leading", "dots..", "we/ird", "séance", "sp ace",
        ] {
            assert!(reg.register(bad).is_err(), "must reject {bad:?}");
        }
        assert!(reg.filter_ok());
        assert!(reg.unregister("custom-svc"));
        assert!(!reg.unregister("custom-svc"));
        assert_eq!(
            reg.require_registered("custom-svc"),
            Err(PolicyError::ServiceNotRegistered("custom-svc".into()))
        );
        reg.register("custom-svc").unwrap();
        assert!(reg.require_registered("custom-svc").is_ok());
    }

    #[test]
    fn node_pin_checks() {
        let pin = NodePin::new("node-01").expect("valid pin");
        let good = id("node-01", "daemon");
        let evil = id("node-02", "daemon");
        assert!(pin.check(&good).is_ok());
        assert!(pin.matches(&good));
        assert_eq!(
            pin.check(&evil),
            Err(PolicyError::NodePinMismatch {
                pinned: "node-01".into(),
                observed: "node-02".into(),
            })
        );
        assert!(!pin.matches(&evil));
        assert!(NodePin::new("NODE-01").is_err(), "pins are validated");
        assert!(NodePin::new("").is_err());
        assert!(check_node_pin("node-01", &good).is_ok());
        assert!(check_node_pin("UPPER", &good).is_err());
        // serde round-trip (transparent: renders as a bare string)
        let json = serde_json::to_string(&pin).unwrap();
        assert_eq!(json, "\"node-01\"");
        assert_eq!(serde_json::from_str::<NodePin>(&json).unwrap(), pin);
    }

    #[test]
    fn reissue_deadline_is_half_life() {
        let nb = 1_000_000i64;
        let na = nb + WORKLOAD_DEFAULT_TTL_SECS as i64; // 6 h
        let deadline = reissue_deadline_secs(nb, na).expect("half-life");
        assert_eq!(deadline, nb + (WORKLOAD_DEFAULT_TTL_SECS as i64) / 2);
        assert!(!reissue_due(nb, na, deadline - 1), "not due before T/2");
        assert!(reissue_due(nb, na, deadline), "due exactly at T/2");
        assert!(reissue_due(nb, na, deadline + 1));
        // odd spans floor the half-life (never later than T/2)
        assert_eq!(reissue_deadline_secs(0, 5), Some(2));
    }

    #[test]
    fn reissue_deadline_degenerate_lifetimes() {
        assert_eq!(reissue_deadline_secs(10, 10), None);
        assert_eq!(reissue_deadline_secs(10, 9), None);
        assert!(!reissue_due(10, 10, i64::MAX));
        assert!(!reissue_due(10, 9, i64::MAX));
        // pre-epoch lifetimes work too
        assert_eq!(reissue_deadline_secs(-100, 100), Some(0));
        // span overflow (would overflow i64) is refused, not wrapped
        assert_eq!(reissue_deadline_secs(i64::MIN, i64::MAX), None);
    }

    #[test]
    fn revocation_freshness_gate_is_min_half_ttl_six_hours() {
        assert_eq!(
            revocation_freshness_gate_secs(24 * HOUR),
            REVOCATION_FRESHNESS_CAP_SECS
        );
        assert_eq!(revocation_freshness_gate_secs(8 * HOUR), 4 * HOUR);
        assert_eq!(revocation_freshness_gate_secs(2 * HOUR), HOUR);
        assert_eq!(revocation_freshness_gate_secs(60), 30);
        assert_eq!(revocation_freshness_gate_secs(0), 0);
    }

    #[test]
    fn join_token_ttl_cap() {
        assert!(validate_join_token_ttl(Duration::from_secs(JOIN_TOKEN_TTL_MAX_SECS)).is_ok());
        assert!(validate_join_token_ttl(Duration::from_secs(MIN)).is_ok());
        assert_eq!(
            validate_join_token_ttl(Duration::from_secs(JOIN_TOKEN_TTL_MAX_SECS + 1)),
            Err(PolicyError::JoinTokenTtlTooLong {
                requested_secs: JOIN_TOKEN_TTL_MAX_SECS + 1,
                max_secs: JOIN_TOKEN_TTL_MAX_SECS,
            })
        );
        assert_eq!(
            validate_join_token_ttl(Duration::ZERO),
            Err(PolicyError::ZeroTtl)
        );
    }
}

#[cfg(test)]
impl ServiceRegistry {
    /// Test helper: all current registrations are non-reserved and valid.
    fn filter_ok(&self) -> bool {
        self.names
            .iter()
            .all(|n| !is_reserved_service_name(n) && model::validate_service_name(n).is_ok())
    }
}
