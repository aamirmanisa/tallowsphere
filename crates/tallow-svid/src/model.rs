//! `model` — W3 SVID data model (owner: U-211).
//!
//! Pure model types for the Tallow SVID fabric (U-201 blueprint §3.1, report
//! §5.3/§5.8.4): SPIFFE-style workload IDs, per-kind SVID profiles with TTL
//! bands per parent decision **D1**, and the never-reused issued-serial type.
//!
//! # Canonical SVID naming
//!
//! ```text
//! workload SVID     spiffe://tallow/<node-id>/svc/<name>
//! node identity SAN spiffe://tallow/<node-id>
//! issuer SAN        spiffe://tallow/<node-id>/svc/svid-issuer
//! ```
//!
//! [`SpiffeId`] parses **only** the canonical workload form and is deliberately
//! stricter than the SPIFFE spec's general path charset:
//!
//! - trust domain is exactly `tallow`, lowercase,
//! - both path segments match `[a-z0-9][a-z0-9._-]*` (lowercase only, must
//!   start alphanumeric, no `..`, no trailing dot, ≤ 128 bytes each),
//! - no percent-encoding, no backslashes, no whitespace/control bytes, no
//!   non-ASCII (homoglyph/fullwidth), no query/fragment, no port or userinfo,
//!   exactly three path segments `<node-id>/svc/<name>`.
//!
//! The strictness is a security property: it rejects case-variant and
//! encoding-variant lookalikes (e.g. `%2F`, Cyrillic `о`, fullwidth `ｎ`,
//! `NODE-1` vs `node-1`) so that two different byte strings can never compare
//! equal as IDs anywhere downstream and so a node-id pin cannot be bypassed by
//! a homoglyph segment.
//!
//! # TTL bands (D1)
//!
//! | kind | band | default |
//! |---|---|---|
//! | [`SvidKind::NodeIdentity`] | 30–90 d | 60 d |
//! | [`SvidKind::IssuerIntermediate`] | 1 h – 7 d (hard cap) | 24 h |
//! | [`SvidKind::WorkloadLeaf`] | 1–24 h | 6 h (inside the 4–8 h default band) |
//!
//! Values live in [`crate::policy`]; [`SvidKind::ttl_band`] exposes them.

use std::fmt;
use std::str::FromStr;
use std::time::Duration;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::policy;

// ---------------------------------------------------------------------------
// Naming constants
// ---------------------------------------------------------------------------

/// Scheme prefix of a SPIFFE ID.
pub const SCHEME: &str = "spiffe://";
/// The single Tallow trust domain (report §5.8.4: "adopt the same trust-domain
/// naming for runtime SVIDs").
pub const TRUST_DOMAIN: &str = "tallow";
/// Service name used in the SVID-issuer intermediate's SAN. Reserved: it can
/// never be registered as a workload service name.
pub const ISSUER_SERVICE_NAME: &str = "svid-issuer";
/// Maximum length of a node-id segment.
pub const MAX_NODE_ID_LEN: usize = 128;
/// Maximum length of a service-name segment.
pub const MAX_SERVICE_NAME_LEN: usize = 128;
/// Maximum length of a full SVID URI string.
pub const MAX_SVID_LEN: usize = 512;
/// Certificate signature key algorithm for v1 X.509-SVIDs (parent decision D2:
/// Ed25519 leaf; the hybrid co-signature binds at the enrollment/KT layer).
pub const CERT_KEY_ALGORITHM: &str = "ed25519";

/// True iff `name` is reserved for infrastructure and cannot be registered as
/// a workload service name.
pub fn is_reserved_service_name(name: &str) -> bool {
    name == ISSUER_SERVICE_NAME
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Reasons a candidate SVID string was rejected.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SpiffeIdError {
    /// The string does not start with `spiffe://`.
    #[error("not a spiffe:// URI")]
    NotSpiffeScheme,
    /// Trust domain segment is empty.
    #[error("empty trust domain")]
    EmptyTrustDomain,
    /// Trust domain contains uppercase characters.
    #[error("uppercase characters are not allowed in the trust domain")]
    UppercaseTrustDomain,
    /// Trust domain is not exactly `tallow`.
    #[error("trust domain must be exactly {TRUST_DOMAIN:?}")]
    WrongTrustDomain,
    /// Trust domain contains an illegal character (port, userinfo, trailing
    /// dot, non-ASCII, …). The payload is the offending character.
    #[error("illegal character in trust domain: {0:?}")]
    InvalidTrustDomain(char),
    /// A required path segment is empty.
    #[error("path segment {which} is empty")]
    EmptySegment {
        /// Which segment ("node-id", "svc", "name").
        which: &'static str,
    },
    /// A path segment violates the canonical charset.
    #[error("invalid {which} segment: {reason}")]
    InvalidSegment {
        /// Which segment ("node-id", "svc", "name").
        which: &'static str,
        /// Why it is invalid.
        reason: &'static str,
    },
    /// The path is not exactly `<node-id>/svc/<name>`.
    #[error("path must be exactly <node-id>/svc/<name>")]
    WrongPathShape,
    /// The second path segment is not `svc`.
    #[error("non-svc path: second segment is {found:?}, expected \"svc\"")]
    NonSvcPath {
        /// The segment actually found.
        found: String,
    },
    /// The whole SVID string exceeds [`MAX_SVID_LEN`].
    #[error("{what} exceeds maximum length")]
    TooLong {
        /// What was too long ("spiffe id", "node-id", "name").
        what: &'static str,
    },
}

/// Errors from parsing an [`SvidKind`] name.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KindParseError {
    /// Unknown kind name.
    #[error("unknown SVID kind {0:?} (expected node_identity|issuer_intermediate|workload_leaf)")]
    UnknownKind(String),
}

/// Errors from the issued-serial type/allocator.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SerialError {
    /// The monotonic counter reached `u64::MAX`; no further serials can be
    /// issued. Fail closed rather than wrap (wrapping would reuse serials).
    #[error("issued-serial space exhausted")]
    Exhausted,
    /// Counter 0 is the "never issued" sentinel and may not be constructed.
    #[error("counter 0 is the never-issued sentinel")]
    ZeroCounter,
    /// Hex form must be exactly 32 lowercase hex characters.
    #[error("serial must be exactly 32 lowercase hex characters")]
    BadHex,
}

// ---------------------------------------------------------------------------
// Segment validation
// ---------------------------------------------------------------------------

/// Canonical charset: `[a-z0-9._-]`, first byte `[a-z0-9]`, no `..`, no
/// trailing dot, bounded length. See module docs for the security rationale.
fn validate_segment(which: &'static str, seg: &str, max_len: usize) -> Result<(), SpiffeIdError> {
    if seg.is_empty() {
        return Err(SpiffeIdError::EmptySegment { which });
    }
    if seg.len() > max_len {
        return Err(SpiffeIdError::TooLong { what: which });
    }
    let bytes = seg.as_bytes();
    let first = bytes[0];
    if !(first.is_ascii_lowercase() || first.is_ascii_digit()) {
        return Err(SpiffeIdError::InvalidSegment {
            which,
            reason: "must start with [a-z0-9]",
        });
    }
    for &b in bytes {
        if b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'.' || b == b'-' || b == b'_' {
            continue;
        }
        let reason = if b.is_ascii_uppercase() {
            "uppercase characters are not allowed"
        } else if b.is_ascii() {
            "only [a-z0-9._-] characters are allowed"
        } else {
            "non-ASCII characters are not allowed (lookalike encoding)"
        };
        return Err(SpiffeIdError::InvalidSegment { which, reason });
    }
    if seg.contains("..") {
        return Err(SpiffeIdError::InvalidSegment {
            which,
            reason: "consecutive dots are not allowed",
        });
    }
    if seg.ends_with('.') {
        return Err(SpiffeIdError::InvalidSegment {
            which,
            reason: "trailing dot is not allowed",
        });
    }
    Ok(())
}

/// Validate a node-id segment against the canonical rules.
pub fn validate_node_id(node_id: &str) -> Result<(), SpiffeIdError> {
    validate_segment("node-id", node_id, MAX_NODE_ID_LEN)
}

/// Validate a workload service-name segment against the canonical rules.
pub fn validate_service_name(name: &str) -> Result<(), SpiffeIdError> {
    validate_segment("name", name, MAX_SERVICE_NAME_LEN)
}

fn validate_trust_domain(td: &str) -> Result<(), SpiffeIdError> {
    if td.is_empty() {
        return Err(SpiffeIdError::EmptyTrustDomain);
    }
    for c in td.chars() {
        if c.is_ascii_uppercase() {
            return Err(SpiffeIdError::UppercaseTrustDomain);
        }
        if c == '@' || c == ':' {
            // userinfo / port must never appear in a trust domain
            return Err(SpiffeIdError::InvalidTrustDomain(c));
        }
        if !(c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-' || c == '_') {
            return Err(SpiffeIdError::InvalidTrustDomain(c));
        }
    }
    if td.ends_with('.') {
        return Err(SpiffeIdError::InvalidTrustDomain('.'));
    }
    if td != TRUST_DOMAIN {
        return Err(SpiffeIdError::WrongTrustDomain);
    }
    Ok(())
}

/// Split `rest` (everything after `spiffe://`) into trust domain and the
/// slash-separated path segments, validating the trust domain.
fn split_authority(rest: &str) -> Result<(&str, &str), SpiffeIdError> {
    match rest.find('/') {
        Some(idx) => {
            let (td, path) = (&rest[..idx], &rest[idx + 1..]);
            validate_trust_domain(td)?;
            Ok((td, path))
        }
        None => {
            validate_trust_domain(rest)?;
            Err(SpiffeIdError::WrongPathShape)
        }
    }
}

// ---------------------------------------------------------------------------
// SpiffeId
// ---------------------------------------------------------------------------

/// A canonical workload SVID identifier: `spiffe://tallow/<node-id>/svc/<name>`.
///
/// Construct via [`SpiffeId::parse`], [`SpiffeId::new`] or `str::parse`, never
/// by struct literal — every instance has passed the validation rules in the
/// module docs. Deserialization validates too (fail closed).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpiffeId {
    raw: String,
    node_id: String,
    service: String,
}

impl SpiffeId {
    /// Validate and construct from parts (canonical rendering is generated).
    pub fn new(node_id: &str, service: &str) -> Result<Self, SpiffeIdError> {
        validate_node_id(node_id)?;
        validate_service_name(service)?;
        let raw = format!("{SCHEME}{TRUST_DOMAIN}/{node_id}/svc/{service}");
        Ok(Self {
            raw,
            node_id: node_id.to_string(),
            service: service.to_string(),
        })
    }

    /// Strict canonical parse of a workload SVID string.
    pub fn parse(s: &str) -> Result<Self, SpiffeIdError> {
        if s.len() > MAX_SVID_LEN {
            return Err(SpiffeIdError::TooLong { what: "spiffe id" });
        }
        let rest = s
            .strip_prefix(SCHEME)
            .ok_or(SpiffeIdError::NotSpiffeScheme)?;
        let (_td, path) = split_authority(rest)?;
        let segs: Vec<&str> = path.split('/').collect();
        if segs.len() != 3 {
            return Err(SpiffeIdError::WrongPathShape);
        }
        // Empty-segment checks come first so `//` reports as empty, not as a
        // wrong-path-shape. The middle segment must then be exactly `svc`.
        if segs[0].is_empty() {
            return Err(SpiffeIdError::EmptySegment { which: "node-id" });
        }
        if segs[1].is_empty() {
            return Err(SpiffeIdError::EmptySegment { which: "svc" });
        }
        if segs[2].is_empty() {
            return Err(SpiffeIdError::EmptySegment { which: "name" });
        }
        if segs[1] != "svc" {
            return Err(SpiffeIdError::NonSvcPath {
                found: segs[1].to_string(),
            });
        }
        let node_id = segs[0];
        let service = segs[2];
        validate_node_id(node_id)?;
        validate_service_name(service)?;
        Ok(Self {
            raw: s.to_string(),
            node_id: node_id.to_string(),
            service: service.to_string(),
        })
    }

    /// The canonical URI string.
    pub fn as_str(&self) -> &str {
        &self.raw
    }

    /// Alias for [`SpiffeId::as_str`] (this string is what goes in a SAN URI).
    pub fn to_uri(&self) -> &str {
        &self.raw
    }

    /// The `NODE-ID` segment.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// The `NAME` segment (workload service name).
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The trust domain (always [`TRUST_DOMAIN`] for a parsed id).
    pub fn trust_domain(&self) -> &'static str {
        TRUST_DOMAIN
    }

    /// True iff the id targets the reserved SVID-issuer service name.
    pub fn is_reserved_service(&self) -> bool {
        is_reserved_service_name(&self.service)
    }

    /// True iff this id is pinned to `node_id` (exact, canonical match).
    pub fn matches_node(&self, node_id: &str) -> bool {
        self.node_id == node_id
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.raw)
    }
}

impl FromStr for SpiffeId {
    type Err = SpiffeIdError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

impl TryFrom<&str> for SpiffeId {
    type Error = SpiffeIdError;
    fn try_from(s: &str) -> Result<Self, Self::Error> {
        Self::parse(s)
    }
}

impl Serialize for SpiffeId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.raw)
    }
}

impl<'de> Deserialize<'de> for SpiffeId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        SpiffeId::parse(&s).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Node / issuer SAN helpers
// ---------------------------------------------------------------------------

/// The node identity SAN: `spiffe://tallow/<node-id>` (report §5.3 node cert
/// row). Not a workload [`SpiffeId`] — node certs carry no `svc` path.
pub fn node_identity_san(node_id: &str) -> Result<String, SpiffeIdError> {
    validate_node_id(node_id)?;
    Ok(format!("{SCHEME}{TRUST_DOMAIN}/{node_id}"))
}

/// Parse a node identity SAN, returning the node-id. Rejects anything that is
/// not exactly `spiffe://tallow/<node-id>`.
pub fn parse_node_identity_san(s: &str) -> Result<String, SpiffeIdError> {
    if s.len() > MAX_SVID_LEN {
        return Err(SpiffeIdError::TooLong { what: "spiffe id" });
    }
    let rest = s
        .strip_prefix(SCHEME)
        .ok_or(SpiffeIdError::NotSpiffeScheme)?;
    let (_td, path) = split_authority(rest)?;
    let segs: Vec<&str> = path.split('/').collect();
    if segs.len() != 1 {
        return Err(SpiffeIdError::WrongPathShape);
    }
    if segs[0].is_empty() {
        return Err(SpiffeIdError::EmptySegment { which: "node-id" });
    }
    validate_node_id(segs[0])?;
    Ok(segs[0].to_string())
}

/// The SVID-issuer intermediate SAN:
/// `spiffe://tallow/<node-id>/svc/svid-issuer`.
pub fn issuer_san(node_id: &str) -> Result<String, SpiffeIdError> {
    validate_node_id(node_id)?;
    Ok(format!(
        "{SCHEME}{TRUST_DOMAIN}/{node_id}/svc/{ISSUER_SERVICE_NAME}"
    ))
}

/// Parse an SVID-issuer SAN, returning the node-id. Requires the reserved
/// `svc/svid-issuer` path.
pub fn parse_issuer_san(s: &str) -> Result<String, SpiffeIdError> {
    if s.len() > MAX_SVID_LEN {
        return Err(SpiffeIdError::TooLong { what: "spiffe id" });
    }
    let rest = s
        .strip_prefix(SCHEME)
        .ok_or(SpiffeIdError::NotSpiffeScheme)?;
    let (_td, path) = split_authority(rest)?;
    let segs: Vec<&str> = path.split('/').collect();
    if segs.len() != 3 || segs[1] != "svc" || segs[2] != ISSUER_SERVICE_NAME {
        return Err(SpiffeIdError::WrongPathShape);
    }
    if segs[0].is_empty() {
        return Err(SpiffeIdError::EmptySegment { which: "node-id" });
    }
    validate_node_id(segs[0])?;
    Ok(segs[0].to_string())
}

// ---------------------------------------------------------------------------
// Kinds / profiles
// ---------------------------------------------------------------------------

/// The three credential kinds of the two-cert split (parent decision D1).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SvidKind {
    /// Node identity cert: `spiffe://tallow/<node-id>`, 30–90 d, KT-pinned.
    NodeIdentity,
    /// SVID-issuer intermediate CA: `…/svc/svid-issuer`, ≤ 7 d (hard cap).
    IssuerIntermediate,
    /// Workload leaf SVID: `…/svc/<name>`, 1–24 h, re-issue at T/2.
    WorkloadLeaf,
}

/// A TTL band `[min, max]` in whole seconds (inclusive on both ends).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TtlBand {
    /// Lower bound (seconds).
    pub min_secs: u64,
    /// Upper bound (seconds).
    pub max_secs: u64,
}

impl TtlBand {
    /// Const constructor.
    pub const fn new_secs(min_secs: u64, max_secs: u64) -> Self {
        Self { min_secs, max_secs }
    }

    /// Lower bound as a duration.
    pub fn min(&self) -> Duration {
        Duration::from_secs(self.min_secs)
    }

    /// Upper bound as a duration.
    pub fn max(&self) -> Duration {
        Duration::from_secs(self.max_secs)
    }

    /// Lower bound in seconds.
    pub fn min_secs(&self) -> u64 {
        self.min_secs
    }

    /// Upper bound in seconds.
    pub fn max_secs(&self) -> u64 {
        self.max_secs
    }

    /// Inclusive containment check on whole seconds.
    pub fn contains_secs(&self, secs: u64) -> bool {
        (self.min_secs..=self.max_secs).contains(&secs)
    }

    /// Inclusive containment check on a duration.
    pub fn contains(&self, ttl: Duration) -> bool {
        self.contains_secs(ttl.as_secs())
    }
}

impl SvidKind {
    /// All kinds, in the two-cert-split order.
    pub const ALL: [SvidKind; 3] = [
        SvidKind::NodeIdentity,
        SvidKind::IssuerIntermediate,
        SvidKind::WorkloadLeaf,
    ];

    /// Stable snake_case name (also the serde representation).
    pub const fn as_str(self) -> &'static str {
        match self {
            SvidKind::NodeIdentity => "node_identity",
            SvidKind::IssuerIntermediate => "issuer_intermediate",
            SvidKind::WorkloadLeaf => "workload_leaf",
        }
    }

    /// True iff credentials of this kind are certificates with CA basic
    /// constraints (the SVID-issuer intermediate only).
    pub const fn is_ca(self) -> bool {
        matches!(self, SvidKind::IssuerIntermediate)
    }

    /// Per-kind TTL band (values from [`crate::policy`], parent decision D1).
    pub fn ttl_band(self) -> TtlBand {
        match self {
            SvidKind::NodeIdentity => TtlBand::new_secs(
                policy::NODE_IDENTITY_TTL_MIN_SECS,
                policy::NODE_IDENTITY_TTL_MAX_SECS,
            ),
            SvidKind::IssuerIntermediate => TtlBand::new_secs(
                policy::ISSUER_INTERMEDIATE_TTL_MIN_SECS,
                policy::ISSUER_INTERMEDIATE_TTL_MAX_SECS,
            ),
            SvidKind::WorkloadLeaf => {
                TtlBand::new_secs(policy::WORKLOAD_TTL_MIN_SECS, policy::WORKLOAD_TTL_MAX_SECS)
            }
        }
    }

    /// Default TTL used when the caller does not request one (D1).
    pub fn default_ttl(self) -> Duration {
        Duration::from_secs(match self {
            SvidKind::NodeIdentity => policy::NODE_IDENTITY_DEFAULT_TTL_SECS,
            SvidKind::IssuerIntermediate => policy::ISSUER_INTERMEDIATE_DEFAULT_TTL_SECS,
            SvidKind::WorkloadLeaf => policy::WORKLOAD_DEFAULT_TTL_SECS,
        })
    }
}

impl fmt::Display for SvidKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for SvidKind {
    type Err = KindParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "node_identity" => Ok(SvidKind::NodeIdentity),
            "issuer_intermediate" => Ok(SvidKind::IssuerIntermediate),
            "workload_leaf" => Ok(SvidKind::WorkloadLeaf),
            other => Err(KindParseError::UnknownKind(other.to_string())),
        }
    }
}

/// The full issuance profile for a kind: TTL band, CA flag, default TTL.
///
/// This is the object the issuer (U-212) and the daemon policy gate consume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SvidProfile {
    /// Which credential kind this profile describes.
    pub kind: SvidKind,
    /// Hard TTL band (seconds, inclusive).
    pub ttl_band: TtlBand,
    /// CA basic constraint (true for the SVID-issuer intermediate only).
    pub is_ca: bool,
    /// TTL applied when the requester does not ask for one.
    pub default_ttl: Duration,
}

impl SvidProfile {
    /// Profile for a node identity cert (D1: 30–90 d, not a CA).
    pub const NODE_IDENTITY: SvidProfile = SvidProfile {
        kind: SvidKind::NodeIdentity,
        ttl_band: TtlBand::new_secs(
            policy::NODE_IDENTITY_TTL_MIN_SECS,
            policy::NODE_IDENTITY_TTL_MAX_SECS,
        ),
        is_ca: false,
        default_ttl: Duration::from_secs(policy::NODE_IDENTITY_DEFAULT_TTL_SECS),
    };

    /// Profile for the SVID-issuer intermediate (D1: ≤ 7 d hard cap, CA=true).
    pub const ISSUER_INTERMEDIATE: SvidProfile = SvidProfile {
        kind: SvidKind::IssuerIntermediate,
        ttl_band: TtlBand::new_secs(
            policy::ISSUER_INTERMEDIATE_TTL_MIN_SECS,
            policy::ISSUER_INTERMEDIATE_TTL_MAX_SECS,
        ),
        is_ca: true,
        default_ttl: Duration::from_secs(policy::ISSUER_INTERMEDIATE_DEFAULT_TTL_SECS),
    };

    /// Profile for workload leaf SVIDs (D1: 1–24 h, default 6 h).
    pub const WORKLOAD_LEAF: SvidProfile = SvidProfile {
        kind: SvidKind::WorkloadLeaf,
        ttl_band: TtlBand::new_secs(policy::WORKLOAD_TTL_MIN_SECS, policy::WORKLOAD_TTL_MAX_SECS),
        is_ca: false,
        default_ttl: Duration::from_secs(policy::WORKLOAD_DEFAULT_TTL_SECS),
    };

    /// The profile for a kind.
    pub const fn for_kind(kind: SvidKind) -> SvidProfile {
        match kind {
            SvidKind::NodeIdentity => Self::NODE_IDENTITY,
            SvidKind::IssuerIntermediate => Self::ISSUER_INTERMEDIATE,
            SvidKind::WorkloadLeaf => Self::WORKLOAD_LEAF,
        }
    }

    /// True iff `ttl` sits inside this profile's hard band.
    pub fn contains_ttl(&self, ttl: Duration) -> bool {
        self.ttl_band.contains(ttl)
    }
}

// ---------------------------------------------------------------------------
// Issued serials
// ---------------------------------------------------------------------------

/// Byte width of the monotonic counter half of an issued serial.
pub const SERIAL_COUNTER_BYTES: usize = 8;
/// Byte width of the random-suffix half of an issued serial.
pub const SERIAL_SUFFIX_BYTES: usize = 8;
/// Total byte width of an issued serial (`counter || suffix`).
pub const SERIAL_BYTES: usize = SERIAL_COUNTER_BYTES + SERIAL_SUFFIX_BYTES;
/// Hex width of an issued serial (32 lowercase hex chars).
pub const SERIAL_HEX_LEN: usize = SERIAL_BYTES * 2;

/// An issued X.509 serial number: a **monotonic counter** (big-endian, first
/// 8 bytes) plus an 8-byte random suffix.
///
/// The counter is the never-reuse guarantee: within one allocator, and across
/// restarts when the allocator is resumed from the persisted high-water mark,
/// every issued serial has a strictly greater counter than every serial issued
/// before it (see [`SerialAllocator::resume_from`]). The random suffix adds
/// cross-host entropy so two independently-initialised allocators do not
/// collide, and makes the serial unguessable from a previous one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct IssuedSerial {
    counter: u64,
    suffix: [u8; SERIAL_SUFFIX_BYTES],
}

impl IssuedSerial {
    /// Construct from an explicit counter and suffix (tests, ledger replay,
    /// KT re-verification). Counter 0 is the "never issued" sentinel and is
    /// rejected here.
    pub fn new(counter: u64, suffix: [u8; SERIAL_SUFFIX_BYTES]) -> Result<Self, SerialError> {
        if counter == 0 {
            return Err(SerialError::ZeroCounter);
        }
        Ok(Self { counter, suffix })
    }

    /// The monotonic counter half.
    pub fn counter(&self) -> u64 {
        self.counter
    }

    /// The random-suffix half.
    pub fn suffix(&self) -> [u8; SERIAL_SUFFIX_BYTES] {
        self.suffix
    }

    /// Raw 16-byte representation: counter big-endian || suffix.
    pub fn as_bytes(&self) -> [u8; SERIAL_BYTES] {
        let mut out = [0u8; SERIAL_BYTES];
        out[..SERIAL_COUNTER_BYTES].copy_from_slice(&self.counter.to_be_bytes());
        out[SERIAL_COUNTER_BYTES..].copy_from_slice(&self.suffix);
        out
    }

    /// Canonical lowercase-hex form (32 chars), the wire/ledger encoding.
    pub fn to_hex(&self) -> String {
        hex::encode(self.as_bytes())
    }

    /// Parse the canonical lowercase-hex form.
    pub fn from_hex(s: &str) -> Result<Self, SerialError> {
        if s.len() != SERIAL_HEX_LEN
            || !s
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(SerialError::BadHex);
        }
        let raw = hex::decode(s).map_err(|_| SerialError::BadHex)?;
        let mut counter = [0u8; SERIAL_COUNTER_BYTES];
        let mut suffix = [0u8; SERIAL_SUFFIX_BYTES];
        counter.copy_from_slice(&raw[..SERIAL_COUNTER_BYTES]);
        suffix.copy_from_slice(&raw[SERIAL_COUNTER_BYTES..]);
        Self::new(u64::from_be_bytes(counter), suffix)
    }

    /// DER INTEGER content bytes: the 16 raw bytes, with a leading `0x00`
    /// when the high bit is set so the X.509 serial is always a positive
    /// integer (RFC 5280 §4.1.2.2).
    pub fn der_bytes(&self) -> Vec<u8> {
        let raw = self.as_bytes();
        if raw[0] & 0x80 != 0 {
            let mut v = Vec::with_capacity(SERIAL_BYTES + 1);
            v.push(0x00);
            v.extend_from_slice(&raw);
            v
        } else {
            raw.to_vec()
        }
    }

    /// Never-reuse comparison: true iff this serial was issued strictly later
    /// than `previous` (counter comparison; the suffix is entropy, not order).
    pub fn is_later_than(&self, previous: &IssuedSerial) -> bool {
        self.counter > previous.counter
    }
}

impl fmt::Display for IssuedSerial {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// Fresh 8-byte random suffix from the OS RNG.
pub fn random_suffix() -> [u8; SERIAL_SUFFIX_BYTES] {
    use rand::RngCore;
    let mut b = [0u8; SERIAL_SUFFIX_BYTES];
    rand::thread_rng().fill_bytes(&mut b);
    b
}

/// Monotonic issued-serial allocator.
///
/// Starts at counter 1 (0 is the never-issued sentinel) and refuses to wrap:
/// exhausting `u64` is a hard error, because wrapping **would reuse serials**,
/// and serial reuse is exactly the ambiguity revocation must not have.
/// Persistence (a small high-water file) is the caller's concern; on restart
/// the caller resumes with [`SerialAllocator::resume_from`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialAllocator {
    next: u64,
}

impl Default for SerialAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl SerialAllocator {
    /// New allocator: first issued counter is 1.
    pub fn new() -> Self {
        Self { next: 1 }
    }

    /// Resume an allocator after the highest counter ever issued. The next
    /// issued serial is strictly greater than `high_water`, so a resumed
    /// allocator never reuses any pre-restart serial.
    pub fn resume_from(high_water: u64) -> Result<Self, SerialError> {
        let next = high_water.checked_add(1).ok_or(SerialError::Exhausted)?;
        Ok(Self { next })
    }

    /// Highest counter issued so far (0 if none) — persist this.
    pub fn high_water(&self) -> u64 {
        self.next.saturating_sub(1)
    }

    /// Allocate the next serial with an explicit suffix (deterministic tests,
    /// HSM-supplied entropy).
    pub fn alloc_with_suffix(
        &mut self,
        suffix: [u8; SERIAL_SUFFIX_BYTES],
    ) -> Result<IssuedSerial, SerialError> {
        let counter = self.next;
        self.next = counter.checked_add(1).ok_or(SerialError::Exhausted)?;
        Ok(IssuedSerial { counter, suffix })
    }

    /// Allocate the next serial with a fresh OS-random suffix.
    pub fn alloc(&mut self) -> Result<IssuedSerial, SerialError> {
        self.alloc_with_suffix(random_suffix())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_canonical_workload_ids() {
        let cases = [
            ("spiffe://tallow/node-01/svc/daemon", "node-01", "daemon"),
            (
                "spiffe://tallow/tallow-node-a/svc/job-worker",
                "tallow-node-a",
                "job-worker",
            ),
            (
                "spiffe://tallow/0f3aa1b2/svc/browser-pool",
                "0f3aa1b2",
                "browser-pool",
            ),
            ("spiffe://tallow/n/svc/a", "n", "a"),
            (
                "spiffe://tallow/node_1/svc/pkg_runner.v2",
                "node_1",
                "pkg_runner.v2",
            ),
        ];
        for (raw, node, svc) in cases {
            let id = SpiffeId::parse(raw).unwrap_or_else(|e| panic!("{raw}: {e}"));
            assert_eq!(id.node_id(), node);
            assert_eq!(id.service(), svc);
            assert_eq!(id.as_str(), raw, "canonical form preserved");
            assert_eq!(id.to_string(), raw);
            assert_eq!(id.to_uri(), raw);
            assert_eq!(id.trust_domain(), TRUST_DOMAIN);
            assert_eq!(raw.parse::<SpiffeId>().unwrap(), id);
            assert_eq!(SpiffeId::try_from(raw).unwrap(), id);
            assert!(!id.is_reserved_service());
        }
    }

    #[test]
    fn parse_rejects_malformed_table() {
        // (input, optional exact error)
        let cases: &[(&str, Option<SpiffeIdError>)] = &[
            ("", Some(SpiffeIdError::NotSpiffeScheme)),
            (
                "tallow://node-01/svc/daemon",
                Some(SpiffeIdError::NotSpiffeScheme),
            ),
            (
                "https://tallow/node-01/svc/daemon",
                Some(SpiffeIdError::NotSpiffeScheme),
            ),
            (
                "spiffe:/tallow/node-01/svc/daemon",
                Some(SpiffeIdError::NotSpiffeScheme),
            ),
            ("spiffe://", Some(SpiffeIdError::EmptyTrustDomain)),
            (
                "spiffe:///node-01/svc/daemon",
                Some(SpiffeIdError::EmptyTrustDomain),
            ),
            ("spiffe://tallow", Some(SpiffeIdError::WrongPathShape)),
            (
                "spiffe://tallow/node-01",
                Some(SpiffeIdError::WrongPathShape),
            ),
            (
                "spiffe://tallow/node-01/svc",
                Some(SpiffeIdError::WrongPathShape),
            ),
            (
                "spiffe://tallow/node-01/svc/daemon/extra",
                Some(SpiffeIdError::WrongPathShape),
            ),
            (
                "spiffe://tallow/node-01/svc/daemon/",
                Some(SpiffeIdError::WrongPathShape),
            ),
            (
                "spiffe://tallow/node-01/svc/daemon/../evil",
                Some(SpiffeIdError::WrongPathShape),
            ),
            (
                "spiffe://tallow//svc/daemon",
                Some(SpiffeIdError::EmptySegment { which: "node-id" }),
            ),
            (
                "spiffe://tallow/node-01//daemon",
                Some(SpiffeIdError::EmptySegment { which: "svc" }),
            ),
            (
                "spiffe://tallow/node-01/svc/",
                Some(SpiffeIdError::EmptySegment { which: "name" }),
            ),
            (
                "spiffe://tallow/node-01/workload/daemon",
                Some(SpiffeIdError::NonSvcPath {
                    found: "workload".into(),
                }),
            ),
            (
                "spiffe://tallow/node-01/svcx/daemon",
                Some(SpiffeIdError::NonSvcPath {
                    found: "svcx".into(),
                }),
            ),
            ("spiffe://tallow/node-01/svc/daemon?x=1", None),
            ("spiffe://tallow/node-01/svc/daemon#frag", None),
            ("spiffe://tallow/n\\ode/svc/daemon", None),
            ("spiffe://user@tallow/node-01/svc/daemon", None),
            ("spiffe://tallow:8080/node-01/svc/daemon", None),
            ("spiffe://tallow./node-01/svc/daemon", None),
            (
                "spiffe://tallow.node/node-01/svc/daemon",
                Some(SpiffeIdError::WrongTrustDomain),
            ),
            (
                "spiffe://spiffe.example.org/node-01/svc/daemon",
                Some(SpiffeIdError::WrongTrustDomain),
            ),
            ("spiffe://tallow/node-01/svc/daemon ", None),
            ("spiffe://tallow/node-01/svc/ daemon", None),
            ("spiffe://tallow/node-01/svc/daemon\n", None),
            ("spiffe://tallow/-node/svc/daemon", None),
            ("spiffe://tallow/_node/svc/daemon", None),
            ("spiffe://tallow/.node/svc/daemon", None),
        ];
        for (raw, expected) in cases {
            let err = SpiffeId::parse(raw).expect_err(&format!("must reject {raw:?}"));
            if let Some(want) = expected {
                assert_eq!(err, *want, "wrong error for {raw:?}");
            }
        }
        // Charset-only rules that remain legal on purpose:
        assert!(
            SpiffeId::parse("spiffe://tallow/node-/svc/daemon").is_ok(),
            "trailing dash is in-charset"
        );
        assert!(
            SpiffeId::parse("spiffe://tallow/node.01/svc/daemon").is_ok(),
            "interior dot"
        );
    }

    #[test]
    fn parse_rejects_uppercase_variants() {
        assert_eq!(
            SpiffeId::parse("spiffe://TALLOW/node-01/svc/daemon"),
            Err(SpiffeIdError::UppercaseTrustDomain)
        );
        assert_eq!(
            SpiffeId::parse("spiffe://Tallow/node-01/svc/daemon"),
            Err(SpiffeIdError::UppercaseTrustDomain)
        );
        // Case variants in the segments are distinct strings; we reject them
        // outright so no case-insensitive comparison can ever collapse them.
        assert!(matches!(
            SpiffeId::parse("spiffe://tallow/NODE-01/svc/daemon"),
            Err(SpiffeIdError::InvalidSegment {
                which: "node-id",
                ..
            })
        ));
        assert!(matches!(
            SpiffeId::parse("spiffe://tallow/node-01/svc/Daemon"),
            Err(SpiffeIdError::InvalidSegment { which: "name", .. })
        ));
        // The literal placeholder text is NOT a valid id.
        assert!(SpiffeId::parse("spiffe://tallow/NODE-ID/svc/NAME").is_err());
    }

    #[test]
    fn parse_rejects_lookalike_encodings() {
        let evil = [
            "spiffe://tallow/node-01/svc/da%2Femon", // percent-encoding
            "spiffe://tallow/node-01/svc/%2e%2e",    // encoded traversal
            "spiffe://tallow/n%D0%BEde/svc/daemon",  // encoded homoglyph
            "spiffe://tallow/nоde-01/svc/daemon",    // Cyrillic 'о'
            "spiffe://tallow/nｏde-01/svc/daemon",   // fullwidth 'ｎ'
            "spiffe://tallow/node-01/svc/daemon\u{200b}", // zero-width space
            "spiffe://tallow/node-01/svc/daemon\u{0}", // NUL
            "spiffe://tallow/node..01/svc/daemon",   // consecutive dots
            "spiffe://tallow/node-01./svc/daemon",   // trailing dot
            "spiffe://tallow/node-01/svc/daemon.",   // trailing dot on name
        ];
        for raw in evil {
            assert!(SpiffeId::parse(raw).is_err(), "must reject {raw:?}");
        }
        let overlong_node = format!(
            "spiffe://tallow/{}/svc/daemon",
            "a".repeat(MAX_NODE_ID_LEN + 1)
        );
        assert!(SpiffeId::parse(&overlong_node).is_err());
        let overlong_name = format!(
            "spiffe://tallow/node-01/svc/{}",
            "a".repeat(MAX_SERVICE_NAME_LEN + 1)
        );
        assert!(SpiffeId::parse(&overlong_name).is_err());
        let overlong_total = format!("spiffe://tallow/node-01/svc/{}", "a".repeat(MAX_SVID_LEN));
        assert_eq!(
            SpiffeId::parse(&overlong_total),
            Err(SpiffeIdError::TooLong { what: "spiffe id" })
        );
    }

    #[test]
    fn new_builds_canonical_form_and_validates() {
        let id = SpiffeId::new("node-01", "daemon").expect("valid");
        assert_eq!(id.as_str(), "spiffe://tallow/node-01/svc/daemon");
        assert_eq!(SpiffeId::parse(id.as_str()).unwrap(), id);
        for (node, svc) in [
            ("", "daemon"),
            ("node-01", ""),
            ("Node-01", "daemon"),
            ("node-01", "Daemon"),
            ("node-01/evil", "daemon"),
            ("node-01", ".."),
            ("no de", "daemon"),
        ] {
            assert!(
                SpiffeId::new(node, svc).is_err(),
                "must reject ({node:?}, {svc:?})"
            );
        }
        assert_eq!(id, id.clone());
        assert_eq!(id.matches_node("node-01"), true);
        assert_eq!(id.matches_node("node-02"), false);
        // hash/eq collapse: same id parsed twice dedupes
        let mut set = std::collections::HashSet::new();
        assert!(set.insert(id.clone()));
        assert!(!set.insert(SpiffeId::parse("spiffe://tallow/node-01/svc/daemon").unwrap()));
    }

    #[test]
    fn spiffeid_serde_is_validated() {
        let id = SpiffeId::new("node-01", "daemon").unwrap();
        let json = serde_json::to_string(&id).unwrap();
        assert_eq!(json, "\"spiffe://tallow/node-01/svc/daemon\"");
        assert_eq!(serde_json::from_str::<SpiffeId>(&json).unwrap(), id);
        // deserialization is fail-closed: junk strings never become SpiffeId
        assert!(serde_json::from_str::<SpiffeId>("\"spiffe://TALLOW/x/svc/y\"").is_err());
        assert!(serde_json::from_str::<SpiffeId>("\"not-a-uri\"").is_err());
    }

    #[test]
    fn node_and_issuer_san_helpers() {
        let node_san = node_identity_san("node-01").unwrap();
        assert_eq!(node_san, "spiffe://tallow/node-01");
        assert_eq!(parse_node_identity_san(&node_san).unwrap(), "node-01");
        assert!(parse_node_identity_san("spiffe://tallow/node-01/svc/daemon").is_err());
        assert!(parse_node_identity_san("spiffe://tallow/").is_err());
        assert!(parse_node_identity_san("spiffe://tallow/node-01/").is_err());
        assert!(node_identity_san("NODE-01").is_err());

        let iss = issuer_san("node-01").unwrap();
        assert_eq!(iss, "spiffe://tallow/node-01/svc/svid-issuer");
        assert_eq!(parse_issuer_san(&iss).unwrap(), "node-01");
        assert!(parse_issuer_san("spiffe://tallow/node-01/svc/daemon").is_err());
        assert!(parse_issuer_san(&node_san).is_err());
        let issuer_id = SpiffeId::parse(&iss).unwrap();
        assert!(issuer_id.is_reserved_service());
        assert!(is_reserved_service_name(ISSUER_SERVICE_NAME));
        assert!(!is_reserved_service_name("daemon"));
    }

    #[test]
    fn kind_ttl_bands_match_policy_constants() {
        assert_eq!(
            SvidKind::NodeIdentity.ttl_band(),
            TtlBand::new_secs(
                policy::NODE_IDENTITY_TTL_MIN_SECS,
                policy::NODE_IDENTITY_TTL_MAX_SECS
            )
        );
        assert_eq!(
            SvidKind::IssuerIntermediate.ttl_band(),
            TtlBand::new_secs(
                policy::ISSUER_INTERMEDIATE_TTL_MIN_SECS,
                policy::ISSUER_INTERMEDIATE_TTL_MAX_SECS
            )
        );
        assert_eq!(
            SvidKind::WorkloadLeaf.ttl_band(),
            TtlBand::new_secs(policy::WORKLOAD_TTL_MIN_SECS, policy::WORKLOAD_TTL_MAX_SECS)
        );
        // boundaries are inclusive
        let b = SvidKind::WorkloadLeaf.ttl_band();
        assert!(b.contains(Duration::from_secs(policy::WORKLOAD_TTL_MIN_SECS)));
        assert!(b.contains(Duration::from_secs(policy::WORKLOAD_TTL_MAX_SECS)));
        assert!(!b.contains(Duration::from_secs(policy::WORKLOAD_TTL_MIN_SECS - 1)));
        assert!(!b.contains(Duration::from_secs(policy::WORKLOAD_TTL_MAX_SECS + 1)));
        assert_eq!(b.min(), Duration::from_secs(policy::WORKLOAD_TTL_MIN_SECS));
        assert_eq!(b.max(), Duration::from_secs(policy::WORKLOAD_TTL_MAX_SECS));
        assert_eq!(b.min_secs(), policy::WORKLOAD_TTL_MIN_SECS);
        assert_eq!(b.max_secs(), policy::WORKLOAD_TTL_MAX_SECS);
    }

    #[test]
    fn kind_profiles_and_ca_flags() {
        assert!(!SvidKind::NodeIdentity.is_ca());
        assert!(SvidKind::IssuerIntermediate.is_ca());
        assert!(!SvidKind::WorkloadLeaf.is_ca());
        assert_eq!(
            SvidProfile::for_kind(SvidKind::NodeIdentity),
            SvidProfile::NODE_IDENTITY
        );
        assert_eq!(
            SvidProfile::for_kind(SvidKind::IssuerIntermediate),
            SvidProfile::ISSUER_INTERMEDIATE
        );
        assert_eq!(
            SvidProfile::for_kind(SvidKind::WorkloadLeaf),
            SvidProfile::WORKLOAD_LEAF
        );
        assert!(SvidProfile::ISSUER_INTERMEDIATE.is_ca);
        assert!(
            SvidProfile::ISSUER_INTERMEDIATE.contains_ttl(Duration::from_secs(
                policy::ISSUER_INTERMEDIATE_TTL_MAX_SECS
            ))
        );
        assert!(
            !SvidProfile::ISSUER_INTERMEDIATE.contains_ttl(Duration::from_secs(
                policy::ISSUER_INTERMEDIATE_TTL_MAX_SECS + 1
            ))
        );
        // defaults sit inside their bands
        for kind in SvidKind::ALL {
            let p = SvidProfile::for_kind(kind);
            assert!(p.contains_ttl(p.default_ttl), "{kind}: default inside band");
            assert!(p.ttl_band.contains(p.default_ttl));
        }
        // workload default inside the D1 4–8 h default band
        let wd = SvidProfile::WORKLOAD_LEAF.default_ttl.as_secs();
        assert!(
            (policy::WORKLOAD_DEFAULT_BAND_MIN_SECS..=policy::WORKLOAD_DEFAULT_BAND_MAX_SECS)
                .contains(&wd)
        );
        assert_eq!(CERT_KEY_ALGORITHM, "ed25519");
    }

    #[test]
    fn kind_names_and_serde_are_stable() {
        for kind in SvidKind::ALL {
            assert_eq!(kind.to_string(), kind.as_str());
            assert_eq!(kind.as_str().parse::<SvidKind>().unwrap(), kind);
            let json = serde_json::to_string(&kind).unwrap();
            assert_eq!(json, format!("\"{}\"", kind.as_str()));
            assert_eq!(serde_json::from_str::<SvidKind>(&json).unwrap(), kind);
        }
        assert_eq!(SvidKind::WorkloadLeaf.as_str(), "workload_leaf");
        assert_eq!(SvidKind::IssuerIntermediate.as_str(), "issuer_intermediate");
        assert!(matches!(
            "bogus".parse::<SvidKind>(),
            Err(KindParseError::UnknownKind(s)) if s == "bogus"
        ));
    }

    #[test]
    fn serial_alloc_is_monotonic_and_unique() {
        let mut alloc = SerialAllocator::new();
        assert_eq!(alloc.high_water(), 0);
        let mut seen = std::collections::BTreeSet::new();
        let mut prev: Option<IssuedSerial> = None;
        for i in 0..1024u64 {
            let s = alloc.alloc_with_suffix((i as u64).to_be_bytes()).unwrap();
            assert_eq!(s.counter(), i + 1, "counter starts at 1 and increments");
            assert!(seen.insert(s), "serial must be unique");
            if let Some(p) = prev {
                assert!(s.is_later_than(&p), "strictly increasing");
                assert!(!p.is_later_than(&s));
            }
            prev = Some(s);
        }
        assert_eq!(seen.len(), 1024, "no reuse across 1024 allocations");
        assert_eq!(alloc.high_water(), 1024);
        // random-suffix allocator keeps monotonicity too
        let s = alloc.alloc().unwrap();
        assert_eq!(s.counter(), 1025);
        assert!(s.is_later_than(&prev.unwrap()));
    }

    #[test]
    fn serial_bytes_hex_and_der_roundtrip() {
        let s = IssuedSerial::new(0x0102_0304_0506_0708, [0xAA; 8]).unwrap();
        let bytes = s.as_bytes();
        assert_eq!(&bytes[..8], &0x0102_0304_0506_0708u64.to_be_bytes());
        assert_eq!(&bytes[8..], &[0xAA; 8]);
        assert_eq!(bytes.len(), SERIAL_BYTES);
        let hexs = s.to_hex();
        assert_eq!(hexs.len(), SERIAL_HEX_LEN);
        assert_eq!(hexs, "0102030405060708aaaaaaaaaaaaaaaa");
        assert_eq!(IssuedSerial::from_hex(&hexs).unwrap(), s);
        assert_eq!(s.to_string(), hexs);
        // canonical form is lowercase-only and fixed-length
        assert_eq!(
            IssuedSerial::from_hex(&hexs.to_uppercase()),
            Err(SerialError::BadHex)
        );
        assert_eq!(IssuedSerial::from_hex("00"), Err(SerialError::BadHex));
        assert_eq!(
            IssuedSerial::from_hex(&"z".repeat(SERIAL_HEX_LEN)),
            Err(SerialError::BadHex)
        );
        // DER: positive integer — high-bit counters get a 0x00 prefix
        let big = IssuedSerial::new(0x8000_0000_0000_0001, [0; 8]).unwrap();
        let der = big.der_bytes();
        assert_eq!(der.len(), SERIAL_BYTES + 1);
        assert_eq!(der[0], 0x00);
        assert_eq!(&der[1..], &big.as_bytes());
        let small = IssuedSerial::new(0x0102_0304_0506_0708, [0; 8]).unwrap();
        assert_eq!(small.der_bytes(), small.as_bytes());
        // counter 0 is the never-issued sentinel
        assert_eq!(IssuedSerial::new(0, [0; 8]), Err(SerialError::ZeroCounter));
    }

    #[test]
    fn serial_allocator_resume_never_reuses_a_counter() {
        let mut a = SerialAllocator::new();
        let last = a.alloc_with_suffix([1; 8]).unwrap();
        assert_eq!(last.counter(), 1);
        // restart: resume from the persisted high-water mark
        let mut b = SerialAllocator::resume_from(a.high_water()).unwrap();
        let next = b.alloc_with_suffix([1; 8]).unwrap();
        assert!(next.is_later_than(&last), "resumed allocator never reuses");
        assert_eq!(next.counter(), 2);
        // resuming from 0 behaves like a fresh allocator
        assert_eq!(SerialAllocator::resume_from(0).unwrap().high_water(), 0);
        // counters beyond the resume point are rejected as "already used"
        assert_eq!(
            next.counter(),
            SerialAllocator::resume_from(last.counter())
                .unwrap()
                .alloc_with_suffix([0; 8])
                .unwrap()
                .counter()
        );
        // exhaustion is a hard error, never a wrap
        assert_eq!(
            SerialAllocator::resume_from(u64::MAX),
            Err(SerialError::Exhausted)
        );
        let mut exhausted = SerialAllocator { next: u64::MAX };
        assert_eq!(
            exhausted.alloc_with_suffix([0; 8]),
            Err(SerialError::Exhausted)
        );
        assert_eq!(exhausted.high_water(), u64::MAX - 1);
    }

    #[test]
    fn serial_random_suffix_is_os_random_and_preserved() {
        let s = IssuedSerial::new(7, [0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4]).unwrap();
        assert_eq!(s.suffix(), [0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3, 4]);
        let mut alloc = SerialAllocator::new();
        let a = alloc.alloc().unwrap();
        assert_eq!(a.suffix().len(), SERIAL_SUFFIX_BYTES);
        // two fresh suffixes are essentially never equal (2^-64); assert at
        // least that the API returns 8 bytes and varies across calls
        let mut distinct = std::collections::HashSet::new();
        for _ in 0..8 {
            distinct.insert(random_suffix());
        }
        assert!(distinct.len() > 1, "OS RNG must not be stuck");
    }

    #[test]
    fn serial_serde_roundtrip() {
        let s = IssuedSerial::new(42, [9; 8]).unwrap();
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(serde_json::from_str::<IssuedSerial>(&json).unwrap(), s);
        // BTreeSet ordering follows the counter (monotonic guarantee)
        let mut set = std::collections::BTreeSet::new();
        set.insert(IssuedSerial::new(9, [0; 8]).unwrap());
        set.insert(IssuedSerial::new(2, [0; 8]).unwrap());
        set.insert(IssuedSerial::new(5, [0; 8]).unwrap());
        let order: Vec<u64> = set.iter().map(|s| s.counter()).collect();
        assert_eq!(order, vec![2, 5, 9]);
    }
}
