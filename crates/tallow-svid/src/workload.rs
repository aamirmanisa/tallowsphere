//! `workload` — Maskinporten-shape workload identity: a **certificate-backed
//! assertion** is exchanged for a **short-lived, scope-bound access token**
//! (row #91, batch-4 lane E; spec refs: `phase5-identity` drafts,
//! `agent-09-geopolitics.md:118,142`).
//!
//! # Shape (Maskinporten, offline)
//!
//! Maskinporten (the Norwegian government OAuth2 authority) works like this:
//! a client owning a registered certificate signs a short-lived JWT
//! *assertion* (`iss` = client id, `aud` = token endpoint, `iat`/`exp` ≤ 2 min,
//! single-use `jti`, `scope`) and POSTs it to the token endpoint; the endpoint
//! checks the assertion against the **registered certificate's** public key
//! and returns a short-lived access token carrying the granted `scope`.
//!
//! This module implements exactly that seam with the crate's offline stack —
//! no HTTP, no network, no new dependencies:
//!
//! ```text
//! WorkloadKey (Ed25519, tallow-crypto)
//!   └─ spki_der() ──► NodeIssuer.issue_workload_leaf_from_spki()  (existing SVID fabric)
//!   └─ mint_assertion(key, chain, id, audience, scopes, ttl, now) ──► AssertionProof
//!         (assertion signed with the workload key; cert DER carried alongside)
//!   └─ TokenAuthority::exchange(proof, now)                       (the token endpoint)
//!         ├─ validates the assertion (version, band, window, audience, jti)
//!         ├─ verifies the cert ties to `iss` (SAN) and to `kid` (SPKI SHA-256)
//!         ├─ verifies the assertion signature **with the certificate's key**
//!         ├─ refuses replayed jti, ungranted scopes, wrong node, expired cert
//!         └─ mints AccessToken (scopes, short TTL, parent_jti, cnf_kid)
//!   └─ TokenVerifier::verify(token, required_scopes, now)          (the resource side)
//!         └─ iss/aud/signature/window + every required scope present
//!   └─ verify_possession(token, subject_key, challenge, sig)       (proof of possession)
//! ```
//!
//! # Fail-closed refusals (all typed, none "assume ok")
//!
//! * **replay** — a `jti` is single-use per issuer inside its validity window
//!   ([`ReplayStore`]); reused assertions are refused ([`WorkloadError::Replay`]).
//! * **expiry** — both assertions and tokens are strict: `iat <= now < exp`
//!   with **no grace**. Lifetime is additionally banded (assertion ≤ 120 s,
//!   token ≤ 15 min) so a long-lived assertion cannot be smuggled in.
//! * **scope-mismatch** — the authority refuses to mint any scope the caller
//!   was not granted (no silent narrowing, no partial grant), and the verifier
//!   refuses a token missing any required scope.
//! * **wrong-issuer/audience** — the assertion `aud` must equal the authority
//!   id; the token `iss`/`aud` must equal the verifier's configured authority.
//! * **wrong-key/wrong-cert** — the assertion signature is checked with the
//!   key inside the presented certificate, and that certificate's SAN must
//!   equal `iss` byte-for-byte, its SPKI SHA-256 must equal `kid`, and its
//!   SHA-256 must equal the signed `cert_sha256` digest. A stolen assertion
//!   signed by a different key never verifies.
//! * **wrong node / reserved subject** — the authority node-pins the subject
//!   (ATK-2.10, reusing [`crate::policy::check_node_pin`]) and refuses the
//!   reserved `svc/svid-issuer` subject.
//!
//! # Canonical bytes
//!
//! Signatures cover **canonical, domain-separated, length-prefixed bytes**
//! (`tallow-workload-assertion-v1` / `tallow-workload-token-v1`), never the
//! JSON encoding — so wire re-serialization, JSON key order and whitespace can
//! never change what was signed. Scope lists inside the signed payload must be
//! in canonical (sorted, deduplicated) form; non-canonical lists are refused
//! at validation time rather than normalized.
//!
//! # Honest scope of this module [partial]
//!
//! * No transport: `exchange` is an in-process call. The HTTP/JWT-wire
//!   envelope (and the `tallow` CLI plumbing) is recorded in the lane log's
//!   §OPEN — `src/main.rs` is unowned this wave.
//! * The authority's key is passed in (vault custody / rotation is the
//!   existing SVID/O-03 concern); this module performs no key persistence.
//! * `ReplayStore` is in-memory, per-process. Durable single-use state across
//!   restarts is a daemon-custody item (see §OPEN in the lane log).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tallow_crypto::sig::ed25519::{self, Ed25519Signer};

use crate::issuer::der;
use crate::issuer::now_unix;
use crate::model::{self, SpiffeId};
use crate::policy::{self, PolicyError, ServiceRegistry};
use crate::verify::match_san_uri;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Wire version of [`WorkloadAssertion`].
pub const ASSERTION_VERSION: u8 = 1;
/// Wire version of [`AccessToken`].
pub const TOKEN_VERSION: u8 = 1;

/// Canonical-bytes domain tag for the assertion signature (v1).
pub const ASSERTION_DOMAIN: &[u8] = b"tallow-workload-assertion-v1";
/// Canonical-bytes domain tag for the access-token signature (v1).
pub const TOKEN_DOMAIN: &[u8] = b"tallow-workload-token-v1";

/// Minimum assertion lifetime (seconds). A zero/negative window is refused.
pub const ASSERTION_TTL_MIN_SECS: i64 = 1;
/// Maximum assertion lifetime (seconds) — the Maskinporten 2-minute rule.
pub const ASSERTION_MAX_TTL_SECS: i64 = 120;
/// Default assertion lifetime (seconds) when the caller does not choose one.
pub const ASSERTION_DEFAULT_TTL_SECS: i64 = 120;
/// Maximum number of scopes an assertion may request (fail closed above).
pub const MAX_SCOPES_PER_ASSERTION: usize = 64;

/// Minimum access-token lifetime (seconds).
pub const TOKEN_TTL_MIN_SECS: i64 = 1;
/// Maximum access-token lifetime (seconds) — "short-lived" is enforced, not
/// merely intended.
pub const TOKEN_MAX_TTL_SECS: i64 = 15 * 60;
/// Default access-token lifetime (seconds) minted by [`TokenAuthority`].
pub const TOKEN_DEFAULT_TTL_SECS: i64 = 5 * 60;

/// Maximum length of the `aud` string carried in an assertion/token.
pub const MAX_AUD_LEN: usize = 256;

/// Hex length of a `jti` (`JTI_BYTES` random bytes, lowercase hex).
pub const JTI_HEX_LEN: usize = 32;
/// Random bytes in a fresh `jti`.
pub const JTI_BYTES: usize = JTI_HEX_LEN / 2;
/// Hex length of an SPKI SHA-256 / cert SHA-256 digest (`kid`, `cert_sha256`).
pub const DIGEST_HEX_LEN: usize = 64;
/// Ed25519 signature length in bytes.
pub const SIGNATURE_LEN: usize = 64;
/// Maximum live entries in one [`ReplayStore`] before it fails closed.
pub const MAX_REPLAY_ENTRIES: usize = 65_536;

/// The 12-byte DER prefix of an Ed25519 `SubjectPublicKeyInfo`
/// (`SEQUENCE { SEQUENCE { OID 1.3.101.112 } BIT STRING 00 || key }`).
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every way assertion minting, exchange or token verification can fail.
///
/// All variants are refusals: no path returns a token/`VerifiedToken` for a
/// credential that failed any check, and none falls back to "assume valid".
#[derive(Debug, Clone, thiserror::Error)]
pub enum WorkloadError {
    /// A scope string is not canonical `<service>:<action>`.
    #[error("malformed scope {scope:?}: {reason}")]
    ScopeMalformed {
        /// The offending string.
        scope: String,
        /// Why it was refused.
        reason: String,
    },
    /// No scopes supplied where at least one is required.
    #[error("empty scope set")]
    EmptyScope,
    /// More scopes than [`MAX_SCOPES_PER_ASSERTION`].
    #[error("too many scopes: {count} > {max}")]
    TooManyScopes {
        /// Supplied count.
        count: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// Subject/service name violations that are not scope strings (grants,
    /// caller names, reserved services).
    #[error("invalid service name {name:?}: {reason}")]
    InvalidServiceName {
        /// The offending name.
        name: String,
        /// Why it was refused.
        reason: String,
    },
    /// Unknown assertion/token wire version.
    #[error("unsupported {what} version {found} (expected {expected})")]
    Version {
        /// "assertion" or "token".
        what: &'static str,
        /// Version found in the credential.
        found: u8,
        /// Version this module understands.
        expected: u8,
    },
    /// Assertion lifetime outside the short-TTL band.
    #[error("assertion ttl {ttl_secs}s outside band {min_secs}..={max_secs}s")]
    AssertionTtl {
        /// Lifetime in seconds.
        ttl_secs: i64,
        /// Band minimum.
        min_secs: i64,
        /// Band maximum.
        max_secs: i64,
    },
    /// Assertion lifetime already over at the evaluation instant.
    #[error("assertion expired at {exp} (now {now})")]
    AssertionExpired {
        /// `exp` of the assertion.
        exp: i64,
        /// Evaluation instant.
        now: i64,
    },
    /// Assertion `iat` lies in the future (no clock-skew grace, fail closed).
    #[error("assertion not yet valid: iat {iat} > now {now}")]
    AssertionNotYetValid {
        /// `iat` of the assertion.
        iat: i64,
        /// Evaluation instant.
        now: i64,
    },
    /// The assertion is addressed to a different authority.
    #[error("assertion audience mismatch: expected {expected:?}, got {got:?}")]
    AudienceMismatch {
        /// Audience this authority answers to.
        expected: String,
        /// Audience found in the assertion.
        got: String,
    },
    /// The assertion subject is the reserved `svc/svid-issuer` identity.
    #[error("assertion subject uses the reserved issuer service name")]
    ReservedSubject,
    /// The assertion subject is pinned to a different node than the authority.
    #[error("node pin: {0}")]
    NodePin(#[from] PolicyError),
    /// The presented certificate did not tie to the assertion identity.
    #[error("certificate identity mismatch: {reason}")]
    CertIdentity {
        /// Why the tie failed (bad DER, SAN mismatch, CA flag, ...).
        reason: String,
    },
    /// `sha256(cert_der)` does not equal the signed `cert_sha256` digest.
    #[error("certificate digest mismatch: signed {expected:?}, presented {got:?}")]
    CertDigestMismatch {
        /// Digest committed inside the signed assertion.
        expected: String,
        /// Digest of the presented certificate.
        got: String,
    },
    /// The certificate is outside its validity window at the evaluation instant.
    #[error("certificate not valid at {now}: window [{not_before}, {not_after})")]
    CertNotValid {
        /// notBefore of the certificate.
        not_before: i64,
        /// notAfter of the certificate.
        not_after: i64,
        /// Evaluation instant.
        now: i64,
    },
    /// The SPKI SHA-256 in `kid` does not match the certificate's key.
    #[error("kid mismatch: certificate SPKI sha256 {expected:?}, assertion kid {got:?}")]
    KidMismatch {
        /// `kid` computed from the presented certificate.
        expected: String,
        /// `kid` claimed by the assertion.
        got: String,
    },
    /// The workload key does not correspond to the certified SVID key.
    #[error("workload key does not match the SVID certificate's key")]
    KeyCertMismatch,
    /// Ed25519 signature verification failed (or the signature was malformed).
    #[error("signature verification failed: {0}")]
    Signature(String),
    /// A `jti` is malformed (must be [`JTI_HEX_LEN`] lowercase hex chars).
    #[error("malformed jti {jti:?}: expected {expected} lowercase hex chars")]
    JtiMalformed {
        /// The offending value.
        jti: String,
        /// Expected hex length.
        expected: usize,
    },
    /// A `jti` was already used by this issuer inside its validity window.
    #[error("replayed jti {jti:?} (already used by issuer)")]
    Replay {
        /// The reused `jti`.
        jti: String,
    },
    /// The replay store hit its fail-closed entry cap (all entries live).
    #[error("replay store full ({max} live entries): refusing new assertions")]
    ReplayStoreFull {
        /// The configured cap.
        max: usize,
    },
    /// The caller asked for a scope it was not granted.
    #[error("scope not granted to caller: {scope}")]
    ScopeNotGranted {
        /// The refused scope.
        scope: String,
    },
    /// Token lifetime outside the short-TTL band.
    #[error("token ttl {ttl_secs}s outside band {min_secs}..={max_secs}s")]
    TokenTtl {
        /// Lifetime in seconds.
        ttl_secs: i64,
        /// Band minimum.
        min_secs: i64,
        /// Band maximum.
        max_secs: i64,
    },
    /// Token lifetime already over at the evaluation instant.
    #[error("token expired at {exp} (now {now})")]
    TokenExpired {
        /// `exp` of the token.
        exp: i64,
        /// Evaluation instant.
        now: i64,
    },
    /// Token `iat` lies in the future.
    #[error("token not yet valid: iat {iat} > now {now}")]
    TokenNotYetValid {
        /// `iat` of the token.
        iat: i64,
        /// Evaluation instant.
        now: i64,
    },
    /// Token `iss`/`aud` is not the authority the verifier trusts.
    #[error("wrong issuer/audience: expected {expected:?}, got iss {got_iss:?} / aud {got_aud:?}")]
    WrongIssuer {
        /// The authority the verifier trusts.
        expected: String,
        /// `iss` found in the token.
        got_iss: String,
        /// `aud` found in the token.
        got_aud: String,
    },
    /// A required scope is missing from the token (scope mismatch).
    #[error("token scope mismatch: required scope {required:?} not present")]
    ScopeMissing {
        /// The required scope that was absent.
        required: String,
    },
    /// The token is not bound to the presented subject key (`cnf_kid`).
    #[error("possession key mismatch: token cnf_kid {expected:?}, presented key {got:?}")]
    PossessionKeyMismatch {
        /// `cnf_kid` of the token.
        expected: String,
        /// SHA-256 SPKI of the presented key.
        got: String,
    },
    /// JSON (de)serialization of a wire form failed.
    #[error("wire json: {0}")]
    Json(String),
}

/// Convenience alias.
pub type Result<T, E = WorkloadError> = std::result::Result<T, E>;

// ---------------------------------------------------------------------------
// Scopes and actions
// ---------------------------------------------------------------------------

/// The verbs a [`Scope`] can carry. Deliberately a closed set — an unknown
/// action can never be spelled into a scope.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Read-only access to the target service.
    Read,
    /// Mutating access to the target service.
    Write,
    /// Administrative/control access to the target service.
    Admin,
}

impl Action {
    /// All actions, in ascending privilege order.
    pub const ALL: [Action; 3] = [Action::Read, Action::Write, Action::Admin];

    /// Stable textual encoding used in scope strings.
    pub const fn as_str(self) -> &'static str {
        match self {
            Action::Read => "read",
            Action::Write => "write",
            Action::Admin => "admin",
        }
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for Action {
    type Err = WorkloadError;
    fn from_str(s: &str) -> Result<Self> {
        match s {
            "read" => Ok(Action::Read),
            "write" => Ok(Action::Write),
            "admin" => Ok(Action::Admin),
            other => Err(WorkloadError::ScopeMalformed {
                scope: other.to_string(),
                reason: "unknown action (expected read|write|admin)".to_string(),
            }),
        }
    }
}

/// A canonical scope: `<target-service>:<action>`, e.g. `relay:write`.
///
/// The service segment is validated with the same canonical charset as SVID
/// service names ([`model::validate_service_name`]) and the reserved
/// `svid-issuer` name is refused, so a scope can never be used to smuggle a
/// lookalike target identity.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Scope {
    service: String,
    action: Action,
}

impl Scope {
    /// Validate and construct.
    pub fn new(service: &str, action: Action) -> Result<Self> {
        validate_service_name(service)?;
        Ok(Self {
            service: service.to_string(),
            action,
        })
    }

    /// Parse the canonical `<service>:<action>` form.
    pub fn parse(s: &str) -> Result<Self> {
        let mut parts = s.split(':');
        let (service, action, extra) = (parts.next(), parts.next(), parts.next());
        let (service, action) = match (service, action, extra) {
            (Some(service), Some(action), None) if !service.is_empty() && !action.is_empty() => {
                (service, action)
            }
            _ => {
                return Err(WorkloadError::ScopeMalformed {
                    scope: s.to_string(),
                    reason: "expected exactly <service>:<action>".to_string(),
                });
            }
        };
        let action: Action = action.parse().map_err(|e| match e {
            WorkloadError::ScopeMalformed { reason, .. } => WorkloadError::ScopeMalformed {
                scope: s.to_string(),
                reason,
            },
            other => other,
        })?;
        Self::new(service, action)
    }

    /// The target service segment.
    pub fn service(&self) -> &str {
        &self.service
    }

    /// The action.
    pub fn action(&self) -> Action {
        self.action
    }
}

impl fmt::Display for Scope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.service, self.action)
    }
}

impl std::str::FromStr for Scope {
    type Err = WorkloadError;
    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

impl Serialize for Scope {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Scope {
    fn deserialize<D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Scope::parse(&s).map_err(serde::de::Error::custom)
    }
}

/// A canonical, deduplicated scope set (sorted). Caps at
/// [`MAX_SCOPES_PER_ASSERTION`].
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeSet {
    inner: BTreeSet<Scope>,
}

impl ScopeSet {
    /// Empty set.
    pub fn empty() -> Self {
        Self {
            inner: BTreeSet::new(),
        }
    }

    /// Build from an iterator; refuses duplicates-collapsing silently only in
    /// the sense that the result is canonical — the cap failure is an error.
    pub fn from_scopes<I: IntoIterator<Item = Scope>>(scopes: I) -> Result<Self> {
        let mut set = Self::empty();
        for scope in scopes {
            set.insert(scope)?;
        }
        Ok(set)
    }

    /// Parse a whitespace-separated scope list (Maskinporten's space-delimited
    /// `scope` parameter). Empty input is an error, not an empty grant.
    pub fn parse_list(s: &str) -> Result<Self> {
        let mut set = Self::empty();
        for tok in s.split_whitespace() {
            set.insert(Scope::parse(tok)?)?;
        }
        if set.is_empty() {
            return Err(WorkloadError::EmptyScope);
        }
        Ok(set)
    }

    /// Insert one scope (idempotent); fails closed above the cap.
    pub fn insert(&mut self, scope: Scope) -> Result<()> {
        if !self.inner.contains(&scope) && self.inner.len() >= MAX_SCOPES_PER_ASSERTION {
            return Err(WorkloadError::TooManyScopes {
                count: self.inner.len() + 1,
                max: MAX_SCOPES_PER_ASSERTION,
            });
        }
        self.inner.insert(scope);
        Ok(())
    }

    /// True iff the set contains `scope`.
    pub fn contains(&self, scope: &Scope) -> bool {
        self.inner.contains(scope)
    }

    /// True iff every scope in `other` is present (i.e. `other ⊆ self`).
    pub fn contains_all(&self, other: &ScopeSet) -> bool {
        other.inner.iter().all(|s| self.inner.contains(s))
    }

    /// Number of scopes.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True iff empty.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Iterate in canonical (sorted) order.
    pub fn iter(&self) -> impl Iterator<Item = &Scope> {
        self.inner.iter()
    }

    /// Canonical string list (sorted) — the wire/storage representation.
    pub fn to_strings(&self) -> Vec<String> {
        self.inner.iter().map(|s| s.to_string()).collect()
    }

    /// Parse a stored string list, requiring canonical (sorted, deduplicated)
    /// form and a non-empty result.
    pub fn from_strings(strings: &[String]) -> Result<Self> {
        let parsed: Vec<Scope> = strings
            .iter()
            .map(|s| Scope::parse(s))
            .collect::<Result<_>>()?;
        let set = Self::from_scopes(parsed)?;
        if set.is_empty() {
            return Err(WorkloadError::EmptyScope);
        }
        if set.to_strings() != strings {
            return Err(WorkloadError::ScopeMalformed {
                scope: strings.join(" "),
                reason: "scope list is not in canonical (sorted, deduplicated) form".to_string(),
            });
        }
        Ok(set)
    }
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Validate a service/caller name for scope and grant purposes (same canonical
/// charset as SVID service names; reserved names refused).
fn validate_service_name(name: &str) -> Result<()> {
    model::validate_service_name(name).map_err(|e| WorkloadError::InvalidServiceName {
        name: name.to_string(),
        reason: e.to_string(),
    })?;
    if model::is_reserved_service_name(name) {
        return Err(WorkloadError::InvalidServiceName {
            name: name.to_string(),
            reason: "reserved for infrastructure (svid-issuer)".to_string(),
        });
    }
    Ok(())
}

/// Length-prefixed field append (`u32` big-endian length + bytes) — the
/// unambiguous canonical form used by this module's signatures.
fn push_field(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

/// SHA-256 hex helper.
fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// `SHA-256(SubjectPublicKeyInfo)` — the crate-wide key binding (identical to
/// [`crate::join::JoinToken::spki_binding`]).
fn spki_sha256(spki: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(spki);
    hasher.finalize().into()
}

/// A fresh, single-use `jti`: [`JTI_BYTES`] OS-random bytes, lowercase hex.
pub fn fresh_jti() -> String {
    use rand::RngCore;
    let mut b = [0u8; JTI_BYTES];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

/// True iff `s` is a well-formed `jti` ([`JTI_HEX_LEN`] lowercase hex chars).
pub fn is_valid_jti(s: &str) -> bool {
    s.len() == JTI_HEX_LEN
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

/// Build the DER `SubjectPublicKeyInfo` of a raw 32-byte Ed25519 public key.
pub fn spki_der_from_raw(raw: &[u8]) -> Result<Vec<u8>> {
    if raw.len() != 32 {
        return Err(WorkloadError::CertIdentity {
            reason: format!("Ed25519 public key must be 32 bytes, got {}", raw.len()),
        });
    }
    let mut out = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
    out.extend_from_slice(&ED25519_SPKI_PREFIX);
    out.extend_from_slice(raw);
    Ok(out)
}

/// The `kid` of a raw Ed25519 public key: `sha256(SPKI DER)` hex — the same
/// binding [`crate::join::JoinToken::spki_binding`] applies to join tokens.
pub fn kid_of_raw_key(raw: &[u8]) -> Result<String> {
    Ok(hex::encode(spki_sha256(&spki_der_from_raw(raw)?)))
}

fn decode_hex_exact<const N: usize>(hex_in: &str, what: &str) -> Result<[u8; N]> {
    let bytes =
        hex::decode(hex_in).map_err(|_| WorkloadError::Signature(format!("{what}: bad hex")))?;
    let arr: [u8; N] = bytes
        .try_into()
        .map_err(|_| WorkloadError::Signature(format!("{what}: expected {N} bytes")))?;
    Ok(arr)
}

// ---------------------------------------------------------------------------
// Workload key
// ---------------------------------------------------------------------------

/// A workload's Ed25519 key (the key that becomes the SVID leaf key and signs
/// its assertions). Secret material; no `Debug`/`Clone` on purpose.
pub struct WorkloadKey {
    signer: Ed25519Signer,
}

impl WorkloadKey {
    /// Fresh random key.
    pub fn generate() -> Self {
        Self {
            signer: Ed25519Signer::keygen(),
        }
    }

    /// Deterministic key from a 32-byte seed (tests, KATs).
    pub fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            signer: Ed25519Signer::from_seed(seed),
        }
    }

    /// Raw 32-byte public key.
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.signer.verifying_key_bytes()
    }

    /// DER `SubjectPublicKeyInfo` — the value to hand to
    /// `NodeIssuer::issue_workload_leaf_from_spki`.
    pub fn spki_der(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ED25519_SPKI_PREFIX.len() + 32);
        out.extend_from_slice(&ED25519_SPKI_PREFIX);
        out.extend_from_slice(&self.signer.verifying_key_bytes());
        out
    }

    /// `sha256(SPKI DER)` hex — the key's `kid`.
    pub fn kid(&self) -> String {
        hex::encode(spki_sha256(&self.spki_der()))
    }

    /// Sign bytes (assertions, possession challenges).
    pub fn sign(&self, message: &[u8]) -> [u8; SIGNATURE_LEN] {
        self.signer.sign(message)
    }
}

// ---------------------------------------------------------------------------
// Assertion
// ---------------------------------------------------------------------------

/// The signed workload assertion: the Maskinporten client-assertion analogue.
///
/// Carries no secrets; the I/O envelope ([`AssertionProof`]) adds the leaf
/// certificate DER and the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadAssertion {
    /// Wire version ([`ASSERTION_VERSION`]).
    pub v: u8,
    /// The workload identity (`spiffe://tallow/<node>/svc/<name>`) — the
    /// client id.
    pub iss: SpiffeId,
    /// The token authority this assertion is addressed to (its id string).
    pub aud: String,
    /// Issued-at (Unix seconds).
    pub iat: i64,
    /// Expiry (Unix seconds); `exp - iat` is inside the short-TTL band.
    pub exp: i64,
    /// Single-use identifier (32 lowercase hex chars).
    pub jti: String,
    /// Requested scopes, canonical (sorted, deduplicated) strings.
    pub scope: Vec<String>,
    /// `sha256(SPKI DER)` of the asserted key (ties to the certificate).
    pub kid: String,
    /// `sha256(leaf certificate DER)` committed inside the signature.
    pub cert_sha256: String,
}

impl WorkloadAssertion {
    /// Structural validation independent of any clock: version, audience
    /// length, `jti`/digest shapes, canonical non-empty scopes, TTL band.
    /// Returns the parsed [`ScopeSet`].
    pub fn validate(&self) -> Result<ScopeSet> {
        if self.v != ASSERTION_VERSION {
            return Err(WorkloadError::Version {
                what: "assertion",
                found: self.v,
                expected: ASSERTION_VERSION,
            });
        }
        if self.aud.is_empty() || self.aud.len() > MAX_AUD_LEN {
            return Err(WorkloadError::AudienceMismatch {
                expected: format!("1..={MAX_AUD_LEN} bytes"),
                got: self.aud.clone(),
            });
        }
        if !is_valid_jti(&self.jti) {
            return Err(WorkloadError::JtiMalformed {
                jti: self.jti.clone(),
                expected: JTI_HEX_LEN,
            });
        }
        check_hex_len(&self.kid, "kid")?;
        check_hex_len(&self.cert_sha256, "cert_sha256")?;
        let ttl = self.exp.saturating_sub(self.iat);
        if !(ASSERTION_TTL_MIN_SECS..=ASSERTION_MAX_TTL_SECS).contains(&ttl) || self.exp <= self.iat
        {
            return Err(WorkloadError::AssertionTtl {
                ttl_secs: ttl,
                min_secs: ASSERTION_TTL_MIN_SECS,
                max_secs: ASSERTION_MAX_TTL_SECS,
            });
        }
        ScopeSet::from_strings(&self.scope)
    }
}

fn check_hex_len(value: &str, what: &str) -> Result<()> {
    if value.len() != DIGEST_HEX_LEN
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(WorkloadError::Signature(format!(
            "{what}: expected {DIGEST_HEX_LEN} lowercase hex chars"
        )));
    }
    Ok(())
}

/// Canonical signed bytes of an assertion (see module docs). The scope list is
/// signed **in storage order**; [`WorkloadAssertion::validate`] is what forces
/// that order to be canonical, so the signature can never be ambiguous.
pub fn assertion_payload(a: &WorkloadAssertion) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(ASSERTION_DOMAIN);
    push_field(&mut out, &[a.v]);
    push_field(&mut out, a.iss.as_str().as_bytes());
    push_field(&mut out, a.aud.as_bytes());
    push_field(&mut out, &a.iat.to_be_bytes());
    push_field(&mut out, &a.exp.to_be_bytes());
    push_field(&mut out, a.jti.as_bytes());
    push_field(&mut out, &(a.scope.len() as u32).to_be_bytes());
    for s in &a.scope {
        push_field(&mut out, s.as_bytes());
    }
    push_field(&mut out, a.kid.as_bytes());
    push_field(&mut out, a.cert_sha256.as_bytes());
    out
}

/// The wire envelope for an assertion: assertion + leaf certificate DER +
/// Ed25519 signature by the workload key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionProof {
    /// The signed assertion.
    pub assertion: WorkloadAssertion,
    /// The workload leaf SVID certificate, DER, lowercase hex.
    pub cert_der_hex: String,
    /// Ed25519 signature over [`assertion_payload`], lowercase hex.
    pub signature: String,
}

impl AssertionProof {
    /// JSON encoding (transport only — signatures cover canonical bytes, not
    /// this JSON).
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| WorkloadError::Json(e.to_string()))
    }

    /// Parse the JSON encoding. Structural checks run on the next
    /// [`TokenAuthority::exchange`]; parsing itself performs no validation
    /// beyond serde.
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| WorkloadError::Json(e.to_string()))
    }

    /// The leaf certificate DER, decoding the hex.
    pub fn cert_der(&self) -> Result<Vec<u8>> {
        hex::decode(&self.cert_der_hex).map_err(|_| WorkloadError::CertIdentity {
            reason: "cert_der_hex is not valid hex".to_string(),
        })
    }
}

/// Mint a certificate-backed assertion.
///
/// * `key` — the workload key; it must be the SVID leaf's key.
/// * `chain` — the workload's issued `[intermediate, leaf]` SVID chain (the
///   leaf is what travels in the proof).
/// * `id` — the workload identity; must equal the leaf's URI SAN exactly.
/// * `audience` — the authority id the assertion is addressed to.
/// * `scopes` — requested scopes (canonical set, non-empty).
/// * `ttl_secs` — `None` yields [`ASSERTION_DEFAULT_TTL_SECS`]; outside
///   [`ASSERTION_TTL_MIN_SECS`]`..=`[`ASSERTION_MAX_TTL_SECS`] is refused.
/// * `now` — explicit issuance instant (Unix seconds).
pub fn mint_assertion(
    key: &WorkloadKey,
    chain: &crate::issuer::IssuedChain,
    id: &SpiffeId,
    audience: &str,
    scopes: &ScopeSet,
    ttl_secs: Option<i64>,
    now: i64,
) -> Result<AssertionProof> {
    let leaf_der = chain.leaf_der().as_ref();
    let info = der::parse_cert(leaf_der).map_err(|e| WorkloadError::CertIdentity {
        reason: format!("leaf certificate DER: {e}"),
    })?;
    if info.is_ca {
        return Err(WorkloadError::CertIdentity {
            reason: "workload leaf must not be a CA".to_string(),
        });
    }
    match_san_uri(&info.san_uris, id.as_str()).map_err(|e| WorkloadError::CertIdentity {
        reason: format!("leaf SAN does not equal the assertion subject: {e}"),
    })?;
    if info.spki_raw_key != key.public_key_bytes().as_slice() {
        return Err(WorkloadError::KeyCertMismatch);
    }
    if scopes.is_empty() {
        return Err(WorkloadError::EmptyScope);
    }

    let ttl = ttl_secs.unwrap_or(ASSERTION_DEFAULT_TTL_SECS);
    if !(ASSERTION_TTL_MIN_SECS..=ASSERTION_MAX_TTL_SECS).contains(&ttl) {
        return Err(WorkloadError::AssertionTtl {
            ttl_secs: ttl,
            min_secs: ASSERTION_TTL_MIN_SECS,
            max_secs: ASSERTION_MAX_TTL_SECS,
        });
    }

    let spki = spki_der_from_raw(info.spki_raw_key)?;
    let assertion = WorkloadAssertion {
        v: ASSERTION_VERSION,
        iss: id.clone(),
        aud: audience.to_string(),
        iat: now,
        exp: now.saturating_add(ttl),
        jti: fresh_jti(),
        scope: scopes.to_strings(),
        kid: hex::encode(spki_sha256(&spki)),
        cert_sha256: sha256_hex(leaf_der),
    };
    let signature = key.sign(&assertion_payload(&assertion));
    Ok(AssertionProof {
        assertion,
        cert_der_hex: hex::encode(leaf_der),
        signature: hex::encode(signature),
    })
}

// ---------------------------------------------------------------------------
// Scope grant policy
// ---------------------------------------------------------------------------

/// Which caller service may request which scopes. Empty by default: nothing
/// is granted until an operator grants it (fail closed).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopePolicy {
    grants: BTreeMap<String, BTreeSet<Scope>>,
}

impl ScopePolicy {
    /// No grants at all.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Grant `scope` to `caller` (caller validated as a service name; reserved
    /// names refused).
    pub fn grant(&mut self, caller: &str, scope: Scope) -> Result<()> {
        validate_service_name(caller)?;
        self.grants
            .entry(caller.to_string())
            .or_default()
            .insert(scope);
        Ok(())
    }

    /// Grant several scopes to one caller.
    pub fn grant_all<I: IntoIterator<Item = Scope>>(
        &mut self,
        caller: &str,
        scopes: I,
    ) -> Result<()> {
        for scope in scopes {
            self.grant(caller, scope)?;
        }
        Ok(())
    }

    /// True iff `caller` may request `scope`.
    pub fn granted(&self, caller: &str, scope: &Scope) -> bool {
        self.grants
            .get(caller)
            .map(|set| set.contains(scope))
            .unwrap_or(false)
    }

    /// The granted scopes of a caller, if any.
    pub fn caller_scopes(&self, caller: &str) -> Option<&BTreeSet<Scope>> {
        self.grants.get(caller)
    }

    /// Number of callers with grants.
    pub fn len(&self) -> usize {
        self.grants.len()
    }

    /// True iff no caller has grants.
    pub fn is_empty(&self) -> bool {
        self.grants.is_empty()
    }

    /// Fail closed when a grant names a caller that is not in the issuance
    /// allowlist: such a grant could never be honoured by a real SVID, so it
    /// is a configuration error, not dead weight.
    pub fn check_registry(&self, registry: &ServiceRegistry) -> Result<()> {
        for caller in self.grants.keys() {
            registry
                .require_registered(caller)
                .map_err(|e| WorkloadError::InvalidServiceName {
                    name: caller.clone(),
                    reason: e.to_string(),
                })?;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Replay store
// ---------------------------------------------------------------------------

/// Single-use `jti` tracking, keyed by `(issuer, jti)`.
///
/// Entries live until the credential's own `exp`; the store is bounded and
/// **fails closed** at its cap (refusing new assertions rather than evicting a
/// live entry and reopening a replay window).
#[derive(Debug, Clone, Default)]
pub struct ReplayStore {
    seen: BTreeMap<(String, String), i64>,
}

impl ReplayStore {
    /// Empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Drop entries whose `exp` is at or before `now`; returns how many were
    /// dropped.
    pub fn prune(&mut self, now: i64) -> usize {
        let before = self.seen.len();
        self.seen.retain(|_, exp| *exp > now);
        before - self.seen.len()
    }

    /// Record `jti` as used by `issuer`, refusing a replay.
    ///
    /// Refusals: malformed `jti` ([`WorkloadError::JtiMalformed`]), an
    /// already-seen `(issuer, jti)` whose `exp` has not passed
    /// ([`WorkloadError::Replay`]), or a full store
    /// ([`WorkloadError::ReplayStoreFull`]).
    pub fn check_and_record(&mut self, issuer: &str, jti: &str, exp: i64, now: i64) -> Result<()> {
        if !is_valid_jti(jti) {
            return Err(WorkloadError::JtiMalformed {
                jti: jti.to_string(),
                expected: JTI_HEX_LEN,
            });
        }
        self.prune(now);
        let key = (issuer.to_string(), jti.to_string());
        if self.seen.contains_key(&key) {
            return Err(WorkloadError::Replay {
                jti: jti.to_string(),
            });
        }
        if self.seen.len() >= MAX_REPLAY_ENTRIES {
            return Err(WorkloadError::ReplayStoreFull {
                max: MAX_REPLAY_ENTRIES,
            });
        }
        self.seen.insert(key, exp);
        Ok(())
    }

    /// True iff `(issuer, jti)` is currently recorded (and unexpired).
    pub fn contains(&self, issuer: &str, jti: &str) -> bool {
        self.seen
            .contains_key(&(issuer.to_string(), jti.to_string()))
    }

    /// Live entries.
    pub fn len(&self) -> usize {
        self.seen.len()
    }

    /// True iff empty.
    pub fn is_empty(&self) -> bool {
        self.seen.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Access token
// ---------------------------------------------------------------------------

/// The short-lived, scope-bound access token minted by [`TokenAuthority`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccessToken {
    /// Wire version ([`TOKEN_VERSION`]).
    pub v: u8,
    /// The issuing authority (its id string, a `SpiffeId`).
    pub iss: SpiffeId,
    /// The workload the token was minted for.
    pub sub: SpiffeId,
    /// Audience: the authority id this token is valid with.
    pub aud: String,
    /// Issued-at (Unix seconds).
    pub iat: i64,
    /// Expiry (Unix seconds).
    pub exp: i64,
    /// Unique token id.
    pub jti: String,
    /// `jti` of the assertion this token was minted from (provenance).
    pub parent_jti: String,
    /// Granted scopes, canonical strings.
    pub scope: Vec<String>,
    /// Key binding: `sha256(SPKI DER)` of the subject key (see
    /// [`verify_possession`]).
    pub cnf_kid: String,
    /// Ed25519 signature by the authority over [`token_payload`], hex.
    pub signature: String,
}

impl AccessToken {
    /// Remaining lifetime in seconds at `now` (may be ≤ 0 for an expired
    /// token; verification refuses independently).
    pub fn expires_in_secs(&self, now: i64) -> i64 {
        self.exp.saturating_sub(now)
    }

    /// Parsed granted scopes.
    pub fn scopes(&self) -> Result<ScopeSet> {
        ScopeSet::from_strings(&self.scope)
    }

    /// Structural validation independent of any clock.
    pub fn validate(&self) -> Result<ScopeSet> {
        if self.v != TOKEN_VERSION {
            return Err(WorkloadError::Version {
                what: "token",
                found: self.v,
                expected: TOKEN_VERSION,
            });
        }
        if self.aud.is_empty() || self.aud.len() > MAX_AUD_LEN {
            return Err(WorkloadError::WrongIssuer {
                expected: format!("1..={MAX_AUD_LEN} bytes"),
                got_iss: self.iss.to_string(),
                got_aud: self.aud.clone(),
            });
        }
        if !is_valid_jti(&self.jti) {
            return Err(WorkloadError::JtiMalformed {
                jti: self.jti.clone(),
                expected: JTI_HEX_LEN,
            });
        }
        if !is_valid_jti(&self.parent_jti) {
            return Err(WorkloadError::JtiMalformed {
                jti: self.parent_jti.clone(),
                expected: JTI_HEX_LEN,
            });
        }
        check_hex_len(&self.cnf_kid, "cnf_kid")?;
        let ttl = self.exp.saturating_sub(self.iat);
        if !(TOKEN_TTL_MIN_SECS..=TOKEN_MAX_TTL_SECS).contains(&ttl) || self.exp <= self.iat {
            return Err(WorkloadError::TokenTtl {
                ttl_secs: ttl,
                min_secs: TOKEN_TTL_MIN_SECS,
                max_secs: TOKEN_MAX_TTL_SECS,
            });
        }
        ScopeSet::from_strings(&self.scope)
    }

    /// JSON encoding (transport only).
    pub fn to_json(&self) -> Result<String> {
        serde_json::to_string(self).map_err(|e| WorkloadError::Json(e.to_string()))
    }

    /// Parse the JSON encoding (validation happens in
    /// [`TokenVerifier::verify`]).
    pub fn from_json(s: &str) -> Result<Self> {
        serde_json::from_str(s).map_err(|e| WorkloadError::Json(e.to_string()))
    }
}

/// Canonical signed bytes of a token (everything except `signature`).
pub fn token_payload(t: &AccessToken) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(TOKEN_DOMAIN);
    push_field(&mut out, &[t.v]);
    push_field(&mut out, t.iss.as_str().as_bytes());
    push_field(&mut out, t.sub.as_str().as_bytes());
    push_field(&mut out, t.aud.as_bytes());
    push_field(&mut out, &t.iat.to_be_bytes());
    push_field(&mut out, &t.exp.to_be_bytes());
    push_field(&mut out, t.jti.as_bytes());
    push_field(&mut out, t.parent_jti.as_bytes());
    push_field(&mut out, &(t.scope.len() as u32).to_be_bytes());
    for s in &t.scope {
        push_field(&mut out, s.as_bytes());
    }
    push_field(&mut out, t.cnf_kid.as_bytes());
    out
}

// ---------------------------------------------------------------------------
// Token authority (the token endpoint)
// ---------------------------------------------------------------------------

/// The authority that exchanges cert-backed assertions for short-lived
/// scope-bound tokens. Holds its own signing key, its identity, the scope
/// grant policy and the single-use `jti` store.
pub struct TokenAuthority {
    id: SpiffeId,
    key: Ed25519Signer,
    policy: ScopePolicy,
    replay: ReplayStore,
    token_ttl_secs: i64,
}

impl TokenAuthority {
    /// Construct with an explicit token TTL (`None` ⇒
    /// [`TOKEN_DEFAULT_TTL_SECS`]); TTLs outside the band are refused at
    /// construction so an authority can never mint an over-long token.
    pub fn new(
        id: SpiffeId,
        key: Ed25519Signer,
        policy: ScopePolicy,
        token_ttl_secs: Option<i64>,
    ) -> Result<Self> {
        let ttl = token_ttl_secs.unwrap_or(TOKEN_DEFAULT_TTL_SECS);
        if !(TOKEN_TTL_MIN_SECS..=TOKEN_MAX_TTL_SECS).contains(&ttl) {
            return Err(WorkloadError::TokenTtl {
                ttl_secs: ttl,
                min_secs: TOKEN_TTL_MIN_SECS,
                max_secs: TOKEN_MAX_TTL_SECS,
            });
        }
        Ok(Self {
            id,
            key,
            policy,
            replay: ReplayStore::new(),
            token_ttl_secs: ttl,
        })
    }

    /// The authority identity (`iss`/`aud` of every token; the string
    /// assertions must address).
    pub fn id(&self) -> &SpiffeId {
        &self.id
    }

    /// The id string assertions must carry in `aud`.
    pub fn endpoint_id(&self) -> &str {
        self.id.as_str()
    }

    /// The authority's Ed25519 verifying key (for [`TokenVerifier`]).
    pub fn verifying_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key_bytes()
    }

    /// A verifier trusting this authority.
    pub fn verifier(&self) -> TokenVerifier {
        TokenVerifier::new(self.id.clone(), self.verifying_key_bytes())
    }

    /// Configured token TTL in seconds.
    pub fn token_ttl_secs(&self) -> i64 {
        self.token_ttl_secs
    }

    /// Live entries in the replay store.
    pub fn replay_len(&self) -> usize {
        self.replay.len()
    }

    /// Exchange an assertion for an access token at the current wall clock.
    pub fn exchange_now(&mut self, proof: &AssertionProof) -> Result<AccessToken> {
        self.exchange(proof, now_unix())
    }

    /// Exchange an assertion for an access token at an explicit instant.
    ///
    /// Checks, in order: structural validity (version/TTL band/jti/scope
    /// canonicality), time window, audience, reserved subject, node pin, leaf
    /// certificate identity (SAN == `iss`, not a CA, valid at `now`), the
    /// signed certificate digest, the `kid`/key tie, the Ed25519 signature
    /// **with the certificate's key**, single-use `jti`, and finally the scope
    /// grant. Any failure returns a typed refusal — no token.
    pub fn exchange(&mut self, proof: &AssertionProof, now: i64) -> Result<AccessToken> {
        let a = &proof.assertion;
        let requested = a.validate()?;

        if a.iat > now {
            return Err(WorkloadError::AssertionNotYetValid { iat: a.iat, now });
        }
        if now >= a.exp {
            return Err(WorkloadError::AssertionExpired { exp: a.exp, now });
        }
        if a.aud != self.id.as_str() {
            return Err(WorkloadError::AudienceMismatch {
                expected: self.id.as_str().to_string(),
                got: a.aud.clone(),
            });
        }
        if a.iss.is_reserved_service() {
            return Err(WorkloadError::ReservedSubject);
        }
        policy::check_node_pin(self.id.node_id(), &a.iss)?;

        let cert_der = proof.cert_der()?;
        let info = der::parse_cert(&cert_der).map_err(|e| WorkloadError::CertIdentity {
            reason: format!("leaf certificate DER: {e}"),
        })?;
        if info.is_ca {
            return Err(WorkloadError::CertIdentity {
                reason: "workload leaf must not be a CA".to_string(),
            });
        }
        if !(info.not_before <= now && now < info.not_after) {
            return Err(WorkloadError::CertNotValid {
                not_before: info.not_before,
                not_after: info.not_after,
                now,
            });
        }
        match_san_uri(&info.san_uris, a.iss.as_str()).map_err(|e| WorkloadError::CertIdentity {
            reason: format!("leaf SAN does not equal the assertion subject: {e}"),
        })?;
        let cert_digest = sha256_hex(&cert_der);
        if cert_digest != a.cert_sha256 {
            return Err(WorkloadError::CertDigestMismatch {
                expected: a.cert_sha256.clone(),
                got: cert_digest,
            });
        }
        let spki = spki_der_from_raw(info.spki_raw_key)?;
        let kid = hex::encode(spki_sha256(&spki));
        if kid != a.kid {
            return Err(WorkloadError::KidMismatch {
                expected: kid,
                got: a.kid.clone(),
            });
        }
        let sig: [u8; SIGNATURE_LEN] = decode_hex_exact(&proof.signature, "signature")?;
        let cert_key: [u8; 32] =
            info.spki_raw_key
                .try_into()
                .map_err(|_| WorkloadError::CertIdentity {
                    reason: "certificate key is not 32 bytes".to_string(),
                })?;
        ed25519::verify(&cert_key, &assertion_payload(a), &sig)
            .map_err(|e| WorkloadError::Signature(e.to_string()))?;

        self.replay
            .check_and_record(a.iss.as_str(), &a.jti, a.exp, now)?;

        for scope in requested.iter() {
            if !self.policy.granted(a.iss.service(), scope) {
                return Err(WorkloadError::ScopeNotGranted {
                    scope: scope.to_string(),
                });
            }
        }

        let token = AccessToken {
            v: TOKEN_VERSION,
            iss: self.id.clone(),
            sub: a.iss.clone(),
            aud: self.id.as_str().to_string(),
            iat: now,
            exp: now.saturating_add(self.token_ttl_secs),
            jti: fresh_jti(),
            parent_jti: a.jti.clone(),
            scope: requested.to_strings(),
            cnf_kid: a.kid.clone(),
            signature: String::new(),
        };
        let mut token = token;
        token.signature = hex::encode(self.key.sign(&token_payload(&token)));
        Ok(token)
    }
}

// ---------------------------------------------------------------------------
// Token verifier (the resource side)
// ---------------------------------------------------------------------------

/// A resource server's view of the trusted authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenVerifier {
    id: SpiffeId,
    key: [u8; 32],
}

/// A token that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedToken {
    /// The workload the token was minted for.
    pub sub: SpiffeId,
    /// Granted scopes.
    pub scopes: ScopeSet,
    /// Issued-at (Unix seconds).
    pub iat: i64,
    /// Expiry (Unix seconds).
    pub exp: i64,
    /// The assertion `jti` that produced this token.
    pub parent_jti: String,
    /// Key binding of the subject key.
    pub cnf_kid: String,
}

impl TokenVerifier {
    /// Trust `id` (the authority) with its Ed25519 key.
    pub fn new(id: SpiffeId, key: [u8; 32]) -> Self {
        Self { id, key }
    }

    /// The trusted authority id.
    pub fn id(&self) -> &SpiffeId {
        &self.id
    }

    /// Verify a token at `now`, requiring **every** scope in `required`.
    ///
    /// Refusals: version/TTL band/canonical scopes, `iss`/`aud` not this
    /// authority ([`WorkloadError::WrongIssuer`]), `iat` in the future
    /// ([`WorkloadError::TokenNotYetValid`]), expired
    /// ([`WorkloadError::TokenExpired`]), any required scope absent
    /// ([`WorkloadError::ScopeMissing`]), bad signature
    /// ([`WorkloadError::Signature`]).
    pub fn verify(
        &self,
        token: &AccessToken,
        required: &ScopeSet,
        now: i64,
    ) -> Result<VerifiedToken> {
        let granted = token.validate()?;
        if token.iss != self.id || token.aud != self.id.as_str() {
            return Err(WorkloadError::WrongIssuer {
                expected: self.id.as_str().to_string(),
                got_iss: token.iss.to_string(),
                got_aud: token.aud.clone(),
            });
        }
        if token.iat > now {
            return Err(WorkloadError::TokenNotYetValid {
                iat: token.iat,
                now,
            });
        }
        if now >= token.exp {
            return Err(WorkloadError::TokenExpired {
                exp: token.exp,
                now,
            });
        }
        let sig: [u8; SIGNATURE_LEN] = decode_hex_exact(&token.signature, "signature")?;
        ed25519::verify(&self.key, &token_payload(token), &sig)
            .map_err(|e| WorkloadError::Signature(e.to_string()))?;
        for scope in required.iter() {
            if !granted.contains(scope) {
                return Err(WorkloadError::ScopeMissing {
                    required: scope.to_string(),
                });
            }
        }
        Ok(VerifiedToken {
            sub: token.sub.clone(),
            scopes: granted,
            iat: token.iat,
            exp: token.exp,
            parent_jti: token.parent_jti.clone(),
            cnf_kid: token.cnf_kid.clone(),
        })
    }
}

/// Proof-of-possession check: the presenter of `token` must hold the subject
/// key the token is bound to (`cnf_kid`), demonstrated by an Ed25519 signature
/// over `challenge` with that key.
pub fn verify_possession(
    token: &AccessToken,
    subject_key: &[u8; 32],
    challenge: &[u8],
    signature: &[u8; SIGNATURE_LEN],
) -> Result<()> {
    let kid = hex::encode(spki_sha256(&spki_der_from_raw(subject_key)?));
    if kid != token.cnf_kid {
        return Err(WorkloadError::PossessionKeyMismatch {
            expected: token.cnf_kid.clone(),
            got: kid,
        });
    }
    ed25519::verify(subject_key, challenge, signature)
        .map_err(|e| WorkloadError::Signature(e.to_string()))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::issuer::IssuedChain;
    use crate::issuer::NodeIssuer;

    /// Fixture instant: the real clock, so the freshly-issued fixture leaf's
    /// validity window contains every test evaluation instant.
    fn t0() -> i64 {
        now_unix()
    }

    fn id(node: &str, svc: &str) -> SpiffeId {
        SpiffeId::new(node, svc).expect("test id")
    }

    fn scope(service: &str, action: Action) -> Scope {
        Scope::new(service, action).expect("test scope")
    }

    /// A real SVID leaf for a fresh workload key, from the crate's NodeIssuer.
    fn fixture(service: &str) -> (WorkloadKey, IssuedChain, SpiffeId) {
        let key = WorkloadKey::generate();
        let mut issuer = NodeIssuer::generate("node-01").expect("issuer");
        issuer
            .issue_issuer_intermediate(None)
            .expect("intermediate");
        let id = id("node-01", service);
        let chain = issuer
            .issue_workload_leaf_from_spki(&key.spki_der(), &id, None)
            .expect("leaf");
        (key, chain, id)
    }

    /// Authority on node-01 with daemon granted relay:write + vault:read.
    fn authority() -> TokenAuthority {
        let issuer_id = SpiffeId::parse(&model::issuer_san("node-01").unwrap()).unwrap();
        let mut policy = ScopePolicy::empty();
        policy
            .grant_all(
                "daemon",
                [scope("relay", Action::Write), scope("vault", Action::Read)],
            )
            .unwrap();
        TokenAuthority::new(issuer_id, Ed25519Signer::from_seed([7u8; 32]), policy, None).unwrap()
    }

    fn daemon_scopes() -> ScopeSet {
        ScopeSet::from_scopes([scope("relay", Action::Write)]).unwrap()
    }

    #[test]
    fn maskinporten_round_trip_end_to_end() {
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let t = t0();
        let proof = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t,
        )
        .expect("mint");

        assert_eq!(
            proof.assertion.exp - proof.assertion.iat,
            ASSERTION_DEFAULT_TTL_SECS
        );
        let token = authority.exchange(&proof, t + 1).expect("exchange");
        assert_eq!(token.sub, wid);
        assert_eq!(token.iss, *authority.id());
        assert_eq!(token.scope, vec!["relay:write".to_string()]);
        assert_eq!(token.expires_in_secs(t + 1), TOKEN_DEFAULT_TTL_SECS);
        assert_eq!(token.parent_jti, proof.assertion.jti);
        assert_eq!(token.cnf_kid, key.kid());

        // Verifier side (also via the JSON wire form).
        let verifier = authority.verifier();
        let wire = token.to_json().expect("json");
        let parsed = AccessToken::from_json(&wire).expect("parse");
        let verified = verifier
            .verify(&parsed, &daemon_scopes(), t + 2)
            .expect("verify");
        assert_eq!(verified.sub, wid);
        assert_eq!(verified.exp, token.exp);

        // Proof of possession ties the token to the workload key.
        let challenge = b"nonce-1";
        let sig = key.sign(challenge);
        verify_possession(&parsed, &key.public_key_bytes(), challenge, &sig).expect("possession");
    }

    #[test]
    fn expired_assertion_refused() {
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let proof = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            Some(60),
            t0(),
        )
        .unwrap();
        let err = authority.exchange(&proof, t0() + 60).expect_err("expired");
        assert!(
            matches!(err, WorkloadError::AssertionExpired { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn not_yet_valid_assertion_refused() {
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let proof = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t0() + 10,
        )
        .unwrap();
        let err = authority.exchange(&proof, t0()).expect_err("future iat");
        assert!(
            matches!(err, WorkloadError::AssertionNotYetValid { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn assertion_ttl_band_enforced() {
        let (key, chain, wid) = fixture("daemon");
        let authority = authority();
        for ttl in [0, -5, ASSERTION_MAX_TTL_SECS + 1] {
            let err = mint_assertion(
                &key,
                &chain,
                &wid,
                authority.endpoint_id(),
                &daemon_scopes(),
                Some(ttl),
                t0(),
            )
            .expect_err("ttl band");
            assert!(matches!(err, WorkloadError::AssertionTtl { .. }), "{err:?}");
        }
        mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            Some(ASSERTION_MAX_TTL_SECS),
            t0(),
        )
        .expect("the 120 s cap itself is allowed");
    }

    #[test]
    fn replayed_assertion_refused() {
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let proof = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t0(),
        )
        .unwrap();
        authority.exchange(&proof, t0()).expect("first use");
        let err = authority.exchange(&proof, t0() + 1).expect_err("replay");
        assert!(matches!(err, WorkloadError::Replay { .. }), "{err:?}");
        assert_eq!(authority.replay_len(), 1);
        // A fresh jti for the same identity is fine.
        let proof2 = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t0() + 2,
        )
        .unwrap();
        authority.exchange(&proof2, t0() + 2).expect("fresh jti");
    }

    #[test]
    fn ungranted_scope_refused_without_partial_grant() {
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let both = ScopeSet::from_scopes([
            scope("relay", Action::Write),
            scope("vault", Action::Write), // not granted
        ])
        .unwrap();
        let proof = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &both,
            None,
            t0(),
        )
        .unwrap();
        let err = authority.exchange(&proof, t0()).expect_err("ungranted");
        assert!(
            matches!(err, WorkloadError::ScopeNotGranted { ref scope } if scope == "vault:write"),
            "{err:?}"
        );
    }

    #[test]
    fn wrong_audience_refused() {
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let proof = mint_assertion(
            &key,
            &chain,
            &wid,
            "spiffe://tallow/node-09/svc/svid-issuer",
            &daemon_scopes(),
            None,
            t0(),
        )
        .unwrap();
        let err = authority.exchange(&proof, t0()).expect_err("aud");
        assert!(
            matches!(err, WorkloadError::AudienceMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn verify_scope_mismatch_refused() {
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let proof = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t0(),
        )
        .unwrap();
        let token = authority.exchange(&proof, t0()).unwrap();
        let required = ScopeSet::from_scopes([scope("relay", Action::Admin)]).unwrap();
        let err = authority
            .verifier()
            .verify(&token, &required, t0())
            .expect_err("missing");
        assert!(
            matches!(err, WorkloadError::ScopeMissing { ref required } if required == "relay:admin"),
            "{err:?}"
        );
    }

    #[test]
    fn wrong_issuer_refused() {
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let proof = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t0(),
        )
        .unwrap();
        let token = authority.exchange(&proof, t0()).unwrap();

        let other = SpiffeId::parse(&model::issuer_san("node-02").unwrap()).unwrap();
        let other_verifier = TokenVerifier::new(other, authority.verifying_key_bytes());
        let err = other_verifier
            .verify(&token, &daemon_scopes(), t0())
            .expect_err("wrong issuer");
        assert!(matches!(err, WorkloadError::WrongIssuer { .. }), "{err:?}");

        let wrong_key_verifier = TokenVerifier::new(authority.id().clone(), [9u8; 32]);
        let err = wrong_key_verifier
            .verify(&token, &daemon_scopes(), t0())
            .expect_err("wrong key");
        assert!(matches!(err, WorkloadError::Signature(_)), "{err:?}");
    }

    #[test]
    fn token_tamper_refused() {
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let proof = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t0(),
        )
        .unwrap();
        let token = authority.exchange(&proof, t0()).unwrap();

        let mut wider = token.clone();
        wider.scope = vec!["relay:admin".to_string()];
        let err = authority
            .verifier()
            .verify(&wider, &ScopeSet::empty(), t0())
            .expect_err("tamper");
        assert!(matches!(err, WorkloadError::Signature(_)), "{err:?}");

        let mut longer = token.clone();
        longer.exp += TOKEN_MAX_TTL_SECS; // beyond the band *and* unsigned
        assert!(longer.validate().is_err(), "band check fires");
        let err = authority
            .verifier()
            .verify(&longer, &ScopeSet::empty(), t0())
            .expect_err("tamper");
        assert!(matches!(err, WorkloadError::TokenTtl { .. }), "{err:?}");
    }

    #[test]
    fn assertion_tamper_refused() {
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let mut proof = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t0(),
        )
        .unwrap();
        proof.assertion.scope = vec!["vault:write".to_string()]; // unsigned edit
        let err = authority.exchange(&proof, t0()).expect_err("tamper");
        assert!(matches!(err, WorkloadError::Signature(_)), "{err:?}");
    }

    #[test]
    fn key_cert_mismatch_refused_at_mint() {
        let (_key, chain, wid) = fixture("daemon");
        let other = WorkloadKey::generate();
        let err = mint_assertion(
            &other,
            &chain,
            &wid,
            "spiffe://tallow/node-01/svc/svid-issuer",
            &daemon_scopes(),
            None,
            t0(),
        )
        .expect_err("key/cert mismatch");
        assert!(matches!(err, WorkloadError::KeyCertMismatch), "{err:?}");
    }

    #[test]
    fn leaf_identity_mismatch_refused_at_mint() {
        let (key, chain, _wid) = fixture("daemon");
        let err = mint_assertion(
            &key,
            &chain,
            &id("node-01", "vault"),
            "spiffe://tallow/node-01/svc/svid-issuer",
            &daemon_scopes(),
            None,
            t0(),
        )
        .expect_err("SAN mismatch");
        assert!(matches!(err, WorkloadError::CertIdentity { .. }), "{err:?}");
    }

    #[test]
    fn kid_mismatch_refused_even_with_valid_signature() {
        // The key really holds the certificate, but the `kid` field names
        // another key and the (attacker-valid) signature covers that payload:
        // the cert/kid tie must still refuse.
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let mut proof = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t0(),
        )
        .unwrap();
        proof.assertion.kid = WorkloadKey::generate().kid();
        proof.signature = hex::encode(key.sign(&assertion_payload(&proof.assertion)));
        let err = authority.exchange(&proof, t0()).expect_err("kid mismatch");
        assert!(matches!(err, WorkloadError::KidMismatch { .. }), "{err:?}");
    }

    #[test]
    fn cert_digest_mismatch_refused() {
        // A second, valid leaf for the *same* key and identity (different
        // serial) swapped into the unsigned envelope must be refused by the
        // signed cert digest — the signature is untouched and still valid.
        let key = WorkloadKey::generate();
        let mut issuer = NodeIssuer::generate("node-01").unwrap();
        issuer.issue_issuer_intermediate(None).unwrap();
        let wid = id("node-01", "daemon");
        let chain_a = issuer
            .issue_workload_leaf_from_spki(&key.spki_der(), &wid, None)
            .unwrap();
        let chain_b = issuer
            .issue_workload_leaf_from_spki(&key.spki_der(), &wid, None)
            .unwrap();
        let mut authority = authority();
        let mut proof = mint_assertion(
            &key,
            &chain_a,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t0(),
        )
        .unwrap();
        proof.cert_der_hex = hex::encode(chain_b.leaf_der().as_ref());
        assert_ne!(
            sha256_hex(chain_b.leaf_der().as_ref()),
            proof.assertion.cert_sha256
        );
        let err = authority.exchange(&proof, t0()).expect_err("cert swap");
        assert!(
            matches!(err, WorkloadError::CertDigestMismatch { .. }),
            "{err:?}"
        );
    }

    #[test]
    fn expired_certificate_refused() {
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let late = t0() + 7 * 3600; // leaf band is 1–24 h; issue instant is now
        let proof = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            late,
        )
        .unwrap();
        let err = authority
            .exchange(&proof, late + 1)
            .expect_err("cert window");
        assert!(matches!(err, WorkloadError::CertNotValid { .. }), "{err:?}");
    }

    #[test]
    fn wrong_node_subject_refused() {
        // Leaf for node-01 presented to an authority whose node pin is node-01
        // is fine; a proof whose subject lies about the node fails parse-time
        // (SpiffeId is strict) or fails the pin. Build the cross-node case
        // with a manually crafted assertion signed by the right key.
        let (key, chain, _wid) = fixture("daemon");
        let mut authority = authority();
        let mut proof = mint_assertion(
            &key,
            &chain,
            &id("node-01", "daemon"),
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t0(),
        )
        .unwrap();
        // Re-sign with a valid signature but a subject that cannot pass the
        // node pin *and* matches no presented SAN: use a SAN of another node.
        let foreign = id("node-02", "daemon");
        proof.assertion.iss = foreign;
        proof.signature = hex::encode(key.sign(&assertion_payload(&proof.assertion)));
        let err = authority.exchange(&proof, t0()).expect_err("node pin");
        assert!(matches!(err, WorkloadError::NodePin(_)), "{err:?}");
    }

    #[test]
    fn reserved_subject_refused() {
        let (key, chain, _wid) = fixture("daemon");
        let mut authority = authority();
        let mut proof = mint_assertion(
            &key,
            &chain,
            &id("node-01", "daemon"),
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t0(),
        )
        .unwrap();
        let reserved = SpiffeId::parse(&model::issuer_san("node-01").unwrap()).unwrap();
        proof.assertion.iss = reserved;
        proof.signature = hex::encode(key.sign(&assertion_payload(&proof.assertion)));
        let err = authority
            .exchange(&proof, t0())
            .expect_err("reserved subject");
        assert!(matches!(err, WorkloadError::ReservedSubject), "{err:?}");
    }

    #[test]
    fn scope_parsing_and_canonicality() {
        assert_eq!(scope("relay", Action::Write).to_string(), "relay:write");
        assert_eq!(
            Scope::parse("relay:write").unwrap(),
            scope("relay", Action::Write)
        );
        assert_eq!(Scope::parse("relay:write").unwrap().action(), Action::Write);
        for bad in [
            "relay",
            "relay:",
            ":write",
            "relay:send",
            "relay:write:x",
            "Re lay:read",
        ] {
            assert!(Scope::parse(bad).is_err(), "must reject {bad:?}");
        }
        // Reserved service names cannot appear as scope targets.
        assert!(Scope::new("svid-issuer", Action::Read).is_err());
        assert!(Scope::new("RELAY", Action::Read).is_err());

        // Sets are canonical: sorted, deduplicated, and caps are enforced.
        let set = ScopeSet::parse_list("vault:read relay:write relay:write").unwrap();
        assert_eq!(set.to_strings(), vec!["relay:write", "vault:read"]);
        assert!(set.contains(&scope("vault", Action::Read)));
        assert!(ScopeSet::parse_list("  ").is_err());
        // Non-canonical stored lists are refused, not normalized.
        assert!(ScopeSet::from_strings(&["vault:read".into(), "relay:write".into()]).is_err());
        assert!(ScopeSet::from_strings(&["relay:write".into(), "relay:write".into()]).is_err());
    }

    #[test]
    fn replay_store_shapes() {
        let mut store = ReplayStore::new();
        let jti = fresh_jti();
        assert!(is_valid_jti(&jti));
        store
            .check_and_record("iss", &jti, t0() + 100, t0())
            .expect("first");
        assert!(store.contains("iss", &jti));
        assert!(matches!(
            store.check_and_record("iss", &jti, t0() + 100, t0() + 1),
            Err(WorkloadError::Replay { .. })
        ));
        // Different issuer, same jti: distinct key, allowed.
        store
            .check_and_record("other", &jti, t0() + 100, t0() + 1)
            .expect("other issuer");
        // Expiry prunes.
        assert_eq!(store.prune(t0() + 101), 2);
        assert!(store.is_empty());
        // Malformed jti refused.
        assert!(matches!(
            store.check_and_record("iss", "not-hex", t0() + 100, t0()),
            Err(WorkloadError::JtiMalformed { .. })
        ));
    }

    #[test]
    fn authority_ttl_and_policy_guards() {
        let issuer_id = SpiffeId::parse(&model::issuer_san("node-01").unwrap()).unwrap();
        let key = Ed25519Signer::from_seed([1u8; 32]);
        for ttl in [0, -1, TOKEN_MAX_TTL_SECS + 1] {
            assert!(matches!(
                TokenAuthority::new(
                    issuer_id.clone(),
                    Ed25519Signer::from_seed([1u8; 32]),
                    ScopePolicy::empty(),
                    Some(ttl)
                ),
                Err(WorkloadError::TokenTtl { .. })
            ));
        }
        let mut policy = ScopePolicy::empty();
        assert!(policy.is_empty());
        assert!(!policy.granted("daemon", &scope("relay", Action::Read)));
        policy
            .grant("daemon", scope("relay", Action::Read))
            .unwrap();
        policy
            .grant("daemon", scope("relay", Action::Read))
            .unwrap(); // idempotent
        assert_eq!(policy.caller_scopes("daemon").unwrap().len(), 1);
        // Reserved caller and malformed caller refused.
        assert!(policy
            .grant("svid-issuer", scope("relay", Action::Read))
            .is_err());
        assert!(policy
            .grant("DAEMON", scope("relay", Action::Read))
            .is_err());

        // check_registry ties grants to the issuance allowlist.
        let mut registry = ServiceRegistry::builtin();
        policy
            .check_registry(&registry)
            .expect("daemon is registered");
        registry.unregister("daemon");
        assert!(policy.check_registry(&registry).is_err());

        // Buildable with default TTL.
        let auth = TokenAuthority::new(issuer_id, key, policy, None).unwrap();
        assert_eq!(auth.token_ttl_secs(), TOKEN_DEFAULT_TTL_SECS);
    }

    #[test]
    fn possession_proof_shapes() {
        let (key, chain, wid) = fixture("daemon");
        let mut authority = authority();
        let proof = mint_assertion(
            &key,
            &chain,
            &wid,
            authority.endpoint_id(),
            &daemon_scopes(),
            None,
            t0(),
        )
        .unwrap();
        let token = authority.exchange(&proof, t0()).unwrap();

        let challenge = b"challenge-bytes";
        let good = key.sign(challenge);
        verify_possession(&token, &key.public_key_bytes(), challenge, &good).expect("holder");
        // Wrong challenge, wrong key, wrong key binding: all refused.
        assert!(verify_possession(&token, &key.public_key_bytes(), b"other", &good).is_err());
        let other = WorkloadKey::generate();
        let other_sig = other.sign(challenge);
        assert!(matches!(
            verify_possession(&token, &other.public_key_bytes(), challenge, &other_sig),
            Err(WorkloadError::PossessionKeyMismatch { .. })
        ));
    }
}
