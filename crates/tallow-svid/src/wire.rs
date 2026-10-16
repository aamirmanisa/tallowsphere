//! `wire` — W3 SVID metadata exchange types (owner: U-211).
//!
//! Serializable shapes for the SVID metadata that travels between the daemon
//! issuer, the Workload API (UDS), the CLI client half and the KT/ledger:
//! the SVID id, the SPKI SHA-256 of the certified key, the issued serial, the
//! validity window, and the **v1 hybrid co-signature binding** (parent
//! decision D2: the X.509 cert is Ed25519-signed by rcgen, while
//! Ed25519+ML-DSA-87 co-signature binds `(SPKI, spiffe-id, serial,
//! not_before/after)` at the enrollment/KT layer — rcgen cannot ML-DSA-sign).
//!
//! Everything is versioned behind [`Envelope`] with a mandatory `v` field and
//! a **fail-closed** version gate: unknown versions are refused, and structs
//! deny unknown fields, so a v1 parser can never silently accept a future or
//! smuggled shape.
//!
//! The canonical signing transcript is [`binding_payload`]: a domain-separated,
//! length-prefixed byte string so the hybrid co-signature can never be
//! replayed against a different field parse.

use serde::{Deserialize, Serialize};

use crate::model::{self, IssuedSerial, SpiffeId, SpiffeIdError, SvidKind, SERIAL_HEX_LEN};

/// Wire protocol version this build speaks. The envelope `v` field must equal
/// this exactly; there are no "compatible" guesses.
pub const WIRE_VERSION: u8 = 1;

/// Version tag inside [`KtBindingV1`].
pub const KT_BINDING_VERSION: u8 = 1;

/// Domain-separation tag prefixed to every KT binding transcript.
pub const KT_BINDING_DOMAIN: &[u8] = b"tallow-svid-kt-binding-v1";

/// Algorithm label for the v1 hybrid co-signature (matches
/// `tallow_crypto::sig::hybrid`: Ed25519 + ML-DSA-87).
pub const KT_BINDING_ALG: &str = "ed25519+ml-dsa-87";

/// SHA-256 digest length in bytes.
pub const SPKI_SHA256_BYTES: usize = 32;
/// Hex width of [`SPKI_SHA256_BYTES`].
pub const SPKI_SHA256_HEX_LEN: usize = SPKI_SHA256_BYTES * 2;

/// Ed25519 signature length in bytes.
pub const ED25519_SIG_BYTES: usize = 64;
/// ML-DSA-87 signature length in bytes (fixed-size in `tallow-crypto`'s
/// verifier: `let sig_bytes: [u8; 4627] = signature…`).
pub const MLDSA87_SIG_BYTES: usize = 4627;

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Wire decoding/validation failures. All are fail-closed.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// Envelope `v` is not [`WIRE_VERSION`].
    #[error("unsupported wire version {0} (this build speaks v{WIRE_VERSION})")]
    UnsupportedVersion(u32),
    /// JSON malformed / missing field / unknown field.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    /// The `svid` field is not a valid id of its declared shape.
    #[error("invalid svid: {0}")]
    Svid(#[from] SpiffeIdError),
    /// The `svid` string parses, but not as the declared [`SvidKind`].
    #[error("svid shape does not match declared kind {kind}")]
    KindShape {
        /// Declared kind.
        kind: SvidKind,
    },
    /// A workload SVID used the reserved `svid-issuer` service name.
    #[error("workload svid must not use the reserved service name")]
    ReservedService,
    /// Serial is not 32 lowercase hex characters.
    #[error("serial must be {SERIAL_HEX_LEN} lowercase hex characters")]
    BadSerial,
    /// SPKI SHA-256 is not 64 lowercase hex characters.
    #[error("spki_sha256 must be {SPKI_SHA256_HEX_LEN} lowercase hex characters")]
    BadSpki,
    /// `not_before >= not_after`.
    #[error("validity window invalid: not_before must be < not_after")]
    BadTimes,
    /// The KT binding failed its own checks (version, algorithm, sig sizes).
    #[error("kt binding invalid: {0}")]
    BadKt(String),
    /// A DER hex field is not valid, non-empty hex.
    #[error("der hex field {field} invalid")]
    BadDerHex {
        /// Which field failed.
        field: &'static str,
    },
}

// ---------------------------------------------------------------------------
// KT binding (hybrid co-signature, D2)
// ---------------------------------------------------------------------------

/// v1 hybrid co-signature binding over the SVID's identity-critical fields
/// (D2). Recorded with the issuance in the KT/ledger; the certificate itself
/// stays Ed25519-only because rcgen cannot ML-DSA-sign.
///
/// The signed message is exactly [`binding_payload`] of the sibling
/// [`SvidMetaV1`] fields; production signs it with
/// `tallow_crypto::sig::HybridSigner::sign`, which must be verified with both
/// halves (unconditional, no short-circuit).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KtBindingV1 {
    /// Binding format version — must be [`KT_BINDING_VERSION`].
    pub v: u8,
    /// Algorithm label — must be [`KT_BINDING_ALG`].
    pub alg: String,
    /// Ed25519 half, lowercase hex (64 bytes → 128 chars).
    pub ed25519: String,
    /// ML-DSA-87 half, lowercase hex (4627 bytes → 9254 chars).
    pub mldsa: String,
    /// Unix seconds at which the co-signature was produced.
    pub signed_at: i64,
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes()
        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn decode_hex_exact(s: &str, want_bytes: usize) -> Option<Vec<u8>> {
    if s.len() != want_bytes * 2 || !is_lower_hex(s) {
        return None;
    }
    hex::decode(s).ok()
}

impl KtBindingV1 {
    /// Validate version, algorithm label and both signature widths.
    pub fn validate(&self) -> Result<(), WireError> {
        if self.v != KT_BINDING_VERSION {
            return Err(WireError::BadKt(format!(
                "unsupported binding version {}",
                self.v
            )));
        }
        if self.alg != KT_BINDING_ALG {
            return Err(WireError::BadKt(format!(
                "algorithm {0:?} is not {KT_BINDING_ALG:?}",
                self.alg
            )));
        }
        if decode_hex_exact(&self.ed25519, ED25519_SIG_BYTES).is_none() {
            return Err(WireError::BadKt(
                "ed25519 half must be 64 bytes of lowercase hex".into(),
            ));
        }
        if decode_hex_exact(&self.mldsa, MLDSA87_SIG_BYTES).is_none() {
            return Err(WireError::BadKt(
                "mldsa half must be 4627 bytes of lowercase hex (ML-DSA-87)".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SVID metadata
// ---------------------------------------------------------------------------

/// Metadata for one issued SVID (the exchange unit over the Workload API and
/// into the KT/ledger).
///
/// `kind` selects the expected shape of `svid`:
/// - [`SvidKind::WorkloadLeaf`] → `spiffe://tallow/<node>/svc/<name>` (and the
///   service name may not be the reserved issuer name),
/// - [`SvidKind::NodeIdentity`] → `spiffe://tallow/<node>`,
/// - [`SvidKind::IssuerIntermediate`] → `spiffe://tallow/<node>/svc/svid-issuer`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SvidMetaV1 {
    /// Credential kind.
    pub kind: SvidKind,
    /// Canonical SVID URI / SAN value.
    pub svid: String,
    /// Issued serial, 32 lowercase hex chars ([`IssuedSerial::to_hex`]).
    pub serial: String,
    /// SHA-256 of the certified SubjectPublicKeyInfo, 64 lowercase hex chars.
    pub spki_sha256: String,
    /// Validity start, unix seconds.
    pub not_before: i64,
    /// Validity end, unix seconds.
    pub not_after: i64,
    /// Hybrid co-signature binding (D2).
    pub kt: KtBindingV1,
}

impl SvidMetaV1 {
    /// Validate every field, fail-closed. `kind`↔`svid` shape must agree.
    pub fn validate(&self) -> Result<(), WireError> {
        IssuedSerial::from_hex(&self.serial).map_err(|_| WireError::BadSerial)?;
        if decode_hex_exact(&self.spki_sha256, SPKI_SHA256_BYTES).is_none() {
            return Err(WireError::BadSpki);
        }
        if self.not_before >= self.not_after {
            return Err(WireError::BadTimes);
        }
        match self.kind {
            SvidKind::WorkloadLeaf => {
                let id = SpiffeId::parse(&self.svid)?;
                if id.is_reserved_service() {
                    return Err(WireError::ReservedService);
                }
            }
            SvidKind::NodeIdentity => {
                if model::parse_node_identity_san(&self.svid).is_err() {
                    return Err(WireError::KindShape { kind: self.kind });
                }
            }
            SvidKind::IssuerIntermediate => {
                if model::parse_issuer_san(&self.svid).is_err() {
                    return Err(WireError::KindShape { kind: self.kind });
                }
            }
        }
        self.kt.validate()?;
        Ok(())
    }

    /// The canonical bytes the hybrid co-signature covers (see
    /// [`binding_payload`]).
    pub fn binding_payload(&self) -> Vec<u8> {
        binding_payload(&KtBindingTranscript {
            kind: self.kind,
            svid: &self.svid,
            serial: &self.serial,
            spki_sha256: &self.spki_sha256,
            not_before: self.not_before,
            not_after: self.not_after,
        })
    }

    /// Fail-closed check that the node segment equals a pinned node id
    /// (ATK-2.10/2.12): an SVID minted for another node never matches.
    pub fn matches_node(&self, node_id: &str) -> Result<(), model::SpiffeIdError> {
        let observed = match self.kind {
            SvidKind::WorkloadLeaf => SpiffeId::parse(&self.svid)?.node_id().to_string(),
            SvidKind::NodeIdentity => model::parse_node_identity_san(&self.svid)?,
            SvidKind::IssuerIntermediate => model::parse_issuer_san(&self.svid)?,
        };
        if observed == node_id {
            Ok(())
        } else {
            Err(model::SpiffeIdError::WrongPathShape)
        }
    }
}

/// The identity-critical fields of one SVID, as covered by the KT binding
/// co-signature.
#[derive(Clone, Copy, Debug)]
pub struct KtBindingTranscript<'a> {
    /// Credential kind.
    pub kind: SvidKind,
    /// Canonical SVID URI.
    pub svid: &'a str,
    /// Issued serial (32 lowercase hex chars).
    pub serial: &'a str,
    /// SPKI SHA-256 (64 lowercase hex chars).
    pub spki_sha256: &'a str,
    /// Validity start, unix seconds.
    pub not_before: i64,
    /// Validity end, unix seconds.
    pub not_after: i64,
}

/// Canonical, domain-separated signing transcript for the hybrid
/// co-signature binding.
///
/// Encoding: [`KT_BINDING_DOMAIN`] `|| 0x00 ||` for each string field
/// (`u32` big-endian length `||` bytes) `||` `not_before` (i64 BE) `||`
/// `not_after` (i64 BE). Length prefixes make the encoding injective, so
/// different field tuples can never produce the same transcript.
pub fn binding_payload(t: &KtBindingTranscript<'_>) -> Vec<u8> {
    let mut out = Vec::with_capacity(128);
    out.extend_from_slice(KT_BINDING_DOMAIN);
    out.push(0x00);
    for field in [t.kind.as_str(), t.svid, t.serial, t.spki_sha256] {
        out.extend_from_slice(&(field.len() as u32).to_be_bytes());
        out.extend_from_slice(field.as_bytes());
    }
    out.extend_from_slice(&t.not_before.to_be_bytes());
    out.extend_from_slice(&t.not_after.to_be_bytes());
    out
}

// ---------------------------------------------------------------------------
// Versioned envelope
// ---------------------------------------------------------------------------

/// Versioned wire envelope: every SVID exchange is framed as
/// `{"v": 1, "body": {...}}`.
///
/// Both directions fail closed: encoding refuses to emit an envelope whose
/// `v` is not [`WIRE_VERSION`], and decoding refuses any other version (no
/// "best effort" parsing of unknown shapes). Unknown fields are denied at
/// both envelope and body level.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope<T> {
    /// Protocol version — must be [`WIRE_VERSION`].
    pub v: u8,
    /// Versioned payload.
    pub body: T,
}

impl<T> Envelope<T> {
    /// Wrap `body` in a v1 envelope (cannot be anything but v1 here).
    pub fn v1(body: T) -> Self {
        Self {
            v: WIRE_VERSION,
            body,
        }
    }

    /// The envelope version field.
    pub fn version(&self) -> u8 {
        self.v
    }
}

impl<T: Serialize> Envelope<T> {
    /// Serialize, refusing to emit an envelope with a non-current version.
    pub fn to_json(&self) -> Result<String, WireError> {
        if self.v != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion(self.v as u32));
        }
        Ok(serde_json::to_string(self)?)
    }
}

impl<'de, T: Deserialize<'de>> Envelope<T> {
    /// Parse, refusing any version other than [`WIRE_VERSION`].
    pub fn from_json(s: &'de str) -> Result<Self, WireError> {
        let env: Envelope<T> = serde_json::from_str(s)?;
        if env.v != WIRE_VERSION {
            return Err(WireError::UnsupportedVersion(env.v as u32));
        }
        Ok(env)
    }
}

impl Envelope<SvidMetaV1> {
    /// Encode + validate SVID metadata as a v1 envelope.
    pub fn encode_meta(meta: &SvidMetaV1) -> Result<String, WireError> {
        meta.validate()?;
        Envelope::v1(meta.clone()).to_json()
    }

    /// Decode a v1 metadata envelope and validate the body.
    pub fn decode_meta(s: &str) -> Result<SvidMetaV1, WireError> {
        let env = Envelope::<SvidMetaV1>::from_json(s)?;
        env.body.validate()?;
        Ok(env.body)
    }
}

// ---------------------------------------------------------------------------
// Issued bundle
// ---------------------------------------------------------------------------

/// The full issuance response the Workload API returns: metadata plus the DER
/// cert material (leaf + chain), hex-encoded.
///
/// `chain_der_hex` is ordered issuer-first (`[intermediate, node]` for a
/// workload leaf under the D1 two-cert split).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IssuedSvidV1 {
    /// Metadata for the leaf.
    pub meta: SvidMetaV1,
    /// Leaf certificate, DER, lowercase hex.
    pub leaf_der_hex: String,
    /// Issuer chain above the leaf, DER, lowercase hex, issuer-first.
    pub chain_der_hex: Vec<String>,
}

fn is_nonempty_lower_hex(s: &str) -> bool {
    !s.is_empty() && s.len().is_multiple_of(2) && is_lower_hex(s)
}

impl IssuedSvidV1 {
    /// Validate metadata and all DER hex fields.
    pub fn validate(&self) -> Result<(), WireError> {
        self.meta.validate()?;
        if !is_nonempty_lower_hex(&self.leaf_der_hex) {
            return Err(WireError::BadDerHex {
                field: "leaf_der_hex",
            });
        }
        for entry in &self.chain_der_hex {
            if !is_nonempty_lower_hex(entry) {
                return Err(WireError::BadDerHex {
                    field: "chain_der_hex",
                });
            }
        }
        Ok(())
    }

    /// Encode as a v1 envelope (validated first).
    pub fn to_json(&self) -> Result<String, WireError> {
        self.validate()?;
        Envelope::v1(self.clone()).to_json()
    }

    /// Decode a v1 bundle envelope and validate it.
    pub fn from_json(s: &str) -> Result<Self, WireError> {
        let env = Envelope::<IssuedSvidV1>::from_json(s)?;
        env.body.validate()?;
        Ok(env.body)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_kt() -> KtBindingV1 {
        KtBindingV1 {
            v: KT_BINDING_VERSION,
            alg: KT_BINDING_ALG.to_string(),
            ed25519: "cd".repeat(ED25519_SIG_BYTES),
            mldsa: "ef".repeat(MLDSA87_SIG_BYTES),
            signed_at: 1_700_000_000,
        }
    }

    fn sample_meta() -> SvidMetaV1 {
        let id = SpiffeId::new("node-01", "daemon").unwrap();
        let serial = IssuedSerial::new(7, [0xAB; 8]).unwrap();
        SvidMetaV1 {
            kind: SvidKind::WorkloadLeaf,
            svid: id.as_str().to_string(),
            serial: serial.to_hex(),
            spki_sha256: "ab".repeat(SPKI_SHA256_BYTES),
            not_before: 1_700_000_000,
            not_after: 1_700_000_000 + 6 * 3600,
            kt: sample_kt(),
        }
    }

    #[test]
    fn meta_serde_roundtrip() {
        let meta = sample_meta();
        meta.validate().expect("sample meta is valid");
        let json = serde_json::to_string(&meta).unwrap();
        let back: SvidMetaV1 = serde_json::from_str(&json).unwrap();
        assert_eq!(back, meta);
        assert!(json.contains("\"kind\":\"workload_leaf\""));
        assert!(json.contains("\"serial\":\"0000000000000007abababababababab\""));
    }

    #[test]
    fn envelope_v1_roundtrip() {
        let meta = sample_meta();
        let json = Envelope::encode_meta(&meta).unwrap();
        assert!(
            json.starts_with("{\"v\":1,"),
            "envelope carries v:1: {json}"
        );
        let decoded = Envelope::<SvidMetaV1>::decode_meta(&json).unwrap();
        assert_eq!(decoded, meta);
        let env = Envelope::<SvidMetaV1>::from_json(&json).unwrap();
        assert_eq!(env.version(), WIRE_VERSION);
        assert_eq!(env.body, meta);
    }

    #[test]
    fn envelope_refuses_unknown_and_missing_versions() {
        let json = Envelope::encode_meta(&sample_meta()).unwrap();
        for v in [0u8, 2, 255] {
            let bumped = json.replacen("\"v\":1", &format!("\"v\":{v}"), 1);
            match Envelope::<SvidMetaV1>::from_json(&bumped) {
                Err(WireError::UnsupportedVersion(got)) => assert_eq!(got as u8, v),
                other => panic!("v={v} must be refused, got {other:?}"),
            }
        }
        // missing v → hard json error, not a default
        let no_v = json.replacen("\"v\":1,", "", 1);
        assert!(matches!(
            Envelope::<SvidMetaV1>::from_json(&no_v),
            Err(WireError::Json(_))
        ));
        // extra envelope field → denied
        let extra = json.replacen("\"v\":1,", "\"v\":1,\"future\":true,", 1);
        assert!(matches!(
            Envelope::<SvidMetaV1>::from_json(&extra),
            Err(WireError::Json(_))
        ));
        // encoding a non-v1 envelope is refused too
        let bogus = Envelope {
            v: 2,
            body: sample_meta(),
        };
        assert!(matches!(
            bogus.to_json(),
            Err(WireError::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn meta_validation_rejects_bad_svid() {
        let mut meta = sample_meta();
        meta.svid = "https://tallow/node-01/svc/daemon".into();
        assert!(matches!(meta.validate(), Err(WireError::Svid(_))));
        meta.svid = "spiffe://tallow/node-01/workload/daemon".into();
        assert!(matches!(meta.validate(), Err(WireError::Svid(_))));
        meta.svid = "spiffe://TALLOW/node-01/svc/daemon".into();
        assert!(matches!(meta.validate(), Err(WireError::Svid(_))));
    }

    #[test]
    fn meta_validation_rejects_reserved_issuer_service_as_workload() {
        let mut meta = sample_meta();
        meta.svid = model::issuer_san("node-01").unwrap();
        assert!(matches!(meta.validate(), Err(WireError::ReservedService)));
    }

    #[test]
    fn meta_validation_checks_kind_shape() {
        // node identity kind + node SAN = ok
        let mut meta = sample_meta();
        meta.kind = SvidKind::NodeIdentity;
        meta.svid = model::node_identity_san("node-01").unwrap();
        meta.validate().expect("node identity shape");
        // node identity kind + workload SVID = reject
        meta.svid = SpiffeId::new("node-01", "daemon").unwrap().to_string();
        assert!(matches!(
            meta.validate(),
            Err(WireError::Svid(_) | WireError::KindShape { .. })
        ));
        // issuer kind + issuer SAN = ok, issuer kind + node SAN = reject
        let mut meta = sample_meta();
        meta.kind = SvidKind::IssuerIntermediate;
        meta.svid = model::issuer_san("node-01").unwrap();
        meta.validate().expect("issuer shape");
        meta.svid = model::node_identity_san("node-01").unwrap();
        assert!(matches!(
            meta.validate(),
            Err(WireError::KindShape {
                kind: SvidKind::IssuerIntermediate
            })
        ));
        // workload kind + node SAN = reject (wrong shape)
        let mut meta = sample_meta();
        meta.svid = model::node_identity_san("node-01").unwrap();
        assert!(matches!(meta.validate(), Err(WireError::Svid(_))));
    }

    #[test]
    fn meta_validation_checks_serial_and_spki_lengths() {
        let mut meta = sample_meta();
        meta.serial = "00".into();
        assert!(matches!(meta.validate(), Err(WireError::BadSerial)));
        meta.serial = "AB".repeat(SERIAL_HEX_LEN / 2); // uppercase is not canonical
        assert!(matches!(meta.validate(), Err(WireError::BadSerial)));
        meta.serial = sample_meta().serial.clone();
        meta.spki_sha256 = "ab".repeat(SPKI_SHA256_BYTES - 1);
        assert!(matches!(meta.validate(), Err(WireError::BadSpki)));
        meta.spki_sha256 = "zz".repeat(SPKI_SHA256_BYTES);
        assert!(matches!(meta.validate(), Err(WireError::BadSpki)));
    }

    #[test]
    fn meta_validation_checks_validity_window() {
        let mut meta = sample_meta();
        meta.not_after = meta.not_before;
        assert!(matches!(meta.validate(), Err(WireError::BadTimes)));
        meta.not_after = meta.not_before - 1;
        assert!(matches!(meta.validate(), Err(WireError::BadTimes)));
        meta.not_after = meta.not_before + 1;
        assert!(meta.validate().is_ok());
    }

    #[test]
    fn meta_matches_node_pins() {
        let meta = sample_meta();
        assert!(meta.matches_node("node-01").is_ok());
        assert!(meta.matches_node("node-02").is_err());
        // pins also work across kinds
        let mut node_meta = sample_meta();
        node_meta.kind = SvidKind::NodeIdentity;
        node_meta.svid = model::node_identity_san("node-09").unwrap();
        assert!(node_meta.matches_node("node-09").is_ok());
        assert!(node_meta.matches_node("node-01").is_err());
    }

    #[test]
    fn meta_rejects_unknown_field_smuggling() {
        let mut value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&sample_meta()).unwrap()).unwrap();
        value["smuggled"] = serde_json::json!("extra");
        let json = value.to_string();
        assert!(matches!(serde_json::from_str::<SvidMetaV1>(&json), Err(_)));
        // and via the envelope path
        let env = format!("{{\"v\":1,\"body\":{json}}}");
        assert!(matches!(
            Envelope::<SvidMetaV1>::from_json(&env),
            Err(WireError::Json(_))
        ));
    }

    #[test]
    fn kt_binding_validation_and_serde() {
        let kt = sample_kt();
        kt.validate().expect("sample binding valid");
        let json = serde_json::to_string(&kt).unwrap();
        assert_eq!(serde_json::from_str::<KtBindingV1>(&json).unwrap(), kt);

        let mut bad = kt.clone();
        bad.v = 2;
        assert!(matches!(bad.validate(), Err(WireError::BadKt(_))));
        let mut bad = kt.clone();
        bad.alg = "ed25519".into();
        assert!(matches!(bad.validate(), Err(WireError::BadKt(_))));
        let mut bad = kt.clone();
        bad.ed25519 = "cd".repeat(63); // 63 bytes
        assert!(matches!(bad.validate(), Err(WireError::BadKt(_))));
        let mut bad = kt.clone();
        bad.mldsa = "ef".repeat(MLDSA87_SIG_BYTES - 1);
        assert!(matches!(bad.validate(), Err(WireError::BadKt(_))));
        let mut bad = kt;
        bad.mldsa = bad.mldsa.to_uppercase(); // non-canonical hex refused
        assert!(matches!(bad.validate(), Err(WireError::BadKt(_))));

        // a bad binding inside meta is caught by meta validation
        let mut meta = sample_meta();
        meta.kt.v = 9;
        assert!(matches!(meta.validate(), Err(WireError::BadKt(_))));
    }

    #[test]
    fn binding_payload_is_deterministic_domain_separated_and_injective() {
        let meta = sample_meta();
        let payload = meta.binding_payload();
        assert!(payload.starts_with(KT_BINDING_DOMAIN));
        assert_eq!(payload[KT_BINDING_DOMAIN.len()], 0x00);
        assert_eq!(payload, meta.binding_payload(), "deterministic");

        // Every field change must change the transcript (injective encoding).
        let base = KtBindingTranscript {
            kind: meta.kind,
            svid: &meta.svid,
            serial: &meta.serial,
            spki_sha256: &meta.spki_sha256,
            not_before: meta.not_before,
            not_after: meta.not_after,
        };
        let base_payload = binding_payload(&base);
        let other_svid = SpiffeId::new("node-02", "daemon").unwrap().to_string();
        let other_serial = IssuedSerial::new(8, [0xAB; 8]).unwrap().to_hex();
        let other_spki = "ba".repeat(SPKI_SHA256_BYTES);
        let variants = [
            KtBindingTranscript {
                kind: SvidKind::NodeIdentity,
                ..base
            },
            KtBindingTranscript {
                svid: &other_svid,
                ..base
            },
            KtBindingTranscript {
                serial: &other_serial,
                ..base
            },
            KtBindingTranscript {
                spki_sha256: &other_spki,
                ..base
            },
            KtBindingTranscript {
                not_before: base.not_before + 1,
                ..base
            },
            KtBindingTranscript {
                not_after: base.not_after + 1,
                ..base
            },
        ];
        let mut seen = std::collections::BTreeSet::new();
        assert!(seen.insert(base_payload.clone()));
        for v in &variants {
            let p = binding_payload(v);
            assert_ne!(p, base_payload, "field change must change the payload");
            assert!(seen.insert(p), "no two variants may collide");
        }
        // length-prefixed fields: swapping values can't be confused with
        // splitting them differently
        let a = "ab";
        let b = "c";
        let t1 = KtBindingTranscript {
            svid: a,
            serial: b,
            ..base
        };
        let t2 = KtBindingTranscript {
            svid: b,
            serial: a,
            ..base
        };
        assert_ne!(binding_payload(&t1), binding_payload(&t2));
    }

    #[test]
    fn issued_bundle_roundtrip_and_validation() {
        let bundle = IssuedSvidV1 {
            meta: sample_meta(),
            leaf_der_hex: "300102".into(),
            chain_der_hex: vec!["300102".into(), "300103".into()],
        };
        bundle.validate().expect("valid bundle");
        let json = bundle.to_json().unwrap();
        assert!(json.starts_with("{\"v\":1,"));
        assert_eq!(IssuedSvidV1::from_json(&json).unwrap(), bundle);

        let mut bad = bundle.clone();
        bad.leaf_der_hex = String::new();
        assert!(matches!(
            bad.validate(),
            Err(WireError::BadDerHex {
                field: "leaf_der_hex"
            })
        ));
        let mut bad = bundle.clone();
        bad.chain_der_hex = vec!["zz".into()];
        assert!(matches!(
            bad.validate(),
            Err(WireError::BadDerHex {
                field: "chain_der_hex"
            })
        ));
        let mut bad = bundle.clone();
        bad.meta.serial = "nothex".into();
        assert!(matches!(bad.validate(), Err(WireError::BadSerial)));
        let mut bad = bundle;
        bad.meta.kt.mldsa = "ef".into();
        assert!(matches!(bad.validate(), Err(WireError::BadKt(_))));
    }

    #[test]
    fn envelope_decode_fails_closed_on_garbage() {
        for junk in ["", "not json", "[]", "{}", "{\"v\":\"1\",\"body\":{}}"] {
            assert!(
                Envelope::<SvidMetaV1>::from_json(junk).is_err(),
                "must reject {junk:?}"
            );
        }
        // a valid v1 envelope whose body fails validation is rejected at the
        // typed decode — body and metadata can never diverge
        let mut meta = sample_meta();
        meta.spki_sha256 = "nope".into();
        let json = format!(
            "{{\"v\":1,\"body\":{}}}",
            serde_json::to_string(&meta).unwrap()
        );
        assert!(matches!(
            Envelope::<SvidMetaV1>::decode_meta(&json),
            Err(WireError::BadSpki)
        ));
    }
}
