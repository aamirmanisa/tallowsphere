//! `issuer` — SVID issuance: [`NodeIssuer`], a pure in-memory Ed25519 X.509-SVID
//! issuer built on `rcgen` 0.13 (owner: U-212; model/policy by U-211).
//!
//! ## Shape (parent decision D1, GOVERNANCE.md)
//!
//! Two-cert split, all Ed25519 (report §5.4 / R-5.1):
//!
//! ```text
//! node identity cert     spiffe://tallow/<node-id>                30–90 d   (self-signed, KT-pinned)
//!   └─ issuer intermediate  …/<node-id>/svc/svid-issuer           ≤ 7 d     (hard cap, renewed by daemon)
//!        └─ workload leaf      …/<node-id>/svc/<name>             1–24 h    (default 4–8 h, re-issue at T/2)
//! ```
//!
//! `issue_issuer_intermediate()` refuses any TTL above the 7-day cap and
//! `issue_workload_leaf()` refuses any leaf TTL outside the 1–24 h band — both
//! via [`crate::policy`] (fail-closed: never silently clamped). Serials come
//! from [`crate::model::SerialAllocator`] (monotonic counter ‖ random suffix,
//! never reused; persistence/resume is the daemon's job).
//!
//! ## Hybrid co-signatures (D2) — NOT in the X.509 cert
//!
//! `rcgen` cannot sign with ML-DSA, so v1 SVIDs are classical Ed25519
//! certificates. The hybrid (Ed25519 + ML-DSA-87) co-signature required by the
//! program binds **at the enrollment / key-transparency layer** — over
//! `(SPKI, spiffe-id, serial, not_before, not_after)` — and is recorded in the
//! KT/ledger entry, never inside the X.509 certificate. Verification here
//! therefore checks the *classical* chain only; callers that need the hybrid
//! binding must check the KT entry (that is a deliberate, documented split, not
//! an omission).
//!
//! ## Key custody
//!
//! Construction takes a caller-provided node key and keeps it **in memory
//! only**. Vault/TPM custody (G-03) is a later task; nothing here writes key
//! material to disk.
//!
//! ## Why there is a hand-rolled DER reader
//!
//! The crate pins `rcgen` with `default-features = false, features = ["aws_lc_rs"]`,
//! so rcgen's `x509-parser` feature is off and `CertificateSigningRequestParams::from_der`
//! / `SubjectPublicKeyInfo::from_der` do not exist in this build. `der` below is
//! the (small, strict) replacement: it extracts exactly what issuance and
//! verification need from a CSR or certificate — never anything else.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, IsCa, KeyPair, KeyUsagePurpose, PublicKeyData, SanType, SerialNumber,
    SignatureAlgorithm, PKCS_ED25519,
};
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};

use crate::model::{self, IssuedSerial, SerialAllocator, SpiffeId, SvidKind, SvidProfile};
use crate::policy::{self, ServiceRegistry};
use crate::verify::SvidError;

/// Common name used when no better subject name is available (kept non-empty so
/// issuer/subject DN chaining is exercised in path building).
pub const NODE_DN_CN: &str = "tallow-svid-node";

// ---------------------------------------------------------------------------
// Minimal DER reader (rcgen's x509-parser feature is not enabled in this crate)
// ---------------------------------------------------------------------------

/// Strict-enough DER reader for the two inputs this crate ingests: PKCS#10
/// certification requests and X.509 certificates (see module docs).
pub(crate) mod der {
    /// DER parse failure (never contains attacker-controlled data lengths).
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DerError(pub &'static str);

    impl std::fmt::Display for DerError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(self.0)
        }
    }

    impl std::error::Error for DerError {}

    /// One DER tag-length-value triple. `full` is the complete TLV (what a
    /// signature covers), `value` the content bytes.
    #[derive(Debug, Clone, Copy)]
    pub struct Tlv<'a> {
        /// DER tag byte (low-tag-number form only).
        pub tag: u8,
        /// Complete TLV bytes.
        pub full: &'a [u8],
        /// Content octets.
        pub value: &'a [u8],
    }

    /// Cursor over a DER byte slice.
    pub struct Reader<'a> {
        buf: &'a [u8],
    }

    fn read_len(b: &[u8]) -> Result<(usize, usize), DerError> {
        let first = *b.first().ok_or(DerError("truncated DER length"))?;
        if first & 0x80 == 0 {
            return Ok((first as usize, 1));
        }
        let n = (first & 0x7f) as usize;
        if n == 0 || n > 4 {
            return Err(DerError("unsupported DER length form"));
        }
        if b.len() < 1 + n {
            return Err(DerError("truncated long-form length"));
        }
        let mut v = 0usize;
        for &byte in &b[1..1 + n] {
            v = (v << 8) | byte as usize;
        }
        Ok((v, 1 + n))
    }

    impl<'a> Reader<'a> {
        /// New cursor.
        pub fn new(buf: &'a [u8]) -> Self {
            Self { buf }
        }
        /// True iff every byte was consumed.
        pub fn is_empty(&self) -> bool {
            self.buf.is_empty()
        }
        /// Tag of the next element, if any.
        pub fn peek_tag(&self) -> Option<u8> {
            self.buf.first().copied()
        }
        /// Read the next TLV.
        pub fn next_tlv(&mut self) -> Result<Tlv<'a>, DerError> {
            let tag = *self.buf.first().ok_or(DerError("unexpected end of DER"))?;
            if tag & 0x1f == 0x1f {
                return Err(DerError("high-tag-number form unsupported"));
            }
            let (len, hdr) = read_len(&self.buf[1..])?;
            let total = 1 + hdr + len;
            if self.buf.len() < total {
                return Err(DerError("DER TLV exceeds buffer"));
            }
            let full = &self.buf[..total];
            let value = &self.buf[1 + hdr..total];
            self.buf = &self.buf[total..];
            Ok(Tlv { tag, full, value })
        }
        /// Read the next TLV, requiring a specific tag.
        pub fn expect(&mut self, tag: u8) -> Result<Tlv<'a>, DerError> {
            let t = self.next_tlv()?;
            if t.tag != tag {
                return Err(DerError("unexpected DER tag"));
            }
            Ok(t)
        }
        /// Descend into a SEQUENCE.
        pub fn expect_seq(&mut self) -> Result<Reader<'a>, DerError> {
            let t = self.expect(0x30)?;
            Ok(Reader::new(t.value))
        }
        /// Read an OBJECT IDENTIFIER's content bytes.
        pub fn expect_oid(&mut self) -> Result<&'a [u8], DerError> {
            Ok(self.expect(0x06)?.value)
        }
    }

    /// OBJECT IDENTIFIER content bytes of `1.3.101.112` (Ed25519).
    pub const ED25519_OID: &[u8] = &[0x2b, 0x65, 0x70];
    /// OBJECT IDENTIFIER content bytes of `2.5.29.17` (subjectAltName).
    pub const SAN_OID: &[u8] = &[0x55, 0x1d, 0x11];
    /// OBJECT IDENTIFIER content bytes of `2.5.29.19` (basicConstraints).
    pub const BASIC_CONSTRAINTS_OID: &[u8] = &[0x55, 0x1d, 0x13];

    /// A parsed PKCS#10 certification request.
    #[derive(Debug)]
    pub struct CsrParts<'a> {
        /// Complete DER of the signed `CertificationRequestInfo`.
        pub cri_der: &'a [u8],
        /// Complete DER of the `SubjectPublicKeyInfo`.
        ///
        /// Retained as part of the parsed view (in-tree issuance can rebuild
        /// it from `raw_public_key`; external verification tooling may want
        /// the exact bytes as presented).
        #[allow(dead_code)]
        pub spki_der: &'a [u8],
        /// Raw public key bits (32 bytes for Ed25519).
        pub raw_public_key: &'a [u8],
        /// Signature bits (64 bytes for Ed25519).
        pub signature: &'a [u8],
    }

    /// True iff `b` is DER-encoded as the given OID content bytes.
    fn oid_is(b: &[u8], oid: &[u8]) -> bool {
        b == oid
    }

    /// Parse an Ed25519 PKCS#10 CSR. The CSR's own signature is *not* verified
    /// here — [`super::NodeIssuer::issue_workload_leaf`] does that
    /// (key-possession) before the key is embedded.
    pub fn parse_csr(csr_der: &[u8]) -> Result<CsrParts<'_>, DerError> {
        let mut outer = Reader::new(csr_der).expect_seq()?;
        let cri = outer.expect(0x30)?;
        let sig_alg = outer.expect(0x30)?;
        let sig_bits = outer.expect(0x03)?;
        if !outer.is_empty() {
            return Err(DerError("trailing bytes after CSR"));
        }
        {
            let mut a = Reader::new(sig_alg.value);
            if !oid_is(a.expect_oid()?, ED25519_OID) {
                return Err(DerError("CSR signature algorithm is not Ed25519"));
            }
        }
        let signature = sig_bits
            .value
            .strip_prefix(&[0x00])
            .ok_or(DerError("bad signature BIT STRING"))?;
        if signature.len() != 64 {
            return Err(DerError("Ed25519 signature must be 64 bytes"));
        }

        let mut cri_r = Reader::new(cri.value);
        let _version = cri_r.expect(0x02)?;
        let _subject = cri_r.expect(0x30)?;
        let spki = cri_r.expect(0x30)?;
        if cri_r.peek_tag() == Some(0xa0) {
            let _attrs = cri_r.expect(0xa0)?;
        }
        if !cri_r.is_empty() {
            return Err(DerError("trailing bytes in CSR info"));
        }

        let raw = parse_spki(spki.full)?;
        Ok(CsrParts {
            cri_der: cri.full,
            spki_der: spki.full,
            raw_public_key: raw,
            signature,
        })
    }

    /// Parse a **complete** DER `SubjectPublicKeyInfo`, returning the raw
    /// Ed25519 public key and requiring the Ed25519 algorithm OID.
    pub fn parse_spki(spki_der: &[u8]) -> Result<&[u8], DerError> {
        let mut r = Reader::new(spki_der);
        let mut seq = r.expect_seq()?;
        {
            let alg = seq.expect(0x30)?;
            let mut a = Reader::new(alg.value);
            if !oid_is(a.expect_oid()?, ED25519_OID) {
                return Err(DerError("public key algorithm is not Ed25519"));
            }
        }
        let bits = seq.expect(0x03)?;
        let raw = bits
            .value
            .strip_prefix(&[0x00])
            .ok_or(DerError("bad public key BIT STRING"))?;
        if raw.len() != 32 {
            return Err(DerError("Ed25519 public key must be 32 bytes"));
        }
        Ok(raw)
    }

    /// Everything issuance/verification needs out of an X.509 certificate.
    #[derive(Debug)]
    pub struct CertInfo<'a> {
        /// notBefore as Unix seconds.
        pub not_before: i64,
        /// notAfter as Unix seconds.
        pub not_after: i64,
        /// `basicConstraints.cA`.
        pub is_ca: bool,
        /// URI general names from the subjectAltName extension, in DER order.
        pub san_uris: Vec<&'a str>,
        /// Content octets of the serialNumber INTEGER.
        pub serial_der: &'a [u8],
        /// Complete DER of the signed `tbsCertificate`.
        pub tbs_der: &'a [u8],
        /// Content bytes of the outer signatureAlgorithm OID.
        ///
        /// Validated during parsing (must equal [`ED25519_OID`]); retained as
        /// part of the parsed view for external verification tooling.
        #[allow(dead_code)]
        pub sig_alg_oid: &'a [u8],
        /// Signature bits (outer signatureValue BIT STRING, unused-bits byte stripped).
        pub signature: &'a [u8],
        /// Raw subject public key bits (32 bytes for Ed25519).
        pub spki_raw_key: &'a [u8],
    }

    fn parse_time(t: Tlv<'_>) -> Result<i64, DerError> {
        let s = std::str::from_utf8(t.value).map_err(|_| DerError("time is not ASCII"))?;
        if !s.ends_with('Z') {
            return Err(DerError("only Zulu ASN.1 times supported"));
        }
        let d = &s[..s.len() - 1];
        let bad = DerError("bad ASN.1 time");
        let (y, mo, da, h, mi, sec): (i64, i64, i64, i64, i64, i64) = match t.tag {
            0x17 => {
                if d.len() != 12 {
                    return Err(bad);
                }
                let yy: i64 = d[0..2].parse().map_err(|_| bad)?;
                let y = if yy >= 50 { 1900 + yy } else { 2000 + yy };
                (
                    y,
                    d[2..4].parse().map_err(|_| bad)?,
                    d[4..6].parse().map_err(|_| bad)?,
                    d[6..8].parse().map_err(|_| bad)?,
                    d[8..10].parse().map_err(|_| bad)?,
                    d[10..12].parse().map_err(|_| bad)?,
                )
            }
            0x18 => {
                if d.len() != 14 {
                    return Err(bad);
                }
                (
                    d[0..4].parse().map_err(|_| bad)?,
                    d[4..6].parse().map_err(|_| bad)?,
                    d[6..8].parse().map_err(|_| bad)?,
                    d[8..10].parse().map_err(|_| bad)?,
                    d[10..12].parse().map_err(|_| bad)?,
                    d[12..14].parse().map_err(|_| bad)?,
                )
            }
            _ => return Err(DerError("not an ASN.1 time")),
        };
        Ok(days_from_civil(y, mo, da) * 86_400 + h * 3600 + mi * 60 + sec)
    }

    /// Days since 1970-01-01 for a proleptic-Gregorian date (Howard Hinnant's
    /// `days_from_civil`).
    fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
        let y = if m <= 2 { y - 1 } else { y };
        let era = if y >= 0 { y } else { y - 399 } / 400;
        let yoe = y - era * 400;
        let mp = if m > 2 { m - 3 } else { m + 9 };
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        era * 146_097 + doe - 719_468
    }

    fn parse_general_name_uris(der: &[u8]) -> Result<Vec<&str>, DerError> {
        let mut r = Reader::new(der);
        let mut names = r.expect_seq()?;
        let mut out = Vec::new();
        while !names.is_empty() {
            let gn = names.next_tlv()?;
            if gn.tag == 0x86 {
                let s =
                    std::str::from_utf8(gn.value).map_err(|_| DerError("URI SAN is not ASCII"))?;
                out.push(s);
            }
        }
        Ok(out)
    }

    fn parse_basic_constraints(der: &[u8]) -> Result<bool, DerError> {
        let mut r = Reader::new(der);
        let mut seq = r.expect_seq()?;
        if seq.peek_tag() == Some(0x01) {
            let b = seq.expect(0x01)?;
            return Ok(b.value != [0x00]);
        }
        Ok(false)
    }

    /// Parse an X.509 certificate into [`CertInfo`].
    pub fn parse_cert(der: &[u8]) -> Result<CertInfo<'_>, DerError> {
        let mut cert = Reader::new(der).expect_seq()?;
        let tbs = cert.expect(0x30)?;
        let sig_alg = cert.expect(0x30)?;
        let sig_bits = cert.expect(0x03)?;
        let sig_alg_oid = {
            let mut a = Reader::new(sig_alg.value);
            a.expect_oid()?
        };
        if sig_alg_oid != ED25519_OID {
            return Err(DerError("certificate signature algorithm is not Ed25519"));
        }
        let signature = sig_bits
            .value
            .strip_prefix(&[0x00])
            .ok_or(DerError("bad signature BIT STRING"))?;

        let mut r = Reader::new(tbs.value);
        if r.peek_tag() == Some(0xa0) {
            let _version = r.expect(0xa0)?;
        }
        let serial = r.expect(0x02)?;
        let _inner_sig_alg = r.expect(0x30)?;
        let _issuer = r.expect(0x30)?;
        let validity = r.expect(0x30)?;
        let (not_before, not_after) = {
            let mut v = Reader::new(validity.value);
            (parse_time(v.next_tlv()?)?, parse_time(v.next_tlv()?)?)
        };
        let _subject = r.expect(0x30)?;
        let spki = r.expect(0x30)?;
        let spki_raw_key = parse_spki(spki.full)?;

        let mut san_uris = Vec::new();
        let mut is_ca = false;
        while !r.is_empty() {
            let t = r.next_tlv()?;
            if t.tag == 0xa3 {
                let mut exts = Reader::new(t.value).expect_seq()?;
                while !exts.is_empty() {
                    let ext = exts.expect(0x30)?;
                    let mut er = Reader::new(ext.value);
                    let oid = er.expect_oid()?;
                    if er.peek_tag() == Some(0x01) {
                        let _critical = er.expect(0x01)?;
                    }
                    let octets = er.expect(0x04)?;
                    if oid_is(oid, SAN_OID) {
                        san_uris = parse_general_name_uris(octets.value)?;
                    } else if oid_is(oid, BASIC_CONSTRAINTS_OID) {
                        is_ca = parse_basic_constraints(octets.value)?;
                    }
                }
            }
        }

        Ok(CertInfo {
            not_before,
            not_after,
            is_ca,
            san_uris,
            serial_der: serial.value,
            tbs_der: tbs.full,
            sig_alg_oid,
            signature,
            spki_raw_key,
        })
    }
}

// ---------------------------------------------------------------------------
// Time helpers
// ---------------------------------------------------------------------------

/// Current wall-clock time as Unix seconds (negative before 1970).
pub fn now_unix() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -((e.duration().as_secs()) as i64),
    }
}

fn system_time(unix_secs: i64) -> SystemTime {
    if unix_secs >= 0 {
        UNIX_EPOCH + Duration::from_secs(unix_secs as u64)
    } else {
        UNIX_EPOCH - Duration::from_secs(unix_secs.unsigned_abs())
    }
}

// ---------------------------------------------------------------------------
// Issuer
// ---------------------------------------------------------------------------

/// Where the workload leaf's public key comes from.
#[derive(Debug, Clone, Copy)]
pub enum LeafSubject<'a> {
    /// DER-encoded `SubjectPublicKeyInfo` (Ed25519 only).
    SpkiDer(&'a [u8]),
    /// DER-encoded PKCS#10 certification request. Its self-signature is
    /// verified (**key possession**) before the key is embedded, and the CSR's
    /// own SAN/extension requests are **ignored** — the SVID SAN always comes
    /// from the model [`SpiffeId`].
    CsrDer(&'a [u8]),
}

/// A single issued certificate.
#[derive(Debug, Clone)]
pub struct IssuedCert {
    /// Credential kind (D1 profile).
    pub kind: SvidKind,
    /// Issued certificate DER.
    pub cert_der: CertificateDer<'static>,
    /// Allocated serial (monotonic counter ‖ random suffix).
    pub serial: IssuedSerial,
    /// Spiffe URI placed in the SAN.
    pub san: String,
    /// notBefore (Unix seconds).
    pub not_before: i64,
    /// notAfter (Unix seconds).
    pub not_after: i64,
}

impl IssuedCert {
    /// Lifetime in whole seconds.
    pub fn ttl_secs(&self) -> u64 {
        self.not_after.saturating_sub(self.not_before).max(0) as u64
    }
}

/// An issued workload chain: `[intermediate, leaf]` (issuance order, the DER
/// order TLS/SPIFFE consumers expect).
#[derive(Debug, Clone)]
pub struct IssuedChain {
    /// `[intermediate, leaf]`.
    pub chain: Vec<CertificateDer<'static>>,
    /// The SVID-issuer intermediate that signed the leaf.
    pub intermediate: IssuedCert,
    /// The workload leaf SVID.
    pub leaf: IssuedCert,
}

impl IssuedChain {
    /// The leaf DER.
    pub fn leaf_der(&self) -> &CertificateDer<'static> {
        &self.chain[1]
    }
    /// The intermediate DER (also the verify-time trust anchor).
    pub fn intermediate_der(&self) -> &CertificateDer<'static> {
        &self.chain[0]
    }
}

struct Intermediate {
    cert: Certificate,
    key: KeyPair,
    issued: IssuedCert,
}

/// In-memory SVID issuer: node Ed25519 key + node identity cert + one active
/// SVID-issuer intermediate, plus the monotonic serial allocator.
///
/// Not `Clone`/`Send`-documented: the node key is secret material held in
/// memory (vault custody lands separately, G-03).
pub struct NodeIssuer {
    node_id: String,
    node_key: KeyPair,
    node_cert: Certificate,
    node_issued: IssuedCert,
    intermediate: Option<Intermediate>,
    serials: SerialAllocator,
    registry: ServiceRegistry,
}

impl std::fmt::Debug for NodeIssuer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NodeIssuer")
            .field("node_id", &self.node_id)
            .field("has_intermediate", &self.intermediate.is_some())
            .field("serial_high_water", &self.serials.high_water())
            .field("registry_len", &self.registry.len())
            .finish_non_exhaustive()
    }
}

impl NodeIssuer {
    /// Build an issuer for `node_id` from a caller-provided Ed25519 key pair.
    ///
    /// Immediately self-issues the node identity cert with the default TTL
    /// (60 d, inside the D1 30–90 d band); re-issue with
    /// [`NodeIssuer::issue_node_identity`].
    pub fn new(node_key: KeyPair, node_id: &str) -> Result<Self, SvidError> {
        model::validate_node_id(node_id)?;
        let serials = SerialAllocator::new();
        let mut issuer = Self {
            node_id: node_id.to_string(),
            node_key,
            // placeholder replaced below before any use
            node_cert: Self::placeholder_cert()?,
            node_issued: IssuedCert {
                kind: SvidKind::NodeIdentity,
                cert_der: CertificateDer::from(Vec::new()),
                serial: IssuedSerial::new(1, [0u8; model::SERIAL_SUFFIX_BYTES])?,
                san: String::new(),
                not_before: 0,
                not_after: 0,
            },
            intermediate: None,
            serials,
            registry: ServiceRegistry::builtin(),
        };
        let issued = issuer.issue_node_identity(None)?;
        debug_assert_eq!(issued.kind, SvidKind::NodeIdentity);
        Ok(issuer)
    }

    /// Generate a fresh Ed25519 node key (convenience; production custody is
    /// the vault's job).
    pub fn generate(node_id: &str) -> Result<Self, SvidError> {
        let key =
            KeyPair::generate_for(&PKCS_ED25519).map_err(|e| SvidError::Key(e.to_string()))?;
        Self::new(key, node_id)
    }

    /// Build an issuer from PKCS#8 DER node key material.
    pub fn from_pkcs8(node_id: &str, pkcs8_der: &[u8]) -> Result<Self, SvidError> {
        let pkcs8 = PrivatePkcs8KeyDer::from(pkcs8_der.to_vec());
        let key = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8, &PKCS_ED25519)
            .map_err(|e| SvidError::Key(e.to_string()))?;
        Self::new(key, node_id)
    }

    /// Replace the workload service allowlist (default: builtins).
    pub fn set_registry(&mut self, registry: ServiceRegistry) {
        self.registry = registry;
    }

    /// The registered-service allowlist in force.
    pub fn registry(&self) -> &ServiceRegistry {
        &self.registry
    }

    /// Node id this issuer is pinned to.
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    /// Node identity cert DER.
    pub fn node_cert_der(&self) -> CertificateDer<'static> {
        self.node_issued.cert_der.clone()
    }

    /// Node identity cert issuance record.
    pub fn node_identity(&self) -> &IssuedCert {
        &self.node_issued
    }

    /// Current SVID-issuer intermediate DER, if one has been issued.
    pub fn intermediate_cert_der(&self) -> Option<CertificateDer<'static>> {
        self.intermediate
            .as_ref()
            .map(|i| i.issued.cert_der.clone())
    }

    /// Current SVID-issuer intermediate issuance record, if any.
    pub fn intermediate(&self) -> Option<&IssuedCert> {
        self.intermediate.as_ref().map(|i| &i.issued)
    }

    /// Highest serial counter issued so far (persist this across restarts and
    /// resume with [`SerialAllocator::resume_from`]).
    pub fn serial_high_water(&self) -> u64 {
        self.serials.high_water()
    }

    /// Self-issue (or re-issue) the node identity cert: `spiffe://tallow/<node-id>`,
    /// self-signed by the node key, TTL inside the D1 30–90 d band.
    pub fn issue_node_identity(&mut self, ttl: Option<Duration>) -> Result<IssuedCert, SvidError> {
        let ttl = policy::effective_ttl(SvidKind::NodeIdentity, ttl)?;
        let san = model::node_identity_san(&self.node_id)?;
        let serial = self.serials.alloc()?;
        let now = now_unix();
        let not_after = now.saturating_add(ttl.as_secs() as i64);
        let params = Self::params(
            &san,
            &self.node_id,
            SvidProfile::NODE_IDENTITY,
            &serial,
            now,
            not_after,
        )?;
        let cert = params
            .self_signed(&self.node_key)
            .map_err(|e| SvidError::Issuance(e.to_string()))?;
        let issued = IssuedCert {
            kind: SvidKind::NodeIdentity,
            cert_der: cert.der().clone(),
            serial,
            san,
            not_before: now,
            not_after,
        };
        self.node_issued = issued.clone();
        self.node_cert = cert;
        Ok(issued)
    }

    /// Issue an SVID-issuer intermediate: `…/<node-id>/svc/svid-issuer`,
    /// CA=true, signed by the node key, **TTL hard-capped at 7 days** (D1).
    /// `None` yields the 24 h default.
    pub fn issue_issuer_intermediate(
        &mut self,
        ttl: Option<Duration>,
    ) -> Result<IssuedCert, SvidError> {
        let ttl = policy::effective_ttl(SvidKind::IssuerIntermediate, ttl)?;
        let san = model::issuer_san(&self.node_id)?;
        let key =
            KeyPair::generate_for(&PKCS_ED25519).map_err(|e| SvidError::Key(e.to_string()))?;
        let serial = self.serials.alloc()?;
        let now = now_unix();
        let not_after = now.saturating_add(ttl.as_secs() as i64);
        let params = Self::params(
            &san,
            &san,
            SvidProfile::ISSUER_INTERMEDIATE,
            &serial,
            now,
            not_after,
        )?;
        let cert = params
            .signed_by(&key, &self.node_cert, &self.node_key)
            .map_err(|e| SvidError::Issuance(e.to_string()))?;
        let issued = IssuedCert {
            kind: SvidKind::IssuerIntermediate,
            cert_der: cert.der().clone(),
            serial,
            san,
            not_before: now,
            not_after,
        };
        self.intermediate = Some(Intermediate { cert, key, issued });
        Ok(self.intermediate.as_ref().expect("just set").issued.clone())
    }

    /// Issue a workload leaf SVID and return the `[intermediate, leaf]` chain.
    ///
    /// * `subject` — the leaf's public key (SPKI DER or a CSR whose
    ///   self-signature is checked for key possession),
    /// * `id` — the workload [`SpiffeId`]; it must name a **registered**
    ///   service (issuance allowlist) and its node segment must match this
    ///   issuer's node id (ATK-2.10 pinning),
    /// * `ttl` — `None` yields the 6 h default; anything outside 1–24 h is
    ///   refused (D1).
    pub fn issue_workload_leaf(
        &mut self,
        subject: LeafSubject<'_>,
        id: &SpiffeId,
        ttl: Option<Duration>,
    ) -> Result<IssuedChain, SvidError> {
        let ttl = policy::effective_ttl(SvidKind::WorkloadLeaf, ttl)?;
        let now = now_unix();
        let not_after = now.saturating_add(ttl.as_secs() as i64);
        self.issue_workload_leaf_window(subject, id, now, not_after)
    }

    /// Issue a workload leaf for an **explicit validity window** (Unix
    /// seconds). Used by tests and by rotation replay; the window's length is
    /// still checked against the D1 leaf band.
    pub fn issue_workload_leaf_window(
        &mut self,
        subject: LeafSubject<'_>,
        id: &SpiffeId,
        not_before: i64,
        not_after: i64,
    ) -> Result<IssuedChain, SvidError> {
        self.registry.require_registered(id.service())?;
        policy::check_node_pin(&self.node_id, id)?;
        let ttl_secs = not_after.saturating_sub(not_before).max(0) as u64;
        policy::validate_ttl_secs(SvidKind::WorkloadLeaf, ttl_secs)?;

        let raw_key: Vec<u8> = match subject {
            LeafSubject::SpkiDer(spki) => der::parse_spki(spki)?.to_vec(),
            LeafSubject::CsrDer(csr) => {
                let parts = der::parse_csr(csr)?;
                Self::check_key_possession(&parts)?;
                parts.raw_public_key.to_vec()
            }
        };
        let subject_key = RawLeafKey { raw: raw_key };

        let intermediate = self
            .intermediate
            .as_ref()
            .ok_or(SvidError::NoIntermediate)?;
        let serial = self.serials.alloc()?;
        let san = id.as_str().to_string();
        let params = Self::params(
            &san,
            &san,
            SvidProfile::WORKLOAD_LEAF,
            &serial,
            not_before,
            not_after,
        )?;
        let leaf = params
            .signed_by(&subject_key, &intermediate.cert, &intermediate.key)
            .map_err(|e| SvidError::Issuance(e.to_string()))?;

        let leaf_issued = IssuedCert {
            kind: SvidKind::WorkloadLeaf,
            cert_der: leaf.der().clone(),
            serial,
            san,
            not_before,
            not_after,
        };
        let intermediate_issued = intermediate.issued.clone();
        Ok(IssuedChain {
            chain: vec![
                intermediate_issued.cert_der.clone(),
                leaf_issued.cert_der.clone(),
            ],
            intermediate: intermediate_issued,
            leaf: leaf_issued,
        })
    }

    /// Convenience: [`LeafSubject::SpkiDer`].
    pub fn issue_workload_leaf_from_spki(
        &mut self,
        spki_der: &[u8],
        id: &SpiffeId,
        ttl: Option<Duration>,
    ) -> Result<IssuedChain, SvidError> {
        self.issue_workload_leaf(LeafSubject::SpkiDer(spki_der), id, ttl)
    }

    /// Convenience: [`LeafSubject::CsrDer`].
    pub fn issue_workload_leaf_from_csr(
        &mut self,
        csr_der: &[u8],
        id: &SpiffeId,
        ttl: Option<Duration>,
    ) -> Result<IssuedChain, SvidError> {
        self.issue_workload_leaf(LeafSubject::CsrDer(csr_der), id, ttl)
    }

    /// Key-possession check for CSR ingest: the CSR's self-signature must
    /// verify under the public key it carries.
    fn check_key_possession(parts: &der::CsrParts<'_>) -> Result<(), SvidError> {
        let pubkey: [u8; 32] = parts
            .raw_public_key
            .try_into()
            .map_err(|_| SvidError::Signature("public key is not 32 bytes".into()))?;
        let sig: [u8; 64] = parts
            .signature
            .try_into()
            .map_err(|_| SvidError::Signature("signature is not 64 bytes".into()))?;
        tallow_crypto::sig::ed25519::verify(&pubkey, parts.cri_der, &sig)
            .map_err(|e| SvidError::Signature(format!("CSR key possession: {e}")))
    }

    /// Build `CertificateParams` from the D1 profile for `kind`.
    fn params(
        san: &str,
        cn: &str,
        profile: SvidProfile,
        serial: &IssuedSerial,
        not_before: i64,
        not_after: i64,
    ) -> Result<CertificateParams, SvidError> {
        let mut params = CertificateParams::default();
        params.not_before = system_time(not_before).into();
        params.not_after = system_time(not_after).into();
        params.serial_number = Some(SerialNumber::from_slice(&serial.as_bytes()));
        params.subject_alt_names = vec![SanType::URI(
            san.try_into()
                .map_err(|e: rcgen::Error| SvidError::Issuance(e.to_string()))?,
        )];
        let mut dn = DistinguishedName::new();
        dn.push(DnType::CommonName, cn);
        params.distinguished_name = dn;
        params.is_ca = if profile.is_ca {
            IsCa::Ca(BasicConstraints::Constrained(0))
        } else {
            IsCa::ExplicitNoCa
        };
        params.key_usages = if profile.is_ca {
            vec![
                KeyUsagePurpose::KeyCertSign,
                KeyUsagePurpose::CrlSign,
                KeyUsagePurpose::DigitalSignature,
            ]
        } else {
            vec![
                KeyUsagePurpose::DigitalSignature,
                KeyUsagePurpose::KeyEncipherment,
            ]
        };
        // Client+server auth so the SVID works for mTLS in either role; the
        // verifier asks for `client_auth` (webpki `required_if_present`).
        params.extended_key_usages = if profile.is_ca {
            Vec::new()
        } else {
            vec![
                ExtendedKeyUsagePurpose::ClientAuth,
                ExtendedKeyUsagePurpose::ServerAuth,
            ]
        };
        Ok(params)
    }

    /// A throwaway self-signed placeholder used only to move it out of the way
    /// during `new` (never exposed).
    fn placeholder_cert() -> Result<Certificate, SvidError> {
        let key =
            KeyPair::generate_for(&PKCS_ED25519).map_err(|e| SvidError::Key(e.to_string()))?;
        let params = Self::params(
            "spiffe://tallow/placeholder",
            NODE_DN_CN,
            SvidProfile::NODE_IDENTITY,
            &IssuedSerial::new(1, [0u8; model::SERIAL_SUFFIX_BYTES])?,
            now_unix() - 60,
            now_unix() + 60,
        )?;
        params
            .self_signed(&key)
            .map_err(|e| SvidError::Issuance(e.to_string()))
    }

    /// Test-only: issue a leaf with an arbitrary SAN string (bypassing the
    /// model's canonical-form validation) so the verifier's lookalike matcher
    /// can be exercised against non-canonical URIs.
    #[cfg(test)]
    pub(crate) fn debug_leaf_with_san(
        &mut self,
        san: &str,
        not_before: i64,
        not_after: i64,
    ) -> Result<CertificateDer<'static>, SvidError> {
        let key =
            KeyPair::generate_for(&PKCS_ED25519).map_err(|e| SvidError::Key(e.to_string()))?;
        let serial = self.serials.alloc()?;
        let params = Self::params(
            san,
            san,
            SvidProfile::WORKLOAD_LEAF,
            &serial,
            not_before,
            not_after,
        )?;
        let intermediate = self
            .intermediate
            .as_ref()
            .ok_or(SvidError::NoIntermediate)?;
        let leaf = params
            .signed_by(&key, &intermediate.cert, &intermediate.key)
            .map_err(|e| SvidError::Issuance(e.to_string()))?;
        Ok(leaf.der().clone())
    }
}

/// Raw Ed25519 public key wrapper so rcgen can embed a key we parsed ourselves
/// (SPKI DER from a CSR or from an enrollment record).
struct RawLeafKey {
    raw: Vec<u8>,
}

impl PublicKeyData for RawLeafKey {
    fn der_bytes(&self) -> &[u8] {
        &self.raw
    }
    fn algorithm(&self) -> &'static SignatureAlgorithm {
        &PKCS_ED25519
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::ServiceRegistry;

    fn id(node: &str, svc: &str) -> SpiffeId {
        SpiffeId::new(node, svc).expect("test id")
    }

    fn issuer() -> NodeIssuer {
        NodeIssuer::generate("node-01").expect("issuer")
    }

    fn issuer_with_intermediate() -> NodeIssuer {
        let mut i = issuer();
        i.issue_issuer_intermediate(None).expect("intermediate");
        i
    }

    /// DER length-prefixed TLV.
    fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        let len = value.len();
        if len < 0x80 {
            out.push(len as u8);
        } else if len < 0x100 {
            out.push(0x81);
            out.push(len as u8);
        } else {
            out.push(0x82);
            out.push((len >> 8) as u8);
            out.push((len & 0xff) as u8);
        }
        out.extend_from_slice(value);
        out
    }

    /// Build a real Ed25519 PKCS#10 CSR (rcgen 0.13 has no CSR *generation*
    /// API, and its parser is feature-gated off in this crate).
    fn build_csr(signer: &tallow_crypto::sig::Ed25519Signer) -> Vec<u8> {
        let pk = signer.verifying_key_bytes();
        let spki = tlv(
            0x30,
            &[
                tlv(0x30, &tlv(0x06, der::ED25519_OID)),
                tlv(0x03, &[&[0x00u8][..], &pk[..]].concat()),
            ]
            .concat(),
        );
        let cri = tlv(
            0x30,
            &[
                tlv(0x02, &[0x00]),
                tlv(0x30, &[]),
                spki.clone(),
                tlv(0xa0, &[]),
            ]
            .concat(),
        );
        let sig = signer.sign(&cri);
        tlv(
            0x30,
            &[
                cri,
                tlv(0x30, &tlv(0x06, der::ED25519_OID)),
                tlv(0x03, &[&[0x00u8][..], &sig[..]].concat()),
            ]
            .concat(),
        )
    }

    #[test]
    fn issuance_window_and_band_checks() {
        let mut i = issuer_with_intermediate();
        // default leaf TTL is inside 4-8 h (D1) and the hard band
        let chain = i
            .issue_workload_leaf_from_spki(
                &spki_of(&KeyPair::generate_for(&PKCS_ED25519).unwrap()),
                &id("node-01", "daemon"),
                None,
            )
            .expect("leaf");
        let ttl = chain.leaf.ttl_secs();
        assert!(
            policy::in_workload_default_band(Duration::from_secs(ttl)),
            "ttl {ttl}"
        );
        // explicit 24h ok, 30 min refused, 7d refused
        let spki = spki_of(&KeyPair::generate_for(&PKCS_ED25519).unwrap());
        assert!(i
            .issue_workload_leaf_from_spki(
                &spki,
                &id("node-01", "daemon"),
                Some(Duration::from_secs(policy::WORKLOAD_TTL_MAX_SECS))
            )
            .is_ok());
        assert!(i
            .issue_workload_leaf_from_spki(
                &spki,
                &id("node-01", "daemon"),
                Some(Duration::from_secs(30 * 60))
            )
            .is_err());
        assert!(i
            .issue_workload_leaf_from_spki(
                &spki,
                &id("node-01", "daemon"),
                Some(Duration::from_secs(7 * policy::DAY))
            )
            .is_err());
    }

    fn spki_of(key: &KeyPair) -> Vec<u8> {
        key.public_key_der()
    }

    #[test]
    fn intermediate_ttl_hard_cap_is_seven_days() {
        let mut i = issuer();
        let max = i
            .issue_issuer_intermediate(Some(Duration::from_secs(
                policy::ISSUER_INTERMEDIATE_TTL_MAX_SECS,
            )))
            .expect("7d allowed");
        assert!(max.ttl_secs() <= policy::ISSUER_INTERMEDIATE_TTL_MAX_SECS);
        assert!(i
            .issue_issuer_intermediate(Some(Duration::from_secs(
                policy::ISSUER_INTERMEDIATE_TTL_MAX_SECS + 1
            )))
            .is_err());
        // D1: ≤7d is a hard cap; nothing bigger can even be requested
        assert!(i
            .issue_issuer_intermediate(Some(Duration::from_secs(30 * policy::DAY)))
            .is_err());
        let default = i.issue_issuer_intermediate(None).expect("default");
        assert!(default.ttl_secs() <= policy::ISSUER_INTERMEDIATE_TTL_MAX_SECS);
    }

    #[test]
    fn intermediate_is_ca_with_reserved_san() {
        let mut i = issuer();
        let mid = i.issue_issuer_intermediate(None).expect("intermediate");
        let info = der::parse_cert(mid.cert_der.as_ref()).expect("der");
        assert!(
            info.is_ca,
            "intermediate must carry basicConstraints CA:TRUE"
        );
        assert_eq!(info.san_uris, vec![model::issuer_san("node-01").unwrap()]);
        let _ = model::parse_issuer_san(info.san_uris[0]).expect("reserved issuer SAN");
    }

    #[test]
    fn node_identity_band_and_san() {
        let mut i = issuer();
        let node = i.issue_node_identity(None).expect("node cert");
        assert!(node.ttl_secs() >= policy::NODE_IDENTITY_TTL_MIN_SECS);
        assert!(node.ttl_secs() <= policy::NODE_IDENTITY_TTL_MAX_SECS);
        let info = der::parse_cert(node.cert_der.as_ref()).expect("der");
        assert_eq!(info.san_uris, vec!["spiffe://tallow/node-01"]);
        assert!(!info.is_ca);
        assert!(i
            .issue_node_identity(Some(Duration::from_secs(90 * policy::DAY)))
            .is_ok());
        assert!(i
            .issue_node_identity(Some(Duration::from_secs(policy::DAY)))
            .is_err());
    }

    #[test]
    fn leaf_from_spki_has_exact_san_and_key() {
        let mut i = issuer_with_intermediate();
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let spki = key.public_key_der();
        let chain = i
            .issue_workload_leaf_from_spki(&spki, &id("node-01", "job-worker"), None)
            .expect("chain");
        assert_eq!(chain.chain.len(), 2);
        let leaf_info = der::parse_cert(chain.leaf_der().as_ref()).unwrap();
        assert_eq!(
            leaf_info.san_uris,
            vec!["spiffe://tallow/node-01/svc/job-worker"]
        );
        assert!(!leaf_info.is_ca);
        assert_eq!(leaf_info.spki_raw_key, der::parse_spki(&spki).unwrap());
    }

    #[test]
    fn leaf_from_csr_verifies_key_possession() {
        let mut i = issuer_with_intermediate();
        let signer = tallow_crypto::sig::Ed25519Signer::keygen();
        let csr = build_csr(&signer);
        let chain = i
            .issue_workload_leaf_from_csr(&csr, &id("node-01", "reader"), None)
            .expect("chain");
        let leaf_info = der::parse_cert(chain.leaf_der().as_ref()).unwrap();
        assert_eq!(leaf_info.spki_raw_key, signer.verifying_key_bytes());
        assert_eq!(
            leaf_info.san_uris,
            vec!["spiffe://tallow/node-01/svc/reader"]
        );

        // Tampering with the CSR signature must fail key possession.
        let mut tampered = csr.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 0x01;
        assert!(matches!(
            i.issue_workload_leaf_from_csr(&tampered, &id("node-01", "reader"), None),
            Err(SvidError::Signature(_))
        ));
        // A different key's CSR must not be accepted as the same subject.
        let other = build_csr(&tallow_crypto::sig::Ed25519Signer::keygen());
        let chain2 = i
            .issue_workload_leaf_from_csr(&other, &id("node-01", "reader"), None)
            .expect("other csr");
        let leaf2 = der::parse_cert(chain2.leaf_der().as_ref()).unwrap();
        assert_ne!(leaf2.spki_raw_key, leaf_info.spki_raw_key);
    }

    #[test]
    fn issuance_allowlist_and_node_pinning_enforced() {
        let mut i = issuer_with_intermediate();
        let spki = KeyPair::generate_for(&PKCS_ED25519)
            .unwrap()
            .public_key_der();
        // unregistered service name
        assert!(matches!(
            i.issue_workload_leaf_from_spki(&spki, &id("node-01", "not-registered"), None),
            Err(SvidError::Policy(
                policy::PolicyError::ServiceNotRegistered(_)
            ))
        ));
        // foreign node
        assert!(matches!(
            i.issue_workload_leaf_from_spki(&spki, &id("node-02", "daemon"), None),
            Err(SvidError::Policy(
                policy::PolicyError::NodePinMismatch { .. }
            ))
        ));
        // reserved infra name is not a workload identity
        let reserved = SpiffeId::new("node-01", model::ISSUER_SERVICE_NAME).expect("parse ok");
        assert!(matches!(
            i.issue_workload_leaf_from_spki(&spki, &reserved, None),
            Err(SvidError::Policy(
                policy::PolicyError::ServiceNotRegistered(_)
            ))
        ));
        // explicit registry override
        let mut reg = ServiceRegistry::empty();
        reg.register("custom-svc").unwrap();
        i.set_registry(reg);
        assert!(i
            .issue_workload_leaf_from_spki(&spki, &id("node-01", "custom-svc"), None)
            .is_ok());
        assert!(i
            .issue_workload_leaf_from_spki(&spki, &id("node-01", "daemon"), None)
            .is_err());
    }

    #[test]
    fn leaf_requires_an_intermediate() {
        let mut i = issuer();
        let spki = KeyPair::generate_for(&PKCS_ED25519)
            .unwrap()
            .public_key_der();
        assert!(matches!(
            i.issue_workload_leaf_from_spki(&spki, &id("node-01", "daemon"), None),
            Err(SvidError::NoIntermediate)
        ));
    }

    #[test]
    fn serials_are_monotonic_and_der_round_trip() {
        let mut i = issuer_with_intermediate();
        let spki = KeyPair::generate_for(&PKCS_ED25519)
            .unwrap()
            .public_key_der();
        let a = i
            .issue_workload_leaf_from_spki(&spki, &id("node-01", "daemon"), None)
            .unwrap();
        let b = i
            .issue_workload_leaf_from_spki(&spki, &id("node-01", "daemon"), None)
            .unwrap();
        assert!(b.leaf.serial.is_later_than(&a.leaf.serial));
        assert_eq!(i.serial_high_water(), b.leaf.serial.counter());
        // The DER serial is the allocator's 16-byte value (minimally encoded).
        let info = der::parse_cert(b.leaf_der().as_ref()).unwrap();
        let mut der_serial = info.serial_der.to_vec();
        if der_serial.first() == Some(&0x00) {
            der_serial.remove(0);
        }
        let mut padded = vec![0u8; model::SERIAL_BYTES - der_serial.len()];
        padded.extend_from_slice(&der_serial);
        assert_eq!(padded, b.leaf.serial.as_bytes().to_vec());
    }

    #[test]
    fn non_ed25519_subject_keys_are_refused() {
        let mut i = issuer_with_intermediate();
        let ecdsa = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let spki = ecdsa.public_key_der();
        assert!(matches!(
            i.issue_workload_leaf_from_spki(&spki, &id("node-01", "daemon"), None),
            Err(SvidError::Der(_))
        ));
        // ...and a malformed CSR
        assert!(matches!(
            i.issue_workload_leaf_from_csr(b"not a csr", &id("node-01", "daemon"), None),
            Err(SvidError::Der(_))
        ));
    }

    #[test]
    fn explicit_window_issuance_allows_replay_windows() {
        let mut i = issuer_with_intermediate();
        let spki = KeyPair::generate_for(&PKCS_ED25519)
            .unwrap()
            .public_key_der();
        let nb = now_unix() - 7200;
        let na = nb + policy::WORKLOAD_DEFAULT_TTL_SECS as i64;
        let chain = i
            .issue_workload_leaf_window(
                LeafSubject::SpkiDer(&spki),
                &id("node-01", "daemon"),
                nb,
                na,
            )
            .expect("explicit window");
        assert_eq!(chain.leaf.not_before, nb);
        // A window longer than the band is still refused.
        assert!(i
            .issue_workload_leaf_window(
                LeafSubject::SpkiDer(&spki),
                &id("node-01", "daemon"),
                nb,
                nb + 30 * policy::DAY as i64
            )
            .is_err());
    }

    #[test]
    fn from_pkcs8_matches_generated_key() {
        let key = KeyPair::generate_for(&PKCS_ED25519).unwrap();
        let pkcs8 = key.serialize_der();
        let mut a = NodeIssuer::from_pkcs8("node-01", &pkcs8).expect("from pkcs8");
        let mut b = NodeIssuer::new(key, "node-01").expect("new");
        assert_eq!(a.node_public_spki(), b.node_public_spki());
        a.issue_issuer_intermediate(None).unwrap();
        b.issue_issuer_intermediate(None).unwrap();
        assert_ne!(
            a.intermediate_cert_der().unwrap(),
            b.intermediate_cert_der().unwrap(),
            "fresh intermediate keys per issuance"
        );
    }
}

#[cfg(test)]
impl NodeIssuer {
    /// Test helper: node public key SPKI DER.
    fn node_public_spki(&self) -> Vec<u8> {
        self.node_key.public_key_der()
    }
}
