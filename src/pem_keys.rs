//! ML-KEM key serialization: the real DER structures, so a PEM round-trip preserves the
//! algorithm (stub register row #91).
//!
//! The gap this closes: `KeyPair.generate` produces an ML-KEM-768 key pair, but `to_pem` wrapped
//! whatever text it was given in `-----BEGIN PUBLIC KEY-----` armour and `from_pem` decided the
//! algorithm by **substring-matching the PEM text**. Neither end touched the key material, so
//! `generate → to_pem → from_pem` reported `algo = "unknown"` for a key the engine had just
//! generated — the algorithm could not survive its own serialization.
//!
//! What is actually specified (and therefore what is implemented here, not approximated):
//!
//! - **FIPS 203** fixes the byte lengths: ML-KEM-512/768/1024 encapsulation keys are 800 / 1184 /
//!   1568 bytes, decapsulation keys 1632 / 2400 / 3168.
//! - **RFC 5958** `OneAsymmetricKey` for the private side:
//!   `SEQUENCE { INTEGER version, AlgorithmIdentifier { OID }, OCTET STRING privateKey }`.
//!   The `privateKey` OCTET STRING carries the **expanded** decapsulation key when no seed is
//!   present, which is the form FIPS 203 §7.1 defines and the form this engine holds.
//! - **draft-ietf-lamps-kyber-certificates** for the public side: `SubjectPublicKeyInfo` whose
//!   `AlgorithmIdentifier` is the bare OID (`2.16.840.1.101.3.4.4.1|2|3` — parameters absent,
//!   since the OID pins the parameter set) and whose `subjectPublicKey` is a `BIT STRING` over
//!   the encapsulation key.
//!
//! The `derived_public` on a parsed private key is computed by **re-deriving it from the
//! decapsulation key** (`DecapsulationKey::encapsulation_key`), not by copying bytes that
//! happened to be nearby. That is what makes the round-trip evidence rather than echo.

use base64::Engine as _;

/// The three FIPS 203 parameter sets this engine can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlKem {
    K512,
    K768,
    K1024,
}

impl MlKem {
    /// The name the `.tl` surface reports in `KeyPair.algo`.
    pub fn name(self) -> &'static str {
        match self {
            MlKem::K512 => "ml-kem-512",
            MlKem::K768 => "ml-kem-768",
            MlKem::K1024 => "ml-kem-1024",
        }
    }

    /// OID content octets for `id-alg-ml-kem-{512,768,1024}` = 2.16.840.1.101.3.4.4.{1,2,3}.
    ///
    /// Encoding, for the record: 2.16 → `0x60`; 840 → `0x86 0x48`; then 1, 101 (0x65), 3, 4, 4
    /// and the set index as single octets.
    fn oid_content(self) -> &'static [u8] {
        match self {
            MlKem::K512 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x01],
            MlKem::K768 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x02],
            MlKem::K1024 => &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x04, 0x03],
        }
    }

    pub fn from_oid_content(oid: &[u8]) -> Option<MlKem> {
        [MlKem::K512, MlKem::K768, MlKem::K1024]
            .into_iter()
            .find(|v| v.oid_content() == oid)
    }

    /// Encapsulation-key length in bytes (FIPS 203 §7.1).
    pub fn ek_len(self) -> usize {
        match self {
            MlKem::K512 => 800,
            MlKem::K768 => 1184,
            MlKem::K1024 => 1568,
        }
    }

    /// Expanded decapsulation-key length in bytes (FIPS 203 §7.1).
    pub fn dk_len(self) -> usize {
        match self {
            MlKem::K512 => 1632,
            MlKem::K768 => 2400,
            MlKem::K1024 => 3168,
        }
    }

    /// Parameter set whose encapsulation key is this long. Unique across the three sets, which is
    /// what lets `to_pem` label a bare `Value::Bytes` correctly without extra type information.
    pub fn from_ek_len(len: usize) -> Option<MlKem> {
        [MlKem::K512, MlKem::K768, MlKem::K1024]
            .into_iter()
            .find(|v| v.ek_len() == len)
    }

    /// Parameter set whose expanded decapsulation key is this long.
    pub fn from_dk_len(len: usize) -> Option<MlKem> {
        [MlKem::K512, MlKem::K768, MlKem::K1024]
            .into_iter()
            .find(|v| v.dk_len() == len)
    }

    /// Re-derive the encapsulation key from an expanded decapsulation key.
    ///
    /// This is the real key-derivation step of FIPS 203 (`DecapsulationKey::encapsulation_key`),
    /// so a parsed private key yields the same public key that generation would have produced.
    /// The length is checked *before* any key type is constructed, so a caller handing over bytes
    /// of the wrong length gets `None` rather than a panic inside the crate's array conversion.
    pub fn derive_public(self, dk: &[u8]) -> Option<Vec<u8>> {
        use ml_kem::kem::DecapsulationKey;
        use ml_kem::{EncodedSizeUser, MlKem1024Params, MlKem512Params, MlKem768Params};

        if dk.len() != self.dk_len() {
            return None;
        }
        match self {
            MlKem::K512 => {
                #[allow(deprecated)]
                let encoded = ml_kem::array::Array::clone_from_slice(dk);
                let key =
                    <DecapsulationKey<MlKem512Params> as EncodedSizeUser>::from_bytes(&encoded);
                Some(EncodedSizeUser::as_bytes(key.encapsulation_key()).to_vec())
            }
            MlKem::K768 => {
                #[allow(deprecated)]
                let encoded = ml_kem::array::Array::clone_from_slice(dk);
                let key =
                    <DecapsulationKey<MlKem768Params> as EncodedSizeUser>::from_bytes(&encoded);
                Some(EncodedSizeUser::as_bytes(key.encapsulation_key()).to_vec())
            }
            MlKem::K1024 => {
                #[allow(deprecated)]
                let encoded = ml_kem::array::Array::clone_from_slice(dk);
                let key =
                    <DecapsulationKey<MlKem1024Params> as EncodedSizeUser>::from_bytes(&encoded);
                Some(EncodedSizeUser::as_bytes(key.encapsulation_key()).to_vec())
            }
        }
    }
}

/// A key recovered from a real DER structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMlKemKey {
    pub variant: MlKem,
    /// True for `PrivateKeyInfo` (RFC 5958), false for `SubjectPublicKeyInfo`.
    pub private: bool,
    /// The key bytes exactly as they appeared inside the OCTET STRING / BIT STRING.
    pub key: Vec<u8>,
    /// For a private key: the encapsulation key re-derived from `key`. `None` for a public key
    /// (its own bytes are the encapsulation key) and for a 64-byte seed body, which cannot be
    /// expanded through ml-kem 0.2's public API.
    pub derived_public: Option<Vec<u8>>,
}

/// Whether a private-key body is the expanded key or a 64-byte seed (FIPS 203 §7.1 vs §7.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrivateBody {
    Expanded,
    Seed,
}

impl ParsedMlKemKey {
    pub fn private_body(&self) -> Option<PrivateBody> {
        if !self.private {
            return None;
        }
        Some(if self.key.len() == self.variant.dk_len() {
            PrivateBody::Expanded
        } else {
            PrivateBody::Seed
        })
    }
}

// ---------------------------------------------------------------------------
// DER writer
// ---------------------------------------------------------------------------

/// DER length octets: short form below 128, else minimal-length long form.
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        return vec![n as u8];
    }
    let mut be = Vec::new();
    let mut v = n;
    while v > 0 {
        be.push((v & 0xff) as u8);
        v >>= 8;
    }
    be.reverse();
    let mut out = vec![0x80 | be.len() as u8];
    out.extend(be);
    out
}

/// One tag-length-value triple.
fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// `SubjectPublicKeyInfo` for an ML-KEM encapsulation key.
pub fn spki_der(variant: MlKem, ek: &[u8]) -> Vec<u8> {
    debug_assert_eq!(ek.len(), variant.ek_len());
    let algorithm = tlv(0x30, &tlv(0x06, variant.oid_content()));
    let mut bits = Vec::with_capacity(ek.len() + 1);
    bits.push(0x00); // unused-bit count: none
    bits.extend_from_slice(ek);
    let mut body = algorithm;
    body.extend(tlv(0x03, &bits));
    tlv(0x30, &body)
}

/// `PrivateKeyInfo` (RFC 5958) for an expanded ML-KEM decapsulation key.
pub fn pkcs8_der(variant: MlKem, dk: &[u8]) -> Vec<u8> {
    debug_assert_eq!(dk.len(), variant.dk_len());
    let mut body = tlv(0x02, &[0x00]); // version 0
    body.extend(tlv(0x30, &tlv(0x06, variant.oid_content())));
    body.extend(tlv(0x04, dk));
    tlv(0x30, &body)
}

// ---------------------------------------------------------------------------
// DER reader
// ---------------------------------------------------------------------------

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID: u8 = 0x06;
const TAG_SEQUENCE: u8 = 0x30;
const TAG_CONTEXT_0: u8 = 0xa0;
const TAG_CONTEXT_1: u8 = 0xa1;

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    fn byte(&mut self) -> Option<u8> {
        let b = *self.buf.get(self.pos)?;
        self.pos += 1;
        Some(b)
    }

    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let slice = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(slice)
    }

    fn at_end(&self) -> bool {
        self.pos == self.buf.len()
    }

    /// Read one TLV. Rejects indefinite lengths and non-minimal long-form lengths, so a
    /// re-encoded structure is byte-identical to what a strict DER writer would emit.
    fn tlv(&mut self) -> Option<(u8, &'a [u8])> {
        let tag = self.byte()?;
        let first = self.byte()?;
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return None; // indefinite (0x80) or absurd
            }
            let mut v = 0usize;
            for _ in 0..n {
                v = (v << 8) | self.byte()? as usize;
            }
            if v < 0x80 {
                return None; // would have fit in the short form
            }
            v
        };
        let content = self.take(len)?;
        Some((tag, content))
    }

    /// An `AlgorithmIdentifier` whose algorithm is one of the ML-KEM OIDs. Parameter fields are
    /// accepted either absent (the draft's encoding) or explicit NULL (as some encoders emit);
    /// any other parameter value is rejected rather than ignored.
    fn ml_kem_algorithm(&mut self) -> Option<MlKem> {
        let (tag, content) = self.tlv()?;
        if tag != TAG_SEQUENCE {
            return None;
        }
        let mut inner = Cursor::new(content);
        let (oid_tag, oid) = inner.tlv()?;
        if oid_tag != TAG_OID {
            return None;
        }
        let variant = MlKem::from_oid_content(oid)?;
        if !inner.at_end() {
            let (param_tag, param) = inner.tlv()?;
            if param_tag != TAG_NULL || !param.is_empty() || !inner.at_end() {
                return None;
            }
        }
        Some(variant)
    }
}

/// Parse a `SubjectPublicKeyInfo` or `PrivateKeyInfo` for ML-KEM.
///
/// Returns `None` for anything that is not exactly one of those two structures holding exactly
/// one of the three ML-KEM parameter sets with a key of the length that set requires.
pub fn parse_ml_kem_der(der: &[u8]) -> Option<ParsedMlKemKey> {
    let mut outer = Cursor::new(der);
    let (tag, body) = outer.tlv()?;
    if tag != TAG_SEQUENCE || !outer.at_end() {
        return None; // not a single top-level SEQUENCE
    }
    // The two structures differ at their second element (AlgorithmIdentifier for both, but a
    // BIT STRING vs an OCTET STRING after it), and a PKCS#8 body's first element is an INTEGER,
    // so the two attempts cannot be confused for one another.
    parse_spki_body(body).or_else(|| parse_pkcs8_body(body))
}

fn parse_spki_body(body: &[u8]) -> Option<ParsedMlKemKey> {
    let mut cursor = Cursor::new(body);
    let variant = cursor.ml_kem_algorithm()?;
    let (bits_tag, bits) = cursor.tlv()?;
    if bits_tag != TAG_BIT_STRING || !cursor.at_end() || bits.is_empty() {
        return None;
    }
    if bits[0] != 0x00 {
        return None; // a BIT STRING with unused bits set is not a key encoding
    }
    let key = &bits[1..];
    if key.len() != variant.ek_len() {
        return None;
    }
    Some(ParsedMlKemKey {
        variant,
        private: false,
        key: key.to_vec(),
        derived_public: None,
    })
}

fn parse_pkcs8_body(body: &[u8]) -> Option<ParsedMlKemKey> {
    let mut cursor = Cursor::new(body);
    let (version_tag, version) = cursor.tlv()?;
    if version_tag != TAG_INTEGER || version != [0x00] {
        return None; // only v0 (no public key, no attributes) is what this engine writes
    }
    let variant = cursor.ml_kem_algorithm()?;
    let (octets_tag, key) = cursor.tlv()?;
    if octets_tag != TAG_OCTET_STRING {
        return None;
    }
    // Optional trailing fields: [0] attributes, [1] public key. Accept and stop, but only
    // trailing context tags — anything else means this is not the structure we think it is.
    while !cursor.at_end() {
        let (tag, _) = cursor.tlv()?;
        if tag != TAG_CONTEXT_0 && tag != TAG_CONTEXT_1 {
            return None;
        }
    }
    let private = key.len() == variant.dk_len() || key.len() == 64;
    if !private {
        return None;
    }
    let derived_public = if key.len() == variant.dk_len() {
        variant.derive_public(key)
    } else {
        None // 64-byte seed: FIPS 203 §7.2 expansion is not reachable through ml-kem 0.2
    };
    Some(ParsedMlKemKey {
        variant,
        private: true,
        key: key.to_vec(),
        derived_public,
    })
}

fn body_like(body: &[u8]) -> Cursor<'_> {
    Cursor::new(body)
}

// ---------------------------------------------------------------------------
// PEM armour
// ---------------------------------------------------------------------------

/// Wrap DER bytes in PEM at 64 columns, the width RFC 7468 specifies.
pub fn to_pem(label: &str, der: &[u8]) -> String {
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or(""));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

pub fn spki_pem(variant: MlKem, ek: &[u8]) -> String {
    to_pem("PUBLIC KEY", &spki_der(variant, ek))
}

pub fn pkcs8_pem(variant: MlKem, dk: &[u8]) -> String {
    to_pem("PRIVATE KEY", &pkcs8_der(variant, dk))
}

/// Strip PEM armour and base64-decode the body. Returns `(label, der)`.
pub fn parse_pem(text: &str) -> Option<(String, Vec<u8>)> {
    let begin = text.find("-----BEGIN ")?;
    let label_start = begin + "-----BEGIN ".len();
    let label_end = text[label_start..].find("-----")? + label_start;
    let label = text[label_start..label_end].trim().to_string();
    let body_start = text[label_end..].find('\n')? + label_end;
    let end_marker = format!("-----END {label}-----");
    let body_end = text[body_start..].find(&end_marker)? + body_start;
    let body: String = text[body_start..body_end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if body.is_empty() {
        return None;
    }
    let der = base64::engine::general_purpose::STANDARD.decode(body).ok()?;
    Some((label, der))
}

/// Parse a PEM carrying an ML-KEM public or private key.
pub fn parse_ml_kem_pem(text: &str) -> Option<ParsedMlKemKey> {
    let (_label, der) = parse_pem(text)?;
    parse_ml_kem_der(&der)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generated(variant: MlKem) -> (Vec<u8>, Vec<u8>) {
        use ml_kem::KemCore;
        use ml_kem::{EncodedSizeUser, MlKem1024, MlKem512, MlKem768};
        match variant {
            MlKem::K512 => {
                let (dk, ek) = MlKem512::generate(&mut rand_core_06::OsRng);
                (
                    EncodedSizeUser::as_bytes(&dk).to_vec(),
                    EncodedSizeUser::as_bytes(&ek).to_vec(),
                )
            }
            MlKem::K768 => {
                let (dk, ek) = MlKem768::generate(&mut rand_core_06::OsRng);
                (
                    EncodedSizeUser::as_bytes(&dk).to_vec(),
                    EncodedSizeUser::as_bytes(&ek).to_vec(),
                )
            }
            MlKem::K1024 => {
                let (dk, ek) = MlKem1024::generate(&mut rand_core_06::OsRng);
                (
                    EncodedSizeUser::as_bytes(&dk).to_vec(),
                    EncodedSizeUser::as_bytes(&ek).to_vec(),
                )
            }
        }
    }

    #[test]
    fn the_parameter_sets_have_the_fips_203_lengths() {
        assert_eq!((MlKem::K512.ek_len(), MlKem::K512.dk_len()), (800, 1632));
        assert_eq!((MlKem::K768.ek_len(), MlKem::K768.dk_len()), (1184, 2400));
        assert_eq!((MlKem::K1024.ek_len(), MlKem::K1024.dk_len()), (1568, 3168));
        // The round-trip dispatch depends on these being unique.
        for v in [MlKem::K512, MlKem::K768, MlKem::K1024] {
            assert_eq!(MlKem::from_ek_len(v.ek_len()), Some(v));
            assert_eq!(MlKem::from_dk_len(v.dk_len()), Some(v));
        }
        assert_eq!(MlKem::from_ek_len(1184 + 1), None);
        assert_eq!(MlKem::from_dk_len(0), None);
    }

    #[test]
    fn every_parameter_set_round_trips_through_spki() {
        for variant in [MlKem::K512, MlKem::K768, MlKem::K1024] {
            let (_dk, ek) = generated(variant);
            let der = spki_der(variant, &ek);
            let parsed = parse_ml_kem_der(&der).expect("SPKI must parse");
            assert_eq!(parsed.variant, variant);
            assert!(!parsed.private);
            assert_eq!(parsed.key, ek, "the encapsulation key must survive verbatim");
            // The structure is what the draft says it is: SEQUENCE { SEQUENCE { OID }, BIT STRING }.
            assert_eq!(der[0], TAG_SEQUENCE);
            let mut expected_alg = vec![0x06, 0x09];
            expected_alg.extend_from_slice(variant.oid_content());
            assert!(
                der.windows(expected_alg.len()).any(|w| w == expected_alg.as_slice()),
                "the parameter set's OID must appear in the AlgorithmIdentifier"
            );
        }
    }

    #[test]
    fn a_parsed_private_key_re_derives_the_public_key_it_was_generated_with() {
        // The strongest form of the round-trip claim: the public key recovered from the parsed
        // PKCS#8 is the one the generator produced, not bytes copied out of the same document.
        let (dk, ek) = generated(MlKem::K768);
        let parsed = parse_ml_kem_der(&pkcs8_der(MlKem::K768, &dk)).expect("PKCS#8 must parse");
        assert!(parsed.private);
        assert_eq!(parsed.key, dk);
        assert_eq!(parsed.private_body(), Some(PrivateBody::Expanded));
        assert_eq!(
            parsed.derived_public.as_deref(),
            Some(ek.as_slice()),
            "re-derived encapsulation key must equal the generated one"
        );
    }

    #[test]
    fn pem_armour_round_trips_and_is_wrapped_at_64_columns() {
        let (_dk, ek) = generated(MlKem::K768);
        let pem = spki_pem(MlKem::K768, &ek);
        let (label, der) = parse_pem(&pem).expect("armour must parse");
        assert_eq!(label, "PUBLIC KEY");
        assert_eq!(der, spki_der(MlKem::K768, &ek));
        for line in pem.lines().skip(1).take_while(|l| !l.starts_with("-----END")) {
            assert!(line.len() <= 64, "PEM body line longer than 64 columns: {line:?}");
        }
        assert!(pem.ends_with("-----END PUBLIC KEY-----\n"));
        let parsed = parse_ml_kem_pem(&pem).expect("ML-KEM PEM must parse");
        assert_eq!(parsed.variant, MlKem::K768);
        assert_eq!(parsed.key, ek);
    }

    #[test]
    fn a_private_pem_reports_the_algorithm_the_generator_used() {
        // The exact trip stub #91 recorded as impossible: generate → to_pem → from_pem.
        let (dk, ek) = generated(MlKem::K768);
        let pem = pkcs8_pem(MlKem::K768, &dk);
        let parsed = parse_ml_kem_pem(&pem).expect("private PEM must parse");
        assert_eq!(parsed.variant.name(), "ml-kem-768");
        assert_eq!(parsed.derived_public.as_deref(), Some(ek.as_slice()));
    }

    #[test]
    fn non_ml_kem_and_malformed_input_is_rejected() {
        // An RSA SPKI (OID 1.2.840.113549.1.1.1 with NULL parameters) must not be read as ML-KEM.
        let rsa_alg = tlv(0x30, &{
            let mut v = tlv(0x06, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
            v.extend(tlv(0x05, &[]));
            v
        });
        let mut bits = vec![0x00];
        bits.extend_from_slice(&[0u8; 32]);
        let mut body = rsa_alg;
        body.extend(tlv(0x03, &bits));
        assert_eq!(parse_ml_kem_der(&tlv(0x30, &body)), None);

        // Truncated DER: every prefix of a valid structure must fail, never panic.
        let (_dk, ek) = generated(MlKem::K512);
        let good = spki_der(MlKem::K512, &ek);
        for cut in 0..good.len() {
            assert!(
                parse_ml_kem_der(&good[..cut]).is_none(),
                "prefix of length {cut} must not parse"
            );
        }

        // Right OID, wrong key length.
        let short = spki_der(MlKem::K512, &ek);
        let mut tampered = short.clone();
        let n = tampered.len();
        tampered.truncate(n - 1);
        assert_eq!(parse_ml_kem_der(&tampered), None);

        // non-minimal length encoding (0x81 0x05 instead of 0x05) must be rejected.
        let minimal = pkcs8_der(MlKem::K512, &[0x11u8; 1632]);
        let mut non_minimal = Vec::new();
        non_minimal.push(TAG_SEQUENCE);
        non_minimal.push(0x81); // long form for a length that fits the short form
        let content_len = minimal.len() - 2;
        non_minimal.push(content_len as u8);
        non_minimal.extend_from_slice(&minimal[2..]);
        assert_eq!(parse_ml_kem_der(&non_minimal), None);
    }

    #[test]
    fn a_seed_form_private_key_is_named_but_not_expanded() {
        // FIPS 203 §7.2: a 64-byte seed body. We name the algorithm (that is the round-trip
        // requirement) and refuse to invent a public key we cannot derive.
        let body = pkcs8_der(MlKem::K768, &[0u8; 2400]);
        assert!(parse_ml_kem_der(&body).is_some());
        let mut seed_body = tlv(0x02, &[0x00]);
        seed_body.extend(tlv(0x30, &tlv(0x06, MlKem::K768.oid_content())));
        seed_body.extend(tlv(0x04, &[0x42u8; 64]));
        let parsed = parse_ml_kem_der(&tlv(0x30, &seed_body)).expect("seed form must parse");
        assert_eq!(parsed.variant, MlKem::K768);
        assert_eq!(parsed.private_body(), Some(PrivateBody::Seed));
        assert_eq!(parsed.derived_public, None);
    }

    #[test]
    fn a_derive_public_call_is_length_checked() {
        // derive_public must not be handed bytes of the wrong length by a future caller.
        assert_eq!(MlKem::K768.derive_public(&[0u8; 64]), None);
    }
}
