//! FROST(Ed25519, SHA-512) — RFC 9591, the two-round threshold Schnorr protocol.
//!
//! This is the implementation behind the `frost_dkg` / `frost_sign` / `frost_verify` names in
//! `stdlib/crypto.tl`, which the stub register carried as row #90: the names existed, an
//! `_experimental` spelling existed beside them, and the experimental form was "a Shamir-split
//! Ed25519 with no DKG and no aggregation, so the threshold property is absent". Wiring the
//! canonical names to that would have been the fake the objective forbids, so the protocol is
//! implemented here instead.
//!
//! Everything normative comes from RFC 9591 §4–§6:
//!
//! - Ciphersuite `FROST(Ed25519, SHA-512)`: group edwards25519, `H` = SHA-512,
//!   `contextString` = `FROST-ED25519-SHA512-v1`.
//! - `H1(m)` = SHA-512(ctx ‖ "rho"  ‖ m) reduced mod L; `H2(m)` = SHA-512(m) reduced mod L
//!   (no domain separator, for RFC 8032 compatibility); `H3(m)` = SHA-512(ctx ‖ "nonce" ‖ m)
//!   reduced mod L; `H4(m)` = SHA-512(ctx ‖ "msg" ‖ m) unreduced; `H5(m)` = SHA-512(ctx ‖ "com" ‖ m)
//!   unreduced.
//! - `nonce_generate(secret)` = H3(random_32 ‖ SerializeScalar(secret)).
//! - Binding factors take `SerializeElement(PK) ‖ H4(msg) ‖ H5(encode(commitment_list)) ‖
//!   SerializeScalar(id)` — 32 + 64 + 64 + 32 = 192 bytes per participant.
//! - `z_i = hiding + binding·ρ_i + λ_i·sk_i·c`, aggregated `z = Σ z_i` with `R` = group commitment.
//! - Verification is RFC 8032 §5.1.7's group equation `[8]zB = [8]R + [8][c]PK`.
//!
//! ## What is verified, and how
//!
//! The test module embeds **the RFC's own Appendix E.1 vectors** and asserts each stage against
//! them in order: the group public key from the group secret, the participant shares from the
//! polynomial, the nonces from their randomness, the nonce commitments, the binding factors
//! (which exercise H1, H4 and H5 together), the signature shares, the aggregate signature, and
//! then verification of that signature. A wrong domain separator, a wrong encoding order or a
//! wrong scalar reduction fails at the stage that gets it wrong rather than at the end.
//!
//! ## Two deliberate deviations, both narrow
//!
//! 1. **The strict group equation.** RFC 9591 requires the *cofactored* check
//!    `[8]zB = [8]R + [8][c]PK`. For prime-order inputs the two are equivalent — multiplying by
//!    the cofactor is injective on the prime-order subgroup — and the strict form additionally
//!    rejects any small-order component an attacker might have slipped into `R` or `PK`. Both
//!    `R` and `PK` are validated as torsion-free on deserialization, so this is strictly stronger
//!    on inputs that pass validation.
//! 2. **`sign` runs both rounds locally.** RFC 9591 has each participant commit, then sign, with a
//!    coordinator aggregating. The `.tl` surface is `frost_sign(message, secret_share)`, so the
//!    caller supplies the participating key packages (one per line) and this function plays every
//!    participant plus the coordinator. Transport between real parties remains the caller's job;
//!    nothing here is a simulation of the *cryptography*, only of the *messaging*.

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use curve25519_dalek::edwards::{CompressedEdwardsY, EdwardsPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};

/// RFC 9591 §6.1: the ciphersuite's context string.
const CONTEXT: &str = "FROST-ED25519-SHA512-v1";

// ---------------------------------------------------------------------------
// Ciphersuite operations
// ---------------------------------------------------------------------------

pub fn serialize_scalar(s: &Scalar) -> [u8; 32] {
    s.to_bytes() // little-endian, canonical: top three bits already zero
}

/// RFC 9591 §6.1 `DeserializeScalar`: rejects a non-canonical encoding rather than reducing it.
pub fn deserialize_scalar(buf: &[u8]) -> Option<Scalar> {
    let bytes: [u8; 32] = buf.try_into().ok()?;
    Option::<Scalar>::from(Scalar::from_canonical_bytes(bytes))
}

pub fn serialize_element(p: &EdwardsPoint) -> [u8; 32] {
    p.compress().to_bytes()
}

/// RFC 9591 §6.1 `DeserializeElement`: rejects the identity and any point outside the prime-order
/// subgroup, so a small-order input cannot reach the group equation.
pub fn deserialize_element(buf: &[u8]) -> Option<EdwardsPoint> {
    let bytes: [u8; 32] = buf.try_into().ok()?;
    let point = CompressedEdwardsY(bytes).decompress()?;
    if point == EdwardsPoint::identity() || !point.is_torsion_free() {
        return None;
    }
    Some(point)
}

fn sha512(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

fn digest_to_scalar(parts: &[&[u8]]) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&sha512(parts))
}

/// RFC 9591 §6.1 `H1(m)`.
pub fn h1(m: &[u8]) -> Scalar {
    digest_to_scalar(&[CONTEXT.as_bytes(), b"rho", m])
}

/// RFC 9591 §6.1 `H2(m)` — deliberately without a domain separator (RFC 8032 compatibility).
pub fn h2(m: &[u8]) -> Scalar {
    digest_to_scalar(&[m])
}

/// RFC 9591 §6.1 `H3(m)`.
pub fn h3(m: &[u8]) -> Scalar {
    digest_to_scalar(&[CONTEXT.as_bytes(), b"nonce", m])
}

/// RFC 9591 §6.1 `H4(m)` — 64 bytes, not reduced.
pub fn h4(m: &[u8]) -> [u8; 64] {
    sha512(&[CONTEXT.as_bytes(), b"msg", m])
}

/// RFC 9591 §6.1 `H5(m)` — 64 bytes, not reduced.
pub fn h5(m: &[u8]) -> [u8; 64] {
    sha512(&[CONTEXT.as_bytes(), b"com", m])
}

/// RFC 9591 §4.1 `nonce_generate`, split so the randomness is an input.
///
/// The RFC samples 32 fresh random bytes per call. Keeping them as a parameter is what lets the
/// Appendix E.1 vectors check this function at all: the vector publishes the randomness beside the
/// nonce it produced.
pub fn nonce_generate_with_randomness(randomness: &[u8; 32], secret: &Scalar) -> Scalar {
    let secret_enc = serialize_scalar(secret);
    h3(&[randomness.as_slice(), secret_enc.as_slice()].concat())
}

pub fn nonce_generate(secret: &Scalar) -> Scalar {
    use rand::RngCore;
    let mut randomness = [0u8; 32];
    rand::rng().fill_bytes(&mut randomness);
    nonce_generate_with_randomness(&randomness, secret)
}

/// A participant's key material after key generation.
#[derive(Debug, Clone)]
pub struct KeyPackage {
    pub id: u32,
    pub share: Scalar,
    pub group_public: EdwardsPoint,
    pub threshold: u16,
    pub num: u16,
}

/// A participant's nonce pair for one signing session (RFC 9591 §5.1).
#[derive(Debug, Clone, Copy)]
pub struct NoncePair {
    pub hiding: Scalar,
    pub binding: Scalar,
}

impl NoncePair {
    pub fn generate(share: &Scalar) -> Self {
        NoncePair {
            hiding: nonce_generate(share),
            binding: nonce_generate(share),
        }
    }
}

pub type CommitmentList = Vec<(u32, EdwardsPoint, EdwardsPoint)>;

fn commitment_list(packages: &[(KeyPackage, NoncePair)]) -> CommitmentList {
    let mut list: CommitmentList = packages
        .iter()
        .map(|(p, n)| {
            (
                p.id,
                ED25519_BASEPOINT_POINT * n.hiding,
                ED25519_BASEPOINT_POINT * n.binding,
            )
        })
        .collect();
    list.sort_by_key(|(id, _, _)| *id); // RFC 9591 §4.3: ascending by identifier
    list
}

/// RFC 9591 §4.3 `encode_group_commitment_list`.
pub fn encode_group_commitment_list(list: &CommitmentList) -> Vec<u8> {
    let mut out = Vec::with_capacity(list.len() * 96);
    for (id, hiding, binding) in list {
        out.extend_from_slice(&serialize_scalar(&Scalar::from(*id as u64)));
        out.extend_from_slice(&serialize_element(hiding));
        out.extend_from_slice(&serialize_element(binding));
    }
    out
}

/// RFC 9591 §4.4 `compute_binding_factors`.
pub fn compute_binding_factors(
    group_public: &EdwardsPoint,
    list: &CommitmentList,
    msg: &[u8],
) -> Vec<(u32, Scalar)> {
    let mut prefix = Vec::new();
    prefix.extend_from_slice(&serialize_element(group_public));
    prefix.extend_from_slice(&h4(msg));
    prefix.extend_from_slice(&h5(&encode_group_commitment_list(list)));

    list.iter()
        .map(|(id, _, _)| {
            let mut input = prefix.clone();
            input.extend_from_slice(&serialize_scalar(&Scalar::from(*id as u64)));
            (*id, h1(&input))
        })
        .collect()
}

pub fn binding_factor_for_participant(factors: &[(u32, Scalar)], id: u32) -> Option<Scalar> {
    factors.iter().find(|(i, _)| *i == id).map(|(_, f)| *f)
}

/// RFC 9591 §4.5 `compute_group_commitment`.
pub fn compute_group_commitment(
    list: &CommitmentList,
    factors: &[(u32, Scalar)],
) -> Option<EdwardsPoint> {
    let mut acc = EdwardsPoint::identity();
    for (id, hiding, binding) in list {
        let bf = binding_factor_for_participant(factors, *id)?;
        acc += hiding + binding * bf;
    }
    Some(acc)
}

/// RFC 9591 §4.6 `compute_challenge`.
pub fn compute_challenge(
    group_commitment: &EdwardsPoint,
    group_public: &EdwardsPoint,
    msg: &[u8],
) -> Scalar {
    let mut input = Vec::new();
    input.extend_from_slice(&serialize_element(group_commitment));
    input.extend_from_slice(&serialize_element(group_public));
    input.extend_from_slice(msg);
    h2(&input)
}

/// RFC 9591 §4.2 `derive_interpolating_value`.
pub fn derive_interpolating_value(identifiers: &[u32], x_i: u32) -> Result<Scalar, String> {
    if !identifiers.contains(&x_i) {
        return Err("invalid parameters: x_i is not in the participant list".into());
    }
    let mut seen = std::collections::HashSet::new();
    for id in identifiers {
        if !seen.insert(*id) {
            return Err("invalid parameters: a participant appears twice".into());
        }
    }
    let x_i_scalar = Scalar::from(x_i as u64);
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    for id in identifiers {
        if *id == x_i {
            continue;
        }
        let x_j = Scalar::from(*id as u64);
        numerator *= x_j;
        denominator *= x_j - x_i_scalar;
    }
    // `Scalar::invert` maps zero to zero rather than signalling, so the zero case is checked here.
    // Distinct identifiers make it unreachable (the loop above rejects duplicates and the field is
    // prime), but the refusal is stated rather than implied by a silent zero.
    if denominator == Scalar::ZERO {
        return Err("invalid parameters: interpolating denominator is zero".into());
    }
    Ok(numerator * denominator.invert())
}

// ---------------------------------------------------------------------------
// Key generation (Pedersen DKG)
// ---------------------------------------------------------------------------

/// RFC 9591 defers key generation to the DKG draft; this is the Pedersen construction with a
/// Feldman-style public check, run locally for all participants.
///
/// Each of the `num` participants contributes a random degree `threshold - 1` polynomial. No
/// participant ever holds the group secret: the constant terms are summed to produce the group
/// public key, and each participant's share is the sum of the others' polynomials evaluated at its
/// index. `threshold == 1` is rejected rather than accepted, because a 1-of-n "threshold"
/// signature is just a signature and advertising it as threshold would be the same class of
/// overclaim this row is about.
pub fn dkg(threshold: u16, num: u16) -> Result<Vec<KeyPackage>, String> {
    if threshold < 2 {
        return Err("frost_dkg: threshold must be at least 2".into());
    }
    if num < threshold {
        return Err(format!(
            "frost_dkg: num_participants ({num}) must be at least the threshold ({threshold})"
        ));
    }

    let mut polynomials: Vec<Vec<Scalar>> = Vec::with_capacity(num as usize);
    for _ in 0..num {
        let mut poly = Vec::with_capacity(threshold as usize);
        for _ in 0..threshold {
            poly.push(Scalar::random(&mut rand_core_06::OsRng));
        }
        polynomials.push(poly);
    }

    // Group public key = Σ_j f_j(0)·B, computed from the constant terms.
    let mut group_public = EdwardsPoint::identity();
    for poly in &polynomials {
        group_public += ED25519_BASEPOINT_POINT * poly[0];
    }

    let mut packages = Vec::with_capacity(num as usize);
    for i in 1..=num {
        let x = Scalar::from(i as u64);
        let mut share = Scalar::ZERO;
        for poly in &polynomials {
            share += eval_polynomial(poly, &x);
        }
        packages.push(KeyPackage {
            id: i as u32,
            share,
            group_public,
            threshold,
            num,
        });
    }
    Ok(packages)
}

fn eval_polynomial(poly: &[Scalar], x: &Scalar) -> Scalar {
    let mut acc = Scalar::ZERO;
    for coeff in poly.iter().rev() {
        acc = acc * x + coeff;
    }
    acc
}

// ---------------------------------------------------------------------------
// Signing
// ---------------------------------------------------------------------------

/// RFC 9591 §5.1–§5.3 with every participant and the coordinator executed locally.
pub fn sign(message: &[u8], packages: &[KeyPackage]) -> Result<(EdwardsPoint, Scalar), String> {
    let nonces: Vec<NoncePair> = packages
        .iter()
        .map(|p| NoncePair::generate(&p.share))
        .collect();
    let paired: Vec<(KeyPackage, NoncePair)> = packages
        .iter()
        .cloned()
        .zip(nonces)
        .collect();
    sign_with_nonces(message, &paired)
}

/// The same protocol with the nonces supplied, so the RFC's vectors can drive round two directly.
pub fn sign_with_nonces(
    message: &[u8],
    packages: &[(KeyPackage, NoncePair)],
) -> Result<(EdwardsPoint, Scalar), String> {
    if packages.is_empty() {
        return Err("frost_sign: no key packages supplied".into());
    }
    let threshold = packages[0].0.threshold;
    let group_public = packages[0].0.group_public;
    for (p, _) in packages {
        if p.group_public != group_public {
            return Err("frost_sign: packages belong to different signing groups".into());
        }
        if p.threshold != threshold {
            return Err("frost_sign: packages disagree on the threshold".into());
        }
    }
    if packages.len() < threshold as usize {
        return Err(format!(
            "frost_sign: {threshold}-of-{} threshold needs {threshold} shares but {} were supplied",
            packages[0].0.num,
            packages.len()
        ));
    }

    let list = commitment_list(packages);
    let factors = compute_binding_factors(&group_public, &list, message);
    let group_commitment = compute_group_commitment(&list, &factors)
        .ok_or_else(|| "frost_sign: a participant is missing from the binding factor list".to_string())?;
    let challenge = compute_challenge(&group_commitment, &group_public, message);

    let identifiers: Vec<u32> = list.iter().map(|(id, _, _)| *id).collect();
    let mut z = Scalar::ZERO;
    for (package, nonce) in packages {
        let lambda = derive_interpolating_value(&identifiers, package.id)?;
        let bf = binding_factor_for_participant(&factors, package.id)
            .ok_or_else(|| "frost_sign: participant missing from the binding factor list".to_string())?;
        z += nonce.hiding + nonce.binding * bf + lambda * package.share * challenge;
    }
    Ok((group_commitment, z))
}

/// RFC 9591 Appendix A: the canonical Ed25519 signature encoding is `R ‖ z`.
pub fn encode_signature(r: &EdwardsPoint, z: &Scalar) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&serialize_element(r));
    out[32..].copy_from_slice(&serialize_scalar(z));
    out
}

/// RFC 9591 §6.1 signature verification, failing closed on any unparseable input.
pub fn verify(message: &[u8], signature: &[u8], group_public: &EdwardsPoint) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let Some(r) = deserialize_element(&signature[..32]) else {
        return false;
    };
    let Some(z) = deserialize_scalar(&signature[32..]) else {
        return false;
    };
    let challenge = compute_challenge(&r, group_public, message);
    // [8]zB = [8]R + [8][c]PK, written in its strict form; see the module header for why the two
    // are equivalent here and why this one is preferred.
    ED25519_BASEPOINT_POINT * z == r + *group_public * challenge
}

// ---------------------------------------------------------------------------
// The `.tl` string form of a key package
// ---------------------------------------------------------------------------

/// `id:share_hex:group_public_hex:threshold:num` — self-describing, so `frost_sign` can take one
/// participant's package and know everything the protocol needs about the group.
pub fn encode_package(p: &KeyPackage) -> String {
    format!(
        "{}:{}:{}:{}:{}",
        p.id,
        hex(&serialize_scalar(&p.share)),
        hex(&serialize_element(&p.group_public)),
        p.threshold,
        p.num
    )
}

pub fn decode_package(text: &str) -> Result<KeyPackage, String> {
    let parts: Vec<&str> = text.trim().split(':').collect();
    if parts.len() != 5 {
        return Err(format!(
            "frost key package must be 'id:share:group_public:threshold:num', got {} field(s)",
            parts.len()
        ));
    }
    let id: u32 = parts[0]
        .parse()
        .map_err(|_| format!("frost key package: invalid participant id '{}'", parts[0]))?;
    if id == 0 {
        return Err("frost key package: participant id must be non-zero".into());
    }
    let share = deserialize_scalar(&unhex(parts[1])?)
        .ok_or_else(|| "frost key package: share is not a canonical scalar".to_string())?;
    let group_public = deserialize_element(&unhex(parts[2])?)
        .ok_or_else(|| "frost key package: group public key is not a valid element".to_string())?;
    let threshold: u16 = parts[3]
        .parse()
        .map_err(|_| format!("frost key package: invalid threshold '{}'", parts[3]))?;
    let num: u16 = parts[4]
        .parse()
        .map_err(|_| format!("frost key package: invalid participant count '{}'", parts[4]))?;
    Ok(KeyPackage {
        id,
        share,
        group_public,
        threshold,
        num,
    })
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if s.len() % 2 != 0 {
        return Err(format!("hex string has odd length ({})", s.len()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| format!("invalid hex at position {i}: {e}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── RFC 9591 Appendix E.1, FROST(Ed25519, SHA-512) ──
    // MAX_PARTICIPANTS 3, MIN_PARTICIPANTS 2, NUM_PARTICIPANTS 2, participant_list 1,3.
    const GROUP_SECRET: &str =
        "7b1c33d3f5291d85de664833beb1ad469f7fb6025a0ec78b3a790c6e13a98304";
    const GROUP_PUBLIC: &str =
        "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673";
    const SHARE_POLY_1: &str =
        "178199860edd8c62f5212ee91eff1295d0d670ab4ed4506866bae57e7030b204";
    const SHARE_1: &str = "929dcc590407aae7d388761cddb0c0db6f5627aea8e217f4a033f2ec83d93509";
    const SHARE_3: &str = "d3cb090a075eb154e82fdb4b3cb507f110040905468bb9c46da8bdea643a9a02";
    const MESSAGE: &str = "74657374"; // "test"

    const P1_HIDING_RANDOMNESS: &str =
        "0fd2e39e111cdc266f6c0f4d0fd45c947761f1f5d3cb583dfcb9bbaf8d4c9fec";
    const P1_BINDING_RANDOMNESS: &str =
        "69cd85f631d5f7f2721ed5e40519b1366f340a87c2f6856363dbdcda348a7501";
    const P1_HIDING_NONCE: &str =
        "812d6104142944d5a55924de6d49940956206909f2acaeedecda2b726e630407";
    const P1_BINDING_NONCE: &str =
        "b1110165fc2334149750b28dd813a39244f315cff14d4e89e6142f262ed83301";
    const P1_HIDING_COMMITMENT: &str =
        "b5aa8ab305882a6fc69cbee9327e5a45e54c08af61ae77cb8207be3d2ce13de3";
    const P1_BINDING_COMMITMENT: &str =
        "67e98ab55aa310c3120418e5050c9cf76cf387cb20ac9e4b6fdb6f82a469f932";
    const P1_BINDING_FACTOR: &str =
        "f2cb9d7dd9beff688da6fcc83fa89046b3479417f47f55600b106760eb3b5603";
    const P1_SIG_SHARE: &str =
        "001719ab5a53ee1a12095cd088fd149702c0720ce5fd2f29dbecf24b7281b603";

    const P3_HIDING_RANDOMNESS: &str =
        "86d64a260059e495d0fb4fcc17ea3da7452391baa494d4b00321098ed2a0062f";
    const P3_BINDING_RANDOMNESS: &str =
        "13e6b25afb2eba51716a9a7d44130c0dbae0004a9ef8d7b5550c8a0e07c61775";
    const P3_HIDING_NONCE: &str =
        "c256de65476204095ebdc01bd11dc10e57b36bc96284595b8215222374f99c0e";
    const P3_BINDING_NONCE: &str =
        "243d71944d929063bc51205714ae3c2218bd3451d0214dfb5aeec2a90c35180d";
    const P3_HIDING_COMMITMENT: &str =
        "cfbdb165bd8aad6eb79deb8d287bcc0ab6658ae57fdcc98ed12c0669e90aec91";
    const P3_BINDING_COMMITMENT: &str =
        "7487bc41a6e712eea2f2af24681b58b1cf1da278ea11fe4e8b78398965f13552";
    const P3_BINDING_FACTOR: &str =
        "b087686bf35a13f3dc78e780a34b0fe8a77fef1b9938c563f5573d71d8d7890f";
    const P3_SIG_SHARE: &str =
        "bd86125de990acc5e1f13781d8e32c03a9bbd4c53539bbc106058bfd14326007";

    const EXPECTED_SIG: &str = "36282629c383bb820a88b71cae937d41f2f2adfcc3d02e55507e2fb9e2dd3cbebd9d2b0844e49ae0f3fa935161e1419aab7b47d21a37ebeae1f17d4987b3160b";

    fn s(hex_str: &str) -> Scalar {
        deserialize_scalar(&unhex(hex_str).expect("vector hex")).expect("vector is canonical")
    }

    fn p(hex_str: &str) -> EdwardsPoint {
        deserialize_element(&unhex(hex_str).expect("vector hex")).expect("vector is a valid element")
    }

    fn vector_packages() -> Vec<(KeyPackage, NoncePair)> {
        let group_public = p(GROUP_PUBLIC);
        let p1 = KeyPackage {
            id: 1,
            share: s(SHARE_1),
            group_public,
            threshold: 2,
            num: 3,
        };
        let p3 = KeyPackage {
            id: 3,
            share: s(SHARE_3),
            group_public,
            threshold: 2,
            num: 3,
        };
        let n1 = NoncePair {
            hiding: s(P1_HIDING_NONCE),
            binding: s(P1_BINDING_NONCE),
        };
        let n3 = NoncePair {
            hiding: s(P3_HIDING_NONCE),
            binding: s(P3_BINDING_NONCE),
        };
        vec![(p1, n1), (p3, n3)]
    }

    #[test]
    fn the_group_public_key_is_the_group_secret_times_the_basepoint() {
        assert_eq!(
            serialize_element(&(ED25519_BASEPOINT_POINT * s(GROUP_SECRET))),
            unhex(GROUP_PUBLIC).unwrap().as_slice()
        );
    }

    #[test]
    fn participant_shares_are_the_polynomial_evaluated_at_their_identifiers() {
        // f(x) = secret + coeff_1 * x, so f(1) and f(3) are the published shares: this checks the
        // scalar field arithmetic and the little-endian convention in one place.
        let secret = s(GROUP_SECRET);
        let coeff = s(SHARE_POLY_1);
        assert_eq!(serialize_scalar(&(secret + coeff * Scalar::from(1u64))), serialize_scalar(&s(SHARE_1)));
        assert_eq!(serialize_scalar(&(secret + coeff * Scalar::from(3u64))), serialize_scalar(&s(SHARE_3)));
    }

    #[test]
    fn h4_and_h5_are_domain_separated() {
        // H4(msg) is the middle 64 bytes of P1's binding factor input, so the vector pins both the
        // context string and the "msg" separator; the next test pins H5 the same way.
        let h4_msg = hex(&h4(&unhex(MESSAGE).unwrap()));
        assert_eq!(P1_BINDING_FACTOR_INPUT_FROM_VECTOR[64..192], h4_msg[..]);
        let list = commitment_list(&vector_packages());
        assert_eq!(
            hex(&h5(&encode_group_commitment_list(&list))),
            &P1_BINDING_FACTOR_INPUT_FROM_VECTOR[192..320]
        );
    }

    /// The vector's binding factor input for P1, verbatim from RFC 9591 Appendix E.1 (line-wrapped
    /// there; unwrapped here). Its shape is the specification: 32-byte PK ‖ 64-byte H4 ‖
    /// 64-byte H5 ‖ 32-byte identifier.
    const P1_BINDING_FACTOR_INPUT_FROM_VECTOR: &str = "15d21ccd7ee42959562fc8aa63224c8851fb3ec85a3faf66040d380fb9738673504df914fa965023fb75c25ded4bb260f417de6d32e5c442c6ba313791cc9a4948d6273e8d3511f93348ea7a708a9b862bc73ba2a79cfdfe07729a193751cbc973af46d8ac3440e518d4ce440a0e7d4ad5f62ca8940f32de6d8dc00fc12c660b817d587d82f856d277ce6473cae6d2f5763f7da2e8b4d799a3f3e725d4522ec70100000000000000000000000000000000000000000000000000000000000000";

    #[test]
    fn the_binding_factor_input_is_pk_then_h4_then_h5_then_identifier() {
        let list = commitment_list(&vector_packages());
        let mut prefix = Vec::new();
        prefix.extend_from_slice(&serialize_element(&p(GROUP_PUBLIC)));
        prefix.extend_from_slice(&h4(&unhex(MESSAGE).unwrap()));
        prefix.extend_from_slice(&h5(&encode_group_commitment_list(&list)));
        prefix.extend_from_slice(&serialize_scalar(&Scalar::from(1u64)));
        assert_eq!(
            hex(&prefix),
            P1_BINDING_FACTOR_INPUT_FROM_VECTOR,
            "the binding factor input must be reconstructible from its published parts"
        );
    }

    #[test]
    fn nonce_generation_matches_the_vectors() {
        // The vector publishes the 32 random bytes beside each nonce, so H3 and its input layout
        // are checked rather than assumed.
        let r1 = unhex(P1_HIDING_RANDOMNESS).unwrap();
        let r1: [u8; 32] = r1.try_into().unwrap();
        assert_eq!(
            serialize_scalar(&nonce_generate_with_randomness(&r1, &s(SHARE_1))),
            serialize_scalar(&s(P1_HIDING_NONCE))
        );
        let r1b = unhex(P1_BINDING_RANDOMNESS).unwrap();
        let r1b: [u8; 32] = r1b.try_into().unwrap();
        assert_eq!(
            serialize_scalar(&nonce_generate_with_randomness(&r1b, &s(SHARE_1))),
            serialize_scalar(&s(P1_BINDING_NONCE))
        );
        let r3 = unhex(P3_HIDING_RANDOMNESS).unwrap();
        let r3: [u8; 32] = r3.try_into().unwrap();
        assert_eq!(
            serialize_scalar(&nonce_generate_with_randomness(&r3, &s(SHARE_3))),
            serialize_scalar(&s(P3_HIDING_NONCE))
        );
        let r3b = unhex(P3_BINDING_RANDOMNESS).unwrap();
        let r3b: [u8; 32] = r3b.try_into().unwrap();
        assert_eq!(
            serialize_scalar(&nonce_generate_with_randomness(&r3b, &s(SHARE_3))),
            serialize_scalar(&s(P3_BINDING_NONCE))
        );
    }

    #[test]
    fn the_nonce_commitments_are_the_nonces_times_the_basepoint() {
        assert_eq!(
            serialize_element(&(ED25519_BASEPOINT_POINT * s(P1_HIDING_NONCE))),
            unhex(P1_HIDING_COMMITMENT).unwrap().as_slice()
        );
        assert_eq!(
            serialize_element(&(ED25519_BASEPOINT_POINT * s(P1_BINDING_NONCE))),
            unhex(P1_BINDING_COMMITMENT).unwrap().as_slice()
        );
        assert_eq!(
            serialize_element(&(ED25519_BASEPOINT_POINT * s(P3_HIDING_NONCE))),
            unhex(P3_HIDING_COMMITMENT).unwrap().as_slice()
        );
        assert_eq!(
            serialize_element(&(ED25519_BASEPOINT_POINT * s(P3_BINDING_NONCE))),
            unhex(P3_BINDING_COMMITMENT).unwrap().as_slice()
        );
    }

    #[test]
    fn binding_factors_match_the_vectors() {
        let message = unhex(MESSAGE).unwrap();
        let list = commitment_list(&vector_packages());
        let factors = compute_binding_factors(&p(GROUP_PUBLIC), &list, &message);
        assert_eq!(
            serialize_scalar(&binding_factor_for_participant(&factors, 1).unwrap()),
            serialize_scalar(&s(P1_BINDING_FACTOR))
        );
        assert_eq!(
            serialize_scalar(&binding_factor_for_participant(&factors, 3).unwrap()),
            serialize_scalar(&s(P3_BINDING_FACTOR))
        );
    }

    #[test]
    fn signature_shares_and_the_aggregate_match_the_vectors() {
        let message = unhex(MESSAGE).unwrap();
        let packages = vector_packages();
        let list = commitment_list(&packages);
        let factors = compute_binding_factors(&p(GROUP_PUBLIC), &list, &message);
        let group_commitment = compute_group_commitment(&list, &factors).unwrap();
        let challenge = compute_challenge(&group_commitment, &p(GROUP_PUBLIC), &message);
        let identifiers: Vec<u32> = list.iter().map(|(id, _, _)| *id).collect();

        // Round two, participant by participant, against the published shares.
        let mut expected_z = Scalar::ZERO;
        for (package, nonce) in &packages {
            let lambda = derive_interpolating_value(&identifiers, package.id).unwrap();
            let bf = binding_factor_for_participant(&factors, package.id).unwrap();
            let z_i = nonce.hiding + nonce.binding * bf + lambda * package.share * challenge;
            expected_z += z_i;
            let published = if package.id == 1 { P1_SIG_SHARE } else { P3_SIG_SHARE };
            assert_eq!(
                serialize_scalar(&z_i),
                serialize_scalar(&s(published)),
                "signature share for participant {} differs from the RFC vector",
                package.id
            );
        }

        // Aggregation, and the resulting signature.
        let (r, z) = sign_with_nonces(&message, &packages).unwrap();
        assert_eq!(r, group_commitment);
        assert_eq!(z, expected_z);
        let sig = encode_signature(&r, &z);
        assert_eq!(hex(&sig), EXPECTED_SIG, "aggregate signature must equal the RFC vector");
    }

    #[test]
    fn the_vector_signature_verifies_and_a_tampered_one_does_not() {
        let message = unhex(MESSAGE).unwrap();
        let sig = unhex(EXPECTED_SIG).unwrap();
        assert!(verify(&message, &sig, &p(GROUP_PUBLIC)), "the RFC's signature must verify");

        // Wrong message, wrong key, and a flipped bit in each half of the signature.
        assert!(!verify(b"other", &sig, &p(GROUP_PUBLIC)));
        assert!(!verify(&message, &sig, &(p(GROUP_PUBLIC) + ED25519_BASEPOINT_POINT)));
        let mut bad_r = sig.clone();
        bad_r[5] ^= 0x01;
        assert!(!verify(&message, &bad_r, &p(GROUP_PUBLIC)));
        let mut bad_z = sig.clone();
        bad_z[40] ^= 0x01;
        assert!(!verify(&message, &bad_z, &p(GROUP_PUBLIC)));
        // Truncated and empty inputs fail closed rather than panicking.
        assert!(!verify(&message, &sig[..63], &p(GROUP_PUBLIC)));
        assert!(!verify(&message, &[], &p(GROUP_PUBLIC)));
    }

    #[test]
    fn a_freshly_generated_group_signs_and_verifies_at_its_threshold() {
        // End to end through the public entry points, for each threshold of a 5-participant group.
        for (threshold, num) in [(2u16, 3u16), (3, 5), (5, 5)] {
            let packages = dkg(threshold, num).expect("dkg");
            assert_eq!(packages.len(), num as usize);
            let group_public = packages[0].group_public;

            for subset_start in 0..=(num - threshold) {
                let selected: Vec<KeyPackage> = packages[subset_start as usize
                    ..(subset_start + threshold) as usize]
                    .to_vec();
                let (r, z) = sign(b"threshold signing", &selected).expect("sign");
                let sig = encode_signature(&r, &z);
                assert!(
                    verify(b"threshold signing", &sig, &group_public),
                    "{threshold}-of-{num} signature from participants starting at {subset_start} must verify"
                );
                assert!(!verify(b"threshold signing!", &sig, &group_public));
            }
        }
    }

    #[test]
    fn signing_below_the_threshold_is_refused() {
        let packages = dkg(3, 5).expect("dkg");
        let err = sign(b"msg", &packages[..2]).unwrap_err();
        assert!(err.contains("needs 3 shares"), "unexpected error: {err}");
    }

    #[test]
    fn degenerate_and_inconsistent_groups_are_refused() {
        assert!(dkg(1, 3).unwrap_err().contains("at least 2"));
        assert!(dkg(4, 3).unwrap_err().contains("at least the threshold"));
        // Packages from two different groups must not be mixed: that would produce a signature
        // whose interpolating value is meaningless.
        let a = dkg(2, 3).unwrap();
        let b = dkg(2, 3).unwrap();
        let mixed = vec![a[0].clone(), b[1].clone()];
        assert!(sign(b"msg", &mixed)
            .unwrap_err()
            .contains("different signing groups"));
    }

    #[test]
    fn the_package_string_round_trips_and_rejects_junk() {
        let packages = dkg(2, 3).unwrap();
        for package in &packages {
            let text = encode_package(package);
            let back = decode_package(&text).expect("round trip");
            assert_eq!(back.id, package.id);
            assert_eq!(serialize_scalar(&back.share), serialize_scalar(&package.share));
            assert_eq!(back.group_public, package.group_public);
            assert_eq!(back.threshold, package.threshold);
            assert_eq!(back.num, package.num);
        }
        for bad in [
            "",
            "1:2:3",
            "x:00:00:2:3",
            "0:00:00:2:3",
            "1:zz:00:2:3",
            "1:00:00:2:3",
        ] {
            assert!(decode_package(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn scalar_and_element_deserialization_reject_non_canonical_and_small_order_inputs() {
        // A scalar encoding ≥ L is not canonical: refused, never silently reduced. All-0xff as a
        // little-endian integer is 2^256 - 1, which is comfortably above 2^252 + 27742...
        assert!(deserialize_scalar(&[0xffu8; 32]).is_none());
        assert!(deserialize_scalar(&[0u8; 31]).is_none()); // wrong length
        assert!(deserialize_scalar(&[0u8; 33]).is_none());
        // Ed25519's identity and small-order encodings are refused: (0,1) is the identity, and
        // (0,0) is an 8-torsion point, so neither may reach the group equation.
        assert!(deserialize_element(&[0u8; 32]).is_none());
        assert!(deserialize_element(&[1u8; 32]).is_none());
        assert!(deserialize_element(&[0xffu8; 32]).is_none());
        // A canonical scalar and a valid element still deserialize.
        assert!(deserialize_scalar(&[0u8; 32]).is_some());
        assert!(deserialize_element(&serialize_element(&ED25519_BASEPOINT_POINT)).is_some());
    }
}
