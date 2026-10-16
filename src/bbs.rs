#![allow(dead_code)] // BBS+ increment 1 of 2: the utility layer. The Core operations
                     // (CoreSign/CoreVerify/CoreProofGen/CoreProofVerify) and the `.tl` wiring land
                     // in the next increment, which is what consumes these functions. Nothing calls
                     // them yet, so the compiler would otherwise warn on every one.
//! BBS signatures over BLS12-381 — draft-irtf-cfrg-bbs-signatures-08, ciphersuite
//! `BLS12-381-SHA-256`.
//!
//! Stub register row #90, third family. The canonical `bbs_issue` / `bbs_prove` / `bbs_verify` names
//! refuse because the `_experimental` counterpart is an Ed25519-commitment approximation with no
//! pairing-based security — a construction with none of the properties the names promise.
//!
//! ## What this increment contains, and what validates it
//!
//! The utility layer the Core operations are built from, each piece checked against the draft rather
//! than against my reading of it:
//!
//! - `expand_message_xmd` (RFC 9380 §5.3.1, SHA-256) — BBS+ needs `expand_message` as a standalone
//!   primitive (for `hash_to_scalar` and for the generator seeds), which is why the ciphersuite's
//!   hash-to-curve suite alone is not enough.
//! - `hash_to_scalar` (§4.2.2): `OS2IP(expand_message(msg, dst, 48)) mod r`. Checked against the
//!   draft's own Appendix D.2.3 vector.
//! - `create_generators` (§4.1.1) and the G1 operations over `blst`. Checked against the strongest
//!   available anchor: §7.2.2 prints **P1 as a literal** — the ciphersuite's fixed point — and §7.2
//!   says P1 *is* `create_generators(count = 1)` under the interface's `api_id`. Reproducing that
//!   literal therefore validates the seed derivation, the DST construction, `expand_message_xmd` and
//!   hash-to-curve in one assertion; a mistake in any of them cannot produce the right 48 bytes.
//!
//! ## Conventions taken from the draft, not guessed
//!
//! - `api_id = ciphersuite_id || "H2G_HM2S_"` for the BBS interface (§3.5). It is confirmed by the
//!   D.2.3 vector's `dst`, which is exactly `api_id || "H2S_"` — the same construction §4.2.3 defines
//!   for `hash_to_scalar_dst`.
//! - `octet_scalar_length = 32`, `octet_point_length = 48`, `expand_len = 48` (§7.2.2).
//! - Scalars live in the prime field of order r; `scalar_mul` **refuses** a scalar ≥ r rather than
//!   silently reducing it, and callers reduce explicitly where the spec says to. A silent reduction
//!   is how a non-canonical scalar turns into a valid-looking signature.
//!
//! ## Verification
//!
//! `create_generators` reproduces the ciphersuite's P1 literal; `hash_to_scalar` reproduces the
//! draft's D.2.3 scalar; the scalar-multiplication byte-order convention is pinned empirically
//! (`1·P = P`, `2·P = P + P`) rather than assumed; compressed points round-trip and a non-subgroup or
//! non-curve encoding is refused.

use blst::{
    blst_final_exp, blst_fp12_is_one, blst_fp12_mul, blst_hash_to_g1, blst_miller_loop, blst_p1,
    blst_p1_add_or_double, blst_p1_affine, blst_p1_affine_in_g1, blst_p1_compress,
    blst_p1_from_affine, blst_p1_in_g1, blst_p1_is_inf, blst_p1_mult, blst_p1_to_affine,
    blst_p1_uncompress, blst_p2, blst_p2_add_or_double, blst_p2_affine, blst_p2_affine_in_g2,
    blst_p2_cneg, blst_p2_compress, blst_p2_from_affine, blst_p2_is_inf, blst_p2_mult,
    blst_p2_to_affine, blst_p2_uncompress, BLST_ERROR,
};
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/// The ciphersuite this module implements, spelled exactly as §7.2.2 spells it.
pub const CIPHERSUITE_ID: &[u8] = b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
/// The BBS interface's suffix, appended to the ciphersuite id to form `api_id` (§3.5).
const H2G_HM2S: &[u8] = b"H2G_HM2S_";

/// §7.2.2 basic parameters.
pub const OCTET_SCALAR_LENGTH: usize = 32;
pub const OCTET_POINT_LENGTH: usize = 48;
pub const EXPAND_LEN: usize = 48;
/// `octet_point_length` for E2 — a compressed G2 point is 96 bytes, which is the length of a public
/// key (§8.4.1's `PK`).
pub const OCTET_POINT_LENGTH_E2: usize = 96;

/// §4.1.1 definitions, as suffixes on `api_id`.
const SEED_DST_SUFFIX: &[u8] = b"SIG_GENERATOR_SEED_";
const GENERATOR_DST_SUFFIX: &[u8] = b"SIG_GENERATOR_DST_";
const GENERATOR_SEED_SUFFIX: &[u8] = b"MESSAGE_GENERATOR_SEED";
/// §4.2.3's `hash_to_scalar_dst` suffix.
pub const H2S_SUFFIX: &[u8] = b"H2S_";
/// §4.1.2's `map_dst` suffix.
pub const MAP_MSG_TO_SCALAR_SUFFIX: &[u8] = b"MAP_MSG_TO_SCALAR_AS_HASH_";
/// §3.4.1's `key_dst` suffix.
const KEYGEN_DST_SUFFIX: &[u8] = b"KEYGEN_DST_";
/// §8.1's mocked-scalar DST suffix, used only by the proof vectors.
pub const MOCK_RANDOM_SCALARS_SUFFIX: &[u8] = b"MOCK_RANDOM_SCALARS_DST_";

/// The ciphersuite's P1, as §7.2.2 prints it (compressed, 48 bytes).
pub const P1_COMPRESSED_HEX: &str =
    "a8ce256102840821a3e94ea9025e4662b205762f9776b3a766c872b948f1fd225e7c59698588e70d11406d161b4e28c9";

/// `api_id` for the BBS interface: `ciphersuite_id || "H2G_HM2S_"`.
pub fn api_id() -> Vec<u8> {
    [CIPHERSUITE_ID, H2G_HM2S].concat()
}

/// `api_id || suffix`, the shape every DST in this document takes.
pub fn dst(suffix: &[u8]) -> Vec<u8> {
    [&api_id()[..], suffix].concat()
}

// ---------------------------------------------------------------------------
// Hex
// ---------------------------------------------------------------------------

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
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

// ---------------------------------------------------------------------------
// The scalar field
// ---------------------------------------------------------------------------

/// The order r of the BLS12-381 prime-order subgroups (log2(r) = 255, per §7.2).
pub fn scalar_field_order() -> BigUint {
    unhex("73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001")
        .map(|bytes| BigUint::from_bytes_be(&bytes))
        .expect("the scalar field order is a valid constant")
}

/// A scalar as its 32-byte big-endian encoding (`I2OSP(k, 32)`).
pub fn scalar_to_octets(k: &BigUint) -> Result<[u8; OCTET_SCALAR_LENGTH], String> {
    if k >= &scalar_field_order() {
        return Err("scalar is not in the range [0, r)".to_string());
    }
    let raw = k.to_bytes_be();
    if raw.len() > OCTET_SCALAR_LENGTH {
        return Err(format!("scalar encodes to {} bytes, expected at most {OCTET_SCALAR_LENGTH}", raw.len()));
    }
    let mut out = [0u8; OCTET_SCALAR_LENGTH];
    out[OCTET_SCALAR_LENGTH - raw.len()..].copy_from_slice(&raw);
    Ok(out)
}

/// Decode a scalar from its 32-byte encoding, under the codecs' own rule: a scalar must be in
/// `[1, r-1]`. Refusing instead of reducing is the point — a silently reduced non-canonical scalar is
/// how a malformed signature or proof starts looking valid (§4.2.4.3, §4.2.4.5).
pub fn octets_to_scalar(octets: &[u8]) -> Result<BigUint, String> {
    if octets.len() != OCTET_SCALAR_LENGTH {
        return Err(format!(
            "octets_to_scalar: expected {OCTET_SCALAR_LENGTH} bytes, got {}",
            octets.len()
        ));
    }
    let value = BigUint::from_bytes_be(octets);
    if value == BigUint::from(0u32) || value >= scalar_field_order() {
        return Err("scalar is not in the range [1, r-1]".to_string());
    }
    Ok(value)
}

/// Explicit modular reduction, for the places the document says `mod r`.
pub fn mod_r(k: &BigUint) -> BigUint {
    k % scalar_field_order()
}

/// `(a + b) mod r`.
pub fn add_mod_r(a: &BigUint, b: &BigUint) -> BigUint {
    mod_r(&(a + b))
}

/// `a * b mod r`.
pub fn mul_mod_r(a: &BigUint, b: &BigUint) -> BigUint {
    mod_r(&(a * b))
}

/// `a - b mod r`.
pub fn sub_mod_r(a: &BigUint, b: &BigUint) -> BigUint {
    let r = scalar_field_order();
    let (a, b) = (a % &r, b % &r);
    if a >= b {
        a - b
    } else {
        &r - &(b - a)
    }
}

/// `-a mod r`.
pub fn neg_mod_r(a: &BigUint) -> BigUint {
    let r = scalar_field_order();
    let a = a % &r;
    if a == BigUint::from(0u32) {
        a
    } else {
        &r - &a
    }
}

/// `a^-1 mod r` by Fermat's little theorem, `a^(r-2) mod r`. Valid because r is prime, and it fails
/// loudly on zero instead of returning a value that would silently produce a broken signature.
pub fn inverse_mod_r(a: &BigUint) -> Result<BigUint, String> {
    let r = scalar_field_order();
    if a % &r == BigUint::from(0u32) {
        return Err("zero has no inverse modulo r".to_string());
    }
    Ok(a.modpow(&(&r - BigUint::from(2u32)), &r))
}

// ---------------------------------------------------------------------------
// expand_message_xmd (RFC 9380 §5.3.1) with SHA-256
// ---------------------------------------------------------------------------

fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in parts {
        h.update(part);
    }
    h.finalize().into()
}

/// `expand_message_xmd(msg, dst, len)` for SHA-256 (`b_in_bytes = 32`, `s_in_bytes = 64`).
pub fn expand_message_xmd(msg: &[u8], dst: &[u8], len: usize) -> Result<Vec<u8>, String> {
    const B: usize = 32; // SHA-256 output size
    const S: usize = 64; // SHA-256 block size
    if len == 0 || len > 255 * B {
        return Err(format!("expand_message_xmd: len must be in 1..={}, got {len}", 255 * B));
    }
    if dst.len() > 255 {
        return Err(format!(
            "expand_message_xmd: dst must be at most 255 octets, got {}",
            dst.len()
        ));
    }
    let ell = len.div_ceil(B);

    // DST_prime = DST || I2OSP(len(DST), 1) (RFC 9380 §5.3.1 step 3). The length suffix is part of
    // the construction, not decoration: without it every generated value here is wrong.
    let mut dst_prime = dst.to_vec();
    dst_prime.push(dst.len() as u8);

    // msg_prime = Z_pad || msg || I2OSP(len, 2) || I2OSP(0, 1) || DST_prime
    let mut msg_prime = vec![0u8; S];
    msg_prime.extend_from_slice(msg);
    msg_prime.extend_from_slice(&(len as u16).to_be_bytes());
    msg_prime.push(0x00);
    msg_prime.extend_from_slice(&dst_prime);
    let b_0 = sha256(&[&msg_prime]);

    let mut out = Vec::with_capacity(ell * B);
    let mut prev = sha256(&[&b_0, &[0x01], &dst_prime]);
    out.extend_from_slice(&prev);
    for i in 2..=ell {
        let xor: Vec<u8> = b_0.iter().zip(prev.iter()).map(|(a, b)| a ^ b).collect();
        prev = sha256(&[&xor, &[i as u8], &dst_prime]);
        out.extend_from_slice(&prev);
    }
    out.truncate(len);
    Ok(out)
}

/// §4.2.2 `hash_to_scalar`: `OS2IP(expand_message(msg, dst, 48)) mod r`.
pub fn hash_to_scalar(msg: &[u8], dst: &[u8]) -> Result<BigUint, String> {
    let uniform = expand_message_xmd(msg, dst, EXPAND_LEN)?;
    Ok(BigUint::from_bytes_be(&uniform) % scalar_field_order())
}

fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

/// §4.2.1 `calculate_random_scalars`: one fresh `get_random(expand_len)` draw per scalar. This is the
/// real path; the proof vectors replace it with `seeded_random_scalars`.
pub fn calculate_random_scalars(count: usize) -> Result<Vec<BigUint>, String> {
    let r = scalar_field_order();
    (0..count)
        .map(|_| Ok(BigUint::from_bytes_be(&random_bytes(EXPAND_LEN)) % &r))
        .collect()
}

/// §8.1 `seeded_random_scalars(SEED, DST, count)` — the deterministic mock the proof vectors use.
///
/// One `expand_message(SEED, DST, 48 * count)` call, then each 48-byte chunk reduced mod r. It is
/// **one** call, not `count` calls: an implementation that drew `count` separate expansions would
/// still produce random-looking output and would not match a single published vector.
pub fn seeded_random_scalars(seed: &[u8], dst: &[u8], count: usize) -> Result<Vec<BigUint>, String> {
    let out_len = EXPAND_LEN
        .checked_mul(count)
        .ok_or_else(|| "count * expand_len overflows".to_string())?;
    if out_len > 65535 {
        return Err(format!(
            "count * expand_len must be at most 65535 (got {out_len}); §8.1 aborts here"
        ));
    }
    if count == 0 {
        return Ok(Vec::new());
    }
    let r = scalar_field_order();
    let expanded = expand_message_xmd(seed, dst, out_len)?;
    Ok(expanded
        .chunks(EXPAND_LEN)
        .map(|chunk| BigUint::from_bytes_be(chunk) % &r)
        .collect())
}

// ---------------------------------------------------------------------------
// G1
// ---------------------------------------------------------------------------

/// A point of G1. Held as `blst`'s projective representation.
#[derive(Clone, Copy)]
pub struct G1(pub(crate) blst_p1);

impl G1 {
    /// The identity (point at infinity).
    pub fn identity() -> Self {
        G1(blst_p1::default())
    }

    /// Decode a compressed point, refusing anything that is not on the curve or not in the
    /// prime-order subgroup.
    pub fn from_compressed(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != OCTET_POINT_LENGTH {
            return Err(format!(
                "octets_to_point_E1: expected {OCTET_POINT_LENGTH} bytes, got {}",
                bytes.len()
            ));
        }
        let mut affine = blst_p1_affine::default();
        let mut point = blst_p1::default();
        let error = unsafe { blst_p1_uncompress(&mut affine, bytes.as_ptr()) };
        if error != BLST_ERROR::BLST_SUCCESS {
            return Err(format!("octets_to_point_E1: not a valid curve point ({error:?})"));
        }
        unsafe {
            blst_p1_from_affine(&mut point, &affine);
            if !blst_p1_affine_in_g1(&affine) {
                return Err("octets_to_point_E1: point is not in the prime-order subgroup".to_string());
            }
        }
        Ok(G1(point))
    }

    /// Decode from hex, the way the draft prints points.
    pub fn from_hex(text: &str) -> Result<Self, String> {
        Self::from_compressed(&unhex(text)?)
    }

    /// The canonical compressed encoding (`point_to_octets_E1`).
    pub fn to_compressed(&self) -> [u8; OCTET_POINT_LENGTH] {
        let mut out = [0u8; OCTET_POINT_LENGTH];
        unsafe { blst_p1_compress(out.as_mut_ptr(), &self.0) };
        out
    }

    pub fn to_hex(&self) -> String {
        hex(&self.to_compressed())
    }

    pub fn is_identity(&self) -> bool {
        unsafe { blst_p1_is_inf(&self.0) }
    }

    /// `hash_to_curve_g1(msg, dst)` from the ciphersuite's hash-to-curve suite.
    pub fn hash_to_curve(msg: &[u8], dst: &[u8]) -> Self {
        let mut point = blst_p1::default();
        unsafe {
            blst_hash_to_g1(
                &mut point,
                msg.as_ptr(),
                msg.len(),
                dst.as_ptr(),
                dst.len(),
                std::ptr::null(),
                0,
            );
        }
        G1(point)
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut out = blst_p1::default();
        unsafe { blst_p1_add_or_double(&mut out, &self.0, &other.0) };
        G1(out)
    }

    /// Scalar multiplication. Refuses `k >= r`: silently reducing here is how a non-canonical scalar
    /// becomes a valid-looking signature, so callers reduce explicitly where the document says to.
    ///
    /// `blst` reads this scalar as a **little-endian** byte string (its scalar type stores it that
    /// way — which is why both `blst_scalar_from_bendian` and `_from_lendian` exist, and why blst's
    /// own code hands `blst_scalar.b` straight to `blst_p1_mult`). The documented encodings in this
    /// module stay big-endian; the reversal is confined to this call.
    pub fn scalar_mul(&self, k: &BigUint) -> Result<Self, String> {
        let mut octets = scalar_to_octets(k)?;
        octets.reverse();
        let mut out = blst_p1::default();
        unsafe { blst_p1_mult(&mut out, &self.0, octets.as_ptr(), OCTET_SCALAR_LENGTH * 8) };
        Ok(G1(out))
    }
}

// ---------------------------------------------------------------------------
// Generators (§4.1.1)
// ---------------------------------------------------------------------------

/// `create_generators(count, api_id)` from §4.1.1, with the BBS interface's `api_id`.
///
/// The returned vector is `(generator_1, ..., generator_count)`, and for the BBS interface
/// `generator_1` is **Q_1** — §4.2.3 defines Q_1 as "the first point returned from
/// create_generators", and §3.5 calls `create_generators(length(messages) + 1, api_id)`, so the
/// array is `(Q_1, H_1, ..., H_L)`. P1 is *not* in this array: it is a ciphersuite constant with its
/// own seed (see `ciphersuite_p1`).
pub fn create_generators(count: usize) -> Result<Vec<G1>, String> {
    let seed_dst = dst(SEED_DST_SUFFIX);
    let generator_dst = dst(GENERATOR_DST_SUFFIX);
    let generator_seed = dst(GENERATOR_SEED_SUFFIX);

    let mut v = expand_message_xmd(&generator_seed, &seed_dst, EXPAND_LEN)?;
    let mut generators = Vec::with_capacity(count);
    for i in 1..=count {
        let mut input = v.clone();
        input.extend_from_slice(&(i as u64).to_be_bytes());
        v = expand_message_xmd(&input, &seed_dst, EXPAND_LEN)?;
        generators.push(G1::hash_to_curve(&v, &generator_dst));
    }
    Ok(generators)
}

/// §7.2's P1: the ciphersuite's fixed G1 point, derived with the ciphersuite's own Definitions.
///
/// This is a trap worth naming. §7.2 says P1 is `create_generators(count = 1)` "with the parameters
/// defined by each ciphersuite", but the Definitions it then lists are *not* the interface's
/// `api_id || suffix` form for the seed: §7.2 gives
/// `generator_seed = ciphersuite_id || "H2G_HM2S_BP_MESSAGE_GENERATOR_SEED"`, whereas §4.1.1's
/// interface form is `api_id || "MESSAGE_GENERATOR_SEED"`. The draft says the similarity to `api_id`
/// is "only for compatibility reasons with previous versions of this document", and the difference is
/// observable: the interface's `generator_1` is Q_1, not P1. `seed_dst` and `generator_dst` do
/// coincide with the interface's (`…H2G_HM2S_SIG_GENERATOR_SEED_` / `…_DST_`).
///
/// §7.2.2 also prints P1 as a literal, so this derivation is checkable rather than asserted.
pub fn ciphersuite_p1() -> Result<G1, String> {
    const BP_SEED_SUFFIX: &[u8] = b"H2G_HM2S_BP_MESSAGE_GENERATOR_SEED";
    const SEED_DST_FULL: &[u8] = b"H2G_HM2S_SIG_GENERATOR_SEED_";
    const GENERATOR_DST_FULL: &[u8] = b"H2G_HM2S_SIG_GENERATOR_DST_";

    let seed_dst = [CIPHERSUITE_ID, SEED_DST_FULL].concat();
    let generator_dst = [CIPHERSUITE_ID, GENERATOR_DST_FULL].concat();
    let generator_seed = [CIPHERSUITE_ID, BP_SEED_SUFFIX].concat();

    let mut v = expand_message_xmd(&generator_seed, &seed_dst, EXPAND_LEN)?;
    let mut input = v.clone();
    input.extend_from_slice(&1u64.to_be_bytes());
    v = expand_message_xmd(&input, &seed_dst, EXPAND_LEN)?;
    Ok(G1::hash_to_curve(&v, &generator_dst))
}

// ---------------------------------------------------------------------------
// G2 — the pairing's other side (public keys and BP2)
// ---------------------------------------------------------------------------

/// A point of G2, held as `blst`'s projective representation.
#[derive(Clone, Copy)]
pub struct G2(pub(crate) blst_p2);

impl G2 {
    pub fn identity() -> Self {
        G2(blst_p2::default())
    }

    /// BP2, the G2 base point (Appendix B). `SkToPk` is `SK · BP2`.
    pub fn generator() -> Self {
        G2(unsafe { *blst::blst_p2_generator() })
    }

    pub fn from_compressed(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() != OCTET_POINT_LENGTH_E2 {
            return Err(format!(
                "octets_to_point_E2: expected {OCTET_POINT_LENGTH_E2} bytes, got {}",
                bytes.len()
            ));
        }
        let mut affine = blst_p2_affine::default();
        let mut point = blst_p2::default();
        let error = unsafe { blst_p2_uncompress(&mut affine, bytes.as_ptr()) };
        if error != BLST_ERROR::BLST_SUCCESS {
            return Err(format!("octets_to_point_E2: not a valid curve point ({error:?})"));
        }
        unsafe {
            blst_p2_from_affine(&mut point, &affine);
            if !blst_p2_affine_in_g2(&affine) {
                return Err("octets_to_point_E2: point is not in the prime-order subgroup".to_string());
            }
        }
        Ok(G2(point))
    }

    pub fn from_hex(text: &str) -> Result<Self, String> {
        Self::from_compressed(&unhex(text)?)
    }

    pub fn to_compressed(&self) -> [u8; OCTET_POINT_LENGTH_E2] {
        let mut out = [0u8; OCTET_POINT_LENGTH_E2];
        unsafe { blst_p2_compress(out.as_mut_ptr(), &self.0) };
        out
    }

    pub fn to_hex(&self) -> String {
        hex(&self.to_compressed())
    }

    pub fn is_identity(&self) -> bool {
        unsafe { blst_p2_is_inf(&self.0) }
    }

    pub fn add(&self, other: &Self) -> Self {
        let mut out = blst_p2::default();
        unsafe { blst_p2_add_or_double(&mut out, &self.0, &other.0) };
        G2(out)
    }

    pub fn neg(&self) -> Self {
        let mut out = self.0;
        unsafe { blst_p2_cneg(&mut out, true) };
        G2(out)
    }

    pub fn scalar_mul(&self, k: &BigUint) -> Result<Self, String> {
        let octets = scalar_to_little_endian(k)?;
        let mut out = blst_p2::default();
        unsafe { blst_p2_mult(&mut out, &self.0, octets.as_ptr(), OCTET_SCALAR_LENGTH * 8) };
        Ok(G2(out))
    }

    fn to_affine(&self) -> blst_p2_affine {
        let mut out = blst_p2_affine::default();
        unsafe { blst_p2_to_affine(&mut out, &self.0) };
        out
    }
}

impl G1 {
    fn to_affine(&self) -> blst_p1_affine {
        let mut out = blst_p1_affine::default();
        unsafe { blst_p1_to_affine(&mut out, &self.0) };
        out
    }
}

/// The scalar as `blst` wants it: little-endian, range-checked first.
fn scalar_to_little_endian(k: &BigUint) -> Result<[u8; OCTET_SCALAR_LENGTH], String> {
    let mut octets = scalar_to_octets(k)?;
    octets.reverse();
    Ok(octets)
}

/// CoreVerify's group equation: `h(A, W + e·BP2) · h(B, −BP2) == Identity_GT` (§3.6.2 step 3).
pub fn pairing_check(a: &G1, w_plus_e_bp2: &G2, b: &G1) -> bool {
    let neg_bp2 = G2::generator().neg();
    let a_affine = a.to_affine();
    let b_affine = b.to_affine();
    let q1 = w_plus_e_bp2.to_affine();
    let q2 = neg_bp2.to_affine();

    // Initialising from `blst_fp12_one` rather than Default: the binding's derive set for the fp12
    // type does not include Default, and a hand-rolled zero is not the multiplicative identity.
    let mut first = unsafe { *blst::blst_fp12_one() };
    let mut second = unsafe { *blst::blst_fp12_one() };
    unsafe {
        blst_miller_loop(&mut first, &q1, &a_affine);
        blst_miller_loop(&mut second, &q2, &b_affine);
    }
    let mut product = unsafe { *blst::blst_fp12_one() };
    unsafe { blst_fp12_mul(&mut product, &first, &second) };
    let mut gt = unsafe { *blst::blst_fp12_one() };
    unsafe { blst_final_exp(&mut gt, &product) };
    unsafe { blst_fp12_is_one(&gt) }
}

// ---------------------------------------------------------------------------
// Serialization (§4.2.4.1)
// ---------------------------------------------------------------------------

/// One element of a `serialize` array.
pub enum Element<'a> {
    Point(&'a G1),
    Scalar(&'a BigUint),
    Integer(u64),
}

/// §4.2.4.1 `serialize`: G1 point → 48 bytes, scalar → `I2OSP(el, 32)`, integer → `I2OSP(el, 8)`.
pub fn serialize(elements: &[Element]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for element in elements {
        match element {
            Element::Point(point) => out.extend_from_slice(&point.to_compressed()),
            Element::Scalar(scalar) => out.extend_from_slice(&scalar_to_octets(scalar)?),
            Element::Integer(value) => out.extend_from_slice(&value.to_be_bytes()),
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// §4.2.3 calculate_domain, §4.1.2 messages_to_scalars
// ---------------------------------------------------------------------------

/// §4.2.3: `hash_to_scalar(serialize((L, Q_1, H_1..H_L)) || api_id || I2OSP(len(header), 8) ||
/// header, api_id || "H2S_")`.
///
/// The 8-byte header length is appended even when the header is empty, and `PK` is the *octet
/// string*, not the decoded point.
pub fn calculate_domain(
    pk: &[u8],
    q1: &G1,
    h_points: &[G1],
    header: &[u8],
) -> Result<BigUint, String> {
    let mut dom_array: Vec<Element> = Vec::with_capacity(h_points.len() + 2);
    dom_array.push(Element::Integer(h_points.len() as u64));
    dom_array.push(Element::Point(q1));
    for point in h_points {
        dom_array.push(Element::Point(point));
    }
    let mut dom_octs = serialize(&dom_array)?;
    dom_octs.extend_from_slice(&api_id());

    let mut dom_input = Vec::with_capacity(pk.len() + dom_octs.len() + 8 + header.len());
    dom_input.extend_from_slice(pk);
    dom_input.extend_from_slice(&dom_octs);
    dom_input.extend_from_slice(&(header.len() as u64).to_be_bytes());
    dom_input.extend_from_slice(header);
    hash_to_scalar(&dom_input, &dst(H2S_SUFFIX))
}

/// §4.1.2: each message hashed to a scalar with `api_id || "MAP_MSG_TO_SCALAR_AS_HASH_"`.
pub fn messages_to_scalars(messages: &[Vec<u8>]) -> Result<Vec<BigUint>, String> {
    let map_dst = dst(MAP_MSG_TO_SCALAR_SUFFIX);
    messages.iter().map(|m| hash_to_scalar(m, &map_dst)).collect()
}

// ---------------------------------------------------------------------------
// §3.4 keys
// ---------------------------------------------------------------------------

/// §3.4.1 `KeyGen`: `SK = hash_to_scalar(key_material || I2OSP(len(key_info), 2) || key_info,
/// key_dst)`, with `key_dst = api_id || "KEYGEN_DST_"`.
pub fn key_gen(key_material: &[u8], key_info: &[u8]) -> Result<BigUint, String> {
    if key_material.len() < 32 {
        return Err(format!(
            "key_material must be at least 32 bytes, got {}",
            key_material.len()
        ));
    }
    if key_info.len() > 65535 {
        return Err(format!("key_info must be at most 65535 bytes, got {}", key_info.len()));
    }
    let mut derive_input = key_material.to_vec();
    derive_input.extend_from_slice(&(key_info.len() as u16).to_be_bytes());
    derive_input.extend_from_slice(key_info);
    let sk = hash_to_scalar(&derive_input, &dst(KEYGEN_DST_SUFFIX))?;
    if sk == BigUint::from(0u32) {
        return Err("key generation produced the zero scalar".to_string());
    }
    Ok(sk)
}

/// §3.4.2 `SkToPk`: `PK = point_to_octets_E2(SK · BP2)`.
pub fn sk_to_pk(sk: &BigUint) -> Result<[u8; OCTET_POINT_LENGTH_E2], String> {
    Ok(G2::generator().scalar_mul(sk)?.to_compressed())
}

/// §4.2.4.6 `octets_to_pubkey`: decode, subgroup-check, and refuse the identity.
pub fn octets_to_pubkey(pk: &[u8]) -> Result<G2, String> {
    let w = G2::from_compressed(pk)?;
    if w.is_identity() {
        return Err("octets_to_pubkey: the public key is the identity".to_string());
    }
    Ok(w)
}

// ---------------------------------------------------------------------------
// §4.2.4.2/3 signature octets
// ---------------------------------------------------------------------------

/// §4.2.4.2 `signature_to_octets((A, e))`.
pub fn signature_to_octets(a: &G1, e: &BigUint) -> Result<Vec<u8>, String> {
    serialize(&[Element::Point(a), Element::Scalar(e)])
}

/// §4.2.4.3 `octets_to_signature`, refusing a wrong length, a bad point, or the identity.
pub fn octets_to_signature(bytes: &[u8]) -> Result<(G1, BigUint), String> {
    const SIGNATURE_LEN: usize = OCTET_POINT_LENGTH + OCTET_SCALAR_LENGTH;
    if bytes.len() != SIGNATURE_LEN {
        return Err(format!(
            "octets_to_signature: expected {SIGNATURE_LEN} bytes, got {}",
            bytes.len()
        ));
    }
    let a = G1::from_compressed(&bytes[..OCTET_POINT_LENGTH])?;
    if a.is_identity() {
        return Err("octets_to_signature: A is the identity".to_string());
    }
    let e = octets_to_scalar(&bytes[OCTET_POINT_LENGTH..])?;
    Ok((a, e))
}

// ---------------------------------------------------------------------------
// §3.6.1/2 CoreSign and CoreVerify
// ---------------------------------------------------------------------------

/// `B = P1 + Q_1·domain + H_1·msg_1 + … + H_L·msg_L` (CoreSign step 3). Exposed because the draft
/// publishes `B` as a vector intermediate: comparing it localises a mismatch to the `B` computation
/// instead of leaving it buried in a signature that does not match.
pub fn compute_b(
    generators: &[G1],
    msg_scalars: &[BigUint],
    domain: &BigUint,
) -> Result<G1, String> {
    if generators.len() != msg_scalars.len() + 1 {
        return Err(format!(
            "generators must be messages + 1 long: {} generators for {} messages",
            generators.len(),
            msg_scalars.len()
        ));
    }
    let mut b = ciphersuite_p1()?.add(&generators[0].scalar_mul(domain)?);
    for (h_point, message) in generators[1..].iter().zip(msg_scalars) {
        b = b.add(&h_point.scalar_mul(message)?);
    }
    Ok(b)
}

/// §3.6.1 `CoreSign`. Signature generation is deterministic: `e` is hashed, not drawn.
pub fn core_sign(
    sk: &BigUint,
    pk: &[u8],
    generators: &[G1],
    header: &[u8],
    msg_scalars: &[BigUint],
) -> Result<Vec<u8>, String> {
    if generators.len() != msg_scalars.len() + 1 {
        return Err(format!(
            "generators must be messages + 1 long: {} generators for {} messages",
            generators.len(),
            msg_scalars.len()
        ));
    }
    let domain = calculate_domain(pk, &generators[0], &generators[1..], header)?;

    let mut e_input: Vec<Element> = Vec::with_capacity(msg_scalars.len() + 2);
    e_input.push(Element::Scalar(sk));
    for message in msg_scalars {
        e_input.push(Element::Scalar(message));
    }
    e_input.push(Element::Scalar(&domain));
    let e = hash_to_scalar(&serialize(&e_input)?, &dst(H2S_SUFFIX))?;

    let b = compute_b(generators, msg_scalars, &domain)?;

    // A = B · (1/(SK + e)). The draft notes the vanishingly small chance that SK + e ≡ 0; it allows
    // either an error or a refusal, and a refusal is the honest one — the alternative is emitting a
    // signature whose A is the identity.
    let sk_plus_e = add_mod_r(sk, &e);
    if sk_plus_e == BigUint::from(0u32) {
        return Err("SK + e ≡ 0 mod r: refusing rather than producing an invalid signature".to_string());
    }
    let a = b.scalar_mul(&inverse_mod_r(&sk_plus_e)?)?;
    if a.is_identity() {
        return Err("the signature point is the identity".to_string());
    }
    signature_to_octets(&a, &e)
}

/// §3.6.2 `CoreVerify`. Fails closed on every malformed input.
pub fn core_verify(
    pk: &[u8],
    signature: &[u8],
    generators: &[G1],
    header: &[u8],
    msg_scalars: &[BigUint],
) -> bool {
    let Ok((a, e)) = octets_to_signature(signature) else {
        return false;
    };
    let Ok(w) = octets_to_pubkey(pk) else {
        return false;
    };
    if generators.len() != msg_scalars.len() + 1 {
        return false;
    }
    let Ok(domain) = calculate_domain(pk, &generators[0], &generators[1..], header) else {
        return false;
    };
    let Ok(b) = compute_b(generators, msg_scalars, &domain) else {
        return false;
    };
    let Ok(bp2_e) = G2::generator().scalar_mul(&e) else {
        return false;
    };
    pairing_check(&a, &w.add(&bp2_e), &b)
}

// ---------------------------------------------------------------------------
// §3.7 proof subroutines and the proof codecs
// ---------------------------------------------------------------------------

/// `(Abar, Bbar, D, T1, T2, domain)` — what ProofInit and ProofVerifyInit return, and the input
/// ProofChallengeCalculate digests.
pub struct ProofInitResult {
    pub a_bar: G1,
    pub b_bar: G1,
    pub d: G1,
    pub t1: G1,
    pub t2: G1,
    pub domain: BigUint,
}

/// A proof: `(Abar, Bbar, D, e^, r1^, r3^, commitments, c)`.
pub struct Proof {
    pub a_bar: G1,
    pub b_bar: G1,
    pub d: G1,
    pub e_hat: BigUint,
    pub r1_hat: BigUint,
    pub r3_hat: BigUint,
    pub commitments: Vec<BigUint>,
    pub challenge: BigUint,
}

/// Undisclosed indexes: the ascending complement of the disclosed ones within `0..length`.
fn complement(disclosed: &[usize], length: usize) -> Vec<usize> {
    (0..length).filter(|i| !disclosed.contains(i)).collect()
}

/// §3.7.1 `ProofInit`.
fn proof_init(
    pk: &[u8],
    signature: &(G1, BigUint),
    generators: &[G1],
    random_scalars: &[BigUint],
    header: &[u8],
    messages: &[BigUint],
    undisclosed_indexes: &[usize],
) -> Result<ProofInitResult, String> {
    let (a, e) = signature;
    let l = messages.len();
    let u = undisclosed_indexes.len();
    // random_scalars is (r1, r2, e~, r1~, r3~, m~_j1, ..., m~_jU).
    if random_scalars.len() != u + 5 {
        return Err(format!(
            "ProofInit: random_scalars must be undisclosed + 5 long ({} for {u} undisclosed)",
            random_scalars.len()
        ));
    }
    if generators.len() != l + 1 {
        return Err(format!("ProofInit: generators must be messages + 1 long"));
    }
    for &j in undisclosed_indexes {
        if j >= l {
            return Err(format!("ProofInit: undisclosed index {j} is out of range"));
        }
    }
    let domain = calculate_domain(pk, &generators[0], &generators[1..], header)?;

    let b = compute_b(generators, messages, &domain)?;
    let r1 = &random_scalars[0];
    let r2 = &random_scalars[1];
    let d = b.scalar_mul(r2)?;
    let a_bar = a.scalar_mul(&mul_mod_r(r1, r2))?;
    // Bbar = D·r1 − Abar·e
    let b_bar = d
        .scalar_mul(r1)?
        .add(&a_bar.scalar_mul(&neg_mod_r(e))?);

    let e_tilde = &random_scalars[2];
    let r1_tilde = &random_scalars[3];
    let r3_tilde = &random_scalars[4];
    let t1 = a_bar
        .scalar_mul(e_tilde)?
        .add(&d.scalar_mul(r1_tilde)?);
    let mut t2 = d.scalar_mul(r3_tilde)?;
    for (position, &j) in undisclosed_indexes.iter().enumerate() {
        let m_tilde = &random_scalars[5 + position];
        t2 = t2.add(&generators[1 + j].scalar_mul(m_tilde)?);
    }
    Ok(ProofInitResult {
        a_bar,
        b_bar,
        d,
        t1,
        t2,
        domain,
    })
}

/// §3.7.4 `ProofChallengeCalculate`. The array is `(R, i1, msg_i1, …, iR, msg_iR, Abar, Bbar, D, T1,
/// T2, domain)`, then `I2OSP(len(ph), 8) || ph` — the 8-byte length is appended even for an empty
/// presentation header.
fn proof_challenge(
    init: &ProofInitResult,
    disclosed_messages: &[BigUint],
    disclosed_indexes: &[usize],
    ph: &[u8],
) -> Result<BigUint, String> {
    if disclosed_messages.len() != disclosed_indexes.len() {
        return Err(format!(
            "ProofChallengeCalculate: {} messages for {} indexes",
            disclosed_messages.len(),
            disclosed_indexes.len()
        ));
    }
    let mut c_arr: Vec<Element> = Vec::with_capacity(2 + disclosed_indexes.len() * 2 + 5);
    c_arr.push(Element::Integer(disclosed_indexes.len() as u64));
    for (position, &index) in disclosed_indexes.iter().enumerate() {
        c_arr.push(Element::Integer(index as u64));
        c_arr.push(Element::Scalar(&disclosed_messages[position]));
    }
    c_arr.push(Element::Point(&init.a_bar));
    c_arr.push(Element::Point(&init.b_bar));
    c_arr.push(Element::Point(&init.d));
    c_arr.push(Element::Point(&init.t1));
    c_arr.push(Element::Point(&init.t2));
    c_arr.push(Element::Scalar(&init.domain));

    let mut c_octs = serialize(&c_arr)?;
    c_octs.extend_from_slice(&(ph.len() as u64).to_be_bytes());
    c_octs.extend_from_slice(ph);
    hash_to_scalar(&c_octs, &dst(H2S_SUFFIX))
}

/// §3.7.2 `ProofFinalize`.
fn proof_finalize(
    init: &ProofInitResult,
    challenge: &BigUint,
    e_value: &BigUint,
    random_scalars: &[BigUint],
    undisclosed_messages: &[BigUint],
) -> Result<Vec<u8>, String> {
    let u = undisclosed_messages.len();
    if random_scalars.len() != u + 5 {
        return Err("ProofFinalize: random_scalars must be undisclosed + 5 long".to_string());
    }
    let (r1, r2, e_tilde, r1_tilde, r3_tilde) = (
        &random_scalars[0],
        &random_scalars[1],
        &random_scalars[2],
        &random_scalars[3],
        &random_scalars[4],
    );
    let r3 = inverse_mod_r(r2)?;

    let e_hat = add_mod_r(e_tilde, &mul_mod_r(e_value, challenge));
    let r1_hat = sub_mod_r(r1_tilde, &mul_mod_r(r1, challenge));
    let r3_hat = sub_mod_r(r3_tilde, &mul_mod_r(&r3, challenge));
    let mut commitments = Vec::with_capacity(u);
    for position in 0..u {
        commitments.push(add_mod_r(
            &random_scalars[5 + position],
            &mul_mod_r(&undisclosed_messages[position], challenge),
        ));
    }

    proof_to_octets(&Proof {
        a_bar: init.a_bar,
        b_bar: init.b_bar,
        d: init.d,
        e_hat,
        r1_hat,
        r3_hat,
        commitments,
        challenge: challenge.clone(),
    })
}

/// §3.7.3 `ProofVerifyInit`. Note it uses the proof's *own* challenge scalar for `T1`/`T2`; recomputing
/// that challenge and comparing is what CoreProofVerify does next.
fn proof_verify_init(
    pk: &[u8],
    proof: &Proof,
    generators: &[G1],
    header: &[u8],
    disclosed_messages: &[BigUint],
    disclosed_indexes: &[usize],
) -> Result<ProofInitResult, String> {
    let r = disclosed_indexes.len();
    let u = proof.commitments.len();
    let l = r + u;
    if disclosed_messages.len() != r {
        return Err("ProofVerifyInit: disclosed_messages must match disclosed_indexes".to_string());
    }
    for &i in disclosed_indexes {
        if i >= l {
            return Err(format!("ProofVerifyInit: disclosed index {i} is out of range"));
        }
    }
    if generators.len() != l + 1 {
        return Err("ProofVerifyInit: generators must be messages + 1 long".to_string());
    }
    let undisclosed = complement(disclosed_indexes, l);
    if undisclosed.len() != u {
        return Err("ProofVerifyInit: the commitment count does not match the index sets".to_string());
    }
    let domain = calculate_domain(pk, &generators[0], &generators[1..], header)?;
    let c = &proof.challenge;

    // T1 = Bbar·c + Abar·e^ + D·r1^
    let t1 = proof
        .b_bar
        .scalar_mul(c)?
        .add(&proof.a_bar.scalar_mul(&proof.e_hat)?)
        .add(&proof.d.scalar_mul(&proof.r1_hat)?);

    // Bv = P1 + Q_1·domain + Σ H_i·msg_i over the DISCLOSED messages only.
    let mut bv = ciphersuite_p1()?.add(&generators[0].scalar_mul(&domain)?);
    for (position, &i) in disclosed_indexes.iter().enumerate() {
        bv = bv.add(&generators[1 + i].scalar_mul(&disclosed_messages[position])?);
    }

    // T2 = Bv·c + D·r3^ + Σ H_j·m^_j over the undisclosed ones.
    let mut t2 = bv
        .scalar_mul(c)?
        .add(&proof.d.scalar_mul(&proof.r3_hat)?);
    for (position, &j) in undisclosed.iter().enumerate() {
        t2 = t2.add(&generators[1 + j].scalar_mul(&proof.commitments[position])?);
    }

    Ok(ProofInitResult {
        a_bar: proof.a_bar,
        b_bar: proof.b_bar,
        d: proof.d,
        t1,
        t2,
        domain,
    })
}

/// §4.2.4.4 `proof_to_octets`.
pub fn proof_to_octets(proof: &Proof) -> Result<Vec<u8>, String> {
    let mut elements: Vec<Element> = Vec::with_capacity(7 + proof.commitments.len());
    elements.push(Element::Point(&proof.a_bar));
    elements.push(Element::Point(&proof.b_bar));
    elements.push(Element::Point(&proof.d));
    elements.push(Element::Scalar(&proof.e_hat));
    elements.push(Element::Scalar(&proof.r1_hat));
    elements.push(Element::Scalar(&proof.r3_hat));
    for commitment in &proof.commitments {
        elements.push(Element::Scalar(commitment));
    }
    elements.push(Element::Scalar(&proof.challenge));
    serialize(&elements)
}

/// §4.2.4.5 `octets_to_proof`: three subgroup-checked non-identity points, then scalars that must each
/// be in `[1, r-1]`. The commitment count is implied by the length, which is why a truncated proof is
/// refused rather than parsed as a shorter one.
pub fn octets_to_proof(bytes: &[u8]) -> Result<Proof, String> {
    const PROOF_LEN_FLOOR: usize = 3 * OCTET_POINT_LENGTH + 4 * OCTET_SCALAR_LENGTH;
    if bytes.len() < PROOF_LEN_FLOOR {
        return Err(format!(
            "octets_to_proof: expected at least {PROOF_LEN_FLOOR} bytes, got {}",
            bytes.len()
        ));
    }
    if (bytes.len() - 3 * OCTET_POINT_LENGTH) % OCTET_SCALAR_LENGTH != 0 {
        return Err("octets_to_proof: the scalar section is not a whole number of scalars".to_string());
    }

    let mut points = Vec::with_capacity(3);
    for i in 0..3 {
        let start = i * OCTET_POINT_LENGTH;
        let point = G1::from_compressed(&bytes[start..start + OCTET_POINT_LENGTH])?;
        if point.is_identity() {
            return Err("octets_to_proof: a proof point is the identity".to_string());
        }
        points.push(point);
    }

    let mut scalars = Vec::new();
    let mut index = 3 * OCTET_POINT_LENGTH;
    while index < bytes.len() {
        scalars.push(octets_to_scalar(&bytes[index..index + OCTET_SCALAR_LENGTH])?);
        index += OCTET_SCALAR_LENGTH;
    }
    if scalars.len() < 4 {
        return Err("octets_to_proof: a proof needs at least four scalars".to_string());
    }
    let challenge = scalars[scalars.len() - 1].clone();
    let commitments = scalars[3..scalars.len() - 1].to_vec();
    Ok(Proof {
        a_bar: points[0],
        b_bar: points[1],
        d: points[2],
        e_hat: scalars[0].clone(),
        r1_hat: scalars[1].clone(),
        r3_hat: scalars[2].clone(),
        commitments,
        challenge,
    })
}

/// §3.6.3 `CoreProofGen`, with the random scalars injected so the published proof vectors can drive it
/// deterministically. The real path is `core_proof_gen`.
pub fn core_proof_gen_with_scalars(
    pk: &[u8],
    signature: &(G1, BigUint),
    generators: &[G1],
    header: &[u8],
    ph: &[u8],
    messages: &[BigUint],
    disclosed_indexes: &[usize],
    random_scalars: &[BigUint],
) -> Result<Vec<u8>, String> {
    let l = messages.len();
    let r = disclosed_indexes.len();
    if r > l {
        return Err("CoreProofGen: more disclosed indexes than messages".to_string());
    }
    for &i in disclosed_indexes {
        if i >= l {
            return Err(format!("CoreProofGen: disclosed index {i} is out of range"));
        }
    }
    let undisclosed = complement(disclosed_indexes, l);
    if random_scalars.len() != undisclosed.len() + 5 {
        return Err(format!(
            "CoreProofGen: random_scalars must be 5 + U long ({} for {} undisclosed)",
            random_scalars.len(),
            undisclosed.len()
        ));
    }
    let disclosed_messages: Vec<BigUint> = disclosed_indexes
        .iter()
        .map(|&i| messages[i].clone())
        .collect();
    let undisclosed_messages: Vec<BigUint> =
        undisclosed.iter().map(|&j| messages[j].clone()).collect();

    let init = proof_init(
        pk,
        signature,
        generators,
        random_scalars,
        header,
        messages,
        &undisclosed,
    )?;
    let challenge = proof_challenge(&init, &disclosed_messages, disclosed_indexes, ph)?;
    proof_finalize(
        &init,
        &challenge,
        &signature.1,
        random_scalars,
        &undisclosed_messages,
    )
}

/// §3.6.3 `CoreProofGen` on the real path: fresh random scalars per proof.
pub fn core_proof_gen(
    pk: &[u8],
    signature: &(G1, BigUint),
    generators: &[G1],
    header: &[u8],
    ph: &[u8],
    messages: &[BigUint],
    disclosed_indexes: &[usize],
) -> Result<Vec<u8>, String> {
    let undisclosed_count = messages.len().saturating_sub(disclosed_indexes.len());
    let random_scalars = calculate_random_scalars(undisclosed_count + 5)?;
    core_proof_gen_with_scalars(
        pk,
        signature,
        generators,
        header,
        ph,
        messages,
        disclosed_indexes,
        &random_scalars,
    )
}

/// §3.6.4 `CoreProofVerify`. Fails closed, and checks the challenge before the pairing.
pub fn core_proof_verify(
    pk: &[u8],
    proof_bytes: &[u8],
    generators: &[G1],
    header: &[u8],
    ph: &[u8],
    disclosed_messages: &[BigUint],
    disclosed_indexes: &[usize],
) -> bool {
    let Ok(proof) = octets_to_proof(proof_bytes) else {
        return false;
    };
    let Ok(w) = octets_to_pubkey(pk) else {
        return false;
    };
    let Ok(init) = proof_verify_init(pk, &proof, generators, header, disclosed_messages, disclosed_indexes)
    else {
        return false;
    };
    let Ok(challenge) = proof_challenge(&init, disclosed_messages, disclosed_indexes, ph) else {
        return false;
    };
    if proof.challenge != challenge {
        return false;
    }
    // h(Abar, W) · h(Bbar, −BP2) == Identity_GT
    pairing_check(&proof.a_bar, &w, &proof.b_bar)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ciphersuite_seed_derivation_reproduces_the_p1_literal() {
        // §7.2: P1 is create_generators(count = 1) under the ciphersuite's own Definitions, and
        // §7.2.2 prints it. Every earlier step — the legacy seed, both DSTs, the seeded
        // expand_message chain, hash_to_curve — has to be right for these 48 bytes to come out.
        let p1 = ciphersuite_p1().expect("P1");
        assert_eq!(
            p1.to_hex(),
            P1_COMPRESSED_HEX,
            "P1 must match the ciphersuite's published value"
        );
    }

    #[test]
    fn the_interface_generators_do_not_start_at_p1() {
        // The trap §7.2 warns about: the interface's create_generators uses `api_id ||
        // "MESSAGE_GENERATOR_SEED"`, not the ciphersuite's `…BP_MESSAGE_GENERATOR_SEED`, so its
        // generator_1 is Q_1 and not the P1 constant. Asserted so a future "simplification" that
        // folds them together fails here instead of silently producing wrong signatures.
        let generators = create_generators(1).unwrap();
        assert_ne!(
            generators[0].to_hex(),
            P1_COMPRESSED_HEX,
            "generator_1 of the interface is Q_1, not P1"
        );
        assert_ne!(
            generators[0].to_hex(),
            ciphersuite_p1().unwrap().to_hex(),
            "the two derivations use different seeds"
        );
    }

    #[test]
    fn hash_to_scalar_matches_the_draft_vector() {
        // Draft-08 Appendix D.2.3: msg, dst = api_id || "H2S_", and the resulting scalar.
        let msg = unhex("9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02").unwrap();
        let expected_dst_text =
            "4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4832535f";
        let expected_dst = unhex(expected_dst_text).unwrap();
        assert_eq!(
            dst(H2S_SUFFIX),
            expected_dst,
            "the vector's dst must be the api_id || \"H2S_\" this module builds"
        );
        let scalar = hash_to_scalar(&msg, &dst(H2S_SUFFIX)).unwrap();
        assert_eq!(
            scalar.to_bytes_be(),
            unhex("0f90cbee27beb214e6545becb8404640d3612da5d6758dffeccd77ed7169807c").unwrap(),
            "hash_to_scalar must match the draft's D.2.3 vector"
        );
    }

    #[test]
    fn scalar_multiplication_uses_the_expected_byte_order() {
        // Pins the convention empirically: if the scalar bytes were read in the wrong order, 1 would
        // not be the identity operation and 2 would not equal P + P.
        let p = create_generators(1).unwrap().remove(0);
        let one = BigUint::from(1u32);
        let two = BigUint::from(2u32);
        assert_eq!(p.scalar_mul(&one).unwrap().to_hex(), p.to_hex(), "1*P must be P");
        assert_eq!(
            p.scalar_mul(&two).unwrap().to_hex(),
            p.add(&p).to_hex(),
            "2*P must be P + P"
        );
    }

    #[test]
    fn scalar_mul_refuses_a_scalar_at_or_above_the_group_order() {
        let p = create_generators(1).unwrap().remove(0);
        let r = scalar_field_order();
        assert!(p.scalar_mul(&r).is_err(), "r is out of range");
        let one = BigUint::from(1u32);
        let r_minus_1 = &r - &one;
        assert!(p.scalar_mul(&r_minus_1).is_ok(), "r-1 is in range");
    }

    #[test]
    fn points_round_trip_and_bad_encodings_are_refused() {
        let p = create_generators(1).unwrap().remove(0);
        let encoded = p.to_compressed();
        assert_eq!(G1::from_compressed(&encoded).unwrap().to_hex(), p.to_hex());

        assert!(G1::from_compressed(&encoded[..47]).is_err(), "short encoding");
        let mut flipped = encoded;
        flipped[10] ^= 0x01;
        assert!(
            G1::from_compressed(&flipped).is_err(),
            "a point not on the curve (or not in the subgroup) must be refused"
        );
        assert!(
            G1::from_compressed(&[0xffu8; OCTET_POINT_LENGTH]).is_err(),
            "an all-ones encoding must be refused"
        );
    }

    #[test]
    fn generators_are_distinct_non_identity_subgroup_points() {
        let generators = create_generators(6).unwrap();
        assert_eq!(generators.len(), 6);
        let mut seen = std::collections::HashSet::new();
        for generator in &generators {
            assert!(!generator.is_identity(), "a generator must not be the identity");
            assert!(seen.insert(generator.to_hex()), "generators must be distinct");
            // Subgroup membership, on the projective form and on the encoding it round-trips to.
            assert!(
                unsafe { blst_p1_in_g1(&generator.0) },
                "a generator must be in the prime-order subgroup"
            );
            G1::from_compressed(&generator.to_compressed()).expect("in the subgroup");
        }
    }

    #[test]
    fn scalar_field_helpers_agree_with_the_group_order() {
        let r = scalar_field_order();
        let one = BigUint::from(1u32);
        assert_eq!(r.bits(), 255, "log2(r) = 255 for BLS12-381");
        assert_eq!(add_mod_r(&r, &one), one, "r + 1 reduces to 1");
        let r_minus_1 = &r - &one;
        assert_eq!(mul_mod_r(&r_minus_1, &r_minus_1), one, "(r-1)^2 = 1 mod r");
        assert!(scalar_to_octets(&r).is_err(), "r is not a valid scalar");
        assert_eq!(
            scalar_to_octets(&one).unwrap(),
            {
                let mut expected = [0u8; 32];
                expected[31] = 1;
                expected
            },
            "I2OSP(1, 32) is 31 zero bytes then 1"
        );
    }

    // ── §8.4 fixtures, parsed from the repo fixture (extracted mechanically from the draft) ──

    const FIXTURE: &str = include_str!("../tests/fixtures/bbs-bls12381-sha256-8.4.txt");

    fn fixtures() -> std::collections::HashMap<String, Vec<u8>> {
        let mut out = std::collections::HashMap::new();
        for line in FIXTURE.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            // Split on '=' and trim each side: the fixture's empty values (m_10 is the empty message)
            // end a line with "= " and a trim would otherwise eat the separator.
            let (name, value) = line
                .split_once('=')
                .unwrap_or_else(|| panic!("fixture line is not 'block.field = hex': {line:?}"));
            let name = name.trim();
            let value = value.trim();
            if value.contains(',') {
                continue; // an index list, read by fixture_index_lists()
            }
            out.insert(
                name.to_string(),
                unhex(value).unwrap_or_else(|e| panic!("fixture field {name}: {e}")),
            );
        }
        out
    }

    /// The fixtures' bracketed index lists (`revealed_indexes = "0,2,4,6"`), which are not hex.
    fn fixture_index_lists() -> std::collections::HashMap<String, Vec<usize>> {
        let mut out = std::collections::HashMap::new();
        for line in FIXTURE.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((name, value)) = line.split_once('=') else {
                continue;
            };
            let value = value.trim();
            if !value.contains(',') {
                continue;
            }
            out.insert(
                name.trim().to_string(),
                value
                    .split(',')
                    .filter_map(|part| part.trim().parse::<usize>().ok())
                    .collect(),
            );
        }
        out
    }

    fn field<'a>(v: &'a std::collections::HashMap<String, Vec<u8>>, name: &str) -> &'a [u8] {
        v.get(name)
            .unwrap_or_else(|| panic!("fixture has no field {name}"))
            .as_slice()
    }

    fn fixture_messages(
        v: &std::collections::HashMap<String, Vec<u8>>,
        block: &str,
        count: usize,
    ) -> Vec<Vec<u8>> {
        (1..=count)
            .map(|i| field(v, &format!("{block}.m_{i}")).to_vec())
            .collect()
    }

    #[test]
    fn create_generators_matches_the_drafts_published_generators() {
        // §8.4.3 prints Q_1 and H_1..H_10 for count = 11 — the interface's own derivation, which
        // increment 1 could only check for distinctness and subgroup membership.
        let v = fixtures();
        let generators = create_generators(11).expect("generators");
        assert_eq!(generators.len(), 11);
        assert_eq!(generators[0].to_hex(), hex(field(&v, "generators.Q_1")), "generator_1 is Q_1");
        for i in 1..=10 {
            assert_eq!(
                generators[i].to_hex(),
                hex(field(&v, &format!("generators.H_{i}"))),
                "H_{i} must match the draft"
            );
        }
    }

    #[test]
    fn messages_to_scalars_matches_the_drafts_dst_and_scalars() {
        let v = fixtures();
        assert_eq!(
            dst(MAP_MSG_TO_SCALAR_SUFFIX),
            field(&v, "msgscalars.dst").to_vec(),
            "the map dst must be api_id || \"MAP_MSG_TO_SCALAR_AS_HASH_\""
        );
        let scalars = messages_to_scalars(&fixture_messages(&v, "messages", 10)).expect("scalars");
        for i in 1..=10 {
            assert_eq!(
                scalar_to_octets(&scalars[i - 1]).unwrap().as_slice(),
                field(&v, &format!("msgscalars.msg_scalar_{i}")),
                "msg_scalar_{i} must match the draft"
            );
        }
    }

    #[test]
    fn key_gen_and_sk_to_pk_match_the_drafts_key_pair() {
        let v = fixtures();
        assert_eq!(
            dst(KEYGEN_DST_SUFFIX),
            field(&v, "key.key_dst").to_vec(),
            "key_dst must be api_id || \"KEYGEN_DST_\""
        );
        let sk = key_gen(field(&v, "key.key_material"), field(&v, "key.key_info")).expect("keygen");
        assert_eq!(sk.to_bytes_be().as_slice(), field(&v, "key.SK"), "SK must match");
        let pk = sk_to_pk(&sk).expect("public key");
        assert_eq!(
            pk.as_slice(),
            field(&v, "key.PK"),
            "PK must match — this is SK · BP2 in G2, so it checks the G2 layer and BP2"
        );
        // A too-short key_material is refused rather than silently accepted.
        assert!(key_gen(&field(&v, "key.key_material")[..31], &[]).is_err());
    }

    #[test]
    fn calculate_domain_and_b_match_the_single_message_fixture() {
        let v = fixtures();
        let generators = create_generators(2).expect("generators");
        let pk = field(&v, "sign1.PK");
        let header = field(&v, "sign1.header");
        let domain = calculate_domain(pk, &generators[0], &generators[1..], header).expect("domain");
        assert_eq!(
            scalar_to_octets(&domain).unwrap().as_slice(),
            field(&v, "sign1.domain"),
            "calculate_domain must match the fixture"
        );
        let msg_scalars =
            messages_to_scalars(&fixture_messages(&v, "sign1", 1)).expect("message scalars");
        assert_eq!(
            compute_b(&generators, &msg_scalars, &domain).expect("B").to_hex(),
            hex(field(&v, "sign1.B")),
            "B = P1 + Q_1·domain + H_1·msg_1 must match the fixture"
        );
    }

    #[test]
    fn core_sign_matches_the_single_message_fixture_and_verifies() {
        let v = fixtures();
        let generators = create_generators(2).expect("generators");
        let pk = field(&v, "sign1.PK");
        let header = field(&v, "sign1.header");
        let msg_scalars =
            messages_to_scalars(&fixture_messages(&v, "sign1", 1)).expect("message scalars");
        let sk = octets_to_scalar(field(&v, "sign1.SK")).expect("SK");

        let signature =
            core_sign(&sk, pk, &generators, header, &msg_scalars).expect("signature");
        assert_eq!(
            signature.as_slice(),
            field(&v, "sign1.signature"),
            "CoreSign must reproduce the fixture signature byte for byte"
        );
        assert!(
            core_verify(pk, &signature, &generators, header, &msg_scalars),
            "the fixture's own signature must verify"
        );
    }

    #[test]
    fn core_sign_and_verify_match_the_multi_message_fixture() {
        let v = fixtures();
        let messages = fixture_messages(&v, "sign10", 10);
        let generators = create_generators(messages.len() + 1).expect("generators");
        let msg_scalars = messages_to_scalars(&messages).expect("message scalars");
        let pk = field(&v, "sign10.PK");
        let header = field(&v, "sign10.header");
        let sk = octets_to_scalar(field(&v, "sign10.SK")).expect("SK");

        let signature = core_sign(&sk, pk, &generators, header, &msg_scalars).expect("signature");
        assert_eq!(
            signature.as_slice(),
            field(&v, "sign10.signature"),
            "the 10-message signature must match the fixture"
        );
        assert!(core_verify(pk, &signature, &generators, header, &msg_scalars));
    }

    #[test]
    fn core_verify_rejects_the_drafts_tampered_cases() {
        let v = fixtures();
        let messages = fixture_messages(&v, "sign10", 10);
        let generators = create_generators(11).expect("generators");
        let msg_scalars = messages_to_scalars(&messages).expect("message scalars");
        let pk = field(&v, "sign10.PK");
        let header = field(&v, "sign10.header");
        let signature = field(&v, "sign10.signature").to_vec();
        assert!(
            core_verify(pk, &signature, &generators, header, &msg_scalars),
            "the untampered fixture must verify first, or the refusals below prove nothing"
        );

        // §D.2.1.2 modified message.
        let mut modified = msg_scalars.clone();
        modified[0] = add_mod_r(&modified[0], &BigUint::from(1u32));
        assert!(!core_verify(pk, &signature, &generators, header, &modified), "modified message");
        // §D.2.1.4 missing message: one fewer message no longer matches 11 generators.
        assert!(
            !core_verify(pk, &signature, &generators, header, &msg_scalars[..9]),
            "missing message"
        );
        // §D.2.1.5 reordered messages.
        let mut reordered = msg_scalars.clone();
        reordered.swap(0, 1);
        assert!(!core_verify(pk, &signature, &generators, header, &reordered), "reordered messages");
        // §D.2.1.7 wrong header.
        let mut wrong_header = header.to_vec();
        wrong_header[0] ^= 0x01;
        assert!(
            !core_verify(pk, &signature, &generators, &wrong_header, &msg_scalars),
            "wrong header"
        );
        // §D.2.1.6 wrong public key. NOTE: the draft's two Sign fixtures share one key pair (the same
        // SK and PK appear in §8.4.4.1 and §8.4.4.2), so borrowing the other fixture's PK proves
        // nothing — a different, valid key has to be constructed.
        let other_sk = add_mod_r(&octets_to_scalar(field(&v, "sign10.SK")).unwrap(), &BigUint::from(1u32));
        let other_pk = sk_to_pk(&other_sk).expect("a second public key");
        assert_ne!(other_pk.as_slice(), field(&v, "sign10.PK"), "the keys must differ");
        assert!(
            !core_verify(&other_pk, &signature, &generators, header, &msg_scalars),
            "wrong public key"
        );
        // A tampered signature and a truncated one.
        let mut tampered = signature.clone();
        tampered[3] ^= 0x08;
        assert!(!core_verify(pk, &tampered, &generators, header, &msg_scalars), "tampered signature");
        assert!(
            !core_verify(pk, &signature[..79], &generators, header, &msg_scalars),
            "truncated signature"
        );
        // The messages that were never signed (§D.2.1.3: an extra unsigned message appended).
        let mut extra = messages.clone();
        extra.push(b"an unsigned message".to_vec());
        let mut extra_scalars = msg_scalars.clone();
        extra_scalars.extend(messages_to_scalars(&[b"an unsigned message".to_vec()]).unwrap());
        assert!(
            !core_verify(pk, &signature, &generators, header, &extra_scalars),
            "an unsigned message must not be accepted"
        );
    }

    #[test]
    fn octets_to_pubkey_and_signature_refuse_malformed_input() {
        let v = fixtures();
        assert_eq!(
            OCTET_POINT_LENGTH_E2,
            field(&v, "key.PK").len(),
            "a public key is a compressed G2 point"
        );
        assert!(octets_to_pubkey(&[0u8; 96]).is_err(), "an all-zero public key is not a point");
        assert!(
            octets_to_pubkey(&field(&v, "key.PK")[..95]).is_err(),
            "a short public key is refused"
        );
        // The compressed encoding of the identity (compression and infinity bits set, payload zero)
        // must be refused: §4.2.4.6 step 4.
        let mut identity = [0u8; 96];
        identity[0] = 0xc0;
        assert!(octets_to_pubkey(&identity).is_err(), "the identity is not a valid public key");

        assert!(octets_to_signature(&[0u8; 80]).is_err(), "an all-zero signature is refused");
        assert!(
            octets_to_signature(&field(&v, "sign1.signature")[..79]).is_err(),
            "a short signature is refused"
        );
        assert!(
            octets_to_signature(&[0u8; 80]).is_err(),
            "a signature whose A is not on the curve is refused, not parsed"
        );
    }

    #[test]
    fn inverse_mod_r_is_a_real_inverse() {
        for candidate in [1u32, 2, 7, 65537] {
            let a = BigUint::from(candidate);
            let inverse = inverse_mod_r(&a).expect("invertible");
            assert_eq!(mul_mod_r(&a, &inverse), BigUint::from(1u32), "{a} * its inverse is 1");
        }
        assert!(inverse_mod_r(&BigUint::from(0u32)).is_err(), "zero has no inverse");
        assert!(inverse_mod_r(&scalar_field_order()).is_err(), "r is 0 mod r and has no inverse");
    }

    #[test]
    fn seeded_random_scalars_matches_the_drafts_mock_vectors() {
        let v = fixtures();
        // §8.4.5 states the DST as an ASCII string, so it is written here rather than hex-decoded:
        // api_id || "MOCK_RANDOM_SCALARS_DST_". A wrong DST changes every scalar below, so the
        // vectors check it even though it is not extracted.
        assert_eq!(
            dst(MOCK_RANDOM_SCALARS_SUFFIX),
            b"BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_".to_vec(),
            "DST must be api_id || \"MOCK_RANDOM_SCALARS_DST_\""
        );
        let seed = field(&v, "proofs.SEED").to_vec();
        assert_eq!(
            String::from_utf8_lossy(&seed),
            "3.141592653589793238462643383279",
            "SEED is the ASCII of pi's first 30 digits, decimal point included"
        );

        let scalars = seeded_random_scalars(&seed, &dst(MOCK_RANDOM_SCALARS_SUFFIX), 10)
            .expect("mocked scalars");
        for i in 1..=10 {
            assert_eq!(
                scalar_to_octets(&scalars[i - 1]).unwrap().as_slice(),
                field(&v, &format!("proofs.random_scalar_{i}")),
                "random_scalar_{i} must match the draft"
            );
        }

        // The §8.1 abort, and the tighter expand_message_xmd cap for SHA-256 (255 * 32 bytes = 170
        // scalars), which the draft's note states as 170.
        assert!(seeded_random_scalars(&seed, b"d", 1366).is_err(), "count * 48 > 65535 aborts");
        assert!(seeded_random_scalars(&seed, b"d", 171).is_err(), "171 scalars exceeds the xmd cap");
        assert!(seeded_random_scalars(&seed, b"d", 170).is_ok(), "170 scalars is the limit");
        assert_eq!(seeded_random_scalars(&seed, b"d", 0).unwrap().len(), 0, "count 0 is empty");
    }

    #[test]
    fn calculate_random_scalars_are_in_range_and_distinct() {
        let scalars = calculate_random_scalars(6).expect("scalars");
        assert_eq!(scalars.len(), 6);
        let r = scalar_field_order();
        let mut seen = std::collections::HashSet::new();
        for scalar in &scalars {
            assert!(scalar < &r, "every scalar is in [0, r)");
            assert!(seen.insert(scalar.to_bytes_be()), "fresh draws must not collide");
        }
        assert_eq!(calculate_random_scalars(0).unwrap().len(), 0);
    }

    // ── §3.7 / Appendix D.2.2: the NIZK proof vectors ──

    struct ProofCase {
        generators: Vec<G1>,
        msg_scalars: Vec<BigUint>,
        undisclosed: Vec<usize>,
        disclosed: Vec<usize>,
        disclosed_messages: Vec<BigUint>,
        undisclosed_messages: Vec<BigUint>,
        random_scalars: Vec<BigUint>,
    }

    /// The shared setup for a proof vector: 10 messages, the generators, the disclosed/undisclosed
    /// split from the fixture's index list, and the mocked random scalars (§8.1, same SEED/DST).
    fn proof_case(
        hex: &std::collections::HashMap<String, Vec<u8>>,
        lists: &std::collections::HashMap<String, Vec<usize>>,
        block: &str,
    ) -> ProofCase {
        let messages = fixture_messages(hex, block, 10);
        let generators = create_generators(messages.len() + 1).expect("generators");
        let msg_scalars = messages_to_scalars(&messages).expect("message scalars");
        let disclosed = lists
            .get(&format!("{block}.revealed_indexes"))
            .unwrap_or_else(|| panic!("no {block}.revealed_indexes in the fixture"))
            .clone();
        let undisclosed: Vec<usize> = (0..msg_scalars.len())
            .filter(|i| !disclosed.contains(i))
            .collect();
        let disclosed_messages: Vec<BigUint> =
            disclosed.iter().map(|&i| msg_scalars[i].clone()).collect();
        let undisclosed_messages: Vec<BigUint> = undisclosed
            .iter()
            .map(|&j| msg_scalars[j].clone())
            .collect();
        let seed = field(hex, "proofs.SEED").to_vec();
        let random_scalars = seeded_random_scalars(
            &seed,
            &dst(MOCK_RANDOM_SCALARS_SUFFIX),
            undisclosed.len() + 5,
        )
        .expect("mocked random scalars");
        ProofCase {
            generators,
            msg_scalars,
            undisclosed,
            disclosed,
            disclosed_messages,
            undisclosed_messages,
            random_scalars,
        }
    }

    #[test]
    fn core_proof_gen_matches_the_draft_proof_vector_stage_by_stage() {
        let hex = fixtures();
        let lists = fixture_index_lists();
        let case = proof_case(&hex, &lists, "d22_1");
        assert_eq!(case.disclosed, vec![0, 2, 4, 6], "the vector discloses 0,2,4,6");
        assert_eq!(case.undisclosed.len(), 6);
        let pk = field(&hex, "d22_1.public_key");
        let header = field(&hex, "d22_1.header");
        let ph = field(&hex, "d22_1.presentation_header");
        let signature = octets_to_signature(field(&hex, "d22_1.signature")).expect("signature");
        assert!(header.is_empty(), "this fixture has no header (hence its name)");
        assert!(!ph.is_empty(), "and it does have a presentation header");

        // Stage 1: domain, as ProofInit computes it.
        let init = proof_init(
            pk,
            &signature,
            &case.generators,
            &case.random_scalars,
            header,
            &case.msg_scalars,
            &case.undisclosed,
        )
        .expect("proof init");
        assert_eq!(
            scalar_to_octets(&init.domain).unwrap().as_slice(),
            field(&hex, "d22_1.domain"),
            "the proof's domain must match the vector"
        );

        // Stage 2: the Fiat-Shamir challenge.
        let challenge = proof_challenge(&init, &case.disclosed_messages, &case.disclosed, ph)
            .expect("challenge");
        assert_eq!(
            scalar_to_octets(&challenge).unwrap().as_slice(),
            field(&hex, "d22_1.challenge"),
            "the challenge must match the vector"
        );

        // Stage 3: the full proof, byte for byte.
        let proof = core_proof_gen_with_scalars(
            pk,
            &signature,
            &case.generators,
            header,
            ph,
            &case.msg_scalars,
            &case.disclosed,
            &case.random_scalars,
        )
        .expect("proof");
        assert_eq!(
            proof.len(),
            464,
            "3 points (144) + 3 scalars (96) + 6 commitments (192) + c (32)"
        );
        assert_eq!(proof.as_slice(), field(&hex, "d22_1.proof"), "the proof must match");

        // And the draft's own proof verifies against the disclosed subset only.
        assert!(
            core_proof_verify(
                pk,
                &proof,
                &case.generators,
                header,
                ph,
                &case.disclosed_messages,
                &case.disclosed
            ),
            "the vector's proof must verify"
        );
    }

    #[test]
    fn the_second_proof_vector_matches_its_published_t1_and_t2() {
        // This fixture publishes T1 and T2, which are ProofVerifyInit's output — so a mismatch here
        // localises to that subroutine instead of hiding in a boolean.
        let v = fixtures();
        let lists = fixture_index_lists();
        let case = proof_case(&v, &lists, "d22_2");
        let pk = field(&v, "d22_2.public_key");
        let header = field(&v, "d22_2.header");
        let ph = field(&v, "d22_2.presentation_header");
        assert!(!header.is_empty(), "this fixture has a header");
        assert!(ph.is_empty(), "and no presentation header");

        let proof_bytes = field(&v, "d22_2.proof").to_vec();
        let parsed = octets_to_proof(&proof_bytes).expect("proof");
        let init = proof_verify_init(
            pk,
            &parsed,
            &case.generators,
            header,
            &case.disclosed_messages,
            &case.disclosed,
        )
        .expect("verify init");
        assert_eq!(init.t1.to_hex(), hex(field(&v, "d22_2.T1")), "T1 must match");
        assert_eq!(init.t2.to_hex(), hex(field(&v, "d22_2.T2")), "T2 must match");
        assert_eq!(
            scalar_to_octets(&init.domain).unwrap().as_slice(),
            field(&v, "d22_2.domain"),
            "the verify-init domain must match"
        );

        // Regenerating it with the same mocked scalars reproduces the bytes, and it verifies.
        let signature = octets_to_signature(field(&v, "d22_2.signature")).expect("signature");
        let regenerated = core_proof_gen_with_scalars(
            pk,
            &signature,
            &case.generators,
            header,
            ph,
            &case.msg_scalars,
            &case.disclosed,
            &case.random_scalars,
        )
        .expect("proof");
        assert_eq!(
            regenerated.as_slice(),
            proof_bytes.as_slice(),
            "the regenerated proof must match the vector"
        );
        assert!(core_proof_verify(
            pk,
            &proof_bytes,
            &case.generators,
            header,
            ph,
            &case.disclosed_messages,
            &case.disclosed
        ));
    }

    #[test]
    fn core_proof_verify_rejects_tampered_proofs_and_wrong_inputs() {
        let hex = fixtures();
        let lists = fixture_index_lists();
        let case = proof_case(&hex, &lists, "d22_1");
        let pk = field(&hex, "d22_1.public_key");
        let header = field(&hex, "d22_1.header");
        let ph = field(&hex, "d22_1.presentation_header");
        let proof = field(&hex, "d22_1.proof").to_vec();
        assert!(
            core_proof_verify(pk, &proof, &case.generators, header, ph, &case.disclosed_messages, &case.disclosed),
            "the untampered proof must verify first"
        );

        // A different presentation header, and a header that is not empty.
        let mut wrong_ph = ph.to_vec();
        wrong_ph[0] ^= 0x01;
        assert!(!core_proof_verify(pk, &proof, &case.generators, header, &wrong_ph, &case.disclosed_messages, &case.disclosed), "wrong presentation header");
        assert!(!core_proof_verify(pk, &proof, &case.generators, b"\x00", ph, &case.disclosed_messages, &case.disclosed), "a header this proof was not made for");
        // No presentation header when one was used.
        assert!(!core_proof_verify(pk, &proof, &case.generators, header, b"", &case.disclosed_messages, &case.disclosed), "missing presentation header");

        // A different disclosed message, and a different index set.
        let mut wrong_messages = case.disclosed_messages.clone();
        wrong_messages[0] = add_mod_r(&wrong_messages[0], &BigUint::from(1u32));
        assert!(!core_proof_verify(pk, &proof, &case.generators, header, ph, &wrong_messages, &case.disclosed), "modified disclosed message");
        let other_indexes = vec![0, 2, 4, 7];
        let other_messages: Vec<BigUint> = other_indexes.iter().map(|&i| case.msg_scalars[i].clone()).collect();
        assert!(!core_proof_verify(pk, &proof, &case.generators, header, ph, &other_messages, &other_indexes), "a different disclosed index set");

        // A different public key.
        let other_pk = sk_to_pk(&add_mod_r(&octets_to_scalar(field(&hex, "key.SK")).unwrap(), &BigUint::from(1u32))).unwrap();
        assert!(!core_proof_verify(&other_pk, &proof, &case.generators, header, ph, &case.disclosed_messages, &case.disclosed), "wrong public key");

        // Tampering: a point bit, a scalar bit, a truncated proof, and a zero scalar.
        let mut point_tampered = proof.clone();
        point_tampered[5] ^= 0x04;
        assert!(!core_proof_verify(pk, &point_tampered, &case.generators, header, ph, &case.disclosed_messages, &case.disclosed), "tampered point");
        let mut scalar_tampered = proof.clone();
        scalar_tampered[200] ^= 0x01;
        assert!(!core_proof_verify(pk, &scalar_tampered, &case.generators, header, ph, &case.disclosed_messages, &case.disclosed), "tampered scalar");
        assert!(!core_proof_verify(pk, &proof[..463], &case.generators, header, ph, &case.disclosed_messages, &case.disclosed), "truncated proof");
        let mut zero_scalar = proof.clone();
        for byte in zero_scalar.iter_mut().skip(150).take(32) {
            *byte = 0;
        }
        assert!(!core_proof_verify(pk, &zero_scalar, &case.generators, header, ph, &case.disclosed_messages, &case.disclosed), "a zero scalar is refused by the codec");
    }

    #[test]
    fn octets_to_proof_refuses_malformed_input() {
        let hex = fixtures();
        let good = field(&hex, "d22_1.proof");
        assert!(octets_to_proof(good).is_ok());
        assert!(octets_to_proof(&[0u8; 271]).is_err(), "below the length floor");
        assert!(octets_to_proof(&good[..good.len() - 1]).is_err(), "not a whole number of scalars");
        let mut bad_point = good.to_vec();
        bad_point[0] = 0xff;
        assert!(octets_to_proof(&bad_point).is_err(), "a point that is not on the curve");
        let mut identity = good.to_vec();
        identity[..48].copy_from_slice(&{
            let mut encoded = [0u8; 48];
            encoded[0] = 0xc0;
            encoded
        });
        assert!(octets_to_proof(&identity).is_err(), "the identity is not a valid proof point");
        let mut zero = good.to_vec();
        for byte in zero.iter_mut().skip(144).take(32) {
            *byte = 0;
        }
        assert!(octets_to_proof(&zero).is_err(), "scalars must be in [1, r-1]");
        // A scalar of exactly r must be refused rather than reduced.
        let mut r_scalar = good.to_vec();
        r_scalar[144..176].copy_from_slice(&{
            let mut bytes = [0u8; 32];
            let r = scalar_field_order();
            let raw = r.to_bytes_be();
            bytes[32 - raw.len()..].copy_from_slice(&raw);
            bytes
        });
        assert!(octets_to_proof(&r_scalar).is_err(), "r is out of range");
    }

    #[test]
    fn core_proof_gen_on_the_real_path_produces_verifying_proofs() {
        let hex = fixtures();
        let lists = fixture_index_lists();
        let case = proof_case(&hex, &lists, "d22_1");
        let pk = field(&hex, "d22_1.public_key");
        let header = field(&hex, "d22_1.header");
        let ph = field(&hex, "d22_1.presentation_header");
        let signature = octets_to_signature(field(&hex, "d22_1.signature")).expect("signature");

        let first = core_proof_gen(pk, &signature, &case.generators, header, ph, &case.msg_scalars, &case.disclosed).expect("proof");
        let second = core_proof_gen(pk, &signature, &case.generators, header, ph, &case.msg_scalars, &case.disclosed).expect("proof");
        assert_ne!(first, second, "fresh randomness must produce different proofs");
        for proof in [&first, &second] {
            assert!(core_proof_verify(pk, proof, &case.generators, header, ph, &case.disclosed_messages, &case.disclosed), "both must verify");
        }
        // Disclosing everything is a valid (degenerate) case: U = 0, so five random scalars.
        let all: Vec<usize> = (0..case.msg_scalars.len()).collect();
        let full = core_proof_gen(pk, &signature, &case.generators, header, ph, &case.msg_scalars, &all).expect("proof");
        assert_eq!(full.len(), 272, "no commitments: the length floor");
        assert!(core_proof_verify(pk, &full, &case.generators, header, ph, &case.msg_scalars, &all));
    }
}
