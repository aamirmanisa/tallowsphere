//! RSABSSA-SHA384-PSS-Randomized — RFC 9474 blind signatures.
//!
//! This is the implementation behind `blind_sign` / `blind_unblind` / `blind_verify` in
//! `stdlib/crypto.tl`, stub register row #90. The stub was explicit about why the canonical names
//! refused: the `_experimental` counterpart is "an XOR-blinding construction, NOT a standard blind
//! signature scheme", and wiring a canonical name to it would have answered a question about a
//! standard with a construction that has none of its properties.
//!
//! ## Why this variant
//!
//! RFC 9474 defines four named variants. This implements **RSABSSA-SHA384-PSS-Randomized** — SHA-384
//! with MGF1-SHA-384 and a 48-byte salt, plus the *randomized* message preparation. It is one of the
//! two the RFC recommends (§5), and the randomization is the part that protects the client from a
//! malicious signer (§5, [Lys22]); the deterministic variants trade that away.
//!
//! ## Why the arithmetic is not OpenSSL's
//!
//! The first cut of this module used the `openssl` crate for `BigNum` arithmetic and RSA key
//! generation, and it did not link in this tree. Rather than work around the link, it was reverted
//! for a packaging reason: this crate publishes `aarch64-unknown-linux-musl` and
//! `aarch64-apple-darwin` artifacts (see `.cargo/config.toml` and the release workflow), and a
//! native OpenSSL dependency would have required vendored OpenSSL for both targets. The arithmetic
//! here is `num_bigint`, already in this tree's lockfile, and RSA key generation is implemented
//! below.
//!
//! RFC 9474 §6.1 places key generation out of scope, so which key generation is used is not a
//! conformance question; the *protocol*, the PSS encoding and the verification are the RFC's, and
//! the Appendix A.1 vector checks every one of those steps against the published values.
//!
//! ## What the `.tl` surface can and cannot express
//!
//! RFC 9474 separates roles: the client blinds, the signer signs, the client unblinds and verifies.
//! The declared surface is `blind_sign(message)`, `blind_unblind(blind_signature, blinding_factor)`
//! and `blind_verify(message, signature, signer_public_key)` — three calls with no room for a
//! message to travel alongside the blind signature. Two consequences, both handled by making the
//! strings self-describing rather than by inventing hidden state:
//!
//! - `blind_sign(message)` runs the client and signer steps locally and returns the *transcript*:
//!   `blinding_factor` is the RFC's `inv`, and `blind_signature` is
//!   `v1:<blind_sig_hex>:<modulus_hex>:<exponent_hex>:<prepared_msg_hex>`. The modulus and exponent
//!   are public; carrying them is what lets `blind_unblind` finish without a fourth call.
//! - `blind_unblind` returns `signature` as `v1:<sig_hex>:<prepared_msg_hex>`. The prepared message
//!   is part of the *signature*, not a secret: it is `msg_prefix ‖ msg`, and `blind_verify` checks
//!   that its trailing bytes are exactly the message the caller passes, so a signature cannot be
//!   replayed against a different message.
//!
//! What this does *not* do is divide the roles across processes: a real deployment has the client
//! and the signer in different places, and the blinding exists so the signer learns nothing. Here
//! the blinding algebra is executed faithfully (the signer's view is the blinded message, never the
//! message), but both roles run in one call. That is the same shape of deviation as FROST's local
//! rounds, and it is recorded rather than glossed.
//!
//! ## Verification
//!
//! The test module parses **RFC 9474 Appendix A.1** out of `tests/fixtures/rfc9474-a1.txt` and
//! asserts every published intermediate in protocol order: the key (`p·q = n`), the EMSA-PSS
//! encoding against `encoded_msg` (which also settles `emBits = modBits - 1`), the blinding algebra
//! against `blinded_msg`, the signer's operation against `blind_sig`, the unblinding against `sig`,
//! and finally that `sig` verifies. The vector was extracted from the RFC's text mechanically; the
//! fixture is data, so no hex was typed by eye.
//!
//! The generated-key path is separately evidenced: the public key is emitted as a real
//! `SubjectPublicKeyInfo` PEM built by the DER writer below, and `openssl rsa -pubin` on this box
//! parses it (checked when this module landed, not asserted in the test suite — a test must not
//! depend on a CLI being installed).

use num_bigint::{BigInt, BigUint, Sign};
use sha2::{Digest, Sha384};

/// The named variant, as RFC 9474 §5 spells it.
pub const VARIANT: &str = "RSABSSA-SHA384-PSS-Randomized";
/// SHA-384 output, and the salt length this variant fixes.
const HASH_LEN: usize = 48;
const SALT_LEN: usize = 48;
/// `PrepareRandomize` prepends this many random bytes (RFC 9474 §4.1).
const PREFIX_LEN: usize = 32;
/// Transcript version tag, so a malformed string is refused rather than misparsed.
const TAG: &str = "v1";
/// The public exponent for generated keys. F4 is the conventional choice.
const PUBLIC_EXPONENT: u32 = 65537;
/// Miller-Rabin rounds for key generation: 4^-24 ≈ 3.6e-15 chance of accepting a composite.
const MILLER_RABIN_ROUNDS: usize = 24;
/// Trial division ahead of Miller-Rabin, which is what keeps key generation quick.
const TRIAL_PRIMES: [u32; 12] = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37];

// ---------------------------------------------------------------------------
// Encoding helpers
// ---------------------------------------------------------------------------

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

/// Big-endian bytes to an integer (RFC 8017's `OS2IP`).
pub fn integer_from_bytes(bytes: &[u8]) -> BigUint {
    BigUint::from_bytes_be(bytes)
}

/// An integer to exactly `length` big-endian bytes (RFC 8017's `I2OSP`); `None` if it does not fit.
pub fn integer_to_bytes(value: &BigUint, length: usize) -> Option<Vec<u8>> {
    let raw = value.to_bytes_be();
    if raw.len() > length {
        return None;
    }
    let mut out = vec![0u8; length - raw.len()];
    out.extend_from_slice(&raw);
    Some(out)
}

fn sha384(data: &[u8]) -> [u8; HASH_LEN] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize().into()
}

/// MGF1 with SHA-384 (RFC 8017 appendix B.2.1).
fn mgf1_sha384(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + HASH_LEN);
    let mut counter: u32 = 0;
    while out.len() < len {
        let mut h = Sha384::new();
        h.update(seed);
        h.update(counter.to_be_bytes());
        out.extend_from_slice(&h.finalize());
        counter += 1;
    }
    out.truncate(len);
    out
}

fn random_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    bytes
}

// ---------------------------------------------------------------------------
// EMSA-PSS (RFC 8017 §9.1)
// ---------------------------------------------------------------------------

/// `EMSA-PSS-ENCODE` with a supplied salt. `em_bits` is `modBits - 1`, the RSASSA-PSS convention —
/// the RFC 9474 A.1 vector's `encoded_msg` is what settled that, since RFC 9474 writes
/// `EMSA-PSS-ENCODE(msg, bit_len(n))` and RFC 8017's RSASSA-PSS uses one bit less.
pub fn emsa_pss_encode(msg: &[u8], em_bits: usize, salt: &[u8]) -> Result<Vec<u8>, String> {
    let em_len = em_bits.div_ceil(8);
    if em_len < HASH_LEN + salt.len() + 2 {
        return Err(format!(
            "message too long: an {em_len}-byte encoding cannot hold a {}-byte salt",
            salt.len()
        ));
    }
    let m_hash = sha384(msg);
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(&m_hash);
    m_prime.extend_from_slice(salt);
    let h = sha384(&m_prime);

    let mut db = vec![0u8; em_len - salt.len() - HASH_LEN - 2];
    db.push(0x01);
    db.extend_from_slice(salt);

    let mask = mgf1_sha384(&h, em_len - HASH_LEN - 1);
    for (byte, m) in db.iter_mut().zip(mask.iter()) {
        *byte ^= m;
    }
    // Clear the leftmost 8*emLen - emBits bits.
    let to_clear = 8 * em_len - em_bits;
    if to_clear > 0 {
        db[0] &= 0xffu8 >> to_clear;
    }

    let mut em = db;
    em.extend_from_slice(&h);
    em.push(0xbc);
    Ok(em)
}

/// `EMSA-PSS-VERIFY` with a fixed salt length, failing closed.
pub fn emsa_pss_verify(msg: &[u8], em: &[u8], em_bits: usize, salt_len: usize) -> bool {
    let em_len = em_bits.div_ceil(8);
    if em.len() != em_len || em_len < salt_len + HASH_LEN + 2 {
        return false;
    }
    if em[em_len - 1] != 0xbc {
        return false;
    }
    let h = &em[em_len - HASH_LEN - 1..em_len - 1];
    let mut db = em[..em_len - HASH_LEN - 1].to_vec();
    let to_clear = 8 * em_len - em_bits;
    if to_clear > 0 {
        if db[0] & !(0xffu8 >> to_clear) != 0 {
            return false; // a set bit that the encoder must have cleared
        }
        db[0] &= 0xffu8 >> to_clear;
    }
    let mask = mgf1_sha384(h, em_len - HASH_LEN - 1);
    for (byte, m) in db.iter_mut().zip(mask.iter()) {
        *byte ^= m;
    }
    if to_clear > 0 {
        db[0] &= 0xffu8 >> to_clear;
    }
    let ps_len = em_len - salt_len - HASH_LEN - 2;
    if db[..ps_len].iter().any(|b| *b != 0) || db[ps_len] != 0x01 {
        return false;
    }
    let salt = &db[ps_len + 1..];
    let mut m_prime = vec![0u8; 8];
    m_prime.extend_from_slice(&sha384(msg));
    m_prime.extend_from_slice(salt);
    sha384(&m_prime)[..] == h[..]
}

// ---------------------------------------------------------------------------
// Integer arithmetic
// ---------------------------------------------------------------------------

/// `a^-1 mod m` by the extended Euclidean algorithm; `None` when `gcd(a, m) != 1`.
pub fn mod_inverse(a: &BigUint, m: &BigUint) -> Option<BigUint> {
    let m_int = BigInt::from(m.clone());
    let zero = BigInt::from(0u32);
    let (mut old_r, mut r) = (BigInt::from(a.clone()), m_int.clone());
    let (mut old_s, mut s) = (BigInt::from(1u32), zero.clone());
    while r != zero {
        let q = &old_r / &r;
        let new_r = &old_r - &q * &r;
        old_r = r;
        r = new_r;
        let new_s = &old_s - &q * &s;
        old_s = s;
        s = new_s;
    }
    if old_r != BigInt::from(1u32) {
        return None; // not invertible modulo m
    }
    let mut inv = old_s % &m_int;
    if inv.sign() == Sign::Minus {
        inv += &m_int;
    }
    inv.to_biguint()
}

fn gcd(mut a: BigUint, mut b: BigUint) -> BigUint {
    let zero = BigUint::from(0u32);
    while b != zero {
        let t = &a % &b;
        a = b;
        b = t;
    }
    a
}

/// A Miller-Rabin probable-prime test: trial division by the small primes, then the fixed small
/// bases plus `MILLER_RABIN_ROUNDS` random ones. A composite that survives trial division almost
/// always fails on the first base, so the expensive path is only walked for candidates that are
/// genuinely hard to refute.
fn is_probable_prime(n: &BigUint) -> bool {
    let one = BigUint::from(1u32);
    let two = BigUint::from(2u32);
    let zero = BigUint::from(0u32);
    if n < &two {
        return false;
    }
    for p in TRIAL_PRIMES {
        let p_int = BigUint::from(p);
        if n == &p_int {
            return true;
        }
        if n % &p_int == zero {
            return false;
        }
    }
    // n - 1 = d * 2^s with d odd.
    let n_minus_1 = n - &one;
    let mut d = n_minus_1.clone();
    let mut s = 0usize;
    while &d % &two == zero {
        d = &d / &two;
        s += 1;
    }

    let witness = |base: &BigUint| -> bool {
        let mut x = base.modpow(&d, n);
        if x == one || x == n_minus_1 {
            return true;
        }
        for _ in 1..s {
            x = x.modpow(&two, n);
            if x == n_minus_1 {
                return true;
            }
        }
        false
    };

    for p in TRIAL_PRIMES {
        let base = BigUint::from(p);
        if base < n_minus_1 && !witness(&base) {
            return false;
        }
    }
    for _ in 0..MILLER_RABIN_ROUNDS {
        // A random base in [2, n-2].
        let k = n.bits().div_ceil(8) as usize;
        let candidate = BigUint::from_bytes_be(&random_bytes(k)) % (n - BigUint::from(3u32));
        let base = candidate + two.clone();
        if !witness(&base) {
            return false;
        }
    }
    true
}

/// A random prime of exactly `bits` bits (top bit set, so the size is not a range).
fn random_prime(bits: usize) -> BigUint {
    let byte_len = bits.div_ceil(8);
    loop {
        let mut bytes = random_bytes(byte_len);
        // Set the top bit so the prime has the requested size, and the low bit so it is odd.
        bytes[0] |= 0x80;
        let last = bytes.len() - 1;
        bytes[last] |= 0x01;
        let candidate = BigUint::from_bytes_be(&bytes);
        if candidate.bits() as usize == bits && is_probable_prime(&candidate) {
            return candidate;
        }
    }
}

// ---------------------------------------------------------------------------
// Minimal DER for the public key
// ---------------------------------------------------------------------------

fn der_length(len: usize) -> Vec<u8> {
    if len < 0x80 {
        vec![len as u8]
    } else {
        let mut raw = len.to_be_bytes().to_vec();
        while raw.first() == Some(&0) {
            raw.remove(0);
        }
        let mut out = vec![0x80 | raw.len() as u8];
        out.extend_from_slice(&raw);
        out
    }
}

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_length(body.len()));
    out.extend_from_slice(body);
    out
}

/// `INTEGER`: DER requires a leading zero byte when the top bit of the value is set, so the value
/// is not mistaken for a negative number.
fn der_integer(value: &BigUint) -> Vec<u8> {
    let raw = value.to_bytes_be();
    if raw.first().is_some_and(|b| b & 0x80 != 0) {
        let mut padded = vec![0u8];
        padded.extend_from_slice(&raw);
        der_tlv(0x02, &padded)
    } else {
        der_tlv(0x02, &raw)
    }
}

/// `SubjectPublicKeyInfo` for an RSA key:
/// `SEQUENCE { SEQUENCE { OID 1.2.840.113549.1.1.1, NULL }, BIT STRING { RSAPublicKey } }`.
fn public_spki_der(n: &BigUint, e: &BigUint) -> Vec<u8> {
    const RSA_ENCRYPTION_OID: [u8; 11] = [
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let mut algorithm = RSA_ENCRYPTION_OID.to_vec();
    algorithm.extend_from_slice(&[0x05, 0x00]); // NULL parameters

    let mut rsa_public_key = der_integer(n);
    rsa_public_key.extend_from_slice(&der_integer(e));

    let mut bit_string = vec![0x00]; // no unused bits
    bit_string.extend_from_slice(&der_tlv(0x30, &rsa_public_key));

    let mut body = der_tlv(0x30, &algorithm);
    body.extend_from_slice(&der_tlv(0x03, &bit_string));
    der_tlv(0x30, &body)
}

fn pem_wrap(label: &str, der: &[u8]) -> String {
    use base64::Engine;
    let b64 = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in b64.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(chunk));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

struct DerReader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        if self.pos + len > self.bytes.len() {
            return Err("RSABSSA DER: truncated".to_string());
        }
        let out = &self.bytes[self.pos..self.pos + len];
        self.pos += len;
        Ok(out)
    }

    /// Read one TLV, requiring `tag`, and reject indefinite and non-minimal lengths.
    fn tlv(&mut self, tag: u8) -> Result<&'a [u8], String> {
        let got = self.take(1)?[0];
        if got != tag {
            return Err(format!("RSABSSA DER: expected tag {tag:#04x}, found {got:#04x}"));
        }
        let first = self.take(1)?[0];
        let len = if first < 0x80 {
            first as usize
        } else {
            let count = (first & 0x7f) as usize;
            if count == 0 {
                return Err("RSABSSA DER: indefinite length is not valid DER".to_string());
            }
            if count > 4 {
                return Err("RSABSSA DER: length is implausibly large".to_string());
            }
            let raw = self.take(count)?;
            if raw[0] == 0 {
                return Err("RSABSSA DER: non-minimal length encoding".to_string());
            }
            let mut value = 0usize;
            for byte in raw {
                value = (value << 8) | *byte as usize;
            }
            if value < 0x80 {
                return Err("RSABSSA DER: length should have used the short form".to_string());
            }
            value
        };
        self.take(len)
    }

    fn finish(&self) -> Result<(), String> {
        if self.pos != self.bytes.len() {
            return Err(format!(
                "RSABSSA DER: {} trailing bytes after the public key",
                self.bytes.len() - self.pos
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

pub struct Signer {
    n: BigUint,
    e: BigUint,
    d: BigUint,
}

impl Signer {
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    pub fn public_exponent(&self) -> &BigUint {
        &self.e
    }

    pub fn private_exponent(&self) -> &BigUint {
        &self.d
    }

    /// Modulus length in bytes — RFC 9474's `modulus_len`, the length of every exchanged string.
    pub fn modulus_len(&self) -> usize {
        (self.n.bits().div_ceil(8)) as usize
    }

    /// The public key as a `SubjectPublicKeyInfo` PEM.
    pub fn public_pem(&self) -> Result<String, String> {
        Ok(pem_wrap("PUBLIC KEY", &public_spki_der(&self.n, &self.e)))
    }
}

/// Generate an RSA key of `bits` bits with `e = 65537`.
pub fn generate_signer(bits: u32) -> Result<Signer, String> {
    if bits < 1024 || bits % 2 != 0 {
        return Err(format!(
            "RSABSSA key generation needs an even bit length of at least 1024, got {bits}"
        ));
    }
    let e = BigUint::from(PUBLIC_EXPONENT);
    let half = (bits / 2) as usize;
    loop {
        let p = random_prime(half);
        let q = random_prime(half);
        if p == q {
            continue;
        }
        let n = &p * &q;
        if n.bits() as u32 != bits {
            continue; // the product may come out one bit short
        }
        let p1 = &p - BigUint::from(1u32);
        let q1 = &q - BigUint::from(1u32);
        let lambda = (&p1 * &q1) / gcd(p1, q1); // Carmichael's λ(n) for n = p*q
        let Some(d) = mod_inverse(&e, &lambda) else {
            continue;
        };
        return Ok(Signer { n, e, d });
    }
}

/// Parse a `SubjectPublicKeyInfo` PEM into `(n, e)`.
pub fn public_parts(pem: &str) -> Result<(BigUint, BigUint), String> {
    use base64::Engine;
    let text = pem.trim();
    if !text.starts_with("-----BEGIN PUBLIC KEY-----") || !text.ends_with("-----END PUBLIC KEY-----")
    {
        return Err("RSABSSA public key must be a 'BEGIN PUBLIC KEY' PEM".to_string());
    }
    let body: String = text
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect::<Vec<_>>()
        .join("");
    let der = base64::engine::general_purpose::STANDARD
        .decode(body.trim())
        .map_err(|e| format!("RSABSSA public key: the PEM body is not valid base64: {e}"))?;

    // SEQUENCE { SEQUENCE { OID, NULL }, BIT STRING { SEQUENCE { INTEGER n, INTEGER e } } }
    let mut outer = DerReader::new(&der);
    let spki = outer.tlv(0x30)?;
    outer.finish()?;

    let mut reader = DerReader::new(spki);
    let _algorithm = reader.tlv(0x30)?;
    let bit_string = reader.tlv(0x03)?;
    reader.finish()?;
    if bit_string.first() != Some(&0x00) {
        return Err("RSABSSA public key: BIT STRING has unused bits".to_string());
    }

    let mut key = DerReader::new(&bit_string[1..]);
    let inner = key.tlv(0x30)?;
    key.finish()?;

    let mut integers = DerReader::new(inner);
    let n = integers.tlv(0x02)?;
    let e = integers.tlv(0x02)?;
    integers.finish()?;
    // A leading zero is required only when the top bit is otherwise set.
    if n.first() == Some(&0) && (n.len() < 2 || n[1] & 0x80 == 0) {
        return Err("RSABSSA public key: non-minimal INTEGER for the modulus".to_string());
    }
    if e.first() == Some(&0) && (e.len() < 2 || e[1] & 0x80 == 0) {
        return Err("RSABSSA public key: non-minimal INTEGER for the exponent".to_string());
    }
    Ok((BigUint::from_bytes_be(n), BigUint::from_bytes_be(e)))
}

// ---------------------------------------------------------------------------
// The protocol (RFC 9474 §4.1–§4.5)
// ---------------------------------------------------------------------------

/// RFC 9474 §4.1 `PrepareRandomize`: 32 fresh random bytes in front of the message.
pub fn prepare(msg: &[u8]) -> Vec<u8> {
    let mut prepared = random_bytes(PREFIX_LEN);
    prepared.extend_from_slice(msg);
    prepared
}

/// This variant's 48-byte salt, from fresh randomness (`sLen = 48` for RSABSSA-SHA384-*).
pub fn random_salt() -> Vec<u8> {
    random_bytes(SALT_LEN)
}

fn modulus_len_bits(n: &BigUint) -> (usize, usize) {
    let bits = n.bits() as usize;
    ((bits + 7) / 8, bits)
}

/// Uniform in `[1, n-1]` by rejection sampling over `modulus_len` bytes, as RFC 9474 §4.2 step 6
/// describes.
fn random_blinding_factor(n: &BigUint) -> BigUint {
    let (k, _) = modulus_len_bits(n);
    let one = BigUint::from(1u32);
    loop {
        let candidate = BigUint::from_bytes_be(&random_bytes(k));
        if candidate >= one && &candidate < n {
            return candidate;
        }
    }
}

/// RFC 9474 §4.2 `Blind`. Returns `(blinded_msg, inv)`.
pub fn blind(
    n: &BigUint,
    e: &BigUint,
    prepared_msg: &[u8],
    salt: &[u8],
) -> Result<(Vec<u8>, BigUint), String> {
    let (k, bits) = modulus_len_bits(n);
    let em_bits = bits - 1;
    let encoded = emsa_pss_encode(prepared_msg, em_bits, salt)?;
    let m = BigUint::from_bytes_be(&encoded);

    // Step 4: the message representative must be co-prime with the modulus.
    if gcd(m.clone(), n.clone()) != BigUint::from(1u32) {
        return Err("invalid input: the encoded message is not co-prime with the modulus".into());
    }

    // Steps 6-8: r uniform in [1, n-1], inv = r^-1 mod n.
    let (r, inv) = loop {
        let r = random_blinding_factor(n);
        match mod_inverse(&r, n) {
            Some(inv) => break (r, inv),
            None => continue, // "blinding error": RFC 9474 §4.2 says to retry
        }
    };

    // Steps 9-11: x = r^e mod n; z = m*x mod n; blinded_msg = I2OSP(z, k).
    let x = r.modpow(e, n);
    let z = (m * x) % n;
    let blinded_msg = integer_to_bytes(&z, k)
        .ok_or_else(|| "RSABSSA: blinding produced an unexpected length".to_string())?;
    Ok((blinded_msg, inv))
}

/// RFC 9474 §4.3 `BlindSign`: `s = blinded_msg^d mod n`, with the RFC's post-check that the public
/// operation recovers the input.
pub fn blind_sign(
    n: &BigUint,
    d: &BigUint,
    e: &BigUint,
    blinded_msg: &[u8],
) -> Result<Vec<u8>, String> {
    let (k, _) = modulus_len_bits(n);
    if blinded_msg.len() != k {
        return Err(format!(
            "unexpected input size: blinded message is {} bytes, expected {k}",
            blinded_msg.len()
        ));
    }
    let m = BigUint::from_bytes_be(blinded_msg);
    if &m >= n {
        return Err("message representative out of range: blinded message ≥ modulus".into());
    }
    let s = m.modpow(d, n);
    // Steps 3-4: RSAVP1(pk, s) must return the input, else "signing failure".
    if s.modpow(e, n) != m {
        return Err("signing failure: the private operation did not invert".into());
    }
    integer_to_bytes(&s, k).ok_or_else(|| "RSABSSA: signing produced an unexpected length".to_string())
}

/// RFC 9474 §4.4 `Finalize`: `sig = blind_sig * inv mod n`, then verify before returning.
pub fn finalize(
    n: &BigUint,
    e: &BigUint,
    prepared_msg: &[u8],
    blind_sig: &[u8],
    inv: &BigUint,
) -> Result<Vec<u8>, String> {
    let (k, _) = modulus_len_bits(n);
    if blind_sig.len() != k {
        return Err(format!(
            "unexpected input size: blind signature is {} bytes, expected {k}",
            blind_sig.len()
        ));
    }
    let z = BigUint::from_bytes_be(blind_sig);
    let s = (z * inv) % n;
    let sig = integer_to_bytes(&s, k)
        .ok_or_else(|| "RSABSSA: unblinding produced an unexpected length".to_string())?;
    if !verify(n, e, prepared_msg, &sig) {
        return Err("invalid signature: the unblinded signature does not verify".into());
    }
    Ok(sig)
}

/// RFC 9474 §4.5, i.e. RSASSA-PSS-VERIFY with this variant's parameters. Fails closed.
pub fn verify(n: &BigUint, e: &BigUint, prepared_msg: &[u8], sig: &[u8]) -> bool {
    let (k, bits) = modulus_len_bits(n);
    if sig.len() != k {
        return false;
    }
    let s = BigUint::from_bytes_be(sig);
    if &s >= n {
        return false;
    }
    let m = s.modpow(e, n);
    let Some(em) = integer_to_bytes(&m, k) else {
        return false;
    };
    emsa_pss_verify(prepared_msg, &em, bits - 1, SALT_LEN)
}

// ---------------------------------------------------------------------------
// Transcript encodings for the `.tl` surface
// ---------------------------------------------------------------------------

/// `v1:<blind_sig>:<n>:<e>:<prepared_msg>` — the signer's response plus what unblinding and the
/// RFC's Finalize verification need. All three carried values are public.
pub fn encode_blind_signature(
    blind_sig: &[u8],
    n: &BigUint,
    e: &BigUint,
    prepared_msg: &[u8],
) -> String {
    format!(
        "{TAG}:{}:{}:{}:{}",
        hex(blind_sig),
        hex(&n.to_bytes_be()),
        hex(&e.to_bytes_be()),
        hex(prepared_msg)
    )
}

pub fn decode_blind_signature(text: &str) -> Result<(Vec<u8>, BigUint, BigUint, Vec<u8>), String> {
    let parts: Vec<&str> = text.trim().split(':').collect();
    if parts.len() != 5 || parts[0] != TAG {
        return Err(format!(
            "blind signature must be '{TAG}:<blind_sig>:<modulus>:<exponent>:<prepared_msg>'"
        ));
    }
    let blind_sig = unhex(parts[1])?;
    let modulus = BigUint::from_bytes_be(&unhex(parts[2])?);
    let exponent = BigUint::from_bytes_be(&unhex(parts[3])?);
    let prepared = unhex(parts[4])?;
    Ok((blind_sig, modulus, exponent, prepared))
}

/// `v1:<sig>:<prepared_msg>` — the signature, with the message it actually signs.
pub fn encode_signature(sig: &[u8], prepared_msg: &[u8]) -> String {
    format!("{TAG}:{}:{}", hex(sig), hex(prepared_msg))
}

pub fn decode_signature(text: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let parts: Vec<&str> = text.trim().split(':').collect();
    if parts.len() != 3 || parts[0] != TAG {
        return Err(format!("signature must be '{TAG}:<sig>:<prepared_msg>'"));
    }
    Ok((unhex(parts[1])?, unhex(parts[2])?))
}

/// A prepared message is valid for a caller's message iff it is that message behind exactly the
/// 32-byte randomizer `PrepareRandomize` prepends. This is what stops a signature from being
/// replayed against a different message.
pub fn prepared_message_matches(prepared: &[u8], msg: &[u8]) -> bool {
    prepared.len() == PREFIX_LEN + msg.len() && prepared[PREFIX_LEN..] == *msg
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 9474 Appendix A.1, extracted mechanically into the repository as data.
    const VECTOR: &str = include_str!("../tests/fixtures/rfc9474-a1.txt");

    fn vector() -> std::collections::HashMap<String, Vec<u8>> {
        let mut out = std::collections::HashMap::new();
        for line in VECTOR.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let (name, value) = line.split_once(" = ").expect("fixture is 'name = hex'");
            out.insert(
                name.to_string(),
                unhex(value).unwrap_or_else(|e| panic!("fixture field {name}: {e}")),
            );
        }
        out
    }

    fn num(v: &std::collections::HashMap<String, Vec<u8>>, name: &str) -> BigUint {
        BigUint::from_bytes_be(&v[name])
    }

    #[test]
    fn the_rfc_vector_is_reproduced_stage_by_stage() {
        let v = vector();
        let n = num(&v, "n");
        let e = num(&v, "e");
        let d = num(&v, "d");
        let prepared = v["prepared_msg"].clone();
        let salt = v["salt"].clone();
        let k = (n.bits().div_ceil(8)) as usize;

        // The key itself, and the vector's own statement that prepared_msg = prefix ‖ msg.
        let p = num(&v, "p");
        let q = num(&v, "q");
        assert_eq!(&p * &q, n, "p*q must equal the modulus");
        assert_eq!(k, 512, "the vector's modulus is 4096 bits");
        assert_eq!(v["prepared_msg"].len(), PREFIX_LEN + v["msg"].len());
        assert!(prepared_message_matches(&prepared, &v["msg"]));

        // EMSA-PSS: emBits = modBits - 1 reproduces the published encoding.
        let em_bits = n.bits() as usize - 1;
        let encoded = emsa_pss_encode(&prepared, em_bits, &salt).unwrap();
        assert_eq!(encoded, v["encoded_msg"], "EMSA-PSS-ENCODE must match the vector");

        // Blind: inv = r^-1, and z = m*r^e mod n is the published blinded message.
        let inv = num(&v, "inv");
        let r = mod_inverse(&inv, &n).expect("inv must be invertible");
        assert_eq!((&r * &inv) % &n, BigUint::from(1u32), "inv must be r^-1 mod n");
        let m = BigUint::from_bytes_be(&v["encoded_msg"]);
        let z = (m * r.modpow(&e, &n)) % &n;
        assert_eq!(
            integer_to_bytes(&z, k).unwrap(),
            v["blinded_msg"],
            "the blinding algebra must reproduce blinded_msg"
        );

        // BlindSign, Finalize, Verify.
        let blind_sig = blind_sign(&n, &d, &e, &v["blinded_msg"]).unwrap();
        assert_eq!(blind_sig, v["blind_sig"], "BlindSign must match the vector");
        let sig = finalize(&n, &e, &prepared, &blind_sig, &inv).unwrap();
        assert_eq!(sig, v["sig"], "Finalize must match the vector");
        assert!(verify(&n, &e, &prepared, &v["sig"]), "the vector's sig must verify");

        // ... and the refusals: a wrong message, a flipped signature bit, a wrong exponent.
        assert!(!verify(&n, &e, b"not the message", &v["sig"]));
        let mut bad = v["sig"].clone();
        bad[7] ^= 0x01;
        assert!(!verify(&n, &e, &prepared, &bad));
        assert!(!verify(&n, &BigUint::from(3u32), &prepared, &v["sig"]));
    }

    #[test]
    fn the_blinding_actually_blinds_and_blind_sign_is_not_the_signature() {
        // The property the row was about: what the signer sees must not be the signature, and the
        // blinded message must not be the PSS encoding.
        let v = vector();
        assert_ne!(v["blinded_msg"], v["encoded_msg"], "the blinded message is not the encoding");
        assert_ne!(v["blind_sig"], v["sig"], "the blind signature is not the final signature");
    }

    #[test]
    fn a_generated_key_blinds_signs_unblinds_and_verifies() {
        let signer = generate_signer(2048).expect("key generation");
        let n = signer.modulus();
        let e = signer.public_exponent();
        assert_eq!(signer.modulus_len(), 256);
        assert_eq!(*e, BigUint::from(PUBLIC_EXPONENT));

        // The public key is a real SPKI document and survives a round trip.
        let pem = signer.public_pem().unwrap();
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----"));
        let (n_pub, e_pub) = public_parts(&pem).unwrap();
        assert_eq!(&n_pub, n, "the PEM must carry the signer's modulus");
        assert_eq!(&e_pub, e, "the PEM must carry the signer's exponent");

        let message = b"an anonymous ballot, unlinkable to its voter";
        let prepared = prepare(message);
        assert!(prepared_message_matches(&prepared, message));

        let (blinded_msg, inv) = blind(&n_pub, &e_pub, &prepared, &random_salt()).unwrap();
        assert_eq!(blinded_msg.len(), signer.modulus_len());
        let blind_sig = blind_sign(n, signer.private_exponent(), &e_pub, &blinded_msg).unwrap();
        let sig = finalize(&n_pub, &e_pub, &prepared, &blind_sig, &inv).unwrap();

        assert!(verify(&n_pub, &e_pub, &prepared, &sig), "the unblinded signature must verify");
        assert_ne!(sig, blind_sig, "unblinding must change the value");
        assert_ne!(
            blinded_msg.as_slice(),
            &sig[..blinded_msg.len()],
            "the signer never sees the signature"
        );

        // And the refusals, so acceptance is distinguishable from accepting anything.
        assert!(!verify(&n_pub, &e_pub, b"a different ballot", &sig));
        let other = generate_signer(2048).unwrap();
        let (other_n, other_e) = public_parts(&other.public_pem().unwrap()).unwrap();
        assert!(
            !verify(&other_n, &other_e, &prepared, &sig),
            "another key must not accept this signature"
        );
        let mut tampered = sig.clone();
        tampered[0] ^= 0x80;
        assert!(!verify(&n_pub, &e_pub, &prepared, &tampered));
    }

    #[test]
    fn a_generated_key_is_consistent_with_its_own_exponents() {
        // d must be e^-1 modulo λ(n): check it through the operation that depends on it.
        let signer = generate_signer(1024).expect("key generation");
        let n = signer.modulus();
        let e = signer.public_exponent();
        let d = signer.private_exponent();
        assert_eq!(n.bits(), 1024);
        for probe in [2u32, 3, 12345] {
            let m = BigUint::from(probe);
            assert_eq!(
                m.modpow(e, n).modpow(d, n),
                m,
                "(m^e)^d must return m for a correctly generated key"
            );
        }
    }

    #[test]
    fn transcript_encodings_round_trip_and_reject_junk() {
        let v = vector();
        let n = num(&v, "n");
        let prepared = v["prepared_msg"].clone();
        let blind_sig = v["blind_sig"].clone();

        let encoded = encode_blind_signature(&blind_sig, &n, &num(&v, "e"), &prepared);
        let (bs, modulus, exponent, prep) = decode_blind_signature(&encoded).unwrap();
        assert_eq!(bs, blind_sig);
        assert_eq!(modulus, n);
        assert_eq!(exponent, num(&v, "e"));
        assert_eq!(prep, prepared);

        let sig_encoded = encode_signature(&v["sig"], &prepared);
        let (sig, prep2) = decode_signature(&sig_encoded).unwrap();
        assert_eq!(sig, v["sig"]);
        assert_eq!(prep2, prepared);

        for bad in [
            "",
            "v2:aa:bb:cc:dd",
            "v1:aa:bb:cc",
            "v1:zz:bb:cc:dd",
            "v1:aa:bb:cc:dd:ee",
        ] {
            assert!(decode_blind_signature(bad).is_err(), "{bad:?} must be refused");
        }
        for bad in ["", "v2:aa:bb", "v1:aa", "v1:zz:bb"] {
            assert!(decode_signature(bad).is_err(), "{bad:?} must be refused");
        }
    }

    #[test]
    fn prepare_randomize_rejects_a_prepared_message_of_the_wrong_shape() {
        assert!(prepared_message_matches(&prepare(b"m"), b"m"));
        assert!(!prepared_message_matches(&prepare(b"m"), b"n"));
        assert!(!prepared_message_matches(b"short", b"short"));
        // A prepared message with the right tail but no prefix is refused.
        assert!(!prepared_message_matches(b"m", b"m"));
    }

    #[test]
    fn emsapss_verify_rejects_structural_damage() {
        let v = vector();
        let prepared = v["prepared_msg"].clone();
        let salt = v["salt"].clone();
        let n = num(&v, "n");
        let em_bits = n.bits() as usize - 1;
        let em = emsa_pss_encode(&prepared, em_bits, &salt).unwrap();
        assert!(emsa_pss_verify(&prepared, &em, em_bits, SALT_LEN));

        // The final 0xbc byte is what marks a PSS encoding.
        let mut wrong_trailer = em.clone();
        let last = wrong_trailer.len() - 1;
        wrong_trailer[last] = 0xbd;
        assert!(!emsa_pss_verify(&prepared, &wrong_trailer, em_bits, SALT_LEN));
        // The top bit that the encoder must clear must be clear.
        let mut top_bit = em.clone();
        top_bit[0] |= 0x80;
        assert!(!emsa_pss_verify(&prepared, &top_bit, em_bits, SALT_LEN));
        // Wrong length and wrong salt length are refused.
        assert!(!emsa_pss_verify(&prepared, &em[..em.len() - 1], em_bits, SALT_LEN));
        assert!(!emsa_pss_verify(&prepared, &em, em_bits, 0));
    }

    #[test]
    fn der_writer_and_reader_agree_and_the_reader_is_strict() {
        let n = num(&vector(), "n");
        let e = BigUint::from(PUBLIC_EXPONENT);
        let der = public_spki_der(&n, &e);
        assert_eq!(der[0], 0x30, "the outer element is a SEQUENCE");
        let pem = pem_wrap("PUBLIC KEY", &der);
        let (n2, e2) = public_parts(&pem).unwrap();
        assert_eq!(n2, n);
        assert_eq!(e2, e);

        // Strictness: each of these must be refused rather than silently accepted.
        let junk = pem_wrap("PUBLIC KEY", &[0xff, 0x00]);
        assert!(public_parts(&junk).is_err(), "not a SEQUENCE");
        let truncated = pem_wrap("PUBLIC KEY", &der[..der.len() - 1]);
        assert!(public_parts(&truncated).is_err(), "truncated DER");
        let mut trailing = der.clone();
        trailing.push(0x00);
        assert!(
            public_parts(&pem_wrap("PUBLIC KEY", &trailing)).is_err(),
            "trailing bytes after the SPKI"
        );
        assert!(
            public_parts("not a pem at all").is_err(),
            "a non-PEM string is refused"
        );
        assert!(
            public_parts("-----BEGIN PUBLIC KEY-----\n!!!!\n-----END PUBLIC KEY-----\n").is_err(),
            "an invalid base64 body is refused"
        );
        // Indefinite length (0x80) is not valid DER.
        let indefinite = vec![0x30, 0x80, 0x00, 0x00];
        assert!(
            public_parts(&pem_wrap("PUBLIC KEY", &indefinite)).is_err(),
            "indefinite-length DER is refused"
        );
    }

    #[test]
    fn key_generation_refuses_impossible_sizes() {
        assert!(generate_signer(1023).is_err(), "odd sizes are refused");
        assert!(generate_signer(512).is_err(), "below 1024 bits is refused");
    }

    #[test]
    fn miller_rabin_agrees_with_known_primes_and_composites() {
        for prime in [3u64, 5, 17, 65537, 2147483647] {
            assert!(is_probable_prime(&BigUint::from(prime)), "{prime} is prime");
        }
        for composite in [4u64, 9, 15, 1001, 65536, 2147483649] {
            assert!(!is_probable_prime(&BigUint::from(composite)), "{composite} is composite");
        }
        assert!(!is_probable_prime(&BigUint::from(1u32)));
        assert!(!is_probable_prime(&BigUint::from(0u32)));
        // Carmichael numbers are the trap a naive Fermat test falls into.
        for carmichael in [561u64, 1105, 41041] {
            assert!(
                !is_probable_prime(&BigUint::from(carmichael)),
                "{carmichael} is composite despite passing Fermat's test"
            );
        }
    }
}
