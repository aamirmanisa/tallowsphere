//! HPKE base mode, one suite: DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM.
//!
//! Why hand-written instead of a crate: `hpke 0.14` requires `kem ^0.3.0` (final),
//! while this tree's `ml-kem 0.2` requires `kem = 0.3.0-pre.0`. Cargo cannot
//! resolve both, and upgrading ML-KEM is a separate, riskier change to the
//! post-quantum path. Everything HPKE needs here — X25519, HKDF-SHA256,
//! AES-128-GCM — is already in the dependency graph, so the composition is done
//! against the standard instead of adding a conflicting dependency.
//!
//! This is a *composition* of standard primitives, not a new primitive, and it
//! is verified against RFC 9180 Appendix A.1: the test at the bottom encrypts
//! the RFC's message with the RFC's ephemeral key and asserts the RFC's
//! ciphertext byte for byte, then decrypts it back.
//!
//! Scope is deliberately narrow: base mode only (no PSK, no authenticated
//! modes), a single ciphersuite, and labels exactly as §5.1 defines them. An
//! unauthenticated mode is what a recipient-public-key seal needs; adding auth
//! modes is a separate decision with its own tests.

use crate::interp::Value;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::Aes128Gcm;
use hkdf::Hkdf;
use sha2::Sha256;
use x25519_dalek::{PublicKey, StaticSecret};

pub const KEM_ID: u16 = 0x0020;
pub const KDF_ID: u16 = 0x0001;
pub const AEAD_ID: u16 = 0x0001;
const NK: usize = 16;
const NN: usize = 12;

/// `suite_id = "HPKE" || I2OSP(kem_id, 2) || I2OSP(kdf_id, 2) || I2OSP(aead_id, 2)`
fn suite_id() -> Vec<u8> {
    let mut v = b"HPKE".to_vec();
    v.extend_from_slice(&KEM_ID.to_be_bytes());
    v.extend_from_slice(&KDF_ID.to_be_bytes());
    v.extend_from_slice(&AEAD_ID.to_be_bytes());
    v
}

/// The KEM has its own domain separator (§4.1): `"KEM" || I2OSP(kem_id, 2)`.
/// Using the HPKE suite id here instead silently produces a different shared
/// secret — which is how the first version of this module failed the RFC vector.
fn kem_suite_id() -> Vec<u8> {
    let mut v = b"KEM".to_vec();
    v.extend_from_slice(&KEM_ID.to_be_bytes());
    v
}

fn labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut input = b"HPKE-v1".to_vec();
    input.extend_from_slice(&suite_id());
    input.extend_from_slice(label);
    input.extend_from_slice(ikm);
    // Extract only: the PRK is the output here. Expanding it would silently
    // derive something else (this is how the first version failed the vector).
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

fn labeled_expand(prk: &[u8], label: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut ctx = (len as u16).to_be_bytes().to_vec();
    ctx.extend_from_slice(b"HPKE-v1");
    ctx.extend_from_slice(&suite_id());
    ctx.extend_from_slice(label);
    ctx.extend_from_slice(info);
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("prk length");
    let mut out = vec![0u8; len];
    hk.expand(&ctx, &mut out).expect("expand");
    out
}

/// DHKEM(X25519, HKDF-SHA256) `ExtractAndExpand`, domain-separated by the KEM
/// suite id ("KEM" || kem_id), not the HPKE one.
fn extract_and_expand(dh: &[u8], kem_context: &[u8]) -> [u8; 32] {
    let eae_prk = kem_labeled_extract(&[], b"eae_prk", dh);
    let sk = kem_labeled_expand(&eae_prk, b"shared_secret", kem_context, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&sk);
    out
}


fn kem_labeled_extract(salt: &[u8], label: &[u8], ikm: &[u8]) -> [u8; 32] {
    let mut input = b"HPKE-v1".to_vec();
    input.extend_from_slice(&kem_suite_id());
    input.extend_from_slice(label);
    input.extend_from_slice(ikm);
    // Extract only: the PRK is the output here. Expanding it would silently
    // derive something else (this is how the first version failed the vector).
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&prk);
    out
}

fn kem_labeled_expand(prk: &[u8], label: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    let mut ctx = (len as u16).to_be_bytes().to_vec();
    ctx.extend_from_slice(b"HPKE-v1");
    ctx.extend_from_slice(&kem_suite_id());
    ctx.extend_from_slice(label);
    ctx.extend_from_slice(info);
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("prk length");
    let mut out = vec![0u8; len];
    hk.expand(&ctx, &mut out).expect("expand");
    out
}

/// The key schedule of §5.1 for base mode (empty PSK, empty psk_id).
struct Context {
    key: [u8; NK],
    base_nonce: [u8; NN],
}

fn key_schedule(shared_secret: &[u8], info: &[u8]) -> Context {
    let psk_id_hash = labeled_extract(&[], b"psk_id_hash", &[]);
    let info_hash = labeled_extract(&[], b"info_hash", info);
    let mut ks_ctx = vec![0u8]; // mode_base
    ks_ctx.extend_from_slice(&psk_id_hash);
    ks_ctx.extend_from_slice(&info_hash);

    let secret = labeled_extract(shared_secret, b"secret", &[]);
    let key = labeled_expand(&secret, b"key", &ks_ctx, NK);
    let base_nonce = labeled_expand(&secret, b"base_nonce", &ks_ctx, NN);

    let mut k = [0u8; NK];
    k.copy_from_slice(&key);
    let mut n = [0u8; NN];
    n.copy_from_slice(&base_nonce);
    Context {
        key: k,
        base_nonce: n,
    }
}

fn nonce_for(ctx: &Context, seq: u64) -> [u8; NN] {
    let mut n = ctx.base_nonce;
    let seq_bytes = seq.to_be_bytes();
    // XOR the sequence number into the last 8 bytes of the nonce (§5.2).
    for i in 0..8 {
        n[NN - 8 + i] ^= seq_bytes[i];
    }
    n
}

fn aead_seal(ctx: &Context, seq: u64, aad: &[u8], pt: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes128Gcm::new_from_slice(&ctx.key).map_err(|e| format!("hpke: key: {e}"))?;
    cipher
        .encrypt(
            &nonce_for(ctx, seq).into(),
            Payload { msg: pt, aad },
        )
        .map_err(|_| "hpke: encryption failed".to_string())
}

fn aead_open(ctx: &Context, seq: u64, aad: &[u8], ct: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes128Gcm::new_from_slice(&ctx.key).map_err(|e| format!("hpke: key: {e}"))?;
    cipher
        .decrypt(
            &nonce_for(ctx, seq).into(),
            Payload { msg: ct, aad },
        )
        .map_err(|_| "hpke: authentication failed".to_string())
}

/// Encap with a caller-supplied ephemeral secret (the RFC vector needs a fixed
/// one; production callers use [`seal`], which generates it).
pub fn seal_with_ephemeral(
    sk_e: &StaticSecret,
    recipient_pk: &PublicKey,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> (PublicKey, Vec<u8>) {
    let enc = PublicKey::from(sk_e);
    let dh = sk_e.diffie_hellman(recipient_pk);
    let mut kem_ctx = enc.as_bytes().to_vec();
    kem_ctx.extend_from_slice(recipient_pk.as_bytes());
    let shared = extract_and_expand(dh.as_bytes(), &kem_ctx);
    let ctx = key_schedule(&shared, info);
    let ct = aead_seal(&ctx, 0, aad, pt).expect("seal with a valid key cannot fail");
    (enc, ct)
}

/// `seal(recipient_pk, info, aad, pt) -> (enc, ct)` in base mode.
pub fn seal(
    recipient_pk: &PublicKey,
    info: &[u8],
    aad: &[u8],
    pt: &[u8],
) -> (PublicKey, Vec<u8>) {
    let sk_e = StaticSecret::random_from_rng(rand_core_06::OsRng);
    seal_with_ephemeral(&sk_e, recipient_pk, info, aad, pt)
}

/// `open(recipient_sk, enc, info, aad, ct) -> pt` in base mode.
pub fn open(
    recipient_sk: &StaticSecret,
    enc: &PublicKey,
    info: &[u8],
    aad: &[u8],
    ct: &[u8],
) -> Result<Vec<u8>, String> {
    let dh = recipient_sk.diffie_hellman(enc);
    let mut kem_ctx = enc.as_bytes().to_vec();
    kem_ctx.extend_from_slice(PublicKey::from(recipient_sk).as_bytes());
    let shared = extract_and_expand(dh.as_bytes(), &kem_ctx);
    let ctx = key_schedule(&shared, info);
    aead_open(&ctx, 0, aad, ct)
}

/// Parse a 32-byte public key from hex, refusing the all-zero point (the
/// low-order identity, which would make the DH output zero).
pub fn public_key_from_hex(hex_str: &str) -> Result<PublicKey, String> {
    let bytes = crate::hpke::unhex(hex_str)?;
    if bytes.len() != 32 {
        return Err(format!(
            "hpke: public key must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    let pk = PublicKey::from(arr);
    if pk.as_bytes().iter().all(|b| *b == 0) {
        return Err("hpke: refusing the all-zero public key".into());
    }
    Ok(pk)
}

pub fn secret_key_from_hex(hex_str: &str) -> Result<StaticSecret, String> {
    let bytes = unhex(hex_str)?;
    if bytes.len() != 32 {
        return Err(format!(
            "hpke: secret key must be 32 bytes, got {}",
            bytes.len()
        ));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(StaticSecret::from(arr))
}

pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    s
}

pub fn unhex(s: &str) -> Result<Vec<u8>, String> {
    let t = s.trim();
    if t.len() % 2 != 0 {
        return Err("hpke: hex input has an odd length".into());
    }
    let mut out = Vec::with_capacity(t.len() / 2);
    let b = t.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char)
            .to_digit(16)
            .ok_or_else(|| "hpke: invalid hex digit".to_string())?;
        let lo = (b[i + 1] as char)
            .to_digit(16)
            .ok_or_else(|| "hpke: invalid hex digit".to_string())?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}

/// Stdlib-facing helpers. Kept here so the module owns the whole composition
/// and `stdlib/crypto.rs` only marshals.
pub fn value_suite() -> Value {
    Value::String(
        "DHKEM(X25519, HKDF-SHA256) / HKDF-SHA256 / AES-128-GCM (RFC 9180 A.1)".into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn h(s: &str) -> Vec<u8> {
        unhex(s).expect("valid hex")
    }

    /// RFC 9180 Appendix A.1.1 — base mode, seq 0.
    #[test]
    fn matches_the_rfc_9180_a11_vector() {
        let sk_em = h("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736");
        let pk_rm = h("3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d");
        let info = h("4f6465206f6e2061204772656369616e2055726e");
        let pt = h("4265617574792069732074727574682c20747275746820626561757479");
        let aad = h("436f756e742d30");
        let want_ct = h("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a9\
6d8770ac83d07bea87e13c512a");

        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_em);
        let sk_e = StaticSecret::from(sk_arr);
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_rm);
        let recipient = PublicKey::from(pk_arr);

        let (enc, ct) = seal_with_ephemeral(&sk_e, &recipient, &info, &aad, &pt);
        assert_eq!(
            hex(enc.as_bytes()),
            "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431",
            "enc must equal the RFC's pkEm"
        );
        assert_eq!(ct, want_ct, "ciphertext must match the RFC byte for byte");

        // And the recipient (the RFC's skRm) recovers the plaintext.
        let sk_rm = h("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8");
        let mut sk_arr = [0u8; 32];
        sk_arr.copy_from_slice(&sk_rm);
        let recipient_sk = StaticSecret::from(sk_arr);
        let got = open(&recipient_sk, &enc, &info, &aad, &ct).expect("opens");
        assert_eq!(got, pt);
    }

    #[test]
    fn a_tampered_ciphertext_or_aad_fails_closed() {
        let sk = StaticSecret::random_from_rng(rand_core_06::OsRng);
        let pk = PublicKey::from(&sk);
        let (enc, ct) = seal(&pk, b"info", b"aad", b"secret");
        let mut bad = ct.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(open(&sk, &enc, b"info", b"aad", &bad).is_err());
        assert!(open(&sk, &enc, b"info", b"other-aad", &ct).is_err());
        assert!(open(&sk, &enc, b"other-info", b"aad", &ct).is_err());
    }

    #[test]
    fn the_all_zero_public_key_is_refused() {
        let zeros = "0".repeat(64);
        assert!(public_key_from_hex(&zeros).is_err());
    }
}
