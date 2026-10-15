//! Handshake construction + transcript math (mirrors the reference core's
//! message builders and `deriveSession`).
//!
//! Message layouts (raw keys — the reference's DER SPKI wrapping is dropped):
//!
//! ```text
//! msg1 = "T1S" | ephC_pub(32) | pad(16..64)
//! msg2 = "T1A" | ephS_pub(32) | nonceS(32) | sigS(64) | pad(16..64)
//! msg3 = "T1C" | device_id(utf8) | ts_ms(8 BE) | sigC(64)
//! ```
//!
//! Transcript binding: s1 = H("tallow-v0" | msg1); s2 = H(s1 | msg2);
//! s3 = H(s2 | msg3). The server signs H(s1 | ephS_pub | nonceS); the client
//! signs H(s2 | device_id | ts_ms). Session keys: HKDF-SHA256 over
//! ikm = DH1 | DH2 with salt H(nonceS | s3) into directional keys
//! `tallow-v0/c2s` and `tallow-v0/s2c`.

use hkdf::Hkdf;
use rand::Rng;
use sha2::{Digest, Sha256};
use x25519_dalek::SharedSecret;

use crate::{MAGIC1, MAGIC2, MAGIC3, PAD_JITTER, PAD_MIN, PROTO_LABEL};

/// sha256 over the concatenation of parts.
pub fn sha256_cat(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Random padding length: `PAD_MIN + uniform(0..PAD_JITTER)`.
pub fn random_pad() -> usize {
    PAD_MIN + rand::thread_rng().gen_range(0..PAD_JITTER)
}

/// Cryptographically random bytes.
pub fn random_bytes(n: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut v = vec![0u8; n];
    rand::thread_rng().fill_bytes(&mut v);
    v
}

/// Build msg1 (client → server).
pub fn build_msg1(eph_c_pub: &[u8; 32], pad_len: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + 32 + pad_len);
    v.extend_from_slice(MAGIC1);
    v.extend_from_slice(eph_c_pub);
    v.extend_from_slice(&random_bytes(pad_len));
    v
}

/// Build msg2 (server → client). `sig_s` is the server's Ed25519 signature
/// over [`server_sig_digest`].
pub fn build_msg2(
    eph_s_pub: &[u8; 32],
    nonce_s: &[u8; 32],
    sig_s: &[u8; 64],
    pad_len: usize,
) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + 32 + 32 + 64 + pad_len);
    v.extend_from_slice(MAGIC2);
    v.extend_from_slice(eph_s_pub);
    v.extend_from_slice(nonce_s);
    v.extend_from_slice(sig_s);
    v.extend_from_slice(&random_bytes(pad_len));
    v
}

/// Build msg3 (client → server).
pub fn build_msg3(device_id: &str, ts_ms: u64, sig_c: &[u8; 64]) -> Vec<u8> {
    let mut v = Vec::with_capacity(3 + device_id.len() + 8 + 64);
    v.extend_from_slice(MAGIC3);
    v.extend_from_slice(device_id.as_bytes());
    v.extend_from_slice(&ts_ms.to_be_bytes());
    v.extend_from_slice(sig_c);
    v
}

/// s1 = H("tallow-v0" | msg1).
pub fn s1_digest(msg1: &[u8]) -> [u8; 32] {
    sha256_cat(&[PROTO_LABEL, msg1])
}

/// Digest the server signs: H(s1 | ephS_pub | nonceS).
pub fn server_sig_digest(s1: &[u8; 32], eph_s_pub: &[u8; 32], nonce_s: &[u8; 32]) -> [u8; 32] {
    sha256_cat(&[s1, eph_s_pub, nonce_s])
}

/// s2 = H(s1 | msg2).
pub fn s2_digest(s1: &[u8; 32], msg2: &[u8]) -> [u8; 32] {
    sha256_cat(&[s1, msg2])
}

/// Digest the client signs: H(s2 | device_id | ts_ms).
pub fn client_sig_digest(s2: &[u8; 32], device_id: &[u8], ts_ms: u64) -> [u8; 32] {
    sha256_cat(&[s2, device_id, &ts_ms.to_be_bytes()])
}

/// s3 = H(s2 | msg3).
pub fn s3_digest(s2: &[u8; 32], msg3: &[u8]) -> [u8; 32] {
    sha256_cat(&[s2, msg3])
}

/// Directional session keys.
pub struct SessionKeys {
    /// Client → server key.
    pub k_c2s: [u8; 32],
    /// Server → client key.
    pub k_s2c: [u8; 32],
}

/// Derive session keys from the two DH shared secrets, nonceS and s3.
///
/// DH1 = ephemeral×ephemeral; DH2 mixes the server's static X25519 key with
/// the client ephemeral — either side computes the same shared value from
/// its own half. Both sides MUST pass `(dh1, dh2)` in that order.
pub fn derive_session(
    dh1: &SharedSecret,
    dh2: &SharedSecret,
    nonce_s: &[u8; 32],
    s3: &[u8; 32],
) -> SessionKeys {
    let mut ikm = [0u8; 64];
    ikm[..32].copy_from_slice(dh1.as_bytes());
    ikm[32..].copy_from_slice(dh2.as_bytes());
    let salt = sha256_cat(&[nonce_s, s3]);
    let hk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut k_c2s = [0u8; 32];
    let mut k_s2c = [0u8; 32];
    hk.expand(b"tallow-v0/c2s", &mut k_c2s)
        .expect("32-byte HKDF expand");
    hk.expand(b"tallow-v0/s2c", &mut k_s2c)
        .expect("32-byte HKDF expand");
    SessionKeys { k_c2s, k_s2c }
}

/// First 16 hex chars of sha256(key) — the session fingerprint used in audit
/// lines (mirrors the reference `fingerprint`).
pub fn key_fp(key: &[u8; 32]) -> String {
    hex::encode(Sha256::digest(key))[..16].to_string()
}
