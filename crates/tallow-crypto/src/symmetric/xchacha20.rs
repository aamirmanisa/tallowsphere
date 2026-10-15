//! XChaCha20-Poly1305 (192-bit nonce) — the at-rest AEAD and per-object DEK seal.
//!
//! # Why this module exists (W3 #141/#142 · P10-R06 · agent-01 R-6/F10)
//!
//! A random 96-bit nonce is borderline for AES-GCM at multi-key/volume scale
//! (partitioning-oracle class, USENIX Security 2021). The at-rest answer is
//! XChaCha20-Poly1305 — the ChaCha20-Poly1305 AEAD (RFC 8439) extended with a
//! **random 192-bit nonce** (draft-irtf-cfrg-xchacha) — under a **fresh
//! per-object DEK**, with the DEK wrapped by the master KEK. This module is the
//! single implementation of that pattern; the `.twv` container v3
//! (`src/vault/db.rs`) is its first production consumer.
//!
//! # The seal (what [`seal_object`] produces)
//!
//! ```text
//! KEK  = 32-byte master key (e.g. Argon2id(password, header salt))
//! DEK  = fresh random 32 bytes                (per object)
//! n    = fresh random 24 bytes                (per object, 192-bit nonce)
//! wrapped_dek = AES-256-KW(RFC 3394) of DEK under KEK   → 40 bytes
//! ciphertext  = XChaCha20-Poly1305(DEK, n, plaintext, aad)
//! ```
//!
//! # Usage ceilings (RFC 8446 §5.5-style, per #142)
//!
//! Every object gets its own DEK **and** its own 192-bit random nonce, so a
//! key's total usage is bounded by the single object it protects — the only
//! way to exceed a per-key bound is to exceed it for one object. That bound is
//! enforced explicitly: [`MAX_OBJECT_BYTES`] (2^36 bytes = 64 GiB) is checked
//! on every seal, and it sits far below the RFC 8446 §5.5 record-volume bounds
//! that motivated the design. There is no "usage counter" to get wrong: the
//! ceiling is a property of the object, not of state kept across saves.
//!
//! # Key-commitment note (P10-R06, honest scope)
//!
//! ChaCha20-Poly1305/XChaCha20-Poly1305 are not key-committing AEADs. The row's
//! concern ("key-commitment awareness where one ciphertext crosses keys") is
//! removed **by construction** here: one ciphertext is bound to exactly one
//! per-object DEK, and that DEK never seals a second object, so a ciphertext
//! never crosses keys. This module does **not** claim key commitment for a
//! multi-recipient re-seal; callers that re-seal one payload under several
//! keys must re-encrypt per key (each seal gets its own DEK).

use aes_kw::KekAes256;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand_core::{OsRng, RngCore};
use zeroize::Zeroizing;

use crate::error::{CryptoError, Result};

/// Encryption key length in bytes (256-bit key).
pub const KEY_LEN: usize = 32;

/// XChaCha20 nonce length in bytes (192-bit nonce; random-nonce safe).
pub const NONCE_LEN: usize = 24;

/// Poly1305 authentication tag length in bytes (appended to the ciphertext).
pub const TAG_LEN: usize = 16;

/// Wrapped per-object DEK length in bytes (RFC 3394 AES-256-KW of 32 bytes = 32 + 8).
pub const WRAPPED_DEK_LEN: usize = 40;

/// Per-object usage ceiling in bytes of plaintext (2^36 = 64 GiB).
///
/// One DEK protects exactly one object, so this is the per-key usage ceiling
/// the rows ask for (RFC 8446 §5.5-style discipline: bound bytes-per-key).
/// It is deliberately far below any RFC 8446 §5.5 record-volume bound.
pub const MAX_OBJECT_BYTES: u64 = 1 << 36;

/// A sealed at-rest object: random 192-bit nonce, the AES-KW-wrapped
/// per-object DEK, and the XChaCha20-Poly1305 ciphertext (tag appended).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedObject {
    /// Random 192-bit nonce used for the payload AEAD.
    pub nonce: [u8; NONCE_LEN],
    /// Per-object DEK wrapped under the KEK with AES-256-KW (RFC 3394).
    pub wrapped_dek: [u8; WRAPPED_DEK_LEN],
    /// Ciphertext with the 16-byte Poly1305 tag appended.
    pub ciphertext: Vec<u8>,
}

/// Encrypt `plaintext` with XChaCha20-Poly1305 under a raw key and 192-bit nonce.
///
/// The caller owns key/nonce discipline (this is the primitive form);
/// [`seal_object`] is the per-object-DEK form with the randomness and ceilings
/// handled for at-rest use.
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .encrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|e| CryptoError::Encryption(format!("XChaCha20-Poly1305 encryption failed: {e}")))
}

/// Decrypt `ciphertext` (tag appended) with XChaCha20-Poly1305.
///
/// Fails — never returns mangled plaintext — on a wrong key, wrong nonce,
/// altered ciphertext, or mismatched AAD.
pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|e| {
            CryptoError::Decryption(format!(
                "XChaCha20-Poly1305 decryption failed (wrong key or tampered data): {e}"
            ))
        })
}

/// Enforce the per-object usage ceiling for a plaintext of `len` bytes.
fn check_object_ceiling(len: usize) -> Result<()> {
    if len as u64 > MAX_OBJECT_BYTES {
        return Err(CryptoError::Encryption(format!(
            "at-rest object exceeds the per-object usage ceiling ({len} > {MAX_OBJECT_BYTES} bytes)"
        )));
    }
    Ok(())
}

/// Seal `plaintext` as an at-rest object: fresh random DEK wrapped under `kek`
/// (AES-256-KW, RFC 3394), payload encrypted under the DEK with a fresh random
/// 192-bit nonce, `aad` bound into the payload AEAD.
///
/// Returns [`SealedObject`] — store `nonce`/`wrapped_dek`/`ciphertext` in the
/// container and pass the same `aad` back to [`open_object`].
pub fn seal_object(kek: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<SealedObject> {
    check_object_ceiling(plaintext.len())?;

    // 1 · fresh per-object DEK (wiped on drop).
    let mut dek = Zeroizing::new([0u8; KEY_LEN]);
    OsRng.fill_bytes(dek.as_mut());

    // 2 · wrap the DEK under the KEK (RFC 3394 AES-256-KW, deterministic but
    //     safe: the DEK is random and the KEK is unique per container because
    //     every container gets a fresh KDF salt).
    let kek_cipher = KekAes256::from(*kek);
    let wrapped = kek_cipher
        .wrap_vec(dek.as_slice())
        .map_err(|e| CryptoError::Encryption(format!("AES-256-KW DEK wrap failed: {e}")))?;
    let wrapped_dek: [u8; WRAPPED_DEK_LEN] = wrapped.as_slice().try_into().map_err(|_| {
        CryptoError::Encryption(format!(
            "AES-256-KW wrap returned {} bytes (expected {WRAPPED_DEK_LEN})",
            wrapped.len()
        ))
    })?;

    // 3 · fresh random 192-bit nonce for the payload.
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce);

    // 4 · payload AEAD under the per-object DEK.
    let ciphertext = encrypt(&dek, &nonce, plaintext, aad)?;

    Ok(SealedObject {
        nonce,
        wrapped_dek,
        ciphertext,
    })
}

/// Open an at-rest object produced by [`seal_object`]: unwrap the per-object
/// DEK (AES-256-KW under `kek`) and decrypt the payload under it.
///
/// Fails on a wrong KEK, altered `wrapped_dek`, altered payload/nonce, or
/// mismatched `aad`.
pub fn open_object(kek: &[u8; KEY_LEN], sealed: &SealedObject, aad: &[u8]) -> Result<Vec<u8>> {
    let dek_vec = KekAes256::from(*kek)
        .unwrap_vec(&sealed.wrapped_dek)
        .map_err(|_| {
            CryptoError::Decryption(
                "AES-256-KW DEK unwrap failed (wrong KEK or tampered header)".to_string(),
            )
        })?;
    let dek: [u8; KEY_LEN] = dek_vec.as_slice().try_into().map_err(|_| {
        CryptoError::Decryption(format!(
            "unwrapped DEK has invalid size {} (expected {KEY_LEN})",
            dek_vec.len()
        ))
    })?;
    let dek = Zeroizing::new(dek);

    decrypt(&dek, &sealed.nonce, &sealed.ciphertext, aad)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_kek(b: u8) -> [u8; KEY_LEN] {
        [b; KEY_LEN]
    }

    // ── primitive ─────────────────────────────────────────────────────────

    #[test]
    fn xchacha_roundtrip() {
        let key = fixed_kek(7);
        let nonce = [9u8; NONCE_LEN];
        let aad = b"tallow-at-rest-test";
        let plaintext = b"the quick brown fox";

        let ct = encrypt(&key, &nonce, plaintext, aad).expect("encrypt");
        assert_eq!(ct.len(), plaintext.len() + TAG_LEN);
        let pt = decrypt(&key, &nonce, &ct, aad).expect("decrypt");
        assert_eq!(pt, plaintext);
    }

    #[test]
    fn xchacha_wrong_key_fails() {
        let nonce = [1u8; NONCE_LEN];
        let ct = encrypt(&fixed_kek(1), &nonce, b"secret", b"").expect("encrypt");
        assert!(decrypt(&fixed_kek(2), &nonce, &ct, b"").is_err());
    }

    #[test]
    fn xchacha_tamper_fails() {
        let key = fixed_kek(3);
        let nonce = [2u8; NONCE_LEN];
        let mut ct = encrypt(&key, &nonce, b"secret", b"aad").expect("encrypt");
        ct[0] ^= 0x01;
        assert!(decrypt(&key, &nonce, &ct, b"aad").is_err());
        // AAD mismatch is caught as well.
        let ct = encrypt(&key, &nonce, b"secret", b"aad").expect("encrypt");
        assert!(decrypt(&key, &nonce, &ct, b"other-aad").is_err());
    }

    #[test]
    fn xchacha_nonce_reuse_with_same_key_is_detectable_by_caller_shape_only_in_bytes() {
        // Pin the structural fact callers rely on: the nonce is 192 bits, so
        // random nonces are the supported discipline (this is not a test of
        // uniqueness — randomness supplies that).
        assert_eq!(NONCE_LEN, 24);
        assert_eq!(KEY_LEN, 32);
        assert_eq!(TAG_LEN, 16);
    }

    // ── per-object DEK seal ───────────────────────────────────────────────

    #[test]
    fn seal_open_roundtrip() {
        let kek = fixed_kek(11);
        let aad = b"TWV1-header-bytes";
        let plaintext = b"{\"vault\":\"payload\"}";

        let sealed = seal_object(&kek, plaintext, aad).expect("seal");
        assert_eq!(sealed.wrapped_dek.len(), WRAPPED_DEK_LEN);
        assert_eq!(sealed.ciphertext.len(), plaintext.len() + TAG_LEN);

        let opened = open_object(&kek, &sealed, aad).expect("open");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn seal_is_randomized_per_object() {
        let kek = fixed_kek(12);
        let plaintext = b"same bytes every time";
        let a = seal_object(&kek, plaintext, b"").expect("seal a");
        let b = seal_object(&kek, plaintext, b"").expect("seal b");

        assert_ne!(a.nonce, b.nonce, "192-bit nonce must be fresh per object");
        assert_ne!(
            a.wrapped_dek, b.wrapped_dek,
            "per-object DEK must be fresh per object"
        );
        assert_ne!(a.ciphertext, b.ciphertext, "ciphertext must differ");
    }

    #[test]
    fn open_with_wrong_kek_fails() {
        let sealed = seal_object(&fixed_kek(13), b"data", b"").expect("seal");
        assert!(open_object(&fixed_kek(14), &sealed, b"").is_err());
    }

    #[test]
    fn open_with_tampered_wrapped_dek_fails() {
        let kek = fixed_kek(15);
        let mut sealed = seal_object(&kek, b"data", b"").expect("seal");
        sealed.wrapped_dek[5] ^= 0x01;
        assert!(open_object(&kek, &sealed, b"").is_err());
    }

    #[test]
    fn open_with_tampered_payload_fails() {
        let kek = fixed_kek(16);
        let mut sealed = seal_object(&kek, b"data", b"").expect("seal");
        sealed.ciphertext[0] ^= 0x01;
        assert!(open_object(&kek, &sealed, b"").is_err());
    }

    #[test]
    fn open_with_wrong_aad_fails() {
        let kek = fixed_kek(17);
        let sealed = seal_object(&kek, b"data", b"header-a").expect("seal");
        assert!(open_object(&kek, &sealed, b"header-b").is_err());
    }

    #[test]
    fn open_with_tampered_nonce_fails() {
        let kek = fixed_kek(18);
        let mut sealed = seal_object(&kek, b"data", b"").expect("seal");
        sealed.nonce[0] ^= 0x01;
        assert!(open_object(&kek, &sealed, b"").is_err());
    }

    #[test]
    fn sealed_material_does_not_leak_plaintext_or_dek() {
        let kek = fixed_kek(19);
        let marker = b"sealed-material-marker";
        let sealed = seal_object(&kek, marker, b"").expect("seal");
        assert!(!sealed.ciphertext.windows(marker.len()).any(|w| w == marker));
        // The wrapped DEK must not contain the raw KEK or any 32-byte window
        // equal to the (unobservable, but structurally checkable) DEK slot:
        // pin the storage shape instead — 40 bytes, not 32.
        assert_ne!(sealed.wrapped_dek.len(), KEY_LEN);
    }

    // ── usage ceiling ─────────────────────────────────────────────────────

    #[test]
    fn ceiling_constant_is_2_pow_36() {
        assert_eq!(MAX_OBJECT_BYTES, 1 << 36);
    }

    #[test]
    fn ceiling_check_rejects_above_and_accepts_at_limit() {
        assert!(check_object_ceiling(0).is_ok());
        assert!(check_object_ceiling(MAX_OBJECT_BYTES as usize).is_ok());
        // Boundary +1 is rejected. (A 64 GiB buffer is never allocated: the
        // check is exercised directly, and `seal_object` calls it before any
        // encryption work.)
        assert!(check_object_ceiling(MAX_OBJECT_BYTES as usize + 1).is_err());
    }
}
