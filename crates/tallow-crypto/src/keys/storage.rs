//! Encrypted keyring storage
//!
//! Two envelope formats coexist:
//!
//! * **Legacy (v0)** — [`EncryptedKeyring`]: `salt ‖ nonce ‖ ciphertext` with
//!   Argon2id parameters implied (the interactive profile). The shape is kept
//!   byte-for-byte because `bincode`-encoded keyrings carry no field names and
//!   no serde defaults — changing this struct would hard-break every stored
//!   file.
//! * **Versioned (v2)** — [`EncryptedKeyringV2`]: a `TKR2` magic prefix, a
//!   format version, and the Argon2id profile id actually used for the
//!   derivation, so parameter-profile changes can never silently break an
//!   existing keyring again. [`open_keyring`] decodes either format and
//!   [`decrypt_opened_keyring`] decrypts through the recorded profile.
//!
//! New writes should prefer [`encrypt_keyring_v2`]. The legacy writer/reader
//! stay for compatibility and use [`Profile::Interactive`], the historical
//! production parameters.

use crate::error::{CryptoError, Result};
use crate::kdf::argon2::{self, Profile};
use crate::symmetric::{chacha_decrypt, chacha_encrypt};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Encrypted keyring (legacy shape — no version or KDF metadata).
///
/// The field set and order are frozen: `bincode` cannot default missing
/// fields, so altering this struct would break every keyring written by older
/// builds. Versioned envelopes are [`EncryptedKeyringV2`].
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedKeyring {
    /// Random salt used as input to Argon2id key derivation
    pub salt: [u8; 16],
    /// ChaCha20-Poly1305 nonce used during encryption
    pub nonce: [u8; 12],
    /// ChaCha20-Poly1305 encrypted key material including authentication tag
    pub ciphertext: Vec<u8>,
}

/// Magic prefix of every v2 keyring envelope (`b"TKR2"`).
///
/// Legacy envelopes begin with a random salt; the 4-byte ASCII magic makes
/// the two formats unambiguous for [`open_keyring`]. A random collision is
/// about one in 2^32 and even then the v2 decode fails cleanly rather than
/// misreading.
pub const KEYRING_V2_MAGIC: [u8; 4] = *b"TKR2";

/// Format version carried inside [`EncryptedKeyringV2`].
pub const KEYRING_V2_VERSION: u8 = 2;

/// Versioned keyring envelope (v2).
///
/// Unlike the legacy shape this records *how* the encryption key was derived:
/// the Argon2id profile id ([`Profile::id`]) is persisted and used on every
/// subsequent read, so changing the crate's default parameters can never
/// silently break an existing keyring.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedKeyringV2 {
    /// Always [`KEYRING_V2_MAGIC`]; validated on open/decrypt.
    pub magic: [u8; 4],
    /// Always [`KEYRING_V2_VERSION`]; validated on open/decrypt.
    pub version: u8,
    /// Argon2id profile id ([`Profile::id`]) used for this derivation.
    pub kdf: u8,
    /// Random salt used as input to Argon2id key derivation
    pub salt: [u8; 16],
    /// ChaCha20-Poly1305 nonce used during encryption
    pub nonce: [u8; 12],
    /// ChaCha20-Poly1305 encrypted key material including authentication tag
    pub ciphertext: Vec<u8>,
}

/// A keyring decoded by [`open_keyring`] — either envelope format.
#[derive(Clone)]
pub enum OpenedKeyring {
    /// Legacy v0 shape (no version/KDF metadata; interactive profile implied).
    Legacy(EncryptedKeyring),
    /// Versioned v2 envelope.
    V2(EncryptedKeyringV2),
}

/// Encrypt a keyring with a passphrase (legacy v0 writer).
///
/// Kept for compatibility with existing callers and `bincode` consumers; new
/// code should prefer [`encrypt_keyring_v2`], which records the KDF profile in
/// the envelope. This path uses [`Profile::Interactive`], the historical
/// production parameters, and is what every previously stored keyring was
/// written with.
pub fn encrypt_keyring(passphrase: &str, keys: &[u8]) -> Result<EncryptedKeyring> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    // Derive encryption key from passphrase
    let key = argon2::derive_key(passphrase.as_bytes(), &salt, 32)?;
    let key_array: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Argon2 derived key is not 32 bytes".to_string()))?;
    // key (Zeroizing<Vec<u8>>) auto-zeroizes on drop

    // Encrypt keys
    let ciphertext = chacha_encrypt(&key_array, &nonce, keys, &[]);

    // Zeroize stack copy of key material before returning
    let mut key_array = key_array;
    key_array.zeroize();

    Ok(EncryptedKeyring {
        salt,
        nonce,
        ciphertext: ciphertext?,
    })
}

/// Decrypt a keyring with a passphrase (legacy v0 reader).
pub fn decrypt_keyring(passphrase: &str, keyring: &EncryptedKeyring) -> Result<Vec<u8>> {
    // Derive decryption key from passphrase
    let key = argon2::derive_key(passphrase.as_bytes(), &keyring.salt, 32)?;
    let key_array: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Argon2 derived key is not 32 bytes".to_string()))?;
    // key (Zeroizing<Vec<u8>>) auto-zeroizes on drop

    // Decrypt keys
    let result = chacha_decrypt(&key_array, &keyring.nonce, &keyring.ciphertext, &[]);

    // Zeroize stack copy of key material before returning
    let mut key_array = key_array;
    key_array.zeroize();

    result
}

/// Encrypt a keyring under an explicit Argon2id profile (v2 writer), recording
/// the profile id in the envelope.
///
/// The chosen profile is persisted, so a later change of the crate's default
/// parameters cannot silently break this keyring: [`decrypt_keyring_v2`]
/// always derives with the profile the file was written with.
pub fn encrypt_keyring_v2(
    passphrase: &str,
    keys: &[u8],
    profile: Profile,
) -> Result<EncryptedKeyringV2> {
    let mut salt = [0u8; 16];
    OsRng.fill_bytes(&mut salt);
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);

    // Derive encryption key from passphrase under the requested profile
    let key = argon2::derive_key_with_profile(profile, passphrase.as_bytes(), &salt, 32)?;
    let key_array: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Argon2 derived key is not 32 bytes".to_string()))?;
    // key (Zeroizing<Vec<u8>>) auto-zeroizes on drop

    // Encrypt keys
    let ciphertext = chacha_encrypt(&key_array, &nonce, keys, &[]);

    // Zeroize stack copy of key material before returning
    let mut key_array = key_array;
    key_array.zeroize();

    Ok(EncryptedKeyringV2 {
        magic: KEYRING_V2_MAGIC,
        version: KEYRING_V2_VERSION,
        kdf: profile.id(),
        salt,
        nonce,
        ciphertext: ciphertext?,
    })
}

/// Decrypt a v2 envelope using the KDF profile recorded inside it.
///
/// Validates the envelope (magic, version, known profile id) before deriving;
/// unknown metadata is a hard error — never a silent fallback to a default
/// profile.
pub fn decrypt_keyring_v2(passphrase: &str, keyring: &EncryptedKeyringV2) -> Result<Vec<u8>> {
    validate_v2(keyring)?;

    // `validate_v2` guarantees a known id, and `from_id` has no hidden state.
    let profile = Profile::from_id(keyring.kdf).ok_or_else(|| {
        CryptoError::InvalidKey(format!("keyring: unknown KDF profile id {}", keyring.kdf))
    })?;

    // Derive decryption key from passphrase under the recorded profile
    let key = argon2::derive_key_with_profile(profile, passphrase.as_bytes(), &keyring.salt, 32)?;
    let key_array: [u8; 32] = key
        .as_slice()
        .try_into()
        .map_err(|_| CryptoError::InvalidKey("Argon2 derived key is not 32 bytes".to_string()))?;
    // key (Zeroizing<Vec<u8>>) auto-zeroizes on drop

    // Decrypt keys
    let result = chacha_decrypt(&key_array, &keyring.nonce, &keyring.ciphertext, &[]);

    // Zeroize stack copy of key material before returning
    let mut key_array = key_array;
    key_array.zeroize();

    result
}

/// Decode a serialized keyring in either format.
///
/// v2 envelopes are recognized by their `TKR2` magic prefix; everything else
/// is decoded as the legacy v0 shape (the only other format that has ever been
/// written). The envelope metadata is validated after decode.
pub fn open_keyring(bytes: &[u8]) -> Result<OpenedKeyring> {
    if bytes.len() >= KEYRING_V2_MAGIC.len() && bytes[..KEYRING_V2_MAGIC.len()] == KEYRING_V2_MAGIC
    {
        let ring: EncryptedKeyringV2 = bincode::deserialize(bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("keyring: v2 decode failed: {e}")))?;
        validate_v2(&ring)?;
        Ok(OpenedKeyring::V2(ring))
    } else {
        let ring: EncryptedKeyring = bincode::deserialize(bytes)
            .map_err(|e| CryptoError::InvalidKey(format!("keyring: legacy decode failed: {e}")))?;
        Ok(OpenedKeyring::Legacy(ring))
    }
}

/// Decrypt an [`OpenedKeyring`] with the format-appropriate path
/// (profile-aware for v2, interactive profile for legacy).
pub fn decrypt_opened_keyring(passphrase: &str, opened: &OpenedKeyring) -> Result<Vec<u8>> {
    match opened {
        OpenedKeyring::Legacy(ring) => decrypt_keyring(passphrase, ring),
        OpenedKeyring::V2(ring) => decrypt_keyring_v2(passphrase, ring),
    }
}

/// Validate v2 envelope metadata before any key derivation happens.
fn validate_v2(ring: &EncryptedKeyringV2) -> Result<()> {
    if ring.magic != KEYRING_V2_MAGIC {
        return Err(CryptoError::InvalidKey(
            "keyring: v2 envelope has a bad magic prefix".to_string(),
        ));
    }
    if ring.version != KEYRING_V2_VERSION {
        return Err(CryptoError::InvalidKey(format!(
            "keyring: unsupported envelope version {}",
            ring.version
        )));
    }
    if Profile::from_id(ring.kdf).is_none() {
        return Err(CryptoError::InvalidKey(format!(
            "keyring: unknown KDF profile id {}",
            ring.kdf
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixed-salt legacy bytes: decoding this exact blob must stay stable
    /// forever (it is what older builds wrote).
    fn legacy_blob_fixed() -> Vec<u8> {
        let ring = EncryptedKeyring {
            salt: [0x11u8; 16],
            nonce: [0x22u8; 12],
            ciphertext: vec![0xAA, 0xBB, 0xCC],
        };
        bincode::serialize(&ring).unwrap()
    }

    #[test]
    fn v2_roundtrip_with_vault_profile() {
        let ring = encrypt_keyring_v2("correct horse", &[0x42u8; 32], Profile::Vault).unwrap();
        assert_eq!(ring.magic, KEYRING_V2_MAGIC);
        assert_eq!(ring.version, KEYRING_V2_VERSION);
        assert_eq!(ring.kdf, Profile::Vault.id());
        assert_eq!(
            decrypt_keyring_v2("correct horse", &ring).unwrap(),
            vec![0x42u8; 32]
        );
        // Wrong passphrase fails the AEAD check, not a silent success.
        assert!(decrypt_keyring_v2("wrong", &ring).is_err());
    }

    #[test]
    fn v2_serialized_bytes_start_with_magic_and_open_as_v2() {
        let ring = encrypt_keyring_v2("pw", &[1u8; 8], Profile::Vault).unwrap();
        let bytes = bincode::serialize(&ring).unwrap();
        assert_eq!(&bytes[..4], &KEYRING_V2_MAGIC);
        match open_keyring(&bytes).unwrap() {
            OpenedKeyring::V2(r) => {
                assert_eq!(r.version, KEYRING_V2_VERSION);
                assert_eq!(
                    decrypt_opened_keyring("pw", &OpenedKeyring::V2(r)).unwrap(),
                    vec![1u8; 8]
                );
            }
            OpenedKeyring::Legacy(_) => panic!("TKR2-prefixed bytes must open as v2"),
        }
    }

    #[test]
    fn open_keyring_reads_legacy_blobs() {
        let bytes = legacy_blob_fixed();
        match open_keyring(&bytes).unwrap() {
            OpenedKeyring::Legacy(r) => {
                assert_eq!(r.salt, [0x11u8; 16]);
                assert_eq!(r.nonce, [0x22u8; 12]);
                assert_eq!(r.ciphertext, vec![0xAA, 0xBB, 0xCC]);
            }
            OpenedKeyring::V2(_) => panic!("legacy bytes must open as legacy"),
        }
    }

    #[test]
    fn legacy_roundtrip_through_open_and_decrypt() {
        // Full legacy write → serialize → open → decrypt (interactive profile).
        let legacy = encrypt_keyring("pw", &[0x33u8; 32]).unwrap();
        let bytes = bincode::serialize(&legacy).unwrap();
        let opened = open_keyring(&bytes).unwrap();
        assert_eq!(
            decrypt_opened_keyring("pw", &opened).unwrap(),
            vec![0x33u8; 32]
        );
    }

    #[test]
    fn v2_tamper_checks_are_clean_errors() {
        let base = encrypt_keyring_v2("pw", &[9u8; 8], Profile::Vault).unwrap();

        let mut bad = base.clone();
        bad.kdf = 9; // unknown profile id — rejected before any derivation
        assert!(decrypt_keyring_v2("pw", &bad).is_err());

        let mut bad = base.clone();
        bad.version = 3; // unknown version
        assert!(decrypt_keyring_v2("pw", &bad).is_err());

        let mut bad = base.clone();
        bad.magic = *b"XXXX"; // bad magic
        assert!(decrypt_keyring_v2("pw", &bad).is_err());
    }

    #[test]
    fn v2_profile_dispatch_proven_by_flip() {
        // Encrypted under Vault but with the id flipped to Interactive: the
        // stored id drives the derivation, so the key differs and the AEAD
        // check fails — there is no silent fallback to a default profile.
        let ring = encrypt_keyring_v2("pw", &[7u8; 16], Profile::Vault).unwrap();
        let mut flipped = ring.clone();
        flipped.kdf = Profile::Interactive.id();
        assert!(decrypt_keyring_v2("pw", &flipped).is_err());
    }

    #[test]
    fn v2_interactive_profile_roundtrip() {
        let ring = encrypt_keyring_v2("pw", &[0x77u8; 16], Profile::Interactive).unwrap();
        assert_eq!(ring.kdf, Profile::Interactive.id());
        assert_eq!(decrypt_keyring_v2("pw", &ring).unwrap(), vec![0x77u8; 16]);
    }
}
