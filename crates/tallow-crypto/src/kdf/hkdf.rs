//! HKDF (HMAC-based Key Derivation Function) implementation

use crate::error::{CryptoError, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

/// Derive key material using HKDF-SHA256
///
/// # Arguments
///
/// * `salt` - Optional salt value (use empty slice for no salt)
/// * `ikm` - Input key material
/// * `info` - Application-specific context information
/// * `len` - Length of output key material in bytes
///
/// # Returns
///
/// Derived key material of the requested length
///
/// # Example
///
/// ```ignore
/// let derived = derive(b"salt", b"input_key_material", b"app_context", 32)?;
/// ```
pub fn derive(salt: &[u8], ikm: &[u8], info: &[u8], len: usize) -> Result<Zeroizing<Vec<u8>>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

    let mut okm = Zeroizing::new(vec![0u8; len]);
    hk.expand(info, &mut okm)
        .map_err(|e| CryptoError::KeyGeneration(format!("HKDF expansion failed: {}", e)))?;

    Ok(okm)
}

/// Derive multiple keys from a single input
///
/// # Arguments
///
/// * `salt` - Optional salt value
/// * `ikm` - Input key material
/// * `contexts` - List of (info, length) pairs for each output key
///
/// # Returns
///
/// Vector of derived keys, one for each context
pub fn derive_multiple(
    salt: &[u8],
    ikm: &[u8],
    contexts: &[(&[u8], usize)],
) -> Result<Vec<Zeroizing<Vec<u8>>>> {
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);

    let mut outputs = Vec::with_capacity(contexts.len());

    for (info, len) in contexts {
        let mut okm = Zeroizing::new(vec![0u8; *len]);
        hk.expand(info, &mut okm)
            .map_err(|e| CryptoError::KeyGeneration(format!("HKDF expansion failed: {}", e)))?;
        outputs.push(okm);
    }

    Ok(outputs)
}

/// Derive a key using BLAKE3 in KDF mode (alternative to HKDF)
///
/// This is a simpler, faster alternative that uses BLAKE3's native KDF mode.
///
/// # Arguments
///
/// * `context` - Context string for domain separation
/// * `ikm` - Input key material
/// * `len` - Length of output key material
///
/// # Returns
///
/// Derived key material
pub fn derive_blake3(context: &str, ikm: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut output = Zeroizing::new(vec![0u8; len]);
    let mut hasher = blake3::Hasher::new_derive_key(context);
    hasher.update(ikm);
    let mut reader = hasher.finalize_xof();
    reader.fill(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hkdf_derive() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context";

        let key1 = derive(salt, ikm, info, 32).unwrap();
        let key2 = derive(salt, ikm, info, 32).unwrap();

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }

    #[test]
    fn test_hkdf_different_info() {
        let ikm = b"input key material";
        let salt = b"salt";

        let key1 = derive(salt, ikm, b"context1", 32).unwrap();
        let key2 = derive(salt, ikm, b"context2", 32).unwrap();

        assert_ne!(key1, key2);
    }

    #[test]
    fn test_hkdf_different_length() {
        let ikm = b"input key material";
        let salt = b"salt";
        let info = b"context";

        let key1 = derive(salt, ikm, info, 32).unwrap();
        let key2 = derive(salt, ikm, info, 64).unwrap();

        assert_eq!(key1.len(), 32);
        assert_eq!(key2.len(), 64);
        // First 32 bytes should be the same
        assert_eq!(key1[..], key2[..32]);
    }

    #[test]
    fn test_derive_multiple() {
        let ikm = b"input key material";
        let salt = b"salt";
        let contexts = vec![(b"key1".as_slice(), 32), (b"key2".as_slice(), 16)];

        let keys = derive_multiple(salt, ikm, &contexts).unwrap();

        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].len(), 32);
        assert_eq!(keys[1].len(), 16);
        assert_ne!(keys[0][..16], keys[1][..]);
    }

    #[test]
    fn test_derive_blake3() {
        let ikm = b"input key material";
        let key1 = derive_blake3("context", ikm, 32);
        let key2 = derive_blake3("context", ikm, 32);

        assert_eq!(key1, key2);
        assert_eq!(key1.len(), 32);
    }
}
