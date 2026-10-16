//! Filename encryption for privacy in transit
//!
//! Encrypts filenames using AES-256-GCM so the relay and network
//! observers cannot see what files are being transferred.

use crate::{ProtocolError, Result};

/// Encrypt a filename for transit
///
/// Uses AES-256-GCM with a random nonce prepended to the ciphertext.
/// The encrypted filename is base64url-encoded for safe transmission.
/// Compatible with [`decrypt_filename`] for round-trip operation.
pub fn encrypt_filename(filename: &str, key: &[u8; 32]) -> Result<String> {
    // Use a random nonce prepended to ciphertext for safe decryption
    encrypt_filename_random(filename, key)
}

/// Decrypt a filename received in transit
pub fn decrypt_filename(encrypted: &str, key: &[u8; 32]) -> Result<String> {
    let ciphertext = base64url_decode(encrypted)
        .map_err(|e| ProtocolError::TransferFailed(format!("Invalid encrypted filename: {}", e)))?;

    // We need to try all possible nonces since we derive it from the plaintext
    // which we don't have yet. Instead, store the nonce as a prefix.
    // Re-approach: prepend the 12-byte nonce to the ciphertext during encryption.

    // Actually, let's use a simpler approach: random nonce prepended to ciphertext
    if ciphertext.len() < 12 {
        return Err(ProtocolError::TransferFailed(
            "Encrypted filename too short".to_string(),
        ));
    }

    let (nonce_bytes, ct) = ciphertext.split_at(12);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(nonce_bytes);

    let aad = b"tallow-filename-v1";
    let plaintext = tallow_crypto::symmetric::aes_decrypt(key, &nonce, ct, aad)
        .map_err(|e| ProtocolError::TransferFailed(format!("Filename decryption failed: {}", e)))?;

    String::from_utf8(plaintext)
        .map_err(|e| ProtocolError::TransferFailed(format!("Invalid UTF-8 filename: {}", e)))
}

/// Encrypt a filename with random nonce (prepended to output)
pub fn encrypt_filename_random(filename: &str, key: &[u8; 32]) -> Result<String> {
    let nonce: [u8; 12] = rand::random();
    let plaintext = filename.as_bytes();
    let aad = b"tallow-filename-v1";

    let ciphertext = tallow_crypto::symmetric::aes_encrypt(key, &nonce, plaintext, aad)
        .map_err(|e| ProtocolError::TransferFailed(format!("Filename encryption failed: {}", e)))?;

    // Prepend nonce to ciphertext
    let mut output = Vec::with_capacity(12 + ciphertext.len());
    output.extend_from_slice(&nonce);
    output.extend_from_slice(&ciphertext);

    Ok(base64url_encode(&output))
}

/// Simple base64url encoding (no padding)
fn base64url_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

    let mut result = String::new();
    let mut i = 0;

    while i < data.len() {
        let b0 = data[i] as u32;
        let b1 = if i + 1 < data.len() {
            data[i + 1] as u32
        } else {
            0
        };
        let b2 = if i + 2 < data.len() {
            data[i + 2] as u32
        } else {
            0
        };

        let triple = (b0 << 16) | (b1 << 8) | b2;

        result.push(ALPHABET[((triple >> 18) & 0x3F) as usize] as char);
        result.push(ALPHABET[((triple >> 12) & 0x3F) as usize] as char);

        if i + 1 < data.len() {
            result.push(ALPHABET[((triple >> 6) & 0x3F) as usize] as char);
        }
        if i + 2 < data.len() {
            result.push(ALPHABET[(triple & 0x3F) as usize] as char);
        }

        i += 3;
    }

    result
}

/// Simple base64url decoding
fn base64url_decode(s: &str) -> std::result::Result<Vec<u8>, String> {
    fn char_to_val(c: u8) -> std::result::Result<u32, String> {
        match c {
            b'A'..=b'Z' => Ok((c - b'A') as u32),
            b'a'..=b'z' => Ok((c - b'a' + 26) as u32),
            b'0'..=b'9' => Ok((c - b'0' + 52) as u32),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(format!("Invalid base64url character: {}", c as char)),
        }
    }

    let bytes = s.as_bytes();
    let mut result = Vec::new();
    let mut i = 0;

    while i < bytes.len() {
        let v0 = char_to_val(bytes[i])?;
        let v1 = if i + 1 < bytes.len() {
            char_to_val(bytes[i + 1])?
        } else {
            0
        };
        let v2 = if i + 2 < bytes.len() {
            char_to_val(bytes[i + 2])?
        } else {
            0
        };
        let v3 = if i + 3 < bytes.len() {
            char_to_val(bytes[i + 3])?
        } else {
            0
        };

        let triple = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;

        result.push(((triple >> 16) & 0xFF) as u8);
        if i + 2 < bytes.len() {
            result.push(((triple >> 8) & 0xFF) as u8);
        }
        if i + 3 < bytes.len() {
            result.push((triple & 0xFF) as u8);
        }

        i += 4;
    }

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = [42u8; 32];
        let filename = "secret_document.pdf";

        let encrypted = encrypt_filename_random(filename, &key).unwrap();
        assert_ne!(encrypted, filename);

        let decrypted = decrypt_filename(&encrypted, &key).unwrap();
        assert_eq!(decrypted, filename);
    }

    #[test]
    fn test_different_keys_different_output() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let filename = "test.txt";

        let enc1 = encrypt_filename_random(filename, &key1).unwrap();
        let enc2 = encrypt_filename_random(filename, &key2).unwrap();

        // Different keys produce different ciphertexts (overwhelmingly likely)
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];

        let encrypted = encrypt_filename_random("test.txt", &key1).unwrap();
        let result = decrypt_filename(&encrypted, &key2);
        assert!(result.is_err());
    }

    #[test]
    fn test_base64url_roundtrip() {
        let data = b"hello world test data 123";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap();
        assert_eq!(&decoded[..data.len()], data.as_slice());
    }
}
