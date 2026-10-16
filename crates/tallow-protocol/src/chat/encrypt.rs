//! Chat message encryption/decryption
//!
//! Uses AES-256-GCM with counter-based nonces and domain-separated AAD.
//! Sender uses even nonce counters, receiver uses odd — preventing
//! nonce collision without coordination.

use crate::transfer::sanitize;

/// Maximum plaintext size for a single chat message (64 KB)
pub const MAX_CHAT_MESSAGE_SIZE: usize = 64 * 1024;

/// Domain separation AAD for chat messages (distinct from file transfer)
const CHAT_AAD: &[u8] = b"tallow-chat-v1";

/// Chat encryption errors
#[derive(Debug, thiserror::Error)]
pub enum ChatCryptoError {
    /// Message exceeds size limit
    #[error("message too large ({size} bytes, max {max})")]
    MessageTooLarge {
        /// Actual size
        size: usize,
        /// Maximum allowed
        max: usize,
    },
    /// AES-GCM encryption failed
    #[error("encryption failed: {0}")]
    EncryptionFailed(String),
    /// AES-GCM decryption failed
    #[error("decryption failed: {0}")]
    DecryptionFailed(String),
    /// Decrypted bytes are not valid UTF-8
    #[error("invalid UTF-8 in decrypted message: {0}")]
    InvalidUtf8(String),
}

/// Encrypt a chat message with AES-256-GCM.
///
/// Builds a 12-byte nonce from the counter, increments counter by 2
/// (even/odd split for sender/receiver), and returns (ciphertext, nonce).
pub fn encrypt_chat_text(
    plaintext: &str,
    session_key: &[u8; 32],
    nonce_counter: &mut u64,
) -> Result<(Vec<u8>, [u8; 12]), ChatCryptoError> {
    if plaintext.len() > MAX_CHAT_MESSAGE_SIZE {
        return Err(ChatCryptoError::MessageTooLarge {
            size: plaintext.len(),
            max: MAX_CHAT_MESSAGE_SIZE,
        });
    }

    // Build 12-byte nonce: [0x02 domain byte][3 zero bytes] || counter.to_be_bytes().
    // The domain byte (0x02 = chat) keeps chat nonces disjoint from chunk
    // nonces (0x01 = chunk, see `transfer::chunking`), so even an accidentally
    // shared key cannot produce an identical (key, nonce) pair across paths.
    let mut nonce = [0u8; 12];
    nonce[0] = 0x02;
    nonce[4..12].copy_from_slice(&nonce_counter.to_be_bytes());

    let ciphertext =
        tallow_crypto::symmetric::aes_encrypt(session_key, &nonce, plaintext.as_bytes(), CHAT_AAD)
            .map_err(|e| ChatCryptoError::EncryptionFailed(e.to_string()))?;

    *nonce_counter += 2; // Even/odd split

    Ok((ciphertext, nonce))
}

/// Decrypt a chat message with AES-256-GCM.
///
/// Verifies the AAD domain tag and returns sanitized plaintext.
pub fn decrypt_chat_text(
    ciphertext: &[u8],
    nonce: &[u8; 12],
    session_key: &[u8; 32],
) -> Result<String, ChatCryptoError> {
    // One-key-one-scheme (crypto report #9): a chat nonce must carry the chat
    // domain byte; a cross-path nonce here documents a scheme mix-up. The AAD
    // domain tag rejects it cryptographically regardless (this is a loud
    // debug-build tripwire, not the security boundary).
    debug_assert_eq!(nonce[0], 0x02, "chat nonce domain byte must be 0x02");
    let plaintext_bytes =
        tallow_crypto::symmetric::aes_decrypt(session_key, nonce, ciphertext, CHAT_AAD)
            .map_err(|e| ChatCryptoError::DecryptionFailed(e.to_string()))?;

    let text = String::from_utf8(plaintext_bytes)
        .map_err(|e| ChatCryptoError::InvalidUtf8(e.to_string()))?;

    // Sanitize to strip ANSI escapes and control characters
    Ok(sanitize::sanitize_display(&text))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        [42u8; 32]
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = test_key();
        let mut counter = 0u64;
        let (ct, nonce) = encrypt_chat_text("hello world", &key, &mut counter).unwrap();
        let decrypted = decrypt_chat_text(&ct, &nonce, &key).unwrap();
        assert_eq!(decrypted, "hello world");
    }

    #[test]
    fn test_nonce_counter_increments_by_two() {
        let key = test_key();
        let mut counter = 0u64;
        encrypt_chat_text("a", &key, &mut counter).unwrap();
        assert_eq!(counter, 2);
        encrypt_chat_text("b", &key, &mut counter).unwrap();
        assert_eq!(counter, 4);
        encrypt_chat_text("c", &key, &mut counter).unwrap();
        assert_eq!(counter, 6);
    }

    #[test]
    fn test_nonce_domain_byte() {
        let key = test_key();
        let mut counter = 0u64;
        let (_ct, nonce) = encrypt_chat_text("a", &key, &mut counter).unwrap();
        assert_eq!(nonce[0], 0x02);
        assert_eq!(&nonce[1..4], &[0u8; 3]);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key = test_key();
        let wrong_key = [0xFF; 32];
        let mut counter = 0u64;
        let (ct, nonce) = encrypt_chat_text("secret", &key, &mut counter).unwrap();
        let result = decrypt_chat_text(&ct, &nonce, &wrong_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_wrong_nonce_fails() {
        let key = test_key();
        let mut counter = 0u64;
        let (ct, nonce) = encrypt_chat_text("secret", &key, &mut counter).unwrap();
        // Flip a COUNTER byte, keeping the 0x02 domain byte intact (the decrypt
        // path debug-asserts it — one-key-one-scheme, crypto report #9).
        // Still the wrong nonce → authentication must fail.
        let mut wrong_nonce = nonce;
        wrong_nonce[11] ^= 0x01;
        let result = decrypt_chat_text(&ct, &wrong_nonce, &key);
        assert!(result.is_err());
    }

    #[test]
    fn test_message_too_large() {
        let key = test_key();
        let mut counter = 0u64;
        let big = "x".repeat(MAX_CHAT_MESSAGE_SIZE + 1);
        let result = encrypt_chat_text(&big, &key, &mut counter);
        assert!(matches!(
            result,
            Err(ChatCryptoError::MessageTooLarge { .. })
        ));
    }

    #[test]
    fn test_empty_message() {
        let key = test_key();
        let mut counter = 0u64;
        let (ct, nonce) = encrypt_chat_text("", &key, &mut counter).unwrap();
        let decrypted = decrypt_chat_text(&ct, &nonce, &key).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn test_unicode_message() {
        let key = test_key();
        let mut counter = 0u64;
        let text = "Hello 🌍 世界 مرحبا";
        let (ct, nonce) = encrypt_chat_text(text, &key, &mut counter).unwrap();
        let decrypted = decrypt_chat_text(&ct, &nonce, &key).unwrap();
        assert_eq!(decrypted, text);
    }

    #[test]
    fn test_ansi_sanitized() {
        let key = test_key();
        let mut counter = 0u64;
        let text = "hello \x1b[31mred\x1b[0m world";
        let (ct, nonce) = encrypt_chat_text(text, &key, &mut counter).unwrap();
        let decrypted = decrypt_chat_text(&ct, &nonce, &key).unwrap();
        // sanitize_display strips ANSI escapes
        assert!(!decrypted.contains("\x1b["));
        assert!(decrypted.contains("hello"));
        assert!(decrypted.contains("world"));
    }

    #[test]
    fn test_nonce_parity_prevents_collision() {
        let key = [99u8; 32];
        let mut sender_counter = 0u64; // even
        let mut receiver_counter = 1u64; // odd

        let (_, nonce_s1) = encrypt_chat_text("hello", &key, &mut sender_counter).unwrap();
        let (_, nonce_r1) = encrypt_chat_text("hi", &key, &mut receiver_counter).unwrap();
        let (_, nonce_s2) = encrypt_chat_text("world", &key, &mut sender_counter).unwrap();
        let (_, nonce_r2) = encrypt_chat_text("there", &key, &mut receiver_counter).unwrap();

        // No nonce should equal any other
        assert_ne!(nonce_s1, nonce_r1);
        assert_ne!(nonce_s1, nonce_s2);
        assert_ne!(nonce_r1, nonce_r2);
        assert_ne!(nonce_s2, nonce_r2);
    }
}

#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn roundtrip_arbitrary_text(text in "\\PC{1,1000}") {
            let key = [42u8; 32];
            let mut counter = 0u64;
            let (ct, nonce) = encrypt_chat_text(&text, &key, &mut counter).unwrap();
            let decrypted = decrypt_chat_text(&ct, &nonce, &key).unwrap();
            // sanitize_display may strip some control chars, so compare sanitized versions
            let expected = crate::transfer::sanitize::sanitize_display(&text);
            prop_assert_eq!(decrypted, expected);
        }
    }
}
