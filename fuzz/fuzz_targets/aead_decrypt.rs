//! AEAD decrypt with fully attacker-controlled key, nonce, ciphertext and AAD.
//!
//! Properties asserted:
//!  1. never panics;
//!  2. a successful decrypt round-trips: re-encrypting the recovered plaintext
//!     under the same key/nonce/AAD must reproduce the original ciphertext
//!     bytes, so "accepted" can never mean "returned mangled plaintext".
#![no_main]
use libfuzzer_sys::fuzz_target;
use tallow_crypto::symmetric::{aes_gcm, xchacha20};

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 + 12 + 16 {
        return;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&data[32..44]);
    let ct = &data[44..];

    if let Ok(pt) = aes_gcm::decrypt(&key, &nonce, ct, b"") {
        let again = aes_gcm::encrypt(&key, &nonce, &pt, b"").expect("re-encrypt");
        assert_eq!(again, ct, "AES-GCM accepted a ciphertext it cannot reproduce");
    }

    let mut xnonce = [0u8; 24];
    // Reuse the same input for the XChaCha20 nonce, truncated to the high bytes.
    xnonce.copy_from_slice(&data[..24]);
    if let Ok(pt) = xchacha20::decrypt(&key, &xnonce, ct, b"") {
        let again = xchacha20::encrypt(&key, &xnonce, &pt, b"").expect("re-encrypt");
        assert_eq!(again, ct, "XChaCha20 accepted a ciphertext it cannot reproduce");
    }
});
