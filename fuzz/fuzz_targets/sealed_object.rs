//! At-rest object parsing: the nonce and wrapped DEK come straight from the
//! fuzzer, the ciphertext is the remaining bytes. Property: no panic, and an
//! object that opens must re-seal to the same plaintext under the same KEK.
#![no_main]
use libfuzzer_sys::fuzz_target;
use tallow_crypto::symmetric::xchacha20::{open_object, seal_object, SealedObject};

fuzz_target!(|data: &[u8]| {
    const NONCE: usize = 24;
    const WRAPPED: usize = 40; // AES-256-KW wraps a 32-byte DEK into 40 bytes
    if data.len() < 32 + NONCE + WRAPPED {
        return;
    }
    let mut kek = [0u8; 32];
    kek.copy_from_slice(&data[..32]);

    let mut nonce = [0u8; NONCE];
    nonce.copy_from_slice(&data[32..32 + NONCE]);
    let mut wrapped_dek = [0u8; WRAPPED];
    wrapped_dek.copy_from_slice(&data[32 + NONCE..32 + NONCE + WRAPPED]);
    let ciphertext = data[32 + NONCE + WRAPPED..].to_vec();

    let sealed = SealedObject { nonce, wrapped_dek, ciphertext };
    if let Ok(pt) = open_object(&kek, &sealed, b"tallow") {
        let re = seal_object(&kek, &pt, b"tallow").expect("re-seal");
        let back = open_object(&kek, &re, b"tallow").expect("re-open");
        assert_eq!(back, pt, "re-sealed object must reopen to the same plaintext");
    }
});
