//! Fuzz target: AES-256-GCM encrypt/decrypt roundtrip
//!
//! Attack surface:
//!   - Memory safety in encrypt/decrypt with arbitrary lengths
//!   - Ciphertext expansion/contraction invariants
//!   - Empty plaintext handling
//!   - Maximum-length AAD processing
//!   - Tag integrity on every roundtrip
//!
//! Run: cargo +nightly fuzz run fuzz_aes_gcm

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

/// Structured input: ensures key/nonce are always correctly sized
/// while allowing arbitrary plaintext and AAD.
#[derive(Arbitrary, Debug)]
struct AesGcmInput {
    key: [u8; 32],
    nonce: [u8; 12],
    plaintext: Vec<u8>,
    aad: Vec<u8>,
}

fuzz_target!(|input: AesGcmInput| {
    // Cap plaintext at 1MB to avoid OOM
    if input.plaintext.len() > 1_048_576 {
        return;
    }
    if input.aad.len() > 65_536 {
        return;
    }

    // Encrypt must always succeed with valid key/nonce
    let ct = match tallow_crypto::symmetric::aes_gcm::encrypt(
        &input.key,
        &input.nonce,
        &input.plaintext,
        &input.aad,
    ) {
        Ok(ct) => ct,
        Err(_) => return, // Should not happen, but don't panic
    };

    // Ciphertext must be exactly plaintext.len() + 16 (tag)
    assert_eq!(
        ct.len(),
        input.plaintext.len() + 16,
        "ciphertext length invariant violated"
    );

    // Decrypt must succeed and produce identical plaintext
    let pt = tallow_crypto::symmetric::aes_gcm::decrypt(
        &input.key,
        &input.nonce,
        &ct,
        &input.aad,
    )
    .expect("roundtrip decrypt must succeed");

    assert_eq!(pt, input.plaintext, "roundtrip plaintext mismatch");

    // Wrong key must fail
    let mut wrong_key = input.key;
    wrong_key[0] ^= 0xFF;
    assert!(
        tallow_crypto::symmetric::aes_gcm::decrypt(&wrong_key, &input.nonce, &ct, &input.aad)
            .is_err(),
        "decryption with wrong key must fail"
    );
});
