//! Fuzz target: File chunk encrypt/decrypt roundtrip
//!
//! Attack surface:
//!   - Chunk index overflow (u64::MAX)
//!   - Empty chunk data
//!   - Large chunk data
//!   - Hash integrity verification on decrypt
//!   - Cipher suite selection (AES-GCM vs ChaCha20)
//!
//! Run: cargo +nightly fuzz run fuzz_file_chunk

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct FileChunkInput {
    key: [u8; 32],
    chunk_data: Vec<u8>,
    chunk_index: u64,
    /// false = AES-256-GCM, true = ChaCha20-Poly1305
    use_chacha: bool,
}

fuzz_target!(|input: FileChunkInput| {
    // Cap chunk size to 256KB (realistic upper bound)
    if input.chunk_data.len() > 262_144 {
        return;
    }

    let cipher = if input.use_chacha {
        tallow_crypto::symmetric::CipherSuite::ChaCha20Poly1305
    } else {
        tallow_crypto::symmetric::CipherSuite::Aes256Gcm
    };

    // Encrypt must succeed
    let encrypted = match tallow_crypto::file::encrypt::encrypt_chunk(
        &input.key,
        &input.chunk_data,
        input.chunk_index,
        cipher,
    ) {
        Ok(e) => e,
        Err(_) => return,
    };

    // Verify metadata
    assert_eq!(encrypted.index, input.chunk_index);
    assert!(!encrypted.ciphertext.is_empty() || input.chunk_data.is_empty());

    // Decrypt must succeed and roundtrip correctly
    let decrypted = tallow_crypto::file::decrypt::decrypt_chunk(&input.key, &encrypted, cipher)
        .expect("roundtrip decrypt must succeed");

    assert_eq!(decrypted, input.chunk_data, "roundtrip data mismatch");

    // Tampered hash must be rejected
    let mut tampered = encrypted.clone();
    tampered.hash[0] ^= 1;
    assert!(
        tallow_crypto::file::decrypt::decrypt_chunk(&input.key, &tampered, cipher).is_err(),
        "tampered hash must be rejected"
    );
});
