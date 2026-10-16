//! Fuzz target: scoped (per-transfer) chunk decryption with arbitrary inputs.
//!
//! Security property: `decrypt_chunk_scoped` must never panic on
//! attacker-controlled ciphertext / transfer ids; every path returns Err.
//!
//! Run: cargo +nightly fuzz run fuzz_chunk_scoped

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tallow_crypto::file::{decrypt_chunk_scoped, EncryptedChunk};
use tallow_crypto::CipherSuite;

#[derive(Arbitrary, Debug)]
struct Input {
    session_key: [u8; 32],
    transfer_id: Vec<u8>,
    index: u64,
    ciphertext: Vec<u8>,
    hash: [u8; 32],
}

fuzz_target!(|input: Input| {
    if input.ciphertext.len() > 1_048_576 {
        return;
    }
    let chunk = EncryptedChunk {
        index: input.index,
        ciphertext: input.ciphertext,
        hash: input.hash,
    };
    // Must never panic; Err is the expected path for hostile input.
    let _ = decrypt_chunk_scoped(
        &input.session_key,
        &input.transfer_id,
        &chunk,
        CipherSuite::Aes256Gcm,
    );
});
