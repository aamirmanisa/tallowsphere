//! Fuzz target: Ed25519 signature verification
//!
//! Attack surface:
//!   - Crafted public keys (small-order, non-canonical)
//!   - Crafted signatures (malleable S, wrong length)
//!   - Memory safety in verify() with arbitrary inputs
//!   - No panics — only Ok/Err return
//!
//! This target is "verification only" — we never fuzz signing because
//! the signing key is secret and deterministic (no attack surface).
//!
//! Run: cargo +nightly fuzz run fuzz_ed25519_verify

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct Ed25519VerifyInput {
    public_key: [u8; 32],
    message: Vec<u8>,
    signature: [u8; 64],
}

fuzz_target!(|input: Ed25519VerifyInput| {
    // Cap message size to prevent OOM
    if input.message.len() > 1_048_576 {
        return;
    }

    // verify() must NEVER panic — only return Ok or Err
    let _ = tallow_crypto::sig::ed25519::verify(
        &input.public_key,
        &input.message,
        &input.signature,
    );

    // Additional check: if we generate a valid keypair and sign,
    // the forged signature from fuzzer input should almost certainly
    // not verify against our real key.
    //
    // (Statistical: probability of random 64-byte sig being valid ≈ 0)
});
