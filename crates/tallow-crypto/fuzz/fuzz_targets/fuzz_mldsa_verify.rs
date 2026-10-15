//! Fuzz target: ML-DSA-87 verification against arbitrary inputs.
//!
//! Security property: verifying attacker-controlled public keys, messages and
//! signatures must never panic — malformed inputs return a clean error.
//!
//! Run: cargo +nightly fuzz run fuzz_mldsa_verify

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tallow_crypto::sig::mldsa;

#[derive(Arbitrary, Debug)]
struct Input {
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // Cap lengths: real ML-DSA-87 keys are ~2.6 KiB and signatures ~4.6 KiB;
    // keep the harness fast while allowing a generous margin around the real
    // sizes.
    if input.public_key.len() > 8192 || input.message.len() > 4096 || input.signature.len() > 16384
    {
        return;
    }
    // Must not panic; Err is acceptable (wrong length / malformed encoding).
    let _ = mldsa::verify(&input.public_key, &input.message, &input.signature);
});
