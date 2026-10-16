//! Fuzz target: SLH-DSA verification against arbitrary inputs.
//!
//! Security property: verifying attacker-controlled public keys, messages and
//! signatures must never panic — malformed inputs return a clean error.
//!
//! Run: cargo +nightly fuzz run fuzz_slhdsa_verify

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tallow_crypto::sig::slhdsa;

#[derive(Arbitrary, Debug)]
struct Input {
    public_key: Vec<u8>,
    message: Vec<u8>,
    signature: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // SLH-DSA-256f signatures are ~49 KiB; cap a little above that so the
    // real size is inside the harness while keeping runs fast.
    if input.public_key.len() > 8192 || input.message.len() > 4096 || input.signature.len() > 65536
    {
        return;
    }
    // Must not panic; Err is acceptable (wrong length / malformed encoding).
    let _ = slhdsa::verify(&input.public_key, &input.message, &input.signature);
});
