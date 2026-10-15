//! Fuzz target: ML-KEM-768 decapsulation against arbitrary ciphertexts.
//!
//! Security property: decapsulation of attacker-controlled ciphertexts must
//! never panic — it must return the deterministic implicit-rejection secret or
//! a clean error.
//!
//! Run: cargo +nightly fuzz run fuzz_mlkem_decaps

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tallow_crypto::kem::mlkem::{Ciphertext, MlKem};

#[derive(Arbitrary, Debug)]
struct Input {
    ct: Vec<u8>,
}

fuzz_target!(|input: Input| {
    // ML-KEM-768 ciphertexts are 1088 bytes; cap generously for parser safety.
    if input.ct.len() > 4096 {
        return;
    }
    let Ok(ct) = Ciphertext::from_bytes(input.ct) else {
        return;
    };
    let (_pk, sk) = match MlKem::keygen() {
        Ok(kp) => kp,
        Err(_) => return,
    };
    // Must not panic; Err is acceptable (invalid length / malformed).
    let _ = MlKem::decapsulate(&sk, &ct);
});
