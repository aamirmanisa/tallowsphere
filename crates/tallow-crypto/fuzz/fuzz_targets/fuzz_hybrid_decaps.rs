//! Fuzz target: hybrid X25519 + ML-KEM decapsulation against arbitrary input.
//!
//! Security property: hybrid decapsulation must never panic on
//! attacker-controlled ciphertext bytes and must reject malformed input
//! cleanly.
//!
//! Run: cargo +nightly fuzz run fuzz_hybrid_decaps

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use tallow_crypto::kem::hybrid::{Ciphertext, HybridKem};
use tallow_crypto::kem::mlkem;

#[derive(Arbitrary, Debug)]
struct Input {
    mlkem_ct: Vec<u8>,
    x25519_public: [u8; 32],
}

fuzz_target!(|input: Input| {
    if input.mlkem_ct.len() > 4096 {
        return;
    }
    let Ok(mlkem_ct) = mlkem::Ciphertext::from_bytes(input.mlkem_ct) else {
        return;
    };
    let ct = Ciphertext {
        mlkem: mlkem_ct,
        x25519_public: x25519_dalek::PublicKey::from(input.x25519_public),
    };
    let (_pk, sk) = match HybridKem::keygen() {
        Ok(kp) => kp,
        Err(_) => return,
    };
    let _ = HybridKem::decapsulate(&sk, &ct);
});
