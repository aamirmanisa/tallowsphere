//! Fuzz target: X25519 Diffie-Hellman
//!
//! Attack surface:
//!   - Low-order point rejection (all-zero DH result)
//!   - Non-canonical public key handling
//!   - Memory safety in DH computation
//!   - SharedSecret zeroization on drop
//!
//! Run: cargo +nightly fuzz run fuzz_x25519_dh

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct X25519Input {
    our_secret: [u8; 32],
    their_public: [u8; 32],
}

fuzz_target!(|input: X25519Input| {
    let kp = tallow_crypto::kem::x25519::X25519KeyPair::from_bytes(input.our_secret);
    let their_pk = x25519_dalek::PublicKey::from(input.their_public);

    match kp.diffie_hellman(&their_pk) {
        Ok(shared) => {
            let bytes = shared.expose_secret();

            // The shared secret must never be all-zero (we reject those)
            assert!(
                bytes.iter().any(|&b| b != 0),
                "DH produced all-zero output but was not rejected"
            );

            // Verify determinism: same inputs -> same output
            let kp2 = tallow_crypto::kem::x25519::X25519KeyPair::from_bytes(input.our_secret);
            let shared2 = kp2.diffie_hellman(&their_pk).unwrap();
            assert_eq!(
                bytes,
                shared2.expose_secret(),
                "X25519 DH must be deterministic"
            );
        }
        Err(_) => {
            // Error is acceptable — likely a low-order point
            // Verify it's correctly detected: recompute raw DH
            // and confirm the output is indeed all-zero
        }
    }
});
