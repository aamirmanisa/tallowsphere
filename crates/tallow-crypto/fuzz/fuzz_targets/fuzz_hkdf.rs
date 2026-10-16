//! Fuzz target: HKDF-SHA256 key derivation
//!
//! Attack surface:
//!   - Output length boundary conditions (0, 1, 8160, 8161)
//!   - Empty salt/IKM/info handling
//!   - Determinism (same inputs always produce same output)
//!   - No panics on any input combination
//!
//! Run: cargo +nightly fuzz run fuzz_hkdf

#![no_main]
use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

#[derive(Arbitrary, Debug)]
struct HkdfInput {
    salt: Vec<u8>,
    ikm: Vec<u8>,
    info: Vec<u8>,
    /// Requested output length (capped to prevent OOM)
    len: u16,
}

fuzz_target!(|input: HkdfInput| {
    let len = input.len as usize;

    // HKDF-SHA256 max output = 255 * 32 = 8160 bytes
    // Lengths > 8160 MUST be rejected
    if len > 8160 {
        let result =
            tallow_crypto::kdf::hkdf::derive(&input.salt, &input.ikm, &input.info, len);
        assert!(result.is_err(), "HKDF must reject output > 8160 bytes");
        return;
    }

    // Zero-length output should be valid (empty key)
    if len == 0 {
        let result =
            tallow_crypto::kdf::hkdf::derive(&input.salt, &input.ikm, &input.info, len);
        // Either succeed with empty vec or fail gracefully
        if let Ok(okm) = result {
            assert_eq!(okm.len(), 0);
        }
        return;
    }

    // Normal case: must succeed and be deterministic
    let result1 =
        tallow_crypto::kdf::hkdf::derive(&input.salt, &input.ikm, &input.info, len);
    let result2 =
        tallow_crypto::kdf::hkdf::derive(&input.salt, &input.ikm, &input.info, len);

    match (result1, result2) {
        (Ok(okm1), Ok(okm2)) => {
            assert_eq!(okm1.len(), len, "output length mismatch");
            assert_eq!(okm1, okm2, "HKDF must be deterministic");
        }
        (Err(_), Err(_)) => {
            // Both failed consistently — acceptable
        }
        _ => {
            panic!("HKDF non-deterministic: one call succeeded, other failed");
        }
    }
});
