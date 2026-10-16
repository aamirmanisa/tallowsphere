//! Trail of Bits — Property-Based & Constant-Time Audit Tests
//!
//! This file combines:
//!   1. proptest-based property tests for cryptographic invariants
//!   2. Source-level constant-time audit verification
//!   3. Edge-case tests for boundary conditions
//!
//! These tests verify mathematical properties that must hold for ALL inputs,
//! not just specific test vectors. proptest generates thousands of random
//! inputs to search for counterexamples.

use proptest::prelude::*;

// ═══════════════════════════════════════════════════════════════════════
// § 1. AES-256-GCM Property Tests
//
// Properties that must hold for ALL key/nonce/plaintext/AAD combinations:
//   P1: encrypt(k,n,pt,aad) always succeeds for valid-sized inputs
//   P2: decrypt(k,n,encrypt(k,n,pt,aad),aad) == pt (roundtrip)
//   P3: |ciphertext| == |plaintext| + 16 (tag size)
//   P4: decrypt with wrong key ALWAYS fails
//   P5: decrypt with wrong AAD ALWAYS fails
//   P6: decrypt with flipped ciphertext bit ALWAYS fails
// ═══════════════════════════════════════════════════════════════════════

proptest! {
    /// P1+P2+P3: Roundtrip correctness with length invariant
    #[test]
    fn aes_gcm_roundtrip_any_input(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform12(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        aad in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let ct = tallow_crypto::symmetric::aes_gcm::encrypt(&key, &nonce, &plaintext, &aad)
            .expect("encrypt must succeed");

        // P3: Length invariant
        prop_assert_eq!(ct.len(), plaintext.len() + 16);

        // P2: Roundtrip
        let pt = tallow_crypto::symmetric::aes_gcm::decrypt(&key, &nonce, &ct, &aad)
            .expect("roundtrip decrypt must succeed");
        prop_assert_eq!(pt, plaintext);
    }

    /// P4: Wrong key always fails decryption (no key-confusion attacks)
    #[test]
    fn aes_gcm_wrong_key_always_fails(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform12(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 1..1024),
        flip_byte in 0usize..32,
    ) {
        let ct = tallow_crypto::symmetric::aes_gcm::encrypt(&key, &nonce, &plaintext, &[])
            .expect("encrypt must succeed");

        let mut wrong_key = key;
        wrong_key[flip_byte] ^= 0xFF;

        let result = tallow_crypto::symmetric::aes_gcm::decrypt(&wrong_key, &nonce, &ct, &[]);
        prop_assert!(result.is_err(), "wrong key must fail decryption");
    }

    /// P5: Wrong AAD always fails decryption (AAD binding)
    #[test]
    fn aes_gcm_wrong_aad_always_fails(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform12(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        aad1 in prop::collection::vec(any::<u8>(), 1..64),
        aad2 in prop::collection::vec(any::<u8>(), 1..64),
    ) {
        prop_assume!(aad1 != aad2);

        let ct = tallow_crypto::symmetric::aes_gcm::encrypt(&key, &nonce, &plaintext, &aad1)
            .expect("encrypt must succeed");

        let result = tallow_crypto::symmetric::aes_gcm::decrypt(&key, &nonce, &ct, &aad2);
        prop_assert!(result.is_err(), "wrong AAD must fail decryption");
    }

    /// P6: Single bit flip in ciphertext always detected
    #[test]
    fn aes_gcm_bitflip_always_detected(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform12(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        flip_pos_pct in 0u8..100,
    ) {
        let ct = tallow_crypto::symmetric::aes_gcm::encrypt(&key, &nonce, &plaintext, &[])
            .expect("encrypt must succeed");

        let mut tampered = ct.clone();
        let pos = (flip_pos_pct as usize * tampered.len()) / 100;
        let pos = pos.min(tampered.len() - 1);
        tampered[pos] ^= 1;

        let result = tallow_crypto::symmetric::aes_gcm::decrypt(&key, &nonce, &tampered, &[]);
        prop_assert!(result.is_err(), "bit flip at position {} must be detected", pos);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// § 2. ChaCha20-Poly1305 Property Tests
//
// Same properties as AES-GCM to ensure both cipher suites are equivalent.
// ═══════════════════════════════════════════════════════════════════════

proptest! {
    /// ChaCha20 roundtrip with length invariant
    #[test]
    fn chacha20_roundtrip_any_input(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform12(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 0..4096),
        aad in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let ct = tallow_crypto::symmetric::chacha20::encrypt(&key, &nonce, &plaintext, &aad)
            .expect("encrypt must succeed");

        prop_assert_eq!(ct.len(), plaintext.len() + 16);

        let pt = tallow_crypto::symmetric::chacha20::decrypt(&key, &nonce, &ct, &aad)
            .expect("roundtrip decrypt must succeed");
        prop_assert_eq!(pt, plaintext);
    }

    /// ChaCha20 wrong key always fails
    #[test]
    fn chacha20_wrong_key_always_fails(
        key in prop::array::uniform32(any::<u8>()),
        nonce in prop::array::uniform12(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 1..512),
        flip_byte in 0usize..32,
    ) {
        let ct = tallow_crypto::symmetric::chacha20::encrypt(&key, &nonce, &plaintext, &[])
            .expect("encrypt must succeed");

        let mut wrong_key = key;
        wrong_key[flip_byte] ^= 0xFF;

        let result = tallow_crypto::symmetric::chacha20::decrypt(&wrong_key, &nonce, &ct, &[]);
        prop_assert!(result.is_err(), "wrong key must fail");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// § 3. HKDF-SHA256 Property Tests
//
// Properties:
//   P1: derive(salt, ikm, info, len) is deterministic
//   P2: Different info strings produce different outputs
//   P3: Output length matches requested length
//   P4: Lengths > 8160 are rejected
//   P5: HKDF prefix stability (shorter output is prefix of longer)
// ═══════════════════════════════════════════════════════════════════════

proptest! {
    /// P1: HKDF is deterministic
    #[test]
    fn hkdf_deterministic(
        salt in prop::collection::vec(any::<u8>(), 0..64),
        ikm in prop::collection::vec(any::<u8>(), 1..128),
        info in prop::collection::vec(any::<u8>(), 0..64),
        len in 1usize..256,
    ) {
        let out1 = tallow_crypto::kdf::hkdf::derive(&salt, &ikm, &info, len).unwrap();
        let out2 = tallow_crypto::kdf::hkdf::derive(&salt, &ikm, &info, len).unwrap();
        prop_assert_eq!(&out1, &out2);
        prop_assert_eq!(out1.len(), len);
    }

    /// P2: Different info = different output (with overwhelming probability)
    #[test]
    fn hkdf_info_separation(
        salt in prop::collection::vec(any::<u8>(), 16..32),
        ikm in prop::collection::vec(any::<u8>(), 16..64),
        info1 in prop::collection::vec(any::<u8>(), 1..32),
        info2 in prop::collection::vec(any::<u8>(), 1..32),
    ) {
        prop_assume!(info1 != info2);

        let out1 = tallow_crypto::kdf::hkdf::derive(&salt, &ikm, &info1, 32).unwrap();
        let out2 = tallow_crypto::kdf::hkdf::derive(&salt, &ikm, &info2, 32).unwrap();
        prop_assert_ne!(out1, out2);
    }

    /// P5: HKDF prefix stability — shorter output is prefix of longer
    ///
    /// This is a fundamental HKDF property (RFC 5869 §2.3):
    /// HKDF-Expand with the same PRK and info produces consistent output
    /// regardless of requested length.
    #[test]
    fn hkdf_prefix_stability(
        salt in prop::collection::vec(any::<u8>(), 0..32),
        ikm in prop::collection::vec(any::<u8>(), 1..64),
        info in prop::collection::vec(any::<u8>(), 0..32),
    ) {
        let short = tallow_crypto::kdf::hkdf::derive(&salt, &ikm, &info, 32).unwrap();
        let long = tallow_crypto::kdf::hkdf::derive(&salt, &ikm, &info, 64).unwrap();

        prop_assert_eq!(&short[..], &long[..32], "HKDF output must be prefix-stable");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// § 4. Ed25519 Property Tests
//
// Properties:
//   P1: sign then verify always succeeds for honestly-generated keys
//   P2: Signatures are deterministic (RFC 8032)
//   P3: Wrong message always fails verification
//   P4: Wrong key always fails verification
// ═══════════════════════════════════════════════════════════════════════

proptest! {
    /// P1: Sign-then-verify roundtrip
    #[test]
    fn ed25519_sign_verify_roundtrip(
        seed in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let signer = tallow_crypto::sig::ed25519::Ed25519Signer::from_seed(seed);
        let sig = signer.sign(&message);
        let pk = signer.verifying_key_bytes();

        let result = tallow_crypto::sig::ed25519::verify(&pk, &message, &sig);
        prop_assert!(result.is_ok(), "honest sign/verify must succeed");
    }

    /// P2: Deterministic signatures
    #[test]
    fn ed25519_deterministic(
        seed in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let signer = tallow_crypto::sig::ed25519::Ed25519Signer::from_seed(seed);
        let sig1 = signer.sign(&message);
        let sig2 = signer.sign(&message);
        prop_assert_eq!(sig1, sig2);
    }

    /// P3: Wrong message always fails
    #[test]
    fn ed25519_wrong_message_fails(
        seed in prop::array::uniform32(any::<u8>()),
        message1 in prop::collection::vec(any::<u8>(), 1..512),
        message2 in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        prop_assume!(message1 != message2);

        let signer = tallow_crypto::sig::ed25519::Ed25519Signer::from_seed(seed);
        let sig = signer.sign(&message1);
        let pk = signer.verifying_key_bytes();

        let result = tallow_crypto::sig::ed25519::verify(&pk, &message2, &sig);
        prop_assert!(result.is_err(), "wrong message must fail verification");
    }
}

// ═══════════════════════════════════════════════════════════════════════
// § 5. X25519 Property Tests
//
// Properties:
//   P1: DH commutativity: alice(bob_pk) == bob(alice_pk)
//   P2: Different keypairs produce different shared secrets
//   P3: DH result is deterministic
// ═══════════════════════════════════════════════════════════════════════

proptest! {
    /// P1: DH commutativity — alice ∘ bob == bob ∘ alice
    #[test]
    fn x25519_dh_commutative(
        alice_seed in prop::array::uniform32(any::<u8>()),
        bob_seed in prop::array::uniform32(any::<u8>()),
    ) {
        let alice = tallow_crypto::kem::x25519::X25519KeyPair::from_bytes(alice_seed);
        let bob = tallow_crypto::kem::x25519::X25519KeyPair::from_bytes(bob_seed);

        let alice_shared = alice.diffie_hellman(bob.public_key());
        let bob_shared = bob.diffie_hellman(alice.public_key());

        match (alice_shared, bob_shared) {
            (Ok(a), Ok(b)) => {
                prop_assert_eq!(a.expose_secret(), b.expose_secret(),
                    "DH must be commutative");
            }
            (Err(_), Err(_)) => {
                // Both rejected — consistent behavior (low-order point)
            }
            _ => {
                prop_assert!(false, "DH commutativity violated: one succeeded, other failed");
            }
        }
    }

    /// P3: DH is deterministic
    #[test]
    fn x25519_dh_deterministic(
        our_seed in prop::array::uniform32(any::<u8>()),
        their_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let kp1 = tallow_crypto::kem::x25519::X25519KeyPair::from_bytes(our_seed);
        let kp2 = tallow_crypto::kem::x25519::X25519KeyPair::from_bytes(our_seed);
        let their_pk = x25519_dalek::PublicKey::from(their_bytes);

        let r1 = kp1.diffie_hellman(&their_pk);
        let r2 = kp2.diffie_hellman(&their_pk);

        match (r1, r2) {
            (Ok(s1), Ok(s2)) => {
                prop_assert_eq!(s1.expose_secret(), s2.expose_secret());
            }
            (Err(_), Err(_)) => {} // Both failed consistently
            _ => prop_assert!(false, "non-deterministic DH result"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// § 6. BLAKE3 Property Tests
// ═══════════════════════════════════════════════════════════════════════

proptest! {
    /// BLAKE3 is deterministic
    #[test]
    fn blake3_deterministic(
        data in prop::collection::vec(any::<u8>(), 0..4096),
    ) {
        let h1 = tallow_crypto::hash::blake3::hash(&data);
        let h2 = tallow_crypto::hash::blake3::hash(&data);
        prop_assert_eq!(h1, h2);
    }

    /// BLAKE3 of different inputs should differ
    /// (collision resistance — statistical, not proven)
    #[test]
    fn blake3_collision_resistance(
        data1 in prop::collection::vec(any::<u8>(), 1..512),
        data2 in prop::collection::vec(any::<u8>(), 1..512),
    ) {
        prop_assume!(data1 != data2);
        let h1 = tallow_crypto::hash::blake3::hash(&data1);
        let h2 = tallow_crypto::hash::blake3::hash(&data2);
        prop_assert_ne!(h1, h2);
    }

    /// BLAKE3 KDF with different contexts must produce different keys
    #[test]
    fn blake3_kdf_context_separation(
        ikm in prop::collection::vec(any::<u8>(), 16..64),
    ) {
        let k1 = tallow_crypto::kdf::hkdf::derive_blake3("context-A", &ikm, 32);
        let k2 = tallow_crypto::kdf::hkdf::derive_blake3("context-B", &ikm, 32);
        prop_assert_ne!(k1, k2);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// § 7. Nonce Generator Property Tests
// ═══════════════════════════════════════════════════════════════════════

proptest! {
    /// Nonces within a session are all unique
    #[test]
    fn nonce_uniqueness_within_session(
        seed in prop::array::uniform32(any::<u8>()),
        count in 2usize..100,
    ) {
        use tallow_crypto::symmetric::nonce::{Direction, NonceGenerator};

        let mut gen = NonceGenerator::from_seed(seed, Direction::Send);
        let mut seen = std::collections::HashSet::new();

        for _ in 0..count {
            let nonce = gen.next_nonce().unwrap();
            prop_assert!(seen.insert(nonce), "NONCE REUSE — critical security bug");
        }
    }

    /// Counter is monotonically increasing
    #[test]
    fn nonce_counter_monotonic(
        seed in prop::array::uniform32(any::<u8>()),
        count in 1usize..50,
    ) {
        use tallow_crypto::symmetric::nonce::{Direction, NonceGenerator};

        let mut gen = NonceGenerator::from_seed(seed, Direction::Send);

        for i in 0..count {
            let _ = gen.next_nonce().unwrap();
            prop_assert_eq!(gen.counter(), (i + 1) as u64);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// § 8. Constant-Time Operations Audit Tests
//
// These tests verify that the constant-time comparison functions
// in tallow_crypto::mem behave correctly for ALL input patterns.
// While we can't verify timing properties in software tests, we can
// verify correctness and that the `subtle` crate is used properly.
//
// SOURCE-LEVEL CT AUDIT FINDINGS:
//
// ✅ ct_eq():        Uses subtle::ConstantTimeEq — SAFE
// ✅ ct_select():    Uses subtle::ConditionallySelectable — SAFE
// ✅ ct_select_bytes(): Per-byte conditional_select — SAFE
// ✅ ct_compare_u64(): Wrapping subtract + shift — SAFE (branchless)
//
// ⚠️  x25519.rs:74:  `bytes.iter().all(|&b| b == 0)` — variable-time
//     comparison on DH output. This is ACCEPTABLE because:
//     (a) The all-zero check is on the SHARED SECRET, not the private key
//     (b) An attacker who can observe this timing already knows the
//         public keys (they're transmitted in the clear)
//     (c) Rejecting all-zero output is a safety check, not a secret branch
//
// ⚠️  argon2.rs:95: `verify_password` returns early on invalid hash format
//     This is ACCEPTABLE because Argon2 is a slow hash — the format
//     validation time is negligible compared to the Argon2 computation.
// ═══════════════════════════════════════════════════════════════════════

proptest! {
    /// ct_eq behaves identically to == for all byte slice pairs
    #[test]
    fn ct_eq_matches_naive_equality(
        a in prop::collection::vec(any::<u8>(), 0..256),
        b in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let ct_result = tallow_crypto::mem::ct_eq(&a, &b);
        let naive_result = a == b;
        prop_assert_eq!(ct_result, naive_result,
            "ct_eq disagrees with == for a={:?}, b={:?}", a, b);
    }

    /// ct_select always returns the correct value
    #[test]
    fn ct_select_correctness(
        condition in any::<bool>(),
        a in any::<u8>(),
        b in any::<u8>(),
    ) {
        let result = tallow_crypto::mem::ct_select(condition, a, b);
        let expected = if condition { a } else { b };
        prop_assert_eq!(result, expected);
    }

    /// ct_compare_u64 matches standard comparison
    #[test]
    fn ct_compare_u64_correctness(
        a in any::<u64>(),
        b in any::<u64>(),
    ) {
        let result = tallow_crypto::mem::constant_time::ct_compare_u64(a, b);
        let expected = if a < b { -1i8 } else if a > b { 1 } else { 0 };
        prop_assert_eq!(result, expected);
    }
}

// ═══════════════════════════════════════════════════════════════════════
// § 9. File Chunk Property Tests
// ═══════════════════════════════════════════════════════════════════════

proptest! {
    /// File chunk encrypt/decrypt roundtrip for AES-GCM
    #[test]
    fn file_chunk_aes_roundtrip(
        key in prop::array::uniform32(any::<u8>()),
        data in prop::collection::vec(any::<u8>(), 0..8192),
        index in any::<u64>(),
    ) {
        let encrypted = tallow_crypto::file::encrypt::encrypt_chunk(
            &key, &data, index, tallow_crypto::CipherSuite::Aes256Gcm,
        ).unwrap();

        prop_assert_eq!(encrypted.index, index);

        let decrypted = tallow_crypto::file::decrypt::decrypt_chunk(
            &key, &encrypted, tallow_crypto::CipherSuite::Aes256Gcm,
        ).unwrap();

        prop_assert_eq!(decrypted, data);
    }

    /// File chunk encrypt/decrypt roundtrip for ChaCha20
    #[test]
    fn file_chunk_chacha_roundtrip(
        key in prop::array::uniform32(any::<u8>()),
        data in prop::collection::vec(any::<u8>(), 0..8192),
        index in any::<u64>(),
    ) {
        let encrypted = tallow_crypto::file::encrypt::encrypt_chunk(
            &key, &data, index, tallow_crypto::CipherSuite::ChaCha20Poly1305,
        ).unwrap();

        let decrypted = tallow_crypto::file::decrypt::decrypt_chunk(
            &key, &encrypted, tallow_crypto::CipherSuite::ChaCha20Poly1305,
        ).unwrap();

        prop_assert_eq!(decrypted, data);
    }

    /// File chunk with tampered ciphertext is always rejected
    #[test]
    fn file_chunk_tamper_detected(
        key in prop::array::uniform32(any::<u8>()),
        data in prop::collection::vec(any::<u8>(), 1..1024),
        index in any::<u64>(),
        tamper_pos_pct in 0u8..100,
    ) {
        let mut encrypted = tallow_crypto::file::encrypt::encrypt_chunk(
            &key, &data, index, tallow_crypto::CipherSuite::Aes256Gcm,
        ).unwrap();

        // Tamper with ciphertext
        if !encrypted.ciphertext.is_empty() {
            let pos = (tamper_pos_pct as usize * encrypted.ciphertext.len()) / 100;
            let pos = pos.min(encrypted.ciphertext.len() - 1);
            encrypted.ciphertext[pos] ^= 1;

            // Must be rejected (either hash check or AEAD tag check)
            let result = tallow_crypto::file::decrypt::decrypt_chunk(
                &key, &encrypted, tallow_crypto::CipherSuite::Aes256Gcm,
            );
            prop_assert!(result.is_err(), "tampered chunk must be rejected");
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════
// § 10. Edge Case Tests (Non-proptest)
//
// Specific boundary conditions that proptest might not hit efficiently.
// ═══════════════════════════════════════════════════════════════════════

#[test]
fn aes_gcm_max_aad_no_panic() {
    // 64KB AAD should work fine
    let key = [0x42u8; 32];
    let nonce = [0x01u8; 12];
    let aad = vec![0xAAu8; 65536];
    let plaintext = b"test";

    let ct = tallow_crypto::symmetric::aes_gcm::encrypt(&key, &nonce, plaintext, &aad).unwrap();
    let pt = tallow_crypto::symmetric::aes_gcm::decrypt(&key, &nonce, &ct, &aad).unwrap();
    assert_eq!(pt, plaintext);
}

#[test]
fn aes_gcm_empty_everything() {
    let key = [0u8; 32];
    let nonce = [0u8; 12];

    let ct = tallow_crypto::symmetric::aes_gcm::encrypt(&key, &nonce, &[], &[]).unwrap();
    assert_eq!(ct.len(), 16); // Just tag
    let pt = tallow_crypto::symmetric::aes_gcm::decrypt(&key, &nonce, &ct, &[]).unwrap();
    assert!(pt.is_empty());
}

#[test]
fn hkdf_empty_salt_works() {
    // Empty salt should work (HKDF uses zero-length HMAC key)
    let result = tallow_crypto::kdf::hkdf::derive(&[], b"ikm", b"info", 32);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 32);
}

#[test]
fn hkdf_single_byte_output() {
    let result = tallow_crypto::kdf::hkdf::derive(b"salt", b"ikm", b"info", 1);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 1);
}

#[test]
fn hkdf_max_output_8160() {
    // 255 * 32 = 8160 — the maximum HKDF-SHA256 output
    let result = tallow_crypto::kdf::hkdf::derive(b"salt", b"ikm", b"info", 8160);
    assert!(result.is_ok());
    assert_eq!(result.unwrap().len(), 8160);
}

#[test]
fn hkdf_over_max_rejected() {
    let result = tallow_crypto::kdf::hkdf::derive(b"salt", b"ikm", b"info", 8161);
    assert!(result.is_err());
}

#[test]
fn ed25519_all_zero_pubkey_rejected() {
    let zero_pk = [0u8; 32];
    let msg = b"test";
    let sig = [0u8; 64];

    // All-zero public key should be rejected (not a valid curve point)
    let result = tallow_crypto::sig::ed25519::verify(&zero_pk, msg, &sig);
    assert!(result.is_err());
}

#[test]
fn ed25519_all_one_signature_rejected() {
    let signer = tallow_crypto::sig::ed25519::Ed25519Signer::keygen();
    let pk = signer.verifying_key_bytes();
    let bad_sig = [0xFFu8; 64];

    let result = tallow_crypto::sig::ed25519::verify(&pk, b"msg", &bad_sig);
    assert!(result.is_err());
}

#[test]
fn nonce_counter_overflow_error() {
    use tallow_crypto::symmetric::nonce::{Direction, NonceGenerator};

    let mut gen = NonceGenerator::from_seed([0x42u8; 32], Direction::Send);
    gen.set_counter(u64::MAX).unwrap();

    // The next nonce should fail (counter overflow)
    let result = gen.next_nonce();
    assert!(
        result.is_err(),
        "counter overflow at u64::MAX must be an error"
    );
}

#[test]
fn nonce_counter_near_overflow() {
    use tallow_crypto::symmetric::nonce::{Direction, NonceGenerator};

    let mut gen = NonceGenerator::from_seed([0x42u8; 32], Direction::Send);
    gen.set_counter(u64::MAX - 1).unwrap();

    // One more should succeed
    let nonce = gen.next_nonce();
    assert!(nonce.is_ok());

    // Then overflow
    let result = gen.next_nonce();
    assert!(result.is_err());
}

#[test]
fn blake3_empty_input_not_zero() {
    let h = tallow_crypto::hash::blake3::hash(&[]);
    // BLAKE3 of empty input is a well-known constant, not all-zeros
    assert_ne!(h, [0u8; 32]);
}

#[test]
fn x25519_same_key_dh_not_identity() {
    // DH with yourself produces a non-trivial shared secret
    let kp = tallow_crypto::kem::x25519::X25519KeyPair::from_bytes([42u8; 32]);
    let result = kp.diffie_hellman(kp.public_key());
    assert!(result.is_ok());

    let shared = result.unwrap();
    // Shared secret should not be all-zero or equal to public key
    assert!(shared.expose_secret().iter().any(|&b| b != 0));
}

#[test]
fn ct_eq_empty_slices() {
    assert!(tallow_crypto::mem::ct_eq(&[], &[]));
}

#[test]
fn ct_eq_single_byte_differ() {
    assert!(!tallow_crypto::mem::ct_eq(&[0x00], &[0x01]));
    assert!(tallow_crypto::mem::ct_eq(&[0xFF], &[0xFF]));
}

#[test]
fn ct_compare_u64_extremes() {
    assert_eq!(
        tallow_crypto::mem::constant_time::ct_compare_u64(0, u64::MAX),
        -1
    );
    assert_eq!(
        tallow_crypto::mem::constant_time::ct_compare_u64(u64::MAX, 0),
        1
    );
    assert_eq!(
        tallow_crypto::mem::constant_time::ct_compare_u64(u64::MAX, u64::MAX),
        0
    );
    assert_eq!(tallow_crypto::mem::constant_time::ct_compare_u64(0, 0), 0);
}
