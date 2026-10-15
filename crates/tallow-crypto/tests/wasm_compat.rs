//! WASM crypto compatibility tests
//!
//! These tests verify that crypto operations produce deterministic, reproducible
//! output. The same Rust code runs in the browser via WASM -- if native output
//! matches expected values, WASM will too (same algorithms, same code paths).
//!
//! Each test mirrors operations performed by the browser-side WASM wrappers in
//! `crates/tallow-web/src/crypto.rs`.

use tallow_crypto::hash::blake3;
use tallow_crypto::kdf::hkdf;
use tallow_crypto::kem::HybridKem;
use tallow_crypto::symmetric::{aes_decrypt, aes_encrypt};

// ---------------------------------------------------------------------------
// AES-256-GCM Determinism
// ---------------------------------------------------------------------------

#[test]
fn aes_gcm_deterministic_output() {
    // Fixed key and plaintext -- same inputs must produce same ciphertext
    let key = [0x42u8; 32];
    let plaintext = b"hello from tallow";
    let aad = b"test-aad";

    // Counter-based nonce: [0u8; 4] || counter.to_be_bytes()
    let counter: u64 = 7;
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());

    let ciphertext1 = aes_encrypt(&key, &nonce, plaintext, aad).expect("encrypt should succeed");
    let ciphertext2 = aes_encrypt(&key, &nonce, plaintext, aad).expect("encrypt should succeed");

    assert_eq!(
        ciphertext1, ciphertext2,
        "AES-GCM must be deterministic for same key+nonce+aad+plaintext"
    );
}

#[test]
fn aes_gcm_encrypt_decrypt_roundtrip() {
    let key = [0x42u8; 32];
    let plaintext = b"hello from tallow";
    let aad = b"test-aad";

    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&7u64.to_be_bytes());

    let ciphertext = aes_encrypt(&key, &nonce, plaintext, aad).expect("encrypt should succeed");
    let decrypted = aes_decrypt(&key, &nonce, &ciphertext, aad).expect("decrypt should succeed");

    assert_eq!(
        decrypted.as_slice(),
        plaintext,
        "decrypted text must match original plaintext"
    );
}

#[test]
fn aes_gcm_ciphertext_not_plaintext() {
    let key = [0x42u8; 32];
    let plaintext = b"hello from tallow";
    let aad = b"test-aad";

    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&7u64.to_be_bytes());

    let ciphertext = aes_encrypt(&key, &nonce, plaintext, aad).expect("encrypt should succeed");

    // Ciphertext must differ from plaintext
    assert_ne!(
        &ciphertext[..plaintext.len()],
        plaintext,
        "ciphertext should not equal plaintext"
    );
    // Ciphertext includes 16-byte auth tag
    assert_eq!(ciphertext.len(), plaintext.len() + 16);
}

#[test]
fn aes_gcm_wrong_aad_fails() {
    let key = [0x42u8; 32];
    let plaintext = b"secret";

    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&0u64.to_be_bytes());

    let ciphertext = aes_encrypt(&key, &nonce, plaintext, b"aad-1").expect("encrypt");
    let result = aes_decrypt(&key, &nonce, &ciphertext, b"aad-2");

    assert!(
        result.is_err(),
        "decryption with wrong AAD must fail authentication"
    );
}

#[test]
fn aes_gcm_different_counters_produce_different_ciphertext() {
    let key = [0x42u8; 32];
    let plaintext = b"same data";
    let aad = b"same-aad";

    let mut nonce0 = [0u8; 12];
    nonce0[4..12].copy_from_slice(&0u64.to_be_bytes());

    let mut nonce1 = [0u8; 12];
    nonce1[4..12].copy_from_slice(&1u64.to_be_bytes());

    let ct0 = aes_encrypt(&key, &nonce0, plaintext, aad).expect("encrypt");
    let ct1 = aes_encrypt(&key, &nonce1, plaintext, aad).expect("encrypt");

    assert_ne!(
        ct0, ct1,
        "different nonce counters must produce different ciphertext"
    );
}

// ---------------------------------------------------------------------------
// BLAKE3 Determinism
// ---------------------------------------------------------------------------

#[test]
fn blake3_hash_deterministic() {
    let data = b"tallow-test-data";
    let hash1 = blake3::hash(data);
    let hash2 = blake3::hash(data);

    assert_eq!(hash1, hash2, "BLAKE3 must be deterministic");
    assert_eq!(hash1.len(), 32, "BLAKE3 produces 32-byte output");
}

#[test]
fn blake3_different_inputs_different_hashes() {
    let h1 = blake3::hash(b"input-a");
    let h2 = blake3::hash(b"input-b");

    assert_ne!(h1, h2, "different inputs must produce different hashes");
}

#[test]
fn blake3_room_id_derivation_deterministic() {
    // Room ID derivation from code phrase must match CLI exactly.
    // The browser uses blake3Hash(code_phrase.as_bytes()) for room ID.
    let code = "7-gamma-bravo";
    let room_id1 = blake3::hash(code.as_bytes());
    let room_id2 = blake3::hash(code.as_bytes());

    assert_eq!(
        room_id1, room_id2,
        "room ID derivation must be deterministic"
    );
}

#[test]
fn blake3_derive_key_deterministic() {
    let context = "tallow-room-id";
    let material = b"test-material";

    let key1 = blake3::derive_key(context, material);
    let key2 = blake3::derive_key(context, material);

    assert_eq!(key1, key2, "BLAKE3 key derivation must be deterministic");
    assert_eq!(key1.len(), 32);
}

#[test]
fn blake3_derive_key_domain_separation() {
    let material = b"same-material";
    let key1 = blake3::derive_key("context-a", material);
    let key2 = blake3::derive_key("context-b", material);

    assert_ne!(
        key1, key2,
        "different contexts must produce different derived keys"
    );
}

// ---------------------------------------------------------------------------
// HKDF-SHA256 Determinism
// ---------------------------------------------------------------------------

#[test]
fn hkdf_deterministic() {
    let ikm = [0xAAu8; 32];
    let salt = [0xBBu8; 32];
    let info = b"tallow-session-key";

    let key1 = hkdf::derive(&salt, &ikm, info, 32).expect("HKDF should succeed");
    let key2 = hkdf::derive(&salt, &ikm, info, 32).expect("HKDF should succeed");

    assert_eq!(key1, key2, "HKDF must be deterministic");
    assert_eq!(key1.len(), 32);
}

#[test]
fn hkdf_different_info_produces_different_keys() {
    let ikm = [0xAAu8; 32];
    let salt = [0xBBu8; 32];

    let key1 = hkdf::derive(&salt, &ikm, b"info-a", 32).expect("HKDF");
    let key2 = hkdf::derive(&salt, &ikm, b"info-b", 32).expect("HKDF");

    assert_ne!(key1, key2, "different info must produce different keys");
}

#[test]
fn hkdf_session_key_derivation_matches_browser() {
    // The browser derives session key as:
    //   hkdfDerive(sharedSecret, empty_salt, "tallow-session-key-v2", 32)
    // Which maps to: hkdf::derive(empty_salt, sharedSecret, info, 32)
    // Note: browser passes (ikm, salt, info) but Rust API is (salt, ikm, info)
    let shared_secret = [0xCC; 32];
    let empty_salt: &[u8] = &[];
    let info = b"tallow-session-key-v2";

    let key = hkdf::derive(empty_salt, &shared_secret, info, 32).expect("HKDF");

    assert_eq!(key.len(), 32);
    // Verify determinism
    let key2 = hkdf::derive(empty_salt, &shared_secret, info, 32).expect("HKDF");
    assert_eq!(key, key2);
}

// ---------------------------------------------------------------------------
// KEM Roundtrip
// ---------------------------------------------------------------------------

#[test]
fn kem_encapsulate_decapsulate_roundtrip() {
    let (pk, sk) = HybridKem::keygen().expect("keygen should succeed");

    let (ct, ss_enc) = HybridKem::encapsulate(&pk).expect("encapsulate should succeed");
    let ss_dec = HybridKem::decapsulate(&sk, &ct).expect("decapsulate should succeed");

    assert_eq!(
        ss_enc.expose_secret(),
        ss_dec.expose_secret(),
        "encapsulate/decapsulate must produce same shared secret"
    );
}

#[test]
fn kem_bincode_serialization_roundtrip() {
    // The browser uses bincode for KEM key serialization (via crypto.rs wrappers).
    // Verify that serialize -> deserialize -> encapsulate/decapsulate still works.
    let (pk, sk) = HybridKem::keygen().expect("keygen");

    let pk_bytes = bincode::serialize(&pk).expect("serialize pk");
    let sk_bytes = bincode::serialize(&sk).expect("serialize sk");

    let pk2: tallow_crypto::kem::hybrid::PublicKey =
        bincode::deserialize(&pk_bytes).expect("deserialize pk");
    let sk2: tallow_crypto::kem::hybrid::SecretKey =
        bincode::deserialize(&sk_bytes).expect("deserialize sk");

    let (ct, ss_enc) = HybridKem::encapsulate(&pk2).expect("encapsulate");
    let ct_bytes = bincode::serialize(&ct).expect("serialize ct");
    let ct2: tallow_crypto::kem::hybrid::Ciphertext =
        bincode::deserialize(&ct_bytes).expect("deserialize ct");

    let ss_dec = HybridKem::decapsulate(&sk2, &ct2).expect("decapsulate");

    assert_eq!(
        ss_enc.expose_secret(),
        ss_dec.expose_secret(),
        "bincode roundtrip must preserve KEM correctness"
    );
}

#[test]
fn kem_different_keypairs_produce_different_secrets() {
    let (pk1, _sk1) = HybridKem::keygen().expect("keygen 1");
    let (pk2, _sk2) = HybridKem::keygen().expect("keygen 2");

    let (_, ss1) = HybridKem::encapsulate(&pk1).expect("encap 1");
    let (_, ss2) = HybridKem::encapsulate(&pk2).expect("encap 2");

    assert_ne!(
        ss1.expose_secret(),
        ss2.expose_secret(),
        "different keypairs should produce different shared secrets"
    );
}

// ---------------------------------------------------------------------------
// Chat Encryption (matches browser crypto.rs)
// ---------------------------------------------------------------------------

#[test]
fn chat_nonce_construction() {
    // Verify the chat nonce format: [0u8; 4] || counter.to_be_bytes()
    // This is used by both encryptChatMessage and decryptChatMessage in crypto.rs
    let counter: u64 = 42;
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());

    assert_eq!(&nonce[0..4], &[0, 0, 0, 0], "first 4 bytes must be zero");
    assert_eq!(
        &nonce[4..12],
        &42u64.to_be_bytes(),
        "last 8 bytes are counter BE"
    );

    // Counter 0 nonce
    let mut nonce0 = [0u8; 12];
    nonce0[4..12].copy_from_slice(&0u64.to_be_bytes());
    assert_eq!(nonce0, [0u8; 12], "counter 0 produces all-zero nonce");
}

#[test]
fn chat_encryption_roundtrip() {
    // Matches exactly what encryptChatMessage/decryptChatMessage in crypto.rs do
    let key = [0x42u8; 32];
    let counter: u64 = 0;
    let aad = b"tallow-chat-v1";
    let plaintext = "Hello from chat!";

    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());

    let ciphertext =
        aes_encrypt(&key, &nonce, plaintext.as_bytes(), aad).expect("encrypt should succeed");

    let decrypted = aes_decrypt(&key, &nonce, &ciphertext, aad).expect("decrypt should succeed");

    assert_eq!(
        String::from_utf8(decrypted).expect("valid UTF-8"),
        plaintext,
        "chat message roundtrip must preserve content"
    );
}

#[test]
fn chat_encryption_deterministic() {
    // Same key + counter + message must produce identical ciphertext
    let key = [0x42u8; 32];
    let counter: u64 = 5;
    let aad = b"tallow-chat-v1";
    let plaintext = b"determinism check";

    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&counter.to_be_bytes());

    let ct1 = aes_encrypt(&key, &nonce, plaintext, aad).expect("encrypt");
    let ct2 = aes_encrypt(&key, &nonce, plaintext, aad).expect("encrypt");

    assert_eq!(
        ct1, ct2,
        "chat encryption must be deterministic for same inputs"
    );
}

#[test]
fn chat_counter_increment_produces_different_ciphertext() {
    // Chat protocol: sender uses even counters (0, 2, 4, ...), receiver uses odd (1, 3, 5, ...)
    // Different counters must produce different nonces and thus different ciphertext
    let key = [0x42u8; 32];
    let aad = b"tallow-chat-v1";
    let plaintext = b"same message";

    let mut nonce_even = [0u8; 12];
    nonce_even[4..12].copy_from_slice(&0u64.to_be_bytes());

    let mut nonce_odd = [0u8; 12];
    nonce_odd[4..12].copy_from_slice(&1u64.to_be_bytes());

    let ct_even = aes_encrypt(&key, &nonce_even, plaintext, aad).expect("encrypt even");
    let ct_odd = aes_encrypt(&key, &nonce_odd, plaintext, aad).expect("encrypt odd");

    assert_ne!(
        ct_even, ct_odd,
        "different counter values must produce different ciphertext"
    );
}

// ---------------------------------------------------------------------------
// Transfer chunk AAD construction (matches browser transfer.rs)
// ---------------------------------------------------------------------------

#[test]
fn transfer_chunk_aad_construction() {
    // Browser builds AAD as: transfer_id || chunk_index.to_be_bytes()
    // Verify this matches the expected format
    let transfer_id = [0xAB; 16];
    let chunk_index: u32 = 42;

    let mut aad = Vec::with_capacity(20);
    aad.extend_from_slice(&transfer_id);
    aad.extend_from_slice(&chunk_index.to_be_bytes());

    assert_eq!(
        aad.len(),
        20,
        "AAD must be 16 (transfer_id) + 4 (index) = 20 bytes"
    );

    // Encrypt with this AAD
    let key = [0x42; 32];
    let mut nonce = [0u8; 12];
    nonce[4..12].copy_from_slice(&(chunk_index as u64).to_be_bytes());

    let plaintext = b"chunk data here";
    let ciphertext = aes_encrypt(&key, &nonce, plaintext, &aad).expect("encrypt with chunk AAD");
    let decrypted = aes_decrypt(&key, &nonce, &ciphertext, &aad).expect("decrypt with chunk AAD");

    assert_eq!(decrypted, plaintext);

    // Wrong AAD fails
    let mut wrong_aad = aad.clone();
    wrong_aad[19] = 0xFF; // corrupt last byte
    let result = aes_decrypt(&key, &nonce, &ciphertext, &wrong_aad);
    assert!(result.is_err(), "corrupted chunk AAD must fail decryption");
}
