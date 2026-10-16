//! Wire-compatibility proof for the AES-256-GCM backend swap (item 6.4).
//!
//! The crate now encrypts bulk AEAD with libcrux-aesgcm; before this change it used
//! RustCrypto's `aes-gcm` 0.10.3. That swap is only legitimate if the bytes are
//! *identical* for the same (key, nonce, AAD, plaintext) — otherwise it is a cipher
//! change that breaks existing peers, needs a wire-version bump, and invalidates
//! published copy. This test is that proof.
//!
//! Both directions are asserted, so neither implementation is treated as the oracle:
//! our ciphertext must equal the reference's, the reference must decrypt ours, and we
//! must decrypt the reference's. `aes-gcm` is a dev-dependency purely as this oracle.
//!
//! Kept deliberately alongside the unit tests in `src/symmetric/aes_gcm.rs`, which
//! additionally pin one fixed vector produced by the pre-swap backend.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use tallow_crypto::symmetric::{aes_decrypt, aes_encrypt};

/// Deterministic bytes from a seed. blake3 in XOF mode: no RNG state to carry, no
/// new dependency, and the same stream on every machine and every run.
fn pseudo_random(seed: &[u8], len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(len + 32);
    let mut counter = 0u64;
    while out.len() < len {
        let mut hasher = blake3::Hasher::new();
        hasher.update(seed);
        hasher.update(&counter.to_le_bytes());
        out.extend_from_slice(hasher.finalize().as_bytes());
        counter += 1;
    }
    out.truncate(len);
    out
}

fn derive(seed: &[u8], tag: &[u8], len: usize) -> Vec<u8> {
    let mut s = seed.to_vec();
    s.extend_from_slice(tag);
    pseudo_random(&s, len)
}

#[test]
fn libcrux_and_rustcrypto_agree_byte_for_byte() {
    const CASES: usize = 2000;
    let mut checked = 0usize;

    for case in 0..CASES {
        let seed = case.to_le_bytes();
        let key: [u8; 32] = derive(&seed, b"key", 32).try_into().unwrap();
        let nonce: [u8; 12] = derive(&seed, b"nonce", 12).try_into().unwrap();

        // Sizes 1..=5000 B, and AAD present in one third of the cases (matching the
        // measurement probe that first established this equivalence).
        let len = 1 + (case * 37) % 5000;
        let plaintext = derive(&seed, b"pt", len);
        let aad: Vec<u8> = if case % 3 == 0 {
            b"tallow-transfer-scope-v1".to_vec()
        } else {
            Vec::new()
        };

        let ours = aes_encrypt(&key, &nonce, &plaintext, &aad).expect("libcrux encrypt");
        let reference = Aes256Gcm::new((&key).into())
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &plaintext,
                    aad: &aad,
                },
            )
            .expect("rustcrypto encrypt");

        assert_eq!(
            ours,
            reference,
            "case {case}: ciphertext+tag differ (len {len}, aad present: {})",
            !aad.is_empty()
        );

        // Both directions — neither side is the oracle.
        assert_eq!(
            aes_decrypt(&key, &nonce, &reference, &aad).expect("libcrux decrypts reference"),
            plaintext,
            "case {case}: we failed to decrypt the reference ciphertext"
        );
        assert_eq!(
            Aes256Gcm::new((&key).into())
                .decrypt(
                    Nonce::from_slice(&nonce),
                    Payload {
                        msg: &ours,
                        aad: &aad
                    }
                )
                .expect("rustcrypto decrypts ours"),
            plaintext,
            "case {case}: the reference failed to decrypt our ciphertext"
        );

        checked += 1;
    }

    assert_eq!(checked, CASES, "every case must actually be exercised");
}

/// NIST CAVS 14.0 AES-256-GCM known-answer vectors, reproduced locally.
///
/// Ruling 0.4 (§2.6 of the TCS-1 spec) requires a crypto-relevant crate to be
/// *vector-proven*: "upstream test vectors reproduced locally". These are the real
/// thing, not a self-generated tape: `gcmEncryptExtIV256.rsp` (CAVS 14.0, generated
/// 2012-08-31), groups `[Keylen = 256] [IVlen = 96] [Taglen = 128]`, one case with no
/// AAD and one with a 128-bit AAD. The vectors were independently re-derived with
/// OpenSSL before being pinned here, so a mis-parse could not have been blessed.
///
/// Provenance of the file (mirror of the NIST CAVS set):
///   pyca/cryptography → vectors/cryptography_vectors/ciphers/AES/GCM/gcmEncryptExtIV256.rsp
///   sha256 4448b4998c3f58cd9f5542ddf7c573189a721ff3d3ac24cd5177bb4910a787f8
#[test]
fn nist_cavs_aes256_gcm_vectors() {
    // Count 0, no AAD.
    let key = hex::decode("31bdadd96698c204aa9ce1448ea94ae1fb4a9a0b3c9d773b51bb1822666b8f22").unwrap();
    let nonce = hex::decode("0d18e06c7c725ac9e362e1ce").unwrap();
    let pt = hex::decode("2db5168e932556f8089a0622981d017d").unwrap();
    let expected = hex::decode("fa4362189661d163fcd6a56d8bf0405ad636ac1bbedd5cc3ee727dc2ab4a9489").unwrap();

    let key: [u8; 32] = key.try_into().unwrap();
    let nonce: [u8; 12] = nonce.try_into().unwrap();
    let got = aes_encrypt(&key, &nonce, &pt, &[]).unwrap();
    assert_eq!(got, expected, "CAVS no-AAD vector mismatch");
    assert_eq!(aes_decrypt(&key, &nonce, &got, &[]).unwrap(), pt);

    // Count 0 of the 128-bit-AAD group.
    let key = hex::decode("92e11dcdaa866f5ce790fd24501f92509aacf4cb8b1339d50c9c1240935dd08b").unwrap();
    let nonce = hex::decode("ac93a1a6145299bde902f21a").unwrap();
    let aad = hex::decode("1e0889016f67601c8ebea4943bc23ad6").unwrap();
    let pt = hex::decode("2d71bcfa914e4ac045b2aa60955fad24").unwrap();
    let expected = hex::decode("8995ae2e6df3dbf96fac7b7137bae67feca5aa77d51d4a0a14d9c51e1da474ab").unwrap();

    let key: [u8; 32] = key.try_into().unwrap();
    let nonce: [u8; 12] = nonce.try_into().unwrap();
    let got = aes_encrypt(&key, &nonce, &pt, &aad).unwrap();
    assert_eq!(got, expected, "CAVS 128-bit-AAD vector mismatch");
    assert_eq!(aes_decrypt(&key, &nonce, &got, &aad).unwrap(), pt);

    // The AAD must be load-bearing: the same vector with the AAD dropped must not
    // authenticate against this tag.
    assert!(aes_decrypt(&key, &nonce, &got, &[]).is_err());
}

/// A tampered tag must be rejected, and no plaintext may escape. Guards the swap
/// against an implementation that returns unauthenticated bytes on failure.
#[test]
fn tampered_ciphertext_is_rejected() {
    let key = [0x42u8; 32];
    let nonce = [0x24u8; 12];
    let aad = b"tallow-transfer-scope-v1";
    let plaintext = b"a chunk that must not survive a flipped bit";

    let mut ct = aes_encrypt(&key, &nonce, plaintext, aad).unwrap();
    let last = ct.len() - 1;
    ct[last] ^= 0x01;

    assert!(
        aes_decrypt(&key, &nonce, &ct, aad).is_err(),
        "a flipped tag bit was accepted"
    );

    // Truncated input (shorter than the 16-byte tag) must fail closed, not panic.
    assert!(aes_decrypt(&key, &nonce, &ct[..8], aad).is_err());
}
