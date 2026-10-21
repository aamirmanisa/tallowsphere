<div align="center">

# tallow-crypto

**Every cryptographic primitive Tallow uses, in one crate — post-quantum, classical, and the hybrid constructions that combine them.**

![suite](https://img.shields.io/badge/suite-TCS--1-1f6feb?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)
![unsafe](https://img.shields.io/badge/unsafe-forbidden-2ea44f?style=flat-square)
![tests](https://img.shields.io/badge/tests-193%20in%20source-informational?style=flat-square)

</div>

---

A protocol is only as trustworthy as the primitives under it, and most projects scatter those across a dozen crates with different error types, different key formats and different opinions about zeroization. This crate is the opposite: one `Result`, one key-handling discipline, one named suite.

## What it is

| Area | Contents |
|---|---|
| **Post-quantum KEM** | ML-KEM (Kyber): keygen, encapsulate, decapsulate |
| **Post-quantum signatures** | ML-DSA (Dilithium) and SLH-DSA (SPHINCS+) |
| **Hybrid** | X25519 + ML-KEM encapsulation; Ed25519 + ML-DSA signatures |
| **Symmetric** | AES-256-GCM, ChaCha20-Poly1305, XChaCha20-Poly1305, AEGIS — with a single `CipherSuite` selector |
| **Hashing** | BLAKE3 (plain, keyed, derive-key, incremental), SHA-3, Merkle trees |
| **PAKE** | CPace, with the TCS-1 deviation record and published vectors |
| **Keys** | Identity keys, prekeys, ephemeral keys, rotation, at-rest storage |
| **File crypto** | Streaming encrypt/decrypt, domain-separated per file |
| **Memory hygiene** | Zeroization on drop, constant-time comparison |

The suite is **named, not implied**: `SUITE_ID = "TCS-1"` and the one-byte wire code `SUITE_CODE_TCS1 = 0x01` that the handshake declares and binds into the transcript. A peer that cannot agree on the suite fails the handshake instead of falling back to something weaker.

```rust
use tallow_crypto::{SUITE_ID, SUITE_CODE_TCS1};

assert_eq!(SUITE_ID, "TCS-1");
assert_eq!(SUITE_CODE_TCS1, 0x01);
```

## What it is not

- **Not a validated module.** There is no CMVP certificate and no claim of one. Known-answer tests prove the implementation matches published vectors; that is not a validation.
- **Not a key-management service.** Keys are bytes; where they live, who may read them and how they rotate is the caller's problem, and `keys::storage` only offers the local file shape.
- **Not a general-purpose TLS stack.** It backs Tallow's own protocol; it does not implement X.509 chains or a web PKI.

## Quick start

### Symmetric

```rust
use tallow_crypto::symmetric::{aes_gcm, chacha20};

let key = [0x42u8; 32];
let nonce = [0x07u8; 12];

let ct = aes_gcm::encrypt(&key, &nonce, b"secret", b"file-id:42")?;
let pt = aes_gcm::decrypt(&key, &nonce, &ct, b"file-id:42")?;
assert_eq!(pt, b"secret");
```

The additional-authenticated-data argument is not optional by accident: binding ciphertext to its context is what stops a valid blob being replayed into a different file or session.

### Hashing

```rust
use tallow_crypto::hash::blake3;

let digest = blake3::hash(b"payload");                 // [u8; 32]
let keyed  = blake3::keyed_hash(&key, b"payload");     // MAC-like
let derived = blake3::derive_key("tallow/file/v1", &key_material);
```

### Hybrid KEM

```rust
use tallow_crypto::kem::hybrid::HybridKem;

let (pk, sk) = HybridKem::keygen()?;
let (ct, sender_secret) = HybridKem::encapsulate(&pk)?;
let receiver_secret = HybridKem::decapsulate(&sk, &ct)?;
assert_eq!(sender_secret.expose_secret(), receiver_secret.expose_secret());
```

Both halves must agree. A break in X25519 alone does not recover the shared secret, because ML-KEM's contribution is mixed in through the KDF.

## Configuration

The crate has no environment variables and no runtime configuration by design — a primitive that reads `std::env` is a primitive whose behaviour you cannot reproduce from the source.

Choices are made in the type system:

- `CipherSuite` selects the AEAD; unknown suites do not fall back.
- Nonces are caller-supplied; the AEAD APIs reject a wrong-length buffer at compile time where the size is fixed (`&[u8; 12]`).
- `keyed_hash` and `derive_key` use distinct BLAKE3 modes; using the wrong one changes the output, which is the point.

## Using it in your service

```toml
# Cargo.toml
[dependencies]
tallow-crypto = { path = "crates/tallow-crypto" }
```

The crate is not published to crates.io. Inside this workspace it is a path dependency; outside, vendor it or depend on the git repository at a pinned commit.

Because the crate forbids `unsafe` (`#![deny(unsafe_code)]`) and warns on missing docs, it is safe to link into a service that must satisfy a supply-chain review: `cargo deny check` and `cargo audit` cover it like any other dependency, and `tallow sbom` will include it in a CycloneDX document.

## Verification

```console
$ cargo test -p tallow-crypto
$ cargo test -p tallow-crypto pake -- --nocapture     # PAKE vectors and adversarial cases
$ cargo test -p tallow-crypto sig::hybrid -- --nocapture
```

There are 193 test functions in the crate source [measured 2026-10-21]. The PAKE tests run both the CPace draft vectors and the TCS-1 vectors, including the adversarial set — a PAKE that passes only the happy path is a PAKE with an unexamined failure mode.

## Limits

| Limit | Detail |
|---|---|
| No hardware-backed keys | Keys live in process memory; TPM/HSM integration is not in this crate |
| No key rotation schedule | `keys::rotation` provides the mechanism, not a policy engine |
| CPace deviations | TCS-1 documents its deviations from the CPace draft; a peer on the plain draft will not interoperate |
| No side-channel audit | Constant-time code is written and tested for obvious timing leaks; there is no formal verification |

## License

MIT. Vendored dependencies keep their own licenses — see `NOTICE`.
