//! B7 cliff-class probe: does `-C target-feature=+aes` actually select the
//! AES-NI/ARMv8 path in the AES-256-GCM backend, or does it fall back to a
//! bitsliced implementation?
//!
//! Backend note (2026-10-21): tallow-crypto moved from libcrux-aesgcm 0.0.8 back
//! to RustCrypto `aes-gcm` 0.10 (two unfixed RustSec advisories in the former).
//! This probe now measures the AES-GCM backend the crate actually links.
//!
//! Build it once per configuration and compare the RESULT line:
//!
//!     cd benchmarks/cliff-probe
//!     cargo run --release -q
//!     RUSTFLAGS="-C target-feature=+aes" cargo run --release -q
//!
//! Use a distinct CARGO_TARGET_DIR per configuration when comparing, so a stale
//! artifact from the other configuration cannot be reused.

use std::time::Instant;

use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};

const MIB: usize = 1 << 20;

fn main() {
    let key = [0x42u8; 32];
    let nonce_bytes = [0x24u8; 12];
    let pt = vec![0xABu8; 8 * MIB];
    let cipher = Aes256Gcm::new_from_slice(&key).expect("32-byte key");
    let nonce = Nonce::from_slice(&nonce_bytes);

    println!(
        "compile-time: cfg(target_feature=\"aes\")={} arch={}",
        cfg!(target_feature = "aes"),
        std::env::consts::ARCH
    );

    let seal = |buf: &[u8]| {
        cipher
            .encrypt(
                nonce,
                Payload {
                    msg: buf,
                    aad: b"",
                },
            )
            .expect("encrypt")
    };

    for _ in 0..2 {
        std::hint::black_box(seal(&pt));
    }

    let iters = 16;
    let t = Instant::now();
    for _ in 0..iters {
        std::hint::black_box(seal(&pt));
    }
    let elapsed = t.elapsed().as_secs_f64();
    let mb = (iters * pt.len()) as f64 / (1024.0 * 1024.0);
    println!(
        "RESULT {:.1} MB/s  ({:.0} MiB in {:.3}s)",
        mb / elapsed,
        mb,
        elapsed
    );
}
