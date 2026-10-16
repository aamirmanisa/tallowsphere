//! B7 cliff-class probe: does `-C target-feature=+aes` actually select
//! libcrux-aesgcm's AES fast path, or does the crate dispatch at runtime?
//!
//! Build it once per configuration and compare the RESULT line. Imports mirror
//! crates/tallow-crypto/src/symmetric/aes_gcm.rs exactly.
//!
//!     cd benchmarks/cliff-probe
//!     cargo run --release -q                                  # ~99 MB/s
//!     RUSTFLAGS="-C target-feature=+aes" cargo run --release -q   # ~909 MB/s
//!
//! See docs/CRYPTO-FASTPATH-AUDIT.md for the full table and the mechanism.
//! Use a distinct CARGO_TARGET_DIR per configuration: the build script that
//! enables libcrux's SIMD module does not declare
//! `cargo:rerun-if-env-changed`, so a shared target dir reuses stale output.

use std::time::Instant;

use libcrux_aesgcm::aes_gcm_256::{Key as LKey, Nonce as LNonce, Tag as LTag};
use libcrux_aesgcm::{AeadConsts as _, AesGcm256};

const MIB: usize = 1 << 20;

fn main() {
    let key: LKey = [0x42u8; 32].into();
    let nonce: LNonce = [0x24u8; 12].into();
    let pt = vec![0xABu8; 8 * MIB];
    let mut ct = vec![0u8; pt.len()];
    let mut tag: LTag = [0u8; AesGcm256::TAG_LEN].into();

    // What the crate believes about this machine, at runtime.
    println!(
        "platform: simd128={} simd256={} aes_ni={}",
        libcrux_platform::simd128_support(),
        libcrux_platform::simd256_support(),
        libcrux_platform::aes_ni_support()
    );
    // What the compiler baked in. This is the field that tracks the 9x.
    println!(
        "compile-time: cfg(target_feature=\"aes\")={} arch={}",
        cfg!(target_feature = "aes"),
        std::env::consts::ARCH
    );

    for _ in 0..2 {
        key.encrypt(&mut ct, &mut tag, &nonce, b"", &pt).unwrap();
    }

    let iters = 32;
    let t = Instant::now();
    for _ in 0..iters {
        key.encrypt(&mut ct, &mut tag, &nonce, b"", &pt).unwrap();
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
