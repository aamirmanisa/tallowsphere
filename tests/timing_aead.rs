//! dudect-style timing check on the AEAD path (P7).
//!
//! Two input classes, interleaved, Welch's t-test on the timing difference. The
//! question is not "is this fast" but "does the wall time depend on the secret".
//!
//! `#[ignore]` by default and run with `-- --ignored --nocapture`. That is a
//! deliberate choice, not an omission: this test measures a *distribution*, and
//! on a shared VM the noise floor moves with whatever else is running. A gate
//! that fails on an unrelated build is worse than no gate — it trains people to
//! re-run until green. The recorded numbers live in the plan document; promoting
//! this to a blocking CI job needs a dedicated (idle, pinned) runner.

use std::time::Instant;

/// Deterministic test vector: 32-byte key, 12-byte nonce, empty-ish plaintext.
fn hex32(seed: u8) -> Vec<u8> {
    (0..32u8).map(|i| seed.wrapping_add(i)).collect()
}

fn decrypt(key: &[u8], nonce: &[u8], ct: &[u8]) -> bool {
    let mut out_len: usize = 0;
    // Raw slices, not C strings: the FFI takes pointers + a length and the key
    // legitimately contains NUL bytes.
    let ptr = unsafe {
        tallow::runtime::crypto_ffi::tallow_aes256_gcm_decrypt(
            key.as_ptr(),
            nonce.as_ptr(),
            ct.as_ptr(),
            ct.len(),
            &mut out_len,
        )
    };
    !ptr.is_null()
}

fn welch(a: &[f64], b: &[f64]) -> f64 {
    let mean = |v: &[f64]| v.iter().sum::<f64>() / v.len() as f64;
    let var = |v: &[f64]| {
        let m = mean(v);
        v.iter().map(|x| (x - m) * (x - m)).sum::<f64>() / (v.len() as f64 - 1.0)
    };
    let (ma, mb) = (mean(a), mean(b));
    let (va, vb) = (var(a), var(b));
    (ma - mb) / ((va / a.len() as f64 + vb / b.len() as f64).sqrt() + 1e-12)
}

fn measure(samples: usize) -> (f64, f64) {
    let nonce = [0u8; 12];
    let ct = vec![0u8; 64];
    let mut ta = Vec::with_capacity(samples);
    let mut tb = Vec::with_capacity(samples);

    // Warm up so the first calls do not dominate.
    for _ in 0..200 {
        decrypt(&hex32(0), &nonce, &ct);
        decrypt(&hex32(1), &nonce, &ct);
    }

    for i in 0..samples {
        // Interleave the classes: any drift hits both equally.
        let (ka, kb) = if i % 2 == 0 {
            (hex32(0), hex32(1))
        } else {
            (hex32(1), hex32(0))
        };
        let t0 = Instant::now();
        decrypt(&ka, &nonce, &ct);
        ta.push(t0.elapsed().as_nanos() as f64);

        let t1 = Instant::now();
        decrypt(&kb, &nonce, &ct);
        tb.push(t1.elapsed().as_nanos() as f64);
    }
    (welch(&ta, &tb), ta.iter().sum::<f64>() / ta.len() as f64)
}

#[test]
#[ignore = "timing measurement: needs an idle host; see the module note"]
fn aead_decrypt_timing_does_not_depend_on_the_key() {
    let samples = 20_000;
    let (t, mean_ns) = measure(samples);
    println!("AEAD decrypt: samples/class={samples} mean={mean_ns:.1}ns welch_t={t:.3}");
    // dudect's rule of thumb: |t| < 10 is indistinguishable from noise.
    assert!(
        t.abs() < 10.0,
        "timing depends on the key: welch t = {t:.3} (mean {mean_ns:.1} ns)"
    );
}
