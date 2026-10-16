//! Request cadence helpers (P1 C3) — jittered sleeps for browser paths.
//!
//! The reader fix's rule: **never sleep a constant** on a request cadence — a
//! fixed interval is a timing fingerprint (a scheduler can bucket sessions by
//! it). [`sleep`] spreads each wait by ±`frac` around the base.
//!
//! Classification of sleeps across `src/browser/` (audit, P1 C3 — see
//! `docs/operations/cadence.md`):
//! - cadence waits → this helper (`wordfence_bypass` challenge waits);
//! - randomised dwells already exist in `warmup.rs` / `behavior.rs`
//!   (`jit.dwell`, `idle_jitter`, `micro_jitter`) — keep using those;
//! - backoff sleeps use `autonomous::backoff_duration` (exponential ±25%);
//! - structural waits (IPv6 race head start, TLS fragment pacing, poll loops,
//!   test plumbing) stay constant by design.

use std::time::Duration;

/// ±`frac` jitter around `base_ms` (frac 0.0 = no jitter; floored at 1 ms).
pub fn jitter(base_ms: u64, frac: f64) -> Duration {
    use rand::Rng as _;
    let frac = frac.clamp(0.0, 1.0);
    let window = (base_ms as f64 * frac) as i64;
    let mut rng = rand::rng();
    let delta = if window > 0 {
        rng.random_range(-window..=window)
    } else {
        0
    };
    let ms = (base_ms as i64 + delta).clamp(1, i64::MAX) as u64;
    Duration::from_millis(ms)
}

/// Sleep one jittered cadence wait (see [`jitter`]).
pub async fn sleep(base_ms: u64, frac: f64) {
    tokio::time::sleep(jitter(base_ms, frac)).await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn jitter_stays_within_the_window_and_varies() {
        let base = 1000u64;
        let mut seen = HashSet::new();
        for _ in 0..64 {
            let d = jitter(base, 0.25).as_millis() as u64;
            assert!((750..=1250).contains(&d), "outside ±25%: {d}");
            seen.insert(d);
        }
        assert!(seen.len() > 8, "jitter must vary (saw {} values)", seen.len());
        // frac 0 keeps the base exactly.
        assert_eq!(jitter(base, 0.0), Duration::from_millis(base));
        // Floor clamp: a tiny base can never produce a zero wait. Asserted as the bound it
        // actually is — jitter is random by design, and 1 + delta is legitimately 1 or 2 ms,
        // so the previous equality was a coin-flip test.
        for _ in 0..64 {
            let d = jitter(1, 1.0);
            assert!(d >= Duration::from_millis(1), "clamp let a zero wait through: {d:?}");
            assert!(d <= Duration::from_millis(2), "window exceeded for base 1: {d:?}");
        }
    }
}
