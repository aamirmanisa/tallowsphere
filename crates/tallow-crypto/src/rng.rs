//! OS randomness for the rand_core 0.10 generation.
//!
//! The dalek 3.0 / curve25519-dalek 5 APIs draw from `rand_core` 0.10, whose `CryptoRng` is built
//! on the fallible `TryRng` trait. The crate's older consumers (argon2's salt generation via
//! password-hash, `rand` 0.8) are still on the 0.6 generation, so the two coexist during the
//! Phase-2 dependency wave — see items 2.2 and 2.3 in the crypto-upgrade tracker. Collapsing them
//! is not possible until argon2 moves generations, which is why this is a helper rather than a
//! blanket replacement of `rand_core::OsRng`.
//!
//! `UnwrapErr` is the documented bridge (curve25519-dalek 5's own `Scalar::random` doc example uses
//! exactly `UnwrapErr(SysRng)`) and on wasm32-unknown-unknown `SysRng` resolves to the browser's
//! CSPRNG through getrandom's `wasm_js` backend.

/// The OS CSPRNG, for APIs that require the rand_core 0.10 generation.
// The dependency is declared as `getrandom04` because this crate's 0.2 pin owns the plain
// `getrandom` name; the Rust path follows the manifest key.
pub(crate) fn csprng() -> impl getrandom04::rand_core::CryptoRng {
    getrandom04::rand_core::UnwrapErr(getrandom04::SysRng)
}
