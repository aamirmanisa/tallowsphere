//! Ratcheting protocols for forward secrecy

pub mod double;
pub mod sparse_pq;

/// Default interval, in ratchet steps, between ML-KEM rekeys.
///
/// **Single source of truth**, and it lives here because this is the ratchet the value
/// parameterises, and because `tallow-crypto` is the only crate both consumers reach
/// **ungated**: `tallow_protocol::chat` is behind the `full` feature and `tallow-web`
/// depends on it with `default-features = false, features = ["wasm"]`, so a constant
/// defined in `tallow-protocol` is reachable by the native path only. That asymmetry is
/// how the divergence happened in the first place — `tallow-web` carried its own copy
/// set to `100` (ten times less often than the native path), with nothing in either
/// file revealing it.
///
/// The interval counts ratchet steps (i.e. messages), not time, so ten is the
/// conservative value and the cost — one ML-KEM encapsulation per ten steps — is
/// negligible against the post-quantum forward-secrecy window it closes.
///
/// NOTE (Step 4.3, other half — SETTLED 2026-10-14): the same numeric `0` reaches two different
/// objects. `tallow-web` maps a caller-supplied `0` to this constant *before* construction
/// (`crates/tallow-web/src/ratchet.rs:147-150`, located by content — this citation has drifted
/// once already), so the `SparsePqRatchet::new` assert is unreachable from the shipped browser
/// path: that lane rekeys every 10 steps, measured at 1621/3191 B frames. Rekeying is disabled
/// only by choice, via `SparsePqRatchet::new_disabled()`, whose sentinel is `u64::MAX`.
pub const DEFAULT_PQ_REKEY_INTERVAL: u64 = 10;
pub mod triple;

pub use double::DoubleRatchet;
pub use sparse_pq::SparsePqRatchet;
pub use triple::TripleRatchet;
