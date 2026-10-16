//! Wire protocol encoding/decoding
//!
//! Messages are serialized with postcard and framed with 4-byte BE length prefixes.

#[cfg(feature = "full")]
pub mod codec;
pub mod messages;
pub mod ordinals;
// `version` compiles unconditionally: it is pure version arithmetic over
// `Message` (no tallow-net), and `kex` — which itself compiles WITHOUT `full`
// in the wasm build, where tallow-web depends on this crate as
// { default-features = false, features = ["wasm"] } — derives its fail-closed
// gate (MIN_ACCEPTED_INIT_VERSION) from MIN_PROTOCOL_VERSION. Gating this module
// broke that build (E0425, then E0432): one wire-version floor has to exist in
// every configuration, so `wire` owns the number, exactly as its docs claim.
pub mod version;

#[cfg(feature = "full")]
pub use codec::TallowCodec;
pub use messages::{Message, PeerPresence, MODE_FULL, MODE_SIMPLE};
pub use version::{
    negotiate_version, process_version_request, version_request, MIN_PROTOCOL_VERSION,
    PROTOCOL_VERSION,
};
