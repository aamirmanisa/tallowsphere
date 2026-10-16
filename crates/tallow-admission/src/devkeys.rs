//! Dev/test key material — seeded from constant labels so test batteries are
//! reproducible, exactly like the reference core's `veil-test/...` seeds.
//!
//! **TEST ONLY.** Production keys come from the device registry / server key
//! files (see SPEC-v2 §5); these functions exist so the port's battery can
//! assert deterministic identities.

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use x25519_dalek::StaticSecret;

/// Server identity: an Ed25519 signing key (authenticates the server to
/// clients) and an X25519 static secret (mixes session keys against the
/// pinned server key).
pub struct ServerIdentity {
    pub ed: SigningKey,
    pub x: StaticSecret,
}

/// Device identity: the registry name plus the device Ed25519 signing key.
pub struct DeviceIdentity {
    pub id: String,
    pub ed: SigningKey,
}

/// 32-byte seed = sha256(label).
pub fn seed32(label: &str) -> [u8; 32] {
    Sha256::digest(label.as_bytes()).into()
}

/// Deterministic Ed25519 key from a label.
pub fn ed_from_label(label: &str) -> SigningKey {
    SigningKey::from_bytes(&seed32(label))
}

/// Deterministic X25519 static secret from a label.
pub fn x_from_label(label: &str) -> StaticSecret {
    StaticSecret::from(seed32(label))
}

/// Deterministic test server identity (seeds: `tallow-test/server/*`).
pub fn server_identity() -> ServerIdentity {
    ServerIdentity {
        ed: ed_from_label("tallow-test/server/ed25519"),
        x: x_from_label("tallow-test/server/x25519"),
    }
}

/// Deterministic test device identity (seed: `tallow-test/device/<name>`).
pub fn device_identity(name: &str) -> DeviceIdentity {
    DeviceIdentity {
        id: name.to_string(),
        ed: ed_from_label(&format!("tallow-test/device/{name}")),
    }
}
