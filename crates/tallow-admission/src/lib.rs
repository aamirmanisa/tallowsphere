//! # tallow-admission — mesh-door admission core
//!
//! The riskiest mechanism of the Tallow mesh door, as a transport-agnostic
//! core: an authenticated device-admission handshake (X25519 ephemeral ECDH
//! mixed against the pinned server static key; Ed25519 device identity;
//! transcript-bound; timestamped; HKDF-derived directional AEAD keys) with
//! **probe-indistinguishability** — every unauthenticated outcome (garbage,
//! HTTP probes, silent lingerers, unknown/revoked devices, tampered or stale
//! handshakes, replays) receives byte-identical cover bytes, exactly like an
//! ordinary web server answering a non-existent path.
//!
//! This is the first production port of the `veil_core.js` reference core
//! (artifacts/tallow-veil-mesh-2026-09-27/tools/veil_core.js). At the port
//! boundary the legacy wire labels were renamed mechanically:
//!
//! | reference (veil v0) | this port (Tallow) |
//! |---|---|
//! | `V1S` / `V1A` / `V1C` magics | `T1S` / `T1A` / `T1C` |
//! | `veil-v0` transcript label | `tallow-v0` |
//! | `veil-v0/c2s`, `veil-v0/s2c` HKDF labels | `tallow-v0/c2s`, `tallow-v0/s2c` |
//! | DER SPKI (44 B) public keys on the wire | raw 32 B X25519 public keys |
//! | `veil-test/...` seeds | `tallow-test/...` seeds (see [`devkeys`]) |
//!
//! The cover response is byte-identical to the reference (260 bytes,
//! sha256 `f23589f6…158bfe` — see [`cover::COVER_SHA256_HEX`]); it mimics an
//! ordinary 404 and is asserted in the battery.
//!
//! ## Architecture
//!
//! The protocol lives in pure state machines ([`server::ServerSession`],
//! [`client::ClientSession`]) that consume bytes and emit [`Action`]s — no
//! I/O. A thin blocking loopback layer lives in [`io`] (used by the battery's
//! TCP test and by the loopback dress rehearsal; the production daemon will
//! sit behind Caddy and can wrap the same core with async I/O).
//!
//! ## Status
//!
//! v0 port — battery-equivalent test suite green is the acceptance for the
//! port itself; deployed-instance acceptance comes at window W2. v1 hardening
//! landed 2026-10-15 (rx-counter monotonicity enforced in `AeadChan::open`;
//! total pre-auth deadline + pre-auth connection cap in `io.rs`); the remaining
//! TODO list (keepalive/idle policy, rate limiting, registry integration) is in
//! `README.md`.

#![forbid(unsafe_code)]

pub mod aead;
pub mod client;
pub mod cover;
pub mod devkeys;
pub mod framing;
pub mod handshake;
pub mod io;
pub mod policy;
pub mod ratelimit;
pub mod server;

pub use aead::AeadChan;
pub use client::{ClientConfig, ClientError, ClientSession};
pub use cover::{cover, COVER_LEN, COVER_SHA256_HEX};
pub use devkeys::{device_identity, server_identity, DeviceIdentity, ServerIdentity};
pub use framing::{frame, FrameDecoder};
pub use handshake::{build_msg1, build_msg2, build_msg3, derive_session, key_fp, sha256_cat};
pub use policy::action_allowed;
pub use server::{
    Action, AuditEvent, AuditSink, DeviceEntry, DeviceRegistry, DeviceStatus, ServerCore,
    ServerSession, StaticRegistry,
};

/// Protocol transcript label (renamed from `veil-v0` at first port).
pub const PROTO_LABEL: &[u8] = b"tallow-v0";

/// Milliseconds since the Unix epoch.
pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock before epoch")
        .as_millis() as u64
}

/// Wire magics (renamed from `V1S`/`V1A`/`V1C`).
pub const MAGIC1: &[u8; 3] = b"T1S";
pub const MAGIC2: &[u8; 3] = b"T1A";
pub const MAGIC3: &[u8; 3] = b"T1C";

/// Linger deadline before a cover reply on the server (milliseconds).
pub const DEADLINE_MS: u64 = 2_000;
/// Client-side frame deadline (milliseconds).
pub const CLIENT_DEADLINE_MS: u64 = 15_000;
/// Handshake timestamp freshness window (milliseconds).
pub const TS_WINDOW_MS: u64 = 120_000;

/// Minimum random padding per handshake message.
pub const PAD_MIN: usize = 16;
/// Padding jitter added on top of [`PAD_MIN`] (uniform `0..PAD_JITTER`).
pub const PAD_JITTER: usize = 48;
