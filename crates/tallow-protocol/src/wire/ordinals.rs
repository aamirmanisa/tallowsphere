//! Wire-message ordinals (postcard discriminant bytes) — single source of
//! truth for the relay-critical routing messages (P1 #13).
//!
//! These lock the first byte of the postcard encoding for messages that
//! relays and clients route on. NEVER renumber; append new variants at the
//! end of `Message` and add constants here. Values are verified against the
//! actual encoding by `wire::messages::tests::ordinal_registry_matches_wire`.

pub const HANDSHAKE_FAILED: u8 = 24;
pub const PEER_ARRIVED: u8 = 6;
pub const PEER_DEPARTED: u8 = 7;
pub const ROOM_LEAVE: u8 = 5;
pub const ROOM_JOINED: u8 = 4;
pub const TARGETED: u8 = 33;
pub const CHUNK: u8 = 11;
pub const MODE_ANNOUNCE: u8 = 71;
pub const MODE_ACCEPT: u8 = 72;
pub const SIMPLE_CHUNK: u8 = 73;
/// Batched ack + credit frame (`Message::Credit`, appended after `SimpleChunk`;
/// wire v6 flow control, A9). Client-to-client only — relays forward it
/// opaquely, so it is registered here for drift protection.
pub const FLOW_CREDIT: u8 = 74;
/// Authenticated Simple-mode announce (`Message::ModeAnnounceAuthed`, appended
/// after `Credit`; security review 2026-09-23, R2). Client-to-client only.
pub const MODE_ANNOUNCE_AUTHED: u8 = 75;
/// Authenticated Simple-mode accept (`Message::ModeAcceptAuthed`).
pub const MODE_ACCEPT_AUTHED: u8 = 76;
