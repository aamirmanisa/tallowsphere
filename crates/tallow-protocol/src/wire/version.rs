//! Protocol version negotiation
//!
//! Version `2` is the KEM handshake (CPace + hybrid KEM) and remains the
//! minimum supported version. Version `3` adds scoped transfer keys
//! (per-transfer subkeys + domain-separated chunk nonces); version `4` marks
//! canonical-kex implementations (CPace + hybrid KEM) and is ACKed via the
//! `CANONICAL_KEX_FLAG` bit in the handshake response; version `5` adds
//! transcript-signed handshakes (`HandshakeSigned` + `PQ_AUTH_FLAG`), where
//! both sides prove possession of their hybrid identity before any data.
//! Version `6` adds wire flow credits (`FLOW_CREDIT_FLAG`); version `7` binds
//! the declared version + a mode byte into the handshake transcript on both
//! sides, so a wire rewrite of `protocol_version` fails the key confirmations
//! instead of silently downgrading (security review 2026-09-23).
//! Versions are negotiated by
//! the handshake itself — the initiator declares its version and the receiver
//! confirms via flag bits in its response. The helpers in this module cover
//! the standalone request/response negotiation path used by older transports.

use super::Message;
use crate::{ProtocolError, Result};

/// Current protocol version
///
/// v6 = wire flow credits (A9); v7 = version+mode transcript binding
/// (security review 2026-09-23 — downgrade rewrites fail loudly); v8 = the
/// declared suite code joins that binding (checklist 5.2), so a peer running an
/// unknown suite is refused rather than defaulted onto ours.
pub const PROTOCOL_VERSION: u32 = 8;

/// Minimum supported protocol version
///
/// v1 predates the KEM handshake and has no implementation; offering or
/// selecting it is a dead end, so it is no longer advertised or accepted.
///
/// **Raised 2 → 4 (2026-10-07, V2-U10 ruling (a)).** The floor used to
/// disagree with the handshake gate: `kex::MIN_ACCEPTED_INIT_VERSION` refuses
/// anything below 4, so a v2/v3 peer negotiated successfully here and then died
/// mid-handshake — the worst failure mode available, since both sides had
/// already committed to a session. The two floors are now the same constant
/// value and a test asserts they agree (`floor_matches_handshake_gate`).
/// keeping 2 was the alternative, but that means actually implementing the v2
/// and v3 handshakes; nothing in the fleet speaks them.
///
/// This module is compiled unconditionally while `kex` is feature-gated, so the
/// constant lives **here** and `kex::MIN_ACCEPTED_INIT_VERSION` is derived from
/// it — one source of truth, and drift between the two floors is no longer
/// expressible.
pub const MIN_PROTOCOL_VERSION: u32 = 4;

/// Negotiate protocol version with peer
///
/// Selects the highest version both sides support, clamped to what this
/// build implements, or returns an error if no compatible version exists.
pub fn negotiate_version(local: u32, remote: u32) -> Result<u32> {
    // Never claim to speak a version this build does not implement.
    let local = local.min(PROTOCOL_VERSION);

    if local < MIN_PROTOCOL_VERSION || remote < MIN_PROTOCOL_VERSION {
        return Err(ProtocolError::VersionMismatch { local, remote });
    }

    Ok(local.min(remote))
}

/// Create a version request message for the current protocol
pub fn version_request() -> Message {
    Message::VersionRequest {
        supported_versions: vec![MIN_PROTOCOL_VERSION, PROTOCOL_VERSION],
    }
}

/// Process a version request and produce a response
///
/// Returns `Ok(VersionResponse)` with the selected version,
/// or `Ok(VersionReject)` if no compatible version exists.
pub fn process_version_request(their_versions: &[u32]) -> Result<Message> {
    // Find the highest version we both support
    let mut best = None;
    for &v in their_versions {
        if (MIN_PROTOCOL_VERSION..=PROTOCOL_VERSION).contains(&v) {
            best = Some(best.map_or(v, |b: u32| b.max(v)));
        }
    }

    match best {
        Some(version) => Ok(Message::VersionResponse {
            selected_version: version,
        }),
        None => Ok(Message::VersionReject {
            reason: format!(
                "no compatible version: we support {}-{}, peer offers {:?}",
                MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, their_versions
            ),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_negotiate_same_version() {
        assert_eq!(negotiate_version(4, 4).unwrap(), 4);
        assert_eq!(negotiate_version(7, 7).unwrap(), 7);
    }

    #[test]
    fn test_negotiate_lower_remote() {
        assert_eq!(negotiate_version(7, 5).unwrap(), 5);
    }

    #[test]
    fn test_negotiate_lower_local() {
        assert_eq!(negotiate_version(5, 7).unwrap(), 5);
    }

    #[test]
    fn test_negotiate_below_minimum_is_rejected() {
        // Everything below the floor (4) is refused on either side. The v2/v3
        // cases are V2-U10: this build used to negotiate them and then fail the
        // handshake gate.
        for v in [1, 2, 3] {
            assert!(
                negotiate_version(v, PROTOCOL_VERSION).is_err(),
                "local v{v} accepted"
            );
            assert!(
                negotiate_version(PROTOCOL_VERSION, v).is_err(),
                "remote v{v} accepted"
            );
        }
    }

    /// The two floors were allowed to drift (negotiator 2, handshake gate 4),
    /// which produced a peer that negotiated successfully and then failed the
    /// handshake. One of them is now derived from the other; this pins it so a
    /// future edit cannot reintroduce the split.
    #[cfg(any(feature = "full", feature = "wasm"))]
    #[test]
    fn floor_matches_handshake_gate() {
        assert_eq!(MIN_PROTOCOL_VERSION, crate::kex::MIN_ACCEPTED_INIT_VERSION);
        assert_eq!(MIN_PROTOCOL_VERSION, 4);
    }

    #[test]
    fn test_negotiate_future_remote_is_clamped() {
        // A peer claiming v99 must not cause us to claim more than we implement.
        assert_eq!(negotiate_version(5, 99).unwrap(), 5);
        assert_eq!(negotiate_version(99, 5).unwrap(), 5);
    }

    #[test]
    fn test_version_request_message() {
        let msg = version_request();
        match msg {
            Message::VersionRequest { supported_versions } => {
                assert!(supported_versions.contains(&PROTOCOL_VERSION));
                assert!(supported_versions.contains(&MIN_PROTOCOL_VERSION));
                // The dead v1 must no longer be advertised.
                assert!(!supported_versions.contains(&1));
                // And neither may v2/v3 — advertising them was exactly the
                // V2-U10 lie: we would negotiate and then refuse the handshake.
                assert!(!supported_versions.contains(&2));
                assert!(!supported_versions.contains(&3));
            }
            _ => panic!("expected VersionRequest"),
        }
    }

    #[test]
    fn test_process_compatible_request() {
        // [1, 2] is now below the floor: the pre-U10 build answered v2 here and
        // the handshake gate then refused it. An honest reject is the fix.
        let response = process_version_request(&[1, 2]).unwrap();
        match response {
            Message::VersionReject { .. } => {}
            _ => panic!("expected VersionReject for a below-floor peer"),
        }
    }

    #[test]
    fn test_process_v3_request() {
        // v3 is below the floor too (see above) — same reasoning.
        let response = process_version_request(&[2, 3]).unwrap();
        match response {
            Message::VersionReject { .. } => {}
            _ => panic!("expected VersionReject for a v3 peer"),
        }
    }

    #[test]
    fn test_process_floor_request_is_accepted() {
        // The floor itself must still be selectable, or raising it would have
        // broken exactly the peers it is meant to allow.
        let response = process_version_request(&[4, 5, 6, 7, 8]).unwrap();
        match response {
            Message::VersionResponse { selected_version } => {
                assert_eq!(selected_version, PROTOCOL_VERSION);
            }
            _ => panic!("expected VersionResponse"),
        }
    }

    #[test]
    fn test_process_incompatible_request() {
        let response = process_version_request(&[99, 100]).unwrap();
        match response {
            Message::VersionReject { .. } => {}
            _ => panic!("expected VersionReject"),
        }
    }
}
