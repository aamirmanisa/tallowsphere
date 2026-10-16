//! Signaling protocol messages

use serde::{Deserialize, Serialize};

/// Signaling messages for peer coordination
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum SignalingMessage {
    /// Join a room
    Join {
        /// Room code
        room_code: String,
        /// Peer identifier
        peer_id: String,
    },
    /// Leave a room
    Leave {
        /// Room code
        room_code: String,
    },
    /// WebRTC offer
    Offer {
        /// Target peer
        to: String,
        /// SDP offer
        sdp: String,
    },
    /// WebRTC answer
    Answer {
        /// Target peer
        to: String,
        /// SDP answer
        sdp: String,
    },
    /// ICE candidate
    IceCandidate {
        /// Target peer
        to: String,
        /// Candidate SDP
        candidate: String,
    },
}
