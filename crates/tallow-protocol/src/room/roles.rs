//! Room role definitions

use serde::{Deserialize, Serialize};

/// Role within a room
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RoomRole {
    /// Room host (creator)
    Host,
    /// Regular member
    Member,
    /// Read-only observer
    ReadOnly,
}

impl RoomRole {
    /// Check if role can send files
    pub fn can_send(&self) -> bool {
        matches!(self, RoomRole::Host | RoomRole::Member)
    }

    /// Check if role can receive files
    pub fn can_receive(&self) -> bool {
        matches!(self, RoomRole::Host | RoomRole::Member)
    }

    /// Check if role can kick others
    pub fn can_kick(&self) -> bool {
        matches!(self, RoomRole::Host)
    }
}
