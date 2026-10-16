//! Room management
//!
//! Manages room participants and their roles for a transfer session.

use super::RoomRole;
use crate::{ProtocolError, Result};

/// Maximum participants per room (sender + receiver)
const MAX_PARTICIPANTS: usize = 2;

/// Room participant
#[derive(Debug, Clone)]
pub struct Participant {
    /// Participant ID
    pub id: String,
    /// Display name
    pub name: String,
    /// Role in room
    pub role: RoomRole,
}

/// Room manager
#[derive(Debug)]
pub struct RoomManager {
    /// Room code
    pub code: String,
    /// Participants
    participants: Vec<Participant>,
}

impl RoomManager {
    /// Create a new room
    pub fn new(code: String) -> Self {
        Self {
            code,
            participants: Vec::new(),
        }
    }

    /// Join a room.
    ///
    /// Adds the participant to the room if there is space and they are
    /// not already present. The first participant becomes the host.
    pub async fn join(&mut self, mut participant: Participant) -> Result<()> {
        // Check if already in room
        if self.participants.iter().any(|p| p.id == participant.id) {
            return Err(ProtocolError::InvalidMessage(format!(
                "Participant {} already in room",
                participant.id
            )));
        }

        // Check room capacity
        if self.participants.len() >= MAX_PARTICIPANTS {
            return Err(ProtocolError::InvalidMessage("Room is full".to_string()));
        }

        // First participant becomes host
        if self.participants.is_empty() {
            participant.role = RoomRole::Host;
        }

        tracing::info!(
            "Participant {} joined room {} as {:?}",
            participant.id,
            self.code,
            participant.role
        );

        self.participants.push(participant);
        Ok(())
    }

    /// Leave a room.
    ///
    /// Removes the participant from the room. If the host leaves and
    /// there are remaining participants, the next participant is promoted.
    pub async fn leave(&mut self, participant_id: &str) -> Result<()> {
        let pos = self
            .participants
            .iter()
            .position(|p| p.id == participant_id)
            .ok_or_else(|| {
                ProtocolError::InvalidMessage(format!("Participant {} not in room", participant_id))
            })?;

        let was_host = self.participants[pos].role == RoomRole::Host;
        self.participants.remove(pos);

        // Promote next participant if host left
        if was_host {
            if let Some(next) = self.participants.first_mut() {
                next.role = RoomRole::Host;
                tracing::info!("Promoted {} to host", next.id);
            }
        }

        tracing::info!("Participant {} left room {}", participant_id, self.code);
        Ok(())
    }

    /// Get participants
    pub fn participants(&self) -> &[Participant] {
        &self.participants
    }

    /// Check if room is empty
    pub fn is_empty(&self) -> bool {
        self.participants.is_empty()
    }

    /// Check if room is full
    pub fn is_full(&self) -> bool {
        self.participants.len() >= MAX_PARTICIPANTS
    }

    /// Check if room is paired (both sender and receiver present)
    pub fn is_paired(&self) -> bool {
        self.participants.len() == MAX_PARTICIPANTS
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_participant(id: &str) -> Participant {
        Participant {
            id: id.to_string(),
            name: id.to_string(),
            role: RoomRole::Member,
        }
    }

    #[tokio::test]
    async fn test_join_first_becomes_host() {
        let mut mgr = RoomManager::new("test-room".to_string());
        mgr.join(make_participant("alice")).await.unwrap();
        assert_eq!(mgr.participants()[0].role, RoomRole::Host);
    }

    #[tokio::test]
    async fn test_join_second_stays_member() {
        let mut mgr = RoomManager::new("test-room".to_string());
        mgr.join(make_participant("alice")).await.unwrap();
        mgr.join(make_participant("bob")).await.unwrap();
        assert_eq!(mgr.participants()[1].role, RoomRole::Member);
    }

    #[tokio::test]
    async fn test_join_full_room() {
        let mut mgr = RoomManager::new("test-room".to_string());
        mgr.join(make_participant("alice")).await.unwrap();
        mgr.join(make_participant("bob")).await.unwrap();
        assert!(mgr.join(make_participant("charlie")).await.is_err());
    }

    #[tokio::test]
    async fn test_join_duplicate() {
        let mut mgr = RoomManager::new("test-room".to_string());
        mgr.join(make_participant("alice")).await.unwrap();
        assert!(mgr.join(make_participant("alice")).await.is_err());
    }

    #[tokio::test]
    async fn test_leave() {
        let mut mgr = RoomManager::new("test-room".to_string());
        mgr.join(make_participant("alice")).await.unwrap();
        mgr.join(make_participant("bob")).await.unwrap();
        mgr.leave("alice").await.unwrap();
        assert_eq!(mgr.participants().len(), 1);
        // Bob should be promoted to host
        assert_eq!(mgr.participants()[0].role, RoomRole::Host);
    }

    #[tokio::test]
    async fn test_leave_nonexistent() {
        let mut mgr = RoomManager::new("test-room".to_string());
        assert!(mgr.leave("nobody").await.is_err());
    }

    #[tokio::test]
    async fn test_is_paired() {
        let mut mgr = RoomManager::new("test-room".to_string());
        assert!(!mgr.is_paired());
        mgr.join(make_participant("alice")).await.unwrap();
        assert!(!mgr.is_paired());
        mgr.join(make_participant("bob")).await.unwrap();
        assert!(mgr.is_paired());
    }
}
