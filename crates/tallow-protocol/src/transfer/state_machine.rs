//! Transfer state machine

use crate::{ProtocolError, Result};

/// Transfer states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransferState {
    /// Idle, no transfer
    Idle,
    /// Queued, waiting for an active slot
    Queued,
    /// Connecting to peer
    Connecting,
    /// Negotiating transfer parameters
    Negotiating,
    /// Actively transferring
    Transferring,
    /// Transfer paused
    Paused,
    /// Transfer completed successfully
    Completed,
    /// Transfer failed
    Failed,
}

/// Transfer state machine
#[derive(Debug)]
pub struct TransferStateMachine {
    state: TransferState,
}

impl TransferStateMachine {
    /// Create a new state machine
    pub fn new() -> Self {
        Self {
            state: TransferState::Idle,
        }
    }

    /// Get current state
    pub fn state(&self) -> TransferState {
        self.state
    }

    /// Transition to a new state
    pub fn transition(&mut self, new_state: TransferState) -> Result<()> {
        // Validate transition
        let valid = match (self.state, new_state) {
            (TransferState::Idle, TransferState::Connecting) => true,
            (TransferState::Idle, TransferState::Queued) => true,
            (TransferState::Queued, TransferState::Connecting) => true,
            (TransferState::Connecting, TransferState::Negotiating) => true,
            (TransferState::Negotiating, TransferState::Transferring) => true,
            (TransferState::Transferring, TransferState::Paused) => true,
            (TransferState::Paused, TransferState::Transferring) => true,
            (TransferState::Transferring, TransferState::Completed) => true,
            (_, TransferState::Failed) => true, // Can fail from any state
            _ => false,
        };

        if !valid {
            return Err(ProtocolError::InvalidStateTransition {
                from: format!("{:?}", self.state),
                to: format!("{:?}", new_state),
            });
        }

        self.state = new_state;
        Ok(())
    }
}

impl Default for TransferStateMachine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_queued_transition_valid() {
        let mut sm = TransferStateMachine::new();
        assert_eq!(sm.state(), TransferState::Idle);
        sm.transition(TransferState::Queued).unwrap();
        assert_eq!(sm.state(), TransferState::Queued);
    }

    #[test]
    fn test_queued_to_connecting() {
        let mut sm = TransferStateMachine::new();
        sm.transition(TransferState::Queued).unwrap();
        sm.transition(TransferState::Connecting).unwrap();
        assert_eq!(sm.state(), TransferState::Connecting);
    }

    #[test]
    fn test_queued_to_transferring_invalid() {
        let mut sm = TransferStateMachine::new();
        sm.transition(TransferState::Queued).unwrap();
        let result = sm.transition(TransferState::Transferring);
        assert!(
            result.is_err(),
            "Queued -> Transferring must go through Connecting"
        );
    }

    #[test]
    fn test_queued_to_failed_valid() {
        let mut sm = TransferStateMachine::new();
        sm.transition(TransferState::Queued).unwrap();
        sm.transition(TransferState::Failed).unwrap();
        assert_eq!(sm.state(), TransferState::Failed);
    }

    #[test]
    fn test_idle_to_connecting_still_valid() {
        let mut sm = TransferStateMachine::new();
        sm.transition(TransferState::Connecting).unwrap();
        assert_eq!(sm.state(), TransferState::Connecting);
    }

    #[test]
    fn test_full_lifecycle_with_queue() {
        let mut sm = TransferStateMachine::new();
        sm.transition(TransferState::Queued).unwrap();
        sm.transition(TransferState::Connecting).unwrap();
        sm.transition(TransferState::Negotiating).unwrap();
        sm.transition(TransferState::Transferring).unwrap();
        sm.transition(TransferState::Paused).unwrap();
        sm.transition(TransferState::Transferring).unwrap();
        sm.transition(TransferState::Completed).unwrap();
        assert_eq!(sm.state(), TransferState::Completed);
    }
}
