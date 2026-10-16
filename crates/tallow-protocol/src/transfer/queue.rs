//! Transfer queue with pause, resume, and cancel support
//!
//! Manages concurrent file transfers with configurable concurrency limits.
//! Transfers can be enqueued, paused, resumed, and cancelled. The queue
//! automatically promotes pending transfers when active slots become available.

use crate::transfer::state_machine::TransferState;
use crate::{ProtocolError, Result};
use std::collections::VecDeque;
use std::path::PathBuf;
use tokio::sync::{mpsc, oneshot};

/// Opaque transfer identifier (16 random bytes)
pub type TransferId = [u8; 16];

/// Command sent to the transfer queue
#[derive(Debug)]
pub enum QueueCommand {
    /// Add a new transfer to the queue
    Enqueue(TransferRequest),
    /// Pause an active transfer
    Pause(TransferId),
    /// Resume a paused transfer
    Resume(TransferId),
    /// Cancel an active or pending transfer
    Cancel(TransferId),
    /// Query the status of all transfers
    ListStatus(oneshot::Sender<Vec<TransferStatus>>),
    /// Shut down the queue, clearing all entries
    Shutdown,
}

/// A request to transfer files
#[derive(Debug, Clone)]
pub struct TransferRequest {
    /// Unique transfer identifier
    pub id: TransferId,
    /// Files to transfer
    pub files: Vec<PathBuf>,
    /// Relay address
    pub relay: String,
    /// Code phrase for the transfer room
    ///
    /// Zeroized on drop via `Zeroizing<String>` to prevent code phrase
    /// leakage in memory after the transfer completes.
    pub code_phrase: zeroize::Zeroizing<String>,
    /// Bandwidth throttle in bytes per second (0 = unlimited)
    pub throttle_bps: u64,
}

/// Status snapshot of a queued transfer
#[derive(Debug, Clone)]
pub struct TransferStatus {
    /// Transfer identifier
    pub id: TransferId,
    /// Current state
    pub state: TransferState,
    /// Bytes transferred so far
    pub bytes_transferred: u64,
    /// Total bytes to transfer
    pub total_bytes: u64,
    /// Files in this transfer
    pub files: Vec<PathBuf>,
}

/// A queued transfer entry (internal bookkeeping)
struct QueueEntry {
    /// Transfer identifier
    id: TransferId,
    /// Original transfer request
    request: TransferRequest,
    /// Current state
    state: TransferState,
    /// Bytes transferred so far
    bytes_transferred: u64,
    /// Total bytes to transfer
    total_bytes: u64,
}

impl QueueEntry {
    /// Create a new entry from a request with the given initial state
    fn new(request: TransferRequest, state: TransferState) -> Self {
        Self {
            id: request.id,
            request,
            state,
            bytes_transferred: 0,
            total_bytes: 0,
        }
    }

    /// Snapshot current status
    fn status(&self) -> TransferStatus {
        TransferStatus {
            id: self.id,
            state: self.state,
            bytes_transferred: self.bytes_transferred,
            total_bytes: self.total_bytes,
            files: self.request.files.clone(),
        }
    }
}

/// Transfer queue manager
///
/// Processes commands from a [`QueueHandle`] and manages the lifecycle of
/// queued, active, and completed transfers.
pub struct TransferQueue {
    /// Transfers waiting for an active slot
    pending: VecDeque<QueueEntry>,
    /// Currently active transfers
    active: Vec<QueueEntry>,
    /// Completed or cancelled transfers
    completed: Vec<QueueEntry>,
    /// Command receiver channel
    cmd_rx: mpsc::Receiver<QueueCommand>,
    /// Maximum number of concurrent active transfers
    max_concurrent: usize,
}

/// Handle for sending commands to the transfer queue
///
/// Cloneable so multiple producers can enqueue work or query status.
#[derive(Clone)]
pub struct QueueHandle {
    cmd_tx: mpsc::Sender<QueueCommand>,
}

impl QueueHandle {
    /// Create a new transfer queue and its associated handle.
    ///
    /// `max_concurrent` controls how many transfers can be active simultaneously.
    /// Returns the queue (to be driven via [`TransferQueue::run`]) and a handle
    /// for sending commands.
    pub fn new(max_concurrent: usize) -> (TransferQueue, Self) {
        let (cmd_tx, cmd_rx) = mpsc::channel(256);
        let queue = TransferQueue {
            pending: VecDeque::new(),
            active: Vec::new(),
            completed: Vec::new(),
            cmd_rx,
            max_concurrent: max_concurrent.max(1),
        };
        let handle = Self { cmd_tx };
        (queue, handle)
    }

    /// Enqueue a new transfer request
    pub async fn enqueue(&self, request: TransferRequest) -> Result<()> {
        self.cmd_tx
            .send(QueueCommand::Enqueue(request))
            .await
            .map_err(|_| ProtocolError::TransferFailed("queue shut down".to_string()))
    }

    /// Pause an active transfer
    pub async fn pause(&self, id: TransferId) -> Result<()> {
        self.cmd_tx
            .send(QueueCommand::Pause(id))
            .await
            .map_err(|_| ProtocolError::TransferFailed("queue shut down".to_string()))
    }

    /// Resume a paused transfer
    pub async fn resume(&self, id: TransferId) -> Result<()> {
        self.cmd_tx
            .send(QueueCommand::Resume(id))
            .await
            .map_err(|_| ProtocolError::TransferFailed("queue shut down".to_string()))
    }

    /// Cancel a pending or active transfer
    pub async fn cancel(&self, id: TransferId) -> Result<()> {
        self.cmd_tx
            .send(QueueCommand::Cancel(id))
            .await
            .map_err(|_| ProtocolError::TransferFailed("queue shut down".to_string()))
    }

    /// List the status of all transfers (pending, active, completed)
    pub async fn list_status(&self) -> Result<Vec<TransferStatus>> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx
            .send(QueueCommand::ListStatus(tx))
            .await
            .map_err(|_| ProtocolError::TransferFailed("queue shut down".to_string()))?;
        rx.await
            .map_err(|_| ProtocolError::TransferFailed("status response lost".to_string()))
    }

    /// Shut down the queue, clearing all entries
    pub async fn shutdown(&self) -> Result<()> {
        self.cmd_tx
            .send(QueueCommand::Shutdown)
            .await
            .map_err(|_| ProtocolError::TransferFailed("queue already shut down".to_string()))
    }
}

impl TransferQueue {
    /// Run the queue event loop, processing commands until shutdown or
    /// all senders are dropped.
    pub async fn run(mut self) {
        while let Some(cmd) = self.cmd_rx.recv().await {
            match cmd {
                QueueCommand::Enqueue(request) => {
                    self.handle_enqueue(request);
                }
                QueueCommand::Pause(id) => {
                    self.handle_pause(id);
                }
                QueueCommand::Resume(id) => {
                    self.handle_resume(id);
                }
                QueueCommand::Cancel(id) => {
                    self.handle_cancel(id);
                }
                QueueCommand::ListStatus(reply) => {
                    let statuses = self.snapshot_all();
                    let _ = reply.send(statuses);
                }
                QueueCommand::Shutdown => {
                    self.pending.clear();
                    self.active.clear();
                    self.completed.clear();
                    break;
                }
            }
        }
    }

    /// Enqueue a transfer. If there is room, start it immediately; otherwise
    /// place it in the pending queue.
    fn handle_enqueue(&mut self, request: TransferRequest) {
        if self.active.len() < self.max_concurrent {
            let entry = QueueEntry::new(request, TransferState::Transferring);
            self.active.push(entry);
        } else {
            let entry = QueueEntry::new(request, TransferState::Idle);
            self.pending.push_back(entry);
        }
    }

    /// Pause an active transfer by setting its state to Paused.
    fn handle_pause(&mut self, id: TransferId) {
        if let Some(entry) = self.active.iter_mut().find(|e| e.id == id) {
            if entry.state == TransferState::Transferring {
                entry.state = TransferState::Paused;
            }
        }
    }

    /// Resume a paused transfer by setting its state back to Transferring.
    fn handle_resume(&mut self, id: TransferId) {
        if let Some(entry) = self.active.iter_mut().find(|e| e.id == id) {
            if entry.state == TransferState::Paused {
                entry.state = TransferState::Transferring;
            }
        }
    }

    /// Cancel a transfer. Removes it from active or pending and promotes
    /// the next pending transfer if an active slot opened.
    fn handle_cancel(&mut self, id: TransferId) {
        // Try to remove from active first
        if let Some(pos) = self.active.iter().position(|e| e.id == id) {
            let mut entry = self.active.remove(pos);
            entry.state = TransferState::Failed;
            self.completed.push(entry);
            self.promote_pending();
            return;
        }

        // Try to remove from pending
        if let Some(pos) = self.pending.iter().position(|e| e.id == id) {
            let mut entry = self.pending.remove(pos).expect("position was valid");
            entry.state = TransferState::Failed;
            self.completed.push(entry);
        }
    }

    /// Move the next pending transfer into active if there is capacity.
    fn promote_pending(&mut self) {
        while self.active.len() < self.max_concurrent {
            if let Some(mut entry) = self.pending.pop_front() {
                entry.state = TransferState::Transferring;
                self.active.push(entry);
            } else {
                break;
            }
        }
    }

    /// Collect status snapshots of all entries (pending, active, completed).
    fn snapshot_all(&self) -> Vec<TransferStatus> {
        let mut statuses =
            Vec::with_capacity(self.pending.len() + self.active.len() + self.completed.len());
        for entry in &self.pending {
            statuses.push(entry.status());
        }
        for entry in &self.active {
            statuses.push(entry.status());
        }
        for entry in &self.completed {
            statuses.push(entry.status());
        }
        statuses
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a transfer request with a given ID byte.
    fn make_request(id_byte: u8) -> TransferRequest {
        TransferRequest {
            id: [id_byte; 16],
            files: vec![PathBuf::from(format!("file_{}.txt", id_byte))],
            relay: "relay.example.com".to_string(),
            code_phrase: zeroize::Zeroizing::new(format!("code-{}", id_byte)),
            throttle_bps: 0,
        }
    }

    #[tokio::test]
    async fn test_enqueue_starts_immediately() {
        let (queue, handle) = QueueHandle::new(2);
        let queue_task = tokio::spawn(queue.run());

        handle.enqueue(make_request(1)).await.unwrap();

        let statuses = handle.list_status().await.unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, TransferState::Transferring);
        assert_eq!(statuses[0].id, [1u8; 16]);

        handle.shutdown().await.unwrap();
        queue_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_enqueue_waits_when_full() {
        let (queue, handle) = QueueHandle::new(1);
        let queue_task = tokio::spawn(queue.run());

        handle.enqueue(make_request(1)).await.unwrap();
        handle.enqueue(make_request(2)).await.unwrap();

        let statuses = handle.list_status().await.unwrap();
        assert_eq!(statuses.len(), 2);

        // First should be pending (Idle), second should be active (Transferring)
        // The pending entries come first in snapshot_all
        let pending: Vec<_> = statuses
            .iter()
            .filter(|s| s.state == TransferState::Idle)
            .collect();
        let active: Vec<_> = statuses
            .iter()
            .filter(|s| s.state == TransferState::Transferring)
            .collect();
        assert_eq!(pending.len(), 1, "one transfer should be pending");
        assert_eq!(active.len(), 1, "one transfer should be active");
        assert_eq!(active[0].id, [1u8; 16], "first enqueued should be active");
        assert_eq!(
            pending[0].id, [2u8; 16],
            "second enqueued should be pending"
        );

        handle.shutdown().await.unwrap();
        queue_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_pause_resume() {
        let (queue, handle) = QueueHandle::new(2);
        let queue_task = tokio::spawn(queue.run());

        handle.enqueue(make_request(1)).await.unwrap();

        // Pause
        handle.pause([1u8; 16]).await.unwrap();
        let statuses = handle.list_status().await.unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, TransferState::Paused);

        // Resume
        handle.resume([1u8; 16]).await.unwrap();
        let statuses = handle.list_status().await.unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, TransferState::Transferring);

        handle.shutdown().await.unwrap();
        queue_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_cancel_active() {
        let (queue, handle) = QueueHandle::new(2);
        let queue_task = tokio::spawn(queue.run());

        handle.enqueue(make_request(1)).await.unwrap();
        handle.cancel([1u8; 16]).await.unwrap();

        let statuses = handle.list_status().await.unwrap();
        assert_eq!(statuses.len(), 1);
        assert_eq!(statuses[0].state, TransferState::Failed);

        handle.shutdown().await.unwrap();
        queue_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_cancel_pending() {
        let (queue, handle) = QueueHandle::new(1);
        let queue_task = tokio::spawn(queue.run());

        handle.enqueue(make_request(1)).await.unwrap();
        handle.enqueue(make_request(2)).await.unwrap();

        // Cancel the pending one (id=2)
        handle.cancel([2u8; 16]).await.unwrap();

        let statuses = handle.list_status().await.unwrap();
        // Should have 2: one active (id=1), one failed/completed (id=2)
        let active: Vec<_> = statuses
            .iter()
            .filter(|s| s.state == TransferState::Transferring)
            .collect();
        let failed: Vec<_> = statuses
            .iter()
            .filter(|s| s.state == TransferState::Failed)
            .collect();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].id, [1u8; 16]);
        assert_eq!(failed.len(), 1);
        assert_eq!(failed[0].id, [2u8; 16]);

        handle.shutdown().await.unwrap();
        queue_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_cancel_active_promotes_pending() {
        let (queue, handle) = QueueHandle::new(1);
        let queue_task = tokio::spawn(queue.run());

        handle.enqueue(make_request(1)).await.unwrap();
        handle.enqueue(make_request(2)).await.unwrap();

        // Cancel active (id=1), should promote pending (id=2)
        handle.cancel([1u8; 16]).await.unwrap();

        let statuses = handle.list_status().await.unwrap();
        let active: Vec<_> = statuses
            .iter()
            .filter(|s| s.state == TransferState::Transferring)
            .collect();
        assert_eq!(active.len(), 1);
        assert_eq!(
            active[0].id, [2u8; 16],
            "pending transfer should be promoted"
        );

        handle.shutdown().await.unwrap();
        queue_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_list_status() {
        let (queue, handle) = QueueHandle::new(1);
        let queue_task = tokio::spawn(queue.run());

        handle.enqueue(make_request(1)).await.unwrap();
        handle.enqueue(make_request(2)).await.unwrap();
        handle.enqueue(make_request(3)).await.unwrap();

        let statuses = handle.list_status().await.unwrap();
        assert_eq!(statuses.len(), 3);

        // 1 active, 2 pending
        let active_count = statuses
            .iter()
            .filter(|s| s.state == TransferState::Transferring)
            .count();
        let pending_count = statuses
            .iter()
            .filter(|s| s.state == TransferState::Idle)
            .count();
        assert_eq!(active_count, 1);
        assert_eq!(pending_count, 2);

        handle.shutdown().await.unwrap();
        queue_task.await.unwrap();
    }

    #[tokio::test]
    async fn test_shutdown_clears_all() {
        let (queue, handle) = QueueHandle::new(2);
        let queue_task = tokio::spawn(queue.run());

        handle.enqueue(make_request(1)).await.unwrap();
        handle.enqueue(make_request(2)).await.unwrap();
        handle.enqueue(make_request(3)).await.unwrap();

        handle.shutdown().await.unwrap();
        queue_task.await.unwrap();

        // After shutdown, sending commands should fail since the receiver is dropped
        let result = handle.enqueue(make_request(4)).await;
        assert!(result.is_err());
    }
}
