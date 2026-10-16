use axum::{
    extract::State,
    response::sse::{Event, KeepAlive, Sse},
};
use futures::stream::Stream;
use serde::Serialize;
use std::convert::Infallible;
use std::sync::Arc;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::AppState;

/// Event emitted to SSE clients when a job's status changes.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "type", content = "data")]
pub enum ProgressEvent {
    #[serde(rename = "job_update")]
    JobUpdate {
        job_id: String,
        status: String,
        detail: Option<String>,
        timestamp: String,
    },
    #[serde(rename = "heartbeat")]
    Heartbeat { timestamp: String },
    #[serde(rename = "file_change")]
    FileChange {
        path: String,
        kind: String, // "create", "modify", "remove", "catchup"
        timestamp: String,
    },
    #[serde(rename = "sync_pair_created")]
    SyncPairCreated {
        pair_id: String,
        name: String,
    },
    #[serde(rename = "sync_pair_removed")]
    SyncPairRemoved {
        pair_id: String,
    },
    #[serde(rename = "sync_file_started")]
    SyncFileStarted {
        pair_id: String,
        relative_path: String,
        strategy: String,
        file_size: u64,
    },
    #[serde(rename = "sync_file_completed")]
    SyncFileCompleted {
        pair_id: String,
        relative_path: String,
        strategy: String,
        bytes_transferred: u64,
        blocks_changed: Option<usize>,
        duration_ms: u64,
    },
    #[serde(rename = "sync_file_error")]
    SyncFileError {
        pair_id: String,
        relative_path: String,
        error: String,
    },
    #[serde(rename = "sync_conflict_detected")]
    SyncConflictDetected {
        pair_id: String,
        relative_path: String,
        winner_device: String,
        loser_device: String,
        conflict_path: String,
    },
    #[serde(rename = "sync_conflict_resolved")]
    SyncConflictResolved {
        pair_id: String,
        relative_path: String,
        resolution: String,
    },
}

/// GET /events — SSE streaming endpoint.
///
/// Returns `text/event-stream` with keep-alive pings every 30 seconds.
/// Clients subscribe to the broadcast channel and receive `ProgressEvent`
/// messages as they are emitted (e.g., on job status changes).
pub async fn sse_handler(
    State(state): State<Arc<AppState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Subscribe to the broadcast channel
    let rx = state.progress_tx.subscribe();

    // Convert broadcast receiver into a filtered SSE stream
    let stream = BroadcastStream::new(rx).filter_map(|result| match result {
        Ok(event) => {
            let json = serde_json::to_string(&event).unwrap_or_default();
            Some(Ok(Event::default().data(json)))
        }
        Err(_) => {
            // Skip lagged messages (client too slow — broadcast dropped events)
            None
        }
    });

    Sse::new(stream).keep_alive(
        KeepAlive::new()
            .interval(std::time::Duration::from_secs(30))
            .text("ping"),
    )
}
