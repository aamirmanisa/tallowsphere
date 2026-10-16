use axum::{extract::State, Json};
use std::sync::Arc;

use crate::AppState;

/// POST /shutdown — gracefully shuts down the daemon.
/// This endpoint is authenticated (behind the auth middleware).
pub async fn shutdown_handler(State(state): State<Arc<AppState>>) -> Json<serde_json::Value> {
    tracing::info!("Shutdown requested via API");
    // Signal graceful shutdown via watch channel
    let _ = state.shutdown_tx.send(true);
    Json(serde_json::json!({"status": "shutting_down"}))
}
