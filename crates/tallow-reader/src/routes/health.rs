use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::AppState;

/// GET /health — unauthenticated liveness check.
pub async fn health_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let stats = state.pool.stats();
    Json(json!({
        "status": "ok",
        "service": "tallow-reader",
        "uptime_secs": state.start_time.elapsed().as_secs(),
        "pool_max": stats.max_size,
    }))
}
