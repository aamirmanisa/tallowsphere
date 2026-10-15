use axum::{extract::State, http::StatusCode, response::Json};
use serde::Serialize;
use std::sync::Arc;

use crate::AppState;

/// Health check response returned by GET /health.
#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub uptime_secs: f64,
    pub version: String,
    pub active_jobs: usize,
}

/// GET /health — returns daemon status as JSON.
/// This endpoint is unauthenticated (exempted in auth middleware).
pub async fn health_handler(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<HealthResponse>) {
    let response = HealthResponse {
        status: "ok".to_string(),
        uptime_secs: state.start_time.elapsed().as_secs_f64(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        active_jobs: 0, // wired to DB in Plan 03-02
    };
    (StatusCode::OK, Json(response))
}
