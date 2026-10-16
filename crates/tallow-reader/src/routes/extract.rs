use axum::{extract::State, http::StatusCode, Json};
use serde_json::{json, Value};
use std::sync::Arc;
use std::time::Instant;

use crate::AppState;
use crate::engine::{ExtractRequest, ExtractResult};

/// POST /extract — run a stealth article extraction.
pub async fn extract_handler(
    State(state): State<Arc<AppState>>,
    Json(req): Json<ExtractRequest>,
) -> (StatusCode, Json<Value>) {
    if req.url.trim().is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "url is required"})),
        );
    }

    let start = Instant::now();
    let result: ExtractResult =
        crate::engine::extract(&state.pool, &state.tor_pool, &req.url, req.anon).await;
    let secs = start.elapsed().as_secs_f64();

    let status = if result.error.is_some() {
        StatusCode::UNPROCESSABLE_ENTITY
    } else {
        StatusCode::OK
    };

    let body = json!({
        "url": result.url,
        "title": result.title,
        "content": result.content,
        "length": result.length,
        "source": result.source,
        "member": result.member,
        "error": result.error,
        "cookies": result.cookies,
        "elapsed_secs": secs,
    });

    (status, Json(body))
}
