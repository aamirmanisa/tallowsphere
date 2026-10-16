use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    routing::{get, post},
    Json, Router,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::AppState;

pub mod extract;
pub mod health;
pub mod pool;

/// Catch-all handler for unmatched routes (auth enforced before this).
async fn catch_all() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not found")
}

/// Create the axum Router.
///
/// Routes:
///   - GET  /health     → unauthenticated (exempted inside auth middleware)
///   - POST /extract    → run a stealth article extraction (authenticated)
///   - GET  /pool       → pool stats (authenticated)
///   - POST /shutdown   → graceful shutdown (authenticated)
///
/// The auth middleware layer is applied to all routes except /health.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health::health_handler))
        .route("/extract", post(extract::extract_handler))
        .route("/pool", get(pool::pool_handler))
        .route("/shutdown", post(shutdown_handler))
        .route("/*rest", get(catch_all))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}

/// POST /shutdown — graceful shutdown via the daemon's watch channel.
async fn shutdown_handler(
    State(state): State<Arc<AppState>>,
) -> (StatusCode, Json<Value>) {
    let _ = state.shutdown_tx.send(true);
    tracing::info!("shutdown requested via API");
    (
        StatusCode::ACCEPTED,
        Json(json!({"status": "shutting down"})),
    )
}
