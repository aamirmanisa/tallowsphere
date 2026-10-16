use axum::{
    http::StatusCode,
    middleware,
    routing::{get, post},
    Router,
};
use std::sync::Arc;
use tower_http::trace::TraceLayer;

use crate::auth;
use crate::AppState;

pub mod handshake;
pub mod health;
pub mod jobs;
pub mod shutdown;
pub mod sync;
// sse is a top-level module (not under routes/) — imported via crate::sse

/// Catch-all handler for unmatched routes.
/// Returns 404; auth enforcement happens in the middleware layer
/// which runs before this handler.
async fn catch_all() -> (StatusCode, &'static str) {
    (StatusCode::NOT_FOUND, "Not found")
}

/// Create the axum Router with all route handlers and middleware.
///
/// Route layout:
///   - GET /health        → unauthenticated (exempted inside auth middleware)
///   - POST /auth/handshake → ipc_auth responder handshake (exempted inside
///     auth middleware; authenticated by PSK proofs, not the bearer token)
///   - POST /jobs          → create a new job (authenticated)
///   - GET /jobs           → list all jobs (authenticated)
///   - GET /jobs/{id}      → get a single job (authenticated)
///   - GET /jobs/{id}/history → get job audit trail (authenticated)
///   - POST /shutdown      → graceful shutdown (authenticated)
///   - GET /events        → SSE progress stream (authenticated)
///   - GET /{*rest}       → catch-all (requires auth, returns 404)
///
/// The auth middleware is applied via `layer` — audit-04 F-8: `layer`, not
/// `route_layer`, so unmatched paths are authenticated too (`route_layer`
/// only runs for matched routes, which let 404/405 probes see the route
/// table unauthenticated). The auth_middleware function exempts `/health`
/// and `/auth/handshake`.
pub fn create_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health::health_handler))
        // ipc_auth responder handshake (B7.1.2) — exempted inside the auth
        // middleware like /health; authenticated by PSK proofs instead.
        .route("/auth/handshake", post(handshake::handshake_handler))
        // Job CRUD routes
        .route("/jobs", get(jobs::list_jobs_handler).post(jobs::create_job_handler))
        .route("/jobs/{id}", get(jobs::get_job_handler))
        .route("/jobs/{id}/history", get(jobs::get_job_history_handler))
        // Sync pair CRUD routes
        .route("/sync/pairs", post(sync::create_pair).get(sync::list_pairs))
        .route("/sync/pairs/{id}", get(sync::get_pair).delete(sync::delete_pair))
        .route("/sync/pairs/{id}/status", get(sync::get_pair_status))
        .route("/sync/pairs/{id}/pause", post(sync::pause_pair))
        .route("/sync/pairs/{id}/resume", post(sync::resume_pair))
        .route("/sync/pairs/{id}/history", get(sync::get_pair_history))
        // Conflict detection and resolution
        .route("/sync/conflicts", get(sync::list_conflicts))
        .route("/sync/conflicts/resolve", post(sync::resolve_conflict))
        // Mesh configuration
        .route("/sync/mesh", post(sync::configure_mesh))
        .route("/sync/mesh/{mesh_id}/status", get(sync::get_mesh_status))
        .route("/sync/mesh/{mesh_id}/peers", get(sync::get_mesh_peers))
        // Shutdown endpoint
        .route("/shutdown", post(shutdown::shutdown_handler))
        // SSE streaming endpoint
        .route("/events", get(crate::sse::sse_handler))
        // Catch-all: auth middleware intercepts unauthenticated requests before this handler
        .route("/*rest", get(catch_all))
        // F-8: `layer` (not `route_layer`) — runs for matched routes, the
        // catch-all, AND unmatched paths (404/405 probes get authenticated
        // too, so the route table is not readable unauthenticated).
        .layer(middleware::from_fn_with_state(
            state.clone(),
            auth::auth_middleware,
        ))
        .with_state(state)
        .layer(TraceLayer::new_for_http())
}
