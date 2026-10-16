use axum::{
    body::Body,
    extract::State,
    http::{header, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Json, Response},
};
use serde_json::json;
use std::sync::Arc;

use crate::AppState;

/// Auth middleware — rejects requests without a valid bearer token.
/// Exempts GET /health from authentication.
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    // Exempt health endpoint from authentication
    if req.uri().path() == "/health" && req.method() == Method::GET {
        return next.run(req).await;
    }

    let auth_header = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .unwrap_or("");

    if !auth_header.starts_with("Bearer ") {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized", "detail": "missing Bearer token"})),
        )
            .into_response();
    }

    let token = &auth_header[7..];

    // Constant-time comparison to avoid timing side-channels
    use blake3::Hasher;
    let mut req_hasher = Hasher::new();
    req_hasher.update(token.as_bytes());
    let req_digest = req_hasher.finalize();

    let mut cfg_hasher = Hasher::new();
    cfg_hasher.update(state.config.token.as_bytes());
    let cfg_digest = cfg_hasher.finalize();

    if req_digest != cfg_digest {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "unauthorized", "detail": "invalid token"})),
        )
            .into_response();
    }

    next.run(req).await
}
