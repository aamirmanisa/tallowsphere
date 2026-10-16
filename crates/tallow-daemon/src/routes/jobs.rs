use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::db;
use crate::AppState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateJobRequest {
    pub name: String,
    pub config: serde_json::Value,
    #[serde(default)] // defaults to 0 if absent
    pub priority: u32,
}

#[derive(Debug, Serialize)]
pub struct CreateJobResponse {
    pub id: String,
    pub name: String,
    pub status: String,
    pub created_at: String,
}

#[derive(Debug, Serialize)]
pub struct JobListResponse {
    pub jobs: Vec<db::Job>,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct JobHistoryResponse {
    pub job_id: String,
    pub events: Vec<db::JobHistoryEntry>,
}

/// POST /jobs — Create a new job.
///
/// Expects JSON body with `name` (1-200 chars), `config` (any JSON value),
/// and optional `priority` (0-10, defaults to 0).
/// Returns 201 with `{id, name, status, created_at}`.
pub async fn create_job_handler(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateJobRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Validate name
    if body.name.is_empty() || body.name.len() > 200 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "name must be 1-200 characters"})),
        );
    }

    // Validate priority (0-10)
    if body.priority > 10 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "priority must be 0-10"})),
        );
    }

    // Serialize config to JSON string
    let config_json = match serde_json::to_string(&body.config) {
        Ok(s) => s,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": format!("invalid config: {}", e)})),
            );
        }
    };

    // Honest submit-time contract: reject any job shape the executor cannot
    // run BEFORE it is queued. The daemon never accepts a job it will only
    // fail later (B8 — no accept-then-fail).
    if let Err(reason) = crate::job_kind::classify(&body.config) {
        return (
            StatusCode::UNPROCESSABLE_ENTITY,
            Json(serde_json::json!({"error": reason})),
        );
    }

    let db_lock = state.db.lock().await;
    match db::create_job_with_priority(&db_lock, &body.name, &config_json, body.priority) {
        Ok(job) => (
            StatusCode::CREATED,
            Json(serde_json::json!(CreateJobResponse {
                id: job.id,
                name: job.name,
                status: job.status,
                created_at: job.created_at,
            })),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to create job: {}", e)})),
        ),
    }
}

/// GET /jobs — List all jobs, newest first.
///
/// Optional query parameter `?status=<status>` filters by job status.
pub async fn list_jobs_handler(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let status_filter = params.get("status").map(|s| s.as_str());

    let db_lock = state.db.lock().await;
    match db::list_jobs(&db_lock, status_filter) {
        Ok(jobs) => {
            let total = jobs.len();
            Json(serde_json::json!(JobListResponse { jobs, total }))
        }
        Err(e) => Json(serde_json::json!({
            "error": format!("failed to list jobs: {}", e),
            "jobs": [],
            "total": 0
        })),
    }
}

/// GET /jobs/:id — Get a single job by ID.
///
/// Returns 200 with the job, or 404 if not found.
pub async fn get_job_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_lock = state.db.lock().await;
    match db::get_job(&db_lock, &id) {
        Ok(Some(job)) => (StatusCode::OK, Json(serde_json::json!(job))),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "job not found"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to get job: {}", e)})),
        ),
    }
}

/// GET /jobs/:id/history — Get audit trail for a job.
///
/// Returns the history of status change events, oldest first.
pub async fn get_job_history_handler(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> Json<serde_json::Value> {
    let db_lock = state.db.lock().await;
    match db::get_job_history(&db_lock, &id) {
        Ok(events) => Json(serde_json::json!(JobHistoryResponse {
            job_id: id,
            events,
        })),
        Err(e) => Json(serde_json::json!({
            "error": format!("failed to get job history: {}", e),
            "job_id": id,
            "events": []
        })),
    }
}
