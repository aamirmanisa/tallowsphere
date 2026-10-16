use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

use crate::conflict;
use crate::db;
use crate::mesh;
use crate::sse::ProgressEvent;
use crate::AppState;

// ---------------------------------------------------------------------------
// Request / Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct CreateSyncPairRequest {
    pub name: String,
    pub source_dir: String,
    pub dest_dir: String,
    pub device_id: String,
    #[serde(default)]
    pub config_json: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct SyncPairResponse {
    pub id: String,
    pub name: String,
    pub source_dir: String,
    pub dest_dir: String,
    pub status: String,
    pub device_id: String,
    pub config_json: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

impl From<db::SyncPair> for SyncPairResponse {
    fn from(p: db::SyncPair) -> Self {
        Self {
            id: p.id,
            name: p.name,
            source_dir: p.source_dir,
            dest_dir: p.dest_dir,
            status: p.status,
            device_id: p.device_id,
            config_json: p.config_json,
            created_at: p.created_at,
            updated_at: p.updated_at,
        }
    }
}

// ---------------------------------------------------------------------------
// POST /sync/pairs — Create a new sync pair
// ---------------------------------------------------------------------------

pub async fn create_pair(
    State(state): State<Arc<AppState>>,
    Json(body): Json<CreateSyncPairRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    // Validate name
    if body.name.is_empty() || body.name.len() > 200 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "name must be 1-200 characters"})),
        );
    }

    // Validate source_dir exists on filesystem
    let src = std::path::Path::new(&body.source_dir);
    if !src.exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("source_dir does not exist: {}", body.source_dir)})),
        );
    }

    // Validate dest_dir exists on filesystem
    let dst = std::path::Path::new(&body.dest_dir);
    if !dst.exists() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": format!("dest_dir does not exist: {}", body.dest_dir)})),
        );
    }

    let db_lock = state.db.lock().await;
    match db::create_sync_pair(
        &db_lock,
        &body.name,
        &body.source_dir,
        &body.dest_dir,
        &body.device_id,
        body.config_json.as_deref(),
    ) {
        Ok(pair) => {
            // Emit SSE event
            let _ = state.progress_tx.send(ProgressEvent::SyncPairCreated {
                pair_id: pair.id.clone(),
                name: pair.name.clone(),
            });

            (StatusCode::CREATED, Json(serde_json::json!(SyncPairResponse::from(pair))))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to create sync pair: {}", e)})),
        ),
    }
}

// ---------------------------------------------------------------------------
// GET /sync/pairs — List all sync pairs
// ---------------------------------------------------------------------------

pub async fn list_pairs(
    State(state): State<Arc<AppState>>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let status_filter = params.get("status").map(|s| s.as_str());
    let db_lock = state.db.lock().await;
    match db::list_sync_pairs(&db_lock, status_filter) {
        Ok(pairs) => {
            let response: Vec<SyncPairResponse> = pairs.into_iter().map(SyncPairResponse::from).collect();
            let total = response.len();
            Json(serde_json::json!({ "pairs": response, "total": total }))
        }
        Err(e) => Json(serde_json::json!({
            "error": format!("failed to list sync pairs: {}", e),
            "pairs": [],
            "total": 0
        })),
    }
}

// ---------------------------------------------------------------------------
// GET /sync/pairs/:id — Get a single sync pair
// ---------------------------------------------------------------------------

pub async fn get_pair(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_lock = state.db.lock().await;
    match db::get_sync_pair(&db_lock, &id) {
        Ok(Some(pair)) => (StatusCode::OK, Json(serde_json::json!(SyncPairResponse::from(pair)))),
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "sync pair not found"})),
        ),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to get sync pair: {}", e)})),
        ),
    }
}

// ---------------------------------------------------------------------------
// DELETE /sync/pairs/:id — Remove a sync pair (CASCADE deletes related rows)
// ---------------------------------------------------------------------------

pub async fn delete_pair(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_lock = state.db.lock().await;
    // Check if pair exists first
    match db::get_sync_pair(&db_lock, &id) {
        Ok(Some(_)) => {},
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "sync pair not found"})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to check sync pair: {}", e)})),
        ),
    }

    match db::delete_sync_pair(&db_lock, &id) {
        Ok(()) => {
            // Emit SSE event
            let _ = state.progress_tx.send(ProgressEvent::SyncPairRemoved {
                pair_id: id.clone(),
            });
            (StatusCode::OK, Json(serde_json::json!({"deleted": id})))
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to delete sync pair: {}", e)})),
        ),
    }
}

// ---------------------------------------------------------------------------
// GET /sync/pairs/:id/status — Get detailed sync pair status
// ---------------------------------------------------------------------------

pub async fn get_pair_status(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_lock = state.db.lock().await;

    // Get the sync pair
    let pair = match db::get_sync_pair(&db_lock, &id) {
        Ok(Some(p)) => p,
        Ok(None) => return (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": "sync pair not found"})),
        ),
        Err(e) => return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to get sync pair: {}", e)})),
        ),
    };

    // Get file versions
    let file_versions = db::get_file_versions_for_pair(&db_lock, &id).unwrap_or_default();
    let file_count = file_versions.len();

    // Get device versions
    let device_versions: Vec<serde_json::Value> = db::get_device_versions(&db_lock, &id)
        .unwrap_or_default()
        .into_iter()
        .map(|(dev_id, ver)| {
            serde_json::json!({"device_id": dev_id, "version": ver})
        })
        .collect();

    // Compute pending changes (files where local_version != max peer version)
    let pending_changes = file_versions.iter()
        .filter(|fv| {
            // For now: if any device has a different version, count as pending
            fv.version > 1 // simple heuristic: version > 1 means changes happened
        })
        .count();

    let last_sync_at = pair.updated_at.clone();

    (StatusCode::OK, Json(serde_json::json!({
        "pair_id": id,
        "file_count": file_count,
        "pending_changes": pending_changes,
        "device_versions": device_versions,
        "last_sync_at": last_sync_at,
    })))
}

// ---------------------------------------------------------------------------
// POST /sync/pairs/:id/pause — Pause a sync pair
// ---------------------------------------------------------------------------

pub async fn pause_pair(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_lock = state.db.lock().await;
    match db::update_sync_pair_status(&db_lock, &id, "paused") {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "paused"}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to pause sync pair: {}", e)})),
        ),
    }
}

// ---------------------------------------------------------------------------
// POST /sync/pairs/:id/resume — Resume a sync pair
// ---------------------------------------------------------------------------

pub async fn resume_pair(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_lock = state.db.lock().await;
    match db::update_sync_pair_status(&db_lock, &id, "active") {
        Ok(()) => (StatusCode::OK, Json(serde_json::json!({"status": "active"}))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": format!("failed to resume sync pair: {}", e)})),
        ),
    }
}

// ---------------------------------------------------------------------------
// GET /sync/pairs/:id/history — Get sync audit trail
// ---------------------------------------------------------------------------

pub async fn get_pair_history(
    State(state): State<Arc<AppState>>,
    Path(id): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let limit: Option<u32> = params
        .get("limit")
        .and_then(|s| s.parse().ok());

    let db_lock = state.db.lock().await;
    match db::get_sync_history(&db_lock, &id, limit) {
        Ok(entries) => {
            let events: Vec<serde_json::Value> = entries
                .into_iter()
                .map(|e| serde_json::json!({
                    "id": e.id,
                    "event": e.event,
                    "relative_path": e.relative_path,
                    "detail": e.detail,
                    "created_at": e.created_at,
                }))
                .collect();
            Json(serde_json::json!({
                "sync_pair_id": id,
                "events": events,
            }))
        }
        Err(e) => Json(serde_json::json!({
            "error": format!("failed to get sync history: {}", e),
            "sync_pair_id": id,
            "events": [],
        })),
    }
}

// ---------------------------------------------------------------------------
// GET /sync/conflicts?pair_id={id} — List unresolved conflicts
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ConflictQuery {
    pub pair_id: String,
}

pub async fn list_conflicts(
    State(state): State<Arc<AppState>>,
    Query(params): Query<ConflictQuery>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_lock = state.db.lock().await;

    // Get all file versions for the pair, group by relative_path
    let file_versions = match db::get_file_versions_for_pair(&db_lock, &params.pair_id) {
        Ok(fv) => fv,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({"error": format!("db error: {}", e)})),
            );
        }
    };

    // Group by relative_path
    let mut grouped: HashMap<String, Vec<&db::FileVersion>> = HashMap::new();
    for fv in &file_versions {
        grouped.entry(fv.relative_path.clone()).or_default().push(fv);
    }

    let mut conflicts: Vec<serde_json::Value> = Vec::new();

    for (path, versions) in &grouped {
        if versions.len() < 2 {
            continue; // can't have conflict with single device
        }
        // Check for conflict
        match conflict::detect_conflict(&db_lock, &params.pair_id, path) {
            Ok(conflict::ConflictStatus::Conflict { versions: ver_list, winner_device, loser_device }) => {
                let device_versions: Vec<serde_json::Value> = ver_list
                    .iter()
                    .map(|(dev, ver, merkle)| {
                        serde_json::json!({
                            "device_id": dev,
                            "version": ver,
                            "merkle_root": merkle,
                        })
                    })
                    .collect();

                conflicts.push(serde_json::json!({
                    "relative_path": path,
                    "device_versions": device_versions,
                    "winner": winner_device,
                    "loser": loser_device,
                }));
            }
            _ => {} // NoConflict or error — skip
        }
    }

    (StatusCode::OK, Json(serde_json::json!({
        "pair_id": params.pair_id,
        "conflicts": conflicts,
        "total": conflicts.len(),
    })))
}

// ---------------------------------------------------------------------------
// POST /sync/conflicts/resolve — Resolve a conflict
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ResolveConflictRequest {
    pub pair_id: String,
    pub relative_path: String,
    pub strategy: String, // "keep-mine" | "keep-theirs" | "keep-both"
}

pub async fn resolve_conflict(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ResolveConflictRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_lock = state.db.lock().await;

    match conflict::resolve_conflict(&db_lock, &state, &body.pair_id, &body.relative_path, &body.strategy) {
        Ok(resolution) => {
            // Emit SSE event
            let _ = state.progress_tx.send(ProgressEvent::SyncConflictResolved {
                pair_id: body.pair_id.clone(),
                relative_path: body.relative_path.clone(),
                resolution: body.strategy.clone(),
            });

            (StatusCode::OK, Json(serde_json::json!({
                "pair_id": resolution.pair_id,
                "relative_path": resolution.relative_path,
                "strategy": resolution.strategy,
                "winner_path": resolution.winner_path,
                "conflict_path": resolution.conflict_path,
                "resolved": resolution.resolved,
            })))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

// ---------------------------------------------------------------------------
// POST /sync/mesh — Configure a new mesh
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub struct ConfigureMeshRequest {
    pub devices: HashMap<String, MeshDeviceRequest>,
    pub folders: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct MeshDeviceRequest {
    pub peer_url: String,
    pub name: String,
}

pub async fn configure_mesh(
    State(state): State<Arc<AppState>>,
    Json(body): Json<ConfigureMeshRequest>,
) -> (StatusCode, Json<serde_json::Value>) {
    let mut devices: HashMap<String, mesh::MeshDevice> = HashMap::new();
    for (id, dev) in &body.devices {
        devices.insert(
            id.clone(),
            mesh::MeshDevice {
                device_id: id.clone(),
                peer_url: dev.peer_url.clone(),
                name: dev.name.clone(),
            },
        );
    }

    let config = mesh::MeshConfig {
        mesh_id: uuid::Uuid::new_v4().to_string(),
        devices,
        folders: body.folders.clone(),
        created_at: chrono::Utc::now().to_rfc3339(),
    };

    let db_lock = state.db.lock().await;
    match mesh::configure_mesh(&db_lock, &state, &config) {
        Ok(result) => {
            let _ = state.progress_tx.send(ProgressEvent::SyncPairCreated {
                pair_id: result.mesh_id.clone(),
                name: format!("mesh with {} devices", result.device_count),
            });

            (StatusCode::CREATED, Json(serde_json::json!({
                "mesh_id": result.mesh_id,
                "device_count": result.device_count,
                "pairs_created": result.pairs_created,
                "pair_ids": result.pair_ids,
            })))
        }
        Err(e) => (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

// ---------------------------------------------------------------------------
// GET /sync/mesh/:mesh_id/status — Get mesh convergence
// ---------------------------------------------------------------------------

pub async fn get_mesh_status(
    State(state): State<Arc<AppState>>,
    Path(mesh_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_lock = state.db.lock().await;
    match mesh::resolve_mesh_state(&db_lock, &mesh_id) {
        Ok(conv) => (StatusCode::OK, Json(serde_json::json!({
            "mesh_id": conv.mesh_id,
            "total_files": conv.total_files,
            "converged_files": conv.converged_files,
            "pending_files": conv.pending_files,
            "conflict_files": conv.conflict_files,
            "peers": conv.peers,
            "file_states": conv.file_states,
        }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        ),
    }
}

// ---------------------------------------------------------------------------
// GET /sync/mesh/:mesh_id/peers — Get peer reachability
// ---------------------------------------------------------------------------

pub async fn get_mesh_peers(
    State(state): State<Arc<AppState>>,
    Path(mesh_id): Path<String>,
) -> (StatusCode, Json<serde_json::Value>) {
    let db_lock = state.db.lock().await;
    match mesh::discover_peers(&db_lock, &mesh_id) {
        Ok(peers) => (StatusCode::OK, Json(serde_json::json!({
            "mesh_id": mesh_id,
            "peers": peers,
        }))),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"error": e})),
        ),
    }
}
