use axum::{extract::State, Json};
use serde_json::{json, Value};
use std::sync::Arc;

use crate::AppState;

fn pool_json(name: &str, max: usize, active: u32, idle: u32, crashed: u32,
             total_tasks: u64, total_created: u64, total_recycled: u64) -> Value {
    json!({
        "name": name,
        "max_size": max,
        "active": active,
        "idle": idle,
        "crashed": crashed,
        "total_tasks": total_tasks,
        "total_created": total_created,
        "total_recycled": total_recycled,
    })
}

/// GET /pool — stats for both egress pools (direct + Tor).
pub async fn pool_handler(State(state): State<Arc<AppState>>) -> Json<Value> {
    let d = state.pool.stats();
    let t = state.tor_pool.stats();
    Json(json!({
        "pools": [
            pool_json("direct", d.max_size, d.active, d.idle, d.crashed,
                      d.total_tasks, d.total_created, d.total_recycled),
            pool_json("tor", t.max_size, t.active, t.idle, t.crashed,
                      t.total_tasks, t.total_created, t.total_recycled),
        ]
    }))
}
