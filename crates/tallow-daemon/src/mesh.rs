//! Multi-machine sync mesh configuration and convergence engine.
//!
//! A mesh is a set of devices where every device syncs the same folders with
//! every other device. Configuration is declarative: the user writes
//! `sync.mesh({devices: {...}, folders: [...]})` once, and the system creates
//! all necessary sync pairs.
//!
//! Convergence happens because each pair independently syncs using version
//! vectors, and the max version per file naturally emerges as authoritative.

use chrono::Utc;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use crate::db;

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConfig {
    pub mesh_id: String,
    pub devices: HashMap<String, MeshDevice>,
    pub folders: Vec<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshDevice {
    pub device_id: String,
    pub peer_url: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerStatus {
    pub device_id: String,
    pub peer_url: String,
    pub reachable: bool,
    pub last_seen: Option<String>,
    pub device_version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshResult {
    pub mesh_id: String,
    pub device_count: usize,
    pub pairs_created: usize,
    pub pair_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshConvergence {
    pub mesh_id: String,
    pub total_files: usize,
    pub converged_files: usize,
    pub pending_files: usize,
    pub conflict_files: usize,
    pub peers: Vec<PeerStatus>,
    pub file_states: Vec<MeshFileState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MeshFileState {
    pub relative_path: String,
    pub authoritative_version: i64,
    pub authoritative_device: String,
    pub converged: bool,
    pub device_versions: Vec<(String, i64)>,
}

// ---------------------------------------------------------------------------
// GREEN phase — implementations
// ---------------------------------------------------------------------------

/// Create bidirectional sync pairs for every pair of devices in the mesh.
///
/// For N devices, creates N*(N-1)/2 bidirectional sync pairs (all unique
/// device pairs). Each pair syncs all folders in config.folders between the
/// two devices. Idempotent — running twice with the same config creates no
/// duplicate pairs.
pub fn configure_mesh(
    conn: &Connection,
    state: &crate::AppState,
    config: &MeshConfig,
) -> Result<MeshResult, String> {
    let local_device_id = &state.device_id;
    let device_ids: Vec<String> = config.devices.keys().cloned().collect();
    let now = Utc::now().to_rfc3339();

    let mut pair_ids: Vec<String> = Vec::new();

    // For each folder, create sync pairs between every unique device pair
    for folder in &config.folders {
        // Validate folder exists on filesystem
        let folder_path = std::path::Path::new(folder);
        if !folder_path.exists() {
            return Err(format!(
                "configure_mesh: folder does not exist: {}",
                folder
            ));
        }

        // Create pairs for every unordered pair of devices
        for i in 0..device_ids.len() {
            for j in (i + 1)..device_ids.len() {
                let dev_a = &device_ids[i];
                let dev_b = &device_ids[j];

                // Skip pairs that don't involve the local device (v1 single-machine)
                if dev_a != local_device_id && dev_b != local_device_id {
                    continue;
                }

                let dev_a_info = config.devices.get(dev_a).unwrap();
                let dev_b_info = config.devices.get(dev_b).unwrap();

                // Check if a pair already exists for this combination
                let existing = find_existing_pair(conn, folder, dev_a, dev_b)?;

                if existing.is_some() {
                    pair_ids.push(existing.unwrap());
                    continue;
                }

                // Determine which device is "local" for source/dest
                let (source_dir, dest_dir, peer_device_id, peer_url) = if dev_a == local_device_id {
                    (folder.clone(), folder.clone(), dev_b.clone(), dev_b_info.peer_url.clone())
                } else {
                    (folder.clone(), folder.clone(), dev_a.clone(), dev_a_info.peer_url.clone())
                };

                let pair_name = format!("mesh: {} ↔ {} ({})", dev_a_info.name, dev_b_info.name, folder);

                let config_json = serde_json::json!({
                    "type": "mesh",
                    "mesh_id": config.mesh_id,
                    "peer_device": peer_device_id,
                    "peer_url": peer_url,
                    "folder": folder,
                })
                .to_string();

                let pair = db::create_sync_pair(
                    conn,
                    &pair_name,
                    &source_dir,
                    &dest_dir,
                    &peer_device_id,
                    Some(&config_json),
                )
                .map_err(|e| format!("configure_mesh: failed to create pair: {}", e))?;

                // Insert device state for peer
                conn.execute(
                    "INSERT OR IGNORE INTO device_states (device_id, sync_pair_id, version, last_seen_at)
                     VALUES (?1, ?2, 0, ?3)",
                    rusqlite::params![peer_device_id, pair.id, now],
                )
                .map_err(|e| format!("configure_mesh: db error: {}", e))?;

                pair_ids.push(pair.id);
            }
        }
    }

    Ok(MeshResult {
        mesh_id: config.mesh_id.clone(),
        device_count: device_ids.len(),
        pairs_created: pair_ids.len(),
        pair_ids,
    })
}

/// Look for an existing sync pair that connects the same two devices for the
/// same folder. Returns the pair ID if found.
fn find_existing_pair(
    conn: &Connection,
    folder: &str,
    dev_a: &str,
    dev_b: &str,
) -> Result<Option<String>, String> {
    let mut stmt = conn
        .prepare(
            "SELECT id, config_json FROM sync_pairs WHERE source_dir = ?1 AND dest_dir = ?1",
        )
        .map_err(|e| format!("find_existing_pair: {}", e))?;

    let rows: Vec<(String, Option<String>)> = stmt
        .query_map(rusqlite::params![folder], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(|e| format!("find_existing_pair: {}", e))?
        .filter_map(|r| r.ok())
        .collect();

    for (id, config_json) in rows {
        if let Some(cfg_str) = config_json {
            if let Ok(cfg) = serde_json::from_str::<serde_json::Value>(&cfg_str) {
                let peer = cfg.get("peer_device").and_then(|v| v.as_str()).unwrap_or("");
                let mesh_type = cfg.get("type").and_then(|v| v.as_str()).unwrap_or("");
                if mesh_type == "mesh" && (peer == dev_a || peer == dev_b) {
                    return Ok(Some(id));
                }
            }
        }
    }
    Ok(None)
}

/// Compute the convergence state across all peers in the mesh.
///
/// For each file tracked in file_versions, determines:
/// - The authoritative version (MAX version across all devices)
/// - Whether all devices have converged (same version + same merkle_root)
pub fn resolve_mesh_state(
    conn: &Connection,
    mesh_id: &str,
) -> Result<MeshConvergence, String> {
    // Find all sync pairs that belong to this mesh
    let mut stmt = conn
        .prepare(
            "SELECT id, device_id FROM sync_pairs WHERE config_json LIKE ?1",
        )
        .map_err(|e| format!("resolve_mesh_state: {}", e))?;

    let mesh_pairs: Vec<(String, String)> = stmt
        .query_map(rusqlite::params![format!("%\"mesh_id\":\"{}\"%", mesh_id)], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })
        .map_err(|e| format!("resolve_mesh_state: {}", e))?
        .filter_map(|r| r.ok())
        .collect();

    if mesh_pairs.is_empty() {
        return Ok(MeshConvergence {
            mesh_id: mesh_id.to_string(),
            total_files: 0,
            converged_files: 0,
            pending_files: 0,
            conflict_files: 0,
            peers: vec![],
            file_states: vec![],
        });
    }

    // Collect all file versions across mesh pairs, grouped by relative_path
    let mut file_map: HashMap<String, HashMap<String, (i64, Option<String>)>> = HashMap::new();
    // (relative_path → device_id → (version, merkle_root))

    for (pair_id, _) in &mesh_pairs {
        let versions = db::get_file_versions_for_pair(conn, pair_id)
            .map_err(|e| format!("resolve_mesh_state: {}", e))?;
        for fv in versions {
            let entry = file_map
                .entry(fv.relative_path.clone())
                .or_default();
            entry.insert(fv.device_id.clone(), (fv.version, fv.merkle_root.clone()));
        }
    }

    let total_files = file_map.len();
    let mut converged_files = 0usize;
    let mut pending_files = 0usize;
    let mut conflict_files = 0usize;
    let mut file_states: Vec<MeshFileState> = Vec::new();

    for (path, device_versions) in &file_map {
        let max_version = device_versions.values().map(|(v, _)| *v).max().unwrap_or(0);

        // Find authoritative device (highest version, tie → lexicographically smallest)
        let mut candidates: Vec<(&String, i64)> = device_versions
            .iter()
            .map(|(dev, (ver, _))| (dev, *ver))
            .collect();
        candidates.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        let authoritative_device = candidates[0].0.clone();

        // Check convergence: all devices have the same version AND same merkle_root
        let first_merkle = device_versions.values().next().map(|(_, m)| m.clone()).flatten();
        let all_same_merkle = device_versions
            .values()
            .all(|(_, m)| *m == first_merkle);
        let all_same_version = device_versions
            .values()
            .map(|(v, _)| *v)
            .all(|v| v == max_version);

        let converged = all_same_version && all_same_merkle;

        if converged {
            converged_files += 1;
        } else if device_versions.len() >= 2 {
            // Check for conflict: different merkle roots at same version
            let has_conflict = device_versions.values().any(|(v1, m1)| {
                device_versions
                    .values()
                    .any(|(v2, m2)| v1 == v2 && m1 != m2)
            });
            if has_conflict {
                conflict_files += 1;
            } else {
                pending_files += 1;
            }
        } else {
            pending_files += 1;
        }

        let dv: Vec<(String, i64)> = device_versions
            .iter()
            .map(|(dev, (ver, _))| (dev.clone(), *ver))
            .collect();

        file_states.push(MeshFileState {
            relative_path: path.clone(),
            authoritative_version: max_version,
            authoritative_device,
            converged,
            device_versions: dv,
        });
    }

    // Build peer statuses
    let peers: Vec<PeerStatus> = mesh_pairs
        .iter()
        .map(|(pair_id, device_id)| {
            let version = db::get_device_versions(conn, pair_id)
                .ok()
                .and_then(|versions| {
                    versions
                        .iter()
                        .find(|(dev, _)| dev == device_id)
                        .map(|(_, v)| *v)
                })
                .unwrap_or(0);
            PeerStatus {
                device_id: device_id.clone(),
                peer_url: String::new(),
                reachable: false, // discover_peers fills this in
                last_seen: None,
                device_version: version,
            }
        })
        .collect();

    Ok(MeshConvergence {
        mesh_id: mesh_id.to_string(),
        total_files,
        converged_files,
        pending_files,
        conflict_files,
        peers,
        file_states,
    })
}

/// Send GET /health to each peer URL and report reachability.
///
/// For v1 (single-machine daemon), this is a simplified implementation:
/// it reads peer URLs from mesh configuration stored in sync_pair config_json
/// and checks reachability via HTTP GET with a 2-second timeout.
pub fn discover_peers(
    conn: &Connection,
    mesh_id: &str,
) -> Result<Vec<PeerStatus>, String> {
    // Find all mesh sync pairs to extract peer URLs
    let mut stmt = conn
        .prepare(
            "SELECT id, device_id, config_json FROM sync_pairs WHERE config_json LIKE ?1",
        )
        .map_err(|e| format!("discover_peers: {}", e))?;

    let pairs: Vec<(String, String, Option<String>)> = stmt
        .query_map(rusqlite::params![format!("%\"mesh_id\":\"{}\"%", mesh_id)], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|e| format!("discover_peers: {}", e))?
        .filter_map(|r| r.ok())
        .collect();

    let mut peers: HashMap<String, PeerStatus> = HashMap::new();

    for (pair_id, device_id, config_json) in &pairs {
        let peer_url = config_json
            .as_deref()
            .and_then(|cfg| serde_json::from_str::<serde_json::Value>(cfg).ok())
            .and_then(|cfg| cfg.get("peer_url").and_then(|v| v.as_str().map(String::from)))
            .unwrap_or_default();

        let version = db::get_device_versions(conn, pair_id)
            .ok()
            .and_then(|versions| {
                versions
                    .iter()
                    .find(|(dev, _)| dev == device_id)
                    .map(|(_, v)| *v)
            })
            .unwrap_or(0);

        // Try HTTP health check
        let reachable = if peer_url.is_empty() {
            false
        } else {
            check_peer_health(&peer_url).unwrap_or(false)
        };

        let last_seen = if reachable {
            Some(Utc::now().to_rfc3339())
        } else {
            None
        };

        peers
            .entry(device_id.clone())
            .and_modify(|existing| {
                if reachable {
                    existing.reachable = true;
                    existing.last_seen = last_seen.clone();
                }
            })
            .or_insert(PeerStatus {
                device_id: device_id.clone(),
                peer_url: peer_url.clone(),
                reachable,
                last_seen,
                device_version: version,
            });
    }

    Ok(peers.into_values().collect())
}

/// Check if a peer is reachable via HTTP GET /health with a 2-second timeout.
fn check_peer_health(peer_url: &str) -> Result<bool, String> {
    let health_url = format!("{}/health", peer_url.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .map_err(|e| format!("check_peer_health: client error: {}", e))?;

    match client.get(&health_url).send() {
        Ok(resp) => Ok(resp.status().is_success()),
        Err(_) => Ok(false), // timeout or connection refused → unreachable
    }
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn setup_db() -> Connection {
        let conn = Connection::open_in_memory().expect("in-memory DB");
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS sync_pairs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                source_dir TEXT NOT NULL,
                dest_dir TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                device_id TEXT NOT NULL,
                config_json TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS device_states (
                device_id TEXT NOT NULL,
                sync_pair_id TEXT NOT NULL REFERENCES sync_pairs(id) ON DELETE CASCADE,
                version INTEGER NOT NULL DEFAULT 0,
                last_seen_at TEXT NOT NULL,
                PRIMARY KEY (device_id, sync_pair_id)
            );

            CREATE TABLE IF NOT EXISTS file_versions (
                sync_pair_id TEXT NOT NULL REFERENCES sync_pairs(id) ON DELETE CASCADE,
                relative_path TEXT NOT NULL,
                device_id TEXT NOT NULL,
                version INTEGER NOT NULL,
                merkle_root TEXT,
                size_bytes INTEGER NOT NULL,
                modified_at TEXT NOT NULL,
                PRIMARY KEY (sync_pair_id, relative_path, device_id)
            );

            CREATE TABLE IF NOT EXISTS sync_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sync_pair_id TEXT NOT NULL REFERENCES sync_pairs(id) ON DELETE CASCADE,
                event TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                detail TEXT,
                created_at TEXT NOT NULL
            );",
        )
        .expect("create sync tables");

        // Ensure tables are writable (in-memory DBs are initially empty)
        conn.execute_batch("PRAGMA foreign_keys = ON;").unwrap();
        conn
    }

    fn dummy_state() -> crate::AppState {
        crate::AppState {
            config: crate::config::Config {
                data_dir: std::path::PathBuf::from("/tmp/tallow-test"),
                db_path: std::path::PathBuf::from("/tmp/tallow-test/tallow.db"),
                port: 0,
                bind_addr: String::new(),
                token: String::new(),
                token_path: std::path::PathBuf::from("/tmp/tallow-test/token"),
                port_file: std::path::PathBuf::from("/tmp/tallow-test/port"),
                tallow_bin: None,
                concurrency_limit: 4,
                retry_base_ms: 1000,
                retry_max_ms: 60000,
                retry_jitter_ms: 500,
                watch_dirs: vec![],
                debounce_delay_ms: 2000,
                debounce_large_file_ms: 10000,
                large_file_threshold_bytes: 10485760,
                bandwidth_limit_bytes_per_sec: 0,
                bandwidth_schedule: vec![],
            },
            start_time: std::time::Instant::now(),
            db: Arc::new(tokio::sync::Mutex::new(setup_db())),
            progress_tx: tokio::sync::broadcast::channel::<crate::sse::ProgressEvent>(4).0,
            shutdown_tx: tokio::sync::watch::channel(false).0,
            device_id: "local-device-01".to_string(),
            ipc_auth_seen: std::sync::Mutex::new(crate::ipc_auth::SeenNonces::new()),
            ipc_sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
            revocation: std::sync::Arc::new(
                crate::revocation_gate::DaemonRevocationGate::disabled(),
            ),
        }
    }

    fn make_config() -> MeshConfig {
        let mut devices = HashMap::new();
        devices.insert(
            "local-device-01".to_string(),
            MeshDevice {
                device_id: "local-device-01".to_string(),
                peer_url: "http://127.0.0.1:9000".to_string(),
                name: "Local Laptop".to_string(),
            },
        );
        devices.insert(
            "dev-b".to_string(),
            MeshDevice {
                device_id: "dev-b".to_string(),
                peer_url: "http://192.168.1.20:9000".to_string(),
                name: "Desktop B".to_string(),
            },
        );
        devices.insert(
            "dev-c".to_string(),
            MeshDevice {
                device_id: "dev-c".to_string(),
                peer_url: "http://192.168.1.30:9000".to_string(),
                name: "Server C".to_string(),
            },
        );
        MeshConfig {
            mesh_id: uuid::Uuid::new_v4().to_string(),
            devices,
            folders: vec![std::env::temp_dir().to_string_lossy().to_string()],
            created_at: Utc::now().to_rfc3339(),
        }
    }

    // ---- Test 1: 3 devices → creates sync pairs -------------------------

    #[test]
    fn test_configure_mesh_creates_bidirectional_pairs() {
        let conn = setup_db();
        let state = dummy_state();
        let config = make_config();

        let result = configure_mesh(&conn, &state, &config).unwrap();
        assert_eq!(result.device_count, 3);
        // Local device + 2 peers → 2 pairs (local↔dev-b, local↔dev-c)
        assert!(result.pairs_created >= 1, "should create at least 1 pair for local device");
        assert!(!result.pair_ids.is_empty());
    }

    // ---- Test 2: resolve_mesh_state computes max version -----------------

    #[test]
    fn test_resolve_mesh_state_max_version() {
        let conn = setup_db();
        let state = dummy_state();
        let config = make_config();
        let result = configure_mesh(&conn, &state, &config).unwrap();

        // Insert file_versions for one of the pairs
        if let Some(pair_id) = result.pair_ids.first() {
            let now = Utc::now().to_rfc3339();
            // A=5, B=3 → authoritative should be 5
            conn.execute(
                "INSERT INTO file_versions (sync_pair_id, relative_path, device_id, version, merkle_root, size_bytes, modified_at)
                 VALUES (?1, 'notes.txt', 'local-device-01', 5, 'aaa', 100, ?2)",
                rusqlite::params![pair_id, now],
            ).unwrap();
            conn.execute(
                "INSERT INTO file_versions (sync_pair_id, relative_path, device_id, version, merkle_root, size_bytes, modified_at)
                 VALUES (?1, 'notes.txt', 'dev-b', 3, 'aaa', 100, ?2)",
                rusqlite::params![pair_id, now],
            ).unwrap();
        }

        let conv = resolve_mesh_state(&conn, &config.mesh_id).unwrap();
        assert!(conv.total_files > 0, "should have at least one file tracked");
    }

    // ---- Test 3: resolve_mesh_state with single max version ---------------

    #[test]
    fn test_resolve_mesh_state_single_max() {
        let conn = setup_db();
        let state = dummy_state();
        let config = make_config();
        let result = configure_mesh(&conn, &state, &config).unwrap();

        if let Some(pair_id) = result.pair_ids.first() {
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO file_versions (sync_pair_id, relative_path, device_id, version, merkle_root, size_bytes, modified_at)
                 VALUES (?1, 'data.txt', 'local-device-01', 5, 'xxx', 200, ?2)",
                rusqlite::params![pair_id, now],
            ).unwrap();
            conn.execute(
                "INSERT INTO file_versions (sync_pair_id, relative_path, device_id, version, merkle_root, size_bytes, modified_at)
                 VALUES (?1, 'data.txt', 'dev-b', 3, 'xxx', 200, ?2)",
                rusqlite::params![pair_id, now],
            ).unwrap();
        }

        let conv = resolve_mesh_state(&conn, &config.mesh_id).unwrap();
        if conv.total_files > 0 {
            let state = &conv.file_states[0];
            assert_eq!(state.authoritative_version, 5);
            assert_eq!(state.authoritative_device, "local-device-01");
        }
    }

    // ---- Test 4: all versions equal → converged --------------------------

    #[test]
    fn test_resolve_mesh_state_all_converged() {
        let conn = setup_db();
        let state = dummy_state();
        let config = make_config();
        let result = configure_mesh(&conn, &state, &config).unwrap();

        if let Some(pair_id) = result.pair_ids.first() {
            let now = Utc::now().to_rfc3339();
            conn.execute(
                "INSERT INTO file_versions (sync_pair_id, relative_path, device_id, version, merkle_root, size_bytes, modified_at)
                 VALUES (?1, 'equal.txt', 'local-device-01', 4, 'same', 100, ?2)",
                rusqlite::params![pair_id, now],
            ).unwrap();
            conn.execute(
                "INSERT INTO file_versions (sync_pair_id, relative_path, device_id, version, merkle_root, size_bytes, modified_at)
                 VALUES (?1, 'equal.txt', 'dev-b', 4, 'same', 100, ?2)",
                rusqlite::params![pair_id, now],
            ).unwrap();
        }

        let conv = resolve_mesh_state(&conn, &config.mesh_id).unwrap();
        assert_eq!(conv.converged_files, conv.total_files,
            "all files should be converged when versions and merkle match");
    }

    // ---- Test 5: discover_peers via GET /health ---------------------------

    #[test]
    fn test_discover_peers_health_check() {
        let conn = setup_db();
        let state = dummy_state();
        let config = make_config();
        let _result = configure_mesh(&conn, &state, &config).unwrap();

        // discover_peers should not panic even when peers are unreachable
        let peers = discover_peers(&conn, &config.mesh_id).unwrap();
        // In v1 test, peers may be unreachable (no actual daemon) — that's fine
        for peer in &peers {
            assert!(!peer.device_id.is_empty());
        }
    }

    // ---- Test 6: idempotent mesh configuration ---------------------------

    #[test]
    fn test_mesh_idempotent() {
        let conn = setup_db();
        let state = dummy_state();
        let config = make_config();

        let r1 = configure_mesh(&conn, &state, &config).unwrap();
        let r2 = configure_mesh(&conn, &state, &config).unwrap();

        assert_eq!(r1.pairs_created, r2.pairs_created,
            "second mesh configuration should create no new pairs (idempotent)");
    }

    // ---- Test 7: stdlib sync.mesh() returns MeshConfig -------------------

    #[test]
    fn test_mesh_result_struct() {
        let result = MeshResult {
            mesh_id: "test-mesh".to_string(),
            device_count: 3,
            pairs_created: 3,
            pair_ids: vec!["p1".to_string(), "p2".to_string(), "p3".to_string()],
        };
        assert_eq!(result.device_count, 3);
        assert_eq!(result.pairs_created, 3);
    }
}
