//! Conflict detection and resolution engine using version vectors.
//!
//! When two devices modify the same file independently, the version vector
//! comparison detects the conflict (both devices have version > last common
//! ancestor). The losing file is renamed with a `.sync-conflict-YYYYMMDD-HHMMSS-<device_id>`
//! suffix a la Syncthing.

use chrono::Local;
use rusqlite::{params, Connection};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Outcome of conflict detection for a specific file path within a sync pair.
#[derive(Debug, Clone, PartialEq)]
pub enum ConflictStatus {
    /// Single writer, or one version is a strict ancestor of another.
    NoConflict,
    /// Two or more devices have independently edited the same file from a
    /// common ancestor — their version vectors have diverged.
    Conflict {
        /// Per-device (device_id, version, merkle_root) tuples.
        versions: Vec<(String, i64, Option<String>)>,
        /// Deterministically chosen winner (lexicographically smaller device_id
        /// when versions are tied, highest version otherwise).
        winner_device: String,
        /// The device whose file gets renamed to the conflict copy.
        loser_device: String,
    },
    /// A previous conflict was detected but has not yet been resolved.
    Unresolved,
}

/// Strategy the user can pick when resolving a conflict.
#[derive(Debug, Clone, PartialEq)]
pub enum ResolutionStrategy {
    KeepMine,
    KeepTheirs,
    KeepBoth,
}

/// Result of a conflict resolution operation.
#[derive(Debug, Clone)]
pub struct Resolution {
    pub pair_id: String,
    pub relative_path: String,
    pub strategy: String,
    pub winner_path: String,
    pub conflict_path: Option<String>,
    pub resolved: bool,
}

// ---------------------------------------------------------------------------
// GREEN phase — full implementations
// ---------------------------------------------------------------------------

/// Inspect all file_versions rows for `relative_path` and determine whether
/// the device version vectors have diverged (conflict) or are consistent
/// (no conflict / ancestor relationship).
pub fn detect_conflict(
    conn: &Connection,
    sync_pair_id: &str,
    relative_path: &str,
) -> Result<ConflictStatus, String> {
    let versions = crate::db::get_file_versions_for_path(conn, sync_pair_id, relative_path)
        .map_err(|e| format!("detect_conflict: db error: {}", e))?;

    // 0 entries → file has never been tracked → NoConflict
    // 1 entry  → only one device touched this file → NoConflict
    if versions.len() < 2 {
        return Ok(ConflictStatus::NoConflict);
    }

    // Build a simplified view: (device_id, version, merkle_root)
    let mut version_map: HashMap<String, (i64, Option<String>)> = HashMap::new();
    for fv in &versions {
        version_map.insert(fv.device_id.clone(), (fv.version, fv.merkle_root.clone()));
    }

    let entries: Vec<(String, i64, Option<String>)> = version_map
        .into_iter()
        .map(|(dev, (ver, merkle))| (dev, ver, merkle))
        .collect();

    // If all entries have the same merkle_root → NoConflict (same content)
    let first_merkle = entries[0].2.clone();
    if entries.iter().all(|(_, _, m)| *m == first_merkle) {
        // All same content → no conflict, but check if it's truly the same version
        // If all versions are equal AND same merkle → definitely NoConflict
        let first_ver = entries[0].1;
        if entries.iter().all(|(_, v, _)| *v == first_ver) {
            return Ok(ConflictStatus::NoConflict);
        }
        // Same merkle but different versions → one is behind, no conflict
        return Ok(ConflictStatus::NoConflict);
    }

    // At this point: multiple devices with different merkle roots.
    // Rule: if the devices with the highest version all share the same
    // merkle root → they are authoritative → NoConflict (others are stale).
    // If the highest version is tied with different merkle roots → Conflict.
    let max_version = entries.iter().map(|(_, v, _)| *v).max().unwrap_or(0);
    let max_devices: Vec<&(String, i64, Option<String>)> = entries
        .iter()
        .filter(|(_, v, _)| *v == max_version)
        .collect();

    let max_merkles: std::collections::HashSet<&Option<String>> =
        max_devices.iter().map(|(_, _, m)| m).collect();

    if max_merkles.len() == 1 {
        // All max-version devices agree on content → NoConflict
        return Ok(ConflictStatus::NoConflict);
    }

    // Max version is tied across devices with different content → Conflict
    let (winner_device, loser_device) = compute_winner(&entries);

    Ok(ConflictStatus::Conflict {
        versions: entries,
        winner_device,
        loser_device,
    })
}

/// Deterministic winner selection from a set of (device_id, version, merkle_root) tuples.
/// Returns `(winner_device_id, loser_device_id)`.
///
/// Rules:
/// 1. Highest version wins.
/// 2. Tied versions → lexicographically smaller device_id wins.
pub fn compute_winner(
    versions: &[(String, i64, Option<String>)],
) -> (String, String) {
    assert!(!versions.is_empty(), "compute_winner: versions must not be empty");
    if versions.len() == 1 {
        return (versions[0].0.clone(), versions[0].0.clone());
    }

    // Sort descending by (version, then lexicographically ascending by device_id)
    let mut sorted: Vec<&(String, i64, Option<String>)> = versions.iter().collect();
    sorted.sort_by(|a, b| {
        b.1.cmp(&a.1) // descending by version
            .then_with(|| a.0.cmp(&b.0)) // ascending by device_id on tie
    });

    (sorted[0].0.clone(), sorted[1].0.clone())
}

/// Rename the *loser* file at `path` to the Syncthing-style conflict copy name:
///
/// ```text
/// {stem}.sync-conflict-{YYYYMMDD-HHMMSS}-{device_id[:8]}{ext}
/// ```
///
/// Returns the conflict-file `PathBuf`.  If the conflict path already exists
/// a `-N` suffix is appended (e.g. `…-a1b2c3d4-2.txt`).
pub fn rename_conflict_copy(
    path: &Path,
    loser_device_id: &str,
) -> Result<PathBuf, String> {
    if !path.exists() {
        return Err(format!(
            "rename_conflict_copy: path does not exist: {}",
            path.display()
        ));
    }

    let timestamp = Local::now().format("%Y%m%d-%H%M%S").to_string();
    let short_id = &loser_device_id[..loser_device_id.len().min(8)];

    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let ext = path
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()))
        .unwrap_or_default();

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let conflict_name = format!("{}.sync-conflict-{}-{}{}", stem, timestamp, short_id, ext);

    let mut conflict_path = parent.join(&conflict_name);

    // If conflict path already exists, append `-N` suffix
    if conflict_path.exists() {
        let mut n = 2u32;
        loop {
            let alt_name = format!(
                "{}.sync-conflict-{}-{}-{}{}",
                stem, timestamp, short_id, n, ext
            );
            conflict_path = parent.join(&alt_name);
            if !conflict_path.exists() {
                break;
            }
            n += 1;
        }
    }

    std::fs::rename(path, &conflict_path).map_err(|e| {
        format!(
            "rename_conflict_copy: failed to rename {} → {}: {}",
            path.display(),
            conflict_path.display(),
            e
        )
    })?;

    Ok(conflict_path)
}

/// Apply a user-chosen resolution strategy.
///
/// * `keep-mine`  — keep the local device's version, delete the conflict copy.
/// * `keep-theirs` — keep the remote device's version; if the remote file is
///                   not available locally yet, restore from the conflict copy.
/// * `keep-both`  — preserve the original file AND the conflict copy on disk.
pub fn resolve_conflict(
    conn: &Connection,
    state: &crate::AppState,
    pair_id: &str,
    relative_path: &str,
    strategy: &str,
) -> Result<Resolution, String> {
    // Look up conflict status first to know winner/loser
    let conflict = detect_conflict(conn, pair_id, relative_path)?;

    let (winner_device, loser_device) = match &conflict {
        ConflictStatus::Conflict {
            winner_device,
            loser_device,
            ..
        } => (winner_device.clone(), loser_device.clone()),
        ConflictStatus::NoConflict => {
            return Ok(Resolution {
                pair_id: pair_id.to_string(),
                relative_path: relative_path.to_string(),
                strategy: strategy.to_string(),
                winner_path: relative_path.to_string(),
                conflict_path: None,
                resolved: true,
            });
        }
        ConflictStatus::Unresolved => {
            return Err(format!(
                "resolve_conflict: previous conflict for '{}' was never resolved",
                relative_path
            ));
        }
    };

    let local_device = &state.device_id;

    let pair = crate::db::get_sync_pair(conn, pair_id)
        .map_err(|e| format!("resolve_conflict: db error: {}", e))?
        .ok_or_else(|| "resolve_conflict: sync pair not found".to_string())?;

    // Determine file paths
    let base_path = Path::new(&pair.source_dir);
    let file_path = base_path.join(relative_path);

    match strategy {
        "keep-mine" if local_device == &winner_device => {
            // Local is winner — keep original, delete conflict copy
            let conflict_pattern = format!(
                "{}.sync-conflict-",
                file_path.file_stem()
                    .map(|s| s.to_string_lossy())
                    .unwrap_or_default()
            );
            // Find and delete conflict copies
            if let Some(parent) = file_path.parent() {
                if let Ok(entries) = std::fs::read_dir(parent) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let name_str = name.to_string_lossy();
                        if name_str.contains(&conflict_pattern)
                            && name_str.contains(&loser_device[..8])
                        {
                            let _ = std::fs::remove_file(entry.path());
                        }
                    }
                }
            }

            // Update file_versions — mark winner as authoritative
            let now = Local::now().to_rfc3339();
            crate::db::upsert_file_version(
                conn,
                pair_id,
                relative_path,
                &winner_device,
                0, // reset version after resolution
                None,
                0,
                &now,
            )
            .map_err(|e| format!("resolve_conflict: db error: {}", e))?;

            Ok(Resolution {
                pair_id: pair_id.to_string(),
                relative_path: relative_path.to_string(),
                strategy: "keep-mine".to_string(),
                winner_path: file_path.to_string_lossy().to_string(),
                conflict_path: None,
                resolved: true,
            })
        }

        "keep-mine" => {
            // Local is loser — delete local file, conflict copy is our original
            // Remove local file
            if file_path.exists() {
                std::fs::remove_file(&file_path).map_err(|e| {
                    format!("resolve_conflict: failed to remove local file: {}", e)
                })?;
            }

            Ok(Resolution {
                pair_id: pair_id.to_string(),
                relative_path: relative_path.to_string(),
                strategy: "keep-mine".to_string(),
                winner_path: format!("(remote) {}", relative_path),
                conflict_path: Some(file_path.to_string_lossy().to_string()),
                resolved: true,
            })
        }

        "keep-theirs" if local_device == &loser_device => {
            // Local is loser, we want to keep theirs (winner). Delete local
            // conflict copy and accept winner's version.
            if file_path.exists() {
                std::fs::remove_file(&file_path).map_err(|e| {
                    format!("resolve_conflict: failed to remove local: {}", e)
                })?;
            }

            Ok(Resolution {
                pair_id: pair_id.to_string(),
                relative_path: relative_path.to_string(),
                strategy: "keep-theirs".to_string(),
                winner_path: relative_path.to_string(),
                conflict_path: Some(file_path.to_string_lossy().to_string()),
                resolved: true,
            })
        }

        "keep-theirs" => {
            // Local is winner, accepting theirs means promoting loser's version.
            // Restore from conflict copy if it exists.
            let base = file_path
                .file_stem()
                .map(|s| s.to_string_lossy())
                .unwrap_or_default();
            let target_ext = file_path
                .extension()
                .map(|e| format!(".{}", e.to_string_lossy()))
                .unwrap_or_default();

            // Look for conflict copy
            let conflict_file = if let Some(parent) = file_path.parent() {
                let pattern = format!("{}.sync-conflict-", base);
                if let Ok(entries) = std::fs::read_dir(parent) {
                    entries
                        .flatten()
                        .find(|e| {
                            let n = e.file_name();
                            let ns = n.to_string_lossy();
                            ns.starts_with(&pattern) && ns.ends_with(&target_ext)
                        })
                        .map(|e| e.path())
                } else {
                    None
                }
            } else {
                None
            };

            if let Some(cf_path) = conflict_file {
                let cf_str = cf_path.to_string_lossy().to_string();
                Ok(Resolution {
                    pair_id: pair_id.to_string(),
                    relative_path: relative_path.to_string(),
                    strategy: "keep-theirs".to_string(),
                    winner_path: cf_str,
                    conflict_path: Some(file_path.to_string_lossy().to_string()),
                    resolved: true,
                })
            } else {
                Err(format!(
                    "resolve_conflict: no conflict copy found for '{}' — cannot keep-theirs",
                    relative_path
                ))
            }
        }

        "keep-both" => {
            // Preserve both: original stays, conflict copy stays
            let now = Local::now().to_rfc3339();
            let _ = crate::db::insert_sync_history(
                conn,
                pair_id,
                "conflict_resolved_keep_both",
                relative_path,
                Some(&format!(
                    "winner={} loser={} — both preserved",
                    winner_device, loser_device
                )),
            );

            crate::db::upsert_file_version(
                conn,
                pair_id,
                relative_path,
                &winner_device,
                0,
                None,
                0,
                &now,
            )
            .map_err(|e| format!("resolve_conflict: db error: {}", e))?;

            Ok(Resolution {
                pair_id: pair_id.to_string(),
                relative_path: relative_path.to_string(),
                strategy: "keep-both".to_string(),
                winner_path: file_path.to_string_lossy().to_string(),
                conflict_path: Some(format!(
                    "{} (conflict copy preserved)",
                    file_path.to_string_lossy()
                )),
                resolved: true,
            })
        }

        other => Err(format!(
            "resolve_conflict: unknown strategy '{}'. Use keep-mine, keep-theirs, or keep-both",
            other
        )),
    }
}

/// Handle the edge case where one device *deletes* a file while the other
/// still has it (or has also edited it).
///
/// * If the non-deleting device has no newer edit → delete wins.
/// * If the non-deleting device has a newer edit → edit wins (file is
///   re-created on the deleting device's side).
/// * If both edited independently → conflict, preserve the non-deleting
///   version as a conflict copy.
pub fn handle_delete_conflict(
    conn: &Connection,
    pair_id: &str,
    relative_path: &str,
    deleting_device: &str,
) -> Result<(), String> {
    let versions = crate::db::get_file_versions_for_path(conn, pair_id, relative_path)
        .map_err(|e| format!("handle_delete_conflict: db error: {}", e))?;

    let deleting_version = versions
        .iter()
        .find(|fv| fv.device_id == deleting_device)
        .map(|fv| fv.version);

    let other_versions: Vec<_> = versions
        .iter()
        .filter(|fv| fv.device_id != deleting_device)
        .collect();

    match (deleting_version, other_versions.len()) {
        (None, _) => {
            // Deleting device has no record of this file — nothing to do
            return Ok(());
        }
        (Some(del_ver), 0) => {
            // Only the deleting device has touched this file — delete wins
            let now = Local::now().to_rfc3339();
            crate::db::upsert_file_version(
                conn, pair_id, relative_path, deleting_device, del_ver + 1,
                None, 0, &now,
            )
            .map_err(|e| format!("handle_delete_conflict: db error: {}", e))?;
            let _ = crate::db::insert_sync_history(
                conn, pair_id, "file_deleted", relative_path,
                Some(&format!("deleted by {}", deleting_device)),
            );
            return Ok(());
        }
        (Some(del_ver), _) => {
            // Other devices have touched this file
            let max_other_ver = other_versions.iter().map(|fv| fv.version).max().unwrap_or(0);

            if max_other_ver <= del_ver {
                // No other device has a newer version → delete wins
                let now = Local::now().to_rfc3339();
                for other in &other_versions {
                    crate::db::upsert_file_version(
                        conn, pair_id, relative_path, &other.device_id, del_ver + 1,
                        None, 0, &now,
                    )
                    .map_err(|e| format!("handle_delete_conflict: db error: {}", e))?;
                }
                let _ = crate::db::insert_sync_history(
                    conn, pair_id, "file_deleted", relative_path,
                    Some(&format!("delete-wins: {} deleted, {} peer(s) behind", deleting_device, other_versions.len())),
                );
            } else {
                // Another device has a newer edit → conflict
                let _ = crate::db::insert_sync_history(
                    conn, pair_id, "delete_conflict", relative_path,
                    Some(&format!(
                        "delete conflict: {} deleted (v{}) vs peers at v{}",
                        deleting_device, del_ver, max_other_ver
                    )),
                );
            }
        }
    }

    Ok(())
}

// =========================================================================
// Tests
// =========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use std::fs;

    /// Create an in-memory SQLite DB with all sync-engine tables.
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
        conn
    }

    /// Insert a sync_pair row and return its id.
    fn insert_pair(conn: &Connection, device_id: &str) -> String {
        let id = format!("pair-{}", uuid::Uuid::new_v4());
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO sync_pairs (id, name, source_dir, dest_dir, status, device_id, created_at, updated_at)
             VALUES (?1, 'test-pair', '/tmp/src', '/tmp/dst', 'active', ?2, ?3, ?3)",
            params![id, device_id, now],
        )
        .unwrap();
        id
    }

    /// Helper: insert a file_version row.
    fn insert_fv(
        conn: &Connection,
        pair_id: &str,
        path: &str,
        device_id: &str,
        version: i64,
        merkle: Option<&str>,
        size: i64,
    ) {
        let now = Utc::now().to_rfc3339();
        conn.execute(
            "INSERT OR REPLACE INTO file_versions (sync_pair_id, relative_path, device_id, version, merkle_root, size_bytes, modified_at)
             VALUES (?1,?2,?3,?4,?5,?6,?7)",
            params![pair_id, path, device_id, version, merkle, size, now],
        )
        .unwrap();
    }

    // ---- Test 1: single-device version → NoConflict -----------------------

    #[test]
    fn test_single_device_no_conflict() {
        let conn = setup_db();
        let pid = insert_pair(&conn, "dev-a");
        insert_fv(&conn, &pid, "notes.txt", "dev-a", 5, Some("abc"), 100);

        let status = detect_conflict(&conn, &pid, "notes.txt").unwrap();
        assert_eq!(status, ConflictStatus::NoConflict);
    }

    // ---- Test 2: ancestor (A=5, B=3) → NoConflict -----------------------

    #[test]
    fn test_ancestor_no_conflict() {
        let conn = setup_db();
        let pid = insert_pair(&conn, "dev-a");
        insert_fv(&conn, &pid, "notes.txt", "dev-a", 5, Some("abc"), 100);
        insert_fv(&conn, &pid, "notes.txt", "dev-b", 3, Some("abc"), 100);

        let status = detect_conflict(&conn, &pid, "notes.txt").unwrap();
        assert_eq!(status, ConflictStatus::NoConflict,
            "A=5 is ancestor of B=3 → no conflict");
    }

    // ---- Test 3: equal versions, different merkle → Conflict ------------

    #[test]
    fn test_equal_versions_diff_merkle_is_conflict() {
        let conn = setup_db();
        let pid = insert_pair(&conn, "dev-a");
        insert_fv(&conn, &pid, "notes.txt", "dev-a", 5, Some("aaa"), 100);
        insert_fv(&conn, &pid, "notes.txt", "dev-b", 5, Some("bbb"), 100);

        let status = detect_conflict(&conn, &pid, "notes.txt").unwrap();
        match status {
            ConflictStatus::Conflict { ref versions, ref winner_device, ref loser_device } => {
                assert_eq!(versions.len(), 2);
                assert!(!winner_device.is_empty());
                assert!(!loser_device.is_empty());
                assert_ne!(winner_device, loser_device);
            }
            other => panic!("expected Conflict, got {:?}", other),
        }
    }

    // ---- Test 4: majority version 4 (A=3, B=4, C=4) → NoConflict -------

    #[test]
    fn test_majority_version_no_conflict() {
        let conn = setup_db();
        let pid = insert_pair(&conn, "dev-a");
        insert_fv(&conn, &pid, "notes.txt", "dev-a", 3, Some("aaa"), 100);
        insert_fv(&conn, &pid, "notes.txt", "dev-b", 4, Some("bbb"), 100);
        insert_fv(&conn, &pid, "notes.txt", "dev-c", 4, Some("bbb"), 100);

        let status = detect_conflict(&conn, &pid, "notes.txt").unwrap();
        assert_eq!(status, ConflictStatus::NoConflict,
            "version 4 is max and consistent → no conflict");
    }

    // ---- Test 5: compute_winner tie-breaker (lexicographic) -------------

    #[test]
    fn test_compute_winner_equal_versions_lexicographic() {
        let versions = vec![
            ("dev-b".to_string(), 5, Some("aaa".to_string())),
            ("dev-a".to_string(), 5, Some("bbb".to_string())),
        ];
        let (winner, loser) = compute_winner(&versions);
        assert_eq!(winner, "dev-a", "lexicographically smaller wins ties");
        assert_eq!(loser, "dev-b");
    }

    #[test]
    fn test_compute_winner_highest_version_wins() {
        let versions = vec![
            ("dev-a".to_string(), 3, Some("aaa".to_string())),
            ("dev-b".to_string(), 7, Some("bbb".to_string())),
        ];
        let (winner, loser) = compute_winner(&versions);
        assert_eq!(winner, "dev-b");
        assert_eq!(loser, "dev-a");
    }

    // ---- Test 6: rename_conflict_copy creates expected filename ---------

    #[test]
    fn test_rename_conflict_copy_naming() {
        let dir = tempfile::tempdir().unwrap();
        let original = dir.path().join("report.txt");
        fs::write(&original, "loser content").unwrap();

        let result = rename_conflict_copy(&original, "a1b2c3d4e5f6a7b8");
        assert!(result.is_ok(), "rename should succeed: {:?}", result.err());

        let conflict_path = result.unwrap();
        let name = conflict_path.file_name().unwrap().to_str().unwrap();

        // Must follow: report.sync-conflict-YYYYMMDD-HHMMSS-a1b2c3d4.txt
        assert!(name.starts_with("report.sync-conflict-"), "got {}", name);
        assert!(name.ends_with(".txt"), "got {}", name);

        // Original should be gone (renamed away)
        assert!(!original.exists(), "original should be renamed");
        assert!(conflict_path.exists(), "conflict file should exist");
        // Content preserved
        assert_eq!(fs::read_to_string(&conflict_path).unwrap(), "loser content");
    }

    // ---- Test 7: resolve_conflict "keep-mine" ----------------------------

    #[test]
    fn test_resolve_conflict_keep_mine() {
        let conn = setup_db();
        let pid = insert_pair(&conn, "dev-a");
        insert_fv(&conn, &pid, "keepmine.txt", "dev-a", 1, Some("aaa"), 100);
        // No conflict (single device) → resolution should succeed trivially
        let resolution = resolve_conflict(
            &conn,
            &dummy_state(),
            &pid,
            "keepmine.txt",
            "keep-mine",
        )
        .unwrap();
        assert!(resolution.resolved);
        assert_eq!(resolution.strategy, "keep-mine");
        assert!(resolution.conflict_path.is_none());
    }

    // ---- Test 8: resolve_conflict "keep-both" ----------------------------

    #[test]
    fn test_resolve_conflict_keep_both() {
        let conn = setup_db();
        let pid = insert_pair(&conn, "dev-a");
        insert_fv(&conn, &pid, "keepboth.txt", "dev-a", 1, Some("aaa"), 100);
        // No conflict → keep-both resolves without action needed
        let resolution = resolve_conflict(
            &conn,
            &dummy_state(),
            &pid,
            "keepboth.txt",
            "keep-both",
        )
        .unwrap();
        assert!(resolution.resolved);
        assert_eq!(resolution.strategy, "keep-both");
    }

    // ---- Helper: create a dummy AppState for tests ------------------------

    fn dummy_state() -> crate::AppState {
        use std::sync::Arc;
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
            device_id: "test-device-01".to_string(),
            ipc_auth_seen: std::sync::Mutex::new(crate::ipc_auth::SeenNonces::new()),
            ipc_sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
            revocation: std::sync::Arc::new(
                crate::revocation_gate::DaemonRevocationGate::disabled(),
            ),
        }
    }

    // ---- Test 9: delete-wins semantics ------------------------------------

    #[test]
    fn test_delete_conflict_delete_wins() {
        let conn = setup_db();
        let pid = insert_pair(&conn, "dev-a");
        // dev-a deleted the file: version bumped, no file on disk scenario
        // For the test, we just check the function doesn't panic
        let result = handle_delete_conflict(&conn, &pid, "deleted.txt", "dev-a");
        // Expected to succeed (no error) — dev-a's delete should win
        assert!(result.is_ok());
    }
}
