use rusqlite::{params, Connection, Result as SqliteResult};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Open a SQLite connection with WAL mode and migrations applied.
///
/// Owner-only state (R-P9 / T-112): the DB carries job/session data, so a
/// pre-existing loose file is tightened before WAL sidecars are created
/// (SQLite derives their mode from the main file), and again after
/// migrations to catch the first WAL write. Best-effort — a permissions
/// hiccup never blocks the daemon; the doctor probe reports the live state.
pub fn open(db_path: &std::path::Path) -> SqliteResult<Connection> {
    let conn = Connection::open(db_path)?;
    harden_state_file(db_path);

    // Enable WAL mode for concurrent reads during writes (SSE)
    conn.execute_batch("PRAGMA journal_mode=WAL;")?;
    // Enforce foreign key constraints
    conn.execute_batch("PRAGMA foreign_keys=ON;")?;
    // Retry for up to 5 seconds when locked (avoids busy errors)
    conn.execute_batch("PRAGMA busy_timeout=5000;")?;

    run_migrations(&conn)?;

    harden_state_file(db_path);
    for suffix in ["-wal", "-shm"] {
        let mut side = db_path.as_os_str().to_owned();
        side.push(suffix);
        harden_state_file(std::path::Path::new(&side));
    }

    Ok(conn)
}

/// Tighten a daemon DB file to 0600 when it has group/other bits
/// (R-P9 / T-112). Best-effort: a missing file is fine, failures are logged.
#[cfg(unix)]
fn harden_state_file(path: &std::path::Path) {
    use std::os::unix::fs::PermissionsExt;
    let Ok(md) = std::fs::metadata(path) else {
        return;
    };
    let mode = md.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        match std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)) {
            Ok(()) => tracing::warn!(
                path = ?path,
                mode = format!("{mode:o}"),
                "daemon db was not owner-only; tightened to 0600 (R-P9)"
            ),
            Err(e) => tracing::warn!(path = ?path, "failed to tighten daemon db: {e}"),
        }
    }
}

#[cfg(not(unix))]
fn harden_state_file(_path: &std::path::Path) {}

#[cfg(test)]
mod state_file_tests {
    /// R-P9 / T-112: a pre-existing loose DB file is tightened in place and
    /// the tighten is idempotent; a missing file is a no-op (best-effort).
    #[cfg(unix)]
    #[test]
    fn harden_state_file_tightens_loose_and_is_idempotent() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("tallow-db-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let p = dir.join("daemon.db");
        std::fs::write(&p, b"seed").expect("seed");
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o644)).expect("loosen");
        super::harden_state_file(&p);
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "loose state file must be tightened to 0600");
        super::harden_state_file(&p);
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        super::harden_state_file(&dir.join("does-not-exist"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Run schema migrations: create tables and indexes if they don't exist.
fn run_migrations(conn: &Connection) -> SqliteResult<()> {
    // Base schema: create tables if they don't exist yet
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS jobs (
            id TEXT PRIMARY KEY,
            name TEXT NOT NULL,
            status TEXT NOT NULL DEFAULT 'created',
            config_json TEXT NOT NULL,
            error_message TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS job_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
            event TEXT NOT NULL,
            detail TEXT,
            timestamp TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_job_history_job_id ON job_history(job_id);
        CREATE INDEX IF NOT EXISTS idx_jobs_status ON jobs(status);
        CREATE INDEX IF NOT EXISTS idx_jobs_created_at ON jobs(created_at);",
    )?;

    // Migration: add priority column (Phase 4 — priority queue)
    let cols: Vec<String> = {
        let mut stmt = conn.prepare("PRAGMA table_info(jobs)")?;
        stmt.query_map([], |row| row.get(1))?
            .filter_map(|r| r.ok())
            .collect()
    };
    if !cols.contains(&"priority".to_string()) {
        conn.execute("ALTER TABLE jobs ADD COLUMN priority INTEGER NOT NULL DEFAULT 0", [])?;
    }
    if !cols.contains(&"retry_count".to_string()) {
        conn.execute("ALTER TABLE jobs ADD COLUMN retry_count INTEGER NOT NULL DEFAULT 0", [])?;
    }
    if !cols.contains(&"max_retries".to_string()) {
        conn.execute("ALTER TABLE jobs ADD COLUMN max_retries INTEGER NOT NULL DEFAULT 3", [])?;
    }

    // Create transfer_resume table (stores checkpoint state for crash recovery)
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS transfer_resume (
            job_id TEXT PRIMARY KEY REFERENCES jobs(id) ON DELETE CASCADE,
            byte_offset INTEGER NOT NULL DEFAULT 0,
            file_path TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL
        );",
    )?;

    // Phase 7 — Sync engine schema
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

        CREATE INDEX IF NOT EXISTS idx_sync_pairs_status ON sync_pairs(status);
        CREATE INDEX IF NOT EXISTS idx_sync_pairs_device_id ON sync_pairs(device_id);

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

        CREATE INDEX IF NOT EXISTS idx_file_versions_pair_path ON file_versions(sync_pair_id, relative_path);

        CREATE TABLE IF NOT EXISTS sync_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sync_pair_id TEXT NOT NULL REFERENCES sync_pairs(id) ON DELETE CASCADE,
            event TEXT NOT NULL,
            relative_path TEXT NOT NULL,
            detail TEXT,
            created_at TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sync_history_pair_created ON sync_history(sync_pair_id, created_at);",
    )?;

    Ok(())
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SyncPair {
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct DeviceState {
    pub device_id: String,
    pub sync_pair_id: String,
    pub version: i64,
    pub last_seen_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct FileVersion {
    pub sync_pair_id: String,
    pub relative_path: String,
    pub device_id: String,
    pub version: i64,
    pub merkle_root: Option<String>,
    pub size_bytes: i64,
    pub modified_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SyncHistory {
    pub id: i64,
    pub sync_pair_id: String,
    pub event: String,
    pub relative_path: String,
    pub detail: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Job {
    pub id: String,
    pub name: String,
    pub status: String,
    pub config_json: String,
    pub error_message: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JobHistoryEntry {
    pub id: i64,
    pub job_id: String,
    pub event: String,
    pub detail: Option<String>,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// DAO functions
// ---------------------------------------------------------------------------

/// Create a new job. Returns the created Job.
pub fn create_job(conn: &Connection, name: &str, config_json: &str) -> SqliteResult<Job> {
    let id = Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO jobs (id, name, status, config_json, created_at, updated_at) VALUES (?1, ?2, 'created', ?3, ?4, ?4)",
        params![id, name, config_json, now],
    )?;

    // Insert initial history event
    conn.execute(
        "INSERT INTO job_history (job_id, event, timestamp) VALUES (?1, 'created', ?2)",
        params![id, now],
    )?;

    Ok(Job {
        id,
        name: name.to_string(),
        status: "created".to_string(),
        config_json: config_json.to_string(),
        error_message: None,
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Get a single job by ID.
pub fn get_job(conn: &Connection, id: &str) -> SqliteResult<Option<Job>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, status, config_json, error_message, created_at, updated_at FROM jobs WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(params![id], |row| {
        Ok(Job {
            id: row.get(0)?,
            name: row.get(1)?,
            status: row.get(2)?,
            config_json: row.get(3)?,
            error_message: row.get(4)?,
            created_at: row.get(5)?,
            updated_at: row.get(6)?,
        })
    })?;
    match rows.next() {
        Some(Ok(job)) => Ok(Some(job)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// List all jobs, newest first. Optional status filter.
pub fn list_jobs(conn: &Connection, status_filter: Option<&str>) -> SqliteResult<Vec<Job>> {
    let jobs = if let Some(status) = status_filter {
        let mut stmt = conn.prepare(
            "SELECT id, name, status, config_json, error_message, created_at, updated_at FROM jobs WHERE status = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![status], |row| {
            Ok(Job {
                id: row.get(0)?,
                name: row.get(1)?,
                status: row.get(2)?,
                config_json: row.get(3)?,
                error_message: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })?;
        let mut vec = Vec::new();
        for row in rows {
            vec.push(row?);
        }
        vec
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, name, status, config_json, error_message, created_at, updated_at FROM jobs ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(Job {
                id: row.get(0)?,
                name: row.get(1)?,
                status: row.get(2)?,
                config_json: row.get(3)?,
                error_message: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })?;
        let mut vec = Vec::new();
        for row in rows {
            vec.push(row?);
        }
        vec
    };
    Ok(jobs)
}

/// Update job status. Also inserts a history entry.
pub fn update_job_status(
    conn: &Connection,
    id: &str,
    new_status: &str,
    detail: Option<&str>,
) -> SqliteResult<()> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE jobs SET status = ?1, updated_at = ?2 WHERE id = ?3",
        params![new_status, now, id],
    )?;
    conn.execute(
        "INSERT INTO job_history (job_id, event, detail, timestamp) VALUES (?1, ?2, ?3, ?4)",
        params![id, new_status, detail, now],
    )?;
    Ok(())
}

/// Get audit trail for a job, ordered from oldest to newest.
pub fn get_job_history(conn: &Connection, job_id: &str) -> SqliteResult<Vec<JobHistoryEntry>> {
    let mut stmt = conn.prepare(
        "SELECT id, job_id, event, detail, timestamp FROM job_history WHERE job_id = ?1 ORDER BY id ASC",
    )?;
    let rows = stmt.query_map(params![job_id], |row| {
        Ok(JobHistoryEntry {
            id: row.get(0)?,
            job_id: row.get(1)?,
            event: row.get(2)?,
            detail: row.get(3)?,
            timestamp: row.get(4)?,
        })
    })?;
    let mut vec = Vec::new();
    for row in rows {
        vec.push(row?);
    }
    Ok(vec)
}

// ---------------------------------------------------------------------------
// Phase 4 DAO: priority queue, transfer resume, retry tracking
// ---------------------------------------------------------------------------

/// Dequeue the highest-priority 'created' job (ties broken by oldest first),
/// atomically marking it 'running'. Returns None if no jobs are ready.
pub fn dequeue_by_priority(conn: &Connection) -> SqliteResult<Option<Job>> {
    // SELECT the highest-priority 'created' job
    let mut stmt = conn.prepare(
        "SELECT id, name, status, config_json, error_message, created_at, updated_at
         FROM jobs WHERE status = 'created'
         ORDER BY priority DESC, created_at ASC
         LIMIT 1",
    )?;

    let job_row: Option<Job> = {
        let mut rows = stmt.query_map([], |row| {
            Ok(Job {
                id: row.get(0)?,
                name: row.get(1)?,
                status: row.get(2)?,
                config_json: row.get(3)?,
                error_message: row.get(4)?,
                created_at: row.get(5)?,
                updated_at: row.get(6)?,
            })
        })?;
        match rows.next() {
            Some(Ok(job)) => Some(job),
            Some(Err(e)) => return Err(e),
            None => None,
        }
    };

    let job = match job_row {
        Some(j) => j,
        None => return Ok(None),
    };

    // Atomically mark as 'running'
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE jobs SET status = 'running', updated_at = ?1 WHERE id = ?2 AND status = 'created'",
        params![now, job.id],
    )?;

    // Insert history entry
    conn.execute(
        "INSERT INTO job_history (job_id, event, detail, timestamp) VALUES (?1, 'running', ?2, ?3)",
        params![job.id, Some("dequeued by priority"), now],
    )?;

    // Return the job with updated status
    Ok(Some(Job {
        status: "running".to_string(),
        updated_at: now,
        ..job
    }))
}

/// Save transfer checkpoint state (upsert).
pub fn save_transfer_state(
    conn: &Connection,
    job_id: &str,
    byte_offset: u64,
    file_path: &str,
) -> SqliteResult<()> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO transfer_resume (job_id, byte_offset, file_path, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(job_id) DO UPDATE SET byte_offset = ?2, file_path = ?3, updated_at = ?4",
        params![job_id, byte_offset as i64, file_path, now],
    )?;
    Ok(())
}

/// Retrieve transfer checkpoint state for a job. Returns (byte_offset, file_path).
pub fn get_transfer_state(conn: &Connection, job_id: &str) -> SqliteResult<Option<(u64, String)>> {
    let mut stmt = conn.prepare(
        "SELECT byte_offset, file_path FROM transfer_resume WHERE job_id = ?1",
    )?;
    let mut rows = stmt.query_map(params![job_id], |row| {
        Ok((row.get::<_, i64>(0)? as u64, row.get::<_, String>(1)?))
    })?;
    match rows.next() {
        Some(Ok(val)) => Ok(Some(val)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// Increment retry_count for a job, returning the new count.
pub fn increment_retry_count(conn: &Connection, job_id: &str) -> SqliteResult<u32> {
    conn.execute(
        "UPDATE jobs SET retry_count = retry_count + 1, updated_at = ?1 WHERE id = ?2",
        params![chrono::Utc::now().to_rfc3339(), job_id],
    )?;
    let new_count: i64 = conn.query_row(
        "SELECT retry_count FROM jobs WHERE id = ?1",
        params![job_id],
        |row| row.get(0),
    )?;
    Ok(new_count as u32)
}

// ---------------------------------------------------------------------------
// Phase 7 DAO: sync pairs, version vectors, file versions, audit trail
// ---------------------------------------------------------------------------

/// Create a new sync pair. Returns the created SyncPair.
pub fn create_sync_pair(
    conn: &Connection,
    name: &str,
    source_dir: &str,
    dest_dir: &str,
    device_id: &str,
    config_json: Option<&str>,
) -> SqliteResult<SyncPair> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO sync_pairs (id, name, source_dir, dest_dir, status, device_id, config_json, created_at, updated_at)
         VALUES (?1, ?2, ?3, ?4, 'active', ?5, ?6, ?7, ?7)",
        params![id, name, source_dir, dest_dir, device_id, config_json, now],
    )?;

    // Insert initial device state entry for local device with version 0
    conn.execute(
        "INSERT INTO device_states (device_id, sync_pair_id, version, last_seen_at) VALUES (?1, ?2, 0, ?3)",
        params![device_id, id, now],
    )?;

    Ok(SyncPair {
        id,
        name: name.to_string(),
        source_dir: source_dir.to_string(),
        dest_dir: dest_dir.to_string(),
        status: "active".to_string(),
        device_id: device_id.to_string(),
        config_json: config_json.map(|s| s.to_string()),
        created_at: now.clone(),
        updated_at: now,
    })
}

/// Get a single sync pair by ID.
pub fn get_sync_pair(conn: &Connection, id: &str) -> SqliteResult<Option<SyncPair>> {
    let mut stmt = conn.prepare(
        "SELECT id, name, source_dir, dest_dir, status, device_id, config_json, created_at, updated_at
         FROM sync_pairs WHERE id = ?1",
    )?;
    let mut rows = stmt.query_map(params![id], |row| {
        Ok(SyncPair {
            id: row.get(0)?,
            name: row.get(1)?,
            source_dir: row.get(2)?,
            dest_dir: row.get(3)?,
            status: row.get(4)?,
            device_id: row.get(5)?,
            config_json: row.get(6)?,
            created_at: row.get(7)?,
            updated_at: row.get(8)?,
        })
    })?;
    match rows.next() {
        Some(Ok(pair)) => Ok(Some(pair)),
        Some(Err(e)) => Err(e),
        None => Ok(None),
    }
}

/// List sync pairs, newest first. Optional status filter.
pub fn list_sync_pairs(
    conn: &Connection,
    status_filter: Option<&str>,
) -> SqliteResult<Vec<SyncPair>> {
    let pairs = if let Some(status) = status_filter {
        let mut stmt = conn.prepare(
            "SELECT id, name, source_dir, dest_dir, status, device_id, config_json, created_at, updated_at
             FROM sync_pairs WHERE status = ?1 ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map(params![status], |row| {
            Ok(SyncPair {
                id: row.get(0)?,
                name: row.get(1)?,
                source_dir: row.get(2)?,
                dest_dir: row.get(3)?,
                status: row.get(4)?,
                device_id: row.get(5)?,
                config_json: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        })?;
        let mut vec = Vec::new();
        for row in rows {
            vec.push(row?);
        }
        vec
    } else {
        let mut stmt = conn.prepare(
            "SELECT id, name, source_dir, dest_dir, status, device_id, config_json, created_at, updated_at
             FROM sync_pairs ORDER BY created_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(SyncPair {
                id: row.get(0)?,
                name: row.get(1)?,
                source_dir: row.get(2)?,
                dest_dir: row.get(3)?,
                status: row.get(4)?,
                device_id: row.get(5)?,
                config_json: row.get(6)?,
                created_at: row.get(7)?,
                updated_at: row.get(8)?,
            })
        })?;
        let mut vec = Vec::new();
        for row in rows {
            vec.push(row?);
        }
        vec
    };
    Ok(pairs)
}

/// Update sync pair status. Also inserts a sync_history entry.
pub fn update_sync_pair_status(
    conn: &Connection,
    id: &str,
    new_status: &str,
) -> SqliteResult<()> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "UPDATE sync_pairs SET status = ?1, updated_at = ?2 WHERE id = ?3",
        params![new_status, now, id],
    )?;
    conn.execute(
        "INSERT INTO sync_history (sync_pair_id, event, relative_path, detail, created_at)
         VALUES (?1, ?2, '', ?3, ?4)",
        params![id, new_status, Some(new_status), now],
    )?;
    Ok(())
}

/// Delete a sync pair and all related rows (CASCADE).
pub fn delete_sync_pair(conn: &Connection, id: &str) -> SqliteResult<()> {
    conn.execute("DELETE FROM sync_pairs WHERE id = ?1", params![id])?;
    Ok(())
}

/// Atomically increment the version counter for a device in a sync pair.
/// Uses UPDATE ... RETURNING for atomic read-then-write (no race condition).
/// Returns the new version value.
pub fn increment_device_version(
    conn: &Connection,
    device_id: &str,
    sync_pair_id: &str,
) -> SqliteResult<u64> {
    let now = chrono::Utc::now().to_rfc3339();
    let new_version: i64 = conn.query_row(
        "UPDATE device_states SET version = version + 1, last_seen_at = ?1
         WHERE device_id = ?2 AND sync_pair_id = ?3
         RETURNING version",
        params![now, device_id, sync_pair_id],
        |row| row.get(0),
    )?;
    Ok(new_version as u64)
}

/// Get all device version vectors for a sync pair.
pub fn get_device_versions(
    conn: &Connection,
    sync_pair_id: &str,
) -> SqliteResult<Vec<(String, i64)>> {
    let mut stmt = conn.prepare(
        "SELECT device_id, version FROM device_states WHERE sync_pair_id = ?1",
    )?;
    let rows = stmt.query_map(params![sync_pair_id], |row| {
        Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
    })?;
    let mut vec = Vec::new();
    for row in rows {
        vec.push(row?);
    }
    Ok(vec)
}

/// Insert or update a file version entry.
pub fn upsert_file_version(
    conn: &Connection,
    sync_pair_id: &str,
    relative_path: &str,
    device_id: &str,
    version: i64,
    merkle_root: Option<&str>,
    size_bytes: i64,
    modified_at: &str,
) -> SqliteResult<()> {
    conn.execute(
        "INSERT INTO file_versions (sync_pair_id, relative_path, device_id, version, merkle_root, size_bytes, modified_at)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
         ON CONFLICT(sync_pair_id, relative_path, device_id)
         DO UPDATE SET version = ?4, merkle_root = ?5, size_bytes = ?6, modified_at = ?7",
        params![sync_pair_id, relative_path, device_id, version, merkle_root, size_bytes, modified_at],
    )?;
    Ok(())
}

/// Get all file version entries for a sync pair.
pub fn get_file_versions_for_pair(
    conn: &Connection,
    sync_pair_id: &str,
) -> SqliteResult<Vec<FileVersion>> {
    let mut stmt = conn.prepare(
        "SELECT sync_pair_id, relative_path, device_id, version, merkle_root, size_bytes, modified_at
         FROM file_versions WHERE sync_pair_id = ?1 ORDER BY relative_path",
    )?;
    let rows = stmt.query_map(params![sync_pair_id], |row| {
        Ok(FileVersion {
            sync_pair_id: row.get(0)?,
            relative_path: row.get(1)?,
            device_id: row.get(2)?,
            version: row.get(3)?,
            merkle_root: row.get(4)?,
            size_bytes: row.get(5)?,
            modified_at: row.get(6)?,
        })
    })?;
    let mut vec = Vec::new();
    for row in rows {
        vec.push(row?);
    }
    Ok(vec)
}

/// Get file version entries for a specific relative path within a sync pair.
pub fn get_file_versions_for_path(
    conn: &Connection,
    sync_pair_id: &str,
    relative_path: &str,
) -> SqliteResult<Vec<FileVersion>> {
    let mut stmt = conn.prepare(
        "SELECT sync_pair_id, relative_path, device_id, version, merkle_root, size_bytes, modified_at
         FROM file_versions WHERE sync_pair_id = ?1 AND relative_path = ?2",
    )?;
    let rows = stmt.query_map(params![sync_pair_id, relative_path], |row| {
        Ok(FileVersion {
            sync_pair_id: row.get(0)?,
            relative_path: row.get(1)?,
            device_id: row.get(2)?,
            version: row.get(3)?,
            merkle_root: row.get(4)?,
            size_bytes: row.get(5)?,
            modified_at: row.get(6)?,
        })
    })?;
    let mut vec = Vec::new();
    for row in rows {
        vec.push(row?);
    }
    Ok(vec)
}

/// Insert an audit trail entry for a sync operation.
pub fn insert_sync_history(
    conn: &Connection,
    sync_pair_id: &str,
    event: &str,
    relative_path: &str,
    detail: Option<&str>,
) -> SqliteResult<()> {
    let now = chrono::Utc::now().to_rfc3339();
    conn.execute(
        "INSERT INTO sync_history (sync_pair_id, event, relative_path, detail, created_at)
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![sync_pair_id, event, relative_path, detail, now],
    )?;
    Ok(())
}

/// Get audit trail for a sync pair, newest first. Optional limit (default 100).
pub fn get_sync_history(
    conn: &Connection,
    sync_pair_id: &str,
    limit: Option<u32>,
) -> SqliteResult<Vec<SyncHistory>> {
    let limit_val = limit.unwrap_or(100) as i64;
    let mut stmt = conn.prepare(
        "SELECT id, sync_pair_id, event, relative_path, detail, created_at
         FROM sync_history WHERE sync_pair_id = ?1
         ORDER BY id DESC LIMIT ?2",
    )?;
    let rows = stmt.query_map(params![sync_pair_id, limit_val], |row| {
        Ok(SyncHistory {
            id: row.get(0)?,
            sync_pair_id: row.get(1)?,
            event: row.get(2)?,
            relative_path: row.get(3)?,
            detail: row.get(4)?,
            created_at: row.get(5)?,
        })
    })?;
    let mut vec = Vec::new();
    for row in rows {
        vec.push(row?);
    }
    Ok(vec)
}

/// Create a job with a specific priority (0-10). Used by the REST handler.
pub fn create_job_with_priority(
    conn: &Connection,
    name: &str,
    config_json: &str,
    priority: u32,
) -> SqliteResult<Job> {
    let id = uuid::Uuid::new_v4().to_string();
    let now = chrono::Utc::now().to_rfc3339();

    conn.execute(
        "INSERT INTO jobs (id, name, status, config_json, priority, retry_count, max_retries, created_at, updated_at)
         VALUES (?1, ?2, 'created', ?3, ?4, 0, 3, ?5, ?5)",
        params![id, name, config_json, priority, now],
    )?;

    conn.execute(
        "INSERT INTO job_history (job_id, event, timestamp) VALUES (?1, 'created', ?2)",
        params![id, now],
    )?;

    Ok(Job {
        id,
        name: name.to_string(),
        status: "created".to_string(),
        config_json: config_json.to_string(),
        error_message: None,
        created_at: now.clone(),
        updated_at: now,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_db() -> Connection {
        Connection::open_in_memory().expect("failed to create in-memory DB")
    }

    fn run_test_migrations(conn: &Connection) {
        // Recreate full migrations to ensure new columns/tables exist
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'created',
                config_json TEXT NOT NULL,
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS job_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                event TEXT NOT NULL,
                detail TEXT,
                timestamp TEXT NOT NULL
            );
            "
        ).expect("failed to create initial tables");

        // Now run the real migrations (which add priority, retry, transfer_resume)
        run_migrations(conn).expect("migrations should succeed");
    }

    // =========================================================================
    // Schema tests
    // =========================================================================

    #[test]
    fn test_priority_column_exists() {
        let conn = setup_db();
        run_test_migrations(&conn);

        let mut stmt = conn.prepare("PRAGMA table_info(jobs)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| row.get::<_, String>(1))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        eprintln!("All columns after migrations: {:?}", columns);

        assert!(
            columns.contains(&"priority".to_string()),
            "jobs table must have priority column. Found: {:?}",
            columns
        );
    }

    #[test]
    fn test_retry_count_column_exists() {
        let conn = setup_db();
        run_test_migrations(&conn);

        let mut stmt = conn.prepare("PRAGMA table_info(jobs)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| Ok(row.get::<_, String>(1)?))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(
            columns.contains(&"retry_count".to_string()),
            "jobs table must have retry_count column"
        );
    }

    #[test]
    fn test_max_retries_column_exists() {
        let conn = setup_db();
        run_test_migrations(&conn);

        let mut stmt = conn.prepare("PRAGMA table_info(jobs)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| Ok(row.get::<_, String>(1)?))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(
            columns.contains(&"max_retries".to_string()),
            "jobs table must have max_retries column"
        );
    }

    #[test]
    fn test_transfer_resume_table_exists() {
        let conn = setup_db();
        run_test_migrations(&conn);

        let mut stmt = conn.prepare("PRAGMA table_info(transfer_resume)").unwrap();
        let columns: Vec<String> = stmt
            .query_map([], |row| Ok(row.get::<_, String>(1)?))
            .unwrap()
            .filter_map(|r| r.ok())
            .collect();

        assert!(
            columns.contains(&"job_id".to_string()),
            "transfer_resume must have job_id column"
        );
        assert!(
            columns.contains(&"byte_offset".to_string()),
            "transfer_resume must have byte_offset column"
        );
        assert!(
            columns.contains(&"file_path".to_string()),
            "transfer_resume must have file_path column"
        );
        assert!(
            columns.contains(&"updated_at".to_string()),
            "transfer_resume must have updated_at column"
        );
    }

    // =========================================================================
    // DAO function tests
    // =========================================================================

    fn insert_test_job(conn: &Connection, name: &str, status: &str, priority: u32) -> Job {
        let id = format!("test-{}-{}", name, uuid::Uuid::new_v4().to_string().split('-').next().unwrap());
        let now = chrono::Utc::now().to_rfc3339();
        conn.execute(
            "INSERT INTO jobs (id, name, status, config_json, priority, retry_count, max_retries, created_at, updated_at) VALUES (?1, ?2, ?3, '{}', ?4, 0, 3, ?5, ?5)",
            rusqlite::params![id, name, status, priority, now],
        ).unwrap();
        Job {
            id,
            name: name.to_string(),
            status: status.to_string(),
            config_json: "{}".to_string(),
            error_message: None,
            created_at: now.clone(),
            updated_at: now,
        }
    }

    #[test]
    fn test_dequeue_by_priority_highest_first() {
        let conn = setup_db();
        run_test_migrations(&conn);

        let _low = insert_test_job(&conn, "low", "created", 0);
        let high = insert_test_job(&conn, "high", "created", 10);
        let _mid = insert_test_job(&conn, "mid", "created", 5);

        let dequeued = dequeue_by_priority(&conn).expect("dequeue failed");
        assert!(dequeued.is_some(), "should dequeue the highest priority job");
        let job = dequeued.unwrap();
        assert_eq!(job.id, high.id, "highest priority (10) should dequeue before 5 and 0");
        assert_eq!(job.status, "running", "dequeued job should be marked running");
    }

    #[test]
    fn test_dequeue_by_priority_returns_none_when_empty() {
        let conn = setup_db();
        run_test_migrations(&conn);

        // No 'created' jobs — should return None
        let result = dequeue_by_priority(&conn).expect("dequeue failed");
        assert!(result.is_none(), "empty queue should return None");
    }

    #[test]
    fn test_save_transfer_state_insert_and_update() {
        let conn = setup_db();
        run_test_migrations(&conn);

        // Create a job first to satisfy foreign key constraint
        let job = insert_test_job(&conn, "transfer-test", "created", 5);

        save_transfer_state(&conn, &job.id, 1024, "/tmp/test.txt").expect("save failed");

        let result = get_transfer_state(&conn, &job.id).expect("get failed");
        assert!(result.is_some());
        let (offset, path) = result.unwrap();
        assert_eq!(offset, 1024);
        assert_eq!(path, "/tmp/test.txt");

        // Update (upsert)
        save_transfer_state(&conn, &job.id, 2048, "/tmp/test2.txt").expect("save failed");
        let result2 = get_transfer_state(&conn, &job.id).expect("get failed");
        assert!(result2.is_some());
        let (offset2, path2) = result2.unwrap();
        assert_eq!(offset2, 2048);
        assert_eq!(path2, "/tmp/test2.txt");
    }

    #[test]
    fn test_get_transfer_state_unknown_job() {
        let conn = setup_db();
        run_test_migrations(&conn);

        let result = get_transfer_state(&conn, "nonexistent").expect("get failed");
        assert!(result.is_none(), "unknown job_id should return None");
    }

    #[test]
    fn test_increment_retry_count() {
        let conn = setup_db();
        run_test_migrations(&conn);

        let job = insert_test_job(&conn, "retry-test", "created", 1);

        let count1 = increment_retry_count(&conn, &job.id).expect("increment failed");
        assert_eq!(count1, 1, "first increment should return 1");

        let count2 = increment_retry_count(&conn, &job.id).expect("increment failed");
        assert_eq!(count2, 2, "second increment should return 2");

        let count3 = increment_retry_count(&conn, &job.id).expect("increment failed");
        assert_eq!(count3, 3, "third increment should return 3");
    }

    // =========================================================================
    // Phase 7 — Sync schema + DAO tests
    // =========================================================================

    fn run_sync_migrations(conn: &Connection) {
        // Run full migrations (includes existing tables + sync tables)
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS jobs (
                id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'created',
                config_json TEXT NOT NULL,
                error_message TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS job_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL REFERENCES jobs(id) ON DELETE CASCADE,
                event TEXT NOT NULL,
                detail TEXT,
                timestamp TEXT NOT NULL
            );"
        ).expect("failed to create base tables");

        run_migrations(conn).expect("migrations should succeed (including sync tables)");
    }

    #[test]
    fn test_sync_schema_tables_exist() {
        let conn = setup_db();
        run_sync_migrations(&conn);

        // Verify all 4 sync tables exist
        for table in &["sync_pairs", "device_states", "file_versions", "sync_history"] {
            let count: i64 = conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                rusqlite::params![table],
                |row| row.get(0),
            ).expect(&format!("failed to query existence of {}", table));
            assert_eq!(count, 1, "table '{}' should exist after migrations", table);
        }
    }

    #[test]
    fn test_create_sync_pair_returns_valid_pair() {
        let conn = setup_db();
        run_sync_migrations(&conn);

        let pair = create_sync_pair(
            &conn,
            "docs-sync",
            "/home/user/docs",
            "/backup/docs",
            "laptop-01",
            None,
        ).expect("create_sync_pair should succeed");

        assert!(!pair.id.is_empty(), "pair should have a UUID id");
        assert_eq!(pair.name, "docs-sync");
        assert_eq!(pair.source_dir, "/home/user/docs");
        assert_eq!(pair.dest_dir, "/backup/docs");
        assert_eq!(pair.device_id, "laptop-01");
        assert_eq!(pair.status, "active");
        assert!(pair.config_json.is_none());
        assert!(!pair.created_at.is_empty());
        assert!(!pair.updated_at.is_empty());
    }

    #[test]
    fn test_increment_device_version_atomic() {
        let conn = setup_db();
        run_sync_migrations(&conn);

        // Create a sync pair (this already inserts device_states with version=0)
        let pair = create_sync_pair(
            &conn, "test-sync", "/src", "/dst", "device-1", None,
        ).expect("create_sync_pair should succeed");

        // create_sync_pair already seeded device_states with version=0

        // Increment version atomically
        let v1 = increment_device_version(&conn, "device-1", &pair.id).expect("increment should succeed");
        assert_eq!(v1, 1, "first increment should return 1");

        let v2 = increment_device_version(&conn, "device-1", &pair.id).expect("second increment should succeed");
        assert_eq!(v2, 2, "second increment should return 2");

        let v3 = increment_device_version(&conn, "device-1", &pair.id).expect("third increment should succeed");
        assert_eq!(v3, 3, "third increment should return 3");
    }

    #[test]
    fn test_upsert_file_version_insert_and_update() {
        let conn = setup_db();
        run_sync_migrations(&conn);

        let pair = create_sync_pair(
            &conn, "test-sync", "/src", "/dst", "device-1", None,
        ).expect("create_sync_pair should succeed");

        // Insert a file version
        upsert_file_version(
            &conn, &pair.id, "notes.txt", "device-1", 1, Some("abc123"), 1024, "2025-01-01T00:00:00Z",
        ).expect("upsert should succeed");

        // Verify it was inserted
        let versions = get_file_versions_for_pair(&conn, &pair.id).expect("get should succeed");
        assert_eq!(versions.len(), 1);
        assert_eq!(versions[0].relative_path, "notes.txt");
        assert_eq!(versions[0].version, 1);
        assert_eq!(versions[0].merkle_root.as_deref(), Some("abc123"));
        assert_eq!(versions[0].size_bytes, 1024);

        // Upsert with updated version
        upsert_file_version(
            &conn, &pair.id, "notes.txt", "device-1", 3, Some("def456"), 2048, "2025-01-02T00:00:00Z",
        ).expect("upsert should succeed");

        let versions2 = get_file_versions_for_pair(&conn, &pair.id).expect("get should succeed");
        assert_eq!(versions2.len(), 1, "should still have 1 entry after upsert");
        assert_eq!(versions2[0].version, 3, "version should be updated");
        assert_eq!(versions2[0].size_bytes, 2048, "size should be updated");
    }

    #[test]
    fn test_get_file_versions_for_pair_multiple_files() {
        let conn = setup_db();
        run_sync_migrations(&conn);

        let pair = create_sync_pair(
            &conn, "multi-sync", "/src", "/dst", "device-1", None,
        ).expect("create_sync_pair should succeed");

        upsert_file_version(&conn, &pair.id, "a.txt", "device-1", 1, None, 100, "2025-01-01T00:00:00Z").unwrap();
        upsert_file_version(&conn, &pair.id, "b.txt", "device-1", 2, None, 200, "2025-01-01T00:00:00Z").unwrap();
        upsert_file_version(&conn, &pair.id, "sub/c.txt", "device-2", 5, None, 300, "2025-01-01T00:00:00Z").unwrap();

        let versions = get_file_versions_for_pair(&conn, &pair.id).expect("get should succeed");
        assert_eq!(versions.len(), 3, "should have 3 file version entries");
    }

    #[test]
    fn test_list_sync_pairs_with_status_filter() {
        let conn = setup_db();
        run_sync_migrations(&conn);

        let _pair1 = create_sync_pair(&conn, "active-sync", "/src1", "/dst1", "dev-1", None).unwrap();

        // Create a second pair and then pause it
        let pair2 = create_sync_pair(&conn, "paused-sync", "/src2", "/dst2", "dev-1", None).unwrap();
        update_sync_pair_status(&conn, &pair2.id, "paused").expect("pause should succeed");

        // List all (no filter)
        let all = list_sync_pairs(&conn, None).expect("list all should succeed");
        assert_eq!(all.len(), 2, "should have 2 total pairs");

        // List only active
        let active = list_sync_pairs(&conn, Some("active")).expect("list active should succeed");
        assert_eq!(active.len(), 1, "should have 1 active pair");
        assert_eq!(active[0].status, "active");

        // List only paused
        let paused = list_sync_pairs(&conn, Some("paused")).expect("list paused should succeed");
        assert_eq!(paused.len(), 1, "should have 1 paused pair");
        assert_eq!(paused[0].status, "paused");
    }
}
