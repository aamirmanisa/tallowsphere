//! Daemon session registry + restart persistence (U-216 / G-07).
//!
//! Split out of `auth.rs` (parent follow-up, `impl/U-216.md` §5): this module
//! owns the minted-session registry, its at-rest digest form, the periodic
//! sweep/flush and the boot restore/sweeper wiring. `auth.rs` keeps the
//! request-path validation and calls [`registered_expiry`] / [`sweep_expired`]
//! from here; `main.rs` wires [`restore_sessions`] and [`spawn_session_sweeper`]
//! at startup, and the handshake route persists each minted session through
//! [`persist_session_now`].

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::AppState;

/// Wall-clock milliseconds for the session-expiry check (pre-epoch ⇒ 0).
pub(crate) fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or(0)
}

// ── Session registry (U-216 / G-07) ────────────────────────────────────────

/// Domain-separation label for the registry's at-rest key digest. The digest
/// is the **only** form the registry persists (G-07: "tokens hashed at
/// rest"); live sessions minted by `POST /auth/handshake` enter the in-memory
/// map under their raw id (the mint site is shared code) and are
/// canonicalized to the digest on every write (see [`canonical_key`]).
const SESSION_KEY_LABEL: &str = "tallow-ipc-session-key-v1|";

/// Registry key digest: lowercase-hex SHA-256 of the domain-separated session
/// id. Deterministic — the same presented id always maps to the same digest,
/// which is what makes reload-by-digest (restart persistence) possible
/// without ever storing the raw token.
fn session_key(id: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SESSION_KEY_LABEL.as_bytes());
    hasher.update(id.as_bytes());
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for b in digest {
        hex.push_str(&format!("{b:02x}"));
    }
    hex
}

/// True for the digest shape the on-disk registry uses: exactly 64 lowercase
/// hex characters. A presented value of this shape is matched **only** via
/// `session_key(value)` — never as a literal map key — so a session digest
/// read off the at-rest file (0600) is never itself replayable as a
/// credential.
fn is_digest_shape(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Expiry of the session the presented header names, or `None` when it names
/// no registry entry.
///
/// Two key spaces coexist (disjoint: raw ids are `sess-<12 hex>`, digests are
/// pure 64-hex): the raw id for sessions minted this run (inserted by the
/// handshake route) and the digest for sessions restored from disk. The raw
/// lookup is skipped for digest-shaped presentations so a leaked at-rest
/// digest cannot authenticate (see [`is_digest_shape`]).
pub(crate) fn registered_expiry(sessions: &HashMap<String, i64>, presented: &str) -> Option<i64> {
    if !is_digest_shape(presented) {
        if let Some(expires) = sessions.get(presented) {
            return Some(*expires);
        }
    }
    sessions.get(&session_key(presented)).copied()
}

/// Drop every registry entry whose expiry has passed (strict `<` rule:
/// expired ⇔ `now_ms >= expires_ms`). Returns how many entries were removed.
pub(crate) fn sweep_expired(sessions: &mut HashMap<String, i64>, now_ms: i64) -> usize {
    let before = sessions.len();
    sessions.retain(|_key, expires| now_ms < *expires);
    before - sessions.len()
}

// ── Session registry persistence (U-216 / G-07 restart persistence) ───────

/// Registry subdirectory under the daemon data dir (created 0700).
const SESSIONS_DIR: &str = "sessions";
/// Registry file inside [`SESSIONS_DIR`] (written 0600, hashed ids only).
const SESSIONS_FILE: &str = "sessions.json";
/// On-disk format version; anything else refuses to load (fail-closed to an
/// empty registry — the daemon then refuses more, never accepts more).
const SESSIONS_FORMAT_VERSION: u32 = 1;

/// Default cadence of the periodic sweep + registry flush.
#[allow(dead_code)] // consumed by `run_daemon` via the parent wiring patch (impl/U-216.md §3)
pub(crate) const SESSION_SWEEP_INTERVAL: Duration = Duration::from_secs(10);

/// One persisted session record: the **digest** of the session id (never the
/// raw token) and its absolute expiry in wall-clock ms.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct SessionRecord {
    key_sha256: String,
    expires_ms: i64,
}

/// The on-disk registry document.
#[derive(Debug, Serialize, Deserialize)]
struct SessionFile {
    version: u32,
    sessions: Vec<SessionRecord>,
}

/// Registry persistence failure (typed — house style, cf. `IpcAuthError`).
///
/// For sessions these failures are never fatal: persistence is best-effort
/// and an unreadable registry starts empty (the daemon re-handshakes
/// clients — refuse-more, never accept-more).
#[derive(Debug)]
enum SessionStoreError {
    /// File-system failure, carrying the offending path.
    Io {
        path: PathBuf,
        source: std::io::Error,
    },
    /// The file exists but is not a usable registry (non-regular file,
    /// unparseable JSON, unknown version).
    Malformed { path: PathBuf, detail: String },
}

impl std::fmt::Display for SessionStoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SessionStoreError::Io { path, source } => {
                write!(f, "session registry I/O failed at {path:?}: {source}")
            }
            SessionStoreError::Malformed { path, detail } => {
                write!(f, "session registry {path:?} is malformed: {detail}")
            }
        }
    }
}

impl std::error::Error for SessionStoreError {}

/// `<data_dir>/sessions/sessions.json` — the persisted session registry
/// (dir 0700 / file 0600, see [`write_sessions`]).
fn sessions_store_path(data_dir: &Path) -> PathBuf {
    data_dir.join(SESSIONS_DIR).join(SESSIONS_FILE)
}

/// Create the registry directory owner-only (0700) — explicitly chmodded so
/// umask cannot loosen it, and a pre-existing loose directory is tightened
/// with a warning (R-P9 / T-112 house pattern).
fn ensure_owner_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir)?.permissions().mode() & 0o777;
        if mode != 0o700 {
            std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
            if mode & 0o077 != 0 {
                tracing::warn!(
                    dir = ?dir,
                    mode = format!("{mode:o}"),
                    "session registry dir was not owner-only; tightened to 0700 (G-07)"
                );
            }
        }
    }
    Ok(())
}

/// Create/rewrite a file owner-only from the first write — 0600 applied at
/// open, no create-then-chmod window (mirrors `main.rs::write_owner_only`).
fn write_owner_only(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)?.write_all(data)
}

/// Canonicalize a registry key for persistence: digest keys pass through
/// unchanged; anything else (a raw live id) is hashed. Guarantees the file
/// can never contain a raw session token.
fn canonical_key(key: &str) -> String {
    if is_digest_shape(key) {
        key.to_string()
    } else {
        session_key(key)
    }
}

/// Snapshot the live registry as persistable records — deduplicated by
/// canonical key (a session present both raw and digest keeps the later
/// expiry) and sorted, so rewrites are byte-stable.
fn snapshot_records(sessions: &HashMap<String, i64>) -> Vec<SessionRecord> {
    let mut by_key: HashMap<String, i64> = HashMap::with_capacity(sessions.len());
    for (key, expires) in sessions {
        by_key
            .entry(canonical_key(key))
            .and_modify(|current| *current = (*current).max(*expires))
            .or_insert(*expires);
    }
    let mut records: Vec<SessionRecord> = by_key
        .into_iter()
        .map(|(key_sha256, expires_ms)| SessionRecord {
            key_sha256,
            expires_ms,
        })
        .collect();
    records.sort_by(|a, b| a.key_sha256.cmp(&b.key_sha256));
    records
}

/// Persist `sessions` to `path` — dir 0700, file 0600, **hashed ids only**,
/// written via tmp+rename so a crash can never leave a torn registry.
/// Returns the number of records written.
fn write_sessions(sessions: &HashMap<String, i64>, path: &Path) -> Result<usize, SessionStoreError> {
    let dir = path.parent().ok_or_else(|| SessionStoreError::Malformed {
        path: path.to_path_buf(),
        detail: "registry path has no parent directory".to_string(),
    })?;
    ensure_owner_dir(dir).map_err(|source| SessionStoreError::Io {
        path: dir.to_path_buf(),
        source,
    })?;

    let records = snapshot_records(sessions);
    let doc = SessionFile {
        version: SESSIONS_FORMAT_VERSION,
        sessions: records,
    };
    let body = serde_json::to_vec(&doc).map_err(|err| SessionStoreError::Malformed {
        path: path.to_path_buf(),
        detail: err.to_string(),
    })?;

    let tmp = path.with_file_name(format!("{SESSIONS_FILE}.tmp"));
    write_owner_only(&tmp, &body).map_err(|source| SessionStoreError::Io {
        path: tmp.clone(),
        source,
    })?;
    std::fs::rename(&tmp, path).map_err(|source| SessionStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    Ok(doc.sessions.len())
}

/// Load the persisted registry, dropping expired records at load (strict
/// `<`; G-07).
///
/// - missing file → `Ok((empty, 0))` (first boot / nothing persisted yet);
/// - non-regular file (directory, symlink) → refused (house policy, cf.
///   `config.rs::read_owner_only_file`);
/// - loose permissions → tightened to 0600 before the contents are trusted;
/// - unparseable JSON / unknown version → refused (caller starts empty);
/// - malformed *record* → skipped with a warning (refuses that value only).
///
/// Returns `(live_records_by_digest, dropped_expired_count)`.
fn read_sessions(path: &Path, now_ms: i64) -> Result<(HashMap<String, i64>, usize), SessionStoreError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        match std::fs::symlink_metadata(path) {
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                return Ok((HashMap::new(), 0));
            }
            Err(source) => {
                return Err(SessionStoreError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
            Ok(meta) => {
                if !meta.file_type().is_file() {
                    return Err(SessionStoreError::Malformed {
                        path: path.to_path_buf(),
                        detail: "not a regular file (refusing symlink/dir)".to_string(),
                    });
                }
                let mode = meta.permissions().mode() & 0o777;
                if mode & 0o077 != 0 {
                    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                        .map_err(|source| SessionStoreError::Io {
                            path: path.to_path_buf(),
                            source,
                        })?;
                    tracing::warn!(
                        path = ?path,
                        mode = format!("{mode:o}"),
                        "session registry was not owner-only; tightened to 0600 (G-07)"
                    );
                }
            }
        }
    }
    #[cfg(not(unix))]
    {
        if !path.exists() {
            return Ok((HashMap::new(), 0));
        }
        if !path.is_file() {
            return Err(SessionStoreError::Malformed {
                path: path.to_path_buf(),
                detail: "not a regular file".to_string(),
            });
        }
    }

    let text = std::fs::read_to_string(path).map_err(|source| SessionStoreError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let doc: SessionFile =
        serde_json::from_str(&text).map_err(|err| SessionStoreError::Malformed {
            path: path.to_path_buf(),
            detail: err.to_string(),
        })?;
    if doc.version != SESSIONS_FORMAT_VERSION {
        return Err(SessionStoreError::Malformed {
            path: path.to_path_buf(),
            detail: format!(
                "unsupported version {} (expected {})",
                doc.version, SESSIONS_FORMAT_VERSION
            ),
        });
    }

    let mut live = HashMap::with_capacity(doc.sessions.len());
    let mut dropped = 0usize;
    let mut malformed = 0usize;
    for record in doc.sessions {
        if !is_digest_shape(&record.key_sha256) {
            malformed += 1;
            continue;
        }
        if now_ms < record.expires_ms {
            live.insert(record.key_sha256, record.expires_ms);
        } else {
            dropped += 1;
        }
    }
    if malformed > 0 {
        tracing::warn!(
            path = ?path,
            skipped = malformed,
            "session registry: skipped malformed records"
        );
    }
    Ok((live, dropped))
}

/// Best-effort flush of the live registry. Failures are logged, never fatal —
/// a request path must never fail because a state file could not be written
/// (house pattern, cf. `db.rs::harden_state_file`).
fn persist_sessions(sessions: &std::sync::Mutex<HashMap<String, i64>>, path: &Path) {
    let snapshot = match sessions.lock() {
        Ok(guard) => guard.clone(),
        Err(poisoned) => poisoned.into_inner().clone(),
    };
    match write_sessions(&snapshot, path) {
        Ok(written) => tracing::debug!(
            path = ?path,
            records = written,
            "session registry persisted"
        ),
        Err(err) => tracing::warn!(
            path = ?path,
            error = %err,
            "failed to persist session registry (best-effort)"
        ),
    }
}

/// Persist the live registry immediately — called by the handshake route the
/// moment a session is minted (parent follow-up, `impl/U-216.md` §5).
///
/// Closes the crash-amnesia window: without it, a session minted between two
/// sweeper ticks exists only in memory until the next flush, so a hard crash
/// loses it (worst case ≤ `SESSION_SWEEP_INTERVAL`). Best-effort by design —
/// like every other session flush, a failed write is logged, never fatal.
pub(crate) fn persist_session_now(state: &AppState) {
    let path = sessions_store_path(&state.config.data_dir);
    persist_sessions(&state.ipc_sessions, &path);
}

/// Reload persisted sessions at service startup — callable from `run_daemon`
/// (parent wiring patch in `impl/U-216.md` §3). Expired records are dropped
/// at load; returns the number of live sessions restored.
///
/// A missing file is an empty registry; an unreadable/corrupt file logs a
/// warning and starts empty — clients simply re-handshake.
#[allow(dead_code)] // consumed by `run_daemon` via the parent wiring patch (impl/U-216.md §3)
pub(crate) fn restore_sessions(state: &AppState) -> usize {
    let path = sessions_store_path(&state.config.data_dir);
    match read_sessions(&path, now_ms()) {
        Ok((restored, dropped)) => {
            if dropped > 0 {
                tracing::info!(
                    path = ?path,
                    dropped,
                    "dropped expired session records at load (G-07)"
                );
            }
            if restored.is_empty() {
                return 0;
            }
            let count = restored.len();
            match state.ipc_sessions.lock() {
                Ok(mut sessions) => sessions.extend(restored),
                Err(poisoned) => poisoned.into_inner().extend(restored),
            }
            tracing::info!(path = ?path, restored = count, "restored ipc sessions from disk");
            count
        }
        Err(err) => {
            tracing::warn!(
                path = ?path,
                error = %err,
                "failed to load session registry; starting empty (clients re-handshake)"
            );
            0
        }
    }
}

/// One sweeper tick: drop expired entries, then flush the registry to disk.
/// Returns the number of entries swept.
fn sweep_tick(sessions: &std::sync::Mutex<HashMap<String, i64>>, store: &Path, now_ms: i64) -> usize {
    let swept = {
        let mut guard = match sessions.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        sweep_expired(&mut guard, now_ms)
    };
    persist_sessions(sessions, store);
    swept
}

/// Spawn the periodic session sweeper as a background tokio task — callable
/// from service startup (parent wiring patch in `impl/U-216.md` §3).
///
/// Each tick drops expired registry entries and re-persists the registry
/// (bounded on-disk staleness ≤ `interval`; a graceful shutdown triggers a
/// final sweep+flush so live sessions survive a restart). The task exits when
/// `shutdown_rx` signals or its sender is dropped.
#[allow(dead_code)] // consumed by `run_daemon` via the parent wiring patch (impl/U-216.md §3)
pub(crate) fn spawn_session_sweeper(
    state: Arc<AppState>,
    interval: Duration,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let store = sessions_store_path(&state.config.data_dir);
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        tracing::info!(
            path = ?store,
            interval_ms = interval.as_millis(),
            "session sweeper started (G-07: sweep + persist)"
        );

        // Immediate first pass: flush whatever boot restored / minted.
        sweep_tick(&state.ipc_sessions, &store, now_ms());

        if *shutdown_rx.borrow() {
            tracing::info!("session sweeper: shutdown already signaled; exiting");
            return;
        }

        loop {
            tokio::select! {
                _ = ticker.tick() => {
                    let swept = sweep_tick(&state.ipc_sessions, &store, now_ms());
                    if swept > 0 {
                        tracing::info!(swept, "session sweeper: dropped expired sessions");
                    }
                }
                _ = shutdown_rx.changed() => {
                    // Final flush so a graceful restart resumes live sessions.
                    sweep_tick(&state.ipc_sessions, &store, now_ms());
                    tracing::info!("session sweeper: shutdown signal; final sweep + flush done");
                    break;
                }
            }
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{session_check, SessionCheck};

    #[test]
    fn sweep_expired_removes_only_dead_entries() {
        let mut map: HashMap<String, i64> = HashMap::from([
            ("a".to_string(), 999),
            ("b".to_string(), 1_000), // boundary: expired at now == expiry
            ("c".to_string(), 1_001),
            ("d".to_string(), 50_000),
        ]);
        assert_eq!(sweep_expired(&mut map, 1_000), 2);
        assert_eq!(map.len(), 2);
        assert!(map.contains_key("c") && map.contains_key("d"));
        // Idempotent: nothing left to sweep.
        assert_eq!(sweep_expired(&mut map, 1_000), 0);
    }

    #[test]
    fn session_key_is_deterministic_hex_domain_separated_from_the_raw_id() {
        let key = session_key("sess-abc123456789");
        assert_eq!(key.len(), 64);
        assert!(key.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')));
        assert_eq!(key, session_key("sess-abc123456789"), "deterministic");
        assert_ne!(key, session_key("sess-abc123456790"));
        assert_ne!(key, "sess-abc123456789");
        assert!(is_digest_shape(&key));
        assert!(!is_digest_shape("sess-abc123456789"));
        assert!(!is_digest_shape("ABC0123456789012345678901234567890123456789012345678901234567890"));
    }

    #[test]
    fn digest_keyed_registry_entries_validate_by_preimage_never_by_digest_itself() {
        // A session restored from disk lives under its digest.
        let raw = "sess-abc123456789";
        let digest = session_key(raw);
        let s = std::sync::Mutex::new(HashMap::from([(digest.clone(), 5_000i64)]));

        // The raw id (what a client presents) validates...
        assert_eq!(session_check(&s, Some(raw), 1_000), SessionCheck::Ok);
        // ...but the digest itself is NOT a credential (leaked at-rest file
        // values must not authenticate).
        assert_eq!(session_check(&s, Some(&digest), 1_000), SessionCheck::Unknown);
    }

    // ── persistence ────────────────────────────────────────────────────────

    #[test]
    fn persistence_round_trip_survives_restart() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = sessions_store_path(dir.path());
        let raw = "sess-abc123456789";

        let mut before = HashMap::new();
        before.insert(raw.to_string(), 5_000i64);
        write_sessions(&before, &path).expect("persist");

        // "Restart": fresh registry loaded from disk (digest-keyed).
        let (restored, dropped) = read_sessions(&path, 1_000).expect("load");
        assert_eq!(dropped, 0);
        assert!(!restored.contains_key(raw), "raw id never restored as a key");
        assert_eq!(restored.get(&session_key(raw)), Some(&5_000));

        let registry = std::sync::Mutex::new(restored);
        assert_eq!(session_check(&registry, Some(raw), 4_999), SessionCheck::Ok);
        assert_eq!(
            session_check(&registry, Some(raw), 5_000),
            SessionCheck::Expired,
            "restored sessions keep the strict expiry rule"
        );
    }

    #[test]
    fn registry_is_hashed_at_rest_and_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = sessions_store_path(dir.path());
        let raw = "sess-abc123456789";

        let mut map = HashMap::new();
        map.insert(raw.to_string(), 9_000i64);
        write_sessions(&map, &path).expect("persist");

        let text = std::fs::read_to_string(&path).expect("read registry");
        assert!(!text.contains(raw), "raw session id must never be written: {text}");
        assert!(text.contains(&session_key(raw)), "digest is what is stored");

        let doc: serde_json::Value = serde_json::from_str(&text).expect("valid json");
        assert_eq!(doc["version"], 1);
        assert_eq!(doc["sessions"].as_array().map(Vec::len), Some(1));
        assert_eq!(doc["sessions"][0]["key_sha256"], session_key(raw));
        assert_eq!(doc["sessions"][0]["expires_ms"], 9_000);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let file_mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(file_mode, 0o600, "file must be owner-only");
            let dir_mode = std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(dir_mode, 0o700, "dir must be owner-only");
        }
    }

    #[test]
    fn load_drops_expired_records_at_load() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = sessions_store_path(dir.path());

        let mut map = HashMap::new();
        map.insert("sess-aaaa00000000".to_string(), 5_000i64); // expired
        map.insert("sess-bbbb11111111".to_string(), 50_000i64); // live
        write_sessions(&map, &path).expect("persist");

        let (restored, dropped) = read_sessions(&path, 6_000).expect("load");
        assert_eq!(dropped, 1, "expired record dropped at load");
        assert_eq!(restored.len(), 1);
        assert!(restored.contains_key(&session_key("sess-bbbb11111111")));
        assert!(!restored.contains_key(&session_key("sess-aaaa00000000")));
    }

    #[test]
    fn load_missing_file_is_empty_and_non_regular_paths_are_refused() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = sessions_store_path(dir.path());

        // Missing file (first boot): empty registry, no error.
        let (restored, dropped) = read_sessions(&path, 1_000).expect("missing → empty");
        assert!(restored.is_empty());
        assert_eq!(dropped, 0);

        // A directory where the file should be refuses.
        std::fs::create_dir_all(&path).expect("mkdir");
        assert!(read_sessions(&path, 1_000).is_err(), "directory refused");

        #[cfg(unix)]
        {
            // A symlinked registry path refuses (house policy).
            let link_dir = tempfile::tempdir().expect("tempdir");
            let target = link_dir.path().join("real.json");
            std::fs::write(&target, "{}").expect("seed");
            let link = sessions_store_path(link_dir.path());
            std::fs::create_dir_all(link.parent().unwrap()).expect("mkdir");
            std::os::unix::fs::symlink(&target, &link).expect("symlink");
            assert!(read_sessions(&link, 1_000).is_err(), "symlink refused");
        }
    }

    #[test]
    fn load_refuses_malformed_and_unknown_version_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = sessions_store_path(dir.path());
        std::fs::create_dir_all(path.parent().unwrap()).expect("mkdir");

        std::fs::write(&path, "not json at all").expect("seed");
        assert!(read_sessions(&path, 1_000).is_err(), "unparseable refused");

        std::fs::write(&path, r#"{"version":99,"sessions":[]}"#).expect("seed");
        assert!(read_sessions(&path, 1_000).is_err(), "unknown version refused");

        // A malformed *record* is skipped, not fatal — the valid sibling loads.
        std::fs::write(
            &path,
            format!(
                r#"{{"version":1,"sessions":[{{"key_sha256":"zz","expires_ms":9000}},{{"key_sha256":"{}","expires_ms":9000}}]}}"#,
                session_key("sess-live00000000")
            ),
        )
        .expect("seed");
        let (restored, _) = read_sessions(&path, 1_000).expect("record-level skip");
        assert_eq!(restored.len(), 1);
    }

    #[test]
    fn registry_rewrite_is_byte_stable() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path_a = sessions_store_path(dir.path());
        let path_b = dir.path().join("sessions").join("copy.json");

        let mut map = HashMap::new();
        map.insert("sess-cccc22222222".to_string(), 9_000i64);
        map.insert("sess-dddd33333333".to_string(), 7_000i64);
        write_sessions(&map, &path_a).expect("first write");
        let (restored, _) = read_sessions(&path_a, 1_000).expect("load");

        // Loading then rewriting yields the identical document (canonical,
        // sorted): the digest space is a fixed point of persistence.
        write_sessions(&restored, &path_b).expect("second write");
        assert_eq!(
            std::fs::read(&path_a).expect("read a"),
            std::fs::read(&path_b).expect("read b"),
            "persist ∘ load must be byte-stable"
        );
    }

    #[test]
    fn persist_session_now_flushes_the_live_registry_immediately() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = test_state(dir.path().to_path_buf());
        let store = sessions_store_path(dir.path());

        assert!(
            !store.exists(),
            "no registry on disk before the mint-time flush"
        );

        let now = now_ms();
        {
            let mut sessions = state.ipc_sessions.lock().expect("lock");
            sessions.insert("sess-minted000000".to_string(), now + 60_000);
        }
        persist_session_now(&state);

        let (restored, _) = read_sessions(&store, now).expect("registry readable");
        assert_eq!(
            restored.get(&session_key("sess-minted000000")).copied(),
            Some(now + 60_000),
            "mint-time flush stores the session (hashed) without waiting for the sweeper"
        );
    }

    // ── sweeper hook + boot restore (AppState-facing) ─────────────────────

    fn test_state(data_dir: PathBuf) -> Arc<AppState> {
        Arc::new(AppState {
            config: crate::config::Config {
                bind_addr: String::new(),
                port: 0,
                token: String::new(),
                data_dir: data_dir.clone(),
                token_path: data_dir.join("token"),
                port_file: data_dir.join("port"),
                db_path: data_dir.join("daemon.db"),
                tallow_bin: None,
                concurrency_limit: 4,
                retry_base_ms: 1000,
                retry_max_ms: 60000,
                retry_jitter_ms: 500,
                bandwidth_limit_bytes_per_sec: 0,
                bandwidth_schedule: Vec::new(),
                watch_dirs: Vec::new(),
                debounce_delay_ms: 2000,
                debounce_large_file_ms: 10000,
                large_file_threshold_bytes: 10485760,
            },
            start_time: std::time::Instant::now(),
            db: Arc::new(tokio::sync::Mutex::new(
                rusqlite::Connection::open_in_memory().expect("in-memory db"),
            )),
            progress_tx: tokio::sync::broadcast::channel::<crate::sse::ProgressEvent>(4).0,
            shutdown_tx: tokio::sync::watch::channel(false).0,
            device_id: "u216-test-device".to_string(),
            ipc_auth_seen: std::sync::Mutex::new(crate::ipc_auth::SeenNonces::new()),
            ipc_sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
            revocation: Arc::new(crate::revocation_gate::DaemonRevocationGate::disabled()),
        })
    }

    #[test]
    fn restore_sessions_populates_the_live_registry_and_drops_expired() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = test_state(dir.path().to_path_buf());
        let store = sessions_store_path(dir.path());

        let now = now_ms();
        let mut persisted = HashMap::new();
        persisted.insert("sess-revive000000".to_string(), now + 60_000); // live
        persisted.insert("sess-expired00000".to_string(), now - 60_000); // expired
        write_sessions(&persisted, &store).expect("persist");

        let count = restore_sessions(&state);
        assert_eq!(count, 1, "expired record dropped at load");
        assert_eq!(
            session_check(&state.ipc_sessions, Some("sess-revive000000"), now),
            SessionCheck::Ok,
            "restored session validates"
        );
        assert_eq!(
            session_check(&state.ipc_sessions, Some("sess-expired00000"), now),
            SessionCheck::Unknown
        );
    }

    #[tokio::test]
    async fn periodic_sweeper_sweeps_flushes_and_stops_on_shutdown() {
        let dir = tempfile::tempdir().expect("tempdir");
        let state = test_state(dir.path().to_path_buf());
        let store = sessions_store_path(dir.path());

        {
            let mut sessions = state.ipc_sessions.lock().expect("lock");
            let now = now_ms();
            sessions.insert("sess-dead00000000".to_string(), now - 1_000); // expired
            sessions.insert("sess-live00000000".to_string(), now + 60_000); // live
        }

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let handle = spawn_session_sweeper(state.clone(), Duration::from_millis(10), shutdown_rx);

        // The interval task must drop the expired entry (bounded wait).
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if !state
                    .ipc_sessions
                    .lock()
                    .expect("lock")
                    .contains_key("sess-dead00000000")
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("sweeper ticked within 3s");

        // ...and flush the live entry to disk (hashed).
        tokio::time::timeout(Duration::from_secs(3), async {
            loop {
                if let Ok((restored, _)) = read_sessions(&store, now_ms()) {
                    if restored.contains_key(&session_key("sess-live00000000")) {
                        break;
                    }
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("registry flushed within 3s");

        // Shutdown ends the task promptly (final flush included).
        shutdown_tx.send(true).expect("send shutdown");
        tokio::time::timeout(Duration::from_secs(3), handle)
            .await
            .expect("sweeper stopped on shutdown")
            .expect("sweeper join");
    }
}
