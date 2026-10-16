//! Disk snapshot store for the FCC RMDB.
//!
//! A refresh can parse a downloaded CSV into an [`RmdbSnapshot`] and persist it
//! to a JSON file on disk; the mitigation dispatch side later reloads the same
//! snapshot and looks up carriers. This keeps the parsed snapshot durable across
//! refresh runs without re-downloading or re-parsing on every dispatch.
//!
//! JSON (via `serde_json`) is used as the on-disk format because
//! [`RmdbSnapshot`] is a plain data struct (`Release version`, source, and a
//! BTreeMap of `carrier -> (certified, holding_company)`), so serialization is
//! stable, human-diffable, and robust to field additions.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use crate::stdlib::phone_osint::{parse_rmdb_csv, RmdbSnapshot};

/// Environment variable that holds the default snapshot path.
///
/// Honored by [`default_snapshot_path`]; the refresh script can point the store
/// at a specific file and the mitigation read side will pick up the same one.
pub const SNAPSHOT_PATH_ENV: &str = "TALLOW_RMDB_SNAPSHOT_PATH";

/// Fallback path when `TALLOW_RMDB_SNAPSHOT_PATH` is unset.
/// Prefers a workspace `data/rmdb_snapshot.json` (persistent, refreshable) when
/// `TALLOW_WORKSPACE` is set; otherwise falls back to a temp file.
fn default_snapshot_path_static() -> String {
    if let Ok(w) = std::env::var("TALLOW_WORKSPACE") {
        if !w.trim().is_empty() {
            return std::path::Path::new(&w)
                .join("data")
                .join("rmdb_snapshot.json")
                .to_string_lossy()
                .to_string();
        }
    }
    if std::path::Path::new("data/rmdb_snapshot.json").exists() {
        return "data/rmdb_snapshot.json".to_string();
    }
    "/tmp/rmdb_snapshot.json".to_string()
}

/// Resolve the snapshot path, honoring `TALLOW_RMDB_SNAPSHOT_PATH`.
///
/// After resolving, this expands a leading `~` to the user's home directory so
/// both an absolute path and a relative/home-anchored path work. The result is
/// passed verbatim to [`save_snapshot`] / [`load_snapshot`] if the caller did
/// not supply a path explicitly.
pub fn default_snapshot_path() -> String {
    match std::env::var(SNAPSHOT_PATH_ENV) {
        Ok(v) if !v.trim().is_empty() => expand_home(&v),
        _ => default_snapshot_path_static(),
    }
}

/// Expand a leading `~` (and `~/`) to the current user's home directory.
fn expand_home(p: &str) -> String {
    if p == "~" {
        if let Ok(h) = std::env::var("HOME") {
            return h;
        }
        return p.to_string();
    }
    if let Some(rest) = p.strip_prefix("~/") {
        if let Ok(h) = std::env::var("HOME") {
            return format!("{}/{}", h, rest);
        }
    }
    p.to_string()
}

/// Serialize `snapshot` to JSON and write it to `path`.
///
/// Writes atomically (write to a temp file in the same directory, then rename)
/// so a concurrent reader never observes a half-written snapshot. Creates the
/// containing directory if it does not exist.
pub fn save_snapshot(snapshot: &RmdbSnapshot, path: &str) -> Result<(), String> {
    let path = Path::new(path);
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("create dir error: {e}"))?;
        }
    }
    let json = serde_json::to_string_pretty(snapshot)
        .map_err(|e| format!("serialize snapshot error: {e}"))?;

    let tmp_path = path.with_extension(format!("{}.tmp", "json"));
    fs::write(&tmp_path, json.as_bytes()).map_err(|e| format!("write error: {e}"))?;
    fs::rename(&tmp_path, path).map_err(|e| format!("rename error: {e}"))?;
    Ok(())
}

/// Load a snapshot previously written by [`save_snapshot`].
///
/// Returns `Err` when the file is missing, unreadable, or not valid JSON for an
/// [`RmdbSnapshot`].
pub fn load_snapshot(path: &str) -> Result<RmdbSnapshot, String> {
    let path = Path::new(path);
    let bytes = fs::read(path).map_err(|e| format!("read error ({path:?}): {e}"))?;
    let snapshot: RmdbSnapshot =
        serde_json::from_slice(&bytes).map_err(|e| format!("deserialize error: {e}"))?;
    Ok(snapshot)
}

/// Parse an FCC RMDB CSV from `text` for `release`, save it to `path`, and
/// return the parsed snapshot.
///
/// This is the one-call refresh entry point: parse the freshly downloaded CSV,
/// persist it to the snapshot store, and hand the parsed snapshot back so the
/// caller can use it immediately (e.g. for a lookup) without a reload.
pub fn refresh_from_csv_text(text: &str, release: &str, path: &str) -> Result<RmdbSnapshot, String> {
    let snapshot = parse_rmdb_csv(text, release);
    save_snapshot(&snapshot, path)?;
    Ok(snapshot)
}

/// Convenience wrapper: refresh using the default snapshot path
/// (`TALLOW_RMDB_SNAPSHOT_PATH` or its fallback).
pub fn refresh_from_csv_default(text: &str, release: &str) -> Result<RmdbSnapshot, String> {
    refresh_from_csv_text(text, release, &default_snapshot_path())
}

/// Load the snapshot using the default path (`TALLOW_RMDB_SNAPSHOT_PATH`).
pub fn load_snapshot_default() -> Result<RmdbSnapshot, String> {
    load_snapshot(&default_snapshot_path())
}

// NOTE: `lookup_carrier` already lives on `RmdbSnapshot` (in phone_osint.rs) and
// operates on the loaded struct, so a loaded snapshot is immediately usable via
// `snapshot.lookup_carrier("t-mobile usa, inc.")` — no extra wiring needed.
// The `use crate::stdlib::phone_osint::RmdbSnapshot;` above is what makes that
// the same type the parser produces and the store reloads.

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stdlib::phone_osint::make_rmdb_snapshot;

    fn sample_snapshot() -> RmdbSnapshot {
        make_rmdb_snapshot(
            vec![
                ("T-MOBILE USA, INC.".to_string(), true, "T-Mobile".to_string()),
                ("Small VOIP LLC".to_string(), false, "".to_string()),
            ],
            "2026-10",
            "fcc-rmdb-csv",
        )
    }

    #[test]
    fn roundtrip_save_load() {
        let dir = std::env::temp_dir().join("rmdb_store_test_roundtrip");
        let path = dir.join("snapshot.json");
        let path_str = path.to_str().unwrap();

        let snap = sample_snapshot();
        save_snapshot(&snap, path_str).expect("save should succeed");
        let loaded = load_snapshot(path_str).expect("load should succeed");

        assert_eq!(loaded.release_version, snap.release_version);
        assert_eq!(loaded.source, snap.source);
        assert_eq!(loaded.len(), snap.len());
        assert_eq!(
            loaded.lookup_carrier("t-mobile usa, inc."),
            Some((true, "T-Mobile".to_string()))
        );
        assert_eq!(
            loaded.lookup_carrier("small voip llc"),
            Some((false, "".to_string()))
        );
        assert!(loaded.lookup_carrier("nope").is_none());
    }

    #[test]
    fn malformed_path_returns_err() {
        let bad = std::env::temp_dir()
            .join("rmdb_store_test_missing_xyz")
            .join("no_such_dir")
            .join("snap.json");
        let path_str = bad.to_str().unwrap();

        let snap = sample_snapshot();
        // Saving into a nonexistent parent dir is fine (we create it) -> OK.
        save_snapshot(&snap, path_str).expect("save should create parents");

        // Loading a path whose parents don't exist must Err (not panic).
        let missing = std::env::temp_dir()
            .join("rmdb_store_test_missing_xyz")
            .join("no_such_dir2")
            .join("gone.json");
        assert!(load_snapshot(missing.to_str().unwrap()).is_err());
    }

    #[test]
    fn refresh_from_csv_saves_and_parses() {
        let dir = std::env::temp_dir().join("rmdb_store_test_refresh");
        let path = dir.join("snapshot.json");
        let path_str = path.to_str().unwrap();

        let csv = "Provider Name,Certified,Holding Company\n\
                   \"T-MOBILE USA, INC.\",Yes,T-Mobile\n\
                   Small VOIP LLC,No,\n";
        let snap = refresh_from_csv_text(csv, "2026-10", path_str).expect("refresh should succeed");

        assert_eq!(snap.release_version, "2026-10");
        assert_eq!(snap.len(), 2);
        // Persisted file is loadable and matches.
        let loaded = load_snapshot(path_str).expect("reload should succeed");
        assert_eq!(loaded.len(), 2);
        assert_eq!(
            loaded.lookup_carrier("t-mobile usa, inc."),
            Some((true, "T-Mobile".to_string()))
        );
    }

    #[test]
    fn env_default_path_is_honored() {
        // T-128: serialize env mutation on the one process-global env lock.
        let _guard = crate::runtime::egress_http::env_lock();
        let dir = std::env::temp_dir().join("rmdb_store_test_env");
        let custom = dir.join("custom_snap.json");
        // Safety: set, then restore.
        let old = std::env::var(SNAPSHOT_PATH_ENV).ok();
        unsafe { std::env::set_var(SNAPSHOT_PATH_ENV, custom.to_str().unwrap()) };

        let snap = sample_snapshot();
        save_snapshot(&snap, &default_snapshot_path()).expect("save via env path");
        let loaded = load_snapshot_default().expect("load via default env path");
        assert_eq!(loaded.release_version, "2026-10");
        assert_eq!(loaded.len(), 2);

        match old {
            Some(v) => unsafe { std::env::set_var(SNAPSHOT_PATH_ENV, v) },
            None => unsafe { std::env::remove_var(SNAPSHOT_PATH_ENV) },
        }
    }
}
