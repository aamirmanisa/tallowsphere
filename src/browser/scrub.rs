//! Amnesic / scrub lifecycle for Tallow.
//!
//! Provides a runtime teardown module that erases the browser footprint left
//! behind after a unit of work, closing gap **G8 §2 (anti-forensics)** and
//! **G8 §8 (ephemeral / amnesic execution)**:
//!
//! * **Cookies** — cleared via CDP (`Network.clearBrowserCookies`), reusing
//!   [`super::session::clear_cookies`].
//! * **localStorage / sessionStorage** — cleared via the CDP `DOMStorage`
//!   domain, reusing [`super::session::clear_local_storage`] /
//!   [`super::session::clear_session_storage`] per security origin.
//! * **Temp files** — Tallow-owned entries under the OS temp dir (e.g. the
//!   `tallow-trace-*` extract dirs created by `trace::open_trace_viewer`) are
//!   overwritten with random bytes then removed.
//! * **Trace / recording archives** — caller-supplied archive paths (trace
//!   ZIPs, recording outputs) are shredded and deleted.
//! * **Browser profile dir** — optionally rotated (renamed) to break
//!   cross-campaign correlation of a recovered profile.
//!
//! A `ScrubPolicy` bitmask selects which of these actions run. The default
//! policy enables all of them. `scrub_on_exit()` installs an amnesic
//! teardown (default-on) that runs the filesystem scrub when the returned
//! guard is dropped.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use super::cdp::CdpClient;
use super::error::BrowserError;
use super::session;

/// Default-on flag for amnesic teardown.
///
/// This is the runtime default for the `@scrub_on_exit` lifecycle. A
/// compiler annotation may be layered on top later; the runtime default
/// alone guarantees the browser footprint is scrubbed unless explicitly
/// disabled (see [`set_scrub_on_exit_default`] and [`scrub_on_exit`]).
static SCRUB_ON_EXIT_DEFAULT: AtomicBool = AtomicBool::new(true);

// ── ScrubPolicy bitmask ──────────────────────────────────────────────

/// Bitmask selecting which scrub actions run during teardown.
///
/// Each constant is a bit; combine with `|` and test with
/// [`ScrubPolicy::has`]. [`ScrubPolicy::ALL`] is the default.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScrubPolicy(u32);

impl ScrubPolicy {
    /// No actions. Useful as a starting mask to build up from.
    pub const NONE: ScrubPolicy = ScrubPolicy(0);

    /// Clear browser cookies via CDP.
    pub const CLEAR_COOKIES: u32 = 1 << 0;
    /// Clear localStorage + sessionStorage via CDP.
    pub const CLEAR_STORAGE: u32 = 1 << 1;
    /// Shred Tallow-owned temp files.
    pub const SHRED_TEMP: u32 = 1 << 2;
    /// Delete trace / recording archives.
    pub const DELETE_TRACES: u32 = 1 << 3;
    /// Rotate the browser profile directory.
    pub const ROTATE_PROFILE_DIR: u32 = 1 << 4;

    /// All scrub actions enabled (the default).
    pub const ALL: ScrubPolicy = ScrubPolicy(
        Self::CLEAR_COOKIES
            | Self::CLEAR_STORAGE
            | Self::SHRED_TEMP
            | Self::DELETE_TRACES
            | Self::ROTATE_PROFILE_DIR,
    );

    /// Build a policy from raw bits.
    pub const fn from_bits(bits: u32) -> ScrubPolicy {
        ScrubPolicy(bits)
    }

    /// Build a policy from a bitmask expression, e.g.
    /// `ScrubPolicy::from_mask(ScrubPolicy::CLEAR_COOKIES | ScrubPolicy::SHRED_TEMP)`.
    pub const fn from_mask(bits: u32) -> ScrubPolicy {
        ScrubPolicy(bits)
    }

    /// Whether `flag` (one of the `ScrubPolicy::*` constants) is set.
    pub const fn has(self, flag: u32) -> bool {
        self.0 & flag != 0
    }

    /// Add a flag (returns a new policy).
    pub const fn with(self, flag: u32) -> ScrubPolicy {
        ScrubPolicy(self.0 | flag)
    }

    /// Remove a flag (returns a new policy).
    pub const fn without(self, flag: u32) -> ScrubPolicy {
        ScrubPolicy(self.0 & !flag)
    }

    /// Raw bitmask value.
    pub const fn bits(self) -> u32 {
        self.0
    }
}

impl Default for ScrubPolicy {
    fn default() -> Self {
        ScrubPolicy::ALL
    }
}

// ── ScrubReport ──────────────────────────────────────────────────────

/// Result of a [`scrub`] run, reporting which actions completed and any
/// errors that were swallowed (scrub is best-effort — one failure must not
/// abort the remaining teardown).
#[derive(Debug, Clone)]
pub struct ScrubReport {
    pub cookies_cleared: bool,
    pub storage_cleared: bool,
    pub temp_shredded: bool,
    pub traces_deleted: bool,
    pub profile_rotated: bool,
    pub errors: Vec<String>,
}

impl ScrubReport {
    /// True if every requested action completed without error.
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

// ── ScrubSession ─────────────────────────────────────────────────────

/// Handle to a browser session that is amnesic by default.
///
/// When dropped, [`ScrubGuard`]`/`[`ScrubSession`]` applies the configured
/// [`ScrubPolicy`] to erase the session's footprint (filesystem scrub;
/// CDP cookie/storage clearing requires an explicit [`ScrubSession::scrub`]
/// call while the CDP client is still alive).
#[derive(Debug)]
pub struct ScrubSession {
    /// CDP session id (if a live browser is attached).
    pub session_id: Option<String>,
    /// Security origins whose storage should be cleared.
    pub origins: Vec<String>,
    /// Policy selecting which scrub actions run.
    pub policy: ScrubPolicy,
    /// Work directory containing trace/recording archives to delete.
    pub work_dir: Option<PathBuf>,
    /// Explicit archive paths to delete.
    pub archives: Vec<PathBuf>,
}

impl ScrubSession {
    /// Create a new amnesic session handle with the default (all-on) policy.
    pub fn new() -> Self {
        Self {
            session_id: None,
            origins: Vec::new(),
            policy: ScrubPolicy::ALL,
            work_dir: None,
            archives: Vec::new(),
        }
    }

    /// Attach a CDP session id so cookie/storage clearing can run.
    pub fn with_session_id(mut self, session_id: impl Into<String>) -> Self {
        self.session_id = Some(session_id.into());
        self
    }

    /// Add a security origin whose storage should be cleared.
    pub fn with_origin(mut self, origin: impl Into<String>) -> Self {
        self.origins.push(origin.into());
        self
    }

    /// Set the scrub policy.
    pub fn with_policy(mut self, policy: ScrubPolicy) -> Self {
        self.policy = policy;
        self
    }

    /// Set the work directory whose trace/recording archives are deleted.
    pub fn with_work_dir(mut self, dir: impl Into<PathBuf>) -> Self {
        self.work_dir = Some(dir.into());
        self
    }

    /// Add an explicit trace/recording archive path to delete.
    pub fn with_archive(mut self, path: impl Into<PathBuf>) -> Self {
        self.archives.push(path.into());
        self
    }

    /// Perform the scrub.
    ///
    /// If a live `client` and `self.session_id` are available, cookies and
    /// storage are cleared via CDP (reusing `session::{clear_cookies,
    /// clear_local_storage, clear_session_storage}`). Filesystem actions
    /// (temp shred, trace deletion, profile rotation) always run.
    pub async fn scrub(&self, client: Option<&CdpClient>) -> ScrubReport {
        let origins: Vec<&str> = self.origins.iter().map(|s| s.as_str()).collect();
        let archives: Vec<&Path> = self.archives.iter().map(|p| p.as_path()).collect();
        scrub(
            client,
            self.session_id.as_deref(),
            &origins,
            self.policy,
            self.work_dir.as_deref(),
            &archives,
        )
        .await
    }
}

impl Default for ScrubSession {
    fn default() -> Self {
        Self::new()
    }
}

// ── scrub() ──────────────────────────────────────────────────────────

/// Perform a full amnesic scrub of the browser footprint.
///
/// * `client` / `session_id` — when both are present, cookies are cleared
///   (reusing [`session::clear_cookies`]) and, for each origin in `origins`,
///   localStorage and sessionStorage are cleared (reusing
///   [`session::clear_local_storage`] / [`session::clear_session_storage`]).
/// * `work_dir` — directory whose contents (trace/recording archives) are
///   shredded when `policy` has [`ScrubPolicy::DELETE_TRACES`].
/// * `archives` — explicit trace/recording archive paths to shred.
///
/// Best-effort: every action is attempted and failures are collected in
/// [`ScrubReport::errors`] rather than aborting the teardown.
pub async fn scrub(
    client: Option<&CdpClient>,
    session_id: Option<&str>,
    origins: &[&str],
    policy: ScrubPolicy,
    work_dir: Option<&Path>,
    archives: &[&Path],
) -> ScrubReport {
    let mut report = ScrubReport {
        cookies_cleared: false,
        storage_cleared: false,
        temp_shredded: false,
        traces_deleted: false,
        profile_rotated: false,
        errors: Vec::new(),
    };

    // ── CDP: cookies + storage (requires a live client + session id) ──
    let live = client.is_some() && session_id.is_some();
    if live {
        let client = client.unwrap();
        let sid = session_id.unwrap();

        if policy.has(ScrubPolicy::CLEAR_COOKIES) {
            match session::clear_cookies(client, sid).await {
                Ok(()) => report.cookies_cleared = true,
                Err(e) => report.errors.push(format!("clear_cookies: {e}")),
            }
        }

        if policy.has(ScrubPolicy::CLEAR_STORAGE) {
            let mut ok = true;
            for origin in origins {
                if let Err(e) = session::clear_local_storage(client, sid, origin).await {
                    report.errors.push(format!("clear_local_storage({origin}): {e}"));
                    ok = false;
                }
                if let Err(e) = session::clear_session_storage(client, sid, origin).await {
                    report.errors.push(format!("clear_session_storage({origin}): {e}"));
                    ok = false;
                }
            }
            // Empty origins means nothing to clear; report as done.
            report.storage_cleared = ok;
        }
    } else if policy.has(ScrubPolicy::CLEAR_COOKIES) || policy.has(ScrubPolicy::CLEAR_STORAGE) {
        report.errors.push(
            "cookies/storage clearing requires a live CDP client + session id".to_string(),
        );
    }

    // ── Filesystem: temp shred, trace deletion, profile rotation ─────
    let file_report = scrub_files(policy, work_dir, archives);
    report.temp_shredded = file_report.temp_shredded;
    report.traces_deleted = file_report.traces_deleted;
    report.profile_rotated = file_report.profile_rotated;
    report.errors.extend(file_report.errors);

    report
}

// ── Filesystem scrub (no live CDP required) ─────────────────────────

/// Result of a filesystem-only scrub (temp shred + trace deletion +
/// profile rotation). Usable without a live browser.
#[derive(Debug, Clone, Default)]
pub struct FileScrubReport {
    pub temp_shredded: bool,
    pub traces_deleted: bool,
    pub profile_rotated: bool,
    pub errors: Vec<String>,
}

impl FileScrubReport {
    /// True if every requested filesystem action completed.
    pub fn ok(&self) -> bool {
        self.errors.is_empty()
    }
}

/// Perform the filesystem portion of a scrub: shred Tallow-owned temp
/// files, delete trace/recording archives, and rotate the profile dir.
pub fn scrub_files(
    policy: ScrubPolicy,
    work_dir: Option<&Path>,
    archives: &[&Path],
) -> FileScrubReport {
    let mut report = FileScrubReport::default();

    if policy.has(ScrubPolicy::SHRED_TEMP) {
        match shred_temp() {
            Ok(()) => report.temp_shredded = true,
            Err(e) => report.errors.push(format!("shred_temp: {e}")),
        }
    }

    if policy.has(ScrubPolicy::DELETE_TRACES) {
        let mut ok = true;
        if let Some(dir) = work_dir {
            for entry in walk_dir(dir) {
                if let Err(e) = shred_path(&entry) {
                    report.errors.push(format!("delete archive {}: {e}", entry.display()));
                    ok = false;
                }
            }
        }
        for archive in archives {
            if let Err(e) = shred_path(archive) {
                report.errors.push(format!("delete archive {}: {e}", archive.display()));
                ok = false;
            }
        }
        report.traces_deleted = ok;
    }

    if policy.has(ScrubPolicy::ROTATE_PROFILE_DIR) {
        match rotate_profile_dir(work_dir) {
            Ok(()) => report.profile_rotated = true,
            Err(e) => report.errors.push(format!("rotate_profile_dir: {e}")),
        }
    }

    report
}

/// Shred and delete a single file: overwrite with random bytes twice, then
/// truncate and remove. Best-effort per-file.
pub fn shred_path(path: &Path) -> Result<(), BrowserError> {
    use rand::RngCore;

    let meta = match fs::metadata(path) {
        Ok(m) => m,
        Err(_) => return Ok(()), // already gone — nothing to shred
    };

    if meta.is_file() {
        let len = meta.len();
        let mut rng = rand::rng();
        for _ in 0..2 {
            let mut data = vec![0u8; len as usize];
            rng.fill_bytes(&mut data);
            if let Ok(mut f) = fs::File::create(path) {
                let _ = f.write_all(&data);
                let _ = f.flush();
            }
        }
        let _ = fs::remove_file(path);
    } else if meta.is_dir() {
        // Recursively shred a directory of archives.
        for entry in walk_dir(path) {
            shred_path(&entry)?;
        }
        let _ = fs::remove_dir(path);
    }

    Ok(())
}

/// Recursively walk a directory, returning every file path beneath it.
pub fn walk_dir(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(cur) = stack.pop() {
        if let Ok(rd) = fs::read_dir(&cur) {
            for entry in rd.flatten() {
                let p = entry.path();
                if p.is_dir() {
                    stack.push(p);
                } else if p.is_file() {
                    out.push(p);
                }
            }
        }
    }
    out
}

/// Shred Tallow-owned entries under the OS temp directory.
///
/// Only entries whose file name begins with `tallow` (e.g. the
/// `tallow-trace-*` extract dirs from `trace::open_trace_viewer`) are
/// touched, so unrelated temp files are never disturbed.
pub fn shred_temp() -> Result<(), BrowserError> {
    let temp = std::env::temp_dir();
    let rd = fs::read_dir(&temp).map_err(|e| {
        BrowserError::SessionError(format!("cannot read temp dir {}: {e}", temp.display()))
    })?;

    for entry in rd.flatten() {
        let name = entry.file_name().to_string_lossy().to_lowercase();
        if name.starts_with("tallow") {
            let path = entry.path();
            if path.is_dir() {
                for f in walk_dir(&path) {
                    shred_path(&f)?;
                }
                let _ = fs::remove_dir_all(&path);
            } else {
                shred_path(&path)?;
            }
        }
    }
    Ok(())
}

/// Rotate (rename) the browser profile directory to a fresh, timestamped
/// name so a recovered profile cannot be correlated across campaigns.
///
/// No-op if `work_dir` is not a directory.
pub fn rotate_profile_dir(work_dir: Option<&Path>) -> Result<(), BrowserError> {
    let dir = match work_dir {
        Some(d) if d.is_dir() => d,
        _ => return Ok(()), // no profile dir supplied — nothing to rotate
    };
    let stamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    let rotated = dir.with_file_name(format!("{}-rot-{}", dir.file_name().map(|n| n.to_string_lossy().to_string()).unwrap_or_default(), stamp));
    fs::rename(dir, &rotated).map_err(|e| {
        BrowserError::SessionError(format!("rotate profile dir {} -> {}: {e}", dir.display(), rotated.display()))
    })?;
    Ok(())
}

// ── Default-on scrub_on_exit ─────────────────────────────────────────

/// Read the default-on amnesic teardown flag.
pub fn scrub_on_exit_default() -> bool {
    SCRUB_ON_EXIT_DEFAULT.load(Ordering::Relaxed)
}

/// Set the default-on amnesic teardown flag.
///
/// Defaults to `true` (amnesic by default). Set to `false` to persist the
/// browser footprint — the opposite of the recommended amnesic posture.
pub fn set_scrub_on_exit_default(on: bool) {
    SCRUB_ON_EXIT_DEFAULT.store(on, Ordering::Relaxed);
}

/// A teardown guard that scrubs the filesystem footprint on drop.
///
/// This is the runtime implementation of the `@scrub_on_exit` lifecycle:
/// a unit of work creates a [`ScrubSession`], then when its scope exits the
/// guard's `Drop` runs the filesystem scrub. The flag is default-on — see
/// [`scrub_on_exit_default`].
pub struct ScrubGuard {
    work_dir: Option<PathBuf>,
    archives: Vec<PathBuf>,
    policy: ScrubPolicy,
    active: bool,
}

impl Drop for ScrubGuard {
    fn drop(&mut self) {
        if !self.active || !scrub_on_exit_default() {
            return;
        }
        let policy = self.policy.without(ScrubPolicy::CLEAR_COOKIES)
            .without(ScrubPolicy::CLEAR_STORAGE);
        let _ = scrub_files(
            policy,
            self.work_dir.as_deref(),
            &self.archives.iter().map(|p| p.as_path()).collect::<Vec<_>>(),
        );
    }
}

/// Install an amnesic teardown guard.
///
/// Call this at the start of a unit of work; the returned guard scrubs the
/// filesystem footprint when dropped. Cookie/storage clearing still requires
/// an explicit [`ScrubSession::scrub`] call while the CDP client is alive.
///
/// This is the documented default-on runtime flag behind the (optional)
/// `@scrub_on_exit` compiler annotation.
pub fn scrub_on_exit(
    work_dir: Option<PathBuf>,
    archives: Vec<PathBuf>,
    policy: ScrubPolicy,
) -> ScrubGuard {
    ScrubGuard {
        work_dir,
        archives,
        policy,
        active: true,
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_bitmask() {
        let p = ScrubPolicy::ALL;
        assert!(p.has(ScrubPolicy::CLEAR_COOKIES));
        assert!(p.has(ScrubPolicy::CLEAR_STORAGE));
        assert!(p.has(ScrubPolicy::SHRED_TEMP));
        assert!(p.has(ScrubPolicy::DELETE_TRACES));
        assert!(p.has(ScrubPolicy::ROTATE_PROFILE_DIR));
        assert_eq!(ScrubPolicy::NONE.bits(), 0);
        assert!(ScrubPolicy::NONE.with(ScrubPolicy::SHRED_TEMP).has(ScrubPolicy::SHRED_TEMP));
        assert!(!ScrubPolicy::NONE.with(ScrubPolicy::SHRED_TEMP).has(ScrubPolicy::DELETE_TRACES));
    }

    #[test]
    fn test_policy_default_is_all() {
        let p = ScrubPolicy::default();
        assert_eq!(p.bits(), ScrubPolicy::ALL.bits());
    }

    #[test]
    fn test_scrub_on_exit_default_flag() {
        let before = scrub_on_exit_default();
        assert!(before, "amnesic teardown should be default-on");
        set_scrub_on_exit_default(false);
        assert!(!scrub_on_exit_default());
        set_scrub_on_exit_default(true);
    }

    #[test]
    fn test_shred_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("trace.zip");
        fs::write(&file, b"some recorded trace bytes").unwrap();
        assert!(file.exists());
        shred_path(&file).unwrap();
        assert!(!file.exists());
    }

    #[test]
    fn test_scrub_files_deletes_archives() {
        let dir = tempfile::tempdir().unwrap();
        let archive = dir.path().join("trace-1.zip");
        fs::write(&archive, b"bytes").unwrap();
        let report = scrub_files(
            ScrubPolicy::from_mask(ScrubPolicy::DELETE_TRACES),
            None,
            &[archive.as_path()],
        );
        assert!(report.traces_deleted);
        assert!(report.ok());
        assert!(!archive.exists());
    }
}
