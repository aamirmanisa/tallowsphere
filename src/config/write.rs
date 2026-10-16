//! KB-1 writes: atomic staged replace, config-history revision hook (D6), and
//! the best-effort ledger seam (D8).
//!
//! # Atomic staged write
//! [`commit`] validates the content strictly (a kernel-managed artifact must be
//! clean under the kernel's own loader), records the revision, then stages the
//! bytes into a temp file **in the target directory** (`O_EXCL`, unix mode per
//! [`FilePermsPolicy`] — `0600` by default and always for secret-bearing
//! files), fsyncs it, renames it over the target (atomic on unix), and fsyncs
//! the directory. On any failure the previous file is left byte-intact and the
//! temp file is removed — a reader never observes a partial artifact.
//!
//! # Config history (parent decision D6)
//! Every accepted write is recorded under
//! `dirs::state_dir()/tallow/config-history` (fallback `~/.local/state/tallow/config-history`),
//! as `<rev:06>/config.toml` (the accepted bytes) + `<rev:06>/meta.toml`
//! (BLAKE3 + monotonic revision + timestamp). Directory `0700`, files `0600`.
//! Recording happens **before** the replace and is fail-closed: if the
//! revision cannot be recorded, the write is refused (`E7008`/`E7009`) — an
//! accepted write is never unrecorded. (KB-3 grows migration/rollback on top;
//! it reads [`latest_revision`]/[`read_revision_meta`] and reuses
//! [`record_revision`].)
//!
//! # Ledger seam (parent decision D8 — best-effort this wave)
//! [`LedgerSink`] is the seam for the later ledger integration: the production
//! implementation [`JournalLedgerSink`] emits an `EventClass::ConfigChange`
//! security event on the default journal, best-effort. **By decision D8 a
//! broken journal never blocks a write** (it is a doctor-warning, KB-6); the
//! seam exists so a later wave can make it refusable without touching the
//! commit path. The event carries the path + size + revision + content hash —
//! **never a config value**.

use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use crate::config::load;
use crate::config::schema::{
    CODE_HISTORY_PATH, CODE_HISTORY_RECORD, CODE_WRITE_IO, ConfigError,
};
use crate::observability;

/// Subdirectory of the state dir holding the config revision store (D6).
pub const HISTORY_DIR_NAME: &str = "config-history";

/// Owner-only file mode used for kernel config artifacts on unix.
pub const CONFIG_FILE_MODE: u32 = 0o600;
/// Owner-only directory mode used for kernel-managed directories on unix.
pub const KERNEL_DIR_MODE: u32 = 0o700;
/// Mode used for non-secret files under [`FilePermsPolicy::OwnerOnlyWhenSecretBearing`].
pub const LOOSE_FILE_MODE: u32 = 0o644;

/// Zero-padded width of revision directory names.
pub const REVISION_PAD: usize = 6;

/// Unix mode policy for the committed config file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum FilePermsPolicy {
    /// Always `0600` on unix (U-202 KB-1: "config file always 0600"). Default.
    #[default]
    OwnerOnlyAlways,
    /// `0600` exactly when the config carries secret-class values, otherwise
    /// the umask-limited `0644` — "0600 for secret-bearing files".
    OwnerOnlyWhenSecretBearing,
}

impl FilePermsPolicy {
    /// The unix mode the kernel requests when creating the staged file.
    pub fn temp_mode(self, secret_bearing: bool) -> u32 {
        match self {
            FilePermsPolicy::OwnerOnlyAlways => CONFIG_FILE_MODE,
            FilePermsPolicy::OwnerOnlyWhenSecretBearing => {
                if secret_bearing {
                    CONFIG_FILE_MODE
                } else {
                    LOOSE_FILE_MODE
                }
            }
        }
    }
}

/// Where the accepted-write revision goes (D6).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum HistoryPolicy {
    /// Record at the D6 default location. Resolution failure refuses the write.
    #[default]
    DefaultLocation,
    /// Record at an explicit root (tests, alternate state roots, KB-3 tools).
    At(PathBuf),
    /// No revision record. Reserved for unit paths — production callers keep
    /// recording on; the kernel write path is fail-closed about history.
    Disabled,
}

/// One accepted config write, as handed to the ledger seam (D8).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConfigWriteEvent {
    /// The config file that was replaced.
    pub path: PathBuf,
    /// Size in bytes of the accepted artifact.
    pub bytes: usize,
    /// Revision recorded in config-history, when one was written.
    pub revision: Option<u64>,
    /// BLAKE3 hash of the accepted artifact.
    pub content_blake3: String,
}

/// Seam for the later ledger integration (D8).
///
/// Contract: **must not block the commit** — the kernel treats an `Err` as a
/// doctor-warning signal, never as a write failure (best-effort by decision
/// D8; a refusable variant is a later-wave decision that plugs in here).
/// Implementations never receive config values, only the metadata above.
pub trait LedgerSink {
    /// Record an accepted write. Errors are surfaced for logging only.
    fn record_config_write(&self, ev: &ConfigWriteEvent) -> Result<(), String>;
}

/// Production ledger seam: best-effort `ConfigChange` event on the default
/// security journal (`$TALLOW_SECURITY_EVENTS` or `~/.tallow/security-events.jsonl`).
#[derive(Debug, Clone, Copy, Default)]
pub struct JournalLedgerSink;

impl LedgerSink for JournalLedgerSink {
    fn record_config_write(&self, ev: &ConfigWriteEvent) -> Result<(), String> {
        observability::emit_to_default_journal(&observability::SecurityEvent {
            class: observability::EventClass::ConfigChange,
            actor: "config.kernel".to_string(),
            target: Some(ev.path.display().to_string()),
            size: ev.bytes,
            at_ms: observability::now_ms(),
        })
        .map(|_| ())
        .map_err(|e| e.to_string())
    }
}

/// The production journal sink, usable as a `'static` reference.
pub static DEFAULT_LEDGER: JournalLedgerSink = JournalLedgerSink;

/// Options for [`commit`].
pub struct WriteOptions<'a> {
    /// History policy (D6). Default: record at the D6 path, fail-closed.
    pub history: HistoryPolicy,
    /// Unix file-mode policy for the committed artifact.
    pub perms: FilePermsPolicy,
    /// Ledger seam (D8). `None` silences; production default is the journal.
    pub ledger: Option<&'a dyn LedgerSink>,
}

impl Default for WriteOptions<'_> {
    fn default() -> Self {
        WriteOptions {
            history: HistoryPolicy::default(),
            perms: FilePermsPolicy::default(),
            ledger: Some(&DEFAULT_LEDGER),
        }
    }
}

impl<'a> WriteOptions<'a> {
    /// Production defaults: D6 history location, `0600` policy, journal ledger.
    pub fn new() -> Self {
        Self::default()
    }

    /// Record history at an explicit root (tests / alternate state roots).
    pub fn with_history_dir(dir: PathBuf) -> Self {
        WriteOptions {
            history: HistoryPolicy::At(dir),
            ..Self::default()
        }
    }

    /// No revision record (unit paths only).
    pub fn without_history(mut self) -> Self {
        self.history = HistoryPolicy::Disabled;
        self
    }

    /// No ledger record (unit paths only).
    pub fn without_ledger(mut self) -> Self {
        self.ledger = None;
        self
    }

    /// Attach an explicit ledger sink.
    pub fn with_ledger(mut self, sink: &'a dyn LedgerSink) -> Self {
        self.ledger = Some(sink);
        self
    }
}

/// Successful commit outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitOutcome {
    /// The replaced config file.
    pub path: PathBuf,
    /// Size in bytes of the accepted artifact.
    pub bytes: usize,
    /// BLAKE3 hash of the accepted artifact.
    pub content_blake3: String,
    /// Revision recorded in config-history, when one was written.
    pub revision: Option<u64>,
}

/// Metadata of one recorded revision (`<rev>/meta.toml`).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionMeta {
    /// Monotonic revision number (directory name is zero-padded).
    pub revision: u64,
    /// Unix-ms instant the revision was recorded.
    pub recorded_at_ms: u64,
    /// BLAKE3 hash of the accepted artifact bytes.
    pub content_blake3: String,
    /// Config file the revision was accepted for.
    pub source_path: String,
    /// BLAKE3 hash of the previously deployed artifact, when one was readable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_blake3: Option<String>,
}

/// A completed history record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevisionRecord {
    /// Monotonic revision number.
    pub revision: u64,
    /// The `<rev>/` directory written.
    pub dir: PathBuf,
    /// BLAKE3 hash of the recorded artifact.
    pub content_blake3: String,
    /// Unix-ms instant the revision was recorded.
    pub recorded_at_ms: u64,
}

/// D6 history root: `dirs::state_dir()/tallow/config-history`, falling back to
/// `~/.local/state/tallow/config-history`. Never a `"."` fallback: an
/// unresolvable location is `E7012`.
pub fn default_history_dir() -> Result<PathBuf, ConfigError> {
    if let Some(state) = dirs::state_dir() {
        return Ok(state.join("tallow").join(HISTORY_DIR_NAME));
    }
    let home = dirs::home_dir().ok_or_else(|| ConfigError::PathUnresolved {
        what: "config-history root (dirs::state_dir() and dirs::home_dir() both unavailable)"
            .to_string(),
    })?;
    Ok(home
        .join(".local")
        .join("state")
        .join("tallow")
        .join(HISTORY_DIR_NAME))
}

/// Directory of one revision: `<root>/<rev:06>`.
pub fn history_revision_dir(root: &Path, revision: u64) -> PathBuf {
    root.join(format!("{revision:0width$}", width = REVISION_PAD))
}

/// Highest revision recorded under `root` (`None` when none exist / no dir).
pub fn latest_revision(root: &Path) -> Result<Option<u64>, ConfigError> {
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(ConfigError::HistoryPath {
                message: format!("cannot read {}: {e}", root.display()),
            })
        }
    };
    let mut latest: Option<u64> = None;
    for entry in entries.flatten() {
        let Ok(name) = entry.file_name().into_string() else {
            continue;
        };
        if let Ok(n) = name.parse::<u64>() {
            latest = Some(latest.map_or(n, |m| m.max(n)));
        }
    }
    Ok(latest)
}

/// Next monotonic revision under `root` (1 when none exist).
pub fn next_revision(root: &Path) -> Result<u64, ConfigError> {
    Ok(latest_revision(root)?.map_or(1, |r| r + 1))
}

/// Record one accepted artifact as a revision (the D6 hook).
///
/// Writes `<root>/<rev:06>/config.toml` (the accepted bytes, `0600`) and
/// `meta.toml` (`0600`); the revision directory and root are created `0700`.
/// `previous` is the artifact being replaced, when readable, and is recorded
/// as a hash chain link — never as content. Errors are typed:
/// location problems `E7009`, revision write problems `E7008`.
pub fn record_revision(
    root: &Path,
    content: &str,
    source: &Path,
    previous: Option<&str>,
    now_ms: u64,
) -> Result<RevisionRecord, ConfigError> {
    ensure_dir_secure(root).map_err(|e| ConfigError::HistoryPath {
        message: format!("cannot create history root {}: {e}", root.display()),
    })?;
    tighten_dir(root);

    let revision = next_revision(root)?;
    let dir = history_revision_dir(root, revision);

    create_dir_owner_only(&dir).map_err(|e| ConfigError::HistoryRecord {
        path: dir.clone(),
        message: format!("cannot create revision directory: {e}"),
    })?;

    let content_blake3 = blake3::hash(content.as_bytes()).to_hex().to_string();
    let artifact_path = dir.join("config.toml");
    write_new_file(&artifact_path, content.as_bytes()).map_err(|e| {
        ConfigError::HistoryRecord {
            path: artifact_path.clone(),
            message: format!("cannot write revision artifact: {e}"),
        }
    })?;

    let meta = RevisionMeta {
        revision,
        recorded_at_ms: now_ms,
        content_blake3: content_blake3.clone(),
        source_path: source.display().to_string(),
        previous_blake3: previous.map(|p| blake3::hash(p.as_bytes()).to_hex().to_string()),
    };
    let meta_text = toml::to_string_pretty(&meta).map_err(|e| ConfigError::HistoryRecord {
        path: dir.clone(),
        message: format!("cannot serialize revision metadata: {e}"),
    })?;
    let meta_path = dir.join("meta.toml");
    write_new_file(&meta_path, meta_text.as_bytes()).map_err(|e| ConfigError::HistoryRecord {
        path: meta_path.clone(),
        message: format!("cannot write revision metadata: {e}"),
    })?;

    Ok(RevisionRecord {
        revision,
        dir,
        content_blake3,
        recorded_at_ms: now_ms,
    })
}

/// Read the metadata of one recorded revision.
pub fn read_revision_meta(root: &Path, revision: u64) -> Result<RevisionMeta, ConfigError> {
    let dir = history_revision_dir(root, revision);
    let meta_path = dir.join("meta.toml");
    let text = fs::read_to_string(&meta_path).map_err(|e| ConfigError::HistoryRecord {
        path: meta_path.clone(),
        message: format!("cannot read revision metadata: {e}"),
    })?;
    toml::from_str(&text).map_err(|e| ConfigError::HistoryRecord {
        path: meta_path,
        message: format!("cannot parse revision metadata: {e}"),
    })
}

/// Commit an accepted artifact to `config_path` (KB-1 write path).
///
/// Order: strict validation → history record (fail-closed) → atomic staged
/// replace (`O_EXCL` temp in the same directory + fsync + rename) → best-effort
/// ledger emission (D8, never blocks). Nothing is written unless the content
/// is strictly valid; the previous file survives any failure byte-intact.
pub fn commit(
    config_path: &Path,
    content: &str,
    opts: &WriteOptions<'_>,
) -> Result<CommitOutcome, ConfigError> {
    // 1. Strict validation: the kernel never writes an artifact it would refuse.
    let loaded = load::load_from_str(content, Some(config_path.to_path_buf()));
    let cfg = match loaded.into_strict() {
        Ok(cfg) => cfg,
        Err(e) => return Err(e),
    };

    // 2. History record (fail-closed, D6) before the replace: an accepted
    //    write is never unrecorded. A failure here leaves the target untouched.
    let previous = fs::read_to_string(config_path).ok();
    let revision = match &opts.history {
        HistoryPolicy::Disabled => None,
        HistoryPolicy::At(dir) => Some(
            record_revision(
                dir,
                content,
                config_path,
                previous.as_deref(),
                unix_ms_now(),
            )?
            .revision,
        ),
        HistoryPolicy::DefaultLocation => {
            let dir = default_history_dir()?;
            Some(
                record_revision(
                    &dir,
                    content,
                    config_path,
                    previous.as_deref(),
                    unix_ms_now(),
                )?
                .revision,
            )
        }
    };

    // 3. Atomic staged replace.
    atomic_replace(config_path, content, opts.perms, cfg.has_secret_values())?;

    let content_blake3 = blake3::hash(content.as_bytes()).to_hex().to_string();
    let outcome = CommitOutcome {
        path: config_path.to_path_buf(),
        bytes: content.len(),
        content_blake3: content_blake3.clone(),
        revision,
    };

    // 4. Ledger seam (D8): best-effort — a broken journal is a doctor warning,
    //    never a blocked write.
    if let Some(sink) = opts.ledger {
        let event = ConfigWriteEvent {
            path: outcome.path.clone(),
            bytes: outcome.bytes,
            revision: outcome.revision,
            content_blake3,
        };
        if let Err(e) = sink.record_config_write(&event) {
            tracing::debug!(
                "config ledger seam (best-effort, D8; doctor-warning follow-up KB-6): {e}"
            );
        }
    }

    Ok(outcome)
}

// ── Internals ────────────────────────────────────────────────────────────────

fn unix_ms_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// Create the directory (and parents) owner-only on unix when we create it.
fn ensure_dir_secure(dir: &Path) -> std::io::Result<()> {
    if dir.is_dir() {
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(KERNEL_DIR_MODE)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir_all(dir)
    }
}

/// Tighten existing loose group/other bits on a kernel-managed directory
/// (D6: dir 0700). Best-effort with a warning — the *files* we create are
/// always created with the right mode.
fn tighten_dir(dir: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(meta) = fs::metadata(dir) {
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                if let Err(e) = fs::set_permissions(dir, fs::Permissions::from_mode(KERNEL_DIR_MODE))
                {
                    tracing::warn!(
                        path = ?dir,
                        mode = format!("{mode:o}"),
                        "config-history directory is not owner-only and could not be tightened: {e}"
                    );
                }
            }
        }
    }
    #[cfg(not(unix))]
    let _ = dir;
}

fn create_dir_owner_only(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new().mode(KERNEL_DIR_MODE).create(dir)
    }
    #[cfg(not(unix))]
    {
        fs::create_dir(dir)
    }
}

/// Create a brand-new file with owner-only mode on unix (never follows a
/// pre-existing path: `create_new` is `O_EXCL`).
fn write_new_file(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(CONFIG_FILE_MODE);
    }
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Atomic staged replace: temp file in the same directory (`O_EXCL` + mode),
/// fsync, rename over the target, fsync the directory.
fn atomic_replace(
    path: &Path,
    content: &str,
    perms: FilePermsPolicy,
    secret_bearing: bool,
) -> Result<(), ConfigError> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    ensure_dir_secure(parent).map_err(|e| ConfigError::Write {
        path: path.to_path_buf(),
        message: format!("cannot create/verify parent directory {}: {e}", parent.display()),
    })?;

    let file_name = path.file_name().ok_or_else(|| ConfigError::Write {
        path: path.to_path_buf(),
        message: "config path has no file name".to_string(),
    })?;

    let tmp_path = parent.join(unique_temp_name(&file_name.to_string_lossy()));

    let write_result = (|| -> std::io::Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(perms.temp_mode(secret_bearing));
        }
        #[cfg(not(unix))]
        let _ = (perms, secret_bearing);
        let mut file = options.open(&tmp_path)?;
        file.write_all(content.as_bytes())?;
        file.sync_all()?;
        Ok(())
    })();

    if let Err(e) = write_result {
        let _ = fs::remove_file(&tmp_path);
        return Err(ConfigError::Write {
            path: path.to_path_buf(),
            message: format!("staging temp file failed: {e}"),
        });
    }

    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(ConfigError::Write {
            path: path.to_path_buf(),
            message: format!("rename over target failed: {e}"),
        });
    }

    // Durability of the rename itself (best-effort: not all platforms allow
    // opening a directory as a File).
    #[cfg(unix)]
    {
        if let Ok(dir_file) = File::open(parent) {
            let _ = dir_file.sync_all();
        }
    }

    Ok(())
}

fn unique_temp_name(base: &str) -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!(".{base}.tmp.{}.{n}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    const VALID: &str = "schema_version = 1\nno_color = true\n";

    #[derive(Default)]
    struct RecordingSink {
        events: Mutex<Vec<ConfigWriteEvent>>,
    }

    impl LedgerSink for RecordingSink {
        fn record_config_write(&self, ev: &ConfigWriteEvent) -> Result<(), String> {
            self.events.lock().expect("lock").push(ev.clone());
            Ok(())
        }
    }

    struct FailingSink;

    impl LedgerSink for FailingSink {
        fn record_config_write(&self, _ev: &ConfigWriteEvent) -> Result<(), String> {
            Err("journal unwritable (simulated)".to_string())
        }
    }

    fn opts_at(dir: &Path) -> WriteOptions<'static> {
        WriteOptions::with_history_dir(dir.to_path_buf()).without_ledger()
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).expect("metadata").permissions().mode() & 0o777
    }

    #[test]
    fn commit_writes_content_and_leaves_no_temp_files() {
        let tmp = crate::config::test_support::TempDir::new("commit");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");

        let outcome = commit(&target, VALID, &opts_at(&hist)).expect("commit");
        assert_eq!(outcome.revision, Some(1));
        assert_eq!(outcome.bytes, VALID.len());
        assert_eq!(fs::read_to_string(&target).expect("read"), VALID);

        let leftovers: Vec<String> = fs::read_dir(tmp.path())
            .expect("dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(leftovers.is_empty(), "temp files left behind: {leftovers:?}");
    }

    #[test]
    fn commit_refuses_invalid_content_and_keeps_previous_file() {
        let tmp = crate::config::test_support::TempDir::new("refuse");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");

        commit(&target, VALID, &opts_at(&hist)).expect("first commit");
        let before = fs::read_to_string(&target).expect("read");

        let bad = "schema_version = 1\nbogus_key = true\n";
        let err = commit(&target, bad, &opts_at(&hist)).expect_err("must refuse");
        assert_eq!(err.code(), crate::config::schema::CODE_REFUSED, "{err}");
        assert!(err.to_string().contains("bogus_key"), "{err}");
        assert_eq!(fs::read_to_string(&target).expect("read"), before);
        // Refused content is not recorded either.
        assert_eq!(latest_revision(&hist).expect("latest"), Some(1));
    }

    #[test]
    fn commit_replaces_atomically_content_swaps() {
        let tmp = crate::config::test_support::TempDir::new("replace");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");

        commit(&target, "schema_version = 1\nno_color = true\n", &opts_at(&hist)).expect("c1");
        let second = "schema_version = 1\nno_color = false\ntelemetry = true\n";
        commit(&target, second, &opts_at(&hist)).expect("c2");
        assert_eq!(fs::read_to_string(&target).expect("read"), second);
        // Still exactly one artifact + no temp files.
        let mut files: Vec<String> = fs::read_dir(tmp.path())
            .expect("dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        files.sort();
        assert_eq!(files, vec!["config.toml".to_string(), "hist".to_string()]);
    }

    #[test]
    fn commit_fails_when_parent_is_a_file_and_writes_nothing() {
        let tmp = crate::config::test_support::TempDir::new("blocked");
        let hist = tmp.join("hist");
        let blocker = tmp.join("blocker");
        fs::write(&blocker, "not a directory").expect("blocker");
        let target = blocker.join("config.toml");

        let err = commit(&target, VALID, &opts_at(&hist)).expect_err("blocked parent");
        assert_eq!(err.code(), crate::config::schema::CODE_WRITE_IO, "{err}");
        assert!(!target.exists());
        // No partial artifact anywhere: the blocker is still a file with its
        // original content.
        assert_eq!(fs::read_to_string(&blocker).expect("read"), "not a directory");
    }

    #[test]
    fn commit_failure_leaves_no_temp_in_directory() {
        let tmp = crate::config::test_support::TempDir::new("notmp");
        let hist = tmp.join("hist");
        // Target directory exists but the *history* is blocked, so commit
        // fails before staging; directory must stay clean.
        let hist_blocker = tmp.join("hist-blocker");
        fs::write(&hist_blocker, "file").expect("hist blocker");
        let target = tmp.join("config.toml");
        let err = commit(&target, VALID, &opts_at(&hist_blocker)).expect_err("hist blocked");
        assert_eq!(err.code(), crate::config::schema::CODE_HISTORY_PATH, "{err}");
        assert!(!target.exists(), "fail-closed: no artifact without a record");
        let entries: Vec<String> = fs::read_dir(tmp.path())
            .expect("dir")
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n.contains(".tmp."))
            .collect();
        assert!(entries.is_empty(), "temp files: {entries:?}");
        let _ = hist;
    }

    #[test]
    fn unix_config_file_is_owner_only_by_default() {
        let tmp = crate::config::test_support::TempDir::new("perms");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");
        commit(&target, VALID, &opts_at(&hist)).expect("commit");
        #[cfg(unix)]
        assert_eq!(mode_of(&target), CONFIG_FILE_MODE, "0600 for config artifacts");
        let _ = target;
    }

    #[test]
    fn perms_policy_matrix_is_explicit() {
        assert_eq!(
            FilePermsPolicy::OwnerOnlyAlways.temp_mode(false),
            CONFIG_FILE_MODE
        );
        assert_eq!(
            FilePermsPolicy::OwnerOnlyAlways.temp_mode(true),
            CONFIG_FILE_MODE
        );
        assert_eq!(
            FilePermsPolicy::OwnerOnlyWhenSecretBearing.temp_mode(true),
            CONFIG_FILE_MODE
        );
        assert_eq!(
            FilePermsPolicy::OwnerOnlyWhenSecretBearing.temp_mode(false),
            LOOSE_FILE_MODE
        );
    }

    #[test]
    fn secret_bearing_file_is_0600_under_loose_policy() {
        let tmp = crate::config::test_support::TempDir::new("secretperms");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");
        let content = "schema_version = 1\n[secrets]\ntok = \"env:TALLOW_X\"\n";
        let opts = WriteOptions {
            history: HistoryPolicy::At(hist),
            perms: FilePermsPolicy::OwnerOnlyWhenSecretBearing,
            ledger: None,
        };
        commit(&target, content, &opts).expect("commit secret-bearing");
        #[cfg(unix)]
        assert_eq!(
            mode_of(&target),
            CONFIG_FILE_MODE,
            "secret-bearing artifacts are always 0600"
        );
        let _ = target;
    }

    #[test]
    fn history_revision_recorded_with_meta_and_perms() {
        let tmp = crate::config::test_support::TempDir::new("hist");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");

        let outcome = commit(&target, VALID, &opts_at(&hist)).expect("commit");
        assert_eq!(outcome.revision, Some(1));
        let rev_dir = history_revision_dir(&hist, 1);
        assert!(rev_dir.is_dir());
        assert_eq!(
            fs::read_to_string(rev_dir.join("config.toml")).expect("artifact"),
            VALID
        );
        let meta = read_revision_meta(&hist, 1).expect("meta");
        assert_eq!(meta.revision, 1);
        assert_eq!(
            meta.content_blake3,
            blake3::hash(VALID.as_bytes()).to_hex().to_string()
        );
        assert_eq!(meta.source_path, target.display().to_string());
        assert!(meta.recorded_at_ms > 0);
        assert!(meta.previous_blake3.is_none(), "first revision has no chain");

        #[cfg(unix)]
        {
            assert_eq!(mode_of(&hist), 0o700, "history root 0700 (D6)");
            assert_eq!(mode_of(&rev_dir), 0o700, "revision dir 0700 (D6)");
            assert_eq!(mode_of(&rev_dir.join("config.toml")), 0o600);
            assert_eq!(mode_of(&rev_dir.join("meta.toml")), 0o600);
        }

        // Second commit chains the previous hash.
        let second = "schema_version = 1\nno_color = false\n";
        commit(&target, second, &opts_at(&hist)).expect("commit 2");
        let meta2 = read_revision_meta(&hist, 2).expect("meta2");
        assert_eq!(
            meta2.previous_blake3.as_deref(),
            Some(blake3::hash(VALID.as_bytes()).to_hex().to_string().as_str())
        );
        assert_eq!(latest_revision(&hist).expect("latest"), Some(2));
    }

    #[test]
    fn revision_numbers_are_monotonic_over_existing_store() {
        let tmp = crate::config::test_support::TempDir::new("mono");
        let hist = tmp.join("hist");
        fs::create_dir_all(&hist).expect("hist");
        // Pre-seed a store (KB-3 style): numeric dirs count, junk is ignored.
        fs::create_dir(history_revision_dir(&hist, 1)).expect("r1");
        fs::create_dir(history_revision_dir(&hist, 3)).expect("r3");
        fs::create_dir(hist.join("junk-name")).expect("junk");
        fs::create_dir(hist.join("000002-backup")).expect("legacy");
        assert_eq!(latest_revision(&hist).expect("latest"), Some(3));
        assert_eq!(next_revision(&hist).expect("next"), 4);

        let target = tmp.join("config.toml");
        let outcome = commit(&target, VALID, &opts_at(&hist)).expect("commit");
        assert_eq!(outcome.revision, Some(4), "no reuse of existing revisions");
    }

    #[test]
    fn history_failure_refuses_write_fail_closed() {
        let tmp = crate::config::test_support::TempDir::new("histfail");
        let blocker = tmp.join("hist-blocker");
        fs::write(&blocker, "a file, not a dir").expect("blocker");
        let target = tmp.join("config.toml");

        let err = commit(&target, VALID, &opts_at(&blocker)).expect_err("refused");
        assert_eq!(err.code(), crate::config::schema::CODE_HISTORY_PATH, "{err}");
        assert!(!target.exists(), "no unrecorded accepted write");
    }

    #[test]
    fn history_can_be_disabled_only_explicitly() {
        let tmp = crate::config::test_support::TempDir::new("nohist");
        let target = tmp.join("config.toml");
        let opts = WriteOptions::default().without_history().without_ledger();
        let outcome = commit(&target, VALID, &opts).expect("commit");
        assert_eq!(outcome.revision, None);
        assert_eq!(fs::read_to_string(&target).expect("read"), VALID);
    }

    #[test]
    fn default_history_dir_matches_d6_and_revision_dir_pads() {
        let dir = default_history_dir().expect("resolve");
        assert!(dir.ends_with("tallow/config-history"), "{dir:?}");
        if let Some(state) = dirs::state_dir() {
            assert!(dir.starts_with(state), "{dir:?}");
        } else if let Some(home) = dirs::home_dir() {
            assert!(dir.starts_with(home.join(".local/state")), "{dir:?}");
        }
        assert_eq!(
            history_revision_dir(Path::new("/r"), 7),
            PathBuf::from("/r/000007")
        );
        assert_eq!(
            history_revision_dir(Path::new("/r"), 1234567),
            PathBuf::from("/r/1234567"),
            "wider than the pad is preserved"
        );
    }

    #[test]
    fn ledger_seam_records_event_without_values() {
        let tmp = crate::config::test_support::TempDir::new("ledger");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");
        let sink = RecordingSink::default();
        let opts = WriteOptions::with_history_dir(hist.clone()).with_ledger(&sink);

        let outcome = commit(&target, VALID, &opts).expect("commit");
        let events = sink.events.lock().expect("lock");
        assert_eq!(events.len(), 1, "one accepted write → one ledger record");
        let ev = &events[0];
        assert_eq!(ev.path, target);
        assert_eq!(ev.bytes, VALID.len());
        assert_eq!(ev.revision, outcome.revision);
        assert_eq!(ev.content_blake3, outcome.content_blake3);
    }

    #[test]
    fn ledger_failure_never_blocks_commit() {
        let tmp = crate::config::test_support::TempDir::new("ledgerfail");
        let hist = tmp.join("hist");
        let target = tmp.join("config.toml");
        let sink = FailingSink;
        let opts = WriteOptions::with_history_dir(hist).with_ledger(&sink);

        let outcome = commit(&target, VALID, &opts).expect("best-effort (D8)");
        assert_eq!(outcome.revision, Some(1));
        assert_eq!(fs::read_to_string(&target).expect("read"), VALID);
    }

    #[test]
    fn read_revision_meta_is_typed_on_missing_revision() {
        let tmp = crate::config::test_support::TempDir::new("nometa");
        let err = read_revision_meta(tmp.path(), 42).expect_err("missing");
        assert_eq!(err.code(), crate::config::schema::CODE_HISTORY_RECORD);
    }

    #[test]
    fn write_options_defaults_are_production_posture() {
        let opts = WriteOptions::new();
        assert_eq!(opts.history, HistoryPolicy::DefaultLocation, "D6 default on");
        assert_eq!(opts.perms, FilePermsPolicy::OwnerOnlyAlways, "0600 default");
        assert!(opts.ledger.is_some(), "journal ledger on by default");
    }
}
