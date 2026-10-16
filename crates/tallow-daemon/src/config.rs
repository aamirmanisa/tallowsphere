use std::fs::{self, OpenOptions};
use std::fmt;
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use rand::Rng;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind_addr: String,
    pub port: u16,
    /// Managed token loaded/created from `token_path`. Read it through
    /// [`Config::resolve_token`] — an external `TALLOW_DAEMON_TOKEN` source
    /// (plaintext or an `env:`/`file:` secret reference, R-7.5) takes
    /// precedence and is resolved lazily at use time.
    pub token: String,
    pub data_dir: PathBuf,
    pub token_path: PathBuf,
    pub port_file: PathBuf,
    pub db_path: PathBuf,
    /// Optional override for the `tallow` binary used to execute
    /// `tallow_script` jobs (env `TALLOW_DAEMON_TALLOW_BIN`). When unset the
    /// executor discovers it next to the daemon binary or on PATH.
    pub tallow_bin: Option<PathBuf>,
    pub concurrency_limit: usize,
    pub retry_base_ms: u64,
    pub retry_max_ms: u64,
    pub retry_jitter_ms: u64,
    pub bandwidth_limit_bytes_per_sec: u64,
    pub bandwidth_schedule: Vec<(String, String, u64)>,
    pub watch_dirs: Vec<PathBuf>,
    pub debounce_delay_ms: u64,
    pub debounce_large_file_ms: u64,
    pub large_file_threshold_bytes: u64,
}

/// Environment variable through which an operator points the daemon at an
/// external bearer-token source instead of the managed token file. The value
/// may be a secret *reference* (`env:NAME`, `file:/path`) — resolved lazily at
/// use time (R-7.5) — or a plaintext token (passthrough, unchanged).
pub const TOKEN_ENV: &str = "TALLOW_DAEMON_TOKEN";

/// A secret value in config, stored **by reference** (R-7.5).
///
/// - `env:NAME` — read environment variable `NAME` when the value is used.
/// - `file:/path` — read `/path` when the value is used; the file must be a
///   regular file (no symlinks/dirs) and is tightened to 0600 before its
///   contents are trusted (same policy as the managed token file, R-5.2A).
/// - anything else — inline plaintext, passthrough unchanged (`Plain`).
///
/// Resolution happens at **use** time, never at parse/load: a rotated env
/// value or file is picked up on the next use, and a broken reference is a
/// hard error at that point — never a silent default or fallback.
#[derive(Clone, PartialEq, Eq)]
pub enum SecretRef {
    /// Inline plaintext value (legacy form — unchanged behaviour).
    Plain(String),
    /// `env:NAME` — resolve from the process environment.
    Env { name: String },
    /// `file:/path` — resolve from an owner-only file on disk.
    File { path: PathBuf },
}

impl SecretRef {
    /// Parse a config value into a secret reference. Only the exact `env:` /
    /// `file:` prefixes are special; everything else is plaintext passthrough.
    pub fn parse(raw: &str) -> Self {
        if let Some(name) = raw.strip_prefix("env:") {
            Self::Env { name: name.to_string() }
        } else if let Some(path) = raw.strip_prefix("file:") {
            Self::File { path: PathBuf::from(path) }
        } else {
            Self::Plain(raw.to_string())
        }
    }

    /// True when the value is a reference rather than inline plaintext.
    pub fn is_reference(&self) -> bool {
        !matches!(self, Self::Plain(_))
    }

    /// Resolve the secret **at use time**. Failures are hard errors — callers
    /// must refuse the operation, never fall back to a default value. The
    /// resolved value must never be logged.
    pub fn resolve(&self) -> anyhow::Result<String> {
        match self {
            Self::Plain(value) => Ok(value.clone()),
            Self::Env { name } => {
                if name.is_empty() {
                    anyhow::bail!("secret reference `env:` has an empty variable name (R-7.5)");
                }
                let value = std::env::var(name).map_err(|_| {
                    anyhow::anyhow!(
                        "secret reference `env:{name}` is not set in the environment (R-7.5)"
                    )
                })?;
                if value.trim().is_empty() {
                    anyhow::bail!(
                        "secret reference `env:{name}` resolved to an empty value (R-7.5)"
                    );
                }
                Ok(value)
            }
            Self::File { path } => read_owner_only_file(path, "secret file"),
        }
    }
}

/// `Debug` is redacted: inline plaintext never appears in logs or error text.
impl fmt::Debug for SecretRef {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plain(_) => f.write_str("SecretRef::Plain(<redacted>)"),
            Self::Env { name } => write!(f, "SecretRef::Env({name})"),
            Self::File { path } => write!(f, "SecretRef::File({path:?})"),
        }
    }
}

/// Read a secret from an owner-only regular file: no symlinks/dirs, loose
/// group/other bits are tightened to 0600 before the contents are trusted
/// (R-5.2A policy), and an empty value is refused. Shared by the managed
/// token file and `file:` secret references.
fn read_owner_only_file(path: &Path, what: &str) -> anyhow::Result<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = fs::symlink_metadata(path).with_context(|| format!("failed to stat {what}"))?;
        if !meta.file_type().is_file() {
            anyhow::bail!("{what} path is not a regular file (refusing symlink/dir): {path:?}");
        }
        let mode = meta.permissions().mode() & 0o777;
        if mode & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600)).with_context(|| {
                format!("{what} has group/other access and could not be tightened to 0600")
            })?;
            tracing::warn!(
                path = ?path,
                mode = format!("{mode:o}"),
                "{} permissions were not owner-only; tightened to 0600 (R-5.2A)",
                what
            );
        }
    }
    #[cfg(not(unix))]
    {
        if !path.is_file() {
            anyhow::bail!("{what} path is not a regular file: {path:?}");
        }
    }

    let value = fs::read_to_string(path)
        .with_context(|| format!("failed to read {what}"))?
        .trim()
        .to_string();
    if value.is_empty() {
        anyhow::bail!(
            "{what} is empty — refusing (empty secrets are hard errors, never a default; R-7.5)"
        );
    }
    Ok(value)
}

impl Config {
    /// Load or create configuration on daemon startup.
    /// Generates a 64-char hex bearer token on first run and persists to disk.
    pub fn load_or_create() -> anyhow::Result<Self> {
        let data_dir = dirs::data_dir()
            .context("failed to determine user data directory")?
            .join("tallow")
            .join("daemon");

        fs::create_dir_all(&data_dir)
            .context("failed to create daemon data directory")?;

        let db_path = data_dir.join("daemon.db");
        let token_path = data_dir.join("token");
        let port_file = data_dir.join("port");
        let token = if token_path.exists() {
            Self::load_token_file(&token_path).context("failed to load token file")?
        } else {
            let new_token = Self::generate_token();
            match Self::create_token_file(&token_path, &new_token) {
                Ok(()) => new_token,
                // Lost the first-run race: another process created the file
                // between the probe above and our O_EXCL open — adopt the
                // winner's file (re-checked) instead of clobbering it.
                Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => {
                    Self::load_token_file(&token_path)
                        .context("failed to load concurrently created token file")?
                }
                Err(err) => {
                    return Err(anyhow::Error::new(err))
                        .context("failed to create token file (O_EXCL, mode 0600)");
                }
            }
        };

        Ok(Self {
            port: 0, // OS assigns a random available port
            bind_addr: String::new(), // set after binding
            token,
            data_dir,
            token_path,
            port_file,
            db_path,
            tallow_bin: std::env::var("TALLOW_DAEMON_TALLOW_BIN")
                .ok()
                .filter(|s| !s.is_empty())
                .map(PathBuf::from),
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
        })
    }

    /// Generate a 64-character hex token from 32 random bytes.
    pub fn generate_token() -> String {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Resolve the effective bearer/PSK token **at use time** (R-7.5).
    ///
    /// Precedence: when `TALLOW_DAEMON_TOKEN` is set it is the source of
    /// record — its value is parsed as a [`SecretRef`], so `env:NAME` /
    /// `file:/path` stay references until this call (rotation is picked up
    /// without a restart) and a plaintext value passes through unchanged.
    /// Otherwise the managed token loaded/created at startup is returned.
    ///
    /// A reference that cannot be resolved is a hard error: callers must
    /// refuse the operation rather than falling back to a default. Never log
    /// the returned value.
    pub fn resolve_token(&self) -> anyhow::Result<String> {
        match std::env::var(TOKEN_ENV).ok().filter(|value| !value.trim().is_empty()) {
            Some(raw) => SecretRef::parse(raw.trim())
                .resolve()
                .context("failed to resolve TALLOW_DAEMON_TOKEN (R-7.5)"),
            None => Ok(self.token.clone()),
        }
    }

    /// Create the token file exclusively (`O_CREAT | O_EXCL`) with owner-only
    /// permissions (mode 0600) and write `token` into it (R-5.2A / audit-04
    /// F-5). `create_new(true)` refuses an existing file — or symlink —
    /// rather than adopting it, and `mode(0o600)` applies at creation so the
    /// token is never briefly readable through a create-then-chmod window.
    fn create_token_file(token_path: &Path, token: &str) -> std::io::Result<()> {
        let mut opts = OpenOptions::new();
        opts.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            opts.mode(0o600);
        }
        let mut file = opts.open(token_path)?;
        file.write_all(token.as_bytes())?;
        file.flush()?;
        Ok(())
    }

    /// Load the token, re-checking the file's permissions first — the load
    /// half of `O_EXCL`+0600 (R-5.2A / audit-04 F-5). A token file that
    /// became group/other-readable is tightened back to 0600 before its
    /// contents are trusted; a path that is not a regular file (symlink,
    /// directory) or a token that is empty refuses to load — an empty token
    /// would let `Authorization: Bearer ` verify against an empty secret.
    fn load_token_file(token_path: &Path) -> anyhow::Result<String> {
        read_owner_only_file(token_path, "token file")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_concurrency_limit_default() {
        let cfg = Config::load_or_create().expect("failed to load config");
        assert_eq!(cfg.concurrency_limit, 4, "default concurrency_limit should be 4");
    }

    #[test]
    fn test_retry_base_ms_default() {
        let cfg = Config::load_or_create().expect("failed to load config");
        assert_eq!(cfg.retry_base_ms, 1000, "default retry_base_ms should be 1000");
    }

    #[test]
    fn test_retry_max_ms_default() {
        let cfg = Config::load_or_create().expect("failed to load config");
        assert_eq!(cfg.retry_max_ms, 60000, "default retry_max_ms should be 60000");
    }

    #[test]
    fn test_retry_jitter_ms_default() {
        let cfg = Config::load_or_create().expect("failed to load config");
        assert_eq!(cfg.retry_jitter_ms, 500, "default retry_jitter_ms should be 500");
    }

    #[test]
    fn test_bandwidth_limit_default_is_zero() {
        let cfg = Config::load_or_create().expect("failed to load config");
        assert_eq!(
            cfg.bandwidth_limit_bytes_per_sec, 0,
            "default bandwidth_limit_bytes_per_sec should be 0 (unlimited)"
        );
    }

    #[test]
    fn test_bandwidth_schedule_default_is_empty() {
        let cfg = Config::load_or_create().expect("failed to load config");
        assert!(
            cfg.bandwidth_schedule.is_empty(),
            "default bandwidth_schedule should be empty"
        );
    }

    // ── R-5.2A token-file hygiene (pure helpers + tempdir; no env mutation) ──

    #[test]
    fn token_file_creation_is_exclusive_and_owner_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("token");
        let token = Config::generate_token();
        Config::create_token_file(&path, &token).expect("first create");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "token file must be created owner-only");
        }

        // O_EXCL: a second create at the same path refuses and leaves the
        // first file's contents untouched.
        let err = Config::create_token_file(&path, "deadbeef").expect_err("O_EXCL refuse");
        assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
        assert_eq!(fs::read_to_string(&path).expect("read"), token);
    }

    #[test]
    fn token_load_rechecks_and_tightens_loose_permissions() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("token");
        fs::write(&path, "61c33ed2").expect("seed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen");
        }

        let token = Config::load_token_file(&path).expect("load");
        assert_eq!(token, "61c33ed2");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "load re-check must tighten group/other access");
        }
    }

    #[test]
    fn token_load_refuses_empty_and_non_file_paths() {
        let dir = tempfile::tempdir().expect("tempdir");
        let empty = dir.path().join("empty");
        fs::write(&empty, "  \n").expect("seed empty");
        assert!(
            Config::load_token_file(&empty).is_err(),
            "empty token refused"
        );

        let as_dir = dir.path().join("dir");
        fs::create_dir(&as_dir).expect("mkdir");
        assert!(
            Config::load_token_file(&as_dir).is_err(),
            "non-file token path refused"
        );
    }

    #[cfg(unix)]
    #[test]
    fn token_load_refuses_symlink_token_path() {
        let dir = tempfile::tempdir().expect("tempdir");
        let real = dir.path().join("real");
        fs::write(&real, "61c33ed2").expect("seed");
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        assert!(
            Config::load_token_file(&link).is_err(),
            "symlinked token path refused"
        );
    }

    // ── R-7.5 secrets-by-reference (helper + use-time resolution) ──────────
    //
    // These tests mutate process-wide env vars (edition 2024: `unsafe`) and
    // serialize on `TOKEN_ENV_LOCK` so they never race each other.

    static TOKEN_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn test_config() -> Config {
        Config {
            bind_addr: String::new(),
            port: 0,
            token: "managed-token".to_string(),
            data_dir: PathBuf::from("/tmp/tallow-t120-data"),
            token_path: PathBuf::from("/tmp/tallow-t120-token"),
            port_file: PathBuf::from("/tmp/tallow-t120-port"),
            db_path: PathBuf::from("/tmp/tallow-t120-db"),
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
        }
    }

    #[test]
    fn secret_ref_env_resolves_at_use() {
        let _guard = TOKEN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let name = "TALLOW_T120_ENV_SECRET";
        unsafe { std::env::set_var(name, "env-ref-value-61c3") };
        let resolved = SecretRef::parse(&format!("env:{name}"))
            .resolve()
            .expect("env ref resolves");
        assert_eq!(resolved, "env-ref-value-61c3");
        unsafe { std::env::remove_var(name) };
    }

    #[test]
    fn secret_ref_file_resolves_and_tightens_to_0600() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("secret");
        fs::write(&path, "  file-ref-value\n").expect("seed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("loosen");
        }

        let resolved = SecretRef::parse(&format!("file:{}", path.display()))
            .resolve()
            .expect("file ref resolves");
        assert_eq!(resolved, "file-ref-value", "value trimmed, not empty");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "file ref load must tighten group/other access");
        }
    }

    #[test]
    fn secret_ref_missing_fails_hard_never_defaults() {
        let _guard = TOKEN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // env refs: unset variable, empty name.
        assert!(SecretRef::parse("env:TALLOW_T120_UNSET").resolve().is_err());
        assert!(SecretRef::parse("env:").resolve().is_err());

        // file refs: missing path, empty file, non-file path (dir).
        let dir = tempfile::tempdir().expect("tempdir");
        assert!(
            SecretRef::parse(&format!("file:{}", dir.path().join("nope").display()))
                .resolve()
                .is_err()
        );
        let empty = dir.path().join("empty");
        fs::write(&empty, "  \n").expect("seed empty");
        assert!(SecretRef::parse(&format!("file:{}", empty.display())).resolve().is_err());
        assert!(SecretRef::parse(&format!("file:{}", dir.path().display())).resolve().is_err());
    }

    #[test]
    fn secret_ref_plaintext_passthrough_unchanged() {
        let plain = SecretRef::parse("inline-token-42");
        assert!(!plain.is_reference());
        assert_eq!(plain.resolve().expect("plain resolves"), "inline-token-42");

        // Only the exact `env:`/`file:` prefixes are references.
        assert!(!SecretRef::parse("env").is_reference());
        assert_eq!(SecretRef::parse("env").resolve().expect("plain"), "env");
        assert!(!SecretRef::parse("file").is_reference());
        assert_eq!(SecretRef::parse("file").resolve().expect("plain"), "file");

        // Debug never leaks inline plaintext into logs/error text.
        let debug = format!("{:?}", SecretRef::parse("super-secret-plaintext"));
        assert!(
            !debug.contains("super-secret-plaintext"),
            "Debug must redact plaintext: {debug}"
        );
    }

    #[test]
    fn resolve_token_uses_reference_at_use_and_errors_hard() {
        let _guard = TOKEN_ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let cfg = test_config();

        // No external source → managed token, unchanged behaviour.
        unsafe { std::env::remove_var(TOKEN_ENV) };
        assert_eq!(cfg.resolve_token().expect("managed"), "managed-token");

        // A broken reference is a hard error — NOT a fallback to the managed token.
        unsafe { std::env::set_var(TOKEN_ENV, "env:TALLOW_T120_TOKEN_MISSING") };
        assert!(
            cfg.resolve_token().is_err(),
            "broken ref must be a hard error, never a silent default"
        );

        // A live reference is resolved lazily at use time: rotation is picked
        // up on the next call, no restart.
        unsafe { std::env::set_var("TALLOW_T120_TOKEN_SRC", "rotated-token-1") };
        unsafe { std::env::set_var(TOKEN_ENV, "env:TALLOW_T120_TOKEN_SRC") };
        assert_eq!(cfg.resolve_token().expect("env ref"), "rotated-token-1");
        unsafe { std::env::set_var("TALLOW_T120_TOKEN_SRC", "rotated-token-2") };
        assert_eq!(cfg.resolve_token().expect("rotated"), "rotated-token-2");

        // Plaintext override passes through unchanged.
        unsafe { std::env::set_var(TOKEN_ENV, "plain-override-token") };
        assert_eq!(cfg.resolve_token().expect("plain override"), "plain-override-token");

        unsafe { std::env::remove_var(TOKEN_ENV) };
        unsafe { std::env::remove_var("TALLOW_T120_TOKEN_SRC") };
    }
}
