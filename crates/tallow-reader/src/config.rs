//! Reader daemon configuration + its persisted secret (bearer token).
//!
//! U-219: the reader's secret write path adopts the hardened secret-file
//! discipline established by the daemon (`crates/tallow-daemon/src/config.rs`,
//! T-120 / R-5.2A) and takes it one step further for the reader: the token is
//! written to a sibling temp file created `O_EXCL` (`create_new`) with
//! owner-only permissions at creation, fsynced, and then atomically renamed
//! over the target. A reader token is only ever observed as a complete,
//! owner-only file, and every surprise on the write path is a typed refusal —
//! never a silent clobber, adopt, or partial write. The read side and the
//! public schema/behaviour are unchanged.

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use anyhow::Context;
use rand::Rng;

/// Daemon configuration. Token + port persisted to `~/.tallow/reader/`.
/// Token is a 64-char hex bearer token generated on first run (0600 perms)
/// and written via the hardened secret-write path (U-219).
#[derive(Debug, Clone)]
pub struct Config {
    pub data_dir: PathBuf,
    pub token: String,
    pub token_path: PathBuf,
    pub port_file: PathBuf,
    pub port: u16,
    pub bind_addr: String,
    pub pool_max_size: usize,
    pub pool_tor_instances: usize,
    pub extract_timeout_secs: u64,
}

/// Typed failures of the hardened secret-write path (U-219). Every surprise is
/// a refusal: an existing temp is never clobbered or adopted, and a failed
/// write never leaves a partial secret behind. Error text carries paths and
/// OS errors only — never secret material.
#[derive(Debug, thiserror::Error)]
pub enum SecretWriteError {
    /// `O_EXCL` temp collision: the temp path already exists (stale file from a
    /// crashed run, another writer, or a pre-created path). Refused without
    /// touching either the temp or the target.
    #[error(
        "refusing secret write: temp file already exists at {path:?} \
         (O_EXCL collision); temp and target left untouched"
    )]
    TempExists { path: PathBuf },

    /// The target path has no parent directory, so no sibling temp (and thus
    /// no atomic rename within the same directory) is possible.
    #[error("refusing secret write: target path has no parent directory: {path:?}")]
    NoParentDir { path: PathBuf },

    /// Creating the O_EXCL temp file failed for a reason other than collision.
    #[error("failed to create secret temp file {path:?} (O_EXCL, mode 0600): {source}")]
    CreateTemp {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Setting owner-only permissions on the temp file failed.
    #[error("failed to set owner-only (0600) permissions on secret temp file {path:?}: {source}")]
    ChmodTemp {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Writing the secret bytes into the temp file failed.
    #[error("failed to write secret data to temp file {path:?}: {source}")]
    WriteTemp {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// fsync of the temp file failed — the secret is not durable, refuse.
    #[error("failed to fsync secret temp file {path:?}: {source}")]
    SyncTemp {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// The final atomic rename over the target failed. The temp (fully written)
    /// is removed best-effort; the target is untouched.
    #[error("failed to atomically rename secret temp {tmp:?} over {target:?}: {source}")]
    Rename {
        tmp: PathBuf,
        target: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

/// Derive a unique sibling temp path in the **same directory** as `target`
/// (same filesystem → the final `rename` is atomic). Unique per call — pid +
/// wall-clock nanos + a process-local counter — so a leftover temp from a
/// crashed run never blocks future writes; an `O_EXCL` collision therefore is
/// a path we did not create, and it is refused, never clobbered.
fn temp_sibling(target: &Path) -> Result<PathBuf, SecretWriteError> {
    use std::sync::atomic::{AtomicU64, Ordering};

    static SEQ: AtomicU64 = AtomicU64::new(0);

    let dir = match target.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
        // A bare relative filename — the sibling lives in the current dir.
        Some(_) => PathBuf::from("."),
        None => {
            return Err(SecretWriteError::NoParentDir {
                path: target.to_path_buf(),
            });
        }
    };
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "secret".to_string());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    Ok(dir.join(format!(".{name}.tmp.{}.{nanos}.{seq}", std::process::id())))
}

/// Hardened secret write (U-219; adopted from the daemon T-120 discipline,
/// audit-04 F-5 / R-5.2A): create `tmp` with `O_EXCL` (`create_new(true)`) and
/// owner-only 0600 permissions **at creation** — no create-then-chmod window —
/// write the secret, fsync, then atomically `rename` it over `target`. The
/// target is only ever a complete, owner-only secret; `rename` does not follow
/// a symlink at the target, so a pre-planted symlink is replaced, not written
/// through. Any failure after the temp was created best-effort-removes it (we
/// own it via O_EXCL, so cleanup cannot clobber another writer's file).
///
/// The temp path is a parameter so tests can pin it to exercise the typed
/// collision/failure paths deterministically.
fn write_secret_atomic(
    target: &Path,
    tmp: &Path,
    secret: &str,
) -> Result<(), SecretWriteError> {
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true); // O_CREAT | O_EXCL
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = match opts.open(tmp) {
        Ok(file) => file,
        Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {
            return Err(SecretWriteError::TempExists {
                path: tmp.to_path_buf(),
            });
        }
        Err(source) => {
            return Err(SecretWriteError::CreateTemp {
                path: tmp.to_path_buf(),
                source,
            });
        }
    };

    // From here on the temp file is ours; on any failure remove it so no
    // partial secret survives.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Belt-and-braces: the creation mode is masked by umask; fchmod on the
        // open handle makes 0600 exact — still with no path-level window.
        if let Err(source) = file.set_permissions(fs::Permissions::from_mode(0o600)) {
            return Err(discard_temp(
                SecretWriteError::ChmodTemp {
                    path: tmp.to_path_buf(),
                    source,
                },
                tmp,
            ));
        }
    }
    if let Err(source) = file.write_all(secret.as_bytes()) {
        return Err(discard_temp(
            SecretWriteError::WriteTemp {
                path: tmp.to_path_buf(),
                source,
            },
            tmp,
        ));
    }
    if let Err(source) = file.sync_all() {
        return Err(discard_temp(
            SecretWriteError::SyncTemp {
                path: tmp.to_path_buf(),
                source,
            },
            tmp,
        ));
    }
    drop(file); // close before rename (keeps the write window explicit)

    if let Err(source) = fs::rename(tmp, target) {
        return Err(discard_temp(
            SecretWriteError::Rename {
                tmp: tmp.to_path_buf(),
                target: target.to_path_buf(),
                source,
            },
            tmp,
        ));
    }

    // Best-effort: fsync the containing directory so the rename itself is
    // durable across a crash. Not fatal — some filesystems refuse dir fsync,
    // and the secret is already complete and atomically in place.
    #[cfg(unix)]
    {
        let dir = match target.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => Some(parent.to_path_buf()),
            Some(_) => Some(PathBuf::from(".")),
            None => None,
        };
        if let Some(dir) = dir {
            if let Ok(handle) = fs::File::open(dir) {
                let _ = handle.sync_all();
            }
        }
    }

    Ok(())
}

/// Best-effort removal of a temp file we created, after a failure: the typed
/// error is what the caller sees; the partial secret must not survive.
fn discard_temp(err: SecretWriteError, tmp: &Path) -> SecretWriteError {
    let _ = fs::remove_file(tmp);
    err
}

impl Config {
    /// Load or create configuration on daemon startup.
    /// Generates a 64-char hex bearer token on first run and persists it to
    /// disk via the hardened secret-write path (`O_EXCL` temp → fsync →
    /// atomic rename, mode 0600).
    pub fn load_or_create() -> anyhow::Result<Self> {
        let data_dir = dirs::data_dir()
            .context("failed to determine user data directory")?
            .join("tallow")
            .join("reader");

        fs::create_dir_all(&data_dir).context("failed to create reader data directory")?;

        let token_path = data_dir.join("token");
        let port_file = data_dir.join("port");

        let token = if token_path.exists() {
            fs::read_to_string(&token_path)
                .context("failed to read token file")?
                .trim()
                .to_string()
        } else {
            let new_token = Self::generate_token();
            // U-219 hardened write: a failure here is a hard error (typed
            // SecretWriteError inside) — never a silent fallback.
            Self::write_token_file(&token_path, &new_token).with_context(|| {
                format!(
                    "failed to persist reader token to {} (O_EXCL temp + atomic rename, mode 0600)",
                    token_path.display()
                )
            })?;
            new_token
        };

        Ok(Self {
            data_dir,
            token,
            token_path,
            port_file,
            port: 0,
            bind_addr: String::new(),
            pool_max_size: 4,
            pool_tor_instances: 1,
            extract_timeout_secs: 60,
        })
    }

    /// Generate a 64-character hex token from 32 random bytes.
    pub fn generate_token() -> String {
        let mut bytes = [0u8; 32];
        rand::rng().fill(&mut bytes);
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }

    /// Persist `token` to `token_path` with the hardened secret-write
    /// discipline (U-219): unique sibling temp created `O_EXCL` with mode 0600
    /// at creation, secret written and fsynced, then atomically renamed over
    /// the target. Replacing an existing token is atomic — readers of the path
    /// only ever see a complete, owner-only file.
    fn write_token_file(token_path: &Path, token: &str) -> Result<(), SecretWriteError> {
        let tmp = temp_sibling(token_path)?;
        write_secret_atomic(token_path, &tmp, token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().expect("tempdir")
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).expect("stat").permissions().mode() & 0o777
    }

    fn dir_entries(dir: &Path) -> Vec<String> {
        let mut names: Vec<String> = fs::read_dir(dir)
            .expect("read_dir")
            .map(|entry| {
                entry
                    .expect("dir entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        names
    }

    // ── U-219: hardened secret writes (O_EXCL temp → fsync → atomic rename) ──

    #[test]
    fn fresh_token_write_is_0600_and_leaves_no_temp() {
        let dir = tempdir();
        let target = dir.path().join("token");
        let token = Config::generate_token();
        assert_eq!(token.len(), 64, "token stays a 64-char hex string");
        assert!(
            token.chars().all(|c| c.is_ascii_hexdigit()),
            "token stays hex: {token}"
        );

        Config::write_token_file(&target, &token).expect("fresh write");

        assert_eq!(fs::read_to_string(&target).expect("read token"), token);
        #[cfg(unix)]
        assert_eq!(mode_of(&target), 0o600, "fresh token file must be 0600");
        assert_eq!(
            dir_entries(dir.path()),
            vec!["token".to_string()],
            "no temp leftovers after a successful write"
        );
    }

    #[test]
    fn atomic_replace_over_existing_token() {
        let dir = tempdir();
        let target = dir.path().join("token");
        fs::write(&target, "old-token-complete").expect("seed");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o644)).expect("loosen");
        }

        let new_token = Config::generate_token();
        Config::write_token_file(&target, &new_token).expect("replace");

        assert_eq!(
            fs::read_to_string(&target).expect("read token"),
            new_token,
            "target atomically replaced with the new token"
        );

        // Temp names are unique per call (pid + nanos + counter), so repeated
        // writes in the same process never collide with their own leftovers.
        let newer_token = Config::generate_token();
        Config::write_token_file(&target, &newer_token).expect("second replace");
        assert_eq!(
            fs::read_to_string(&target).expect("read token"),
            newer_token,
            "second atomic replace lands"
        );

        #[cfg(unix)]
        assert_eq!(
            mode_of(&target),
            0o600,
            "replacement is owner-only even if the old file was 0644"
        );
        assert_eq!(
            dir_entries(dir.path()),
            vec!["token".to_string()],
            "no temp leftovers after a replace"
        );
    }

    #[test]
    fn temp_collision_is_typed_refusal_and_nothing_is_clobbered() {
        let dir = tempdir();
        let target = dir.path().join("token");
        fs::write(&target, "old-token-complete").expect("seed target");
        let tmp = dir.path().join(".token.tmp.pinned");
        fs::write(&tmp, "not-ours").expect("seed temp");

        let err =
            write_secret_atomic(&target, &tmp, "new-secret").expect_err("collision must refuse");
        match err {
            SecretWriteError::TempExists { path } => assert_eq!(path, tmp),
            other => panic!("expected typed SecretWriteError::TempExists, got: {other:?}"),
        }

        assert_eq!(
            fs::read_to_string(&target).expect("read"),
            "old-token-complete",
            "target untouched on temp collision"
        );
        assert_eq!(
            fs::read_to_string(&tmp).expect("read temp"),
            "not-ours",
            "foreign temp never clobbered or removed"
        );
    }

    #[test]
    fn failure_after_write_leaves_no_partial_secret_and_cleans_temp() {
        // Simulate a failure at the last step: rename(2) refuses to rename a
        // file over an existing directory (EISDIR). The temp gets fully
        // written + fsynced, then the atomic swap fails — the error must be
        // typed, the target untouched, and no partial temp left behind.
        let dir = tempdir();
        let target = dir.path().join("token-target");
        fs::create_dir(&target).expect("mkdir target");
        let tmp = dir.path().join(".token.tmp.pinned");

        let err = write_secret_atomic(&target, &tmp, "written-but-never-visible")
            .expect_err("rename over a directory must fail");
        match err {
            SecretWriteError::Rename {
                tmp: e_tmp,
                target: e_target,
                ..
            } => {
                assert_eq!(e_tmp, tmp);
                assert_eq!(e_target, target);
            }
            other => panic!("expected typed SecretWriteError::Rename, got: {other:?}"),
        }

        assert!(
            !tmp.exists(),
            "temp must be cleaned up — no partial secret left behind"
        );
        assert!(target.is_dir(), "target untouched");
        assert_eq!(
            dir_entries(dir.path()),
            vec!["token-target".to_string()],
            "directory contains no leftovers"
        );
    }

    #[test]
    fn missing_temp_directory_is_typed_create_failure_target_untouched() {
        let dir = tempdir();
        let target = dir.path().join("token");
        fs::write(&target, "old-token-complete").expect("seed");
        let tmp = dir.path().join("no-such-dir").join(".token.tmp");

        let err = write_secret_atomic(&target, &tmp, "new-secret")
            .expect_err("missing temp directory must fail");
        match err {
            SecretWriteError::CreateTemp { path, .. } => assert_eq!(path, tmp),
            other => panic!("expected typed SecretWriteError::CreateTemp, got: {other:?}"),
        }

        assert_eq!(
            fs::read_to_string(&target).expect("read"),
            "old-token-complete",
            "target untouched on create failure"
        );
        assert_eq!(
            dir_entries(dir.path()),
            vec!["token".to_string()],
            "nothing created"
        );
    }

    #[test]
    fn parentless_target_is_typed_refusal() {
        let err = Config::write_token_file(Path::new("/"), "deadbeef")
            .expect_err("a path without a parent directory must refuse");
        match err {
            SecretWriteError::NoParentDir { path } => assert_eq!(path, PathBuf::from("/")),
            other => panic!("expected typed SecretWriteError::NoParentDir, got: {other:?}"),
        }
    }
}
