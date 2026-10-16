//! The read-only contract of the KT log — the property the sluice anchor depends on.
//!
//! Why this lives here and not only beside the type: the **lib test target does not compile at this
//! revision** (`f3b34bef`; two pre-existing errors in unrelated test modules — `E0133`, `E0308`,
//! `E0425`), so the in-file unit tests in `src/kt_log.rs` cannot be run from a clean checkout. This
//! target compiles against the public API only, so it runs. The same three assertions are mirrored in
//! `src/kt_log.rs`; keep the two in step.
//!
//! The contract: a caller that may read the log but not write it (the anchor account) must be able to
//! open and verify it — `KtLog::open` is the *write* path (`create + append`, mode `0600`, tightening
//! group/other bits back to `0600`), so using it as a reader demanded write permission on the log and
//! undid any operator group-read grant on the next open.

use std::fs;
use std::path::PathBuf;
use tallow::kt_log::{KtError, KtLog};

fn scratch(name: &str) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join(name);
    (dir, path)
}

fn write_one(log_path: &std::path::Path, payload: &[u8]) {
    let mut log = KtLog::open(log_path).expect("the write path opens a fresh log");
    log.append_at(payload, 1_700_000_000_000).expect("append");
}

#[test]
fn read_only_open_reads_the_chain_and_leaves_the_mode_alone() {
    let (_dir, path) = scratch("kt.log");
    write_one(&path, b"first");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // An operator grants group read so a second account can verify. Reading must not undo it.
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).expect("chmod 0640");
    }

    let reader = KtLog::open_read_only(&path).expect("a reader opens the log");
    assert_eq!(reader.len(), 1, "the reader sees the whole chain");
    reader.verify_chain().expect("the chain verifies");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).expect("metadata").permissions().mode() & 0o777,
            0o640,
            "a read-only open must not tighten the mode"
        );
    }
}

#[test]
fn read_only_open_refuses_a_missing_log_instead_of_creating_one() {
    let (_dir, path) = scratch("absent.log");

    assert!(
        KtLog::open_read_only(&path).is_err(),
        "an absent log is an error for a reader"
    );
    assert!(
        !path.exists(),
        "a read path must never bring a log into existence"
    );

    // The write path still creates it, so the two halves stay distinguishable.
    assert!(KtLog::open(&path).is_ok(), "the write path creates the log");
    assert!(path.exists());
}

#[test]
fn a_read_only_handle_refuses_to_append_and_writes_nothing() {
    let (_dir, path) = scratch("kt.log");
    write_one(&path, b"only entry");
    let before = fs::read_to_string(&path).expect("read back");

    let mut reader = KtLog::open_read_only(&path).expect("a reader opens the log");
    let err = reader
        .append_at(b"must not land", 1_700_000_000_000)
        .expect_err("appending through a read-only handle must fail");

    assert!(
        matches!(err, KtError::Io(ref e) if e.kind() == std::io::ErrorKind::PermissionDenied),
        "the refusal is a PermissionDenied, not a silent no-op: {err:?}"
    );
    assert_eq!(
        fs::read_to_string(&path).expect("read back"),
        before,
        "not one byte may reach the file"
    );
    assert_eq!(reader.len(), 1, "the in-memory chain must not grow");
}
