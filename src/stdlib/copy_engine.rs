//! Standard library: `copy_engine` — minimal, REAL file-copy engine.
//!
//! This module replaced a stub (2026-09-05) that reported success with
//! `bytes_copied: 0` while performing zero I/O. It now performs real `std::fs`
//! I/O with actual byte counts and honest error propagation.
//!
//! Scope: single-file copies (with automatic creation of a missing destination
//! parent directory). Directory trees, symlink policies, metadata policies,
//! verification and parallelism are the domain of the full
//! `tallow-copy-engine` crate (`crates/tallow-copy-engine`,
//! `use tallow_copy_engine`) — the crate is what `transfer.fast_copy` /
//! `transfer.fast_copy_dir` route through. Any plan action this minimal engine
//! cannot honestly perform is refused with an explicit error pointing there.

use std::fs;
use std::path::{Path, PathBuf};

/// A single copy job: copy file `src` to `dst`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyJob {
    pub src: String,
    pub dst: String,
}

impl CopyJob {
    pub fn copy(src: &str, dst: &str) -> Self {
        CopyJob {
            src: src.to_string(),
            dst: dst.to_string(),
        }
    }
}

/// Kinds of actions a [`CopyPlan`] can contain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CopyActionKind {
    Mkdir,
    CopyFile,
    Symlink,
    Hardlink,
    Chmod,
}

/// A single concrete filesystem action produced by [`plan`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopyAction {
    pub kind: CopyActionKind,
    pub src: PathBuf,
    pub dst: PathBuf,
}

/// An executable copy plan.
#[derive(Clone, Debug, Default)]
pub struct CopyPlan {
    pub actions: Vec<CopyAction>,
    pub items: Vec<CopyJob>,
}

/// Result of a successful [`execute`] run.
///
/// `failed`/`errors` are kept for API compatibility and are always `0`/empty
/// on success — any failure is returned as an `Err` carrying the underlying
/// I/O error rather than being hidden in the report.
#[derive(Clone, Debug, Default)]
pub struct CopyReport {
    pub copied: usize,
    pub failed: usize,
    pub errors: Vec<String>,
    pub copied_files: usize,
    pub bytes_copied: u64,
}

/// Build a concrete [`CopyPlan`] from a [`CopyJob`].
///
/// Real preflight: the source must exist and be a regular file (directory
/// copies are out of scope for this minimal engine — see the module docs).
/// If the destination's parent directory is missing, a `Mkdir` action is
/// emitted ahead of the `CopyFile` action.
pub fn plan(job: CopyJob) -> Result<CopyPlan, Box<dyn std::error::Error>> {
    let src = Path::new(&job.src);
    let dst = Path::new(&job.dst);

    if src == dst {
        return Err(format!(
            "copy_engine::plan: destination '{}' equals the source",
            job.dst
        )
        .into());
    }
    let meta = fs::metadata(src)
        .map_err(|e| format!("copy_engine::plan: source '{}' is not accessible: {e}", job.src))?;
    if !meta.is_file() {
        return Err(format!(
            "copy_engine::plan: source '{}' is not a regular file (directory copies are out of \
             scope for the stdlib engine; use crates/tallow-copy-engine)",
            job.src
        )
        .into());
    }

    let mut actions = Vec::new();
    if let Some(parent) = dst.parent() {
        if !parent.as_os_str().is_empty() && !parent.exists() {
            actions.push(CopyAction {
                kind: CopyActionKind::Mkdir,
                src: PathBuf::new(),
                dst: parent.to_path_buf(),
            });
        }
    }
    actions.push(CopyAction {
        kind: CopyActionKind::CopyFile,
        src: src.to_path_buf(),
        dst: dst.to_path_buf(),
    });
    Ok(CopyPlan {
        actions,
        items: vec![job],
    })
}

/// Execute a [`CopyPlan`] with real I/O.
///
/// Returns `Err(...)` with the underlying I/O error on the first failure —
/// this module never fabricates a success report. On success the report
/// carries the real number of files copied and the real byte count.
pub fn execute(plan: &CopyPlan) -> Result<CopyReport, Box<dyn std::error::Error>> {
    let mut report = CopyReport::default();
    if plan.actions.is_empty() {
        return Err("copy_engine::execute: plan contains no actions".into());
    }

    for action in &plan.actions {
        match action.kind {
            CopyActionKind::Mkdir => {
                fs::create_dir_all(&action.dst).map_err(|e| {
                    format!(
                        "copy_engine::execute: mkdir '{}' failed: {e}",
                        action.dst.display()
                    )
                })?;
                report.copied += 1;
            }
            CopyActionKind::CopyFile => {
                let bytes = fs::copy(&action.src, &action.dst).map_err(|e| {
                    format!(
                        "copy_engine::execute: copy '{}' -> '{}' failed: {e}",
                        action.src.display(),
                        action.dst.display()
                    )
                })?;
                report.copied += 1;
                report.copied_files += 1;
                report.bytes_copied = report.bytes_copied.saturating_add(bytes);
            }
            CopyActionKind::Hardlink => {
                fs::hard_link(&action.src, &action.dst).map_err(|e| {
                    format!(
                        "copy_engine::execute: hard_link '{}' -> '{}' failed: {e}",
                        action.src.display(),
                        action.dst.display()
                    )
                })?;
                report.copied += 1;
                report.copied_files += 1;
            }
            CopyActionKind::Symlink | CopyActionKind::Chmod => {
                return Err(format!(
                    "copy_engine::execute: {:?} actions are not implemented by the stdlib minimal \
                     engine; use crates/tallow-copy-engine for full copy semantics",
                    action.kind
                )
                .into());
            }
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn copy_engine_copies_real_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("source.bin");
        let dst = tmp.path().join("destination.bin");
        let payload = b"real copy engine bytes \x00\x01\x02\xff";
        fs::write(&src, payload).unwrap();

        let job = CopyJob::copy(src.to_str().unwrap(), dst.to_str().unwrap());
        let plan = plan(job).expect("plan should succeed for an existing file");
        let report = execute(&plan).expect("execute should succeed");

        assert_eq!(
            report.bytes_copied,
            payload.len() as u64,
            "byte count must reflect the real copy"
        );
        assert_eq!(report.copied_files, 1);
        assert_eq!(report.failed, 0);
        assert!(report.errors.is_empty());
        // The destination must contain the exact payload.
        assert_eq!(fs::read(&dst).unwrap(), payload);
    }

    #[test]
    fn copy_engine_creates_missing_parent_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("source.txt");
        let dst = tmp.path().join("does").join("not").join("exist").join("dest.txt");
        fs::write(&src, b"deep copy").unwrap();

        let plan = plan(CopyJob::copy(src.to_str().unwrap(), dst.to_str().unwrap())).unwrap();
        // Two actions: Mkdir (missing parent) then CopyFile.
        assert_eq!(plan.actions.len(), 2);
        assert!(matches!(plan.actions[0].kind, CopyActionKind::Mkdir));

        let report = execute(&plan).unwrap();
        assert_eq!(report.copied, 2);
        assert_eq!(report.bytes_copied, 9);
        assert_eq!(fs::read_to_string(&dst).unwrap(), "deep copy");
    }

    #[test]
    fn copy_engine_plan_rejects_missing_source() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("no_such_file.txt");
        let dst = tmp.path().join("dest.txt");
        let err = plan(CopyJob::copy(missing.to_str().unwrap(), dst.to_str().unwrap()))
            .expect_err("plan must reject a missing source");
        assert!(
            err.to_string().contains("not accessible"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn copy_engine_plan_rejects_directory_source() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("adir");
        fs::create_dir(&dir).unwrap();
        let dst = tmp.path().join("dest.txt");
        let err = plan(CopyJob::copy(dir.to_str().unwrap(), dst.to_str().unwrap()))
            .expect_err("plan must reject a directory source");
        assert!(
            err.to_string().contains("not a regular file"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn copy_engine_execute_empty_plan_is_an_error() {
        let plan = CopyPlan::default();
        let err = execute(&plan).expect_err("empty plan must not report success");
        assert!(
            err.to_string().contains("no actions"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn copy_engine_propagates_io_error() {
        let tmp = tempfile::tempdir().unwrap();
        let missing = tmp.path().join("no_such_file.txt");
        let dst = tmp.path().join("dest.txt");
        // Build the plan by hand to skip plan()'s preflight, then execute: the
        // copy must fail with the underlying I/O error, not a fake success.
        let plan = CopyPlan {
            actions: vec![CopyAction {
                kind: CopyActionKind::CopyFile,
                src: missing.clone(),
                dst,
            }],
            items: vec![CopyJob::copy(
                missing.to_str().unwrap(),
                tmp.path().join("dest.txt").to_str().unwrap(),
            )],
        };
        let err = execute(&plan).expect_err("copy of a missing file must error");
        assert!(
            err.to_string().contains("copy_engine::execute: copy"),
            "unexpected error: {err}"
        );
    }
}
