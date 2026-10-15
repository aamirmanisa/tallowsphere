//! `tallow run --sandbox` — kernel confinement (Landlock) for a program run.
//!
//! `@sandbox` / `@sandboxed` annotations were validation-only (audit R3:
//! "Sandbox is validation-only"). This module is the explicit runtime
//! enforcement path: the run is re-executed as a CHILD process confined by
//! [`crate::sandbox_runtime::run_sandboxed_rw`]:
//!
//! * read + execute: system trees, `/opt`, `/proc`, `/dev`, the CWD, the
//!   program's directory, and the effective temp dir;
//! * write: the effective temp dir + `/tmp` (+ `/dev/null`);
//! * everything else: denied.
//!
//! Fail-closed: if Landlock cannot be installed, the child refuses to exec —
//! the program does NOT silently run unconfined.
//!
//! Note: confinement here is filesystem-level (Landlock). Syscall-level
//! seccomp for the runtime (`crate::sandbox_runtime::install_seccomp`) must
//! be installed post-startup inside the executing process; wiring that into
//! `run` is a tracked follow-up (see `sandbox_runtime.rs` header).

use std::path::PathBuf;
use std::process::Command;

/// Re-exec `tallow run <file> [-- args…]` confined. Returns the child's exit code.
pub fn run_confined_self(
    file: &std::path::Path,
    script: bool,
    program_args: &[String],
) -> Result<i32, String> {
    let exe = std::env::current_exe().map_err(|e| format!("sandbox: current_exe: {e}"))?;
    let cwd = std::env::current_dir().map_err(|e| format!("sandbox: cwd: {e}"))?;
    let tmp = std::env::temp_dir();

    let mut read_paths: Vec<PathBuf> = [
        "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/dev", "/proc", "/opt",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    read_paths.push(cwd.clone());
    read_paths.push(tmp.clone());
    if let Some(parent) = file.parent() {
        read_paths.push(parent.to_path_buf());
    }
    if let Ok(canon) = file.canonicalize() {
        if let Some(parent) = canon.parent() {
            read_paths.push(parent.to_path_buf());
        }
    }

    let write_paths: Vec<PathBuf> = vec![
        tmp.clone(),
        PathBuf::from("/tmp"),
        PathBuf::from("/dev/null"),
    ];

    let mut cmd = Command::new(&exe);
    cmd.arg("run");
    if script {
        cmd.arg("--script");
    }
    cmd.arg(file);
    if !program_args.is_empty() {
        cmd.arg("--");
        cmd.args(program_args);
    }
    cmd.current_dir(&cwd);
    // Marker so the child can tell intentional confinement from a bare run
    // (suppresses the unconfined-annotation warning inside the child).
    cmd.env("TALLOW_SANDBOX_CHILD", "1");
    // Keep the JSONL log sink inside the write set (the default ~/.tallow is
    // denied by the confinement, which would print a spurious "logging init
    // failed: Permission denied" on every sandboxed run).
    cmd.env("TALLOW_LOG_DIR", tmp.join("tallow-sandbox-logs"));

    crate::sandbox_runtime::run_sandboxed_rw(&mut cmd, &read_paths, &write_paths)?;
    eprintln!(
        "[tallow] sandbox: Landlock confinement active (reads: system + CWD; writes: {} + /tmp)",
        tmp.display()
    );

    let status = cmd.status().map_err(|e| {
        format!(
            "sandbox: confined child refused to start ({e}) — Landlock unavailable? refusing to run unconfined"
        )
    })?;
    Ok(status.code().unwrap_or(128))
}
