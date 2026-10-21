//! Sandboxed process runtime — non-Unix build.
//!
//! The real implementation (`sandbox_runtime.rs`) installs seccomp-BPF and
//! Landlock in a `CommandExt::pre_exec` hook. Neither the syscalls nor the
//! pre-exec hook exist on Windows, so this build exposes the same five entry
//! points and refuses every one of them.
//!
//! Refusing is the point: a `run_sandboxed` that quietly returned `Ok(())`
//! would tell the caller the child is confined when it is not.

use std::path::PathBuf;
use std::process::Command;

const WHY: &str = "sandboxing (seccomp-BPF + Landlock) is a Linux kernel feature; \
                   this build targets a platform without it";

/// Always `Err` on this platform.
pub fn install_seccomp(_allowed: &[&str], _deny_default: bool) -> Result<(), String> {
    Err(format!("install_seccomp: {WHY}"))
}

/// Always `Err` on this platform.
pub fn install_landlock(_read_paths: &[PathBuf]) -> Result<(), String> {
    Err(format!("install_landlock: {WHY}"))
}

/// Always `Err` on this platform.
pub fn install_landlock_rw(
    _read_paths: &[PathBuf],
    _write_paths: &[PathBuf],
) -> Result<(), String> {
    Err(format!("install_landlock_rw: {WHY}"))
}

/// Always `Err` on this platform — the child is never spawned with a
/// confinement that does not exist here.
pub fn run_sandboxed(_cmd: &mut Command, _read_paths: &[PathBuf]) -> Result<(), String> {
    Err(format!("run_sandboxed: {WHY}"))
}

/// Always `Err` on this platform.
pub fn run_sandboxed_rw(
    _cmd: &mut Command,
    _read_paths: &[PathBuf],
    _write_paths: &[PathBuf],
) -> Result<(), String> {
    Err(format!("run_sandboxed_rw: {WHY}"))
}
