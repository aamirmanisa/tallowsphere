//! Process-local runtime capability policy for the tree-walking interpreter
//! (security-audit R2, 2026-09-29).
//!
//! The 35 policy passes run in the `tallow` **CLI** pipeline only; an
//! `Interpreter` embedded via `Interpreter::new()` + `run()` performs no
//! capability checks. This module provides the opt-in gate: attach a
//! [`RuntimeCapabilityPolicy`] to an interpreter (setter API or the
//! `TALLOW_DENY_READ` / `TALLOW_DENY_WRITE` colon-separated env lists) and
//! the `fs.*` builtin dispatch consults it before every read or write,
//! returning `capability_denied: …` as a normal language `Err` value.
//!
//! Semantics: DENY-lists over the default (unrestricted) baseline — an
//! interpreter without a policy behaves exactly as before. Paths match by
//! prefix after resolution (canonicalized when the target exists, absolute
//! lexical otherwise), so denying `/etc` also denies `/etc/passwd`.
//!
//! Scope today: the filesystem surface (`fs.read` / `fs.write` / `fs.append`
//! / `fs.mkdir` / `fs.delete` / `fs.copy` / `fs.list_dir` / …).
//! `process.exec` gating (needs a policy seam in the free-function
//! `stdlib::process::dispatch`) and a config-file surface are tracked
//! follow-ups — `.scratch/tallow-r2-runtime-capabilities/`.

use std::path::{Path, PathBuf};

/// Deny-list policy consulted by the interpreter's `fs.*` dispatch.
#[derive(Debug, Default, Clone)]
pub struct RuntimeCapabilityPolicy {
    deny_read_paths: Vec<PathBuf>,
    deny_write_paths: Vec<PathBuf>,
}

impl RuntimeCapabilityPolicy {
    pub fn new() -> Self {
        Self::default()
    }

    /// Deny reads beneath `path` (prefix match).
    pub fn deny_read(mut self, path: impl Into<PathBuf>) -> Self {
        self.deny_read_paths.push(path.into());
        self
    }

    /// Deny writes beneath `path` (prefix match).
    pub fn deny_write(mut self, path: impl Into<PathBuf>) -> Self {
        self.deny_write_paths.push(path.into());
        self
    }

    /// Parse `TALLOW_DENY_READ` / `TALLOW_DENY_WRITE` (colon-separated path
    /// lists). Returns `None` when neither variable is set.
    pub fn from_env() -> Option<Self> {
        let read = std::env::var("TALLOW_DENY_READ").ok();
        let write = std::env::var("TALLOW_DENY_WRITE").ok();
        if read.is_none() && write.is_none() {
            return None;
        }
        let mut pol = Self::new();
        for v in read.iter().flat_map(|v| v.split(':')) {
            if !v.is_empty() {
                pol = pol.deny_read(v);
            }
        }
        for v in write.iter().flat_map(|v| v.split(':')) {
            if !v.is_empty() {
                pol = pol.deny_write(v);
            }
        }
        Some(pol)
    }

    pub fn check_read(&self, path: &str) -> Result<(), String> {
        Self::check(path, &self.deny_read_paths, "read")
    }

    pub fn check_write(&self, path: &str) -> Result<(), String> {
        Self::check(path, &self.deny_write_paths, "write")
    }

    fn check(path: &str, denies: &[PathBuf], verb: &str) -> Result<(), String> {
        if denies.is_empty() {
            return Ok(());
        }
        let abs = Self::absolute(path);
        for deny in denies {
            let deny_abs = Self::absolute(&deny.to_string_lossy());
            if abs.starts_with(&deny_abs) {
                return Err(format!("{verb} of {path} denied by policy ({})", deny.display()));
            }
            // Canonicalize when possible so symlinked paths cannot dodge a
            // deny prefix; the lexical check above keeps non-existent write
            // targets covered.
            let deny_canon = std::fs::canonicalize(&deny_abs).unwrap_or_else(|_| deny_abs.clone());
            if let Ok(target_canon) = std::fs::canonicalize(&abs) {
                if target_canon.starts_with(&deny_canon) {
                    return Err(format!("{verb} of {path} denied by policy ({})", deny.display()));
                }
            }
        }
        Ok(())
    }

    fn absolute(path: &str) -> PathBuf {
        let p = Path::new(path);
        if p.is_absolute() {
            p.to_path_buf()
        } else {
            std::env::current_dir()
                .map(|c| c.join(p))
                .unwrap_or_else(|_| p.to_path_buf())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_write_prefix_blocks_children() {
        let pol = RuntimeCapabilityPolicy::new().deny_write("/etc");
        assert!(pol.check_write("/etc/passwd").is_err());
        assert!(pol.check_write("/etc").is_err());
        assert!(pol.check_write("/tmp/ok").is_ok());
        assert!(pol.check_read("/etc/passwd").is_ok(), "write deny must not gate reads");
    }

    #[test]
    fn deny_read_blocks_and_leaves_writes_alone() {
        let pol = RuntimeCapabilityPolicy::new().deny_read("/home/secret");
        assert!(pol.check_read("/home/secret/keys.txt").is_err());
        assert!(pol.check_write("/home/secret/keys.txt").is_ok(), "read deny must not gate writes");
        assert!(pol.check_read("/home/public/x").is_ok());
    }

    #[test]
    fn empty_policy_allows_everything() {
        let pol = RuntimeCapabilityPolicy::default();
        assert!(pol.check_read("/etc/passwd").is_ok());
        assert!(pol.check_write("/etc/passwd").is_ok());
    }

    #[test]
    fn relative_paths_resolve_against_cwd() {
        let pol = RuntimeCapabilityPolicy::new().deny_write("relative-deny");
        assert!(pol.check_write("relative-deny/file").is_err());
        let cwd = std::env::current_dir().unwrap();
        let abs = cwd.join("relative-deny/file");
        assert!(pol.check_read(&abs.to_string_lossy()).is_ok(), "write deny must not gate reads");
    }
}
