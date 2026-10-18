//! Build script (N2, W4 · 2026-09-26): burn the source identity into the
//! binary. `tallow version` prints `GIT_HASH` / `BUILD_DATE` via `option_env!`,
//! so these two env vars give any binary a provable provenance:
//! commit SHA (+ explicit dirty flag) and the UTC build timestamp.
//!
//! Deliberately NOT watching .git/index: the dirty flag is computed at build
//! time (the moment the binary is produced), and watching staging state would
//! retrigger rebuilds on every `git add`.
use std::process::Command;

fn run(cmd: &str, args: &[&str]) -> Option<String> {
    let out = Command::new(cmd).args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn main() {
    let sha = run("git", &["rev-parse", "--short=10", "HEAD"]).unwrap_or_else(|| "unknown".into());
    // No git at all -> do not claim clean provenance.
    //
    // `--untracked-files=no`: untracked scratch (`artifacts/`, build output
    // buckets) is not a modification of the tree that was built, so counting it
    // made every binary from a working directory with one untracked folder
    // report "(dirty)" even at a clean commit — the stamp lying in the
    // direction that trains people to ignore it. Same convention as
    // `git describe --dirty`, which looks only at tracked content.
    let dirty = match run("git", &["status", "--porcelain", "--untracked-files=no"]) {
        Some(s) => !s.is_empty(),
        None => true,
    };
    let git = if dirty && sha != "unknown" {
        format!("{sha} (dirty)")
    } else {
        sha
    };
    let date = run("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]).unwrap_or_else(|| "dev".into());

    println!("cargo:rustc-env=GIT_HASH={git}");
    println!("cargo:rustc-env=BUILD_DATE={date}");
    // Re-run when HEAD moves (checkout/branch switch) AND when the branch it points at moves (commit).
    // `.git/HEAD` alone is not enough and the earlier version of this file claimed otherwise: HEAD holds
    // a ref POINTER (`ref: refs/heads/v1`), which a commit does not modify — only the ref's own file
    // changes — so watching HEAD alone left the embedded SHA frozen at whatever commit was current when
    // the stamp was last written, which is the exact failure this stamp exists to prevent. `.git/refs` is
    // watched as a directory so any ref move retriggers.
    // Still deliberately NOT watching .git/index: the dirty flag is computed at build time (the moment
    // the binary is produced), and watching staging state would retrigger rebuilds on every `git add`.
    println!("cargo:rerun-if-changed=.git/HEAD");
    println!("cargo:rerun-if-changed=.git/refs");
    println!("cargo:rerun-if-changed=build.rs");
}
