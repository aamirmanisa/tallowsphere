//! A1.4.2 — `tallow never-check`: NEVER-invariants probe.
//!
//! Runs the canonical static gate (`scripts/never_check.sh --no-cargo`): the
//! N1–N10 source guards from the NEVER ledger, without any build. The full
//! gate (including the cargo closure-test slices) runs in CI
//! (`.github/workflows/never-invariants.yml`) and manually via
//! `bash scripts/never_check.sh` (add `--live-egress` for the live Tor check).
//!
//! Exit codes: 0 = all hard checks pass (or gate script absent → SKIP);
//! 1 = at least one hard FAIL or the gate could not run.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Locate `scripts/never_check.sh`: walk up from the cwd (so `tallow
/// never-check` works from any subdirectory of the repo), then fall back to the
/// build-time crate root for repo-built binaries.
fn find_gate_script() -> Option<PathBuf> {
    if let Ok(mut dir) = std::env::current_dir() {
        for _ in 0..12 {
            let candidate = dir.join("scripts").join("never_check.sh");
            if candidate.is_file() {
                return Some(candidate);
            }
            if !dir.pop() {
                break;
            }
        }
    }
    let manifest_candidate = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("scripts")
        .join("never_check.sh");
    manifest_candidate.is_file().then_some(manifest_candidate)
}

/// Run the static NEVER gate and print a plain-text verdict. Returns the
/// process exit code (`0` pass/skip, `1` fail).
pub fn run_never_probe() -> i32 {
    let Some(script) = find_gate_script() else {
        println!(
            "[SKIP] never-invariants gate (scripts/never_check.sh not found — run from the repo root)"
        );
        return 0;
    };
    let repo_root = script
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new("."));
    let output = match Command::new("bash")
        .arg(&script)
        .arg("--no-cargo")
        .current_dir(repo_root)
        .output()
    {
        Ok(output) => output,
        Err(e) => {
            println!("[FAIL] never-invariants gate could not run: {e}");
            return 1;
        }
    };

    println!("--- NEVER-invariants gate (scripts/never_check.sh --no-cargo) ---");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    // Full output can be long; show the tail context (summary lives there)…
    let tail_start = lines.len().saturating_sub(12);
    for line in &lines[tail_start..] {
        println!("{line}");
    }
    // …then surface every hard failure wherever it appeared.
    let fail_lines: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|line| line.contains("[FAIL]"))
        .collect();
    if !fail_lines.is_empty() {
        println!("--- hard failures ---");
        for line in fail_lines {
            println!("{line}");
        }
    }

    let rc = output.status.code().unwrap_or(1);
    if rc == 0 {
        println!("[PASS] never-invariants (N1–N10 static guards; exit 0)");
        0
    } else {
        println!("[FAIL] never-invariants gate exited {rc}");
        1
    }
}
