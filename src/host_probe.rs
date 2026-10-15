//! Host-hardening sysctl probe (SFIL T-124 - rows #70/#125, R-P9-3).
//!
//! Pure, read-only inspection of the kernel hardening knobs exposed under
//! `/proc/sys/` (Linux). Nothing here writes, spawns, or opens a socket:
//! each probe reads at most one small text file and returns a structured
//! [`HostProbeFinding`]. The probe exists so `tallow doctor` can report the
//! live wire state of the host posture - io_uring off, unprivileged BPF
//! off, `kptr_restrict` >= 1 - instead of restating the design claim
//! (R-P9-3: kernel attack-surface reduction for daemon/browser hosts;
//! io_uring stays unused in Tallow async paths).
//!
//! Graceful by design: not every kernel exposes every sysctl
//! (`kernel/io_uring_disabled` only exists since Linux 5.12, and minimal
//! containers may mount a partial `/proc/sys`). An absent or unreadable
//! file becomes a WARN finding - never an error, never a panic.
//!
//! Testability: every entry point takes the sysctl root as a parameter;
//! [`DEFAULT_ROOT`] is `/proc/sys` and the `*_default()` wrappers use it.
//! Wiring (recorded in the T-124 evidence, applied by the integrator):
//! `pub mod host_probe;` in `src/lib.rs` and the doctor arm calling
//! `summary(DEFAULT_ROOT)`.

use std::path::{Path, PathBuf};

/// Default sysctl root - the live kernel view on Linux.
pub const DEFAULT_ROOT: &str = "/proc/sys";

/// The value relation a [`SysctlSpec`] requires.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WantCheck {
    /// The observed value must equal the target exactly.
    Exact(u64),
    /// The observed value must be at least the target.
    Min(u64),
}

impl WantCheck {
    /// Human/JSON label for the requirement: `"2"` or `">=1"`.
    pub fn want_label(self) -> String {
        match self {
            WantCheck::Exact(v) => v.to_string(),
            WantCheck::Min(v) => format!(">={v}"),
        }
    }

    /// Whether `observed` satisfies this requirement.
    pub fn satisfied_by(self, observed: u64) -> bool {
        match self {
            WantCheck::Exact(v) => observed == v,
            WantCheck::Min(v) => observed >= v,
        }
    }
}

/// One hardening control the probe checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SysctlSpec {
    /// Dotted sysctl name (`kernel.kptr_restrict`).
    pub name: &'static str,
    /// Path relative to the sysctl root (`kernel/kptr_restrict`).
    pub rel_path: &'static str,
    /// Required value relation.
    pub want: WantCheck,
    /// One-line rationale (R-P9-3).
    pub purpose: &'static str,
}

/// The R-P9-3 controls, in doctor report order.
pub const HARDENING_SPECS: &[SysctlSpec] = &[
    SysctlSpec {
        name: "kernel.io_uring_disabled",
        rel_path: "kernel/io_uring_disabled",
        want: WantCheck::Exact(2),
        purpose: "disable io_uring for all users (seccomp-bypass / LPE surface)",
    },
    SysctlSpec {
        name: "kernel.unprivileged_bpf_disabled",
        rel_path: "kernel/unprivileged_bpf_disabled",
        // Kernel admin-guide: 1 = disabled permanently, 2 = disabled but
        // re-enablable at runtime; both mean "unprivileged BPF off", so
        // both satisfy the control. Value 2 still gets an advisory note
        // (1 is the stronger setting).
        want: WantCheck::Min(1),
        purpose: "unprivileged BPF off (kernel attack-surface reduction)",
    },
    SysctlSpec {
        name: "kernel.kptr_restrict",
        rel_path: "kernel/kptr_restrict",
        want: WantCheck::Min(1),
        purpose: "hide kernel pointers from unprivileged users",
    },
];

/// Status of one finding or summary line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostProbeStatus {
    /// Present and meeting the requirement.
    Pass,
    /// Absent, unreadable, unparseable, or below the requirement - advisory.
    Warn,
}

impl HostProbeStatus {
    /// `"PASS"` / `"WARN"` (mirrors the doctor probe labels).
    pub fn label(self) -> &'static str {
        match self {
            HostProbeStatus::Pass => "PASS",
            HostProbeStatus::Warn => "WARN",
        }
    }
}

/// Structured result for one sysctl probe.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProbeFinding {
    /// Dotted sysctl name.
    pub name: &'static str,
    /// Full path that was read.
    pub path: String,
    /// Requirement label (`"2"`, `">=1"`).
    pub want: String,
    /// Whether the file existed and was read.
    pub present: bool,
    /// Observed value (trimmed), when present.
    pub value: Option<String>,
    /// Whether the observed value meets `want`.
    pub value_ok: bool,
    /// One-line explanation, with a `sysctl -w` repair hint when below want.
    pub note: String,
}

impl HostProbeFinding {
    /// PASS only when present and compliant; everything else is WARN.
    pub fn status(&self) -> HostProbeStatus {
        if self.present && self.value_ok {
            HostProbeStatus::Pass
        } else {
            HostProbeStatus::Warn
        }
    }
}

/// Pass/warn summary line for one finding (doctor-renderable).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostProbeSummary {
    /// Dotted sysctl name.
    pub name: &'static str,
    /// Pass / warn per item.
    pub status: HostProbeStatus,
    /// One-line detail: observed value (or absence) + requirement note.
    pub detail: String,
}

/// Probe one spec against `root`. Never fails: a missing sysctl yields
/// `present: false`; an unreadable one keeps `present: true` with no value;
/// a non-numeric value stays observed with `value_ok: false`.
pub fn probe_sysctl(root: &Path, spec: &SysctlSpec) -> HostProbeFinding {
    let path: PathBuf = root.join(spec.rel_path);
    let want = spec.want.want_label();
    let path_str = path.display().to_string();

    match std::fs::read_to_string(&path) {
        Ok(raw) => {
            let trimmed = raw.trim();
            match trimmed.parse::<u64>() {
                Ok(observed) => {
                    let value_ok = spec.want.satisfied_by(observed);
                    let note = if value_ok {
                        ok_note(spec.name, observed, &want)
                    } else {
                        warn_note(spec.name, observed, &want)
                    };
                    HostProbeFinding {
                        name: spec.name,
                        path: path_str,
                        want,
                        present: true,
                        value: Some(trimmed.to_string()),
                        value_ok,
                        note,
                    }
                }
                Err(_) => {
                    let note = format!(
                        "unparseable sysctl value {trimmed:?} - cannot verify (want {want})"
                    );
                    HostProbeFinding {
                        name: spec.name,
                        path: path_str,
                        want,
                        present: true,
                        value: Some(trimmed.to_string()),
                        value_ok: false,
                        note,
                    }
                }
            }
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            let note =
                format!("not exposed by this kernel ({err}) - cannot verify (want {want})");
            HostProbeFinding {
                name: spec.name,
                path: path_str,
                want,
                present: false,
                value: None,
                value_ok: false,
                note,
            }
        }
        Err(err) => {
            let note = format!("sysctl unreadable ({err}) - cannot verify (want {want})");
            HostProbeFinding {
                name: spec.name,
                path: path_str,
                want,
                present: true,
                value: None,
                value_ok: false,
                note,
            }
        }
    }
}

/// Probe all R-P9-3 controls under `root` (read-only; never fails).
pub fn probe_hardening(root: impl AsRef<Path>) -> Vec<HostProbeFinding> {
    let root = root.as_ref();
    HARDENING_SPECS
        .iter()
        .map(|spec| probe_sysctl(root, spec))
        .collect()
}

/// Convenience: probe the live kernel view ([`DEFAULT_ROOT`]).
pub fn probe_hardening_default() -> Vec<HostProbeFinding> {
    probe_hardening(DEFAULT_ROOT)
}

/// Summarize findings into pass/warn lines (one per item).
pub fn summarize(findings: &[HostProbeFinding]) -> Vec<HostProbeSummary> {
    findings
        .iter()
        .map(|f| HostProbeSummary {
            name: f.name,
            status: f.status(),
            detail: detail_line(f),
        })
        .collect()
}

/// Convenience: probe + summarize `root` in one step.
pub fn summary(root: impl AsRef<Path>) -> Vec<HostProbeSummary> {
    summarize(&probe_hardening(root))
}

/// Convenience: probe + summarize the live kernel view ([`DEFAULT_ROOT`]).
pub fn summary_default() -> Vec<HostProbeSummary> {
    summary(DEFAULT_ROOT)
}

/// One doctor-renderable line: observed value/absence + requirement note.
fn detail_line(f: &HostProbeFinding) -> String {
    match (&f.value, f.present) {
        (Some(value), _) => format!("value {value} - {}", f.note),
        (None, true) => format!("unreadable - {}", f.note),
        (None, false) => format!("absent - {}", f.note),
    }
}

/// One-line note for a compliant observation.
fn ok_note(name: &str, value: u64, want: &str) -> String {
    match (name, value) {
        ("kernel.io_uring_disabled", 2) => {
            "io_uring disabled for all users (want 2)".to_string()
        }
        ("kernel.unprivileged_bpf_disabled", 1) => {
            "unprivileged BPF disabled permanently (want >=1)".to_string()
        }
        ("kernel.unprivileged_bpf_disabled", 2) => [
            "unprivileged BPF disabled; value 2 is re-enablable at runtime,",
            "1 is permanent (want >=1)",
        ]
        .join(" "),
        ("kernel.kptr_restrict", 1) => {
            "kernel pointers hidden from unprivileged users (want >=1)".to_string()
        }
        ("kernel.kptr_restrict", 2) => {
            "kernel pointers hidden from all users (want >=1)".to_string()
        }
        _ => format!("observed value {value} meets want {want}"),
    }
}

/// One-line note for a non-compliant observation, with a repair hint.
fn warn_note(name: &str, value: u64, want: &str) -> String {
    match (name, value) {
        ("kernel.io_uring_disabled", 0) => [
            "io_uring enabled for all users (want 2)",
            "- Fix: sysctl -w kernel.io_uring_disabled=2",
        ]
        .join(" "),
        ("kernel.io_uring_disabled", _) => [
            "io_uring disabled for unprivileged users only;",
            "want 2 = disabled for all users",
            "- Fix: sysctl -w kernel.io_uring_disabled=2",
        ]
        .join(" "),
        ("kernel.unprivileged_bpf_disabled", _) => [
            "unprivileged BPF enabled (want >=1)",
            "- Fix: sysctl -w kernel.unprivileged_bpf_disabled=1",
        ]
        .join(" "),
        ("kernel.kptr_restrict", _) => [
            "kernel pointers exposed (want >=1)",
            "- Fix: sysctl -w kernel.kptr_restrict=1",
        ]
        .join(" "),
        _ => format!("observed value {value} does not satisfy want {want} - adjust via sysctl(8)"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Unique writable sysctl root under the system temp dir (no /proc
    /// dependency, no network, no cross-test collisions).
    fn scratch_root(tag: &str) -> PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let root = std::env::temp_dir().join(format!(
            "tallow_host_probe_{}_{}_{}",
            std::process::id(),
            tag,
            nanos
        ));
        std::fs::create_dir_all(root.join("kernel")).expect("create scratch root");
        root
    }

    fn write_sysctl(root: &Path, rel_path: &str, value: &str) {
        // Real /proc/sys files carry a trailing newline; keep that shape.
        std::fs::write(root.join(rel_path), format!("{value}\n")).expect("write sysctl fixture");
    }

    fn finding<'a>(findings: &'a [HostProbeFinding], name: &str) -> &'a HostProbeFinding {
        findings
            .iter()
            .find(|f| f.name == name)
            .unwrap_or_else(|| panic!("missing finding for {name}"))
    }

    #[test]
    fn hardened_values_all_pass() {
        let root = scratch_root("hardened");
        write_sysctl(&root, "kernel/io_uring_disabled", "2");
        write_sysctl(&root, "kernel/unprivileged_bpf_disabled", "1");
        write_sysctl(&root, "kernel/kptr_restrict", "2");
        let findings = probe_hardening(&root);
        assert_eq!(findings.len(), HARDENING_SPECS.len());
        for f in &findings {
            assert!(f.present && f.value_ok, "{}: {f:?}", f.name);
            assert_eq!(f.status(), HostProbeStatus::Pass, "{}", f.name);
        }
        let summaries = summary(&root);
        assert_eq!(summaries.len(), 3);
        assert!(summaries.iter().all(|s| s.status == HostProbeStatus::Pass));
        assert!(summaries.iter().all(|s| s.detail.contains("value ")));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn soft_values_warn_with_repair_hints() {
        let root = scratch_root("soft");
        write_sysctl(&root, "kernel/io_uring_disabled", "0");
        write_sysctl(&root, "kernel/unprivileged_bpf_disabled", "0");
        write_sysctl(&root, "kernel/kptr_restrict", "0");
        let findings = probe_hardening(&root);
        for f in &findings {
            assert!(f.present, "{}", f.name);
            assert!(!f.value_ok, "{} unexpectedly compliant: {f:?}", f.name);
            assert_eq!(f.status(), HostProbeStatus::Warn, "{}", f.name);
        }
        assert!(finding(&findings, "kernel.io_uring_disabled")
            .note
            .contains("sysctl -w kernel.io_uring_disabled=2"));
        assert!(finding(&findings, "kernel.kptr_restrict")
            .note
            .contains("sysctl -w kernel.kptr_restrict=1"));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn absent_files_are_graceful_warns() {
        let root = scratch_root("absent");
        let findings = probe_hardening(&root);
        assert_eq!(findings.len(), 3);
        for f in &findings {
            assert!(!f.present, "{}", f.name);
            assert!(f.value.is_none());
            assert!(!f.value_ok);
            assert_eq!(f.status(), HostProbeStatus::Warn);
            assert!(f.note.contains("cannot verify"), "{}: {}", f.name, f.note);
        }
        // A nonexistent root is equally graceful.
        let missing = probe_hardening(root.join("nope"));
        assert!(missing
            .iter()
            .all(|f| !f.present && f.status() == HostProbeStatus::Warn));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn boundary_values_match_the_want_operators() {
        let root = scratch_root("boundary");
        // io_uring: exact 2 - the unprivileged-only setting (1) still warns.
        write_sysctl(&root, "kernel/io_uring_disabled", "1");
        // bpf: >=1 - both 1 (permanent) and 2 (re-enablable) mean disabled.
        write_sysctl(&root, "kernel/unprivileged_bpf_disabled", "2");
        // kptr_restrict: >=1 - the 1 floor passes; 2 would too.
        write_sysctl(&root, "kernel/kptr_restrict", "1");
        let findings = probe_hardening(&root);
        assert_eq!(
            finding(&findings, "kernel.io_uring_disabled").status(),
            HostProbeStatus::Warn
        );
        assert!(finding(&findings, "kernel.unprivileged_bpf_disabled").value_ok);
        assert!(finding(&findings, "kernel.kptr_restrict").value_ok);
        // Values are read trimmed (real files end in '\n').
        assert_eq!(
            finding(&findings, "kernel.kptr_restrict").value.as_deref(),
            Some("1")
        );
        assert_eq!(WantCheck::Min(1).want_label(), ">=1");
        assert_eq!(WantCheck::Exact(2).want_label(), "2");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn unparseable_value_is_a_warn() {
        let root = scratch_root("unparseable");
        write_sysctl(&root, "kernel/io_uring_disabled", "disabled");
        let findings = probe_hardening(&root);
        let f = finding(&findings, "kernel.io_uring_disabled");
        assert!(f.present && !f.value_ok);
        assert_eq!(f.status(), HostProbeStatus::Warn);
        assert!(f.note.contains("unparseable"), "{}", f.note);
        let _ = std::fs::remove_dir_all(&root);
    }
}
