//! Kernel parameter tuner for `@requires_scale(.high)` workloads.
//!
//! On Linux, reads and writes `/proc/sys` parameters to optimize for
//! high-scale networking (millions of connections). All changes are
//! logged and automatically reverted when the `KernelTuner` is dropped.
//!
//! On non-Linux platforms this is a no-op that prints a warning.

use std::path::PathBuf;

/// A single parameter that was successfully changed, storing its
/// original value so it can be restored on rollback.
struct TunedParam {
    path: String,
    original_value: String,
}

/// Manages kernel parameter tuning and automatic rollback.
pub struct KernelTuner {
    params: Vec<TunedParam>,
    log_path: PathBuf,
}

/// High-scale parameter set: (proc path, desired value).
#[cfg(target_os = "linux")]
const HIGH_SCALE_PARAMS: &[(&str, &str)] = &[
    ("/proc/sys/fs/file-max", "20000000"),
    ("/proc/sys/net/ipv4/ip_local_port_range", "1024\t65535"),
    ("/proc/sys/net/ipv4/tcp_tw_reuse", "1"),
    ("/proc/sys/net/core/somaxconn", "65535"),
    ("/proc/sys/net/ipv4/tcp_max_syn_backlog", "65535"),
];

#[cfg(target_os = "linux")]
impl KernelTuner {
    /// Apply high-scale kernel parameters. Reads the original value of
    /// each parameter, attempts to write the new value, and records
    /// successful changes for later rollback.
    pub fn apply_high_scale() -> Result<Self, String> {
        use std::fs;
        use std::io::Write;

        let log_path = std::env::temp_dir().join("tallow-kernel-changes.log");
        let mut tuned = Vec::new();
        let mut log_lines: Vec<String> = Vec::new();

        for &(path, desired) in HIGH_SCALE_PARAMS {
            // Read original value
            let original = match fs::read_to_string(path) {
                Ok(v) => v.trim().to_string(),
                Err(e) => {
                    let msg = format!("[SKIP] {path}: cannot read ({e})");
                    eprintln!("{msg}");
                    log_lines.push(msg);
                    continue;
                }
            };

            // Write new value
            match fs::write(path, desired) {
                Ok(()) => {
                    let msg = format!("[OK]   {path}: {original} -> {desired}");
                    eprintln!("{msg}");
                    log_lines.push(msg);
                    tuned.push(TunedParam {
                        path: path.to_string(),
                        original_value: original,
                    });
                }
                Err(e) => {
                    let msg = format!("[FAIL] {path}: cannot write ({e})");
                    eprintln!("{msg}");
                    log_lines.push(msg);
                }
            }
        }

        // Write log file
        if let Ok(mut f) = fs::File::create(&log_path) {
            for line in &log_lines {
                let _ = writeln!(f, "{line}");
            }
        }

        eprintln!(
            "tallow: kernel tuner applied {}/{} parameters (log: {})",
            tuned.len(),
            HIGH_SCALE_PARAMS.len(),
            log_path.display()
        );

        Ok(Self {
            params: tuned,
            log_path,
        })
    }

    /// Revert all tuned parameters to their original values, in reverse
    /// order. Collects any errors and returns them as a combined message.
    pub fn rollback(&self) -> Result<(), String> {
        use std::fs;

        let mut errors = Vec::new();
        for param in self.params.iter().rev() {
            if let Err(e) = fs::write(&param.path, &param.original_value) {
                errors.push(format!("{}: {e}", param.path));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "failed to rollback {} parameter(s): {}",
                errors.len(),
                errors.join("; ")
            ))
        }
    }

    /// Number of parameters that were successfully tuned.
    pub fn tuned_count(&self) -> usize {
        self.params.len()
    }
}

#[cfg(not(target_os = "linux"))]
impl KernelTuner {
    /// On non-Linux platforms, kernel tuning is not supported. Returns
    /// an empty tuner with zero tuned parameters.
    pub fn apply_high_scale() -> Result<Self, String> {
        eprintln!("tallow: kernel tuning is only supported on Linux; skipping");
        Ok(Self {
            params: Vec::new(),
            log_path: std::env::temp_dir().join("tallow-kernel-changes.log"),
        })
    }

    /// No-op on non-Linux — nothing to revert.
    pub fn rollback(&self) -> Result<(), String> {
        Ok(())
    }

    /// Number of parameters that were successfully tuned (always 0 on
    /// non-Linux).
    pub fn tuned_count(&self) -> usize {
        self.params.len()
    }
}

// ── FFI Wrappers ────────────────────────────────────────────────────────────
//
// `extern "C"` entry points matching the declarations the LLVM codegen emits
// in its preamble (src/codegen.rs: `declare i32 @tallow_kernel_tune_apply()`
// and `declare void @tallow_kernel_tune_rollback(ptr)`). The tuner instance is
// kept alive in a process-global slot so `rollback` always has a target.

use std::ffi::c_void;
use std::sync::Mutex;

/// The most recently applied tuner (if any), kept for rollback.
static ACTIVE_TUNER: Mutex<Option<KernelTuner>> = Mutex::new(None);

/// Apply the high-scale kernel parameter set. Returns 0 on success, -1 on
/// error (check `tallow_last_error`).
#[unsafe(no_mangle)]
pub extern "C" fn tallow_kernel_tune_apply() -> i32 {
    match KernelTuner::apply_high_scale() {
        Ok(tuner) => {
            if let Ok(mut guard) = ACTIVE_TUNER.lock() {
                *guard = Some(tuner);
            }
            0
        }
        Err(e) => {
            super::set_last_error(format!("kernel_tune.apply: {e}"));
            -1
        }
    }
}

/// Roll back the previously applied kernel tuning (if any). `_handle` is
/// accepted for signature compatibility with the codegen declaration; the
/// stored tuner is rolled back regardless. Safe to call with null / when
/// nothing was applied.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_kernel_tune_rollback(_handle: *mut c_void) {
    if let Ok(mut guard) = ACTIVE_TUNER.lock() {
        if let Some(tuner) = guard.take() {
            if let Err(e) = tuner.rollback() {
                super::set_last_error(format!("kernel_tune.rollback: {e}"));
            }
        }
    }
}

impl Drop for KernelTuner {
    fn drop(&mut self) {
        if self.params.is_empty() {
            return;
        }
        match self.rollback() {
            Ok(()) => eprintln!(
                "tallow: kernel tuner rolled back {} parameter(s)",
                self.params.len()
            ),
            Err(e) => eprintln!("tallow: kernel tuner rollback error: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tuner_no_op_on_non_linux() {
        // apply_high_scale must succeed (never Err) on every platform. On
        // non-Linux it always tunes zero parameters (guarded no-op). On Linux it
        // may actually tune kernel params if we have CAP_SYS_ADMIN (as root), so
        // we only assert a hard zero on non-Linux and a behavior-agnostic result
        // on Linux.
        let tuner = KernelTuner::apply_high_scale()
            .expect("apply_high_scale should not return Err");
        #[cfg(target_os = "linux")]
        {
            // On Linux the count is environment-dependent (0 if not privileged,
            // >0 if root with CAP_SYS_ADMIN). Either way rollback must succeed.
            let _ = tuner.tuned_count();
        }
        #[cfg(not(target_os = "linux"))]
        {
            assert_eq!(tuner.tuned_count(), 0);
        }
        // Rollback should also be fine regardless — on non-Linux nothing to
        // revert; on Linux it restores any tuned values.
        assert!(tuner.rollback().is_ok());
    }
}
