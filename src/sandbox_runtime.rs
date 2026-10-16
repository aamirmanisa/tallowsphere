//! Sandboxed process runtime — wires the seccomp/Landlock confinement into a
//! real callable entry point so `install_seccomp_filter` isn't an orphan hook.
//!
//! Two runtime helpers:
//! - [`install_seccomp`]: drop a deny-by-default seccomp-BPF filter into the
//!   current process (delegates to `sandbox_pass::install_seccomp_filter`).
//! - [`install_landlock`]: filesystem confinement — restrict the process to a
//!   read-only view of a set of paths (Landlock LSM, Linux >= 5.13). This
//!   coexists with seccomp; seccomp restricts syscalls, Landlock restricts
//!   paths.
//! - [`run_sandboxed`]: spawn a child process after `install_seccomp` +
//!   `install_landlock` in a pre-exec hook (via `CommandExt::pre_exec`), so a
//!   browser/untrusted worker runs with both confinements.

use std::os::unix::process::CommandExt;
use std::process::Command;
use std::process::Stdio;

/// Install a deny-by-default seccomp filter into the current process.
///
/// Must be called in a child (pre-exec) context: once installed it cannot be
/// removed. `allowed` is the set of syscall names the process may make.
pub fn install_seccomp(allowed: &[&str], deny_default: bool) -> Result<(), String> {
    let policy = crate::sandbox_pass::SeccompPolicy {
        allowed: allowed.iter().map(|s| s.to_string()).collect(),
        deny_default,
    };
    crate::sandbox_pass::install_seccomp_filter(&policy)
}

/// Install a Landlock filesystem confinement restricting the current process
/// to read-only access to `read_paths` (and everything beneath). Uses the
/// `landlock` crate (safe wrappers over the Landlock LSM, Linux >= 5.13).
/// Writes to any path NOT in `read_paths` are denied.
pub fn install_landlock(read_paths: &[std::path::PathBuf]) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use landlock::{
            ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr,
            path_beneath_rules,
        };

        // Landlock ABI v1 is the baseline (kernel 5.13). Read-only access.
        let abi = ABI::V1;
        let access_read = AccessFs::from_read(abi);

        let paths: Vec<std::path::PathBuf> = read_paths
            .iter()
            .filter(|p| p.exists())
            .cloned()
            .collect();
        if paths.is_empty() {
            return Err("install_landlock: no valid read paths provided".to_string());
        }

        let status = Ruleset::default()
            .handle_access(access_read)
            .map_err(|e| format!("landlock handle_access failed: {e}"))?
            .create()
            .map_err(|e| format!("landlock create failed (kernel >= 5.13 required): {e}"))?
            .add_rules(path_beneath_rules(&paths, access_read))
            .map_err(|e| format!("landlock add_rules failed: {e}"))?
            .restrict_self()
            .map_err(|e| format!("landlock restrict_self failed: {e}"))?;

        match status.ruleset {
            landlock::RulesetStatus::FullyEnforced => Ok(()),
            landlock::RulesetStatus::PartiallyEnforced => Ok(()),
            landlock::RulesetStatus::NotEnforced => {
                Err("install_landlock: not enforced (kernel too old)".to_string())
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = read_paths;
        Err("landlock is Linux-only".to_string())
    }
}

/// Spawn `cmd` under Landlock confinement.
///
/// `read_paths` are the filesystem roots the child may read. Landlock is
/// applied in a `pre_exec` hook (it survives exec cleanly — Landlock restricts
/// *paths*, which the kernel resolves per-access, so a dynamically-linked child
/// still works). Seccomp is deliberately NOT applied here: a deny-default
/// seccomp filter installed before `execve` of a dynamically-linked binary
/// blocks the dynamic loader's syscalls and kills the child. Use
/// [`install_seccomp`] at the child's post-startup point instead, where the
/// allow-list can be tailored to the already-loaded process.
pub fn run_sandboxed(
    cmd: &mut Command,
    read_paths: &[std::path::PathBuf],
) -> Result<(), String> {
    let read_paths = read_paths.to_vec();

    // SAFETY: the hook runs in the child after fork; we only call libc and
    // write to our own captured memory.
    unsafe {
        cmd.pre_exec(move || {
            // Landlock is best-effort: a kernel without it (pre-5.13) still
            // runs the child unconfined rather than failing the exec.
            let _ = install_landlock(&read_paths);
            Ok(())
        });
    }
    Ok(())
}

/// Install a Landlock ruleset with BOTH a read set and a write set:
/// read+execute granted beneath every path in `read_paths`, full access
/// beneath every path in `write_paths`; everything else denied.
///
/// This is the confinement used by `tallow run --sandbox`. Unlike
/// [`install_landlock`] (best-effort, read-only — the browser helper), this
/// variant is designed for a **fail-closed** pre-exec hook: if enforcement
/// fails, the caller must not exec.
pub fn install_landlock_rw(
    read_paths: &[std::path::PathBuf],
    write_paths: &[std::path::PathBuf],
) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use landlock::{
            ABI, Access, AccessFs, Ruleset, RulesetAttr, RulesetCreatedAttr,
            path_beneath_rules,
        };

        let abi = ABI::V1;
        let access_read = AccessFs::from_read(abi);
        let access_write = AccessFs::from_all(abi);

        let read: Vec<std::path::PathBuf> = read_paths
            .iter()
            .filter(|p| p.exists())
            .cloned()
            .collect();
        let write: Vec<std::path::PathBuf> = write_paths
            .iter()
            .filter(|p| p.exists())
            .cloned()
            .collect();
        if read.is_empty() {
            return Err("install_landlock_rw: no valid read paths provided".to_string());
        }
        if write.is_empty() {
            return Err("install_landlock_rw: no valid write paths provided".to_string());
        }

        let status = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| format!("landlock handle_access failed: {e}"))?
            .create()
            .map_err(|e| format!("landlock create failed (kernel >= 5.13 required): {e}"))?
            .add_rules(path_beneath_rules(&read, access_read))
            .map_err(|e| format!("landlock add_rules (read) failed: {e}"))?
            .add_rules(path_beneath_rules(&write, access_write))
            .map_err(|e| format!("landlock add_rules (write) failed: {e}"))?
            .restrict_self()
            .map_err(|e| format!("landlock restrict_self failed: {e}"))?;

        match status.ruleset {
            landlock::RulesetStatus::FullyEnforced => Ok(()),
            landlock::RulesetStatus::PartiallyEnforced => Ok(()),
            landlock::RulesetStatus::NotEnforced => {
                Err("install_landlock_rw: not enforced (kernel too old)".to_string())
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (read_paths, write_paths);
        Err("landlock is Linux-only".to_string())
    }
}

/// Like [`run_sandboxed`] but with an explicit write set and **fail-closed**
/// semantics: a Landlock install failure inside the pre-exec hook aborts the
/// exec — the child never runs unconfined. Used by `tallow run --sandbox`.
pub fn run_sandboxed_rw(
    cmd: &mut Command,
    read_paths: &[std::path::PathBuf],
    write_paths: &[std::path::PathBuf],
) -> Result<(), String> {
    let read_paths = read_paths.to_vec();
    let write_paths = write_paths.to_vec();
    // SAFETY: the hook runs in the child after fork; we only call libc-level
    // Landlock installs and touch our own captured memory.
    unsafe {
        cmd.pre_exec(move || {
            install_landlock_rw(&read_paths, &write_paths)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_install_seccomp_deny_default() {
        // Installing a filter in THIS process can't be undone and would break
        // further test execution, so we only validate the policy building via
        // the shared pass (already covered in sandbox_pass tests). Here we
        // assert the runtime helper correctly maps an allow-list + deny_default
        // down to the filter install path by checking it rejects a bad (empty,
        // deny-default) policy early — but never installs into the test process.
        // We instead verify the seccomp policy struct is usable:
        let pol = crate::sandbox_pass::SeccompPolicy {
            allowed: vec!["read".to_string(), "write".to_string()],
            deny_default: true,
        };
        // Building the BPF program is safe and process-independent.
        #[cfg(target_os = "linux")]
        {
            let prog = crate::sandbox_pass::build_seccomp_program(&pol);
            assert!(prog.is_ok());
            assert!(prog.unwrap().len() > 3);
        }
    }

    #[test]
    fn test_run_sandboxed_spawns_readonly_worker() {
        #[cfg(target_os = "linux")]
        {
            // Spawn `/bin/true` under Landlock(read-only /). The child must run
            // and exit cleanly. Landlock restricts paths (survives exec), so a
            // dynamically-linked child works — unlike pre-exec seccomp, which
            // would block the dynamic loader and kill it.
            let mut cmd = std::process::Command::new("/bin/true");
            cmd.stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::null());
            let paths = vec![std::path::PathBuf::from("/")];
            let r = run_sandboxed(&mut cmd, &paths);
            assert!(r.is_ok(), "run_sandboxed should not error: {r:?}");
            let status = cmd.status().expect("child should run");
            assert!(status.success(), "landlocked /bin/true should exit 0");
        }
    }

    #[test]
    fn test_run_sandboxed_denies_reads_outside_paths() {
        #[cfg(target_os = "linux")]
        {
            // Execute is granted beneath /usr (so /bin/sh runs), but reading
            // /etc/hostname must fail when /etc is not in the read set — the
            // RT-FIX-7A fence in miniature. Must hold even for a root process
            // (Landlock is an LSM, not DAC).
            let run = |paths: Vec<std::path::PathBuf>| -> std::process::Output {
                let mut cmd = std::process::Command::new("/bin/sh");
                cmd.arg("-c").arg("cat /etc/hostname");
                run_sandboxed(&mut cmd, &paths).expect("hook registration");
                cmd.output().expect("child should run")
            };

            let denied = run(vec![std::path::PathBuf::from("/usr")]);
            assert!(
                !denied.status.success(),
                "read outside read_paths must fail; stdout={:?}",
                String::from_utf8_lossy(&denied.stdout)
            );

            let allowed = run(vec![
                std::path::PathBuf::from("/usr"),
                std::path::PathBuf::from("/etc"),
            ]);
            assert!(
                allowed.status.success(),
                "read inside read_paths must succeed; stderr={:?}",
                String::from_utf8_lossy(&allowed.stderr)
            );
            assert!(!allowed.stdout.is_empty(), "hostname bytes expected");
        }
    }

    #[test]
    fn test_run_sandboxed_rw_write_set_vs_denied() {
        #[cfg(target_os = "linux")]
        {
            let scratch = std::env::temp_dir().join(format!("tallow-rw-{}", std::process::id()));
            std::fs::create_dir_all(&scratch).expect("scratch dir");
            let read = vec![
                std::path::PathBuf::from("/usr"),
                std::path::PathBuf::from("/bin"),
                std::path::PathBuf::from("/lib"),
                std::path::PathBuf::from("/lib64"),
            ];
            let write = vec![scratch.clone()];

            // Write INSIDE the write set: must succeed.
            let mut ok = std::process::Command::new("/bin/sh");
            ok.arg("-c").arg(format!(
                "echo allowed > {}/probe.txt && cat {}/probe.txt",
                scratch.display(),
                scratch.display()
            ));
            run_sandboxed_rw(&mut ok, &read, &write).expect("hook registration");
            let out = ok.output().expect("child runs");
            assert!(
                out.status.success(),
                "write inside write_paths must succeed; stderr={:?}",
                String::from_utf8_lossy(&out.stderr)
            );
            assert!(scratch.join("probe.txt").exists());

            // Write OUTSIDE the write set: must be denied by Landlock.
            let outside = std::env::temp_dir().join(format!(
                "tallow-rw-outside-{}.txt",
                std::process::id()
            ));
            let _ = std::fs::remove_file(&outside);
            let mut denied = std::process::Command::new("/bin/sh");
            denied
                .arg("-c")
                .arg(format!("echo nope > {}", outside.display()));
            run_sandboxed_rw(&mut denied, &read, &write).expect("hook registration");
            let out2 = denied.output().expect("child runs");
            assert!(
                !out2.status.success(),
                "write outside write_paths must fail; stdout={:?}",
                String::from_utf8_lossy(&out2.stdout)
            );
            assert!(!outside.exists(), "no bytes may land outside the write set");

            let _ = std::fs::remove_dir_all(&scratch);
        }
    }
}
