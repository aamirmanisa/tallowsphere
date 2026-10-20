//! Process-level hardening applied at startup (P10-R13 / T-125).
//!
//! Two idempotent, best-effort steps:
//!
//! 1. **No core dumps** — `RLIMIT_CORE` soft *and* hard limits are set to `0`
//!    so secrets held in memory can never be written to disk by a crash. This
//!    deliberately re-asserts what
//!    `tallow_crypto::mem::wipe::prevent_core_dumps()` already does, so the
//!    guarantee also holds on paths that skip (or fail) the crypto-library
//!    init.
//! 2. **File-descriptor floor** — the soft `RLIMIT_NOFILE` is raised to
//!    `NOFILE_SOFT_FLOOR` when the environment starts lower, never above the
//!    current hard limit and never lowered, so long-lived browser/daemon
//!    workloads avoid spurious `EMFILE` failures.
//!
//! [`apply_process_hardening`] is safe to call more than once and is expected
//! to run before any secret-bearing work (key loading, vault access, network
//! I/O). A restricted environment may deny `setrlimit`; callers should warn
//! and continue — but never silently ignore the failure.
//!
//! On non-Unix platforms both steps are no-ops returning `Ok(())`.

use std::io;

/// Target soft floor for `RLIMIT_NOFILE` (raised only when the current soft
/// limit is lower; capped by the current hard limit). 4096 covers
/// Chromium-family browser workloads and typical daemon connection counts.
#[cfg(unix)]
pub const NOFILE_SOFT_FLOOR: libc::rlim_t = 4096;

/// Apply process hardening (no core dumps; `RLIMIT_NOFILE` floor).
///
/// Idempotent: calling it again after a successful run leaves the limits
/// unchanged. Returns an error only when the platform rejects the request
/// (e.g. `setrlimit` denied by a sandbox).
pub fn apply_process_hardening() -> io::Result<()> {
    #[cfg(unix)]
    {
        disable_core_dumps()?;
        ensure_nofile_floor(NOFILE_SOFT_FLOOR)?;
    }
    Ok(())
}

/// Set `RLIMIT_CORE` soft + hard to 0 (idempotent fast path when already 0/0).
#[cfg(unix)]
fn disable_core_dumps() -> io::Result<()> {
    let lim = get_rlimit(libc::RLIMIT_CORE)?;
    if lim.rlim_cur == 0 && lim.rlim_max == 0 {
        return Ok(());
    }
    set_rlimit(libc::RLIMIT_CORE, 0, 0)
}

/// Raise the soft `RLIMIT_NOFILE` to `floor` when below it (never above the
/// hard limit, never lowering an already-sufficient soft limit).
#[cfg(unix)]
fn ensure_nofile_floor(floor: libc::rlim_t) -> io::Result<()> {
    let lim = get_rlimit(libc::RLIMIT_NOFILE)?;
    if lim.rlim_cur >= floor {
        return Ok(());
    }
    let target = floor.min(lim.rlim_max);
    if target <= lim.rlim_cur {
        // Hard limit is already below the floor; nothing safe to raise.
        return Ok(());
    }
    set_rlimit(libc::RLIMIT_NOFILE, target, lim.rlim_max)
}

/// The resource argument type differs by libc: glibc names it
/// `__rlimit_resource_t`, musl (and the BSDs) take a plain `c_int`. Naming the
/// alias here is what lets one source tree build for both (musl target found
/// this: `__rlimit_resource_t` does not exist there).
#[cfg(all(unix, not(target_env = "musl")))]
pub type RlimitResource = libc::__rlimit_resource_t;
#[cfg(all(unix, target_env = "musl"))]
pub type RlimitResource = libc::c_int;

/// Read a resource limit via `getrlimit(2)`.
#[cfg(unix)]
pub fn get_rlimit(resource: RlimitResource) -> io::Result<libc::rlimit> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is a valid, fully initialized `rlimit`; the kernel writes
    // the current limits of `resource` into it and does not retain the pointer.
    if unsafe { libc::getrlimit(resource, &mut lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(lim)
}

/// Set both limits of `resource` via `setrlimit(2)`.
#[cfg(unix)]
pub fn set_rlimit(resource: RlimitResource, soft: libc::rlim_t, hard: libc::rlim_t) -> io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: soft,
        rlim_max: hard,
    };
    // SAFETY: `lim` is a valid, fully initialized `rlimit`; setrlimit only
    // reads it for the duration of the call.
    if unsafe { libc::setrlimit(resource, &lim) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// Both steps are applied in one shot: the CORE readback is 0/0, the
    /// NOFILE floor is respected without ever lowering anything, and a second
    /// call is a no-op (idempotent). The process's previous limits are
    /// restored where the environment allows it (restoring a lowered *hard*
    /// limit needs `CAP_SYS_RESOURCE`, e.g. when running as root) so the rest
    /// of the suite is unaffected.
    #[test]
    fn apply_process_hardening_sets_limits_and_is_idempotent() {
        let core_before = get_rlimit(libc::RLIMIT_CORE).expect("read initial RLIMIT_CORE");
        let nofile_before = get_rlimit(libc::RLIMIT_NOFILE).expect("read initial RLIMIT_NOFILE");

        for attempt in 1..=2 {
            let res = apply_process_hardening();
            assert!(
                res.is_ok(),
                "apply_process_hardening() attempt {attempt} failed: {res:?}"
            );
        }

        let core_after = get_rlimit(libc::RLIMIT_CORE).expect("read hardened RLIMIT_CORE");
        assert_eq!(core_after.rlim_cur, 0, "RLIMIT_CORE soft limit must be 0");
        assert_eq!(core_after.rlim_max, 0, "RLIMIT_CORE hard limit must be 0");

        let nofile_after = get_rlimit(libc::RLIMIT_NOFILE).expect("read hardened RLIMIT_NOFILE");
        let expected_floor = NOFILE_SOFT_FLOOR
            .min(nofile_before.rlim_max)
            .max(nofile_before.rlim_cur);
        assert!(
            nofile_after.rlim_cur >= expected_floor,
            "RLIMIT_NOFILE soft {} is below expected floor {} (was {})",
            nofile_after.rlim_cur,
            expected_floor,
            nofile_before.rlim_cur
        );
        assert!(
            nofile_after.rlim_cur <= nofile_before.rlim_max,
            "RLIMIT_NOFILE soft {} was raised above the hard limit {}",
            nofile_after.rlim_cur,
            nofile_before.rlim_max
        );

        // Restore. Lowering the soft NOFILE limit is always permitted;
        // restoring a lowered *hard* CORE limit needs CAP_SYS_RESOURCE, so it
        // is best-effort — the test never fails on an unprivileged host.
        set_rlimit(
            libc::RLIMIT_NOFILE,
            nofile_before.rlim_cur,
            nofile_before.rlim_max,
        )
        .expect("restore RLIMIT_NOFILE");
        match set_rlimit(libc::RLIMIT_CORE, core_before.rlim_cur, core_before.rlim_max) {
            Ok(()) => {
                let restored = get_rlimit(libc::RLIMIT_CORE).expect("read restored RLIMIT_CORE");
                assert_eq!(
                    restored.rlim_cur, core_before.rlim_cur,
                    "RLIMIT_CORE soft limit must be restored"
                );
            }
            Err(err) => eprintln!(
                "note: RLIMIT_CORE left disabled (soft+hard 0); restoring the hard limit needs CAP_SYS_RESOURCE: {err}"
            ),
        }
    }
}
