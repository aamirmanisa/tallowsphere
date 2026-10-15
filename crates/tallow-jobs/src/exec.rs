//! Subprocess runner for `tallow run <script> [-- <args...>]` with a hard
//! timeout, optional per-recipe working directory, and output capture.

use crate::recipe::EgressMode;
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// Outcome of one script execution.
#[derive(Debug, Clone)]
pub struct RunOutcome {
    /// Process exit code (`None` if killed by signal).
    pub exit_code: Option<i32>,
    pub timed_out: bool,
    pub duration_ms: u64,
    pub stdout: String,
    pub stderr: String,
}

impl RunOutcome {
    /// A run is successful when it exited 0 and was not killed.
    pub fn ok(&self) -> bool {
        !self.timed_out && self.exit_code == Some(0)
    }
}

/// Binary used to execute recipes; `TALLOW_JOBS_TALLOW_BIN` overrides
/// (used by tests / non-PATH installs).
pub fn tallow_bin() -> String {
    std::env::var("TALLOW_JOBS_TALLOW_BIN").unwrap_or_else(|_| "tallow".to_string())
}

/// Env operations implied by an egress policy: (`key=value` sets, removals).
///
/// The runtime's precedence is `TALLOW_PROXY` → `TALLOW_ALLOW_DIRECT` →
/// fail-closed Tor default, so:
/// - `Tor` strips an ambient `TALLOW_ALLOW_DIRECT` (a declaration of tor must
///   not be silently overridden; ambient `TALLOW_PROXY` remains the explicit
///   operator override per the contract).
/// - `Direct` strips ambient `TALLOW_PROXY` (which would otherwise win by
///   precedence) and forces `TALLOW_ALLOW_DIRECT=1`.
pub fn egress_env_ops(mode: EgressMode) -> (Vec<(&'static str, &'static str)>, Vec<&'static str>) {
    match mode {
        EgressMode::Tor => (Vec::new(), vec!["TALLOW_ALLOW_DIRECT"]),
        EgressMode::Direct => (vec![("TALLOW_ALLOW_DIRECT", "1")], vec!["TALLOW_PROXY"]),
    }
}

/// Run `tallow run <script>`, optionally from `cwd`.
pub fn run_script(
    script: &Path,
    timeout: Duration,
    envs: &[(String, String)],
) -> std::io::Result<RunOutcome> {
    run_recipe(script, &[], None, timeout, envs, EgressMode::Tor)
}

/// Run `tallow run <script> [-- args...]`, optionally from `cwd`, under the
/// recipe's declared egress policy.
pub fn run_recipe(
    script: &Path,
    args: &[String],
    cwd: Option<&Path>,
    timeout: Duration,
    envs: &[(String, String)],
    egress: EgressMode,
) -> std::io::Result<RunOutcome> {
    run_recipe_with_bin(&tallow_bin(), script, args, cwd, timeout, envs, egress)
}

pub const OUTPUT_CAP: usize = 256 * 1024;

/// Simplified runner (no args / no cwd) — kept for tests.
pub fn run_with_bin(
    bin: &str,
    script: &Path,
    timeout: Duration,
    envs: &[(String, String)],
) -> std::io::Result<RunOutcome> {
    run_recipe_with_bin(bin, script, &[], None, timeout, envs, EgressMode::Tor)
}

/// Full runner: binary override, args, cwd, egress policy.
pub fn run_recipe_with_bin(
    bin: &str,
    script: &Path,
    args: &[String],
    cwd: Option<&Path>,
    timeout: Duration,
    envs: &[(String, String)],
    egress: EgressMode,
) -> std::io::Result<RunOutcome> {
    let start = Instant::now();
    let mut cmd = Command::new(bin);
    cmd.arg("run").arg(script);
    if !args.is_empty() {
        cmd.arg("--");
        for a in args {
            cmd.arg(a);
        }
    }
    if let Some(d) = cwd {
        cmd.current_dir(d);
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let (sets, removes) = egress_env_ops(egress);
    for (k, v) in sets {
        cmd.env(k, v);
    }
    for k in removes {
        cmd.env_remove(k);
    }
    let mut child = cmd.spawn()?;

    let out_pipe = child.stdout.take().expect("piped stdout");
    let err_pipe = child.stderr.take().expect("piped stderr");
    let obuf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
    let ebuf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));

    let t_out = {
        let buf = Arc::clone(&obuf);
        std::thread::spawn(move || read_all(out_pipe, buf))
    };
    let t_err = {
        let buf = Arc::clone(&ebuf);
        std::thread::spawn(move || read_all(err_pipe, buf))
    };

    let mut timed_out = false;
    let exit_code;
    loop {
        match child.try_wait()? {
            Some(status) => {
                exit_code = status.code();
                break;
            }
            None => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let status = child.wait()?;
                    exit_code = status.code();
                    timed_out = true;
                    break;
                }
                std::thread::sleep(Duration::from_millis(20));
            }
        }
    }

    let _ = t_out.join();
    let _ = t_err.join();

    let stdout = String::from_utf8_lossy(&obuf.lock().expect("stdout lock")).into_owned();
    let stderr = String::from_utf8_lossy(&ebuf.lock().expect("stderr lock")).into_owned();
    Ok(RunOutcome {
        exit_code,
        timed_out,
        duration_ms: start.elapsed().as_millis() as u64,
        stdout: cap_tail(stdout),
        stderr: cap_tail(stderr),
    })
}

fn read_all(mut pipe: impl Read, buf: Arc<Mutex<Vec<u8>>>) {
    let mut chunk = [0u8; 8192];
    loop {
        match pipe.read(&mut chunk) {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                let mut b = buf.lock().expect("buf lock");
                b.extend_from_slice(&chunk[..n]);
            }
        }
    }
}

/// Keep the last [`OUTPUT_CAP`] bytes (most useful tail).
fn cap_tail(mut s: String) -> String {
    if s.len() > OUTPUT_CAP {
        let cut = s.len() - OUTPUT_CAP;
        // Move to a char boundary.
        let mut idx = cut;
        while !s.is_char_boundary(idx) {
            idx += 1;
        }
        s = s.split_off(idx);
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn egress_ops_map_to_contract() {
        let (sets, removes) = egress_env_ops(EgressMode::Tor);
        assert!(sets.is_empty());
        assert_eq!(removes, vec!["TALLOW_ALLOW_DIRECT"]);

        let (sets, removes) = egress_env_ops(EgressMode::Direct);
        assert_eq!(sets, vec![("TALLOW_ALLOW_DIRECT", "1")]);
        assert_eq!(removes, vec!["TALLOW_PROXY"]);
    }
}
