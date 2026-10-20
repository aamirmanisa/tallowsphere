//! Standard library: `tallow.process` -- Process management.
//!
//! Provides process.exec/run (synchronous), process.spawn (async with handle),
//! process.exit, process.pid. The handle struct is `Process` (the name
//! `stdlib/process.tl` declares) and supports .wait(), .kill() and .is_running().
//! `ChildProcess` is still accepted from older values.

use super::StdlibResult;
use crate::interp::Value;
use std::collections::HashMap;
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

static CHILD_PROCESSES: std::sync::LazyLock<Mutex<HashMap<u32, Child>>> =
    std::sync::LazyLock::new(|| Mutex::new(HashMap::new()));

/// Dispatch a `tallow.process.*` function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "exec" | "run" => Some(process_exec(args)),
        "spawn" => Some(process_spawn(args)),
        "exit" => {
            let code = match args.first() {
                Some(Value::Int(n)) => *n as i32,
                _ => 0,
            };
            std::process::exit(code);
        }
        "pid" => Some(Ok(Value::Int(std::process::id() as i128))),
        _ => None,
    }
}

/// Dispatch a method call on a ChildProcess struct.
pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    if let Value::Struct { name, fields } = object {
        // `stdlib/process.tl` declares the handle as `Process`; the router used to
        // dispatch only `ChildProcess`, so every declared method was unreachable.
        // Accept both names rather than renaming either side.
        if name != "ChildProcess" && name != "Process" {
            return None;
        }
        let pid = fields
            .iter()
            .find(|(k, _)| k == "pid")
            .and_then(|(_, v)| if let Value::Int(n) = v { Some(*n as u32) } else { None });
        let pid = match pid {
            Some(p) => p,
            None => return Some(Err("ChildProcess has no pid".into())),
        };

        match method {
            "wait" => Some(child_wait(pid)),
            "kill" => Some(child_kill(pid)),
            "is_running" => Some(child_is_running(pid)),
            _ => None,
        }
    } else {
        None
    }
}

/// `Process.is_running()` — reap-aware liveness.
///
/// `kill(pid, 0)` alone reports a zombie as alive: the child has exited but the
/// kernel keeps the pid until someone waits. `try_wait` answers the real question
/// and reaps the entry when the process is gone.
fn child_is_running(pid: u32) -> StdlibResult {
    let mut map = CHILD_PROCESSES.lock().unwrap();
    if let Some(child) = map.get_mut(&pid) {
        return match child.try_wait() {
            Ok(None) => Ok(Value::Bool(true)),
            Ok(Some(_)) => {
                map.remove(&pid);
                Ok(Value::Bool(false))
            }
            Err(e) => Err(format!("is_running: {e}")),
        };
    }
    // Not one of ours: fall back to the signal-0 probe.
    #[cfg(unix)]
    {
        Ok(Value::Bool(unsafe { libc::kill(pid as i32, 0) } == 0))
    }
    #[cfg(not(unix))]
    {
        Err("Process.is_running: handle is not tracked and this platform has no probe".into())
    }
}


/// Flatten `args: []String` call arguments.
///
/// The declared surface takes an array, but the positionals arrive as one
/// `Value::Array`; mapping `as_string` over them stringified the whole array and
/// handed the child a single argument that looked like `["hello"]`. Expand arrays
/// one level instead, which is what the signature promises.
fn flatten_args(args: &[Value]) -> Vec<String> {
    let mut out = Vec::new();
    for a in args {
        match a {
            Value::Array(items) => out.extend(items.iter().map(|v| v.as_string())),
            _ => out.push(a.as_string()),
        }
    }
    out
}

fn process_exec(args: Vec<Value>) -> StdlibResult {
    let cmd = args.first().map(|v| v.as_string()).unwrap_or_default();
    if cmd.is_empty() {
        return Err("process.exec requires a command string".into());
    }
    let args_list = flatten_args(&args[1..]);
    match Command::new(&cmd).args(&args_list).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let status_code = output.status.code().unwrap_or(-1);
            Ok(Value::Struct {
                name: "Output".to_string(),
                fields: vec![
                    ("stdout".to_string(), Value::String(stdout)),
                    ("stderr".to_string(), Value::String(stderr)),
                    ("exit_code".to_string(), Value::Int(status_code as i128)),
                    ("success".to_string(), Value::Bool(output.status.success())),
                ],
            })
        }
        Err(e) => Ok(Value::Err(Box::new(Value::String(e.to_string())))),
    }
}

fn process_spawn(args: Vec<Value>) -> StdlibResult {
    let cmd = args.first().map(|v| v.as_string()).unwrap_or_default();
    if cmd.is_empty() {
        return Err("process.spawn requires a command string".into());
    }
    let args_list = flatten_args(&args[1..]);
    match Command::new(&cmd)
        .args(&args_list)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => {
            let pid = child.id();
            CHILD_PROCESSES.lock().unwrap().insert(pid, child);
            Ok(Value::Struct {
                // The language declares `Process`; producing `ChildProcess` made the
                // declared type unnameable and hid every method behind a name the
                // router had to be taught separately.
                name: "Process".to_string(),
                fields: vec![
                    ("pid".to_string(), Value::Int(pid as i128)),
                    ("running".to_string(), Value::Bool(true)),
                ],
            })
        }
        Err(e) => Ok(Value::Err(Box::new(Value::String(e.to_string())))),
    }
}

fn child_wait(pid: u32) -> StdlibResult {
    let mut map = CHILD_PROCESSES.lock().unwrap();
    match map.remove(&pid) {
        Some(child) => match child.wait_with_output() {
            Ok(output) => {
                let stdout = String::from_utf8_lossy(&output.stdout).to_string();
                let stderr = String::from_utf8_lossy(&output.stderr).to_string();
                let status_code = output.status.code().unwrap_or(-1);
                Ok(Value::Struct {
                    name: "Output".to_string(),
                    fields: vec![
                        ("stdout".to_string(), Value::String(stdout)),
                        ("stderr".to_string(), Value::String(stderr)),
                        ("exit_code".to_string(), Value::Int(status_code as i128)),
                        ("success".to_string(), Value::Bool(output.status.success())),
                    ],
                })
            }
            Err(e) => Ok(Value::Err(Box::new(Value::String(e.to_string())))),
        },
        None => Err(format!("No child process with pid {pid}")),
    }
}

fn child_kill(pid: u32) -> StdlibResult {
    let mut map = CHILD_PROCESSES.lock().unwrap();
    match map.get_mut(&pid) {
        Some(child) => match child.kill() {
            Ok(()) => {
                // Reap before dropping the handle. A killed-but-unreaped child stays
                // a zombie, and the signal-0 probe reports zombies as alive, so
                // is_running() used to stay true after a successful kill.
                let _ = child.wait();
                map.remove(&pid);
                Ok(Value::Nil)
            }
            Err(e) => Ok(Value::Err(Box::new(Value::String(e.to_string())))),
        },
        None => Err(format!("No child process with pid {pid}")),
    }
}
