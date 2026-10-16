//! Standard library: `tallow.process` -- Process management.
//!
//! Provides process.exec/run (synchronous), process.spawn (async with handle),
//! process.exit, process.pid. ChildProcess struct supports .wait() and .kill().

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
        if name != "ChildProcess" {
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
            _ => None,
        }
    } else {
        None
    }
}

fn process_exec(args: Vec<Value>) -> StdlibResult {
    let cmd = args.first().map(|v| v.as_string()).unwrap_or_default();
    if cmd.is_empty() {
        return Err("process.exec requires a command string".into());
    }
    let args_list: Vec<String> = args.iter().skip(1).map(|v| v.as_string()).collect();
    match Command::new(&cmd).args(&args_list).output() {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let status_code = output.status.code().unwrap_or(-1);
            Ok(Value::Struct {
                name: "ProcessResult".to_string(),
                fields: vec![
                    ("stdout".to_string(), Value::String(stdout)),
                    ("stderr".to_string(), Value::String(stderr)),
                    ("status".to_string(), Value::Int(status_code as i128)),
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
    let args_list: Vec<String> = args.iter().skip(1).map(|v| v.as_string()).collect();
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
                name: "ChildProcess".to_string(),
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
                    name: "ProcessResult".to_string(),
                    fields: vec![
                        ("stdout".to_string(), Value::String(stdout)),
                        ("stderr".to_string(), Value::String(stderr)),
                        ("status".to_string(), Value::Int(status_code as i128)),
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
                // Remove after kill
                drop(map);
                let mut map = CHILD_PROCESSES.lock().unwrap();
                map.remove(&pid);
                Ok(Value::Nil)
            }
            Err(e) => Ok(Value::Err(Box::new(Value::String(e.to_string())))),
        },
        None => Err(format!("No child process with pid {pid}")),
    }
}
