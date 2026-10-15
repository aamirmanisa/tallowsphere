//! Standard library: `tallow.env` -- Environment variables.

use super::StdlibResult;
use crate::interp::Value;

/// Dispatch a `tallow.env.*` function call.
///
/// Functions already implemented inline in interp.rs (get, cwd, home, args)
/// return None to fall through.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        // Implemented inline in interp.rs — fall through
        "get" | "cwd" | "home" | "args" => None,

        "home_dir" => Some(env_home_dir(&args)),
        "config_dir" => Some(env_config_dir(&args)),
        "data_dir" => Some(env_data_dir(&args)),
        "temp_dir" => Some(env_temp_dir(&args)),
        "cache_dir" => Some(env_cache_dir(&args)),

        // Declared in stdlib/env.tl with empty `// native:` bodies, previously
        // absent from every dispatcher. Implemented 2026-10-12.
        "get_or" => {
            let name = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => {
                    return Some(Err(
                        "env.get_or expects (name: String, default: String)".into(),
                    ))
                }
            };
            let default = match args.get(1) {
                Some(Value::String(s)) => s.clone(),
                _ => {
                    return Some(Err(
                        "env.get_or expects (name: String, default: String)".into(),
                    ))
                }
            };
            Some(Ok(Value::String(
                std::env::var(&name).unwrap_or(default),
            )))
        }

        "exe_path" => match std::env::current_exe() {
            Ok(p) => Some(Ok(Value::String(p.to_string_lossy().into_owned()))),
            Err(e) => Some(Err(format!("env.exe_path: {e}"))),
        },

        "set" => {
            let name = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => return Some(Err("env.set expects (name: String, value: String)".into())),
            };
            let value = match args.get(1) {
                Some(Value::String(s)) => s.clone(),
                _ => return Some(Err("env.set expects (name: String, value: String)".into())),
            };
            // SAFETY: set_var is unsafe since Rust 1.78 due to potential data races
            // in multi-threaded programs. The Tallow interpreter is single-threaded.
            unsafe {
                std::env::set_var(&name, &value);
            }
            Some(Ok(Value::Nil))
        }

        "all" => {
            let pairs: Vec<(Value, Value)> = std::env::vars()
                .map(|(k, v)| (Value::String(k), Value::String(v)))
                .collect();
            Some(Ok(Value::Map(pairs)))
        }

        _ => None,
    }
}

/// Dispatch a method call on a `tallow.env` object.
pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

// ── Platform-aware directory functions ────────────────────────────────────

fn env_home_dir(_args: &[Value]) -> StdlibResult {
    let home = if cfg!(windows) {
        std::env::var("USERPROFILE")
            .or_else(|_| std::env::var("HOME"))
            .unwrap_or_default()
    } else {
        std::env::var("HOME").unwrap_or_default()
    };
    Ok(Value::String(home))
}

fn env_config_dir(_args: &[Value]) -> StdlibResult {
    let dir = if cfg!(windows) {
        std::env::var("APPDATA").unwrap_or_default()
    } else if cfg!(target_os = "macos") {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{}/Library/Application Support", home)
    } else {
        std::env::var("XDG_CONFIG_HOME").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            format!("{}/.config", home)
        })
    };
    Ok(Value::String(dir))
}

fn env_data_dir(_args: &[Value]) -> StdlibResult {
    let dir = if cfg!(windows) {
        std::env::var("LOCALAPPDATA").unwrap_or_default()
    } else if cfg!(target_os = "macos") {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{}/Library/Application Support", home)
    } else {
        std::env::var("XDG_DATA_HOME").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            format!("{}/.local/share", home)
        })
    };
    Ok(Value::String(dir))
}

fn env_temp_dir(_args: &[Value]) -> StdlibResult {
    let dir = std::env::temp_dir().to_string_lossy().to_string();
    Ok(Value::String(dir))
}

fn env_cache_dir(_args: &[Value]) -> StdlibResult {
    let dir = if cfg!(windows) {
        let local = std::env::var("LOCALAPPDATA").unwrap_or_default();
        format!("{}/Temp", local)
    } else if cfg!(target_os = "macos") {
        let home = std::env::var("HOME").unwrap_or_default();
        format!("{}/Library/Caches", home)
    } else {
        std::env::var("XDG_CACHE_HOME").unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_default();
            format!("{}/.cache", home)
        })
    };
    Ok(Value::String(dir))
}
