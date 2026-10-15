//! Standard library: `tallow.log` -- Structured logging (privacy-aware).
//!
//! The `log.debug/info/warn/error/fatal` *calls* are implemented inline in
//! `interp.rs` (they need the interpreter's privacy handling). This module owns
//! the **configuration** those calls consult: minimum level, output format and
//! output sink. `set_level` / `set_format` / `set_output` were declared in
//! `stdlib/log.tl` with empty `// native:` bodies and were previously absent
//! from every dispatcher, so they were uncallable. Implemented 2026-10-12.

use super::StdlibResult;
use crate::interp::Value;
use std::io::Write;
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::{LazyLock, Mutex};

// ── Level ranking ────────────────────────────────────────────────────────────

/// Severity rank. Higher is more severe. `None` for an unrecognised name so
/// callers can reject rather than silently pick a default.
fn level_rank(name: &str) -> Option<u8> {
    match name.to_ascii_lowercase().as_str() {
        "debug" => Some(1),
        "info" => Some(2),
        "warn" | "warning" => Some(3),
        "error" => Some(4),
        "fatal" => Some(5),
        _ => None,
    }
}

/// Default is `debug` — the *least* restrictive level the language exposes
/// (`info/debug/warn/error/fatal`; there is no `trace`).
///
/// This is load-bearing: every level must still emit by default, or adding the
/// filter would silently change behaviour for existing scripts. The interpreter
/// test `log_multiple_levels` asserts all four of debug/info/warn/error produce
/// output, and would fail against any stricter default.
const DEFAULT_MIN_LEVEL: u8 = 1;

static MIN_LEVEL: AtomicU8 = AtomicU8::new(DEFAULT_MIN_LEVEL);

/// 0 = text, 1 = json.
static FORMAT: AtomicU8 = AtomicU8::new(0);

static OUTPUT_PATH: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

// ── Hooks used by the interpreter's log emission ─────────────────────────────

/// Whether a message at `level_name` should be emitted at all.
///
/// An unrecognised level name emits rather than being dropped — losing a log
/// line because of a typo is worse than being slightly too verbose.
pub fn should_emit(level_name: &str) -> bool {
    match level_rank(level_name) {
        Some(rank) => rank >= MIN_LEVEL.load(Ordering::Relaxed),
        None => true,
    }
}

/// Whether `set_format("json")` was requested.
pub fn is_json_format() -> bool {
    FORMAT.load(Ordering::Relaxed) == 1
}

/// Write one already-formatted line to the configured sink.
///
/// Falls back to stderr if a configured file cannot be written, and says so —
/// a redirect that silently stops logging is its own failure mode.
pub fn emit(line: &str) {
    let path = OUTPUT_PATH
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or(None);
    match path {
        None => eprintln!("{line}"),
        Some(p) => match std::fs::OpenOptions::new().create(true).append(true).open(&p) {
            Ok(mut file) => {
                let _ = writeln!(file, "{line}");
            }
            Err(e) => {
                eprintln!("{line}");
                eprintln!("[WARN] log.set_output: cannot write '{p}': {e} — falling back to stderr");
            }
        },
    }
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

/// Dispatch a `tallow.log.*` function call.
///
/// The `info`/`warn`/`error`/`debug`/`fatal` calls are implemented inline in
/// interp.rs — return None to fall through. `set_level`/`set_format`/
/// `set_output` are real implementations here.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        // Implemented inline in interp.rs — fall through
        "info" | "warn" | "error" | "debug" | "fatal" => None,

        "set_level" => Some(set_level(args)),
        "set_format" => Some(set_format(args)),
        "set_output" => Some(set_output(args)),

        _ => None,
    }
}

/// Dispatch a method call on a `tallow.log` object.
pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

/// Accept a `Level` as a string (`"info"`) or an enum value (`Level.Info`).
fn level_arg(args: &[Value]) -> Result<String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(Value::Enum { variant, .. }) => Ok(variant.clone()),
        _ => Err("log.set_level expects a Level (string or enum)".into()),
    }
}

fn set_level(args: Vec<Value>) -> StdlibResult {
    let raw = level_arg(&args)?;
    match level_rank(&raw) {
        Some(rank) => {
            MIN_LEVEL.store(rank, Ordering::Relaxed);
            Ok(Value::Nil)
        }
        None => Err(format!(
            "log.set_level: unknown level '{raw}' (expected debug, info, warn, error or fatal)"
        )),
    }
}

fn parse_format(name: &str) -> Option<u8> {
    match name.to_ascii_lowercase().as_str() {
        "text" | "plain" => Some(0),
        "json" => Some(1),
        _ => None,
    }
}

fn set_format(args: Vec<Value>) -> StdlibResult {
    let raw = match args.first() {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Enum { variant, .. }) => variant.clone(),
        _ => return Err("log.set_format expects a Format (string or enum)".into()),
    };
    match parse_format(&raw) {
        Some(f) => {
            FORMAT.store(f, Ordering::Relaxed);
            Ok(Value::Nil)
        }
        None => Err(format!(
            "log.set_format: unknown format '{raw}' (expected text or json)"
        )),
    }
}

fn set_output(args: Vec<Value>) -> StdlibResult {
    let path = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("log.set_output expects a string path".into()),
    };
    // Prove we can actually write it *now*, so a bad path fails at the call
    // site instead of silently at the first log line.
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("log.set_output: cannot open '{path}': {e}"))?;
    match OUTPUT_PATH.lock() {
        Ok(mut guard) => *guard = Some(path),
        Err(_) => return Err("log.set_output: output path mutex poisoned".into()),
    }
    Ok(Value::Nil)
}

#[cfg(test)]
mod tests {
    use super::*;

    // NOTE: deliberately only the *pure* helpers are unit-tested here.
    // `set_level`/`set_format`/`set_output` mutate process-wide statics, and
    // Rust runs tests in parallel — mutating a global here could break the
    // interpreter's own log tests (which assert on output line counts) with a
    // flaky failure. Those paths are covered by end-to-end probes instead,
    // which run in a separate process and therefore cannot interfere.

    #[test]
    fn level_rank_is_ordered_and_rejects_unknown() {
        assert!(level_rank("debug") < level_rank("info"));
        assert!(level_rank("info") < level_rank("warn"));
        assert!(level_rank("warn") < level_rank("error"));
        assert!(level_rank("error") < level_rank("fatal"));
        assert_eq!(level_rank("WARNING"), level_rank("warn"));
        assert_eq!(level_rank("DEBUG"), level_rank("debug"));
        assert_eq!(level_rank("verbose"), None);
        assert_eq!(level_rank(""), None);
    }

    #[test]
    fn default_min_level_lets_every_language_level_through() {
        // Guards the load-bearing default: if this constant is ever tightened,
        // existing scripts silently lose log output (and interp's
        // log_multiple_levels test breaks).
        for lvl in ["debug", "info", "warn", "error", "fatal"] {
            assert!(
                level_rank(lvl).unwrap() >= DEFAULT_MIN_LEVEL,
                "{lvl} must emit at the default level"
            );
        }
    }

    #[test]
    fn parse_format_accepts_text_and_json_only() {
        assert_eq!(parse_format("text"), Some(0));
        assert_eq!(parse_format("plain"), Some(0));
        assert_eq!(parse_format("JSON"), Some(1));
        assert_eq!(parse_format("xml"), None);
    }

    #[test]
    fn arg_validation_errors_do_not_mutate_globals() {
        // Error paths must reject before storing anything.
        assert!(set_level(vec![]).is_err());
        assert!(set_level(vec![Value::String("verbose".into())]).is_err());
        assert!(set_format(vec![]).is_err());
        assert!(set_format(vec![Value::String("xml".into())]).is_err());
        assert!(set_output(vec![]).is_err());
        assert_eq!(MIN_LEVEL.load(Ordering::Relaxed), DEFAULT_MIN_LEVEL);
        assert_eq!(FORMAT.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn unrecognised_level_name_still_emits() {
        // should_emit must not be the thing that silently drops a log line.
        assert!(should_emit("not-a-level"));
    }
}
