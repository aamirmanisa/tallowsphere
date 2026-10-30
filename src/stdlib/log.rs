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

// ── Trace id (G52) ───────────────────────────────────────────────────────────
//
// Process-wide, deliberately: task-scope propagation needs the structured
// concurrency model (G46) that does not exist yet, and a half-propagation
// mechanism invented now would have to be thrown away when it lands. See
// docs/spec/STRUCTURED-LOGGING.md.

/// Longest accepted trace id, in characters (spec: "≤64 chars").
pub const MAX_TRACE_LEN: usize = 64;

static TRACE_ID: LazyLock<Mutex<Option<String>>> = LazyLock::new(|| Mutex::new(None));

/// The process-wide trace id, or `None` when unset.
pub fn trace_id() -> Option<String> {
    TRACE_ID.lock().map(|guard| guard.clone()).unwrap_or(None)
}

/// Set (`Some`) or clear (`None`) the process-wide trace id.
///
/// Refuses an id longer than [`MAX_TRACE_LEN`] *characters* before mutating
/// anything, so a rejected call leaves the previous id in place.
pub fn set_trace(id: Option<&str>) -> Result<(), String> {
    let mut guard = TRACE_ID
        .lock()
        .map_err(|_| "log.set_trace: trace id mutex poisoned".to_string())?;
    match id {
        None => {
            *guard = None;
            Ok(())
        }
        Some(raw) => {
            let len = raw.chars().count();
            if len > MAX_TRACE_LEN {
                return Err(format!(
                    "log.set_trace: trace id is {len} characters, the maximum is {MAX_TRACE_LEN}"
                ));
            }
            *guard = Some(raw.to_string());
            Ok(())
        }
    }
}

// ── Record fields (G52) ──────────────────────────────────────────────────────

/// Keys the logger writes itself; a field may not claim one.
pub const RESERVED_KEYS: [&str; 3] = ["level", "ts", "trace"];

/// A field value reduced to something with a defined rendering.
///
/// `Private`/`Secret` carry no payload on purpose: the value has already been
/// replaced by its redaction marker, so it cannot be recovered from here.
#[derive(Debug, Clone, PartialEq)]
pub enum FieldValue {
    Str(String),
    Int(i128),
    Float(f64),
    Bool(bool),
    Redacted,
    Secret,
}

impl FieldValue {
    /// The JSON form. Private/Secret render as the marker *string*.
    pub fn to_json(&self) -> serde_json::Value {
        match self {
            FieldValue::Str(s) => serde_json::Value::String(s.clone()),
            FieldValue::Int(n) => serde_json::Number::from_i128(*n)
                .map(serde_json::Value::Number)
                .unwrap_or_else(|| serde_json::Value::String(n.to_string())),
            FieldValue::Float(f) => serde_json::Number::from_f64(*f)
                .map(serde_json::Value::Number)
                .unwrap_or_else(|| serde_json::Value::String(format_float(*f))),
            FieldValue::Bool(b) => serde_json::Value::Bool(*b),
            FieldValue::Redacted => serde_json::Value::String("[REDACTED]".to_string()),
            FieldValue::Secret => serde_json::Value::String("[SECRET]".to_string()),
        }
    }

    /// The `k=v` form used by the text format.
    pub fn to_text(&self) -> String {
        match self {
            FieldValue::Str(s) => s.clone(),
            FieldValue::Int(n) => n.to_string(),
            FieldValue::Float(f) => format_float(*f),
            FieldValue::Bool(b) => b.to_string(),
            FieldValue::Redacted => "[REDACTED]".to_string(),
            FieldValue::Secret => "[SECRET]".to_string(),
        }
    }
}

fn format_float(f: f64) -> String {
    if f.is_nan() {
        "nan".to_string()
    } else if f.is_infinite() {
        if f < 0.0 {
            "-inf".to_string()
        } else {
            "inf".to_string()
        }
    } else {
        f.to_string()
    }
}

/// One normalised field, in insertion order.
#[derive(Debug, Clone, PartialEq)]
pub struct RecordField {
    pub key: String,
    pub value: FieldValue,
}

/// The value-kind name used in refusal messages.
fn kind_name(value: &Value) -> &'static str {
    match value {
        Value::Nil => "Nil",
        Value::Bool(_) => "Bool",
        Value::Int(_) => "Int",
        Value::Float(_) => "Float",
        Value::String(_) => "String",
        Value::Module(_) => "Module",
        Value::Array(_) => "Array",
        Value::Map(_) => "Map",
        Value::Ok(_) => "Ok",
        Value::Err(_) => "Err",
        Value::Private(_) => "Private",
        Value::Secret(_) => "Secret",
        Value::Function { .. } => "Function",
        Value::Enum { .. } => "Enum",
        Value::Struct { .. } => "Struct",
        Value::Range { .. } => "Range",
        _ => "non-scalar",
    }
}

/// The indefinite article for a type name, so refusals read as English.
fn article(kind: &str) -> &'static str {
    match kind.chars().next() {
        Some('A' | 'E' | 'I' | 'O' | 'U') => "an",
        _ => "a",
    }
}

/// Validate a `log.record` field map and reduce it to renderable scalars.
///
/// Insertion order is preserved — the text format depends on it. Validation
/// runs to completion before anything is emitted, so a refusal produces no
/// partial line.
pub fn normalise_fields(fields: &[(Value, Value)]) -> Result<Vec<RecordField>, String> {
    let mut out = Vec::with_capacity(fields.len());
    for (key, value) in fields {
        let key = match key {
            Value::String(k) => k.clone(),
            other => {
                return Err(format!(
                    "log.record: field names must be strings, got {}",
                    kind_name(other)
                ));
            }
        };
        if RESERVED_KEYS.contains(&key.as_str()) {
            return Err(format!(
                "log.record: field name '{key}' is reserved — the logger owns level, ts and trace"
            ));
        }
        let value = match value {
            Value::String(s) => FieldValue::Str(s.clone()),
            Value::Int(n) => FieldValue::Int(*n),
            Value::Float(f) => FieldValue::Float(*f),
            Value::Bool(b) => FieldValue::Bool(*b),
            Value::Private(_) => FieldValue::Redacted,
            Value::Secret(_) => FieldValue::Secret,
            other => {
                return Err(format!(
                    "log.record: field '{key}' is {} {} value — only string, int, float and bool \
                     fields are supported (a nested value has no defined rendering)",
                    article(kind_name(other)),
                    kind_name(other)
                ));
            }
        };
        out.push(RecordField { key, value });
    }
    Ok(out)
}

/// Render one record in the configured format.
///
/// json: `{"level":…,"ts":…,"msg":…,"trace":…,…fields}` with `msg` taken from
/// `fields["msg"]` (empty when absent) and the rest merged at the top level.
/// text: `[LEVEL] [ts] [trace] k=v …`, keys in insertion order.
pub fn format_record(level: &str, ts: &str, fields: &[RecordField]) -> String {
    let trace = trace_id();
    if is_json_format() {
        let mut obj = serde_json::Map::new();
        obj.insert(
            "level".to_string(),
            serde_json::Value::String(level.to_string()),
        );
        obj.insert("ts".to_string(), serde_json::Value::String(ts.to_string()));
        let msg = fields
            .iter()
            .find(|f| f.key == "msg")
            .map(|f| f.value.to_json())
            .unwrap_or_else(|| serde_json::Value::String(String::new()));
        obj.insert("msg".to_string(), msg);
        if let Some(t) = &trace {
            obj.insert("trace".to_string(), serde_json::Value::String(t.clone()));
        }
        for f in fields {
            if f.key == "msg" {
                continue; // already placed, and not duplicated
            }
            obj.insert(f.key.clone(), f.value.to_json());
        }
        serde_json::Value::Object(obj).to_string()
    } else {
        let mut line = format!("[{level}] [{ts}]");
        if let Some(t) = &trace {
            line.push_str(&format!(" [{t}]"));
        }
        for f in fields {
            line.push_str(&format!(" {}={}", f.key, f.value.to_text()));
        }
        line
    }
}

/// The canonical (uppercase) spelling of a level name, or `None` if unknown.
pub fn canonical_level(name: &str) -> Option<String> {
    level_rank(name)?;
    Some(name.to_ascii_uppercase())
}

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
        // G52: process-wide trace id
        "set_trace" => Some(set_trace_call(args)),
        "trace" => Some(Ok(match trace_id() {
            Some(id) => Value::String(id),
            None => Value::Nil,
        })),

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

/// `log.set_trace(id)` — a string sets the process-wide id, `nil` clears it.
fn set_trace_call(args: Vec<Value>) -> StdlibResult {
    match args.first() {
        Some(Value::Nil) => {
            set_trace(None)?;
            Ok(Value::Nil)
        }
        Some(Value::String(s)) => {
            set_trace(Some(s))?;
            Ok(Value::Nil)
        }
        _ => Err("log.set_trace expects a string trace id, or nil to clear it".into()),
    }
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

    #[test]
    fn canonical_level_is_uppercase_and_rejects_unknown() {
        assert_eq!(canonical_level("info").as_deref(), Some("INFO"));
        assert_eq!(canonical_level("Warn").as_deref(), Some("WARN"));
        assert_eq!(canonical_level("verbose"), None);
    }

    fn f(k: &str, v: Value) -> (Value, Value) {
        (Value::String(k.to_string()), v)
    }

    #[test]
    fn normalise_fields_preserves_insertion_order_and_types() {
        let fields = vec![
            f("z", Value::Int(1)),
            f("a", Value::String("s".into())),
            f("m", Value::Float(1.5)),
            f("b", Value::Bool(true)),
        ];
        let out = normalise_fields(&fields).expect("fields accepted");
        let keys: Vec<&str> = out.iter().map(|r| r.key.as_str()).collect();
        assert_eq!(keys, ["z", "a", "m", "b"]);
        assert_eq!(out[0].value, FieldValue::Int(1));
        assert_eq!(out[1].value, FieldValue::Str("s".into()));
        assert_eq!(out[2].value, FieldValue::Float(1.5));
        assert_eq!(out[3].value, FieldValue::Bool(true));
        // JSON types survive: a bool is a bool, an int is a number.
        assert_eq!(out[0].value.to_json(), serde_json::json!(1));
        assert_eq!(out[3].value.to_json(), serde_json::json!(true));
        assert_eq!(out[1].value.to_json(), serde_json::json!("s"));
    }

    #[test]
    fn normalise_fields_refuses_the_keys_the_logger_owns() {
        for key in RESERVED_KEYS {
            let fields = vec![f(key, Value::String("x".into()))];
            let err = normalise_fields(&fields).expect_err("reserved key must be refused");
            assert!(
                err.contains(&format!("'{key}' is reserved")),
                "error must name the key: {err}"
            );
        }
    }

    #[test]
    fn normalise_fields_redacts_private_and_secret() {
        let fields = vec![
            f("p", Value::Private(Box::new(Value::String("a@b".into())))),
            f("s", Value::Secret(Box::new(Value::String("tok".into())))),
        ];
        let out = normalise_fields(&fields).expect("fields accepted");
        assert_eq!(out[0].value, FieldValue::Redacted);
        assert_eq!(out[1].value, FieldValue::Secret);
        assert_eq!(out[0].value.to_json(), serde_json::json!("[REDACTED]"));
        assert_eq!(out[1].value.to_json(), serde_json::json!("[SECRET]"));
        assert_eq!(out[0].value.to_text(), "[REDACTED]");
        assert_eq!(out[1].value.to_text(), "[SECRET]");
    }

    #[test]
    fn normalise_fields_refuses_nested_values_by_name() {
        let cases = vec![
            (
                "arr",
                Value::Array(vec![Value::Int(1)]),
                "field 'arr' is an Array value",
            ),
            (
                "mp",
                Value::Map(vec![f("k", Value::Int(1))]),
                "field 'mp' is a Map value",
            ),
            (
                "st",
                Value::Struct {
                    name: "S".into(),
                    fields: vec![],
                },
                "field 'st' is a Struct value",
            ),
        ];
        for (key, value, expected) in cases {
            let err = normalise_fields(&[f(key, value)]).expect_err("nested value must be refused");
            assert!(err.contains(expected), "got: {err}");
        }
    }

    #[test]
    fn normalise_fields_refuses_a_non_string_key() {
        let err = normalise_fields(&[(Value::Int(1), Value::Int(2))])
            .expect_err("non-string key must be refused");
        assert!(err.contains("field names must be strings"), "got: {err}");
    }
}
