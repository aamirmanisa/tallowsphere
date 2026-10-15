//! Standard library: `tallow.db` — SQLite database connections.
//!
//! REGISTERED (FIX13, 2026-08-27) as an honest bridge. FIX12 could not
//! register this module because `interp::DbConn` is a tuple struct with a
//! PRIVATE field — stdlib code can neither construct nor destructure a
//! connection handle — and `interp::Value` lacked `rusqlite::ToSql`.
//! interp.rs is read-only for this sprint, so:
//!
//! - `db.connect` is intentionally NOT a dispatch arm: the interpreter's
//!   inline handler (src/interp.rs, the `"db.connect"` arm) is live and
//!   real, and returning `Some(..)` here would shadow it (interp routes
//!   stdlib dispatch results before its inline match). `db.connect` falls
//!   through (`None`) exactly as before FIX13.
//! - `db.sqlite` / `db.sqlite_memory` have no inline fallback, so they
//!   return an honest `Err("db bridge requires interp support …")` instead
//!   of pretending to open a connection we cannot represent in `Value`
//!   (constructing `Value::DbConnection` requires the private `DbConn`
//!   constructor).
//! - `db.open` / `db.memory` remain served by the interpreter's inline
//!   handlers (unchanged) — asserted by
//!   `backward_compat_db_memory_still_works` in tests/stdlib_dispatch.rs.
//! - `rusqlite::ToSql for Value` now lives in `db_support` (sibling
//!   module), unblocking parameter binding the moment interp.rs exposes a
//!   `DbConn` accessor/constructor in a future sprint.

use super::StdlibResult;
use crate::interp::Value;

/// Honest error for operations that need a live `DbConn` handle.
const BRIDGE_MSG: &str = "db bridge requires interp support: interp::DbConn's \
inner field is private and interp.rs is read-only in this sprint — use \
db.open / db.memory / db.connect (interpreter inline handlers) for live \
SQLite access";

/// Contract-level dispatch for `tallow.db.*` functions.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    let _ = args;
    match function {
        // "connect" is deliberately absent (see module docs — inline handler
        // in interp.rs serves it). "sqlite" / "sqlite_memory" have no inline
        // fallback → honest error rather than a fake success.
        "sqlite" | "sqlite_memory" => Some(Err(BRIDGE_MSG.to_string())),
        _ => None,
    }
}

/// Contract-level dispatch for `tallow.db.*` struct methods.
///
/// Row accessors are pure (they operate on the struct's own fields) and are
/// implemented for real. Connection/Transaction methods need a live handle
/// this module cannot represent in `Value` → honest error. Note: the router
/// in mod.rs currently sends Struct name "Connection" to forensics, so the
/// Connection/Transaction arms below are reachable only via direct calls;
/// they exist so the contract surface is explicit and honest.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, fields } = object else {
        return None;
    };
    match name.as_str() {
        "Row" => match method {
            "get" => Some(row_get(fields, args)),
            "get_string" => Some(row_get_typed(fields, args, "string")),
            "get_int" | "get_i64" => Some(row_get_typed(fields, args, "int")),
            "get_float" | "get_f64" => Some(row_get_typed(fields, args, "float")),
            "get_bool" => Some(row_get_typed(fields, args, "bool")),
            "columns" => Some(Ok(fields
                .iter()
                .find(|(k, _)| k.as_str() == "columns")
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Map(vec![])))),
            "len" => {
                let n = fields
                    .iter()
                    .find(|(k, _)| k.as_str() == "columns")
                    .and_then(|(_, v)| match v {
                        Value::Map(m) => Some(m.len() as i128),
                        _ => None,
                    })
                    .unwrap_or(0);
                Some(Ok(Value::Int(n)))
            }
            _ => None,
        },
        "Connection" | "Transaction" => match method {
            "query" | "query_one" | "execute" | "table_exists" | "begin"
            | "begin_transaction" | "commit" | "rollback" | "close" | "ping" => {
                Some(Err(BRIDGE_MSG.to_string()))
            }
            _ => None,
        },
        _ => None,
    }
}

/// `Row.get(col) -> Value`
fn row_get(fields: &[(String, Value)], args: Vec<Value>) -> StdlibResult {
    let col = string_arg(&args, 0, "db.Row.get")?;
    let Some((_, Value::Map(cols))) = fields.iter().find(|(k, _)| k.as_str() == "columns") else {
        return Ok(Value::Nil);
    };
    Ok(cols
        .iter()
        .find(|(k, _)| k.as_string() == col)
        .map(|(_, v)| v.clone())
        .unwrap_or(Value::Nil))
}

/// `Row.get_string/get_int/get_float/get_bool(col)` — typed column access.
fn row_get_typed(fields: &[(String, Value)], args: Vec<Value>, ty: &str) -> StdlibResult {
    let col = string_arg(&args, 0, "db.Row.get_*")?;
    let raw = row_get(fields, vec![Value::String(col)])?;
    match ty {
        "string" => Ok(Value::String(raw.as_string())),
        "int" => match raw {
            Value::Int(i) => Ok(Value::Int(i)),
            Value::Float(f) => Ok(Value::Int(f as i128)),
            Value::String(s) => s
                .parse::<i128>()
                .map(Value::Int)
                .map_err(|e| format!("db.Row.get_int: {e}")),
            _ => Err(format!(
                "db.Row.get_int: column is not an integer ({})",
                raw.as_string()
            )),
        },
        "float" => match raw {
            Value::Float(f) => Ok(Value::Float(f)),
            Value::Int(i) => Ok(Value::Float(i as f64)),
            Value::String(s) => s
                .parse::<f64>()
                .map(Value::Float)
                .map_err(|e| format!("db.Row.get_float: {e}")),
            _ => Err(format!(
                "db.Row.get_float: column is not a number ({})",
                raw.as_string()
            )),
        },
        "bool" => match raw {
            Value::Bool(b) => Ok(Value::Bool(b)),
            Value::Int(i) => Ok(Value::Bool(i != 0)),
            _ => Err(format!(
                "db.Row.get_bool: column is not a boolean ({})",
                raw.as_string()
            )),
        },
        _ => unreachable!("row_get_typed called with unknown type"),
    }
}

fn string_arg(args: &[Value], idx: usize, ctx: &str) -> Result<String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.clone()),
        _ => Err(format!("{ctx}: expected a String at argument {idx}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sqlite_memory_is_honest_bridge_error() {
        let r = dispatch("sqlite_memory", vec![]).expect("sqlite_memory is a known arm");
        let msg = r.expect_err("bridge must not pretend to open a connection");
        assert!(msg.contains("db bridge requires interp support"), "{msg}");
    }

    #[test]
    fn sqlite_is_honest_bridge_error() {
        let r = dispatch("sqlite", vec![Value::String("/tmp/x.db".into())])
            .expect("sqlite is a known arm");
        let msg = r.expect_err("bridge must not pretend to open a connection");
        assert!(msg.contains("db bridge requires interp support"), "{msg}");
    }

    #[test]
    fn connect_falls_through_to_inline_handler() {
        // "connect" must NOT be a dispatch arm — interp.rs serves it inline;
        // Some(..) here would shadow the live handler and break db.connect.
        assert!(dispatch("connect", vec![]).is_none());
    }

    #[test]
    fn unknown_functions_none() {
        assert!(dispatch("nonsense", vec![]).is_none());
    }

    #[test]
    fn row_get_works_on_struct_fields() {
        let row = Value::Struct {
            name: "Row".into(),
            fields: vec![(
                "columns".into(),
                Value::Map(vec![
                    (Value::String("id".into()), Value::Int(7)),
                    (Value::String("name".into()), Value::String("alice".into())),
                ]),
            )],
        };
        let r = dispatch_method(&row, "get", vec![Value::String("name".into())])
            .expect("Row.get is a known arm")
            .expect("get should succeed");
        assert!(matches!(r, Value::String(s) if s == "alice"));
    }

    #[test]
    fn connection_methods_are_honest_errors() {
        let conn = Value::Struct {
            name: "Connection".into(),
            fields: vec![],
        };
        for method in ["query", "execute", "close", "ping"] {
            let r = dispatch_method(&conn, method, vec![Value::String("SELECT 1".into())])
                .expect("connection method should be a known arm")
                .expect_err("connection methods need a live handle");
            assert!(r.contains("db bridge requires interp support"), "{r}");
        }
    }
}
