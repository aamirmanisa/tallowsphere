//! FFI wrappers for Tallow database operations (compiled binaries).
//!
//! Compiled Tallow programs calling `db.connect` / `db.query` / `db.execute` /
//! `db.close` emit `call` instructions to these symbols. Backed by rusqlite
//! (bundled SQLite). Handles are opaque `*mut c_void` pointers to a
//! `rusqlite::Connection`; the caller must pass the handle back unchanged.
//!
//! Conventions (matching the rest of the runtime FFI):
//! - null / -1 on error, `tallow_last_error()` for the message,
//! - string results are heap C strings freed with `tallow_free_string`.

use std::ffi::c_void;
use std::os::raw::c_char;

use super::{cstr_to_str, set_last_error, string_to_cstr};

/// Open a SQLite database. `dsn` may be a file path or `:memory:`.
/// Returns an opaque connection handle, or null on error.
/// The caller must free the handle with `tallow_db_close`.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_db_connect(dsn: *const c_char) -> *mut c_void {
    let dsn_str = match unsafe { cstr_to_str(dsn) } {
        Some(s) => s,
        None => {
            set_last_error("db.connect: null or invalid DSN".to_string());
            return std::ptr::null_mut();
        }
    };
    let conn = if dsn_str == ":memory:" || dsn_str == "memory" || dsn_str == "file::memory:" {
        rusqlite::Connection::open_in_memory()
    } else {
        rusqlite::Connection::open(dsn_str)
    };
    match conn {
        Ok(conn) => Box::into_raw(Box::new(conn)) as *mut c_void,
        Err(e) => {
            set_last_error(format!("db.connect({dsn_str}): {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Run a SQL query and return the result set as a JSON array of row objects,
/// e.g. `[{"id":1,"name":"alice"}, ...]` (values: null / number / string).
/// Returns a heap C string; free with `tallow_free_string`. Null on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_db_query(conn: *mut c_void, sql: *const c_char) -> *mut c_char {
    let sql_str = match unsafe { cstr_to_str(sql) } {
        Some(s) => s,
        None => {
            set_last_error("db.query: null SQL".to_string());
            return std::ptr::null_mut();
        }
    };
    let Some(conn) = conn_ptr(conn) else {
        return std::ptr::null_mut();
    };
    match query_json(conn, sql_str) {
        Ok(json) => string_to_cstr(&json),
        Err(e) => {
            set_last_error(format!("db.query: {e}"));
            std::ptr::null_mut()
        }
    }
}

/// Execute a non-query SQL statement. Returns the number of affected rows,
/// or -1 on error.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_db_execute(conn: *mut c_void, sql: *const c_char) -> i64 {
    let sql_str = match unsafe { cstr_to_str(sql) } {
        Some(s) => s,
        None => {
            set_last_error("db.execute: null SQL".to_string());
            return -1;
        }
    };
    let Some(conn) = conn_ptr(conn) else {
        return -1;
    };
    match conn.execute(sql_str, []) {
        Ok(affected) => affected as i64,
        Err(e) => {
            set_last_error(format!("db.execute: {e}"));
            -1
        }
    }
}

/// Close a connection previously returned by `tallow_db_connect`.
/// Safe to call with null. The handle must not be used afterwards.
#[unsafe(no_mangle)]
pub extern "C" fn tallow_db_close(conn: *mut c_void) {
    if !conn.is_null() {
        unsafe {
            drop(Box::from_raw(conn as *mut rusqlite::Connection));
        }
    }
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn conn_ptr<'a>(handle: *mut c_void) -> Option<&'a mut rusqlite::Connection> {
    if handle.is_null() {
        set_last_error("db: null connection handle".to_string());
        return None;
    }
    Some(unsafe { &mut *(handle as *mut rusqlite::Connection) })
}

fn query_json(conn: &mut rusqlite::Connection, sql: &str) -> Result<String, String> {
    let mut stmt = conn.prepare(sql).map_err(|e| e.to_string())?;
    let col_count = stmt.column_count();
    let col_names: Vec<String> = (0..col_count)
        .map(|i| stmt.column_name(i).unwrap_or("").to_string())
        .collect();
    let mut rows = stmt.query([]).map_err(|e| e.to_string())?;
    let mut out: Vec<serde_json::Value> = Vec::new();
    while let Some(row) = rows.next().map_err(|e| e.to_string())? {
        let mut obj = serde_json::Map::new();
        for (i, name) in col_names.iter().enumerate() {
            let v: rusqlite::types::Value = row.get(i).map_err(|e| e.to_string())?;
            obj.insert(name.clone(), sqlite_value_to_json(v));
        }
        out.push(serde_json::Value::Object(obj));
    }
    serde_json::to_string(&out).map_err(|e| e.to_string())
}

fn sqlite_value_to_json(v: rusqlite::types::Value) -> serde_json::Value {
    match v {
        rusqlite::types::Value::Null => serde_json::Value::Null,
        rusqlite::types::Value::Integer(i) => serde_json::Value::from(i),
        rusqlite::types::Value::Real(r) => serde_json::Number::from_f64(r)
            .map(serde_json::Value::Number)
            .unwrap_or(serde_json::Value::Null),
        rusqlite::types::Value::Text(s) => serde_json::Value::String(s),
        rusqlite::types::Value::Blob(b) => {
            serde_json::Value::String(String::from_utf8_lossy(&b).to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn db_roundtrip_via_ffi() {
        let dsn = CString::new(":memory:").unwrap();
        let conn = tallow_db_connect(dsn.as_ptr());
        assert!(!conn.is_null());

        let create = CString::new("CREATE TABLE t (id INTEGER, name TEXT)").unwrap();
        assert_eq!(tallow_db_execute(conn, create.as_ptr()), 0);

        let insert = CString::new("INSERT INTO t (id, name) VALUES (1, 'alice')").unwrap();
        assert_eq!(tallow_db_execute(conn, insert.as_ptr()), 1);

        let q = CString::new("SELECT id, name FROM t").unwrap();
        let json = tallow_db_query(conn, q.as_ptr());
        assert!(!json.is_null());
        let text = unsafe { std::ffi::CStr::from_ptr(json).to_str().unwrap() };
        assert!(text.contains("alice"), "query result missing row: {text}");
        unsafe { super::super::tallow_free_string(json) };

        tallow_db_close(conn);
        tallow_db_close(std::ptr::null_mut()); // null-safe
    }

    #[test]
    fn db_connect_bad_path_fails_honestly() {
        let dsn = CString::new("/nonexistent/dir/that/cannot/exist/x.db").unwrap();
        let conn = tallow_db_connect(dsn.as_ptr());
        assert!(conn.is_null());
    }
}
