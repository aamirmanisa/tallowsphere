//! Standard library: `tallow.timeseries` — financial time-series storage.
//!
//! Stores tick data and OHLCV bars in SQLite with efficient time-range
//! queries using indexes. Supports multiple symbols and resolutions.
//!
//! # API
//! - `TS.new(path)` — create/open a time-series database
//! - `ts.insert(symbol, timestamp, price, volume?)` — insert a tick
//! - `ts.insert_bar(symbol, ts, open, high, low, close, volume)` — insert OHLCV
//! - `ts.range(symbol, from_ts, to_ts)` — query ticks in range
//! - `ts.bars(symbol, from_ts, to_ts)` — query bars in range
//! - `ts.latest(symbol)` — get latest tick/bar for symbol
//! - `ts.symbols()` — list all symbols

use super::StdlibResult;
use crate::interp::{type_name, Value};

use rusqlite::Connection;
use std::sync::{Arc, Mutex};
use std::collections::HashMap;

// FIX12 (2026-08-27): converted `static mut` to a Mutex-wrapped static —
// edition-2024 denies mutable references to mutable statics, so the orphaned
// module could not compile once registered.
static DB_INSTANCES: Mutex<Option<HashMap<String, Arc<Mutex<Connection>>>>> = Mutex::new(None);

fn get_db(name: &str) -> Result<Arc<Mutex<Connection>>, String> {
    let mut dbs = DB_INSTANCES
        .lock()
        .map_err(|e| format!("TS registry lock: {e}"))?;
    let dbs = dbs.get_or_insert_with(HashMap::new);
    if !dbs.contains_key(name) {
        let conn = Connection::open(name)
            .map_err(|e| format!("TS open: {e}"))?;
        conn.execute_batch("
                CREATE TABLE IF NOT EXISTS ticks (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    symbol TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    price REAL NOT NULL,
                    volume REAL
                );
                CREATE INDEX IF NOT EXISTS idx_ticks_symbol_ts ON ticks(symbol, timestamp);
                CREATE TABLE IF NOT EXISTS bars (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    symbol TEXT NOT NULL,
                    timestamp INTEGER NOT NULL,
                    open REAL NOT NULL,
                    high REAL NOT NULL,
                    low REAL NOT NULL,
                    close REAL NOT NULL,
                    volume REAL
                );
                CREATE INDEX IF NOT EXISTS idx_bars_symbol_ts ON bars(symbol, timestamp);
            ").map_err(|e| format!("TS schema: {e}"))?;
        dbs.insert(name.to_string(), Arc::new(Mutex::new(conn)));
    }
    Ok(Arc::clone(dbs.get(name).ok_or("DB not found")?))
}

pub fn insert_tick(path: &str, symbol: &str, timestamp: i64, price: f64, volume: Option<f64>) -> StdlibResult {
    let db = get_db(path)?;
    let conn = db.lock().map_err(|e| format!("TS lock: {e}"))?;
    conn.execute(
        "INSERT INTO ticks (symbol, timestamp, price, volume) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![symbol, timestamp, price, volume],
    ).map_err(|e| format!("TS insert: {e}"))?;
    Ok(Value::Bool(true))
}

pub fn insert_bar(path: &str, symbol: &str, ts: i64, open: f64, high: f64, low: f64, close: f64, volume: Option<f64>) -> StdlibResult {
    let db = get_db(path)?;
    let conn = db.lock().map_err(|e| format!("TS lock: {e}"))?;
    conn.execute(
        "INSERT INTO bars (symbol, timestamp, open, high, low, close, volume) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![symbol, ts, open, high, low, close, volume],
    ).map_err(|e| format!("TS insert bar: {e}"))?;
    Ok(Value::Bool(true))
}

pub fn query_ticks(path: &str, symbol: &str, from: Option<i64>, to: Option<i64>) -> StdlibResult {
    let db = get_db(path)?;
    let conn = db.lock().map_err(|e| format!("TS lock: {e}"))?;
    let mut sql = String::from("SELECT timestamp, price, volume FROM ticks WHERE symbol = ?1");
    if from.is_some() { sql.push_str(" AND timestamp >= ?2"); }
    if to.is_some() { sql.push_str(" AND timestamp <= ?3"); }
    sql.push_str(" ORDER BY timestamp");

    let mut stmt = conn.prepare(&sql).map_err(|e| format!("TS query: {e}"))?;
    let rows: Vec<Value> = stmt.query_map(
        rusqlite::params![symbol, from, to],
        |row| {
            let ts: i64 = row.get(0)?;
            let price: f64 = row.get(1)?;
            let vol: Option<f64> = row.get(2)?;
            Ok(Value::Struct {
                name: "Tick".into(),
                fields: vec![
                    ("timestamp".into(), Value::Int(ts as i128)),
                    ("price".into(), Value::Float(price)),
                    ("volume".into(), vol.map(Value::Float).unwrap_or(Value::Nil)),
                ],
            })
        },
    ).map_err(|e| format!("TS query: {e}"))?
    .filter_map(|r| r.ok())
    .collect();

    Ok(Value::Array(rows))
}

pub fn query_bars(path: &str, symbol: &str, from: Option<i64>, to: Option<i64>) -> StdlibResult {
    let db = get_db(path)?;
    let conn = db.lock().map_err(|e| format!("TS lock: {e}"))?;
    let mut sql = String::from("SELECT timestamp, open, high, low, close, volume FROM bars WHERE symbol = ?1");
    if from.is_some() { sql.push_str(" AND timestamp >= ?2"); }
    if to.is_some() { sql.push_str(" AND timestamp <= ?3"); }
    sql.push_str(" ORDER BY timestamp LIMIT 5000");

    let mut stmt = conn.prepare(&sql).map_err(|e| format!("TS query: {e}"))?;
    let rows: Vec<Value> = stmt.query_map(
        rusqlite::params![symbol, from, to],
        |row| {
            Ok(Value::Struct {
                name: "Bar".into(),
                fields: vec![
                    ("timestamp".into(), Value::Int(row.get::<_, i64>(0)? as i128)),
                    ("open".into(), Value::Float(row.get(1)?)),
                    ("high".into(), Value::Float(row.get(2)?)),
                    ("low".into(), Value::Float(row.get(3)?)),
                    ("close".into(), Value::Float(row.get(4)?)),
                    ("volume".into(), row.get::<_, Option<f64>>(5).map(|v| v.map(Value::Float).unwrap_or(Value::Nil)).unwrap_or(Value::Nil)),
                ],
            })
        },
    ).map_err(|e| format!("TS query: {e}"))?
    .filter_map(|r| r.ok())
    .collect();

    Ok(Value::Array(rows))
}

pub fn latest_tick(path: &str, symbol: &str) -> StdlibResult {
    let db = get_db(path)?;
    let conn = db.lock().map_err(|e| format!("TS lock: {e}"))?;
    let mut stmt = conn.prepare("SELECT timestamp, price, volume FROM ticks WHERE symbol = ?1 ORDER BY timestamp DESC LIMIT 1")
        .map_err(|e| format!("TS: {e}"))?;
    let row = stmt.query_row(rusqlite::params![symbol], |row| {
        Ok(Value::Struct {
            name: "Tick".into(),
            fields: vec![
                ("timestamp".into(), Value::Int(row.get::<_, i64>(0).unwrap_or(0) as i128)),
                ("price".into(), Value::Float(row.get::<_, f64>(1).unwrap_or(0.0))),
                ("volume".into(), row.get::<_, Option<f64>>(2).map(|v| match v { Some(x) => Value::Float(x), None => Value::Nil }).unwrap_or(Value::Nil)),
            ],
        })
    });
    match row {
        Ok(v) => Ok(v),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(Value::Nil),
        Err(e) => Err(format!("TS latest: {e}")),
    }
}

pub fn list_symbols(path: &str) -> StdlibResult {
    let db = get_db(path)?;
    let conn = db.lock().map_err(|e| format!("TS lock: {e}"))?;
    let mut stmt = conn.prepare("SELECT DISTINCT symbol FROM ticks UNION SELECT DISTINCT symbol FROM bars")
        .map_err(|e| format!("TS: {e}"))?;
    let symbols: Vec<Value> = stmt.query_map([], |row| {
        let s: String = row.get(0)?;
        Ok(Value::String(s))
    }).map_err(|e| format!("TS: {e}"))?
    .filter_map(|r| r.ok())
    .collect();
    Ok(Value::Array(symbols))
}

// ── Dispatch ──

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "new" => Some(ts_new(args)),
        _ => None,
    }
}

pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if !matches!(object, Value::Struct { name, .. } if name == "TimeSeries") { return None; }
    let path = match object {
        Value::Struct { fields, .. } => field_str(fields, "path"),
        _ => return None,
    };
    match method {
        "insert" => Some(ts_insert(&path, args)),
        "insert_bar" => Some(ts_insert_bar(&path, args)),
        "range" => Some(ts_range(&path, args)),
        "bars" => Some(ts_bars(&path, args)),
        "latest" => Some(ts_latest(&path, args)),
        "symbols" => Some(ts_symbols(&path)),
        _ => None,
    }
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function, "new")
}

fn ts_new(args: Vec<Value>) -> StdlibResult {
    let path = expect_first_str(&args, "path")?;
    get_db(path)?; // creates and initializes
    Ok(Value::Struct {
        name: "TimeSeries".into(),
        fields: vec![("path".into(), Value::String(path.clone()))],
    })
}

fn ts_insert(path: &str, args: Vec<Value>) -> StdlibResult {
    let sym = expect_str_at(args.get(0), "symbol")?;
    let ts = get_i64(args.get(1), "timestamp")?;
    let price = get_f64(args.get(2), "price")?;
    let vol = args.get(3).and_then(|v| if let Value::Float(f) = v { Some(*f) } else { None });
    insert_tick(path, sym, ts, price, vol)
}

fn ts_insert_bar(path: &str, args: Vec<Value>) -> StdlibResult {
    let sym = expect_str_at(args.get(0), "symbol")?;
    let ts = get_i64(args.get(1), "timestamp")?;
    let o = get_f64_direct(args.get(2), "open")?;
    let h = get_f64_direct(args.get(3), "high")?;
    let l = get_f64_direct(args.get(4), "low")?;
    let c = get_f64_direct(args.get(5), "close")?;
    let vol = args.get(6).and_then(|v| if let Value::Float(f) = v { Some(*f) } else { None });
    insert_bar(path, sym, ts, o, h, l, c, vol)
}

fn ts_range(path: &str, args: Vec<Value>) -> StdlibResult {
    let sym = expect_str_at(args.get(0), "symbol")?;
    let from = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as i64) } else { None });
    let to = args.get(2).and_then(|v| if let Value::Int(i) = v { Some(*i as i64) } else { None });
    query_ticks(path, sym, from, to)
}

fn ts_bars(path: &str, args: Vec<Value>) -> StdlibResult {
    let sym = expect_str_at(args.get(0), "symbol")?;
    let from = args.get(1).and_then(|v| if let Value::Int(i) = v { Some(*i as i64) } else { None });
    let to = args.get(2).and_then(|v| if let Value::Int(i) = v { Some(*i as i64) } else { None });
    query_bars(path, sym, from, to)
}

fn ts_latest(path: &str, args: Vec<Value>) -> StdlibResult {
    let sym = expect_str_at(args.get(0), "symbol")?;
    latest_tick(path, sym)
}

fn ts_symbols(path: &str) -> StdlibResult {
    list_symbols(path)
}

// Helpers

fn field_str(fields: &[(String, Value)], name: &str) -> String {
    fields.iter().find(|(n,_)| n == name)
        .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
        .unwrap_or_default()
}

fn expect_first_str<'a>(args: &'a [Value], name: &str) -> Result<&'a String, String> {
    match args.first() {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name}")),
    }
}

fn expect_str_at<'a>(val: Option<&'a Value>, name: &str) -> Result<&'a String, String> {
    match val {
        Some(Value::String(s)) => Ok(s),
        Some(o) => Err(format!("Expected String {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name}")),
    }
}

fn get_i64(val: Option<&Value>, name: &str) -> Result<i64, String> {
    match val {
        Some(Value::Int(i)) => Ok(*i as i64),
        Some(Value::Float(f)) => Ok(*f as i64),
        Some(o) => Err(format!("Expected number {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name}")),
    }
}

fn get_f64(val: Option<&Value>, name: &str) -> Result<f64, String> {
    get_f64_direct(val, name)
}

fn get_f64_direct(val: Option<&Value>, name: &str) -> Result<f64, String> {
    match val {
        Some(Value::Float(f)) => Ok(*f),
        Some(Value::Int(i)) => Ok(*i as f64),
        Some(o) => Err(format!("Expected number {name}, got {}", type_name(o))),
        None => Err(format!("Missing {name}")),
    }
}