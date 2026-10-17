//! Standard library: tallow.sync — concurrency primitives AND file sync engine.
//!
//! Provides channel, Mutex, RwLock, Barrier, and Once for goroutine coordination.
//! Also provides bidirectional folder sync, mesh sync, conflict resolution,
//! and sync status queries via HTTP calls to the tallow-daemon.

use crate::interp::Value;
use crate::stdlib::StdlibResult;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{LazyLock, Mutex};

// ── Daemon communication helpers ───────────────────────────────────────

/// Read the daemon port from ~/.tallow/daemon/port file.
/// Returns None if the port file doesn't exist (daemon not started).
fn read_daemon_port() -> Option<u16> {
    let port_path = dirs::data_dir()?.join("tallow").join("daemon").join("port");
    let content = std::fs::read_to_string(&port_path).ok()?;
    content.trim().parse::<u16>().ok()
}

/// Read the daemon bearer token from ~/.tallow/daemon/token file.
fn read_daemon_token() -> Option<String> {
    let token_path = dirs::data_dir()?.join("tallow").join("daemon").join("token");
    let content = std::fs::read_to_string(&token_path).ok()?;
    Some(content.trim().to_string())
}

/// Build the full daemon URL for an API endpoint.
fn daemon_url(endpoint: &str) -> Result<String, String> {
    let port = read_daemon_port()
        .ok_or_else(|| "sync: daemon not running — start tallow-daemon first".to_string())?;
    Ok(format!("http://127.0.0.1:{}{}", port, endpoint))
}

/// Perform an authenticated POST request to the daemon.
fn daemon_post(
    endpoint: &str,
    body: Option<serde_json::Value>,
) -> Result<serde_json::Value, String> {
    let url = daemon_url(endpoint)?;
    let token = read_daemon_token().unwrap_or_default();
    let client = reqwest::blocking::Client::new();
    let mut req = client.post(&url).header("Authorization", format!("Bearer {}", token));
    if let Some(b) = &body {
        req = req.json(b);
    }
    let resp = req.send().map_err(|e| {
        if e.is_connect() {
            format!("sync: daemon not running on {} — start tallow-daemon first", url)
        } else {
            format!("sync: daemon request failed: {}", e)
        }
    })?;
    let status = resp.status();
    let json: serde_json::Value = resp.json().map_err(|e| format!("sync: invalid response: {}", e))?;
    if !status.is_success() {
        let msg = json.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error");
        return Err(format!("sync: daemon error ({}): {}", status.as_u16(), msg));
    }
    Ok(json)
}

/// Perform an authenticated GET request to the daemon.
fn daemon_get(endpoint: &str) -> Result<serde_json::Value, String> {
    let url = daemon_url(endpoint)?;
    let token = read_daemon_token().unwrap_or_default();
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(&url)
        .header("Authorization", format!("Bearer {}", token))
        .send()
        .map_err(|e| {
            if e.is_connect() {
                format!("sync: daemon not running on {} — start tallow-daemon first", url)
            } else {
                format!("sync: daemon request failed: {}", e)
            }
        })?;
    let status = resp.status();
    let json: serde_json::Value = resp.json().map_err(|e| format!("sync: invalid response: {}", e))?;
    if !status.is_success() {
        let msg = json.get("error").and_then(|v| v.as_str()).unwrap_or("unknown error");
        return Err(format!("sync: daemon error ({}): {}", status.as_u16(), msg));
    }
    Ok(json)
}

// ── JSON → Value conversion helpers ────────────────────────────────────

fn json_to_value(json: &serde_json::Value) -> Value {
    match json {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i as i128)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(arr) => {
            Value::Array(arr.iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(obj) => {
            let fields: Vec<(Value, Value)> = obj
                .iter()
                .map(|(k, v)| (Value::String(k.clone()), json_to_value(v)))
                .collect();
            Value::Map(fields)
        }
    }
}

fn json_obj_to_struct(name: &str, json: &serde_json::Value) -> Value {
    if let serde_json::Value::Object(obj) = json {
        let fields: Vec<(String, Value)> = obj
            .iter()
            .map(|(k, v)| (k.clone(), json_to_value(v)))
            .collect();
        Value::Struct {
            name: name.to_string(),
            fields,
        }
    } else {
        // Non-object JSON — wrap as string field
        Value::Struct {
            name: name.to_string(),
            fields: vec![("value".to_string(), json_to_value(json))],
        }
    }
}

// ── Argument helpers ───────────────────────────────────────────────────

fn get_string_arg(args: &[Value], idx: usize) -> Option<String> {
    args.get(idx).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        _ => None,
    })
}

// ── File sync functions ────────────────────────────────────────────────

/// sync.bidirectional(source, dest, device_id, peer_url) -> SyncPair
fn sync_bidirectional(args: Vec<Value>) -> StdlibResult {
    let source = get_string_arg(&args, 0)
        .ok_or("sync.bidirectional: requires source directory path (string)")?;
    let dest = get_string_arg(&args, 1)
        .ok_or("sync.bidirectional: requires destination directory path (string)")?;
    let device_id = get_string_arg(&args, 2)
        .ok_or("sync.bidirectional: requires device_id (string)")?;
    let _peer_url = get_string_arg(&args, 3)
        .ok_or("sync.bidirectional: requires peer_url (string)")?;
    let name = format!("{} <-> {}", source, dest);

    let body = serde_json::json!({
        "name": name,
        "source_dir": source,
        "dest_dir": dest,
        "device_id": device_id,
    });

    let json = daemon_post("/sync/pairs", Some(body))?;
    Ok(json_obj_to_struct("SyncPair", &json))
}

/// sync.mesh(config_map) -> MeshConfig
/// config_map is a Tallow Map of device_id -> { peer_url, name } plus optional "folders" array.
fn sync_mesh(args: Vec<Value>) -> StdlibResult {
    if args.is_empty() {
        return Err("sync.mesh: requires config map with devices and folders".into());
    }

    // Extract devices and folders from the Tallow Map argument
    let (devices_map, folders) = match &args[0] {
        Value::Map(entries) => {
            let mut devices = serde_json::Map::new();
            let mut folders_val: Vec<serde_json::Value> = vec![];

            for (k, v) in entries {
                if let Value::String(key) = k {
                    if key == "folders" {
                        if let Value::Array(arr) = v {
                            folders_val = arr
                                .iter()
                                .map(|item| match item {
                                    Value::String(s) => serde_json::Value::String(s.clone()),
                                    other => serde_json::Value::String(format!("{}", type_name(other))),
                                })
                                .collect();
                        }
                    } else {
                        // Assume it's a device entry: value should be a Map { peer_url, name }
                        if let Value::Map(dev_fields) = v {
                            let mut dev_obj = serde_json::Map::new();
                            for (dk, dv) in dev_fields {
                                let field_name = match dk {
                                    Value::String(s) => s.clone(),
                                    other => format!("{}", type_name(other)),
                                };
                                let field_val = match dv {
                                    Value::String(s) => serde_json::Value::String(s.clone()),
                                    Value::Int(n) => serde_json::Value::Number((*n as i64).into()),
                                    Value::Float(f) => serde_json::json!(*f),
                                    Value::Bool(b) => serde_json::Value::Bool(*b),
                                    other => serde_json::Value::String(format!("{}", type_name(other))),
                                };
                                dev_obj.insert(field_name, field_val);
                            }
                            devices.insert(key.clone(), serde_json::Value::Object(dev_obj));
                        }
                    }
                }
            }

            (serde_json::Value::Object(devices), folders_val)
        }
        other => return Err(format!("sync.mesh: expected Map, got {}", type_name(other))),
    };

    let body = serde_json::json!({
        "devices": devices_map,
        "folders": folders,
    });

    let json = daemon_post("/sync/mesh", Some(body))?;
    Ok(json_obj_to_struct("MeshConfig", &json))
}

/// sync.status(pair_id) -> SyncStatus
fn sync_status(args: Vec<Value>) -> StdlibResult {
    let pair_id = get_string_arg(&args, 0)
        .ok_or("sync.status: requires sync pair ID (string)")?;
    let json = daemon_get(&format!("/sync/pairs/{}/status", pair_id))?;
    Ok(json_obj_to_struct("SyncStatus", &json))
}

/// sync.list_pairs(status?) -> Array[SyncPair]
fn sync_list_pairs(args: Vec<Value>) -> StdlibResult {
    let endpoint = if let Some(status) = get_string_arg(&args, 0) {
        format!("/sync/pairs?status={}", status)
    } else {
        "/sync/pairs".to_string()
    };
    let json = daemon_get(&endpoint)?;
    if let serde_json::Value::Array(arr) = &json {
        let pairs: Vec<Value> = arr
            .iter()
            .map(|p| json_obj_to_struct("SyncPair", p))
            .collect();
        Ok(Value::Array(pairs))
    } else {
        // Could be wrapped in { pairs: [...] }
        if let Some(arr) = json.get("pairs").and_then(|v| v.as_array()) {
            let pairs: Vec<Value> = arr
                .iter()
                .map(|p| json_obj_to_struct("SyncPair", p))
                .collect();
            Ok(Value::Array(pairs))
        } else {
            Ok(json_obj_to_struct("SyncPairList", &json))
        }
    }
}

/// sync.resolve_conflict(path, strategy) -> Resolution
fn sync_resolve_conflict(args: Vec<Value>) -> StdlibResult {
    let path = get_string_arg(&args, 0)
        .ok_or("sync.resolve_conflict: requires file path (string)")?;
    let strategy = get_string_arg(&args, 1)
        .ok_or("sync.resolve_conflict: requires strategy (keep-mine, keep-theirs, keep-both)")?;

    let body = serde_json::json!({
        "path": path,
        "strategy": strategy,
    });
    let json = daemon_post("/sync/conflicts/resolve", Some(body))?;
    Ok(json_obj_to_struct("Resolution", &json))
}

/// sync.pause(id) -> Nil (on success) or error
fn sync_pause(args: Vec<Value>) -> StdlibResult {
    let pair_id = get_string_arg(&args, 0)
        .ok_or("sync.pause: requires sync pair ID (string)")?;
    daemon_post(&format!("/sync/pairs/{}/pause", pair_id), None)?;
    Ok(Value::Nil)
}

/// sync.resume(id) -> Nil (on success) or error
fn sync_resume(args: Vec<Value>) -> StdlibResult {
    let pair_id = get_string_arg(&args, 0)
        .ok_or("sync.resume: requires sync pair ID (string)")?;
    daemon_post(&format!("/sync/pairs/{}/resume", pair_id), None)?;
    Ok(Value::Nil)
}

// ── Concurrency dispatch (original sync module) ────────────────────────

/// Dispatch a sync module function call by name.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    // Try file sync functions first
    match function {
        "bidirectional" => return Some(sync_bidirectional(args)),
        "mesh" => return Some(sync_mesh(args)),
        "status" => return Some(sync_status(args)),
        "list_pairs" => return Some(sync_list_pairs(args)),
        "resolve_conflict" => return Some(sync_resolve_conflict(args)),
        "pause" => return Some(sync_pause(args)),
        "resume" => return Some(sync_resume(args)),
        _ => {} // fall through to concurrency functions
    }

    // Concurrency primitives
    match function {
        "channel" => Some(sync_channel(args)),
        "unbounded" => Some(sync_unbounded()),
        "mutex" => {
            let val = args.into_iter().next().unwrap_or(Value::Nil);
            Some(Ok(Value::Struct {
                name: "SyncMutex".to_string(),
                fields: vec![("value".to_string(), val)],
            }))
        }
        "rwlock" => {
            let val = args.into_iter().next().unwrap_or(Value::Nil);
            Some(Ok(Value::Struct {
                name: "SyncRwLock".to_string(),
                fields: vec![("value".to_string(), val)],
            }))
        }
        "barrier" => {
            let count = args
                .first()
                .and_then(|v| match v {
                    Value::Int(n) => Some(*n as usize),
                    _ => None,
                })
                .unwrap_or(2);
            Some(Ok(Value::Struct {
                name: "SyncBarrier".to_string(),
                fields: vec![("count".to_string(), Value::Int(count as i128))],
            }))
        }
        "once" => Some(Ok(Value::Struct {
            name: "SyncOnce".to_string(),
            fields: vec![("called".to_string(), Value::Bool(false))],
        })),
        // Declared in stdlib/sync.tl with empty `// native:` bodies and previously
        // absent from every dispatcher. Implemented 2026-10-12.
        "atomic" => Some(sync_atomic(args)),
        "wait_group" => Some(sync_wait_group(args)),
        _ => None,
    }
}

/// Dispatch a method call on a sync struct type.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if let Value::Struct { name, fields } = object {
        // File sync struct field access
        match name.as_str() {
            "SyncPair" | "SyncStatus" | "SyncFileEntry" | "MeshConfig"
            | "Resolution" | "SyncHistoryEntry" => {
                for (field_name, field_value) in fields {
                    if field_name == method {
                        return Some(Ok(field_value.clone()));
                    }
                }
                return Some(Err(format!("{} has no field '{}'", name, method)));
            }
            _ => {}
        }

        // Concurrency struct methods
        match name.as_str() {
            "SyncMutex" => sync_mutex_method(fields, method, args),
            "SyncRwLock" => sync_rwlock_method(fields, method, args),
            "SyncBarrier" => sync_barrier_method(fields, method, args),
            "SyncOnce" => sync_once_method(fields, method, args),
            "AtomicI64" => atomic_method(fields, method, args),
            "WaitGroup" => wait_group_method(fields, method, args),
            _ => None,
        }
    } else {
        let _ = method;
        let _ = args;
        None
    }
}

// ── sync.channel(capacity?) → Struct { sender, receiver } ──

fn sync_channel(args: Vec<Value>) -> StdlibResult {
    let capacity: Option<usize> = match args.first() {
        Some(Value::Int(n)) => {
            let n = *n;
            if n < 0 {
                return Err("sync.channel: capacity cannot be negative".into());
            }
            Some(n as usize)
        }
        Some(other) => {
            return Err(format!(
                "sync.channel: expected integer capacity, got {}",
                type_name(other)
            )
            .into())
        }
        None => None, // unbuffered
    };

    let ch = crate::interp::ChannelHandle::new(capacity);
    Ok(Value::Struct {
        name: "SyncChannel".to_string(),
        fields: vec![("handle".to_string(), Value::Channel(ch))],
    })
}

/// sync.unbounded() → SyncChannel backed by an unbounded crossbeam channel.
fn sync_unbounded() -> StdlibResult {
    let ch = crate::interp::ChannelHandle::new(None);
    Ok(Value::Struct {
        name: "SyncChannel".to_string(),
        fields: vec![("handle".to_string(), Value::Channel(ch))],
    })
}

// ── Mutex methods ──

fn sync_mutex_method(
    fields: &[(String, Value)],
    method: &str,
    args: Vec<Value>,
) -> Option<StdlibResult> {
    // Functional in-memory Mutex: `new` allocates a SyncMutex, `lock` hands
    // back a SyncGuard snapshot of the current value, and `value` reads it.
    // A real interleaved lock requires an actor runtime; within the
    // interpreter each mutation is atomic, so guarding is implicit. Unknown
    // methods return `None` to fall through to the interpreter.
    match method {
        "new" => {
            let val = args.into_iter().next().unwrap_or(Value::Nil);
            Some(Ok(Value::Struct {
                name: "SyncMutex".to_string(),
                fields: vec![("value".to_string(), val)],
            }))
        }
        "lock" => {
            let value = fields
                .iter()
                .find(|(k, _)| k == "value")
                .map(|(_, v)| v.clone());
            Some(Ok(Value::Struct {
                name: "SyncGuard".to_string(),
                fields: vec![("value".to_string(), value.unwrap_or(Value::Nil))],
            }))
        }
        // Declared in stdlib/sync.tl as `fn try_lock(self) -> T?` with the body
        // `// native: returns nil if already locked`, and previously absent from this match — a
        // call died with `unknown method: .try_lock()` while `lock` one arm above worked.
        //
        // It mirrors `lock`'s documented model instead of inventing contention: within the
        // interpreter every mutation is already atomic (see this function's header), so a lock is
        // never held across an interleaved region and the "already locked" branch is unreachable
        // BY CONSTRUCTION, not by omission. Returning the value is the true answer under that
        // model; fabricating a nil to make the optional type look used would be the fake.
        // Making `try_lock` observably fail needs the actor runtime the header describes.
        "try_lock" => {
            let value = fields
                .iter()
                .find(|(k, _)| k == "value")
                .map(|(_, v)| v.clone());
            Some(Ok(value.unwrap_or(Value::Nil)))
        }
        "value" => {
            let val = fields
                .iter()
                .find(|(k, _)| k == "value")
                .map(|(_, v)| v.clone());
            Some(Ok(val.unwrap_or(Value::Nil)))
        }
        _ => None,
    }
}

// ── RwLock methods ──

fn sync_rwlock_method(
    fields: &[(String, Value)],
    method: &str,
    args: Vec<Value>,
) -> Option<StdlibResult> {
    match method {
        "new" => {
            let val = args.into_iter().next().unwrap_or(Value::Nil);
            Some(Ok(Value::Struct {
                name: "SyncRwLock".to_string(),
                fields: vec![("value".to_string(), val)],
            }))
        }
        "read" | "write" => {
            let value = fields
                .iter()
                .find(|(k, _)| k == "value")
                .map(|(_, v)| v.clone());
            Some(Ok(Value::Struct {
                name: "SyncGuard".to_string(),
                fields: vec![("value".to_string(), value.unwrap_or(Value::Nil))],
            }))
        }
        "value" => {
            let val = fields
                .iter()
                .find(|(k, _)| k == "value")
                .map(|(_, v)| v.clone());
            Some(Ok(val.unwrap_or(Value::Nil)))
        }
        _ => None,
    }
}

// ── Barrier methods ──

fn sync_barrier_method(
    _fields: &[(String, Value)],
    method: &str,
    args: Vec<Value>,
) -> Option<StdlibResult> {
    match method {
        "new" => {
            let count = args
                .first()
                .and_then(|v| match v {
                    Value::Int(n) => Some(*n as usize),
                    _ => None,
                })
                .unwrap_or(2);
            Some(Ok(Value::Struct {
                name: "SyncBarrier".to_string(),
                fields: vec![("count".to_string(), Value::Int(count as i128))],
            }))
        }
        "wait" => {
            // Single-threaded: return immediately (goroutines aren't implemented yet)
            Some(Ok(Value::Nil))
        }
        _ => None,
    }
}

// ── Once methods ──

fn sync_once_method(
    _fields: &[(String, Value)],
    method: &str,
    _args: Vec<Value>,
) -> Option<StdlibResult> {
    match method {
        "new" => {
            Some(Ok(Value::Struct {
                name: "SyncOnce".to_string(),
                fields: vec![("called".to_string(), Value::Bool(false))],
            }))
        }
        "do" => {
            // Single-threaded: mark called
            Some(Ok(Value::Bool(true)))
        }
        _ => None,
    }
}

fn type_name(val: &Value) -> &'static str {
    match val {
        Value::Nil => "nil",
        Value::Bool(_) => "bool",
        Value::Int(_) => "int",
        Value::Float(_) => "float",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Map(_) => "map",
        Value::Struct { .. } => "struct",
        _ => "unknown",
    }
}

// ── AtomicI64 / WaitGroup ────────────────────────────────────────────────────
//
// State lives in a **registry keyed by an id carried in the handle**, not in the
// struct's own fields. `dispatch_method` receives the object by reference and
// returns a fresh Value, so it cannot mutate the caller's binding: an inline
// field would make `a.store(5)` mutate a throwaway copy and a later `a.load()`
// still return the old value — a silent wrong value. This is the same registry
// pattern `stdlib/fs.rs` uses for watchers.
//
// The interpreter is single-threaded, so these are faithful handles rather than
// real concurrency primitives; `WaitGroup.wait` says so explicitly instead of
// blocking forever.

static NEXT_SYNC_ID: AtomicU64 = AtomicU64::new(1);
static ATOMICS: LazyLock<Mutex<HashMap<u64, i64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static WAITGROUPS: LazyLock<Mutex<HashMap<u64, i64>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

fn next_sync_id() -> u64 {
    NEXT_SYNC_ID.fetch_add(1, Ordering::Relaxed)
}

fn handle_id(fields: &[(String, Value)]) -> Option<u64> {
    fields
        .iter()
        .find(|(k, _)| k == "id")
        .and_then(|(_, v)| match v {
            Value::Int(n) if *n > 0 => Some(*n as u64),
            _ => None,
        })
}

fn int_arg(args: &[Value], idx: usize, what: &str, fname: &str) -> Result<i64, String> {
    match args.get(idx) {
        Some(Value::Int(n)) => Ok(*n as i64),
        _ => Err(format!(
            "{fname}: expected integer {what} as argument {}",
            idx + 1
        )),
    }
}

fn sync_atomic(args: Vec<Value>) -> StdlibResult {
    let initial = match args.first() {
        Some(Value::Int(n)) => *n as i64,
        None => 0,
        _ => return Err("sync.atomic expects an i64 value".into()),
    };
    let id = next_sync_id();
    match ATOMICS.lock() {
        Ok(mut registry) => {
            registry.insert(id, initial);
        }
        Err(_) => return Err("sync.atomic: registry poisoned".into()),
    }
    Ok(Value::Struct {
        name: "AtomicI64".to_string(),
        fields: vec![("id".to_string(), Value::Int(id as i128))],
    })
}

fn sync_wait_group(_args: Vec<Value>) -> StdlibResult {
    let id = next_sync_id();
    match WAITGROUPS.lock() {
        Ok(mut registry) => {
            registry.insert(id, 0);
        }
        Err(_) => return Err("sync.wait_group: registry poisoned".into()),
    }
    Ok(Value::Struct {
        name: "WaitGroup".to_string(),
        fields: vec![("id".to_string(), Value::Int(id as i128))],
    })
}

fn atomic_method(
    fields: &[(String, Value)],
    method: &str,
    args: Vec<Value>,
) -> Option<StdlibResult> {
    let id = match handle_id(fields) {
        Some(id) => id,
        None => return Some(Err("AtomicI64 handle is missing its id".into())),
    };
    let mut registry = match ATOMICS.lock() {
        Ok(g) => g,
        Err(_) => return Some(Err("sync.atomic: registry poisoned".into())),
    };
    if !registry.contains_key(&id) {
        return Some(Err(format!("AtomicI64 handle {id} is no longer valid")));
    }
    match method {
        "load" => Some(Ok(Value::Int(registry[&id] as i128))),
        "store" => match int_arg(&args, 0, "value", "AtomicI64.store") {
            Ok(v) => {
                registry.insert(id, v);
                Some(Ok(Value::Nil))
            }
            Err(e) => Some(Err(e)),
        },
        // `add`/`sub` return the PREVIOUS value, per the .tl declaration.
        "add" | "sub" => {
            let delta = match int_arg(&args, 0, "delta", "AtomicI64.add") {
                Ok(d) => d,
                Err(e) => return Some(Err(e)),
            };
            let delta = if method == "sub" { -delta } else { delta };
            let previous = registry[&id];
            registry.insert(id, previous.wrapping_add(delta));
            Some(Ok(Value::Int(previous as i128)))
        }
        "compare_swap" => {
            let expected = match int_arg(&args, 0, "expected", "AtomicI64.compare_swap") {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
            let new = match int_arg(&args, 1, "new", "AtomicI64.compare_swap") {
                Ok(v) => v,
                Err(e) => return Some(Err(e)),
            };
            if registry[&id] == expected {
                registry.insert(id, new);
                Some(Ok(Value::Bool(true)))
            } else {
                Some(Ok(Value::Bool(false)))
            }
        }
        other => Some(Err(format!(
            "AtomicI64 has no method '{other}' (expected load, store, add, sub, compare_swap)"
        ))),
    }
}

fn wait_group_method(
    fields: &[(String, Value)],
    method: &str,
    args: Vec<Value>,
) -> Option<StdlibResult> {
    let id = match handle_id(fields) {
        Some(id) => id,
        None => return Some(Err("WaitGroup handle is missing its id".into())),
    };
    let mut registry = match WAITGROUPS.lock() {
        Ok(g) => g,
        Err(_) => return Some(Err("sync.wait_group: registry poisoned".into())),
    };
    if !registry.contains_key(&id) {
        return Some(Err(format!("WaitGroup handle {id} is no longer valid")));
    }
    match method {
        "add" => match int_arg(&args, 0, "count", "WaitGroup.add") {
            Ok(c) if c >= 0 => {
                let current = registry[&id];
                registry.insert(id, current + c);
                Some(Ok(Value::Nil))
            }
            Ok(c) => Some(Err(format!(
                "WaitGroup.add: count must be non-negative, got {c}"
            ))),
            Err(e) => Some(Err(e)),
        },
        "done" => {
            let current = registry[&id];
            if current <= 0 {
                return Some(Err(
                    "WaitGroup.done: counter is already 0 (unbalanced done)".into(),
                ));
            }
            registry.insert(id, current - 1);
            Some(Ok(Value::Nil))
        }
        "wait" => {
            let current = registry[&id];
            if current == 0 {
                Some(Ok(Value::Nil))
            } else {
                Some(Err(format!(
                    "WaitGroup.wait: counter is {current}, not 0. This interpreter is \
                     single-threaded, so no pending task can decrement it and wait() would \
                     block forever — balance add/done before calling wait()."
                )))
            }
        }
        other => Some(Err(format!(
            "WaitGroup has no method '{other}' (expected add, done, wait)"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interp::Value;

    #[test]
    fn channel_returns_struct() {
        let result = dispatch("channel", vec![]).unwrap().unwrap();
        match result {
            Value::Struct { name, .. } => assert_eq!(name, "SyncChannel"),
            _ => panic!("expected struct"),
        }
    }

    #[test]
    fn channel_with_capacity() {
        let result = dispatch("channel", vec![Value::Int(10)]).unwrap().unwrap();
        match result {
            Value::Struct { name, .. } => assert_eq!(name, "SyncChannel"),
            _ => panic!("expected struct"),
        }
    }

    #[test]
    fn channel_with_zero_capacity_is_synchronous() {
        let result = dispatch("channel", vec![Value::Int(0)]).unwrap().unwrap();
        match result {
            Value::Struct { name, .. } => assert_eq!(name, "SyncChannel"),
            _ => panic!("expected struct"),
        }
    }

    #[test]
    fn mutex_new_returns_struct() {
        let result = dispatch_method(
            &Value::Struct {
                name: "SyncMutex".into(),
                fields: vec![],
            },
            "new",
            vec![Value::Int(42)],
        );
        assert!(result.is_some());
    }

    /// `try_lock` was declared in stdlib/sync.tl and answered by nothing, so this call was
    /// `unknown method: .try_lock()`. It must return the value (never a fabricated nil): under the
    /// interpreter's documented non-contended model the "already locked" branch cannot occur.
    #[test]
    fn mutex_try_lock_returns_the_value() {
        let m = Value::Struct {
            name: "SyncMutex".into(),
            fields: vec![("value".into(), Value::Int(7))],
        };
        match dispatch_method(&m, "try_lock", vec![]).unwrap().unwrap() {
            Value::Int(n) => assert_eq!(n, 7),
            other => panic!("expected the guarded value, got {other:?}"),
        }
    }

    /// And `lock` still hands back a guard, unchanged by the arm above.
    #[test]
    fn mutex_lock_still_returns_a_guard() {
        let m = Value::Struct {
            name: "SyncMutex".into(),
            fields: vec![("value".into(), Value::Int(7))],
        };
        match dispatch_method(&m, "lock", vec![]).unwrap().unwrap() {
            Value::Struct { name, fields } => {
                assert_eq!(name, "SyncGuard");
                // `Value` has no PartialEq, so match rather than compare.
                assert!(fields
                    .iter()
                    .any(|(k, v)| k == "value" && matches!(v, Value::Int(7))));
            }
            other => panic!("expected SyncGuard, got {other:?}"),
        }
    }

    #[test]
    fn rwlock_new_returns_struct() {
        let result = dispatch_method(
            &Value::Struct {
                name: "SyncRwLock".into(),
                fields: vec![],
            },
            "new",
            vec![Value::String("data".into())],
        );
        assert!(result.is_some());
    }

    #[test]
    fn barrier_new_requires_count() {
        let result = dispatch_method(
            &Value::Struct {
                name: "SyncBarrier".into(),
                fields: vec![],
            },
            "new",
            vec![Value::Int(4)],
        );
        assert!(result.is_some());
    }

    #[test]
    fn once_new_returns_struct() {
        let result = dispatch_method(
            &Value::Struct {
                name: "SyncOnce".into(),
                fields: vec![],
            },
            "new",
            vec![],
        );
        assert!(result.is_some());
    }

    // =========================================================================
    // Phase 7 — File sync function tests
    // =========================================================================

    #[test]
    fn sync_bidirectional_dispatch_routes() {
        // Should return Some (dispatch routing exists), but will be Err
        // because daemon is not running (circuit breaker).
        let result = dispatch("bidirectional", vec![
            Value::String("/home/docs".into()),
            Value::String("/backup/docs".into()),
            Value::String("laptop-01".into()),
            Value::String("http://127.0.0.1:9999".into()),
        ]);
        assert!(result.is_some(), "sync.bidirectional should be routable");
        // Circuit breaker: daemon not running should produce a clear error
        let err = result.unwrap().unwrap_err();
        assert!(
            err.contains("daemon not running") || err.contains("Connection refused") || err.contains("127.0.0.1"),
            "error should mention daemon connectivity: {}",
            err
        );
    }

    #[test]
    fn sync_mesh_dispatch_routes() {
        let config_map = Value::Map(vec![
            (Value::String("laptop-01".into()), Value::String("http://127.0.0.1:9990".into())),
            (Value::String("laptop-02".into()), Value::String("http://127.0.0.1:9991".into())),
        ]);
        let result = dispatch("mesh", vec![config_map]);
        assert!(result.is_some(), "sync.mesh should be routable");
        // FIX16: the previous assertion expected an Ok(MeshConfig) with a
        // `device_count` field — that described removed fake behavior.
        // sync.mesh is daemon-backed: it POSTs /sync/mesh to the tallow daemon
        // and wraps the daemon's JSON response. With no daemon running (the
        // test environment), the honest result is a clear Err, exactly like
        // sync.bidirectional above.
        let err = result.unwrap().unwrap_err();
        assert!(
            err.contains("daemon not running") || err.contains("Connection refused") || err.contains("127.0.0.1"),
            "error should mention daemon connectivity: {}",
            err
        );
    }

    #[test]
    fn sync_status_dispatch_routes() {
        let result = dispatch("status", vec![Value::String("fake-pair-id".into())]);
        assert!(result.is_some(), "sync.status should be routable");
    }

    #[test]
    fn sync_list_pairs_dispatch_routes() {
        let result = dispatch("list_pairs", vec![]);
        assert!(result.is_some(), "sync.list_pairs should be routable");
    }

    #[test]
    fn sync_resolve_conflict_dispatch_routes() {
        let result = dispatch("resolve_conflict", vec![
            Value::String("notes.txt".into()),
            Value::String("keep-mine".into()),
        ]);
        assert!(result.is_some(), "sync.resolve_conflict should be routable");
    }

    #[test]
    fn sync_pause_resume_dispatch_routes() {
        let result = dispatch("pause", vec![Value::String("fake-pair-id".into())]);
        assert!(result.is_some(), "sync.pause should be routable");

        let result = dispatch("resume", vec![Value::String("fake-pair-id".into())]);
        assert!(result.is_some(), "sync.resume should be routable");
    }

    // ── AtomicI64 / WaitGroup (added 2026-10-12) ──

    fn fields_of(v: &Value) -> Vec<(String, Value)> {
        match v {
            Value::Struct { fields, .. } => fields.clone(),
            other => panic!("expected Struct, got {other:?}"),
        }
    }

    #[test]
    fn atomic_mutation_is_visible_through_the_handle() {
        // The property the registry exists for: mutating through one handle
        // must be visible when reading through the same handle again.
        let handle = sync_atomic(vec![Value::Int(10)]).unwrap();
        let f = fields_of(&handle);

        let load = || match atomic_method(&f, "load", vec![]).unwrap().unwrap() {
            Value::Int(n) => n,
            other => panic!("expected Int, got {other:?}"),
        };
        assert_eq!(load(), 10);

        atomic_method(&f, "store", vec![Value::Int(42)])
            .unwrap()
            .unwrap();
        assert_eq!(load(), 42, "store must be visible through the handle");
    }

    #[test]
    fn atomic_add_and_sub_return_the_previous_value() {
        let f = fields_of(&sync_atomic(vec![Value::Int(100)]).unwrap());

        match atomic_method(&f, "add", vec![Value::Int(5)])
            .unwrap()
            .unwrap()
        {
            Value::Int(prev) => assert_eq!(prev, 100),
            other => panic!("add should return the previous value, got {other:?}"),
        }
        match atomic_method(&f, "sub", vec![Value::Int(20)])
            .unwrap()
            .unwrap()
        {
            Value::Int(prev) => assert_eq!(prev, 105),
            other => panic!("sub should return the previous value, got {other:?}"),
        }
        match atomic_method(&f, "load", vec![]).unwrap().unwrap() {
            Value::Int(n) => assert_eq!(n, 85),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn atomic_compare_swap_only_swaps_on_match() {
        let f = fields_of(&sync_atomic(vec![Value::Int(7)]).unwrap());

        match atomic_method(&f, "compare_swap", vec![Value::Int(999), Value::Int(0)])
            .unwrap()
            .unwrap()
        {
            Value::Bool(swapped) => assert!(!swapped, "mismatched expected must not swap"),
            other => panic!("{other:?}"),
        }
        match atomic_method(&f, "load", vec![]).unwrap().unwrap() {
            Value::Int(n) => assert_eq!(n, 7, "value must be untouched after a failed swap"),
            other => panic!("{other:?}"),
        }
        match atomic_method(&f, "compare_swap", vec![Value::Int(7), Value::Int(0)])
            .unwrap()
            .unwrap()
        {
            Value::Bool(swapped) => assert!(swapped),
            other => panic!("{other:?}"),
        }
        match atomic_method(&f, "load", vec![]).unwrap().unwrap() {
            Value::Int(n) => assert_eq!(n, 0),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn atomic_rejects_bad_method_and_bad_args() {
        let f = fields_of(&sync_atomic(vec![Value::Int(1)]).unwrap());
        assert!(atomic_method(&f, "frobnicate", vec![]).unwrap().is_err());
        assert!(atomic_method(&f, "store", vec![]).unwrap().is_err());
        assert!(atomic_method(&f, "add", vec![Value::String("x".into())])
            .unwrap()
            .is_err());
        assert!(sync_atomic(vec![Value::String("x".into())]).is_err());
        // A handle with no id is rejected rather than silently defaulting.
        assert!(
            atomic_method(&[("value".to_string(), Value::Int(1))], "load", vec![])
                .unwrap()
                .is_err()
        );
    }

    #[test]
    fn wait_group_balances_and_wait_refuses_to_hang() {
        let f = fields_of(&sync_wait_group(vec![]).unwrap());

        // At zero, wait() returns.
        assert!(wait_group_method(&f, "wait", vec![]).unwrap().is_ok());

        // With work outstanding it must ERROR, not block: the interpreter is
        // single-threaded, so nothing could ever decrement the counter.
        wait_group_method(&f, "add", vec![Value::Int(2)])
            .unwrap()
            .unwrap();
        assert!(
            wait_group_method(&f, "wait", vec![]).unwrap().is_err(),
            "wait() with a non-zero counter must error, never hang"
        );

        wait_group_method(&f, "done", vec![]).unwrap().unwrap();
        wait_group_method(&f, "done", vec![]).unwrap().unwrap();
        assert!(wait_group_method(&f, "wait", vec![]).unwrap().is_ok());

        assert!(wait_group_method(&f, "done", vec![]).unwrap().is_err());
        assert!(wait_group_method(&f, "add", vec![Value::Int(-1)])
            .unwrap()
            .is_err());
        assert!(wait_group_method(&f, "frobnicate", vec![]).unwrap().is_err());
    }

    #[test]
    fn atomic_handles_are_independent() {
        let a = fields_of(&sync_atomic(vec![Value::Int(1)]).unwrap());
        let b = fields_of(&sync_atomic(vec![Value::Int(1)]).unwrap());
        atomic_method(&a, "store", vec![Value::Int(50)])
            .unwrap()
            .unwrap();
        assert!(matches!(
            atomic_method(&b, "load", vec![]).unwrap().unwrap(),
            Value::Int(1)
        ));
        assert!(matches!(
            atomic_method(&a, "load", vec![]).unwrap().unwrap(),
            Value::Int(50)
        ));
    }

    #[test]
    fn sync_unknown_function_returns_none() {
        let result = dispatch("nonexistent_sync_fn", vec![]);
        assert!(result.is_none(), "unknown sync function should return None");
    }
}
