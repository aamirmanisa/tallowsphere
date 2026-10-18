//! Standard library: `tallow.fs` -- Filesystem operations.

use super::StdlibResult;
use crate::interp::Value;
use base64::Engine;
use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::UNIX_EPOCH;

// ══════════════════════════════════════════════════════════════════
// Global watcher registry
// ══════════════════════════════════════════════════════════════════

static WATCHER_ID_COUNTER: LazyLock<Mutex<u64>> = LazyLock::new(|| Mutex::new(0));

fn next_watcher_id() -> u64 {
    let mut counter = WATCHER_ID_COUNTER.lock().unwrap();
    *counter += 1;
    *counter
}

struct WatcherEntry {
    _watcher: notify::RecommendedWatcher,
    events: std::sync::Arc<Mutex<Vec<FsEvent>>>,
}

#[derive(Clone, Debug)]
struct FsEvent {
    kind: String,
    path: String,
}

static WATCHERS: LazyLock<Mutex<HashMap<u64, WatcherEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Dispatch a `tallow.fs.*` function call.
///
/// Functions already implemented inline in interp.rs (exists, is_file, is_dir,
/// read, write, append, copy, mkdir, delete/remove, list_dir/readdir) return
/// None to fall through. Only truly unimplemented functions return not_yet().
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        // Implemented inline in interp.rs — fall through
        "exists" | "is_file" | "is_dir" | "read" | "write" | "append" | "copy" | "mkdir"
        | "delete" | "remove" | "list_dir" | "readdir" => None,

        "read_file" => Some(do_read_file(args)),
        "write_file" => Some(do_write_file(args)),
        "rename" => Some(do_rename(args)),
        "stat" => Some(do_stat(args)),
        // `fs.file_size(path) -> Result<u64>` was declared in stdlib/fs.tl with
        // no arm in any dispatcher, so every call died as "undefined function"
        // in the interpreter (register #84). One `metadata` call, same source
        // of truth as `do_stat`.
        "file_size" => Some(do_file_size(args)),
        "temp_file" => Some(do_temp_file(args)),

        // Filesystem watching
        "watch" => Some(do_watch(args)),
        "watch_poll" => Some(do_watch_poll(args)),
        "watch_stop" => Some(do_watch_stop(args)),

        // Async I/O (transparent fallback to sync on non-io_uring platforms)
        "read_file_async" => Some(do_read_file(args)),
        "write_file_async" => Some(do_write_file(args)),

        // Declared in stdlib/fs.tl with empty `// native:` bodies and previously
        // absent from every dispatcher — therefore uncallable. Implemented 2026-10-12.
        "append_file" => Some(do_append_file(args)),
        "remove_dir_all" => Some(do_remove_dir_all(args)),
        "read_lines" => Some(do_read_lines(args)),

        // Also declared with empty `// native:` bodies. `Bytes` is base64 at
        // runtime — the convention `compress` already uses — so these are the
        // binary-safe counterparts of read_file/write_file. Implemented 2026-10-12.
        "read_bytes" => Some(do_read_bytes(args)),
        "write_bytes" => Some(do_write_bytes(args)),

        _ => None,
    }
}

/// Dispatch a method call on a `tallow.fs` object (e.g., FileInfo, FsWatcher).
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if let Value::Struct { name, fields } = object {
        if name == "FileInfo" {
            // Look up the field by method name (field accessor pattern)
            for (field_name, field_value) in fields {
                if field_name == method {
                    return Some(Ok(field_value.clone()));
                }
            }
            return Some(Err(format!("FileInfo has no field '{method}'")));
        }
        if name == "FsWatcher" {
            // Extract watcher ID from fields
            let watcher_id = fields
                .iter()
                .find(|(k, _)| k == "id")
                .and_then(|(_, v)| match v {
                    Value::Int(n) => Some(*n as u64),
                    _ => None,
                });
            match method {
                "poll" => {
                    if let Some(id) = watcher_id {
                        return Some(do_watch_poll(vec![Value::Int(id as i128)]));
                    }
                    return Some(Err("FsWatcher.poll: missing watcher id".into()));
                }
                "stop" => {
                    if let Some(id) = watcher_id {
                        return Some(do_watch_stop(vec![Value::Int(id as i128)]));
                    }
                    return Some(Err("FsWatcher.stop: missing watcher id".into()));
                }
                _ => {
                    // Field accessor fallback
                    for (field_name, field_value) in fields {
                        if field_name == method {
                            return Some(Ok(field_value.clone()));
                        }
                    }
                    return Some(Err(format!("FsWatcher has no method '{method}'")));
                }
            }
        }
    }
    let _ = args;
    None
}

// ── Implementations ──────────────────────────────────────────────────────────

/// `fs.append_file(path: String, content: String) -> Result<()>`
///
/// Creates the file if absent, appends otherwise. Mirrors `fs.write_file`'s
/// parent-directory creation so append-to-new-path behaves like write.
fn do_append_file(args: Vec<Value>) -> StdlibResult {
    use std::io::Write;
    let path = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.append_file: expected string path as first argument".into()),
    };
    let content = match args.get(1) {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.append_file: expected string content as second argument".into()),
    };
    if let Some(parent) = std::path::Path::new(&path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|e| format!("fs.append_file: {e}"))?;
    file.write_all(content.as_bytes())
        .map(|_| Value::Nil)
        .map_err(|e| format!("fs.append_file: {e}"))
}

/// `fs.remove_dir_all(path: String) -> Result<()>`
fn do_remove_dir_all(args: Vec<Value>) -> StdlibResult {
    let path = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.remove_dir_all: expected string path argument".into()),
    };
    std::fs::remove_dir_all(&path)
        .map(|_| Value::Nil)
        .map_err(|e| format!("fs.remove_dir_all: {e}"))
}

/// `fs.read_lines(path: String) -> Result<[]String>`
///
/// Splits on newlines. `str::lines()` already drops the trailing empty element
/// produced by a final newline, and handles CRLF, so no post-processing.
fn do_read_lines(args: Vec<Value>) -> StdlibResult {
    let path = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.read_lines: expected string path argument".into()),
    };
    let text = std::fs::read_to_string(&path).map_err(|e| format!("fs.read_lines: {e}"))?;
    Ok(Value::Array(
        text.lines().map(|l| Value::String(l.to_string())).collect(),
    ))
}

/// `fs.read_bytes(path: String) -> Result<Bytes>`
///
/// Returns the file's **raw bytes** as a `Bytes` value. It is not a `String`,
/// and it is **not** base64 text: `Bytes` and `String` are distinct at the
/// interpreter boundary, so this value cannot be handed to a text function by
/// accident — `provenance.hash_body(fs.read_bytes(p))` fails loudly with
/// `expected String, got Bytes` instead of silently fingerprinting an encoded
/// form (the G-14 silent-wrong-digest defect). For a file's sha256 use
/// `provenance.hash_bytes`; for the encoded text form the compiled/FFI
/// boundary uses, call `.base64()` on the value.
///
/// T_0831EDBA — one representation on both engines: a `Bytes` value
/// *stringifies* to its base64 encoding, so `print(fs.read_bytes(p))` is the
/// same bytes whether the interpreter or the native lowering ran the program
/// (the native FFI hands back base64, and the interpreter's own rendering used
/// to be a `<bytes:N bytes>` summary). The value stays raw here — the base64
/// text is the rendering/wire form, not the interpreter's storage form.
fn do_read_bytes(args: Vec<Value>) -> StdlibResult {
    let path = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.read_bytes: expected string path argument".into()),
    };
    let bytes = std::fs::read(&path).map_err(|e| format!("fs.read_bytes: {e}"))?;
    Ok(Value::Bytes(bytes))
}

/// `fs.write_bytes(path: String, data: Bytes) -> Result<()>`
///
/// Writes `data` verbatim. A base64 `String` is accepted too, for callers that
/// hold the encoded form (which is how the compiled/FFI boundary carries
/// `Bytes`, and what `read_bytes` returned before it produced a real `Bytes`
/// value); invalid base64 is a failure, never a silent truncation.
fn do_write_bytes(args: Vec<Value>) -> StdlibResult {
    let path = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.write_bytes: expected string path as first argument".into()),
    };
    let bytes = match args.get(1) {
        Some(Value::Bytes(b)) => b.clone(),
        Some(Value::String(s)) => base64::engine::general_purpose::STANDARD
            .decode(s.as_bytes())
            .map_err(|e| format!("fs.write_bytes: invalid base64: {e}"))?,
        _ => {
            return Err(
                "fs.write_bytes: expected Bytes data (or base64 String) as second argument".into(),
            );
        }
    };
    if let Some(parent) = std::path::Path::new(&path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    std::fs::write(&path, &bytes)
        .map(|_| Value::Nil)
        .map_err(|e| format!("fs.write_bytes: {e}"))
}

fn do_read_file(args: Vec<Value>) -> StdlibResult {
    let path = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.read_file: expected string path argument".into()),
    };
    // Contract settled 2026-10-15: `stdlib/fs.tl` declares `read_file -> String` and both engines
    // return the bare string; a read FAILURE is a loud error, never an `Err` value and never an
    // empty string. The `.tl` declaration was flipped to match the behaviour rather than the
    // reverse, and the interpreter's builtin `read_file` was brought onto the same contract. Do not
    // re-wrap this in `Ok(..)`: that is what made `if let Ok(c) = read_file(p)` silently never fire.
    std::fs::read_to_string(&path).map(Value::String).map_err(|e| format!("fs.read_file: {e}"))
}

fn do_write_file(args: Vec<Value>) -> StdlibResult {
    let path = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.write_file: expected string path as first argument".into()),
    };
    let content = match args.get(1) {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.write_file: expected string content as second argument".into()),
    };
    // Auto-create parent directories (key difference from fs.write)
    if let Some(parent) = std::path::Path::new(&path).parent() {
        if !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }
    }
    std::fs::write(&path, &content).map(|_| Value::Nil).map_err(|e| format!("fs.write_file: {e}"))
}

fn do_rename(args: Vec<Value>) -> StdlibResult {
    let src = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.rename: expected string source path as first argument".into()),
    };
    let dst = match args.get(1) {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.rename: expected string destination path as second argument".into()),
    };
    std::fs::rename(&src, &dst).map(|_| Value::Nil).map_err(|e| format!("fs.rename: {e}"))
}

fn do_stat(args: Vec<Value>) -> StdlibResult {
    let path = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.stat: expected string path argument".into()),
    };
    let meta = std::fs::metadata(&path).map_err(|e| format!("fs.stat: {e}"))?;
    let size = meta.len() as i128;
    let modified_at = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i128)
        .unwrap_or(0);
    let is_file = meta.is_file();
    let is_dir = meta.is_dir();

    Ok(Value::Struct {
        name: "FileInfo".to_string(),
        fields: vec![
            ("size".to_string(), Value::Int(size)),
            ("modified_at".to_string(), Value::Int(modified_at)),
            ("is_file".to_string(), Value::Bool(is_file)),
            ("is_dir".to_string(), Value::Bool(is_dir)),
        ],
    })
}

/// `fs.file_size(path)` — byte length of a regular file. Symlinks are followed
/// (`metadata`, not `symlink_metadata`), matching `fs.stat`'s `size` field.
fn do_file_size(args: Vec<Value>) -> StdlibResult {
    let path = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.file_size: expected string path argument".into()),
    };
    let meta = std::fs::metadata(&path).map_err(|e| format!("fs.file_size: {e}"))?;
    Ok(Value::Int(meta.len() as i128))
}

fn do_temp_file(args: Vec<Value>) -> StdlibResult {
    let _ = args;
    let tmp_dir = std::env::temp_dir();
    let unique = rand::random::<u32>();
    let filename = format!("tallow_tmp_{}_{}", std::process::id(), unique);
    let path = tmp_dir.join(filename);
    std::fs::File::create(&path).map_err(|e| format!("fs.temp_file: {e}"))?;
    Ok(Value::String(path.to_string_lossy().to_string()))
}

// ══════════════════════════════════════════════════════════════════
// Filesystem Watching (STDX-01)
// ══════════════════════════════════════════════════════════════════

fn do_watch(args: Vec<Value>) -> StdlibResult {
    use notify::{RecursiveMode, Watcher};

    let path = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("fs.watch: expected string path argument".into()),
    };

    let events: std::sync::Arc<Mutex<Vec<FsEvent>>> =
        std::sync::Arc::new(Mutex::new(Vec::new()));
    let events_clone = events.clone();

    let mut watcher = notify::recommended_watcher(move |res: Result<notify::Event, notify::Error>| {
        if let Ok(event) = res {
            let kind = match event.kind {
                notify::EventKind::Create(_) => "create",
                notify::EventKind::Modify(_) => "modify",
                notify::EventKind::Remove(_) => "remove",
                _ => return, // ignore access/other events
            };
            for p in &event.paths {
                if let Ok(mut evts) = events_clone.lock() {
                    evts.push(FsEvent {
                        kind: kind.to_string(),
                        path: p.to_string_lossy().to_string(),
                    });
                }
            }
        }
    })
    .map_err(|e| format!("fs.watch: failed to create watcher: {e}"))?;

    watcher
        .watch(std::path::Path::new(&path), RecursiveMode::Recursive)
        .map_err(|e| format!("fs.watch: failed to watch path '{path}': {e}"))?;

    let id = next_watcher_id();
    WATCHERS.lock().unwrap().insert(
        id,
        WatcherEntry {
            _watcher: watcher,
            events,
        },
    );

    Ok(Value::Struct {
        name: "FsWatcher".to_string(),
        fields: vec![
            ("id".to_string(), Value::Int(id as i128)),
            ("path".to_string(), Value::String(path)),
        ],
    })
}

fn do_watch_poll(args: Vec<Value>) -> StdlibResult {
    let id = match args.first() {
        Some(Value::Int(n)) => *n as u64,
        _ => return Err("fs.watch_poll: expected watcher id (int) argument".into()),
    };

    let watchers = WATCHERS.lock().unwrap();
    let entry = match watchers.get(&id) {
        Some(e) => e,
        None => return Err(format!("fs.watch_poll: no watcher with id {id}")),
    };

    let mut events = entry.events.lock().unwrap();
    let result: Vec<Value> = events
        .drain(..)
        .map(|evt| {
            Value::Struct {
                name: "FsEvent".to_string(),
                fields: vec![
                    ("kind".to_string(), Value::String(evt.kind)),
                    ("path".to_string(), Value::String(evt.path)),
                ],
            }
        })
        .collect();

    Ok(Value::Array(result))
}

fn do_watch_stop(args: Vec<Value>) -> StdlibResult {
    let id = match args.first() {
        Some(Value::Int(n)) => *n as u64,
        _ => return Err("fs.watch_stop: expected watcher id (int) argument".into()),
    };

    let removed = WATCHERS.lock().unwrap().remove(&id);
    if removed.is_some() {
        Ok(Value::Bool(true))
    } else {
        Err(format!("fs.watch_stop: no watcher with id {id}"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fs_watch_create_stop() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_string_lossy().to_string();

        // Create watcher
        let result = do_watch(vec![Value::String(path.clone())]);
        assert!(result.is_ok(), "watch should succeed: {:?}", result);

        let watcher = result.unwrap();
        let id = match &watcher {
            Value::Struct { name, fields } => {
                assert_eq!(name, "FsWatcher");
                match &fields.iter().find(|(k, _)| k == "id").unwrap().1 {
                    Value::Int(n) => *n,
                    _ => panic!("expected Int id"),
                }
            }
            _ => panic!("expected Struct"),
        };

        // Stop watcher
        let stop = do_watch_stop(vec![Value::Int(id)]);
        assert!(stop.is_ok());
    }

    #[test]
    fn test_fs_watch_poll_events() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_string_lossy().to_string();

        // Create watcher
        let watcher = do_watch(vec![Value::String(path.clone())]).unwrap();
        let id = match &watcher {
            Value::Struct { fields, .. } => {
                match &fields.iter().find(|(k, _)| k == "id").unwrap().1 {
                    Value::Int(n) => *n,
                    _ => panic!("expected Int id"),
                }
            }
            _ => panic!("expected Struct"),
        };

        // Write a file to trigger events
        let test_file = tmp.path().join("test_event.txt");
        std::fs::write(&test_file, "hello").unwrap();

        // Give the watcher time to detect the event
        std::thread::sleep(std::time::Duration::from_millis(500));

        // Poll events
        let poll_result = do_watch_poll(vec![Value::Int(id)]);
        assert!(poll_result.is_ok(), "poll should succeed: {:?}", poll_result);

        let events = match poll_result.unwrap() {
            Value::Array(arr) => arr,
            _ => panic!("expected Array"),
        };

        // We should have at least one event (create or modify)
        assert!(
            !events.is_empty(),
            "should have at least one event after writing a file"
        );

        // Verify event structure
        for event in &events {
            match event {
                Value::Struct { name, fields } => {
                    assert_eq!(name, "FsEvent");
                    assert!(fields.iter().any(|(k, _)| k == "kind"));
                    assert!(fields.iter().any(|(k, _)| k == "path"));
                }
                _ => panic!("expected FsEvent struct"),
            }
        }

        // Cleanup
        do_watch_stop(vec![Value::Int(id)]).unwrap();
    }

    #[test]
    fn test_fs_watch_poll_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_string_lossy().to_string();

        let watcher = do_watch(vec![Value::String(path)]).unwrap();
        let id = match &watcher {
            Value::Struct { fields, .. } => {
                match &fields.iter().find(|(k, _)| k == "id").unwrap().1 {
                    Value::Int(n) => *n,
                    _ => panic!("expected Int id"),
                }
            }
            _ => panic!("expected Struct"),
        };

        // Poll immediately -- should be empty
        let poll_result = do_watch_poll(vec![Value::Int(id)]).unwrap();
        match poll_result {
            Value::Array(arr) => assert!(arr.is_empty(), "poll immediately should return empty"),
            _ => panic!("expected Array"),
        }

        do_watch_stop(vec![Value::Int(id)]).unwrap();
    }

    #[test]
    fn test_read_file_async_fallback() {
        // read_file_async falls back to sync read_file
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_string_lossy().to_string();
        std::fs::write(&path, "async fallback test").unwrap();

        let result = dispatch("read_file_async", vec![Value::String(path)]);
        assert!(result.is_some());
        let value = result.unwrap().unwrap();
        match value {
            Value::String(s) => assert_eq!(s, "async fallback test"),
            _ => panic!("expected String"),
        }
    }

    /// G-14 regression: `fs.read_bytes` must hand back a real `Bytes` value.
    /// While it returned base64 text, `provenance.hash_body(read_bytes(p))`
    /// silently produced the sha256 of the encoding at rc=0.
    #[test]
    fn test_read_bytes_returns_raw_bytes_not_base64_text() {
        const PAYLOAD: &[u8] = b"binary\x00payload\xff\xfe"; // 16 bytes, non-UTF-8
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("payload.bin");
        std::fs::write(&path, PAYLOAD).unwrap();
        let ps = path.to_string_lossy().to_string();

        let value = dispatch("read_bytes", vec![Value::String(ps)])
            .expect("read_bytes routable")
            .expect("read_bytes ok");
        match value {
            Value::Bytes(b) => assert_eq!(b, PAYLOAD, "raw bytes must survive verbatim"),
            other => panic!("expected Bytes, got {other:?}"),
        }
    }

    /// `fs.write_bytes` takes `Bytes` verbatim; the base64 `String` shape it
    /// accepted before is kept for the compiled/FFI callers.
    #[test]
    fn test_write_bytes_accepts_bytes_and_base64_string() {
        let tmp = tempfile::tempdir().unwrap();
        let raw_dst = tmp.path().join("from_bytes.bin");
        let b64_dst = tmp.path().join("from_b64.bin");
        const PAYLOAD: &[u8] = b"binary\x00payload\xff\xfe";

        dispatch(
            "write_bytes",
            vec![
                Value::String(raw_dst.to_string_lossy().to_string()),
                Value::Bytes(PAYLOAD.to_vec()),
            ],
        )
        .expect("routable")
        .expect("write from Bytes");
        assert_eq!(std::fs::read(&raw_dst).unwrap(), PAYLOAD);

        dispatch(
            "write_bytes",
            vec![
                Value::String(b64_dst.to_string_lossy().to_string()),
                Value::String("YmluYXJ5AHBheWxvYWT//g==".into()),
            ],
        )
        .expect("routable")
        .expect("write from base64 String");
        assert_eq!(std::fs::read(&b64_dst).unwrap(), PAYLOAD);

        // Junk still fails closed rather than writing a partial file.
        assert!(
            dispatch(
                "write_bytes",
                vec![
                    Value::String(tmp.path().join("nope.bin").to_string_lossy().to_string()),
                    Value::String("!!!not-base64!!!".into()),
                ],
            )
            .expect("routable")
            .is_err()
        );
    }

    /// t_0831edba: one `Bytes` representation on both engines. A `Bytes` value
    /// prints as its **base64** encoding — the form the compiled path already
    /// carries across the FFI (`tallow_fs_read_bytes` returns it,
    /// `tallow_fs_write_bytes` accepts it) — so `print(fs.read_bytes(p))` no
    /// longer depends on which engine ran the program. The value itself is
    /// still a `Bytes` (see the test above): that is what keeps
    /// `provenance.hash_body` from absorbing it.
    #[test]
    fn interp_print_read_bytes_renders_the_base64_representation() {
        const PAYLOAD: &[u8] = b"binary\x00payload\xff\xfe"; // 16 bytes, non-UTF-8
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("payload.bin");
        std::fs::write(&path, PAYLOAD).unwrap();

        let src = format!(
            "fn main() {{ let b = fs.read_bytes(\"{}\")\n print(b) }}",
            path.to_string_lossy()
        );
        let (tokens, lex_errs) = crate::lexer::tokenize(&src);
        assert!(lex_errs.is_empty(), "lex errors: {lex_errs:?}");
        let program = crate::parser::Parser::parse(tokens).expect("parse error");
        let mut interp = crate::interp::Interpreter::new();
        interp.run(&program).expect("interp run failed");
        assert_eq!(
            interp.output,
            vec!["YmluYXJ5AHBheWxvYWT//g==".to_string()],
            "a Bytes value must print as its base64 encoding, not a summary"
        );
    }
}
