//! Root-crate logging standard (T-127 / R-6.3): tracing → redaction → JSONL.
//!
//! One entry point, [`init_logging`], installs a process-wide `tracing`
//! subscriber built from three pieces (and nothing else):
//!
//! 1. [`EnvFilter`] — `RUST_LOG` is honoured; when unset or unparseable the
//!    level falls back to [`DEFAULT_LEVEL`] (`info`).
//! 2. A redaction layer ([`RedactionLayer`]) that scrubs secret-looking field
//!    values **before** any sink sees the event — the same choke-point
//!    discipline as [`crate::observability`] and [`crate::redaction`]: raw
//!    values are replaced by [`REDACTED`], never merely hidden in a view.
//! 3. A JSON-lines file sink at `~/.tallow/tallow.log.jsonl` (dir `0700`,
//!    file `0600`, `O_APPEND`), with size-based rotation: once the file
//!    reaches [`ROTATE_MAX_BYTES`] it is renamed to `<name>.1` and a fresh
//!    file is opened.
//!
//! `~/.tallow` is deliberately the same private directory the security-event
//! journal uses ([`crate::observability`]); one private dir, one permission
//! story. The log directory can be overridden with `TALLOW_LOG_DIR` (used by
//! tests; not part of the CLI contract).
//!
//! Because the only sink in the stack is the redacting one, there is no
//! unredacted output path by construction (no console layer is installed
//! here). Failure policy mirrors the ops plane: logging must never take the
//! process down — a sink error is reported on stderr and dropped.
//!
//! Dependencies: only `tracing` + `tracing-subscriber` (versions pinned to
//! the ones already in `Cargo.lock`: 0.1.44 / 0.3.23).
//!
//! Wiring (owned by the parent — recorded in
//! `research/tallow-security-2026-09-12/phase13-implementation/impl/T-127.md`):
//! `pub mod logging;` in `src/lib.rs` and a `tallow::logging::init_logging()`
//! call at the top of `fn main` in `src/main.rs`.

use std::env;
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use tracing::field::{Field, Visit};
use tracing::{Event, Subscriber};
use tracing_subscriber::layer::{Context, Layer, SubscriberExt};
use tracing_subscriber::registry::LookupSpan;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

// ── Constants ────────────────────────────────────────────────────────────────

/// Default level when `RUST_LOG` is unset or unparseable.
pub const DEFAULT_LEVEL: &str = "info";

/// File name of the JSONL sink inside the log directory.
pub const LOG_FILE_NAME: &str = "tallow.log.jsonl";

/// Environment override for the log directory (default `~/.tallow`).
pub const LOG_DIR_ENV: &str = "TALLOW_LOG_DIR";

/// Rotate once the sink reaches this many bytes (5 MiB). One backup kept
/// (`tallow.log.jsonl.1`); dependency-free by design.
pub const ROTATE_MAX_BYTES: u64 = 5 * 1024 * 1024;

/// What a secret-looking field value is replaced with.
pub const REDACTED: &str = "[REDACTED]";

/// Substring patterns that mark a field name as secret-bearing. Matching is
/// case-insensitive and ignores `_`/`-` separators (`API-KEY`, `api_key`,
/// `apiKey` all match). Mirrors the "redact before the sink sees it"
/// convention of [`crate::observability`]; over-redaction is deliberate
/// (e.g. `input_tokens` matches `token`) — never leak to under-cover.
pub const SECRET_PATTERNS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "credential",
    "private_key",
    "access_key",
    "authorization",
    "cookie",
];

// ── Redaction policy ─────────────────────────────────────────────────────────

/// Field-name redaction policy for the logging sink.
#[derive(Debug, Clone)]
pub struct Redactor {
    patterns: Vec<&'static str>,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::standard()
    }
}

impl Redactor {
    /// The standard policy ([`SECRET_PATTERNS`]).
    pub fn standard() -> Self {
        Redactor {
            patterns: SECRET_PATTERNS.to_vec(),
        }
    }

    /// Lowercase and treat `-` like `_` so `API-KEY` and `api_key` normalize
    /// the same way.
    fn normalize(name: &str) -> String {
        name.to_ascii_lowercase().replace('-', "_")
    }

    /// Does `field_name` look secret-bearing?
    pub fn is_secret(&self, field_name: &str) -> bool {
        let name = Self::normalize(field_name);
        // Separator-stripped view: `api_key` ↔ `apikey` ↔ `apiKey`.
        let compact: String = name.chars().filter(|c| *c != '_').collect();
        self.patterns.iter().any(|pat| {
            let compact_pat: String = pat.chars().filter(|c| *c != '_').collect();
            name.contains(pat) || compact.contains(&compact_pat)
        })
    }

    /// Scrub one field capture. Non-secret names pass through unchanged.
    pub fn scrub(&self, field_name: &str, value: &str) -> String {
        if self.is_secret(field_name) {
            REDACTED.to_string()
        } else {
            value.to_string()
        }
    }

    /// Best-effort scrub of `key=value` pairs inside a free-form message.
    /// `tracing` messages arrive preformatted, so only this convention can be
    /// covered honestly; the mitigation for anything else is the field-name
    /// policy above plus `crate::observability` for security signals.
    pub fn scrub_message(&self, message: &str) -> String {
        let mut out = String::with_capacity(message.len());
        for (i, token) in message.split(' ').enumerate() {
            if i > 0 {
                out.push(' ');
            }
            match token.split_once('=') {
                Some((key, _)) if !key.is_empty() && self.is_secret(key) => {
                    out.push_str(key);
                    out.push('=');
                    out.push_str(REDACTED);
                }
                _ => out.push_str(token),
            }
        }
        out
    }
}

// ── JSONL rendering ──────────────────────────────────────────────────────────

/// Minimal JSON string escaping — no serde dependency on this path.
fn json_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len() + 8);
    for ch in input.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

/// Render one event as a JSON line. Field values (and `key=value` pairs in
/// the message) are scrubbed by `redactor` **before** serialization.
fn format_jsonl(
    ts_ms: u128,
    level: &str,
    target: &str,
    message: &str,
    fields: &[(String, String)],
    redactor: &Redactor,
) -> String {
    let mut line = String::with_capacity(160 + message.len());
    line.push_str("{\"ts_unix_ms\":");
    line.push_str(&ts_ms.to_string());
    line.push_str(",\"level\":\"");
    line.push_str(&json_escape(level));
    line.push_str("\",\"target\":\"");
    line.push_str(&json_escape(target));
    line.push_str("\",\"message\":\"");
    line.push_str(&json_escape(&redactor.scrub_message(message)));
    line.push_str("\",\"fields\":{");
    for (i, (name, value)) in fields.iter().enumerate() {
        if i > 0 {
            line.push(',');
        }
        line.push('"');
        line.push_str(&json_escape(name));
        line.push_str("\":\"");
        line.push_str(&json_escape(&redactor.scrub(name, value)));
        line.push('"');
    }
    line.push_str("}}\n");
    line
}

/// Visitor that flattens a `tracing` event into (message, named fields).
#[derive(Default)]
struct FieldGather {
    message: Option<String>,
    fields: Vec<(String, String)>,
}

impl FieldGather {
    fn push(&mut self, field: &Field, value: String) {
        if field.name() == "message" {
            self.message = Some(value);
        } else {
            self.fields.push((field.name().to_string(), value));
        }
    }
}

impl Visit for FieldGather {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        self.push(field, format!("{value:?}"));
    }
    fn record_str(&mut self, field: &Field, value: &str) {
        self.push(field, value.to_string());
    }
    fn record_i64(&mut self, field: &Field, value: i64) {
        self.push(field, value.to_string());
    }
    fn record_u64(&mut self, field: &Field, value: u64) {
        self.push(field, value.to_string());
    }
    fn record_bool(&mut self, field: &Field, value: bool) {
        self.push(field, value.to_string());
    }
    fn record_f64(&mut self, field: &Field, value: f64) {
        self.push(field, value.to_string());
    }
}

// ── Paths ────────────────────────────────────────────────────────────────────

/// Log directory: `$TALLOW_LOG_DIR` when set and non-empty, else `~/.tallow`
/// (same private dir as the security-event journal).
pub fn log_dir() -> PathBuf {
    match env::var_os(LOG_DIR_ENV) {
        Some(dir) if !dir.is_empty() => PathBuf::from(dir),
        _ => dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".tallow"),
    }
}

/// Full path of the JSONL sink: [`log_dir`] + [`LOG_FILE_NAME`].
pub fn log_file_path() -> PathBuf {
    log_dir().join(LOG_FILE_NAME)
}

/// `<name>.1` — the single rotation target of `path`.
fn rotated_path(path: &Path) -> PathBuf {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| LOG_FILE_NAME.to_string());
    path.with_file_name(format!("{name}.1"))
}

fn now_unix_ms() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or_default()
}

// ── Private file mechanics ───────────────────────────────────────────────────

/// Create the sink directory, `0700` on unix (created dirs only; an existing
/// dir is left as-is — matching `crate::observability`'s best-effort stance).
#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

/// Open the sink for append, `0600`, creating it if needed. The mode is also
/// enforced on pre-existing files that were created with looser umask perms.
#[cfg(unix)]
fn open_private_append(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    let file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    if file.metadata()?.permissions().mode() & 0o777 != 0o600 {
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(file)
}

#[cfg(not(unix))]
fn open_private_append(path: &Path) -> io::Result<File> {
    OpenOptions::new().create(true).append(true).open(path)
}

/// Size/permission/rotation mechanics of the JSONL file, kept separate from
/// the `Layer` plumbing so tests can exercise it directly (temp-dir override,
/// 0600 assertion, rotation with a small budget).
struct JsonlSink {
    path: PathBuf,
    max_bytes: u64,
    state: Mutex<SinkState>,
}

#[derive(Default)]
struct SinkState {
    file: Option<File>,
    written: u64,
}

impl JsonlSink {
    fn new(path: PathBuf, max_bytes: u64) -> Self {
        JsonlSink {
            path,
            max_bytes,
            state: Mutex::new(SinkState::default()),
        }
    }

    fn path(&self) -> &Path {
        &self.path
    }

    /// Create the private dir and open (0600) the log file eagerly, so a dir
    /// or permission problem surfaces at init, not on the first log line.
    fn prepare(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        self.open_locked(&mut state)
    }

    fn open_locked(&self, state: &mut SinkState) -> io::Result<()> {
        if let Some(parent) = self.path.parent() {
            create_private_dir(parent)?;
        }
        let file = open_private_append(&self.path)?;
        state.written = file.metadata().map(|m| m.len()).unwrap_or(0);
        state.file = Some(file);
        Ok(())
    }

    /// Append one preformatted JSON line; rotate first when already over the
    /// byte budget.
    fn write_line(&self, line: &str) -> io::Result<()> {
        let mut state = self.state.lock().unwrap_or_else(|p| p.into_inner());
        if state.file.is_none() {
            self.open_locked(&mut state)?;
        }
        if state.written > 0 && state.written >= self.max_bytes {
            self.rotate_locked(&mut state)?;
        }
        let file = state
            .file
            .as_mut()
            .ok_or_else(|| io::Error::other("log file not open"))?;
        file.write_all(line.as_bytes())?;
        file.flush()?;
        state.written += line.len() as u64;
        Ok(())
    }

    /// Close → rename current file to `<name>.1` (replacing any previous
    /// backup) → open a fresh 0600 file.
    fn rotate_locked(&self, state: &mut SinkState) -> io::Result<()> {
        state.file = None; // close before rename
        let rotated = rotated_path(&self.path);
        if rotated.exists() {
            fs::remove_file(&rotated)?;
        }
        fs::rename(&self.path, &rotated)?;
        self.open_locked(state)
    }
}

// ── Layer + init ─────────────────────────────────────────────────────────────

/// Redaction + JSONL file sink as one `tracing` layer: every event is
/// scrubbed, serialized to one JSON line, and appended to the `0600` sink
/// (rotating at `max_bytes` to `<file>.1`). Write failures degrade to a
/// stderr note; logging never fails the process (ops-plane fail-open).
pub struct RedactionLayer {
    sink: JsonlSink,
    redactor: Redactor,
}

impl RedactionLayer {
    /// Layer writing to `path` with the default rotation budget.
    pub fn new(path: PathBuf) -> Self {
        Self::with_max_bytes(path, ROTATE_MAX_BYTES)
    }

    /// As [`RedactionLayer::new`], with an explicit rotation budget (tests).
    pub fn with_max_bytes(path: PathBuf, max_bytes: u64) -> Self {
        RedactionLayer {
            sink: JsonlSink::new(path, max_bytes),
            redactor: Redactor::standard(),
        }
    }

    /// Create the sink dir/file (0600) eagerly; see [`JsonlSink::prepare`].
    pub fn prepare(&self) -> io::Result<()> {
        self.sink.prepare()
    }

    /// Sink path (reporting/tests).
    pub fn path(&self) -> &Path {
        self.sink.path()
    }
}

impl<S> Layer<S> for RedactionLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let meta = event.metadata();
        let mut gather = FieldGather::default();
        event.record(&mut gather);
        let message = gather.message.unwrap_or_default();
        let line = format_jsonl(
            now_unix_ms(),
            meta.level().as_str(),
            meta.target(),
            &message,
            &gather.fields,
            &self.redactor,
        );
        if let Err(err) = self.sink.write_line(&line) {
            eprintln!("tallow: log sink {}: {err}", self.sink.path().display());
        }
    }
}

/// Install the process-wide logging stack (call once, early in `main`).
///
/// Returns an error only if the sink could not be prepared (directory/file
/// creation); an already-installed global subscriber is deliberately not an
/// error — the existing subscriber is kept.
pub fn init_logging() -> io::Result<()> {
    let layer = RedactionLayer::new(log_file_path());
    layer.prepare()?;

    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(DEFAULT_LEVEL));

    let _ = tracing_subscriber::registry()
        .with(filter)
        .with(layer)
        .try_init();
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(tag: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("tallow-logging-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    /// Secret-looking field names scrub to `[REDACTED]`; benign values pass
    /// through; the rendered JSONL line never contains the raw secret
    /// (neither in a field value nor as a message `key=value` pair).
    #[test]
    fn redaction_filter_scrubs_secret_fields() {
        let redactor = Redactor::standard();

        assert!(redactor.is_secret("api_key"));
        assert!(redactor.is_secret("API-KEY"));
        assert!(redactor.is_secret("db_password"));
        assert!(redactor.is_secret("authorization"));
        assert!(!redactor.is_secret("message"));
        assert!(!redactor.is_secret("path"));

        assert_eq!(redactor.scrub("token", "s3cr3t"), REDACTED);
        assert_eq!(redactor.scrub("path", "/tmp/x"), "/tmp/x");

        let fields = vec![
            ("api_key".to_string(), "s3cr3t".to_string()),
            ("path".to_string(), "/tmp/x".to_string()),
        ];
        let line = format_jsonl(
            42,
            "INFO",
            "tallow::t127",
            "connect attempt api_key=s3cr3t path=/tmp/x",
            &fields,
            &redactor,
        );
        assert!(line.starts_with("{\"ts_unix_ms\":42,\"level\":\"INFO\""), "line: {line}");
        assert!(line.contains(REDACTED), "line: {line}");
        assert!(!line.contains("s3cr3t"), "raw secret leaked: {line}");
        assert!(line.contains("/tmp/x"), "benign value must survive: {line}");
        assert!(line.ends_with("}\n"), "line must be JSONL-terminated: {line}");
    }

    /// `TALLOW_LOG_DIR` (temp-dir override) drives the sink path; the file is
    /// created `0600` and receives the appended line.
    #[test]
    fn sink_path_override_and_0600() {
        // T-128: serialize env mutation on the one process-global env lock.
        let _guard = crate::runtime::egress_http::env_lock();
        let dir = scratch_dir("sink");
        // SAFETY (Rust 2024: env mutation is unsafe): this test is the only
        // reader/writer of TALLOW_LOG_DIR in this module; it restores the
        // environment before returning.
        unsafe { env::set_var(LOG_DIR_ENV, &dir) };
        let path = log_file_path();
        assert_eq!(path, dir.join(LOG_FILE_NAME));

        let layer = RedactionLayer::new(path.clone());
        layer.prepare().expect("prepare sink");
        assert!(path.exists(), "sink file must exist after prepare");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "sink must be 0600");
        }

        layer
            .sink
            .write_line("{\"message\":\"hello\"}\n")
            .expect("append line");
        let body = fs::read_to_string(&path).unwrap();
        assert!(body.contains("hello"), "appended line missing: {body}");

        unsafe { env::remove_var(LOG_DIR_ENV) };
        let _ = fs::remove_dir_all(&dir);
    }

    /// Past the byte budget the current file becomes `<file>.1` and a fresh
    /// file starts (old lines never carry over).
    #[test]
    fn sink_rotates_to_dot_one() {
        let dir = scratch_dir("rotate");
        let path = dir.join(LOG_FILE_NAME);
        let layer = RedactionLayer::with_max_bytes(path.clone(), 16);

        layer.sink.write_line("0123456789\n").unwrap(); // 11 bytes
        layer.sink.write_line("0123456789\n").unwrap(); // 22 bytes → over budget
        layer.sink.write_line("abcdefghij\n").unwrap(); // rotates, then writes

        let rotated = rotated_path(&path);
        assert!(rotated.exists(), "rotation target missing");
        assert!(
            fs::read_to_string(&rotated).unwrap().contains("0123456789"),
            "backup must keep the pre-rotation lines"
        );
        let fresh = fs::read_to_string(&path).unwrap();
        assert!(fresh.contains("abcdefghij"), "fresh file must carry the new line");
        assert!(
            !fresh.contains("0123456789"),
            "fresh file must not carry rotated lines: {fresh}"
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
