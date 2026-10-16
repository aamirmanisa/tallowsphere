// tallow.log — Structured logging (privacy-aware)
//
// All private types are automatically redacted in log output.
// Secret types cannot appear in logs at all (compile error).

/// Log levels
enum Level {
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

/// Log a debug message
fn debug(msg: String) {
    // native: logs at DEBUG level
    // private types in msg auto-redacted
}

/// Log an info message
fn info(msg: String) {
    // native: logs at INFO level
}

/// Log a warning
fn warn(msg: String) {
    // native: logs at WARN level
}

/// Log an error
fn error(msg: String) {
    // native: logs at ERROR level
}

/// Log fatal error and exit
fn fatal(msg: String) {
    // native: logs at FATAL level, then exits process
}

/// Structured log entry
fn info(msg: String, fields: Map<String, Value>) {
    // native: structured logging with key-value pairs
    // Output format: {"level":"info","msg":"...","key":"value","ts":"..."}
}

fn debug(msg: String, fields: Map<String, Value>) {
    // native: structured debug log
}

fn warn(msg: String, fields: Map<String, Value>) {
    // native: structured warning log
}

fn error(msg: String, fields: Map<String, Value>) {
    // native: structured error log
}

/// Set minimum log level
fn set_level(level: Level) {
    // native: sets global minimum log level
}

/// Set log output format
enum Format {
    Text,      // human-readable
    Json,      // structured JSON
    Compact,   // minimal text
}

fn set_format(format: Format) {
    // native: sets output format
}

/// Set log output destination
fn set_output(path: String) {
    // native: redirects log output to file
}
