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
// native: logs at DEBUG level
// private types in msg auto-redacted
native fn debug(msg: String)

/// Log an info message
// native: logs at INFO level
native fn info(msg: String)

/// Log a warning
// native: logs at WARN level
native fn warn(msg: String)

/// Log an error
// native: logs at ERROR level
native fn error(msg: String)

/// Log fatal error and exit
// native: logs at FATAL level, then exits process
native fn fatal(msg: String)

/// Structured log entry
// native: structured logging with key-value pairs
// Output format: "level":"info","msg":"...","key":"value","ts":"..."
native fn info(msg: String, fields: Map<String, Value>)

// native: structured debug log
native fn debug(msg: String, fields: Map<String, Value>)

// native: structured warning log
native fn warn(msg: String, fields: Map<String, Value>)

// native: structured error log
native fn error(msg: String, fields: Map<String, Value>)

/// Emit one structured record
// native: json merges the fields at the top level, with "msg" taken from
// native: fields["msg"] or ""; text renders [LEVEL] [ts] [trace] k=v in insertion order.
// native: a field named level/ts/trace is refused (the logger owns those keys);
// native: Private/Secret values render [REDACTED]/[SECRET]; a nested
// native: Array/Map/Struct value is refused by name rather than stringified.
native fn record(level: Level, fields: Map<String, Value>)

/// Set the process-wide trace id
// native: the id must be at most 64 characters; nil clears it.
// native: process-wide, not task-local (task-scope propagation needs G46).
native fn set_trace(id: String?)

/// Read the process-wide trace id
// native: returns the trace id, or nil when unset
native fn trace() -> String?

/// Set minimum log level
// native: sets global minimum log level
native fn set_level(level: Level)

/// Set log output format
enum Format {
    Text,      // human-readable
    Json,      // structured JSON
    Compact,   // minimal text
}

// native: sets output format
native fn set_format(format: Format)

/// Set log output destination
// native: redirects log output to file
native fn set_output(path: String)
