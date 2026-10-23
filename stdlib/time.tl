// tallow.time — Time, duration, timezone
//
// Time handling with Duration literals and timezone support.

/// Current timestamp
// native: returns current UTC timestamp
native fn now() -> Timestamp

/// Current monotonic time (for measuring elapsed)
// native: monotonic nanoseconds
native fn monotonic() -> u64

/// Sleep for duration
// native: blocks current task for duration
native fn sleep(d: Duration)

/// Timestamp (UTC, nanosecond precision)
struct Timestamp {
    nanos: u64,     // nanoseconds since Unix epoch
}

/// Duration
struct Duration {
    nanos: u64,
}

// Duration constructors (used via literals: 60.seconds, 5.minutes, etc.)
impl i64 {
    native fn nanoseconds(self) -> Duration
    native fn microseconds(self) -> Duration
    native fn milliseconds(self) -> Duration
    native fn seconds(self) -> Duration
    native fn minutes(self) -> Duration
    native fn hours(self) -> Duration
    native fn days(self) -> Duration
}

impl Timestamp {
    /// Format timestamp as ISO 8601 string
    // native: "2026-03-01T14:23:11Z"
    native fn to_iso(self) -> String

    /// Format with custom pattern
    // native: formats using strftime-like pattern
    native fn format(self, pattern: String) -> String

    /// Unix timestamp in seconds
    fn unix(self) -> i64 {
        self.nanos / 1_000_000_000
    }

    /// Unix timestamp in milliseconds
    fn unix_ms(self) -> i64 {
        self.nanos / 1_000_000
    }

    /// Add duration
    fn add(self, d: Duration) -> Timestamp {
        Timestamp { nanos: self.nanos + d.nanos }
    }

    /// Subtract duration
    fn sub(self, d: Duration) -> Timestamp {
        Timestamp { nanos: self.nanos - d.nanos }
    }

    /// Duration since another timestamp
    fn since(self, other: Timestamp) -> Duration {
        Duration { nanos: self.nanos - other.nanos }
    }
}

impl Duration {
    fn as_seconds(self) -> f64 {
        self.nanos / 1_000_000_000.0
    }

    fn as_millis(self) -> f64 {
        self.nanos / 1_000_000.0
    }
}

/// Parse ISO 8601 string
// native: parses ISO 8601 timestamp
native fn parse_iso(s: String) -> Result<Timestamp>

/// Measure execution time of a block
fn measure<T>(f: fn() -> T) -> (T, Duration) {
    let start = monotonic()
    let result = f()
    let elapsed = Duration { nanos: monotonic() - start }
    (result, elapsed)
}
