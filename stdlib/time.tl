// tallow.time — Time, duration, timezone
//
// Time handling with Duration literals and timezone support.

/// Current timestamp
fn now() -> Timestamp {
    // native: returns current UTC timestamp
}

/// Current monotonic time (for measuring elapsed)
fn monotonic() -> u64 {
    // native: monotonic nanoseconds
}

/// Sleep for duration
fn sleep(d: Duration) {
    // native: blocks current task for duration
}

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
    fn nanoseconds(self) -> Duration  { Duration { nanos: self } }
    fn microseconds(self) -> Duration { Duration { nanos: self * 1_000 } }
    fn milliseconds(self) -> Duration { Duration { nanos: self * 1_000_000 } }
    fn seconds(self) -> Duration      { Duration { nanos: self * 1_000_000_000 } }
    fn minutes(self) -> Duration      { Duration { nanos: self * 60_000_000_000 } }
    fn hours(self) -> Duration        { Duration { nanos: self * 3_600_000_000_000 } }
    fn days(self) -> Duration         { Duration { nanos: self * 86_400_000_000_000 } }
}

impl Timestamp {
    /// Format timestamp as ISO 8601 string
    fn to_iso(self) -> String {
        // native: "2026-03-01T14:23:11Z"
    }

    /// Format with custom pattern
    fn format(self, pattern: String) -> String {
        // native: formats using strftime-like pattern
    }

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
fn parse_iso(s: String) -> Result<Timestamp> {
    // native: parses ISO 8601 timestamp
}

/// Measure execution time of a block
fn measure<T>(f: fn() -> T) -> (T, Duration) {
    let start = monotonic()
    let result = f()
    let elapsed = Duration { nanos: monotonic() - start }
    (result, elapsed)
}
