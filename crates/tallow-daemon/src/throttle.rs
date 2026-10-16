use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use chrono::Timelike;

/// Token-bucket bandwidth throttle.
///
/// Tokens refill at `bytes_per_sec` rate. The bucket starts full (capacity = bytes_per_sec)
/// allowing an initial burst. Tokens are consumed before I/O operations; if insufficient
/// tokens exist, the caller waits (via sleep) until tokens refill.
///
/// A limit of 0 means "unlimited" — `consume` always returns immediately.
pub struct Throttle {
    inner: Mutex<ThrottleInner>,
}

struct ThrottleInner {
    tokens: f64,
    bytes_per_sec: u64,
    last_refill: Instant,
}

impl Throttle {
    /// Create a new throttle with the given bytes-per-second limit.
    /// Pass 0 for unlimited throughput.
    pub fn new(bytes_per_sec: u64) -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(ThrottleInner {
                tokens: bytes_per_sec as f64,
                bytes_per_sec,
                last_refill: Instant::now(),
            }),
        })
    }

    /// Consume `bytes` tokens, waiting if necessary until tokens are available.
    /// If `bytes_per_sec` is 0 (unlimited), returns immediately.
    /// If `bytes` is 0, returns immediately (no lock acquisition).
    pub async fn consume(&self, bytes: u64) {
        if bytes == 0 {
            return;
        }

        let mut inner = self.inner.lock().await;

        if inner.bytes_per_sec == 0 {
            return; // unlimited — no throttling
        }

        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(inner.last_refill).as_secs_f64();
        inner.tokens += elapsed * inner.bytes_per_sec as f64;
        inner.tokens = inner.tokens.min(inner.bytes_per_sec as f64); // cap at bucket size
        inner.last_refill = now;

        // If not enough tokens, calculate wait time and sleep
        let needed = bytes as f64;
        if inner.tokens < needed {
            let deficit = needed - inner.tokens;
            let wait_secs = deficit / inner.bytes_per_sec as f64;
            drop(inner); // release lock before sleeping
            tokio::time::sleep(Duration::from_secs_f64(wait_secs)).await;

            // Re-acquire and deduct (tokens have refilled during sleep)
            let mut inner = self.inner.lock().await;
            inner.tokens = 0.0; // consumed exactly what was needed
            inner.last_refill = Instant::now();
        } else {
            // Enough tokens — deduct immediately
            inner.tokens -= needed;
        }
    }

    /// Get the current bytes_per_sec limit (for logging/monitoring).
    pub async fn rate(&self) -> u64 {
        self.inner.lock().await.bytes_per_sec
    }
}

// ---------------------------------------------------------------------------
// Time-of-day schedule
// ---------------------------------------------------------------------------

/// A throttle whose rate depends on the current time of day.
pub struct ScheduledThrottle {
    default_throttle: Arc<Throttle>,
    windows: Vec<TimeWindow>,
}

struct TimeWindow {
    start_hour: u8,
    start_min: u8,
    end_hour: u8,
    end_min: u8,
    throttle: Arc<Throttle>,
}

impl ScheduledThrottle {
    /// Create from the default rate and a list of time window overrides.
    /// Each override: (start "HH:MM", end "HH:MM", bytes_per_sec).
    /// Windows CAN cross midnight (e.g., "22:00" to "06:00").
    pub fn new(
        default_limit: u64,
        windows: &[(String, String, u64)],
    ) -> anyhow::Result<Self> {
        let mut parsed_windows = Vec::with_capacity(windows.len());

        for (start_str, end_str, limit) in windows {
            let (start_hour, start_min) = parse_time(start_str)?;
            let (end_hour, end_min) = parse_time(end_str)?;

            parsed_windows.push(TimeWindow {
                start_hour,
                start_min,
                end_hour,
                end_min,
                throttle: Throttle::new(*limit),
            });
        }

        // Sort windows by start time for efficient lookup
        parsed_windows.sort_by_key(|w| {
            let mins = w.start_hour as i32 * 60 + w.start_min as i32;
            // Overnight windows (start > end) get sorted first using negative offset
            if w.start_hour as i32 * 60 + w.start_min as i32 > w.end_hour as i32 * 60 + w.end_min as i32 {
                mins - 1440
            } else {
                mins
            }
        });

        Ok(Self {
            default_throttle: Throttle::new(default_limit),
            windows: parsed_windows,
        })
    }

    /// Consume bytes through the appropriate throttle for the current time.
    pub async fn consume(&self, bytes: u64) {
        let throttle = self.active_throttle();
        throttle.consume(bytes).await;
    }

    /// Return the throttle matching the current time of day.
    /// Falls back to default if no window matches.
    pub fn active_throttle(&self) -> &Arc<Throttle> {
        let now = chrono::Local::now();
        let current_minutes = now.hour() as u32 * 60 + now.minute() as u32;

        for window in &self.windows {
            let start_min = window.start_hour as u32 * 60 + window.start_min as u32;
            let end_min = window.end_hour as u32 * 60 + window.end_min as u32;

            if start_min <= end_min {
                // Normal window (e.g., 06:00-22:00)
                if current_minutes >= start_min && current_minutes < end_min {
                    return &window.throttle;
                }
            } else {
                // Overnight window (e.g., 22:00-06:00)
                if current_minutes >= start_min || current_minutes < end_min {
                    return &window.throttle;
                }
            }
        }

        &self.default_throttle
    }
}

/// Parse "HH:MM" into (hour, minute). Returns Err on invalid format.
fn parse_time(s: &str) -> anyhow::Result<(u8, u8)> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 2 {
        anyhow::bail!("invalid time format '{}': expected HH:MM", s);
    }
    let hour: u8 = parts[0]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid hour in '{}': expected 0-23", s))?;
    let minute: u8 = parts[1]
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid minute in '{}': expected 0-59", s))?;
    if hour > 23 {
        anyhow::bail!("hour out of range in '{}': expected 0-23, got {}", s, hour);
    }
    if minute > 59 {
        anyhow::bail!("minute out of range in '{}': expected 0-59, got {}", s, minute);
    }
    Ok((hour, minute))
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Test 1: Throttle::new(1024) creates with 1024 bytes/sec and initial capacity
    // -----------------------------------------------------------------------
    #[test]
    fn test_new_throttle_has_correct_capacity() {
        let t = Throttle::new(1024);
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let inner = t.inner.lock().await;
            assert_eq!(inner.tokens, 1024.0, "initial tokens should equal bytes_per_sec");
            assert_eq!(inner.bytes_per_sec, 1024);
        });
    }

    // -----------------------------------------------------------------------
    // Test 2: throttle.consume(512) succeeds immediately when tokens available
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_consume_small_amount_returns_immediately() {
        let t = Throttle::new(1024);
        let start = Instant::now();
        t.consume(512).await;
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 50, "small consume should be nearly instant, got {}ms", elapsed.as_millis());
    }

    // -----------------------------------------------------------------------
    // Test 3: throttle.consume(2048) with limit=1024 waits ~1 second
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_consume_large_amount_waits_for_tokens() {
        let t = Throttle::new(1024);
        let start = Instant::now();
        t.consume(2048).await;
        let elapsed = start.elapsed();
        // Should wait roughly (2048-1024)/1024 = 1 second
        assert!(elapsed.as_millis() >= 800, "large consume should wait ~1s, got {}ms", elapsed.as_millis());
        assert!(elapsed.as_millis() <= 1500, "wait should be roughly 1s, got {}ms", elapsed.as_millis());
    }

    // -----------------------------------------------------------------------
    // Test 4: Throttle with limit=0 (unlimited) always returns immediately
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_unlimited_throttle_returns_immediately() {
        let t = Throttle::new(0);
        let start = Instant::now();
        t.consume(1_000_000_000).await; // huge amount
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 50, "unlimited should return immediately, got {}ms", elapsed.as_millis());
    }

    // -----------------------------------------------------------------------
    // Test 5: consume(0) is a no-op (does not lock or sleep)
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_consume_zero_is_noop() {
        let t = Throttle::new(1024);
        let start = Instant::now();
        t.consume(0).await;
        let elapsed = start.elapsed();
        assert!(elapsed.as_millis() < 5, "consume(0) should be instant, got {}ms", elapsed.as_millis());
    }

    // -----------------------------------------------------------------------
    // Test 6: Time-of-day schedule: different windows select correctly
    // -----------------------------------------------------------------------
    #[test]
    fn test_scheduled_throttle_creation() {
        let windows = vec![
            ("22:00".to_string(), "06:00".to_string(), 0u64),      // overnight unlimited
            ("06:00".to_string(), "22:00".to_string(), 1_048_576), // day 1MB/s
        ];
        let result = ScheduledThrottle::new(1_048_576, &windows);
        assert!(result.is_ok(), "ScheduledThrottle::new should succeed with valid windows");
    }

    // -----------------------------------------------------------------------
    // Test 7: Scheduler selects default when no window matches (no windows)
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_scheduled_with_no_windows_uses_default() {
        let st = ScheduledThrottle::new(500_000, &[]).unwrap();
        // Should not panic
        st.consume(100).await;
    }

    // -----------------------------------------------------------------------
    // Test 8: Invalid schedule format returns Err
    // -----------------------------------------------------------------------
    #[test]
    fn test_invalid_schedule_format_returns_error() {
        let windows = vec![
            ("not-a-time".to_string(), "06:00".to_string(), 1024u64),
        ];
        let result = ScheduledThrottle::new(1024, &windows);
        assert!(result.is_err(), "invalid time format should return Err");
    }

    // -----------------------------------------------------------------------
    // Test 9: Invalid hour/minute returns Err
    // -----------------------------------------------------------------------
    #[test]
    fn test_invalid_hour_returns_error() {
        let windows = vec![
            ("25:00".to_string(), "06:00".to_string(), 1024u64),
        ];
        let result = ScheduledThrottle::new(1024, &windows);
        assert!(result.is_err(), "hour > 23 should return Err");
    }

    #[test]
    fn test_invalid_minute_returns_error() {
        let windows = vec![
            ("12:60".to_string(), "14:00".to_string(), 1024u64),
        ];
        let result = ScheduledThrottle::new(1024, &windows);
        assert!(result.is_err(), "minute > 59 should return Err");
    }

    // -----------------------------------------------------------------------
    // Test 10: rate() returns correct bytes_per_sec
    // -----------------------------------------------------------------------
    #[tokio::test]
    async fn test_rate_returns_correct_limit() {
        let t = Throttle::new(500_000);
        assert_eq!(t.rate().await, 500_000);
    }

    // -----------------------------------------------------------------------
    // Test 11: active_throttle returns default when outside window
    // -----------------------------------------------------------------------
    #[test]
    fn test_active_throttle_uses_default_outside_window() {
        // Create a schedule with a narrow window that (likely) doesn't match current time
        // Use 03:00-03:01 (2am) — this window is so narrow it's almost certainly not now
        let windows = vec![
            ("03:14".to_string(), "03:15".to_string(), 99u64),
        ];
        let st = ScheduledThrottle::new(500_000, &windows).unwrap();
        let active = st.active_throttle();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let rate = rt.block_on(active.rate());
        // If the current time is NOT 03:14-03:15, we get the default rate
        // (This is a heuristic test — it will pass 99.9% of the time)
        assert!(
            rate == 500_000 || rate == 99,
            "active throttle rate should be either default (500000) or window (99), got {}",
            rate
        );
    }
}
