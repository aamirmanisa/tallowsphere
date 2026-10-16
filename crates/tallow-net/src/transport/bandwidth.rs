//! Bandwidth limiting and traffic shaping
//!
//! Implements a simple token-bucket rate limiter that sleeps when the
//! send rate exceeds the configured maximum bytes per second.

use std::time::Duration;

/// Bandwidth limiter for rate control (token-bucket algorithm)
#[derive(Debug)]
pub struct BandwidthLimiter {
    /// Maximum bytes per second
    max_bps: u64,
    /// Current window start
    window_start: std::time::Instant,
    /// Bytes sent in current window
    bytes_sent: u64,
}

impl BandwidthLimiter {
    /// Create a new bandwidth limiter
    pub fn new(max_bps: u64) -> Self {
        Self {
            max_bps,
            window_start: std::time::Instant::now(),
            bytes_sent: 0,
        }
    }

    /// Wait if necessary to respect rate limit.
    ///
    /// Uses a sliding window: if the bytes sent in the current window exceed
    /// the rate limit, sleep until enough time has passed to stay within budget.
    /// Returns the duration slept, or `Duration::ZERO` if no wait was needed.
    pub async fn wait_if_needed(&mut self, bytes: usize) -> Duration {
        if self.max_bps == 0 {
            return Duration::ZERO;
        }

        self.bytes_sent += bytes as u64;

        let elapsed = self.window_start.elapsed();

        // Reset window after 1 second to avoid accumulated drift
        if elapsed >= Duration::from_secs(1) {
            self.window_start = std::time::Instant::now();
            self.bytes_sent = bytes as u64;
            return Duration::ZERO;
        }

        // Only sleep if we've exceeded the rate for the elapsed window
        if self.bytes_sent > self.max_bps {
            // We need to wait until enough time passes for the bytes to be "allowed"
            let needed_secs = self.bytes_sent as f64 / self.max_bps as f64;
            let needed = Duration::from_secs_f64(needed_secs);
            if needed > elapsed {
                let sleep_duration = needed - elapsed;
                tokio::time::sleep(sleep_duration).await;
                return sleep_duration;
            }
        }

        Duration::ZERO
    }

    /// Get current throughput estimate in bytes per second
    pub fn current_throughput(&self) -> u64 {
        let elapsed = self.window_start.elapsed();
        if elapsed.as_millis() == 0 {
            return 0;
        }
        (self.bytes_sent as f64 / elapsed.as_secs_f64()) as u64
    }

    /// Reset the rate limiter window
    pub fn reset(&mut self) {
        self.window_start = std::time::Instant::now();
        self.bytes_sent = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_unlimited_bandwidth() {
        let mut limiter = BandwidthLimiter::new(0);
        let waited = limiter.wait_if_needed(1024).await;
        assert_eq!(waited, Duration::ZERO);
    }

    #[tokio::test]
    async fn test_bandwidth_no_wait_under_limit() {
        let mut limiter = BandwidthLimiter::new(1_000_000); // 1 MB/s
        let waited = limiter.wait_if_needed(100).await; // 100 bytes
        assert_eq!(waited, Duration::ZERO);
    }

    #[test]
    fn test_current_throughput_initial() {
        let limiter = BandwidthLimiter::new(1_000_000);
        assert_eq!(limiter.current_throughput(), 0);
    }

    #[test]
    fn test_reset() {
        let mut limiter = BandwidthLimiter::new(1_000_000);
        limiter.bytes_sent = 5000;
        limiter.reset();
        assert_eq!(limiter.bytes_sent, 0);
    }
}
