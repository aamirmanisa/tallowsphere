//! Transfer progress tracking

use std::time::{Duration, Instant};

/// Transfer progress information
#[derive(Debug, Clone)]
pub struct TransferProgress {
    /// Bytes transferred
    pub bytes_transferred: u64,
    /// Total bytes
    pub total_bytes: u64,
    /// Current speed in bytes/second
    pub speed_bps: u64,
    /// Estimated time remaining in seconds
    pub eta_seconds: u64,
    /// Transfer start time
    start_time: Instant,
}

impl TransferProgress {
    /// Create new progress tracker
    pub fn new(total_bytes: u64) -> Self {
        Self {
            bytes_transferred: 0,
            total_bytes,
            speed_bps: 0,
            eta_seconds: 0,
            start_time: Instant::now(),
        }
    }

    /// Update progress
    pub fn update(&mut self, bytes_transferred: u64) {
        self.bytes_transferred = bytes_transferred;
        let elapsed = self.start_time.elapsed();

        if elapsed.as_secs() > 0 {
            self.speed_bps = bytes_transferred / elapsed.as_secs();

            let remaining = self.total_bytes.saturating_sub(bytes_transferred);
            if let Some(eta) = remaining.checked_div(self.speed_bps) {
                self.eta_seconds = eta;
            }
        }
    }

    /// Get completion percentage
    pub fn percentage(&self) -> f64 {
        if self.total_bytes == 0 {
            return 0.0;
        }
        (self.bytes_transferred as f64 / self.total_bytes as f64) * 100.0
    }

    /// Get elapsed time
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }
}
