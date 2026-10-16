//! Traffic analysis resistance
//!
//! Provides padding and constant-rate shaping to make it harder
//! for a network observer to determine transfer sizes and timing.

use tokio::time::{sleep, Duration, Instant};

/// Traffic shaper for resisting traffic analysis
#[derive(Debug)]
pub struct TrafficShaper {
    /// Target constant rate in bytes/sec
    target_rate: u64,
    /// Standard packet size for padding
    packet_size: usize,
    /// Bytes sent in current window
    window_bytes: u64,
    /// Window start time
    window_start: Instant,
}

impl TrafficShaper {
    /// Create a new traffic shaper
    ///
    /// `target_rate` is in bytes/sec (must be > 0). Packets will be padded to `packet_size`.
    pub fn new(target_rate: u64) -> Self {
        Self {
            target_rate: target_rate.max(1), // Prevent division by zero
            packet_size: 1024,
            window_bytes: 0,
            window_start: Instant::now(),
        }
    }

    /// Create with custom packet size
    pub fn with_packet_size(mut self, size: usize) -> Self {
        self.packet_size = size;
        self
    }

    /// Shape traffic to constant rate
    ///
    /// Delays sending if we're ahead of the target rate.
    /// Returns the padded data ready to send.
    pub async fn shape(&mut self, data: &[u8]) -> Vec<u8> {
        let padded = self.pad_packet(data, self.packet_size);

        // Calculate how long we should have taken to send window_bytes at target_rate
        let elapsed = self.window_start.elapsed();
        let expected_duration =
            Duration::from_secs_f64(self.window_bytes as f64 / self.target_rate as f64);

        if expected_duration > elapsed {
            sleep(expected_duration - elapsed).await;
        }

        self.window_bytes += padded.len() as u64;

        // Reset window every 10 seconds to avoid drift
        if elapsed > Duration::from_secs(10) {
            self.window_bytes = 0;
            self.window_start = Instant::now();
        }

        padded
    }

    /// Pad packet to fixed size
    ///
    /// Pads with random bytes to prevent length-based analysis.
    /// The first 4 bytes encode the real data length.
    pub fn pad_packet(&self, data: &[u8], target_size: usize) -> Vec<u8> {
        let real_size = target_size.max(data.len() + 4);
        let mut padded = Vec::with_capacity(real_size);

        // Encode real data length as 4-byte big-endian
        let len = data.len() as u32;
        padded.extend_from_slice(&len.to_be_bytes());
        padded.extend_from_slice(data);

        // Pad with random bytes
        if padded.len() < real_size {
            let padding: Vec<u8> = (0..real_size - padded.len())
                .map(|_| rand::random())
                .collect();
            padded.extend_from_slice(&padding);
        }

        padded
    }

    /// Unpad a packet to recover the original data
    pub fn unpad_packet(data: &[u8]) -> Option<Vec<u8>> {
        if data.len() < 4 {
            return None;
        }

        let real_len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
        if data.len() < 4 + real_len {
            return None;
        }

        Some(data[4..4 + real_len].to_vec())
    }

    /// Generate a dummy (cover traffic) packet
    ///
    /// Used to send noise when no real data is being transferred,
    /// making it impossible to distinguish idle from active.
    pub fn dummy_packet(&self) -> Vec<u8> {
        self.pad_packet(&[], self.packet_size)
    }

    /// Get current target rate
    pub fn target_rate(&self) -> u64 {
        self.target_rate
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pad_unpad_roundtrip() {
        let shaper = TrafficShaper::new(1024);
        let data = b"hello world";
        let padded = shaper.pad_packet(data, 256);
        assert_eq!(padded.len(), 256);
        let recovered = TrafficShaper::unpad_packet(&padded).unwrap();
        assert_eq!(&recovered, data);
    }

    #[test]
    fn test_dummy_packet() {
        let shaper = TrafficShaper::new(1024);
        let dummy = shaper.dummy_packet();
        assert_eq!(dummy.len(), 1024);
        let recovered = TrafficShaper::unpad_packet(&dummy).unwrap();
        assert!(recovered.is_empty());
    }

    #[test]
    fn test_data_larger_than_target() {
        let shaper = TrafficShaper::new(1024);
        let data = vec![0xAB; 2000];
        let padded = shaper.pad_packet(&data, 256);
        // Should be at least data.len() + 4
        assert!(padded.len() >= 2004);
        let recovered = TrafficShaper::unpad_packet(&padded).unwrap();
        assert_eq!(recovered, data);
    }
}
