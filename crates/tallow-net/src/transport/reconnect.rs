//! Auto-reconnect with exponential backoff for transient network failures
//!
//! Provides [`ReconnectConfig`] for configuring retry behavior and free functions
//! [`send_with_retry`] and [`receive_with_retry`] that wrap `PeerChannel` operations
//! with automatic retry on transient I/O errors (connection reset, timeout, etc.).
//!
//! # Design
//!
//! Rather than wrapping `PeerChannel` in a new struct (which is complex due to
//! `&mut self` async methods), this module exposes free functions that accept
//! `&mut impl PeerChannel` alongside a `ReconnectConfig`. This keeps the retry
//! logic decoupled from the transport layer.

use crate::transport::PeerChannel;
use crate::NetworkError;
use std::time::Duration;
use tracing::warn;

/// Configuration for auto-reconnect behavior with exponential backoff.
///
/// Defaults:
/// - `max_retries`: 5
/// - `initial_backoff`: 1 second
/// - `max_backoff`: 30 seconds
/// - `jitter_factor`: 0.1 (10% of backoff duration)
#[derive(Debug, Clone)]
pub struct ReconnectConfig {
    /// Maximum reconnection attempts (0 to disable retries)
    pub max_retries: u32,
    /// Initial backoff duration before the first retry
    pub initial_backoff: Duration,
    /// Maximum backoff cap — backoff will never exceed this
    pub max_backoff: Duration,
    /// Jitter factor in range 0.0..1.0, added to backoff to avoid thundering herd
    pub jitter_factor: f64,
}

impl Default for ReconnectConfig {
    fn default() -> Self {
        Self {
            max_retries: 5,
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            jitter_factor: 0.1,
        }
    }
}

impl ReconnectConfig {
    /// Create a config, clamping `jitter_factor` to `[0.0, 1.0]` and
    /// ensuring `max_backoff >= initial_backoff`.
    pub fn new(max_retries: u32, initial: Duration, max: Duration, jitter: f64) -> Self {
        Self {
            max_retries,
            initial_backoff: initial,
            max_backoff: if max < initial { initial } else { max },
            jitter_factor: jitter.clamp(0.0, 1.0),
        }
    }

    /// Calculate the backoff duration for a given attempt number (0-indexed).
    ///
    /// Uses exponential backoff: `initial_backoff * 2^attempt`, capped at `max_backoff`.
    /// Deterministic jitter is added based on the attempt number to avoid
    /// thundering herd while remaining testable (no RNG).
    ///
    /// NOTE: Jitter is deterministic (based on attempt number) for testability.
    /// For true thundering-herd avoidance across multiple independent clients,
    /// a randomized jitter source would be needed.
    pub fn backoff_for_attempt(&self, attempt: u32) -> Duration {
        let base = self.initial_backoff.as_millis() as u64;
        let exponential = base.saturating_mul(2_u64.saturating_pow(attempt));
        let capped = exponential.min(self.max_backoff.as_millis() as u64);

        // Add deterministic jitter based on attempt number
        let jitter_range = (capped as f64 * self.jitter_factor.clamp(0.0, 1.0)) as u64;
        let jitter = if jitter_range > 0 {
            // Simple deterministic jitter using attempt number as seed
            (attempt as u64 * 7 + 13) % (jitter_range + 1)
        } else {
            0
        };

        Duration::from_millis(capped.saturating_add(jitter))
    }

    /// Check whether a [`NetworkError`] is transient (worth retrying).
    ///
    /// Transient errors include connection resets, aborts, timeouts, broken pipes,
    /// and unexpected EOF. Non-transient errors (authentication, protocol, DNS)
    /// are never retried.
    pub fn is_transient(err: &NetworkError) -> bool {
        match err {
            NetworkError::Timeout => true,
            NetworkError::ConnectionFailed(_) => true,
            NetworkError::Io(io_err) => Self::is_transient_io(io_err),
            // Protocol, auth, DNS, TLS errors are not transient.
            // A policy denial (R-08 batch-3 · #131/#132, fail-closed egress
            // route refusal) is never transient either: retrying cannot change
            // the policy, and retrying must never downgrade to a direct route.
            NetworkError::AuthenticationFailed
            | NetworkError::ProtocolNegotiation(_)
            | NetworkError::DnsResolution(_)
            | NetworkError::TlsError(_)
            | NetworkError::NatTraversal(_)
            | NetworkError::DiscoveryError(_)
            | NetworkError::PolicyDenied(_)
            | NetworkError::RelayError(_) => false,
        }
    }

    /// Check whether a raw `std::io::Error` is transient.
    pub fn is_transient_io(err: &std::io::Error) -> bool {
        matches!(
            err.kind(),
            std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::TimedOut
                | std::io::ErrorKind::BrokenPipe
                | std::io::ErrorKind::UnexpectedEof
        )
    }
}

/// Send a message through a `PeerChannel` with automatic retry on transient failures.
///
/// On each transient error, sleeps for an exponentially increasing backoff duration
/// before retrying. Returns the first non-transient error or the final transient
/// error after all retries are exhausted.
pub async fn send_with_retry(
    channel: &mut impl PeerChannel,
    data: &[u8],
    config: &ReconnectConfig,
) -> crate::Result<()> {
    let mut attempts: u32 = 0;
    loop {
        match channel.send_message(data).await {
            Ok(()) => return Ok(()),
            Err(e) if ReconnectConfig::is_transient(&e) && attempts < config.max_retries => {
                attempts += 1;
                let backoff = config.backoff_for_attempt(attempts);
                warn!(
                    attempt = attempts,
                    max = config.max_retries,
                    backoff_ms = backoff.as_millis() as u64,
                    "Send failed, retrying: {}",
                    e
                );
                tokio::time::sleep(backoff).await;
            }
            Err(e) => return Err(e),
        }
    }
}

/// Receive a message through a `PeerChannel` with automatic retry on transient failures.
///
/// On each transient error, sleeps for an exponentially increasing backoff duration
/// before retrying. Returns the first non-transient error or the final transient
/// error after all retries are exhausted.
pub async fn receive_with_retry(
    channel: &mut impl PeerChannel,
    buf: &mut [u8],
    config: &ReconnectConfig,
) -> crate::Result<usize> {
    let mut attempts: u32 = 0;
    loop {
        match channel.receive_message(buf).await {
            Ok(n) => return Ok(n),
            Err(e) if ReconnectConfig::is_transient(&e) && attempts < config.max_retries => {
                attempts += 1;
                let backoff = config.backoff_for_attempt(attempts);
                warn!(
                    attempt = attempts,
                    max = config.max_retries,
                    backoff_ms = backoff.as_millis() as u64,
                    "Receive failed, retrying: {}",
                    e
                );
                tokio::time::sleep(backoff).await;
            }
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backoff_calculation() {
        let config = ReconnectConfig {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            jitter_factor: 0.0, // Disable jitter for predictable testing
            ..Default::default()
        };

        // attempt 0: 1s * 2^0 = 1s
        assert_eq!(config.backoff_for_attempt(0).as_millis(), 1000);
        // attempt 1: 1s * 2^1 = 2s
        assert_eq!(config.backoff_for_attempt(1).as_millis(), 2000);
        // attempt 2: 1s * 2^2 = 4s
        assert_eq!(config.backoff_for_attempt(2).as_millis(), 4000);
        // attempt 3: 1s * 2^3 = 8s
        assert_eq!(config.backoff_for_attempt(3).as_millis(), 8000);
        // attempt 4: 1s * 2^4 = 16s
        assert_eq!(config.backoff_for_attempt(4).as_millis(), 16000);
        // attempt 5: 1s * 2^5 = 32s -> capped at 30s
        assert_eq!(config.backoff_for_attempt(5).as_millis(), 30000);
        // attempt 10: still capped at 30s
        assert_eq!(config.backoff_for_attempt(10).as_millis(), 30000);
    }

    #[test]
    fn test_backoff_jitter_bounded() {
        let config = ReconnectConfig {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            jitter_factor: 0.1, // 10% jitter
            ..Default::default()
        };

        for attempt in 0..20 {
            let with_jitter = config.backoff_for_attempt(attempt);

            // Calculate the base (without jitter) for comparison
            let base = 1000_u64.saturating_mul(2_u64.saturating_pow(attempt));
            let capped = base.min(30000);
            let jitter_range = (capped as f64 * 0.1) as u64;

            // Backoff must be >= capped (jitter is always additive)
            assert!(
                with_jitter.as_millis() as u64 >= capped,
                "attempt {}: backoff {} < base {}",
                attempt,
                with_jitter.as_millis(),
                capped
            );
            // Backoff must be <= capped + jitter_range
            assert!(
                with_jitter.as_millis() as u64 <= capped + jitter_range,
                "attempt {}: backoff {} > base {} + jitter {}",
                attempt,
                with_jitter.as_millis(),
                capped,
                jitter_range
            );
        }
    }

    #[test]
    fn test_is_transient_network_errors() {
        // Transient errors
        assert!(ReconnectConfig::is_transient(&NetworkError::Timeout));
        assert!(ReconnectConfig::is_transient(
            &NetworkError::ConnectionFailed("reset".to_string())
        ));
        assert!(ReconnectConfig::is_transient(&NetworkError::Io(
            std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reset")
        )));
        assert!(ReconnectConfig::is_transient(&NetworkError::Io(
            std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "aborted")
        )));
        assert!(ReconnectConfig::is_transient(&NetworkError::Io(
            std::io::Error::new(std::io::ErrorKind::TimedOut, "timeout")
        )));
        assert!(ReconnectConfig::is_transient(&NetworkError::Io(
            std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken")
        )));
        assert!(ReconnectConfig::is_transient(&NetworkError::Io(
            std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "eof")
        )));

        // Non-transient errors
        assert!(!ReconnectConfig::is_transient(
            &NetworkError::AuthenticationFailed
        ));
        assert!(!ReconnectConfig::is_transient(
            &NetworkError::ProtocolNegotiation("bad".to_string())
        ));
        assert!(!ReconnectConfig::is_transient(
            &NetworkError::DnsResolution("fail".to_string())
        ));
        assert!(!ReconnectConfig::is_transient(&NetworkError::TlsError(
            "cert".to_string()
        )));
        assert!(!ReconnectConfig::is_transient(&NetworkError::NatTraversal(
            "fail".to_string()
        )));
        assert!(!ReconnectConfig::is_transient(
            &NetworkError::DiscoveryError("fail".to_string())
        ));
        assert!(!ReconnectConfig::is_transient(&NetworkError::RelayError(
            "fail".to_string()
        )));
        assert!(!ReconnectConfig::is_transient(&NetworkError::Io(
            std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied")
        )));
    }

    #[test]
    fn test_zero_retries_disabled() {
        let config = ReconnectConfig {
            max_retries: 0,
            ..Default::default()
        };

        // With max_retries=0, the retry condition `attempts < config.max_retries`
        // is never true, so any transient error is returned immediately.
        assert_eq!(config.max_retries, 0);

        // Backoff for attempt 0 should still be valid (even if never used)
        let backoff = config.backoff_for_attempt(0);
        assert!(backoff.as_millis() > 0);
    }

    #[test]
    fn test_default_config() {
        let config = ReconnectConfig::default();
        assert_eq!(config.max_retries, 5);
        assert_eq!(config.initial_backoff, Duration::from_secs(1));
        assert_eq!(config.max_backoff, Duration::from_secs(30));
        assert!((config.jitter_factor - 0.1).abs() < f64::EPSILON);
    }

    #[test]
    fn test_backoff_overflow_safety() {
        let config = ReconnectConfig {
            initial_backoff: Duration::from_secs(1),
            max_backoff: Duration::from_secs(30),
            jitter_factor: 0.0,
            max_retries: 100,
        };

        // Very high attempt number should not panic due to overflow
        let backoff = config.backoff_for_attempt(63);
        assert_eq!(backoff.as_millis(), 30000); // Capped at max_backoff

        let backoff = config.backoff_for_attempt(u32::MAX);
        assert_eq!(backoff.as_millis(), 30000); // Capped at max_backoff
    }

    /// Test that send_with_retry fails immediately on non-transient errors
    #[tokio::test]
    async fn test_send_with_retry_non_transient_fails_immediately() {
        struct FailChannel {
            call_count: u32,
        }

        impl PeerChannel for FailChannel {
            async fn send_message(&mut self, _data: &[u8]) -> crate::Result<()> {
                self.call_count += 1;
                Err(NetworkError::AuthenticationFailed)
            }
            async fn receive_message(&mut self, _buf: &mut [u8]) -> crate::Result<usize> {
                Ok(0)
            }
            async fn close(&mut self) {}
            fn transport_description(&self) -> String {
                "test".to_string()
            }
        }

        let config = ReconnectConfig {
            max_retries: 5,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            jitter_factor: 0.0,
        };
        let mut channel = FailChannel { call_count: 0 };

        let result = send_with_retry(&mut channel, b"hello", &config).await;
        assert!(result.is_err());
        // Should have only been called once (no retries for non-transient)
        assert_eq!(channel.call_count, 1);
    }

    /// Test that send_with_retry retries on transient errors
    #[tokio::test]
    async fn test_send_with_retry_retries_transient() {
        struct TransientThenOk {
            call_count: u32,
            fail_count: u32,
        }

        impl PeerChannel for TransientThenOk {
            async fn send_message(&mut self, _data: &[u8]) -> crate::Result<()> {
                self.call_count += 1;
                if self.call_count <= self.fail_count {
                    Err(NetworkError::Io(std::io::Error::new(
                        std::io::ErrorKind::ConnectionReset,
                        "connection reset",
                    )))
                } else {
                    Ok(())
                }
            }
            async fn receive_message(&mut self, _buf: &mut [u8]) -> crate::Result<usize> {
                Ok(0)
            }
            async fn close(&mut self) {}
            fn transport_description(&self) -> String {
                "test".to_string()
            }
        }

        let config = ReconnectConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            jitter_factor: 0.0,
        };
        let mut channel = TransientThenOk {
            call_count: 0,
            fail_count: 2,
        };

        let result = send_with_retry(&mut channel, b"hello", &config).await;
        assert!(result.is_ok());
        // 2 failures + 1 success = 3 calls
        assert_eq!(channel.call_count, 3);
    }

    /// Test that receive_with_retry retries on transient errors
    #[tokio::test]
    async fn test_receive_with_retry_retries_transient() {
        struct TransientThenOk {
            call_count: u32,
            fail_count: u32,
        }

        impl PeerChannel for TransientThenOk {
            async fn send_message(&mut self, _data: &[u8]) -> crate::Result<()> {
                Ok(())
            }
            async fn receive_message(&mut self, buf: &mut [u8]) -> crate::Result<usize> {
                self.call_count += 1;
                if self.call_count <= self.fail_count {
                    Err(NetworkError::Timeout)
                } else {
                    buf[0] = 42;
                    Ok(1)
                }
            }
            async fn close(&mut self) {}
            fn transport_description(&self) -> String {
                "test".to_string()
            }
        }

        let config = ReconnectConfig {
            max_retries: 5,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            jitter_factor: 0.0,
        };
        let mut channel = TransientThenOk {
            call_count: 0,
            fail_count: 3,
        };
        let mut buf = [0u8; 64];

        let result = receive_with_retry(&mut channel, &mut buf, &config).await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 1);
        assert_eq!(buf[0], 42);
        // 3 failures + 1 success = 4 calls
        assert_eq!(channel.call_count, 4);
    }

    /// Test that retries are exhausted when all attempts fail
    #[tokio::test]
    async fn test_send_with_retry_exhausts_retries() {
        struct AlwaysFail {
            call_count: u32,
        }

        impl PeerChannel for AlwaysFail {
            async fn send_message(&mut self, _data: &[u8]) -> crate::Result<()> {
                self.call_count += 1;
                Err(NetworkError::Io(std::io::Error::new(
                    std::io::ErrorKind::BrokenPipe,
                    "broken pipe",
                )))
            }
            async fn receive_message(&mut self, _buf: &mut [u8]) -> crate::Result<usize> {
                Ok(0)
            }
            async fn close(&mut self) {}
            fn transport_description(&self) -> String {
                "test".to_string()
            }
        }

        let config = ReconnectConfig {
            max_retries: 3,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            jitter_factor: 0.0,
        };
        let mut channel = AlwaysFail { call_count: 0 };

        let result = send_with_retry(&mut channel, b"hello", &config).await;
        assert!(result.is_err());
        // 1 initial + 3 retries = 4 calls total
        assert_eq!(channel.call_count, 4);
    }

    /// Test with max_retries=0: no retries, transient errors fail immediately
    #[tokio::test]
    async fn test_send_zero_retries_no_retry() {
        struct TransientFail {
            call_count: u32,
        }

        impl PeerChannel for TransientFail {
            async fn send_message(&mut self, _data: &[u8]) -> crate::Result<()> {
                self.call_count += 1;
                Err(NetworkError::Io(std::io::Error::new(
                    std::io::ErrorKind::ConnectionReset,
                    "reset",
                )))
            }
            async fn receive_message(&mut self, _buf: &mut [u8]) -> crate::Result<usize> {
                Ok(0)
            }
            async fn close(&mut self) {}
            fn transport_description(&self) -> String {
                "test".to_string()
            }
        }

        let config = ReconnectConfig {
            max_retries: 0,
            initial_backoff: Duration::from_millis(1),
            max_backoff: Duration::from_millis(10),
            jitter_factor: 0.0,
        };
        let mut channel = TransientFail { call_count: 0 };

        let result = send_with_retry(&mut channel, b"hello", &config).await;
        assert!(result.is_err());
        // Only 1 call — no retries
        assert_eq!(channel.call_count, 1);
    }
}
