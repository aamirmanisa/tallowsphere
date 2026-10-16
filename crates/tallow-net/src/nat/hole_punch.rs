//! UDP hole punching for NAT traversal
//!
//! Implements simultaneous UDP hole punching for NAT traversal. Both peers
//! send packets to each other's public address (discovered via STUN) at the
//! same time, creating NAT pinhole mappings that allow bidirectional traffic.

use crate::{NetworkError, Result};
use std::net::SocketAddr;
use std::time::Duration;

/// Maximum number of hole-punch attempts
const MAX_ATTEMPTS: usize = 10;

/// Delay between hole-punch packets
const PUNCH_INTERVAL: Duration = Duration::from_millis(200);

/// Timeout for the entire hole-punch process
const PUNCH_TIMEOUT: Duration = Duration::from_secs(5);

/// Magic bytes to identify hole-punch packets
const PUNCH_MAGIC: &[u8; 4] = b"TLOW";

/// Attempt UDP hole punching between two peers.
///
/// Sends repeated small packets from `local` to `remote` while
/// simultaneously listening for incoming packets. If a packet is
/// received from the remote peer, the hole punch is successful.
pub async fn punch_hole(local: SocketAddr, remote: SocketAddr) -> Result<()> {
    let socket = tokio::net::UdpSocket::bind(local).await.map_err(|e| {
        NetworkError::NatTraversal(format!("Failed to bind for hole punching: {}", e))
    })?;

    tracing::info!("Starting hole punch: local={}, remote={}", local, remote);

    let result = tokio::time::timeout(PUNCH_TIMEOUT, async {
        for attempt in 0..MAX_ATTEMPTS {
            // Send a punch packet
            let mut packet = Vec::with_capacity(8);
            packet.extend_from_slice(PUNCH_MAGIC);
            packet.extend_from_slice(&(attempt as u32).to_be_bytes());

            if let Err(e) = socket.send_to(&packet, remote).await {
                tracing::debug!("Hole punch send attempt {} failed: {}", attempt, e);
            }

            // Try to receive a response
            let mut buf = [0u8; 64];
            match tokio::time::timeout(PUNCH_INTERVAL, socket.recv_from(&mut buf)).await {
                Ok(Ok((len, from))) => {
                    if len >= 4 && &buf[..4] == PUNCH_MAGIC {
                        tracing::info!(
                            "Hole punch successful on attempt {} from {}",
                            attempt,
                            from
                        );
                        return Ok(());
                    }
                }
                Ok(Err(e)) => {
                    tracing::debug!("Hole punch recv error: {}", e);
                }
                Err(_) => {
                    // Timeout on this attempt, try again
                    tracing::trace!("Hole punch attempt {} timed out", attempt);
                }
            }
        }

        Err(NetworkError::NatTraversal(format!(
            "Hole punch failed after {} attempts",
            MAX_ATTEMPTS
        )))
    })
    .await;

    match result {
        Ok(inner) => inner,
        Err(_) => Err(NetworkError::NatTraversal(
            "Hole punch timed out".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_punch_magic() {
        assert_eq!(PUNCH_MAGIC, b"TLOW");
    }

    #[test]
    fn test_constants() {
        assert_eq!(MAX_ATTEMPTS, 10);
        assert_eq!(PUNCH_INTERVAL, Duration::from_millis(200));
        assert_eq!(PUNCH_TIMEOUT, Duration::from_secs(5));
    }
}
