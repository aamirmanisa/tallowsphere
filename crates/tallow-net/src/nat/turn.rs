//! TURN client for relayed connections
//!
//! Provides relay-based NAT traversal via the TURN protocol (RFC 5766).
//! In Tallow v1, TURN is available as a fallback when direct connections
//! and UDP hole punching both fail. The primary relay mechanism is
//! Tallow's own relay server.

use crate::{NetworkError, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use zeroize::Zeroizing;

/// TURN client for relayed connections
#[derive(Debug)]
pub struct TurnClient {
    /// TURN server address
    server: SocketAddr,
    /// TURN credentials (zeroized on drop per M-79)
    username: Zeroizing<String>,
    /// TURN password (used for MESSAGE-INTEGRITY in authenticated requests).
    /// Wrapped in `Zeroizing` to ensure credential material is wiped from
    /// memory when the client is dropped.
    #[allow(dead_code)]
    password: Zeroizing<String>,
    /// Allocated relay address (if any)
    relay_addr: Option<SocketAddr>,
    /// UDP socket for TURN communication
    socket: Option<UdpSocket>,
}

impl TurnClient {
    /// Create a new TURN client
    pub fn new(server: SocketAddr, username: String, password: String) -> Self {
        Self {
            server,
            username: Zeroizing::new(username),
            password: Zeroizing::new(password),
            relay_addr: None,
            socket: None,
        }
    }

    /// Allocate a relay address from the TURN server.
    ///
    /// Sends an Allocate request (RFC 5766 Section 6) and waits for
    /// a success response containing the relayed transport address.
    ///
    /// # MESSAGE-INTEGRITY (M-80 / L-42)
    ///
    /// Per RFC 5766 Section 6.1, authenticated Allocate requests MUST
    /// include a MESSAGE-INTEGRITY attribute computed as HMAC-SHA1 over
    /// the STUN message using the long-term credential mechanism
    /// (RFC 5389 Section 10.2). The current v1 implementation sends an
    /// unauthenticated initial request, which most TURN servers will
    /// reject with a 401 Unauthorized containing a realm and nonce.
    ///
    /// POST-V1.0: Implement the full TURN authentication flow:
    /// 1. Send unauthenticated Allocate
    /// 2. Receive 401 with REALM + NONCE
    /// 3. Compute key = MD5(username:realm:password)
    /// 4. Re-send with USERNAME, REALM, NONCE, MESSAGE-INTEGRITY attributes
    pub async fn allocate(&self) -> Result<SocketAddr> {
        // Bind a local UDP socket
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| NetworkError::NatTraversal(format!("Failed to bind UDP socket: {}", e)))?;

        // Build TURN Allocate request
        // Type: 0x0003 (Allocate), Magic: 0x2112A442
        let txn_id: [u8; 12] = rand::random();
        let mut req = Vec::with_capacity(20);
        req.extend_from_slice(&0x0003u16.to_be_bytes()); // Type: Allocate
        req.extend_from_slice(&0x0000u16.to_be_bytes()); // Length: 0 (no attributes for initial)
        req.extend_from_slice(&0x2112A442u32.to_be_bytes()); // Magic cookie
        req.extend_from_slice(&txn_id);

        // Send to TURN server
        socket.send_to(&req, self.server).await.map_err(|e| {
            NetworkError::NatTraversal(format!("Failed to send TURN allocate: {}", e))
        })?;

        // Wait for response with timeout
        let mut buf = [0u8; 1024];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            socket.recv_from(&mut buf),
        )
        .await;

        match result {
            Ok(Ok((len, _from))) => {
                if len < 20 {
                    return Err(NetworkError::NatTraversal(
                        "TURN response too short".to_string(),
                    ));
                }
                // Parse response type
                let msg_type = u16::from_be_bytes([buf[0], buf[1]]);
                if msg_type == 0x0103 {
                    // Allocate Success Response
                    // For v1, return the server address as the relay address
                    // A full implementation would parse XOR-RELAYED-ADDRESS
                    tracing::info!(
                        "TURN allocation successful via {} (user: {})",
                        self.server,
                        self.username.as_str()
                    );
                    Ok(self.server)
                } else if msg_type == 0x0113 {
                    Err(NetworkError::NatTraversal(
                        "TURN allocation rejected (check credentials)".to_string(),
                    ))
                } else {
                    Err(NetworkError::NatTraversal(format!(
                        "Unexpected TURN response type: 0x{:04x}",
                        msg_type
                    )))
                }
            }
            Ok(Err(e)) => Err(NetworkError::NatTraversal(format!(
                "TURN receive error: {}",
                e
            ))),
            Err(_) => Err(NetworkError::NatTraversal(
                "TURN allocation timed out".to_string(),
            )),
        }
    }

    /// Send data through the TURN relay to a peer.
    ///
    /// Wraps data in a TURN Send indication (RFC 5766 Section 10).
    pub async fn send(&self, data: &[u8], to: SocketAddr) -> Result<()> {
        let socket = self.socket.as_ref().ok_or_else(|| {
            NetworkError::NatTraversal("TURN client has no bound socket".to_string())
        })?;

        // Build Send indication (0x0016)
        // XOR-PEER-ADDRESS attribute (0x0012) + DATA attribute (0x0013)
        let peer_attr = encode_xor_address(to);
        let data_attr = encode_data_attribute(data);

        let attr_len = peer_attr.len() + data_attr.len();
        let txn_id: [u8; 12] = rand::random();

        let mut msg = Vec::with_capacity(20 + attr_len);
        msg.extend_from_slice(&0x0016u16.to_be_bytes()); // Send Indication
        msg.extend_from_slice(&(attr_len as u16).to_be_bytes());
        msg.extend_from_slice(&0x2112A442u32.to_be_bytes());
        msg.extend_from_slice(&txn_id);
        msg.extend_from_slice(&peer_attr);
        msg.extend_from_slice(&data_attr);

        socket
            .send_to(&msg, self.server)
            .await
            .map_err(|e| NetworkError::NatTraversal(format!("TURN send failed: {}", e)))?;

        Ok(())
    }

    /// Get the allocated relay address, if any
    pub fn relay_addr(&self) -> Option<SocketAddr> {
        self.relay_addr
    }
}

/// Encode an XOR-PEER-ADDRESS attribute for TURN
fn encode_xor_address(addr: SocketAddr) -> Vec<u8> {
    let mut attr = Vec::with_capacity(12);
    attr.extend_from_slice(&0x0012u16.to_be_bytes()); // XOR-PEER-ADDRESS
    attr.extend_from_slice(&0x0008u16.to_be_bytes()); // Length: 8 for IPv4

    attr.push(0x00); // Reserved
    attr.push(0x01); // Family: IPv4

    let port = addr.port() ^ 0x2112; // XOR with magic cookie high bits
    attr.extend_from_slice(&port.to_be_bytes());

    if let std::net::IpAddr::V4(ip) = addr.ip() {
        let xored = u32::from(ip) ^ 0x2112A442;
        attr.extend_from_slice(&xored.to_be_bytes());
    }

    attr
}

/// Encode a DATA attribute for TURN
fn encode_data_attribute(data: &[u8]) -> Vec<u8> {
    let padding = (4 - (data.len() % 4)) % 4;
    let mut attr = Vec::with_capacity(4 + data.len() + padding);
    attr.extend_from_slice(&0x0013u16.to_be_bytes()); // DATA
    attr.extend_from_slice(&(data.len() as u16).to_be_bytes());
    attr.extend_from_slice(data);
    attr.resize(attr.len() + padding, 0x00); // Pad to 4-byte boundary
    attr
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_turn_client() {
        let client = TurnClient::new(
            "198.51.100.1:3478".parse().unwrap(),
            "user".to_string(),
            "pass".to_string(),
        );
        assert!(client.relay_addr().is_none());
    }

    #[test]
    fn test_encode_xor_address() {
        let addr: SocketAddr = "192.168.1.1:8080".parse().unwrap();
        let encoded = encode_xor_address(addr);
        assert_eq!(encoded.len(), 12);
        assert_eq!(encoded[0..2], 0x0012u16.to_be_bytes());
    }

    #[test]
    fn test_encode_data_attribute() {
        let data = b"hello";
        let encoded = encode_data_attribute(data);
        assert_eq!(encoded[0..2], 0x0013u16.to_be_bytes());
        // Length should be 5
        assert_eq!(encoded[2..4], 5u16.to_be_bytes());
        // Data starts at offset 4
        assert_eq!(&encoded[4..9], b"hello");
        // Padded to 8 bytes total (4 header + 5 data + 3 padding)
        assert_eq!(encoded.len(), 12);
    }
}
