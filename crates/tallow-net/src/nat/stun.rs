//! STUN client for NAT type discovery
//!
//! Implements a minimal STUN Binding Request (RFC 5389) to discover
//! the public IP address and port mapping of the client.

use crate::error::NetworkError;
use crate::Result;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};

/// Tallow STUN servers (coturn on the relay box) — no third-party ICE servers.
pub const DEFAULT_STUN: &str = "relay.sendtallow.com:3478";
pub const ALT_STUN: &str = "relay-us.sendtallow.com:3478";

/// STUN magic cookie (RFC 5389)
const MAGIC_COOKIE: u32 = 0x2112A442;

/// STUN message types
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_RESPONSE: u16 = 0x0101;

/// STUN attribute types
const ATTR_MAPPED_ADDRESS: u16 = 0x0001;
const ATTR_XOR_MAPPED_ADDRESS: u16 = 0x0020;

/// STUN client for discovering public address
#[derive(Debug)]
pub struct StunClient {
    server: SocketAddr,
}

/// STUN binding result
#[derive(Debug, Clone)]
pub struct StunResult {
    /// Public (mapped) address as seen by the STUN server
    pub mapped_addr: SocketAddr,
    /// Local address used
    pub local_addr: SocketAddr,
}

impl StunClient {
    /// Create a new STUN client targeting a specific server
    pub fn new(server: SocketAddr) -> Self {
        Self { server }
    }

    /// Create a STUN client from a hostname (resolves DNS).
    ///
    /// # DNS Privacy Limitation (C-09)
    ///
    /// This method uses the system DNS resolver (`tokio::net::lookup_host`),
    /// which sends plaintext DNS queries. If a `DohResolver` is available,
    /// callers should resolve the STUN server hostname via DoH first and
    /// pass the resulting `SocketAddr` to [`StunClient::new`] instead.
    ///
    /// STUN itself does not support DoH natively — the UDP binding request
    /// goes directly to the resolved IP. The DNS lookup is the only leak
    /// point; once resolved, STUN traffic is UDP to an IP address.
    pub async fn from_hostname(hostname: &str) -> Result<Self> {
        let addr = tokio::net::lookup_host(hostname)
            .await
            .map_err(|e| {
                NetworkError::DnsResolution(format!(
                    "DNS resolution failed for {}: {}",
                    hostname, e
                ))
            })?
            .next()
            .ok_or_else(|| {
                NetworkError::DnsResolution(format!("No addresses found for {}", hostname))
            })?;

        Ok(Self { server: addr })
    }

    /// Discover public address using STUN, binding from a specific local port.
    ///
    /// This is critical for hole punching: the STUN-discovered mapped address
    /// must correspond to the same NAT binding that quinn will use. If we discover
    /// from a different port, the NAT maps to a different external port and the
    /// candidate is useless.
    pub async fn discover_from_port(&self, local_port: u16) -> Result<StunResult> {
        let bind_addr: SocketAddr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            local_port,
        );
        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            NetworkError::NatTraversal(format!(
                "Failed to bind UDP socket to port {}: {}",
                local_port, e
            ))
        })?;

        let local_addr = socket.local_addr().map_err(|e| {
            NetworkError::NatTraversal(format!("Failed to get local address: {}", e))
        })?;

        // Build STUN Binding Request
        let transaction_id: [u8; 12] = rand::random();
        let request = build_binding_request(&transaction_id);

        // Send request
        socket.send_to(&request, self.server).await.map_err(|e| {
            NetworkError::NatTraversal(format!("Failed to send STUN request: {}", e))
        })?;

        // Wait for response (3 second timeout)
        let mut buf = [0u8; 576];
        let (len, from) = timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| {
                NetworkError::NatTraversal(format!("Failed to receive STUN response: {}", e))
            })?;

        // L-54: Validate that the response came from the expected STUN server.
        // Without this check, an attacker on the network could inject a forged
        // STUN response with a spoofed mapped address, causing us to advertise
        // an attacker-controlled address as our public endpoint.
        if from.ip() != self.server.ip() {
            return Err(NetworkError::NatTraversal(format!(
                "STUN response from unexpected source {} (expected {})",
                from, self.server
            )));
        }

        // Parse response
        let mapped_addr = parse_binding_response(&buf[..len], &transaction_id)?;

        Ok(StunResult {
            mapped_addr,
            local_addr,
        })
    }

    /// Discover public address via STUN Binding Request
    pub async fn discover_public_address(&self) -> Result<StunResult> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|e| NetworkError::NatTraversal(format!("Failed to bind UDP socket: {}", e)))?;

        let local_addr = socket.local_addr().map_err(|e| {
            NetworkError::NatTraversal(format!("Failed to get local address: {}", e))
        })?;

        // Build STUN Binding Request
        let transaction_id: [u8; 12] = rand::random();
        let request = build_binding_request(&transaction_id);

        // Send request
        socket.send_to(&request, self.server).await.map_err(|e| {
            NetworkError::NatTraversal(format!("Failed to send STUN request: {}", e))
        })?;

        // Wait for response (3 second timeout)
        let mut buf = [0u8; 576];
        let (len, from) = timeout(Duration::from_secs(3), socket.recv_from(&mut buf))
            .await
            .map_err(|_| NetworkError::Timeout)?
            .map_err(|e| {
                NetworkError::NatTraversal(format!("Failed to receive STUN response: {}", e))
            })?;

        // L-54: Validate that the response came from the expected STUN server.
        if from.ip() != self.server.ip() {
            return Err(NetworkError::NatTraversal(format!(
                "STUN response from unexpected source {} (expected {})",
                from, self.server
            )));
        }

        // Parse response
        let mapped_addr = parse_binding_response(&buf[..len], &transaction_id)?;

        Ok(StunResult {
            mapped_addr,
            local_addr,
        })
    }
}

/// Build a STUN Binding Request message
fn build_binding_request(transaction_id: &[u8; 12]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(20);

    // Message Type: Binding Request (0x0001)
    msg.extend_from_slice(&BINDING_REQUEST.to_be_bytes());
    // Message Length: 0 (no attributes)
    msg.extend_from_slice(&0u16.to_be_bytes());
    // Magic Cookie
    msg.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    // Transaction ID (12 bytes)
    msg.extend_from_slice(transaction_id);

    msg
}

/// Parse a STUN Binding Response
fn parse_binding_response(data: &[u8], expected_txn: &[u8; 12]) -> Result<SocketAddr> {
    if data.len() < 20 {
        return Err(NetworkError::NatTraversal(
            "STUN response too short".to_string(),
        ));
    }

    // Check message type
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    if msg_type != BINDING_RESPONSE {
        return Err(NetworkError::NatTraversal(format!(
            "Unexpected STUN message type: 0x{:04x}",
            msg_type
        )));
    }

    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;

    // Check magic cookie
    let cookie = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
    if cookie != MAGIC_COOKIE {
        return Err(NetworkError::NatTraversal(
            "Invalid STUN magic cookie".to_string(),
        ));
    }

    // Check transaction ID
    if data[8..20] != *expected_txn {
        return Err(NetworkError::NatTraversal(
            "STUN transaction ID mismatch".to_string(),
        ));
    }

    // Parse attributes
    let attrs = &data[20..20 + msg_len.min(data.len() - 20)];
    let mut i = 0;

    while i + 4 <= attrs.len() {
        let attr_type = u16::from_be_bytes([attrs[i], attrs[i + 1]]);
        let attr_len = u16::from_be_bytes([attrs[i + 2], attrs[i + 3]]) as usize;
        let attr_data = &attrs[i + 4..];

        if attr_data.len() < attr_len {
            break;
        }

        match attr_type {
            ATTR_XOR_MAPPED_ADDRESS => {
                return parse_xor_mapped_address(&attr_data[..attr_len], data);
            }
            ATTR_MAPPED_ADDRESS => {
                return parse_mapped_address(&attr_data[..attr_len]);
            }
            _ => {}
        }

        // Attributes are padded to 4-byte boundaries
        let padded_len = (attr_len + 3) & !3;
        i += 4 + padded_len;
    }

    Err(NetworkError::NatTraversal(
        "No mapped address in STUN response".to_string(),
    ))
}

/// Parse XOR-MAPPED-ADDRESS attribute
fn parse_xor_mapped_address(data: &[u8], header: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        return Err(NetworkError::NatTraversal(
            "XOR-MAPPED-ADDRESS too short".to_string(),
        ));
    }

    let family = data[1];
    let xport = u16::from_be_bytes([data[2], data[3]]) ^ (MAGIC_COOKIE >> 16) as u16;

    match family {
        0x01 => {
            // IPv4
            let xaddr = u32::from_be_bytes([data[4], data[5], data[6], data[7]]) ^ MAGIC_COOKIE;
            let ip = std::net::Ipv4Addr::from(xaddr);
            Ok(SocketAddr::new(ip.into(), xport))
        }
        0x02 => {
            // IPv6
            if data.len() < 20 {
                return Err(NetworkError::NatTraversal(
                    "XOR-MAPPED-ADDRESS IPv6 too short".to_string(),
                ));
            }
            let mut xaddr = [0u8; 16];
            xaddr.copy_from_slice(&data[4..20]);
            // XOR with magic cookie + transaction ID
            for j in 0..4 {
                xaddr[j] ^= header[4 + j];
            }
            for j in 0..12 {
                xaddr[4 + j] ^= header[8 + j];
            }
            let ip = std::net::Ipv6Addr::from(xaddr);
            Ok(SocketAddr::new(ip.into(), xport))
        }
        _ => Err(NetworkError::NatTraversal(format!(
            "Unknown address family: {}",
            family
        ))),
    }
}

/// Parse MAPPED-ADDRESS attribute
fn parse_mapped_address(data: &[u8]) -> Result<SocketAddr> {
    if data.len() < 8 {
        return Err(NetworkError::NatTraversal(
            "MAPPED-ADDRESS too short".to_string(),
        ));
    }

    let family = data[1];
    let port = u16::from_be_bytes([data[2], data[3]]);

    match family {
        0x01 => {
            let ip = std::net::Ipv4Addr::new(data[4], data[5], data[6], data[7]);
            Ok(SocketAddr::new(ip.into(), port))
        }
        0x02 => {
            if data.len() < 20 {
                return Err(NetworkError::NatTraversal(
                    "MAPPED-ADDRESS IPv6 too short".to_string(),
                ));
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&data[4..20]);
            let ip = std::net::Ipv6Addr::from(addr);
            Ok(SocketAddr::new(ip.into(), port))
        }
        _ => Err(NetworkError::NatTraversal(format!(
            "Unknown address family: {}",
            family
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_binding_request() {
        let txn = [1u8; 12];
        let msg = build_binding_request(&txn);
        assert_eq!(msg.len(), 20);
        assert_eq!(msg[0], 0x00);
        assert_eq!(msg[1], 0x01);
        assert_eq!(msg[2], 0x00);
        assert_eq!(msg[3], 0x00);
        assert_eq!(
            u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]),
            MAGIC_COOKIE
        );
        assert_eq!(&msg[8..20], &txn);
    }

    #[test]
    fn test_parse_xor_mapped_ipv4() {
        let txn = [0xAA; 12];
        let mut resp = Vec::new();
        resp.extend_from_slice(&BINDING_RESPONSE.to_be_bytes());
        resp.extend_from_slice(&12u16.to_be_bytes());
        resp.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        resp.extend_from_slice(&txn);
        // XOR-MAPPED-ADDRESS attribute
        resp.extend_from_slice(&ATTR_XOR_MAPPED_ADDRESS.to_be_bytes());
        resp.extend_from_slice(&8u16.to_be_bytes());
        resp.push(0x00); // reserved
        resp.push(0x01); // IPv4
        let xport = 8080u16 ^ 0x2112;
        resp.extend_from_slice(&xport.to_be_bytes());
        let ip_raw = u32::from_be_bytes([192, 168, 1, 1]) ^ MAGIC_COOKIE;
        resp.extend_from_slice(&ip_raw.to_be_bytes());

        let result = parse_binding_response(&resp, &txn).unwrap();
        assert_eq!(
            result.ip(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1))
        );
        assert_eq!(result.port(), 8080);
    }

    #[test]
    fn test_stun_client_from_hostname_format() {
        // Verify that the STUN server constants have the expected host:port format
        assert!(DEFAULT_STUN.contains(':'));
        assert!(ALT_STUN.contains(':'));
    }
}
