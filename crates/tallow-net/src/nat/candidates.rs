//! ICE-like candidate gathering for P2P direct connection
//!
//! Gathers local host addresses and STUN server-reflexive addresses
//! for exchanging with the remote peer via the relay.

use crate::error::NetworkError;
use crate::Result;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Candidate type for P2P connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CandidateType {
    /// Local network interface address
    Host = 0,
    /// STUN server-reflexive (public) address
    ServerReflexive = 1,
    /// UPnP port-mapped address
    UPnP = 2,
}

/// A network candidate for P2P direct connection
#[derive(Debug, Clone)]
pub struct Candidate {
    /// Socket address (IP + port)
    pub addr: SocketAddr,
    /// Type of candidate
    pub candidate_type: CandidateType,
    /// Priority (higher = preferred). Host=100, SRFLX=50, UPnP=30.
    pub priority: u32,
}

/// Gather all available candidates for P2P connection.
///
/// Binds to `local_port` for STUN discovery so the discovered public address
/// maps to the same port the quinn Endpoint will use.
///
/// Returns candidates sorted by priority (highest first).
pub async fn gather_candidates(local_port: u16) -> Vec<Candidate> {
    let mut candidates = Vec::new();

    // 1. Host candidates: local network interfaces
    if let Ok(ip) = get_local_ip() {
        candidates.push(Candidate {
            addr: SocketAddr::new(ip, local_port),
            candidate_type: CandidateType::Host,
            priority: 100,
        });
    }

    // 2. Server-reflexive candidate: STUN discovery from the same port
    match crate::nat::stun::StunClient::from_hostname(crate::nat::stun::DEFAULT_STUN).await {
        Ok(client) => match client.discover_from_port(local_port).await {
            Ok(result) => {
                // L-53: Reject private/reserved IPs for ServerReflexive candidates.
                // A STUN server returning a private IP means we're behind a
                // carrier-grade NAT or the STUN server is on the LAN — the
                // address is not routable from the internet and useless as
                // a server-reflexive candidate.
                if is_private_ip(&result.mapped_addr.ip()) {
                    tracing::warn!(
                        "STUN returned private IP {} — not usable as ServerReflexive candidate",
                        result.mapped_addr
                    );
                } else {
                    candidates.push(Candidate {
                        addr: result.mapped_addr,
                        candidate_type: CandidateType::ServerReflexive,
                        priority: 50,
                    });
                }
            }
            Err(e) => {
                tracing::warn!("STUN discovery failed: {}", e);
            }
        },
        Err(e) => {
            tracing::warn!("STUN client creation failed: {}", e);
        }
    }

    // Sort by priority descending
    candidates.sort_by_key(|a| std::cmp::Reverse(a.priority));
    candidates
}

/// Check if an IP address is in a private/reserved range (RFC 1918 + RFC 6598).
///
/// Used by L-53 to reject STUN server-reflexive candidates that return
/// private IPs, which are not routable from the internet.
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (16..=31).contains(&octets[1]))
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 100.64.0.0/10 (Carrier-grade NAT, RFC 6598)
            || (octets[0] == 100 && (64..=127).contains(&octets[1]))
        }
        IpAddr::V6(v6) => {
            // fc00::/7 (Unique Local Address)
            let first = v6.segments()[0];
            (first & 0xfe00) == 0xfc00
        }
    }
}

/// Get the primary local IP address (non-loopback, non-link-local).
///
/// # Technique (M-52)
///
/// Uses the standard "connect a UDP socket to an external IP" trick to
/// discover the default route interface address. The `connect()` call on
/// a UDP socket does NOT send any packets — it only configures the
/// kernel's routing table lookup, which sets the socket's local address
/// to the interface that would be used to reach 8.8.8.8.
///
/// No data is transmitted to 8.8.8.8. This is a widely-used technique
/// (e.g., Python's `socket.connect(('8.8.8.8', 80))`) and is safe for
/// local IP discovery. The address 8.8.8.8 is used purely as a routable
/// destination to trigger route selection.
///
/// **Firewall log fingerprint**: Even though no packet is sent, some
/// host-based firewalls log the `connect()` syscall (e.g., Windows Firewall
/// with advanced auditing). This creates a log entry referencing 8.8.8.8:80,
/// which could identify Tallow usage on forensic analysis of the host.
/// A purely local alternative (enumerating network interfaces) would
/// avoid even the routing table lookup but requires platform-specific
/// APIs (e.g., `getifaddrs` on Unix) and doesn't reliably identify the
/// "primary" interface on multi-homed systems.
fn get_local_ip() -> Result<IpAddr> {
    // Bind a UDP socket to an external address to discover the default route IP.
    // NOTE: connect() on a UDP socket does NOT send packets — it only performs
    // a kernel routing table lookup to determine which local interface would
    // be used to reach the destination.
    let socket = std::net::UdpSocket::bind("0.0.0.0:0")
        .map_err(|e| NetworkError::NatTraversal(format!("bind failed: {}", e)))?;
    socket
        .connect("8.8.8.8:80")
        .map_err(|e| NetworkError::NatTraversal(format!("connect failed: {}", e)))?;
    let addr = socket
        .local_addr()
        .map_err(|e| NetworkError::NatTraversal(format!("local_addr failed: {}", e)))?;
    Ok(addr.ip())
}

/// Validate a candidate address is safe to connect to.
///
/// Rejects loopback, link-local, broadcast, multicast, and unspecified addresses.
/// Prevents an attacker from redirecting connections to unintended addresses.
pub fn validate_candidate_addr(addr: &SocketAddr) -> bool {
    let ip = addr.ip();
    if ip.is_loopback() || ip.is_multicast() || ip.is_unspecified() {
        return false;
    }
    // Check link-local
    match ip {
        IpAddr::V4(v4) => {
            // 169.254.0.0/16 link-local
            if v4.octets()[0] == 169 && v4.octets()[1] == 254 {
                return false;
            }
            // 255.255.255.255 broadcast
            if v4 == Ipv4Addr::BROADCAST {
                return false;
            }
        }
        IpAddr::V6(v6) => {
            // fe80::/10 link-local
            let segments = v6.segments();
            if segments[0] & 0xffc0 == 0xfe80 {
                return false;
            }
        }
    }
    // Port must be valid (1-65535)
    addr.port() > 0
}

/// Encode a SocketAddr into bytes for wire transport.
///
/// IPv4: 6 bytes (4 IP + 2 port). IPv6: 18 bytes (16 IP + 2 port).
pub fn encode_socket_addr(addr: SocketAddr) -> Vec<u8> {
    let mut buf = Vec::new();
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.extend_from_slice(&v4.octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
        IpAddr::V6(v6) => {
            buf.extend_from_slice(&v6.octets());
            buf.extend_from_slice(&addr.port().to_be_bytes());
        }
    }
    buf
}

/// Decode a SocketAddr from bytes. Inverse of `encode_socket_addr`.
pub fn decode_socket_addr(bytes: &[u8]) -> Result<SocketAddr> {
    match bytes.len() {
        6 => {
            let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
            let port = u16::from_be_bytes([bytes[4], bytes[5]]);
            Ok(SocketAddr::new(IpAddr::V4(ip), port))
        }
        18 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&bytes[..16]);
            let ip = std::net::Ipv6Addr::from(octets);
            let port = u16::from_be_bytes([bytes[16], bytes[17]]);
            Ok(SocketAddr::new(IpAddr::V6(ip), port))
        }
        n => Err(NetworkError::NatTraversal(format!(
            "Invalid candidate address length: {} (expected 6 or 18)",
            n
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_ipv4() {
        let addr: SocketAddr = "192.168.1.42:8080".parse().unwrap();
        let encoded = encode_socket_addr(addr);
        assert_eq!(encoded.len(), 6);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_encode_decode_ipv6() {
        let addr: SocketAddr = "[::1]:4433".parse().unwrap();
        let encoded = encode_socket_addr(addr);
        assert_eq!(encoded.len(), 18);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    #[test]
    fn test_validate_rejects_loopback() {
        assert!(!validate_candidate_addr(&"127.0.0.1:1234".parse().unwrap()));
        assert!(!validate_candidate_addr(&"[::1]:1234".parse().unwrap()));
    }

    #[test]
    fn test_validate_rejects_link_local() {
        assert!(!validate_candidate_addr(
            &"169.254.1.1:1234".parse().unwrap()
        ));
    }

    #[test]
    fn test_validate_rejects_broadcast() {
        assert!(!validate_candidate_addr(
            &"255.255.255.255:1234".parse().unwrap()
        ));
    }

    #[test]
    fn test_validate_rejects_multicast() {
        assert!(!validate_candidate_addr(&"224.0.0.1:1234".parse().unwrap()));
    }

    #[test]
    fn test_validate_rejects_unspecified() {
        assert!(!validate_candidate_addr(&"0.0.0.0:1234".parse().unwrap()));
    }

    #[test]
    fn test_validate_rejects_port_zero() {
        assert!(!validate_candidate_addr(&"192.168.1.1:0".parse().unwrap()));
    }

    #[test]
    fn test_validate_accepts_valid() {
        assert!(validate_candidate_addr(
            &"192.168.1.42:8080".parse().unwrap()
        ));
        assert!(validate_candidate_addr(&"8.8.8.8:4433".parse().unwrap()));
    }

    #[test]
    fn test_decode_invalid_length() {
        assert!(decode_socket_addr(&[1, 2, 3]).is_err());
    }

    // --- Phase 20 Plan 03 additions ---

    /// Verify CandidateType discriminant values match the binary protocol
    #[test]
    fn test_candidate_type_values() {
        assert_eq!(CandidateType::Host as u8, 0);
        assert_eq!(CandidateType::ServerReflexive as u8, 1);
        assert_eq!(CandidateType::UPnP as u8, 2);
    }

    /// Edge case: near-zero IP address with minimal port
    #[test]
    fn test_encode_decode_near_zero_ipv4() {
        let addr: SocketAddr = "0.0.0.1:1".parse().unwrap();
        let encoded = encode_socket_addr(addr);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    /// Edge case: maximum IPv4 address and maximum port
    #[test]
    fn test_encode_decode_max_ipv4() {
        let addr: SocketAddr = "255.255.255.254:65535".parse().unwrap();
        let encoded = encode_socket_addr(addr);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    /// Full IPv6 address with non-trivial segments
    #[test]
    fn test_encode_decode_ipv6_full() {
        let addr: SocketAddr = "[2001:db8::1]:4433".parse().unwrap();
        let encoded = encode_socket_addr(addr);
        assert_eq!(encoded.len(), 18);
        let decoded = decode_socket_addr(&encoded).unwrap();
        assert_eq!(decoded, addr);
    }

    /// Private ranges should be valid candidates (LAN peers)
    #[test]
    fn test_validate_accepts_private_ranges() {
        assert!(validate_candidate_addr(&"10.0.0.1:8080".parse().unwrap()));
        assert!(validate_candidate_addr(&"172.16.0.1:8080".parse().unwrap()));
        assert!(validate_candidate_addr(
            &"192.168.0.1:8080".parse().unwrap()
        ));
    }

    /// IPv6 link-local (fe80::/10) should be rejected
    #[test]
    fn test_validate_rejects_ipv6_link_local() {
        assert!(!validate_candidate_addr(&"[fe80::1]:8080".parse().unwrap()));
    }

    /// IPv6 multicast (ff00::/8) should be rejected
    #[test]
    fn test_validate_rejects_ipv6_multicast() {
        assert!(!validate_candidate_addr(&"[ff02::1]:8080".parse().unwrap()));
    }

    /// IPv6 unspecified (::) should be rejected
    #[test]
    fn test_validate_rejects_ipv6_unspecified() {
        assert!(!validate_candidate_addr(&"[::]:8080".parse().unwrap()));
    }

    /// Candidates should sort by priority descending
    #[test]
    fn test_candidate_sorting_by_priority() {
        let mut candidates = [
            Candidate {
                addr: "8.8.8.8:4433".parse().unwrap(),
                candidate_type: CandidateType::ServerReflexive,
                priority: 50,
            },
            Candidate {
                addr: "192.168.1.1:4433".parse().unwrap(),
                candidate_type: CandidateType::Host,
                priority: 100,
            },
            Candidate {
                addr: "1.2.3.4:4433".parse().unwrap(),
                candidate_type: CandidateType::UPnP,
                priority: 30,
            },
        ];
        candidates.sort_by_key(|a| std::cmp::Reverse(a.priority));
        assert_eq!(candidates[0].priority, 100); // Host first
        assert_eq!(candidates[1].priority, 50); // SRFLX second
        assert_eq!(candidates[2].priority, 30); // UPnP last
    }

    /// Test gather_candidates returns at least host candidate on systems with a NIC.
    /// STUN may fail without internet, but host discovery should work.
    #[tokio::test]
    async fn test_gather_candidates_returns_host() {
        let candidates = gather_candidates(0).await;
        // On most systems with a network interface, we get at least a host candidate.
        // STUN may fail (no internet) but host should work.
        // We don't assert non-empty because CI may lack a NIC.
        for c in &candidates {
            assert!(c.priority > 0);
            // All candidates should have a valid port (or 0 if we passed 0)
            // and a valid IP address
            assert!(!c.addr.ip().is_loopback() || c.addr.port() == 0);
        }
    }

    /// Decode rejects completely empty input
    #[test]
    fn test_decode_empty_input() {
        assert!(decode_socket_addr(&[]).is_err());
    }

    /// Decode rejects input of wrong sizes (not 6 or 18)
    #[test]
    fn test_decode_invalid_sizes() {
        assert!(decode_socket_addr(&[1]).is_err());
        assert!(decode_socket_addr(&[1, 2]).is_err());
        assert!(decode_socket_addr(&[1, 2, 3, 4, 5]).is_err()); // one short of IPv4
        assert!(decode_socket_addr(&[1, 2, 3, 4, 5, 6, 7]).is_err()); // one over IPv4
        assert!(decode_socket_addr(&[0u8; 17]).is_err()); // one short of IPv6
        assert!(decode_socket_addr(&[0u8; 19]).is_err()); // one over IPv6
    }

    /// Port encoding is big-endian
    #[test]
    fn test_encode_port_big_endian() {
        let addr: SocketAddr = "1.2.3.4:8080".parse().unwrap(); // 8080 = 0x1F90
        let encoded = encode_socket_addr(addr);
        // Bytes 4-5 should be port in BE: 0x1F, 0x90
        assert_eq!(encoded[4], 0x1F);
        assert_eq!(encoded[5], 0x90);
    }
}
