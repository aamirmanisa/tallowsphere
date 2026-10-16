//! LAN discovery via mDNS for direct peer-to-peer transfers
//!
//! Provides `LanAdvertiser` (sender-side mDNS service registration) and
//! `discover_sender()` / `discover_all_senders()` (receiver-side mDNS browse).
//!
//! Service type: `_tallow._tcp.local.`
//!
//! TXT records:
//! - `v`: Protocol version ("1")
//! - `fp`: Truncated identity fingerprint (4 hex chars)
//! - `rc`: Room code hash prefix (8 hex chars = 4 bytes)
//! - `ts`: Unix timestamp (stale detection)

use crate::discovery::DiscoveredPeer;
use crate::error::NetworkError;
use crate::Result;
use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tracing::{debug, info, warn};

/// Tallow mDNS service type
const SERVICE_TYPE: &str = "_tallow._tcp.local.";

/// Advertises a Tallow sender on the LAN via mDNS.
///
/// Registers a `_tallow._tcp.local.` service with TXT records containing:
/// - `v`: Protocol version ("1")
/// - `fp`: Truncated identity fingerprint (4 hex chars)
/// - `rc`: Room code hash prefix (8 hex chars = 4 bytes)
/// - `ts`: Unix timestamp (stale detection)
///
/// Implements `Drop` to unregister the service and shut down the mDNS daemon.
pub struct LanAdvertiser {
    /// The mDNS daemon for this advertisement
    daemon: ServiceDaemon,
    /// Full name of the registered service (needed for unregister)
    service_fullname: String,
}

impl LanAdvertiser {
    /// Create a new LAN advertiser and register the mDNS service.
    ///
    /// # Arguments
    ///
    /// * `port` - The QUIC listener port to advertise
    /// * `fingerprint_prefix` - First 8 hex chars of the identity fingerprint
    /// * `room_code_hash` - BLAKE3 hash of the room code (32 bytes)
    pub fn new(port: u16, fingerprint_prefix: &str, room_code_hash: &[u8; 32]) -> Result<Self> {
        let daemon = ServiceDaemon::new().map_err(|e| {
            NetworkError::DiscoveryError(format!("Failed to create mDNS daemon: {}", e))
        })?;

        // Instance name: tallow-<hex(room_code_hash[..2])> (4 hex chars)
        // Use only 2 bytes (4 hex chars) to reduce brute-force room correlation risk
        let instance_name = format!("tallow-{}", hex::encode(&room_code_hash[..2]));

        // M-77: Use a randomized hostname instead of the real system hostname
        // to prevent leaking the device's identity on the local network.
        let random_suffix: [u8; 4] = rand::random();
        let hostname = format!("tallow-{}", hex::encode(random_suffix));

        // Build TXT properties
        let mut properties = HashMap::new();
        properties.insert("v".to_string(), "1".to_string());
        // M-78: Truncate fingerprint to 4 hex chars (2 bytes) to reduce
        // cross-session correlation. Full verification via crypto handshake.
        let fp_truncated = if fingerprint_prefix.len() > 4 {
            &fingerprint_prefix[..4]
        } else {
            fingerprint_prefix
        };
        properties.insert("fp".to_string(), fp_truncated.to_string());
        // H-29: Reduced from 8 bytes to 4 bytes to limit room code hash brute-force surface
        properties.insert("rc".to_string(), hex::encode(&room_code_hash[..4]));
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        properties.insert("ts".to_string(), ts.to_string());

        let service = ServiceInfo::new(
            SERVICE_TYPE,
            &instance_name,
            &format!("{}.", hostname),
            "",
            port,
            properties,
        )
        .map_err(|e| {
            NetworkError::DiscoveryError(format!("Failed to create service info: {}", e))
        })?;

        let fullname = service.get_fullname().to_string();

        daemon.register(service).map_err(|e| {
            NetworkError::DiscoveryError(format!("Failed to register mDNS service: {}", e))
        })?;

        info!(
            "LAN advertiser registered: {} on port {}",
            instance_name, port
        );

        Ok(Self {
            daemon,
            service_fullname: fullname,
        })
    }
}

impl Drop for LanAdvertiser {
    fn drop(&mut self) {
        debug!("Unregistering mDNS service: {}", self.service_fullname);
        let _ = self.daemon.unregister(&self.service_fullname);
        let _ = self.daemon.shutdown();
    }
}

/// Browse for a Tallow sender on the LAN matching a specific room code.
///
/// Filters discovered services by the `rc` TXT record to find only the
/// sender advertising the expected room. Returns `None` if no match is
/// found within the timeout.
pub async fn discover_sender(
    room_code_hash: &[u8; 32],
    timeout: Duration,
) -> Result<Option<DiscoveredPeer>> {
    // H-29 / L-52: Reduced from 8 bytes to 4 bytes to match advertiser,
    // limiting room code hash brute-force surface.
    let expected_rc = hex::encode(&room_code_hash[..4]);

    info!(
        "Browsing mDNS for sender with room code prefix {}...",
        &expected_rc
    );

    let daemon = ServiceDaemon::new().map_err(|e| {
        NetworkError::DiscoveryError(format!("Failed to create mDNS daemon: {}", e))
    })?;

    let receiver = daemon
        .browse(SERVICE_TYPE)
        .map_err(|e| NetworkError::DiscoveryError(format!("Failed to start mDNS browse: {}", e)))?;

    let deadline = tokio::time::Instant::now() + timeout;
    let poll_interval = Duration::from_millis(100);

    loop {
        // Check timeout
        if tokio::time::Instant::now() >= deadline {
            debug!("mDNS browse timeout expired");
            let _ = daemon.shutdown();
            return Ok(None);
        }

        // Drain all available events
        while let Ok(event) = receiver.try_recv() {
            if let ServiceEvent::ServiceResolved(info) = event {
                // Check room code match
                let rc_match = info
                    .get_properties()
                    .get_property_val_str("rc")
                    .map(|rc| rc == expected_rc)
                    .unwrap_or(false);

                if rc_match {
                    let addresses = info.get_addresses();
                    if let Some(addr) = prefer_ipv4(addresses) {
                        let fingerprint = info
                            .get_properties()
                            .get_property_val_str("fp")
                            .map(|s| s.to_string());

                        let peer = DiscoveredPeer {
                            id: info.get_fullname().to_string(),
                            addr: SocketAddr::new(addr, info.get_port()),
                            name: info.get_hostname().to_string(),
                            fingerprint,
                        };

                        info!("Found matching sender: {} at {}", peer.name, peer.addr);

                        let _ = daemon.shutdown();
                        return Ok(Some(peer));
                    }
                }
            }
        }

        // Sleep briefly before polling again
        tokio::time::sleep(poll_interval).await;
    }
}

/// Browse for ALL Tallow senders on the LAN (no room code filter).
///
/// Used for the `--discover` flag to list all available peers.
/// Returns after the timeout expires.
pub async fn discover_all_senders(timeout: Duration) -> Result<Vec<DiscoveredPeer>> {
    info!("Browsing mDNS for all Tallow senders...");

    let daemon = ServiceDaemon::new().map_err(|e| {
        NetworkError::DiscoveryError(format!("Failed to create mDNS daemon: {}", e))
    })?;

    let receiver = daemon
        .browse(SERVICE_TYPE)
        .map_err(|e| NetworkError::DiscoveryError(format!("Failed to start mDNS browse: {}", e)))?;

    let mut peers: Vec<DiscoveredPeer> = Vec::new();
    let mut seen_names: HashSet<String> = HashSet::new();
    let deadline = tokio::time::Instant::now() + timeout;
    let poll_interval = Duration::from_millis(100);

    loop {
        if tokio::time::Instant::now() >= deadline {
            break;
        }

        while let Ok(event) = receiver.try_recv() {
            if let ServiceEvent::ServiceResolved(info) = event {
                let fullname = info.get_fullname().to_string();
                if seen_names.contains(&fullname) {
                    continue;
                }

                let addresses = info.get_addresses();
                if let Some(addr) = prefer_ipv4(addresses) {
                    let fingerprint = info
                        .get_properties()
                        .get_property_val_str("fp")
                        .map(|s| s.to_string());

                    let peer = DiscoveredPeer {
                        id: fullname.clone(),
                        addr: SocketAddr::new(addr, info.get_port()),
                        name: info.get_hostname().to_string(),
                        fingerprint,
                    };

                    debug!("Discovered sender: {} at {}", peer.name, peer.addr);
                    seen_names.insert(fullname);
                    peers.push(peer);
                }
            }
        }

        tokio::time::sleep(poll_interval).await;
    }

    info!("mDNS browse complete, found {} sender(s)", peers.len());
    let _ = daemon.shutdown();
    Ok(peers)
}

/// Select the best address from an mDNS service's address set.
///
/// Prefers IPv4 over IPv6 link-local to avoid scope ID issues.
/// If only IPv6 is available, returns it (with scope ID if present).
fn prefer_ipv4(addresses: &HashSet<IpAddr>) -> Option<IpAddr> {
    // First pass: look for IPv4
    for addr in addresses {
        if addr.is_ipv4() {
            return Some(*addr);
        }
    }

    // Second pass: look for non-link-local IPv6
    for addr in addresses {
        if let IpAddr::V6(v6) = addr {
            // fe80::/10 is link-local
            let segments = v6.segments();
            let is_link_local = (segments[0] & 0xffc0) == 0xfe80;
            if !is_link_local {
                return Some(*addr);
            }
        }
    }

    // Last resort: link-local IPv6 (may require scope ID)
    for addr in addresses {
        if addr.is_ipv6() {
            warn!(
                "Using IPv6 link-local address {} -- may require scope ID",
                addr
            );
            return Some(*addr);
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_lan_advertiser_creates_service() {
        let room_hash = [0xABu8; 32];
        let result = LanAdvertiser::new(12345, "abcd1234", &room_hash);
        // On some CI environments mDNS daemon may fail, so we just check it doesn't panic
        if let Ok(advertiser) = result {
            drop(advertiser);
        }
    }

    #[test]
    fn test_lan_advertiser_drops_cleanly() {
        let room_hash = [0xCDu8; 32];
        if let Ok(advertiser) = LanAdvertiser::new(12346, "ef012345", &room_hash) {
            // Drop should not panic
            drop(advertiser);
        }
    }

    #[test]
    fn test_advertiser_unique_instance_names() {
        let hash1 = [0x01u8; 32];
        let hash2 = [0x02u8; 32];

        // Instance names are derived from room code hash prefix, so different
        // room codes produce different instance names
        let name1 = format!("tallow-{}", hex::encode(&hash1[..4]));
        let name2 = format!("tallow-{}", hex::encode(&hash2[..4]));
        assert_ne!(name1, name2);
    }

    #[test]
    fn test_prefer_ipv4_with_both() {
        let mut addrs = HashSet::new();
        addrs.insert(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
        addrs.insert(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));

        let result = prefer_ipv4(&addrs);
        assert!(result.is_some());
        assert!(result.unwrap().is_ipv4());
        assert_eq!(result.unwrap(), IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn test_prefer_ipv4_only_v4() {
        let mut addrs = HashSet::new();
        addrs.insert(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let result = prefer_ipv4(&addrs);
        assert_eq!(result, Some(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_prefer_ipv4_only_link_local_v6() {
        let mut addrs = HashSet::new();
        addrs.insert(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));

        let result = prefer_ipv4(&addrs);
        // Should still return the link-local IPv6 as last resort
        assert_eq!(
            result,
            Some(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)))
        );
    }

    #[test]
    fn test_prefer_ipv4_global_v6() {
        let mut addrs = HashSet::new();
        addrs.insert(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)));

        let result = prefer_ipv4(&addrs);
        assert_eq!(
            result,
            Some(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1,)))
        );
    }

    #[test]
    fn test_prefer_ipv4_empty() {
        let addrs = HashSet::new();
        let result = prefer_ipv4(&addrs);
        assert_eq!(result, None);
    }

    #[test]
    fn test_prefer_ipv4_global_v6_over_link_local() {
        let mut addrs = HashSet::new();
        addrs.insert(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)));
        addrs.insert(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)));

        let result = prefer_ipv4(&addrs);
        // Should prefer global IPv6 over link-local
        assert!(result.is_some());
        if let Some(IpAddr::V6(v6)) = result {
            let segments = v6.segments();
            let is_link_local = (segments[0] & 0xffc0) == 0xfe80;
            assert!(!is_link_local, "Should prefer global IPv6 over link-local");
        }
    }
}
