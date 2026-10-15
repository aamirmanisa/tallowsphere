//! UPnP/IGD port mapping for NAT traversal
//!
//! Uses igd-next to request port forwarding from the local gateway router.
//! This allows direct peer connections when both sides are behind NAT.

use crate::error::NetworkError;
use crate::Result;
use std::net::SocketAddr;

/// Add a UPnP port mapping on the local gateway
///
/// Requests the router to forward `external_port` to `internal_addr`.
/// The lease lasts for `duration_secs` seconds (0 = permanent).
pub async fn add_port_mapping(
    external_port: u16,
    internal_addr: SocketAddr,
    description: &str,
    duration_secs: u32,
) -> Result<u16> {
    let gateway = igd_next::aio::tokio::search_gateway(Default::default())
        .await
        .map_err(|e| NetworkError::NatTraversal(format!("UPnP gateway not found: {}", e)))?;

    gateway
        .add_port(
            igd_next::PortMappingProtocol::TCP,
            external_port,
            internal_addr,
            duration_secs,
            description,
        )
        .await
        .map_err(|e| NetworkError::NatTraversal(format!("UPnP port mapping failed: {}", e)))?;

    Ok(external_port)
}

/// Remove a UPnP port mapping
pub async fn remove_port_mapping(external_port: u16) -> Result<()> {
    let gateway = igd_next::aio::tokio::search_gateway(Default::default())
        .await
        .map_err(|e| NetworkError::NatTraversal(format!("UPnP gateway not found: {}", e)))?;

    gateway
        .remove_port(igd_next::PortMappingProtocol::TCP, external_port)
        .await
        .map_err(|e| NetworkError::NatTraversal(format!("UPnP port unmapping failed: {}", e)))?;

    Ok(())
}

/// Get the external IP address from the gateway
pub async fn get_external_ip() -> Result<std::net::IpAddr> {
    let gateway = igd_next::aio::tokio::search_gateway(Default::default())
        .await
        .map_err(|e| NetworkError::NatTraversal(format!("UPnP gateway not found: {}", e)))?;

    let ip = gateway
        .get_external_ip()
        .await
        .map_err(|e| NetworkError::NatTraversal(format!("Failed to get external IP: {}", e)))?;

    Ok(ip)
}
