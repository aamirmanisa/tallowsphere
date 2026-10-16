//! NAT type detection via STUN
//!
//! Uses two STUN servers to classify the NAT type by comparing
//! mapped addresses from different servers.

use super::stun::{StunClient, ALT_STUN, DEFAULT_STUN};
use crate::Result;

/// NAT type classification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    /// No NAT (public IP)
    None,
    /// Full cone NAT (easiest to traverse)
    FullCone,
    /// Restricted cone NAT
    RestrictedCone,
    /// Port-restricted cone NAT
    PortRestricted,
    /// Symmetric NAT (hardest to traverse)
    Symmetric,
    /// Unknown or detection failed
    Unknown,
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "No NAT (public IP)"),
            Self::FullCone => write!(f, "Full Cone NAT"),
            Self::RestrictedCone => write!(f, "Restricted Cone NAT"),
            Self::PortRestricted => write!(f, "Port-Restricted Cone NAT"),
            Self::Symmetric => write!(f, "Symmetric NAT"),
            Self::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Detect NAT type using two STUN servers
///
/// Compares the mapped addresses from two different STUN servers.
/// If they differ, the NAT is symmetric. If they match, it's cone-type.
pub async fn detect() -> Result<NatType> {
    // Try first STUN server
    let client1 = match StunClient::from_hostname(DEFAULT_STUN).await {
        Ok(c) => c,
        Err(_) => return Ok(NatType::Unknown),
    };

    let result1 = match client1.discover_public_address().await {
        Ok(r) => r,
        Err(_) => return Ok(NatType::Unknown),
    };

    // Check if local == mapped (no NAT)
    // Guard against invalid/unspecified addresses from misconfigured STUN servers
    if result1.local_addr.ip() == result1.mapped_addr.ip()
        && !result1.mapped_addr.ip().is_unspecified()
        && !result1.mapped_addr.ip().is_loopback()
    {
        return Ok(NatType::None);
    }

    // Try second STUN server to detect symmetric NAT
    let client2 = match StunClient::from_hostname(ALT_STUN).await {
        Ok(c) => c,
        Err(_) => {
            // Can't determine type with one server, assume cone
            return Ok(NatType::FullCone);
        }
    };

    let result2 = match client2.discover_public_address().await {
        Ok(r) => r,
        Err(_) => return Ok(NatType::FullCone),
    };

    // If mapped addresses differ between servers → Symmetric NAT
    if result1.mapped_addr != result2.mapped_addr {
        return Ok(NatType::Symmetric);
    }

    // Same mapped address from both servers → some form of cone NAT
    // Full classification requires additional tests (sending from different ports)
    // but for our purposes, cone NAT is traversable
    Ok(NatType::FullCone)
}
