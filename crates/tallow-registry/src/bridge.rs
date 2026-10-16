//! Bridge: registry rows → [`tallow_admission::server::DeviceEntry`].
//!
//! Preview of checklist item 2.4 (admitting devices minted in the console):
//! a registry row mints directly into the shape the admission core consumes.

use ed25519_dalek::VerifyingKey;

use tallow_admission::server::{DeviceEntry, DeviceStatus};

use crate::store::DeviceRow;

/// Bridge errors.
#[derive(Debug, thiserror::Error)]
pub enum BridgeError {
    #[error("bad ed_pub_hex: {0}")]
    Hex(String),
    #[error("unknown status: {0}")]
    Status(String),
}

/// Convert a registry row into an admission `DeviceEntry`.
pub fn to_device_entry(row: &DeviceRow) -> Result<DeviceEntry, BridgeError> {
    let raw = hex::decode(&row.ed_pub_hex).map_err(|e| BridgeError::Hex(e.to_string()))?;
    let arr: [u8; 32] = raw
        .try_into()
        .map_err(|v: Vec<u8>| BridgeError::Hex(format!("expected 32 bytes, got {}", v.len())))?;
    let ed = VerifyingKey::from_bytes(&arr).map_err(|e| BridgeError::Hex(e.to_string()))?;
    let status = match row.status.as_str() {
        "active" => DeviceStatus::Active,
        "revoked" => DeviceStatus::Revoked,
        other => return Err(BridgeError::Status(other.to_string())),
    };
    Ok(DeviceEntry {
        id: row.id.clone(),
        ed,
        role: row.role.clone(),
        status,
    })
}
