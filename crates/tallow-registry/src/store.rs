//! File-backed device registry (`registry.json`) — atomic writes.
//!
//! v1 shape: `{"v":1,"devices":[{id, role, status, ed_pub_hex, created_ms,
//! updated_ms, notes}]}`. Status is `"active"` or `"revoked"`. The registry
//! feeds the admission door through [`crate::bridge`] and, later, the
//! console device store (item 2.4).

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::now_ms;

/// One device row.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceRow {
    pub id: String,
    pub role: String,
    /// `"active"` | `"revoked"`.
    pub status: String,
    /// Raw Ed25519 public key, lowercase hex (64 chars).
    pub ed_pub_hex: String,
    pub created_ms: u64,
    pub updated_ms: u64,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RegistryDoc {
    v: u32,
    devices: Vec<DeviceRow>,
}

/// Store errors.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("unknown device: {0}")]
    Unknown(String),
    #[error("invalid status: {0}")]
    Status(String),
    #[error("invalid ed_pub_hex: {0}")]
    Key(String),
}

/// The registry store (load, mutate, save).
pub struct RegistryStore {
    path: PathBuf,
    doc: RegistryDoc,
}

fn validate_status(s: &str) -> Result<(), StoreError> {
    match s {
        "active" | "revoked" => Ok(()),
        other => Err(StoreError::Status(other.to_string())),
    }
}

fn validate_key(hex_str: &str) -> Result<(), StoreError> {
    let raw = hex::decode(hex_str).map_err(|e| StoreError::Key(e.to_string()))?;
    if raw.len() != 32 {
        return Err(StoreError::Key(format!(
            "expected 32 bytes, got {}",
            raw.len()
        )));
    }
    Ok(())
}

impl RegistryStore {
    /// Create an empty registry if missing; otherwise load it.
    pub fn init(path: &Path) -> Result<Self, StoreError> {
        if path.exists() {
            return Self::load(path);
        }
        let store = Self {
            path: path.to_path_buf(),
            doc: RegistryDoc {
                v: 1,
                devices: Vec::new(),
            },
        };
        store.save()?;
        Ok(store)
    }

    /// Load an existing registry file.
    pub fn load(path: &Path) -> Result<Self, StoreError> {
        let text = std::fs::read_to_string(path)?;
        let doc: RegistryDoc = serde_json::from_str(&text)?;
        Ok(Self {
            path: path.to_path_buf(),
            doc,
        })
    }

    /// Atomic save (write tmp file, rename over target).
    pub fn save(&self) -> Result<(), StoreError> {
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_string_pretty(&self.doc)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }

    /// Insert or update a row (created_ms preserved on update).
    pub fn upsert(
        &mut self,
        id: &str,
        role: &str,
        status: &str,
        ed_pub_hex: &str,
        notes: Option<String>,
    ) -> Result<&DeviceRow, StoreError> {
        validate_status(status)?;
        validate_key(ed_pub_hex)?;
        let now = now_ms();
        let idx = match self.doc.devices.iter().position(|r| r.id == id) {
            Some(i) => {
                let row = &mut self.doc.devices[i];
                row.role = role.to_string();
                row.status = status.to_string();
                row.ed_pub_hex = ed_pub_hex.to_string();
                row.notes = notes;
                row.updated_ms = now;
                i
            }
            None => {
                self.doc.devices.push(DeviceRow {
                    id: id.to_string(),
                    role: role.to_string(),
                    status: status.to_string(),
                    ed_pub_hex: ed_pub_hex.to_string(),
                    created_ms: now,
                    updated_ms: now,
                    notes,
                });
                self.doc.devices.len() - 1
            }
        };
        Ok(&self.doc.devices[idx])
    }

    /// Flip a device to `"revoked"`.
    pub fn revoke(&mut self, id: &str) -> Result<(), StoreError> {
        let now = now_ms();
        let row = self
            .doc
            .devices
            .iter_mut()
            .find(|r| r.id == id)
            .ok_or_else(|| StoreError::Unknown(id.to_string()))?;
        row.status = "revoked".to_string();
        row.updated_ms = now;
        Ok(())
    }

    pub fn get(&self, id: &str) -> Option<&DeviceRow> {
        self.doc.devices.iter().find(|r| r.id == id)
    }

    pub fn devices(&self) -> &[DeviceRow] {
        &self.doc.devices
    }

    /// Document value (for `list --json`).
    pub fn to_value(&self) -> serde_json::Value {
        serde_json::to_value(&self.doc).expect("registry serialize")
    }
}
