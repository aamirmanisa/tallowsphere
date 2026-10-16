//! Privacy and PII protection configuration (privacy.toml).

use serde::{Deserialize, Serialize};

/// PII scanning, redaction, and data retention settings.
///
/// ```toml
/// # privacy.toml
/// pii_scan_enabled = true
/// redaction_enabled = true
/// fingerprint_dedup = true
/// retention_days = 30             # 0 = no auto-expiry
///
/// [pii_types]
/// email = true
/// phone = true
/// ssn = true
/// credit_card = true
/// ip_address = true
/// name = false                    # high false-positive rate
/// address = false
/// date_of_birth = true
///
/// [redaction]
/// style = "mask"                  # "mask" | "hash" | "remove"
/// mask_char = "*"
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrivacyToml {
    /// Enable automatic PII scanning on page content.
    pub pii_scan_enabled: bool,
    /// Enable automatic redaction of detected PII.
    pub redaction_enabled: bool,
    /// Enable content fingerprinting for deduplication.
    pub fingerprint_dedup: bool,
    /// Auto-delete stored data after N days (0 = never).
    pub retention_days: u32,
    /// Which PII types to scan for.
    pub pii_types: PiiTypeToggles,
    /// Redaction style settings.
    pub redaction: RedactionStyle,
}

impl Default for PrivacyToml {
    fn default() -> Self {
        Self {
            pii_scan_enabled: true,
            redaction_enabled: true,
            fingerprint_dedup: true,
            retention_days: 30,
            pii_types: PiiTypeToggles::default(),
            redaction: RedactionStyle::default(),
        }
    }
}

/// Toggle individual PII detection types.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PiiTypeToggles {
    pub email: bool,
    pub phone: bool,
    pub ssn: bool,
    pub credit_card: bool,
    pub ip_address: bool,
    pub name: bool,
    pub address: bool,
    pub date_of_birth: bool,
}

impl Default for PiiTypeToggles {
    fn default() -> Self {
        Self {
            email: true,
            phone: true,
            ssn: true,
            credit_card: true,
            ip_address: true,
            name: false,    // high false-positive rate
            address: false, // high false-positive rate
            date_of_birth: true,
        }
    }
}

/// How redacted content is replaced.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct RedactionStyle {
    /// Redaction method: "mask", "hash", "remove".
    pub style: String,
    /// Character used for masking.
    pub mask_char: String,
}

impl Default for RedactionStyle {
    fn default() -> Self {
        Self {
            style: "mask".into(),
            mask_char: "*".into(),
        }
    }
}
