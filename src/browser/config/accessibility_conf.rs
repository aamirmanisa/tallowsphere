//! Accessibility auditing configuration (accessibility.toml).

use serde::{Deserialize, Serialize};

/// WCAG compliance auditing and consent banner handling.
///
/// ```toml
/// # accessibility.toml
/// wcag_level = "AA"              # "A" | "AA" | "AAA"
/// auto_audit = false             # Run WCAG audit on every page load
/// fail_on_violations = false     # Treat violations as errors
///
/// [consent]
/// auto_handle = true             # Automatically handle consent banners
/// strategy = "accept"            # "accept" | "reject" | "ignore"
/// reject_tracking = true         # Reject tracking cookies when rejecting
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct AccessibilityToml {
    /// WCAG conformance level: "A", "AA", "AAA".
    pub wcag_level: String,
    /// Automatically run WCAG audit on page load.
    pub auto_audit: bool,
    /// Treat WCAG violations as errors (fail the operation).
    pub fail_on_violations: bool,
    /// Consent banner handling.
    pub consent: ConsentToml,
}

impl Default for AccessibilityToml {
    fn default() -> Self {
        Self {
            wcag_level: "AA".into(),
            auto_audit: false,
            fail_on_violations: false,
            consent: ConsentToml::default(),
        }
    }
}

/// Cookie consent banner handling.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ConsentToml {
    /// Automatically detect and handle consent banners.
    pub auto_handle: bool,
    /// Strategy: "accept", "reject", "ignore".
    pub strategy: String,
    /// When rejecting, specifically reject tracking cookies.
    pub reject_tracking: bool,
}

impl Default for ConsentToml {
    fn default() -> Self {
        Self {
            auto_handle: true,
            strategy: "accept".into(),
            reject_tracking: true,
        }
    }
}
