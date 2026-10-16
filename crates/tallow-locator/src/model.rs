//! Data model: normalized offers + job classes.

use serde::{Deserialize, Serialize};

/// Job class — drives the jurisdiction policy and scoring floors
/// (SPEC-v2 §11 · ruling 6.5: US excluded for privacy role; relay is a
/// bandwidth object with a permissive-deny posture; general is the default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum JobClass {
    /// Privacy-relevant workloads (scrape identity, admin-shaped traffic).
    /// Allowed jurisdictions: tier ≤ 2 (EU/EEA + CH + IS). US excluded.
    Privacy,
    /// Bandwidth objects (relay roles). Permissive tier ≤ 3, US flagged.
    Relay,
    /// General workloads. Any *known* jurisdiction; unknown still fails closed.
    General,
}

impl JobClass {
    pub fn as_str(self) -> &'static str {
        match self {
            JobClass::Privacy => "privacy",
            JobClass::Relay => "relay",
            JobClass::General => "general",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "privacy" => Some(JobClass::Privacy),
            "relay" => Some(JobClass::Relay),
            "general" | "worker" => Some(JobClass::General),
            _ => None,
        }
    }

    /// Maximum allowed jurisdiction tier for this class (v1 policy).
    pub fn max_tier(self) -> u8 {
        match self {
            JobClass::Privacy => 2,
            JobClass::Relay => 3,
            JobClass::General => 3,
        }
    }
}

/// One normalized offer — provider catalogs flattened to a common shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Offer {
    /// Provider id: `hetzner` | `vultr` | `digitalocean` | `ovh`.
    pub provider: String,
    /// Provider plan id/name (e.g. `cx22`, `vc2-1c-2gb`).
    pub plan: String,
    /// Provider region code (e.g. `hel1`, `ams`, `gra`).
    pub region: String,
    /// City (human label).
    pub city: String,
    /// ISO-3166 alpha-2 country code.
    pub country: String,
    /// Monthly price in EUR (normalized; v1 fixtures are EUR-native).
    pub price_month_eur: f64,
    pub vcpu: u32,
    pub mem_mb: u32,
    pub disk_gb: u32,
    /// `x86_64` | `arm64`.
    pub arch: String,
    /// Raw provider handle (server type id, plan id) for traceability.
    pub source_id: String,
}

impl Offer {
    /// Stable display id: `provider/plan@region`.
    pub fn id(&self) -> String {
        format!("{}/{}@{}", self.provider, self.plan, self.region)
    }
}
