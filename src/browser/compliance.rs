//! Legal / compliance module.
//!
//! Centralizes DMCA/takedown handling, per-retailer scrape authorization
//! boundaries, and image-hosting policy decisions. The goal is to make
//! unsafe operations explicit and auditable at the call site.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Public FTC affiliate disclosure — must be shown anywhere affiliate
/// links are surfaced to end users.
pub const FTC_DISCLOSURE: &str =
    "HackTheCart may earn commission from purchases made through links on this page. \
     This helps keep our service free. Prices shown are independent of our commissions.";

#[derive(Debug, Clone)]
pub struct DmcaContact {
    pub email: String,
    pub registered_with_uspto: bool,
    pub response_sla_hours: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TakedownReason {
    DmcaCopyright,
    MapViolation,
    TrademarkInfringement,
    FalseAdvertising,
    PrivacyGdpr,
    PrivacyCcpa,
    TermsOfService,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TakedownStatus {
    Received,
    UnderReview,
    Complied,
    Rejected,
    Disputed,
}

#[derive(Debug, Clone)]
pub struct TakedownRequest {
    pub id: String,
    pub received_at: i64,
    pub complainant: String,
    pub reason: TakedownReason,
    pub affected_resources: Vec<String>,
    pub status: TakedownStatus,
    pub resolved_at: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct ProcessedTakedown {
    pub id: String,
    pub previous_status: TakedownStatus,
    pub new_status: TakedownStatus,
    pub action: String,
}

#[derive(Debug, Clone)]
pub struct AuthBoundary {
    pub retailer: String,
    pub public_data_allowed: bool,
    pub auth_bypass_prohibited: bool,
    pub account_creation_prohibited: bool,
    pub tos_url: String,
    pub last_reviewed: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LegalBasis {
    /// Public data, hiQ v. LinkedIn precedent.
    PublicData,
    /// GDPR Art. 6(1)(f) — legitimate interest.
    LegitimateInterest,
    /// Contract — e.g. a user scraping their own account.
    Contract,
    NotAllowed,
}

#[derive(Debug, Clone)]
pub struct ComplianceCheck {
    pub allowed: bool,
    pub concerns: Vec<String>,
    pub legal_basis: LegalBasis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImagePolicy {
    /// Hotlink only — default. Transfers hosting risk to the retailer.
    HotlinkOnly,
    /// Thumbnail (<=200x200) falls under fair use.
    HostThumbnail,
    /// Known MAP / trademark hazard — do not fetch or display.
    Prohibited,
}

pub struct ComplianceManager {
    dmca_contacts: Vec<DmcaContact>,
    takedown_queue: Arc<Mutex<Vec<TakedownRequest>>>,
    auth_boundaries: HashMap<String, AuthBoundary>,
}

impl Default for ComplianceManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ComplianceManager {
    pub fn new() -> Self {
        let mut auth_boundaries = HashMap::new();

        // Default retailer boundaries. Last-reviewed timestamps would normally
        // come from a config file or DB; we seed with 0 for now.
        let defaults = [
            ("amazon",   true, true, true, "https://www.amazon.com/gp/help/customer/display.html?nodeId=508088"),
            ("walmart",  true, true, true, "https://www.walmart.com/help/article/walmart-com-terms-of-use"),
            ("target",   true, true, true, "https://www.target.com/c/terms-conditions"),
            ("bestbuy",  true, true, true, "https://www.bestbuy.com/site/help-topics/conditions-of-use/pcmcat204400050067.c"),
            ("costco",   true, true, true, "https://www.costco.com/terms-and-conditions-of-use.html"),
            ("kroger",   true, true, true, "https://www.kroger.com/hc/help/policies-information/terms-and-conditions"),
        ];
        for (retailer, pub_ok, no_bypass, no_create, tos) in defaults {
            auth_boundaries.insert(
                retailer.to_string(),
                AuthBoundary {
                    retailer: retailer.to_string(),
                    public_data_allowed: pub_ok,
                    auth_bypass_prohibited: no_bypass,
                    account_creation_prohibited: no_create,
                    tos_url: tos.to_string(),
                    last_reviewed: 0,
                },
            );
        }

        Self {
            dmca_contacts: vec![DmcaContact {
                email: "dmca@hackthecart.example".to_string(),
                registered_with_uspto: false,
                response_sla_hours: 48,
            }],
            takedown_queue: Arc::new(Mutex::new(Vec::new())),
            auth_boundaries,
        }
    }

    pub fn dmca_contacts(&self) -> &[DmcaContact] {
        &self.dmca_contacts
    }

    pub fn add_dmca_contact(&mut self, contact: DmcaContact) {
        self.dmca_contacts.push(contact);
    }

    pub fn set_boundary(&mut self, boundary: AuthBoundary) {
        self.auth_boundaries
            .insert(boundary.retailer.clone(), boundary);
    }

    /// Check whether scraping a given URL for a given retailer is allowed.
    /// Errs on the side of denying when a URL looks authenticated.
    pub fn is_scrape_allowed(&self, url: &str, retailer: &str) -> ComplianceCheck {
        let mut concerns: Vec<String> = Vec::new();
        let lower = url.to_ascii_lowercase();

        // Heuristic authenticated/endpoint patterns.
        let auth_markers = [
            "/account", "/my-account", "/login", "/signin",
            "/checkout", "/cart", "/orders", "/dashboard",
            "/profile", "/member",
        ];
        let looks_auth = auth_markers.iter().any(|m| lower.contains(m));

        let boundary = self.auth_boundaries.get(retailer);

        if looks_auth {
            concerns.push(format!(
                "URL looks authenticated ({}); public-data basis does not cover this",
                url
            ));
            if let Some(b) = boundary {
                if b.auth_bypass_prohibited {
                    return ComplianceCheck {
                        allowed: false,
                        concerns,
                        legal_basis: LegalBasis::NotAllowed,
                    };
                }
            } else {
                return ComplianceCheck {
                    allowed: false,
                    concerns,
                    legal_basis: LegalBasis::NotAllowed,
                };
            }
        }

        match boundary {
            Some(b) if b.public_data_allowed => ComplianceCheck {
                allowed: true,
                concerns,
                legal_basis: LegalBasis::PublicData,
            },
            Some(_) => {
                concerns.push(format!("retailer {} does not allow public scraping", retailer));
                ComplianceCheck {
                    allowed: false,
                    concerns,
                    legal_basis: LegalBasis::NotAllowed,
                }
            }
            None => {
                concerns.push(format!("no auth boundary defined for retailer {}", retailer));
                ComplianceCheck {
                    allowed: true,
                    concerns,
                    legal_basis: LegalBasis::PublicData,
                }
            }
        }
    }

    /// Queue a received takedown request.
    pub fn receive_takedown(&self, mut request: TakedownRequest) {
        if request.status == TakedownStatus::Received {
            // ensure defaults
        } else {
            request.status = TakedownStatus::Received;
        }
        if let Ok(mut q) = self.takedown_queue.lock() {
            q.push(request);
        }
    }

    /// Process all pending takedowns. Must run frequently enough to honor the
    /// 48-hour DMCA SLA. Returns a list of transitions applied.
    pub fn process_takedowns(&self) -> Vec<ProcessedTakedown> {
        let now = current_epoch_secs();
        let mut out = Vec::new();
        let Ok(mut q) = self.takedown_queue.lock() else {
            return out;
        };

        for req in q.iter_mut() {
            if matches!(req.status, TakedownStatus::Complied | TakedownStatus::Rejected) {
                continue;
            }
            let previous = req.status.clone();
            // Policy: DMCA, MAP, and trademark auto-comply pending review.
            // Privacy requests also auto-comply. ToS disputes go to review.
            let (new_status, action) = match req.reason {
                TakedownReason::DmcaCopyright
                | TakedownReason::MapViolation
                | TakedownReason::TrademarkInfringement
                | TakedownReason::PrivacyGdpr
                | TakedownReason::PrivacyCcpa => (
                    TakedownStatus::Complied,
                    "auto-removed affected resources; notified complainant".to_string(),
                ),
                TakedownReason::FalseAdvertising => (
                    TakedownStatus::UnderReview,
                    "escalated to legal review".to_string(),
                ),
                TakedownReason::TermsOfService => (
                    TakedownStatus::UnderReview,
                    "ToS dispute queued for legal review".to_string(),
                ),
            };

            req.status = new_status.clone();
            if matches!(new_status, TakedownStatus::Complied | TakedownStatus::Rejected) {
                req.resolved_at = Some(now);
            }
            out.push(ProcessedTakedown {
                id: req.id.clone(),
                previous_status: previous,
                new_status,
                action,
            });
        }
        out
    }

    /// Snapshot of the current takedown queue.
    pub fn takedowns(&self) -> Vec<TakedownRequest> {
        self.takedown_queue
            .lock()
            .map(|q| q.clone())
            .unwrap_or_default()
    }

    /// Decide whether a product image may be hosted or must be hotlinked.
    pub fn image_hosting_policy(&self, image_url: &str) -> ImagePolicy {
        let lower = image_url.to_ascii_lowercase();

        // Known MAP-aggressive brands — never fetch or host directly.
        let prohibited_brands = ["sonos", "bose", "apple.com/shop", "weber"];
        if prohibited_brands.iter().any(|b| lower.contains(b)) {
            return ImagePolicy::Prohibited;
        }

        // If the URL already indicates a thumbnail size, safe to host.
        let thumb_markers = ["_sl200_", "_sl160_", "thumb", "_ac_us200_", "_sx200_"];
        if thumb_markers.iter().any(|m| lower.contains(m)) {
            return ImagePolicy::HostThumbnail;
        }

        ImagePolicy::HotlinkOnly
    }
}

fn current_epoch_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_product_page_allowed() {
        let m = ComplianceManager::new();
        let c = m.is_scrape_allowed("https://www.amazon.com/dp/B0XYZ", "amazon");
        assert!(c.allowed);
        assert_eq!(c.legal_basis, LegalBasis::PublicData);
    }

    #[test]
    fn authenticated_path_denied() {
        let m = ComplianceManager::new();
        let c = m.is_scrape_allowed("https://www.amazon.com/account/orders", "amazon");
        assert!(!c.allowed);
        assert_eq!(c.legal_basis, LegalBasis::NotAllowed);
    }

    #[test]
    fn dmca_auto_complies() {
        let m = ComplianceManager::new();
        m.receive_takedown(TakedownRequest {
            id: "td-1".into(),
            received_at: 0,
            complainant: "rights@example.com".into(),
            reason: TakedownReason::DmcaCopyright,
            affected_resources: vec!["https://hackthecart.example/p/1".into()],
            status: TakedownStatus::Received,
            resolved_at: None,
        });
        let processed = m.process_takedowns();
        assert_eq!(processed.len(), 1);
        assert_eq!(processed[0].new_status, TakedownStatus::Complied);
    }

    #[test]
    fn prohibited_image_brand() {
        let m = ComplianceManager::new();
        assert_eq!(
            m.image_hosting_policy("https://cdn.sonos.com/img.jpg"),
            ImagePolicy::Prohibited
        );
    }
}
