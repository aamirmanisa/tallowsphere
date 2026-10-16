//! Logged-out vs logged-in auth strategy registry (T3.25).
//!
//! Encodes per-retailer policy on when it's safe to authenticate before
//! scraping and what data types require which auth state.

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthState {
    LoggedOut,
    LoggedIn,
    Guest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    None,
    Low,
    Medium,
    High,
    Prohibited,
}

#[derive(Debug, Clone)]
pub struct ScrapeTactic {
    pub data_type: String,
    pub required_auth: AuthState,
    pub risk_level: RiskLevel,
    pub notes: String,
}

#[derive(Debug, Clone)]
pub struct AuthStrategy {
    pub retailer: String,
    pub default_state: AuthState,
    pub login_benefits: Vec<String>,
    pub login_risks: Vec<String>,
    pub scrape_tactics: Vec<ScrapeTactic>,
}

pub struct AuthStrategyRegistry {
    strategies: HashMap<String, AuthStrategy>,
}

impl AuthStrategyRegistry {
    pub fn new() -> Self {
        Self {
            strategies: HashMap::new(),
        }
    }

    pub fn add(&mut self, s: AuthStrategy) {
        self.strategies.insert(s.retailer.clone(), s);
    }

    pub fn get(&self, retailer: &str) -> Option<&AuthStrategy> {
        self.strategies.get(retailer)
    }

    pub fn recommend_auth(&self, retailer: &str, data_type: &str) -> Option<ScrapeTactic> {
        self.strategies
            .get(retailer)?
            .scrape_tactics
            .iter()
            .find(|t| t.data_type == data_type)
            .cloned()
    }

    pub fn is_safe_to_scrape(&self, retailer: &str, data_type: &str) -> bool {
        match self.recommend_auth(retailer, data_type) {
            Some(t) => !matches!(t.risk_level, RiskLevel::Prohibited),
            None => false,
        }
    }

    pub fn seed_defaults(&mut self) {
        self.add(AuthStrategy {
            retailer: "amazon".into(),
            default_state: AuthState::LoggedOut,
            login_benefits: vec!["Prime prices".into(), "1-click info".into()],
            login_risks: vec!["Account ban".into(), "CAPTCHA escalation".into()],
            scrape_tactics: vec![
                ScrapeTactic {
                    data_type: "catalog".into(),
                    required_auth: AuthState::LoggedOut,
                    risk_level: RiskLevel::Low,
                    notes: "Public product pages".into(),
                },
                ScrapeTactic {
                    data_type: "prime_price".into(),
                    required_auth: AuthState::LoggedIn,
                    risk_level: RiskLevel::Prohibited,
                    notes: "Never log in to Amazon - account ban risk".into(),
                },
            ],
        });

        self.add(AuthStrategy {
            retailer: "costco".into(),
            default_state: AuthState::LoggedOut,
            login_benefits: vec!["Member prices".into(), "Warehouse inventory".into()],
            login_risks: vec!["Membership revoked".into()],
            scrape_tactics: vec![
                ScrapeTactic {
                    data_type: "catalog".into(),
                    required_auth: AuthState::LoggedOut,
                    risk_level: RiskLevel::Medium,
                    notes: "Public catalog - use headed Chrome with warmup".into(),
                },
                ScrapeTactic {
                    data_type: "member_prices".into(),
                    required_auth: AuthState::LoggedIn,
                    risk_level: RiskLevel::Prohibited,
                    notes: "Use Instacart as proxy for member data".into(),
                },
            ],
        });

        self.add(AuthStrategy {
            retailer: "walmart".into(),
            default_state: AuthState::LoggedOut,
            login_benefits: vec!["Walmart+ pricing".into()],
            login_risks: vec!["Account flags".into()],
            scrape_tactics: vec![ScrapeTactic {
                data_type: "catalog".into(),
                required_auth: AuthState::LoggedOut,
                risk_level: RiskLevel::Low,
                notes: "Public catalog accessible".into(),
            }],
        });

        self.add(AuthStrategy {
            retailer: "target".into(),
            default_state: AuthState::LoggedOut,
            login_benefits: vec!["Circle offers".into()],
            login_risks: vec!["Account lockouts".into()],
            scrape_tactics: vec![ScrapeTactic {
                data_type: "catalog".into(),
                required_auth: AuthState::LoggedOut,
                risk_level: RiskLevel::Low,
                notes: "Public redsky API usable".into(),
            }],
        });

        self.add(AuthStrategy {
            retailer: "kroger".into(),
            default_state: AuthState::Guest,
            login_benefits: vec!["Loyalty prices".into()],
            login_risks: vec!["Loyalty card ban".into()],
            scrape_tactics: vec![ScrapeTactic {
                data_type: "catalog".into(),
                required_auth: AuthState::Guest,
                risk_level: RiskLevel::Medium,
                notes: "Requires ZIP selection".into(),
            }],
        });

        self.add(AuthStrategy {
            retailer: "bestbuy".into(),
            default_state: AuthState::LoggedOut,
            login_benefits: vec!["My Best Buy pricing".into()],
            login_risks: vec!["Account ban".into()],
            scrape_tactics: vec![ScrapeTactic {
                data_type: "catalog".into(),
                required_auth: AuthState::LoggedOut,
                risk_level: RiskLevel::Medium,
                notes: "Akamai bot detection".into(),
            }],
        });

        self.add(AuthStrategy {
            retailer: "homedepot".into(),
            default_state: AuthState::LoggedOut,
            login_benefits: vec!["Pro pricing".into()],
            login_risks: vec!["Pro account revoked".into()],
            scrape_tactics: vec![ScrapeTactic {
                data_type: "catalog".into(),
                required_auth: AuthState::LoggedOut,
                risk_level: RiskLevel::Low,
                notes: "Public catalog".into(),
            }],
        });

        self.add(AuthStrategy {
            retailer: "samsclub".into(),
            default_state: AuthState::LoggedOut,
            login_benefits: vec!["Member pricing".into()],
            login_risks: vec!["Membership revoked".into()],
            scrape_tactics: vec![ScrapeTactic {
                data_type: "catalog".into(),
                required_auth: AuthState::LoggedOut,
                risk_level: RiskLevel::Medium,
                notes: "Limited public catalog".into(),
            }],
        });

        self.add(AuthStrategy {
            retailer: "aldi".into(),
            default_state: AuthState::LoggedOut,
            login_benefits: vec![],
            login_risks: vec![],
            scrape_tactics: vec![ScrapeTactic {
                data_type: "catalog".into(),
                required_auth: AuthState::LoggedOut,
                risk_level: RiskLevel::Low,
                notes: "Public weekly specials".into(),
            }],
        });

        self.add(AuthStrategy {
            retailer: "heb".into(),
            default_state: AuthState::Guest,
            login_benefits: vec!["Curbside prices".into()],
            login_risks: vec!["Account ban".into()],
            scrape_tactics: vec![ScrapeTactic {
                data_type: "catalog".into(),
                required_auth: AuthState::Guest,
                risk_level: RiskLevel::Medium,
                notes: "Requires store selection".into(),
            }],
        });
    }
}

impl Default for AuthStrategyRegistry {
    fn default() -> Self {
        let mut r = Self::new();
        r.seed_defaults();
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seeds_expected_retailers() {
        let r = AuthStrategyRegistry::default();
        for name in [
            "amazon",
            "costco",
            "walmart",
            "target",
            "kroger",
            "bestbuy",
            "homedepot",
            "samsclub",
            "aldi",
            "heb",
        ] {
            assert!(r.get(name).is_some(), "missing {}", name);
        }
    }

    #[test]
    fn amazon_prime_prohibited() {
        let r = AuthStrategyRegistry::default();
        assert!(!r.is_safe_to_scrape("amazon", "prime_price"));
        assert!(r.is_safe_to_scrape("amazon", "catalog"));
    }

    #[test]
    fn recommend_auth_state() {
        let r = AuthStrategyRegistry::default();
        let t = r.recommend_auth("costco", "catalog").unwrap();
        assert_eq!(t.required_auth, AuthState::LoggedOut);
        assert_eq!(t.risk_level, RiskLevel::Medium);
    }

    #[test]
    fn unknown_retailer_not_safe() {
        let r = AuthStrategyRegistry::default();
        assert!(!r.is_safe_to_scrape("unknown", "catalog"));
    }
}
