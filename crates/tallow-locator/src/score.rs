//! Deterministic scoring: cost · latency · jurisdiction · capability.
//!
//! Everything here is pure and synchronous — same input ⇒ same output ⇒ same
//! scorecard digest (determinism is a tested property).
//!
//! Honest v1 limits: latency uses a **static baselines table** (region →
//! representative RTT from the anchor box); live RIPE-Atlas baselines are a
//! follow-up. The jurisdiction table is a v1 static mapping (ruling 6.5) and
//! is deliberately conservative: **unknown country ⇒ excluded in every class**
//! (fail closed, no guessing).

use crate::model::{JobClass, Offer};
use serde::{Deserialize, Serialize};

/// Model version tag — travels in receipts so a scorecard is reproducible
/// against an explicit model revision.
pub const MODEL_V: &str = "locator-model/v1";

/// Relative weights (normalized to sum 1.0 by [`ScoringModel::new`]).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Weights {
    pub cost: f64,
    pub latency: f64,
    pub jurisdiction: f64,
    pub capability: f64,
}

impl Default for Weights {
    fn default() -> Self {
        Self {
            cost: 0.35,
            latency: 0.25,
            jurisdiction: 0.25,
            capability: 0.15,
        }
    }
}

/// Hard floors — an offer failing any of these is excluded before scoring.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct Floors {
    pub max_price_eur: f64,
    pub min_vcpu: u32,
    pub min_mem_mb: u32,
    /// A chosen offer must reach this total (0–100) or the run refuses.
    pub min_score: f64,
}

impl Default for Floors {
    fn default() -> Self {
        Self {
            max_price_eur: 10.0,
            min_vcpu: 1,
            min_mem_mb: 1024,
            min_score: 45.0,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ScoringModel {
    pub weights: Weights,
    pub floors: Floors,
}

impl Default for ScoringModel {
    fn default() -> Self {
        Self {
            weights: Weights::default(),
            floors: Floors::default(),
        }
    }
}

/// Why an offer was excluded (fail-close accounting; carried into receipts).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Exclusion {
    UnknownCountry(String),
    Jurisdiction {
        country: String,
        tier: u8,
        class: JobClass,
    },
    Price {
        price: f64,
        max: f64,
    },
    Capability {
        detail: String,
    },
}

impl Exclusion {
    /// Stable machine key for breakdown maps.
    pub fn key(&self) -> &'static str {
        match self {
            Exclusion::UnknownCountry(_) => "unknown_country",
            Exclusion::Jurisdiction { .. } => "jurisdiction",
            Exclusion::Price { .. } => "price",
            Exclusion::Capability { .. } => "capability",
        }
    }

    pub fn detail(&self) -> String {
        match self {
            Exclusion::UnknownCountry(c) => format!("unknown jurisdiction: {c}"),
            Exclusion::Jurisdiction {
                country,
                tier,
                class,
            } => {
                format!("{country} tier {tier} > max for class {}", class.as_str())
            }
            Exclusion::Price { price, max } => {
                format!("price {price:.2} EUR > max {max:.2} EUR")
            }
            Exclusion::Capability { detail } => detail.clone(),
        }
    }
}

/// A scored offer.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Score {
    /// Weighted total, 0–100, 2 decimals.
    pub total: f64,
    pub cost: f64,
    pub latency: f64,
    pub jurisdiction: f64,
    pub capability: f64,
}

/// v1 jurisdiction tiers (static; amendable by operator ruling).
/// 1 = privacy-preferred (IS) · 2 = EU/EEA + CH + UK · 3 = permissive-only.
pub fn jurisdiction_tier(country: &str) -> Option<u8> {
    let c = country.to_uppercase();
    match c.as_str() {
        "IS" => Some(1),
        "CH" | "NO" | "LI" => Some(2),
        "AT" | "BE" | "BG" | "HR" | "CY" | "CZ" | "DK" | "EE" | "FI" | "FR" | "DE" | "GR"
        | "HU" | "IE" | "IT" | "LV" | "LT" | "LU" | "MT" | "NL" | "PL" | "PT" | "RO" | "SK"
        | "SI" | "ES" | "SE" | "GB" => Some(2),
        "US" | "CA" | "SG" | "AU" | "JP" | "KR" | "IN" | "BR" | "AE" | "ZA" => Some(3),
        _ => None,
    }
}

/// Static latency baselines (ms RTT from the anchor box, hel1). `None` region
/// ⇒ a mediocre default score (documented, not guessed-silent).
pub fn baseline_rtt_ms(region: &str) -> Option<u32> {
    match region.to_lowercase().as_str() {
        "hel1" | "hel" => Some(3),
        "sto" | "sto1" => Some(22),
        "nbg1" | "nbg" => Some(28),
        "fra" | "fra1" | "fsn1" | "fsn" => Some(30),
        "ams" | "ams3" | "ams1" => Some(32),
        "par" | "par1" | "gra" => Some(36),
        "lon" | "lhr" | "lhr1" => Some(38),
        "mad" => Some(52),
        "ash" | "ash-hillsboro" | "ashburn" => Some(112),
        "ewr" | "nyc" | "nyc1" | "nyc3" => Some(118),
        "tor" | "yyz" => Some(115),
        "blr" | "sfo" | "sfo3" => Some(178),
        "lax" | "lax1" => Some(188),
        "sgp" | "sgp1" | "sin" => Some(180),
        "blr1" => Some(210),
        "syd" | "syd1" => Some(260),
        _ => None,
    }
}

fn clamp01(x: f64) -> f64 {
    x.clamp(0.0, 1.0)
}

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// Score one offer under a model. `Err(Exclusion)` when the offer is not
/// compliant (the caller accounts every exclusion; nothing is dropped).
pub fn score_offer(
    offer: &Offer,
    class: JobClass,
    model: &ScoringModel,
) -> Result<Score, Exclusion> {
    // 1. Jurisdiction (fail closed: unknown ⇒ out).
    let cc = offer.country.to_uppercase();
    let tier = jurisdiction_tier(&cc).ok_or_else(|| Exclusion::UnknownCountry(cc.clone()))?;
    if tier > class.max_tier() {
        return Err(Exclusion::Jurisdiction {
            country: cc,
            tier,
            class,
        });
    }
    // 2. Floors.
    if offer.price_month_eur > model.floors.max_price_eur {
        return Err(Exclusion::Price {
            price: offer.price_month_eur,
            max: model.floors.max_price_eur,
        });
    }
    if offer.vcpu < model.floors.min_vcpu {
        return Err(Exclusion::Capability {
            detail: format!("{} vcpu < min {}", offer.vcpu, model.floors.min_vcpu),
        });
    }
    if offer.mem_mb < model.floors.min_mem_mb {
        return Err(Exclusion::Capability {
            detail: format!("{} MB < min {} MB", offer.mem_mb, model.floors.min_mem_mb),
        });
    }

    // 3. Component scores (0–1).
    let cost =
        clamp01((model.floors.max_price_eur - offer.price_month_eur) / model.floors.max_price_eur);
    let latency = match baseline_rtt_ms(&offer.region) {
        Some(ms) => clamp01(1.0 - (ms as f64) / 200.0),
        None => 0.30, // unknown region baseline: mediocre, documented
    };
    let jurisdiction = match tier {
        1 => 1.0,
        2 => 0.8,
        _ => 0.4,
    };
    let capability = clamp01((offer.vcpu as f64 / model.floors.min_vcpu.max(1) as f64) / 3.0);

    let w = &model.weights;
    let total = (cost * w.cost
        + latency * w.latency
        + jurisdiction * w.jurisdiction
        + capability * w.capability)
        * 100.0;
    Ok(Score {
        total: round2(total),
        cost: round2(cost),
        latency: round2(latency),
        jurisdiction: round2(jurisdiction),
        capability: round2(capability),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn offer(country: &str, region: &str, price: f64, vcpu: u32, mem: u32) -> Offer {
        Offer {
            provider: "t".into(),
            plan: "p".into(),
            region: region.into(),
            city: "c".into(),
            country: country.into(),
            price_month_eur: price,
            vcpu,
            mem_mb: mem,
            disk_gb: 40,
            arch: "x86_64".into(),
            source_id: "1".into(),
        }
    }

    #[test]
    fn us_excluded_for_privacy_allowed_for_relay() {
        let o = offer("US", "ash", 5.0, 2, 4096);
        let m = ScoringModel::default();
        assert!(matches!(
            score_offer(&o, JobClass::Privacy, &m),
            Err(Exclusion::Jurisdiction { .. })
        ));
        assert!(score_offer(&o, JobClass::Relay, &m).is_ok());
    }

    #[test]
    fn unknown_country_fails_closed_everywhere() {
        let o = offer("XX", "xx1", 5.0, 2, 4096);
        let m = ScoringModel::default();
        for c in [JobClass::Privacy, JobClass::Relay, JobClass::General] {
            assert!(matches!(
                score_offer(&o, c, &m),
                Err(Exclusion::UnknownCountry(_))
            ));
        }
    }

    #[test]
    fn price_floor_and_capability_floor() {
        let m = ScoringModel::default();
        let too_pricey = offer("FI", "hel1", 11.0, 2, 4096);
        assert!(matches!(
            score_offer(&too_pricey, JobClass::Privacy, &m),
            Err(Exclusion::Price { .. })
        ));
        let too_small = offer("FI", "hel1", 4.0, 1, 512);
        assert!(matches!(
            score_offer(&too_small, JobClass::Privacy, &m),
            Err(Exclusion::Capability { .. })
        ));
    }

    #[test]
    fn cost_is_monotonic() {
        let m = ScoringModel::default();
        let cheap = offer("FI", "hel1", 3.0, 2, 4096);
        let dear = offer("FI", "hel1", 9.0, 2, 4096);
        let sc = score_offer(&cheap, JobClass::Privacy, &m).unwrap().total;
        let sd = score_offer(&dear, JobClass::Privacy, &m).unwrap().total;
        assert!(sc > sd, "cheap {sc} should beat dear {sd}");
    }

    #[test]
    fn iceland_beats_germany_all_else_equal() {
        let m = ScoringModel::default();
        let is = offer("IS", "hel1", 5.0, 2, 4096);
        let de = offer("DE", "fsn1", 5.0, 2, 4096);
        let s_is = score_offer(&is, JobClass::Privacy, &m).unwrap().total;
        let s_de = score_offer(&de, JobClass::Privacy, &m).unwrap().total;
        assert!(s_is > s_de, "IS {s_is} should beat DE {s_de}");
    }

    #[test]
    fn determinism_same_input_same_scores() {
        let m = ScoringModel::default();
        let o = offer("FI", "hel1", 4.35, 2, 4096);
        let a = score_offer(&o, JobClass::Privacy, &m).unwrap();
        let b = score_offer(&o, JobClass::Privacy, &m).unwrap();
        assert_eq!(a, b);
    }
}
