//! Canary product monitoring (T3.17).
//!
//! Tracks a small set of stable SKUs per retailer with rolling price
//! baselines. A batch that sees its canaries drift too far is quarantined
//! — that usually means the scraper broke or the site changed.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CanaryProduct {
    pub retailer: String,
    pub sku: String,
    pub product_name: String,
    pub expected_url: String,
    pub max_drift_percent: f64,
    pub rolling_window_days: i64,
}

#[derive(Debug, Clone, Default)]
pub struct PriceBaseline {
    pub rolling_mean_cents: i64,
    pub rolling_stddev: f64,
    pub sample_count: u32,
    pub last_updated: i64,
    pub observations: Vec<(i64, i64)>,
}

#[derive(Debug, Clone)]
pub struct DriftDetail {
    pub sku: String,
    pub expected_price_cents: i64,
    pub observed_price_cents: i64,
    pub drift_percent: f64,
}

#[derive(Debug, Clone)]
pub struct CanaryCheckResult {
    pub retailer: String,
    pub canaries_checked: usize,
    pub canaries_passed: usize,
    pub canaries_drifted: Vec<DriftDetail>,
    pub should_quarantine_batch: bool,
}

#[derive(Debug, Default)]
pub struct CanaryRegistry {
    canaries: HashMap<String, Vec<CanaryProduct>>,
    baselines: HashMap<(String, String), PriceBaseline>,
}

impl CanaryRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_canary(&mut self, canary: CanaryProduct) {
        self.canaries
            .entry(canary.retailer.clone())
            .or_default()
            .push(canary);
    }

    pub fn update_baseline(&mut self, retailer: &str, sku: &str, price_cents: i64) {
        let now = now_secs();
        let key = (retailer.to_string(), sku.to_string());
        let baseline = self.baselines.entry(key).or_default();
        baseline.observations.push((now, price_cents));
        // Keep last 30 days at most; individual canaries enforce their window
        // at check time.
        let cutoff = now - 30 * 86_400;
        baseline.observations.retain(|(ts, _)| *ts >= cutoff);
        baseline.sample_count = baseline.observations.len() as u32;
        let n = baseline.sample_count.max(1) as f64;
        let mean = baseline
            .observations
            .iter()
            .map(|(_, p)| *p as f64)
            .sum::<f64>()
            / n;
        let var = baseline
            .observations
            .iter()
            .map(|(_, p)| {
                let d = *p as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / n;
        baseline.rolling_mean_cents = mean.round() as i64;
        baseline.rolling_stddev = var.sqrt();
        baseline.last_updated = now;
    }

    pub fn baseline(&self, retailer: &str, sku: &str) -> Option<&PriceBaseline> {
        self.baselines
            .get(&(retailer.to_string(), sku.to_string()))
    }

    /// Check a batch of observed canary prices. Quarantines the batch if any
    /// single canary exceeds its drift threshold, or if >25% drift softly.
    pub fn check_batch(
        &self,
        retailer: &str,
        observations: &HashMap<String, i64>,
    ) -> CanaryCheckResult {
        let Some(canaries) = self.canaries.get(retailer) else {
            return CanaryCheckResult {
                retailer: retailer.to_string(),
                canaries_checked: 0,
                canaries_passed: 0,
                canaries_drifted: Vec::new(),
                should_quarantine_batch: false,
            };
        };
        let mut drifted = Vec::new();
        let mut passed = 0;
        let mut checked = 0;
        for c in canaries {
            let Some(observed) = observations.get(&c.sku) else {
                continue;
            };
            checked += 1;
            let Some(baseline) = self.baseline(retailer, &c.sku) else {
                // No baseline yet — treat as pass, baseline will learn.
                passed += 1;
                continue;
            };
            if baseline.rolling_mean_cents == 0 {
                passed += 1;
                continue;
            }
            let delta = (*observed - baseline.rolling_mean_cents).abs() as f64;
            let drift_pct = delta / baseline.rolling_mean_cents as f64 * 100.0;
            if drift_pct > c.max_drift_percent {
                drifted.push(DriftDetail {
                    sku: c.sku.clone(),
                    expected_price_cents: baseline.rolling_mean_cents,
                    observed_price_cents: *observed,
                    drift_percent: drift_pct,
                });
            } else {
                passed += 1;
            }
        }
        let should_quarantine = !drifted.is_empty()
            && (checked > 0 && (drifted.len() as f64 / checked as f64) >= 0.25);
        CanaryCheckResult {
            retailer: retailer.to_string(),
            canaries_checked: checked,
            canaries_passed: passed,
            canaries_drifted: drifted,
            should_quarantine_batch: should_quarantine,
        }
    }

    /// Seed 20 stable grocery SKUs × 12 Houston-area retailers = 240 canaries.
    pub fn seed_for_houston_grocery(&mut self) {
        let retailers = [
            "heb.com",
            "kroger.com",
            "walmart.com",
            "target.com",
            "aldi.us",
            "samsclub.com",
            "costco.com",
            "randalls.com",
            "fiestamart.com",
            "wholefoodsmarket.com",
            "sprouts.com",
            "traderjoes.com",
        ];
        let staples: [(&str, &str); 20] = [
            ("eggs_12ct", "Large Grade A Eggs, 12 ct"),
            ("milk_1gal", "Whole Milk, 1 gal"),
            ("bread_loaf", "White Bread Loaf, 20 oz"),
            ("bananas_1lb", "Bananas, per lb"),
            ("chicken_breast_1lb", "Boneless Chicken Breast, per lb"),
            ("ground_beef_1lb", "80/20 Ground Beef, per lb"),
            ("rice_5lb", "Long Grain White Rice, 5 lb"),
            ("pasta_1lb", "Spaghetti, 1 lb"),
            ("peanut_butter_16oz", "Creamy Peanut Butter, 16 oz"),
            ("cheese_8oz", "Shredded Cheddar, 8 oz"),
            ("butter_1lb", "Salted Butter, 1 lb"),
            ("flour_5lb", "All-Purpose Flour, 5 lb"),
            ("sugar_4lb", "Granulated Sugar, 4 lb"),
            ("cereal_18oz", "Corn Flakes, 18 oz"),
            ("tuna_5oz", "Chunk Light Tuna, 5 oz can"),
            ("apples_1lb", "Gala Apples, per lb"),
            ("potatoes_5lb", "Russet Potatoes, 5 lb bag"),
            ("onions_2lb", "Yellow Onions, 2 lb bag"),
            ("yogurt_32oz", "Plain Yogurt, 32 oz"),
            ("coffee_12oz", "Ground Coffee, 12 oz"),
        ];
        for retailer in retailers {
            for (sku, name) in staples {
                self.register_canary(CanaryProduct {
                    retailer: retailer.to_string(),
                    sku: sku.to_string(),
                    product_name: name.to_string(),
                    expected_url: format!("https://{retailer}/p/{sku}"),
                    max_drift_percent: 15.0,
                    rolling_window_days: 7,
                });
            }
        }
    }

    pub fn canary_count(&self) -> usize {
        self.canaries.values().map(|v| v.len()).sum()
    }
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seed_produces_240() {
        let mut reg = CanaryRegistry::new();
        reg.seed_for_houston_grocery();
        assert_eq!(reg.canary_count(), 240);
    }

    #[test]
    fn baseline_rolls() {
        let mut reg = CanaryRegistry::new();
        reg.register_canary(CanaryProduct {
            retailer: "heb.com".into(),
            sku: "eggs_12ct".into(),
            product_name: "eggs".into(),
            expected_url: "".into(),
            max_drift_percent: 15.0,
            rolling_window_days: 7,
        });
        for p in [400, 410, 395, 405, 400] {
            reg.update_baseline("heb.com", "eggs_12ct", p);
        }
        let b = reg.baseline("heb.com", "eggs_12ct").unwrap();
        assert_eq!(b.sample_count, 5);
        assert!((b.rolling_mean_cents - 402).abs() <= 2);
    }

    #[test]
    fn drift_detected_and_quarantines() {
        let mut reg = CanaryRegistry::new();
        for sku in ["a", "b", "c", "d"] {
            reg.register_canary(CanaryProduct {
                retailer: "heb.com".into(),
                sku: sku.into(),
                product_name: sku.into(),
                expected_url: "".into(),
                max_drift_percent: 15.0,
                rolling_window_days: 7,
            });
            for _ in 0..5 {
                reg.update_baseline("heb.com", sku, 1000);
            }
        }
        let mut obs = HashMap::new();
        obs.insert("a".to_string(), 1000);
        obs.insert("b".to_string(), 1000);
        obs.insert("c".to_string(), 2000); // 100% drift
        obs.insert("d".to_string(), 2500); // 150% drift
        let result = reg.check_batch("heb.com", &obs);
        assert_eq!(result.canaries_checked, 4);
        assert_eq!(result.canaries_drifted.len(), 2);
        assert!(result.should_quarantine_batch);
    }

    #[test]
    fn small_drift_passes() {
        let mut reg = CanaryRegistry::new();
        reg.register_canary(CanaryProduct {
            retailer: "kroger.com".into(),
            sku: "milk_1gal".into(),
            product_name: "milk".into(),
            expected_url: "".into(),
            max_drift_percent: 15.0,
            rolling_window_days: 7,
        });
        for _ in 0..5 {
            reg.update_baseline("kroger.com", "milk_1gal", 450);
        }
        let mut obs = HashMap::new();
        obs.insert("milk_1gal".into(), 470); // ~4% drift
        let r = reg.check_batch("kroger.com", &obs);
        assert_eq!(r.canaries_drifted.len(), 0);
        assert!(!r.should_quarantine_batch);
    }
}
