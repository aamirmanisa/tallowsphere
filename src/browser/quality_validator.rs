//! Data quality validation engine for scraped price observations.
//!
//! Catches silently-wrong scrape data before it pollutes the database.
//! Multiple tiers: schema contract, category bounds, z-score outliers,
//! MAD (robust), percent-change gate, canary drift, cross-source
//! triangulation, and locale/currency sanity.

use std::collections::HashMap;

// ---------- Core types ----------

#[derive(Debug, Clone)]
pub struct PriceObservation {
    pub sku: String,
    pub canonical_id: i64,
    pub store_id: i64,
    pub source: String,
    pub category: String,
    pub price_cents: i64,
    pub raw_price_string: String,
    pub currency: String,
    pub url: String,
    pub observed_at: i64, // unix seconds
    pub batch_id: String,
}

#[derive(Debug, Clone)]
pub struct CanonicalProduct {
    pub canonical_id: i64,
    pub category: String,
    pub title: String,
}

#[derive(Debug, Clone)]
pub struct PriceBounds {
    pub category: String,
    pub min_cents: i64,
    pub max_cents: i64,
    pub typical_min: i64,
    pub typical_max: i64,
}

#[derive(Debug, Clone)]
pub struct CanaryProduct {
    pub canonical_id: i64,
    pub store_id: i64,
    pub baseline_price_cents: i64,
    pub baseline_observed_at: i64,
    pub max_drift_percent: f64,
}

#[derive(Debug, Clone, Default)]
pub struct PriceHistoryStore {
    /// canonical_id -> chronological price history (cents)
    history: HashMap<i64, Vec<i64>>,
    /// canonical_id -> most recent observation
    last: HashMap<i64, i64>,
    /// batch_id -> canary observations seen in batch
    canary_batches: HashMap<String, Vec<(i64, i64)>>, // (canonical_id, price)
}

impl PriceHistoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record(&mut self, canonical_id: i64, price: i64) {
        self.history.entry(canonical_id).or_default().push(price);
        self.last.insert(canonical_id, price);
    }

    pub fn history_for(&self, canonical_id: i64) -> &[i64] {
        self.history
            .get(&canonical_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }

    pub fn last_for(&self, canonical_id: i64) -> Option<i64> {
        self.last.get(&canonical_id).copied()
    }

    pub fn record_canary_in_batch(&mut self, batch_id: &str, canonical_id: i64, price: i64) {
        self.canary_batches
            .entry(batch_id.to_string())
            .or_default()
            .push((canonical_id, price));
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum ValidationStatus {
    Pass,
    Quarantine,
    Reject,
}

#[derive(Debug, Clone)]
pub struct ValidationResult {
    pub status: ValidationStatus,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    pub confidence_adjustment: f64,
}

impl ValidationResult {
    fn new() -> Self {
        Self {
            status: ValidationStatus::Pass,
            warnings: Vec::new(),
            errors: Vec::new(),
            confidence_adjustment: 1.0,
        }
    }

    fn reject(&mut self, msg: impl Into<String>) {
        self.errors.push(msg.into());
        self.status = ValidationStatus::Reject;
        self.confidence_adjustment = 0.0;
    }

    fn quarantine(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
        if self.status == ValidationStatus::Pass {
            self.status = ValidationStatus::Quarantine;
        }
        self.confidence_adjustment *= 0.5;
    }

    fn warn(&mut self, msg: impl Into<String>) {
        self.warnings.push(msg.into());
        self.confidence_adjustment *= 0.85;
    }
}

// ---------- Default category bounds ----------

pub fn default_category_bounds() -> Vec<PriceBounds> {
    let b = |category: &str, min: i64, max: i64, tmin: i64, tmax: i64| PriceBounds {
        category: category.to_string(),
        min_cents: min,
        max_cents: max,
        typical_min: tmin,
        typical_max: tmax,
    };
    vec![
        b("tv", 8_000, 30_000_00, 150_00, 5_000_00),
        b("headphones", 5_00, 5_000_00, 20_00, 500_00),
        b("laptop", 100_00, 20_000_00, 400_00, 3_500_00),
        b("phone", 50_00, 5_000_00, 150_00, 1_800_00),
        b("tablet", 50_00, 5_000_00, 100_00, 1_500_00),
        b("monitor", 50_00, 10_000_00, 100_00, 1_500_00),
        b("keyboard", 5_00, 1_000_00, 15_00, 300_00),
        b("mouse", 3_00, 500_00, 10_00, 150_00),
        b("gpu", 100_00, 10_000_00, 200_00, 3_000_00),
        b("cpu", 50_00, 5_000_00, 100_00, 1_500_00),
        b("ssd", 10_00, 3_000_00, 30_00, 500_00),
        b("ram", 10_00, 2_000_00, 30_00, 500_00),
        b("console", 100_00, 2_000_00, 200_00, 700_00),
        b("game", 1_00, 200_00, 10_00, 80_00),
        b("book", 1_00, 500_00, 5_00, 50_00),
        b("groceries", 25, 500_00, 99, 50_00),
        b("eggs", 99, 30_00, 2_00, 12_00),
        b("milk", 99, 15_00, 2_00, 8_00),
        b("bread", 50, 20_00, 1_50, 8_00),
        b("cheese", 1_00, 100_00, 3_00, 20_00),
        b("meat", 1_00, 200_00, 5_00, 50_00),
        b("produce", 25, 50_00, 50, 15_00),
        b("cereal", 1_00, 30_00, 2_00, 10_00),
        b("coffee", 2_00, 100_00, 5_00, 30_00),
        b("soda", 50, 30_00, 1_00, 10_00),
        b("shampoo", 1_00, 50_00, 3_00, 20_00),
        b("toothpaste", 99, 20_00, 2_00, 8_00),
        b("detergent", 2_00, 60_00, 5_00, 25_00),
        b("shoes", 5_00, 2_000_00, 20_00, 300_00),
        b("shirt", 3_00, 500_00, 10_00, 100_00),
        b("pants", 5_00, 1_000_00, 15_00, 150_00),
        b("jacket", 10_00, 5_000_00, 30_00, 500_00),
        b("watch", 5_00, 50_000_00, 30_00, 1_000_00),
        b("toy", 1_00, 500_00, 5_00, 80_00),
        b("furniture", 10_00, 10_000_00, 50_00, 2_000_00),
        b("mattress", 50_00, 10_000_00, 200_00, 2_000_00),
        b("appliance", 20_00, 10_000_00, 100_00, 2_000_00),
        b("vacuum", 20_00, 3_000_00, 50_00, 800_00),
        b("microwave", 30_00, 2_000_00, 60_00, 500_00),
        b("refrigerator", 200_00, 15_000_00, 400_00, 3_000_00),
        b("dishwasher", 150_00, 5_000_00, 300_00, 1_500_00),
        b("camera", 30_00, 20_000_00, 100_00, 3_000_00),
        b("lens", 50_00, 15_000_00, 150_00, 2_500_00),
        b("speaker", 10_00, 5_000_00, 30_00, 800_00),
        b("bike", 50_00, 15_000_00, 150_00, 3_000_00),
        b("tire", 20_00, 2_000_00, 50_00, 400_00),
        b("tool", 3_00, 2_000_00, 15_00, 300_00),
        b("battery", 1_00, 500_00, 3_00, 80_00),
        b("charger", 3_00, 300_00, 10_00, 80_00),
        b("cable", 1_00, 200_00, 5_00, 50_00),
    ]
}

// ---------- Validator ----------

pub struct QualityValidator {
    pub bounds: HashMap<String, PriceBounds>,
    pub canaries: Vec<CanaryProduct>,
    pub history: PriceHistoryStore,
}

impl Default for QualityValidator {
    fn default() -> Self {
        Self::new()
    }
}

impl QualityValidator {
    pub fn new() -> Self {
        let mut bounds = HashMap::new();
        for b in default_category_bounds() {
            bounds.insert(b.category.clone(), b);
        }
        Self {
            bounds,
            canaries: Vec::new(),
            history: PriceHistoryStore::new(),
        }
    }

    pub fn with_canaries(mut self, canaries: Vec<CanaryProduct>) -> Self {
        self.canaries = canaries;
        self
    }

    pub fn validate(
        &self,
        observation: &PriceObservation,
        product: &CanonicalProduct,
    ) -> ValidationResult {
        let mut result = ValidationResult::new();

        // 1. Schema contract
        let schema_errs = self.check_schema(observation);
        for e in schema_errs {
            result.reject(e);
        }
        if result.status == ValidationStatus::Reject {
            return result;
        }

        // 8. Locale/currency sanity
        if let Some(msg) = self.check_locale(observation) {
            result.reject(msg);
            return result;
        }

        // 2. Category bounds
        let bound_msgs = self.check_bounds(observation, &product.category);
        for m in bound_msgs {
            // hard vs soft is encoded in prefix
            if let Some(rest) = m.strip_prefix("HARD:") {
                result.reject(rest.to_string());
            } else if let Some(rest) = m.strip_prefix("SOFT:") {
                result.warn(rest.to_string());
            }
        }
        if result.status == ValidationStatus::Reject {
            return result;
        }

        let history = self.history.history_for(observation.canonical_id);

        // 3. Z-score
        if let Some(z) = self.check_zscore(observation, history) {
            if z.abs() > 4.0 {
                result.quarantine(format!(
                    "z-score {:.2} exceeds ±4 (historical outlier)",
                    z
                ));
            } else if z.abs() > 3.0 {
                result.warn(format!("z-score {:.2} exceeds ±3", z));
            }
        }

        // 4. MAD
        if let Some(mz) = self.check_mad(observation, history) {
            if mz.abs() > 5.0 {
                result.quarantine(format!(
                    "modified z-score {:.2} exceeds ±5 (MAD outlier)",
                    mz
                ));
            }
        }

        // 5. Percent change gate
        if let Some(last) = self.history.last_for(observation.canonical_id) {
            if let Some(pct) = self.check_percent_change(observation.price_cents, last) {
                if pct.abs() > 50.0 {
                    result.quarantine(format!(
                        "price changed {:.1}% vs last observation — re-scrape",
                        pct
                    ));
                } else if pct.abs() > 25.0 {
                    result.warn(format!("price changed {:.1}% vs last observation", pct));
                }
            }
        }

        // 6. Canary check for this batch
        if !self.check_canaries(&observation.batch_id) {
            result.quarantine(format!(
                "canary drift detected for batch {} — scraper may be broken",
                observation.batch_id
            ));
        }

        result
    }

    // 1. Schema contract
    pub fn check_schema(&self, obs: &PriceObservation) -> Vec<String> {
        let mut errs = Vec::new();
        if obs.price_cents <= 0 {
            errs.push(format!("price must be > 0 (got {})", obs.price_cents));
        }
        if obs.price_cents >= 1_000_000_00 {
            errs.push(format!(
                "price must be < $1,000,000 (got {} cents)",
                obs.price_cents
            ));
        }
        // cents means integer — already enforced by i64
        if !is_valid_currency(&obs.currency) {
            errs.push(format!("invalid currency code: {}", obs.currency));
        }
        if !is_valid_url(&obs.url) {
            errs.push(format!("invalid url: {}", obs.url));
        }
        // Timestamps: sane window (2000-01-01 .. 2100-01-01)
        if obs.observed_at < 946_684_800 || obs.observed_at > 4_102_444_800 {
            errs.push(format!(
                "observed_at timestamp out of range: {}",
                obs.observed_at
            ));
        }
        if obs.sku.is_empty() {
            errs.push("sku empty".into());
        }
        errs
    }

    // 2. Category bounds
    pub fn check_bounds(&self, obs: &PriceObservation, category: &str) -> Vec<String> {
        let mut msgs = Vec::new();
        let bounds = match self.bounds.get(category) {
            Some(b) => b,
            None => return msgs,
        };
        if obs.price_cents < bounds.min_cents {
            msgs.push(format!(
                "HARD:price {} below hard min {} for category {}",
                obs.price_cents, bounds.min_cents, category
            ));
            return msgs;
        }
        if obs.price_cents > bounds.max_cents {
            msgs.push(format!(
                "HARD:price {} above hard max {} for category {}",
                obs.price_cents, bounds.max_cents, category
            ));
            return msgs;
        }
        if obs.price_cents < bounds.typical_min {
            msgs.push(format!(
                "SOFT:price {} below typical min {} for {}",
                obs.price_cents, bounds.typical_min, category
            ));
        }
        if obs.price_cents > bounds.typical_max {
            msgs.push(format!(
                "SOFT:price {} above typical max {} for {}",
                obs.price_cents, bounds.typical_max, category
            ));
        }
        msgs
    }

    // 3. Z-score
    pub fn check_zscore(&self, obs: &PriceObservation, history: &[i64]) -> Option<f64> {
        if history.len() < 7 {
            return None;
        }
        let n = history.len() as f64;
        let mean = history.iter().map(|x| *x as f64).sum::<f64>() / n;
        let var = history
            .iter()
            .map(|x| {
                let d = *x as f64 - mean;
                d * d
            })
            .sum::<f64>()
            / n;
        let std = var.sqrt();
        if std < 1.0 {
            return None;
        }
        Some((obs.price_cents as f64 - mean) / std)
    }

    // 4. Modified z-score via MAD
    pub fn check_mad(&self, obs: &PriceObservation, history: &[i64]) -> Option<f64> {
        if history.len() < 7 {
            return None;
        }
        let mut sorted: Vec<f64> = history.iter().map(|x| *x as f64).collect();
        sorted.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = sorted[sorted.len() / 2];
        let mut devs: Vec<f64> = sorted.iter().map(|x| (x - median).abs()).collect();
        devs.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mad = devs[devs.len() / 2];
        if mad < 1.0 {
            return None;
        }
        // 0.6745 constant: converts MAD to std-dev-equivalent under normality
        Some(0.6745 * (obs.price_cents as f64 - median) / mad)
    }

    // 5. Percent change
    pub fn check_percent_change(&self, new: i64, last: i64) -> Option<f64> {
        if last <= 0 {
            return None;
        }
        Some(((new - last) as f64 / last as f64) * 100.0)
    }

    // 6. Canary check
    pub fn check_canaries(&self, batch_id: &str) -> bool {
        let obs = match self.history.canary_batches.get(batch_id) {
            Some(v) => v,
            None => return true, // no canaries recorded -> no evidence of drift
        };
        for (canonical_id, observed_price) in obs {
            let canary = match self.canaries.iter().find(|c| c.canonical_id == *canonical_id) {
                Some(c) => c,
                None => continue,
            };
            let drift = ((*observed_price - canary.baseline_price_cents) as f64
                / canary.baseline_price_cents as f64)
                .abs()
                * 100.0;
            if drift > canary.max_drift_percent {
                return false;
            }
        }
        true
    }

    // 7. Cross-source triangulation
    pub fn triangulate(&self, _sku: &str, observations: &[PriceObservation]) -> i64 {
        if observations.is_empty() {
            return 0;
        }
        let mut prices: Vec<i64> = observations.iter().map(|o| o.price_cents).collect();
        prices.sort();
        let median = prices[prices.len() / 2];
        if observations.len() < 3 {
            return median;
        }
        // Downweight sources >20% off median
        let mut kept: Vec<f64> = Vec::new();
        let mut weights: Vec<f64> = Vec::new();
        for p in &prices {
            let diff_pct = ((*p - median) as f64 / median as f64).abs() * 100.0;
            let w = if diff_pct > 20.0 { 0.25 } else { 1.0 };
            kept.push(*p as f64);
            weights.push(w);
        }
        let sum_w: f64 = weights.iter().sum();
        let weighted: f64 = kept.iter().zip(weights.iter()).map(|(p, w)| p * w).sum();
        (weighted / sum_w).round() as i64
    }

    // 8. Locale/currency sanity — detects $1.299,00 vs $1,299.00 confusion
    fn check_locale(&self, obs: &PriceObservation) -> Option<String> {
        let raw = obs.raw_price_string.trim();
        if raw.is_empty() {
            return None;
        }

        // Strip leading currency symbols/letters
        let digits: String = raw
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '.' || *c == ',')
            .collect();

        if digits.is_empty() {
            return None;
        }

        // Integer part check
        let int_part_len = digits
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .count();
        if int_part_len > 6 {
            return Some(format!(
                "integer part too long ({} digits) in price '{}'",
                int_part_len, raw
            ));
        }

        // Detect EU locale (1.299,00) vs US (1,299.00)
        // If the LAST separator is ',', it is the decimal marker (EU).
        // If we parsed it as US (last '.'), it would silently misalign by 100x.
        let last_dot = digits.rfind('.');
        let last_comma = digits.rfind(',');
        if let (Some(d), Some(c)) = (last_dot, last_comma) {
            if c > d {
                // EU format — last separator is comma => decimal
                // Ensure price_cents reconstruction matches
                let eu_normalized = digits.replace('.', "").replacen(',', ".", 1);
                if let Ok(parsed) = eu_normalized.parse::<f64>() {
                    let expected_cents = (parsed * 100.0).round() as i64;
                    if (expected_cents - obs.price_cents).abs() > 1 {
                        return Some(format!(
                            "locale mismatch: raw '{}' implies {} cents, got {}",
                            raw, expected_cents, obs.price_cents
                        ));
                    }
                }
            }
        } else if let Some(c) = last_comma {
            // Only commas present. Ambiguous: "1,299" could be thousands or decimal.
            // If exactly 2 digits after last comma and no dots, treat as EU decimal.
            let after = &digits[c + 1..];
            if after.len() == 2 {
                if let Ok(parsed) = digits.replacen(',', ".", 1).parse::<f64>() {
                    let expected_cents = (parsed * 100.0).round() as i64;
                    if (expected_cents - obs.price_cents).abs() > 1 {
                        return Some(format!(
                            "locale mismatch (EU decimal): raw '{}' implies {} cents, got {}",
                            raw, expected_cents, obs.price_cents
                        ));
                    }
                }
            }
        }
        None
    }
}

// ---------- Helpers ----------

fn is_valid_currency(code: &str) -> bool {
    matches!(
        code,
        "USD" | "EUR" | "GBP" | "CAD" | "AUD" | "JPY" | "CHF" | "CNY" | "SEK" | "NOK" | "DKK"
            | "NZD" | "MXN" | "BRL" | "INR" | "SGD" | "HKD" | "KRW"
    )
}

fn is_valid_url(url: &str) -> bool {
    (url.starts_with("http://") || url.starts_with("https://")) && url.len() > 10
}

// ---------- Tests ----------

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_obs(category: &str, price_cents: i64) -> PriceObservation {
        PriceObservation {
            sku: "SKU-1".into(),
            canonical_id: 1,
            store_id: 1,
            source: "test".into(),
            category: category.into(),
            price_cents,
            raw_price_string: format!("${}.{:02}", price_cents / 100, price_cents % 100),
            currency: "USD".into(),
            url: "https://example.com/product/1".into(),
            observed_at: 1_800_000_000,
            batch_id: "batch-1".into(),
        }
    }

    fn mk_product(category: &str) -> CanonicalProduct {
        CanonicalProduct {
            canonical_id: 1,
            category: category.into(),
            title: "Test Product".into(),
        }
    }

    #[test]
    fn rejects_penny_tv() {
        let v = QualityValidator::new();
        let obs = mk_obs("tv", 1); // $0.01
        let r = v.validate(&obs, &mk_product("tv"));
        assert_eq!(r.status, ValidationStatus::Reject);
        assert!(!r.errors.is_empty());
    }

    #[test]
    fn quarantines_nine_dollar_tv() {
        let v = QualityValidator::new();
        let obs = mk_obs("tv", 9_99); // $9.99 TV — above hard min 80.00? min=8000
        // $9.99 = 999 cents, below hard min 8000 -> reject. Use $99.99 to trigger soft.
        let obs2 = mk_obs("tv", 99_99); // below typical_min 150_00 but above hard min 8000
        let r = v.validate(&obs2, &mk_product("tv"));
        assert_ne!(r.status, ValidationStatus::Reject);
        assert!(!r.warnings.is_empty());
        // and $9.99 rejects
        let r1 = v.validate(&obs, &mk_product("tv"));
        assert_eq!(r1.status, ValidationStatus::Reject);
    }

    #[test]
    fn passes_normal_tv() {
        let v = QualityValidator::new();
        let obs = mk_obs("tv", 899_00);
        let r = v.validate(&obs, &mk_product("tv"));
        assert_eq!(r.status, ValidationStatus::Pass);
    }

    #[test]
    fn passes_black_friday_tv() {
        let v = QualityValidator::new();
        let obs = mk_obs("tv", 399_00);
        let r = v.validate(&obs, &mk_product("tv"));
        assert_eq!(r.status, ValidationStatus::Pass);
    }

    #[test]
    fn zscore_detects_outlier() {
        let v = QualityValidator::new();
        let history: Vec<i64> = vec![899_00, 905_00, 890_00, 895_00, 901_00, 898_00, 902_00];
        let obs = mk_obs("tv", 200_00); // huge deviation
        let z = v.check_zscore(&obs, &history).unwrap();
        assert!(z.abs() > 4.0, "z-score should exceed 4, got {}", z);
    }

    #[test]
    fn zscore_ignores_short_history() {
        let v = QualityValidator::new();
        let history: Vec<i64> = vec![899_00, 905_00];
        let obs = mk_obs("tv", 200_00);
        assert!(v.check_zscore(&obs, &history).is_none());
    }

    #[test]
    fn mad_detects_robust_outlier() {
        let v = QualityValidator::new();
        let history: Vec<i64> = vec![100_00, 100_00, 100_00, 100_00, 100_00, 100_00, 100_00];
        let obs = mk_obs("tv", 500_00);
        // MAD = 0 here, so returns None (avoids div by zero)
        assert!(v.check_mad(&obs, &history).is_none());

        let history2: Vec<i64> =
            vec![100_00, 102_00, 99_00, 101_00, 98_00, 103_00, 100_00];
        let obs2 = mk_obs("tv", 500_00);
        let mz = v.check_mad(&obs2, &history2).unwrap();
        assert!(mz.abs() > 5.0);
    }

    #[test]
    fn percent_change_gate() {
        let v = QualityValidator::new();
        assert!(v.check_percent_change(200_00, 100_00).unwrap() > 50.0);
        assert!(v.check_percent_change(110_00, 100_00).unwrap() < 50.0);
        assert!(v.check_percent_change(100_00, 0).is_none());
    }

    #[test]
    fn canary_drift_detected() {
        let canaries = vec![CanaryProduct {
            canonical_id: 42,
            store_id: 1,
            baseline_price_cents: 100_00,
            baseline_observed_at: 1_800_000_000,
            max_drift_percent: 15.0,
        }];
        let mut v = QualityValidator::new().with_canaries(canaries);
        v.history
            .record_canary_in_batch("batch-bad", 42, 50_00); // 50% drift
        v.history
            .record_canary_in_batch("batch-good", 42, 105_00); // 5% drift
        assert!(!v.check_canaries("batch-bad"));
        assert!(v.check_canaries("batch-good"));
        assert!(v.check_canaries("batch-unseen"));
    }

    #[test]
    fn triangulate_three_sources() {
        let v = QualityValidator::new();
        let obs = vec![
            mk_obs("tv", 800_00),
            mk_obs("tv", 810_00),
            mk_obs("tv", 820_00),
        ];
        let result = v.triangulate("SKU-1", &obs);
        assert!((result - 810_00).abs() < 500);
    }

    #[test]
    fn triangulate_downweights_outlier() {
        let v = QualityValidator::new();
        let obs = vec![
            mk_obs("tv", 800_00),
            mk_obs("tv", 810_00),
            mk_obs("tv", 2_000_00), // way off
        ];
        let result = v.triangulate("SKU-1", &obs);
        // median = 810_00. outlier should be weighted 0.25
        assert!(result < 1_200_00, "expected downweighted, got {}", result);
    }

    #[test]
    fn rejects_bad_currency() {
        let v = QualityValidator::new();
        let mut obs = mk_obs("tv", 899_00);
        obs.currency = "XXX".into();
        let r = v.validate(&obs, &mk_product("tv"));
        assert_eq!(r.status, ValidationStatus::Reject);
    }

    #[test]
    fn rejects_bad_url() {
        let v = QualityValidator::new();
        let mut obs = mk_obs("tv", 899_00);
        obs.url = "not-a-url".into();
        let r = v.validate(&obs, &mk_product("tv"));
        assert_eq!(r.status, ValidationStatus::Reject);
    }

    #[test]
    fn rejects_eu_locale_mismatch() {
        let v = QualityValidator::new();
        let mut obs = mk_obs("tv", 1_29); // parsed US-style as $1.29
        obs.raw_price_string = "1.299,00".into(); // actually €1299.00 EU
        let r = v.validate(&obs, &mk_product("tv"));
        assert_eq!(r.status, ValidationStatus::Reject);
    }

    #[test]
    fn passes_us_locale() {
        let v = QualityValidator::new();
        let mut obs = mk_obs("tv", 1_299_00);
        obs.raw_price_string = "$1,299.00".into();
        let r = v.validate(&obs, &mk_product("tv"));
        assert_eq!(r.status, ValidationStatus::Pass);
    }

    #[test]
    fn rejects_million_dollar_price() {
        let v = QualityValidator::new();
        let obs = mk_obs("tv", 1_000_000_00);
        let r = v.validate(&obs, &mk_product("tv"));
        assert_eq!(r.status, ValidationStatus::Reject);
    }

    #[test]
    fn eggs_category_bounds() {
        let v = QualityValidator::new();
        let pass = mk_obs("eggs", 4_99);
        assert_eq!(
            v.validate(&pass, &mk_product("eggs")).status,
            ValidationStatus::Pass
        );
        let reject_high = mk_obs("eggs", 100_00);
        assert_eq!(
            v.validate(&reject_high, &mk_product("eggs")).status,
            ValidationStatus::Reject
        );
        let reject_low = mk_obs("eggs", 50);
        assert_eq!(
            v.validate(&reject_low, &mk_product("eggs")).status,
            ValidationStatus::Reject
        );
    }
}
