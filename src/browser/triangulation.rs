//! Multi-source price triangulation and trust scoring for HackTheCart.
//!
//! Combines observations from multiple sources (APIs, scrapes, user reports)
//! into a single consensus price with confidence scoring. Trust scores adapt
//! over time based on each source's agreement with consensus.

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Trust scorer tracking per-source reliability.
#[derive(Debug, Clone)]
pub struct TrustScorer {
    source_trust: HashMap<String, f64>,
}

/// A single price observation from one source.
#[derive(Debug, Clone)]
pub struct SourceObservation {
    pub source: String,
    pub price_cents: i64,
    pub observed_at: i64,
    pub confidence: f64,
}

/// Result of triangulating multiple observations.
#[derive(Debug, Clone)]
pub struct TriangulationResult {
    pub consensus_price_cents: i64,
    pub confidence: f64,
    pub agreement_count: usize,
    pub disagreement_count: usize,
    pub used_sources: Vec<String>,
    pub rejected_sources: Vec<(String, i64, String)>,
}

impl TrustScorer {
    pub fn new() -> Self {
        let mut source_trust = HashMap::new();
        source_trust.insert("kroger_api".into(), 0.98);
        source_trust.insert("walmart_api".into(), 0.97);
        source_trust.insert("bestbuy_api".into(), 0.97);
        source_trust.insert("ebay_api".into(), 0.92);
        source_trust.insert("etsy_api".into(), 0.90);
        source_trust.insert("flipp_api".into(), 0.93);
        source_trust.insert("shopify_products".into(), 0.95);
        source_trust.insert("instacart_scrape".into(), 0.65);
        source_trust.insert("amazon_scrape".into(), 0.85);
        source_trust.insert("walmart_scrape".into(), 0.88);
        source_trust.insert("costco_scrape".into(), 0.80);
        source_trust.insert("samsclub_scrape".into(), 0.83);
        source_trust.insert("user_report".into(), 0.85);
        source_trust.insert("user_receipt_ocr".into(), 0.95);
        Self { source_trust }
    }

    pub fn trust(&self, source: &str) -> f64 {
        *self.source_trust.get(source).unwrap_or(&0.5)
    }

    /// Update trust via exponential moving average based on consensus agreement.
    pub fn record_agreement(&mut self, source: &str, agreed: bool) {
        let current = self.trust(source);
        let new = if agreed {
            (current * 0.95 + 1.0 * 0.05).min(1.0)
        } else {
            (current * 0.95 + 0.0 * 0.05).max(0.1)
        };
        self.source_trust.insert(source.to_string(), new);
    }

    pub fn set_trust(&mut self, source: &str, trust: f64) {
        self.source_trust.insert(source.to_string(), trust.clamp(0.0, 1.0));
    }
}

impl Default for TrustScorer {
    fn default() -> Self {
        Self::new()
    }
}

/// Triangulates multiple observations into a consensus price.
#[derive(Debug, Clone)]
pub struct Triangulator {
    pub scorer: TrustScorer,
    /// Maximum deviation from median before rejection (default 0.20 = 20%).
    pub deviation_threshold: f64,
    /// Maximum age in seconds before observation is dropped (default 3600).
    pub max_age_seconds: i64,
    /// Override "now" for deterministic tests.
    now_override: Option<i64>,
}

impl Triangulator {
    pub fn new() -> Self {
        Self {
            scorer: TrustScorer::new(),
            deviation_threshold: 0.20,
            max_age_seconds: 3600,
            now_override: None,
        }
    }

    pub fn with_now(mut self, t: i64) -> Self {
        self.now_override = Some(t);
        self
    }

    fn current_time(&self) -> i64 {
        self.now_override.unwrap_or_else(now)
    }

    /// Combine N observations into a consensus price.
    pub fn triangulate(&self, observations: &[SourceObservation]) -> TriangulationResult {
        let current = self.current_time();

        // 1. Drop stale observations.
        let mut rejected: Vec<(String, i64, String)> = Vec::new();
        let fresh: Vec<&SourceObservation> = observations
            .iter()
            .filter(|o| {
                let age = current - o.observed_at;
                if age > self.max_age_seconds {
                    rejected.push((
                        o.source.clone(),
                        o.price_cents,
                        format!("stale ({}s old)", age),
                    ));
                    false
                } else {
                    true
                }
            })
            .collect();

        if fresh.is_empty() {
            return TriangulationResult {
                consensus_price_cents: 0,
                confidence: 0.0,
                agreement_count: 0,
                disagreement_count: rejected.len(),
                used_sources: Vec::new(),
                rejected_sources: rejected,
            };
        }

        // Handle single observation case.
        if fresh.len() == 1 {
            let o = fresh[0];
            let conf = self.confidence_for_single(o);
            return TriangulationResult {
                consensus_price_cents: o.price_cents,
                confidence: conf,
                agreement_count: 1,
                disagreement_count: rejected.len(),
                used_sources: vec![o.source.clone()],
                rejected_sources: rejected,
            };
        }

        // 2. Weighted median (weight = trust × recency × base confidence).
        let weighted: Vec<(i64, f64, &SourceObservation)> = fresh
            .iter()
            .map(|o| {
                let w = self.scorer.trust(&o.source)
                    * self.recency_factor_at(o.observed_at, current)
                    * o.confidence;
                (o.price_cents, w, *o)
            })
            .collect();

        let median = Self::weighted_median_impl(&weighted);

        // 3 & 4. Reject sources deviating more than threshold from median.
        let mut accepted: Vec<(i64, f64, &SourceObservation)> = Vec::new();
        for (price, weight, obs) in &weighted {
            let deviation = if median == 0 {
                if *price == 0 { 0.0 } else { 1.0 }
            } else {
                ((*price - median).abs() as f64) / (median as f64)
            };
            if deviation > self.deviation_threshold {
                rejected.push((
                    obs.source.clone(),
                    *price,
                    format!("outlier ({:.1}% from median)", deviation * 100.0),
                ));
            } else {
                accepted.push((*price, *weight, *obs));
            }
        }

        if accepted.is_empty() {
            // All disagreed — fall back to median with very low confidence.
            return TriangulationResult {
                consensus_price_cents: median,
                confidence: 0.1,
                agreement_count: 0,
                disagreement_count: rejected.len(),
                used_sources: Vec::new(),
                rejected_sources: rejected,
            };
        }

        // 5. Recalculate consensus from accepted sources.
        let consensus = Self::weighted_median_impl(&accepted);

        // 6. Confidence = (agreement / total_fresh) × avg_trust of accepted.
        let total_fresh = fresh.len() as f64;
        let agreement_ratio = accepted.len() as f64 / total_fresh;
        let avg_trust: f64 = accepted
            .iter()
            .map(|(_, _, o)| self.scorer.trust(&o.source))
            .sum::<f64>()
            / accepted.len() as f64;
        let avg_recency: f64 = accepted
            .iter()
            .map(|(_, _, o)| self.recency_factor_at(o.observed_at, current))
            .sum::<f64>()
            / accepted.len() as f64;

        let confidence = (agreement_ratio * avg_trust * avg_recency).clamp(0.0, 1.0);

        let used_sources: Vec<String> =
            accepted.iter().map(|(_, _, o)| o.source.clone()).collect();

        TriangulationResult {
            consensus_price_cents: consensus,
            confidence,
            agreement_count: accepted.len(),
            disagreement_count: rejected.len(),
            used_sources,
            rejected_sources: rejected,
        }
    }

    /// Confidence score for a single standalone observation.
    pub fn confidence_for_single(&self, obs: &SourceObservation) -> f64 {
        let trust = self.scorer.trust(&obs.source);
        let recency = self.recency_factor_at(obs.observed_at, self.current_time());
        let base = obs.confidence;
        (trust * recency * base).clamp(0.0, 1.0)
    }

    pub fn recency_factor(&self, observed_at: i64) -> f64 {
        self.recency_factor_at(observed_at, self.current_time())
    }

    fn recency_factor_at(&self, observed_at: i64, current: i64) -> f64 {
        let age_hours = (current - observed_at) / 3600;
        if age_hours < 1 {
            1.0
        } else if age_hours < 6 {
            0.95
        } else if age_hours < 24 {
            0.85
        } else if age_hours < 72 {
            0.65
        } else {
            0.4
        }
    }

    /// Weighted median: the value at which the cumulative weight crosses half.
    fn weighted_median_impl<T>(values: &[(i64, f64, T)]) -> i64
    where
        T: Copy,
    {
        if values.is_empty() {
            return 0;
        }
        let mut sorted: Vec<(i64, f64)> = values.iter().map(|(p, w, _)| (*p, *w)).collect();
        sorted.sort_by_key(|(p, _)| *p);
        let total: f64 = sorted.iter().map(|(_, w)| *w).sum();
        if total <= 0.0 {
            // Fall back to unweighted median.
            return sorted[sorted.len() / 2].0;
        }
        let half = total / 2.0;
        let mut cum = 0.0;
        for (p, w) in &sorted {
            cum += *w;
            if cum >= half {
                return *p;
            }
        }
        sorted.last().map(|(p, _)| *p).unwrap_or(0)
    }

    /// Public weighted median for external callers / tests.
    pub fn weighted_median(&self, values: &[(i64, f64)]) -> i64 {
        let wrapped: Vec<(i64, f64, ())> = values.iter().map(|(p, w)| (*p, *w, ())).collect();
        Self::weighted_median_impl(&wrapped)
    }
}

impl Default for Triangulator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(source: &str, price: i64, age_secs: i64, base: f64, t: i64) -> SourceObservation {
        SourceObservation {
            source: source.to_string(),
            price_cents: price,
            observed_at: t - age_secs,
            confidence: base,
        }
    }

    #[test]
    fn three_sources_agree_high_confidence() {
        let t = 1_000_000;
        let tri = Triangulator::new().with_now(t);
        let observations = vec![
            obs("kroger_api", 499, 60, 1.0, t),
            obs("walmart_api", 500, 60, 1.0, t),
            obs("bestbuy_api", 501, 60, 1.0, t),
        ];
        let r = tri.triangulate(&observations);
        assert_eq!(r.agreement_count, 3);
        assert_eq!(r.disagreement_count, 0);
        assert!(r.confidence > 0.9, "expected high confidence, got {}", r.confidence);
        assert!((499..=501).contains(&r.consensus_price_cents));
    }

    #[test]
    fn two_agree_one_outlier_rejects_outlier() {
        let t = 1_000_000;
        let tri = Triangulator::new().with_now(t);
        let observations = vec![
            obs("kroger_api", 500, 60, 1.0, t),
            obs("walmart_api", 505, 60, 1.0, t),
            obs("amazon_scrape", 2000, 60, 1.0, t), // 4x outlier
        ];
        let r = tri.triangulate(&observations);
        assert_eq!(r.agreement_count, 2);
        assert_eq!(r.disagreement_count, 1);
        assert_eq!(r.rejected_sources.len(), 1);
        assert_eq!(r.rejected_sources[0].0, "amazon_scrape");
        assert!(r.consensus_price_cents >= 500 && r.consensus_price_cents <= 505);
        assert!(r.confidence > 0.4 && r.confidence < 0.95);
    }

    #[test]
    fn all_disagree_low_confidence() {
        let t = 1_000_000;
        let tri = Triangulator::new().with_now(t);
        let observations = vec![
            obs("kroger_api", 100, 60, 1.0, t),
            obs("walmart_api", 500, 60, 1.0, t),
            obs("amazon_scrape", 2000, 60, 1.0, t),
        ];
        let r = tri.triangulate(&observations);
        // Whichever the median lands on, other two will be >20% off.
        assert!(r.confidence < 0.5, "expected low confidence, got {}", r.confidence);
    }

    #[test]
    fn stale_observation_lower_confidence() {
        let t = 1_000_000;
        let tri = Triangulator::new().with_now(t);
        // 50 hours old → recency 0.65
        let o = obs("kroger_api", 500, 50 * 3600, 1.0, t);
        let c = tri.confidence_for_single(&o);
        assert!(c < 0.7 && c > 0.5, "got {}", c);

        // Fresh
        let o2 = obs("kroger_api", 500, 60, 1.0, t);
        let c2 = tri.confidence_for_single(&o2);
        assert!(c2 > c);
    }

    #[test]
    fn stale_observation_dropped_entirely() {
        let t = 1_000_000;
        let tri = Triangulator::new().with_now(t);
        // max_age_seconds = 3600, so 2h old is dropped.
        let observations = vec![obs("kroger_api", 500, 7200, 1.0, t)];
        let r = tri.triangulate(&observations);
        assert_eq!(r.agreement_count, 0);
        assert_eq!(r.disagreement_count, 1);
        assert_eq!(r.confidence, 0.0);
    }

    #[test]
    fn single_source_confidence_equals_trust_times_base() {
        let t = 1_000_000;
        let tri = Triangulator::new().with_now(t);
        let o = obs("kroger_api", 500, 60, 0.8, t);
        let c = tri.confidence_for_single(&o);
        // trust 0.98 × recency 1.0 × base 0.8
        let expected = 0.98 * 1.0 * 0.8;
        assert!((c - expected).abs() < 1e-9, "got {}, expected {}", c, expected);
    }

    #[test]
    fn single_source_triangulation_returns_its_price() {
        let t = 1_000_000;
        let tri = Triangulator::new().with_now(t);
        let observations = vec![obs("kroger_api", 1234, 60, 1.0, t)];
        let r = tri.triangulate(&observations);
        assert_eq!(r.consensus_price_cents, 1234);
        assert_eq!(r.agreement_count, 1);
        assert!(r.confidence > 0.9);
    }

    #[test]
    fn trust_adapts_over_time_wrong_source_drops() {
        let mut scorer = TrustScorer::new();
        let initial = scorer.trust("amazon_scrape");
        for _ in 0..200 {
            scorer.record_agreement("amazon_scrape", false);
        }
        let after = scorer.trust("amazon_scrape");
        assert!(after < initial, "trust should drop: {} -> {}", initial, after);
        assert!(after <= 0.15, "should approach floor, got {}", after);
    }

    #[test]
    fn trust_adapts_over_time_correct_source_rises() {
        let mut scorer = TrustScorer::new();
        let initial = scorer.trust("instacart_scrape"); // 0.65
        for _ in 0..200 {
            scorer.record_agreement("instacart_scrape", true);
        }
        let after = scorer.trust("instacart_scrape");
        assert!(after > initial);
        assert!(after > 0.95);
    }

    #[test]
    fn unknown_source_default_trust() {
        let scorer = TrustScorer::new();
        assert_eq!(scorer.trust("mystery_source"), 0.5);
    }

    #[test]
    fn weighted_median_basic() {
        let tri = Triangulator::new();
        // Price 100 has high weight, should dominate.
        let vals = vec![(100, 10.0), (200, 1.0), (300, 1.0)];
        assert_eq!(tri.weighted_median(&vals), 100);
    }
}
