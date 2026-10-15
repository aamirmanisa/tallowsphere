//! Shrinkflation detector: tracks size changes for canonical products and
//! computes the effective price increase hidden by the smaller package.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct SizeObservation {
    pub observed_at: i64,
    pub size_value: f64,
    pub size_unit: String,
    pub price_cents: i64,
    pub source: String,
}

#[derive(Debug, Clone)]
pub struct ProductSizeHistory {
    pub canonical_product_id: i64,
    pub name: String,
    pub brand: String,
    pub size_observations: Vec<SizeObservation>,
}

#[derive(Debug, Clone)]
pub struct ShrinkflationEvent {
    pub canonical_product_id: i64,
    pub name: String,
    pub brand: String,
    pub original_size: f64,
    pub original_unit: String,
    pub new_size: f64,
    pub new_unit: String,
    pub size_decrease_percent: f64,
    pub original_price_cents: i64,
    pub new_price_cents: i64,
    pub effective_price_increase_percent: f64,
    pub detected_at: i64,
    pub verified: bool,
}

#[derive(Default)]
pub struct ShrinkflationDetector {
    products: HashMap<i64, ProductSizeHistory>,
}

impl ShrinkflationDetector {
    pub fn new() -> Self {
        Self { products: HashMap::new() }
    }

    /// Register a product with its metadata (idempotent).
    pub fn register_product(&mut self, id: i64, name: &str, brand: &str) {
        self.products
            .entry(id)
            .or_insert_with(|| ProductSizeHistory {
                canonical_product_id: id,
                name: name.to_string(),
                brand: brand.to_string(),
                size_observations: Vec::new(),
            });
    }

    /// Record a size observation under a product id. If the product has
    /// not been registered the caller should `register_product` first; we
    /// auto-create with empty name to keep the API ergonomic.
    pub fn record_observation_for(&mut self, product_id: i64, obs: SizeObservation) {
        let entry = self
            .products
            .entry(product_id)
            .or_insert_with(|| ProductSizeHistory {
                canonical_product_id: product_id,
                name: String::new(),
                brand: String::new(),
                size_observations: Vec::new(),
            });
        entry.size_observations.push(obs);
        entry.size_observations.sort_by_key(|o| o.observed_at);
    }

    /// Convenience: push an observation without supplying product id
    /// (uses source field as a dummy key — retained for spec compatibility).
    pub fn record_observation(&mut self, obs: SizeObservation) {
        // Spec signature; default bucket = 0.
        self.record_observation_for(0, obs);
    }

    /// Detect all shrink events for a product by scanning consecutive
    /// observations for a unit-consistent size decrease.
    pub fn detect_shrinkflation(&self, product_id: i64) -> Vec<ShrinkflationEvent> {
        let Some(hist) = self.products.get(&product_id) else {
            return Vec::new();
        };
        let obs = &hist.size_observations;
        let mut events = Vec::new();
        for window in obs.windows(2) {
            if let Some(mut ev) = Self::compute_shrink(&window[0], &window[1]) {
                ev.canonical_product_id = product_id;
                ev.name = hist.name.clone();
                ev.brand = hist.brand.clone();
                events.push(ev);
            }
        }
        events
    }

    /// All shrinkflation events detected across the full corpus that
    /// occurred within the last `days` days.
    pub fn recent_events(&self, days: i32) -> Vec<ShrinkflationEvent> {
        let now_ref = self
            .products
            .values()
            .flat_map(|p| p.size_observations.iter())
            .map(|o| o.observed_at)
            .max()
            .unwrap_or(0);
        let cutoff = now_ref - (days as i64) * 86_400;
        let mut out = Vec::new();
        for id in self.products.keys() {
            for ev in self.detect_shrinkflation(*id) {
                if ev.detected_at >= cutoff {
                    out.push(ev);
                }
            }
        }
        out.sort_by_key(|e| -e.detected_at);
        out
    }

    /// Top shrinks by size decrease %.
    pub fn biggest_shrinks(&self, limit: usize) -> Vec<ShrinkflationEvent> {
        let mut all: Vec<ShrinkflationEvent> = self
            .products
            .keys()
            .flat_map(|id| self.detect_shrinkflation(*id))
            .collect();
        all.sort_by(|a, b| {
            b.size_decrease_percent
                .partial_cmp(&a.size_decrease_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        all.truncate(limit);
        all
    }

    /// Core comparison: returns a ShrinkflationEvent if `b` is smaller than
    /// `a` (in the same unit) by a meaningful margin (>=2%). Also computes
    /// the effective price-per-unit increase between the two observations.
    pub(crate) fn compute_shrink(
        a: &SizeObservation,
        b: &SizeObservation,
    ) -> Option<ShrinkflationEvent> {
        if a.size_unit != b.size_unit {
            return None;
        }
        if a.size_value <= 0.0 || b.size_value <= 0.0 {
            return None;
        }
        if b.size_value >= a.size_value {
            return None;
        }
        let decrease = ((a.size_value - b.size_value) / a.size_value) * 100.0;
        if decrease < 2.0 {
            return None;
        }

        let ppu_a = a.price_cents as f64 / a.size_value;
        let ppu_b = b.price_cents as f64 / b.size_value;
        let effective = if ppu_a > 0.0 {
            ((ppu_b - ppu_a) / ppu_a) * 100.0
        } else {
            0.0
        };

        Some(ShrinkflationEvent {
            canonical_product_id: 0,
            name: String::new(),
            brand: String::new(),
            original_size: a.size_value,
            original_unit: a.size_unit.clone(),
            new_size: b.size_value,
            new_unit: b.size_unit.clone(),
            size_decrease_percent: decrease,
            original_price_cents: a.price_cents,
            new_price_cents: b.price_cents,
            effective_price_increase_percent: effective,
            detected_at: b.observed_at,
            verified: false,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn obs(ts: i64, size: f64, unit: &str, price: i64) -> SizeObservation {
        SizeObservation {
            observed_at: ts,
            size_value: size,
            size_unit: unit.into(),
            price_cents: price,
            source: "test".into(),
        }
    }

    #[test]
    fn detects_classic_shrink() {
        let mut d = ShrinkflationDetector::new();
        d.register_product(1, "Cereal", "BrandX");
        d.record_observation_for(1, obs(0, 18.0, "oz", 399));
        d.record_observation_for(1, obs(1_000_000, 16.0, "oz", 399));
        let events = d.detect_shrinkflation(1);
        assert_eq!(events.len(), 1);
        let e = &events[0];
        assert!((e.size_decrease_percent - 11.11).abs() < 0.1);
        assert!(e.effective_price_increase_percent > 12.0);
    }

    #[test]
    fn ignores_different_units() {
        assert!(ShrinkflationDetector::compute_shrink(
            &obs(0, 500.0, "g", 100),
            &obs(1, 16.0, "oz", 100)
        )
        .is_none());
    }

    #[test]
    fn ignores_growth() {
        assert!(ShrinkflationDetector::compute_shrink(
            &obs(0, 10.0, "oz", 100),
            &obs(1, 12.0, "oz", 100)
        )
        .is_none());
    }

    #[test]
    fn ignores_tiny_change() {
        assert!(ShrinkflationDetector::compute_shrink(
            &obs(0, 100.0, "g", 100),
            &obs(1, 99.0, "g", 100)
        )
        .is_none());
    }

    #[test]
    fn biggest_shrinks_ordered() {
        let mut d = ShrinkflationDetector::new();
        d.register_product(1, "A", "X");
        d.register_product(2, "B", "Y");
        d.record_observation_for(1, obs(0, 100.0, "g", 100));
        d.record_observation_for(1, obs(1, 90.0, "g", 100));
        d.record_observation_for(2, obs(0, 100.0, "g", 100));
        d.record_observation_for(2, obs(1, 70.0, "g", 100));
        let top = d.biggest_shrinks(5);
        assert_eq!(top.len(), 2);
        assert!(top[0].size_decrease_percent > top[1].size_decrease_percent);
    }

    #[test]
    fn recent_events_filters() {
        let mut d = ShrinkflationDetector::new();
        d.register_product(1, "A", "X");
        d.record_observation_for(1, obs(0, 100.0, "g", 100));
        d.record_observation_for(1, obs(86_400 * 10, 90.0, "g", 100));
        let r = d.recent_events(30);
        assert_eq!(r.len(), 1);
    }
}
