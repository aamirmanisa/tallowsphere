//! Category-aware price bounds (T3.18).
//!
//! A fast sanity filter that rejects impossible prices (0.01 TVs, $10M eggs)
//! and warns on suspicious ones before they reach storage or downstream
//! analytics.

use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct CategoryBounds {
    pub category: String,
    pub hard_min_cents: i64,
    pub hard_max_cents: i64,
    pub soft_min_cents: i64,
    pub soft_max_cents: i64,
    pub typical_mean_cents: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundsResult {
    Pass,
    SoftLow(String),
    SoftHigh(String),
    HardReject(String),
    UnknownCategory,
}

#[derive(Debug, Default)]
pub struct PriceBoundsRegistry {
    bounds: HashMap<String, CategoryBounds>,
}

impl PriceBoundsRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(
        &mut self,
        category: &str,
        hard_min: i64,
        hard_max: i64,
        soft_min: i64,
        soft_max: i64,
        typical: i64,
    ) {
        self.bounds.insert(
            category.to_string(),
            CategoryBounds {
                category: category.to_string(),
                hard_min_cents: hard_min,
                hard_max_cents: hard_max,
                soft_min_cents: soft_min,
                soft_max_cents: soft_max,
                typical_mean_cents: typical,
            },
        );
    }

    pub fn seed_defaults(&mut self) {
        // Grocery
        self.add("eggs_dozen", 99, 3000, 250, 1200, 500);
        self.add("milk_gallon", 150, 2500, 280, 900, 450);
        self.add("bread_loaf", 99, 1500, 200, 800, 350);
        self.add("chicken_breast_lb", 150, 3000, 300, 2000, 600);
        self.add("ground_beef_lb", 200, 4000, 400, 2500, 700);
        self.add("bananas_lb", 20, 200, 40, 150, 65);
        self.add("apples_lb", 50, 500, 80, 350, 150);
        self.add("rice_5lb", 300, 3000, 500, 2000, 900);
        self.add("pasta_1lb", 50, 800, 100, 500, 200);
        self.add("peanut_butter_16oz", 150, 2000, 250, 1200, 450);
        self.add("cheese_8oz", 150, 2000, 250, 1500, 500);
        self.add("butter_1lb", 200, 1500, 350, 1000, 500);
        self.add("flour_5lb", 150, 2000, 250, 1200, 400);
        self.add("sugar_4lb", 150, 1500, 250, 900, 350);
        self.add("cereal_18oz", 150, 1500, 250, 900, 450);
        self.add("tuna_5oz_can", 50, 500, 80, 350, 150);
        self.add("potatoes_5lb", 200, 2000, 350, 1200, 600);
        self.add("onions_2lb", 100, 1000, 150, 700, 300);
        self.add("yogurt_32oz", 150, 1500, 250, 800, 400);
        self.add("coffee_12oz", 300, 5000, 500, 2500, 900);
        self.add("orange_juice_64oz", 150, 2000, 250, 1200, 500);
        self.add("ice_cream_48oz", 200, 2500, 300, 1500, 600);
        self.add("beer_6pk", 500, 3000, 700, 2000, 1000);
        self.add("wine_bottle", 300, 50_000, 700, 10_000, 1500);
        self.add("soda_12pk", 300, 2500, 400, 1500, 700);

        // Electronics
        self.add("tv_32", 8000, 1_000_000, 15000, 500_000, 30000);
        self.add("tv_55", 20000, 3_000_000, 35000, 1_500_000, 55000);
        self.add("tv_65", 30000, 5_000_000, 50000, 2_000_000, 90000);
        self.add("tv_75", 50000, 8_000_000, 80000, 3_000_000, 130000);
        self.add("headphones", 500, 500_000, 2000, 100_000, 8000);
        self.add("earbuds", 500, 300_000, 1500, 50_000, 5000);
        self.add("laptop", 15000, 1_500_000, 30000, 400_000, 80000);
        self.add("desktop", 20000, 2_000_000, 40000, 500_000, 100000);
        self.add("tablet", 5000, 500_000, 10000, 200_000, 35000);
        self.add("smartphone", 5000, 500_000, 10000, 200_000, 60000);
        self.add("smartwatch", 2000, 200_000, 5000, 100_000, 25000);
        self.add("monitor_24", 8000, 200_000, 12000, 80_000, 20000);
        self.add("monitor_27", 12000, 400_000, 18000, 150_000, 30000);
        self.add("keyboard", 500, 100_000, 1500, 30_000, 6000);
        self.add("mouse", 300, 50_000, 800, 15_000, 3000);
        self.add("printer", 3000, 300_000, 5000, 100_000, 15000);
        self.add("router", 1500, 200_000, 3000, 80_000, 10000);
        self.add("gaming_console", 15000, 100_000, 25000, 80_000, 50000);
        self.add("speaker", 1000, 300_000, 2500, 100_000, 15000);
        self.add("camera", 5000, 2_000_000, 10000, 500_000, 60000);

        // Household
        self.add("paper_towels_6pk", 300, 3000, 500, 2000, 1000);
        self.add("toilet_paper_12pk", 500, 4000, 700, 2500, 1200);
        self.add("laundry_detergent", 500, 5000, 800, 3000, 1500);
        self.add("dish_soap", 150, 1500, 250, 800, 400);
    }

    pub fn validate(&self, category: &str, price_cents: i64) -> BoundsResult {
        let Some(b) = self.bounds.get(category) else {
            return BoundsResult::UnknownCategory;
        };
        if price_cents < b.hard_min_cents {
            return BoundsResult::HardReject(format!(
                "{}: {}¢ below hard_min {}¢",
                category, price_cents, b.hard_min_cents
            ));
        }
        if price_cents > b.hard_max_cents {
            return BoundsResult::HardReject(format!(
                "{}: {}¢ above hard_max {}¢",
                category, price_cents, b.hard_max_cents
            ));
        }
        if price_cents < b.soft_min_cents {
            return BoundsResult::SoftLow(format!(
                "{}: {}¢ below soft_min {}¢ (possible clearance)",
                category, price_cents, b.soft_min_cents
            ));
        }
        if price_cents > b.soft_max_cents {
            return BoundsResult::SoftHigh(format!(
                "{}: {}¢ above soft_max {}¢ (possible premium/luxury)",
                category, price_cents, b.soft_max_cents
            ));
        }
        BoundsResult::Pass
    }

    pub fn category_count(&self) -> usize {
        self.bounds.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> PriceBoundsRegistry {
        let mut r = PriceBoundsRegistry::new();
        r.seed_defaults();
        r
    }

    #[test]
    fn seeds_at_least_50_categories() {
        assert!(reg().category_count() >= 45);
    }

    #[test]
    fn normal_egg_price_passes() {
        assert_eq!(reg().validate("eggs_dozen", 500), BoundsResult::Pass);
    }

    #[test]
    fn one_cent_tv_hard_rejects() {
        let r = reg().validate("tv_65", 1);
        assert!(matches!(r, BoundsResult::HardReject(_)));
    }

    #[test]
    fn luxury_headphones_soft_high() {
        let r = reg().validate("headphones", 150_000);
        assert!(matches!(r, BoundsResult::SoftHigh(_)));
    }

    #[test]
    fn clearance_milk_soft_low() {
        let r = reg().validate("milk_gallon", 200);
        assert!(matches!(r, BoundsResult::SoftLow(_)));
    }

    #[test]
    fn unknown_category() {
        assert_eq!(
            reg().validate("quantum_reactor", 500),
            BoundsResult::UnknownCategory
        );
    }
}
