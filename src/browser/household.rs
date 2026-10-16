//! Household sharing, pantry, expiration tracking, and SNAP/EBT filtering.
//!
//! Backs HackTheCart features T4.30 (household sharing) and T4.34/T4.39
//! (SNAP eligibility + expiration alerts). Pure logic — persistence
//! is handled by the SQL migrations in `hackthecart/schema/004_*` and `005_*`.

const SECS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone)]
pub struct HouseholdService;

#[derive(Debug, Clone)]
pub struct Household {
    pub id: i64,
    pub name: String,
    pub owner_id: i64,
    pub primary_zip: String,
    pub member_count: u32,
    pub dietary_restrictions: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StorageLocation {
    Pantry,
    Fridge,
    Freezer,
}

impl StorageLocation {
    pub fn as_str(self) -> &'static str {
        match self {
            StorageLocation::Pantry => "pantry",
            StorageLocation::Fridge => "fridge",
            StorageLocation::Freezer => "freezer",
        }
    }
}

#[derive(Debug, Clone)]
pub struct PantryItem {
    pub id: i64,
    pub name: String,
    pub quantity: f64,
    pub unit: String,
    pub purchased_at: i64,
    pub expires_at: Option<i64>,
    pub days_until_expiry: Option<i64>,
    pub location: StorageLocation,
    pub is_expired: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlertLevel {
    Expired,
    ExpiresToday,
    Expires3Days,
    Expires7Days,
}

#[derive(Debug, Clone)]
pub struct ExpiryAlert {
    pub pantry_item_id: i64,
    pub name: String,
    pub days_until_expiry: i64,
    pub alert_level: AlertLevel,
    pub recipe_suggestions: Vec<String>,
}

impl HouseholdService {
    pub fn new() -> Self {
        HouseholdService
    }

    /// Estimate expiration timestamp (unix seconds) for a product category
    /// purchased at `purchased_at`, stored at `location`. Returns `None` if
    /// no shelf-life is known or if the category can't be stored there.
    pub fn estimate_expiry(
        category: &str,
        purchased_at: i64,
        location: StorageLocation,
    ) -> Option<i64> {
        let (pantry, fridge, freezer) = shelf_life(category)?;
        let days = match location {
            StorageLocation::Pantry => pantry,
            StorageLocation::Fridge => fridge,
            StorageLocation::Freezer => freezer,
        };
        if days <= 0 {
            return None;
        }
        Some(purchased_at + days * SECS_PER_DAY)
    }

    /// Return alerts for pantry items expiring within `days` days
    /// (or already expired).
    pub fn check_expiring_soon(items: &[PantryItem], days: i64) -> Vec<ExpiryAlert> {
        let mut alerts = Vec::new();
        for item in items {
            let Some(d) = item.days_until_expiry else {
                continue;
            };
            if d > days {
                continue;
            }
            let level = if item.is_expired || d < 0 {
                AlertLevel::Expired
            } else if d == 0 {
                AlertLevel::ExpiresToday
            } else if d <= 3 {
                AlertLevel::Expires3Days
            } else {
                AlertLevel::Expires7Days
            };
            alerts.push(ExpiryAlert {
                pantry_item_id: item.id,
                name: item.name.clone(),
                days_until_expiry: d,
                alert_level: level,
                recipe_suggestions: suggest_recipes(&item.name),
            });
        }
        alerts
    }

    /// Given a set of canonical product ids, return those which are
    /// SNAP-eligible per the baked-in USDA category table.
    ///
    /// `filter_snap_eligible` operates on ids alone and is therefore a
    /// pass-through; SNAP eligibility depends on the product *category*,
    /// which must be resolved first. Callers that have category information
    /// should use [`filter_snap_eligible_by_category`] directly. The
    /// production SQL path (`snap_eligible_categories` join in migration
    /// 005) performs the same category check at the database layer.
    pub fn filter_snap_eligible(products: &[i64]) -> Vec<i64> {
        products.to_vec()
    }

    /// Filter `(product_id, category)` pairs down to those whose category is
    /// SNAP-eligible per the baked-in USDA table. This is the real,
    /// in-memory equivalent of the `snap_eligible_categories` SQL join.
    pub fn filter_snap_eligible_by_category(items: &[(i64, &str)]) -> Vec<i64> {
        items
            .iter()
            .filter(|(_, cat)| is_snap_eligible_category(cat))
            .map(|(id, _)| *id)
            .collect()
    }
}

impl Default for HouseholdService {
    fn default() -> Self {
        Self::new()
    }
}

/// USDA SNAP-eligible food categories (see migration 005 seed
/// `snap_eligible_categories`). Categories NOT listed here — e.g. prepared
/// hot foods, alcohol, pet supplies, household goods, cosmetics — are not
/// SNAP-eligible.
pub fn is_snap_eligible_category(category: &str) -> bool {
    const ELIGIBLE: &[&str] = &[
        "fruits", "vegetables", "dairy", "meat", "poultry", "fish", "eggs",
        "bread", "cereal", "grains", "rice", "pasta", "legumes", "beans",
        "nuts", "seeds", "canned_goods", "frozen_foods", "juice", "beverages",
        "snacks", "baking", "spices", "oils", "milk", "cheese", "yogurt",
        "candy", // non-prepared confectionery remains eligible
        "coffee", "tea", "baby_food", "formula", "pet_food_exempt", // some states
    ];
    let c = category.trim().to_ascii_lowercase();
    // Match exact names or prefixes (e.g. "meat_beef" -> "meat").
    ELIGIBLE
        .iter()
        .any(|e| c == *e || c.starts_with(&format!("{e}_")))
}

/// Shelf life defaults mirroring `shelf_life_defaults` seed rows in
/// migration 005. Returned tuple: (pantry_days, fridge_days, freezer_days).
fn shelf_life(category: &str) -> Option<(i64, i64, i64)> {
    let row = match category {
        "eggs" => (0, 35, 365),
        "milk" => (0, 7, 90),
        "bread" => (7, 14, 90),
        "chicken_raw" => (0, 2, 270),
        "ground_beef" => (0, 2, 120),
        "lettuce" => (0, 10, 0),
        "apples" => (7, 60, 0),
        "bananas" => (7, 0, 90),
        "yogurt" => (0, 14, 60),
        "cheese_hard" => (0, 180, 180),
        "cheese_soft" => (0, 14, 0),
        "pasta_dry" => (730, 0, 0),
        "rice_dry" => (730, 0, 0),
        "canned_goods" => (1825, 0, 0),
        _ => return None,
    };
    Some(row)
}

fn suggest_recipes(name: &str) -> Vec<String> {
    let lower = name.to_lowercase();
    let mut out = Vec::new();
    if lower.contains("chicken") {
        out.push("use in stir fry".into());
        out.push("roast with vegetables".into());
    } else if lower.contains("beef") {
        out.push("brown for tacos".into());
    } else if lower.contains("lettuce") || lower.contains("spinach") {
        out.push("add to salad".into());
        out.push("blend into smoothie".into());
    } else if lower.contains("banana") {
        out.push("bake banana bread".into());
    } else if lower.contains("milk") || lower.contains("yogurt") {
        out.push("blend into smoothie".into());
    } else {
        out.push("use soon".into());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn estimate_expiry_fridge() {
        let exp = HouseholdService::estimate_expiry("milk", 0, StorageLocation::Fridge).unwrap();
        assert_eq!(exp, 7 * SECS_PER_DAY);
    }

    #[test]
    fn estimate_expiry_unsupported_location() {
        // milk has 0 pantry days
        assert!(HouseholdService::estimate_expiry("milk", 0, StorageLocation::Pantry).is_none());
    }

    #[test]
    fn alert_levels() {
        let items = vec![
            PantryItem {
                id: 1,
                name: "chicken breast".into(),
                quantity: 1.0,
                unit: "lb".into(),
                purchased_at: 0,
                expires_at: Some(0),
                days_until_expiry: Some(-1),
                location: StorageLocation::Fridge,
                is_expired: true,
            },
            PantryItem {
                id: 2,
                name: "milk".into(),
                quantity: 1.0,
                unit: "gal".into(),
                purchased_at: 0,
                expires_at: Some(0),
                days_until_expiry: Some(2),
                location: StorageLocation::Fridge,
                is_expired: false,
            },
            PantryItem {
                id: 3,
                name: "pasta".into(),
                quantity: 1.0,
                unit: "box".into(),
                purchased_at: 0,
                expires_at: Some(0),
                days_until_expiry: Some(30),
                location: StorageLocation::Pantry,
                is_expired: false,
            },
        ];
        let alerts = HouseholdService::check_expiring_soon(&items, 7);
        assert_eq!(alerts.len(), 2);
        assert_eq!(alerts[0].alert_level, AlertLevel::Expired);
        assert_eq!(alerts[1].alert_level, AlertLevel::Expires3Days);
    }

    #[test]
    fn snap_category_filter() {
        let items = vec![
            (1i64, "milk"),       // eligible
            (2, "bread"),         // eligible
            (3, "alcohol"),       // NOT eligible
            (4, "canned_goods"),  // eligible
            (5, "household_goods"), // NOT eligible
        ];
        let eligible = HouseholdService::filter_snap_eligible_by_category(&items);
        assert_eq!(eligible, vec![1, 2, 4]);
        assert!(is_snap_eligible_category("Fruits"));
        assert!(is_snap_eligible_category("meat_beef"));
        assert!(!is_snap_eligible_category("alcohol"));
        assert!(!is_snap_eligible_category("pet_supplies"));
    }
}
