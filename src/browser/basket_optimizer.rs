//! Basket optimizer — the killer feature of Tallow.
//!
//! Given a parsed `Recipe` and a set of nearby stores with priced listings,
//! computes:
//!  * Per-store single-basket totals (sorted cheapest first).
//!  * Optimal multi-store split (greedy assignment of each ingredient to its
//!    cheapest store).
//!  * The single cheapest store that has every item.
//!  * The closest store that can fulfill the whole basket.

use std::collections::HashMap;

use crate::browser::recipe_parser::{Ingredient, Recipe};

/// In-memory view of a store.
#[derive(Debug, Clone)]
pub struct StoreInfo {
    pub store_id: i64,
    pub name: String,
    /// Great-circle distance (miles) from the query zip to this store, filled
    /// by [`ProductDb::stores_within`] via the haversine formula.
    pub distance_mi: f64,
    /// Latitude in decimal degrees (WGS84).
    pub lat: f64,
    /// Longitude in decimal degrees (WGS84).
    pub lon: f64,
}

/// A priced listing of a product at a particular store.
/// Keyed by a coarse canonical name so that ingredient names can match it.
#[derive(Debug, Clone)]
pub struct StoreListing {
    pub store_listing_id: i64,
    pub canonical_id: i64,
    pub canonical_name: String,
    pub product_name: String,
    pub price_cents: i64,
    pub unit_price_cents: i64,
    pub pack_size_text: String,
    pub image_url: Option<String>,
}

/// Database shim. Replace with a real backing store later; the optimizer
/// only depends on these two lookups.
#[derive(Debug, Default, Clone)]
pub struct ProductDb {
    pub stores: Vec<StoreInfo>,
    /// store_id -> listings
    pub listings: HashMap<i64, Vec<StoreListing>>,
    /// ZIP/postal code -> (lat, lon) geographic anchor used to compute
    /// haversine distances to each store. Unknown zips resolve to no stores.
    pub zip_coords: HashMap<String, (f64, f64)>,
}

impl ProductDb {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_store(&mut self, s: StoreInfo) {
        self.stores.push(s);
    }

    pub fn add_listing(&mut self, store_id: i64, listing: StoreListing) {
        self.listings.entry(store_id).or_default().push(listing);
    }

    /// Register the geographic anchor `(lat, lon)` for a ZIP/postal code so
    /// that [`Self::stores_within`] can compute real distances to it.
    pub fn set_zip_coords(&mut self, zip: &str, lat: f64, lon: f64) {
        self.zip_coords.insert(zip.to_string(), (lat, lon));
    }

    /// Return the stores within `max_mi` (great-circle miles) of the given zip.
    ///
    /// Real implementation: looks up the zip's `(lat, lon)` in the store index
    /// ([`ProductDb::zip_coords`]), computes the haversine distance to every
    /// store, keeps those within `max_mi`, and fills each returned store's
    /// `distance_mi` with the computed value (sorted nearest-first).
    ///
    /// Returns an empty vec when the zip is unknown (no geographic anchor to
    /// measure against) — never a guess.
    pub fn stores_within(&self, zip: &str, max_mi: f64) -> Vec<StoreInfo> {
        let Some((zip_lat, zip_lon)) = self.zip_coords.get(zip) else {
            return Vec::new();
        };
        let mut nearby: Vec<StoreInfo> = self
            .stores
            .iter()
            .map(|s| {
                let mut out = s.clone();
                out.distance_mi = haversine_miles(*zip_lat, *zip_lon, s.lat, s.lon);
                out
            })
            .filter(|s| s.distance_mi <= max_mi)
            .collect();
        nearby.sort_by(|a, b| {
            a.distance_mi
                .partial_cmp(&b.distance_mi)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        nearby
    }

    pub fn listings_for(&self, store_id: i64) -> &[StoreListing] {
        self.listings
            .get(&store_id)
            .map(|v| v.as_slice())
            .unwrap_or(&[])
    }
}

/// Great-circle distance in statute miles between two WGS84 coordinates,
/// using the haversine formula with a mean Earth radius of 3958.8 miles.
pub fn haversine_miles(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    const EARTH_RADIUS_MILES: f64 = 3958.8;
    let d_lat = (lat2 - lat1).to_radians();
    let d_lon = (lon2 - lon1).to_radians();
    let a = (d_lat / 2.0).sin().powi(2)
        + lat1.to_radians().cos() * lat2.to_radians().cos() * (d_lon / 2.0).sin().powi(2);
    2.0 * EARTH_RADIUS_MILES * a.sqrt().asin()
}

pub struct BasketOptimizer {
    db: ProductDb,
}

#[derive(Debug, Clone)]
pub struct Basket {
    pub items: Vec<BasketItem>,
    pub total_cents: i64,
    pub store: String,
    pub store_id: i64,
    pub distance_mi: f64,
    pub missing_items: Vec<String>,
    pub substitutions: Vec<Substitution>,
}

#[derive(Debug, Clone)]
pub struct BasketItem {
    pub ingredient: String,
    pub product_name: String,
    pub price_cents: i64,
    pub unit_price_cents: i64,
    pub quantity_needed: f64,
    pub quantity_unit: String,
    pub image_url: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Substitution {
    pub original: String,
    pub substitute: String,
    pub reason: String,
    pub price_delta_cents: i64,
}

#[derive(Debug, Clone)]
pub struct OptimizationResult {
    pub single_store_baskets: Vec<Basket>,
    pub split_basket: Option<SplitBasket>,
    pub cheapest_single: Basket,
    pub closest_with_all_items: Option<Basket>,
}

#[derive(Debug, Clone)]
pub struct SplitBasket {
    pub stores: Vec<Basket>,
    pub total_cents: i64,
    pub savings_vs_cheapest_single: i64,
    pub extra_stops: usize,
}

#[derive(Debug, Clone)]
pub struct CanonicalMatch {
    pub canonical_id: i64,
    pub store_listing_id: i64,
    pub price_cents: i64,
    pub unit_price_cents: i64,
    pub product_name: String,
    pub image_url: Option<String>,
    pub confidence: f64,
}

impl BasketOptimizer {
    pub fn new() -> Self {
        Self { db: ProductDb::new() }
    }

    pub fn with_db(db: ProductDb) -> Self {
        Self { db }
    }

    pub fn db_mut(&mut self) -> &mut ProductDb {
        &mut self.db
    }

    /// Main entry point.
    pub fn optimize(
        &self,
        recipe: &Recipe,
        user_zip: &str,
        max_distance_mi: f64,
        max_stores: u8,
    ) -> OptimizationResult {
        let stores = self.db.stores_within(user_zip, max_distance_mi);

        // Per-store baskets.
        let mut single_store_baskets: Vec<Basket> = stores
            .iter()
            .map(|s| self.fulfill_basket_with_store(&recipe.ingredients, s))
            .collect();
        single_store_baskets.sort_by_key(|b| (b.missing_items.len() as i64, b.total_cents));

        // Cheapest single store with zero missing items, else cheapest overall.
        let cheapest_single = single_store_baskets
            .iter()
            .find(|b| b.missing_items.is_empty())
            .cloned()
            .unwrap_or_else(|| {
                single_store_baskets
                    .first()
                    .cloned()
                    .unwrap_or_else(|| empty_basket())
            });

        // Closest store that has all items.
        let mut with_all: Vec<Basket> = single_store_baskets
            .iter()
            .filter(|b| b.missing_items.is_empty())
            .cloned()
            .collect();
        with_all.sort_by(|a, b| {
            a.distance_mi
                .partial_cmp(&b.distance_mi)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        let closest_with_all_items = with_all.first().cloned();

        // Split basket — only if user allowed more than one store.
        let split_basket = if max_stores > 1 && stores.len() > 1 {
            let ids: Vec<i64> = stores.iter().map(|s| s.store_id).collect();
            let split = self.greedy_split(&recipe.ingredients, &ids, max_stores as usize);
            let savings = cheapest_single.total_cents - split.total_cents;
            Some(SplitBasket {
                savings_vs_cheapest_single: savings,
                ..split
            })
        } else {
            None
        };

        OptimizationResult {
            single_store_baskets,
            split_basket,
            cheapest_single,
            closest_with_all_items,
        }
    }

    /// For each store, try to fulfill the basket. Exposed for tests and scripts.
    pub fn fulfill_basket(&self, ingredients: &[Ingredient], store_id: i64) -> Basket {
        let store = self
            .db
            .stores
            .iter()
            .find(|s| s.store_id == store_id)
            .cloned()
            .unwrap_or(StoreInfo {
                store_id,
                name: format!("store-{}", store_id),
                distance_mi: 0.0,
                lat: 0.0,
                lon: 0.0,
            });
        self.fulfill_basket_with_store(ingredients, &store)
    }

    fn fulfill_basket_with_store(&self, ingredients: &[Ingredient], store: &StoreInfo) -> Basket {
        let mut items = Vec::new();
        let mut missing = Vec::new();
        let mut total = 0i64;

        for ing in ingredients {
            if ing.optional {
                continue;
            }
            match self.match_ingredient(ing, store.store_id) {
                Some(m) => {
                    total += m.price_cents;
                    items.push(BasketItem {
                        ingredient: ing.item.clone(),
                        product_name: m.product_name,
                        price_cents: m.price_cents,
                        unit_price_cents: m.unit_price_cents,
                        quantity_needed: ing.quantity.unwrap_or(1.0),
                        quantity_unit: ing.unit.clone().unwrap_or_default(),
                        image_url: m.image_url,
                    });
                }
                None => missing.push(ing.item.clone()),
            }
        }

        Basket {
            items,
            total_cents: total,
            store: store.name.clone(),
            store_id: store.store_id,
            distance_mi: store.distance_mi,
            missing_items: missing,
            substitutions: Vec::new(),
        }
    }

    /// Greedy split: for each ingredient, pick the store with the cheapest
    /// matching listing. Constrain to at most `max_stores` distinct stores
    /// by collapsing the tail into the first unused store.
    pub fn greedy_split(
        &self,
        ingredients: &[Ingredient],
        store_ids: &[i64],
        max_stores: usize,
    ) -> SplitBasket {
        // First pass: pick the cheapest store per ingredient.
        let mut assignment: HashMap<i64, Vec<BasketItem>> = HashMap::new();
        for ing in ingredients {
            if ing.optional {
                continue;
            }
            let mut best: Option<(i64, CanonicalMatch)> = None;
            for sid in store_ids {
                if let Some(m) = self.match_ingredient(ing, *sid) {
                    match &best {
                        Some((_, cur)) if cur.price_cents <= m.price_cents => {}
                        _ => best = Some((*sid, m)),
                    }
                }
            }
            if let Some((sid, m)) = best {
                assignment.entry(sid).or_default().push(BasketItem {
                    ingredient: ing.item.clone(),
                    product_name: m.product_name,
                    price_cents: m.price_cents,
                    unit_price_cents: m.unit_price_cents,
                    quantity_needed: ing.quantity.unwrap_or(1.0),
                    quantity_unit: ing.unit.clone().unwrap_or_default(),
                    image_url: m.image_url,
                });
            }
        }

        // Collapse down to max_stores by moving items from the smallest
        // store-baskets to the next cheapest available match in another
        // already-chosen store.
        if assignment.len() > max_stores {
            let mut ranked: Vec<(i64, i64)> = assignment
                .iter()
                .map(|(k, v)| (*k, v.iter().map(|i| i.price_cents).sum::<i64>()))
                .collect();
            ranked.sort_by_key(|r| r.1); // smallest totals first get dropped
            let drop_count = assignment.len() - max_stores;
            let to_drop: Vec<i64> = ranked.iter().take(drop_count).map(|r| r.0).collect();
            let keepers: Vec<i64> = ranked.iter().skip(drop_count).map(|r| r.0).collect();

            for sid in to_drop {
                if let Some(items) = assignment.remove(&sid) {
                    for it in items {
                        // Find cheapest in kept stores.
                        let mut best: Option<(i64, CanonicalMatch)> = None;
                        let synthetic_ing = Ingredient {
                            raw_text: it.ingredient.clone(),
                            quantity: Some(it.quantity_needed),
                            unit: Some(it.quantity_unit.clone()),
                            item: it.ingredient.clone(),
                            preparation: None,
                            optional: false,
                        };
                        for ksid in &keepers {
                            if let Some(m) = self.match_ingredient(&synthetic_ing, *ksid) {
                                match &best {
                                    Some((_, cur)) if cur.price_cents <= m.price_cents => {}
                                    _ => best = Some((*ksid, m)),
                                }
                            }
                        }
                        if let Some((ksid, m)) = best {
                            assignment.entry(ksid).or_default().push(BasketItem {
                                ingredient: synthetic_ing.item.clone(),
                                product_name: m.product_name,
                                price_cents: m.price_cents,
                                unit_price_cents: m.unit_price_cents,
                                quantity_needed: synthetic_ing.quantity.unwrap_or(1.0),
                                quantity_unit: synthetic_ing.unit.clone().unwrap_or_default(),
                                image_url: m.image_url,
                            });
                        }
                    }
                }
            }
        }

        // Build a Basket per store.
        let mut stores_out: Vec<Basket> = assignment
            .into_iter()
            .map(|(sid, items)| {
                let store = self
                    .db
                    .stores
                    .iter()
                    .find(|s| s.store_id == sid)
                    .cloned()
                    .unwrap_or(StoreInfo {
                        store_id: sid,
                        name: format!("store-{}", sid),
                        distance_mi: 0.0,
                        lat: 0.0,
                        lon: 0.0,
                    });
                let total: i64 = items.iter().map(|i| i.price_cents).sum();
                Basket {
                    items,
                    total_cents: total,
                    store: store.name,
                    store_id: store.store_id,
                    distance_mi: store.distance_mi,
                    missing_items: Vec::new(),
                    substitutions: Vec::new(),
                }
            })
            .collect();
        stores_out.sort_by_key(|b| b.total_cents);
        let total: i64 = stores_out.iter().map(|b| b.total_cents).sum();
        let extra_stops = stores_out.len().saturating_sub(1);

        SplitBasket {
            stores: stores_out,
            total_cents: total,
            savings_vs_cheapest_single: 0,
            extra_stops,
        }
    }

    /// Match an ingredient to a canonical product at a specific store.
    ///
    /// Naive string-containment match against canonical_name / product_name.
    /// Returns the cheapest listing whose name contains any non-stopword from
    /// the ingredient item.
    pub fn match_ingredient(
        &self,
        ingredient: &Ingredient,
        store_id: i64,
    ) -> Option<CanonicalMatch> {
        let needle = ingredient.item.to_lowercase();
        if needle.is_empty() {
            return None;
        }
        let tokens: Vec<&str> = needle
            .split_whitespace()
            .filter(|t| !is_stopword(t))
            .collect();
        if tokens.is_empty() {
            return None;
        }

        let listings = self.db.listings_for(store_id);
        let mut best: Option<(CanonicalMatch, usize)> = None;
        for l in listings {
            let hay = format!("{} {}", l.canonical_name, l.product_name).to_lowercase();
            let hits: usize = tokens.iter().filter(|t| hay.contains(*t)).count();
            if hits == 0 {
                continue;
            }
            let confidence = hits as f64 / tokens.len() as f64;
            let cand = CanonicalMatch {
                canonical_id: l.canonical_id,
                store_listing_id: l.store_listing_id,
                price_cents: l.price_cents,
                unit_price_cents: l.unit_price_cents,
                product_name: l.product_name.clone(),
                image_url: l.image_url.clone(),
                confidence,
            };
            match &best {
                Some((cur, cur_hits)) => {
                    if hits > *cur_hits
                        || (hits == *cur_hits && cand.price_cents < cur.price_cents)
                    {
                        best = Some((cand, hits));
                    }
                }
                None => best = Some((cand, hits)),
            }
        }
        best.map(|(c, _)| c)
    }
}

fn empty_basket() -> Basket {
    Basket {
        items: Vec::new(),
        total_cents: 0,
        store: String::new(),
        store_id: 0,
        distance_mi: 0.0,
        missing_items: Vec::new(),
        substitutions: Vec::new(),
    }
}

fn is_stopword(w: &str) -> bool {
    matches!(
        w,
        "the"
            | "a"
            | "an"
            | "of"
            | "for"
            | "and"
            | "or"
            | "to"
            | "with"
            | "fresh"
            | "dried"
            | "ground"
            | "whole"
            | "large"
            | "small"
            | "medium"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::recipe_parser::RecipeParser;

    fn mk_listing(
        id: i64,
        canonical: &str,
        name: &str,
        price: i64,
        unit_price: i64,
    ) -> StoreListing {
        StoreListing {
            store_listing_id: id,
            canonical_id: id,
            canonical_name: canonical.to_string(),
            product_name: name.to_string(),
            price_cents: price,
            unit_price_cents: unit_price,
            pack_size_text: "1".to_string(),
            image_url: None,
        }
    }

    fn sample_db() -> ProductDb {
        let mut db = ProductDb::new();
        // Anchor the query zip near (40.0, -74.0). Stores are placed at known
        // lat/lon so stores_within computes real haversine distances.
        db.set_zip_coords("00000", 40.0, -74.0);
        db.add_store(StoreInfo {
            store_id: 1,
            name: "Aldi".into(),
            distance_mi: 0.0,
            lat: 40.0009,
            lon: -74.0,
        });
        db.add_store(StoreInfo {
            store_id: 2,
            name: "Walmart".into(),
            distance_mi: 0.0,
            lat: 40.05,
            lon: -74.0,
        });
        db.add_store(StoreInfo {
            store_id: 3,
            name: "Whole Foods".into(),
            distance_mi: 0.0,
            lat: 40.09,
            lon: -74.0,
        });
        // A store ~69 mi north — outside any reasonable `max_distance_mi` used
        // by the tests below, proving geographic exclusion works.
        db.add_store(StoreInfo {
            store_id: 4,
            name: "Far Mart".into(),
            distance_mi: 0.0,
            lat: 41.0,
            lon: -74.0,
        });

        // Aldi: cheapest on most things
        db.add_listing(1, mk_listing(101, "flour", "All-Purpose Flour 5lb", 250, 50));
        db.add_listing(1, mk_listing(102, "salt", "Table Salt 26oz", 99, 4));
        db.add_listing(1, mk_listing(103, "ground beef", "80/20 Ground Beef 1lb", 499, 499));
        db.add_listing(1, mk_listing(104, "tomatoes", "Diced Tomatoes 14oz can", 89, 6));
        db.add_listing(1, mk_listing(105, "garlic", "Garlic Bulb", 49, 49));

        // Walmart
        db.add_listing(2, mk_listing(201, "flour", "Gold Medal Flour 5lb", 299, 60));
        db.add_listing(2, mk_listing(202, "salt", "Morton Salt 26oz", 129, 5));
        db.add_listing(2, mk_listing(203, "ground beef", "Ground Beef 1lb", 549, 549));
        db.add_listing(2, mk_listing(204, "tomatoes", "Hunts Diced Tomatoes 14oz", 99, 7));
        db.add_listing(2, mk_listing(205, "garlic", "Fresh Garlic", 59, 59));

        // Whole Foods (pricey)
        db.add_listing(3, mk_listing(301, "flour", "Organic Flour 5lb", 599, 120));
        db.add_listing(3, mk_listing(302, "salt", "Sea Salt 16oz", 299, 19));
        db.add_listing(3, mk_listing(303, "ground beef", "Grass Fed Beef 1lb", 899, 899));
        db.add_listing(3, mk_listing(304, "tomatoes", "Organic Diced Tomatoes", 199, 14));
        db.add_listing(3, mk_listing(305, "garlic", "Organic Garlic", 99, 99));

        db
    }

    fn sample_recipe() -> Recipe {
        Recipe {
            title: "Test".into(),
            servings: 4,
            prep_time_minutes: None,
            cook_time_minutes: None,
            ingredients: vec![
                RecipeParser::parse_ingredient("2 cups flour"),
                RecipeParser::parse_ingredient("1 tsp salt"),
                RecipeParser::parse_ingredient("1 lb ground beef"),
                RecipeParser::parse_ingredient("1 can diced tomatoes"),
                RecipeParser::parse_ingredient("3 cloves garlic, minced"),
            ],
            instructions: vec![],
            source_url: None,
            image_url: None,
        }
    }

    #[test]
    fn cheapest_single_store_is_aldi() {
        let opt = BasketOptimizer::with_db(sample_db());
        let result = opt.optimize(&sample_recipe(), "00000", 10.0, 1);
        assert_eq!(result.cheapest_single.store, "Aldi");
        assert!(result.cheapest_single.missing_items.is_empty());
        assert_eq!(result.cheapest_single.items.len(), 5);
    }

    #[test]
    fn split_basket_never_exceeds_single() {
        let opt = BasketOptimizer::with_db(sample_db());
        let result = opt.optimize(&sample_recipe(), "00000", 10.0, 3);
        let split = result.split_basket.as_ref().expect("split");
        assert!(split.total_cents <= result.cheapest_single.total_cents);
    }

    #[test]
    fn match_ingredient_picks_cheapest_overlap() {
        let opt = BasketOptimizer::with_db(sample_db());
        let ing = RecipeParser::parse_ingredient("1 lb ground beef");
        let m = opt.match_ingredient(&ing, 1).expect("match");
        assert_eq!(m.price_cents, 499);
    }

    #[test]
    fn haversine_known_distances() {
        // ~0.069 mi per 0.001 deg of latitude.
        let small = haversine_miles(40.0, -74.0, 40.001, -74.0);
        assert!((small - 0.069).abs() < 0.01);
        // 1 deg of latitude ≈ 69 mi.
        let one_deg = haversine_miles(40.0, -74.0, 41.0, -74.0);
        assert!((one_deg - 69.0).abs() < 1.0);
        // Zero distance at identical coordinates.
        let zero = haversine_miles(40.0, -74.0, 40.0, -74.0);
        assert!(zero.abs() < 1e-9);
        // Symmetric.
        assert!((small - haversine_miles(40.001, -74.0, 40.0, -74.0)).abs() < 1e-9);
    }

    #[test]
    fn stores_within_filters_by_haversine_distance() {
        let db = sample_db();
        // Aldi/Walmart/Whole Foods are within 10 mi; Far Mart (~69 mi) is not.
        let nearby = db.stores_within("00000", 10.0);
        let ids: Vec<i64> = nearby.iter().map(|s| s.store_id).collect();
        assert_eq!(ids, vec![1, 2, 3]);
        assert!(!ids.contains(&4));

        // distance_mi is filled with a real computed value and sorted nearest-first.
        assert!(nearby[0].distance_mi < nearby[1].distance_mi);
        assert!(nearby[1].distance_mi < nearby[2].distance_mi);
        assert!(nearby[0].distance_mi > 0.0);
        // Far Mart excluded because its distance exceeds max_mi.
        assert!(haversine_miles(40.0, -74.0, 41.0, -74.0) > 10.0);
    }

    #[test]
    fn stores_within_unknown_zip_is_empty() {
        let db = sample_db();
        // No anchor registered for this zip → no stores (never a guess).
        assert!(db.stores_within("99999", 1000.0).is_empty());
    }

    #[test]
    fn optimize_uses_real_nearby_stores() {
        let opt = BasketOptimizer::with_db(sample_db());
        // Far Mart (id 4) has no listings and sits ~69 mi away; optimize must
        // not even consider it. cheapest single store is still Aldi.
        let result = opt.optimize(&sample_recipe(), "00000", 10.0, 3);
        assert_eq!(result.cheapest_single.store, "Aldi");
        assert!(result.cheapest_single.missing_items.is_empty());
        // Closest-with-all-items is Aldi (nearest store that has everything).
        assert_eq!(
            result.closest_with_all_items.as_ref().map(|b| b.store.as_str()),
            Some("Aldi")
        );
    }
}
