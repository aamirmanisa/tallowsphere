//! Product substitution engine: maintains a graph of canonical product →
//! alternatives and answers "find me something else" queries (out of stock,
//! cheaper, generic equivalent, dietary swap, etc.).

use std::collections::HashMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SubstitutionType {
    Equivalent,
    Upgrade,
    Downgrade,
    CloseAlternative,
    DietarySwap,
    PackSize,
}

#[derive(Debug, Clone)]
pub struct Substitute {
    pub canonical_id: i64,
    pub similarity: f64,
    pub substitution_type: SubstitutionType,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SuggestionReason {
    OutOfStock,
    CheaperAlternative,
    BetterUnitPrice,
    DietaryRestriction,
    BrandPreference,
}

#[derive(Debug, Clone)]
pub struct SubstituteOption {
    pub canonical_id: i64,
    pub product_name: String,
    pub brand: String,
    pub price_cents: i64,
    pub unit_price_cents: i64,
    pub store_id: i64,
    pub price_delta_cents: i64,
    pub similarity: f64,
    pub notes: String,
}

#[derive(Debug, Clone)]
pub struct SubstitutionSuggestion {
    pub original: String,
    pub suggestions: Vec<SubstituteOption>,
    pub reason: SuggestionReason,
}

#[derive(Debug, Clone)]
struct ProductInfo {
    name: String,
    brand: String,
    price_cents: i64,
    unit_price_cents: i64,
    store_id: i64,
    is_generic: bool,
}

#[derive(Default)]
pub struct SubstitutionEngine {
    substitution_graph: HashMap<i64, Vec<Substitute>>,
    catalog: HashMap<i64, ProductInfo>,
}

impl SubstitutionEngine {
    pub fn new() -> Self {
        Self {
            substitution_graph: HashMap::new(),
            catalog: HashMap::new(),
        }
    }

    /// Register a product so its metadata is available when building
    /// SubstituteOptions.
    #[allow(clippy::too_many_arguments)]
    pub fn register_product(
        &mut self,
        id: i64,
        name: &str,
        brand: &str,
        price_cents: i64,
        unit_price_cents: i64,
        store_id: i64,
        is_generic: bool,
    ) {
        self.catalog.insert(
            id,
            ProductInfo {
                name: name.to_string(),
                brand: brand.to_string(),
                price_cents,
                unit_price_cents,
                store_id,
                is_generic,
            },
        );
    }

    /// Add a directed edge from → to in the substitution graph.
    pub fn add_substitute(&mut self, from: i64, to: Substitute) {
        self.substitution_graph.entry(from).or_default().push(to);
    }

    fn build_option(&self, from_id: i64, sub: &Substitute) -> Option<SubstituteOption> {
        let info = self.catalog.get(&sub.canonical_id)?;
        let from_price = self.catalog.get(&from_id).map(|i| i.price_cents).unwrap_or(0);
        Some(SubstituteOption {
            canonical_id: sub.canonical_id,
            product_name: info.name.clone(),
            brand: info.brand.clone(),
            price_cents: info.price_cents,
            unit_price_cents: info.unit_price_cents,
            store_id: info.store_id,
            price_delta_cents: info.price_cents - from_price,
            similarity: sub.similarity,
            notes: sub.reason.clone(),
        })
    }

    /// Main query: find substitutes for a product under a given reason.
    pub fn find_substitutes(
        &self,
        canonical_id: i64,
        reason: SuggestionReason,
    ) -> SubstitutionSuggestion {
        let original = self
            .catalog
            .get(&canonical_id)
            .map(|i| i.name.clone())
            .unwrap_or_default();

        let subs = self
            .substitution_graph
            .get(&canonical_id)
            .cloned()
            .unwrap_or_default();

        // Filter by reason.
        let filtered: Vec<Substitute> = subs
            .into_iter()
            .filter(|s| match reason {
                SuggestionReason::DietaryRestriction => {
                    s.substitution_type == SubstitutionType::DietarySwap
                }
                SuggestionReason::BrandPreference => matches!(
                    s.substitution_type,
                    SubstitutionType::Equivalent | SubstitutionType::Downgrade
                ),
                SuggestionReason::OutOfStock => s.substitution_type != SubstitutionType::Upgrade
                    || s.similarity >= 0.8,
                _ => true,
            })
            .collect();

        let mut options: Vec<SubstituteOption> = filtered
            .iter()
            .filter_map(|s| self.build_option(canonical_id, s))
            .collect();

        // Sort by reason-appropriate key.
        match reason {
            SuggestionReason::CheaperAlternative => {
                options.sort_by_key(|o| o.price_cents);
            }
            SuggestionReason::BetterUnitPrice => {
                options.sort_by_key(|o| o.unit_price_cents);
            }
            _ => {
                options.sort_by(|a, b| {
                    b.similarity
                        .partial_cmp(&a.similarity)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
        }

        SubstitutionSuggestion {
            original,
            suggestions: options,
            reason,
        }
    }

    /// Cheapest substitute available, optionally scoped to a store.
    pub fn cheapest_substitute(
        &self,
        canonical_id: i64,
        store_id: i64,
    ) -> Option<SubstituteOption> {
        let sugg = self.find_substitutes(canonical_id, SuggestionReason::CheaperAlternative);
        sugg.suggestions
            .into_iter()
            .filter(|o| store_id == 0 || o.store_id == store_id)
            .min_by_key(|o| o.price_cents)
    }

    /// Find a store-brand / generic equivalent of a branded product.
    pub fn find_generic(&self, canonical_id: i64) -> Option<SubstituteOption> {
        let subs = self.substitution_graph.get(&canonical_id)?;
        subs.iter()
            .filter(|s| s.substitution_type == SubstitutionType::Equivalent)
            .filter_map(|s| {
                let info = self.catalog.get(&s.canonical_id)?;
                if info.is_generic {
                    self.build_option(canonical_id, s)
                } else {
                    None
                }
            })
            .min_by_key(|o| o.price_cents)
    }

    /// Seed a few well-known substitution patterns. Callers still need to
    /// `register_product` for the referenced ids; this only wires edges.
    pub fn seed_common_substitutions(&mut self) {
        // ground beef (100) -> ground turkey (101)
        self.add_substitute(
            100,
            Substitute {
                canonical_id: 101,
                similarity: 0.75,
                substitution_type: SubstitutionType::CloseAlternative,
                reason: "leaner protein, similar cooking".into(),
            },
        );
        // butter (200) -> margarine (201)
        self.add_substitute(
            200,
            Substitute {
                canonical_id: 201,
                similarity: 0.7,
                substitution_type: SubstitutionType::CloseAlternative,
                reason: "plant-based fat alternative".into(),
            },
        );
        // cow milk (300) -> oat milk (301)
        self.add_substitute(
            300,
            Substitute {
                canonical_id: 301,
                similarity: 0.8,
                substitution_type: SubstitutionType::DietarySwap,
                reason: "vegan / lactose-free".into(),
            },
        );
        // wheat pasta (400) -> gluten-free pasta (401)
        self.add_substitute(
            400,
            Substitute {
                canonical_id: 401,
                similarity: 0.85,
                substitution_type: SubstitutionType::DietarySwap,
                reason: "gluten-free".into(),
            },
        );
        // heavy cream (500) -> half and half (501)
        self.add_substitute(
            500,
            Substitute {
                canonical_id: 501,
                similarity: 0.9,
                substitution_type: SubstitutionType::Downgrade,
                reason: "lower fat content".into(),
            },
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> SubstitutionEngine {
        let mut e = SubstitutionEngine::new();
        e.register_product(1, "Name Brand Cereal", "Kellogg", 499, 30, 1, false);
        e.register_product(2, "Store Brand Cereal", "Kirkland", 299, 18, 1, true);
        e.register_product(3, "Premium Organic Cereal", "Nature", 699, 42, 1, false);
        e.add_substitute(
            1,
            Substitute {
                canonical_id: 2,
                similarity: 0.9,
                substitution_type: SubstitutionType::Equivalent,
                reason: "store brand".into(),
            },
        );
        e.add_substitute(
            1,
            Substitute {
                canonical_id: 3,
                similarity: 0.85,
                substitution_type: SubstitutionType::Upgrade,
                reason: "organic".into(),
            },
        );
        e
    }

    #[test]
    fn find_cheaper_sorts_by_price() {
        let e = engine();
        let s = e.find_substitutes(1, SuggestionReason::CheaperAlternative);
        assert_eq!(s.suggestions[0].canonical_id, 2);
    }

    #[test]
    fn find_better_unit_price() {
        let e = engine();
        let s = e.find_substitutes(1, SuggestionReason::BetterUnitPrice);
        assert_eq!(s.suggestions[0].canonical_id, 2);
    }

    #[test]
    fn cheapest_substitute_returns_generic() {
        let e = engine();
        let c = e.cheapest_substitute(1, 0).unwrap();
        assert_eq!(c.canonical_id, 2);
        assert!(c.price_delta_cents < 0);
    }

    #[test]
    fn find_generic_returns_kirkland() {
        let e = engine();
        let g = e.find_generic(1).unwrap();
        assert_eq!(g.canonical_id, 2);
    }

    #[test]
    fn dietary_filter() {
        let mut e = SubstitutionEngine::new();
        e.register_product(10, "Milk", "Dairy", 300, 20, 1, false);
        e.register_product(11, "Oat Milk", "Oatly", 500, 35, 1, false);
        e.register_product(12, "Store Milk", "SB", 250, 16, 1, true);
        e.add_substitute(
            10,
            Substitute {
                canonical_id: 11,
                similarity: 0.8,
                substitution_type: SubstitutionType::DietarySwap,
                reason: "vegan".into(),
            },
        );
        e.add_substitute(
            10,
            Substitute {
                canonical_id: 12,
                similarity: 0.95,
                substitution_type: SubstitutionType::Equivalent,
                reason: "store brand".into(),
            },
        );
        let s = e.find_substitutes(10, SuggestionReason::DietaryRestriction);
        assert_eq!(s.suggestions.len(), 1);
        assert_eq!(s.suggestions[0].canonical_id, 11);
    }

    #[test]
    fn seed_adds_edges() {
        let mut e = SubstitutionEngine::new();
        e.seed_common_substitutions();
        assert!(e.substitution_graph.contains_key(&100));
        assert!(e.substitution_graph.contains_key(&300));
    }

    #[test]
    fn no_substitutes_empty_result() {
        let e = SubstitutionEngine::new();
        let s = e.find_substitutes(999, SuggestionReason::OutOfStock);
        assert!(s.suggestions.is_empty());
    }
}
