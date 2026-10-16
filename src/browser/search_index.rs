//! Search index wrapper supporting multiple backends.
//!
//! Starts with an in-memory inverted index for Tier 1 / MVP. The
//! [`SearchBackend`] trait lets production swap to Typesense / Meilisearch
//! without changing call sites.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

#[derive(Debug, Clone)]
pub struct IndexedProduct {
    pub id: i64,
    pub name: String,
    pub brand: String,
    pub category: String,
    pub size: String,
    pub image_url: Option<String>,
    pub current_min_price_cents: Option<i64>,
    pub current_max_price_cents: Option<i64>,
    pub store_count: i32,
    pub popularity_score: f64,
}

#[derive(Debug, Clone)]
pub enum SortBy {
    Relevance,
    PriceAsc,
    PriceDesc,
    UnitPriceAsc,
    Newest,
    Distance,
}

#[derive(Debug, Clone)]
pub struct SearchQuery {
    pub text: String,
    pub category: Option<String>,
    pub brand: Option<String>,
    pub zip: Option<String>,
    pub max_distance_mi: Option<f64>,
    pub min_price_cents: Option<i64>,
    pub max_price_cents: Option<i64>,
    pub in_stock_only: bool,
    pub on_sale_only: bool,
    pub sort_by: SortBy,
    pub limit: usize,
    pub offset: usize,
}

impl Default for SearchQuery {
    fn default() -> Self {
        Self {
            text: String::new(),
            category: None,
            brand: None,
            zip: None,
            max_distance_mi: None,
            min_price_cents: None,
            max_price_cents: None,
            in_stock_only: false,
            on_sale_only: false,
            sort_by: SortBy::Relevance,
            limit: 20,
            offset: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SearchResult {
    pub product: IndexedProduct,
    pub score: f64,
    pub highlights: Vec<String>,
}

/// Pluggable search backend interface. The in-memory implementation
/// satisfies this so production may swap to Typesense / Meilisearch.
pub trait SearchBackend: Send + Sync {
    fn index(&self, product: IndexedProduct) -> Result<(), String>;
    fn delete(&self, id: i64) -> Result<(), String>;
    fn search(&self, query: &SearchQuery) -> Result<Vec<SearchResult>, String>;
    fn suggest(&self, prefix: &str, limit: usize) -> Result<Vec<String>, String>;
}

const STOPWORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "of", "for", "to", "in", "on", "with", "by", "is", "at",
];

pub struct ProductSearchIndex {
    inverted: RwLock<HashMap<String, Vec<i64>>>,
    products: RwLock<HashMap<i64, IndexedProduct>>,
}

impl Default for ProductSearchIndex {
    fn default() -> Self {
        Self::new()
    }
}

impl ProductSearchIndex {
    pub fn new() -> Self {
        Self {
            inverted: RwLock::new(HashMap::new()),
            products: RwLock::new(HashMap::new()),
        }
    }

    pub fn add(&self, product: IndexedProduct) {
        let id = product.id;
        // Remove first to keep inverted index clean on re-index.
        self.remove(id);

        let tokens = Self::tokenize(&format!(
            "{} {} {} {}",
            product.name, product.brand, product.category, product.size
        ));

        {
            let mut inv = self.inverted.write().unwrap();
            for tok in tokens {
                inv.entry(tok).or_insert_with(Vec::new).push(id);
            }
        }
        self.products.write().unwrap().insert(id, product);
    }

    pub fn remove(&self, id: i64) {
        self.products.write().unwrap().remove(&id);
        let mut inv = self.inverted.write().unwrap();
        for ids in inv.values_mut() {
            ids.retain(|x| *x != id);
        }
        inv.retain(|_, v| !v.is_empty());
    }

    pub fn search(&self, query: &SearchQuery) -> Vec<SearchResult> {
        let tokens = Self::tokenize(&query.text);
        let products = self.products.read().unwrap();

        // Candidate set: union of postings; if no tokens, all products.
        let candidates: HashSet<i64> = if tokens.is_empty() {
            products.keys().copied().collect()
        } else {
            let inv = self.inverted.read().unwrap();
            let mut set: HashSet<i64> = HashSet::new();
            for tok in &tokens {
                if let Some(ids) = inv.get(tok) {
                    for id in ids {
                        set.insert(*id);
                    }
                }
            }
            set
        };

        let mut results: Vec<SearchResult> = candidates
            .into_iter()
            .filter_map(|id| products.get(&id).cloned())
            .map(|p| {
                let score = self.score_result(&p, &tokens);
                let highlights = tokens
                    .iter()
                    .filter(|t| p.name.to_lowercase().contains(t.as_str()))
                    .cloned()
                    .collect();
                SearchResult { product: p, score, highlights }
            })
            .collect();

        results = self.faceted_filter(results, query);

        match query.sort_by {
            SortBy::Relevance => {
                results.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal))
            }
            SortBy::PriceAsc => results.sort_by_key(|r| r.product.current_min_price_cents.unwrap_or(i64::MAX)),
            SortBy::PriceDesc => {
                results.sort_by(|a, b| {
                    b.product
                        .current_max_price_cents
                        .unwrap_or(i64::MIN)
                        .cmp(&a.product.current_max_price_cents.unwrap_or(i64::MIN))
                })
            }
            SortBy::UnitPriceAsc => results.sort_by_key(|r| r.product.current_min_price_cents.unwrap_or(i64::MAX)),
            SortBy::Newest => results.sort_by_key(|r| -r.product.id),
            SortBy::Distance => {} // Distance requires store-location join; no-op here.
        }

        let start = query.offset.min(results.len());
        let end = (start + query.limit).min(results.len());
        results[start..end].to_vec()
    }

    pub fn suggest(&self, prefix: &str, limit: usize) -> Vec<String> {
        let prefix_l = prefix.to_lowercase();
        if prefix_l.is_empty() {
            return Vec::new();
        }
        let inv = self.inverted.read().unwrap();
        let mut matches: Vec<String> = inv
            .keys()
            .filter(|k| k.starts_with(&prefix_l))
            .cloned()
            .collect();
        matches.sort();
        matches.truncate(limit);
        matches
    }

    fn tokenize(text: &str) -> Vec<String> {
        text.to_lowercase()
            .split(|c: char| !c.is_alphanumeric())
            .filter(|s| !s.is_empty() && !STOPWORDS.contains(s))
            .map(|s| {
                // Trivial stemmer: strip trailing 's'.
                if s.len() > 3 && s.ends_with('s') {
                    s[..s.len() - 1].to_string()
                } else {
                    s.to_string()
                }
            })
            .collect()
    }

    fn score_result(&self, product: &IndexedProduct, query_tokens: &[String]) -> f64 {
        if query_tokens.is_empty() {
            return product.popularity_score;
        }
        let name_l = product.name.to_lowercase();
        let brand_l = product.brand.to_lowercase();
        let cat_l = product.category.to_lowercase();

        let mut score = 0.0;
        for tok in query_tokens {
            if name_l.contains(tok) {
                score += 3.0;
            }
            if brand_l.contains(tok) {
                score += 2.0;
            }
            if cat_l.contains(tok) {
                score += 1.0;
            }
        }
        score += product.popularity_score * 0.1;
        score += (product.store_count as f64).ln_1p() * 0.5;
        score
    }

    fn faceted_filter(&self, results: Vec<SearchResult>, query: &SearchQuery) -> Vec<SearchResult> {
        results
            .into_iter()
            .filter(|r| {
                if let Some(cat) = &query.category {
                    if !r.product.category.eq_ignore_ascii_case(cat) {
                        return false;
                    }
                }
                if let Some(brand) = &query.brand {
                    if !r.product.brand.eq_ignore_ascii_case(brand) {
                        return false;
                    }
                }
                if let Some(min) = query.min_price_cents {
                    if r.product.current_min_price_cents.unwrap_or(i64::MAX) < min {
                        return false;
                    }
                }
                if let Some(max) = query.max_price_cents {
                    if r.product.current_max_price_cents.unwrap_or(0) > max {
                        return false;
                    }
                }
                if query.in_stock_only && r.product.store_count <= 0 {
                    return false;
                }
                true
            })
            .collect()
    }
}

impl SearchBackend for ProductSearchIndex {
    fn index(&self, product: IndexedProduct) -> Result<(), String> {
        self.add(product);
        Ok(())
    }
    fn delete(&self, id: i64) -> Result<(), String> {
        self.remove(id);
        Ok(())
    }
    fn search(&self, query: &SearchQuery) -> Result<Vec<SearchResult>, String> {
        Ok(ProductSearchIndex::search(self, query))
    }
    fn suggest(&self, prefix: &str, limit: usize) -> Result<Vec<String>, String> {
        Ok(ProductSearchIndex::suggest(self, prefix, limit))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(id: i64, name: &str, brand: &str, cat: &str, price: i64) -> IndexedProduct {
        IndexedProduct {
            id,
            name: name.into(),
            brand: brand.into(),
            category: cat.into(),
            size: "1ct".into(),
            image_url: None,
            current_min_price_cents: Some(price),
            current_max_price_cents: Some(price + 100),
            store_count: 3,
            popularity_score: 1.0,
        }
    }

    #[test]
    fn add_and_search_by_text() {
        let idx = ProductSearchIndex::new();
        idx.add(sample(1, "Organic Milk", "Horizon", "dairy", 499));
        idx.add(sample(2, "Almond Milk", "Silk", "dairy", 399));
        idx.add(sample(3, "Sourdough Bread", "Boudin", "bakery", 699));

        let q = SearchQuery { text: "milk".into(), ..Default::default() };
        let r = idx.search(&q);
        assert_eq!(r.len(), 2);
        assert!(r.iter().all(|x| x.product.category == "dairy"));
    }

    #[test]
    fn filter_by_category_and_sort_price() {
        let idx = ProductSearchIndex::new();
        idx.add(sample(1, "Organic Milk", "Horizon", "dairy", 499));
        idx.add(sample(2, "Almond Milk", "Silk", "dairy", 399));
        idx.add(sample(3, "Whole Milk", "Generic", "dairy", 299));

        let q = SearchQuery {
            text: "milk".into(),
            category: Some("dairy".into()),
            sort_by: SortBy::PriceAsc,
            ..Default::default()
        };
        let r = idx.search(&q);
        assert_eq!(r.len(), 3);
        assert_eq!(r[0].product.id, 3);
        assert_eq!(r[2].product.id, 1);
    }

    #[test]
    fn suggest_autocomplete() {
        let idx = ProductSearchIndex::new();
        idx.add(sample(1, "Organic Milk", "Horizon", "dairy", 499));
        idx.add(sample(2, "Almond Milk", "Silk", "dairy", 399));
        let s = idx.suggest("mil", 5);
        assert!(s.iter().any(|t| t == "milk"));
    }

    #[test]
    fn remove_works() {
        let idx = ProductSearchIndex::new();
        idx.add(sample(1, "Organic Milk", "Horizon", "dairy", 499));
        idx.remove(1);
        let q = SearchQuery { text: "milk".into(), ..Default::default() };
        assert!(idx.search(&q).is_empty());
    }

    #[test]
    fn backend_trait_works() {
        let idx: Box<dyn SearchBackend> = Box::new(ProductSearchIndex::new());
        idx.index(sample(1, "Eggs", "Farm", "dairy", 599)).unwrap();
        let r = idx.search(&SearchQuery { text: "eggs".into(), ..Default::default() }).unwrap();
        assert_eq!(r.len(), 1);
    }
}
