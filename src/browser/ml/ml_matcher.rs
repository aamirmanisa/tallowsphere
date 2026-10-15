//! ML-driven product matcher.
//!
//! Strategy:
//!   1. UPC exact match -> 0.99 confidence (UpcExact)
//!   2. Embed query, retrieve top-K from vector store (EmbeddingSimilarity)
//!   3. Re-rank with a feature-blended pseudo cross-encoder
//!      score = embedding_cosine * 0.6 + text_overlap * 0.3 + brand_bonus * 0.1
//!      (size match contributes a small additive bonus)
//!   4. Return best match + alternatives, or NoMatch.

use std::collections::{HashMap, HashSet};

use super::embeddings::EmbeddingEngine;
use super::vector_store::VectorStore;

#[derive(Debug, Clone)]
pub struct ProductMeta {
    pub id: i64,
    pub name: String,
    pub brand: String,
    pub size: String,
    pub upc: Option<String>,
    pub image_url: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlMatchMethod {
    UpcExact,
    EmbeddingSimilarity,
    CrossEncoderRerank,
    NoMatch,
}

#[derive(Debug, Clone)]
pub struct MlMatchResult {
    pub canonical_id: Option<i64>,
    pub confidence: f64,
    pub method: MlMatchMethod,
    pub alternatives: Vec<(i64, f64)>,
}

pub struct MlProductMatcher {
    embedding_engine: EmbeddingEngine,
    vector_store: VectorStore,
    product_metadata: HashMap<i64, ProductMeta>,
    upc_index: HashMap<String, i64>,
}

impl MlProductMatcher {
    pub fn new(embedding_engine: EmbeddingEngine) -> Self {
        let dim = embedding_engine.dim();
        Self {
            embedding_engine,
            vector_store: VectorStore::new(dim),
            product_metadata: HashMap::new(),
            upc_index: HashMap::new(),
        }
    }

    /// Register a canonical product.
    pub fn register(&mut self, product: ProductMeta) {
        let text = Self::product_text(&product);
        if let Ok(v) = self.embedding_engine.embed(&text) {
            self.vector_store.add(product.id, v);
        }
        if let Some(upc) = &product.upc {
            self.upc_index.insert(upc.clone(), product.id);
        }
        self.product_metadata.insert(product.id, product);
    }

    pub fn len(&self) -> usize {
        self.product_metadata.len()
    }

    pub fn is_empty(&self) -> bool {
        self.product_metadata.is_empty()
    }

    /// Match a scraped listing against the canonical catalog.
    pub fn match_listing(
        &self,
        title: &str,
        brand: Option<&str>,
        size: Option<&str>,
    ) -> MlMatchResult {
        // 1. UPC fast-path — caller can pass UPC-looking string in title.
        if let Some(upc) = extract_upc(title) {
            if let Some(&id) = self.upc_index.get(&upc) {
                return MlMatchResult {
                    canonical_id: Some(id),
                    confidence: 0.99,
                    method: MlMatchMethod::UpcExact,
                    alternatives: Vec::new(),
                };
            }
        }

        if self.vector_store.is_empty() {
            return MlMatchResult {
                canonical_id: None,
                confidence: 0.0,
                method: MlMatchMethod::NoMatch,
                alternatives: Vec::new(),
            };
        }

        // 2. Embed query and retrieve top-20 candidates.
        let query_text = build_query_text(title, brand, size);
        let q = match self.embedding_engine.embed(&query_text) {
            Ok(v) => v,
            Err(_) => {
                return MlMatchResult {
                    canonical_id: None,
                    confidence: 0.0,
                    method: MlMatchMethod::NoMatch,
                    alternatives: Vec::new(),
                };
            }
        };
        let candidates = self.vector_store.search(&q, 20);
        if candidates.is_empty() {
            return MlMatchResult {
                canonical_id: None,
                confidence: 0.0,
                method: MlMatchMethod::NoMatch,
                alternatives: Vec::new(),
            };
        }

        // 3. Cross-encoder rerank with feature blending.
        let pairs: Vec<(i64, f32)> =
            candidates.iter().map(|r| (r.id, r.score)).collect();
        let reranked = self.cross_encoder_rerank((title, brand, size), &pairs);

        if reranked.is_empty() {
            return MlMatchResult {
                canonical_id: None,
                confidence: 0.0,
                method: MlMatchMethod::NoMatch,
                alternatives: Vec::new(),
            };
        }

        let (best_id, best_score) = reranked[0];
        let alternatives = reranked.iter().skip(1).take(4).cloned().collect();
        let method = if reranked.len() > 1 {
            MlMatchMethod::CrossEncoderRerank
        } else {
            MlMatchMethod::EmbeddingSimilarity
        };
        MlMatchResult {
            canonical_id: Some(best_id),
            confidence: best_score.clamp(0.0, 1.0),
            method,
            alternatives,
        }
    }

    /// Pseudo cross-encoder. Blends embedding cosine with token-overlap,
    /// brand-match bonus, and size-match bonus.
    pub fn cross_encoder_rerank(
        &self,
        query: (&str, Option<&str>, Option<&str>),
        candidates: &[(i64, f32)],
    ) -> Vec<(i64, f64)> {
        let (q_title, q_brand, q_size) = query;
        let q_tokens = tokenize(q_title);

        let mut scored: Vec<(i64, f64)> = candidates
            .iter()
            .filter_map(|(id, cos)| {
                let meta = self.product_metadata.get(id)?;
                let cand_tokens = tokenize(&meta.name);
                let overlap = jaccard(&q_tokens, &cand_tokens);
                let brand_bonus = match q_brand {
                    Some(b) if !b.is_empty()
                        && b.to_lowercase() == meta.brand.to_lowercase() =>
                    {
                        1.0
                    }
                    Some(_) => 0.0,
                    None => 0.5, // unknown brand — neutral
                };
                let size_bonus = match q_size {
                    Some(s) if !s.is_empty()
                        && normalize_size(s) == normalize_size(&meta.size) =>
                    {
                        0.05
                    }
                    _ => 0.0,
                };
                let score = (*cos as f64) * 0.6
                    + overlap * 0.3
                    + brand_bonus * 0.1
                    + size_bonus;
                Some((*id, score))
            })
            .collect();

        scored.sort_by(|a, b| {
            b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal)
        });
        scored
    }

    /// Build the canonical embedding input for a product.
    pub fn product_text(meta: &ProductMeta) -> String {
        let mut s = String::new();
        if !meta.brand.is_empty() {
            s.push_str(&meta.brand);
            s.push(' ');
        }
        s.push_str(&meta.name);
        if !meta.size.is_empty() {
            s.push(' ');
            s.push_str(&meta.size);
        }
        s
    }
}

fn build_query_text(title: &str, brand: Option<&str>, size: Option<&str>) -> String {
    let mut s = String::new();
    if let Some(b) = brand {
        if !b.is_empty() {
            s.push_str(b);
            s.push(' ');
        }
    }
    s.push_str(title);
    if let Some(sz) = size {
        if !sz.is_empty() {
            s.push(' ');
            s.push_str(sz);
        }
    }
    s
}

fn tokenize(s: &str) -> HashSet<String> {
    s.to_lowercase()
        .split(|c: char| !c.is_alphanumeric())
        .filter(|t| !t.is_empty() && t.len() > 1)
        .map(|t| t.to_string())
        .collect()
}

fn jaccard(a: &HashSet<String>, b: &HashSet<String>) -> f64 {
    if a.is_empty() && b.is_empty() {
        return 0.0;
    }
    let inter = a.intersection(b).count() as f64;
    let union = a.union(b).count() as f64;
    if union == 0.0 {
        0.0
    } else {
        inter / union
    }
}

fn normalize_size(s: &str) -> String {
    s.to_lowercase()
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect()
}

/// Heuristic UPC extractor: a 12-13 digit run.
fn extract_upc(s: &str) -> Option<String> {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.len() == 12 || digits.len() == 13 {
        Some(digits)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_matcher() -> MlProductMatcher {
        let mut m = MlProductMatcher::new(EmbeddingEngine::mock(384));
        m.register(ProductMeta {
            id: 1,
            name: "Organic Whole Milk".to_string(),
            brand: "Horizon".to_string(),
            size: "1 gallon".to_string(),
            upc: Some("012345678905".to_string()),
            image_url: None,
        });
        m.register(ProductMeta {
            id: 2,
            name: "Organic Skim Milk".to_string(),
            brand: "Horizon".to_string(),
            size: "1 gallon".to_string(),
            upc: Some("012345678912".to_string()),
            image_url: None,
        });
        m.register(ProductMeta {
            id: 3,
            name: "Almond Milk Unsweetened".to_string(),
            brand: "Silk".to_string(),
            size: "64 oz".to_string(),
            upc: None,
            image_url: None,
        });
        m
    }

    #[test]
    fn upc_match_high_confidence() {
        let m = make_matcher();
        let r = m.match_listing("012345678905", None, None);
        assert_eq!(r.method, MlMatchMethod::UpcExact);
        assert_eq!(r.canonical_id, Some(1));
        assert!(r.confidence >= 0.99);
    }

    #[test]
    fn similar_title_finds_match() {
        let m = make_matcher();
        let r = m.match_listing(
            "Organic Whole Milk",
            Some("Horizon"),
            Some("1 gallon"),
        );
        assert_eq!(r.canonical_id, Some(1));
        assert!(r.confidence > 0.3);
    }

    #[test]
    fn different_brand_lower_confidence() {
        let m = make_matcher();
        let same_brand = m.match_listing(
            "Organic Whole Milk",
            Some("Horizon"),
            Some("1 gallon"),
        );
        let diff_brand = m.match_listing(
            "Organic Whole Milk",
            Some("NotARealBrand"),
            Some("1 gallon"),
        );
        // Same brand should score >= different brand for the same target.
        assert!(
            same_brand.confidence >= diff_brand.confidence,
            "{} vs {}",
            same_brand.confidence,
            diff_brand.confidence
        );
    }

    #[test]
    fn empty_index_returns_no_match() {
        let m = MlProductMatcher::new(EmbeddingEngine::mock(384));
        let r = m.match_listing("anything", None, None);
        assert_eq!(r.method, MlMatchMethod::NoMatch);
        assert!(r.canonical_id.is_none());
    }

    #[test]
    fn alternatives_populated() {
        let m = make_matcher();
        let r = m.match_listing("Milk", None, None);
        assert!(r.canonical_id.is_some());
        assert!(!r.alternatives.is_empty());
    }

    #[test]
    fn product_text_includes_all_fields() {
        let meta = ProductMeta {
            id: 1,
            name: "Whole Milk".to_string(),
            brand: "Horizon".to_string(),
            size: "1 gal".to_string(),
            upc: None,
            image_url: None,
        };
        let t = MlProductMatcher::product_text(&meta);
        assert!(t.contains("Horizon"));
        assert!(t.contains("Whole Milk"));
        assert!(t.contains("1 gal"));
    }
}
