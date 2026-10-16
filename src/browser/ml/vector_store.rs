//! In-memory vector store with linear cosine search.
//!
//! Suitable for <10K vectors. Above that, swap in HNSW from `instant-distance`
//! or `hnsw_rs`. The public API is intentionally minimal so a future HNSW
//! backend can be a drop-in replacement.

use std::collections::HashMap;
use std::fs;

use super::embeddings::EmbeddingEngine;

#[derive(Debug, Clone, PartialEq)]
pub struct SearchResult {
    pub id: i64,
    pub score: f32,
}

pub struct VectorStore {
    vectors: HashMap<i64, Vec<f32>>,
    dim: usize,
}

impl VectorStore {
    pub fn new(dim: usize) -> Self {
        Self {
            vectors: HashMap::new(),
            dim,
        }
    }

    pub fn dim(&self) -> usize {
        self.dim
    }

    /// Add a vector. Caller should pre-normalize for cosine via dot-product.
    /// Vectors of mismatched dimension are silently dropped (debug-asserted).
    pub fn add(&mut self, id: i64, vector: Vec<f32>) {
        debug_assert_eq!(vector.len(), self.dim, "vector dim mismatch");
        if vector.len() == self.dim {
            self.vectors.insert(id, vector);
        }
    }

    pub fn remove(&mut self, id: i64) {
        self.vectors.remove(&id);
    }

    pub fn len(&self) -> usize {
        self.vectors.len()
    }

    pub fn is_empty(&self) -> bool {
        self.vectors.is_empty()
    }

    /// Linear cosine search returning top-k highest similarity scores.
    pub fn search(&self, query: &[f32], top_k: usize) -> Vec<SearchResult> {
        self.search_filtered(query, top_k, |_| true)
    }

    /// Filtered linear search — `filter(id) == false` excludes that vector.
    pub fn search_filtered(
        &self,
        query: &[f32],
        top_k: usize,
        filter: impl Fn(i64) -> bool,
    ) -> Vec<SearchResult> {
        if query.len() != self.dim || top_k == 0 {
            return Vec::new();
        }
        let mut scored: Vec<SearchResult> = self
            .vectors
            .iter()
            .filter(|(id, _)| filter(**id))
            .map(|(id, v)| SearchResult {
                id: *id,
                score: EmbeddingEngine::cosine(query, v),
            })
            .collect();
        scored.sort_by(|a, b| b.score.partial_cmp(&a.score).unwrap_or(std::cmp::Ordering::Equal));
        scored.truncate(top_k);
        scored
    }

    /// Save to disk as a tiny JSON file. Uses no extra deps.
    pub fn save(&self, path: &str) -> Result<(), String> {
        let mut s = String::new();
        s.push_str(&format!("{{\"dim\":{},\"vectors\":{{", self.dim));
        let mut first = true;
        for (id, v) in &self.vectors {
            if !first {
                s.push(',');
            }
            first = false;
            s.push_str(&format!("\"{}\":[", id));
            for (i, x) in v.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                s.push_str(&format!("{}", x));
            }
            s.push(']');
        }
        s.push_str("}}");
        fs::write(path, s).map_err(|e| e.to_string())
    }

    /// Load from disk. Tolerant minimal parser matching `save`'s format.
    pub fn load(path: &str) -> Result<Self, String> {
        let raw = fs::read_to_string(path).map_err(|e| e.to_string())?;
        let dim_idx = raw.find("\"dim\":").ok_or("missing dim")? + 6;
        let dim_end = raw[dim_idx..]
            .find(|c: char| c == ',' || c == '}')
            .ok_or("malformed dim")?;
        let dim: usize = raw[dim_idx..dim_idx + dim_end]
            .trim()
            .parse()
            .map_err(|e: std::num::ParseIntError| e.to_string())?;

        let mut store = VectorStore::new(dim);
        let vec_start = raw.find("\"vectors\":{").ok_or("missing vectors")? + 11;
        let body = &raw[vec_start..raw.rfind("}}").unwrap_or(raw.len())];

        // Split entries by `],"` boundaries — naive but matches save() output.
        let mut rest = body;
        while let Some(q1) = rest.find('"') {
            rest = &rest[q1 + 1..];
            let q2 = rest.find('"').ok_or("malformed id")?;
            let id: i64 = rest[..q2].parse().map_err(|e: std::num::ParseIntError| e.to_string())?;
            rest = &rest[q2 + 1..];
            let lb = rest.find('[').ok_or("missing [")?;
            let rb = rest.find(']').ok_or("missing ]")?;
            let nums = &rest[lb + 1..rb];
            let v: Result<Vec<f32>, _> = nums
                .split(',')
                .filter(|s| !s.is_empty())
                .map(|s| s.trim().parse::<f32>())
                .collect();
            let v = v.map_err(|e| e.to_string())?;
            store.add(id, v);
            rest = &rest[rb + 1..];
        }
        Ok(store)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::ml::embeddings::EmbeddingEngine;

    fn engine() -> EmbeddingEngine {
        EmbeddingEngine::mock(64)
    }

    #[test]
    fn add_remove_len() {
        let mut s = VectorStore::new(64);
        let e = engine();
        s.add(1, e.embed("apple").unwrap());
        s.add(2, e.embed("banana").unwrap());
        assert_eq!(s.len(), 2);
        s.remove(1);
        assert_eq!(s.len(), 1);
        assert!(!s.is_empty());
    }

    #[test]
    fn search_top_k_orders_by_score() {
        let mut s = VectorStore::new(64);
        let e = engine();
        s.add(1, e.embed("organic whole milk gallon").unwrap());
        s.add(2, e.embed("organic skim milk gallon").unwrap());
        s.add(3, e.embed("ferrari sports car").unwrap());

        let q = e.embed("organic whole milk").unwrap();
        let results = s.search(&q, 3);
        assert_eq!(results.len(), 3);
        // First result should be id 1 (closest match).
        assert_eq!(results[0].id, 1);
        // Ferrari should be last.
        assert_eq!(results[2].id, 3);
        // Scores must be monotonically non-increasing.
        assert!(results[0].score >= results[1].score);
        assert!(results[1].score >= results[2].score);
    }

    #[test]
    fn filtered_search_excludes_ids() {
        let mut s = VectorStore::new(64);
        let e = engine();
        s.add(1, e.embed("alpha").unwrap());
        s.add(2, e.embed("beta").unwrap());
        s.add(3, e.embed("gamma").unwrap());

        let q = e.embed("alpha").unwrap();
        let results = s.search_filtered(&q, 10, |id| id != 1);
        assert!(results.iter().all(|r| r.id != 1));
        assert_eq!(results.len(), 2);
    }

    #[test]
    fn save_and_load_roundtrip() {
        let mut s = VectorStore::new(64);
        let e = engine();
        s.add(10, e.embed("hello").unwrap());
        s.add(20, e.embed("world").unwrap());

        let path = std::env::temp_dir().join("tallow_vec_store_test.json");
        let path_str = path.to_str().unwrap();
        s.save(path_str).unwrap();

        let loaded = VectorStore::load(path_str).unwrap();
        assert_eq!(loaded.dim(), 64);
        assert_eq!(loaded.len(), 2);

        let q = e.embed("hello").unwrap();
        let r = loaded.search(&q, 1);
        assert_eq!(r[0].id, 10);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn dim_mismatch_query_returns_empty() {
        let mut s = VectorStore::new(64);
        let e = engine();
        s.add(1, e.embed("x").unwrap());
        let bad_query = vec![0.0f32; 32];
        assert!(s.search(&bad_query, 5).is_empty());
    }
}
