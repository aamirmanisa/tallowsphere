//! Text embeddings via Candle (mock-by-default).
//!
//! **Honesty note:** the `real-ml` cargo feature is **not shipped** in this
//! crate. There is no declared `real-ml` feature in `Cargo.toml`, and the
//! candle-based BGE-small-en-v1.5 loader is not implemented — so enabling it
//! (if the feature ever gets declared) returns a clear `Err`, never a silent
//! fallback. By default we use a deterministic **non-semantic** mock that
//! produces 384-dim vectors derived from a stable hash (FNV-1a bag-of-words)
//! of the input text. This makes tests reproducible and lets the rest of the
//! ML pipeline (vector store, matcher, reranker) be developed and tested
//! without committing ~150MB of model weights — but the mock vectors do NOT
//! capture meaning, only token overlap, so treat them as structural features,
//! not semantic embeddings.

use std::path::PathBuf;

use super::MlError;

/// Default BGE-small-en-v1.5 embedding dimension.
pub const DEFAULT_DIM: usize = 384;

/// Where to run inference.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeviceChoice {
    Cpu,
    Cuda(usize),
    Metal,
}

/// Configuration for loading a real embedding model.
#[derive(Debug, Clone)]
pub struct EmbeddingConfig {
    pub model_path: PathBuf,
    pub device: DeviceChoice,
    pub batch_size: usize,
    pub max_seq_len: usize,
}

impl Default for EmbeddingConfig {
    fn default() -> Self {
        Self {
            model_path: PathBuf::from("models/bge-small-en-v1.5"),
            device: DeviceChoice::Cpu,
            batch_size: 32,
            max_seq_len: 512,
        }
    }
}

/// An embedding engine. May be backed by a real model or a deterministic mock.
pub struct EmbeddingEngine {
    real: bool,
    dim: usize,
    #[allow(dead_code)]
    device: DeviceChoice,
}

impl EmbeddingEngine {
    /// Load BGE-small-en-v1.5 from `config.model_path`.
    ///
    /// **`real-ml` is not shipped.** There is no candle-based loader in this
    /// build, so enabling the feature cannot yield a real model — this
    /// returns an honest, documented error instead of silently falling back
    /// to the mock (a silent fallback would make callers believe they got
    /// semantic embeddings when they did not). With the default (no
    /// `real-ml`) build, this returns the deterministic FNV-1a mock engine —
    /// reproducible but **not semantic** (see [`EmbeddingEngine::mock`]).
    pub fn new(config: EmbeddingConfig) -> Result<Self, MlError> {
        #[cfg(feature = "real-ml")]
        {
            // real-ml is not shipped: the candle-based BGE-small-en-v1.5
            // loader is not implemented. Honest error — do NOT fall back to
            // the mock, because callers enabling real-ml expect semantics.
            let _ = config;
            return Err(MlError::ModelLoad(
                "real-ml is not shipped: the candle-based BGE-small-en-v1.5 loader is not implemented in this build. Use the default deterministic FNV-1a mock (EmbeddingEngine::new with default features, or EmbeddingEngine::mock) — it is NOT semantic, only reproducible.".to_string(),
            ));
        }
        #[cfg(not(feature = "real-ml"))]
        {
            let _ = config;
            Ok(Self {
                real: false,
                dim: DEFAULT_DIM,
                device: DeviceChoice::Cpu,
            })
        }
    }

    /// Mock engine for tests — deterministic **non-semantic**
    /// pseudo-embeddings of `dim` dimensions (FNV-1a bag-of-words over
    /// tokens + bigrams). Same text → same vector; similar token overlap →
    /// nearby vectors; but meaning is NOT captured.
    pub fn mock(dim: usize) -> Self {
        Self {
            real: false,
            dim,
            device: DeviceChoice::Cpu,
        }
    }

    /// Embed a single text into a normalized vector.
    pub fn embed(&self, text: &str) -> Result<Vec<f32>, MlError> {
        let mut v = mock_embedding(text, self.dim);
        Self::normalize(&mut v);
        Ok(v)
    }

    /// Batch embed for throughput.
    pub fn embed_batch(&self, texts: &[&str]) -> Result<Vec<Vec<f32>>, MlError> {
        texts.iter().map(|t| self.embed(t)).collect()
    }

    /// L2-normalize a vector in place. Zero vectors are left untouched.
    pub fn normalize(vec: &mut [f32]) {
        let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
        if norm > 0.0 {
            for x in vec.iter_mut() {
                *x /= norm;
            }
        }
    }

    /// Cosine similarity between two equally-sized vectors.
    /// If both are pre-normalized, this is just the dot product.
    pub fn cosine(a: &[f32], b: &[f32]) -> f32 {
        if a.len() != b.len() || a.is_empty() {
            return 0.0;
        }
        let mut dot = 0.0f32;
        let mut na = 0.0f32;
        let mut nb = 0.0f32;
        for i in 0..a.len() {
            dot += a[i] * b[i];
            na += a[i] * a[i];
            nb += b[i] * b[i];
        }
        let denom = na.sqrt() * nb.sqrt();
        if denom == 0.0 {
            0.0
        } else {
            dot / denom
        }
    }

    /// True if backed by a real loaded model.
    pub fn is_real(&self) -> bool {
        self.real
    }

    /// Embedding dimension.
    pub fn dim(&self) -> usize {
        self.dim
    }
}

/// Deterministic, content-aware mock embedding.
///
/// We tokenize on whitespace + punctuation and hash each token into a
/// fixed-dim bag-of-features vector. Tokens contribute weighted bumps so
/// that texts sharing tokens land near each other in cosine space.
fn mock_embedding(text: &str, dim: usize) -> Vec<f32> {
    let mut v = vec![0.0f32; dim];
    let lower = text.to_lowercase();

    // Token-level features.
    for tok in lower.split(|c: char| !c.is_alphanumeric()).filter(|s| !s.is_empty()) {
        let h = fnv1a(tok.as_bytes());
        let idx = (h as usize) % dim;
        v[idx] += 1.0;
        // Spread some signal to two more buckets to soften aliasing.
        let idx2 = ((h.wrapping_mul(2654435761)) as usize) % dim;
        v[idx2] += 0.5;
        let idx3 = ((h.wrapping_mul(40503)) as usize) % dim;
        v[idx3] += 0.25;
    }

    // Character-bigram features so even single tokens have richer signal.
    let bytes = lower.as_bytes();
    if bytes.len() >= 2 {
        for w in bytes.windows(2) {
            let h = fnv1a(w);
            let idx = (h as usize) % dim;
            v[idx] += 0.1;
        }
    }

    // Document-level salt so empty / unknown texts still differ slightly.
    let salt = fnv1a(text.as_bytes()) as usize % dim;
    v[salt] += 0.01;

    v
}

/// 64-bit FNV-1a hash. Stable across runs and platforms.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in bytes {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_is_deterministic() {
        let e = EmbeddingEngine::mock(384);
        let a = e.embed("organic whole milk 1 gallon").unwrap();
        let b = e.embed("organic whole milk 1 gallon").unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 384);
    }

    #[test]
    fn mock_normalized() {
        let e = EmbeddingEngine::mock(384);
        let v = e.embed("hello world").unwrap();
        let norm: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
        assert!((norm - 1.0).abs() < 1e-5);
    }

    #[test]
    fn similar_texts_have_higher_cosine() {
        let e = EmbeddingEngine::mock(384);
        let a = e.embed("organic whole milk gallon").unwrap();
        let b = e.embed("organic whole milk half gallon").unwrap();
        let c = e.embed("ferrari sports car red").unwrap();
        let sim_ab = EmbeddingEngine::cosine(&a, &b);
        let sim_ac = EmbeddingEngine::cosine(&a, &c);
        assert!(sim_ab > sim_ac, "{} should exceed {}", sim_ab, sim_ac);
    }

    #[test]
    fn cosine_self_is_one() {
        let e = EmbeddingEngine::mock(64);
        let v = e.embed("the quick brown fox").unwrap();
        let s = EmbeddingEngine::cosine(&v, &v);
        assert!((s - 1.0).abs() < 1e-5);
    }

    #[test]
    fn batch_matches_single() {
        let e = EmbeddingEngine::mock(128);
        let texts = ["alpha", "beta", "gamma"];
        let batch = e.embed_batch(&texts).unwrap();
        for (i, t) in texts.iter().enumerate() {
            assert_eq!(batch[i], e.embed(t).unwrap());
        }
    }

    #[test]
    fn is_real_false_by_default() {
        let e = EmbeddingEngine::mock(384);
        assert!(!e.is_real());
    }
}
