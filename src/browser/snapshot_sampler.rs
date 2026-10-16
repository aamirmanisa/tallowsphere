//! HTML Snapshot Sampling (T3.19)
//!
//! Deterministic hash-based sampling of scraped HTML for debugging and
//! regression analysis. Always samples failures and edge cases. Stores
//! gzip-compressed snapshots with metadata.

use flate2::write::GzEncoder;
use flate2::read::GzDecoder;
use flate2::Compression;
use sha2::{Digest, Sha256};
use std::collections::hash_map::DefaultHasher;
use std::fs;
use std::hash::{Hash, Hasher};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

#[derive(Debug, Clone, Default)]
pub struct SamplerStats {
    pub total_observed: u64,
    pub total_sampled: u64,
    pub storage_bytes: u64,
    pub oldest_snapshot: Option<i64>,
}

#[derive(Debug, Clone)]
pub struct SnapshotMetadata {
    pub id: String,
    pub url: String,
    pub retailer: String,
    pub scraped_at: i64,
    pub content_hash: String,
    pub size_bytes: usize,
    pub has_json_ld: bool,
    pub extraction_method: String,
    pub success: bool,
}

impl SnapshotMetadata {
    fn to_json(&self) -> String {
        format!(
            "{{\"id\":\"{}\",\"url\":{},\"retailer\":\"{}\",\"scraped_at\":{},\"content_hash\":\"{}\",\"size_bytes\":{},\"has_json_ld\":{},\"extraction_method\":\"{}\",\"success\":{}}}",
            self.id,
            json_str(&self.url),
            self.retailer,
            self.scraped_at,
            self.content_hash,
            self.size_bytes,
            self.has_json_ld,
            self.extraction_method,
            self.success
        )
    }

    fn from_json(s: &str) -> Result<Self, String> {
        // minimal JSON parser for our fields
        let get = |key: &str| -> Option<String> {
            let pat = format!("\"{}\":", key);
            let i = s.find(&pat)?;
            let rest = &s[i + pat.len()..];
            let rest = rest.trim_start();
            if rest.starts_with('"') {
                let end = rest[1..].find('"')?;
                Some(rest[1..1 + end].to_string())
            } else {
                let end = rest.find(|c: char| c == ',' || c == '}')?;
                Some(rest[..end].trim().to_string())
            }
        };
        Ok(SnapshotMetadata {
            id: get("id").ok_or("id")?,
            url: get("url").ok_or("url")?,
            retailer: get("retailer").ok_or("retailer")?,
            scraped_at: get("scraped_at").ok_or("scraped_at")?.parse().map_err(|e: std::num::ParseIntError| e.to_string())?,
            content_hash: get("content_hash").ok_or("content_hash")?,
            size_bytes: get("size_bytes").ok_or("size_bytes")?.parse().map_err(|e: std::num::ParseIntError| e.to_string())?,
            has_json_ld: get("has_json_ld").ok_or("has_json_ld")?.parse().map_err(|e: std::str::ParseBoolError| e.to_string())?,
            extraction_method: get("extraction_method").ok_or("extraction_method")?,
            success: get("success").ok_or("success")?.parse().map_err(|e: std::str::ParseBoolError| e.to_string())?,
        })
    }
}

fn json_str(s: &str) -> String {
    let mut out = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub struct SnapshotSampler {
    sample_rate: f64,
    storage_path: String,
    retention_days: i64,
    stats: Arc<RwLock<SamplerStats>>,
}

impl SnapshotSampler {
    pub fn new(storage_path: &str, sample_rate: f64) -> Self {
        let _ = fs::create_dir_all(storage_path);
        Self {
            sample_rate: sample_rate.clamp(0.0, 1.0),
            storage_path: storage_path.to_string(),
            retention_days: 30,
            stats: Arc::new(RwLock::new(SamplerStats::default())),
        }
    }

    pub fn with_retention(mut self, days: i64) -> Self {
        self.retention_days = days;
        self
    }

    /// Deterministic hash-based sampling decision. Same URL always decided the same way.
    pub fn should_sample(&self, url: &str) -> bool {
        if let Ok(mut s) = self.stats.write() {
            s.total_observed += 1;
        }
        if self.sample_rate >= 1.0 {
            return true;
        }
        if self.sample_rate <= 0.0 {
            return false;
        }
        let mut h = DefaultHasher::new();
        url.hash(&mut h);
        let v = h.finish();
        // Normalize to [0, 1)
        let norm = (v as f64) / (u64::MAX as f64);
        norm < self.sample_rate
    }

    pub fn store(
        &self,
        url: &str,
        retailer: &str,
        html: &str,
        success: bool,
    ) -> Result<String, String> {
        let id = uuid_v4();
        let mut hasher = Sha256::new();
        hasher.update(html.as_bytes());
        let content_hash = hex_encode(&hasher.finalize());

        let has_json_ld = html.contains("application/ld+json");
        let meta = SnapshotMetadata {
            id: id.clone(),
            url: url.to_string(),
            retailer: retailer.to_string(),
            scraped_at: now_secs(),
            content_hash,
            size_bytes: html.len(),
            has_json_ld,
            extraction_method: "html".to_string(),
            success,
        };

        let dir = Path::new(&self.storage_path);
        fs::create_dir_all(dir).map_err(|e| e.to_string())?;

        let html_path = dir.join(format!("{}.html.gz", id));
        let meta_path = dir.join(format!("{}.meta.json", id));

        let file = fs::File::create(&html_path).map_err(|e| e.to_string())?;
        let mut enc = GzEncoder::new(file, Compression::default());
        enc.write_all(html.as_bytes()).map_err(|e| e.to_string())?;
        enc.finish().map_err(|e| e.to_string())?;

        fs::write(&meta_path, meta.to_json()).map_err(|e| e.to_string())?;

        let compressed_size = fs::metadata(&html_path).map(|m| m.len()).unwrap_or(0);
        if let Ok(mut s) = self.stats.write() {
            s.total_sampled += 1;
            s.storage_bytes += compressed_size;
            s.oldest_snapshot = match s.oldest_snapshot {
                None => Some(meta.scraped_at),
                Some(v) => Some(v.min(meta.scraped_at)),
            };
        }
        Ok(id)
    }

    pub fn retrieve(&self, id: &str) -> Result<(String, SnapshotMetadata), String> {
        let dir = Path::new(&self.storage_path);
        let html_path = dir.join(format!("{}.html.gz", id));
        let meta_path = dir.join(format!("{}.meta.json", id));

        let meta_str = fs::read_to_string(&meta_path).map_err(|e| e.to_string())?;
        let meta = SnapshotMetadata::from_json(&meta_str)?;

        let file = fs::File::open(&html_path).map_err(|e| e.to_string())?;
        let mut dec = GzDecoder::new(file);
        let mut html = String::new();
        dec.read_to_string(&mut html).map_err(|e| e.to_string())?;
        Ok((html, meta))
    }

    pub fn search(&self, retailer: &str, from: i64, to: i64) -> Vec<SnapshotMetadata> {
        let dir = Path::new(&self.storage_path);
        let mut results = Vec::new();
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return results,
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if !path.file_name().and_then(|n| n.to_str()).map(|n| n.ends_with(".meta.json")).unwrap_or(false) {
                continue;
            }
            if let Ok(s) = fs::read_to_string(&path) {
                if let Ok(m) = SnapshotMetadata::from_json(&s) {
                    if m.retailer == retailer && m.scraped_at >= from && m.scraped_at <= to {
                        results.push(m);
                    }
                }
            }
        }
        results
    }

    pub fn cleanup(&self) -> Result<u64, String> {
        let dir = Path::new(&self.storage_path);
        let cutoff = now_secs() - self.retention_days * 86400;
        let mut freed: u64 = 0;
        let mut oldest: Option<i64> = None;

        let entries = fs::read_dir(dir).map_err(|e| e.to_string())?;
        let mut to_remove: Vec<(PathBuf, PathBuf, u64)> = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            if !path.file_name().and_then(|n| n.to_str()).map(|n| n.ends_with(".meta.json")).unwrap_or(false) {
                continue;
            }
            if let Ok(s) = fs::read_to_string(&path) {
                if let Ok(m) = SnapshotMetadata::from_json(&s) {
                    if m.scraped_at < cutoff {
                        let html_path = dir.join(format!("{}.html.gz", m.id));
                        let sz = fs::metadata(&html_path).map(|m| m.len()).unwrap_or(0);
                        to_remove.push((path.clone(), html_path, sz));
                    } else {
                        oldest = Some(match oldest {
                            None => m.scraped_at,
                            Some(v) => v.min(m.scraped_at),
                        });
                    }
                }
            }
        }
        for (meta_p, html_p, sz) in to_remove {
            let _ = fs::remove_file(&meta_p);
            let _ = fs::remove_file(&html_p);
            freed += sz;
        }
        if let Ok(mut s) = self.stats.write() {
            s.storage_bytes = s.storage_bytes.saturating_sub(freed);
            s.oldest_snapshot = oldest;
        }
        Ok(freed)
    }

    pub fn stats(&self) -> SamplerStats {
        self.stats.read().map(|s| s.clone()).unwrap_or_default()
    }
}

pub fn should_force_sample(success: bool, status_code: u16, html_size: usize) -> bool {
    if !success {
        return true;
    }
    if status_code >= 400 {
        return true;
    }
    if html_size < 5000 {
        return true;
    }
    false
}

fn now_secs() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn hex_encode(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn uuid_v4() -> String {
    uuid::Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env::temp_dir;

    fn tmpdir(name: &str) -> String {
        let p = temp_dir().join(format!("tallow_snap_{}_{}", name, uuid_v4()));
        p.to_string_lossy().to_string()
    }

    #[test]
    fn force_sample_rules() {
        assert!(should_force_sample(false, 200, 100_000));
        assert!(should_force_sample(true, 429, 100_000));
        assert!(should_force_sample(true, 200, 1_000));
        assert!(!should_force_sample(true, 200, 100_000));
    }

    #[test]
    fn sample_rate_bounds() {
        let s = SnapshotSampler::new(&tmpdir("rate1"), 1.0);
        assert!(s.should_sample("https://example.com/a"));
        let s0 = SnapshotSampler::new(&tmpdir("rate0"), 0.0);
        assert!(!s0.should_sample("https://example.com/a"));
    }

    #[test]
    fn deterministic_sampling() {
        let s = SnapshotSampler::new(&tmpdir("det"), 0.5);
        let a = s.should_sample("https://a.com/x");
        let b = s.should_sample("https://a.com/x");
        assert_eq!(a, b);
    }

    #[test]
    fn store_and_retrieve() {
        let dir = tmpdir("sr");
        let s = SnapshotSampler::new(&dir, 1.0);
        let html = "<html><script type=\"application/ld+json\">{}</script>hello</html>";
        let id = s.store("https://e.com/p", "acme", html, true).unwrap();
        let (h, m) = s.retrieve(&id).unwrap();
        assert_eq!(h, html);
        assert!(m.has_json_ld);
        assert_eq!(m.retailer, "acme");
    }

    #[test]
    fn search_by_retailer() {
        let dir = tmpdir("search");
        let s = SnapshotSampler::new(&dir, 1.0);
        s.store("https://a.com", "r1", "<html>a</html>", true).unwrap();
        s.store("https://b.com", "r2", "<html>b</html>", true).unwrap();
        let found = s.search("r1", 0, now_secs() + 10);
        assert_eq!(found.len(), 1);
    }
}
