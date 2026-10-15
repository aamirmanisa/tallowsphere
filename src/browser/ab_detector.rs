//! A/B layout detection (T3.23).
//!
//! Retailers frequently run A/B tests and rotate layouts. This module extracts
//! structural fingerprints from HTML and tracks which variants we've seen per
//! target, so scrapers can detect new variants early and adapt selectors.

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};

/// Structural features used to fingerprint a page layout.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StructuralFeatures {
    pub dom_depth: u32,
    pub top_level_class_hash: String,
    pub has_grid_layout: bool,
    pub has_list_layout: bool,
    pub has_card_layout: bool,
    pub product_count: u32,
    pub uses_react: bool,
    pub uses_vue: bool,
    pub primary_price_selector: Option<String>,
}

/// A single layout variant that has been observed for a target.
#[derive(Debug, Clone)]
pub struct LayoutFingerprint {
    pub variant_id: String,
    pub features: StructuralFeatures,
    pub first_seen: i64,
    pub last_seen: i64,
    pub occurrence_count: u64,
}

/// Result of detecting which variant a page belongs to.
#[derive(Debug, Clone)]
pub struct DetectionResult {
    pub variant_id: String,
    pub is_new_variant: bool,
    pub variant_stability: f64,
    pub all_variants_seen: Vec<String>,
}

pub struct AbLayoutDetector {
    fingerprints: HashMap<String, Vec<LayoutFingerprint>>,
}

impl Default for AbLayoutDetector {
    fn default() -> Self {
        Self::new()
    }
}

fn now_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Cheap deterministic hash (FNV-1a 64-bit).
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in bytes {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100_0000_01b3);
    }
    h
}

impl AbLayoutDetector {
    pub fn new() -> Self {
        Self {
            fingerprints: HashMap::new(),
        }
    }

    /// Extract structural features from raw HTML.
    ///
    /// Uses cheap substring heuristics rather than a full parser — we're
    /// fingerprinting, not extracting.
    pub fn extract_features(html: &str) -> StructuralFeatures {
        let lower = html.to_ascii_lowercase();

        // DOM depth: approximate via max nesting of open tags
        let mut depth: u32 = 0;
        let mut max_depth: u32 = 0;
        let bytes = lower.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'<' {
                if i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    depth = depth.saturating_sub(1);
                } else if i + 1 < bytes.len()
                    && bytes[i + 1] != b'!'
                    && bytes[i + 1] != b'?'
                {
                    // Skip self-closing tags (ends with "/>")
                    // Find end of tag
                    let mut j = i + 1;
                    let mut self_closing = false;
                    while j < bytes.len() && bytes[j] != b'>' {
                        if bytes[j] == b'/' && j + 1 < bytes.len() && bytes[j + 1] == b'>' {
                            self_closing = true;
                        }
                        j += 1;
                    }
                    if !self_closing {
                        depth += 1;
                        if depth > max_depth {
                            max_depth = depth;
                        }
                    }
                    i = j;
                }
            }
            i += 1;
        }

        // Collect first 10 class names
        let mut classes: Vec<&str> = Vec::new();
        let mut search_from = 0;
        while classes.len() < 10 {
            if let Some(pos) = lower[search_from..].find("class=\"") {
                let start = search_from + pos + 7;
                if let Some(end_rel) = lower[start..].find('"') {
                    let cls = &lower[start..start + end_rel];
                    for c in cls.split_whitespace().take(10 - classes.len()) {
                        classes.push(c);
                    }
                    search_from = start + end_rel + 1;
                } else {
                    break;
                }
            } else {
                break;
            }
        }
        let joined = classes.join(",");
        let top_level_class_hash = format!("{:016x}", fnv1a(joined.as_bytes()));

        // Layout heuristics
        let has_grid_layout =
            lower.contains("display:grid") || lower.contains("grid-template") || lower.contains("class=\"grid") || lower.contains(" grid ");
        let has_list_layout =
            lower.contains("<ul") || lower.contains("<ol") || lower.contains("class=\"list");
        let has_card_layout =
            lower.contains("class=\"card") || lower.contains("product-card") || lower.contains("item-card");

        // Count product-ish things
        let product_count = [
            "data-product",
            "class=\"product",
            "product-tile",
            "product-card",
            "itemtype=\"http://schema.org/product",
        ]
        .iter()
        .map(|needle| lower.matches(needle).count() as u32)
        .sum::<u32>();

        // Framework detection
        let uses_react = lower.contains("data-reactroot")
            || lower.contains("data-react")
            || lower.contains("__next_data__")
            || lower.contains("_reactlistening");
        let uses_vue = lower.contains("data-v-") || lower.contains("__vue__") || lower.contains("data-server-rendered");

        // Primary price selector — heuristic
        let primary_price_selector = if lower.contains("itemprop=\"price\"") {
            Some("[itemprop=\"price\"]".to_string())
        } else if lower.contains("class=\"price") {
            Some(".price".to_string())
        } else if lower.contains("data-price") {
            Some("[data-price]".to_string())
        } else {
            None
        };

        StructuralFeatures {
            dom_depth: max_depth,
            top_level_class_hash,
            has_grid_layout,
            has_list_layout,
            has_card_layout,
            product_count,
            uses_react,
            uses_vue,
            primary_price_selector,
        }
    }

    /// Compute a stable fingerprint string from features.
    pub fn fingerprint(features: &StructuralFeatures) -> String {
        // Bucket product count to absorb minor variation
        let product_bucket = match features.product_count {
            0 => 0,
            1..=5 => 1,
            6..=15 => 2,
            16..=40 => 3,
            _ => 4,
        };
        // Bucket depth
        let depth_bucket = features.dom_depth / 5;

        let payload = format!(
            "{}|{}|{}|{}|{}|{}|{}|{}|{}",
            depth_bucket,
            features.top_level_class_hash,
            features.has_grid_layout as u8,
            features.has_list_layout as u8,
            features.has_card_layout as u8,
            product_bucket,
            features.uses_react as u8,
            features.uses_vue as u8,
            features.primary_price_selector.as_deref().unwrap_or("-"),
        );
        format!("{:016x}", fnv1a(payload.as_bytes()))
    }

    /// Detect which variant a page is. Updates internal state.
    pub fn detect(&mut self, target: &str, html: &str) -> DetectionResult {
        let features = Self::extract_features(html);
        let variant_id = Self::fingerprint(&features);
        let now = now_secs();

        let entry = self.fingerprints.entry(target.to_string()).or_default();

        let mut is_new_variant = true;
        for fp in entry.iter_mut() {
            if fp.variant_id == variant_id {
                fp.last_seen = now;
                fp.occurrence_count += 1;
                is_new_variant = false;
                break;
            }
        }
        if is_new_variant {
            entry.push(LayoutFingerprint {
                variant_id: variant_id.clone(),
                features,
                first_seen: now,
                last_seen: now,
                occurrence_count: 1,
            });
        }

        let total: u64 = entry.iter().map(|f| f.occurrence_count).sum();
        let this_count = entry
            .iter()
            .find(|f| f.variant_id == variant_id)
            .map(|f| f.occurrence_count)
            .unwrap_or(1);
        let variant_stability = if total == 0 {
            0.0
        } else {
            this_count as f64 / total as f64
        };

        let mut seen: HashSet<String> = HashSet::new();
        let mut all_variants_seen = Vec::new();
        for f in entry.iter() {
            if seen.insert(f.variant_id.clone()) {
                all_variants_seen.push(f.variant_id.clone());
            }
        }

        DetectionResult {
            variant_id,
            is_new_variant,
            variant_stability,
            all_variants_seen,
        }
    }

    /// Return all fingerprints seen for a target.
    pub fn variants_for(&self, target: &str) -> Option<&Vec<LayoutFingerprint>> {
        self.fingerprints.get(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_detects_react_and_grid() {
        let html = r#"<html><body data-reactroot><div class="grid product-card"><span itemprop="price">$9</span></div></body></html>"#;
        let f = AbLayoutDetector::extract_features(html);
        assert!(f.uses_react);
        assert!(f.has_card_layout);
        assert_eq!(f.primary_price_selector.as_deref(), Some("[itemprop=\"price\"]"));
    }

    #[test]
    fn fingerprint_is_stable_for_same_html() {
        let html = r#"<div class="product"><span class="price">$1</span></div>"#;
        let a = AbLayoutDetector::fingerprint(&AbLayoutDetector::extract_features(html));
        let b = AbLayoutDetector::fingerprint(&AbLayoutDetector::extract_features(html));
        assert_eq!(a, b);
    }

    #[test]
    fn detect_tracks_new_and_repeat_variants() {
        let mut d = AbLayoutDetector::new();
        let html_a = r#"<div class="grid"><div class="product-card"><span class="price">$1</span></div></div>"#;
        let html_b = r#"<ul class="list"><li data-product><span data-price="2">$2</span></li></ul>"#;

        let r1 = d.detect("walmart.com", html_a);
        assert!(r1.is_new_variant);
        assert_eq!(r1.all_variants_seen.len(), 1);

        let r2 = d.detect("walmart.com", html_a);
        assert!(!r2.is_new_variant);
        assert!((r2.variant_stability - 1.0).abs() < 1e-9);

        let r3 = d.detect("walmart.com", html_b);
        assert!(r3.is_new_variant);
        assert_eq!(r3.all_variants_seen.len(), 2);
        // variant_stability for B should be 1/3
        assert!((r3.variant_stability - (1.0 / 3.0)).abs() < 1e-9);
    }

    #[test]
    fn different_layouts_produce_different_fingerprints() {
        let a = AbLayoutDetector::fingerprint(&AbLayoutDetector::extract_features(
            r#"<div class="grid"><div class="product-card"></div></div>"#,
        ));
        let b = AbLayoutDetector::fingerprint(&AbLayoutDetector::extract_features(
            r#"<ul class="list"><li data-product></li></ul>"#,
        ));
        assert_ne!(a, b);
    }
}
