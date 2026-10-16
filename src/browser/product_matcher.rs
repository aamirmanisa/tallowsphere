//! Product matching engine for HackTheCart price comparison.
//!
//! Maps scraped store listings to canonical products using a tiered strategy:
//!   1. UPC/GTIN exact match       (confidence ~0.99)
//!   2. Brand + Model + Size match (confidence 0.85-0.95)
//!   3. Title token Jaccard        (confidence 0.6-0.8)
//!   4. Image perceptual hash      (confidence 0.7-0.9)
//!   5. Human review queue fallback
//!
//! This module is self-contained: the canonical product store is an in-memory
//! index that callers seed with `register_canonical`. Production deployments
//! will back this with a database, but the matching algorithms live here.

use std::collections::{HashMap, HashSet};
use std::sync::RwLock;

/// A scraped listing from a retailer site, pre-matching.
#[derive(Debug, Clone, Default)]
pub struct ScrapedListing {
    pub title: String,
    pub upc: Option<String>,
    pub gtin: Option<String>,
    pub price_cents: i64,
    pub image_url: Option<String>,
    pub size_text: Option<String>,
    pub brand_text: Option<String>,
    pub source: String,
}

/// How a match was produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MatchMethod {
    UpcExact,
    UpcFuzzy,
    BrandModelExact,
    TitleEmbedding,
    ImageHash,
    HumanReview,
    NoMatch,
}

/// Result of matching a single listing.
#[derive(Debug, Clone)]
pub struct MatchResult {
    pub canonical_id: Option<i64>,
    pub confidence: f64,
    pub method: MatchMethod,
    /// Runner-up candidates, ranked by score desc.
    pub alternatives: Vec<(i64, f64)>,
}

impl MatchResult {
    fn no_match() -> Self {
        Self { canonical_id: None, confidence: 0.0, method: MatchMethod::NoMatch, alternatives: vec![] }
    }
    fn human(alts: Vec<(i64, f64)>) -> Self {
        Self { canonical_id: None, confidence: 0.0, method: MatchMethod::HumanReview, alternatives: alts }
    }
}

/// A known canonical product the matcher indexes against.
#[derive(Debug, Clone, Default)]
pub struct CanonicalProduct {
    pub id: i64,
    pub title: String,
    pub brand: String,
    pub model: Option<String>,
    pub gtin14: Option<String>,
    pub size_value: Option<f64>,
    pub size_unit: Option<String>,
    pub pack_count: Option<i32>,
    pub image_phash: Option<u64>,
}

/// Brand dictionary: canonical name → alias list.
const BRAND_ALIASES: &[(&str, &[&str])] = &[
    ("Coca-Cola", &["coke", "coca cola", "coca-cola", "coca-cola classic", "coke classic"]),
    ("Pepsi", &["pepsi", "pepsico", "pepsi-cola", "pepsi cola"]),
    ("Dr Pepper", &["dr pepper", "dr. pepper", "drpepper"]),
    ("Sprite", &["sprite"]),
    ("Mountain Dew", &["mountain dew", "mtn dew", "mtndew"]),
    ("Gatorade", &["gatorade"]),
    ("Red Bull", &["red bull", "redbull"]),
    ("Monster", &["monster", "monster energy"]),
    ("Kellogg's", &["kelloggs", "kellogg", "kellogg's"]),
    ("General Mills", &["general mills"]),
    ("Post", &["post"]),
    ("Quaker", &["quaker", "quaker oats"]),
    ("Nestle", &["nestle", "nestlé"]),
    ("Nestlé", &["nestle", "nestlé"]),
    ("Hershey's", &["hershey", "hersheys", "hershey's"]),
    ("Mars", &["mars"]),
    ("Cadbury", &["cadbury"]),
    ("Lindt", &["lindt"]),
    ("Ferrero", &["ferrero"]),
    ("Lay's", &["lays", "lay's"]),
    ("Doritos", &["doritos"]),
    ("Cheetos", &["cheetos"]),
    ("Pringles", &["pringles"]),
    ("Ruffles", &["ruffles"]),
    ("Tostitos", &["tostitos"]),
    ("Oreo", &["oreo", "oreos"]),
    ("Nabisco", &["nabisco"]),
    ("Keebler", &["keebler"]),
    ("Heinz", &["heinz"]),
    ("Kraft", &["kraft"]),
    ("Hellmann's", &["hellmanns", "hellmann's"]),
    ("Campbell's", &["campbells", "campbell's"]),
    ("Progresso", &["progresso"]),
    ("Chef Boyardee", &["chef boyardee"]),
    ("Dole", &["dole"]),
    ("Del Monte", &["del monte"]),
    ("Ocean Spray", &["ocean spray"]),
    ("Tropicana", &["tropicana"]),
    ("Minute Maid", &["minute maid"]),
    ("Simply", &["simply"]),
    ("Folgers", &["folgers"]),
    ("Maxwell House", &["maxwell house"]),
    ("Starbucks", &["starbucks"]),
    ("Keurig", &["keurig"]),
    ("Nespresso", &["nespresso"]),
    ("Lipton", &["lipton"]),
    ("Twinings", &["twinings"]),
    ("Bigelow", &["bigelow"]),
    ("Celestial Seasonings", &["celestial seasonings"]),
    ("Tide", &["tide"]),
    ("Gain", &["gain"]),
    ("Persil", &["persil"]),
    ("Arm & Hammer", &["arm & hammer", "arm and hammer"]),
    ("Downy", &["downy"]),
    ("Bounce", &["bounce"]),
    ("Clorox", &["clorox"]),
    ("Lysol", &["lysol"]),
    ("Mr. Clean", &["mr clean", "mr. clean"]),
    ("Windex", &["windex"]),
    ("Pine-Sol", &["pine-sol", "pine sol"]),
    ("Dawn", &["dawn"]),
    ("Palmolive", &["palmolive"]),
    ("Cascade", &["cascade"]),
    ("Finish", &["finish"]),
    ("Charmin", &["charmin"]),
    ("Bounty", &["bounty"]),
    ("Kleenex", &["kleenex"]),
    ("Scott", &["scott"]),
    ("Puffs", &["puffs"]),
    ("Pampers", &["pampers"]),
    ("Huggies", &["huggies"]),
    ("Luvs", &["luvs"]),
    ("Dove", &["dove"]),
    ("Olay", &["olay"]),
    ("Neutrogena", &["neutrogena"]),
    ("Cetaphil", &["cetaphil"]),
    ("CeraVe", &["cerave"]),
    ("Aveeno", &["aveeno"]),
    ("Nivea", &["nivea"]),
    ("L'Oréal", &["loreal", "l'oreal", "l'oréal"]),
    ("Maybelline", &["maybelline"]),
    ("Revlon", &["revlon"]),
    ("Colgate", &["colgate"]),
    ("Crest", &["crest"]),
    ("Sensodyne", &["sensodyne"]),
    ("Oral-B", &["oral-b", "oral b"]),
    ("Listerine", &["listerine"]),
    ("Gillette", &["gillette"]),
    ("Schick", &["schick"]),
    ("Bic", &["bic"]),
    ("Sony", &["sony"]),
    ("Samsung", &["samsung"]),
    ("LG", &["lg"]),
    ("Panasonic", &["panasonic"]),
    ("TCL", &["tcl"]),
    ("Hisense", &["hisense"]),
    ("Vizio", &["vizio"]),
    ("Apple", &["apple"]),
    ("Microsoft", &["microsoft"]),
    ("Google", &["google"]),
    ("Amazon", &["amazon"]),
    ("Dell", &["dell"]),
    ("HP", &["hp", "hewlett-packard", "hewlett packard"]),
    ("Lenovo", &["lenovo"]),
    ("Asus", &["asus"]),
    ("Acer", &["acer"]),
    ("Logitech", &["logitech"]),
    ("Razer", &["razer"]),
    ("Corsair", &["corsair"]),
    ("Bose", &["bose"]),
    ("JBL", &["jbl"]),
    ("Beats", &["beats", "beats by dre"]),
    ("Sennheiser", &["sennheiser"]),
    ("Nike", &["nike"]),
    ("Adidas", &["adidas"]),
    ("Puma", &["puma"]),
    ("Under Armour", &["under armour", "underarmour"]),
    ("Reebok", &["reebok"]),
    ("Brooks", &["brooks"]),
    ("New Balance", &["new balance"]),
    ("Asics", &["asics"]),
    ("Hoka", &["hoka", "hoka one one"]),
    ("Raspberry Pi", &["raspberry pi", "raspi", "rpi"]),
    ("Intel", &["intel"]),
    ("AMD", &["amd"]),
    ("Nvidia", &["nvidia"]),
];

/// Common English stopwords stripped during tokenization.
const STOPWORDS: &[&str] = &[
    "the", "a", "an", "and", "or", "of", "for", "with", "in", "on", "at", "to",
    "by", "from", "is", "are", "was", "were", "be", "been", "new", "pack",
];

pub struct ProductMatcher {
    inner: RwLock<MatcherIndex>,
}

#[derive(Default)]
struct MatcherIndex {
    products: HashMap<i64, CanonicalProduct>,
    by_gtin: HashMap<String, i64>,
    /// brand-lowercase → [product_id]
    by_brand: HashMap<String, Vec<i64>>,
}

impl Default for ProductMatcher {
    fn default() -> Self { Self::new() }
}

impl ProductMatcher {
    pub fn new() -> Self {
        Self { inner: RwLock::new(MatcherIndex::default()) }
    }

    /// Seed the index with a canonical product.
    pub fn register_canonical(&self, mut p: CanonicalProduct) {
        let mut idx = self.inner.write().unwrap();
        if let Some(ref g) = p.gtin14 {
            let norm = Self::normalize_upc(g);
            p.gtin14 = Some(norm.clone());
            idx.by_gtin.insert(norm, p.id);
        }
        idx.by_brand.entry(p.brand.to_lowercase()).or_default().push(p.id);
        idx.products.insert(p.id, p);
    }

    pub fn len(&self) -> usize { self.inner.read().unwrap().products.len() }
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    /// Primary entry point: attempt to match a scraped listing.
    pub fn match_listing(&self, listing: &ScrapedListing) -> MatchResult {
        // Tier 1: exact UPC/GTIN
        let raw_code = listing.gtin.as_deref().or(listing.upc.as_deref());
        if let Some(code) = raw_code {
            if let Some(id) = self.try_upc_match(code) {
                return MatchResult {
                    canonical_id: Some(id),
                    confidence: 0.99,
                    method: MatchMethod::UpcExact,
                    alternatives: vec![],
                };
            }
        }

        // Tier 2: brand + model + size
        if let Some((id, score)) = self.try_brand_model_match(listing) {
            return MatchResult {
                canonical_id: Some(id),
                confidence: score,
                method: MatchMethod::BrandModelExact,
                alternatives: vec![],
            };
        }

        // Tier 3: title token Jaccard similarity
        let title_matches = self.try_title_similarity(&listing.title);
        if let Some(&(id, score)) = title_matches.first() {
            if score >= 0.75 {
                let conf = 0.6 + (score - 0.75) * 0.8; // map 0.75..1.0 → 0.6..0.8
                return MatchResult {
                    canonical_id: Some(id),
                    confidence: conf.min(0.8),
                    method: MatchMethod::TitleEmbedding,
                    alternatives: title_matches.iter().skip(1).take(3).copied().collect(),
                };
            }
        }

        // Tier 4: image perceptual hash
        if let Some(url) = listing.image_url.as_deref() {
            if let Some((id, score)) = self.try_image_hash(url) {
                return MatchResult {
                    canonical_id: Some(id),
                    confidence: score,
                    method: MatchMethod::ImageHash,
                    alternatives: vec![],
                };
            }
        }

        // Tier 5: punt to humans if we have *any* near-matches
        if !title_matches.is_empty() {
            return MatchResult::human(title_matches.into_iter().take(5).collect());
        }
        MatchResult::no_match()
    }

    // --- Tier implementations ------------------------------------------------

    pub fn try_upc_match(&self, upc: &str) -> Option<i64> {
        let norm = Self::normalize_upc(upc);
        if norm.is_empty() { return None; }
        let idx = self.inner.read().unwrap();
        idx.by_gtin.get(&norm).copied()
    }

    pub fn try_brand_model_match(&self, listing: &ScrapedListing) -> Option<(i64, f64)> {
        let brand = listing
            .brand_text
            .clone()
            .or_else(|| Self::extract_brand(&listing.title))?;
        let size = listing.size_text.as_deref()
            .and_then(Self::extract_size)
            .or_else(|| Self::extract_size(&listing.title));
        let pack = Self::extract_pack_count(&listing.title);

        let idx = self.inner.read().unwrap();
        let candidates = idx.by_brand.get(&brand.to_lowercase())?;

        let title_tokens = Self::tokenize(&listing.title);
        let mut best: Option<(i64, f64)> = None;

        for cid in candidates {
            let Some(prod) = idx.products.get(cid) else { continue };
            let mut score: f64 = 0.5; // brand match base

            if let Some(model) = &prod.model {
                let mt = model.to_lowercase();
                if listing.title.to_lowercase().contains(&mt) {
                    score += 0.3;
                }
            }
            if let (Some((sv, su)), Some(ps), Some(pu)) = (size.as_ref(), prod.size_value.as_ref(), prod.size_unit.as_ref()) {
                if (sv - ps).abs() < f64::EPSILON && su.eq_ignore_ascii_case(pu) {
                    score += 0.1;
                }
            }
            if let (Some(pk), Some(pp)) = (pack, prod.pack_count) {
                if pk == pp { score += 0.05; }
            }
            // Light title overlap bonus
            let prod_tokens = Self::tokenize(&prod.title);
            let j = Self::jaccard_similarity(&title_tokens, &prod_tokens);
            score += j * 0.1;

            let score = score.min(0.95);
            if score >= 0.85 && best.map(|b| score > b.1).unwrap_or(true) {
                best = Some((*cid, score));
            }
        }
        best
    }

    pub fn try_title_similarity(&self, title: &str) -> Vec<(i64, f64)> {
        let a = Self::tokenize(title);
        if a.is_empty() { return vec![]; }
        let a_grams = Self::ngrams(&a, 3);
        let idx = self.inner.read().unwrap();
        let mut scored: Vec<(i64, f64)> = idx.products.values().map(|p| {
            let b = Self::tokenize(&p.title);
            let b_grams = Self::ngrams(&b, 3);
            let score = if a_grams.is_empty() || b_grams.is_empty() {
                Self::jaccard_similarity(&a, &b)
            } else {
                Self::jaccard_similarity(&a_grams, &b_grams)
            };
            (p.id, score)
        }).collect();
        scored.sort_by(|x, y| y.1.partial_cmp(&x.1).unwrap_or(std::cmp::Ordering::Equal));
        scored.retain(|(_, s)| *s > 0.0);
        scored
    }

    pub fn try_image_hash(&self, image_url: &str) -> Option<(i64, f64)> {
        // We don't fetch here; we expect the caller to precompute hashes via
        // `perceptual_hash`. As a deterministic fallback we hash the URL bytes
        // so the algorithm still runs end-to-end in tests.
        let hash = Self::perceptual_hash(image_url.as_bytes());
        let idx = self.inner.read().unwrap();
        let mut best: Option<(i64, u32)> = None;
        for p in idx.products.values() {
            if let Some(ph) = p.image_phash {
                let d = Self::hamming_distance(hash, ph);
                if d < 10 && best.map(|b| d < b.1).unwrap_or(true) {
                    best = Some((p.id, d));
                }
            }
        }
        best.map(|(id, d)| {
            // d in 0..10  →  confidence 0.9..0.7
            let conf = 0.9 - (d as f64 / 10.0) * 0.2;
            (id, conf)
        })
    }

    // --- Static helpers ------------------------------------------------------

    /// Normalize a UPC/EAN/GTIN to a 14-digit zero-padded GTIN-14 string.
    pub fn normalize_upc(upc: &str) -> String {
        let digits: String = upc.chars().filter(|c| c.is_ascii_digit()).collect();
        if digits.is_empty() { return String::new(); }
        if digits.len() > 14 { return digits[digits.len() - 14..].to_string(); }
        format!("{:0>14}", digits)
    }

    /// Extract a canonical brand name from a messy title.
    pub fn extract_brand(title: &str) -> Option<String> {
        let lower = title.to_lowercase();
        let mut best: Option<(&str, usize)> = None;
        for (canonical, aliases) in BRAND_ALIASES {
            for alias in *aliases {
                if let Some(pos) = lower.find(alias) {
                    // Require word boundary on left
                    let left_ok = pos == 0 || !lower.as_bytes()[pos - 1].is_ascii_alphanumeric();
                    let right = pos + alias.len();
                    let right_ok = right == lower.len() || !lower.as_bytes()[right].is_ascii_alphanumeric();
                    if left_ok && right_ok {
                        // Prefer longer alias matches and earlier positions.
                        let len = alias.len();
                        if best.map(|b| len > b.1).unwrap_or(true) {
                            best = Some((canonical, len));
                        }
                    }
                }
            }
        }
        best.map(|(c, _)| c.to_string())
    }

    /// Extract a (value, unit) size from a title. Units are normalized lowercase.
    pub fn extract_size(text: &str) -> Option<(f64, String)> {
        // Match "12 oz", "1.5 L", "500ml", "2 lb", "16 fl oz"
        let bytes = text.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                let start = i;
                while i < bytes.len() && (bytes[i].is_ascii_digit() || bytes[i] == b'.') { i += 1; }
                let num_str = &text[start..i];
                // skip spaces
                let mut j = i;
                while j < bytes.len() && bytes[j] == b' ' { j += 1; }
                // read unit letters
                let u_start = j;
                while j < bytes.len() && (bytes[j].is_ascii_alphabetic() || bytes[j] == b' ') && j - u_start < 10 {
                    j += 1;
                }
                let unit_raw = text[u_start..j].trim().to_lowercase();
                // Allow "fl oz" two-word unit
                let unit = if unit_raw.starts_with("fl oz") { "fl oz".to_string() }
                    else if unit_raw.starts_with("fl ") { let rest = &unit_raw[3..]; format!("fl {}", rest.split_whitespace().next().unwrap_or("")) }
                    else { unit_raw.split_whitespace().next().unwrap_or("").to_string() };
                const VALID: &[&str] = &["oz","fl oz","lb","lbs","kg","g","mg","ml","l","ct","pk","pack","count"];
                if VALID.contains(&unit.as_str()) {
                    if let Ok(v) = num_str.parse::<f64>() {
                        let norm_unit = match unit.as_str() {
                            "lbs" => "lb",
                            "count" => "ct",
                            "pack" => "pk",
                            other => other,
                        };
                        return Some((v, norm_unit.to_string()));
                    }
                }
                i = j.max(i + 1);
            } else {
                i += 1;
            }
        }
        None
    }

    /// Extract a pack count like "12 pack", "24ct", "6 pk".
    pub fn extract_pack_count(title: &str) -> Option<i32> {
        let lower = title.to_lowercase();
        let bytes = lower.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                let start = i;
                while i < bytes.len() && bytes[i].is_ascii_digit() { i += 1; }
                let num: i32 = lower[start..i].parse().ok()?;
                let mut j = i;
                while j < bytes.len() && bytes[j] == b' ' { j += 1; }
                let rest = &lower[j..];
                for tag in &["pack", "pk", "ct", "count"] {
                    if rest.starts_with(tag) {
                        let after = j + tag.len();
                        if after == lower.len() || !bytes[after].is_ascii_alphanumeric() {
                            return Some(num);
                        }
                    }
                }
            } else {
                i += 1;
            }
        }
        None
    }

    /// Lowercased, stopword-stripped, punctuation-free tokens with light stemming.
    pub fn tokenize(text: &str) -> Vec<String> {
        let lower = text.to_lowercase();
        let mut out = Vec::new();
        for raw in lower.split(|c: char| !c.is_ascii_alphanumeric()) {
            if raw.is_empty() { continue; }
            if STOPWORDS.contains(&raw) { continue; }
            out.push(Self::stem(raw));
        }
        out
    }

    fn stem(tok: &str) -> String {
        // Minimal suffix stripping — enough for commerce titles.
        for suf in &["ies", "es", "s"] {
            if tok.len() > suf.len() + 2 && tok.ends_with(suf) {
                return tok[..tok.len() - suf.len()].to_string();
            }
        }
        tok.to_string()
    }

    fn ngrams(tokens: &[String], n: usize) -> Vec<String> {
        if tokens.len() < n { return tokens.to_vec(); }
        (0..=tokens.len() - n).map(|i| tokens[i..i + n].join(" ")).collect()
    }

    /// Jaccard = |A ∩ B| / |A ∪ B| over unique items.
    pub fn jaccard_similarity(a: &[String], b: &[String]) -> f64 {
        if a.is_empty() && b.is_empty() { return 0.0; }
        let set_a: HashSet<&String> = a.iter().collect();
        let set_b: HashSet<&String> = b.iter().collect();
        let inter = set_a.intersection(&set_b).count() as f64;
        let union = set_a.union(&set_b).count() as f64;
        if union == 0.0 { 0.0 } else { inter / union }
    }

    /// Cheap 64-bit perceptual hash over raw bytes: average-bucket DCT-ish fold.
    /// Good enough for deterministic dedupe in tests; production should use
    /// a proper pHash/blockhash over decoded pixel data.
    pub fn perceptual_hash(image_bytes: &[u8]) -> u64 {
        if image_bytes.is_empty() { return 0; }
        let mut buckets = [0u64; 64];
        let mut counts = [0u64; 64];
        for (i, b) in image_bytes.iter().enumerate() {
            let slot = i % 64;
            buckets[slot] += *b as u64;
            counts[slot] += 1;
        }
        let mut means = [0u64; 64];
        let mut total = 0u64;
        for i in 0..64 {
            means[i] = if counts[i] > 0 { buckets[i] / counts[i] } else { 0 };
            total += means[i];
        }
        let avg = total / 64;
        let mut hash: u64 = 0;
        for (i, m) in means.iter().enumerate() {
            if *m >= avg { hash |= 1u64 << i; }
        }
        hash
    }

    pub fn hamming_distance(a: u64, b: u64) -> u32 {
        (a ^ b).count_ones()
    }
}

// -----------------------------------------------------------------------------
// Tests
// -----------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upc_normalize_12_to_14() {
        assert_eq!(ProductMatcher::normalize_upc("049000028911"), "00049000028911");
        assert_eq!(ProductMatcher::normalize_upc("0-49000-02891-1"), "00049000028911");
        assert_eq!(ProductMatcher::normalize_upc("  49000028911 "), "00049000028911");
    }

    #[test]
    fn upc_normalize_14_passthrough() {
        assert_eq!(ProductMatcher::normalize_upc("10049000028918"), "10049000028918");
    }

    #[test]
    fn upc_normalize_empty() {
        assert_eq!(ProductMatcher::normalize_upc("abc"), "");
    }

    #[test]
    fn brand_extract_basic() {
        assert_eq!(
            ProductMatcher::extract_brand("Coca-Cola Classic 12 oz Cans (24 Pack)").as_deref(),
            Some("Coca-Cola")
        );
        assert_eq!(
            ProductMatcher::extract_brand("Raspberry Pi 5 8GB Model B").as_deref(),
            Some("Raspberry Pi")
        );
        assert_eq!(
            ProductMatcher::extract_brand("KELLOGG'S Corn Flakes Cereal 18oz").as_deref(),
            Some("Kellogg's")
        );
        assert_eq!(
            ProductMatcher::extract_brand("Random off-brand noodles").as_deref(),
            None
        );
    }

    #[test]
    fn size_regex_variants() {
        assert_eq!(ProductMatcher::extract_size("Coke 12 oz cans"), Some((12.0, "oz".to_string())));
        assert_eq!(ProductMatcher::extract_size("Water 1.5 L bottle"), Some((1.5, "l".to_string())));
        assert_eq!(ProductMatcher::extract_size("Chips 2 lb bag"), Some((2.0, "lb".to_string())));
        assert_eq!(ProductMatcher::extract_size("Ice Cream 500 ml"), Some((500.0, "ml".to_string())));
        assert_eq!(ProductMatcher::extract_size("no size here"), None);
    }

    #[test]
    fn pack_count_extraction() {
        assert_eq!(ProductMatcher::extract_pack_count("Coke 12oz 24 pack"), Some(24));
        assert_eq!(ProductMatcher::extract_pack_count("Tissues 12ct"), Some(12));
        assert_eq!(ProductMatcher::extract_pack_count("Beer 6 pk"), Some(6));
        assert_eq!(ProductMatcher::extract_pack_count("Just some product"), None);
    }

    #[test]
    fn jaccard_basics() {
        let a: Vec<String> = vec!["a".into(), "b".into(), "c".into()];
        let b: Vec<String> = vec!["b".into(), "c".into(), "d".into()];
        let j = ProductMatcher::jaccard_similarity(&a, &b);
        assert!((j - 0.5).abs() < 1e-9);

        let empty: Vec<String> = vec![];
        assert_eq!(ProductMatcher::jaccard_similarity(&empty, &empty), 0.0);

        let same = vec!["x".to_string(), "y".to_string()];
        assert!((ProductMatcher::jaccard_similarity(&same, &same) - 1.0).abs() < 1e-9);
    }

    #[test]
    fn hamming_distance_works() {
        assert_eq!(ProductMatcher::hamming_distance(0b0000, 0b0000), 0);
        assert_eq!(ProductMatcher::hamming_distance(0b1010, 0b0101), 4);
        assert_eq!(ProductMatcher::hamming_distance(0xFFFFFFFFFFFFFFFF, 0), 64);
    }

    #[test]
    fn tokenize_strips_stopwords_and_stems() {
        let toks = ProductMatcher::tokenize("The Coke and Chips for Kids");
        assert!(toks.contains(&"coke".to_string()));
        assert!(toks.contains(&"chip".to_string())); // "chips" → "chip"
        assert!(!toks.contains(&"the".to_string()));
        assert!(!toks.contains(&"and".to_string()));
        assert!(!toks.contains(&"for".to_string()));
    }

    #[test]
    fn upc_exact_match_end_to_end() {
        let m = ProductMatcher::new();
        m.register_canonical(CanonicalProduct {
            id: 1,
            title: "Coca-Cola 12 oz Can".into(),
            brand: "Coca-Cola".into(),
            gtin14: Some("049000028911".into()),
            ..Default::default()
        });
        let r = m.match_listing(&ScrapedListing {
            title: "Coke can".into(),
            upc: Some("0-49000-02891-1".into()),
            ..Default::default()
        });
        assert_eq!(r.method, MatchMethod::UpcExact);
        assert_eq!(r.canonical_id, Some(1));
        assert!(r.confidence > 0.98);
    }

    #[test]
    fn brand_model_size_match() {
        let m = ProductMatcher::new();
        m.register_canonical(CanonicalProduct {
            id: 42,
            title: "Raspberry Pi 5 8GB".into(),
            brand: "Raspberry Pi".into(),
            model: Some("Pi 5".into()),
            size_value: Some(8.0),
            size_unit: Some("g".into()),
            ..Default::default()
        });
        let r = m.match_listing(&ScrapedListing {
            title: "Raspberry Pi 5 Model B 8 g RAM".into(),
            ..Default::default()
        });
        assert_eq!(r.canonical_id, Some(42));
        assert!(matches!(r.method, MatchMethod::BrandModelExact | MatchMethod::TitleEmbedding));
    }

    #[test]
    fn no_match_returns_nomatch() {
        let m = ProductMatcher::new();
        let r = m.match_listing(&ScrapedListing {
            title: "completely unknown xyzzy".into(),
            ..Default::default()
        });
        assert_eq!(r.method, MatchMethod::NoMatch);
        assert!(r.canonical_id.is_none());
    }

    #[test]
    fn perceptual_hash_stable_and_similar_inputs_close() {
        let a = ProductMatcher::perceptual_hash(b"hello world this is a test image blob");
        let b = ProductMatcher::perceptual_hash(b"hello world this is a test image blob");
        assert_eq!(a, b);
        let c = ProductMatcher::perceptual_hash(b"hello world this is a test image blob!");
        assert!(ProductMatcher::hamming_distance(a, c) < 32);
    }
}
