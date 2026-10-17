//! Smart extraction — tries structured-data strategies in order of trust.
//!
//! JSON-LD is the **primary** path: it's the public structured data contract
//! that major retailers publish and rarely change. CSS heuristics are the
//! last resort, since class names churn constantly.
//!
//! Tier order (highest trust first):
//! 1. JSON-LD (schema.org Product)         confidence 0.95
//! 2. Microdata (itemprop attributes)      confidence 0.85
//! 3. OpenGraph meta tags                  confidence 0.75
//! 4. CSS heuristics (class-based)         confidence 0.55
//!
//! Each tier builds on existing extractors in `structured_data` and
//! `ai_extract` — no duplication.

use crate::browser::ai_extract::SchemaExtractor;
use crate::browser::llm_extract::LlmExtractor;
use crate::browser::page::Page;
use crate::browser::structured_data::StructuredDataExtractor;
use serde_json::Value;
use std::collections::HashMap;

/// Unified product data with provenance.
#[derive(Debug, Clone)]
pub struct ExtractedProduct {
    pub name: Option<String>,
    pub brand: Option<String>,
    pub price_cents: Option<i64>,
    pub currency: Option<String>,
    pub sale_price_cents: Option<i64>,
    pub availability: Option<String>,
    pub sku: Option<String>,
    pub gtin: Option<String>,
    pub mpn: Option<String>,
    pub image_url: Option<String>,
    pub description: Option<String>,
    pub rating: Option<f64>,
    pub review_count: Option<i64>,
    pub category: Option<String>,

    pub extraction_method: ExtractionMethod,
    pub confidence: f64,
}

impl ExtractedProduct {
    fn empty(method: ExtractionMethod, confidence: f64) -> Self {
        Self {
            name: None,
            brand: None,
            price_cents: None,
            currency: None,
            sale_price_cents: None,
            availability: None,
            sku: None,
            gtin: None,
            mpn: None,
            image_url: None,
            description: None,
            rating: None,
            review_count: None,
            category: None,
            extraction_method: method,
            confidence,
        }
    }

    /// Sentinel: all strategies failed.
    pub fn failed() -> Self {
        Self::empty(ExtractionMethod::Failed, 0.0)
    }

    /// True if any meaningful field was populated.
    fn has_data(&self) -> bool {
        self.name.is_some() || self.price_cents.is_some()
    }
}

/// Provenance of an extraction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractionMethod {
    /// Schema.org JSON-LD — highest trust, public contract.
    JsonLd,
    /// HTML microdata via `itemprop` attributes.
    Microdata,
    /// OpenGraph / product meta tags.
    OpenGraph,
    /// CSS class heuristics (`.price`, `[data-price]`).
    CssHeuristics,
    /// AI/vision model fallback.
    AiVision,
    /// LLM (Ollama) schema-based fallback. Default-ON; disable per instance
    /// with `enable_llm_fallback(false)`, or globally with `TALLOW_LLM_EXTRACT=0`.
    LlmFallback,
    /// All strategies failed.
    Failed,
}

/// Smart extractor — tries strategies from highest to lowest trust.
///
/// Carries the LLM fallback configuration. The tier is **on only when an engine
/// is configured** (`TALLOW_LLM_BASE_URL`; see [`SmartExtractor::default`] and
/// `resolve_engine_config`) — `TALLOW_LLM_EXTRACT=1` forces it on regardless, so
/// an operator can watch it fail rather than have the failure hidden. When
/// `enable_llm_fallback` is `false`, behavior is identical to the legacy
/// stateless extractor: the JSON-LD → Microdata → OpenGraph → CSS cascade, then
/// `ExtractedProduct::failed()`. When enabled, a failed cascade falls through to
/// a schema extractor (`LlmExtractor`, any supported engine) with validation and
/// heal-retry, after a measured tier check: the tier's state is recorded and a
/// tier that is not enabled returns without sending anything, recording why. The
/// first successful page caches a schema per domain+page-type, after which
/// extraction is CSS-speed with zero model calls.
#[derive(Debug, Clone)]
pub struct SmartExtractor {
    /// Enable the LLM (Ollama) extraction as the final fallback tier.
    pub enable_llm_fallback: bool,
    /// Ollama API base URL (used only when `enable_llm_fallback` is set).
    pub ollama_url: String,
    /// Engine model name.
    pub model: String,
    /// On-disk schema cache directory for `LlmExtractor`.
    pub cache_dir: String,
    /// Whether the tier may send page content to a third-party vendor. Fail-closed:
    /// `TransferPolicy::none()` refuses a remote engine.
    pub llm_transfer: crate::browser::llm_transfer::TransferPolicy,
    /// Why the tier is in its current state — `"configured"`, or the exact
    /// refusal that kept it off. Carried on the struct so a caller can report it
    /// without re-deriving it from the environment.
    pub llm_reason: String,
}

impl Default for SmartExtractor {
    fn default() -> Self {
        // The tier is ON only when an engine is CONFIGURED. It used to be on by
        // default while pointing at a local service; a tier that is on with
        // nothing answering reports "not attempted" as "attempted, failed",
        // which is the defect this phase exists to remove.
        // `TALLOW_LLM_EXTRACT=1` still forces it on, so an operator can choose to
        // watch the failure rather than have it hidden.
        let forced = std::env::var("TALLOW_LLM_EXTRACT")
            .map(|v| v != "0" && !v.eq_ignore_ascii_case("false"))
            .ok();
        let (llm_on, reason, url, model) =
            match crate::browser::llm_extract::resolve_engine_config(&|k| std::env::var(k).ok()) {
                Ok(cfg) => (
                    forced.unwrap_or(true),
                    "configured".to_string(),
                    cfg.base_url,
                    cfg.model,
                ),
                Err(reason) => (
                    forced.unwrap_or(false),
                    reason,
                    "http://localhost:11434".to_string(),
                    "llama3.2".to_string(),
                ),
            };
        Self {
            enable_llm_fallback: llm_on,
            ollama_url: url,
            model,
            cache_dir: ".tallow-schemas".to_string(),
            llm_transfer: crate::browser::llm_transfer::TransferPolicy::from_env(&|k| {
                std::env::var(k).ok()
            }),
            llm_reason: reason,
        }
    }
}

impl SmartExtractor {
    /// Construct a smart extractor via [`SmartExtractor::default`] — the LLM
    /// fallback is **on** unless `TALLOW_LLM_EXTRACT=0`. Use
    /// [`SmartExtractor::with_llm_fallback`] to choose explicitly.
    pub fn new() -> Self {
        Self::default()
    }

    /// Construct a smart extractor, optionally enabling the LLM final fallback.
    pub fn with_llm_fallback(enable: bool) -> Self {
        let mut s = Self::default();
        s.enable_llm_fallback = enable;
        s
    }

    /// Builder-style: enable (or disable) the LLM fallback.
    pub fn enable_llm_fallback(mut self, on: bool) -> Self {
        self.enable_llm_fallback = on;
        self
    }

    /// Set Ollama connection details for the LLM fallback.
    pub fn llm_config(mut self, ollama_url: &str, model: &str, cache_dir: &str) -> Self {
        self.ollama_url = ollama_url.to_string();
        self.model = model.to_string();
        self.cache_dir = cache_dir.to_string();
        self
    }

    /// Primary entry point. Tries JSON-LD → Microdata → OpenGraph → CSS, then
    /// (if enabled) the LLM fallback as the final tier.
    ///
    /// The `page` is used to resolve the current URL so the LLM extractor can
    /// derive the domain for its schema cache.
    pub async fn extract_product(&mut self, page: &Page, html: &str) -> ExtractedProduct {
        if let Some(p) = Self::try_jsonld(html) {
            return p;
        }
        if let Some(p) = Self::try_microdata(html) {
            return p;
        }
        if let Some(p) = Self::try_opengraph(html) {
            return p;
        }
        if let Some(p) = Self::try_css(html) {
            return p;
        }
        // Final fallback tier: LLM (opt-in).
        if self.enable_llm_fallback {
            let url = page.url().await.unwrap_or_default();
            if let Some(p) = self.try_llm_fallback(html, &url).await {
                return p;
            }
        }
        ExtractedProduct::failed()
    }

    /// Synchronous variant for callers without a live Page. Always uses the
    /// default (LLM fallback disabled) configuration.
    pub fn extract_from_html(html: &str) -> ExtractedProduct {
        let s = SmartExtractor::default();
        s.extract_from_html_sync(html)
    }

    /// Synchronous extraction honoring this extractor's configuration. Because
    /// the LLM fallback is async, this is a convenience that only runs the
    /// synchronous cascade; for the LLM tier use [`SmartExtractor::extract_product`].
    pub fn extract_from_html_sync(&self, html: &str) -> ExtractedProduct {
        if let Some(p) = Self::try_jsonld(html) {
            return p;
        }
        if let Some(p) = Self::try_microdata(html) {
            return p;
        }
        if let Some(p) = Self::try_opengraph(html) {
            return p;
        }
        if let Some(p) = Self::try_css(html) {
            return p;
        }
        ExtractedProduct::failed()
    }

    /// Final fallback: LLM (Ollama) schema extraction with validation and
    /// heal-retry. Returns `Some` only if a validated product (name or price)
    /// was produced; never panics.
    async fn try_llm_fallback(&mut self, html: &str, url: &str) -> Option<ExtractedProduct> {
        let domain = domain_of(url);
        // An explicitly configured engine wins, so TALLOW_LLM_ENGINE is honoured
        // here; `llm_config()`'s fields are the fallback for a caller that set
        // the URL and model directly.
        let mut llm = match crate::browser::llm_extract::resolve_engine_config(&|k| {
            std::env::var(k).ok()
        }) {
            Ok(cfg) => {
                LlmExtractor::with_engine(cfg.engine, &cfg.base_url, &cfg.model, &self.cache_dir)
            }
            Err(_) => LlmExtractor::with_config(&self.ollama_url, &self.model, &self.cache_dir),
        }
        .with_transfer(self.llm_transfer.clone());

        // Measure, record, then decide — nothing is sent before both hold. This
        // is the difference P1.T4 is about: "tier enabled" and "tier working"
        // must not be the same claim, and a run that sends nothing must say so.
        let state = llm.tier_state().await;
        crate::run_evidence::record("llm_tier", state.to_evidence());
        if !state.enabled {
            crate::run_evidence::record_limitations(&[format!(
                "llm tier not used for {domain}: {}",
                state.reason
            )]);
            return None;
        }

        // Phase 1: use a cached schema at CSS speed (zero LLM cost). If the
        // result validates, return it. Otherwise heal the schema and retry.
        if let Ok(items) = llm.extract(html, &domain) {
            if let Some(schema) = llm.find_schema(&domain) {
                if let Some(item) = items.first() {
                    let validation = llm.validate(item, &schema);
                    if validation.valid {
                        if let Some(p) = product_from_item(item, 0.90) {
                            return Some(p);
                        }
                    }
                    // Heal + retry: regenerate the schema and re-extract.
                    if let Ok(healed) = llm.heal_schema(html, &domain).await {
                        if let Ok(healed_items) = llm.extract(html, &domain) {
                            if let Some(item) = healed_items.first() {
                                let v = llm.validate(item, &healed);
                                if v.valid {
                                    if let Some(p) = product_from_item(item, 0.85) {
                                        return Some(p);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Phase 2: no usable cached schema — generate one via LLM, then extract.
        if let Ok(schema) = llm.generate_schema(html, &domain, "product_detail").await {
            if let Ok(items) = llm.extract(html, &domain) {
                if let Some(item) = items.first() {
                    let validation = llm.validate(item, &schema);
                    if validation.valid {
                        if let Some(p) = product_from_item(item, 0.85) {
                            return Some(p);
                        }
                    }
                }
            }
        }

        None
    }

    // ---- Tier 1: JSON-LD ------------------------------------------------

    pub fn try_jsonld(html: &str) -> Option<ExtractedProduct> {
        let blocks = StructuredDataExtractor::extract_json_ld(html);
        for block in &blocks {
            if let Some(product_obj) = find_product_in_ld(block) {
                let mut out = ExtractedProduct::empty(ExtractionMethod::JsonLd, 0.95);
                populate_from_jsonld(&mut out, product_obj);
                if out.has_data() {
                    return Some(out);
                }
            }
        }
        None
    }

    // ---- Tier 2: Microdata ---------------------------------------------

    pub fn try_microdata(html: &str) -> Option<ExtractedProduct> {
        let items = StructuredDataExtractor::extract_microdata(html);
        for item in &items {
            let is_product = item
                .item_type
                .as_deref()
                .map(|t| t.contains("Product"))
                .unwrap_or(false);
            if !is_product {
                continue;
            }

            let mut out = ExtractedProduct::empty(ExtractionMethod::Microdata, 0.85);
            for (prop, value) in &item.properties {
                match prop.as_str() {
                    "name" => out.name = Some(value.clone()),
                    "brand" => out.brand = Some(value.clone()),
                    "price" => out.price_cents = parse_price_to_cents(value),
                    "priceCurrency" => out.currency = Some(value.clone()),
                    "availability" => {
                        out.availability = Some(
                            value
                                .replace("https://schema.org/", "")
                                .replace("http://schema.org/", ""),
                        );
                    }
                    "sku" => out.sku = Some(value.clone()),
                    "gtin" | "gtin13" | "gtin12" | "gtin8" | "gtin14" => {
                        out.gtin = Some(value.clone())
                    }
                    "mpn" => out.mpn = Some(value.clone()),
                    "image" => out.image_url = Some(value.clone()),
                    "description" => out.description = Some(value.clone()),
                    "ratingValue" => out.rating = value.parse().ok(),
                    "reviewCount" => out.review_count = value.replace(',', "").parse().ok(),
                    "category" => out.category = Some(value.clone()),
                    _ => {}
                }
            }
            if out.has_data() {
                return Some(out);
            }
        }
        None
    }

    // ---- Tier 3: OpenGraph ---------------------------------------------

    pub fn try_opengraph(html: &str) -> Option<ExtractedProduct> {
        let mut out = ExtractedProduct::empty(ExtractionMethod::OpenGraph, 0.75);
        out.name = meta(html, "og:title");
        out.image_url = meta(html, "og:image");
        out.description = meta(html, "og:description");
        out.brand = meta(html, "product:brand").or_else(|| meta(html, "og:brand"));

        if let Some(p) =
            meta(html, "product:price:amount").or_else(|| meta(html, "og:price:amount"))
        {
            out.price_cents = parse_price_to_cents(&p);
        }
        out.currency =
            meta(html, "product:price:currency").or_else(|| meta(html, "og:price:currency"));

        if let Some(sale) = meta(html, "product:sale_price:amount") {
            out.sale_price_cents = parse_price_to_cents(&sale);
        }
        out.availability =
            meta(html, "product:availability").or_else(|| meta(html, "og:availability"));
        out.category = meta(html, "product:category");

        if out.has_data() { Some(out) } else { None }
    }

    // ---- Tier 4: CSS heuristics ----------------------------------------

    pub fn try_css(html: &str) -> Option<ExtractedProduct> {
        let p = SchemaExtractor::extract_product(html)?;
        let mut out = ExtractedProduct::empty(ExtractionMethod::CssHeuristics, 0.55);
        out.name = p.name;
        out.brand = p.brand;
        out.price_cents = p.price.and_then(|f| Some((f * 100.0).round() as i64));
        out.currency = p.currency;
        out.availability = p.availability;
        out.rating = p.rating;
        out.image_url = p.image_url;
        out.sku = p.sku;
        if out.has_data() { Some(out) } else { None }
    }
}

// ---------------------------------------------------------------------------
// JSON-LD helpers
// ---------------------------------------------------------------------------

fn is_product_type(t: &str) -> bool {
    matches!(t, "Product" | "IndividualProduct" | "ProductModel")
}

/// Walk a JSON-LD value looking for a Product object.
/// Handles: direct, array, @graph, nested.
fn find_product_in_ld(val: &Value) -> Option<&Value> {
    // Direct match
    if let Some(t) = val.get("@type").and_then(|v| v.as_str()) {
        if is_product_type(t) {
            return Some(val);
        }
    }
    // @type can also be an array
    if let Some(arr) = val.get("@type").and_then(|v| v.as_array()) {
        if arr.iter().filter_map(|v| v.as_str()).any(is_product_type) {
            return Some(val);
        }
    }
    // @graph
    if let Some(graph) = val.get("@graph").and_then(|v| v.as_array()) {
        for item in graph {
            if let Some(found) = find_product_in_ld(item) {
                return Some(found);
            }
        }
    }
    None
}

fn populate_from_jsonld(out: &mut ExtractedProduct, obj: &Value) {
    out.name = obj.get("name").and_then(value_to_string);
    out.description = obj.get("description").and_then(value_to_string);
    out.sku = obj.get("sku").and_then(value_to_string);
    out.mpn = obj.get("mpn").and_then(value_to_string);
    out.gtin = obj
        .get("gtin13")
        .or_else(|| obj.get("gtin12"))
        .or_else(|| obj.get("gtin14"))
        .or_else(|| obj.get("gtin8"))
        .or_else(|| obj.get("gtin"))
        .and_then(value_to_string);

    // brand can be a string or a nested {"name": "X"}
    out.brand = obj.get("brand").and_then(|b| {
        b.as_str().map(|s| s.to_string()).or_else(|| {
            b.get("name")
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
    });

    // image: string | array | {url}
    out.image_url = obj.get("image").and_then(|v| {
        v.as_str()
            .map(|s| s.to_string())
            .or_else(|| {
                v.as_array().and_then(|a| a.first()).and_then(|f| {
                    f.as_str()
                        .map(|s| s.to_string())
                        .or_else(|| f.get("url").and_then(|u| u.as_str()).map(|s| s.to_string()))
                })
            })
            .or_else(|| v.get("url").and_then(|u| u.as_str()).map(|s| s.to_string()))
    });

    out.category = obj.get("category").and_then(value_to_string);

    // offers: object, array, or AggregateOffer
    if let Some(offers) = obj.get("offers") {
        let primary = if offers.is_array() {
            offers.as_array().and_then(|a| a.first())
        } else {
            Some(offers)
        };

        if let Some(offer) = primary {
            // AggregateOffer uses lowPrice
            if let Some(price) = offer
                .get("price")
                .or_else(|| offer.get("lowPrice"))
                .and_then(value_to_string)
            {
                out.price_cents = parse_price_to_cents(&price);
            }
            out.currency = offer.get("priceCurrency").and_then(value_to_string);
            out.availability = offer.get("availability").and_then(|v| {
                v.as_str().map(|s| {
                    s.replace("https://schema.org/", "")
                        .replace("http://schema.org/", "")
                })
            });

            // Sale price heuristics
            if let Some(sale) = offer
                .get("salePrice")
                .or_else(|| offer.get("sale_price"))
                .and_then(value_to_string)
            {
                out.sale_price_cents = parse_price_to_cents(&sale);
            }
        }
    }

    // aggregateRating
    if let Some(r) = obj.get("aggregateRating") {
        out.rating = r.get("ratingValue").and_then(|v| {
            v.as_f64()
                .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
        });
        out.review_count = r
            .get("reviewCount")
            .or_else(|| r.get("ratingCount"))
            .and_then(|v| {
                v.as_i64()
                    .or_else(|| v.as_str().and_then(|s| s.replace(',', "").parse().ok()))
            });
    }
}

fn value_to_string(v: &Value) -> Option<String> {
    v.as_str()
        .map(|s| s.to_string())
        .or_else(|| v.as_f64().map(|f| format!("{f}")))
        .or_else(|| v.as_i64().map(|i| format!("{i}")))
}

// ---------------------------------------------------------------------------
// Price parsing
// ---------------------------------------------------------------------------

/// Parse a price string into integer cents.
///
/// Handles:
/// - `"$19.99"`        → 1999
/// - `"19.99 USD"`     → 1999
/// - `"1,299.00"`      → 129900   (US thousands)
/// - `"1.299,00"`      → 129900   (EU thousands)
/// - `"19"`            → 1900
/// - invalid           → None
pub fn parse_price_to_cents(s: &str) -> Option<i64> {
    // Keep only digits, dot, comma, minus
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.' || *c == ',' || *c == '-')
        .collect();
    if cleaned.is_empty() || cleaned == "-" {
        return None;
    }

    let last_dot = cleaned.rfind('.');
    let last_comma = cleaned.rfind(',');

    let normalized: String = match (last_dot, last_comma) {
        (Some(d), Some(c)) if c > d => {
            // EU: 1.299,00 → 1299.00
            cleaned.replace('.', "").replace(',', ".")
        }
        (Some(_), Some(_)) => {
            // US: 1,299.00 → 1299.00
            cleaned.replace(',', "")
        }
        (None, Some(_)) => {
            // Ambiguous single comma: if exactly 2 trailing digits after comma,
            // treat as EU decimal; otherwise as US thousands separator.
            let parts: Vec<&str> = cleaned.split(',').collect();
            if parts.len() == 2 && parts[1].len() == 2 {
                cleaned.replace(',', ".")
            } else {
                cleaned.replace(',', "")
            }
        }
        (Some(_), None) | (None, None) => cleaned.clone(),
    };

    let f: f64 = normalized.parse().ok()?;
    if !f.is_finite() {
        return None;
    }
    Some((f * 100.0).round() as i64)
}

// ---------------------------------------------------------------------------
// LLM fallback helpers
// ---------------------------------------------------------------------------

/// Derive a bare domain (host) from a URL, for the LLM schema cache key.
fn domain_of(url: &str) -> String {
    let trimmed = url.trim();
    let after_scheme = trimmed
        .find("://")
        .map(|i| &trimmed[i + 3..])
        .unwrap_or(trimmed);
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    // Strip an optional port (e.g. "localhost:11434").
    let host_no_port = host.rsplit(':').next().unwrap_or(host);
    if host_no_port.is_empty() {
        "localhost".to_string()
    } else {
        host_no_port.to_string()
    }
}

/// Convert an `LlmExtractor` item map (field name → string) into an
/// `ExtractedProduct`. Returns `None` if neither a name nor a price was found.
fn product_from_item(item: &HashMap<String, String>, confidence: f64) -> Option<ExtractedProduct> {
    let mut out = ExtractedProduct::empty(ExtractionMethod::LlmFallback, confidence);
    out.name = item.get("title").or_else(|| item.get("name")).cloned();
    out.brand = item.get("brand").cloned();
    out.currency = item.get("currency").cloned();
    out.sku = item.get("sku").cloned();
    out.image_url = item.get("image_url").cloned();
    out.description = item.get("description").cloned();
    out.availability = item.get("availability").cloned();
    out.category = item.get("category").cloned();
    if let Some(r) = item.get("rating").and_then(|v| v.parse::<f64>().ok()) {
        out.rating = Some(r);
    }
    if let Some(rc) = item.get("review_count").and_then(|v| v.parse::<i64>().ok()) {
        out.review_count = Some(rc);
    }
    // Prefer an already-normalized cents value, else parse a raw price string.
    out.price_cents = item
        .get("price_cents")
        .and_then(|s| s.parse::<i64>().ok())
        .or_else(|| item.get("price").and_then(|s| parse_price_to_cents(s)));
    if out.has_data() { Some(out) } else { None }
}

// ---------------------------------------------------------------------------
// Meta tag helper (OpenGraph etc.)
// ---------------------------------------------------------------------------

fn meta(html: &str, name: &str) -> Option<String> {
    let lower = html.to_lowercase();
    let name_lower = name.to_lowercase();

    for attr in &["property", "name"] {
        for quote in ['"', '\''] {
            let pattern = format!("{attr}={quote}{name_lower}{quote}");
            if let Some(pos) = lower.find(&pattern) {
                // Find enclosing <meta ...>
                let tag_start = lower[..pos].rfind("<meta")?;
                let tag_end = html[tag_start..].find('>')? + tag_start;
                let tag = &html[tag_start..=tag_end];
                // Find content="..."
                let tag_lower = tag.to_lowercase();
                for q in ['"', '\''] {
                    let cp = format!("content={q}");
                    if let Some(cs) = tag_lower.find(&cp) {
                        let vs = cs + cp.len();
                        if let Some(ve) = tag[vs..].find(q) {
                            let val = tag[vs..vs + ve].to_string();
                            if !val.is_empty() {
                                return Some(val);
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Price parsing ----

    #[test]
    fn price_us_simple() {
        assert_eq!(parse_price_to_cents("$19.99"), Some(1999));
    }

    #[test]
    fn price_with_currency_suffix() {
        assert_eq!(parse_price_to_cents("19.99 USD"), Some(1999));
    }

    #[test]
    fn price_us_thousands() {
        assert_eq!(parse_price_to_cents("1,299.00"), Some(129900));
        assert_eq!(parse_price_to_cents("$1,299.00"), Some(129900));
    }

    #[test]
    fn price_eu_thousands() {
        assert_eq!(parse_price_to_cents("1.299,00"), Some(129900));
        assert_eq!(parse_price_to_cents("1.299,00 €"), Some(129900));
    }

    #[test]
    fn price_eu_decimal_only() {
        assert_eq!(parse_price_to_cents("19,99"), Some(1999));
    }

    #[test]
    fn price_integer() {
        assert_eq!(parse_price_to_cents("19"), Some(1900));
    }

    #[test]
    fn price_invalid() {
        assert!(parse_price_to_cents("free").is_none());
        assert!(parse_price_to_cents("").is_none());
    }

    // ---- JSON-LD: Amazon-style ----

    #[test]
    fn amazon_jsonld() {
        let html = r#"<html><head>
<script type="application/ld+json">
{
  "@context": "https://schema.org/",
  "@type": "Product",
  "name": "Echo Dot (5th Gen)",
  "brand": {"@type": "Brand", "name": "Amazon"},
  "sku": "B09B8V1LZ3",
  "mpn": "C2N6L4",
  "image": ["https://m.media-shop-06.example/images/I/71xoR4A6q-L.jpg"],
  "description": "Smart speaker with Alexa",
  "offers": {
    "@type": "Offer",
    "price": "49.99",
    "priceCurrency": "USD",
    "availability": "https://schema.org/InStock"
  },
  "aggregateRating": {"@type": "AggregateRating", "ratingValue": "4.7", "reviewCount": 452301}
}
</script></head><body></body></html>"#;
        let p = SmartExtractor::try_jsonld(html).unwrap();
        assert_eq!(p.extraction_method, ExtractionMethod::JsonLd);
        assert_eq!(p.name.as_deref(), Some("Echo Dot (5th Gen)"));
        assert_eq!(p.brand.as_deref(), Some("Amazon"));
        assert_eq!(p.sku.as_deref(), Some("B09B8V1LZ3"));
        assert_eq!(p.mpn.as_deref(), Some("C2N6L4"));
        assert_eq!(p.price_cents, Some(4999));
        assert_eq!(p.currency.as_deref(), Some("USD"));
        assert_eq!(p.availability.as_deref(), Some("InStock"));
        assert_eq!(p.rating, Some(4.7));
        assert_eq!(p.review_count, Some(452301));
        // The fixture is de-identified: `m.media-amazon.com` is written as
        // `m.media-shop-06.example`, so the old `media-amazon` assertion could never hold against
        // the fixture it was paired with.
        assert!(p.image_url.as_deref().unwrap().contains("media-shop-06"));
    }

    // ---- JSON-LD: Walmart-style (@graph) ----

    #[test]
    fn walmart_jsonld_graph() {
        let html = r#"<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@graph": [
    {"@type": "BreadcrumbList", "itemListElement": []},
    {
      "@type": "Product",
      "name": "Great Value Whole Milk, 1 Gallon",
      "brand": "Great Value",
      "sku": "10450115",
      "gtin13": "0078742133201",
      "image": "https://i5.walmartimages.com/asr/xyz.jpg",
      "offers": {
        "@type": "Offer",
        "price": 3.64,
        "priceCurrency": "USD",
        "availability": "https://schema.org/InStock"
      }
    }
  ]
}
</script>"#;
        let p = SmartExtractor::try_jsonld(html).unwrap();
        assert_eq!(p.name.as_deref(), Some("Great Value Whole Milk, 1 Gallon"));
        assert_eq!(p.brand.as_deref(), Some("Great Value"));
        assert_eq!(p.gtin.as_deref(), Some("0078742133201"));
        assert_eq!(p.price_cents, Some(364));
    }

    // ---- JSON-LD: Target-style (offers as array) ----

    #[test]
    fn target_jsonld_offer_array() {
        let html = r#"<script type="application/ld+json">
{
  "@type": "Product",
  "name": "Threshold 8-Cup Coffee Maker",
  "brand": {"name": "Threshold"},
  "sku": "54321098",
  "offers": [{
    "@type": "Offer",
    "price": "24.99",
    "priceCurrency": "USD",
    "availability": "https://schema.org/InStock"
  }]
}
</script>"#;
        let p = SmartExtractor::try_jsonld(html).unwrap();
        assert_eq!(p.name.as_deref(), Some("Threshold 8-Cup Coffee Maker"));
        assert_eq!(p.brand.as_deref(), Some("Threshold"));
        assert_eq!(p.price_cents, Some(2499));
    }

    // ---- JSON-LD: Kroger-style (AggregateOffer) ----

    #[test]
    fn kroger_jsonld_aggregate() {
        let html = r#"<script type="application/ld+json">
{
  "@context": "https://schema.org",
  "@type": "Product",
  "name": "Kroger Organic Bananas",
  "brand": {"@type": "Brand", "name": "Kroger"},
  "gtin12": "011110000000",
  "offers": {
    "@type": "AggregateOffer",
    "lowPrice": "0.69",
    "priceCurrency": "USD",
    "availability": "https://schema.org/InStock"
  }
}
</script>"#;
        let p = SmartExtractor::try_jsonld(html).unwrap();
        assert_eq!(p.name.as_deref(), Some("Kroger Organic Bananas"));
        assert_eq!(p.gtin.as_deref(), Some("011110000000"));
        assert_eq!(p.price_cents, Some(69));
    }

    // ---- Microdata-only ----

    #[test]
    fn microdata_only_page() {
        let html = r#"<html><body>
<div itemscope itemtype="https://schema.org/Product">
  <span itemprop="name">Wool Socks</span>
  <span itemprop="brand">Acme</span>
  <meta itemprop="price" content="12.50">
  <meta itemprop="priceCurrency" content="USD">
  <link itemprop="availability" href="https://schema.org/InStock">
  <meta itemprop="sku" content="SOCK-42">
</div>
</body></html>"#;
        // Must fall through past JSON-LD (none present).
        let p = SmartExtractor::extract_from_html(html);
        assert_eq!(p.extraction_method, ExtractionMethod::Microdata);
        assert_eq!(p.name.as_deref(), Some("Wool Socks"));
        assert_eq!(p.brand.as_deref(), Some("Acme"));
        assert_eq!(p.price_cents, Some(1250));
        assert_eq!(p.sku.as_deref(), Some("SOCK-42"));
    }

    // ---- OpenGraph-only ----

    #[test]
    fn opengraph_only_page() {
        let html = r#"<html><head>
<meta property="og:title" content="Leather Wallet">
<meta property="og:image" content="https://cdn.example.com/wallet.jpg">
<meta property="og:description" content="Handmade leather wallet">
<meta property="product:brand" content="CraftCo">
<meta property="product:price:amount" content="59.00">
<meta property="product:price:currency" content="USD">
<meta property="product:availability" content="in stock">
</head><body></body></html>"#;
        let p = SmartExtractor::extract_from_html(html);
        assert_eq!(p.extraction_method, ExtractionMethod::OpenGraph);
        assert_eq!(p.name.as_deref(), Some("Leather Wallet"));
        assert_eq!(p.brand.as_deref(), Some("CraftCo"));
        assert_eq!(p.price_cents, Some(5900));
        assert_eq!(p.currency.as_deref(), Some("USD"));
    }

    // ---- CSS fallback ----

    #[test]
    fn css_only_fallback() {
        // No JSON-LD, no microdata, no OG — fall to CSS heuristics.
        let html = r#"<html><body>
<h1 class="product-title">Generic Mug</h1>
<span class="price">$8.49</span>
</body></html>"#;
        let p = SmartExtractor::extract_from_html(html);
        // CSS is last resort; accept Failed if SchemaExtractor doesn't match,
        // otherwise it should be CssHeuristics.
        assert!(
            p.extraction_method == ExtractionMethod::CssHeuristics
                || p.extraction_method == ExtractionMethod::Failed
        );
    }

    #[test]
    fn failed_when_no_data() {
        let html = "<html><body>nothing here</body></html>";
        let p = SmartExtractor::extract_from_html(html);
        assert_eq!(p.extraction_method, ExtractionMethod::Failed);
        assert_eq!(p.confidence, 0.0);
    }

    #[test]
    fn jsonld_beats_opengraph() {
        // Both present — JSON-LD must win.
        let html = r#"<html><head>
<meta property="og:title" content="OG Name">
<meta property="product:price:amount" content="99.00">
<script type="application/ld+json">
{"@type":"Product","name":"LD Name","offers":{"price":"5.00","priceCurrency":"USD"}}
</script>
</head><body></body></html>"#;
        let p = SmartExtractor::extract_from_html(html);
        assert_eq!(p.extraction_method, ExtractionMethod::JsonLd);
        assert_eq!(p.name.as_deref(), Some("LD Name"));
        assert_eq!(p.price_cents, Some(500));
    }
}
