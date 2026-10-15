//! LLM-powered extraction pipeline for Tallow's browser engine.
//!
//! Implements the Crawl4AI `JsonCssExtractionStrategy` pattern:
//! 1. Send sample HTML to an LLM (Ollama or compatible endpoint)
//! 2. LLM generates a CSS extraction schema (field name + selector + transforms)
//! 3. Execute extraction at CSS speed — zero LLM cost per subsequent page
//! 4. If extraction fails → LLM regenerates the schema automatically
//! 5. Cache schemas per domain + page-type on disk
//!
//! When Ollama is unavailable, falls back to predefined schemas for common
//! page types and then to `smart_extract` / `ai_extract` heuristics.

use crate::browser::smart_extract::{SmartExtractor, parse_price_to_cents};
use scraper::{Html, Selector};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

const EXTRACTOR_CONTRACT_VERSION: &str = "llm.extractor.contract.v2";

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A complete extraction schema for a given domain + page type.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractionSchema {
    /// Domain this schema was generated for (e.g. "amazon.com").
    pub domain: String,
    /// Page type: "product_listing", "product_detail", "article", "recipe", etc.
    pub page_type: String,
    /// Ordered list of field extractors.
    pub fields: Vec<FieldExtractor>,
    /// Unix timestamp when this schema was created.
    pub created_at: i64,
    /// Number of successful extractions using this schema.
    pub success_count: u64,
    /// Number of failed extractions using this schema.
    pub fail_count: u64,
    /// Schema version (incremented on regeneration).
    pub version: u32,
}

/// Versioned extraction contract sidecar persisted alongside schemas.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtractorContractVersion {
    /// Stable identifier: `{domain}::{page_type}::v{schema_version}`
    pub contract_id: String,
    /// Contract schema version for this sidecar format.
    pub contract_version: String,
    /// Mirrors `ExtractionSchema.version`.
    pub schema_version: u32,
    /// Domain this contract is for.
    pub domain: String,
    /// Page type this contract is for.
    pub page_type: String,
    /// Required field names that define parse success.
    pub required_fields: Vec<String>,
    /// Total selectors represented (primary + fallback).
    pub selector_count: usize,
    /// Deterministic digest of selector + transform contract.
    pub digest: String,
    /// Unix timestamp for when this sidecar was generated.
    pub generated_at: i64,
}

/// A single field extractor within a schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldExtractor {
    /// Field name: "price", "title", "image_url", etc.
    pub name: String,
    /// Primary CSS selector.
    pub selector: String,
    /// If `None`, extract text content. If `Some("href")`, extract that attribute.
    pub attribute: Option<String>,
    /// Optional post-processing transform.
    pub transform: Option<TransformFn>,
    /// Whether this field must be present for extraction to count as successful.
    pub required: bool,
    /// Fallback selectors tried in order if the primary fails.
    pub fallback_selectors: Vec<String>,
}

/// Post-processing transforms applied after CSS selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransformFn {
    /// Trim leading/trailing whitespace.
    TrimWhitespace,
    /// Parse price text ("$12.99") into cents string ("1299").
    ParsePrice,
    /// Parse as integer.
    ParseInt,
    /// Parse as float.
    ParseFloat,
    /// Resolve relative URLs against the page base.
    ExtractUrl,
    /// Strip any remaining HTML tags from text content.
    StripHtml,
    /// Apply a regex and return the first capture group.
    RegexExtract(String),
    /// Custom JS-style expression (stored for documentation, applied as regex).
    Custom(String),
}

/// Result of schema validation.
#[derive(Debug, Clone)]
pub struct ValidationResult {
    /// True if all required fields were extracted.
    pub valid: bool,
    /// Fields that were missing.
    pub missing_required: Vec<String>,
    /// Fields that were present but empty.
    pub empty_fields: Vec<String>,
    /// Total fields extracted successfully.
    pub extracted_count: usize,
    /// Total fields defined in the schema.
    pub total_fields: usize,
}

/// Unified extraction output.
#[derive(Debug, Clone)]
pub struct ExtractedData {
    /// Page type that was detected.
    pub page_type: String,
    /// All items extracted (one per repeated block, or a single item).
    pub items: Vec<HashMap<String, String>>,
    /// The schema used for extraction.
    pub schema_domain: String,
    /// Whether the LLM was called during this extraction.
    pub used_llm: bool,
    /// Confidence in the extraction (0.0 - 1.0).
    pub confidence: f64,
}

// ---------------------------------------------------------------------------
// Engine selection
// ---------------------------------------------------------------------------

/// Which HTTP API the schema-first tier speaks to.
///
/// This was Ollama-only, which made the *decided* engine unreachable: there was
/// no way to point the tier at an OpenAI-compatible endpoint. Selection is
/// explicit and the default preserves the previous behaviour rather than
/// changing it silently.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Engine {
    /// Ollama's `/api/generate` — the historical default.
    #[default]
    Ollama,
    /// An OpenAI-compatible `/v1/chat/completions` endpoint.
    OpenAiCompatible,
}

impl Engine {
    /// Parse an engine name as an operator would spell it.
    pub fn parse(name: &str) -> Option<Engine> {
        match name.trim().to_ascii_lowercase().as_str() {
            "" | "ollama" => Some(Engine::Ollama),
            "openai" | "openai-compatible" | "openai_compatible" => Some(Engine::OpenAiCompatible),
            _ => None,
        }
    }

    /// The name recorded in run evidence, so "which tier ran" is a fact about
    /// the run rather than an inference from configuration.
    pub fn as_str(self) -> &'static str {
        match self {
            Engine::Ollama => "ollama",
            Engine::OpenAiCompatible => "openai-compatible",
        }
    }
}

/// Errors during LLM extraction.
#[derive(Debug)]
pub enum ExtractError {
    /// Ollama is not reachable.
    OllamaUnavailable(String),
    /// The selected engine cannot be used as configured — a missing credential,
    /// say. Distinct from `OllamaUnavailable`, which is a reachability failure:
    /// "not configured" and "not answering" need different fixes.
    EngineMisconfigured(String),
    /// LLM returned unparseable output.
    LlmParseFailed(String),
    /// No schema available and LLM unavailable.
    NoSchema(String),
    /// CSS selector parse error.
    SelectorError(String),
    /// I/O error (disk cache).
    IoError(std::io::Error),
    /// HTTP request error.
    HttpError(String),
    /// Extraction produced no results.
    EmptyResult,
}

impl std::fmt::Display for ExtractError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExtractError::OllamaUnavailable(msg) => write!(f, "ollama unavailable: {msg}"),
            ExtractError::EngineMisconfigured(msg) => write!(f, "engine misconfigured: {msg}"),
            ExtractError::LlmParseFailed(msg) => write!(f, "LLM parse failed: {msg}"),
            ExtractError::NoSchema(msg) => write!(f, "no schema: {msg}"),
            ExtractError::SelectorError(msg) => write!(f, "selector error: {msg}"),
            ExtractError::IoError(e) => write!(f, "I/O error: {e}"),
            ExtractError::HttpError(msg) => write!(f, "HTTP error: {msg}"),
            ExtractError::EmptyResult => write!(f, "extraction produced no results"),
        }
    }
}

impl std::error::Error for ExtractError {}

impl From<std::io::Error> for ExtractError {
    fn from(e: std::io::Error) -> Self {
        ExtractError::IoError(e)
    }
}

// ---------------------------------------------------------------------------
// LlmExtractor
// ---------------------------------------------------------------------------

/// LLM-powered extraction engine.
///
/// Uses Ollama (or a compatible OpenAI-style API) to generate CSS extraction
/// schemas from sample HTML, then executes extraction at CSS speed with no
/// subsequent LLM calls.
pub struct LlmExtractor {
    /// Which API this extractor speaks to.
    pub engine: Engine,
    /// Whether page content may be sent to this engine (see
    /// [`crate::browser::llm_transfer`]). Defaults to *no policy*, which refuses
    /// a remote transfer — the gate is fail-closed, so a caller that never
    /// considered the question does not get to send content to a vendor.
    pub transfer: crate::browser::llm_transfer::TransferPolicy,
    /// The run's spend cap.
    pub budget: LlmBudget,
    /// Model calls made by this extractor. An atomic rather than a plain counter
    /// because the call path takes `&self`.
    calls_made: std::sync::atomic::AtomicU64,
    /// Engine base URL (default: `http://localhost:11434`). Named for its
    /// historical Ollama-only meaning; with `engine: OpenAiCompatible` it is the
    /// OpenAI-compatible root that `/v1/chat/completions` is appended to.
    pub ollama_url: String,
    /// Model name to use (default: `llama3.2`).
    pub model: String,
    /// In-memory schema cache keyed by `"{domain}::{page_type}"`.
    pub schema_cache: HashMap<String, ExtractionSchema>,
    /// Directory for persisted schema JSON files.
    pub cache_dir: PathBuf,
    /// HTTP client for Ollama API calls.
    client: reqwest::Client,
    /// Whether Ollama was confirmed available (cached probe result).
    ollama_available: Option<bool>,
}

impl LlmExtractor {
    /// Create a new `LlmExtractor` with default settings.
    pub fn new() -> Self {
        Self::with_config("http://localhost:11434", "llama3.2", ".tallow-schemas")
    }

    /// Create a new `LlmExtractor` for an Ollama endpoint.
    ///
    /// Kept because callers (`smart_extract`) describe an Ollama URL and that is
    /// part of their contract. It is exactly [`Self::with_engine`] with
    /// [`Engine::Ollama`], so one body serves both and they cannot drift.
    pub fn with_config(ollama_url: &str, model: &str, cache_dir: &str) -> Self {
        Self::with_engine(Engine::Ollama, ollama_url, model, cache_dir)
    }

    /// Create a new `LlmExtractor` for an explicit engine.
    ///
    /// The URL is checked against the zone predicate here, before any request
    /// exists, so an engine cannot be added that bypasses the egress route.
    pub fn with_engine(engine: Engine, base_url: &str, model: &str, cache_dir: &str) -> Self {
        let cache_path = PathBuf::from(cache_dir);
        let _ = std::fs::create_dir_all(&cache_path);

        let mut extractor = Self {
            engine,
            transfer: crate::browser::llm_transfer::TransferPolicy::none(),
            budget: LlmBudget::from_env(&|k| std::env::var(k).ok()),
            calls_made: std::sync::atomic::AtomicU64::new(0),
            ollama_url: base_url.trim_end_matches('/').to_string(),
            model: model.to_string(),
            schema_cache: HashMap::new(),
            cache_dir: cache_path,
            client: {
                // T-207: the zone predicate decides the route — loopback
                // (default Ollama) stays in-zone; a WAN URL rides the
                // contract.
                let mut builder =
                    reqwest::Client::builder().timeout(std::time::Duration::from_secs(120));
                match crate::browser::zone::browser_zone_egress_for(base_url) {
                    Ok(crate::browser::zone::ZoneEgress::InZone) => {}
                    Ok(_) => {
                        if let Ok(Some(zp)) = crate::browser::zone::browser_zone_reqwest_proxy() {
                            builder = builder.proxy(zp);
                        }
                    }
                    Err(reason) => {
                        // Refuse rather than egress from the box IP (N3).
                        panic!("{reason}");
                    }
                }
                builder.build().unwrap_or_default()
            },
            ollama_available: None,
        };

        // Load all cached schemas from disk.
        extractor.load_cached_schemas();
        extractor
    }

    // -----------------------------------------------------------------------
    // Core API
    // -----------------------------------------------------------------------

    /// Extract data using a cached schema -- no LLM call, pure CSS selection.
    ///
    /// Returns one `HashMap` per repeated item found on the page (e.g. product
    /// listing pages yield multiple items).
    pub fn extract(
        &self,
        html: &str,
        domain: &str,
    ) -> Result<Vec<HashMap<String, String>>, ExtractError> {
        // Try domain-specific schema first, then predefined.
        let schema = self
            .find_schema(domain)
            .ok_or_else(|| ExtractError::NoSchema(format!("no schema for domain {domain}")))?;
        self.execute_schema(html, &schema)
    }

    /// Generate a new schema from sample HTML using the LLM.
    pub async fn generate_schema(
        &mut self,
        html: &str,
        domain: &str,
        page_type: &str,
    ) -> Result<ExtractionSchema, ExtractError> {
        self.ensure_engine_available().await?;

        let clean_sample = Self::prepare_html_sample(html);
        let prompt = Self::build_prompt(&clean_sample, domain, page_type);

        let response = self.call_engine(&prompt).await?;
        let schema = self.parse_llm_response(&response, domain, page_type)?;

        // Validate the schema actually works on the source HTML.
        let test_results = self.execute_schema(html, &schema);
        if let Ok(ref items) = test_results {
            if items.is_empty() {
                return Err(ExtractError::LlmParseFailed(
                    "generated schema extracted zero items from source HTML".into(),
                ));
            }
        }

        // Cache in memory and on disk.
        let key = cache_key(domain, page_type);
        self.schema_cache.insert(key, schema.clone());
        self.save_schema(&schema)?;

        Ok(schema)
    }

    /// Auto-detect page type and extract.
    ///
    /// 1. Check for cached schema for this domain.
    /// 2. If found, execute at CSS speed.
    /// 3. If extraction fails (>10% failure rate), regenerate via LLM.
    /// 4. If no schema and no LLM, fall back to predefined schemas + smart_extract.
    pub async fn auto_extract(
        &mut self,
        html: &str,
        url: &str,
    ) -> Result<ExtractedData, ExtractError> {
        let domain = extract_domain(url);
        let page_type = detect_page_type(html);

        // Try cached schema for this domain.
        let key = cache_key(&domain, &page_type);
        if let Some(schema) = self.schema_cache.get(&key).cloned() {
            if let Ok(items) = self.execute_schema(html, &schema) {
                if !items.is_empty() {
                    let validation = self.validate(&items[0], &schema);
                    if validation.valid {
                        // Update success count.
                        if let Some(s) = self.schema_cache.get_mut(&key) {
                            s.success_count += 1;
                        }
                        if let Some(s) = self.schema_cache.get(&key) {
                            let _ = self.save_schema(s);
                        }
                        return Ok(ExtractedData {
                            page_type,
                            items,
                            schema_domain: domain,
                            used_llm: false,
                            confidence: 0.90,
                        });
                    } else {
                        // Track failure.
                        if let Some(s) = self.schema_cache.get_mut(&key) {
                            s.fail_count += 1;
                        }
                        if let Some(s) = self.schema_cache.get(&key) {
                            let _ = self.save_schema(s);
                        }
                    }
                }
            }

            // Check if schema needs regeneration (>10% failure rate).
            if let Some(schema) = self.schema_cache.get(&key) {
                if schema.success_count > 0 && schema.fail_count > schema.success_count / 10 {
                    // Try to heal.
                    if let Ok(new_schema) = self.heal_schema(html, &domain).await {
                        if let Ok(items) = self.execute_schema(html, &new_schema) {
                            if !items.is_empty() {
                                return Ok(ExtractedData {
                                    page_type,
                                    items,
                                    schema_domain: domain,
                                    used_llm: true,
                                    confidence: 0.85,
                                });
                            }
                        }
                    }
                }
            }
        }

        // Try predefined schemas.
        if let Ok(items) = self.extract_with_predefined(html, &page_type) {
            if !items.is_empty() {
                return Ok(ExtractedData {
                    page_type,
                    items,
                    schema_domain: "predefined".into(),
                    used_llm: false,
                    confidence: 0.80,
                });
            }
        }

        // Try LLM generation if available.
        if self.check_ollama_available().await {
            if let Ok(schema) = self.generate_schema(html, &domain, &page_type).await {
                if let Ok(items) = self.execute_schema(html, &schema) {
                    if !items.is_empty() {
                        return Ok(ExtractedData {
                            page_type,
                            items,
                            schema_domain: domain,
                            used_llm: true,
                            confidence: 0.85,
                        });
                    }
                }
            }
        }

        // Final fallback: smart_extract heuristics.
        let product = SmartExtractor::extract_from_html(html);
        if product.name.is_some() || product.price_cents.is_some() {
            let mut map = HashMap::new();
            if let Some(ref name) = product.name {
                map.insert("title".into(), name.clone());
            }
            if let Some(cents) = product.price_cents {
                map.insert("price_cents".into(), cents.to_string());
            }
            if let Some(ref brand) = product.brand {
                map.insert("brand".into(), brand.clone());
            }
            if let Some(ref img) = product.image_url {
                map.insert("image_url".into(), img.clone());
            }
            if let Some(ref sku) = product.sku {
                map.insert("sku".into(), sku.clone());
            }
            if let Some(ref avail) = product.availability {
                map.insert("availability".into(), avail.clone());
            }
            if let Some(ref currency) = product.currency {
                map.insert("currency".into(), currency.clone());
            }
            if let Some(rating) = product.rating {
                map.insert("rating".into(), rating.to_string());
            }
            return Ok(ExtractedData {
                page_type: "product_detail".into(),
                items: vec![map],
                schema_domain: "smart_extract".into(),
                used_llm: false,
                confidence: product.confidence,
            });
        }

        Err(ExtractError::EmptyResult)
    }

    /// Validate extraction results against a schema.
    pub fn validate(
        &self,
        results: &HashMap<String, String>,
        schema: &ExtractionSchema,
    ) -> ValidationResult {
        let mut missing_required = Vec::new();
        let mut empty_fields = Vec::new();
        let mut extracted_count = 0;

        for field in &schema.fields {
            match results.get(&field.name) {
                Some(val) if !val.trim().is_empty() => {
                    extracted_count += 1;
                }
                Some(_) => {
                    empty_fields.push(field.name.clone());
                    if field.required {
                        missing_required.push(field.name.clone());
                    }
                }
                None => {
                    if field.required {
                        missing_required.push(field.name.clone());
                    }
                }
            }
        }

        ValidationResult {
            valid: missing_required.is_empty(),
            missing_required,
            empty_fields,
            extracted_count,
            total_fields: schema.fields.len(),
        }
    }

    /// If validation fails, regenerate the schema via LLM.
    pub async fn heal_schema(
        &mut self,
        html: &str,
        domain: &str,
    ) -> Result<ExtractionSchema, ExtractError> {
        let page_type = detect_page_type(html);

        // Archive current version before regenerating.
        let key = cache_key(domain, &page_type);
        let next_version = self
            .schema_cache
            .get(&key)
            .map(|s| s.version + 1)
            .unwrap_or(1);

        let mut schema = self.generate_schema(html, domain, &page_type).await?;
        schema.version = next_version;

        // Persist with version history.
        self.schema_cache.insert(key, schema.clone());
        self.save_schema(&schema)?;

        Ok(schema)
    }

    // -----------------------------------------------------------------------
    // Schema execution — pure CSS, zero LLM cost
    // -----------------------------------------------------------------------

    /// Execute a schema against HTML, returning extracted items.
    fn execute_schema(
        &self,
        html: &str,
        schema: &ExtractionSchema,
    ) -> Result<Vec<HashMap<String, String>>, ExtractError> {
        let document = Html::parse_document(html);
        let mut item = HashMap::new();

        for field in &schema.fields {
            let value = self.extract_field(&document, field);
            if let Some(val) = value {
                item.insert(field.name.clone(), val);
            }
        }

        if item.is_empty() {
            return Err(ExtractError::EmptyResult);
        }

        Ok(vec![item])
    }

    /// Extract a single field using its primary selector and fallbacks.
    fn extract_field(&self, document: &Html, field: &FieldExtractor) -> Option<String> {
        // Try primary selector.
        if let Some(val) = self.try_selector(document, &field.selector, &field.attribute) {
            return Some(self.apply_transform(&val, &field.transform));
        }

        // Try fallback selectors.
        for fallback in &field.fallback_selectors {
            if let Some(val) = self.try_selector(document, fallback, &field.attribute) {
                return Some(self.apply_transform(&val, &field.transform));
            }
        }

        None
    }

    /// Try a single CSS selector and extract text or attribute.
    fn try_selector(
        &self,
        document: &Html,
        selector_str: &str,
        attribute: &Option<String>,
    ) -> Option<String> {
        let selector = Selector::parse(selector_str).ok()?;
        let element = document.select(&selector).next()?;

        let raw = match attribute {
            Some(attr) => element.value().attr(attr)?.to_string(),
            None => element
                .text()
                .collect::<Vec<_>>()
                .join(" ")
                .trim()
                .to_string(),
        };

        if raw.is_empty() { None } else { Some(raw) }
    }

    /// Apply a transform function to an extracted value.
    fn apply_transform(&self, value: &str, transform: &Option<TransformFn>) -> String {
        match transform {
            None => value.to_string(),
            Some(TransformFn::TrimWhitespace) => value.trim().to_string(),
            Some(TransformFn::ParsePrice) => parse_price_to_cents(value)
                .map(|c| c.to_string())
                .unwrap_or_else(|| value.to_string()),
            Some(TransformFn::ParseInt) => {
                let cleaned: String = value
                    .chars()
                    .filter(|c| c.is_ascii_digit() || *c == '-')
                    .collect();
                cleaned
                    .parse::<i64>()
                    .map(|n| n.to_string())
                    .unwrap_or_else(|_| value.to_string())
            }
            Some(TransformFn::ParseFloat) => {
                let cleaned: String = value
                    .chars()
                    .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
                    .collect();
                cleaned
                    .parse::<f64>()
                    .map(|n| n.to_string())
                    .unwrap_or_else(|_| value.to_string())
            }
            Some(TransformFn::ExtractUrl) => {
                // Already extracted from href/src attribute; return as-is.
                value.to_string()
            }
            Some(TransformFn::StripHtml) => {
                let fragment = Html::parse_fragment(value);
                fragment
                    .root_element()
                    .text()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .trim()
                    .to_string()
            }
            Some(TransformFn::RegexExtract(pattern)) => regex::Regex::new(pattern)
                .ok()
                .and_then(|re| re.captures(value))
                .and_then(|caps| caps.get(1).or_else(|| caps.get(0)))
                .map(|m| m.as_str().to_string())
                .unwrap_or_else(|| value.to_string()),
            Some(TransformFn::Custom(expr)) => {
                // Custom expressions: treat as regex for now.
                regex::Regex::new(expr)
                    .ok()
                    .and_then(|re| re.captures(value))
                    .and_then(|caps| caps.get(1).or_else(|| caps.get(0)))
                    .map(|m| m.as_str().to_string())
                    .unwrap_or_else(|| value.to_string())
            }
        }
    }

    // -----------------------------------------------------------------------
    // LLM integration (Ollama)
    // -----------------------------------------------------------------------

    /// Check if Ollama is reachable (cached after first probe).
    async fn check_ollama_available(&mut self) -> bool {
        if let Some(avail) = self.ollama_available {
            return avail;
        }
        let url = format!("{}/api/tags", self.ollama_url);
        let available = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(3))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        self.ollama_available = Some(available);
        available
    }

    /// Ensure Ollama is available; return error if not.
    async fn ensure_ollama_available(&mut self) -> Result<(), ExtractError> {
        if self.check_ollama_available().await {
            Ok(())
        } else {
            Err(ExtractError::OllamaUnavailable(format!(
                "cannot reach Ollama at {}",
                self.ollama_url
            )))
        }
    }

    /// Probe an OpenAI-compatible endpoint.
    ///
    /// `/v1/models` is the cheapest question that separates "reachable" from
    /// "not": a bounded GET with no model call, so probing cannot itself burn a
    /// completion — or, worse, half an extraction.
    async fn check_openai_compatible_available(&mut self) -> bool {
        if let Some(avail) = self.ollama_available {
            return avail;
        }
        let url = format!("{}/v1/models", self.ollama_url);
        let available = self
            .client
            .get(&url)
            .timeout(std::time::Duration::from_secs(3))
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false);
        self.ollama_available = Some(available);
        available
    }

    /// Ensure the selected engine is usable before a request is spent.
    ///
    /// An OpenAI-compatible endpoint has no cheap liveness probe that is not
    /// itself a billed request, so availability here means *configured*: a
    /// credential is present. A missing credential is refused, never sent
    /// unauthenticated.
    async fn ensure_engine_available(&mut self) -> Result<(), ExtractError> {
        // The transfer gate comes first: it is not about whether the engine
        // answers, but whether we are permitted to send to it at all.
        if let crate::browser::llm_transfer::TransferDecision::Refuse(reason) =
            crate::browser::llm_transfer::decide(self.is_third_party(), &self.transfer)
        {
            return Err(ExtractError::EngineMisconfigured(reason));
        }
        match self.engine {
            Engine::Ollama => self.ensure_ollama_available().await,
            Engine::OpenAiCompatible => {
                resolve_api_key_live()?;
                if self.check_openai_compatible_available().await {
                    Ok(())
                } else {
                    Err(ExtractError::EngineMisconfigured(format!(
                        "cannot reach the OpenAI-compatible engine at {}",
                        self.ollama_url
                    )))
                }
            }
        }
    }

    /// Call the selected engine.
    ///
    /// One place decides, so an engine cannot be selected in configuration and
    /// then ignored by the call path.
    async fn call_engine(&self, prompt: &str) -> Result<String, ExtractError> {
        // Spend is checked before the call, not reported after it.
        let made = self.calls_made.load(std::sync::atomic::Ordering::SeqCst);
        self.budget
            .check_calls(made)
            .map_err(ExtractError::EngineMisconfigured)?;
        self.budget
            .check_prompt(prompt.len())
            .map_err(ExtractError::EngineMisconfigured)?;
        self.calls_made
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);

        let text = match self.engine {
            Engine::Ollama => self.call_ollama(prompt).await?,
            Engine::OpenAiCompatible => self.call_openai_compatible(prompt).await?,
        };
        // Which engine ran is RECORDED, not inferred from configuration: a
        // configured engine that was never called is not a fact about the run.
        crate::run_evidence::record(
            "llm_engine",
            serde_json::json!({
                "engine": self.engine.as_str(),
                "model": self.model,
                "base_url": self.ollama_url,
                "prompt_chars": prompt.len(),
                "response_chars": text.len(),
            }),
        );
        Ok(text)
    }

    /// Declare the transfer policy this extractor runs under.
    pub fn with_transfer(mut self, transfer: crate::browser::llm_transfer::TransferPolicy) -> Self {
        self.transfer = transfer;
        self
    }

    /// Is this engine's endpoint outside the box's zone?
    ///
    /// An unknown route counts as third-party: failing closed is the only safe
    /// reading of "we could not tell where this would go".
    fn is_third_party(&self) -> bool {
        !matches!(
            crate::browser::zone::browser_zone_egress_for(&self.ollama_url),
            Ok(crate::browser::zone::ZoneEgress::InZone)
        )
    }

    /// Measure the tier's state: every field is observed here, so "enabled" and
    /// "working" stop being the same claim. Idempotent — the probe is cached.
    pub async fn tier_state(&mut self) -> TierState {
        let credential_present = resolve_api_key_live().is_ok();
        let reachable = match self.engine {
            Engine::Ollama => self.check_ollama_available().await,
            Engine::OpenAiCompatible => {
                credential_present && self.check_openai_compatible_available().await
            }
        };
        // The transfer decision is part of the tier's state, not a separate
        // concern: a tier that could reach the engine but is not permitted to
        // send to it is not enabled, and saying "enabled" there would be the same
        // conflation this phase removes.
        let third_party = self.is_third_party();
        let decision = crate::browser::llm_transfer::decide(third_party, &self.transfer);
        let transfer_allowed = decision.is_allowed();

        let reason = match &decision {
            crate::browser::llm_transfer::TransferDecision::Refuse(r) => {
                format!("disabled ({r})")
            }
            crate::browser::llm_transfer::TransferDecision::Allow => {
                if self.engine == Engine::OpenAiCompatible && !credential_present {
                    format!("disabled (no credential: {LLM_API_KEY_ENV})")
                } else if !reachable {
                    format!("disabled (engine not reachable at {})", self.ollama_url)
                } else if third_party {
                    format!(
                        "enabled (third-party transfer permitted by {})",
                        self.transfer.source
                    )
                } else {
                    "enabled (in-zone engine: content does not leave the box)".to_string()
                }
            }
        };
        TierState {
            enabled: credential_present && reachable && transfer_allowed,
            transfer_allowed,
            calls_made: self.calls_made.load(std::sync::atomic::Ordering::SeqCst),
            max_calls: self.budget.max_calls,
            engine: self.engine.as_str(),
            engine_url: self.ollama_url.clone(),
            model: self.model.clone(),
            credential_present,
            reachable,
            reason,
        }
    }

    /// Call an OpenAI-compatible `/v1/chat/completions` endpoint.
    ///
    /// Rides `self.client`, which the constructor already bound to the guarded
    /// egress plane — adding an engine does not add an egress path.
    ///
    /// **Data-flow (P1.T3):** the request carries the page's sampled content and
    /// the extraction prompt to the configured vendor, and the response carries
    /// the generated schema back. With the guard intact the box IP does not leave
    /// the box: a WAN URL is reached through `browser_zone_reqwest_proxy`, and if
    /// the zone predicate refuses, the constructor has already refused to build a
    /// client at all rather than egressing direct (tagged N3). No
    /// `TALLOW_ALLOW_DIRECT`-style bypass exists here on purpose.
    async fn call_openai_compatible(&self, prompt: &str) -> Result<String, ExtractError> {
        let key = resolve_api_key_live()?;
        let url = format!("{}/v1/chat/completions", self.ollama_url);
        let body = openai_request_body(&self.model, prompt);

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {key}"))
            .json(&body)
            .send()
            .await
            .map_err(|e| ExtractError::HttpError(e.to_string()))?;

        let status = resp.status();
        if !status.is_success() {
            // The URL and status only: an error body can quote the request back,
            // and the request carries the credential.
            return Err(ExtractError::HttpError(format!(
                "{url} returned status {status}"
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ExtractError::HttpError(e.to_string()))?;
        parse_openai_response(&json)
    }

    /// Call the Ollama generate API.
    async fn call_ollama(&self, prompt: &str) -> Result<String, ExtractError> {
        let url = format!("{}/api/generate", self.ollama_url);

        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            "options": {
                "temperature": 0.1,
                "num_predict": 4096
            }
        });

        let resp = self
            .client
            .post(&url)
            .json(&body)
            .send()
            .await
            .map_err(|e| ExtractError::HttpError(e.to_string()))?;

        if !resp.status().is_success() {
            return Err(ExtractError::HttpError(format!(
                "Ollama returned status {}",
                resp.status()
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| ExtractError::HttpError(e.to_string()))?;

        json.get("response")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .ok_or_else(|| {
                ExtractError::LlmParseFailed("no 'response' field in Ollama output".into())
            })
    }

    /// Prepare a truncated, cleaned HTML sample for the LLM prompt.
    fn prepare_html_sample(html: &str) -> String {
        use std::sync::LazyLock;

        static RE_SCRIPT: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"(?is)<script\b[^>]*>.*?</script>").expect("static regex")
        });
        static RE_STYLE: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"(?is)<style\b[^>]*>.*?</style>").expect("static regex")
        });
        static RE_NOSCRIPT: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"(?is)<noscript\b[^>]*>.*?</noscript>").expect("static regex")
        });
        static RE_SVG: LazyLock<regex::Regex> = LazyLock::new(|| {
            regex::Regex::new(r"(?is)<svg\b[^>]*>.*?</svg>").expect("static regex")
        });
        static RE_COMMENT: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"(?s)<!--.*?-->").expect("static regex"));
        static RE_WHITESPACE: LazyLock<regex::Regex> =
            LazyLock::new(|| regex::Regex::new(r"\s{3,}").expect("static regex"));

        // Use the existing clean-text pipeline but keep more structure for CSS analysis.
        let mut sample = html.to_string();

        // Remove script/style/noscript/svg blocks to reduce noise.
        sample = RE_SCRIPT.replace_all(&sample, "").to_string();
        sample = RE_STYLE.replace_all(&sample, "").to_string();
        sample = RE_NOSCRIPT.replace_all(&sample, "").to_string();
        sample = RE_SVG.replace_all(&sample, "").to_string();

        // Remove HTML comments.
        sample = RE_COMMENT.replace_all(&sample, "").to_string();

        // Collapse excessive whitespace.
        sample = RE_WHITESPACE.replace_all(&sample, "  ").to_string();

        // Truncate to ~4000 characters to fit LLM context.
        if sample.len() > 4000 {
            sample.truncate(4000);
            sample.push_str("\n<!-- TRUNCATED -->");
        }

        sample
    }

    /// Build the LLM prompt for schema generation.
    fn build_prompt(html_sample: &str, domain: &str, page_type: &str) -> String {
        let hash = "#";
        format!(
            "You are an expert web scraping engineer. Analyze the following HTML from {domain} \
             and generate a JSON extraction schema.\n\n\
             Page type: {page_type}\n\n\
             Your task:\n\
             1. Identify the CSS selectors for each data field on this page.\n\
             2. For each field, provide a primary selector and 1-2 fallback selectors.\n\
             3. Specify whether to extract text content or a specific attribute (like \"href\" or \"src\").\n\
             4. Specify any transforms needed (trim_whitespace, parse_price, parse_int, parse_float, extract_url, strip_html).\n\n\
             Respond with ONLY valid JSON in this exact format (no markdown, no explanation):\n\
             {{\n\
               \"page_type\": \"{page_type}\",\n\
               \"fields\": [\n\
                 {{\n\
                   \"name\": \"field_name\",\n\
                   \"selector\": \"css.selector\",\n\
                   \"attribute\": null,\n\
                   \"transform\": \"trim_whitespace\",\n\
                   \"required\": true,\n\
                   \"fallback_selectors\": [\".alt-selector\", \"{hash}backup-selector\"]\n\
                 }}\n\
               ]\n\
             }}\n\n\
             Common fields by page type:\n\
             - product_detail: title, price, currency, brand, image_url, description, sku, availability, rating, review_count, category\n\
             - product_listing: items (repeated), each with: title, price, image_url, link\n\
             - article: title, author, date, body, image_url\n\
             - recipe: name, ingredients, instructions, prep_time, cook_time, servings, image_url\n\
             - job_listing: title, company, location, salary, description, apply_url\n\
             - real_estate: address, price, bedrooms, bathrooms, sqft, image_url, description\n\n\
             For \"transform\" use one of: null, \"trim_whitespace\", \"parse_price\", \"parse_int\", \"parse_float\", \"extract_url\", \"strip_html\"\n\n\
             HTML sample:\n{html_sample}"
        )
    }

    /// Parse the LLM JSON response into an `ExtractionSchema`.
    fn parse_llm_response(
        &self,
        response: &str,
        domain: &str,
        page_type: &str,
    ) -> Result<ExtractionSchema, ExtractError> {
        // Find JSON in the response (LLMs sometimes wrap in markdown).
        let json_str = extract_json_block(response).ok_or_else(|| {
            ExtractError::LlmParseFailed(format!(
                "no valid JSON found in LLM response (length {})",
                response.len()
            ))
        })?;

        let parsed: serde_json::Value = serde_json::from_str(&json_str)
            .map_err(|e| ExtractError::LlmParseFailed(format!("JSON parse error: {e}")))?;

        let fields_val = parsed
            .get("fields")
            .and_then(|v| v.as_array())
            .ok_or_else(|| {
                ExtractError::LlmParseFailed("missing 'fields' array in LLM response".into())
            })?;

        let mut fields = Vec::new();
        for f in fields_val {
            let name = f
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if name.is_empty() {
                continue;
            }

            let selector = f
                .get("selector")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            if selector.is_empty() {
                continue;
            }

            // Validate the selector actually parses.
            if Selector::parse(&selector).is_err() {
                continue;
            }

            let attribute = f
                .get("attribute")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .map(|s| s.to_string());

            let transform = f
                .get("transform")
                .and_then(|v| v.as_str())
                .and_then(parse_transform_name);

            let required = f.get("required").and_then(|v| v.as_bool()).unwrap_or(false);

            let fallback_selectors: Vec<String> = f
                .get("fallback_selectors")
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str())
                        .filter(|s| !s.is_empty() && Selector::parse(s).is_ok())
                        .map(|s| s.to_string())
                        .collect()
                })
                .unwrap_or_default();

            fields.push(FieldExtractor {
                name,
                selector,
                attribute,
                transform,
                required,
                fallback_selectors,
            });
        }

        if fields.is_empty() {
            return Err(ExtractError::LlmParseFailed(
                "LLM response produced zero valid field extractors".into(),
            ));
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Ok(ExtractionSchema {
            domain: domain.to_string(),
            page_type: parsed
                .get("page_type")
                .and_then(|v| v.as_str())
                .unwrap_or(page_type)
                .to_string(),
            fields,
            created_at: now,
            success_count: 0,
            fail_count: 0,
            version: 1,
        })
    }

    // -----------------------------------------------------------------------
    // Predefined schemas
    // -----------------------------------------------------------------------

    /// Try extracting with built-in predefined schemas (no LLM needed).
    fn extract_with_predefined(
        &self,
        html: &str,
        page_type: &str,
    ) -> Result<Vec<HashMap<String, String>>, ExtractError> {
        let schema = predefined_schema(page_type).ok_or_else(|| {
            ExtractError::NoSchema(format!("no predefined schema for {page_type}"))
        })?;
        self.execute_schema(html, &schema)
    }

    /// Apply an arbitrary [`ExtractionSchema`] — typically one produced by
    /// [`ExtractionSchema::from_v1_json`] — to one HTML document.
    ///
    /// This is the public half of `execute_schema`, exposed so the extraction
    /// path can be driven by a **schema file** from outside this module (the
    /// `schema-first` tier's whole premise) without reimplementing selector
    /// application anywhere else. A second implementation of "apply this field's
    /// selectors" would be a second answer to "which fields did this page
    /// yield", which is exactly how two callers come to disagree about a page.
    ///
    /// Returns one map per extracted item: field name → value. A field that
    /// matched nothing is **absent from the map**, never present as an empty
    /// string — absence is a fact the caller must be able to see (see
    /// `ProvenanceRecord::limitations` and `run_evidence::record_limitations`).
    pub fn extract_with_schema(
        &self,
        html: &str,
        schema: &ExtractionSchema,
    ) -> Result<Vec<HashMap<String, String>>, ExtractError> {
        self.execute_schema(html, schema)
    }

    // -----------------------------------------------------------------------
    // Schema caching
    // -----------------------------------------------------------------------

    /// Find the best schema for a domain (domain-specific > predefined).
    pub fn find_schema(&self, domain: &str) -> Option<ExtractionSchema> {
        // Try all page types for this domain.
        for page_type in &[
            "product_detail",
            "product_listing",
            "article",
            "recipe",
            "job_listing",
            "real_estate",
        ] {
            let key = cache_key(domain, page_type);
            if let Some(schema) = self.schema_cache.get(&key) {
                return Some(schema.clone());
            }
        }
        None
    }

    /// Load all cached schemas from the disk cache directory.
    fn load_cached_schemas(&mut self) {
        let entries = match std::fs::read_dir(&self.cache_dir) {
            Ok(e) => e,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }

            if let Ok(contents) = std::fs::read_to_string(&path) {
                if let Ok(schema) = serde_json::from_str::<ExtractionSchema>(&contents) {
                    let key = cache_key(&schema.domain, &schema.page_type);
                    self.schema_cache.insert(key, schema);
                }
            }
        }
    }

    /// Save a schema to disk.
    fn save_schema(&self, schema: &ExtractionSchema) -> Result<(), ExtractError> {
        let filename = format!(
            "{}_{}_v{}.json",
            sanitize_filename(&schema.domain),
            sanitize_filename(&schema.page_type),
            schema.version
        );
        let path = self.cache_dir.join(&filename);

        let json = serde_json::to_string_pretty(schema)
            .map_err(|e| ExtractError::LlmParseFailed(format!("serialize error: {e}")))?;
        std::fs::write(&path, json)?;

        // Also write a "latest" symlink-style file (just a copy for Windows compat).
        let latest_filename = format!(
            "{}_{}_latest.json",
            sanitize_filename(&schema.domain),
            sanitize_filename(&schema.page_type),
        );
        let latest_path = self.cache_dir.join(&latest_filename);
        let latest_json = serde_json::to_string_pretty(schema)
            .map_err(|e| ExtractError::LlmParseFailed(format!("serialize error: {e}")))?;
        std::fs::write(&latest_path, latest_json)?;

        self.save_contract_snapshot(schema)?;

        // Prune old versions (keep last 3).
        self.prune_old_versions(&schema.domain, &schema.page_type, schema.version);

        Ok(())
    }

    fn save_contract_snapshot(&self, schema: &ExtractionSchema) -> Result<(), ExtractError> {
        let contract = build_contract_snapshot(schema);
        let versioned_filename = format!(
            "{}_{}_contract_v{}.json",
            sanitize_filename(&schema.domain),
            sanitize_filename(&schema.page_type),
            schema.version
        );
        let versioned_path = self.cache_dir.join(versioned_filename);
        let latest_filename = format!(
            "{}_{}_contract_latest.json",
            sanitize_filename(&schema.domain),
            sanitize_filename(&schema.page_type),
        );
        let latest_path = self.cache_dir.join(latest_filename);
        let json = serde_json::to_string_pretty(&contract)
            .map_err(|e| ExtractError::LlmParseFailed(format!("serialize contract error: {e}")))?;
        std::fs::write(&versioned_path, &json)?;
        std::fs::write(&latest_path, json)?;
        Ok(())
    }

    /// Remove schema versions older than `keep_last - 2` to retain 3 total.
    fn prune_old_versions(&self, domain: &str, page_type: &str, current_version: u32) {
        if current_version <= 3 {
            return;
        }
        let cutoff = current_version - 3;
        let prefix = format!(
            "{}_{}_v",
            sanitize_filename(domain),
            sanitize_filename(page_type),
        );

        if let Ok(entries) = std::fs::read_dir(&self.cache_dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if !name.starts_with(&prefix) || !name.ends_with(".json") {
                    continue;
                }
                // Extract version number.
                let version_part = &name[prefix.len()..name.len() - 5]; // strip ".json"
                if let Ok(v) = version_part.parse::<u32>() {
                    if v <= cutoff {
                        let _ = std::fs::remove_file(entry.path());
                    }
                }
            }
        }
    }
}

fn contract_id_for_schema(schema: &ExtractionSchema) -> String {
    format!(
        "{}::{}::v{}",
        schema.domain, schema.page_type, schema.version
    )
}

fn contract_digest(schema: &ExtractionSchema) -> String {
    let selectors: Vec<serde_json::Value> = schema
        .fields
        .iter()
        .map(|field| {
            serde_json::json!({
                "name": field.name,
                "selector": field.selector,
                "attribute": field.attribute,
                "transform": field.transform,
                "required": field.required,
                "fallback_selectors": field.fallback_selectors,
            })
        })
        .collect();
    let canonical = serde_json::json!({
        "domain": schema.domain,
        "page_type": schema.page_type,
        "schema_version": schema.version,
        "fields": selectors,
    });
    let encoded = serde_json::to_vec(&canonical).unwrap_or_default();
    blake3::hash(&encoded).to_hex().to_string()
}

fn build_contract_snapshot(schema: &ExtractionSchema) -> ExtractorContractVersion {
    let required_fields = schema
        .fields
        .iter()
        .filter(|f| f.required)
        .map(|f| f.name.clone())
        .collect::<Vec<_>>();
    let selector_count = schema
        .fields
        .iter()
        .map(|f| 1usize + f.fallback_selectors.len())
        .sum();
    ExtractorContractVersion {
        contract_id: contract_id_for_schema(schema),
        contract_version: EXTRACTOR_CONTRACT_VERSION.to_string(),
        schema_version: schema.version,
        domain: schema.domain.clone(),
        page_type: schema.page_type.clone(),
        required_fields,
        selector_count,
        digest: contract_digest(schema),
        generated_at: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
    }
}

// ---------------------------------------------------------------------------
// tallow.extraction_schema.v1 contract loader (B7 / 3.5)
// ---------------------------------------------------------------------------
//
// The `predefined_schema` presets below are hardcoded Rust structs — the
// "hardcoded product-listing path" B7 names. This loader is the generic
// counterpart: it consumes an arbitrary `tallow.extraction_schema.v1` contract
// document (the format the request-plan runner and `validate_extraction_rows.py`
// already use) so extraction can be driven by a schema FILE rather than a fixed
// page-type list.
//
// Mapping: `selectors[]` sorted by `priority` — the first `css` selector is
// primary, the remaining `css` selectors become `fallback_selectors`
// (non-CSS kinds such as `json_path` are out of scope for this CSS extractor and
// are skipped). `coercion[]` maps to a `TransformFn`, preferring a substantive
// coercion (parse_money / parse_url / …) over a whitespace trim.

/// Raw `tallow.extraction_schema.v1` document (only the fields this loader needs).
#[derive(Debug, Deserialize)]
struct V1Contract {
    #[serde(default)]
    schema_version: String,
    #[serde(default)]
    schema_id: String,
    #[serde(default)]
    entity: String,
    #[serde(default)]
    fields: Vec<V1Field>,
    /// The contract's own quality thresholds. Shipped schemas declare them
    /// (`min_row_confidence`, `max_null_required_fields`,
    /// `quarantine_below_confidence`); absent means "no threshold".
    #[serde(default)]
    quality: V1Quality,
}

/// `quality` block of a v1 contract, as the row gate reads it.
#[derive(Debug, Deserialize, Default)]
struct V1Quality {
    #[serde(default)]
    min_row_confidence: f64,
    #[serde(default)]
    max_null_required_fields: u64,
    #[serde(default)]
    quarantine_below_confidence: f64,
}

#[derive(Debug, Deserialize)]
struct V1Field {
    name: String,
    /// The contract's declared field type (a row cell must carry it). Captured
    /// here rather than re-read elsewhere so this module stays the only parser
    /// of the v1 format.
    #[serde(rename = "type", default)]
    type_name: String,
    #[serde(default)]
    required: bool,
    #[serde(default)]
    selectors: Vec<V1Selector>,
    #[serde(default)]
    coercion: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct V1Selector {
    #[serde(default)]
    kind: String,
    #[serde(default)]
    value: String,
    #[serde(default)]
    attribute: Option<String>,
    #[serde(default)]
    priority: i32,
}

/// The parts of a `tallow.extraction_schema.v1` contract the **row** contract
/// needs and the extractor does not: the contract's own id and each field's
/// declared type.
///
/// Deliberately a sibling of [`ExtractionSchema::from_v1_json`] rather than new
/// fields on `ExtractionSchema`: selector application has no use for either
/// value, and widening that struct would churn every construction site (the
/// predefined-schema builders included). Both readers share `V1Contract`, so the
/// v1 format still has exactly one parser — a second one would be a second
/// answer to "what does this contract say".
#[derive(Debug, Clone)]
pub struct SchemaMetadata {
    /// `schema_id` from the contract — the row's `extraction_schema_id`.
    pub schema_id: String,
    /// `entity` from the contract (`""` when absent).
    pub entity: String,
    /// Field name → declared type, for the row's `field_cell.type`.
    pub field_types: HashMap<String, String>,
    /// A row below this confidence is quarantined (`quality.min_row_confidence`).
    pub min_row_confidence: f64,
    /// More null required fields than this quarantines the row
    /// (`quality.max_null_required_fields`).
    pub max_null_required_fields: u64,
    /// `quality.quarantine_below_confidence`. Carried for completeness: the
    /// repository's row gate does NOT read it, so it must not drive the status
    /// decision here without that gate being changed to match.
    pub quarantine_below_confidence: f64,
}

/// Read the row-facing metadata out of a `tallow.extraction_schema.v1` document.
///
/// Refuses a document that is not a v1 contract, with the same message the
/// loader gives, so a caller cannot get metadata for a contract the loader would
/// reject.
pub fn v1_schema_metadata(json: &str) -> Result<SchemaMetadata, String> {
    let c: V1Contract = serde_json::from_str(json)
        .map_err(|e| format!("invalid tallow.extraction_schema.v1 document: {e}"))?;
    if c.schema_version != "tallow.extraction_schema.v1" {
        return Err(format!(
            "unsupported schema_version {:?} (expected \"tallow.extraction_schema.v1\")",
            c.schema_version
        ));
    }
    let field_types = c
        .fields
        .iter()
        .map(|f| (f.name.clone(), f.type_name.clone()))
        .collect();
    Ok(SchemaMetadata {
        schema_id: c.schema_id,
        entity: c.entity,
        field_types,
        min_row_confidence: c.quality.min_row_confidence,
        max_null_required_fields: c.quality.max_null_required_fields,
        quarantine_below_confidence: c.quality.quarantine_below_confidence,
    })
}

/// Map a `tallow.extraction_schema.v1` coercion name to a [`TransformFn`].
fn coercion_to_transform(coercion: &str) -> Option<TransformFn> {
    match coercion {
        "trim" | "normalize_whitespace" => Some(TransformFn::TrimWhitespace),
        "parse_money" => Some(TransformFn::ParsePrice),
        "parse_int" => Some(TransformFn::ParseInt),
        "parse_float" => Some(TransformFn::ParseFloat),
        "parse_url" => Some(TransformFn::ExtractUrl),
        "strip_html" => Some(TransformFn::StripHtml),
        _ => None,
    }
}

impl ExtractionSchema {
    /// Load an arbitrary `tallow.extraction_schema.v1` contract document.
    ///
    /// `domain` keys the schema cache (the v1 contract carries no domain).
    /// Returns `Err` naming the offending field when the document is not a v1
    /// contract or a field has no CSS selector.
    pub fn from_v1_json(json: &str, domain: &str) -> Result<Self, String> {
        let c: V1Contract = serde_json::from_str(json)
            .map_err(|e| format!("invalid tallow.extraction_schema.v1 document: {e}"))?;
        if c.schema_version != "tallow.extraction_schema.v1" {
            return Err(format!(
                "unsupported schema_version {:?} (expected \"tallow.extraction_schema.v1\")",
                c.schema_version
            ));
        }

        let mut fields = Vec::with_capacity(c.fields.len());
        for f in c.fields {
            let mut sels = f.selectors;
            sels.sort_by_key(|s| s.priority);
            let primary = sels
                .iter()
                .find(|s| s.kind == "css")
                .ok_or_else(|| format!("field {:?}: no css selector", f.name))?;

            let fallback_selectors = sels
                .iter()
                .filter(|s| s.kind == "css" && s.value != primary.value)
                .map(|s| s.value.clone())
                .collect();

            let mapped: Vec<TransformFn> = f
                .coercion
                .iter()
                .filter_map(|c| coercion_to_transform(c))
                .collect();
            let transform = mapped
                .iter()
                .position(|t| !matches!(t, TransformFn::TrimWhitespace))
                .map(|i| mapped[i].clone())
                .or_else(|| mapped.first().cloned());

            fields.push(FieldExtractor {
                name: f.name,
                selector: primary.value.clone(),
                attribute: primary.attribute.clone(),
                transform,
                required: f.required,
                fallback_selectors,
            });
        }

        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        Ok(ExtractionSchema {
            domain: domain.to_string(),
            page_type: if c.entity.is_empty() {
                c.schema_id
            } else {
                c.entity
            },
            fields,
            created_at: now,
            success_count: 0,
            fail_count: 0,
            version: 1,
        })
    }
}

// ---------------------------------------------------------------------------
// Predefined schemas — no LLM required
// ---------------------------------------------------------------------------

/// Return a predefined schema for a common page type, if available.
pub fn predefined_schema(page_type: &str) -> Option<ExtractionSchema> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    match page_type {
        "product_detail" => Some(predefined_product_detail(now)),
        "product_listing" => Some(predefined_product_listing(now)),
        "article" => Some(predefined_article(now)),
        "recipe" => Some(predefined_recipe(now)),
        "job_listing" => Some(predefined_job_listing(now)),
        "real_estate" => Some(predefined_real_estate(now)),
        _ => None,
    }
}

fn predefined_product_detail(now: i64) -> ExtractionSchema {
    ExtractionSchema {
        domain: "predefined".into(),
        page_type: "product_detail".into(),
        created_at: now,
        success_count: 0,
        fail_count: 0,
        version: 1,
        fields: vec![
            FieldExtractor {
                name: "title".into(),
                selector: "h1".into(),
                attribute: None,
                transform: Some(TransformFn::TrimWhitespace),
                required: true,
                fallback_selectors: vec![
                    "[data-testid=\"product-title\"]".into(),
                    ".product-title".into(),
                    ".product-name".into(),
                    "#productTitle".into(),
                    "[itemprop=\"name\"]".into(),
                ],
            },
            FieldExtractor {
                name: "price".into(),
                selector: "[itemprop=\"price\"]".into(),
                attribute: Some("content".into()),
                transform: Some(TransformFn::ParsePrice),
                required: true,
                fallback_selectors: vec![
                    ".price".into(),
                    ".product-price".into(),
                    "[data-price]".into(),
                    ".offer-price".into(),
                    ".sale-price".into(),
                    ".price-current".into(),
                ],
            },
            FieldExtractor {
                name: "currency".into(),
                selector: "[itemprop=\"priceCurrency\"]".into(),
                attribute: Some("content".into()),
                transform: None,
                required: false,
                fallback_selectors: vec![],
            },
            FieldExtractor {
                name: "brand".into(),
                selector: "[itemprop=\"brand\"]".into(),
                attribute: None,
                transform: Some(TransformFn::TrimWhitespace),
                required: false,
                fallback_selectors: vec![
                    ".product-brand".into(),
                    ".brand-name".into(),
                    "[data-brand]".into(),
                ],
            },
            FieldExtractor {
                name: "image_url".into(),
                selector: "[itemprop=\"image\"]".into(),
                attribute: Some("src".into()),
                transform: None,
                required: false,
                fallback_selectors: vec![
                    ".product-image img".into(),
                    "#main-image".into(),
                    ".gallery img:first-child".into(),
                    "img.product-img".into(),
                ],
            },
            FieldExtractor {
                name: "description".into(),
                selector: "[itemprop=\"description\"]".into(),
                attribute: None,
                transform: Some(TransformFn::StripHtml),
                required: false,
                fallback_selectors: vec![
                    ".product-description".into(),
                    "#product-description".into(),
                    ".description".into(),
                ],
            },
            FieldExtractor {
                name: "sku".into(),
                selector: "[itemprop=\"sku\"]".into(),
                attribute: Some("content".into()),
                transform: None,
                required: false,
                fallback_selectors: vec!["[data-sku]".into(), ".product-sku".into()],
            },
            FieldExtractor {
                name: "availability".into(),
                selector: "[itemprop=\"availability\"]".into(),
                attribute: Some("content".into()),
                transform: None,
                required: false,
                fallback_selectors: vec![
                    ".availability".into(),
                    ".stock-status".into(),
                    "[data-availability]".into(),
                ],
            },
            FieldExtractor {
                name: "rating".into(),
                selector: "[itemprop=\"ratingValue\"]".into(),
                attribute: Some("content".into()),
                transform: Some(TransformFn::ParseFloat),
                required: false,
                fallback_selectors: vec![".rating-value".into(), ".star-rating".into()],
            },
            FieldExtractor {
                name: "review_count".into(),
                selector: "[itemprop=\"reviewCount\"]".into(),
                attribute: Some("content".into()),
                transform: Some(TransformFn::ParseInt),
                required: false,
                fallback_selectors: vec![".review-count".into(), ".num-reviews".into()],
            },
        ],
    }
}

fn predefined_product_listing(now: i64) -> ExtractionSchema {
    ExtractionSchema {
        domain: "predefined".into(),
        page_type: "product_listing".into(),
        created_at: now,
        success_count: 0,
        fail_count: 0,
        version: 1,
        fields: vec![
            FieldExtractor {
                name: "title".into(),
                selector: ".product-card h2, .product-card h3, .product-item h2".into(),
                attribute: None,
                transform: Some(TransformFn::TrimWhitespace),
                required: true,
                fallback_selectors: vec![
                    "[data-testid=\"product-name\"]".into(),
                    ".product-title a".into(),
                    ".item-title".into(),
                ],
            },
            FieldExtractor {
                name: "price".into(),
                selector: ".product-card .price, .product-item .price".into(),
                attribute: None,
                transform: Some(TransformFn::ParsePrice),
                required: false,
                fallback_selectors: vec![".product-price".into(), "[data-price]".into()],
            },
            FieldExtractor {
                name: "image_url".into(),
                selector: ".product-card img, .product-item img".into(),
                attribute: Some("src".into()),
                transform: None,
                required: false,
                fallback_selectors: vec![".product-image img".into(), ".item-image img".into()],
            },
            FieldExtractor {
                name: "link".into(),
                selector: ".product-card a, .product-item a".into(),
                attribute: Some("href".into()),
                transform: None,
                required: false,
                fallback_selectors: vec![".product-title a".into(), ".product-link".into()],
            },
        ],
    }
}

fn predefined_article(now: i64) -> ExtractionSchema {
    ExtractionSchema {
        domain: "predefined".into(),
        page_type: "article".into(),
        created_at: now,
        success_count: 0,
        fail_count: 0,
        version: 1,
        fields: vec![
            FieldExtractor {
                name: "title".into(),
                selector: "h1".into(),
                attribute: None,
                transform: Some(TransformFn::TrimWhitespace),
                required: true,
                fallback_selectors: vec![
                    ".article-title".into(),
                    ".post-title".into(),
                    "[itemprop=\"headline\"]".into(),
                ],
            },
            FieldExtractor {
                name: "author".into(),
                selector: "[itemprop=\"author\"]".into(),
                attribute: None,
                transform: Some(TransformFn::TrimWhitespace),
                required: false,
                fallback_selectors: vec![
                    ".author-name".into(),
                    ".byline".into(),
                    "[rel=\"author\"]".into(),
                ],
            },
            FieldExtractor {
                name: "date".into(),
                selector: "time[datetime]".into(),
                attribute: Some("datetime".into()),
                transform: None,
                required: false,
                fallback_selectors: vec![
                    "[itemprop=\"datePublished\"]".into(),
                    ".publish-date".into(),
                    ".article-date".into(),
                ],
            },
            FieldExtractor {
                name: "body".into(),
                selector: "article".into(),
                attribute: None,
                transform: Some(TransformFn::StripHtml),
                required: false,
                fallback_selectors: vec![
                    ".article-body".into(),
                    ".post-content".into(),
                    ".entry-content".into(),
                    "[itemprop=\"articleBody\"]".into(),
                    "#article-body".into(),
                ],
            },
            FieldExtractor {
                name: "image_url".into(),
                selector: "article img, .article-hero img".into(),
                attribute: Some("src".into()),
                transform: None,
                required: false,
                fallback_selectors: vec![
                    "[itemprop=\"image\"]".into(),
                    ".featured-image img".into(),
                ],
            },
        ],
    }
}

fn predefined_recipe(now: i64) -> ExtractionSchema {
    ExtractionSchema {
        domain: "predefined".into(),
        page_type: "recipe".into(),
        created_at: now,
        success_count: 0,
        fail_count: 0,
        version: 1,
        fields: vec![
            FieldExtractor {
                name: "name".into(),
                selector: "h1".into(),
                attribute: None,
                transform: Some(TransformFn::TrimWhitespace),
                required: true,
                fallback_selectors: vec![
                    "[itemprop=\"name\"]".into(),
                    ".recipe-title".into(),
                    ".recipe-name".into(),
                ],
            },
            FieldExtractor {
                name: "prep_time".into(),
                selector: "[itemprop=\"prepTime\"]".into(),
                attribute: Some("content".into()),
                transform: None,
                required: false,
                fallback_selectors: vec![".prep-time".into(), ".recipe-prep-time".into()],
            },
            FieldExtractor {
                name: "cook_time".into(),
                selector: "[itemprop=\"cookTime\"]".into(),
                attribute: Some("content".into()),
                transform: None,
                required: false,
                fallback_selectors: vec![".cook-time".into(), ".recipe-cook-time".into()],
            },
            FieldExtractor {
                name: "servings".into(),
                selector: "[itemprop=\"recipeYield\"]".into(),
                attribute: None,
                transform: Some(TransformFn::TrimWhitespace),
                required: false,
                fallback_selectors: vec![
                    ".servings".into(),
                    ".recipe-servings".into(),
                    ".yield".into(),
                ],
            },
            FieldExtractor {
                name: "image_url".into(),
                selector: ".recipe-image img, [itemprop=\"image\"]".into(),
                attribute: Some("src".into()),
                transform: None,
                required: false,
                fallback_selectors: vec![".hero-image img".into()],
            },
        ],
    }
}

fn predefined_job_listing(now: i64) -> ExtractionSchema {
    ExtractionSchema {
        domain: "predefined".into(),
        page_type: "job_listing".into(),
        created_at: now,
        success_count: 0,
        fail_count: 0,
        version: 1,
        fields: vec![
            FieldExtractor {
                name: "title".into(),
                selector: "h1".into(),
                attribute: None,
                transform: Some(TransformFn::TrimWhitespace),
                required: true,
                fallback_selectors: vec![
                    "[itemprop=\"title\"]".into(),
                    ".job-title".into(),
                    ".posting-title".into(),
                ],
            },
            FieldExtractor {
                name: "company".into(),
                selector: "[itemprop=\"hiringOrganization\"]".into(),
                attribute: None,
                transform: Some(TransformFn::TrimWhitespace),
                required: false,
                fallback_selectors: vec![
                    ".company-name".into(),
                    ".employer".into(),
                    "[data-company]".into(),
                ],
            },
            FieldExtractor {
                name: "location".into(),
                selector: "[itemprop=\"jobLocation\"]".into(),
                attribute: None,
                transform: Some(TransformFn::TrimWhitespace),
                required: false,
                fallback_selectors: vec![".job-location".into(), ".location".into()],
            },
            FieldExtractor {
                name: "salary".into(),
                selector: "[itemprop=\"baseSalary\"]".into(),
                attribute: None,
                transform: Some(TransformFn::TrimWhitespace),
                required: false,
                fallback_selectors: vec![
                    ".salary".into(),
                    ".compensation".into(),
                    ".pay-range".into(),
                ],
            },
            FieldExtractor {
                name: "description".into(),
                selector: "[itemprop=\"description\"]".into(),
                attribute: None,
                transform: Some(TransformFn::StripHtml),
                required: false,
                fallback_selectors: vec![
                    ".job-description".into(),
                    "#job-description".into(),
                    ".description".into(),
                ],
            },
            FieldExtractor {
                name: "apply_url".into(),
                selector: "a.apply-button, a.apply-link, [data-apply-url]".into(),
                attribute: Some("href".into()),
                transform: None,
                required: false,
                fallback_selectors: vec![".apply a".into(), "#apply-button".into()],
            },
        ],
    }
}

fn predefined_real_estate(now: i64) -> ExtractionSchema {
    ExtractionSchema {
        domain: "predefined".into(),
        page_type: "real_estate".into(),
        created_at: now,
        success_count: 0,
        fail_count: 0,
        version: 1,
        fields: vec![
            FieldExtractor {
                name: "address".into(),
                selector: "[itemprop=\"address\"]".into(),
                attribute: None,
                transform: Some(TransformFn::TrimWhitespace),
                required: true,
                fallback_selectors: vec![
                    ".property-address".into(),
                    ".listing-address".into(),
                    "h1".into(),
                ],
            },
            FieldExtractor {
                name: "price".into(),
                selector: "[itemprop=\"price\"]".into(),
                attribute: Some("content".into()),
                transform: Some(TransformFn::ParsePrice),
                required: true,
                fallback_selectors: vec![
                    ".listing-price".into(),
                    ".property-price".into(),
                    ".price".into(),
                ],
            },
            FieldExtractor {
                name: "bedrooms".into(),
                selector: "[data-testid=\"bed-count\"], .beds".into(),
                attribute: None,
                transform: Some(TransformFn::ParseInt),
                required: false,
                fallback_selectors: vec![".bedrooms".into(), "[itemprop=\"numberOfRooms\"]".into()],
            },
            FieldExtractor {
                name: "bathrooms".into(),
                selector: "[data-testid=\"bath-count\"], .baths".into(),
                attribute: None,
                transform: Some(TransformFn::ParseFloat),
                required: false,
                fallback_selectors: vec![".bathrooms".into()],
            },
            FieldExtractor {
                name: "sqft".into(),
                selector: "[data-testid=\"sqft\"], .sqft".into(),
                attribute: None,
                transform: Some(TransformFn::ParseInt),
                required: false,
                fallback_selectors: vec![
                    ".property-sqft".into(),
                    ".square-feet".into(),
                    "[itemprop=\"floorSize\"]".into(),
                ],
            },
            FieldExtractor {
                name: "image_url".into(),
                selector: ".listing-image img, .property-image img".into(),
                attribute: Some("src".into()),
                transform: None,
                required: false,
                fallback_selectors: vec![
                    ".gallery img:first-child".into(),
                    "[itemprop=\"image\"]".into(),
                ],
            },
            FieldExtractor {
                name: "description".into(),
                selector: ".listing-description, .property-description".into(),
                attribute: None,
                transform: Some(TransformFn::StripHtml),
                required: false,
                fallback_selectors: vec![
                    "[itemprop=\"description\"]".into(),
                    "#description".into(),
                ],
            },
        ],
    }
}

// ---------------------------------------------------------------------------
// Page type detection
// ---------------------------------------------------------------------------

/// Heuristic page-type detection from HTML content.
fn detect_page_type(html: &str) -> String {
    let lower = html.to_lowercase();

    // Check JSON-LD first — most reliable signal.
    if let Some(ld_type) = detect_jsonld_type(&lower) {
        return ld_type;
    }

    // Schema.org microdata.
    if lower.contains("itemtype") {
        if lower.contains("schema.org/product") {
            // Heuristic: if there are multiple product containers, it's a listing.
            let product_count = lower.matches("schema.org/product").count();
            return if product_count > 2 {
                "product_listing".into()
            } else {
                "product_detail".into()
            };
        }
        if lower.contains("schema.org/recipe") {
            return "recipe".into();
        }
        if lower.contains("schema.org/article")
            || lower.contains("schema.org/newsarticle")
            || lower.contains("schema.org/blogposting")
        {
            return "article".into();
        }
        if lower.contains("schema.org/jobposting") {
            return "job_listing".into();
        }
        if lower.contains("schema.org/realestate")
            || lower.contains("schema.org/residence")
            || lower.contains("schema.org/house")
            || lower.contains("schema.org/apartment")
        {
            return "real_estate".into();
        }
    }

    // CSS class heuristics.
    let product_signals = [
        "add-to-cart",
        "addtocart",
        "add_to_cart",
        "buy-now",
        "product-price",
        "product-detail",
        "product-info",
    ];
    let listing_signals = [
        "product-list",
        "product-grid",
        "search-results",
        "category-products",
        "product-card",
    ];
    let recipe_signals = [
        "recipe-ingredient",
        "recipe-instruction",
        "recipe-card",
        "cook-time",
        "prep-time",
    ];
    let article_signals = [
        "article-body",
        "post-content",
        "entry-content",
        "article-content",
        "byline",
    ];
    let job_signals = [
        "job-listing",
        "job-posting",
        "apply-button",
        "job-description",
        "career",
    ];

    let count =
        |signals: &[&str]| -> usize { signals.iter().filter(|s| lower.contains(*s)).count() };

    let scores = [
        ("product_detail", count(&product_signals)),
        ("product_listing", count(&listing_signals)),
        ("recipe", count(&recipe_signals)),
        ("article", count(&article_signals)),
        ("job_listing", count(&job_signals)),
    ];

    scores
        .iter()
        .max_by_key(|(_t, s)| *s)
        .filter(|(_t, s)| *s > 0)
        .map(|(t, _s)| t.to_string())
        .unwrap_or_else(|| "unknown".into())
}

/// Detect page type from JSON-LD blocks.
fn detect_jsonld_type(html_lower: &str) -> Option<String> {
    // Quick check for JSON-LD presence.
    if !html_lower.contains("application/ld+json") {
        return None;
    }

    let type_map = [
        ("\"recipe\"", "recipe"),
        ("\"product\"", "product_detail"),
        ("\"newsarticle\"", "article"),
        ("\"article\"", "article"),
        ("\"blogposting\"", "article"),
        ("\"jobposting\"", "job_listing"),
        ("\"realestateListing\"", "real_estate"),
    ];

    for (pattern, page_type) in &type_map {
        if html_lower.contains(pattern) {
            return Some(page_type.to_string());
        }
    }

    None
}

// ---------------------------------------------------------------------------
// Utility functions
// ---------------------------------------------------------------------------

/// Build a cache key from domain + page type.
fn cache_key(domain: &str, page_type: &str) -> String {
    format!("{domain}::{page_type}")
}

/// Extract the domain from a URL string.
fn extract_domain(url: &str) -> String {
    url.split("://")
        .nth(1)
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
        .split(':')
        .next()
        .unwrap_or(url)
        .to_lowercase()
}

/// Sanitize a string for use as a filename.
fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Parse a transform name string from LLM output into a `TransformFn`.
fn parse_transform_name(name: &str) -> Option<TransformFn> {
    match name {
        "trim_whitespace" | "trim" => Some(TransformFn::TrimWhitespace),
        "parse_price" | "price" => Some(TransformFn::ParsePrice),
        "parse_int" | "int" | "integer" => Some(TransformFn::ParseInt),
        "parse_float" | "float" => Some(TransformFn::ParseFloat),
        "extract_url" | "url" => Some(TransformFn::ExtractUrl),
        "strip_html" | "html" => Some(TransformFn::StripHtml),
        "" | "null" | "none" => None,
        other => {
            // Treat anything else as a regex pattern.
            Some(TransformFn::RegexExtract(other.to_string()))
        }
    }
}

/// Extract the first JSON object from a string (handles markdown code blocks).
fn extract_json_block(text: &str) -> Option<String> {
    // Try to find JSON inside ```json ... ``` markers.
    if let Some(start) = text.find("```json") {
        let json_start = start + 7;
        if let Some(end) = text[json_start..].find("```") {
            return Some(text[json_start..json_start + end].trim().to_string());
        }
    }
    // Try to find JSON inside ``` ... ``` markers (no language tag).
    if let Some(start) = text.find("```") {
        let json_start = start + 3;
        if let Some(end) = text[json_start..].find("```") {
            let candidate = text[json_start..json_start + end].trim();
            if candidate.starts_with('{') {
                return Some(candidate.to_string());
            }
        }
    }
    // Try to find a raw JSON object.
    if let Some(start) = text.find('{') {
        // Find the matching closing brace by counting depth.
        let bytes = text[start..].as_bytes();
        let mut depth = 0;
        for (i, &b) in bytes.iter().enumerate() {
            match b {
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        return Some(text[start..start + i + 1].to_string());
                    }
                }
                _ => {}
            }
        }
    }
    None
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Engine helpers (pure, so they are testable without a network)
// ---------------------------------------------------------------------------

/// Environment variable holding the engine credential.
///
/// Read at call time and never stored on the extractor, so a credential cannot
/// reach a `Debug` rendering, a disk cache, or a receipt. It is never an argv
/// value and never a `.tl` literal.
pub const LLM_API_KEY_ENV: &str = "TALLOW_LLM_API_KEY";

/// Environment variable selecting the engine (`ollama` | `openai`).
pub const LLM_ENGINE_ENV: &str = "TALLOW_LLM_ENGINE";
/// Environment variable holding the engine's base URL. **Unset means no engine
/// is configured**, which is what keeps the tier off.
pub const LLM_BASE_URL_ENV: &str = "TALLOW_LLM_BASE_URL";
/// Environment variable overriding the model.
pub const LLM_MODEL_ENV: &str = "TALLOW_LLM_MODEL";

/// The engine the operator decided on (2026-10-14): the fleet's current model,
/// not a local Ollama.
pub const DEFAULT_CLOUD_MODEL: &str = "deepseek/deepseek-flash";

/// A resolved engine configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineConfig {
    pub engine: Engine,
    pub base_url: String,
    pub model: String,
}

/// Resolve the engine configuration from the environment.
///
/// Refusing here is the point. The tier used to be ON by default while nothing
/// answered it, so "not attempted" was reported as "attempted, failed". With no
/// base URL there is no engine, so the honest answer is a reason — not a default
/// pointing at a local service the operator has decided not to run.
pub fn resolve_engine_config(
    getenv: &dyn Fn(&str) -> Option<String>,
) -> Result<EngineConfig, String> {
    let base_url = getenv(LLM_BASE_URL_ENV)
        .map(|s| s.trim().trim_end_matches('/').to_string())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            format!(
                "{LLM_BASE_URL_ENV} is not set: no engine is configured, so the schema-first \
                 tier stays off instead of on-with-nothing-answering"
            )
        })?;

    let engine = match getenv(LLM_ENGINE_ENV) {
        Some(name) => Engine::parse(&name).ok_or_else(|| {
            format!("{LLM_ENGINE_ENV}={name:?} is not a known engine (ollama|openai)")
        })?,
        None => Engine::OpenAiCompatible,
    };

    let model = getenv(LLM_MODEL_ENV)
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| match engine {
            Engine::OpenAiCompatible => DEFAULT_CLOUD_MODEL.to_string(),
            Engine::Ollama => "llama3.2".to_string(),
        });

    Ok(EngineConfig {
        engine,
        base_url,
        model,
    })
}

/// Name the tier's credential is stored under in the vault
/// (`crate::vault::credential`).
pub const LLM_VAULT_ENTRY: &str = "tallow-llm-api-key";

/// The tier's credential as the custody vault holds it.
///
/// `None` covers every failure — absent, unreadable, wrong key — because the
/// caller's next step is the same in each case: refuse. The distinction matters
/// at the refusal message, not here, and a locked vault must never read as "no
/// credential configured".
///
/// Note: `Credential::password` is `Zeroizing<String>`; returning a plain
/// `String` drops that guarantee for the copy that lives for the duration of the
/// request. That copy is unavoidable when the value becomes an HTTP header, and
/// it is stated rather than implied.
pub fn vault_api_key(name: &str) -> Option<String> {
    crate::vault::credential::get(name)
        .ok()
        .map(|c| c.password.to_string())
}

/// Resolve the credential, refusing rather than egressing unauthenticated.
///
/// Two sources, in order: the environment (an explicit, per-run override), then
/// the vault (custody). Neither is argv, and neither is a `.tl` literal.
pub fn resolve_api_key(
    getenv: &dyn Fn(&str) -> Option<String>,
    from_vault: &dyn Fn(&str) -> Option<String>,
) -> Result<String, ExtractError> {
    if let Some(k) = getenv(LLM_API_KEY_ENV).filter(|k| !k.trim().is_empty()) {
        return Ok(k.trim().to_string());
    }
    if let Some(k) = from_vault(LLM_VAULT_ENTRY).filter(|k| !k.trim().is_empty()) {
        return Ok(k.trim().to_string());
    }
    Err(ExtractError::EngineMisconfigured(format!(
        "no credential: {LLM_API_KEY_ENV} is unset and the vault holds no {LLM_VAULT_ENTRY} \
         entry — refusing to call an OpenAI-compatible endpoint without a credential"
    )))
}

/// The real lookups: environment + vault custody.
pub fn resolve_api_key_live() -> Result<String, ExtractError> {
    resolve_api_key(&|k| std::env::var(k).ok(), &|n| vault_api_key(n))
}

/// The tier's state, measured rather than inferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierState {
    pub enabled: bool,
    pub engine: &'static str,
    pub engine_url: String,
    pub model: String,
    pub credential_present: bool,
    pub reachable: bool,
    /// Whether the content may be sent to this engine at all. False for a remote
    /// engine with no authorising policy, which is what makes the gate
    /// fail-closed rather than advisory.
    pub transfer_allowed: bool,
    /// Model calls made so far, and the cap — so "how much did this run spend"
    /// is a measurement, not an estimate.
    pub calls_made: u64,
    pub max_calls: u64,
    pub reason: String,
}

impl TierState {
    /// The run-evidence payload: one record per run, so a reader can tell
    /// "enabled" from "enabled and working".
    pub fn to_evidence(&self) -> serde_json::Value {
        serde_json::json!({
            "enabled": self.enabled,
            "engine": self.engine,
            "engine_url": self.engine_url,
            "model": self.model,
            "credential_present": self.credential_present,
            "reachable": self.reachable,
            "transfer_allowed": self.transfer_allowed,
            "calls_made": self.calls_made,
            "max_calls": self.max_calls,
            "reason": self.reason,
        })
    }
}

/// A per-run cap on what the tier may spend.
///
/// **Fail-closed:** past the cap the tier REFUSES rather than running. A budget
/// that degrades into "kept going" is not a budget.
///
/// Note: the P1.T6 step says to match `budget.rs`. There is no `budget.rs` in
/// this tree (`rg --files src | rg budget` → nothing), so there is nothing to
/// match; this is the equivalent shape, and the difference is recorded rather
/// than glossed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LlmBudget {
    /// Maximum model calls for one run.
    pub max_calls: u64,
    /// Maximum characters in a single prompt.
    pub max_prompt_chars: usize,
    /// Where the numbers came from.
    pub source: String,
}

/// Default call cap when nothing is declared.
pub const DEFAULT_MAX_CALLS: u64 = 16;
/// Default per-prompt character cap.
pub const DEFAULT_MAX_PROMPT_CHARS: usize = 400_000;

impl LlmBudget {
    pub fn from_env(getenv: &dyn Fn(&str) -> Option<String>) -> Self {
        let parse_num = |key: &str| -> Option<u64> {
            getenv(key)
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .and_then(|s| s.parse::<u64>().ok())
        };
        let declared = parse_num("TALLOW_LLM_MAX_CALLS").is_some()
            || parse_num("TALLOW_LLM_MAX_PROMPT_CHARS").is_some();
        Self {
            max_calls: parse_num("TALLOW_LLM_MAX_CALLS").unwrap_or(DEFAULT_MAX_CALLS),
            max_prompt_chars: parse_num("TALLOW_LLM_MAX_PROMPT_CHARS")
                .map(|n| n as usize)
                .unwrap_or(DEFAULT_MAX_PROMPT_CHARS),
            source: if declared {
                "environment".to_string()
            } else {
                "defaults".to_string()
            },
        }
    }

    /// May one more call be made, given `made` so far?
    pub fn check_calls(&self, made: u64) -> Result<(), String> {
        if made >= self.max_calls {
            return Err(format!(
                "budget exhausted: {made} of {} model calls used ({}) — refusing rather than \
                 exceeding the cap",
                self.max_calls, self.source
            ));
        }
        Ok(())
    }

    /// May a prompt of this size be sent?
    pub fn check_prompt(&self, chars: usize) -> Result<(), String> {
        if chars > self.max_prompt_chars {
            return Err(format!(
                "prompt is {chars} chars, over the {} cap ({}) — refusing rather than sending \
                 an unbounded payload",
                self.max_prompt_chars, self.source
            ));
        }
        Ok(())
    }
}

/// The body an OpenAI-compatible chat endpoint expects.
pub fn openai_request_body(model: &str, prompt: &str) -> serde_json::Value {
    serde_json::json!({
        "model": model,
        "messages": [{ "role": "user", "content": prompt }],
        "temperature": 0.1,
        "max_tokens": 4096,
        "stream": false
    })
}

/// Pull the assistant text out of an OpenAI-compatible chat response.
pub fn parse_openai_response(json: &serde_json::Value) -> Result<String, ExtractError> {
    json.get("choices")
        .and_then(|c| c.as_array())
        .and_then(|a| a.first())
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|t| t.as_str())
        .map(|s| s.to_string())
        .ok_or_else(|| {
            ExtractError::LlmParseFailed("response had no choices[0].message.content".to_string())
        })
}

#[cfg(test)]
mod engine_tests {
    use super::*;

    #[test]
    fn the_engine_parses_the_names_an_operator_would_use() {
        assert_eq!(Engine::parse("ollama"), Some(Engine::Ollama));
        assert_eq!(Engine::parse(""), Some(Engine::Ollama));
        assert_eq!(
            Engine::parse(" openai-compatible "),
            Some(Engine::OpenAiCompatible)
        );
        assert_eq!(Engine::parse("openai"), Some(Engine::OpenAiCompatible));
        assert_eq!(
            Engine::parse("gemini"),
            None,
            "an unknown engine is refused, not silently defaulted"
        );
        assert_eq!(
            Engine::default(),
            Engine::Ollama,
            "the default must not change silently out from under existing callers"
        );
    }

    #[test]
    fn the_openai_body_is_a_chat_request_and_not_an_ollama_one() {
        let body = openai_request_body("deepseek/deepseek-flash", "extract this");
        assert_eq!(body["model"], "deepseek/deepseek-flash");
        assert_eq!(body["stream"], false);
        assert_eq!(body["messages"][0]["role"], "user");
        assert_eq!(body["messages"][0]["content"], "extract this");
        // Ollama's shape is `prompt` + `options`; neither may leak through.
        assert!(body.get("options").is_none(), "{body}");
        assert!(body.get("prompt").is_none(), "{body}");
    }

    #[test]
    fn the_response_is_parsed_where_the_text_actually_lives() {
        let chat = serde_json::json!({
            "choices": [{ "message": { "role": "assistant", "content": "hello" } }]
        });
        assert_eq!(parse_openai_response(&chat).unwrap(), "hello");

        // An Ollama-shaped response must not be mistaken for a chat response:
        // reading `response` here would silently succeed against the wrong API.
        let ollama = serde_json::json!({ "response": "hello" });
        assert!(matches!(
            parse_openai_response(&ollama),
            Err(ExtractError::LlmParseFailed(_))
        ));
    }

    #[test]
    fn a_missing_credential_is_refused_rather_than_sent_unauthenticated() {
        let absent = |_: &str| None;
        let blank = |_: &str| Some("   ".to_string());
        let present = |_: &str| Some("k".to_string());
        let no_vault = |_: &str| None;

        assert!(matches!(
            resolve_api_key(&absent, &no_vault),
            Err(ExtractError::EngineMisconfigured(_))
        ));
        assert!(matches!(
            resolve_api_key(&blank, &no_vault),
            Err(ExtractError::EngineMisconfigured(_))
        ));
        assert_eq!(resolve_api_key(&present, &no_vault).unwrap(), "k");
    }

    #[test]
    fn the_vault_is_consulted_when_the_environment_is_empty() {
        let no_env = |_: &str| None;
        let vault = |name: &str| (name == LLM_VAULT_ENTRY).then(|| "from-vault".to_string());
        assert_eq!(resolve_api_key(&no_env, &vault).unwrap(), "from-vault");

        // A blank vault value is not a credential either.
        let blank_vault = |_: &str| Some("  ".to_string());
        assert!(matches!(
            resolve_api_key(&no_env, &blank_vault),
            Err(ExtractError::EngineMisconfigured(_))
        ));
    }

    #[test]
    fn the_environment_wins_over_the_vault() {
        let env = |_: &str| Some("from-env".to_string());
        let vault = |_: &str| Some("from-vault".to_string());
        assert_eq!(resolve_api_key(&env, &vault).unwrap(), "from-env");
    }

    #[test]
    fn the_refusal_names_both_sources_it_looked_at() {
        let none = |_: &str| None;
        match resolve_api_key(&none, &none) {
            Err(ExtractError::EngineMisconfigured(reason)) => {
                assert!(reason.contains(LLM_API_KEY_ENV), "{reason}");
                assert!(reason.contains(LLM_VAULT_ENTRY), "{reason}");
            }
            other => panic!("expected a refusal, got {other:?}"),
        }
    }

    #[test]
    fn an_unconfigured_tier_is_off_with_a_reason_naming_the_variable() {
        let none = |_: &str| None;
        match resolve_engine_config(&none) {
            Err(reason) => assert!(reason.contains(LLM_BASE_URL_ENV), "{reason}"),
            Ok(cfg) => panic!("no base URL must not resolve to a usable engine: {cfg:?}"),
        }
    }

    #[test]
    fn a_configured_tier_defaults_to_the_decided_model() {
        let env = |k: &str| match k {
            "TALLOW_LLM_BASE_URL" => Some("https://api.example.invalid/v1/".to_string()),
            _ => None,
        };
        let cfg = resolve_engine_config(&env).expect("a base URL configures the tier");
        assert_eq!(
            cfg.engine,
            Engine::OpenAiCompatible,
            "the cloud engine is the active one"
        );
        assert_eq!(cfg.model, DEFAULT_CLOUD_MODEL);
        assert_eq!(
            cfg.base_url, "https://api.example.invalid/v1",
            "trailing slash trimmed"
        );
    }

    #[test]
    fn an_explicit_model_and_engine_override_the_defaults() {
        let env = |k: &str| match k {
            "TALLOW_LLM_BASE_URL" => Some("http://localhost:11434".to_string()),
            "TALLOW_LLM_ENGINE" => Some("ollama".to_string()),
            "TALLOW_LLM_MODEL" => Some("llama3.2".to_string()),
            _ => None,
        };
        let cfg = resolve_engine_config(&env).expect("resolves");
        assert_eq!(cfg.engine, Engine::Ollama);
        assert_eq!(cfg.model, "llama3.2");
    }

    #[test]
    fn an_unknown_engine_name_is_refused_not_defaulted() {
        let env = |k: &str| match k {
            "TALLOW_LLM_BASE_URL" => Some("https://api.example.invalid".to_string()),
            "TALLOW_LLM_ENGINE" => Some("gemini".to_string()),
            _ => None,
        };
        assert!(
            resolve_engine_config(&env).is_err(),
            "an unknown engine must not silently default"
        );
    }

    #[test]
    fn the_tier_state_payload_carries_every_measured_field() {
        let state = TierState {
            enabled: false,
            engine: "openai-compatible",
            engine_url: "https://api.example.invalid".to_string(),
            model: DEFAULT_CLOUD_MODEL.to_string(),
            credential_present: false,
            reachable: false,
            transfer_allowed: false,
            calls_made: 0,
            max_calls: DEFAULT_MAX_CALLS,
            reason: "disabled (no credential: TALLOW_LLM_API_KEY)".to_string(),
        };
        let ev = state.to_evidence();
        for key in [
            "enabled",
            "engine",
            "engine_url",
            "model",
            "credential_present",
            "reachable",
            "transfer_allowed",
            "calls_made",
            "max_calls",
            "reason",
        ] {
            assert!(ev.get(key).is_some(), "missing {key} in {ev}");
        }
        assert_eq!(ev["credential_present"], false);
    }

    #[test]
    fn the_budget_refuses_past_the_call_cap_rather_than_running() {
        let b = LlmBudget {
            max_calls: 2,
            max_prompt_chars: 100,
            source: "test".to_string(),
        };
        assert!(b.check_calls(0).is_ok());
        assert!(b.check_calls(1).is_ok());
        // At the cap, and past it, the answer is a refusal — not a warning.
        match b.check_calls(2) {
            Err(reason) => assert!(reason.contains("budget exhausted"), "{reason}"),
            Ok(()) => panic!("a call at the cap must be refused"),
        }
        assert!(b.check_calls(9).is_err());
    }

    #[test]
    fn an_oversized_prompt_is_refused_before_it_is_sent() {
        let b = LlmBudget {
            max_calls: 1,
            max_prompt_chars: 10,
            source: "test".to_string(),
        };
        assert!(b.check_prompt(10).is_ok(), "exactly at the cap is allowed");
        match b.check_prompt(11) {
            Err(reason) => assert!(reason.contains("over the"), "{reason}"),
            Ok(()) => panic!("an over-cap prompt must be refused"),
        }
    }

    #[test]
    fn the_budget_defaults_are_bounded_and_declared_as_defaults() {
        let none = |_: &str| None;
        let b = LlmBudget::from_env(&none);
        assert_eq!(b.max_calls, DEFAULT_MAX_CALLS);
        assert_eq!(b.max_prompt_chars, DEFAULT_MAX_PROMPT_CHARS);
        assert_eq!(
            b.source, "defaults",
            "an undeclared cap must not claim to be configured"
        );

        let env = |k: &str| match k {
            "TALLOW_LLM_MAX_CALLS" => Some("3".to_string()),
            _ => None,
        };
        let b = LlmBudget::from_env(&env);
        assert_eq!(b.max_calls, 3);
        assert_eq!(b.source, "environment");
        // A non-numeric value does not become a silent zero-cap.
        let junk = |_: &str| Some("many".to_string());
        let b = LlmBudget::from_env(&junk);
        assert_eq!(
            b.max_calls, DEFAULT_MAX_CALLS,
            "unparseable falls back to the default"
        );
    }

    #[test]
    fn the_credential_comes_from_a_named_environment_variable() {
        assert_eq!(LLM_API_KEY_ENV, "TALLOW_LLM_API_KEY");
        assert_eq!(Engine::Ollama.as_str(), "ollama");
        assert_eq!(Engine::OpenAiCompatible.as_str(), "openai-compatible");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn loads_tallow_extraction_schema_v1_contract() {
        // B7 / 3.5: the generic v1 contract loader, exercised against the real
        // committed example schema.
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/schemas/tallow/examples/product-listing.extraction.schema.json"
        );
        let json = std::fs::read_to_string(path).expect("read v1 example schema");
        let s = ExtractionSchema::from_v1_json(&json, "example.com").expect("load v1 schema");

        assert_eq!(s.domain, "example.com");
        assert_eq!(s.page_type, "product_listing");
        assert_eq!(s.fields.len(), 3);

        // name: the css selector (priority 0) wins over the lower-priority
        // json_path selector, which is skipped — non-CSS kinds are out of scope
        // for this CSS extractor, so no fallback is recorded.
        let name = &s.fields[0];
        assert_eq!(name.name, "name");
        assert_eq!(name.selector, ".product .name");
        assert!(name.required);
        assert!(name.fallback_selectors.is_empty());
        assert!(matches!(name.transform, Some(TransformFn::TrimWhitespace)));

        // price: coercion ["trim","parse_money"] must prefer parse_money over
        // the whitespace trim.
        let price = &s.fields[1];
        assert_eq!(price.name, "price");
        assert!(matches!(price.transform, Some(TransformFn::ParsePrice)));

        // url: attribute capture + parse_url coercion.
        let url = &s.fields[2];
        assert_eq!(url.name, "url");
        assert_eq!(url.selector, ".product a");
        assert_eq!(url.attribute.as_deref(), Some("href"));
        assert!(matches!(url.transform, Some(TransformFn::ExtractUrl)));
    }

    #[test]
    fn rejects_non_v1_or_selectorless_contracts() {
        let bad_version = r#"{"schema_version":"tallow.extraction_schema.v2","fields":[]}"#;
        let err = ExtractionSchema::from_v1_json(bad_version, "d").unwrap_err();
        assert!(err.contains("unsupported schema_version"), "got {err}");

        let no_css = r#"{"schema_version":"tallow.extraction_schema.v1","entity":"e",
            "fields":[{"name":"x","selectors":[{"kind":"json_path","value":"$.a","priority":0}]}]}"#;
        let err = ExtractionSchema::from_v1_json(no_css, "d").unwrap_err();
        assert!(err.contains("no css selector"), "got {err}");
    }

    /// W1 acceptance: after the first page of a domain+page-type, **model calls
    /// must be 0**. Seed the schema cache exactly as `generate_schema` would
    /// after the first page, then prove repeated extraction takes the cached
    /// CSS-speed path (`used_llm == false`) — no Ollama, no network.
    #[tokio::test]
    async fn cached_schema_extracts_at_css_speed_with_zero_model_calls() {
        let dir = std::env::temp_dir().join(format!(
            "tallow-llm-cache-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let mut ex =
            LlmExtractor::with_config("http://localhost:11434", "llama3.2", dir.to_str().unwrap());

        // 3× schema.org/Product microdata (no JSON-LD) ⇒ "product_listing".
        let html = r#"<html><body>
            <div itemtype="https://schema.org/Product">
              <span class="name">Fiji Water 1 L</span><span class="price">$2.48</span></div>
            <div itemtype="https://schema.org/Product">
              <span class="name">Fiji Water 6 pk</span><span class="price">$11.97</span></div>
            <div itemtype="https://schema.org/Product">
              <span class="name">Fiji Water 12 pk</span><span class="price">$22.98</span></div>
        </body></html>"#;
        assert_eq!(detect_page_type(html), "product_listing");

        let key = cache_key("example.com", "product_listing");
        ex.schema_cache.insert(
            key.clone(),
            ExtractionSchema {
                domain: "example.com".into(),
                page_type: "product_listing".into(),
                fields: vec![
                    FieldExtractor {
                        name: "name".into(),
                        selector: ".name".into(),
                        attribute: None,
                        transform: Some(TransformFn::TrimWhitespace),
                        required: true,
                        fallback_selectors: vec![],
                    },
                    FieldExtractor {
                        name: "price".into(),
                        selector: ".price".into(),
                        attribute: None,
                        transform: Some(TransformFn::ParsePrice),
                        required: false,
                        fallback_selectors: vec![],
                    },
                ],
                created_at: 0,
                success_count: 0,
                fail_count: 0,
                version: 1,
            },
        );

        // Page 1 and page 2 of the same domain+page-type.
        let first = ex
            .auto_extract(html, "https://example.com/products")
            .await
            .expect("first extraction");
        let second = ex
            .auto_extract(html, "https://example.com/products")
            .await
            .expect("second extraction");

        for (n, out) in [("first", &first), ("second", &second)] {
            assert!(!out.used_llm, "{n} extraction must not call the model");
            // `schema_domain == the real domain` proves the CACHED path ran —
            // the predefined fallback reports "predefined" instead.
            assert_eq!(out.schema_domain, "example.com", "{n}: not the cached path");
            assert_eq!(out.page_type, "product_listing");
            assert!(!out.items.is_empty(), "{n}: no items extracted");
        }

        let names: Vec<&str> = second
            .items
            .iter()
            .filter_map(|m| m.get("name").map(String::as_str))
            .collect();
        assert!(
            names.iter().any(|n| n.contains("Fiji Water")),
            "expected extracted names, got {names:?}"
        );

        // Two cache hits, zero regenerations: the constraint held.
        let cached = ex.schema_cache.get(&key).expect("schema still cached");
        assert_eq!(
            cached.success_count, 2,
            "schema must be reused, not regenerated"
        );
        assert_eq!(cached.fail_count, 0);
    }

    #[test]
    fn test_extract_domain() {
        assert_eq!(
            extract_domain("https://www.amazon.com/dp/B09X"),
            "www.amazon.com"
        );
        assert_eq!(
            extract_domain("http://example.com:8080/path"),
            "example.com"
        );
        assert_eq!(
            extract_domain("https://shop.shop-b.example/product/123"),
            "shop.shop-b.example"
        );
    }

    #[test]
    fn test_cache_key() {
        assert_eq!(
            cache_key("amazon.com", "product_detail"),
            "amazon.com::product_detail"
        );
    }

    #[test]
    fn test_sanitize_filename() {
        assert_eq!(sanitize_filename("amazon.com"), "amazon_com");
        assert_eq!(
            sanitize_filename("www.test-site.co.uk"),
            "www_test-site_co_uk"
        );
    }

    #[test]
    fn test_detect_page_type_jsonld_product() {
        let html =
            r#"<script type="application/ld+json">{"@type":"Product","name":"Widget"}</script>"#;
        assert_eq!(detect_page_type(html), "product_detail");
    }

    #[test]
    fn test_detect_page_type_jsonld_recipe() {
        let html =
            r#"<script type="application/ld+json">{"@type":"Recipe","name":"Cake"}</script>"#;
        assert_eq!(detect_page_type(html), "recipe");
    }

    #[test]
    fn test_detect_page_type_css_heuristics() {
        let html = r#"<div class="product-grid"><div class="product-card"><span class="price">$10</span></div></div>"#;
        assert_eq!(detect_page_type(html), "product_listing");
    }

    #[test]
    fn test_detect_page_type_article() {
        let html = r#"<div class="article-body"><div class="byline">By Author</div><div class="entry-content">Content</div></div>"#;
        assert_eq!(detect_page_type(html), "article");
    }

    #[test]
    fn test_detect_page_type_unknown() {
        let html = "<html><body>Hello world</body></html>";
        assert_eq!(detect_page_type(html), "unknown");
    }

    #[test]
    fn test_extract_json_block_raw() {
        let text = r#"Here is the schema: {"page_type": "product", "fields": []}"#;
        let json = extract_json_block(text).unwrap();
        assert!(json.starts_with('{'));
        assert!(json.contains("page_type"));
    }

    #[test]
    fn test_extract_json_block_markdown() {
        let text = "Here:\n```json\n{\"page_type\": \"recipe\", \"fields\": []}\n```\nDone.";
        let json = extract_json_block(text).unwrap();
        assert!(json.contains("recipe"));
    }

    #[test]
    fn test_extract_json_block_nested() {
        let text = r#"{"outer": {"inner": {"deep": true}}, "arr": [1, 2]}"#;
        let json = extract_json_block(text).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert!(parsed.get("outer").is_some());
    }

    #[test]
    fn test_parse_transform_name() {
        assert!(matches!(
            parse_transform_name("trim_whitespace"),
            Some(TransformFn::TrimWhitespace)
        ));
        assert!(matches!(
            parse_transform_name("parse_price"),
            Some(TransformFn::ParsePrice)
        ));
        assert!(matches!(
            parse_transform_name("parse_int"),
            Some(TransformFn::ParseInt)
        ));
        assert!(matches!(parse_transform_name(""), None));
        assert!(matches!(parse_transform_name("null"), None));
        assert!(matches!(parse_transform_name("none"), None));
        assert!(matches!(
            parse_transform_name(r"\d+"),
            Some(TransformFn::RegexExtract(_))
        ));
    }

    #[test]
    fn test_predefined_product_detail_schema() {
        let schema = predefined_schema("product_detail").unwrap();
        assert_eq!(schema.page_type, "product_detail");
        assert!(schema.fields.len() >= 5);
        assert!(
            schema
                .fields
                .iter()
                .any(|f| f.name == "title" && f.required)
        );
        assert!(
            schema
                .fields
                .iter()
                .any(|f| f.name == "price" && f.required)
        );
    }

    #[test]
    fn test_predefined_schemas_exist() {
        assert!(predefined_schema("product_detail").is_some());
        assert!(predefined_schema("product_listing").is_some());
        assert!(predefined_schema("article").is_some());
        assert!(predefined_schema("recipe").is_some());
        assert!(predefined_schema("job_listing").is_some());
        assert!(predefined_schema("real_estate").is_some());
        assert!(predefined_schema("nonexistent").is_none());
    }

    #[test]
    fn test_css_extraction_product_microdata() {
        let html = r#"<html><body>
            <h1>Test Product</h1>
            <meta itemprop="price" content="29.99">
            <meta itemprop="priceCurrency" content="USD">
            <span itemprop="brand">TestBrand</span>
            <meta itemprop="sku" content="SKU-123">
        </body></html>"#;

        let extractor =
            LlmExtractor::with_config("http://localhost:11434", "test", ".tallow-schemas-test");
        let schema = predefined_product_detail(0);
        let results = extractor.execute_schema(html, &schema).unwrap();
        assert!(!results.is_empty());

        let item = &results[0];
        assert_eq!(item.get("title").map(|s| s.as_str()), Some("Test Product"));
    }

    #[test]
    fn test_validation_all_required_present() {
        let extractor = LlmExtractor::new();
        let schema = predefined_product_detail(0);

        let mut results = HashMap::new();
        results.insert("title".into(), "Widget".into());
        results.insert("price".into(), "1999".into());

        let validation = extractor.validate(&results, &schema);
        assert!(validation.valid);
        assert!(validation.missing_required.is_empty());
    }

    #[test]
    fn test_validation_missing_required() {
        let extractor = LlmExtractor::new();
        let schema = predefined_product_detail(0);

        let mut results = HashMap::new();
        results.insert("brand".into(), "Acme".into());
        // Missing title and price — both required.

        let validation = extractor.validate(&results, &schema);
        assert!(!validation.valid);
        assert!(validation.missing_required.contains(&"title".to_string()));
        assert!(validation.missing_required.contains(&"price".to_string()));
    }

    #[test]
    fn test_transform_parse_price() {
        let extractor = LlmExtractor::new();
        let result = extractor.apply_transform("$29.99", &Some(TransformFn::ParsePrice));
        assert_eq!(result, "2999");
    }

    #[test]
    fn test_transform_parse_int() {
        let extractor = LlmExtractor::new();
        let result = extractor.apply_transform("42 reviews", &Some(TransformFn::ParseInt));
        assert_eq!(result, "42");
    }

    #[test]
    fn test_transform_parse_float() {
        let extractor = LlmExtractor::new();
        let result = extractor.apply_transform("4.7 stars", &Some(TransformFn::ParseFloat));
        assert_eq!(result, "4.7");
    }

    #[test]
    fn test_transform_strip_html() {
        let extractor = LlmExtractor::new();
        let result = extractor.apply_transform("<b>Bold</b> text", &Some(TransformFn::StripHtml));
        assert_eq!(result, "Bold  text");
    }

    #[test]
    fn test_transform_regex_extract() {
        let extractor = LlmExtractor::new();
        let result = extractor.apply_transform(
            "SKU: AB-12345",
            &Some(TransformFn::RegexExtract(r"([A-Z]{2}-\d+)".into())),
        );
        assert_eq!(result, "AB-12345");
    }

    #[test]
    fn test_llm_response_parsing() {
        let extractor = LlmExtractor::new();
        let response = r##"```json
{
  "page_type": "product_detail",
  "fields": [
    {
      "name": "title",
      "selector": "h1.product-title",
      "attribute": null,
      "transform": "trim_whitespace",
      "required": true,
      "fallback_selectors": [".product-name", "#title"]
    },
    {
      "name": "price",
      "selector": ".price-value",
      "attribute": null,
      "transform": "parse_price",
      "required": true,
      "fallback_selectors": [".offer-price"]
    }
  ]
}
```"##;

        let schema = extractor
            .parse_llm_response(response, "example.com", "product_detail")
            .unwrap();
        assert_eq!(schema.domain, "example.com");
        assert_eq!(schema.page_type, "product_detail");
        assert_eq!(schema.fields.len(), 2);
        assert_eq!(schema.fields[0].name, "title");
        assert_eq!(schema.fields[0].selector, "h1.product-title");
        assert!(schema.fields[0].required);
        assert_eq!(schema.fields[0].fallback_selectors.len(), 2);
        assert_eq!(schema.fields[1].name, "price");
        assert!(matches!(
            schema.fields[1].transform,
            Some(TransformFn::ParsePrice)
        ));
    }

    #[test]
    fn test_llm_response_parsing_rejects_invalid_selectors() {
        let extractor = LlmExtractor::new();
        let response = r#"{
  "page_type": "test",
  "fields": [
    {"name": "good", "selector": "h1", "attribute": null, "transform": null, "required": true, "fallback_selectors": []},
    {"name": "bad", "selector": "<<<invalid>>>", "attribute": null, "transform": null, "required": true, "fallback_selectors": []}
  ]
}"#;
        let schema = extractor
            .parse_llm_response(response, "test.com", "test")
            .unwrap();
        // The invalid selector should be filtered out.
        assert_eq!(schema.fields.len(), 1);
        assert_eq!(schema.fields[0].name, "good");
    }

    #[test]
    fn test_schema_serialization_roundtrip() {
        let schema = predefined_product_detail(1234567890);
        let json = serde_json::to_string_pretty(&schema).unwrap();
        let deserialized: ExtractionSchema = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.domain, schema.domain);
        assert_eq!(deserialized.page_type, schema.page_type);
        assert_eq!(deserialized.fields.len(), schema.fields.len());
        assert_eq!(deserialized.created_at, schema.created_at);
    }

    #[test]
    fn test_contract_snapshot_has_required_fields_and_digest() {
        let schema = predefined_product_detail(1234567890);
        let snapshot = build_contract_snapshot(&schema);
        assert_eq!(snapshot.contract_version, EXTRACTOR_CONTRACT_VERSION);
        assert!(
            snapshot
                .contract_id
                .contains("predefined::product_detail::v1")
        );
        assert!(snapshot.required_fields.contains(&"title".to_string()));
        assert!(snapshot.required_fields.contains(&"price".to_string()));
        assert!(snapshot.selector_count >= schema.fields.len());
        assert!(!snapshot.digest.is_empty());
    }

    // Clean up test cache directory.
    #[test]
    fn test_cleanup() {
        let _ = std::fs::remove_dir_all(".tallow-schemas-test");
    }
}
