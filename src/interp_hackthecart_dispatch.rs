//! HackTheCart module dispatcher for the Tallow interpreter.
//!
//! Surfaces the 44 browser/* helper modules to Tallow scripts via static
//! dotted-name calls (e.g. `ProductMatcher.new()`).
//!
//! The interpreter routes unknown builtin names through
//! [`dispatch_hackthecart_static`]. Constructors return a `Value::BrowserObject`
//! whose `kind` is the type name and whose `handle` is the wrapped Rust
//! object. Instance methods on those objects are routed via
//! [`dispatch_hackthecart_method`] from the method-call dispatcher.
//!
//! Scope: this is a *surfacing* layer. Constructors are wired for all 44
//! modules. The crawl engine is now reachable from scripts: `CrawlQueue`
//! push/pop operate a real in-process queue, `AdaptiveCrawler.fetch` /
//! `CrawlPipeline.fetch` run the real HTTP crawl path, `JobQueue`
//! enqueue/dequeue/ack/nack drive the real in-memory queue, and the
//! extractors (`SmartExtractor`, `SitemapParser`, `SchemaExtractor`,
//! `StructuredDataExtractor`, `SelfHealingSelector`, `RecipeParser`,
//! `UnitNormalizer`) call their real implementations.
//!
//! Methods whose inputs are Rust-only types (e.g. `StealthProfile`,
//! `PriceObservation`) return an honest `Err` explaining why — never a fake
//! success. Everything else returns a clear "not yet dispatched" error so
//! callers get a useful diagnostic instead of "unknown builtin".
//!
//! Intentional limitations/gates in this surface are catalogued in
//! `docs/operations/stub-register.md` (seeded by remediation task R2-6).

use std::sync::{Arc, Mutex};

use crate::browser;
use crate::interp::{BrowserHandle, RuntimeError, Value};

/// Helper trait to convert Rust types into Tallow `Value` enum.
/// Used by method dispatchers to keep marshalling concise.
pub trait IntoTallowValue {
    fn into_value(self) -> Value;
}

impl IntoTallowValue for i64 {
    fn into_value(self) -> Value { Value::Int(self as i128) }
}
impl IntoTallowValue for i128 {
    fn into_value(self) -> Value { Value::Int(self) }
}
impl IntoTallowValue for f64 {
    fn into_value(self) -> Value { Value::Float(self) }
}
impl IntoTallowValue for String {
    fn into_value(self) -> Value { Value::String(self) }
}
impl IntoTallowValue for bool {
    fn into_value(self) -> Value { Value::Bool(self) }
}
impl<T: IntoTallowValue> IntoTallowValue for Option<T> {
    fn into_value(self) -> Value {
        match self {
            Some(v) => v.into_value(),
            None => Value::Nil,
        }
    }
}
impl<T: IntoTallowValue> IntoTallowValue for Vec<T> {
    fn into_value(self) -> Value {
        Value::Array(self.into_iter().map(|v| v.into_value()).collect())
    }
}

/// Wrap a Rust value as a Tallow `BrowserObject` with the given kind tag.
fn obj<T: Send + Sync + 'static>(kind: &str, v: T) -> Value {
    let handle: Arc<dyn std::any::Any + Send + Sync> = Arc::new(v);
    Value::BrowserObject(BrowserHandle {
        kind: kind.to_string(),
        handle,
    })
}

fn ok(v: Value) -> Value {
    Value::Ok(Box::new(v))
}

/// Run a future to completion from the synchronous interpreter thread.
///
/// Mirrors `interp::get_browser_runtime`: if this thread is already inside a
/// tokio runtime, block on its handle; otherwise use a lazily-initialized
/// current-thread runtime. Only bounded futures are bridged here (the
/// interpreter is single-threaded per script).
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.block_on(fut)
    } else {
        static RT: std::sync::OnceLock<tokio::runtime::Runtime> = std::sync::OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("failed to create HackTheCart dispatch tokio runtime")
        })
        .block_on(fut)
    }
}

/// Marshal a `serde_json` value into a Tallow `Value` (objects become Maps).
fn json_to_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => match n.as_i64() {
            Some(i) => Value::Int(i as i128),
            None => Value::Float(n.as_f64().unwrap_or(0.0)),
        },
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(items) => {
            Value::Array(items.iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(map) => Value::Map(
            map.iter()
                .map(|(k, v)| (Value::String(k.clone()), json_to_value(v)))
                .collect(),
        ),
    }
}

/// Marshal a `crawl_queue::CrawlJob` into a Tallow Struct.
fn crawl_job_to_value(job: &browser::crawl_queue::CrawlJob) -> Value {
    Value::Struct {
        name: "CrawlJob".to_string(),
        fields: vec![
            ("url".to_string(), Value::String(job.url.clone())),
            ("priority".to_string(), Value::Int(job.priority as i128)),
            ("retries".to_string(), Value::Int(job.retries as i128)),
            (
                "max_retries".to_string(),
                Value::Int(job.max_retries as i128),
            ),
            ("domain".to_string(), Value::String(job.domain.clone())),
            ("depth".to_string(), Value::Int(job.depth as i128)),
        ],
    }
}

/// Marshal a `CrawlResult` into a Tallow Struct.
fn crawl_result_to_value(r: &browser::adaptive_crawler::CrawlResult) -> Value {
    Value::Struct {
        name: "CrawlResult".to_string(),
        fields: vec![
            ("url".to_string(), Value::String(r.url.clone())),
            ("body".to_string(), Value::String(r.body.clone())),
            ("status".to_string(), Value::Int(r.status as i128)),
            ("source".to_string(), Value::String(format!("{:?}", r.source))),
            (
                "content_type".to_string(),
                match &r.content_type {
                    Some(ct) => Value::String(ct.clone()),
                    None => Value::Nil,
                },
            ),
            ("unchanged".to_string(), Value::Bool(r.unchanged)),
        ],
    }
}

/// Marshal a `sitemap::SitemapEntry` into a Tallow Struct.
fn sitemap_entry_to_value(e: &browser::sitemap::SitemapEntry) -> Value {
    Value::Struct {
        name: "SitemapEntry".to_string(),
        fields: vec![
            ("url".to_string(), Value::String(e.url.clone())),
            (
                "lastmod".to_string(),
                match &e.lastmod {
                    Some(v) => Value::String(v.clone()),
                    None => Value::Nil,
                },
            ),
            (
                "priority".to_string(),
                match e.priority {
                    Some(p) => Value::Float(p),
                    None => Value::Nil,
                },
            ),
            (
                "changefreq".to_string(),
                match &e.changefreq {
                    Some(v) => Value::String(v.clone()),
                    None => Value::Nil,
                },
            ),
        ],
    }
}

/// Marshal an `ai_extract::ProductData` into a Tallow Struct.
fn ai_product_to_value(p: &browser::ai_extract::ProductData) -> Value {
    let mut fields: Vec<(String, Value)> = Vec::new();
    for (k, v) in [
        ("name", p.name.clone()),
        ("currency", p.currency.clone()),
        ("availability", p.availability.clone()),
        ("image_url", p.image_url.clone()),
        ("brand", p.brand.clone()),
        ("sku", p.sku.clone()),
    ] {
        fields.push((
            k.to_string(),
            match v {
                Some(s) => Value::String(s),
                None => Value::Nil,
            },
        ));
    }
    fields.push((
        "price".to_string(),
        p.price.map(Value::Float).unwrap_or(Value::Nil),
    ));
    fields.push((
        "rating".to_string(),
        p.rating.map(Value::Float).unwrap_or(Value::Nil),
    ));
    Value::Struct {
        name: "ProductData".to_string(),
        fields,
    }
}

/// Marshal a `structured_data::ProductData` into a Tallow Struct.
fn structured_product_to_value(p: &browser::structured_data::ProductData) -> Value {
    let mut fields: Vec<(String, Value)> = Vec::new();
    for (k, v) in [
        ("name", p.name.clone()),
        ("price", p.price.clone()),
        ("currency", p.currency.clone()),
        ("availability", p.availability.clone()),
        ("image", p.image.clone()),
        ("description", p.description.clone()),
        ("brand", p.brand.clone()),
        ("sku", p.sku.clone()),
    ] {
        fields.push((
            k.to_string(),
            match v {
                Some(s) => Value::String(s),
                None => Value::Nil,
            },
        ));
    }
    fields.push((
        "price_value".to_string(),
        p.price_value.map(Value::Float).unwrap_or(Value::Nil),
    ));
    fields.push((
        "rating".to_string(),
        p.rating.map(Value::Float).unwrap_or(Value::Nil),
    ));
    fields.push((
        "review_count".to_string(),
        p.review_count.map(|c| Value::Int(c as i128)).unwrap_or(Value::Nil),
    ));
    Value::Struct {
        name: "ProductData".to_string(),
        fields,
    }
}

/// Marshal a `smart_extract::ExtractedProduct` into a Tallow Struct.
fn extracted_product_to_value(p: &browser::smart_extract::ExtractedProduct) -> Value {
    let mut fields: Vec<(String, Value)> = Vec::new();
    for (k, v) in [
        ("name", p.name.clone()),
        ("brand", p.brand.clone()),
        ("currency", p.currency.clone()),
        ("availability", p.availability.clone()),
        ("sku", p.sku.clone()),
        ("gtin", p.gtin.clone()),
        ("mpn", p.mpn.clone()),
        ("image_url", p.image_url.clone()),
        ("description", p.description.clone()),
        ("category", p.category.clone()),
    ] {
        fields.push((
            k.to_string(),
            match v {
                Some(s) => Value::String(s),
                None => Value::Nil,
            },
        ));
    }
    for (k, v) in [
        ("price_cents", p.price_cents.map(|c| Value::Int(c as i128))),
        (
            "sale_price_cents",
            p.sale_price_cents.map(|c| Value::Int(c as i128)),
        ),
        ("rating", p.rating.map(Value::Float)),
        ("review_count", p.review_count.map(|c| Value::Int(c as i128))),
    ] {
        fields.push((k.to_string(), v.unwrap_or(Value::Nil)));
    }
    fields.push((
        "extraction_method".to_string(),
        Value::String(format!("{:?}", p.extraction_method)),
    ));
    fields.push(("confidence".to_string(), Value::Float(p.confidence)));
    Value::Struct {
        name: "ExtractedProduct".to_string(),
        fields,
    }
}

/// Marshal a `recipe_parser::Ingredient` into a Tallow Struct.
fn ingredient_to_value(i: &browser::recipe_parser::Ingredient) -> Value {
    Value::Struct {
        name: "Ingredient".to_string(),
        fields: vec![
            ("raw_text".to_string(), Value::String(i.raw_text.clone())),
            (
                "quantity".to_string(),
                i.quantity.map(Value::Float).unwrap_or(Value::Nil),
            ),
            (
                "unit".to_string(),
                i.unit.clone().map(Value::String).unwrap_or(Value::Nil),
            ),
            ("item".to_string(), Value::String(i.item.clone())),
            (
                "preparation".to_string(),
                i.preparation.clone().map(Value::String).unwrap_or(Value::Nil),
            ),
            ("optional".to_string(), Value::Bool(i.optional)),
        ],
    }
}

/// Marshal a `self_heal::SelectorCandidate` into a Tallow Struct.
fn selector_candidate_to_value(c: &browser::self_heal::SelectorCandidate) -> Value {
    Value::Struct {
        name: "SelectorCandidate".to_string(),
        fields: vec![
            ("selector".to_string(), Value::String(c.selector.clone())),
            ("confidence".to_string(), Value::Float(c.confidence)),
            ("reason".to_string(), Value::String(c.reason.clone())),
            ("sample_text".to_string(), Value::String(c.sample_text.clone())),
        ],
    }
}

/// Marshal a `price_history::PricePoint` into a Tallow Struct.
fn price_point_to_value(p: &browser::price_history::PricePoint) -> Value {
    Value::Struct {
        name: "PricePoint".to_string(),
        fields: vec![
            ("timestamp".to_string(), Value::Int(p.timestamp as i128)),
            ("price_cents".to_string(), Value::Int(p.price_cents as i128)),
            (
                "sale_price_cents".to_string(),
                p.sale_price_cents
                    .map(|c| Value::Int(c as i128))
                    .unwrap_or(Value::Nil),
            ),
            ("in_stock".to_string(), Value::Bool(p.in_stock)),
            ("source".to_string(), Value::String(p.source.clone())),
        ],
    }
}

/// Marshal a `job_queue::Job` into a Tallow Struct.
fn job_to_value(j: &browser::job_queue::Job) -> Value {
    Value::Struct {
        name: "Job".to_string(),
        fields: vec![
            ("id".to_string(), Value::String(j.id.clone())),
            (
                "job_type".to_string(),
                Value::String(format!("{:?}", j.job_type)),
            ),
            ("priority".to_string(), Value::Int(j.priority as i128)),
            ("payload".to_string(), json_to_value(&j.payload)),
            ("created_at".to_string(), Value::Int(j.created_at as i128)),
            ("scheduled_for".to_string(), Value::Int(j.scheduled_for as i128)),
            ("attempts".to_string(), Value::Int(j.attempts as i128)),
            ("max_attempts".to_string(), Value::Int(j.max_attempts as i128)),
            ("backoff_ms".to_string(), Value::Int(j.backoff_ms as i128)),
        ],
    }
}

/// Parse a job-type string into the `job_queue::JobType` enum.
fn job_type_from_str(s: &str) -> Option<browser::job_queue::JobType> {
    match s {
        "ScrapePage" => Some(browser::job_queue::JobType::ScrapePage),
        "ExtractProduct" => Some(browser::job_queue::JobType::ExtractProduct),
        "MatchProduct" => Some(browser::job_queue::JobType::MatchProduct),
        "ValidatePrice" => Some(browser::job_queue::JobType::ValidatePrice),
        "SendAlert" => Some(browser::job_queue::JobType::SendAlert),
        "RefreshCookies" => Some(browser::job_queue::JobType::RefreshCookies),
        "WarmupProfile" => Some(browser::job_queue::JobType::WarmupProfile),
        "ParseFlyer" => Some(browser::job_queue::JobType::ParseFlyer),
        "SyncApi" => Some(browser::job_queue::JobType::SyncApi),
        _ => None,
    }
}

/// Look up a named field in a Tallow `Struct` or `Map` value.
fn tagged_field<'a>(v: &'a Value, key: &str) -> Option<&'a Value> {
    match v {
        Value::Struct { fields, .. } => fields.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        Value::Map(entries) => entries.iter().find_map(|(k, v)| match k {
            Value::String(s) if s == key => Some(v),
            _ => None,
        }),
        _ => None,
    }
}

/// Short type tag for error messages.
fn value_kind(v: &Value) -> &'static str {
    match v {
        Value::Nil => "Nil",
        Value::Bool(_) => "Bool",
        Value::Int(_) => "Int",
        Value::Float(_) => "Float",
        Value::String(_) => "String",
        Value::Array(_) => "Array",
        Value::Map(_) => "Map",
        Value::Struct { .. } => "Struct",
        _ => "value",
    }
}

/// Integral numeric coercion: `Int`, or an integral `Float` → `i64`.
fn value_as_i64(v: &Value) -> Option<i64> {
    match v {
        Value::Int(i) => Some(*i as i64),
        Value::Float(f) if f.is_finite() && f.fract() == 0.0 => Some(*f as i64),
        _ => None,
    }
}

/// Numeric coercion: `Int` or `Float` → `f64`.
fn value_as_f64(v: &Value) -> Option<f64> {
    match v {
        Value::Int(i) => Some(*i as f64),
        Value::Float(f) if f.is_finite() => Some(*f),
        _ => None,
    }
}

/// Marshal a Tallow array of observation records (Struct or Map, fields:
/// `source`, `price_cents`, optional `observed_at` unix secs, optional
/// `confidence`) into `triangulation::SourceObservation` values.
///
/// Never drops inputs silently: a missing/ill-typed field is an error naming
/// the offending element, so a consensus can only be computed from the
/// observations the caller actually passed.
fn observations_from_value(
    v: &Value,
) -> Result<Vec<browser::triangulation::SourceObservation>, String> {
    let items = match v {
        Value::Array(items) => items,
        other => {
            return Err(format!(
                "observations must be an array of {{source, price_cents, …}} records, got {}",
                value_kind(other)
            ))
        }
    };
    if items.is_empty() {
        return Err(
            "observations must be a non-empty array — refusing to report a consensus over zero observations"
                .to_string(),
        );
    }
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut out = Vec::with_capacity(items.len());
    for (i, item) in items.iter().enumerate() {
        if !matches!(item, Value::Struct { .. } | Value::Map(_)) {
            return Err(format!(
                "observations[{i}] must be a Struct or Map with fields {{source, price_cents, observed_at, confidence}}, got {}",
                value_kind(item)
            ));
        }
        let source = match tagged_field(item, "source") {
            Some(Value::String(s)) if !s.trim().is_empty() => s.clone(),
            Some(Value::String(_)) => {
                return Err(format!("observations[{i}].source must be a non-empty string"))
            }
            Some(other) => {
                return Err(format!(
                    "observations[{i}].source must be a String, got {}",
                    value_kind(other)
                ))
            }
            None => {
                return Err(format!(
                    "observations[{i}] is missing the required 'source' field (got {})",
                    value_kind(item)
                ))
            }
        };
        let price_cents = match tagged_field(item, "price_cents") {
            Some(v) => value_as_i64(v).ok_or_else(|| {
                format!(
                    "observations[{i}].price_cents must be an Int (cents), got {}",
                    value_kind(v)
                )
            })?,
            None => {
                return Err(format!(
                    "observations[{i}] is missing the required 'price_cents' field (got {})",
                    value_kind(item)
                ))
            }
        };
        let observed_at = match tagged_field(item, "observed_at") {
            Some(v) => value_as_i64(v).ok_or_else(|| {
                format!(
                    "observations[{i}].observed_at must be an Int (unix seconds), got {}",
                    value_kind(v)
                )
            })?,
            // Absent timestamp = observed now (same convention as PriceHistoryEngine.record).
            None => now,
        };
        let confidence = match tagged_field(item, "confidence") {
            Some(v) => value_as_f64(v).ok_or_else(|| {
                format!(
                    "observations[{i}].confidence must be a Float in 0.0..=1.0, got {}",
                    value_kind(v)
                )
            })?,
            None => 1.0,
        };
        out.push(browser::triangulation::SourceObservation {
            source,
            price_cents,
            observed_at,
            confidence,
        });
    }
    Ok(out)
}


/// Static-call dispatch (e.g. `ProductMatcher.new()`).
///
/// Returns `Some(result)` if `name` matches a HackTheCart builtin, otherwise
/// `None` so the caller can fall through to other dispatchers.
pub fn dispatch_hackthecart_static(
    name: &str,
    args: &[Value],
) -> Option<Result<Value, RuntimeError>> {
    let result: Value = match name {
        // ── Constructors with no args ─────────────────────────────────
        "ProductMatcher.new" => ok(obj(
            "ProductMatcher",
            browser::product_matcher::ProductMatcher::new(),
        )),
        "QualityValidator.new" => ok(obj(
            "QualityValidator",
            browser::quality_validator::QualityValidator::new(),
        )),
        "Triangulator.new" => ok(obj(
            "Triangulator",
            browser::triangulation::Triangulator::new(),
        )),
        "CanaryRegistry.new" => ok(obj(
            "CanaryRegistry",
            browser::canary::CanaryRegistry::new(),
        )),
        "PriceBoundsRegistry.new" => ok(obj(
            "PriceBoundsRegistry",
            browser::price_bounds::PriceBoundsRegistry::new(),
        )),
        "AbLayoutDetector.new" => ok(obj(
            "AbLayoutDetector",
            browser::ab_detector::AbLayoutDetector::new(),
        )),
        "ZipRotator.new" => ok(obj(
            "ZipRotator",
            browser::zip_rotation::ZipRotator::new(),
        )),
        "ObservabilityDashboard.new" => ok(obj(
            "ObservabilityDashboard",
            browser::observability::ObservabilityDashboard::new(),
        )),
        "AuthStrategyRegistry.new" => ok(obj(
            "AuthStrategyRegistry",
            browser::auth_strategy::AuthStrategyRegistry::new(),
        )),
        "BasketOptimizer.new" => ok(obj(
            "BasketOptimizer",
            browser::basket_optimizer::BasketOptimizer::new(),
        )),
        "PriceHistoryEngine.new" => ok(obj(
            "PriceHistoryEngine",
            Mutex::new(browser::price_history::PriceHistoryEngine::new()),
        )),
        "ShrinkflationDetector.new" => ok(obj(
            "ShrinkflationDetector",
            browser::shrinkflation::ShrinkflationDetector::new(),
        )),
        "SubstitutionEngine.new" => ok(obj(
            "SubstitutionEngine",
            browser::substitution::SubstitutionEngine::new(),
        )),
        "HouseholdService.new" => ok(obj(
            "HouseholdService",
            browser::household::HouseholdService::new(),
        )),
        "AffiliateManager.new" => ok(obj(
            "AffiliateManager",
            browser::affiliate::AffiliateManager::new(),
        )),
        "ComplianceManager.new" => ok(obj(
            "ComplianceManager",
            browser::compliance::ComplianceManager::new(),
        )),
        "ProductSearchIndex.new" => ok(obj(
            "ProductSearchIndex",
            browser::search_index::ProductSearchIndex::new(),
        )),
        "AdaptiveCrawler.new" => ok(obj(
            "AdaptiveCrawler",
            browser::adaptive_crawler::AdaptiveCrawler::new(),
        )),
        "CrawlQueue.new" => ok(obj(
            "CrawlQueue",
            Mutex::new(browser::crawl_queue::CrawlQueue::new()),
        )),
        "CrawlPipeline.new" => ok(obj(
            "CrawlPipeline",
            Mutex::new(browser::crawl_pipeline::CrawlPipelineBuilder::new().build()),
        )),
        "AntiBotOrchestrator.new" => ok(obj(
            "AntiBotOrchestrator",
            browser::antibot::AntiBotOrchestrator::new(),
        )),

        // ── Constructors with simple args ─────────────────────────────
        "SelectorChain.new" => {
            let field = args.first().map(|v| v.as_string()).unwrap_or_default();
            ok(obj(
                "SelectorChain",
                browser::selector_chain::SelectorChain::new(&field),
            ))
        }
        "SnapshotSampler.new" => {
            let path = args.first().map(|v| v.as_string()).unwrap_or_default();
            let rate = match args.get(1) {
                Some(Value::Float(f)) => *f,
                Some(Value::Int(i)) => *i as f64,
                _ => 0.01,
            };
            ok(obj(
                "SnapshotSampler",
                browser::snapshot_sampler::SnapshotSampler::new(&path, rate),
            ))
        }
        "CircuitBreaker.new" => {
            let target = args.first().map(|v| v.as_string()).unwrap_or_default();
            ok(obj(
                "CircuitBreaker",
                Mutex::new(browser::circuit_breaker::CircuitBreaker::new(&target)),
            ))
        }
        "DeadLetterQueue.new" => {
            let max = match args.first() {
                Some(Value::Int(i)) => *i as usize,
                _ => 1000,
            };
            ok(obj("DeadLetterQueue", browser::dlq::DeadLetterQueue::new(max)))
        }
        "SchemaDriftDetector.new" => {
            let thresh = match args.first() {
                Some(Value::Float(f)) => *f,
                Some(Value::Int(i)) => *i as f64,
                _ => 0.1,
            };
            ok(obj(
                "SchemaDriftDetector",
                browser::schema_drift::SchemaDriftDetector::new(thresh),
            ))
        }
        "JobQueue.new" => {
            let bp = match args.first() {
                Some(Value::Int(i)) => *i as usize,
                _ => 10_000,
            };
            ok(obj("JobQueue", browser::job_queue::JobQueue::new(bp)))
        }
        "TypesenseClient.new" => {
            let url = args.first().map(|v| v.as_string()).unwrap_or_default();
            let key = args.get(1).map(|v| v.as_string()).unwrap_or_default();
            ok(obj(
                "TypesenseClient",
                browser::typesense::TypesenseClient::new(&url, &key),
            ))
        }
        "ProvenanceRecord.new" => {
            let price = match args.first() {
                Some(Value::Int(i)) => *i as i64,
                _ => 0,
            };
            let pid = match args.get(1) {
                Some(Value::Int(i)) => *i as i64,
                _ => 0,
            };
            let sid = match args.get(2) {
                Some(Value::Int(i)) => *i as i64,
                _ => 0,
            };
            let src = args.get(3).map(|v| v.as_string()).unwrap_or_default();
            ok(obj(
                "ProvenanceRecord",
                browser::provenance::ProvenanceRecord::new(price, pid, sid, &src),
            ))
        }

        // ── Singletons / pools whose constructors take optional args (real
        //    constructors; omitted args fall back to documented defaults) ──
        "CookieFarm.new" => {
            let ua = args
                .first()
                .map(|v| v.as_string())
                .unwrap_or_else(|| "Mozilla/5.0".to_string());
            ok(obj("CookieFarm", browser::cookie_farm::CookieFarm::new(&ua)))
        }
        "ProfilePool.new" => {
            let dir = args
                .first()
                .map(|v| v.as_string())
                .unwrap_or_else(|| ".".to_string());
            let max = match args.get(1) {
                Some(Value::Int(i)) => *i as usize,
                _ => 16,
            };
            ok(obj(
                "ProfilePool",
                browser::warmup::ProfilePool::new(std::path::PathBuf::from(dir), max),
            ))
        }
        "ProxyPool.new" => ok(obj("ProxyPool", browser::proxy::ProxyPool::new())),
        "DomainRateManager.new" => {
            let rate = match args.first() {
                Some(Value::Float(f)) => *f,
                Some(Value::Int(i)) => *i as f64,
                _ => 1.0,
            };
            ok(obj(
                "DomainRateManager",
                browser::ratelimit::DomainRateManager::new(rate),
            ))
        }

        // ── Real constructors (previously empty type-tag handles) ─────
        "SmartExtractor.new" => {
            // Optional first arg enables the LLM (Ollama) fallback tier.
            let llm = match args.first() {
                Some(Value::Bool(b)) => *b,
                _ => false,
            };
            ok(obj(
                "SmartExtractor",
                browser::smart_extract::SmartExtractor::with_llm_fallback(llm),
            ))
        }
        "ResourceBlocker.new" => ok(obj(
            "ResourceBlocker",
            browser::resource_blocker::ResourceBlocker,
        )),
        "UnitNormalizer.new" => ok(obj(
            "UnitNormalizer",
            browser::unit_normalizer::UnitNormalizer,
        )),
        "RecipeParser.new" => ok(obj(
            "RecipeParser",
            browser::recipe_parser::RecipeParser,
        )),
        "SitemapParser.new" => ok(obj("SitemapParser", browser::sitemap::SitemapParser)),
        "FingerprintValidator.new" => ok(obj(
            "FingerprintValidator",
            browser::fingerprint_validator::FingerprintValidator,
        )),
        "SchemaExtractor.new" => ok(obj("SchemaExtractor", browser::ai_extract::SchemaExtractor)),
        "StructuredDataExtractor.new" => ok(obj(
            "StructuredDataExtractor",
            browser::structured_data::StructuredDataExtractor,
        )),
        "SelfHealingSelector.new" => ok(obj(
            "SelfHealingSelector",
            browser::self_heal::SelfHealingSelector,
        )),

        // ── Direct-call (associated function) constructors ─────────────
        "Http2Fingerprint.chrome" => ok(obj(
            "Http2Fingerprint",
            browser::http2_fingerprint::Http2Fingerprint::chrome(),
        )),

        _ => return None,
    };
    Some(Ok(result))
}

/// Instance method dispatch for HackTheCart-wrapped objects.
///
/// Called from the method-call dispatcher when the object is a
/// `BrowserObject` whose `kind` is one of the HackTheCart type tags but the
/// existing browser dispatch didn't recognize the method.
///
/// Wired methods call the real browser implementations (crawl queue, crawl
/// engine fetch, job queue, extractors). Methods whose inputs are Rust-only
/// types return an honest `Err` naming the Rust API to use instead. Anything
/// else returns a clear "not yet dispatched" error — never a fake success.
pub fn dispatch_hackthecart_method(
    bh: &BrowserHandle,
    method: &str,
    args: &[Value],
) -> Option<Result<Value, RuntimeError>> {
    let kind = bh.kind.as_str();

    // ── Wired instance methods ───────────────────────────────────────────
    match (kind, method) {
        ("ProductMatcher", "match_listing") => {
            let matcher = bh
                .handle
                .downcast_ref::<browser::product_matcher::ProductMatcher>()?;
            let title = args.first().map(|v| v.as_string()).unwrap_or_default();
            let brand = args.get(1).map(|v| v.as_string()).unwrap_or_default();
            let size = args.get(2).map(|v| v.as_string());
            let _unit = args.get(3).map(|v| v.as_string());
            let listing = browser::product_matcher::ScrapedListing {
                title,
                upc: None,
                gtin: None,
                price_cents: 0,
                image_url: None,
                size_text: size,
                brand_text: Some(brand),
                source: "interp".to_string(),
            };
            let result = matcher.match_listing(&listing);
            return Some(Ok(Value::Struct {
                name: "MatchResult".to_string(),
                fields: vec![
                    (
                        "canonical_id".to_string(),
                        match result.canonical_id {
                            Some(id) => Value::Int(id as i128),
                            None => Value::Nil,
                        },
                    ),
                    ("confidence".to_string(), Value::Float(result.confidence)),
                    (
                        "method".to_string(),
                        Value::String(format!("{:?}", result.method)),
                    ),
                ],
            }));
        }

        ("Triangulator", "triangulate") => {
            let tri = bh
                .handle
                .downcast_ref::<browser::triangulation::Triangulator>()?;
            // R2-5-HTC / R2-6: observations are marshalled from Tallow values.
            // Never silently substitute an empty slice — a consensus computed
            // over zero observations is a fabricated result.
            let Some(raw) = args.first() else {
                return Some(Err(RuntimeError::Error(
                    "Triangulator.triangulate: observations argument required — pass a non-empty array of {source: String, price_cents: Int, observed_at: Int (unix secs, defaults to now), confidence: Float (defaults to 1.0)}".to_string(),
                )));
            };
            let observations = match observations_from_value(raw) {
                Ok(obs) => obs,
                Err(msg) => {
                    return Some(Err(RuntimeError::Error(format!(
                        "Triangulator.triangulate: {msg}"
                    ))))
                }
            };
            let result = tri.triangulate(&observations);
            return Some(Ok(Value::Struct {
                name: "TriangulationResult".to_string(),
                fields: vec![
                    (
                        "consensus_price_cents".to_string(),
                        Value::Int(result.consensus_price_cents as i128),
                    ),
                    ("confidence".to_string(), Value::Float(result.confidence)),
                    (
                        "agreement_count".to_string(),
                        Value::Int(result.agreement_count as i128),
                    ),
                ],
            }));
        }

        ("PriceHistoryEngine", "record") => {
            let eng = bh
                .handle
                .downcast_ref::<Mutex<browser::price_history::PriceHistoryEngine>>()?;
            // Required: product_id, store_id, price_cents. Never silently write
            // a (0, 0, 0) point when the caller omits them — that would seed
            // the price history (and downstream triangulation) with fabricated data.
            let (Some(product_id), Some(store_id), Some(price_cents)) = (
                args.first().and_then(value_as_i64),
                args.get(1).and_then(value_as_i64),
                args.get(2).and_then(value_as_i64),
            ) else {
                return Some(Ok(Value::Err(Box::new(Value::String(
                    "PriceHistoryEngine.record requires product_id, store_id, price_cents (Ints); optional: sale_price_cents (Int), in_stock (Bool, default true), source (String, default \"interp\")".to_string(),
                )))));
            };
            let sale_price_cents = match args.get(3) {
                Some(Value::Int(i)) => Some(*i as i64),
                _ => None,
            };
            let in_stock = match args.get(4) {
                Some(Value::Bool(b)) => *b,
                _ => true,
            };
            let source = args
                .get(5)
                .map(|v| v.as_string())
                .unwrap_or_else(|| "interp".to_string());
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let point = browser::price_history::PricePoint {
                timestamp,
                price_cents,
                sale_price_cents,
                in_stock,
                source,
            };
            let mut guard = match eng.lock() {
                Ok(g) => g,
                Err(_) => {
                    return Some(Ok(Value::Err(Box::new(Value::String(
                        "PriceHistoryEngine mutex poisoned".to_string(),
                    )))))
                }
            };
            guard.record(product_id, store_id, point);
            return Some(Ok(Value::Bool(true)));
        }
        ("PriceHistoryEngine", "get_history") => {
            let eng = bh
                .handle
                .downcast_ref::<Mutex<browser::price_history::PriceHistoryEngine>>()?;
            let product_id = match args.first() {
                Some(Value::Int(i)) => *i as i64,
                _ => 0,
            };
            let store_id = match args.get(1) {
                Some(Value::Int(i)) => *i as i64,
                _ => 0,
            };
            let days = match args.get(2) {
                Some(Value::Int(i)) => *i as i32,
                _ => 30,
            };
            let guard = match eng.lock() {
                Ok(g) => g,
                Err(_) => {
                    return Some(Ok(Value::Err(Box::new(Value::String(
                        "PriceHistoryEngine mutex poisoned".to_string(),
                    )))))
                }
            };
            let history = guard.get_history(product_id, store_id, days);
            return Some(Ok(Value::Struct {
                name: "PriceHistory".to_string(),
                fields: vec![
                    ("product_id".to_string(), Value::Int(product_id as i128)),
                    ("store_id".to_string(), Value::Int(store_id as i128)),
                    (
                        "points".to_string(),
                        Value::Array(history.points.iter().map(price_point_to_value).collect()),
                    ),
                ],
            }));
        }

        ("BasketOptimizer", "optimize") => {
            // The real optimize() requires a populated Rust-side ProductDb and
            // a typed Recipe — neither is constructible from Tallow values.
            return Some(Err(RuntimeError::Error(
                "BasketOptimizer.optimize is not callable from Tallow: it requires a populated Rust-side ProductDb and a typed Recipe. Use the Rust API (browser::basket_optimizer) instead.".to_string(),
            )));
        }

        ("QualityValidator", "validate") => {
            // The real validate() requires typed PriceObservation +
            // CanonicalProduct structs, which are Rust-only types.
            return Some(Err(RuntimeError::Error(
                "QualityValidator.validate is not callable from Tallow: it requires Rust-side PriceObservation + CanonicalProduct values. Use the Rust API (browser::quality_validator) instead.".to_string(),
            )));
        }

        ("CrawlQueue", "push") => {
            let q = bh
                .handle
                .downcast_ref::<Mutex<browser::crawl_queue::CrawlQueue>>()?;
            let url = args.first().map(|v| v.as_string()).unwrap_or_default();
            if url.is_empty() {
                return Some(Ok(Value::Err(Box::new(Value::String(
                    "CrawlQueue.push requires a URL argument".to_string(),
                )))));
            }
            let priority = match args.get(1) {
                Some(Value::Int(i)) => (*i).clamp(0, 255) as u8,
                _ => 0,
            };
            let mut guard = match q.lock() {
                Ok(g) => g,
                Err(_) => {
                    return Some(Ok(Value::Err(Box::new(Value::String(
                        "CrawlQueue mutex poisoned".to_string(),
                    )))))
                }
            };
            // Real push: returns false when the URL was already queued (dedup).
            let pushed = guard.push(&url, priority);
            return Some(Ok(Value::Bool(pushed)));
        }
        ("CrawlQueue", "pop") => {
            let q = bh
                .handle
                .downcast_ref::<Mutex<browser::crawl_queue::CrawlQueue>>()?;
            let mut guard = match q.lock() {
                Ok(g) => g,
                Err(_) => {
                    return Some(Ok(Value::Err(Box::new(Value::String(
                        "CrawlQueue mutex poisoned".to_string(),
                    )))))
                }
            };
            return Some(Ok(match guard.pop() {
                Some(job) => crawl_job_to_value(&job),
                None => Value::Nil,
            }));
        }
        ("CrawlQueue", "len") => {
            let q = bh
                .handle
                .downcast_ref::<Mutex<browser::crawl_queue::CrawlQueue>>()?;
            let guard = match q.lock() {
                Ok(g) => g,
                Err(_) => {
                    return Some(Ok(Value::Err(Box::new(Value::String(
                        "CrawlQueue mutex poisoned".to_string(),
                    )))))
                }
            };
            return Some(Ok(Value::Int(guard.len() as i128)));
        }
        ("CrawlQueue", "is_empty") => {
            let q = bh
                .handle
                .downcast_ref::<Mutex<browser::crawl_queue::CrawlQueue>>()?;
            let guard = match q.lock() {
                Ok(g) => g,
                Err(_) => {
                    return Some(Ok(Value::Err(Box::new(Value::String(
                        "CrawlQueue mutex poisoned".to_string(),
                    )))))
                }
            };
            return Some(Ok(Value::Bool(guard.is_empty())));
        }

        ("CircuitBreaker", "allow_request") => {
            let cb = bh
                .handle
                .downcast_ref::<Mutex<browser::circuit_breaker::CircuitBreaker>>()?;
            let mut guard = match cb.lock() {
                Ok(g) => g,
                Err(_) => {
                    return Some(Ok(Value::Err(Box::new(Value::String(
                        "CircuitBreaker mutex poisoned".to_string(),
                    )))))
                }
            };
            // Real breaker state: opens after repeated failures.
            return Some(Ok(Value::Bool(guard.should_allow())));
        }
        ("CircuitBreaker", "record_success") => {
            let cb = bh
                .handle
                .downcast_ref::<Mutex<browser::circuit_breaker::CircuitBreaker>>()?;
            let mut guard = match cb.lock() {
                Ok(g) => g,
                Err(_) => {
                    return Some(Ok(Value::Err(Box::new(Value::String(
                        "CircuitBreaker mutex poisoned".to_string(),
                    )))))
                }
            };
            guard.on_success();
            return Some(Ok(Value::Nil));
        }
        ("CircuitBreaker", "record_failure") => {
            let cb = bh
                .handle
                .downcast_ref::<Mutex<browser::circuit_breaker::CircuitBreaker>>()?;
            let mut guard = match cb.lock() {
                Ok(g) => g,
                Err(_) => {
                    return Some(Ok(Value::Err(Box::new(Value::String(
                        "CircuitBreaker mutex poisoned".to_string(),
                    )))))
                }
            };
            guard.on_failure();
            return Some(Ok(Value::Nil));
        }
        ("CircuitBreaker", "success_rate") => {
            let cb = bh
                .handle
                .downcast_ref::<Mutex<browser::circuit_breaker::CircuitBreaker>>()?;
            let guard = match cb.lock() {
                Ok(g) => g,
                Err(_) => {
                    return Some(Ok(Value::Err(Box::new(Value::String(
                        "CircuitBreaker mutex poisoned".to_string(),
                    )))))
                }
            };
            return Some(Ok(Value::Float(guard.success_rate())));
        }

        // ── SmartExtractor: real synchronous extraction cascade ────────
        ("SmartExtractor", "extract") | ("SmartExtractor", "extract_from_html") => {
            let ex = bh.handle.downcast_ref::<browser::smart_extract::SmartExtractor>()?;
            let html = args.first().map(|v| v.as_string()).unwrap_or_default();
            let product = ex.extract_from_html_sync(&html);
            return Some(Ok(extracted_product_to_value(&product)));
        }

        // ── SitemapParser: real XML sitemap parsing ────────────────────
        ("SitemapParser", "parse") => {
            let _ = bh.handle.downcast_ref::<browser::sitemap::SitemapParser>()?;
            let xml = args.first().map(|v| v.as_string()).unwrap_or_default();
            let entries = browser::sitemap::SitemapParser::parse(&xml);
            return Some(Ok(Value::Array(
                entries.iter().map(sitemap_entry_to_value).collect(),
            )));
        }
        ("SitemapParser", "fetch_sitemap") => {
            let _ = bh.handle.downcast_ref::<browser::sitemap::SitemapParser>()?;
            let url = args.first().map(|v| v.as_string()).unwrap_or_default();
            return Some(Ok(match browser::sitemap::SitemapParser::fetch_sitemap(&url) {
                Ok(entries) => Value::Array(entries.iter().map(sitemap_entry_to_value).collect()),
                Err(e) => Value::Err(Box::new(Value::String(e))),
            }));
        }

        // ── SchemaExtractor / StructuredDataExtractor: real rule-based extraction ──
        ("SchemaExtractor", "extract_product") => {
            let _ = bh.handle.downcast_ref::<browser::ai_extract::SchemaExtractor>()?;
            let html = args.first().map(|v| v.as_string()).unwrap_or_default();
            return Some(Ok(
                match browser::ai_extract::SchemaExtractor::extract_product(&html) {
                    Some(p) => ai_product_to_value(&p),
                    None => Value::Nil,
                },
            ));
        }
        ("StructuredDataExtractor", "extract_product") => {
            let _ =
                bh.handle.downcast_ref::<browser::structured_data::StructuredDataExtractor>()?;
            let html = args.first().map(|v| v.as_string()).unwrap_or_default();
            return Some(Ok(
                match browser::structured_data::StructuredDataExtractor::extract_product(&html) {
                    Some(p) => structured_product_to_value(&p),
                    None => Value::Nil,
                },
            ));
        }
        ("StructuredDataExtractor", "extract_json_ld") => {
            let _ =
                bh.handle.downcast_ref::<browser::structured_data::StructuredDataExtractor>()?;
            let html = args.first().map(|v| v.as_string()).unwrap_or_default();
            let blocks = browser::structured_data::StructuredDataExtractor::extract_json_ld(&html);
            return Some(Ok(Value::Array(blocks.iter().map(json_to_value).collect())));
        }

        // ── RecipeParser / UnitNormalizer / SelfHealingSelector ─────────
        ("RecipeParser", "parse_ingredient") => {
            let _ = bh.handle.downcast_ref::<browser::recipe_parser::RecipeParser>()?;
            let line = args.first().map(|v| v.as_string()).unwrap_or_default();
            let ing = browser::recipe_parser::RecipeParser::parse_ingredient(&line);
            return Some(Ok(ingredient_to_value(&ing)));
        }
        ("UnitNormalizer", "parse_size") => {
            let _ = bh.handle.downcast_ref::<browser::unit_normalizer::UnitNormalizer>()?;
            let size_text = args.first().map(|v| v.as_string()).unwrap_or_default();
            return Some(Ok(
                match browser::unit_normalizer::UnitNormalizer::parse_size(&size_text) {
                    Some((amount, unit)) => Value::Struct {
                        name: "Size".to_string(),
                        fields: vec![
                            ("amount".to_string(), Value::Float(amount)),
                            ("unit".to_string(), Value::String(unit)),
                        ],
                    },
                    None => Value::Nil,
                },
            ));
        }
        ("SelfHealingSelector", "heal") => {
            let _ = bh.handle.downcast_ref::<browser::self_heal::SelfHealingSelector>()?;
            let html = args.first().map(|v| v.as_string()).unwrap_or_default();
            let selector = args.get(1).map(|v| v.as_string()).unwrap_or_default();
            let candidates = browser::self_heal::SelfHealingSelector::heal(&html, &selector);
            return Some(Ok(Value::Array(
                candidates.iter().map(selector_candidate_to_value).collect(),
            )));
        }

        // ── AdaptiveCrawler / CrawlPipeline: real fetch (HTTP path) ────
        ("AdaptiveCrawler", "fetch") => {
            let crawler =
                bh.handle.downcast_ref::<browser::adaptive_crawler::AdaptiveCrawler>()?;
            let url = args.first().map(|v| v.as_string()).unwrap_or_default();
            if url.is_empty() {
                return Some(Ok(Value::Err(Box::new(Value::String(
                    "AdaptiveCrawler.fetch requires a URL argument".to_string(),
                )))));
            }
            // No browser Page is constructible from Tallow values — this is
            // the honest HTTP-only path; JS-rendered pages are not escalated.
            let result = block_on(crawler.fetch(&url, None));
            return Some(Ok(match result {
                Ok(cr) => crawl_result_to_value(&cr),
                Err(e) => Value::Err(Box::new(Value::String(format!("{e}")))),
            }));
        }
        ("CrawlPipeline", "fetch") => {
            let pipe =
                bh.handle.downcast_ref::<Mutex<browser::crawl_pipeline::CrawlPipeline>>()?;
            let url = args.first().map(|v| v.as_string()).unwrap_or_default();
            if url.is_empty() {
                return Some(Ok(Value::Err(Box::new(Value::String(
                    "CrawlPipeline.fetch requires a URL argument".to_string(),
                )))));
            }
            let mut guard = match pipe.lock() {
                Ok(g) => g,
                Err(_) => {
                    return Some(Ok(Value::Err(Box::new(Value::String(
                        "CrawlPipeline mutex poisoned".to_string(),
                    )))))
                }
            };
            // HTTP-only (no Tallow Page object); retries/backoff are governed
            // by the pipeline's RetryConfig.
            let result = block_on(guard.fetch(&url, None));
            return Some(Ok(match result {
                Ok(cr) => crawl_result_to_value(&cr),
                Err(e) => Value::Err(Box::new(Value::String(format!("{e}")))),
            }));
        }

        // ── JobQueue: real in-memory queue (enqueue/dequeue/ack/nack) ──
        ("JobQueue", "enqueue") => {
            let q = bh.handle.downcast_ref::<browser::job_queue::JobQueue>()?;
            let Some(job_type) = args
                .first()
                .map(|v| v.as_string())
                .and_then(|s| job_type_from_str(&s))
            else {
                return Some(Ok(Value::Err(Box::new(Value::String(
                    "JobQueue.enqueue requires a job type: ScrapePage|ExtractProduct|MatchProduct|ValidatePrice|SendAlert|RefreshCookies|WarmupProfile|ParseFlyer|SyncApi".to_string(),
                )))));
            };
            let payload_str = args.get(1).map(|v| v.as_string()).unwrap_or_default();
            // Accept a JSON string as structured payload; fall back to a plain string.
            let payload = serde_json::from_str::<serde_json::Value>(&payload_str)
                .unwrap_or(serde_json::Value::String(payload_str));
            let job = browser::job_queue::Job::new(job_type, payload);
            return Some(Ok(match q.enqueue(job) {
                Ok(()) => Value::Bool(true),
                Err(e) => Value::Err(Box::new(Value::String(format!("{e}")))),
            }));
        }
        ("JobQueue", "dequeue") => {
            let q = bh.handle.downcast_ref::<browser::job_queue::JobQueue>()?;
            let worker = args
                .first()
                .map(|v| v.as_string())
                .unwrap_or_else(|| "interp".to_string());
            return Some(Ok(match q.dequeue(&worker) {
                Some(job) => job_to_value(&job),
                None => Value::Nil,
            }));
        }
        ("JobQueue", "ack") => {
            let q = bh.handle.downcast_ref::<browser::job_queue::JobQueue>()?;
            let id = args.first().map(|v| v.as_string()).unwrap_or_default();
            return Some(Ok(match q.ack(&id) {
                Ok(()) => Value::Bool(true),
                Err(e) => Value::Err(Box::new(Value::String(format!("{e}")))),
            }));
        }
        ("JobQueue", "nack") => {
            let q = bh.handle.downcast_ref::<browser::job_queue::JobQueue>()?;
            let id = args.first().map(|v| v.as_string()).unwrap_or_default();
            let error = args.get(1).map(|v| v.as_string()).unwrap_or_default();
            return Some(Ok(match q.nack(&id, &error, None) {
                Ok(()) => Value::Bool(true),
                Err(e) => Value::Err(Box::new(Value::String(format!("{e}")))),
            }));
        }

        // ── Honest errors for methods whose inputs are Rust-only types ──
        ("FingerprintValidator", "validate") => {
            return Some(Err(RuntimeError::Error(
                "FingerprintValidator.validate is not callable from Tallow: it requires a Rust-side StealthProfile. Use the Rust API (browser::fingerprint_validator) instead.".to_string(),
            )));
        }

        _ => {}
    }

    // Recognized kinds — return a "not yet dispatched" placeholder so
    // callers get a useful error instead of "unknown browser method".
    const KNOWN: &[&str] = &[
        "ProductMatcher",
        "QualityValidator",
        "Triangulator",
        "SmartExtractor",
        "SelectorChain",
        "CanaryRegistry",
        "PriceBoundsRegistry",
        "SnapshotSampler",
        "CircuitBreaker",
        "DeadLetterQueue",
        "ResourceBlocker",
        "AbLayoutDetector",
        "ZipRotator",
        "ObservabilityDashboard",
        "SchemaDriftDetector",
        "AuthStrategyRegistry",
        "UnitNormalizer",
        "RecipeParser",
        "BasketOptimizer",
        "PriceHistoryEngine",
        "ShrinkflationDetector",
        "SubstitutionEngine",
        "HouseholdService",
        "AffiliateManager",
        "ComplianceManager",
        "ProductSearchIndex",
        "ProvenanceRecord",
        "JobQueue",
        "AdaptiveCrawler",
        "CrawlQueue",
        "CrawlPipeline",
        "SitemapParser",
        "AntiBotOrchestrator",
        "CookieFarm",
        "ProfilePool",
        "ProxyPool",
        "DomainRateManager",
        "FingerprintValidator",
        "SchemaExtractor",
        "StructuredDataExtractor",
        "SelfHealingSelector",
        "TypesenseClient",
        "Http2Fingerprint",
    ];

    if !KNOWN.contains(&kind) {
        return None;
    }

    Some(Err(RuntimeError::Error(format!(
        "HackTheCart method not yet dispatched: {kind}.{method}() — constructor wired, method stub pending"
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_matcher_new_returns_object() {
        let r = dispatch_hackthecart_static("ProductMatcher.new", &[])
            .expect("ProductMatcher.new should be recognized")
            .expect("dispatch should succeed");
        // Result is wrapped in Ok(...)
        match r {
            Value::Ok(inner) => match *inner {
                Value::BrowserObject(bh) => {
                    assert_eq!(bh.kind, "ProductMatcher");
                }
                other => panic!("expected BrowserObject, got {other:?}"),
            },
            other => panic!("expected Ok(...), got {other:?}"),
        }
    }

    fn unwrap_browser_handle(v: Value) -> BrowserHandle {
        match v {
            Value::Ok(inner) => match *inner {
                Value::BrowserObject(bh) => bh,
                other => panic!("expected BrowserObject, got {other:?}"),
            },
            other => panic!("expected Ok(...), got {other:?}"),
        }
    }

    #[test]
    fn product_matcher_match_listing_dispatch() {
        let v = dispatch_hackthecart_static("ProductMatcher.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);
        let r = dispatch_hackthecart_method(
            &bh,
            "match_listing",
            &[
                Value::String("Coca-Cola 12oz".into()),
                Value::String("Coca-Cola".into()),
                Value::String("12".into()),
                Value::String("oz".into()),
            ],
        )
        .expect("dispatched")
        .expect("ok");
        match r {
            Value::Struct { name, fields } => {
                assert_eq!(name, "MatchResult");
                assert!(fields.iter().any(|(k, _)| k == "confidence"));
                assert!(fields.iter().any(|(k, _)| k == "method"));
            }
            other => panic!("expected MatchResult struct, got {other:?}"),
        }
    }

    #[test]
    fn circuit_breaker_allow_request_dispatch() {
        let v = dispatch_hackthecart_static(
            "CircuitBreaker.new",
            &[Value::String("example.com".into())],
        )
        .unwrap()
        .unwrap();
        let bh = unwrap_browser_handle(v);
        let r = dispatch_hackthecart_method(
            &bh,
            "allow_request",
            &[Value::String("example.com".into())],
        )
        .expect("dispatched")
        .expect("ok");
        assert!(matches!(r, Value::Bool(_)));
    }

    #[test]
    fn unknown_name_returns_none() {
        assert!(dispatch_hackthecart_static("NotAThing.new", &[]).is_none());
    }

    #[test]
    fn crawl_queue_push_pop_roundtrip() {
        // Regression: push/pop must operate a REAL in-process queue — a URL
        // pushed must come back out, and dup pushes must report false.
        let v = dispatch_hackthecart_static("CrawlQueue.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);

        let r = dispatch_hackthecart_method(
            &bh,
            "push",
            &[Value::String("https://example.com/p1".into())],
        )
        .expect("dispatched")
        .expect("ok");
        assert!(matches!(r, Value::Bool(true)), "first push must succeed");

        // Duplicate push → false (dedup), not a silent true.
        let r = dispatch_hackthecart_method(
            &bh,
            "push",
            &[Value::String("https://example.com/p1".into())],
        )
        .expect("dispatched")
        .expect("ok");
        assert!(matches!(r, Value::Bool(false)), "duplicate push must report false");

        let r = dispatch_hackthecart_method(&bh, "len", &[])
            .expect("dispatched")
            .expect("ok");
        assert!(matches!(r, Value::Int(1)));

        let r = dispatch_hackthecart_method(&bh, "pop", &[])
            .expect("dispatched")
            .expect("ok");
        match r {
            Value::Struct { name, fields } => {
                assert_eq!(name, "CrawlJob");
                assert!(fields.iter().any(|(k, v)| k == "url"
                    && matches!(v, Value::String(u) if u == "https://example.com/p1")));
            }
            other => panic!("expected CrawlJob struct, got {other:?}"),
        }

        let r = dispatch_hackthecart_method(&bh, "is_empty", &[])
            .expect("dispatched")
            .expect("ok");
        assert!(matches!(r, Value::Bool(true)), "queue drained after pop");
    }

    #[test]
    fn job_queue_enqueue_dequeue_roundtrip() {
        let v = dispatch_hackthecart_static("JobQueue.new", &[Value::Int(100)])
            .unwrap()
            .unwrap();
        let bh = unwrap_browser_handle(v);
        let r = dispatch_hackthecart_method(
            &bh,
            "enqueue",
            &[
                Value::String("ScrapePage".into()),
                Value::String("{\"url\":\"https://example.com/\"}".into()),
            ],
        )
        .expect("dispatched")
        .expect("ok");
        assert!(matches!(r, Value::Bool(true)));

        let r = dispatch_hackthecart_method(&bh, "dequeue", &[Value::String("w1".into())])
            .expect("dispatched")
            .expect("ok");
        match r {
            Value::Struct { name, fields } => {
                assert_eq!(name, "Job");
                assert!(fields.iter().any(|(k, v)| k == "job_type"
                    && matches!(v, Value::String(t) if t == "ScrapePage")));
                assert!(fields.iter().any(|(k, _)| k == "id"));
            }
            other => panic!("expected Job struct, got {other:?}"),
        }
    }

    #[test]
    fn smart_extractor_extract_is_wired() {
        // Regression: SmartExtractor must call the real extraction cascade,
        // not return a type-tag error.
        let v = dispatch_hackthecart_static("SmartExtractor.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);
        let html = r#"<html><head>
<script type="application/ld+json">
{"@type":"Product","name":"Echo Dot (5th Gen)","offers":{"price":"49.99","priceCurrency":"USD"}}
</script></head><body></body></html>"#;
        let r = dispatch_hackthecart_method(&bh, "extract", &[Value::String(html.into())])
            .expect("dispatched")
            .expect("ok");
        match r {
            Value::Struct { name, fields } => {
                assert_eq!(name, "ExtractedProduct");
                assert!(fields.iter().any(|(k, v)| k == "extraction_method"
                    && matches!(v, Value::String(m) if m == "JsonLd")));
                assert!(fields.iter().any(|(k, v)| k == "price_cents"
                    && matches!(v, Value::Int(c) if *c == 4999)));
            }
            other => panic!("expected ExtractedProduct struct, got {other:?}"),
        }
    }

    #[test]
    fn rust_only_methods_return_honest_errors() {
        // QualityValidator.validate takes Rust-only types — must error with a
        // clear message, never fake success.
        let v = dispatch_hackthecart_static("QualityValidator.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);
        let r = dispatch_hackthecart_method(&bh, "validate", &[])
            .expect("dispatched");
        assert!(r.is_err(), "validate must be an honest error, not fake success");

        // SitemapParser.parse is stateless and wired — must succeed.
        let v = dispatch_hackthecart_static("SitemapParser.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);
        let xml = r#"<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://example.com/a</loc></url></urlset>"#;
        let r = dispatch_hackthecart_method(&bh, "parse", &[Value::String(xml.into())])
            .expect("dispatched")
            .expect("ok");
        match r {
            Value::Array(items) => assert_eq!(items.len(), 1),
            other => panic!("expected sitemap entries array, got {other:?}"),
        }
    }

    #[test]
    fn triangulator_triangulate_requires_real_observations() {
        // Regression (R2-5-HTC / R2-6): the arm used to discard its input and
        // triangulate over an empty slice, fabricating a consensus over zero
        // observations. Missing/empty/malformed input must now be an honest
        // error, never a silent empty call.
        let v = dispatch_hackthecart_static("Triangulator.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);

        // No observations argument at all.
        let r = dispatch_hackthecart_method(&bh, "triangulate", &[]).expect("dispatched");
        assert!(r.is_err(), "missing observations must be an honest error");

        // Empty array.
        let r =
            dispatch_hackthecart_method(&bh, "triangulate", &[Value::Array(vec![])])
                .expect("dispatched");
        assert!(r.is_err(), "empty observations must be an honest error");

        // Not an array.
        let r =
            dispatch_hackthecart_method(&bh, "triangulate", &[Value::String("nope".into())])
                .expect("dispatched");
        assert!(r.is_err(), "non-array observations must be an honest error");

        // Observation missing the required 'source' field.
        let r = dispatch_hackthecart_method(
            &bh,
            "triangulate",
            &[Value::Array(vec![Value::Struct {
                name: "SourceObservation".to_string(),
                fields: vec![("price_cents".to_string(), Value::Int(499))],
            }])],
        )
        .expect("dispatched");
        assert!(
            r.is_err(),
            "an observation without 'source' must be an honest error"
        );
    }

    #[test]
    fn triangulator_triangulate_uses_passed_observations() {
        // Regression (R2-5-HTC): the consensus must be computed from the
        // observations actually passed in (Struct and Map forms both work).
        let v = dispatch_hackthecart_static("Triangulator.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i128;

        let obs_struct = |source: &str, price: i128| Value::Struct {
            name: "SourceObservation".to_string(),
            fields: vec![
                ("source".to_string(), Value::String(source.to_string())),
                ("price_cents".to_string(), Value::Int(price)),
                ("observed_at".to_string(), Value::Int(now)),
            ],
        };
        // Map form is accepted too, with `confidence` defaulted to 1.0.
        let obs_map = Value::Map(vec![
            (
                Value::String("source".to_string()),
                Value::String("walmart_api".to_string()),
            ),
            (
                Value::String("price_cents".to_string()),
                Value::Int(501),
            ),
            (
                Value::String("observed_at".to_string()),
                Value::Int(now),
            ),
        ]);

        let r = dispatch_hackthecart_method(
            &bh,
            "triangulate",
            &[Value::Array(vec![
                obs_struct("kroger_api", 499),
                obs_map,
            ])],
        )
        .expect("dispatched")
        .expect("ok");
        match r {
            Value::Struct { name, fields } => {
                assert_eq!(name, "TriangulationResult");
                let get = |k: &str| fields.iter().find(|(f, _)| f == k).map(|(_, v)| v);
                assert!(
                    matches!(get("agreement_count"), Some(Value::Int(2))),
                    "two agreeing observations must both count"
                );
                let consensus = match get("consensus_price_cents") {
                    Some(Value::Int(c)) => *c,
                    other => panic!("expected Int consensus, got {other:?}"),
                };
                assert!(
                    (499..=501).contains(&consensus),
                    "consensus {consensus} must be derived from the passed observations"
                );
                match get("confidence") {
                    Some(Value::Float(c)) => {
                        assert!(*c > 0.5, "two agreeing sources → confident, got {c}")
                    }
                    other => panic!("expected Float confidence, got {other:?}"),
                }
            }
            other => panic!("expected TriangulationResult struct, got {other:?}"),
        }
    }
}
