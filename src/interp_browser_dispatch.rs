//! Browser helper-module dispatcher for the Tallow interpreter.
//!
//! Surfaces 18 browser/* helper modules to Tallow scripts via static
//! dotted-name calls (e.g. `ProductMatcher.new()`).
//!
//! The interpreter routes unknown builtin names through
//! [`dispatch_browser_static`]. Constructors return a `Value::BrowserObject`
//! whose `kind` is the type name and whose `handle` is the wrapped Rust
//! object. Instance methods on those objects are routed via
//! [`dispatch_browser_method`] from the method-call dispatcher.
//!
//! Scope: this is a *surfacing* layer. Constructors are wired for the 18
//! modules that have real methods behind them. The other 25 kinds were
//! constructor-only (every method refused with "not yet dispatched") and were
//! removed on 2026-10-17 — they now resolve as unknown builtins instead of
//! handing scripts an object that cannot do anything. The crawl engine is
//! reachable from scripts: `CrawlQueue` push/pop operate a real in-process
//! queue, `AdaptiveCrawler.fetch` / `CrawlPipeline.fetch` run the real HTTP
//! crawl path, `JobQueue` enqueue/dequeue/ack/nack drive the real in-memory
//! queue, and the extractors (`SmartExtractor`, `SitemapParser`,
//! `SchemaExtractor`, `StructuredDataExtractor`, `SelfHealingSelector`,
//! `RecipeParser`, `UnitNormalizer`) call their real implementations.
//!
//! Methods whose inputs are Rust-only types (e.g. `StealthProfile`,
//! `PriceObservation`) return an honest `Err` explaining why — never a fake
//! success. An unknown method on a live kind falls through to the normal
//! unknown-method diagnostic.
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
/// Uses the SAME runtime that owns the interpreter's browser objects
/// (`interp::get_browser_runtime`). This is load-bearing, not tidiness:
/// `CdpClient::connect` spawns its WebSocket read loop as a task on whichever
/// runtime is current at connect time, and that task is what routes every
/// command reply. Driving a `Page` from a *second* runtime writes the command
/// but never polls the reader, so `Page.navigate`'s reply never arrives and
/// every `Runtime.evaluate` goes unanswered — while Chrome happily loads the
/// page. That was register #105: 5 s command timeout, then a 90 s navigation
/// timeout in which every readiness poll reported `answered=false`.
///
/// The `Handle::try_current` branch covers a caller that is already inside a
/// runtime (re-entering a runtime by `block_on` panics).
fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        handle.block_on(fut)
    } else {
        crate::interp::get_browser_runtime().block_on(fut)
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
/// Extract an optional `Page` from the arguments after the URL (register #32).
///
/// `Ok(None)` when the caller passes nothing (HTTP-only, unchanged behaviour),
/// `Ok(Some(page))` when it passes the handle `Browser.new_page()` returned,
/// and an error message otherwise — a silently-ignored wrong argument would
/// put the caller back in the "no browser page available" path with no
/// explanation of why the page it passed had no effect.
fn browser_page_arg(rest: &[Value]) -> Result<Option<&crate::browser::Page>, String> {
    match rest.first() {
        None | Some(Value::Nil) => Ok(None),
        Some(Value::BrowserObject(bh)) if bh.kind == "Page" => bh
            .handle
            .downcast_ref::<crate::browser::Page>()
            .map(Some)
            .ok_or_else(|| "invalid page handle".to_string()),
        Some(other) => Err(format!(
            "fetch(url, page) expects a Page from Browser.new_page(), got {}",
            crate::interp::type_name(other)
        )),
    }
}

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

/// A required field of a Map/Struct argument. Missing is an error naming the
/// field, never a fabricated default.
fn require_field<'a>(
    v: &'a Value,
    key: &str,
    context: &str,
) -> Result<&'a Value, RuntimeError> {
    tagged_field(v, key).ok_or_else(|| {
        RuntimeError::Error(format!("{context}: missing required field `{key}`"))
    })
}

fn field_string(v: &Value, key: &str) -> Option<String> {
    match tagged_field(v, key) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn field_i64(v: &Value, key: &str) -> Option<i64> {
    tagged_field(v, key).and_then(value_as_i64)
}

fn field_f64(v: &Value, key: &str) -> Option<f64> {
    tagged_field(v, key).and_then(value_as_f64)
}

fn field_string_array(v: &Value, key: &str) -> Option<Vec<String>> {
    match tagged_field(v, key) {
        Some(Value::Array(items)) => Some(
            items
                .iter()
                .filter_map(|item| match item {
                    Value::String(s) => Some(s.clone()),
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    }
}

/// Build a `PriceObservation` from a Map/Struct. Every field is required:
/// the validator's job is to judge real data, not to judge defaults this
/// bridge invented.
fn price_observation_from_value(v: &Value) -> Result<browser::quality_validator::PriceObservation, RuntimeError> {
    let context = "QualityValidator.validate(observation)";
    if !matches!(v, Value::Map(_) | Value::Struct { .. }) {
        return Err(RuntimeError::Error(format!(
            "{context}: expected a Map/Struct, got {}",
            value_kind(v)
        )));
    }
    Ok(browser::quality_validator::PriceObservation {
        sku: require_field(v, "sku", context)?.as_string(),
        canonical_id: value_as_i64(require_field(v, "canonical_id", context)?)
            .ok_or_else(|| RuntimeError::Error(format!("{context}: canonical_id must be an Int")))?,
        store_id: value_as_i64(require_field(v, "store_id", context)?)
            .ok_or_else(|| RuntimeError::Error(format!("{context}: store_id must be an Int")))?,
        source: require_field(v, "source", context)?.as_string(),
        category: require_field(v, "category", context)?.as_string(),
        price_cents: value_as_i64(require_field(v, "price_cents", context)?)
            .ok_or_else(|| RuntimeError::Error(format!("{context}: price_cents must be an Int")))?,
        raw_price_string: require_field(v, "raw_price_string", context)?.as_string(),
        currency: require_field(v, "currency", context)?.as_string(),
        url: require_field(v, "url", context)?.as_string(),
        observed_at: value_as_i64(require_field(v, "observed_at", context)?)
            .ok_or_else(|| RuntimeError::Error(format!("{context}: observed_at must be an Int (unix seconds)")))?,
        batch_id: require_field(v, "batch_id", context)?.as_string(),
    })
}

fn canonical_product_from_value(
    v: &Value,
) -> Result<browser::quality_validator::CanonicalProduct, RuntimeError> {
    let context = "QualityValidator.validate(product)";
    if !matches!(v, Value::Map(_) | Value::Struct { .. }) {
        return Err(RuntimeError::Error(format!(
            "{context}: expected a Map/Struct, got {}",
            value_kind(v)
        )));
    }
    Ok(browser::quality_validator::CanonicalProduct {
        canonical_id: value_as_i64(require_field(v, "canonical_id", context)?)
            .ok_or_else(|| RuntimeError::Error(format!("{context}: canonical_id must be an Int")))?,
        category: require_field(v, "category", context)?.as_string(),
        title: require_field(v, "title", context)?.as_string(),
    })
}

fn required_int(v: &Value, key: &str, context: &str) -> Result<i64, RuntimeError> {
    value_as_i64(require_field(v, key, context)?)
        .ok_or_else(|| RuntimeError::Error(format!("{context}: `{key}` must be an Int")))
}

fn required_f64(v: &Value, key: &str, context: &str) -> Result<f64, RuntimeError> {
    value_as_f64(require_field(v, key, context)?)
        .ok_or_else(|| RuntimeError::Error(format!("{context}: `{key}` must be a Float")))
}

fn required_string(v: &Value, key: &str, context: &str) -> Result<String, RuntimeError> {
    match require_field(v, key, context)? {
        Value::String(s) => Ok(s.clone()),
        other => Err(RuntimeError::Error(format!(
            "{context}: `{key}` must be a String, got {}",
            value_kind(other)
        ))),
    }
}

/// Build (recipe, catalog, zip, radius, stop limit) from one config map.
///
/// Shape:
/// ```text
/// {
///   zip, zip_lat, zip_lon,
///   max_distance_mi?, max_stores?,
///   title?, servings?,
///   ingredients: [{ item, quantity?, unit?, preparation?, optional?, raw_text? }],
///   stores:      [{ store_id, name, lat, lon }],
///   listings:    [{ store_id, store_listing_id, canonical_id, canonical_name,
///                   product_name, price_cents, unit_price_cents,
///                   pack_size_text?, image_url? }],
/// }
/// ```
fn basket_config_from_value(
    v: &Value,
) -> Result<
    (
        browser::recipe_parser::Recipe,
        browser::basket_optimizer::ProductDb,
        String,
        f64,
        u8,
    ),
    RuntimeError,
> {
    use browser::basket_optimizer::{ProductDb, StoreInfo, StoreListing};

    let context = "BasketOptimizer.optimize(config)";
    if !matches!(v, Value::Map(_) | Value::Struct { .. }) {
        return Err(RuntimeError::Error(format!(
            "{context}: expected a Map/Struct, got {}",
            value_kind(v)
        )));
    }

    let zip = required_string(v, "zip", context)?;
    let zip_lat = required_f64(v, "zip_lat", context)?;
    let zip_lon = required_f64(v, "zip_lon", context)?;
    let max_distance_mi = field_f64(v, "max_distance_mi").unwrap_or(10.0);
    if !(max_distance_mi.is_finite() && max_distance_mi > 0.0) {
        return Err(RuntimeError::Error(format!(
            "{context}: `max_distance_mi` must be a positive finite Float"
        )));
    }
    let max_stores_raw = field_i64(v, "max_stores").unwrap_or(3);
    if !(0..=u8::MAX as i64).contains(&max_stores_raw) {
        return Err(RuntimeError::Error(format!(
            "{context}: `max_stores` must be an Int in 0..=255"
        )));
    }
    let max_stores = max_stores_raw as u8;

    let Some(Value::Array(ingredient_items)) = tagged_field(v, "ingredients") else {
        return Err(RuntimeError::Error(format!(
            "{context}: `ingredients` must be an Array"
        )));
    };
    let mut ingredients = Vec::with_capacity(ingredient_items.len());
    for (index, item) in ingredient_items.iter().enumerate() {
        let item_context = format!("ingredients[{index}]");
        if !matches!(item, Value::Map(_) | Value::Struct { .. }) {
            return Err(RuntimeError::Error(format!(
                "{item_context}: expected a Map/Struct"
            )));
        }
        let item_name = required_string(item, "item", &item_context)?;
        ingredients.push(browser::recipe_parser::Ingredient {
            raw_text: field_string(item, "raw_text").unwrap_or_else(|| item_name.clone()),
            quantity: field_f64(item, "quantity"),
            unit: field_string(item, "unit"),
            item: item_name,
            preparation: field_string(item, "preparation"),
            optional: matches!(tagged_field(item, "optional"), Some(Value::Bool(true))),
        });
    }

    let mut db = ProductDb::new();
    db.set_zip_coords(&zip, zip_lat, zip_lon);

    let Some(Value::Array(store_items)) = tagged_field(v, "stores") else {
        return Err(RuntimeError::Error(format!(
            "{context}: `stores` must be an Array"
        )));
    };
    for (index, store) in store_items.iter().enumerate() {
        let store_context = format!("stores[{index}]");
        if !matches!(store, Value::Map(_) | Value::Struct { .. }) {
            return Err(RuntimeError::Error(format!(
                "{store_context}: expected a Map/Struct"
            )));
        }
        db.add_store(StoreInfo {
            store_id: required_int(store, "store_id", &store_context)?,
            name: required_string(store, "name", &store_context)?,
            distance_mi: 0.0,
            lat: required_f64(store, "lat", &store_context)?,
            lon: required_f64(store, "lon", &store_context)?,
        });
    }

    let Some(Value::Array(listing_items)) = tagged_field(v, "listings") else {
        return Err(RuntimeError::Error(format!(
            "{context}: `listings` must be an Array"
        )));
    };
    for (index, listing) in listing_items.iter().enumerate() {
        let listing_context = format!("listings[{index}]");
        if !matches!(listing, Value::Map(_) | Value::Struct { .. }) {
            return Err(RuntimeError::Error(format!(
                "{listing_context}: expected a Map/Struct"
            )));
        }
        let store_id = required_int(listing, "store_id", &listing_context)?;
        db.add_listing(
            store_id,
            StoreListing {
                store_listing_id: required_int(listing, "store_listing_id", &listing_context)?,
                canonical_id: required_int(listing, "canonical_id", &listing_context)?,
                canonical_name: required_string(listing, "canonical_name", &listing_context)?,
                product_name: required_string(listing, "product_name", &listing_context)?,
                price_cents: required_int(listing, "price_cents", &listing_context)?,
                unit_price_cents: required_int(listing, "unit_price_cents", &listing_context)?,
                pack_size_text: field_string(listing, "pack_size_text").unwrap_or_default(),
                image_url: field_string(listing, "image_url"),
            },
        );
    }

    let servings = field_i64(v, "servings").unwrap_or(1);
    if !(0..=i32::MAX as i64).contains(&servings) {
        return Err(RuntimeError::Error(format!(
            "{context}: `servings` must be an Int in 0..=2147483647"
        )));
    }
    let recipe = browser::recipe_parser::Recipe {
        title: field_string(v, "title").unwrap_or_else(|| "Untitled".to_string()),
        servings: servings as i32,
        prep_time_minutes: None,
        cook_time_minutes: None,
        ingredients,
        instructions: Vec::new(),
        source_url: None,
        image_url: None,
    };

    Ok((recipe, db, zip, max_distance_mi, max_stores))
}

fn basket_item_to_value(item: &browser::basket_optimizer::BasketItem) -> Value {
    Value::Struct {
        name: "BasketItem".to_string(),
        fields: vec![
            (
                "ingredient".to_string(),
                Value::String(item.ingredient.clone()),
            ),
            (
                "product_name".to_string(),
                Value::String(item.product_name.clone()),
            ),
            ("price_cents".to_string(), Value::Int(item.price_cents as i128)),
            (
                "unit_price_cents".to_string(),
                Value::Int(item.unit_price_cents as i128),
            ),
            (
                "quantity_needed".to_string(),
                Value::Float(item.quantity_needed),
            ),
            (
                "quantity_unit".to_string(),
                Value::String(item.quantity_unit.clone()),
            ),
            (
                "image_url".to_string(),
                match &item.image_url {
                    Some(url) => Value::String(url.clone()),
                    None => Value::Nil,
                },
            ),
        ],
    }
}

fn substitution_to_value(sub: &browser::basket_optimizer::Substitution) -> Value {
    Value::Struct {
        name: "Substitution".to_string(),
        fields: vec![
            ("original".to_string(), Value::String(sub.original.clone())),
            (
                "substitute".to_string(),
                Value::String(sub.substitute.clone()),
            ),
            ("reason".to_string(), Value::String(sub.reason.clone())),
            (
                "price_delta_cents".to_string(),
                Value::Int(sub.price_delta_cents as i128),
            ),
        ],
    }
}

fn basket_to_value(basket: &browser::basket_optimizer::Basket) -> Value {
    Value::Struct {
        name: "Basket".to_string(),
        fields: vec![
            (
                "items".to_string(),
                Value::Array(basket.items.iter().map(basket_item_to_value).collect()),
            ),
            (
                "total_cents".to_string(),
                Value::Int(basket.total_cents as i128),
            ),
            ("store".to_string(), Value::String(basket.store.clone())),
            ("store_id".to_string(), Value::Int(basket.store_id as i128)),
            ("distance_mi".to_string(), Value::Float(basket.distance_mi)),
            (
                "missing_items".to_string(),
                Value::Array(
                    basket
                        .missing_items
                        .iter()
                        .map(|item| Value::String(item.clone()))
                        .collect(),
                ),
            ),
            (
                "substitutions".to_string(),
                Value::Array(basket.substitutions.iter().map(substitution_to_value).collect()),
            ),
        ],
    }
}

fn basket_result_to_value(result: &browser::basket_optimizer::OptimizationResult) -> Value {
    let split = match &result.split_basket {
        Some(split) => Value::Struct {
            name: "SplitBasket".to_string(),
            fields: vec![
                (
                    "stores".to_string(),
                    Value::Array(split.stores.iter().map(basket_to_value).collect()),
                ),
                ("total_cents".to_string(), Value::Int(split.total_cents as i128)),
                (
                    "savings_vs_cheapest_single".to_string(),
                    Value::Int(split.savings_vs_cheapest_single as i128),
                ),
                ("extra_stops".to_string(), Value::Int(split.extra_stops as i128)),
            ],
        },
        None => Value::Nil,
    };
    Value::Struct {
        name: "OptimizationResult".to_string(),
        fields: vec![
            (
                "single_store_baskets".to_string(),
                Value::Array(
                    result
                        .single_store_baskets
                        .iter()
                        .map(basket_to_value)
                        .collect(),
                ),
            ),
            ("split_basket".to_string(), split),
            (
                "cheapest_single".to_string(),
                basket_to_value(&result.cheapest_single),
            ),
            (
                "closest_with_all_items".to_string(),
                match &result.closest_with_all_items {
                    Some(basket) => basket_to_value(basket),
                    None => Value::Nil,
                },
            ),
        ],
    }
}

/// Build a `StealthProfile` from a Map/Struct. Absent fields keep the
/// Chrome-on-Windows preset value, so a partial profile is a real profile with
/// documented defaults rather than a zeroed one that fails every check.
fn stealth_profile_from_value(
    v: &Value,
) -> Result<browser::stealth::StealthProfile, RuntimeError> {
    let context = "FingerprintValidator.validate(profile)";
    if !matches!(v, Value::Map(_) | Value::Struct { .. }) {
        return Err(RuntimeError::Error(format!(
            "{context}: expected a Map/Struct, got {}",
            value_kind(v)
        )));
    }
    let mut profile = browser::stealth::StealthProfile::chrome_windows();
    if let Some(value) = field_string(v, "user_agent") {
        profile.user_agent = value;
    }
    if let Some(value) = field_string(v, "platform") {
        profile.platform = value;
    }
    if let Some(value) = field_string(v, "vendor") {
        profile.vendor = value;
    }
    if let Some(value) = field_string_array(v, "languages") {
        profile.languages = value;
    }
    if let Some(value) = field_i64(v, "hardware_concurrency") {
        profile.hardware_concurrency = value.max(0) as u32;
    }
    if let Some(value) = field_f64(v, "device_memory") {
        profile.device_memory = value;
    }
    if let Some(value) = field_i64(v, "max_touch_points") {
        profile.max_touch_points = value.max(0) as u32;
    }
    if let Some(Value::Array(pair)) = tagged_field(v, "viewport") {
        if let (Some(width), Some(height)) = (
            pair.first().and_then(value_as_i64),
            pair.get(1).and_then(value_as_i64),
        ) {
            profile.viewport = (width.max(0) as u32, height.max(0) as u32);
        }
    }
    if let Some(value) = field_f64(v, "device_scale_factor") {
        profile.device_scale_factor = value;
    }
    if let Some(value) = field_string(v, "webgl_vendor") {
        profile.webgl_vendor = value;
    }
    if let Some(value) = field_string(v, "webgl_renderer") {
        profile.webgl_renderer = value;
    }
    if let Some(value) = field_string(v, "timezone") {
        profile.timezone = value;
    }
    if let Some(value) = field_string(v, "locale") {
        profile.locale = value;
    }
    if let Some(value) = field_i64(v, "canvas_noise_seed") {
        profile.canvas_noise_seed = value.max(0) as u64;
    }
    if let Some(Value::Bool(value)) = tagged_field(v, "is_firefox_profile") {
        profile.is_firefox_profile = *value;
    }
    Ok(profile)
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
/// Returns `Some(result)` if `name` matches a Tallow builtin, otherwise
/// `None` so the caller can fall through to other dispatchers.
/// True when `name` is one of the static entries this dispatcher serves.
///
/// The interpreter's method-call path needs this **before** evaluating
/// arguments: `AdaptiveCrawler.new()` is a static namespace call, not a method
/// on a value, and args must not be evaluated twice when it turns out not to
/// be one.
pub fn is_browser_static(name: &str) -> bool {
    matches!(
        name,
          "AdaptiveCrawler.new"
        | "BasketOptimizer.new"
        | "CanaryRegistry.new"
        | "CircuitBreaker.new"
        | "CrawlPipeline.new"
        | "CrawlQueue.new"
        | "FingerprintValidator.new"
        | "JobQueue.new"
        | "PriceBoundsRegistry.new"
        | "PriceHistoryEngine.new"
        | "ProductMatcher.new"
        | "QualityValidator.new"
        | "RecipeParser.new"
        | "SchemaExtractor.new"
        | "SelectorChain.new"
        | "SelfHealingSelector.new"
        | "SitemapParser.new"
        | "SmartExtractor.new"
        | "StructuredDataExtractor.new"
        | "Triangulator.new"
        | "UnitNormalizer.new"
    )
}

pub fn dispatch_browser_static(
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
        "BasketOptimizer.new" => ok(obj(
            "BasketOptimizer",
            browser::basket_optimizer::BasketOptimizer::new(),
        )),
        "PriceHistoryEngine.new" => ok(obj(
            "PriceHistoryEngine",
            Mutex::new(browser::price_history::PriceHistoryEngine::new()),
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
        "CircuitBreaker.new" => {
            let target = args.first().map(|v| v.as_string()).unwrap_or_default();
            ok(obj(
                "CircuitBreaker",
                Mutex::new(browser::circuit_breaker::CircuitBreaker::new(&target)),
            ))
        }
        "JobQueue.new" => {
            let bp = match args.first() {
                Some(Value::Int(i)) => *i as usize,
                _ => 10_000,
            };
            ok(obj("JobQueue", browser::job_queue::JobQueue::new(bp)))
        }
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
        _ => return None,
    };
    Some(Ok(result))
}

/// Instance method dispatch for Tallow-wrapped objects.
///
/// Called from the method-call dispatcher when the object is a
/// `BrowserObject` whose `kind` is one of the Tallow type tags but the
/// existing browser dispatch didn't recognize the method.
///
/// Wired methods call the real browser implementations (crawl queue, crawl
/// engine fetch, job queue, extractors). Methods whose inputs are Rust-only
/// types return an honest `Err` naming the Rust API to use instead. An
/// unwired method on a live kind returns a clear "not wired" error — never a
/// fake success.
pub fn dispatch_browser_method(
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
            let listing = match args.first() {
                Some(value) if matches!(value, Value::Map(_) | Value::Struct { .. }) => {
                    let text = |key: &str| tagged_field(value, key).map(|v| v.as_string());
                    browser::product_matcher::ScrapedListing {
                        title: text("title").unwrap_or_default(),
                        upc: text("upc"),
                        gtin: text("gtin"),
                        price_cents: tagged_field(value, "price_cents")
                            .and_then(value_as_i64)
                            .unwrap_or(0),
                        image_url: text("image_url"),
                        size_text: text("size_text").or_else(|| text("size")),
                        brand_text: text("brand_text").or_else(|| text("brand")),
                        source: text("source").unwrap_or_else(|| "interp".to_string()),
                    }
                }
                _ => {
                    let title = args.first().map(|v| v.as_string()).unwrap_or_default();
                    let brand = args.get(1).map(|v| v.as_string()).unwrap_or_default();
                    let size = args.get(2).map(|v| v.as_string());
                    let _unit = args.get(3).map(|v| v.as_string());
                    browser::product_matcher::ScrapedListing {
                        title,
                        upc: None,
                        gtin: None,
                        price_cents: 0,
                        image_url: None,
                        size_text: size,
                        brand_text: Some(brand),
                        source: "interp".to_string(),
                    }
                }
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
            // R2-5 / R2-6: observations are marshalled from Tallow values.
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
            let result = match args.get(1) {
                Some(value) => {
                    let Some(threshold) = value_as_f64(value) else {
                        return Some(Err(RuntimeError::Error(format!(
                            "Triangulator.triangulate: deviation_threshold must be a Float in 0.0..=1.0, got {}",
                            value_kind(value)
                        ))));
                    };
                    if !(0.0..=1.0).contains(&threshold) {
                        return Some(Err(RuntimeError::Error(format!(
                            "Triangulator.triangulate: deviation_threshold {threshold} is outside 0.0..=1.0"
                        ))));
                    }
                    tri.triangulate_with_threshold(&observations, threshold)
                }
                None => tri.triangulate(&observations),
            };
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
            // Stateless form: build a transient ProductDb from the config map,
            // so one script call never mutates the receiver's catalog.
            let Some(config) = args.first() else {
                return Some(Err(RuntimeError::Error(
                    "BasketOptimizer.optimize expects one Map/Struct config".to_string(),
                )));
            };
            let (recipe, db, zip, max_distance_mi, max_stores) =
                match basket_config_from_value(config) {
                    Ok(parsed) => parsed,
                    Err(err) => return Some(Err(err)),
                };
            let optimizer = browser::basket_optimizer::BasketOptimizer::with_db(db);
            let result = optimizer.optimize(&recipe, &zip, max_distance_mi, max_stores);
            return Some(Ok(basket_result_to_value(&result)));
        }

        ("QualityValidator", "validate") => {
            let validator = bh
                .handle
                .downcast_ref::<browser::quality_validator::QualityValidator>()?;
            let (Some(observation_value), Some(product_value)) = (args.first(), args.get(1)) else {
                return Some(Err(RuntimeError::Error(
                    "QualityValidator.validate expects (observation, product): two Map/Struct values".to_string(),
                )));
            };
            let observation = match price_observation_from_value(observation_value) {
                Ok(value) => value,
                Err(err) => return Some(Err(err)),
            };
            let product = match canonical_product_from_value(product_value) {
                Ok(value) => value,
                Err(err) => return Some(Err(err)),
            };
            let result = validator.validate(&observation, &product);
            return Some(Ok(Value::Struct {
                name: "ValidationResult".to_string(),
                fields: vec![
                    (
                        "status".to_string(),
                        Value::String(format!("{:?}", result.status)),
                    ),
                    (
                        "warnings".to_string(),
                        Value::Array(result.warnings.into_iter().map(Value::String).collect()),
                    ),
                    (
                        "errors".to_string(),
                        Value::Array(result.errors.into_iter().map(Value::String).collect()),
                    ),
                    (
                        "confidence_adjustment".to_string(),
                        Value::Float(result.confidence_adjustment),
                    ),
                ],
            }));
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
            // Register #32: escalation was implemented in Rust but unreachable
            // from Tallow — the `page` argument was hard-wired to `None`, so a
            // JS-rendered page could only ever return the "no browser page
            // available" error. Accept the Page handle the caller already got
            // from `Browser.new_page()` and hand it to the crawler.
            let page_arg = match browser_page_arg(&args[1..]) {
                Ok(p) => p,
                Err(msg) => return Some(Ok(Value::Err(Box::new(Value::String(msg))))),
            };
            let result = block_on(crawler.fetch(&url, page_arg));
            // The language-level return type is `Result<CrawlResult, String>`
            // (every error path below returns `Value::Err`), so success must be
            // `Value::Ok` — a bare `Struct` matches neither arm of
            // `match c.fetch(...) { Ok(r) -> …, Err(e) -> … }` and the
            // interpreter aborts with "non-exhaustive match".
            return Some(Ok(match result {
                Ok(cr) => Value::Ok(Box::new(crawl_result_to_value(&cr))),
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
            // Register #32: same escalation gap as AdaptiveCrawler above;
            // retries/backoff remain governed by the pipeline's RetryConfig.
            let page_arg = match browser_page_arg(&args[1..]) {
                Ok(p) => p,
                Err(msg) => return Some(Ok(Value::Err(Box::new(Value::String(msg))))),
            };
            let result = block_on(guard.fetch(&url, page_arg));
            // Same Result contract as AdaptiveCrawler.fetch above.
            return Some(Ok(match result {
                Ok(cr) => Value::Ok(Box::new(crawl_result_to_value(&cr))),
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
            let Some(value) = args.first() else {
                return Some(Err(RuntimeError::Error(
                    "FingerprintValidator.validate expects a profile Map/Struct (absent fields keep the Chrome-on-Windows preset)".to_string(),
                )));
            };
            let profile = match stealth_profile_from_value(value) {
                Ok(profile) => profile,
                Err(err) => return Some(Err(err)),
            };
            let warnings = browser::fingerprint_validator::FingerprintValidator::validate(&profile);
            let items: Vec<Value> = warnings
                .into_iter()
                .map(|warning| Value::Struct {
                    name: "FingerprintWarning".to_string(),
                    fields: vec![
                        (
                            "severity".to_string(),
                            Value::String(format!("{:?}", warning.severity)),
                        ),
                        (
                            "vectors".to_string(),
                            Value::Array(
                                warning
                                    .vectors
                                    .iter()
                                    .map(|vector| Value::String((*vector).to_string()))
                                    .collect(),
                            ),
                        ),
                        ("message".to_string(), Value::String(warning.message)),
                    ],
                })
                .collect();
            return Some(Ok(Value::Array(items)));
        }

        _ => {}
    }

    // Live kinds only: the 25 constructor-only kinds were pruned 2026-10-17.
    const KNOWN: &[&str] = &[
        "ProductMatcher",
        "QualityValidator",
        "Triangulator",
        "SmartExtractor",
        "CircuitBreaker",
        "UnitNormalizer",
        "RecipeParser",
        "BasketOptimizer",
        "PriceHistoryEngine",
        "JobQueue",
        "AdaptiveCrawler",
        "CrawlQueue",
        "CrawlPipeline",
        "SitemapParser",
        "FingerprintValidator",
        "SchemaExtractor",
        "StructuredDataExtractor",
        "SelfHealingSelector",
    ];

    if !KNOWN.contains(&kind) {
        return None;
    }

    Some(Err(RuntimeError::Error(format!(
        "Tallow method not wired: {kind}.{method}() — this kind exists but has no Tallow binding for that method"
    ))))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn product_matcher_new_returns_object() {
        let r = dispatch_browser_static("ProductMatcher.new", &[])
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
        let v = dispatch_browser_static("ProductMatcher.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);
        let r = dispatch_browser_method(
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
    fn product_matcher_accepts_full_listing_map() {
        let v = dispatch_browser_static("ProductMatcher.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);
        let listing = Value::Map(vec![
            (
                Value::String("title".to_string()),
                Value::String("Acme Cola 12 oz".to_string()),
            ),
            (
                Value::String("upc".to_string()),
                Value::String("012345678905".to_string()),
            ),
            (
                Value::String("price_cents".to_string()),
                Value::Int(129),
            ),
            (
                Value::String("image_url".to_string()),
                Value::String("https://example.test/a.png".to_string()),
            ),
            (
                Value::String("brand".to_string()),
                Value::String("Acme".to_string()),
            ),
        ]);
        let r = dispatch_browser_method(&bh, "match_listing", &[listing])
            .expect("dispatched")
            .expect("ok");
        assert!(
            matches!(r, Value::Struct { ref name, .. } if name == "MatchResult"),
            "expected MatchResult, got {r:?}"
        );
    }

    #[test]
    fn triangulator_threshold_override_applies_per_call() {
        let v = dispatch_browser_static("Triangulator.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i128;
        let obs = |source: &str, price: i128| Value::Struct {
            name: "SourceObservation".to_string(),
            fields: vec![
                ("source".to_string(), Value::String(source.to_string())),
                ("price_cents".to_string(), Value::Int(price)),
                ("observed_at".to_string(), Value::Int(now)),
            ],
        };
        let observations = Value::Array(vec![
            obs("a", 10_000),
            obs("b", 20_000), // 100% spread: rejected at 0.20, admitted at 1.0
        ]);
        let consensus = |args: &[Value]| match dispatch_browser_method(&bh, "triangulate", args)
            .expect("dispatched")
            .expect("ok")
        {
            Value::Struct { fields, .. } => {
                let field_i = |name: &str| {
                    fields
                        .iter()
                        .find(|(k, _)| k == name)
                        .and_then(|(_, v)| match v {
                            Value::Int(i) => Some(*i),
                            _ => None,
                        })
                        .expect("int field")
                };
                (field_i("consensus_price_cents"), field_i("agreement_count"))
            }
            other => panic!("expected TriangulationResult, got {other:?}"),
        };

        let (default_consensus, default_agreement) = consensus(&[observations.clone()]);
        let (wide_consensus, wide_agreement) = consensus(&[observations, Value::Float(1.0)]);
        assert_eq!(default_agreement, 1, "the 100%-spread observation must be rejected by default");
        assert_eq!(wide_agreement, 2, "a 1.0 threshold must admit it");
        assert_eq!(default_consensus, 10_000);
        let _ = wide_consensus;
    }

    #[test]
    fn quality_validator_accepts_map_records() {
        let v = dispatch_browser_static("QualityValidator.new", &[])
            .unwrap()
            .unwrap();
        let bh = unwrap_browser_handle(v);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs() as i128;
        let observation = Value::Map(vec![
            (Value::String("sku".to_string()), Value::String("SKU-1".to_string())),
            (Value::String("canonical_id".to_string()), Value::Int(42)),
            (Value::String("store_id".to_string()), Value::Int(7)),
            (Value::String("source".to_string()), Value::String("test".to_string())),
            (Value::String("category".to_string()), Value::String("produce".to_string())),
            (Value::String("price_cents".to_string()), Value::Int(199)),
            (Value::String("raw_price_string".to_string()), Value::String("$1.99".to_string())),
            (Value::String("currency".to_string()), Value::String("USD".to_string())),
            (Value::String("url".to_string()), Value::String("https://example.test/p/1".to_string())),
            (Value::String("observed_at".to_string()), Value::Int(now)),
            (Value::String("batch_id".to_string()), Value::String("b1".to_string())),
        ]);
        let product = Value::Map(vec![
            (Value::String("canonical_id".to_string()), Value::Int(42)),
            (Value::String("category".to_string()), Value::String("produce".to_string())),
            (Value::String("title".to_string()), Value::String("Bananas".to_string())),
        ]);
        let r = dispatch_browser_method(&bh, "validate", &[observation, product])
            .expect("dispatched")
            .expect("ok");
        match r {
            Value::Struct { name, fields } => {
                assert_eq!(name, "ValidationResult");
                assert!(fields.iter().any(|(k, _)| k == "status"));
                assert!(fields.iter().any(|(k, _)| k == "errors"));
            }
            other => panic!("expected ValidationResult, got {other:?}"),
        }
    }

    #[test]
    fn fingerprint_validator_accepts_partial_profile() {
        let v = dispatch_browser_static("FingerprintValidator.new", &[])
            .unwrap()
            .unwrap();
        let bh = unwrap_browser_handle(v);
        let profile = Value::Map(vec![
            (
                Value::String("user_agent".to_string()),
                Value::String(
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/151.0.0.0 Safari/537.36"
                        .to_string(),
                ),
            ),
            (
                Value::String("platform".to_string()),
                Value::String("MacIntel".to_string()),
            ),
        ]);
        let r = dispatch_browser_method(&bh, "validate", &[profile])
            .expect("dispatched")
            .expect("ok");
        match r {
            Value::Array(items) => assert!(
                !items.is_empty(),
                "a Windows UA with platform MacIntel must produce at least one warning"
            ),
            other => panic!("expected an array of warnings, got {other:?}"),
        }
    }

    #[test]
    fn basket_optimizer_accepts_inline_catalog() {
        let v = dispatch_browser_static("BasketOptimizer.new", &[])
            .unwrap()
            .unwrap();
        let bh = unwrap_browser_handle(v);
        let store = |id: i64, name: &str, lat: f64| {
            Value::Map(vec![
                (Value::String("store_id".into()), Value::Int(id as i128)),
                (Value::String("name".into()), Value::String(name.into())),
                (Value::String("lat".into()), Value::Float(lat)),
                (Value::String("lon".into()), Value::Float(-74.0)),
            ])
        };
        let listing = |store_id: i64, id: i64, name: &str, price: i64| {
            Value::Map(vec![
                (Value::String("store_id".into()), Value::Int(store_id as i128)),
                (Value::String("store_listing_id".into()), Value::Int(id as i128)),
                (Value::String("canonical_id".into()), Value::Int((id * 10) as i128)),
                (Value::String("canonical_name".into()), Value::String(name.into())),
                (Value::String("product_name".into()), Value::String(format!("{name} brand"))),
                (Value::String("price_cents".into()), Value::Int(price as i128)),
                (Value::String("unit_price_cents".into()), Value::Int(price as i128)),
            ])
        };
        let config = Value::Map(vec![
            (Value::String("zip".into()), Value::String("00000".into())),
            (Value::String("zip_lat".into()), Value::Float(40.0)),
            (Value::String("zip_lon".into()), Value::Float(-74.0)),
            (Value::String("max_distance_mi".into()), Value::Float(10.0)),
            (Value::String("max_stores".into()), Value::Int(3)),
            (
                Value::String("ingredients".into()),
                Value::Array(vec![
                    Value::Map(vec![(Value::String("item".into()), Value::String("milk".into()))]),
                    Value::Map(vec![(Value::String("item".into()), Value::String("bread".into()))]),
                ]),
            ),
            (
                Value::String("stores".into()),
                Value::Array(vec![store(1, "Near A", 40.01), store(2, "Near B", 40.02)]),
            ),
            (
                Value::String("listings".into()),
                Value::Array(vec![
                    listing(1, 1, "milk", 300),
                    listing(1, 2, "bread", 200),
                    listing(2, 3, "milk", 250),
                    listing(2, 4, "bread", 400),
                ]),
            ),
        ]);
        let r = dispatch_browser_method(&bh, "optimize", &[config])
            .expect("dispatched")
            .expect("ok");
        let Value::Struct { name, fields } = r else {
            panic!("expected OptimizationResult")
        };
        assert_eq!(name, "OptimizationResult");
        let field = |key: &str| {
            fields
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| v.clone())
                .unwrap_or_else(|| panic!("missing {key}"))
        };
        match field("single_store_baskets") {
            Value::Array(baskets) => assert_eq!(baskets.len(), 2, "both stores within 10 mi"),
            other => panic!("expected array, got {other:?}"),
        }
        match field("cheapest_single") {
            Value::Struct { fields, .. } => {
                let total = fields
                    .iter()
                    .find(|(k, _)| k == "total_cents")
                    .map(|(_, v)| v.clone());
                match total {
                    Some(Value::Int(cents)) => assert_eq!(cents, 500, "store 1 totals 300+200"),
                    other => panic!("expected total_cents Int(500), got {other:?}"),
                }
            }
            other => panic!("expected Basket, got {other:?}"),
        }
    }

    #[test]
    fn circuit_breaker_allow_request_dispatch() {
        let v = dispatch_browser_static(
            "CircuitBreaker.new",
            &[Value::String("example.com".into())],
        )
        .unwrap()
        .unwrap();
        let bh = unwrap_browser_handle(v);
        let r = dispatch_browser_method(
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
        assert!(dispatch_browser_static("NotAThing.new", &[]).is_none());
    }

    #[test]
    fn crawl_queue_push_pop_roundtrip() {
        // Regression: push/pop must operate a REAL in-process queue — a URL
        // pushed must come back out, and dup pushes must report false.
        let v = dispatch_browser_static("CrawlQueue.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);

        let r = dispatch_browser_method(
            &bh,
            "push",
            &[Value::String("https://example.com/p1".into())],
        )
        .expect("dispatched")
        .expect("ok");
        assert!(matches!(r, Value::Bool(true)), "first push must succeed");

        // Duplicate push → false (dedup), not a silent true.
        let r = dispatch_browser_method(
            &bh,
            "push",
            &[Value::String("https://example.com/p1".into())],
        )
        .expect("dispatched")
        .expect("ok");
        assert!(matches!(r, Value::Bool(false)), "duplicate push must report false");

        let r = dispatch_browser_method(&bh, "len", &[])
            .expect("dispatched")
            .expect("ok");
        assert!(matches!(r, Value::Int(1)));

        let r = dispatch_browser_method(&bh, "pop", &[])
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

        let r = dispatch_browser_method(&bh, "is_empty", &[])
            .expect("dispatched")
            .expect("ok");
        assert!(matches!(r, Value::Bool(true)), "queue drained after pop");
    }

    #[test]
    fn job_queue_enqueue_dequeue_roundtrip() {
        let v = dispatch_browser_static("JobQueue.new", &[Value::Int(100)])
            .unwrap()
            .unwrap();
        let bh = unwrap_browser_handle(v);
        let r = dispatch_browser_method(
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

        let r = dispatch_browser_method(&bh, "dequeue", &[Value::String("w1".into())])
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
        let v = dispatch_browser_static("SmartExtractor.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);
        let html = r#"<html><head>
<script type="application/ld+json">
{"@type":"Product","name":"Echo Dot (5th Gen)","offers":{"price":"49.99","priceCurrency":"USD"}}
</script></head><body></body></html>"#;
        let r = dispatch_browser_method(&bh, "extract", &[Value::String(html.into())])
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
        let v = dispatch_browser_static("QualityValidator.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);
        let r = dispatch_browser_method(&bh, "validate", &[])
            .expect("dispatched");
        assert!(r.is_err(), "validate must be an honest error, not fake success");

        // SitemapParser.parse is stateless and wired — must succeed.
        let v = dispatch_browser_static("SitemapParser.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);
        let xml = r#"<?xml version="1.0"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://example.com/a</loc></url></urlset>"#;
        let r = dispatch_browser_method(&bh, "parse", &[Value::String(xml.into())])
            .expect("dispatched")
            .expect("ok");
        match r {
            Value::Array(items) => assert_eq!(items.len(), 1),
            other => panic!("expected sitemap entries array, got {other:?}"),
        }
    }

    #[test]
    fn triangulator_triangulate_requires_real_observations() {
        // Regression (R2-5 / R2-6): the arm used to discard its input and
        // triangulate over an empty slice, fabricating a consensus over zero
        // observations. Missing/empty/malformed input must now be an honest
        // error, never a silent empty call.
        let v = dispatch_browser_static("Triangulator.new", &[]).unwrap().unwrap();
        let bh = unwrap_browser_handle(v);

        // No observations argument at all.
        let r = dispatch_browser_method(&bh, "triangulate", &[]).expect("dispatched");
        assert!(r.is_err(), "missing observations must be an honest error");

        // Empty array.
        let r =
            dispatch_browser_method(&bh, "triangulate", &[Value::Array(vec![])])
                .expect("dispatched");
        assert!(r.is_err(), "empty observations must be an honest error");

        // Not an array.
        let r =
            dispatch_browser_method(&bh, "triangulate", &[Value::String("nope".into())])
                .expect("dispatched");
        assert!(r.is_err(), "non-array observations must be an honest error");

        // Observation missing the required 'source' field.
        let r = dispatch_browser_method(
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
        // Regression (R2-5): the consensus must be computed from the
        // observations actually passed in (Struct and Map forms both work).
        let v = dispatch_browser_static("Triangulator.new", &[]).unwrap().unwrap();
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

        let r = dispatch_browser_method(
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

    #[test]
    fn removed_constructor_only_kinds_are_unknown() {
        for name in [
            "SelectorChain.new",
            "CanaryRegistry.new",
            "PriceBoundsRegistry.new",
            "Http2Fingerprint.chrome",
        ] {
            assert!(
                dispatch_browser_static(name, &[]).is_none(),
                "{name} should no longer dispatch: the constructor-only surface was pruned"
            );
        }
    }

    #[test]
    fn live_kinds_still_construct() {
        for name in ["CrawlQueue.new", "ProductMatcher.new", "JobQueue.new"] {
            assert!(
                matches!(dispatch_browser_static(name, &[]), Some(Ok(_))),
                "{name} must still construct"
            );
        }
    }
}
