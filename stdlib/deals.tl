// Tallow Deals stdlib — deal hunting primitives.
//
// Provides type-safe deal discovery, price monitoring, and anomaly detection
// across retailers. Per-retailer configs live in configs/tallow/retailers/*.json.

struct PricePoint {
    price: f64,
    currency: String,
    timestamp: String,
    was_price: f64,
    discount_pct: f64,
    in_stock: bool,
    source: String,
}

struct DealProduct {
    retailer: String,
    sku: String,
    url: String,
    title: String,
    current_price: PricePoint,
    category: String,
    image_url: String,
    deal_type: String,
    confidence: f64,
    extracted_at: String,
}

struct DealAlert {
    product: DealProduct,
    alert_type: String,
    severity: String,
    savings_pct: f64,
    message: String,
}

struct RetailerConfig {
    name: String,
    base_url: String,
    deals_page_url: String,
    clearance_page_url: String,
    product_selector: String,
    price_selector: String,
    title_selector: String,
    image_selector: String,
    was_price_selector: String,
    stock_selector: String,
    sku_pattern: String,
    api_endpoints: Map<String, String>,
    rate_limit_ms: i64,
    requires_browser: bool,
}

native fn price_check(url: String, retailer: String) -> PricePoint
native fn detect_anomaly(current: f64, history: List<Map>, threshold: f64) -> Map
native fn scrape_deals_page(config_name: String) -> List<DealProduct>
native fn load_retailer_config(name: String) -> RetailerConfig
native fn compare_price(current: f64, was: f64) -> f64
native fn to_jsonl(deal: DealProduct) -> String
native fn to_jsonl_alert(alert: DealAlert) -> String
native fn price_history_add(retailer: String, sku: String, price: f64, was_price: f64, url: String) -> i64
native fn price_history_get(retailer: String, sku: String, limit: i64) -> List<Map>
native fn price_history_stats(retailer: String, sku: String) -> Map
native fn detect_anomaly_zscore(current_price: f64, retailer: String, sku: String, sigma: f64) -> Map
native fn detect_price_error(current_price: f64, was_price: f64, market_price: f64) -> Map
