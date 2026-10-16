//! Scraping preset system — five levels from lightweight recon to maximum stealth.
//!
//! Each [`ScrapeLevel`] configures the entire pipeline: engine mode, stealth,
//! proxy tier, extraction strategy, rate limits, and crypto layers.
//!
//! [`PresetManager`] holds per-site presets that describe *what* data each level
//! extracts (fields, endpoints, estimated volume) for 20+ built-in sites.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

#[path = "route_model.rs"]
pub mod route_model;

pub use route_model::{RouteDepthPolicy, RoutePolicy, RouteTransportPolicy};

// ─────────────────────────────────────────────────────────────────────────────
// ScrapeLevel
// ─────────────────────────────────────────────────────────────────────────────

/// Five-tier scraping intensity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ScrapeLevel {
    /// HTTP only, no stealth, public data only.
    L1Scout,
    /// Stealth HTTP + TLS fingerprint.
    L2Standard,
    /// Cookie farm + proxy rotation + smart extract.
    L3Deep,
    /// Dual-mode + LLM extraction + all proxies.
    L4Full,
    /// Everything + residential + behavioral sim + HAR.
    L5Maximum,
}

impl ScrapeLevel {
    /// Numeric rank (1–5).
    pub fn rank(self) -> u8 {
        match self {
            Self::L1Scout => 1,
            Self::L2Standard => 2,
            Self::L3Deep => 3,
            Self::L4Full => 4,
            Self::L5Maximum => 5,
        }
    }

    /// Stable canonical identifier for API/client payloads.
    pub fn id(self) -> &'static str {
        match self {
            Self::L1Scout => "L1Scout",
            Self::L2Standard => "L2Standard",
            Self::L3Deep => "L3Deep",
            Self::L4Full => "L4Full",
            Self::L5Maximum => "L5Maximum",
        }
    }

    /// Stable short code for compact display.
    pub fn code(self) -> &'static str {
        match self {
            Self::L1Scout => "L1",
            Self::L2Standard => "L2",
            Self::L3Deep => "L3",
            Self::L4Full => "L4",
            Self::L5Maximum => "L5",
        }
    }

    /// Short human-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Self::L1Scout => "Scout",
            Self::L2Standard => "Standard",
            Self::L3Deep => "Deep",
            Self::L4Full => "Full",
            Self::L5Maximum => "Maximum",
        }
    }

    /// One-line description.
    pub fn description(self) -> &'static str {
        match self {
            Self::L1Scout => "HTTP only, no stealth, public data recon",
            Self::L2Standard => "Stealth HTTP with TLS/H2 fingerprinting",
            Self::L3Deep => "Cookie farm, proxy rotation, smart extraction",
            Self::L4Full => "Dual-mode engine, LLM extraction, full proxy suite",
            Self::L5Maximum => "Everything enabled — residential, behavioral sim, HAR capture",
        }
    }

    /// All levels in order.
    pub fn all() -> &'static [ScrapeLevel] {
        &[
            Self::L1Scout,
            Self::L2Standard,
            Self::L3Deep,
            Self::L4Full,
            Self::L5Maximum,
        ]
    }
}

impl std::fmt::Display for ScrapeLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "L{} {}", self.rank(), self.name())
    }
}

/// Practical route metadata coupled to a selected scrape preset level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RoutePresetHint {
    /// Scrape level that this route hint was derived from.
    pub level: ScrapeLevel,
    /// Route policy in strongly typed form for downstream wiring.
    pub route_policy: RoutePolicy,
    /// Compact D/T metadata tag for config payloads.
    pub dt_style: String,
    /// Short operator-facing guidance for when to use this route.
    pub selection_hint: &'static str,
}

fn route_policy_for_level(level: ScrapeLevel) -> RoutePolicy {
    match level {
        ScrapeLevel::L1Scout => RoutePolicy {
            depth: RouteDepthPolicy::Limited { max_depth: 1 },
            transport: RouteTransportPolicy::Auto,
        },
        ScrapeLevel::L2Standard => RoutePolicy {
            depth: RouteDepthPolicy::Limited { max_depth: 2 },
            transport: RouteTransportPolicy::PreferWebSocket,
        },
        ScrapeLevel::L3Deep => RoutePolicy {
            depth: RouteDepthPolicy::Limited { max_depth: 4 },
            transport: RouteTransportPolicy::PreferWebSocket,
        },
        ScrapeLevel::L4Full => RoutePolicy {
            depth: RouteDepthPolicy::Limited { max_depth: 8 },
            transport: RouteTransportPolicy::PreferPipe,
        },
        ScrapeLevel::L5Maximum => RoutePolicy {
            depth: RouteDepthPolicy::Unlimited,
            transport: RouteTransportPolicy::PipeOnly,
        },
    }
}

fn route_selection_hint_for_level(level: ScrapeLevel) -> &'static str {
    match level {
        ScrapeLevel::L1Scout => "Fast single-hop recon with runtime transport fallback.",
        ScrapeLevel::L2Standard => {
            "Light anti-bot pressure; keep traversal shallow and prefer WebSocket."
        }
        ScrapeLevel::L3Deep => {
            "Paginated sessions; moderate depth with resilient WebSocket preference."
        }
        ScrapeLevel::L4Full => {
            "Dual-mode extraction; deeper route with pipe-preferred local stability."
        }
        ScrapeLevel::L5Maximum => {
            "Long-running deep scrape; unbounded depth with pipe-only transport."
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// LevelConfig
// ─────────────────────────────────────────────────────────────────────────────

/// Full pipeline configuration derived from a [`ScrapeLevel`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LevelConfig {
    pub level: ScrapeLevel,
    pub name: String,
    pub description: String,

    // Engine settings
    /// `"http"`, `"stealth_http"`, `"dual_mode"`, or `"browser"`.
    pub engine_mode: String,
    pub stealth_enabled: bool,
    pub stealth_v3_enabled: bool,
    /// TLS fingerprint profile: `None`, `"chrome136"`, `"firefox131"`.
    pub tls_fingerprint: Option<String>,
    pub h2_fingerprint: bool,
    pub behavioral_sim: bool,
    pub weibull_timing: bool,

    // Proxy settings
    /// `"direct"`, `"tor"`, `"datacenter"`, `"residential"`, `"mobile"`, `"auto"`.
    pub proxy_tier: String,
    pub proxy_rotation: bool,
    pub asn_diversity: bool,
    pub ipv6_pool: bool,

    // Anti-bot
    pub cookie_farm: bool,
    pub vendor_detection: bool,
    pub slider_captcha: bool,
    pub retry_intelligence: bool,

    // Extraction
    /// `"raw_html"`, `"smart_extract"`, `"llm_extract"`, `"css_schema"`.
    pub extraction_mode: String,
    pub self_healing_selectors: bool,
    pub schema_drift_detection: bool,
    pub image_price_detection: bool,

    // Data capture
    pub har_capture: bool,
    pub screenshot_capture: bool,
    pub download_images: bool,
    pub full_html_archive: bool,

    // Rate limiting
    pub max_concurrency: u32,
    pub rate_limit_per_second: f64,
    pub respect_robots_txt: bool,

    // Crypto
    /// 1–5 encryption layers.
    pub encryption_layers: u8,
}

impl LevelConfig {
    /// Build the default configuration for a given level.
    pub fn from_level(level: ScrapeLevel) -> Self {
        match level {
            ScrapeLevel::L1Scout => Self {
                level,
                name: "Scout".into(),
                description: "HTTP only, no stealth, public data recon".into(),
                engine_mode: "http".into(),
                stealth_enabled: false,
                stealth_v3_enabled: false,
                tls_fingerprint: None,
                h2_fingerprint: false,
                behavioral_sim: false,
                weibull_timing: false,
                proxy_tier: "tor".into(),
                proxy_rotation: true,
                asn_diversity: false,
                ipv6_pool: false,
                cookie_farm: false,
                vendor_detection: false,
                slider_captcha: false,
                retry_intelligence: false,
                extraction_mode: "raw_html".into(),
                self_healing_selectors: false,
                schema_drift_detection: false,
                image_price_detection: false,
                har_capture: false,
                screenshot_capture: false,
                download_images: false,
                full_html_archive: false,
                max_concurrency: 20,
                rate_limit_per_second: 5.0,
                respect_robots_txt: true,
                encryption_layers: 3,
            },
            ScrapeLevel::L2Standard => Self {
                level,
                name: "Standard".into(),
                description: "Stealth HTTP with TLS/H2 fingerprinting".into(),
                engine_mode: "stealth_http".into(),
                stealth_enabled: true,
                stealth_v3_enabled: false,
                tls_fingerprint: Some("chrome136".into()),
                h2_fingerprint: true,
                behavioral_sim: false,
                weibull_timing: false,
                proxy_tier: "auto".into(),
                proxy_rotation: true,
                asn_diversity: false,
                ipv6_pool: false,
                cookie_farm: false,
                vendor_detection: true,
                slider_captcha: false,
                retry_intelligence: false,
                extraction_mode: "smart_extract".into(),
                self_healing_selectors: true,
                schema_drift_detection: false,
                image_price_detection: false,
                har_capture: false,
                screenshot_capture: false,
                download_images: false,
                full_html_archive: false,
                max_concurrency: 10,
                rate_limit_per_second: 2.0,
                respect_robots_txt: true,
                encryption_layers: 5,
            },
            ScrapeLevel::L3Deep => Self {
                level,
                name: "Deep".into(),
                description: "Cookie farm, proxy rotation, smart extraction".into(),
                engine_mode: "stealth_http".into(),
                stealth_enabled: true,
                stealth_v3_enabled: true,
                tls_fingerprint: Some("chrome136".into()),
                h2_fingerprint: true,
                behavioral_sim: false,
                weibull_timing: false,
                proxy_tier: "residential".into(),
                proxy_rotation: true,
                asn_diversity: true,
                ipv6_pool: false,
                cookie_farm: true,
                vendor_detection: true,
                slider_captcha: false,
                retry_intelligence: true,
                extraction_mode: "smart_extract".into(),
                self_healing_selectors: true,
                schema_drift_detection: true,
                image_price_detection: false,
                har_capture: false,
                screenshot_capture: false,
                download_images: false,
                full_html_archive: false,
                max_concurrency: 5,
                rate_limit_per_second: 1.0,
                respect_robots_txt: true,
                encryption_layers: 5,
            },
            ScrapeLevel::L4Full => Self {
                level,
                name: "Full".into(),
                description: "Dual-mode engine, LLM extraction, full proxy suite".into(),
                engine_mode: "dual_mode".into(),
                stealth_enabled: true,
                stealth_v3_enabled: true,
                tls_fingerprint: Some("chrome136".into()),
                h2_fingerprint: true,
                behavioral_sim: true,
                weibull_timing: true,
                proxy_tier: "residential".into(),
                proxy_rotation: true,
                asn_diversity: true,
                ipv6_pool: false,
                cookie_farm: true,
                vendor_detection: true,
                slider_captcha: false,
                retry_intelligence: true,
                extraction_mode: "llm_extract".into(),
                self_healing_selectors: true,
                schema_drift_detection: true,
                image_price_detection: true,
                har_capture: false,
                screenshot_capture: false,
                download_images: true,
                full_html_archive: false,
                max_concurrency: 3,
                rate_limit_per_second: 0.5,
                respect_robots_txt: true,
                encryption_layers: 5,
            },
            ScrapeLevel::L5Maximum => Self {
                level,
                name: "Maximum".into(),
                description: "Everything enabled — residential, behavioral sim, HAR capture".into(),
                engine_mode: "dual_mode".into(),
                stealth_enabled: true,
                stealth_v3_enabled: true,
                tls_fingerprint: Some("chrome136".into()),
                h2_fingerprint: true,
                behavioral_sim: true,
                weibull_timing: true,
                proxy_tier: "mobile".into(),
                proxy_rotation: true,
                asn_diversity: true,
                ipv6_pool: true,
                cookie_farm: true,
                vendor_detection: true,
                slider_captcha: true,
                retry_intelligence: true,
                // Use smart_extract so the Zacks hardcoded extractor fast-path can fire;
                // LLM extraction is too slow for 200-concurrent bulk scraping.
                extraction_mode: "smart_extract".into(),
                self_healing_selectors: true,
                schema_drift_detection: true,
                image_price_detection: true,
                har_capture: true,
                // screenshot_capture disabled: execute pipeline has no Chromium source;
                // enabling this previously caused jobs to fast-fail immediately.
                screenshot_capture: false,
                download_images: true,
                full_html_archive: true,
                // 200 workers × 0.3 req/s = 60 req/s aggregate across proxy rotation
                max_concurrency: 200,
                rate_limit_per_second: 0.3,
                respect_robots_txt: true,
                encryption_layers: 5,
            },
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-Site Presets
// ─────────────────────────────────────────────────────────────────────────────

/// Site-specific scraping configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SitePreset {
    pub domain: String,
    pub display_name: String,
    /// Hex colour for UI badges.
    pub brand_color: String,
    pub default_level: ScrapeLevel,
    pub levels: HashMap<ScrapeLevel, SiteLevelData>,
}

/// What a particular level extracts from a particular site.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiteLevelData {
    pub description: String,
    /// Field names this level yields.
    pub data_fields: Vec<String>,
    /// API endpoints or URL patterns to hit.
    pub endpoints: Vec<String>,
    pub requires_auth: bool,
    /// Human-readable estimate, e.g. `"~50K products"`.
    pub estimated_items: String,
    /// Human-readable estimate, e.g. `"~5 min"`.
    pub estimated_time: String,
}

// ─────────────────────────────────────────────────────────────────────────────
// PresetManager
// ─────────────────────────────────────────────────────────────────────────────

/// Central registry for site presets and level configs.
#[derive(Debug, Clone)]
pub struct PresetManager {
    site_presets: HashMap<String, SitePreset>,
}

fn normalize_domain(domain: &str) -> String {
    let trimmed = domain.trim().trim_matches('/');
    let without_scheme = trimmed
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(trimmed);
    let host = without_scheme
        .split('/')
        .next()
        .unwrap_or(without_scheme)
        .split(':')
        .next()
        .unwrap_or(without_scheme)
        .trim()
        .trim_end_matches('.');
    let lowered = host.to_ascii_lowercase();
    lowered.strip_prefix("www.").unwrap_or(&lowered).to_string()
}

impl PresetManager {
    /// Build the manager with all built-in presets.
    pub fn new() -> Self {
        let mut site_presets = HashMap::new();
        for preset in builtin_presets() {
            site_presets.insert(normalize_domain(&preset.domain), preset);
        }
        Self { site_presets }
    }

    /// Look up a site by domain.
    pub fn get_site_preset(&self, domain: &str) -> Option<&SitePreset> {
        self.site_presets.get(&normalize_domain(domain))
    }

    /// Get the default [`LevelConfig`] for a given level.
    pub fn get_level_config(&self, level: ScrapeLevel) -> LevelConfig {
        LevelConfig::from_level(level)
    }

    /// Get the site-specific data for a domain at a particular level.
    pub fn get_site_level(&self, domain: &str, level: ScrapeLevel) -> Option<&SiteLevelData> {
        self.get_site_preset(domain)
            .and_then(|sp| sp.levels.get(&level))
    }

    /// Recommend a scrape level based on detected anti-bot vendor.
    pub fn recommend_level(&self, domain: &str, vendor: Option<&str>) -> ScrapeLevel {
        let domain = normalize_domain(domain);

        // If we have a site-specific default, start there.
        let site_default = self.site_presets.get(&domain).map(|sp| sp.default_level);

        let vendor_level = match vendor {
            None | Some("") => ScrapeLevel::L1Scout,
            Some("cloudflare") | Some("Cloudflare") => ScrapeLevel::L2Standard,
            Some("aws_waf") | Some("AwsWaf") | Some("AWS WAF") => ScrapeLevel::L2Standard,
            Some("akamai") | Some("Akamai") | Some("Akamai Bot Manager") => ScrapeLevel::L3Deep,
            Some("imperva") | Some("Imperva") | Some("Incapsula") | Some("Imperva / Incapsula") => {
                ScrapeLevel::L3Deep
            }
            Some("perimeterx")
            | Some("PerimeterX")
            | Some("PerimeterX / HUMAN")
            | Some("datadome")
            | Some("DataDome") => ScrapeLevel::L4Full,
            Some("shape_security") | Some("ShapeSecurity") | Some("Shape Security (F5)") => {
                ScrapeLevel::L4Full
            }
            Some("kasada") | Some("Kasada") => ScrapeLevel::L5Maximum,
            _ => ScrapeLevel::L2Standard,
        };

        // Take the higher of site-specific and vendor-based.
        match site_default {
            Some(sd) if sd.rank() > vendor_level.rank() => sd,
            _ => vendor_level,
        }
    }

    /// List all registered site presets.
    pub fn list_sites(&self) -> Vec<&SitePreset> {
        let mut sites: Vec<_> = self.site_presets.values().collect();
        sites.sort_by_key(|s| &s.domain);
        sites
    }

    /// Enumerate all levels with name and description.
    pub fn list_levels() -> Vec<(ScrapeLevel, &'static str, &'static str)> {
        ScrapeLevel::all()
            .iter()
            .map(|l| (*l, l.name(), l.description()))
            .collect()
    }

    /// Build a practical depth/transport hint for a specific scrape level.
    pub fn route_hint_for_level(level: ScrapeLevel) -> RoutePresetHint {
        let route_policy = route_policy_for_level(level);
        debug_assert!(route_policy.validate().is_ok());
        RoutePresetHint {
            level,
            dt_style: route_policy.dt_style_code(),
            route_policy,
            selection_hint: route_selection_hint_for_level(level),
        }
    }

    /// Recommend a route hint using the same level selection pipeline as
    /// [`PresetManager::auto_configure`].
    pub fn recommend_route_hint(
        &self,
        domain: &str,
        vendor: Option<&str>,
        difficulty: &str,
    ) -> RoutePresetHint {
        let level = self.auto_configure(domain, vendor, difficulty).level;
        Self::route_hint_for_level(level)
    }

    /// Build a [`LevelConfig`] tuned for a specific domain.
    ///
    /// Starts from the recommended level, then adjusts based on the site's
    /// known requirements (auth, heavy anti-bot, etc.).
    pub fn auto_configure(
        &self,
        domain: &str,
        vendor: Option<&str>,
        difficulty: &str,
    ) -> LevelConfig {
        let domain = normalize_domain(domain);
        let base_level = self.recommend_level(&domain, vendor);

        // Bump up if difficulty is explicitly stated.
        let level = match difficulty {
            "easy" => base_level,
            "medium" if base_level.rank() < 3 => ScrapeLevel::L3Deep,
            "hard" if base_level.rank() < 4 => ScrapeLevel::L4Full,
            "extreme" => ScrapeLevel::L5Maximum,
            _ => base_level,
        };

        let mut cfg = LevelConfig::from_level(level);

        // Site-specific tweaks.
        if let Some(preset) = self.site_presets.get(&domain) {
            // If the site has auth requirements at this level, note it.
            if let Some(sld) = preset.levels.get(&level) {
                if sld.requires_auth {
                    // Auth sites often need cookie farm even at lower levels.
                    cfg.cookie_farm = true;
                }
            }
        }

        // Known difficult domains get extra hardening regardless of level.
        match domain.as_str() {
            "site-16.example" => {
                cfg.behavioral_sim = true;
                cfg.weibull_timing = true;
                cfg.cookie_farm = true;
            }
            "site-39.example" => {
                cfg.cookie_farm = true;
                cfg.vendor_detection = true;
            }
            _ => {}
        }

        cfg
    }
}

impl Default for PresetManager {
    fn default() -> Self {
        Self::new()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Built-in preset database
// ─────────────────────────────────────────────────────────────────────────────

/// Helper to build a five-level map.
fn levels(data: [(ScrapeLevel, SiteLevelData); 5]) -> HashMap<ScrapeLevel, SiteLevelData> {
    data.into_iter()
        .map(|(level, mut site_data)| {
            let cfg = LevelConfig::from_level(level);

            if !cfg.screenshot_capture {
                site_data
                    .data_fields
                    .retain(|field| !field.to_ascii_lowercase().contains("screenshot"));
                site_data.description =
                    strip_description_tokens(&site_data.description, &["screenshot"]);
            }

            if !cfg.har_capture {
                site_data
                    .data_fields
                    .retain(|field| !field.eq_ignore_ascii_case("har_capture"));
                site_data.description = strip_description_tokens(&site_data.description, &["har"]);
            }

            if !cfg.full_html_archive {
                site_data.data_fields.retain(|field| {
                    !field.eq_ignore_ascii_case("full_html")
                        && !field.eq_ignore_ascii_case("full_session")
                });
                site_data.description = strip_description_tokens(
                    &site_data.description,
                    &["full archive", "full html", "full session"],
                );
            }
            (level, site_data)
        })
        .collect()
}

fn strip_description_tokens(description: &str, forbidden_terms: &[&str]) -> String {
    let forbidden: Vec<String> = forbidden_terms
        .iter()
        .map(|term| term.to_ascii_lowercase())
        .collect();
    let parts: Vec<&str> = description
        .split('+')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .filter(|part| {
            let lowered = part.to_ascii_lowercase();
            !forbidden.iter().any(|term| lowered.contains(term))
        })
        .collect();
    if parts.is_empty() {
        description.to_string()
    } else {
        parts.join(" + ")
    }
}

fn s(v: &str) -> String {
    v.into()
}

fn sv(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).into()).collect()
}

/// All built-in site presets.
fn builtin_presets() -> Vec<SitePreset> {
    vec![
        // ─── Grocery ──────────────────────────────────────────────────
        SitePreset {
            domain: s("shop-a.example"),
            display_name: s("Walmart"),
            brand_color: s("#0071CE"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Public product listing via search API"),
                        data_fields: sv(&["name", "price", "url", "availability"]),
                        endpoints: sv(&["/search/api/preso"]),
                        requires_auth: false,
                        estimated_items: s("~5K products"),
                        estimated_time: s("~3 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Full product cards with images and ratings"),
                        data_fields: sv(&[
                            "name",
                            "price",
                            "url",
                            "availability",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                        ]),
                        endpoints: sv(&["/search/api/preso", "/product/{id}"]),
                        requires_auth: false,
                        estimated_items: s("~50K products"),
                        estimated_time: s("~15 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Product detail with nutrition and category tree"),
                        data_fields: sv(&[
                            "name",
                            "price",
                            "url",
                            "availability",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "nutrition_facts",
                            "category_path",
                            "upc",
                            "weight",
                        ]),
                        endpoints: sv(&["/search/api/preso", "/product/{id}", "/ip/{slug}"]),
                        requires_auth: false,
                        estimated_items: s("~100K products"),
                        estimated_time: s("~45 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Full catalog + price history + store-level inventory"),
                        data_fields: sv(&[
                            "name",
                            "price",
                            "url",
                            "availability",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "nutrition_facts",
                            "category_path",
                            "upc",
                            "weight",
                            "price_history",
                            "store_inventory",
                            "seller_info",
                        ]),
                        endpoints: sv(&[
                            "/search/api/preso",
                            "/product/{id}",
                            "/ip/{slug}",
                            "/store/{id}/inventory",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~200K products"),
                        estimated_time: s("~2 hours"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Complete data + HAR + full archive"),
                        data_fields: sv(&[
                            "name",
                            "price",
                            "url",
                            "availability",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "nutrition_facts",
                            "category_path",
                            "upc",
                            "weight",
                            "price_history",
                            "store_inventory",
                            "seller_info",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/search/api/preso",
                            "/product/{id}",
                            "/ip/{slug}",
                            "/store/{id}/inventory",
                            "/reviews/{id}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~300K products"),
                        estimated_time: s("~6 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("shop-b.example"),
            display_name: s("Target"),
            brand_color: s("#CC0000"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Redsky API product search"),
                        data_fields: sv(&["tcin", "title", "price", "availability"]),
                        endpoints: sv(&["/redsky_aggregations/v1/web/plp_search_v2"]),
                        requires_auth: false,
                        estimated_items: s("~5K products"),
                        estimated_time: s("~2 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Full product detail from Redsky"),
                        data_fields: sv(&[
                            "tcin",
                            "title",
                            "price",
                            "availability",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "upc",
                        ]),
                        endpoints: sv(&[
                            "/redsky_aggregations/v1/web/plp_search_v2",
                            "/redsky_aggregations/v1/web/pdp_client_v1",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~23K grocery products"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Product + nutrition + fulfillment options"),
                        data_fields: sv(&[
                            "tcin",
                            "title",
                            "price",
                            "availability",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "upc",
                            "nutrition_facts",
                            "category_path",
                            "fulfillment_options",
                            "store_location",
                        ]),
                        endpoints: sv(&[
                            "/redsky_aggregations/v1/web/plp_search_v2",
                            "/redsky_aggregations/v1/web/pdp_client_v1",
                            "/redsky_aggregations/v1/web/fiats_v1",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~23K products"),
                        estimated_time: s("~20 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("All data + reviews + price tracking"),
                        data_fields: sv(&[
                            "tcin",
                            "title",
                            "price",
                            "availability",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "upc",
                            "nutrition_facts",
                            "category_path",
                            "fulfillment_options",
                            "store_location",
                            "reviews_text",
                            "price_history",
                            "promotions",
                        ]),
                        endpoints: sv(&[
                            "/redsky_aggregations/v1/web/plp_search_v2",
                            "/redsky_aggregations/v1/web/pdp_client_v1",
                            "/redsky_aggregations/v1/web/fiats_v1",
                            "/reviews/v2/{tcin}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~23K products"),
                        estimated_time: s("~45 min"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR"),
                        data_fields: sv(&[
                            "tcin",
                            "title",
                            "price",
                            "availability",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "upc",
                            "nutrition_facts",
                            "category_path",
                            "fulfillment_options",
                            "store_location",
                            "reviews_text",
                            "price_history",
                            "promotions",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/redsky_aggregations/v1/web/plp_search_v2",
                            "/redsky_aggregations/v1/web/pdp_client_v1",
                            "/reviews/v2/{tcin}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~23K products"),
                        estimated_time: s("~2 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("site-15.example"),
            display_name: s("Kroger"),
            brand_color: s("#0068A5"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Public product search"),
                        data_fields: sv(&["upc", "name", "price", "brand"]),
                        endpoints: sv(&["/search?query={q}"]),
                        requires_auth: false,
                        estimated_items: s("~5K products"),
                        estimated_time: s("~3 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Product detail + images + categories"),
                        data_fields: sv(&[
                            "upc",
                            "name",
                            "price",
                            "brand",
                            "image_url",
                            "category",
                            "size",
                            "availability",
                        ]),
                        endpoints: sv(&["/search?query={q}", "/p/{slug}"]),
                        requires_auth: false,
                        estimated_items: s("~20K products"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Nutrition + store pricing"),
                        data_fields: sv(&[
                            "upc",
                            "name",
                            "price",
                            "brand",
                            "image_url",
                            "category",
                            "size",
                            "availability",
                            "nutrition_facts",
                            "ingredients",
                            "store_price",
                            "unit_price",
                        ]),
                        endpoints: sv(&[
                            "/search?query={q}",
                            "/p/{slug}",
                            "/product/api/detail/{upc}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~40K products"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Full catalog + coupons + alternatives"),
                        data_fields: sv(&[
                            "upc",
                            "name",
                            "price",
                            "brand",
                            "image_url",
                            "category",
                            "size",
                            "availability",
                            "nutrition_facts",
                            "ingredients",
                            "store_price",
                            "unit_price",
                            "coupons",
                            "related_products",
                            "price_history",
                        ]),
                        endpoints: sv(&[
                            "/search?query={q}",
                            "/p/{slug}",
                            "/product/api/detail/{upc}",
                            "/coupons/api",
                        ]),
                        requires_auth: true,
                        estimated_items: s("~60K products"),
                        estimated_time: s("~1 hour"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Complete archive + HAR"),
                        data_fields: sv(&[
                            "upc",
                            "name",
                            "price",
                            "brand",
                            "image_url",
                            "category",
                            "size",
                            "availability",
                            "nutrition_facts",
                            "ingredients",
                            "store_price",
                            "unit_price",
                            "coupons",
                            "related_products",
                            "price_history",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/search?query={q}",
                            "/p/{slug}",
                            "/product/api/detail/{upc}",
                            "/coupons/api",
                        ]),
                        requires_auth: true,
                        estimated_items: s("~60K products"),
                        estimated_time: s("~3 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("shop-d.example"),
            display_name: s("H-E-B"),
            brand_color: s("#E31837"),
            default_level: ScrapeLevel::L1Scout,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Mobile API product search"),
                        data_fields: sv(&["sku", "name", "price", "brand"]),
                        endpoints: sv(&["/commerce-search/v1/search"]),
                        requires_auth: false,
                        estimated_items: s("~10K products"),
                        estimated_time: s("~2 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Product detail + images + store"),
                        data_fields: sv(&[
                            "sku",
                            "name",
                            "price",
                            "brand",
                            "image_url",
                            "category",
                            "size",
                            "store_id",
                            "availability",
                        ]),
                        endpoints: sv(&["/commerce-search/v1/search", "/product-detail/v1/{sku}"]),
                        requires_auth: false,
                        estimated_items: s("~44K products"),
                        estimated_time: s("~5 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Nutrition + ingredients + unit price"),
                        data_fields: sv(&[
                            "sku",
                            "name",
                            "price",
                            "brand",
                            "image_url",
                            "category",
                            "size",
                            "store_id",
                            "availability",
                            "nutrition_facts",
                            "ingredients",
                            "unit_price",
                            "snap_eligible",
                        ]),
                        endpoints: sv(&["/commerce-search/v1/search", "/product-detail/v1/{sku}"]),
                        requires_auth: false,
                        estimated_items: s("~44K products"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Multi-store pricing + curbside data"),
                        data_fields: sv(&[
                            "sku",
                            "name",
                            "price",
                            "brand",
                            "image_url",
                            "category",
                            "size",
                            "store_id",
                            "availability",
                            "nutrition_facts",
                            "ingredients",
                            "unit_price",
                            "snap_eligible",
                            "curbside_available",
                            "multi_store_prices",
                            "promotions",
                        ]),
                        endpoints: sv(&[
                            "/commerce-search/v1/search",
                            "/product-detail/v1/{sku}",
                            "/stores/v1/nearby",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~44K products x 5 stores"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + all stores + HAR"),
                        data_fields: sv(&[
                            "sku",
                            "name",
                            "price",
                            "brand",
                            "image_url",
                            "category",
                            "size",
                            "store_id",
                            "availability",
                            "nutrition_facts",
                            "ingredients",
                            "unit_price",
                            "snap_eligible",
                            "curbside_available",
                            "multi_store_prices",
                            "promotions",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/commerce-search/v1/search",
                            "/product-detail/v1/{sku}",
                            "/stores/v1/nearby",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~44K products x all stores"),
                        estimated_time: s("~2 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("shop-21.example"),
            display_name: s("Costco"),
            brand_color: s("#E31837"),
            default_level: ScrapeLevel::L3Deep,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Public category pages"),
                        data_fields: sv(&["item_number", "name", "price"]),
                        endpoints: sv(&["/CatalogSearch?keyword={q}"]),
                        requires_auth: false,
                        estimated_items: s("~2K products"),
                        estimated_time: s("~5 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Product search with details"),
                        data_fields: sv(&[
                            "item_number",
                            "name",
                            "price",
                            "image_url",
                            "brand",
                            "rating",
                            "unit_price",
                        ]),
                        endpoints: sv(&[
                            "/CatalogSearch?keyword={q}",
                            "/product.{item_number}.html",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K products"),
                        estimated_time: s("~15 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Member pricing + delivery options"),
                        data_fields: sv(&[
                            "item_number",
                            "name",
                            "price",
                            "image_url",
                            "brand",
                            "rating",
                            "unit_price",
                            "member_price",
                            "delivery_options",
                            "warehouse_availability",
                        ]),
                        endpoints: sv(&[
                            "/CatalogSearch?keyword={q}",
                            "/product.{item_number}.html",
                            "/AjaxWarehouseAvailability",
                        ]),
                        requires_auth: true,
                        estimated_items: s("~15K products"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Full catalog + reviews + specs"),
                        data_fields: sv(&[
                            "item_number",
                            "name",
                            "price",
                            "image_url",
                            "brand",
                            "rating",
                            "unit_price",
                            "member_price",
                            "delivery_options",
                            "warehouse_availability",
                            "reviews_text",
                            "specifications",
                            "similar_items",
                        ]),
                        endpoints: sv(&[
                            "/CatalogSearch?keyword={q}",
                            "/product.{item_number}.html",
                            "/AjaxWarehouseAvailability",
                            "/AjaxBVReviewSummary",
                        ]),
                        requires_auth: true,
                        estimated_items: s("~20K products"),
                        estimated_time: s("~1 hour"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Complete archive + HAR"),
                        data_fields: sv(&[
                            "item_number",
                            "name",
                            "price",
                            "image_url",
                            "brand",
                            "rating",
                            "unit_price",
                            "member_price",
                            "delivery_options",
                            "warehouse_availability",
                            "reviews_text",
                            "specifications",
                            "similar_items",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/CatalogSearch?keyword={q}",
                            "/product.{item_number}.html",
                            "/AjaxWarehouseAvailability",
                            "/AjaxBVReviewSummary",
                        ]),
                        requires_auth: true,
                        estimated_items: s("~20K products"),
                        estimated_time: s("~4 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("shop-06.example"),
            display_name: s("Amazon / Whole Foods"),
            brand_color: s("#FF9900"),
            default_level: ScrapeLevel::L3Deep,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Search results page scrape"),
                        data_fields: sv(&["asin", "title", "price", "url"]),
                        endpoints: sv(&["/s?k={query}"]),
                        requires_auth: false,
                        estimated_items: s("~5K products"),
                        estimated_time: s("~5 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Product detail pages"),
                        data_fields: sv(&[
                            "asin",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "category",
                        ]),
                        endpoints: sv(&["/s?k={query}", "/dp/{asin}"]),
                        requires_auth: false,
                        estimated_items: s("~20K products"),
                        estimated_time: s("~20 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full detail + buy box + variations"),
                        data_fields: sv(&[
                            "asin",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "category",
                            "buy_box_seller",
                            "variations",
                            "bullet_points",
                            "description",
                        ]),
                        endpoints: sv(&["/s?k={query}", "/dp/{asin}", "/gp/aod/ajax/{asin}"]),
                        requires_auth: false,
                        estimated_items: s("~50K products"),
                        estimated_time: s("~1 hour"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Reviews + seller data + BSR"),
                        data_fields: sv(&[
                            "asin",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "category",
                            "buy_box_seller",
                            "variations",
                            "bullet_points",
                            "description",
                            "reviews_text",
                            "bsr_rank",
                            "seller_info",
                            "fba_fees",
                        ]),
                        endpoints: sv(&[
                            "/s?k={query}",
                            "/dp/{asin}",
                            "/gp/aod/ajax/{asin}",
                            "/product-reviews/{asin}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~100K products"),
                        estimated_time: s("~3 hours"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Complete archive + Whole Foods + HAR"),
                        data_fields: sv(&[
                            "asin",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "category",
                            "buy_box_seller",
                            "variations",
                            "bullet_points",
                            "description",
                            "reviews_text",
                            "bsr_rank",
                            "seller_info",
                            "fba_fees",
                            "whole_foods_availability",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/s?k={query}",
                            "/dp/{asin}",
                            "/gp/aod/ajax/{asin}",
                            "/product-reviews/{asin}",
                            "/alm/storefront",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~200K products"),
                        estimated_time: s("~8 hours"),
                    },
                ),
            ]),
        },
        // ─── Real Estate ──────────────────────────────────────────────
        SitePreset {
            domain: s("site-39.example"),
            display_name: s("Zillow"),
            brand_color: s("#006AFF"),
            default_level: ScrapeLevel::L3Deep,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Public search results"),
                        data_fields: sv(&["zpid", "address", "price", "beds", "baths", "sqft"]),
                        endpoints: sv(&["/search/GetSearchPageState.htm"]),
                        requires_auth: false,
                        estimated_items: s("~5K listings"),
                        estimated_time: s("~5 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Listing cards + images"),
                        data_fields: sv(&[
                            "zpid",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                            "image_url",
                            "listing_type",
                            "days_on_market",
                            "zestimate",
                        ]),
                        endpoints: sv(&["/search/GetSearchPageState.htm", "/homedetails/{zpid}"]),
                        requires_auth: false,
                        estimated_items: s("~20K listings"),
                        estimated_time: s("~15 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full property detail + tax + school data"),
                        data_fields: sv(&[
                            "zpid",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                            "image_url",
                            "listing_type",
                            "days_on_market",
                            "zestimate",
                            "tax_history",
                            "price_history",
                            "school_rating",
                            "lot_size",
                            "year_built",
                            "hoa",
                        ]),
                        endpoints: sv(&[
                            "/search/GetSearchPageState.htm",
                            "/homedetails/{zpid}",
                            "/graphql",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~50K listings"),
                        estimated_time: s("~45 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Neighborhood data + agent info + rental comps"),
                        data_fields: sv(&[
                            "zpid",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                            "image_url",
                            "listing_type",
                            "days_on_market",
                            "zestimate",
                            "tax_history",
                            "price_history",
                            "school_rating",
                            "lot_size",
                            "year_built",
                            "hoa",
                            "neighborhood_stats",
                            "agent_info",
                            "rental_estimate",
                            "comparable_sales",
                        ]),
                        endpoints: sv(&[
                            "/search/GetSearchPageState.htm",
                            "/homedetails/{zpid}",
                            "/graphql",
                            "/rental-manager/api",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~100K listings"),
                        estimated_time: s("~2 hours"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + all images + HAR"),
                        data_fields: sv(&[
                            "zpid",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                            "image_url",
                            "listing_type",
                            "days_on_market",
                            "zestimate",
                            "tax_history",
                            "price_history",
                            "school_rating",
                            "lot_size",
                            "year_built",
                            "hoa",
                            "neighborhood_stats",
                            "agent_info",
                            "rental_estimate",
                            "comparable_sales",
                            "all_photos",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/search/GetSearchPageState.htm",
                            "/homedetails/{zpid}",
                            "/graphql",
                            "/rental-manager/api",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~200K listings"),
                        estimated_time: s("~6 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("site-25.example"),
            display_name: s("Redfin"),
            brand_color: s("#A02021"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Stingray API search"),
                        data_fields: sv(&[
                            "property_id",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                        ]),
                        endpoints: sv(&["/stingray/api/gis"]),
                        requires_auth: false,
                        estimated_items: s("~5K listings"),
                        estimated_time: s("~3 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Full listing data"),
                        data_fields: sv(&[
                            "property_id",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                            "image_url",
                            "listing_type",
                            "days_on_market",
                            "hoa",
                            "year_built",
                        ]),
                        endpoints: sv(&[
                            "/stingray/api/gis",
                            "/stingray/api/home/details/belowTheFold",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~20K listings"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Property detail + estimate + tax"),
                        data_fields: sv(&[
                            "property_id",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                            "image_url",
                            "listing_type",
                            "days_on_market",
                            "hoa",
                            "year_built",
                            "redfin_estimate",
                            "tax_history",
                            "price_history",
                            "school_data",
                            "walk_score",
                        ]),
                        endpoints: sv(&[
                            "/stingray/api/gis",
                            "/stingray/api/home/details/belowTheFold",
                            "/stingray/api/home/details/aboveTheFold",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~50K listings"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Agent + neighborhood + comps"),
                        data_fields: sv(&[
                            "property_id",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                            "image_url",
                            "listing_type",
                            "days_on_market",
                            "hoa",
                            "year_built",
                            "redfin_estimate",
                            "tax_history",
                            "price_history",
                            "school_data",
                            "walk_score",
                            "agent_info",
                            "neighborhood_stats",
                            "comparable_sales",
                        ]),
                        endpoints: sv(&[
                            "/stingray/api/gis",
                            "/stingray/api/home/details/belowTheFold",
                            "/stingray/api/home/details/aboveTheFold",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~100K listings"),
                        estimated_time: s("~1 hour"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + all photos + HAR"),
                        data_fields: sv(&[
                            "property_id",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                            "image_url",
                            "listing_type",
                            "days_on_market",
                            "hoa",
                            "year_built",
                            "redfin_estimate",
                            "tax_history",
                            "price_history",
                            "school_data",
                            "walk_score",
                            "agent_info",
                            "neighborhood_stats",
                            "comparable_sales",
                            "all_photos",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/stingray/api/gis",
                            "/stingray/api/home/details/belowTheFold",
                            "/stingray/api/home/details/aboveTheFold",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~200K listings"),
                        estimated_time: s("~4 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("site-23.example"),
            display_name: s("site-23.example"),
            brand_color: s("#D92228"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Search API listings"),
                        data_fields: sv(&[
                            "property_id",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                        ]),
                        endpoints: sv(&["/api/v1/hulk?client_id=rdc-x"]),
                        requires_auth: false,
                        estimated_items: s("~5K listings"),
                        estimated_time: s("~3 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Listing detail + images"),
                        data_fields: sv(&[
                            "property_id",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                            "image_url",
                            "listing_type",
                            "days_on_market",
                            "lot_size",
                        ]),
                        endpoints: sv(&[
                            "/api/v1/hulk?client_id=rdc-x",
                            "/realestateandhomes-detail/{slug}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~20K listings"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full detail + schools + tax"),
                        data_fields: sv(&[
                            "property_id",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                            "image_url",
                            "listing_type",
                            "days_on_market",
                            "lot_size",
                            "tax_history",
                            "price_history",
                            "school_data",
                            "features",
                        ]),
                        endpoints: sv(&[
                            "/api/v1/hulk?client_id=rdc-x",
                            "/realestateandhomes-detail/{slug}",
                            "/api/v1/properties/{id}/schools",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~50K listings"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Neighborhood + agent + mortgage data"),
                        data_fields: sv(&[
                            "property_id",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                            "image_url",
                            "listing_type",
                            "days_on_market",
                            "lot_size",
                            "tax_history",
                            "price_history",
                            "school_data",
                            "features",
                            "agent_info",
                            "neighborhood",
                            "mortgage_rates",
                        ]),
                        endpoints: sv(&[
                            "/api/v1/hulk?client_id=rdc-x",
                            "/realestateandhomes-detail/{slug}",
                            "/api/v1/properties/{id}/schools",
                            "/api/v1/neighborhood/{zip}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~100K listings"),
                        estimated_time: s("~1 hour"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR"),
                        data_fields: sv(&[
                            "property_id",
                            "address",
                            "price",
                            "beds",
                            "baths",
                            "sqft",
                            "image_url",
                            "listing_type",
                            "days_on_market",
                            "lot_size",
                            "tax_history",
                            "price_history",
                            "school_data",
                            "features",
                            "agent_info",
                            "neighborhood",
                            "mortgage_rates",
                            "all_photos",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/api/v1/hulk?client_id=rdc-x",
                            "/realestateandhomes-detail/{slug}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~200K listings"),
                        estimated_time: s("~4 hours"),
                    },
                ),
            ]),
        },
        // ─── Finance ──────────────────────────────────────────────────
        SitePreset {
            domain: s("tradingview.com"),
            display_name: s("TradingView"),
            brand_color: s("#2962FF"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Scanner API — basic quotes"),
                        data_fields: sv(&["symbol", "price", "change", "signal"]),
                        endpoints: sv(&["/api/v1/symbols", "/scanner"]),
                        requires_auth: false,
                        estimated_items: s("~10K symbols"),
                        estimated_time: s("~2 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Scanner API — technical indicators"),
                        data_fields: sv(&[
                            "symbol", "price", "change", "signal", "volume", "rsi", "macd", "sma",
                        ]),
                        endpoints: sv(&["/api/v1/symbols", "/scanner", "/api/v1/study_templates"]),
                        requires_auth: false,
                        estimated_items: s("~10K symbols"),
                        estimated_time: s("~5 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Scanner API — fundamentals"),
                        data_fields: sv(&[
                            "symbol",
                            "price",
                            "change",
                            "signal",
                            "volume",
                            "rsi",
                            "macd",
                            "sma",
                            "pe_ratio",
                            "market_cap",
                            "eps",
                            "revenue",
                        ]),
                        endpoints: sv(&["/api/v1/symbols", "/scanner", "/api/v1/study_templates"]),
                        requires_auth: false,
                        estimated_items: s("~10K symbols"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("OHLCV history + community ideas via WebSocket"),
                        data_fields: sv(&[
                            "symbol",
                            "price",
                            "change",
                            "signal",
                            "volume",
                            "rsi",
                            "macd",
                            "sma",
                            "pe_ratio",
                            "market_cap",
                            "eps",
                            "revenue",
                            "ohlcv_history",
                            "economic_calendar",
                            "community_ideas",
                        ]),
                        endpoints: sv(&[
                            "/scanner",
                            "/api/v1/study_templates",
                            "wss://data.tradingview.com/socket.io",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K symbols + 5yr history"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Real-time stream + full session capture"),
                        data_fields: sv(&[
                            "symbol",
                            "price",
                            "change",
                            "signal",
                            "volume",
                            "rsi",
                            "macd",
                            "sma",
                            "pe_ratio",
                            "market_cap",
                            "eps",
                            "revenue",
                            "ohlcv_history",
                            "economic_calendar",
                            "community_ideas",
                            "real_time_stream",
                            "har_capture",
                            "full_session",
                        ]),
                        endpoints: sv(&[
                            "/scanner",
                            "wss://data.tradingview.com/socket.io",
                            "wss://prodata.tradingview.com/socket.io",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K symbols + live stream"),
                        estimated_time: s("continuous"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("site-14.example"),
            display_name: s("site-14.example"),
            brand_color: s("#0B6623"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Public quote pages"),
                        data_fields: sv(&["symbol", "name", "price", "change", "change_pct"]),
                        endpoints: sv(&["/equities/{slug}", "/currencies/{pair}"]),
                        requires_auth: false,
                        estimated_items: s("~5K instruments"),
                        estimated_time: s("~3 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Quote + technical summary"),
                        data_fields: sv(&[
                            "symbol",
                            "name",
                            "price",
                            "change",
                            "change_pct",
                            "volume",
                            "open",
                            "high",
                            "low",
                            "technical_summary",
                        ]),
                        endpoints: sv(&[
                            "/equities/{slug}",
                            "/currencies/{pair}",
                            "/technical/{slug}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K instruments"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Financials + ratios + earnings"),
                        data_fields: sv(&[
                            "symbol",
                            "name",
                            "price",
                            "change",
                            "change_pct",
                            "volume",
                            "open",
                            "high",
                            "low",
                            "technical_summary",
                            "income_statement",
                            "balance_sheet",
                            "pe_ratio",
                            "eps",
                            "dividend_yield",
                        ]),
                        endpoints: sv(&[
                            "/equities/{slug}",
                            "/technical/{slug}",
                            "/equities/{slug}-financial-summary",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K instruments"),
                        estimated_time: s("~20 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Historical data + economic calendar"),
                        data_fields: sv(&[
                            "symbol",
                            "name",
                            "price",
                            "change",
                            "change_pct",
                            "volume",
                            "open",
                            "high",
                            "low",
                            "technical_summary",
                            "income_statement",
                            "balance_sheet",
                            "pe_ratio",
                            "eps",
                            "dividend_yield",
                            "ohlcv_history",
                            "economic_calendar",
                            "analyst_ratings",
                        ]),
                        endpoints: sv(&[
                            "/equities/{slug}",
                            "/equities/{slug}-historical-data",
                            "/economic-calendar/",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K instruments + history"),
                        estimated_time: s("~45 min"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR"),
                        data_fields: sv(&[
                            "symbol",
                            "name",
                            "price",
                            "change",
                            "change_pct",
                            "volume",
                            "open",
                            "high",
                            "low",
                            "technical_summary",
                            "income_statement",
                            "balance_sheet",
                            "pe_ratio",
                            "eps",
                            "dividend_yield",
                            "ohlcv_history",
                            "economic_calendar",
                            "analyst_ratings",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/equities/{slug}",
                            "/equities/{slug}-historical-data",
                            "/economic-calendar/",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K instruments + history"),
                        estimated_time: s("~2 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("finance.yahoo.com"),
            display_name: s("Yahoo Finance"),
            brand_color: s("#6001D2"),
            default_level: ScrapeLevel::L1Scout,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Public quote API"),
                        data_fields: sv(&["symbol", "price", "change", "change_pct", "volume"]),
                        endpoints: sv(&["/v8/finance/chart/{symbol}", "/v7/finance/quote"]),
                        requires_auth: false,
                        estimated_items: s("~10K symbols"),
                        estimated_time: s("~2 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Quote + key stats"),
                        data_fields: sv(&[
                            "symbol",
                            "price",
                            "change",
                            "change_pct",
                            "volume",
                            "market_cap",
                            "pe_ratio",
                            "eps",
                            "dividend_yield",
                            "52w_high",
                            "52w_low",
                        ]),
                        endpoints: sv(&[
                            "/v8/finance/chart/{symbol}",
                            "/v7/finance/quote",
                            "/v10/finance/quoteSummary/{symbol}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K symbols"),
                        estimated_time: s("~5 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Financials + analyst ratings"),
                        data_fields: sv(&[
                            "symbol",
                            "price",
                            "change",
                            "change_pct",
                            "volume",
                            "market_cap",
                            "pe_ratio",
                            "eps",
                            "dividend_yield",
                            "52w_high",
                            "52w_low",
                            "income_statement",
                            "balance_sheet",
                            "cash_flow",
                            "analyst_ratings",
                        ]),
                        endpoints: sv(&[
                            "/v8/finance/chart/{symbol}",
                            "/v10/finance/quoteSummary/{symbol}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K symbols"),
                        estimated_time: s("~15 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Historical OHLCV + options chain"),
                        data_fields: sv(&[
                            "symbol",
                            "price",
                            "change",
                            "change_pct",
                            "volume",
                            "market_cap",
                            "pe_ratio",
                            "eps",
                            "dividend_yield",
                            "52w_high",
                            "52w_low",
                            "income_statement",
                            "balance_sheet",
                            "cash_flow",
                            "analyst_ratings",
                            "ohlcv_history",
                            "options_chain",
                            "insider_transactions",
                        ]),
                        endpoints: sv(&[
                            "/v8/finance/chart/{symbol}",
                            "/v10/finance/quoteSummary/{symbol}",
                            "/v7/finance/options/{symbol}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K symbols + options"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR"),
                        data_fields: sv(&[
                            "symbol",
                            "price",
                            "change",
                            "change_pct",
                            "volume",
                            "market_cap",
                            "pe_ratio",
                            "eps",
                            "dividend_yield",
                            "52w_high",
                            "52w_low",
                            "income_statement",
                            "balance_sheet",
                            "cash_flow",
                            "analyst_ratings",
                            "ohlcv_history",
                            "options_chain",
                            "insider_transactions",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/v8/finance/chart/{symbol}",
                            "/v10/finance/quoteSummary/{symbol}",
                            "/v7/finance/options/{symbol}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K symbols"),
                        estimated_time: s("~2 hours"),
                    },
                ),
            ]),
        },
        // ─── News ─────────────────────────────────────────────────────
        SitePreset {
            domain: s("site-38.example"),
            display_name: s("Zacks"),
            brand_color: s("#0057B8"),
            default_level: ScrapeLevel::L3Deep,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Public quote pages and basic market stats"),
                        data_fields: sv(&[
                            "symbol",
                            "company_name",
                            "last_price",
                            "change",
                            "change_pct",
                            "quote_time",
                        ]),
                        endpoints: sv(&["/stock/quote/{symbol}"]),
                        requires_auth: false,
                        estimated_items: s("~8K symbols"),
                        estimated_time: s("~3 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Quote plus rank headline and earnings date"),
                        data_fields: sv(&[
                            "symbol",
                            "company_name",
                            "last_price",
                            "change",
                            "change_pct",
                            "quote_time",
                            "zacks_rank",
                            "rank_text",
                            "industry_rank",
                            "earnings_date",
                        ]),
                        endpoints: sv(&["/stock/quote/{symbol}", "/stock/research/{symbol}"]),
                        requires_auth: false,
                        estimated_items: s("~8K symbols"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Rank factors, style scores, and estimate revisions"),
                        data_fields: sv(&[
                            "symbol",
                            "company_name",
                            "last_price",
                            "change",
                            "change_pct",
                            "quote_time",
                            "zacks_rank",
                            "rank_text",
                            "industry_rank",
                            "earnings_date",
                            "style_score_value",
                            "style_score_growth",
                            "style_score_momentum",
                            "style_score_vgm",
                            "eps_estimate_current_year",
                            "eps_estimate_next_year",
                            "revision_30d",
                        ]),
                        endpoints: sv(&[
                            "/stock/quote/{symbol}",
                            "/stock/research/{symbol}",
                            "/stock/quote/{symbol}/earnings-estimates",
                        ]),
                        requires_auth: true,
                        estimated_items: s("~8K symbols"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Detailed estimate tables and research metadata"),
                        data_fields: sv(&[
                            "symbol",
                            "company_name",
                            "last_price",
                            "change",
                            "change_pct",
                            "quote_time",
                            "zacks_rank",
                            "rank_text",
                            "industry_rank",
                            "earnings_date",
                            "style_score_value",
                            "style_score_growth",
                            "style_score_momentum",
                            "style_score_vgm",
                            "eps_estimate_current_year",
                            "eps_estimate_next_year",
                            "revision_30d",
                            "earnings_surprise_history",
                            "brokerage_recommendations",
                            "news_headlines",
                            "research_article_meta",
                        ]),
                        endpoints: sv(&[
                            "/stock/quote/{symbol}",
                            "/stock/research/{symbol}",
                            "/stock/quote/{symbol}/earnings-estimates",
                            "/stock/research/{symbol}/brokerage-recommendations",
                        ]),
                        requires_auth: true,
                        estimated_items: s("~8K symbols + estimate tables"),
                        estimated_time: s("~90 min"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s(
                            "Full research archive with ranking history and session artifacts",
                        ),
                        data_fields: sv(&[
                            "symbol",
                            "company_name",
                            "last_price",
                            "change",
                            "change_pct",
                            "quote_time",
                            "zacks_rank",
                            "rank_text",
                            "industry_rank",
                            "earnings_date",
                            "style_score_value",
                            "style_score_growth",
                            "style_score_momentum",
                            "style_score_vgm",
                            "eps_estimate_current_year",
                            "eps_estimate_next_year",
                            "revision_30d",
                            "earnings_surprise_history",
                            "brokerage_recommendations",
                            "news_headlines",
                            "research_article_meta",
                            "rank_history",
                            "estimate_revision_history",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/stock/quote/{symbol}",
                            "/stock/research/{symbol}",
                            "/stock/quote/{symbol}/earnings-estimates",
                            "/stock/research/{symbol}/brokerage-recommendations",
                            "/stock/news/{symbol}",
                        ]),
                        requires_auth: true,
                        estimated_items: s("~8K symbols + history"),
                        estimated_time: s("~4 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("site-21.example"),
            display_name: s("New York Times"),
            brand_color: s("#000000"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("RSS feeds + public headlines"),
                        data_fields: sv(&["title", "url", "published_date", "section"]),
                        endpoints: sv(&[
                            "/svc/collections/v1/publish/site-21.example/section/{section}",
                            "/services/xml/rss/nyt/{section}.xml",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~500 articles"),
                        estimated_time: s("~1 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Article metadata + snippets"),
                        data_fields: sv(&[
                            "title",
                            "url",
                            "published_date",
                            "section",
                            "author",
                            "snippet",
                            "image_url",
                            "tags",
                        ]),
                        endpoints: sv(&[
                            "/svc/collections/v1/publish/site-21.example/section/{section}",
                            "/{year}/{month}/{day}/{slug}.html",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~2K articles"),
                        estimated_time: s("~5 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full article text + related"),
                        data_fields: sv(&[
                            "title",
                            "url",
                            "published_date",
                            "section",
                            "author",
                            "snippet",
                            "image_url",
                            "tags",
                            "full_text",
                            "related_articles",
                            "comments_count",
                        ]),
                        endpoints: sv(&["/{year}/{month}/{day}/{slug}.html"]),
                        requires_auth: false,
                        estimated_items: s("~5K articles"),
                        estimated_time: s("~15 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Archive + comments + media"),
                        data_fields: sv(&[
                            "title",
                            "url",
                            "published_date",
                            "section",
                            "author",
                            "snippet",
                            "image_url",
                            "tags",
                            "full_text",
                            "related_articles",
                            "comments_count",
                            "comments_text",
                            "embedded_media",
                            "archive_metadata",
                        ]),
                        endpoints: sv(&[
                            "/{year}/{month}/{day}/{slug}.html",
                            "/svc/community/V3/requestHandler",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K articles"),
                        estimated_time: s("~45 min"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR + media download"),
                        data_fields: sv(&[
                            "title",
                            "url",
                            "published_date",
                            "section",
                            "author",
                            "snippet",
                            "image_url",
                            "tags",
                            "full_text",
                            "related_articles",
                            "comments_count",
                            "comments_text",
                            "embedded_media",
                            "archive_metadata",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/{year}/{month}/{day}/{slug}.html",
                            "/svc/community/V3/requestHandler",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~20K articles"),
                        estimated_time: s("~3 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("site-03.example"),
            display_name: s("Bloomberg"),
            brand_color: s("#000000"),
            default_level: ScrapeLevel::L3Deep,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Public headlines + market data"),
                        data_fields: sv(&["title", "url", "published_date", "section"]),
                        endpoints: sv(&["/markets", "/technology", "/politics"]),
                        requires_auth: false,
                        estimated_items: s("~200 articles"),
                        estimated_time: s("~2 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Article previews + author"),
                        data_fields: sv(&[
                            "title",
                            "url",
                            "published_date",
                            "section",
                            "author",
                            "snippet",
                            "image_url",
                        ]),
                        endpoints: sv(&[
                            "/markets",
                            "/technology",
                            "/politics",
                            "/news/articles/{slug}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~1K articles"),
                        estimated_time: s("~5 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full article text (paywall bypass via cache)"),
                        data_fields: sv(&[
                            "title",
                            "url",
                            "published_date",
                            "section",
                            "author",
                            "snippet",
                            "image_url",
                            "full_text",
                            "tags",
                            "tickers_mentioned",
                        ]),
                        endpoints: sv(&["/news/articles/{slug}", "/tosv2.html?vid={vid}"]),
                        requires_auth: false,
                        estimated_items: s("~3K articles"),
                        estimated_time: s("~15 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Market data terminal quotes"),
                        data_fields: sv(&[
                            "title",
                            "url",
                            "published_date",
                            "section",
                            "author",
                            "snippet",
                            "image_url",
                            "full_text",
                            "tags",
                            "tickers_mentioned",
                            "market_data",
                            "company_profile",
                            "earnings_data",
                        ]),
                        endpoints: sv(&[
                            "/news/articles/{slug}",
                            "/quote/{ticker}",
                            "/profile/{ticker}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~5K articles + 2K quotes"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR"),
                        data_fields: sv(&[
                            "title",
                            "url",
                            "published_date",
                            "section",
                            "author",
                            "snippet",
                            "image_url",
                            "full_text",
                            "tags",
                            "tickers_mentioned",
                            "market_data",
                            "company_profile",
                            "earnings_data",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/news/articles/{slug}",
                            "/quote/{ticker}",
                            "/profile/{ticker}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~10K articles"),
                        estimated_time: s("~2 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("site-26.example"),
            display_name: s("Reuters"),
            brand_color: s("#FF8000"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Public wire feed"),
                        data_fields: sv(&["title", "url", "published_date", "section"]),
                        endpoints: sv(&[
                            "/pf/api/v3/content/fetch/articles-by-section-alias-or-id-v1",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~500 articles"),
                        estimated_time: s("~1 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Article metadata + snippets"),
                        data_fields: sv(&[
                            "title",
                            "url",
                            "published_date",
                            "section",
                            "author",
                            "snippet",
                            "image_url",
                            "tags",
                        ]),
                        endpoints: sv(&[
                            "/pf/api/v3/content/fetch/articles-by-section-alias-or-id-v1",
                            "/{section}/{slug}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~2K articles"),
                        estimated_time: s("~5 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full article text"),
                        data_fields: sv(&[
                            "title",
                            "url",
                            "published_date",
                            "section",
                            "author",
                            "snippet",
                            "image_url",
                            "tags",
                            "full_text",
                            "related_articles",
                        ]),
                        endpoints: sv(&["/{section}/{slug}"]),
                        requires_auth: false,
                        estimated_items: s("~5K articles"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Archive + market data"),
                        data_fields: sv(&[
                            "title",
                            "url",
                            "published_date",
                            "section",
                            "author",
                            "snippet",
                            "image_url",
                            "tags",
                            "full_text",
                            "related_articles",
                            "market_data",
                            "company_news",
                        ]),
                        endpoints: sv(&["/{section}/{slug}", "/markets/companies/{ric}"]),
                        requires_auth: false,
                        estimated_items: s("~10K articles"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR"),
                        data_fields: sv(&[
                            "title",
                            "url",
                            "published_date",
                            "section",
                            "author",
                            "snippet",
                            "image_url",
                            "tags",
                            "full_text",
                            "related_articles",
                            "market_data",
                            "company_news",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&["/{section}/{slug}", "/markets/companies/{ric}"]),
                        requires_auth: false,
                        estimated_items: s("~20K articles"),
                        estimated_time: s("~2 hours"),
                    },
                ),
            ]),
        },
        // ─── E-commerce ───────────────────────────────────────────────
        SitePreset {
            domain: s("shop-27.example"),
            display_name: s("eBay"),
            brand_color: s("#E53238"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Search results scrape"),
                        data_fields: sv(&["item_id", "title", "price", "url"]),
                        endpoints: sv(&["/sch/i.html?_nkw={query}"]),
                        requires_auth: false,
                        estimated_items: s("~10K listings"),
                        estimated_time: s("~3 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Listing detail + images"),
                        data_fields: sv(&[
                            "item_id",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "seller",
                            "condition",
                            "shipping_cost",
                            "bids",
                            "time_left",
                        ]),
                        endpoints: sv(&["/sch/i.html?_nkw={query}", "/itm/{item_id}"]),
                        requires_auth: false,
                        estimated_items: s("~30K listings"),
                        estimated_time: s("~15 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full listing + seller feedback"),
                        data_fields: sv(&[
                            "item_id",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "seller",
                            "condition",
                            "shipping_cost",
                            "bids",
                            "time_left",
                            "seller_feedback_score",
                            "item_specifics",
                            "description_html",
                            "category_path",
                        ]),
                        endpoints: sv(&["/sch/i.html?_nkw={query}", "/itm/{item_id}"]),
                        requires_auth: false,
                        estimated_items: s("~50K listings"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Completed listings + price history"),
                        data_fields: sv(&[
                            "item_id",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "seller",
                            "condition",
                            "shipping_cost",
                            "bids",
                            "time_left",
                            "seller_feedback_score",
                            "item_specifics",
                            "description_html",
                            "category_path",
                            "completed_price",
                            "sold_count",
                            "watchers",
                        ]),
                        endpoints: sv(&[
                            "/sch/i.html?_nkw={query}",
                            "/itm/{item_id}",
                            "/sch/i.html?_nkw={query}&LH_Complete=1&LH_Sold=1",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~100K listings"),
                        estimated_time: s("~1 hour"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR"),
                        data_fields: sv(&[
                            "item_id",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "seller",
                            "condition",
                            "shipping_cost",
                            "bids",
                            "time_left",
                            "seller_feedback_score",
                            "item_specifics",
                            "description_html",
                            "category_path",
                            "completed_price",
                            "sold_count",
                            "watchers",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&["/sch/i.html?_nkw={query}", "/itm/{item_id}"]),
                        requires_auth: false,
                        estimated_items: s("~200K listings"),
                        estimated_time: s("~4 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("shop-c.example"),
            display_name: s("Best Buy"),
            brand_color: s("#0046BE"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Product search API"),
                        data_fields: sv(&["sku", "name", "price", "url"]),
                        endpoints: sv(&["/api/tcfb/model.json?paths=%5B%5B%22shop%22"]),
                        requires_auth: false,
                        estimated_items: s("~5K products"),
                        estimated_time: s("~3 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Product detail + specs"),
                        data_fields: sv(&[
                            "sku",
                            "name",
                            "price",
                            "url",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "availability",
                        ]),
                        endpoints: sv(&["/api/tcfb/model.json", "/site/{slug}/{sku}.p"]),
                        requires_auth: false,
                        estimated_items: s("~20K products"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full specs + open-box pricing"),
                        data_fields: sv(&[
                            "sku",
                            "name",
                            "price",
                            "url",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "availability",
                            "specifications",
                            "open_box_price",
                            "category_path",
                            "model_number",
                        ]),
                        endpoints: sv(&[
                            "/api/tcfb/model.json",
                            "/site/{slug}/{sku}.p",
                            "/api/3.0/priceBlocks",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~30K products"),
                        estimated_time: s("~20 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Reviews + store inventory"),
                        data_fields: sv(&[
                            "sku",
                            "name",
                            "price",
                            "url",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "availability",
                            "specifications",
                            "open_box_price",
                            "category_path",
                            "model_number",
                            "reviews_text",
                            "store_availability",
                            "price_history",
                        ]),
                        endpoints: sv(&[
                            "/api/tcfb/model.json",
                            "/site/{slug}/{sku}.p",
                            "/api/3.0/priceBlocks",
                            "/ugc/v2/reviews",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~50K products"),
                        estimated_time: s("~45 min"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR"),
                        data_fields: sv(&[
                            "sku",
                            "name",
                            "price",
                            "url",
                            "image_url",
                            "rating",
                            "review_count",
                            "brand",
                            "availability",
                            "specifications",
                            "open_box_price",
                            "category_path",
                            "model_number",
                            "reviews_text",
                            "store_availability",
                            "price_history",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/api/tcfb/model.json",
                            "/site/{slug}/{sku}.p",
                            "/ugc/v2/reviews",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~50K products"),
                        estimated_time: s("~3 hours"),
                    },
                ),
            ]),
        },
        // ─── Social ───────────────────────────────────────────────────
        SitePreset {
            domain: s("site-24.example"),
            display_name: s("Reddit"),
            brand_color: s("#FF4500"),
            default_level: ScrapeLevel::L1Scout,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Public JSON API"),
                        data_fields: sv(&[
                            "id",
                            "title",
                            "subreddit",
                            "score",
                            "url",
                            "num_comments",
                        ]),
                        endpoints: sv(&["/r/{subreddit}.json", "/r/{subreddit}/hot.json"]),
                        requires_auth: false,
                        estimated_items: s("~10K posts"),
                        estimated_time: s("~2 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Post detail + top comments"),
                        data_fields: sv(&[
                            "id",
                            "title",
                            "subreddit",
                            "score",
                            "url",
                            "num_comments",
                            "author",
                            "selftext",
                            "created_utc",
                            "top_comments",
                        ]),
                        endpoints: sv(&[
                            "/r/{subreddit}.json",
                            "/r/{subreddit}/comments/{id}.json",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~20K posts"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full comment trees + user profiles"),
                        data_fields: sv(&[
                            "id",
                            "title",
                            "subreddit",
                            "score",
                            "url",
                            "num_comments",
                            "author",
                            "selftext",
                            "created_utc",
                            "top_comments",
                            "all_comments",
                            "author_karma",
                            "author_account_age",
                        ]),
                        endpoints: sv(&[
                            "/r/{subreddit}.json",
                            "/r/{subreddit}/comments/{id}.json",
                            "/user/{author}/about.json",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~50K posts"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Subreddit analytics + crosspost tracking"),
                        data_fields: sv(&[
                            "id",
                            "title",
                            "subreddit",
                            "score",
                            "url",
                            "num_comments",
                            "author",
                            "selftext",
                            "created_utc",
                            "top_comments",
                            "all_comments",
                            "author_karma",
                            "author_account_age",
                            "crosspost_info",
                            "flair",
                            "awards",
                            "upvote_ratio",
                        ]),
                        endpoints: sv(&[
                            "/r/{subreddit}.json",
                            "/r/{subreddit}/comments/{id}.json",
                            "/user/{author}/about.json",
                            "/api/info.json",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~100K posts"),
                        estimated_time: s("~1 hour"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + media + HAR"),
                        data_fields: sv(&[
                            "id",
                            "title",
                            "subreddit",
                            "score",
                            "url",
                            "num_comments",
                            "author",
                            "selftext",
                            "created_utc",
                            "top_comments",
                            "all_comments",
                            "author_karma",
                            "author_account_age",
                            "crosspost_info",
                            "flair",
                            "awards",
                            "upvote_ratio",
                            "media_urls",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/r/{subreddit}.json",
                            "/r/{subreddit}/comments/{id}.json",
                            "/user/{author}/about.json",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~200K posts"),
                        estimated_time: s("~4 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("site-16.example"),
            display_name: s("LinkedIn"),
            brand_color: s("#0A66C2"),
            default_level: ScrapeLevel::L4Full,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Public profile snippets via Google cache"),
                        data_fields: sv(&["name", "headline", "location", "profile_url"]),
                        endpoints: sv(&["/in/{slug}"]),
                        requires_auth: false,
                        estimated_items: s("~500 profiles"),
                        estimated_time: s("~5 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Public profile + company pages"),
                        data_fields: sv(&[
                            "name",
                            "headline",
                            "location",
                            "profile_url",
                            "company",
                            "title",
                            "summary",
                        ]),
                        endpoints: sv(&["/in/{slug}", "/company/{slug}"]),
                        requires_auth: false,
                        estimated_items: s("~2K profiles"),
                        estimated_time: s("~15 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full profile + experience history"),
                        data_fields: sv(&[
                            "name",
                            "headline",
                            "location",
                            "profile_url",
                            "company",
                            "title",
                            "summary",
                            "experience",
                            "education",
                            "skills",
                            "connections_count",
                        ]),
                        endpoints: sv(&["/in/{slug}", "/voyager/api/identity/profiles/{id}"]),
                        requires_auth: true,
                        estimated_items: s("~5K profiles"),
                        estimated_time: s("~30 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Job listings + company employees"),
                        data_fields: sv(&[
                            "name",
                            "headline",
                            "location",
                            "profile_url",
                            "company",
                            "title",
                            "summary",
                            "experience",
                            "education",
                            "skills",
                            "connections_count",
                            "job_listings",
                            "company_employees",
                            "endorsements",
                        ]),
                        endpoints: sv(&[
                            "/in/{slug}",
                            "/voyager/api/identity/profiles/{id}",
                            "/voyager/api/search/dash/clusters",
                            "/jobs/search",
                        ]),
                        requires_auth: true,
                        estimated_items: s("~10K profiles"),
                        estimated_time: s("~1 hour"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full network graph + HAR"),
                        data_fields: sv(&[
                            "name",
                            "headline",
                            "location",
                            "profile_url",
                            "company",
                            "title",
                            "summary",
                            "experience",
                            "education",
                            "skills",
                            "connections_count",
                            "job_listings",
                            "company_employees",
                            "endorsements",
                            "activity_feed",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/in/{slug}",
                            "/voyager/api/identity/profiles/{id}",
                            "/voyager/api/search/dash/clusters",
                        ]),
                        requires_auth: true,
                        estimated_items: s("~20K profiles"),
                        estimated_time: s("~4 hours"),
                    },
                ),
            ]),
        },
        // ─── Extra grocery stores ─────────────────────────────────────
        // (Amazon is already above as "Amazon / Whole Foods")

        // ─── Additional e-commerce ────────────────────────────────────
        SitePreset {
            domain: s("shop-59.example"),
            display_name: s("Newegg"),
            brand_color: s("#CF6412"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Search results page"),
                        data_fields: sv(&["item_number", "title", "price", "url"]),
                        endpoints: sv(&["/p/pl?d={query}"]),
                        requires_auth: false,
                        estimated_items: s("~5K products"),
                        estimated_time: s("~3 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Product cards + specs"),
                        data_fields: sv(&[
                            "item_number",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "brand",
                            "rating",
                            "review_count",
                            "shipping",
                        ]),
                        endpoints: sv(&["/p/pl?d={query}", "/p/{item_number}"]),
                        requires_auth: false,
                        estimated_items: s("~15K products"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full specs + seller info"),
                        data_fields: sv(&[
                            "item_number",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "brand",
                            "rating",
                            "review_count",
                            "shipping",
                            "specifications",
                            "seller_name",
                            "seller_rating",
                            "warranty",
                        ]),
                        endpoints: sv(&["/p/pl?d={query}", "/p/{item_number}"]),
                        requires_auth: false,
                        estimated_items: s("~30K products"),
                        estimated_time: s("~20 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Reviews + price tracking + combos"),
                        data_fields: sv(&[
                            "item_number",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "brand",
                            "rating",
                            "review_count",
                            "shipping",
                            "specifications",
                            "seller_name",
                            "seller_rating",
                            "warranty",
                            "reviews_text",
                            "price_history",
                            "combo_deals",
                        ]),
                        endpoints: sv(&[
                            "/p/pl?d={query}",
                            "/p/{item_number}",
                            "/product/api/ReviewSummary",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~50K products"),
                        estimated_time: s("~45 min"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR"),
                        data_fields: sv(&[
                            "item_number",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "brand",
                            "rating",
                            "review_count",
                            "shipping",
                            "specifications",
                            "seller_name",
                            "seller_rating",
                            "warranty",
                            "reviews_text",
                            "price_history",
                            "combo_deals",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&["/p/pl?d={query}", "/p/{item_number}"]),
                        requires_auth: false,
                        estimated_items: s("~50K products"),
                        estimated_time: s("~3 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("shop-41.example"),
            display_name: s("Home Depot"),
            brand_color: s("#F96302"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Search API product listing"),
                        data_fields: sv(&["product_id", "name", "price", "url"]),
                        endpoints: sv(&["/federation-gateway/graphql?opname=searchModel"]),
                        requires_auth: false,
                        estimated_items: s("~5K products"),
                        estimated_time: s("~3 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Product detail + images"),
                        data_fields: sv(&[
                            "product_id",
                            "name",
                            "price",
                            "url",
                            "image_url",
                            "brand",
                            "rating",
                            "review_count",
                            "model_number",
                        ]),
                        endpoints: sv(&[
                            "/federation-gateway/graphql?opname=searchModel",
                            "/p/{slug}/{product_id}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~20K products"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full specs + store inventory"),
                        data_fields: sv(&[
                            "product_id",
                            "name",
                            "price",
                            "url",
                            "image_url",
                            "brand",
                            "rating",
                            "review_count",
                            "model_number",
                            "specifications",
                            "store_inventory",
                            "delivery_options",
                            "category_path",
                        ]),
                        endpoints: sv(&[
                            "/federation-gateway/graphql?opname=searchModel",
                            "/p/{slug}/{product_id}",
                            "/federation-gateway/graphql?opname=storeSearch",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~40K products"),
                        estimated_time: s("~25 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Reviews + Q&A + related"),
                        data_fields: sv(&[
                            "product_id",
                            "name",
                            "price",
                            "url",
                            "image_url",
                            "brand",
                            "rating",
                            "review_count",
                            "model_number",
                            "specifications",
                            "store_inventory",
                            "delivery_options",
                            "category_path",
                            "reviews_text",
                            "questions_answers",
                            "related_products",
                        ]),
                        endpoints: sv(&[
                            "/federation-gateway/graphql?opname=searchModel",
                            "/p/{slug}/{product_id}",
                            "/federation-gateway/graphql?opname=storeSearch",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~60K products"),
                        estimated_time: s("~1 hour"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR"),
                        data_fields: sv(&[
                            "product_id",
                            "name",
                            "price",
                            "url",
                            "image_url",
                            "brand",
                            "rating",
                            "review_count",
                            "model_number",
                            "specifications",
                            "store_inventory",
                            "delivery_options",
                            "category_path",
                            "reviews_text",
                            "questions_answers",
                            "related_products",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&["/federation-gateway/graphql", "/p/{slug}/{product_id}"]),
                        requires_auth: false,
                        estimated_items: s("~60K products"),
                        estimated_time: s("~4 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("shop-54.example"),
            display_name: s("Lowe's"),
            brand_color: s("#004990"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Search API"),
                        data_fields: sv(&["product_id", "name", "price", "url"]),
                        endpoints: sv(&["/search?searchTerm={query}"]),
                        requires_auth: false,
                        estimated_items: s("~5K products"),
                        estimated_time: s("~3 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Product detail + images"),
                        data_fields: sv(&[
                            "product_id",
                            "name",
                            "price",
                            "url",
                            "image_url",
                            "brand",
                            "rating",
                            "review_count",
                            "model_number",
                        ]),
                        endpoints: sv(&["/search?searchTerm={query}", "/pd/{slug}/{product_id}"]),
                        requires_auth: false,
                        estimated_items: s("~20K products"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full specs + availability"),
                        data_fields: sv(&[
                            "product_id",
                            "name",
                            "price",
                            "url",
                            "image_url",
                            "brand",
                            "rating",
                            "review_count",
                            "model_number",
                            "specifications",
                            "store_availability",
                            "delivery_options",
                        ]),
                        endpoints: sv(&["/search?searchTerm={query}", "/pd/{slug}/{product_id}"]),
                        requires_auth: false,
                        estimated_items: s("~40K products"),
                        estimated_time: s("~25 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Reviews + installation services"),
                        data_fields: sv(&[
                            "product_id",
                            "name",
                            "price",
                            "url",
                            "image_url",
                            "brand",
                            "rating",
                            "review_count",
                            "model_number",
                            "specifications",
                            "store_availability",
                            "delivery_options",
                            "reviews_text",
                            "installation_available",
                            "related_products",
                        ]),
                        endpoints: sv(&[
                            "/search?searchTerm={query}",
                            "/pd/{slug}/{product_id}",
                            "/reviews/v2/{product_id}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~60K products"),
                        estimated_time: s("~1 hour"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR"),
                        data_fields: sv(&[
                            "product_id",
                            "name",
                            "price",
                            "url",
                            "image_url",
                            "brand",
                            "rating",
                            "review_count",
                            "model_number",
                            "specifications",
                            "store_availability",
                            "delivery_options",
                            "reviews_text",
                            "installation_available",
                            "related_products",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&["/search?searchTerm={query}", "/pd/{slug}/{product_id}"]),
                        requires_auth: false,
                        estimated_items: s("~60K products"),
                        estimated_time: s("~4 hours"),
                    },
                ),
            ]),
        },
        SitePreset {
            domain: s("site-08.example"),
            display_name: s("Etsy"),
            brand_color: s("#F16521"),
            default_level: ScrapeLevel::L2Standard,
            levels: levels([
                (
                    ScrapeLevel::L1Scout,
                    SiteLevelData {
                        description: s("Search results page"),
                        data_fields: sv(&["listing_id", "title", "price", "url"]),
                        endpoints: sv(&["/search?q={query}"]),
                        requires_auth: false,
                        estimated_items: s("~10K listings"),
                        estimated_time: s("~3 min"),
                    },
                ),
                (
                    ScrapeLevel::L2Standard,
                    SiteLevelData {
                        description: s("Listing detail + shop info"),
                        data_fields: sv(&[
                            "listing_id",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "shop_name",
                            "rating",
                            "review_count",
                            "shipping",
                        ]),
                        endpoints: sv(&["/search?q={query}", "/listing/{listing_id}"]),
                        requires_auth: false,
                        estimated_items: s("~20K listings"),
                        estimated_time: s("~10 min"),
                    },
                ),
                (
                    ScrapeLevel::L3Deep,
                    SiteLevelData {
                        description: s("Full listing + reviews + variations"),
                        data_fields: sv(&[
                            "listing_id",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "shop_name",
                            "rating",
                            "review_count",
                            "shipping",
                            "variations",
                            "materials",
                            "description",
                            "category_path",
                        ]),
                        endpoints: sv(&["/search?q={query}", "/listing/{listing_id}"]),
                        requires_auth: false,
                        estimated_items: s("~40K listings"),
                        estimated_time: s("~25 min"),
                    },
                ),
                (
                    ScrapeLevel::L4Full,
                    SiteLevelData {
                        description: s("Shop analytics + review text"),
                        data_fields: sv(&[
                            "listing_id",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "shop_name",
                            "rating",
                            "review_count",
                            "shipping",
                            "variations",
                            "materials",
                            "description",
                            "category_path",
                            "reviews_text",
                            "shop_sales_count",
                            "favorited_count",
                        ]),
                        endpoints: sv(&[
                            "/search?q={query}",
                            "/listing/{listing_id}",
                            "/shop/{shop_name}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~80K listings"),
                        estimated_time: s("~1 hour"),
                    },
                ),
                (
                    ScrapeLevel::L5Maximum,
                    SiteLevelData {
                        description: s("Full archive + HAR"),
                        data_fields: sv(&[
                            "listing_id",
                            "title",
                            "price",
                            "url",
                            "image_url",
                            "shop_name",
                            "rating",
                            "review_count",
                            "shipping",
                            "variations",
                            "materials",
                            "description",
                            "category_path",
                            "reviews_text",
                            "shop_sales_count",
                            "favorited_count",
                            "har_capture",
                            "full_html",
                        ]),
                        endpoints: sv(&[
                            "/search?q={query}",
                            "/listing/{listing_id}",
                            "/shop/{shop_name}",
                        ]),
                        requires_auth: false,
                        estimated_items: s("~100K listings"),
                        estimated_time: s("~4 hours"),
                    },
                ),
            ]),
        },
    ]
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_config_roundtrip() {
        for level in ScrapeLevel::all() {
            let cfg = LevelConfig::from_level(*level);
            assert_eq!(cfg.level, *level);
            assert!(!cfg.name.is_empty());
            assert!(!cfg.description.is_empty());
            assert!(cfg.max_concurrency >= 1);
            assert!(cfg.rate_limit_per_second > 0.0);
            assert!(cfg.encryption_layers >= 1);
        }
    }

    #[test]
    fn level_contract_core_fields_match_expected_values() {
        let cases = [
            (
                ScrapeLevel::L1Scout,
                "http",
                "raw_html",
                "tor",
                20_u32,
                5.0_f64,
                false,
                false,
                false,
            ),
            (
                ScrapeLevel::L2Standard,
                "stealth_http",
                "smart_extract",
                "auto",
                10_u32,
                2.0_f64,
                false,
                false,
                false,
            ),
            (
                ScrapeLevel::L3Deep,
                "stealth_http",
                "smart_extract",
                "residential",
                5_u32,
                1.0_f64,
                false,
                false,
                false,
            ),
            (
                ScrapeLevel::L4Full,
                "dual_mode",
                "llm_extract",
                "residential",
                3_u32,
                0.5_f64,
                false,
                false,
                false,
            ),
            (
                ScrapeLevel::L5Maximum,
                "dual_mode",
                "smart_extract",
                "mobile",
                200_u32,
                0.3_f64,
                true,
                false,
                true,
            ),
        ];

        for (
            level,
            engine_mode,
            extraction_mode,
            proxy_tier,
            max_concurrency,
            rate_limit_per_second,
            har_capture,
            screenshot_capture,
            full_html_archive,
        ) in cases
        {
            let cfg = LevelConfig::from_level(level);
            assert_eq!(
                cfg.engine_mode, engine_mode,
                "engine_mode mismatch for {level:?}"
            );
            assert_eq!(
                cfg.extraction_mode, extraction_mode,
                "extraction_mode mismatch for {level:?}"
            );
            assert_eq!(
                cfg.proxy_tier, proxy_tier,
                "proxy_tier mismatch for {level:?}"
            );
            assert_eq!(
                cfg.max_concurrency, max_concurrency,
                "max_concurrency mismatch for {level:?}"
            );
            assert!(
                (cfg.rate_limit_per_second - rate_limit_per_second).abs() < 1e-12,
                "rate_limit_per_second mismatch for {level:?}: expected {}, got {}",
                rate_limit_per_second,
                cfg.rate_limit_per_second
            );
            assert_eq!(
                cfg.har_capture, har_capture,
                "har_capture mismatch for {level:?}"
            );
            assert_eq!(
                cfg.screenshot_capture, screenshot_capture,
                "screenshot_capture mismatch for {level:?}"
            );
            assert_eq!(
                cfg.full_html_archive, full_html_archive,
                "full_html_archive mismatch for {level:?}"
            );
        }
    }

    #[test]
    fn level_ordering() {
        assert!(ScrapeLevel::L1Scout.rank() < ScrapeLevel::L2Standard.rank());
        assert!(ScrapeLevel::L2Standard.rank() < ScrapeLevel::L3Deep.rank());
        assert!(ScrapeLevel::L3Deep.rank() < ScrapeLevel::L4Full.rank());
        assert!(ScrapeLevel::L4Full.rank() < ScrapeLevel::L5Maximum.rank());
    }

    #[test]
    fn stealth_escalation() {
        let l1 = LevelConfig::from_level(ScrapeLevel::L1Scout);
        let l3 = LevelConfig::from_level(ScrapeLevel::L3Deep);
        let l5 = LevelConfig::from_level(ScrapeLevel::L5Maximum);

        assert!(!l1.stealth_enabled);
        assert!(l3.stealth_enabled);
        assert!(l3.stealth_v3_enabled);
        assert!(l5.behavioral_sim);
        assert!(l5.slider_captcha);
        assert!(l5.har_capture);
    }

    #[test]
    fn concurrency_tightens_through_l4_with_l5_bulk_exception() {
        let levels = ScrapeLevel::all();
        for pair in levels.windows(2) {
            let lower = LevelConfig::from_level(pair[0]);
            let higher = LevelConfig::from_level(pair[1]);
            if pair[1] == ScrapeLevel::L5Maximum {
                continue;
            }
            assert!(
                lower.max_concurrency >= higher.max_concurrency,
                "L{} concurrency {} should be >= L{} concurrency {}",
                pair[0].rank(),
                lower.max_concurrency,
                pair[1].rank(),
                higher.max_concurrency,
            );
        }

        let l5 = LevelConfig::from_level(ScrapeLevel::L5Maximum);
        assert_eq!(
            l5.max_concurrency, 200,
            "L5 maximum concurrency should remain the bulk-scrape override"
        );
    }

    #[test]
    fn l5_runtime_profile_matches_bulk_scrape_truth() {
        let l5 = LevelConfig::from_level(ScrapeLevel::L5Maximum);
        assert_eq!(l5.engine_mode, "dual_mode");
        assert_eq!(l5.extraction_mode, "smart_extract");
        assert_eq!(l5.max_concurrency, 200);
        assert!(l5.har_capture);
        assert!(!l5.screenshot_capture);
        assert!(l5.full_html_archive);
    }

    #[test]
    fn rate_decreases_with_level() {
        let levels = ScrapeLevel::all();
        for pair in levels.windows(2) {
            let lower = LevelConfig::from_level(pair[0]);
            let higher = LevelConfig::from_level(pair[1]);
            assert!(
                lower.rate_limit_per_second >= higher.rate_limit_per_second,
                "L{} rate {} should be >= L{} rate {}",
                pair[0].rank(),
                lower.rate_limit_per_second,
                pair[1].rank(),
                higher.rate_limit_per_second,
            );
        }
    }

    #[test]
    fn preset_manager_loads_all_sites() {
        let mgr = PresetManager::new();
        let sites = mgr.list_sites();
        assert!(
            sites.len() >= 20,
            "Expected at least 20 sites, got {}",
            sites.len()
        );
    }

    #[test]
    fn every_site_has_all_five_levels() {
        let mgr = PresetManager::new();
        for site in mgr.list_sites() {
            for level in ScrapeLevel::all() {
                assert!(
                    site.levels.contains_key(level),
                    "Site {} missing level {:?}",
                    site.domain,
                    level
                );
            }
        }
    }

    #[test]
    fn site_metadata_artifact_claims_match_runtime_caps() {
        let mgr = PresetManager::new();
        for site in mgr.list_sites() {
            for level in ScrapeLevel::all() {
                let cfg = LevelConfig::from_level(*level);
                let data = &site.levels[level];

                let has_screenshot_claim = data
                    .data_fields
                    .iter()
                    .any(|field| field.to_ascii_lowercase().contains("screenshot"))
                    || data.description.to_ascii_lowercase().contains("screenshot");
                if cfg.screenshot_capture {
                    assert!(
                        has_screenshot_claim,
                        "Site {} {:?} should advertise screenshot support when runtime screenshots are enabled",
                        site.domain, level
                    );
                } else {
                    assert!(
                        !has_screenshot_claim,
                        "Site {} {:?} advertises screenshots while runtime screenshots are disabled: {}",
                        site.domain, level, data.description
                    );
                }

                let has_har_capture = data
                    .data_fields
                    .iter()
                    .any(|field| field.eq_ignore_ascii_case("har_capture"));
                if cfg.har_capture {
                    assert!(
                        has_har_capture,
                        "Site {} {:?} should include har_capture when runtime HAR capture is enabled",
                        site.domain, level
                    );
                } else {
                    assert!(
                        !has_har_capture,
                        "Site {} {:?} includes har_capture while runtime HAR capture is disabled",
                        site.domain, level
                    );
                }

                let has_full_archive_field = data.data_fields.iter().any(|field| {
                    field.eq_ignore_ascii_case("full_html")
                        || field.eq_ignore_ascii_case("full_session")
                });
                if cfg.full_html_archive {
                    assert!(
                        has_full_archive_field,
                        "Site {} {:?} should include full archive field when runtime full_html_archive is enabled",
                        site.domain, level
                    );
                } else {
                    assert!(
                        !has_full_archive_field,
                        "Site {} {:?} includes full archive fields while runtime full_html_archive is disabled",
                        site.domain, level
                    );
                }
            }
        }
    }

    #[test]
    fn site_level_data_fields_grow_with_level() {
        let mgr = PresetManager::new();
        for site in mgr.list_sites() {
            let levels = ScrapeLevel::all();
            for pair in levels.windows(2) {
                let lower = &site.levels[&pair[0]];
                let higher = &site.levels[&pair[1]];
                assert!(
                    higher.data_fields.len() >= lower.data_fields.len(),
                    "Site {} L{} has {} fields but L{} has {} fields",
                    site.domain,
                    pair[0].rank(),
                    lower.data_fields.len(),
                    pair[1].rank(),
                    higher.data_fields.len(),
                );
            }
        }
    }

    #[test]
    fn recommend_level_no_vendor() {
        let mgr = PresetManager::new();
        assert_eq!(
            mgr.recommend_level("example.com", None),
            ScrapeLevel::L1Scout
        );
    }

    #[test]
    fn recommend_level_cloudflare() {
        let mgr = PresetManager::new();
        assert_eq!(
            mgr.recommend_level("example.com", Some("Cloudflare")),
            ScrapeLevel::L2Standard
        );
    }

    #[test]
    fn recommend_level_akamai() {
        let mgr = PresetManager::new();
        assert_eq!(
            mgr.recommend_level("example.com", Some("Akamai")),
            ScrapeLevel::L3Deep
        );
    }

    #[test]
    fn recommend_level_perimeterx() {
        let mgr = PresetManager::new();
        assert_eq!(
            mgr.recommend_level("example.com", Some("PerimeterX")),
            ScrapeLevel::L4Full
        );
    }

    #[test]
    fn recommend_level_kasada() {
        let mgr = PresetManager::new();
        assert_eq!(
            mgr.recommend_level("example.com", Some("Kasada")),
            ScrapeLevel::L5Maximum
        );
    }

    #[test]
    fn recommend_level_site_default_overrides_low_vendor() {
        let mgr = PresetManager::new();
        // LinkedIn defaults to L4Full — should not drop to L1 just because no vendor.
        let level = mgr.recommend_level("site-16.example", None);
        assert!(
            level.rank() >= ScrapeLevel::L4Full.rank(),
            "LinkedIn should be at least L4, got {:?}",
            level
        );
    }

    #[test]
    fn route_hint_for_level_exposes_dt_metadata() {
        let cases = [
            (
                ScrapeLevel::L1Scout,
                RoutePolicy {
                    depth: RouteDepthPolicy::Limited { max_depth: 1 },
                    transport: RouteTransportPolicy::Auto,
                },
                "D1-TA",
            ),
            (
                ScrapeLevel::L2Standard,
                RoutePolicy {
                    depth: RouteDepthPolicy::Limited { max_depth: 2 },
                    transport: RouteTransportPolicy::PreferWebSocket,
                },
                "D2-TWP",
            ),
            (
                ScrapeLevel::L3Deep,
                RoutePolicy {
                    depth: RouteDepthPolicy::Limited { max_depth: 4 },
                    transport: RouteTransportPolicy::PreferWebSocket,
                },
                "D4-TWP",
            ),
            (
                ScrapeLevel::L4Full,
                RoutePolicy {
                    depth: RouteDepthPolicy::Limited { max_depth: 8 },
                    transport: RouteTransportPolicy::PreferPipe,
                },
                "D8-TPP",
            ),
            (
                ScrapeLevel::L5Maximum,
                RoutePolicy {
                    depth: RouteDepthPolicy::Unlimited,
                    transport: RouteTransportPolicy::PipeOnly,
                },
                "DU-TPO",
            ),
        ];

        for (level, expected_policy, expected_style) in cases {
            let hint = PresetManager::route_hint_for_level(level);
            assert_eq!(hint.level, level);
            assert_eq!(hint.route_policy, expected_policy);
            assert_eq!(hint.dt_style, expected_style);
            assert!(!hint.selection_hint.is_empty());
            assert_eq!(
                RoutePolicy::from_dt_style_code(&hint.dt_style),
                Some(expected_policy)
            );
        }
    }

    #[test]
    fn recommend_route_hint_matches_auto_configure_level() {
        let mgr = PresetManager::new();

        let hard_hint = mgr.recommend_route_hint("example.com", None, "hard");
        assert_eq!(hard_hint.level, ScrapeLevel::L4Full);
        assert_eq!(hard_hint.dt_style, "D8-TPP");

        let kasada_hint = mgr.recommend_route_hint("example.com", Some("Kasada"), "easy");
        assert_eq!(kasada_hint.level, ScrapeLevel::L5Maximum);
        assert_eq!(kasada_hint.dt_style, "DU-TPO");
    }

    #[test]
    fn auto_configure_difficulty() {
        let mgr = PresetManager::new();

        let easy = mgr.auto_configure("example.com", None, "easy");
        assert_eq!(easy.level, ScrapeLevel::L1Scout);

        let hard = mgr.auto_configure("example.com", None, "hard");
        assert_eq!(hard.level, ScrapeLevel::L4Full);

        let extreme = mgr.auto_configure("example.com", None, "extreme");
        assert_eq!(extreme.level, ScrapeLevel::L5Maximum);
    }

    #[test]
    fn auto_configure_linkedin_hardening() {
        let mgr = PresetManager::new();
        let cfg = mgr.auto_configure("site-16.example", None, "easy");
        assert!(cfg.behavioral_sim);
        assert!(cfg.weibull_timing);
        assert!(cfg.cookie_farm);
    }

    #[test]
    fn list_levels_returns_five() {
        let levels = PresetManager::list_levels();
        assert_eq!(levels.len(), 5);
        assert_eq!(levels[0].0, ScrapeLevel::L1Scout);
        assert_eq!(levels[4].0, ScrapeLevel::L5Maximum);
    }

    #[test]
    fn get_site_level_returns_data() {
        let mgr = PresetManager::new();
        let data = mgr.get_site_level("shop-a.example", ScrapeLevel::L3Deep);
        assert!(data.is_some());
        let d = data.unwrap();
        assert!(d.data_fields.contains(&"nutrition_facts".to_string()));
    }

    #[test]
    fn get_site_level_unknown_domain_returns_none() {
        let mgr = PresetManager::new();
        assert!(
            mgr.get_site_level("nonexistent.xyz", ScrapeLevel::L1Scout)
                .is_none()
        );
    }

    #[test]
    fn display_impl() {
        assert_eq!(format!("{}", ScrapeLevel::L1Scout), "L1 Scout");
        assert_eq!(format!("{}", ScrapeLevel::L5Maximum), "L5 Maximum");
    }

    #[test]
    fn serde_roundtrip_level() {
        let level = ScrapeLevel::L3Deep;
        let json = serde_json::to_string(&level).unwrap();
        let back: ScrapeLevel = serde_json::from_str(&json).unwrap();
        assert_eq!(back, level);
    }

    #[test]
    fn serde_roundtrip_config() {
        let cfg = LevelConfig::from_level(ScrapeLevel::L4Full);
        let json = serde_json::to_string(&cfg).unwrap();
        let back: LevelConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(back.level, cfg.level);
        assert_eq!(back.max_concurrency, cfg.max_concurrency);
    }

    #[test]
    fn grocery_sites_present() {
        let mgr = PresetManager::new();
        for domain in &[
            "shop-a.example",
            "shop-b.example",
            "site-15.example",
            "shop-d.example",
            "shop-21.example",
            "shop-06.example",
        ] {
            assert!(
                mgr.get_site_preset(domain).is_some(),
                "Missing grocery site: {}",
                domain
            );
        }
    }

    #[test]
    fn real_estate_sites_present() {
        let mgr = PresetManager::new();
        for domain in &["site-39.example", "site-25.example", "site-23.example"] {
            assert!(
                mgr.get_site_preset(domain).is_some(),
                "Missing real estate site: {}",
                domain
            );
        }
    }

    #[test]
    fn finance_sites_present() {
        let mgr = PresetManager::new();
        for domain in &[
            "tradingview.com",
            "site-14.example",
            "finance.yahoo.com",
            "site-38.example",
        ] {
            assert!(
                mgr.get_site_preset(domain).is_some(),
                "Missing finance site: {}",
                domain
            );
        }
    }

    #[test]
    fn zacks_lookup_normalizes_www_case_and_whitespace() {
        let mgr = PresetManager::new();

        let direct = mgr.get_site_preset("site-38.example");
        assert!(direct.is_some(), "Missing site-38.example preset");
        assert_eq!(direct.unwrap().domain, "site-38.example");

        let with_www = mgr.get_site_preset("site-38.example");
        assert!(with_www.is_some(), "Missing site-38.example lookup");
        assert_eq!(with_www.unwrap().domain, "site-38.example");

        let noisy = mgr.get_site_preset("  site-38.example  ");
        assert!(noisy.is_some(), "Missing normalized mixed-case lookup");
        assert_eq!(noisy.unwrap().domain, "site-38.example");
    }

    #[test]
    fn news_sites_present() {
        let mgr = PresetManager::new();
        for domain in &["site-21.example", "site-03.example", "site-26.example"] {
            assert!(
                mgr.get_site_preset(domain).is_some(),
                "Missing news site: {}",
                domain
            );
        }
    }

    #[test]
    fn social_sites_present() {
        let mgr = PresetManager::new();
        for domain in &["site-24.example", "site-16.example"] {
            assert!(
                mgr.get_site_preset(domain).is_some(),
                "Missing social site: {}",
                domain
            );
        }
    }
}
