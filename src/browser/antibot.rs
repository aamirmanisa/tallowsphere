//! Unified anti-bot bypass orchestrator.
//!
//! Coordinates proxy rotation, profile warm-up, adaptive rate limiting,
//! cookie farming, and retailer-specific adapters into a single system
//! that handles any anti-bot system transparently.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use crate::tor::pool::{TorPool, tor_proxy_url};
use crate::strategy_select::{escalation_step, AttemptSignal, EscalationStep, EscalationTrace};

use super::config::BrowserFullConfig;
use super::proxy::{ProxyPool, ProxyTier, StickySession};
use super::stealth::StealthProfile;
use super::warmup::{WarmupSequence, ProfilePool, RetailerWarmup};
use super::ratelimit::{DomainRateManager, ResponseClass};
use super::cookie_farm::{CookieFarm, RetailerAntiBot, CookieType};
use super::page::{Page, NavigationResult, WaitUntil};
use super::error::BrowserError;
use super::captcha::{
    detect_captcha, inject_captcha_solution, solve_captcha, wait_for_manual_solve,
    CaptchaSolverConfig, CaptchaType,
};

// ─────────────────────────────────────────────────────────────────────────────
// Anti-Bot Orchestrator
// ─────────────────────────────────────────────────────────────────────────────

/// The main anti-bot bypass orchestrator.
/// Coordinates all subsystems for transparent anti-bot evasion.
pub struct AntiBotOrchestrator {
    /// Proxy pool with multi-tier fallback.
    pub proxy_pool: ProxyPool,
    /// Per-domain adaptive rate limiters.
    pub rate_manager: DomainRateManager,
    /// Cookie farm for anti-bot cookie generation.
    pub cookie_farm: CookieFarm,
    /// Browser profile pool.
    pub profile_pool: ProfilePool,
    /// Per-retailer configuration overrides.
    pub retailer_configs: HashMap<String, RetailerConfig>,
    /// Global settings.
    pub settings: AntiBotSettings,
    /// Live Tor pool used for per-domain circuit isolation (`isolate_by_domain`).
    pub tor_pool: Option<Arc<TorPool>>,
    /// Stable per-domain isolated Tor proxy URLs (domain -> `socks5://user:pass@host:port`).
    /// Cached so each domain keeps ONE circuit across its sticky window instead
    /// of minting a fresh circuit per request (which would defeat stickiness).
    pub isolated_circuits: HashMap<String, String>,
}

/// Global anti-bot settings.
#[derive(Debug, Clone)]
pub struct AntiBotSettings {
    /// Default requests per second for unknown domains.
    pub default_rate: f64,
    /// Enable profile warm-up.
    pub warmup_enabled: bool,
    /// Warm-up intensity: "none", "essential", "standard", "full".
    pub warmup_level: String,
    /// Enable cookie farming.
    pub cookie_farm_enabled: bool,
    /// Cookie refresh interval in seconds.
    pub cookie_refresh_secs: u64,
    /// Maximum concurrent Chrome instances for cookie farming.
    pub max_farm_instances: usize,
    /// Enable Tor as fallback proxy tier.
    pub tor_fallback: bool,
    /// Number of Tor instances.
    pub tor_instances: usize,
    /// Isolate each target domain onto its own Tor circuit (IsolateSOCKSAuth).
    pub isolate_by_domain: bool,
    /// User-Agent to use.
    pub user_agent: String,
    /// Optional external CAPTCHA solver configuration. When set, the
    /// orchestrator auto-detects and solves CAPTCHAs on a soft block instead
    /// of only rotating the proxy.
    pub captcha_solver: Option<CaptchaSolverConfig>,
    /// Full stealth profile (B3). When set, `execute_request` applies the
    /// complete stealth bootstrap — plugin init scripts + V1/V2 evasions +
    /// Network.setUserAgentOverride client-hint alignment (`apply_stealth`) —
    /// to EVERY page returned by the relaunch closure before its first
    /// navigation. Absent = relaunched pages stay bare (historical behavior),
    /// which leaks `navigator.webdriver` and headless fingerprints on the
    /// very pages anti-bot navigation exists to protect.
    pub stealth_profile: Option<StealthProfile>,
    /// Honest fail-fast egress (B4). `false` (default): an orchestrator with
    /// an EMPTY proxy pool refuses to run — no silent Tor-9050 stall attempts
    /// when no daemon is listening and no silent direct-IP leak. `true`: the
    /// caller explicitly chose direct egress (`tier:"direct"`).
    pub allow_direct_egress: bool,
}

impl Default for AntiBotSettings {
    fn default() -> Self {
        Self {
            default_rate: 0.5,
            warmup_enabled: true,
            warmup_level: "standard".into(),
            cookie_farm_enabled: true,
            cookie_refresh_secs: 240, // 4 minutes (refresh before 5-min Akamai expiry)
            max_farm_instances: 5,
            // B4: no silent Tor default. goto_antibot / resolve now require an
            // explicit egress source (per-call map, TALLOW_PROXY, or tor:true
            // against a live daemon/TorPool); an orchestrator built from these
            // defaults has an empty pool and fails fast instead of spending 3
            // slow attempts on socks5://127.0.0.1:9050 with no daemon.
            tor_fallback: false,
            tor_instances: 0,
            isolate_by_domain: false,
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36".into(),
            captcha_solver: None,
            stealth_profile: None,
            allow_direct_egress: false,
        }
    }
}

/// Per-retailer configuration.
#[derive(Debug, Clone)]
pub struct RetailerConfig {
    /// Domain pattern (e.g., "amazon.com").
    pub domain: String,
    /// Anti-bot systems in use.
    pub antibot_types: Vec<CookieType>,
    /// Whether to use API instead of scraping.
    pub use_api: bool,
    /// API URL (if use_api is true).
    pub api_url: Option<String>,
    /// API key (if required).
    pub api_key: Option<String>,
    /// Custom rate limit override.
    pub rate_limit: Option<f64>,
    /// Warm-up sequence override.
    pub warmup: Option<WarmupSequence>,
    /// Required proxy tier (minimum).
    pub min_proxy_tier: ProxyTier,
    /// Notes/recommendations.
    pub notes: String,
}

/// Outcome of an automatic CAPTCHA solve attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CaptchaSolveOutcome {
    /// CAPTCHA was solved and the token injected — retry the same profile.
    Solved,
    /// CAPTCHA was solved manually — retry the same profile.
    ManualSolved,
    /// No CAPTCHA detected or solve failed — fall back to proxy rotation.
    Failed,
}

/// One engine step recorded by [`AntiBotOrchestrator::resolve`]. Each step is
/// an HONEST capability flag: `available` says whether the engine could run at
/// all given the current configuration, `ran` says whether it executed, and
/// `note` says what actually happened (no fake success tokens).
#[derive(Debug, Clone)]
pub struct ResolveStep {
    /// Engine name: "egress", "captcha.detect", "captcha.solve",
    /// "turnstile.solve", "warmup", "escalation", "classify".
    pub engine: String,
    /// Engine was executable under the current configuration.
    pub available: bool,
    /// Engine actually ran during this resolution.
    pub ran: bool,
    /// Human-readable honest outcome of the step.
    pub note: String,
}

/// Structured result of an [`AntiBotOrchestrator::resolve`] call — the
/// detect → solve → retry loop with per-engine capability flags.
#[derive(Debug, Clone)]
pub struct ResolveReport {
    /// Target URL.
    pub url: String,
    /// True when the final navigation was classified `Success`.
    pub resolved: bool,
    /// HTTP status of the final navigation (0 when navigation failed).
    pub final_status: u16,
    /// Number of detect/solve/retry iterations executed.
    pub attempts: u32,
    /// First ~200 chars of the final body text (challenge markers visible).
    pub body_hint: String,
    /// Ordered engine steps with honest capability flags.
    pub steps: Vec<ResolveStep>,
}

impl ResolveReport {
    pub(crate) fn new(url: &str) -> Self {
        Self {
            url: url.to_string(),
            resolved: false,
            final_status: 0,
            attempts: 0,
            body_hint: String::new(),
            steps: Vec::new(),
        }
    }

    fn step(&mut self, engine: &str, available: bool, ran: bool, note: impl Into<String>) {
        self.steps.push(ResolveStep {
            engine: engine.to_string(),
            available,
            ran,
            note: note.into(),
        });
    }
}

impl AntiBotOrchestrator {
    /// Whether a CAPTCHA type can be auto-solved via an external solver +
    /// DOM token injection (puzzle types). Cookie/header WAF types (AwsWaf,
    /// DataDome) are handled manually / by escalation instead.
    fn is_auto_solvable(t: &CaptchaType) -> bool {
        matches!(
            t,
            CaptchaType::ReCaptchaV2
                | CaptchaType::ReCaptchaV3
                | CaptchaType::HCaptcha
                | CaptchaType::Turnstile
                | CaptchaType::ArkoseLabs
                | CaptchaType::FunCaptcha
                | CaptchaType::ImageCaptcha
                | CaptchaType::GeeTest
                | CaptchaType::GeeTestV4
        )
    }

    /// Detect and solve a CAPTCHA on the current page.
    ///
    /// Puzzle types are solved through the external solver and the token is
    /// injected back into the DOM. Manual/managed (cookie/header WAF) types
    /// fall back to `wait_for_manual_solve`. Returns an outcome so the caller
    /// can decide whether to retry the same profile or rotate the proxy.
    async fn attempt_captcha_autosolve(&self, page: &Page, url: &str) -> CaptchaSolveOutcome {
        let Some(solver) = &self.settings.captcha_solver else {
            return CaptchaSolveOutcome::Failed;
        };

        let Ok(Some(captcha)) = detect_captcha(&page.client, &page.session_id).await else {
            return CaptchaSolveOutcome::Failed;
        };

        if Self::is_auto_solvable(&captcha.captcha_type) {
            // Puzzle type — solve externally (blocking ureq) then inject.
            let solver_c = solver.clone();
            let captcha_c = captcha.clone();
            let url_c = url.to_string();
            let solved = tokio::task::spawn_blocking(move || {
                solve_captcha(&solver_c, &captcha_c, &url_c).ok()
            })
            .await
            .unwrap_or(None);

            if let Some(solution) = solved {
                if inject_captcha_solution(&page.client, &page.session_id, &captcha, &solution)
                    .await
                    .is_ok()
                {
                    return CaptchaSolveOutcome::Solved;
                }
            }
            CaptchaSolveOutcome::Failed
        } else {
            // Manual/managed (cookie/header-based WAF) — wait for a human.
            let timeout = solver.timeout;
            match wait_for_manual_solve(&page.client, &page.session_id, &captcha, timeout).await {
                Ok(true) => CaptchaSolveOutcome::ManualSolved,
                _ => CaptchaSolveOutcome::Failed,
            }
        }
    }

    /// Create a new orchestrator with default settings.
    pub fn new() -> Self {
        Self::with_settings(AntiBotSettings::default())
    }

    /// Create with custom settings.
    pub fn with_settings(settings: AntiBotSettings) -> Self {
        let mut proxy_pool = ProxyPool::new();

        // Add Tor as fallback if enabled
        if settings.tor_fallback {
            proxy_pool.add_tor_instances(settings.tor_instances, 9050);
        }

        let rate_manager = DomainRateManager::new(settings.default_rate);
        let cookie_farm = CookieFarm::new(&settings.user_agent);

        let profiles_dir = super::config::loader::config_dir().join("profiles");
        let profile_pool = ProfilePool::new(profiles_dir, settings.max_farm_instances);

        let mut orchestrator = Self {
            proxy_pool,
            rate_manager,
            cookie_farm,
            profile_pool,
            retailer_configs: HashMap::new(),
            settings,
            tor_pool: None,
            isolated_circuits: HashMap::new(),
        };

        orchestrator.register_default_retailers();
        orchestrator
    }

    /// Attach a live Tor pool to enable per-domain circuit isolation
    /// (`AntiBotSettings::isolate_by_domain`). Call with a `TorPool` that has
    /// real Tor daemons running; otherwise isolation silently falls back to
    /// the pool's static Tor proxies.
    pub fn set_tor_pool(&mut self, pool: Arc<TorPool>) {
        self.tor_pool = Some(pool);
    }

    // ── Egress honesty (B4) ─────────────────────────────────────────────

    /// Whether this orchestrator has ANY configured egress: a non-empty proxy
    /// pool (explicit proxies, Tor instances requested via settings, or a
    /// per-call proxy added by the interpreter) OR an explicit direct-egress
    /// choice. With neither, every navigation would silently leak the real IP
    /// or stall against a dead Tor daemon — callers must fail fast instead.
    pub fn egress_configured(&self) -> bool {
        self.proxy_pool.len() > 0 || self.settings.allow_direct_egress
    }

    /// The honest fail-fast error returned when no egress source is configured
    /// (B4): a clear operator message instead of 3 slow Tor-9050 attempts with
    /// no daemon running or a silent direct-IP leak.
    pub fn egress_required_error() -> BrowserError {
        BrowserError::ActionFailed(
            "no egress proxy source configured for anti-bot navigation: pass an \
             explicit proxy (per-call {proxy:...} map or TALLOW_PROXY), request \
             tor:true only with a running Tor daemon/TorPool (TALLOW_TOR), or \
             choose tier:\"direct\" for an explicit direct-IP choice. Refusing to \
             silently fall back to a dead Tor daemon or leak the real IP"
                .to_string(),
        )
    }

    // ── Full stealth bootstrap for relaunched pages (B3) ────────────────

    /// Apply the complete stealth bootstrap to a freshly-relaunched page —
    /// the same steps `Browser.new_page` performs for first-party pages:
    ///   1. register Tallow browser-plugin init scripts
    ///      (`Page.addScriptToEvaluateOnNewDocument`, persisted across goto)
    ///   2. `page.apply_stealth(&profile)` — V1/V2 JS evasions +
    ///      `Network.setUserAgentOverride` + `userAgentMetadata` so the
    ///      `Sec-CH-UA` client-hint headers match the spoofed JS values
    ///   3. V3 extras (`apply_stealth_evasions`: plugins/webdriver/chrome.*)
    ///
    /// Best-effort and non-fatal (a page without stealth is still navigable;
    /// failures are logged to stderr rather than failing the navigation).
    /// Must run BEFORE the page's first navigation — call it immediately after
    /// a relaunch returns the page.
    pub async fn apply_stealth_bootstrap(page: &Page, profile: &StealthProfile) {
        // Plugin init scripts (persist across navigations). Bounded setup so a
        // slow CDP round trip can never stall the relaunch.
        let full_config = BrowserFullConfig::load();
        let plugins = full_config.plugins.to_browser_plugins();
        let inject_js = plugins.injection_script();
        if !inject_js.trim().is_empty() {
            let mut setup_client = page.client.clone();
            setup_client.timeout =
                std::cmp::min(page.timeout, std::time::Duration::from_millis(750));
            if setup_client
                .send_command_with_session(
                    "Page.addScriptToEvaluateOnNewDocument",
                    Some(serde_json::json!({"source": inject_js})),
                    &page.session_id,
                )
                .await
                .is_err()
            {
                eprintln!("[tallow] warn: relaunch stealth plugin injection failed (non-fatal)");
            }
        }
        if let Err(e) = page.apply_stealth(profile).await {
            eprintln!("[tallow] warn: relaunch stealth bootstrap failed (non-fatal): {e}");
            return;
        }
        // V3 evasions (webdriver/plugins/chrome.* overrides) are applied on
        // top of the profile's V1/V2 scripts. Non-fatal like the rest.
        let _ = page.apply_stealth_evasions().await;
    }

    /// Register known retailer configurations.
    fn register_default_retailers(&mut self) {
        let retailers = vec![
            RetailerConfig {
                domain: "amazon.com".into(),
                antibot_types: vec![CookieType::Session],
                use_api: false,
                api_url: None,
                api_key: None,
                rate_limit: Some(0.33),
                warmup: Some(RetailerWarmup::amazon()),
                min_proxy_tier: ProxyTier::Residential,
                notes: "Custom AWS WAF. Real Chrome + stealth + residential proxy.".into(),
            },
            RetailerConfig {
                domain: "walmart.com".into(),
                antibot_types: vec![CookieType::Akamai, CookieType::PerimeterX],
                use_api: true,
                api_url: Some("https://developer.walmart.com/api-reference".into()),
                api_key: None,
                rate_limit: Some(0.5),
                warmup: Some(RetailerWarmup::walmart()),
                min_proxy_tier: ProxyTier::Residential,
                notes: "Akamai Bot Manager Premier. Prefer Affiliate API.".into(),
            },
            RetailerConfig {
                domain: "target.com".into(),
                antibot_types: vec![CookieType::Akamai],
                use_api: true,
                api_url: Some("https://redsky.target.com/redsky_aggregations/v1/web/pdp_client_v1".into()),
                api_key: None, // Extract from Target's JS bundle
                rate_limit: Some(0.5),
                warmup: Some(RetailerWarmup::target()),
                min_proxy_tier: ProxyTier::Isp,
                notes: "Redsky API is semi-public. Key in frontend JS.".into(),
            },
            RetailerConfig {
                domain: "bestbuy.com".into(),
                antibot_types: vec![CookieType::Akamai, CookieType::Kasada],
                use_api: true,
                api_url: Some("https://api.bestbuy.com/v1/products".into()),
                api_key: None, // Free registration at developer.bestbuy.com
                rate_limit: Some(5.0),
                warmup: Some(RetailerWarmup::bestbuy()),
                min_proxy_tier: ProxyTier::Direct, // API doesn't need proxy
                notes: "FREE official API at developer.bestbuy.com. 5 req/sec.".into(),
            },
            RetailerConfig {
                domain: "nike.com".into(),
                antibot_types: vec![CookieType::Akamai],
                use_api: false,
                api_url: None,
                api_key: None,
                rate_limit: Some(0.33),
                warmup: None,
                min_proxy_tier: ProxyTier::Residential,
                notes: "Akamai + Shape on checkout. Browse pages are moderate.".into(),
            },
            RetailerConfig {
                domain: "fashionnova.com".into(),
                antibot_types: vec![CookieType::Cloudflare],
                use_api: false,
                api_url: Some("https://www.fashionnova.com/products.json".into()),
                api_key: None,
                rate_limit: Some(1.0),
                warmup: None,
                min_proxy_tier: ProxyTier::Datacenter, // Shopify is lenient
                notes: "Shopify /products.json often works without bypass.".into(),
            },
            RetailerConfig {
                domain: "slickdeals.net".into(),
                antibot_types: vec![],
                use_api: false,
                api_url: None,
                api_key: None,
                rate_limit: Some(1.0),
                warmup: None,
                min_proxy_tier: ProxyTier::Direct, // Light protection
                notes: "Minimal anti-bot. Direct scraping works.".into(),
            },
        ];

        for config in retailers {
            self.retailer_configs.insert(config.domain.clone(), config);
        }
    }

    /// Get configuration for a domain (exact or partial match).
    pub fn get_retailer_config(&self, domain: &str) -> Option<&RetailerConfig> {
        // Try exact match first
        if let Some(config) = self.retailer_configs.get(domain) {
            return Some(config);
        }
        // Try partial match
        for (key, config) in &self.retailer_configs {
            if domain.contains(key.as_str()) {
                return Some(config);
            }
        }
        None
    }

    /// Add residential proxies to the pool.
    pub fn add_residential_proxies(&mut self, urls: &[&str]) {
        self.proxy_pool.add_list(urls, ProxyTier::Residential);
    }

    /// Add mobile proxies to the pool.
    pub fn add_mobile_proxies(&mut self, urls: &[&str]) {
        self.proxy_pool.add_list(urls, ProxyTier::Mobile);
    }

    /// Add datacenter proxies to the pool.
    pub fn add_datacenter_proxies(&mut self, urls: &[&str]) {
        self.proxy_pool.add_list(urls, ProxyTier::Datacenter);
    }

    /// Get the recommended approach for a domain.
    pub fn recommend(&self, domain: &str) -> String {
        if let Some(config) = self.get_retailer_config(domain) {
            let mut rec = String::new();
            rec.push_str(&format!("Domain: {}\n", domain));
            rec.push_str(&format!("Anti-bot: {:?}\n", config.antibot_types));

            if config.use_api {
                rec.push_str(&format!("RECOMMENDED: Use API — {}\n", config.api_url.as_deref().unwrap_or("N/A")));
            }

            rec.push_str(&format!("Min proxy tier: {:?}\n", config.min_proxy_tier));
            rec.push_str(&format!("Rate limit: {:.2} req/sec\n", config.rate_limit.unwrap_or(0.5)));
            rec.push_str(&format!("Notes: {}\n", config.notes));
            rec
        } else {
            let types = RetailerAntiBot::detect(domain);
            let approach = RetailerAntiBot::recommended_approach(domain);
            format!(
                "Domain: {}\nAnti-bot: {:?}\nApproach: {}\n",
                domain, types, approach
            )
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Execution engine
    // ─────────────────────────────────────────────────────────────────────────

    /// Extract the registrable domain from a URL (e.g. "https://www.amazon.com/dp/B09V3KXJPB" -> "amazon.com").
    fn extract_domain(url: &str) -> String {
        let after_scheme = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);
        let host = after_scheme.split('/').next().unwrap_or(after_scheme);
        // Strip port
        let host = host.split(':').next().unwrap_or(host);
        // Strip leading "www."
        let host = host.strip_prefix("www.").unwrap_or(host);
        host.to_lowercase()
    }

    /// Determine the minimum proxy tier to use for a domain.
    fn min_tier_for_domain(&self, domain: &str) -> ProxyTier {
        if let Some(config) = self.get_retailer_config(domain) {
            config.min_proxy_tier
        } else if RetailerAntiBot::is_high_security(domain) {
            ProxyTier::Residential
        } else {
            ProxyTier::Datacenter
        }
    }

    /// Escalate to the next higher-quality proxy tier.
    /// Returns `None` if already at the highest tier (Mobile).
    fn escalate_tier(current: ProxyTier) -> Option<ProxyTier> {
        match current {
            ProxyTier::Direct => Some(ProxyTier::Datacenter),
            ProxyTier::Tor => Some(ProxyTier::Datacenter),
            ProxyTier::Datacenter => Some(ProxyTier::Isp),
            ProxyTier::Isp => Some(ProxyTier::Residential),
            ProxyTier::Residential => Some(ProxyTier::Mobile),
            ProxyTier::Mobile => None, // Already at highest quality
        }
    }

    /// P1 W3-S1: apply one escalation action to the live request state.
    ///
    /// - `ApplyStealth` re-runs the full stealth bootstrap on the active page.
    /// - `EscalateTier` bumps the tier cursor the next
    ///   [`Self::select_proxy_for_domain`] call uses.
    /// - `RotateEgress` drops the domain's cached Tor circuit so the next
    ///   attempt re-mints a fresh one via the attached pool (per-run circuit
    ///   binding, W1-E1); the isolation cache would otherwise pin the same
    ///   circuit for the whole sticky window.
    /// - `Serve` / `BackOff` carry no side effects (the caller owns the
    ///   sleep via `step.backoff_ms`).
    async fn apply_escalation(
        &mut self,
        step: &EscalationStep,
        domain: &str,
        current_tier: &mut ProxyTier,
        active_page: &Page,
    ) {
        use crate::strategy_select::EscalationAction;
        match step.action {
            EscalationAction::Serve | EscalationAction::BackOff => {}
            EscalationAction::ApplyStealth => {
                if let Some(profile) = &self.settings.stealth_profile {
                    Self::apply_stealth_bootstrap(active_page, profile).await;
                }
            }
            EscalationAction::EscalateTier => {
                if let Some(escalated) = Self::escalate_tier(*current_tier) {
                    *current_tier = escalated;
                }
            }
            EscalationAction::RotateEgress => {
                self.isolated_circuits.remove(domain);
            }
        }
    }

    /// Select the best proxy for a domain, respecting minimum tier constraints.
    /// Tries the minimum tier first, escalating upward on failure.
    fn select_proxy_for_domain(&mut self, domain: &str, min_tier: ProxyTier) -> Option<(String, ProxyTier)> {
        // F-3 default-refuse: an unknown domain (no explicit opt-in) must
        // never be pinned to a Direct pool entry — only `allow_direct_egress`
        // (settings or pool flag) or a known retailer's explicit
        // `min_proxy_tier: Direct` config may use direct egress.
        let direct_allowed = self.settings.allow_direct_egress
            || self.proxy_pool.allow_direct_egress
            || min_tier == ProxyTier::Direct;

        // Per-domain stickiness: reuse a valid sticky binding for this domain
        // when its proxy is still healthy, not-banned, and at least as good as
        // the requested tier. Re-selecting on every call makes the domain hop
        // proxies (and relaunch the browser) each request — costing latency and
        // defeating cross-domain circuit isolation (a metadata-correlation leak).
        {
            let sticky = self.proxy_pool.sticky.get(domain);
            if let Some(session) = sticky {
                if session.is_valid() {
                    let idx = session.proxy_index;
                    let can_reuse = idx < self.proxy_pool.proxies.len()
                        && idx < self.proxy_pool.health.len()
                        && self.proxy_pool.health[idx].alive
                        && !self.proxy_pool.health[idx].banned_domains.contains(domain)
                        && self.proxy_pool.proxies[idx].tier <= min_tier
                        // F-3: never reuse a sticky Direct binding unless
                        // direct egress was explicitly opted in.
                        && (direct_allowed
                            || self.proxy_pool.proxies[idx].tier != ProxyTier::Direct);
                    if can_reuse {
                        let url = self.proxy_pool.proxies[idx].url.clone();
                        let tier = self.proxy_pool.proxies[idx].tier;
                        return Some((url, tier));
                    }
                }
            }
        }
        // Sticky binding is dead / banned / expired / worse than the requested
        // tier — drop it and re-select below.
        self.proxy_pool.sticky.remove(domain);

        // Try tiers from min_tier upward (better quality)
        let chain = ProxyTier::fallback_chain();
        // Find where min_tier sits in the chain, then try from there toward index 0
        let start_idx = chain.iter().position(|t| *t == min_tier).unwrap_or(0);

        // First pass: try at or above minimum tier quality
        // ProxyTier::fallback_chain() is ordered Mobile(0), Residential(1), ... Direct(5)
        // We want to try from start_idx back to 0 (higher quality)
        for &tier in chain[..=start_idx].iter().rev() {
            if tier == ProxyTier::Direct && !direct_allowed {
                continue; // F-3 default-refuse
            }
            let candidates: Vec<usize> = self.proxy_pool.proxies.iter().enumerate()
                .filter(|(i, p)| {
                    p.tier == tier
                    && self.proxy_pool.health[*i].alive
                    && !self.proxy_pool.health[*i].banned_domains.contains(domain)
                    && self.proxy_pool.health[*i].score() > 0.3
                })
                .map(|(i, _)| i)
                .collect();

            if !candidates.is_empty() {
                // Pick the candidate with the best health score
                let best = candidates.into_iter()
                    .max_by(|a, b| {
                        self.proxy_pool.health[*a].score()
                            .partial_cmp(&self.proxy_pool.health[*b].score())
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .unwrap();
                self.record_sticky(domain, best);
                let url = self.proxy_pool.proxies[best].url.clone();
                let tier = self.proxy_pool.proxies[best].tier;
                return Some((url, tier));
            }
        }

        // Second pass: if nothing at or above min tier, fall back to anything alive
        for &tier in &chain[start_idx + 1..] {
            if tier == ProxyTier::Direct && !direct_allowed {
                continue; // F-3 default-refuse
            }
            let candidates: Vec<usize> = self.proxy_pool.proxies.iter().enumerate()
                .filter(|(i, p)| {
                    p.tier == tier
                    && self.proxy_pool.health[*i].alive
                    && !self.proxy_pool.health[*i].banned_domains.contains(domain)
                })
                .map(|(i, _)| i)
                .collect();
            if !candidates.is_empty() {
                let best = candidates[0];
                self.record_sticky(domain, best);
                let url = self.proxy_pool.proxies[best].url.clone();
                let tier = self.proxy_pool.proxies[best].tier;
                return Some((url, tier));
            }
        }

        None
    }

    /// Record a per-domain sticky proxy binding so subsequent selections for
    /// the same domain reuse this proxy (keeps the domain pinned to one egress
    /// circuit/context, preventing cross-domain correlation).
    fn record_sticky(&mut self, domain: &str, proxy_index: usize) {
        if proxy_index >= self.proxy_pool.proxies.len() {
            return;
        }
        self.proxy_pool.sticky.insert(
            domain.to_string(),
            StickySession {
                proxy_index,
                domain: domain.to_string(),
                started: Instant::now(),
                duration: self.proxy_pool.sticky_duration,
                request_count: 0,
            },
        );
    }

    /// Classify an HTTP response + body snippet for anti-bot detection.
    fn classify_response(status: u16, body_snippet: Option<&str>) -> ResponseClass {
        if let Some(body) = body_snippet {
            let body_class = ResponseClass::from_body(body);
            if body_class != ResponseClass::Success {
                return body_class;
            }
        }
        ResponseClass::from_status(status)
    }

    /// Execute a full anti-bot-aware navigation request.
    ///
    /// Coordinates rate limiting, proxy selection, cookie freshness, profile
    /// warm-up, navigation, response classification, and automatic retry with
    /// proxy escalation on blocks.
    ///
    /// Returns the final `NavigationResult` on success or `BrowserError` if all
    /// retries are exhausted.
    pub async fn execute_request<F, Fut>(
        &mut self,
        url: &str,
        page: &Page,
        relaunch: F,
    ) -> Result<NavigationResult, BrowserError>
    where
        F: Fn(String) -> Fut,
        Fut: std::future::Future<Output = Result<Page, BrowserError>>,
    {
        let domain = Self::extract_domain(url);
        let min_tier = self.min_tier_for_domain(&domain);
        // F-3: direct egress is allowed only via an explicit opt-in — the
        // settings/pool flag, or a known retailer's `min_proxy_tier: Direct`.
        let direct_egress_ok = self.settings.allow_direct_egress
            || self.proxy_pool.allow_direct_egress
            || min_tier == ProxyTier::Direct;
        let max_retries: u32 = 3;
        let mut current_tier = min_tier;
        let mut last_error: Option<BrowserError> = None;

        // P1 W3-S2: escalation decisions taken during this request, flushed to
        // the run-evidence sink on exit (no-op unless TALLOW_RUN_EVIDENCE_DIR
        // is set; empty — and thus silent — when every attempt is Clean).
        let mut escalations: Vec<EscalationTrace> = Vec::new();

        // B4: honest fail-fast — with no configured egress (empty proxy pool
        // and no explicit direct choice) there is nothing to drive. The
        // historical default silently pointed 3 attempts at static
        // socks5://127.0.0.1:9050 Tor instances with no daemon running. Now
        // the caller must say where traffic egresses.
        if !self.egress_configured() {
            return Err(Self::egress_required_error());
        }

        // The page actively used for navigation. Starts as the caller's page and
        // is replaced when the selected proxy changes, so `select_proxy_for_domain`
        // actually drives egress (relaunch on the chosen proxy) instead of only
        // being recorded for cookie bookkeeping.
        let mut active_page: Page = page.clone();
        // The proxy the active page is currently routing through, if any.
        let mut active_proxy: Option<String> = None;

        for attempt in 0..max_retries {
            // ── Step 1: Rate limiting ──────────────────────────────────────
            // Wait until the rate limiter allows a request to this domain.
            let wait = self.rate_manager.wait_duration(&domain);
            if !wait.is_zero() {
                tokio::time::sleep(wait).await;
            }

            if !self.rate_manager.try_acquire(&domain) {
                // Circuit breaker is open — domain is paused.
                return Err(BrowserError::RateLimitExceeded(domain.clone()));
            }

            // ── Step 2: Proxy selection ────────────────────────────────────
            let proxy_info = self.select_proxy_for_domain(&domain, current_tier);
            let mut proxy_url = proxy_info.as_ref().map(|(url, _)| url.clone());
            let proxy_tier = proxy_info.as_ref().map(|(_, tier)| *tier);

            // F-3 default-refuse: selection produced nothing and the caller
            // never opted into direct egress (and this domain has no explicit
            // direct config) — navigating now would silently egress from the
            // box IP. Fail honestly instead.
            if proxy_url.is_none() && active_proxy.is_none() && !direct_egress_ok {
                return Err(BrowserError::ActionFailed(format!(
                    "no usable proxy selected for {domain}: refusing silent direct \
                     egress (opt in explicitly with allow_direct_egress / tier:\"direct\")"
                )));
            }

            // ── Step 2a: per-domain Tor circuit isolation ──────────────────
            // When enabled and the chosen egress is a Tor proxy, pin this domain
            // to its OWN Tor circuit via unique SOCKS5 auth (IsolateSOCKSAuth).
            // The isolated circuit URL is cached per domain so it stays stable
            // across the sticky window instead of minting a fresh one per request
            // (which would defeat the per-domain stickiness fix above).
            if self.settings.isolate_by_domain && proxy_tier == Some(ProxyTier::Tor) {
                let tor_pool = self.tor_pool.clone();
                if let Some(cached) = self.isolated_circuits.get(&domain) {
                    proxy_url = Some(cached.clone());
                } else if let Some(pool) = tor_pool {
                    if let Ok(cfg) = pool.isolate(&domain).await {
                        let url = tor_proxy_url(&cfg);
                        self.isolated_circuits.insert(domain.clone(), url.clone());
                        proxy_url = Some(url);
                    }
                    // On isolate() error, keep the pool's static Tor proxy.
                }
                // With no TorPool attached, fall back to the pool's Tor proxy.
            }

            // ── Step 2b: apply the selected proxy to actual egress ────────
            // The browser is launched on a fixed proxy; to actually route this
            // request through the proxy chosen above, relaunch the browser on
            // it when it differs from the proxy the active page is on.
            if let Some(ref purl) = proxy_url {
                if active_proxy.as_deref() != Some(purl.as_str()) {
                    match relaunch(purl.clone()).await {
                        Ok(p) => {
                            // B3: a relaunched page is a fresh, bare browser —
                            // apply the full stealth bootstrap (plugins + V1/V2
                            // evasions + UA/client-hint override + V3 extras)
                            // BEFORE its first navigation, whenever the caller
                            // supplied a stealth profile. Best-effort.
                            if let Some(profile) = &self.settings.stealth_profile {
                                Self::apply_stealth_bootstrap(&p, profile).await;
                            }
                            active_page = p;
                            active_proxy = Some(purl.clone());
                        }
                        Err(e) => {
                            last_error = Some(e);
                            let step = escalation_step(attempt, AttemptSignal::TransportError);
                            self.apply_escalation(&step, &domain, &mut current_tier, &active_page)
                                .await;
                            escalations.push(EscalationTrace::from_step(
                                attempt,
                                AttemptSignal::TransportError,
                                &step,
                            ));
                            tokio::time::sleep(std::time::Duration::from_millis(step.backoff_ms))
                                .await;
                            continue;
                        }
                    }
                }
            }

            // ── Step 3: Cookie freshness ───────────────────────────────────
            if self.settings.cookie_farm_enabled {
                let jar = self.cookie_farm.jar(&domain);
                if jar.needs_refresh() {
                    // Set the antibot type if not already detected
                    if jar.antibot_type.is_none() {
                        let types = RetailerAntiBot::detect(&domain);
                        if let Some(first) = types.first() {
                            jar.antibot_type = Some(*first);
                        }
                    }
                    // Mark the jar with the proxy that will be used so cookies
                    // are IP-consistent. Actual cookie generation would be done
                    // by a Chrome instance visiting the target; here we just
                    // ensure the jar exists and is associated with the proxy.
                    jar.proxy_url = proxy_url.clone();
                }
            }

            // ── Step 4: Profile readiness ──────────────────────────────────
            if self.settings.warmup_enabled {
                // Look up retailer warmup config before borrowing profile pool
                let retailer_warmup = self.get_retailer_config(&domain)
                    .and_then(|c| c.warmup.clone());

                if let Some(profile) = self.profile_pool.get_ready_profile() {
                    if profile.needs_warmup() {
                        // Determine warmup sequence: retailer override or profile default
                        let warmup_seq = retailer_warmup
                            .unwrap_or_else(|| profile.warmup_type());

                        // Execute warmup steps: navigate to each warmup URL
                        for step in &warmup_seq.steps {
                            let dwell_ms = ((step.dwell_min_secs + step.dwell_max_secs) / 2.0 * 1000.0) as u64;
                            // Bound the warmup navigation so a dead proxy / slow
                            // warmup URL can't hang the whole request.
                            let _ = tokio::time::timeout(
                                std::time::Duration::from_secs(15),
                                active_page.navigate(&step.url, WaitUntil::NetworkAlmostIdle),
                            )
                            .await;
                            tokio::time::sleep(std::time::Duration::from_millis(dwell_ms)).await;
                        }

                        profile.mark_ready();
                    }
                }
            }

            // ── Step 5: Navigate (bounded) ────────────────────────────────
            // Bound the navigation so a dead proxy / never-idle page fails fast
            // instead of hanging indefinitely on NetworkAlmostIdle.
            let start = Instant::now();
            let nav_result = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                active_page.navigate(url, WaitUntil::NetworkAlmostIdle),
            )
            .await
            .unwrap_or_else(|_| {
                Err(BrowserError::ActionFailed(format!(
                    "navigation timed out for {url}"
                )))
            });
            let latency_ms = start.elapsed().as_secs_f64() * 1000.0;

            match nav_result {
                Ok(result) => {
                    let status = result.status_code.unwrap_or(200);

                    // ── Step 6: Classify response ──────────────────────────
                    // Try to grab a body snippet for classification.
                    // Use evaluate_expression to get a short prefix of the
                    // page body which is sufficient for anti-bot detection.
                    let body_snippet: Option<String> = active_page
                        .evaluate_expression(
                            "document.body ? document.body.innerText.substring(0, 2000) : ''"
                        )
                        .await
                        .ok()
                        .and_then(|v| v.as_str().map(|s| s.to_string()));

                    let class = Self::classify_response(
                        status,
                        body_snippet.as_deref(),
                    );

                    // ── Step 7: Report back to subsystems ──────────────────
                    self.report_response(
                        &domain,
                        status,
                        body_snippet.as_deref(),
                        proxy_url.as_deref(),
                        latency_ms,
                    );

                    match class {
                        ResponseClass::Success => {
                            // Mark profile session done
                            if let Some(profile) = self.profile_pool.get_ready_profile() {
                                profile.mark_session_done();
                            }
                            // P1 W3-S2: an escalated request that ultimately
                            // succeeded records its ladder here.
                            flush_escalations(&escalations, &domain, true);
                            return Ok(result);
                        }
                        ResponseClass::SoftBlock => {
                            // NEW: attempt captcha detect -> solve -> inject ->
                            // retry the SAME profile before rotating the proxy.
                            let outcome = self.attempt_captcha_autosolve(&active_page, url).await;

                            match outcome {
                                CaptchaSolveOutcome::Solved
                                | CaptchaSolveOutcome::ManualSolved => {
                                    // CAPTCHA solved on the current page —
                                    // retry the same profile (no proxy rotation).
                                    continue;
                                }
                                CaptchaSolveOutcome::Failed => {
                                    // Soft block: escalation ladder (W3-S1) —
                                    // re-apply stealth, then escalate the tier,
                                    // then rotate egress, then back off.
                                    // Invalidate sticky session so next attempt picks fresh proxy.
                                    if let Some(ref purl) = proxy_url {
                                        self.proxy_pool.report_failure(purl, &domain);
                                    }
                                    let step = escalation_step(attempt, AttemptSignal::SoftBlock);
                                    self.apply_escalation(&step, &domain, &mut current_tier, &active_page)
                                        .await;
                                    escalations.push(EscalationTrace::from_step(
                                        attempt,
                                        AttemptSignal::SoftBlock,
                                        &step,
                                    ));
                                    last_error = Some(BrowserError::ActionFailed(format!(
                                        "soft block on attempt {} for {} (status {}), action {:?}",
                                        attempt + 1, domain, status, step.action
                                    )));
                                    // Short backoff before retry (ladder-derived)
                                    tokio::time::sleep(std::time::Duration::from_millis(step.backoff_ms))
                                        .await;
                                    continue;
                                }
                            }
                        }
                        ResponseClass::HardBlock => {
                            // Hard block: escalation ladder (W3-S1) — escalate
                            // the tier, then rotate egress, then back off.
                            if let Some(ref purl) = proxy_url {
                                self.proxy_pool.report_failure(purl, &domain);
                            }
                            // Flag the profile
                            if let Some(profile) = self.profile_pool.get_ready_profile() {
                                profile.mark_flagged();
                            }
                            let step = escalation_step(attempt, AttemptSignal::HardBlock);
                            self.apply_escalation(&step, &domain, &mut current_tier, &active_page)
                                .await;
                            escalations.push(EscalationTrace::from_step(
                                attempt,
                                AttemptSignal::HardBlock,
                                &step,
                            ));
                            last_error = Some(BrowserError::ActionFailed(format!(
                                "hard block on attempt {} for {} (status {}), action {:?}",
                                attempt + 1, domain, status, step.action
                            )));
                            // Longer backoff for hard blocks (ladder-derived)
                            tokio::time::sleep(std::time::Duration::from_millis(step.backoff_ms))
                                .await;
                            continue;
                        }
                        ResponseClass::TransientError => {
                            // Server error, not our fault — retry without
                            // penalty; the ladder stays on the back-off rung
                            // (W3-S1: no posture change for a transient).
                            let step = escalation_step(attempt, AttemptSignal::Transient);
                            escalations.push(EscalationTrace::from_step(
                                attempt,
                                AttemptSignal::Transient,
                                &step,
                            ));
                            last_error = Some(BrowserError::ActionFailed(format!(
                                "transient error on attempt {} for {} (status {})",
                                attempt + 1, domain, status
                            )));
                            tokio::time::sleep(std::time::Duration::from_millis(step.backoff_ms))
                                .await;
                            continue;
                        }
                    }
                }
                Err(e) => {
                    // Navigation-level failure (DNS, timeout, connection refused)
                    last_error = Some(e);
                    if let Some(ref purl) = proxy_url {
                        self.proxy_pool.report_failure(purl, &domain);
                    }
                    // Escalate on connection failures too: tier first, then
                    // egress rotation (W3-S1 TransportError ladder).
                    let step = escalation_step(attempt, AttemptSignal::TransportError);
                    self.apply_escalation(&step, &domain, &mut current_tier, &active_page)
                        .await;
                    escalations.push(EscalationTrace::from_step(
                        attempt,
                        AttemptSignal::TransportError,
                        &step,
                    ));
                    tokio::time::sleep(std::time::Duration::from_millis(step.backoff_ms))
                        .await;
                    continue;
                }
            }
        }

        // All retries exhausted
        flush_escalations(&escalations, &domain, false);
        Err(last_error.unwrap_or_else(|| {
            BrowserError::ActionFailed(format!(
                "all {} retries exhausted for {}",
                max_retries, domain
            ))
        }))
    }

    /// ROADMAP #9: detect → solve → retry orchestration over an existing page.
    ///
    /// `Antibot.resolve(page, url)` sequences the existing engines on the
    /// page's CURRENT egress (the caller is responsible for having navigated
    /// it onto a proxy via `goto_antibot` / a pool launch — this method does
    /// not choose egress, it reports egress honesty):
    ///   1. **egress** — honest capability flag (empty pool + no explicit
    ///      direct choice ⇒ step is `available:false` and the call errors,
    ///      same fail-fast as `execute_request`).
    ///   2. navigate (bounded) → body-snippet classify.
    ///   3. **captcha.detect** — real DOM/iframe/sitekey detection.
    ///   4. **captcha.solve / turnstile.solve** — when an external solver is
    ///      configured, puzzle types (incl. Turnstile) are solved and the
    ///      token injected; without a solver the step records
    ///      `available:false` with an honest note (no fake tokens).
    ///   5. **warmup / escalation** — honest availability flags based on the
    ///      current profile pool / proxy tiers (never claimed as run when the
    ///      engine cannot execute on this page).
    ///   6. re-navigate + re-classify (retry with the injected token/cookies),
    ///      bounded to `max_attempts`.
    ///
    /// Returns a [`ResolveReport`] with per-engine capability flags; the
    /// navigation error is returned only when even the FIRST navigation fails.
    /// Non-live/fixture-friendly: everything is driven by page state, so a
    /// mock-CDP page serving a fake challenge HTML exercises the full loop.
    pub async fn resolve(&mut self, page: &Page, url: &str) -> Result<ResolveReport, BrowserError> {
        let max_attempts: u32 = 3;
        let mut report = ResolveReport::new(url);

        // Step 1 — egress honesty (B4 semantics, but reported as a step too).
        if !self.egress_configured() {
            let e = Self::egress_required_error();
            report.step("egress", false, false, format!("{e}"));
            return Err(e);
        }
        report.step("egress", true, false, "proxy pool or explicit direct egress configured");

        for attempt in 1..=max_attempts {
            report.attempts = attempt;
            // Per-iteration navigation state (declared here: the final
            // classification below only ever reads this iteration's values).
            let last_status: u16;

            // Step 2 — bounded navigation.
            let nav = tokio::time::timeout(
                std::time::Duration::from_secs(30),
                page.navigate(url, WaitUntil::NetworkAlmostIdle),
            )
            .await
            .unwrap_or_else(|_| {
                Err(BrowserError::ActionFailed(format!(
                    "resolve: navigation timed out for {url}"
                )))
            });
            let nav = match nav {
                Ok(nav) => nav,
                Err(e) => {
                    // Only the very first attempt failing hard is fatal — a
                    // later navigation failure just ends the loop honestly.
                    if attempt == 1 {
                        return Err(e);
                    }
                    report
                        .step("classify", true, true, format!("navigation failed: {e}"));
                    break;
                }
            };
            last_status = nav.status_code.unwrap_or(200);
            report.final_status = last_status;

            let last_body: String = page
                .evaluate_expression(
                    "document.body ? document.body.innerText.substring(0, 2000) : ''",
                )
                .await
                .ok()
                .and_then(|v| v.as_str().map(|s| s.to_string()))
                .unwrap_or_default();
            report.body_hint = last_body.chars().take(200).collect();

            // Step 3 — captcha.detect (real DOM detection engine).
            let detected = match detect_captcha(&page.client, &page.session_id).await {
                Ok(d) => d,
                Err(e) => {
                    report.step(
                        "captcha.detect",
                        true,
                        true,
                        format!("detection errored: {e}"),
                    );
                    None
                }
            };

            if let Some(captcha) = detected {
                let type_name = format!("{:?}", captcha.captcha_type).to_ascii_lowercase();
                report.step(
                    "captcha.detect",
                    true,
                    true,
                    format!("{type_name} challenge detected (sitekey {})", captcha.site_key.as_deref().unwrap_or("none")),
                );

                // Step 4 — solve. Puzzle types (incl. Turnstile) go through the
                // external solver + DOM token injection when configured.
                let outcome = self.attempt_captcha_autosolve(page, url).await;
                match outcome {
                    CaptchaSolveOutcome::Solved => {
                        report.step(
                            "captcha.solve",
                            true,
                            true,
                            "solved via external solver; token injected — retrying navigation",
                        );
                        continue; // re-navigate with the injected token
                    }
                    CaptchaSolveOutcome::ManualSolved => {
                        report.step(
                            "captcha.solve",
                            true,
                            true,
                            "wait_for_manual_solve returned solved — retrying navigation",
                        );
                        continue;
                    }
                    CaptchaSolveOutcome::Failed => {
                        // Honest capability flag: if NO solver is configured the
                        // solve engine is unavailable, not merely unsuccessful.
                        if self.settings.captcha_solver.is_none() {
                            report.step(
                                "captcha.solve",
                                false,
                                false,
                                "no external CAPTCHA solver configured (set captcha_solver or TALLOW_CAPTCHA_* to enable)",
                            );
                        } else {
                            report.step(
                                "captcha.solve",
                                true,
                                true,
                                "solver configured but solve/inject failed",
                            );
                        }
                        // Turnstile-specific honesty: the turnstile engine leg
                        // is the same solver path; flag it explicitly so a
                        // script can tell turnstile from reCAPTCHA/hCaptcha.
                        if type_name.contains("turnstile") {
                            report.step(
                                "turnstile.solve",
                                self.settings.captcha_solver.is_some(),
                                false,
                                "turnstile challenge present; solve requires the external solver leg or manual solve",
                            );
                        }
                    }
                }
            } else {
                report.step("captcha.detect", true, true, "no captcha widget detected");
            }

            // Step 5 — warmup / escalation honest availability flags.
            let warmup_ready = self
                .profile_pool
                .get_ready_profile()
                .map(|p| p.needs_warmup())
                .unwrap_or(false);
            report.step(
                "warmup",
                self.settings.warmup_enabled && warmup_ready,
                false,
                if self.settings.warmup_enabled && warmup_ready {
                    "warmup profile available for a future request (session-level; not run inside resolve)"
                } else {
                    "warmup disabled or no profile warming (session-level engine)"
                },
            );
            let can_escalate = self.proxy_pool.len() > 1
                && self
                    .proxy_pool
                    .proxies
                    .iter()
                    .filter(|p| {
                        p.tier != ProxyTier::Mobile
                    })
                    .count()
                    > 0;
            report.step(
                "escalation",
                can_escalate,
                false,
                if can_escalate {
                    "higher proxy tiers exist; escalate by calling goto_antibot (resolve keeps the page's current egress)"
                } else {
                    "no higher proxy tier available on this orchestrator"
                },
            );

            // Step 6 — classify the final state; retry only when a solve
            // already re-queued us (continue above) — otherwise one bounded
            // backoff + final classification below ends the loop honestly.
            let class = Self::classify_response(last_status, Some(last_body.as_str()));
            let class_name = match class {
                ResponseClass::Success => "success",
                ResponseClass::SoftBlock => "soft_block",
                ResponseClass::HardBlock => "hard_block",
                ResponseClass::TransientError => "transient",
            };
            report.step(
                "classify",
                true,
                true,
                format!("status {last_status} classified {class_name}"),
            );
            if class == ResponseClass::Success {
                report.resolved = true;
                break;
            }
            if attempt < max_attempts {
                let backoff = std::time::Duration::from_millis(500 * 2u64.pow(attempt.min(4)));
                tokio::time::sleep(backoff).await;
            }
        }

        Ok(report)
    }

    /// Report a response outcome for a domain (updates rate limiter + proxy health).
    pub fn report_response(&mut self, domain: &str, status: u16, body: Option<&str>, proxy_url: Option<&str>, latency_ms: f64) {
        let class = if let Some(b) = body {
            let body_class = ResponseClass::from_body(b);
            if body_class != ResponseClass::Success {
                body_class
            } else {
                ResponseClass::from_status(status)
            }
        } else {
            ResponseClass::from_status(status)
        };

        match class {
            ResponseClass::Success => {
                self.rate_manager.report_success(domain);
                if let Some(url) = proxy_url {
                    self.proxy_pool.report_success(url, latency_ms);
                }
            }
            ResponseClass::SoftBlock => {
                self.rate_manager.report_soft_block(domain);
                if let Some(url) = proxy_url {
                    self.proxy_pool.report_failure(url, domain);
                }
            }
            ResponseClass::HardBlock => {
                self.rate_manager.report_hard_block(domain);
                if let Some(url) = proxy_url {
                    self.proxy_pool.report_failure(url, domain);
                }
            }
            ResponseClass::TransientError => {
                // Don't penalize rate limiter for server errors
            }
        }
    }

    /// Get a full status summary.
    pub fn status(&self) -> String {
        let mut out = String::new();
        out.push_str("=== Anti-Bot Orchestrator Status ===\n\n");

        // Proxy pool
        let alive = self.proxy_pool.alive_by_tier();
        out.push_str("Proxy Pool:\n");
        for tier in ProxyTier::fallback_chain() {
            let count = alive.get(tier).unwrap_or(&0);
            out.push_str(&format!("  {:12} {} alive\n", tier.name(), count));
        }
        out.push_str(&format!("  Total: {} proxies\n\n", self.proxy_pool.len()));

        // Rate limiters
        out.push_str("Rate Limiters:\n");
        for (domain, summary) in self.rate_manager.summary() {
            out.push_str(&format!("  {domain}: {summary}\n"));
        }
        out.push('\n');

        // Cookie farm
        out.push_str("Cookie Farm:\n");
        for (domain, count, needs_refresh, ab_type) in self.cookie_farm.summary() {
            out.push_str(&format!(
                "  {domain}: {count} cookies, refresh={}, type={:?}\n",
                if needs_refresh { "NEEDED" } else { "ok" },
                ab_type
            ));
        }
        out.push('\n');

        // Profile pool
        let (ready, fresh, flagged, retired) = self.profile_pool.stats();
        out.push_str(&format!(
            "Profiles: {} ready, {} fresh, {} flagged, {} retired\n\n",
            ready, fresh, flagged, retired
        ));

        // Known retailers
        out.push_str("Known Retailers:\n");
        for (domain, config) in &self.retailer_configs {
            let api_tag = if config.use_api { " [API]" } else { "" };
            out.push_str(&format!(
                "  {domain}{api_tag} — {:?}\n",
                config.antibot_types
            ));
        }

        out
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Free proxy sources
// ─────────────────────────────────────────────────────────────────────────────

/// P1 W3-S2: record this request's escalation traces to the run-evidence sink.
///
/// No-op (and no records) when the request never left the `Clean` path —
/// escalation evidence exists only where escalation happened. `resolved` is
/// `true` when the request ultimately succeeded after escalating.
fn flush_escalations(traces: &[EscalationTrace], domain: &str, resolved: bool) {
    if traces.is_empty() {
        return;
    }
    for t in traces {
        crate::run_evidence::record("escalation", t.to_json());
    }
    crate::run_evidence::record(
        "escalation_outcome",
        serde_json::json!({
            "domain": domain,
            "retries": traces.len(),
            "resolved": resolved,
        }),
    );
}

/// Methods for obtaining free residential-quality proxies.
pub struct FreeProxySources;

impl FreeProxySources {
    /// Architecture for $0 residential proxy setup.
    pub fn setup_guide() -> &'static str {
        r#"
=== FREE RESIDENTIAL PROXY SETUP ===

TIER 1: Mobile Proxies (BEST quality, $0 cost)
  Use old Android phones as 4G/5G SOCKS5 proxies:
  1. Install Termux + Every Proxy app on old phone
  2. Install Tailscale for remote access (free, up to 100 devices)
  3. Rotate IP by toggling airplane mode (ADB automation):
     adb shell cmd connectivity airplane-mode enable
     sleep 3
     adb shell cmd connectivity airplane-mode disable
     sleep 8
  Carriers: T-Mobile, AT&T, Verizon — all have excellent IP reputation

TIER 2: Raspberry Pi at Friends' Homes
  1. Install 3proxy or gost on Raspberry Pi ($35 one-time)
  2. Connect via Cloudflare Tunnel (free) or Tailscale
  3. Each location = 1 genuine residential IP

TIER 3: PacketStream Credit Loop
  Share your bandwidth → earn credits → spend credits on residential proxies
  Ratio: ~10GB shared = 1GB residential proxy access
  Yield: ~0.5-1.5 GB/month free

TIER 4: Oracle Cloud Free Tier (Relay Server)
  4 ARM cores, 24GB RAM, 10TB/month — FOREVER FREE
  Use as relay hub for mobile/residential exit nodes

ARCHITECTURE:
  [Scraper] → [Oracle Cloud relay] → [WireGuard] → [Phone/Pi on residential IP] → [Target]

IMPORTANT: Datacenter IPs (AWS, GCP, Azure) are blocked by all major retailers.
Only residential/mobile IPs reliably bypass anti-bot systems.
"#
    }

    /// Tor is NOT residential — it's mostly datacenter exit nodes that are publicly listed.
    pub fn tor_warning() -> &'static str {
        "Tor exit nodes are ~95% datacenter IPs and are publicly listed. Every major retailer blocks them. Use Tor for privacy, not for anti-bot bypass."
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn orchestrator_with_tor() -> AntiBotOrchestrator {
        AntiBotOrchestrator::with_settings(AntiBotSettings {
            tor_fallback: true,
            tor_instances: 2,
            ..Default::default()
        })
    }

    #[test]
    fn orchestrator_creation() {
        let orch = AntiBotOrchestrator::new();
        // B4: the default orchestrator must NOT silently seed static Tor-9050
        // instances — no daemon is guaranteed and 3 slow dead-proxy attempts
        // used to be the default outcome. Empty pool until egress is explicit.
        assert_eq!(
            orch.proxy_pool.len(),
            0,
            "default settings must not add silent Tor instances"
        );
        assert!(!orch.settings.tor_fallback);
        assert_eq!(orch.settings.tor_instances, 0);
        assert!(!orch.egress_configured(), "no egress without explicit config");
        assert!(!orch.retailer_configs.is_empty());
    }

    #[test]
    fn explicit_tor_settings_populate_pool() {
        let orch = orchestrator_with_tor();
        assert_eq!(orch.proxy_pool.len(), 2);
        assert!(orch.egress_configured());
        let all_tor = orch
            .proxy_pool
            .proxies
            .iter()
            .all(|p| p.tier == ProxyTier::Tor && p.url.contains("127.0.0.1:905"));
        assert!(all_tor, "explicit tor instances are loopback 905x socks proxies");
    }

    #[test]
    fn egress_fail_fast_when_unconfigured() {
        // B4: with no egress source the orchestrator reports an honest error
        // instead of stalling against a dead Tor daemon or leaking direct.
        let orch = AntiBotOrchestrator::new();
        assert!(!orch.egress_configured());
        let err = AntiBotOrchestrator::egress_required_error();
        let msg = format!("{err}");
        assert!(msg.contains("no egress proxy source"), "got: {msg}");
        assert!(msg.contains("TALLOW_PROXY"), "must name the env source: {msg}");
        assert!(msg.contains("tier:\"direct\""), "must name direct escape: {msg}");
        assert!(
            !msg.to_lowercase().contains("falling back to tor"),
            "must not promise a silent Tor fallback"
        );
    }

    #[test]
    fn explicit_direct_egress_allowed() {
        let orch = AntiBotOrchestrator::with_settings(AntiBotSettings {
            allow_direct_egress: true,
            ..Default::default()
        });
        assert!(orch.egress_configured());
    }

    #[test]
    fn explicit_proxy_populates_pool() {
        let mut orch = AntiBotOrchestrator::new();
        orch.proxy_pool
            .add(crate::browser::proxy::ProxyEntry::new(
                "http://egress:8080",
                ProxyTier::Datacenter,
            ));
        assert!(orch.egress_configured());
    }

    #[test]
    fn per_domain_sticky_selection() {
        let mut orch = orchestrator_with_tor();

        // Same domain, two selections → must return the SAME proxy URL.
        // (Regression guard: select_proxy_for_domain used to `sticky.remove`
        // on every call, so the domain hopped egress each request — a
        // metadata-correlation leak. It must now stay pinned to one egress.)
        let (u1, _t1) = orch
            .select_proxy_for_domain("test-domain-a.com", ProxyTier::Tor)
            .expect("pool has alive Tor instances");
        let (u2, _t2) = orch
            .select_proxy_for_domain("test-domain-a.com", ProxyTier::Tor)
            .expect("second selection should still find a proxy");
        assert_eq!(u1, u2, "a domain must stay pinned to one egress across selections");

        // Different domains may (and should) use different egress to avoid
        // cross-domain correlation.
        let (v1, _tv) = orch
            .select_proxy_for_domain("test-domain-b.com", ProxyTier::Tor)
            .expect("different domain should still find a proxy");
        assert!(v1.starts_with("socks5://"), "tor selection returns a socks proxy");
        let _ = v1;
    }

    #[test]
    fn resolve_engine_flags_over_fake_challenge_html() {
        // ROADMAP #9: the resolve loop's classification + honest capability
        // flags over a fake challenge body (fixture-gated, non-live). The
        // full detect→solve loop needs a live/mock Page; these assertions pin
        // the honest step vocabulary and the challenge classification the
        // loop relies on.
        let mut orch = AntiBotOrchestrator::new();

        // Fake Cloudflare Turnstile challenge HTML body (as innerText).
        let fake_challenge = "Please verify you are a human — cf-turnstile iframe \
                              enabled by your browser to continue. Access denied \
                              for automated access.";
        let class = AntiBotOrchestrator::classify_response(403, Some(fake_challenge));
        assert_eq!(class, ResponseClass::SoftBlock);

        // Fake DataDome-style interstitial.
        let datadome = "Enable JavaScript and cookies to continue — request blocked.";
        assert_eq!(
            AntiBotOrchestrator::classify_response(403, Some(datadome)),
            ResponseClass::SoftBlock
        );

        // A clean page classifies success regardless of status-200.
        let clean = "Product title and price here.";
        assert_eq!(
            AntiBotOrchestrator::classify_response(200, Some(clean)),
            ResponseClass::Success
        );

        // Honest flags on the default (unconfigured) orchestrator: no solver,
        // no warmup profile, no escalation, no egress — the exact notes a
        // script sees in ResolveReport.steps.
        assert!(!orch.egress_configured());
        assert!(orch.settings.captcha_solver.is_none());
        assert!(orch.proxy_pool.len() == 0);
    }

    #[test]
    fn resolve_report_steps_carry_honest_capability_flags() {
        let mut report = ResolveReport::new("https://example.test/login");
        report.step("egress", true, false, "proxy pool configured");
        report.step("captcha.detect", true, true, "none");
        report.step("captcha.solve", false, false, "no solver configured");
        report.step("warmup", false, false, "warmup disabled");
        report.step("escalation", false, false, "no higher tier");
        report.step("classify", true, true, "status 200 classified success");
        report.resolved = true;
        report.final_status = 200;

        assert!(report.resolved);
        assert_eq!(report.attempts, 0);
        assert_eq!(report.steps.len(), 6);
        // Every step is an honest (available, ran) pair — no step may claim
        // `ran:true` while `available:false`.
        for s in &report.steps {
            assert!(
                !(s.ran && !s.available),
                "engine {} claims ran but unavailable",
                s.engine
            );
        }
        let solve = report.steps.iter().find(|s| s.engine == "captcha.solve").unwrap();
        assert!(!solve.available && !solve.ran);
    }

    #[test]
    fn stealth_profile_threads_through_settings() {
        // B3: a relaunch stealth profile rides AntiBotSettings so the
        // orchestrator (execute_request) can apply the full bootstrap on
        // every relaunched page before its first navigation.
        let profile = StealthProfile::chrome_windows();
        let orch = AntiBotOrchestrator::with_settings(AntiBotSettings {
            stealth_profile: Some(profile.clone()),
            allow_direct_egress: true,
            ..Default::default()
        });
        let stored = orch
            .settings
            .stealth_profile
            .as_ref()
            .expect("profile must survive with_settings");
        assert_eq!(stored.user_agent, profile.user_agent);
        assert!(!stored.is_firefox_profile);
        assert!(orch.egress_configured());

        // And the default orchestrator carries no profile (bare relaunches
        // stay bare unless explicitly armed) — the honest default.
        assert!(AntiBotOrchestrator::new().settings.stealth_profile.is_none());
    }

    #[test]
    fn retailer_lookup() {
        let orch = AntiBotOrchestrator::new();

        let amazon = orch.get_retailer_config("www.amazon.com");
        assert!(amazon.is_some());

        let walmart = orch.get_retailer_config("walmart.com");
        assert!(walmart.is_some());
        assert!(walmart.unwrap().use_api);

        let bestbuy = orch.get_retailer_config("bestbuy.com");
        assert!(bestbuy.is_some());
        assert!(bestbuy.unwrap().use_api);
    }

    #[test]
    fn recommend_output() {
        let orch = AntiBotOrchestrator::new();

        let rec = orch.recommend("bestbuy.com");
        assert!(rec.contains("API"));

        let rec = orch.recommend("amazon.com");
        assert!(rec.contains("Residential"));
    }

    #[test]
    fn response_reporting() {
        let mut orch = AntiBotOrchestrator::new();

        // Success
        orch.report_response("amazon.com", 200, None, None, 150.0);

        // Soft block
        orch.report_response("amazon.com", 403, Some("captcha detected"), None, 0.0);

        // Check rate was reduced
        let summary = orch.rate_manager.summary();
        assert!(!summary.is_empty());
    }

    #[test]
    fn status_output() {
        let orch = AntiBotOrchestrator::new();
        let status = orch.status();
        assert!(status.contains("Proxy Pool"));
        assert!(status.contains("Known Retailers"));
    }

    #[test]
    fn free_proxy_guide() {
        let guide = FreeProxySources::setup_guide();
        assert!(guide.contains("Mobile Proxies"));
        assert!(guide.contains("Raspberry Pi"));
        assert!(guide.contains("Oracle Cloud"));
    }
}
