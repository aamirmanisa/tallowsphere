//! Browser automation module for Tallow.
//!
//! Provides CDP-based browser control with process lifecycle management,
//! page navigation with lifecycle events, element querying with auto-waiting,
//! robots.txt compliance, rate limiting, retry logic, and typed error handling.

/// Named network profiles, as (download_kbps, upload_kbps, latency_ms).
///
/// Shared by the interpreter arm and the native FFI: a preset table in two
/// places is a divergence waiting to happen.
pub fn network_preset(preset: &str) -> Option<(f64, f64, f64)> {
    match preset.trim().to_ascii_lowercase().as_str() {
        "slow-3g" | "slow3g" => Some((400.0, 400.0, 500.0)),
        "fast-3g" | "fast3g" => Some((1_600.0, 750.0, 150.0)),
        "4g" => Some((9_000.0, 3_000.0, 50.0)),
        "none" | "off" | "reset" => Some((0.0, 0.0, 0.0)),
        _ => None,
    }
}

pub mod ab_detector;
pub mod accessibility;
pub mod adaptive_crawler;
pub mod advanced_stealth;
pub mod affiliate;
pub mod ai_extract;
pub mod antibot;
pub mod auth;
pub mod auth_strategy;
pub mod autonomous;
pub mod basket_optimizer;
pub mod behavior;
pub mod cadence;
pub mod canary;
pub mod captcha;
pub mod cdp;
pub mod sentinels;
pub mod cft_pins;
pub mod circuit_breaker;
pub mod compliance;
pub mod config;
pub mod cookie_farm;
pub mod crawl_pipeline;
pub mod crawl_queue;
pub mod devices;
pub mod distributed;
pub mod dlq;
pub mod download;
pub mod dpi_bypass;
pub mod dual_mode;
pub mod element;
pub mod emulation;
pub mod error;
pub mod fallback;
pub mod fingerprint_coherence;
pub mod fingerprint_validator;
pub mod frame;
pub mod free_proxies;
pub mod har_import;
pub mod household;
pub mod html_parser;
pub mod http2_fingerprint;
pub mod intelligence;
pub mod interaction;
pub mod ippool;
pub mod ipv6_pool;
pub mod job_queue;
pub mod juggler;
pub mod llm_extract;
pub mod llm_transfer;
pub mod markdown;
pub mod ml;
pub mod network;
pub mod network_stealth;
pub mod observability;
pub mod page;
pub mod perf_engine;
pub mod plugins;
pub mod pool;
pub mod presets;
pub mod price_bounds;
pub mod price_history;
pub mod privacy;
pub mod process;
pub mod product_matcher;
pub mod provenance;
pub mod proxy;
pub mod quality_validator;
pub mod ratelimit;
pub mod reality;
pub mod recipe_parser;
pub mod recording;
pub mod residential;
pub mod resource_blocker;
pub mod retry;
pub mod retry_intelligence;
pub mod robots;
pub mod route_model;
pub mod router;
pub mod runtime_fingerprint_audit;
pub mod scheduler;
pub mod schema_drift;
pub mod scrub;
pub mod search_engine;
pub mod search_index;
pub mod selector_chain;
pub mod self_heal;
pub mod session;
pub mod shrinkflation;
pub mod sitemap;
pub mod slider_captcha;
pub mod smart_extract;
pub mod snapshot_sampler;
pub mod socks_shim;
pub mod stealth;
pub mod stealth_v2;
pub mod stealth_v3;
pub mod storage;
pub mod structured_data;
pub mod substitution;
pub mod tor_stealth;
pub mod trace;
pub mod traffic_morph;
pub mod triangulation;
pub mod typesense;
pub mod unit_normalizer;
pub mod vendor_detect;
pub mod visual;
pub mod warmup;
pub mod wordfence_bypass;
pub mod wordpress_auth;
pub mod zip_rotation;
pub mod zone;

pub use ab_detector::{AbLayoutDetector, DetectionResult, LayoutFingerprint, StructuralFeatures};
pub use accessibility::{
    AXNode, AXProperty, AXValue, ConsentBannerInfo, WcagAuditResult, WcagLevel, WcagViolation,
    accept_consent, detect_consent_banner, get_accessibility_tree, impact_weight,
    query_accessibility_node, reject_tracking_cookies, run_wcag_audit,
};
pub use adaptive_crawler::{AdaptiveCrawler, CrawlResult, CrawlSource};
pub use ai_extract::{
    ArticleData, ProductData as AiProductData, RecipeData, SchemaExtractor, html_to_clean_text,
};
pub use antibot::{AntiBotOrchestrator, AntiBotSettings, FreeProxySources, RetailerConfig};
pub use auth::{
    OAuthTokenResult, capture_oauth_redirect, decode_totp_secret, generate_totp,
    generate_totp_default, is_logged_in, restore_login_session, save_login_session,
};
pub use behavior::BehaviorSimulator;
pub use captcha::{
    CaptchaInfo, CaptchaSolverConfig, CaptchaType, detect_captcha, inject_captcha_solution,
    solve_captcha, wait_for_manual_solve,
};
pub use cdp::{CdpClient, TransportMode};
pub use config::BrowserFullConfig;
pub use cookie_farm::{AntiBotCookie, CookieFarm, CookieType, DomainCookieJar, RetailerAntiBot};
pub use crawl_queue::{CrawlJob, CrawlQueue, DeltaPlan, delta_crawl_enabled};
pub use devices::{
    DeviceDescriptor, device_count, get_device, list_devices, list_devices_by_category,
};
pub use download::{
    ensure_browser_available, find_installed_chrome, install_browser, list_installed,
    remove_version,
};
pub use element::{ElementChain, ElementHandle, ShadowRoot};
pub use emulation::{
    DeviceProfile, apply_stealth_profile, clear_device_metrics, clear_geolocation, set_geolocation,
    set_locale, set_timezone, set_touch_emulation, set_user_agent, set_viewport,
};
pub use error::{BrowserError, NavigationError};
pub use fingerprint_validator::{
    ALL_CONSISTENT_FINGERPRINTS, ConsistentFingerprint, FingerprintValidator, FingerprintWarning,
    LINUX_CHROME_MESA, MAC_CHROME_APPLE, Severity, WINDOWS_CHROME_INTEL, WINDOWS_CHROME_NVIDIA,
    detect_os_from_fonts, validate_fingerprint, validate_fonts_for_ua,
};
pub use frame::FrameInfo;
pub use html_parser::{HtmlParser, strip_html_tags};
pub use http2_fingerprint::{
    Http2ConnConfig, Http2Fingerprint, akamai_fingerprint_string, chrome_header_order,
    firefox_header_order, header_order_for, safari_header_order,
};
pub use interaction::{
    ClickOptions, MODIFIER_ALT, MODIFIER_CTRL, MODIFIER_META, MODIFIER_SHIFT, MouseButton,
    SelectBy, bezier_mouse_path, gaussian_keystroke_delay,
};
pub use llm_extract::{
    ExtractError, ExtractedData, ExtractionSchema, ExtractorContractVersion, FieldExtractor,
    LlmExtractor, TransformFn, ValidationResult,
};
pub use markdown::html_to_markdown;
pub use network::{
    HeaderEntry, InterceptAction, InterceptRule, MockResponse, NetworkInterceptor, RequestStage,
    ResourceType, WebSocketConnection, WebSocketFrame, WebSocketFrameDirection,
    WebSocketInterceptConfig, WebSocketInterceptor, WebSocketMonitor,
};
pub use page::{
    CookieConsentStrategy, DialogHandler, NavigationResult, Page, PaginationInfo, WaitUntil,
};
pub use pool::{
    BrowserPool, LoadSignal, PoolConfig, PoolHandle, PoolSnapshot, PoolStats, ScalingPolicy,
    system_headroom,
};
pub use privacy::{
    ContentFingerprint, PiiScanResult, PiiType, RetentionEntry, RetentionRegistry, scan_and_redact,
};
pub use process::{BrowserBackend, BrowserConfig, BrowserProcess};
pub use product_matcher::{
    CanonicalProduct, MatchMethod, MatchResult, ProductMatcher, ScrapedListing,
};
pub use proxy::{ProxyEntry, ProxyHealth, ProxyPool, ProxyTier};
pub use ratelimit::{AdaptiveRateLimiter, DomainRateManager, ResponseClass};
pub use recording::{
    RecordingConfig, RecordingResult, encode_as_avi_mjpeg, encode_frames, encode_with_ffmpeg,
    ffmpeg_available, parse_resolution, save_as_frames,
};
pub use resource_blocker::{BlockProfile, ResourceBlocker};
pub use retry::{BackoffStrategy, RetryConfig, retry_with_backoff};
pub use robots::{RateLimiter, RobotsCache};
pub use scheduler::{
    CronExpr, Frequency, MissedPolicy, ScheduleStore, ScheduledJob, SchedulerDaemon, epoch_secs,
    format_epoch, parse_interval, print_schedule_table, validate_daily_time,
};
pub use scrub::{
    FileScrubReport, ScrubGuard, ScrubPolicy, ScrubReport, ScrubSession, scrub, scrub_files,
    scrub_on_exit, scrub_on_exit_default, set_scrub_on_exit_default,
};
pub use search_engine::urlencoded as search_engine_urlencoded;
pub use self_heal::{SelectorCandidate, SelfHealingSelector};
pub use session::{
    BrowserSession, CdpCookie, capture_session, clear_cookies, get_cookies, get_local_storage,
    get_session_storage, load_session, save_session,
};
pub use sitemap::{SitemapEntry, SitemapParser};
pub use slider_captcha::{
    CdpMouseEvent, SliderConfig, SliderSpeed, SliderTrajectory, TrajectoryPoint,
    TrajectoryValidation, alibaba_slider, generate_slider_trajectory, generic_slider, jd_slider,
    tencent_slider, trajectory_to_cdp_events, validate_trajectory,
};
pub use stealth::StealthProfile;
pub use storage::{
    InMemoryBackend, ParquetBackend, S3Backend, SqliteBackend, StorageBackend, StorageError,
    StorageKind, StoredItem, UpsertOutcome, canonical_key, open_backend,
};
pub use structured_data::{MicrodataItem, ProductData, StructuredDataExtractor};
pub use trace::{TraceAction, TraceNetworkEvent, TraceRecorder, open_trace_viewer};
pub use visual::{
    BaselineManifest, DiffResult, PdfOptions, capture_element_screenshot, capture_screenshot,
    capture_viewport_screenshot, compare_screenshots, compare_with_baseline, load_baseline,
    print_to_pdf, save_baseline,
};
pub use warmup::{ManagedProfile, ProfilePool, RetailerWarmup, WarmupSequence};
pub use zip_rotation::{Region, ZipEntry, ZipPool, ZipRotator};
// Root re-exports added 2026-09-15: the tallow-search browser-gated contract
// tests import these at the `tallow::browser` root; they were only reachable
// via their submodules (`presets::`, `dual_mode::`).
pub use dual_mode::{DualModeEngine, DualModeResponse, EngineMode};
pub use presets::{LevelConfig, PresetManager, ScrapeLevel};
