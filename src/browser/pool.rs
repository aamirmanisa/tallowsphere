//! Browser pool manager for Tallow.
//!
//! Manages a pool of browser instances with semaphore-gated acquire/release,
//! crash detection and replacement, recycling between tasks, proxy rotation,
//! and observable stats.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;

use tokio::sync::{Mutex, Semaphore, OwnedSemaphorePermit};

use super::cdp::CdpClient;
use super::error::BrowserError;
use super::fingerprint_validator::{FingerprintValidator, Severity};
use super::process::{BrowserConfig, BrowserProcess};
use super::stealth::StealthProfile;

/// State of a browser instance in the pool.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrowserState {
    /// Instance is available for use.
    Idle,
    /// Instance is currently in use by a task.
    Active,
    /// Instance has crashed and needs replacement.
    Crashed,
}

impl fmt::Display for BrowserState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BrowserState::Idle => write!(f, "idle"),
            BrowserState::Active => write!(f, "active"),
            BrowserState::Crashed => write!(f, "crashed"),
        }
    }
}

/// A browser instance managed by the pool.
pub struct PooledBrowser {
    /// The underlying browser process.
    pub process: BrowserProcess,
    /// CDP client connected to this browser.
    pub client: CdpClient,
    /// CDP session ID for this browser's default page.
    pub session_id: String,
    /// Current state of this instance.
    state: BrowserState,
    /// Number of tasks completed by this instance.
    tasks_completed: u32,
    /// Proxy URL assigned to this instance (if any).
    #[allow(dead_code)]
    proxy: Option<String>,
    /// Task class of the cohort this instance last served (R-7 bookkeeping;
    /// see [`BrowserPool::instance_cohorts`]).
    #[allow(dead_code)]
    cohort: Option<String>,
    /// Position in the pool's instance vector.
    #[allow(dead_code)]
    index: usize,
}

/// Per-launch egress-identity minter (W1-E4).
///
/// A pool slot is long-lived: it serves up to `max_tasks_per_instance` tasks
/// before it is retired, and a static `proxies` entry hands every one of those
/// launches the *same* credentials — so the slot keeps one Tor circuit for its
/// whole life. A minter is consulted on every `launch_instance` instead, so a
/// relaunched slot gets fresh credentials and therefore a new circuit
/// (`IsolateSOCKSAuth` assigns a circuit per distinct SOCKS5 user/pass pair).
///
/// Wrapped in a newtype rather than stored as `Arc<dyn Fn>` directly so
/// `PoolConfig` keeps its `Debug`/`Clone` derives.
pub struct ProxyMint(Arc<dyn Fn(usize) -> Option<String> + Send + Sync>);

impl ProxyMint {
    pub fn new(f: impl Fn(usize) -> Option<String> + Send + Sync + 'static) -> Self {
        Self(Arc::new(f))
    }

    /// Mint the egress URL for a pool slot (`None` = direct).
    pub fn get(&self, index: usize) -> Option<String> {
        (self.0)(index)
    }
}

impl Clone for ProxyMint {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl std::fmt::Debug for ProxyMint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProxyMint(<per-launch identity factory>)")
    }
}

/// Configuration for a browser pool.
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// Maximum number of browser instances (default: 4).
    pub max_size: usize,
    /// Recycle instance after this many tasks (default: 100).
    pub max_tasks_per_instance: u32,
    /// Browser launch configuration.
    pub browser_config: BrowserConfig,
    /// Proxy URLs for IPPool-style routing (empty = no proxy).
    pub proxies: Vec<String>,
    /// Optional ProxyPool (Layer 4, tiered rotation). When set, it takes
    /// priority over the static `proxies` list (Layer 1) in `proxy_for_index`.
    pub proxy_pool: Option<Arc<std::sync::Mutex<super::proxy::ProxyPool>>>,
    /// Route browser traffic through Tor (default: false).
    pub tor_enabled: bool,
    /// Number of Tor instances to spawn for pool rotation (default: 1).
    pub tor_instances: usize,
    /// Clear cookies/storage on release (default: true).
    pub recycle_on_release: bool,
    /// Per-launch egress-identity minter (W1-E4). When set, every
    /// [`BrowserPool::launch_instance`] consults it for a FRESH proxy URL, so a
    /// relaunched slot gets new credentials — and therefore its own Tor circuit
    /// — instead of inheriting the identity its predecessor used. Takes
    /// priority over `proxy_pool` and `proxies` on the launch path only;
    /// `proxy_for_index` (the reporting path) still reflects the static
    /// configuration. `None` (default) leaves behaviour untouched.
    pub proxy_mint: Option<ProxyMint>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_size: 4,
            max_tasks_per_instance: 100,
            browser_config: BrowserConfig::default(),
            proxies: Vec::new(),
            proxy_pool: None,
            tor_enabled: false,
            tor_instances: 1,
            recycle_on_release: true,
            proxy_mint: None,
        }
    }
}

/// A point-in-time load signal consumed by [`BrowserPool::autoscale`].
///
/// Values are supplied by the caller (typically the scheduler/worker on a
/// tick). CPU and memory headroom are ratios in `[0.0, 1.0]` where `1.0`
/// means fully idle/sufficient and `0.0` means saturated. Pass `f32::NAN`
/// to indicate headroom that could not be measured; autoscaling treats an
/// unknown headroom as *sufficient* so it never stalls growth on a probe
/// failure.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LoadSignal {
    /// Number of jobs waiting in the queue (backlog depth).
    pub queue_depth: u32,
    /// Number of currently in-flight (active) browser instances.
    pub in_flight: u32,
    /// Available CPU headroom as a ratio in `[0.0, 1.0]` (NaN = unknown).
    pub cpu_headroom: f32,
    /// Available memory headroom as a ratio in `[0.0, 1.0]` (NaN = unknown).
    pub mem_headroom: f32,
}

impl Default for LoadSignal {
    fn default() -> Self {
        Self {
            queue_depth: 0,
            in_flight: 0,
            cpu_headroom: f32::NAN,
            mem_headroom: f32::NAN,
        }
    }
}

/// Scaling policy for CPU/memory-aware browser-pool autoscaling
/// (a Crawlee `AutoscaledPool`-style policy).
///
/// Autoscaling is **disabled by default**: when [`Self::enabled`] is `false`
/// the pool falls back to the fixed [`PoolConfig::max_size`] capacity exactly
/// as before. When enabled, the pool grows toward [`Self::autoscale_max`]
/// (never past the hard [`Self::hard_cap`]) when demand is high **and** the
/// host has sufficient CPU/memory headroom, and shrinks toward [`Self::min_size`]
/// when demand is low. The decision logic mirrors `perf_engine::AdaptiveConcurrency`
/// (AIMD): additive increase in steps, multiplicative decrease by a factor.
#[derive(Debug, Clone)]
pub struct ScalingPolicy {
    /// Enable dynamic scaling (default: false — fixed `max_size`).
    pub enabled: bool,
    /// Lower bound the pool never shrinks below (default: 1).
    pub min_size: usize,
    /// Largest size autoscaling may grow to. Must be `<= hard_cap`.
    pub autoscale_max: usize,
    /// Absolute hard ceiling on pool size. Must be `>= autoscale_max`.
    pub hard_cap: usize,
    /// Demand ratio (`(in_flight + queue_depth) / target_size`) at or above
    /// which the pool grows (AIMD additive-increase trigger).
    pub scale_up_threshold: f32,
    /// Demand ratio at or below which the pool shrinks (AIMD decrease trigger).
    pub scale_down_threshold: f32,
    /// CPU headroom ratio required to allow a scale-up (default: 0.25).
    pub cpu_headroom_ratio: f32,
    /// Memory headroom ratio required to allow a scale-up (default: 0.15).
    pub mem_headroom_ratio: f32,
    /// Instances added per scale-up step (AIMD additive-increase step).
    pub increase_step: usize,
    /// Factor applied to the target size on scale-down (AIMD multiplicative
    /// decrease factor; e.g. 0.5 halves the target each idle tick).
    pub decrease_factor: f64,
}

impl Default for ScalingPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            min_size: 1,
            autoscale_max: 8,
            hard_cap: 16,
            scale_up_threshold: 0.8,
            scale_down_threshold: 0.2,
            cpu_headroom_ratio: 0.25,
            mem_headroom_ratio: 0.15,
            increase_step: 1,
            decrease_factor: 0.5,
        }
    }
}

// ---------------------------------------------------------------------------
// Cohort fingerprint policy (report ag03 R-7 / matrix row #45)
// ---------------------------------------------------------------------------
//
// The pool is the single place that assigns a *fingerprint identity* to a
// browser. R-7's discipline is:
//
//   * one coherent family per cohort — every browser serving a task class
//     presents the *same* coherent profile; attributes are never mixed or
//     randomized per request (uniformity beats randomization);
//   * rotation per task class — a profile changes only at task-class/run
//     boundaries, and every change is recorded (deliberate, never silent drift);
//   * declared-bot default — public scraping defaults to the honest
//     `TallowScraper/<v> (+contact)` identity; stealth profiles are reserved
//     for task classes that are explicitly cleared for them.

/// Task-class id for public web scraping.
///
/// This is the class whose honest default posture is the declared-bot
/// identity (R-7). Any class not explicitly cleared for stealth gets the
/// policy default posture, so this constant only needs to be used by callers
/// that want to be explicit.
pub const TASK_CLASS_PUBLIC_SCRAPING: &str = "public-scraping";

/// Built-in contact embedded in the declared-bot user agent.
///
/// Operators running at scale should point their own contact at themselves
/// (via `TALLOW_BOT_CONTACT` or [`DeclaredBotIdentity::contact`]) — an honest
/// declared bot is only useful if the site can reach a human about it.
pub const DEFAULT_BOT_CONTACT: &str = "https://github.com/tallow-lang/tallow";

/// Honest declared-bot identity: `TallowScraper/<version> (+contact)`.
///
/// This is the R-7 "declared bot" path: the client tells the site it is a bot
/// instead of impersonating a human browser. It is the default posture for
/// public scraping; stealth profiles are reserved for legally-cleared sources.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeclaredBotIdentity {
    /// Product-token version (default: this crate's version).
    pub version: String,
    /// Contact (URL or e-mail) the site can use to reach the operator.
    pub contact: String,
}

impl Default for DeclaredBotIdentity {
    fn default() -> Self {
        Self {
            version: env!("CARGO_PKG_VERSION").to_string(),
            // `TALLOW_BOT_CONTACT` lets a deployment declare its own contact
            // without a rebuild; unset/blank falls back to the project contact.
            contact: std::env::var("TALLOW_BOT_CONTACT")
                .ok()
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| DEFAULT_BOT_CONTACT.to_string()),
        }
    }
}

impl DeclaredBotIdentity {
    /// The declared user-agent string: `TallowScraper/<version> (+<contact>)`
    /// (`+contact` is omitted when no contact is configured).
    pub fn user_agent(&self) -> String {
        if self.contact.is_empty() {
            format!("TallowScraper/{}", self.version)
        } else {
            format!("TallowScraper/{} (+{})", self.version, self.contact)
        }
    }
}

/// A coherent fingerprint family — the engine-consistent attribute set that
/// must never be mixed across the browsers of one cohort (R-7).
///
/// Classified *from* an existing [`StealthProfile`] (via [`ProfileFamily::of`])
/// so the family a cohort presents can always be derived and asserted from the
/// profile itself; there is no second source of truth to drift.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProfileFamily {
    /// Chrome on Windows.
    ChromeWindows,
    /// Chrome on macOS.
    ChromeMacos,
    /// Chrome on Linux (X11).
    ChromeLinux,
    /// Chrome on Android.
    MobileAndroid,
    /// Chrome (CriOS) on iOS.
    MobileIos,
    /// Firefox/Tor-Browser family (`is_firefox_profile`).
    TorFirefox,
    /// Declared bot: `TallowScraper/<v> (+contact)`.
    DeclaredBot,
    /// Anything a factory method did not produce.
    Custom,
}

impl ProfileFamily {
    /// Classify a profile into its family. Engine-affecting attributes (UA,
    /// `is_firefox_profile`) decide — identity-only fields (timezone, canvas
    /// seed, …) are rotated within a family and must not change the family.
    pub fn of(profile: &StealthProfile) -> Self {
        let ua = &profile.user_agent;
        if ua.contains("TallowScraper/") {
            return Self::DeclaredBot;
        }
        if profile.is_firefox_profile || ua.contains("Firefox/") {
            return Self::TorFirefox;
        }
        if ua.contains("Android") {
            return Self::MobileAndroid;
        }
        // iPhone/iPad UAs also contain "Mac OS X" — classify before macOS.
        if ua.contains("iPhone") || ua.contains("iPad") {
            return Self::MobileIos;
        }
        if ua.contains("Windows") {
            return Self::ChromeWindows;
        }
        if ua.contains("Macintosh") || ua.contains("Mac OS X") {
            return Self::ChromeMacos;
        }
        if ua.contains("X11; Linux") || ua.contains("Linux x86_64") {
            return Self::ChromeLinux;
        }
        Self::Custom
    }

    /// Stable short id for logs, evidence and tests.
    pub fn id(self) -> &'static str {
        match self {
            Self::ChromeWindows => "chrome-windows",
            Self::ChromeMacos => "chrome-macos",
            Self::ChromeLinux => "chrome-linux",
            Self::MobileAndroid => "mobile-android",
            Self::MobileIos => "mobile-ios",
            Self::TorFirefox => "tor-firefox",
            Self::DeclaredBot => "declared-bot",
            Self::Custom => "custom",
        }
    }
}

/// Build the declared-bot [`StealthProfile`] (R-7 honest default).
///
/// The profile does not pretend to be a human browser: the UA announces
/// `TallowScraper/<v> (+contact)` and the platform reports the *actual* host
/// OS, because a declared bot gains nothing from claiming a foreign OS (the
/// TCP/IP layer would contradict it — see `network_stealth.rs`). Engine fields
/// stay Chromium-consistent, so the profile is internally coherent for
/// [`FingerprintValidator`]. Identity fields (canvas seed, timezone, …) are
/// constants: the declared identity is uniform across the cohort by design.
pub fn declared_bot_profile(identity: &DeclaredBotIdentity) -> StealthProfile {
    // Start from the engine-coherent preset for the real host OS so platform,
    // GPU and resolution stay truthful, then swap in the declared UA.
    let mut profile = match std::env::consts::OS {
        "windows" => StealthProfile::chrome_windows(),
        "macos" => StealthProfile::chrome_macos(),
        _ => StealthProfile::chrome_linux(),
    };
    profile.user_agent = identity.user_agent();
    // A server-side bot is honest about running in UTC; it is not claiming a
    // human's location.
    profile.timezone = "UTC".to_string();
    profile
}

/// The fingerprint posture a cohort presents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CohortPosture {
    /// Honest declared bot — `TallowScraper/<v> (+contact)`.
    /// The R-7 default for public scraping.
    DeclaredBot,
    /// A coherent stealth profile family. Reserved for task classes that are
    /// explicitly cleared for stealth (legally-cleared sources).
    Stealth,
}

/// When a cohort's profile rotates.
///
/// Rotation is always deliberate: whatever the policy, the pool only re-rolls
/// at the documented boundary and records the event in
/// [`BrowserPool::rotation_log`] — profiles never drift silently per request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RotationPolicy {
    /// Fresh identity roll at each run boundary ([`BrowserPool::begin_run`]);
    /// stable within a run (family fixed, identity-only fields re-rolled).
    PerRun,
    /// Stable for the entire life of the cohort; only an explicit
    /// [`BrowserPool::rotate_cohort`] changes it (default).
    PerCohort,
}

/// Cohort fingerprint policy for a [`BrowserPool`].
///
/// Set with [`BrowserPool::with_cohorts`]. Defaults implement R-7: the honest
/// declared-bot posture for public scraping, no stealth classes, per-cohort
/// stability.
#[derive(Debug, Clone)]
pub struct CohortPolicy {
    /// Posture for task classes not explicitly listed in `stealth_classes`.
    /// Default: [`CohortPosture::DeclaredBot`].
    pub default_posture: CohortPosture,
    /// Task classes explicitly cleared for stealth (legally-cleared sources).
    /// Empty by default — stealth must be granted to a class, never assumed.
    pub stealth_classes: Vec<String>,
    /// Coherent stealth families the pool may assign, deterministically per
    /// class. Desktop Chromium families by default: a mobile family on a
    /// desktop host (or a Firefox family on Chromium) is exactly the
    /// cross-family contradiction this cohort model exists to prevent.
    pub stealth_palette: Vec<StealthProfile>,
    /// Rotation policy. Default: [`RotationPolicy::PerCohort`] (stable).
    pub rotation: RotationPolicy,
    /// Declared-bot identity for [`CohortPosture::DeclaredBot`].
    pub declared_bot: DeclaredBotIdentity,
}

impl Default for CohortPolicy {
    fn default() -> Self {
        Self {
            default_posture: CohortPosture::DeclaredBot,
            stealth_classes: Vec::new(),
            stealth_palette: vec![
                StealthProfile::chrome_windows(),
                StealthProfile::chrome_macos(),
                StealthProfile::chrome_linux(),
            ],
            rotation: RotationPolicy::PerCohort,
            declared_bot: DeclaredBotIdentity::default(),
        }
    }
}

impl CohortPolicy {
    /// Posture for a task class: an explicit stealth clearance wins, otherwise
    /// the policy default (DeclaredBot) applies. Class ids are matched
    /// case-insensitively on trimmed input.
    pub fn posture_for(&self, task_class: &str) -> CohortPosture {
        let class = task_class.trim().to_ascii_lowercase();
        if self
            .stealth_classes
            .iter()
            .any(|c| c.trim().to_ascii_lowercase() == class)
        {
            CohortPosture::Stealth
        } else {
            self.default_posture
        }
    }

    /// Deterministically pick the stealth family for a class.
    ///
    /// The pick is a stable hash of the class id, so the same class presents
    /// the same family across runs, processes and hosts — the class set is the
    /// rotation unit (R-7: rotate per task class, not per request).
    pub fn stealth_profile_for(&self, task_class: &str) -> StealthProfile {
        if self.stealth_palette.is_empty() {
            return StealthProfile::chrome_windows();
        }
        let class = task_class.trim().to_ascii_lowercase();
        let idx = (stable_hash(&class) as usize) % self.stealth_palette.len();
        self.stealth_palette[idx].clone()
    }
}

/// FNV-1a — a stable, allocation-free hash (std's `DefaultHasher` is not
/// guaranteed stable across releases, which would make cohort families drift
/// between builds).
fn stable_hash(s: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

/// A cohort's assigned fingerprint identity (read-only view).
#[derive(Debug, Clone)]
pub struct CohortAssignment {
    /// Task class this cohort serves.
    pub task_class: String,
    /// Posture of the cohort.
    pub posture: CohortPosture,
    /// Coherent family of the assigned profile.
    pub family: ProfileFamily,
    /// The single profile every browser in this cohort presents.
    pub profile: StealthProfile,
    /// Rotation epoch: `0` at first assignment, `+1` per deliberate rotation.
    pub epoch: u64,
}

impl CohortAssignment {
    /// `true` when the assigned profile has no `Critical` cross-vector
    /// contradiction (`FingerprintValidator`). A cohort must only ever serve
    /// coherent profiles; this is the assertion tests and audits use.
    pub fn is_coherent(&self) -> bool {
        !FingerprintValidator::validate(&self.profile)
            .iter()
            .any(|w| w.severity == Severity::Critical)
    }
}

/// One deliberate cohort rotation (audit trail — the "not silent drift" leg).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RotationEvent {
    /// Task class whose cohort rotated.
    pub task_class: String,
    /// Epoch after the rotation.
    pub epoch: u64,
    /// Why it rotated (e.g. `"run boundary"`, operator note).
    pub reason: String,
}

/// Internal per-cohort state held by the pool registry.
struct CohortState {
    posture: CohortPosture,
    family: ProfileFamily,
    profile: StealthProfile,
    epoch: u64,
}

/// Read-only view conversion.
fn cohort_view(task_class: &str, state: &CohortState) -> CohortAssignment {
    CohortAssignment {
        task_class: task_class.to_string(),
        posture: state.posture,
        family: state.family,
        profile: state.profile.clone(),
        epoch: state.epoch,
    }
}

/// Atomic counters for pool statistics.
pub struct PoolStats {
    /// Number of currently active (in-use) instances.
    pub active: AtomicU32,
    /// Number of currently idle (available) instances.
    pub idle: AtomicU32,
    /// Number of instances that have crashed and not yet been replaced.
    pub crashed: AtomicU32,
    /// Total tasks completed across all instances.
    pub total_tasks: AtomicU64,
    /// Total browser instances ever created.
    pub total_created: AtomicU64,
    /// Total recycle operations (cookie/storage clears).
    pub total_recycled: AtomicU64,
}

impl PoolStats {
    /// Create a new PoolStats with all zeroes.
    fn new() -> Self {
        Self {
            active: AtomicU32::new(0),
            idle: AtomicU32::new(0),
            crashed: AtomicU32::new(0),
            total_tasks: AtomicU64::new(0),
            total_created: AtomicU64::new(0),
            total_recycled: AtomicU64::new(0),
        }
    }
}

/// A snapshot of pool statistics at a point in time.
#[derive(Debug, Clone)]
pub struct PoolSnapshot {
    /// Number of currently active instances.
    pub active: u32,
    /// Number of currently idle instances.
    pub idle: u32,
    /// Number of crashed instances.
    pub crashed: u32,
    /// Total tasks completed.
    pub total_tasks: u64,
    /// Total instances ever created.
    pub total_created: u64,
    /// Total recycle operations.
    pub total_recycled: u64,
    /// Maximum pool size.
    pub max_size: usize,
}

impl fmt::Display for PoolSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Pool[{}/{} active, {} idle, {} crashed | tasks: {}, created: {}, recycled: {}]",
            self.active, self.max_size, self.idle, self.crashed,
            self.total_tasks, self.total_created, self.total_recycled
        )
    }
}

/// Handle returned by `BrowserPool::acquire()`.
///
/// Holds a reference to the acquired browser's CdpClient and session,
/// plus the semaphore permit that is automatically released on drop.
pub struct PoolHandle {
    /// CDP client for the acquired browser instance.
    pub client: CdpClient,
    /// CDP session ID for the acquired browser.
    pub session_id: String,
    /// Index of this instance in the pool.
    pub index: usize,
    /// Cohort assignment (task class + coherent profile) when the handle came
    /// from [`BrowserPool::acquire_for`]; `None` for plain
    /// [`BrowserPool::acquire`] (no cohort requested).
    pub cohort: Option<CohortAssignment>,
    /// Semaphore permit -- released on drop.
    _permit: OwnedSemaphorePermit,
}

/// Browser pool manager.
///
/// Lazily creates browser instances up to `max_size`, gates concurrent
/// access with a semaphore, and recycles/replaces instances as needed.
pub struct BrowserPool {
    config: PoolConfig,
    instances: Arc<Mutex<Vec<Option<PooledBrowser>>>>,
    semaphore: Arc<Semaphore>,
    stats: Arc<PoolStats>,
    /// Autoscaling policy. `None` (default) keeps the fixed `max_size`.
    scaling: Option<ScalingPolicy>,
    /// Current desired pool size when autoscaling is enabled; otherwise equals
    /// `max_size`. Atomic so `scale_up`/`scale_down` can be driven from any task.
    target_size: Arc<AtomicU32>,
    /// Cohort fingerprint policy (R-7). Always present; defaults implement the
    /// declared-bot default for public scraping + per-cohort stability.
    cohort_policy: CohortPolicy,
    /// Cohort registry: task class -> assigned coherent profile. The registry
    /// is the "one family per cohort" guarantee — every acquire for a class
    /// reads the same profile until it is deliberately rotated.
    cohorts: Arc<Mutex<HashMap<String, CohortState>>>,
    /// Deliberate-rotation audit trail (never silent drift). `std::sync::Mutex`
    /// so the log can be read synchronously from tests/audits.
    rotation_log: Arc<std::sync::Mutex<Vec<RotationEvent>>>,
}

impl fmt::Debug for BrowserPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BrowserPool")
            .field("config", &self.config)
            .field("max_size", &self.config.max_size)
            .finish_non_exhaustive()
    }
}

impl BrowserPool {
    /// Create a new browser pool with the given configuration.
    ///
    /// Instances are created lazily on first `acquire()` -- no browsers
    /// are launched at construction time.
    pub async fn new(config: PoolConfig) -> Result<Self, BrowserError> {
        let max_size = config.max_size;
        if max_size == 0 {
            return Err(BrowserError::PoolError(
                "max_size must be at least 1".to_string(),
            ));
        }

        let mut instances = Vec::with_capacity(max_size);
        for _ in 0..max_size {
            instances.push(None);
        }

        Ok(Self {
            config,
            instances: Arc::new(Mutex::new(instances)),
            semaphore: Arc::new(Semaphore::new(max_size)),
            stats: Arc::new(PoolStats::new()),
            scaling: None,
            target_size: Arc::new(AtomicU32::new(max_size as u32)),
            cohort_policy: CohortPolicy::default(),
            cohorts: Arc::new(Mutex::new(HashMap::new())),
            rotation_log: Arc::new(std::sync::Mutex::new(Vec::new())),
        })
    }

    /// Enable autoscaling with `policy` for this pool (builder-style).
    ///
    /// When `policy.enabled` is `true` the pool's target size is set to
    /// `policy.min_size` and [`Self::autoscale`] / [`Self::scale_up`] can grow
    /// it beyond `max_size` (up to `hard_cap`). When disabled the pool keeps
    /// its fixed `max_size` fallback.
    pub fn with_scaling(mut self, policy: ScalingPolicy) -> Self {
        let target = if policy.enabled {
            policy.min_size.max(1) as u32
        } else {
            self.config.max_size as u32
        };
        self.scaling = Some(policy);
        self.target_size.store(target, Ordering::Relaxed);
        self
    }

    // -----------------------------------------------------------------------
    // Cohort fingerprint assignment (R-7): one coherent family per task class,
    // deliberate rotation only.
    // -----------------------------------------------------------------------

    /// Set the cohort fingerprint policy (builder-style).
    ///
    /// The default policy already implements R-7 (declared-bot posture for
    /// public scraping, per-cohort stability); use this to grant specific task
    /// classes a stealth posture or switch to per-run rotation.
    pub fn with_cohorts(mut self, policy: CohortPolicy) -> Self {
        self.cohort_policy = policy;
        self
    }

    /// Read-only access to the cohort policy.
    pub fn cohort_policy(&self) -> &CohortPolicy {
        &self.cohort_policy
    }

    /// Assign — or fetch — the coherent cohort profile for `task_class`.
    ///
    /// The first call for a class creates the cohort (epoch `0`); every later
    /// call returns the *same* profile, so all browsers serving a task class
    /// present one coherent family and attributes are never mixed (uniformity
    /// over randomization). The profile changes only via
    /// [`Self::rotate_cohort`] or, under [`RotationPolicy::PerRun`],
    /// [`Self::begin_run`] — never silently per acquire.
    pub async fn cohort_for(&self, task_class: &str) -> CohortAssignment {
        let mut cohorts = self.cohorts.lock().await;
        let entry = cohorts
            .entry(task_class.to_string())
            .or_insert_with(|| self.fresh_cohort(task_class));
        cohort_view(task_class, entry)
    }

    /// Mark the start of a new run for `task_class`.
    ///
    /// Under [`RotationPolicy::PerRun`] a stealth cohort re-rolls its
    /// identity-only fields (family stays fixed — no cross-family mixing) and
    /// the rotation is recorded with reason `"run boundary"`. Under
    /// [`RotationPolicy::PerCohort`] this is a no-op: stability is the point.
    /// Declared-bot cohorts keep the declared identity pinned under both
    /// policies — an announcement that silently changes is drift, and the
    /// declared identity is the constant that makes the cohort honest.
    pub async fn begin_run(&self, task_class: &str) -> CohortAssignment {
        let mut cohorts = self.cohorts.lock().await;
        // A freshly created cohort's first run is not a rotation — it is the
        // initial assignment (epoch 0, nothing logged).
        let is_new = !cohorts.contains_key(task_class);
        let entry = cohorts
            .entry(task_class.to_string())
            .or_insert_with(|| self.fresh_cohort(task_class));
        if !is_new
            && self.cohort_policy.rotation == RotationPolicy::PerRun
            && entry.posture == CohortPosture::Stealth
        {
            // Identity-only roll (timezone, canvas seed, languages, …): the
            // engine-consistent family fields stay untouched.
            entry.profile.randomize();
            self.bump_epoch(task_class, entry, "run boundary");
        }
        cohort_view(task_class, entry)
    }

    /// Deliberately rotate a cohort's profile.
    ///
    /// The rotation is recorded with the caller's `reason`, so every profile
    /// change is traceable. Stealth cohorts re-roll identity-only fields;
    /// declared-bot cohorts keep the pinned honest identity (nothing to hide,
    /// nothing to rotate — the epoch still advances so the call is visible).
    pub async fn rotate_cohort(
        &self,
        task_class: &str,
        reason: impl Into<String>,
    ) -> CohortAssignment {
        let reason = reason.into();
        let mut cohorts = self.cohorts.lock().await;
        let entry = cohorts
            .entry(task_class.to_string())
            .or_insert_with(|| self.fresh_cohort(task_class));
        if entry.posture == CohortPosture::Stealth {
            entry.profile.randomize();
        }
        self.bump_epoch(task_class, entry, &reason);
        cohort_view(task_class, entry)
    }

    /// The deliberate-rotation audit trail, oldest first.
    pub fn rotation_log(&self) -> Vec<RotationEvent> {
        self.rotation_log
            .lock()
            .map(|log| log.clone())
            .unwrap_or_default()
    }

    /// Number of task-class cohorts currently registered.
    pub async fn cohort_count(&self) -> usize {
        self.cohorts.lock().await.len()
    }

    /// Build the initial state for a task class per the cohort policy.
    fn fresh_cohort(&self, task_class: &str) -> CohortState {
        let posture = self.cohort_policy.posture_for(task_class);
        let profile = match posture {
            CohortPosture::DeclaredBot => {
                declared_bot_profile(&self.cohort_policy.declared_bot)
            }
            CohortPosture::Stealth => self.cohort_policy.stealth_profile_for(task_class),
        };
        let family = ProfileFamily::of(&profile);
        CohortState {
            posture,
            family,
            profile,
            epoch: 0,
        }
    }

    /// Advance a cohort's epoch and record the rotation.
    fn bump_epoch(&self, task_class: &str, state: &mut CohortState, reason: &str) {
        state.epoch += 1;
        if let Ok(mut log) = self.rotation_log.lock() {
            log.push(RotationEvent {
                task_class: task_class.to_string(),
                epoch: state.epoch,
                reason: reason.to_string(),
            });
        }
    }

    /// Acquire a browser instance from the pool.
    ///
    /// Blocks until a semaphore permit is available (i.e., pool is not full).
    /// Finds an idle instance or launches a new one in an empty slot.
    /// Health-checks idle instances before returning them.
    pub async fn acquire(&self) -> Result<PoolHandle, BrowserError> {
        // Acquire semaphore permit (blocks if all slots are busy)
        let permit = Arc::clone(&self.semaphore)
            .acquire_owned()
            .await
            .map_err(|_| BrowserError::PoolExhausted)?;

        let mut instances = self.instances.lock().await;

        // First: try to find an Idle instance
        let mut idle_index = None;
        for (i, slot) in instances.iter().enumerate() {
            if let Some(inst) = slot {
                if inst.state == BrowserState::Idle {
                    idle_index = Some(i);
                    break;
                }
            }
        }

        if let Some(idx) = idle_index {
            // Health-check the idle instance
            let healthy = {
                let inst = instances[idx].as_ref().unwrap();
                Self::check_health(inst).await
            };

            if healthy {
                // Mark as Active and return
                let inst = instances[idx].as_mut().unwrap();
                inst.state = BrowserState::Active;
                self.stats.active.fetch_add(1, Ordering::Relaxed);
                self.stats.idle.fetch_sub(1, Ordering::Relaxed);

                return Ok(PoolHandle {
                    client: inst.client.clone(),
                    session_id: inst.session_id.clone(),
                    index: idx,
                    cohort: None,
                    _permit: permit,
                });
            } else {
                // Instance is dead -- mark as crashed and replace
                let inst = instances[idx].as_mut().unwrap();
                inst.state = BrowserState::Crashed;
                self.stats.idle.fetch_sub(1, Ordering::Relaxed);
                self.stats.crashed.fetch_add(1, Ordering::Relaxed);

                // Kill and clear the slot
                instances[idx].as_mut().unwrap().process.kill();
                instances[idx] = None;
                self.stats.crashed.fetch_sub(1, Ordering::Relaxed);

                // Launch replacement
                let new_inst = self.launch_instance(idx).await?;
                let handle = PoolHandle {
                    client: new_inst.client.clone(),
                    session_id: new_inst.session_id.clone(),
                    index: idx,
                    cohort: None,
                    _permit: permit,
                };
                instances[idx] = Some(new_inst);
                self.stats.active.fetch_add(1, Ordering::Relaxed);
                return Ok(handle);
            }
        }

        // No idle instance found -- find an empty slot and launch a new browser
        let empty_index = instances.iter().position(|slot| slot.is_none());
        if let Some(idx) = empty_index {
            // Autoscaling backpressure: when enabled, do not launch beyond the
            // current target size. High demand is met by raising the target via
            // `autoscale()` (driven by the scheduler on a tick), not by
            // blowing past `target_size`. Returns `PoolExhausted` as the
            // backpressure signal so callers can trigger a scale-up and retry.
            if self.is_scaling_enabled() {
                let live = instances.iter().filter(|s| s.is_some()).count();
                let target = self.target_size.load(Ordering::Relaxed) as usize;
                if live >= target && target < self.hard_cap() {
                    return Err(BrowserError::PoolExhausted);
                }
            }
            let new_inst = self.launch_instance(idx).await?;
            let handle = PoolHandle {
                client: new_inst.client.clone(),
                session_id: new_inst.session_id.clone(),
                index: idx,
                cohort: None,
                _permit: permit,
            };
            instances[idx] = Some(new_inst);
            self.stats.active.fetch_add(1, Ordering::Relaxed);
            return Ok(handle);
        }

        // Should not reach here (semaphore guarantees a slot), but be safe
        drop(instances);
        Err(BrowserError::PoolExhausted)
    }

    /// Acquire a browser for `task_class`, tagged with the cohort's coherent
    /// profile (R-7).
    ///
    /// This is the cohort-aware acquire: the returned handle carries the one
    /// profile every browser of the cohort presents, so the caller applies
    /// exactly that identity — never a per-launch random one. The instance
    /// slot is also stamped with the task class
    /// (see [`Self::instance_cohorts`]) so an audit can tell which cohort a
    /// live browser last served.
    pub async fn acquire_for(&self, task_class: &str) -> Result<PoolHandle, BrowserError> {
        let cohort = self.cohort_for(task_class).await;
        let mut handle = self.acquire().await?;
        {
            let mut instances = self.instances.lock().await;
            if let Some(Some(inst)) = instances.get_mut(handle.index) {
                inst.cohort = Some(task_class.to_string());
            }
        }
        handle.cohort = Some(cohort);
        Ok(handle)
    }

    /// Release a browser instance back to the pool.
    ///
    /// If `recycle_on_release` is enabled, clears cookies and cache.
    /// If the instance has completed `max_tasks_per_instance` tasks,
    /// the instance is retired (killed) and the slot is cleared for
    /// a fresh browser on next acquire.
    pub async fn release(&self, index: usize) -> Result<(), BrowserError> {
        let mut instances = self.instances.lock().await;

        let slot = instances.get_mut(index).ok_or_else(|| {
            BrowserError::PoolError(format!("invalid pool index: {index}"))
        })?;

        let inst = match slot {
            Some(inst) => inst,
            None => return Ok(()), // Already cleared
        };

        // Increment tasks completed
        inst.tasks_completed += 1;
        self.stats.total_tasks.fetch_add(1, Ordering::Relaxed);

        // Recycle: clear cookies and cache
        if self.config.recycle_on_release {
            // Best-effort: don't fail release if recycling fails
            let _ = inst
                .client
                .send_command("Network.clearBrowserCookies", None)
                .await;
            let _ = inst
                .client
                .send_command("Network.clearBrowserCache", None)
                .await;
            self.stats.total_recycled.fetch_add(1, Ordering::Relaxed);
        }

        // Check if instance should be retired
        if inst.tasks_completed >= self.config.max_tasks_per_instance {
            inst.process.kill();
            *slot = None;
            self.stats.active.fetch_sub(1, Ordering::Relaxed);
            // Slot is now empty -- next acquire will create a fresh instance
            return Ok(());
        }

        // Mark as idle
        inst.state = BrowserState::Idle;
        self.stats.active.fetch_sub(1, Ordering::Relaxed);
        self.stats.idle.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Check if a pooled browser instance is still alive.
    ///
    /// Sends `Browser.getVersion` with a 2-second timeout.
    async fn check_health(instance: &PooledBrowser) -> bool {
        let client = instance.client.clone();
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(2),
            client.send_command("Browser.getVersion", None),
        )
        .await;

        matches!(result, Ok(Ok(_)))
    }

    /// Replace a crashed browser instance at the given index.
    ///
    /// Kills the old process, launches a new browser in the same slot
    /// with the same proxy assignment.
    pub async fn replace_crashed(&self, index: usize) -> Result<(), BrowserError> {
        let mut instances = self.instances.lock().await;

        let slot = instances.get_mut(index).ok_or_else(|| {
            BrowserError::PoolError(format!("invalid pool index: {index}"))
        })?;

        // Kill old process if present
        if let Some(inst) = slot {
            inst.process.kill();
            if inst.state == BrowserState::Crashed {
                self.stats.crashed.fetch_sub(1, Ordering::Relaxed);
            } else {
                // Adjust whatever state it was in
                match inst.state {
                    BrowserState::Idle => {
                        self.stats.idle.fetch_sub(1, Ordering::Relaxed);
                    }
                    BrowserState::Active => {
                        self.stats.active.fetch_sub(1, Ordering::Relaxed);
                    }
                    _ => {}
                }
            }
        }

        // Clear slot and launch fresh instance
        *slot = None;
        let new_inst = self.launch_instance(index).await?;
        *slot = Some(new_inst);
        self.stats.idle.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }

    /// Return a snapshot of current pool statistics.
    pub fn stats(&self) -> PoolSnapshot {
        PoolSnapshot {
            active: self.stats.active.load(Ordering::Relaxed),
            idle: self.stats.idle.load(Ordering::Relaxed),
            crashed: self.stats.crashed.load(Ordering::Relaxed),
            total_tasks: self.stats.total_tasks.load(Ordering::Relaxed),
            total_created: self.stats.total_created.load(Ordering::Relaxed),
            total_recycled: self.stats.total_recycled.load(Ordering::Relaxed),
            max_size: self.config.max_size,
        }
    }

    /// Returns `true` when autoscaling is enabled for this pool.
    pub fn is_scaling_enabled(&self) -> bool {
        self.scaling.as_ref().map(|s| s.enabled).unwrap_or(false)
    }

    /// Absolute hard ceiling on pool size. With autoscaling disabled this is
    /// the fixed [`PoolConfig::max_size`].
    pub fn hard_cap(&self) -> usize {
        match &self.scaling {
            Some(p) if p.enabled => p.hard_cap,
            _ => self.config.max_size,
        }
    }

    /// Lower bound the pool never shrinks below (autoscaling only).
    pub fn min_size(&self) -> usize {
        match &self.scaling {
            Some(p) if p.enabled => p.min_size.max(1),
            _ => self.config.max_size,
        }
    }

    /// Largest size autoscaling may grow to (autoscaling only).
    pub fn autoscale_max(&self) -> usize {
        match &self.scaling {
            Some(p) if p.enabled => p.autoscale_max.min(p.hard_cap),
            _ => self.config.max_size,
        }
    }

    /// Current target pool size (equals `max_size` when autoscaling is off).
    pub fn target_size(&self) -> usize {
        self.target_size.load(Ordering::Relaxed) as usize
    }

    /// Number of currently materialized (launched) browser instances.
    ///
    /// Public introspection helper; internal scale logic computes the live
    /// count inline to avoid double-locking the instance mutex.
    #[allow(dead_code)]
    async fn live_count(&self) -> usize {
        let instances = self.instances.lock().await;
        instances.iter().filter(|s| s.is_some()).count()
    }

    /// Grow the pool by `step` instances, up to `autoscale_max`/`hard_cap`.
    ///
    /// Grows the instance vector and semaphore capacity so [`Self::acquire`]
    /// can launch more browsers. Returns the new target size. No-op (returns
    /// current target) when autoscaling is disabled — the fixed `max_size`
    /// fallback applies.
    pub async fn scale_up(&self, step: usize) -> usize {
        let cap = self.autoscale_max();
        let current = self.target_size.load(Ordering::Relaxed) as usize;
        let next = current.saturating_add(step).min(cap);
        if next <= current {
            return current;
        }
        let added = next - current;

        let mut instances = self.instances.lock().await;
        self.semaphore.add_permits(added);
        for _ in 0..added {
            instances.push(None);
        }
        self.target_size.store(next as u32, Ordering::Relaxed);
        next
    }

    /// Shrink the pool toward `min_size` by a multiplicative `factor`,
    /// killing idle instances first (active instances are never interrupted).
    ///
    /// Returns the new target size. No-op when autoscaling is disabled.
    pub async fn scale_down(&self, factor: f64) -> usize {
        let min_size = self.min_size();
        let current = self.target_size.load(Ordering::Relaxed) as usize;
        let mut next = ((current as f64) * factor).floor() as usize;
        if next < min_size {
            next = min_size;
        }
        if next >= current {
            return current;
        }

        let mut instances = self.instances.lock().await;
        let mut live = instances.iter().filter(|s| s.is_some()).count();
        // Kill idle instances (from the tail) until the live count <= target.
        for slot in instances.iter_mut().rev() {
            if live <= next {
                break;
            }
            if let Some(inst) = slot {
                if inst.state == BrowserState::Idle {
                    inst.process.kill();
                    *slot = None;
                    self.stats.idle.fetch_sub(1, Ordering::Relaxed);
                    live -= 1;
                }
            }
        }
        self.target_size.store(next as u32, Ordering::Relaxed);
        next
    }

    /// Inspect a [`LoadSignal`] and grow or shrink the pool toward the target.
    ///
    /// Growth is gated on **both** high demand **and** sufficient CPU/memory
    /// headroom; the pool never exceeds `autoscale_max`/`hard_cap`. Shrinking
    /// drives the pool toward `min_size` when demand is low. Decision logic
    /// mirrors `perf_engine::AdaptiveConcurrency` (AIMD): additive increase in
    /// steps, multiplicative decrease by a factor. Returns the new target size.
    ///
    /// No-op when autoscaling is disabled (returns the fixed target).
    pub async fn autoscale(&self, load: LoadSignal) -> usize {
        let Some(policy) = self.scaling.clone() else {
            return self.target_size.load(Ordering::Relaxed) as usize;
        };
        if !policy.enabled {
            return self.target_size.load(Ordering::Relaxed) as usize;
        }

        let current = self.target_size.load(Ordering::Relaxed) as usize;
        let demand = load.in_flight.saturating_add(load.queue_depth) as f32;
        let demand_ratio = demand / current.max(1) as f32;

        // Unknown headroom (NaN) is treated as *sufficient* so a probe failure
        // never stalls growth; only a measured deficit blocks scale-up.
        let cpu_ok =
            load.cpu_headroom.is_nan() || load.cpu_headroom >= policy.cpu_headroom_ratio;
        let mem_ok =
            load.mem_headroom.is_nan() || load.mem_headroom >= policy.mem_headroom_ratio;

        if demand_ratio >= policy.scale_up_threshold && cpu_ok && mem_ok && current < policy.autoscale_max {
            self.scale_up(policy.increase_step).await
        } else if demand_ratio <= policy.scale_down_threshold && current > policy.min_size {
            self.scale_down(policy.decrease_factor).await
        } else {
            current
        }
    }

    /// Shut down the pool, killing all browser processes.
    pub async fn shutdown(&self) -> Result<(), BrowserError> {
        let mut instances = self.instances.lock().await;
        for slot in instances.iter_mut() {
            if let Some(inst) = slot {
                inst.process.kill();
            }
            *slot = None;
        }
        self.stats.active.store(0, Ordering::Relaxed);
        self.stats.idle.store(0, Ordering::Relaxed);
        self.stats.crashed.store(0, Ordering::Relaxed);
        Ok(())
    }

    /// Check health of all non-empty instances.
    ///
    /// Returns a list of `(index, healthy)` pairs.
    pub async fn health_check_all(&self) -> Vec<(usize, bool)> {
        let instances = self.instances.lock().await;
        let mut results = Vec::new();

        for (i, slot) in instances.iter().enumerate() {
            if let Some(inst) = slot {
                let healthy = Self::check_health(inst).await;
                results.push((i, healthy));
            }
        }

        results
    }

    /// Get the proxy assigned to a given pool index.
    ///
    /// Returns `None` if no proxies are configured.
    /// Uses round-robin: `proxies[index % proxies.len()]`.
    pub fn proxy_for_index(&self, index: usize) -> Option<String> {
        // Layer 4 (ProxyPool, tiered rotation) takes priority over Layer 1
        // (static proxies). The ProxyPool resolves the best-tier proxy for a
        // synthetic routing domain; its sticky-session state is guarded by the
        // std Mutex.
        if let Some(pool) = &self.config.proxy_pool {
            if let Ok(mut guard) = pool.lock() {
                if let Some(entry) = guard.get_proxy("__resolve__") {
                    return Some(entry.url.clone());
                }
            }
        }
        if self.config.proxies.is_empty() {
            None
        } else {
            Some(self.config.proxies[index % self.config.proxies.len()].clone())
        }
    }

    /// Async alias for [`Self::proxy_for_index`] — resolves the proxy for an
    /// instance index, preferring the ProxyPool (Layer 4) over the static list
    /// (Layer 1). Returns `None` for a direct connection.
    ///
    /// A configured [`PoolConfig::proxy_mint`] wins over both: it is consulted
    /// HERE, on the launch path, so every launch gets a fresh identity, and
    /// deliberately not in `proxy_for_index`, so a reporting call never burns
    /// one.
    pub async fn resolve_proxy(&self, index: usize) -> Option<String> {
        if let Some(mint) = &self.config.proxy_mint {
            return mint.get(index);
        }
        self.proxy_for_index(index)
    }

    /// Return the proxy assignment for each occupied instance slot.
    pub async fn instance_proxies(&self) -> Vec<(usize, Option<String>)> {
        let instances = self.instances.lock().await;
        let mut result = Vec::new();
        for (i, slot) in instances.iter().enumerate() {
            if slot.is_some() {
                result.push((i, self.proxy_for_index(i)));
            }
        }
        result
    }

    /// Task-class commitment per live instance slot (`(index, task_class)`).
    ///
    /// The cohort bookkeeping side of R-7: shows which cohort each materialized
    /// browser last served (`None` = not yet acquired via
    /// [`Self::acquire_for`]).
    pub async fn instance_cohorts(&self) -> Vec<(usize, Option<String>)> {
        let instances = self.instances.lock().await;
        let mut result = Vec::new();
        for (i, slot) in instances.iter().enumerate() {
            if let Some(inst) = slot {
                result.push((i, inst.cohort.clone()));
            }
        }
        result
    }

    // -----------------------------------------------------------------------
    // Flat session management (Phase 48-01)
    // -----------------------------------------------------------------------

    /// Create multiple tabs (flat sessions) within a single browser instance.
    ///
    /// Instead of launching N browser processes, creates N targets within
    /// a single browser. Each target gets its own flat CDP session multiplexed
    /// over one WebSocket connection. Supports 50+ tabs per browser.
    ///
    /// Returns a Vec of `(session_id, target_id)` pairs.
    pub async fn create_flat_sessions(
        &self,
        count: usize,
        context_id: Option<&str>,
    ) -> Result<Vec<(String, String)>, BrowserError> {
        if count == 0 {
            return Ok(Vec::new());
        }

        let instances = self.instances.lock().await;
        let active_inst = instances
            .iter()
            .find_map(|slot| slot.as_ref())
            .ok_or_else(|| {
                BrowserError::PoolError(
                    "no browser instances available for flat sessions".to_string(),
                )
            })?;

        let client = active_inst.client.clone();
        drop(instances);

        client.enable_auto_attach_flat().await?;

        let mut sessions = Vec::with_capacity(count);
        for _ in 0..count {
            let target_id = if let Some(ctx) = context_id {
                client
                    .create_target_in_context("about:blank", ctx)
                    .await?
            } else {
                let result = client
                    .send_command(
                        "Target.createTarget",
                        Some(serde_json::json!({"url": "about:blank"})),
                    )
                    .await?;
                result
                    .get("targetId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string()
            };

            let session_id = client.attach_flat(&target_id).await?;
            sessions.push((session_id, target_id));
        }

        Ok(sessions)
    }

    /// Create an isolated browser context with optional proxy for flat sessions.
    ///
    /// This combines `create_browser_context_with_proxy` with the pool's
    /// first available browser instance.
    pub async fn create_isolated_context(
        &self,
        proxy_server: Option<&str>,
    ) -> Result<String, BrowserError> {
        let instances = self.instances.lock().await;
        let active_inst = instances
            .iter()
            .find_map(|slot| slot.as_ref())
            .ok_or_else(|| {
                BrowserError::PoolError(
                    "no browser instances available for context creation".to_string(),
                )
            })?;
        let client = active_inst.client.clone();
        drop(instances);

        client.create_browser_context_with_proxy(proxy_server).await
    }

    /// Launch a new browser instance for the given pool index.
    ///
    /// Applies proxy routing if proxies are configured.
    async fn launch_instance(&self, index: usize) -> Result<PooledBrowser, BrowserError> {
        // Route egress through `resolve_proxy` (ProxyPool -> static proxies ->
        // direct) and apply it to `BrowserConfig.proxy` — the field
        // `BrowserProcess::launch` translates into Chrome's `--proxy-server`
        // flag (process.rs), matching the repro_proxy pattern of setting
        // `config.proxy` and never pushing a reserved `--proxy-server` arg
        // into `config.args`. Per-call `stealth` from the `BrowserPool.create`
        // egress map rides along on the base `browser_config`.
        let proxy = self.resolve_proxy(index).await;
        let config = Self::instance_launch_config(&self.config.browser_config, proxy.as_deref());

        // Launch browser process
        let process = BrowserProcess::launch(&config)?;

        // Connect CDP client
        let client = CdpClient::connect(&process.ws_url).await?;

        // Create a default page and get session
        let page = client.create_page(None).await?;
        let session_id = page.session_id.clone();

        self.stats.total_created.fetch_add(1, Ordering::Relaxed);

        Ok(PooledBrowser {
            process,
            client,
            session_id,
            state: BrowserState::Active,
            tasks_completed: 0,
            proxy,
            cohort: None,
            index,
        })
    }

    /// Per-instance `BrowserConfig` for a resolved proxy (or `None` = direct).
    ///
    /// `proxy` lands in `config.proxy` — the field `BrowserProcess::launch`
    /// turns into Chrome's `--proxy-server` flag (process.rs) — rather than in
    /// `config.args`, so the per-pool egress selected by `BrowserPool.create`'s
    /// egress map (or the `TALLOW_PROXY`/`TALLOW_TOR` fallback) reaches Chrome
    /// through the validated field. Per-call `stealth` from the map rides along
    /// on the cloned base config. Exposed `pub(crate)` so tests can assert the
    /// map -> `config.proxy` plumbing without launching a browser.
    pub(crate) fn instance_launch_config(base: &BrowserConfig, proxy: Option<&str>) -> BrowserConfig {
        let mut config = base.clone();
        if let Some(url) = proxy {
            config.proxy = Some(url.to_string());
        }
        config
    }

    /// Read-only access to the pool configuration.
    ///
    /// In-crate tests use this to assert that the per-call egress map passed
    /// to `BrowserPool.create` reached `PoolConfig.proxies`/`proxy_pool` and
    /// `browser_config.stealth` end-to-end.
    #[cfg(test)]
    pub(crate) fn config_for_test(&self) -> &PoolConfig {
        &self.config
    }
}

/// Best-effort sample of the host's current CPU and memory headroom.
///
/// Reads Linux `/proc/stat` and `/proc/meminfo`. Returns `(cpu, mem)` ratios
/// in `[0.0, 1.0]` (`1.0` = fully idle / plenty of memory). Either (or both)
/// may be `None` when the host doesn't expose procfs (non-Linux) or on parse
/// failure — callers should treat `None` as "unknown = sufficient" so a probe
/// failure never stalls autoscaling.
pub fn system_headroom() -> (Option<f32>, Option<f32>) {
    (read_cpu_headroom(), read_mem_headroom())
}

/// Fraction of the CPU that is idle (from `/proc/stat`), `None` if unavailable.
fn read_cpu_headroom() -> Option<f32> {
    let data = std::fs::read_to_string("/proc/stat").ok()?;
    let line = data.lines().next()?;
    let fields: Vec<u64> = line
        .split_whitespace()
        .skip(1) // skip the "cpu" label
        .filter_map(|s| s.parse().ok())
        .collect();
    let total: u64 = fields.iter().sum();
    if total == 0 {
        return None;
    }
    // /proc/stat "cpu" ordering: user nice system idle iowait irq softirq steal ...
    let idle = fields.get(3).copied().unwrap_or(0) + fields.get(4).copied().unwrap_or(0);
    Some((idle as f32) / (total as f32))
}

/// Fraction of memory available (from `/proc/meminfo`), `None` if unavailable.
fn read_mem_headroom() -> Option<f32> {
    let data = std::fs::read_to_string("/proc/meminfo").ok()?;
    let total = parse_meminfo_kb(&data, "MemTotal")?;
    let avail = parse_meminfo_kb(&data, "MemAvailable")?;
    if total == 0 {
        return None;
    }
    Some((avail as f32) / (total as f32))
}

/// Parse a `key: <value> kB` line from `/proc/meminfo`.
fn parse_meminfo_kb(data: &str, key: &str) -> Option<u64> {
    for line in data.lines() {
        if let Some(rest) = line.strip_prefix(key) {
            let rest = rest.trim_start_matches(':').trim_start();
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enabled_policy() -> ScalingPolicy {
        ScalingPolicy {
            enabled: true,
            min_size: 1,
            autoscale_max: 8,
            hard_cap: 16,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn test_autoscale_disabled_is_noop() {
        let pool = BrowserPool::new(PoolConfig::default()).await.unwrap();
        // Autoscaling disabled by default: fixed max_size fallback.
        assert_eq!(pool.target_size(), 4);
        assert!(!pool.is_scaling_enabled());
        let t = pool
            .autoscale(LoadSignal {
                queue_depth: 50,
                in_flight: 4,
                cpu_headroom: 1.0,
                mem_headroom: 1.0,
            })
            .await;
        assert_eq!(t, 4); // unchanged
        assert_eq!(pool.target_size(), 4);
    }

    #[tokio::test]
    async fn test_scale_up_grows_target_and_respects_cap() {
        let pool = BrowserPool::new(PoolConfig::default())
            .await
            .unwrap()
            .with_scaling(enabled_policy());
        assert_eq!(pool.target_size(), 1); // starts at min_size
        assert_eq!(pool.scale_up(3).await, 4); // additive increase
        assert_eq!(pool.scale_up(100).await, 8); // clamped to autoscale_max
        assert_eq!(pool.target_size(), 8);
        assert_eq!(pool.scale_up(10).await, 8); // no growth past autoscale_max
    }

    #[tokio::test]
    async fn test_scale_down_respects_min_size() {
        let pool = BrowserPool::new(PoolConfig::default())
            .await
            .unwrap()
            .with_scaling(enabled_policy());
        pool.scale_up(7).await; // target 1 -> 8
        assert_eq!(pool.scale_down(0.5).await, 4); // multiplicative decrease
        assert_eq!(pool.scale_down(0.5).await, 2);
        assert_eq!(pool.scale_down(0.5).await, 1); // floored at min_size
        assert_eq!(pool.target_size(), 1);
    }

    #[tokio::test]
    async fn test_autoscale_scales_up_on_high_demand_with_headroom() {
        let pool = BrowserPool::new(PoolConfig::default())
            .await
            .unwrap()
            .with_scaling(enabled_policy());
        let t = pool
            .autoscale(LoadSignal {
                queue_depth: 10,
                in_flight: 0,
                cpu_headroom: 0.9,
                mem_headroom: 0.9,
            })
            .await;
        assert!(t > 1); // grew from min_size
    }

    #[tokio::test]
    async fn test_autoscale_blocked_when_no_headroom() {
        let pool = BrowserPool::new(PoolConfig::default())
            .await
            .unwrap()
            .with_scaling(enabled_policy());
        let t = pool
            .autoscale(LoadSignal {
                queue_depth: 10,
                in_flight: 0,
                cpu_headroom: 0.0, // CPU saturated -> must NOT scale up
                mem_headroom: 1.0,
            })
            .await;
        assert_eq!(t, 1);
        assert_eq!(pool.target_size(), 1);
    }

    #[tokio::test]
    async fn test_autoscale_unknown_headroom_allows_growth() {
        let pool = BrowserPool::new(PoolConfig::default())
            .await
            .unwrap()
            .with_scaling(enabled_policy());
        let t = pool
            .autoscale(LoadSignal {
                queue_depth: 10,
                in_flight: 0,
                cpu_headroom: f32::NAN,
                mem_headroom: f32::NAN,
            })
            .await;
        assert!(t > 1); // unknown headroom treated as sufficient
    }

    #[tokio::test]
    async fn test_autoscale_scales_down_when_idle() {
        let pool = BrowserPool::new(PoolConfig::default())
            .await
            .unwrap()
            .with_scaling(enabled_policy());
        // Grow first.
        pool.autoscale(LoadSignal {
            queue_depth: 10,
            in_flight: 0,
            cpu_headroom: 0.9,
            mem_headroom: 0.9,
        })
        .await;
        assert!(pool.target_size() > 1);
        // Then go idle -> shrink toward min_size.
        let t = pool
            .autoscale(LoadSignal {
                queue_depth: 0,
                in_flight: 0,
                cpu_headroom: 0.9,
                mem_headroom: 0.9,
            })
            .await;
        assert_eq!(t, 1);
    }

    #[tokio::test]
    async fn test_with_scaling_disabled_keeps_max_size() {
        let policy = ScalingPolicy {
            enabled: false,
            ..Default::default()
        };
        let pool = BrowserPool::new(PoolConfig::default())
            .await
            .unwrap()
            .with_scaling(policy);
        assert_eq!(pool.target_size(), 4); // fixed max_size fallback
        assert_eq!(pool.hard_cap(), 4);
    }

    #[test]
    fn test_parse_meminfo_kb() {
        let data = "MemTotal:       16000000 kB\nMemFree:        8000000 kB\nMemAvailable:   12000000 kB\n";
        assert_eq!(parse_meminfo_kb(data, "MemTotal"), Some(16_000_000));
        assert_eq!(parse_meminfo_kb(data, "MemAvailable"), Some(12_000_000));
        assert_eq!(parse_meminfo_kb(data, "Missing"), None);
    }

    #[test]
    fn test_system_headroom_ranges() {
        // On Linux /proc is present; on other hosts it must degrade to None
        // (never panic). Just assert the return is well-formed.
        let (cpu, mem) = system_headroom();
        if let Some(c) = cpu {
            assert!((0.0..=1.0).contains(&c));
        }
        if let Some(m) = mem {
            assert!((0.0..=1.0).contains(&m));
        }
    }

    #[test]
    fn test_pool_config_defaults() {
        let config = PoolConfig::default();
        assert_eq!(config.max_size, 4);
        assert_eq!(config.max_tasks_per_instance, 100);
        assert!(config.recycle_on_release);
        assert!(config.proxies.is_empty());
    }

    #[test]
    fn test_pool_stats_initial_values() {
        let stats = PoolStats::new();
        assert_eq!(stats.active.load(Ordering::Relaxed), 0);
        assert_eq!(stats.idle.load(Ordering::Relaxed), 0);
        assert_eq!(stats.crashed.load(Ordering::Relaxed), 0);
        assert_eq!(stats.total_tasks.load(Ordering::Relaxed), 0);
        assert_eq!(stats.total_created.load(Ordering::Relaxed), 0);
        assert_eq!(stats.total_recycled.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_pool_snapshot_display() {
        let snap = PoolSnapshot {
            active: 2,
            idle: 1,
            crashed: 0,
            total_tasks: 42,
            total_created: 5,
            total_recycled: 3,
            max_size: 4,
        };
        let display = format!("{snap}");
        assert!(display.contains("2/4 active"));
        assert!(display.contains("1 idle"));
        assert!(display.contains("0 crashed"));
        assert!(display.contains("tasks: 42"));
        assert!(display.contains("created: 5"));
        assert!(display.contains("recycled: 3"));
    }

    #[test]
    fn test_proxy_assignment_round_robin() {
        let config = PoolConfig {
            proxies: vec![
                "socks5://proxy-a:1080".to_string(),
                "socks5://proxy-b:1080".to_string(),
                "socks5://proxy-c:1080".to_string(),
            ],
            ..PoolConfig::default()
        };

        // Create a pool config and test proxy_for_index logic directly
        // proxy_for_index uses: proxies[index % proxies.len()]
        let proxies = &config.proxies;
        assert_eq!(proxies[0 % 3], "socks5://proxy-a:1080");
        assert_eq!(proxies[1 % 3], "socks5://proxy-b:1080");
        assert_eq!(proxies[2 % 3], "socks5://proxy-c:1080");
        assert_eq!(proxies[3 % 3], "socks5://proxy-a:1080"); // wraps
        assert_eq!(proxies[4 % 3], "socks5://proxy-b:1080"); // wraps
        assert_eq!(proxies[5 % 3], "socks5://proxy-c:1080"); // wraps
    }

    #[test]
    fn test_browser_state_display() {
        assert_eq!(format!("{}", BrowserState::Idle), "idle");
        assert_eq!(format!("{}", BrowserState::Active), "active");
        assert_eq!(format!("{}", BrowserState::Crashed), "crashed");
    }

    #[test]
    fn test_browser_state_equality() {
        assert_eq!(BrowserState::Idle, BrowserState::Idle);
        assert_ne!(BrowserState::Idle, BrowserState::Active);
        assert_ne!(BrowserState::Active, BrowserState::Crashed);
    }

    #[test]
    fn test_pool_snapshot_all_zeroes() {
        let snap = PoolSnapshot {
            active: 0,
            idle: 0,
            crashed: 0,
            total_tasks: 0,
            total_created: 0,
            total_recycled: 0,
            max_size: 8,
        };
        let display = format!("{snap}");
        assert!(display.contains("0/8 active"));
        assert!(display.contains("0 idle"));
        assert!(display.contains("0 crashed"));
    }

    #[test]
    fn test_pool_config_custom() {
        let config = PoolConfig {
            max_size: 16,
            max_tasks_per_instance: 50,
            browser_config: BrowserConfig::default(),
            proxies: vec!["http://proxy:8080".to_string()],
            proxy_pool: None,
            proxy_mint: None,
            tor_enabled: false,
            tor_instances: 0,
            recycle_on_release: false,
        };
        assert_eq!(config.max_size, 16);
        assert_eq!(config.max_tasks_per_instance, 50);
        assert!(!config.recycle_on_release);
        assert_eq!(config.proxies.len(), 1);
    }

    #[tokio::test]
    async fn test_pool_new_zero_size_errors() {
        let config = PoolConfig {
            max_size: 0,
            ..PoolConfig::default()
        };
        let result = BrowserPool::new(config).await;
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.to_string().contains("max_size must be at least 1"));
    }

    #[tokio::test]
    async fn test_pool_new_initializes_empty_slots() {
        let config = PoolConfig {
            max_size: 3,
            ..PoolConfig::default()
        };
        let pool = BrowserPool::new(config).await.unwrap();
        let instances = pool.instances.lock().await;
        assert_eq!(instances.len(), 3);
        assert!(instances.iter().all(|slot| slot.is_none()));
    }

    #[tokio::test]
    async fn test_pool_stats_snapshot() {
        let config = PoolConfig::default();
        let pool = BrowserPool::new(config).await.unwrap();
        let snap = pool.stats();
        assert_eq!(snap.active, 0);
        assert_eq!(snap.idle, 0);
        assert_eq!(snap.crashed, 0);
        assert_eq!(snap.total_tasks, 0);
        assert_eq!(snap.total_created, 0);
        assert_eq!(snap.total_recycled, 0);
        assert_eq!(snap.max_size, 4);
    }

    /// A configured `proxy_mint` is consulted on the LAUNCH path and wins over
    /// the static list, and each call yields a fresh identity — that freshness
    /// is the whole point (a relaunched slot must not inherit its predecessor's
    /// Tor circuit). `proxy_for_index` (the reporting path) must NOT consult it,
    /// or a status read would burn an identity.
    #[tokio::test]
    async fn test_proxy_mint_wins_on_launch_path_and_stays_fresh() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;

        let calls = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&calls);
        let config = PoolConfig {
            proxies: vec!["socks5://static-a:1080".to_string()],
            proxy_mint: Some(ProxyMint::new(move |i: usize| {
                let n = counter.fetch_add(1, Ordering::SeqCst);
                Some(format!("socks5h://mint-{i}-{n}:tok@127.0.0.1:9050"))
            })),
            ..Default::default()
        };
        let pool = BrowserPool::new(config).await.expect("pool");

        let a = pool.resolve_proxy(0).await.expect("minted url");
        let b = pool.resolve_proxy(0).await.expect("minted url");
        assert!(a.starts_with("socks5h://mint-0-"), "{a}");
        assert_ne!(a, b, "each launch must mint a fresh identity");
        assert_eq!(calls.load(Ordering::SeqCst), 2);

        assert_eq!(
            pool.proxy_for_index(0).as_deref(),
            Some("socks5://static-a:1080"),
            "reporting path still reflects the static configuration"
        );
        assert_eq!(
            calls.load(Ordering::SeqCst),
            2,
            "proxy_for_index must not mint an identity"
        );
    }

    #[tokio::test]
    async fn test_pool_proxy_for_index_no_proxies() {
        let config = PoolConfig::default();
        let pool = BrowserPool::new(config).await.unwrap();
        assert_eq!(pool.proxy_for_index(0), None);
        assert_eq!(pool.proxy_for_index(5), None);
    }

    #[tokio::test]
    async fn test_pool_proxy_for_index_with_proxies() {
        let config = PoolConfig {
            proxies: vec![
                "http://a:8080".to_string(),
                "http://b:8080".to_string(),
                "http://c:8080".to_string(),
            ],
            ..PoolConfig::default()
        };
        let pool = BrowserPool::new(config).await.unwrap();
        assert_eq!(pool.proxy_for_index(0), Some("http://a:8080".to_string()));
        assert_eq!(pool.proxy_for_index(1), Some("http://b:8080".to_string()));
        assert_eq!(pool.proxy_for_index(2), Some("http://c:8080".to_string()));
        assert_eq!(pool.proxy_for_index(3), Some("http://a:8080".to_string())); // wraps
        assert_eq!(pool.proxy_for_index(4), Some("http://b:8080".to_string())); // wraps
        assert_eq!(pool.proxy_for_index(5), Some("http://c:8080".to_string())); // wraps
    }

    #[tokio::test]
    async fn test_pool_shutdown_clears_stats() {
        let config = PoolConfig::default();
        let pool = BrowserPool::new(config).await.unwrap();
        pool.shutdown().await.unwrap();
        let snap = pool.stats();
        assert_eq!(snap.active, 0);
        assert_eq!(snap.idle, 0);
        assert_eq!(snap.crashed, 0);
    }

    #[tokio::test]
    async fn test_pool_instance_proxies_empty() {
        let config = PoolConfig::default();
        let pool = BrowserPool::new(config).await.unwrap();
        let proxies = pool.instance_proxies().await;
        assert!(proxies.is_empty());
    }

    #[test]
    fn test_pool_snapshot_max_size_visible() {
        let snap = PoolSnapshot {
            active: 4,
            idle: 0,
            crashed: 0,
            total_tasks: 100,
            total_created: 8,
            total_recycled: 6,
            max_size: 4,
        };
        // All slots active
        assert_eq!(snap.active, snap.max_size as u32);
        assert_eq!(snap.idle, 0);
        let display = format!("{snap}");
        assert!(display.contains("4/4 active"));
    }

    #[test]
    fn test_pool_config_max_tasks_per_instance() {
        // Verify the default and custom max_tasks_per_instance values
        let default_config = PoolConfig::default();
        assert_eq!(default_config.max_tasks_per_instance, 100);

        let custom_config = PoolConfig {
            max_tasks_per_instance: 2,
            ..PoolConfig::default()
        };
        assert_eq!(custom_config.max_tasks_per_instance, 2);
    }

    #[test]
    fn test_pool_config_recycle_flag() {
        let config_on = PoolConfig {
            recycle_on_release: true,
            ..PoolConfig::default()
        };
        assert!(config_on.recycle_on_release);

        let config_off = PoolConfig {
            recycle_on_release: false,
            ..PoolConfig::default()
        };
        assert!(!config_off.recycle_on_release);
    }

    #[tokio::test]
    async fn test_pool_health_check_all_empty() {
        let config = PoolConfig::default();
        let pool = BrowserPool::new(config).await.unwrap();
        let results = pool.health_check_all().await;
        // No instances launched yet, should be empty
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_pool_release_invalid_index() {
        let config = PoolConfig {
            max_size: 2,
            ..PoolConfig::default()
        };
        let pool = BrowserPool::new(config).await.unwrap();
        // Release index that's out of bounds
        let result = pool.release(10).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid pool index"));
    }

    #[tokio::test]
    async fn test_pool_release_empty_slot_is_ok() {
        let config = PoolConfig {
            max_size: 2,
            ..PoolConfig::default()
        };
        let pool = BrowserPool::new(config).await.unwrap();
        // Releasing an empty slot is a no-op, not an error
        let result = pool.release(0).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_pool_replace_crashed_invalid_index() {
        let config = PoolConfig {
            max_size: 2,
            ..PoolConfig::default()
        };
        let pool = BrowserPool::new(config).await.unwrap();
        let result = pool.replace_crashed(10).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid pool index"));
    }

    #[test]
    fn test_browser_state_copy_clone() {
        let state = BrowserState::Active;
        let copied = state;
        let cloned = state.clone();
        assert_eq!(copied, BrowserState::Active);
        assert_eq!(cloned, BrowserState::Active);
    }

    #[test]
    fn test_pool_snapshot_clone() {
        let snap = PoolSnapshot {
            active: 1,
            idle: 2,
            crashed: 0,
            total_tasks: 10,
            total_created: 3,
            total_recycled: 2,
            max_size: 4,
        };
        let snap2 = snap.clone();
        assert_eq!(snap.active, snap2.active);
        assert_eq!(snap.idle, snap2.idle);
        assert_eq!(snap.max_size, snap2.max_size);
    }

    #[test]
    fn test_proxy_for_index_single_proxy() {
        let config = PoolConfig {
            proxies: vec!["http://only:8080".to_string()],
            ..PoolConfig::default()
        };
        // With single proxy, all indices map to it
        let proxies = &config.proxies;
        assert_eq!(proxies[0 % 1], "http://only:8080");
        assert_eq!(proxies[1 % 1], "http://only:8080");
        assert_eq!(proxies[99 % 1], "http://only:8080");
    }

    // -----------------------------------------------------------------------
    // Phase 48-01: Flat session management tests
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn test_create_flat_sessions_zero_count() {
        let config = PoolConfig::default();
        let pool = BrowserPool::new(config).await.unwrap();
        let result = pool.create_flat_sessions(0, None).await;
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[tokio::test]
    async fn test_create_flat_sessions_no_instances_errors() {
        let config = PoolConfig::default();
        let pool = BrowserPool::new(config).await.unwrap();
        let result = pool.create_flat_sessions(5, None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no browser instances available"));
    }

    #[tokio::test]
    async fn test_create_isolated_context_no_instances_errors() {
        let config = PoolConfig::default();
        let pool = BrowserPool::new(config).await.unwrap();
        let result = pool.create_isolated_context(None).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("no browser instances available"));
    }

    #[tokio::test]
    async fn test_create_isolated_context_with_proxy_no_instances() {
        let config = PoolConfig::default();
        let pool = BrowserPool::new(config).await.unwrap();
        let result = pool
            .create_isolated_context(Some("socks5://proxy:1080"))
            .await;
        assert!(result.is_err());
    }

    // -----------------------------------------------------------------------
    // Roadmap #6: per-call egress/stealth (map -> resolve_proxy ->
    // BrowserConfig.proxy / stealth plumbing)
    // -----------------------------------------------------------------------

    #[test]
    fn test_instance_launch_config_proxy_goes_to_config_proxy_not_args() {
        // The `BrowserPool.create` egress map's proxy must reach
        // `BrowserConfig.proxy` (the field process.rs turns into Chrome's
        // `--proxy-server` flag) — repro_proxy style — and never a reserved
        // `--proxy-server` flag inside `config.args`.
        let base = BrowserConfig {
            stealth: true,
            ..BrowserConfig::default()
        };
        let shaped = BrowserPool::instance_launch_config(&base, Some("http://egress:8080"));
        assert_eq!(shaped.proxy.as_deref(), Some("http://egress:8080"));
        assert!(
            !shaped.args.iter().any(|a| a.contains("--proxy-server")),
            "proxy must ride config.proxy, not args: {:?}",
            shaped.args
        );
        // Stealth from the map's base config is preserved per instance.
        assert!(shaped.stealth);
        assert_eq!(shaped.headless, base.headless);
    }

    #[test]
    fn test_instance_launch_config_direct_keeps_no_proxy() {
        let base = BrowserConfig {
            stealth: false,
            ..BrowserConfig::default()
        };
        let shaped = BrowserPool::instance_launch_config(&base, None);
        assert_eq!(shaped.proxy, None);
        assert!(!shaped.stealth);
    }

    #[tokio::test]
    async fn test_pool_config_from_egress_map_resolves_to_proxy() {
        // Mirror exactly what interp.rs "BrowserPool.create" builds from the
        // optional egress map `{proxy, stealth, tier}`: the URL lands in both
        // the static `proxies` list and the tiered ProxyPool (Layer 4 wins in
        // resolve_proxy), while stealth rides on the per-instance config.
        let mut pp = super::super::proxy::ProxyPool::new();
        pp.add(super::super::proxy::ProxyEntry::new(
            "http://egress:8080",
            super::super::proxy::ProxyTier::Datacenter,
        ));
        let config = PoolConfig {
            browser_config: BrowserConfig {
                stealth: true,
                ..BrowserConfig::default()
            },
            proxies: vec!["http://egress:8080".to_string()],
            proxy_pool: Some(Arc::new(std::sync::Mutex::new(pp))),
            ..PoolConfig::default()
        };
        let pool = BrowserPool::new(config).await.unwrap();

        // resolve_proxy (the cascade launch_instance consults) yields the
        // map's proxy…
        assert_eq!(
            pool.resolve_proxy(0).await.as_deref(),
            Some("http://egress:8080")
        );
        // …and launch-time config shaping puts it in config.proxy with the
        // map's stealth intact.
        let cfg = pool.config_for_test();
        assert_eq!(cfg.browser_config.stealth, true);
        assert_eq!(
            BrowserPool::instance_launch_config(
                &cfg.browser_config,
                pool.resolve_proxy(0).await.as_deref(),
            )
            .proxy
            .as_deref(),
            Some("http://egress:8080")
        );
    }

    #[tokio::test]
    async fn test_pool_direct_default_resolves_none() {
        // No egress map, no env: the pool is DIRECT (resolve_proxy -> None),
        // which is the leak-risk default the create-site warning flags unless
        // the caller explicitly chose tier:"direct".
        let config = PoolConfig::default();
        let pool = BrowserPool::new(config).await.unwrap();
        assert_eq!(pool.resolve_proxy(0).await, None);
        let shaped = BrowserPool::instance_launch_config(
            &pool.config_for_test().browser_config,
            None,
        );
        assert_eq!(shaped.proxy, None);
    }

    // -----------------------------------------------------------------------
    // R-7: cohort fingerprint identity — declared-bot default, coherent family
    // per task class, deliberate rotation only
    // -----------------------------------------------------------------------

    #[test]
    fn test_declared_bot_ua_format() {
        let identity = DeclaredBotIdentity {
            version: "9.9.9".to_string(),
            contact: "ops@example.com".to_string(),
        };
        assert_eq!(
            identity.user_agent(),
            "TallowScraper/9.9.9 (+ops@example.com)"
        );
        // No contact configured -> bare product token, still declared.
        let bare = DeclaredBotIdentity {
            version: "1.0.0".to_string(),
            contact: String::new(),
        };
        assert_eq!(bare.user_agent(), "TallowScraper/1.0.0");
    }

    #[test]
    fn test_declared_bot_identity_defaults_and_env_contact() {
        let _guard = crate::runtime::egress_http::env_lock();
        let prior = std::env::var("TALLOW_BOT_CONTACT").ok();

        // Unset -> built-in contact, crate version.
        unsafe { std::env::remove_var("TALLOW_BOT_CONTACT") };
        let identity = DeclaredBotIdentity::default();
        assert_eq!(identity.version, env!("CARGO_PKG_VERSION"));
        assert_eq!(identity.contact, DEFAULT_BOT_CONTACT);

        // Operator contact wins (trimmed); blank falls back.
        unsafe { std::env::set_var("TALLOW_BOT_CONTACT", "  https://ops.example/bot  ") };
        let custom = DeclaredBotIdentity::default();
        assert_eq!(custom.contact, "https://ops.example/bot");

        unsafe { std::env::set_var("TALLOW_BOT_CONTACT", "   ") };
        assert_eq!(DeclaredBotIdentity::default().contact, DEFAULT_BOT_CONTACT);

        match prior {
            Some(v) => unsafe { std::env::set_var("TALLOW_BOT_CONTACT", v) },
            None => unsafe { std::env::remove_var("TALLOW_BOT_CONTACT") },
        }
    }

    #[test]
    fn test_declared_bot_profile_declares_itself_and_is_coherent() {
        let identity = DeclaredBotIdentity {
            version: "9.9.9".to_string(),
            contact: "ops@example.com".to_string(),
        };
        let profile = declared_bot_profile(&identity);

        // Declared: the UA announces the bot (no human impersonation).
        assert!(profile.user_agent.starts_with("TallowScraper/9.9.9"));
        // Classified into its own family, not any Chrome family.
        assert_eq!(ProfileFamily::of(&profile), ProfileFamily::DeclaredBot);
        // Engine-coherent: no Critical cross-vector contradiction.
        let assignment = CohortAssignment {
            task_class: TASK_CLASS_PUBLIC_SCRAPING.to_string(),
            posture: CohortPosture::DeclaredBot,
            family: ProfileFamily::of(&profile),
            profile,
            epoch: 0,
        };
        assert!(
            assignment.is_coherent(),
            "declared-bot profile must be cross-vector coherent"
        );
    }

    #[test]
    fn test_profile_family_classification_of_builtin_presets() {
        assert_eq!(
            ProfileFamily::of(&StealthProfile::chrome_windows()),
            ProfileFamily::ChromeWindows
        );
        assert_eq!(
            ProfileFamily::of(&StealthProfile::chrome_macos()),
            ProfileFamily::ChromeMacos
        );
        assert_eq!(
            ProfileFamily::of(&StealthProfile::chrome_linux()),
            ProfileFamily::ChromeLinux
        );
        assert_eq!(
            ProfileFamily::of(&StealthProfile::mobile_android()),
            ProfileFamily::MobileAndroid
        );
        assert_eq!(
            ProfileFamily::of(&StealthProfile::mobile_ios()),
            ProfileFamily::MobileIos
        );
        // Firefox flag wins over the UA text (Tor path).
        let mut firefox = StealthProfile::chrome_windows();
        firefox.is_firefox_profile = true;
        firefox.user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
            .to_string();
        assert_eq!(ProfileFamily::of(&firefox), ProfileFamily::TorFirefox);
        // Family ids are stable strings (used in logs/audit).
        assert_eq!(ProfileFamily::DeclaredBot.id(), "declared-bot");
    }

    #[tokio::test]
    async fn test_cohort_default_posture_is_declared_bot_public_scraping() {
        // R-7: public scraping defaults to the honest declared-bot posture —
        // no stealth class was ever granted to it.
        let pool = BrowserPool::new(PoolConfig::default()).await.unwrap();
        let assignment = pool.cohort_for(TASK_CLASS_PUBLIC_SCRAPING).await;
        assert_eq!(assignment.posture, CohortPosture::DeclaredBot);
        assert_eq!(assignment.family, ProfileFamily::DeclaredBot);
        assert_eq!(assignment.epoch, 0);
        assert!(assignment.profile.user_agent.contains("TallowScraper/"));
        assert!(assignment.is_coherent());

        // The declared-bot default is the posture for *unlisted* classes too:
        // stealth is granted, never assumed.
        let other = pool.cohort_for("some-other-class").await;
        assert_eq!(other.posture, CohortPosture::DeclaredBot);
    }

    #[tokio::test]
    async fn test_cohort_is_uniform_across_browsers_of_a_class() {
        // "browsers in one cohort present a coherent family": every read for
        // the same class returns the identical profile — no per-acquire
        // randomization, no attribute mixing.
        let pool = BrowserPool::new(PoolConfig::default()).await.unwrap();
        let first = pool.cohort_for(TASK_CLASS_PUBLIC_SCRAPING).await;
        let second = pool.cohort_for(TASK_CLASS_PUBLIC_SCRAPING).await;
        assert_eq!(first.family, second.family);
        assert_eq!(first.posture, second.posture);
        assert_eq!(first.profile.user_agent, second.profile.user_agent);
        assert_eq!(first.profile.timezone, second.profile.timezone);
        assert_eq!(first.profile.canvas_noise_seed, second.profile.canvas_noise_seed);
        assert_eq!(first.profile.viewport, second.profile.viewport);
        assert_eq!(first.epoch, second.epoch);
        assert_eq!(pool.cohort_count().await, 1);
    }

    #[tokio::test]
    async fn test_cohort_per_cohort_stability_ignores_run_boundaries() {
        // Default rotation policy is PerCohort: begin_run is a no-op and
        // nothing is logged (no implied rotation).
        let policy = CohortPolicy {
            stealth_classes: vec!["cleared-source".to_string()],
            ..CohortPolicy::default()
        };
        let pool = BrowserPool::new(PoolConfig::default())
            .await
            .unwrap()
            .with_cohorts(policy);

        let before = pool.cohort_for("cleared-source").await;
        let after = pool.begin_run("cleared-source").await;
        assert_eq!(
            before.profile.canvas_noise_seed,
            after.profile.canvas_noise_seed
        );
        assert_eq!(after.epoch, 0);
        assert!(pool.rotation_log().is_empty());
    }

    #[tokio::test]
    async fn test_cohort_per_run_rotation_is_deliberate_and_logged() {
        let policy = CohortPolicy {
            stealth_classes: vec!["cleared-source".to_string()],
            rotation: RotationPolicy::PerRun,
            ..CohortPolicy::default()
        };
        let pool = BrowserPool::new(PoolConfig::default())
            .await
            .unwrap()
            .with_cohorts(policy);

        // First run: initial assignment, not a rotation.
        let run0 = pool.begin_run("cleared-source").await;
        assert_eq!(run0.epoch, 0);
        assert!(pool.rotation_log().is_empty());

        // Second run: identity re-rolled, family preserved, rotation recorded.
        let run1 = pool.begin_run("cleared-source").await;
        assert_eq!(run1.epoch, 1);
        assert_ne!(
            run0.profile.canvas_noise_seed, run1.profile.canvas_noise_seed,
            "a new run must re-roll the identity-only fields"
        );
        assert_eq!(
            run0.family, run1.family,
            "rotation must stay inside the family — no attribute mixing"
        );
        assert_eq!(run0.profile.user_agent, run1.profile.user_agent);

        let log = pool.rotation_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].task_class, "cleared-source");
        assert_eq!(log[0].epoch, 1);
        assert_eq!(log[0].reason, "run boundary");

        // Stable within the run.
        let again = pool.cohort_for("cleared-source").await;
        assert_eq!(again.profile.canvas_noise_seed, run1.profile.canvas_noise_seed);
        assert_eq!(again.epoch, 1);
        // ...and still only one mutation was ever logged.
        assert_eq!(pool.rotation_log().len(), 1);
    }

    #[tokio::test]
    async fn test_cohort_declared_bot_identity_is_pinned_across_rotations() {
        // The declared identity is the honest constant: an explicit rotation
        // bumps the epoch + logs, but the announced UA does not drift.
        let pool = BrowserPool::new(PoolConfig::default()).await.unwrap();
        let before = pool.cohort_for(TASK_CLASS_PUBLIC_SCRAPING).await;
        let after = pool
            .rotate_cohort(TASK_CLASS_PUBLIC_SCRAPING, "operator review")
            .await;
        assert_eq!(before.profile.user_agent, after.profile.user_agent);
        assert_eq!(after.epoch, 1);
        let log = pool.rotation_log();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].task_class, TASK_CLASS_PUBLIC_SCRAPING);
        assert_eq!(log[0].reason, "operator review");
    }

    #[tokio::test]
    async fn test_stealth_classes_are_disjoint_from_the_declared_bot_default() {
        // A class cleared for stealth gets a coherent desktop-Chromium family;
        // public scraping keeps the declared bot — nothing leaks between
        // cohorts.
        let policy = CohortPolicy {
            stealth_classes: vec!["cleared-source".to_string()],
            ..CohortPolicy::default()
        };
        let pool = BrowserPool::new(PoolConfig::default())
            .await
            .unwrap()
            .with_cohorts(policy);

        let public = pool.cohort_for(TASK_CLASS_PUBLIC_SCRAPING).await;
        let cleared = pool.cohort_for("cleared-source").await;

        assert_eq!(public.posture, CohortPosture::DeclaredBot);
        assert_eq!(public.family, ProfileFamily::DeclaredBot);
        assert_eq!(cleared.posture, CohortPosture::Stealth);
        assert_ne!(cleared.family.id(), public.family.id());
        assert!(matches!(
            cleared.family,
            ProfileFamily::ChromeWindows | ProfileFamily::ChromeMacos | ProfileFamily::ChromeLinux
        ));
        assert!(cleared.is_coherent());
        assert!(cleared.profile.user_agent.contains("Chrome/"));
        assert!(!cleared.profile.user_agent.contains("TallowScraper"));
    }

    #[tokio::test]
    async fn test_cohort_family_pick_is_stable_across_pools() {
        // Deterministic per class id: two independent pools (same class, same
        // policy) pick the same family and profile — cohort identity does not
        // drift between runs/processes.
        let make_policy = || CohortPolicy {
            stealth_classes: vec!["cleared-source".to_string()],
            ..CohortPolicy::default()
        };
        let a = BrowserPool::new(PoolConfig::default())
            .await
            .unwrap()
            .with_cohorts(make_policy())
            .cohort_for("cleared-source")
            .await;
        let b = BrowserPool::new(PoolConfig::default())
            .await
            .unwrap()
            .with_cohorts(make_policy())
            .cohort_for("cleared-source")
            .await;
        assert_eq!(a.family, b.family);
        assert_eq!(a.profile.user_agent, b.profile.user_agent);
        assert_eq!(a.profile.webgl_renderer, b.profile.webgl_renderer);
    }

    #[tokio::test]
    async fn test_cohort_policy_matches_class_ids_trimmed_and_case_folded() {
        // Class ids are matched on trimmed, case-folded input — a "Cleared Source"
        // id must not silently fall out of the granted posture.
        let policy = CohortPolicy {
            stealth_classes: vec!["Cleared Source".to_string()],
            ..CohortPolicy::default()
        };
        assert_eq!(policy.posture_for(" cleared source "), CohortPosture::Stealth);
        assert_eq!(policy.posture_for("PUBLIC-SCRAPING"), CohortPosture::DeclaredBot);
    }

    #[test]
    fn test_stable_hash_is_deterministic() {
        assert_eq!(stable_hash("cleared-source"), stable_hash("cleared-source"));
        assert_ne!(stable_hash("cleared-source"), stable_hash("other-source"));
        // FNV-1a reference values (cross-release stability is the contract).
        assert_eq!(stable_hash(""), 0xcbf2_9ce4_8422_2325);
    }

    #[tokio::test]
    async fn test_pool_default_policy_is_r7() {
        let pool = BrowserPool::new(PoolConfig::default()).await.unwrap();
        let policy = pool.cohort_policy();
        assert_eq!(policy.default_posture, CohortPosture::DeclaredBot);
        assert!(policy.stealth_classes.is_empty());
        assert_eq!(policy.rotation, RotationPolicy::PerCohort);
        assert!(!policy.stealth_palette.is_empty());
    }
}
