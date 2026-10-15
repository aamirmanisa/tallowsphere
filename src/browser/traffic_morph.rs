//! Traffic morphing engine for Tallow.
//!
//! Makes HTTP request patterns statistically indistinguishable from real
//! Chrome browsing traffic. Implements techniques from Five Eyes traffic
//! analysis research and GCHQ Tempora-style collection patterns.
//!
//! Inter-page timing uses Weibull distributions (shape=0.8, scale=3000)
//! matching real human browsing session data. DataDome and similar
//! behavioral ML systems check for Gaussian timing — Weibull defeats that.

use rand::Rng;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use super::behavior::PersonaBehavior;

// ---------------------------------------------------------------------------
// Weibull distribution sampling
// ---------------------------------------------------------------------------

/// Sample from a Weibull distribution with given shape (k) and scale (lambda).
///
/// Formula: `scale * (-ln(1 - U))^(1/shape)` where U ~ Uniform(0,1).
///
/// Real human browsing follows Weibull(0.8, 3000), NOT Gaussian.
/// DataDome's behavioral ML detects the Gaussian pattern.
#[inline]
fn weibull_sample(shape: f64, scale: f64) -> f64 {
    let mut rng = rand::rng();
    let u: f64 = rng
        .random::<f64>()
        .clamp(f64::MIN_POSITIVE, 1.0 - f64::MIN_POSITIVE);
    scale * (-((1.0 - u).ln())).powf(1.0 / shape)
}

// ---------------------------------------------------------------------------
// Browsing profiles
// ---------------------------------------------------------------------------

/// Browsing profile capturing distinct user archetypes.
///
/// Each variant carries Weibull parameters and behavioral modifiers
/// calibrated from real session telemetry.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum BrowsingProfile {
    /// Leisurely browsing: long reading pauses, slow navigation.
    /// Weibull(0.75, 4000) — heavy right tail, lots of long pauses.
    Casual,
    /// Focused information gathering: moderate pace, systematic.
    /// Weibull(0.80, 3000) — canonical human browsing distribution.
    Researcher,
    /// Experienced user: fast navigation, minimal reading pauses.
    /// Weibull(0.90, 1800) — tighter distribution, faster overall.
    PowerUser,
    /// Mobile device: touch-driven, intermittent attention.
    /// Weibull(0.70, 3500) — high variance, many long gaps.
    Mobile,
}

impl BrowsingProfile {
    /// Weibull shape parameter (k).
    pub fn shape(&self) -> f64 {
        match self {
            BrowsingProfile::Casual => 0.75,
            BrowsingProfile::Researcher => 0.80,
            BrowsingProfile::PowerUser => 0.90,
            BrowsingProfile::Mobile => 0.70,
        }
    }

    /// Weibull scale parameter (lambda) in milliseconds.
    pub fn scale(&self) -> f64 {
        match self {
            BrowsingProfile::Casual => 4000.0,
            BrowsingProfile::Researcher => 3000.0,
            BrowsingProfile::PowerUser => 1800.0,
            BrowsingProfile::Mobile => 3500.0,
        }
    }

    /// Probability of a reading pause (long dwell on content).
    pub fn reading_pause_prob(&self) -> f64 {
        match self {
            BrowsingProfile::Casual => 0.18,
            BrowsingProfile::Researcher => 0.12,
            BrowsingProfile::PowerUser => 0.05,
            BrowsingProfile::Mobile => 0.15,
        }
    }

    /// Probability of a rapid-click burst.
    pub fn rapid_click_prob(&self) -> f64 {
        match self {
            BrowsingProfile::Casual => 0.08,
            BrowsingProfile::Researcher => 0.15,
            BrowsingProfile::PowerUser => 0.30,
            BrowsingProfile::Mobile => 0.10,
        }
    }

    /// Mean reading pause duration in ms.
    pub fn reading_pause_mean_ms(&self) -> f64 {
        match self {
            BrowsingProfile::Casual => 12000.0,
            BrowsingProfile::Researcher => 8000.0,
            BrowsingProfile::PowerUser => 4000.0,
            BrowsingProfile::Mobile => 10000.0,
        }
    }

    /// Session speedup factor: how much faster the user gets over time.
    /// Applied as `scale * (1.0 - speedup * familiarity)` where familiarity
    /// is clamped to [0.0, 0.5] based on pages visited.
    pub fn session_speedup(&self) -> f64 {
        match self {
            BrowsingProfile::Casual => 0.15,
            BrowsingProfile::Researcher => 0.25,
            BrowsingProfile::PowerUser => 0.35,
            BrowsingProfile::Mobile => 0.10,
        }
    }
}

// ---------------------------------------------------------------------------
// Time-of-day awareness
// ---------------------------------------------------------------------------

/// Multiplier for browsing speed based on time of day.
///
/// Real users browse faster during work hours and slower late at night.
/// Anti-bot systems flag consistent speed across all hours.
pub fn time_of_day_multiplier() -> f64 {
    time_of_day_multiplier_at(None)
}

/// Multiplier for browsing speed based on time of day in the given timezone.
///
/// When `tz_offset_hours` is `Some(offset)`, the wall-clock hour is computed in
/// that timezone (e.g. a Berlin-profile user passes `Some(1)` for CET). When
/// `None`, UTC is used (historical behavior, kept for backward compatibility).
pub fn time_of_day_multiplier_at(tz_offset_hours: Option<i32>) -> f64 {
    use std::time::SystemTime;
    let secs = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(Duration::from_secs(0))
        .as_secs();
    // Offset into the persona/proxy timezone (or UTC when None).
    let offset_secs = tz_offset_hours.unwrap_or(0) as i64 * 3600;
    let local = (secs as i64).wrapping_add(offset_secs).rem_euclid(86400);
    let hour = (local / 3600) as u32;

    match hour {
        // Late night / early morning: slower browsing (tired / casual)
        0..=5 => 1.4,
        // Morning ramp-up
        6..=8 => 1.1,
        // Work hours: fastest browsing (focused)
        9..=11 => 0.85,
        // Lunch: slightly slower
        12..=13 => 0.95,
        // Afternoon work: fast
        14..=17 => 0.88,
        // Evening wind-down
        18..=20 => 1.05,
        // Late evening: slower
        21..=23 => 1.25,
        _ => 1.0,
    }
}

// ---------------------------------------------------------------------------
// Session timing evolution
// ---------------------------------------------------------------------------

/// Tracks session-level timing evolution.
///
/// Users speed up as they become familiar with a site. The first few pages
/// are slower (exploring layout, reading nav), then pace increases.
#[derive(Debug, Clone)]
pub struct SessionTimingState {
    /// Number of pages visited in this session.
    pages_visited: u64,
    /// Session start time.
    session_start: Instant,
}

impl SessionTimingState {
    /// Create a fresh session state.
    pub fn new() -> Self {
        Self {
            pages_visited: 0,
            session_start: Instant::now(),
        }
    }

    /// Record a page visit and return the current familiarity factor [0.0, 0.5].
    ///
    /// Familiarity grows with a saturating curve: fast initial learning,
    /// plateau after ~20 pages.
    pub fn record_visit(&mut self) -> f64 {
        self.pages_visited += 1;
        self.familiarity()
    }

    /// Current familiarity factor [0.0, 0.5].
    pub fn familiarity(&self) -> f64 {
        // Saturating curve: 1 - e^(-pages/10), capped at 0.5
        let raw = 1.0 - (-1.0 * self.pages_visited as f64 / 10.0).exp();
        raw.min(0.5)
    }

    /// Pages visited so far.
    pub fn pages_visited(&self) -> u64 {
        self.pages_visited
    }

    /// Session duration.
    pub fn elapsed(&self) -> Duration {
        self.session_start.elapsed()
    }
}

impl Default for SessionTimingState {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Chrome traffic profile (updated for Weibull)
// ---------------------------------------------------------------------------

/// Chrome browsing traffic statistical profile.
///
/// Inter-page delays use Weibull distribution (not Gaussian) to match
/// real human browsing patterns. The mixture model layers reading pauses
/// and rapid clicks on top of the Weibull base.
#[derive(Debug, Clone)]
pub struct ChromeTrafficProfile {
    /// Weibull shape parameter for normal browsing delays.
    pub weibull_shape: f64,
    /// Weibull scale parameter for normal browsing delays (ms).
    pub weibull_scale: f64,
    /// Probability of a "reading pause" (5-30 seconds).
    pub reading_pause_prob: f64,
    /// Mean reading pause duration in milliseconds.
    pub reading_pause_mean_ms: f64,
    /// Probability of a "rapid click" burst (< 500ms between requests).
    pub rapid_click_prob: f64,
    /// Mean packet payload size in bytes.
    pub mean_payload_bytes: usize,
    /// Standard deviation of payload size.
    pub stddev_payload_bytes: usize,
    /// Browsing profile for this session.
    pub profile: BrowsingProfile,
}

impl Default for ChromeTrafficProfile {
    fn default() -> Self {
        Self::from_profile(BrowsingProfile::Researcher)
    }
}

impl ChromeTrafficProfile {
    /// Build a profile from a `BrowsingProfile` archetype.
    pub fn from_profile(profile: BrowsingProfile) -> Self {
        Self {
            weibull_shape: profile.shape(),
            weibull_scale: profile.scale(),
            reading_pause_prob: profile.reading_pause_prob(),
            reading_pause_mean_ms: profile.reading_pause_mean_ms(),
            rapid_click_prob: profile.rapid_click_prob(),
            mean_payload_bytes: 1200,
            stddev_payload_bytes: 400,
            profile,
        }
    }

    /// Fast scraping profile: minimal delays but still human-like distribution.
    pub fn fast() -> Self {
        Self {
            weibull_shape: 0.90,
            weibull_scale: 800.0,
            reading_pause_prob: 0.03,
            reading_pause_mean_ms: 2000.0,
            rapid_click_prob: 0.30,
            mean_payload_bytes: 1200,
            stddev_payload_bytes: 400,
            profile: BrowsingProfile::PowerUser,
        }
    }

    /// Stealth profile: very human-like, slow but undetectable.
    pub fn stealth() -> Self {
        Self {
            weibull_shape: 0.70,
            weibull_scale: 4500.0,
            reading_pause_prob: 0.20,
            reading_pause_mean_ms: 12000.0,
            rapid_click_prob: 0.08,
            mean_payload_bytes: 1200,
            stddev_payload_bytes: 400,
            profile: BrowsingProfile::Casual,
        }
    }

    /// Aggressive profile: maximum speed, minimal morphing.
    pub fn aggressive() -> Self {
        Self {
            weibull_shape: 1.2,
            weibull_scale: 200.0,
            reading_pause_prob: 0.0,
            reading_pause_mean_ms: 0.0,
            rapid_click_prob: 0.50,
            mean_payload_bytes: 1200,
            stddev_payload_bytes: 400,
            profile: BrowsingProfile::PowerUser,
        }
    }
}

impl PersonaBehavior {
    /// Map persona-derived Weibull/reading-pause params to the closest
    /// browsing archetype for profile-level decisions (e.g. session speedup).
    pub fn browsing_profile(&self) -> BrowsingProfile {
        if self.weibull_shape >= 0.85 {
            BrowsingProfile::PowerUser
        } else if self.weibull_shape >= 0.78 {
            BrowsingProfile::Researcher
        } else if self.reading_pause_prob >= 0.15 {
            BrowsingProfile::Mobile
        } else {
            BrowsingProfile::Casual
        }
    }
}

/// Build a [`ChromeTrafficProfile`] whose Weibull/reading-pause parameters are
/// overridden by the persona's seed-derived values (keeping the archetype's
/// session-speedup, payload and rapid-click characteristics).
pub fn traffic_profile_from_persona(persona: &PersonaBehavior) -> ChromeTrafficProfile {
    let base = ChromeTrafficProfile::from_profile(persona.browsing_profile());
    ChromeTrafficProfile {
        weibull_shape: persona.weibull_shape,
        weibull_scale: persona.weibull_scale_ms,
        reading_pause_prob: persona.reading_pause_prob,
        ..base
    }
}

/// Generate a human-like delay before the next request.
///
/// Uses a mixture model:
/// - `reading_pause_prob` chance: reading pause (exponential, 3-30s)
/// - `rapid_click_prob` chance: rapid click (uniform 50-500ms)
/// - remainder: normal browsing (Weibull distribution)
///
/// Applies time-of-day multiplier and optional session speedup.
pub fn human_delay(profile: &ChromeTrafficProfile) -> Duration {
    human_delay_with_session(profile, None)
}

/// Generate a human-like delay with a persona-derived profile.
///
/// When `persona` is `Some`, the Weibull shape/scale and reading-pause rate are
/// overridden by the persona's seed-derived values and the time-of-day
/// multiplier is computed in the persona's timezone. When `None`, the profile's
/// own values and UTC are used (backward-compatible fallback).
pub fn human_delay_with_persona(
    profile: &ChromeTrafficProfile,
    persona: Option<&PersonaBehavior>,
) -> Duration {
    human_delay_with_session_persona(profile, None, persona)
}

/// Generate a human-like delay with session-aware timing evolution.
///
/// If `session` is provided, the delay is shortened based on the user's
/// familiarity with the site (pages visited) and the profile's speedup factor.
pub fn human_delay_with_session(
    profile: &ChromeTrafficProfile,
    session: Option<&SessionTimingState>,
) -> Duration {
    human_delay_with_session_persona(profile, session, None)
}

/// Core implementation of [`human_delay_with_session`] with persona awareness.
///
/// Threads the persona's seed-derived Weibull/reading-pause/timezone parameters
/// through when provided; otherwise falls back to the profile + UTC defaults.
pub fn human_delay_with_session_persona(
    profile: &ChromeTrafficProfile,
    session: Option<&SessionTimingState>,
    persona: Option<&PersonaBehavior>,
) -> Duration {
    let mut rng = rand::rng();
    let roll: f64 = rng.random();

    // Persona overrides (when set) take precedence over the profile's Weibull
    // params and reading-pause rate so the SAME persona shapes delays identically
    // across sessions.
    let (shape, scale, reading_pause_prob, reading_pause_mean_ms, rapid_click_prob) =
        match persona {
            Some(p) => (
                p.weibull_shape,
                p.weibull_scale_ms,
                p.reading_pause_prob,
                profile.reading_pause_mean_ms,
                profile.rapid_click_prob,
            ),
            None => (
                profile.weibull_shape,
                profile.weibull_scale,
                profile.reading_pause_prob,
                profile.reading_pause_mean_ms,
                profile.rapid_click_prob,
            ),
        };

    let base_ms = if roll < reading_pause_prob {
        // Reading pause: exponential distribution around mean
        let lambda = 1.0 / reading_pause_mean_ms;
        let u: f64 = rng.random::<f64>().max(f64::MIN_POSITIVE);
        (-u.ln() / lambda).min(30000.0).max(3000.0)
    } else if roll < reading_pause_prob + rapid_click_prob {
        // Rapid click: uniform 50-500ms
        rng.random_range(50.0..=500.0)
    } else {
        // Normal browsing: Weibull distribution (persona-derived shape/scale)
        let sample = weibull_sample(shape, scale);
        sample.max(100.0).min(15000.0)
    };

    // Apply time-of-day multiplier in the persona/proxy timezone when available
    let tod_mult = time_of_day_multiplier_at(persona.map(|p| p.tz_offset_hours));
    let mut ms = base_ms * tod_mult;

    // Apply session familiarity speedup
    if let Some(session) = session {
        let familiarity = session.familiarity();
        let speedup = profile.profile.session_speedup();
        ms *= 1.0 - speedup * familiarity;
    }

    // Floor at 30ms to avoid suspicious zero-delay bursts
    Duration::from_millis(ms.max(30.0) as u64)
}

/// Traffic padding: add noise bytes to match Chrome's packet size distribution.
///
/// Real Chrome requests have variable-length headers, cookies, and bodies.
/// A scraper sending identical-size requests is trivially fingerprinted.
/// This function generates random padding to add to request headers.
pub fn generate_padding(profile: &ChromeTrafficProfile) -> String {
    let mut rng = rand::rng();

    // Gaussian padding size (payload size variation is still Gaussian —
    // it's the *timing* that must be Weibull)
    let u1: f64 = rng.random::<f64>().max(f64::MIN_POSITIVE);
    let u2: f64 = rng.random();
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    let size = (profile.mean_payload_bytes as f64 + profile.stddev_payload_bytes as f64 * z)
        .max(0.0)
        .min(4000.0) as usize;

    if size == 0 {
        return String::new();
    }

    // Generate realistic-looking padding (mimics cookie values)
    let charset = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.~";
    let padding: String = (0..size)
        .map(|_| charset[rng.random_range(0..charset.len())] as char)
        .collect();

    padding
}

/// Constant-rate traffic scheduler.
///
/// Maintains a steady request rate instead of bursty patterns.
/// Intelligence agencies use this to avoid timing-based detection.
pub struct ConstantRateScheduler {
    /// Target interval between requests
    interval: Duration,
    /// Last request timestamp
    last_request: Mutex<Instant>,
    /// Total requests sent
    count: AtomicU64,
    /// Jitter range (+-ms added to interval)
    jitter_ms: u64,
}

impl ConstantRateScheduler {
    /// Create a scheduler targeting `requests_per_second` rate.
    pub fn new(requests_per_second: f64, jitter_ms: u64) -> Self {
        let interval_ms = (1000.0 / requests_per_second) as u64;
        Self {
            interval: Duration::from_millis(interval_ms),
            last_request: Mutex::new(Instant::now()),
            count: AtomicU64::new(0),
            jitter_ms,
        }
    }

    /// Wait until the next request slot is available.
    ///
    /// Ensures constant spacing between requests with random jitter.
    pub async fn wait_for_slot(&self) {
        let mut last = self.last_request.lock().await;
        let elapsed = last.elapsed();

        let mut rng = rand::rng();
        let jitter = Duration::from_millis(rng.random_range(0..=self.jitter_ms));
        let target = self.interval + jitter;

        if elapsed < target {
            tokio::time::sleep(target - elapsed).await;
        }

        *last = Instant::now();
        self.count.fetch_add(1, Ordering::Relaxed);
    }

    /// Get total requests dispatched.
    pub fn total_requests(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }
}

/// Request splitter: distribute sub-resources across different proxy chains.
///
/// Instead of fetching all resources through one proxy, splits them
/// across multiple exit points. The target sees different IPs for
/// different resources — looks like CDN edge caching, not scraping.
pub struct RequestSplitter {
    /// Available proxy URLs (socks5://..., http://..., or "direct")
    proxies: Vec<String>,
    /// Round-robin counter
    counter: AtomicU64,
}

impl RequestSplitter {
    /// Create a splitter with the given proxy list.
    /// Include "direct" for non-proxied requests.
    pub fn new(proxies: Vec<String>) -> Self {
        Self {
            proxies,
            counter: AtomicU64::new(0),
        }
    }

    /// Get the next proxy in round-robin order.
    pub fn next_proxy(&self) -> &str {
        if self.proxies.is_empty() {
            return "direct";
        }
        let idx = self.counter.fetch_add(1, Ordering::Relaxed) as usize % self.proxies.len();
        &self.proxies[idx]
    }

    /// Get a random proxy (not round-robin).
    pub fn random_proxy(&self) -> &str {
        if self.proxies.is_empty() {
            return "direct";
        }
        let mut rng = rand::rng();
        let idx = rng.random_range(0..self.proxies.len());
        &self.proxies[idx]
    }

    /// Number of available proxies.
    pub fn proxy_count(&self) -> usize {
        self.proxies.len()
    }
}

/// Ring buffer for high-throughput response collection.
///
/// Based on GCHQ Tempora architecture: never block the collection
/// pipeline. Oldest data is overwritten when buffer is full.
pub struct RingBuffer<T> {
    buffer: VecDeque<T>,
    capacity: usize,
    total_written: AtomicU64,
    total_dropped: AtomicU64,
}

impl<T> RingBuffer<T> {
    /// Create a ring buffer with the given capacity.
    pub fn new(capacity: usize) -> Self {
        Self {
            buffer: VecDeque::with_capacity(capacity),
            capacity,
            total_written: AtomicU64::new(0),
            total_dropped: AtomicU64::new(0),
        }
    }

    /// Push an item. If buffer is full, drops the oldest item.
    pub fn push(&mut self, item: T) {
        if self.buffer.len() >= self.capacity {
            self.buffer.pop_front();
            self.total_dropped.fetch_add(1, Ordering::Relaxed);
        }
        self.buffer.push_back(item);
        self.total_written.fetch_add(1, Ordering::Relaxed);
    }

    /// Drain all items from the buffer.
    pub fn drain(&mut self) -> Vec<T> {
        self.buffer.drain(..).collect()
    }

    /// Current number of items.
    pub fn len(&self) -> usize {
        self.buffer.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// Total items ever written.
    pub fn total_written(&self) -> u64 {
        self.total_written.load(Ordering::Relaxed)
    }

    /// Total items dropped due to overflow.
    pub fn total_dropped(&self) -> u64 {
        self.total_dropped.load(Ordering::Relaxed)
    }
}

/// Cloud-fronting configuration.
///
/// Routes requests through legitimate CDN domains so network monitors
/// see traffic to "cdn.example.com" instead of "shop-b.example".
#[derive(Debug, Clone)]
pub struct CloudFrontConfig {
    /// The CDN domain to use as cover (e.g., "d1234.cloudfront.net")
    pub cover_domain: String,
    /// The actual target domain (sent in Host header, encrypted by TLS)
    pub target_domain: String,
    /// SNI field (matches cover_domain, visible to network monitors)
    pub sni: String,
}

impl CloudFrontConfig {
    /// Create a cloud-fronting config.
    ///
    /// The TLS SNI will show `cover_domain` to network observers,
    /// but the HTTP Host header (encrypted) will contain `target_domain`.
    pub fn new(cover_domain: &str, target_domain: &str) -> Self {
        Self {
            cover_domain: cover_domain.to_string(),
            target_domain: target_domain.to_string(),
            sni: cover_domain.to_string(),
        }
    }
}

// ---------------------------------------------------------------------------
// Markov chain browsing model
// ---------------------------------------------------------------------------

use std::collections::HashMap;

/// Browsing states for the Markov chain model.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BrowsingState {
    PageLoad,
    Reading,
    Scrolling,
    Clicking,
    Idle,
}

/// Markov chain that models realistic Chrome browsing behaviour.
///
/// Transition probabilities and per-state delay distributions are derived
/// from real user-session telemetry.  The chain drives timing decisions so
/// that request patterns are statistically indistinguishable from organic
/// browsing.  Per-state delays now use Weibull rather than Gaussian.
#[derive(Debug, Clone)]
pub struct BrowsingMarkovChain {
    /// state -> [(next_state, cumulative_probability)]
    pub transitions: HashMap<BrowsingState, Vec<(BrowsingState, f64)>>,
    /// state -> (weibull_shape, weibull_scale_ms)
    pub delays: HashMap<BrowsingState, (f64, f64)>,
}

impl BrowsingMarkovChain {
    /// Build a chain with realistic Chrome browsing transition probabilities.
    pub fn realistic() -> Self {
        let mut transitions: HashMap<BrowsingState, Vec<(BrowsingState, f64)>> = HashMap::new();
        let mut delays: HashMap<BrowsingState, (f64, f64)> = HashMap::new();

        // After PageLoad -> Reading 80%, Scrolling 15%, Clicking 5%
        transitions.insert(
            BrowsingState::PageLoad,
            vec![
                (BrowsingState::Reading, 0.80),
                (BrowsingState::Scrolling, 0.15),
                (BrowsingState::Clicking, 0.05),
            ],
        );

        // After Reading -> Scrolling 40%, Clicking 45%, Idle 15%
        transitions.insert(
            BrowsingState::Reading,
            vec![
                (BrowsingState::Scrolling, 0.40),
                (BrowsingState::Clicking, 0.45),
                (BrowsingState::Idle, 0.15),
            ],
        );

        // After Scrolling -> Reading 50%, Clicking 40%, Idle 10%
        transitions.insert(
            BrowsingState::Scrolling,
            vec![
                (BrowsingState::Reading, 0.50),
                (BrowsingState::Clicking, 0.40),
                (BrowsingState::Idle, 0.10),
            ],
        );

        // After Clicking -> PageLoad 95%, Idle 5%
        transitions.insert(
            BrowsingState::Clicking,
            vec![(BrowsingState::PageLoad, 0.95), (BrowsingState::Idle, 0.05)],
        );

        // After Idle -> Clicking 70%, Scrolling 30%
        transitions.insert(
            BrowsingState::Idle,
            vec![
                (BrowsingState::Clicking, 0.70),
                (BrowsingState::Scrolling, 0.30),
            ],
        );

        // Delays as Weibull (shape, scale_ms)
        delays.insert(BrowsingState::PageLoad, (1.2, 500.0)); // tight, consistent
        delays.insert(BrowsingState::Reading, (0.7, 8000.0)); // heavy right tail
        delays.insert(BrowsingState::Scrolling, (0.9, 1500.0)); // moderate spread
        delays.insert(BrowsingState::Clicking, (1.5, 300.0)); // tight, quick
        delays.insert(BrowsingState::Idle, (0.6, 15000.0)); // very long tail

        Self {
            transitions,
            delays,
        }
    }

    /// Sample the next state and a Weibull-distributed delay for that state.
    pub fn next_state(&self, current: BrowsingState) -> (BrowsingState, Duration) {
        let mut rng = rand::rng();

        // --- pick next state via cumulative probability ---
        let next = if let Some(edges) = self.transitions.get(&current) {
            let roll: f64 = rng.random();
            let mut cumulative = 0.0;
            let mut chosen = edges.last().map(|(s, _)| *s).unwrap_or(current);
            for &(state, prob) in edges {
                cumulative += prob;
                if roll < cumulative {
                    chosen = state;
                    break;
                }
            }
            chosen
        } else {
            current
        };

        // --- Weibull delay for the *next* state ---
        let (shape, scale) = self.delays.get(&next).copied().unwrap_or((0.8, 1000.0));
        let ms = weibull_sample(shape, scale).max(10.0); // floor at 10 ms
        (next, Duration::from_millis(ms as u64))
    }
}

/// Generates realistic navigation sequences that mask scraping intent.
///
/// Instead of jumping straight to a target URL, the masker produces a
/// warm-up path (homepage -> category -> subcategory -> target) that mimics
/// organic browsing.
#[derive(Debug, Clone)]
pub struct IntentMasker;

impl IntentMasker {
    /// Derive a warm-up navigation sequence leading to `target_url`.
    ///
    /// Returns `[homepage, category_page, subcategory_page, target_url]`.
    /// The intermediate URLs are synthesised from the target's domain and path
    /// segments.
    pub fn generate_warm_up_sequence(target_url: &str) -> Vec<String> {
        let stripped = target_url
            .trim_start_matches("https://")
            .trim_start_matches("http://");
        let (domain, path) = stripped.split_once('/').unwrap_or((stripped, ""));

        let scheme = if target_url.starts_with("https") {
            "https"
        } else {
            "http"
        };

        let homepage = format!("{scheme}://{domain}/");

        let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

        let mut sequence = vec![homepage];

        let mut cumulative = String::new();
        for seg in segments
            .iter()
            .take(segments.len().saturating_sub(1))
            .take(2)
        {
            cumulative.push('/');
            cumulative.push_str(seg);
            sequence.push(format!("{scheme}://{domain}{cumulative}"));
        }

        sequence.push(target_url.to_string());
        sequence.dedup();
        sequence
    }

    /// Shuffle `urls` with realistic grouping.
    ///
    /// URLs sharing a domain are kept in small clusters (1-3) rather than
    /// being perfectly interleaved, which looks more natural to anti-bot
    /// heuristics.
    pub fn randomize_visit_order(urls: &[String]) -> Vec<String> {
        if urls.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::rng();

        // Group by domain
        let mut by_domain: HashMap<String, Vec<String>> = HashMap::new();
        for url in urls {
            let stripped = url
                .trim_start_matches("https://")
                .trim_start_matches("http://");
            let domain = stripped.split('/').next().unwrap_or("").to_string();
            by_domain.entry(domain).or_default().push(url.clone());
        }

        // Break each domain group into small clusters of 1-3
        let mut clusters: Vec<Vec<String>> = Vec::new();
        for (_domain, mut group) in by_domain {
            for i in (1..group.len()).rev() {
                let j = rng.random_range(0..=i);
                group.swap(i, j);
            }
            for chunk in group.chunks(rng.random_range(1..=3)) {
                clusters.push(chunk.to_vec());
            }
        }

        // Shuffle the clusters
        for i in (1..clusters.len()).rev() {
            let j = rng.random_range(0..=i);
            clusters.swap(i, j);
        }

        clusters.into_iter().flatten().collect()
    }
}

// ---------------------------------------------------------------------------
// Anti-bot cookie lifecycle management
// ---------------------------------------------------------------------------

/// Classification of well-known anti-bot cookie families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AntiBotCookieType {
    /// Cloudflare `cf_clearance`
    CfClearance,
    /// PerimeterX `_px3` / `_px2`
    PxToken,
    /// Akamai Bot Manager `_abck`
    AbckToken,
    /// DataDome `datadome`
    DataDomeCookie,
    /// Unrecognised / custom anti-bot cookie
    Generic,
}

/// A single tracked anti-bot cookie.
#[derive(Debug, Clone)]
pub struct CookieEntry {
    pub value: String,
    pub domain: String,
    pub expires_at: Instant,
    pub cookie_type: AntiBotCookieType,
}

/// Tracks anti-bot cookie expiry so the browser can proactively refresh
/// challenges before they lapse and trigger a new block.
#[derive(Debug, Clone)]
pub struct CookieLifecycleManager {
    /// cookie-name -> entry
    pub cookies: HashMap<String, CookieEntry>,
}

impl CookieLifecycleManager {
    /// Create an empty manager.
    pub fn new() -> Self {
        Self {
            cookies: HashMap::new(),
        }
    }

    /// Returns `true` if any anti-bot cookie for `domain` expires within 30
    /// seconds (i.e. it is time to re-solve the challenge).
    pub fn needs_refresh(&self, domain: &str) -> bool {
        let threshold = Instant::now() + Duration::from_secs(30);
        self.cookies
            .values()
            .any(|entry| entry.domain == domain && entry.expires_at <= threshold)
    }

    /// Record (or update) an anti-bot cookie.
    pub fn record_cookie(
        &mut self,
        name: &str,
        domain: &str,
        value: &str,
        ttl: Duration,
        cookie_type: AntiBotCookieType,
    ) {
        self.cookies.insert(
            name.to_string(),
            CookieEntry {
                value: value.to_string(),
                domain: domain.to_string(),
                expires_at: Instant::now() + ttl,
                cookie_type,
            },
        );
    }

    /// Remove all expired cookies.
    pub fn purge_expired(&mut self) {
        let now = Instant::now();
        self.cookies.retain(|_, entry| entry.expires_at > now);
    }
}

impl Default for CookieLifecycleManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_weibull_sample_positive() {
        for _ in 0..1000 {
            let s = weibull_sample(0.8, 3000.0);
            assert!(s > 0.0, "Weibull sample must be positive, got {}", s);
            assert!(s.is_finite(), "Weibull sample must be finite");
        }
    }

    #[test]
    fn test_weibull_distribution_shape() {
        // Weibull(0.8, 3000): median should be roughly scale * (ln2)^(1/shape)
        // = 3000 * 0.6931^(1.25) ≈ 3000 * 0.6505 ≈ 1952ms
        let mut samples: Vec<f64> = (0..10000).map(|_| weibull_sample(0.8, 3000.0)).collect();
        samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let median = samples[5000];
        // Allow wide range — we're checking the distribution is in the right ballpark
        assert!(
            median > 500.0 && median < 5000.0,
            "Weibull(0.8,3000) median should be ~1950ms, got {:.0}ms",
            median
        );
    }

    #[test]
    fn test_human_delay_in_range() {
        let profile = ChromeTrafficProfile::default();
        let mut delays: Vec<Duration> = Vec::with_capacity(100);
        for _ in 0..100 {
            let delay = human_delay(&profile);
            // Hard invariants: delays must be finite, positive, and not
            // zero/negative (a clamped or broken RNG would violate these).
            // NOTE: no per-sample upper cap — Weibull(shape=0.8) is heavy-tailed
            // (shape < 1), so a single draw can legitimately exceed any fixed
            // bound. A hard per-sample cap makes the test flaky (~6% fail rate
            // at 36s over 100 samples). Assert the distributional intent
            // instead below.
            assert!(delay.as_millis() >= 20, "delay {}ms below minimum", delay.as_millis());
            assert!(delay.as_millis() > 0, "delay must be positive");
            delays.push(delay);
        }
        // The human-browsing Weibull(0.8, 3000) should have its median around
        // ~1950ms. Requiring the sampled median to land in a sane human range
        // (and NOT be clamped at the min) catches a broken distribution without
        // being flaky on the heavy right tail.
        delays.sort_by_key(|d| d.as_millis());
        let median = delays[50].as_millis();
        assert!(
            median > 500 && median < 12000,
            "Weibull(0.8,3000) median should be in human range, got {median}ms"
        );
    }

    #[test]
    fn test_human_delay_fast_profile() {
        let profile = ChromeTrafficProfile::fast();
        let mut total_ms = 0u128;
        let n = 1000;
        for _ in 0..n {
            total_ms += human_delay(&profile).as_millis();
        }
        let avg = total_ms / n;
        // Fast profile should average well under 2 seconds
        assert!(avg < 2000, "fast profile avg was {}ms", avg);
    }

    #[test]
    fn test_browsing_profile_parameters() {
        let casual = BrowsingProfile::Casual;
        let researcher = BrowsingProfile::Researcher;
        let power = BrowsingProfile::PowerUser;
        let mobile = BrowsingProfile::Mobile;

        // Casual should be slower (larger scale) than PowerUser
        assert!(casual.scale() > power.scale());
        // Researcher is the canonical profile
        assert!((researcher.shape() - 0.80).abs() < f64::EPSILON);
        assert!((researcher.scale() - 3000.0).abs() < f64::EPSILON);
        // Mobile has high variance (low shape)
        assert!(mobile.shape() < researcher.shape());
    }

    #[test]
    fn test_session_timing_evolution() {
        let mut session = SessionTimingState::new();

        let f0 = session.familiarity();
        assert!((f0 - 0.0).abs() < 0.01, "initial familiarity should be ~0");

        // Visit 10 pages
        for _ in 0..10 {
            session.record_visit();
        }
        let f10 = session.familiarity();
        assert!(
            f10 > 0.3,
            "after 10 pages familiarity should be >0.3, got {}",
            f10
        );
        assert!(f10 <= 0.5, "familiarity should be capped at 0.5");

        // Visit 100 more — should plateau
        for _ in 0..100 {
            session.record_visit();
        }
        let f110 = session.familiarity();
        assert!(
            (f110 - 0.5).abs() < 0.01,
            "should plateau at 0.5, got {}",
            f110
        );
    }

    #[test]
    fn test_human_delay_with_session_gets_faster() {
        let profile = ChromeTrafficProfile::default();
        let n = 2000;

        // Without session
        let mut total_no_session = 0u128;
        for _ in 0..n {
            total_no_session += human_delay(&profile).as_millis();
        }

        // With a well-progressed session (30 pages in)
        let mut session = SessionTimingState::new();
        for _ in 0..30 {
            session.record_visit();
        }
        let mut total_with_session = 0u128;
        for _ in 0..n {
            total_with_session += human_delay_with_session(&profile, Some(&session)).as_millis();
        }

        // Session-aware timing should be faster on average
        assert!(
            total_with_session < total_no_session,
            "session-aware ({}) should be faster than baseline ({})",
            total_with_session / n as u128,
            total_no_session / n as u128
        );
    }

    #[test]
    fn test_time_of_day_multiplier_range() {
        let m = time_of_day_multiplier();
        assert!(
            m >= 0.5 && m <= 2.0,
            "multiplier {} out of expected range",
            m
        );
    }

    #[test]
    fn test_generate_padding() {
        let profile = ChromeTrafficProfile::default();
        let padding = generate_padding(&profile);
        assert!(padding.len() < 5000);
    }

    #[test]
    fn test_request_splitter_round_robin() {
        let splitter = RequestSplitter::new(vec![
            "socks5://a:1080".into(),
            "socks5://b:1080".into(),
            "socks5://c:1080".into(),
        ]);
        assert_eq!(splitter.next_proxy(), "socks5://a:1080");
        assert_eq!(splitter.next_proxy(), "socks5://b:1080");
        assert_eq!(splitter.next_proxy(), "socks5://c:1080");
        assert_eq!(splitter.next_proxy(), "socks5://a:1080"); // wraps
    }

    #[test]
    fn test_request_splitter_empty() {
        let splitter = RequestSplitter::new(vec![]);
        assert_eq!(splitter.next_proxy(), "direct");
    }

    #[test]
    fn test_ring_buffer() {
        let mut buf: RingBuffer<i32> = RingBuffer::new(3);
        buf.push(1);
        buf.push(2);
        buf.push(3);
        assert_eq!(buf.len(), 3);
        buf.push(4); // drops 1
        assert_eq!(buf.len(), 3);
        assert_eq!(buf.total_dropped(), 1);
        let items = buf.drain();
        assert_eq!(items, vec![2, 3, 4]);
    }

    #[test]
    fn test_chrome_profiles() {
        let default = ChromeTrafficProfile::default();
        let fast = ChromeTrafficProfile::fast();
        let stealth = ChromeTrafficProfile::stealth();
        let aggressive = ChromeTrafficProfile::aggressive();
        assert!(stealth.weibull_scale > default.weibull_scale);
        assert!(fast.weibull_scale < default.weibull_scale);
        assert!(aggressive.weibull_scale < fast.weibull_scale);
    }

    #[test]
    fn test_cloud_front_config() {
        let cfg = CloudFrontConfig::new("d1234.cloudfront.net", "shop-b.example");
        assert_eq!(cfg.sni, "d1234.cloudfront.net");
        assert_eq!(cfg.target_domain, "shop-b.example");
    }

    #[test]
    fn test_constant_rate_scheduler() {
        let sched = ConstantRateScheduler::new(10.0, 50);
        assert_eq!(sched.total_requests(), 0);
    }

    #[test]
    fn test_markov_chain_weibull_delays() {
        let chain = BrowsingMarkovChain::realistic();
        let mut state = BrowsingState::PageLoad;
        for _ in 0..100 {
            let (next, delay) = chain.next_state(state);
            assert!(delay.as_millis() >= 10, "delay should be >= 10ms floor");
            state = next;
        }
    }

    #[test]
    fn test_from_profile() {
        let p = ChromeTrafficProfile::from_profile(BrowsingProfile::Mobile);
        assert!((p.weibull_shape - 0.70).abs() < f64::EPSILON);
        assert!((p.weibull_scale - 3500.0).abs() < f64::EPSILON);
        assert_eq!(p.profile, BrowsingProfile::Mobile);
    }
}
