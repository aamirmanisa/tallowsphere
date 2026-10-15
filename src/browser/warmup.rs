//! Browser profile warm-up for anti-bot evasion.
//!
//! Fresh browser profiles with zero history are flagged by anti-bot systems.
//! This module provides warm-up sequences that build browsing history, cookies,
//! and cache entries to make profiles appear organic.

use std::path::PathBuf;
use std::time::Duration;

use rand::Rng;
use rand::rngs::StdRng;
use rand::SeedableRng;

use super::behavior::PersonaBehavior;
use super::error::BrowserError;
use super::interaction::ClickOptions;
use super::page::{Page, WaitUntil};

// ─────────────────────────────────────────────────────────────────────────────
// Warm-up sequences
// ─────────────────────────────────────────────────────────────────────────────

/// A single step in a warm-up sequence.
#[derive(Debug, Clone)]
pub struct WarmupStep {
    /// URL to visit.
    pub url: String,
    /// Minimum dwell time before next step (seconds).
    pub dwell_min_secs: f64,
    /// Maximum dwell time (randomized between min/max).
    pub dwell_max_secs: f64,
    /// Whether to simulate scrolling on this page.
    pub scroll: bool,
    /// Whether to simulate mouse movement on this page.
    pub mouse_move: bool,
    /// Optional: CSS selector to click before leaving.
    pub click_selector: Option<String>,
}

impl WarmupStep {
    pub fn simple(url: &str, dwell_min: f64, dwell_max: f64) -> Self {
        Self {
            url: url.to_string(),
            dwell_min_secs: dwell_min,
            dwell_max_secs: dwell_max,
            scroll: true,
            mouse_move: true,
            click_selector: None,
        }
    }

    pub fn with_click(url: &str, dwell_min: f64, dwell_max: f64, selector: &str) -> Self {
        Self {
            url: url.to_string(),
            dwell_min_secs: dwell_min,
            dwell_max_secs: dwell_max,
            scroll: true,
            mouse_move: true,
            click_selector: Some(selector.to_string()),
        }
    }
}

/// A complete warm-up sequence.
#[derive(Debug, Clone)]
pub struct WarmupSequence {
    pub name: String,
    pub steps: Vec<WarmupStep>,
}

impl WarmupSequence {
    /// Essential warm-up: Google + YouTube + Wikipedia.
    /// Builds basic cookie jar and browsing history.
    /// Duration: ~20-40 seconds.
    pub fn essential() -> Self {
        Self {
            name: "essential".into(),
            steps: vec![
                WarmupStep::simple("https://www.google.com", 2.0, 4.0),
                WarmupStep::simple("https://www.youtube.com", 2.0, 5.0),
                WarmupStep::simple("https://www.wikipedia.org", 2.0, 4.0),
            ],
        }
    }

    /// Standard warm-up: Essential + news + social.
    /// Builds a more diverse browsing profile.
    /// Duration: ~40-80 seconds.
    pub fn standard() -> Self {
        Self {
            name: "standard".into(),
            steps: vec![
                WarmupStep::simple("https://www.google.com", 2.0, 5.0),
                WarmupStep::simple("https://www.youtube.com", 3.0, 6.0),
                WarmupStep::simple("https://www.wikipedia.org", 2.0, 4.0),
                WarmupStep::simple("https://news.ycombinator.com", 2.0, 5.0),
                WarmupStep::simple("https://www.reddit.com", 3.0, 6.0),
            ],
        }
    }

    /// Full warm-up for high-security targets: Standard + e-commerce.
    /// Duration: ~60-120 seconds.
    pub fn full() -> Self {
        Self {
            name: "full".into(),
            steps: vec![
                WarmupStep::simple("https://www.google.com", 2.0, 5.0),
                WarmupStep::simple("https://www.youtube.com", 3.0, 6.0),
                WarmupStep::simple("https://www.wikipedia.org", 2.0, 4.0),
                WarmupStep::simple("https://news.ycombinator.com", 2.0, 5.0),
                WarmupStep::simple("https://www.reddit.com", 3.0, 6.0),
                WarmupStep::simple("https://www.amazon.com", 3.0, 7.0),
                WarmupStep::simple("https://www.ebay.com", 2.0, 5.0),
            ],
        }
    }

    /// Domain-specific warm-up: visits the target domain's homepage
    /// and 2-3 category pages before scraping product pages.
    pub fn domain_warmup(homepage: &str, category_urls: &[&str]) -> Self {
        let mut steps = vec![
            // Visit homepage first
            WarmupStep::simple(homepage, 3.0, 7.0),
        ];

        // Visit 2-3 category pages
        for url in category_urls.iter().take(3) {
            steps.push(WarmupStep::simple(url, 2.0, 5.0));
        }

        Self {
            name: format!("domain:{homepage}"),
            steps,
        }
    }

    /// Abbreviated warm-up for returning profiles (already have cookies).
    /// Duration: ~10-15 seconds.
    pub fn abbreviated() -> Self {
        Self {
            name: "abbreviated".into(),
            steps: vec![
                WarmupStep::simple("https://www.google.com", 2.0, 4.0),
            ],
        }
    }

    /// No warm-up — skip entirely.
    pub fn none() -> Self {
        Self {
            name: "none".into(),
            steps: vec![],
        }
    }

    /// Estimated total duration range (min, max) in seconds.
    pub fn estimated_duration(&self) -> (f64, f64) {
        let min: f64 = self.steps.iter().map(|s| s.dwell_min_secs).sum();
        let max: f64 = self.steps.iter().map(|s| s.dwell_max_secs).sum();
        (min, max)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile lifecycle
// ─────────────────────────────────────────────────────────────────────────────

/// Profile state tracks the lifecycle of a browser profile.
#[derive(Debug, Clone, PartialEq)]
pub enum ProfileState {
    /// Freshly created, no history.
    Fresh,
    /// Warm-up in progress.
    WarmingUp,
    /// Ready for scraping.
    Ready,
    /// Flagged by anti-bot — needs cooldown or retirement.
    Flagged,
    /// Retired — too many flags, should not be reused.
    Retired,
}

/// A managed browser profile with warm-up tracking.
#[derive(Debug, Clone)]
pub struct ManagedProfile {
    /// Profile directory path (Chrome --user-data-dir).
    pub data_dir: PathBuf,
    /// Current state.
    pub state: ProfileState,
    /// User agent assigned to this profile.
    pub user_agent: String,
    /// Proxy URL assigned to this profile.
    pub proxy: Option<String>,
    /// Number of times this profile has been warmed up.
    pub warmup_count: u32,
    /// Number of scraping sessions completed.
    pub session_count: u32,
    /// Number of times flagged by anti-bot.
    pub flag_count: u32,
    /// Creation timestamp.
    pub created_at: std::time::SystemTime,
    /// Last used timestamp.
    pub last_used: std::time::SystemTime,
    /// Maximum age before retirement (days).
    pub max_age_days: u32,
    /// Maximum flags before retirement.
    pub max_flags: u32,
}

impl ManagedProfile {
    pub fn new(data_dir: PathBuf, user_agent: &str) -> Self {
        let now = std::time::SystemTime::now();
        Self {
            data_dir,
            state: ProfileState::Fresh,
            user_agent: user_agent.to_string(),
            proxy: None,
            warmup_count: 0,
            session_count: 0,
            flag_count: 0,
            created_at: now,
            last_used: now,
            max_age_days: 14,
            max_flags: 3,
        }
    }

    /// Check if profile should be retired.
    pub fn should_retire(&self) -> bool {
        if self.flag_count >= self.max_flags {
            return true;
        }
        if let Ok(age) = self.created_at.elapsed() {
            if age > Duration::from_secs(self.max_age_days as u64 * 86400) {
                return true;
            }
        }
        false
    }

    /// Check if profile needs warm-up (fresh or stale).
    pub fn needs_warmup(&self) -> bool {
        if self.state == ProfileState::Fresh {
            return true;
        }
        // Stale if not used in 24 hours
        if let Ok(idle) = self.last_used.elapsed() {
            if idle > Duration::from_secs(86400) {
                return true;
            }
        }
        false
    }

    /// What warm-up sequence to use.
    pub fn warmup_type(&self) -> WarmupSequence {
        match self.state {
            ProfileState::Fresh => WarmupSequence::full(),
            _ if self.needs_warmup() => WarmupSequence::abbreviated(),
            _ => WarmupSequence::none(),
        }
    }

    /// Mark as warmed up and ready.
    pub fn mark_ready(&mut self) {
        self.state = ProfileState::Ready;
        self.warmup_count += 1;
        self.last_used = std::time::SystemTime::now();
    }

    /// Mark a completed scraping session.
    pub fn mark_session_done(&mut self) {
        self.session_count += 1;
        self.last_used = std::time::SystemTime::now();
    }

    /// Mark as flagged by anti-bot.
    pub fn mark_flagged(&mut self) {
        self.flag_count += 1;
        if self.should_retire() {
            self.state = ProfileState::Retired;
        } else {
            self.state = ProfileState::Flagged;
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Profile pool
// ─────────────────────────────────────────────────────────────────────────────

/// Manages a pool of browser profiles.
pub struct ProfilePool {
    pub profiles: Vec<ManagedProfile>,
    pub profiles_dir: PathBuf,
    pub max_profiles: usize,
}

impl ProfilePool {
    pub fn new(profiles_dir: PathBuf, max_profiles: usize) -> Self {
        Self {
            profiles: Vec::new(),
            profiles_dir,
            max_profiles,
        }
    }

    /// Get a ready profile, creating one if needed.
    pub fn get_ready_profile(&mut self) -> Option<&mut ManagedProfile> {
        // Find an existing ready profile
        if let Some(idx) = self.profiles.iter().position(|p| p.state == ProfileState::Ready) {
            return Some(&mut self.profiles[idx]);
        }

        // Create a new one if under limit
        if self.profiles.len() < self.max_profiles {
            let idx = self.profiles.len();
            let data_dir = self.profiles_dir.join(format!("profile-{idx}"));
            let ua = crate::browser::stealth::StealthProfile::chrome_windows().user_agent;
            self.profiles.push(ManagedProfile::new(data_dir, &ua));
            return self.profiles.last_mut();
        }

        None
    }

    /// Clean up retired profiles.
    pub fn cleanup(&mut self) {
        self.profiles.retain(|p| p.state != ProfileState::Retired);
    }

    /// Count profiles by state.
    pub fn stats(&self) -> (usize, usize, usize, usize) {
        let ready = self.profiles.iter().filter(|p| p.state == ProfileState::Ready).count();
        let fresh = self.profiles.iter().filter(|p| p.state == ProfileState::Fresh).count();
        let flagged = self.profiles.iter().filter(|p| p.state == ProfileState::Flagged).count();
        let retired = self.profiles.iter().filter(|p| p.state == ProfileState::Retired).count();
        (ready, fresh, flagged, retired)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Retailer-specific warm-up presets
// ─────────────────────────────────────────────────────────────────────────────

/// Pre-built warm-up sequences for major retailers.
pub struct RetailerWarmup;

impl RetailerWarmup {
    pub fn amazon() -> WarmupSequence {
        WarmupSequence::domain_warmup(
            "https://www.amazon.com",
            &[
                "https://www.amazon.com/gp/bestsellers/",
                "https://www.amazon.com/deals",
            ],
        )
    }

    pub fn walmart() -> WarmupSequence {
        WarmupSequence::domain_warmup(
            "https://www.walmart.com",
            &[
                "https://www.walmart.com/shop/deals",
                "https://www.walmart.com/browse/electronics",
            ],
        )
    }

    pub fn target() -> WarmupSequence {
        WarmupSequence::domain_warmup(
            "https://www.target.com",
            &[
                "https://www.target.com/c/top-deals/-/N-2bfiy",
                "https://www.target.com/c/electronics/-/N-5xtg6",
            ],
        )
    }

    pub fn bestbuy() -> WarmupSequence {
        WarmupSequence::domain_warmup(
            "https://www.bestbuy.com",
            &[
                "https://www.bestbuy.com/site/top-deals/all-top-deals/pcmcat1563299784494.c",
            ],
        )
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Warmup execution engine
// ─────────────────────────────────────────────────────────────────────────────

/// Execute a full warm-up sequence against a live browser page.
///
/// Iterates through each [`WarmupStep`], navigating to the URL, dwelling for
/// a randomised duration (between `dwell_min_secs` and `dwell_max_secs`),
/// optionally scrolling the page, and optionally clicking a selector.
///
/// Failed steps are skipped with a warning log — the remaining steps still
/// execute so that partial warm-up is better than none.
pub async fn execute_warmup(
    page: &Page,
    sequence: &WarmupSequence,
) -> Result<(), BrowserError> {
    execute_warmup_with_persona(page, sequence, None).await
}

/// Persona-aware variant of [`execute_warmup`].
///
/// When `persona` is `Some`, dwell times and mouse/scroll jitter are drawn from a
/// seeded `StdRng` derived from the persona seed, so the SAME persona warms up
/// the same way every session. When `None`, the historical time-based jitter is
/// used (backward compatible).
pub async fn execute_warmup_with_persona(
    page: &Page,
    sequence: &WarmupSequence,
    persona: Option<&PersonaBehavior>,
) -> Result<(), BrowserError> {
    if sequence.steps.is_empty() {
        return Ok(());
    }

    let step_count = sequence.steps.len();
    eprintln!("[warmup] starting sequence '{}' ({} steps)", sequence.name, step_count);

    let mut jit = WarmupJitter::new(persona);

    for (i, step) in sequence.steps.iter().enumerate() {
        let step_num = i + 1;

        // ── Navigate ────────────────────────────────────────────────────
        match page.navigate(&step.url, WaitUntil::Load).await {
            Ok(_) => {}
            Err(e) => {
                eprintln!("[warmup] step {step_num} navigate failed ({}): {e}, skipping", step.url);
                continue;
            }
        }

        // ── Randomised dwell time ───────────────────────────────────────
        let dwell_secs = jit.dwell(step.dwell_min_secs, step.dwell_max_secs);
        let dwell = Duration::from_secs_f64(dwell_secs);

        // ── Mouse movement (simple jitter via scroll) ───────────────────
        if step.mouse_move {
            // Small random mouse-like scroll movements to create activity
            let micro_moves = 2 + (dwell_secs as u64 % 3);
            let interval = dwell / (micro_moves as u32 + 1);
            for _ in 0..micro_moves {
                tokio::time::sleep(interval).await;
                // Small vertical jitter — looks like casual reading
                let jitter_y = 20.0 + (jit.next_u32() % 60) as f64;
                let _ = page.scroll_by(0.0, jitter_y).await;
            }
            // Sleep remaining fraction
            tokio::time::sleep(interval).await;
        } else {
            tokio::time::sleep(dwell).await;
        }

        // ── Scroll down ─────────────────────────────────────────────────
        if step.scroll {
            let scroll_amount = 300.0 + (jit.next_u32() % 700) as f64;
            let _ = page.scroll_by(0.0, scroll_amount).await;
            // Brief pause after scroll
            tokio::time::sleep(Duration::from_millis(300 + (jit.next_u32() % 500) as u64)).await;
        }

        // ── Optional click ──────────────────────────────────────────────
        if let Some(ref selector) = step.click_selector {
            match page.query_selector(selector).await {
                Ok(Some(el)) => {
                    if el.click(ClickOptions::default()).await.is_ok() {
                        // Wait a moment for navigation/JS after click
                        tokio::time::sleep(Duration::from_millis(
                            500 + (jit.next_u32() % 1000) as u64,
                        ))
                        .await;
                    }
                }
                Ok(None) => {}
                Err(_) => {}
            }
        }

        // Step complete — no logging needed for non-error path
    }

    eprintln!("[warmup] sequence '{}' complete", sequence.name);
    Ok(())
}

impl ProfilePool {
    /// Warm up a fresh or stale profile using the provided browser page.
    ///
    /// Selects the appropriate [`WarmupSequence`] based on the profile's state
    /// (full for fresh profiles, abbreviated for stale ones), executes the
    /// sequence, and marks the profile as ready on success.
    ///
    /// Returns the profile index that was warmed up, or `None` if no profile
    /// needed warming.
    pub async fn warmup_next_profile(
        &mut self,
        page: &Page,
    ) -> Result<Option<usize>, BrowserError> {
        // Find a profile that needs warming up
        let idx = match self
            .profiles
            .iter()
            .position(|p| p.needs_warmup() && p.state != ProfileState::Retired)
        {
            Some(idx) => idx,
            None => return Ok(None),
        };

        let sequence = self.profiles[idx].warmup_type();
        self.profiles[idx].state = ProfileState::WarmingUp;

        match execute_warmup(page, &sequence).await {
            Ok(()) => {
                self.profiles[idx].mark_ready();
                Ok(Some(idx))
            }
            Err(e) => {
                // Warmup failed — revert to Fresh so it can be retried later
                self.profiles[idx].state = ProfileState::Fresh;
                eprintln!("[warmup] profile {idx} warmup failed: {e}");
                Err(e)
            }
        }
    }

    /// Warm up all profiles that need it, sequentially.
    ///
    /// Returns the count of profiles successfully warmed up.
    pub async fn warmup_all(&mut self, page: &Page) -> usize {
        let mut count = 0;
        loop {
            match self.warmup_next_profile(page).await {
                Ok(Some(_)) => count += 1,
                Ok(None) => break,
                Err(e) => {
                    eprintln!("[warmup] stopping warmup_all after failure: {e}");
                    break;
                }
            }
        }
        count
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Cheap pseudo-random u32 using system time. Not cryptographic — fine for
/// dwell jitter and scroll offsets.
fn rand_u32() -> u32 {
    use std::time::SystemTime;
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    // xorshift-style mix
    let mut x = nanos;
    x ^= x << 13;
    x ^= x >> 17;
    x ^= x << 5;
    x
}

/// Generate a randomised dwell time between min and max seconds.
fn randomised_dwell(min: f64, max: f64) -> f64 {
    if max <= min {
        return min;
    }
    let frac = (rand_u32() % 10000) as f64 / 10000.0;
    min + frac * (max - min)
}

/// Jitter source for warm-up dwell/timing.
///
/// When a persona is present, jitter is drawn from a seeded `StdRng` derived
/// from the persona seed so warm-up is deterministic per persona. Otherwise it
/// falls back to the historical time-based `rand_u32()` (backward compatible).
struct WarmupJitter {
    rng: Option<StdRng>,
}

impl WarmupJitter {
    fn new(persona: Option<&PersonaBehavior>) -> Self {
        // Mix the persona seed with a fixed salt so the warm-up stream is
        // distinct from the traffic-morph/behavioral streams of the same persona.
        let rng = persona.map(|p| StdRng::seed_from_u64(p.seed ^ 0x5EED_11A7));
        Self { rng }
    }

    /// Next u32 in the stream.
    fn next_u32(&mut self) -> u32 {
        match &mut self.rng {
            Some(rng) => rng.random_range(0..u32::MAX),
            None => rand_u32(),
        }
    }

    /// Randomised dwell time between min and max seconds.
    fn dwell(&mut self, min: f64, max: f64) -> f64 {
        if let Some(rng) = &mut self.rng {
            if max <= min {
                return min;
            }
            let frac: f64 = rng.random();
            min + frac * (max - min)
        } else {
            randomised_dwell(min, max)
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn warmup_sequences() {
        let essential = WarmupSequence::essential();
        assert_eq!(essential.steps.len(), 3);

        let standard = WarmupSequence::standard();
        assert_eq!(standard.steps.len(), 5);

        let full = WarmupSequence::full();
        assert_eq!(full.steps.len(), 7);

        let (min, max) = full.estimated_duration();
        assert!(min > 15.0);
        assert!(max > min);
    }

    #[test]
    fn profile_lifecycle() {
        let mut profile = ManagedProfile::new(PathBuf::from("/tmp/p1"), "Chrome/131");
        assert_eq!(profile.state, ProfileState::Fresh);
        assert!(profile.needs_warmup());

        profile.mark_ready();
        assert_eq!(profile.state, ProfileState::Ready);
        assert!(!profile.needs_warmup());

        profile.mark_session_done();
        assert_eq!(profile.session_count, 1);

        profile.mark_flagged();
        assert_eq!(profile.flag_count, 1);
        assert_eq!(profile.state, ProfileState::Flagged);
    }

    #[test]
    fn profile_retirement() {
        let mut profile = ManagedProfile::new(PathBuf::from("/tmp/p1"), "Chrome/131");
        profile.max_flags = 2;

        profile.mark_flagged();
        assert!(!profile.should_retire());

        profile.mark_flagged();
        assert!(profile.should_retire());
        assert_eq!(profile.state, ProfileState::Retired);
    }

    #[test]
    fn retailer_presets() {
        let amazon = RetailerWarmup::amazon();
        assert!(amazon.steps.len() >= 3);
        assert!(amazon.steps[0].url.contains("amazon.com"));

        let walmart = RetailerWarmup::walmart();
        assert!(walmart.steps[0].url.contains("walmart.com"));
    }
}
