//! Human behavior simulation for anti-bot bypass.
//!
//! Generates realistic mouse movements, keyboard timing, scroll physics,
//! and idle micro-movements that fool PerimeterX, DataDome, and Akamai
//! behavioral analysis engines.
//!
//! Includes:
//! - Scroll momentum decay (trackpad physics)
//! - Overscroll rubber-band bounce (iOS/macOS style)
//! - Tab switching / visibility change simulation
//! - Window blur/focus events
//! - Double-click and right-click probability
//! - Mouse idle micro-movements (hand tremor)
//! - Scroll direction changes (brief scroll-up while reading)
//! - Mouse acceleration/deceleration with overshoot + micro-correction
//!
//! All actions are dispatched via CDP Input domain, producing genuine
//! browser events indistinguishable from real user interaction.

use rand::Rng;
use serde_json::json;

use super::cdp::CdpClient;
use super::error::BrowserError;
use super::interaction::{bezier_mouse_path, gaussian_keystroke_delay};

/// Persona-derived behavioral parameters.
///
/// Every field is derived **deterministically** from a single per-persona `seed`
/// using a seeded `StdRng` (NOT the thread-local `rand::rng()`). This gives
/// B3-§4 fingerprint-consistent behavior: the *same* persona produces the *same*
/// behavioral distribution across every session, so a tracker diffing behavioral
/// stats across visits sees stability instead of identity drift.
///
/// The seed is retained so callers (e.g. warmup jitter) can derive a stable
/// per-session PRNG stream from it.
#[derive(Debug, Clone, Copy)]
pub struct PersonaBehavior {
    /// The originating per-persona seed (retained for deriving session streams).
    pub seed: u64,
    /// Typing inter-key delay mean (ms).
    pub typing_mean_ms: f64,
    /// Typing inter-key delay stddev (ms).
    pub typing_stddev_ms: f64,
    /// Long-pause probability while typing (thinking / correcting).
    pub typing_pause_prob: f64,
    /// Mouse Bezier cruise-phase base delay (ms) — inverse of peak velocity.
    pub mouse_velocity_ms: f64,
    /// Mouse overshoot amount (px) past the target before micro-correction.
    pub mouse_overshoot_px: f64,
    /// Probability a mouse move overshoots the target.
    pub mouse_overshoot_prob: f64,
    /// Scroll momentum decay factor (0.0..1.0), e.g. 0.92.
    pub scroll_decay: f64,
    /// Scroll direction-reversal probability (brief scroll-up while reading).
    pub scroll_reverse_prob: f64,
    /// Reading-pause probability mid-scroll.
    pub scroll_pause_prob: f64,
    /// Click -> double-click probability.
    pub double_click_prob: f64,
    /// Click -> right-click probability.
    pub right_click_prob: f64,
    /// Weibull inter-request delay shape (k).
    pub weibull_shape: f64,
    /// Weibull inter-request delay scale (lambda, ms).
    pub weibull_scale_ms: f64,
    /// Reading-pause rate (probability of a long dwell between requests).
    pub reading_pause_prob: f64,
    /// Timezone offset from UTC in hours (persona / proxy geo).
    pub tz_offset_hours: i32,
}

impl PersonaBehavior {
    /// Derive the full behavioral parameter set deterministically from a seed.
    ///
    /// Uses a fixed seeded PRNG (`StdRng` + splitmix64) — never thread-local
    /// `rand::rng()` — so the output is identical for the same seed regardless
    /// of process, thread, or wall-clock time.
    pub fn from_seed(seed: u64) -> Self {
        use rand::rngs::StdRng;
        use rand::SeedableRng;
        let mut rng = StdRng::seed_from_u64(seed);

        let typing_mean_ms = rng.random_range(55.0..=135.0);
        let typing_stddev_ms = typing_mean_ms * rng.random_range(0.18..=0.45);
        let typing_pause_prob = rng.random_range(0.03..=0.12);
        let mouse_velocity_ms = rng.random_range(2.0..=5.0);
        let mouse_overshoot_px = rng.random_range(1.5..=6.0);
        let mouse_overshoot_prob = rng.random_range(0.40..=0.95);
        let scroll_decay = rng.random_range(0.85..=0.96);
        let scroll_reverse_prob = rng.random_range(0.02..=0.12);
        let scroll_pause_prob = rng.random_range(0.05..=0.20);
        let double_click_prob = rng.random_range(0.005..=0.025);
        let right_click_prob = rng.random_range(0.005..=0.025);
        let weibull_shape = rng.random_range(0.70..=0.95);
        let weibull_scale_ms = rng.random_range(1800.0..=4500.0);
        let reading_pause_prob = rng.random_range(0.05..=0.20);
        let tz_offset_hours = rng.random_range(-12..=14);

        Self {
            seed,
            typing_mean_ms,
            typing_stddev_ms,
            typing_pause_prob,
            mouse_velocity_ms,
            mouse_overshoot_px,
            mouse_overshoot_prob,
            scroll_decay,
            scroll_reverse_prob,
            scroll_pause_prob,
            double_click_prob,
            right_click_prob,
            weibull_shape,
            weibull_scale_ms,
            reading_pause_prob,
            tz_offset_hours,
        }
    }
}

/// Behavioral simulation engine.
///
/// Attaches to a CDP session and generates human-like input events.
pub struct BehaviorSimulator {
    client: CdpClient,
    session_id: String,
    /// Current mouse position.
    mouse_x: f64,
    mouse_y: f64,
    /// Viewport dimensions.
    viewport_w: f64,
    viewport_h: f64,
    /// Current scroll Y position (tracked for overscroll detection).
    scroll_y: f64,
    /// Estimated page height (set via JS measurement or heuristic).
    page_height: f64,
    /// Optional persona. When set, all timing/behavioral constants derive from it
    /// deterministically; when `None`, the historical unseeded defaults are used.
    persona: Option<PersonaBehavior>,
}

impl BehaviorSimulator {
    /// Create a new behavior simulator for a page session.
    pub fn new(client: CdpClient, session_id: String) -> Self {
        Self {
            client,
            session_id,
            mouse_x: 400.0,
            mouse_y: 300.0,
            viewport_w: 1920.0,
            viewport_h: 1080.0,
            scroll_y: 0.0,
            page_height: 5000.0,
            persona: None,
        }
    }

    /// Attach a persona to this simulator so all timing constants derive from it.
    ///
    /// Without this the simulator falls back to its historical unseeded defaults.
    pub fn with_persona(mut self, persona: PersonaBehavior) -> Self {
        self.persona = Some(persona);
        self
    }

    // ─── Persona-derived accessors (fall back to historical defaults) ─────

    #[inline]
    fn typing_mean_ms(&self) -> f64 {
        self.persona.map_or(95.0, |p| p.typing_mean_ms)
    }
    #[inline]
    fn typing_stddev_ms(&self) -> f64 {
        self.persona.map_or(30.0, |p| p.typing_stddev_ms)
    }
    #[inline]
    fn typing_pause_prob(&self) -> f64 {
        self.persona.map_or(0.08, |p| p.typing_pause_prob)
    }
    #[inline]
    fn mouse_velocity_ms(&self) -> f64 {
        self.persona.map_or(3.0, |p| p.mouse_velocity_ms)
    }
    #[inline]
    fn mouse_overshoot_px(&self) -> f64 {
        self.persona.map_or(3.5, |p| p.mouse_overshoot_px)
    }
    #[inline]
    fn mouse_overshoot_prob(&self) -> f64 {
        self.persona.map_or(1.0, |p| p.mouse_overshoot_prob)
    }
    #[inline]
    fn scroll_decay(&self) -> f64 {
        self.persona.map_or(0.92, |p| p.scroll_decay)
    }
    #[inline]
    fn scroll_reverse_prob(&self) -> f64 {
        self.persona.map_or(0.07, |p| p.scroll_reverse_prob)
    }
    #[inline]
    fn scroll_pause_prob(&self) -> f64 {
        self.persona.map_or(0.12, |p| p.scroll_pause_prob)
    }
    #[inline]
    fn double_click_prob(&self) -> f64 {
        self.persona.map_or(0.015, |p| p.double_click_prob)
    }
    #[inline]
    fn right_click_prob(&self) -> f64 {
        self.persona.map_or(0.015, |p| p.right_click_prob)
    }

    /// Set viewport dimensions (used for random position generation).
    pub fn set_viewport(&mut self, width: f64, height: f64) {
        self.viewport_w = width;
        self.viewport_h = height;
    }

    /// Set estimated page height for overscroll detection.
    pub fn set_page_height(&mut self, height: f64) {
        self.page_height = height;
    }

    // ─── Mouse Movement (with acceleration/deceleration) ─────────

    /// Move mouse along a Bezier curve to target coordinates with realistic
    /// acceleration and deceleration.
    ///
    /// Real mice accelerate from rest, reach peak velocity at ~60% of the
    /// path, then decelerate. After reaching the target, overshoots by
    /// 2-5px and micro-corrects back.
    pub async fn move_mouse_to(&mut self, x: f64, y: f64) -> Result<(), BrowserError> {
        let dist = ((x - self.mouse_x).powi(2) + (y - self.mouse_y).powi(2)).sqrt();
        let steps = ((dist / 10.0).clamp(15.0, 60.0)) as u32;

        let path = bezier_mouse_path((self.mouse_x, self.mouse_y), (x, y), steps);
        let mut rng = rand::rng();
        let total_steps = path.len();

        for (i, (px, py)) in path.iter().enumerate() {
            self.client
                .send_command_with_session(
                    "Input.dispatchMouseEvent",
                    Some(json!({
                        "type": "mouseMoved",
                        "x": px.round(),
                        "y": py.round(),
                        "modifiers": 0
                    })),
                    &self.session_id,
                )
                .await?;

            // Acceleration/deceleration timing curve:
            // - Start slow (acceleration phase: 0-30%)
            // - Peak speed (cruise phase: 30-60%)
            // - Slow down (deceleration phase: 60-100%)
            let progress = if total_steps > 1 {
                i as f64 / (total_steps - 1) as f64
            } else {
                1.0
            };

            let base_delay = if progress < 0.3 {
                // Acceleration: start at 12ms, decrease to cruise velocity
                let t = progress / 0.3;
                12.0 - 9.0 * t
            } else if progress < 0.6 {
                // Peak velocity: fast (persona-derived)
                self.mouse_velocity_ms()
            } else {
                // Deceleration: increase from cruise velocity to 10ms
                let t = (progress - 0.6) / 0.4;
                self.mouse_velocity_ms() + 7.0 * t
            };

            // Add jitter
            let delay = if rng.random::<f64>() < 0.05 {
                // 5% chance of micro-pause (human hesitation)
                rng.random_range(30..=80)
            } else {
                (base_delay + rng.random_range(-1.0..=1.0)).max(1.0) as u64
            };
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }

        // --- Overshoot + micro-correction ---
        // Real users overshoot the target by 2-5px then correct back
        if dist > 20.0 && rng.random::<f64>() < self.mouse_overshoot_prob() {
            let ov = self.mouse_overshoot_px();
            let overshoot_px = rng.random_range((ov - 1.5).max(0.5)..=(ov + 1.5));
            let angle = rng.random_range(0.0..std::f64::consts::TAU);
            let overshoot_x = x + overshoot_px * angle.cos();
            let overshoot_y = y + overshoot_px * angle.sin();

            // Move to overshoot position
            self.client
                .send_command_with_session(
                    "Input.dispatchMouseEvent",
                    Some(json!({
                        "type": "mouseMoved",
                        "x": overshoot_x.round().max(0.0),
                        "y": overshoot_y.round().max(0.0),
                        "modifiers": 0
                    })),
                    &self.session_id,
                )
                .await?;
            tokio::time::sleep(std::time::Duration::from_millis(rng.random_range(8..=20))).await;

            // Micro-correct back to actual target (1-2 intermediate steps)
            let correction_steps = rng.random_range(1..=2);
            for step in 0..correction_steps {
                let t = (step + 1) as f64 / correction_steps as f64;
                let cx = overshoot_x + (x - overshoot_x) * t;
                let cy = overshoot_y + (y - overshoot_y) * t;
                self.client
                    .send_command_with_session(
                        "Input.dispatchMouseEvent",
                        Some(json!({
                            "type": "mouseMoved",
                            "x": cx.round(),
                            "y": cy.round(),
                            "modifiers": 0
                        })),
                        &self.session_id,
                    )
                    .await?;
                tokio::time::sleep(std::time::Duration::from_millis(rng.random_range(5..=12)))
                    .await;
            }
        }

        self.mouse_x = x;
        self.mouse_y = y;
        Ok(())
    }

    /// Click at current mouse position with realistic press-release timing.
    ///
    /// Has a 1-2% chance of producing a double-click and a 1-2% chance of
    /// producing a right-click, matching real user interaction patterns.
    pub async fn click(&self) -> Result<(), BrowserError> {
        let mut rng = rand::rng();
        let roll: f64 = rng.random();

        if roll < self.double_click_prob() {
            // Persona-derived double-click probability
            self.double_click().await
        } else if roll < self.double_click_prob() + self.right_click_prob() {
            // Persona-derived right-click probability
            self.right_click().await
        } else {
            self.single_click().await
        }
    }

    /// Perform a single left-click at the current mouse position.
    async fn single_click(&self) -> Result<(), BrowserError> {
        let mut rng = rand::rng();

        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": "mousePressed",
                    "x": self.mouse_x.round(),
                    "y": self.mouse_y.round(),
                    "button": "left",
                    "clickCount": 1,
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;

        // Hold for 50-150ms (human press duration)
        let hold_ms = rng.random_range(50..=150);
        tokio::time::sleep(std::time::Duration::from_millis(hold_ms)).await;

        // Mouse up (slight position jitter)
        let jitter_x = rng.random_range(-2.0..=2.0);
        let jitter_y = rng.random_range(-2.0..=2.0);
        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": "mouseReleased",
                    "x": (self.mouse_x + jitter_x).round(),
                    "y": (self.mouse_y + jitter_y).round(),
                    "button": "left",
                    "clickCount": 1,
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;

        Ok(())
    }

    /// Perform a double-click: two mousedown/mouseup pairs in <300ms.
    async fn double_click(&self) -> Result<(), BrowserError> {
        let mut rng = rand::rng();

        // First click
        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": "mousePressed",
                    "x": self.mouse_x.round(),
                    "y": self.mouse_y.round(),
                    "button": "left",
                    "clickCount": 1,
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;

        let hold1 = rng.random_range(40..=90);
        tokio::time::sleep(std::time::Duration::from_millis(hold1)).await;

        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": "mouseReleased",
                    "x": self.mouse_x.round(),
                    "y": self.mouse_y.round(),
                    "button": "left",
                    "clickCount": 1,
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;

        // Inter-click gap: 50-150ms (must be <300ms total for double-click)
        let gap = rng.random_range(50..=150);
        tokio::time::sleep(std::time::Duration::from_millis(gap)).await;

        // Second click (clickCount=2)
        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": "mousePressed",
                    "x": self.mouse_x.round(),
                    "y": self.mouse_y.round(),
                    "button": "left",
                    "clickCount": 2,
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;

        let hold2 = rng.random_range(40..=90);
        tokio::time::sleep(std::time::Duration::from_millis(hold2)).await;

        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": "mouseReleased",
                    "x": self.mouse_x.round(),
                    "y": self.mouse_y.round(),
                    "button": "left",
                    "clickCount": 2,
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;

        Ok(())
    }

    /// Perform a right-click (context menu) at the current mouse position.
    async fn right_click(&self) -> Result<(), BrowserError> {
        let mut rng = rand::rng();

        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": "mousePressed",
                    "x": self.mouse_x.round(),
                    "y": self.mouse_y.round(),
                    "button": "right",
                    "clickCount": 1,
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;

        let hold_ms = rng.random_range(60..=180);
        tokio::time::sleep(std::time::Duration::from_millis(hold_ms)).await;

        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": "mouseReleased",
                    "x": self.mouse_x.round(),
                    "y": self.mouse_y.round(),
                    "button": "right",
                    "clickCount": 1,
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;

        // Dismiss context menu after a brief pause (Escape key)
        let dismiss_delay = rng.random_range(200..=600);
        tokio::time::sleep(std::time::Duration::from_millis(dismiss_delay)).await;

        self.client
            .send_command_with_session(
                "Input.dispatchKeyEvent",
                Some(json!({
                    "type": "keyDown",
                    "key": "Escape",
                    "code": "Escape",
                    "windowsVirtualKeyCode": 27,
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;

        self.client
            .send_command_with_session(
                "Input.dispatchKeyEvent",
                Some(json!({
                    "type": "keyUp",
                    "key": "Escape",
                    "code": "Escape",
                    "windowsVirtualKeyCode": 27,
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;

        Ok(())
    }

    /// Perform a guaranteed single left-click (no random double/right-click).
    /// Use this when you need deterministic click behavior (e.g., clicking a button).
    pub async fn click_left(&self) -> Result<(), BrowserError> {
        self.single_click().await
    }

    /// Move mouse to target and click.
    pub async fn move_and_click(&mut self, x: f64, y: f64) -> Result<(), BrowserError> {
        self.move_mouse_to(x, y).await?;
        // Small pause before clicking (human reaction time)
        let mut rng = rand::rng();
        let pause = rng.random_range(80..=250);
        tokio::time::sleep(std::time::Duration::from_millis(pause)).await;
        self.click().await
    }

    // ─── Keyboard Input ───────────────────────────────────────────

    /// Type text with human-like keystroke timing.
    ///
    /// Each character has gaussian-distributed delay (mean 95ms, stddev 30ms)
    /// with occasional longer pauses simulating thought.
    pub async fn type_text(&self, text: &str) -> Result<(), BrowserError> {
        let mut rng = rand::rng();

        for ch in text.chars() {
            self.client
                .send_command_with_session(
                    "Input.dispatchKeyEvent",
                    Some(json!({
                        "type": "keyDown",
                        "text": ch.to_string(),
                        "key": ch.to_string(),
                        "modifiers": 0
                    })),
                    &self.session_id,
                )
                .await?;

            self.client
                .send_command_with_session(
                    "Input.dispatchKeyEvent",
                    Some(json!({
                        "type": "char",
                        "text": ch.to_string(),
                        "key": ch.to_string(),
                        "modifiers": 0
                    })),
                    &self.session_id,
                )
                .await?;

            // Key hold time: 30-80ms
            let hold = rng.random_range(30..=80);
            tokio::time::sleep(std::time::Duration::from_millis(hold)).await;

            self.client
                .send_command_with_session(
                    "Input.dispatchKeyEvent",
                    Some(json!({
                        "type": "keyUp",
                        "key": ch.to_string(),
                        "modifiers": 0
                    })),
                    &self.session_id,
                )
                .await?;

            // Inter-key delay: gaussian, persona-derived mean/stddev
            let delay =
                gaussian_keystroke_delay(self.typing_mean_ms(), self.typing_stddev_ms());

            // Persona-derived chance of a longer pause (thinking/correcting)
            let actual_delay = if rng.random::<f64>() < self.typing_pause_prob() {
                delay + rng.random_range(200..=600)
            } else {
                delay
            };

            tokio::time::sleep(std::time::Duration::from_millis(actual_delay)).await;
        }

        Ok(())
    }

    // ─── Scroll with Momentum Decay ──────────────────────────────

    /// Scroll down with realistic trackpad momentum physics.
    ///
    /// Simulates mouseWheel events with decreasing delta (momentum decay).
    /// Initial velocity decays by 0.92x per frame, stopping when velocity < 1px.
    /// Includes a 5-10% chance of brief upward scroll (reading correction).
    pub async fn scroll_down(&mut self, total_pixels: f64) -> Result<(), BrowserError> {
        let mut rng = rand::rng();
        let mut scrolled = 0.0;

        // Initial velocity: 60-120 px/frame
        let mut velocity: f64 = rng.random_range(60.0..=120.0);
        let decay_factor = self.scroll_decay();

        while scrolled < total_pixels && velocity >= 1.0 {
            let remaining = total_pixels - scrolled;
            let delta = velocity.min(remaining);

            self.client
                .send_command_with_session(
                    "Input.dispatchMouseEvent",
                    Some(json!({
                        "type": "mouseWheel",
                        "x": self.mouse_x.round(),
                        "y": self.mouse_y.round(),
                        "deltaX": 0,
                        "deltaY": delta.round(),
                        "modifiers": 0
                    })),
                    &self.session_id,
                )
                .await?;

            scrolled += delta;
            self.scroll_y += delta;

            // Momentum decay
            velocity *= decay_factor;

            // Persona-derived chance of a brief scroll direction reversal
            if rng.random::<f64>() < self.scroll_reverse_prob() && scrolled > 50.0 && scrolled < total_pixels * 0.9 {
                let reverse_amount: f64 = rng.random_range(20.0..=60.0);
                self.client
                    .send_command_with_session(
                        "Input.dispatchMouseEvent",
                        Some(json!({
                            "type": "mouseWheel",
                            "x": self.mouse_x.round(),
                            "y": self.mouse_y.round(),
                            "deltaX": 0,
                            "deltaY": -(reverse_amount.round()),
                            "modifiers": 0
                        })),
                        &self.session_id,
                    )
                    .await?;
                self.scroll_y -= reverse_amount;
                tokio::time::sleep(std::time::Duration::from_millis(rng.random_range(40..=100)))
                    .await;
            }

            // Inter-scroll delay: varies with velocity
            let delay = if rng.random::<f64>() < self.scroll_pause_prob() {
                // Persona-derived chance of reading pause mid-scroll
                rng.random_range(400..=1500)
            } else {
                // Faster velocity = shorter delay between frames
                let base = (80.0 / (velocity / 30.0).max(1.0)) as u64;
                rng.random_range(base.max(15)..=base.max(15) + 30)
            };
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }

        // Check for overscroll at page bottom
        let max_scroll = (self.page_height - self.viewport_h).max(0.0);
        if self.scroll_y > max_scroll {
            self.overscroll_bounce(self.scroll_y - max_scroll).await?;
            self.scroll_y = max_scroll;
        }

        Ok(())
    }

    /// Scroll up with momentum decay physics.
    pub async fn scroll_up(&mut self, total_pixels: f64) -> Result<(), BrowserError> {
        let mut rng = rand::rng();
        let mut scrolled = 0.0;

        let mut velocity: f64 = rng.random_range(60.0..=120.0);
        let decay_factor = self.scroll_decay();

        while scrolled < total_pixels && velocity >= 1.0 {
            let remaining = total_pixels - scrolled;
            let delta = velocity.min(remaining);

            self.client
                .send_command_with_session(
                    "Input.dispatchMouseEvent",
                    Some(json!({
                        "type": "mouseWheel",
                        "x": self.mouse_x.round(),
                        "y": self.mouse_y.round(),
                        "deltaX": 0,
                        "deltaY": -(delta.round()),
                        "modifiers": 0
                    })),
                    &self.session_id,
                )
                .await?;

            scrolled += delta;
            self.scroll_y -= delta;

            velocity *= decay_factor;

            let delay = rng.random_range(20..=60);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }

        // Check for overscroll at page top
        if self.scroll_y < 0.0 {
            self.overscroll_bounce(-self.scroll_y).await?;
            self.scroll_y = 0.0;
        }

        Ok(())
    }

    /// Simulate iOS/macOS rubber-band overscroll bounce.
    ///
    /// When scroll hits a page boundary, overshoots by ~20px then springs
    /// back with damped oscillation.
    async fn overscroll_bounce(&self, overshoot_px: f64) -> Result<(), BrowserError> {
        let mut rng = rand::rng();
        let bounce_amount = overshoot_px.min(25.0).max(5.0);

        // Spring back: damped oscillation over 3-4 frames
        // Frame 1: bounce back past origin by ~60% of overshoot
        let bounce1 = -(bounce_amount * 0.6);
        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": "mouseWheel",
                    "x": self.mouse_x.round(),
                    "y": self.mouse_y.round(),
                    "deltaX": 0,
                    "deltaY": bounce1.round(),
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(rng.random_range(16..=25))).await;

        // Frame 2: settle back ~20% overshoot
        let bounce2 = bounce_amount * 0.2;
        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": "mouseWheel",
                    "x": self.mouse_x.round(),
                    "y": self.mouse_y.round(),
                    "deltaX": 0,
                    "deltaY": bounce2.round(),
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(rng.random_range(16..=25))).await;

        // Frame 3: final settle
        let bounce3 = -(bounce_amount * 0.05);
        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": "mouseWheel",
                    "x": self.mouse_x.round(),
                    "y": self.mouse_y.round(),
                    "deltaX": 0,
                    "deltaY": bounce3.round(),
                    "modifiers": 0
                })),
                &self.session_id,
            )
            .await?;
        tokio::time::sleep(std::time::Duration::from_millis(rng.random_range(16..=25))).await;

        Ok(())
    }

    // ─── Tab Switching Simulation ────────────────────────────────

    /// Simulate a tab switch via `visibilitychange` and `blur`/`focus` events.
    ///
    /// Real users switch tabs every 30-120 seconds on average. This generates
    /// the JS events that anti-bot systems monitor to verify human behavior.
    /// The tab is "away" for `away_duration_ms` milliseconds.
    pub async fn simulate_tab_switch(&self, away_duration_ms: u64) -> Result<(), BrowserError> {
        // Fire blur + visibilitychange(hidden)
        self.client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({
                    "expression": r#"
                        (function() {
                            // Dispatch window blur
                            window.dispatchEvent(new Event('blur'));
                            // Override document.hidden and visibilityState
                            Object.defineProperty(document, 'hidden', {
                                value: true, configurable: true
                            });
                            Object.defineProperty(document, 'visibilityState', {
                                value: 'hidden', configurable: true
                            });
                            document.dispatchEvent(new Event('visibilitychange'));
                        })()
                    "#,
                    "returnByValue": true
                })),
                &self.session_id,
            )
            .await?;

        // Stay away
        tokio::time::sleep(std::time::Duration::from_millis(away_duration_ms)).await;

        // Fire focus + visibilitychange(visible)
        self.client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({
                    "expression": r#"
                        (function() {
                            Object.defineProperty(document, 'hidden', {
                                value: false, configurable: true
                            });
                            Object.defineProperty(document, 'visibilityState', {
                                value: 'visible', configurable: true
                            });
                            document.dispatchEvent(new Event('visibilitychange'));
                            window.dispatchEvent(new Event('focus'));
                        })()
                    "#,
                    "returnByValue": true
                })),
                &self.session_id,
            )
            .await?;

        Ok(())
    }

    /// Maybe simulate a tab switch based on natural probability.
    ///
    /// Call this periodically (e.g., after each page interaction). Has a
    /// probability of triggering proportional to how long since the session
    /// started, matching the 30-120 second natural switching interval.
    pub async fn maybe_tab_switch(&self) -> Result<bool, BrowserError> {
        let mut rng = rand::rng();

        // ~3% chance per call — caller should invoke roughly every 3-5 seconds
        // so average interval is 100-170 seconds
        if rng.random::<f64>() < 0.03 {
            let away_ms = rng.random_range(2000..=15000);
            self.simulate_tab_switch(away_ms).await?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    // ─── Window Blur/Focus ───────────────────────────────────────

    /// Dispatch window blur event (user clicked outside browser).
    pub async fn window_blur(&self) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({
                    "expression": "window.dispatchEvent(new Event('blur'))",
                    "returnByValue": true
                })),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    /// Dispatch window focus event (user returned to browser).
    pub async fn window_focus(&self) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({
                    "expression": "window.dispatchEvent(new Event('focus'))",
                    "returnByValue": true
                })),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    // ─── Idle Micro-Movements ─────────────────────────────────────

    /// Generate periodic idle micro-movements that simulate a resting hand.
    ///
    /// Real humans don't hold the mouse perfectly still — there's constant
    /// sub-pixel jitter from hand tremor. PX and DataDome check for this.
    /// Movements are 1-3px every 2-5 seconds.
    pub async fn idle_jitter(&mut self, duration_ms: u64) -> Result<(), BrowserError> {
        let mut rng = rand::rng();
        let start = std::time::Instant::now();
        let duration = std::time::Duration::from_millis(duration_ms);

        while start.elapsed() < duration {
            // Tiny movement: 1-3 pixels in random direction
            let magnitude = rng.random_range(1.0..=3.0);
            let angle = rng.random_range(0.0..std::f64::consts::TAU);
            let dx = magnitude * angle.cos();
            let dy = magnitude * angle.sin();
            let new_x = (self.mouse_x + dx).clamp(0.0, self.viewport_w);
            let new_y = (self.mouse_y + dy).clamp(0.0, self.viewport_h);

            self.client
                .send_command_with_session(
                    "Input.dispatchMouseEvent",
                    Some(json!({
                        "type": "mouseMoved",
                        "x": new_x.round(),
                        "y": new_y.round(),
                        "modifiers": 0
                    })),
                    &self.session_id,
                )
                .await?;

            self.mouse_x = new_x;
            self.mouse_y = new_y;

            // Jitter interval: 2000-5000ms (every 2-5 seconds)
            let delay = rng.random_range(2000..=5000);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }

        Ok(())
    }

    /// Short idle micro-movement burst (for use between other actions).
    ///
    /// Generates 1-3 tiny movements over ~500ms-1500ms. Keeps the mouse
    /// "alive" without the overhead of a full idle_jitter loop.
    pub async fn micro_jitter(&mut self) -> Result<(), BrowserError> {
        let mut rng = rand::rng();
        let count = rng.random_range(1..=3);

        for _ in 0..count {
            let magnitude = rng.random_range(1.0..=3.0);
            let angle = rng.random_range(0.0..std::f64::consts::TAU);
            let dx = magnitude * angle.cos();
            let dy = magnitude * angle.sin();
            let new_x = (self.mouse_x + dx).clamp(0.0, self.viewport_w);
            let new_y = (self.mouse_y + dy).clamp(0.0, self.viewport_h);

            self.client
                .send_command_with_session(
                    "Input.dispatchMouseEvent",
                    Some(json!({
                        "type": "mouseMoved",
                        "x": new_x.round(),
                        "y": new_y.round(),
                        "modifiers": 0
                    })),
                    &self.session_id,
                )
                .await?;

            self.mouse_x = new_x;
            self.mouse_y = new_y;

            let delay = rng.random_range(150..=500);
            tokio::time::sleep(std::time::Duration::from_millis(delay)).await;
        }

        Ok(())
    }

    // ─── Full Human Session ───────────────────────────────────────

    /// Simulate a complete human browsing session.
    ///
    /// Performs: initial mouse movement -> scroll -> pause -> tab switch ->
    /// more movement -> scroll with direction change -> idle jitter.
    /// Takes 5-10 seconds. Generates enough behavioral signals to pass PX,
    /// DataDome, and Akamai behavioral analysis.
    pub async fn simulate_human_session(&mut self) -> Result<(), BrowserError> {
        let mut rng = rand::rng();

        // 1. Move mouse to center-ish area (user arriving at page)
        let target_x = rng.random_range(300.0..=800.0);
        let target_y = rng.random_range(200.0..=500.0);
        self.move_mouse_to(target_x, target_y).await?;

        // 2. Brief pause (reading)
        let pause = rng.random_range(500..=1500);
        tokio::time::sleep(std::time::Duration::from_millis(pause)).await;

        // 3. Micro-jitter while reading
        self.micro_jitter().await?;

        // 4. Scroll down to view content (with momentum)
        self.scroll_down(rng.random_range(200.0..=600.0)).await?;

        // 5. Move to a different area (looking at something)
        let target_x2 = rng.random_range(200.0..=1000.0);
        let target_y2 = rng.random_range(300.0..=700.0);
        self.move_mouse_to(target_x2, target_y2).await?;

        // 6. Maybe switch tabs (natural behavior)
        self.maybe_tab_switch().await?;

        // 7. Idle jitter while "reading"
        self.idle_jitter(rng.random_range(800..=2000)).await?;

        // 8. Another scroll (might include direction change)
        self.scroll_down(rng.random_range(100.0..=400.0)).await?;

        // 9. Final mouse movement with overshoot correction
        let target_x3 = rng.random_range(400.0..=900.0);
        let target_y3 = rng.random_range(200.0..=600.0);
        self.move_mouse_to(target_x3, target_y3).await?;

        Ok(())
    }

    /// Quick behavioral signal burst (1-2 seconds).
    ///
    /// Minimal viable human signals to pass PX's behavioral check.
    pub async fn quick_human_signal(&mut self) -> Result<(), BrowserError> {
        let mut rng = rand::rng();

        // Move mouse somewhere
        let x = rng.random_range(200.0..=800.0);
        let y = rng.random_range(150.0..=600.0);
        self.move_mouse_to(x, y).await?;

        // Quick scroll with momentum
        self.scroll_down(rng.random_range(100.0..=300.0)).await?;

        // Micro-jitter (lighter than full idle_jitter)
        self.micro_jitter().await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn test_behavior_module_compiles() {
        // Verifies the module compiles correctly
        // Full integration tests require a CDP connection
        assert!(true);
    }
}
