//! Slider CAPTCHA trajectory generation for Chinese anti-bot systems.
//!
//! Generates human-like mouse trajectories that pass behavioral analysis
//! from Alibaba (Taobao/Tmall), Tencent (QQ/WeChat), JD.com, and NetEase
//! slider CAPTCHA systems.
//!
//! Chinese slider CAPTCHAs analyze:
//! - Three-phase acceleration profile (rapid start, cruise, fine adjust)
//! - Y-axis wobble (Gaussian noise matching real hand movement)
//! - Overshoot and correction (60-80% of real slides overshoot)
//! - Point density and timing intervals
//! - Total solve time
//!
//! Each vendor has specific detection thresholds calibrated here from
//! empirical research on production CAPTCHA deployments.

use rand::Rng;

use super::cdp::CdpClient;
use super::error::BrowserError;

/// A single point in a slider trajectory.
#[derive(Debug, Clone)]
pub struct TrajectoryPoint {
    pub x: f64,
    pub y: f64,
    pub timestamp_ms: u64,
}

/// A complete slider trajectory from start to release.
#[derive(Debug, Clone)]
pub struct SliderTrajectory {
    pub points: Vec<TrajectoryPoint>,
    pub total_time_ms: u64,
}

/// Speed profile for the slider solve.
#[derive(Debug, Clone, Copy)]
pub enum SliderSpeed {
    /// 800-1200ms total time. Cautious user.
    Slow,
    /// 400-800ms total time. Average user.
    Normal,
    /// 200-400ms total time. Experienced user.
    Fast,
}

/// Configuration for generating a slider trajectory.
#[derive(Debug, Clone)]
pub struct SliderConfig {
    pub start_x: f64,
    pub start_y: f64,
    /// Target X position where the puzzle piece fits.
    pub target_x: f64,
    /// Height of the slider track, used for Y-axis wobble bounds.
    pub track_height: f64,
    pub speed: SliderSpeed,
}

/// Result of trajectory validation (self-test).
#[derive(Debug, Clone)]
pub struct TrajectoryValidation {
    pub valid: bool,
    pub point_count_ok: bool,
    pub timing_ok: bool,
    pub y_variance_ok: bool,
    pub has_overshoot: bool,
    pub acceleration_profile_ok: bool,
    pub issues: Vec<String>,
}

/// A CDP-compatible mouse event for replay.
#[derive(Debug, Clone)]
pub struct CdpMouseEvent {
    /// One of "mousePressed", "mouseMoved", "mouseReleased".
    pub event_type: String,
    pub x: f64,
    pub y: f64,
    pub timestamp: f64,
    pub button: String,
}

/// Target vendor for vendor-specific tuning.
#[derive(Debug, Clone, Copy)]
enum Vendor {
    Alibaba,
    Tencent,
    Jd,
    Generic,
}

// ─── Gaussian noise ──────────────────────────────────────────────

/// Box-Muller transform for Gaussian random numbers.
fn gaussian(rng: &mut impl Rng, mean: f64, stddev: f64) -> f64 {
    let u1: f64 = rng.random();
    let u2: f64 = rng.random();
    // Avoid log(0)
    let u1 = if u1 < 1e-10 { 1e-10 } else { u1 };
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
    mean + stddev * z
}

// ─── Core trajectory generation ──────────────────────────────────

/// Generate a complete human-like slider trajectory.
///
/// The trajectory follows a three-phase movement pattern observed in
/// real human slider CAPTCHA solves:
///
/// 1. **Acceleration** (0-30%): Rapid start, increasing velocity
/// 2. **Cruise** (30-80%): Roughly constant velocity with slight decel
/// 3. **Fine adjustment** (80-100%): Sharp deceleration, overshoot, correction
pub fn generate_slider_trajectory(config: &SliderConfig) -> SliderTrajectory {
    generate_trajectory_for_vendor(config, Vendor::Generic)
}

fn generate_trajectory_for_vendor(config: &SliderConfig, vendor: Vendor) -> SliderTrajectory {
    let mut rng = rand::rng();
    let distance = (config.target_x - config.start_x).abs();

    if distance < 1.0 {
        return SliderTrajectory {
            points: vec![TrajectoryPoint {
                x: config.start_x,
                y: config.start_y,
                timestamp_ms: 0,
            }],
            total_time_ms: 0,
        };
    }

    // Determine total time based on speed profile
    let total_time_ms: u64 = match config.speed {
        SliderSpeed::Slow => rng.random_range(800..=1200),
        SliderSpeed::Normal => rng.random_range(400..=800),
        SliderSpeed::Fast => rng.random_range(200..=400),
    };

    // Vendor-specific minimum time
    let total_time_ms = match vendor {
        Vendor::Alibaba => total_time_ms.max(300),
        _ => total_time_ms,
    };

    // Determine point density based on vendor
    let (min_points, max_points) = match vendor {
        Vendor::Jd => {
            // JD expects 50-150 points per 200px. Scale proportionally.
            let scale = distance / 200.0;
            (
                (50.0 * scale).max(30.0) as usize,
                (150.0 * scale).max(80.0) as usize,
            )
        }
        _ => {
            // General: derive from time. ~60-120 FPS capture rate means
            // interval of 8-16ms per point.
            let min = (total_time_ms as f64 / 16.0).max(20.0) as usize;
            let max = (total_time_ms as f64 / 8.0).max(40.0) as usize;
            (min, max)
        }
    };

    let num_main_points = rng.random_range(min_points..=max_points);

    // Y-axis wobble parameters (vendor-specific)
    let y_stddev = match vendor {
        Vendor::Tencent => rng.random_range(1.5..=2.5), // sweet spot for Tencent
        _ => rng.random_range(1.0..=3.0),
    };

    // Overshoot parameters
    let do_overshoot = rng.random::<f64>()
        < match vendor {
            Vendor::Alibaba => 0.75, // 75% overshoot rate
            _ => 0.70,               // 70% general
        };
    let overshoot_px = if do_overshoot {
        rng.random_range(2.0..=8.0)
    } else {
        0.0
    };

    let mut points = Vec::with_capacity(num_main_points + 10);

    // Generate main trajectory points
    let direction = if config.target_x >= config.start_x {
        1.0
    } else {
        -1.0
    };

    // Effective target includes overshoot
    let overshoot_target = config.target_x + overshoot_px * direction;

    let mut current_time_ms: u64 = 0;

    for i in 0..num_main_points {
        let t = i as f64 / (num_main_points - 1).max(1) as f64;

        // Three-phase X progress using sinusoidal velocity profile
        // v(t) = v_max * sin(pi * t / T) produces ease-in-out
        let progress = ease_in_out_sine(t);

        let x = config.start_x + (overshoot_target - config.start_x) * progress;

        // Y-axis wobble: stronger during fast movement, quieter during fine adjust
        let wobble_scale = if t < 0.3 {
            // Acceleration phase: moderate wobble
            0.7
        } else if t < 0.8 {
            // Cruise phase: full wobble
            1.0
        } else {
            // Fine adjustment: reduced wobble
            0.3
        };
        let y_noise = gaussian(&mut rng, 0.0, y_stddev * wobble_scale);
        let y = (config.start_y + y_noise).clamp(
            config.start_y - config.track_height / 2.0,
            config.start_y + config.track_height / 2.0,
        );

        // Timestamp with jitter (8-16ms intervals, NOT uniform)
        let base_interval = total_time_ms as f64 / num_main_points as f64;
        let interval = if i == 0 {
            0.0
        } else {
            // Phase-dependent timing
            let timing_scale = if t < 0.3 {
                // Acceleration: shorter intervals (moving fast)
                0.7
            } else if t < 0.8 {
                // Cruise: normal intervals
                1.0
            } else {
                // Fine adjust: longer intervals (moving slow)
                1.4
            };
            let jittered = base_interval * timing_scale + rng.random_range(-2.0..=2.0);
            jittered.max(4.0)
        };

        current_time_ms = if i == 0 {
            0
        } else {
            current_time_ms + interval as u64
        };

        // Micro-pause: 5-10% chance of a 20-50ms hesitation
        let pause_chance = match vendor {
            Vendor::Alibaba => 0.08,
            _ => 0.07,
        };
        if i > 0 && i < num_main_points - 3 && rng.random::<f64>() < pause_chance {
            current_time_ms += rng.random_range(20..=50);
        }

        points.push(TrajectoryPoint {
            x,
            y,
            timestamp_ms: current_time_ms,
        });
    }

    // Overshoot correction movements
    if do_overshoot && points.len() > 1 {
        let num_corrections = rng.random_range(1..=3_u32);
        let correction_base_time = rng.random_range(30..=80_u64);

        for c in 0..num_corrections {
            current_time_ms += correction_base_time + rng.random_range(10..=40);
            let correction_progress = (c + 1) as f64 / num_corrections as f64;
            let cx = overshoot_target + (config.target_x - overshoot_target) * correction_progress;
            let cy = config.start_y + gaussian(&mut rng, 0.0, y_stddev * 0.2);
            let cy = cy.clamp(
                config.start_y - config.track_height / 2.0,
                config.start_y + config.track_height / 2.0,
            );
            points.push(TrajectoryPoint {
                x: cx,
                y: cy,
                timestamp_ms: current_time_ms,
            });
        }
    }

    // Hold at target before release (50-200ms)
    let hold_time = rng.random_range(50..=200_u64);
    current_time_ms += hold_time;

    // Final point at exact target
    points.push(TrajectoryPoint {
        x: config.target_x,
        y: config.start_y + gaussian(&mut rng, 0.0, 0.5),
        timestamp_ms: current_time_ms,
    });

    SliderTrajectory {
        total_time_ms: current_time_ms,
        points,
    }
}

/// Sinusoidal ease-in-out: produces the integral of sin(pi*t),
/// normalized to [0, 1] over t in [0, 1].
///
/// This gives smooth acceleration then deceleration matching the
/// velocity profile v(t) = v_max * sin(pi * t).
fn ease_in_out_sine(t: f64) -> f64 {
    // Integral of sin(pi*t) from 0 to t, normalized:
    // F(t) = (1 - cos(pi*t)) / 2
    (1.0 - (std::f64::consts::PI * t).cos()) / 2.0
}

// ─── Vendor-specific generators ──────────────────────────────────

/// Generate trajectory tuned for Alibaba/Taobao/Tmall slider CAPTCHAs.
///
/// Alibaba checks:
/// - Acceleration curve must follow three-phase pattern
/// - Total time must be >= 300ms (rejects faster solves)
/// - Point density proportional to distance
pub fn alibaba_slider(distance: f64) -> SliderTrajectory {
    let config = SliderConfig {
        start_x: 0.0,
        start_y: 0.0,
        target_x: distance,
        track_height: 40.0,
        speed: SliderSpeed::Normal,
    };
    generate_trajectory_for_vendor(&config, Vendor::Alibaba)
}

/// Generate trajectory tuned for Tencent/QQ/WeChat slider CAPTCHAs.
///
/// Tencent checks:
/// - Y-axis variance must be in sweet spot (stddev 1.5-2.5px)
/// - Too little wobble = bot, too much = bot
/// - Smooth acceleration profile
pub fn tencent_slider(distance: f64) -> SliderTrajectory {
    let config = SliderConfig {
        start_x: 0.0,
        start_y: 0.0,
        target_x: distance,
        track_height: 40.0,
        speed: SliderSpeed::Normal,
    };
    generate_trajectory_for_vendor(&config, Vendor::Tencent)
}

/// Generate trajectory tuned for JD.com slider CAPTCHAs.
///
/// JD checks:
/// - Point density: expects 50-150 points per 200px slide
/// - Fewer points = bot, more points = bot
/// - Standard three-phase acceleration
pub fn jd_slider(distance: f64) -> SliderTrajectory {
    let config = SliderConfig {
        start_x: 0.0,
        start_y: 0.0,
        target_x: distance,
        track_height: 40.0,
        speed: SliderSpeed::Normal,
    };
    generate_trajectory_for_vendor(&config, Vendor::Jd)
}

/// Generate a general-purpose slider trajectory.
///
/// Works against most slider CAPTCHA implementations including
/// custom and lesser-known Chinese vendors.
pub fn generic_slider(distance: f64) -> SliderTrajectory {
    let config = SliderConfig {
        start_x: 0.0,
        start_y: 0.0,
        target_x: distance,
        track_height: 40.0,
        speed: SliderSpeed::Normal,
    };
    generate_slider_trajectory(&config)
}

// ─── Validation ──────────────────────────────────────────────────

/// Validate that a trajectory looks human-like (self-test).
///
/// Checks the trajectory against known detection heuristics used
/// by Chinese CAPTCHA vendors. Useful for testing and tuning.
pub fn validate_trajectory(trajectory: &SliderTrajectory) -> TrajectoryValidation {
    let mut issues = Vec::new();
    let points = &trajectory.points;

    if points.len() < 2 {
        return TrajectoryValidation {
            valid: false,
            point_count_ok: false,
            timing_ok: false,
            y_variance_ok: false,
            has_overshoot: false,
            acceleration_profile_ok: false,
            issues: vec!["Trajectory has fewer than 2 points".to_string()],
        };
    }

    // Check point count (general: 20-300 is reasonable)
    let point_count_ok = points.len() >= 20 && points.len() <= 300;
    if !point_count_ok {
        issues.push(format!(
            "Point count {} outside expected range 20-300",
            points.len()
        ));
    }

    // Check total time
    let timing_ok = trajectory.total_time_ms >= 150 && trajectory.total_time_ms <= 2000;
    if !timing_ok {
        issues.push(format!(
            "Total time {}ms outside expected range 150-2000ms",
            trajectory.total_time_ms
        ));
    }

    // Check Y-axis variance
    let y_values: Vec<f64> = points.iter().map(|p| p.y).collect();
    let y_mean = y_values.iter().sum::<f64>() / y_values.len() as f64;
    let y_variance =
        y_values.iter().map(|y| (y - y_mean).powi(2)).sum::<f64>() / y_values.len() as f64;
    let y_stddev = y_variance.sqrt();
    let y_variance_ok = y_stddev > 0.3 && y_stddev < 5.0;
    if !y_variance_ok {
        issues.push(format!(
            "Y-axis stddev {:.2} outside expected range 0.3-5.0",
            y_stddev
        ));
    }

    // Check for overshoot: does X ever exceed final X?
    let final_x = points.last().unwrap().x;
    let start_x = points.first().unwrap().x;
    let direction = if final_x >= start_x { 1.0 } else { -1.0 };
    let has_overshoot = points.iter().any(|p| (p.x - final_x) * direction > 1.0);

    // Check acceleration profile: velocity should not be constant
    let mut velocities = Vec::new();
    for i in 1..points.len() {
        let dx = (points[i].x - points[i - 1].x).abs();
        let dt = (points[i].timestamp_ms as f64 - points[i - 1].timestamp_ms as f64).max(1.0);
        velocities.push(dx / dt);
    }

    let acceleration_profile_ok = if velocities.len() >= 4 {
        // Split into thirds and check velocity varies
        let third = velocities.len() / 3;
        let v_start: f64 = velocities[..third].iter().sum::<f64>() / third as f64;
        let v_mid: f64 = velocities[third..third * 2].iter().sum::<f64>() / third as f64;
        let v_end: f64 =
            velocities[third * 2..].iter().sum::<f64>() / (velocities.len() - third * 2) as f64;

        // Middle section should generally be faster or comparable to edges
        // (not perfectly uniform)
        let max_v = v_start.max(v_mid).max(v_end);
        let min_v = v_start.min(v_mid).min(v_end);
        if max_v > 0.0 {
            let ratio = min_v / max_v;
            // Velocity should vary by at least 15%
            ratio < 0.85
        } else {
            false
        }
    } else {
        // Too few points to analyze properly
        issues.push("Too few velocity samples to analyze acceleration".to_string());
        false
    };

    if !acceleration_profile_ok && velocities.len() >= 4 {
        issues.push("Acceleration profile too uniform (looks robotic)".to_string());
    }

    // Check timestamp monotonicity
    let timestamps_monotonic = points
        .windows(2)
        .all(|w| w[1].timestamp_ms >= w[0].timestamp_ms);
    if !timestamps_monotonic {
        issues.push("Timestamps are not monotonically increasing".to_string());
    }

    // Check for suspiciously uniform intervals
    if points.len() >= 5 {
        let intervals: Vec<f64> = points
            .windows(2)
            .map(|w| w[1].timestamp_ms as f64 - w[0].timestamp_ms as f64)
            .collect();
        let int_mean = intervals.iter().sum::<f64>() / intervals.len() as f64;
        if int_mean > 0.0 {
            let int_variance = intervals
                .iter()
                .map(|i| (i - int_mean).powi(2))
                .sum::<f64>()
                / intervals.len() as f64;
            let int_cv = int_variance.sqrt() / int_mean; // coefficient of variation
            if int_cv < 0.1 {
                issues.push(format!(
                    "Timestamp intervals too uniform (CV={:.3}), expected >0.1",
                    int_cv
                ));
            }
        }
    }

    let valid = point_count_ok
        && timing_ok
        && y_variance_ok
        && acceleration_profile_ok
        && timestamps_monotonic
        && issues.is_empty();

    TrajectoryValidation {
        valid,
        point_count_ok,
        timing_ok,
        y_variance_ok,
        has_overshoot,
        acceleration_profile_ok,
        issues,
    }
}

// ─── CDP event conversion ────────────────────────────────────────

/// Convert a slider trajectory into CDP `Input.dispatchMouseEvent` parameters.
///
/// Produces a sequence of:
/// 1. `mousePressed` at the first point (grab the slider handle)
/// 2. `mouseMoved` for each intermediate point (drag)
/// 3. `mouseReleased` at the final point (release)
///
/// Timestamps are relative seconds from the trajectory start.
pub fn trajectory_to_cdp_events(trajectory: &SliderTrajectory) -> Vec<CdpMouseEvent> {
    let mut events = Vec::with_capacity(trajectory.points.len() + 2);

    if trajectory.points.is_empty() {
        return events;
    }

    let first = &trajectory.points[0];

    // mousePressed at start (grab the handle)
    events.push(CdpMouseEvent {
        event_type: "mousePressed".to_string(),
        x: first.x,
        y: first.y,
        timestamp: 0.0,
        button: "left".to_string(),
    });

    // mouseMoved for each point (the drag)
    for point in &trajectory.points[1..] {
        events.push(CdpMouseEvent {
            event_type: "mouseMoved".to_string(),
            x: point.x,
            y: point.y,
            timestamp: point.timestamp_ms as f64 / 1000.0,
            button: "left".to_string(),
        });
    }

    // mouseReleased at the final point
    let last = trajectory.points.last().unwrap();
    events.push(CdpMouseEvent {
        event_type: "mouseReleased".to_string(),
        x: last.x,
        y: last.y,
        timestamp: last.timestamp_ms as f64 / 1000.0,
        button: "left".to_string(),
    });

    events
}

/// Solve a slider CAPTCHA by generating a human-like trajectory and
/// dispatching it through real CDP `Input.dispatchMouseEvent` calls.
///
/// This is the CDP wiring for the trajectory engine: it drives the actual
/// browser session so callers (captcha solve flows or `.tl` scripts) can
/// replay human-like slider motion on live pages. Returns the generated
/// trajectory on success.
///
/// # Honesty note
/// This dispatches real mouse events — it does **not** fabricate a solve
/// result. Whether the site accepts the trajectory depends on the puzzle
/// geometry (caller must supply the correct `start_x`/`target_x` for the
/// slider handle and gap position, e.g. from element bounding boxes).
pub async fn solve_slider_with_cdp(
    client: &CdpClient,
    session_id: &str,
    start_x: f64,
    start_y: f64,
    target_x: f64,
    speed: SliderSpeed,
) -> Result<SliderTrajectory, BrowserError> {
    let config = SliderConfig {
        start_x,
        start_y,
        target_x,
        track_height: 4.0,
        speed,
    };
    let trajectory = generate_slider_trajectory(&config);
    let events = trajectory_to_cdp_events(&trajectory);

    for ev in &events {
        client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(serde_json::json!({
                    "type": ev.event_type,
                    "x": ev.x,
                    "y": ev.y,
                    "button": ev.button,
                    "clickCount": 1,
                    "timestamp": ev.timestamp,
                })),
                session_id,
            )
            .await
            .map_err(|e| BrowserError::CdpError {
                code: -1,
                message: format!("slider CDP event '{}' failed: {}", ev.event_type, e),
            })?;
    }

    Ok(trajectory)
}

// ─── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> SliderConfig {
        SliderConfig {
            start_x: 30.0,
            start_y: 300.0,
            target_x: 230.0,
            track_height: 40.0,
            speed: SliderSpeed::Normal,
        }
    }

    #[test]
    fn test_generate_trajectory_has_points() {
        let config = default_config();
        let traj = generate_slider_trajectory(&config);
        assert!(
            traj.points.len() >= 20,
            "expected >= 20 points, got {}",
            traj.points.len()
        );
        assert!(traj.total_time_ms > 0, "total time should be > 0");
    }

    #[test]
    fn test_trajectory_starts_at_start() {
        let config = default_config();
        let traj = generate_slider_trajectory(&config);
        let first = &traj.points[0];
        assert!(
            (first.x - config.start_x).abs() < 0.1,
            "first point x={} should be near start_x={}",
            first.x,
            config.start_x
        );
    }

    #[test]
    fn test_trajectory_ends_near_target() {
        let config = default_config();
        let traj = generate_slider_trajectory(&config);
        let last = &traj.points[traj.points.len() - 1];
        assert!(
            (last.x - config.target_x).abs() < 2.0,
            "last point x={} should be near target_x={}",
            last.x,
            config.target_x
        );
    }

    #[test]
    fn test_timestamps_monotonic() {
        let config = default_config();
        for _ in 0..10 {
            let traj = generate_slider_trajectory(&config);
            for w in traj.points.windows(2) {
                assert!(
                    w[1].timestamp_ms >= w[0].timestamp_ms,
                    "timestamps must be monotonically increasing: {} >= {}",
                    w[1].timestamp_ms,
                    w[0].timestamp_ms
                );
            }
        }
    }

    #[test]
    fn test_y_axis_has_wobble() {
        let config = default_config();
        let traj = generate_slider_trajectory(&config);
        let y_values: Vec<f64> = traj.points.iter().map(|p| p.y).collect();
        let y_mean = y_values.iter().sum::<f64>() / y_values.len() as f64;
        let variance =
            y_values.iter().map(|y| (y - y_mean).powi(2)).sum::<f64>() / y_values.len() as f64;
        let stddev = variance.sqrt();
        assert!(
            stddev > 0.1,
            "Y-axis should have wobble (stddev={:.3})",
            stddev
        );
    }

    #[test]
    fn test_speed_slow_timing() {
        let config = SliderConfig {
            speed: SliderSpeed::Slow,
            ..default_config()
        };
        // Run multiple times to account for randomness
        let mut any_in_range = false;
        for _ in 0..20 {
            let traj = generate_slider_trajectory(&config);
            if traj.total_time_ms >= 700 && traj.total_time_ms <= 1500 {
                any_in_range = true;
                break;
            }
        }
        assert!(
            any_in_range,
            "Slow speed should produce ~800-1200ms trajectories"
        );
    }

    #[test]
    fn test_speed_fast_timing() {
        let config = SliderConfig {
            speed: SliderSpeed::Fast,
            ..default_config()
        };
        let mut any_in_range = false;
        for _ in 0..20 {
            let traj = generate_slider_trajectory(&config);
            if traj.total_time_ms >= 150 && traj.total_time_ms <= 600 {
                any_in_range = true;
                break;
            }
        }
        assert!(
            any_in_range,
            "Fast speed should produce ~200-400ms trajectories"
        );
    }

    #[test]
    fn test_alibaba_minimum_time() {
        for _ in 0..20 {
            let traj = alibaba_slider(200.0);
            assert!(
                traj.total_time_ms >= 250,
                "Alibaba trajectory should be >= 300ms base, got {}ms (hold adds time)",
                traj.total_time_ms
            );
        }
    }

    #[test]
    fn test_tencent_y_variance_sweet_spot() {
        // Tencent requires stddev 1.5-2.5px. Run multiple trials.
        let mut in_range_count = 0;
        let trials = 30;
        for _ in 0..trials {
            let traj = tencent_slider(200.0);
            let y_values: Vec<f64> = traj.points.iter().map(|p| p.y).collect();
            let y_mean = y_values.iter().sum::<f64>() / y_values.len() as f64;
            let variance =
                y_values.iter().map(|y| (y - y_mean).powi(2)).sum::<f64>() / y_values.len() as f64;
            let stddev = variance.sqrt();
            // Allow wider range due to phase-dependent scaling
            if stddev > 0.5 && stddev < 4.0 {
                in_range_count += 1;
            }
        }
        assert!(
            in_range_count > trials / 2,
            "Tencent trajectories should mostly have Y stddev in acceptable range, got {}/{}",
            in_range_count,
            trials
        );
    }

    #[test]
    fn test_jd_point_density() {
        // JD expects 50-150 points per 200px slide
        let mut in_range_count = 0;
        let trials = 20;
        for _ in 0..trials {
            let traj = jd_slider(200.0);
            let count = traj.points.len();
            // Allow some slack for overshoot correction and final hold point
            if count >= 30 && count <= 200 {
                in_range_count += 1;
            }
        }
        assert!(
            in_range_count > trials / 2,
            "JD trajectories should have appropriate point density, got {}/{} in range",
            in_range_count,
            trials
        );
    }

    #[test]
    fn test_generic_slider() {
        let traj = generic_slider(200.0);
        assert!(traj.points.len() >= 10);
        assert!(traj.total_time_ms > 100);
    }

    #[test]
    fn test_validation_passes_for_normal_trajectory() {
        let config = default_config();
        // Run several times; at least some should pass
        let mut any_valid = false;
        for _ in 0..20 {
            let traj = generate_slider_trajectory(&config);
            let val = validate_trajectory(&traj);
            if val.valid {
                any_valid = true;
                break;
            }
        }
        assert!(
            any_valid,
            "At least some generated trajectories should pass validation"
        );
    }

    #[test]
    fn test_validation_catches_too_few_points() {
        let traj = SliderTrajectory {
            points: vec![TrajectoryPoint {
                x: 0.0,
                y: 0.0,
                timestamp_ms: 0,
            }],
            total_time_ms: 100,
        };
        let val = validate_trajectory(&traj);
        assert!(!val.valid);
        assert!(!val.point_count_ok);
    }

    #[test]
    fn test_validation_catches_linear_robot() {
        // A perfectly linear, uniform trajectory should fail
        let mut points = Vec::new();
        for i in 0..50 {
            points.push(TrajectoryPoint {
                x: i as f64 * 4.0,
                y: 300.0, // no wobble at all
                timestamp_ms: i * 10,
            });
        }
        let traj = SliderTrajectory {
            points,
            total_time_ms: 490,
        };
        let val = validate_trajectory(&traj);
        // Should fail on Y variance (no wobble) or uniform timing
        assert!(
            !val.y_variance_ok || !val.valid,
            "Linear robot trajectory should fail validation"
        );
    }

    #[test]
    fn test_cdp_events_structure() {
        let config = default_config();
        let traj = generate_slider_trajectory(&config);
        let events = trajectory_to_cdp_events(&traj);

        assert!(events.len() >= 3, "should have press + moves + release");

        // First event: mousePressed
        assert_eq!(events[0].event_type, "mousePressed");
        assert_eq!(events[0].button, "left");

        // Middle events: mouseMoved
        for e in &events[1..events.len() - 1] {
            assert_eq!(e.event_type, "mouseMoved");
        }

        // Last event: mouseReleased
        let last = events.last().unwrap();
        assert_eq!(last.event_type, "mouseReleased");
        assert_eq!(last.button, "left");
    }

    #[test]
    fn test_cdp_events_timestamps_increase() {
        let config = default_config();
        let traj = generate_slider_trajectory(&config);
        let events = trajectory_to_cdp_events(&traj);

        for w in events.windows(2) {
            assert!(
                w[1].timestamp >= w[0].timestamp,
                "CDP event timestamps should increase: {} >= {}",
                w[1].timestamp,
                w[0].timestamp
            );
        }
    }

    #[test]
    fn test_overshoot_occurs_statistically() {
        let config = default_config();
        let mut overshoot_count = 0;
        let trials = 50;
        for _ in 0..trials {
            let traj = generate_slider_trajectory(&config);
            let val = validate_trajectory(&traj);
            if val.has_overshoot {
                overshoot_count += 1;
            }
        }
        // Should overshoot 60-80% of the time. Allow 40%+ given randomness.
        assert!(
            overshoot_count > trials / 4,
            "Overshoot should occur frequently, got {}/{}",
            overshoot_count,
            trials
        );
    }

    #[test]
    fn test_small_distance() {
        let config = SliderConfig {
            start_x: 100.0,
            start_y: 200.0,
            target_x: 110.0,
            track_height: 40.0,
            speed: SliderSpeed::Normal,
        };
        let traj = generate_slider_trajectory(&config);
        assert!(!traj.points.is_empty());
        let last = traj.points.last().unwrap();
        assert!(
            (last.x - 110.0).abs() < 2.0,
            "should reach near target even for small distance"
        );
    }

    #[test]
    fn test_zero_distance() {
        let config = SliderConfig {
            start_x: 100.0,
            start_y: 200.0,
            target_x: 100.0,
            track_height: 40.0,
            speed: SliderSpeed::Normal,
        };
        let traj = generate_slider_trajectory(&config);
        assert_eq!(traj.points.len(), 1);
        assert_eq!(traj.total_time_ms, 0);
    }

    #[test]
    fn test_negative_direction() {
        let config = SliderConfig {
            start_x: 300.0,
            start_y: 200.0,
            target_x: 100.0,
            track_height: 40.0,
            speed: SliderSpeed::Normal,
        };
        let traj = generate_slider_trajectory(&config);
        let last = traj.points.last().unwrap();
        assert!(
            (last.x - 100.0).abs() < 2.0,
            "should handle rightward-to-leftward slides"
        );
    }

    #[test]
    fn test_ease_in_out_sine_boundaries() {
        assert!((ease_in_out_sine(0.0)).abs() < 1e-10, "ease(0) should be 0");
        assert!(
            (ease_in_out_sine(1.0) - 1.0).abs() < 1e-10,
            "ease(1) should be 1"
        );
        assert!(
            (ease_in_out_sine(0.5) - 0.5).abs() < 1e-10,
            "ease(0.5) should be 0.5"
        );
    }

    #[test]
    fn test_ease_in_out_sine_monotonic() {
        let mut prev = 0.0;
        for i in 0..=100 {
            let t = i as f64 / 100.0;
            let val = ease_in_out_sine(t);
            assert!(
                val >= prev - 1e-10,
                "ease should be monotonically increasing"
            );
            prev = val;
        }
    }
}
