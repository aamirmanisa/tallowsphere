//! Interaction types for browser element and page operations.
//!
//! Provides types and constants for click operations, dropdown selection,
//! keyboard modifiers, and special key code mapping.

use std::time::Duration;

/// Options for click operations.
#[derive(Debug, Clone)]
pub struct ClickOptions {
    /// Which mouse button to use.
    pub button: MouseButton,
    /// Number of clicks: 1=single, 2=double, 3=triple.
    pub click_count: u32,
    /// Bitfield of active modifiers: Alt=1, Ctrl=2, Meta=4, Shift=8.
    pub modifiers: u32,
    /// Timeout for the auto-wait actionability check (visible + stable + enabled).
    /// Defaults to 30 seconds.
    pub timeout: Duration,
}

impl Default for ClickOptions {
    fn default() -> Self {
        ClickOptions {
            button: MouseButton::Left,
            click_count: 1,
            modifiers: 0,
            timeout: Duration::from_secs(30),
        }
    }
}

/// Mouse button for click operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Right,
    Middle,
}

impl MouseButton {
    /// Returns the CDP string representation of this button.
    pub fn as_str(&self) -> &'static str {
        match self {
            MouseButton::Left => "left",
            MouseButton::Right => "right",
            MouseButton::Middle => "middle",
        }
    }
}

/// How to select a dropdown option.
#[derive(Debug, Clone)]
pub enum SelectBy {
    /// Select by the `value` attribute of the option.
    Value(String),
    /// Select by numeric index (0-based).
    Index(usize),
    /// Select by visible text label.
    Label(String),
}

/// Keyboard modifier: Alt key.
pub const MODIFIER_ALT: u32 = 1;
/// Keyboard modifier: Ctrl key.
pub const MODIFIER_CTRL: u32 = 2;
/// Keyboard modifier: Meta key (Cmd on macOS, Win on Windows).
pub const MODIFIER_META: u32 = 4;
/// Keyboard modifier: Shift key.
pub const MODIFIER_SHIFT: u32 = 8;

/// Map special key names to their Windows virtual key codes.
///
/// Returns `None` for regular character keys.
pub fn special_key_code(key: &str) -> Option<u32> {
    match key {
        "Backspace" => Some(8),
        "Tab" => Some(9),
        "Enter" => Some(13),
        "Shift" => Some(16),
        "Control" => Some(17),
        "Alt" => Some(18),
        "Escape" => Some(27),
        "Space" | " " => Some(32),
        "PageUp" => Some(33),
        "PageDown" => Some(34),
        "End" => Some(35),
        "Home" => Some(36),
        "ArrowLeft" => Some(37),
        "ArrowUp" => Some(38),
        "ArrowRight" => Some(39),
        "ArrowDown" => Some(40),
        "Delete" => Some(46),
        "F1" => Some(112),
        "F2" => Some(113),
        "F3" => Some(114),
        "F4" => Some(115),
        "F5" => Some(116),
        "F6" => Some(117),
        "F7" => Some(118),
        "F8" => Some(119),
        "F9" => Some(120),
        "F10" => Some(121),
        "F11" => Some(122),
        "F12" => Some(123),
        _ => None,
    }
}

/// Generate a cubic Bezier mouse path with randomized control points.
///
/// The two control points are offset from the straight line between `from` and `to`
/// by a random amount (up to 30% of the total distance). Returns `steps` intermediate
/// points along the curve, always starting at `from` and ending at `to`.
///
/// Uses `rand::rng()` for control point randomization.
pub fn bezier_mouse_path(from: (f64, f64), to: (f64, f64), steps: u32) -> Vec<(f64, f64)> {
    use rand::Rng;

    if steps == 0 {
        return vec![];
    }
    if steps == 1 {
        return vec![to];
    }

    let mut rng = rand::rng();
    let dx = to.0 - from.0;
    let dy = to.1 - from.1;
    let dist = (dx * dx + dy * dy).sqrt();
    let max_offset = dist * 0.3;

    // Perpendicular direction for offsets
    let (px, py) = if dist > 0.0 {
        (-dy / dist, dx / dist)
    } else {
        (0.0, 0.0)
    };

    // Control point 1: ~1/3 along the line + perpendicular offset
    let offset1 = rng.random_range(-max_offset..=max_offset);
    let cp1 = (
        from.0 + dx * 0.25 + px * offset1,
        from.1 + dy * 0.25 + py * offset1,
    );

    // Control point 2: ~2/3 along the line + perpendicular offset
    let offset2 = rng.random_range(-max_offset..=max_offset);
    let cp2 = (
        from.0 + dx * 0.75 + px * offset2,
        from.1 + dy * 0.75 + py * offset2,
    );

    let mut points = Vec::with_capacity(steps as usize);
    for i in 0..steps {
        let t = if steps > 1 {
            i as f64 / (steps - 1) as f64
        } else {
            1.0
        };
        let inv = 1.0 - t;
        // Cubic Bezier: B(t) = (1-t)^3*P0 + 3*(1-t)^2*t*P1 + 3*(1-t)*t^2*P2 + t^3*P3
        let x = inv.powi(3) * from.0
            + 3.0 * inv.powi(2) * t * cp1.0
            + 3.0 * inv * t.powi(2) * cp2.0
            + t.powi(3) * to.0;
        let y = inv.powi(3) * from.1
            + 3.0 * inv.powi(2) * t * cp1.1
            + 3.0 * inv * t.powi(2) * cp2.1
            + t.powi(3) * to.1;
        points.push((x, y));
    }

    points
}

/// Generate a single keystroke delay (ms) from a gaussian distribution.
///
/// Uses the Box-Muller transform to generate normally distributed values.
/// The result is clamped to `[mean/3, mean*3]` to avoid extreme values.
///
/// Does NOT depend on `rand_distr` -- implements Box-Muller inline.
pub fn gaussian_keystroke_delay(mean_ms: f64, stddev_ms: f64) -> u64 {
    use rand::Rng;

    let mut rng = rand::rng();

    // Box-Muller transform
    let u1: f64 = rng.random::<f64>().max(f64::MIN_POSITIVE); // avoid ln(0)
    let u2: f64 = rng.random::<f64>();
    let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();

    let value = mean_ms + stddev_ms * z;

    // Clamp to [mean/3, mean*3]
    let min_val = mean_ms / 3.0;
    let max_val = mean_ms * 3.0;
    let clamped = value.clamp(min_val, max_val).round() as u64;
    clamped.max(1) // ensure at least 1ms
}

/// Build the JavaScript function string for a SelectBy variant.
///
/// The returned JS function is designed to be called via `Runtime.callFunctionOn`
/// on a `<select>` element. It sets the value and dispatches input + change events.
pub fn select_js_function(by: &SelectBy) -> String {
    match by {
        SelectBy::Value(val) => {
            let escaped = val.replace('\\', "\\\\").replace('\'', "\\'");
            format!(
                "function() {{ this.value = '{}'; this.dispatchEvent(new Event('input', {{bubbles: true}})); this.dispatchEvent(new Event('change', {{bubbles: true}})); }}",
                escaped
            )
        }
        SelectBy::Index(idx) => {
            format!(
                "function() {{ this.selectedIndex = {}; this.dispatchEvent(new Event('input', {{bubbles: true}})); this.dispatchEvent(new Event('change', {{bubbles: true}})); }}",
                idx
            )
        }
        SelectBy::Label(label) => {
            let escaped = label.replace('\\', "\\\\").replace('\'', "\\'");
            format!(
                "function() {{ for (var i = 0; i < this.options.length; i++) {{ if (this.options[i].text === '{}') {{ this.selectedIndex = i; break; }} }} this.dispatchEvent(new Event('input', {{bubbles: true}})); this.dispatchEvent(new Event('change', {{bubbles: true}})); }}",
                escaped
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_click_options_default() {
        let opts = ClickOptions::default();
        assert_eq!(opts.button, MouseButton::Left);
        assert_eq!(opts.click_count, 1);
        assert_eq!(opts.modifiers, 0);
    }

    #[test]
    fn test_mouse_button_as_str_left() {
        assert_eq!(MouseButton::Left.as_str(), "left");
    }

    #[test]
    fn test_mouse_button_as_str_right() {
        assert_eq!(MouseButton::Right.as_str(), "right");
    }

    #[test]
    fn test_mouse_button_as_str_middle() {
        assert_eq!(MouseButton::Middle.as_str(), "middle");
    }

    #[test]
    fn test_modifier_constants() {
        assert_eq!(MODIFIER_ALT, 1);
        assert_eq!(MODIFIER_CTRL, 2);
        assert_eq!(MODIFIER_META, 4);
        assert_eq!(MODIFIER_SHIFT, 8);
    }

    #[test]
    fn test_modifier_combinations() {
        // Ctrl+Shift
        let mods = MODIFIER_CTRL | MODIFIER_SHIFT;
        assert_eq!(mods, 10);
        assert!(mods & MODIFIER_CTRL != 0);
        assert!(mods & MODIFIER_SHIFT != 0);
        assert!(mods & MODIFIER_ALT == 0);
        assert!(mods & MODIFIER_META == 0);
    }

    #[test]
    fn test_special_key_code_enter() {
        assert_eq!(special_key_code("Enter"), Some(13));
    }

    #[test]
    fn test_special_key_code_tab() {
        assert_eq!(special_key_code("Tab"), Some(9));
    }

    #[test]
    fn test_special_key_code_escape() {
        assert_eq!(special_key_code("Escape"), Some(27));
    }

    #[test]
    fn test_special_key_code_backspace() {
        assert_eq!(special_key_code("Backspace"), Some(8));
    }

    #[test]
    fn test_special_key_code_delete() {
        assert_eq!(special_key_code("Delete"), Some(46));
    }

    #[test]
    fn test_special_key_code_arrows() {
        assert_eq!(special_key_code("ArrowUp"), Some(38));
        assert_eq!(special_key_code("ArrowDown"), Some(40));
        assert_eq!(special_key_code("ArrowLeft"), Some(37));
        assert_eq!(special_key_code("ArrowRight"), Some(39));
    }

    #[test]
    fn test_special_key_code_f_keys() {
        assert_eq!(special_key_code("F1"), Some(112));
        assert_eq!(special_key_code("F5"), Some(116));
        assert_eq!(special_key_code("F12"), Some(123));
    }

    #[test]
    fn test_special_key_code_navigation() {
        assert_eq!(special_key_code("Home"), Some(36));
        assert_eq!(special_key_code("End"), Some(35));
        assert_eq!(special_key_code("PageUp"), Some(33));
        assert_eq!(special_key_code("PageDown"), Some(34));
    }

    #[test]
    fn test_special_key_code_regular_char() {
        assert_eq!(special_key_code("a"), None);
        assert_eq!(special_key_code("z"), None);
        assert_eq!(special_key_code("1"), None);
    }

    #[test]
    fn test_select_js_function_by_value() {
        let js = select_js_function(&SelectBy::Value("option1".to_string()));
        assert!(js.contains("this.value = 'option1'"));
        assert!(js.contains("dispatchEvent"));
        assert!(js.contains("'input'"));
        assert!(js.contains("'change'"));
    }

    #[test]
    fn test_select_js_function_by_value_escapes_quotes() {
        let js = select_js_function(&SelectBy::Value("it's".to_string()));
        assert!(js.contains("it\\'s"));
    }

    #[test]
    fn test_select_js_function_by_index() {
        let js = select_js_function(&SelectBy::Index(3));
        assert!(js.contains("this.selectedIndex = 3"));
        assert!(js.contains("dispatchEvent"));
    }

    #[test]
    fn test_select_js_function_by_label() {
        let js = select_js_function(&SelectBy::Label("United States".to_string()));
        assert!(js.contains("this.options[i].text === 'United States'"));
        assert!(js.contains("this.selectedIndex = i"));
        assert!(js.contains("dispatchEvent"));
    }

    #[test]
    fn test_select_js_function_by_label_escapes_quotes() {
        let js = select_js_function(&SelectBy::Label("it's a label".to_string()));
        assert!(js.contains("it\\'s a label"));
    }

    // -- Bezier mouse path tests --

    #[test]
    fn bezier_mouse_path_correct_step_count() {
        let points = bezier_mouse_path((0.0, 0.0), (100.0, 100.0), 20);
        assert_eq!(points.len(), 20);
    }

    #[test]
    fn bezier_mouse_path_starts_at_from() {
        let from = (10.0, 20.0);
        let to = (200.0, 300.0);
        let points = bezier_mouse_path(from, to, 50);
        assert!(!points.is_empty());
        let first = points[0];
        assert!((first.0 - from.0).abs() < 0.01, "first point x should be near from.x");
        assert!((first.1 - from.1).abs() < 0.01, "first point y should be near from.y");
    }

    #[test]
    fn bezier_mouse_path_ends_at_to() {
        let from = (10.0, 20.0);
        let to = (200.0, 300.0);
        let points = bezier_mouse_path(from, to, 50);
        let last = points.last().unwrap();
        assert!((last.0 - to.0).abs() < 0.01, "last point x should be near to.x");
        assert!((last.1 - to.1).abs() < 0.01, "last point y should be near to.y");
    }

    #[test]
    fn bezier_mouse_path_is_not_a_straight_line() {
        // A Bezier curve with random control points should deviate from
        // the straight line between from and to for most intermediate points.
        let from = (0.0, 0.0);
        let to = (100.0, 0.0);
        let points = bezier_mouse_path(from, to, 100);
        // At least some intermediate points should have non-zero Y
        let has_deviation = points[10..90]
            .iter()
            .any(|(_, y)| y.abs() > 0.001);
        // NOTE: This may very rarely fail if random offsets are extremely small,
        // but with 30% max offset on 100px distance it's virtually impossible.
        assert!(has_deviation, "Bezier curve should deviate from straight line");
    }

    #[test]
    fn bezier_mouse_path_zero_steps_returns_empty() {
        let points = bezier_mouse_path((0.0, 0.0), (100.0, 100.0), 0);
        assert!(points.is_empty());
    }

    #[test]
    fn bezier_mouse_path_one_step_returns_target() {
        let to = (100.0, 200.0);
        let points = bezier_mouse_path((0.0, 0.0), to, 1);
        assert_eq!(points.len(), 1);
        assert!((points[0].0 - to.0).abs() < 0.01);
        assert!((points[0].1 - to.1).abs() < 0.01);
    }

    #[test]
    fn bezier_mouse_path_same_from_and_to() {
        let p = (50.0, 50.0);
        let points = bezier_mouse_path(p, p, 10);
        assert_eq!(points.len(), 10);
        for pt in &points {
            assert!((pt.0 - 50.0).abs() < 0.01);
            assert!((pt.1 - 50.0).abs() < 0.01);
        }
    }

    // -- Gaussian keystroke delay tests --

    #[test]
    fn gaussian_keystroke_delay_in_valid_range() {
        let mean = 100.0;
        let stddev = 20.0;
        for _ in 0..100 {
            let delay = gaussian_keystroke_delay(mean, stddev);
            assert!(delay >= 1, "delay should be at least 1ms");
            // Clamped to [mean/3, mean*3] = [33, 300]
            assert!(delay >= 33, "delay {} should be >= mean/3 = 33", delay);
            assert!(delay <= 300, "delay {} should be <= mean*3 = 300", delay);
        }
    }

    #[test]
    fn gaussian_keystroke_delay_varies() {
        // Multiple calls should not all return the same value (gaussian randomness)
        let delays: Vec<u64> = (0..50)
            .map(|_| gaussian_keystroke_delay(100.0, 25.0))
            .collect();
        let unique: std::collections::HashSet<u64> = delays.into_iter().collect();
        assert!(unique.len() > 1, "gaussian delays should have some variation");
    }

    #[test]
    fn gaussian_keystroke_delay_small_stddev() {
        // With very small stddev, most values should be near the mean
        for _ in 0..50 {
            let delay = gaussian_keystroke_delay(50.0, 1.0);
            assert!(delay >= 16, "delay {} should be >= mean/3 = 16", delay);
            assert!(delay <= 150, "delay {} should be <= mean*3 = 150", delay);
        }
    }
}
