//! Device profile registry for browser emulation.
//!
//! Contains 163 device profiles matching Playwright's device descriptors.
//! Provides lookup by name, listing, and filtering by category.

use crate::interp::Value;

/// A device profile describing viewport, scale, user-agent, and capabilities.
#[derive(Debug, Clone)]
pub struct DeviceDescriptor {
    pub name: &'static str,
    pub viewport_width: u32,
    pub viewport_height: u32,
    pub device_scale_factor: f64,
    pub is_mobile: bool,
    pub has_touch: bool,
    pub user_agent: &'static str,
    pub default_browser: &'static str,
}

impl DeviceDescriptor {
    /// Convert this descriptor to a Tallow `Value::Struct`.
    pub fn to_value(&self) -> Value {
        Value::Struct {
            name: "DeviceProfile".to_string(),
            fields: vec![
                ("name".to_string(), Value::String(self.name.to_string())),
                ("viewport_width".to_string(), Value::Int(self.viewport_width as i128)),
                ("viewport_height".to_string(), Value::Int(self.viewport_height as i128)),
                ("device_scale_factor".to_string(), Value::Float(self.device_scale_factor)),
                ("is_mobile".to_string(), Value::Bool(self.is_mobile)),
                ("has_touch".to_string(), Value::Bool(self.has_touch)),
                ("user_agent".to_string(), Value::String(self.user_agent.to_string())),
                ("default_browser".to_string(), Value::String(self.default_browser.to_string())),
            ],
        }
    }
}

/// Get a device profile by name. Case-insensitive.
pub fn get_device(name: &str) -> Option<&'static DeviceDescriptor> {
    let lower = name.to_lowercase();
    ALL_DEVICES.iter().find(|d| d.name.to_lowercase() == lower)
}

/// List all available device profile names.
pub fn list_devices() -> Vec<&'static str> {
    ALL_DEVICES.iter().map(|d| d.name).collect()
}

/// List devices filtered by category.
pub fn list_devices_by_category(category: &str) -> Vec<&'static str> {
    ALL_DEVICES
        .iter()
        .filter(|d| match category.to_lowercase().as_str() {
            "iphone" => d.name.to_lowercase().contains("iphone"),
            "ipad" => d.name.to_lowercase().contains("ipad"),
            "pixel" => d.name.to_lowercase().contains("pixel"),
            "galaxy" => d.name.to_lowercase().contains("galaxy"),
            "desktop" => d.name.to_lowercase().contains("desktop"),
            "mobile" => d.is_mobile,
            "tablet" => d.is_mobile && d.viewport_width > 700,
            _ => true,
        })
        .map(|d| d.name)
        .collect()
}

/// Total number of device profiles.
pub fn device_count() -> usize {
    ALL_DEVICES.len()
}

// ---------------------------------------------------------------------------
// 163 Device Profiles — matching Playwright device descriptors
// ---------------------------------------------------------------------------

static ALL_DEVICES: &[DeviceDescriptor] = &[
    // ── iPhones ──────────────────────────────────────────────────────────────
    DeviceDescriptor { name: "iPhone 6", viewport_width: 375, viewport_height: 667, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 6 landscape", viewport_width: 667, viewport_height: 375, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 6 Plus", viewport_width: 414, viewport_height: 736, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 6 Plus landscape", viewport_width: 736, viewport_height: 414, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 11_0 like Mac OS X) AppleWebKit/604.1.38 (KHTML, like Gecko) Version/11.0 Mobile/15A372 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 7", viewport_width: 375, viewport_height: 667, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 7 landscape", viewport_width: 667, viewport_height: 375, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 7 Plus", viewport_width: 414, viewport_height: 736, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 7 Plus landscape", viewport_width: 736, viewport_height: 414, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 8", viewport_width: 375, viewport_height: 667, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 8 landscape", viewport_width: 667, viewport_height: 375, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 8 Plus", viewport_width: 414, viewport_height: 736, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 8 Plus landscape", viewport_width: 736, viewport_height: 414, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone SE", viewport_width: 320, viewport_height: 568, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone SE landscape", viewport_width: 568, viewport_height: 320, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone X", viewport_width: 375, viewport_height: 812, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone X landscape", viewport_width: 812, viewport_height: 375, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/13.0.3 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone XR", viewport_width: 414, viewport_height: 896, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone XR landscape", viewport_width: 896, viewport_height: 414, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 11", viewport_width: 414, viewport_height: 896, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 11 landscape", viewport_width: 896, viewport_height: 414, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 11 Pro", viewport_width: 375, viewport_height: 812, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 11 Pro landscape", viewport_width: 812, viewport_height: 375, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 11 Pro Max", viewport_width: 414, viewport_height: 896, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 11 Pro Max landscape", viewport_width: 896, viewport_height: 414, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 12", viewport_width: 390, viewport_height: 844, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 12 landscape", viewport_width: 844, viewport_height: 390, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 12 Mini", viewport_width: 375, viewport_height: 812, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 12 Mini landscape", viewport_width: 812, viewport_height: 375, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 12 Pro", viewport_width: 390, viewport_height: 844, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 12 Pro landscape", viewport_width: 844, viewport_height: 390, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 12 Pro Max", viewport_width: 428, viewport_height: 926, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 12 Pro Max landscape", viewport_width: 926, viewport_height: 428, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 13", viewport_width: 390, viewport_height: 844, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 13 landscape", viewport_width: 844, viewport_height: 390, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 13 Mini", viewport_width: 375, viewport_height: 812, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 13 Mini landscape", viewport_width: 812, viewport_height: 375, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 13 Pro", viewport_width: 390, viewport_height: 844, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 13 Pro landscape", viewport_width: 844, viewport_height: 390, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 13 Pro Max", viewport_width: 428, viewport_height: 926, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 13 Pro Max landscape", viewport_width: 926, viewport_height: 428, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 14", viewport_width: 390, viewport_height: 844, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 14 landscape", viewport_width: 844, viewport_height: 390, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 14 Plus", viewport_width: 428, viewport_height: 926, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 14 Plus landscape", viewport_width: 926, viewport_height: 428, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 14 Pro", viewport_width: 393, viewport_height: 852, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 14 Pro landscape", viewport_width: 852, viewport_height: 393, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 14 Pro Max", viewport_width: 430, viewport_height: 932, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 14 Pro Max landscape", viewport_width: 932, viewport_height: 430, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 15", viewport_width: 393, viewport_height: 852, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 15 landscape", viewport_width: 852, viewport_height: 393, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 15 Plus", viewport_width: 430, viewport_height: 932, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 15 Plus landscape", viewport_width: 932, viewport_height: 430, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 15 Pro", viewport_width: 393, viewport_height: 852, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 15 Pro landscape", viewport_width: 852, viewport_height: 393, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 15 Pro Max", viewport_width: 430, viewport_height: 932, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPhone 15 Pro Max landscape", viewport_width: 932, viewport_height: 430, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },

    // ── iPads ────────────────────────────────────────────────────────────────
    DeviceDescriptor { name: "iPad (gen 5)", viewport_width: 768, viewport_height: 1024, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad (gen 5) landscape", viewport_width: 1024, viewport_height: 768, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad (gen 6)", viewport_width: 768, viewport_height: 1024, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad (gen 6) landscape", viewport_width: 1024, viewport_height: 768, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 12_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad (gen 7)", viewport_width: 810, viewport_height: 1080, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad (gen 7) landscape", viewport_width: 1080, viewport_height: 810, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad (gen 8)", viewport_width: 810, viewport_height: 1080, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad (gen 8) landscape", viewport_width: 1080, viewport_height: 810, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.5 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad (gen 9)", viewport_width: 810, viewport_height: 1080, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad (gen 9) landscape", viewport_width: 1080, viewport_height: 810, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad (gen 10)", viewport_width: 820, viewport_height: 1180, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad (gen 10) landscape", viewport_width: 1180, viewport_height: 820, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Mini", viewport_width: 768, viewport_height: 1024, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Mini landscape", viewport_width: 1024, viewport_height: 768, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Mini (6th gen)", viewport_width: 744, viewport_height: 1133, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Mini (6th gen) landscape", viewport_width: 1133, viewport_height: 744, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Air", viewport_width: 820, viewport_height: 1180, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Air landscape", viewport_width: 1180, viewport_height: 820, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 15_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Air 4", viewport_width: 820, viewport_height: 1180, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Air 4 landscape", viewport_width: 1180, viewport_height: 820, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Pro 11", viewport_width: 834, viewport_height: 1194, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Pro 11 landscape", viewport_width: 1194, viewport_height: 834, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Pro 12.9", viewport_width: 1024, viewport_height: 1366, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Pro 12.9 landscape", viewport_width: 1366, viewport_height: 1024, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1", default_browser: "webkit" },

    // ── Pixels ───────────────────────────────────────────────────────────────
    DeviceDescriptor { name: "Pixel 2", viewport_width: 411, viewport_height: 731, device_scale_factor: 2.625, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 8.0; Pixel 2 Build/OPD3.170816.012) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 2 landscape", viewport_width: 731, viewport_height: 411, device_scale_factor: 2.625, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 8.0; Pixel 2 Build/OPD3.170816.012) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 2 XL", viewport_width: 411, viewport_height: 823, device_scale_factor: 3.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 8.0.0; Pixel 2 XL Build/OPD1.170816.004) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 2 XL landscape", viewport_width: 823, viewport_height: 411, device_scale_factor: 3.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 8.0.0; Pixel 2 XL Build/OPD1.170816.004) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 3", viewport_width: 393, viewport_height: 786, device_scale_factor: 2.75, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 9; Pixel 3 Build/PQ3A.190801.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 3 landscape", viewport_width: 786, viewport_height: 393, device_scale_factor: 2.75, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 9; Pixel 3 Build/PQ3A.190801.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 4", viewport_width: 353, viewport_height: 745, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 10; Pixel 4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 4 landscape", viewport_width: 745, viewport_height: 353, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 10; Pixel 4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 4a (5G)", viewport_width: 393, viewport_height: 851, device_scale_factor: 2.75, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 11; Pixel 4a (5G)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 4a (5G) landscape", viewport_width: 851, viewport_height: 393, device_scale_factor: 2.75, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 11; Pixel 4a (5G)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 5", viewport_width: 393, viewport_height: 851, device_scale_factor: 2.75, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 5 landscape", viewport_width: 851, viewport_height: 393, device_scale_factor: 2.75, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 11; Pixel 5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 7", viewport_width: 412, viewport_height: 915, device_scale_factor: 2.625, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 7 landscape", viewport_width: 915, viewport_height: 412, device_scale_factor: 2.625, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },

    // ── Samsung Galaxy ───────────────────────────────────────────────────────
    DeviceDescriptor { name: "Galaxy S5", viewport_width: 360, viewport_height: 640, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy S5 landscape", viewport_width: 640, viewport_height: 360, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 5.0; SM-G900P Build/LRX21T) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy S8", viewport_width: 360, viewport_height: 740, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 7.0; SM-G950U Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy S8 landscape", viewport_width: 740, viewport_height: 360, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 7.0; SM-G950U Build/NRD90M) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy S9+", viewport_width: 320, viewport_height: 658, device_scale_factor: 4.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 8.0.0; SM-G965U Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy S9+ landscape", viewport_width: 658, viewport_height: 320, device_scale_factor: 4.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 8.0.0; SM-G965U Build/R16NW) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy Tab S4", viewport_width: 712, viewport_height: 1138, device_scale_factor: 2.25, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 8.1.0; SM-T835) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy Tab S4 landscape", viewport_width: 1138, viewport_height: 712, device_scale_factor: 2.25, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 8.1.0; SM-T835) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy Note 3", viewport_width: 360, viewport_height: 640, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 4.3; SM-N9005 Build/JSS15J) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy Note 3 landscape", viewport_width: 640, viewport_height: 360, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 4.3; SM-N9005 Build/JSS15J) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy Note II", viewport_width: 360, viewport_height: 640, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; U; Android 4.1; en-us; GT-N7100 Build/JRO03C) AppleWebKit/534.30 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/534.30", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy Note II landscape", viewport_width: 640, viewport_height: 360, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; U; Android 4.1; en-us; GT-N7100 Build/JRO03C) AppleWebKit/534.30 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/534.30", default_browser: "chromium" },

    // ── Other Android ────────────────────────────────────────────────────────
    DeviceDescriptor { name: "Moto G4", viewport_width: 360, viewport_height: 640, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 7.0; Moto G (4)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Moto G4 landscape", viewport_width: 640, viewport_height: 360, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 7.0; Moto G (4)) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 5", viewport_width: 360, viewport_height: 640, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 5 landscape", viewport_width: 640, viewport_height: 360, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 6.0; Nexus 5 Build/MRA58N) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 5X", viewport_width: 412, viewport_height: 732, device_scale_factor: 2.625, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 8.0.0; Nexus 5X Build/OPR4.170623.006) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 5X landscape", viewport_width: 732, viewport_height: 412, device_scale_factor: 2.625, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 8.0.0; Nexus 5X Build/OPR4.170623.006) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 6", viewport_width: 412, viewport_height: 732, device_scale_factor: 3.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 7.1.1; Nexus 6 Build/N6F26U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 6 landscape", viewport_width: 732, viewport_height: 412, device_scale_factor: 3.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 7.1.1; Nexus 6 Build/N6F26U) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 6P", viewport_width: 412, viewport_height: 732, device_scale_factor: 3.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 8.0.0; Nexus 6P Build/OPP3.170518.006) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 6P landscape", viewport_width: 732, viewport_height: 412, device_scale_factor: 3.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 8.0.0; Nexus 6P Build/OPP3.170518.006) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 7", viewport_width: 600, viewport_height: 960, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 4.3; Nexus 7 Build/JSS15Q) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 7 landscape", viewport_width: 960, viewport_height: 600, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 4.3; Nexus 7 Build/JSS15Q) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 10", viewport_width: 800, viewport_height: 1280, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 4.3; Nexus 10 Build/JSS15Q) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 10 landscape", viewport_width: 1280, viewport_height: 800, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 4.3; Nexus 10 Build/JSS15Q) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "LG Optimus L70", viewport_width: 384, viewport_height: 640, device_scale_factor: 1.25, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; U; Android 4.4.2; en-us; LGMS323 Build/KOT49I.MS32310c) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "LG Optimus L70 landscape", viewport_width: 640, viewport_height: 384, device_scale_factor: 1.25, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; U; Android 4.4.2; en-us; LGMS323 Build/KOT49I.MS32310c) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nokia Lumia 520", viewport_width: 320, viewport_height: 533, device_scale_factor: 1.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch; NOKIA; Lumia 520)", default_browser: "chromium" },
    DeviceDescriptor { name: "Nokia Lumia 520 landscape", viewport_width: 533, viewport_height: 320, device_scale_factor: 1.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (compatible; MSIE 10.0; Windows Phone 8.0; Trident/6.0; IEMobile/10.0; ARM; Touch; NOKIA; Lumia 520)", default_browser: "chromium" },
    DeviceDescriptor { name: "Nokia N9", viewport_width: 480, viewport_height: 854, device_scale_factor: 1.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (MeeGo; NokiaN9) AppleWebKit/534.13 (KHTML, like Gecko) NokiaBrowser/8.5.0 Mobile Safari/534.13", default_browser: "webkit" },
    DeviceDescriptor { name: "Nokia N9 landscape", viewport_width: 854, viewport_height: 480, device_scale_factor: 1.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (MeeGo; NokiaN9) AppleWebKit/534.13 (KHTML, like Gecko) NokiaBrowser/8.5.0 Mobile Safari/534.13", default_browser: "webkit" },
    DeviceDescriptor { name: "Kindle Fire HDX", viewport_width: 800, viewport_height: 1280, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; U; en-us; KFAPWI Build/JDQ39) AppleWebKit/535.19 (KHTML, like Gecko) Silk/3.13 Safari/535.19 Silk-Accelerated=true", default_browser: "webkit" },
    DeviceDescriptor { name: "Kindle Fire HDX landscape", viewport_width: 1280, viewport_height: 800, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; U; en-us; KFAPWI Build/JDQ39) AppleWebKit/535.19 (KHTML, like Gecko) Silk/3.13 Safari/535.19 Silk-Accelerated=true", default_browser: "webkit" },
    DeviceDescriptor { name: "Blackberry PlayBook", viewport_width: 600, viewport_height: 1024, device_scale_factor: 1.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (PlayBook; U; RIM Tablet OS 2.1.0; en-US) AppleWebKit/536.2+ (KHTML, like Gecko) Version/7.2.1.0 Safari/536.2+", default_browser: "webkit" },
    DeviceDescriptor { name: "Blackberry PlayBook landscape", viewport_width: 1024, viewport_height: 600, device_scale_factor: 1.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (PlayBook; U; RIM Tablet OS 2.1.0; en-US) AppleWebKit/536.2+ (KHTML, like Gecko) Version/7.2.1.0 Safari/536.2+", default_browser: "webkit" },

    // ── Microsoft Surface ────────────────────────────────────────────────────
    DeviceDescriptor { name: "Microsoft Lumia 550", viewport_width: 640, viewport_height: 360, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Windows Phone 10.0; Android 4.0.3; Microsoft; Lumia 550) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/14.14263", default_browser: "chromium" },
    DeviceDescriptor { name: "Microsoft Lumia 950", viewport_width: 360, viewport_height: 640, device_scale_factor: 4.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Windows Phone 10.0; Android 4.0.3; Microsoft; Lumia 950) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2486.0 Mobile Safari/537.36 Edge/14.14263", default_browser: "chromium" },
    DeviceDescriptor { name: "JioPhone 2", viewport_width: 240, viewport_height: 320, device_scale_factor: 1.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Mobile; LYF/F300B/LYF-F300B-001-01-15-130718-i;Android; rv:48.0) Gecko/48.0 Firefox/48.0 KAIOS/2.5", default_browser: "firefox" },
    DeviceDescriptor { name: "JioPhone 2 landscape", viewport_width: 320, viewport_height: 240, device_scale_factor: 1.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Mobile; LYF/F300B/LYF-F300B-001-01-15-130718-i;Android; rv:48.0) Gecko/48.0 Firefox/48.0 KAIOS/2.5", default_browser: "firefox" },

    // ── Desktops ─────────────────────────────────────────────────────────────
    DeviceDescriptor { name: "Desktop Chrome", viewport_width: 1280, viewport_height: 720, device_scale_factor: 1.0, is_mobile: false, has_touch: false, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Desktop Chrome HiDPI", viewport_width: 1280, viewport_height: 720, device_scale_factor: 2.0, is_mobile: false, has_touch: false, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Desktop Edge", viewport_width: 1280, viewport_height: 720, device_scale_factor: 1.0, is_mobile: false, has_touch: false, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36 Edg/120.0.2210.91", default_browser: "chromium" },
    DeviceDescriptor { name: "Desktop Firefox", viewport_width: 1280, viewport_height: 720, device_scale_factor: 1.0, is_mobile: false, has_touch: false, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", default_browser: "firefox" },
    DeviceDescriptor { name: "Desktop Firefox HiDPI", viewport_width: 1280, viewport_height: 720, device_scale_factor: 2.0, is_mobile: false, has_touch: false, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0", default_browser: "firefox" },
    DeviceDescriptor { name: "Desktop Safari", viewport_width: 1280, viewport_height: 720, device_scale_factor: 2.0, is_mobile: false, has_touch: false, user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15", default_browser: "webkit" },

    // ── Common resolutions ───────────────────────────────────────────────────
    DeviceDescriptor { name: "1920x1080", viewport_width: 1920, viewport_height: 1080, device_scale_factor: 1.0, is_mobile: false, has_touch: false, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "1366x768", viewport_width: 1366, viewport_height: 768, device_scale_factor: 1.0, is_mobile: false, has_touch: false, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "2560x1440", viewport_width: 2560, viewport_height: 1440, device_scale_factor: 1.0, is_mobile: false, has_touch: false, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "3840x2160", viewport_width: 3840, viewport_height: 2160, device_scale_factor: 2.0, is_mobile: false, has_touch: false, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "1440x900", viewport_width: 1440, viewport_height: 900, device_scale_factor: 2.0, is_mobile: false, has_touch: false, user_agent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15", default_browser: "webkit" },

    // ── Additional Pixel variants ────────────────────────────────────────────
    DeviceDescriptor { name: "Pixel 3 XL", viewport_width: 412, viewport_height: 847, device_scale_factor: 3.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 9; Pixel 3 XL Build/PQ3A.190801.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 3 XL landscape", viewport_width: 847, viewport_height: 412, device_scale_factor: 3.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 9; Pixel 3 XL Build/PQ3A.190801.002) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 4 XL", viewport_width: 412, viewport_height: 869, device_scale_factor: 3.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 10; Pixel 4 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 4 XL landscape", viewport_width: 869, viewport_height: 412, device_scale_factor: 3.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 10; Pixel 4 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 6", viewport_width: 412, viewport_height: 915, device_scale_factor: 2.625, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Pixel 6 landscape", viewport_width: 915, viewport_height: 412, device_scale_factor: 2.625, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 12; Pixel 6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },

    // ── Additional Samsung Galaxy variants ────────────────────────────────────
    DeviceDescriptor { name: "Galaxy S20", viewport_width: 360, viewport_height: 800, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy S20 landscape", viewport_width: 800, viewport_height: 360, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 10; SM-G981B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy S21", viewport_width: 360, viewport_height: 800, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Galaxy S21 landscape", viewport_width: 800, viewport_height: 360, device_scale_factor: 3.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },

    // ── Additional iPads ─────────────────────────────────────────────────────
    DeviceDescriptor { name: "iPad Air 5", viewport_width: 820, viewport_height: 1180, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },
    DeviceDescriptor { name: "iPad Air 5 landscape", viewport_width: 1180, viewport_height: 820, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (iPad; CPU OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1", default_browser: "webkit" },

    // ── Additional Nexus/other ───────────────────────────────────────────────
    DeviceDescriptor { name: "Nexus 4", viewport_width: 384, viewport_height: 640, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 4.4.2; Nexus 4 Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Nexus 4 landscape", viewport_width: 640, viewport_height: 384, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 4.4.2; Nexus 4 Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },

    // ── Surface devices ──────────────────────────────────────────────────────
    DeviceDescriptor { name: "Surface Pro 7", viewport_width: 912, viewport_height: 1368, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Surface Pro 7 landscape", viewport_width: 1368, viewport_height: 912, device_scale_factor: 2.0, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Surface Duo", viewport_width: 540, viewport_height: 720, device_scale_factor: 2.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 11.0; Surface Duo) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
    DeviceDescriptor { name: "Surface Duo landscape", viewport_width: 720, viewport_height: 540, device_scale_factor: 2.5, is_mobile: true, has_touch: true, user_agent: "Mozilla/5.0 (Linux; Android 11.0; Surface Duo) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.230 Mobile Safari/537.36", default_browser: "chromium" },
];


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_device_get_iphone_15() {
        let d = get_device("iPhone 15").expect("should find iPhone 15");
        assert_eq!(d.viewport_width, 393);
        assert_eq!(d.viewport_height, 852);
        assert_eq!(d.device_scale_factor, 3.0);
        assert!(d.is_mobile);
        assert!(d.has_touch);
        assert!(d.user_agent.contains("iPhone"));
        assert_eq!(d.default_browser, "webkit");
    }

    #[test]
    fn test_device_get_pixel_7() {
        let d = get_device("Pixel 7").expect("should find Pixel 7");
        assert_eq!(d.viewport_width, 412);
        assert_eq!(d.viewport_height, 915);
        assert_eq!(d.device_scale_factor, 2.625);
        assert!(d.is_mobile);
        assert!(d.has_touch);
        assert!(d.user_agent.contains("Pixel 7"));
        assert_eq!(d.default_browser, "chromium");
    }

    #[test]
    fn test_device_get_desktop_chrome() {
        let d = get_device("Desktop Chrome").expect("should find Desktop Chrome");
        assert_eq!(d.viewport_width, 1280);
        assert_eq!(d.viewport_height, 720);
        assert_eq!(d.device_scale_factor, 1.0);
        assert!(!d.is_mobile);
        assert!(!d.has_touch);
        assert!(d.user_agent.contains("Chrome"));
        assert_eq!(d.default_browser, "chromium");
    }

    #[test]
    fn test_device_get_unknown() {
        assert!(get_device("NonExistentDevice123").is_none());
    }

    #[test]
    fn test_device_get_case_insensitive() {
        assert!(get_device("iphone 15").is_some());
        assert!(get_device("IPHONE 15").is_some());
        assert!(get_device("desktop chrome").is_some());
    }

    #[test]
    fn test_device_list_count() {
        let count = device_count();
        assert!(count >= 35, "should have at least 35 devices, got {}", count);
        // We have 163 devices
        assert_eq!(count, 163, "expected exactly 163 device profiles, got {}", count);
    }

    #[test]
    fn test_device_list_category_iphone() {
        let iphones = list_devices_by_category("iphone");
        assert!(iphones.len() >= 10, "should have at least 10 iPhones, got {}", iphones.len());
        for name in &iphones {
            assert!(name.to_lowercase().contains("iphone"), "expected iphone in {}", name);
        }
    }

    #[test]
    fn test_device_list_category_mobile() {
        let mobiles = list_devices_by_category("mobile");
        let total = device_count();
        // Most devices are mobile
        assert!(mobiles.len() > total / 2, "most devices should be mobile");
        for name in &mobiles {
            let d = get_device(name).unwrap();
            assert!(d.is_mobile, "{} should be mobile", name);
        }
    }

    #[test]
    fn test_device_list_category_desktop() {
        let desktops = list_devices_by_category("desktop");
        assert!(!desktops.is_empty(), "should have desktop devices");
        for name in &desktops {
            assert!(name.to_lowercase().contains("desktop"), "expected desktop in {}", name);
        }
    }

    #[test]
    fn test_device_list_category_tablet() {
        let tablets = list_devices_by_category("tablet");
        assert!(!tablets.is_empty(), "should have tablet devices");
        for name in &tablets {
            let d = get_device(name).unwrap();
            assert!(d.is_mobile, "tablet {} should have is_mobile=true", name);
            assert!(d.viewport_width > 700, "tablet {} should have wide viewport ({})", name, d.viewport_width);
        }
    }

    #[test]
    fn test_device_to_value() {
        let d = get_device("iPhone 15").unwrap();
        let val = d.to_value();
        match val {
            Value::Struct { name, fields } => {
                assert_eq!(name, "DeviceProfile");
                assert_eq!(fields.len(), 8);
                // Check that name field is correct
                let name_field = fields.iter().find(|(k, _)| k == "name").unwrap();
                match &name_field.1 {
                    Value::String(s) => assert_eq!(s, "iPhone 15"),
                    _ => panic!("name should be String"),
                }
            }
            _ => panic!("expected Struct"),
        }
    }

    #[test]
    fn test_device_list_has_all_major_brands() {
        let names = list_devices();
        let has_iphone = names.iter().any(|n| n.to_lowercase().contains("iphone"));
        let has_ipad = names.iter().any(|n| n.to_lowercase().contains("ipad"));
        let has_pixel = names.iter().any(|n| n.to_lowercase().contains("pixel"));
        let has_galaxy = names.iter().any(|n| n.to_lowercase().contains("galaxy"));
        let has_desktop = names.iter().any(|n| n.to_lowercase().contains("desktop"));
        let has_nexus = names.iter().any(|n| n.to_lowercase().contains("nexus"));
        assert!(has_iphone, "should have iPhones");
        assert!(has_ipad, "should have iPads");
        assert!(has_pixel, "should have Pixels");
        assert!(has_galaxy, "should have Galaxy devices");
        assert!(has_desktop, "should have desktops");
        assert!(has_nexus, "should have Nexus devices");
    }

    #[test]
    fn test_device_landscape_variants() {
        // Landscape variants should swap width and height
        let portrait = get_device("iPhone 15").unwrap();
        let landscape = get_device("iPhone 15 landscape").unwrap();
        assert_eq!(portrait.viewport_width, landscape.viewport_height);
        assert_eq!(portrait.viewport_height, landscape.viewport_width);
        assert_eq!(portrait.device_scale_factor, landscape.device_scale_factor);
        assert_eq!(portrait.is_mobile, landscape.is_mobile);
    }
}
