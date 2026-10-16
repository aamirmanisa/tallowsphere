//! Network interception and monitoring configuration (network.toml).

use serde::{Deserialize, Serialize};

/// Network interception, HAR recording, and WebSocket monitoring.
///
/// ```toml
/// # network.toml
/// intercept_enabled = false
/// har_recording = false
/// har_output_dir = "har/"
/// websocket_monitor = false
///
/// # Block resource types to speed up page loads
/// [blocked_resources]
/// images = false
/// stylesheets = false
/// fonts = false
/// media = false
/// scripts = false                 # careful: breaks most sites
///
/// # Custom intercept rules (array of tables)
/// [[rules]]
/// url_pattern = "*.doubleclick.net/*"
/// action = "block"
///
/// [[rules]]
/// url_pattern = "*/api/analytics*"
/// action = "block"
///
/// [[rules]]
/// url_pattern = "*/api/config"
/// action = "mock"
/// mock_status = 200
/// mock_body = '{"feature_flags": {}}'
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct NetworkToml {
    /// Enable request/response interception.
    pub intercept_enabled: bool,
    /// Record all network traffic as HAR.
    pub har_recording: bool,
    /// Output directory for HAR files.
    pub har_output_dir: String,
    /// Monitor WebSocket frames.
    pub websocket_monitor: bool,
    /// Block certain resource types for performance.
    pub blocked_resources: BlockedResources,
    /// Custom intercept rules.
    pub rules: Vec<InterceptRuleToml>,
}

impl Default for NetworkToml {
    fn default() -> Self {
        Self {
            intercept_enabled: false,
            har_recording: false,
            har_output_dir: "har/".into(),
            websocket_monitor: false,
            blocked_resources: BlockedResources::default(),
            rules: vec![],
        }
    }
}

/// Resource types to block for faster page loads.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct BlockedResources {
    pub images: bool,
    pub stylesheets: bool,
    pub fonts: bool,
    pub media: bool,
    pub scripts: bool,
}

impl Default for BlockedResources {
    fn default() -> Self {
        Self {
            images: false,
            stylesheets: false,
            fonts: false,
            media: false,
            scripts: false,
        }
    }
}

/// A single intercept rule in TOML.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct InterceptRuleToml {
    /// URL glob pattern to match.
    pub url_pattern: String,
    /// Action: "block", "continue", "mock".
    pub action: String,
    /// HTTP method filter (empty = all).
    pub method: String,
    /// Mock response status code (only for action = "mock").
    pub mock_status: u16,
    /// Mock response body (only for action = "mock").
    pub mock_body: String,
    /// Mock response headers as "Key: Value" lines.
    pub mock_headers: Vec<String>,
}

impl Default for InterceptRuleToml {
    fn default() -> Self {
        Self {
            url_pattern: String::new(),
            action: "block".into(),
            method: String::new(),
            mock_status: 200,
            mock_body: String::new(),
            mock_headers: vec![],
        }
    }
}
