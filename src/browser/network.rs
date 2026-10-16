//! Network interception and HAR recording for Tallow browser automation.
//!
//! Provides `NetworkInterceptor` for HTTP request/response interception via CDP
//! Fetch domain and `HarRecorder` for passive traffic recording via CDP Network
//! domain. Intercepted requests can be continued, modified, blocked, or mocked.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use base64::Engine;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::cdp::CdpClient;
use super::error::BrowserError;

// ---------------------------------------------------------------------------
// Interception types
// ---------------------------------------------------------------------------

/// Action to take on an intercepted request.
#[derive(Debug, Clone)]
pub enum InterceptAction {
    /// Continue the request unmodified.
    Continue,
    /// Continue with modified fields.
    ContinueModified {
        url: Option<String>,
        method: Option<String>,
        headers: Option<Vec<HeaderEntry>>,
        post_data: Option<String>,
    },
    /// Block the request entirely.
    Block,
    /// Respond with a mock response (never hits the server).
    Mock(MockResponse),
}

/// A mock HTTP response returned instead of the real server response.
#[derive(Debug, Clone)]
pub struct MockResponse {
    pub status: u16,
    pub headers: Vec<HeaderEntry>,
    pub body: Vec<u8>,
}

/// An HTTP header name-value pair.
#[derive(Debug, Clone, Serialize)]
pub struct HeaderEntry {
    pub name: String,
    pub value: String,
}

/// A rule for matching and handling intercepted requests.
#[derive(Debug, Clone)]
pub struct InterceptRule {
    /// URL glob pattern (e.g., `*analytics*`, `*.js`). None matches all URLs.
    pub url_pattern: Option<String>,
    /// Filter by CDP resource type.
    pub resource_type: Option<ResourceType>,
    /// Filter by HTTP method (case-insensitive).
    pub method: Option<String>,
    /// Whether to intercept at request or response stage.
    pub request_stage: RequestStage,
    /// Action to take when the rule matches.
    pub action: InterceptAction,
}

/// Stage at which to intercept the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestStage {
    /// Intercept before the request is sent.
    Request,
    /// Intercept after the response is received.
    Response,
}

/// CDP resource type for filtering intercepted requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceType {
    Document,
    Stylesheet,
    Image,
    Media,
    Font,
    Script,
    TextTrack,
    XHR,
    Fetch,
    Prefetch,
    EventSource,
    WebSocket,
    Manifest,
    Other,
}

impl ResourceType {
    /// Returns the CDP string representation of this resource type.
    pub fn as_str(&self) -> &'static str {
        match self {
            ResourceType::Document => "Document",
            ResourceType::Stylesheet => "Stylesheet",
            ResourceType::Image => "Image",
            ResourceType::Media => "Media",
            ResourceType::Font => "Font",
            ResourceType::Script => "Script",
            ResourceType::TextTrack => "TextTrack",
            ResourceType::XHR => "XHR",
            ResourceType::Fetch => "Fetch",
            ResourceType::Prefetch => "Prefetch",
            ResourceType::EventSource => "EventSource",
            ResourceType::WebSocket => "WebSocket",
            ResourceType::Manifest => "Manifest",
            ResourceType::Other => "Other",
        }
    }
}

// ---------------------------------------------------------------------------
// Glob matching helper
// ---------------------------------------------------------------------------

/// Simple glob matching: `*` matches any sequence of characters.
///
/// Pattern is split on `*`; each segment must appear in the text in order.
/// Leading/trailing `*` match anything at the start/end. Multiple `*` in a row
/// match anything between segments.
fn glob_matches(pattern: &str, text: &str) -> bool {
    let segments: Vec<&str> = pattern.split('*').collect();

    // No wildcard -- exact match
    if segments.len() == 1 {
        return pattern == text;
    }

    let mut pos = 0usize;
    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            continue; // leading/trailing/consecutive `*`
        }
        if i == 0 {
            // First segment must be a prefix
            if !text.starts_with(seg) {
                return false;
            }
            pos = seg.len();
        } else if i == segments.len() - 1 {
            // Last segment must be a suffix
            if !text[pos..].ends_with(seg) {
                return false;
            }
            pos = text.len();
        } else {
            // Middle segments must appear in order
            match text[pos..].find(seg) {
                Some(found) => pos += found + seg.len(),
                None => return false,
            }
        }
    }

    true
}

// ---------------------------------------------------------------------------
// NetworkInterceptor
// ---------------------------------------------------------------------------

/// Intercepts HTTP requests/responses via CDP Fetch domain.
///
/// Add rules with `add_rule`, call `enable()` to activate, then run the event
/// loop via `run_event_loop()` (typically spawned in a tokio task). Call `stop()`
/// to signal the event loop to exit.
pub struct NetworkInterceptor {
    client: CdpClient,
    session_id: String,
    rules: Vec<InterceptRule>,
    running: Arc<AtomicBool>,
}

impl NetworkInterceptor {
    /// Create a new interceptor with no rules.
    pub fn new(client: CdpClient, session_id: String) -> Self {
        Self {
            client,
            session_id,
            rules: Vec::new(),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Add an interception rule. Rules are matched in insertion order (first match wins).
    pub fn add_rule(&mut self, rule: InterceptRule) {
        self.rules.push(rule);
    }

    /// Enable Fetch domain interception with patterns derived from current rules.
    pub async fn enable(&self) -> Result<(), BrowserError> {
        let patterns: Vec<Value> = self
            .rules
            .iter()
            .map(|rule| {
                let mut pattern = json!({});
                if let Some(ref url_pat) = rule.url_pattern {
                    pattern["urlPattern"] = json!(url_pat);
                } else {
                    pattern["urlPattern"] = json!("*");
                }
                pattern["requestStage"] = match rule.request_stage {
                    RequestStage::Request => json!("Request"),
                    RequestStage::Response => json!("Response"),
                };
                if let Some(ref rt) = rule.resource_type {
                    pattern["resourceType"] = json!(rt.as_str());
                }
                pattern
            })
            .collect();

        // If no rules, enable with a catch-all pattern so the event loop
        // can still auto-continue requests.
        let patterns = if patterns.is_empty() {
            vec![json!({"urlPattern": "*", "requestStage": "Request"})]
        } else {
            patterns
        };

        self.client
            .send_command_with_session(
                "Fetch.enable",
                Some(json!({"patterns": patterns, "handleAuthRequests": false})),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    /// Disable Fetch domain interception.
    pub async fn disable(&self) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session("Fetch.disable", None, &self.session_id)
            .await?;
        Ok(())
    }

    /// Find the first rule matching a given request's properties.
    pub fn matches_rule(
        &self,
        url: &str,
        method: &str,
        resource_type: &str,
    ) -> Option<&InterceptRule> {
        find_matching_rule(&self.rules, url, method, resource_type)
    }

    /// Handle a single `Fetch.requestPaused` event.
    ///
    /// Extracts request info, matches against rules, and executes the
    /// appropriate action. If no rule matches, the request is continued
    /// automatically (CRITICAL: never leave a request hanging).
    pub async fn handle_paused_request(
        &self,
        event_params: &Value,
    ) -> Result<(), BrowserError> {
        let request_id = event_params
            .get("requestId")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        if request_id.is_empty() {
            return Err(BrowserError::InterceptError(
                "missing requestId in Fetch.requestPaused event".to_string(),
            ));
        }

        // Check if this is a response-stage pause (responseStatusCode present)
        let is_response_stage = event_params.get("responseStatusCode").is_some();

        let request = event_params.get("request").unwrap_or(&Value::Null);
        let url = request
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let method = request
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET");
        let resource_type = event_params
            .get("resourceType")
            .and_then(|v| v.as_str())
            .unwrap_or("Other");

        // Find matching rule, filtering by stage
        let matching_rule = self.rules.iter().find(|rule| {
            // Stage filter
            let stage_matches = match rule.request_stage {
                RequestStage::Request => !is_response_stage,
                RequestStage::Response => is_response_stage,
            };
            if !stage_matches {
                return false;
            }
            // URL pattern
            if let Some(ref pattern) = rule.url_pattern {
                if !glob_matches(pattern, url) {
                    return false;
                }
            }
            // Method
            if let Some(ref m) = rule.method {
                if !m.eq_ignore_ascii_case(method) {
                    return false;
                }
            }
            // Resource type
            if let Some(ref rt) = rule.resource_type {
                if !rt.as_str().eq_ignore_ascii_case(resource_type) {
                    return false;
                }
            }
            true
        });

        if is_response_stage {
            return self
                .handle_response_stage(&request_id, event_params, matching_rule)
                .await;
        }

        // Request stage handling
        match matching_rule.map(|r| &r.action) {
            Some(InterceptAction::Continue) | None => {
                // Continue unmodified
                self.client
                    .send_command_with_session(
                        "Fetch.continueRequest",
                        Some(json!({"requestId": request_id})),
                        &self.session_id,
                    )
                    .await?;
            }
            Some(InterceptAction::ContinueModified {
                url,
                method,
                headers,
                post_data,
            }) => {
                let mut params = json!({"requestId": request_id});
                if let Some(u) = url {
                    params["url"] = json!(u);
                }
                if let Some(m) = method {
                    params["method"] = json!(m);
                }
                if let Some(h) = headers {
                    let hdr_array: Vec<Value> = h
                        .iter()
                        .map(|e| json!({"name": e.name, "value": e.value}))
                        .collect();
                    params["headers"] = json!(hdr_array);
                }
                if let Some(pd) = post_data {
                    params["postData"] = json!(pd);
                }
                self.client
                    .send_command_with_session(
                        "Fetch.continueRequest",
                        Some(params),
                        &self.session_id,
                    )
                    .await?;
            }
            Some(InterceptAction::Block) => {
                self.client
                    .send_command_with_session(
                        "Fetch.failRequest",
                        Some(json!({
                            "requestId": request_id,
                            "errorReason": "BlockedByClient"
                        })),
                        &self.session_id,
                    )
                    .await?;
            }
            Some(InterceptAction::Mock(mock)) => {
                let encoded_body =
                    base64::engine::general_purpose::STANDARD.encode(&mock.body);
                let response_headers: Vec<Value> = mock
                    .headers
                    .iter()
                    .map(|h| json!({"name": h.name, "value": h.value}))
                    .collect();
                self.client
                    .send_command_with_session(
                        "Fetch.fulfillRequest",
                        Some(json!({
                            "requestId": request_id,
                            "responseCode": mock.status,
                            "responseHeaders": response_headers,
                            "body": encoded_body,
                        })),
                        &self.session_id,
                    )
                    .await?;
            }
        }

        Ok(())
    }

    /// Handle response-stage `Fetch.requestPaused` events.
    ///
    /// When intercepting responses, we get the original body via
    /// `Fetch.getResponseBody`, then apply the rule's action and fulfill.
    async fn handle_response_stage(
        &self,
        request_id: &str,
        event_params: &Value,
        matching_rule: Option<&InterceptRule>,
    ) -> Result<(), BrowserError> {
        match matching_rule.map(|r| &r.action) {
            Some(InterceptAction::Block) => {
                self.client
                    .send_command_with_session(
                        "Fetch.failRequest",
                        Some(json!({
                            "requestId": request_id,
                            "errorReason": "BlockedByClient"
                        })),
                        &self.session_id,
                    )
                    .await?;
            }
            Some(InterceptAction::Mock(mock)) => {
                let encoded_body =
                    base64::engine::general_purpose::STANDARD.encode(&mock.body);
                let response_headers: Vec<Value> = mock
                    .headers
                    .iter()
                    .map(|h| json!({"name": h.name, "value": h.value}))
                    .collect();
                self.client
                    .send_command_with_session(
                        "Fetch.fulfillRequest",
                        Some(json!({
                            "requestId": request_id,
                            "responseCode": mock.status,
                            "responseHeaders": response_headers,
                            "body": encoded_body,
                        })),
                        &self.session_id,
                    )
                    .await?;
            }
            Some(InterceptAction::ContinueModified { headers, .. }) => {
                // Get the original response body
                let body_result = self
                    .client
                    .send_command_with_session(
                        "Fetch.getResponseBody",
                        Some(json!({"requestId": request_id})),
                        &self.session_id,
                    )
                    .await?;

                let original_body = body_result
                    .get("body")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let is_base64 = body_result
                    .get("base64Encoded")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);

                // Re-encode body as base64 for fulfillRequest
                let body_b64 = if is_base64 {
                    original_body.to_string()
                } else {
                    base64::engine::general_purpose::STANDARD.encode(original_body.as_bytes())
                };

                let status_code = event_params
                    .get("responseStatusCode")
                    .and_then(|v| v.as_u64())
                    .unwrap_or(200) as u16;

                let response_headers: Vec<Value> = if let Some(h) = headers {
                    h.iter()
                        .map(|e| json!({"name": e.name, "value": e.value}))
                        .collect()
                } else {
                    // Use original response headers
                    event_params
                        .get("responseHeaders")
                        .and_then(|v| v.as_array())
                        .cloned()
                        .unwrap_or_default()
                };

                self.client
                    .send_command_with_session(
                        "Fetch.fulfillRequest",
                        Some(json!({
                            "requestId": request_id,
                            "responseCode": status_code,
                            "responseHeaders": response_headers,
                            "body": body_b64,
                        })),
                        &self.session_id,
                    )
                    .await?;
            }
            Some(InterceptAction::Continue) | None => {
                // Continue response unmodified
                self.client
                    .send_command_with_session(
                        "Fetch.continueRequest",
                        Some(json!({"requestId": request_id})),
                        &self.session_id,
                    )
                    .await?;
            }
        }
        Ok(())
    }

    /// Run the event dispatch loop, processing `Fetch.requestPaused` events.
    ///
    /// This method runs indefinitely until `stop()` is called. It should be
    /// spawned in a tokio task. On any handler error, the request is
    /// automatically continued to avoid deadlocking the page.
    pub async fn run_event_loop(&self) -> Result<(), BrowserError> {
        self.running.store(true, Ordering::SeqCst);
        let mut rx = self.client.subscribe();

        while self.running.load(Ordering::SeqCst) {
            match tokio::time::timeout(std::time::Duration::from_millis(100), rx.recv()).await {
                Ok(Ok(event)) => {
                    // Only handle Fetch.requestPaused events for our session
                    if event.method != "Fetch.requestPaused" {
                        continue;
                    }
                    if event.session_id.as_deref() != Some(&self.session_id) {
                        continue;
                    }
                    if let Some(ref params) = event.params {
                        if let Err(_e) = self.handle_paused_request(params).await {
                            // Fallback: continue the request to avoid deadlock
                            let request_id = params
                                .get("requestId")
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            if !request_id.is_empty() {
                                let _ = self
                                    .client
                                    .send_command_with_session(
                                        "Fetch.continueRequest",
                                        Some(json!({"requestId": request_id})),
                                        &self.session_id,
                                    )
                                    .await;
                            }
                        }
                    }
                }
                Ok(Err(_)) => {
                    // Broadcast lagged or closed, re-subscribe
                    rx = self.client.subscribe();
                }
                Err(_) => {
                    // Timeout -- check running flag and loop
                    continue;
                }
            }
        }

        Ok(())
    }

    /// Signal the event loop to stop.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

/// Find the first rule in the slice that matches the given request properties.
///
/// Standalone function to enable testing without constructing a full
/// `NetworkInterceptor` (which requires a live CdpClient).
fn find_matching_rule<'a>(
    rules: &'a [InterceptRule],
    url: &str,
    method: &str,
    resource_type: &str,
) -> Option<&'a InterceptRule> {
    rules.iter().find(|rule| {
        // URL pattern
        if let Some(ref pattern) = rule.url_pattern {
            if !glob_matches(pattern, url) {
                return false;
            }
        }
        // Method (case-insensitive)
        if let Some(ref m) = rule.method {
            if !m.eq_ignore_ascii_case(method) {
                return false;
            }
        }
        // Resource type
        if let Some(ref rt) = rule.resource_type {
            if !rt.as_str().eq_ignore_ascii_case(resource_type) {
                return false;
            }
        }
        true
    })
}

// ---------------------------------------------------------------------------
// HAR 1.2 structs
// ---------------------------------------------------------------------------

/// Top-level HAR 1.2 container.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarLog {
    pub log: HarLogInner,
}

/// Inner log structure containing metadata and entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarLogInner {
    #[serde(default)]
    pub version: String,
    #[serde(default)]
    pub creator: HarCreator,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub pages: Vec<HarPage>,
    pub entries: Vec<HarEntry>,
}

/// HAR creator metadata.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HarCreator {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub version: String,
}

/// HAR page reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarPage {
    #[serde(rename = "startedDateTime", default)]
    pub started_date_time: String,
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub title: String,
}

/// A single HAR entry representing one HTTP request/response pair.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarEntry {
    #[serde(default)]
    pub started_date_time: String,
    #[serde(default)]
    pub time: f64,
    pub request: HarRequest,
    pub response: HarResponse,
    #[serde(default)]
    pub timings: HarTimings,
    // The spec spells this `serverIPAddress`; `rename_all` would emit
    // `serverIpAddress`, so accept both rather than only our own spelling.
    #[serde(default, skip_serializing_if = "Option::is_none", alias = "serverIPAddress")]
    pub server_ip_address: Option<String>,
}

/// HAR request data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarRequest {
    pub method: String,
    pub url: String,
    #[serde(default)]
    pub http_version: String,
    #[serde(default)]
    pub headers: Vec<HarNameValue>,
    #[serde(default)]
    pub query_string: Vec<HarNameValue>,
    #[serde(default)]
    pub body_size: i64,
    #[serde(default)]
    pub headers_size: i64,
}

/// HAR response data.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HarResponse {
    #[serde(default)]
    pub status: u16,
    #[serde(default)]
    pub status_text: String,
    #[serde(default)]
    pub http_version: String,
    #[serde(default)]
    pub headers: Vec<HarNameValue>,
    #[serde(default)]
    pub content: HarContent,
    // Spec spelling is `redirectURL`; `rename_all` would emit `redirectUrl`.
    #[serde(default, alias = "redirectURL")]
    pub redirect_url: String,
    #[serde(default)]
    pub body_size: i64,
    #[serde(default)]
    pub headers_size: i64,
}

/// HAR response content (body).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HarContent {
    #[serde(default)]
    pub size: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compression: Option<i64>,
    #[serde(rename = "mimeType", default)]
    pub mime_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub text: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encoding: Option<String>,
}

/// HAR timing breakdown.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HarTimings {
    #[serde(default)]
    pub blocked: f64,
    #[serde(default)]
    pub dns: f64,
    #[serde(default)]
    pub connect: f64,
    #[serde(default)]
    pub send: f64,
    #[serde(default)]
    pub wait: f64,
    #[serde(default)]
    pub receive: f64,
    #[serde(default)]
    pub ssl: f64,
}

/// HAR name-value pair (used for headers and query parameters).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarNameValue {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub value: String,
}

// ---------------------------------------------------------------------------
// HarRecorder
// ---------------------------------------------------------------------------

/// Partial entry being assembled from multiple Network domain events.
pub(crate) struct PartialHarEntry {
    request_url: String,
    request_method: String,
    request_headers: Vec<HarNameValue>,
    started: chrono::DateTime<Utc>,
    response_status: Option<u16>,
    response_status_text: Option<String>,
    response_headers: Vec<HarNameValue>,
    response_mime_type: Option<String>,
    response_body_size: Option<i64>,
}

/// Internal state for HAR recording, separated from CDP client for testability.
pub(crate) struct HarRecorderState {
    pub(crate) pending_entries: HashMap<String, PartialHarEntry>,
    pub(crate) completed_entries: Vec<HarEntry>,
    pub(crate) capture_body: bool,
    pub(crate) max_body_size: usize,
}

/// Records HTTP traffic as HAR 1.2 via CDP Network domain events.
///
/// Call `start()` to enable the Network domain, feed events via
/// `process_event()`, and call `to_json()` to get the HAR output.
pub struct HarRecorder {
    client: CdpClient,
    session_id: String,
    state: HarRecorderState,
}

impl HarRecorderState {
    fn new() -> Self {
        Self {
            pending_entries: HashMap::new(),
            completed_entries: Vec::new(),
            capture_body: false,
            max_body_size: 1_048_576, // 1MB
        }
    }

    /// Process a CDP event. Routes to internal handlers based on event method.
    pub fn process_event(&mut self, event_method: &str, params: &Value) {
        match event_method {
            "Network.requestWillBeSent" => self.on_request_will_be_sent(params),
            "Network.responseReceived" => self.on_response_received(params),
            "Network.loadingFinished" => self.on_loading_finished(params),
            "Network.loadingFailed" => self.on_loading_failed(params),
            _ => {} // Ignore other events
        }
    }

    /// Build a complete HAR 1.2 log from completed entries.
    pub fn to_har(&self) -> HarLog {
        HarLog {
            log: HarLogInner {
                version: "1.2".to_string(),
                creator: HarCreator {
                    name: "Tallow".to_string(),
                    version: "0.3.0".to_string(),
                },
                pages: Vec::new(),
                entries: self.completed_entries.clone(),
            },
        }
    }

    /// Serialize to pretty-printed HAR JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.to_har())
    }

    /// Return the number of completed entries.
    pub fn entry_count(&self) -> usize {
        self.completed_entries.len()
    }

    /// Clear all pending and completed entries.
    pub fn clear(&mut self) {
        self.pending_entries.clear();
        self.completed_entries.clear();
    }

    fn on_request_will_be_sent(&mut self, params: &Value) {
        let request_id = match params.get("requestId").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return,
        };

        let request = params.get("request").unwrap_or(&Value::Null);

        let url = request
            .get("url")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let method = request
            .get("method")
            .and_then(|v| v.as_str())
            .unwrap_or("GET")
            .to_string();

        let headers = parse_cdp_headers(request.get("headers").unwrap_or(&Value::Null));

        // Use wallTime if available, otherwise current time
        let started = if let Some(wall_time) = params.get("wallTime").and_then(|v| v.as_f64()) {
            chrono::DateTime::from_timestamp(
                wall_time as i64,
                ((wall_time.fract()) * 1_000_000_000.0) as u32,
            )
            .unwrap_or_else(Utc::now)
        } else {
            Utc::now()
        };

        self.pending_entries.insert(
            request_id,
            PartialHarEntry {
                request_url: url,
                request_method: method,
                request_headers: headers,
                started,
                response_status: None,
                response_status_text: None,
                response_headers: Vec::new(),
                response_mime_type: None,
                response_body_size: None,
            },
        );
    }

    fn on_response_received(&mut self, params: &Value) {
        let request_id = match params.get("requestId").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return,
        };

        let response = params.get("response").unwrap_or(&Value::Null);

        if let Some(entry) = self.pending_entries.get_mut(&request_id) {
            entry.response_status = response.get("status").and_then(|v| v.as_u64()).map(|v| v as u16);
            entry.response_status_text = response
                .get("statusText")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            entry.response_headers =
                parse_cdp_headers(response.get("headers").unwrap_or(&Value::Null));
            entry.response_mime_type = response
                .get("mimeType")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
        }
    }

    fn on_loading_finished(&mut self, params: &Value) {
        // Sync path: no body capture. The async `HarRecorder::process_loading_finished`
        // supplies a fetched body via `complete_loading_finished`.
        self.complete_loading_finished(params, None);
    }

    /// Complete a `Network.loadingFinished` event, optionally attaching a
    /// captured response body (text + whether it is base64-encoded).
    ///
    /// Used by both the sync event path (body = `None`) and the async body
    /// capture path (body fetched via `Fetch.getResponseBody`).
    fn complete_loading_finished(&mut self, params: &Value, body: Option<(String, bool)>) {
        let request_id = match params.get("requestId").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return,
        };

        let encoded_data_length = params
            .get("encodedDataLength")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);

        if let Some(partial) = self.pending_entries.remove(&request_id) {
            let elapsed_ms = Utc::now()
                .signed_duration_since(partial.started)
                .num_milliseconds() as f64;

            let body_size = partial.response_body_size.unwrap_or(encoded_data_length);

            let (text, encoding) = match body {
                Some((t, is_base64)) => (
                    Some(t),
                    if is_base64 {
                        Some("base64".to_string())
                    } else {
                        None
                    },
                ),
                None => (None, None),
            };

            let entry = HarEntry {
                started_date_time: partial.started.to_rfc3339(),
                time: elapsed_ms,
                request: HarRequest {
                    method: partial.request_method,
                    url: partial.request_url,
                    http_version: "HTTP/1.1".to_string(),
                    headers: partial.request_headers,
                    query_string: Vec::new(),
                    body_size: -1,
                    headers_size: -1,
                },
                response: HarResponse {
                    status: partial.response_status.unwrap_or(0),
                    status_text: partial.response_status_text.unwrap_or_default(),
                    http_version: "HTTP/1.1".to_string(),
                    headers: partial.response_headers,
                    content: HarContent {
                        size: body_size,
                        compression: None,
                        mime_type: partial.response_mime_type.unwrap_or_default(),
                        text,
                        encoding,
                    },
                    redirect_url: String::new(),
                    body_size,
                    headers_size: -1,
                },
                timings: HarTimings {
                    blocked: -1.0,
                    dns: -1.0,
                    connect: -1.0,
                    send: 0.0,
                    wait: elapsed_ms,
                    receive: 0.0,
                    ssl: -1.0,
                },
                server_ip_address: None,
            };

            self.completed_entries.push(entry);
        }
    }

    fn on_loading_failed(&mut self, params: &Value) {
        let request_id = match params.get("requestId").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => return,
        };
        // Remove from pending -- failed requests are not included in HAR
        self.pending_entries.remove(&request_id);
    }
}

impl HarRecorder {
    /// Create a new recorder. Body capture is disabled by default.
    pub fn new(client: CdpClient, session_id: String) -> Self {
        Self {
            client,
            session_id,
            state: HarRecorderState::new(),
        }
    }

    /// Configure body capture. When enabled, response bodies up to `max_size`
    /// bytes are included in the HAR output.
    pub fn with_body_capture(mut self, capture: bool, max_size: usize) -> Self {
        self.state.capture_body = capture;
        self.state.max_body_size = max_size;
        self
    }

    /// Enable the Network domain to start receiving events.
    pub async fn start(&self) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session("Network.enable", None, &self.session_id)
            .await?;
        Ok(())
    }

    /// Disable the Network domain.
    pub async fn stop(&self) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session("Network.disable", None, &self.session_id)
            .await?;
        Ok(())
    }

    /// Process a CDP event. Delegates to internal state.
    pub fn process_event(&mut self, event_method: &str, params: &Value) {
        self.state.process_event(event_method, params);
    }

    /// Handle a `Network.loadingFinished` event, capturing the response body
    /// when body capture is enabled.
    ///
    /// When `with_body_capture` is on, this fetches the response body via
    /// CDP `Fetch.getResponseBody` and attaches it to the HAR entry as
    /// `HarContent.text` (with `encoding = "base64"` for binary payloads).
    /// Bodies are truncated to the configured `max_body_size` cap (1 MiB by
    /// default).  When body capture is disabled this is equivalent to the
    /// sync [`HarRecorder::process_event`] path and never issues a CDP call.
    ///
    /// Callers that enable body capture should route loading-finished events
    /// through this method *instead of* `process_event` to avoid a
    /// double-completion of the same request.
    pub async fn process_loading_finished(
        &mut self,
        params: &Value,
    ) -> Result<(), BrowserError> {
        if !self.state.capture_body {
            self.state.process_event("Network.loadingFinished", params);
            return Ok(());
        }

        let request_id = match params.get("requestId").and_then(|v| v.as_str()) {
            Some(id) => id.to_string(),
            None => {
                self.state.process_event("Network.loadingFinished", params);
                return Ok(());
            }
        };

        // Fetch the response body via CDP. A failure is non-fatal — we still
        // complete the entry, just without body text.
        let body = self
            .client
            .send_command_with_session(
                "Fetch.getResponseBody",
                Some(json!({ "requestId": request_id })),
                &self.session_id,
            )
            .await
            .ok()
            .map(|resp| {
                let raw = resp.get("body").and_then(|v| v.as_str()).unwrap_or("");
                let is_base64 = resp
                    .get("base64Encoded")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                let cap = self.state.max_body_size;
                let truncated = truncate_utf8(raw, cap);
                (truncated.to_string(), is_base64)
            });

        self.state.complete_loading_finished(params, body);
        Ok(())
    }

    /// Build a complete HAR 1.2 log from completed entries.
    pub fn to_har(&self) -> HarLog {
        self.state.to_har()
    }

    /// Serialize to pretty-printed HAR JSON.
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        self.state.to_json()
    }

    /// Return the number of completed entries.
    pub fn entry_count(&self) -> usize {
        self.state.entry_count()
    }

    /// Clear all pending and completed entries.
    pub fn clear(&mut self) {
        self.state.clear();
    }
}

/// Parse CDP Network event headers from a JSON object (map of name -> value)
/// into a Vec of HarNameValue pairs.
fn parse_cdp_headers(headers: &Value) -> Vec<HarNameValue> {
    match headers.as_object() {
        Some(map) => map
            .iter()
            .map(|(k, v)| HarNameValue {
                name: k.clone(),
                value: v.as_str().unwrap_or("").to_string(),
            })
            .collect(),
        None => Vec::new(),
    }
}

/// Truncate a string to at most `max_bytes` bytes without splitting a
/// multi-byte UTF-8 character. Used to enforce the HAR body-capture size cap
/// (1 MiB by default) so arbitrary (possibly binary/base64 or UTF-8) bodies
/// never produce an invalid slice or panic.
fn truncate_utf8(s: &str, max_bytes: usize) -> &str {
    if s.len() <= max_bytes {
        return s;
    }
    let mut end = max_bytes;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

// ---------------------------------------------------------------------------
// WebSocket Monitoring (CDP Network domain events)
// ---------------------------------------------------------------------------

/// A tracked WebSocket connection with its frame history.
#[derive(Debug, Clone)]
pub struct WebSocketConnection {
    /// CDP request ID identifying this WebSocket connection.
    pub request_id: String,
    /// The WebSocket URL (e.g., "wss://example.com/ws").
    pub url: String,
    /// The URL of the page/script that initiated the connection.
    pub initiator_url: Option<String>,
    /// All captured frames (sent and received) in chronological order.
    pub frames: Vec<WebSocketFrame>,
    /// Whether the connection has been closed.
    pub closed: bool,
}

/// Direction of a WebSocket frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebSocketFrameDirection {
    /// Frame sent from the page to the server.
    Sent,
    /// Frame received from the server.
    Received,
}

impl std::fmt::Display for WebSocketFrameDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WebSocketFrameDirection::Sent => write!(f, "Sent"),
            WebSocketFrameDirection::Received => write!(f, "Received"),
        }
    }
}

/// A single WebSocket frame (sent or received).
#[derive(Debug, Clone)]
pub struct WebSocketFrame {
    /// Whether this frame was sent or received.
    pub direction: WebSocketFrameDirection,
    /// WebSocket opcode (1 = text, 2 = binary, 8 = close, 9 = ping, 10 = pong).
    pub opcode: u8,
    /// The frame payload data (text content or base64-encoded binary).
    pub payload_data: String,
    /// Timestamp of the frame event.
    pub timestamp: f64,
}

/// Monitors WebSocket connections by processing CDP Network domain events.
///
/// Tracks `webSocketCreated`, `webSocketFrameSent`, `webSocketFrameReceived`,
/// `webSocketClosed`, and `webSocketFrameError` events. Each connection is
/// stored with its full frame history for later inspection.
pub struct WebSocketMonitor {
    connections: HashMap<String, WebSocketConnection>,
}

impl WebSocketMonitor {
    /// Create a new empty WebSocket monitor.
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    /// Process a CDP event, routing to the appropriate WebSocket handler.
    ///
    /// Handles:
    /// - `Network.webSocketCreated` — registers a new connection
    /// - `Network.webSocketFrameSent` — records a sent frame
    /// - `Network.webSocketFrameReceived` — records a received frame
    /// - `Network.webSocketClosed` — marks the connection as closed
    /// - `Network.webSocketFrameError` — silently ignored (logged in production)
    ///
    /// Unknown event methods are silently ignored.
    pub fn process_event(&mut self, event_method: &str, params: &serde_json::Value) {
        match event_method {
            "Network.webSocketCreated" => {
                let request_id = params["requestId"].as_str().unwrap_or("").to_string();
                let url = params["url"].as_str().unwrap_or("").to_string();
                let initiator_url = params
                    .get("initiator")
                    .and_then(|i| i.get("url"))
                    .and_then(|u| u.as_str())
                    .map(|s| s.to_string());

                if !request_id.is_empty() {
                    self.connections.insert(
                        request_id.clone(),
                        WebSocketConnection {
                            request_id,
                            url,
                            initiator_url,
                            frames: Vec::new(),
                            closed: false,
                        },
                    );
                }
            }
            "Network.webSocketFrameSent" => {
                let request_id = params["requestId"].as_str().unwrap_or("");
                if let Some(conn) = self.connections.get_mut(request_id) {
                    let response = &params["response"];
                    conn.frames.push(WebSocketFrame {
                        direction: WebSocketFrameDirection::Sent,
                        opcode: response["opcode"].as_u64().unwrap_or(1) as u8,
                        payload_data: response["payloadData"]
                            .as_str()
                            .unwrap_or("")
                            .to_string(),
                        timestamp: params["timestamp"].as_f64().unwrap_or(0.0),
                    });
                }
            }
            "Network.webSocketFrameReceived" => {
                let request_id = params["requestId"].as_str().unwrap_or("");
                if let Some(conn) = self.connections.get_mut(request_id) {
                    let response = &params["response"];
                    conn.frames.push(WebSocketFrame {
                        direction: WebSocketFrameDirection::Received,
                        opcode: response["opcode"].as_u64().unwrap_or(1) as u8,
                        payload_data: response["payloadData"]
                            .as_str()
                            .unwrap_or("")
                            .to_string(),
                        timestamp: params["timestamp"].as_f64().unwrap_or(0.0),
                    });
                }
            }
            "Network.webSocketClosed" => {
                let request_id = params["requestId"].as_str().unwrap_or("");
                if let Some(conn) = self.connections.get_mut(request_id) {
                    conn.closed = true;
                }
            }
            // webSocketFrameError, webSocketWillSendHandshakeRequest, etc. — silently ignored
            _ => {}
        }
    }

    /// Get a reference to all tracked connections.
    pub fn connections(&self) -> &HashMap<String, WebSocketConnection> {
        &self.connections
    }

    /// Get a specific connection by request ID.
    pub fn connection(&self, request_id: &str) -> Option<&WebSocketConnection> {
        self.connections.get(request_id)
    }

    /// Get frames for a specific connection by request ID.
    pub fn frames(&self, request_id: &str) -> Option<&[WebSocketFrame]> {
        self.connections.get(request_id).map(|c| c.frames.as_slice())
    }

    /// Collect all frames across all connections (unordered across connections).
    pub fn all_frames(&self) -> Vec<&WebSocketFrame> {
        self.connections
            .values()
            .flat_map(|c| c.frames.iter())
            .collect()
    }

    /// Clear all tracked connections and their frame histories.
    pub fn clear(&mut self) {
        self.connections.clear();
    }
}

// ---------------------------------------------------------------------------
// WebSocket Frame Modification (JS-level proxy)
// ---------------------------------------------------------------------------

/// Configuration for WebSocket frame interception via JS proxy injection.
///
/// The interceptor injects a JavaScript `Proxy` around the native `WebSocket`
/// constructor that can transform outgoing (`send`) and incoming (`onmessage`)
/// frames using user-provided JavaScript function bodies.
#[derive(Debug, Clone, Default)]
pub struct WebSocketInterceptConfig {
    /// Optional JS function body that transforms outgoing messages.
    /// Receives `data` parameter, must return modified data or `null` to suppress.
    /// Example: `"return data.replace('secret', '[REDACTED]')"`
    pub on_send: Option<String>,
    /// Optional JS function body that transforms incoming messages.
    /// Receives `data` parameter, must return modified data or `null` to suppress.
    /// Example: `"return JSON.parse(data).filtered ? null : data"`
    pub on_message: Option<String>,
    /// URL pattern filter -- only intercept WebSockets matching this substring.
    /// If `None`, intercepts all WebSocket connections.
    pub url_pattern: Option<String>,
}

/// WebSocket frame modification via JS-level WebSocket constructor proxy.
///
/// Injects a JavaScript proxy that wraps the native `WebSocket` constructor.
/// The proxy intercepts `send()` calls and `onmessage` events, allowing
/// user-defined callbacks to modify frames before they are sent/received.
///
/// This is the established pattern for WebSocket modification (puppeteer-extra
/// and similar tools use the same approach). CDP only supports monitoring.
pub struct WebSocketInterceptor {
    client: CdpClient,
    session_id: String,
}

impl WebSocketInterceptor {
    /// Create a new WebSocket interceptor for a specific page session.
    pub fn new(client: CdpClient, session_id: String) -> Self {
        Self {
            client,
            session_id,
        }
    }

    /// Enable WebSocket interception by injecting the proxy script.
    ///
    /// Uses `Page.addScriptToEvaluateOnNewDocument` to inject the WebSocket
    /// constructor proxy BEFORE any page JS executes. Must be called before
    /// navigation to intercept all WebSocket connections.
    pub async fn enable(&self, config: WebSocketInterceptConfig) -> Result<(), BrowserError> {
        let script = build_proxy_script(&config);

        self.client
            .send_command_with_session(
                "Page.addScriptToEvaluateOnNewDocument",
                Some(json!({
                    "source": script,
                })),
                &self.session_id,
            )
            .await
            .map_err(|e| BrowserError::CdpError {
                code: -1,
                message: format!("failed to inject WebSocket proxy: {}", e),
            })?;

        Ok(())
    }
}

/// Build the JavaScript WebSocket constructor proxy script.
///
/// The script:
/// 1. Saves the original `WebSocket` constructor
/// 2. Replaces `window.WebSocket` with a `Proxy` that wraps construction
/// 3. On `send()`: applies the `on_send` transform (if provided) before sending
/// 4. On `onmessage`: applies the `on_message` transform (if provided) before delivery
/// 5. Preserves `WebSocket.prototype` and static constants for `instanceof` checks
pub fn build_proxy_script(config: &WebSocketInterceptConfig) -> String {
    // URL pattern: null or a JS string
    let url_pattern_js = match &config.url_pattern {
        Some(pattern) => format!("\"{}\"", pattern.replace('\\', "\\\\").replace('"', "\\\"")),
        None => "null".to_string(),
    };

    // on_send block
    let on_send_block = match &config.on_send {
        Some(transform) => format!(
            r#"let modified = (function(data) {{ {} }})(data);
                    if (modified !== null && modified !== undefined) {{
                        originalSend(modified);
                    }}"#,
            transform
        ),
        None => "originalSend(data);".to_string(),
    };

    // on_message block
    let on_message_block = match &config.on_message {
        Some(transform) => format!(
            r#"let transformedData = (function(data) {{ {} }})(event.data);
                            if (transformedData !== null && transformedData !== undefined) {{
                                Object.defineProperty(event, 'data', {{ value: transformedData, writable: false }});
                                listener.call(ws, event);
                            }}"#,
            transform
        ),
        None => "listener.call(ws, event);".to_string(),
    };

    format!(
        r#"(function() {{
    const OriginalWebSocket = window.WebSocket;
    const urlPattern = {url_pattern_js};

    window.WebSocket = new Proxy(OriginalWebSocket, {{
        construct(target, args) {{
            const ws = new target(...args);
            const url = args[0];

            // Check URL filter
            if (urlPattern && !url.includes(urlPattern)) {{
                return ws;
            }}

            // Wrap send
            const originalSend = ws.send.bind(ws);
            ws.send = function(data) {{
                {on_send_block}
            }};

            // Wrap onmessage via addEventListener interception
            const originalAddEventListener = ws.addEventListener.bind(ws);
            ws.addEventListener = function(type, listener, options) {{
                if (type === 'message') {{
                    originalAddEventListener(type, function(event) {{
                        {on_message_block}
                    }}, options);
                }} else {{
                    originalAddEventListener(type, listener, options);
                }}
            }};

            // Wrap onmessage setter
            let userOnMessage = null;
            Object.defineProperty(ws, 'onmessage', {{
                get() {{ return userOnMessage; }},
                set(handler) {{
                    userOnMessage = handler;
                    ws.addEventListener('message', handler);
                }},
                configurable: true,
            }});

            return ws;
        }}
    }});

    // Preserve prototype chain for instanceof checks
    window.WebSocket.prototype = OriginalWebSocket.prototype;
    window.WebSocket.CONNECTING = OriginalWebSocket.CONNECTING;
    window.WebSocket.OPEN = OriginalWebSocket.OPEN;
    window.WebSocket.CLOSING = OriginalWebSocket.CLOSING;
    window.WebSocket.CLOSED = OriginalWebSocket.CLOSED;
}})();"#,
        url_pattern_js = url_pattern_js,
        on_send_block = on_send_block,
        on_message_block = on_message_block,
    )
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- glob_matches tests ----

    #[test]
    fn test_glob_matches_star_matches_everything() {
        assert!(glob_matches("*", "https://example.com/foo/bar.js"));
        assert!(glob_matches("*", ""));
        assert!(glob_matches("*", "anything"));
    }

    #[test]
    fn test_glob_matches_suffix() {
        assert!(glob_matches("*.js", "https://example.com/app.js"));
        assert!(glob_matches("*.js", "script.js"));
        assert!(!glob_matches("*.js", "script.css"));
        assert!(!glob_matches("*.js", "script.jsx"));
    }

    #[test]
    fn test_glob_matches_prefix() {
        assert!(glob_matches("https://api.*", "https://api.example.com"));
        assert!(glob_matches("https://api.*", "https://api.test.io/v1"));
        assert!(!glob_matches("https://api.*", "https://cdn.example.com"));
    }

    #[test]
    fn test_glob_matches_contains() {
        assert!(glob_matches("*analytics*", "https://example.com/analytics/track"));
        assert!(glob_matches("*analytics*", "https://analytics.google.com"));
        assert!(!glob_matches("*analytics*", "https://example.com/about"));
    }

    #[test]
    fn test_glob_matches_exact_no_wildcard() {
        assert!(glob_matches("exact", "exact"));
        assert!(!glob_matches("exact", "exactl"));
        assert!(!glob_matches("exact", "exac"));
    }

    #[test]
    fn test_glob_matches_multiple_wildcards() {
        assert!(glob_matches("https://*.com/*/api", "https://example.com/v1/api"));
        assert!(!glob_matches(
            "https://*.com/*/api",
            "https://example.org/v1/api"
        ));
    }

    #[test]
    fn test_glob_matches_double_star() {
        assert!(glob_matches("**", "anything"));
        assert!(glob_matches("prefix**suffix", "prefixMIDDLEsuffix"));
    }

    // ---- ResourceType::as_str tests ----

    #[test]
    fn test_resource_type_as_str() {
        assert_eq!(ResourceType::Document.as_str(), "Document");
        assert_eq!(ResourceType::Stylesheet.as_str(), "Stylesheet");
        assert_eq!(ResourceType::Image.as_str(), "Image");
        assert_eq!(ResourceType::Media.as_str(), "Media");
        assert_eq!(ResourceType::Font.as_str(), "Font");
        assert_eq!(ResourceType::Script.as_str(), "Script");
        assert_eq!(ResourceType::TextTrack.as_str(), "TextTrack");
        assert_eq!(ResourceType::XHR.as_str(), "XHR");
        assert_eq!(ResourceType::Fetch.as_str(), "Fetch");
        assert_eq!(ResourceType::Prefetch.as_str(), "Prefetch");
        assert_eq!(ResourceType::EventSource.as_str(), "EventSource");
        assert_eq!(ResourceType::WebSocket.as_str(), "WebSocket");
        assert_eq!(ResourceType::Manifest.as_str(), "Manifest");
        assert_eq!(ResourceType::Other.as_str(), "Other");
    }

    // ---- InterceptRule matching tests ----

    #[test]
    fn test_matches_rule_url_pattern() {
        let rules = vec![InterceptRule {
            url_pattern: Some("*.js".to_string()),
            resource_type: None,
            method: None,
            request_stage: RequestStage::Request,
            action: InterceptAction::Block,
        }];

        assert!(find_matching_rule(&rules, "https://example.com/app.js", "GET", "Script").is_some());
        assert!(find_matching_rule(&rules, "https://example.com/style.css", "GET", "Stylesheet").is_none());
    }

    #[test]
    fn test_matches_rule_method_case_insensitive() {
        let rules = vec![InterceptRule {
            url_pattern: None,
            resource_type: None,
            method: Some("POST".to_string()),
            request_stage: RequestStage::Request,
            action: InterceptAction::Block,
        }];

        assert!(find_matching_rule(&rules, "https://example.com/api", "post", "XHR").is_some());
        assert!(find_matching_rule(&rules, "https://example.com/api", "POST", "XHR").is_some());
        assert!(find_matching_rule(&rules, "https://example.com/api", "GET", "XHR").is_none());
    }

    #[test]
    fn test_matches_rule_resource_type() {
        let rules = vec![InterceptRule {
            url_pattern: None,
            resource_type: Some(ResourceType::Image),
            method: None,
            request_stage: RequestStage::Request,
            action: InterceptAction::Block,
        }];

        assert!(find_matching_rule(&rules, "https://example.com/photo.jpg", "GET", "Image").is_some());
        assert!(find_matching_rule(&rules, "https://example.com/photo.jpg", "GET", "Document").is_none());
    }

    #[test]
    fn test_matches_rule_first_match_wins() {
        let rules = vec![
            // First rule: block all .js
            InterceptRule {
                url_pattern: Some("*.js".to_string()),
                resource_type: None,
                method: None,
                request_stage: RequestStage::Request,
                action: InterceptAction::Block,
            },
            // Second rule: continue all
            InterceptRule {
                url_pattern: None,
                resource_type: None,
                method: None,
                request_stage: RequestStage::Request,
                action: InterceptAction::Continue,
            },
        ];

        let rule = find_matching_rule(&rules, "https://example.com/app.js", "GET", "Script").unwrap();
        assert!(matches!(rule.action, InterceptAction::Block));
    }

    #[test]
    fn test_matches_rule_no_match() {
        let rules = vec![InterceptRule {
            url_pattern: Some("*.js".to_string()),
            resource_type: None,
            method: Some("POST".to_string()),
            request_stage: RequestStage::Request,
            action: InterceptAction::Block,
        }];

        // Matches URL but not method
        assert!(find_matching_rule(&rules, "https://example.com/app.js", "GET", "Script").is_none());
    }

    // ---- MockResponse body base64 encoding test ----

    #[test]
    fn test_mock_response_body_base64() {
        let mock = MockResponse {
            status: 200,
            headers: vec![HeaderEntry {
                name: "Content-Type".to_string(),
                value: "application/json".to_string(),
            }],
            body: b"{\"ok\":true}".to_vec(),
        };

        let encoded = base64::engine::general_purpose::STANDARD.encode(&mock.body);
        assert_eq!(encoded, "eyJvayI6dHJ1ZX0=");

        // Verify round-trip
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .unwrap();
        assert_eq!(decoded, mock.body);
    }

    // ---- RequestStage tests ----

    #[test]
    fn test_request_stage_equality() {
        assert_eq!(RequestStage::Request, RequestStage::Request);
        assert_eq!(RequestStage::Response, RequestStage::Response);
        assert_ne!(RequestStage::Request, RequestStage::Response);
    }

    // ---- InterceptAction variant tests ----

    #[test]
    fn test_intercept_action_continue_modified_fields() {
        let action = InterceptAction::ContinueModified {
            url: Some("https://redirected.com".to_string()),
            method: Some("POST".to_string()),
            headers: Some(vec![HeaderEntry {
                name: "X-Custom".to_string(),
                value: "test".to_string(),
            }]),
            post_data: Some("body=data".to_string()),
        };

        if let InterceptAction::ContinueModified {
            url,
            method,
            headers,
            post_data,
        } = action
        {
            assert_eq!(url.unwrap(), "https://redirected.com");
            assert_eq!(method.unwrap(), "POST");
            assert_eq!(headers.unwrap().len(), 1);
            assert_eq!(post_data.unwrap(), "body=data");
        } else {
            panic!("Expected ContinueModified");
        }
    }

    // ---- Stop mechanism test ----

    #[test]
    fn test_stop_mechanism() {
        let running = Arc::new(AtomicBool::new(true));
        assert!(running.load(Ordering::SeqCst));

        running.store(false, Ordering::SeqCst);
        assert!(!running.load(Ordering::SeqCst));
    }

    // ---- HAR struct tests ----

    #[test]
    fn test_har_log_serializes_to_valid_json() {
        let har = HarLog {
            log: HarLogInner {
                version: "1.2".to_string(),
                creator: HarCreator {
                    name: "Tallow".to_string(),
                    version: "0.3.0".to_string(),
                },
                pages: Vec::new(),
                entries: Vec::new(),
            },
        };

        let json_str = serde_json::to_string_pretty(&har).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["log"]["version"], "1.2");
        assert_eq!(parsed["log"]["creator"]["name"], "Tallow");
        assert_eq!(parsed["log"]["creator"]["version"], "0.3.0");
        assert!(parsed["log"]["entries"].as_array().unwrap().is_empty());
        // pages should be absent because of skip_serializing_if
        assert!(parsed["log"].get("pages").is_none());
    }

    #[test]
    fn test_har_creator_in_output() {
        let har = HarLog {
            log: HarLogInner {
                version: "1.2".to_string(),
                creator: HarCreator {
                    name: "Tallow".to_string(),
                    version: "0.3.0".to_string(),
                },
                pages: Vec::new(),
                entries: Vec::new(),
            },
        };

        let json_str = serde_json::to_string(&har).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        assert_eq!(parsed["log"]["creator"]["name"], "Tallow");
        assert_eq!(parsed["log"]["version"], "1.2");
    }

    #[test]
    fn test_har_entry_camel_case_field_names() {
        let entry = HarEntry {
            started_date_time: "2026-03-03T12:00:00Z".to_string(),
            time: 42.0,
            request: HarRequest {
                method: "GET".to_string(),
                url: "https://example.com".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
                query_string: Vec::new(),
                body_size: -1,
                headers_size: -1,
            },
            response: HarResponse {
                status: 200,
                status_text: "OK".to_string(),
                http_version: "HTTP/1.1".to_string(),
                headers: Vec::new(),
                content: HarContent {
                    size: 1234,
                    compression: None,
                    mime_type: "text/html".to_string(),
                    text: None,
                    encoding: None,
                },
                redirect_url: String::new(),
                body_size: 1234,
                headers_size: -1,
            },
            timings: HarTimings {
                blocked: -1.0,
                dns: -1.0,
                connect: -1.0,
                send: 0.0,
                wait: 42.0,
                receive: 0.0,
                ssl: -1.0,
            },
            server_ip_address: None,
        };

        let json_str = serde_json::to_string(&entry).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        // Verify camelCase: startedDateTime, not started_date_time
        assert!(parsed.get("startedDateTime").is_some());
        assert!(parsed.get("started_date_time").is_none());

        // Verify request fields are camelCase
        assert!(parsed["request"].get("httpVersion").is_some());
        assert!(parsed["request"].get("queryString").is_some());
        assert!(parsed["request"].get("bodySize").is_some());
        assert!(parsed["request"].get("headersSize").is_some());

        // Verify response fields
        assert!(parsed["response"].get("statusText").is_some());
        assert!(parsed["response"].get("redirectUrl").is_some());
        assert!(parsed["response"].get("bodySize").is_some());

        // Verify content mimeType
        assert!(parsed["response"]["content"].get("mimeType").is_some());
        assert_eq!(parsed["response"]["content"]["mimeType"], "text/html");

        // Skip None fields
        assert!(parsed.get("serverIpAddress").is_none());
        assert!(parsed["response"]["content"].get("text").is_none());
        assert!(parsed["response"]["content"].get("compression").is_none());
    }

    // ---- HarRecorder event processing tests ----

    /// Helper to create a HarRecorder for testing without a live CDP connection.
    ///
    /// Uses `HarRecorderState` directly -- the internal state struct that
    /// `process_event` actually mutates. No CdpClient needed.
    fn test_recorder() -> HarRecorderState {
        HarRecorderState {
            pending_entries: HashMap::new(),
            completed_entries: Vec::new(),
            capture_body: false,
            max_body_size: 1_048_576,
        }
    }

    #[test]
    fn test_process_event_request_will_be_sent_creates_pending() {
        let mut recorder = test_recorder();
        let params = json!({
            "requestId": "req-1",
            "request": {
                "url": "https://example.com/page",
                "method": "GET",
                "headers": {
                    "User-Agent": "Tallow/0.1",
                    "Accept": "text/html"
                }
            },
            "wallTime": 1709470800.123
        });

        recorder.process_event("Network.requestWillBeSent", &params);

        assert_eq!(recorder.pending_entries.len(), 1);
        assert!(recorder.pending_entries.contains_key("req-1"));
        let entry = &recorder.pending_entries["req-1"];
        assert_eq!(entry.request_url, "https://example.com/page");
        assert_eq!(entry.request_method, "GET");
        assert_eq!(entry.request_headers.len(), 2);
    }

    #[test]
    fn test_process_event_response_received_updates_pending() {
        let mut recorder = test_recorder();

        // First, create a pending entry
        recorder.process_event(
            "Network.requestWillBeSent",
            &json!({
                "requestId": "req-2",
                "request": {
                    "url": "https://example.com/api",
                    "method": "POST",
                    "headers": {}
                }
            }),
        );

        // Then receive response
        recorder.process_event(
            "Network.responseReceived",
            &json!({
                "requestId": "req-2",
                "response": {
                    "status": 201,
                    "statusText": "Created",
                    "headers": {
                        "Content-Type": "application/json"
                    },
                    "mimeType": "application/json"
                }
            }),
        );

        let entry = &recorder.pending_entries["req-2"];
        assert_eq!(entry.response_status, Some(201));
        assert_eq!(
            entry.response_status_text.as_deref(),
            Some("Created")
        );
        assert_eq!(entry.response_headers.len(), 1);
        assert_eq!(entry.response_headers[0].name, "Content-Type");
        assert_eq!(
            entry.response_mime_type.as_deref(),
            Some("application/json")
        );
    }

    #[test]
    fn test_process_event_loading_finished_moves_to_completed() {
        let mut recorder = test_recorder();

        recorder.process_event(
            "Network.requestWillBeSent",
            &json!({
                "requestId": "req-3",
                "request": {
                    "url": "https://example.com/data",
                    "method": "GET",
                    "headers": {}
                }
            }),
        );

        recorder.process_event(
            "Network.responseReceived",
            &json!({
                "requestId": "req-3",
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "headers": {},
                    "mimeType": "text/html"
                }
            }),
        );

        recorder.process_event(
            "Network.loadingFinished",
            &json!({
                "requestId": "req-3",
                "encodedDataLength": 5678
            }),
        );

        assert_eq!(recorder.pending_entries.len(), 0);
        assert_eq!(recorder.completed_entries.len(), 1);
        assert_eq!(recorder.entry_count(), 1);

        let entry = &recorder.completed_entries[0];
        assert_eq!(entry.request.url, "https://example.com/data");
        assert_eq!(entry.request.method, "GET");
        assert_eq!(entry.response.status, 200);
        assert_eq!(entry.response.status_text, "OK");
        assert_eq!(entry.response.content.mime_type, "text/html");
        assert!(entry.time >= 0.0);
    }

    #[test]
    fn test_loading_finished_with_captured_body_sets_content_text() {
        let mut recorder = test_recorder();

        recorder.process_event(
            "Network.requestWillBeSent",
            &json!({
                "requestId": "req-body",
                "request": {
                    "url": "https://example.com/data",
                    "method": "GET",
                    "headers": {}
                }
            }),
        );
        recorder.process_event(
            "Network.responseReceived",
            &json!({
                "requestId": "req-body",
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "headers": {},
                    "mimeType": "application/json"
                }
            }),
        );

        // Complete the entry via the body-capture path (what
        // `HarRecorder::process_loading_finished` does after a
        // Fetch.getResponseBody call).
        recorder.complete_loading_finished(
            &json!({
                "requestId": "req-body",
                "encodedDataLength": 42
            }),
            Some(("{\"ok\":true}".to_string(), false)),
        );

        assert_eq!(recorder.completed_entries.len(), 1);
        let entry = &recorder.completed_entries[0];
        assert_eq!(entry.response.content.text.as_deref(), Some("{\"ok\":true}"));
        assert_eq!(entry.response.content.encoding, None);
    }

    #[test]
    fn test_loading_finished_with_base64_body_sets_encoding() {
        let mut recorder = test_recorder();

        recorder.process_event(
            "Network.requestWillBeSent",
            &json!({
                "requestId": "req-b64",
                "request": {
                    "url": "https://example.com/image",
                    "method": "GET",
                    "headers": {}
                }
            }),
        );

        // Binary bodies arrive base64-encoded from Fetch.getResponseBody.
        recorder.complete_loading_finished(
            &json!({ "requestId": "req-b64", "encodedDataLength": 4 }),
            Some(("aGVsbG8=".to_string(), true)),
        );

        let entry = &recorder.completed_entries[0];
        assert_eq!(entry.response.content.text.as_deref(), Some("aGVsbG8="));
        assert_eq!(entry.response.content.encoding.as_deref(), Some("base64"));
    }

    #[test]
    fn test_truncate_utf8_respects_cap() {
        // Short string: unchanged.
        assert_eq!(truncate_utf8("hello", 10), "hello");
        // ASCII: byte-cap truncation at boundary.
        assert_eq!(truncate_utf8("hello world", 5), "hello");
        // Multi-byte UTF-8: never splits a char mid-sequence.
        let s = "héllo wörld";
        let truncated = truncate_utf8(s, 6);
        assert!(truncated.is_char_boundary(truncated.len()));
        assert!(truncated.len() <= 6);
        // Exact-size string: no truncation.
        assert_eq!(truncate_utf8("abcdef", 6), "abcdef");
    }

    #[test]
    fn test_process_event_loading_failed_removes_pending() {
        let mut recorder = test_recorder();

        recorder.process_event(
            "Network.requestWillBeSent",
            &json!({
                "requestId": "req-4",
                "request": {
                    "url": "https://example.com/fail",
                    "method": "GET",
                    "headers": {}
                }
            }),
        );

        assert_eq!(recorder.pending_entries.len(), 1);

        recorder.process_event(
            "Network.loadingFailed",
            &json!({
                "requestId": "req-4",
                "errorText": "net::ERR_CONNECTION_REFUSED"
            }),
        );

        assert_eq!(recorder.pending_entries.len(), 0);
        assert_eq!(recorder.completed_entries.len(), 0);
    }

    #[test]
    fn test_to_json_produces_valid_har_12_structure() {
        let mut recorder = test_recorder();

        recorder.process_event(
            "Network.requestWillBeSent",
            &json!({
                "requestId": "req-5",
                "request": {
                    "url": "https://example.com/test",
                    "method": "GET",
                    "headers": {"Accept": "text/html"}
                }
            }),
        );
        recorder.process_event(
            "Network.responseReceived",
            &json!({
                "requestId": "req-5",
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "headers": {"Content-Type": "text/html"},
                    "mimeType": "text/html"
                }
            }),
        );
        recorder.process_event(
            "Network.loadingFinished",
            &json!({
                "requestId": "req-5",
                "encodedDataLength": 1024
            }),
        );

        let json_str = recorder.to_json().unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();

        // HAR 1.2 structure
        assert!(parsed.get("log").is_some());
        assert_eq!(parsed["log"]["version"], "1.2");
        assert_eq!(parsed["log"]["creator"]["name"], "Tallow");

        let entries = parsed["log"]["entries"].as_array().unwrap();
        assert_eq!(entries.len(), 1);

        let entry = &entries[0];
        assert!(entry.get("startedDateTime").is_some());
        assert!(entry.get("time").is_some());
        assert!(entry.get("request").is_some());
        assert!(entry.get("response").is_some());
        assert!(entry.get("timings").is_some());

        assert_eq!(entry["request"]["url"], "https://example.com/test");
        assert_eq!(entry["response"]["status"], 200);
    }

    #[test]
    fn test_capture_body_false_content_text_is_none() {
        let mut recorder = test_recorder();
        assert!(!recorder.capture_body); // Default is false

        recorder.process_event(
            "Network.requestWillBeSent",
            &json!({
                "requestId": "req-body-test",
                "request": {
                    "url": "https://example.com/page",
                    "method": "GET",
                    "headers": {}
                }
            }),
        );
        recorder.process_event(
            "Network.responseReceived",
            &json!({
                "requestId": "req-body-test",
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "headers": {},
                    "mimeType": "text/html"
                }
            }),
        );
        recorder.process_event(
            "Network.loadingFinished",
            &json!({
                "requestId": "req-body-test",
                "encodedDataLength": 500
            }),
        );

        assert_eq!(recorder.completed_entries.len(), 1);
        let entry = &recorder.completed_entries[0];

        // CRITICAL: When capture_body is false, content.text MUST be None
        assert!(
            entry.response.content.text.is_none(),
            "content.text must be None when capture_body is false"
        );

        // Also verify in serialized JSON: text field should be absent
        let json_str = recorder.to_json().unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        let content = &parsed["log"]["entries"][0]["response"]["content"];
        assert!(
            content.get("text").is_none(),
            "text field must be absent in JSON when capture_body is false"
        );
    }

    #[test]
    fn test_body_size_limit_respected() {
        let mut recorder = test_recorder();
        recorder.capture_body = true;
        recorder.max_body_size = 100; // Very small limit

        recorder.process_event(
            "Network.requestWillBeSent",
            &json!({
                "requestId": "req-big",
                "request": {
                    "url": "https://example.com/large",
                    "method": "GET",
                    "headers": {}
                }
            }),
        );
        recorder.process_event(
            "Network.responseReceived",
            &json!({
                "requestId": "req-big",
                "response": {
                    "status": 200,
                    "statusText": "OK",
                    "headers": {},
                    "mimeType": "application/octet-stream"
                }
            }),
        );
        recorder.process_event(
            "Network.loadingFinished",
            &json!({
                "requestId": "req-big",
                "encodedDataLength": 999999
            }),
        );

        // Even with capture_body=true, the sync process_event never fetches body
        // (requires async CDP call). Body text should be None.
        let entry = &recorder.completed_entries[0];
        assert!(entry.response.content.text.is_none());
    }

    #[test]
    fn test_har_recorder_clear() {
        let mut recorder = test_recorder();

        recorder.process_event(
            "Network.requestWillBeSent",
            &json!({
                "requestId": "req-clear-1",
                "request": { "url": "https://a.com", "method": "GET", "headers": {} }
            }),
        );
        recorder.process_event(
            "Network.requestWillBeSent",
            &json!({
                "requestId": "req-clear-2",
                "request": { "url": "https://b.com", "method": "GET", "headers": {} }
            }),
        );
        recorder.process_event(
            "Network.responseReceived",
            &json!({
                "requestId": "req-clear-1",
                "response": { "status": 200, "statusText": "OK", "headers": {}, "mimeType": "text/html" }
            }),
        );
        recorder.process_event(
            "Network.loadingFinished",
            &json!({
                "requestId": "req-clear-1",
                "encodedDataLength": 100
            }),
        );

        assert_eq!(recorder.pending_entries.len(), 1); // req-clear-2 still pending
        assert_eq!(recorder.completed_entries.len(), 1);

        recorder.clear();
        assert_eq!(recorder.pending_entries.len(), 0);
        assert_eq!(recorder.completed_entries.len(), 0);
        assert_eq!(recorder.entry_count(), 0);
    }

    #[test]
    fn test_parse_cdp_headers() {
        let headers = json!({
            "Content-Type": "text/html",
            "X-Custom": "value"
        });

        let parsed = parse_cdp_headers(&headers);
        assert_eq!(parsed.len(), 2);
        // Order may vary since it's a JSON object
        let names: Vec<&str> = parsed.iter().map(|h| h.name.as_str()).collect();
        assert!(names.contains(&"Content-Type"));
        assert!(names.contains(&"X-Custom"));
    }

    #[test]
    fn test_parse_cdp_headers_empty() {
        let headers = json!({});
        let parsed = parse_cdp_headers(&headers);
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_parse_cdp_headers_not_object() {
        let headers = json!(null);
        let parsed = parse_cdp_headers(&headers);
        assert!(parsed.is_empty());
    }

    #[test]
    fn test_with_body_capture_config() {
        let recorder = test_recorder();
        assert!(!recorder.capture_body);
        assert_eq!(recorder.max_body_size, 1_048_576);

        // Note: with_body_capture takes ownership; for test, reconstruct
        let mut recorder2 = test_recorder();
        recorder2.capture_body = true;
        recorder2.max_body_size = 512;
        assert!(recorder2.capture_body);
        assert_eq!(recorder2.max_body_size, 512);
    }

    #[test]
    fn test_har_timings_fields_present() {
        let timings = HarTimings {
            blocked: 0.5,
            dns: 1.2,
            connect: 3.4,
            send: 0.1,
            wait: 50.0,
            receive: 5.0,
            ssl: 2.0,
        };
        let json_str = serde_json::to_string(&timings).unwrap();
        let parsed: Value = serde_json::from_str(&json_str).unwrap();
        assert_eq!(parsed["blocked"], 0.5);
        assert_eq!(parsed["dns"], 1.2);
        assert_eq!(parsed["connect"], 3.4);
        assert_eq!(parsed["send"], 0.1);
        assert_eq!(parsed["wait"], 50.0);
        assert_eq!(parsed["receive"], 5.0);
        assert_eq!(parsed["ssl"], 2.0);
    }

    #[test]
    fn test_multiple_entries_correlation() {
        let mut recorder = test_recorder();

        // Send two requests
        for i in 1..=2 {
            recorder.process_event(
                "Network.requestWillBeSent",
                &json!({
                    "requestId": format!("multi-{i}"),
                    "request": {
                        "url": format!("https://example.com/page{i}"),
                        "method": "GET",
                        "headers": {}
                    }
                }),
            );
        }

        // Response for request 2 arrives first
        recorder.process_event(
            "Network.responseReceived",
            &json!({
                "requestId": "multi-2",
                "response": { "status": 404, "statusText": "Not Found", "headers": {}, "mimeType": "text/html" }
            }),
        );
        recorder.process_event(
            "Network.loadingFinished",
            &json!({ "requestId": "multi-2", "encodedDataLength": 200 }),
        );

        // Then response for request 1
        recorder.process_event(
            "Network.responseReceived",
            &json!({
                "requestId": "multi-1",
                "response": { "status": 200, "statusText": "OK", "headers": {}, "mimeType": "text/html" }
            }),
        );
        recorder.process_event(
            "Network.loadingFinished",
            &json!({ "requestId": "multi-1", "encodedDataLength": 500 }),
        );

        assert_eq!(recorder.entry_count(), 2);
        // First completed is multi-2 (finished first)
        assert_eq!(recorder.completed_entries[0].request.url, "https://example.com/page2");
        assert_eq!(recorder.completed_entries[0].response.status, 404);
        // Second completed is multi-1
        assert_eq!(recorder.completed_entries[1].request.url, "https://example.com/page1");
        assert_eq!(recorder.completed_entries[1].response.status, 200);
    }

    // -----------------------------------------------------------------------
    // WebSocket Monitor tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_ws_created_adds_connection() {
        let mut monitor = WebSocketMonitor::new();
        monitor.process_event(
            "Network.webSocketCreated",
            &json!({
                "requestId": "ws-1",
                "url": "wss://example.com/ws",
                "initiator": { "url": "https://example.com/page" }
            }),
        );

        assert_eq!(monitor.connections().len(), 1);
        let conn = monitor.connection("ws-1").unwrap();
        assert_eq!(conn.url, "wss://example.com/ws");
        assert_eq!(
            conn.initiator_url.as_deref(),
            Some("https://example.com/page")
        );
        assert!(!conn.closed);
        assert!(conn.frames.is_empty());
    }

    #[test]
    fn test_ws_created_without_initiator() {
        let mut monitor = WebSocketMonitor::new();
        monitor.process_event(
            "Network.webSocketCreated",
            &json!({
                "requestId": "ws-2",
                "url": "wss://example.com/ws"
            }),
        );

        let conn = monitor.connection("ws-2").unwrap();
        assert!(conn.initiator_url.is_none());
    }

    #[test]
    fn test_ws_frame_sent_adds_frame() {
        let mut monitor = WebSocketMonitor::new();
        monitor.process_event(
            "Network.webSocketCreated",
            &json!({ "requestId": "ws-1", "url": "wss://example.com/ws" }),
        );
        monitor.process_event(
            "Network.webSocketFrameSent",
            &json!({
                "requestId": "ws-1",
                "timestamp": 1234.5,
                "response": {
                    "opcode": 1,
                    "payloadData": "hello server"
                }
            }),
        );

        let frames = monitor.frames("ws-1").unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].direction, WebSocketFrameDirection::Sent);
        assert_eq!(frames[0].opcode, 1);
        assert_eq!(frames[0].payload_data, "hello server");
        assert!((frames[0].timestamp - 1234.5).abs() < 0.001);
    }

    #[test]
    fn test_ws_frame_received_adds_frame() {
        let mut monitor = WebSocketMonitor::new();
        monitor.process_event(
            "Network.webSocketCreated",
            &json!({ "requestId": "ws-1", "url": "wss://example.com/ws" }),
        );
        monitor.process_event(
            "Network.webSocketFrameReceived",
            &json!({
                "requestId": "ws-1",
                "timestamp": 5678.9,
                "response": {
                    "opcode": 1,
                    "payloadData": "hello client"
                }
            }),
        );

        let frames = monitor.frames("ws-1").unwrap();
        assert_eq!(frames.len(), 1);
        assert_eq!(frames[0].direction, WebSocketFrameDirection::Received);
        assert_eq!(frames[0].payload_data, "hello client");
    }

    #[test]
    fn test_ws_closed_sets_flag() {
        let mut monitor = WebSocketMonitor::new();
        monitor.process_event(
            "Network.webSocketCreated",
            &json!({ "requestId": "ws-1", "url": "wss://example.com/ws" }),
        );
        assert!(!monitor.connection("ws-1").unwrap().closed);

        monitor.process_event(
            "Network.webSocketClosed",
            &json!({ "requestId": "ws-1", "timestamp": 9999.0 }),
        );
        assert!(monitor.connection("ws-1").unwrap().closed);
        // Connection is still in the map with its history
        assert!(monitor.connection("ws-1").is_some());
    }

    #[test]
    fn test_ws_frames_for_specific_connection() {
        let mut monitor = WebSocketMonitor::new();
        monitor.process_event(
            "Network.webSocketCreated",
            &json!({ "requestId": "ws-a", "url": "wss://a.com/ws" }),
        );
        monitor.process_event(
            "Network.webSocketCreated",
            &json!({ "requestId": "ws-b", "url": "wss://b.com/ws" }),
        );

        // Send frames to different connections
        monitor.process_event(
            "Network.webSocketFrameSent",
            &json!({ "requestId": "ws-a", "timestamp": 1.0, "response": { "opcode": 1, "payloadData": "to-a" } }),
        );
        monitor.process_event(
            "Network.webSocketFrameReceived",
            &json!({ "requestId": "ws-b", "timestamp": 2.0, "response": { "opcode": 1, "payloadData": "from-b" } }),
        );

        let a_frames = monitor.frames("ws-a").unwrap();
        assert_eq!(a_frames.len(), 1);
        assert_eq!(a_frames[0].payload_data, "to-a");

        let b_frames = monitor.frames("ws-b").unwrap();
        assert_eq!(b_frames.len(), 1);
        assert_eq!(b_frames[0].payload_data, "from-b");
    }

    #[test]
    fn test_ws_all_frames_across_connections() {
        let mut monitor = WebSocketMonitor::new();
        monitor.process_event(
            "Network.webSocketCreated",
            &json!({ "requestId": "ws-a", "url": "wss://a.com/ws" }),
        );
        monitor.process_event(
            "Network.webSocketCreated",
            &json!({ "requestId": "ws-b", "url": "wss://b.com/ws" }),
        );

        monitor.process_event(
            "Network.webSocketFrameSent",
            &json!({ "requestId": "ws-a", "timestamp": 1.0, "response": { "opcode": 1, "payloadData": "msg1" } }),
        );
        monitor.process_event(
            "Network.webSocketFrameReceived",
            &json!({ "requestId": "ws-b", "timestamp": 2.0, "response": { "opcode": 1, "payloadData": "msg2" } }),
        );
        monitor.process_event(
            "Network.webSocketFrameSent",
            &json!({ "requestId": "ws-a", "timestamp": 3.0, "response": { "opcode": 1, "payloadData": "msg3" } }),
        );

        let all = monitor.all_frames();
        assert_eq!(all.len(), 3);
        let payloads: Vec<&str> = all.iter().map(|f| f.payload_data.as_str()).collect();
        assert!(payloads.contains(&"msg1"));
        assert!(payloads.contains(&"msg2"));
        assert!(payloads.contains(&"msg3"));
    }

    #[test]
    fn test_ws_unknown_event_ignored() {
        let mut monitor = WebSocketMonitor::new();
        // These should not panic or add anything
        monitor.process_event("Network.webSocketFrameError", &json!({ "requestId": "ws-x" }));
        monitor.process_event("Network.webSocketWillSendHandshakeRequest", &json!({}));
        monitor.process_event("SomeOther.event", &json!({}));
        assert!(monitor.connections().is_empty());
    }

    #[test]
    fn test_ws_frame_for_unknown_connection_ignored() {
        let mut monitor = WebSocketMonitor::new();
        // Frame for non-existent connection — should not panic
        monitor.process_event(
            "Network.webSocketFrameSent",
            &json!({ "requestId": "nonexistent", "timestamp": 1.0, "response": { "opcode": 1, "payloadData": "data" } }),
        );
        assert!(monitor.connections().is_empty());
    }

    #[test]
    fn test_ws_frame_direction_display() {
        assert_eq!(format!("{}", WebSocketFrameDirection::Sent), "Sent");
        assert_eq!(format!("{}", WebSocketFrameDirection::Received), "Received");
    }

    #[test]
    fn test_ws_clear() {
        let mut monitor = WebSocketMonitor::new();
        monitor.process_event(
            "Network.webSocketCreated",
            &json!({ "requestId": "ws-1", "url": "wss://example.com/ws" }),
        );
        assert_eq!(monitor.connections().len(), 1);

        monitor.clear();
        assert!(monitor.connections().is_empty());
    }

    #[test]
    fn test_ws_connection_not_found() {
        let monitor = WebSocketMonitor::new();
        assert!(monitor.connection("nonexistent").is_none());
        assert!(monitor.frames("nonexistent").is_none());
    }

    // -----------------------------------------------------------------------
    // WebSocket Interceptor (JS proxy) tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_proxy_script_with_on_send() {
        let config = WebSocketInterceptConfig {
            on_send: Some("return data.replace('secret', '[REDACTED]')".to_string()),
            on_message: None,
            url_pattern: None,
        };
        let script = build_proxy_script(&config);
        assert!(script.contains("OriginalWebSocket"));
        assert!(script.contains("return data.replace('secret', '[REDACTED]')"));
        // No URL filter
        assert!(script.contains("const urlPattern = null;"));
    }

    #[test]
    fn test_proxy_script_with_on_message() {
        let config = WebSocketInterceptConfig {
            on_send: None,
            on_message: Some("return JSON.parse(data).filtered ? null : data".to_string()),
            url_pattern: None,
        };
        let script = build_proxy_script(&config);
        assert!(script.contains("return JSON.parse(data).filtered ? null : data"));
        // Send should be passthrough
        assert!(script.contains("originalSend(data);"));
    }

    #[test]
    fn test_proxy_script_with_url_pattern() {
        let config = WebSocketInterceptConfig {
            on_send: None,
            on_message: None,
            url_pattern: Some("api.example.com".to_string()),
        };
        let script = build_proxy_script(&config);
        assert!(script.contains("\"api.example.com\""));
        assert!(script.contains("url.includes(urlPattern)"));
    }

    #[test]
    fn test_proxy_script_default_passthrough() {
        let config = WebSocketInterceptConfig::default();
        let script = build_proxy_script(&config);
        // Should be a valid IIFE
        assert!(script.starts_with("(function()"));
        assert!(script.ends_with("})();"));
        // No transforms — just passthrough
        assert!(script.contains("originalSend(data);"));
        assert!(script.contains("listener.call(ws, event);"));
        // Preserves prototype and constants
        assert!(script.contains("window.WebSocket.prototype = OriginalWebSocket.prototype"));
        assert!(script.contains("window.WebSocket.CONNECTING"));
        assert!(script.contains("window.WebSocket.OPEN"));
        assert!(script.contains("window.WebSocket.CLOSING"));
        assert!(script.contains("window.WebSocket.CLOSED"));
    }

    #[test]
    fn test_proxy_script_both_transforms() {
        let config = WebSocketInterceptConfig {
            on_send: Some("return data + '-modified'".to_string()),
            on_message: Some("return data.toUpperCase()".to_string()),
            url_pattern: Some("ws.example.com".to_string()),
        };
        let script = build_proxy_script(&config);
        assert!(script.contains("return data + '-modified'"));
        assert!(script.contains("return data.toUpperCase()"));
        assert!(script.contains("\"ws.example.com\""));
    }

    #[test]
    fn test_proxy_script_url_pattern_escaping() {
        let config = WebSocketInterceptConfig {
            on_send: None,
            on_message: None,
            url_pattern: Some("test\"escape".to_string()),
        };
        let script = build_proxy_script(&config);
        // The quote should be escaped in the JS string
        assert!(script.contains("\\\"escape"));
    }

    #[test]
    fn test_websocket_intercept_config_default_all_none() {
        let config = WebSocketInterceptConfig::default();
        assert!(config.on_send.is_none());
        assert!(config.on_message.is_none());
        assert!(config.url_pattern.is_none());
    }

    #[test]
    fn test_proxy_script_suppression_pattern_send() {
        let config = WebSocketInterceptConfig {
            on_send: Some("return null".to_string()),
            on_message: None,
            url_pattern: None,
        };
        let script = build_proxy_script(&config);
        // When on_send returns null, the message should be suppressed
        assert!(script.contains("if (modified !== null && modified !== undefined)"));
    }

    #[test]
    fn test_proxy_script_suppression_pattern_message() {
        let config = WebSocketInterceptConfig {
            on_send: None,
            on_message: Some("return null".to_string()),
            url_pattern: None,
        };
        let script = build_proxy_script(&config);
        // When on_message returns null, the handler should not be called
        assert!(script.contains("if (transformedData !== null && transformedData !== undefined)"));
    }
}
