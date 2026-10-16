//! Accessibility auditing and cookie consent handling for browser automation.
//!
//! Provides:
//! - Full accessibility tree retrieval via CDP `Accessibility.getFullAXTree`
//! - WCAG compliance auditing via axe-core injection and `Runtime.evaluate`
//! - Cookie consent banner detection using DOM heuristics
//! - Auto-accept and selective reject of consent banners

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use super::cdp::CdpClient;
use super::error::BrowserError;

// ---------------------------------------------------------------------------
// WCAG conformance level
// ---------------------------------------------------------------------------

/// WCAG conformance level for auditing.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum WcagLevel {
    A,
    AA,
    AAA,
}

impl WcagLevel {
    pub fn axe_tags(&self) -> Vec<&'static str> {
        match self {
            WcagLevel::A => vec!["wcag2a", "wcag21a"],
            WcagLevel::AA => vec!["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"],
            WcagLevel::AAA => vec!["wcag2a", "wcag2aa", "wcag2aaa", "wcag21a", "wcag21aa", "wcag21aaa"],
        }
    }
}

// ---------------------------------------------------------------------------
// Axe-core JS (vendored)
// ---------------------------------------------------------------------------

/// Vendored axe-core JavaScript library for WCAG auditing.
/// Replace vendor/axe-core/axe.min.js with the real axe-core release for
/// production use. The stub returns empty results.
const AXE_CORE_JS: &str = include_str!("../../vendor/axe-core/axe.min.js");

// ---------------------------------------------------------------------------
// Accessibility tree types
// ---------------------------------------------------------------------------

/// A single node in the accessibility tree.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AXNode {
    /// Unique node identifier within the accessibility tree.
    pub node_id: String,
    /// ARIA role of the node (e.g. "button", "heading", "link").
    pub role: String,
    /// Accessible name of the node.
    pub name: Option<String>,
    /// Accessible value (e.g. input value, slider position).
    pub value: Option<String>,
    /// Accessible description.
    pub description: Option<String>,
    /// IDs of child nodes in the tree.
    pub children: Vec<String>,
    /// Additional accessibility properties.
    pub properties: Vec<AXProperty>,
}

/// An accessibility property on a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AXProperty {
    /// Property name (e.g. "focusable", "disabled", "level").
    pub name: String,
    /// Property value.
    pub value: AXValue,
}

/// Typed accessibility property value.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AXValue {
    /// String value.
    String(String),
    /// Boolean value.
    Bool(bool),
    /// Numeric value.
    Number(f64),
    /// No value / not applicable.
    None,
}

// ---------------------------------------------------------------------------
// WCAG audit types
// ---------------------------------------------------------------------------

/// A single WCAG violation found by axe-core.
#[derive(Debug, Clone, Serialize)]
pub struct WcagViolation {
    /// Rule identifier (e.g. "color-contrast", "image-alt").
    pub id: String,
    /// Impact level: "critical", "serious", "moderate", or "minor".
    pub impact: String,
    /// Human-readable description of the violation.
    pub description: String,
    /// URL to the axe-core help page for this rule.
    pub help_url: String,
    /// Number of DOM nodes affected by this violation.
    pub nodes_count: usize,
}

/// Complete WCAG audit result from axe-core.
#[derive(Debug, Clone, Serialize)]
pub struct WcagAuditResult {
    /// Violations found (accessibility failures).
    pub violations: Vec<WcagViolation>,
    /// Number of rules that passed.
    pub passes_count: usize,
    /// Number of rules that could not be fully evaluated.
    pub incomplete_count: usize,
    /// Number of rules that were not applicable.
    pub inapplicable_count: usize,
}

// ---------------------------------------------------------------------------
// Cookie consent types
// ---------------------------------------------------------------------------

/// Information about a detected cookie consent banner.
#[derive(Debug, Clone)]
pub struct ConsentBannerInfo {
    /// Whether a consent banner was found on the page.
    pub found: bool,
    /// CSS selector for the banner container element.
    pub banner_selector: Option<String>,
    /// CSS selector for the "accept all" button.
    pub accept_selector: Option<String>,
    /// CSS selector for the "reject all" button.
    pub reject_selector: Option<String>,
    /// CSS selector for the "customize/manage" button.
    pub customize_selector: Option<String>,
}

// ---------------------------------------------------------------------------
// Accessibility tree functions
// ---------------------------------------------------------------------------

/// Parse a CDP accessibility node from the `Accessibility.getFullAXTree` response.
fn parse_ax_node(node: &Value) -> AXNode {
    let node_id = node
        .get("nodeId")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let role = node
        .get("role")
        .and_then(|v| v.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("none")
        .to_string();

    let name = node
        .get("name")
        .and_then(|v| v.get("value"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let value = node
        .get("value")
        .and_then(|v| v.get("value"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let description = node
        .get("description")
        .and_then(|v| v.get("value"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let children = node
        .get("childIds")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();

    let properties = node
        .get("properties")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|prop| {
                    let name = prop.get("name")?.as_str()?.to_string();
                    let raw_value = prop.get("value").and_then(|v| v.get("value"));
                    let value = match raw_value {
                        Some(Value::String(s)) => AXValue::String(s.clone()),
                        Some(Value::Bool(b)) => AXValue::Bool(*b),
                        Some(Value::Number(n)) => {
                            AXValue::Number(n.as_f64().unwrap_or(0.0))
                        }
                        _ => AXValue::None,
                    };
                    Some(AXProperty { name, value })
                })
                .collect()
        })
        .unwrap_or_default();

    AXNode {
        node_id,
        role,
        name,
        value,
        description,
        children,
        properties,
    }
}

/// Retrieve the full accessibility tree for the current page.
///
/// Enables the Accessibility domain and calls `Accessibility.getFullAXTree`,
/// then parses all nodes into `AXNode` structs.
pub async fn get_accessibility_tree(
    client: &CdpClient,
    session_id: &str,
) -> Result<Vec<AXNode>, BrowserError> {
    // Enable the Accessibility domain (idempotent)
    client
        .send_command_with_session("Accessibility.enable", None, session_id)
        .await?;

    // Get the full accessibility tree
    let result = client
        .send_command_with_session("Accessibility.getFullAXTree", None, session_id)
        .await?;

    let nodes = result
        .get("nodes")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(parse_ax_node).collect())
        .unwrap_or_default();

    Ok(nodes)
}

/// Query the accessibility tree for nodes matching optional role and/or name filters.
///
/// Uses `Accessibility.queryAXTree` which is more efficient than fetching
/// the full tree and filtering client-side.
pub async fn query_accessibility_node(
    client: &CdpClient,
    session_id: &str,
    role: Option<&str>,
    name: Option<&str>,
) -> Result<Vec<AXNode>, BrowserError> {
    // Enable the Accessibility domain (idempotent)
    client
        .send_command_with_session("Accessibility.enable", None, session_id)
        .await?;

    let mut params = json!({});
    if let Some(r) = role {
        params["accessibleRole"] = json!(r);
    }
    if let Some(n) = name {
        params["accessibleName"] = json!(n);
    }

    let result = client
        .send_command_with_session("Accessibility.queryAXTree", Some(params), session_id)
        .await?;

    let nodes = result
        .get("nodes")
        .and_then(|v| v.as_array())
        .map(|arr| arr.iter().map(parse_ax_node).collect())
        .unwrap_or_default();

    Ok(nodes)
}

// ---------------------------------------------------------------------------
// WCAG audit functions
// ---------------------------------------------------------------------------

/// Run a WCAG compliance audit on the current page using axe-core.
///
/// Injects the axe-core library via `Runtime.evaluate`, then executes
/// `axe.run()` and parses the structured results into `WcagAuditResult`.
pub async fn run_wcag_audit(
    client: &CdpClient,
    session_id: &str,
    level: WcagLevel,
) -> Result<WcagAuditResult, BrowserError> {
    // Step 1: Inject axe-core JS into the page
    client
        .send_command_with_session(
            "Runtime.evaluate",
            Some(json!({
                "expression": AXE_CORE_JS,
                "returnByValue": true,
            })),
            session_id,
        )
        .await?;

    // Step 2: Run axe.run() with WCAG level tag filters and get JSON results
    let tags_json = serde_json::to_string(&level.axe_tags())
        .unwrap_or_else(|_| "[]".to_string());
    let run_expr = format!(
        "axe.run(document, {{ runOnly: {{ type: 'tag', values: {} }} }}).then(function(r) {{ return JSON.stringify(r); }})",
        tags_json
    );
    let run_result = client
        .send_command_with_session(
            "Runtime.evaluate",
            Some(json!({
                "expression": run_expr,
                "awaitPromise": true,
                "returnByValue": true,
            })),
            session_id,
        )
        .await?;

    // Extract the string result
    let json_str = run_result
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or("{}");

    let axe_result: Value =
        serde_json::from_str(json_str).unwrap_or_else(|_| json!({}));

    // Parse violations
    let violations = axe_result
        .get("violations")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .map(|v| WcagViolation {
                    id: v
                        .get("id")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    impact: v
                        .get("impact")
                        .and_then(|x| x.as_str())
                        .unwrap_or("minor")
                        .to_string(),
                    description: v
                        .get("description")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    help_url: v
                        .get("helpUrl")
                        .and_then(|x| x.as_str())
                        .unwrap_or("")
                        .to_string(),
                    nodes_count: v
                        .get("nodes")
                        .and_then(|x| x.as_array())
                        .map(|a| a.len())
                        .unwrap_or(0),
                })
                .collect()
        })
        .unwrap_or_default();

    let passes_count = axe_result
        .get("passes")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    let incomplete_count = axe_result
        .get("incomplete")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    let inapplicable_count = axe_result
        .get("inapplicable")
        .and_then(|v| v.as_array())
        .map(|a| a.len())
        .unwrap_or(0);

    Ok(WcagAuditResult {
        violations,
        passes_count,
        incomplete_count,
        inapplicable_count,
    })
}

/// Return the numeric severity weight for a WCAG violation impact level.
/// Higher weight = more severe. Useful for sorting violations by severity.
pub fn impact_weight(impact: &str) -> u8 {
    match impact {
        "critical" => 4,
        "serious" => 3,
        "moderate" => 2,
        "minor" => 1,
        _ => 0,
    }
}

// ---------------------------------------------------------------------------
// Cookie consent detection and handling
// ---------------------------------------------------------------------------

/// JavaScript that detects cookie consent banners using DOM heuristics.
///
/// Searches for common consent banner selectors, checks visibility and
/// z-index, then looks for accept/reject/customize buttons by text content.
const DETECT_CONSENT_JS: &str = r#"
(function() {
    var selectors = [
        '#cookie-banner', '#cookie-consent', '[class*="cookie-consent"]',
        '[class*="cookie-banner"]', '[class*="consent-banner"]',
        '[id*="consent"]', '[class*="gdpr"]', '[class*="CookieConsent"]',
        '.cc-banner', '#onetrust-banner-sdk', '#CybotCookiebotDialog'
    ];

    var banner = null;
    var bannerSelector = null;

    for (var i = 0; i < selectors.length; i++) {
        var el = document.querySelector(selectors[i]);
        if (el) {
            var style = window.getComputedStyle(el);
            var visible = el.offsetHeight > 0
                && style.display !== 'none'
                && style.visibility !== 'hidden';
            var zIndex = parseInt(style.zIndex, 10) || 0;
            var position = style.position;
            if (visible && (zIndex >= 100 || position === 'fixed' || position === 'sticky')) {
                banner = el;
                bannerSelector = selectors[i];
                break;
            }
        }
    }

    if (!banner) {
        return JSON.stringify({ found: false });
    }

    var acceptKw = ['accept all', 'accept cookies', 'agree', 'ok', 'got it', 'allow all', 'consent', 'i agree', 'accept'];
    var rejectKw = ['reject all', 'decline', 'deny', 'refuse', 'reject'];
    var customKw = ['manage', 'customize', 'settings', 'preferences', 'more options'];

    function findButton(root, keywords) {
        var buttons = root.querySelectorAll('button, a[role="button"], [class*="btn"], input[type="submit"], input[type="button"]');
        for (var i = 0; i < buttons.length; i++) {
            var text = (buttons[i].textContent || buttons[i].value || '').trim().toLowerCase();
            for (var j = 0; j < keywords.length; j++) {
                if (text.indexOf(keywords[j]) !== -1) {
                    var tag = buttons[i].tagName.toLowerCase();
                    var id = buttons[i].id;
                    if (id) return '#' + id;
                    var cls = buttons[i].className;
                    if (typeof cls === 'string' && cls.trim()) {
                        return tag + '.' + cls.trim().split(/\s+/).join('.');
                    }
                    return bannerSelector + ' ' + tag + ':nth-child(' + (Array.from(buttons[i].parentNode.children).indexOf(buttons[i]) + 1) + ')';
                }
            }
        }
        return null;
    }

    var result = {
        found: true,
        banner_selector: bannerSelector,
        accept_selector: findButton(banner, acceptKw),
        reject_selector: findButton(banner, rejectKw),
        customize_selector: findButton(banner, customKw)
    };

    return JSON.stringify(result);
})()
"#;

/// Detect a cookie consent banner on the current page.
///
/// Uses DOM heuristics to find common consent banner patterns from
/// OneTrust, Cookiebot, and custom implementations. Checks for visibility,
/// high z-index, and fixed/sticky positioning. Identifies accept, reject,
/// and customize buttons by scanning button text content.
pub async fn detect_consent_banner(
    client: &CdpClient,
    session_id: &str,
) -> Result<ConsentBannerInfo, BrowserError> {
    let result = client
        .send_command_with_session(
            "Runtime.evaluate",
            Some(json!({
                "expression": DETECT_CONSENT_JS,
                "returnByValue": true,
            })),
            session_id,
        )
        .await?;

    let json_str = result
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_str())
        .unwrap_or(r#"{"found":false}"#);

    let parsed: Value =
        serde_json::from_str(json_str).unwrap_or_else(|_| json!({"found": false}));

    let found = parsed
        .get("found")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if !found {
        return Ok(ConsentBannerInfo {
            found: false,
            banner_selector: None,
            accept_selector: None,
            reject_selector: None,
            customize_selector: None,
        });
    }

    Ok(ConsentBannerInfo {
        found: true,
        banner_selector: parsed
            .get("banner_selector")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        accept_selector: parsed
            .get("accept_selector")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        reject_selector: parsed
            .get("reject_selector")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        customize_selector: parsed
            .get("customize_selector")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
    })
}

/// Accept the consent banner by clicking the accept button.
///
/// Returns `true` if the accept button was found and clicked, `false` if
/// no accept button was available. Waits 500ms after click for the banner
/// to dismiss.
pub async fn accept_consent(
    client: &CdpClient,
    session_id: &str,
    banner: &ConsentBannerInfo,
) -> Result<bool, BrowserError> {
    let selector = match &banner.accept_selector {
        Some(sel) => sel.clone(),
        None => return Ok(false),
    };

    let escaped = selector.replace('\\', "\\\\").replace('\'', "\\'");
    let js = format!(
        r#"(function() {{
            var el = document.querySelector('{escaped}');
            if (el) {{ el.click(); return true; }}
            return false;
        }})()"#
    );

    let result = client
        .send_command_with_session(
            "Runtime.evaluate",
            Some(json!({
                "expression": js,
                "returnByValue": true,
            })),
            session_id,
        )
        .await?;

    let clicked = result
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if clicked {
        // Wait for banner to dismiss
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    Ok(clicked)
}

/// Reject tracking cookies by clicking the reject button or unchecking
/// tracking categories in the customization panel.
///
/// Strategy:
/// 1. If a reject button exists, click it directly.
/// 2. If only a customize button exists, click it, then attempt to uncheck
///    tracking category toggles (marketing, advertising, analytics,
///    targeting, performance) while leaving functional/necessary checked.
/// 3. Look for a save/confirm button after toggling.
///
/// Returns `true` if tracking cookies were successfully rejected, `false`
/// if unable to determine or interact with granular controls.
pub async fn reject_tracking_cookies(
    client: &CdpClient,
    session_id: &str,
    banner: &ConsentBannerInfo,
) -> Result<bool, BrowserError> {
    // Strategy 1: Direct reject button
    if let Some(ref reject_sel) = banner.reject_selector {
        let escaped = reject_sel.replace('\\', "\\\\").replace('\'', "\\'");
        let js = format!(
            r#"(function() {{
                var el = document.querySelector('{escaped}');
                if (el) {{ el.click(); return true; }}
                return false;
            }})()"#
        );

        let result = client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({
                    "expression": js,
                    "returnByValue": true,
                })),
                session_id,
            )
            .await?;

        let clicked = result
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if clicked {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            return Ok(true);
        }
    }

    // Strategy 2: Open customize panel and toggle tracking off
    if let Some(ref customize_sel) = banner.customize_selector {
        let escaped = customize_sel.replace('\\', "\\\\").replace('\'', "\\'");
        let open_js = format!(
            r#"(function() {{
                var el = document.querySelector('{escaped}');
                if (el) {{ el.click(); return true; }}
                return false;
            }})()"#
        );

        let open_result = client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({
                    "expression": open_js,
                    "returnByValue": true,
                })),
                session_id,
            )
            .await?;

        let opened = open_result
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if !opened {
            return Ok(false);
        }

        // Wait for customize panel to appear
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;

        // Attempt to toggle off tracking categories
        let toggled = find_and_toggle_tracking_categories(client, session_id).await?;
        return Ok(toggled);
    }

    Ok(false)
}

/// JavaScript that finds and unchecks tracking category toggles in a consent
/// customization panel. Searches for labels/text containing tracking-related
/// keywords and unchecks their associated checkboxes or toggle inputs.
const TOGGLE_TRACKING_JS: &str = r#"
(function() {
    var trackingKeywords = ['marketing', 'advertising', 'analytics', 'targeting', 'performance', 'tracking', 'social media'];
    var necessaryKeywords = ['necessary', 'essential', 'functional', 'required', 'strictly necessary'];
    var toggled = 0;

    // Find all labels/text containers
    var labels = document.querySelectorAll('label, [class*="category"], [class*="purpose"], [class*="toggle-label"], span, p, div');

    for (var i = 0; i < labels.length; i++) {
        var text = (labels[i].textContent || '').trim().toLowerCase();
        if (text.length > 200) continue;

        var isTracking = false;
        var isNecessary = false;
        for (var j = 0; j < trackingKeywords.length; j++) {
            if (text.indexOf(trackingKeywords[j]) !== -1) { isTracking = true; break; }
        }
        for (var j = 0; j < necessaryKeywords.length; j++) {
            if (text.indexOf(necessaryKeywords[j]) !== -1) { isNecessary = true; break; }
        }

        if (isTracking && !isNecessary) {
            // Look for associated checkbox/toggle
            var container = labels[i].closest('[class*="category"], [class*="purpose"], [class*="toggle"], [class*="cookie-type"], li, tr, div');
            if (!container) container = labels[i].parentElement;
            if (container) {
                var inputs = container.querySelectorAll('input[type="checkbox"], [role="switch"], [class*="toggle"]');
                for (var k = 0; k < inputs.length; k++) {
                    var inp = inputs[k];
                    if (inp.type === 'checkbox' && inp.checked && !inp.disabled) {
                        inp.click();
                        toggled++;
                    } else if (inp.getAttribute('aria-checked') === 'true') {
                        inp.click();
                        toggled++;
                    }
                }
            }
        }
    }

    // Look for save/confirm button after toggling
    if (toggled > 0) {
        var saveKeywords = ['save', 'confirm', 'apply', 'save preferences', 'confirm choices', 'save settings'];
        var buttons = document.querySelectorAll('button, a[role="button"], [class*="btn"], input[type="submit"]');
        for (var i = 0; i < buttons.length; i++) {
            var btnText = (buttons[i].textContent || buttons[i].value || '').trim().toLowerCase();
            for (var j = 0; j < saveKeywords.length; j++) {
                if (btnText.indexOf(saveKeywords[j]) !== -1) {
                    buttons[i].click();
                    return toggled;
                }
            }
        }
    }

    return toggled;
})()
"#;

/// Find and toggle off tracking cookie categories in an open consent
/// customization panel.
///
/// Searches for labels containing tracking-related keywords (marketing,
/// advertising, analytics, targeting, performance) and unchecks their
/// associated checkboxes/toggles. Skips necessary/essential categories.
/// Clicks save/confirm button if found.
async fn find_and_toggle_tracking_categories(
    client: &CdpClient,
    session_id: &str,
) -> Result<bool, BrowserError> {
    let result = client
        .send_command_with_session(
            "Runtime.evaluate",
            Some(json!({
                "expression": TOGGLE_TRACKING_JS,
                "returnByValue": true,
            })),
            session_id,
        )
        .await?;

    let toggled = result
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_i64())
        .unwrap_or(0);

    if toggled > 0 {
        // Wait for preferences to apply
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }

    Ok(toggled > 0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // -- AXNode deserialization tests --

    #[test]
    fn test_ax_node_from_cdp_json() {
        let cdp_node = json!({
            "nodeId": "node-1",
            "role": { "type": "role", "value": "button" },
            "name": { "type": "computedString", "value": "Submit" },
            "description": { "type": "computedString", "value": "Submit form" },
            "childIds": ["node-2", "node-3"],
            "properties": [
                {
                    "name": "focusable",
                    "value": { "type": "boolean", "value": true }
                },
                {
                    "name": "level",
                    "value": { "type": "integer", "value": 2.0 }
                }
            ]
        });

        let node = parse_ax_node(&cdp_node);
        assert_eq!(node.node_id, "node-1");
        assert_eq!(node.role, "button");
        assert_eq!(node.name, Some("Submit".to_string()));
        assert_eq!(node.description, Some("Submit form".to_string()));
        assert_eq!(node.children, vec!["node-2", "node-3"]);
        assert_eq!(node.properties.len(), 2);
        assert_eq!(node.properties[0].name, "focusable");
        assert!(matches!(node.properties[0].value, AXValue::Bool(true)));
        assert_eq!(node.properties[1].name, "level");
        assert!(matches!(node.properties[1].value, AXValue::Number(v) if (v - 2.0).abs() < f64::EPSILON));
    }

    #[test]
    fn test_ax_node_minimal_cdp_json() {
        let cdp_node = json!({
            "nodeId": "root",
            "role": { "type": "role", "value": "WebArea" }
        });

        let node = parse_ax_node(&cdp_node);
        assert_eq!(node.node_id, "root");
        assert_eq!(node.role, "WebArea");
        assert!(node.name.is_none());
        assert!(node.value.is_none());
        assert!(node.description.is_none());
        assert!(node.children.is_empty());
        assert!(node.properties.is_empty());
    }

    #[test]
    fn test_ax_node_with_value() {
        let cdp_node = json!({
            "nodeId": "input-1",
            "role": { "type": "role", "value": "textbox" },
            "name": { "type": "computedString", "value": "Email" },
            "value": { "type": "computedString", "value": "user@example.com" }
        });

        let node = parse_ax_node(&cdp_node);
        assert_eq!(node.value, Some("user@example.com".to_string()));
    }

    #[test]
    fn test_ax_node_string_property() {
        let cdp_node = json!({
            "nodeId": "n1",
            "role": { "type": "role", "value": "heading" },
            "properties": [
                {
                    "name": "roledescription",
                    "value": { "type": "string", "value": "Section heading" }
                }
            ]
        });

        let node = parse_ax_node(&cdp_node);
        assert_eq!(node.properties.len(), 1);
        assert!(matches!(&node.properties[0].value, AXValue::String(s) if s == "Section heading"));
    }

    #[test]
    fn test_ax_node_none_property() {
        let cdp_node = json!({
            "nodeId": "n2",
            "role": { "type": "role", "value": "generic" },
            "properties": [
                {
                    "name": "unknown",
                    "value": { "type": "idref" }
                }
            ]
        });

        let node = parse_ax_node(&cdp_node);
        assert_eq!(node.properties.len(), 1);
        assert!(matches!(node.properties[0].value, AXValue::None));
    }

    // -- WcagAuditResult parsing tests --

    #[test]
    fn test_wcag_audit_result_from_axe_json() {
        let axe_output = json!({
            "violations": [
                {
                    "id": "color-contrast",
                    "impact": "serious",
                    "description": "Elements must have sufficient color contrast",
                    "helpUrl": "https://dequeuniversity.com/rules/axe/4.7/color-contrast",
                    "nodes": [
                        {"html": "<p>low contrast</p>"},
                        {"html": "<span>also low</span>"}
                    ]
                },
                {
                    "id": "image-alt",
                    "impact": "critical",
                    "description": "Images must have alternate text",
                    "helpUrl": "https://dequeuniversity.com/rules/axe/4.7/image-alt",
                    "nodes": [
                        {"html": "<img src='photo.jpg'>"}
                    ]
                }
            ],
            "passes": [{"id": "html-has-lang"}, {"id": "document-title"}, {"id": "meta-viewport"}],
            "incomplete": [{"id": "aria-allowed-attr"}],
            "inapplicable": [{"id": "area-alt"}, {"id": "blink"}]
        });

        let violations = axe_output
            .get("violations")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|v| WcagViolation {
                id: v["id"].as_str().unwrap().to_string(),
                impact: v["impact"].as_str().unwrap().to_string(),
                description: v["description"].as_str().unwrap().to_string(),
                help_url: v["helpUrl"].as_str().unwrap().to_string(),
                nodes_count: v["nodes"].as_array().unwrap().len(),
            })
            .collect::<Vec<_>>();

        let result = WcagAuditResult {
            violations,
            passes_count: 3,
            incomplete_count: 1,
            inapplicable_count: 2,
        };

        assert_eq!(result.violations.len(), 2);
        assert_eq!(result.violations[0].id, "color-contrast");
        assert_eq!(result.violations[0].impact, "serious");
        assert_eq!(result.violations[0].nodes_count, 2);
        assert_eq!(result.violations[1].id, "image-alt");
        assert_eq!(result.violations[1].impact, "critical");
        assert_eq!(result.violations[1].nodes_count, 1);
        assert_eq!(result.passes_count, 3);
        assert_eq!(result.incomplete_count, 1);
        assert_eq!(result.inapplicable_count, 2);
    }

    #[test]
    fn test_wcag_audit_result_empty() {
        let result = WcagAuditResult {
            violations: vec![],
            passes_count: 10,
            incomplete_count: 0,
            inapplicable_count: 5,
        };

        assert!(result.violations.is_empty());
        assert_eq!(result.passes_count, 10);
    }

    #[test]
    fn test_wcag_violation_impact_ordering() {
        let violations = vec![
            WcagViolation {
                id: "minor-rule".to_string(),
                impact: "minor".to_string(),
                description: "Minor issue".to_string(),
                help_url: String::new(),
                nodes_count: 1,
            },
            WcagViolation {
                id: "critical-rule".to_string(),
                impact: "critical".to_string(),
                description: "Critical issue".to_string(),
                help_url: String::new(),
                nodes_count: 5,
            },
            WcagViolation {
                id: "serious-rule".to_string(),
                impact: "serious".to_string(),
                description: "Serious issue".to_string(),
                help_url: String::new(),
                nodes_count: 3,
            },
            WcagViolation {
                id: "moderate-rule".to_string(),
                impact: "moderate".to_string(),
                description: "Moderate issue".to_string(),
                help_url: String::new(),
                nodes_count: 2,
            },
        ];

        // Sort by impact severity (most severe first)
        let mut sorted = violations.clone();
        sorted.sort_by(|a, b| impact_weight(&b.impact).cmp(&impact_weight(&a.impact)));

        assert_eq!(sorted[0].impact, "critical");
        assert_eq!(sorted[1].impact, "serious");
        assert_eq!(sorted[2].impact, "moderate");
        assert_eq!(sorted[3].impact, "minor");
    }

    #[test]
    fn test_impact_weight_values() {
        assert_eq!(impact_weight("critical"), 4);
        assert_eq!(impact_weight("serious"), 3);
        assert_eq!(impact_weight("moderate"), 2);
        assert_eq!(impact_weight("minor"), 1);
        assert_eq!(impact_weight("unknown"), 0);
    }

    // -- ConsentBannerInfo tests --

    #[test]
    fn test_consent_banner_info_found() {
        let info = ConsentBannerInfo {
            found: true,
            banner_selector: Some("#cookie-consent".to_string()),
            accept_selector: Some("button.accept-all".to_string()),
            reject_selector: Some("button.reject-all".to_string()),
            customize_selector: Some("button.manage".to_string()),
        };

        assert!(info.found);
        assert_eq!(info.banner_selector.as_deref(), Some("#cookie-consent"));
        assert_eq!(info.accept_selector.as_deref(), Some("button.accept-all"));
        assert_eq!(info.reject_selector.as_deref(), Some("button.reject-all"));
        assert_eq!(info.customize_selector.as_deref(), Some("button.manage"));
    }

    #[test]
    fn test_consent_banner_info_not_found() {
        let info = ConsentBannerInfo {
            found: false,
            banner_selector: None,
            accept_selector: None,
            reject_selector: None,
            customize_selector: None,
        };

        assert!(!info.found);
        assert!(info.banner_selector.is_none());
        assert!(info.accept_selector.is_none());
        assert!(info.reject_selector.is_none());
        assert!(info.customize_selector.is_none());
    }

    #[test]
    fn test_consent_banner_info_partial_buttons() {
        // Common case: banner has accept but no reject button
        let info = ConsentBannerInfo {
            found: true,
            banner_selector: Some("#onetrust-banner-sdk".to_string()),
            accept_selector: Some("#onetrust-accept-btn-handler".to_string()),
            reject_selector: None,
            customize_selector: Some("#onetrust-pc-btn-handler".to_string()),
        };

        assert!(info.found);
        assert!(info.accept_selector.is_some());
        assert!(info.reject_selector.is_none());
        assert!(info.customize_selector.is_some());
    }

    // -- Consent keyword matching tests --

    #[test]
    fn test_accept_keyword_matching() {
        let accept_keywords = [
            "accept all", "accept cookies", "agree", "ok", "got it",
            "allow all", "consent", "i agree", "accept",
        ];

        let test_texts = [
            ("Accept All Cookies", true),
            ("I Agree to Cookies", true),
            ("Got It!", true),
            ("Allow All", true),
            ("Reject All", false),
            ("Manage Settings", false),
        ];

        for (text, should_match) in &test_texts {
            let lower = text.to_lowercase();
            let matched = accept_keywords.iter().any(|kw| lower.contains(kw));
            assert_eq!(
                matched, *should_match,
                "Text '{}' match={} expected={}",
                text, matched, should_match
            );
        }
    }

    #[test]
    fn test_reject_keyword_matching() {
        let reject_keywords = ["reject all", "decline", "deny", "refuse", "reject"];

        let test_texts = [
            ("Reject All", true),
            ("Decline Cookies", true),
            ("Deny", true),
            ("Accept All", false),
            ("Manage", false),
        ];

        for (text, should_match) in &test_texts {
            let lower = text.to_lowercase();
            let matched = reject_keywords.iter().any(|kw| lower.contains(kw));
            assert_eq!(
                matched, *should_match,
                "Text '{}' match={} expected={}",
                text, matched, should_match
            );
        }
    }

    #[test]
    fn test_customize_keyword_matching() {
        let customize_keywords = [
            "manage", "customize", "settings", "preferences", "more options",
        ];

        let test_texts = [
            ("Manage Preferences", true),
            ("Customize Cookies", true),
            ("Cookie Settings", true),
            ("More Options", true),
            ("Accept All", false),
            ("Reject All", false),
        ];

        for (text, should_match) in &test_texts {
            let lower = text.to_lowercase();
            let matched = customize_keywords.iter().any(|kw| lower.contains(kw));
            assert_eq!(
                matched, *should_match,
                "Text '{}' match={} expected={}",
                text, matched, should_match
            );
        }
    }

    // -- JSON parsing for detect_consent_banner --

    #[test]
    fn test_detect_consent_banner_json_not_found() {
        let json_str = r#"{"found":false}"#;
        let parsed: Value = serde_json::from_str(json_str).unwrap();
        let found = parsed.get("found").and_then(|v| v.as_bool()).unwrap_or(false);
        assert!(!found);
    }

    #[test]
    fn test_detect_consent_banner_json_found() {
        let json_str = r##"{
            "found": true,
            "banner_selector": "#cookie-consent",
            "accept_selector": "button.accept",
            "reject_selector": null,
            "customize_selector": "button.manage"
        }"##;

        let parsed: Value = serde_json::from_str(json_str).unwrap();
        let found = parsed.get("found").and_then(|v| v.as_bool()).unwrap_or(false);
        assert!(found);
        assert_eq!(
            parsed.get("banner_selector").and_then(|v| v.as_str()),
            Some("#cookie-consent")
        );
        assert_eq!(
            parsed.get("accept_selector").and_then(|v| v.as_str()),
            Some("button.accept")
        );
        assert!(parsed.get("reject_selector").and_then(|v| v.as_str()).is_none());
        assert_eq!(
            parsed.get("customize_selector").and_then(|v| v.as_str()),
            Some("button.manage")
        );
    }

    // -- AXE_CORE_JS const test --

    #[test]
    fn test_axe_core_js_loaded() {
        // Verify the include_str! constant is non-empty
        assert!(!AXE_CORE_JS.is_empty());
        // Verify stub content (or real axe-core content)
        assert!(AXE_CORE_JS.contains("axe"));
    }

    // -- AXValue serialization tests --

    #[test]
    fn test_ax_value_serialization() {
        let string_val = AXValue::String("hello".to_string());
        let json = serde_json::to_string(&string_val).unwrap();
        assert_eq!(json, r#""hello""#);

        let bool_val = AXValue::Bool(true);
        let json = serde_json::to_string(&bool_val).unwrap();
        assert_eq!(json, "true");

        let num_val = AXValue::Number(42.0);
        let json = serde_json::to_string(&num_val).unwrap();
        assert_eq!(json, "42.0");
    }

    #[test]
    fn test_ax_node_serialization_roundtrip() {
        let node = AXNode {
            node_id: "test-1".to_string(),
            role: "button".to_string(),
            name: Some("Click me".to_string()),
            value: None,
            description: None,
            children: vec!["child-1".to_string()],
            properties: vec![AXProperty {
                name: "focusable".to_string(),
                value: AXValue::Bool(true),
            }],
        };

        let json = serde_json::to_string(&node).unwrap();
        let deserialized: AXNode = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.node_id, "test-1");
        assert_eq!(deserialized.role, "button");
        assert_eq!(deserialized.name, Some("Click me".to_string()));
        assert_eq!(deserialized.children.len(), 1);
        assert_eq!(deserialized.properties.len(), 1);
    }

    // -- WcagLevel tests --

    #[test]
    fn wcag_level_tags() {
        assert_eq!(WcagLevel::A.axe_tags().len(), 2);
        assert_eq!(WcagLevel::AA.axe_tags().len(), 4);
        assert_eq!(WcagLevel::AAA.axe_tags().len(), 6);
    }

    // -- Consent detection JS constant tests --

    #[test]
    fn test_detect_consent_js_contains_selectors() {
        assert!(DETECT_CONSENT_JS.contains("#cookie-banner"));
        assert!(DETECT_CONSENT_JS.contains("#cookie-consent"));
        assert!(DETECT_CONSENT_JS.contains("#onetrust-banner-sdk"));
        assert!(DETECT_CONSENT_JS.contains("#CybotCookiebotDialog"));
        assert!(DETECT_CONSENT_JS.contains(".cc-banner"));
    }

    #[test]
    fn test_detect_consent_js_contains_keywords() {
        assert!(DETECT_CONSENT_JS.contains("accept all"));
        assert!(DETECT_CONSENT_JS.contains("reject all"));
        assert!(DETECT_CONSENT_JS.contains("manage"));
        assert!(DETECT_CONSENT_JS.contains("preferences"));
    }

    #[test]
    fn test_toggle_tracking_js_contains_categories() {
        assert!(TOGGLE_TRACKING_JS.contains("marketing"));
        assert!(TOGGLE_TRACKING_JS.contains("advertising"));
        assert!(TOGGLE_TRACKING_JS.contains("analytics"));
        assert!(TOGGLE_TRACKING_JS.contains("targeting"));
        assert!(TOGGLE_TRACKING_JS.contains("performance"));
        // Necessary categories should be preserved
        assert!(TOGGLE_TRACKING_JS.contains("necessary"));
        assert!(TOGGLE_TRACKING_JS.contains("essential"));
    }

    #[test]
    fn test_toggle_tracking_js_has_save_button_logic() {
        assert!(TOGGLE_TRACKING_JS.contains("save"));
        assert!(TOGGLE_TRACKING_JS.contains("confirm"));
        assert!(TOGGLE_TRACKING_JS.contains("apply"));
    }
}
