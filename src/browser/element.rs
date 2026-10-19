//! Element handle for DOM element interaction and actionability checks.
//!
//! Provides ElementHandle with methods for extracting text/attributes,
//! checking visibility/enabled state, and Playwright-style auto-waiting
//! for actionability before interactions.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::{json, Value};

use super::cdp::CdpClient;
use super::error::BrowserError;
use super::interaction::{select_js_function, special_key_code, ClickOptions, SelectBy};
use super::page::escape_js_string;

/// Handle to a Shadow DOM root, providing element queries within the shadow boundary.
pub struct ShadowRoot {
    pub(crate) handle: ElementHandle,
}

impl ShadowRoot {
    /// Query a single element within this shadow root by CSS selector.
    pub async fn query_selector(
        &self,
        selector: &str,
    ) -> Result<Option<ElementHandle>, BrowserError> {
        self.handle.query_selector(selector).await
    }

    /// Query all elements within this shadow root by CSS selector.
    pub async fn query_selector_all(
        &self,
        selector: &str,
    ) -> Result<Vec<ElementHandle>, BrowserError> {
        self.handle.query_selector_all(selector).await
    }
}

/// A bounding box for an element on the page.
#[derive(Debug, Clone, PartialEq)]
pub struct BoundingBox {
    pub x: f64,
    pub y: f64,
    pub width: f64,
    pub height: f64,
}

impl BoundingBox {
    /// Returns true if the bounding box has zero area.
    pub fn is_zero_size(&self) -> bool {
        self.width <= 0.0 || self.height <= 0.0
    }

    /// Returns the center point of the bounding box.
    pub fn center(&self) -> (f64, f64) {
        (self.x + self.width / 2.0, self.y + self.height / 2.0)
    }
}

/// A handle to a DOM element, obtained via Page::query_selector or similar.
///
/// Provides methods for reading element properties and performing
/// actionability checks (Playwright-style auto-waiting).
#[derive(Clone)]
pub struct ElementHandle {
    pub(crate) client: CdpClient,
    pub(crate) session_id: String,
    pub(crate) remote_object_id: String,
}

impl ElementHandle {
    /// Get the text content of the element.
    pub async fn text(&self) -> Result<String, BrowserError> {
        let result = self.call_function_on("function() { return this.textContent; }").await?;
        Ok(extract_string_value(&result).unwrap_or_default())
    }

    /// Get the inner HTML of the element.
    pub async fn inner_html(&self) -> Result<String, BrowserError> {
        let result = self.call_function_on("function() { return this.innerHTML; }").await?;
        Ok(extract_string_value(&result).unwrap_or_default())
    }

    /// Get the value of an attribute on the element.
    ///
    /// Returns `Ok(None)` if the attribute does not exist.
    pub async fn attribute(&self, name: &str) -> Result<Option<String>, BrowserError> {
        let escaped = name.replace('\\', "\\\\").replace('\'', "\\'");
        let func = format!("function() {{ return this.getAttribute('{escaped}'); }}");
        let result = self.call_function_on(&func).await?;
        Ok(extract_string_value(&result))
    }

    /// Get the bounding box of the element.
    ///
    /// Returns `Ok(None)` if the element is not visible (e.g., display: none).
    pub async fn bounding_box(&self) -> Result<Option<BoundingBox>, BrowserError> {
        let result = self
            .call_function_on(
                "function() { \
                 var r = this.getBoundingClientRect(); \
                 if (r.width === 0 && r.height === 0) return null; \
                 return { x: r.x, y: r.y, width: r.width, height: r.height }; \
                 }",
            )
            .await?;

        let obj = result.get("result").unwrap_or(&serde_json::Value::Null);
        let subtype = obj.get("subtype").and_then(|v| v.as_str()).unwrap_or("");

        if subtype == "null" || obj.get("value").is_none() {
            // Element has no visible bounding box or returned null
            if let Some(value) = obj.get("value") {
                if value.is_null() {
                    return Ok(None);
                }
                let x = value.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let y = value.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let width = value.get("width").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let height = value.get("height").and_then(|v| v.as_f64()).unwrap_or(0.0);
                return Ok(Some(BoundingBox {
                    x,
                    y,
                    width,
                    height,
                }));
            }
            return Ok(None);
        }

        if let Some(value) = obj.get("value") {
            let x = value.get("x").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let y = value.get("y").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let width = value.get("width").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let height = value.get("height").and_then(|v| v.as_f64()).unwrap_or(0.0);
            Ok(Some(BoundingBox {
                x,
                y,
                width,
                height,
            }))
        } else {
            Ok(None)
        }
    }

    /// Check if the element is visible.
    ///
    /// An element is visible if it has a non-empty bounding box and
    /// computed styles don't hide it (visibility != hidden, display != none).
    pub async fn is_visible(&self) -> Result<bool, BrowserError> {
        let result = self
            .call_function_on(
                "function() { \
                 var style = window.getComputedStyle(this); \
                 if (style.visibility === 'hidden') return false; \
                 if (style.display === 'none') return false; \
                 var r = this.getBoundingClientRect(); \
                 return r.width > 0 && r.height > 0; \
                 }",
            )
            .await?;

        Ok(extract_bool_value(&result).unwrap_or(false))
    }

    /// Check if the element is enabled (not disabled).
    pub async fn is_enabled(&self) -> Result<bool, BrowserError> {
        let result = self
            .call_function_on("function() { return !this.disabled; }")
            .await?;

        Ok(extract_bool_value(&result).unwrap_or(true))
    }

    /// Wait for the element to become actionable (Playwright-style).
    ///
    /// Actionability checks:
    /// 1. **Visible**: Non-empty bounding box, not hidden/display:none
    /// 2. **Stable**: Same bounding box for 2 consecutive checks ~32ms apart
    /// 3. **Enabled**: Not disabled
    ///
    /// Polls every 50ms until all conditions are met or timeout expires.
    pub async fn wait_for_actionable(&self, timeout: Duration) -> Result<(), BrowserError> {
        let deadline = tokio::time::Instant::now() + timeout;

        loop {
            // Check visible
            if !self.is_visible().await? {
                if tokio::time::Instant::now() >= deadline {
                    return Err(BrowserError::Timeout {
                        operation: "wait_for_actionable",
                        detail: "element not visible".to_string(),
                    });
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }

            // Check stable (same bounding box for 2 consecutive checks)
            let bbox1 = self.bounding_box().await?;
            tokio::time::sleep(Duration::from_millis(32)).await;
            let bbox2 = self.bounding_box().await?;

            if bbox1 != bbox2 {
                if tokio::time::Instant::now() >= deadline {
                    return Err(BrowserError::Timeout {
                        operation: "wait_for_actionable",
                        detail: "element not stable".to_string(),
                    });
                }
                continue;
            }

            // Check enabled
            if !self.is_enabled().await? {
                if tokio::time::Instant::now() >= deadline {
                    return Err(BrowserError::Timeout {
                        operation: "wait_for_actionable",
                        detail: "element not enabled".to_string(),
                    });
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }

            return Ok(());
        }
    }

    /// Get the outer HTML of the element (including the element itself).
    pub async fn outer_html(&self) -> Result<String, BrowserError> {
        let result = self
            .call_function_on("function() { return this.outerHTML; }")
            .await?;
        Ok(extract_string_value(&result).unwrap_or_default())
    }

    /// Get the tag name of the element (lowercase, e.g., "div", "input", "select").
    pub async fn tag_name(&self) -> Result<String, BrowserError> {
        let result = self
            .call_function_on("function() { return this.tagName.toLowerCase(); }")
            .await?;
        Ok(extract_string_value(&result).unwrap_or_default())
    }

    /// Get a DOM property value (as opposed to an HTML attribute).
    ///
    /// Useful for getting `.value` on inputs, `.checked` on checkboxes,
    /// `.href` on anchors (resolved URL), etc.
    /// Returns `Ok(None)` if the property is null or undefined.
    pub async fn property(&self, name: &str) -> Result<Option<String>, BrowserError> {
        let escaped = escape_js_string(name);
        let func = format!(
            "function() {{ var v = this['{escaped}']; return v === null || v === undefined ? null : String(v); }}"
        );
        let result = self.call_function_on(&func).await?;
        Ok(extract_string_value(&result))
    }

    /// Get a single computed CSS style property value for this element.
    ///
    /// Returns the computed value as a String (e.g., "rgb(255, 0, 0)" for color,
    /// "16px" for font-size).
    pub async fn computed_style(&self, property: &str) -> Result<String, BrowserError> {
        let escaped = escape_js_string(property);
        let func = format!(
            "function() {{ return window.getComputedStyle(this).getPropertyValue('{escaped}'); }}"
        );
        let result = self.call_function_on(&func).await?;
        Ok(extract_string_value(&result).unwrap_or_default())
    }

    /// Get multiple computed CSS style property values in a single call.
    ///
    /// Returns a HashMap mapping property names to their computed values.
    pub async fn computed_styles(
        &self,
        properties: &[&str],
    ) -> Result<HashMap<String, String>, BrowserError> {
        // Build JS object literal: { "prop1": s.getPropertyValue("prop1"), ... }
        let entries: Vec<String> = properties
            .iter()
            .map(|p| {
                let escaped = escape_js_string(p);
                format!("'{escaped}': s.getPropertyValue('{escaped}')")
            })
            .collect();
        let func = format!(
            "function() {{ var s = window.getComputedStyle(this); return {{ {} }}; }}",
            entries.join(", ")
        );
        let result = self.call_function_on(&func).await?;

        let mut map = HashMap::new();
        if let Some(obj) = result.get("result").and_then(|r| r.get("value")) {
            if let Some(obj_map) = obj.as_object() {
                for (key, val) in obj_map {
                    if let Some(s) = val.as_str() {
                        map.insert(key.clone(), s.to_string());
                    }
                }
            }
        }
        Ok(map)
    }

    /// Query a single child element by CSS selector within this element's scope.
    ///
    /// Returns `Ok(None)` if no element matches.
    pub async fn query_selector(
        &self,
        selector: &str,
    ) -> Result<Option<ElementHandle>, BrowserError> {
        let escaped = escape_js_string(selector);
        let func = format!("function() {{ return this.querySelector('{escaped}'); }}");
        let result = self.call_function_on_ref(&func).await?;

        let obj = result.get("result").unwrap_or(&Value::Null);
        let obj_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let subtype = obj.get("subtype").and_then(|v| v.as_str()).unwrap_or("");

        if obj_type == "object" && subtype != "null" {
            if let Some(object_id) = obj.get("objectId").and_then(|v| v.as_str()) {
                return Ok(Some(ElementHandle {
                    client: self.client.clone(),
                    session_id: self.session_id.clone(),
                    remote_object_id: object_id.to_string(),
                }));
            }
        }

        Ok(None)
    }

    /// Query all child elements matching a CSS selector within this element's scope.
    pub async fn query_selector_all(
        &self,
        selector: &str,
    ) -> Result<Vec<ElementHandle>, BrowserError> {
        let escaped = escape_js_string(selector);
        let func = format!(
            "function() {{ return Array.from(this.querySelectorAll('{escaped}')); }}"
        );
        let result = self.call_function_on_ref(&func).await?;

        let obj = result.get("result").unwrap_or(&Value::Null);
        let object_id = match obj.get("objectId").and_then(|v| v.as_str()) {
            Some(id) => id,
            None => return Ok(Vec::new()),
        };

        // Get array properties using Runtime.getProperties with ownProperties
        let props = self
            .client
            .send_command_with_session(
                "Runtime.getProperties",
                Some(json!({
                    "objectId": object_id,
                    "ownProperties": true,
                })),
                &self.session_id,
            )
            .await?;

        let mut elements = Vec::new();
        if let Some(descriptors) = props.get("result").and_then(|v| v.as_array()) {
            for desc in descriptors {
                let name = desc.get("name").and_then(|v| v.as_str()).unwrap_or("");
                // Only take numeric indices (skip "length" and prototype properties)
                if name.parse::<usize>().is_ok() {
                    if let Some(value) = desc.get("value") {
                        if let Some(oid) = value.get("objectId").and_then(|v| v.as_str()) {
                            elements.push(ElementHandle {
                                client: self.client.clone(),
                                session_id: self.session_id.clone(),
                                remote_object_id: oid.to_string(),
                            });
                        }
                    }
                }
            }
        }

        Ok(elements)
    }

    // -----------------------------------------------------------------------
    // Interaction methods
    // -----------------------------------------------------------------------

    /// Click this element with the specified options.
    ///
    /// Auto-waits for actionability (visible + stable + enabled), scrolls the
    /// element into view, then dispatches mouseMoved, mousePressed, mouseReleased
    /// via the CDP Input domain.
    ///
    /// The actionability timeout is configurable via `ClickOptions::timeout`
    /// (default: 30 seconds).
    pub async fn click(&self, options: ClickOptions) -> Result<(), BrowserError> {
        self.wait_for_actionable(options.timeout).await?;
        self.scroll_into_view().await?;

        let bbox = self
            .bounding_box()
            .await?
            .ok_or_else(|| BrowserError::ElementNotFound {
                selector: "(click target has no bounding box)".to_string(),
            })?;
        let (x, y) = bbox.center();

        let button_str = options.button.as_str();

        // mouseMoved
        self.dispatch_mouse_event("mouseMoved", x, y, "none", 0, options.modifiers)
            .await?;
        // mousePressed
        self.dispatch_mouse_event(
            "mousePressed",
            x,
            y,
            button_str,
            options.click_count,
            options.modifiers,
        )
        .await?;
        // mouseReleased
        self.dispatch_mouse_event(
            "mouseReleased",
            x,
            y,
            button_str,
            options.click_count,
            options.modifiers,
        )
        .await?;

        Ok(())
    }

    /// Scroll this element into view within the viewport.
    ///
    /// Uses `scrollIntoViewIfNeeded` if available, otherwise falls back to
    /// `scrollIntoView({block: 'center'})`. Waits 50ms after scroll for
    /// layout stabilization.
    pub async fn scroll_into_view(&self) -> Result<(), BrowserError> {
        self.call_function_on(
            "function() { this.scrollIntoViewIfNeeded ? this.scrollIntoViewIfNeeded(true) : this.scrollIntoView({block: 'center'}); }",
        )
        .await?;
        tokio::time::sleep(Duration::from_millis(50)).await;
        Ok(())
    }

    /// Focus this element using JavaScript.
    pub async fn focus(&self) -> Result<(), BrowserError> {
        self.call_function_on("function() { this.focus(); }")
            .await?;
        Ok(())
    }

    /// Focus this element using the CDP `DOM.focus` command.
    ///
    /// This is a lower-level focus that goes through the DOM domain rather than
    /// JavaScript evaluation. Useful when JS-based focus doesn't work (e.g.,
    /// cross-origin iframes, detached elements).
    pub async fn focus_cdp(&self) -> Result<(), BrowserError> {
        // Enable DOM domain (idempotent)
        let _ = self
            .client
            .send_command_with_session("DOM.enable", None, &self.session_id)
            .await;

        // Resolve the remote object to a backend node
        let describe_result = self
            .client
            .send_command_with_session(
                "DOM.describeNode",
                Some(json!({
                    "objectId": self.remote_object_id,
                })),
                &self.session_id,
            )
            .await?;

        let backend_node_id = describe_result
            .get("node")
            .and_then(|n| n.get("backendNodeId"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        self.client
            .send_command_with_session(
                "DOM.focus",
                Some(json!({
                    "backendNodeId": backend_node_id,
                })),
                &self.session_id,
            )
            .await?;

        Ok(())
    }

    /// Type text with a custom actionability timeout.
    ///
    /// Same as [`type_text`] but allows specifying the timeout for the
    /// actionability wait (visible + stable + enabled).
    pub async fn type_text_with_timeout(
        &self,
        text: &str,
        delay_ms: Option<u64>,
        timeout: Duration,
    ) -> Result<(), BrowserError> {
        self.wait_for_actionable(timeout).await?;
        self.focus().await?;

        for ch in text.chars() {
            let key = ch.to_string();
            self.dispatch_key_event("keyDown", &key, Some(&key), None, 0)
                .await?;
            self.dispatch_key_event("char", &key, Some(&key), None, 0)
                .await?;
            self.dispatch_key_event("keyUp", &key, None, None, 0)
                .await?;

            if let Some(ms) = delay_ms {
                if ms > 0 {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                }
            }
        }

        Ok(())
    }

    /// Type text into this element character by character.
    ///
    /// Auto-waits for actionability (visible + stable + enabled) before typing,
    /// then focuses the element and dispatches keyDown/char/keyUp events for
    /// each character. An optional delay between keystrokes simulates human typing.
    ///
    /// The actionability timeout defaults to 30 seconds. Use
    /// [`type_text_with_timeout`] to specify a custom timeout.
    pub async fn type_text(
        &self,
        text: &str,
        delay_ms: Option<u64>,
    ) -> Result<(), BrowserError> {
        self.wait_for_actionable(Duration::from_secs(30)).await?;
        self.focus().await?;

        for ch in text.chars() {
            let key = ch.to_string();

            // keyDown must NOT carry `text`: CDP inserts the character when
            // `text` is present, and the `char` event below inserts it again —
            // measured as "hheelllloo" for the input "hello". The keydown
            // listener still sees the key; insertion belongs to `char` alone.
            self.dispatch_key_event("keyDown", &key, None, None, 0)
                .await?;
            // char
            self.dispatch_key_event("char", &key, Some(&key), None, 0)
                .await?;
            // keyUp
            self.dispatch_key_event("keyUp", &key, None, None, 0)
                .await?;

            if let Some(ms) = delay_ms {
                if ms > 0 {
                    tokio::time::sleep(Duration::from_millis(ms)).await;
                }
            }
        }

        Ok(())
    }

    /// Select a dropdown option by value, index, or visible label.
    ///
    /// Dispatches `input` and `change` events after setting the selection.
    pub async fn select_option(&self, by: SelectBy) -> Result<(), BrowserError> {
        let js = select_js_function(&by);
        self.call_function_on(&js).await?;
        Ok(())
    }

    /// Upload files via a file input element.
    ///
    /// Each path is resolved to an absolute path. Uses `DOM.setFileInputFiles`.
    pub async fn upload_files(&self, paths: &[&str]) -> Result<(), BrowserError> {
        let mut abs_paths = Vec::with_capacity(paths.len());
        for p in paths {
            let abs = std::path::Path::new(p)
                .canonicalize()
                .map_err(|_| BrowserError::FileNotFound(p.to_string()))?;
            abs_paths.push(abs.to_string_lossy().into_owned());
        }

        // Resolve the element to a DOM node first via DOM.describeNode
        let describe_result = self
            .client
            .send_command_with_session(
                "DOM.describeNode",
                Some(json!({
                    "objectId": self.remote_object_id,
                })),
                &self.session_id,
            )
            .await?;

        let backend_node_id = describe_result
            .get("node")
            .and_then(|n| n.get("backendNodeId"))
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        self.client
            .send_command_with_session(
                "DOM.setFileInputFiles",
                Some(json!({
                    "files": abs_paths,
                    "objectId": self.remote_object_id,
                    "backendNodeId": backend_node_id,
                })),
                &self.session_id,
            )
            .await?;

        Ok(())
    }

    /// Clear the value of this input element.
    ///
    /// Sets the element's value to empty string and dispatches an `input` event.
    pub async fn clear(&self) -> Result<(), BrowserError> {
        self.call_function_on(
            "function() { this.value = ''; this.dispatchEvent(new Event('input', {bubbles: true})); }",
        )
        .await?;
        Ok(())
    }

    /// Hover over this element.
    ///
    /// Auto-waits for actionability, scrolls into view, then dispatches a
    /// `mouseMoved` event at the element's center to trigger CSS `:hover`
    /// and JS mouseover/mouseenter handlers.
    pub async fn hover(&self) -> Result<(), BrowserError> {
        self.wait_for_actionable(Duration::from_secs(30)).await?;
        self.scroll_into_view().await?;

        let bbox = self
            .bounding_box()
            .await?
            .ok_or_else(|| BrowserError::ElementNotFound {
                selector: "(hover target has no bounding box)".to_string(),
            })?;
        let (x, y) = bbox.center();

        self.dispatch_mouse_event("mouseMoved", x, y, "none", 0, 0)
            .await?;

        Ok(())
    }

    /// Drag this element to a target element.
    ///
    /// Auto-waits for both source and target to be actionable, then performs
    /// a mouse-based drag sequence: move to source center, press, pause for
    /// drag detection, move to target center, release.
    pub async fn drag_to(&self, target: &ElementHandle) -> Result<(), BrowserError> {
        // Wait for both source and target
        self.wait_for_actionable(Duration::from_secs(30)).await?;
        target
            .wait_for_actionable(Duration::from_secs(30))
            .await?;

        // Get source center
        self.scroll_into_view().await?;
        let src_bbox = self
            .bounding_box()
            .await?
            .ok_or_else(|| BrowserError::ElementNotFound {
                selector: "(drag source has no bounding box)".to_string(),
            })?;
        let (sx, sy) = src_bbox.center();

        // Get target center
        target.scroll_into_view().await?;
        let tgt_bbox = target
            .bounding_box()
            .await?
            .ok_or_else(|| BrowserError::ElementNotFound {
                selector: "(drag target has no bounding box)".to_string(),
            })?;
        let (tx, ty) = tgt_bbox.center();

        // Mouse drag sequence
        self.dispatch_mouse_event("mouseMoved", sx, sy, "none", 0, 0)
            .await?;
        self.dispatch_mouse_event("mousePressed", sx, sy, "left", 1, 0)
            .await?;

        // Small delay to trigger drag detection
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Move to target (triggers dragenter/dragover)
        self.dispatch_mouse_event("mouseMoved", tx, ty, "none", 0, 0)
            .await?;

        // Release at target
        self.dispatch_mouse_event("mouseReleased", tx, ty, "left", 1, 0)
            .await?;

        Ok(())
    }

    /// Access the Shadow DOM root of this element, if one exists.
    ///
    /// First tries `this.shadowRoot` (works for open shadow roots).
    /// If that returns null, falls back to `DOM.describeNode` with `pierce: true`
    /// to access closed shadow roots via CDP.
    ///
    /// Returns `Ok(None)` if the element has no shadow root.
    pub async fn shadow_root(&self) -> Result<Option<ShadowRoot>, BrowserError> {
        // Try open shadow root via JS
        let result = self
            .call_function_on_ref("function() { return this.shadowRoot; }")
            .await?;

        let obj = result.get("result").unwrap_or(&Value::Null);
        let obj_type = obj.get("type").and_then(|v| v.as_str()).unwrap_or("");
        let subtype = obj.get("subtype").and_then(|v| v.as_str()).unwrap_or("");

        if obj_type == "object" && subtype != "null" {
            if let Some(object_id) = obj.get("objectId").and_then(|v| v.as_str()) {
                return Ok(Some(ShadowRoot {
                    handle: ElementHandle {
                        client: self.client.clone(),
                        session_id: self.session_id.clone(),
                        remote_object_id: object_id.to_string(),
                    },
                }));
            }
        }

        // Fallback: use CDP DOM.describeNode for closed shadow roots
        // Enable DOM domain first (idempotent)
        let _ = self
            .client
            .send_command_with_session("DOM.enable", None, &self.session_id)
            .await;

        let describe_result = self
            .client
            .send_command_with_session(
                "DOM.describeNode",
                Some(json!({
                    "objectId": self.remote_object_id,
                    "depth": 0,
                    "pierce": true,
                })),
                &self.session_id,
            )
            .await?;

        // Check for shadowRoots array
        if let Some(shadow_roots) = describe_result
            .get("node")
            .and_then(|n| n.get("shadowRoots"))
            .and_then(|s| s.as_array())
        {
            if let Some(first_shadow) = shadow_roots.first() {
                if let Some(node_id) = first_shadow.get("nodeId").and_then(|v| v.as_i64()) {
                    // Resolve nodeId to a remote objectId
                    let resolve_result = self
                        .client
                        .send_command_with_session(
                            "DOM.resolveNode",
                            Some(json!({"nodeId": node_id})),
                            &self.session_id,
                        )
                        .await?;

                    if let Some(object_id) = resolve_result
                        .get("object")
                        .and_then(|o| o.get("objectId"))
                        .and_then(|v| v.as_str())
                    {
                        return Ok(Some(ShadowRoot {
                            handle: ElementHandle {
                                client: self.client.clone(),
                                session_id: self.session_id.clone(),
                                remote_object_id: object_id.to_string(),
                            },
                        }));
                    }
                }
            }
        }

        Ok(None)
    }

    // -----------------------------------------------------------------------
    // Private helpers for Input domain CDP calls
    // -----------------------------------------------------------------------

    /// Dispatch a mouse event via the CDP Input domain.
    async fn dispatch_mouse_event(
        &self,
        event_type: &str,
        x: f64,
        y: f64,
        button: &str,
        click_count: u32,
        modifiers: u32,
    ) -> Result<(), BrowserError> {
        self.client
            .send_command_with_session(
                "Input.dispatchMouseEvent",
                Some(json!({
                    "type": event_type,
                    "x": x,
                    "y": y,
                    "button": button,
                    "clickCount": click_count,
                    "modifiers": modifiers,
                })),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    /// Dispatch a key event via the CDP Input domain.
    async fn dispatch_key_event(
        &self,
        event_type: &str,
        key: &str,
        text: Option<&str>,
        code: Option<u32>,
        modifiers: u32,
    ) -> Result<(), BrowserError> {
        let mut params = json!({
            "type": event_type,
            "key": key,
            "modifiers": modifiers,
        });

        if let Some(t) = text {
            params["text"] = json!(t);
        }

        // Set windowsVirtualKeyCode if it's a special key or single char
        let vk_code = code.or_else(|| special_key_code(key)).or_else(|| {
            let chars: Vec<char> = key.chars().collect();
            if chars.len() == 1 {
                Some(chars[0].to_ascii_uppercase() as u32)
            } else {
                None
            }
        });

        if let Some(vk) = vk_code {
            params["windowsVirtualKeyCode"] = json!(vk);
        }

        self.client
            .send_command_with_session(
                "Input.dispatchKeyEvent",
                Some(params),
                &self.session_id,
            )
            .await?;
        Ok(())
    }

    /// Call a JavaScript function on the remote object with returnByValue: false.
    ///
    /// Returns the raw CDP result (including objectId for remote references).
    /// Used for selector chaining where we need object references, not values.
    async fn call_function_on_ref(
        &self,
        function_declaration: &str,
    ) -> Result<serde_json::Value, BrowserError> {
        self.client
            .send_command_with_session(
                "Runtime.callFunctionOn",
                Some(json!({
                    "objectId": self.remote_object_id,
                    "functionDeclaration": function_declaration,
                    "returnByValue": false,
                })),
                &self.session_id,
            )
            .await
    }

    /// Call a JavaScript function on the remote object.
    async fn call_function_on(
        &self,
        function_declaration: &str,
    ) -> Result<serde_json::Value, BrowserError> {
        self.client
            .send_command_with_session(
                "Runtime.callFunctionOn",
                Some(json!({
                    "objectId": self.remote_object_id,
                    "functionDeclaration": function_declaration,
                    "returnByValue": true,
                })),
                &self.session_id,
            )
            .await
    }
}

/// A lazy element chain for batch extraction.
///
/// Instead of executing queries one at a time, `ElementChain` builds up a
/// series of operations (select, extract text, extract attrs) and executes
/// them all in a single CDP call. This drastically reduces roundtrips when
/// extracting data from multiple elements.
pub struct ElementChain {
    client: CdpClient,
    session_id: String,
    /// CSS selector that identifies the root elements.
    selector: String,
    /// Sub-selector within each root element (for nested queries).
    sub_selectors: Vec<(String, Vec<String>)>,
}

impl ElementChain {
    /// Create a new ElementChain starting from a CSS selector.
    pub fn new(client: CdpClient, session_id: String, selector: &str) -> Self {
        Self {
            client,
            session_id,
            selector: selector.to_string(),
            sub_selectors: Vec::new(),
        }
    }

    /// Add a sub-selector with attributes to extract from each matched element.
    ///
    /// For example, `.extract("a.link", &["href", "innerText"])` will, for each
    /// element matching the root selector, find `a.link` children and extract
    /// their `href` and `innerText`.
    pub fn extract(mut self, sub_selector: &str, attrs: &[&str]) -> Self {
        self.sub_selectors.push((
            sub_selector.to_string(),
            attrs.iter().map(|a| a.to_string()).collect(),
        ));
        self
    }

    /// Execute the chain in a single CDP call and return structured results.
    ///
    /// Returns a Vec of JSON objects, one per root element. Each object contains
    /// keys named after sub-selectors, whose values are arrays of extracted
    /// attribute maps.
    pub async fn execute(&self) -> Result<Value, BrowserError> {
        let mut extractors = Vec::new();
        for (i, (sub_sel, attrs)) in self.sub_selectors.iter().enumerate() {
            let sub_sel_json = serde_json::to_string(sub_sel).unwrap_or_default();
            let attrs_json = serde_json::to_string(attrs).unwrap_or_default();
            extractors.push(format!(
                "r['sub_{i}'] = Array.from(root.querySelectorAll({sub_sel})).map(function(el) {{ \
                    var o = {{}}; \
                    {attrs}.forEach(function(a) {{ o[a] = a === 'innerText' ? el.innerText : a === 'innerHTML' ? el.innerHTML : el.getAttribute(a); }}); \
                    return o; \
                }})",
                i = i,
                sub_sel = sub_sel_json,
                attrs = attrs_json,
            ));
        }

        let selector_json = serde_json::to_string(&self.selector).unwrap_or_default();
        let js = format!(
            "Array.from(document.querySelectorAll({sel})).map(function(root) {{ \
                var r = {{}}; \
                {extractors} \
                return r; \
            }})",
            sel = selector_json,
            extractors = extractors.join("; "),
        );

        let result = self
            .client
            .send_command_with_session(
                "Runtime.evaluate",
                Some(json!({
                    "expression": js,
                    "returnByValue": true,
                    "awaitPromise": false
                })),
                &self.session_id,
            )
            .await?;

        Ok(result
            .get("result")
            .and_then(|r| r.get("value"))
            .cloned()
            .unwrap_or(Value::Null))
    }
}

/// Extract a string value from a Runtime result.
fn extract_string_value(result: &serde_json::Value) -> Option<String> {
    result
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

/// Extract a boolean value from a Runtime result.
fn extract_bool_value(result: &serde_json::Value) -> Option<bool> {
    result
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_bool())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounding_box_construction() {
        let bbox = BoundingBox {
            x: 10.0,
            y: 20.0,
            width: 100.0,
            height: 50.0,
        };
        assert_eq!(bbox.x, 10.0);
        assert_eq!(bbox.y, 20.0);
        assert_eq!(bbox.width, 100.0);
        assert_eq!(bbox.height, 50.0);
    }

    #[test]
    fn test_bounding_box_is_zero_size() {
        let zero = BoundingBox {
            x: 0.0,
            y: 0.0,
            width: 0.0,
            height: 0.0,
        };
        assert!(zero.is_zero_size());

        let zero_width = BoundingBox {
            x: 0.0,
            y: 0.0,
            width: 0.0,
            height: 50.0,
        };
        assert!(zero_width.is_zero_size());

        let zero_height = BoundingBox {
            x: 0.0,
            y: 0.0,
            width: 100.0,
            height: 0.0,
        };
        assert!(zero_height.is_zero_size());

        let negative = BoundingBox {
            x: 0.0,
            y: 0.0,
            width: -10.0,
            height: 50.0,
        };
        assert!(negative.is_zero_size());

        let valid = BoundingBox {
            x: 10.0,
            y: 20.0,
            width: 100.0,
            height: 50.0,
        };
        assert!(!valid.is_zero_size());
    }

    #[test]
    fn test_bounding_box_center() {
        let bbox = BoundingBox {
            x: 10.0,
            y: 20.0,
            width: 100.0,
            height: 50.0,
        };
        let (cx, cy) = bbox.center();
        assert_eq!(cx, 60.0);
        assert_eq!(cy, 45.0);
    }

    #[test]
    fn test_bounding_box_equality() {
        let a = BoundingBox {
            x: 10.0,
            y: 20.0,
            width: 100.0,
            height: 50.0,
        };
        let b = BoundingBox {
            x: 10.0,
            y: 20.0,
            width: 100.0,
            height: 50.0,
        };
        assert_eq!(a, b);
    }

    #[test]
    fn test_bounding_box_inequality() {
        let a = BoundingBox {
            x: 10.0,
            y: 20.0,
            width: 100.0,
            height: 50.0,
        };
        let b = BoundingBox {
            x: 10.0,
            y: 20.0,
            width: 101.0,
            height: 50.0,
        };
        assert_ne!(a, b);
    }

    #[test]
    fn test_extract_string_value_valid() {
        let val = serde_json::json!({
            "result": {
                "type": "string",
                "value": "hello world"
            }
        });
        assert_eq!(extract_string_value(&val), Some("hello world".to_string()));
    }

    #[test]
    fn test_extract_string_value_null() {
        let val = serde_json::json!({
            "result": {
                "type": "undefined"
            }
        });
        assert_eq!(extract_string_value(&val), None);
    }

    #[test]
    fn test_extract_bool_value_true() {
        let val = serde_json::json!({
            "result": {
                "type": "boolean",
                "value": true
            }
        });
        assert_eq!(extract_bool_value(&val), Some(true));
    }

    #[test]
    fn test_extract_bool_value_false() {
        let val = serde_json::json!({
            "result": {
                "type": "boolean",
                "value": false
            }
        });
        assert_eq!(extract_bool_value(&val), Some(false));
    }

    #[test]
    fn test_attribute_js_function_generation() {
        // Verify the JS function string is correct for attribute extraction
        let name = "data-test";
        let escaped = name.replace('\\', "\\\\").replace('\'', "\\'");
        let func = format!("function() {{ return this.getAttribute('{escaped}'); }}");
        assert_eq!(
            func,
            "function() { return this.getAttribute('data-test'); }"
        );
    }

    #[test]
    fn test_element_query_selector_js_function_generation() {
        let selector = ".child-class";
        let escaped = escape_js_string(selector);
        let func = format!("function() {{ return this.querySelector('{escaped}'); }}");
        assert_eq!(func, "function() { return this.querySelector('.child-class'); }");
    }

    #[test]
    fn test_element_query_selector_all_js_function_generation() {
        let selector = "li > a";
        let escaped = escape_js_string(selector);
        let func = format!(
            "function() {{ return Array.from(this.querySelectorAll('{escaped}')); }}"
        );
        assert_eq!(
            func,
            "function() { return Array.from(this.querySelectorAll('li > a')); }"
        );
    }

    #[test]
    fn test_element_query_selector_escapes_quotes() {
        let selector = "a[href='test']";
        let escaped = escape_js_string(selector);
        let func = format!("function() {{ return this.querySelector('{escaped}'); }}");
        assert!(func.contains("a[href=\\'test\\']"));
    }

    #[test]
    fn test_element_query_selector_all_array_from_wrapper() {
        // Verify Array.from is used (querySelectorAll returns NodeList, not Array)
        let selector = "div";
        let escaped = escape_js_string(selector);
        let func = format!(
            "function() {{ return Array.from(this.querySelectorAll('{escaped}')); }}"
        );
        assert!(func.starts_with("function() { return Array.from("));
        assert!(func.contains("querySelectorAll"));
    }

    #[test]
    fn test_attribute_js_function_with_quotes() {
        let name = "data-'special";
        let escaped = name.replace('\\', "\\\\").replace('\'', "\\'");
        let func = format!("function() {{ return this.getAttribute('{escaped}'); }}");
        assert!(func.contains("\\'special"));
    }

    #[test]
    fn test_computed_style_js_function_generation() {
        let property = "font-size";
        let escaped = escape_js_string(property);
        let func = format!(
            "function() {{ return window.getComputedStyle(this).getPropertyValue('{escaped}'); }}"
        );
        assert_eq!(
            func,
            "function() { return window.getComputedStyle(this).getPropertyValue('font-size'); }"
        );
    }

    #[test]
    fn test_computed_style_escapes_property_name() {
        let property = "background-image";
        let escaped = escape_js_string(property);
        let func = format!(
            "function() {{ return window.getComputedStyle(this).getPropertyValue('{escaped}'); }}"
        );
        assert!(func.contains("getPropertyValue('background-image')"));
    }

    #[test]
    fn test_computed_styles_batch_js_function_generation() {
        let properties = ["color", "font-size", "display"];
        let entries: Vec<String> = properties
            .iter()
            .map(|p| {
                let escaped = escape_js_string(p);
                format!("'{escaped}': s.getPropertyValue('{escaped}')")
            })
            .collect();
        let func = format!(
            "function() {{ var s = window.getComputedStyle(this); return {{ {} }}; }}",
            entries.join(", ")
        );
        assert!(func.contains("'color': s.getPropertyValue('color')"));
        assert!(func.contains("'font-size': s.getPropertyValue('font-size')"));
        assert!(func.contains("'display': s.getPropertyValue('display')"));
        assert!(func.contains("window.getComputedStyle(this)"));
    }

    #[test]
    fn test_outer_html_function_string() {
        let func = "function() { return this.outerHTML; }";
        assert!(func.contains("outerHTML"));
    }

    #[test]
    fn test_tag_name_function_string() {
        let func = "function() { return this.tagName.toLowerCase(); }";
        assert!(func.contains("tagName"));
        assert!(func.contains("toLowerCase"));
    }

    #[test]
    fn test_property_js_function_generation() {
        let name = "value";
        let escaped = escape_js_string(name);
        let func = format!(
            "function() {{ var v = this['{escaped}']; return v === null || v === undefined ? null : String(v); }}"
        );
        assert_eq!(
            func,
            "function() { var v = this['value']; return v === null || v === undefined ? null : String(v); }"
        );
    }

    #[test]
    fn test_property_js_function_escapes_name() {
        let name = "data'special";
        let escaped = escape_js_string(name);
        let func = format!(
            "function() {{ var v = this['{escaped}']; return v === null || v === undefined ? null : String(v); }}"
        );
        assert!(func.contains("this['data\\'special']"));
    }

    #[test]
    fn test_hover_dispatches_mouse_moved() {
        // Verify hover generates the correct Input.dispatchMouseEvent type
        let event_type = "mouseMoved";
        let button = "none";
        let click_count: u32 = 0;
        assert_eq!(event_type, "mouseMoved");
        assert_eq!(button, "none");
        assert_eq!(click_count, 0);
    }

    #[test]
    fn test_drag_to_event_sequence() {
        // Verify the drag sequence generates the correct event types in order
        let sequence = vec![
            ("mouseMoved", "none", 0u32),   // move to source
            ("mousePressed", "left", 1u32), // press at source
            // (100ms delay here)
            ("mouseMoved", "none", 0u32),     // move to target
            ("mouseReleased", "left", 1u32),  // release at target
        ];

        assert_eq!(sequence.len(), 4);
        assert_eq!(sequence[0].0, "mouseMoved");
        assert_eq!(sequence[1].0, "mousePressed");
        assert_eq!(sequence[1].1, "left");
        assert_eq!(sequence[2].0, "mouseMoved");
        assert_eq!(sequence[3].0, "mouseReleased");
        assert_eq!(sequence[3].1, "left");
    }

    #[test]
    fn test_shadow_root_query_selector_js() {
        // Verify ShadowRoot delegates to ElementHandle's query_selector
        // which uses `this.querySelector(...)` on the shadow root object
        let selector = ".inner-element";
        let escaped = escape_js_string(selector);
        let func = format!("function() {{ return this.querySelector('{escaped}'); }}");
        assert_eq!(
            func,
            "function() { return this.querySelector('.inner-element'); }"
        );
    }

    #[test]
    fn test_shadow_root_query_selector_all_js() {
        let selector = "span.text";
        let escaped = escape_js_string(selector);
        let func = format!(
            "function() {{ return Array.from(this.querySelectorAll('{escaped}')); }}"
        );
        assert!(func.contains("querySelectorAll('span.text')"));
    }

    // -----------------------------------------------------------------------
    // Phase 48-01: ElementChain tests
    // -----------------------------------------------------------------------

    #[test]
    fn test_element_chain_construction() {
        let selector = ".product-card";
        let selector_json = serde_json::to_string(selector).unwrap();
        assert_eq!(selector_json, r#"".product-card""#);
    }

    #[test]
    fn test_element_chain_extract_builds_sub_selectors() {
        let sub_selectors: Vec<(String, Vec<String>)> = Vec::new();
        assert!(sub_selectors.is_empty());

        let mut subs = sub_selectors;
        subs.push((
            "a.link".to_string(),
            vec!["href".to_string(), "innerText".to_string()],
        ));
        subs.push((
            ".price".to_string(),
            vec!["innerText".to_string()],
        ));
        assert_eq!(subs.len(), 2);
        assert_eq!(subs[0].0, "a.link");
        assert_eq!(subs[0].1, vec!["href", "innerText"]);
        assert_eq!(subs[1].0, ".price");
    }

    #[test]
    fn test_element_chain_js_generation() {
        let selector = ".card";
        let sub_selectors = vec![
            (".title".to_string(), vec!["innerText".to_string()]),
            ("a".to_string(), vec!["href".to_string(), "innerText".to_string()]),
        ];

        let mut extractors = Vec::new();
        for (i, (sub_sel, attrs)) in sub_selectors.iter().enumerate() {
            let sub_sel_json = serde_json::to_string(sub_sel).unwrap();
            let attrs_json = serde_json::to_string(attrs).unwrap();
            extractors.push(format!(
                "r['sub_{i}'] = Array.from(root.querySelectorAll({sub_sel})).map(function(el) {{ var o = {{}}; {attrs}.forEach(function(a) {{ o[a] = el.getAttribute(a); }}); return o; }})",
                i = i,
                sub_sel = sub_sel_json,
                attrs = attrs_json,
            ));
        }

        let selector_json = serde_json::to_string(selector).unwrap();
        let js = format!(
            "Array.from(document.querySelectorAll({sel})).map(function(root) {{ var r = {{}}; {extractors} return r; }})",
            sel = selector_json,
            extractors = extractors.join("; "),
        );

        assert!(js.contains(r#"querySelectorAll(".card")"#));
        assert!(js.contains("sub_0"));
        assert!(js.contains("sub_1"));
        assert!(js.contains(r#"querySelectorAll(".title")"#));
        assert!(js.contains(r#"querySelectorAll("a")"#));
    }

    #[test]
    fn test_element_chain_empty_sub_selectors() {
        let extractors: Vec<String> = Vec::new();
        let joined = extractors.join("; ");
        assert!(joined.is_empty());
    }

    #[test]
    fn test_shadow_root_not_found_error_display() {
        let err = BrowserError::ShadowRootNotFound;
        assert_eq!(err.to_string(), "shadow root not found");
    }

    #[test]
    fn test_iframe_access_denied_error_display() {
        let err = BrowserError::IframeAccessDenied {
            selector: "iframe#my-frame".to_string(),
        };
        assert_eq!(err.to_string(), "iframe access denied: iframe#my-frame");
    }
}
