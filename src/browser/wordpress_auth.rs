//! WordPress authentication automation for Tallow.
//!
//! Handles the full WordPress login flow including:
//! - Nonce extraction from login pages
//! - Login form submission
//! - 2FA detection and manual intervention prompts
//! - wp_rest nonce extraction for REST API calls
//! - Authenticated session validation
//!
//! Used in conjunction with the cookie bridge (Page::authenticated_request)
//! to make authenticated REST API calls after login.

use super::error::BrowserError;
use super::page::Page;
use serde_json::{json, Value};

/// A WordPress nonce extracted from a page.
#[derive(Debug, Clone)]
pub struct WpNonce {
    /// The nonce value (10-character hex string).
    pub value: String,
    /// Where the nonce was found (e.g., "rest_api", "admin_page").
    pub source: String,
    /// The nonce action/key name (e.g., "wp_rest").
    pub action: String,
}

/// Result of a login attempt.
#[derive(Debug, Clone)]
pub enum LoginResult {
    /// Login succeeded — session is active.
    Success { redirect_url: String },
    /// 2FA is required — need to provide code.
    TwoFactorRequired { method: String },
    /// Login failed — wrong credentials.
    Failed { reason: String },
    /// Unknown state — check the page manually.
    Unknown { page_title: String },
}

/// Extract the WordPress REST API nonce (wp_rest) from the current page.
///
/// WordPress exposes the REST nonce via `wpApiSettings.nonce` in the admin
/// and via a `<script>` tag on some front-end pages.
pub async fn wp_extract_rest_nonce(page: &Page) -> Result<Option<WpNonce>, BrowserError> {
    let js = r#"
        (function() {
            // Method 1: wpApiSettings (admin pages)
            if (typeof wpApiSettings !== 'undefined' && wpApiSettings.nonce) {
                return {nonce: wpApiSettings.nonce, source: 'wpApiSettings'};
            }
            // Method 2: Check for nonce hidden fields
            var nonceField = document.querySelector('#_wpnonce, input[name="_wpnonce"]');
            if (nonceField) {
                return {nonce: nonceField.value, source: 'hidden_field'};
            }
            // Method 3: Check script tags for nonce
            var scripts = document.querySelectorAll('script');
            for (var i = 0; i < scripts.length; i++) {
                var match = scripts[i].textContent.match(/["']nonce["']\s*:\s*["']([a-f0-9]+)["']/i);
                if (match) return {nonce: match[1], source: 'script_tag'};
                match = scripts[i].textContent.match(/"_wpnonce"\s*:\s*"([a-f0-9]+)"/i);
                if (match) return {nonce: match[1], source: 'script_tag'};
            }
            return null;
        })()
    "#;

    let result = page.evaluate_expression(js).await?;

    if let Value::Object(ref map) = result {
        if let Some(nonce_val) = map.get("nonce") {
            if let Some(nonce_str) = nonce_val.as_str() {
                let source = map
                    .get("source")
                    .and_then(|s| s.as_str())
                    .unwrap_or("unknown");
                return Ok(Some(WpNonce {
                    value: nonce_str.to_string(),
                    source: source.to_string(),
                    action: "wp_rest".to_string(),
                }));
            }
        }
    }

    Ok(None)
}

/// Check if the current page indicates a logged-in WordPress session.
///
/// Detects the WordPress admin bar, dashboard elements, or user menu.
pub async fn wp_is_logged_in(page: &Page) -> Result<bool, BrowserError> {
    let js = r#"
        (function() {
            // WordPress admin bar
            if (document.getElementById('wpadminbar')) return true;
            // Logged-in body class
            if (document.body && document.body.className.indexOf('logged-in') > -1) return true;
            // WooCommerce / member area indicators
            if (document.querySelector('.user-logged-in, .account-dashboard')) return true;
            // Check for logout link (strong indicator)
            var links = document.querySelectorAll('a[href*="logout"], a[href*="wp-login.php?action=logout"]');
            if (links.length > 0) return true;
            return false;
        })()
    "#;

    let result = page.evaluate_expression(js).await?;
    Ok(result.as_bool().unwrap_or(false))
}

/// Attempt a WordPress login via the wp-login.php form.
///
/// Navigates to wp-login.php, fills the form, and submits it.
/// Returns LoginResult indicating success, 2FA requirement, or failure.
pub async fn wp_login(
    page: &Page,
    username: &str,
    password: &str,
) -> Result<LoginResult, BrowserError> {
    use super::page::WaitUntil;

    // Navigate to login page
    page.navigate(
        "https://www.ghraonline.com/wp-login.php",
        WaitUntil::DomContentLoaded,
    )
    .await?;

    // Fill and submit the login form via JavaScript
    let login_js = format!(
        r#"
        (function() {{
            var userField = document.getElementById('user_login') || document.querySelector('input[name="log"]');
            var passField = document.getElementById('user_pass') || document.querySelector('input[name="pwd"]');
            var form = document.getElementById('loginform') || document.querySelector('form[name="loginform"]');

            if (!userField || !passField) {{
                return JSON.stringify({{error: 'login_form_not_found'}});
            }}

            userField.value = {user_json};
            passField.value = {pass_json};

            // Check for 2FA field (some plugins add it on the same page)
            var twofaField = document.querySelector('input[name="two_factor_code"], input[name="otp"], input[name="2facode"]');
            if (twofaField) {{
                return JSON.stringify({{status: '2fa_required', field: twofaField.name}});
            }}

            // Submit the form
            if (form) {{
                form.submit();
            }} else {{
                // Fallback: click the submit button
                var submitBtn = document.getElementById('wp-submit') || document.querySelector('input[type="submit"]');
                if (submitBtn) submitBtn.click();
            }}

            return JSON.stringify({{status: 'submitted'}});
        }})()
    "#,
        user_json = serde_json::to_string(username).unwrap_or_default(),
        pass_json = serde_json::to_string(password).unwrap_or_default(),
    );

    let result = page.evaluate_expression(&login_js).await?;

    if let Some(result_str) = result.as_str() {
        if let Ok(parsed) = serde_json::from_str::<Value>(result_str) {
            if let Some(status) = parsed.get("status").and_then(|s| s.as_str()) {
                match status {
                    "2fa_required" => {
                        let method = parsed
                            .get("field")
                            .and_then(|f| f.as_str())
                            .unwrap_or("unknown");
                        return Ok(LoginResult::TwoFactorRequired {
                            method: method.to_string(),
                        });
                    }
                    "error" => {
                        return Ok(LoginResult::Failed {
                            reason: "Login form not found on page".to_string(),
                        });
                    }
                    _ => {}
                }
            }
        }
    }

    // Wait for the page to process the login
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    // Check the result
    let current_url = page.url().await.unwrap_or_default();

    // Detect login outcome
    if current_url.contains("wp-admin") || current_url.contains("member-login")
        || current_url.contains("dashboard")
    {
        return Ok(LoginResult::Success {
            redirect_url: current_url,
        });
    }

    // Check for 2FA page
    let title = page.title().await.unwrap_or_default();
    if title.contains("Two Factor") || title.contains("2FA") || title.contains("Authentication code")
    {
        return Ok(LoginResult::TwoFactorRequired {
            method: "page_detected".to_string(),
        });
    }

    // Check if still on login page (failed)
    if current_url.contains("wp-login.php") {
        // Check for error message
        let has_error = page
            .evaluate_expression(
                "!!document.getElementById('login_error') || document.querySelector('.message') !== null",
            )
            .await
            .map(|v| v.as_bool().unwrap_or(false))
            .unwrap_or(false);

        if has_error {
            return Ok(LoginResult::Failed {
                reason: "Invalid username or password".to_string(),
            });
        }
        return Ok(LoginResult::Failed {
            reason: "Login failed — check credentials".to_string(),
        });
    }

    // Unknown state
    Ok(LoginResult::Unknown {
        page_title: title,
    })
}

/// Extract all WordPress nonces from the current page (REST, admin, etc.).
pub async fn wp_extract_all_nonces(page: &Page) -> Result<Vec<WpNonce>, BrowserError> {
    let mut nonces = Vec::new();

    // Try REST nonce first
    if let Some(rest_nonce) = wp_extract_rest_nonce(page).await? {
        nonces.push(rest_nonce);
    }

    // Try to find other nonces via JS
    let js = r#"
        (function() {
            var nonces = [];
            // Hidden _wpnonce fields
            document.querySelectorAll('input[type="hidden"][name="_wpnonce"], input[type="hidden"][id="_wpnonce"]').forEach(function(el) {
                nonces.push({value: el.value, source: 'hidden_input', action: el.name || '_wpnonce'});
            });
            // wp_rest nonce from wpApiSettings
            if (typeof wpApiSettings !== 'undefined' && wpApiSettings.nonce) {
                nonces.push({value: wpApiSettings.nonce, source: 'wpApiSettings', action: 'wp_rest'});
            }
            return nonces;
        })()
    "#;

    let result = page.evaluate_expression(js).await?;
    if let Value::Array(arr) = result {
        for item in arr {
            if let Value::Object(ref map) = item {
                if let (Some(val), Some(src), Some(act)) = (
                    map.get("value").and_then(|v| v.as_str()),
                    map.get("source").and_then(|v| v.as_str()),
                    map.get("action").and_then(|v| v.as_str()),
                ) {
                    nonces.push(WpNonce {
                        value: val.to_string(),
                        source: src.to_string(),
                        action: act.to_string(),
                    });
                }
            }
        }
    }

    Ok(nonces)
}
