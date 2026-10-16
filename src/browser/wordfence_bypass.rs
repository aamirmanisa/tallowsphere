//! Wordfence JS challenge bypass for Tallow.
//!
//! Detects Wordfence "One moment, please..." JS challenge pages and
//! automates bypass via CDP JavaScript execution. Wordfence uses a
//! cookie-based challenge — once solved, the cookie persists for the session.
//!
//! Strategy:
//! 1. Navigate to target URL
//! 2. Detect if Wordfence challenge page loaded
//! 3. Execute the challenge JS via Runtime.evaluate
//! 4. Wait for the redirect to the real page
//! 5. Verify we're past the challenge

use std::time::Duration;

use super::error::BrowserError;
use super::page::Page;

/// Wordfence challenge page title text.
const WF_CHALLENGE_TITLE: &str = "One moment, please";

/// Maximum seconds to wait for JS challenge to resolve and redirect.
const WF_TIMEOUT_SECS: u64 = 15;

/// Detect if the current page is a Wordfence JS challenge page.
pub async fn is_wordfence_challenge(page: &Page) -> Result<bool, BrowserError> {
    match page.title().await {
        Ok(title) => Ok(title.contains(WF_CHALLENGE_TITLE)),
        Err(_) => Ok(false),
    }
}

/// Bypass the Wordfence JS challenge on the current page.
///
/// Wordfence challenge pages load a JavaScript payload that computes a
/// challenge response and sets a cookie (`wfvt_*`, `wordfence_verifiedHuman`).
/// Once the JS executes, the page auto-redirects to the original URL.
///
/// This function:
/// 1. Waits for any inline scripts to execute
/// 2. Checks if the challenge was auto-passed (redirect happened)
/// 3. If still on challenge page, evaluates the challenge script manually
/// 4. Waits for the redirect and returns the final page URL
pub async fn bypass_wordfence_challenge(page: &Page) -> Result<String, BrowserError> {
    // Wait a moment for auto-redirect (some browsers execute JS automatically).
    // P1 C3: jittered cadence wait — a constant 2 s is a timing fingerprint.
    super::cadence::sleep(2000, 0.35).await;

    let current_title = page.title().await.unwrap_or_default();
    if !current_title.contains(WF_CHALLENGE_TITLE) {
        // Already past the challenge — auto-redirect worked
        return page.url().await;
    }

    // Still on challenge page — execute the challenge JS manually
    // Wordfence loads a script that computes wfvt_* cookie and redirects
    let bypass_js = r#"
        (function() {
            // Wordfence challenge: look for the auto-redirect script
            var scripts = document.querySelectorAll('script');
            var found = false;
            for (var i = 0; i < scripts.length; i++) {
                var src = scripts[i].src || '';
                var text = scripts[i].textContent || '';
                // Wordfence typically injects a script with challenge computation
                if (src.indexOf('wordfence') > -1 || text.indexOf('wordfence_verifiedHuman') > -1) {
                    // The script should auto-execute on load, but force it if needed
                    try { eval(text); found = true; } catch(e) {}
                }
            }
            // If no Wordfence script found, try generic challenge bypass
            if (!found) {
                // Some versions use a simple cookie + redirect
                var forms = document.forms;
                if (forms.length > 0) {
                    // Try submitting any form (some challenges use button-based verify)
                    try { forms[0].submit(); } catch(e) {}
                }
            }
            return found ? 'bypass_attempted' : 'no_challenge_found';
        })()
    "#;

    let result = page.evaluate_expression(bypass_js).await?;

    // Wait for redirect (Wordfence typically redirects within 1-3 seconds).
    // P1 C3: jittered poll cadence.
    let start = std::time::Instant::now();
    loop {
        super::cadence::sleep(500, 0.4).await;

        // Check if we've been redirected past the challenge
        let title = page.title().await.unwrap_or_default();
        if !title.contains(WF_CHALLENGE_TITLE) {
            return page.url().await;
        }

        if start.elapsed().as_secs() > WF_TIMEOUT_SECS {
            return Err(BrowserError::Timeout {
                operation: "bypass_wordfence",
                detail: "Wordfence challenge not bypassed within timeout".to_string(),
            });
        }
    }
}

/// Navigate to a URL, automatically bypassing Wordfence if encountered.
///
/// This is the primary entry point — call this instead of `page.navigate()`
/// for sites protected by Wordfence.
pub async fn navigate_bypass_wordfence(page: &Page, url: &str) -> Result<String, BrowserError> {
    // Navigate with 8-second soft timeout — Wordfence pages never fire DOMContentLoaded
    page.navigate_timed(url, 8).await?;

    // Check for Wordfence
    if is_wordfence_challenge(page).await? {
        let final_url = bypass_wordfence_challenge(page).await?;
        // Re-navigate to ensure the page is fully loaded after bypass
        page.navigate(&final_url, super::page::WaitUntil::DomContentLoaded).await?;
        return Ok(final_url);
    }

    // No Wordfence detected — return current URL
    page.url().await
}
