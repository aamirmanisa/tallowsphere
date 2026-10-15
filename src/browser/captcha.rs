//! CAPTCHA detection, external solver integration, and manual solve mode.
//!
//! Supports reCAPTCHA v2/v3, hCaptcha, and Cloudflare Turnstile detection
//! via DOM inspection. Integrates with 2Captcha-compatible solver APIs
//! and provides a manual solve fallback for headful browsers.

use std::time::Duration;

use serde_json::json;

use super::cdp::CdpClient;
use super::error::BrowserError;

// ── CAPTCHA types (BRCA-01) ─────────────────────────────────────────

/// Supported CAPTCHA types that can be detected and solved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptchaType {
    ReCaptchaV2,
    ReCaptchaV3,
    HCaptcha,
    /// Cloudflare Turnstile challenge.
    Turnstile,
    /// AWS WAF CAPTCHA challenge.
    AwsWaf,
    /// Arkose Labs (formerly FunCaptcha) enterprise challenge.
    ArkoseLabs,
    /// DataDome bot-protection CAPTCHA.
    DataDome,
    /// FunCaptcha (legacy Arkose Labs integration).
    FunCaptcha,
    /// Image / normal text CAPTCHA (also known as NormalCaptcha). The base64
    /// image is carried on `CaptchaInfo.extra["body"]`.
    ImageCaptcha,
    /// GeeTest v3 (slide/puzzle/click challenge).
    GeeTest,
    /// GeeTest v4 (behavioral + puzzle challenge).
    GeeTestV4,
}

impl CaptchaType {
    /// Return the solver task type string for 2Captcha-compatible APIs.
    pub fn solver_task_type(&self) -> &'static str {
        match self {
            CaptchaType::ReCaptchaV2 => "RecaptchaV2TaskProxyless",
            CaptchaType::ReCaptchaV3 => "RecaptchaV3TaskProxyless",
            CaptchaType::HCaptcha => "HCaptchaTaskProxyless",
            CaptchaType::Turnstile => "TurnstileTaskProxyless",
            CaptchaType::AwsWaf => "AntiAwsTask",
            CaptchaType::ArkoseLabs => "ArkoseLabsTaskProxyless",
            CaptchaType::DataDome => "DataDomeSliderTask",
            CaptchaType::FunCaptcha => "FunCaptchaTaskProxyless",
            CaptchaType::ImageCaptcha => "ImageToTextTask",
            CaptchaType::GeeTest => "GeeTestTaskProxyless",
            CaptchaType::GeeTestV4 => "GeeTestV4TaskProxyless",
        }
    }

    /// Return the solution field name in solver API responses.
    pub fn solution_field(&self) -> &'static str {
        match self {
            CaptchaType::ReCaptchaV2 | CaptchaType::ReCaptchaV3 => "gRecaptchaResponse",
            CaptchaType::HCaptcha => "token",
            CaptchaType::Turnstile => "token",
            CaptchaType::AwsWaf => "cookie",
            CaptchaType::ArkoseLabs => "token",
            CaptchaType::DataDome => "cookie",
            CaptchaType::FunCaptcha => "token",
            CaptchaType::ImageCaptcha => "text",
            CaptchaType::GeeTest => "challenge",
            CaptchaType::GeeTestV4 => "pass_token",
        }
    }
}

impl std::fmt::Display for CaptchaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CaptchaType::ReCaptchaV2 => write!(f, "reCAPTCHA v2"),
            CaptchaType::ReCaptchaV3 => write!(f, "reCAPTCHA v3"),
            CaptchaType::HCaptcha => write!(f, "hCaptcha"),
            CaptchaType::Turnstile => write!(f, "Cloudflare Turnstile"),
            CaptchaType::AwsWaf => write!(f, "AWS WAF"),
            CaptchaType::ArkoseLabs => write!(f, "Arkose Labs"),
            CaptchaType::DataDome => write!(f, "DataDome"),
            CaptchaType::FunCaptcha => write!(f, "FunCaptcha"),
            CaptchaType::ImageCaptcha => write!(f, "Image CAPTCHA"),
            CaptchaType::GeeTest => write!(f, "GeeTest"),
            CaptchaType::GeeTestV4 => write!(f, "GeeTest v4"),
        }
    }
}

/// Information about a detected CAPTCHA on a page.
#[derive(Debug, Clone)]
pub struct CaptchaInfo {
    pub captcha_type: CaptchaType,
    pub site_key: Option<String>,
    pub element_selector: String,
    /// Solver-specific payload fields discovered during detection.
    /// Used by image CAPTCHAs (`body`, `textInstructions`) and GeeTest v3/v4
    /// (`gt`, `challenge`, `captchaId`). Merged into the solver task payload.
    pub extra: Option<serde_json::Value>,
}

// ── CAPTCHA solver backends ─────────────────────────────────────────

/// Supported CAPTCHA solving service backends.
///
/// Each variant carries the base URL, submit path, and result path for the
/// corresponding third-party API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CaptchaBackend {
    /// 2Captcha — <https://2captcha.com>
    TwoCaptcha,
    /// Anti-Captcha — <https://api.anti-captcha.com>
    AntiCaptcha,
    /// CapSolver — <https://api.capsolver.com>
    CapSolver,
    /// CapMonster — <https://api.capmonster.cloud>
    CapMonster,
    /// DeathByCaptcha — <https://api.dbcapi.me> (in.php/res.php form protocol).
    ///
    /// Note: DeathByCaptcha natively authenticates with username+password and
    /// returns plain-text responses; here it is treated as a 2Captcha-style
    /// `/in.php`+`/res.php` backend using `api_key` as the account key so it
    /// routes through the same code path.
    DeathByCaptcha,
    /// Custom service URL using a 2Captcha-compatible API.
    Custom(String),
}

impl CaptchaBackend {
    /// Return the base URL for this backend (no trailing slash).
    pub fn base_url(&self) -> &str {
        match self {
            CaptchaBackend::TwoCaptcha => "https://2captcha.com",
            CaptchaBackend::AntiCaptcha => "https://api.anti-captcha.com",
            CaptchaBackend::CapSolver => "https://api.capsolver.com",
            CaptchaBackend::CapMonster => "https://api.capmonster.cloud",
            CaptchaBackend::DeathByCaptcha => "https://api.dbcapi.me",
            CaptchaBackend::Custom(url) => url.as_str(),
        }
    }

    /// Return the path used to submit a new solve task.
    pub fn submit_path(&self) -> &str {
        match self {
            CaptchaBackend::TwoCaptcha
            | CaptchaBackend::DeathByCaptcha
            | CaptchaBackend::Custom(_) => "/in.php",
            CaptchaBackend::AntiCaptcha
            | CaptchaBackend::CapSolver
            | CaptchaBackend::CapMonster => "/createTask",
        }
    }

    /// Return the path used to poll for a solve result.
    pub fn result_path(&self) -> &str {
        match self {
            CaptchaBackend::TwoCaptcha
            | CaptchaBackend::DeathByCaptcha
            | CaptchaBackend::Custom(_) => "/res.php",
            CaptchaBackend::AntiCaptcha
            | CaptchaBackend::CapSolver
            | CaptchaBackend::CapMonster => "/getTaskResult",
        }
    }

    /// Whether this backend speaks the legacy 2Captcha `/in.php`+`/res.php`
    /// form-encoded protocol (as opposed to the JSON `/createTask` task API).
    pub fn uses_legacy_form_protocol(&self) -> bool {
        self.submit_path() == "/in.php"
    }
}

// ── Detection (BRCA-01) ─────────────────────────────────────────────

/// Detect a CAPTCHA on the current page by inspecting the DOM.
///
/// Checks for reCAPTCHA v2, reCAPTCHA v3, hCaptcha, and Cloudflare Turnstile
/// in priority order. Returns the first match with its site key and selector.
pub async fn detect_captcha(
    client: &CdpClient,
    session_id: &str,
) -> Result<Option<CaptchaInfo>, BrowserError> {
    let js = r#"
    (function() {
        // 1. reCAPTCHA v2: .g-recaptcha element with data-sitekey
        var el = document.querySelector('.g-recaptcha');
        if (el) {
            return JSON.stringify({
                type: 'recaptcha_v2',
                siteKey: el.getAttribute('data-sitekey') || null,
                selector: '.g-recaptcha'
            });
        }

        // 2. reCAPTCHA v2 via iframe
        var iframe = document.querySelector('iframe[src*="recaptcha"]');
        if (iframe) {
            // Try to extract sitekey from iframe src
            var src = iframe.getAttribute('src') || '';
            var match = src.match(/[?&]k=([^&]+)/);
            return JSON.stringify({
                type: 'recaptcha_v2',
                siteKey: match ? match[1] : null,
                selector: 'iframe[src*="recaptcha"]'
            });
        }

        // 3. reCAPTCHA v3: script tag present but no visible widget
        var script = document.querySelector('script[src*="recaptcha/api.js"]');
        if (script) {
            var src = script.getAttribute('src') || '';
            var match = src.match(/[?&]render=([^&]+)/);
            return JSON.stringify({
                type: 'recaptcha_v3',
                siteKey: match ? match[1] : null,
                selector: 'script[src*="recaptcha/api.js"]'
            });
        }

        // 4. hCaptcha: .h-captcha element with data-sitekey
        var hel = document.querySelector('.h-captcha');
        if (hel) {
            return JSON.stringify({
                type: 'hcaptcha',
                siteKey: hel.getAttribute('data-sitekey') || null,
                selector: '.h-captcha'
            });
        }

        // 5. hCaptcha via iframe
        var hiframe = document.querySelector('iframe[src*="hcaptcha"]');
        if (hiframe) {
            return JSON.stringify({
                type: 'hcaptcha',
                siteKey: null,
                selector: 'iframe[src*="hcaptcha"]'
            });
        }

        // 6. Cloudflare Turnstile: .cf-turnstile element
        var tsel = document.querySelector('.cf-turnstile');
        if (tsel) {
            return JSON.stringify({
                type: 'turnstile',
                siteKey: tsel.getAttribute('data-sitekey') || null,
                selector: '.cf-turnstile'
            });
        }

        // 7. Turnstile via iframe
        var tiframe = document.querySelector('iframe[src*="challenges.cloudflare.com"]');
        if (tiframe) {
            return JSON.stringify({
                type: 'turnstile',
                siteKey: null,
                selector: 'iframe[src*="challenges.cloudflare.com"]'
            });
        }

        return null;
    })()
    "#;

    let params = json!({
        "expression": js,
        "returnByValue": true,
    });

    let result = client
        .send_command_with_session("Runtime.evaluate", Some(params), session_id)
        .await?;

    let value = result
        .get("result")
        .and_then(|r| r.get("value"));

    let json_str = match value {
        Some(serde_json::Value::String(s)) => s.clone(),
        _ => return Ok(None),
    };

    let parsed: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| BrowserError::CaptchaError(format!("failed to parse detection result: {}", e)))?;

    let captcha_type = match parsed.get("type").and_then(|t| t.as_str()) {
        Some("recaptcha_v2") => CaptchaType::ReCaptchaV2,
        Some("recaptcha_v3") => CaptchaType::ReCaptchaV3,
        Some("hcaptcha") => CaptchaType::HCaptcha,
        Some("turnstile") => CaptchaType::Turnstile,
        _ => return Ok(None),
    };

    let site_key = parsed
        .get("siteKey")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let selector = parsed
        .get("selector")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(Some(CaptchaInfo {
        captcha_type,
        site_key,
        element_selector: selector,
        extra: None,
    }))
}

// ── External solver integration (BRCA-02) ───────────────────────────

/// Configuration for an external CAPTCHA solving service (2Captcha-compatible).
#[derive(Debug, Clone)]
pub struct CaptchaSolverConfig {
    /// API key for the solver service.
    pub api_key: String,
    /// Base URL of the solver service (e.g., "https://api.2captcha.com").
    ///
    /// Kept for backward compatibility. When `backend` is set, the backend's
    /// `base_url()` takes precedence over this field.
    pub service_url: String,
    /// Solver backend to use for submit/result endpoints.
    pub backend: CaptchaBackend,
    /// Maximum time to wait for a solution.
    pub timeout: Duration,
    /// Interval between polling for the solution.
    pub poll_interval: Duration,
}

impl CaptchaSolverConfig {
    /// Create a new config with default timeout (120s), poll interval (5s),
    /// and `TwoCaptcha` backend.
    pub fn new(api_key: &str, service_url: &str) -> Self {
        Self {
            api_key: api_key.to_string(),
            service_url: service_url.to_string(),
            backend: CaptchaBackend::TwoCaptcha,
            timeout: Duration::from_secs(120),
            poll_interval: Duration::from_secs(5),
        }
    }

    /// Set the solver backend (builder pattern).
    pub fn with_backend(mut self, backend: CaptchaBackend) -> Self {
        self.backend = backend;
        self
    }
}

/// Build the JSON payload for creating a solver task.
pub fn build_create_task_payload(
    config: &CaptchaSolverConfig,
    captcha: &CaptchaInfo,
    page_url: &str,
) -> serde_json::Value {
    let mut task = json!({
        "type": captcha.captcha_type.solver_task_type(),
        "websiteURL": page_url,
    });

    // Merge solver-specific payload fields discovered during detection:
    // image CAPTCHAs -> `body`, `textInstructions`; GeeTest v3/v4 -> `gt`,
    // `challenge`, `captchaId`.
    if let Some(ref extra) = captcha.extra {
        if let Some(obj) = extra.as_object() {
            for (k, v) in obj {
                task[k] = v.clone();
            }
        }
    }

    if let Some(ref key) = captcha.site_key {
        task["websiteKey"] = json!(key);
    }

    json!({
        "clientKey": config.api_key,
        "task": task,
    })
}

/// Solve a CAPTCHA using an external 2Captcha-compatible service.
///
/// Routes through the configured `CaptchaBackend`'s `base_url()` +
/// `submit_path()` + `result_path()`:
/// - JSON `/createTask`+`/getTaskResult` backends (AntiCaptcha, CapSolver,
///   CapMonster) use the task API.
/// - Legacy `/in.php`+`/res.php` backends (TwoCaptcha, DeathByCaptcha, Custom)
///   use the form-encoded protocol.
///
/// This is a blocking (synchronous) function using `ureq`.
pub fn solve_captcha(
    config: &CaptchaSolverConfig,
    captcha: &CaptchaInfo,
    page_url: &str,
) -> Result<String, BrowserError> {
    let base = config.backend.base_url();
    let submit_path = config.backend.submit_path();
    let result_path = config.backend.result_path();

    if config.backend.uses_legacy_form_protocol() {
        solve_captcha_legacy_form(config, captcha, page_url, base, submit_path, result_path)
    } else {
        solve_captcha_task_json(config, captcha, page_url, base, submit_path, result_path)
    }
}

/// Solve via the JSON `/createTask`+`/getTaskResult` task API.
fn solve_captcha_task_json(
    config: &CaptchaSolverConfig,
    captcha: &CaptchaInfo,
    page_url: &str,
    base: &str,
    submit_path: &str,
    result_path: &str,
) -> Result<String, BrowserError> {
    let create_url = format!("{}{}", base, submit_path);
    let payload = build_create_task_payload(config, captcha, page_url);

    // Step 1: Submit task
    let body: String = crate::runtime::egress_http::post(&create_url)
        .send_json(&payload)
        .map_err(|e| BrowserError::CaptchaError(format!("failed to create solver task: {}\n{}", e, payload)))?
        .into_body()
        .read_to_string()
        .map_err(|e| BrowserError::CaptchaError(format!("failed to read create response: {}", e)))?;

    let resp: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| BrowserError::CaptchaError(format!("failed to parse create response: {}", e)))?;

    let error_id = resp.get("errorId").and_then(|v: &serde_json::Value| v.as_i64()).unwrap_or(0);
    if error_id != 0 {
        let desc = resp
            .get("errorDescription")
            .and_then(|v: &serde_json::Value| v.as_str())
            .unwrap_or("unknown error");
        return Err(BrowserError::CaptchaError(format!(
            "solver API error: {}",
            desc
        )));
    }

    let task_id = resp
        .get("taskId")
        .and_then(|v: &serde_json::Value| v.as_u64())
        .ok_or_else(|| BrowserError::CaptchaError("no taskId in response".to_string()))?;

    // Step 2: Poll for result
    let result_url = format!("{}{}", base, result_path);
    let deadline = std::time::Instant::now() + config.timeout;

    loop {
        std::thread::sleep(config.poll_interval);

        if std::time::Instant::now() >= deadline {
            return Err(BrowserError::CaptchaSolveTimeout);
        }

        let poll_payload = json!({
            "clientKey": config.api_key,
            "taskId": task_id,
        });

        let poll_body: String = crate::runtime::egress_http::post(&result_url)
            .send_json(&poll_payload)
            .map_err(|e| {
                BrowserError::CaptchaError(format!("failed to poll solver result: {}", e))
            })?
            .into_body()
            .read_to_string()
            .map_err(|e| {
                BrowserError::CaptchaError(format!("failed to read poll response: {}", e))
            })?;

        let poll_resp: serde_json::Value = serde_json::from_str(&poll_body)
            .map_err(|e| {
                BrowserError::CaptchaError(format!("failed to parse poll response: {}", e))
            })?;

        let status = poll_resp
            .get("status")
            .and_then(|v: &serde_json::Value| v.as_str())
            .unwrap_or("processing");

        if status == "ready" {
            let solution_field = captcha.captcha_type.solution_field();
            let solution = poll_resp
                .get("solution")
                .and_then(|s: &serde_json::Value| s.get(solution_field))
                .and_then(|v: &serde_json::Value| v.as_str())
                .ok_or_else(|| {
                    BrowserError::CaptchaError(format!(
                        "solution field '{}' not found in response",
                        solution_field
                    ))
                })?;
            return Ok(solution.to_string());
        }
    }
}

/// Solve via the legacy 2Captcha `/in.php`+`/res.php` form-encoded protocol.
///
/// Used by TwoCaptcha, DeathByCaptcha, and Custom endpoints. Builds a
/// form-encoded payload from the solver task and polls `res.php` until a
/// solution is returned.
fn solve_captcha_legacy_form(
    config: &CaptchaSolverConfig,
    captcha: &CaptchaInfo,
    page_url: &str,
    base: &str,
    submit_path: &str,
    result_path: &str,
) -> Result<String, BrowserError> {
    let payload = build_create_task_payload(config, captcha, page_url);
    let task_type = payload["task"]["type"].as_str().unwrap_or("");

    // Map the solver task type to a 2Captcha `method`.
    let method = if task_type == "ImageToTextTask" {
        "base64"
    } else if task_type.starts_with("Recaptcha") {
        "userrecaptcha"
    } else if task_type.starts_with("HCaptcha") {
        "hcaptcha"
    } else if task_type.starts_with("Turnstile") {
        "turnstile"
    } else {
        // Generic/fallback method for token-style challenges.
        "userrecaptcha"
    };

    // Build form fields from the task object.
    let mut fields: Vec<(String, String)> = Vec::new();
    fields.push(("key".to_string(), config.api_key.clone()));
    fields.push(("method".to_string(), method.to_string()));
    fields.push(("json".to_string(), "1".to_string()));

    if let Some(task) = payload["task"].as_object() {
        for (k, v) in task {
            let val = v.as_str().unwrap_or("");
            match k.as_str() {
                "body" => fields.push(("body".to_string(), val.to_string())),
                "textInstructions" => {
                    fields.push(("textinstructions".to_string(), val.to_string()))
                }
                "websiteKey" => fields.push(("googlekey".to_string(), val.to_string())),
                "websiteURL" => fields.push(("pageurl".to_string(), val.to_string())),
                "gt" => fields.push(("gt".to_string(), val.to_string())),
                "challenge" => fields.push(("challenge".to_string(), val.to_string())),
                "captchaId" => fields.push(("captchaId".to_string(), val.to_string())),
                _ => {}
            }
        }
    }

    // URL-encode form body.
    let enc = |s: &str| urlencoding::encode(s).into_owned();
    let form_body = fields
        .iter()
        .map(|(k, v)| format!("{}={}", k, enc(v)))
        .collect::<Vec<_>>()
        .join("&");

    // Step 1: Submit task to /in.php.
    let submit_url = format!("{}{}", base, submit_path);
    let body: String = crate::runtime::egress_http::post(&submit_url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(form_body.as_bytes())
        .map_err(|e| BrowserError::CaptchaError(format!("failed to create solver task: {}", e)))?
        .into_body()
        .read_to_string()
        .map_err(|e| BrowserError::CaptchaError(format!("failed to read create response: {}", e)))?;

    let resp: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| BrowserError::CaptchaError(format!("failed to parse create response: {}", e)))?;

    let status = resp.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
    if status != 1 {
        let desc = resp
            .get("error_text")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown error");
        return Err(BrowserError::CaptchaError(format!("solver API error: {}", desc)));
    }

    let task_id = resp
        .get("request")
        .and_then(|v| v.as_str())
        .ok_or_else(|| BrowserError::CaptchaError("no task id in response".to_string()))?;

    // Step 2: Poll /res.php until solved.
    let deadline = std::time::Instant::now() + config.timeout;
    loop {
        std::thread::sleep(config.poll_interval);

        if std::time::Instant::now() >= deadline {
            return Err(BrowserError::CaptchaSolveTimeout);
        }

        let result_url = format!(
            "{}?key={}&action=get&id={}&json=1",
            format!("{}{}", base, result_path),
            enc(&config.api_key),
            enc(task_id)
        );

        let poll_body: String = crate::runtime::egress_http::get(&result_url)
            .call()
            .map_err(|e| {
                BrowserError::CaptchaError(format!("failed to poll solver result: {}", e))
            })?
            .into_body()
            .read_to_string()
            .map_err(|e| {
                BrowserError::CaptchaError(format!("failed to read poll response: {}", e))
            })?;

        let poll_resp: serde_json::Value = serde_json::from_str(&poll_body)
            .map_err(|e| {
                BrowserError::CaptchaError(format!("failed to parse poll response: {}", e))
            })?;

        let poll_status = poll_resp.get("status").and_then(|v| v.as_i64()).unwrap_or(0);
        let request = poll_resp.get("request").and_then(|v| v.as_str()).unwrap_or("");

        if poll_status == 1 {
            return Ok(request.to_string());
        }
        if request == "CAPCHA_NOT_READY" {
            continue;
        }
        if request.starts_with("ERROR") {
            return Err(BrowserError::CaptchaError(format!(
                "solver poll error: {}",
                request
            )));
        }
    }
}

/// Build the JavaScript to inject a solved CAPTCHA token back into the page.
pub fn build_inject_js(captcha: &CaptchaInfo, solution: &str) -> String {
    let escaped = solution.replace('\\', "\\\\").replace('"', "\\\"");

    match captcha.captcha_type {
        CaptchaType::ReCaptchaV2 | CaptchaType::ReCaptchaV3 => {
            format!(
                r#"(function() {{
    var textarea = document.getElementById('g-recaptcha-response');
    if (textarea) {{
        textarea.style.display = '';
        textarea.value = "{}";
    }}
    // Also set any hidden textareas (some sites have multiple)
    var all = document.querySelectorAll('[name="g-recaptcha-response"]');
    for (var i = 0; i < all.length; i++) {{
        all[i].value = "{}";
    }}
    // Trigger callback if available
    if (typeof ___grecaptcha_cfg !== 'undefined') {{
        var clients = ___grecaptcha_cfg.clients;
        if (clients) {{
            for (var cid in clients) {{
                var client = clients[cid];
                if (client && client.U && client.U.U && client.U.U.callback) {{
                    client.U.U.callback("{}");
                }}
            }}
        }}
    }}
}})()"#,
                escaped, escaped, escaped
            )
        }
        CaptchaType::HCaptcha => {
            format!(
                r#"(function() {{
    var textarea = document.querySelector('[name="h-captcha-response"]');
    if (textarea) {{
        textarea.value = "{}";
    }}
    var iframe = document.querySelector('iframe[data-hcaptcha-widget-id]');
    if (iframe) {{
        var widgetId = iframe.getAttribute('data-hcaptcha-widget-id');
        if (typeof hcaptcha !== 'undefined' && widgetId) {{
            // Trigger internal callback
            try {{ hcaptcha.execute({{ async: false }}); }} catch(e) {{}}
        }}
    }}
    // Dispatch change event on the response element
    var responseEl = document.querySelector('.h-captcha textarea');
    if (responseEl) {{
        responseEl.value = "{}";
        responseEl.dispatchEvent(new Event('change', {{ bubbles: true }}));
    }}
}})()"#,
                escaped, escaped
            )
        }
        CaptchaType::Turnstile => {
            format!(
                r#"(function() {{
    var input = document.querySelector('[name="cf-turnstile-response"]');
    if (input) {{
        input.value = "{}";
    }}
    // Try to trigger Turnstile callback
    if (typeof turnstile !== 'undefined') {{
        var widgets = document.querySelectorAll('.cf-turnstile');
        for (var i = 0; i < widgets.length; i++) {{
            var cb = widgets[i].getAttribute('data-callback');
            if (cb && typeof window[cb] === 'function') {{
                window[cb]("{}");
            }}
        }}
    }}
}})()"#,
                escaped, escaped
            )
        }
        // New CAPTCHA types — solution injection is service-specific and
        // typically handled via cookie or header rather than DOM injection.
        CaptchaType::AwsWaf
        | CaptchaType::ArkoseLabs
        | CaptchaType::DataDome
        | CaptchaType::FunCaptcha
        | CaptchaType::ImageCaptcha => {
            format!(
                r#"(function() {{
    // Generic token injection: set a hidden input if present.
    var el = document.querySelector('[name="captcha-response"]');
    if (el) {{ el.value = "{}"; }}
}})()"#,
                escaped
            )
        }
        // GeeTest v3/v4 — set the hidden challenge/validate/seccode inputs.
        CaptchaType::GeeTest | CaptchaType::GeeTestV4 => {
            format!(
                r#"(function() {{
    var names = ['geetest_challenge', 'geetest_validate', 'geetest_seccode'];
    for (var i = 0; i < names.length; i++) {{
        var el = document.querySelector('[name="' + names[i] + '"]');
        if (el) {{ el.value = "{}"; }}
    }}
    var response = document.querySelector('[name="geetest_response"]');
    if (response) {{ response.value = "{}"; }}
}})()"#,
                escaped, escaped
            )
        }
    }
}

/// Inject a solved CAPTCHA token into the page.
///
/// Sets the appropriate response field and triggers callbacks for the
/// detected CAPTCHA type.
pub async fn inject_captcha_solution(
    client: &CdpClient,
    session_id: &str,
    captcha: &CaptchaInfo,
    solution: &str,
) -> Result<(), BrowserError> {
    let js = build_inject_js(captcha, solution);

    let params = json!({
        "expression": js,
        "returnByValue": true,
    });

    client
        .send_command_with_session("Runtime.evaluate", Some(params), session_id)
        .await?;

    Ok(())
}

// ── Manual solve mode (BRCA-03) ─────────────────────────────────────

/// Wait for a human to manually solve a CAPTCHA.
///
/// Polls every 2 seconds checking if the CAPTCHA response field has been
/// populated (indicating the user solved it). Logs instructions to stderr
/// so the user knows what to do.
///
/// Returns `true` if solved within timeout, `false` if timeout expired.
pub async fn wait_for_manual_solve(
    client: &CdpClient,
    session_id: &str,
    captcha: &CaptchaInfo,
    timeout: Duration,
) -> Result<bool, BrowserError> {
    // Warn if headless
    let headless_check = json!({
        "expression": "navigator.webdriver === true || navigator.userAgent.includes('HeadlessChrome')",
        "returnByValue": true,
    });
    let headless_result = client
        .send_command_with_session("Runtime.evaluate", Some(headless_check), session_id)
        .await?;
    let is_headless = headless_result
        .get("result")
        .and_then(|r| r.get("value"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);

    if is_headless {
        eprintln!(
            "WARNING: Browser is in headless mode -- manual CAPTCHA solving requires headful mode."
        );
    }

    eprintln!(
        "CAPTCHA detected ({}). Please solve manually. Waiting up to {}s...",
        captcha.captcha_type,
        timeout.as_secs()
    );

    let start = std::time::Instant::now();
    let poll_interval = Duration::from_secs(2);

    let check_js = build_manual_solve_check_js(captcha);

    loop {
        let params = json!({
            "expression": &check_js,
            "returnByValue": true,
        });

        let result = client
            .send_command_with_session("Runtime.evaluate", Some(params), session_id)
            .await?;

        let solved = result
            .get("result")
            .and_then(|r| r.get("value"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        if solved {
            eprintln!("CAPTCHA solved successfully.");
            return Ok(true);
        }

        if start.elapsed() >= timeout {
            eprintln!("CAPTCHA solve timeout expired.");
            return Ok(false);
        }

        tokio::time::sleep(poll_interval).await;
    }
}

/// Build JavaScript to check if a CAPTCHA has been solved manually.
fn build_manual_solve_check_js(captcha: &CaptchaInfo) -> String {
    match captcha.captcha_type {
        CaptchaType::ReCaptchaV2 | CaptchaType::ReCaptchaV3 => {
            r#"(function() {
                var el = document.getElementById('g-recaptcha-response');
                return el !== null && el.value !== '';
            })()"#
                .to_string()
        }
        CaptchaType::HCaptcha => {
            r#"(function() {
                var el = document.querySelector('[name="h-captcha-response"]');
                return el !== null && el.value !== '';
            })()"#
                .to_string()
        }
        CaptchaType::Turnstile => {
            r#"(function() {
                var el = document.querySelector('[name="cf-turnstile-response"]');
                return el !== null && el.value !== '';
            })()"#
                .to_string()
        }
        CaptchaType::AwsWaf
        | CaptchaType::ArkoseLabs
        | CaptchaType::DataDome
        | CaptchaType::FunCaptcha
        | CaptchaType::ImageCaptcha => {
            r#"(function() {
                var el = document.querySelector('[name="captcha-response"]');
                return el !== null && el.value !== '';
            })()"#
                .to_string()
        }
        CaptchaType::GeeTest | CaptchaType::GeeTestV4 => {
            r#"(function() {
                var el = document.querySelector('[name="geetest_challenge"]');
                return el !== null && el.value !== '';
            })()"#
                .to_string()
        }
    }
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_captcha_type_equality() {
        assert_eq!(CaptchaType::ReCaptchaV2, CaptchaType::ReCaptchaV2);
        assert_eq!(CaptchaType::HCaptcha, CaptchaType::HCaptcha);
        assert_ne!(CaptchaType::ReCaptchaV2, CaptchaType::ReCaptchaV3);
        assert_ne!(CaptchaType::HCaptcha, CaptchaType::Turnstile);
    }

    #[test]
    fn test_captcha_type_debug() {
        let dbg = format!("{:?}", CaptchaType::ReCaptchaV2);
        assert_eq!(dbg, "ReCaptchaV2");
        let dbg = format!("{:?}", CaptchaType::Turnstile);
        assert_eq!(dbg, "Turnstile");
    }

    #[test]
    fn test_captcha_type_display() {
        assert_eq!(CaptchaType::ReCaptchaV2.to_string(), "reCAPTCHA v2");
        assert_eq!(CaptchaType::ReCaptchaV3.to_string(), "reCAPTCHA v3");
        assert_eq!(CaptchaType::HCaptcha.to_string(), "hCaptcha");
        assert_eq!(
            CaptchaType::Turnstile.to_string(),
            "Cloudflare Turnstile"
        );
    }

    #[test]
    fn test_captcha_solver_config_defaults() {
        let config = CaptchaSolverConfig::new("test-key", "https://api.2captcha.com");
        assert_eq!(config.api_key, "test-key");
        assert_eq!(config.service_url, "https://api.2captcha.com");
        assert_eq!(config.timeout, Duration::from_secs(120));
        assert_eq!(config.poll_interval, Duration::from_secs(5));
    }

    #[test]
    fn test_solver_task_type_mapping() {
        assert_eq!(
            CaptchaType::ReCaptchaV2.solver_task_type(),
            "RecaptchaV2TaskProxyless"
        );
        assert_eq!(
            CaptchaType::ReCaptchaV3.solver_task_type(),
            "RecaptchaV3TaskProxyless"
        );
        assert_eq!(
            CaptchaType::HCaptcha.solver_task_type(),
            "HCaptchaTaskProxyless"
        );
        assert_eq!(
            CaptchaType::Turnstile.solver_task_type(),
            "TurnstileTaskProxyless"
        );
    }

    #[test]
    fn test_build_create_task_payload_recaptcha_v2() {
        let config = CaptchaSolverConfig::new("my-api-key", "https://solver.example.com");
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::ReCaptchaV2,
            site_key: Some("6LcXxxxxxxxxxxxxxxx".to_string()),
            element_selector: ".g-recaptcha".to_string(),
            extra: None,
        };

        let payload = build_create_task_payload(&config, &captcha, "https://target.com/login");

        assert_eq!(payload["clientKey"], "my-api-key");
        assert_eq!(payload["task"]["type"], "RecaptchaV2TaskProxyless");
        assert_eq!(payload["task"]["websiteURL"], "https://target.com/login");
        assert_eq!(payload["task"]["websiteKey"], "6LcXxxxxxxxxxxxxxxx");
    }

    #[test]
    fn test_build_create_task_payload_hcaptcha_no_sitekey() {
        let config = CaptchaSolverConfig::new("key", "https://solver.example.com");
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::HCaptcha,
            site_key: None,
            element_selector: "iframe[src*=\"hcaptcha\"]".to_string(),
            extra: None,
        };

        let payload = build_create_task_payload(&config, &captcha, "https://example.com");

        assert_eq!(payload["task"]["type"], "HCaptchaTaskProxyless");
        assert!(payload["task"].get("websiteKey").is_none());
    }

    #[test]
    fn test_build_create_task_payload_turnstile() {
        let config = CaptchaSolverConfig::new("key", "https://solver.example.com");
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::Turnstile,
            site_key: Some("0x4AAAAAAA".to_string()),
            element_selector: ".cf-turnstile".to_string(),
            extra: None,
        };

        let payload = build_create_task_payload(&config, &captcha, "https://target.com");

        assert_eq!(payload["task"]["type"], "TurnstileTaskProxyless");
        assert_eq!(payload["task"]["websiteKey"], "0x4AAAAAAA");
    }

    #[test]
    fn test_inject_js_recaptcha_v2() {
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::ReCaptchaV2,
            site_key: Some("key".to_string()),
            element_selector: ".g-recaptcha".to_string(),
            extra: None,
        };

        let js = build_inject_js(&captcha, "03AGdBq24...");
        assert!(js.contains("g-recaptcha-response"));
        assert!(js.contains("03AGdBq24..."));
        assert!(js.contains("___grecaptcha_cfg"));
    }

    #[test]
    fn test_inject_js_hcaptcha() {
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::HCaptcha,
            site_key: None,
            element_selector: ".h-captcha".to_string(),
            extra: None,
        };

        let js = build_inject_js(&captcha, "P0_eyJ...");
        assert!(js.contains("h-captcha-response"));
        assert!(js.contains("P0_eyJ..."));
    }

    #[test]
    fn test_inject_js_turnstile() {
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::Turnstile,
            site_key: Some("0x4AAAA".to_string()),
            element_selector: ".cf-turnstile".to_string(),
            extra: None,
        };

        let js = build_inject_js(&captcha, "0.abcdef...");
        assert!(js.contains("cf-turnstile-response"));
        assert!(js.contains("0.abcdef..."));
        assert!(js.contains("data-callback"));
    }

    #[test]
    fn test_inject_js_escapes_quotes() {
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::ReCaptchaV2,
            site_key: None,
            element_selector: ".g-recaptcha".to_string(),
            extra: None,
        };

        let js = build_inject_js(&captcha, "token\"with\\special");
        assert!(js.contains(r#"token\"with\\special"#));
    }

    #[test]
    fn test_captcha_info_with_site_key() {
        let info = CaptchaInfo {
            captcha_type: CaptchaType::ReCaptchaV2,
            site_key: Some("6LcXyyy".to_string()),
            element_selector: ".g-recaptcha".to_string(),
            extra: None,
        };
        assert!(info.site_key.is_some());
        assert_eq!(info.element_selector, ".g-recaptcha");
    }

    #[test]
    fn test_captcha_info_without_site_key() {
        let info = CaptchaInfo {
            captcha_type: CaptchaType::HCaptcha,
            site_key: None,
            element_selector: "iframe[src*=\"hcaptcha\"]".to_string(),
            extra: None,
        };
        assert!(info.site_key.is_none());
    }

    #[test]
    fn test_manual_solve_check_js_recaptcha() {
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::ReCaptchaV2,
            site_key: None,
            element_selector: ".g-recaptcha".to_string(),
            extra: None,
        };
        let js = build_manual_solve_check_js(&captcha);
        assert!(js.contains("g-recaptcha-response"));
        assert!(js.contains(".value !== ''"));
    }

    #[test]
    fn test_manual_solve_check_js_hcaptcha() {
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::HCaptcha,
            site_key: None,
            element_selector: ".h-captcha".to_string(),
            extra: None,
        };
        let js = build_manual_solve_check_js(&captcha);
        assert!(js.contains("h-captcha-response"));
    }

    #[test]
    fn test_manual_solve_check_js_turnstile() {
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::Turnstile,
            site_key: None,
            element_selector: ".cf-turnstile".to_string(),
            extra: None,
        };
        let js = build_manual_solve_check_js(&captcha);
        assert!(js.contains("cf-turnstile-response"));
    }

    #[test]
    fn test_solution_field_mapping() {
        assert_eq!(
            CaptchaType::ReCaptchaV2.solution_field(),
            "gRecaptchaResponse"
        );
        assert_eq!(
            CaptchaType::ReCaptchaV3.solution_field(),
            "gRecaptchaResponse"
        );
        assert_eq!(CaptchaType::HCaptcha.solution_field(), "token");
        assert_eq!(CaptchaType::Turnstile.solution_field(), "token");
    }

    #[test]
    fn captcha_backend_urls() {
        // TwoCaptcha
        let b = CaptchaBackend::TwoCaptcha;
        assert_eq!(b.base_url(), "https://2captcha.com");
        assert_eq!(b.submit_path(), "/in.php");
        assert_eq!(b.result_path(), "/res.php");

        // AntiCaptcha
        let b = CaptchaBackend::AntiCaptcha;
        assert_eq!(b.base_url(), "https://api.anti-captcha.com");
        assert_eq!(b.submit_path(), "/createTask");
        assert_eq!(b.result_path(), "/getTaskResult");

        // CapSolver
        let b = CaptchaBackend::CapSolver;
        assert_eq!(b.base_url(), "https://api.capsolver.com");
        assert_eq!(b.submit_path(), "/createTask");
        assert_eq!(b.result_path(), "/getTaskResult");

        // CapMonster
        let b = CaptchaBackend::CapMonster;
        assert_eq!(b.base_url(), "https://api.capmonster.cloud");
        assert_eq!(b.submit_path(), "/createTask");
        assert_eq!(b.result_path(), "/getTaskResult");

        // DeathByCaptcha — api.dbcapi.me with in.php/res.php form protocol
        let b = CaptchaBackend::DeathByCaptcha;
        assert_eq!(b.base_url(), "https://api.dbcapi.me");
        assert_eq!(b.submit_path(), "/in.php");
        assert_eq!(b.result_path(), "/res.php");
        assert!(b.uses_legacy_form_protocol());

        // Custom — uses 2Captcha-compatible paths
        let b = CaptchaBackend::Custom("https://my-solver.example.com".to_string());
        assert_eq!(b.base_url(), "https://my-solver.example.com");
        assert_eq!(b.submit_path(), "/in.php");
        assert_eq!(b.result_path(), "/res.php");
        assert!(b.uses_legacy_form_protocol());

        // JSON task backends do not use the legacy form protocol
        assert!(!CaptchaBackend::CapSolver.uses_legacy_form_protocol());
        assert!(!CaptchaBackend::AntiCaptcha.uses_legacy_form_protocol());
    }

    #[test]
    fn test_new_captcha_type_task_types() {
        assert_eq!(CaptchaType::ImageCaptcha.solver_task_type(), "ImageToTextTask");
        assert_eq!(CaptchaType::GeeTest.solver_task_type(), "GeeTestTaskProxyless");
        assert_eq!(
            CaptchaType::GeeTestV4.solver_task_type(),
            "GeeTestV4TaskProxyless"
        );
        assert_eq!(CaptchaType::ImageCaptcha.solution_field(), "text");
        assert_eq!(CaptchaType::GeeTest.solution_field(), "challenge");
        assert_eq!(CaptchaType::GeeTestV4.solution_field(), "pass_token");
    }

    #[test]
    fn test_build_create_task_payload_image_captcha() {
        let config = CaptchaSolverConfig::new("key", "https://solver.example.com");
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::ImageCaptcha,
            site_key: None,
            element_selector: ".captcha-image".to_string(),
            extra: Some(serde_json::json!({
                "body": "aGVsbG8gd29ybGQ=",
                "textInstructions": "type the text"
            })),
        };

        let payload = build_create_task_payload(&config, &captcha, "https://example.com");
        assert_eq!(payload["task"]["type"], "ImageToTextTask");
        assert_eq!(payload["task"]["body"], "aGVsbG8gd29ybGQ=");
        assert_eq!(payload["task"]["textInstructions"], "type the text");
    }

    #[test]
    fn test_build_create_task_payload_geetest() {
        let config = CaptchaSolverConfig::new("key", "https://solver.example.com");
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::GeeTest,
            site_key: None,
            element_selector: ".geetest".to_string(),
            extra: Some(serde_json::json!({
                "gt": "gt-key",
                "challenge": "challenge-value",
                "captchaId": "captcha-1"
            })),
        };

        let payload = build_create_task_payload(&config, &captcha, "https://example.com");
        assert_eq!(payload["task"]["type"], "GeeTestTaskProxyless");
        assert_eq!(payload["task"]["gt"], "gt-key");
        assert_eq!(payload["task"]["challenge"], "challenge-value");
        assert_eq!(payload["task"]["captchaId"], "captcha-1");
    }

    #[test]
    fn test_inject_js_geetest() {
        let captcha = CaptchaInfo {
            captcha_type: CaptchaType::GeeTest,
            site_key: None,
            element_selector: ".geetest".to_string(),
            extra: None,
        };
        let js = build_inject_js(&captcha, "validate-token");
        assert!(js.contains("geetest_challenge"));
        assert!(js.contains("geetest_response"));
    }
}
