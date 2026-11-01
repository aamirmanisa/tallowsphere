//! Tallow Request Plan Execution Core — HTTP execution engine.
//! Provides the foundation for all HTTP-based browser operations.

pub const EXECUTION_CONTRACT_SCHEMA: &str = "tallow.request_plan_execution_contract.v1";
pub const EXECUTION_CORE_VERSION: &str = "request-plan-execution-core-v1";
pub const DEFAULT_MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;
pub const MAX_BATCH_URLS: usize = 256;
pub const MAX_BATCH_CONCURRENCY: usize = 16;

pub struct HttpExecutionOutcome {
    pub http_status: Option<u16>,
    pub body: Vec<u8>,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub duration_ms: u64,
    pub truncated: bool,
    pub error_kind: String,
    pub error_message: String,
    pub retryable: bool,
    pub success: bool,
}

pub struct ExecutionOptions {
    pub timeout: u64,
    pub max_response_bytes: usize,
    pub follow_redirects: bool,
    pub max_redirects: u32,
}

impl Default for ExecutionOptions {
    fn default() -> Self {
        ExecutionOptions {
            timeout: 30_000,
            max_response_bytes: DEFAULT_MAX_RESPONSE_BYTES,
            follow_redirects: true,
            max_redirects: 10,
        }
    }
}

pub fn classify_error_kind(http_status: Option<u16>, transport_error: bool, body_too_large: bool) -> String {
    if let Some(status) = http_status {
        if status == 429 { "rate_limited".into() }
        else if body_too_large { "body_too_large".into() }
        else if (400..500).contains(&status) { "http_4xx".into() }
        else if (500..600).contains(&status) { "http_5xx".into() }
        else { "none".into() }
    } else if transport_error {
        "transport".into()
    } else {
        "none".into()
    }
}

pub fn execute_get(url: &str, options: ExecutionOptions) -> HttpExecutionOutcome {
    let start = std::time::Instant::now();
    // Scope gate first: the register is the authorization decision, and it is
    // taken before `egress_refusal()` (a proxy contract, not a permission) and
    // before any request is built. The URL is the plan file's target as it
    // reached the executor; the verb is the one this function sends — GET.
    //
    // Returned, not fatal: the caller (`cli::request_plan_cmd` ->
    // `execute_and_record`) turns a non-success outcome into a failed row and
    // `canonical_error`, then continues the plan. Exiting here would abort a
    // multi-request run over one out-of-scope target and lose the report for
    // the requests that were in scope.
    if let Err(r) = crate::scope::require(url, "GET") {
        return HttpExecutionOutcome {
            http_status: None, body: vec![], url: url.to_string(),
            headers: vec![], duration_ms: start.elapsed().as_millis() as u64, truncated: false,
            // Same slot `egress_refusal()` uses; not retryable — a refusal is
            // a decision, not a flake.
            error_kind: classify_error_kind(None, true, false),
            error_message: format!("{} — {}", r.code(), r.explain()),
            retryable: false, success: false,
        };
    }
    // Egress contract (T-104b): a configured-but-unusable proxy is a hard
    // refusal — surface it in the outcome instead of egressing from the box
    // IP (this was the last allowlisted bare unproxied GET in the runtime
    // tree). Mirrors the interpreter fetch pre-check (interp.rs, T-104).
    if let Some(reason) = crate::runtime::egress_http::egress_refusal() {
        return HttpExecutionOutcome {
            http_status: None, body: vec![], url: url.to_string(),
            headers: vec![], duration_ms: start.elapsed().as_millis() as u64, truncated: false,
            // Same classification slot as a transport failure, with the
            // refusal string as the message; not retryable — a malformed
            // proxy cannot recover by retrying.
            error_kind: classify_error_kind(None, true, false),
            error_message: reason, retryable: false, success: false,
        };
    }
    match crate::runtime::egress_http::get(url).call()
    {
        Ok(resp) => {
            let status = Some(resp.status().as_u16());
            // Capture response headers BEFORE consuming the body.
            let headers: Vec<(String, String)> = resp
                .headers()
                .iter()
                .map(|(name, value)| {
                    (
                        name.as_str().to_string(),
                        value.to_str().unwrap_or("").to_string(),
                    )
                })
                .collect();
            let elapsed_ms = start.elapsed().as_millis() as u64;
            let body = match resp.into_body().read_to_vec() {
                Ok(b) if b.len() <= options.max_response_bytes => b,
                Ok(_) => {
                    return HttpExecutionOutcome {
                        http_status: status, body: vec![], url: url.to_string(),
                        headers, duration_ms: elapsed_ms, truncated: true,
                        error_kind: "body_too_large".into(), error_message: "Response exceeds max size".into(),
                        retryable: false, success: false,
                    };
                }
                Err(e) => {
                    return HttpExecutionOutcome {
                        http_status: status, body: vec![], url: url.to_string(),
                        headers, duration_ms: elapsed_ms, truncated: false,
                        error_kind: classify_error_kind(status, false, false),
                        error_message: format!("{e}"), retryable: true, success: false,
                    };
                }
            };
            let error_kind = classify_error_kind(status, false, false);
            let retryable = error_kind == "rate_limited" || error_kind == "http_5xx";
            HttpExecutionOutcome {
                http_status: status, body, url: url.to_string(),
                headers, duration_ms: elapsed_ms, truncated: false,
                error_kind, error_message: String::new(),
                retryable,
                success: matches!(status, Some(s) if (s as u32) < 400),
            }
        }
        Err(e) => HttpExecutionOutcome {
            http_status: None, body: vec![], url: url.to_string(),
            headers: vec![], duration_ms: start.elapsed().as_millis() as u64, truncated: false,
            error_kind: classify_error_kind(None, true, false),
            error_message: format!("{e}"), retryable: true, success: false,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::{override_register, ScopeRegister};

    /// A plan target the register does not list is refused, and the refusal
    /// comes back in the outcome (not as a process exit) because the only
    /// caller records a failed row and continues the plan.
    #[test]
    fn execute_get_refuses_an_unlisted_plan_target() {
        let _guard = override_register(ScopeRegister::granting(&[("listed.example", &["GET"])]));

        let out = execute_get("https://unlisted.example/page", ExecutionOptions::default());

        assert!(!out.success, "an unlisted target must not report success");
        assert_eq!(out.http_status, None);
        assert!(out.body.is_empty(), "a refusal has no body");
        assert!(!out.retryable, "a refusal is a decision, not a flake");
        assert!(
            out.error_message.contains("scope:not-listed"),
            "refusal must name the ground, got: {}",
            out.error_message
        );
        assert_eq!(out.url, "https://unlisted.example/page");
    }

    /// The gate is reached before `egress_refusal()` and before any socket:
    /// with an empty register the URL is refused even though a proxy is or is
    /// not configured — and the stored URL is the plan's, unmodified.
    #[test]
    fn an_empty_register_refuses_every_plan_target() {
        let _guard = override_register(ScopeRegister::empty());

        let out = execute_get("http://127.0.0.1:9/health", ExecutionOptions::default());

        assert!(!out.success);
        assert!(
            out.error_message.contains("scope:not-listed"),
            "empty register must refuse loopback too, got: {}",
            out.error_message
        );
    }
}
