//! Local/non-live browser fallback planner.
//!
//! Phase 4 deliberately stops at a deterministic planning boundary. The types in
//! this module reuse the route/budget model to explain when browser fallback
//! would be needed, while proving that the default local planner does not launch
//! Chrome, open CDP, perform network I/O, capture HAR/screenshots/DOM, or touch
//! sessions/credentials.

use serde::{Deserialize, Serialize};

use super::route_model::{
    RouteDecision, RouteFieldSpec, RouteRequestPolicy, RouteTransportClass, RouteTransportPolicy,
    route,
};

/// Machine-readable schema tag for Phase 4 fallback decision reports.
pub const FALLBACK_DECISION_REPORT_SCHEMA_VERSION: &str =
    "tallow.browser_fallback_decision_report.v1";

/// Requested browser fallback mode from a target/request plan.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFallbackMode {
    /// Never consider browser fallback.
    Never,
    /// Consider browser fallback only when route/reason metadata requires it.
    Reasoned,
    /// Always plan the browser tier, while still not executing it locally.
    Always,
}

impl Default for BrowserFallbackMode {
    fn default() -> Self {
        Self::Never
    }
}

/// Artifact policy values consumed as planning data only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrowserFallbackArtifactPolicy {
    pub capture_body: bool,
    pub screenshots: bool,
    pub har: bool,
    pub dom_snapshot: bool,
    pub response_snippet_bytes: u32,
}

impl Default for BrowserFallbackArtifactPolicy {
    fn default() -> Self {
        Self {
            capture_body: false,
            screenshots: false,
            har: false,
            dom_snapshot: false,
            response_snippet_bytes: 0,
        }
    }
}

/// Planner input. This is intentionally plain data and safe to construct in
/// tests without opening a browser or network socket.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BrowserFallbackRequest {
    pub target_id: String,
    pub url: String,
    pub mode: BrowserFallbackMode,
    pub reasons: Vec<String>,
    pub target_fields: Vec<RouteFieldSpec>,
    pub route_policy: RouteRequestPolicy,
    pub artifact_policy: BrowserFallbackArtifactPolicy,
    pub transport_policy: RouteTransportPolicy,
    pub live_execution_allowed: bool,
    pub artifact_capture_allowed: bool,
}

impl Default for BrowserFallbackRequest {
    fn default() -> Self {
        Self {
            target_id: String::new(),
            url: String::new(),
            mode: BrowserFallbackMode::Never,
            reasons: Vec::new(),
            target_fields: Vec::new(),
            route_policy: RouteRequestPolicy::default(),
            artifact_policy: BrowserFallbackArtifactPolicy::default(),
            transport_policy: RouteTransportPolicy::WebSocketOnly,
            live_execution_allowed: false,
            artifact_capture_allowed: false,
        }
    }
}

/// Phase 4 planner result status.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrowserFallbackStatus {
    /// Browser fallback was planned locally but not executed.
    PlannedFailClosed,
    /// A policy/human-gate refusal blocked browser fallback.
    BlockedByPolicy,
    /// Budget guardrails blocked browser fallback.
    BlockedByBudget,
    /// The request stays on HTTP/non-browser transports.
    HttpOnly,
}

impl BrowserFallbackStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlannedFailClosed => "planned_fail_closed",
            Self::BlockedByPolicy => "blocked_by_policy",
            Self::BlockedByBudget => "blocked_by_budget",
            Self::HttpOnly => "http_only",
        }
    }
}

/// Artifact-policy hook emitted by the planner. Hooks describe what would be
/// captured by a future approved executor, not captured bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserFallbackArtifactHook {
    pub artifact: String,
    pub requested: bool,
    pub status: String,
    pub reason: String,
}

/// Non-live fallback planning decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserFallbackDecision {
    pub target_id: String,
    pub url: String,
    pub status: BrowserFallbackStatus,
    pub status_code: String,
    pub browser_required: bool,
    pub route: RouteDecision,
    pub reason_codes: Vec<String>,
    pub cdp_transport_policy: String,
    pub pipe_status: String,
    pub artifact_hooks: Vec<BrowserFallbackArtifactHook>,
    pub budget_within_cap: bool,
    pub would_launch_browser: bool,
    pub performed_network_io: bool,
    pub captured_artifacts: bool,
    pub claims_live_browser_ready: bool,
    pub claims_production_fallback_ready: bool,
}

/// Stateless local planner.
#[derive(Debug, Clone, Default)]
pub struct BrowserFallbackPlanner;

impl BrowserFallbackPlanner {
    /// Plan browser fallback locally without executing browser/network/capture
    /// side effects.
    pub fn plan(&self, request: &BrowserFallbackRequest) -> BrowserFallbackDecision {
        let route_decision = route(&request.url, &request.target_fields, &request.route_policy);
        let route_wants_browser = route_decision.transport == RouteTransportClass::T4Browser;
        let reasoned_browser = request.mode == BrowserFallbackMode::Reasoned
            && (!request.reasons.is_empty() || route_wants_browser);
        let browser_required = match request.mode {
            BrowserFallbackMode::Never => false,
            BrowserFallbackMode::Reasoned => reasoned_browser,
            BrowserFallbackMode::Always => true,
        };
        let browser_would_be_required = route_wants_browser || !request.reasons.is_empty();
        let pipe_requested = matches!(
            request.transport_policy,
            RouteTransportPolicy::PreferPipe | RouteTransportPolicy::PipeOnly
        );
        let budget_refused = browser_required && !route_decision.budget_within_cap;

        let mut reason_codes = Vec::new();
        reason_codes.push(format!(
            "route_{}",
            normalize_reason_code(&route_decision.reason)
        ));
        for reason in &request.reasons {
            reason_codes.push(format!(
                "browser_fallback_reason_{}",
                normalize_reason_code(reason)
            ));
        }

        if request.mode == BrowserFallbackMode::Never && browser_would_be_required {
            reason_codes.push("browser_fallback_mode_never".to_string());
        }
        if pipe_requested {
            reason_codes.push("cdp_pipe_unsupported_fail_closed".to_string());
        }
        if budget_refused {
            reason_codes.push(route_decision.budget_guardrail.clone());
        }
        if browser_required && !request.live_execution_allowed {
            reason_codes.push("browser_launch_blocked_by_local_non_live_policy".to_string());
        } else if browser_required {
            reason_codes.push("browser_launch_not_executed_by_phase4_planner".to_string());
        }

        let status = if request.mode == BrowserFallbackMode::Never && browser_would_be_required {
            BrowserFallbackStatus::BlockedByPolicy
        } else if pipe_requested {
            BrowserFallbackStatus::BlockedByPolicy
        } else if budget_refused {
            BrowserFallbackStatus::BlockedByBudget
        } else if browser_required {
            BrowserFallbackStatus::PlannedFailClosed
        } else {
            BrowserFallbackStatus::HttpOnly
        };

        BrowserFallbackDecision {
            target_id: request.target_id.clone(),
            url: request.url.clone(),
            status,
            status_code: status.as_str().to_string(),
            browser_required,
            route: route_decision.clone(),
            reason_codes: dedupe(reason_codes),
            cdp_transport_policy: transport_policy_label(request.transport_policy).to_string(),
            pipe_status: "unsupported_fail_closed".to_string(),
            artifact_hooks: artifact_hooks(
                &request.artifact_policy,
                request.artifact_capture_allowed,
            ),
            budget_within_cap: route_decision.budget_within_cap,
            would_launch_browser: false,
            performed_network_io: false,
            captured_artifacts: false,
            claims_live_browser_ready: false,
            claims_production_fallback_ready: false,
        }
    }
}

/// Metrics aggregated over a local decision report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserFallbackMetrics {
    pub total_decisions: usize,
    pub planned_fail_closed: usize,
    pub blocked_by_policy: usize,
    pub blocked_by_budget: usize,
    pub http_only: usize,
    pub live_launch_refusals: usize,
    pub budget_refusals: usize,
    pub pipe_refusals: usize,
    pub artifact_capture_refusals: usize,
    pub performed_network_io: usize,
    pub captured_artifacts: usize,
}

/// Report non-claims carried with Phase 4 artifacts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserFallbackNonClaims {
    pub live_browser_ready: bool,
    pub production_fallback_ready: bool,
    pub live_scraping: bool,
    pub screenshots_har_dom_capture: bool,
    pub credentialed_sessions: bool,
    pub windows_support: bool,
}

impl Default for BrowserFallbackNonClaims {
    fn default() -> Self {
        Self {
            live_browser_ready: false,
            production_fallback_ready: false,
            live_scraping: false,
            screenshots_har_dom_capture: false,
            credentialed_sessions: false,
            windows_support: false,
        }
    }
}

/// Machine-readable Phase 4 local decision report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrowserFallbackDecisionReport {
    pub schema_version: String,
    pub phase: String,
    pub run_id: String,
    pub decisions: Vec<BrowserFallbackDecision>,
    pub metrics: BrowserFallbackMetrics,
    pub non_claims: BrowserFallbackNonClaims,
}

impl BrowserFallbackDecisionReport {
    pub fn from_decisions(
        run_id: impl Into<String>,
        decisions: Vec<BrowserFallbackDecision>,
    ) -> Self {
        let metrics = BrowserFallbackMetrics::from_decisions(&decisions);
        Self {
            schema_version: FALLBACK_DECISION_REPORT_SCHEMA_VERSION.to_string(),
            phase: "phase4-browser-fallback-service".to_string(),
            run_id: run_id.into(),
            decisions,
            metrics,
            non_claims: BrowserFallbackNonClaims::default(),
        }
    }
}

impl BrowserFallbackMetrics {
    pub fn from_decisions(decisions: &[BrowserFallbackDecision]) -> Self {
        Self {
            total_decisions: decisions.len(),
            planned_fail_closed: decisions
                .iter()
                .filter(|decision| decision.status == BrowserFallbackStatus::PlannedFailClosed)
                .count(),
            blocked_by_policy: decisions
                .iter()
                .filter(|decision| decision.status == BrowserFallbackStatus::BlockedByPolicy)
                .count(),
            blocked_by_budget: decisions
                .iter()
                .filter(|decision| decision.status == BrowserFallbackStatus::BlockedByBudget)
                .count(),
            http_only: decisions
                .iter()
                .filter(|decision| decision.status == BrowserFallbackStatus::HttpOnly)
                .count(),
            live_launch_refusals: decisions
                .iter()
                .filter(|decision| {
                    decision
                        .reason_codes
                        .iter()
                        .any(|reason| reason == "browser_launch_blocked_by_local_non_live_policy")
                })
                .count(),
            budget_refusals: decisions
                .iter()
                .filter(|decision| decision.status == BrowserFallbackStatus::BlockedByBudget)
                .count(),
            pipe_refusals: decisions
                .iter()
                .filter(|decision| {
                    decision
                        .reason_codes
                        .iter()
                        .any(|reason| reason == "cdp_pipe_unsupported_fail_closed")
                })
                .count(),
            artifact_capture_refusals: decisions
                .iter()
                .map(|decision| {
                    decision
                        .artifact_hooks
                        .iter()
                        .filter(|hook| hook.status == "refused_live_capture")
                        .count()
                })
                .sum(),
            performed_network_io: decisions
                .iter()
                .filter(|decision| decision.performed_network_io)
                .count(),
            captured_artifacts: decisions
                .iter()
                .filter(|decision| decision.captured_artifacts)
                .count(),
        }
    }
}

fn artifact_hooks(
    policy: &BrowserFallbackArtifactPolicy,
    artifact_capture_allowed: bool,
) -> Vec<BrowserFallbackArtifactHook> {
    vec![
        body_hook(policy.capture_body, policy.response_snippet_bytes),
        live_capture_hook("screenshot", policy.screenshots, artifact_capture_allowed),
        live_capture_hook("har", policy.har, artifact_capture_allowed),
        live_capture_hook(
            "dom_snapshot",
            policy.dom_snapshot,
            artifact_capture_allowed,
        ),
    ]
}

fn body_hook(requested: bool, snippet_bytes: u32) -> BrowserFallbackArtifactHook {
    if requested {
        BrowserFallbackArtifactHook {
            artifact: "response_body".to_string(),
            requested,
            status: "redacted_snippet_planned_not_captured".to_string(),
            reason: format!(
                "Phase 4 planner records a policy hook only; snippet_bytes={snippet_bytes}; no response body was fetched or persisted"
            ),
        }
    } else {
        BrowserFallbackArtifactHook {
            artifact: "response_body".to_string(),
            requested,
            status: "not_requested".to_string(),
            reason: "no response body capture requested".to_string(),
        }
    }
}

fn live_capture_hook(
    artifact: &str,
    requested: bool,
    artifact_capture_allowed: bool,
) -> BrowserFallbackArtifactHook {
    let (status, reason) = if requested && artifact_capture_allowed {
        (
            "planned_not_captured",
            "capture was allowed only as planning metadata; Phase 4 still captures no live artifacts",
        )
    } else if requested {
        (
            "refused_live_capture",
            "live browser artifact capture is human-gated and not executed by the Phase 4 planner",
        )
    } else {
        ("not_requested", "artifact capture was not requested")
    };

    BrowserFallbackArtifactHook {
        artifact: artifact.to_string(),
        requested,
        status: status.to_string(),
        reason: reason.to_string(),
    }
}

fn transport_policy_label(policy: RouteTransportPolicy) -> &'static str {
    match policy {
        RouteTransportPolicy::Auto => "websocket_only_default",
        RouteTransportPolicy::PreferWebSocket => "prefer_websocket",
        RouteTransportPolicy::PreferPipe => "prefer_pipe_unsupported_fail_closed",
        RouteTransportPolicy::WebSocketOnly => "websocket_only",
        RouteTransportPolicy::PipeOnly => "pipe_only_unsupported_fail_closed",
    }
}

fn normalize_reason_code(reason: &str) -> String {
    let mut normalized = String::new();
    let mut last_was_separator = false;
    for ch in reason.chars() {
        if ch.is_ascii_alphanumeric() {
            normalized.push(ch.to_ascii_lowercase());
            last_was_separator = false;
        } else if !last_was_separator {
            normalized.push('_');
            last_was_separator = true;
        }
    }
    let trimmed = normalized.trim_matches('_');
    if trimmed.is_empty() {
        "unspecified".to_string()
    } else {
        trimmed.to_string()
    }
}

fn dedupe(values: Vec<String>) -> Vec<String> {
    let mut deduped = Vec::new();
    for value in values {
        if !deduped.contains(&value) {
            deduped.push(value);
        }
    }
    deduped
}

#[cfg(test)]
mod tests {
    use super::super::route_model::{RouteBudgetClass, RouteFieldSpec, RouteTransportClass};
    use super::*;

    #[test]
    fn planner_never_performs_live_side_effects() {
        let request = BrowserFallbackRequest {
            target_id: "unit".to_string(),
            url: "https://example.test/product".to_string(),
            mode: BrowserFallbackMode::Reasoned,
            reasons: vec!["requires_javascript".to_string()],
            target_fields: vec![RouteFieldSpec::required("raw_html")],
            route_policy: RouteRequestPolicy {
                budget_class: RouteBudgetClass::Expensive,
                preferred_transport: Some(RouteTransportClass::T4Browser),
                ..RouteRequestPolicy::default()
            },
            ..BrowserFallbackRequest::default()
        };

        let decision = BrowserFallbackPlanner.plan(&request);
        assert_eq!(decision.status, BrowserFallbackStatus::PlannedFailClosed);
        assert!(!decision.would_launch_browser);
        assert!(!decision.performed_network_io);
        assert!(!decision.captured_artifacts);
    }
}
