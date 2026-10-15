use std::fs;
use std::path::Path;

use serde::Serialize;
use sha2::{Digest, Sha256};
use tallow::browser::fallback::{
    BrowserFallbackArtifactPolicy, BrowserFallbackDecisionReport, BrowserFallbackMode,
    BrowserFallbackPlanner, BrowserFallbackRequest, BrowserFallbackStatus,
};
use tallow::browser::route_model::{
    RouteBudgetClass, RouteFieldSpec, RouteRequestPolicy, RouteTransportClass, RouteTransportPolicy,
};

fn js_fallback_request() -> BrowserFallbackRequest {
    BrowserFallbackRequest {
        target_id: "js-product".to_string(),
        url: "https://shop.example/products/1".to_string(),
        mode: BrowserFallbackMode::Reasoned,
        reasons: vec!["requires_javascript".to_string(), "dom_state".to_string()],
        target_fields: vec![
            RouteFieldSpec::required("name"),
            RouteFieldSpec::required("price"),
            RouteFieldSpec::required("raw_html"),
        ],
        route_policy: RouteRequestPolicy {
            budget_class: RouteBudgetClass::Expensive,
            preferred_transport: Some(RouteTransportClass::T4Browser),
            ..RouteRequestPolicy::default()
        },
        artifact_policy: BrowserFallbackArtifactPolicy {
            capture_body: true,
            screenshots: true,
            har: true,
            dom_snapshot: true,
            response_snippet_bytes: 256,
        },
        transport_policy: RouteTransportPolicy::WebSocketOnly,
        live_execution_allowed: false,
        artifact_capture_allowed: false,
    }
}

#[test]
fn reasoned_fallback_is_planned_but_live_execution_stays_fail_closed() {
    let decision = BrowserFallbackPlanner::default().plan(&js_fallback_request());

    assert_eq!(decision.status, BrowserFallbackStatus::PlannedFailClosed);
    assert_eq!(decision.route.transport, RouteTransportClass::T4Browser);
    assert!(decision.browser_required);
    assert!(decision.budget_within_cap);
    assert!(!decision.would_launch_browser);
    assert!(!decision.performed_network_io);
    assert!(!decision.captured_artifacts);
    assert!(!decision.claims_live_browser_ready);
    assert!(!decision.claims_production_fallback_ready);
    assert!(
        decision
            .reason_codes
            .contains(&"browser_fallback_reason_requires_javascript".to_string())
    );
    assert!(
        decision
            .reason_codes
            .contains(&"browser_launch_blocked_by_local_non_live_policy".to_string())
    );
    assert_eq!(decision.cdp_transport_policy, "websocket_only");
    assert_eq!(decision.pipe_status, "unsupported_fail_closed");

    let screenshot = decision
        .artifact_hooks
        .iter()
        .find(|hook| hook.artifact == "screenshot")
        .expect("screenshot hook");
    assert!(screenshot.requested);
    assert_eq!(screenshot.status, "refused_live_capture");
}

#[test]
fn fallback_budget_exhaustion_is_reported_before_any_live_io() {
    let mut request = js_fallback_request();
    request.target_id = "cheap-full-capture".to_string();
    request.route_policy.budget_class = RouteBudgetClass::Cheap;

    let decision = BrowserFallbackPlanner::default().plan(&request);

    assert_eq!(decision.status, BrowserFallbackStatus::BlockedByBudget);
    assert!(!decision.budget_within_cap);
    assert!(
        decision
            .reason_codes
            .contains(&"budget_guardrail_depth_floor_exceeds_budget_cap".to_string())
    );
    assert!(!decision.would_launch_browser);
    assert!(!decision.performed_network_io);
}

#[test]
fn fallback_mode_never_blocks_browser_plan() {
    let mut request = js_fallback_request();
    request.target_id = "fallback-disabled".to_string();
    request.mode = BrowserFallbackMode::Never;

    let decision = BrowserFallbackPlanner::default().plan(&request);

    assert_eq!(decision.status, BrowserFallbackStatus::BlockedByPolicy);
    assert!(
        decision
            .reason_codes
            .contains(&"browser_fallback_mode_never".to_string())
    );
    assert!(!decision.would_launch_browser);
    assert!(!decision.performed_network_io);
}

#[test]
fn pipe_transport_preference_fails_closed() {
    let mut request = js_fallback_request();
    request.target_id = "pipe-requested".to_string();
    request.transport_policy = RouteTransportPolicy::PipeOnly;

    let decision = BrowserFallbackPlanner::default().plan(&request);

    assert_eq!(decision.status, BrowserFallbackStatus::BlockedByPolicy);
    assert!(
        decision
            .reason_codes
            .contains(&"cdp_pipe_unsupported_fail_closed".to_string())
    );
    assert_eq!(decision.pipe_status, "unsupported_fail_closed");
    assert!(!decision.would_launch_browser);
}

#[test]
fn phase4_artifact_bundle_is_generated_from_local_planner_output() {
    let planner = BrowserFallbackPlanner::default();
    let mut budget_request = js_fallback_request();
    budget_request.target_id = "cheap-full-capture".to_string();
    budget_request.route_policy.budget_class = RouteBudgetClass::Cheap;

    let report = BrowserFallbackDecisionReport::from_decisions(
        "phase4-browser-fallback-service-local-proof",
        vec![
            planner.plan(&js_fallback_request()),
            planner.plan(&budget_request),
        ],
    );

    assert_eq!(
        report.schema_version,
        "tallow.browser_fallback_decision_report.v1"
    );
    assert_eq!(report.metrics.total_decisions, 2);
    assert_eq!(report.metrics.live_launch_refusals, 2);
    assert_eq!(report.metrics.budget_refusals, 1);
    assert!(!report.non_claims.live_browser_ready);
    assert!(!report.non_claims.production_fallback_ready);

    let base = Path::new("artifacts/phase4/browser-fallback-service-local");
    fs::create_dir_all(base).expect("create phase4 artifact dir");

    let decision_report = write_json(base.join("decision-report.json"), &report);
    let metrics = write_json(base.join("metrics.json"), &report.metrics);
    let command_log = write_text(
        base.join("command-log.txt"),
        "cargo test --test browser_fallback_service -- --nocapture\n",
    );
    let readme = write_text(
        base.join("README.txt"),
        "Phase 4 local/non-live browser fallback planner proof. No browser launch, no external scraping, no HAR/screenshot/DOM capture against live targets, no credentials.\n",
    );

    let hash_checks = vec![
        decision_report.clone(),
        metrics.clone(),
        command_log.clone(),
        readme.clone(),
    ];
    let hash_checks_file = write_json(base.join("hash-checks.json"), &hash_checks);

    let manifest = serde_json::json!({
        "schema_version": "tallow.artifact_manifest.v1",
        "artifact_id": "phase4-browser-fallback-service-local-proof",
        "run_id": "phase4-browser-fallback-service-local-proof",
        "launch_id": "phase4-browser-fallback-service-local-proof",
        "target_manifest_ref": "local planner fixture in tests/browser_fallback_service.rs",
        "files": [decision_report, metrics, command_log, readme, hash_checks_file],
        "phase4_non_claims": {
            "live_browser_ready": false,
            "live_scraping": false,
            "production_fallback_ready": false,
            "screenshots_har_dom_capture": false,
            "credentialed_sessions": false,
            "windows_support": false
        },
        "replay": {
            "safe_to_replay": true,
            "requires_approval": false,
            "replay_reason": "Local/non-live planner fixture only; no network or browser process."
        },
        "redaction": {
            "status": "not_required",
            "pii_policy": "no_pii_expected",
            "notes": "Planner artifacts contain route metadata only, no response bodies, no DOM, no screenshots, no HAR, no cookies."
        },
        "retention": {
            "retention_days": 30,
            "delete_after_utc": "2026-07-13T00:00:00Z"
        }
    });
    write_json(base.join("artifact_manifest.json"), &manifest);

    let manifest_text = fs::read_to_string(base.join("artifact_manifest.json")).unwrap();
    assert!(manifest_text.contains("phase4-browser-fallback-service-local-proof"));
    assert!(!manifest_text.contains("<html"));
    assert!(!manifest_text.contains("Set-Cookie"));
}

#[derive(Clone, Debug, Serialize)]
struct FileHash {
    path: String,
    artifact_class: String,
    exists: bool,
    size_bytes: u64,
    sha256: String,
    redaction_status: String,
}

fn write_json(path: impl AsRef<Path>, value: &impl Serialize) -> FileHash {
    let path = path.as_ref();
    let bytes = serde_json::to_vec_pretty(value).expect("serialize json");
    fs::write(path, &bytes).expect("write json artifact");
    file_hash(path, artifact_class(path))
}

fn write_text(path: impl AsRef<Path>, text: &str) -> FileHash {
    let path = path.as_ref();
    fs::write(path, text).expect("write text artifact");
    file_hash(path, artifact_class(path))
}

fn file_hash(path: &Path, artifact_class: &str) -> FileHash {
    let bytes = fs::read(path).expect("read artifact");
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let digest = hasher.finalize();
    FileHash {
        path: path.to_string_lossy().replace('\\', "/"),
        artifact_class: artifact_class.to_string(),
        exists: true,
        size_bytes: bytes.len() as u64,
        sha256: digest.iter().map(|byte| format!("{byte:02x}")).collect(),
        redaction_status: "not_required".to_string(),
    }
}

fn artifact_class(path: &Path) -> &str {
    match path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or_default()
    {
        "decision-report.json" => "fallback_decision_report",
        "metrics.json" => "metrics",
        "command-log.txt" => "command_log",
        "README.txt" => "readme",
        "hash-checks.json" => "hash_checks",
        _ => "artifact",
    }
}
