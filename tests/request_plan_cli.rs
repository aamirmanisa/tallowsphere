use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::net::TcpListener;
use std::path::Path;
use std::process::Command;
use std::thread;

fn minimal_plan(url: String) -> Value {
    json!({
        "schema_version": "tallow.request_plan.v1",
        "manifest_id": "native-run-plan-cli-test",
        "request_count": 1,
        "requests": [
            {
                "index": 0,
                "target_id": "loopback_status",
                "url": url,
                "method": "GET",
                "headers": {"Accept": "application/json"},
                "browser_fallback": {"mode": "never"},
                "compliance": {
                    "source_authority": "public_web",
                    "purpose": "native_run_plan_cli_test",
                    "legal_basis": "legitimate_interest",
                    "pii_policy": "no_pii_expected",
                    "retention_days": 7,
                    "robots_mode": "strict",
                    "requires_approval": false
                }
            }
        ],
        "legacy_http_batch": {
            "compatible": true,
            "blocked_reasons": [],
            "headers": {},
            "target_urls": [url]
        },
        "status_boundary": "native run-plan CLI dry-run fixture"
    })
}

fn minimal_plan_with_method(url: String, method: &str) -> Value {
    let mut plan = minimal_plan(url);
    plan["requests"][0]["method"] = Value::String(method.to_string());
    plan
}

fn generated_tl_source(body: &str) -> String {
    format!(
        "// @generated_by(tool: \\\"tallow-test\\\", schema: \\\"tallow.generated_tl.v1\\\")\n{body}\n"
    )
}

fn minimal_source_manifest(url: String) -> Value {
    json!({
        "schema_version": "tallow.target_manifest.v2",
        "manifest_id": "operator-cli-source-manifest",
        "defaults": {
            "browser_fallback": {"mode": "never"},
            "headers": {
                "Accept": "application/json",
                "User-Agent": "TallowBot/operator-cli-test"
            }
        },
        "policy": {
            "allowlist": {
                "domains": ["127.0.0.1", "localhost"],
                "url_patterns": ["http://127.0.0.1/*", "http://localhost/*"]
            },
            "denylist": {"domains": [], "url_patterns": []},
            "rate_limits": {
                "per_domain": {
                    "127.0.0.1": {"concurrent": 1, "requests_per_minute": 60},
                    "localhost": {"concurrent": 1, "requests_per_minute": 60}
                },
                "per_ip_pool": {"default": {"concurrent": 1, "requests_per_minute": 60}}
            },
            "robots": {"mode": "strict"}
        },
        "targets": [{
            "id": "loopback_status",
            "method": "GET",
            "url": url,
            "compliance": {
                "source_authority": "owned_system",
                "purpose": "operator_cli_local_test",
                "legal_basis": "legitimate_interest",
                "pii_policy": "no_pii_expected",
                "retention_days": 1,
                "robots_mode": "strict"
            }
        }]
    })
}

fn assert_canonical_error_shape(
    error: &Value,
    expected_kind: &str,
    expected_policy_blocked: bool,
    expected_phase: &str,
) {
    assert_eq!(error["kind"], expected_kind);
    assert!(
        error["message"]
            .as_str()
            .is_some_and(|message| !message.is_empty())
    );
    assert!(error["retryable"].is_boolean());
    assert_eq!(error["policy_blocked"], expected_policy_blocked);
    assert!(error.get("source_target_id").is_some());
    assert!(error.get("url").is_some());
    assert_eq!(error["phase"], expected_phase);
}

fn minimal_plan_with_header(url: String, header_name: &str, header_value: &str) -> Value {
    let mut plan = minimal_plan(url);
    plan["requests"][0]["headers"] = json!({header_name: header_value});
    plan
}

fn write_compliance_gate_report(path: &Path, manifest_path: &Path, target_id: &str) {
    let raw = std::fs::read(manifest_path).expect("read source manifest for compliance report");
    let report = json!({
        "schema_version": "tallow.compliance_gate_report.v1",
        "generated_at_utc": "2026-06-22T00:00:00Z",
        "passed": true,
        "mode": "local_no_secret_proof",
        "network_scope": "local",
        "target_manifest": {
            "path": manifest_path.to_str().unwrap(),
            "schema_version": "tallow.target_manifest.v2",
            "manifest_id": "native-run-plan-policy-test",
            "sha256": sha256_hex(&raw),
        },
        "summary": {
            "targets_total": 1,
            "targets_with_auth_ref": 0,
            "violations_count": 0,
            "warnings_count": 0,
            "redaction_findings_total": 0,
            "retention_plans_total": 1,
        },
        "production_gate": {
            "approval_id": "",
            "legal_metadata_status": "complete",
            "redaction_status": "passed",
            "retention_status": "dry_run_only",
            "accepted_for_live_preflight": true,
            "accepted_for_live_execution": false,
            "network_io_performed": false,
            "destructive_retention_performed": false,
        },
        "legal": {
            "targets": [
                {
                    "target_id": target_id,
                    "source_authority": "public_web",
                    "purpose": "native_run_plan_cli_policy_test",
                    "legal_basis": "legitimate_interest",
                    "pii_policy": "no_pii_expected",
                    "retention_days": 7,
                    "robots_mode": "strict",
                }
            ]
        },
        "gates": [],
        "violations": [],
        "warnings": [],
        "vault": {
            "resolver": "fake_local_reference_only",
            "references_total": 0,
            "references": [],
            "no_secret_material_resolved": true,
            "secret_material_serialized": false,
            "real_vault_contacted": false,
        },
        "redaction": {
            "scanner": "test_fixture",
            "paths_scanned": [],
            "findings_total": 0,
            "findings": [],
            "raw_values_emitted": false,
        },
        "retention": {
            "dry_run": true,
            "requested_action": "dry-run",
            "destructive_action_performed": false,
            "plans": [{"target_id": target_id, "retention_days": 7, "delete_after_utc": "2026-06-29T00:00:00Z", "action": "plan_only_no_delete"}],
        },
        "non_claims": {
            "no_live_external_scraping": true,
            "no_real_secret_material": true,
            "no_real_vault_configuration": true,
            "no_destructive_retention_purge": true,
            "no_production_compliance_readiness": true,
        }
    });
    std::fs::write(path, serde_json::to_string_pretty(&report).unwrap())
        .expect("write compliance gate report");
}

fn minimal_plan_with_auth_ref(url: String, auth_ref: &str) -> Value {
    let mut plan = minimal_plan(url);
    plan["requests"][0]["auth_ref"] = Value::String(auth_ref.to_string());
    plan
}

fn minimal_plan_with_browser_fallback(url: String, mode: &str) -> Value {
    let mut plan = minimal_plan(url);
    plan["requests"][0]["browser_fallback"] = json!({
        "mode": mode,
        "reasons": ["requires_javascript"],
        "transport": "websocket_cdp",
        "budget": {"max_pages": 1, "max_seconds": 15},
        "challenge_policy": "classify_and_stop"
    });
    plan["requests"][0]["artifact_policy"] = json!({
        "capture_body": "redacted",
        "screenshots": "on_challenge",
        "har": "on_challenge",
        "dom": "on_challenge"
    });
    plan
}

fn minimal_plan_with_browser_artifacts(url: String) -> Value {
    let mut plan = minimal_plan(url);
    plan["requests"][0]["artifact_policy"] = json!({
        "capture_body": "redacted",
        "screenshots": "never",
        "har": "never",
        "dom": true
    });
    plan
}

fn minimal_plan_with_malformed_browser_fields(url: String) -> Value {
    let mut plan = minimal_plan(url);
    plan["requests"][0]["browser_fallback"] = json!({"mode": true});
    plan["requests"][0]["artifact_policy"] = Value::Bool(true);
    plan
}

fn minimal_post_plan(url: String) -> Value {
    let mut plan = minimal_plan_with_method(url, "POST");
    plan["requests"][0]["headers"] = json!({
        "Accept": "application/json",
        "Content-Type": "application/json"
    });
    plan["requests"][0]["body"] = json!({
        "kind": "json",
        "content_type": "application/json",
        "value": {"ok": true}
    });
    plan
}

fn sha256_hex(raw: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(raw);
    format!("{:x}", hasher.finalize())
}

fn attach_source_manifest(mut plan: Value, manifest_path: &Path) -> Value {
    let raw = std::fs::read(manifest_path).expect("read source manifest");
    plan["source_manifest"] = json!({
        "path": manifest_path.to_str().unwrap(),
        "sha256": sha256_hex(&raw),
        "schema_version": "tallow.target_manifest.v2"
    });
    plan
}

fn spawn_one_request_server_with_body(body: &'static [u8]) -> (String, thread::JoinHandle<usize>) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback server");
    let url = format!(
        "http://127.0.0.1:{}/status",
        listener.local_addr().unwrap().port()
    );
    let handle = thread::spawn(move || {
        let (mut stream, _addr) = listener.accept().expect("accept one request");
        let mut buffer = [0_u8; 1024];
        let read = stream.read(&mut buffer).unwrap_or(0);
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(body);
        stream.write_all(&response).expect("write response");
        read
    });
    (url, handle)
}

fn spawn_one_request_json_server() -> (String, thread::JoinHandle<usize>) {
    spawn_one_request_server_with_body(b"{\"ok\":true}")
}

fn spawn_one_request_empty_server() -> (String, thread::JoinHandle<usize>) {
    spawn_one_request_server_with_body(b"")
}

fn policy_manifest(url: &str, deny_patterns: Vec<&str>) -> Value {
    let host = url::Url::parse(url)
        .expect("test url parses")
        .host_str()
        .expect("test url has host")
        .to_string();
    json!({
        "schema_version": "tallow.target_manifest.v2",
        "manifest_id": "native-run-plan-policy-test",
        "targets": [
            {
                "id": "loopback_status",
                "url": url,
                "method": "GET",
                "headers": {},
                "compliance": {
                    "source_authority": "public_web",
                    "purpose": "native_run_plan_cli_policy_test",
                    "legal_basis": "legitimate_interest",
                    "pii_policy": "no_pii_expected",
                    "retention_days": 7,
                    "robots_mode": "strict",
                    "requires_approval": false
                }
            }
        ],
        "policy": {
            "allowlist": {"domains": [host], "url_patterns": [format!("{}/*", url.rsplit_once('/').map(|(base, _)| base).unwrap_or(url))]},
            "denylist": {"domains": [], "url_patterns": deny_patterns},
            "robots": {"mode": "strict"},
            "rate_limits": {"per_domain": {host: {"requests_per_minute": 60, "concurrent": 1}}}
        }
    })
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_without_explicit_approval_is_blocked_before_network() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/status",
        listener.local_addr().unwrap().port()
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("live-no-approval.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let compliance_report_path = temp.path().join("compliance_audit_report.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(minimal_plan(url), &manifest_path);
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");
    write_compliance_gate_report(&compliance_report_path, &manifest_path, "loopback_status");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live",
            "--compliance-gate-report",
            compliance_report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["passed"], false);
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "blocked");
    assert_eq!(
        report["requests"][0]["blocked_reasons"][0]["code"],
        "live_approval_required"
    );
    assert_canonical_error_shape(
        &report["requests"][0]["error"],
        "robots_policy",
        true,
        "request_policy",
    );
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => panic!("live approval gate unexpectedly opened connection from {addr}"),
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_preflight_requires_compliance_gate_report_before_network() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/status",
        listener.local_addr().unwrap().port()
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp
        .path()
        .join("live-preflight-missing-compliance-gate.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(minimal_plan(url), &manifest_path);
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live-preflight",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["passed"], false);
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "blocked");
    let codes: Vec<String> = report["requests"][0]["blocked_reasons"]
        .as_array()
        .expect("blocked reasons")
        .iter()
        .map(|reason| reason["code"].as_str().unwrap_or_default().to_string())
        .collect();
    assert!(
        codes
            .iter()
            .any(|code| code == "compliance_gate_report_required"),
        "expected compliance_gate_report_required in {codes:?}"
    );
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => panic!("compliance gate unexpectedly opened connection from {addr}"),
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_approved_requires_compliance_gate_report_before_network() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/status",
        listener.local_addr().unwrap().port()
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp
        .path()
        .join("live-missing-compliance-gate.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(minimal_plan(url), &manifest_path);
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live",
            "--approve-live",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "blocked");
    let reason_codes: Vec<&str> = report["requests"][0]["blocked_reasons"]
        .as_array()
        .expect("blocked reasons")
        .iter()
        .filter_map(|reason| reason["code"].as_str())
        .collect();
    assert!(reason_codes.contains(&"compliance_gate_report_required"));
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => panic!(
            "approved live missing compliance gate unexpectedly opened connection from {addr}"
        ),
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_approved_rejects_compliance_report_missing_manifest_sha_before_network() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/status",
        listener.local_addr().unwrap().port()
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp
        .path()
        .join("live-missing-compliance-sha.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let compliance_report_path = temp.path().join("compliance_audit_report.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(minimal_plan(url), &manifest_path);
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");
    write_compliance_gate_report(&compliance_report_path, &manifest_path, "loopback_status");
    let mut compliance_report: Value =
        serde_json::from_str(&std::fs::read_to_string(&compliance_report_path).unwrap()).unwrap();
    compliance_report
        .as_object_mut()
        .expect("compliance report object")
        .remove("target_manifest");
    std::fs::write(
        &compliance_report_path,
        serde_json::to_string_pretty(&compliance_report).unwrap(),
    )
    .expect("write incomplete compliance report");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live",
            "--approve-live",
            "--compliance-gate-report",
            compliance_report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "blocked");
    let reason_codes: Vec<&str> = report["requests"][0]["blocked_reasons"]
        .as_array()
        .expect("blocked reasons")
        .iter()
        .filter_map(|reason| reason["code"].as_str())
        .collect();
    assert!(reason_codes.contains(&"compliance_gate_report_invalid"));
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => panic!(
            "missing compliance target manifest sha unexpectedly opened connection from {addr}"
        ),
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_approved_blocks_literal_sensitive_headers_before_network() {
    let (url, handle) = spawn_one_request_json_server();
    let literal_auth_header = "Bearer p1-010-canary-literal";
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp
        .path()
        .join("live-literal-sensitive-header.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let compliance_report_path = temp.path().join("compliance_audit_report.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(
        minimal_plan_with_header(url, "Authorization", literal_auth_header),
        &manifest_path,
    );
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");
    write_compliance_gate_report(&compliance_report_path, &manifest_path, "loopback_status");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live",
            "--approve-live",
            "--compliance-gate-report",
            compliance_report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains(literal_auth_header));
    assert!(!stderr.contains(literal_auth_header));
    assert!(
        !handle.is_finished(),
        "literal sensitive header gate must block before network I/O"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "blocked");
    let reason_codes: Vec<&str> = report["requests"][0]["blocked_reasons"]
        .as_array()
        .expect("blocked reasons")
        .iter()
        .filter_map(|reason| reason["code"].as_str())
        .collect();
    assert!(reason_codes.contains(&"sensitive_header"));
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_approved_blocks_token_like_literal_headers_before_network() {
    let (url, handle) = spawn_one_request_json_server();
    let literal_token_header = "phase2-access-token-canary";
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp
        .path()
        .join("live-token-like-header.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let compliance_report_path = temp.path().join("compliance_audit_report.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(
        minimal_plan_with_header(url, "X-Access-Token", literal_token_header),
        &manifest_path,
    );
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");
    write_compliance_gate_report(&compliance_report_path, &manifest_path, "loopback_status");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live",
            "--approve-live",
            "--compliance-gate-report",
            compliance_report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stdout.contains(literal_token_header));
    assert!(!stderr.contains(literal_token_header));
    assert!(
        !handle.is_finished(),
        "token-like header gate must block before network I/O"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["summary"]["executed"], 0);
    let reason_codes: Vec<&str> = report["requests"][0]["blocked_reasons"]
        .as_array()
        .expect("blocked reasons")
        .iter()
        .filter_map(|reason| reason["code"].as_str())
        .collect();
    assert!(reason_codes.contains(&"sensitive_header"));
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_approved_requires_isolated_output_dir_before_network() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/status",
        listener.local_addr().unwrap().port()
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("live-dirty-output.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let compliance_report_path = temp.path().join("compliance_audit_report.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::create_dir_all(&output_dir).expect("create output dir");
    std::fs::write(output_dir.join("old-artifact.json"), "{}").expect("seed output dir");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(minimal_plan(url), &manifest_path);
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");
    write_compliance_gate_report(&compliance_report_path, &manifest_path, "loopback_status");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live",
            "--approve-live",
            "--compliance-gate-report",
            compliance_report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(
        report["requests"][0]["blocked_reasons"][0]["code"],
        "live_output_dir_not_isolated"
    );
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => panic!("live output gate unexpectedly opened connection from {addr}"),
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_approved_executes_loopback_after_policy_gates() {
    let (url, handle) = spawn_one_request_json_server();
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("live-approved.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let compliance_report_path = temp.path().join("compliance_audit_report.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(minimal_plan(url), &manifest_path);
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");
    write_compliance_gate_report(&compliance_report_path, &manifest_path, "loopback_status");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live",
            "--approve-live",
            "--compliance-gate-report",
            compliance_report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow run-plan");

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let bytes_read = handle.join().expect("server thread joins");
    assert!(
        bytes_read > 0,
        "approved live execution should hit loopback server"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["passed"], true);
    assert_eq!(report["network_scope"], "live");
    assert_eq!(report["dry_run"], false);
    assert_eq!(report["summary"]["executed"], 1);
    assert_eq!(report["summary"]["succeeded"], 1);
    assert_eq!(report["requests"][0]["status"], "succeeded");
    assert_eq!(report["requests"][0]["http_status"], 200);
    assert_eq!(report["requests"][0]["body_len"], 11);
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_approved_writes_hash_checked_artifacts() {
    let (url, handle) = spawn_one_request_json_server();
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("live-artifacts.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let compliance_report_path = temp.path().join("compliance_audit_report.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let mut plan = attach_source_manifest(minimal_plan(url), &manifest_path);
    plan["requests"][0]["body"] = Value::String("MYRAWSECRET".to_string());
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");
    write_compliance_gate_report(&compliance_report_path, &manifest_path, "loopback_status");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live",
            "--approve-live",
            "--compliance-gate-report",
            compliance_report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow run-plan");

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(handle.join().expect("server thread joins") > 0);
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    let response_body_rel = report["requests"][0]["artifacts"]["response_body"]
        .as_str()
        .expect("response body artifact path");
    let response_metadata_rel = report["requests"][0]["artifacts"]["response_metadata"]
        .as_str()
        .expect("response metadata artifact path");

    for name in [
        "artifact_manifest.json",
        "request_plan.v1.json",
        "requests.jsonl",
        "response_metadata.jsonl",
        "source_index.csv",
        "run_metrics.json",
        "compliance_report.json",
    ] {
        assert!(output_dir.join(name).exists(), "missing artifact {name}");
    }
    assert!(
        output_dir.join("responses").is_dir(),
        "missing responses/ directory"
    );
    assert!(
        output_dir.join(response_metadata_rel).exists(),
        "missing response metadata artifact"
    );
    let response_body = std::fs::read_to_string(output_dir.join(response_body_rel))
        .expect("read response body artifact");
    assert!(
        response_body.contains("<redacted:sha256:"),
        "body artifact should be redacted"
    );
    assert!(
        !response_body.contains("{\"ok\":true}"),
        "raw response body must not be written to redacted artifact"
    );
    let redacted_plan = std::fs::read_to_string(output_dir.join("request_plan.v1.json"))
        .expect("read redacted plan snapshot");
    assert!(
        redacted_plan.contains("<redacted:sha256:"),
        "plan snapshot should include redaction marker"
    );
    assert!(
        !redacted_plan.contains("MYRAWSECRET"),
        "request body-like values must not be written raw to plan snapshot"
    );

    let manifest: Value = serde_json::from_str(
        &std::fs::read_to_string(output_dir.join("artifact_manifest.json")).unwrap(),
    )
    .expect("artifact manifest JSON");
    assert_eq!(manifest["schema_version"], "tallow.artifact_manifest.v1");
    let files = manifest["files"].as_array().expect("manifest files array");
    let paths: Vec<&str> = files
        .iter()
        .filter_map(|entry| entry["path"].as_str())
        .collect();
    for expected in [
        "request_plan.v1.json",
        "requests.jsonl",
        "response_metadata.jsonl",
        "source_index.csv",
        "run_metrics.json",
        "compliance_report.json",
        response_body_rel,
        response_metadata_rel,
    ] {
        assert!(paths.contains(&expected), "manifest missing {expected}");
    }
    for entry in files {
        let rel = entry["path"].as_str().expect("manifest path");
        let bytes = std::fs::read(output_dir.join(rel)).expect("manifest file exists");
        assert_eq!(entry["size_bytes"], bytes.len() as u64);
        assert_eq!(entry["sha256"], sha256_hex(&bytes));
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_approved_hash_redacts_empty_response_body_artifact() {
    let (url, handle) = spawn_one_request_empty_server();
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("live-empty-response.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let compliance_report_path = temp.path().join("compliance_audit_report.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(minimal_plan(url), &manifest_path);
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");
    write_compliance_gate_report(&compliance_report_path, &manifest_path, "loopback_status");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live",
            "--approve-live",
            "--compliance-gate-report",
            compliance_report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow run-plan");

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(handle.join().expect("server thread joins") > 0);
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["requests"][0]["body_len"], 0);
    let response_body_rel = report["requests"][0]["artifacts"]["response_body"]
        .as_str()
        .expect("response body artifact path");
    let response_body = std::fs::read_to_string(output_dir.join(response_body_rel))
        .expect("read response body artifact");
    assert_eq!(
        response_body.trim(),
        format!("<redacted:sha256:{}>", sha256_hex(b"")),
        "empty response bodies should still be represented by a hash redaction marker"
    );
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_preflight_emits_non_claims_without_network() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/status",
        listener.local_addr().unwrap().port()
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("live-preflight.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let compliance_report_path = temp.path().join("compliance_audit_report.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(minimal_plan(url), &manifest_path);
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");
    write_compliance_gate_report(&compliance_report_path, &manifest_path, "loopback_status");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live-preflight",
            "--compliance-gate-report",
            compliance_report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow run-plan");

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "policy_preflight_passed");
    assert_eq!(report["non_claims"]["live_external_scraping"], false);
    assert_eq!(report["non_claims"]["browser_execution"], false);
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => panic!("live-preflight unexpectedly opened connection from {addr}"),
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_preflight_accepts_fake_local_auth_ref_as_redacted_metadata() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/status",
        listener.local_addr().unwrap().port()
    );
    let raw_auth_ref = "vault://local/p1-009-demo-reference";
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp
        .path()
        .join("live-preflight-local-vault.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let compliance_report_path = temp.path().join("compliance_audit_report.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(
        minimal_plan_with_auth_ref(url, raw_auth_ref),
        &manifest_path,
    );
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");
    write_compliance_gate_report(&compliance_report_path, &manifest_path, "loopback_status");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live-preflight",
            "--compliance-gate-report",
            compliance_report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow run-plan");

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        !report_text.contains(raw_auth_ref),
        "raw auth_ref must not be serialized"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["passed"], true);
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["vault_resolution"]["references_total"], 1);
    assert_eq!(
        report["vault_resolution"]["secret_material_serialized"],
        false
    );
    assert_eq!(report["vault_resolution"]["auth_ref_serialized"], false);
    assert_eq!(report["vault_resolution"]["real_vault_contacted"], false);
    let reference = &report["vault_resolution"]["references"][0];
    assert_eq!(reference["provider_id"], "local");
    assert_eq!(reference["resolution_status"], "accepted_local_reference");
    assert_eq!(
        reference["reference_hash"],
        sha256_hex(raw_auth_ref.as_bytes())
    );
    assert_eq!(reference["secret_material_serialized"], false);
    assert_eq!(reference["auth_ref_serialized"], false);
    assert_eq!(reference["real_vault_contacted"], false);
    assert_eq!(report["requests"][0]["auth_ref_present"], true);
    assert_eq!(
        report["requests"][0]["vault_reference"]["reference_hash"],
        sha256_hex(raw_auth_ref.as_bytes())
    );
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => {
            panic!("live-preflight local auth_ref unexpectedly opened connection from {addr}")
        }
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_approved_blocks_real_vault_auth_ref_before_network_without_raw_ref() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/status",
        listener.local_addr().unwrap().port()
    );
    let raw_auth_ref = "vault://aws-sm/prod/p1-009-canary-reference";
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("live-real-vault.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let compliance_report_path = temp.path().join("compliance_audit_report.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(
        minimal_plan_with_auth_ref(url, raw_auth_ref),
        &manifest_path,
    );
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");
    write_compliance_gate_report(&compliance_report_path, &manifest_path, "loopback_status");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live",
            "--approve-live",
            "--compliance-gate-report",
            compliance_report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report_text = String::from_utf8_lossy(&output.stdout);
    assert!(
        !report_text.contains(raw_auth_ref),
        "raw auth_ref must not be serialized"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["passed"], false);
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "blocked");
    let reason_codes: Vec<&str> = report["requests"][0]["blocked_reasons"]
        .as_array()
        .expect("blocked reasons")
        .iter()
        .filter_map(|reason| reason["code"].as_str())
        .collect();
    assert!(reason_codes.contains(&"unsupported_vault_provider"));
    assert_eq!(
        report["vault_resolution"]["secret_material_serialized"],
        false
    );
    assert_eq!(report["vault_resolution"]["auth_ref_serialized"], false);
    assert_eq!(report["vault_resolution"]["real_vault_contacted"], false);
    let reference = &report["vault_resolution"]["references"][0];
    assert_eq!(reference["provider_id"], "aws-sm");
    assert_eq!(
        reference["resolution_status"],
        "unsupported_provider_fail_closed"
    );
    assert_eq!(
        reference["reference_hash"],
        sha256_hex(raw_auth_ref.as_bytes())
    );
    assert_eq!(reference["secret_material_serialized"], false);
    assert_eq!(reference["auth_ref_serialized"], false);
    assert_eq!(reference["real_vault_contacted"], false);
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => panic!("real vault auth_ref unexpectedly opened connection from {addr}"),
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_preflight_blocks_reasoned_browser_fallback_without_network() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/browser",
        listener.local_addr().unwrap().port()
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp
        .path()
        .join("live-preflight-browser.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(
        minimal_plan_with_browser_fallback(url, "reasoned"),
        &manifest_path,
    );
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live-preflight",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "blocked");
    let reason_codes: Vec<&str> = report["requests"][0]["blocked_reasons"]
        .as_array()
        .expect("blocked reasons")
        .iter()
        .filter_map(|reason| reason["code"].as_str())
        .collect();
    assert!(reason_codes.contains(&"live_browser_fallback_not_enabled"));
    assert!(reason_codes.contains(&"browser_artifact_capture_not_enabled"));
    assert_eq!(report["non_claims"]["browser_execution"], false);
    assert_eq!(report["browser_fallback"]["pipe_transport"], "fail_closed");
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => {
            panic!("live-preflight browser fallback unexpectedly opened connection from {addr}")
        }
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_approved_blocks_reasoned_browser_fallback_before_network() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/browser",
        listener.local_addr().unwrap().port()
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("live-browser.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let compliance_report_path = temp.path().join("compliance_audit_report.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(
        minimal_plan_with_browser_fallback(url, "reasoned"),
        &manifest_path,
    );
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");
    write_compliance_gate_report(&compliance_report_path, &manifest_path, "loopback_status");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live",
            "--approve-live",
            "--compliance-gate-report",
            compliance_report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "blocked");
    assert_eq!(report["non_claims"]["browser_execution"], false);
    assert_eq!(
        report["browser_fallback"]["websocket_cdp"],
        "not_implemented"
    );
    let reason_codes: Vec<&str> = report["requests"][0]["blocked_reasons"]
        .as_array()
        .expect("blocked reasons")
        .iter()
        .filter_map(|reason| reason["code"].as_str())
        .collect();
    assert!(reason_codes.contains(&"live_browser_fallback_not_enabled"));
    assert!(reason_codes.contains(&"browser_artifact_capture_not_enabled"));
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => {
            panic!("approved live browser fallback unexpectedly opened connection from {addr}")
        }
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_preflight_blocks_browser_artifact_capture_without_fallback() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/artifact",
        listener.local_addr().unwrap().port()
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp
        .path()
        .join("live-preflight-browser-artifact.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(minimal_plan_with_browser_artifacts(url), &manifest_path);
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live-preflight",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "blocked");
    let reason_codes: Vec<&str> = report["requests"][0]["blocked_reasons"]
        .as_array()
        .expect("blocked reasons")
        .iter()
        .filter_map(|reason| reason["code"].as_str())
        .collect();
    assert!(reason_codes.contains(&"browser_artifact_capture_not_enabled"));
    assert!(!reason_codes.contains(&"live_browser_fallback_not_enabled"));
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => {
            panic!("browser artifact preflight unexpectedly opened connection from {addr}")
        }
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_preflight_blocks_malformed_browser_fields() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/malformed-browser",
        listener.local_addr().unwrap().port()
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp
        .path()
        .join("live-preflight-malformed-browser.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(
        minimal_plan_with_malformed_browser_fields(url),
        &manifest_path,
    );
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live-preflight",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "blocked");
    let reason_codes: Vec<&str> = report["requests"][0]["blocked_reasons"]
        .as_array()
        .expect("blocked reasons")
        .iter()
        .filter_map(|reason| reason["code"].as_str())
        .collect();
    assert!(reason_codes.contains(&"invalid_browser_fallback"));
    assert!(reason_codes.contains(&"invalid_artifact_policy"));
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => {
            panic!("malformed browser fields unexpectedly opened connection from {addr}")
        }
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_preflight_rejects_post_until_native_live_support() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/graphql",
        listener.local_addr().unwrap().port()
    );
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("live-preflight-post.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(&url, vec![])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(minimal_post_plan(url), &manifest_path);
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live-preflight",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "blocked");
    assert_eq!(
        report["requests"][0]["blocked_reasons"][0]["code"],
        "live_method_not_enabled"
    );
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => panic!("live-preflight POST unexpectedly opened connection from {addr}"),
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_preflight_denied_manifest_url_is_blocked() {
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("policy-denied.request-plan.v1.json");
    let manifest_path = temp.path().join("source.target-manifest.v2.json");
    let output_dir = temp.path().join("run-artifacts");
    let url = "https://example.com/status";
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&policy_manifest(url, vec![url])).unwrap(),
    )
    .expect("write source manifest");
    let plan = attach_source_manifest(minimal_plan(url.to_string()), &manifest_path);
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live-preflight",
            "--dry-run",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["passed"], false);
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["summary"]["blocked"], 1);
    assert_eq!(report["requests"][0]["status"], "blocked");
    assert_eq!(
        report["requests"][0]["blocked_reasons"][0]["code"],
        "policy_denylist"
    );
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_attached_missing_source_manifest_is_blocked() {
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("missing-manifest.request-plan.v1.json");
    let output_dir = temp.path().join("run-artifacts");
    let missing_manifest = temp.path().join("missing.target-manifest.v2.json");
    let mut plan = minimal_plan("https://example.com/status".to_string());
    plan["source_manifest"] = json!({
        "path": missing_manifest.to_str().unwrap(),
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "schema_version": "tallow.target_manifest.v2"
    });
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "local",
            "--dry-run",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["passed"], false);
    assert_eq!(report["summary"]["blocked"], 1);
    assert_eq!(report["requests"][0]["status"], "blocked");
    assert_eq!(
        report["requests"][0]["blocked_reasons"][0]["code"],
        "source_manifest_missing"
    );
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_attached_directory_source_manifest_is_blocked() {
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("directory-manifest.request-plan.v1.json");
    let output_dir = temp.path().join("run-artifacts");
    let mut plan = minimal_plan("https://example.com/status".to_string());
    plan["source_manifest"] = json!({
        "path": temp.path().to_str().unwrap(),
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "schema_version": "tallow.target_manifest.v2"
    });
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "local",
            "--dry-run",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["passed"], false);
    assert_eq!(report["summary"]["blocked"], 1);
    assert_eq!(report["requests"][0]["status"], "blocked");
    assert_eq!(
        report["requests"][0]["blocked_reasons"][0]["code"],
        "source_manifest_invalid"
    );
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_attached_invalid_json_source_manifest_is_blocked() {
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp
        .path()
        .join("invalid-json-manifest.request-plan.v1.json");
    let manifest_path = temp.path().join("invalid.target-manifest.v2.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(&manifest_path, "{not json").expect("write invalid source manifest");
    let plan = attach_source_manifest(
        minimal_plan("https://example.com/status".to_string()),
        &manifest_path,
    );
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "local",
            "--dry-run",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["passed"], false);
    assert_eq!(report["summary"]["blocked"], 1);
    assert_eq!(
        report["requests"][0]["blocked_reasons"][0]["code"],
        "source_manifest_invalid"
    );
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_plan_level_source_manifest_block_applies_to_every_request() {
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp
        .path()
        .join("multi-missing-manifest.request-plan.v1.json");
    let output_dir = temp.path().join("run-artifacts");
    let missing_manifest = temp.path().join("missing.target-manifest.v2.json");
    let mut plan = minimal_plan("https://example.com/status".to_string());
    let second = json!({
        "index": 1,
        "target_id": "loopback_other",
        "url": "https://example.com/other",
        "method": "GET",
        "headers": {"Accept": "application/json"},
        "browser_fallback": {"mode": "never"},
        "compliance": {
            "source_authority": "public_web",
            "purpose": "native_run_plan_cli_test",
            "legal_basis": "legitimate_interest",
            "pii_policy": "no_pii_expected",
            "retention_days": 7,
            "robots_mode": "strict",
            "requires_approval": false
        }
    });
    plan["request_count"] = json!(2);
    plan["requests"].as_array_mut().unwrap().push(second);
    plan["legacy_http_batch"]["target_urls"] =
        json!(["https://example.com/status", "https://example.com/other"]);
    plan["source_manifest"] = json!({
        "path": missing_manifest.to_str().unwrap(),
        "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
        "schema_version": "tallow.target_manifest.v2"
    });
    std::fs::write(&plan_path, serde_json::to_string_pretty(&plan).unwrap()).expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "local",
            "--dry-run",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["summary"]["blocked"], 2);
    assert_eq!(report["requests"][0]["status"], "blocked");
    assert_eq!(report["requests"][1]["status"], "blocked");
    assert_eq!(
        report["requests"][0]["blocked_reasons"][0]["code"],
        "source_manifest_missing"
    );
    assert_eq!(
        report["requests"][1]["blocked_reasons"][0]["code"],
        "source_manifest_missing"
    );
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_dry_run_rejects_non_http_urls() {
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("file-url.request-plan.v1.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &plan_path,
        serde_json::to_string_pretty(&minimal_plan("file:///etc/passwd".to_string())).unwrap(),
    )
    .expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "local",
            "--dry-run",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["passed"], false);
    assert_eq!(report["summary"]["blocked"], 1);
    assert_eq!(report["requests"][0]["status"], "blocked");
    assert_eq!(report["unsupported_reasons"][0]["code"], "invalid_url");
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_live_preflight_rejects_unsupported_methods() {
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("delete.request-plan.v1.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &plan_path,
        serde_json::to_string_pretty(&minimal_plan_with_method(
            "https://example.com/status".to_string(),
            "DELETE",
        ))
        .unwrap(),
    )
    .expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "live-preflight",
            "--dry-run",
        ])
        .output()
        .expect("run tallow run-plan");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["passed"], false);
    assert_eq!(report["summary"]["blocked"], 1);
    assert_eq!(report["requests"][0]["status"], "blocked");
    assert_eq!(
        report["unsupported_reasons"][0]["code"],
        "unsupported_method"
    );
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_dry_run_local_accepts_external_plan_without_network() {
    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("external.request-plan.v1.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &plan_path,
        serde_json::to_string_pretty(&minimal_plan("https://example.com/status".to_string()))
            .unwrap(),
    )
    .expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "local",
            "--dry-run",
        ])
        .output()
        .expect("run tallow run-plan");

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(report["passed"], true);
    assert_eq!(report["summary"]["planned"], 1);
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["summary"]["blocked"], 0);
    assert_eq!(report["requests"][0]["status"], "planned");
    assert_eq!(
        report["requests"][0]["original_url"],
        "https://example.com/status"
    );
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_dry_run_local_prints_report_and_does_not_connect() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/status",
        listener.local_addr().unwrap().port()
    );

    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("plan.request-plan.v1.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &plan_path,
        serde_json::to_string_pretty(&minimal_plan(url)).unwrap(),
    )
    .expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            "--plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "local",
            "--policy",
            "strict",
            "--dry-run",
        ])
        .output()
        .expect("run tallow run-plan");

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(
        report["schema_version"],
        "tallow.request_plan_run_report.v1"
    );
    assert_eq!(report["runner"], "tallow-native-run-plan");
    assert_eq!(report["network_scope"], "local");
    assert_eq!(report["policy"], "strict");
    assert_eq!(report["dry_run"], true);
    assert_eq!(report["passed"], true);
    assert_eq!(report["summary"]["planned"], 1);
    assert_eq!(report["summary"]["executed"], 0);
    assert_eq!(report["requests"][0]["status"], "planned");
    assert_eq!(
        report["execution_core"]["schema_version"],
        "tallow.request_plan_execution_contract.v1"
    );
    assert_eq!(
        report["execution_core"]["version"],
        "request-plan-execution-core-v1"
    );
    assert_eq!(report["execution_core"]["role"], "native_cli_bridge");

    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => panic!("dry-run unexpectedly opened a loopback connection from {addr}"),
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn operator_cli_help_lists_supported_scraper_workflow() {
    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("--help")
        .output()
        .expect("run tallow --help");
    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in [
        "doctor",
        "check",
        "run",
        "validate-manifest",
        "build-plan",
        "run-plan",
        "package-report",
    ] {
        assert!(
            stdout.contains(command),
            "missing operator command {command} in help:\n{stdout}"
        );
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn run_plan_accepts_positional_plan_path_for_operator_workflow() {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback listener");
    listener
        .set_nonblocking(true)
        .expect("set listener nonblocking");
    let url = format!(
        "http://127.0.0.1:{}/status",
        listener.local_addr().unwrap().port()
    );

    let temp = tempfile::tempdir().expect("tempdir");
    let plan_path = temp.path().join("operator.request-plan.v1.json");
    let output_dir = temp.path().join("run-artifacts");
    std::fs::write(
        &plan_path,
        serde_json::to_string_pretty(&minimal_plan(url)).unwrap(),
    )
    .expect("write plan");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "run-plan",
            plan_path.to_str().unwrap(),
            "--output-dir",
            output_dir.to_str().unwrap(),
            "--network-scope",
            "local",
            "--policy",
            "strict",
            "--dry-run",
        ])
        .output()
        .expect("run tallow run-plan positional");

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout is JSON report");
    assert_eq!(
        report["schema_version"],
        "tallow.request_plan_run_report.v1"
    );
    assert_eq!(report["summary"]["planned"], 1);
    assert_eq!(report["summary"]["executed"], 0);
    match listener.accept() {
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => {}
        Ok((_, addr)) => panic!("dry-run unexpectedly opened a loopback connection from {addr}"),
        Err(err) => panic!("unexpected listener error: {err}"),
    }
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn validate_manifest_command_writes_local_no_network_report() {
    let temp = tempfile::tempdir().expect("tempdir");
    let manifest_path = temp.path().join("source-manifest.json");
    let report_path = temp.path().join("validate-report.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&minimal_source_manifest(
            "http://127.0.0.1/status".to_string(),
        ))
        .unwrap(),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "validate-manifest",
            manifest_path.to_str().unwrap(),
            "--report-path",
            report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow validate-manifest");

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout_report: Value = serde_json::from_slice(&output.stdout).expect("stdout JSON report");
    let file_report: Value =
        serde_json::from_slice(&std::fs::read(&report_path).expect("read validation report"))
            .expect("file JSON report");
    assert_eq!(stdout_report, file_report);
    assert_eq!(
        stdout_report["schema_version"],
        "tallow.validate_manifest_report.v1"
    );
    assert_eq!(stdout_report["passed"], true);
    assert_eq!(stdout_report["summary"]["targets"], 1);
    assert_eq!(stdout_report["non_claims"]["no_network_io"], true);
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn validate_manifest_command_rejects_v2_unsafe_target_ids() {
    let temp = tempfile::tempdir().expect("tempdir");
    let manifest_path = temp.path().join("source-manifest.json");
    let mut manifest = minimal_source_manifest("http://127.0.0.1/status".to_string());
    manifest["targets"][0]["id"] = Value::String("not safe".to_string());
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).unwrap(),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["validate-manifest", manifest_path.to_str().unwrap()])
        .output()
        .expect("run tallow validate-manifest");

    assert_eq!(
        output.status.code(),
        Some(2),
        "stdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout JSON report");
    assert_eq!(
        report["schema_version"],
        "tallow.validate_manifest_report.v1"
    );
    assert_eq!(report["passed"], false);
    let errors = report["errors"].as_array().expect("errors array");
    assert!(
        errors.iter().any(|error| error
            .as_str()
            .unwrap_or("")
            .contains("targets[0].id is required and must be v2-safe")),
        "missing v2-safe id error: {errors:?}"
    );
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn build_plan_command_writes_request_plan_and_report() {
    let temp = tempfile::tempdir().expect("tempdir");
    let manifest_path = temp.path().join("source-manifest.json");
    let plan_path = temp.path().join("built.request-plan.v1.json");
    let report_path = temp.path().join("build-report.json");
    std::fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&minimal_source_manifest(
            "http://127.0.0.1/status".to_string(),
        ))
        .unwrap(),
    )
    .expect("write manifest");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "build-plan",
            manifest_path.to_str().unwrap(),
            "--output",
            plan_path.to_str().unwrap(),
            "--report-path",
            report_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow build-plan");

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let plan: Value =
        serde_json::from_slice(&std::fs::read(&plan_path).expect("read plan")).expect("plan JSON");
    let report: Value = serde_json::from_slice(&std::fs::read(&report_path).expect("read report"))
        .expect("report JSON");
    assert_eq!(plan["schema_version"], "tallow.request_plan.v1");
    assert_eq!(plan["manifest_id"], "operator-cli-source-manifest");
    assert_eq!(plan["request_count"], 1);
    assert_eq!(report["schema_version"], "tallow.request_plan_report.v1");
    assert_eq!(report["passed"], true);
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn package_report_excludes_existing_output_with_mixed_path_forms() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = temp.path().join("run-dir");
    std::fs::create_dir_all(&run_dir).expect("create run dir");
    std::fs::write(run_dir.join("artifact.txt"), b"stable artifact\n").expect("write artifact");
    let output_path = run_dir.join("package-report.json");
    std::fs::write(&output_path, b"stale package report\n").expect("write stale output");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .current_dir(temp.path())
        .args([
            "package-report",
            "run-dir",
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow package-report");

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("stdout package JSON");
    let files = report["files"].as_array().expect("files array");
    assert_eq!(report["summary"]["files"], 1);
    assert!(
        files
            .iter()
            .all(|entry| entry["path"] != "package-report.json"),
        "package report must not include its own output: {files:?}"
    );
    assert_eq!(files[0]["path"], "artifact.txt");
    let expected_hash = format!("{:x}", Sha256::digest(b"stable artifact\n"));
    assert_eq!(files[0]["sha256"], expected_hash);
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn package_report_command_writes_hash_checked_manifest() {
    let temp = tempfile::tempdir().expect("tempdir");
    let run_dir = temp.path().join("run-dir");
    let nested_dir = run_dir.join("artifacts");
    std::fs::create_dir_all(&nested_dir).expect("create run dir");
    let report_path = run_dir.join("run-report.json");
    let artifact_path = nested_dir.join("response-body.redacted.txt");
    std::fs::write(&report_path, b"{\"passed\":true}\n").expect("write run report");
    std::fs::write(&artifact_path, b"redacted body\n").expect("write artifact");
    let output_path = temp.path().join("package-report.json");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "package-report",
            run_dir.to_str().unwrap(),
            "--output",
            output_path.to_str().unwrap(),
        ])
        .output()
        .expect("run tallow package-report");

    assert!(
        output.status.success(),
        "status={:?}\nstdout={}\nstderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout_report: Value = serde_json::from_slice(&output.stdout).expect("stdout package JSON");
    let file_report: Value =
        serde_json::from_slice(&std::fs::read(&output_path).expect("read package report"))
            .expect("file package JSON");
    assert_eq!(stdout_report, file_report);
    assert_eq!(stdout_report["schema_version"], "tallow.package_report.v1");
    assert_eq!(stdout_report["summary"]["files"], 2);
    assert_eq!(stdout_report["non_claims"]["no_network_io"], true);
    assert_canonical_error_shape(&stdout_report["error"], "none", false, "artifact_packaging");

    let files = stdout_report["files"].as_array().expect("files array");
    let artifact = files
        .iter()
        .find(|entry| entry["path"] == "artifacts/response-body.redacted.txt")
        .expect("artifact entry");
    let expected_hash = format!("{:x}", Sha256::digest(b"redacted body\n"));
    assert_eq!(artifact["sha256"], expected_hash);
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn fmt_generated_tl_check_accepts_formatted_header_without_rewriting() {
    let temp = tempfile::tempdir().expect("tempdir");
    let tl_path = temp.path().join("generated-formatted.tl");
    let source = generated_tl_source(
        r#"fn main() {
    print("ok")
}"#,
    );
    std::fs::write(&tl_path, &source).expect("write generated tl");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["fmt", tl_path.to_str().unwrap(), "--check"])
        .output()
        .expect("run tallow fmt --check");

    assert!(
        output.status.success(),
        "formatted generated TL should pass check despite generated header\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&tl_path).expect("read generated tl"),
        source,
        "fmt --check must not rewrite generated source"
    );
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn fmt_generated_tl_check_rejects_unformatted_without_rewriting() {
    let temp = tempfile::tempdir().expect("tempdir");
    let tl_path = temp.path().join("generated-unformatted.tl");
    let source = generated_tl_source("fn main(){\nprint(\"ok\")\n}");
    std::fs::write(&tl_path, &source).expect("write generated tl");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args(["fmt", tl_path.to_str().unwrap(), "--check"])
        .output()
        .expect("run tallow fmt --check");

    assert!(
        !output.status.success(),
        "fmt --check should reject unformatted generated TL\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read_to_string(&tl_path).expect("read generated tl"),
        source,
        "fmt --check must not rewrite generated source"
    );
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        combined.contains("not formatted"),
        "unexpected output: {combined}"
    );
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn lint_generated_scraper_profile_blocks_missing_legal_and_http_import() {
    let temp = tempfile::tempdir().expect("tempdir");
    let tl_path = temp.path().join("generated-scraper.tl");
    std::fs::write(
        &tl_path,
        generated_tl_source(
            r#"fn main() {
    let response = http.get("https://example.invalid/products")
}"#,
        ),
    )
    .expect("write generated tl");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "lint",
            tl_path.to_str().unwrap(),
            "--profile",
            "scraper",
            "--format",
            "json",
        ])
        .output()
        .expect("run tallow lint --profile scraper");

    assert!(
        !output.status.success(),
        "scraper lint should fail closed\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("lint JSON stdout");
    assert_eq!(report["profile"], "scraper");
    let codes: Vec<&str> = report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .filter_map(|diag| diag["code"].as_str())
        .collect();
    assert!(
        codes.contains(&"E-SCRAPER-IMPORT"),
        "missing canonical import diagnostic in {codes:?}"
    );
    assert!(
        codes.contains(&"E-SCRAPER-LEGAL"),
        "missing @legal diagnostic in {codes:?}"
    );
}

#[test]
#[ignore = "request-plan CLI verbs (run-plan, build-plan, lint, package-report, fmt --check) are not implemented in this tree — parked as U-218; this suite records the intended contract"]
fn lint_generated_scraper_profile_allows_canonical_import_without_http_call() {
    let temp = tempfile::tempdir().expect("tempdir");
    let tl_path = temp.path().join("generated-scraper-import-only.tl");
    std::fs::write(
        &tl_path,
        generated_tl_source(
            r#"import tallow.http

fn main() {
    print("ok")
}"#,
        ),
    )
    .expect("write generated tl");

    let output = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .args([
            "lint",
            tl_path.to_str().unwrap(),
            "--profile",
            "scraper",
            "--format",
            "json",
        ])
        .output()
        .expect("run tallow lint --profile scraper");

    assert!(
        output.status.success(),
        "canonical import alone should not be treated as HTTP work\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("lint JSON stdout");
    let codes: Vec<&str> = report["diagnostics"]
        .as_array()
        .expect("diagnostics array")
        .iter()
        .filter_map(|diag| diag["code"].as_str())
        .collect();
    assert!(
        !codes.contains(&"E-SCRAPER-LEGAL"),
        "import-only file must not require @legal: {codes:?}"
    );
}
