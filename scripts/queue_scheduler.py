#!/usr/bin/env python3
"""Linux-native local/mock adaptive queue scheduler proof for Phase 6.

This script intentionally stays in the Phase 6 safety boundary:
- local/mock execution only by default;
- no live external crawling/scraping;
- no secrets/vault resolution;
- no destructive queue purge command;
- stdlib-only so it runs on Linux/CachyOS without PowerShell.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEDULER_VERSION = "phase6-adaptive-scheduler-v0"
STATE_SCHEMA = "tallow.queue.scheduler_state.v1"
REPORT_SCHEMA = "tallow.queue.scheduler_run_report.v1"
ARTIFACT_SCHEMA = "tallow.artifact_manifest.v1"
JOB_REPORT_SCHEMA = "tallow.queue.scheduler_job_report.v1"
SENSITIVE_HEADER_FRAGMENTS = ("authorization", "cookie", "token", "api-key", "apikey", "secret", "password")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class SchedulerError(Exception):
    def __init__(self, message: str, exit_code: int = 2) -> None:
        super().__init__(message)
        self.exit_code = exit_code


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, separators=(",", ": ")) + "\n"


def write_json_atomic(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(stable_json(data), encoding="utf-8")
    tmp.replace(path)


def append_jsonl(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("".join(json.dumps(row, sort_keys=True) + "\n" for row in rows), encoding="utf-8")


def display_path(path: Path) -> str:
    resolved = path.resolve()
    try:
        return str(resolved.relative_to(ROOT))
    except ValueError:
        return str(resolved)


def redact_value(value: Any) -> str:
    raw = str(value).encode("utf-8", errors="replace")
    return f"<redacted:sha256:{sha256_bytes(raw)}:bytes:{len(raw)}>"


def redact_request(request: dict[str, Any]) -> dict[str, Any]:
    redacted = json.loads(json.dumps(request))
    headers = redacted.get("headers")
    if isinstance(headers, dict):
        redacted["headers"] = {
            str(key): redact_value(value) if is_sensitive_header(str(key), value) else value
            for key, value in headers.items()
        }
    body = redacted.get("body")
    if isinstance(body, dict) and body.get("value") is not None:
        redacted_body = dict(body)
        redacted_body["value"] = redact_value(json.dumps(body.get("value"), sort_keys=True))
        redacted["body"] = redacted_body
    return redacted


def is_sensitive_header(name: str, value: Any) -> bool:
    lower_name = name.lower()
    lower_value = str(value).lower()
    return any(fragment in lower_name for fragment in SENSITIVE_HEADER_FRAGMENTS) or "bearer " in lower_value


def load_plan(path: Path) -> tuple[dict[str, Any], str]:
    data = path.read_bytes()
    plan = json.loads(data.decode("utf-8"))
    if plan.get("schema_version") != "tallow.request_plan.v1":
        raise SchedulerError("request plan schema_version must be tallow.request_plan.v1")
    requests = plan.get("requests")
    if not isinstance(requests, list):
        raise SchedulerError("request plan must contain requests[]")
    if plan.get("request_count") != len(requests):
        raise SchedulerError("request_count does not match requests length")
    return plan, sha256_bytes(data)


def parse_url(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("invalid_url_scheme")
    return parsed


def is_loopback_url(url: str) -> bool:
    try:
        parsed = parse_url(url)
    except ValueError:
        return False
    host = parsed.hostname or ""
    return host in LOOPBACK_HOSTS


def domain_for_request(request: dict[str, Any]) -> str:
    try:
        parsed = parse_url(str(request.get("url", "")))
        return parsed.hostname or "unknown"
    except ValueError:
        return "invalid"


def rewrite_to_mock_base(url: str, mock_base_url: str | None) -> str:
    if not mock_base_url:
        return url
    original = parse_url(url)
    base = parse_url(mock_base_url)
    return urllib.parse.urlunparse((base.scheme, base.netloc, original.path or "/", original.params, original.query, original.fragment))


def job_id_for(index: int, request: dict[str, Any]) -> str:
    target_id = str(request.get("target_id") or f"target_{index}")
    url = str(request.get("url") or "")
    digest = sha256_bytes(f"{index}\0{target_id}\0{url}".encode("utf-8"))[:12]
    safe_target = "".join(ch if ch.isalnum() or ch in {"-", "_"} else "_" for ch in target_id)[:32]
    return f"job_{index:04d}_{safe_target}_{digest}"


def classify_request(request: dict[str, Any], *, network_scope: str, mock_base_url: str | None) -> list[dict[str, Any]]:
    reasons: list[dict[str, Any]] = []
    url = str(request.get("url") or "")
    try:
        parse_url(url)
    except ValueError as exc:
        reasons.append({"reason_code": str(exc), "field": "url", "retryable": False, "human_action": "fix_target_url"})

    method = str(request.get("method") or "GET").upper()
    if method not in {"GET", "POST"}:
        reasons.append({"reason_code": "unsupported_method", "field": "method", "retryable": False, "human_action": "use_supported_method"})

    if network_scope != "local":
        reasons.append({"reason_code": "live_execution_human_gate", "field": "network_scope", "retryable": False, "human_action": "request_explicit_live_approval"})
    elif url and not is_loopback_url(url) and not mock_base_url:
        reasons.append({"reason_code": "external_network_disabled", "field": "url", "retryable": False, "human_action": "use_mock_base_url_or_live_policy_gate"})

    browser_fallback = request.get("browser_fallback")
    if isinstance(browser_fallback, dict) and browser_fallback.get("mode", "never") != "never":
        reasons.append({"reason_code": "unsupported_browser_fallback", "field": "browser_fallback.mode", "retryable": False, "human_action": "defer_to_browser_fallback_phase"})
    if request.get("auth_ref"):
        reasons.append({"reason_code": "unsupported_auth_ref", "field": "auth_ref", "retryable": False, "human_action": "defer_to_phase9_vault_gate"})
    if request.get("extraction_schema_ref"):
        reasons.append({"reason_code": "unsupported_extraction_schema", "field": "extraction_schema_ref", "retryable": False, "human_action": "defer_to_live_extraction_gate"})

    artifact_policy = request.get("artifact_policy")
    if isinstance(artifact_policy, dict):
        if artifact_policy.get("har", "never") != "never":
            reasons.append({"reason_code": "unsupported_har_capture", "field": "artifact_policy.har", "retryable": False, "human_action": "defer_to_live_artifact_capture_gate"})
        if artifact_policy.get("screenshots", "never") != "never":
            reasons.append({"reason_code": "unsupported_screenshot_capture", "field": "artifact_policy.screenshots", "retryable": False, "human_action": "defer_to_live_artifact_capture_gate"})

    compliance = request.get("compliance")
    if isinstance(compliance, dict) and compliance.get("requires_approval"):
        reasons.append({"reason_code": "requires_human_approval", "field": "compliance.requires_approval", "retryable": False, "human_action": "obtain_explicit_approval"})

    headers = request.get("headers")
    if isinstance(headers, dict):
        for name, value in headers.items():
            if is_sensitive_header(str(name), value):
                reasons.append({"reason_code": "sensitive_header", "field": f"headers.{name}", "retryable": False, "human_action": "replace_literal_secret_with_safe_ref"})
    return reasons


def build_initial_state(
    *,
    plan_path: Path,
    plan_sha: str,
    plan: dict[str, Any],
    output_dir: Path,
    network_scope: str,
    mock_base_url: str | None,
    global_concurrency: int,
    default_domain_concurrency: int,
    max_attempts: int,
) -> dict[str, Any]:
    requests = plan["requests"]
    domains: dict[str, dict[str, Any]] = {}
    jobs: list[dict[str, Any]] = []
    for index, request in enumerate(requests):
        domain = domain_for_request(request)
        if domain not in domains:
            cap = max(1, min(global_concurrency, default_domain_concurrency))
            domains[domain] = {
                "cap": cap,
                "current": cap,
                "successes": 0,
                "failures": 0,
                "throttles": 0,
                "next_allowed_at_utc": None,
                "policy_source": "phase6_default_local_budget",
            }
        blocked_reasons = classify_request(request, network_scope=network_scope, mock_base_url=mock_base_url)
        request_retry = request.get("retry") if isinstance(request.get("retry"), dict) else {}
        request_max_attempts = int(request_retry.get("max_attempts") or max_attempts)
        jobs.append(
            {
                "job_id": job_id_for(index, request),
                "request_index": index,
                "target_id": str(request.get("target_id") or f"target_{index}"),
                "domain": domain,
                "method": str(request.get("method") or "GET").upper(),
                "url_sha256": sha256_bytes(str(request.get("url") or "").encode("utf-8")),
                "status": "blocked" if blocked_reasons else "pending",
                "attempts": 0,
                "max_attempts": request_max_attempts,
                "blocked_reasons": blocked_reasons,
                "last_error_kind": None,
                "last_error_code": None,
                "http_status": None,
                "execution_report_path": None,
                "artifact_manifest_path": None,
                "lease_owner": None,
                "lease_acquired_at_utc": None,
                "lease_expires_at_utc": None,
            }
        )

    queue_id = "queue_" + sha256_bytes(f"{plan_sha}\0{network_scope}\0{global_concurrency}\0{default_domain_concurrency}".encode("utf-8"))[:16]
    now = now_utc()
    state = {
        "schema_version": STATE_SCHEMA,
        "scheduler_version": SCHEDULER_VERSION,
        "queue_id": queue_id,
        "status": "pending",
        "created_at_utc": now,
        "updated_at_utc": now,
        "network_scope": network_scope,
        "execution_backend": "local_mock",
        "plan": {
            "path": display_path(plan_path),
            "sha256": plan_sha,
            "schema_version": plan.get("schema_version"),
            "manifest_id": plan.get("manifest_id"),
            "request_count": len(requests),
        },
        "output": {
            "output_dir": display_path(output_dir),
            "state_path": display_path(output_dir / "queue_state.json"),
            "run_report_path": display_path(output_dir / "queue_run_report.json"),
            "blocked_targets_path": display_path(output_dir / "blocked_targets.jsonl"),
            "dead_letter_path": display_path(output_dir / "dead_letter.jsonl"),
            "artifact_manifest_path": display_path(output_dir / "artifact_manifest.json"),
        },
        "resume_fingerprint": sha256_bytes(
            stable_json(
                {
                    "plan_sha256": plan_sha,
                    "scheduler_version": SCHEDULER_VERSION,
                    "network_scope": network_scope,
                    "global_concurrency": global_concurrency,
                    "default_domain_concurrency": default_domain_concurrency,
                    "max_attempts_default": max_attempts,
                }
            ).encode("utf-8")
        ),
        "budgets": {"global_concurrency": global_concurrency, "domains": domains},
        "jobs": jobs,
        "checkpoints": [],
        "non_claims": non_claims(),
    }
    add_checkpoint(state, "state_initialized")
    return state


def non_claims() -> dict[str, bool]:
    return {
        "live_external_scraping": False,
        "production_queue_ready": False,
        "distributed_workers": False,
        "destructive_purge_supported": False,
        "vault_or_secret_resolution": False,
        "browser_fallback_execution": False,
        "windows_support": False,
        "benchmark_or_performance_claim": False,
    }


def add_checkpoint(state: dict[str, Any], event: str, extra: dict[str, Any] | None = None) -> None:
    checkpoints = state.setdefault("checkpoints", [])
    checkpoint = {"sequence": len(checkpoints) + 1, "event": event, "written_at_utc": now_utc()}
    if extra:
        checkpoint.update(extra)
    checkpoints.append(checkpoint)
    state["updated_at_utc"] = checkpoint["written_at_utc"]


def load_resume_state(state_path: Path, *, plan_sha: str) -> dict[str, Any]:
    state = json.loads(state_path.read_text(encoding="utf-8"))
    if state.get("schema_version") != STATE_SCHEMA:
        raise SchedulerError("resume state schema mismatch")
    if state.get("plan", {}).get("sha256") != plan_sha:
        raise SchedulerError("plan hash mismatch for resume state")
    for job in state.get("jobs", []):
        if job.get("status") not in {"completed", "dead_letter", "blocked"}:
            job["status"] = "pending"
            job["lease_owner"] = None
            job["lease_acquired_at_utc"] = None
            job["lease_expires_at_utc"] = None
    add_checkpoint(state, "resume_loaded")
    return state


def write_plan_snapshot(output_dir: Path, plan: dict[str, Any]) -> Path:
    snapshot = json.loads(json.dumps(plan))
    snapshot["requests"] = [redact_request(request) for request in plan.get("requests", [])]
    path = output_dir / "request_plan.v1.json"
    write_json_atomic(path, snapshot)
    return path


def redacted_response_body(raw: bytes) -> bytes:
    payload = {
        "redacted": True,
        "sha256": sha256_bytes(raw),
        "size_bytes": len(raw),
        "body": f"<redacted:sha256:{sha256_bytes(raw)}:bytes:{len(raw)}>",
    }
    return stable_json(payload).encode("utf-8")


def synthetic_response(url: str, method: str, attempt: int, body: bytes | None) -> tuple[int, bytes, dict[str, str]]:
    parsed = parse_url(url)
    path = parsed.path or "/"
    if path.startswith("/retry") and attempt == 1:
        status = 500
        ok = False
    elif path.startswith("/always500"):
        status = 500
        ok = False
    else:
        status = 200
        ok = True
    payload = {"ok": ok, "method": method, "path": path, "attempt": attempt, "synthetic_local": True}
    if body:
        payload["request_body_sha256"] = sha256_bytes(body)
    return status, stable_json(payload).encode("utf-8"), {"content-type": "application/json"}


def perform_request(request: dict[str, Any], *, url: str, attempt: int, simulate: bool, timeout: float = 5.0) -> tuple[int | None, bytes, str | None]:
    method = str(request.get("method") or "GET").upper()
    body_bytes: bytes | None = None
    headers = {str(k): str(v) for k, v in (request.get("headers") or {}).items() if not is_sensitive_header(str(k), v)}
    body = request.get("body")
    if method == "POST" and isinstance(body, dict) and body.get("kind") == "json":
        body_bytes = json.dumps(body.get("value"), sort_keys=True).encode("utf-8")
        headers.setdefault("Content-Type", body.get("content_type") or "application/json")
    if simulate:
        status, payload, _headers = synthetic_response(url, method, attempt, body_bytes)
        return status, payload, None
    req = urllib.request.Request(url, data=body_bytes, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as response:  # noqa: S310 - local/mock only after classification
            return response.status, response.read(), None
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(), None
    except urllib.error.URLError as exc:
        return None, str(exc).encode("utf-8", errors="replace"), "network_error"


def error_kind_for_status(status: int | None, explicit_error: str | None = None) -> str | None:
    if explicit_error:
        return explicit_error
    if status is None:
        return "network_error"
    if status == 429:
        return "http_429"
    if 500 <= status <= 599:
        return "http_5xx"
    if 400 <= status <= 499:
        return "http_4xx"
    return None


def should_retry(request: dict[str, Any], error_kind: str | None, attempt: int, max_attempts: int) -> bool:
    if not error_kind or attempt >= max_attempts:
        return False
    retry_value = request.get("retry")
    retry: dict[str, Any] = retry_value if isinstance(retry_value, dict) else {}
    retry_kinds = set(retry.get("retry_on_error_kinds") or ["http_5xx", "http_429", "network_error"])
    return error_kind in retry_kinds


def write_job_artifacts(output_dir: Path, job: dict[str, Any], job_report: dict[str, Any], response_files: list[Path]) -> tuple[Path, Path]:
    job_dir = output_dir / "jobs" / job["job_id"]
    job_dir.mkdir(parents=True, exist_ok=True)
    report_path = job_dir / "execution_report.json"
    write_json_atomic(report_path, job_report)
    files = []
    for path in [report_path, *response_files]:
        if path.exists():
            files.append(
                {
                    "path": display_path(path),
                    "artifact_class": "logs" if path == report_path else "raw_response",
                    "exists": True,
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                    "redaction_status": "not_applicable" if path == report_path else "redacted",
                }
            )
    manifest = {
        "schema_version": ARTIFACT_SCHEMA,
        "artifact_id": f"{job['job_id']}-artifacts",
        "launch_id": "phase6-adaptive-scheduler-local",
        "run_id": job["job_id"],
        "generated_at_utc": now_utc(),
        "files": files,
        "request": {"target_id": job.get("target_id"), "headers_redacted": True, "body_redacted": True},
        "response": {"status": job.get("http_status") or 0, "headers_redacted": True, "body_capture": "redacted", "error_kind": job.get("last_error_kind") or "none"},
        "redaction": {"status": "passed", "pii_policy": "no_pii_expected", "notes": "Phase 6 job artifacts redact bodies by hash."},
        "retention": {"retention_days": 7},
        "replay": {"safe_to_replay": False, "replay_reason": "local/mock proof artifact", "requires_approval": True},
    }
    manifest_path = job_dir / "artifact_manifest.json"
    write_json_atomic(manifest_path, manifest)
    return report_path, manifest_path


def execute_job(
    *,
    output_dir: Path,
    state: dict[str, Any],
    job: dict[str, Any],
    request: dict[str, Any],
    mock_base_url: str | None,
    simulate: bool,
) -> None:
    domain = job["domain"]
    budget = state["budgets"]["domains"].setdefault(domain, {"cap": 1, "current": 1, "successes": 0, "failures": 0, "throttles": 0, "next_allowed_at_utc": None})
    job["status"] = "running"
    job["lease_owner"] = "phase6-local-scheduler"
    job["lease_acquired_at_utc"] = now_utc()
    job["lease_expires_at_utc"] = None
    add_checkpoint(state, "job_started", {"job_id": job["job_id"]})

    response_files: list[Path] = []
    attempts: list[dict[str, Any]] = []
    max_attempts = int(job.get("max_attempts") or 1)
    final_error: str | None = None
    final_status: int | None = None
    final_response_path: str | None = None
    for attempt in range(int(job.get("attempts") or 0) + 1, max_attempts + 1):
        rewritten_url = rewrite_to_mock_base(str(request.get("url") or ""), mock_base_url)
        status, raw_body, explicit_error = perform_request(request, url=rewritten_url, attempt=attempt, simulate=simulate)
        error_kind = error_kind_for_status(status, explicit_error)
        response_path = output_dir / "jobs" / job["job_id"] / f"response_body_attempt_{attempt:03d}.redacted.json"
        response_path.parent.mkdir(parents=True, exist_ok=True)
        response_path.write_bytes(redacted_response_body(raw_body))
        response_files.append(response_path)
        final_response_path = display_path(response_path)
        final_status = status
        final_error = error_kind
        job["attempts"] = attempt
        job["http_status"] = status
        job["last_error_kind"] = error_kind
        job["last_error_code"] = status
        if error_kind in {"http_429"}:
            budget["throttles"] = int(budget.get("throttles") or 0) + 1
            budget["current"] = 1
            budget["next_allowed_at_utc"] = now_utc()
        elif error_kind:
            budget["failures"] = int(budget.get("failures") or 0) + 1
            budget["current"] = max(1, int(budget.get("current") or 1) - 1)
        else:
            budget["successes"] = int(budget.get("successes") or 0) + 1
            budget["current"] = min(int(budget.get("cap") or 1), int(budget.get("current") or 1) + 1)
        attempts.append({"attempt": attempt, "http_status": status, "error_kind": error_kind, "response_body_path": final_response_path})
        add_checkpoint(state, "job_attempt_recorded", {"job_id": job["job_id"], "attempt": attempt, "status": status, "error_kind": error_kind})
        if not should_retry(request, error_kind, attempt, max_attempts):
            break

    if final_error:
        job["status"] = "dead_letter"
        job["last_error_kind"] = "retry_exhausted" if final_error in {"http_5xx", "http_429", "network_error"} else final_error
    else:
        job["status"] = "completed"
    job["lease_owner"] = None
    job["lease_acquired_at_utc"] = None

    job_report = {
        "schema_version": JOB_REPORT_SCHEMA,
        "job_id": job["job_id"],
        "target_id": job["target_id"],
        "status": job["status"],
        "attempts": attempts,
        "final_http_status": final_status,
        "final_error_kind": job.get("last_error_kind"),
        "response_body_path": final_response_path,
        "redaction": {"response_body": "sha256_only", "request_body": "hash_only"},
    }
    report_path, manifest_path = write_job_artifacts(output_dir, job, job_report, response_files)
    job["execution_report_path"] = display_path(report_path)
    job["artifact_manifest_path"] = display_path(manifest_path)
    add_checkpoint(state, "job_finished", {"job_id": job["job_id"], "status": job["status"]})


def summarize(state: dict[str, Any], *, dry_run: bool) -> dict[str, int]:
    jobs = state.get("jobs", [])
    return {
        "planned": len(jobs),
        "executed": 0 if dry_run else sum(1 for job in jobs if int(job.get("attempts") or 0) > 0),
        "completed": sum(1 for job in jobs if job.get("status") == "completed"),
        "blocked": sum(1 for job in jobs if job.get("status") == "blocked"),
        "dead_letter": sum(1 for job in jobs if job.get("status") == "dead_letter"),
        "deferred": sum(1 for job in jobs if job.get("status") == "deferred"),
        "attempts": sum(int(job.get("attempts") or 0) for job in jobs),
    }


def write_classification_files(output_dir: Path, state: dict[str, Any]) -> tuple[Path, Path]:
    blocked_rows: list[dict[str, Any]] = []
    dlq_rows: list[dict[str, Any]] = []
    for job in state.get("jobs", []):
        if job.get("status") == "blocked":
            blocked_rows.append(
                {
                    "schema_version": "tallow.queue.blocked_target.v1",
                    "queue_id": state.get("queue_id"),
                    "job_id": job.get("job_id"),
                    "target_id": job.get("target_id"),
                    "request_index": job.get("request_index"),
                    "domain": job.get("domain"),
                    "classification": "blocked",
                    "blocked_reasons": job.get("blocked_reasons") or [],
                    "retryable": False,
                }
            )
        if job.get("status") == "dead_letter":
            dlq_rows.append(
                {
                    "schema_version": "tallow.queue.dead_letter.v1",
                    "queue_id": state.get("queue_id"),
                    "job_id": job.get("job_id"),
                    "target_id": job.get("target_id"),
                    "request_index": job.get("request_index"),
                    "domain": job.get("domain"),
                    "attempts": job.get("attempts"),
                    "max_attempts": job.get("max_attempts"),
                    "classification": "dead_letter",
                    "reason_code": "retry_exhausted",
                    "last_error_kind": job.get("last_error_kind"),
                    "last_error_code": job.get("last_error_code"),
                    "execution_report_path": job.get("execution_report_path"),
                    "artifact_manifest_path": job.get("artifact_manifest_path"),
                    "retryable": False,
                }
            )
    blocked_path = output_dir / "blocked_targets.jsonl"
    dlq_path = output_dir / "dead_letter.jsonl"
    append_jsonl(blocked_path, blocked_rows)
    append_jsonl(dlq_path, dlq_rows)
    return blocked_path, dlq_path


def build_run_report(state: dict[str, Any], *, dry_run: bool, exit_code: int, command: list[str]) -> dict[str, Any]:
    summary = summarize(state, dry_run=dry_run)
    passed = exit_code == 0
    return {
        "schema_version": REPORT_SCHEMA,
        "passed": passed,
        "exit_code": exit_code,
        "dry_run": dry_run,
        "generated_at_utc": now_utc(),
        "scheduler": {"version": SCHEDULER_VERSION, "platform": "linux-cachyos-local"},
        "queue_id": state.get("queue_id"),
        "status": state.get("status"),
        "summary": summary,
        "state_path": state.get("output", {}).get("state_path"),
        "blocked_targets_path": state.get("output", {}).get("blocked_targets_path"),
        "dead_letter_path": state.get("output", {}).get("dead_letter_path"),
        "artifact_manifest_path": state.get("output", {}).get("artifact_manifest_path"),
        "budgets": state.get("budgets"),
        "jobs": [
            {
                "job_id": job.get("job_id"),
                "target_id": job.get("target_id"),
                "request_index": job.get("request_index"),
                "domain": job.get("domain"),
                "status": job.get("status"),
                "attempts": job.get("attempts"),
                "http_status": job.get("http_status"),
                "last_error_kind": job.get("last_error_kind"),
                "blocked_reasons": job.get("blocked_reasons"),
                "execution_report_path": job.get("execution_report_path"),
                "artifact_manifest_path": job.get("artifact_manifest_path"),
            }
            for job in state.get("jobs", [])
        ],
        "command": command,
        "non_claims": state.get("non_claims") or non_claims(),
        "safety_boundary": "Phase 6 local/mock scheduler proof only; no live external scraping, secrets, destructive purges, deploys, benchmarks, or Windows support.",
    }


def build_artifact_manifest(output_dir: Path, files: list[Path]) -> dict[str, Any]:
    manifest_files = []
    for path in files:
        if path.exists():
            artifact_class = "logs"
            if path.name.endswith("manifest.json") or path.name == "request_plan.v1.json":
                artifact_class = "manifest"
            elif "metrics" in path.name or "report" in path.name or path.name == "queue_state.json":
                artifact_class = "metrics"
            elif "dead_letter" in path.name or "blocked" in path.name:
                artifact_class = "quarantine"
            manifest_files.append(
                {
                    "path": display_path(path),
                    "artifact_class": artifact_class,
                    "exists": True,
                    "size_bytes": path.stat().st_size,
                    "sha256": sha256_file(path),
                    "redaction_status": "redacted" if path.name == "request_plan.v1.json" else "not_applicable",
                }
            )
    return {
        "schema_version": ARTIFACT_SCHEMA,
        "artifact_id": "phase6-adaptive-scheduler-local",
        "launch_id": "phase6-adaptive-scheduler-local",
        "run_id": "phase6-local-proof",
        "generated_at_utc": now_utc(),
        "files": manifest_files,
        "request": {"headers_redacted": True, "body_redacted": True},
        "response": {"status": 0, "headers_redacted": True, "body_capture": "redacted", "error_kind": "not_applicable"},
        "redaction": {"status": "passed", "pii_policy": "no_pii_expected", "notes": "Phase 6 top-level proof files contain no raw secrets."},
        "retention": {"retention_days": 7},
        "replay": {"safe_to_replay": False, "replay_reason": "local/mock proof; no live replay by default", "requires_approval": True},
        "non_claims": non_claims(),
    }


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Phase 6 Linux-native local/mock adaptive queue scheduler")
    parser.add_argument("--plan", required=True, help="Input tallow.request_plan.v1 JSON")
    parser.add_argument("--output-dir", required=True, help="Directory for queue state/report/artifacts")
    parser.add_argument("--state", help="Optional queue_state.json path; defaults to <output-dir>/queue_state.json")
    parser.add_argument("--network-scope", choices=["local", "live"], default="local", help="Execution scope. Phase 6 only executes local; live is fail-closed.")
    parser.add_argument("--mock-base-url", help="Loopback base URL to rewrite external plan URLs for local/mock execution")
    parser.add_argument("--dry-run", action="store_true", help="Classify/plan only; write state/report/artifacts but do not execute requests")
    parser.add_argument("--resume", action="store_true", help="Resume existing queue state after verifying plan hash")
    parser.add_argument("--force", action="store_true", help="Allow overwriting an existing non-resume local proof output directory")
    parser.add_argument("--max-attempts", type=int, default=2, help="Default max attempts for requests without retry.max_attempts")
    parser.add_argument("--global-concurrency", type=int, default=2, help="Global local scheduler concurrency budget used for planning/provenance")
    parser.add_argument("--default-domain-concurrency", type=int, default=1, help="Default per-domain local scheduler cap")
    parser.add_argument("--stop-after", type=int, help="Stop after N completed jobs, mark remaining jobs deferred, and exit 3")
    parser.add_argument("--simulate", action="store_true", help="Use deterministic synthetic local responses instead of opening loopback sockets")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(sys.argv[1:] if argv is None else argv)
    plan_path = Path(args.plan).resolve()
    output_dir = Path(args.output_dir).resolve()
    state_path = Path(args.state).resolve() if args.state else output_dir / "queue_state.json"
    report_path = output_dir / "queue_run_report.json"
    command_log_path = output_dir / "command_log.txt"
    output_dir.mkdir(parents=True, exist_ok=True)

    plan, plan_sha = load_plan(plan_path)
    command = ["python3", "scripts/queue_scheduler.py", *sys.argv[1:]]
    command_log_path.write_text(" ".join(command) + "\n", encoding="utf-8")
    snapshot_path = write_plan_snapshot(output_dir, plan)

    if args.resume:
        try:
            state = load_resume_state(state_path, plan_sha=plan_sha)
        except SchedulerError as exc:
            print(str(exc), file=sys.stderr)
            return exc.exit_code
    else:
        if state_path.exists() and not args.force:
            raise SchedulerError(f"state already exists at {state_path}; use --resume or --force")
        state = build_initial_state(
            plan_path=plan_path,
            plan_sha=plan_sha,
            plan=plan,
            output_dir=output_dir,
            network_scope=args.network_scope,
            mock_base_url=args.mock_base_url,
            global_concurrency=args.global_concurrency,
            default_domain_concurrency=args.default_domain_concurrency,
            max_attempts=args.max_attempts,
        )
    state["output"]["state_path"] = display_path(state_path)

    blocked_before_execution = any(job.get("status") == "blocked" for job in state.get("jobs", []))
    if args.dry_run:
        for job in state.get("jobs", []):
            if job.get("status") == "pending":
                job["status"] = "planned"
        state["status"] = "blocked" if blocked_before_execution else "planned"
        exit_code = 2 if blocked_before_execution else 0
    elif blocked_before_execution:
        state["status"] = "blocked"
        exit_code = 2
    else:
        completed_this_run = 0
        for job in state.get("jobs", []):
            if job.get("status") == "completed":
                continue
            if args.stop_after is not None and completed_this_run >= args.stop_after:
                if job.get("status") == "pending":
                    job["status"] = "deferred"
                continue
            request = plan["requests"][int(job["request_index"])]
            execute_job(output_dir=output_dir, state=state, job=job, request=request, mock_base_url=args.mock_base_url, simulate=bool(args.simulate))
            if job.get("status") == "completed":
                completed_this_run += 1
        if args.stop_after is not None and any(job.get("status") in {"pending", "deferred"} for job in state.get("jobs", [])):
            for job in state.get("jobs", []):
                if job.get("status") == "pending":
                    job["status"] = "deferred"
            state["status"] = "stopped"
            add_checkpoint(state, "stop_after_reached", {"stop_after": args.stop_after})
            exit_code = 3
        elif any(job.get("status") == "dead_letter" for job in state.get("jobs", [])):
            state["status"] = "completed_with_dlq"
            exit_code = 1
        else:
            state["status"] = "completed"
            exit_code = 0

    blocked_path, dlq_path = write_classification_files(output_dir, state)
    add_checkpoint(state, "final_state_recorded", {"status": state.get("status")})
    write_json_atomic(state_path, state)
    report = build_run_report(state, dry_run=bool(args.dry_run), exit_code=exit_code, command=command)
    write_json_atomic(report_path, report)

    files = [snapshot_path, state_path, report_path, blocked_path, dlq_path, command_log_path]
    for job in state.get("jobs", []):
        for key in ("execution_report_path", "artifact_manifest_path"):
            value = job.get(key)
            if value:
                path = Path(value)
                if not path.is_absolute():
                    path = ROOT / path
                files.append(path)
    artifact_manifest = build_artifact_manifest(output_dir, files)
    write_json_atomic(output_dir / "artifact_manifest.json", artifact_manifest)
    print(stable_json({"exit_code": exit_code, "status": state.get("status"), "summary": report["summary"], "report_path": display_path(report_path)}), end="")
    return exit_code


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SchedulerError as exc:
        print(str(exc), file=sys.stderr)
        raise SystemExit(exc.exit_code)
