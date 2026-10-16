#!/usr/bin/env python3
"""Run a Phase 2 Tallow request-plan artifact in a local-safe runtime slice.

This runner consumes `tallow.request_plan.v1` JSON directly. It is intentionally
Linux-native, stdlib-only, and local/mock-first. It does not use the legacy TL
`http.batch` downgrade path.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import html
import ipaddress
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
RUNNER_SCHEMA = "tallow.request_plan_run_report.v1"
ARTIFACT_SCHEMA = "tallow.artifact_manifest.v1"
RUNNER_VERSION = "phase2-request-plan-runner-v0"
EXECUTION_CONTRACT_REL_PATH = Path("schemas/tallow/request-plan-execution-contract.v1.json")
EXTRACTION_ROW_SCHEMA_REL_PATH = Path("schemas/tallow/extraction-row.schema.json")
EXTRACTION_VALIDATOR_REL_PATH = Path("scripts/validate_extraction_rows.py")
HOP_BY_HOP_HEADERS = {"connection", "host", "content-length", "proxy-authenticate", "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"}
SENSITIVE_HEADER_NAMES = {"authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key", "api-key", "apikey", "x-auth-token", "x-csrf-token"}
COMPLIANCE_REQUIRED_KEYS = {"source_authority", "purpose", "legal_basis", "pii_policy", "retention_days", "robots_mode"}
LOCAL_VAULT_PROVIDER_IDS = {"local", "fake"}


class RunnerError(Exception):
    """Fatal invocation/input/output error."""


@dataclass
class UnsupportedReason:
    index: int
    target_id: str
    field: str
    value: Any
    reason: str
    code: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "target_id": self.target_id,
            "field": self.field,
            "value": self.value,
            "reason": self.reason,
            "code": self.code,
            "severity": "fatal",
        }


@dataclass
class PreparedRequest:
    index: int
    target_id: str
    method: str
    original_url: str
    executed_url: str
    headers: dict[str, str]
    body_bytes: bytes | None
    body_metadata: dict[str, Any]
    graphql: dict[str, Any] | None
    compliance: dict[str, Any]
    retry: dict[str, Any] | None
    artifact_policy: dict[str, Any] | None
    extraction_schema_ref: Any | None
    vault_reference: dict[str, Any] | None


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def compact_json_bytes(data: Any) -> bytes:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(value: str) -> str:
    return sha256_bytes(value.encode("utf-8", errors="replace"))


def utc_now() -> datetime:
    return datetime.now(timezone.utc).replace(microsecond=0)


def iso_utc(dt: datetime) -> str:
    return dt.isoformat().replace("+00:00", "Z")


def resolve_path(path_arg: str) -> Path:
    path = Path(path_arg)
    if not path.is_absolute():
        path = ROOT / path
    return path


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path)


def sanitize_id(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9_.:-]+", "_", value).strip("_")
    return cleaned[:96] or "request"


@lru_cache(maxsize=1)
def load_execution_contract() -> tuple[dict[str, Any], bytes]:
    path = ROOT / EXECUTION_CONTRACT_REL_PATH
    raw = path.read_bytes()
    contract = json.loads(raw.decode("utf-8"))
    if not isinstance(contract, dict):
        raise RunnerError("request-plan execution contract must be a JSON object")
    return contract, raw


def load_execution_contract_summary() -> dict[str, Any]:
    contract, raw = load_execution_contract()
    raw_body_limits = contract.get("body_limits")
    body_limits: dict[str, Any] = raw_body_limits if isinstance(raw_body_limits, dict) else {}
    return {
        "schema_version": contract.get("schema_version"),
        "version": contract.get("version"),
        "source": str(EXECUTION_CONTRACT_REL_PATH),
        "role": "python_compatibility_bridge",
        "sha256": sha256_bytes(raw),
        "supported_methods": contract.get("supported_methods", []),
        "max_response_bytes_default": body_limits.get("max_response_bytes_default"),
    }


def contract_supported_methods() -> set[str]:
    contract, _raw = load_execution_contract()
    methods = contract.get("supported_methods")
    if not isinstance(methods, list) or not all(isinstance(method, str) for method in methods):
        raise RunnerError("request-plan execution contract supported_methods must be a string array")
    return {method.upper() for method in methods}


def contract_default_max_response_bytes() -> int:
    contract, _raw = load_execution_contract()
    raw_body_limits = contract.get("body_limits")
    body_limits: dict[str, Any] = raw_body_limits if isinstance(raw_body_limits, dict) else {}
    default = body_limits.get("max_response_bytes_default")
    if not isinstance(default, int) or default < 1:
        raise RunnerError("request-plan execution contract body_limits.max_response_bytes_default must be a positive integer")
    return default


def load_plan(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise RunnerError("request plan must be a JSON object")
    return data, raw


def validate_plan_shape(plan: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if plan.get("schema_version") != "tallow.request_plan.v1":
        errors.append("schema_version must be tallow.request_plan.v1")
    requests = plan.get("requests")
    if not isinstance(requests, list):
        errors.append("requests must be an array")
    else:
        if plan.get("request_count") != len(requests):
            errors.append("request_count must match len(requests)")
        for index, request in enumerate(requests):
            if not isinstance(request, dict):
                errors.append(f"requests[{index}] must be an object")
                continue
            for key in ("target_id", "url", "method", "headers", "compliance"):
                if key not in request:
                    errors.append(f"requests[{index}].{key} is required")
            if not isinstance(request.get("target_id"), str) or not request.get("target_id"):
                errors.append(f"requests[{index}].target_id must be a non-empty string")
            if not isinstance(request.get("url"), str) or not request.get("url"):
                errors.append(f"requests[{index}].url must be a non-empty string")
            if not isinstance(request.get("method"), str):
                errors.append(f"requests[{index}].method must be a string")
            if not isinstance(request.get("headers"), dict):
                errors.append(f"requests[{index}].headers must be an object")
            if not isinstance(request.get("compliance"), dict):
                errors.append(f"requests[{index}].compliance must be an object")
    return errors


def parse_url(url: str) -> urllib.parse.ParseResult:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("url must be HTTP(S)")
    return parsed


def rewrite_url(original_url: str, mock_base_url: str | None) -> str:
    original = parse_url(original_url)
    if not mock_base_url:
        return original_url
    base = parse_url(mock_base_url)
    base_path = base.path.rstrip("/")
    original_path = original.path or "/"
    path = f"{base_path}{original_path}" if base_path else original_path
    return urllib.parse.urlunparse((base.scheme, base.netloc, path, "", original.query, ""))


def is_loopback_host(hostname: str | None) -> bool:
    if not hostname:
        return False
    host = hostname.strip("[]").lower()
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def header_value_looks_unresolved(value: str) -> bool:
    lowered = value.lower()
    return "{{" in value or "}}" in value or "vault://" in lowered or "secret://" in lowered


def vault_provider_id(auth_ref: str) -> tuple[str, str]:
    parsed = urllib.parse.urlparse(auth_ref)
    if parsed.scheme == "vault":
        return "vault", parsed.netloc or "unknown"
    if parsed.scheme:
        return parsed.scheme, parsed.scheme
    return "inline", "inline"


def classify_vault_reference(auth_ref: Any, reasons: list[UnsupportedReason], index: int, target_id: str) -> dict[str, Any] | None:
    if auth_ref is None:
        return None
    if not isinstance(auth_ref, str) or not auth_ref.strip():
        reasons.append(UnsupportedReason(index, target_id, "auth_ref", "<redacted>", "auth_ref must be a non-empty vault/local/fake reference, not inline secret material", "inline_auth_ref"))
        return {
            "index": index,
            "target_id": target_id,
            "scheme": "inline",
            "provider_id": "inline",
            "reference_hash": sha256_text(str(auth_ref)),
            "status": "inline_auth_ref_rejected",
            "resolution_status": "inline_auth_ref_rejected",
            "secret_material_resolved": False,
            "secret_material_serialized": False,
            "auth_ref_serialized": False,
            "real_vault_contacted": False,
        }

    scheme, provider_id = vault_provider_id(auth_ref)
    provider_id = provider_id.lower()
    if provider_id in LOCAL_VAULT_PROVIDER_IDS and scheme in {"vault", "local", "fake"}:
        status = "accepted_local_reference"
    elif scheme == "inline":
        status = "inline_auth_ref_rejected"
        reasons.append(UnsupportedReason(index, target_id, "auth_ref", "<redacted>", "auth_ref must be a vault/local/fake reference, not inline secret material", "inline_auth_ref"))
    else:
        status = "unsupported_provider_fail_closed"
        reasons.append(UnsupportedReason(index, target_id, "auth_ref", "<redacted>", "real or unsupported vault providers are fail-closed in the Python runner; configure an approved provider before live credential resolution", "unsupported_vault_provider"))
    return {
        "index": index,
        "target_id": target_id,
        "scheme": scheme,
        "provider_id": provider_id,
        "reference_hash": sha256_text(auth_ref),
        "status": status,
        "resolution_status": status,
        "secret_material_resolved": False,
        "secret_material_serialized": False,
        "auth_ref_serialized": False,
        "real_vault_contacted": False,
    }


def sensitive_header_name(name: str) -> bool:
    lower = name.lower()
    return (
        lower in SENSITIVE_HEADER_NAMES
        or "token" in lower
        or "secret" in lower
        or "credential" in lower
        or "auth" in lower
        or "api-key" in lower
        or "apikey" in lower
        or lower.endswith("-key")
        or lower.endswith("_key")
        or lower == "key"
    )


def sanitized_headers(raw_headers: Any, reasons: list[UnsupportedReason], index: int, target_id: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    if not isinstance(raw_headers, dict):
        reasons.append(UnsupportedReason(index, target_id, "headers", raw_headers, "headers must be an object with string keys and values", "invalid_headers"))
        return headers
    for key, value in raw_headers.items():
        if not isinstance(key, str) or not isinstance(value, str):
            reasons.append(UnsupportedReason(index, target_id, "headers", raw_headers, "headers must have string keys and values", "invalid_headers"))
            continue
        if key.lower() in HOP_BY_HOP_HEADERS:
            reasons.append(UnsupportedReason(index, target_id, f"headers.{key}", value, "hop-by-hop or transport-controlled header is not supported", "unsupported_header"))
            continue
        if sensitive_header_name(key):
            reasons.append(UnsupportedReason(index, target_id, f"headers.{key}", "<redacted>", "literal sensitive header values must use a future auth_ref resolver and are not supported by this runner", "sensitive_header"))
            continue
        if header_value_looks_unresolved(value):
            reasons.append(UnsupportedReason(index, target_id, f"headers.{key}", "<redacted>", "header value appears to contain an unresolved secret/template reference", "unresolved_header_secret"))
            continue
        headers[key] = value
    return headers


def prepare_body(request: dict[str, Any], reasons: list[UnsupportedReason], index: int, target_id: str, method: str) -> tuple[bytes | None, dict[str, Any]]:
    body = request.get("body")
    metadata: dict[str, Any] = {"present": body is not None, "kind": None, "content_type": None, "sha256": None, "size_bytes": 0}
    if body is None:
        if method == "POST":
            reasons.append(UnsupportedReason(index, target_id, "body", None, "POST requires body.kind=json in phase2 runner", "unsupported_body"))
        return None, metadata
    if not isinstance(body, dict):
        reasons.append(UnsupportedReason(index, target_id, "body", body, "body must be an object", "invalid_body"))
        return None, metadata
    kind = body.get("kind")
    metadata["kind"] = kind
    if kind in (None, "none"):
        if method == "POST":
            reasons.append(UnsupportedReason(index, target_id, "body.kind", kind, "POST requires body.kind=json in phase2 runner", "unsupported_body"))
        return None, metadata
    if kind != "json":
        reasons.append(UnsupportedReason(index, target_id, "body.kind", kind, "only body.kind=json is supported in phase2 runner", "unsupported_body"))
        return None, metadata
    if method != "POST":
        reasons.append(UnsupportedReason(index, target_id, "body.kind", kind, "JSON body execution is only supported for POST", "unsupported_body"))
        return None, metadata
    value = body.get("value")
    if value is None:
        reasons.append(UnsupportedReason(index, target_id, "body.value", None, "body.kind=json requires body.value", "invalid_body"))
        return None, metadata
    content_type = body.get("content_type") or "application/json"
    if not isinstance(content_type, str) or "application/json" not in content_type.lower():
        reasons.append(UnsupportedReason(index, target_id, "body.content_type", content_type, "JSON body requires application/json content type", "unsupported_body"))
        return None, metadata
    encoded = compact_json_bytes(value)
    metadata.update({"content_type": content_type, "sha256": sha256_bytes(encoded), "size_bytes": len(encoded)})
    return encoded, metadata


def validate_graphql(request: dict[str, Any], body_bytes: bytes | None, reasons: list[UnsupportedReason], index: int, target_id: str, method: str) -> dict[str, Any] | None:
    graphql = request.get("graphql")
    if graphql is None:
        return None
    if not isinstance(graphql, dict):
        reasons.append(UnsupportedReason(index, target_id, "graphql", graphql, "graphql metadata must be an object", "invalid_graphql"))
        return None
    if graphql.get("query_ref") is not None:
        reasons.append(UnsupportedReason(index, target_id, "graphql.query_ref", graphql.get("query_ref"), "graphql.query_ref resolver is not implemented", "unsupported_graphql"))
    if graphql.get("operation_type") != "query":
        reasons.append(UnsupportedReason(index, target_id, "graphql.operation_type", graphql.get("operation_type"), "only GraphQL query operations are supported in phase2 runner", "unsupported_graphql"))
    body = request.get("body") if isinstance(request.get("body"), dict) else {}
    value = body.get("value") if isinstance(body, dict) else None
    if method != "POST" or body_bytes is None or not isinstance(value, dict) or not isinstance(value.get("query"), str):
        reasons.append(UnsupportedReason(index, target_id, "graphql", graphql, "GraphQL execution requires POST body.kind=json with inline body.value.query", "unsupported_graphql"))
    return {
        "operation_type": graphql.get("operation_type"),
        "operation_name": graphql.get("operation_name"),
        "variables_sha256": sha256_bytes(compact_json_bytes(graphql.get("variables"))) if graphql.get("variables") is not None else None,
    }


def browser_fallback_capability_summary() -> dict[str, Any]:
    return {
        "implemented": False,
        "default_mode": "never",
        "recognized_modes": ["never", "reasoned"],
        "enabled_modes": ["never"],
        "reasoned_mode": "fail_closed_until_websocket_cdp_artifact_gate",
        "websocket_cdp": "not_implemented",
        "pipe_transport": "fail_closed",
        "artifact_capture": "blocked_until_browser_runtime_proof",
        "challenge_policy": "classify_and_stop_no_stealth_or_captcha_bypass",
    }


def validate_browser_fallback(request: dict[str, Any], reasons: list[UnsupportedReason], index: int, target_id: str) -> None:
    fallback = request.get("browser_fallback")
    if fallback is None:
        return
    if not isinstance(fallback, dict):
        reasons.append(UnsupportedReason(index, target_id, "browser_fallback", fallback, "browser_fallback must be an object", "invalid_browser_fallback"))
        return
    if "mode" not in fallback:
        return
    mode = fallback["mode"]
    if isinstance(mode, str):
        if mode == "never":
            return
        if mode == "reasoned":
            reasons.append(UnsupportedReason(index, target_id, "browser_fallback.mode", mode, "reasoned browser fallback is recognized but fail-closed until WebSocket CDP execution, artifact capture, budget, and challenge-classification proofs are implemented", "live_browser_fallback_not_enabled"))
        else:
            reasons.append(UnsupportedReason(index, target_id, "browser_fallback.mode", mode, "browser_fallback.mode must be never or reasoned; reasoned is currently fail-closed", "unsupported_browser_fallback"))
    else:
        reasons.append(UnsupportedReason(index, target_id, "browser_fallback.mode", mode, "browser_fallback.mode must be a string value: never or reasoned", "invalid_browser_fallback"))


def validate_artifact_policy(request: dict[str, Any], reasons: list[UnsupportedReason], index: int, target_id: str) -> dict[str, Any] | None:
    policy = request.get("artifact_policy")
    if policy is None:
        return None
    if not isinstance(policy, dict):
        reasons.append(UnsupportedReason(index, target_id, "artifact_policy", policy, "artifact_policy must be an object", "invalid_artifact_policy"))
        return None
    capture_body = policy.get("capture_body", "none")
    if capture_body not in {"none", "redacted"}:
        reasons.append(UnsupportedReason(index, target_id, "artifact_policy.capture_body", capture_body, "only capture_body=none/redacted is supported in phase2 runner", "unsupported_artifact_policy"))
    screenshots = policy.get("screenshots", "never")
    if screenshots != "never":
        reasons.append(UnsupportedReason(index, target_id, "artifact_policy.screenshots", screenshots, "browser screenshot artifacts require browser runtime and are fail-closed until local proofs exist", "browser_artifact_capture_not_enabled"))
    har = policy.get("har", "never")
    if har != "never":
        reasons.append(UnsupportedReason(index, target_id, "artifact_policy.har", har, "browser HAR artifacts require browser/network capture runtime and are fail-closed until local proofs exist", "browser_artifact_capture_not_enabled"))
    dom = policy.get("dom", "never")
    if dom != "never":
        reasons.append(UnsupportedReason(index, target_id, "artifact_policy.dom", dom, "browser DOM artifacts require browser runtime and are fail-closed until local proofs exist", "browser_artifact_capture_not_enabled"))
    snippet = policy.get("response_snippet_bytes", 0)
    if snippet is not None and (not isinstance(snippet, int) or snippet < 0):
        reasons.append(UnsupportedReason(index, target_id, "artifact_policy.response_snippet_bytes", snippet, "response_snippet_bytes must be a non-negative integer", "invalid_artifact_policy"))
    return policy


def retry_config(request: dict[str, Any], reasons: list[UnsupportedReason], index: int, target_id: str) -> dict[str, Any] | None:
    retry = request.get("retry")
    if retry is None:
        return None
    if not isinstance(retry, dict):
        reasons.append(UnsupportedReason(index, target_id, "retry", retry, "retry must be an object", "invalid_retry"))
        return None
    max_attempts = retry.get("max_attempts", 1)
    if not isinstance(max_attempts, int) or max_attempts < 1 or max_attempts > 10:
        reasons.append(UnsupportedReason(index, target_id, "retry.max_attempts", max_attempts, "max_attempts must be an integer from 1 to 10", "invalid_retry"))
    backoff_ms = retry.get("backoff_ms", [])
    if backoff_ms is not None and not isinstance(backoff_ms, list):
        reasons.append(UnsupportedReason(index, target_id, "retry.backoff_ms", backoff_ms, "backoff_ms must be an array", "invalid_retry"))
    retry_on = retry.get("retry_on_error_kinds", [])
    if retry_on is not None and not isinstance(retry_on, list):
        reasons.append(UnsupportedReason(index, target_id, "retry.retry_on_error_kinds", retry_on, "retry_on_error_kinds must be an array", "invalid_retry"))
    return retry


def prepare_requests(plan: dict[str, Any], mock_base_url: str | None, network_scope: str) -> tuple[list[PreparedRequest], list[UnsupportedReason]]:
    prepared: list[PreparedRequest] = []
    reasons: list[UnsupportedReason] = []
    supported_methods = contract_supported_methods()
    for index, request in enumerate(plan.get("requests", [])):
        target_id = str(request.get("target_id") or f"request_{index}")
        method = str(request.get("method") or "").upper()
        original_url = str(request.get("url") or "")
        if method not in supported_methods:
            reasons.append(UnsupportedReason(index, target_id, "method", method, f"only {', '.join(sorted(supported_methods))} are supported by the request-plan execution contract", "unsupported_method"))
        try:
            executed_url = rewrite_url(original_url, mock_base_url)
            parsed_executed = parse_url(executed_url)
            if network_scope == "local":
                if not is_loopback_host(parsed_executed.hostname):
                    reasons.append(UnsupportedReason(index, target_id, "url", original_url, "external_network_disabled: only loopback URLs are allowed without a future live gate", "external_network_disabled"))
            elif network_scope in {"live-preflight", "live"}:
                pass
            else:
                reasons.append(UnsupportedReason(index, target_id, "network_scope", network_scope, "unsupported network scope", "unsupported_network_scope"))
        except ValueError as exc:
            executed_url = original_url
            reasons.append(UnsupportedReason(index, target_id, "url", original_url, str(exc), "invalid_url"))
        headers = sanitized_headers(request.get("headers", {}), reasons, index, target_id)
        body_bytes, body_metadata = prepare_body(request, reasons, index, target_id, method)
        graphql = validate_graphql(request, body_bytes, reasons, index, target_id, method)
        vault_reference = classify_vault_reference(request.get("auth_ref"), reasons, index, target_id)
        validate_browser_fallback(request, reasons, index, target_id)
        artifact_policy = validate_artifact_policy(request, reasons, index, target_id)
        retry = retry_config(request, reasons, index, target_id)
        compliance = request.get("compliance") if isinstance(request.get("compliance"), dict) else {}

        prepared.append(
            PreparedRequest(
                index=index,
                target_id=target_id,
                method=method,
                original_url=original_url,
                executed_url=executed_url,
                headers=headers,
                body_bytes=body_bytes,
                body_metadata=body_metadata,
                graphql=graphql,
                compliance=compliance,
                retry=retry,
                artifact_policy=artifact_policy,
                extraction_schema_ref=request.get("extraction_schema_ref"),
                vault_reference=vault_reference,
            )
        )
    return prepared, reasons


def classify_error(http_status: int | None, exc: BaseException | None) -> str:
    if exc is not None:
        if isinstance(exc, TimeoutError):
            return "timeout"
        return "transport"
    if http_status == 429:
        return "rate_limited"
    if http_status in {401, 403}:
        return "auth"
    if http_status is None:
        return "unknown"
    if 500 <= http_status <= 599:
        return "http_5xx"
    if 400 <= http_status <= 499:
        return "http_4xx"
    return "none"


def canonical_error_kind(kind: str | None) -> str:
    raw = str(kind or "unknown")
    mapping = {
        "network_error": "transport",
        "http_429": "rate_limited",
        "server": "http_5xx",
        "policy_blocked": "robots_policy",
        "policy_denylist": "robots_policy",
        "policy_allowlist": "robots_policy",
        "policy_missing": "robots_policy",
        "policy_robots": "robots_policy",
        "policy_robots_off_requires_approval": "robots_policy",
        "policy_rate_limit": "robots_policy",
        "external_network_disabled": "robots_policy",
        "live_approval_required": "robots_policy",
        "compliance_gate_report_required": "robots_policy",
        "compliance_gate_report_invalid": "robots_policy",
        "compliance_gate_report_failed": "robots_policy",
        "compliance_gate_legal_metadata_missing": "robots_policy",
        "sensitive_header": "robots_policy",
        "source_manifest_missing": "robots_policy",
        "source_manifest_invalid": "robots_policy",
        "source_manifest_sha256": "robots_policy",
        "source_manifest_target_mismatch": "robots_policy",
        "policy_compliance": "robots_policy",
        "live_execution_disabled": "robots_policy",
        "inline_auth_ref": "auth",
        "unsupported_vault_provider": "auth",
        "unresolved_header_secret": "auth",
        "unsupported_provider_fail_closed": "auth",
        "browser_artifact_capture_not_enabled": "browser",
        "live_browser_fallback_not_enabled": "browser",
        "unsupported_browser_fallback": "browser",
        "invalid_browser_fallback": "browser",
        "unsupported_method": "validation",
        "invalid_method": "validation",
        "invalid_url": "validation",
        "invalid_body": "validation",
        "invalid_graphql": "validation",
        "invalid_retry": "validation",
        "invalid_artifact_policy": "validation",
        "unsupported_artifact_policy": "validation",
        "unsupported_network_scope": "validation",
        "invalid_headers": "validation",
        "unsupported_header": "validation",
        "unsupported_body": "validation",
        "unsupported_graphql": "validation",
        "extraction_schema_invalid": "validation",
        "multiple_extraction_schemas": "validation",
    }
    canonical = mapping.get(raw, raw)
    if canonical in {
        "none",
        "transport",
        "dns",
        "tls",
        "timeout",
        "http_4xx",
        "auth",
        "rate_limited",
        "http_5xx",
        "robots_policy",
        "browser",
        "extraction",
        "validation",
        "body_too_large",
        "storage",
        "internal",
        "unknown",
    }:
        return canonical
    return "unknown"


def canonical_error_object(kind: str | None, message: str | None, retryable: bool, policy_blocked: bool, source_target_id: str | None, url: str | None, phase: str) -> dict[str, Any]:
    canonical = canonical_error_kind(kind)
    return {
        "kind": canonical,
        "message": message or ("no error" if canonical == "none" else "unspecified error"),
        "retryable": bool(retryable),
        "policy_blocked": bool(policy_blocked),
        "source_target_id": source_target_id,
        "url": url,
        "phase": phase,
    }


def error_from_reasons(prepared: PreparedRequest, reasons: list[UnsupportedReason], phase: str) -> dict[str, Any]:
    row_reasons = [reason for reason in reasons if reason.index == prepared.index]
    if not row_reasons:
        return canonical_error_object("none", "no error", False, False, prepared.target_id, prepared.original_url, phase)
    first_code = row_reasons[0].code
    policy_blocked = any(canonical_error_kind(reason.code) in {"robots_policy", "auth", "browser"} for reason in row_reasons)
    message = "; ".join(reason.reason for reason in row_reasons)
    return canonical_error_object(first_code, message, False, policy_blocked, prepared.target_id, prepared.original_url, phase)


def should_retry(error_kind: str, retry: dict[str, Any] | None) -> bool:
    if not retry:
        return False
    retry_on = retry.get("retry_on_error_kinds") or []
    return error_kind in retry_on


def retry_backoff_seconds(retry: dict[str, Any] | None, attempt_index: int) -> float:
    if not retry:
        return 0.0
    backoff = retry.get("backoff_ms") or []
    if not isinstance(backoff, list) or not backoff:
        return 0.0
    raw = backoff[min(attempt_index, len(backoff) - 1)]
    if isinstance(raw, (int, float)) and raw > 0:
        return min(float(raw) / 1000.0, 2.0)
    return 0.0


def request_dir(output_dir: Path, prepared: PreparedRequest) -> Path:
    return output_dir / "requests" / f"{prepared.index:04d}-{sanitize_id(prepared.target_id)}"


def write_request_artifact(output_dir: Path, prepared: PreparedRequest) -> str:
    req_dir = request_dir(output_dir, prepared)
    req_dir.mkdir(parents=True, exist_ok=True)
    artifact = {
        "schema_version": "tallow.request_plan_request_artifact.v1",
        "index": prepared.index,
        "target_id": prepared.target_id,
        "method": prepared.method,
        "original_url": prepared.original_url,
        "executed_url": prepared.executed_url,
        "headers_redacted": True,
        "header_names": sorted(prepared.headers),
        "body": prepared.body_metadata,
        "graphql": prepared.graphql,
        "auth_ref_present": prepared.vault_reference is not None,
        "vault_reference": prepared.vault_reference,
        "compliance": {
            "source_authority": prepared.compliance.get("source_authority"),
            "legal_basis": prepared.compliance.get("legal_basis"),
            "purpose": prepared.compliance.get("purpose"),
            "pii_policy": prepared.compliance.get("pii_policy"),
            "robots_mode": prepared.compliance.get("robots_mode"),
            "retention_days": prepared.compliance.get("retention_days"),
        },
    }
    rel = Path("requests") / f"{prepared.index:04d}-{sanitize_id(prepared.target_id)}" / "request.redacted.json"
    (output_dir / rel).write_text(stable_json(artifact), encoding="utf-8")
    return str(rel)


SENSITIVE_RESPONSE_KEYS = {
    "authorization",
    "cookie",
    "set-cookie",
    "token",
    "access_token",
    "refresh_token",
    "password",
    "secret",
    "api_key",
    "apikey",
    "query",
}


def redaction_marker(value: Any) -> str:
    encoded = compact_json_bytes(value) if not isinstance(value, bytes) else value
    return f"<redacted:sha256:{sha256_bytes(encoded)}>"


def redact_json_value(value: Any) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            if key_text.lower() in SENSITIVE_RESPONSE_KEYS or sensitive_header_name(key_text):
                redacted[key_text] = redaction_marker(item)
            else:
                redacted[key_text] = redact_json_value(item)
        return redacted
    if isinstance(value, list):
        return [redact_json_value(item) for item in value]
    return value


def redact_response_body(body: bytes, content_type: str | None) -> bytes:
    if not body:
        return body
    content_type_lc = (content_type or "").lower()
    text = body.decode("utf-8", errors="replace")
    if "json" in content_type_lc or text.lstrip().startswith(("{", "[")):
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            pass
        else:
            return compact_json_bytes(redact_json_value(parsed))
    # Last-resort scrub for text bodies that echo GraphQL operations outside JSON.
    text = re.sub(r"\b(query|mutation)\s+[A-Za-z0-9_]+[^\n\r]*", lambda match: redaction_marker(match.group(0)), text)
    return text.encode("utf-8")


def redact_plan_snapshot_value(value: Any, path: tuple[str, ...] = ()) -> Any:
    if isinstance(value, dict):
        redacted: dict[str, Any] = {}
        for key, item in value.items():
            key_text = str(key)
            key_lc = key_text.lower()
            parent = path[-1].lower() if path else ""
            if key_lc == "auth_ref" or (parent == "headers" and sensitive_header_name(key_text)) or (parent == "body" and key_lc == "value"):
                redacted[key_text] = redaction_marker(item)
            else:
                redacted[key_text] = redact_plan_snapshot_value(item, (*path, key_text))
        return redacted
    if isinstance(value, list):
        return [redact_plan_snapshot_value(item, path) for item in value]
    return value


def write_response_artifacts(output_dir: Path, prepared: PreparedRequest, final: dict[str, Any], max_response_bytes: int) -> dict[str, str | None]:
    req_dir = request_dir(output_dir, prepared)
    req_dir.mkdir(parents=True, exist_ok=True)
    body = final.get("body_bytes") or b""
    if not isinstance(body, bytes):
        body = b""
    body_sha = sha256_bytes(body)
    metadata_rel = Path("requests") / f"{prepared.index:04d}-{sanitize_id(prepared.target_id)}" / "response.metadata.json"
    capture = "none"
    body_rel: Path | None = None
    policy = prepared.artifact_policy or {}
    capture_body = policy.get("capture_body", "none")
    snippet_bytes = policy.get("response_snippet_bytes", 0)
    redacted_body_sha: str | None = None
    if capture_body == "redacted":
        capture = "redacted"
        limit = min(int(snippet_bytes or 4096), max_response_bytes)
        body_rel = Path("requests") / f"{prepared.index:04d}-{sanitize_id(prepared.target_id)}" / "response.body.redacted.txt"
        redacted_body = redact_response_body(body, final.get("content_type"))[:limit]
        redacted_body_sha = sha256_bytes(redacted_body)
        (output_dir / body_rel).write_bytes(redacted_body)
    metadata = {
        "schema_version": "tallow.request_plan_response_artifact.v1",
        "index": prepared.index,
        "target_id": prepared.target_id,
        "attempt_index": final.get("attempts", 1),
        "status_code": final.get("http_status") or 0,
        "final_url": prepared.executed_url,
        "headers_redacted": True,
        "response_header_names": sorted((final.get("headers") or {}).keys()),
        "body_size": len(body),
        "body_sha256": body_sha,
        "redacted_body_sha256": redacted_body_sha,
        "body_capture": capture,
        "content_type": final.get("content_type"),
        "duration_ms": final.get("duration_ms"),
        "error_kind": final.get("error_kind"),
        "retryable": final.get("retryable"),
        "body_artifact": str(body_rel) if body_rel else None,
    }
    (output_dir / metadata_rel).write_text(stable_json(metadata), encoding="utf-8")
    return {"response_metadata": str(metadata_rel), "response_body": str(body_rel) if body_rel else None}



def resolve_extraction_schema_path(ref: Any) -> Path:
    if not isinstance(ref, str) or not ref.strip():
        raise ValueError("extraction_schema_ref must be a non-empty string")
    path = Path(ref)
    if not path.is_absolute():
        path = ROOT / path
    resolved = path.resolve()
    root = ROOT.resolve()
    if not resolved.is_relative_to(root):
        raise ValueError("extraction_schema_ref must resolve inside the repository schema registry")
    return resolved


@lru_cache(maxsize=32)
def load_extraction_schema(ref: str) -> tuple[Path, dict[str, Any]]:
    path = resolve_extraction_schema_path(ref)
    if not path.exists() or not path.is_file():
        raise ValueError("extraction_schema_ref must point to a readable JSON schema file")
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("extraction schema must be a JSON object")
    if data.get("schema_version") != "tallow.extraction_schema.v1":
        raise ValueError("extraction schema_version must be tallow.extraction_schema.v1")
    if not isinstance(data.get("schema_id"), str) or not data.get("schema_id"):
        raise ValueError("extraction schema_id must be a non-empty string")
    if not isinstance(data.get("entity"), str) or not data.get("entity"):
        raise ValueError("extraction schema entity must be a non-empty string")
    fields = data.get("fields")
    if not isinstance(fields, list) or not fields:
        raise ValueError("extraction schema fields must be a non-empty array")
    return path, data


def validate_extraction_references(prepared: list[PreparedRequest]) -> list[UnsupportedReason]:
    reasons: list[UnsupportedReason] = []
    schema_paths: set[Path] = set()
    for req in prepared:
        if req.extraction_schema_ref is None:
            continue
        try:
            schema_path, _schema = load_extraction_schema(str(req.extraction_schema_ref))
            schema_paths.add(schema_path)
        except Exception as exc:  # noqa: BLE001 - surfaced in blocked report
            reasons.append(
                UnsupportedReason(
                    req.index,
                    req.target_id,
                    "extraction_schema_ref",
                    str(req.extraction_schema_ref),
                    f"extraction schema could not be loaded: {exc}",
                    "extraction_schema_invalid",
                )
            )
    if len(schema_paths) > 1:
        for req in prepared:
            if req.extraction_schema_ref is not None:
                reasons.append(
                    UnsupportedReason(
                        req.index,
                        req.target_id,
                        "extraction_schema_ref",
                        str(req.extraction_schema_ref),
                        "this runtime slice supports one extraction schema per request-plan run",
                        "multiple_extraction_schemas",
                    )
                )
    return reasons


def json_path_values(data: Any, path: str) -> list[Any]:
    if not path.startswith("$."):
        return []
    values: list[Any] = [data]
    for raw_part in path[2:].split("."):
        next_values: list[Any] = []
        is_array = raw_part.endswith("[*]")
        key = raw_part[:-3] if is_array else raw_part
        for item in values:
            if isinstance(item, dict) and key in item:
                value = item[key]
                if is_array:
                    if isinstance(value, list):
                        next_values.extend(value)
                else:
                    next_values.append(value)
            elif isinstance(item, list):
                for element in item:
                    if isinstance(element, dict) and key in element:
                        value = element[key]
                        if is_array and isinstance(value, list):
                            next_values.extend(value)
                        elif not is_array:
                            next_values.append(value)
        values = next_values
        if not values:
            break
    return values


def strip_tags(value: str) -> str:
    text = re.sub(r"<[^>]+>", " ", value)
    return html.unescape(re.sub(r"\s+", " ", text).strip())


def css_class_values(text: str, selector: str, attribute: str | None) -> list[Any]:
    classes = re.findall(r"\.([A-Za-z0-9_-]+)", selector)
    if not classes:
        return []
    target_class = classes[-1]
    class_attr = rf"class=[\"'][^\"']*\b{re.escape(target_class)}\b[^\"']*[\"']"
    if attribute:
        attr = re.escape(attribute)
        pattern = rf"<(?P<tag>[A-Za-z0-9:-]+)(?=[^>]*{class_attr})[^>]*\s{attr}=[\"'](?P<value>[^\"']*)[\"'][^>]*>"
        return [html.unescape(match.group("value")) for match in re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL)]
    pattern = rf"<(?P<tag>[A-Za-z0-9:-]+)(?=[^>]*{class_attr})[^>]*>(?P<body>.*?)</(?P=tag)>"
    return [strip_tags(match.group("body")) for match in re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL)]


def meta_values(text: str, selector: str) -> list[Any]:
    escaped = re.escape(selector)
    patterns = [
        rf"<meta[^>]+name=[\"']{escaped}[\"'][^>]+content=[\"'](?P<value>[^\"']*)[\"'][^>]*>",
        rf"<meta[^>]+property=[\"']{escaped}[\"'][^>]+content=[\"'](?P<value>[^\"']*)[\"'][^>]*>",
    ]
    values: list[Any] = []
    for pattern in patterns:
        values.extend(html.unescape(match.group("value")) for match in re.finditer(pattern, text, flags=re.IGNORECASE | re.DOTALL))
    return values


def selector_values(data: Any, text: str, selector: dict[str, Any]) -> list[Any]:
    kind = selector.get("kind")
    value = selector.get("value")
    if not isinstance(kind, str) or not isinstance(value, str):
        return []
    if kind == "json_path":
        return json_path_values(data, value) if data is not None else []
    if kind == "css":
        attribute = selector.get("attribute")
        return css_class_values(text, value, attribute if isinstance(attribute, str) else None)
    if kind == "regex":
        try:
            return [match.group(1) if match.groups() else match.group(0) for match in re.finditer(value, text)]
        except re.error:
            return []
    if kind == "meta":
        return meta_values(text, value)
    if kind == "literal" and value == "source_url":
        return []
    return []


def coerce_extracted_value(value: Any, field_type: str, coercion: Any) -> Any:
    steps = coercion if isinstance(coercion, list) else []
    result = value
    if isinstance(result, str):
        if "trim" in steps:
            result = result.strip()
        if "normalize_whitespace" in steps:
            result = re.sub(r"\s+", " ", result).strip()
    if field_type == "money" and isinstance(result, str) and "parse_money" in steps:
        cleaned = result.replace("$", "").replace(",", "").strip()
        try:
            amount = float(cleaned)
        except ValueError:
            return result
        return {"amount": amount, "cents": int(round(amount * 100))}
    return result


def parse_response_payload(body: bytes, content_type: str | None) -> tuple[Any, str]:
    text = body.decode("utf-8", errors="replace")
    content_type_lc = (content_type or "").lower()
    if "json" in content_type_lc or text.lstrip().startswith(("{", "[")):
        try:
            return json.loads(text), text
        except json.JSONDecodeError:
            return None, text
    return None, text


def build_field_cells(schema: dict[str, Any], payload: Any, text: str, row_index: int, source_url: str) -> tuple[dict[str, Any], int, float, list[str]]:
    cells: dict[str, Any] = {}
    required_null_count = 0
    confidence_values: list[float] = []
    quarantine_reasons: list[str] = []
    fields = [field for field in schema.get("fields", []) if isinstance(field, dict)]
    for field in fields:
        name = str(field.get("name") or "field")
        field_type = str(field.get("type") or "string")
        required = bool(field.get("required"))
        selected_value: Any = None
        selector_kind: str | None = None
        selector_text: str | None = None
        selector_confidence = 0.0
        found = False
        selectors = sorted(
            [selector for selector in field.get("selectors", []) if isinstance(selector, dict)],
            key=lambda selector: int(selector.get("priority") or 0),
        )
        for selector in selectors:
            values = selector_values(payload, text, selector)
            if not values:
                continue
            if row_index >= len(values):
                continue
            selected_value = coerce_extracted_value(values[row_index], field_type, field.get("coercion"))
            selector_kind = str(selector.get("kind"))
            selector_text = str(selector.get("value"))
            hint = selector.get("confidence_hint")
            selector_confidence = float(hint) if isinstance(hint, (int, float)) else 0.9
            found = selected_value is not None and selected_value != ""
            break
        if not found and field_type == "url" and any(isinstance(step, str) and step == "parse_url" for step in (field.get("coercion") or [])):
            selected_value = source_url
            selector_kind = "literal"
            selector_text = "source_url"
            selector_confidence = 0.75
            found = True
        if found:
            confidence_values.append(selector_confidence)
            null_reason = None
        else:
            selected_value = None
            selector_confidence = 0.0
            null_reason = "missing"
            quarantine_reasons.append(f"selector_miss:{name}")
            if required:
                required_null_count += 1
                quarantine_reasons.append(f"required_field_null:{name}")
        cells[name] = {
            "value": selected_value,
            "type": field_type,
            "required": required,
            "confidence": selector_confidence,
            "null_reason": null_reason,
            "selector_kind": selector_kind,
            "selector": selector_text,
            "degraded": not found,
            "source_evidence": (f"method:{selector_kind};selector:{selector_text}" if found else "selector_miss")[:256],
        }
    min_confidence = float((schema.get("quality") or {}).get("min_row_confidence", 0.0)) if isinstance(schema.get("quality"), dict) else 0.0
    row_confidence = min(confidence_values) if confidence_values else 0.0
    if row_confidence < min_confidence:
        quarantine_reasons.append("row_confidence_below_min")
    selector_health = len(confidence_values) / max(len(fields), 1)
    return cells, required_null_count, selector_health, sorted(set(quarantine_reasons))


def extraction_row_count(schema: dict[str, Any], payload: Any, text: str) -> int:
    max_count = 0
    for field in schema.get("fields", []):
        if not isinstance(field, dict):
            continue
        for selector in field.get("selectors", []):
            if isinstance(selector, dict):
                max_count = max(max_count, len(selector_values(payload, text, selector)))
    return max(max_count, 1)


def extract_rows_for_response(prepared: PreparedRequest, final: dict[str, Any], generated_at: datetime) -> tuple[list[dict[str, Any]], list[dict[str, Any]], Path | None]:
    if prepared.extraction_schema_ref is None or not final.get("success"):
        return [], [], None
    schema_path, schema = load_extraction_schema(str(prepared.extraction_schema_ref))
    body = final.get("body_bytes") or b""
    if not isinstance(body, bytes):
        body = b""
    payload, text = parse_response_payload(body, final.get("content_type"))
    rows: list[dict[str, Any]] = []
    quarantine: list[dict[str, Any]] = []
    row_count = extraction_row_count(schema, payload, text)
    schema_quality = schema.get("quality") if isinstance(schema.get("quality"), dict) else {}
    max_required_nulls = int(schema_quality.get("max_null_required_fields", 0))
    min_row_confidence = float(schema_quality.get("min_row_confidence", 0.0))
    for idx in range(row_count):
        cells, required_null_count, selector_health, reasons = build_field_cells(schema, payload, text, idx, prepared.original_url)
        confidence_values = [float(cell["confidence"]) for cell in cells.values() if isinstance(cell.get("confidence"), (int, float)) and float(cell["confidence"]) > 0]
        row_confidence = min(confidence_values) if confidence_values else 0.0
        should_quarantine = required_null_count > max_required_nulls or row_confidence < min_row_confidence
        status = "quarantined" if should_quarantine else "accepted"
        row = {
            "schema_version": "tallow.extraction_row.v1",
            "row_id": sanitize_id(f"{prepared.target_id}-{schema.get('schema_id')}-{idx}"),
            "run_id": "request_plan_runner",
            "target_id": prepared.target_id,
            "source_url": prepared.original_url,
            "extraction_schema_id": schema.get("schema_id"),
            "extraction_schema_version": schema.get("schema_version"),
            "entity": schema.get("entity"),
            "row_index": idx,
            "extracted_at_utc": iso_utc(generated_at),
            "mode": "local_mock",
            "status": status,
            "row_confidence": row_confidence,
            "fields": cells,
            "quality": {
                "required_null_count": required_null_count,
                "selector_health": selector_health,
                "drift_detected": bool(reasons),
                "quarantine_reasons": reasons if should_quarantine else [],
            },
            "non_claims": {
                "live_scraping": False,
                "external_dataset": False,
                "production_ready": False,
            },
        }
        rows.append(row)
        if status == "quarantined":
            quarantine.append(row)
    return rows, quarantine, schema_path


def write_jsonl_rows(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def write_extraction_artifacts(output_dir: Path, extracted: list[tuple[PreparedRequest, dict[str, Any]]], generated_at: datetime) -> tuple[dict[str, Any] | None, int, int]:
    extraction_rows: list[dict[str, Any]] = []
    quarantine_rows: list[dict[str, Any]] = []
    schema_path: Path | None = None
    for prepared, final in extracted:
        rows, quarantine, current_schema_path = extract_rows_for_response(prepared, final, generated_at)
        extraction_rows.extend(rows)
        quarantine_rows.extend(quarantine)
        if current_schema_path is not None:
            schema_path = current_schema_path
    if schema_path is None:
        return None, 0, 0
    rows_rel = Path("extraction") / "rows.jsonl"
    quarantine_rel = Path("extraction") / "quarantine.jsonl"
    validation_rel = Path("extraction") / "validation_report.json"
    rows_path = output_dir / rows_rel
    quarantine_path = output_dir / quarantine_rel
    validation_path = output_dir / validation_rel
    write_jsonl_rows(rows_path, extraction_rows)
    write_jsonl_rows(quarantine_path, quarantine_rows)
    proc = subprocess.run(
        [
            sys.executable,
            str(ROOT / EXTRACTION_VALIDATOR_REL_PATH),
            "--schema",
            str(schema_path),
            "--row-schema",
            str(ROOT / EXTRACTION_ROW_SCHEMA_REL_PATH),
            "--rows",
            str(rows_path),
            "--quarantine-path",
            str(quarantine_path),
            "--report-path",
            str(validation_path),
        ],
        cwd=ROOT,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if proc.returncode != 0:
        raise RunnerError(f"extraction row validation failed: {proc.stdout}{proc.stderr}")
    return {
        "schema": display_path(schema_path),
        "rows": str(rows_rel),
        "quarantine": str(quarantine_rel),
        "validation_report": str(validation_rel),
    }, len(extraction_rows), len(quarantine_rows)


def perform_attempt(prepared: PreparedRequest, timeout_seconds: float, max_response_bytes: int) -> dict[str, Any]:
    started = time.monotonic()
    headers = dict(prepared.headers)
    data = prepared.body_bytes
    if data is not None and not any(key.lower() == "content-type" for key in headers):
        content_type = prepared.body_metadata.get("content_type") or "application/json"
        headers["Content-Type"] = str(content_type)
    req = urllib.request.Request(prepared.executed_url, data=data, headers=headers, method=prepared.method)
    status: int | None = None
    body = b""
    response_headers: dict[str, str] = {}
    exc: BaseException | None = None
    try:
        with urllib.request.urlopen(req, timeout=timeout_seconds) as resp:
            status = int(resp.status)
            response_headers = {key: value for key, value in resp.headers.items()}
            body = resp.read(max_response_bytes + 1)
    except urllib.error.HTTPError as err:
        status = int(err.code)
        response_headers = {key: value for key, value in err.headers.items()}
        body = err.read(max_response_bytes + 1)
    except (urllib.error.URLError, TimeoutError, OSError) as err:
        exc = err
    duration_ms = int((time.monotonic() - started) * 1000)
    too_large = len(body) > max_response_bytes
    if too_large:
        body = body[:max_response_bytes]
    error_kind = "body_too_large" if too_large else classify_error(status, exc)
    success = status is not None and 200 <= status <= 399 and not too_large and exc is None
    return {
        "success": success,
        "http_status": status,
        "body_bytes": body,
        "headers": response_headers,
        "content_type": response_headers.get("Content-Type") or response_headers.get("content-type"),
        "duration_ms": duration_ms,
        "error_kind": error_kind,
        "error_message": str(exc) if exc is not None else None,
        "retryable": error_kind in {"http_5xx", "rate_limited", "timeout", "transport"},
    }


def execute_request(output_dir: Path, prepared: PreparedRequest, timeout_seconds: float, max_response_bytes: int) -> tuple[dict[str, Any], dict[str, Any]]:
    write_request_artifact(output_dir, prepared)
    retry = prepared.retry
    max_attempts = int(retry.get("max_attempts", 1)) if retry else 1
    attempts: list[dict[str, Any]] = []
    final: dict[str, Any] | None = None
    for attempt_index in range(max_attempts):
        attempt = perform_attempt(prepared, timeout_seconds, max_response_bytes)
        attempts.append({
            "attempt": attempt_index + 1,
            "http_status": attempt.get("http_status"),
            "duration_ms": attempt.get("duration_ms"),
            "error_kind": attempt.get("error_kind"),
            "success": attempt.get("success"),
        })
        final = attempt
        if attempt["success"]:
            break
        if attempt_index >= max_attempts - 1 or not should_retry(str(attempt.get("error_kind")), retry):
            break
        backoff = retry_backoff_seconds(retry, attempt_index)
        if backoff > 0:
            time.sleep(backoff)
    assert final is not None
    artifact_paths = write_response_artifacts(output_dir, prepared, {**final, "attempts": len(attempts)}, max_response_bytes)
    body = final.get("body_bytes") or b""
    if not isinstance(body, bytes):
        body = b""
    status = "succeeded" if final["success"] else "failed"
    error = canonical_error_object(
        str(final.get("error_kind")),
        final.get("error_message") if isinstance(final.get("error_message"), str) else None,
        bool(final.get("retryable")),
        False,
        prepared.target_id,
        prepared.original_url,
        "request_execution",
    )
    row = {
        "index": prepared.index,
        "target_id": prepared.target_id,
        "method": prepared.method,
        "original_url": prepared.original_url,
        "executed_url": prepared.executed_url,
        "status": status,
        "attempts": len(attempts),
        "attempt_records": attempts,
        "http_status": final.get("http_status"),
        "body_len": len(body),
        "response_sha256": sha256_bytes(body) if body else None,
        "content_type": final.get("content_type"),
        "is_graphql": prepared.graphql is not None,
        "graphql": prepared.graphql,
        "auth_ref_present": prepared.vault_reference is not None,
        "vault_reference": prepared.vault_reference,
        "error_kind": final.get("error_kind"),
        "error_message": final.get("error_message"),
        "error": error,
        "retryable": final.get("retryable"),
        "artifacts": artifact_paths,
        "blocked_reasons": [],
    }
    return row, final


def blocked_request_row(prepared: PreparedRequest, reasons: list[UnsupportedReason]) -> dict[str, Any]:
    row_reasons = [reason for reason in reasons if reason.index == prepared.index]
    error = error_from_reasons(prepared, reasons, "request_policy")
    return {
        "index": prepared.index,
        "target_id": prepared.target_id,
        "method": prepared.method,
        "original_url": prepared.original_url,
        "executed_url": None,
        "status": "blocked",
        "attempts": 0,
        "http_status": None,
        "body_len": 0,
        "response_sha256": None,
        "content_type": None,
        "is_graphql": prepared.graphql is not None,
        "graphql": prepared.graphql,
        "auth_ref_present": prepared.vault_reference is not None,
        "vault_reference": prepared.vault_reference,
        "error_kind": error["kind"],
        "error_message": error["message"],
        "error": error,
        "artifacts": {"response_metadata": None, "response_body": None},
        "blocked_reasons": [reason.as_dict() for reason in row_reasons],
    }


def planned_request_row(prepared: PreparedRequest) -> dict[str, Any]:
    return {
        "index": prepared.index,
        "target_id": prepared.target_id,
        "method": prepared.method,
        "original_url": prepared.original_url,
        "executed_url": prepared.executed_url,
        "status": "planned",
        "attempts": 0,
        "http_status": None,
        "body_len": 0,
        "response_sha256": None,
        "content_type": None,
        "is_graphql": prepared.graphql is not None,
        "graphql": prepared.graphql,
        "auth_ref_present": prepared.vault_reference is not None,
        "vault_reference": prepared.vault_reference,
        "error_kind": "none",
        "error_message": None,
        "error": canonical_error_object("none", "no error", False, False, prepared.target_id, prepared.original_url, "request_planning"),
        "artifacts": {"response_metadata": None, "response_body": None},
        "blocked_reasons": [],
    }


def policy_preflight_request_row(prepared: PreparedRequest) -> dict[str, Any]:
    row = planned_request_row(prepared)
    row["status"] = "policy_preflight_passed"
    row["executed_url"] = None
    row["error_kind"] = "none"
    return row


def domain_matches(hostname: str | None, domains: Any) -> bool:
    if not hostname or not isinstance(domains, list):
        return False
    host = hostname.lower().strip("[]")
    for domain in domains:
        if not isinstance(domain, str) or not domain:
            continue
        normalized = domain.lower().lstrip(".")
        if host == normalized or host.endswith(f".{normalized}"):
            return True
    return False


def pattern_matches(url: str, patterns: Any) -> bool:
    if not isinstance(patterns, list) or not patterns:
        return False
    return any(isinstance(pattern, str) and fnmatch.fnmatch(url, pattern) for pattern in patterns)


def source_manifest_path(plan: dict[str, Any]) -> Path | None:
    source = plan.get("source_manifest")
    if not isinstance(source, dict) or not isinstance(source.get("path"), str):
        return None
    path = Path(source["path"])
    return path if path.is_absolute() else ROOT / path


def validate_source_manifest(plan: dict[str, Any], *, required: bool = True) -> tuple[dict[str, Any] | None, list[UnsupportedReason]]:
    reasons: list[UnsupportedReason] = []
    source_raw = plan.get("source_manifest")
    source_attached = "source_manifest" in plan
    if source_attached and not isinstance(source_raw, dict):
        reasons.append(UnsupportedReason(0, "<plan>", "source_manifest", None, "source manifest reference must be an object", "source_manifest_invalid"))
        return None, reasons
    path = source_manifest_path(plan)
    source = source_raw if isinstance(source_raw, dict) else {}
    if path is None:
        if required or source_attached:
            reasons.append(UnsupportedReason(0, "<plan>", "source_manifest.path", None, "request policy requires a readable source manifest path when source_manifest is attached", "source_manifest_missing"))
        return None, reasons
    if not path.exists():
        if required or source_attached:
            reasons.append(UnsupportedReason(0, "<plan>", "source_manifest.path", str(path), "source manifest file does not exist", "source_manifest_missing"))
        return None, reasons
    if not path.is_file():
        reasons.append(UnsupportedReason(0, "<plan>", "source_manifest.path", str(path), "source manifest path must be a readable JSON file", "source_manifest_invalid"))
        return None, reasons
    try:
        raw = path.read_bytes()
    except OSError as exc:
        reasons.append(UnsupportedReason(0, "<plan>", "source_manifest.path", str(path), f"source manifest file could not be read: {exc}", "source_manifest_invalid"))
        return None, reasons
    expected_sha = source.get("sha256") if isinstance(source, dict) else None
    actual_sha = sha256_bytes(raw)
    if expected_sha != actual_sha:
        reasons.append(UnsupportedReason(0, "<plan>", "source_manifest.sha256", "<redacted>", "source manifest sha256 does not match request plan", "source_manifest_sha256"))
        return None, reasons
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        reasons.append(UnsupportedReason(0, "<plan>", "source_manifest", str(path), f"source manifest must be valid JSON: {exc}", "source_manifest_invalid"))
        return None, reasons
    if not isinstance(manifest, dict):
        reasons.append(UnsupportedReason(0, "<plan>", "source_manifest", str(path), "source manifest must be a JSON object", "source_manifest_invalid"))
        return None, reasons
    return manifest, reasons


def validate_manifest_request_policy(manifest: dict[str, Any], prepared: list[PreparedRequest]) -> list[UnsupportedReason]:
    policy = manifest.get("policy")
    if not isinstance(policy, dict):
        return [UnsupportedReason(req.index, req.target_id, "policy", None, "request policy enforcement requires source manifest policy", "policy_missing") for req in prepared]
    allowlist = policy.get("allowlist") if isinstance(policy.get("allowlist"), dict) else {}
    denylist = policy.get("denylist") if isinstance(policy.get("denylist"), dict) else {}
    robots = policy.get("robots") if isinstance(policy.get("robots"), dict) else {}
    rate_limits = policy.get("rate_limits") if isinstance(policy.get("rate_limits"), dict) else {}
    per_domain = rate_limits.get("per_domain") if isinstance(rate_limits.get("per_domain"), dict) else {}
    target_by_id = {target.get("id"): target for target in manifest.get("targets", []) if isinstance(target, dict)}
    reasons: list[UnsupportedReason] = []
    for req in prepared:
        parsed = parse_url(req.original_url)
        host = parsed.hostname or ""
        if domain_matches(host, denylist.get("domains")) or pattern_matches(req.original_url, denylist.get("url_patterns")):
            reasons.append(UnsupportedReason(req.index, req.target_id, "policy.denylist", req.original_url, "target is blocked by source manifest denylist", "policy_denylist"))
        allowed_by_domain = domain_matches(host, allowlist.get("domains"))
        allowed_by_pattern = pattern_matches(req.original_url, allowlist.get("url_patterns"))
        if not (allowed_by_domain or allowed_by_pattern):
            reasons.append(UnsupportedReason(req.index, req.target_id, "policy.allowlist", req.original_url, "target is not covered by source manifest allowlist", "policy_allowlist"))
        robots_mode = robots.get("mode") or req.compliance.get("robots_mode")
        if robots_mode not in {"strict", "advisory", "off"}:
            reasons.append(UnsupportedReason(req.index, req.target_id, "policy.robots.mode", robots_mode, "request policy requires robots mode strict, advisory, or explicitly approved off", "policy_robots"))
        elif robots_mode == "off":
            reasons.append(UnsupportedReason(req.index, req.target_id, "policy.robots.mode", robots_mode, "robots mode off requires an explicit approval gate that is not implemented in this runtime slice", "policy_robots_off_requires_approval"))
        limit = per_domain.get(host)
        if not isinstance(limit, dict) or not isinstance(limit.get("requests_per_minute"), int) or limit.get("requests_per_minute", 0) <= 0 or not isinstance(limit.get("concurrent"), int) or limit.get("concurrent", 0) <= 0:
            reasons.append(UnsupportedReason(req.index, req.target_id, "policy.rate_limits.per_domain", host, "request policy requires positive per-domain rate limits", "policy_rate_limit"))
        manifest_target = target_by_id.get(req.target_id)
        if isinstance(manifest_target, dict) and isinstance(manifest_target.get("compliance"), dict):
            compliance = manifest_target["compliance"]
        else:
            compliance = req.compliance
        missing = sorted(COMPLIANCE_REQUIRED_KEYS - set(compliance))
        if missing:
            reasons.append(UnsupportedReason(req.index, req.target_id, "compliance", missing, "request policy requires complete compliance metadata", "policy_compliance"))
        if compliance.get("requires_approval") is True:
            reasons.append(UnsupportedReason(req.index, req.target_id, "compliance.requires_approval", compliance.get("requires_approval"), "request policy requires approval-free or already-approved targets", "policy_compliance"))
    return reasons


def expand_plan_reasons(reasons: list[UnsupportedReason], prepared: list[PreparedRequest]) -> list[UnsupportedReason]:
    if not reasons or not prepared:
        return reasons
    expanded: list[UnsupportedReason] = []
    for req in prepared:
        for reason in reasons:
            expanded.append(UnsupportedReason(req.index, req.target_id, reason.field, reason.value, reason.reason, reason.code))
    return expanded


def validate_request_policy(plan: dict[str, Any], prepared: list[PreparedRequest], *, required: bool = False) -> tuple[list[UnsupportedReason], bool]:
    manifest, reasons = validate_source_manifest(plan, required=required)
    if reasons:
        return expand_plan_reasons(reasons, prepared), True
    if manifest is None:
        return [], False
    return validate_manifest_request_policy(manifest, prepared), True


def validate_live_policy_preflight(plan: dict[str, Any], prepared: list[PreparedRequest]) -> list[UnsupportedReason]:
    reasons, _evaluated = validate_request_policy(plan, prepared, required=True)
    return reasons


def compliance_gate_reasons(plan: dict[str, Any], prepared: list[PreparedRequest], report_arg: str | None) -> list[UnsupportedReason]:
    def per_request(code: str, field: str, message: str, value: Any = "<redacted>") -> list[UnsupportedReason]:
        return [UnsupportedReason(req.index, req.target_id, field, value, message, code) for req in prepared]

    if not report_arg:
        return per_request(
            "compliance_gate_report_required",
            "compliance_gate_report",
            "live/live-preflight request-plan execution requires a compliance gate report before network policy can pass",
            None,
        )
    report_path = resolve_path(report_arg)
    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return per_request(
            "compliance_gate_report_invalid",
            "compliance_gate_report",
            f"compliance gate report could not be read as JSON: {exc}",
            "<redacted>",
        )
    if not isinstance(report, dict) or report.get("schema_version") != "tallow.compliance_gate_report.v1" or report.get("passed") is not True:
        return per_request(
            "compliance_gate_report_invalid",
            "compliance_gate_report",
            "compliance gate report must be a passing tallow.compliance_gate_report.v1 object",
            "<redacted>",
        )
    production_gate = report.get("production_gate")
    legal = report.get("legal")
    legal_targets = legal.get("targets") if isinstance(legal, dict) else None
    if not isinstance(production_gate, dict) or not isinstance(legal_targets, list):
        return per_request(
            "compliance_gate_legal_metadata_missing",
            "compliance_gate_report.legal",
            "compliance gate report must include production_gate and legal.targets metadata",
            "<redacted>",
        )
    if production_gate.get("legal_metadata_status") != "complete":
        return per_request(
            "compliance_gate_legal_metadata_missing",
            "compliance_gate_report.production_gate.legal_metadata_status",
            "compliance gate legal metadata is incomplete",
            "<redacted>",
        )
    if production_gate.get("redaction_status") != "passed" or production_gate.get("retention_status") != "dry_run_only":
        return per_request(
            "compliance_gate_report_invalid",
            "compliance_gate_report.production_gate",
            "compliance gate report must have passed redaction and dry-run-only retention status",
            "<redacted>",
        )
    if production_gate.get("network_io_performed") is not False or production_gate.get("destructive_retention_performed") is not False:
        return per_request(
            "compliance_gate_report_invalid",
            "compliance_gate_report.production_gate",
            "compliance gate proof must not perform network I/O or destructive retention",
            "<redacted>",
        )
    if production_gate.get("accepted_for_live_preflight") is not True:
        return per_request(
            "compliance_gate_report_invalid",
            "compliance_gate_report.production_gate.accepted_for_live_preflight",
            "compliance gate report is not accepted for live preflight",
            "<redacted>",
        )
    source = plan.get("source_manifest") if isinstance(plan.get("source_manifest"), dict) else {}
    expected_sha = source.get("sha256") if isinstance(source, dict) else None
    target_manifest = report.get("target_manifest")
    report_sha = target_manifest.get("sha256") if isinstance(target_manifest, dict) else None
    if expected_sha and report_sha != expected_sha:
        return per_request(
            "compliance_gate_report_invalid",
            "compliance_gate_report.target_manifest.sha256",
            "compliance gate report target manifest sha256 must be present and match the request-plan source manifest",
            "<redacted>",
        )
    required_legal = {"target_id", "source_authority", "purpose", "legal_basis", "pii_policy", "retention_days", "robots_mode"}
    legal_by_id = {item.get("target_id"): item for item in legal_targets if isinstance(item, dict)}
    for req in prepared:
        legal_target = legal_by_id.get(req.target_id)
        if not isinstance(legal_target, dict) or any(key not in legal_target or legal_target.get(key) in (None, "") for key in required_legal):
            return per_request(
                "compliance_gate_legal_metadata_missing",
                "compliance_gate_report.legal.targets",
                "compliance gate report must carry complete legal metadata for every request target",
                "<redacted>",
            )
    vault = report.get("vault") if isinstance(report.get("vault"), dict) else {}
    redaction = report.get("redaction") if isinstance(report.get("redaction"), dict) else {}
    retention = report.get("retention") if isinstance(report.get("retention"), dict) else {}
    if vault.get("real_vault_contacted") is not False or vault.get("secret_material_serialized") is not False:
        return per_request("compliance_gate_report_invalid", "compliance_gate_report.vault", "compliance gate vault proof must not contact real vaults or serialize secret material", "<redacted>")
    if redaction.get("raw_values_emitted") is not False or retention.get("destructive_action_performed") is not False:
        return per_request("compliance_gate_report_invalid", "compliance_gate_report", "compliance gate proof must not emit raw values or perform destructive retention", "<redacted>")
    return []


def write_requests_jsonl(output_dir: Path, rows: list[dict[str, Any]]) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    with (output_dir / "requests.jsonl").open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False) + "\n")


def file_entry(path: Path, artifact_class: str, redaction_status: str, root: Path | None = None) -> dict[str, Any]:
    display = str(path.relative_to(root)) if root and path.exists() and path.resolve().is_relative_to(root.resolve()) else display_path(path)
    entry: dict[str, Any] = {"path": display, "artifact_class": artifact_class, "exists": path.exists(), "redaction_status": redaction_status}
    if path.exists() and path.is_file():
        data = path.read_bytes()
        entry["size_bytes"] = len(data)
        entry["sha256"] = sha256_bytes(data)
    return entry


def write_artifact_manifest(output_dir: Path, report_path: Path, plan_snapshot: Path, rows: list[dict[str, Any]], generated_at: datetime) -> Path:
    files: list[dict[str, Any]] = []
    files.append(file_entry(report_path, "metrics", "redacted"))
    files.append(file_entry(plan_snapshot, "manifest", "redacted", output_dir))
    files.append(file_entry(output_dir / "requests.jsonl", "normalized_rows", "redacted", output_dir))
    vault_report_path = output_dir / "vault_resolution_report.json"
    if vault_report_path.exists():
        files.append(file_entry(vault_report_path, "manifest", "redacted", output_dir))
    for row in rows:
        req_dir = request_dir(output_dir, PreparedRequest(
            index=int(row["index"]), target_id=str(row["target_id"]), method=str(row["method"]), original_url=str(row["original_url"]), executed_url=str(row.get("executed_url") or ""), headers={}, body_bytes=None, body_metadata={}, graphql=None, compliance={}, retry=None, artifact_policy=None, extraction_schema_ref=None, vault_reference=None
        ))
        request_artifact = req_dir / "request.redacted.json"
        response_metadata = req_dir / "response.metadata.json"
        if request_artifact.exists():
            files.append(file_entry(request_artifact, "other", "redacted", output_dir))
        if response_metadata.exists():
            files.append(file_entry(response_metadata, "raw_response", "redacted", output_dir))
        body_rel = (row.get("artifacts") or {}).get("response_body")
        if body_rel:
            files.append(file_entry(output_dir / body_rel, "raw_response", "redacted", output_dir))
    for rel, artifact_class in (
        (Path("extraction") / "rows.jsonl", "normalized_rows"),
        (Path("extraction") / "quarantine.jsonl", "normalized_rows"),
        (Path("extraction") / "validation_report.json", "metrics"),
    ):
        artifact_path = output_dir / rel
        if artifact_path.exists():
            files.append(file_entry(artifact_path, artifact_class, "redacted", output_dir))
    retention_days = 7
    manifest_path = output_dir / "artifact_manifest.json"
    manifest = {
        "schema_version": ARTIFACT_SCHEMA,
        "artifact_id": output_dir.name,
        "launch_id": output_dir.name,
        "run_id": "request_plan_runner",
        "generated_at_utc": iso_utc(generated_at),
        "files": files,
        "redaction": {"status": "passed", "pii_policy": "runner_local_mock_redacted", "notes": "raw request bodies are not embedded in execution_report.json"},
        "retention": {"retention_days": retention_days, "delete_after_utc": iso_utc(generated_at + timedelta(days=retention_days))},
        "replay": {"safe_to_replay": False, "requires_approval": True, "replay_reason": "phase2 local/mock runner artifacts require request-level review before replay"},
    }
    manifest_path.write_text(stable_json(manifest), encoding="utf-8")
    return manifest_path


def copy_plan_snapshot(plan_path: Path, output_dir: Path) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    dest = output_dir / "request_plan.v1.json"
    plan = json.loads(plan_path.read_text(encoding="utf-8"))
    snapshot = redact_plan_snapshot_value(plan)
    if isinstance(snapshot, dict):
        snapshot["artifact_snapshot_redacted"] = True
    dest.write_text(stable_json(snapshot), encoding="utf-8")
    return dest


def build_vault_resolution_report(prepared: list[PreparedRequest], generated_at: datetime) -> dict[str, Any]:
    references = [req.vault_reference for req in prepared if req.vault_reference is not None]
    return {
        "schema_version": "tallow.vault_resolution_report.v1",
        "generated_at_utc": iso_utc(generated_at),
        "resolver": "fake_local_reference_only",
        "references_total": len(references),
        "references": references,
        "no_secret_material_resolved": True,
        "secret_material_serialized": False,
        "real_vault_contacted": False,
        "non_claims": {
            "no_real_vault_configuration": True,
            "no_real_secret_material": True,
            "no_live_secret_resolution": True,
        },
    }


def write_vault_resolution_report(output_dir: Path, report: dict[str, Any]) -> Path:
    path = output_dir / "vault_resolution_report.json"
    path.write_text(stable_json(report), encoding="utf-8")
    return path


def build_base_report(plan: dict[str, Any], plan_path: Path, plan_raw: bytes, args: argparse.Namespace, output_dir: Path, generated_at: datetime) -> dict[str, Any]:
    return {
        "schema_version": RUNNER_SCHEMA,
        "passed": False,
        "exit_code": None,
        "dry_run": bool(args.dry_run),
        "generated_at_utc": iso_utc(generated_at),
        "runner": {
            "name": "scripts/run_tallow_request_plan.py",
            "version": RUNNER_VERSION,
            "python": sys.version.split()[0],
            "platform": sys.platform,
        },
        "execution_core": load_execution_contract_summary(),
        "plan": {
            "path": display_path(plan_path),
            "sha256": sha256_bytes(plan_raw),
            "schema_version": plan.get("schema_version"),
            "manifest_id": plan.get("manifest_id"),
            "request_count": plan.get("request_count"),
            "source_manifest": plan.get("source_manifest"),
        },
        "mode": {
            "network_scope": args.network_scope,
            "mock_base_url": args.mock_base_url,
            "concurrency": args.concurrency,
            "timeout_seconds": args.timeout_seconds,
            "max_response_bytes": args.max_response_bytes,
            "fail_on_unsupported": True,
            "compliance_gate_report": display_path(resolve_path(args.compliance_gate_report)) if args.compliance_gate_report else None,
        },
        "browser_fallback": browser_fallback_capability_summary(),
        "non_claims": {
            "browser_execution": False,
            "vault_secret_resolution": False,
            "production_compliance": False,
            "benchmark_or_performance_claim": False,
            "live_external_scraping": False,
        },
        "output": {
            "output_dir": display_path(output_dir),
            "artifact_manifest": None,
            "vault_resolution_report": None,
            "extraction": None,
        },
        "summary": {
            "planned": int(plan.get("request_count") or 0),
            "executed": 0,
            "succeeded": 0,
            "failed": 0,
            "blocked": 0,
            "unsupported": 0,
            "attempts": 0,
            "extraction_rows": 0,
            "extraction_quarantined": 0,
            "duration_ms": 0,
        },
        "gates": [],
        "unsupported": [],
        "vault_resolution": {
            "schema_version": "tallow.vault_resolution_report.v1",
            "generated_at_utc": iso_utc(generated_at),
            "resolver": "fake_local_reference_only",
            "references_total": 0,
            "references": [],
            "no_secret_material_resolved": True,
            "secret_material_serialized": False,
            "real_vault_contacted": False,
            "non_claims": {
                "no_real_vault_configuration": True,
                "no_real_secret_material": True,
                "no_live_secret_resolution": True,
            },
        },
        "requests": [],
    }


def write_report_with_manifest(report: dict[str, Any], report_path: Path, output_dir: Path, plan_snapshot: Path, generated_at: datetime) -> None:
    report_path.parent.mkdir(parents=True, exist_ok=True)
    write_requests_jsonl(output_dir, report.get("requests", []))
    vault_report = report.get("vault_resolution") if isinstance(report.get("vault_resolution"), dict) else None
    if vault_report is not None:
        vault_path = write_vault_resolution_report(output_dir, vault_report)
        report["output"]["vault_resolution_report"] = {
            "path": display_path(vault_path),
            "schema_version": vault_report.get("schema_version"),
            "sha256": sha256_bytes(vault_path.read_bytes()),
        }
    manifest_path = output_dir / "artifact_manifest.json"
    # Avoid circular checksums: the artifact manifest records the final report
    # hash, while the report records the manifest path/schema without embedding
    # the manifest hash back into the report.
    report["output"]["artifact_manifest"] = {
        "path": display_path(manifest_path),
        "schema_version": ARTIFACT_SCHEMA,
        "sha256": None,
    }
    report_path.write_text(stable_json(report), encoding="utf-8")
    write_artifact_manifest(output_dir, report_path, plan_snapshot, report.get("requests", []), generated_at)


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run a tallow.request_plan.v1 artifact with local-safe Phase 2 semantics")
    parser.add_argument("--plan", required=True, help="Input tallow.request_plan.v1 JSON")
    parser.add_argument("--report-path", "--report", dest="report_path", required=True, help="Output execution report JSON")
    parser.add_argument("--output-dir", help="Output artifact directory; defaults to a sibling directory for the report")
    parser.add_argument("--mock-base-url", help="Rewrite all request URLs to this loopback base URL while preserving path/query")
    parser.add_argument("--network-scope", default="local", choices=["local", "live-preflight", "live"], help="Network policy scope; live-preflight validates policy without I/O, live remains approval-gated")
    parser.add_argument("--live-policy-preflight", action="store_true", help="Legacy alias for --network-scope live-preflight; validate source-manifest live policy gates without network requests")
    parser.add_argument("--concurrency", type=int, default=1, help="Reserved for future parallel execution; this slice executes sequentially")
    parser.add_argument("--timeout-seconds", type=float, default=5.0)
    parser.add_argument("--max-response-bytes", type=int, default=contract_default_max_response_bytes())
    parser.add_argument("--dry-run", action="store_true", help="Validate/classify without performing network requests")
    parser.add_argument("--compliance-gate-report", help="Required for live-preflight/live: path to a passing tallow.compliance_gate_report.v1 local proof report")
    return parser.parse_args(argv)


def run(args: argparse.Namespace) -> int:
    started_mono = time.monotonic()
    generated_at = utc_now()
    plan_path = resolve_path(args.plan)
    report_path = resolve_path(args.report_path)
    output_dir = resolve_path(args.output_dir) if args.output_dir else report_path.with_suffix("").with_name(report_path.stem + "-artifacts")
    plan, plan_raw = load_plan(plan_path)
    output_dir.mkdir(parents=True, exist_ok=True)
    plan_snapshot = copy_plan_snapshot(plan_path, output_dir)
    report = build_base_report(plan, plan_path, plan_raw, args, output_dir, generated_at)

    shape_errors = validate_plan_shape(plan)
    if shape_errors:
        report["gates"].append({"name": "plan_shape", "status": "fail", "details": "; ".join(shape_errors)})
        report["exit_code"] = 1
        report["summary"]["duration_ms"] = int((time.monotonic() - started_mono) * 1000)
        write_report_with_manifest(report, report_path, output_dir, plan_snapshot, generated_at)
        raise RunnerError("; ".join(shape_errors))
    report["gates"].append({"name": "plan_shape", "status": "pass", "details": "request plan shape accepted"})

    prepared, unsupported = prepare_requests(plan, args.mock_base_url, args.network_scope)
    report["vault_resolution"] = build_vault_resolution_report(prepared, generated_at)
    unsupported.extend(validate_extraction_references(prepared))
    if unsupported:
        report["unsupported"] = [reason.as_dict() for reason in unsupported]
        report["requests"] = [blocked_request_row(req, unsupported) for req in prepared]
        blocked = sum(1 for row in report["requests"] if row["blocked_reasons"])
        report["summary"].update({"executed": 0, "succeeded": 0, "failed": 0, "blocked": blocked, "unsupported": len(unsupported), "attempts": 0})
        report["gates"].append({"name": "unsupported_semantics", "status": "fail", "details": f"{len(unsupported)} unsupported semantic record(s)"})
        report["exit_code"] = 2
        report["summary"]["duration_ms"] = int((time.monotonic() - started_mono) * 1000)
        write_report_with_manifest(report, report_path, output_dir, plan_snapshot, generated_at)
        print("request plan refused: unsupported runtime fields", file=sys.stderr)
        for reason in unsupported:
            print(f"- {reason.target_id}: {reason.field}: {reason.reason}", file=sys.stderr)
        return 2
    report["gates"].append({"name": "unsupported_semantics", "status": "pass", "details": "all requests are supported by phase2 runner"})

    policy_reasons, policy_evaluated = validate_request_policy(plan, prepared, required=False)
    if policy_reasons:
        report["unsupported"] = [reason.as_dict() for reason in policy_reasons]
        report["requests"] = [blocked_request_row(req, policy_reasons) for req in prepared]
        blocked = sum(1 for row in report["requests"] if row["blocked_reasons"])
        report["summary"].update({"planned": len(prepared), "executed": 0, "succeeded": 0, "failed": 0, "blocked": blocked, "unsupported": len(policy_reasons), "attempts": 0})
        report["gates"].append({"name": "request_policy", "status": "fail", "details": f"{len(policy_reasons)} request policy violation(s)"})
        report["exit_code"] = 2
        report["summary"]["duration_ms"] = int((time.monotonic() - started_mono) * 1000)
        write_report_with_manifest(report, report_path, output_dir, plan_snapshot, generated_at)
        print("request plan refused: request policy denied one or more requests", file=sys.stderr)
        for reason in policy_reasons:
            print(f"- {reason.target_id}: {reason.field}: {reason.reason}", file=sys.stderr)
        return 2
    if policy_evaluated:
        report["gates"].append({"name": "request_policy", "status": "pass", "details": "source manifest allowlist/denylist/robots/rate-limit/compliance gates passed"})

    live_preflight_requested = args.network_scope == "live-preflight" or (args.network_scope == "live" and args.live_policy_preflight)
    if live_preflight_requested:
        compliance_reasons = compliance_gate_reasons(plan, prepared, args.compliance_gate_report)
        if compliance_reasons:
            report["unsupported"] = [reason.as_dict() for reason in compliance_reasons]
            report["requests"] = [blocked_request_row(req, compliance_reasons) for req in prepared]
            blocked = sum(1 for row in report["requests"] if row["blocked_reasons"])
            report["summary"].update({"planned": len(prepared), "executed": 0, "succeeded": 0, "failed": 0, "blocked": blocked, "unsupported": len(compliance_reasons), "attempts": 0})
            report["gates"].append({"name": "production_compliance_gate", "status": "fail", "details": f"{len(compliance_reasons)} production compliance gate violation(s)"})
            report["exit_code"] = 2
            report["summary"]["duration_ms"] = int((time.monotonic() - started_mono) * 1000)
            write_report_with_manifest(report, report_path, output_dir, plan_snapshot, generated_at)
            print("request plan refused: production compliance gate failed", file=sys.stderr)
            for reason in compliance_reasons:
                print(f"- {reason.target_id}: {reason.field}: {reason.reason}", file=sys.stderr)
            return 2
        report["gates"].append({"name": "production_compliance_gate", "status": "pass", "details": "compliance gate report accepted for live preflight; no network requests executed"})
        live_reasons = validate_live_policy_preflight(plan, prepared)
        if live_reasons:
            report["unsupported"] = [reason.as_dict() for reason in live_reasons]
            report["requests"] = [blocked_request_row(req, live_reasons) for req in prepared]
            blocked = sum(1 for row in report["requests"] if row["blocked_reasons"])
            report["summary"].update({"planned": len(prepared), "executed": 0, "succeeded": 0, "failed": 0, "blocked": blocked, "unsupported": len(live_reasons), "attempts": 0})
            report["gates"].append({"name": "live_policy_preflight", "status": "fail", "details": f"{len(live_reasons)} live policy preflight violation(s)"})
            report["exit_code"] = 2
            report["summary"]["duration_ms"] = int((time.monotonic() - started_mono) * 1000)
            write_report_with_manifest(report, report_path, output_dir, plan_snapshot, generated_at)
            print("request plan refused: live policy preflight failed", file=sys.stderr)
            for reason in live_reasons:
                print(f"- {reason.target_id}: {reason.field}: {reason.reason}", file=sys.stderr)
            return 2
        rows = [policy_preflight_request_row(req) for req in prepared]
        report["requests"] = rows
        report["summary"].update({"planned": len(rows), "executed": 0, "succeeded": 0, "failed": 0, "blocked": 0, "unsupported": 0, "attempts": 0})
        report["gates"].append({"name": "live_policy_preflight", "status": "pass", "details": "source manifest allowlist/denylist/robots/rate-limit/compliance gates passed; no network requests executed"})
        report["passed"] = True
        report["exit_code"] = 0
        report["summary"]["duration_ms"] = int((time.monotonic() - started_mono) * 1000)
        write_report_with_manifest(report, report_path, output_dir, plan_snapshot, generated_at)
        print(f"request plan live policy preflight report written: {display_path(report_path)}")
        return 0

    if args.network_scope == "live":
        live_reasons = [
            UnsupportedReason(req.index, req.target_id, "network_scope", "live", "live network execution is not implemented in the Python compatibility runner; use native tallow run-plan --network-scope live --approve-live", "live_execution_disabled")
            for req in prepared
        ]
        report["unsupported"] = [reason.as_dict() for reason in live_reasons]
        report["requests"] = [blocked_request_row(req, live_reasons) for req in prepared]
        blocked = sum(1 for row in report["requests"] if row["blocked_reasons"])
        report["summary"].update({"planned": len(prepared), "executed": 0, "succeeded": 0, "failed": 0, "blocked": blocked, "unsupported": len(live_reasons), "attempts": 0})
        report["gates"].append({"name": "live_execution", "status": "fail", "details": "Python compatibility runner keeps live execution disabled; use native CLI approval gate"})
        report["exit_code"] = 2
        report["summary"]["duration_ms"] = int((time.monotonic() - started_mono) * 1000)
        write_report_with_manifest(report, report_path, output_dir, plan_snapshot, generated_at)
        print("request plan refused: Python compatibility runner live execution is disabled", file=sys.stderr)
        return 2

    if args.dry_run:
        rows = [planned_request_row(req) for req in prepared]
        report["requests"] = rows
        report["summary"].update({"planned": len(rows), "executed": 0, "succeeded": 0, "failed": 0, "blocked": 0, "unsupported": 0, "attempts": 0})
        report["passed"] = True
        report["exit_code"] = 0
        report["summary"]["duration_ms"] = int((time.monotonic() - started_mono) * 1000)
        write_report_with_manifest(report, report_path, output_dir, plan_snapshot, generated_at)
        print(f"request plan dry-run report written: {display_path(report_path)}")
        return 0

    rows: list[dict[str, Any]] = []
    extraction_inputs: list[tuple[PreparedRequest, dict[str, Any]]] = []
    for req in prepared:
        row, final = execute_request(output_dir, req, args.timeout_seconds, args.max_response_bytes)
        rows.append(row)
        if req.extraction_schema_ref is not None and row.get("status") == "succeeded":
            extraction_inputs.append((req, final))
    extraction_output, extraction_count, quarantine_count = write_extraction_artifacts(output_dir, extraction_inputs, generated_at)
    if extraction_output is not None:
        report["output"]["extraction"] = extraction_output
    succeeded = sum(1 for row in rows if row.get("status") == "succeeded")
    failed = sum(1 for row in rows if row.get("status") == "failed")
    attempts = sum(int(row.get("attempts") or 0) for row in rows)
    report["requests"] = rows
    report["summary"].update({
        "planned": len(rows),
        "executed": len(rows),
        "succeeded": succeeded,
        "failed": failed,
        "blocked": 0,
        "unsupported": 0,
        "attempts": attempts,
        "extraction_rows": extraction_count,
        "extraction_quarantined": quarantine_count,
    })
    report["passed"] = failed == 0
    report["exit_code"] = 0 if failed == 0 else 3
    report["summary"]["duration_ms"] = int((time.monotonic() - started_mono) * 1000)
    write_report_with_manifest(report, report_path, output_dir, plan_snapshot, generated_at)
    print(f"request plan execution report written: {display_path(report_path)}")
    return int(report["exit_code"])


def main(argv: list[str] | None = None) -> int:
    try:
        args = parse_args(argv or sys.argv[1:])
        if args.concurrency < 1:
            raise RunnerError("--concurrency must be >= 1")
        if args.timeout_seconds <= 0:
            raise RunnerError("--timeout-seconds must be > 0")
        if args.max_response_bytes < 1:
            raise RunnerError("--max-response-bytes must be >= 1")
        return run(args)
    except (OSError, json.JSONDecodeError, RunnerError, ValueError) as exc:
        print(f"request plan runner failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
