#!/usr/bin/env python3
"""Build a Phase 2 request plan from a target-manifest v2 artifact.

This is the second BLK-008 producer-migration slice. It consumes a canonical
`tallow.target_manifest.v2` artifact, preserves full object-target metadata in a
request-plan JSON artifact, and only emits a legacy `http.batch` TL transport
script when the downgrade is provably safe.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_OUTPUT_DIR = ROOT / "artifacts" / "phase2" / "request-plans"
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
REQUIRED_COMPLIANCE = {"source_authority", "purpose", "legal_basis", "pii_policy", "retention_days", "robots_mode"}
REQUIRED_POLICY = {"allowlist", "denylist", "robots", "rate_limits"}


class RequestPlanError(Exception):
    """Raised when the target manifest cannot become a request plan."""


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resolve_path(path_arg: str) -> Path:
    path = Path(path_arg)
    if not path.is_absolute():
        path = ROOT / path
    return path


def display_path(path: Path) -> str:
    try:
        return str(path.relative_to(ROOT))
    except ValueError:
        return str(path)


def default_output_path(manifest_path: Path, source_hash: str) -> Path:
    stem = manifest_path.name
    for suffix in (".target-manifest.v2.json", ".json"):
        if stem.endswith(suffix):
            stem = stem[: -len(suffix)]
            break
    return DEFAULT_OUTPUT_DIR / f"{stem}.{source_hash[:12]}.request-plan.v1.json"


def default_report_path(output_path: Path) -> Path:
    name = output_path.name
    suffix = ".request-plan.v1.json"
    if name.endswith(suffix):
        name = name[: -len(suffix)] + ".request-plan-report.json"
    else:
        name = output_path.stem + ".request-plan-report.json"
    return output_path.with_name(name)


def load_manifest(path: Path) -> tuple[dict[str, Any], bytes]:
    raw = path.read_bytes()
    data = json.loads(raw.decode("utf-8"))
    if not isinstance(data, dict):
        raise RequestPlanError("target manifest must be a JSON object")
    return data, raw


def require_manifest_v2(manifest: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    if manifest.get("schema_version") != "tallow.target_manifest.v2":
        errors.append("schema_version must be tallow.target_manifest.v2")
    if not isinstance(manifest.get("manifest_id"), str) or not manifest.get("manifest_id"):
        errors.append("manifest_id is required")
    targets = manifest.get("targets")
    if not isinstance(targets, list) or not targets:
        errors.append("targets must be a non-empty array")
    policy = manifest.get("policy")
    if not isinstance(policy, dict):
        errors.append("policy object is required")
    else:
        missing = sorted(REQUIRED_POLICY - set(policy))
        if missing:
            errors.append(f"policy missing required keys: {', '.join(missing)}")
    if isinstance(targets, list):
        seen: set[str] = set()
        for index, target in enumerate(targets):
            prefix = f"targets[{index}]"
            if not isinstance(target, dict):
                errors.append(f"{prefix} must be an object, not a legacy string")
                continue
            tid = target.get("id")
            if not isinstance(tid, str) or not re.match(r"^[A-Za-z0-9_.:-]+$", tid):
                errors.append(f"{prefix}.id is required and must be v2-safe")
            elif tid in seen:
                errors.append(f"{prefix}.id duplicates {tid}")
            else:
                seen.add(tid)
            url = target.get("url")
            if not isinstance(url, str) or not url.startswith(("http://", "https://")):
                errors.append(f"{prefix}.url must be HTTP(S)")
            if target.get("method") not in METHODS:
                errors.append(f"{prefix}.method must be one of {', '.join(sorted(METHODS))}")
            compliance = target.get("compliance")
            if not isinstance(compliance, dict):
                errors.append(f"{prefix}.compliance object is required")
            else:
                missing = sorted(REQUIRED_COMPLIANCE - set(compliance))
                if missing:
                    errors.append(f"{prefix}.compliance missing required keys: {', '.join(missing)}")
    return errors


def merge_headers(defaults: dict[str, Any], target: dict[str, Any]) -> dict[str, str]:
    merged: dict[str, str] = {}
    default_headers = defaults.get("headers")
    if isinstance(default_headers, dict):
        for key, value in default_headers.items():
            if isinstance(key, str) and isinstance(value, str):
                merged[key] = value
    target_headers = target.get("headers")
    if isinstance(target_headers, dict):
        for key, value in target_headers.items():
            if isinstance(key, str) and isinstance(value, str):
                merged[key] = value
    return merged


def inherited_or_target(defaults: dict[str, Any], target: dict[str, Any], key: str) -> Any | None:
    if key in target:
        return target[key]
    return defaults.get(key)


def copy_if_present(source: dict[str, Any], key: str, dest: dict[str, Any]) -> None:
    if key in source:
        dest[key] = source[key]


def request_from_target(defaults: dict[str, Any], target: dict[str, Any], index: int) -> dict[str, Any]:
    request: dict[str, Any] = {
        "index": index,
        "target_id": target["id"],
        "url": target["url"],
        "method": target["method"],
        "headers": merge_headers(defaults, target),
        "compliance": target["compliance"],
    }
    for key in ("body", "graphql", "auth_ref", "extraction_schema_ref", "tags"):
        copy_if_present(target, key, request)
    for key in ("browser_fallback", "artifact_policy", "retry"):
        value = inherited_or_target(defaults, target, key)
        if value is not None:
            request[key] = value
    return request


def compatibility_reasons(manifest: dict[str, Any], requests: list[dict[str, Any]]) -> list[str]:
    reasons: list[str] = []
    raw_defaults = manifest.get("defaults")
    defaults: dict[str, Any] = raw_defaults if isinstance(raw_defaults, dict) else {}
    raw_default_browser = defaults.get("browser_fallback")
    default_browser: dict[str, Any] | None = raw_default_browser if isinstance(raw_default_browser, dict) else None
    if isinstance(default_browser, dict) and default_browser.get("mode") not in (None, "never"):
        reasons.append(f"defaults.browser_fallback mode {default_browser.get('mode')} cannot be represented in legacy http.batch TL")
    raw_targets = manifest.get("targets")
    targets: list[Any] = raw_targets if isinstance(raw_targets, list) else []
    for index, request in enumerate(requests):
        target = targets[index] if index < len(targets) and isinstance(targets[index], dict) else {}
        label = request.get("target_id") or f"targets[{index}]"
        method = request.get("method")
        if method != "GET":
            reasons.append(f"{label}: method {method} cannot be represented in legacy http.batch TL")
        body = request.get("body")
        if isinstance(body, dict) and body.get("kind") != "none":
            reasons.append(f"{label}: body cannot be represented in legacy http.batch TL")
        elif body is not None and not isinstance(body, dict):
            reasons.append(f"{label}: body cannot be represented in legacy http.batch TL")
        if request.get("graphql") is not None:
            reasons.append(f"{label}: graphql metadata cannot be represented in legacy http.batch TL")
        if isinstance(target, dict) and target.get("headers"):
            reasons.append(f"{label}: per-target headers cannot be represented in legacy http.batch TL")
        if request.get("auth_ref") is not None:
            reasons.append(f"{label}: auth_ref cannot be represented in legacy http.batch TL")
        if request.get("retry") is not None:
            reasons.append(f"{label}: retry policy cannot be represented in legacy http.batch TL")
        if isinstance(target, dict) and target.get("browser_fallback") is not None:
            reasons.append(f"{label}: per-target browser_fallback cannot be represented in legacy http.batch TL")
        if request.get("artifact_policy") is not None:
            reasons.append(f"{label}: artifact_policy cannot be represented in legacy http.batch TL")
    return reasons


def build_request_plan(manifest: dict[str, Any], manifest_path: Path, source_hash: str) -> dict[str, Any]:
    errors = require_manifest_v2(manifest)
    if errors:
        raise RequestPlanError("; ".join(errors))
    raw_defaults = manifest.get("defaults")
    defaults: dict[str, Any] = raw_defaults if isinstance(raw_defaults, dict) else {}
    raw_targets = manifest.get("targets")
    if not isinstance(raw_targets, list):
        raise RequestPlanError("targets must be a non-empty array")
    targets: list[dict[str, Any]] = [target for target in raw_targets if isinstance(target, dict)]
    requests = [request_from_target(defaults, target, index) for index, target in enumerate(targets)]
    blocked = compatibility_reasons(manifest, requests)
    raw_global_headers = defaults.get("headers")
    global_headers: dict[str, Any] = raw_global_headers if isinstance(raw_global_headers, dict) else {}
    return {
        "schema_version": "tallow.request_plan.v1",
        "manifest_id": manifest["manifest_id"],
        "source_manifest": {
            "path": display_path(manifest_path),
            "sha256": source_hash,
            "schema_version": manifest.get("schema_version"),
        },
        "request_count": len(requests),
        "requests": requests,
        "legacy_http_batch": {
            "compatible": not blocked,
            "blocked_reasons": blocked,
            "headers": global_headers,
            "target_urls": [request["url"] for request in requests],
        },
        "status_boundary": "Request plan preserves v2 target metadata. Legacy TL output, when emitted, is a downgrade transport only and not runtime proof for full v2 semantics.",
    }


def tl_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def render_legacy_tl(plan: dict[str, Any], concurrency: int) -> str:
    legacy = plan["legacy_http_batch"]
    urls = legacy["target_urls"]
    headers = legacy.get("headers") if isinstance(legacy.get("headers"), dict) else {}
    lines: list[str] = [
        "// Generated by scripts/build_tallow_request_plan.py",
        "// Legacy transport TL: safe URL/global-header downgrade only.",
        "// Full v2 target metadata remains in the request-plan JSON sidecar.",
        "",
        "import tallow.http",
        "",
        "@cra_class(.class_i)",
        "@legal(basis: .public_data, purpose: \"phase2 legacy request-plan transport\", personal_data: false, robots_txt: .respect)",
        "fn main() {",
        "    let target_urls = [",
    ]
    for index, url in enumerate(urls):
        comma = "," if index < len(urls) - 1 else ""
        lines.append(f"        {tl_string(url)}{comma}")
    lines.extend([
        "    ]",
        "",
        "    let headers = {",
    ])
    header_items = list(headers.items())
    for index, (key, value) in enumerate(header_items):
        comma = "," if index < len(header_items) - 1 else ""
        lines.append(f"        {tl_string(str(key))}: {tl_string(str(value))}{comma}")
    lines.extend([
        "    }",
        "",
        f"    let l1_concurrency = {concurrency}",
        "    let responses = http.batch(target_urls, l1_concurrency, headers)",
        "    print(\"legacy transport request count=\" + responses.len.to_string())",
        "}",
        "",
    ])
    return "\n".join(lines)


def write_plan(path: Path, plan: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(plan), encoding="utf-8")


def write_report(path: Path, plan: dict[str, Any], output_path: Path, legacy_tl_path: Path | None, exit_code: int) -> None:
    report = {
        "schema_version": "tallow.request_plan_report.v1",
        "passed": exit_code == 0,
        "output": {
            "path": display_path(output_path),
            "sha256": sha256_hex(output_path.read_bytes()) if output_path.exists() else None,
        },
        "legacy_tl": {
            "path": display_path(legacy_tl_path) if legacy_tl_path else None,
            "emitted": bool(legacy_tl_path and legacy_tl_path.exists()),
            "compatible": plan["legacy_http_batch"]["compatible"],
            "blocked_reasons": plan["legacy_http_batch"]["blocked_reasons"],
        },
        "request_count": plan.get("request_count", 0),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(stable_json(report), encoding="utf-8")


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Build a Tallow Phase 2 request plan from target-manifest v2")
    parser.add_argument("--manifest", required=True, help="Input tallow.target_manifest.v2 JSON artifact")
    parser.add_argument("--output", help="Output request-plan JSON path")
    parser.add_argument("--report-path", help="Optional request-plan report path")
    parser.add_argument("--write-report-default", action="store_true", help="Write a default sibling report when --report-path is omitted")
    parser.add_argument("--legacy-tl-output", help="Optional legacy http.batch TL output. Fails with exit 2 if downgrade is lossy")
    parser.add_argument("--legacy-concurrency", type=int, default=4, help="Concurrency value used in generated legacy TL")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        manifest_path = resolve_path(args.manifest)
        manifest, raw = load_manifest(manifest_path)
        source_hash = sha256_hex(raw)
        output_path = resolve_path(args.output) if args.output else default_output_path(manifest_path, source_hash)
        plan = build_request_plan(manifest, manifest_path, source_hash)
        write_plan(output_path, plan)

        legacy_tl_path = resolve_path(args.legacy_tl_output) if args.legacy_tl_output else None
        exit_code = 0
        if legacy_tl_path is not None:
            if plan["legacy_http_batch"]["compatible"]:
                legacy_tl_path.parent.mkdir(parents=True, exist_ok=True)
                legacy_tl_path.write_text(render_legacy_tl(plan, args.legacy_concurrency), encoding="utf-8")
            else:
                exit_code = 2
                if legacy_tl_path.exists():
                    legacy_tl_path.unlink()
                for reason in plan["legacy_http_batch"]["blocked_reasons"]:
                    print(f"- {reason}", file=sys.stderr)
                print(
                    "legacy TL not emitted: manifest contains fields preserved in the request plan that cannot be represented in legacy http.batch TL",
                    file=sys.stderr,
                )

        report_path: Path | None = None
        if args.report_path:
            report_path = resolve_path(args.report_path)
        elif args.write_report_default:
            report_path = default_report_path(output_path)
        if report_path is not None:
            write_report(report_path, plan, output_path, legacy_tl_path, exit_code)

        print(f"request plan written: {display_path(output_path)}")
        if legacy_tl_path is not None and legacy_tl_path.exists():
            print(f"legacy TL written: {display_path(legacy_tl_path)}")
        return exit_code
    except (OSError, json.JSONDecodeError, RequestPlanError) as exc:
        print(f"request plan build failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
