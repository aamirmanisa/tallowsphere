#!/usr/bin/env python3
"""Plan local-safe failure replay from request-plan execution reports.

The Phase 7 Linux-native default is dry-run. Live replay is deliberately refused
without an explicit future human gate.
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "tallow.failure_replay.v1"


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def resolve_path(path_arg: str) -> Path:
    path = Path(path_arg)
    return path if path.is_absolute() else ROOT / path


def display_path(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(ROOT.resolve()))
    except ValueError:
        return str(path.resolve())


def load_report(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SystemExit(f"execution report must be a JSON object: {path}")
    if data.get("schema_version") != "tallow.request_plan_run_report.v1":
        raise SystemExit(f"unsupported execution report schema_version: {data.get('schema_version')!r}")
    return data


def is_loopback_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower().strip("[]")
    return host in {"127.0.0.1", "::1", "localhost"} or host.startswith("127.")


def replay_candidates(report: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []
    for item in report.get("requests", []):
        if not isinstance(item, dict):
            continue
        status = str(item.get("status") or "")
        error_kind = str(item.get("error_kind") or "none")
        retryable = bool(item.get("retryable"))
        if retryable or status == "failed" or error_kind not in {"none", ""}:
            candidates.append(
                {
                    "index": item.get("index"),
                    "target_id": item.get("target_id"),
                    "method": item.get("method"),
                    "original_url": item.get("original_url"),
                    "executed_url": item.get("executed_url"),
                    "original_status": status,
                    "original_http_status": item.get("http_status"),
                    "original_error_kind": error_kind,
                    "original_retryable": retryable,
                    "attempts": item.get("attempts"),
                    "replay_status": "planned",
                    "replay_error_kind": None,
                    "resolved": False,
                }
            )
    return candidates


def build_report(report: dict[str, Any], report_path: Path, *, execute: bool, network_scope: str, max_replay: int, refusal: str | None = None) -> dict[str, Any]:
    candidates = replay_candidates(report)[:max_replay]
    attempted = 0 if not execute or refusal else 0
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "input": {
            "execution_report_path": display_path(report_path),
            "execution_report_schema_version": report.get("schema_version"),
        },
        "dry_run": not execute,
        "network_scope": network_scope,
        "max_replay": max_replay,
        "counts": {
            "candidates_total": len(candidates),
            "replay_attempted": attempted,
            "replay_success_status": 0,
            "replay_transport_error": 0,
            "replay_still_retryable": 0,
            "replay_resolved": 0,
            "refused": 1 if refusal else 0,
        },
        "replay_items": candidates,
        "refusal": refusal,
        "non_claims": {
            "no_network_io_performed": attempted == 0,
            "no_live_replay_performed": network_scope != "live" or attempted == 0,
            "not_production_incident_automation": True,
        },
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-report", required=True, help="Path to tallow.request_plan_run_report.v1 JSON")
    parser.add_argument("--report-path", required=True, help="Output tallow.failure_replay.v1 report path")
    parser.add_argument("--max-replay", type=int, default=1000, help="Maximum replay candidates to include")
    parser.add_argument("--execute", action="store_true", help="Attempt local replay. Live replay is refused by this Phase 7 tool.")
    parser.add_argument("--network-scope", choices=["local", "live"], default="local", help="Replay network scope")
    args = parser.parse_args()

    report_path = resolve_path(args.execution_report)
    output_path = resolve_path(args.report_path)
    source = load_report(report_path)
    refusal = None
    exit_code = 0
    if args.execute and args.network_scope == "live":
        refusal = "live replay requires explicit human approval and is outside Phase 7 automation"
        exit_code = 2
    elif args.execute:
        non_loopback = [item.get("executed_url") for item in replay_candidates(source) if not is_loopback_url(str(item.get("executed_url") or ""))]
        if non_loopback:
            refusal = "local replay requires loopback executed_url values only"
            exit_code = 2
        else:
            refusal = "local execute replay is intentionally not performed by the Phase 7 proof; use dry-run candidate reports"
            exit_code = 2

    payload = build_report(source, report_path, execute=args.execute, network_scope=args.network_scope, max_replay=args.max_replay, refusal=refusal)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(stable_json(payload), encoding="utf-8")
    if refusal:
        print(refusal, file=sys.stderr)
    print(f"wrote failure replay report: {display_path(output_path)}")
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
