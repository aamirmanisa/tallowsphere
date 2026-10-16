#!/usr/bin/env python3
"""Extract local Phase 7 run metrics from a request-plan execution report."""
from __future__ import annotations

import argparse
import json
import math
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "tallow.run_metrics.v1"


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


def p95_nearest_rank(samples: list[int | float]) -> int | float | None:
    if not samples:
        return None
    ordered = sorted(samples)
    index = max(0, math.ceil(0.95 * len(ordered)) - 1)
    return ordered[index]


def extract_metrics(report: dict[str, Any], report_path: Path) -> dict[str, Any]:
    requests = [item for item in report.get("requests", []) if isinstance(item, dict)]
    raw_summary = report.get("summary")
    summary: dict[str, Any] = raw_summary if isinstance(raw_summary, dict) else {}
    planned = int(summary.get("planned") or len(requests) or 0)
    executed = int(summary.get("executed") or sum(1 for item in requests if item.get("status") not in {"planned", "blocked"}))
    succeeded = int(summary.get("succeeded") or sum(1 for item in requests if item.get("status") == "succeeded"))
    failed = int(summary.get("failed") or sum(1 for item in requests if item.get("status") == "failed"))
    attempts = int(summary.get("attempts") or sum(int(item.get("attempts") or 0) for item in requests))
    blocked = int(summary.get("blocked") or sum(1 for item in requests if item.get("status") == "blocked"))
    unsupported = int(summary.get("unsupported") or 0)
    retry_attempts = max(0, attempts - executed)

    latency_samples: list[int | float] = []
    method_counts: Counter[str] = Counter()
    status_counts: Counter[str] = Counter()
    error_kind_counts: Counter[str] = Counter()
    graphql_count = 0
    for item in requests:
        method_counts[str(item.get("method") or "UNKNOWN").upper()] += 1
        status = item.get("http_status")
        status_counts[str(status if status is not None else "none")] += 1
        error_kind_counts[str(item.get("error_kind") or "none")] += 1
        if item.get("is_graphql"):
            graphql_count += 1
        for attempt in item.get("attempt_records") or []:
            if isinstance(attempt, dict) and isinstance(attempt.get("duration_ms"), (int, float)):
                latency_samples.append(attempt["duration_ms"])

    success_rate = (succeeded / planned) if planned else 0.0
    retry_rate = (retry_attempts / attempts) if attempts else 0.0
    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "source": {
            "execution_report_path": display_path(report_path),
            "execution_report_schema_version": report.get("schema_version"),
            "manifest_id": (report.get("plan") or {}).get("manifest_id") if isinstance(report.get("plan"), dict) else None,
        },
        "summary": {
            "planned": planned,
            "executed": executed,
            "succeeded": succeeded,
            "failed": failed,
            "blocked": blocked,
            "unsupported": unsupported,
            "attempts": attempts,
            "retry_attempts": retry_attempts,
            "graphql_requests": graphql_count,
        },
        "quality": {
            "success_rate": success_rate,
            "retry_rate": retry_rate,
            "method_counts": dict(sorted(method_counts.items())),
            "http_status_counts": dict(sorted(status_counts.items())),
            "error_kind_counts": dict(sorted(error_kind_counts.items())),
        },
        "latency": {
            "status": "available" if latency_samples else "unavailable",
            "sample_count": len(latency_samples),
            "p95_ms": p95_nearest_rank(latency_samples),
            "reason": None if latency_samples else "no duration_ms values found in attempt_records",
        },
        "non_claims": {
            "no_live_replay_performed": True,
            "no_external_scraping_performed": True,
            "not_a_benchmark_or_production_slo": True,
        },
    }
    return payload


def write_markdown(path: Path, payload: dict[str, Any]) -> None:
    summary = payload["summary"]
    quality = payload["quality"]
    latency = payload["latency"]
    lines = [
        "# Phase 7 Run Metrics",
        "",
        f"Schema: `{payload['schema_version']}`",
        f"Generated: `{payload['generated_at_utc']}`",
        "",
        "## Summary",
        "",
        f"- Planned: {summary['planned']}",
        f"- Executed: {summary['executed']}",
        f"- Succeeded: {summary['succeeded']}",
        f"- Failed: {summary['failed']}",
        f"- Attempts: {summary['attempts']}",
        f"- Retry attempts: {summary['retry_attempts']}",
        f"- Success rate: {quality['success_rate']:.6f}",
        f"- Retry rate: {quality['retry_rate']:.6f}",
        f"- P95 latency ms: {latency['p95_ms']}",
        "",
        "## Non-claims",
        "",
        "- No live replay was performed.",
        "- No external scraping/crawling was performed.",
        "- This is not a production SLO or benchmark claim.",
        "",
    ]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-report", required=True, help="Path to tallow.request_plan_run_report.v1 JSON")
    parser.add_argument("--output-json", required=True, help="Output tallow.run_metrics.v1 JSON path")
    parser.add_argument("--output-markdown", required=True, help="Output Markdown summary path")
    args = parser.parse_args()

    report_path = resolve_path(args.execution_report)
    output_json = resolve_path(args.output_json)
    output_markdown = resolve_path(args.output_markdown)
    payload = extract_metrics(load_report(report_path), report_path)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(stable_json(payload), encoding="utf-8")
    write_markdown(output_markdown, payload)
    print(f"wrote metrics json: {display_path(output_json)}")
    print(f"wrote metrics markdown: {display_path(output_markdown)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
