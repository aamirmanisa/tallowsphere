#!/usr/bin/env python3
"""Build a local Phase 7 domain dashboard from a request-plan execution report."""
from __future__ import annotations

import argparse
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
SCHEMA_VERSION = "tallow.domain_dashboard.v1"


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


def root_domain(url: str) -> str:
    host = (urlparse(url).hostname or "unknown").lower().strip("[]")
    if host in {"localhost", "unknown"}:
        return host
    if all(part.isdigit() for part in host.split(".")):
        return host
    labels = [part for part in host.split(".") if part]
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return host or "unknown"


def build_dashboard(report: dict[str, Any], report_path: Path, output_json: Path, output_csv: Path) -> dict[str, Any]:
    per_domain: dict[str, dict[str, Any]] = defaultdict(
        lambda: {
            "attempts_total": 0,
            "success_count": 0,
            "fail_count": 0,
            "unresolved_count": 0,
            "status_distribution": Counter(),
            "error_kind_distribution": Counter(),
            "graphql_count": 0,
            "target_ids": [],
        }
    )
    requests = [item for item in report.get("requests", []) if isinstance(item, dict)]
    for item in requests:
        domain = root_domain(str(item.get("original_url") or item.get("executed_url") or ""))
        row = per_domain[domain]
        attempts = int(item.get("attempts") or 0)
        row["attempts_total"] += attempts
        if item.get("status") == "succeeded" or item.get("http_status") in range(200, 300):
            row["success_count"] += 1
        elif item.get("status") == "planned":
            row["unresolved_count"] += 1
        else:
            row["fail_count"] += 1
        status = item.get("http_status")
        row["status_distribution"][str(status if status is not None else "none")] += 1
        row["error_kind_distribution"][str(item.get("error_kind") or "none")] += 1
        if item.get("is_graphql"):
            row["graphql_count"] += 1
        if item.get("target_id") is not None:
            row["target_ids"].append(str(item["target_id"]))

    domains: list[dict[str, Any]] = []
    for domain, row in sorted(per_domain.items()):
        completed = row["success_count"] + row["fail_count"]
        domains.append(
            {
                "domain": domain,
                "attempts_total": row["attempts_total"],
                "success_count": row["success_count"],
                "fail_count": row["fail_count"],
                "unresolved_count": row["unresolved_count"],
                "success_rate": (row["success_count"] / completed) if completed else 0.0,
                "status_distribution": dict(sorted(row["status_distribution"].items())),
                "status_distribution_json": json.dumps(dict(sorted(row["status_distribution"].items())), sort_keys=True),
                "error_kind_distribution": dict(sorted(row["error_kind_distribution"].items())),
                "graphql_count": row["graphql_count"],
                "target_ids": sorted(row["target_ids"]),
            }
        )

    payload = {
        "schema_version": SCHEMA_VERSION,
        "generated_at_utc": utc_now(),
        "source": {"execution_report_path": display_path(report_path)},
        "outputs": {"json": display_path(output_json), "csv": display_path(output_csv)},
        "runs_total": 1,
        "runs_processed": 1,
        "rows_total": len(requests),
        "domains_total": len(domains),
        "domains": domains,
        "non_claims": {
            "no_live_replay_performed": True,
            "no_external_scraping_performed": True,
            "not_a_production_dashboard": True,
        },
    }
    return payload


def write_csv(path: Path, domains: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["domain", "attempts_total", "success_count", "fail_count", "unresolved_count", "success_rate", "status_distribution_json"],
        )
        writer.writeheader()
        for row in domains:
            writer.writerow({key: row[key] for key in writer.fieldnames})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execution-report", required=True, help="Path to tallow.request_plan_run_report.v1 JSON")
    parser.add_argument("--output-json", required=True, help="Output tallow.domain_dashboard.v1 JSON path")
    parser.add_argument("--output-csv", required=True, help="Output CSV dashboard path")
    args = parser.parse_args()

    report_path = resolve_path(args.execution_report)
    output_json = resolve_path(args.output_json)
    output_csv = resolve_path(args.output_csv)
    payload = build_dashboard(load_report(report_path), report_path, output_json, output_csv)
    output_json.parent.mkdir(parents=True, exist_ok=True)
    output_json.write_text(stable_json(payload), encoding="utf-8")
    write_csv(output_csv, payload["domains"])
    print(f"wrote domain dashboard json: {display_path(output_json)}")
    print(f"wrote domain dashboard csv: {display_path(output_csv)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
