#!/usr/bin/env python3
"""Create a canonical local/mock source-backed research package.

P1-006 turns the formerly custom Ashraf-style glue into one repeatable package
initializer. It produces the inquiry scaffold, target manifest, request plan,
legacy-safe TL transport when representable, contract validation report, and a
no-network dry-run report/artifact folder.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import quote_plus

ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_tallow_request_plan.py"
RUNNER = ROOT / "scripts" / "run_tallow_request_plan.py"
VALIDATOR = ROOT / "scripts" / "validate_tallow_contracts.py"
DEFAULT_SEARCH_HOST = "www.bing.com"


class ResearchPackageError(Exception):
    """Raised when the research package cannot be initialized safely."""


def stable_json(data: Any) -> str:
    return json.dumps(data, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


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


def slugify(value: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9]+", "_", value.strip().lower()).strip("_")
    return slug or "research_package"


def load_entities(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8", newline="") as handle:
        sample = handle.read(2048)
        handle.seek(0)
        has_header = csv.Sniffer().has_header(sample) if sample.strip() else False
        if has_header:
            rows = [dict(row) for row in csv.DictReader(handle)]
        else:
            rows = [{"name": row[0], "type": row[1] if len(row) > 1 else "entity"} for row in csv.reader(handle) if row]
    entities: list[dict[str, str]] = []
    for row in rows:
        name = str(row.get("name") or row.get("entity") or "").strip()
        if not name:
            continue
        entity_type = str(row.get("type") or "entity").strip() or "entity"
        entities.append({"name": name, "type": entity_type})
    if not entities:
        raise ResearchPackageError("entities file must contain at least one entity name")
    return entities


def load_queries(path: Path, entities: list[dict[str, str]]) -> list[str]:
    text = path.read_text(encoding="utf-8")
    queries: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped.startswith(("-", "*")):
            continue
        backticks = re.findall(r"`([^`]+)`", stripped)
        if backticks:
            queries.extend(item.strip() for item in backticks if item.strip())
        else:
            query = stripped.lstrip("-* ").strip()
            if query:
                queries.append(query)
    if not queries:
        queries = [f"{entity['name']} official public records" for entity in entities]
    deduped: list[str] = []
    seen: set[str] = set()
    for query in queries:
        if query not in seen:
            deduped.append(query)
            seen.add(query)
    return deduped


def build_manifest(slug: str, queries: list[str], host: str) -> dict[str, Any]:
    targets: list[dict[str, Any]] = []
    for index, query in enumerate(queries):
        target_id = f"{slugify(slug)}_{index:03d}_{slugify(query)[:48]}"
        targets.append(
            {
                "id": target_id,
                "method": "GET",
                "url": f"https://{host}/search?q={quote_plus(query)}",
                "tags": ["public-source", "research-package", "search-discovery"],
                "compliance": {
                    "source_authority": "public_web",
                    "purpose": "source-backed public research package discovery; no contact and no private-data harvesting",
                    "legal_basis": "public_data",
                    "pii_policy": "business/public-record context only; minimize and redact personal-looking data",
                    "retention_days": 30,
                    "robots_mode": "strict",
                },
            }
        )
    return {
        "schema_version": "tallow.target_manifest.v2",
        "manifest_id": f"{slugify(slug)}_public_sources",
        "defaults": {
            "headers": {
                "Accept": "text/html,application/xhtml+xml,application/xml,text/plain,*/*;q=0.8",
                "User-Agent": "TallowBot/research-package-init public-data no-login contact-none",
            },
            "browser_fallback": {"mode": "never"},
        },
        "policy": {
            "allowlist": {"domains": [host], "url_patterns": [f"https://{host}/search*"]},
            "denylist": {"domains": [], "url_patterns": ["*/login*", "*/signin*", "*/account*", "*/captcha*"]},
            "rate_limits": {"per_domain": {host: {"concurrent": 1, "requests_per_minute": 30}}, "per_ip_pool": {"default": {"concurrent": 1, "requests_per_minute": 30}}},
            "robots": {"mode": "strict"},
        },
        "targets": targets,
    }


def run_cmd(args: list[str], output_dir: Path, command_log: list[dict[str, Any]]) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=ROOT, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False, timeout=120)
    command_log.append(
        {
            "args": [str(arg) for arg in args],
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
        }
    )
    if result.returncode != 0:
        (output_dir / "run_notes.md").write_text(render_run_notes(command_log), encoding="utf-8")
        raise ResearchPackageError(f"command failed ({result.returncode}): {' '.join(str(arg) for arg in args)}\n{result.stderr}{result.stdout}")
    return result


def render_inquiry(slug: str, entities: list[dict[str, str]], queries: list[str]) -> str:
    lines = [
        f"# {slug.replace('_', ' ').title()} Research Inquiry",
        "",
        f"Generated: {utc_now()}",
        "",
        "## Scope",
        "",
        "Public/authorized-source research only. No login-gated scraping, no CAPTCHA/paywall bypass, no contact, no private personal-data harvesting, and no speculation as fact.",
        "",
        "## Entities",
        "",
    ]
    lines.extend(f"- {entity['name']} ({entity['type']})" for entity in entities)
    lines.extend(["", "## Queries", ""])
    lines.extend(f"- `{query}`" for query in queries)
    lines.extend(["", "## Evidence workflow", "", "1. Validate `sources_manifest.json`.", "2. Build `*.request-plan.v1.json`.", "3. Run dry-run/preflight locally before any live approval.", "4. Store artifacts and cite only source-backed facts.", ""])
    return "\n".join(lines)


def render_readme(slug: str) -> str:
    upper = slug.upper()
    return f"""# {slug} canonical source-backed research package

Generated by `scripts/build_research_package.py`.

## Boundary

Canonical source-backed research package. No login-gated scraping, no CAPTCHA/paywall bypass, no private API reverse engineering, no contact, and no private personal-data harvesting.

## Files

- `{upper}.md` — research inquiry scaffold.
- `entities.csv` — input entities.
- `queries.md` — input query plan.
- `sources_manifest.json` — `tallow.target_manifest.v2` public-source manifest.
- `{slug}.request-plan.v1.json` — generated request plan.
- `{slug}.request-plan-report.json` — request-plan build report.
- `{slug}.legacy-http-batch.tl` — legacy-safe TL transport when representable.
- `tallow_contract_validation_report.json` — contract validation report.
- `request_plan_dry_run_report.json` — no-network dry-run report.
- `request_plan_dry_run_artifacts/` — dry-run artifact folder.
- `run_notes.md` and `tallow_run_report.md` — command log and package status.

## Next safe command

```bash
python3 scripts/run_tallow_request_plan.py \\
  --plan {slug}.request-plan.v1.json \\
  --report-path request_plan_dry_run_report.json \\
  --output-dir request_plan_dry_run_artifacts \\
  --mock-base-url http://127.0.0.1:9 \\
  --dry-run
```
"""


def render_run_notes(command_log: list[dict[str, Any]]) -> str:
    lines = ["# Run notes", "", f"Generated: {utc_now()}", "", "## Commands", ""]
    for item in command_log:
        lines.extend(
            [
                "```bash",
                " ".join(item["args"]),
                "```",
                f"Return code: `{item['returncode']}`",
                "",
            ]
        )
    return "\n".join(lines)


def render_run_report(slug: str, output_dir: Path, command_log: list[dict[str, Any]]) -> str:
    dry_run_path = output_dir / "request_plan_dry_run_report.json"
    dry_run = json.loads(dry_run_path.read_text(encoding="utf-8")) if dry_run_path.exists() else {}
    return "\n".join(
        [
            f"# {slug} Tallow run report",
            "",
            f"Generated: {utc_now()}",
            "",
            "## Status",
            "",
            f"- Contract/dry-run passed: `{bool(dry_run.get('passed'))}`",
            f"- Planned requests: `{dry_run.get('summary', {}).get('planned')}`",
            f"- Executed requests: `{dry_run.get('summary', {}).get('executed')}`",
            "- Network mode: dry-run/no-network with mock loopback base URL.",
            "",
            "## Commands run",
            "",
            *[f"- `{ ' '.join(item['args']) }` -> `{item['returncode']}`" for item in command_log],
            "",
        ]
    )


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Initialize a canonical source-backed research package")
    parser.add_argument("--slug", required=True, help="Package slug, e.g. ashraf_ali_business_inquiry")
    parser.add_argument("--entities", required=True, help="CSV with at least a name column")
    parser.add_argument("--queries", required=True, help="Markdown query plan; backticked bullet items become search targets")
    parser.add_argument("--public-only", action="store_true", help="Required safety boundary: public/authorized source package only")
    parser.add_argument("--output", required=True, help="Output package directory")
    parser.add_argument("--search-host", default=DEFAULT_SEARCH_HOST, help="Public search host for generated discovery targets")
    parser.add_argument("--mock-base-url", default="http://127.0.0.1:9", help="Loopback base URL used for no-network dry-run classification")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    try:
        if not args.public_only:
            raise ResearchPackageError("--public-only is required; authorized/live packages need a separate approval-gated workflow")
        slug = slugify(args.slug)
        output_dir = resolve_path(args.output)
        output_dir.mkdir(parents=True, exist_ok=True)
        entities_path = resolve_path(args.entities)
        queries_path = resolve_path(args.queries)
        entities = load_entities(entities_path)
        queries = load_queries(queries_path, entities)
        shutil.copyfile(entities_path, output_dir / "entities.csv")
        shutil.copyfile(queries_path, output_dir / "queries.md")

        inquiry_path = output_dir / f"{slug.upper()}.md"
        manifest_path = output_dir / "sources_manifest.json"
        plan_path = output_dir / f"{slug}.request-plan.v1.json"
        builder_report_path = output_dir / f"{slug}.request-plan-report.json"
        legacy_tl_path = output_dir / f"{slug}.legacy-http-batch.tl"
        contract_report_path = output_dir / "tallow_contract_validation_report.json"
        dry_run_report_path = output_dir / "request_plan_dry_run_report.json"
        dry_run_artifacts = output_dir / "request_plan_dry_run_artifacts"

        inquiry_path.write_text(render_inquiry(slug, entities, queries), encoding="utf-8")
        manifest_path.write_text(stable_json(build_manifest(slug, queries, args.search_host)), encoding="utf-8")
        (output_dir / "README.md").write_text(render_readme(slug), encoding="utf-8")

        command_log: list[dict[str, Any]] = []
        run_cmd([sys.executable, "-B", str(VALIDATOR), "--target-manifest", str(manifest_path), "--report-path", str(contract_report_path)], output_dir, command_log)
        run_cmd(
            [
                sys.executable,
                "-B",
                str(BUILDER),
                "--manifest",
                str(manifest_path),
                "--output",
                str(plan_path),
                "--report-path",
                str(builder_report_path),
                "--legacy-tl-output",
                str(legacy_tl_path),
            ],
            output_dir,
            command_log,
        )
        run_cmd(
            [
                sys.executable,
                "-B",
                str(RUNNER),
                "--plan",
                str(plan_path),
                "--report-path",
                str(dry_run_report_path),
                "--output-dir",
                str(dry_run_artifacts),
                "--mock-base-url",
                str(args.mock_base_url),
                "--dry-run",
            ],
            output_dir,
            command_log,
        )
        (output_dir / "run_notes.md").write_text(render_run_notes(command_log), encoding="utf-8")
        (output_dir / "tallow_run_report.md").write_text(render_run_report(slug, output_dir, command_log), encoding="utf-8")
        print(stable_json({"passed": True, "package_dir": display_path(output_dir), "request_count": len(queries), "dry_run_report": display_path(dry_run_report_path)}), end="")
        return 0
    except (OSError, json.JSONDecodeError, subprocess.TimeoutExpired, ResearchPackageError) as exc:
        print(f"research package init failed: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
