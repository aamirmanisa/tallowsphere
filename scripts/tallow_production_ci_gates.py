#!/usr/bin/env python3
"""P2-006 Tallow production CI gate runner.

The default matrix is offline/fail-closed: it runs local Rust/Python gates plus
P2-005 benchmark scaffolding checks, while refusing live benchmark, paid API, and
Firecrawl-service credentials in the default CI environment.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

def find_repo_root(start: Path) -> Path:
    for candidate in (start, *start.parents):
        if (candidate / "Cargo.toml").exists() and (candidate / "scripts").is_dir():
            return candidate
    raise RuntimeError(f"could not locate repo root from {start}")


REPO_ROOT = find_repo_root(Path(__file__).resolve())
FALSE_VALUES = {"", "0", "false", "no", "off"}


@dataclass(frozen=True)
class Gate:
    gate_id: str
    card: str
    command: str
    live_safe: bool = True


REQUIRED_GATES: tuple[Gate, ...] = (
    Gate("p2-006-cargo-check", "P2-006", "cargo check --locked"),
    Gate("p2-006-browser-contracts", "P2-006", "cargo test --locked --test browser_contracts"),
    Gate("p2-006-request-plan-cli", "P2-006", "cargo test --locked --test request_plan_cli -- --nocapture"),
    Gate("p2-006-request-plan-builder", "P2-006", "python3 -B -m unittest tests.test_phase2_request_plan_builder -v"),
    Gate("p2-006-request-plan-runner", "P2-006", "python3 -B -m unittest tests.test_phase2_request_plan_runner -v"),
    Gate("p2-006-extraction-rows", "P2-006", "python3 -B -m unittest tests.test_phase5_extraction_rows -v"),
    Gate("p2-006-compliance-gate", "P2-006", "python3 -B -m unittest tests.test_phase9_compliance_gate -v"),
    Gate("p2-006-phase1-smoke", "P2-006", "python3 scripts/phase1_smoke_ladder.py"),
    Gate("p2-006-contract-validation", "P2-006", "python3 scripts/validate_tallow_contracts.py"),
    Gate("p2-005-benchmark-protocol", "P2-005", "python3 -B -m unittest tests.test_phase10_benchmark_protocol -v"),
    Gate("p2-005-benchmark-help", "P2-005", "python3 scripts/benchmark_phase10_fixture.py --help"),
)

LIVE_ENV_FLAGS = (
    "TALLOW_RUN_LIVE_BENCHMARKS",
    "TALLOW_LIVE_BENCHMARK_APPROVAL",
    "TALLOW_ENABLE_PAID_APIS",
    "FIRECRAWL_API_KEY",
    "FIRECRAWL_TOKEN",
    "FIRECRAWL_BASE_URL",
)

FORBIDDEN_COMMAND_FRAGMENTS = (
    "benchmark_all_sites",
    "run_baseline_benchmark_500",
    "run_scraping_benchmark_pack",
    "run_competitor_parity_benchmarks",
    "firecrawl-self-hosted",
    "--live",
    "--paid",
)


def is_false(value: str | None) -> bool:
    return (value or "").strip().lower() in FALSE_VALUES


def fail_closed_environment() -> list[str]:
    errors: list[str] = []
    if not is_false(os.environ.get("TALLOW_RUN_BROWSER_LIVE_TESTS")):
        errors.append("TALLOW_RUN_BROWSER_LIVE_TESTS must be unset/false for CI gates")
    for name in LIVE_ENV_FLAGS:
        if not is_false(os.environ.get(name)):
            errors.append(f"{name} must be unset/false for default CI gates")
    for gate in REQUIRED_GATES:
        lowered = gate.command.lower()
        for fragment in FORBIDDEN_COMMAND_FRAGMENTS:
            if fragment in lowered:
                errors.append(f"forbidden live/paid command fragment in {gate.gate_id}: {fragment}")
    return errors


def command_env() -> dict[str, str]:
    env = os.environ.copy()
    env["TALLOW_RUN_BROWSER_LIVE_TESTS"] = "0"
    env["TALLOW_RUN_LIVE_BENCHMARKS"] = "0"
    env["FIRECRAWL_DISABLED"] = "1"
    env["RUST_MIN_STACK"] = env.get("RUST_MIN_STACK", "8388608")
    return env


def print_gate_list() -> None:
    print(json.dumps([asdict(gate) for gate in REQUIRED_GATES], indent=2, sort_keys=True))


def check_workflow(path: Path) -> int:
    text = path.read_text(encoding="utf-8")
    uses_runner = "python3 scripts/tallow_production_ci_gates.py --run" in text
    missing: list[str] = []
    for gate in REQUIRED_GATES:
        if gate.command not in text and not uses_runner:
            missing.append(f"{gate.gate_id}: {gate.command}")
    if missing:
        print("CI workflow is missing required gates:", file=sys.stderr)
        for item in missing:
            print(f"- {item}", file=sys.stderr)
        return 2
    print(f"CI workflow gate check passed: {path}")
    print(f"required_gate_count={len(REQUIRED_GATES)}")
    return 0


def run_gates() -> int:
    env_errors = fail_closed_environment()
    if env_errors:
        for error in env_errors:
            print(error, file=sys.stderr)
        return 2
    for gate in REQUIRED_GATES:
        print(f"::group::{gate.gate_id}")
        print(f"$ {gate.command}")
        proc = subprocess.run(shlex.split(gate.command), cwd=REPO_ROOT, env=command_env(), check=False)
        print("::endgroup::")
        if proc.returncode != 0:
            print(f"gate failed: {gate.gate_id} (exit {proc.returncode})", file=sys.stderr)
            return proc.returncode or 1
    print("all Tallow production CI gates passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Run/check fail-closed Tallow production CI gates")
    parser.add_argument("--list", action="store_true", help="Print required gate matrix as JSON")
    parser.add_argument("--check-workflow", help="Verify a workflow contains or delegates to the required matrix")
    parser.add_argument("--run", action="store_true", help="Execute all required gates")
    args = parser.parse_args()

    if args.list:
        print_gate_list()
        return 0
    if args.check_workflow:
        return check_workflow(Path(args.check_workflow))
    if args.run:
        return run_gates()
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
