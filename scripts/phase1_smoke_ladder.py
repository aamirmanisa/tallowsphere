#!/usr/bin/env python3
"""Linux/CachyOS Phase 1 smoke ladder for the root Tallow workspace.

Non-destructive checks only. Writes a JSON report under artifacts/phase1 and
exits non-zero when any required Phase 1 rung fails.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import os
import platform
import shlex
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = REPO_ROOT / "artifacts" / "phase1" / "phase1_smoke_ladder_report.json"
DEFAULT_TALLOW_BINARY = REPO_ROOT / "target" / "debug" / "tallow"


def now() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


def trim_output(text: str, limit: int = 12_000) -> str:
    text = text.strip()
    if len(text) <= limit:
        return text
    return text[:limit] + "\n... truncated ..."


def command_text(cmd: list[str]) -> str:
    return shlex.join(str(part) for part in cmd)


class SmokeLadder:
    def __init__(self, report_path: Path) -> None:
        self.report_path = report_path
        self.results: list[dict[str, Any]] = []

    def add_result(
        self,
        *,
        name: str,
        status: str,
        message: str,
        required: bool,
        command: list[str] | None = None,
        exit_code: int | None = None,
        output: str = "",
        duration_seconds: float = 0.0,
        blocker_ids: list[str] | None = None,
    ) -> None:
        blocker_ids = blocker_ids or []
        if status == "fail" and required and "BLK-006" not in blocker_ids:
            blocker_ids = [*blocker_ids, "BLK-006"]
        result = {
            "name": name,
            "status": status,
            "required": required,
            "message": message,
            "command": command_text(command) if command else None,
            "exit_code": exit_code,
            "duration_seconds": round(duration_seconds, 3),
            "output": trim_output(output),
            "blocker_ids": blocker_ids if status in {"fail", "warn"} else [],
        }
        self.results.append(result)
        print(f"[{status.upper()}] {name}: {message}")

    def run(
        self,
        name: str,
        cmd: list[str],
        *,
        required: bool = True,
        blocker_ids: list[str] | None = None,
        timeout: int = 120,
        env: dict[str, str] | None = None,
    ) -> subprocess.CompletedProcess[str] | None:
        start = time.monotonic()
        try:
            proc = subprocess.run(
                cmd,
                cwd=REPO_ROOT,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                timeout=timeout,
            )
            duration = time.monotonic() - start
            status = "pass" if proc.returncode == 0 else ("fail" if required else "warn")
            self.add_result(
                name=name,
                status=status,
                required=required,
                message="command completed" if proc.returncode == 0 else f"command failed (exit {proc.returncode})",
                command=cmd,
                exit_code=proc.returncode,
                output=proc.stdout,
                duration_seconds=duration,
                blocker_ids=blocker_ids or [],
            )
            return proc
        except subprocess.TimeoutExpired as exc:
            duration = time.monotonic() - start
            output = exc.stdout or ""
            if isinstance(output, bytes):
                output = output.decode(errors="replace")
            self.add_result(
                name=name,
                status="fail" if required else "warn",
                required=required,
                message=f"command timed out after {timeout}s",
                command=cmd,
                exit_code=None,
                output=output,
                duration_seconds=duration,
                blocker_ids=blocker_ids or [],
            )
            return None
        except OSError as exc:
            duration = time.monotonic() - start
            self.add_result(
                name=name,
                status="fail" if required else "warn",
                required=required,
                message=f"could not start command: {exc}",
                command=cmd,
                exit_code=None,
                output="",
                duration_seconds=duration,
                blocker_ids=blocker_ids or [],
            )
            return None

    def tool(self, name: str, *, required: bool, blocker_ids: list[str] | None = None) -> None:
        path = shutil.which(name)
        if path is None:
            self.add_result(
                name=f"tool:{name}",
                status="fail" if required else "warn",
                required=required,
                message="not found on PATH",
                command=[name, "--version"],
                blocker_ids=blocker_ids or [],
            )
            return
        self.run(
            f"tool:{name}",
            [path, "--version"],
            required=required,
            blocker_ids=blocker_ids,
            timeout=60,
        )

    def write_report(self, started_at: str, tallow_binary: Path) -> dict[str, Any]:
        pass_count = sum(1 for result in self.results if result["status"] == "pass")
        warn_count = sum(1 for result in self.results if result["status"] == "warn")
        fail_count = sum(1 for result in self.results if result["status"] == "fail")
        blocker_ids = sorted(
            {
                blocker
                for result in self.results
                for blocker in result.get("blocker_ids", [])
                if result["status"] in {"fail", "warn"}
            }
        )
        report = {
            "schema_version": 1,
            "name": "phase1_smoke_ladder",
            "target": "linux-cachyos",
            "started_at": started_at,
            "finished_at": now(),
            "repo_root": str(REPO_ROOT),
            "tallow_binary": str(tallow_binary),
            "report_path": str(self.report_path),
            "fresh_shell_metadata": {
                "cwd_at_start": os.getcwd(),
                "python": sys.version.split()[0],
                "platform": platform.platform(),
                "uname": platform.uname()._asdict(),
                "shell": os.environ.get("SHELL", ""),
                "user": os.environ.get("USER", ""),
                "path": os.environ.get("PATH", ""),
            },
            "passed": fail_count == 0,
            "summary": {"pass": pass_count, "warn": warn_count, "fail": fail_count},
            "active_blockers": blocker_ids,
            "results": self.results,
        }
        self.report_path.parent.mkdir(parents=True, exist_ok=True)
        tmp_path = self.report_path.with_suffix(self.report_path.suffix + ".tmp")
        tmp_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        tmp_path.replace(self.report_path)
        return report


def resolve_path(path_text: str) -> Path:
    path = Path(path_text).expanduser()
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path


def main() -> int:
    parser = argparse.ArgumentParser(description="Run Linux/CachyOS Phase 1 Tallow smoke ladder")
    parser.add_argument("--tallow-binary", default=str(DEFAULT_TALLOW_BINARY), help="Tallow binary to smoke test")
    parser.add_argument("--report-path", default=str(DEFAULT_REPORT), help="JSON report output path")
    parser.add_argument("--skip-build", action="store_true", help="Do not run cargo build --bin tallow before binary checks")
    parser.add_argument("--skip-targeted-tests", action="store_true", help="Skip targeted browser/codegen regression tests")
    args = parser.parse_args()

    started_at = now()
    report_path = resolve_path(args.report_path)
    tallow_binary = resolve_path(args.tallow_binary)
    ladder = SmokeLadder(report_path)

    print("Tallow Phase 1 smoke ladder — Linux/CachyOS")
    print(f"Repo: {REPO_ROOT}")
    print(f"Binary: {tallow_binary}")

    ladder.run("platform:uname", ["uname", "-a"], required=True, blocker_ids=["BLK-002"], timeout=30)
    ladder.tool("cargo", required=True, blocker_ids=["BLK-002"])
    ladder.tool("rustc", required=True, blocker_ids=["BLK-002"])
    ladder.tool("git", required=True, blocker_ids=["BLK-002"])
    ladder.tool("node", required=False, blocker_ids=["BLK-002"])
    ladder.tool("npm", required=False, blocker_ids=["BLK-002"])

    ladder.run("cargo-check", ["cargo", "check", "--locked"], required=True, blocker_ids=["BLK-020"], timeout=600)

    if not args.skip_build:
        ladder.run("cargo-build-tallow", ["cargo", "build", "--locked", "--bin", "tallow"], required=True, blocker_ids=["BLK-004"], timeout=600)

    if not tallow_binary.exists():
        ladder.add_result(
            name="tallow-binary-present",
            status="fail",
            required=True,
            message=f"missing: {tallow_binary}",
            command=None,
            blocker_ids=["BLK-004"],
        )
    elif not os.access(tallow_binary, os.X_OK):
        ladder.add_result(
            name="tallow-binary-present",
            status="fail",
            required=True,
            message=f"not executable: {tallow_binary}",
            command=None,
            blocker_ids=["BLK-004"],
        )
    else:
        ladder.add_result(
            name="tallow-binary-present",
            status="pass",
            required=True,
            message=f"found executable: {tallow_binary}",
        )

    if not args.skip_targeted_tests:
        test_env = os.environ.copy()
        # Keep the default Phase 1 ladder non-live even if the caller's shell
        # exported the opt-in live browser flag. Browser launch proof is a
        # separate, explicit gate; this ladder verifies resolver/path behavior.
        test_env["TALLOW_RUN_BROWSER_LIVE_TESTS"] = "0"
        ladder.run(
            "cargo-test-browser-codegen-fetch",
            ["cargo", "test", "--locked", "--test", "browser_codegen_integration", "codegen_emits_fetch_declaration", "--", "--nocapture"],
            required=True,
            blocker_ids=["BLK-020"],
            timeout=600,
            env=test_env,
        )
        ladder.run(
            "cargo-test-browser-flow-runtime",
            ["cargo", "test", "--locked", "--test", "browser_flow_runtime_integration", "--", "--nocapture", "--test-threads=1"],
            required=True,
            blocker_ids=["BLK-020", "BLK-005"],
            timeout=600,
            env=test_env,
        )

    if tallow_binary.exists() and os.access(tallow_binary, os.X_OK):
        binary = str(tallow_binary)
        hello = str(REPO_ROOT / "examples" / "hello_simple.tl")
        ladder.run("tallow---version", [binary, "--version"], required=True, blocker_ids=["BLK-004"], timeout=60)
        ladder.run("tallow-version", [binary, "version"], required=True, blocker_ids=["BLK-004"], timeout=60)
        # Bare `tallow doctor` requires a check selector; exit 1 with usage
        # hint is the correct behavior until more checks exist.
        ladder.run("tallow-doctor", [binary, "doctor", "--stdlib-scraper"], required=True, blocker_ids=["BLK-004"], timeout=120)
        ladder.run(
            "tallow-doctor-stdlib-scraper",
            [binary, "doctor", "--stdlib-scraper"],
            required=True,
            blocker_ids=["BLK-006"],
            timeout=120,
        )
        ladder.run("tallow-check-hello", [binary, "check", hello], required=True, blocker_ids=["BLK-006"], timeout=120)
        ladder.run("tallow-run-hello", [binary, "run", hello], required=True, blocker_ids=["BLK-006"], timeout=120)
        ladder.run("tallow-browser-path", [binary, "browser", "path"], required=True, blocker_ids=["BLK-005"], timeout=120)

    report = ladder.write_report(started_at, tallow_binary)
    summary = report["summary"]
    print("")
    print(f"Summary: pass={summary['pass']} warn={summary['warn']} fail={summary['fail']}")
    print(f"Report: {report_path}")
    if report["active_blockers"]:
        print("Active blockers: " + ", ".join(report["active_blockers"]))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
