#!/usr/bin/env python3
"""Run the conformance suite against a Tallow binary.

Every case is a `.tl` program plus a `.json` expectation produced by `--refresh`.
A case is accepted only when BOTH planes (interpreter and native) agree with the
expectation, so a plane that silently diverges fails the suite instead of the user.

    python3 conformance/run.py --tallow /path/to/tallow
    python3 conformance/run.py --tallow /path/to/tallow --refresh
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

CASES = Path(__file__).resolve().parent / "cases"
PLANES = (("interpret", ["--interpret"]), ("native", ["--require-native"]))


def run_one(tallow: str, program: Path, plane_args: list[str]) -> dict:
    p = subprocess.run([tallow, "run", *plane_args, str(program)],
                       capture_output=True, text=True, timeout=120,
                       env={"TALLOW_ALLOW_DIRECT": "1", "PATH": "/usr/bin:/bin"})
    return {"stdout": p.stdout, "stderr": p.stderr, "exit": p.returncode}


def agrees(expect: dict, got: dict) -> tuple[bool, str]:
    kind = expect["kind"]
    if kind == "accept":
        if got["exit"] != 0:
            return False, f"exit {got['exit']}: {got['stderr'].strip()[:200]}"
        if got["stdout"] != expect["stdout"]:
            return False, f"stdout {got['stdout']!r} != {expect['stdout']!r}"
        return True, ""
    if kind == "reject":
        if got["exit"] == 0:
            return False, "accepted, but the suite expects a diagnostic"
        if expect.get("code") and expect["code"] not in got["stderr"]:
            return False, f"missing {expect['code']} in diagnostics"
        return True, ""
    if kind == "runtime":
        if got["exit"] == 0:
            return False, "ran, but the suite expects a runtime error"
        if expect.get("message") and expect["message"] not in got["stderr"]:
            return False, f"missing {expect['message']!r} in stderr"
        return True, ""
    raise ValueError(f"unknown kind {kind}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--tallow", required=True)
    ap.add_argument("--refresh", action="store_true",
                    help="rewrite expectations from the reference engine (both planes must agree)")
    a = ap.parse_args()

    failures = 0
    for program in sorted(CASES.glob("*.tl")):
        meta_path = program.with_suffix(".json")
        results = {name: run_one(a.tallow, program, args) for name, args in PLANES}

        if a.refresh:
            interp, native = results["interpret"], results["native"]
            if interp["exit"] != native["exit"] or interp["stdout"] != native["stdout"]:
                print(f"REFUSED {program.name}: planes disagree "
                      f"(interp exit {interp['exit']}, native exit {native['exit']})")
                failures += 1
                continue
            if interp["exit"] == 0:
                expect = {"kind": "accept", "stdout": interp["stdout"]}
            elif "non-exhaustive match" in interp["stderr"]:
                expect = {"kind": "runtime", "message": "non-exhaustive match"}
            else:
                import re
                m = re.search(r"(E\d{4})", interp["stderr"])
                expect = {"kind": "reject", "code": m.group(1) if m else ""}
            meta_path.write_text(json.dumps(expect, indent=2) + "\n")
            print(f"refreshed {program.name}: {expect}")
            continue

        if not meta_path.exists():
            print(f"MISSING  {program.name}: no expectation (run --refresh)")
            failures += 1
            continue
        expect = json.loads(meta_path.read_text())
        for name, got in results.items():
            ok, why = agrees(expect, got)
            if not ok:
                print(f"FAIL     {program.name} [{name}] {why}")
                failures += 1
                break

    print(f"\n{failures} failure(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
