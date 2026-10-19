#!/usr/bin/env python3
"""Every integration test target must be either run by CI or explicitly excluded.

`cargo test --lib` cannot see `tests/*.rs`. Before this check, 13 of 79 targets
were named in the workflow and the rest ran in no pipeline — a fixture pinned by
nothing is a contract enforced by nothing.

Two states are allowed:
  * the target is named by a `--test <name>` flag somewhere in ci.yml, or
  * it appears in ci-excluded-suites.txt with a reason.

Anything else is a silent skip and fails this check.

Run: python3 scripts/check_test_coverage.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
EXCLUSIONS = ROOT / "ci-excluded-suites.txt"


def main() -> int:
    ci = WORKFLOW.read_text(encoding="utf-8")
    run_names = set(re.findall(r"--test\s+([a-z0-9_]+)", ci))

    excluded: dict[str, str] = {}
    if EXCLUSIONS.exists():
        for raw in EXCLUSIONS.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            name, _, reason = line.partition(":")
            excluded[name.strip()] = reason.strip()

    targets = sorted(p.stem for p in (ROOT / "tests").glob("*.rs"))
    unaccounted = [t for t in targets if t not in run_names and t not in excluded]

    for name in unaccounted:
        print(f"UNACCOUNTED {name}: not run by CI and not listed in ci-excluded-suites.txt")
    print(
        f"{len(targets)} targets: {len(run_names & set(targets))} in CI, "
        f"{len(excluded)} excluded with a reason, {len(unaccounted)} unaccounted"
    )
    return 1 if unaccounted else 0


if __name__ == "__main__":
    sys.exit(main())
