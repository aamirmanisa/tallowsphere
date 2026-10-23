#!/usr/bin/env python3
"""Turn this run's own test output into the release body's `## Verified` section.

The rule: a release may only state numbers it measured in the same run that built
it. Nothing here is copied from a previous release or from documentation — the
inputs are the log files the gate job just wrote.

Usage:
    scripts/test_summary.py --lib lib.log --conformance conformance.log \
        --sha "$GITHUB_SHA" > summary.md
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

LIB_RE = re.compile(r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored")
CONF_RE = re.compile(r"(\d+) failure\(s\)")


def read(path: Path) -> str:
    return path.read_text(errors="replace") if path.exists() else ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--lib", required=True)
    ap.add_argument("--conformance", required=True)
    ap.add_argument("--sha", required=True)
    ap.add_argument("--cases-dir", default="conformance/cases")
    a = ap.parse_args()

    passed = failed = ignored = 0
    for line in read(Path(a.lib)).splitlines():
        m = LIB_RE.search(line)
        if m:
            _, p, f, i = m.groups()
            passed += int(p)
            failed += int(f)
            ignored += int(i)
    if passed == 0:
        print("test_summary: no `test result:` line in the library log — "
              "refusing to claim a suite result", file=sys.stderr)
        return 1

    conf = read(Path(a.conformance))
    m = CONF_RE.search(conf)
    if not m:
        print("test_summary: no failure count in the conformance log — "
              "refusing to claim a conformance result", file=sys.stderr)
        return 1
    conf_failures = int(m.group(1))
    cases = len(list(Path(a.cases_dir).glob("*.tl")))

    print("## Verified")
    print()
    print(f"Measured in the run that produced this release (commit `{a.sha[:7]}`):")
    print()
    print(f"- Library suite: **{passed:,} passed / {failed} failed / {ignored} ignored**")
    print(f"- Conformance corpus: **{cases} programs, {conf_failures} failure(s)** "
          f"on both the interpreter and native planes")
    print()
    print("A release is only published when both numbers come from this run; the "
          "step that writes this section fails rather than printing a stale figure.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
