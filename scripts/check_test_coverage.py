#!/usr/bin/env python3
"""Every integration test target must be run by CI or registered as debt.

`cargo test --lib` cannot see `tests/*.rs`. Before this check, most targets ran
in no pipeline — a fixture pinned by nothing is a contract enforced by nothing.

Three states are allowed:
  * the target is named by a `--test <name>` flag somewhere in ci.yml,
  * it is in the exclusion registry with a bucket, an owner and a future expiry,
  * it does not exist (the registry may mention a deleted target — that fails
    too, because a registry that outlives its targets stops being read).

The registry format is `target | bucket | owner | reason | YYYY-MM-DD`. Entries
expire: an exclusion that nobody revisited is indistinguishable from a decision
nobody made.

Run: python3 scripts/check_test_coverage.py
"""
from __future__ import annotations

import datetime as dt
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"
EXCLUSIONS = ROOT / "ci-excluded-suites.txt"
BUCKETS = {"browser", "service", "perf", "host", "parked", "triage"}


def parse_registry(text: str) -> tuple[dict[str, tuple[str, str, str, dt.date]], list[str]]:
    entries: dict[str, tuple[str, str, str, dt.date]] = {}
    problems: list[str] = []
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) != 5:
            problems.append(f"MALFORMED {line!r}: expected target | bucket | owner | reason | expiry")
            continue
        name, bucket, owner, reason, expires = parts
        if bucket not in BUCKETS:
            problems.append(f"BAD BUCKET {name}: {bucket!r} not in {sorted(BUCKETS)}")
            continue
        if not owner:
            problems.append(f"NO OWNER {name}")
        try:
            when = dt.date.fromisoformat(expires)
        except ValueError:
            problems.append(f"BAD EXPIRY {name}: {expires!r} is not YYYY-MM-DD")
            continue
        entries[name] = (bucket, owner, reason, when)
    return entries, problems


def main() -> int:
    ci = WORKFLOW.read_text(encoding="utf-8")
    run_names = set(re.findall(r"--test\s+([a-z0-9_]+)", ci))

    entries, problems = parse_registry(EXCLUSIONS.read_text(encoding="utf-8"))
    today = dt.date.today()
    for name, (bucket, owner, _reason, when) in sorted(entries.items()):
        if when < today:
            problems.append(f"EXPIRED {name} ({bucket}, owner {owner}) — triage it or move it into CI")

    targets = sorted(p.stem for p in (ROOT / "tests").glob("*.rs"))
    unknown = sorted(set(entries) - set(targets))
    for name in unknown:
        problems.append(f"STALE {name}: listed in the registry but no tests/{name}.rs exists")

    unaccounted = [t for t in targets if t not in run_names and t not in entries]

    for name in unaccounted:
        print(f"UNACCOUNTED {name}: not run by CI and not listed in ci-excluded-suites.txt")
    for p in problems:
        print(p)

    by_bucket: dict[str, int] = {}
    for bucket, _owner, _reason, _when in entries.values():
        by_bucket[bucket] = by_bucket.get(bucket, 0) + 1
    summary = ", ".join(f"{k} {v}" for k, v in sorted(by_bucket.items()))
    print(
        f"{len(targets)} targets: {len(run_names & set(targets))} in CI, "
        f"{len(entries)} registered as debt ({summary}), {len(unaccounted)} unaccounted, "
        f"{len(problems)} registry problem(s)"
    )
    return 1 if unaccounted or problems else 0


if __name__ == "__main__":
    sys.exit(main())
