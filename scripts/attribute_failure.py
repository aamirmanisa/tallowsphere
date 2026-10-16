#!/usr/bin/env python3
"""Attribute a CI test failure: pre-existing at the base revision, or caused here?

The house rule is that a pre-existing failure must not be reported as this
change's. That rule currently lives in prose — a comment in ci.yml explains the
warning baseline, and plan documents hand-annotate "this failure is NOT from this
work". Prose does not survive a CI run: a red job prints a failing test name and
leaves the reader to work out whose it is.

This makes the attribution explicit and provable. For each failing test it runs
the same test at the merge-base revision, in a detached worktree with its own
target dir, and labels the result:

    PRE-EXISTING     fails at the base too      -> not this change's fault
    CAUSED           passes at the base         -> this change broke it
    NOT-REPRODUCED   passes on re-run here      -> rerun before believing the log
    UNKNOWN          could not run at the base  -> say so, never guess

It never infers from file paths or from who touched what: the label comes from
running the test. Exit 1 if any test is CAUSED, 0 otherwise (UNKNOWN does not
fail the run -- it is reported, not hidden).

Usage:
    # from a CI log
    cargo test --locked --lib 2>&1 | tee /tmp/t.log || \
        scripts/attribute_failure.py --log /tmp/t.log

    # explicit names
    scripts/attribute_failure.py --test cli::pkg::tests::foo --base origin/main

    # prove the classification logic without building anything
    scripts/attribute_failure.py --self-test
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# `test path::to::name ... FAILED`
FAILED_RE = re.compile(r"^test\s+(\S+)\s+\.\.\.\s+FAILED\s*$", re.M)

PRE_EXISTING, CAUSED, NOT_REPRODUCED, UNKNOWN = (
    "PRE-EXISTING",
    "CAUSED",
    "NOT-REPRODUCED",
    "UNKNOWN",
)


def classify(passes_at_base, passes_here):
    """The whole attribution rule, in one place.

    A label is never inferred from a file path, an author, or a heuristic -- it
    comes from running the test at both revisions.
    """
    if passes_at_base is None or passes_here is None:
        return UNKNOWN  # could not run it; say so rather than guess
    if passes_here:
        return NOT_REPRODUCED  # it is not failing now -- rerun before believing the log
    if not passes_at_base:
        return PRE_EXISTING  # fails at the base too: not this change's
    return CAUSED  # passed at the base, fails here


def failing_tests_from_log(path: Path):
    text = path.read_text(encoding="utf-8", errors="replace")
    return sorted(set(FAILED_RE.findall(text)))


def git(*args, cwd=REPO):
    p = subprocess.run(["git", *args], cwd=str(cwd), capture_output=True, text=True)
    return p.returncode, p.stdout.strip()


def resolve_base(explicit: str | None) -> str | None:
    if explicit:
        return explicit
    for cand in ("origin/main", "origin/master", "main", "master"):
        rc, out = git("rev-parse", "--verify", "--quiet", cand)
        if rc == 0:
            rc, mb = git("merge-base", "HEAD", cand)
            if rc == 0 and mb:
                return mb
    rc, out = git("rev-parse", "--verify", "--quiet", "HEAD~1")
    return out if rc == 0 else None


def run_tests(runner, names, cwd, env=None):
    """Return {name: bool passed}. `runner` is argv prefix; names are appended."""
    results = {}
    for n in names:
        try:
            p = subprocess.run(
                [*runner, n, "--", "--exact"],
                cwd=str(cwd),
                env=env,
                capture_output=True,
                text=True,
                timeout=1800,
            )
            results[n] = p.returncode == 0
        except Exception:
            results[n] = None  # could not run
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--log", default="", help="file containing cargo test output")
    ap.add_argument("--test", action="append", default=[], help="a failing test name (repeatable)")
    ap.add_argument("--base", default="", help="base revision (default: merge-base with main)")
    ap.add_argument("--runner", default="cargo test --locked --lib")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    names = list(args.test)
    if args.log:
        p = Path(args.log)
        if not p.is_file():
            print(f"attribute-failure: no such log: {p}", file=sys.stderr)
            return 2
        names += failing_tests_from_log(p)

    names = sorted(set(names))
    if not names:
        print("attribute-failure: no failing tests named or found in the log -- nothing to attribute")
        return 0

    base = resolve_base(args.base or None)
    if not base:
        print("attribute-failure: cannot resolve a base revision; every test is UNKNOWN", file=sys.stderr)
        for n in names:
            print(f"  {UNKNOWN      :12}  {n}")
        return 0

    runner = args.runner.split()
    print(f"attribute-failure: {len(names)} failing test(s); base = {base[:12]}")
    print("  (base is run in a detached worktree with its own target dir; nothing in your tree is touched)")

    tmp = Path(tempfile.mkdtemp(prefix="attr-base-", dir=os.environ.get("TMPDIR") or None))
    wt = tmp / "tree"
    rc, _ = git("worktree", "add", "--detach", "--quiet", str(wt), base)
    if rc != 0:
        print("  could not create a base worktree -- reporting UNKNOWN", file=sys.stderr)
        shutil.rmtree(tmp, ignore_errors=True)
        for n in names:
            print(f"  {UNKNOWN      :12}  {n}")
        return 0

    try:
        env = dict(os.environ)
        env["CARGO_TARGET_DIR"] = str(tmp / "target")
        at_base = run_tests(runner, names, wt, env)
        here = run_tests(runner, names, REPO)
    finally:
        git("worktree", "remove", "--force", str(wt))
        shutil.rmtree(tmp, ignore_errors=True)

    caused = []
    for n in names:
        label = classify(at_base.get(n), here.get(n))
        if label == CAUSED:
            caused.append(n)
        print(f"  {label:14}  {n}")

    print()
    print(f"ATTRIBUTION: {len(caused)} caused, {len(names) - len(caused)} pre-existing/unknown")
    return 1 if caused else 0


# --------------------------------------------------------------------------
# Self-test: prove the classification without building anything. The runner is
# replaced by a table, so the mapping (fail-at-base -> PRE-EXISTING, pass-at-base
# -> CAUSED, un-runnable -> UNKNOWN) is exercised directly.
# --------------------------------------------------------------------------
# (name, passes_at_base, passes_here, EXPECTED LABEL). Expectations are written
# out literally rather than derived from the rule, so this cannot agree with a
# broken classifier by construction -- it caught the mislabelled case below.
CASES = [
    ("suite::pre_existing", False, False, PRE_EXISTING),
    ("suite::caused", True, False, CAUSED),
    ("suite::not_reproduced", True, True, NOT_REPRODUCED),
    ("suite::flaky_gone", False, True, NOT_REPRODUCED),
    ("suite::unrunnable_base", None, False, UNKNOWN),
    ("suite::unrunnable_here", False, None, UNKNOWN),
]


def self_test() -> int:
    print("classification:")

    def state(v):
        return "pass" if v else ("fail" if v is False else "n/a")

    ok = True
    for name, b, h, want in CASES:
        got = classify(b, h)
        if got != want:
            ok = False
        mark = "ok " if got == want else "BAD"
        print(f"  {mark} {name:22} base={state(b):4} here={state(h):4} -> {got:14} (want {want})")

    print("log parser:")
    with tempfile.TemporaryDirectory() as td:
        log = Path(td) / "t.log"
        log.write_text(
            "running 3 tests\n"
            "test suite::caused ... FAILED\n"
            "test suite::fine ... ok\n"
            "test suite::pre_existing ... FAILED\n"
            "unrelated line\n",
            encoding="utf-8",
        )
        names = failing_tests_from_log(log)
        want = ["suite::caused", "suite::pre_existing"]
        if names == want:
            print(f"  ok  parsed {names}")
        else:
            ok = False
            print(f"  BAD parsed {names}, want {want}")

    print(f"self-test: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
