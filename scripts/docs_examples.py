#!/usr/bin/env python3
"""G59 — docs that run.

Every ```tallow / ```tl fenced block in docs/ and README.md must carry an explicit
marker, and every `run` marker is executed. A stale example therefore fails CI
instead of quietly lying in the docs.

Markers (after the language, in the fence info string):

    ```tallow run                  execute; must exit 0
    ```tallow run:fail:E0125       execute; must exit non-zero AND print every listed code
    ```tallow skip:<reason>        not executed; the reason is required

An unmarked block is an error: silence is how examples rot.

Usage:
    scripts/docs_examples.py [--check] [--bin PATH] [--only PATH_SUBSTRING]

Exit codes: 0 = every block honoured its marker, 1 = at least one failure.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
import pathlib

LANGS = ("tallow", "tl")
FENCE = re.compile(r"^```(tallow|tl)([^\n]*)\n(.*?)^```[ \t]*$", re.S | re.M)
TIMEOUT = 120


def docs_files(root: pathlib.Path) -> list[pathlib.Path]:
    files = sorted(root.glob("docs/**/*.md"))
    readme = root / "README.md"
    if readme.exists():
        files.insert(0, readme)
    return files


def parse_marker(info: str) -> tuple[str, str, list[str]]:
    """Return (kind, reason_or_empty, required_error_codes)."""
    info = info.strip()
    if not info:
        return "unmarked", "", []
    head, _, rest = info.partition(":")
    head = head.strip()
    rest = rest.strip()
    if head == "run":
        if rest.startswith("fail:"):
            codes = [c.strip() for c in rest[len("fail:"):].split(",") if c.strip()]
            return "run:fail", "", codes
        codes = [c.strip() for c in rest.split(",") if c.strip()]
        return "run" if not codes else "run:fail", "", codes
    if head == "skip":
        return "skip", rest, []
    return "unmarked", "", []


def find_binary(explicit: str | None) -> str:
    for candidate in (explicit, os.environ.get("TALLOW_BIN")):
        if candidate and pathlib.Path(candidate).exists():
            return candidate
    for rel in ("target/debug/tallow", "target/release/tallow"):
        p = pathlib.Path(rel)
        if p.exists():
            return str(p.resolve())
    found = shutil.which("tallow")
    if found:
        return found
    sys.exit("docs_examples: no tallow binary (set TALLOW_BIN or build target/debug/tallow)")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="accepted for CI symmetry; failures always exit 1")
    ap.add_argument("--bin", default=None)
    ap.add_argument("--only", default=None, help="restrict to paths containing this substring")
    ap.add_argument("--root", default=".", help="repository root")
    args = ap.parse_args()

    root = pathlib.Path(args.root).resolve()
    binary = find_binary(args.bin)

    ran = failed = skipped = 0
    failures: list[str] = []

    with tempfile.TemporaryDirectory(prefix="tallow-docs-") as tmp:
        for path in docs_files(root):
            rel = path.relative_to(root)
            text = path.read_text(errors="replace")
            for m in FENCE.finditer(text):
                line = text[: m.start()].count("\n") + 1
                kind, reason, codes = parse_marker(m.group(2))
                where = f"{rel}:{line}"
                body = m.group(3)

                if kind == "unmarked":
                    failed += 1
                    failures.append(f"{where}: unmarked fence — add `run`, `run:fail:<CODE>` or `skip:<reason>`")
                    continue

                if kind == "skip":
                    if not reason:
                        failed += 1
                        failures.append(f"{where}: `skip` without a reason")
                        continue
                    skipped += 1
                    continue

                if args.only and args.only not in str(rel):
                    continue
                ran += 1
                src = pathlib.Path(tmp) / f"block_{abs(hash((str(rel), line)))}.tl"
                src.write_text(body)
                try:
                    proc = subprocess.run(
                        [binary, "run", str(src)],
                        capture_output=True, text=True, timeout=TIMEOUT,
                    )
                except subprocess.TimeoutExpired:
                    failed += 1
                    failures.append(f"{where}: timed out after {TIMEOUT}s")
                    continue

                output = proc.stdout + proc.stderr
                if kind == "run":
                    if proc.returncode != 0:
                        failed += 1
                        first = next((l for l in output.splitlines() if l.strip()), "")
                        failures.append(f"{where}: exited {proc.returncode} — {first[:160]}")
                else:
                    missing = [c for c in codes if c not in output]
                    if proc.returncode == 0 or missing:
                        failed += 1
                        why = "exited 0" if proc.returncode == 0 else f"did not print {missing}"
                        failures.append(f"{where}: expected failure {codes}, but {why}")

    print(f"docs_examples: {ran} executed, {skipped} skipped, {failed} failed")
    for f in failures:
        print(f"  FAIL {f}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
