#!/usr/bin/env python3
"""Keep the feature backlog's evidence honest.

Every row marked DONE must cite at least one real path, and any `path:line`
citation must point inside the file. A symbol named without a file is rejected:
"`parse_sdl:748`" cannot be followed by a reader, and a stale line number is the
cheapest way for a DONE claim to become false without anyone editing the row.
A `path:line` with no identifier after it is reported as an advisory (it cannot
be drift-checked) but does not fail the run.

Usage: scripts/check_backlog_evidence.py [--root .] [--file PATH]
Exit 0 = every DONE row is checkable; 1 = at least one is not.
"""

from __future__ import annotations

import argparse
import pathlib
import re
import sys

ROW = re.compile(r"^(N|G|A)\d+$")
REF = re.compile(r"([A-Za-z0-9_./-]+\.(?:rs|tl|py|md|json|toml|yml))(?::(\d+))?")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--file", default="docs/plans/2026-10-tallow-2.0-feature-backlog.md")
    args = ap.parse_args()

    root = pathlib.Path(args.root).resolve()
    doc = root / args.file
    by_name: dict[str, pathlib.Path] = {}
    for ext in ("*.rs", "*.py", "*.tl", "*.md", "*.yml"):
        for p in root.rglob(ext):
            if "target" in p.parts or "node_modules" in p.parts:
                continue
            by_name.setdefault(p.name, p)

    problems: list[str] = []
    bare: list[str] = []
    checked_rows = 0
    refs = 0

    for line in doc.read_text().splitlines():
        if not line.startswith("| "):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 7 or not ROW.match(cells[0]):
            continue
        if cells[5].upper() != "DONE":
            continue
        checked_rows += 1
        found = 0
        for span in re.findall(r"`([^`]+)`", cells[6]):
            m = REF.match(span)
            if not m:
                continue
            path, lineno = m.group(1), m.group(2)
            target = root / path
            if not target.exists():
                target = by_name.get(pathlib.Path(path).name)
            if target is None:
                problems.append(f"{cells[0]}: cited file not in tree — {path}")
                continue
            found += 1
            refs += 1
            text = target.read_text(errors="ignore")
            lines = text.splitlines()
            if lineno:
                if int(lineno) > len(lines):
                    problems.append(f"{cells[0]}: {path}:{lineno} is past EOF ({len(lines)} lines)")
                else:
                    # A line number inside the file is not evidence unless the symbol
                    # named beside it is on that line: ast.rs:313 held StmtKind::Let
                    # while the row claimed Pattern. Check the trailing identifier.
                    rest = span[m.end():].strip()
                    sym = rest.split()[0] if rest else ""
                    if sym and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", sym):
                        if sym not in lines[int(lineno) - 1]:
                            problems.append(
                                f"{cells[0]}: {path}:{lineno} does not mention `{sym}`"
                            )
                    else:
                        # No identifier follows the line number, so nothing ties the
                        # number to the code it is meant to evidence. Such a ref cannot
                        # drift *visibly*: G07 carried `src/typeck.rs:4801` for months
                        # while the file gained 66 lines above it and the row kept
                        # pointing at an unrelated `let mut covered`. Reported, not
                        # failed, because the check is advisory here and the rows that
                        # carry an unanchored ref predate this rule.
                        bare.append(f"{cells[0]}: {path}:{lineno} has no symbol anchor")
        if not found:
            problems.append(f"{cells[0]}: DONE with no checkable path — {cells[6][:70]}")

    print(f"backlog evidence: {checked_rows} DONE rows, {refs} path refs, {len(problems)} problem(s)")
    if bare:
        print(f"  advisory: {len(bare)} citation(s) name a line but no symbol to check it against")
        for b in bare:
            print(f"    {b}")
    for p in problems:
        print(f"  FAIL {p}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
