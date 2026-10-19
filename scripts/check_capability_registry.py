#!/usr/bin/env python3
"""Check the machine-readable capability registry against the code.

`surface_entry` in src/stdlib/browser.rs asserts, per method, which planes
implement it. Those assertions were wrong twice: `Page.goto_antibot` claimed
`implemented_interp_routed` with zero arms, and `Page.resolve_antibot` had no
entry at all. Both were found by hand, weeks late.

This script derives the claim from the registry and the fact from the arms:

    status contains "native"  -> src/codegen.rs must contain ("Page", "X")
    status contains "interp"  -> src/interp.rs  must contain ("Page", "X")
    status is declared_*      -> neither file may contain it

Exit 1 on any mismatch. Run: python3 scripts/check_capability_registry.py
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "src" / "stdlib" / "browser.rs"
PLANES = {"native": ROOT / "src" / "codegen.rs", "interp": ROOT / "src" / "interp.rs"}

LABEL_AND_STATUS = re.compile(r'"([^"]+)"\s*,\s*"([^"]*)"\s*,\s*"([a-z_]+)"')


def entries(text: str) -> list[tuple[str, str, str]]:
    """Yield (label, area, status) per surface_entry call.

    Comment lines are stripped first: the `goto_antibot` entry documents its own
    status inline, and a flat regex over the raw text silently skipped it —
    a checker that undercounts its population is the defect it exists to catch.
    """
    found: list[tuple[str, str, str]] = []
    for block in text.split("surface_entry(")[1:]:
        body = "\n".join(
            line for line in block.splitlines() if not line.strip().startswith("//")
        )
        match = LABEL_AND_STATUS.search(body)
        if match:
            found.append((match.group(1), match.group(2), match.group(3)))
    return found


def arms(path: Path, method: str) -> int:
    text = path.read_text(encoding="utf-8", errors="replace")
    return len(re.findall(r'\(\s*"Page"\s*,\s*"%s"' % re.escape(method), text))


def main() -> int:
    text = REGISTRY.read_text(encoding="utf-8", errors="replace")
    problems: list[str] = []
    checked = 0

    for label, _area, status in entries(text):
        match = re.match(r"Page\.([A-Za-z0-9_]+)", label)
        if not match:
            continue
        method = match.group(1)
        checked += 1
        native = arms(PLANES["native"], method)
        interp = arms(PLANES["interp"], method)

        if status.startswith("declared_"):
            if native or interp:
                problems.append(
                    f"{method}: registry says {status}, but arms exist "
                    f"(codegen={native}, interp={interp})"
                )
            continue
        if "native" in status and native == 0:
            problems.append(f"{method}: registry says {status}, codegen has no arm")
        if "interp" in status and interp == 0:
            problems.append(f"{method}: registry says {status}, interp has no arm")
        # Reverse assertions are deliberately omitted: statuses such as
        # `implemented_mock_contract_tested` describe a plane this script cannot
        # enumerate, so "no arm expected" would produce false failures.

    for problem in problems:
        print(f"MISMATCH {problem}")
    print(f"checked {checked} Page entries, {len(problems)} mismatches")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
