#!/usr/bin/env python3
"""Census every method in `impl Page` against the codegen and interpreter arms.

Why: the three-entry registry in src/stdlib/browser.rs does not cover the rest of
the surface, and two "unlowered method" claims were once invented from a grep that
matched only the exact tuple form `("Page", "name")`. The callbacks are dispatched
through or-patterns (`("Page", m @ ("on_console" | ...))`), so an exact-tuple grep
reports them as missing when they are implemented. This script matches by quoted
name instead, which is the property that actually matters.

Exit codes: 0 = every method is mentioned on both planes (or allowlisted),
1 = at least one method is missing a plane.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Methods that are deliberately refused on both planes, with the reason. An entry
# here is a decision, not a gap: the refusal itself is pinned by
# tests/browser_unlowered_gaps.rs.
REFUSED = {
    "goto_antibot": "egress is process-level (BrowserConfig.proxy); honest home is BrowserPool.create",
}


def page_methods() -> list[str]:
    lines = (ROOT / "stdlib/browser.tl").read_text().splitlines()
    start = next(i for i, line in enumerate(lines) if line.strip().startswith("impl Page"))
    depth = 0
    found: list[str] = []
    for i in range(start, len(lines)):
        line = lines[i]
        depth += line.count("{") - line.count("}")
        m = re.match(r"\s*fn\s+([a-z_0-9]+)\s*\(", line)
        if m and depth >= 1:
            found.append(m.group(1))
        if i > start and depth <= 0:
            break
    return found


def main() -> int:
    methods = page_methods()
    codegen = (ROOT / "src/codegen.rs").read_text()
    interp = (ROOT / "src/interp.rs").read_text()

    missing_native = [m for m in methods if f'"{m}"' not in codegen]
    missing_interp = [m for m in methods if f'"{m}"' not in interp]

    problems = 0
    for name in missing_native:
        if name in REFUSED:
            print(f"refused-on-purpose  Page.{name}: {REFUSED[name]}")
        else:
            problems += 1
            print(f"MISMATCH  Page.{name} has no codegen arm")
    for name in missing_interp:
        if name in REFUSED:
            continue
        problems += 1
        print(f"MISMATCH  Page.{name} has no interpreter arm")

    implemented = len(methods) - len(set(missing_native) | set(missing_interp))
    print(f"checked {len(methods)} Page methods, {implemented} on both planes, {problems} mismatch(es)")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
