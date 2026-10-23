#!/usr/bin/env python3
"""Build a GitHub release body from CHANGELOG.md, or fail loudly.

The rule this enforces: every release states WHAT WAS ADDED and WHAT WAS FIXED.
A release without both headings does not get a body, which means the workflow
fails before anything is published — a missing explanation is a release blocker,
not a formatting preference.

Usage:
    scripts/release_body.py v1.2.1 > release_body.md
    scripts/release_body.py v1.2.1 --check      # exit 1 if the rule is unmet
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

CHANGELOG = Path(__file__).resolve().parent.parent / "CHANGELOG.md"
REQUIRED = ("added", "fixed")

VERIFY_BLOCK = """
---

Five targets, each with a `.sha256` sidecar and a Sigstore keyless signature:

```
cosign verify-blob --signature <archive>.sig <archive>
sha256sum -c <archive>.sha256
```
"""


def section(text: str, version: str) -> str | None:
    """Return the changelog section for `version`, without the next heading."""
    pattern = re.compile(rf"^## \[{re.escape(version)}\][^\n]*\n", re.MULTILINE)
    m = pattern.search(text)
    if not m:
        return None
    rest = text[m.end():]
    nxt = re.search(r"^## \[", rest, re.MULTILINE)
    body = rest[: nxt.start()] if nxt else rest
    return body.strip("\n")


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print("usage: release_body.py <vX.Y.Z> [--check] [--verified PATH]", file=sys.stderr)
        return 64
    version = argv[1]
    check = "--check" in argv[2:]
    verified = None
    if "--verified" in argv[2:]:
        idx = argv.index("--verified")
        if idx + 1 >= len(argv):
            print("release_body: --verified needs a path", file=sys.stderr)
            return 64
        verified = Path(argv[idx + 1])
        if not verified.exists() or not verified.read_text().strip():
            print(f"release_body: {verified} is missing or empty — a Verified "
                  f"section must carry this run's measured numbers", file=sys.stderr)
            return 1

    body = section(CHANGELOG.read_text(), version)
    if body is None:
        print(
            f"release_body: no CHANGELOG section for {version}; "
            f"every release must record what was added and what was fixed",
            file=sys.stderr,
        )
        return 1

    lowered = body.lower()
    missing = [h for h in REQUIRED if h not in lowered]
    if missing:
        print(
            f"release_body: {version} is missing required heading(s): "
            + ", ".join(missing)
            + " — the body must state what was added and what was fixed",
            file=sys.stderr,
        )
        return 1

    if check:
        print(f"release_body: {version} OK ({len(body)} chars)")
        return 0

    title_line = body.splitlines()[0] if body else version
    print(f"# Tallow {version}")
    print()
    if "—" in title_line:
        print(f"*{title_line.split('—', 1)[1].strip()}*")
        print()
    print(body)
    if verified is not None:
        print()
        print("---")
        print()
        print(verified.read_text().strip())
    print(VERIFY_BLOCK)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
