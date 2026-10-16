#!/usr/bin/env python3
"""Panic-policy drift gate (sheet U-J02).

docs/PANIC-POLICY.md states two facts about the tree: the shipped profiles set
`panic = "abort"`, and there are 7 `catch_unwind` call sites that are therefore
inert in release (src/main.rs:2, src/interp.rs:5). This recomputes both. If a
new catch_unwind appears or a profile changes, the policy document is stale and
this fails -- update the document, do not silently invalidate it.

Exit: 0 policy matches the tree; 1 drift; 2 could not evaluate.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Declared by docs/PANIC-POLICY.md.
EXPECT_PROFILE_PANIC = {"release": "abort"}   # [profile.max] must inherit release, not restate
DECLARED_SITES = {"src/main.rs": 2, "src/interp.rs": 5}
# Files that mention catch_unwind but are not shipped code.
EXCLUDED = {"tests/fuzz_safety.rs"}


def load_profiles(path: Path):
    try:
        import tomllib

        with open(path, "rb") as fh:
            return tomllib.load(fh).get("profile", {})
    except Exception as e:  # pragma: no cover
        print(f"  could not parse {path}: {e}")
        return None


def count_calls(path: Path) -> int:
    """Call sites only: a line with `catch_unwind(` that is not a comment.

    Matches calls, not prose. `src/interp.rs` also has a *test function named*
    ...catch_unwind..., which is a definition, not a call.
    """
    n = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        s = line.strip()
        if s.startswith("//") or s.startswith("*"):
            continue
        # `\b` before catch_unwind so the test *function name*
        # (`spawn_agent_crash_isolation_via_catch_unwind(`) does not count: the
        # preceding `_` is a word character, so there is no boundary there.
        if re.search(r"\bcatch_unwind\s*\(", s):
            n += 1
    return n


def main() -> int:
    rows = []
    rc = 0

    profiles = load_profiles(REPO / "Cargo.toml")
    if profiles is None:
        return 2

    for name, want in EXPECT_PROFILE_PANIC.items():
        got = profiles.get(name, {}).get("panic", "<unset>")
        if got == want:
            rows.append(("profile", "pass", f"[profile.{name}] panic = {got}"))
        else:
            rows.append(("profile", "DRIFT", f"[profile.{name}] panic = {got}, policy says {want}"))
            rc = 1

    mx = profiles.get("max", {})
    if mx.get("panic") is None and mx.get("inherits") == "release":
        rows.append(("profile", "pass", "[profile.max] inherits release -> abort"))
    else:
        rows.append(
            (
                "profile",
                "DRIFT",
                f"[profile.max] panic={mx.get('panic', '<unset>')} inherits={mx.get('inherits', '<none>')}"
                " -- policy assumes it inherits release",
            )
        )
        rc = 1

    # Any file in shipped code that mentions catch_unwind and is not declared.
    found = {}
    for base in ("src", "crates", "tests"):
        d = REPO / base
        if not d.is_dir():
            continue
        for f in d.rglob("*.rs"):
            rel = str(f.relative_to(REPO))
            if rel in EXCLUDED:
                continue
            n = count_calls(f)
            if n:
                found[rel] = n

    for rel, want in sorted(DECLARED_SITES.items()):
        got = found.get(rel, 0)
        if got == want:
            rows.append(("call-sites", "pass", f"{rel}: {got}"))
        else:
            rows.append(("call-sites", "DRIFT", f"{rel}: {got} call site(s), policy says {want}"))
            rc = 1

    for rel, got in sorted(found.items()):
        if rel not in DECLARED_SITES:
            rows.append(("call-sites", "DRIFT", f"{rel}: {got} undocumented call site(s)"))
            rc = 1

    width = max(len(r[0]) for r in rows)
    for check, status, msg in rows:
        print(f"  {check.ljust(width)}  {status:5}  {msg}")
    print(f"\nPANIC-POLICY GATE: {'FAIL' if rc else 'PASS'}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
