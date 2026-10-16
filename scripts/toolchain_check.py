#!/usr/bin/env python3
"""Toolchain gate (sheet U-C15): bare `cargo` must work unattended in this repo.

The README used to say a plain `cargo` call fails here and needs a
`systemd-run --scope` wrapper. Measured 2026-10-16, that is false for this tree:
`rust-toolchain.toml` pins the compiler, so cargo resolves with no wrapper, no
RUSTUP_TOOLCHAIN and no HOME. What actually fails is a cargo call *outside* a tree
that pins one, because rustup on this box has no default toolchain.

This gate keeps the repo half true: the pin must exist, and bare cargo must work
with the environment scrubbed. The box half (no rustup default) is reported as a
note, not a failure -- it is not something a fresh clone can fix.

Exit: 0 pass; 1 gap; 2 could not evaluate.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def main() -> int:
    rows = []
    rc = 0

    pin = REPO / "rust-toolchain.toml"
    if not pin.is_file():
        rows.append(("toolchain-pin", "GAP", "no rust-toolchain.toml -- bare cargo depends on rustup's default"))
        rc = 1
        channel = None
    else:
        text = pin.read_text(encoding="utf-8", errors="replace")
        m = re.search(r'^\s*channel\s*=\s*"([^"]+)"', text, re.M)
        if m:
            channel = m.group(1)
            rows.append(("toolchain-pin", "pass", f"rust-toolchain.toml pins channel = {channel!r}"))
        else:
            channel = None
            rows.append(("toolchain-pin", "GAP", "rust-toolchain.toml has no `channel`"))
            rc = 1

    cargo = shutil.which("cargo")
    if cargo is None:
        rows.append(("bare-cargo", "could-not-evaluate", "cargo not on PATH"))
        rc = rc or 2
    else:
        env = {k: v for k, v in os.environ.items() if k not in ("RUSTUP_TOOLCHAIN", "HOME")}
        try:
            p = subprocess.run(
                [cargo, "metadata", "--no-deps", "--format-version", "1"],
                cwd=str(REPO),
                env=env,
                capture_output=True,
                text=True,
                timeout=180,
            )
        except Exception as e:
            rows.append(("bare-cargo", "could-not-evaluate", f"cargo invocation failed: {e}"))
            rc = rc or 2
            p = None
        if p is not None:
            if p.returncode == 0:
                rows.append(
                    ("bare-cargo", "pass", "resolves with no wrapper, no RUSTUP_TOOLCHAIN and no HOME")
                )
            else:
                first = (p.stderr or "").strip().splitlines()
                rows.append(
                    (
                        "bare-cargo",
                        "GAP",
                        "bare cargo does not resolve in this tree: " + (first[0] if first else "no stderr"),
                    )
                )
                rc = 1

    # Box-level residue: informational. A fresh clone cannot fix it, so it never
    # fails this gate.
    try:
        s = subprocess.run(
            ["rustup", "show"], capture_output=True, text=True, timeout=60
        ).stdout
        act = re.search(r"^(\S+)\s+\(active\)", s, re.M)
        rows.append(
            (
                "rustup-default",
                "note",
                f"active toolchain {act.group(1) if act else '?'} comes from the pin; "
                "no default is configured (out-of-tree cargo calls need `rustup default`)",
            )
        )
    except Exception:
        rows.append(("rustup-default", "note", "rustup not available to query"))

    width = max(len(r[0]) for r in rows)
    for check, status, msg in rows:
        print(f"  {check.ljust(width)}  {status:4}  {msg}")
    print(f"\nTOOLCHAIN GATE: {'FAIL' if rc == 1 else ('INCOMPLETE' if rc == 2 else 'PASS')}")
    return rc


if __name__ == "__main__":
    sys.exit(main())
