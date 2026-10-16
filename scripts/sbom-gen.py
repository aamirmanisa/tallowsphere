#!/usr/bin/env python3
"""sbom-gen.py — minimal SBOM inventory generator + drift gate (T-114, Nixe/Tallow).

Scoping refs: research/tallow-security-2026-09-12/final/final-question.md item 5
("SBOM drift gate"), 18-attack-surface.md §18.6 (CHAIN-5-2; R-P9-1/R-P9-15).

Produces a deterministic, canonical JSON inventory of every package in the
workspace dependency graph from `cargo metadata --locked` (offline-first, no
build, no absolute paths). CI regenerates the artifact and fails if it differs
from the committed snapshot `scripts/sbom.snapshot.json`, so any
dependency-graph or Cargo.lock change must land together with an explicit
snapshot update in the same change.

Usage (run from the repo root):
  python3 scripts/sbom-gen.py                                      # print SBOM to stdout
  python3 scripts/sbom-gen.py --write scripts/sbom.snapshot.json   # (re)write snapshot
  python3 scripts/sbom-gen.py --check scripts/sbom.snapshot.json   # CI drift gate

Exit codes: 0 = ok / no drift; 1 = drift detected; 2 = generator/metadata error.

Artifact shape ("tallow-sbom-min/1"): one JSON object per line inside
"packages", sorted by (name, version, source, license) so diffs are
line-per-package:

  {
    "format": "tallow-sbom-min/1",
    "generator": "scripts/sbom-gen.py",
    "lockfileSha256": "<sha256 of committed Cargo.lock bytes>",
    "packageCount": N,
    "packages": [
      {"license":"...","name":"...","source":"...","version":"..."},
      ...
    ]
  }
"""

from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def cargo_metadata() -> dict:
    """Resolve the workspace dependency graph, offline first.

    The artifact must not depend on network state, so the primary attempt is
    fully offline (`--offline --locked`). On a cold cargo cache (e.g. a fresh
    CI runner that never ran `cargo fetch`), registry summaries may be missing
    for the offline resolver; in that case retry once *without* `--offline`.
    Both attempts carry `--locked`, so Cargo.lock can never be mutated.
    """
    base = ["cargo", "metadata", "--locked", "--format-version", "1"]
    proc = subprocess.run(
        base + ["--offline"], cwd=REPO_ROOT, capture_output=True, text=True
    )
    if proc.returncode == 0:
        return json.loads(proc.stdout)

    offline_err = proc.stderr
    sys.stderr.write(
        "sbom-gen: note: offline resolution unavailable (cold cache?); "
        "retrying `cargo metadata --locked` with registry access\n"
    )
    proc = subprocess.run(base, cwd=REPO_ROOT, capture_output=True, text=True)
    if proc.returncode != 0:
        sys.stderr.write(
            "sbom-gen: `cargo metadata --locked` failed (offline attempt and "
            "registry attempt both failed).\n-- offline attempt stderr:\n%s\n"
            "-- registry attempt stderr:\n%s\n" % (offline_err, proc.stderr)
        )
        sys.exit(2)
    return json.loads(proc.stdout)


def build_sbom(meta: dict) -> dict:
    lock_path = REPO_ROOT / "Cargo.lock"
    if not lock_path.is_file():
        sys.stderr.write("sbom-gen: Cargo.lock not found at %s\n" % lock_path)
        sys.exit(2)
    packages = []
    for pkg in meta["packages"]:
        packages.append(
            {
                "name": pkg["name"],
                "version": pkg["version"],
                "source": pkg.get("source") or "workspace-path",
                "license": pkg.get("license") or "UNKNOWN",
            }
        )
    packages.sort(key=lambda p: (p["name"], p["version"], p["source"], p["license"]))
    return {
        "format": "tallow-sbom-min/1",
        "generator": "scripts/sbom-gen.py",
        "lockfileSha256": hashlib.sha256(lock_path.read_bytes()).hexdigest(),
        "packageCount": len(packages),
        "packages": packages,
    }


def render(sbom: dict) -> str:
    lines = [
        "{",
        '  "format": %s,' % json.dumps(sbom["format"]),
        '  "generator": %s,' % json.dumps(sbom["generator"]),
        '  "lockfileSha256": %s,' % json.dumps(sbom["lockfileSha256"]),
        '  "packageCount": %d,' % sbom["packageCount"],
        '  "packages": [',
    ]
    pkgs = sbom["packages"]
    for i, pkg in enumerate(pkgs):
        comma = "," if i < len(pkgs) - 1 else ""
        lines.append("    " + json.dumps(pkg, sort_keys=True, separators=(",", ":")) + comma)
    lines += ["  ]", "}", ""]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Generate or check the minimal workspace SBOM inventory (T-114)"
    )
    ap.add_argument("--write", metavar="PATH", help="write the SBOM snapshot to PATH")
    ap.add_argument(
        "--check",
        metavar="PATH",
        help="fail (exit 1) if PATH differs from the regenerated SBOM",
    )
    args = ap.parse_args()

    sbom = build_sbom(cargo_metadata())
    text = render(sbom)

    if args.write:
        out = Path(args.write)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(text, encoding="utf-8")
        print("sbom-gen: wrote %s (%d packages)" % (out, sbom["packageCount"]))
        return 0

    if args.check:
        snapshot = Path(args.check)
        if not snapshot.is_file():
            sys.stderr.write("sbom-gen: snapshot %s not found\n" % snapshot)
            return 2
        expected = snapshot.read_text(encoding="utf-8")
        if expected == text:
            print(
                "sbom-gen: SBOM drift gate OK — regenerated artifact matches %s"
                % snapshot
            )
            return 0
        sys.stderr.writelines(
            difflib.unified_diff(
                expected.splitlines(keepends=True),
                text.splitlines(keepends=True),
                fromfile="%s (committed)" % snapshot,
                tofile="regenerated",
            )
        )
        sys.stderr.write(
            "sbom-gen: SBOM DRIFT — %s does not match the regenerated artifact; "
            "update the snapshot in the same change:\n"
            "  python3 scripts/sbom-gen.py --write %s\n" % (snapshot, snapshot)
        )
        return 1

    sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
