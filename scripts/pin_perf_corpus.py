#!/usr/bin/env python3
"""pin_perf_corpus.py — freeze the compiler/parser benchmark corpus (TALLOW perf gate).

Why this exists
---------------
The regression gate compares two measurements only when they were taken over the
same inputs. Until now the harness globbed `examples/*.tl`, a directory that moves
for reasons that have nothing to do with performance: example bugs get fixed,
effect annotations get added, examples move out. Every one of those edits changed
the corpus sha256 and the gate — correctly — refused to compare
("corpus sha mismatch — not the same measurement"), which blocks a release.

Pinning moves the corpus out of the moving tree. `benchmarks/corpus/` is a frozen
copy of the measured programs plus a manifest that records each file's sha256 and
the aggregate corpus sha256. The harness measures the pin, so the measurement
identity is stable across unrelated edits to `examples/`. Re-pinning is a
deliberate, reviewable commit — never an accident of editing an example.

Usage:
  python3 scripts/pin_perf_corpus.py                 # re-pin from examples/*.tl
  python3 scripts/pin_perf_corpus.py --check         # verify the pin is intact
  python3 scripts/pin_perf_corpus.py --from-glob 'examples/*.tl' --dest benchmarks/corpus

Exit: 0 = pinned / intact · 1 = drift (with --check) · 2 = usage or IO error.

House conventions: stdlib only; repo root self-detected; no absolute paths. The
corpus hashing is imported from the harness itself so there is exactly one
definition of "the corpus sha256".
"""
from __future__ import annotations

import argparse
import json
import shutil
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "benchmarks"))
import run_compiler_parser as harness  # noqa: E402  (single source of the hash rule)

SCHEMA = "tallow-bench-corpus/1"


def build_manifest(files: list[Path], source_glob: str) -> dict:
    members = {str(p.relative_to(REPO)): harness.sha256_file(p) for p in files}
    return {
        "schema": SCHEMA,
        "pinned_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "source_glob": source_glob,
        "files": len(files),
        "sha256": harness.corpus_sha(files),
        "members": members,
    }


def check(manifest_path: Path) -> int:
    man = json.loads(manifest_path.read_text())
    members = man.get("members") or {}
    if not members:
        print(f"pin_perf_corpus: {manifest_path} has no members", file=sys.stderr)
        return 2
    files = [REPO / rel for rel in sorted(members)]
    missing = [str(f.relative_to(REPO)) for f in files if not f.is_file()]
    if missing:
        print("pin_perf_corpus: pinned corpus files missing:", file=sys.stderr)
        for m in missing:
            print(f"  - {m}", file=sys.stderr)
        return 1
    drift = [str(f.relative_to(REPO)) for f in files
             if harness.sha256_file(f) != members[str(f.relative_to(REPO))]]
    if drift:
        print("pin_perf_corpus: pinned corpus MODIFIED (content no longer matches "
              "the manifest):", file=sys.stderr)
        for d in drift:
            print(f"  - {d}", file=sys.stderr)
        print("  re-pin deliberately: python3 scripts/pin_perf_corpus.py", file=sys.stderr)
        return 1
    agg = harness.corpus_sha(files)
    if agg != man.get("sha256"):
        print(f"pin_perf_corpus: manifest aggregate does not reproduce "
              f"({agg[:12]}.. != {man.get('sha256', '')[:12]}..)", file=sys.stderr)
        return 1
    print(f"pin_perf_corpus: intact — {len(files)} files, corpus sha256 {agg}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Pin the compiler/parser benchmark corpus")
    ap.add_argument("--from-glob", default="examples/*.tl")
    ap.add_argument("--dest", default="benchmarks/corpus")
    ap.add_argument("--check", action="store_true",
                    help="verify the existing pin instead of writing it")
    args = ap.parse_args()

    dest = REPO / args.dest
    manifest_path = dest / "manifest.json"

    if args.check:
        if not manifest_path.is_file():
            print(f"pin_perf_corpus: no manifest at {manifest_path}", file=sys.stderr)
            return 2
        return check(manifest_path)

    src = sorted(REPO.glob(args.from_glob))
    if not src:
        print(f"pin_perf_corpus: no files match {args.from_glob!r}", file=sys.stderr)
        return 2

    dest.mkdir(parents=True, exist_ok=True)

    # Remove stale members so the pin never silently keeps a file that was dropped
    # from the source set; only generated members are touched.
    keep = {p.name for p in src}
    for old in dest.glob("*.tl"):
        if old.name not in keep:
            old.unlink()

    for p in src:
        shutil.copyfile(p, dest / p.name)

    files = sorted(dest.glob("*.tl"))
    manifest = build_manifest(files, args.from_glob)
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")

    print(f"pin_perf_corpus: pinned {len(files)} files -> {dest.relative_to(REPO)}")
    print(f"  corpus sha256 {manifest['sha256']}")
    print(f"  re-measure the baseline on this corpus before committing a new baseline:")
    print(f"    python3 benchmarks/run_compiler_parser.py \\")
    print(f"      --corpus-manifest benchmarks/corpus/manifest.json --out <baseline>.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
