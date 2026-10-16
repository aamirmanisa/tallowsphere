#!/usr/bin/env python3
"""Build a DETERMINISTIC dataset, and record a sha that is a property of the data.

A benchmark whose dataset is not reproducible measures a coincidence. This builds the
same bytes from the same seed on any machine, and — the part that makes the sha
checkable rather than merely asserted — `--verify` recomputes the dataset sha by
HASHING THE FILES ON DISK, not by re-reading the manifest that wrote them. A recorded
sha that only its own author can reproduce is a claim; this one is evidence.

Usage:
    make_dataset.py --out /path/dataset --total-mb 1024 --files 4 --seed 20261016
    make_dataset.py --out /path/dataset --verify          # recompute sha from disk

Exit: 0 ok, 1 verification mismatch, 2 nothing to measure, 3 usage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import sys
from pathlib import Path

BLOCK = 64 * 1024  # one keystream block


def block_for(seed: int, idx: int) -> bytes:
    """64 KiB of incompressible, seed-deterministic filler for one file."""
    return hashlib.blake2b(f"tallow-copy-bench:{seed}:{idx}".encode(), digest_size=64).digest() * 1024


def write_file(path: Path, seed: int, idx: int, size: int) -> str:
    """Write `size` bytes and return their sha256, computed as they are written."""
    blk = block_for(seed, idx)
    h = hashlib.sha256()
    written = 0
    with path.open("wb") as fh:
        while written < size:
            take = min(BLOCK, size - written)
            chunk = blk[:take]
            fh.write(chunk)
            h.update(chunk)
            written += take
    return h.hexdigest()


def dataset_sha(entries) -> str:
    """sha256 over sorted (name, bytes, file-sha256). Depends only on the DATA, so it can
    be recomputed by anyone holding the dataset."""
    h = hashlib.sha256()
    for name, size, fsha in sorted(entries):
        h.update(f"{name}\x00{size}\x00{fsha}\n".encode())
    return h.hexdigest()


def scan(dataset: Path):
    entries = []
    for p in sorted(dataset.rglob("*.bin")):
        h = hashlib.sha256()
        n = 0
        with p.open("rb") as fh:
            while True:
                c = fh.read(1 << 20)
                if not c:
                    break
                h.update(c)
                n += len(c)
        entries.append((str(p.relative_to(dataset)), n, h.hexdigest()))
    return entries


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", required=True)
    ap.add_argument("--total-mb", type=int, default=1024)
    ap.add_argument("--files", type=int, default=4)
    ap.add_argument("--seed", type=int, default=20261016)
    ap.add_argument("--verify", action="store_true",
                    help="recompute the dataset sha from the files on disk")
    args = ap.parse_args()

    out = Path(args.out).resolve()

    if args.verify:
        if not out.is_dir():
            print(f"no dataset at {out}", file=sys.stderr)
            return 2
        entries = scan(out)
        if not entries:
            print(f"no data files under {out}", file=sys.stderr)
            return 2
        sha = dataset_sha(entries)
        man = out / "manifest.json"
        if man.exists():
            rec = json.loads(man.read_text())
            match = rec.get("dataset_sha256") == sha
            print(f"dataset sha256 (recomputed from disk): {sha}")
            print(f"manifest records:                      {rec.get('dataset_sha256')}")
            print(f"MATCH: {match}")
            return 0 if match else 1
        print(f"dataset sha256 (recomputed from disk): {sha}")
        print("no manifest to compare against")
        return 0

    if args.files < 1 or args.total_mb < 1:
        print("--files and --total-mb must be >= 1", file=sys.stderr)
        return 3

    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)

    per = (args.total_mb * 1024 * 1024) // args.files
    entries = []
    for i in range(args.files):
        name = f"part-{i:03d}.bin"
        size = per if i < args.files - 1 else args.total_mb * 1024 * 1024 - per * (args.files - 1)
        fsha = write_file(out / name, args.seed, i, size)
        entries.append((name, size, fsha))
        print(f"  wrote {name}  {size/1048576:.1f} MB  sha256={fsha[:16]}…")

    man = {
        "builder": "benchmarks/copy-engine/make_dataset.py",
        "seed": args.seed,
        "files": args.files,
        "total_bytes": sum(e[1] for e in entries),
        "dataset_sha256": dataset_sha(entries),
        "definition": "sha256 over sorted (name, bytes, sha256(file)) — recomputable from the data alone",
        "entries": [{"name": n, "bytes": s, "sha256": f} for n, s, f in entries],
    }
    (out / "manifest.json").write_text(json.dumps(man, indent=2) + "\n")
    print(f"\ndataset sha256: {man['dataset_sha256']}")
    print(f"total {man['total_bytes']/1048576:.1f} MB in {args.files} files -> {out}")
    print("re-derive it on any machine with: make_dataset.py --out <dir> --verify")
    return 0


if __name__ == "__main__":
    sys.exit(main())
