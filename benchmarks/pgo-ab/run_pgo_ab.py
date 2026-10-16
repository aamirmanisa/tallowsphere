#!/usr/bin/env python3
"""base vs PGO: measure the two binaries, and prove they behave identically first.

Sheet item U-C11. "Pipeline emits it; measured on the real binary" — so this measures the two
binaries that pipeline produced, on work tallow's own code actually does.

Two rules, and the first one runs before any timing:

  1. A PGO build that changed behaviour is not an optimization. Byte-identical `copy` output and
     identical `check` output are required BEFORE any number is reported; a mismatch exits 2 and
     prints no timings at all, so a corrupted profile can never be laundered into a speed-up.
  2. Iterations are INTERLEAVED (base, pgo, base, pgo, …), not run in two blocks. Running one arm
     to completion and then the other measures whatever else the box was doing between them —
     this box is shared, and that failure mode has already produced a wrong number once here.

The measured work is `copy` and `check`: tallow's own code. The native `run` path is clang+ld
dominated (docs/RUN-ENGINES.md) and PGO cannot move it, so timing it would produce a ratio diluted
into meaninglessness rather than a decision.

Usage:
    run_pgo_ab.py --base /tmp/pgo-base/release/tallow --pgo /tmp/pgo-use/release/tallow
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        while chunk := fh.read(1 << 20):
            h.update(chunk)
    return h.hexdigest()


def run(cmd, timeout=600):
    t0 = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    return time.perf_counter() - t0, r


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--pgo", required=True)
    ap.add_argument("--iters", type=int, default=5)
    ap.add_argument("--mb", type=int, default=1024, help="size of the copy corpus file")
    ap.add_argument("--fe-fns", type=int, default=20000,
                    help="functions in the generated front-end corpus")
    ap.add_argument("--out", default=str(HERE / "results.json"))
    args = ap.parse_args()

    base, pgo = Path(args.base).resolve(), Path(args.pgo).resolve()
    for b in (base, pgo):
        if not os.access(b, os.X_OK):
            print(f"not executable: {b}", file=sys.stderr)
            return 2

    # The `check` corpus is GENERATED, and that is a correction: `stdlib/*.tl` does not typecheck
    # standalone (browser.tl alone reports 50 errors and `check` exits in 0.01 s), so using it as
    # the workload measured a fast FAILURE — 11 ms against a 9 ms process-start floor, i.e. no
    # signal at all. The floor is what exposed it. A synthetic file of simple functions passes
    # check and takes ~25 s at 20k functions, which is ~2000x the floor.
    work = Path(os.environ.get("TMPDIR", "/tmp")) / "pgo-ab"
    work.mkdir(parents=True, exist_ok=True)
    fe = work / f"fe-{args.fe_fns}.tl"
    if not fe.exists():
        lines = ["// front-end corpus (generated)", ""]
        for i in range(args.fe_fns):
            lines += [f"fn f{i}(a: Int) -> Int {{", f"    return a + {i}", "}", ""]
        fe.write_text("\n".join(lines))
    tl = [fe]

    big = work / "big.bin"
    if not big.exists() or big.stat().st_size != args.mb * 1048576:
        with big.open("wb") as fh:
            fh.write(os.urandom(1 << 20))
            for _ in range(args.mb - 1):
                fh.write(os.urandom(1 << 20))
    expect_big = sha256_file(big)

    print(f"base  {base}  {base.stat().st_size} bytes  sha={sha256_file(base)[:16]}…")
    print(f"pgo   {pgo}  {pgo.stat().st_size} bytes  sha={sha256_file(pgo)[:16]}…")
    print(f"copy corpus {big} ({args.mb} MiB), check corpus {len(tl)} file(s)\n")

    # ---- RULE 1: behaviour must be identical, checked before any timing ----------------
    print("correctness gate (required before any timing):")
    for label, b in (("base", base), ("pgo", pgo)):
        dst = work / f"out-{label}.bin"
        if dst.exists():
            dst.unlink()
        _, r = run([str(b), "copy", str(big), str(dst)])
        got = sha256_file(dst) if dst.exists() else "MISSING"
        dst.unlink(missing_ok=True)
        if r.returncode != 0 or got != expect_big:
            print(f"  {label}: copy produced a WRONG result (rc={r.returncode}) — refusing to time")
            return 2
        print(f"  {label}: copy byte-identical to source ✓")
    base_check, pgo_check = {}, {}
    for f in tl:
        _, r = run([str(base), "check", str(f)])
        base_check[f.name] = (r.returncode, r.stdout)
        _, r = run([str(pgo), "check", str(f)])
        pgo_check[f.name] = (r.returncode, r.stdout)
    diff = [n for n in base_check if base_check[n] != pgo_check[n]]
    if diff:
        print(f"  check output DIFFERS on {diff} — refusing to time")
        return 2
    print(f"  check: identical rc+stdout on all {len(tl)} file(s) ✓\n")

    # ---- RULE 2: interleave the arms --------------------------------------------------
    load_before = Path("/proc/loadavg").read_text().split()[:3]
    arms = {"base": base, "pgo": pgo}
    timings = {k: {"copy": [], "check": [], "floor": []} for k in arms}

    for i in range(args.iters):
        for name, b in arms.items():
            dst = work / f"i{i}-{name}.bin"
            if dst.exists():
                dst.unlink()
            w, r = run([str(b), "copy", str(big), str(dst)])
            dst.unlink(missing_ok=True)
            if r.returncode == 0:
                timings[name]["copy"].append(w)
            w, _ = run([str(b), "check", *[str(f) for f in tl]])
            timings[name]["check"].append(w)
            w, _ = run([str(b), "--version"])
            timings[name]["floor"].append(w)
        print(f"  iteration {i+1}/{args.iters} done", flush=True)

    load_after = Path("/proc/loadavg").read_text().split()[:3]
    result = {
        "_meta": {
            "harness": "benchmarks/pgo-ab/run_pgo_ab.py",
            "item": "U-C11 (PGO half; BOLT absent on this box)",
            "base_binary": str(base), "base_sha256": sha256_file(base),
            "pgo_binary": str(pgo), "pgo_sha256": sha256_file(pgo),
            "iters": args.iters, "copy_mib": args.mb,
            "check_corpus": [f.name for f in tl],
            "loadavg_before": load_before, "loadavg_after": load_after,
            "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "correctness": "copy sha verified identical and check stdout verified identical before timing",
        },
        "arms": {},
    }
    print()
    for name in arms:
        t = timings[name]
        med = {k: round(statistics.median(v), 4) for k, v in t.items() if v}
        result["arms"][name] = {"median_s": med, "runs": {k: len(v) for k, v in t.items()}}
        print(f"  {name:5s} copy {med.get('copy'):.4f}s  check {med.get('check'):.4f}s  "
              f"floor {med.get('floor'):.4f}s")
    bc, pc = result["arms"]["base"]["median_s"], result["arms"]["pgo"]["median_s"]
    for w in ("copy", "check"):
        if bc.get(w) and pc.get(w):
            d = (bc[w] - pc[w]) / bc[w] * 100
            result["arms"].setdefault("delta", {})[w] = round(d, 2)
            print(f"  {w}: {bc[w]:.4f}s -> {pc[w]:.4f}s  = {d:+.2f}%  "
                  f"({bc[w]/pc[w]:.3f}x)")
    Path(args.out).write_text(json.dumps(result, indent=2) + "\n")
    print(f"\nwrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
