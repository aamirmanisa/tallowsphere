#!/usr/bin/env python3
"""Measure `tallow run` on both engines, and pin where they DISAGREE.

Native is the default. The interpreter is otherwise only a fallback, and the fallback
fires on a build failure or a crash — never on a SILENT miscompile, where the native
binary exits 0 with wrong output and nothing signals that anything happened. That class is
why an explicit `--interpret` exists, and it is why this harness does two jobs: publish the
startup/turnaround numbers the sheet asks for, and check that the two engines produce the
same answer.

A program known to diverge can be marked as such. Marked divergences are REPRODUCED and
reported (so the bug cannot quietly vanish); UNMARKED divergences exit non-zero, because a
harness that finds the engines disagreeing on something it thought was fine should not
report success.

Usage:
    run_engine_bench.py [--binary /usr/local/bin/tallow] [--iters 5] [--json]

Exit: 0 measured (no unexpected divergence), 1 UNMARKED divergence, 2 nothing measurable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PROGRAMS = HERE / "programs"

# (label, path, known_divergence, why)
#
# The interpreter was already reachable before an explicit flag existed, but only as a SIDE
# EFFECT: tests/parity/README.md documents the reference leg as `tallow run <fixture>
# --target x86_64-linux`, because a cross target makes `is_cross` skip the native path. That
# is an accidental mechanism (it also silences the cross-compilation warning path) standing
# in for a choice, which is what --interpret replaces.
#
# The map-mut case is NOT marked known-divergent. Its own header comment still says native
# silently miscompiles .set(); the shipped binary now prints len 10 / k3 3 / MAP_MUT_OK, and
# tests/parity/README.md:152 records that as FIXED. So this entry is a REGRESSION PIN: if the
# engines ever disagree here again, that is an UNMARKED divergence and the harness exits 1.
CASES = [
    ("hello (trivial)", PROGRAMS / "hello.tl", False, ""),
    ("loop 200k (compute)", PROGRAMS / "loop.tl", False, ""),
    ("map .set() regression pin", REPO / "tests/parity/parity_programs/06_map_mut.tl", False,
     "was a silent native miscompile (len=0/nil, rc=0, no signal to fire the fallback); "
     "fixed per tests/parity/README.md:152 — any divergence now is a REGRESSION"),
]


def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            for key in ("model name", "Hardware", "CPU part"):
                if line.lower().startswith(key.lower()):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def run_once(cmd, iters: int):
    """Median wall seconds over `iters`, plus the last run's stdout/rc. Outputs must be
    stable across iterations or the median describes a moving target."""
    walls, outs, rcs = [], set(), set()
    for _ in range(iters):
        t0 = time.perf_counter()
        r = subprocess.run(cmd, capture_output=True, text=True)
        walls.append(time.perf_counter() - t0)
        outs.add(r.stdout)
        rcs.add(r.returncode)
    return statistics.median(walls), min(walls), sorted(outs), sorted(rcs)


def peak_rss_kb(cmd) -> int:
    if not Path("/usr/bin/time").exists():
        return -1
    r = subprocess.run(["/usr/bin/time", "-f", "%M"] + list(cmd), capture_output=True, text=True)
    if r.returncode != 0:
        return -1
    try:
        return int(r.stderr.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return -1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--binary", default="")
    ap.add_argument("--iters", type=int, default=5)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.json:
        p = HERE / "results.json"
        if not p.exists():
            print("no results.json yet", file=sys.stderr)
            return 2
        print(p.read_text())
        return 0

    binary = args.binary or "/usr/local/bin/tallow"
    if not Path(binary).exists():
        print(f"no binary at {binary}", file=sys.stderr)
        return 2

    results = {
        "_meta": {
            "harness": "benchmarks/run-engines/run_engine_bench.py",
            "binary": binary,
            "binary_sha256": sha256_file(Path(binary)),
            "kernel": platform.release(),
            "cpu": cpu_model(),
            "vcpus": os.cpu_count(),
            "loadavg_1_5_15": Path("/proc/loadavg").read_text().split()[:3],
            "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "iters": args.iters,
            "timing": "median wall over N runs of the whole `tallow run` invocation, "
                      "perf_counter around the child; this INCLUDES the native path's "
                      "compile+link, because that is what a user waits for",
            "floor": "`tallow --version` median = the cost of starting the binary and "
                     "nothing else; reported so the engine's work can be separated from "
                     "process startup",
        },
        "cases": {},
    }

    floor, _, _, _ = run_once([binary, "--version"], max(args.iters, 7))
    print(f"binary  {binary}  sha256={results['_meta']['binary_sha256'][:16]}…")
    print(f"process floor (`tallow --version`): {floor*1000:.2f} ms")
    print(f"loadavg {results['_meta']['loadavg_1_5_15']}  iters {args.iters}\n")

    measured = 0
    unexpected = []
    for label, path, known, why in CASES:
        if not path.exists():
            print(f"  {label:24s} MISSING {path}")
            continue
        native_ms, nmin, nout, nrc = run_once([binary, "run", str(path)], args.iters)
        interp_ms, imin, iout, irc = run_once([binary, "run", "--interpret", str(path)], args.iters)
        measured += 1
        agree = (nout == iout and nrc == irc)
        rec = {
            "program": str(path.relative_to(REPO)) if REPO in path.parents else str(path),
            "program_sha256": sha256_file(path),
            "engines_agree": agree,
            "known_divergence": known,
            "native": {
                "median_ms": round(native_ms * 1000, 2), "min_ms": round(nmin * 1000, 2),
                "stdout": nout, "rc": nrc,
                "median_ms_excl_process_floor": round((native_ms - floor) * 1000, 2),
                "peak_rss_kb": peak_rss_kb([binary, "run", str(path)]),
            },
            "interpret": {
                "median_ms": round(interp_ms * 1000, 2), "min_ms": round(imin * 1000, 2),
                "stdout": iout, "rc": irc,
                "median_ms_excl_process_floor": round((interp_ms - floor) * 1000, 2),
                "peak_rss_kb": peak_rss_kb([binary, "run", "--interpret", str(path)]),
            },
        }
        if not agree and known:
            rec["divergence_status"] = "KNOWN divergence reproduced"
        elif not agree:
            rec["divergence_status"] = "UNEXPECTED divergence"
            unexpected.append(label)
        else:
            rec["divergence_status"] = "engines agree"
        results["cases"][label] = rec

        flag = "" if agree else ("  [KNOWN DIVERGENCE reproduced]" if known
                                 else "  [UNEXPECTED DIVERGENCE]")
        print(f"  {label:24s} native {native_ms*1000:8.2f} ms   "
              f"interpret {interp_ms*1000:8.2f} ms   "
              f"ratio {native_ms/interp_ms:5.2f}x{flag}")
        if not agree:
            print(f"      native rc={nrc} out={nout}")
            print(f"      interp rc={irc} out={iout}")
            if known:
                print(f"      known: {why}")

    if not measured:
        print("\nnothing measurable.", file=sys.stderr)
        return 2

    (HERE / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"\nwrote {HERE / 'results.json'}  ({measured} cases)")
    if unexpected:
        print(f"UNEXPECTED divergence on: {unexpected} — the engines disagree on programs "
              f"not marked as known-divergent", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
