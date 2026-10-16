#!/usr/bin/env python3
"""Measure `tallow run` on every engine it has, and pin where they DISAGREE.

Native is the default. The interpreter is a fallback you can also ask for explicitly. The
Cranelift JIT tier is a third engine that exists in-tree (`src/codegen_cranelift.rs`,
feature-gated, default OFF) and has **no linker in the loop** — which matters because the
native path's measured cost IS the linker (0.28–32 s per invocation against ~0.1 s of
codegen). This harness measures all three and checks that they compute the same answers.

A program known to diverge can be marked as such. Marked divergences are REPRODUCED and
reported (so the bug cannot quietly vanish); UNMARKED divergences exit non-zero, because a
harness that finds the engines disagreeing on something it thought was fine should not
report success.

Engine availability is **discovered, never assumed**: an engine that cannot run a program
(the JIT rejects strings, arrays, closures and builtin calls such as `print`) is reported as
REJECTED with its reason, not silently omitted.

Usage:
    run_engine_bench.py [--binary target/release/tallow] [--iters 5]
    run_engine_bench.py --engines native,interpret,cranelift [--out results-jit.json]
    run_engine_bench.py --json

Exit: 0 measured (no unexpected divergence), 1 UNMARKED divergence, 2 nothing measurable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
PROGRAMS = HERE / "programs"

# Engine name -> the extra argv that selects it.
ENGINES = {
    "native": [],
    "interpret": ["--interpret"],
    "cranelift": ["--backend", "cranelift"],
}

# (label, path, known_divergence, why, expected_main_return_or_None)
#
# The interpreter was already reachable before an explicit flag existed, but only as a SIDE
# EFFECT: tests/parity/README.md documents the reference leg as `tallow run <fixture>
# --target x86_64-linux`, because a cross target makes `is_cross` skip the native path. That
# accidental mechanism is what --interpret replaces.
#
# The map-mut case is NOT marked known-divergent. Its own header comment still says native
# silently miscompiles .set(); the shipped binary now prints len 10 / k3 3 / MAP_MUT_OK, and
# tests/parity/README.md:152 records that as FIXED. It is a REGRESSION PIN: if the engines
# disagree there again, that is an UNMARKED divergence and this harness exits 1.
CASES = [
    ("hello (trivial)", PROGRAMS / "hello.tl", False, "", None),
    ("loop 200k (compute)", PROGRAMS / "loop.tl", False, "", None),
    ("map .set() regression pin", REPO / "tests/parity/parity_programs/06_map_mut.tl", False,
     "was a silent native miscompile (len=0/nil, rc=0, no signal to fire the fallback); "
     "fixed per tests/parity/README.md:152 — any divergence now is a REGRESSION", None),
    # Cranelift-tier cases. compute.tl is print-free because the JIT rejects builtin calls;
    # its `main` return is reported on stderr and checked against the value computed here.
    ("compute 3M (JIT-capable)", PROGRAMS / "compute.tl", False, "",
     3000000 * 2999999 // 2),
    ("compute 3M + print (JIT must reject)", PROGRAMS / "compute_print.tl", True,
     "the Cranelift tier supports the numeric core only and REJECTS builtin calls; a tier "
     "that refuses loudly is working correctly, so this is a pinned expectation",
     3000000 * 2999999 // 2),
    # What the Cranelift tier can actually do today, pinned so the gap cannot drift silently.
    ("jit arithmetic (JIT works)", PROGRAMS / "jit_arith.tl", False, "", 7),
    ("jit function call (JIT ICEs)", PROGRAMS / "jit_fncall.tl", True,
     "the Cranelift tier does not refuse a top-level call — it ICEs. Pinned as a KNOWN "
     "defect: an ICE is a crash, and it must stay visible rather than be tolerated", 5),
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
    """Median wall seconds over `iters`, plus the distinct stdouts/stderrs and rcs. Outputs
    must be stable across iterations or the median describes a moving target."""
    walls, outs, errs, rcs = [], set(), set(), set()
    for _ in range(iters):
        t0 = time.perf_counter()
        r = subprocess.run(cmd, capture_output=True, text=True)
        walls.append(time.perf_counter() - t0)
        outs.add(r.stdout)
        errs.add(r.stderr)
        rcs.add(r.returncode)
    return statistics.median(walls), min(walls), sorted(outs), sorted(errs), sorted(rcs)


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
    ap.add_argument("--engines", default="native,interpret",
                    help="comma list from: " + ", ".join(ENGINES))
    ap.add_argument("--out", default="results.json")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    if args.json:
        p = HERE / args.out
        if not p.exists():
            print(f"no {p}", file=sys.stderr)
            return 2
        print(p.read_text())
        return 0

    engines = [e.strip() for e in args.engines.split(",") if e.strip()]
    unknown = [e for e in engines if e not in ENGINES]
    if unknown:
        print(f"unknown engine(s): {unknown} (known: {list(ENGINES)})", file=sys.stderr)
        return 2

    binary = args.binary or "/usr/local/bin/tallow"
    if not Path(binary).exists():
        print(f"no binary at {binary}", file=sys.stderr)
        return 2

    results = {
        "_meta": {
            "harness": "benchmarks/run-engines/run_engine_bench.py",
            "binary": binary,
            "binary_sha256": sha256_file(Path(binary)),
            "engines": engines,
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

    floor, _, _, _, _ = run_once([binary, "--version"], max(args.iters, 7))
    print(f"binary  {binary}  sha256={results['_meta']['binary_sha256'][:16]}…")
    print(f"engines {', '.join(engines)}")
    print(f"process floor (`tallow --version`): {floor*1000:.2f} ms")
    print(f"loadavg {results['_meta']['loadavg_1_5_15']}  iters {args.iters}\n")

    measured = 0
    unexpected = []
    for label, path, known, why, expect in CASES:
        if not path.exists():
            print(f"  {label:26s} MISSING {path}")
            continue
        rec = {
            "program": str(path.relative_to(REPO)) if REPO in path.parents else str(path),
            "program_sha256": sha256_file(path),
            "known_divergence": known,
            "expected_main_return": expect,
            "engines": {},
        }
        for eng in engines:
            cmd = [binary, "run"] + ENGINES[eng] + [str(path)]
            med, mn, outs, errs, rcs = run_once(cmd, args.iters)
            err = "\n".join(errs)
            ice = "internal compiler error" in err
            rejected = ("cannot run this program" in err
                        or "built WITHOUT the `jit` feature" in err
                        or "unknown backend" in err)
            entry = {
                "median_ms": round(med * 1000, 2), "min_ms": round(mn * 1000, 2),
                "median_ms_excl_process_floor": round((med - floor) * 1000, 2),
                "stdout": outs, "rc": rcs, "peak_rss_kb": peak_rss_kb(cmd),
            }
            if ice:
                # A crash is not a refusal. Never let one read as "ran".
                entry["internal_compiler_error"] = True
                entry["reason"] = "ICE — crashed, did not refuse"
            elif rejected:
                entry["rejected"] = True
                entry["reason"] = next(
                    (l.strip() for l in err.splitlines()
                     if "cannot run this program" in l or "WITHOUT" in l),
                    "rejected")
            m = re.search(r"main returned (-?\d+)", err)
            if m:
                entry["reported_main_return"] = int(m.group(1))
                if expect is not None:
                    entry["value_correct"] = (int(m.group(1)) == expect)
            rec["engines"][eng] = entry
        # Correctness gate: stdout must be identical across the engines that actually ran.
        ran = {e: tuple(v["stdout"]) for e, v in rec["engines"].items()
               if not v.get("rejected") and not v.get("internal_compiler_error")}
        rec["engines_agree"] = len(set(ran.values())) <= 1
        iced = [e for e, v in rec["engines"].items() if v.get("internal_compiler_error")]
        if iced and not known:
            rec["divergence_status"] = "UNEXPECTED ICE"
            unexpected.append(f"{label} [{','.join(iced)}]")
        elif not rec["engines_agree"] and known:
            rec["divergence_status"] = "KNOWN divergence reproduced"
        elif not rec["engines_agree"]:
            rec["divergence_status"] = "UNEXPECTED divergence"
            unexpected.append(label)
        else:
            rec["divergence_status"] = "engines agree"
        results["cases"][label] = rec
        measured += 1

        print(f"  {label}")
        for eng, v in rec["engines"].items():
            if v.get("internal_compiler_error"):
                print(f"      {eng:10s} *** ICE ***  crashed instead of refusing")
            elif v.get("rejected"):
                print(f"      {eng:10s} REJECTED  {v['reason'][:84]}")
            else:
                extra = ""
                if "reported_main_return" in v:
                    ok = v.get("value_correct")
                    extra = (f"  main={v['reported_main_return']}"
                             + ("" if ok is None else ("  VALUE OK" if ok else "  VALUE WRONG")))
                print(f"      {eng:10s} {v['median_ms']:9.2f} ms  "
                      f"rss={v['peak_rss_kb']:>8} KB{extra}")
        if rec["engines_agree"]:
            print("      -> stdout identical across the engines that ran")
        else:
            print(f"      -> {rec['divergence_status']}")
            if known:
                print(f"         expected: {why[:96]}")

    if not measured:
        print("\nnothing measurable.", file=sys.stderr)
        return 2

    (HERE / args.out).write_text(json.dumps(results, indent=2) + "\n")
    print(f"\nwrote {HERE / args.out}  ({measured} cases, engines: {', '.join(engines)})")
    if unexpected:
        print(f"UNEXPECTED divergence on: {unexpected} — the engines disagree on programs "
              f"not marked as known-divergent", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
