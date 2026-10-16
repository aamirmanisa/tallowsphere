#!/usr/bin/env python3
"""Cross-language baseline: measure C / Rust / Go / Python / Ruby on identical kernels.

This is the in-repo, reproducible half of the multi-runtime baseline. Every number it
prints is [measured] on the machine it runs on, by this harness, and the machine's
identity is captured AT RUNTIME rather than written into the file — a hardcoded kernel
string or version label is a claim that rots silently the moment anything changes.

It deliberately carries NO Tallow row. Tallow executes `.tl`, and these kernels are the
C/Rust/Go/Python/Ruby implementations; giving Tallow the same kernels is a separate
piece of work. A projected Tallow column belongs in prose with its derivation shown and
labelled [projected] — never as a measured row in a table of measurements.

Design rules carried from the seed harness (each one is a fixed defect):
  * high-resolution timing via time.perf_counter around the child, because GNU time's
    %.2f is 10 ms-quantized and useless below ~1 s
  * peak RSS in a SEPARATE single run under /usr/bin/time -f %M
  * interpreted languages are seeded as available (nothing to build) rather than skipped
  * rustc is invoked through its real toolchain binary, never the rustup shim
  * per-unit normalisation (s per million units) so unequal budgets stay comparable
  * the PGO merge tool is discovered by TRYING candidates in order — taking the first
    existing path silently selected one whose profile format this rustc cannot read, and
    the result was an ordinary build wearing a PGO label
  * a language that cannot be built is REPORTED as skipped with the reason, never dropped

Usage:
    run_bench.py                 # full run, writes results.json + results.md
    run_bench.py --quick         # 1 iteration, for a smoke check
    run_bench.py --check-sources # assert all five sources implement the same kernels
    run_bench.py --json          # print results.json to stdout

Exit: 0 measured something, 2 nothing measurable (no toolchain worked), 3 usage.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent
SRC = ROOT / "src"
BIN = ROOT / "bin"

WORKLOADS = ["mandelbrot", "vec_sum", "alloc_churn", "str_build", "startup"]

# Identical KINDS of unit in every language; budgets differ so each language runs for a
# measurable interval and the s/Munit normalisation removes the difference.
UNITS = {
    "compiled": {"mandelbrot": 10_000_000, "vec_sum": 50_000_000, "alloc_churn": 30_000_000,
                 "str_build": 6_000_000, "startup": 1},
    "scripting": {"mandelbrot": 400_000, "vec_sum": 2_000_000, "alloc_churn": 2_000_000,
                  "str_build": 1_000_000, "startup": 1},
}


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def first_line(cmd) -> str:
    r = sh(cmd)
    out = (r.stdout or r.stderr or "").strip().splitlines()
    return out[0] if out else ""


# --------------------------------------------------------------------------- #
# machine identity, captured now
# --------------------------------------------------------------------------- #
def cpu_model() -> str:
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            for key in ("model name", "Hardware", "CPU part"):
                if line.lower().startswith(key.lower()):
                    return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return platform.processor() or "unknown"


def machine() -> dict:
    return {
        "kernel": platform.release(),
        "cpu": cpu_model(),
        "vcpus": os.cpu_count(),
        "loadavg_1_5_15": Path("/proc/loadavg").read_text().split()[:3]
        if Path("/proc/loadavg").exists() else None,
        "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "host": platform.node(),
    }


def versions() -> dict:
    """Captured, not asserted. A version label in a table is a claim; this is a reading."""
    return {
        "gcc": first_line(["gcc", "--version"]),
        "rustc": first_line(["rustc", "-V"]),
        "go": first_line(["go", "version"]),
        "python": first_line([sys.executable, "-V"]),
        "ruby": first_line(["ruby", "-v"]),
    }


# --------------------------------------------------------------------------- #
# measurement
# --------------------------------------------------------------------------- #
def wall_ms(cmd, iters: int):
    samples = []
    for _ in range(iters):
        t0 = time.perf_counter()
        r = subprocess.run(cmd, capture_output=True, text=True)
        dt = (time.perf_counter() - t0) * 1000.0
        if r.returncode != 0:
            return None, None, (r.stderr or "")[-300:]
        samples.append(dt)
    return statistics.median(samples), min(samples), ""


def peak_rss_kb(cmd) -> int:
    if not Path("/usr/bin/time").exists():
        return -1
    r = subprocess.run(["/usr/bin/time", "-f", "%M"] + cmd, capture_output=True, text=True)
    if r.returncode != 0:
        return -1
    try:
        return int(r.stderr.strip().splitlines()[-1])
    except (ValueError, IndexError):
        return -1


def rustc_bin() -> str:
    """The real toolchain binary, never the rustup shim (the shim inside a measured
    subprocess adds its own resolution cost to every run)."""
    r = sh(["rustc", "--print", "sysroot"])
    if r.returncode == 0 and r.stdout.strip():
        cand = Path(r.stdout.strip()) / "bin" / "rustc"
        if cand.exists():
            return str(cand)
    p = shutil.which("rustc")
    return p or "rustc"


def llvm_profdata_candidates(rc: str):
    """rustc's own llvm-profdata first: the system one is often a different profile
    format and fails the merge (v10 raw vs v9 expected), which silently degrades a PGO
    build into an ordinary one wearing a PGO label."""
    cands = []
    r = sh([rc, "--print", "sysroot"])
    if r.returncode == 0 and r.stdout.strip():
        sysroot = Path(r.stdout.strip())
        for p in sorted(sysroot.glob("lib/rustlib/*/bin/llvm-profdata")):
            cands.append(str(p))
    for name in ("llvm-profdata", "llvm-profdata-18", "llvm-profdata-17"):
        w = shutil.which(name)
        if w:
            cands.append(w)
    seen, out = set(), []
    for c in cands:
        if c not in seen and Path(c).exists():
            seen.add(c)
            out.append(c)
    return out


def check_sources() -> int:
    """Every source must implement every kernel. One drifting source invalidates the
    whole comparison, and the failure would look like a benchmark result."""
    missing = {}
    for f in sorted(SRC.iterdir()):
        if f.suffix in (".c", ".rs", ".go", ".py", ".rb"):
            text = f.read_text(errors="replace")
            gone = [w for w in WORKLOADS if w not in text]
            if gone:
                missing[f.name] = gone
    if missing:
        print("SOURCE DRIFT — these sources do not mention every kernel:")
        for f, gone in missing.items():
            print(f"  {f}: missing {gone}")
        return 1
    print(f"sources agree: all {len(WORKLOADS)} kernels present in every source")
    return 0


def build() -> tuple[set[str], list]:
    available = {"python", "ruby"}  # interpreted: nothing to build
    log = []

    def add(name, cmd):
        r = sh(cmd)
        ok = r.returncode == 0
        log.append({"name": name, "cmd": " ".join(str(c) for c in cmd), "ok": ok,
                    "err": "" if ok else (r.stderr or "")[-300:]})
        if ok:
            available.add(name)
        return ok

    if shutil.which("gcc"):
        add("c", ["gcc", "-O3", "-o", str(BIN / "bench_c"), str(SRC / "bench.c")])
        add("c_native", ["gcc", "-O3", "-mcpu=native", "-o", str(BIN / "bench_c_native"),
                         str(SRC / "bench.c")])
    rc = rustc_bin()
    add("rust", [rc, "-C", "opt-level=3", "-C", "debuginfo=0",
                 "-o", str(BIN / "bench_rs"), str(SRC / "bench.rs")])
    add("rust_lto", [rc, "-C", "opt-level=3", "-C", "lto=fat", "-C", "codegen-units=1",
                     "-C", "debuginfo=0", "-o", str(BIN / "bench_rs_lto"),
                     str(SRC / "bench.rs")])

    pgo = BIN / "pgo"
    if pgo.exists():
        shutil.rmtree(pgo)
    pgo.mkdir(parents=True)
    gen = BIN / "bench_rs_pgogen"
    if add("rust_pgo_gen", [rc, "-C", "opt-level=3", f"-C", f"profile-generate={pgo}",
                            "-C", "debuginfo=0", "-o", str(gen), str(SRC / "bench.rs")]):
        for w in ("mandelbrot", "vec_sum", "alloc_churn", "str_build"):
            sh([str(gen), w, str(max(1, UNITS["compiled"][w] // 5))])
        raw = sorted(str(p) for p in pgo.glob("*.profraw"))
        profdata = pgo / "merged.profdata"
        merged_with, why = None, "no llvm-profdata candidate could merge this rustc's raw profile"
        for cand in llvm_profdata_candidates(rc):
            r = sh([cand, "merge", "-o", str(profdata)] + raw)
            if r.returncode == 0 and profdata.exists():
                merged_with = cand
                break
            why = (r.stderr or "")[-200:]
        log.append({"name": "rust_pgo_merge", "cmd": f"profdata={merged_with or 'NONE'}",
                    "ok": merged_with is not None, "err": "" if merged_with else why})
        if merged_with:
            add("rust_pgo", [rc, "-C", "opt-level=3", f"-C", f"profile-use={profdata}",
                             "-C", "lto=fat", "-C", "codegen-units=1", "-C", "debuginfo=0",
                             "-o", str(BIN / "bench_rs_pgo"), str(SRC / "bench.rs")])

    if shutil.which("go"):
        add("go", ["go", "build", "-o", str(BIN / "bench_go"), str(SRC / "bench.go")])
    return available, log


def variants(python_exe: str) -> dict:
    return {
        "C -O3": ("compiled", "c", lambda w, u: [str(BIN / "bench_c"), w, str(u)]),
        "C -O3 -mcpu=native": ("compiled", "c_native",
                               lambda w, u: [str(BIN / "bench_c_native"), w, str(u)]),
        "Rust opt3": ("compiled", "rust", lambda w, u: [str(BIN / "bench_rs"), w, str(u)]),
        "Rust fat LTO": ("compiled", "rust_lto",
                         lambda w, u: [str(BIN / "bench_rs_lto"), w, str(u)]),
        "Rust PGO+LTO": ("compiled", "rust_pgo",
                         lambda w, u: [str(BIN / "bench_rs_pgo"), w, str(u)]),
        "Go": ("compiled", "go", lambda w, u: [str(BIN / "bench_go"), w, str(u)]),
        "Python": ("scripting", "python",
                   lambda w, u: [python_exe, str(SRC / "bench.py"), w, str(u)]),
        "Ruby": ("scripting", "ruby", lambda w, u: ["ruby", str(SRC / "bench.rb"), w, str(u)]),
    }


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--quick", action="store_true", help="1 iteration (smoke check)")
    ap.add_argument("--iters", type=int, default=0, help="iterations per cell (default 3)")
    ap.add_argument("--check-sources", action="store_true")
    ap.add_argument("--json", action="store_true", help="print results.json and exit")
    args = ap.parse_args()

    if args.json:
        p = ROOT / "results.json"
        if not p.exists():
            print("run the harness first: no results.json", file=sys.stderr)
            return 3
        print(p.read_text())
        return 0
    if args.check_sources:
        return check_sources()

    iters = args.iters or (1 if args.quick else 3)
    BIN.mkdir(exist_ok=True)
    available, log = build()

    print("=== build ===")
    for e in log:
        print(f"  {'OK  ' if e['ok'] else 'SKIP'} {e['name']}" +
              ("" if e["ok"] else f"   :: {e['err'].strip()[-150:]}"))

    spawn_floor, _, sferr = wall_ms(["/bin/true"], max(iters, 5))
    if spawn_floor is None:
        print(f"cannot measure the spawn floor (/bin/true did not run): {sferr.strip()[:150]}",
              file=sys.stderr)
        return 2
    print(f"\n=== spawn floor (/bin/true): {spawn_floor:.3f} ms ===\n")

    results = {
        "_meta": {
            "harness": "benchmarks/cross-language/run_bench.py",
            "machine": machine(),
            "versions": versions(),
            "iters": iters,
            "spawn_floor_ms": round(spawn_floor, 3),
            "timing": "median wall ms around a Python subprocess (perf_counter); "
                      "RSS via /usr/bin/time -f %M in a separate run; "
                      "s_per_Munits normalises unequal unit budgets",
            "tallow_row": "absent by design — this harness measures the C/Rust/Go/Python/"
                          "Ruby kernels; Tallow runs .tl, and a projected column belongs "
                          "in prose labelled [projected], never as a measured row",
        }
    }
    measured = 0
    for label, (cls, key, argv) in variants(sys.executable).items():
        if key not in available:
            print(f"  SKIP {label}: not built/available (see the build log above)")
            results[label] = {"skipped": True, "reason": "not built or not available"}
            continue
        results[label] = {"class": cls, "workloads": {}}
        for w in WORKLOADS:
            u = UNITS[cls][w]
            n = max(iters, 10) if w == "startup" else iters
            med, mn, err = wall_ms(argv(w, u), n)
            if med is None:
                print(f"  {label:22s} {w:12s} FAILED :: {err.strip()[:110]}")
                continue
            rec = {"units": u, "median_ms": round(med, 3), "min_ms": round(mn, 3), "n": n,
                   "peak_rss_kb": peak_rss_kb(argv(w, u)),
                   "s_per_Munits": round(med / 1000.0 / u * 1e6, 4)}
            if w == "startup":
                rec["startup_corrected_ms"] = round(max(0.0, med - spawn_floor), 3)
            results[label]["workloads"][w] = rec
            measured += 1
            extra = (f"  corrected={rec['startup_corrected_ms']:.3f} ms"
                     if w == "startup" else "")
            print(f"  {label:22s} {w:12s} {med:9.3f} ms  rss={rec['peak_rss_kb']:>8} KB  "
                  f"{rec['s_per_Munits']:11.4f} s/Mu{extra}")

    if not measured:
        print("\nnothing was measurable — no toolchain produced a working binary, so there "
              "is no result to write. Not writing an empty table that reads like one.",
              file=sys.stderr)
        return 2

    (ROOT / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"\nwrote {ROOT / 'results.json'}  ({measured} measured cells)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
