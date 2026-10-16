#!/usr/bin/env python3
"""Independently measure `tallow copy` on a deterministic dataset — target vs shipped.

The repo documented a 2.6 GB/s copy figure and flagged it in the same breath as
"internal" (docs/TALLOW-LANGUAGE-COMPARISON-2026-09-12.md, "Perf caveat"). An internal
number is not a measurement. This measures the SHIPPED binary, on data whose sha256 is
recorded, and anchors it to coreutils `cp` on the same bytes so the number has a scale
rather than a halo.

Two rules it will not bend:
  * a copy is only counted if the destination is BYTE-IDENTICAL to the source. A fast
    copy that corrupts is not a fast copy, and throughput alone cannot tell you which
    one you have.
  * every row carries all six fields (binary sha, dataset sha, kernel, CPU, load
    average, peak RSS). No dataset sha, no row.

Usage:
    run_copy_bench.py --dataset /path/dataset [--binary /usr/local/bin/tallow]
    run_copy_bench.py --dataset /path/dataset --json

Exit: 0 measured, 1 a copy verified INCORRECT, 2 nothing measurable, 3 usage.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent


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
        while True:
            c = fh.read(1 << 20)
            if not c:
                break
            h.update(c)
    return h.hexdigest()


def timed(cmd) -> tuple[float, int]:
    """Return (wall seconds, returncode)."""
    t0 = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True, text=True)
    return time.perf_counter() - t0, r.returncode


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


def spawn_floor_s(cmd, n: int = 15) -> float:
    """Median wall of a no-data invocation of the tool, so per-process startup can be
    subtracted instead of being reported as transfer speed. A 46 MB binary and a 130 KB
    binary do not pay the same price to start, and this harness launches one process per
    file — so the difference would otherwise land in the GB/s column."""
    samples = []
    for _ in range(n):
        t0 = time.perf_counter()
        r = subprocess.run(list(cmd), capture_output=True, text=True)
        samples.append(time.perf_counter() - t0)
        if r.returncode != 0:
            return -1.0
    return statistics.median(samples)


def evict(p: Path) -> bool:
    """Evict THIS file's pages from the page cache, surgically.

    A copy measured with the source in page cache measures memory bandwidth and tells you
    nothing about disk throughput — and it overstates by roughly an order of magnitude.
    POSIX_FADV_DONTNEED drops only this file's clean pages, so it does not disturb the
    companion builds sharing the box the way a global /proc/sys/vm/drop_caches would.
    """
    if not hasattr(os, "posix_fadvise"):
        return False
    try:
        fd = os.open(p, os.O_RDONLY)
    except OSError:
        return False
    try:
        os.posix_fadvise(fd, 0, 0, os.POSIX_FADV_DONTNEED)
    except OSError:
        return False
    finally:
        os.close(fd)
    return True


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dataset", required=True)
    ap.add_argument("--binary", default="")
    ap.add_argument("--iters", type=int, default=3)
    ap.add_argument("--cache", choices=["warm", "cold", "both"], default="both",
                    help="warm = source in page cache; cold = source evicted per run "
                         "(default both, so the overstatement is visible rather than assumed)")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()

    root = Path(args.dataset).resolve()
    man_p = root / "manifest.json"

    if args.json:
        p = HERE / "results.json"
        if not p.exists():
            print("no results.json yet", file=sys.stderr)
            return 3
        print(p.read_text())
        return 0

    if not man_p.exists():
        print(f"no manifest at {man_p} — run make_dataset.py first. Refusing to measure "
              f"a dataset with no recorded sha: the row would not be publishable.",
              file=sys.stderr)
        return 2
    man = json.loads(man_p.read_text())

    # The dataset sha is recomputed from the bytes on disk, never trusted from the manifest.
    entries = sorted((e["name"], e["bytes"], e["sha256"]) for e in man["entries"])
    h = hashlib.sha256()
    for name, size, fsha in entries:
        h.update(f"{name}\x00{size}\x00{fsha}\n".encode())
    dataset_sha = h.hexdigest()
    sha_matches = dataset_sha == man["dataset_sha256"]

    binary = args.binary or shutil.which("tallow") or ""
    if not binary or not Path(binary).exists():
        print("no tallow binary (--binary, or on PATH). Nothing to measure.", file=sys.stderr)
        return 2
    binary_sha = sha256_file(Path(binary))

    total = sum(e[1] for e in entries)
    print(f"binary  {binary}  sha256={binary_sha[:16]}…")
    print(f"dataset {root}  sha256={dataset_sha[:16]}…  ({total/1048576:.1f} MB, "
          f"{len(entries)} files)  matches manifest: {sha_matches}")
    print(f"iters   {args.iters}\n")

    results = {
        "_meta": {
            "harness": "benchmarks/copy-engine/run_copy_bench.py",
            "binary": binary,
            "binary_sha256": binary_sha,
            "dataset": str(root),
            "dataset_sha256": dataset_sha,
            "dataset_matches_manifest": sha_matches,
            "dataset_bytes": total,
            "kernel": platform.release(),
            "cpu": cpu_model(),
            "vcpus": os.cpu_count(),
            "loadavg_1_5_15": Path("/proc/loadavg").read_text().split()[:3],
            "date_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "iters": args.iters,
            "timing": "median wall over N runs, perf_counter around the child; peak RSS from a "
                      "separate /usr/bin/time -f %M run of the largest file",
            "cache_modes": "warm = source already in page cache (this measures MEMORY bandwidth "
                           "and overstates disk throughput by roughly an order of magnitude); "
                           "cold = source pages evicted with POSIX_FADV_DONTNEED before each "
                           "timed run (surgical — not a global drop_caches). Only the cold row "
                           "speaks to disk throughput; compare it to the documented 2.6 GB/s.",
            "correctness": "a run counts only if sha256(dst) == sha256(src)",
        },
        "variants": {},
    }

    ok_any = False
    bad_any = False
    tmp = Path(tempfile.mkdtemp(prefix="copybench-"))
    modes = ["warm", "cold"] if args.cache == "both" else [args.cache]
    try:
        candidates = [("tallow copy (shipped)", [binary, "copy"]),
                      ("coreutils cp", [shutil.which("cp") or "cp"])]
        biggest = max(entries, key=lambda e: e[1])
        acc: dict[str, dict] = {}
        for cache in modes:
            eviction_worked = True
            # ALTERNATE the variant order on every iteration. Fixed order lets the first
            # variant's own dirty-page writeback interfere with the second variant's runs,
            # which showed up here as a ~1.5x gap that was partly an artefact of order.
            for it in range(args.iters):
                order = candidates if it % 2 == 0 else list(reversed(candidates))
                for label, prefix in order:
                    a = acc.setdefault(f"{label} [{cache}]",
                                       {"cache": cache, "walls": [], "wrong": 0, "rss": -1,
                                        "iter_s": [], "spawn_floor_s": -1.0})
                    it_total = 0.0
                    for name, size, fsha in entries:
                        src = root / name
                        dst = tmp / f"{label.split()[0]}-{it}-{name}"
                        if dst.exists():
                            dst.unlink()
                        if cache == "cold":
                            eviction_worked &= evict(src)
                        w, rc = timed(prefix + [str(src), str(dst)])
                        if rc != 0 or not dst.exists():
                            print(f"  {label} [{cache}]: rc={rc} on {name} — run discarded")
                            continue
                        if sha256_file(dst) != fsha:
                            a["wrong"] += 1
                            print(f"  {label} [{cache}]: {name} COPY VERIFIED INCORRECT (sha mismatch)")
                            continue
                        a["walls"].append(w)
                        it_total += w
                        if name == biggest[0]:
                            if cache == "cold":
                                evict(src)
                            a["rss"] = max(a["rss"], peak_rss_kb(prefix + [str(src), str(dst)]))
                        dst.unlink()
                    # One iteration's whole-dataset time. This is the divisor for the rate:
                    # a per-FILE median over whole-dataset bytes overstates by len(entries)
                    # and is exactly the bug this comment exists to prevent recurring.
                    a["iter_s"].append(it_total)
                    subprocess.run(["sync"], check=False)
            if cache == "cold" and not eviction_worked:
                print("  WARNING: POSIX_FADV_DONTNEED did not take — the 'cold' row is NOT cold "
                      "and must not be read as disk throughput")
                results["_meta"]["cold_eviction_failed"] = True

        floors = {}
        for label, prefix in candidates:
            fl = spawn_floor_s([prefix[0], "--version"])
            floors[label] = fl
            print(f"  spawn floor  {label:22s} "
                  + (f"{fl*1000:7.2f} ms" if fl >= 0 else "n/a"))
        print()

        for key, a in acc.items():
            if a["iter_s"]:
                ok_any = True
                med = statistics.median(a["iter_s"])
                rate = total / med / 1e9
                floor = floors.get(key.rsplit(" [", 1)[0], -1.0)
                nproc = len(entries)  # one process per file
                corr_s = med - nproc * floor if floor >= 0 else -1.0
                rec = {
                    "runs": len(a["iter_s"]), "median_s": round(med, 4),
                    "min_s": round(min(a["iter_s"]), 4), "gbps": round(rate, 3),
                    "peak_rss_kb": a["rss"], "incorrect_copies": a["wrong"],
                    "bytes_per_run": total, "cache": a["cache"],
                    "spawn_floor_ms_per_process": round(floor * 1000, 3) if floor >= 0 else None,
                    "processes_per_iteration": nproc,
                }
                if corr_s > 0:
                    rec["gbps_excluding_spawn"] = round(total / corr_s / 1e9, 3)
                results["variants"][key] = rec
                tail = (f"  excl.spawn={rec['gbps_excluding_spawn']:6.3f} GB/s"
                        if "gbps_excluding_spawn" in rec else "")
                print(f"  {key:32s} {med:7.4f} s  {rate:7.3f} GB/s{tail}  "
                      f"rss={a['rss'] if a['rss'] >= 0 else 'n/a'} KB  wrong={a['wrong']}")
            else:
                results["variants"][key] = {"skipped": True, "cache": a["cache"],
                                            "reason": "no run produced a correct copy"}
                print(f"  {key:32s} SKIPPED: no correct copy produced")
            bad_any = bad_any or a["wrong"] > 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    if not ok_any:
        print("\nnothing measurable — no copy completed correctly.", file=sys.stderr)
        return 2

    (HERE / "results.json").write_text(json.dumps(results, indent=2) + "\n")
    print(f"\nwrote {HERE / 'results.json'}")
    return 1 if bad_any else 0


if __name__ == "__main__":
    sys.exit(main())
