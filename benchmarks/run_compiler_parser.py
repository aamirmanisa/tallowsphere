#!/usr/bin/env python3
"""run_compiler_parser.py — compiler/parser benchmark harness (TALLOW sheet U-C02).

Measures `tallow check` wall time over a `.tl` corpus with warm-up and repeated
iterations, and records, for every run, the six fields a publishable row needs
(U-C05): binary sha, corpus sha, kernel, CPU, load average, peak RSS.

Design rules (house conventions):
  * stdlib only; the repo root is self-detected; no absolute paths baked in.
  * never fabricates a number: if no `tallow` binary is found it exits 2 with the
    build command, rather than emitting a placeholder.
  * non-destructive: reads the corpus, writes only the `--out` JSON.

Usage:
  python3 benchmarks/run_compiler_parser.py                 # -> benchmarks/out/current.json
  python3 benchmarks/run_compiler_parser.py --tallow target/release/tallow
  python3 benchmarks/run_compiler_parser.py --iters 7 --warmup 2 --out /tmp/cur.json
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
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DEFAULT_OUT = REPO / "benchmarks" / "out" / "current.json"
TIME_BIN = "/usr/bin/time"


def find_binary(explicit: str | None) -> Path | None:
    cands: list[str] = []
    if explicit:
        cands.append(explicit)
    if os.environ.get("TALLOW_BIN"):
        cands.append(os.environ["TALLOW_BIN"])
    cands += [str(REPO / "target" / "release" / "tallow"),
              str(REPO / "target" / "debug" / "tallow"),
              "/usr/local/bin/tallow"]
    for c in cands:
        p = Path(c)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    return None


def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def corpus_files(glob: str) -> list[Path]:
    return sorted(REPO.glob(glob))


def corpus_sha(files: list[Path]) -> str:
    h = hashlib.sha256()
    for p in files:
        h.update(str(p.relative_to(REPO)).encode())
        h.update(b"\0")
        h.update(sha256_file(p).encode())
        h.update(b"\n")
    return h.hexdigest()


def binary_version(binp: Path) -> dict:
    out = {"path": str(binp), "sha256": sha256_file(binp)}
    try:
        r = subprocess.run([str(binp), "--version"], capture_output=True, text=True, timeout=30)
        out["version_raw"] = (r.stdout or r.stderr).strip().splitlines()[0] if (r.stdout or r.stderr) else ""
    except Exception as e:  # pragma: no cover
        out["version_raw"] = f"<error: {e}>"
    return out


def peak_rss_mb(binp: Path, a_file: Path) -> float | None:
    """Peak RSS (MB) of a single dedicated run, via /usr/bin/time -f %M (KiB)."""
    if not (os.path.exists(TIME_BIN) and os.access(TIME_BIN, os.X_OK)):
        return None
    r = subprocess.run([TIME_BIN, "-f", "%M", str(binp), "check", "-q", str(a_file)],
                       capture_output=True, text=True)
    for line in reversed((r.stderr or "").strip().splitlines()):
        line = line.strip()
        if line.isdigit():
            return round(int(line) / 1024.0, 1)
    return None


def env_info() -> dict:
    cpu = "unknown"
    try:
        for line in Path("/proc/cpuinfo").read_text().splitlines():
            if line.lower().startswith(("model name", "hardware", "model")) and ":" in line:
                cpu = line.split(":", 1)[1].strip()
                break
    except Exception:
        pass
    try:
        load = [round(x, 2) for x in os.getloadavg()]
    except Exception:
        load = []
    return {
        "kernel": platform.release(),
        "cpu": cpu,
        "cpus": os.cpu_count(),
        "loadavg": load,
    }


def run_check(binp: Path, f: Path, parser_mode: str) -> float:
    """Wall ms for one `tallow check --format json` run."""
    t0 = time.perf_counter()
    subprocess.run([str(binp), "check", "--format", "json", "-q", "--parser-mode", parser_mode, str(f)],
                   capture_output=True, text=True)
    return (time.perf_counter() - t0) * 1000.0


def main() -> int:
    ap = argparse.ArgumentParser(description="Tallow compiler/parser benchmark harness")
    ap.add_argument("--tallow", default=None, help="path to the tallow binary")
    ap.add_argument("--corpus-glob", default="examples/*.tl", help="repo-relative glob (default examples/*.tl)")
    ap.add_argument("--iters", type=int, default=5)
    ap.add_argument("--warmup", type=int, default=2)
    ap.add_argument("--parser-mode", default="recover", choices=["recover", "fast"])
    ap.add_argument("--out", default=str(DEFAULT_OUT))
    args = ap.parse_args()

    binp = find_binary(args.tallow)
    if binp is None:
        print("run_compiler_parser: no tallow binary found. Build one first:\n"
              "  cargo build --locked --bin tallow   # -> target/debug/tallow\n"
              "  (or pass --tallow <path>, or set TALLOW_BIN)", file=sys.stderr)
        return 2

    files = corpus_files(args.corpus_glob)
    if not files:
        print(f"run_compiler_parser: no files match {args.corpus_glob!r}", file=sys.stderr)
        return 2

    # warm-up (JIT/fs cache) — not measured
    for f in files:
        for _ in range(args.warmup):
            run_check(binp, f, args.parser_mode)

    per_file: dict[str, dict] = {}
    ok = 0
    all_ms: list[float] = []
    for f in files:
        samples = [run_check(binp, f, args.parser_mode) for _ in range(args.iters)]
        # success = the file type-checks (exit 0). Re-run once to get the code.
        r = subprocess.run([str(binp), "check", "--format", "json", "-q",
                            "--parser-mode", args.parser_mode, str(f)],
                           capture_output=True, text=True)
        good = (r.returncode == 0)
        ok += 1 if good else 0
        rel = str(f.relative_to(REPO))
        per_file[rel] = {"ok": good, "median_ms": round(statistics.median(samples), 3)}
        all_ms.extend(samples)

    all_ms.sort()
    n = len(all_ms)
    metrics = {
        "files_total": len(files),
        "files_ok": ok,
        "success_rate": round(ok / len(files), 4),
        "unresolved": len(files) - ok,
        "check_ms_median": round(statistics.median(all_ms), 3),
        "check_ms_min": round(all_ms[0], 3),
        "check_ms_p95": round(all_ms[min(n - 1, int(round(0.95 * (n - 1))))], 3),
        "check_ms_max": round(all_ms[-1], 3),
        "throughput_files_per_s": round(len(files) / (sum(all_ms) / 1000.0), 3) if all_ms else 0.0,
        "peak_rss_mb": peak_rss_mb(binp, files[0]),
    }

    doc = {
        "schema": "tallow-bench/1",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "binary": binary_version(binp),
        "corpus": {"glob": args.corpus_glob, "files": len(files), "sha256": corpus_sha(files)},
        "environment": env_info(),
        "params": {"iters": args.iters, "warmup": args.warmup, "parser_mode": args.parser_mode},
        "metrics": metrics,
        "per_file": per_file,
    }

    outp = Path(args.out)
    outp.parent.mkdir(parents=True, exist_ok=True)
    outp.write_text(json.dumps(doc, indent=2) + "\n")
    print(f"run_compiler_parser: {outp}")
    print(json.dumps(metrics, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
