#!/usr/bin/env python3
"""profile_ab.py — A/B the `release` profile against `max` (TALLOW sheet U-C10).

Builds the `tallow` binary once per profile from the same tree, and records for
each: wall build time, binary size, and a compiler/parser harness run over
examples/*.tl. Writes benchmarks/out/profile-ab.json and prints a table.

Why A/B before flipping: making `[profile.max]` (fat LTO, codegen-units=1) the
release default trades release build time for runtime/size. That trade must be
measured before it is adopted (U-C10's gate is "before/after number recorded").

Run it inside a memory scope (see the launch line in the report):
  systemd-run --scope --collect -q -p MemoryMax=11G -p MemorySwapMax=4G \
    --setenv HOME=/root --setenv CARGO_BUILD_JOBS=2 \
    --working-directory=/home/aamir/tallowsphere -- python3 benchmarks/profile_ab.py
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
OUT = REPO / "benchmarks" / "out" / "profile-ab.json"
CARGO = os.environ.get("CARGO", "/root/.cargo/bin/cargo")
PROFILES = ("release", "max")


def sh(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=REPO, capture_output=True, text=True, **kw)


def main() -> int:
    OUT.parent.mkdir(parents=True, exist_ok=True)
    results = {"schema": "tallow-profile-ab/1",
               "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
               "cargo": sh([CARGO, "--version"]).stdout.strip(), "profiles": {}}

    for prof in PROFILES:
        print(f"[profile_ab] building --profile {prof} ...", flush=True)
        t0 = time.perf_counter()
        # --profile release is equivalent to --release; keep the form uniform.
        r = sh([CARGO, "build", "--locked", "--profile", prof, "--bin", "tallow"])
        wall = round(time.perf_counter() - t0, 1)
        if r.returncode != 0:
            print(f"[profile_ab] build FAILED for {prof} (rc={r.returncode})", file=sys.stderr)
            print((r.stderr or "")[-3000:], file=sys.stderr)
            results["profiles"][prof] = {"build_ok": False, "build_wall_s": wall}
            continue

        tdir = REPO / "target" / ("release" if prof == "release" else prof)
        binp = tdir / "tallow"
        size = binp.stat().st_size if binp.exists() else None
        entry: dict = {"build_ok": True, "build_wall_s": wall,
                       "binary": str(binp.relative_to(REPO)), "binary_bytes": size,
                       "binary_mb": round(size / 1e6, 1) if size else None}

        harness_out = REPO / "benchmarks" / "out" / f"ab-{prof}.json"
        h = sh([sys.executable, "benchmarks/run_compiler_parser.py", "--tallow", str(binp),
                "--corpus-glob", "examples/*.tl", "--iters", "3", "--warmup", "1",
                "--out", str(harness_out)])
        if h.returncode == 0 and harness_out.exists():
            entry["metrics"] = json.loads(harness_out.read_text())["metrics"]
        else:
            entry["metrics"] = None
            entry["harness_error"] = (h.stderr or "")[-500:]
        results["profiles"][prof] = entry
        print(f"[profile_ab] {prof}: build {wall}s · "
              f"{entry['binary_mb']} MB · {entry.get('metrics')}")

    OUT.write_text(json.dumps(results, indent=2) + "\n")
    print(f"[profile_ab] wrote {OUT}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
