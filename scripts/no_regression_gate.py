#!/usr/bin/env python3
"""no_regression_gate.py — compiler/parser performance regression gate (TALLOW sheet U-C01).

Two comparison modes plus a self-test:

  --baseline B --current C   compare a fresh measurement against the committed baseline.
                             FAILS on a regression past the budget below.
  --targets  T --current C   check the measurement is inside the committed target ranges.
  --self-test                prove the gate FAILS on a seeded regression (of every class)
                             and PASSES on a clean copy -- the gate's own gate.

Exit: 0 = pass · 1 = regression / out of range · 2 = usage or IO error.

House conventions: stdlib only; repo root self-detected; no absolute paths; the
only file written is the optional --report JSON.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]

# ── Regression budgets ────────────────────────────────────────────────────────
# The first two thresholds are named by the upgrade sheet (U-C01):
SUCCESS_RATE_MAX_DROP_PP = 1.0   # max success-rate drop, in percentage points
UNRESOLVED_MAX_INCREASE = 0      # max unresolved-count increase
# The rest are timing/memory budgets. Run-to-run noise measured on the reference
# box is ~2.4% on the median; 15-20% leaves ~6-8x headroom so a red gate means a
# real regression, not scheduler jitter.
LATENCY_MAX_INCREASE_PCT = 15.0
THROUGHPUT_MAX_DROP_PCT = 15.0
RSS_MAX_INCREASE_PCT = 20.0

METRICS = ("files_total", "files_ok", "success_rate", "unresolved",
           "check_ms_median", "check_ms_p95", "throughput_files_per_s", "peak_rss_mb")


def load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def _m(doc: dict) -> dict:
    m = doc.get("metrics")
    if not isinstance(m, dict):
        raise ValueError("document has no 'metrics' object")
    return m


def compare(baseline: dict, current: dict) -> list[str]:
    """Return a list of regression findings (empty == pass)."""
    b, c = _m(baseline), _m(current)
    fails: list[str] = []

    # Same inputs are a precondition: a corpus change is not a regression, it is
    # a different measurement.
    bsha = baseline.get("corpus", {}).get("sha256")
    csha = current.get("corpus", {}).get("sha256")
    if bsha and csha and bsha != csha:
        fails.append(f"corpus sha mismatch ({bsha[:12]}.. != {csha[:12]}..) — not the same measurement")

    if "success_rate" in b and "success_rate" in c:
        drop_pp = (b["success_rate"] - c["success_rate"]) * 100.0
        if drop_pp > SUCCESS_RATE_MAX_DROP_PP:
            fails.append(f"success_rate dropped {drop_pp:.2f} pp "
                         f"(> {SUCCESS_RATE_MAX_DROP_PP} pp budget)")

    if "unresolved" in b and "unresolved" in c:
        inc = c["unresolved"] - b["unresolved"]
        if inc > UNRESOLVED_MAX_INCREASE:
            fails.append(f"unresolved increased by {inc} (> {UNRESOLVED_MAX_INCREASE} budget)")

    for key, pct, direction in (("check_ms_median", LATENCY_MAX_INCREASE_PCT, "up"),
                                ("check_ms_p95", LATENCY_MAX_INCREASE_PCT, "up"),
                                ("throughput_files_per_s", THROUGHPUT_MAX_DROP_PCT, "down"),
                                ("peak_rss_mb", RSS_MAX_INCREASE_PCT, "up")):
        bv, cv = b.get(key), c.get(key)
        if bv is None or cv is None or bv == 0:
            continue
        if direction == "up":
            delta = (cv - bv) / bv * 100.0
            if delta > pct:
                fails.append(f"{key} regressed {delta:+.1f}% (> {pct}% budget): {bv} -> {cv}")
        else:
            delta = (bv - cv) / bv * 100.0
            if delta > pct:
                fails.append(f"{key} dropped {delta:.1f}% (> {pct}% budget): {bv} -> {cv}")

    return fails


def check_targets(targets: dict, current: dict) -> list[str]:
    """Return range violations (empty == inside every target)."""
    c = _m(current)
    fails: list[str] = []
    for name, spec in targets.get("metrics", {}).items():
        if name not in c:
            continue
        lo, hi = spec["range"]
        v = c[name]
        if not (lo <= v <= hi):
            fails.append(f"{name}={v} outside target range [{lo}, {hi}]")
    return fails


# ── self-test ─────────────────────────────────────────────────────────────────
BASE = {"files_total": 58, "files_ok": 51, "success_rate": 0.8793, "unresolved": 7,
        "check_ms_median": 13.0, "check_ms_p95": 16.6, "throughput_files_per_s": 10.8,
        "peak_rss_mb": 23.3}


def _doc(metrics: dict, corpus_sha: str = "deadbeef" * 8) -> dict:
    return {"schema": "tallow-bench/1", "corpus": {"sha256": corpus_sha}, "metrics": metrics}


def self_test() -> int:
    base = _doc(BASE)
    rc = 0

    clean = _doc(dict(BASE))
    if compare(base, clean):
        print("SELF-TEST FAIL: a clean copy was reported as a regression"); rc = 1
    else:
        print("  clean copy: pass (expected)")

    regressions = {
        "success_rate -2.0 pp":       {"success_rate": BASE["success_rate"] - 0.02},
        "unresolved +1":              {"unresolved": BASE["unresolved"] + 1},
        "check_ms_median +30%":       {"check_ms_median": BASE["check_ms_median"] * 1.30},
        "check_ms_p95 +30%":          {"check_ms_p95": BASE["check_ms_p95"] * 1.30},
        "throughput -30%":            {"throughput_files_per_s": BASE["throughput_files_per_s"] * 0.70},
        "peak_rss_mb +50%":           {"peak_rss_mb": BASE["peak_rss_mb"] * 1.50},
    }
    for name, patch in regressions.items():
        cur = dict(BASE); cur.update(patch)
        fails = compare(base, _doc(cur))
        if fails:
            print(f"  detected {name:22} -> {fails[0]}")
        else:
            print(f"SELF-TEST FAIL: {name} was NOT detected"); rc = 1

    # a wrong corpus must be caught
    if not compare(base, _doc(dict(BASE), corpus_sha="cafebabe" * 8)):
        print("SELF-TEST FAIL: corpus sha mismatch was not detected"); rc = 1
    else:
        print("  detected corpus sha mismatch      -> not the same measurement")

    # a permitted sub-threshold drift must PASS (no false positive)
    sub = dict(BASE); sub["success_rate"] = BASE["success_rate"] - 0.005  # 0.5 pp
    if compare(base, _doc(sub)):
        print("SELF-TEST FAIL: a sub-threshold drift was flagged"); rc = 1
    else:
        print("  sub-threshold drift (0.5 pp): pass (expected)")

    # range check
    tg = {"metrics": {"success_rate": {"range": [0.85, 1.0]}}}
    if check_targets(tg, _doc({"success_rate": 0.90})):
        print("SELF-TEST FAIL: in-range value rejected"); rc = 1
    if not check_targets(tg, _doc({"success_rate": 0.50})):
        print("SELF-TEST FAIL: out-of-range value accepted"); rc = 1

    print("self-test:", "PASS" if rc == 0 else "FAIL")
    return rc


def main() -> int:
    ap = argparse.ArgumentParser(description="Tallow compiler/parser regression gate")
    ap.add_argument("--baseline")
    ap.add_argument("--targets")
    ap.add_argument("--current")
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--report", help="optional path to write a JSON verdict")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    if not args.current:
        print("no_regression_gate: --current is required", file=sys.stderr); return 2
    try:
        current = load(args.current)
    except Exception as e:
        print(f"no_regression_gate: cannot read --current: {e}", file=sys.stderr); return 2

    fails: list[str] = []
    if args.baseline:
        fails += compare(load(args.baseline), current)
    if args.targets:
        fails += check_targets(load(args.targets), current)
    if not (args.baseline or args.targets):
        print("no_regression_gate: give --baseline and/or --targets", file=sys.stderr); return 2

    verdict = {"pass": not fails, "findings": fails,
               "current_metrics": current.get("metrics", {})}
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(verdict, indent=2) + "\n")

    if fails:
        print("PERF GATE: FAIL")
        for f in fails:
            print("  -", f)
        return 1
    print("PERF GATE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
