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
# box is ~8% on the median (four runs, 2026-10-16); 15-20% leaves ~2x headroom so a
# red gate means a real regression, not scheduler jitter.
# `check_ms_p95` is deliberately NOT gated (see compare()): across those same four
# runs it spans 16.5-24.1 ms (~46%), so any budget tight enough to be useful would
# fire on noise. It stays a reported metric; the median carries the latency signal.
LATENCY_MAX_INCREASE_PCT = 15.0
THROUGHPUT_MAX_DROP_PCT = 15.0
RSS_MAX_INCREASE_PCT = 20.0

METRICS = ("files_total", "files_ok", "success_rate", "unresolved",
           "check_ms_median", "check_ms_p95", "throughput_files_per_s", "peak_rss_mb")

# Metrics whose value depends on the MACHINE rather than the code. Gating these across two
# platforms is not a regression test — it is two unrelated measurements subtracted, and the
# difference is reported as a regression. They are gated only when the environment identity
# matches.
ENV_DEPENDENT = ("check_ms_median", "throughput_files_per_s", "peak_rss_mb")


def env_arch(doc: dict) -> str:
    return str(doc.get("environment", {}).get("arch", "") or "").strip().lower()


def same_platform(baseline: dict, current: dict) -> tuple[bool, str]:
    """Are these two measurements comparable on timing at all?

    An ABSENT arch is not a match. Treating unknown as equal is how a CI runner ends up
    being compared against a laptop and the difference filed as a regression, so unknown
    fails closed here: no arch, no timing comparison.
    """
    a, b = env_arch(baseline), env_arch(current)
    if not a or not b:
        return False, (f"environment arch missing (baseline={a or 'absent'}, "
                       f"current={b or 'absent'})")
    if a != b:
        return False, f"different architectures (baseline={a}, current={b})"
    return True, ""


def load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def _m(doc: dict) -> dict:
    m = doc.get("metrics")
    if not isinstance(m, dict):
        raise ValueError("document has no 'metrics' object")
    return m


def compare(baseline: dict, current: dict, notes: list[str] | None = None) -> list[str]:
    """Return a list of regression findings (empty == pass).

    `notes` (optional) collects what was deliberately NOT compared and why, so a skipped
    check is visible rather than indistinguishable from a passing one.
    """
    b, c = _m(baseline), _m(current)
    fails: list[str] = []
    timed_ok, why_not = same_platform(baseline, current)
    if not timed_ok and notes is not None:
        notes.append(f"environment-dependent metrics NOT compared: {why_not}")

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
                                ("throughput_files_per_s", THROUGHPUT_MAX_DROP_PCT, "down"),
                                ("peak_rss_mb", RSS_MAX_INCREASE_PCT, "up")):
        if key in ENV_DEPENDENT and not timed_ok:
            continue
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


def _doc(metrics: dict, corpus_sha: str = "deadbeef" * 8, arch: str = "aarch64") -> dict:
    env = {"arch": arch} if arch else {}
    return {"schema": "tallow-bench/1", "corpus": {"sha256": corpus_sha},
            "environment": env, "metrics": metrics}


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

    # A wrong corpus must be caught
    if not compare(base, _doc(dict(BASE), corpus_sha="cafebabe" * 8)):
        print("SELF-TEST FAIL: corpus sha mismatch was not detected"); rc = 1
    else:
        print("  detected corpus sha mismatch      -> not the same measurement")

    # Timing must be compared on the same platform, and NOT across platforms. Both
    # directions are asserted: skipping too much is as wrong as comparing too much.
    slow = dict(BASE); slow["check_ms_median"] = BASE["check_ms_median"] * 1.30
    if not compare(base, _doc(slow, arch="aarch64")):
        print("SELF-TEST FAIL: same-platform timing regression was NOT detected"); rc = 1
    else:
        print("  same-platform timing regression (aarch64): detected (expected)")
    if compare(base, _doc(slow, arch="x86_64")):
        print("SELF-TEST FAIL: a cross-platform timing difference was filed as a regression")
        rc = 1
    else:
        print("  cross-platform timing (x86_64 vs aarch64): NOT compared (expected)")
    if compare(base, _doc(slow, arch="")):
        print("SELF-TEST FAIL: an absent arch was treated as a comparable platform"); rc = 1
    else:
        print("  absent arch: timing NOT compared (expected)")
    # ...and the skip must be REPORTED, not silent
    notes: list[str] = []
    compare(base, _doc(dict(BASE), arch="x86_64"), notes)
    if not notes:
        print("SELF-TEST FAIL: the skipped timing comparison was not reported"); rc = 1
    else:
        print(f"  skip is reported: {notes[0][:70]}")

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
    notes: list[str] = []
    if args.baseline:
        fails += compare(load(args.baseline), current, notes)
    if args.targets:
        fails += check_targets(load(args.targets), current)
    if not (args.baseline or args.targets):
        print("no_regression_gate: give --baseline and/or --targets", file=sys.stderr); return 2

    verdict = {"pass": not fails, "findings": fails,
               "not_compared": notes,
               "current_metrics": current.get("metrics", {})}
    if args.report:
        Path(args.report).parent.mkdir(parents=True, exist_ok=True)
        Path(args.report).write_text(json.dumps(verdict, indent=2) + "\n")

    for n in notes:
        print(f"  note: {n}")
    if fails:
        print("PERF GATE: FAIL")
        for f in fails:
            print("  -", f)
        return 1
    print("PERF GATE: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
