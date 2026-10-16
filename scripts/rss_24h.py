#!/usr/bin/env python3
"""Measure RSS over 24 h, not over a run.

Every RSS figure this repo published came from a benchmark run lasting seconds or
minutes. That cannot see the thing that actually matters for a long-lived process:
whether resident memory is stable, or climbing. A run that ends in 12 s cannot
distinguish a settled runtime from one that has not finished leaking.

This samples resident memory of real, long-lived Tallow processes over 24 h and
reports the trajectory per subject.

Subjects are resolved from the process table each tick (--match <regex> against
the full command line), so a restart is observed rather than ending the study,
and a pid change is counted. Sampling is READ-ONLY: it never signals, restarts,
or reconfigures a subject. Production services are safe to watch.

    scripts/rss_24h.py --match 'tallow-admissiond --listen' --out run/daemon.jsonl \
        --duration 24 --interval 60
    scripts/rss_24h.py --report run/daemon.jsonl
    scripts/rss_24h.py --self-test

Refuses to fabricate: if no subject is ever observed, the report says so and the
process exits 2 rather than printing an empty table that reads like a result.

Exit: 0 completed, 2 nothing measurable (no subject observed / unreadable out),
3 usage error.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import statistics
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

STABLE_PCT = 5.0  # growth from first-hour to last-hour median that counts as climbing
MIN_TREND_HOURS = 2.0  # below this the first-hour and last-hour windows overlap


# --------------------------------------------------------------------------- #
# sampling
# --------------------------------------------------------------------------- #
def _read(path: str) -> str | None:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _status_fields(pid: int) -> dict:
    txt = _read(f"/proc/{pid}/status")
    if not txt:
        return {}
    out = {}
    for line in txt.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            out[k.strip()] = v.strip()
    return out


def _smaps_rollup(pid: int) -> dict:
    """Pss/Anonymous/Swap — what a status read cannot give, and what fragmentation
    actually shows up in. Root-only for other users' processes; absent is fine."""
    txt = _read(f"/proc/{pid}/smaps_rollup")
    if not txt:
        return {}
    vals = {}
    for line in txt.splitlines():
        parts = line.split()
        # the unit is the LAST token ("Rss:  1316 kB"); testing parts[1] matched
        # nothing, so this returned {} for every process with NO error -- a silent
        # zero that made the caller report a readable file as unreadable
        if len(parts) >= 2 and parts[-1] == "kB":
            try:
                vals[parts[0].rstrip(":")] = int(parts[-2])
            except ValueError:
                pass
    return vals


def _cpu_seconds(pid: int) -> float | None:
    txt = _read(f"/proc/{pid}/stat")
    if not txt:
        return None
    try:
        rest = txt[txt.rindex(")") + 2:].split()
        return (int(rest[11]) + int(rest[12])) / os.sysconf("SC_CLK_TCK")
    except (ValueError, IndexError):
        return None


def sample_pid(pid: int) -> dict:
    st = _status_fields(pid)
    if not st:
        return {"alive": False}
    row = {
        "alive": True,
        "vm_rss_kb": int(st.get("VmRSS", "0 kB").split()[0]) if "VmRSS" in st else None,
        "vm_size_kb": int(st.get("VmSize", "0 kB").split()[0]) if "VmSize" in st else None,
        "threads": int(st["Threads"]) if "Threads" in st else None,
        "cpu_s": _cpu_seconds(pid),
    }
    try:
        row["fds"] = len(os.listdir(f"/proc/{pid}/fd"))
    except OSError:
        row["fds"] = None
    sm = _smaps_rollup(pid)
    for k in ("Rss", "Pss", "Anonymous", "Private_Dirty", "Swap"):
        if k in sm:
            row[f"{k.lower()}_kb"] = sm[k]
    return row


def system_row() -> dict:
    out = {}
    la = _read("/proc/loadavg")
    if la:
        try:
            out["load1"] = float(la.split()[0])
        except (ValueError, IndexError):
            pass
    mem = _read("/proc/meminfo")
    if mem:
        for line in mem.splitlines():
            if line.startswith("MemAvailable:"):
                try:
                    out["mem_available_mb"] = round(int(line.split()[1]) / 1024)
                except (ValueError, IndexError):
                    pass
                break
    return out


_SELF_MARKER = "rss_24h.py"
_skip_cache: set[int] | None = None


def _skip_pids() -> set[int]:
    """This process and its ancestors, plus anything running the harness.

    A --match regex is tested against every command line on the box, and the
    harness's OWN command line contains that regex -- so without this the study
    samples itself, its supervisor shell and its `timeout` wrapper, and those junk
    subjects land in the dataset as if they were Tallow processes. Measured on the
    first smoke run: 3 of its 10 "subjects" were the measurement, not a subject.
    Same self-match hazard as `pkill -f <pattern>`.
    """
    global _skip_cache
    if _skip_cache is not None:
        return _skip_cache
    chain, cur = set(), os.getpid()
    for _ in range(25):
        if cur <= 1:
            break
        chain.add(cur)
        txt = _read(f"/proc/{cur}/stat")
        if not txt:
            break
        try:
            cur = int(txt[txt.rindex(")") + 2:].split()[1])
        except (ValueError, IndexError):
            break
    _skip_cache = chain
    return chain


def resolve(match: re.Pattern) -> list[tuple[int, str]]:
    """Read-only discovery from /proc. Returns [(pid, cmdline)]."""
    skip = _skip_pids()
    found = []
    for entry in os.listdir("/proc"):
        if not entry.isdigit():
            continue
        pid = int(entry)
        if pid in skip:
            continue
        cmd = _read(f"/proc/{pid}/cmdline")
        if not cmd:
            continue
        line = cmd.replace("\0", " ").strip()
        if _SELF_MARKER in line:
            continue
        if line and match.search(line):
            found.append((pid, line))
    return sorted(found)


# --------------------------------------------------------------------------- #
# report
# --------------------------------------------------------------------------- #
def summarise(rows: list[dict]) -> dict:
    by_subject: dict[str, list[dict]] = {}
    for r in rows:
        by_subject.setdefault(r.get("subject", "?"), []).append(r)

    report = {"subjects": {}, "samples": len(rows)}
    for subj, rs in sorted(by_subject.items()):
        live = [r for r in rs if r.get("alive") and r.get("vm_rss_kb")]
        pids = {r.get("pid") for r in rs if r.get("pid")}
        entry: dict = {
            "ticks": len(rs),
            "observed": len(live),
            "distinct_pids": len(pids),
            "restarts_or_replacements": max(0, len(pids) - 1),
        }
        if not live:
            entry["verdict"] = "NEVER-OBSERVED"
            report["subjects"][subj] = entry
            continue
        rss = [r["vm_rss_kb"] for r in live]
        entry["peak_rss_kb"] = max(rss)
        entry["min_rss_kb"] = min(rss)
        entry["last_rss_kb"] = rss[-1]
        # first-hour vs last-hour medians: a single endpoint pair is noise
        t0 = live[0]["epoch"]
        span_h = (live[-1]["epoch"] - t0) / 3600
        entry["span_hours"] = round(span_h, 3)
        first = [r["vm_rss_kb"] for r in live if r["epoch"] - t0 <= 3600]
        last = [r["vm_rss_kb"] for r in live if live[-1]["epoch"] - r["epoch"] <= 3600]
        entry["first_hour_median_kb"] = int(statistics.median(first)) if first else None
        entry["last_hour_median_kb"] = int(statistics.median(last)) if last else None
        if span_h < MIN_TREND_HOURS:
            # On a short run the first-hour and last-hour windows are the SAME
            # window, so the delta is identically zero. Reporting that as STABLE is
            # a false green: it reads as "measured, no growth" when nothing
            # measurable about growth happened. Measured: a 72 s smoke run came back
            # "+0.00% STABLE" for every subject, including ones that will move.
            entry["verdict"] = "TOO-SHORT-TO-TREND"
        elif entry["first_hour_median_kb"] and entry["last_hour_median_kb"]:
            a, b = entry["first_hour_median_kb"], entry["last_hour_median_kb"]
            pct = (b - a) / a * 100
            entry["growth_pct"] = round(pct, 2)
            entry["growth_mb_per_h"] = round((b - a) / 1024 / span_h, 3)
            entry["verdict"] = "GROWING" if abs(pct) >= STABLE_PCT else "STABLE"
        else:
            entry["verdict"] = "TOO-SHORT-TO-TREND"
        if "anonymous_kb" in live[-1]:
            entry["anonymous_kb_last"] = live[-1]["anonymous_kb"]
        if "pss_kb" in live[-1]:
            entry["pss_kb_last"] = live[-1]["pss_kb"]
        report["subjects"][subj] = entry
    return report


def load_rows(path: Path) -> list[dict]:
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return rows


def print_report(path: Path) -> int:
    if not path.is_file():
        print(f"rss-24h: no such file: {path}", file=sys.stderr)
        return 3
    rows = load_rows(path)
    rep = summarise(rows)
    if not rep["samples"]:
        print("rss-24h: the file has no samples -- nothing measured, nothing claimed")
        return 2
    print(f"samples: {rep['samples']}")

    def kb(v):
        return f"{v/1024:.1f} MB" if isinstance(v, int) else "n/a"

    for subj, e in rep["subjects"].items():
        print(f"\n{subj}")
        print(f"  ticks {e['ticks']}, observed {e['observed']}, distinct pids {e['distinct_pids']}"
              f" (replacements {e['restarts_or_replacements']})")
        if e["verdict"] == "NEVER-OBSERVED":
            print("  verdict: NEVER-OBSERVED -- the subject was never seen alive")
            continue
        print(f"  peak RSS {kb(e['peak_rss_kb'])}   min {kb(e['min_rss_kb'])}   last {kb(e['last_rss_kb'])}")
        print(f"  first-hour median {kb(e.get('first_hour_median_kb'))}"
              f"  ->  last-hour median {kb(e.get('last_hour_median_kb'))}")
        if "growth_pct" in e:
            print(f"  growth {e['growth_pct']:+.2f}%  ({e['growth_mb_per_h']:+.3f} MB/h)")
        print(f"  verdict: {e['verdict']}")
    if all(v["verdict"] == "NEVER-OBSERVED" for v in rep["subjects"].values()):
        return 2
    return 0


# --------------------------------------------------------------------------- #
# self-test: prove the sampler and the report math against real processes, now
# --------------------------------------------------------------------------- #
def self_test() -> int:
    import tempfile

    ok = True
    with tempfile.TemporaryDirectory() as td:
        out = Path(td) / "probe.jsonl"
        child = subprocess.Popen(["sleep", "20"])
        quiet = subprocess.Popen(["sleep", "21"])  # deliberately outside the pattern below
        try:
            study(out_path=out, match=re.compile(r"sleep 20"), duration_s=6, interval=2,
                  label_all="self-test")
            rows = load_rows(out)
            got = {r.get("subject") for r in rows}
            pids = {r.get("pid") for r in rows if r.get("pid")}
            sorted_pids = sorted(p for p in pids if p is not None)
            live = [r for r in rows if r.get("alive")]
            print(f"sampler: {len(rows)} tick(s), {len(live)} live row(s), pids={sorted_pids}")
            if not rows or not live:
                print("  BAD no live samples against a real process")
                ok = False
            if child.pid not in pids:
                print(f"  BAD the matched child pid {child.pid} is not in {sorted_pids}")
                ok = False
            if quiet.pid in pids:
                print("  BAD an unmatched process was sampled")
                ok = False
            if not all(r.get("vm_rss_kb") for r in live):
                print("  BAD a live sample carried no vm_rss_kb")
                ok = False
            if not any("pss_kb" in r for r in live):
                print("  BAD smaps_rollup parsed to nothing -- Pss/Anonymous ARE the")
                print("      fragmentation evidence this study exists to collect")
                ok = False
            else:
                print(f"  smaps_rollup parsed: last pss_kb={live[-1].get('pss_kb')} kB, "
                      f"anonymous_kb={live[-1].get('anonymous_kb')} kB")
        finally:
            for p in (child, quiet):
                p.terminate()
                try:
                    p.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    p.kill()

        # report math on synthetic trajectories. Each subject's span must exceed the
        # trend window, or the correct verdict is TOO-SHORT-TO-TREND -- so build 4 h.
        synth = Path(td) / "synth.jsonl"
        t = time.time()
        with synth.open("w") as fh:
            for i in range(240):  # 4 h at 1 min, flat at 10 MB
                fh.write(json.dumps({"epoch": t + i * 60, "subject": "flat", "pid": 1,
                                     "alive": True, "vm_rss_kb": 10 * 1024}) + "\n")
            for i in range(240):  # 4 h, climbing 10 -> 20 MB
                fh.write(json.dumps({"epoch": t + i * 60, "subject": "climb", "pid": 2,
                                     "alive": True,
                                     "vm_rss_kb": int((10 + 10 * i / 239) * 1024)}) + "\n")
        rep = summarise(load_rows(synth))
        flat, climb = rep["subjects"]["flat"], rep["subjects"]["climb"]
        print(f"report: flat verdict {flat['verdict']} ({flat.get('growth_pct')}%), "
              f"climb verdict {climb['verdict']} ({climb.get('growth_pct')}%)")
        if flat["verdict"] != "STABLE":
            print("  BAD a flat trajectory was not called STABLE")
            ok = False
        if climb["verdict"] != "GROWING":
            print("  BAD a climbing trajectory was not called GROWING")
            ok = False
        if climb["peak_rss_kb"] != 20 * 1024:
            print(f"  BAD peak {climb['peak_rss_kb']} != {20*1024}")
            ok = False

        # a run shorter than the trend window must NOT come back STABLE
        brief = Path(td) / "brief.jsonl"
        with brief.open("w") as fh:
            for i in range(8):
                fh.write(json.dumps({"epoch": t + i * 10, "subject": "brief", "pid": 3,
                                     "alive": True, "vm_rss_kb": 5 * 1024}) + "\n")
        vb = summarise(load_rows(brief))["subjects"]["brief"]["verdict"]
        if vb != "TOO-SHORT-TO-TREND":
            print(f"  BAD a 70-second run reported {vb}, not TOO-SHORT-TO-TREND")
            ok = False
        else:
            print("report: a 70-second run is TOO-SHORT-TO-TREND, never STABLE")

        # a never-observed subject must not read like a clean result
        empty = Path(td) / "empty.jsonl"
        empty.write_text(json.dumps({"epoch": t, "subject": "ghost", "pid": None,
                                     "alive": False}) + "\n")
        rep2 = summarise(load_rows(empty))
        if rep2["subjects"]["ghost"]["verdict"] != "NEVER-OBSERVED":
            print("  BAD an unobserved subject was not flagged")
            ok = False
        else:
            print("report: an unobserved subject is flagged NEVER-OBSERVED")

    print(f"self-test: {'PASS' if ok else 'FAIL'}")
    return 0 if ok else 1


# --------------------------------------------------------------------------- #
# the study loop
# --------------------------------------------------------------------------- #
def study(out_path: Path, match: re.Pattern, duration_s: float, interval: float,
          spawn: list[tuple[str, list[str]]] | None = None, label_all: str | None = None) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stop = {"now": False}

    def _stop(*_):
        stop["now"] = True

    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, _stop)

    procs: list[tuple[str, subprocess.Popen]] = []
    for name, argv in (spawn or []):
        procs.append((name, subprocess.Popen(argv, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.DEVNULL)))
        print(f"spawned subject '{name}' as pid {procs[-1][1].pid}")

    t0 = time.time()
    ticks = 0
    with out_path.open("a", encoding="utf-8") as fh:
        while not stop["now"] and (time.time() - t0) < duration_s:
            epoch = time.time()
            ts = datetime.fromtimestamp(epoch, timezone.utc).isoformat(timespec="seconds")
            sysrow = system_row()

            def emit(subject: str, pid: int | None):
                row = {"ts": ts, "epoch": epoch, "subject": subject, "pid": pid}
                row.update(sample_pid(pid) if pid else {"alive": False})
                row.update(sysrow)
                fh.write(json.dumps(row) + "\n")

            seen = 0
            for pid, line in resolve(match):
                emit(label_all or line[:120], pid)
                seen += 1
            for name, p in procs:
                if p.poll() is None:
                    emit(name, p.pid)
                    seen += 1
                else:
                    fh.write(json.dumps({"ts": ts, "epoch": epoch, "subject": name,
                                         "pid": p.pid, "alive": False, "exit_code": p.returncode}) + "\n")
            fh.flush()
            ticks += 1
            if ticks % 10 == 1:
                print(f"  tick {ticks}: {seen} live subject(s), t+{(epoch-t0)/60:.1f} min", flush=True)
            # sleep in slices so a stop signal is honoured promptly
            wake = time.time() + interval
            while time.time() < wake and not stop["now"]:
                time.sleep(min(1.0, wake - time.time()))

    for name, p in procs:
        if p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=10)
            except subprocess.TimeoutExpired:
                p.kill()
    print(f"study finished after {ticks} tick(s) at {datetime.now(timezone.utc).isoformat(timespec='seconds')}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    # action="append" MUTATES the default in place, so the default must be None;
    # a "" default fails with AttributeError: 'str' object has no attribute 'append'
    ap.add_argument("--match", default=None, action="append",
                    help="regex against the full command line (repeatable)")
    ap.add_argument("--spawn", default=None, action="append",
                    help="OWNED subject as label::command (repeatable)")
    ap.add_argument("--out", default="")
    ap.add_argument("--report", default="")
    ap.add_argument("--duration", type=float, default=24.0, help="hours (default 24)")
    ap.add_argument("--interval", type=float, default=60.0, help="seconds between samples")
    ap.add_argument("--label", default="", help="prefix every match-resolved subject with this")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    if args.report:
        return print_report(Path(args.report))
    if not args.out:
        print("rss-24h: --out is required for a study", file=sys.stderr)
        return 3
    pats = [p for p in (args.match or []) if p]
    if not pats and not args.spawn:
        print("rss-24h: give at least one --match or --spawn", file=sys.stderr)
        return 3
    match = re.compile("|".join(f"(?:{p})" for p in pats)) if pats else re.compile(r"(?!x)x")

    spawned = []
    for spec in (args.spawn or []):
        if "::" not in spec:
            print(f"rss-24h: --spawn wants label::command, got {spec!r}", file=sys.stderr)
            return 3
        label, cmd = spec.split("::", 1)
        spawned.append((label, cmd.split()))

    return study(Path(args.out), match, args.duration * 3600, args.interval, spawned,
                 args.label or None)


if __name__ == "__main__":
    sys.exit(main())
