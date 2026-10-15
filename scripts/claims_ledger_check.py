#!/usr/bin/env python3
"""claims-ledger check — gate logic for the Tallow claims ledger.

Implements the design in `research/tallow-v1/cycle-02/03-claims-register.md`
§3.2 (data model + gate mechanics) — rules R1-R6:

  R1 coverage        every entry parses; id unique; bucket/label/action in enum;
                     >=1 source; every source anchor resolves (file exists,
                     line <= line count).
  R2 shipped-needs-test  label: shipped => method present and resolvable
                     (tests/*.rs::name | benches/* | docs/benchmarks/*.md).
  R3 bucket-D rejection  bucket: D => label == target-only AND
                     action in {rewrite, retire}.
  R4 source-side sweep   §1 regex patterns over the registered source files;
                     matches not attributable to an entry (anchor line/range or
                     normalized text) => warning (hard fail after adoption).
  R5 stale check     last_verified older than 90 days => warning.
  R6 report          --format text|json; counts by label/bucket;
                     exit 0 clean | 1 hard fail | 2 warnings only
                     (2 is also used for usage/load errors — see message).

Fast-path philosophy (same as scripts/never_check.sh): read-only, Linux-only,
no cargo, no builds. The --no-cargo flag is accepted for CLI compatibility and
is a no-op: this check never invokes cargo.

Exit codes: 0 = clean; 1 = one or more hard findings; 2 = warnings only,
or usage/ledger load error.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import json
import re
import sys
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.stderr.write("claims_ledger_check: PyYAML not available (python3 -c 'import yaml')\n")
    sys.exit(2)

BUCKETS = ("A", "B", "C", "D", "S")
LABELS = ("shipped", "partial", "target-only")
ACTIONS = ("keep", "edit", "rewrite", "retire")
STALE_DAYS = 90

# §1 sweep patterns (kept parallel to scripts/claims_sweep.sh).
SWEEP_PATTERNS = (
    ("numeric", re.compile(
        r"[0-9][0-9,.]*\+?\s?(?:K concurrent|M concurrent|x faster|GB/s|MB/s|µs|us|ms|s|×)"
        r"(?![0-9A-Za-z/])")),
    ("absolute", re.compile(
        r"undetect|unblockable|military|quantum|guarantee|zero[ -]simulation|fastest|"
        r"100K|10M\+|DPDK|io_uring", re.I)),
    ("jurisdiction", re.compile(r"\b(?:CCPA|LGPD|PIPEDA|APPI|PIPL|HIPAA|SOX|PCI-DSS)\b")),
)

ANCHOR_RE = re.compile(r"^(?P<path>.+?)(?::(?P<start>[0-9]+)(?:\s*[-\u2013]\s*(?P<end>[0-9]+))?)?$")

DISPLAY_CAP = 40


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", s.strip().lower())


class Finding(dict):
    pass


def parse_anchor(anchor: str):
    """Return (path, start, end) — start/end None when no line given."""
    m = ANCHOR_RE.match(anchor.strip().strip("`"))
    if not m:
        return None
    path = m.group("path")
    start = int(m.group("start")) if m.group("start") else None
    end = int(m.group("end")) if m.group("end") else start
    return path, start, end


def check_method(root: Path, method: str):
    """R2 — resolvable method: tests/*.rs::name | benches/* | docs/benchmarks/*.md."""
    m = method.strip().strip("`")
    if not m:
        return False, "method is empty"
    name = None
    for sep in ("::", "#"):
        if sep in m:
            m, _, name = m.partition(sep)
            break
    rel = m.strip()
    p = (root / rel)
    if rel.startswith("tests/") and rel.endswith(".rs"):
        if not p.exists():
            return False, f"test file missing: {rel}"
        if name:
            text = p.read_text(errors="ignore")
            if not re.search(r"fn\s+%s\b" % re.escape(name), text) and name not in text:
                return False, f"test fn '{name}' not found in {rel}"
        elif not name:
            return False, f"test method needs '::<test_fn>' form: {rel}"
        return True, ""
    if rel.startswith("benches/"):
        if not p.exists():
            return False, f"bench path missing: {rel}"
        return True, ""
    if rel.startswith("docs/benchmarks/") and rel.endswith(".md"):
        if not p.exists():
            return False, f"protocol doc missing: {rel}"
        if name:
            if _norm(name) not in _norm(p.read_text(errors="ignore")):
                return False, f"row text '{name}' not found in {rel}"
        return True, ""
    return False, ("unresolvable method form (allowed: tests/*.rs::name, "
                   f"benches/*, docs/benchmarks/*.md): {rel}")


def load_ledger(path: Path):
    data = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace"))
    if isinstance(data, dict) and "entries" in data:
        data = data["entries"]
    if not isinstance(data, list):
        raise ValueError("ledger root is not a list of entries")
    return data


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="claims_ledger_check.py", add_help=True,
        description="Claims-ledger gate (cycle-02/03 §3.2, rules R1-R6).")
    ap.add_argument("--root", default=None,
                    help="repo root to resolve anchors against (default: parent of scripts/)")
    ap.add_argument("--ledger", default=None,
                    help="ledger path, relative to --root unless absolute (default: docs/claims-ledger.yaml)")
    ap.add_argument("--format", choices=("text", "json"), default="text")
    ap.add_argument("--warn-only", action="store_true",
                    help="report hard findings but always exit 0 (phased adoption)")
    ap.add_argument("--no-cargo", action="store_true",
                    help="accepted for CLI compat; this check never invokes cargo (no-op)")
    ap.add_argument("--now", default=None,
                    help="override today's date (YYYY-MM-DD) for the R5 stale check")
    args = ap.parse_args(argv)

    root = Path(args.root).resolve() if args.root else Path(__file__).resolve().parent.parent
    ledger_path = Path(args.ledger) if args.ledger else Path("docs/claims-ledger.yaml")
    if not ledger_path.is_absolute():
        ledger_path = root / ledger_path

    hard: list[dict] = []
    warn: list[dict] = []
    today = (_dt.date.fromisoformat(args.now) if args.now else _dt.date.today())

    def H(rid, rule, msg):
        hard.append({"id": rid, "rule": rule, "msg": msg})

    def W(rid, rule, msg, **extra):
        warn.append({"id": rid, "rule": rule, "msg": msg, **extra})

    if not ledger_path.exists():
        err = f"ledger not found: {ledger_path}"
        if args.format == "json":
            print(json.dumps({"ok": False, "error": err}, indent=2))
        else:
            print(f"ERROR: {err}")
        return 2

    try:
        entries = load_ledger(ledger_path)
    except Exception as exc:  # noqa: BLE001 — report any parse failure verbatim
        err = f"ledger load error: {exc}"
        if args.format == "json":
            print(json.dumps({"ok": False, "error": err}, indent=2))
        else:
            print(f"ERROR: {err}")
        return 2

    seen_ids: set[str] = set()
    anchors_by_file: dict[str, list[tuple[int, int]]] = {}
    blobs: list[str] = []

    # ---- R1 coverage + R2 + R3 + R5 -------------------------------------
    for e in entries:
        if not isinstance(e, dict):
            H("<entry>", "R1", f"entry is not a mapping: {e!r}")
            continue
        rid = str(e.get("id") or "<missing-id>")
        if rid in seen_ids:
            H(rid, "R1", f"duplicate id: {rid}")
        seen_ids.add(rid)

        blob = " ".join(str(e.get(k) or "") for k in
                        ("id", "claim", "sources", "method", "reason", "action", "owner"))
        blobs.append(_norm(blob))

        bucket, label, action = e.get("bucket"), e.get("label"), e.get("action")
        if bucket not in BUCKETS:
            H(rid, "R1", f"bucket '{bucket}' not in {list(BUCKETS)}")
        if label not in LABELS:
            H(rid, "R1", f"label '{label}' not in {list(LABELS)}")
        if action not in ACTIONS:
            H(rid, "R1", f"action '{action}' not in {list(ACTIONS)}")

        srcs = e.get("sources") or []
        if not srcs:
            H(rid, "R1", "no sources")
        for s in srcs:
            parsed = parse_anchor(str(s))
            if not parsed:
                H(rid, "R1", f"unparsable source anchor: {s!r}")
                continue
            path, start, end = parsed
            p = root / path
            if not p.exists():
                H(rid, "R1", f"missing source file: {path}")
                continue
            nlines = len(p.read_text(errors="ignore", encoding="utf-8").splitlines())
            if start is not None:
                if start < 1 or start > nlines or (end is not None and end > nlines):
                    H(rid, "R1", f"{s} out of range (file has {nlines} lines)")
                else:
                    anchors_by_file.setdefault(path, []).append(
                        (start, end if end is not None else start))

        # R5 stale
        lv = e.get("last_verified")
        if lv is not None:
            try:
                if isinstance(lv, _dt.date):
                    lvd = lv
                else:
                    lvd = _dt.date.fromisoformat(str(lv))
                age = (today - lvd).days
                if age > STALE_DAYS:
                    W(rid, "R5", f"last_verified {age}d old (>{STALE_DAYS}d)")
            except ValueError:
                W(rid, "R5", f"unparsable last_verified: {lv!r}")

        # R2 shipped-needs-test
        if label == "shipped":
            method = e.get("method")
            if not method:
                H(rid, "R2", "label=shipped without method (no test/bench/protocol mapping)")
            else:
                ok, why = check_method(root, str(method))
                if not ok:
                    H(rid, "R2", f"label=shipped, method not resolvable — {why}")

        # R3 bucket-D rejection
        if bucket == "D":
            if label != "target-only":
                H(rid, "R3", f"bucket=D but label={label} (requires target-only)")
            if action not in ("rewrite", "retire"):
                H(rid, "R3", f"bucket=D but action={action} (requires rewrite|retire)")

    # ---- R4 source-side sweep -------------------------------------------
    sweep_files = sorted({p for p in anchors_by_file})
    scanned: list[str] = []
    for rel in sweep_files:
        p = root / rel
        if not p.exists():
            continue
        scanned.append(rel)
        try:
            lines = p.read_text(errors="ignore", encoding="utf-8").splitlines()
        except OSError:
            continue
        ranges = anchors_by_file.get(rel, [])
        for lineno, line in enumerate(lines, 1):
            for pname, pat in SWEEP_PATTERNS:
                for m in pat.finditer(line):
                    tok = m.group(0).strip().strip("`\"'[]()")
                    ntok = tok.lower()
                    attributed = any(a <= lineno <= b for a, b in ranges) or \
                        any(ntok and ntok in b for b in blobs)
                    if not attributed:
                        W(None, "R4", f"unregistered match {tok!r} ({pname})",
                          file=rel, line=lineno, pattern=pname, match=tok)

    # ---- R6 report -------------------------------------------------------
    by_label = {k: sum(1 for e in entries if isinstance(e, dict) and e.get("label") == k)
                for k in LABELS}
    by_bucket = {k: sum(1 for e in entries if isinstance(e, dict) and e.get("bucket") == k)
                 for k in BUCKETS}
    hard_ids = sorted({f["id"] for f in hard})
    warnings_total = len(warn)
    exit_code = 1 if hard else (2 if warn else 0)
    shown = warn[:DISPLAY_CAP]

    result = {
        "tool": "claims_ledger_check",
        "version": "0.1.0-E-3-06",
        "root": str(root),
        "ledger": str(ledger_path),
        "generated_at": _dt.datetime.now(_dt.timezone.utc).isoformat(timespec="seconds"),
        "ok": not hard,
        "exit_code": 0 if args.warn_only else exit_code,
        "summary": {
            "entries": len(entries),
            "by_label": by_label,
            "by_bucket": by_bucket,
            "hard_rows": len(hard_ids),
            "hard_findings": len(hard),
            "warnings_total": warnings_total,
            "warnings_shown": len(shown),
            "sweep_files": len(scanned),
        },
        "hard": hard,
        "warnings": shown,
        "warnings_truncated": warnings_total > len(shown),
        "warn_only": args.warn_only,
    }

    if args.format == "json":
        print(json.dumps(result, indent=2))
    else:
        print(f"claims-ledger check · root={root}")
        print(f"ledger: {ledger_path}")
        print(f"entries: {len(entries)} "
              f"(by label: {', '.join(f'{k}={v}' for k, v in by_label.items())}) "
              f"(by bucket: {', '.join(f'{k}={v}' for k, v in by_bucket.items())})")
        if hard:
            print(f"\nHARD findings ({len(hard_ids)} rows / {len(hard)} findings):")
            for f in hard:
                print(f"  [FAIL {f['rule']}] {f['id']}: {f['msg']}")
        else:
            print("\nHARD findings: none")
        if shown:
            print(f"\nWARN ({warnings_total}; showing first {len(shown)}):")
            for w in shown:
                loc = f"{w['file']}:{w['line']}" if w.get("file") else "-"
                print(f"  [WARN {w['rule']}] {loc} {w['id'] or ''}: {w['msg']}")
            if warnings_total > len(shown):
                print(f"  ... {warnings_total - len(shown)} more warnings "
                      f"(use --format json for the full list)")
        else:
            print("\nWARN: none")
        verdict = "PASS" if exit_code == 0 else ("FAIL" if exit_code == 1 else "WARN-ONLY")
        forced = " (exit forced to 0 by --warn-only)" if args.warn_only and exit_code else ""
        print(f"\nRESULT: {verdict} — exit {0 if args.warn_only else exit_code}{forced}")

    return 0 if args.warn_only else exit_code


if __name__ == "__main__":
    sys.exit(main())
