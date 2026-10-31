#!/usr/bin/env python3
"""check_deny_expiry.py — make the documented review deadline on ignored
advisories an actual gate.

Why this exists. `deny.toml` and `.cargo/audit.toml` carry ignore lists whose
comments say, in two places:

    Every entry below expires 2027-01-31; the gate fails again on that date so
    the decision is re-made rather than inherited.

Nothing enforced that. `cargo deny` has no expiry mechanism for `ignore`
entries, and no script in this repository read the date, so on 2027-02-01 every
entry would have stayed silently ignored while the comment claimed otherwise.
Measured 2026-10-31: `grep -rn 2027-01-31` found only comments and one unrelated
test fixture (tests/scope_gate.rs). A deadline nothing checks is a wish.

What is enforced, all offline and deterministic:

  1. Each of the two ignore-list files must carry exactly one structured marker
     line `# review-deadline: YYYY-MM-DD`. A missing or duplicated marker is a
     failure — an undated exception list is exactly what this gate is for.
  2. Today must be on or before every deadline. Past it, the gate fails and names
     the file, the deadline and the entries that need re-deciding.
  3. Every `"RUSTSEC-YYYY-NNNN"` ignore entry must name an advisory that exists
     in the local advisory database (skipped when the database is absent, with a
     loud note rather than a silent pass). A typo'd or withdrawn ID silently
     matches nothing and hides a real finding; this catches that.

Usage:
  python3 scripts/check_deny_expiry.py                  # gate (exit 1 on failure)
  python3 scripts/check_deny_expiry.py --today 2027-02-01   # what the gate will say then

Exit codes: 0 = ok; 1 = a deadline has passed or a marker/entry is malformed;
2 = the script could not read an input it needs.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = ("deny.toml", ".cargo/audit.toml")
MARKER = re.compile(r"^#\s*review-deadline:\s*(\d{4}-\d{2}-\d{2})\s*$", re.MULTILINE)
ENTRY = re.compile(r'"RUSTSEC-(\d{4})-(\d{4})"')


def parse_deadline(path: Path, text: str, problems: list[str]) -> dt.date | None:
    found = MARKER.findall(text)
    if not found:
        problems.append(
            f"{path}: no '# review-deadline: YYYY-MM-DD' marker — an ignore list "
            f"without a review date is an exception with no end"
        )
        return None
    if len(found) > 1:
        problems.append(
            f"{path}: {len(found)} '# review-deadline' markers ({', '.join(found)}); "
            f"keep exactly one so the deadline is unambiguous"
        )
        return None
    try:
        return dt.date.fromisoformat(found[0])
    except ValueError:
        problems.append(f"{path}: review-deadline {found[0]!r} is not a YYYY-MM-DD date")
        return None


def advisory_db() -> Path | None:
    explicit = os.environ.get("CARGO_ADVISORY_DB")
    candidates = [Path(explicit)] if explicit else []
    candidates.append(Path(os.path.expanduser("~/.cargo/advisory-db")))
    for cand in candidates:
        if (cand / "crates").is_dir():
            return cand
    return None


def known_advisories(db: Path) -> set[str]:
    ids: set[str] = set()
    for pkg_dir in (db / "crates").iterdir():
        if not pkg_dir.is_dir():
            continue
        for f in pkg_dir.glob("RUSTSEC-*.md"):
            ids.add(f.stem)
    return ids


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument(
        "--today",
        metavar="YYYY-MM-DD",
        help="date to evaluate against (default: today, UTC) — for proving the gate fails",
    )
    args = ap.parse_args(argv[1:])

    today = (
        dt.date.fromisoformat(args.today)
        if args.today
        else dt.datetime.now(dt.timezone.utc).date()
    )

    problems: list[str] = []
    notes: list[str] = []
    db = advisory_db()
    known = known_advisories(db) if db else set()
    if not db:
        notes.append(
            "no advisory database found (CARGO_ADVISORY_DB or ~/.cargo/advisory-db); "
            "ignore-entry existence checks were skipped — this is not a pass"
        )

    total_entries = 0
    for rel in FILES:
        path = ROOT / rel
        if not path.is_file():
            problems.append(f"{rel}: missing (expected an ignore list here)")
            continue
        text = path.read_text(encoding="utf-8")
        entries = sorted(set(ENTRY.findall(text)))
        total_entries += len(entries)
        deadline = parse_deadline(Path(rel), text, problems)

        for year, num in entries:
            adv = f"RUSTSEC-{year}-{num}"
            if db and adv not in known:
                problems.append(
                    f"{rel}: {adv} is ignored but does not exist in {db} — "
                    f"a stale or typo'd entry suppresses nothing and hides a real finding"
                )

        if deadline and today > deadline:
            listed = ", ".join(f"RUSTSEC-{y}-{n}" for y, n in entries)
            problems.append(
                f"{rel}: review deadline {deadline.isoformat()} has passed "
                f"(today {today.isoformat()}) — re-decide {len(entries)} ignored "
                f"advisori(es) before the next release: {listed}"
            )

    for note in notes:
        print(f"note: {note}", file=sys.stderr)

    if problems:
        for p in problems:
            print(f"FAIL {p}", file=sys.stderr)
        print(
            f"deny-expiry: {len(problems)} problem(s) across {len(FILES)} ignore list(s)",
            file=sys.stderr,
        )
        return 1

    print(
        f"deny-expiry: ok — {total_entries} ignored advisori(es) across "
        f"{len(FILES)} file(s), all inside their review deadline as of {today.isoformat()}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
