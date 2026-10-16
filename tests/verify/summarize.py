#!/usr/bin/env python3
"""Summarize a system_battery.sh results.tsv: counts + every non-PASS row."""
import sys, collections

path = sys.argv[1] if len(sys.argv) > 1 else "/tmp/nixe-verify/results.tsv"
rows = []
with open(path, encoding="utf-8", errors="replace") as f:
    for line in f:
        parts = line.rstrip("\n").split("\t", 2)
        if len(parts) >= 2:
            rows.append((parts[0], parts[1], parts[2] if len(parts) > 2 else ""))

print(f"total rows: {len(rows)}")
counts = collections.Counter(v for _, v, _ in rows)
for v, n in counts.most_common():
    print(f"  {v:9s} {n}")
print()
print("== non-PASS ==")
for name, verdict, note in rows:
    if verdict != "PASS":
        print(f"[{verdict}] {name} :: {note[:200]}")
