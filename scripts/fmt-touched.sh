#!/bin/sh
# fmt-touched.sh — run rustfmt over ONLY the .rs files changed since <base>.
#
# Why this exists: `cargo fmt --all` is impractical in this workspace. Measured
# 2026-10-16 — the same command takes 10.3 s on a rustfmt-clean tree and >5 min
# here, because the tree carries 2,827 formatting-diff blocks across 874 tracked
# .rs files, and rustfmt spends ~65 s on src/interp.rs (56,216 lines) alone.
# The README's rule is "format only the files you touched"; this is that rule as
# a command, so it is not a judgement call each time.
#
#   scripts/fmt-touched.sh                # check the working tree vs HEAD
#   scripts/fmt-touched.sh --write        # rewrite them in place
#   scripts/fmt-touched.sh main           # check everything since main
#   scripts/fmt-touched.sh main --write
#
# Exit: 0 nothing to do, or rustfmt clean; 1 rustfmt reported diffs (check mode);
#       2 usage error or rustfmt not on PATH.

set -u

BASE=HEAD
CHECK=1
for arg in "$@"; do
  case "$arg" in
    --write) CHECK=0 ;;
    --check) CHECK=1 ;;
    -h|--help) sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "fmt-touched: unknown option: $arg" >&2; exit 2 ;;
    *) BASE="$arg" ;;
  esac
done

if ! command -v rustfmt >/dev/null 2>&1; then
  echo "fmt-touched: rustfmt not on PATH" >&2
  exit 2
fi

# ACMR: deleted files have nothing to format.
FILES=$(git diff --name-only --diff-filter=ACMR "$BASE" -- '*.rs' 2>/dev/null)

if [ -z "$FILES" ]; then
  echo "fmt-touched: no .rs changes vs $BASE — nothing to do"
  exit 0
fi

N=$(printf '%s\n' "$FILES" | wc -l | tr -d ' ')
echo "fmt-touched: $N .rs file(s) vs $BASE, mode=$([ "$CHECK" -eq 1 ] && echo check || echo write)"
if printf '%s\n' "$FILES" | grep -q '^src/interp.rs$'; then
  echo "  note: src/interp.rs is in this set — rustfmt alone takes ~65 s on it"
fi

t0=$(date +%s)
if [ "$CHECK" -eq 1 ]; then
  # shellcheck disable=SC2086
  rustfmt --edition 2024 --check $FILES
  rc=$?
else
  # shellcheck disable=SC2086
  rustfmt --edition 2024 $FILES
  rc=$?
fi
t1=$(date +%s)
echo "fmt-touched: finished in $((t1 - t0))s (rustfmt rc=$rc)"
exit $rc
