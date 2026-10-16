#!/usr/bin/env bash
# scripts/fault_suite.sh — fault-injection suite driver (B3.2.2 / B3.2.3).
#
# Read-only. Two phases:
#   1. if `cargo` is on PATH: `cargo test --lib fault_injection` (offline subset)
#   2. always: print the MANUAL protocol checklist for the scenarios with
#      `offline_checkable: false` in src/fault_injection.rs — these need a live
#      egress run and are OPERATOR-RUN (never in CI, never unattended).
#
# Exit status: 0 when the offline tests pass (or cargo is unavailable and the
# tests were honestly skipped); 1 when a test run fails. Never fails the shell
# on a missing cargo — this box runs with no cargo by house rule.
#
# Usage:  bash scripts/fault_suite.sh [--manual-only]
#         (--manual-only skips the cargo phase and prints only the checklist)
#
# Failures => postmortem. See docs/postmortems/README.md + TEMPLATE.md.

set -u

MANUAL_ONLY=0
for arg in "$@"; do
    case "$arg" in
        --manual-only) MANUAL_ONLY=1 ;;
        -h|--help)
            echo "usage: bash scripts/fault_suite.sh [--manual-only]"
            exit 0
            ;;
        *)
            echo "unknown argument: $arg" >&2
            exit 2
            ;;
    esac
done

# Repo-root detection from the script's own location — path-portable: works from
# any cwd, via an absolute or relative invocation, and through symlinks
# (BASH_SOURCE with a $0 fallback for non-bash shells).
SOURCE="${BASH_SOURCE[0]:-$0}"
while [ -L "$SOURCE" ]; do
    DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
    SOURCE="$(readlink "$SOURCE")"
    [ "$SOURCE" = "${SOURCE#/}" ] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
RC=0

echo "== Tallow fault-injection suite =="
echo "root:    $ROOT"
echo "module:  src/fault_injection.rs (suite of 11 scenarios; 7 offline-checkable)"
echo

# ── phase 1: offline subset (cargo, when available) ────────────────────────
if [ "$MANUAL_ONLY" -eq 1 ]; then
    echo "-- SKIP: --manual-only; not running cargo test"
elif command -v cargo >/dev/null 2>&1; then
    echo "-- cargo test --lib fault_injection"
    (cd "$ROOT" && cargo test --lib fault_injection)
    RC=$?
    if [ "$RC" -eq 0 ]; then
        echo "-- offline subset: PASS"
    else
        echo "-- offline subset: FAIL (rc=$RC) — file a postmortem: docs/postmortems/README.md"
    fi
else
    echo "-- SKIP: cargo not found in PATH; in-repo test run not executed."
    echo "   (offline subset is still proven out-of-tree by the AGT-134 rustc harness;"
    echo "    this driver only reports what runs on THIS host)"
fi

echo

# ── phase 2: manual protocol checklist (offline_checkable: false) ──────────
echo "== MANUAL PROTOCOL CHECKLIST — OPERATOR-RUN (live egress required) =="
echo "Preconditions for every row: a real Tor instance reachable on the configured"
echo "SOCKS5 endpoint; a disposable upstream URL that echoes what it received."
echo "For each row: kill Tor at the stated moment, then confirm the expected"
echo "handling. Any deviation => fault-suite FAILURE => postmortem."
echo
echo "[ ] tor-kill-after-connect"
echo "    fault:      SOCKS5/TCP connect succeeds, Tor killed before any"
echo "                request is answered."
echo "    expect:     transport error surfaced; no partial record written;"
echo "                NO silent retry through the dead proxy."
echo "    evidence:   error line + absence of output artifact."
echo
echo "[ ] tor-kill-before-response"
echo "    fault:      request written to Tor, killed before first response byte."
echo "    expect:     surfaced error; no hung task past deadline; no cached"
echo "                success; no fallback to direct egress."
echo "    evidence:   request log + operator terminal capture."
echo
echo "[ ] tor-kill-during-body"
echo "    fault:      Tor killed after a partial response body arrived."
echo "    expect:     partial body discarded (never parsed, never archived as"
echo "                complete); error surfaced; fixity/checksum path records"
echo "                no success."
echo "    evidence:   truncated artifact rejected + error line."
echo
echo "[ ] tor-kill-mid-headers"
echo "    fault:      Tor killed after status line / partial headers arrived."
echo "    expect:     no success recorded from partial headers; error surfaced;"
echo "                request NOT silently re-dispatched on a new circuit."
echo "    evidence:   error line + single-dispatch request log."
echo
echo "On any failure: capture logs, then file docs/postmortems/YYYY-MM-DD-<slug>.md"
echo "using docs/postmortems/TEMPLATE.md."
echo

if [ "$RC" -eq 0 ]; then
    echo "SUMMARY: fault suite OK (offline phase: see above; manual phase: operator-run)."
else
    echo "SUMMARY: fault suite FAILED (offline phase rc=$RC)."
fi
exit "$RC"
