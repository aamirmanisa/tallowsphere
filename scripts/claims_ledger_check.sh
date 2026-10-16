#!/usr/bin/env bash
# claims_ledger_check.sh — thin wrapper for the claims-ledger gate.
#
# Design: research/tallow-v1/cycle-02/03-claims-register.md §3.2 (artifact
# docs/claims-ledger.yaml; logic in scripts/claims_ledger_check.py).
# Fast-path, Linux-only, read-only: greps/reads only, never invokes cargo and
# writes no file. Same philosophy as scripts/never_check.sh.
#
# Usage (from the repo root or anywhere — root is resolved from this script):
#   bash scripts/claims_ledger_check.sh [--format json] [--warn-only]
#                                       [--root DIR] [--ledger PATH] [--no-cargo]
#
# Exit: 0 = clean · 1 = hard findings · 2 = warnings only, or usage/load error.
# (--no-cargo is accepted for CLI compatibility and is a no-op.)
set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if ! command -v python3 >/dev/null 2>&1; then
  echo "claims_ledger_check: python3 not found" >&2
  exit 2
fi
if ! python3 -c 'import yaml' >/dev/null 2>&1; then
  echo "claims_ledger_check: PyYAML required (python3 -c 'import yaml' failed)" >&2
  exit 2
fi

exec python3 "$ROOT/scripts/claims_ledger_check.py" "$@"
