#!/usr/bin/env bash
# Format check without cargo-fmt.
#
# Why this exists: on this box `cargo fmt --all -- --check` blocks indefinitely
# (measured: >400 s, ~1 s of CPU). The underlying `rustfmt` is healthy — running it
# directly over every tracked .rs file completes in ~58 s. `cargo-fmt` spawns
# rustfmt once with every target path; whatever it waits on there, the direct call
# does not.
#
# Usage:
#   scripts/fmt-check.sh            # report files that would change (exit 1 if any)
#   scripts/fmt-check.sh --write    # format them in place
set -euo pipefail

cd "$(dirname "$0")/.."

mapfile -t files < <(git ls-files '*.rs')
if [ "${#files[@]}" -eq 0 ]; then
    echo "no rust files tracked" >&2
    exit 0
fi

if [ "${1:-}" = "--write" ]; then
    rustfmt --edition 2021 "${files[@]}"
    echo "formatted ${#files[@]} files"
    exit 0
fi

out="$(mktemp)"
trap 'rm -f "$out"' EXIT
status=0
rustfmt --check --edition 2021 "${files[@]}" > "$out" 2>&1 || status=$?

if [ "$status" -eq 0 ]; then
    echo "format: clean (${#files[@]} files)"
    exit 0
fi

changed=$(grep -c '^Diff in ' "$out" || true)
echo "format: ${changed} diff block(s) across ${#files[@]} files"
head -40 "$out"
exit 1
