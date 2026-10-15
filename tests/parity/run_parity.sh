#!/usr/bin/env bash
# Tallow behavioral-parity runner (Phase 4.1b / 1.3).
# For each parity_programs/*.tl:
#   REFERENCE (tree-walk):  tallow run <file> --target <cross>   -> forces the interpreter path
#   NATIVE:                 tallow build <file> (temp dir) then run the compiled binary
#   Compare stdout + exit code. Report MATCH / DIVERGE / REFUSED / ERROR(build|timeout).
# stderr is captured but NOT compared (differs by path by design).
#
# Fixtures declare their expected outcome in their own head, so a refusal is asserted rather than
# ignored:
#   // parity: expect-refusal             both legs must refuse (interpreter rc != 0, native build rc != 0)
#   // parity: expect-build-fallback      the native build is documented to fail (fail-loud/fallback)
# Without a marker, a failing native build is an ERROR(build): reported, with the build output, and
# NOT counted as a pass — an unclassified build failure must never look like coverage.
set -u

REPO="${REPO:-$(cd "$(dirname "$0")/../.." && pwd)}"
TALLOW="${TALLOW:-$REPO/target/debug/tallow}"
PROGS_DIR="$(dirname "$0")/parity_programs"
# A cross triple forces the interpreter path (is_cross guard skips native).
CROSS_TARGET="${CROSS_TARGET:-x86_64-linux}"
TIMEOUT_S="${TIMEOUT_S:-30}"

if [ ! -x "$TALLOW" ]; then
  echo "ERROR: tallow binary not found at $TALLOW (build it first: cargo build --bin tallow)"
  echo "       (set TALLOW=<path> to point at a binary built with a custom CARGO_TARGET_DIR)"
  exit 2
fi

pass=0; diverge=0; refused=0; fallback=0; error=0
for f in "$PROGS_DIR"/*.tl; do
  name=$(basename "$f")
  expect=""
  grep -q 'parity: expect-refusal'        "$f" && expect=refusal
  grep -q 'parity: expect-build-fallback' "$f" && expect=fallback

  # ── reference: tree-walking interpreter (cross target -> not native) ──
  ref_out=$(timeout "$TIMEOUT_S" "$TALLOW" run "$f" --target "$CROSS_TARGET" 2>/dev/null); ref_rc=$?
  # ── native: build to a temp dir then run the binary ──
  tmp=$(mktemp -d); cp "$f" "$tmp/prog.tl"
  bld_out=$(timeout "$TIMEOUT_S" "$TALLOW" build "$tmp/prog.tl" 2>&1); bld_rc=$?

  # A shared target directory under concurrent load can fail a build that succeeds in isolation;
  # retry once before treating it as an outcome. Skipped for declared refusals (deterministic).
  if [ "$bld_rc" -ne 0 ] && [ "$expect" != "refusal" ]; then
    sleep 2
    bld_out=$(timeout "$TIMEOUT_S" "$TALLOW" build "$tmp/prog.tl" 2>&1); bld_rc=$?
  fi

  if [ "$bld_rc" -ne 0 ]; then
    if [ "$expect" = "refusal" ]; then
      if [ "$ref_rc" -ne 0 ]; then
        echo "$name: REFUSED (both legs; interpreter rc=$ref_rc, native build rc=$bld_rc)"
        refused=$((refused+1))
      else
        echo "$name: DIVERGE (declared expect-refusal but the interpreter SUCCEEDED on a call the native build rejects)"
        diverge=$((diverge+1))
      fi
    elif [ "$expect" = "fallback" ]; then
      echo "$name: FALLBACK(documented; native build rc=$bld_rc)"
      fallback=$((fallback+1))
    else
      echo "$name: ERROR(build)"
      echo "  reason: $(printf '%s' "$bld_out" | grep -iE 'error|refus|not supported|unavailable' | head -1 | cut -c1-140)"
      error=$((error+1))
    fi
  else
    nat_out=$(timeout "$TIMEOUT_S" "$tmp/prog" 2>/dev/null); nat_rc=$?
    nat_rc=${nat_rc:-1}  # 124 (timeout) or signal crash yields non-zero
    if [ "$ref_rc" -eq "$nat_rc" ] && [ "$ref_out" = "$nat_out" ]; then
      echo "$name: MATCH (rc=$ref_rc)"
      pass=$((pass+1))
    else
      echo "$name: DIVERGE (ref_rc=$ref_rc nat_rc=$nat_rc)"
      [ "$ref_out" != "$nat_out" ] && { echo "  ref : $(echo "$ref_out" | head -1)"; echo "  nat : $(echo "$nat_out" | head -1)"; }
      diverge=$((diverge+1))
    fi
  fi
  rm -rf "$tmp"
done

echo "-----"
echo "RESULT: $pass MATCH, $refused REFUSED, $fallback FALLBACK, $diverge DIVERGE, $error ERROR(build)"
echo "        ($((pass+refused+fallback+diverge+error)) fixtures; every fixture must land in a named class)"
[ "$diverge" -eq 0 ] || exit 1
exit 0
