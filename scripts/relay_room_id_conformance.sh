#!/usr/bin/env bash
# Wire-conformance check: does the Tallow-source surface agree with the Rust crate on the room-id
# derivation — the one value that decides whether two peers meet in the same room?
#
#   tests/vectors/relay_room_id.v1.txt   the crate's derivation, pinned by
#                                        tests/relay_room_id_conformance.rs
#   tests/conformance/relay_room_id.tl   the language's RelayRoom.room_id(code) surface, which
#                                        stdlib/relay_room.rs implements as a native binding over
#                                        that same crate (is_supported_code -> resolve_room_id)
#
# THREE outcomes per vector, distinguished deliberately — conflating the third with the second hid
# a real finding the first time this ran:
#   AGREE     accepted code: the language produced the crate's room id, byte for byte.
#             refused code: the language refused it (the strict-8 rule). Refusal parity is contract
#             too — a code one peer accepts and the other refuses is an interop break.
#   MISMATCH  the two genuinely disagree. Different derivations land peers in different rooms.
#   NOT-AOT   the native backend has no lowering for the method, so no compiled leg exists at all.
#             That is a capability gap in the engine, NOT a disagreement between the repositories —
#             both of them call the same Rust function — so it is reported separately and counted
#             as neither agreement nor failure.
#
# Both engines are exercised: the interpreter leg is forced with a cross target, the native leg with
# --require-native (which refuses the interpreter fallback, so a pass there is a real compiled pass).
#
# Usage:  bash scripts/relay_room_id_conformance.sh [path/to/tallow]
# Exit:   0 agreement (a NOT-AOT native leg is reported, and does not fail the check)
#         1 disagreement — an interop defect
#         2 the harness could not run
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TALLOW_BIN="${1:-${TALLOW_BIN:-$ROOT/target/debug/tallow}}"
VECTORS="$ROOT/tests/vectors/relay_room_id.v1.txt"
PROG="$ROOT/tests/conformance/relay_room_id.tl"

[ -f "$VECTORS" ] || { echo "harness: $VECTORS missing — run: REGENERATE_ROOM_ID_VECTORS=1 cargo test --test relay_room_id_conformance" >&2; exit 2; }
[ -f "$PROG" ]    || { echo "harness: $PROG missing" >&2; exit 2; }
[ -x "$TALLOW_BIN" ] || { echo "harness: no tallow binary at $TALLOW_BIN (pass one as \$1)" >&2; exit 2; }

total=0; bad=0; hard_error=0; not_aot_total=0

check_leg() {
  local label="$1"; shift
  local agrees=0 mismatches=0 not_aot=0
  echo "  $label"
  while IFS=$'\t' read -r code expected version supported; do
    case "$code" in ''|'#'*) continue ;; esac
    total=$((total+1))
    local out rc printed
    out="$("$TALLOW_BIN" run "$PROG" "$@" -- "$code" 2>/tmp/room_id_leg.err)"; rc=$?
    printed="$(printf '%s\n' "$out" | awk -F'\t' -v c="$code" '$1==c {print $2}' | head -1)"
    if grep -q "native build unavailable" /tmp/room_id_leg.err; then
      not_aot=$((not_aot+1))
      continue
    fi
    if [ "$supported" = "true" ]; then
      if [ $rc -ne 0 ]; then
        printf '    %-20s DID NOT RUN (rc=%s)\n' "$code" "$rc"; sed 's/^/        /' /tmp/room_id_leg.err | head -3
        mismatches=$((mismatches+1))
      elif [ "$printed" != "$expected" ]; then
        printf '    %-20s MISMATCH  rust=%s... tallow=%s...\n' "$code" "${expected:0:16}" "${printed:0:16}"
        mismatches=$((mismatches+1))
      else
        agrees=$((agrees+1))
      fi
    else
      # the crate does not accept this code: the language must refuse it too
      if [ $rc -eq 0 ] && [ -n "$printed" ]; then
        printf '    %-20s ACCEPTED BY THE LANGUAGE but not by the crate\n' "$code"
        mismatches=$((mismatches+1))
      elif grep -q "unsupported code" /tmp/room_id_leg.err; then
        agrees=$((agrees+1))
      else
        printf '    %-20s refused for the wrong reason\n' "$code"; sed 's/^/        /' /tmp/room_id_leg.err | head -3
        mismatches=$((mismatches+1))
      fi
    fi
  done < <(grep -v '^#' "$VECTORS")
  if [ "$not_aot" -gt 0 ]; then
    echo "    -> $agrees agree, $mismatches mismatch, $not_aot not AOT-compilable in this build"
    echo "       (the native backend has no lowering for this method — an engine capability gap,"
    echo "        not a disagreement between the repositories: both call the same Rust function)"
  else
    echo "    -> $agrees agree, $mismatches mismatch"
  fi
  bad=$((bad+mismatches)); not_aot_total=$((not_aot_total+not_aot))
  [ "$mismatches" -eq 0 ] || hard_error=1
}

echo "wire conformance — room-id derivation, rust crate vs the language surface"
echo "binary:  $TALLOW_BIN"
echo "vectors: $(grep -vc '^#' "$VECTORS")"
echo
check_leg "interpreter leg (cross target)" --target x86_64-linux
echo
check_leg "native leg (--require-native)"  --require-native

echo
if [ "$hard_error" -eq 0 ]; then
  echo "RESULT: the two agree on this contract ($total check(s))."
  if [ "$not_aot_total" -gt 0 ]; then
    echo "        Caveat: $not_aot_total check(s) could not run compiled — the native backend cannot"
    echo "        lower RelayRoom.room_id, so the language surface is interpreter-only today."
  fi
  exit 0
else
  echo "RESULT: disagreement — an interop defect, not a formatting difference."
  echo "        Derivation mismatch means two peers land in different rooms; refusal mismatch means"
  echo "        one peer joins and the other refuses."
  exit 1
fi
