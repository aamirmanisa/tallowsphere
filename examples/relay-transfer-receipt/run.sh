#!/usr/bin/env bash
# Stage 3 / Slice 1 — relay transfer + .tl receipt verification (local-only demo).
#
# Flow:
#   1. payload  : N random bytes (default 4 MiB)
#   2. relay    : `tallow relay --port 6880` (TallowTransfer relay-v1 server)
#   3. receive  : `tallow receive --relay ... --code ...`  (waits for pairing)
#   4. send     : `tallow send --relay ... --code ... <payload>` (E2E-encrypted, BLAKE3)
#   5. verify   : `tallow run verify_receipt.tl -- <source> <received> <expected>`
#                 (independent receipt verification, in pure .tl)
#
# Usage:  ./run.sh [workdir]        (default workdir: /tmp/tallow-receipt-demo)
set -euo pipefail

TALLOW=${TALLOW:-"$(cd "$(dirname "$0")/../.." && pwd)/target/debug/tallow"}
WORK=${1:-/tmp/tallow-receipt-demo}
PORT=${PORT:-6880}
CODE=${CODE:-receipt-demo-pair}
SIZE=${SIZE:-4194304}

mkdir -p "$WORK/recv"
head -c "$SIZE" /dev/urandom > "$WORK/payload.bin"
EXPECTED=$("$TALLOW" hash "$WORK/payload.bin" | tail -1)
echo "payload : $WORK/payload.bin ($SIZE bytes)"
echo "blake3  : $EXPECTED"

"$TALLOW" relay --port "$PORT" -q & RELAY=$!
trap 'kill $RELAY 2>/dev/null || true' EXIT
sleep 1

"$TALLOW" receive --relay "127.0.0.1:$PORT" --code "$CODE" \
    --output "$WORK/recv" -y --overwrite --timeout 180 > "$WORK/receive.log" 2>&1 & RECV=$!
sleep 1
"$TALLOW" send --relay "127.0.0.1:$PORT" --code "$CODE" \
    "$WORK/payload.bin" > "$WORK/send.log" 2>&1

wait "$RECV"

echo "── verifier ──"
"$TALLOW" run "$(dirname "$0")/verify_receipt.tl" -- \
    "$WORK/payload.bin" "$WORK/recv/payload.bin" "$EXPECTED"
