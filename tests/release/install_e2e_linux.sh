#!/usr/bin/env bash
# End-to-end tests for install.sh against a LOCAL fixture release (no GitHub).
#
# Runs the real installer (POSIX `sh`) over loopback HTTP with a throwaway
# signing key, asserting both the happy path and the fail-closed refusals:
#
#   C1  env-mode positive: full resolve -> download -> sha256 -> Ed25519 ->
#       extract -> run; the pin is written to a fresh key file; override warned
#   C2  env-mode with a pre-existing CORRECT key file: trusted, no fallback
#   C3  env-mode with a planted WRONG key file: override wins, warned loudly,
#       file left untouched
#   C4  pin-mode with a planted WRONG key file: REFUSED before any network I/O
#   C5  pin-mode + TALLOW_ALLOW_KEY_OVERRIDE=1: proceeds past the key stage,
#       then fails at signature verification (proves the override path)
#   C6  placeholder pin: refuses with "no release public key configured"
#   C7  wrong-key signature: '"signature INVALID" refusal
#   C8  tampered archive: "checksum MISMATCH" refusal
#
# Usage: bash tests/release/install_e2e_linux.sh   (from the repo root or not)
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
PY="${PYTHON:-python3}"
PORT="${PORT:-8899}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/tallow-install-e2e.XXXXXX")"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); echo "PASS: $1"; }
bad() { FAIL=$((FAIL+1)); echo "FAIL: $1"; }
cleanup() {
    [ -n "${SRV_PID:-}" ] && kill "$SRV_PID" 2>/dev/null
    rm -rf "$WORK"
}
trap cleanup EXIT

mkdir -p "$WORK/keys"

# ── fixture + local release server ───────────────────────────────────────
"$PY" "$ROOT/tests/release/make_fixture.py" --out "$WORK/served" --platform linux --port "$PORT" > "$WORK/fixture.json" \
    || { echo "fixture generation failed"; exit 1; }
ARCHIVE="$("$PY" -c "import json;print(json.load(open('$WORK/fixture.json'))['archive'])")"
PUB="$(cat "$WORK/served/fixture_pub.b64")"
API="http://127.0.0.1:$PORT/latest.json"
INSTALL_SH="$ROOT/install.sh"

"$PY" -m http.server "$PORT" --directory "$WORK/served" > "$WORK/httpd.log" 2>&1 &
SRV_PID=$!
for _ in 1 2 3 4 5 6 7 8 9 10; do
    if command -v curl >/dev/null 2>&1 && curl -s -o /dev/null "http://127.0.0.1:$PORT/latest.json"; then break; fi
    sleep 0.5
done
hits() { grep -c 'GET ' "$WORK/httpd.log" 2>/dev/null || true; }

run_install() { # NAME KEYFILE LOG [VAR=VAL ...]
    local name="$1" keyfile="$2" log="$3"; shift 3
    ( export TALLOW_INSTALL_DIR="$WORK/inst-$name" TALLOW_KEY_FILE="$keyfile" \
             TALLOW_RELEASE_API_URL="$API" "$@"
      sh "$INSTALL_SH" ) > "$log" 2>&1
    return $?
}

echo "fixture: $ARCHIVE  |  pub: $PUB"
echo

# ── C1: env-mode positive ────────────────────────────────────────────────
K1="$WORK/keys/c1.pub"
run_install c1 "$K1" "$WORK/c1.log" "TALLOW_PUBKEY=$PUB"; rc=$?
[ "$rc" -eq 0 ]                     && ok "C1 rc=0"              || bad "C1 rc=$rc"
grep -q 'override in effect' "$WORK/c1.log" && ok "C1 override warning shown" || bad "C1 override warning missing"
grep -q 'Pinned release key written' "$WORK/c1.log" && ok "C1 pin written to key file" || bad "C1 pin-write message missing"
[ -f "$K1" ] && cmp -s "$K1" <(printf '%s' "$PUB" | base64 -d) && ok "C1 key file content == fixture key" || bad "C1 key file wrong"
[ -x "$WORK/inst-c1/tallow" ]       && ok "C1 binary installed"  || bad "C1 binary missing"
grep -q 'tallow 1.0.0-fixture' "$WORK/c1.log" && ok "C1 installed binary ran (version)" || bad "C1 version output missing"
grep -q 'checksum: OK' "$WORK/c1.log" && ok "C1 checksum verified" || bad "C1 checksum check missing"
grep -q 'signature: VALID' "$WORK/c1.log" && ok "C1 signature verified" || bad "C1 signature check missing"

# ── C2: pre-existing correct key file, no override fallback ──────────────
K2="$WORK/keys/c2.pub"
printf '%s' "$PUB" | base64 -d > "$K2"
run_install c2 "$K2" "$WORK/c2.log" "TALLOW_PUBKEY=$PUB"; rc=$?
[ "$rc" -eq 0 ] && ok "C2 rc=0 (correct file trusted)" || bad "C2 rc=$rc"
grep -q 'differs from the TALLOW_PUBKEY override' "$WORK/c2.log" && bad "C2 unexpected override-fallback warning" || ok "C2 no fallback warning"

# ── C3: planted wrong key file + env override -> override wins ───────────
K3="$WORK/keys/c3.pub"
head -c 32 /dev/urandom > "$K3"
cp "$K3" "$WORK/keys/c3.orig"
run_install c3 "$K3" "$WORK/c3.log" "TALLOW_PUBKEY=$PUB"; rc=$?
[ "$rc" -eq 0 ] && ok "C3 rc=0 (override wins over planted file)" || bad "C3 rc=$rc"
grep -q 'differs from the TALLOW_PUBKEY override' "$WORK/c3.log" && ok "C3 override-divergence warning shown" || bad "C3 warning missing"
cmp -s "$K3" "$WORK/keys/c3.orig" && ok "C3 planted file left untouched" || bad "C3 file was modified"

# ── C4: pin-mode, planted wrong file -> refused before any network ───────
K4="$WORK/keys/c4.pub"
head -c 32 /dev/urandom > "$K4"
h0="$(hits)"
run_install c4 "$K4" "$WORK/c4.log"; rc=$?
h1="$(hits)"
[ "$rc" -ne 0 ] && ok "C4 refused (rc=$rc)" || bad "C4 unexpectedly succeeded"
grep -q 'does not match the pinned release key' "$WORK/c4.log" && ok "C4 refusal message" || bad "C4 message missing"
[ "$h1" = "$h0" ] && ok "C4 zero network requests (fail-closed before download)" || bad "C4 reached the network (hits $h0 -> $h1)"

# ── C5: pin-mode + TALLOW_ALLOW_KEY_OVERRIDE=1 -> past key stage, sig fail
h0="$(hits)"
run_install c5 "$K4" "$WORK/c5.log" "TALLOW_ALLOW_KEY_OVERRIDE=1"; rc=$?
h1="$(hits)"
[ "$rc" -ne 0 ] && ok "C5 refused at signature (rc=$rc)" || bad "C5 unexpectedly succeeded"
grep -q 'using the local key (TALLOW_ALLOW_KEY_OVERRIDE=1)' "$WORK/c5.log" && ok "C5 override warning" || bad "C5 warning missing"
grep -q 'signature INVALID' "$WORK/c5.log" && ok "C5 failed at signature (as designed)" || bad "C5 did not reach signature check"
[ "$h1" != "$h0" ] && ok "C5 proceeded past the key stage" || bad "C5 still blocked at key stage"

# ── C6: placeholder pin -> refuse, offline ───────────────────────────────
sed 's/A+aERLPFs+33G1fsvkRRtP6L1666gcbehEPsaRmMeU4=/REPLACE_WITH_BASE64_ED25519_PUBLIC_KEY/' \
    "$INSTALL_SH" > "$WORK/install-placeholder.sh"
K6="$WORK/keys/c6.pub"
( export TALLOW_INSTALL_DIR="$WORK/inst-c6" TALLOW_KEY_FILE="$K6" TALLOW_RELEASE_API_URL="$API"
  sh "$WORK/install-placeholder.sh" ) > "$WORK/c6.log" 2>&1; rc=$?
[ "$rc" -ne 0 ] && ok "C6 placeholder refused (rc=$rc)" || bad "C6 unexpectedly succeeded"
grep -q 'no release public key configured' "$WORK/c6.log" && ok "C6 placeholder message" || bad "C6 message missing"

# ── C7: signature from a different key -> INVALID ────────────────────────
altkey="$WORK/keys/alt.pem"
openssl genpkey -algorithm ED25519 -out "$altkey" 2>/dev/null
hexd="$(cut -d ' ' -f1 < "$WORK/served/$ARCHIVE.sha256")"
printf '%s' "$hexd" > "$WORK/keys/alt.msg"
openssl pkeyutl -sign -inkey "$altkey" -rawin -in "$WORK/keys/alt.msg" -out "$WORK/served/$ARCHIVE.tallow.sig" 2>/dev/null
K7="$WORK/keys/c7.pub"
run_install c7 "$K7" "$WORK/c7.log" "TALLOW_PUBKEY=$PUB"; rc=$?
[ "$rc" -ne 0 ] && ok "C7 wrong-key signature refused (rc=$rc)" || bad "C7 unexpectedly succeeded"
grep -q 'signature INVALID' "$WORK/c7.log" && ok "C7 INVALID message" || bad "C7 message missing"

# ── C8: tampered archive -> checksum MISMATCH (runs last; corrupts fixture)
printf '\x00' >> "$WORK/served/$ARCHIVE"
K8="$WORK/keys/c8.pub"
run_install c8 "$K8" "$WORK/c8.log" "TALLOW_PUBKEY=$PUB"; rc=$?
[ "$rc" -ne 0 ] && ok "C8 tamper refused (rc=$rc)" || bad "C8 unexpectedly succeeded"
grep -q 'checksum MISMATCH' "$WORK/c8.log" && ok "C8 mismatch message" || bad "C8 message missing"

echo
echo "TOTAL: $((PASS+FAIL)) checks, $FAIL failures"
[ "$FAIL" -eq 0 ]
