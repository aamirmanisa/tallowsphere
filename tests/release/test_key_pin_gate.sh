#!/usr/bin/env bash
# Gate test for scripts/check_release_key_pin.sh (F-18): the release signing
# key must equal the key pinned in BOTH installers.
#
# Usage: bash tests/release/test_key_pin_gate.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
S="$ROOT/scripts/check_release_key_pin.sh"
W="$(mktemp -d "${TMPDIR:-/tmp}/tallow-pin-gate.XXXXXX")"
trap 'rm -rf "$W"' EXIT
fails=0; total=0
check() {
    total=$((total+1))
    if [ "$2" = "$3" ]; then echo "PASS: $1 (rc=$3)"; else echo "FAIL: $1 expected rc=$2 got rc=$3"; fails=$((fails+1)); fi
}

pin="$(grep -oE 'TALLOW_PUBKEY:-[A-Za-z0-9+/_]+=*' "$ROOT/install.sh" | head -n1 | sed -E 's/^TALLOW_PUBKEY:-//')"
echo "parsed pin: [$pin]"
printf '%s' "$pin" | base64 -d > "$W/pin.raw"
echo "pin raw: $(wc -c < "$W/pin.raw") bytes | fingerprint sha256:$(sha256sum "$W/pin.raw" | cut -d' ' -f1)"
echo "expected fingerprint: a42d6f389d9615a8f9c69376f40e46ae9775bf354b3739bef23dbe8d3c7ec1ef"
echo

# 1. positive: raw 32-byte pub (CI form)
bash "$S" "$W/pin.raw" "$ROOT" > "$W/o1" 2>&1; check "positive-raw" 0 $?; cat "$W/o1"

# 2. positive: base64 text form
printf '%s\n' "$pin" > "$W/pub.b64"
bash "$S" "$W/pub.b64" "$ROOT" > "$W/o2" 2>&1; check "positive-base64" 0 $?

# 3. mismatch: first byte flipped
cp "$W/pin.raw" "$W/bad.raw"; printf '\xff' | dd of="$W/bad.raw" bs=1 seek=0 conv=notrunc 2>/dev/null
bash "$S" "$W/bad.raw" "$ROOT" > "$W/o3" 2>&1; rc=$?; check "mismatch-byteflip" 1 $rc
grep -q 'does NOT match' "$W/o3" && echo "  ↳ mismatch message present" || { echo "  ↳ MISSING mismatch message"; fails=$((fails+1)); }

# 4. wrong length (31 bytes)
head -c 31 "$W/pin.raw" > "$W/short.raw"
bash "$S" "$W/short.raw" "$ROOT" > "$W/o4" 2>&1; check "short-key" 1 $?

# 5. pin drift between installers
mkdir -p "$W/root1"
cp "$ROOT/install.sh" "$ROOT/install.ps1" "$W/root1/"
sed -i 's/else { "A+aERLPFs/else { "Z+aERLPFs/' "$W/root1/install.ps1"
bash "$S" "$W/pin.raw" "$W/root1" > "$W/o5" 2>&1; check "pin-drift" 1 $?
grep -q 'pins disagree' "$W/o5" && echo "  ↳ drift message present" || { echo "  ↳ MISSING drift message"; fails=$((fails+1)); }

# 6. placeholder sentinel in both installers
mkdir -p "$W/root2"
cp "$ROOT/install.sh" "$ROOT/install.ps1" "$W/root2/"
sed -i 's/A+aERLPFs+33G1fsvkRRtP6L1666gcbehEPsaRmMeU4=/REPLACE_WITH_BASE64_ED25519_PUBLIC_KEY/' "$W/root2/install.sh" "$W/root2/install.ps1"
bash "$S" "$W/pin.raw" "$W/root2" > "$W/o6" 2>&1; check "placeholder" 1 $?
grep -q 'placeholder' "$W/o6" && echo "  ↳ placeholder message present" || { echo "  ↳ MISSING placeholder message"; fails=$((fails+1)); }

# 7. missing pub file
bash "$S" "$W/nope.raw" "$ROOT" > "$W/o7" 2>&1; check "missing-pub" 1 $?

# 8. fingerprint cross-check (decoded pin matches the recorded operator fingerprint)
fp="$(sha256sum "$W/pin.raw" | cut -d' ' -f1)"
total=$((total+1))
if [ "$fp" = "a42d6f389d9615a8f9c69376f40e46ae9775bf354b3739bef23dbe8d3c7ec1ef" ]; then
    echo "PASS: fingerprint cross-check (decoded pin == a42d6f38…)"; else echo "FAIL: fingerprint mismatch: $fp"; fails=$((fails+1)); fi

echo
echo "TOTAL: $total cases, $fails failures"
[ "$fails" -eq 0 ]
