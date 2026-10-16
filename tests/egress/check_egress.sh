#!/usr/bin/env bash
# Egress acceptance check — the leak test for the compiled (native) AND
# interpreted scrape paths.
#
# Requires: a live network, and Tor on 127.0.0.1:9050 (or set TALLOW_PROXY to
# another proxy). NOT part of `cargo test`: it talks to the network and asserts
# on live Tor exits, so it runs on demand.
#
#   bash tests/egress/check_egress.sh
#
# What it proves: the COMPILED fetch() and browser (CDP), and the INTERPRETED
# (tree-walking) fetch() and Browser API, egress somewhere other than the box's
# own IP *with no configuration at all* — Tor is the fail-closed default — and
# that TALLOW_ALLOW_DIRECT=1 is the one explicit way back to a direct
# connection. Before the fail-closed change both paths required TALLOW_TOR=1 to
# be exported, so a program that forgot leaked the box IP by omission.
#
# The interpreter arms close audit-03 §7 / ATK-1.2 (interpreter paths had no
# live leak test): `tallow run` is native-first, so a cross `--target wasm`
# skips the native block and makes the tree-walking interpreter execute the
# probe. A malformed TALLOW_PROXY must hard-refuse on both paths (N3) before
# any request — refusal marker in the output, no IP.
#
# G12–G14 (T-118b) close the last "missing" rows of the guarantee matrix
# (impl/T-118-guarantee-matrix.md): the interpreted stdlib `http.*` client
# (http_ip.tl), the interpreted-browser dual-stack/IPv6 target (cdp_ip64.tl),
# and the `--script` inline-deps path (script_ip.tl, whose `egress-dep`
# dependency is published into a scratch HOME registry inside this script).
#
# Note on rotation: a Tor exit can change between the reference probe and the
# tallow run, so the assertion is "differs from the box IP" (a leak is
# impossible to confuse with an exit); the observed values are printed so a
# human can see they are exits.
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
TALLOW="${TALLOW_BIN:-$REPO/target/debug/tallow}"
TOR_SOCKS_HOST="${TALLOW_TOR_SOCKS_HOST:-127.0.0.1:9050}"
PROXY="${TALLOW_PROXY:-}"

pass=0; fail=0; skipped=0
ok()   { printf '  \033[32mPASS\033[0m %s\n' "$1"; pass=$((pass+1)); }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
skip() { printf '  \033[33mSKIP\033[0m %s\n' "$1"; skipped=$((skipped+1)); }
note() { printf '       %s\n' "$1"; }

# An IP literal starts with a digit (v4 like v6); an error, null or refusal
# value starts with a letter or a quote. `ip_like` is therefore exactly "the
# output is an IP": every positive arm below demands `ip_like`, so a null or
# error value ("nil", an error page, a refusal) can never read as a pass;
# the refusal arms assert the opposite (`! ip_like`).
ip_like() { [ "$1" != "${1#[0-9]}" ]; }

# `why` phrases a probe value for the failure messages below: an empty reading
# is "no reading" — the engine produced nothing (killed, OOM, launch failure;
# see the 2026-09-14 egress-battery incident) — and must never be described as
# if it were an observed leak of the box IP.
why() { [ -n "$1" ] && printf '%s' "$1" || printf 'NO READING (the engine produced nothing — check kills/OOM/env; this is not a pass)'; }

[ -x "$TALLOW" ] || { echo "no tallow binary at $TALLOW (cargo build first)"; exit 2; }

echo "== reference IPs =="
BOX_IP="$(timeout 25 curl -s https://api.ipify.org || true)"
BOX_IP6="$(timeout 25 curl -s https://api64.ipify.org || true)"
EXIT_IP="$(timeout 40 curl -s --socks5-hostname "$TOR_SOCKS_HOST" https://api.ipify.org || true)"
echo "  box IP (direct)     : ${BOX_IP:-<none>}"
echo "  box IP (dual-stack) : ${BOX_IP6:-<none>}"
echo "  Tor exit (reference): ${EXIT_IP:-<none>}"
[ -n "$BOX_IP" ] || { echo "cannot reach api.ipify.org — aborting"; exit 2; }
# The box has a public IPv6 as well as an IPv4, and a dual-stack target is
# reached over IPv6 (both curl and Tallow prefer it). An IPv4-only assertion
# therefore cannot see an IPv6 leak — this is the arm that catches it.
if [ -z "$BOX_IP6" ] || [ "$BOX_IP6" = "$BOX_IP" ]; then
  note "box has no separate IPv6 identity (dual-stack probe: ${BOX_IP6:-<none>}) — IPv6 arm will be skipped"
  BOX_IP6=""
fi

# Run a probe file with a guaranteed-clean Tallow environment plus the caller's
# assignments (e.g. TALLOW_ALLOW_DIRECT=1). All three egress vars are cleared
# FIRST — `env` requires its options before the assignments (`env X=1 -u Y` just
# fails with `env: '-u': No such file or directory`, which silently made the
# opt-out arm return nothing), and a leak test must never inherit a proxy from
# the caller's shell.
run_probe() { # $1 = probe file; remaining args = env(1) assignments
  local probe="$1"; shift
  env -u TALLOW_TOR -u TALLOW_PROXY -u TALLOW_ALLOW_DIRECT "$@" \
    timeout 300 "$TALLOW" run "$probe" 2>&1 | grep -E "_ip=" | head -1 | sed 's/.*=//'
}
# Interpreter arms: `tallow run` is native-first, and only a cross target
# skips the native block deterministically (src/main.rs), so `--target wasm`
# makes the tree-walking interpreter execute the probe. Same env scrubbing and
# same `_ip=` extraction as run_probe.
run_probe_interp() { # $1 = probe file; remaining args = env(1) assignments
  local probe="$1"; shift
  env -u TALLOW_TOR -u TALLOW_PROXY -u TALLOW_ALLOW_DIRECT "$@" \
    timeout 300 "$TALLOW" run --target wasm "$probe" 2>&1 | grep -E "_ip=" | head -1 | sed 's/.*=//'
}

# Combined output of one probe run — the refusal arms need the marker text and
# the absence of an IP, so they cannot go through the `_ip=`-only extractor.
run_probe_raw() { # $1 = probe; $2 = extra run flags ("" or "--target wasm"); rest = env(1) assignments
  local probe="$1" flags="$2"; shift 2
  env -u TALLOW_TOR -u TALLOW_PROXY -u TALLOW_ALLOW_DIRECT "$@" \
    timeout 300 "$TALLOW" run $flags "$probe" 2>&1
}
# Like run_probe, with up to 3 attempts (Tor circuit-build stalls are
# retried after a short cooldown, a real IP is returned immediately.
run_probe_retry() { # same args as run_probe
  local v=""
  for _attempt in 1 2 3; do
    v="$(run_probe "$@")"
    [ -n "$v" ] && { printf '%s' "$v"; return; }
    sleep 5
  done
  printf '%s' "$v"
}

# ── L1: exit diversity — N distinct circuits per run (P1 W1-E2) ─────────────
#
# Every run mints its own SOCKS5 identity (src/runtime/fetch.rs; Tor's
# IsolateSOCKSAuth), so N runs must land on >= TALLOW_EGRESS_DIVERSITY_MIN
# distinct exits, none of them the box IP. Stickiness control: the SAME stream
# id twice must resolve to the SAME exit (one task = one exit, W1-E4). The
# exit set is recorded as JSON for the scoreboard / wave evidence.
run_diversity_section() {
  echo
  echo "== L1: exit diversity (N distinct circuits) =="
  local n="${TALLOW_EGRESS_DIVERSITY_N:-10}"
  local min="${TALLOW_EGRESS_DIVERSITY_MIN:-6}"
  local evid="${TALLOW_EGRESS_EVIDENCE_DIR:-$REPO/artifacts/egress-diversity}"
  local st="$(date +%s)"
  local exits=() ok_runs=0 i e
  for i in $(seq 1 "$n"); do
    e="$(run_probe_retry "$REPO/tests/egress/fetch_ip.tl" TALLOW_TOR_STREAM_ID="diversity-${st}-${i}")"
    if [ -n "$e" ] && ip_like "$e" && [ "$e" != "$BOX_IP" ]; then
      exits+=("$e"); ok_runs=$((ok_runs+1))
    else
      note "run $i produced $(why "$e") — counted as a failed run (not an exit)"
    fi
  done
  local distinct=0
  if [ "${#exits[@]}" -gt 0 ]; then
    distinct="$(printf '%s\n' "${exits[@]}" | sort -u | wc -l | tr -d ' ')"
  fi
  note "runs=$n ok=$ok_runs distinct_exits=$distinct (min $min)"
  note "exits: ${exits[*]:-<none>}"
  if [ "$ok_runs" -lt "$n" ]; then
    bad "L1 exit diversity: only $ok_runs/$n runs produced an exit — rerun when Tor is healthy (see the per-run notes)"
  elif [ "$distinct" -ge "$min" ]; then
    ok "L1 exit diversity: $distinct distinct exits across $n runs (>= $min), none the box IP"
  else
    bad "L1 exit diversity: only $distinct distinct exits across $n runs (< $min) — circuit isolation may be off (TALLOW_TOR_ISOLATE=0? shared credentials?)"
  fi
  # Stickiness control: same stream id → same circuit → same exit.
  local sid="sticky-${st}"
  local s1 s2
  s1="$(run_probe "$REPO/tests/egress/fetch_ip.tl" TALLOW_TOR_STREAM_ID="$sid")"
  s2="$(run_probe "$REPO/tests/egress/fetch_ip.tl" TALLOW_TOR_STREAM_ID="$sid")"
  note "sticky pair ($sid): ${s1:-<none>} / ${s2:-<none>}"
  if [ -n "$s1" ] && [ "$s1" = "$s2" ] && [ "$s1" != "$BOX_IP" ]; then
    ok "L1 stickiness: one stream id keeps one exit (${s1}) across runs"
  else
    bad "L1 stickiness: same stream id gave ${s1:-<none>} then ${s2:-<none>} — the per-run circuit binding is not sticky"
  fi
  # Record the exit set (JSON) for the scoreboard / evidence.
  mkdir -p "$evid"
  local json="$evid/egress-diversity-$(date -u +%Y%m%dT%H%M%SZ).json"
  EXITS_JSON="$(printf '%s\n' ${exits[@]+"${exits[@]}"})" DISTINCT="$distinct" MIN="$min" N="$n" \
    OKRUNS="$ok_runs" BOX="$BOX_IP" S1="${s1:-}" S2="${s2:-}" SID="$sid" \
    python3 - "$json" <<'PY'
import datetime, json, os, sys
exits = [line for line in os.environ.get("EXITS_JSON", "").splitlines() if line.strip()]
s1, s2 = os.environ.get("S1", ""), os.environ.get("S2", "")
doc = {
    "schema": "tallow.egress_diversity.v1",
    "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
    "runs": int(os.environ["N"]),
    "ok_runs": int(os.environ["OKRUNS"]),
    "distinct_exits": int(os.environ["DISTINCT"]),
    "min_required": int(os.environ["MIN"]),
    "box_ip": os.environ["BOX"],
    "exits": exits,
    "sticky": {
        "stream_id": os.environ["SID"],
        "first": s1,
        "second": s2,
        "held": bool(s1) and s1 == s2,
    },
}
with open(sys.argv[1], "w", encoding="utf-8") as fh:
    json.dump(doc, fh, indent=2, sort_keys=True)
    fh.write("\n")
print(f"       exit-set recorded: {sys.argv[1]}")
PY
}

# Section filter: `TALLOW_EGRESS_ONLY=div` runs ONLY the L1 exit-diversity
# section and exits (reference IPs above are computed first; helpers defined
# above). Used by the P1 wave evidence runner / the target scoreboard feed;
# unset runs every section in order.
if [ "${TALLOW_EGRESS_ONLY:-}" = "div" ]; then
  run_diversity_section
  echo
  echo "== summary (div only) =="
  echo "  passed=$pass failed=$fail skipped=$skipped"
  [ "$fail" -eq 0 ] || { echo "  EGRESS DIVERSITY FAILED"; exit 1; }
  echo "  exit diversity OK"
  exit 0
fi


echo
echo "== compiled fetch() =="
DIRECT="$(run_probe "$REPO/tests/egress/fetch_ip.tl" TALLOW_ALLOW_DIRECT=1)"
DEFAULT="$(run_probe "$REPO/tests/egress/fetch_ip.tl")"
note "TALLOW_ALLOW_DIRECT=1 -> ${DIRECT:-<none>}"
note "no env at all         -> ${DEFAULT:-<none>}"
if [ "$DIRECT" = "$BOX_IP" ]; then
  ok "opt-out control: TALLOW_ALLOW_DIRECT=1 really does go direct (${DIRECT})"
else
  bad "opt-out control: expected the box IP ${BOX_IP} with TALLOW_ALLOW_DIRECT=1, got ${DIRECT:-<none>}"
fi
if [ -n "$DEFAULT" ] && ip_like "$DEFAULT" && [ "$DEFAULT" != "$BOX_IP" ]; then
  ok "fail-closed default: with NO env at all the compiled fetch still rides Tor (${DEFAULT} != ${BOX_IP})"
else
  bad "LEAK: with no env at all the compiled fetch used ${DEFAULT:-<none>} (box ${BOX_IP}) — the default must be Tor"
fi

echo
echo "== compiled browser (CDP) =="
CDP_DEFAULT="$(run_probe "$REPO/tests/egress/cdp_ip.tl")"
CDP_TORED="$(run_probe "$REPO/tests/egress/cdp_ip.tl" TALLOW_TOR=1)"
note "no env at all -> ${CDP_DEFAULT:-<none>}"
note "TALLOW_TOR=1  -> ${CDP_TORED:-<none>}"
if [ -n "$CDP_DEFAULT" ] && ip_like "$CDP_DEFAULT" && [ "$CDP_DEFAULT" != "$BOX_IP" ]; then
  ok "fail-closed default: with NO env at all the compiled browser rides Tor (${CDP_DEFAULT} != ${BOX_IP})"
else
  bad "LEAK/ERROR: with no env at all the compiled browser gave $(why "$CDP_DEFAULT") (box ${BOX_IP}) — the default must be Tor"
fi
if [ -n "$CDP_TORED" ] && ip_like "$CDP_TORED" && [ "$CDP_TORED" != "$BOX_IP" ]; then
  ok "TALLOW_TOR=1 still routes the compiled browser off the box IP (${CDP_TORED} != ${BOX_IP})"
else
  bad "LEAK/ERROR: TALLOW_TOR=1 did not change the browser egress IP — CDP gave $(why "$CDP_TORED") (box ${BOX_IP})"
fi



echo
echo "== interpreter fetch() + Browser (tree-walking, --target wasm) =="
# audit-03 §7 / ATK-1.2: interpreter paths had no live leak test. Assertions
# mirror the compiled arms; the direct control must equal the box IP, the
# default must be a non-box value that is neither null nor an error.
I_DIRECT="$(run_probe_interp "$REPO/tests/egress/fetch_ip.tl" TALLOW_ALLOW_DIRECT=1)"
I_DEFAULT="$(run_probe_interp "$REPO/tests/egress/fetch_ip.tl")"
I_CDP="$(run_probe_interp "$REPO/tests/egress/cdp_ip.tl")"
note "interp fetch: TALLOW_ALLOW_DIRECT=1 -> ${I_DIRECT:-<none>}"
note "interp fetch: no env at all         -> ${I_DEFAULT:-<none>}"
note "interp browser: no env at all       -> ${I_CDP:-<none>}"
if [ "$I_DIRECT" = "$BOX_IP" ]; then
  ok "interp opt-out control: TALLOW_ALLOW_DIRECT=1 really does go direct (${I_DIRECT})"
else
  bad "interp opt-out control: expected the box IP ${BOX_IP}, got ${I_DIRECT:-<none>}"
fi
if [ -n "$I_DEFAULT" ] && ip_like "$I_DEFAULT" && [ "$I_DEFAULT" != "$BOX_IP" ]; then
  ok "interp fail-closed default: with NO env at all the interpreted fetch rides Tor (${I_DEFAULT} != ${BOX_IP})"
else
  bad "LEAK/ERROR: with no env at all the interpreted fetch gave $(why "$I_DEFAULT") (box ${BOX_IP}) — expected a non-box exit"
fi
if [ -n "$I_CDP" ] && ip_like "$I_CDP" && [ "$I_CDP" != "$BOX_IP" ]; then
  ok "interp browser fail-closed default: with NO env at all the interpreted browser rides Tor (${I_CDP} != ${BOX_IP})"
else
  bad "LEAK/ERROR: with no env at all the interpreted browser gave $(why "$I_CDP") (box ${BOX_IP}) — expected a non-box exit"
fi

echo
echo "== malformed TALLOW_PROXY — hard-refusal contract (N3, both paths) =="
# `::::nope` is the exact malformed URL the unit tests pin
# (unparseable_proxy_url_reports_a_hard_refusal /
# interpreter_fetch_refuses_on_bad_proxy). A refused run attempts NO request:
# the compiled FFI nulls the handle and parks the reason in tallow_last_error
# (its marker is therefore not printed — the anti-leak signal is the null
# handle), the interpreter surfaces the reason in the fetch result. Either way
# the value must not be an IP and the run must not have egressed.
CR_RAW="$(run_probe_raw "$REPO/tests/egress/fetch_ip.tl" "" TALLOW_PROXY='::::nope')"
IR_RAW="$(run_probe_raw "$REPO/tests/egress/fetch_ip.tl" "--target wasm" TALLOW_PROXY='::::nope')"
CR_VAL="$(printf '%s\n' "$CR_RAW" | grep -E "_ip=" | head -1 | sed 's/.*=//')"
IR_VAL="$(printf '%s\n' "$IR_RAW" | grep -E "_ip=" | head -1 | sed 's/.*=//')"
note "compiled bad proxy    -> ${CR_VAL:-<none>}"
note "interpreter bad proxy -> ${IR_VAL:-<none>}"
if [ -n "$CR_VAL" ] && ! ip_like "$CR_VAL"; then
  ok "compiled refusal: malformed TALLOW_PROXY emitted no IP (${CR_VAL})"
else
  bad "LEAK: compiled fetch produced an IP under a malformed TALLOW_PROXY (${CR_VAL:-<none>})"
fi
if [ -n "$IR_VAL" ] && ! ip_like "$IR_VAL"; then
  if printf '%s\n' "$IR_RAW" | grep -q "refusing to run unproxied"; then
    ok "interpreter refusal: 'refusing to run unproxied' marker present, no IP emitted"
  else
    bad "interpreter refusal: no IP but the 'refusing to run unproxied' marker is missing (${IR_VAL})"
  fi
else
  bad "LEAK: interpreted fetch produced an IP under a malformed TALLOW_PROXY (${IR_VAL:-<none>})"
fi

echo
if [ -n "$PROXY" ]; then
  echo "== TALLOW_PROXY=$PROXY (compiled fetch) =="
  PROXIED="$(run_probe "$REPO/tests/egress/fetch_ip.tl" TALLOW_PROXY="$PROXY")"
  note "TALLOW_PROXY -> ${PROXIED:-<none>}"
  if [ -n "$PROXIED" ] && ip_like "$PROXIED" && [ "$PROXIED" != "$BOX_IP" ]; then
    ok "explicit TALLOW_PROXY routes compiled fetch off the box IP"
  else
    bad "explicit TALLOW_PROXY leaked ${PROXIED:-<none>} (box ${BOX_IP})"
  fi
  echo
fi

echo
echo "== IPv6 / dual-stack target (compiled fetch) =="
if [ -n "$BOX_IP6" ]; then
  IP6_DEFAULT="$(run_probe "$REPO/tests/egress/fetch_ip64.tl")"
  note "no env at all -> ${IP6_DEFAULT:-<none>}   (box IPv6 is ${BOX_IP6})"
  if [ -n "$IP6_DEFAULT" ] && ip_like "$IP6_DEFAULT" && [ "$IP6_DEFAULT" != "$BOX_IP6" ] && [ "$IP6_DEFAULT" != "$BOX_IP" ]; then
    ok "fail-closed default: a dual-stack target is not reached over the box's IPv6 either (${IP6_DEFAULT})"
  else
    bad "LEAK/ERROR: the dual-stack target probe gave $(why "$IP6_DEFAULT") (box ${BOX_IP6}) — expected a non-box exit, not the box's own IPv6/IPv4"
  fi
  echo
else
  note "skipped: no separate IPv6 identity detected on this box"
  echo
fi

echo
echo "== G12: interpreted stdlib http.* (tree-walking, --target wasm) =="
# G12 (T-118b): the interpreted stdlib HTTP client (`http.get/post/...`, routed
# through runtime::egress_http) had no live probe. Same contract as fetch:
# default rides Tor, TALLOW_ALLOW_DIRECT=1 is the only explicit opt-out.
I_HTTP_DIRECT="$(run_probe_interp "$REPO/tests/egress/http_ip.tl" TALLOW_ALLOW_DIRECT=1)"
I_HTTP="$(run_probe_interp "$REPO/tests/egress/http_ip.tl")"
note "interp http.get: TALLOW_ALLOW_DIRECT=1 -> ${I_HTTP_DIRECT:-<none>}"
note "interp http.get: no env at all         -> ${I_HTTP:-<none>}"
if [ "$I_HTTP_DIRECT" = "$BOX_IP" ]; then
  ok "interp http.get opt-out control: TALLOW_ALLOW_DIRECT=1 really does go direct (${I_HTTP_DIRECT})"
else
  bad "interp http.get opt-out control: expected the box IP ${BOX_IP}, got ${I_HTTP_DIRECT:-<none>}"
fi
if [ -n "$I_HTTP" ] && ip_like "$I_HTTP" && [ "$I_HTTP" != "$BOX_IP" ]; then
  ok "interp http.get fail-closed default: with NO env at all the interpreted stdlib HTTP rides Tor (${I_HTTP} != ${BOX_IP})"
else
  bad "LEAK/ERROR: with no env at all interpreted http.get gave $(why "$I_HTTP") (box ${BOX_IP}) — expected a non-box exit"
fi

echo
echo "== G13: interpreted browser, IPv6 / dual-stack target (--target wasm) =="
# G13 (T-118b): the interpreter browser arm was IPv4-only; a dual-stack target
# reached over the box's own IPv6 would still leak. Mirrors the compiled IPv6
# arm and skips when the box has no separate IPv6 identity. (The probe prints
# cdp_ip64=, so this arm extracts with its own grep rather than `_ip=`.)
if [ -n "$BOX_IP6" ]; then
  I_CDP6_RAW="$(run_probe_raw "$REPO/tests/egress/cdp_ip64.tl" "--target wasm")"
  I_CDP6="$(printf '%s\n' "$I_CDP6_RAW" | grep -E "cdp_ip64=" | head -1 | sed 's/.*=//')"
  note "interp browser (api64) -> ${I_CDP6:-<none>}   (box IPv6 is ${BOX_IP6})"
  if [ -n "$I_CDP6" ] && ip_like "$I_CDP6" && [ "$I_CDP6" != "$BOX_IP6" ] && [ "$I_CDP6" != "$BOX_IP" ]; then
    ok "interp browser: a dual-stack target is not reached over the box's own IPv6 either (${I_CDP6})"
  else
    bad "LEAK/ERROR: interpreted browser gave $(why "$I_CDP6") (box ${BOX_IP6}) — expected a non-box exit, not the box's own IPv6/IPv4"
  fi
else
  skip "G13: no separate IPv6 identity detected on this box"
fi

echo
echo "== G14: --script inline-deps egress (PEP 723 dependency) =="
# G14 (T-118b): the --script path installs the script's inline dependency
# into a temp project before running (pkg/script_runner.rs::prepare_script).
# A scratch HOME gives that install a private package registry
# (~/.tallow/registry) and TMPDIR a private script-project cache, so the
# caller's environment is untouched: the trivial `egress-dep` package is
# published into the scratch registry first, and the run must prove the
# inline-deps path actually engaged (`Auto-installing: egress-dep`) before its
# egress value is asserted.
SCRIPT_SCRATCH="$(mktemp -d 2>/dev/null || true)"
G14_READY=0
if [ -n "$SCRIPT_SCRATCH" ] \
   && mkdir -p "$SCRIPT_SCRATCH/pkg" "$SCRIPT_SCRATCH/tmp" \
   && printf '[package]\nname = "egress-dep"\nversion = "0.1.0"\n' > "$SCRIPT_SCRATCH/pkg/tallow.toml" \
   && printf 'fn placeholder() {}\n' > "$SCRIPT_SCRATCH/pkg/lib.tl" \
   && ( cd "$SCRIPT_SCRATCH/pkg" && HOME="$SCRIPT_SCRATCH" timeout 60 "$TALLOW" publish >/dev/null 2>&1 ); then
  G14_READY=1
fi
if [ "$G14_READY" = 1 ]; then
  S_RAW="$(env -u TALLOW_TOR -u TALLOW_PROXY -u TALLOW_ALLOW_DIRECT \
    HOME="$SCRIPT_SCRATCH" TMPDIR="$SCRIPT_SCRATCH/tmp" \
    timeout 300 "$TALLOW" run --script "$REPO/tests/egress/script_ip.tl" 2>&1)"
  S_VAL="$(printf '%s\n' "$S_RAW" | grep -E "script_ip=" | head -1 | sed 's/.*=//')"
  note "--script inline-deps -> ${S_VAL:-<none>}"
  if ! printf '%s\n' "$S_RAW" | grep -q "Auto-installing: egress-dep"; then
    bad "G14: the inline dependency was not installed ('Auto-installing: egress-dep' marker missing) — the arm did not exercise the --script deps path"
  elif [ -n "$S_VAL" ] && ip_like "$S_VAL" && [ "$S_VAL" != "$BOX_IP" ]; then
    ok "--script inline-deps fail-closed default: fetch with an installed inline dep rides Tor (${S_VAL} != ${BOX_IP})"
  else
    bad "LEAK/ERROR: --script inline-deps fetch gave $(why "$S_VAL") (box ${BOX_IP}) — expected a non-box exit"
  fi
else
  skip "G14: scratch registry/package setup failed (mktemp or publish) — inline-deps path not exercised"
fi
[ -z "$SCRIPT_SCRATCH" ] || rm -rf "$SCRIPT_SCRATCH"

run_diversity_section

echo
echo "== summary =="
echo "  passed=$pass failed=$fail skipped=$skipped"
[ "$fail" -eq 0 ] || { echo "  EGRESS LEAK — do not treat scraping as anonymous"; exit 1; }
echo "  no leak observed: compiled and interpreted egress differ from the box IP when a proxy is configured"
