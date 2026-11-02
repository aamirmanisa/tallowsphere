#!/usr/bin/env bash
# Post-publication verification of a tallowsphere release.
#
#   scripts/verify_release_assets.sh [--lax-revision] [TAG] [PLATFORM]
#
#     TAG       release tag (default: the newest release the API returns)
#     PLATFORM  linux-aarch64 | linux-x86_64 | macos-aarch64 | macos-x86_64 |
#               windows-x86_64            (default: this host's platform)
#     --lax-revision
#               step 3c (the binary's revision must be the tag's own commit) is
#               a WARNING instead of a failure. Needed only for artifacts built
#               before the tag↔build path was unified — see step 3c below.
#
# What this is for
# ----------------
# A release is finished when the *published* artifact has been downloaded,
# hash-checked, installed and exercised — not when CI turns green. This script
# is that check, expressed as a command instead of an operator's memory:
#
#   1. the release exists, is not a draft, carries at least five assets, and
#      every shipped platform has an archive, a .sha256 sidecar and a .sig;
#   2. the chosen platform's archive downloads and its sha256 matches the
#      published sidecar (and the sidecar names the file it claims to describe);
#   3. the binary inside extracts and runs `--version`: the version equals the
#      tag, `git:` names a real revision (never `unknown`, never `dirty`), and
#      that revision is a prefix of the tag's own commit;
#   4. the asset count and every asset name with its byte size are reported.
#
# READ-ONLY. It performs GETs and writes only inside its own temp directory:
# it does not publish, edit, delete, re-tag or upload anything.
#
# Only curl (HTTP) and python3 (JSON, hashing, archive extraction) are used —
# deliberately no `gh`, no jq, no sha256sum, no tar/unzip, so the same script
# works on a bare runner where the release tooling is exactly what is missing.
#
# Exit status: 0 all checks passed; 1 a check failed; 2 bad usage; 3 the archive
# verified but the binary could not be executed on this host (foreign platform).
#
# Env overrides: TALLOW_RELEASE_REPO, TALLOW_GH_TOKEN_FILE, KEEP=1 (keep the
# temp dir, printing its path).

set -uo pipefail

REPO="${TALLOW_RELEASE_REPO:-aamirmanisa/tallowsphere}"
API="https://api.github.com/repos/$REPO"
TOKEN_FILE="${TALLOW_GH_TOKEN_FILE:-/root/.gh-token-tallow}"

PLATFORMS="linux-aarch64 linux-x86_64 macos-aarch64 macos-x86_64 windows-x86_64"

usage() {
    sed -n '2,40p' "$0" | sed -e 's/^# \{0,1\}//'
    exit 2
}

LAX_REVISION=0
POSITIONAL=()
for arg in "$@"; do
    case "$arg" in
        -h|--help)      usage ;;
        --lax-revision) LAX_REVISION=1 ;;
        -*)             printf 'unknown option: %s\n' "$arg" >&2; usage ;;
        *)              POSITIONAL+=("$arg") ;;
    esac
done
[ "${#POSITIONAL[@]}" -le 2 ] || usage

TAG="${POSITIONAL[0]:-}"
PLATFORM="${POSITIONAL[1]:-}"

# ── Reporting ────────────────────────────────────────────────────────────────
step() { printf '\n== %s\n' "$*"; }
ok()   { printf '  ok    %s\n' "$*"; }
info() { printf '        %s\n' "$*"; }
fail() { printf '  FAIL  %s\n' "$*" >&2; exit 1; }

host_platform() {
    local os arch
    os="$(uname -s)"; arch="$(uname -m)"
    case "$os:$arch" in
        Linux:aarch64|Linux:arm64)   echo linux-aarch64 ;;
        Linux:x86_64|Linux:amd64)    echo linux-x86_64 ;;
        Darwin:arm64)                echo macos-aarch64 ;;
        Darwin:x86_64)               echo macos-x86_64 ;;
        MINGW*:x86_64|MSYS*:x86_64)  echo windows-x86_64 ;;
        *) return 1 ;;
    esac
}

[ -n "$PLATFORM" ] || PLATFORM="$(host_platform)" || fail "cannot infer the host platform; pass one of: $PLATFORMS"
case " $PLATFORMS " in
    *" $PLATFORM "*) ;;
    *) fail "unknown platform '$PLATFORM'; expected one of: $PLATFORMS" ;;
esac

[ -r "$TOKEN_FILE" ] || fail "token file $TOKEN_FILE is not readable"
TOKEN="$(tr -d '\r\n' < "$TOKEN_FILE")"
[ -n "$TOKEN" ] || fail "token file $TOKEN_FILE is empty"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/verify-release.XXXXXX")" || fail "mktemp failed"
cleanup() {
    if [ "${KEEP:-0}" = 1 ]; then info "temp dir kept: $WORK"; else rm -rf "$WORK"; fi
}
trap cleanup EXIT

# api_get URL OUTFILE -> prints the HTTP status code
api_get() {
    curl -sS -L --retry 3 --retry-delay 2 -o "$2" -w '%{http_code}' \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Accept: application/vnd.github+json' \
        -H 'X-GitHub-Api-Version: 2022-11-28' \
        "$1"
}

printf 'verify_release_assets: repo=%s platform=%s tag=%s\n' \
    "$REPO" "$PLATFORM" "${TAG:-<newest>}"
printf 'host: %s %s\n' "$(uname -s)" "$(uname -m)"

# ── Resolve the tag ──────────────────────────────────────────────────────────
if [ -z "$TAG" ]; then
    step "resolve: newest release"
    code="$(api_get "$API/releases?per_page=1" "$WORK/releases.json")" \
        || fail "curl failed listing releases"
    [ "$code" = 200 ] || fail "listing releases returned HTTP $code"
    TAG="$(python3 - "$WORK/releases.json" <<'PY'
import json, sys
rel = json.load(open(sys.argv[1]))
print(rel[0]["tag_name"] if rel else "")
PY
)"
    [ -n "$TAG" ] || fail "the repository has no releases"
    ok "newest release: $TAG"
fi

case "$TAG" in
    v*) TAGVER="${TAG#v}" ;;
    *)  TAGVER="$TAG" ;;
esac

# ── 1. Release metadata ──────────────────────────────────────────────────────
step "1. release metadata"
code="$(api_get "$API/releases/tags/$TAG" "$WORK/release.json")" || fail "curl failed for releases/tags/$TAG"
case "$code" in
    200) ok "GET /releases/tags/$TAG -> 200" ;;
    404) hint=""
         case "$TAG" in
             v*) ;;
             *) hint=" (did you mean v$TAG?)" ;;
         esac
         fail "no release for tag $TAG (HTTP 404) — the tag may exist without a release, or the name is wrong$hint" ;;
    *)   fail "GET /releases/tags/$TAG -> HTTP $code" ;;
esac

# Publish the metadata as shell assignments; values are numbers/booleans from
# the API's own JSON, but they are read through a whitelist anyway.
meta="$(python3 - "$WORK/release.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
a = r.get("assets", [])
print("M_TAGNAME=%s" % r.get("tag_name", ""))
print("M_DRAFT=%s" % ("true" if r.get("draft") else "false"))
print("M_PRE=%s" % ("true" if r.get("prerelease") else "false"))
print("M_PUBLISHED=%s" % (r.get("published_at") or "null"))
print("M_COUNT=%d" % len(a))
PY
)"
while IFS='=' read -r k v; do
    case "$k" in
        M_TAGNAME|M_DRAFT|M_PRE|M_PUBLISHED) [ "$v" = "${v//[^A-Za-z0-9:._TZ\/-]/}" ] && printf -v "$k" '%s' "$v" ;;
        M_COUNT) case "$v" in ''|*[!0-9]*) fail "asset count is not a number: $v" ;; esac; printf -v "$k" '%s' "$v" ;;
    esac
done <<< "$meta"
: "${M_COUNT:?could not read asset count}"

ok "tag_name=$M_TAGNAME  published_at=$M_PUBLISHED  prerelease=$M_PRE"
[ "$M_TAGNAME" = "$TAG" ] || fail "release reports tag_name '$M_TAGNAME', asked for '$TAG'"
[ "$M_DRAFT" = false ] || fail "release $TAG is still a DRAFT — not published, so nothing here is a published artifact yet"
ok "release is published (not a draft)"
info "assets on the release: $M_COUNT"

[ "$M_COUNT" -ge 5 ] || fail "release $TAG has $M_COUNT asset(s); expected at least 5 (one archive per platform, plus sidecars and signatures)"
ok "asset count $M_COUNT >= 5"

# Every shipped platform must be complete: archive + .sha256 + .sig. A release
# that carries five archives but a sidecar for only four is exactly the state
# the release workflow's "Verify every archive has checksum and signature" step
# exists to prevent; check the published result, not the step.
completeness="$(python3 - "$WORK/release.json" "$PLATFORMS" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
names = {a["name"]: a for a in r.get("assets", [])}
platforms = sys.argv[2].split()
problems, found = [], []
for p in platforms:
    archives = [n for n in names if n.startswith("tallow-%s-" % p) and (n.endswith(".tar.gz") or n.endswith(".zip"))]
    if len(archives) != 1:
        problems.append("%s: expected exactly 1 archive, found %d %s" % (p, len(archives), sorted(archives)))
        continue
    a = archives[0]
    found.append(a)
    for suffix in (".sha256", ".sig"):
        if a + suffix not in names:
            problems.append("%s: missing %s" % (p, a + suffix))
for p in problems:
    print("PROBLEM " + p)
print("PLATFORMS_OK " + ",".join(found))
PY
)"
problems="$(printf '%s\n' "$completeness" | sed -n 's/^PROBLEM //p')"
if [ -n "$problems" ]; then
    printf '%s\n' "$problems" | while IFS= read -r p; do printf '  FAIL  %s\n' "$p" >&2; done
    fail "platform assets are incomplete (see above)"
fi
ok "all five platforms ship archive + .sha256 + .sig"

# ── 2. Download and hash-check the chosen platform's archive ─────────────────
step "2. download + sha256 ($PLATFORM)"
archive="$(python3 - "$WORK/release.json" "$PLATFORM" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
p = sys.argv[2]
for a in r.get("assets", []):
    n = a["name"]
    if n.startswith("tallow-%s-" % p) and (n.endswith(".tar.gz") or n.endswith(".zip")):
        print("%s\t%s\t%d" % (n, a["url"], a["size"]))
        break
PY
)"
[ -n "$archive" ] || fail "no archive for platform $PLATFORM on release $TAG"
ASSET_NAME="$(printf '%s' "$archive" | cut -f1)"
ASSET_URL="$(printf '%s' "$archive" | cut -f2)"
ASSET_SIZE="$(printf '%s' "$archive" | cut -f3)"
SIDECAR_NAME="$ASSET_NAME.sha256"

info "archive: $ASSET_NAME ($ASSET_SIZE bytes)"
info "sha256 sidecar: $SIDECAR_NAME"

# The sidecar is a small text asset: fetch it exactly like any other download.
sidecar_url="$(python3 - "$WORK/release.json" "$SIDECAR_NAME" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
for a in r.get("assets", []):
    if a["name"] == sys.argv[2]:
        print(a["url"]); break
PY
)"
[ -n "$sidecar_url" ] || fail "release $TAG has no $SIDECAR_NAME"

dl() { # dl URL DEST LABEL
    local code
    code="$(curl -sS -L --retry 3 --retry-delay 2 --fail -o "$2" -w '%{http_code}' \
        -H "Authorization: Bearer $TOKEN" \
        -H 'Accept: application/octet-stream' \
        "$1")"
    local rc=$?
    [ $rc -eq 0 ] || fail "download of $3 failed (curl exit $rc)"
    ok "downloaded $3 (HTTP $code)"
}
dl "$sidecar_url" "$WORK/$SIDECAR_NAME" "$SIDECAR_NAME"
dl "$ASSET_URL"   "$WORK/$ASSET_NAME"   "$ASSET_NAME"

verify="$(python3 - "$WORK/$ASSET_NAME" "$WORK/$SIDECAR_NAME" "$ASSET_NAME" <<'PY'
import hashlib, sys
path, sidecar, name = sys.argv[1], sys.argv[2], sys.argv[3]
text = open(sidecar, encoding="utf-8", errors="replace").read().strip()
parts = text.split()
if not parts:
    print("FAIL sidecar %s is empty" % sidecar); raise SystemExit(0)
want = parts[0].lower()
named = parts[1].lstrip("*") if len(parts) > 1 else ""
if len(want) != 64 or any(c not in "0123456789abcdef" for c in want):
    print("FAIL sidecar does not start with a sha256 hex digest: %r" % text[:80]); raise SystemExit(0)
if named and named != name:
    print("FAIL sidecar describes %r but the archive is %r" % (named, name)); raise SystemExit(0)
h = hashlib.sha256()
n = 0
with open(path, "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk); n += len(chunk)
got = h.hexdigest()
print("SIZE %d" % n)
print("WANT %s" % want)
print("GOT  %s" % got)
print("RESULT %s" % ("MATCH" if got == want else "MISMATCH"))
PY
)"
printf '%s\n' "$verify" | sed -n 's/^SIZE /  size /p;s/^WANT /  want /p;s/^GOT  /  got  /p'
case "$verify" in
    *"RESULT MATCH"*) ok "sha256 matches the published sidecar" ;;
    *) fail "sha256 does not match the published sidecar" ;;
esac
got_size="$(printf '%s\n' "$verify" | sed -n 's/^SIZE //p')"
[ "$got_size" = "$ASSET_SIZE" ] || fail "downloaded $got_size bytes, release metadata says $ASSET_SIZE"
ok "size matches release metadata ($ASSET_SIZE bytes)"

# ── 3. Extract the binary and exercise it ────────────────────────────────────
step "3. extract + --version"
case "$ASSET_NAME" in
    *.zip)      BINMEMBER="tallow.exe" ;;
    *.tar.gz)   BINMEMBER="tallow" ;;
    *)          fail "unexpected archive type: $ASSET_NAME" ;;
esac

# Extract one member by name through the archive reader rather than a shell
# utility: no tar/unzip dependency, and no path-traversal surface because
# nothing is unpacked but the single file written below.
extract="$(python3 - "$WORK/$ASSET_NAME" "$WORK/$BINMEMBER" "$BINMEMBER" <<'PY'
import os, sys, tarfile, zipfile
src, dest, member_name = sys.argv[1], sys.argv[2], sys.argv[3]
try:
    if src.endswith(".zip"):
        with zipfile.ZipFile(src) as z:
            members = [n for n in z.namelist() if n.lstrip("./") == member_name]
            if len(members) != 1:
                print("FAIL expected one %s in the zip, found %s" % (member_name, members)); raise SystemExit(0)
            with z.open(members[0]) as f:
                data = f.read()
    else:
        with tarfile.open(src, "r:gz") as t:
            members = [m for m in t.getmembers() if m.isfile() and m.name.lstrip("./") == member_name]
            if len(members) != 1:
                print("FAIL expected one %s in the tarball, found %s" % (member_name, [m.name for m in members])); raise SystemExit(0)
            f = t.extractfile(members[0])
            data = f.read()
    with open(dest, "wb") as out:
        out.write(data)
    os.chmod(dest, 0o755)
    print("OK %d" % len(data))
except Exception as exc:  # corrupt archive, wrong format, truncated download
    print("FAIL extraction failed: %s: %s" % (type(exc).__name__, exc))
PY
)"
case "$extract" in
    OK\ *) ok "extracted $BINMEMBER ($(printf '%s' "$extract" | cut -d' ' -f2) bytes)" ;;
    *)     fail "${extract#FAIL }" ;;
esac

HOST_PLATFORM="$(host_platform || true)"
can_execute=false
[ "$PLATFORM" = "${HOST_PLATFORM:-none}" ] && can_execute=true

if [ "$can_execute" = true ]; then
    version_out="$("$WORK/$BINMEMBER" --version 2>&1)" || fail "$BINMEMBER --version exited non-zero: $version_out"
    printf '%s\n' "$version_out" | sed 's/^/        | /'
    bver="$(printf '%s\n' "$version_out" | sed -n '1s/^tallow \([^ ]*\)$/\1/p')"
    bgit="$(printf '%s\n' "$version_out" | sed -n 's/^  git: *\(.*\)$/\1/p')"
    [ -n "$bver" ] || fail "could not parse a version from the first --version line"
    [ -n "$bgit" ] || fail "the --version output has no 'git:' line"
else
    # A foreign-architecture binary cannot execute here (cross-built aarch64 ELF
    # or a PE/COFF .exe, or anything meant for another OS). The version string is
    # a compile-time literal, so its presence is a real — if weaker — check. The
    # build stamp is *also* a literal, but a 10-hex regex over a Mach-O or PE
    # image matches random data far too often to be evidence: a candidate list
    # containing "0000000000" is noise, not a stamp. So this path reports only
    # what it actually proved, and refuses to call the verification complete.
    info "platform $PLATFORM cannot execute on host ${HOST_PLATFORM:-unknown} — structural check only"
    verpresent="$(python3 - "$WORK/$BINMEMBER" "$TAGVER" <<'PY'
import sys
data = open(sys.argv[1], "rb").read()
print("yes" if sys.argv[2].encode() in data else "no")
PY
)"
    if [ "$verpresent" = yes ]; then
        ok "the version string '$TAGVER' is present in the $PLATFORM binary"
    else
        info "the version string '$TAGVER' was not found in the $PLATFORM binary"
    fi
    bver=""
    bgit=""
    printf '  FAIL  %s\n' "step 3 cannot be completed here: a $PLATFORM binary will not execute on ${HOST_PLATFORM:-this host}" >&2
    printf '        run this script on a %s machine, or pass %s to verify the host artifact\n' "$PLATFORM" "${HOST_PLATFORM:-<host platform>}" >&2
    printf '\nUNVERIFIED: %s @ %s — archive hash checked, but the binary was not exercised\n' "$REPO" "$TAG" >&2
    exit 3
fi

step "3a. version equals the tag"
case "$bver" in
    "$TAGVER"|"$TAGVER.0") ok "binary version $bver == tag $TAG" ;;
    *) fail "binary version '$bver' does not equal tag version '$TAGVER'" ;;
esac

step "3b. git: names a real revision"
case "$bgit" in
    ""|unknown*) fail "git: line is '$bgit' — the binary carries no build stamp" ;;
    *dirty*)     fail "git: line is '$bgit' — the artifact was built from a dirty tree" ;;
esac
case "$bgit" in
    *[!0-9a-f]*|"") fail "git: line '$bgit' is not a hex revision id" ;;
esac
[ "${#bgit}" -ge 7 ] || fail "git: line '$bgit' is too short to be a revision id"
ok "git: $bgit (clean, ${#bgit} hex chars)"

# The revision must be the tag's own commit, not merely some commit: an
# artifact built from a neighbouring tree is the failure this catches.
step "3c. git: is the tag's commit"
code="$(api_get "$API/git/ref/tags/$TAG" "$WORK/ref.json")" || fail "curl failed for git/ref/tags/$TAG"
[ "$code" = 200 ] || fail "GET /git/ref/tags/$TAG -> HTTP $code (cannot resolve the tag's commit)"
refinfo="$(python3 - "$WORK/ref.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
o = r.get("object", {})
print("%s %s" % (o.get("type", ""), o.get("sha", "")), file=sys.stdout)
PY
)"
objtype="${refinfo%% *}"; objsha="${refinfo##* }"
if [ "$objtype" = tag ]; then
    code="$(api_get "$API/git/tags/$objsha" "$WORK/tagobj.json")" || fail "curl failed for git/tags/$objsha"
    [ "$code" = 200 ] || fail "GET /git/tags/$objsha -> HTTP $code"
    commit="$(python3 - "$WORK/tagobj.json" <<'PY'
import json, sys
print(json.load(open(sys.argv[1])).get("object", {}).get("sha", ""))
PY
)"
    info "annotated tag object $objsha -> commit $commit"
else
    commit="$objsha"
    info "lightweight tag -> commit $commit"
fi
[ -n "$commit" ] || fail "could not resolve a commit for tag $TAG"
case "$commit" in
    "$bgit"*) ok "binary revision $bgit is a prefix of tag commit $commit" ;;
    *)
        # Why this is fatal by default: the current Release workflow builds from
        # `actions/checkout` of the tag, so the stamp `build.rs` burns in is the
        # tag's own commit. An artifact whose stamp is a different commit was not
        # built from the code the tag names, and that is the provenance question
        # a post-publication check exists to answer.
        #
        # Why the escape hatch exists: artifacts cut before the release path was
        # unified were built elsewhere (a filtered tree, a rewritten history), so
        # their stamp legitimately points at a commit that no longer exists here.
        # Measured on v1.5.8: the binary says 6aa9fcfb14 while the tag resolves
        # to 3f11dc06 and 6aa9fcf is unreachable from any branch. Merging that
        # into "pass" would hide it; refusing to check anything else would make
        # the script useless on a known-published release. So it is a warning
        # only when asked for explicitly.
        if [ "$LAX_REVISION" = 1 ]; then
            printf '  WARN  binary revision %s is NOT the tag commit %s (--lax-revision: not fatal)\n' "$bgit" "$commit"
            info "the artifact was built from a different commit than $TAG names"
            WARNINGS=$(( ${WARNINGS:-0} + 1 ))
        else
            fail "binary revision '$bgit' is NOT the tag's commit ($commit) — the artifact was not built from $TAG (pass --lax-revision to downgrade this to a warning)"
        fi
        ;;
esac

# ── 4. Asset inventory ──────────────────────────────────────────────────────
step "4. asset inventory ($REPO @ $TAG)"
python3 - "$WORK/release.json" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
assets = sorted(r.get("assets", []), key=lambda a: a["name"])
total = 0
print("  %12s  %s" % ("bytes", "asset"))
for a in assets:
    total += a["size"]
    print("  %12d  %s" % (a["size"], a["name"]))
print("  %12d  %s asset(s)" % (total, len(assets)))
PY
ok "reported $M_COUNT asset(s)"

if [ "${WARNINGS:-0}" -gt 0 ]; then
    printf '\nPASS with %d warning(s): %s @ %s — archive verified end-to-end on %s\n' \
        "$WARNINGS" "$REPO" "$TAG" "$PLATFORM"
else
    printf '\nPASS: %s @ %s — archive verified end-to-end on %s\n' "$REPO" "$TAG" "$PLATFORM"
fi
