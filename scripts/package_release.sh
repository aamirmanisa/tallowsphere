#!/usr/bin/env bash
# Package one built `tallow` binary into the archive layout the release ships.
#
#   scripts/package_release.sh <target-triple> <version> [--out DIR]
#
# Reads target/<triple>/release/tallow (tallow.exe for windows triples), writes
# <out>/tallow-<label>-<version>.<ext> plus a .sha256 sidecar. Deliberately has no
# build step: the same script runs in CI and by hand, so the local artifact and the
# published one cannot drift in layout.
set -euo pipefail

if [ $# -lt 2 ]; then
    echo "usage: $0 <target-triple> <version> [--out DIR]" >&2
    exit 2
fi

TARGET="$1"
VERSION="$2"
OUT="dist"
if [ "${3:-}" = "--out" ]; then OUT="${4:?--out needs a directory}"; fi
mkdir -p "$OUT"
OUT="$(cd "$OUT" && pwd)"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BIN_DIR="$ROOT/target/$TARGET/release"

case "$TARGET" in
    *-windows-*)
        BIN="$BIN_DIR/tallow.exe"
        # cargo names a staticlib after the crate on MSVC: tallow.lib, not
        # libtallow.a. The compiler's own search (find_runtime_lib_for_target)
        # looks for exactly this name beside the binary.
        RUNTIME_LIB="$BIN_DIR/tallow.lib"
        LABEL="windows-$(echo "$TARGET" | cut -d- -f1)"; EXT="zip" ;;
    *-apple-darwin) BIN="$BIN_DIR/tallow"; RUNTIME_LIB="$BIN_DIR/libtallow.a"; LABEL="macos-$(echo "$TARGET" | cut -d- -f1)"; EXT="tar.gz" ;;
    *-linux-musl) BIN="$BIN_DIR/tallow"; RUNTIME_LIB="$BIN_DIR/libtallow.a"; LABEL="linux-$(echo "$TARGET" | cut -d- -f1)"; EXT="tar.gz" ;;
    *-linux-gnu) BIN="$BIN_DIR/tallow"; RUNTIME_LIB="$BIN_DIR/libtallow.a"; LABEL="linux-$(echo "$TARGET" | cut -d- -f1)"; EXT="tar.gz" ;;
    *) echo "unsupported target: $TARGET" >&2; exit 2 ;;
esac

if [ ! -f "$BIN" ]; then
    echo "missing $BIN — build it first: cargo build --profile release --locked --target $TARGET --bin tallow" >&2
    exit 1
fi

# The compiler links compiled programs against this archive (src/codegen.rs,
# find_runtime_lib_for_target: "same directory as the tallow binary" is the
# first search step). Without it beside the binary, any program that calls a
# runtime symbol fails to link on a machine that has no build tree — measured
# 2026-10-20: the installed binary could not run `print(find(true))` because
# tallow_print_optional was unresolved.
RUNTIME_A="$RUNTIME_LIB"
if [ ! -f "$RUNTIME_A" ]; then
    echo "missing $RUNTIME_A — build it too: cargo build --profile release --locked --target $TARGET --lib" >&2
    exit 1
fi

mkdir -p "$OUT"
STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# ── Reproducibility ────────────────────────────────────────────────────────────
# The archive bytes must depend only on the inputs, not on when the packer ran.
# Without this, `cp` stamps the staged copies with "now", and tar/zip record that
# mtime in every member header — so two runs over the *same* binary produced
# different sha256 (measured 2026-10-31: two consecutive runs differed at byte 14).
# Pin the timestamp and normalise ownership/order so a rebuild of the same commit
# yields the same bytes.
EPOCH="${SOURCE_DATE_EPOCH:-}"
if [ -z "$EPOCH" ]; then
    # Fall back to the commit time (stable for a given tree), then to 0.
    EPOCH="$(git -C "$ROOT" log -1 --format=%ct 2>/dev/null || true)"
fi
[ -n "$EPOCH" ] || EPOCH=0
export TZ=UTC LC_ALL=C
umask 022

ARCHIVE="$OUT/tallow-$LABEL-$VERSION.$EXT"
rm -f "$ARCHIVE" "$ARCHIVE.sha256"

# Stamp every staged file at the fixed epoch, and hand tar the same value.
fix_time() { touch -d "@$EPOCH" "$1" 2>/dev/null || touch -t 197001010000.00 "$1"; }

# The licence travels with the artifact. MIT (LICENSE, 1.5 KB) requires the
# copyright and permission notice to be included in all copies or substantial
# portions; until 2026-10-31 the archives carried the binary and the runtime
# archive and nothing else, so every downloaded tarball was redistributed under
# terms it did not reproduce. NOTICE is shipped beside it because it states the
# repository's licence composition (this workspace is MIT; Tallow/ is AGPL).
cp "$ROOT/LICENSE" "$ROOT/NOTICE" "$STAGE/"
fix_time "$STAGE/LICENSE"; fix_time "$STAGE/NOTICE"

if [ "$EXT" = "zip" ]; then
    cp "$BIN" "$STAGE/tallow.exe"; fix_time "$STAGE/tallow.exe"
    cp "$RUNTIME_A" "$STAGE/tallow.lib"; fix_time "$STAGE/tallow.lib"
    # `zip` is not on the Windows runner's PATH (measured 2026-10-21: the
    # release failed with "zip: command not found" after a clean build). Git
    # Bash has cygpath but no zip; 7-Zip is installed on the GitHub Windows
    # images, and Compress-Archive is the last resort.
    if command -v zip >/dev/null 2>&1; then
        (cd "$STAGE" && zip -X -q -6 "$ARCHIVE" tallow.exe tallow.lib LICENSE NOTICE)
    elif [ -x "/c/Program Files/7-Zip/7z.exe" ]; then
        WARCHIVE="$(cygpath -w "$ARCHIVE")"
        # -mx=5, not -mx=9. Measured on this payload shape (46 MB exe + 241 MB
        # runtime archive, 285 MB total, 4 threads): mx=9 161 s / 89 MB,
        # mx=5 21 s / 91 MB, mx=1 5 s / 95 MB. Level 9 buys ~2% archive size for
        # ~8x the time, and on the 573 MB Windows payload that is the difference
        # between ~40 s and the 190-238 s the release jobs measured.
        (cd "$STAGE" && "/c/Program Files/7-Zip/7z.exe" a -tzip -mmt=4 -mx=5 "$WARCHIVE" tallow.exe tallow.lib LICENSE NOTICE >/dev/null)
    else
        WPATH="$(cygpath -w "$STAGE")\\tallow.exe"
        WLIB="$(cygpath -w "$STAGE")\\tallow.lib"
        WLIC="$(cygpath -w "$STAGE")\\LICENSE"
        WNOT="$(cygpath -w "$STAGE")\\NOTICE"
        WARCHIVE="$(cygpath -w "$ARCHIVE")"
        powershell -NoProfile -Command "Compress-Archive -Path '$WPATH','$WLIB','$WLIC','$WNOT' -DestinationPath '$WARCHIVE' -Force"
    fi
else
    cp "$BIN" "$STAGE/tallow"; fix_time "$STAGE/tallow"
    cp "$RUNTIME_A" "$STAGE/libtallow.a"; fix_time "$STAGE/libtallow.a"
    # Sorted members, zeroed owner/group, fixed mtime, gzip with -n (no name or
    # timestamp in the header). `tar czf` alone is NOT reproducible: it records
    # the staged files' mtimes, which `cp` sets to the moment of packing.
    #
    # bsdtar (macOS) supports none of --sort/--owner/--group and dies with
    # "Option --sort=name is not supported", which failed both macOS targets.
    # Prefer a GNU tar — Homebrew's gnu-tar installs it as `gtar` — and fall back
    # to bsdtar's own flags, saying plainly that the archive is then not
    # byte-reproducible instead of pretending the flags were applied.
    if tar --sort=name -cf /dev/null --files-from /dev/null 2>/dev/null; then
        TAR=tar
        TARFLAGS=(--sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH")
    elif command -v gtar >/dev/null 2>&1; then
        TAR=gtar
        TARFLAGS=(--sort=name --owner=0 --group=0 --numeric-owner --mtime="@$EPOCH")
    else
        echo "package_release: no GNU tar on this host — members are staged at a fixed" \
             "mtime, but the archive is NOT byte-reproducible here (bsdtar has no --sort)" >&2
        TAR=tar
        TARFLAGS=(--uid 0 --gid 0 --uname root --gname wheel)
    fi
    "$TAR" "${TARFLAGS[@]}" \
        -cf - -C "$STAGE" LICENSE NOTICE libtallow.a tallow | gzip -n -9 > "$ARCHIVE"
fi

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUT" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256")
else
    (cd "$OUT" && shasum -a 256 "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256")
fi

echo "$ARCHIVE"
cat "$ARCHIVE.sha256"
