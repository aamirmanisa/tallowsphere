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

ARCHIVE="$OUT/tallow-$LABEL-$VERSION.$EXT"
rm -f "$ARCHIVE" "$ARCHIVE.sha256"

if [ "$EXT" = "zip" ]; then
    cp "$BIN" "$STAGE/tallow.exe"
    cp "$RUNTIME_A" "$STAGE/tallow.lib"
    (cd "$STAGE" && zip -q -9 "$ARCHIVE" tallow.exe tallow.lib) || { echo "zip failed (install zip or pass a linux target)" >&2; exit 1; }
else
    cp "$BIN" "$STAGE/tallow"
    cp "$RUNTIME_A" "$STAGE/libtallow.a"
    tar czf "$ARCHIVE" -C "$STAGE" tallow libtallow.a
fi

if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUT" && sha256sum "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256")
else
    (cd "$OUT" && shasum -a 256 "$(basename "$ARCHIVE")" > "$(basename "$ARCHIVE").sha256")
fi

echo "$ARCHIVE"
cat "$ARCHIVE.sha256"
