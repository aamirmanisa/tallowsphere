#!/usr/bin/env bash
# Install the Tallow compiler.
#
#   ./install.sh                     # latest release for this machine into ~/.local
#   ./install.sh --prefix /usr/local # system-wide (run with sudo)
#   ./install.sh --from dist/tallow-linux-aarch64-1.1.5.tar.gz
#   ./install.sh --version 1.1.5
#
# Two files are installed, always into the same directory:
#   tallow        the compiler
#   libtallow.a   the runtime archive it links compiled programs against
# Losing the second one is not a visible error until a program calls a runtime
# symbol; the installer keeps them together and then proves the pair by
# compiling and running a program.
set -euo pipefail

VERSION="${TALLOW_VERSION:-}"
PREFIX="${PREFIX:-$HOME/.local}"
FROM=""
REPO="${TALLOW_REPO:-aamirmanisa/tallowsphere}"

usage() { sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

while [ $# -gt 0 ]; do
    case "$1" in
        --prefix)  PREFIX="$2"; shift 2 ;;
        --version) VERSION="${2#v}"; shift 2 ;;
        --from)    FROM="$2"; shift 2 ;;
        -h|--help) usage 0 ;;
        *) echo "unknown argument: $1" >&2; usage 1 ;;
    esac
done

# The default is "the latest published release", resolved at run time. Pinning a
# literal version here is how this script came to advertise "latest" while
# installing 1.1.1 three releases after it stopped being current — and after the
# tag it named had no assets at all.
if [ -z "$VERSION" ]; then
    _api="https://api.github.com/repos/$REPO/releases/latest"
    VERSION="$(curl -fsSL "$_api" 2>/dev/null \
        | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' \
        | head -n 1)"
    if [ -z "$VERSION" ]; then
        echo "cannot determine the latest release of $REPO (no network, or none published yet)" >&2
        echo "  pass --version <v> or --from <archive>" >&2
        exit 2
    fi
fi

case "$(uname -s)" in
    Linux)  os=linux ;;
    Darwin) os=macos ;;
    *) echo "unsupported OS $(uname -s); on Windows unpack the .zip and keep tallow.exe beside tallow.lib" >&2; exit 1 ;;
esac
case "$(uname -m)" in
    x86_64|amd64) arch=x86_64 ;;
    aarch64|arm64) arch=aarch64 ;;
    *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;;
esac
label="$os-$arch"
asset="tallow-$label-$VERSION.tar.gz"

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

if [ -n "$FROM" ]; then
    src="$FROM"
else
    base="${TALLOW_RELEASE_BASE:-https://github.com/$REPO/releases/download/v$VERSION}"
    echo "fetching $base/$asset"
    curl -fsSL --retry 3 -o "$tmp/$asset" "$base/$asset"
    if curl -fsSL --retry 3 -o "$tmp/$asset.sha256" "$base/$asset.sha256" 2>/dev/null; then
        (cd "$tmp" && sha256sum -c "$asset.sha256")
    else
        echo "warning: no checksum published for $asset — installing unverified bytes" >&2
    fi
    src="$tmp/$asset"
fi

[ -f "$src" ] || { echo "missing archive $src" >&2; exit 1; }
tar xzf "$src" -C "$tmp"
[ -x "$tmp/tallow" ] || { echo "archive has no tallow binary" >&2; exit 1; }
[ -f "$tmp/libtallow.a" ] || { echo "archive has no libtallow.a — the compiler cannot link programs" >&2; exit 1; }

mkdir -p "$PREFIX/bin"
install -m 0755 "$tmp/tallow" "$PREFIX/bin/tallow"
install -m 0644 "$tmp/libtallow.a" "$PREFIX/bin/libtallow.a"

echo "installed $("$PREFIX/bin/tallow" --version | head -1) into $PREFIX/bin"

# Prove the pair: a program that needs a runtime symbol, compiled and run.
cat > "$tmp/probe.tl" <<'TL'
fn find(hit: bool) -> i64? {
    if hit { return 7 }
    return nil
}
fn main() {
    print(find(true))
}
TL
out="$(cd "$PREFIX/bin" && ./tallow run --require-native "$tmp/probe.tl")"
[ "$out" = "7" ] || { echo "installed compiler failed its own probe (got '$out')" >&2; exit 1; }
echo "probe ok — native compile and run work"
case ":$PATH:" in
    *":$PREFIX/bin:"*) ;;
    *) echo "note: add $PREFIX/bin to PATH" ;;
esac
