#!/usr/bin/env bash
# B6.4.3 — replay-determinism CI job (byte-equality harness for event replay).
# Runs the integration target that pins replay byte-determinism and
# fingerprint stability (tests/replay_determinism.rs). Read-only for the repo.
set -u

# Repo-root detection from the script's own location — path-portable: works from
# any cwd, via an absolute or relative invocation, and through symlinks
# (BASH_SOURCE with a $0 fallback for non-bash shells).
SOURCE="${BASH_SOURCE[0]:-$0}"
while [ -L "$SOURCE" ]; do
  DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
  SOURCE="$(readlink "$SOURCE")"
  [ "$SOURCE" = "${SOURCE#/}" ] && SOURCE="$DIR/$SOURCE"
done
SCRIPT_DIR="$(cd -P "$(dirname "$SOURCE")" && pwd)"
cd "$SCRIPT_DIR/.." || exit 2
export PATH="$HOME/.cargo/bin:$PATH"

echo "== replay-determinism CI (upcasters) =="
cargo test --test replay_determinism
rc=$?
if [ "$rc" -eq 0 ]; then
  echo "replay-determinism: OK (exit 0)"
else
  echo "replay-determinism: FAILED (exit $rc)"
fi
exit "$rc"
