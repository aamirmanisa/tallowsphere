# Phase 1 Smoke Ladder

Status: Linux/CachyOS is the active Phase 1 target. Windows/PowerShell smoke evidence is retained as historical/non-target unless Windows support is explicitly requested.

`scripts/phase1_smoke_ladder.py` is a non-destructive Linux/CachyOS gate runner for the root Tallow workspace. It continues after failures, writes a machine-readable report, and exits non-zero when any required Phase 1 rung fails.

## Usage

Normal local run from the workspace root:

```bash
python3 scripts/phase1_smoke_ladder.py
```

Fresh-shell gate run used for Phase 1 evidence:

```bash
env -i HOME="$HOME" USER="$USER" PATH="/usr/local/sbin:/usr/local/bin:/usr/bin:/bin" SHELL="/bin/bash" TERM="${TERM:-dumb}" \
  bash --noprofile --norc -lc 'cd ~/Nixe && python3 scripts/phase1_smoke_ladder.py'
```

The script defaults to:

```text
tallow binary: target/debug/tallow
report path: artifacts/phase1/phase1_smoke_ladder_report.json
```

Options:

```bash
python3 scripts/phase1_smoke_ladder.py --tallow-binary ./target/debug/tallow
python3 scripts/phase1_smoke_ladder.py --report-path artifacts/phase1/custom_report.json
python3 scripts/phase1_smoke_ladder.py --skip-build
python3 scripts/phase1_smoke_ladder.py --skip-targeted-tests
```

## Required ladder rungs

The default ladder verifies:

- `uname -a`
- `cargo --version`
- `rustc --version`
- `git --version`
- advisory `node --version`
- advisory `npm --version`
- `cargo check --locked`
- `cargo build --locked --bin tallow`
- `target/debug/tallow` exists and is executable
- `cargo test --locked --test browser_codegen_integration codegen_emits_fetch_declaration -- --nocapture`
- `cargo test --locked --test browser_flow_runtime_integration -- --nocapture --test-threads=1`
- `target/debug/tallow --version`
- `target/debug/tallow version`
- `target/debug/tallow doctor`
- `target/debug/tallow check examples/hello_simple.tl`
- `target/debug/tallow run examples/hello_simple.tl`
- `target/debug/tallow browser path`

## Browser-live safety

The default ladder is non-live. It explicitly sets `TALLOW_RUN_BROWSER_LIVE_TESTS=0` for targeted browser cargo tests, even if the caller's shell exported the live-test flag. Browser launch proof is a separate explicit gate; this ladder verifies resolver/path behavior only.

## Report contract

The JSON report includes:

- schema/version metadata
- fresh-shell metadata, including PATH and platform details
- pass/warn/fail summary
- active blocker IDs for any failed or warning rungs
- per-rung command, exit code, duration, output, and blocker mapping

Relevant blockers:

- `BLK-002`: Linux/CachyOS toolchain/PATH checks.
- `BLK-004`: doctor/runtime launch/artifact checks.
- `BLK-005`: browser resolver/path checks.
- `BLK-006`: Phase 1 smoke ladder failure.
- `BLK-020`: Linux cargo check / targeted browser compiler-runtime regression.

## Legacy PowerShell ladder

`scripts/phase1_smoke_ladder.ps1` remains in the repository as a Windows-oriented historical helper. It is not the active Linux/CachyOS Phase 1 gate.
