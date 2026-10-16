# Release Bootstrap Checklist

> **Scope (2026-10-15).** This is the exit record for the root Tallow **workspace** (`~/Nixe`), not for
> this repository: it names workspace scripts and the workspace CI matrix, and it is retained here as
> the doctrine the product tree inherits. What this repository carries and verifies is
> `.github/workflows/ci.yml` (12 jobs) and `.github/workflows/tallow-production-ci-gates.yml`; see
> `MANIFEST.md` § "CI carried, and what was left behind".

> status: verified 2026-09-05 (C6 docs wave — Phase 1 Linux/CachyOS exit gates current).

Use this checklist as the Phase 1 release/bootstrap exit record for the root Tallow workspace. Active target: Linux/CachyOS from repo root `~/Nixe`. Windows VC++/PowerShell criteria are retained as legacy/non-target unless Windows support is explicitly requested.

## Phase 1 Linux/CachyOS Exit Gates

- [ ] `./target/debug/tallow doctor` passes with `passed=true` in `artifacts/doctor/tallow_doctor_report.json`.
- [ ] `python3 scripts/phase1_smoke_ladder.py` passes with every required rung recorded as `pass` in `artifacts/phase1/phase1_smoke_ladder_report.json`.
- [ ] Required PATH tools are available from the fresh shell: `cargo`, `rustc`, `git`, `node`, and `npm`.
- [ ] Tallow can report its selected browser path with `./target/debug/tallow browser path`.
- [ ] `cargo check --locked` passes from the workspace root.
- [ ] Targeted non-live browser/compiler tests pass through the smoke ladder.
- [ ] Artifact reports are retained for review under `artifacts/doctor/` and `artifacts/phase1/`.
- [ ] Evidence below is collected in the release/bootstrap handoff.

## Commands

Run from `~/Nixe`:

```bash
cargo build --locked --bin tallow
./target/debug/tallow doctor
python3 scripts/phase1_smoke_ladder.py
./target/debug/tallow --version
./target/debug/tallow version
./target/debug/tallow check examples/hello_simple.tl
./target/debug/tallow run examples/hello_simple.tl
./target/debug/tallow browser path
cargo check --locked
```

The smoke ladder already repeats the key Tallow and locked cargo probes when the environment is healthy. Keep the standalone command results in the handoff anyway so a reviewer can distinguish script health from direct operator checks.

## Windows VC++ Runtime Decision (deferred/non-target)

Only complete this section if Windows support is explicitly requested.

- Install the supported Microsoft VC++ runtime on every Windows runner and developer host that launches `.tallow-bin\tallow.exe`.
- Produce and release a static CRT Tallow binary so the executable does not depend on the missing VC++ runtime DLLs.

The current known launch failure is `-1073741515 (0xC0000135)`, which means Windows could not load a required runtime component. A passing doctor report must no longer show missing required DLLs such as `vcruntime140.dll`, `vcruntime140_1.dll`, `msvcp140.dll`, or `ucrtbase.dll` as blocking errors.

## Evidence To Collect

Include these items in the release/bootstrap handoff:

- Timestamp, machine name, Linux kernel/distro, and shell used for the run.
- The exact Tallow binary path, `--version` output, and binary SHA-256 from the doctor report.
- PATH probe output for `cargo`, `rustc`, `git`, `node`, and `npm`.
- `cargo check --locked` result from the root workspace.
- `tallow check examples/hello_simple.tl` and `tallow run examples/hello_simple.tl` results.
- `tallow browser path` output, plus browser version/path reported by the doctor.
- `artifacts/doctor/tallow_doctor_report.json`.
- `artifacts/phase1/phase1_smoke_ladder_report.json`.
- Any explicit waivers, each with owner, date, reason, and follow-up issue.

## Waiver Rules

Waivers should be rare. A waived Linux/CachyOS gate must include an owner, a concrete follow-up, and proof that the remaining Phase 1 work is not blocked by the waiver. Do not waive binary launch, doctor pass, smoke ladder pass, or browser path discovery for a Linux/CachyOS Phase 1 exit. Windows VC++/static CRT decisions are separate deferred/non-target work unless Windows support is requested.
