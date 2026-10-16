# Tallow Doctor

Status: Linux/CachyOS native doctor is the active Phase 1 gate. Windows PowerShell doctor support is retained as a non-target legacy path unless Windows support is explicitly requested.

## Linux/CachyOS usage

From the root workspace:

```bash
cargo build --locked --bin tallow
./target/debug/tallow doctor
```

The doctor is non-destructive. It writes a machine-readable report to:

```text
artifacts/doctor/tallow_doctor_report.json
```

The report is written via a temporary same-directory JSON file and then renamed into place.

## Linux/CachyOS checks

`tallow doctor` currently records:

- platform/architecture
- required toolchain probes:
  - `cargo --version`
  - `rustc --version`
  - `git --version`
- advisory Node probes:
  - `node --version`
  - `npm --version`
- artifact directory writeability under `artifacts/doctor`
- current Tallow binary launch:
  - `tallow --version`
  - `tallow version`
  - `tallow browser path`
- browser resolver proof using the same Chrome/Chromium resolver as the CLI
- browser `--version` when a browser is found

Each command probe has a bounded timeout. Required probe failures make the doctor exit non-zero. Optional/advisory probe failures are warnings in the JSON report.

Relevant blocker mapping:

- `BLK-002`: required Linux/CachyOS toolchain/PATH checks fail.
- `BLK-004`: doctor/runtime launch/artifact checks fail.
- `BLK-005`: browser resolver or `tallow browser path` fails.

## Windows legacy usage

Windows remains deferred/non-target for current Phase 1 work. If Windows support is requested, use the existing PowerShell script:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\tallow_doctor.ps1
```

The PowerShell doctor reports Windows-specific runtime DLL and PowerShell policy details. Those findings are historical/non-target for the Linux/CachyOS 1000x upgrade gate.
