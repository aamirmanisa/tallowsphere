# Tallow Runtime Bootstrap

> status: verified 2026-09-05 (C6 docs wave — Linux/CachyOS Phase 1 bootstrap path current).

This guide is the Phase 1 bootstrap path for making the root Tallow workspace diagnosable before scraper/browser upgrade work continues.

Use [`release-bootstrap-checklist.md`](release-bootstrap-checklist.md) as the operator-facing Phase 1 exit record. This guide explains the bootstrap path; the checklist names the exact release gates and evidence to collect.

## Current Gate

Active target: Linux/CachyOS. Run the native doctor first:

```bash
cargo build --locked --bin tallow
./target/debug/tallow doctor
```

Then run the Linux/CachyOS smoke ladder:

```bash
python3 scripts/phase1_smoke_ladder.py
```

For the fresh-shell gate used as final evidence:

```bash
env -i HOME="$HOME" USER="$USER" PATH="/usr/local/sbin:/usr/local/bin:/usr/bin:/bin" SHELL="/bin/bash" TERM="${TERM:-dumb}" \
  bash --noprofile --norc -lc 'cd ~/Nixe && python3 scripts/phase1_smoke_ladder.py'
```

These commands are non-live by default for browser tests. They write reports under:

```text
artifacts/doctor/tallow_doctor_report.json
artifacts/phase1/phase1_smoke_ladder_report.json
```

Windows PowerShell doctor/smoke scripts are retained as legacy/non-target paths unless Windows support is explicitly requested.

## Current Known Failure

No active Linux/CachyOS Phase 1 runtime/toolchain/smoke failure is open. The accepted Linux gate is recorded in `docs/mega/phase1-linux-doctor-smoke-report.md` and the latest full smoke ladder reports `pass=17 warn=0 fail=0`.

Historical Windows binaries failed before CLI startup with:

```text
-1073741515 (0xC0000135)
```

That status means Windows could not load a required runtime component. Windows VC++ runtime work is deferred/non-target for the current Linux/CachyOS upgrade unless Windows support is explicitly requested.

The Windows installer now runs a non-destructive VC++ runtime preflight before it launches `tallow.exe version`. It checks for the runtime DLLs used by current binaries, including `vcruntime140.dll`, `vcruntime140_1.dll`, and `msvcp140.dll`, from the installed executable directory and standard Windows runtime locations. If those DLLs are missing, the installer explains that `0xC0000135` means Windows could not load a required DLL, skips the launch probe, and asks the user to install or repair the Microsoft Visual C++ Redistributable for Visual Studio 2015-2022 (x64). It does not install the redistributable automatically.

## Toolchain Expectations

For full Phase 1 verification, a normal development shell should have these commands available and executable:

```powershell
cargo --version
rustc --version
rustup --version
git --version
node --version
npm --version
```

`pnpm`, `cmake`, `cl`, `link`, and `lld` are useful for broader build/release work, but the first smoke gate should focus on launching Tallow and running `cargo check`.

Do not rely on Codex Desktop internal runtime paths as project setup. They can be versioned implementation details and may not include npm, pnpm, Python, Rust, Git, or MSVC tools.

## Windows Setup

Use a normal PowerShell or Developer PowerShell session with Rust, Git, Node.js, and npm on `PATH`. Repo PowerShell scripts should be launched with an explicit execution policy bypass:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\tallow_doctor.ps1
```

Windows release binaries that link the dynamic MSVC CRT require the Microsoft Visual C++ Redistributable to be installed on the target machine. If distributing to machines without that runtime, build a release variant that statically links the CRT instead of depending on `vcruntime140.dll` and related DLLs.

Browser checks should run after the CLI can start. Browser installation and cache location may vary by user profile, Tallow data directory, and Playwright/Patchright configuration.

## Linux Setup

Use a shell with Rust, Git, Node.js, and npm on `PATH`. Install the system packages needed by the chosen browser engine before expecting browser smoke tests to pass; headless Chromium-family browsers usually require distro graphics, font, sandbox, NSS, and GTK-related runtime libraries.

Run repo scripts through their checked-in shell or PowerShell entrypoints. If PowerShell scripts are used on Linux, invoke them through `pwsh` and keep any local execution-policy behavior explicit in the command or shell profile.

## macOS Setup

Use a shell with Rust, Git, Node.js, and npm on `PATH`. Xcode Command Line Tools should be installed so native crates and build scripts can find the compiler, linker, SDK, and Git integration expected by Cargo workflows.

Browser smoke tests should be run after the CLI starts and after browser runtime dependencies are available for the current user. Managed browser caches may live outside the repo and should not be assumed present on a fresh checkout.

## Browser Bootstrap

The doctor only inventories browser state. It should not install or download browsers.

Useful checks after the Linux binary starts:

```bash
./target/debug/tallow browser path
```

Legacy Windows examples, if Windows support is requested later:

```powershell
.\.tallow-bin\tallow.exe browser list
.\.tallow-bin\tallow.exe browser path
```

Managed browser installs live under Tallow's data directory at `data_dir/tallow/browsers`, not always under `~/.tallow/browsers`. `tallow browser path` may differ from the runtime launch resolver because the launch path can also consider Playwright/Patchright caches and config layering.

## Phase 1 Exit Criteria

Linux/CachyOS Phase 1 runtime/bootstrap work is complete when the fresh-shell smoke ladder succeeds with no active blockers:

```bash
env -i HOME="$HOME" USER="$USER" PATH="/usr/local/sbin:/usr/local/bin:/usr/bin:/bin" SHELL="/bin/bash" TERM="${TERM:-dumb}" \
  bash --noprofile --norc -lc 'cd ~/Nixe && python3 scripts/phase1_smoke_ladder.py'
```

The ladder covers:

```bash
cargo --version
rustc --version
git --version
node --version || true
npm --version || true
cargo check --locked
cargo build --locked --bin tallow
cargo test --locked --test browser_codegen_integration codegen_emits_fetch_declaration -- --nocapture
cargo test --locked --test browser_flow_runtime_integration -- --nocapture --test-threads=1
./target/debug/tallow --version
./target/debug/tallow version
./target/debug/tallow doctor
./target/debug/tallow check examples/hello_simple.tl
./target/debug/tallow run examples/hello_simple.tl
./target/debug/tallow browser path
```

Windows PowerShell/VC++ criteria are deferred/non-target unless Windows support is explicitly requested.
