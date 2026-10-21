# Platform parity — what actually builds and runs where

**Updated:** 2026-10-21 · **Evidence:** CI runs on `windows-latest`, `macos-latest`,
`ubuntu-latest`, plus local `cargo check`/`cargo test` on the aarch64 box.

## Status

| Surface | Linux | macOS | Windows |
|---|---|---|---|
| `cargo check --workspace --all-targets` | pass | pass | pass |
| `cargo test --lib` | 9,145 passed / 0 failed | 9,140 passed / 0 failed | 9,108 passed / 0 failed |
| Native plane (clang link) | pass | pass | not supported (`blst`/BoringSSL C deps) |
| Firefox/Camoufox Juggler transport | yes | yes | **refuses at launch** — fd 3/4 pipe passing is Unix-only; Chromium/CDP is the supported backend |
| seccomp-BPF + Landlock sandbox | yes | refuses (`Err`) | refuses (`Err`) |

## What was broken, and why it was invisible

The crate had never been compiled off Linux. Two jobs in CI (`Test (Windows)`,
`Test (macOS)`) were permanently red, and the failure set never changed between
runs, so it read as chronic noise rather than as a defect.

Windows: 41 compile errors, all `std::os::unix` / `libc` uses outside any `cfg`
gate — file locking via `flock`, the credential prompt via `termios`, a 0600
assertion, `pre_exec`-based sandbox installs, and the Juggler pipe launch.

macOS: 4 compile errors. `RlimitResource` was keyed on `not(target_env = "musl")`,
which selects glibc's `__rlimit_resource_t` on Apple targets as well; and
`sandbox_pass` guarded a call to a Linux-only function with `cfg!()`, which is a
boolean, not a compile-time remover.

## The one class of bug that took the longest

Every failure on both non-Linux platforms, from 37 on Windows and 5 on macOS
down to zero, came from a single mechanism: a listener set non-blocking so its
accept loop can poll, whose **accepted** socket inherits that non-blocking state
on Windows and macOS (it does not on Linux). The first read then returns
`WouldBlock`, the server treats it as a closed client, drops the connection
unread, and the peer reports `EINVAL` (macOS) or `WSAECONNABORTED` / 10053
(Windows).

It appeared in three shapes:

- two hand-rolled mock servers in `browser::crawl_pipeline` (7 Windows tests,
  2 macOS tests) — fixed by `set_nonblocking(false)` on the accepted socket;
- `browser::observability::serve_metrics`, which is SHIPPING code: a macOS
  Prometheus scrape got a zero-byte response — fixed the same way;
- earlier, `sluice`'s `File::try_lock` on Windows, where `LockFileEx` is
  mandatory rather than advisory, so locking the log file blocked every reader
  (fixed by locking a `<log>.lock` sidecar).

`browser::socks_shim` and `stdlib net.accept` already forced accepted sockets
back to blocking; that is why the SOCKS shim and user-level TCP never showed the
symptom.

## Final state

CI run 39649906928 on `22a7020`: **17 of 17 jobs green** — Check, Clippy,
Security Audit, Dependency Check, SBOM, SBOM drift, CBOM drift, Canonical pins,
Claims ledger, Wire conformance, Zero-trust conformance, Parity, Contract and
CLI suites, Perf regression gate, Test (Linux), Test (macOS), Test (Windows).

Tests by platform: Linux 9,145 / macOS 9,140 / Windows 9,108, zero failures.
The 33 ignored tests are the same set on every platform: mesh-only and
privileged-environment cases.
