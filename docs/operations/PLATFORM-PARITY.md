# Platform parity — what actually builds and runs where

**Updated:** 2026-10-21 · **Evidence:** CI runs on `windows-latest`, `macos-latest`,
`ubuntu-latest`, plus local `cargo check`/`cargo test` on the aarch64 box.

## Status

| Surface | Linux | macOS | Windows |
|---|---|---|---|
| `cargo check --workspace --all-targets` | pass | pass | pass |
| `cargo test --lib` | 9,145 passed / 0 failed | 9,138 passed / 2 failed | 9,100 passed / 8 failed |
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

## The transport defect, and its cause

Every remaining failure on both non-Linux platforms was the same class: a plain
`ureq` GET to a loopback `TcpListener` succeeded on Linux and failed on macOS
(`EINVAL`) and Windows (`WSAECONNABORTED`, 10053), across the
`browser::crawl_pipeline` delta and transport families.

Cause: the test mock servers bind a `TcpListener`, call
`set_nonblocking(true)` so the accept loop can poll, then read the request from
the accepted socket. Whether the ACCEPTED socket inherits the listener's
non-blocking state is platform-specific — it does on Windows and macOS, it does
not on Linux. So off Linux the first `read` returned `WouldBlock`, the server
treated it as a client close and dropped the connection unread, and the client
saw a reset (`10053`) or `EINVAL` depending on the kernel's framing of that
reset.

Fix: both mock servers call `set_nonblocking(false)` on the accepted socket
before reading. This is a test-harness defect, not a transport defect: the
production code path was never involved, which is why it only ever appeared in
tests that hand-roll a server.
