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

## The one open defect

Every remaining failure on both non-Linux platforms is the same class: a plain
`ureq` GET to a loopback `TcpListener` succeeds on Linux and fails on macOS
(`EINVAL`) and Windows (`WSAECONNABORTED`, 10053). On macOS two tests hit it, on
Windows seven (all in `browser::crawl_pipeline`: the delta and transport
families). The representative failure:

```
thread 'transport_agent_cache_reuses_keepalive_connections' panicked
  phase A request: Io(Os { code: 22, kind: InvalidInput, message: "Invalid argument" })
```

A plain `ureq` GET against a loopback `TcpListener` returns `EINVAL` on macOS and
succeeds on Linux. Not yet diagnosed: the call is inside ureq/rustls, and the
failing branch cannot be reproduced on this box (no macOS host, and the macOS
leg of CI is the only place it runs). Recorded here rather than papered over with
a `cfg` skip, because if a plain HTTP request fails with EINVAL on macOS it is a
product defect, not a test defect.

Next step for whoever picks it up: run the test on a macOS host with
`RUST_BACKTRACE=full` and `strace`-equivalent (`dtruss` requires SIP off), and
check whether `.cargo/config.toml`'s `aarch64-apple-darwin` rustflags
(`+aes,+crc,...`) are producing a codegen path that the platform rejects. The
same flags are used for the release build, so this is not test-only.
