# W13 probe — every unix-only symbol on the Windows compile path

Lane: `probe`, tag `probe`. Base commit **7f744ac** (`tallowsphere`, 2026-11-02),
worktree `rel/w13-probe`. Cargo was **not run in this
lane** (lane rule); every number below is a static census produced by
`reports/w13_unix_scan.py`, which is committed with this report so the counts can be
re-derived rather than trusted.

## What the scanner does, and the two things it cannot see

`reports/w13_unix_scan.py`:

1. Blanks Rust comments and string/char-literal bodies (positions preserved), so brace
   matching is never fooled by a `}` inside a literal.
2. Walks every item at every nesting level, collecting `#[cfg(...)]` attributes and
   whether that item is **windows-false**: `unix`, `not(windows)`, `target_os = "linux"`,
   `target_family = "unix"`. `#[cfg(test)]` is **not** a gate — `--all-targets` compiles
   test code, and the Windows job builds all targets.
3. Emits every occurrence of `libc::*`, `std::os::unix*`, `UnixStream|Listener|Datagram`,
   `if_nametoindex`, `suseconds_t`, `socklen_t`, the `*RawFd` family, and
   `ExitStatusExt|PermissionsExt|OpenOptionsExt|DirBuilderExt|FileTypeExt|MetadataExt`.
   An occurrence is **reachable** unless some enclosing item is windows-false gated — a
   necessary condition for the symbol to be compiled on windows-msvc.

Two blind spots, stated because they produce the false positives in Table B:

- **Module-file inclusion is not modelled.** `#[cfg(unix)] pub mod sandbox_runtime;` in
  `src/lib.rs:171` gates the *file*; the walker sees the file's own contents with no
  enclosing gate. Same for `src/stdlib/platform/mod.rs:12` (`#[cfg(unix)] pub mod unix;`).
- **It matches symbol spellings, not target paths.** `std::os::windows::fs::MetadataExt`
  trips the bare `MetadataExt` pattern.

## Census

At 7f744ac, whole workspace, `vendor/`, `target/`, `.git/` excluded:

| measure | count |
|---|---|
| files containing at least one unix-only occurrence | 66 |
| occurrences (all, gated or not) | 406 |
| occurrences in `src/` | 344 |
| occurrences in `crates/` | 42 |
| occurrences in `tests/` | 20 |
| **reachable before this lane's fix** | **70** |
| **reachable after this lane's fix** | **44** |
| of those 44: real Windows compile breaks in production code | **0** |
| of those 44: real breaks under `--all-targets` (tests) | 14 |
| of those 44: not a break (libc-crate symbol exists on Windows, or windows-only code) | 26 |
| of those 44: scanner false positives (module-file gate, windows-path import) | 4 |

The rest — 336 occurrences — sit behind a windows-false cfg chain already, in 160
`#[cfg(unix)]` regions against 66 `cfg(not(unix))|cfg(windows)|cfg(not(target_os="linux"))`
stubs. Those chains were resolved one occurrence at a time; a count of `libc::` lines
alone (181 in `src/`) would have been wrong in both directions.

## The 319 figure in the lane brief

The brief cites **319 unix-only sites**. I could not reproduce 319 from any definition I
can state, and I am not carrying an unverified number into a table:

- occurrences: 406
- occurrences outside `#[cfg(test)] mod tests` tails: 356
- occurrences in `src/` only: 344
- distinct `(file, line)` pairs: 331
- `libc::` lines alone in `src/`: 181

319 is therefore recorded as **unverified provenance** — presumably an earlier, narrower
regex or an earlier tree. Every number this report acts on is the re-derived one above.
The conclusion does not move: the fix set is the same 26 occurrences either way, and the
residual real breaks are the ten test-target sites in Table B.

## What this lane changed (`src/stdlib/topology.rs`)

Twenty-six occurrences became unreachable on non-unix. Two mechanisms:

**1. `scope_id_for` — cfg-split body.** `if_nametoindex(3)` is Unix-only; the Windows
`libc` crate does not declare it (`src/windows/mod.rs` has no such symbol). The numeric
form (`fe80::1%3`) still works everywhere because it is a `u32` parse. The name form
(`fe80::1%eth0`) now returns a refusal naming the missing mechanism and offering the
numeric scope id — it does not fall back to scope 0, which would silently retarget a
link-local probe at the wrong interface.

**2. `traceroute_fn` — cfg(unix) real, cfg(not(unix)) refusing stub.** The function was
the only unix-only code outside the `raw` module. Its body needs, on the Ubuntu x86_64 and
windows-msvc planes:

| symbol | site (pre-fix line) | in windows libc crate? |
|---|---|---|
| `libc::socket` | 2514 | yes |
| `libc::AF_INET` | 2514 | **no** |
| `libc::SOCK_RAW` | 2514 | **no** |
| `libc::IPPROTO_ICMP` | 2514 | **no** |
| `libc::timeval` | 2521, 2531 | yes |
| `libc::suseconds_t` | 2523 | **no** |
| `libc::setsockopt` | 2526, 2559 | yes |
| `libc::SOL_SOCKET` | 2528 | **no** |
| `libc::SO_RCVTIMEO` | 2529 | **no** |
| `libc::socklen_t` | 2531, 2564 | **no** |
| `libc::c_void` | 2452, 2530, 2563 | yes (core::ffi re-export) |
| `libc::recv` | 2452 | **no** (only `recvfrom`) |
| `libc::close` | 2550, 2641 | yes |
| `libc::c_int` | 2445, 2556, 2564 | yes |
| `std::os::unix::io::AsRawFd::as_raw_fd` | 2557 | **no** (std path) |
| `libc::IPPROTO_IP` | 2561 | **no** |
| `libc::IP_TTL` | 2562 | **no** |

"in windows libc crate?" is read from the vendored crate source,
`libc-0.2.191/src/windows/mod.rs` — e.g. `signal`/`sighandler_t`/`SIGINT`/`SIGTERM`/
`SIG_DFL` and `printf` are declared there (lines 13, 238, 242, 247, 277, 405), while the
socket family above is not. This matters: it is why Table B's `runtime/mod.rs` and
`transfer_net.rs` rows are *not* breaks even though they call libc.

`AsnTable` and `icmp_for_port` are now `#[cfg(unix)]` too: their only two references are
inside `traceroute_fn` (lines 2544 and 2608), so on non-unix both would have been dead
code that still did not compile.

**Ordering of the stub.** The `#[cfg(not(unix))] traceroute_fn` calls
`require_authorized(&target)` **before** refusing on platform. If it refused on platform
first, a Windows build would answer `unsupported` where the register says
`scope:not-listed` — the wrong reason, and it would skip the gate. A platform limit must
not become an authorization bypass. Only after the target is authorized does the
platform refusal stand, and the sentence says no probe was sent.

## What cannot exist on Windows at all

These are not cfg gaps to be filled; the mechanism is absent from the platform's socket
API, and a Windows build must refuse rather than pretend:

- **IPv4 traceroute.** A raw `AF_INET`/`SOCK_RAW`/`IPPROTO_ICMP` socket, a `SO_RCVTIMEO`
  receive timeout on it, and `IP_TTL` steering on the UDP probe's descriptor. Windows
  exposes TTL through `IP_TTL` on a Winsock socket only via a different ABI and cannot
  receive raw ICMP errors from the UDP socket's path the way Unix does; the `libc` crate
  declares none of it. Implementable, if at all, only by a `windows-sys` rewrite over
  Winsock and `IcmpSendEcho`-style APIs — that is behaviour work, not a gate.
- **Raw SYN / FIN / NULL / XMAS scans.** `src/stdlib/topology.rs:553` gates the whole
  `raw` module to `target_os = "linux"`; the `#[cfg(not(target_os = "linux"))]` twin at
  1018 returns `io::ErrorKind::Unsupported` from `RawSyn::open`, `send_probe`, and
  `icmpv6_echo`. So on Windows these techniques were **already** refusal stubs before
  this lane — I changed nothing there, and the evasion techniques cannot emit a probe
  because they cannot open the socket. (Note `RawSyn::collect` returns `Ok(vec![])`, i.e.
  silent no-answer rather than an error; callers classify that as `open|filtered`, which
  is the honest reading of "no packet was sent".)
- **ICMPv6 echo (host discovery).** Same module split; the non-Linux `icmpv6_echo`
  returns `Unsupported`, and `v6_discover_fn` folds a transport error into the
  `unsupported` list rather than reporting the host down. Windows answers ICMPv6 echo
  through `Icmp6SendEcho2`, not a raw socket.

## Table B — residual reachable occurrences (44) and their verdicts

### B1. Real breaks under `--all-targets` (14 occurrences on 10 lines) — tests only, not fixed in this lane

| file:line | symbol | remedy |
|---|---|---|
| `tests/bridge_marshal_adversarial.rs:531` | `libc::sysconf`, `libc::_SC_PAGESIZE` | page size via `std::env::var("TALLOW_PAGE_KB")` fallback or `cfg(unix)` wrapper returning 4 |
| `tests/bridge_overhead.rs:602` | same | same |
| `tests/bridge_ownership_adversarial.rs:524` | same | same |
| `tests/defer_parity.rs:440` | same | same |
| `tests/topology_ipv6.rs:137` | `libc::geteuid` | `#[cfg(unix)] fn running_as_root()`, `#[cfg(not(unix))] fn running_as_root() -> bool { false }` |
| `tests/topology_scan.rs:58,115,144,409` | `libc::geteuid` | same |
| `tests/callnorm_adversarial.rs:190` | `std::os::unix::process::ExitStatusExt` | test the exit code via `status.code()`; the `.signal()` assertion is unix-only and should be `#[cfg(unix)]` |

Not fixed here because this lane's code deliverable is the production module; the same
`cfg` split applies but the four `sysconf` helpers are duplicated in four files and want
one shared test helper, which is a different lane's diff.

### B2. Not breaks — windows code or a symbol the windows libc crate declares (17)

| file:line | symbol | why it compiles |
|---|---|---|
| `src/runtime/mod.rs:142–171` (13 occurrences) | `libc::printf`, `libc::c_char` | `printf` is declared at `libc-0.2.191/src/windows/mod.rs:277`; `c_char` is a core re-export |
| `src/stdlib/transfer_net.rs:544–566` (13 occurrences) | `libc::signal`, `sighandler_t`, `SIGINT`, `SIGTERM`, `SIG_DFL`, `c_int` | all declared at windows/mod.rs:13,238,242,247,405 — **compiles**, but see caveat below |

Counts in that column overlap no other row: B1 14 + B2 26 + B3 4 = 44.

Caveat on `transfer_net.rs` `relay_signal`: it builds on Windows, but the CRT's `signal`
is not a POSIX signal. `SIGTERM` is never raised by Windows, and a console `Ctrl+C`
arrives as `SIGINT` through the CRT only if the process installed a handler; the
cooperative-interrupt guard therefore degrades to "never fires" rather than "aborts the
transfer". That is a behaviour defect, not a compile break, and this file is inside the
sendtallow boundary — reported, not touched.

### B3. False positives from the two scanner blind spots (4)

| file:line | symbol | reason |
|---|---|---|
| `src/sandbox_runtime.rs:15` | `std::os::unix::process::CommandExt` | `src/lib.rs:171` gates the module; non-unix pulls `sandbox_runtime_nonunix.rs` |
| `src/stdlib/platform/unix/xattr.rs:99` | `std::os::unix::fs::symlink` | `src/stdlib/platform/mod.rs:12` gates `pub mod unix` |
| `src/stdlib/filter.rs:148` | `MetadataExt` | it is `std::os::windows::fs::MetadataExt` — windows-only by construction |
| `src/stdlib/transfer.rs:666` | `OpenOptionsExt` | `std::os::windows::fs::OpenOptionsExt` — same |

## Acceptance

**Not run.** The lane rule for this job is "do NOT run cargo in this lane; a later wave
owns the builds", so there is no `cargo check` output to paste and I will not imply one.
What was run, and its output:

- `python3 reports/w13_unix_scan.py` against the worktree: 66 files, 406 occurrences,
  44 reachable.
- the same script against `git archive HEAD` in a scratch directory: 70 reachable.
  Delta = the 26 occurrences this commit gates, all in `src/stdlib/topology.rs`.
- `grep -n "AsnTable|icmp_for_port" src/stdlib/topology.rs`: references only at 2410,
  2415, 2442 (definition) and 2544, 2608 (inside `traceroute_fn`).

The unix build must still be checked by the build wave; the change is attribute-only and
touches no unix-compiled expression except making the `scope_id_for` body a cfg-split
block with the same statements.
