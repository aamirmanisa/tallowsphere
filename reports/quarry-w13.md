# W13 — cfg-gated egress census (lane report)

Lane: quarry. Tree `/home/aamir/tallow-worktrees/w13/quarry`, branch
`rel/w13-quarry`, base `7f744ac`. No `cargo` was run: the project build belongs
to a later wave. The test file was compile-checked and executed directly with
`rustc --edition 2021 --test`, which uses std only and does not touch the
workspace build graph.

## What was wrong

The egress gate (`tests/egress_gate_coverage.rs`) treats every `.rs` file as
flat text. Rust does not compile a `#[cfg(unix)]` item on Windows or a
`#[cfg(not(unix))]` item on Linux, so the gate has no way to state what the
other platform of a cfg-split path does. Worse, the gate's needle list
(`egress_http::` / `ureq::` / `reqwest::` verbs, `TcpStream::connect`,
`UdpSocket::connect`, `connect_timeout`) does not include the primitives
platform-gated code actually uses: `Command::new(`, `libc::socket(`,
`UdpSocket::bind(`. Result: every cfg-gated egress path in the tree was
invisible to the gate, and a Windows build could never surface the missing
grant because the Unix branch is not compiled.

A second defect sat in the gate's own region cut: `production_region()` looked
for the literal `#[cfg(test)]`, so test modules declared
`#[cfg(all(test, unix))]` (`src/browser/cdp.rs:187`,
`src/runtime/hardening.rs:110`) were read as production code.

## What was measured (read-only)

`reports/probes/cfg_unix_egress_census.py`, 595 files, 271 egress-capable
production sites:

| guard view | sites |
|---|---|
| absent on Windows | 14 |
| only on Windows | 10 |
| compiles on both | 0 |
| no cfg guard | 247 |

The 14 absent-on-Windows sites are 9 `Command::new`, 3 `libc::socket` and 2
`UdpSocket::bind`. **0 of the 14 match the gate's needles.** Full table with
`file:line`, guard, Windows-reachability verdict and open-defect flags is in
`reports/egress-surface-inventory.md` §"CFG-gated egress census".

## What was fixed (no build required)

- `tests/egress_gate_coverage.rs`:
  - `CFG_EGRESS`: 24 rows (14 absent-on-Windows + 10 only-on-Windows), each with
    the exact cfg expression, primitive class, a machine-checked other-platform
    verdict (`unreachable:` / `equivalent:` / `only-on-windows:`) and a note.
    Bidirectional and stale-checked, cap 24 — a new cfg-gated egress site fails
    until it is enumerated.
  - `cfg_egress_sites()`: resolves inline `#[cfg(...)]` item spans and inherits
    `#[cfg(...)] mod` guards transitively, so a future site in
    `src/stdlib/platform/unix/*` or `src/sandbox_runtime.rs` is enumerated.
  - `production_region()`: cuts at any cfg expression naming the bare `test`
    token.
- `reports/egress-surface-inventory.md`: the census section above.
- `reports/probes/cfg_unix_egress_census.{py,json}`: the reproduction, now in
  the tree.

## Verification (measured)

Command: `CARGO_MANIFEST_DIR=<repo> rustc --edition 2021 --test
tests/egress_gate_coverage.rs -o <scratch>/egress_gate_coverage_test`, then run
the binary.

- Baseline: `test result: ok. 5 passed; 0 failed` — `cfg census: 24 sites
  scanned, 24 rows (14 absent, 10 windows-only, cap 24)`. Existing gate result
  unchanged: 49 gated files, 8 debt, 0 ungated.
- Negative control A (pre-existing gate): adding
  `fn _probe() { let _ = std::net::TcpStream::connect("203.0.113.1:80"); }` as
  `src/_ungated_probe.rs` fails `every_egress_site_consults_scope_require`,
  naming the file.
- Negative control B (new pin): adding
  `#[cfg(unix)] fn _probe() { let _ = std::process::Command::new("browser"); }`
  as `src/_cfg_probe.rs` fails `cfg_gated_egress_sites_are_enumerated` with
  `src/_cfg_probe.rs:2: new cfg-gated egress site [proc] under 'unix' has no
  CFG_EGRESS row`. Both probe files were deleted; `git status` clean for `src/`.

## Open defects recorded, not fixed

- **O1** `src/browser/juggler.rs:91`: the Unix Firefox/Camoufox launch is
  `Command::new(chrome_path)` with no `scope::require` anywhere in the file.
  Windows refuses at `juggler.rs:223`, so the defect is Unix-only. Fixing it
  needs the grant vocabulary for a browser launch and a build to exercise it.
- **O2** `src/stdlib/topology.rs:593,714,832`: raw ICMP/ICMPv6/TCP sockets are
  credited by the file-level `scope::require` at `:190`, which belongs to the
  connect-probe helpers, not to `icmpv6_echo`, `RawSyn::open` or `icmp_echo`.
  Per-function gating changes scan-path authorization semantics and needs the
  topology tests; out of reach without a build.
