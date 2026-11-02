# Egress surface outside the 25 gated modules

Measured 2026-11-01 on `e2d91ac`. Written because the wave-5 claim "25 modules gated,
0 ungated" was **true only for the predicate the coverage test uses**
(`src/stdlib/*.rs` containing an `egress_http::` request verb). A sweep over every
request primitive in every non-test region finds a much larger ungated surface.

**Re-measured 2026-11-01 at `6bb094b`.** Three rows in the HTTP table are now closed
(`9925c2b`, merged `6bb094b`); the rows are kept and marked rather than deleted, so the
delta stays auditable. Counts below are the `6bb094b` scan, with the `e2d91ac` value in
parentheses wherever it moved. The counting script that reproduces both columns is
`reports/inventory_scan.py`; it reproduces the original `e2d91ac` table exactly
(20 files / 32 sites, every row at the published line numbers).


## Method

- Walk `src/**/*.rs`; cut each file at its first `#[cfg(test)]` so test harnesses do
  not count as egress.
- A file is **gated** if its production region contains `scope::require`.
- Classify the rest by primitive: `egress_http::<verb>(`, `ureq::<verb>(`,
  `reqwest::Client::new|builder`, `reqwest::<verb>(` for HTTP egress;
  `TcpStream::connect`, `UdpSocket::connect`, `connect_timeout` for raw connects;
  `bind` / `Command::new` for the non-egress class.
- Two readings the script has to make explicit, because the prose above does not state them
  and a re-run that differs on either gets different numbers:
  - **`egress_http::agent_with_timeouts(` counts as an HTTP egress primitive.** It is the
    request-client factory — the module builds that agent and issues on it a few lines later
    (`agent.get(url)`), so a row that names only that line is still a request site. Four of
    the twenty rows below are that shape.
  - **`reqwest::blocking::Client::new|builder` counts too.** The document's shorthand says
    `reqwest::Client::…`; the `blocking::` module path is the same primitive.
  Comment lines (`// …`) are not counted as sites.

## Counts

At `6bb094b`, with the `e2d91ac` value in parentheses where it moved:

- files calling `scope::require` outside tests: **34** (31)
- HTTP egress with no register call: **17 files / 26 sites** (20 / 32)
- raw socket connect with no register call: **15 files / 36 sites** (unchanged)
- bind/listen/subprocess (not egress by itself): **38 files / 99 sites** (unchanged)

The earlier text of this section said 32 gated files and 32/77 for the last class; neither
reproduces from the predicate above, and both are corrected here rather than left to flatter
the delta. The three-class totals are unaffected by the `6bb094b` merge except in HTTP.

### HTTP egress, ungated — 17 files / 26 sites (was 20 / 32)

Rows marked **closed** are gated at `6bb094b` and no longer appear in the count; their
`e2d91ac` line numbers are kept so the original measurement can still be located.

| file | sites | lines (`e2d91ac`) | status |
|---|---|---|---|
| `src/agent_reasoning.rs` | 2 | 579, 748 | open |
| `src/browser/adaptive_crawler.rs` | 2 | 54, 69 | open |
| `src/browser/autonomous.rs` | 1 | 274 | open |
| `src/browser/captcha.rs` | 4 | 427, 478, 580, 621 | **closed** — `6bb094b`, gate `captcha.rs:418` (`gate_solver`) |
| `src/browser/download.rs` | 3 | 197, 305, 739 | open |
| `src/browser/dpi_bypass.rs` | 1 | 398 | open |
| `src/browser/dual_mode.rs` | 2 | 432, 551 | open |
| `src/browser/free_proxies.rs` | 2 | 35, 96 | open |
| `src/browser/llm_extract.rs` | 1 | 296 | open |
| `src/browser/perf_engine.rs` | 1 | 103 | open |
| `src/browser/proxy_intelligence.rs` | 2 | 152, 200 | open |
| `src/browser/robots.rs` | 1 | 79 | **closed** — `6bb094b`, gate `robots.rs:81` |
| `src/browser/sitemap.rs` | 1 | 184 | **closed** — `6bb094b`, gate `sitemap.rs:186` |
| `src/browser/typesense.rs` | 1 | 166 | open |
| `src/cli/daemon.rs` | 1 | 215 | open |
| `src/request_plan.rs` | 1 | 72 | open |
| `src/signing.rs` | 2 | 259, 307 | open |
| `src/stdlib/cnam_dip.rs` | 1 | 129 | open |
| `src/stdlib/lrn_dip.rs` | 1 | 129 | open |
| `src/stdlib/sync.rs` | 2 | 44, 69 | open |

The three closed rows were closed by one commit, `9925c2b`, and each is fatal rather than
returned — the deciding caller is named per site in `reports/vellum-egress-docs.md`. All
three modules now contain `scope::require`, so they also leave the ungated set entirely
rather than shrinking within it.


### Raw socket connect, ungated — 15 files / 36 sites

| file | sites | lines |
|---|---|---|
| `src/browser/ipv6_pool.rs` | 1 | 642 |
| `src/browser/network_stealth.rs` | 4 | 252, 257, 265, 268 |
| `src/browser/process.rs` | 1 | 936 |
| `src/browser/proxy.rs` | 1 | 642 |
| `src/browser/socks_shim.rs` | 1 | 187 |
| `src/cli/fingerprint_audit_cmd.rs` | 1 | 1516 |
| `src/cli/request_plan_cmd.rs` | 1 | 972 |
| `src/cli/veil_cmd.rs` | 4 | 195, 273, 289, 589 |
| `src/main.rs` | 7 | 2312, 2513, 2540, 2591, 5733, 6012 … |
| `src/mesh/remote.rs` | 1 | 602 |
| `src/stdlib/cnam_dip.rs` | 1 | 131 |
| `src/stdlib/lrn_dip.rs` | 1 | 131 |
| `src/stdlib/mesh.rs` | 1 | 482 |
| `src/stdlib/topology.rs` | 5 | 389, 481, 1595, 1765, 2092 |
| `src/stdlib/transfer_net.rs` | 6 | 1003, 1193, 1365, 3170, 3521, 3575 |

## Caveats that make this a work list, not a panic

- **Loopback-only sites are not a policy hole.** Several connect to 127.0.0.1 for the
  browser's own control socket, the CDP endpoint, or a local proxy. They appear here
  because the predicate cannot tell them apart; gating a loopback control socket buys
  nothing.
- **Hardcoded constant targets differ from caller-supplied URLs.** `src/browser/download.rs:197`
  fetches `CFT_LAST_KNOWN_GOOD_URL`; `src/main.rs:2312` connects to `8.8.8.8:80` to detect
  the public IP. Neither is attacker-influenced, but under the register's doctrine every
  host is granted or refused, so an operator reading the register would expect them there.
- **`src/stdlib/transfer_net.rs` and `src/stdlib/relay_room.rs` are the sendtallow boundary** —
  ruled out of scope for the fleet by the operator, so their sites are excluded from gate work.
- **`bind` / `Command::new` are not egress.** The third class is reported for completeness only.

## Consequence for `tests/egress_gate_coverage.rs`

Its predicate is `src/stdlib/*.rs` x `egress_http::`, which is why 30 files above never
failed it. The durable fix is to widen it to `ureq::`, `reqwest` and `TcpStream::connect`
across `src/`, with an explicit debt list that shrinks as gates land — not to add a gate
for every row here, and not to leave the predicate as it is and call the surface covered.

Status: **inventory only, nothing is gated by this document.** Three of the browser rows in
the first table were closed by `6bb094b`; the rest is a backlog with a measured size. The
counts above are re-derived from `6bb094b`, not carried forward: the script that produces
them is `reports/probes/inventory_scan.py`, and it reproduces the original `e2d91ac`
table exactly — run it against both revisions to see the six-site delta for yourself:

```bash
python3 reports/inventory_scan.py e2d91ac   # 20 files / 32 sites
python3 reports/inventory_scan.py 6bb094b   # 17 files / 26 sites
python3 reports/inventory_scan.py 758e5bc   #  3 files /  5 sites   (see the re-measure below)
```

## Re-measured at `758e5bc` (2026-11-01, wave 12)

The script moved into the tree (`reports/inventory_scan.py`) so the number the
coverage gate cites can be reproduced from the repository instead of from a
scratch directory.

| class | `6bb094b` | `758e5bc` |
|---|---|---|
| files calling `scope::require` in the production region | 34 | **53** |
| HTTP egress with no register call | 17 files / 26 sites | **3 files / 5 sites** |
| raw socket connect with no register call | 15 files / 36 sites | **7 files / 15 sites** |
| bind / listen / subprocess (not egress) | 38 files / 99 sites | 34 files / 71 sites |

The three ungated HTTP files are exactly the three HTTP rows on
`tests/egress_gate_coverage.rs`'s DEBT list: `src/cli/daemon.rs` (:215),
`src/signing.rs` (:259, :307), `src/stdlib/sync.rs` (:44, :69). The seven ungated
raw-connect files are exactly the seven raw DEBT rows (`browser/process.rs`,
`browser/socks_shim.rs`, `cli/fingerprint_audit_cmd.rs`, `cli/request_plan_cmd.rs`,
`cli/veil_cmd.rs` — 4 sites, `stdlib/mesh.rs`, `stdlib/transfer_net.rs` — 6 sites).

That agreement is the useful result, not the drop: **the DEBT list is complete
with respect to this predicate** — there is no ungated file outside it, and no
file on it that the scan cannot see. What the predicate still cannot see is the
class `quarry` is census-ing (QUIC, DNS resolution, child processes, browser
CDP), so this table is a claim about HTTP and raw TCP, not about every socket.

### Correction, same day: file-level completeness is not site-level coverage

`reports/quarry-w12.md` (§2) measures what this document's predicate cannot, and
it changes how the paragraph above should be read. Over 176 network-capable
sites in production regions:

- a `scope::require` earlier in the **same function**: **12**
- genuinely ungated: **164**
- invisible to the predicate: **135**, of which **61 sit in files the coverage
  gate reports as gated**
- of 87 sites inside files called gated, **75 have no `require` in their
  enclosing function**

`tests/egress_gate_coverage.rs` decides gating with `is_gated(text)` — one
`scope::require` anywhere in the production region marks the whole file
(verified: the test computes `egress_sites(text)` and then gates on the file).
So "0 ungated" is a file-granularity claim, and the debt list is complete only
in that sense. The durable fix is site-level gating: for each site, require a
`require` in its enclosing function, with a per-site debt list that shrinks.
Until that lands, any statement of the form "N gated / 0 ungated" carries this
caveat with it.

## CFG-gated egress census (2026-11-02, wave 13, `7f744ac`)

The egress gate reads every `.rs` file as flat text. Rust does not: a
`#[cfg(unix)]` item is not compiled on Windows, and a `#[cfg(not(unix))]` item
is not compiled on Linux. This section measures every egress-capable call site
that a Windows build cannot compile, so the other-platform path is named rather
than assumed.

Measured read-only, no `cargo`, by
`reports/probes/cfg_unix_egress_census.py` (writes
`reports/probes/cfg_unix_egress_census.json`). It resolves the attribute that
owns each line by brace/`;` span matching, evaluates the expression against
synthetic `linux` / `macos` / `windows` targets, and propagates
`#[cfg(...)] mod X;` guards transitively into the module file it resolves to.
`Command::new(` is counted as egress-capable here for the same reason section
4.11 of `reports/quarry-w12.md` counted it: a launched browser is
network-capable by construction.

### Counts

| measure | value |
|---|---|
| `src/**/*.rs` files | 595 |
| egress-capable call sites in production regions | 271 |
| …behind a guard that is **absent on Windows** | **14** |
| …behind a guard that is **only on Windows** | **10** |
| …under a guard that compiles on both (e.g. `feature`) | 0 |
| …with no cfg guard at all | 247 |

Two module-level `cfg(unix)` guards carry no egress site on this revision and
are therefore not rows below: `src/lib.rs:170` (`pub mod sandbox_runtime;` →
`src/sandbox_runtime.rs`, whose only `Command::new` calls are inside its
`#[cfg(test)]` region at `:232–313`) and `src/stdlib/platform/mod.rs:12`
(`pub mod unix;` → `src/stdlib/platform/unix/{mod,xattr}.rs`). Both have a
`#[cfg(not(unix))]` counterpart (`sandbox_runtime_nonunix.rs`,
`platform/windows/`). They are named here because a future egress site landing
in either file inherits the guard and must be enumerated by the coverage test
below — which is exactly why the test implements module-guard inheritance.

### Sites absent from a Windows build — 14

Verdict vocabulary: **unreachable** = the Windows branch refuses or does not
exist; **equivalent** = a Windows path at the named site does the same work.
`open:` marks a site with no `scope::require` in its enclosing function.

| file:line | guard | class | Windows can reach | verdict |
|---|---|---|---|---|
| `src/browser/juggler.rs:91` | `unix` | proc `Command::new(chrome_path)` | no — `juggler.rs:223` `#[cfg(not(unix))] launch` returns `ConnectionFailed`, spawns nothing | unreachable; **open:** `juggler.rs` has no `scope::require`; the Unix Firefox/Camoufox launch is ungated child-process egress |
| `src/browser/trace.rs:455` | `target_os = "macos"` | proc `open` | yes — `trace.rs:449` `#[cfg(target_os = "windows")] Command::new("cmd")` | equivalent; local viewer open, not network |
| `src/browser/trace.rs:461` | `target_os = "linux"` | proc `xdg-open` | yes — `trace.rs:449` `cmd` | equivalent; local viewer open, not network |
| `src/main.rs:2203` | `target_os = "macos"` | proc `brew` | yes — `main.rs:2167` `winget`, `:2183` `choco` | equivalent; ffmpeg install, local OS maintenance |
| `src/main.rs:2220` | `not(any(target_os = "windows", target_os = "macos"))` | proc `sudo apt` | yes — `main.rs:2167`/`:2183` | equivalent; ffmpeg install |
| `src/main.rs:2230` | same | proc `sudo dnf` | yes — `main.rs:2167`/`:2183` | equivalent; ffmpeg install |
| `src/main.rs:2240` | same | proc `sudo pacman` | yes — `main.rs:2167`/`:2183` | equivalent; ffmpeg install |
| `src/main.rs:4813` | `unix` | proc `chown` | yes — `main.rs:4973`/`:4984`/`:4992` `#[cfg(windows)] icacls` save/restore | equivalent; local file metadata, not network |
| `src/runtime/io_uring_runtime.rs:123` | `all(target_os = "linux", feature = "io-uring-backend")` | proc `uname -r` | no — fn is cfg'd out; `is_available()` returns `false` off Linux | unreachable; local kernel probe, not network |
| `src/stdlib/topology.rs:593` | `target_os = "linux"` | raw `libc::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)` | no — `topology.rs:1001` `#[cfg(not(target_os = "linux"))] mod raw` returns `Unsupported` | unreachable; **open:** `icmpv6_echo` has no `scope::require` |
| `src/stdlib/topology.rs:701` | `target_os = "linux"` | udp `UdpSocket::bind("[::]:0")` | no — `:1001` stub returns `Unsupported` | unreachable; `udp_source_v6` routes a `connect()` for source selection and sends no packet |
| `src/stdlib/topology.rs:714` | `target_os = "linux"` | raw `libc::socket(AF_INET, SOCK_RAW, IPPROTO_TCP)` | no — `:1001` stub | unreachable; **open:** `RawSyn::open` has no `scope::require` |
| `src/stdlib/topology.rs:743` | `target_os = "linux"` | udp `UdpSocket::bind("0.0.0.0:0")` | no — `:1001` stub | unreachable; `RawSyn::source_for` routes a `connect()` for source selection and sends no packet |
| `src/stdlib/topology.rs:832` | `target_os = "linux"` | raw `libc::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)` | no — `:1001` stub | unreachable; **open:** `icmp_echo` has no `scope::require` |

### Sites only on Windows — 10 (the other half of each pair)

All are `proc` (`Command::new`), none is network egress, and none is visible to
the gate's needles either. They are enumerated so the pairing is auditable:
`src/browser/process.rs:1397` (`tasklist` liveness), `src/browser/trace.rs:449`
(`cmd` viewer), `src/main.rs:2167`/`:2183` (`winget`/`choco`),
`src/main.rs:4973`/`:4984`/`:4992` (`icacls`), `src/pkg/cache.rs:575`/`:618`
(`cmd` junction/link), `src/stdlib/transfer.rs:718` (`powershell` VSS copy).

### The coverage hole this creates in `tests/egress_gate_coverage.rs`

1. **No cfg parsing at all.** `egress_sites()` maps `production_region(text)`
   line-by-line through `has_http_site` / `has_raw_site`; nothing in the file
   reads an attribute. It therefore checks each platform branch as if it were
   compiled everywhere, and can never assert that the *other* branch of a
   `cfg` pair exists, is gated, or refuses. A Windows-only path cannot be
   inferred from a Unix-only one, and vice versa.
2. **0 of the 14 absent-on-Windows sites match its needles.** The classes are
   `proc` (9), `raw` (3) and `udp` (2); `Command::new(`, `libc::socket(` and
   `UdpSocket::bind(` are not in `REQUEST_VERBS` or `RAW_NEEDLES`. So cfg is
   not what hides these from the gate — the primitive list is. But cfg makes
   the blind spot durable: the branch that would expose the class is compiled
   out, so no Windows build, lint or type-check ever reaches the missing grant.
   The same is true of all 10 Windows-only sites.
3. **`is_gated` is file-granular.** `src/main.rs` holds both `cfg(unix) chown`
   and `cfg(windows) icacls`; one `scope::require` anywhere in the production
   region marks the whole file gated, so a grant present in one platform branch
   credits the other. This is the same file-vs-site defect as §"Correction,
   same day" above, with cfg as the split.
4. **The test-region cut was itself cfg-blind.** `production_region` looked for
   the literal `#[cfg(test)]` only. `src/browser/cdp.rs:187` and
   `src/runtime/hardening.rs:110` declare their unit-test modules
   `#[cfg(all(test, unix))]`; those test bodies were being read as production
   code. No egress site or `scope::require` sits there today, so no number in
   this document moves — but a test-only socket would have been counted as
   egress, and a `scope::require` in such a test module would have marked the
   file gated. Closed in this wave.

### Fix landed (no build required)

`tests/egress_gate_coverage.rs` now carries the census as a pin:

- `CFG_EGRESS` — 24 rows (`file`, `line`, `guard`, `class`, view, other-platform
  verdict, note), cap 24. Bidirectional: an unlisted cfg-gated egress site
  fails, a stale row fails, and a row whose guard expression or class drifted
  fails. Verdicts are machine-checked to start with `unreachable:`,
  `equivalent:` or `only-on-windows:`.
- `cfg_egress_sites()` — resolves inline `#[cfg(...)]` item spans and inherits
  `#[cfg(...)] mod` guards transitively, so a site landing in
  `src/stdlib/platform/unix/*` or `src/sandbox_runtime.rs` is enumerated
  without a per-file special case.
- `production_region()` — cuts at any cfg expression naming the bare `test`
  token, not just the literal `#[cfg(test)]`.
- Negative control, run 2026-11-02: adding
  `#[cfg(unix)] fn _probe() { let _ = std::process::Command::new("browser"); }`
  as `src/_cfg_probe.rs` turns `cfg_gated_egress_sites_are_enumerated` red,
  naming `src/_cfg_probe.rs:2 … has no CFG_EGRESS row`. Deleting it restores
  green (5 passed, 0 failed, without cargo).

### Open defects this census records but does not fix

- **O1 — `src/browser/juggler.rs:91`.** The Unix Firefox/Camoufox launch has no
  `scope::require`; the file name `juggler` does not appear in the gate's
  gated/debt lists because its only egress primitive is a child process.
  Fixing it needs a decision about what target/verb a browser launch is granted
  under and a test that exercises the launch path — both require a build, which
  this lane does not own.
- **O2 — `src/stdlib/topology.rs:593,714,832`.** Raw ICMP/ICMPv6/TCP sockets run
  under a file-level `scope::require` that belongs to the connect-probe helpers
  (`:190`), not to `icmpv6_echo`, `RawSyn::open` or `icmp_echo`. Per-function
  gating is the durable fix; it changes authorization semantics on the scan
  path, so it belongs to a lane that can run the topology tests.

