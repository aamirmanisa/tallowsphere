# Changelog

All notable changes to Tallow are recorded here.

Every version section MUST contain `### What was wrong` and `### What was fixed`.
`scripts/release_body.py` builds the GitHub release body from these sections and
the release workflow fails when either heading is missing — a release that does
not say what broke and what repaired it cannot be published.
Format: [Keep a Changelog](https://keepachangelog.com/) · versions: [SemVer](https://semver.org/).
Release identity for V1 is **local-only (R0)** — see `docs/release/versioning-policy.md`.

## [v1.4.0] — 2026-10-23 — model providers, without keys in the language

### What was wrong

Tallow had no way to reach a model provider. The directorate/agent work could plan
and journal a task graph, but the step that actually reasons had nowhere to go, so
every "agent" claim stopped at the orchestration layer. Building the provider
surface also exposed a language defect that had been latent since modules were
introduced.

### What was fixed

- **`llm` module** (`stdlib/llm.tl` + `src/stdlib/llm.rs`): `providers`, `models`,
  `complete`, `verify`. Twenty providers across four wire protocols — OpenAI chat
  completions (OpenAI, xAI, DeepSeek, Alibaba DashScope, Mistral, Moonshot, Z.ai,
  MiniMax, NVIDIA NIM, ByteDance Ark, Tencent Hunyuan, Baidu Qianfan, and any
  self-hosted OpenAI-compatible server), Anthropic messages, Google
  generateContent, Azure OpenAI, Cohere v2. Four providers are declared
  `unavailable` **with the reason** (Meta has no inference API; Bedrock needs SigV4;
  watsonx needs IAM exchange; Xiaomi has no public API), each with the route that
  does work.
- **Model discovery, not a model list.** `llm.models` calls the provider's own
  `/models` endpoint at call time and parses it per protocol, so a provider
  changing its line does not need a release.
- **Credentials never enter the language.** Config names `key_env` or `key_file`; an
  inline `key = "..."` is refused with a message naming the fix and never echoes
  the value; key files must be mode 0600; errors are redacted; no request is sent
  when the credential is missing. The CLI has no `--key` flag on purpose.
- **CLI**: `tallow llm providers|models|verify|complete|init` (`init` writes the
  config at mode 600).
- **Interpreter defect**: a lowercase module name shadowed a *user variable*. With
  `llm` registered, `let llm = h.llm_calls` evaluated to `"__module_llm__"` instead
  of the field. Variables now take precedence over module sentinels — modules are a
  fallback, not a reserved word.
- **Egress, stated rather than assumed**: model traffic does not use the Tor
  browsing plane. The credential in the header is an identity, so Tor buys no
  anonymity there and breaks providers that block exits; `llm` connects directly
  unless `TALLOW_LLM_PROXY` is set.

### Counts

86 → 87 modules; 1,126 → 1,130 function declarations. Gate moved in the same
commit with the reason inline.

Verified: `tests/llm_providers.rs` 7 passed against a local server enforcing each
protocol's authentication surface (Bearer, `x-api-key` + `anthropic-version`,
`x-goog-api-key`, `api-key`), including a custom self-hosted provider, redaction on
a 401, local refusal on a missing key with zero requests sent, and the 20-provider
registry. Full lib suite: 9,212 passed / 0 failed / 33 ignored.

## [v1.3.0] — 2026-10-23 — the mesh crosses a socket

### What was wrong

The mesh execution plane ran inside one process. Its leases, epochs and
checkpoints were enforced by threads, so "a straggler is fenced" was true only
for a worker that was slow, never for a peer that had become unreachable: there
was no transport, no node identity, and nothing that could tell a stopped process
from a dead one. `src/stdlib/mesh.rs` also still models every node as
`simulated: true`, and nothing in the engine made that false for a node that was
actually doing work.

Running the new tests also exposed four defects that had nothing to do with the
network and would have persisted silently:

- a task slower than its lease was reassigned forever, because nothing bounded
  lease expiry;
- reassignment could return a task to the very node that had just failed it,
  burning every retry without reaching a live worker;
- a reassigned `pure` task got a different seed, so a partitioned run committed a
  different checkpoint than an uninterrupted one;
- a refused join looked like success, because the worker treated the server
  closing the socket as a clean shutdown.

### What was fixed

- `src/mesh/wire.rs` — 1 MiB length-prefixed frames, every frame Ed25519-signed
  over a fixed canonical string; replay refused by per-run nonce; oversized
  frames refused before allocation; `FrameReader` decodes only complete frames so
  a read timeout cannot split a length prefix.
- `src/mesh/remote.rs` — `MeshServer` accepts joins against a node allowlist and
  refuses everyone else with a signed reason; reconciles availability with
  `(task, epoch, deadline)` leases; reassigns on expiry at `epoch + 1` and
  discards late answers from stale epochs; caps attempts per task class and
  journals `TaskFailed` instead of spinning; excludes the expired holder when
  another peer exists; keeps `pure` seeds attempt-independent.
- `tallow mesh worker --connect … --node … --key … --server-key … --run-id …`
  joins a coordinator and executes assignments; a refused join now exits non-zero.
- `simulated` flips **per node**, only after that node has joined and had one
  result committed. There is no global flag.
- Control frames (`stop`, `inject`) over the wire are accepted only from
  allowlisted operator keys.

### Not claimed

Plaintext TCP, no NAT traversal, no TLS, no key rotation. The topology plane
(`src/stdlib/mesh.rs`: membership, gossip, DHT) is still simulated; M4 makes the
execution plane real, not the topology plane.

Verified: `tests/mesh_remote.rs` 3 passed — two worker processes over TCP, w1
frozen with SIGSTOP before the plan, six tasks, 300 ms leases: remote checkpoints
equal a local reference run, at least one reassignment, w1 stays `simulated` and
w2 becomes real, exactly one commit per task, and thawing w1 adds none.

## [v1.2.2] — 2026-10-23 — the mesh gets a surface

### What was wrong

The engine had a mesh module that Tallow code could not call. `src/stdlib/mesh.rs`
dispatched `mesh.*`, and `src/stdlib/mod.rs` routed it, but the interpreter's
module registry never listed it — neither in `is_stdlib_module` nor in the
module-sentinel match — so `mesh.MeshNode.new(...)` died as
"undefined variable: mesh". The entire simulated topology plane had never been
reachable from the language it is part of.

There was also no execution surface at all: the coordinator, journal, leases and
workers existed as Rust, with no declared way to reach them.

### What was fixed

- `Mesh.plan(tasks, seed)` and `Mesh.replay(journal_path)` are published in
  `stdlib/mesh.tl` and answered by `src/stdlib/mesh_exec.rs`. Planning is
  deterministic and validates task classes, missing dependencies, duplicate ids
  and dependency cycles (the refusal names the path, e.g. `a -> b -> a`).
  Replay recomputes every checkpoint and reports the first wave that disagrees.
- `mesh` and `Mesh` are registered in both interpreter tables, which is what
  makes any module callable from Tallow at all.
- `Mesh.run` is deliberately NOT declared: running a plan needs a worker pool
  executing Tallow functions, each with its own interpreter, and that executor
  does not exist. A declaration that cannot execute is the defect 1.2.0 removed.

### Counts

stdlib modules 85 → 86; function declarations 1,124 → 1,126. The gate moved in
the same commit, with the reason inline.

Verified: `stdlib/mesh.tl` checks clean (6 items); the diamond plans to 3 waves
`[1, 2, 1]`; a cycle is refused with its path; an `io` task without an
idempotency key is refused — all three through the shipped binary
(`tests/mesh_plan_tl.rs`, 3 passed).

## [v1.2.1] — 2026-10-23 — declared is what you get

### What was wrong

Six module-level browser helpers returned a primitive where `stdlib/browser.tl`
declares a struct: `page_throttle_cpu` answered `Ok(Float)` — the rate handed in,
echoed back; `page_wait_for_url` answered `Ok(Bool)`, discarding the matched URL
and the elapsed time; `page_wait_for_function` answered `Ok(Bool)`;
`page_add_script_tag` and `page_add_style_tag` answered `Ok(String)`;
`page_emulate_media` answered `Ok(Nil)`; `page_set_content` answered a bare
`Ok(Int)`. The `Page.*` methods for the same operations already built the
declared structs, so declaration, interpreter and native arms disagreed three
ways on the same call.

Second defect, found while fixing the first: the shared `WaitResult` builder had
been producing 7 of the 9 declared fields since it was written — `status` and
`event` never existed.

Third, in the build itself: a killed test run left an orphaned `chrome-headless`
(ppid 1) holding `/run/nixe-heavy-build.lock`, so `cargo test` sat parked for 15
minutes with no compiler running. Killing the orphan let the build finish in 20
seconds.

### What was fixed

- `page_set_content` → `PageContentResult { loaded, content_length }`
- `page_throttle_cpu` → `CpuThrottle { rate, applied }`
- `page_emulate_media` → `MediaEmulation { media_type, color_scheme, reduced_motion, applied }`
- `page_wait_for_url` / `page_wait_for_function` → `WaitResult`, with `matched`,
  `elapsed_ms`, and for the URL waiter the URL it matched
- `page_add_script_tag` / `page_add_init_script` → `ScriptTag`;
  `page_add_style_tag` → `StyleTag`
- `WaitResult` now carries all nine declared fields.
- Native lowering added for these seven helpers on the current-page receiver. It
  falls back to the interpreter by name when a match-arm binding's struct type
  cannot be inferred — a missing optimisation, not a wrong answer.
- Release bodies are now generated from this file and the build fails if the
  section lacks "What was wrong" / "What was fixed".

Programs that printed the old primitive now print a struct — which is what the
declaration always said. Migration surface was measured before the change: five
of the six helpers had zero call sites in the repository; the sixth had two,
both tests introduced by this work.

Verification: 6/6 browser tests, including one asserting all nine declared
fields; full lib suite 9,159 passed / 0 failed / 33 ignored.

## [v1.2.0] — 2026-10-23 — the surface stops lying

The counts were right and parts of the surface behind them were not. This release
makes the published surface executable and the manifest valid Tallow.

### Added
- **41 browser declarations now execute.** `page_extract_all_text/attrs`,
  `page_capture_dom_snapshot`, `page_structured_data`, `page_text_redacted`,
  `page_block_non_essential`, `page_wait_for_stable`, `page_detect_pagination`,
  `page_handle_cookie_consent`, ten delegations (`set_content`, `content`,
  `add_init_script`, `add_script_tag`, `add_style_tag`, `wait_for_function`,
  `wait_for_url`, `wait_for_timeout`, `throttle_cpu`, `emulate_media`), three
  event waiters, eight callback registrations, the WordPress/Wordfence set, and
  `browser_context_create`. A current-page registry in the interpreter is what
  lets a module-level helper reach a live tab.
- **Agent handles answer `status()`, `is_done()` and `cancel()`**, with
  cooperative cancellation at function-call boundaries and `spawn_await`
  reporting cancellation instead of `Ok(nil)`.
- **Grammar**: record types `{a: T}` / `{T, U}`, `fn()` without a return,
  contextual keywords in name positions, generic type aliases, and type-scoped
  function names `fn Type.member(...)`.
- WordPress fixture (`scripts/wordpress_fixture.sh`) and live-page tests that
  skip when Chrome is absent.

### Fixed
- `page.goto` reported success while the tab sat on Chromium's error page; it
  now returns a navigation failure.
- A `Page` outliving its `Browser` handle left a reaped browser and a hanging
  `Runtime.evaluate`; the interpreter retains the browser for the program's life.
- `Page.evaluate` returned every result as a string, double-quoting JS strings.
- `json.get` ignored its default argument, breaking `map.get(k, 0)`.
- `tallow check`: 85 of 85 stdlib modules now pass (was 20). 355 declarations
  moved to the spec's `native fn` form, 100 array types corrected to `[]T`, and
  the checker learned `Float`/`Int`/`Bool`/`str`.
- Native lowering for `math.asin/acos/atan/atan2/cbrt` and the integer helpers
  `abs_i/min_i/max_i/clamp_i`.

### Changed
- The published function count is **1,124**. The six-function difference from
  1,118 is `timeseries.tl`'s `method … on TimeSeries` declarations, which no
  counter ever read; nothing was added to the surface.

## [v1.1.5] — 2026-10-22 — `String.parse()` compiles

One gap, and it was the kind that only shows up when you re-measure your own
claims instead of re-reading them.

`String.parse()` had no codegen lowering. The interpreter ran it, the native
backend refused the build by name, and `--require-native` therefore rejected
every program that converted a string to a number — including
`examples/error_handling.tl`. The README said "10 programs identical on both
planes"; the honest count was nine, and that is what it said for one release.

Now lowered: `tallow_str_parse_i64` (`src/runtime/string_ffi.rs`) parses with
the interpreter's own `str::parse::<i64>`, so the accepted spelling is identical
(optional sign, ASCII digits, no whitespace, no separators, no radix prefix).
Unparseable text exits 1 with the interpreter's exact sentence,
`runtime error: cannot parse '<s>' as number`. Float text is **refused by name**
— ``native plane cannot carry it through this integer ABI; use `.to_float()` ``
— rather than truncated, because a truncation would be the silent divergence
this codebase exists to avoid; the interpreter returns `Float` there and the two
planes deliberately differ, visibly.

Verified: `examples/error_handling.tl` now runs identically on both planes
(stdout byte-identical, both rc 0), `cargo test --lib string_ffi` 3 passed,
`tests/interp_codegen_parity.rs::string_parse_*` 2 passed.

## [v1.1.4] — 2026-10-21 — green on three platforms, and no advisory left open

Seven of the ten red CI jobs were arguing about code, not about policy. This
change settles the four that were genuinely broken in the dependency tree: two
platform builds, a test that could not pass on a host without softhsm, six
regression targets nothing ran, and thirteen RustSec advisories.

### Security
- **`libcrux-aesgcm` 0.0.8 → RustCrypto `aes-gcm` 0.10 (item 6.4 reversed).**
  libcrux 0.0.8 carries RUSTSEC-2026-0209 (no AAD length limit) and
  RUSTSEC-2026-0211 (non-constant-time tag comparison); 0.0.8 is the newest
  published release and the upstream fixes are unmerged. Wire format is
  byte-identical — `tests/aes_gcm_differential.rs` proves it against eight
  ciphertexts generated from the 1.1.x libcrux backend, NIST CAVS vectors, and a
  tamper case. Measured cost on aarch64: 128.3 MB/s vs 984.6 MB/s with `+aes`
  (7.7×) — recorded in `docs/CRYPTO-FASTPATH-AUDIT.md`.
- `rustls` 0.23.45 → 0.23.46, `rustls-webpki` 0.103.15 → 0.103.16,
  `webpki-roots` 1.0.6 → 1.0.10, `webpki-root-certs` 1.0.9 → 1.0.10.
- `zip` 2.4.2 → 9.0.0 (RUSTSEC-2026-0367/-0368/-0369). The upgrade also closed a
  zip-slip: `src/browser/trace.rs` extracted entries with `zip.join(entry.name())`
  and now uses `enclosed_name()`, which refuses absolute and `..` paths.
- `cargo audit`: 13 advisories → 0. `deny.toml` gains `bzip2-1.0.6` (zip 9's
  pure-Rust bzip2 decoder) and `Apache-2.0 WITH LLVM-exception` (the cranelift
  family, reached only with the optional JIT feature), and records the
  `mach`/RUSTSEC-2020-0168 acceptance that `region` forces on macOS. Verified
  the way CI runs it — `cargo deny --all-features check` — which is what caught
  both of those; the earlier plain `cargo deny check` never saw the optional
  dependency set.

### Fixed
- **The workspace did not build on macOS or Windows.** `landlock` (Linux LSM) was
  declared unconditionally in the root and `tallow-daemon`; `landlock-0.4.7`
  calls `libc::prctl`, absent off-Linux, so both crates failed at compile. Moved
  under `[target.'cfg(target_os = "linux")'.dependencies]`.
- **`crypto::test_hsm_list_slots` failed on every host without softhsm.** It
  unwrapped `Hsm.list_slots()`, which correctly returns "no PKCS#11 provider
  module found". Now skips on that environmental error and still fails on any
  other.
- **Six regression targets ran in no pipeline**: `exit_in_conditional`,
  `fs_read_file_native`, `native_fn_decl`, `optional_implicit_wrap`,
  `optional_match_unwrap`, `script_mode`. Added to the contract job;
  `check_test_coverage.py` now reports `103 targets: 66 in CI, 37 excluded with a
  reason, 0 unaccounted`.
- **Clippy job could not start**: the workflow installed clippy for `stable`
  while `rust-toolchain.toml` pins 1.98.1. Job now pins the same toolchain.

### Changed
- `scripts/sbom.snapshot.json`, `scripts/crypto-inventory.json` and
  `crates/CANONICAL-SYNC.sha256` regenerated (204 pinned files) — all three drift
  gates pass.
- `docs/PGO.md`, `scripts/pgo_ab.sh`, `benchmarks/cliff-probe` re-measured against
  `aes-gcm`; the old 111/973 MB/s figures described a backend that no longer ships.

### Fixed (cross-platform)
- **The crate did not compile for Windows.** Fifteen `std::os::unix` /
  `libc` uses sat outside any `cfg` gate. Each now has a real branch or an honest
  refusal, not a stub that pretends to work:
  - `sluice.rs` receipt-log lock: `libc::flock` → `File::try_lock`/`unlock`
    (flock on Unix, `LockFileEx` on Windows), same semantics, no `unsafe`.
  - `cli/secrets_cmd.rs` masked prompt: hand-rolled `termios` →
    `console::Term::read_secure_line` (already in the dependency graph); the
    0600 write is `cfg(unix)`-gated with a note that Windows inherits the
    directory ACL.
  - `stdlib/secrets.rs` store write: same 0600 gate.
  - `sandbox_runtime`: Unix implementation behind `cfg(unix)`; the non-Unix
    module exposes the same five entry points and returns `Err`, because a
    `run_sandboxed` that returned `Ok` would claim a confinement that is not
    there.
  - `browser/juggler.rs`: the `pre_exec` + fd 3/4 pipe launch is `cfg(unix)`;
    on Windows `launch` refuses and names the Chromium/CDP backend.
- **The crate did not compile for macOS.** `RlimitResource` was keyed on
  `not(target_env = "musl")`, so it selected glibc's `__rlimit_resource_t` on
  Apple targets too; now keyed on `target_env = "gnu"`. `sandbox_pass`'s seccomp
  call was a `cfg!()` runtime test around a `#[cfg(target_os = "linux")]`
  function — a `cfg!()` never removes the call site; it is now a real `cfg` split,
  and the syscall-table test is Linux-gated.

### Fixed (platform test parity — the rest of the red)

The first pass above made the crate *compile* off Linux. These are the failures
that were left once it ran there.

- **Accepted sockets inherited the listener's non-blocking mode.** A listener is
  set non-blocking so its accept loop can poll; on Windows and macOS the socket
  returned by `accept()` inherits that state (on Linux it does not). The first
  read returned `WouldBlock`, each server treated it as a closed client and
  dropped the connection unread, and the peer reported `EINVAL` (macOS) or
  `WSAECONNABORTED`/10053 (Windows). Three sites:
  - the two hand-rolled mock servers in `browser::crawl_pipeline` (7 Windows and
    2 macOS test failures) — `set_nonblocking(false)` on the accepted socket;
  - **`browser::observability::serve_metrics` — shipping code.** On macOS a
    Prometheus scrape of the metrics port got a zero-byte response. Same fix,
    with the reason at the call site.
- **`sluice`'s receipt log locked the data file, which Windows refuses to share.**
  `LockFileEx` is a mandatory lock, so every reader of the KT log got
  `os error 33` (11 Windows failures). The lock moved to a `<log>.lock` sidecar;
  the log itself is never held while being read.
- **Four macOS tests asserted platform assumptions, not product behaviour**:
  a 50 ms heartbeat interval that overshot to 157 ms on a loaded runner (now
  2 s), a hard-coded `linux-arm64` install directory (`BrowserPlatform::detect()`),
  Landlock paths compared uncanonicalised (`/var` vs `/private/var`), and JA4T
  expected to be `derived` on a platform where it is correctly `unavailable`.
- **Windows fixture failures**: `File::open()` then `set_modified` (Access
  denied), `PATH` joined with `:` instead of `;`, a TOML fixture carrying a
  backslash path, and provenance paths normalised with `\` instead of `/`.
- **`browser_install_dir` ignored `TALLOW_DATA_HOME`**, which is the only
  writable location macOS and Windows give an installed tool.

### Fixed (production gates)

- **`Tallow Production CI Gates` could never pass.** Its gate list invoked
  `scripts/phase1_smoke_ladder.py`, which existed only in the older Nixe
  workspace and was never carried into this repository, so `p2-006-phase1-smoke`
  exited 2 on every commit. The ladder is now part of the tree and passes
  (17 rungs, `pass=17 warn=0 fail=0`); its generated receipt is gitignored.

### Verified

- CI run `39655436215` on `1836329f`: **17 of 17 jobs green**.
- `Tallow Production CI Gates` run `39655436090` on the same tree: success.
- Tests: Linux 9,145 / macOS 9,140 / Windows 9,108 — zero failures on each.
  The 33 ignored tests are the same set everywhere (mesh-only and
  privileged-environment cases).
- `docs/operations/PLATFORM-PARITY.md` states, per platform, what builds, what
  runs, and what refuses on purpose.


## [v1.1.3] — 2026-10-21 — three defects a five-line script found

Two example scripts for the language repository turned over three codegen and
packaging defects in an hour. None was visible to the suite: no test in it read a
file, exited from a conditional, or passed an argument to a program.

### Added
- **A `.tl` file is a program.** `tallow app.tl` runs it; a `#!/usr/bin/env tallow`
  shebang is accepted (the line is blanked, not stripped, so spans still index the
  original source); arguments after the path belong to the program
  (`./wc.tl notes.txt` becomes `tallow run wc.tl -- notes.txt`).

### Fixed
- **`fs.read_file` had no native plane (#138).** The "could not open" report was
  emitted from the ok block using a buffer defined in the fail block — invalid IR,
  so clang 18 died in the register coalescer and every file-reading program fell
  back to the interpreter. The report now lives on the fail path; the ok path
  compares `fread()` against `st_size` and fails loudly on a short read.
- **`exit()` inside a conditional produced invalid IR (#139).** `process.exit(n)`
  emits `unreachable`, after which the enclosing `if` appended a dead `br`.
  `emit_line` now drops a branch when the current block already ends in a
  terminator.
- **`install.sh` advertised "latest" and installed 1.1.1 (#140).** `VERSION` was a
  literal, so it requested an asset that never existed. It now resolves
  `/releases/latest` after argument parsing and exits 2 with a usable message when
  it cannot.

## [v1.1.2] — 2026-10-21 — a Result cannot be dropped

### Fixed
- **A discarded `Result` was silent success (#133).** Both planes now run the same
  rule: a `Result`-valued call whose value nobody reads, in a non-final statement
  of a block, is checked — `Err` writes to stderr and exits 1.
- **`match` on a `T?` now compiles (#134).** The payload type comes from the
  callee's signature instead of being refused.
- **Returning a computed value from a `-> T?` function was refused on the native
  plane (#135).** `coerce` now boxes any non-optional value whose slot is optional;
  unwrapping (`T?` → `T`) is still refused, because it needs a check the compiler
  cannot invent.

### Changed
- Register rows #129, #130 and #132 were re-measured rather than restated; see
  `docs/operations/stub-register.md` for the corrected premises.

## [v1.1.1] — 2026-10-10 — the deployment's fix, landed (prepared on `v1`, local-only)

v1.1 released a gate whose deployment ran a fix the release did not contain. The installed binary had been
built from the live tree plus a patch binding a **read-only open** into `sluice verify`, and that patch — the
one that makes the anchor control deployable at all — existed in no commit. The release therefore could not
reproduce the binary its own deployment depended on.

### Fixed
- **`KtLog::open_read_only` is in the tree.** `verify` and `verify_segment_close` take a read handle on the
  receipt log instead of a write handle, so the account that checks the log is no longer an account that can
  rewrite it.

### Known gap, recorded rather than hidden
- The running deployment still describes its binary as built from a live patched tree, so it is not yet
  reproducible from a revision. Re-deploying from this tag closes that, and the deployment-provenance gate
  is the mechanism that will say so.

## [v1.1] — 2026-10-10 — the cross-domain release gate (prepared on `v1`, local-only)

Adds **Sluice**, a cross-domain release gate: one decision over whether material may cross a domain
boundary, with failures attributed to the BOUNDARY MODEL rather than to the material. Cross-domain transfer
failures are failures of the boundary, not of what is being transferred.

### The gate
- **Stage order is frozen**: plan+lineage → channel admit → channel obligations → class gate → caveat gate
  → release+receipt. `exit 0` = ALLOW, `exit 1` = DENY.
- **14 emittable deny codes**, each with a stable machine-readable form so a caller can tell a boundary
  refusal from an infrastructure failure.
- **Receipts are digest-only** and hash-chained into the existing KT log — no sidecar, no plaintext.
- **CLI**: `check` / `channels` / `explain` / `release` / `verify` / `rotate`.

### Verification
- A **30-gate regression battery** (`tools/regression_gates.sh`) runs over both the deliverable and the
  product: a clean-checkout build gate, a deployment-drift gate, and auditors that re-derive every count,
  citation and path the documents state rather than trusting them.
- **124 defects** found and recorded across 45 waves, each with its reproduction and severity.

### Deployment
- Installed and running on the reference host: daily rotation, hourly divergence monitoring, hourly anchor
  recording. Each is proven by a real run, not by its unit being enabled.

### Release identity
- Tag `v1.1` pairs with Cargo version `1.1.0`. Release identity remains **local-only (R0)** per R-03.
- This entry covers the gate and its verification. Other work on the `v1` line between the freeze and this
  tag is recorded in the commit history rather than summarised here.

## [v1.0] — 2026-09-14 — V1 freeze (prepared on `v1`, local-only)

The first V1 freeze candidate, assembled through the R-08 execution program
(batches 1–4) on branch `v1` (17 checkpoint commits B0–B16, tip `fea1029`),
verified by batteries 2–9. Not a public release; tag + archive mechanics per
`docs/release/` and decision R-03/D6.

### Identity fabric (W3)
- **SVID workload identity** — certs, issuer, relay mutual-auth, zero-trust policy
  pack (`W7201–W7203`), short-lived scope-bound workload tokens, sector pseudonyms.
- **Enrollment ceremony** — two-sided SAS-based enrollment with single-use
  SPKI-bound tokens and honest attestation (`src/enrollment.rs`, `pake/sas.rs`).
- **Revocation** — signed revocation lists with TTL-bounded staleness, checked at
  the daemon handshake seam (refuse new sessions; established sessions
  untouched per D-4); KT-logged.
- **Recovery** — offline custody shares (Shamir, k≥2 distinct custodians),
  dual-control recovery with root-commitment verification, root-rotation
  ceremony (Ed25519 approvals, no self-approval, re-verify-at-execute,
  retired roots never re-anchored); honest-unrecoverable doctrine; KT-logged.
- **Persona firewall** — enforcement layer with typed findings/refusals.

### Key transparency
- Append-only BLAKE3 KT log with signed tree heads, inclusion and consistency
  proofs; event payloads committed by hash (caller-held evidence). Wired into
  enrollment, recovery and revocation flows.

### Config kernel
- Layered scopes (KB-2), versioning/migrations (KB-3), signed config bundles
  (Ed25519; verify-before-load), secure-by-default lint pack.

### Crypto & supply chain
- AEAD upgrades (agent channel v2; CredentialVault), Argon2id single-source
  parameters, AEGIS gating, constant-time test harness + procurement rule,
  cargo-vet trust foundation, SBOM/CBOM drift gates.

### Transport, egress, measurement
- TallowTransfer relay end-to-end + delta-sync resume; transport fallback and
  bandwidth limits; fail-closed Tor egress (direct is an explicit opt-in);
  browser/measurement readiness for the D4 calibration run.

### Compliance
- Compliance report generator with CRA 24h / CERT-In 6h early-warning clocks
  and ZNISM self-assessment output.

### Gates & process
- `release_gate.sh` acceptance battery (`--twice`, `--quick`, evidence archive),
  `never_check.sh` (static + cargo + optional live egress), `kev_gate.sh`,
  claims-ledger gate; freeze chain F-01…F-08 defined.

### Known limitations (honest, per freeze review)
- Live calibration run **R-01** pending (windows A/B); cost/perf multipliers stay
  `[target-only]` until then.
- SLIP-39 mnemonic leg blocked (no offline crate/wordlist) — recorded, not built;
  FROST k-of-n authorizer dep-gated; mesh/swarm legs are W5 by design.
- Release identity is local-only (no remote, no CI execution); non-Linux targets
  not exercised on this host.
