# Platform build and test — five release targets, three test legs, one rule

How this repository builds and tests Tallow across platforms, and what each
platform-specific decision buys. Scope: the root workspace (`package tallow`,
MIT — see `LICENSE`). Companion reading: `docs/RUN-ENGINES.md` (interpreter vs
native plane), `docs/FAILURE-ATTRIBUTION.md` (how a red test is labelled),
`.github/workflows/ci.yml` and `.github/workflows/release.yml` (the sources this
page describes).

Every number and path on this page was read out of the tree at `758e5bc`
(version `1.7.0`, `Cargo.toml:3`). Where a fact could not be established from
the tree, the sentence says **unverified** and what would settle it. Nothing
here is a measurement of a build I ran: see the last section.

## 1. The five release targets

`.github/workflows/release.yml` builds a release matrix of exactly five entries
(`release.yml:203-225`):

| label | runner (`os`) | rust target triple |
|---|---|---|
| `linux-x86_64` | `ubuntu-24.04` | `x86_64-unknown-linux-gnu` |
| `linux-aarch64` | `ubuntu-24.04` | `aarch64-unknown-linux-gnu` |
| `macos-x86_64` | `macos-15` | `x86_64-apple-darwin` |
| `macos-aarch64` | `macos-15` | `aarch64-apple-darwin` |
| `windows-x86_64` | `windows-latest` | `x86_64-pc-windows-msvc` |

Two properties of that matrix are deliberate and load-bearing:

- **Linux ships GNU, not musl.** The comment at `release.yml:205-210` records
  the reason with a date: the C++ dependency stack (`btls-sys`) is compiled with
  the host C++ compiler, which emits glibc-only fortified symbols
  (`__snprintf_chk`, `__memcpy_chk`, `__isoc23_strtoul`), so a musl link fails
  unless a musl C++ cross toolchain is present, and Ubuntu ships `musl-gcc`
  without `musl-g++`. Measured 2026-10-20. As a consequence the
  `x86_64-unknown-linux-musl` and `aarch64-unknown-linux-musl` rustflags that
  `.cargo/config.toml` still carries (section 3) are **not** exercised by this
  repository's release workflow. `.cargo/config.toml:63` says they exist because
  *"Nixe's release.yml publishes aarch64-unknown-linux-musl and
  aarch64-apple-darwin"* — a tree outside this repository. Whether that workflow
  still publishes musl artifacts, and whether `x86_64-unknown-linux-musl` is
  built by anything at all, is **unverified** here: nothing in this tree
  references it.
- **The toolchain is pinned to `1.98.1` and the target's std is installed
  explicitly.** `rust-toolchain.toml` pins `channel = "1.98.1"`; the release
  build asks `dtolnay/rust-toolchain` for `toolchain: 1.98.1` with
  `targets: ${{ matrix.target }}` (`release.yml:241`). The comment there
  records why: asking for `stable` installs std for the cross targets against
  *stable* while cargo then runs the pinned 1.98.1, so every cross build died
  with `E0463 can't find crate for core` (measured 2026-10-21).

A tag builds, checksums and signs the five archives and stops at a **draft**
release; publishing is a separate `workflow_dispatch` with `inputs.publish=true`
(`release.yml:3-19`).

## 2. The rule: unix-only code is `cfg(unix)` with a REFUSING stub

When a capability depends on a Unix facility, the platform split is not
`#[cfg]`-away the function. The Unix code lives behind `#[cfg(unix)]` and every
other platform gets a stub with **the same signatures that returns `Err`/refuses
by name**. A stub that returned `Ok(())` would tell the caller the work happened
when it did not.

The two canonical examples in this tree:

**`sandbox_runtime`** — `src/lib.rs:168-174` selects the module:

```text
#[cfg(unix)]
pub mod sandbox_runtime;
#[cfg(not(unix))]
#[path = "sandbox_runtime_nonunix.rs"]
pub mod sandbox_runtime;
```

`src/sandbox_runtime_nonunix.rs` (48 lines) exposes the same five entry points —
`install_seccomp`, `install_landlock`, `install_landlock_rw`, `run_sandboxed`,
`run_sandboxed_rw` — and each returns `Err` carrying one shared `WHY` string:
*"sandboxing (seccomp-BPF + Landlock) is a Linux kernel feature; this build
targets a platform without it"*. Its module doc states the design rule directly:
a `run_sandboxed` that quietly returned `Ok(())` would tell the caller the child
is confined when it is not.

**The Juggler pipe** — `src/browser/juggler.rs:217-236` keeps `launch` under
`#[cfg(not(unix))]` as a refusal: the Firefox/Camoufox `-juggler-pipe` transport
hands the browser descriptors 3 (commands in) and 4 (responses out), which are
only expressible as inherited file descriptors on a Unix-like OS, so the stub
returns `BrowserError::ConnectionFailed` naming the working alternative (the
Chromium/CDP backend).

The same shape recurs at 38 sites (`grep -rn 'cfg(not(unix))' --include=*.rs src
crates | wc -l`). These are representative, not exhaustive:

| site | Unix facility | what the non-Unix side does |
|---|---|---|
| `src/logging.rs:296,317` | an owner-only private directory and an append-only open with Unix permission bits | plain `create_dir_all` / `OpenOptions::append` — the file is still created and appended to, and the platform-specific permission promise is simply not claimed |
| `src/browser/process.rs:338-343` | `--remote-debugging-pipe` fd 3/4 wiring | returns `ConnectionFailed` naming WebSocket CDP as the alternative |
| `src/stdlib/process.rs:85-88` | a process-liveness probe | `Err("Process.is_running: handle is not tracked and this platform has no probe")` — a refusal by name |
| `src/config/write.rs:464,491,501,555` | owner-only directory/file creation | the creation still happens; the *permission* tightening does not, and the code says so by compiling the perms out |

The rule is checked, not just documented: CI compiles every target on Windows
(section 4), and `cargo check --locked --workspace --all-targets` on
`windows-latest` is the step whose comment (`ci.yml:147-152`) records that
unix-only code compiled for a Windows target has broken this tree twice.

## 3. Per-target rustflags (`.cargo/config.toml`)

The file sets `[build] jobs = 8`, `incremental = false` (build-time, not
platform), and then a `[target.*]` table per triple. The flags are not a tuning
knob: they move the shipped binary off a **silent** bitsliced fallback.

| triple | rustflags | why |
|---|---|---|
| `aarch64-unknown-linux-gnu` | `-C target-feature=+aes`, `--cfg aes_armv8` | libcrux-aesgcm picks its ARMv8 AES path from the target feature (111 MB/s vs 973 MB/s without — the comment's measured figure); RustCrypto `aes` 0.8 is inert without `--cfg aes_armv8` |
| `aarch64-unknown-linux-musl` | same two | the same cliff on a target that cannot inherit the gnu table |
| `aarch64-apple-darwin` | same two | same |
| `x86_64-unknown-linux-gnu` | `-C target-feature=+aes,+avx2,+pclmulqdq` | libcrux's x64 AES path, its `simd256` impl, and `libcrux_platform::pmull_support()` for GHASH (applied 2026-10-16, sheet U-F12) |
| `x86_64-unknown-linux-musl` | same three | same |
| `x86_64-apple-darwin` | same three | same |
| `x86_64-pc-windows-msvc` | same three | same; the lld `link-arg` line above it is commented out |

Three things a reader must not miss:

- **`+` adds to the default feature set**, so `crt-static` and x86_64's baseline
  SSE2 are preserved. The cost is a hard floor: an x86_64 binary built here
  requires AES-NI + AVX2 + PCLMULQDQ (Intel Haswell 2013+, AMD Excavator
  2015+) and will fault on older CPUs. `+aes` on aarch64 requires the ARMv8 AES
  extension. That trade was decided explicitly by the operator on 2026-10-16
  (`.cargo/config.toml:98`, "COMPATIBILITY CALL") and is written into the
  config, not implied by it.
- **Exporting `RUSTFLAGS` makes cargo ignore this entire table.** The config
  repeats that warning at both sites (`.cargo/config.toml:37` and `:53`). A
  build environment that sets `RUSTFLAGS` silently measures and ships the slow
  path. Neither workflow sets `RUSTFLAGS` at workflow or job level (checked: the
  only occurrence is a comment at `ci.yml:48` explaining why it is not set).
- **No `--cfg aes_armv8` on x86_64.** It is RustCrypto's ARM opt-in and means
  nothing there; adding it would only add an unintended cfg.

The config's own comment (`.cargo/config.toml:55-58`) records one tuning attempt
that was refused: `-C link-arg=-fuse-ld=gold` was tried on 2026-10-16, it links,
but cargo prints *"the gold linker is deprecated and has known bugs with Rust"*,
so it was reverted. `lld` and `mold` are not installed on the box the config was
written on; installing one is a package change, not a config change.

## 4. The CI matrix: what each job proves

`.github/workflows/ci.yml` defines 24 jobs (24 block-level keys under `jobs:`).
Counted on this tree by parsing the YAML rather than reading it. The
brief's matrix — check, test-linux, test-windows, test-macos, parity, clippy,
audit, deny, sbom, cbom — is a subset; **there is no job called `cbom`**. The
CBOM gate is `cbom-drift`, and `sbom` (artifact generation) is distinct from
`sbom-drift` (the blocking comparison). The full set is below so the subset
cannot be mistaken for the whole.

### The five platform-critical jobs

| job | runner | command it runs | what it proves |
|---|---|---|---|
| `check` | `ubuntu-latest` | `cargo check --locked --workspace --all-targets` | the whole workspace, including every test target, type-checks. It gates `test-linux`, `test-windows`, `test-macos`, `zero-trust-conformance`, `contract-cli`, `structured-logging`, `conformance`, `browser`, `wordpress-fixture`, `parity`, `perf-regression` (all `needs: check`) |
| `test-linux` | `ubuntu-latest` | `cargo test --locked --lib -- --test-threads=4`, then `scripts/attribute_failure.py` on failure | the ~9k-test lib suite on the host platform, and — when it fails — a *proven* label of pre-existing vs caused-by-this-run (the base revision is rebuilt; `fetch-depth: 0` exists for that) |
| `test-windows` | `windows-latest` | PRs: `cargo check --locked --workspace --all-targets`. main/tags: `cargo test --locked --lib -- --test-threads=4` | the **compile plane** on every PR — unix-only code that does not build on Windows fails here — and the full suite on main and tags. The split is stated in the job comment: the leg is the wall on every run (10.8-11.4 min), so PRs compile every target and skip execution |
| `test-macos` | `macos-latest` | `cargo test --locked --lib -- --test-threads=4` | the lib suite on Apple's toolchain |
| `parity` | `ubuntu-latest` | `tests/parity/run_parity.sh`, after `cargo build --locked --bin tallow` and installing `clang liblzma-dev libbz2-dev`; `DIVERGE` fails the job | that the interpreter and the native plane agree on the fixture corpus. The runner defaults `TALLOW` to `target/debug/tallow` (`run_parity.sh:18`), so the plain binary build suffices; the native link dependencies are installed at `ci.yml:652-670` |

Note on `test-windows`: on a PR it does **not** run the test suite. A Windows-only
runtime failure that compiles cleanly will not be caught before merge; it is
caught on the next push to main or on the tag. That is a deliberate, documented
trade, not an oversight.

### The quality and composition gates

| job | proves |
|---|---|
| `clippy` | `cargo clippy --locked --all-targets -- -W clippy::all` under **1.98.1** (not `stable` — installing the component only for `stable` left it absent for the pinned toolchain) |
| `audit` | `cargo audit --file Cargo.lock` over the dependency graph (`.cargo/audit.toml` ignore list); the job's own exit status is the verdict — the rustsec/audit-check action was dropped 2026-11-05 because it posted a second, differently-cased check run and its job stayed green regardless |
| `deny` | `cargo deny check --all-features` (blocking advisory verdicts), plus `scripts/check_deny_expiry.py` — the ignore lists carry review deadlines that nothing read before 2026-10-31 |
| `sbom` | generates CycloneDX SBOMs (`tallow.sbom.json`, `tallow-crypto.sbom.json`) and uploads them as an artifact. It proves generation, not freshness |
| `sbom-drift` | `scripts/sbom-gen.py --check scripts/sbom.snapshot.json` — the committed inventory byte-matches regeneration. **This** is the blocking one |
| `cbom-drift` | `scripts/crypto-inventory.py --check scripts/crypto-inventory.json` — the crypto inventory byte-matches regeneration, every crypto-shaped token is covered by the agility registry, and no active registered algorithm has vanished from source. Stdlib-only python3, no toolchain, no network |
| `claims-ledger` | `scripts/claims_ledger_check.py`; accepts rc 0 or 2 (warnings-only baseline) |
| `canonical-pins` | `sha256sum -c crates/CANONICAL-SYNC.sha256`, the manifest is regenerable, and the manifest names repositories rather than filesystem paths |
| `wire-conformance` | the room-id derivation matches its committed vectors, in the crate and on the language surface, on both engines |
| `perf-regression` | `benchmarks/run_compiler_parser.py` over `examples/*.tl`, then `scripts/no_regression_gate.py` on target ranges plus the platform-independent baseline counts. Timing is deliberately **not** gated on the x86_64 runner against the committed aarch64 baseline — the skip is printed, and an unknown arch fails closed |

### Feature-gated builds

| job | proves |
|---|---|
| `mls-feature` | `--features mls` compiles and `examples/mls_probe.rs` drives create→add→join→encrypt→process, **and** the default build still refuses `crypto.mls_*` by name (`grep -q "features mls"`) |
| `zk-feature` | `--features zk` tests, **and** the default build refuses `crypto.zk_*` by name. Run with `--interpret` on purpose: there is no ZK native lowering, so `--require-native` would fail on that first and the feature message would never appear |
| `fhe-feature` | `--features fhe` lib tests (`fhe::`) |

### Suites that need more than a compiler

| job | proves |
|---|---|
| `zero-trust-conformance` | `cargo test --test zero_trust_conformance -- --test-threads=1` — negative boundary probes: browser-zone predicate refusals, non-loopback CDP connect refusals, the CDP relay's 8 MiB frame cap. Loopback only, no network |
| `contract-cli` | the integration suites `cargo test --lib` cannot see (58 of 60 `tests/*.rs` targets ran in no pipeline before this job existed), plus the static gates: capability registry matches the code, every test target is run or explicitly excluded, every DONE backlog row cites a real path, and `scripts/docs_examples.py` (G59) executes every `run`-marked doc example and fails an unmarked block |
| `structured-logging` | `cargo test --test structured_logging -- --test-threads=2`; each case drives the real binary on the interpreter plane because the level/format/sink state is process-wide |
| `conformance` | `cargo test --test conformance_runner`, pinned to the just-built binary via `TALLOW_BIN`. Was release-only until 2026-10-23 |
| `browser` | the browser suites that pass on the pinned Chrome for Testing build |
| `wordpress-fixture` | the `wp_*` browser helpers against a real WordPress fixture |

`deny`, `audit`, `sbom*`, `cbom-drift`, `claims-ledger`, `clippy` and the
`*-feature` jobs have no `needs:` — they start immediately and do not wait for
`check`.

### What CI does *not* check

- **`cargo fmt`.** Not a job. The header comment (`ci.yml:22-24`) records the
  measurement: `cargo fmt --all -- --check` reports 7,902 files and 121,519 diff
  lines, i.e. rustfmt has never been run across this workspace. That is a
  repo-wide style decision, deliberately not made in passing.
- **`cargo vet`.** Inputs are carried (`supply-chain/`), the ledger is empty, so
  there is nothing to certify against. Not wired.
- **`RUSTFLAGS: -D warnings`.** Deliberately not set: the tree carries a
  pre-existing warning baseline (159 in the lib target alone), so `-D warnings`
  would fail every cargo job on warnings predating this repository. Making
  warnings blocking is a separate work item.

## 5. Building locally

The commands CI uses, in the order it uses them:

```text
cargo check --locked --workspace --all-targets        # the compile plane
cargo test  --locked --lib -- --test-threads=4        # the unit suite
cargo build --locked --bin tallow                     # the binary
cargo build --locked --lib --bin tallow               # + target/debug/libtallow.a for the parity runner
```

`--locked` everywhere: CI runs against the committed `Cargo.lock`. A local
`cargo test` without `--locked` can resolve a different graph and will not
reproduce a CI result.

Native-plane work needs `clang liblzma-dev libbz2-dev` on Linux — without them
every native test fails at link time with `cannot find -llzma`, which reads as a
code defect and is not one. The static gates are plain `python3`:

```text
python3 scripts/check_backlog_evidence.py          # every DONE backlog row cites a real path
python3 scripts/docs_examples.py                   # every ```tallow/```tl block is marked and `run` ones execute
python3 scripts/check_test_coverage.py             # every test target is run or explicitly excluded
```

`scripts/check_backlog_evidence.py` exits 0 on a clean tree and 1 otherwise; a
`path:line` citation fails when the symbol named beside it is not on that line.

`scripts/docs_examples.py` needs a binary from **this** tree: it looks for
`--bin PATH`, then `TALLOW_BIN`, then `target/debug/tallow`, then
`target/release/tallow`, and deliberately refuses to fall back to a `tallow` on
`PATH` — a PATH binary is a different build, and running the docs against it
reports the repository's examples as wrong when only the binary was. Run
`cargo build --bin tallow` first, or the script exits saying it has no repo
binary to use.

Two of the three static scripts above were run for this page and are quoted
from real output, not from the workflow: `check_backlog_evidence.py` exited 0
after the G07 fix described in `reports/w13-TAG.md`, and
`check_test_coverage.py` printed *"189 targets: 183 in CI, 6 registered as debt
(host 3, perf 3), 0 unaccounted, 0 registry problem(s)"*. `docs_examples.py` was
**not** run to completion: it needs a built `tallow` binary and this lane does
not run cargo, so it exited 1 with exactly the refusal quoted above:

```text
$ python3 scripts/docs_examples.py
docs_examples: no repo tallow binary — build it (cargo build --bin tallow) or set TALLOW_BIN; refusing to fall back to a `tallow` on PATH, which is a different build
exit=1
```

## 6. What this page did not verify

- **No build was run for this page.** Every command above is quoted from
  `.github/workflows/ci.yml`; none of the outputs shown in the YAML comments
  (timings, test counts, the 111/973 MB/s figures) were re-measured here. They
  are cited to the file and line that records them.
- **No CI run was observed.** "Green" claims in this page describe what the
  workflow *is written to do*, not a run I saw. Whether the current `main`
  passes all 24 jobs is **unverified** — the job comments record the state at
  their revision.
- **The musl targets** are in `.cargo/config.toml` but in no release matrix
  here; whether anything ships them is **unverified**.
- **`macos-latest` vs `macos-15`**: CI tests on `macos-latest`, the release
  builds on `macos-15`. The runner image those resolve to at any given time is
  GitHub's to change and is **unverified** here.
