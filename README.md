<div align="center">

# Tallow Extraction Engine

**A schema you write once, applied to a page you already have — no model, no API key, no network.**

![status](https://img.shields.io/badge/status-1.1.4-informational?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)
![rust](https://img.shields.io/badge/rust-1.98.1-dea584?style=flat-square&logo=rust&logoColor=white)
![backend](https://img.shields.io/badge/backend-LLVM%20%C2%B7%20clang%2018-2d2d2d?style=flat-square)
![artifact](https://img.shields.io/badge/linux--aarch64-stable-2ea44f?style=flat-square)

[Extraction](#extraction-in-five-minutes) · [Install](#install) · [The language](#the-language-underneath) · [Architecture](#architecture) · [Build](#building-from-source) · [Deploy](#hosting-and-deployment) · [Limits](#what-it-does-not-do-yet)

</div>

---

This repository is **the extraction engine of the Tallow language/runtime, published as the source tree it lives in.** Tallow is a statically typed systems language with an anti-bot scraping and OSINT runtime; this line of work is the schema-first extraction stack — its bindings in the compiler, HAR import, provenance records, and the CLI verbs that drive them.

Two properties shape everything here.

**Extraction is schema-first and local.** A contract is applied to an HTML file you already have. No LLM, no API key, no engine, no egress. The model-backed tier exists for pages a selector cannot cover, and it stays off until you name an engine and a policy that permits the transfer.

**Nothing fails quietly.** A page that misses a required field writes no row and exits `1`. A refusal names its reason. A short read is an error, not a truncated string.

## Extraction in five minutes

```console
$ cargo build --bin tallow        # or install a release, below

$ ./target/debug/tallow schema check \
    schemas/tallow/examples/product-listing.extraction.schema.json
ok: … — tallow.extraction_schema.v1, 3 field(s)

$ ./target/debug/tallow extract \
    --schema schemas/tallow/examples/product-listing.extraction.schema.json \
    --html /tmp/product.html --out /tmp/out
extract: 1 item(s) → 1 row(s)
  rows:       /tmp/out/run-<pid>.rows.jsonl
  quarantine: /tmp/out/run-<pid>.quarantine.jsonl
  schema: example.product_listing.v1 (no egress performed)
```

[measured 2026-10-22 · release `v1.1.4` · `schema check` exit 0; `extract` exit 0 with one row, empty quarantine]

Each line of `run-<pid>.rows.jsonl` is a `tallow.extraction_row.v1` object. Every field records its `value`, the `selector` that produced it, its `selector_kind`, its `confidence`, and `source_evidence` — a row you can argue with rather than only trust. A field that cannot be filled at the required confidence is quarantined instead of becoming a plausible guess.

`tallow schema check` is the gate to run in CI before a run depends on a contract. `tallow plan dry-run <manifest>` prints exactly what would be fetched and performs no egress; it refuses a manifest whose requests omit their `compliance` block.

## The model-backed tier — optional, off by default

For pages a selector cannot cover — layout that changes per visitor, content behind client-side rendering — there is an engine-agnostic extraction tier. It is off until an engine is named, and it refuses a third-party transfer that no policy permits:

```console
$ export TALLOW_LLM_ENGINE=ollama
$ export TALLOW_LLM_BASE_URL=http://localhost:11434
$ export TALLOW_LLM_MODEL=llama3
$ export TALLOW_LLM_PII_POLICY=no-pii     # required before content leaves the box
```

A loopback endpoint needs no policy; anything outside the box's zone needs one, and the refusal is by name rather than a silent downgrade. Spend is capped per run (16 model calls / 400k prompt characters); past the cap the tier refuses instead of continuing.

The credential resolves from vault custody first, then the environment — never from `argv`, never from a `.tl` literal:

```console
$ tallow secrets set tallow-llm-api-key --origin https://your-endpoint   # echo off; 0600
$ tallow secrets list
```

There is deliberately no `--password` flag: a secret on the command line is a secret in `ps` and in shell history.

## What this is not

- **Not SendTallow.** The file-transfer product is a separate surface.
- **Not Sluice.** The cross-domain release gate is a separate published deliverable.
- **Not a standalone package.** The FFI and codegen lowering arms live in the compiler and the declared surface lives in `stdlib/browser.tl`; the workspace is what builds.
- **Not an anonymous scraper.** This repository carries the egress *policy*. The plane that makes traffic anonymous — deny-by-default SOCKS chokepoint, allowlist, Tor configuration, in-container firewall — is a separate repository. Neither is a working anonymous scraper without the other, and no claim here says otherwise.

## Install

### One line (linux-aarch64)

```console
$ curl -fsSL https://raw.githubusercontent.com/aamirmanisa/tallowsphere/main/install.sh | bash
```

The installer resolves the newest release, verifies the checksum, unpacks **both** `tallow` and `libtallow.a`, then compiles and runs a probe program before reporting success:

```console
fetching https://github.com/aamirmanisa/tallowsphere/releases/download/v1.1.4/tallow-linux-aarch64-1.1.4.tar.gz
tallow-linux-aarch64-1.1.4.tar.gz: OK
installed tallow 1.1.4 into /root/.local/bin
probe ok — native compile and run work
```

[measured 2026-10-22 · release `v1.1.4` · commit `0dfad23a52`]

```console
$ curl -fsSL …/install.sh | bash -s -- --prefix /usr/local
$ curl -fsSL …/install.sh | bash -s -- --version 1.1.4
$ ./install.sh --from ./tallow-linux-aarch64-1.1.4.tar.gz    # air-gapped
```

### What the machine needs

| Requirement | Why | Detail |
|---|---|---|
| **clang** | Tallow emits LLVM IR and asks `clang` to assemble and link it | 14–18; 18.1.3 is what every measurement here used. Override with `TALLOW_CLANG` |
| **linux-aarch64** | The only platform with a published build | Everything else: [build from source](#building-from-source) |
| **~575 MB disk** | 46 MB compiler + 527 MB static archive | The archive is not optional: every program links against it |

`clang` is required at **run time**, not only at build time — the compiler invokes it for each program it builds. A machine without `clang` can execute pre-built binaries but cannot compile anything.

### Check the install

```console
$ tallow --version
tallow 1.1.4
  platform: linux
  arch: aarch64
  build: 2026-10-21T23:30:51Z
  git: 0dfad23a52
```

The `git:` line is provenance: a release artifact reports the commit it was built from, and a debug build reports `(dirty)` so the two are distinguishable.

## The language underneath

The extraction stack is written in Tallow and lowered by Tallow's compiler, so the language is not a detail of this repository — it is the trunk.

```tallow
fn main() {
    let names = ["ada", "grace", "edsger"]
    for name in names {
        print("hello, " + name)
    }
}
```

```console
$ tallow run hello.tl
hello, ada
hello, grace
hello, edsger
```

**Two execution planes, one language.** Every program runs in the interpreter (`tallow run --interpret`) and compiles to a native binary (`tallow build`). That is not a convenience — it is the correctness harness: a codegen bug appears as a disagreement between planes, and every test that touches behaviour runs both.

**Nothing hidden at run time.** A compiled program is a normal ELF binary linked against `libc` and the Tallow archive. No garbage collector, no VM handshake, no configuration lookup at startup.

### Scripts

```tallow
#!/usr/bin/env tallow
fn main() {
    let path = env.args()[0]          // the script path is not included
    let text = fs.read_file(path)
    print(text.split("\n").len().to_string() + " lines in " + path)
}
```

```console
$ chmod +x lines.tl && ./lines.tl notes.txt
3 lines in notes.txt
```

The shebang line is blanked rather than removed, so diagnostics still point at the line you wrote, and arguments after the path reach the program. Complete examples live in the language repository: [`wc.tl`](https://github.com/aamirmanisa/Tallow-Language/blob/main/examples/scripts/wc.tl), [`todo.tl`](https://github.com/aamirmanisa/Tallow-Language/blob/main/examples/scripts/todo.tl).

The **language surface** — specification, tutorial, conformance cases — is a separate repository, [Tallow-Language](https://github.com/aamirmanisa/Tallow-Language). There is exactly one implementation of the compiler, and it lives here.

## Command surface

| Command | What it does |
|---|---|
| `tallow schema check <file>` | Validate an extraction contract; the CI gate for one |
| `tallow extract --schema … --html … --out …` | Extract rows from a local HTML file; no network access |
| `tallow plan dry-run <file>` | Print what a request plan would fetch; no egress |
| `tallow check <file>` | Parse, type-check, verify contracts — no code generation |
| `tallow build <file>` · `tallow run <file>` | Compile and link; build and execute (`--interpret` skips the compiler) |
| `tallow fmt` · `tallow lint` · `tallow test` | Format; static analysis; run project tests |
| `tallow repl` · `tallow lsp` · `tallow doc` | Interactive shell; editor integration; documentation |
| `tallow add/remove/install/update/tree/why` | Dependency management against `tallow.toml` and `tallow.lock` |
| `tallow sbom` · `tallow sign` · `tallow verify` | CycloneDX SBOM; Ed25519 + SLSA signing and verification |
| `tallow targets` | The compilation targets this build knows |

Operational verbs are documented in [`docs/`](docs/) and in `tallow --help`, which lists all of them with exit codes.

**Exit codes.** `0` success · `1` program failed or diagnostics · `2` usage · `64` bad invocation · `69` refused by policy · `70` internal. A build that produces no binary never exits `0`.

## Architecture

```
 source .tl
     │
 lexer ──▶ parser (recover | fast) ──▶ imports ──▶ typeck ──▶ contracts ──▶ IR ──▶ clang ──▶ ELF
                                                                     │
                                                                     └──▶ interpreter (second plane)
```

| Layer | Responsibility | Location |
|---|---|---|
| Front end | Lexing, error-recovering parsing, import resolution, type checking, contract verification | `src/lexer.rs`, `src/parser*.rs`, `src/typeck.rs` |
| Back end | IR construction and emission, lowering of every stdlib call, link step | `src/codegen.rs` |
| Interpreter | Independent execution plane for the same AST | `src/interp.rs` |
| Extraction tier | Schema application, model tier, HAR import, provenance, smart extract | `src/browser/llm_extract.rs`, `src/browser/har_import.rs` |
| Standard library | 111 modules: text, collections, files, JSON, HTTP, crypto, database, browser, CLI | `src/stdlib/` |
| Browser runtime | Chrome over CDP: 138 files / 103,104 LOC, 163 device profiles, stealth and CAPTCHA handling | `src/browser/` |
| Toolchain | Build, run, check, fmt, lint, test, doc, repl, lsp, packages, SBOM, signing | `src/main.rs`, `src/cli/` |
| Fleet crates | Daemon, jobs, admission, registry, mesh, reader, crypto, net, protocol, SVID, locator, advisory, copy engine | `crates/` |

The engine is ~534,000 lines of Rust [measured 2026-10-21]. The browser runtime is not a side artefact of the extraction tier — it is why the repository carries device profiles, CDP profiles and CAPTCHA handling at all.

### The crates

Each crate has its own page with setup, API and deployment notes.

| Crate | What it is | README |
|---|---|---|
| `tallow-crypto` | PQC, symmetric, hashing, PAKE, ratchets — TCS-1 suite | [read](crates/tallow-crypto/README.md) |
| `tallow-net` | QUIC, TCP+TLS, mDNS, NAT traversal, relay, Tor/SOCKS | [read](crates/tallow-net/README.md) |
| `tallow-protocol` | Wire format, transfer pipeline, compression, rooms, chat | [read](crates/tallow-protocol/README.md) |
| `tallow-daemon` | Background service with an HTTP API for sync and jobs | [read](crates/tallow-daemon/README.md) |
| `tallow-jobs` | `.tl` recipe scheduler with signed run receipts | [read](crates/tallow-jobs/README.md) |
| `tallow-registry` | Device registry + hash-chained receipt ledger | [read](crates/tallow-registry/README.md) |
| `tallow-admission` | Mesh-door admission with probe-indistinguishable cover | [read](crates/tallow-admission/README.md) |
| `tallow-svid` | SPIFFE-style workload identity | [read](crates/tallow-svid/README.md) |
| `tallow-reader` | Protected extraction daemon: warm browser pool over HTTP | [read](crates/tallow-reader/README.md) |
| `tallow-locator` | Lawful egress broker: score, select, fail closed | [read](crates/tallow-locator/README.md) |
| `tallow-advisory` | Read-only anomaly findings for a human | [read](crates/tallow-advisory/README.md) |
| `tallow-copy-engine` | Planning and execution engine for file copies | [read](crates/tallow-copy-engine/README.md) |

## Building from source

```console
$ git clone https://github.com/aamirmanisa/tallowsphere
$ cd tallowsphere
$ rustup toolchain install 1.98.1        # rust-toolchain.toml pins it
$ cargo build --release --locked --bin tallow --lib
```

The `--lib` target is the one that matters: it produces `libtallow.a`, which compiled programs link against. A binary built without it can emit IR and then fails at link time.

Build prerequisites: Rust 1.98.1 (edition 2024), `clang`, `gcc`/`g++`, `cmake`, `pkg-config`, `perl`. The vendored BoringSSL is why `g++` is required; there is no pure-Rust build of the browser-impersonation backend.

On a small host, cap the build instead of watching it swap:

```console
$ CARGO_BUILD_JOBS=2 systemd-run --scope -p MemoryMax=11G -- \
    cargo build --profile release --locked --target aarch64-unknown-linux-gnu --bin tallow --lib
```

[measured 2026-10-21 · 2-job scope · 14m 08s for binary + archive]

`[profile.release]` is tuned for the development loop. `[profile.max]` is fat LTO with one codegen unit and ships smaller binaries — about 20% smaller (36.6 vs 46.0 MB) and ~8% less RSS, at ~11% more build time and **no measurable runtime benefit** (median 12.81 vs 12.84 ms) [measured 2026-10-16].

## Hosting and deployment

### Install on a server

```console
$ curl -fsSL …/install.sh | bash -s -- --prefix /usr/local
```

For a fleet, keep versions side by side so an upgrade is a symlink swap and rollback is a directory:

```console
$ install -d /opt/tallow/1.1.4 && tar -xzf tallow-linux-aarch64-1.1.4.tar.gz -C /opt/tallow/1.1.4
$ ln -sfn /opt/tallow/1.1.4 /opt/tallow/current
$ ln -sf /opt/tallow/current/bin/tallow /usr/local/bin/tallow
```

### Run the extraction daemon

`tallow-reader` keeps a warm browser pool and serves extraction over an authenticated HTTP API on loopback:

```ini
# /etc/systemd/system/tallow-reader.service
[Service]
ExecStart=/usr/local/bin/tallow-reader --pool-size 4
User=tallow
Restart=always
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=/var/lib/tallow-reader
```

The token is generated on first run and written `0600`. Endpoints, the Tor pool and the identity rules are on [the crate page](crates/tallow-reader/README.md).

### Run the background daemon

```console
$ tallow-daemon install      # writes and enables the systemd unit
$ tallow-daemon start
$ tallow-daemon status
```

It serves sync, jobs and health endpoints on loopback by default and will not bind a public interface without an explicit configuration change. Logs go to the journal; `RUST_LOG=tallow_daemon=debug` raises verbosity.

### Container

```dockerfile
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends clang ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=builder /src/target/aarch64-unknown-linux-gnu/release/tallow        /usr/local/bin/tallow
COPY --from=builder /src/target/aarch64-unknown-linux-gnu/release/libtallow.a  /usr/local/lib/libtallow.a
ENTRYPOINT ["tallow"]
```

`clang` must be in the runtime image for anything to compile inside the container.

### Publish a release

```console
$ cargo build --profile release --locked --target aarch64-unknown-linux-gnu --bin tallow --lib
$ ./scripts/package_release.sh aarch64-unknown-linux-gnu 1.1.4 --out dist/
```

The packer refuses a dirty tree — a tarball must never claim `git: … (dirty)`. It writes the archive and its `.sha256`, and stamps the commit into the binary's version output. Upload both; the installer verifies the checksum before unpacking.

## Verification

| Gate | Result | Revision |
|---|---|---|
| `cargo test --lib` | **9,147 passed · 0 failed · 33 ignored** (321.14 s) | `0dfad23a52`, 2026-10-21 [measured] |
| Extraction, schema-first | `schema check` exit 0; `extract` exit 0, one row, no egress | released 1.1.4 [measured] |
| Conformance | **17 programs × 2 planes, 0 failures** against the installed 1.1.4 binary | 2026-10-22 [measured] |
| Examples & tutorial | **9 of 10 programs** byte-identical on both planes; `error_handling.tl` uses `String.parse`, which has no native lowering — the documented interpreter fallback runs it and `--require-native` refuses (registered, stub #138) | 2026-10-22 [measured] |
| Install probe | compiles and runs a program from the installed archive | 2026-10-21 [measured] |

```console
$ cargo test --lib -- --test-threads=2
$ cargo test --test script_mode --test fs_read_file_native --test exit_in_conditional
$ python3 conformance/run.py --tallow $(command -v tallow)
```

**How to read numbers in this repository.** Every quantitative claim carries a label: **[measured]** reproduced from a command in this tree at the stated revision · **[partial]** measured for part of the claim only · **[target-only]** a goal, not a measurement. A number without a label is prose.

## What it does not do yet

| Limit | Detail | Status |
|---|---|---|
| **musl targets** | The browser backend needs BoringSSL's C++, which has no musl `g++` on this host (`MUSL_RC=101`) | blocked; needs an Alpine build host |
| **Archive size** | `libtallow.a` is 527 MB; `strip` recovers ~11%, so the fix is a `cdylib` or a crate split | open |
| **Platform builds** | Only `linux-aarch64` has a published artifact; x86_64, macOS and Windows have no CI-produced binary | open |
| **Declared types vs values** | `let x: i64 = "nope"` passes `check` with 0 warnings — the annotation is not enforced against the initialiser | open (#137) |
| **Interpreter coercion** | In some stdlib arms the interpreter coerces an argument where the compiled leg refuses, so a wrong-typed call can pass `check` and return a plausible answer | open; recorded as a language-level question |

## Documentation

- [`docs/extraction-engine/`](docs/extraction-engine/) — the extraction product's spec, checklist and runbook
- [`docs/INSTALL.md`](docs/INSTALL.md) — install, upgrade, uninstall
- [`TALLOW_SPEC.md`](TALLOW_SPEC.md) — the language specification carried in this tree
- [`stdlib/README.md`](stdlib/README.md) — the standard library map
- [`conformance/README.md`](conformance/README.md) — the conformance harness
- [`SECURITY.md`](SECURITY.md) — reporting, scope, and the cryptographic-validation statement
- [`docs/operations/stub-register.md`](docs/operations/stub-register.md) — every admitted stub, one row each
- [`MANIFEST.md`](MANIFEST.md) — what this published tree contains and what was filtered
- [Tallow-Language](https://github.com/aamirmanisa/Tallow-Language) — specification, tutorial, conformance cases

## Contributing

```console
$ cargo check
$ cargo test --lib <name> -- --nocapture
$ cargo test --test <suite>
```

Keep a change inside the layer that owns the behaviour: a rule that belongs in the type checker does not belong in codegen. When a change touches both planes, change both and prove they agree.

## License

MIT for the root workspace. Vendored components keep their own licenses — see [`NOTICE`](NOTICE) and `tallow licenses`.
