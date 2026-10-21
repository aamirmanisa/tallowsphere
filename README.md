<div align="center">

# Tallow

**A statically typed language that compiles to a native binary — with contracts, a real standard library, a browser runtime, and a toolchain that ships.**

![status](https://img.shields.io/badge/status-1.1.3-informational?style=flat-square)
![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)
![rust](https://img.shields.io/badge/rust-1.98.1-dea584?style=flat-square&logo=rust&logoColor=white)
![backend](https://img.shields.io/badge/backend-LLVM%20%C2%B7%20clang%2018-2d2d2d?style=flat-square)
![artifact](https://img.shields.io/badge/linux--aarch64-stable-2ea44f?style=flat-square)

[Install](#install) · [First program](#your-first-program) · [Scripts](#scripts) · [Command surface](#the-command-surface) · [Architecture](#architecture) · [Build](#building-from-source) · [Deploy](#hosting-and-deployment) · [Limits](#what-it-does-not-do-yet)

</div>

---

Most languages ask you to choose between fast and readable, then hand you a build system to apologise for the choice. Tallow is built the other way round: a small typed language, no hidden runtime, compiled through LLVM into one executable that starts in milliseconds and links nothing you have to install.

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

That is the whole workflow. `tallow build hello.tl` leaves a native binary beside the source. `tallow check` tells you what is wrong before anything is compiled.

## What this repository is

This is the **engine**: lexer, parser, type checker, contract checker, LLVM code generator, interpreter, standard library, package manager, formatter, language server, browser runtime, and the operational crates the fleet runs on. The language surface — specification, tutorial, conformance cases — lives in [Tallow-Language](https://github.com/aamirmanisa/Tallow-Language).

**Two properties make it worth reading.**

*Every program has two execution planes.* The same source runs in the interpreter (`tallow run --interpret`) and compiles to a native binary (`tallow build`). That is not a convenience — it is the correctness harness. A codegen bug shows up as a disagreement between planes, and the suite runs both.

*Nothing fails quietly.* Refusals are typed and named: a missing file, a short read, a host missing from the outbound authorization register. Each produces a specific error and a non-zero exit, never a silently degraded result.

## Install

### One line (linux-aarch64)

```console
$ curl -fsSL https://raw.githubusercontent.com/aamirmanisa/tallowsphere/main/install.sh | bash
```

The installer resolves the newest release, verifies the archive checksum, unpacks **both** `tallow` and `libtallow.a`, then compiles and runs a probe program before it reports success:

```console
fetching …/releases/download/v1.1.3/tallow-linux-aarch64-1.1.3.tar.gz
tallow-linux-aarch64-1.1.3.tar.gz: OK
installed tallow 1.1.3 into /root/.local/bin
probe ok — native compile and run work
```

[measured 2026-10-21 · release `v1.1.3` · commit `31d84f47e2`]

Choose a prefix, pin a version, or install from a file:

```console
$ curl -fsSL …/install.sh | bash -s -- --prefix /usr/local
$ curl -fsSL …/install.sh | bash -s -- --version 1.1.3
$ ./install.sh --from ./tallow-linux-aarch64-1.1.3.tar.gz    # air-gapped
```

### What the machine needs

| Requirement | Why | Detail |
|---|---|---|
| **clang** | Tallow emits LLVM IR and asks `clang` to assemble and link it | 14–18; 18.1.3 is what every measurement here used. Override with `TALLOW_CLANG` |
| **linux-aarch64** | The only platform with a published build | Everything else: [build from source](#building-from-source) |
| **~570 MB disk** | 46 MB compiler + 522 MB static archive | The archive is not optional: every program links against it |

`clang` is required at **run time**, not only at build time — the compiler invokes it for each program it builds. A machine without `clang` can execute pre-built binaries but cannot compile anything.

### Check the install

```console
$ tallow --version
tallow 1.1.3
  platform: linux
  arch: aarch64
  git: 31d84f47e2
```

The `git:` line is provenance, not decoration: a release artifact reports the commit it was built from, and a debug build reports `(dirty)` so you can tell them apart.

## Your first program

```tallow
// greet.tl
fn greet(name: str) -> str {
    return "hello, " + name
}

fn main() {
    print(greet("world"))
}
```

```console
$ tallow check greet.tl      # types and contracts; builds nothing
1 items, 0 warning(s)

$ tallow build greet.tl      # native binary beside the source
$ ./greet
hello, world
```

## Scripts

A `.tl` file with a shebang is a program you execute, not an argument to a subcommand:

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

The shebang line is blanked rather than removed, so a parse error still reports the line number you see in your editor. Arguments after the path reach the program: `./wc.tl notes.txt` gives `args[0] == "notes.txt"`.

Runnable examples live in the language repository: [`wc.tl`](https://github.com/aamirmanisa/Tallow-Language/blob/main/examples/scripts/wc.tl) and [`todo.tl`](https://github.com/aamirmanisa/Tallow-Language/blob/main/examples/scripts/todo.tl).

## The command surface

One binary, a deliberately flat set of verbs. The daily ones:

| Command | What it does |
|---|---|
| `tallow new <name>` | Scaffold a project with `tallow.toml` and `src/main.tl` |
| `tallow check <file>` | Parse, type-check, verify contracts — no code generation |
| `tallow build <file>` | Emit IR, compile and link a native binary |
| `tallow run <file>` | Build and execute; `--interpret` skips the compiler |
| `tallow fmt` · `tallow lint` | Format; static analysis |
| `tallow test` | Run project test files |
| `tallow repl` · `tallow lsp` | Interactive shell; editor integration |
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
| Standard library | 111 modules: text, collections, files, JSON, HTTP, crypto, database, browser, CLI | `src/stdlib/` |
| Browser runtime | Chrome over CDP: 138 files / 103,104 LOC, 163 device profiles, stealth and CAPTCHA handling | `src/browser/` |
| Toolchain | Build, run, check, fmt, lint, test, doc, repl, lsp, packages, SBOM, signing | `src/main.rs`, `src/cli/` |
| Fleet crates | Daemon, jobs, admission, registry, mesh, reader, crypto, net, protocol, SVID, locator, advisory, copy engine | `crates/` |

The engine is ~534,000 lines of Rust [measured 2026-10-21]. The browser runtime is not a side artefact of the extraction tier — it is why the repository carries device profiles, CDP profiles and CAPTCHA handling at all.

### The crates

Each crate has its own README with setup, API and deployment notes.

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

Binary only — faster, but it cannot compile programs on its own:

```console
$ cargo build --release --bin tallow
```

Build prerequisites: Rust 1.98.1 (edition 2024), `clang`, `gcc`/`g++`, `cmake`, `pkg-config`, `perl`. The vendored BoringSSL is the reason `g++` is required; there is no pure-Rust build of the browser-impersonation backend.

On a small host, cap the build instead of watching it swap:

```console
$ CARGO_BUILD_JOBS=2 systemd-run --scope -p MemoryMax=11G -- \
    cargo build --profile release --locked --target aarch64-unknown-linux-gnu --bin tallow --lib
```

[measured 2026-10-21 · 2-job scope · 14m 08s for binary + archive]

### Release profile

`[profile.release]` is tuned for the development loop. `[profile.max]` is fat LTO with one codegen unit and ships smaller binaries:

```console
$ cargo build --profile max --bin tallow     # ~20% smaller (36.6 vs 46.0 MB), ~8% less RSS
$ cargo build --bin tallow                   # iterate with this
```

[measured 2026-10-16] `--profile max` costs about 11% more build time and has **no measurable runtime benefit** (median 12.81 vs 12.84 ms). Do not claim a speed win for it.

## Hosting and deployment

### Install on a server

```console
$ curl -fsSL …/install.sh | bash -s -- --prefix /usr/local
```

For a fleet, keep versions side by side so an upgrade is a symlink swap and rollback is a directory:

```console
$ install -d /opt/tallow/1.1.3 && tar -xzf tallow-linux-aarch64-1.1.3.tar.gz -C /opt/tallow/1.1.3
$ ln -sfn /opt/tallow/1.1.3 /opt/tallow/current
$ ln -sf /opt/tallow/current/bin/tallow /usr/local/bin/tallow
```

### Run the daemon

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
$ ./scripts/package_release.sh aarch64-unknown-linux-gnu 1.1.3 --out dist/
```

The packer refuses a dirty tree — a tarball must never claim `git: … (dirty)`. It writes `tallow-linux-<arch>-<version>.tar.gz` and its `.sha256`, and the commit is stamped into the binary's version output. Upload both files; the installer verifies the checksum before unpacking.

## The egress plane

This repository is the engine; the plane that makes its traffic anonymous is a separate repository (`tallow-scrape-sandbox`): the deny-by-default SOCKS chokepoint over an explicit allowlist, Tor configuration, and the in-container firewall. The engine carries the *policy* — Tor-first, proxy-aware, refusing a bare leak — not the plane. Neither is a working anonymous scraper without the other, and no claim here says otherwise.

## Verification

| Gate | Result | Revision |
|---|---|---|
| `cargo test --lib` | **9,139 passed · 0 failed · 33 ignored** (526.18 s, 2 threads) | `31d84f47e2`, 2026-10-21 [measured] |
| Conformance | **20/20 cases, 0 failures** against the installed 1.1.3 binary | 2026-10-21 [measured] |
| Examples & tutorial | **10 programs**, identical output on both planes, 0 failures | 2026-10-21 [measured] |
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
| **Archive size** | `libtallow.a` is 522 MB; `strip` recovers ~11%, so the fix is a `cdylib` or a crate split | open |
| **Platform builds** | Only `linux-aarch64` has a published artifact; x86_64, macOS and Windows have no CI-produced binary | open |
| **Declared types vs values** | `let x: i64 = "nope"` passes `check` with 0 warnings — the annotation is not enforced against the initialiser | open (#137) |
| **Interpreter coercion** | In some stdlib arms the interpreter coerces an argument where the compiled leg refuses, so a wrong-typed call can pass `check` and return a plausible answer | open; recorded as a language-level question |

## Documentation

- [`docs/INSTALL.md`](docs/INSTALL.md) — install, upgrade, uninstall
- [`docs/CLI.md`](docs/CLI.md) — every verb and every exit code
- [`TALLOW_SPEC.md`](TALLOW_SPEC.md) — the language specification
- [`stdlib/README.md`](stdlib/README.md) — the standard library map
- [`conformance/README.md`](conformance/README.md) — the conformance harness
- [`examples/`](examples/) — from hello world to scripts with arguments
- [`SECURITY.md`](SECURITY.md) — reporting, scope, and the cryptographic-validation statement
- [`docs/operations/stub-register.md`](docs/operations/stub-register.md) — every admitted stub, one row each
- [`MANIFEST.md`](MANIFEST.md) — what this published tree contains and what was filtered
- [Tallow-Language](https://github.com/aamirmanisa/Tallow-Language) — tutorial, spec, conformance cases

## Contributing

```console
$ cargo check
$ cargo test --lib <name> -- --nocapture
$ cargo test --test <suite>
```

Keep a change inside the layer that owns the behaviour: a rule that belongs in the type checker does not belong in codegen. When a change touches both planes, change both and prove they agree.

## License

MIT for the root workspace. Vendored components keep their own licenses — see [`NOTICE`](NOTICE) and `tallow licenses`.
