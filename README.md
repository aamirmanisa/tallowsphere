# Tallow Extraction Engine

The extraction engine of the [Tallow](#the-tree-it-lives-in) language/runtime: the schema-first extraction
tier and everything it needs — its native bindings in the compiler, HAR capture import, provenance records,
and the CLI verbs that drive them — carried in the source tree at the revision where that work completed.

**Revision under this README:** `7364aa59` — the base tree `03bc941b` plus the 27-commit series in
`patches/`, already applied in this history.

> The SHAs here differ from the ones in the development history because this tree was filtered for
> publication. The mapping, and what was filtered out, is in [`MANIFEST.md`](MANIFEST.md).

## Use it in five minutes — no config, no keys, no network

Extraction here is **schema-first and local**: a contract is applied to an HTML file you already have.
No LLM, no API key, no engine, no egress.

> **If you are an AI agent**, read [`AGENTS.md`](AGENTS.md) first — it is written for you and carries
> this quickstart with exit codes, the full CLI surface, and the honest limits of the tree.

```bash
cargo build --bin tallow

# 1. validate a contract (this is also the CI gate for one)
./target/debug/tallow schema check schemas/tallow/examples/product-listing.extraction.schema.json
# ok: … — tallow.extraction_schema.v1, 3 field(s)                                          exit 0

# 2. extract rows from a LOCAL html file, against that contract
./target/debug/tallow extract \
  --schema schemas/tallow/examples/product-listing.extraction.schema.json \
  --html /tmp/product.html --out /tmp/out
# extract: 1 item(s) → 1 row(s) · schema: example.product_listing.v1 (no egress performed)  exit 0
```

Rows land in `run-<pid>.rows.jsonl`, one `tallow.extraction_row.v1` object per line, each field
naming its `value`, the `selector` that produced it, its `selector_kind` and its `source_evidence`.
A page that misses a required field writes nothing and exits `1` rather than guessing.

## Two ways to use it

**1. Nothing to configure.** Schema-first extraction runs against an HTML file you already have — no
key, no engine, no egress (quickstart above). Hand this repository link to an AI and it reads
[`AGENTS.md`](AGENTS.md) and drives that path itself.

**2. Configure it your way.** Everything else is opt-in and nothing is enabled silently: the
model-backed tier, credential custody, the egress plane. See below.

## Configure it (optional)

Nothing here is needed for the local path. Each piece is off until you turn it on.

**The model-backed tier** (`src/browser/llm_extract.rs`) — for pages a selector cannot cover. It is
off until an engine is named, and it refuses a third-party transfer that no policy permits:

```bash
export TALLOW_LLM_ENGINE=ollama              # or: openai-compatible
export TALLOW_LLM_BASE_URL=http://localhost:11434
export TALLOW_LLM_MODEL=llama3
export TALLOW_LLM_PII_POLICY=no-pii          # required before content leaves the box
# a loopback endpoint needs no policy; anything outside the box's zone needs one
```

**The credential** resolves from vault custody first, then the environment — never from `argv`, never
from a `.tl` literal. Enroll it once, with echo off (there is deliberately no `--password` flag: a
secret on the command line is a secret in `ps` and in shell history):

```bash
tallow secrets set tallow-llm-api-key --origin https://your-endpoint   # writes ~/.config/tallow/secrets.json, 0600
tallow secrets list
```

`TALLOW_LLM_API_KEY` is the per-run override when you do not want custody. Spend is capped per run
(16 model calls / 400k prompt chars) and past the cap the tier **refuses** rather than continuing.

**Configuration and hardening:**

```bash
tallow config list                 # every value in the active config
tallow config set <key> <value>
tallow config path                 # where it lives
tallow config lint                 # score it against the hardening baseline
```

**The egress plane** is a separate repository, `tallow-scrape-sandbox` — the deny-by-default SOCKS
chokepoint, allowlist, Tor configuration and in-container firewall. This engine carries the egress
*policy* (Tor-first, proxy-aware, refusing a bare leak) and not the plane; neither is a working
anonymous scraper without the other.

## The browser system

`src/browser/` is the other half of this engine — **138 files, 101,790 LOC** of production Chrome
control over CDP: stealth/anti-detection profiles, CAPTCHA handling, behavioural cadence, a
distributed pool — behind both a CLI and the `.tl` surface in `stdlib/browser.tl` (`Browser`,
`Page`, `Element`, `Crawler`, `Captcha`…). 163 device profiles, 15 TOML config files, 8 CAPTCHA
types.

```bash
tallow browser install        # download a compatible Chromium build (~150 MB)
tallow browser path           # where that binary is
tallow browser list           # installed versions
tallow browser devices        # all 163 device profiles
tallow browser pool           # pool status; start it with `tallow browser daemon`
tallow browser config list    # the 15 config files, by name
tallow browser open           # launch Chrome with all Tallow features enabled
tallow browser schedule       # run .tl scripts on a cron or interval
```

Verified in this tree: `path`, `list`, `devices`, `pool` and `config list` (all exit 0). `install`
downloads a Chromium build and `open` drives a real browser, so neither belongs in a quickstart nor
in CI — but the browser is why the repo carries `configs/` and the device table, and it is not a
side artefact of the extraction tier.

## What it is

Tallow is a privacy-first systems language and an anti-bot scraping + OSINT runtime. This line of work made
the extraction stack's advertised behaviour match its actual behaviour. The execution plan's own goal:

> Close the verified-open items from the audit and make the extraction stack's advertised behaviour match
> its actual behaviour, without breaking the egress contract or interp/native parity.

What that produced:

- **The schema-first extraction tier** (`src/browser/llm_extract.rs`) — engine-agnostic, off unless
  configured, spend-capped, and gated on the plan's own compliance block before any third-party transfer.
- **Credential custody** — the tier resolves its API key from vault custody (entry `tallow-llm-api-key`)
  with an env fallback, refusing by name when neither is present. No key in a `.tl` literal, none in `argv`.
- **Native bindings** — `StructuredData.extract` and `Crawler.from_sitemap` lower in the compiled path
  (`src/runtime/structured_data_ffi.rs`, codegen arms, interpreter arms made strict), so the declared
  `// native` surface is fully bound.
- **HAR 1.2 import** (`src/browser/har_import.rs`), redacted on the way in.
- **Provenance** — typed limitations recorded in the run evidence.
- **CLI** — `tallow schema check`, `tallow plan dry-run`, `tallow extract`.

One defect class this work surfaced and did **not** close: the interpreter coerces arguments
(`v.as_string()`) where the compiled leg refuses, so a wrong-typed call can pass `tallow check` and return a
plausible wrong answer. Two arms were made strict here; the class is much wider and is recorded as a
language-level question rather than quietly patched.

## Layout

| Path | What |
|---|---|
| `src/browser/` | the browser system (138 files / 101,790 LOC — Chrome over CDP, stealth, CAPTCHA, pool) plus the extraction tier, HAR import, provenance, smart-extract |
| `src/runtime/structured_data_ffi.rs`, `src/codegen.rs`, `src/interp.rs` | the native bindings and their arms |
| `src/cli/{extract,schema,plan}_cmd.rs` | the CLI verbs |
| `stdlib/browser.tl` | the declared `.tl` surface |
| `tests/{structured_data,crawler}_parity.rs`, `tests/parity/parity_programs/` | the engine-parity tests |
| `docs/extraction-engine/`, `docs/plans/2026-10-14-*` | the document set that defines the product |
| `patches/` | the 27-commit series, already applied in this history and kept for review |
| `verification/` | what was measured, by which command, at which revision |
| `README.tallow-upstream.md` | the tree's original README, kept rather than overwritten |
| `.github/workflows/ci.yml` | the gates that can pass in this tree — six jobs the development tree has are deliberately not carried, with reasons in `MANIFEST.md` |

## The tree it lives in

The extraction engine is part of the Tallow compiler + runtime, not a standalone crate: the FFI and lowering
arms live in the compiler, and the declared surface lives in `stdlib/`. That is why this repository carries
the source tree rather than a package — the workspace is what builds.

## Build

```bash
cargo check            # the workspace
cargo build --bin tallow
cargo test -p tallow-locator
```

Rust edition 2024. On the aarch64 development box, note two rules that cost real time: a plain `cargo` call
inside an agent session fails (use a `systemd-run --scope` wrapper), and a full rebuild must be capped with
`MemoryMax`, never `MemoryHigh` — a soft watermark below the peak stalls `rustc` at 0% CPU. Formatting the
whole workspace hangs; format only the files you touched.

## The egress plane

This repository is the scraper. The plane that makes its traffic anonymous is a separate repository,
`tallow-scrape-sandbox`: the deny-by-default SOCKS chokepoint over an explicit allowlist, the Tor
configuration, the in-container firewall, the host systemd units and the operations runbook. The engine
carries the egress *policy* — Tor-first, proxy-aware, refusing a bare leak — and not the plane. The two are a
pair: neither is a working anonymous scraper without the other.

## What it is not

Not SendTallow (the file-transfer product). Not the `Tallow/` subdirectory (a separate repository on its own
line). Not the Sluice release gate (a separate published deliverable).
