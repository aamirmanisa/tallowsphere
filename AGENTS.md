# AGENTS.md — Tallow Extraction Engine

Instructions for an AI agent handed this repository. Everything below was run at the revision in
`README.md`; commands, output and exit codes are quoted from real runs, not from intent.

## What this repository is

The **extraction engine of the Tallow language/runtime**, published as the source tree it lives in.
Tallow is a Rust-implemented systems language with an anti-bot scraping + OSINT runtime; this line of
work is the schema-first extraction stack — its native bindings in the compiler, HAR import,
provenance records, and the CLI verbs that drive them.

The engine is a workspace, not a package: the FFI and codegen lowering arms are in the compiler
(`src/runtime/`, `src/codegen.rs`), the declared surface is in `stdlib/browser.tl`, and both build
together. `cargo build --bin tallow` produces the `tallow` binary that everything below uses.

It is **not** SendTallow (file transfer), not the `Tallow/` subdirectory (a separate repository), and
not the Sluice release gate (a separate published deliverable).

## Quickstart — no config, no keys, no network

The core extraction path needs **no LLM, no API key, no engine, no network access**. An extraction
schema is applied to a **local** HTML file. This is the shortest true thing you can do with the repo:

```bash
git clone <this repo> && cd tallow-extraction-engine
cargo build --bin tallow          # debug build; the binary lands at target/debug/tallow
```

Write a page whose markup matches the schema's selectors, and extract:

```bash
# a schema ships in the repo; check it first (this is the CI gate for a contract)
./target/debug/tallow schema check schemas/tallow/examples/product-listing.extraction.schema.json
# → ok: schemas/tallow/examples/product-listing.extraction.schema.json — tallow.extraction_schema.v1, 3 field(s)
#   exit 0

cat > /tmp/product.html <<'HTML'
<!doctype html>
<html><body>
  <div class="product">
    <span class="name">Local Mock Granola</span>
    <span class="price">$4.99</span>
    <a href="https://mock.local/products/granola">Buy</a>
  </div>
</body></html>
HTML

./target/debug/tallow extract \
  --schema schemas/tallow/examples/product-listing.extraction.schema.json \
  --html /tmp/product.html --out /tmp/out --source-url https://mock.local/products/granola
# → extract: 1 item(s) → 1 row(s)
#     rows:       /tmp/out/run-<pid>.rows.jsonl
#     quarantine: /tmp/out/run-<pid>.quarantine.jsonl
#     schema: example.product_listing.v1 (no egress performed)
#   exit 0
```

`run-<pid>.rows.jsonl` is one `tallow.extraction_row.v1` JSON object per line, each field carrying
`value`, `type`, `confidence`, the `selector` that produced it, `selector_kind` (`css` / `json_path` /
`literal`) and `source_evidence`. Example field, verbatim:

```json
"name": { "value": "Local Mock Granola", "type": "string", "required": true, "confidence": 1.0,
          "selector": ".product .name", "selector_kind": "css",
          "source_evidence": "local html: /tmp/product.html" }
```

Notes that save time:

- A page that does not satisfy a **required** field yields nothing usable: `extract` exits **1** with
  `extraction produced no results` and writes no rows. That is a refusal, not a crash.
- Selector priority is real: priority 0 for each field in the shipped example is CSS, priority 1 is a
  `json_path` fallback, so a page needs one or the other — not both.
- `money` fields come back as **cents as a string** (`"$4.99"` → `"499"`), from the `parse_money`
  coercion. Expect that shape rather than a decimal.
- Exit codes: `0` rows written · `1` nothing usable (the failing field is named on stderr) · `64`
  usage error or unreadable file.

## The rest of the CLI surface

| Verb | What it does | Egress |
|---|---|---|
| `schema check <file>` | Validate a `tallow.extraction_schema.v1` contract; refuses by naming the failing field | none |
| `plan dry-run <file>` | Print exactly what a `tallow.request_plan.v1` manifest would fetch; refuses a request whose `compliance` block is missing | none |
| `extract --schema --html --out` | Rows from a **local** HTML file (above) | none |
| `run <file.tl>` | Compile and run a Tallow program; `--target x86_64-linux` forces the tree-walking interpreter, `--require-native` refuses the interpreted fallback | as the program does |
| `build` / `check` / `fmt` / `lint` / `test` / `repl` / `lsp` | Language toolchain | none |
| `config get/set/list/path/lint/presets/bundle` | Read and write the active config; `lint` scores it against the hardening baseline | none |
| `secrets set/list/check/rm` | Credential enrollment. Reads the value from the terminal with echo **off** — there is deliberately no `--password` flag (a secret on the command line is a secret in `ps` and in shell history); writes `~/.config/tallow/secrets.json`, mode 0600 | none |
| `veil connect tor\|mesh\|direct` | Assert and announce an egress rung, handing env to child runs | as named |

The compiled path is not a side path: `StructuredData.extract` and `Crawler.from_sitemap` are bound
natively (`src/runtime/structured_data_ffi.rs`, codegen arms) and pinned by engine-parity tests
(`tests/structured_data_parity.rs`), which assert the interpreter and compiled legs produce
byte-identical stdout against a reference block.

## The browser system — the other half of the tree

`src/browser/` is **138 files / 101,790 LOC** of Chrome control over CDP: stealth profiles, CAPTCHA
handling, behavioural cadence, a distributed pool, plus the extraction tier. It is exposed as both a
CLI and a `.tl` surface (`stdlib/browser.tl`: `Browser`, `Page`, `Element`, `Crawler`, `Captcha`…)
with 163 device profiles and 15 TOML config files. If a task is about the browser, this is the
subsystem — not an artefact of the extraction work.

```bash
tallow browser path        # the installed Chromium binary
tallow browser list        # installed browser versions
tallow browser devices     # all 163 device profiles
tallow browser pool        # pool status; `tallow browser daemon` starts it
tallow browser config list # the 15 config files, by name
```

`install` downloads a Chromium build (~150 MB) and `open` drives a real browser: treat both as
egress-bearing and never put them in CI. `devices`, `path`, `list`, `pool` and `config list` are
read-only and safe anywhere.

## The LLM tier — optional, and you do not need it

`src/browser/llm_extract.rs` is a schema-first tier that can send a page sample to a model. It is
**off unless configured**: it needs an engine (`TALLOW_LLM_ENGINE` = `ollama` or
`openai-compatible`, with `TALLOW_LLM_BASE_URL` and `TALLOW_LLM_MODEL`), a credential, and — for any
endpoint outside the box's zone — a policy in the plan's `compliance` block (`pii_policy`,
`requires_approval`; the env equivalents are `TALLOW_LLM_PII_POLICY` and `TALLOW_LLM_REQUIRES_APPROVAL`),
because with no policy a third-party transfer is **refused** (`src/browser/llm_transfer.rs` is
fail-closed by design). A loopback endpoint needs no policy: nothing leaves the box. The credential
resolves from vault custody (entry `tallow-llm-api-key`) with an env fallback
(`TALLOW_LLM_API_KEY`), never from `argv` and never from a `.tl` literal; enroll it with
`tallow secrets set tallow-llm-api-key --origin https://your-endpoint`.
Spend is capped per run (`LlmBudget`, 16 model calls / 400k prompt chars) and past the cap the tier
**refuses rather than continuing**.

If you are using this repo to extract data, ignore the tier. If you are *changing* it, read
`docs/plans/2026-10-14-tallow-scraper-execution-plan.md` first.

## Build and test

```bash
cargo check                                  # whole workspace
cargo build --bin tallow
cargo test -p tallow --lib                   # the lib suite; use CARGO_TARGET_DIR to keep it off-tree
cargo test --test structured_data_parity     # engine parity for the bound native
```

Rust **edition 2024** (`rust-toolchain.toml` pins it). Three rules that each cost real time on a
memory-constrained box:

- `cargo fmt` over the whole workspace **hangs** — format only the files you touched.
- A full rebuild must be capped with `MemoryMax` (a hard limit), never `MemoryHigh` — a soft watermark
  below the peak stalls `rustc` at 0% CPU instead of failing.
- `cargo test` builds the package's binaries before the test target. On a slow debug build, run
  `cargo build --bins` once rather than letting four `rustc` processes thrash.

## Working rules for an agent in this tree

- `cargo check` clean is the floor for any change; a change to the compiler or codegen also needs the
  parity tests, because the interpreter and compiled legs must agree byte for byte.
- Never revert unrelated edits; the tree is often intentionally dirty.
- Verification claims must name the artifact (`file:line`, command, exit code) rather than assert
  "done". Several status sections in `docs/plans/` have proven stale, and their commit citations
  unresolvable — if a plan says a thing is open, check the code before doing the work.
- The parser treats **braces in string literals as interpolation**. A JSON-LD body inside a `.tl`
  string therefore needs escaping, or the emitted IR references an undefined global.

## Where the truth lives

| Path | What |
|---|---|
| `README.md` | the product front door and what this revision contains |
| `MANIFEST.md` | the publication mapping: dev revision → published revision, and what was filtered |
| `patches/` | the 27-commit series, already applied, kept for review |
| `docs/extraction-engine/` | the product documents (audit, contracts) |
| `docs/plans/2026-10-14-*` | the execution plan and its report — the definition of done |
| `verification/` | what was measured, by which command, at which revision |
| `stdlib/browser.tl` | the declared `.tl` surface for the browser/extraction natives |
| `README.tallow-upstream.md` | the upstream tree's original README, kept rather than overwritten |
