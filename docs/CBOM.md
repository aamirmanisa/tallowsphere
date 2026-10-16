# `tallow sbom --format cbom` — the Cryptographic Bill of Materials verb

```sh
tallow sbom --format cbom                  # fail-closed; refuses if any source will not parse
tallow sbom --format cbom --allow-partial  # emit anyway; the artifact records what it skipped
tallow sbom --format cbom --output cbom.json
```

## What was actually missing

Two pieces already existed and neither was reachable from the command line:

- `src/sbom.rs` has `generate_cbom()` and `scan_crypto_usage()`, with passing unit tests
  (`test_cbom_crypto_inventory`, `test_cbom_empty`).
- `scripts/crypto-inventory.py` (1,557 lines) emits a different artifact — format
  `tallow-cbom-seed/1` — over this repo's own crypto source roots, and the `cbom-drift` CI job
  gates it with `--check`. **That job is unaffected by this verb**; the two are different
  artifacts answering different questions (that one inventories *this repo's* crypto roots for
  drift; this one emits a CycloneDX CBOM for *a project's* `.tl` sources).

The verb itself refused: `unsupported SBOM format: cbom. Only 'cyclonedx' is supported.` So the
capability existed as a library function and a separate Python seed, and not as a command.

## How it works

Walks the current directory for `.tl` sources (skipping `target/`, `.git/`, `node_modules/`,
`dist/`, `vendor/`, `artifacts/`), parses each through the same pipeline the rest of the CLI uses
(`tallow::lexer::tokenize` → `tallow::parser::Parser::parse`), collects `scan_crypto_usage` per
file, qualifies each usage's location with its file, sorts and de-duplicates, and hands the set to
`generate_cbom`. Emits CycloneDX with `cbom:type`, `cbom:pqc_count` and `cbom:classical_count`.

## Fail-closed by default, and the hatch is not quiet

An unparsable source **refuses the whole run** and names itself. A CBOM that quietly skipped a file
it could not read would under-report the crypto in use, and an under-reporting inventory is worse
than none — its only value is that it is complete.

`--allow-partial` is the deliberate escape hatch. It is not quiet, because a CBOM is written to a
file and read later by someone who never saw the stderr:

| Property | When |
|---|---|
| `cbom:complete` | always — `"true"` or `"false"` |
| `cbom:skipped_count` | only when something was skipped |
| `cbom:skipped_sources` | newline-delimited relative paths, pairs by index with… |
| `cbom:skipped_reasons` | …the parse error for each |

**Why newline and not comma:** the first version joined on `","`, and a `ParseError`'s Debug
rendering contains commas (`ParseError { msg: "…", span: 631..634 }`). A consumer splitting the
value got **397 fragments for 60 sources** — a structured field that cannot be parsed back is not
structured. Neither a path nor a Debug rendering can contain a newline, so these round-trip exactly.
Found by checking the delivered value rather than trusting the code that wrote it.

## Measured, on this repo

| | |
|---|---|
| `.tl` sources found | **235** |
| parsed | **175** |
| **rejected by the parser** | **60** |
| algorithms found (175 sources) | `AES-256-GCM`, `BLAKE3`, `MD5`, `ML-DSA`, `SHA1` (pqc 1 / classical 4) |

`MD5` and `SHA1` appearing in a crypto inventory is the artifact doing its job.

### The 60 unparsable sources are a finding in their own right

Not a defect this verb introduced — the parser rejects them today, and the same files are rejected
by anything else that parses `.tl`. The failures cluster in the stdlib declaration files and are
grammar gaps, not typos: `stdlib/algos.tl: expected item (fn, struct, enum, impl, trait, const,
type, import), found module`; `stdlib/captcha.tl: expected ']', found 'String'`; `stdlib/entity.tl:
expected '(', found '.'`. They are the `.tl`-declaration-gap class already documented in the parser
reference. **This is why the verb cannot produce a complete CBOM for its own repo**, and it is
tracked separately rather than papered over by the hatch.

## Verification (2026-10-16, aarch64, `--profile release`, 6m59s)

| Check | Result |
|---|---|
| `--format cbom` at repo root | rc=1, **0 bytes** of output, names all 60 sources |
| `--format cbom --allow-partial` | rc=0, `cbom:complete=false`, skipped_count 60 → **60** sources, **60** reasons (round-trip exact) |
| clean single-file scope | rc=0, `cbom:complete=true`, **4** components, no skipped properties |
| `--format cyclonedx` | 809 components, sha256 `eb0c4c07…` — **byte-identical to the pre-change binary** |
| `--format spdx` | still refused, with a message that now names what *is* exposed |

`spdx`, `spdx3` and `cra` generators exist in `tallow::sbom` and remain unexposed by this verb; the
error message says so rather than pretending they do not exist.
