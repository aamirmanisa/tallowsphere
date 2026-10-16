# NIXE/TALLOW Deep Research Report

Generated: 2026-04-23 10:32:08 -05:00

## 1) Scope Clarification

There is no literal folder at `E:\Nixe\tallow`.

For this audit, the Tallow scope was treated as:

- `E:\Nixe\src` (core language/compiler/runtime)
- `E:\Nixe\stdlib` (Tallow `.tl` stdlib surface)
- `E:\Nixe\scripts` (automation and scrape orchestration scripts)
- `E:\Nixe\crates` (core Rust crates: crypto/net/protocol)
- `E:\Nixe\tallow-search` (API/web product + artifacts)
- `E:\Nixe\openclaw-tallow` (OpenClaw-on-Tallow release workspace)

## 2) Full File/Folder Inventory Artifacts

I generated complete recursive inventory files for the scope above:

- `E:\Nixe\docs\TALLOW_SCOPE_FILE_FOLDER_INDEX.txt`
- `E:\Nixe\docs\TALLOW_SCOPE_COUNTS.csv`
- `E:\Nixe\docs\TALLOW_SCOPE_EXTENSION_COUNTS.csv`

`TALLOW_SCOPE_FILE_FOLDER_INDEX.txt` contains every directory and file path (plus file size) in scope.

Format:

- `D<TAB>absolute_directory_path`
- `F<TAB>absolute_file_path<TAB>size_bytes`

## 3) Inventory Summary (Current Snapshot)

| Root | Directories | Files |
|---|---:|---:|
| `E:\Nixe\src` | 12 | 246 |
| `E:\Nixe\stdlib` | 0 | 33 |
| `E:\Nixe\scripts` | 1 | 141 |
| `E:\Nixe\crates` | 1388 | 10655 |
| `E:\Nixe\tallow-search` | 6999 | 57056 |
| `E:\Nixe\openclaw-tallow` | 42 | 176 |

Important composition note:

- `tallow-search` is heavily dominated by generated/build artifacts (`target`, bundled web outputs), not just source code.

Top immediate `tallow-search` subtree counts:

- `target`: 41,537 files
- `web`: 14,781 files
- `api`: 159 files
- `artifacts`: 380 files
- `docs`: 122 files

## 4) Tallow Language: Compiler/Parser/Runtime Features

### 4.1 Core module surface (`E:\Nixe\src\lib.rs`)

Core modules exported include:

- Language pipeline: `lexer`, `parser`, `ast`, `typeck`, `interp`, `codegen`, `fmt`, `error`, `lsp`
- Runtime/stdlib: `runtime`, `stdlib`, `pkg`, `net`, `tor`, `vault`
- Security/compliance/assurance passes: `privacy_pass`, `legal_pass`, `consent_pass`, `erasure_pass`, `contract_pass`, `sast_pass`, `safety_pass`, `sandbox_pass`, `crypto_policy_pass`, `constitution_pass`, `ai_act_pass`, `nis2_pass`, `otel_pass`, and others

### 4.2 Lexer (`E:\Nixe\src\lexer.rs`)

Tokenization supports:

- Keywords: `fn`, `let`, `var`, `const`, `struct`, `enum`, `impl`, `trait`, `match`, `if`, `else`, `for`, `while`, `import`, `async`, `await`, `bail`, `bail_if`, `defer`, `dyn`, etc.
- Privacy qualifiers: `private`, `secret`
- Literals: integers, floats, strings, interpolated strings (`StringStart/StringMid/StringEnd`)
- Rich operators: arithmetic, bitwise, logical, shift, power, and compound assignments
- Delimiters/punctuation for tuples/arrays/maps/generics/calls/annotations

### 4.3 Parser (`E:\Nixe\src\parser.rs`)

Parser capabilities include:

- Recovery + fast parse modes (`parse_recovering`, `parse`)
- Items: functions, structs, enums, traits, impl blocks, consts, type aliases, imports
- Statements: `let`, `var`, `return`, `for`, `while`, `loop`, `break`, `continue`, `bail`, `bail_if`
- Expressions: precedence-climbing, unary/binary ops, calls, field/index access, closures, block expressions, `if`, `match`, map/array literals, interpolated strings, casts, try (`?`)
- Patterns/types: destructuring patterns, match arms, generic type parsing
- Extensive parser tests for advanced syntax (generics, async, closures, struct spread, patterns, named args)

### 4.4 AST (`E:\Nixe\src\ast.rs`)

AST models include:

- `Program`, `Item`, `FnDecl`, `StructDecl`, `EnumDecl`, `TraitDecl`, `ImplBlock`, `ConstDecl`, `TypeAlias`, `ImportDecl`
- Statement and expression enums (`StmtKind`, `ExprKind`)
- Pattern system (`Pattern`, `MatchArm`)
- Type system expressions (`TypeExpr`, `TypeExprKind`)
- Agent-level enum and annotation models for policy/task semantics

### 4.5 Type Checker (`E:\Nixe\src\typeck.rs`)

Type-check layer includes:

- Function/struct/enum/trait/impl registration and validation
- Type resolution for primitives, generics, option/result/map/set/tuple/function signatures
- Return coverage checks and pattern binding checks
- Match exhaustiveness checks
- Privacy/sensitivity qualifiers and helper predicates
- Network-touch detection and browser-navigation usage checks in function bodies
- Agent-task annotation registration and analysis hooks

### 4.6 Code Generator (`E:\Nixe\src\codegen.rs`)

Codegen capabilities include:

- Multi-target compile entry points (`compile_with_target*`)
- Import resolution, monomorphization, trait/vtable emission
- Sync + async function emission wrappers
- Control-flow emission: `if`, loops, `match` (int/string/result/enum patterns)
- Builtins/stdlib lowering for string/array/map/math/fs/http/net/crypto/regex/time/process/json/url
- Browser method call emission path (`emit_browser_method_call`)
- Deterministic toolchain args + runtime lib discovery

### 4.7 Interpreter Runtime (`E:\Nixe\src\interp.rs`)

Interpreter/runtime features include:

- Program register/run/call API (`run`, `run_capturing`, `call_fn_with_args`)
- Scoped environment and closure capture execution
- Coverage recording and source tracking
- Import resolution/loading
- Value/provenance chains and redaction/masking/hash helpers
- Async handling (`await`, promise-like wait semantics)
- Extensive method dispatch including arrays/maps/strings and stdlib modules
- Browser sentinel integrations and domain-specific sentinels (observability, transfer, security families)

### 4.8 CLI/Tooling (`E:\Nixe\src\main.rs`)

CLI supports broad workflows including:

- `build`, `run`, `check`, `lint`, `fmt`, `doc`, `test`, `repl`, `lsp`, `targets`
- compliance/security: `audit`, `sast`, `pia`, `sbom`, `smt-export`
- package management: `add`, `remove`, `update`, `install`, `publish`, `search`, `why`, `patch*`, `tree`, `cache`, `outdated`
- crypto utilities: `hash`, `encrypt`, signing/verification commands
- browser subcommands and configuration/completions

## 5) Scraper Engine Features (Tallow Browser Stack)

### 5.1 Browser module breadth (`E:\Nixe\src\browser\mod.rs`)

The browser stack exposes a large modular scraping platform, including:

- CDP/browser control, page/frame/element/session/network handling
- anti-bot/stealth stack: `stealth`, `stealth_v2`, `stealth_v3`, `advanced_stealth`, `vendor_detect`, `retry_intelligence`
- proxy/identity stack: proxy pool/intelligence, ASN diversity, IPv6 pool, mobile rotation, tor tooling
- extraction stack: smart/AI/LLM extraction, structured data, schema drift, self-healing selectors
- orchestration: adaptive/turbo/distributed crawling, queue/scheduler/router, dual-mode engine
- quality/compliance/observability: robots/rate limiting, quality validation, trace/recording, provenance/privacy scanning
- specialized modules: slider CAPTCHA, warmup/cookie farm, resource blocker, A/B layout detection

### 5.2 Level system (`E:\Nixe\src\browser\presets.rs`)

Internal level enum:

- `L1Scout`
- `L2Standard`
- `L3Deep`
- `L4Full`
- `L5Maximum`

Default level configs include:

- L1: `http`, low stealth, max concurrency 20, raw extract
- L2: `stealth_http`, TLS/H2 fingerprinting, concurrency 10
- L3: residential+cookie farm+retry intelligence, concurrency 5
- L4: dual-mode + LLM extract + behavioral sim, concurrency 3
- L5: dual-mode + mobile/ipv6 + slider + HAR/full archive, concurrency 200

Route-policy depth/transport increases by level, with L5 using unlimited depth + pipe-only transport.

### 5.3 Canonical level IDs used by API (`E:\Nixe\tallow-search\api\src\routes\presets.rs`)

`tallow-search` maps internal level names to API-facing canonical IDs:

- `L1Scout` -> `L1Quick`
- `L2Standard` -> `L2Standard`
- `L3Deep` -> `L3Deep`
- `L4Full` -> `L4Complete`
- `L5Maximum` -> `L5Extreme`

This is why snapshot tooling accepts `L1Quick..L5Extreme` naming.

## 6) Tallow Search Project Features (`E:\Nixe\tallow-search`)

### 6.1 API architecture (`api/src`)

- Axum API with auth middleware, CORS validation, startup config validation, migrations, scheduler startup
- Browser-enabled routes gated by feature flag
- URL outbound guard includes SSRF/private-IP protections

### 6.2 API route surface (`api/src/routes`)

Route module categories:

- `data_*`: 24 modules (market/news/econ/crypto/patents/regulatory/zacks/etc.)
- `finance_*`: 5 modules
- `site_profiles_*`: 48 modules
- execution/export/admin routes: execute + execute_* + export/presets/jobs/proxies/results

### 6.3 Zacks snapshot runner (`api/src/bin/rating_snapshot_once.rs`)

Current single snapshot binary supports:

- one-time snapshot orchestration and ingestion-run lifecycle tracking
- provider/universe/level/proxy-tier and concurrency controls
- API dispatch preflight validation (db reachability, auth env, proxy env, URL health)
- canonical level parsing (`L1Quick/L2Standard/L3Deep/L4Complete/L5Extreme`)
- job insertion/start/polling and completion metrics
- row counting for total extracted and Zacks-specific extractor rows

### 6.4 Web frontend (`web/src`)

Astro + Svelte app with feature areas including:

- search/analyze/jobs/settings/export
- finance tabs (dashboard, screener, compare, options, darkpool, congress, signals)
- grocery/property workflows
- proxy manager, level selector, history, charts, alert/webhook configuration

## 7) Core Crates (`E:\Nixe\crates`)

### 7.1 `tallow-crypto`

- PQ + hybrid crypto primitives (KEM/signature/symmetric/hash/KDF/ratchet/memory hygiene)
- strict no-unsafe posture and zeroization-focused safety model

### 7.2 `tallow-net`

- transport/discovery/NAT/privacy/relay/signaling modules
- QUIC/TLS-oriented network substrate and peer-channel abstractions

### 7.3 `tallow-protocol`

- wire protocol, transfer, room/chat, metadata, compression/multi-transfer modules
- feature-gated full vs wasm profiles

## 8) Tallow `.tl` Surface

- Scope-wide `.tl` files discovered: 600
- Root stdlib `.tl` modules in `E:\Nixe\stdlib`: 33 (agent/browser/cloud/crypto/db/http/net/osint/forensics/transfer/etc.)
- Additional `.tl` workloads exist across examples, scripts, hackthecart pipelines, and `openclaw-tallow/tallow`

## 9) OpenClaw-Tallow Workspace (`E:\Nixe\openclaw-tallow`)

Release workspace provides:

- OpenClaw-style platform layers implemented in `.tl`
- capability registry/parity matrix generation
- policy engine and pack lifecycle
- scraping subsystem contracts/orchestration
- compatibility adapters and migration artifacts
- reliability/security/compatibility gate scripts and reports

Key directories:

- `tallow/` (product logic in `.tl`)
- `packs/` (capability pack manifests)
- `policy/` (deny-by-default policy profile)
- `registry/` (generated registry/parity)
- `scripts/` (gate + soak/disaster-recovery automation)
- `reports/` (gate + reliability runtime evidence)

## 10) What Was Delivered for "See Every File/Folder"

Delivered artifacts that satisfy full recursive visibility:

- Full index of every directory and file in scope:
  - `E:\Nixe\docs\TALLOW_SCOPE_FILE_FOLDER_INDEX.txt`
- Summary counts by root:
  - `E:\Nixe\docs\TALLOW_SCOPE_COUNTS.csv`
- Extension-level composition by root:
  - `E:\Nixe\docs\TALLOW_SCOPE_EXTENSION_COUNTS.csv`

If you want, I can generate a second "source-only" index that excludes build artifacts (for example, `target`, bundled outputs, and cache-heavy trees) so the inventory is easier to review manually.
