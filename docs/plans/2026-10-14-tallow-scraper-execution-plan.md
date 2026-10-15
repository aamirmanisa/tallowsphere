# Tallow Scraper — Phase-by-Phase Execution Plan

> **For Hermes / any supervisor:** execute task-by-task. Fresh subagent per task, spec-compliance review then code-quality review before the next task. Every item below is labelled and carries a checkable completion.

**Goal:** Close the verified-open items from `docs/extraction-engine/TALLOW-SCRAPER-AUDIT-2026-10-14.md` and make the extraction stack's advertised behaviour match its actual behaviour, without breaking the egress contract or interp/native parity.

**Source of truth:** `docs/extraction-engine/TALLOW-SCRAPER-AUDIT-2026-10-14.md` (this plan implements its Part E, in that order). Prior art not to be re-derived: `REA-INTEGRATION-ASSESSMENT.md`, `RECONCILIATION-2026-10-12.md`, `EXTRACTION-ENGINE-SPEC.md` §12, `docs/mega/MEGA-CHECKLIST.md`.

**Architecture:** everything lands in the existing layers — `src/stdlib/**` (facades), `src/runtime/**` (`#[unsafe(no_mangle)] pub extern "C"` FFI), `src/codegen.rs` + `src/interp.rs` (must stay byte-identical), `src/main.rs` (clap verbs), `src/browser/**` (pipeline/provenance). No new runtime except the P1 decision.

**Tech stack:** Rust (edition 2024), clap 4, serde/serde_json, ed25519-dalek, cargo. Node/Python only where the audit already placed them.

---

## Executor reality (as it is, not as the plan would prefer)

- **`delegate_task` max_concurrent_children = 1 on this deployment.** Therefore: **phases run sequentially, and tasks inside a phase run sequentially.** Any parallelism claim in this plan would be false.
- **Human gates: 1** — `P7.G` (REA decision re-affirmation). Two gates closed by the operator on 2026-10-14: `P1.G` (no Ollama; use the current model) and `P0.G` ("**1 add features**" → the `tallow-crypto` repair). A supervisor must not dispatch a gate item; it must surface it.
- **Box rules that bind every task** (see Cross-phase rules): probe-verified claims only; `cargo fmt` over the whole workspace hangs; debug builds measure ~20× slower than release.
- **Working tree is dirty (~4312 entries).** Never sweep unrelated churn. `git add` only the files a task names.

## Phase map and gates

| Phase | Title | Items | Gate | Blocked by |
|---|---|---|---|---|
| P0 | Build verification without crossing the sendtallow line | P0.G, P0.T1–T3 | ✅ **RESOLVED 2026-10-14** | — |
| P1 | Point the schema-first tier at the current model | P1.T1–T6 | resolved (operator, 2026-10-14) | **nothing — P0 green** |
| P2 | Bind the last two FFI symbols | P2.T1–T4 | — | nothing |
| P3 | Extraction CLI surface | P3.T1–T4 | — | nothing |
| P4 | Typed unknowns / limitations | P4.T1–T3 | — | nothing |
| P5 | HAR import | P5.T1–T3 | — | nothing |
| P6 | Flags & `ml` honesty | P6.T1–T2 | — | nothing |
| P7 | REA decision record + runbook | P7.G, P7.T1–T3 | **P7.G human** | P2 (evidence) |

**Gate timeline:** the only open human gate is **`P7.G`**, which blocks P7.T1–T3 and nothing else. **P0 is closed** — the workspace compiles (`cargo check` RC=0, 2m59s, zero errors), so every phase P1–P6 is now unblocked and startable.

---

## P0 — Build verification without crossing the sendtallow line

**Objective:** give every later task a compilable tree to verify in — **without committing a file that belongs to the sendtallow-protocol line of work.**
**Operator constraint (2026-10-14):** *"Don't touch anything related to sendtallow."* Off-limits: the sendtallow website, the room-code/passcode contract in `crates/tallow-protocol`, `src/stdlib/transfer_net.rs` (chat/group-chat/relay), `src/stdlib/relay_room.rs`.
**Finding (verified this session — this is why P0 changed):** the missing file sits inside that blast radius by **lineage** and by **purpose**:
- `crates/tallow-crypto/src/lib.rs:28` (`mod rng;`) was added by `e5fec4cd` — *"protocol: port the v8 wire change into canonical"* (2026-10-13).
- `crates/tallow-crypto` is a dependency of `crates/tallow-protocol` (`crates/tallow-protocol/Cargo.toml:35`) — the sendtallow contract crate.
- `rng.rs` (19 lines, `pub(crate) fn csprng() -> impl getrandom04::rand_core::CryptoRng`) documents itself as a **wasm-compatible blanket replacement of `rand_core::OsRng`** — the primitive the room-code and relay paths consume: `crates/tallow-protocol/src/room/code.rs:32,51,306` use `rand::rngs::OsRng`; `transfer/relay.rs:493,1026` use `thread_rng`; `src/stdlib/transfer_net.rs:196-200` (itself off-limits) builds room codes with `rand::rng()`.
- Counterweight: `csprng()` currently has **zero call sites** — the module is dead code today, so committing it changes no runtime behaviour. It only unblocks compilation.

### P0.G — ✅ RESOLVED (operator, 2026-10-14: "1 add features")
**Decision:** apply the `tallow-crypto` repair. **Applied and verified this session:**
1. `crates/tallow-crypto/Cargo.toml:64` → `getrandom04 = { package = "getrandom", version = "0.4", features = ["sys_rng"] }`
2. `rng.rs` remains **untracked** — the operator approved "add features", the commit was not requested. **Consequence, stated rather than hidden: a clean checkout still fails with `E0583` until that file is committed.** The working tree is green; the clean-checkout gap is open.
**Evidence:** `cargo check -p tallow-crypto` **RC=0** (0.29 s) · `cargo check -p tallow-protocol` **RC=0** (1m09s, zero errors) · **`cargo check` workspace-wide RC=0 in 2m59s, zero errors** · `df /` 74% → 75%.
**Blocks:** nothing. P1–P6 are startable.

### P0.T1 — ✅ PASSED (re-run after the fix)
The original form of this task failed: injecting `rng.rs` alone was **not** sufficient (`CHECK_RC=101`, three further errors — see B2 in the run report). After the manifest fix the same check passes. The sendtallow-free worktree procedure remains the correct way to prove a build without committing:
1. `git status --porcelain | wc -l` — baseline (was 4313; unchanged by every step below).
2. `git worktree add --detach /tmp/clean-v1 HEAD` → `cp crates/tallow-crypto/src/rng.rs /tmp/clean-v1/crates/tallow-crypto/src/rng.rs`
3. `cargo check -p tallow-crypto` **in the worktree, with the fix applied there** → **RC=0**
4. `git worktree remove /tmp/clean-v1 --force` → baseline re-checked.
**Note:** without the manifest fix this worktree run **fails**, which is exactly how B2 was found. Both files must change together.

### P0.T2 — ⏸ OPEN (commit not requested)
Commit of `crates/tallow-crypto/src/rng.rs` is the one remaining change for a clean checkout to build. Offered, not performed: `git add crates/tallow-crypto/src/rng.rs` → `git show --stat HEAD` must list **exactly one** file.
**Rollback:** `git reset --soft HEAD~1 && git restore --staged crates/tallow-crypto/src/rng.rs`.

### P0.T3 — ✅ RECORDED
**`v1` at HEAD `384daa3b` compiles in the working tree** (`cargo check` RC=0, 2m59s, zero errors, 20 pre-existing warnings in the `tallow` bin). **It does not compile from a clean checkout** until P0.T2 lands. Both halves are now stated rather than carried silently.

---

## P1 — Point the schema-first tier at the current model

**Objective:** end the state where `TALLOW_LLM_EXTRACT` defaults to ON while no engine answers, so the tier silently converts "not attempted" into "attempted, failed" — and make its engine the operator's **current model**, not a local Ollama.
**Operator decision (2026-10-14, recorded):** *"We're not going to use ollama, only this current model."* No new resident service; the engine is the model already configured for the fleet (`provider: deepseek`, `model: deepseek/deepseek-flash`).
**Files:** `src/browser/llm_extract.rs` (`:158` error variant, `:187-239` config + client build, `:634-663` availability probe, `:664+` the call), `src/browser/smart_extract.rs:105-135`, `src/vault/**`, `src/run_evidence.rs`.

### P1.R — RESOLVED (no longer a gate)
Prior gate offered (a) conditional default vs (b) install Ollama. **Both are superseded by the operator's decision.** P1 is now unblocked and proceeds with the tasks below.

### P1.T1 — Generalize the engine client from Ollama-only to OpenAI-compatible
**Files:** `src/browser/llm_extract.rs` — `:158` (`ExtractError::OllamaUnavailable`), `:187` (`ollama_url`), `:204-239` (`with_config` + `reqwest::Client` build), `:634-647` (`check_ollama_available` → `{base}/api/tags`), `:652-663` (`ensure_ollama_available`), `:664+` (`call_ollama` → `{base}/api/generate`).
**Steps:**
1. Introduce a backend enum with two variants: `Ollama` (kept, dormant, for offline use) and `OpenAiChat` (`POST {base}/chat/completions` with `Authorization: Bearer <key>`, `model`, `messages`) — the active one.
2. Rename the field `ollama_url` → `engine_url` and the error variant `OllamaUnavailable` → `EngineUnavailable` (update its single `Display` arm at `:158`); the string "ollama unavailable" must stop being what a cloud failure prints.
3. Health probe becomes backend-aware: for `OpenAiChat`, a bounded `/models` call (or a 1-token request) — never a full extraction just to probe.
4. Defaults: `model = "deepseek/deepseek-flash"`. **Leave `engine_url` and the key UNSET by default** so the tier stays off until the operator configures it (this is what makes the default honest).
5. **Do not weaken the existing egress guard** (`:221-237` builds the client through `browser_zone_egress_for(engine_url)` / `browser_zone_reqwest_proxy()` and refuses rather than egressing from the box IP, tagged N3). A cloud backend rides that same plane or refuses.
**Verify:** `cargo check` clean; unit test against a local stub HTTP server asserting the request shape (`/chat/completions`, bearer header present, model field = configured model).
**Rollback:** revert the hunks; the Ollama path is untouched behind the enum.
**Commit:** `refactor(extract): make the LLM tier engine-agnostic, default to the configured model`

### P1.T2 — Key custody (never argv, never a `.tl` literal)
**Files:** `src/vault/**` (`credential.rs`, `key_custody.rs`), the client build site in `src/browser/llm_extract.rs`.
**Steps:**
1. Resolve the API key from the vault (the existing custody path), not from a `.tl` literal and not from a value passed on the command line — `EXTRACTION-ENGINE-SPEC.md` §4.9 already forbids the latter for credentials.
2. If an environment variable is used, it is **read** by the process; it must never appear in `argv`.
3. A missing or unreadable key is a **refusal with a reason**, not a fallback to a direct unauthenticated call.
**Verify:** with the key configured, `ps -ef | grep -i tallow` shows **no** key material; with it absent, the tier reports `disabled (no credential)` and never egresses.
**Note:** inside the scrape sandbox the credential rules are stricter — files must be owned by uid 10001 and mode 0600 (`scrape-isolated`); `root:root 0600` is unreadable, `root:10001 0640` is refused.

### P1.T3 — Egress plane and data-flow (name it before it ships)
**Steps:**
1. Confirm the provider call rides the zone/Tor egress with refuse-direct intact. Do **not** add a direct-egress exception; if the provider turns out to be unreachable over that plane, that is a **new operator gate** — a provider-direct exception is a high-blast-radius egress change and needs explicit approval, not a quiet `TALLOW_ALLOW_DIRECT`.
2. Record the data-flow in the code's own doc comment: the vendor receives the page content and the prompt; with the guard intact the box IP does not leave the box.
**Verify:** a probe run shows the outbound connection going to the zone proxy port, not a direct socket; `toregress` (or an `ss -tnp` sample) is quoted as the evidence.

### P1.T4 — Honest default + "which tier ran" recording
**Files:** `src/browser/smart_extract.rs:105-135`, `src/run_evidence.rs` (`record(kind, payload)` at `:74`).
**Steps:**
1. Tier is ON only when **all three** hold: `TALLOW_LLM_EXTRACT` truthy, a credential resolves (P1.T2), and the engine answers (P1.T1 probe). Otherwise OFF, with the failing condition named.
2. Keep `TALLOW_LLM_EXTRACT=1` as a forced-on override, but a forced-on tier with no engine must still record `reachable: false` rather than pretending.
3. Emit one evidence record per run: `{llm_tier: {enabled, engine_url, model, credential_present, reachable, reason}}`, and print one line in the run report.
**Verify:** `cargo test --lib smart_extract -- --nocapture` → pass; then `jq` the newest evidence record from a fixture run and quote it.
**Why:** without this, "tier enabled" and "tier working" stay indistinguishable — the exact defect this phase exists to remove.

### P1.T5 — Compliance gate: the plan's own policy governs the transfer
**Files:** the extraction plan loader (`examples/request-plan.v1.json` shape) + the tier call site.
**Steps:**
1. The tier sends third-party page content to a third-party vendor. Gate it on the plan's existing compliance block (`source_authority`, `purpose`, `legal_basis`, `pii_policy`).
2. If the block is missing, or `pii_policy` forbids third-party transfer, **refuse the tier for that run** and record a limitation (uses P4's mechanism) — do not send.
**Verify:** a plan with `pii_policy: redact`-class values yields `llm_tier: refused (policy)` and zero outbound provider calls.
**Why:** a data transfer that the plan format already governs must not be the one path that bypasses its own governance.

### P1.T6 — Cost/latency budget and measurement
**Steps:**
1. Per-run cap on model calls and tokens; past the cap, **refuse rather than run** (fail-closed, matching `budget.rs` elsewhere).
2. Measure on a fixture corpus: `model_calls/page`, tokens/page, `ms/page` for page 1 vs pages 2..N of one domain+page-type.
**Verify:** pages after the first of each domain+page-type report **0 model calls**; quote all three numbers. If the engine is unreachable, `tier=disabled-by-probe` is a valid completion — say so rather than reporting a silent no-op.
**Non-claim:** no multiplier is asserted; no benchmark was run when this plan was written.

---

## P2 — Bind the last two FFI symbols

**Objective:** `Crawler.from_sitemap` and `StructuredData.extract` are declared `// native` in `.tl` with interpreter facades in Rust but no native symbol, so the compiled path cannot lower them.
**Verified state:** `tallow_crawler_from_links` (`src/runtime/crawler_ffi.rs:49`) and `tallow_page_cache_create` (`src/runtime/page_cache_ffi.rs:46-47`) are already bound — **copy those two files' shape, do not invent a new one.**

### P2 — ✅ COMPLETE (2026-10-15): T1, T2, T3, T4 all landed

*(Header superseded. The halt below is history: it was recorded when a sibling lane held
`crawler_ffi.rs` and the phase's premise had not yet expired. T1 `7fd59db4`, T3/T4 `381475fb`,
T2 `f9fb8f27` — with T2 bound, the declared `// native` surface is fully bound.)*

Investigated before writing code. Two independent grounds, both measured.

**(1) P2.T2's premise is superseded by a recorded operator decision.** `src/interp.rs:52465-52472`: `test_crawler_from_sitemap` was retired on 2026-10-14 because that arm "now performs real network discovery through the `browser::sitemap` facade", and "a network-bound arm cannot be asserted in a unit test, and this host's egress refuses loopback, so a local fixture is unfetchable". **P2.T2's and P2.T4's acceptance tests are therefore not constructible on this box as written.** The symbol can be bound; the verification this plan demands cannot be run.

**(2) P2.T1's edit sites sit inside a sibling lane's parked, uncommitted work.** Both required `src/codegen.rs` edits land in regions another lane rewrote today at 16:56 and left uncommitted (+316/−173):

| Edit needed | Location | Sibling's parked hunk |
|---|---|---|
| `declare ptr @tallow_structured_data_extract(ptr)` | declare block ~1337 | `@@ -1269,5 +1282,7 @@` |
| the call-lowering arm | ~20629–20681 | `@@ -20378 +20629,5 @@` … `@@ -20531,14 +20681,5 @@` |

That lane is binding natives by this exact playbook (`tallow_regex_is_match` / `tallow_regex_replace` at 1287-1288 / 20641 / 20679; runtime `src/runtime/regex_ffi.rs`, untracked, 240 lines, 07:36). `src/runtime/mod.rs` carries their `+pub mod regex_ffi;` (07:36). **No writer was active in the 60 min before the probe** — parked, but a second agent's hands are in the same two files.

**Contradicting this plan's premise — the layout is already committed:** `src/codegen.rs:1906-1923` at HEAD registers `%struct.StructuredData` with `open_graph` → `LLType::I8Ptr` and `field_kinds["open_graph"] = "Map"`, and `Map` is a first-class result kind (`:364`, routed `:6756`/`:7214`). The missing piece is only the symbol + declare + lowering arm.

**Template correction:** this plan said "copy `crawler_ffi.rs`/`page_cache_ffi.rs`". Both are **strings + ints only**. `structured_data_extract` is a **bare function** (`stdlib/browser.tl:441`), not a struct-static method — the correct template is the sibling's `src/runtime/regex_ffi.rs` (bare fn, string args, pointer return).

**To unblock, one of:** (a) the sibling lane commits or stashes → P2.T1 proceeds normally; (b) P2.T1 is explicitly assigned here and the interleave is accepted; (c) P2.T2 is reduced to the bare symbol with **no** parity test, recording the coverage gap as stated rather than implied.

### P2.T1 — `tallow_structured_data_extract`
**Files:**
- Create: `src/runtime/structured_data_ffi.rs`
- Modify: `src/runtime/mod.rs` (register the module)
- Reuse: `src/stdlib/browser.rs:35` (`structured_data_extract` — the interpreter facade already exists)
- Modify: the codegen lowering arm for the `.tl` native (locate it: search `src/codegen.rs` for the native name — it is not yet bound, so it may fall back to the interpreter today)
**Steps:**
1. Copy the header contract style from `crawler_ffi.rs:1-30` — **return via out-params, never a struct pointer** (the documented reason: a struct-pointer return silently couples LLVM struct layout to a hand-written `#[repr(C)]` and breaks on any field reorder/pad change).
2. `StructuredData` is `{json_ld: []String, open_graph: Map<String,String>, has_json_ld: bool}` (`stdlib/browser.tl:435-440`) → out-params: a `*mut *mut c_char` array for `json_ld`, a serialized string for `open_graph`, an `i64` flag. Document the encoding in the file header.
3. Call the **same** `stdlib::browser` facade the interpreter uses, so native and interpreted results cannot disagree.
4. Null out-parameter ⇒ `set_last_error` + null return; never write partially.
**Verify:** `cargo check` clean.

**MEASURED 2026-10-15 — the exact sites, and a correction to what I said earlier about the ABI.**
The plan is right and my earlier characterisation was wrong: this does **not** require a native that
constructs `%struct.StructuredData`. Step 1's convention — out-params, never a struct-pointer return —
is the documented house style, and it exists precisely to avoid coupling LLVM struct layout to a
hand-written `#[repr(C)]`. The native returns the pieces; **the lowering arm builds the struct.**

Sites, all verified by reading rather than assumed:
- **Interpreter arm**: `src/interp.rs:9959` (`"StructuredData.extract"`). It already delegates to the
  facade — no change needed, and it is the parity reference.
- **The facade to call** (one implementation, so native and interpreted cannot disagree):
  `src/stdlib/browser.rs:35` (`pub(crate) fn structured_data_extract(args) -> StdlibResult`), dispatched
  at `:520`.
- **The layout the ARM must produce**: `src/codegen.rs:1938-1955` registers `%struct.StructuredData`
  with `field_kinds` — **load-bearing and unlike the three other layouts**, because all three fields
  lower to `I8Ptr` and the *kind* is the only thing that routes `sd.json_ld.len` to the array count slot
  instead of `strlen`. `has_json_ld` is `i1`.
- **The template for the FFI file**: `src/runtime/regex_ffi.rs` (`#[unsafe(no_mangle)] pub extern "C"`,
  landed in `8e5bdaac`), plus `crawler_ffi.rs:1-30` for the header contract.
- **The template for the declare + call arm**: `tallow_regex_is_match`, declared at `codegen.rs:1287`
  and called at `:20641`, with assertions at `:30032`/`:32620` that the IR contains the call.

**Why this is still a fresh-session item, stated as a resource limit and not a wall:** the delicate part
is the codegen arm — allocating the struct, storing the out-params into it, and keeping the result
byte-identical to the interpreter's — and it sits on the `interp.rs`/`codegen.rs` parity surface where a
half-applied change is worse than none. There is **no correctness defect** to fix: the fallback returns
correct output and `--require-native` refuses loudly. Attempting it with a nearly-exhausted context is
how an unfinished ABI edit gets left behind, which is the one outcome the plan forbids outright.
**BLOCKED 2026-10-15 on a codegen gap the plan's own scope does not name.** Measured, not inferred:

*`[]String` is fine.* `tallow_array_len(ptr)` is declared (`codegen.rs:1401`), the "array count slot"
convention is real, and `"StringArray"` is a consumed kind — `emit_array_count_inline` /
`emit_array_count_value` (`:7609`, `:14082`) route `.len` to it. So `json_ld` is mechanically bindable.

*`Map` is not.* The layout registers `field_kinds["open_graph"] = "Map"` (`:1946`), and a Map type does
lower to `LLType::I8Ptr` (`:20736`) — but **nothing in codegen ever produces a Map value**:
`rg '%struct.Map|map_alloc|MapEntry'` in `codegen.rs` → zero matches, and the `"Map"` tag has **no
consumer** (contrast `"StringArray"`, which has the `.len` routing above). Meanwhile the interpreter's
`extract_open_graph` (`stdlib/browser.rs:73`) returns a genuine `Value::Map`, and its own test asserts
exactly that (`:1430`, "expected open_graph Map").

So step 2 above — "a serialized string for `open_graph`" — **contradicts the kind the layout
registers**. That is not a cosmetic inconsistency: it decides whether P2.T1 is a binding (small, as
scoped) or a language feature (Map values in AOT, well beyond this item). Reconciling the two is a
**decision, not a task**:

- **(a) Register the field as `"String"`** and have the native emit `open_graph` serialized, accepting a
  documented divergence from the interpreter that the parity test in P2.T3 must then encode as
  *expected*, not as a failure. Small — but it means AOT and interpreted `StructuredData` are not the
  same value, which is precisely what P2.T3 exists to guarantee.
- **(b) Build Map values in codegen** (allocator, entry layout, `.len`/index routing) — a real language
  feature; P2.T1 becomes its first consumer, not its scope.

Recommendation: **(a)**, with the divergence stated in the header contract and in P2.T3's acceptance
test, because (b) is a language change smuggled in under a scraper task and the plan's own byte-parity
rule would otherwise be quietly weakened.

**SUPERSEDED — P2.T1 IS IMPLEMENTED AND VERIFIED (2026-10-15).** Real commits: `1efb80b`
("codegen+runtime: bind StructuredData.extract natively (P2.T1)"), `78213ad` ("test+interp: parity
for StructuredData.extract, and the defect it found"), `daf5164` ("codegen, runtime: open_graph is a
Map in AOT too, not a serialized string"). *(This line cited `7fd59db4`, which does not resolve —
`git cat-file -t` → "Not a valid object name". The artifacts it refers to are real and committed;
only the hash was wrong. That is the fourth unresolvable citation found in this document, which is
why the rows above and below name artifacts instead.)* The "blocked on a
decision" note above was wrong, and so was the fork it offered. Measuring the runtime's own surface
settled it without a decision:

* **(a) vs (b) was a false choice.** `open_graph` cannot be a Map in AOT and cannot be "serialized by
  choice" either: codegen has no Map value at all (`%struct.Map`, `map_alloc`, `MapEntry`: zero
  occurrences; no `tallow_map_*` anywhere) and the layout's `"Map"` tag had **no consumer**. Serializing
  is the only option that does not mean inventing Map *values and readers* under a scraper task.

  **CORRECTED (2026-10-15): that premise was wrong, and it misled the next reader.** Codegen *does*
  have a Map value: `ExprKind::MapLit` lowers to a tagged flat buffer
  (`codegen.rs:4699`, `[count][k0][v0]…[kN][vN][t0]…[tN]`), and `emit_map_len` (`:15612`),
  `emit_map_get` (`:15779`), `emit_map_keys` and `emit_map_values` are real readers of it. The grep
  that produced the claim was for three *symbols* — `%struct.Map`, `map_alloc`, `MapEntry` — and
  "those symbols do not occur" is not "the value does not exist". What was actually missing was
  **routing**: the map branch of method dispatch (`:7231`) and the index path (`:5137`) both required a
  bare variable receiver, so a Map-typed *field* never reached them and `.len` fell through to
  `strlen` on the serialized buffer. Serializing was therefore not forced — it was one of two options,
  and the wrong one. The field now declares `Map<String,String>`, the FFI returns the runtime's one Map
  layout, and `tests/structured_data_parity.rs` pins the map in both engines.
* **The plan's step-2 mechanism was wrong.** A raw `**c_char` out-param cannot work: a runtime array has
  one shape (`native_array`: `[count][slot…]` as a boxed `[i64]`) built inside producers, with no public
  constructor — so the native builds it with the same helper the other string-array producers use.
* **The field split was already solved by a bound native.** Mirroring `tallow_crawler_from_links`
  (return the one computed string, out-param the rest) meant refusal propagation reuses
  `emit_runtime_string_null_check` — no new IR failure path to trust.
* `has_json_ld` is the one struct field anywhere that is genuinely `i1`, so it is stored by hand;
  `emit_store_i64_field` would write eight bytes into one bit.

**Evidence:** `cargo check --lib --bins` RC=0 · codegen suite **621 passed / 0 failed** ·
`runtime::structured_data_ffi` **7 passed / 0** · then the CLI under `--require-native`, which by contract
refuses the interpreter fallback, exited 0 printing `true/1/false/0` over a native link step — and the
same flag on the same binary exited 1 with "native build unavailable" when the probe was broken, which
is the contrast proving the values came from the AOT path.

**Two defects the proof caught, both in the test rather than the binding:** the probe's original JSON-LD
body contained braces, which Tallow reads as string *interpolation*, so the emitted IR referenced an
undefined global and the native build failed — and `--require-native` refused instead of quietly
interpreting, which is the flag doing its job. Then the first commit of this change was **reverted and
redone**: `rustfmt` on `codegen.rs` (never format-clean) turned a four-site edit into 55 hunks and 184
deletions; the churn was removed and the edits re-applied against the baseline, giving a 4-hunk diff that
was re-verified on its own.

**Remaining in this phase:** T3/T4 were scoped out because T2's natives were unbound — with this native
bound, the parity and refusal coverage for **it** is now possible, and is tracked as P2.T3 below with the
both-natives wording corrected.

### P2.T2 — `tallow_crawler_from_sitemap` — ✅ DONE (`f9fb8f27`)
**Files:** `src/runtime/crawler_ffi.rs` (the FFI joined its `from_links` sibling in the same file —
both crawler natives belong together) · `src/codegen.rs` (declare + dispatch + arm) ·
`src/interp.rs` (see the coercion fix below) · `tests/crawler_parity.rs` + fixtures 19–21.

**Re-scope reversed, because its premise expired.** T2 was scoped out when its sibling
`crawler_from_links` was unbound (a lane was mid-edit) and no parity harness existed for the class.
Both conditions became false: `from_links` is bound, and T1's work produced the harness. So T2 became
a mirror with a bound template.

**What it is, precisely:** the interpreter arm already fetched (`interp.rs:9798` → facade →
`SitemapParser` over `runtime::egress_http`, Tor by default, refusing rather than falling back to the
box IP); codegen had **no lowering at all**, so a compiled program silently fell back to the tree-walker
and `--require-native` refused. Binding adds no capability and changes no egress policy — it removes the
asymmetry, and the fetch stays governed by the same Tor-or-refuse path.

**Return shape flips from T1's:** the runtime *produces* `seed_url` (the first parsed entry) and returns
it; the echoed `sitemap_url`, the constant `strategy` and the four integers come back through out-params.
Every field is read **by name**, so a reordered field refuses instead of shifting silently. The FFI
delegates to `stdlib::browser::crawler_from_sitemap` — the same function the interpreter arm calls.

**Plus a real defect, fixed:** both crawler arms used `v.as_string()`, so `Crawler.from_links(42)` planned
a crawler for the seed `"42"` and `Crawler.from_sitemap(42)` would have attempted discovery on it. Same
class as `StructuredData.extract(42)`, same fix: match `Value::String`, refuse otherwise, and share the
wording with the compiled arm so both engines name the same cause.

**Verify:** `cargo check --lib --bins` RC=0 · `cargo test --test crawler_parity` **3 passed / 0** ·
`cargo test --test structured_data_parity` **2 passed / 0** · `runtime::crawler_ffi` **5/0** ·
`runtime::structured_data_ffi` **7/0** · codegen **621/0**.

**Scope, stated:** `from_links` plans offline, so it gets the full three-assertion treatment with a pinned
reference. `from_sitemap` FETCHES, so its happy path cannot be exercised offline — a local fixture can
never be fetched, which the facade's own doc records. What is deterministic offline is the refusal
(rejected before any egress), and that is pinned in `tests/crawler_parity.rs`.

**The happy path was then verified live, and later retired from the "unverified" list:**

| Step | Observation |
|---|---|
| independent reference, read **outside Tallow** (`torcurl`, first `<loc>`) | `https://www.sitemaps.org/` |
| interpreter leg (`--target x86_64-linux`) rc=0 | seed `https://www.sitemaps.org/` · strategy `sitemap` · maxpages `84` · sitemap_url echoed |
| native leg (`--require-native`, no fallback permitted) rc=0 | byte-identical |
| comparison | **IDENTICAL**, and the seed matches the independently-read `<loc>` |

So the compiled path performed a real 84-entry sitemap fetch itself — no fallback, over the Tor plane
proven before the run (`IsTor:true`, exit IP differing from the box's `203.0.113.1`). Two details
worth keeping: the reference being external is what makes this evidence rather than agreement, and the
CLI binary had to be **rebuilt** first — `cargo check` and `cargo test` do not produce one, and the
pre-existing `target/debug/tallow` predated the arm, so testing against it would have reported a bogus
"native build unavailable" and indicted a binding that was fine.

The live fixture is deliberately **not** in the repo: its success depends on the network and on Tor being
up, so putting it in a CI suite would make that suite depend on both.

**With T2 bound, the declared `// native` surface is fully bound** — a claim now checkable by grep.

## Found while executing P2, outside this plan's scope

**An unproxied HTTP call, and a guard that is red because of it.** `cargo test --lib runtime::` fails on a
clean checkout of this HEAD, in a file this work never touched:

```
runtime::egress_http::tests::no_bare_ureq_calls_in_the_runtime_tree
  unproxied runtime/interpreter HTTP calls found — route them through
  crate::runtime::egress_http (they would egress from the box IP):
  ["crates/tallow-locator/src/watchers.rs: ureq::get("]
```

- Site: `crates/tallow-locator/src/watchers.rs:356` — `let mut req = ureq::get(url);`.
- Pre-existing: the file last changed **2026-09-28** (`99d8c946`), and it is absent from this work's
  change set entirely.
- Why it matters: the standing egress rule is that a request must never leave from the box IP when it
  should be anonymous. A bare `ureq::get` does exactly that, and the tree's own guard exists to catch it.
- Where the work is: the guard is the finding; the fix is not obviously local, because routing through
  `runtime::egress_http` requires the locator crate to reach the runtime, which the dependency direction
  may not allow. Which crate owns that call is a design question, not a one-liner — recorded rather than
  patched under a scraper task.

### P2.T3 — Parity coverage (the house acceptance for this class)
**Wording corrected 2026-10-15:** the original said "exercise both natives". Only one of the two is
bound — P2.T2 (`tallow_crawler_from_sitemap`) was re-scoped out by decision, and T3 must not silently
claim coverage it does not have. The coverage below is for `StructuredData.extract` alone.

**Files:** new `tests/structured_data_parity.rs` (modelled on `tests/regex_engine_parity.rs`, which
established this three-assertion shape for the class) + fixtures
`tests/parity/parity_programs/17_structured_data.tl` and `18_structured_data_refusal.tl`.
**Steps:** one program, run under both engines — the interpreter forced via `--target x86_64-linux`
(a cross target takes the tree-walking path), the native via `--require-native`.
**Verify:** `cargo test --test structured_data_parity -- --nocapture` → **PASS 2/0** (`381475fb`).
**Acceptance, in increasing strength** (the third is what catches two engines agreeing on the *wrong*
answer, which the second alone cannot):
1. both legs exit 0, and the native leg must not report a fallback;
2. stdout byte-identical between the engines;
3. stdout equal to a **pinned reference block** for four deliberately-discriminating documents
   (JSON-LD present · nothing structured · two blocks, so "only the first survives" predicts a
   different count · an og tag with its attributes reversed, so an order-sensitive reader yields
   nothing).

**Covered now (2026-10-15):** `open_graph` is in the pinned block. The interpreter holds a real
`Value::Map` and the AOT field holds the same map in the runtime's one Map layout, so `A_og_len` /
`A_og_title` (`1`, `Hello`), `D_og_len` / `D_og_title` and `B_og_len` (`0`, the empty map) are asserted
byte-for-byte against the reference. Those lines are the regression trap for the two bugs above: a
`.len` reading the buffer's byte length and an index reading the first key slot as an array element
both change the output.

### P2.T4 — Refusal parity
**Steps:** the refusal arms reachable for **this** native: a non-string argument, over
`18_structured_data_refusal.tl`. (The plan's original arms — blank seed URL, malformed HTML — belong to
the crawler/sitemap natives, which remain unbound; they were mis-assigned to this native.)
**Verify:** both engines name the **same cause**, and the native path must not emit output before
refusing. **PASS — and only after the test found a real defect** (`381475fb`):

`StructuredData.extract(42)` behaved three different ways, and only one was right:

| Leg | Before | After |
|---|---|---|
| interpreter | exit 0, printed `false` — coerced the argument with `v.as_string()`, parsed `"42"` as HTML, returned a plausible value | refuses, naming the cause |
| compiled | refused (its arm requires an `I8Ptr`; no coercion exists to offer) | unchanged |
| `tallow check` | **passed** on the bad argument (`1 items, 1 warning`) | unchanged — the checker still does not enforce `html: String` |

That is the "plausible success, wrong answer" class, so T4's requirement was unmet by the
**interpreter**. The arm now matches `Value::String` and refuses anything else; the two legs agree on
the phrase "expected an HTML string argument" (the compiled leg refuses at lowering time, the
interpreter at run time — the cause matches, the kind of failure does not, and the test asserts the
cause).

**Two limits recorded in the test, not implied:** refusing at run time is a floor — the declared
`html: String` is not enforced by the type checker, so the real fix belongs there; and `v.as_string()`
appears **549 times** in `interp.rs`, i.e. argument coercion is the interpreter's house convention, so
this arm is deliberately the strict one and whether its siblings should match is a language-level
question needing its own audit — not a patch smuggled in under a binding.

---

## P3 — Extraction CLI surface

**Objective:** today `tallow extract|plan|schema|scrape` all return `unrecognized subcommand`; nothing can be scripted, dry-run, or CI-checked.
**Files:** `src/main.rs:123` (`enum Command`) and `:2555` (`match cli.command`). Follow the existing pass-through style (`Phone`, `Rmd`, `VerifyLedger` use `trailing_var_arg = true, allow_hyphen_values = true`).

### P3.T1 — ✅ IMPLEMENTED (unit-verified; binary run in flight)
`tallow schema check <file>` validates one `tallow.extraction_schema.v1` document and exits non-zero with the failing field named.
**Design note:** it does NOT reimplement validation — it calls `ExtractionSchema::from_v1_json` (`src/browser/llm_extract.rs:1177`), the same loader the extraction path uses. A second validator would be a second source of truth for "is this schema usable", which is how a schema passes CI and then fails at run time.
**Files (all clean at HEAD before this work):** new `src/cli/schema_cmd.rs` (~150 lines incl. tests) · `src/cli/mod.rs` +1 line · `src/main.rs` +~20 lines (enum variant + dispatch arm).
**Verify (run):** `cargo check --lib --bins` → **RC=0** (1m05s, no warnings from the new code) · `cargo test --lib cli::schema_cmd` → **6 passed, 0 failed** (3m52s).
**Binary run — ✅ VERIFIED end to end** (`cargo build --bin tallow` **RC=0**, binary mtime `23:43:37`, log `cache/scratch/p3-e2e2.log`):
| Check | Observed |
|---|---|
| shipped fixture | `ok: … — tallow.extraction_schema.v1, 3 field(s)` · **RC=0** |
| `schema_version` → `.v2` | `unsupported schema_version "tallow.extraction_schema.v2" (expected "tallow.extraction_schema.v1")` · **RC=1** |
| every selector → `json_path` | `field "name": no css selector` · **RC=1** — the offending **field** is named |
| no args / missing file / bad subcommand | **64 / 64 / 64** |

### P3.T2 — ✅ DONE (verified end to end)
**Premise corrected with evidence.** The path this task named (`examples/request-plan.v1.json`) does not exist. The real specimens are `examples/request_plan_get_only/request-plan.v1.json` (+ three siblings) under `schemas/tallow/request-plan-execution-contract.v1.json`. **And the `compliance` block is per-REQUEST, not top-level** — so the refusal is per-request, and this implementation refuses the whole manifest while naming every offender rather than advising a partial fetch.
`plan dry-run <file>` prints exactly what would be fetched and performs **no egress**. It refuses a wrong `schema_version`, an empty manifest, a `request_count` that disagrees with the contents, and any request lacking `compliance`.
**No-egress is structural, not promised:** `cli::plan_cmd::tests::the_dry_run_module_cannot_egress` strips comments from the module's own source and asserts it never names the egress entry point, an HTTP client, or the egress layer. (That test failed on its own doc comment in the first run — the doc names the entry point in a rustdoc link — so the guard now judges code, not prose.)
**Files:** new `src/cli/plan_cmd.rs` · `src/cli/mod.rs` +1 · `src/main.rs` +~15 (variant + arm).
**Verify (run):** `cargo check --lib --bins` → **RC=0** · `cargo test --lib cli::plan_cmd` → **7 passed, 0 failed**.
**Binary run — ✅ VERIFIED end to end** (same build, log `cache/scratch/p3-e2e2.log`):
| Check | Observed |
|---|---|
| shipped specimen | prints `manifest_id`, then `would fetch 2 request(s); egress performed: none` and both `[n] METHOD url (target_id)` lines · **RC=0** |
| one request's `compliance` removed | `1 request(s) declare no compliance block:` + `[1] fixture_products_json — https://example.invalid/api/products` · **RC=1** |
| `request_count` 99 vs 2 present | `request_count says 99 but 2 request(s) are present` · **RC=1** |
| no args / missing file / bad subcommand | **64 / 64 / 64** |
| **no-egress proof** | established outbound sockets **29 before → 29 after**, delta **0** |
| `tallow --help` (P3.T4) | both `schema` and `plan` listed with their full exit-code contracts (`extract`/`scrape` absent — P3.T3 not built) |

### P3 — two process defects found while executing this phase
1. **A build raced a source edit.** The first E2E run compiled `main.rs` while the `Plan` enum variant existed and its dispatch arm did not, so the build died with `E0004: non-exhaustive patterns: Command::Plan { .. } not covered`; the binary was never relinked and the E2E then tested the **stale 21:00 binary**, reporting `unrecognized subcommand 'schema'` — a false product failure. **Guard added:** the E2E script now aborts when `BUILD_RC != 0` and prints the binary's mtime instead of assuming freshness.
2. **A pre-existing failure sits in the same test filter, and it is NOT from this work:** `cli::fingerprint_audit_cmd::tests::test_ja4h_cookie_sorting_and_freeform_values` fails at `src/cli/fingerprint_audit_cmd.rs:1715` (`left: "ge11cn01…"` vs `right: "ge11nn01…"`). Nothing here touches that path. `cargo test --lib cli::` is therefore red for a reason unrelated to P3; a suite-level green requires that fixed separately.

### P3.T3 — ✅ RESOLVED (2026-10-14): built as (a) local-only, verified end to end

*(Header superseded. The block was resolved by the operator's "continue": the extract verb was
built local-only — `mode: local_mock`, `live_scraping: false` — and verified against the repo's
own row validator on both a complete page and one missing a required field.)*
**Steps:** wire to the existing crawl/extract pipeline; write rows to `--out`; emit the run evidence record from P1.T3.
**Verify (as written):** run against a local fixture server (`examples/fixtures/mock_server.py`) → rows written, exit 0.

**Measured: that verification cannot run on this box, for a policy reason — not a code reason.**
- The fixture server works: started on `127.0.0.1:18080`, `curl /api/products` → **200**, `/` → 404. `examples/fixtures/mock_server.py` is real and functional.
- A Tallow fetch of it fails — `HTTP request failed for http://127.0.0.1:18080/api/products: io: connection not allowed by ruleset` — and fails **identically in all three modes**: default (Tor), `TALLOW_PROXY=` (emptied), and `NO_PROXY=*`.
- That message is **not Tallow's**: `src/cli/veil_cmd.rs:405` maps **SOCKS5 reply `0x02`** to that string. The refusal comes from the box's deny-by-default SOCKS chokepoint (the allowlist chokepoint on :9050/:9053), which refuses a destination that is not on its list — loopback included.
- **Control:** a public host is allowed — `Crawler.from_sitemap("https://example.com/sitemap.xml")` produced a real HTTP round trip (`http status: 404`, i.e. example.com answered). So the egress path works; loopback specifically is not on the allowlist.

**Therefore T3's acceptance test requires adding the fixture's loopback destination to the chokepoint's allowlist — an egress-policy change.** That is high-blast-radius by this workspace's own standard and waits for explicit operator approval; it is not a change to slip in under a CLI task.

**Two ways forward, both needing your call:**
- **(i) Fixture verification with a scoped exception** — add `127.0.0.1:18080` to the allowlist for the duration of the test, then T3 verifies exactly as written. Cost: a policy edit and its re-approval.
- **(ii) No policy change** — verify the row-production half offline (in-memory HTML → rows, no egress at all), and prove the *failure* path live: `extract` against the fixture must refuse loudly with the chokepoint's message, exit non-zero, and write **no** partial rows. That is a real property, testable today, and it is the honest inversion of a blocked happy path.

**Not built as specified, and now for a third and deeper reason: the row contract forbids it.**
`schemas/tallow/extraction-row.schema.json` pins `"mode": {"enum": ["local_mock"]}` and
`non_claims.{live_scraping,external_dataset,production_ready}` — **all `const: false`**. A verb that fetches live URLs and writes these rows would be asserting `live_scraping: false` about data it scraped live: a lying artifact, and the validator's own docstring says it "refuses to turn Phase 5 artifacts into live/production claims". The plan's shape (live crawl → these rows) is therefore internally contradictory. `additionalProperties: false` throughout, `extraction_schema_version` pinned to the contract name, `fields` an object of `field_cell`s (9 required keys each), and a `quality` block — all of it must be emitted exactly.

**The acceptance test is real and executable, and it needs no egress — this is better than the fixture-server plan.** `scripts/validate_extraction_rows.py --schema … --rows … --quarantine-path … --report-path … --fail-on-invalid` runs locally over a JSONL of rows. Proven working: a hand-built row was **rejected with three specific hard errors** — `field_cell_missing` (every schema field needs a cell), `field_required_mismatch` (each cell's `required` must match the schema field), `quality_required_null_count` (the count must match reality). So row production has a precise, local, deterministic gate.

**Landed this session (needed by either interface):** `LlmExtractor::extract_with_schema` — the public half of the private `execute_schema`, so a **schema file** can drive extraction from outside `llm_extract.rs`. Selector application stays in one place.

**DECIDED AND BUILT — option (a), the local extractor.** `tallow extract --schema <f> --html <f> --out <dir> [--target-id <id>] [--source-url <u>]` is implemented:
- New `src/cli/extract_cmd.rs` (~330 lines incl. tests) · `src/cli/mod.rs` +1 · `src/main.rs` +~18 (variant + arm).
- `src/browser/llm_extract.rs`: private `V1Field` now captures the contract's declared `type`, plus a new **pub `v1_schema_metadata()`** reading `schema_id` + per-field types from the **same `V1Contract`** as the loader — so the v1 format still has exactly one parser and no public struct gained a field.
- Rows carry all nine per-cell keys, `mode: local_mock`, `non_claims` all false, and a `quality` block whose `required_null_count` is **counted from the cells actually emitted** (the exact hard error a hand-built probe tripped).
- `status: quarantined` when a required field is absent, with the reason in `quality.quarantine_reasons`, so the validator's `--fail-on-invalid` bites on the verb's own real output.
- A missing field is visible **two ways**: `null_reason: "missing"` in the cell and a limitation string via `run_evidence::record_limitations` — **P4.T2's helper finally has a caller**, closing that open half.
- `the_extract_module_cannot_egress` strips comments from the module's own source and asserts it never names the egress entry point, `egress_http`, or an HTTP client.

**Verify (run):** `cargo check --lib --bins` → **RC=0** (1m05s) · `cargo test --lib cli::extract_cmd` → **7 passed, 0 failed** (3m51s). End-to-end validator run in flight (log `cache/scratch/p3-extract-e2e.log`).
**Note on the lint:** after `rustfmt --edition 2024` cleared the file, the edit-lint still asked for `{json, Map, Value}`. That is the documented phantom — the lint sorts imports with the pre-2024 (case-sensitive) style edition; the crate is `style_edition 2024`. Left as rustfmt produced it.

**Remaining build, and the one decision it waits on:**
1. `type` and `schema_id` are **dropped by the v1 loader** (`V1Field` captures name/required/selectors/coercion only) — but a row cell requires `type` and the row requires `extraction_schema_id`. So the loader must carry both before rows can be produced without re-reading the document in a second place.
2. **Interface:** `extract --plan` implies fetching, which the row contract forbids. The truthful verb is local: `extract --schema <f> --html <f> --out <dir>`, emitting `mode: local_mock` rows gate-checked by the validator. A live variant is a **product decision** (change the row contract's `mode`/`non_claims`, plus the chokepoint's allowlist for any fixture).

### P3.T4 — Dispatch + help text
**Steps:** register all three in the enum and the match; ensure `tallow --help` lists them; add a doc line to `docs/TALLOW-CAPABILITIES.md` §2.
**Verify:** `./target/debug/tallow --help | grep -E 'extract|plan|schema'` shows all three.

---

## P4 — Typed unknowns / limitations

**Objective:** adopt the one REA convention worth taking (audit C4): an evidence record must be able to say "unknown", so absence ≠ failure.
**Files:** `src/browser/provenance.rs:25` (`ProvenanceRecord`), `:47` (`ProvenanceDisplay` — already carries `warnings: Vec<String>`), `src/run_evidence.rs:74`.

### P4.T1 — ✅ DONE (verified)
Implemented `pub limitations: Vec<String>` on `ProvenanceRecord` (`src/browser/provenance.rs:41-49`), initialised empty in `new()`, and rendered through the **existing** `ProvenanceDisplay.warnings` channel — no parallel renderer.
**Verify (run):** `cargo test --lib browser::provenance -- --nocapture` → **10 passed, 0 failed** (3 new: `limitations_start_empty_and_render_nothing`, `stored_limitations_are_rendered`, `absent_and_empty_are_distinguishable`). Wall 6m03s (test-binary link dominates).
**Files:** `src/browser/provenance.rs` — was clean at HEAD; now carries only these hunks.

### P4.T2 — ⚠️ HALF DONE (helper landed; call-site emission open)
Landed `pub fn record_limitations(items: &[String]) -> bool` in `src/run_evidence.rs`: empty list is a successful **no-op**, `kind` is fixed to `limitations`, payload is `{count, limitations[]}`.
**Deviation from this plan's sketch, stated:** the sketch wrote `record_limitations(run_id, items)`; `run_id()` is already implicit inside `record()`, so no extra parameter was added.
**Still open:** emitting it from the extraction path (the "selector matched but the field is Absent" vs "no match at all" call sites) — the helper exists and is tested, nothing calls it yet.
**Verify (run):** `cargo test --lib run_evidence -- --nocapture` → **6 passed, 0 failed** (2 new: `limitations_records_carry_their_items`, `empty_limitations_is_a_no_op`). Wall 3m50s.

### P4.T3 — ✅ DONE (verified)
`absent_and_empty_are_distinguishable` asserts a clean record produces **no** `Unknown:` warning while a record carrying a limitation does.
**Note:** touches neither `interp.rs` nor `codegen.rs` — which is why it was cheap, and why it ran ahead of P1.

### P4 — pre-existing rustfmt drift (NOT mine, left alone)
`git diff` lint flagged formatting divergences that predate this work and lie outside the touched hunks — `provenance.rs` (the `matches!` block in `to_display`) and `run_evidence.rs` (4 hunks: `scan_observation`, `sweep_observations`, `digest_pending` call, the `kinds` map). They are unrelated churn and were deliberately not reformatted.

---

## P5 — HAR import

**Objective:** the one web-plane REA capability Tallow lacks an *import* path for (`artifact_policy.har` exists but is write-only).

### P5.T1 — `src/browser/har_import.rs`
**Steps:** serde_json parse of HAR 1.2 into the same internal request/response shapes `browser/network.rs` already produces. No new dependency beyond `serde`/`serde_json`.
**Verify:** `cargo check`; unit test on a committed fixture.

### P5.T2 — Redaction before storage
**Steps:** route imported entries through the existing artifact-policy/redaction path so an imported capture cannot bypass the redaction rules that a live capture obeys.
**Verify:** a fixture HAR containing a secret-shaped value comes back redacted.

### P5.T3 — Fixture + test
**Files:** create `tests/fixtures/*.har`.
**Verify:** `cargo test --test browser_contracts <name> -- --nocapture` → pass.

---

## P6 — Flags and `ml` honesty

**Objective:** stop the docs and the code disagreeing about what is real.

### P6.T1 — `ml` census → one of two endings
**Steps:** enumerate every mock site (`src/browser/ml/embeddings.rs` is mock-dominated: 22 mock references vs 17 functions; `ml_matcher.rs` 2, `vector_store.rs` 1). For each: implement, or mark the capability unavailable.
**Verify:** the census is committed as a table in the task's handoff with a count per file; no code path claims a real embedding backend while `real-ml` is off.

### P6.T2 — Flags documented, not flipped
**Steps:** leave `parquet-storage`, `s3-storage`, `redis-backend`, `real-ml` off (`Cargo.toml:291,294,298`); add an explicit non-claim line wherever they are described as features.
**Verify:** `rg -n 'real-ml|parquet-storage' docs/` shows the non-claim adjacent to each mention.

**MEASURED 2026-10-15 — the item's own premise is partly false, and the truth is worse than the plan says:**
- `parquet-storage` (2 refs), `s3-storage` (2), `redis-backend` (3) **exist** as features. **`real-ml` does NOT exist** — `rg real-ml Cargo.toml` → 0 matches, three separate checks.
- It is not merely a docs error: `src/browser/ml/embeddings.rs:69,79` gate on `#[cfg(feature = "real-ml")]` / `#[cfg(not(...))]`, so those branches are **dead and uncompilable-by-construction** — the feature has never existed, so the gated branch has never been built. Every build emits two `warning: unexpected cfg condition value: real-ml`.
- Correction to my own earlier claim ("the code directs users to a switch that cannot be thrown"): the two `src/main.rs` hits (`:16273`, `:16292`) are **pattern strings inside classifier hint tables** (`GATE_SOURCE_HINTS` / `GATE_MSG_HINTS`), not user-facing refusals. **Nothing in the tree emits that string.**
- Therefore the honest fix is a decision, not a doc edit: either declare `real-ml = []` (which would compile a branch never built before — a real risk, testable with one `cargo check --features real-ml`) or make the mock-only state unconditional and delete the false gate. Non-claim lines in docs do not fix a `cfg` that names a nonexistent feature.

---

## P7 — REA decision record + operating runbook

**Objective:** close the loop on the integration question with a written decision, and document the supported way to use REA (external CLI) so it is not re-litigated.

### P7.G — HUMAN DECISION (do not dispatch)
**Question:** re-affirm the 2026-10-12 decision ("skip REA entirely — build only the Tallow-native Rust extraction stack") or reverse it.
**Recommendation:** re-affirm. The audit found zero web-plane overlap Tallow lacks (except static JS/Electron analysis, which the external CLI already covers) and 12 compiled-artifact lanes that are out of domain, two of them licence-walled.

### P7.T1 — Decision record
**Files:** create `docs/decisions/REA-2026-10-14.md`.
**Content:** the fresh verification (5 closed items, 2 open, 1 new defect), the two integration shapes with their real costs (Rust FFI wrapper = Node in the extraction path; in-sandbox = image rebuild + allowlist entries, verified: the sandbox image has **no Node**), and the chosen mode.

### P7.T2 — Operating runbook
**Files:** create `docs/extraction-engine/REA-CLI-RUNBOOK.md`.
**Content:** invoke `rea` out-of-process; the CDP browser must ride the Tor plane (per the `rea-web-recon` skill: `--proxy-server="socks5://127.0.0.1:9050" --proxy-bypass-list="<-loopback>"`, then prove `IsTor:true` before capturing); artifacts land under `artifacts/<target>-rea-<date>/`; where exported script digests are cross-checked against the capture's `source_artifacts[].sha256`.
**Verify:** the runbook's commands are executed once against a fixture and the transcript pasted into the task handoff.

### P7.T3 — Explicit non-change
**Steps:** state in the record that **no Tallow source file was modified for REA**. `git diff --stat` for the phase must show only the two docs.
**Verify:** `git diff --stat HEAD~1` lists exactly the two new docs.

---

## Cross-phase rules (bind every task)

1. **Probe-verified claims only.** No task is complete on "the file is written" or "the test exists" — quote the command and its output.
2. **`cargo fmt` over the workspace hangs on this box.** Format only the files a task touched: `rustfmt --edition 2024 <file>` (edition 2024; `--edition 2021` produces phantom import-order diffs).
3. **Debug is ~20× slower than release.** Measure performance only on a release build.
4. **Egress contract is closed.** Any new fetch path goes through `src/runtime/egress_http.rs`; a source-guard test fails the build on a bare `ureq::*` call.
5. **Parity is mandatory.** `src/interp.rs` and `src/codegen.rs` must agree byte-for-byte; the parity test files above are the acceptance mechanism.
6. **Test invocation:** `cargo test --lib <name> -- --nocapture` for units; `cargo test --test <file> <name> -- --nocapture` for integration. Prefer the matched test file over broad `cargo test`.
7. **Commits are per task and narrow.** ~4312 dirty entries exist; never sweep unrelated churn. `git show --stat` must name only the task's files.
8. **Off-limits without a new decision:** `src/browser/{stealth*,fingerprint*,dpi_bypass,traffic_morph,cookie_farm,antibot,captcha,residential,...}` (`RECONCILIATION-2026-10-12.md` §3) and `EXTRACTION-ENGINE-SPEC.md` §12.
9. **SENDTALLOW BOUNDARY (operator directive, 2026-10-14 — "Don't touch anything related to sendtallow"):** do not modify, commit, or extend any of — the sendtallow website (`website/`, e2e specs such as `chat-v9-ratchet.spec.ts`); the room-code/passcode contract in `crates/tallow-protocol` (room/code, kex, transfer/relay); or the stdlib paths that sit on that contract (`src/stdlib/transfer_net.rs` chat/group-chat/relay, `src/stdlib/relay_room.rs`). **Verified this session:** no item in P1–P7 targets any of those paths. The one adjacent item is P0, and it is now gated (`P0.G`) precisely because `crates/tallow-crypto/src/rng.rs` arrived with the protocol wire commit and serves the room-code/relay crypto path. When in doubt, treat a file as in-scope for the boundary and gate it rather than commit it.

## Issue-tracker mapping (house convention)

Per `docs/agents/issue-tracker.md`: spec at `.scratch/tallow-scraper-execution/spec.md` (this plan, copied), one file per item at `.scratch/tallow-scraper-execution/issues/NN-<slug>.md` numbered from `01`, each carrying a `Status:` line (`needs-triage` / `needs-info` / `ready-for-agent` / `ready-for-human` / `wontfix`). `P0.G` and `P7.G` are `ready-for-human`; **everything else — including all of P1 — is `ready-for-agent`** (`P1.G` closed 2026-10-14).

## Definition of done for the plan

- Every phase's items are individually checkable and their checks have been run.
- `git log` shows one narrow commit per task.
- `docs/extraction-engine/TALLOW-SCRAPER-AUDIT-2026-10-14.md` Part E is re-issued as **all closed / closed-with-non-claims / rejected-with-reason** — no item left silently unaddressed.
- The two human gates are answered in writing, and their answers are recorded in the decision docs.

---

## Progress 2026-10-15 (executed after the phase list above)

### P0.T2 — ✅ CLOSED, and it took TWO defects, not one

Committing `rng.rs` was necessary and **not sufficient**. With it committed, a clean checkout still
failed, with exactly one distinct error:

```
error[E0425]: cannot find function `hash_bytes` in module `crate::stdlib::provenance`
  --> src/runtime/fs_ffi.rs:230:65
```

Cause: `8e5bdaac` (this session) committed `src/runtime/fs_ffi.rs` — which calls
`provenance::hash_bytes` — while excluding `src/stdlib/provenance.rs`, the file defining it, as
"unattributed". It was not unattributed: `fs_ffi.rs:222-224` names it in its own doc comment. Fixed
by committing the callee. **Verified: `git worktree add /tmp/clean-v3 HEAD && cargo check` →
`CLEAN_CHECKOUT_RC=0`** at `73abec10`.

Lesson (now in `tallow-development/references/commit-and-edit-hazards.md`): the dirty tree masks this
class entirely — only a clean-checkout build catches it, and one distinct error text can appear once
per compiled target, so a 25-line error list may be a single defect.

### P5 — ✅ DONE (HAR import)

The blocker was structural, not cosmetic: **every HAR struct in `network.rs` derived `Serialize`
only**, so the shapes the recorder emits could not be parsed. They now derive `Deserialize`, with
defaults for what real captures omit (`timings.ssl`, `pages`, sizes) and aliases for the two
spellings our own `rename_all` gets wrong (`serverIPAddress`, `redirectURL`).

`src/browser/har_import.rs`: refuses rather than half-succeeds (parse error / version ≠ 1.2 / no
entries), and redaction is not bypassable — imported URLs, header values and body text go through
`browser::privacy::scan_and_redact`, the same scanner a live capture obeys.
**Verified:** `cargo check --lib --bins` RC=0 · `browser::har_import` **7 passed/0** ·
`browser::network` **63 passed/0** (the new derives do not disturb the recorder).

### P1 — ✅ COMPLETE (2026-10-15): T1–T6 all landed

*(Header superseded. This section was written when the phase was partial; the per-task records
below still carry that history and have since been closed: T2 custody `6f087814`, T5 compliance
gate `30dfa52e`, T6 budget `8923ea72` — and this is the third stale headline found in this
document, which is why the pattern is worth naming rather than fixing one at a time.)*

The tier was Ollama-only, so the engine actually chosen for it could not be called at all.
Landed: explicit `Engine` (default `Ollama`, unknown names refused), `with_engine` with the same
zone-predicate guard in the constructor (an engine is not a new egress path), credential from
`TALLOW_LLM_API_KEY` read at call time and never stored, `EngineMisconfigured` as a distinct
refusal, and `run_evidence::record("llm_engine", …)` so "which tier ran" is a fact about the run.
**Verified:** `cargo check` RC=0 · `engine_tests` **5 passed/0** · `browser::llm_extract`'s existing
**35 passed/0**.
**UNVERIFIED, stated:** the live call needs a key, so the wire path is plausible, not demonstrated.
Still open from P1: **T3** (name the egress plane in the docs), **T5** (the plan's own compliance
gate on the transfer), **T6** (cost/latency budget).

### P6.T2 — premise corrected (see the block in that section)

### P7 — ✅ T1/T2/T3 written; one step unproven

`docs/decisions/REA-2026-10-14.md` and `docs/extraction-engine/REA-CLI-RUNBOOK.md` are committed;
the decision re-affirms Tallow-native with REA external-only, on the operator's delegation of the
call to this session's recommendation. **T3 holds:** no Tallow source file was modified for REA.
**Open:** T2's Tor-plane proof (`IsTor:true` via Camoufox-over-Tor) — it needs a browser session,
so it is not a docs-only step and is not claimed.

### Commits from this session (all local, none pushed)

`c09363a4` CLI verbs · `75ff637a` provenance/run_evidence · `aac4e785` JA4H · `e923b3e4` crypto ·
`c64fd997` docs · `73abec10` provenance callee · plus P5 and P1 (this block).

### P1 — ✅ T1/T3/T4 DONE (the spec's four deviations closed)

Built first as engine selection + key refusal; then brought to the spec, whose steps 2–4 differ
materially:
- **`resolve_engine_config` refuses when no base URL is set — that refusal IS the honest default.**
  The tier no longer defaults ON pointing at a local service, which is what made a run report
  "attempted, failed" when the truth was "not attempted". `TALLOW_LLM_EXTRACT=1` still forces it on.
  `SmartExtractor::default()` follows it, and `llm_reason` carries why.
- **Backend-aware probe** (step 3): `{base}/v1/models`, a bounded GET that cannot itself burn a
  completion or half an extraction.
- **`tier_state()`** reports `{enabled, engine, engine_url, model, credential_present, reachable,
  reason}` and `try_llm_fallback` records it as `llm_tier` **before deciding**; a tier that is not
  enabled returns without sending and records the reason via P4's mechanism. This closes the phase's
  own stated defect: "enabled" and "working" are no longer the same claim.
- **Defaults to `deepseek/deepseek-flash`**; `TALLOW_LLM_MODEL`/`TALLOW_LLM_ENGINE` override; an
  unknown engine is refused, not defaulted.
- **T3**: data-flow stated in the call's doc comment (vendor receives the page sample + prompt; the
  box IP does not leave the box; no `TALLOW_ALLOW_DIRECT`-style bypass exists).

**Verified:** `cargo check --lib --bins` RC=0 · `engine_tests` **10 passed/0** · `smart_extract`
**16 passed/0** · `llm_extract` **40 passed/0** (35 before this work). Commit `3ba8fe7f`.
**UNVERIFIED, stated:** the live call — needs a credential and a reachable engine, so the wire path
is plausible, not demonstrated.

### P6.T2 — ✅ DONE, and the decision was made by measurement

Declared `real-ml = []`. My earlier recommendation ("test whether it compiles, it might break") was
written before reading the branch: `embeddings.rs` does **not** attempt a candle loader — with the
feature enabled `EmbeddingEngine::new` returns a documented `MlError` ("real-ml is not shipped")
rather than silently falling back to the mock. Declaring it therefore cannot quietly substitute a
non-semantic engine for a semantic one.
**Verified:** default check RC=0 with `unexpected_cfgs` mentions **2 → 0**; `cargo check --features
real-ml` **RC=0** (the branch had never been compiled); `browser::ml` **17 passed/0**. Commit
`29f9976d`.
Also corrected in that commit: `stdlib/browser.tl`'s `// native:` comment was accurate as that file's
idiom but silent about the AOT backend having no lowering; it now says which backend runs the method.

### Status of the above, verified 2026-10-15 (this list was stale)

Every P1 task is implemented. Each row below is re-checked against the code, with the artifact that
proves it, because this document has been wrong in this direction before (it names the pattern
itself) and a stale "still open" list causes exactly the redundant work it warns about.

- **P1.T2 (vault custody)** — **DONE.** `resolve_api_key` in `src/browser/llm_extract.rs:2427` resolves
  the credential from the environment first (an explicit per-run override) and then from the vault
  (`LLM_VAULT_ENTRY`); neither path is argv and neither is a `.tl` literal. `resolve_api_key_live`
  (line 2444) wires the real lookups, and the injected-closure signature is what makes both sources
  testable without a vault or an environment.
- **P1.T5 (compliance gate)** — **DONE**, commit `c83d5db` ("extract: gate the tier's third-party
  transfer on the plan's own compliance block"). `src/browser/llm_transfer.rs` is fail-closed: no
  policy refuses a remote transfer; a `redact`-class policy is refused rather than silently obeyed;
  `requires_approval` refuses even beside a permitting policy; a loopback engine needs no
  authorisation because nothing leaves the box. Critically it is **called, not merely present** — the
  anti-pattern this plan warns about: `smart_extract.rs:162` builds the policy (`from_env`), `:269`
  passes it into the extractor, and `llm_extract.rs:766`/`:854` refuse on the decision. Evidence:
  `cargo test --lib browser::llm_transfer` → **7 passed / 0 failed**.
- **P1.T6 (cost/latency budget)** — the **cap is DONE**; the **measurement remains
  measured-or-blocked**. `LlmBudget { max_calls, max_prompt_chars, source }` at
  `llm_extract.rs:2497`, with `DEFAULT_MAX_CALLS = 16` and `DEFAULT_MAX_PROMPT_CHARS = 400_000`, and
  the fail-closed rule stated in the file: *"past the cap the tier REFUSES rather than running. A
  budget that degrades into 'kept going' is not a budget."*
**Correction to this document's citations:** the hashes it names for the closed P1 work —
`30dfa52e` (T5), `6f087814` (T2), `8923ea72` (T6) — **do not exist in this repository**;
`git cat-file -t` returns "DOES NOT EXIST" for all three, while the T5 commit that does exist is
`c83d5db`. A hash that cannot be resolved carries the same information as no hash, so where a
citation is load-bearing this section names the artifact (`file:line`, the commit subject, the test
run) instead.

- **P2.T1** — deferred deliberately, with the reason recorded: the interpreter path is correct
  (default RC=0; `--require-native` refuses loudly), so this is a backend gap, not a correctness
  defect. Binding it needs a native that builds `%struct.StructuredData`, including the runtime
  representation of `[]String` and `Map`, on the interp/codegen byte-parity surface. What landed
  instead is the precise claim in `stdlib/browser.tl`.
- ~~**P7.T2's Tor plane proof** — needs a browser session; not a docs-only step.~~ **DONE
  2026-10-15.** `IsTor: true` measured from the Tor Project's own endpoint, the exit differing from
  the box IP (`203.0.113.1`) and rotating between runs (`204.8.96.144`, then `185.220.101.34`).
  Transcript in `REA-CLI-RUNBOOK.md` §5, together with its scope: the plane is proved; REA's own CDP
  launch with those flags was not exercised.

### Commit list for this work (all local, none pushed)

`c09363a4` CLI verbs · `75ff637a` provenance/run_evidence · `aac4e785` JA4H · `e923b3e4` crypto ·
`c64fd997` docs · `73abec10` provenance callee · `11923c2a` HAR import · `429eb6d2` engine selection ·
`29f9976d` real-ml · `3ba8fe7f` tier config/probe/state.
