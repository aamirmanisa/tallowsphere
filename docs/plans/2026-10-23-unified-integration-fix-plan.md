# Unified integration and fix plan

Date: 2026-10-23. Baseline: engine `9cd968d` (v1.4.0), spec `9a7fd3d`.
Status: plan only. No code changed by the audit that produced it.

---

## 0. Baseline — what exists, measured

| Area | State | Evidence |
| --- | --- | --- |
| Engine | 548 Rust files, 541,627 lines in `src/`, 13 crates, 799 locked packages | `find`/`wc` at `9cd968d` |
| Tests | 9,212 passed / 0 failed / 33 ignored | `cargo test --locked --lib` |
| Integration | language_surface 5, llm_providers 7, mesh_plan_tl 3, mesh_workers 5, mesh_remote 3 | targeted runs |
| Stdlib | 87 modules, 1,130 declarations, `tallow check` 87/87 clean | check sweep |
| Invariants | 0 `todo!()`/`unimplemented!()`, 0 empty declarations, 0 unmentioned declarations | `census_surface.py` |
| Supply chain | advisories/bans/licenses/sources ok | `cargo deny` |
| Spec | 7 docs + `generated.json`, 18 conformance programs, **no CI** | `ls .github` (empty) |
| Cross-repo | conformance 0 failures against released v1.4.0 | `conformance/run.py` |
| Gaps | topology simulated; `Mesh.run` absent; 25 interpreter-only helpers; spec drift unchecked; 38 excluded suites | audit, below |

**Two repositories, one interface.** The engine owns all executable code. The spec repo
owns prose + `generated.json`, both derived from the engine's `stdlib/*.tl` by
`tools/generate.py`. There is no runtime coupling; the contract is (a) the declaration
manifest, (b) the conformance corpus, (c) the provenance SHA.

---

## 1. Target architecture

```
        ┌──────────────────────── Tallow-Language ────────────────────────┐
        │ spec/ (7 docs) · generated.json · conformance/ (18 programs) · CI   │
        └───────────────▲─────────────────────────────────┬───────────────┘
        regenerate (SHA)│                                 │ conformance run
        ┌───────────────┴─────────────────────────────────▼───────────────┐
        │                        tallowsphere (engine)                    │
        │  lex → parse → typecheck → policy → codegen | interp → runtime   │
        │  stdlib/ (87 modules) ⇄ src/stdlib/*.rs (dispatch)               │
        │  mesh: planning/journal (real) · wire (real) · topology (TO BUILD)│
        │  llm: providers/models/complete/verify (real)                    │
        └───────────────▲─────────────────────────────────────────────────┘
                        │ tasks, checkpoints, journals
        ┌───────────────┴─────────────────────────────────────────────────┐
        │ Directorate: SENTINEL · ORACLE · GHOST · CARTOGRAPHER · QUARTERMASTER │
        │ each = @agent_task fns + stdlib tools + a mesh task graph        │
        └──────────────────────────────────────────────────────────────────┘
```

Dependency edges: directorate → stdlib tools → runtime; directorate → mesh (scheduling);
directorate → llm (cognition, recorded); mesh → wire → TCP; spec ← generator ← stdlib;
conformance → engine binary.

---

## 2. Remediation register

Each row is independently shippable. `Gate` is the measurement that closes it.

### Integrity and cross-repo gates

**R1 — Spec drift is silent.**
Evidence: regenerating against `9cd968d` changes 4 files (`engine_sha` only); no CI in
`Tallow-Language`.
Fix: workflow `spec-freshness.yml`: checkout spec + engine at the SHA in
`generated.json`, run `tools/generate.py --engine <engine>`, fail if `git diff` is
non-empty; second job runs `conformance/run.py` against the engine's release binary.
Tag the spec `spec-vX.Y.Z` per engine release.
Gate: a stale spec turns CI red; a green run posts the diff-free SHA pair.

**R2 — Conformance is only exercised during release.** — **DONE** (2026-10-24)
Conformance now runs in `ci.yml` ("Conformance corpus" step: `python3 conformance/run.py --tallow target/debug/tallow`), and again in the release gate with its log captured into the body's Verified section.

Original evidence:
Evidence: `conformance/run.py` appears in `release.yml:329` only.
Fix: add a `conformance` job to `ci.yml` that builds the binary and runs the corpus on
every push; keep the release copy as the last gate.
Gate: CI job present and green on main.

**R3 — 38 integration suites are excluded.**
Evidence: `ci-excluded-suites.txt` (38 entries; the file states the goal is empty).
Fix: triage into three buckets — (a) needs a service (WordPress, docker) → run in a
container job; (b) needs Chrome → run in the existing browser job with a headless
Chromium; (c) genuinely obsolete → delete the target and its entry.
Gate: registry shrinks every PR; count published in the release body.

**R4 — `cargo deny` prints a stale-ignore warning.** — **DONE** (2026-10-24)
Not stale: `RUSTSEC-2026-0167` (pqcrypto-classicmceliece) matches only in the `--all-features` graph, which is the graph CI gates on; a plain `cargo deny check` therefore reports it as not-detected. Verified both ways — `cargo deny check` → advisories ok, `cargo deny --all-features check` → the advisory fires. `deny.toml` now says so at the entry.

Original evidence:
Evidence: `deny.toml:52` ignores `RUSTSEC-2026-0167`, which matches no crate.
Fix: remove the stale ignore after confirming the crate is above the patched version.
Gate: `cargo deny check` clean with no warnings.

### Mesh

**R5 — Topology plane is simulated.** — **DONE** (2026-10-24)
Closed by `74f7029` (heartbeats, liveness, SIGSTOP/SIGCONT test) and `0de3e29`
(`MeshNode` is a real TCP peer: listener, hello handshake, gossip and DHT over
sockets; `simulated` derived from the handshake). The evidence below is the
state that motivated the work, kept for the record.
Evidence: `src/stdlib/mesh.rs:175` `("simulated", true)`; `:339` connectivity simulated.
Fix: back membership with `src/mesh/wire.rs`: signed `join`/`heartbeat` frames, a peer
table fed by completed handshakes, `simulated` computed per node from
(handshake ∧ one committed task) — the rule M4 already applies on the execution side.
Deprecate the in-process node map; keep the DHT as an explicitly `research` module or
delete it.
Gate: two-process test — node A joins, is SIGSTOPped, disappears from the table within
the heartbeat budget; SIGCONT restores it; `simulated` is false only for committed nodes.

**R6 — `Mesh.run` is unpublished, so plans cannot execute Tallow functions.** — **DONE** (2026-10-24)
`Mesh.run` is implemented and exercised: `tests/mesh_run_tl` (5/5) runs a real task graph through the published surface, and the signed-manifest gate refuses unlisted ids. `examples/directorate/directorate.tl` plans 5 waves and commits 15 tasks.

Original evidence:
Evidence: `stdlib/mesh.tl` declares only `plan`/`replay`; workers run built-in
`hash`/`sleep:<ms>` executors.
Fix: worker-side executor: one interpreter per worker thread (the M1 pattern),
`TaskFn` resolved by function name through the existing function table; task class
`llm` recorded as prompt/response hashes for replay; attempt caps unchanged.
Gate: a Tallow program whose tasks are Tallow functions produces identical checkpoint
hashes at 1 and 8 workers; a `llm` task replays with the model detached.

**R7 — Speculative duplicates are in-process only.** — **DONE** (2026-10-24)
Decided, not extended: §9 of `docs/architecture/tallow-mesh-execution-plane-2026-10-23.md`
("speculation stays in-process") states the choice and the reason — speculation
answers "slow but alive", lease reassignment answers "gone", and mixing them
makes neither provable. The wire has no `speculate` frame. No code change, as the
gate required.
Original fix: decide explicitly. Recommendation: do not extend speculation to the wire
(reassignment covers "gone"); document the decision in the architecture doc so it is
not re-litigated.
Gate: doc line + no code change.

### LLM

**R8 — Providers are verified against a protocol mock, not vendors.** — **DONE** (2026-10-24)
`scripts/llm_verify_matrix.py` reads the same `llm.toml` the engine reads, runs
`tallow llm verify <id>` per provider, and writes a dated table
(`docs/operations/llm-verify-2026-10-24.md`: provider, protocol, model count,
latency, status, detail). It refuses to run when a configured `key_file` is
group/other readable (verified: mode 0644 → exit 1 with the reason) and never
reads or prints key material. First run found a real defect in the local
provider config: `model_path` had been set to the chat path, so verification
requested `/v1/v1/chat/completions` and got a 404; corrected to `/models`, and
the provider now answers (1 model, 4 ms).
Original evidence: `tests/llm_providers.rs` runs against a local server; no keys in CI.
Fix: `scripts/llm_verify_matrix.py` — reads `~/.config/tallow/llm.toml`, calls
`tallow llm verify <p>` for each configured provider, writes a dated table (provider,
protocol, model count, latency, status) to `docs/operations/llm-verify-<date>.md`.
Never prints keys; refuses to run if a key file is world-readable.
Gate: table with ≥1 live provider and no key material in the artifact.

**R9 — `llm` calls are not journalled as mesh tasks.**
Fix: `Mesh` task class `llm` wraps `llm.complete`; journal stores prompt hash, response
hash, and the response text **only** for `public` data class; private class marks the
task non-replayable and `Mesh.replay` refuses that journal with a reason.
Gate: replay of a public-class run succeeds with the model detached; replay of a
private-class run fails with "non-replayable: private data class".

**R10 — `llm` and `Mesh.plan` have no native lowering.** — **investigated, still open** (2026-10-24)

Measured this iteration. A native lowering for `llm.complete` was written (FFI
`tallow_llm_complete`, three strings in / one string out) and it did reach the
model from compiled code — but it returned the *text* where the interpreter
returns a `Completion` struct, so the same program printed `ready` natively and
`Completion { text: "ready", model: …, prompt_hash: …, tokens_in: 17, … }`
interpreted. That is a parity break, not a fix, and it was reverted.

The blocker for both items is the same: a method whose result is a struct with
string fields needs struct-return lowering in this backend (`Transfer.chunk`
shows the shape, returning `%struct .ChunkInfo`). `Mesh.plan` additionally takes
an array of `MeshTask` structs. Until that exists, the loud interpreter fallback
is the correct behaviour: it keeps both planes agreeing, which matters more than
the string "native" on the build.

Original fix:
Evidence: shipped binary prints "native build unavailable … running in the interpreter".
Fix: codegen arms for the four `llm` functions and `Mesh.plan/replay`; struct-return
kinds already exist from the browser work.
Gate: `--require-native` passes on a program using all six functions; outputs match the
interpreter byte-for-byte.

### Directorate

**R11 — Four of five desks exist only as a design.** — **DONE** (2026-10-24)
All five desks are programs: `examples/directorate/{sentinel,oracle,ghost,cartographer,quartermaster}.tl`.
Each runs on real stdlib calls (`TLSProfile.list`, `process.exec`, `provenance.*`),
writes a graded provenance record, and has a refusal branch that fires on a real
condition (ORACLE: inventory too thin to rank; GHOST: private data on a
non-anonymous plane; CARTOGRAPHER: fewer than two subjects/axes; QUARTERMASTER:
a plan with no rollback; SENTINEL: grade below the dissemination threshold).
Each declares the task ids it contributes in `fragment()`, and
`tests/directorate_desks.rs` fails if one of those ids is not planned by
`directorate.tl`. Evidence from the audit:
Fix: one program per desk following the SENTINEL pattern — real stdlib calls, a
provenance record, one refusal branch, and a task-graph fragment consumed by
`directorate.tl`.
Gate: each desk runs end-to-end on fixtures; `directorate.tl` still plans 5 waves.

**R12 — No agent cognition is wired.** — **DONE** (2026-10-24)
`directorate.tl` runs the full graph against the local model: 5 waves [5,5,3,1,1],
15 tasks committed, 0 failed, `replayable=true`. The journal carries
`{"kind":"llm_recorded","model":"MiniCPM","prompt_hash":…,"response":…,"response_hash":…}`
for CARTOGRAPHER's brief. SENTINEL's verdict stays rule-based, as the plan required.
Original fix: D3 from the architecture doc — CARTOGRAPHER's `brief` task becomes an `llm` task
with a fixed prompt template and a recorded response; SENTINEL's verdict stays
rule-based until the llm path is proven.
Gate: one directorate run whose journal shows an `llm` task with prompt/response
hashes, replayable per R9.

**R13 — Research controls are design, not code.** — **DONE** (2026-10-24)
All four controls are code, each with a test that fails when bypassed:
egress ledger `f4593a0` (budget + stop on 403/429, fail-closed JSONL);
jurisdiction gate `e889bf1` (explicit table, checked before the budget);
scope manifest `5f697b7` (Ed25519 over canonical bytes, unlisted task refused
by name, expired authorizes nothing); ombuds channel `src/ombuds.rs` (append
+ fsync, hash chain + Ed25519 over each entry, key must be 0600, restart
resumes the chain). A `Mesh.run` refusal is written to the channel when one is
configured — tests/ombuds_mesh_tl proves it end to end and verifies the log
with the public key alone.
Evidence kept from the audit:
Fix: implement in this order — (1) scope manifest as a signed JSON object checked at
task creation, (2) egress ledger (per-target budget, stop on 403/429) inside `http`,
(3) jurisdiction table checked before a collection task is planned, (4) ombuds as an
append-only log with its own credentials.
Gate: each has a test that fails when the control is bypassed.

### Release engineering

**R14 — Drafts can sit unpublished, and bodies can drift.** — **DONE** (2026-10-24)
`release.yml` drafts, then a separate job verifies body ≥ 500 bytes, ≥ 15 assets, one archive's `sha256sum -c`, and only then flips `--draft=false`. A release that uploads ten of fifteen assets stays draft and fails.

Original evidence:
Evidence: v1.2.2 sat draft with 15 assets; v1.2.1 shipped an empty body before the gate.
Fix: workflow step after upload — verify `sha256sum -c` on one asset, assert body
length > 0, then `draft: false`. Keep the manual promotion as an option behind an input.
Gate: next release is published by CI, body non-empty, one asset checksum verified.

**R15 — Release notes tell the reader what they get.** — **DONE** (2026-10-24)
`scripts/release_body.py` requires `## Added` and `## Fixed`; the body's `## Verified` section is generated by `scripts/test_summary.py` from this run's `lib.log` and `conformance.log` and the workflow greps for the heading before publishing.

Original evidence:
Done: `scripts/release_body.py` requires `## Added` and `## Fixed`; all 9 live releases
rewritten (`9cd968d`). Remaining: add a `## Verified` section auto-filled from the test
counts, so the body carries its own evidence.

---

## 3. Phases

Each phase has an entry condition, a bounded task list, and an exit gate. Nothing in a
later phase starts while an earlier gate is red.

**Phase 0 — Freeze the baseline (0.5 day).**
Tasks: tag the plan; record R1–R15 as issues; publish the audit numbers in the README
`[measured]` labels.
Exit: issue list exists; baseline table reproduced by one command.

**Phase 1 — Cross-repo integrity (2–3 days). R1, R2, R3, R4, R14.**
Why first: every later phase changes the surface, and without the freshness and
conformance gates each change adds silent drift.
Exit: spec CI green and stale-detecting; conformance in main CI; excluded suites down
by at least 10; `cargo deny` warning-free; next release auto-published.

**Phase 2 — Mesh completeness (5–7 days). R6, R5, R7.**
Order inside the phase: `Mesh.run` (R6) before topology (R5), because topology needs a
real committed task to define "real".
Exit: R6 and R5 gates; architecture doc updated with the speculation decision.

**Phase 3 — Cognition (3–4 days). R9, R12.**
Exit: an `llm` task in a directorate journal, replayable with the model detached, and a
private-class run that refuses replay.

**Phase 4 — Directorate breadth (4–5 days). R11, R13.**
Exit: five desks running; four controls with bypass tests.

**Phase 5 — Performance and parity (4–6 days). R10, R8.**
Exit: `--require-native` parity for `llm`/`Mesh`; live verify table published.

**Phase 6 — Hardening (3–4 days). R3 tail, R15, release 1.5.0.**
Exit: excluded suites ≤ 15; release body carries Added/Fixed/Verified; assets verified.

Total: **21–28 engineering days** of focused work; the critical path is Phase 1 → 2 → 3.

---

## 4. Requirement coverage (no omission check)

| Requirement (source) | Where satisfied |
| --- | --- |
| M0 plan/seeds/journal/replay | done (`c7a8da7`), `Mesh.plan/replay` |
| M1 workers/leases/retry | done (`758167a`) |
| M2 stragglers/speculation | done (`14cdcf2`); wire decision R7 |
| M3 memory/control | done (`14cdcf2`) |
| M4 real wire | done (`2d2a0cf`), R5 completes topology |
| M5 publish surface | done (`22c7b40`) |
| Five agents, 11 research domains | design + research done; R11/R12/R13 complete it |
| Zero stubs / no simulation | 0 stubs; topology simulation R5 |
| 20 providers, custom endpoints, discovery, key security | done v1.4.0; R8 live matrix, R10 native |
| Release bodies Added/Fixed | done (`9cd968d`); R14 auto-publish, R15 verified section |
| Measured claims, no unverified assertions | baseline table; every gate is a command |
| Egress discipline | `llm` documented exception; R13 egress ledger |

---

## 5. Risks

| Risk | Mitigation |
| --- | --- |
| Topology rewrite destabilises the execution plane | R5 touches only `src/stdlib/mesh.rs` + wire heartbeats; execution tests unchanged |
| Spec CI needs engine source in the spec repo | check out engine by SHA in the workflow; no submodule |
| `llm` live matrix needs operator keys | operator-run script, results committed without secrets; skip-list when absent |
| Native lowering diverges from interpreter | parity test per function, same pattern as `4d2cad5` |
| Phase 1 grows (38 suites) | timebox to 10 suites; remainder stays debt with a published count |
