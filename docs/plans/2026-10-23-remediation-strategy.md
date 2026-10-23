# Remediation and implementation strategy — v2

Derived from `docs/research/multi-domain-report-2026-10-23.md` (§11 limits, consolidated
risks) and `docs/plans/2026-10-23-unified-integration-fix-plan.md` (R1–R15).
Baseline: engine `9cd968d` (v1.4.0), spec `9a7fd3d`. This document is the execution-grade
version: root causes, work breakdown, infrastructure deltas, migration, milestones with
dependencies, verification protocols, rollback, sign-off.

Roles named are Hermes profiles in the operator's fleet, not headcount: **forge**
(implementation), **sentinel** (security review, bypass tests), **architect** (design
review), **scrivener** (spec/docs), **alden** (orchestration, release cut). One profile may
hold two roles; every gate has exactly one accountable profile.

---

## 1. Root-cause analysis

Five root causes explain every finding in the report. Fixing symptoms without these
produces recurrence.

| # | Root cause | Findings it explains | Structural fix |
| --- | --- | --- | --- |
| RC-1 | **Gates exist only where a human remembered to run them.** Conformance runs in the release workflow only; the spec repo has no CI; 42 suites are excluded by list; `cargo deny` warns on a stale ignore nobody removed. | Spec drift, unexercised suites, stale advisory ignore | Phase 1: every invariant becomes a CI job that fails the push, not a checklist item |
| RC-2 | **The native backend is a second implementation with no parity contract.** 25 `page_*` helpers, `Mesh.plan/replay`, `llm.*` fall back to the interpreter. | Behaviour depends on build flag; "native build unavailable" messages | Phase 5: parity tests generated from one corpus, run per function; coverage published as a number |
| RC-3 | **Declared surface ran ahead of implemented surface.** `mesh` and `Mesh` were dispatched but unreachable; `Mesh.run` was deliberately withheld; topology is an in-process model. | Topology simulation, missing executor, prior `undefined variable: Mesh` | Rule: a declaration is added in the same commit as its executable arm and its gate test; surface count is a *gate*, not a metric |
| RC-4 | **Design documents were treated as deliverables.** Scope manifest, ombuds, jurisdiction check, egress ledger were specified in architecture §6 and implemented nowhere; four of five desks exist as prose. | Directorate incompleteness, unenforced controls | Phase 4: every control ships with a bypass test that fails when the control is removed; a design section without a test is marked `[design]` |
| RC-5 | **Credentials and privacy live outside the type system at the boundary.** The language refuses inline keys, but key files, environment, CI secrets and shell history are untyped. | Risk 4; no rotation path; no multi-user story | Phase 3: key-file mode enforced at load, rotation documented and drilled, scan for secrets on every egress path including model context |

---

## 2. Work breakdown

Twenty items, each ≤ 2 days, each with one owner and one closing command. IDs are stable;
the earlier R-numbers are shown in brackets.

### WS-A — Integrity gates (owner: sentinel; reviewer: architect)

**A1 [R1] Spec freshness CI.** Workflow in `Tallow-Language`: checkout spec and engine at
the SHA recorded in `generated.json`; run `tools/generate.py --engine <path>`; fail on any
`git diff --stat`. Second job runs `conformance/run.py` against a binary built from that
SHA.
*Close:* intentionally stale `generated.json` → red; fresh → green with the SHA pair in the
job summary.

**A2 [R2] Conformance in main CI.** `ci.yml` job `conformance`: build `--release`, run 21
cases. Keep the release-workflow copy.
*Close:* job present and green; removing it makes the required-check list fail.

**A3 [R3] Suite triage.** Bucket the 42 entries: needs-service → container job;
needs-browser → headless job; obsolete → delete target + entry. Timebox 10 entries.
*Close:* count in `ci-excluded-suites.txt` drops by ≥10; a script asserts the file has no
entry without a bucket comment.

**A4 [R4] Dependency hygiene.** Remove the stale `deny.toml` ignore; add `cargo deny check`
to the required checks with `--deny warnings`.
*Close:* zero warnings; a planted stale ignore fails CI.

### WS-B — Execution plane (owner: forge; reviewer: alden)

**B1 [R6] `Mesh.run`.** `src/mesh/exec.rs`: worker pulls `TaskFn` by name from the
interpreter's function table, one interpreter instance per worker thread, checkpoint after
each wave barrier. `Mesh.run(plan, workers)` lowers through the existing coordinator.
*Close:* `tests/mesh_run_tl.rs` — a Tallow program of 8 function tasks yields identical
checkpoint hashes at 1 and 8 workers; a task returning `Err` produces `TaskFailed`, not a
panic; unknown function name refuses at plan time with the name.

**B2 [R5] Real topology.** Membership from `src/mesh/wire.rs` heartbeats: `join`,
`heartbeat` (epoch + monotonic counter), signed like every other frame; peer table expires
entries after `3 × heartbeat_interval`; `simulated` computed per node as
`!(handshake ∧ committed_task)`. Delete the in-process node map; move the DHT behind a
`research` feature flag or remove it.
*Close:* two-process test — A joins, SIGSTOP → disappears within the budget; SIGCONT →
returns; `simulated` false only for nodes with a commit; wire replay guard rejects a
replayed heartbeat nonce.

**B3 [R7] Speculation decision.** One paragraph in
`docs/architecture/tallow-mesh-execution-plane-2026-10-23.md`: speculation stays
in-process; the wire uses lease expiry and reassignment.
*Close:* doc line exists; no code delta; reviewer signs.

### WS-C — Cognition and controls (owner: forge; reviewer: sentinel)

**C1 [R9] Journalled `llm` tasks.** `TaskClass::Llm` wraps `llm.complete`; journal record
gains `prompt_hash`, `response_hash`, `data_class`. Public class stores response text;
private class stores hashes only and stamps `replayable: false`. `Mesh.replay` refuses a
journal containing a private completion, naming the task.
*Close:* public-class run replays with the model stub returning a poisoned answer (replay
must not call it); private-class replay errors with `non-replayable: private data class`.

**C2 [R12] CARTOGRAPHER brief on the model.** Fixed prompt template in
`examples/directorate/`, response recorded per C1, verdict still rule-derived (the model
drafts, the rules grade).
*Close:* one directorate run journals an `llm` task with both hashes; re-running with the
model offline reproduces the same checkpoints.

**C3 [R13a] Signed scope manifest.** `manifest.json` with tools, data classes, targets,
third parties, budget, expiry; Ed25519-signed by the operator key; checked at task
creation; revoking it invalidates derived tokens and queued tasks.
*Close:* a run without a manifest refuses at plan time; a revoked manifest cancels queued
tasks within one wave.

**C4 [R13b] Egress ledger.** Per-target budget and stop-on-403/429 inside the `http`
plane; entries appended to the run journal.
*Close:* a fixture returning 429 stops the target after the budget; a fourth request is
refused locally with zero sockets opened.

**C5 [R13c] Jurisdiction check.** Table of prohibited uses and recipient classes checked
before a collection task is planned.
*Close:* a task naming a prohibited function fails at plan time with the rule id.

**C6 [R13d] Ombuds channel.** Append-only log with its own credentials, outside the
analytic chain; reports are signed and immutable.
*Close:* tamper attempt is rejected; an ombuds entry cannot be edited by the directorate
identity.

### WS-D — Parity and providers (owner: forge; reviewer: architect)

**D1 [R10] Native arms.** Codegen for `llm.*` and `Mesh.plan/replay` (six functions), plus
the 25 `page_*` helpers in three groups. Struct-return kinds already exist.
*Close:* `--require-native` passes for a program using all 31; a parity generator compares
interpreter and native output on a 40-case corpus, byte-for-byte.

**D2 [R8] Live provider matrix.** `scripts/llm_verify_matrix.py`; refuses world-readable
key files; output table committed without secrets.
*Close:* one live provider row; `grep -E 'sk-|key'` on the artifact returns nothing but
column headers.

### WS-E — Release engineering (owner: alden; reviewer: sentinel)

**E1 [R14] Auto-publish.** After upload: `sha256sum -c` one asset, assert body ≥ 500 chars
and contains `## Added` and `## Fixed`, then `draft: false`. Manual path behind an input.
*Close:* next release publishes itself; a deliberately empty body fails the job.

**E2 [R15] `## Verified` section.** Generated from the run's own counts (lib, conformance,
targeted suites) with the commit SHA.
*Close:* body contains the counts that the run actually printed.

---

## 3. Infrastructure and configuration deltas

| Item | Change | Where | Reversible |
| --- | --- | --- | --- |
| Spec CI | new `spec-freshness.yml` + conformance job | `Tallow-Language/.github/workflows/` | delete file |
| Engine CI | `conformance` job; `cargo deny --deny warnings`; required checks updated | `tallowsphere/.github/workflows/ci.yml` | revert commit |
| Test fixtures | container job (WordPress, MySQL) + headless Chromium job | `ci.yml`, `scripts/wordpress_fixture.sh` | revert commit |
| Key permissions | `llm.toml` and key files must be `0600`; loader refuses otherwise | `src/stdlib/llm.rs` | code revert |
| Journal schema | `v2` record with `data_class`, `replayable`, `prompt_hash`; reader accepts v1 and treats it as `replayable: true` for non-llm tasks, refuses llm v1 records | `src/mesh/journal.rs` | keep v1 reader |
| Wire frames | new `heartbeat` kind; version string bumped to `tallow-mesh/2`; v1 peers refused by name | `src/mesh/wire.rs` | pin v1 in config |
| Release workflow | post-upload verification step; `draft: false` | `.github/workflows/release.yml` | input `publish: false` |
| Branch protection | required checks: lib, conformance, spec-freshness, deny | GitHub settings | toggle |

No host-level change is required. No new service, no proxy, no egress-plane change — the
`llm` Tor bypass stays as documented, and no fleet-wide environment variable changes.

---

## 4. Data migration and cleanup

**M1 — Spec regeneration.** Regenerate `generated.json` and the six derived docs at the
first release after Phase 1; tag `spec-v1.5.0`. Old tags stay; no history rewrite.
*Verification:* `git diff` between regenerate-at-tag-twice is empty (idempotence).

**M2 — Journal compatibility.** M4 journals (no `data_class`) remain readable: non-llm
records replay, llm records refuse with `legacy journal: llm task without data class`.
Migration is read-compatible, not a rewrite — no journal file is edited, because editing a
journal destroys the property it exists to provide.

**M3 — Checkpoint compatibility.** Checkpoint hashing is unchanged, so pre-existing
checkpoints remain valid comparisons. `Mesh.replay` gains a version field check; a
`checkpoint_v1` journal replays under v1 rules.

**M4 — Release cleanup.** Draft releases with empty bodies: none remain (v1.2.1 fixed).
Add a scheduled job that lists drafts older than 24 h and fails loudly rather than leaving
them.

**M5 — Excluded-suite registry.** `ci-excluded-suites.txt` becomes a structured file:
`target | bucket | owner | reason | expiry`. Entries without an expiry fail CI after the
expiry date.

**M6 — Secret sweep.** Before multi-user use: scan the workspace and both repos for key
material (`sk-`, `AKIA`, PEM blocks, `hex64` near `key`), rotate anything found, and record
the sweep in `docs/operations/`.

---

## 5. Milestones, dependencies, timeline

| Milestone | Contents | Depends on | Duration | Owner | Exit evidence |
| --- | --- | --- | --- | --- | --- |
| **M0 Baseline** | File WBS-01..20; tag plan; record baseline numbers | — | 0.5 d | alden | issue list + baseline table reproduced by one script |
| **M1 Integrity** | A1–A4, E1, E2 | M0 | 3 d | sentinel | five green required checks; stale-spec test red-on-demand; next release self-published |
| **M2 Execution** | B1, B2, B3 | M1 | 7 d | forge | `mesh_run_tl` + topology partition test green; wire v2 documented |
| **M3 Cognition** | C1, C2 | M2 | 3 d | forge | replayed llm task; private-class refusal |
| **M4 Controls** | C3–C6 | M3 | 5 d | sentinel | four bypass tests |
| **M5 Parity** | D1, D2 | M4 | 6 d | forge | `--require-native` 31/31; parity corpus 40/40; live matrix |
| **M6 Release** | M1–M5 data items, tag v1.5.0, publish | M5 | 3 d | alden | 5 platforms verified, sha256 OK, body Added/Fixed/Verified |

**Total 27.5 engineering days.** Critical path: M1 → M2 → M3 → M6. M4 and M5 can run in
parallel with each other after M3; D2 can start any time the operator supplies a key.

**Dependency graph (hard edges):**
A1 → A2 → E1 (a release must not publish a spec it cannot verify).
B1 → B2 → C1 (topology needs a committed task; cognition needs the executor).
C1 → C2 and C1 → C3 (manifest checks the same journal the llm task writes).
D1 → M6 (parity is a release gate only if claimed in the body).
C5 → C6 (the ombuds receives jurisdiction refusals).

---

## 6. Verification and testing protocols

**Per-item gate.** Every WBS item closes only on a command whose output is quoted in the
commit message or the PR body. "Tests pass" without a command is not evidence.

**Regression policy — three layers, each run before every merge to main:**
1. Targeted: the item's own test file.
2. Plane: `cargo test --locked --lib` (currently 9,212 tests, ~160 s) + conformance.
3. Claim: any number written into a doc or release body is re-derived in the same run;
   a doc claim without a live command is removed.

**Negative tests are mandatory** for gates: a gate that has never been seen failing is not
known to work. Each CI gate ships with a documented way to make it fail (stale spec,
planted ignore, empty body) and that demonstration is recorded once in the PR.

**Provenance rule.** After any edit made during a verification run, the previous green
result testifies about a different tree: re-run, and cite the commit SHA alongside the
count.

**New-suite accounting.** A test file added to `tests/` must be named in `ci.yml` or in
`ci-excluded-suites.txt` with a bucket — otherwise the coverage script fails. This is the
rule that would have caught the `mesh_plan_tl`/`mesh_workers` gap.

**Parity protocol (D1).** One corpus, two engines: generate 40 programs (10 per feature
group), run interpreter and `--require-native`, diff stdout byte-for-byte. Any diff is a
blocker; a new divergence requires an explicit `known_divergence` entry with an expiry.

---

## 7. Rollback procedures

| Change class | Trigger | Rollback | Time to restore |
| --- | --- | --- | --- |
| CI gate too strict (false red) | main blocked > 2 h by a gate defect | revert the workflow commit; gates are independent files | < 5 min |
| Wire v2 incompatible | a v1 peer cannot join | set `mesh.wire_version = 1` in config; v1 code path retained | < 1 min, no rebuild |
| Topology regression | peer table flaps or commit counts differ | disable `topology_wire` feature flag → falls back to the old in-process map, and `simulated` reverts to `true` | restart only |
| `Mesh.run` defect | checkpoint divergence at N workers | unpublish the function behind the surface gate (declaration removed in the same commit as the arm) | one release |
| Journal v2 defect | replay refuses a valid v1 journal | ship reader fix; journals are never rewritten | one patch release |
| Codegen parity regression | native/interpreter diff | `TALLOW_FORCE_INTERPRETER=1` for the affected binary; revert the codegen commit | immediate |
| Release published wrongly | bad asset or body | `gh release edit --draft` + delete assets; the tag stays, a new patch tag supersedes | < 15 min |

**Rules.** No rollback rewrites history: tags are immutable, a bad release is superseded,
never deleted. A rollback is recorded in `CHANGELOG.md` under `Fixed` with the mechanism,
not the blame.

**High-impact changes needing written operator sign-off before merge:** wire version bump,
journal schema change, key-permission enforcement (breaks existing configs), required-check
list changes, and anything changing the published function count.

---

## 8. Risk register

| ID | Risk | P | Impact | Mitigation | Owner |
| --- | --- | --- | --- | --- | --- |
| K1 | Topology rewrite destabilises execution plane | M | H | feature flag + fallback map; execution tests unchanged and run before merge | forge |
| K2 | `Mesh.run` exposes interpreter thread-safety assumptions | M | H | one interpreter per thread, no shared `Env`; concurrency test at 8 workers with 200 tasks | forge |
| K3 | Spec CI requires engine checkout and slows the spec repo | L | M | shallow clone at the pinned SHA; cache the toolchain | sentinel |
| K4 | Live provider matrix needs keys and may leak them | M | H | operator-run, refuses non-0600, output scanned for key patterns before commit | sentinel |
| K5 | Parity work reveals deeper backend defects and expands | H | M | timebox per group; `known_divergence` with expiry; publish the number instead of hiding it | architect |
| K6 | 42 excluded suites hide a real defect | M | H | triage by bucket, not by convenience; the 10 timeboxed first are the highest-traffic paths | sentinel |
| K7 | Journal schema change breaks existing runs | L | H | read-compatible reader; v1 llm records refuse by design, with a named error | forge |
| K8 | Controls (manifest/ombuds) are built but bypassable | M | H | bypass tests are the acceptance criterion; no control ships without one | sentinel |

---

## 9. Deliverables per stage and sign-off

| Stage | Deliverables | Sign-off criterion | Signs |
| --- | --- | --- | --- |
| M0 | baseline table, issue list, plan tag | numbers reproduce from one command | alden |
| M1 | 5 CI jobs, `ci-excluded-suites.txt` v2, auto-publish step | every gate demonstrably red when broken; next release self-published | sentinel + architect |
| M2 | `mesh_run_tl.rs`, topology test, wire v2 spec section, decision paragraph | identical checkpoints 1 vs 8; partition test green; doc updated | architect |
| M3 | llm task class, replay refusal, CARTOGRAPHER brief | public replay offline; private refusal named | sentinel |
| M4 | manifest, ledger, jurisdiction table, ombuds + 4 bypass tests | each control fails its own bypass test when removed | sentinel + alden |
| M5 | codegen arms, parity corpus, provider matrix | 31/31 native, 40/40 parity, ≥1 live provider | architect |
| M6 | v1.5.0 tag, 5 builds, release body | assets verified, body Added/Fixed/Verified, URLs 200 unauthenticated | alden |

**Definition of done for any item:** command run, output recorded, negative case shown,
docs updated in the same commit, and no unrelated file churn in the diff.

---

## 10. Success metrics

| Metric | Baseline (2026-10-23) | Target at M6 | How measured |
| --- | --- | --- | --- |
| Lib suite | 9,212 / 0 / 33 | ≥ 9,400 / 0 / 33 | `cargo test --locked --lib` |
| Conformance cases | 21, run only at release | 21, run on every push | CI job |
| Spec drift | undetectable | detected in ≤ 1 push | freshness job |
| Excluded suites | 42 | ≤ 15, each with owner + expiry | registry file |
| Native coverage of declared surface | 6 of 31 new functions | 31 of 31 | `--require-native` sweep |
| Mesh: functions executable | built-in executors only | Tallow functions at 1–8 workers | `mesh_run_tl` |
| Topology nodes with `simulated: false` | 0 | every node with a commit | topology test |
| `llm` tasks replayable | none (not journalled) | public yes, private refused | replay test |
| Controls with bypass tests | 0 of 4 | 4 of 4 | test names in CI |
| Release publish | manual, draft risk | automatic after verification | workflow run |
| Time from tag to verified assets | ~25 min manual | ≤ 10 min automatic | run duration |

---

## 11. Immediate next three actions

1. **A1** — write `spec-freshness.yml`, run it once against a deliberately stale
   `generated.json`, record the red output. Cheapest gate, largest credibility gain.
2. **B1** — `Mesh.run` with the function executor; without it every directorate claim stays
   a plan.
3. **C1** — journalled `llm` tasks with the public/private split; it is the difference
   between "we call a model" and "we can prove what the model was asked and answered".

Everything else can slip a week without changing what the system is. These three change
what it is.
