# Cold-Start Study — Outline (Linux lane)

> **Status: [target-only] outline.** Nothing in this document has been executed. It specifies
> the study that a later wave (cycle-02/10 §3.4, C11/E9) will run: scripts, arms, run counts,
> instrumentation, and acceptance. No numbers here are claims — do not cite any value from this
> file as measured.

**Question.** Clean-environment wall-clock from "install initiated" to "first validated record
emitted" — Tallow (single binary + one stack) vs a Playwright + scrapy + proxy + compliance-class
baseline. Reported as median + p95 over **≥5 fresh runs per arm**, with step counts documented and
re-derived from logs.

**Context inputs.** `research/tallow-v1/cycle-02/10-browser-and-measurement-readiness.md` §3.4
(design), `research/tallow-v1/cycle-01/09-toolchain-and-release.md` §5.2 (RG-2 named target),
`CHARTER.md` anti-hype rules (≥10–100×-class metrics are the defensible bucket for cold-start /
ops burden — this study measures *time-to-first-validated-record*, not throughput).

---

## 1. Arms

| Arm | Definition | Notes |
| --- | --- | --- |
| **A1 — Tallow, binary provisioning** | Fresh env → place pre-built artifact (`target/release/tallow`, sha256 pinned) → `tallow version` → scaffold scan (`tallow new scan`) → edit to one fixture target + one validation rule → run → first validated record | Primary Tallow arm. No compile step. |
| **A2 — Tallow, source build** | As A1 but binary obtained via `cargo build --release` from pinned commit (under `scripts/ram_guard.sh`) | **Reported separately**, never merged into A1 medians (build time dwarfs provisioning). |
| **B — Baseline stack** | Fresh env → python + scrapy + playwright + chromium + proxy + compliance wrapper at parity scope → first validated record against the same fixture target | Parity scope must be fixed in the spec pass; any scope reduction is recorded as a footnote, not silently. |
| **X — Official installer (`install.sh`)** | **Excluded today**: fails closed on the placeholder release key (`install.sh:26,75`) | Re-enter only after the key is pinned (cycle-01 09 rec #2). Until then every claim says "binary-provisioning arm". |

Success definition (primary): **≥1 validated record emitted against the local fixture target**.
A live static target variant is a *separate, labeled sub-run* requiring D4-adjacent operator
approval — it never counts toward the primary medians.

## 2. Environment protocol (per run)

- Fresh, empty work directory per run (state machine asserts emptiness before step 1).
- Same host for all runs of a session; host SKU + kernel + `df` headroom recorded in `env-lock.json`.
- Page-cache state: documented per run; A1/A2/B all start from the same documented cache
  precondition (no `drop_caches` unless the run set is explicitly labeled cold-cache; if used,
  root-only and recorded).
- Network: study must run **offline** in local-fixture mode: fixture target served from
  `examples/fixtures/mock_server.py 127.0.0.1:<port>`; Arm B dependency install uses a
  pre-staged wheel cache. Any step that needs real network is a gated follow-up, not part of
  the default run set.
- No `-q` on `tallow run` steps (engine markers must stay visible); the cold-start step log
  records the engine marker scan result for every Tallow run step.

## 3. Scripts (planned — to be created in the execution wave, not now)

| Script | Responsibility |
| --- | --- |
| `scripts/coldstart/run_arm.py` | Executes one arm as a numbered state machine; monotonic per-step timestamps → `timings.csv` (`step_id, step_name, start_ms, duration_ms, rc, note`); asserts expected step count; **a failed step is recorded, not retried** (failure is data). |
| `scripts/coldstart/run_all.sh` | Orchestrates ≥5 runs/arm into `artifacts/benchmarks/{yyyy-mm}/coldstart/{arm}/run-{N}/`; refuses a dirty/fresh-env violation; single-writer discipline. |
| `scripts/coldstart/envlock.py` | Emits `env-lock.json` per run: commit sha, artifact sha256, host SKU, kernel, tool versions (python/node/chromium), `df`. |

Each run directory: `timings.csv`, `console.log`, `env-lock.json`. Failure runs stay in place and
are counted (a failed run is data, not a do-over — cycle-01 10 §172 precedent).

## 4. Run plan & reporting

- **≥5 measured runs per arm**, plus 1 documented practice run (excluded, labeled).
- Total wall-clock = install-start → first-validated-record (monotonic clock; subprocess at the
  driver adds ~1–3 ms, noted).
- Report median + p95 per arm; median step count; failure notes; step counts re-derived from logs
  by hand once per arm (assert script's count matches).
- Results doc (planned name): `docs/benchmarks/cold-start-results-<date>.md`, with env-lock header
  and per-run raw timing files hash-pinned.
- Reproduction: a second-session re-run of ≥2 runs/arm must reproduce arm medians within the
  noise envelope stated in the results doc.

## 5. Risks / open items

1. **Installer path blocked** (placeholder key) → all Tallow numbers are provisioning/build arms
   until D6/T3 resolves; this must appear in every published result.
2. **Arm B parity scope** — the baseline stack's "compliance wrapper" has no single canonical
   definition; the spec pass must freeze it or the comparison is not defensible.
3. **Offline Arm B** depends on a pre-staged wheel cache existing on the box; verify before
   scheduling.
4. **Cold vs warm caches** — "cold-start" names the *environment*, not necessarily cold page
   cache; the chosen precondition must be stated in the results doc, once.
5. **Live-target sub-run** needs D4-adjacent approval; without it the study still closes on the
   fixture-target definition (explicitly labeled).
