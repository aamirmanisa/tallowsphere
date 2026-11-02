# Release gate — static steps re-run at `73688a5`

Re-run of the release gate's static steps on the tree that carries the
`rel/w14-lexicon` landing (`f972560`, chained native-array `.len` reads the
count; CI wiring `73688a5`). Every row below is an observed exit code and the
summary line the step itself printed, not an inference from a green workflow.

Tree state at measurement: branch `rel/w15-ledger`, working tree clean,
`HEAD = 73688a5` (`main`). Host: `aarch64` Linux, local checkout — not a CI
runner. Steps are run from the repository root unless the row says otherwise.

## 1. Static steps (`release.yml` → "Static gates")

| step | command | exit | measured summary |
|---|---|---|---|
| panic policy | `python3 scripts/panic_policy_check.py` | 0 | PASS — `[profile.release] panic = abort`, `[profile.max]` inherits; 9 call sites (`src/interp.rs` 4, `src/main.rs` 2, `src/mesh/worker.rs` 1, `src/supply_chain.rs` 2) |
| claims ledger | `python3 scripts/claims_ledger_check.py` | 0 | PASS — 75 entries (shipped=2, partial=51, target-only=22), buckets A=8 B=8 C=2 D=15 S=42; HARD findings: none; WARN: none |
| capability registry | `python3 scripts/check_capability_registry.py` | 0 | 3 `Page` entries checked, 0 mismatches |
| FFI symbols | `python3 scripts/check_ffi_symbols.py` | 0 | 330 runtime FFI fns, 291 emitted symbols, 0 problems |
| test coverage | `python3 scripts/check_test_coverage.py` | 0 | 190 targets: 184 in CI, 6 registered as debt (host 3, perf 3), 0 unaccounted |
| deny expiry | `python3 scripts/check_deny_expiry.py` | 0 | 32 ignored advisories across 2 files, all inside their review deadline as of 2026-11-02 |

The covered-target count is the interesting one for this landing: the new
`tests/chained_native_array_len.rs` is accounted for as a CI target
(`.github/workflows/ci.yml:316` passes `--test chained_native_array_len` to the
conformance leg), so the lexicon commit did not add an unaccounted suite.

## 2. Drift gates (`release.yml` → "SBOM drift" / "CBOM drift")

| step | command | exit | measured summary |
|---|---|---|---|
| SBOM drift | `python3 scripts/sbom-gen.py --check scripts/sbom.snapshot.json` | 0 | regenerated artifact matches `scripts/sbom.snapshot.json` |
| CBOM drift | `python3 scripts/crypto-inventory.py --check scripts/crypto-inventory.json` | 0 | regenerated artifact matches `scripts/crypto-inventory.json` |

Both are byte comparisons against a regenerated artifact, so a green here means
the committed files are what this tree produces — not that the tree is
dependency-clean. See §4.

## 3. Canonical pins (`ci.yml` → "Canonical pin gate")

| step | command | exit | measured summary |
|---|---|---|---|
| verify pins | `cd crates && sha256sum -c CANONICAL-SYNC.sha256` | 0 | 204 pinned files: OK, 0 failures, 0 stale names, no duplicate paths |
| regenerable | `scripts/gen-canonical-pins.sh` then diff | 0 | regenerated manifest byte-identical to the committed one (`pinned files: 204`) |
| no filesystem paths | `grep -nE '^(/\|~\|[A-Za-z]:[\\/])'` | 0 | manifest carries no absolute or home-relative path |

**Rows that moved: none.** The manifest was regenerated and diffed; the diff is
empty. That is the correct outcome for this tree, and the reason is structural
rather than lucky: the pin set covers exactly four vendored crates —
`tallow-crypto`, `tallow-net`, `tallow-protocol`, `tallow-svid` — and `f972560`
touched `src/codegen.rs`, `tests/chained_native_array_len.rs`,
`tests/fixtures/chained_native_array_len.tl`, and (at `73688a5`)
`.github/workflows/ci.yml`. None of those live under the pinned crates, so no
pinned file's digest could change. No `Cargo.toml`/`Cargo.lock` version change
occurred in this landing either, which is why the SBOM snapshot is also still
current (the trap that usually bites a version bump is not in play here).

## 4. What this record does not establish

- **It does not establish that the release is shippable.** These are the static
  and drift steps only. The gate's dynamic half — dependency advisories, the
  lib suite, the conformance corpus on both planes, the five-platform matrix —
  did not run here, and a tag cut on the strength of this page alone would be
  cut on half a verdict.
- **The advisory step is unverified, and the lock suggests it is still red.**
  `release.yml`'s blocking `cargo deny --all-features check advisories` step
  documents itself as failing until zstd is off `0.13.3`. `Cargo.lock` at this
  commit still pins **`zstd 0.13.4`** alongside `0.14.3` (and `zstd-safe 7.4.0`),
  which is below the `>=0.14.3` floor RUSTSEC-2026-0391 names. I did not run
  `cargo deny` (it resolves the advisory DB at run time), so this is reported as
  **unverified** rather than as a red: the lock fact is measured, the verdict is
  not. What settles it: `cargo deny --all-features check advisories` on this
  commit.
- **The pin verify is CI-only.** `ci.yml` runs all three canonical-pin steps;
  `release.yml` runs none of them. A pinned-crate edit therefore drifts the
  manifest and is caught on the commit, but not by the gate that runs after the
  tag. Not a defect in this landing (§3 moved nothing), but it is a coverage
  hole between the two workflows, of the kind the release gate has closed twice
  before for SBOM and CBOM drift.
