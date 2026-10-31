# Format-migration policy

Format drift across the artifact corpus is handled by `src/format_policy.rs`
(frozen interface §6, B6.2.1–B6.2.3). The module is the **pure decision layer**:
no I/O, no clock, no state. Operators and pipelines call it; nothing here
touches disks.

## 1 · Monitoring (B6.2.1)

For each artifact create a `FormatRecord` — its `current` format (`format`
name + `version`) and, if it has migrated before, `migrated_from` for
provenance. Monitor it against the chosen target:

- `monitor(rec, target)` → `Current` when `current` equals the target
  (name **and** version), else `Migrate { target }`.
- Drift is **direction-blind**: a version bump and a rollback both read
  `Migrate`. The operator owns the target.
- A `FormatRef` with an **empty format name** is refused on either side
  (`BadInput("format")`) — an unnamed format can never be a target.
- `migrated_from` never affects the verdict.

## 2 · Migration planning (B6.2.2)

Run the whole corpus through `plan(recs, target)`:

- Output is one `MigrationPlan { artifact, from, to }` per **drifting** record;
  already-current records are omitted.
- Plans are **sorted by artifact** (stable for duplicates) — the plan is
  reproducible byte-for-byte from the same inputs.
- Refusal is **atomic**: one invalid record refuses the entire request; no
  partial plan is emitted. An empty corpus (or an all-current corpus) yields
  an empty plan — provably nothing to do.

## 3 · Applying a plan (B6.2.3)

`apply(plan)` is total (a `MigrationPlan` is already validated by `plan`) and
returns a `MigrationResult`:

- `migrated.current` ← `plan.to`; `migrated.migrated_from` ← the plan source;
  the artifact name is carried over unchanged. The record therefore carries
  its own provenance chain.
- `apply` is a pure function: applying the same plan twice returns equal
  results and never mutates the plan.

## 4 · The originals-kept invariant

**Migration produces a copy; the original is never destroyed.**

- `MigrationResult::original_retained` is **always `true`** — a constant of
  the policy, not an input-dependent flag (pinned by the `apply_*` tests).
- Rationale: the source-format artifact is the fixity/audit anchor. A
  migration that discards the original breaks provenance (`artifact_index`
  lineage, fixity re-checks) and cannot be undone if the target format turns
  out to be lossy.
- Consequence for tooling: after applying a plan, both formats coexist for
  the artifact until a separate, explicit retention/erasure decision is made
  (never made by this module). Do not add a branch that can set
  `original_retained` to `false`.

## 5 · Operating notes

- Cadence: re-run `monitor` on every ingest or format-registry change; `plan`
  output is the worklist.
- Wire format: variant names are verbatim (`"Current"`, `"Migrate"`,
  `"BadInput"`); `FormatError` serializes as e.g. `{"BadInput":"format"}` and
  deserializes only from `'static` input (literals).
- Verification: `cargo test --lib format_policy`.
