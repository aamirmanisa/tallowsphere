# Maintenance cadence for next-full work

## Recommendation

Adopt a light recurring cadence that matches the problems already documented in `docs/codex`: tracked status noise, artifact sprawl, instruction drift, and inconsistent session startup. The cadence should stay small enough that it prevents rework without turning Codex hygiene into its own project.

## Weekly cadence

Use the weekly loop to keep the workspace usable between larger cleanup passes.

- Review path-scoped `git status` in the root and the subproject you actually worked in so intentional dirty areas do not get rediscovered every session.
- Re-check the known noisy buckets called out in [noise-inventory.md](../noise-inventory.md): `/.playwright-mcp/`, `/artifacts/`, `/tmp/`, and any new root `probe_*` or `tmp_*` outputs.
- Confirm the current work still follows the narrow verification rules in [verification-commands.md](../verification-commands.md) instead of drifting into broad repo-wide runs.
- If UI work happened that week, re-read [ui-baseline.md](../ui-baseline.md), [accessibility.md](../accessibility.md), and [motion-performance.md](../motion-performance.md) before the next UI edit wave.
- Update or retire any short-lived cleanup note only if it has become false enough to mislead the next session.

## Monthly cadence

Use the monthly loop for policy and doc drift, not daily housekeeping.

- Re-run the root clutter and artifact-bucket audit implied by [cleanup-execution.md](../cleanup-execution.md) and [noise-inventory.md](../noise-inventory.md) to see whether ignored buckets are becoming invisible landfills.
- Review whether the contract docs still match actual operating behavior, especially [verification-commands.md](../verification-commands.md), [review-checklists.md](../review-checklists.md), and any active checklist under `docs/codex/next-full-work/`.
- Re-check whether any new subproject or workflow now needs a local override, following the restraint in [next-full-checklist.md](../next-full-checklist.md) and [future-checklists.md](../future-checklists.md): add local guidance only where verification or operating rules truly diverge.
- Retire or relabel stale evidence docs so snapshots do not get mistaken for current policy.
- Review whether helper-doc or helper-script gaps are still causing repeated manual work; if not, do not add more automation.

## Before a big push

Run this before a major feature push, a broad cleanup pass, or any large Codex session in an already-dirty tree.

- Re-read the root `AGENTS.md` plus the nearest local `AGENTS.md` or `AGENTS.override.md` for the target area.
- Re-check the applicable contract docs in `docs/codex` before touching files: verification, review, and UI guidance where relevant.
- Inspect narrow `git status` for the exact paths you plan to touch so existing dirt is understood before new edits begin.
- Decide the smallest trustworthy verification loop up front using [verification-commands.md](../verification-commands.md).
- If the push may generate screenshots, exports, probes, or temp outputs, decide their destination first so the repo root does not become the default bucket.
- If the push crosses product boundaries, split the work by subproject rather than treating `~/Nixe` as one app.

## Pre-flight checklist

Use this at the start of a large Codex session.

- Start in the smallest relevant subdirectory.
- Read the nearest instruction chain before opening broad searches.
- Check narrow `git status` for the intended paths.
- Identify which docs are contracts for this session.
- Choose the narrowest verification command before editing.
- Decide where temporary outputs will go if the task is likely to generate them.

## Post-flight checklist

Use this before ending a large Codex session.

- Re-run narrow `git status` for the paths you touched and confirm any remaining dirt is understood.
- Make sure new screenshots, exports, probes, and temp files are either intentionally kept, moved into the right bucket, or explicitly left for a reviewed follow-up.
- Confirm that any workflow or review-rule change is reflected in the relevant `docs/codex` contract doc, not only in agent memory.
- Confirm the verification actually run matches the change scope, or record why verification was intentionally not run.
- Retire or update any temporary note that would mislead the next session.

## Contracts vs references

Treat these `docs/codex` files as operational contracts.

- [next-full-checklist.md](../next-full-checklist.md): current execution contract for the next substantial Codex cleanup and hardening pass.
- [verification-commands.md](../verification-commands.md): verification contract until wrapper scripts exist.
- [review-checklists.md](../review-checklists.md): review contract when a change falls into one of the sensitive scopes it defines.
- [ui-baseline.md](../ui-baseline.md), [accessibility.md](../accessibility.md), and [motion-performance.md](../motion-performance.md): UI contracts whenever frontend work is touched.
- Files under `docs/codex/next-full-work/`: local decision records for active next-full checklist items once written.

Treat these as references or evidence, not evergreen contracts.

- [next-task-checklist.md](../next-task-checklist.md): completed historical queue.
- [future-checklists.md](../future-checklists.md): sequencing guidance for later waves, not a rulebook for every session.
- [workspace-optimization.md](../workspace-optimization.md): rationale and setup background.
- [noise-inventory.md](../noise-inventory.md): audit snapshot that informs policy but does not replace policy.
- [cleanup-execution.md](../cleanup-execution.md): execution record and evidence snapshot.
- [verification-root-hackthecart.md](../verification-root-hackthecart.md) and [verification-tallowsearch-firecrawl.md](../verification-tallowsearch-firecrawl.md): verification evidence, not recurring operating contracts.
- `docs/codex/cleanup-manifests/`: cleanup evidence and supporting manifests unless a later policy doc explicitly promotes one into a contract.

## Smallest useful next additions

Do not add scripts yet. When the next-full checklist reaches helper work, add only the smallest set that removes repeated manual friction.

1. Add `docs/codex/maintenance-commands.md` first.
   Why: the workspace already has the policies and verification rules; what is still missing is one short operator-facing index for the recurring commands used during cleanup, instruction checks, and status triage.
2. Add a path-scoped git-status helper script second.
   Why: the most common repeated action across the current docs is narrow status inspection in a dirty tree. This gives immediate value with low risk and no destructive behavior.
3. Add a root-clutter count helper script third.
   Why: weekly and monthly maintenance both depend on quickly checking whether root clutter, `probe_*`, `tmp_*`, and artifact buckets are growing again.
4. Defer the active-instruction-files helper until after the two scripts above.
   Why: instruction-chain verification matters, but it is less frequent than status triage and clutter counting, and the existing verification evidence already documents the manual baseline.

## Priority rule

Prefer docs before scripts, and prefer scripts that only inspect state before scripts that infer or mutate it. That keeps the next-full helper layer composable, path-scoped, and safe in a deliberately dirty workspace.
