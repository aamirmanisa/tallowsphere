# Maintenance Cadence

This is the recurring hygiene contract for keeping `~/Nixe` workable as a Codex-first workspace.

## Weekly

- Review path-scoped `git status` in the root and the subproject you actually worked in.
- Re-check noisy buckets listed in [noise-inventory.md](./noise-inventory.md): `/.playwright-mcp/`, `/artifacts/`, `/tmp/`, and any new root `probe_*` or `tmp_*` outputs.
- Use the narrow verification loops in [verification-commands.md](./verification-commands.md) instead of broad repo-wide runs.
- If UI work happened, re-read [ui-baseline.md](./ui-baseline.md), [accessibility.md](./accessibility.md), and [motion-performance.md](./motion-performance.md) before the next UI-heavy pass.
- Retire or update short-lived cleanup notes once they become misleading.

## Monthly

- Re-run the root clutter and artifact-bucket audit implied by [cleanup-execution.md](./cleanup-execution.md) and [noise-inventory.md](./noise-inventory.md).
- Review whether contract docs still match current operating behavior:
  - [verification-commands.md](./verification-commands.md)
  - [review-checklists.md](./review-checklists.md)
  - [next-full-checklist.md](./next-full-checklist.md)
- Re-check whether any new subproject actually needs a local override.
- Retire or relabel stale evidence docs so they are not mistaken for current policy.
- Add automation only when the same manual step keeps repeating.

## Before A Big Push

- Re-read the root `AGENTS.md` plus the nearest local `AGENTS.md` or `AGENTS.override.md`.
- Re-check the relevant contract docs before touching files.
- Inspect narrow `git status` for the exact paths you plan to touch.
- Decide the smallest trustworthy verification loop up front.
- Decide the destination for screenshots, exports, probes, and temp outputs before you generate them.
- If work crosses product boundaries, split it by subproject instead of treating `~/Nixe` as one app.

## Pre-Flight

- Start in the smallest relevant subdirectory.
- Read the nearest instruction chain before broad searches.
- Check narrow `git status` for the intended paths.
- Identify which docs are contracts for this session.
- Choose the narrowest verification command before editing.
- Decide where temporary outputs will go if the task is likely to generate them.

## Post-Flight

- Re-run narrow `git status` for the paths you touched.
- Make sure new screenshots, exports, probes, and temp files are intentionally kept, moved to the right bucket, or explicitly deferred.
- Reflect any workflow or review-rule change in the relevant `docs/codex` contract doc.
- State the verification actually run, or why it was intentionally skipped.
- Retire or update any temporary note that would mislead the next session.

## Contracts

Treat these files as operational contracts:

- [next-full-checklist.md](./next-full-checklist.md)
- [verification-commands.md](./verification-commands.md)
- [review-checklists.md](./review-checklists.md)
- [ui-baseline.md](./ui-baseline.md)
- [accessibility.md](./accessibility.md)
- [motion-performance.md](./motion-performance.md)
- files under `docs/codex/next-full-work/` while the corresponding checklist work is active

## References

Treat these as references or evidence:

- [next-task-checklist.md](./next-task-checklist.md)
- [future-checklists.md](./future-checklists.md)
- [workspace-optimization.md](./workspace-optimization.md)
- [noise-inventory.md](./noise-inventory.md)
- [cleanup-execution.md](./cleanup-execution.md)
- [verification-root-hackthecart.md](./verification-root-hackthecart.md)
- [verification-tallowsearch-firecrawl.md](./verification-tallowsearch-firecrawl.md)
- `docs/codex/cleanup-manifests/`
