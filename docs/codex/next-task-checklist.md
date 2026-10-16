# Next Task Checklist

Status: complete. The successor execution queues are [next-full-checklist.md](./next-full-checklist.md) and [future-checklists.md](./future-checklists.md).

This checklist is the next execution queue for improving `~/Nixe` as a Codex-first workspace.

## Phase 1: Verify The New Codex Setup

- [x] Run `codex --ask-for-approval never "Summarize the current instructions."` from `~/Nixe`
- [x] Run `codex --cd hackthecart --ask-for-approval never "Show which instruction files are active."`
- [x] Run `codex --cd tallow-search --ask-for-approval never "Show which instruction files are active."`
- [x] Run `codex --cd firecrawl-self-hosted/apps/api --ask-for-approval never "Show which instruction files are active."`
- [x] Confirm the nearest `AGENTS.md` or `AGENTS.override.md` wins in each subproject
- [x] Capture any instruction-loading surprises and fold them back into the repo docs

## Phase 2: Add Missing Local Overrides

- [x] Add `hackthecart/api/AGENTS.override.md`
- [x] Add `hackthecart/web/AGENTS.override.md`
- [x] Add `tallow-search/api/AGENTS.override.md`
- [x] Add `tallow-search/web/AGENTS.override.md`
- [x] Add a root `src/AGENTS.override.md` for Tallow compiler/runtime work
- [x] Add `tests/AGENTS.override.md` for root Rust test guidance if test workflows diverge from general rules

## Phase 3: Reduce Search And Context Noise

- [x] Inventory noisy paths that Codex should usually ignore
- [x] Review whether screenshots, probes, temp outputs, and generated CSV/JSON dumps should be gitignored
- [x] Consolidate scattered temp outputs under a small number of directories such as `tmp/` and `artifacts/`
- [x] Reduce root-level clutter from one-off screenshots and run outputs where possible
- [x] Document which artifact directories are intentionally committed versus disposable

## Phase 4: Standardize Verification Commands

- [x] Add a root helper doc for the most common verify commands by subproject
- [x] Add a `hackthecart` verification script or doc wrapper for API, web, and pipeline checks
- [x] Add a `tallow-search` verification script or doc wrapper for API and web checks
- [x] Add a root Tallow verification wrapper for focused Rust compiler/runtime checks
- [x] Document when to run targeted checks versus full-suite checks

## Phase 5: Improve Review And Safety Rules

- [x] Add a Codex review checklist for data-sensitive `hackthecart` changes
- [x] Add a Codex review checklist for API contract changes in `tallow-search`
- [x] Add a Codex review checklist for performance- or safety-sensitive Tallow runtime/compiler changes
- [x] Document "do not touch without explicit intent" paths if there are unstable or vendor-like areas

## Phase 6: Optional Global Codex Setup

- [x] Decide whether to add a user-level `~/.codex/AGENTS.md` for personal defaults outside this repo
- [x] Decide whether to add a user-level `~/.codex/config.toml` profile tuned for this machine
- [x] Keep personal defaults short so repo-local instructions stay authoritative

## Suggested Order

1. Verify the setup actually loads correctly.
2. Add local overrides in the busiest subprojects.
3. Clean up search noise so Codex operates faster and with less irrelevant context.
4. Standardize verification and review loops.
