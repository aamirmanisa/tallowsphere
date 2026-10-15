# Next Full Checklist

This is the successor to [next-task-checklist.md](./next-task-checklist.md). Use it for the next substantial Codex-focused cleanup and hardening pass in `~/Nixe`.

## Goal

Reduce tracked review noise, make the remaining artifact policy explicit, and add a few low-friction automation hooks so Codex can operate in this workspace with less manual setup.

## Phase 1: Resolve The Remaining Root Artifact Policy

- [x] Decide whether the remaining `70` tracked root loose-clutter files should stay at repo root, move into a tracked `docs/reference-assets/` style location, or move into an ignored artifact bucket in a reviewed change
- [x] Group the `70` tracked root files into categories such as product screenshots, infra screenshots, export data, SQL seeds, and search/reference outputs
- [x] Create one policy doc that explains which root-level tracked artifacts are intentional and which should eventually move
- [x] Decide whether `search-chicken.png` should remain a root-level tracked working asset or move with the rest of the tracked screenshots
- [ ] If any root tracked artifacts move, update every direct file reference that depends on the old location

## Phase 2: Decide What To Do With `/.playwright-mcp/`

- [x] Inventory what is actually still useful inside `/.playwright-mcp/`
- [x] Split the bucket into three classes: keep tracked, keep but ignore future output, or remove from the repo in a separate reviewed cleanup
- [x] If tracked retention is required, document why in a Codex-facing policy note
- [x] If future captures should remain local-only, keep the root ignore rule and document the operating convention
- [x] If historical tracked captures are no longer needed, plan a separate cleanup change that removes or relocates them without mixing it into feature work

## Phase 3: Reduce Tracked Status Noise

- [x] Audit the current tracked-dirty root files and classify each one as active work, config drift, or stale residue
- [x] Audit `.claude` tracked modifications and decide whether they should be kept, trimmed further, or isolated into a clearly documented migration state
- [x] Audit tracked modifications in `package.json`, `package-lock.json`, and subproject package manifests so the workspace bootstrap story stays coherent
- [x] Decide whether `Cargo.lock` should be treated as part of the Codex migration work or left entirely outside it
- [x] Write a short "known intentional dirty areas" doc so future Codex sessions do not waste time rediscovering the same status noise

## Phase 4: Add Repeatable Workspace Helpers

- [x] Add a `docs/codex/maintenance-commands.md` helper doc for the most common cleanup, verification, and status-triage commands
- [x] Add a small root script for the scoped root-clutter counts used in [cleanup-execution.md](./cleanup-execution.md)
- [x] Add a small root script for printing active instruction files from the common working directories
- [x] Add a small root script for path-scoped git status checks used during cleanup and documentation passes
- [x] Keep every helper path-scoped and non-destructive by default

## Phase 5: Tighten Subproject Guidance Where It Still Matters

- [x] Decide whether `hackthecart/import/`, `hackthecart/infra/scripts/`, and `hackthecart/data/` need narrower local overrides beyond the current `AGENTS` files
- [x] Decide whether `tallow-search/extension/` needs its own override because browser-extension work has a different verification loop than the API and web apps
- [x] Decide whether root `scripts/` or `docs/` need local overrides for operational tooling and reference maintenance
- [x] Add overrides only where behavior or verification actually diverges; avoid blanket instruction sprawl

## Phase 6: Create A Stable Maintenance Cadence

- [x] Define what should happen weekly, monthly, and before major feature pushes for Codex hygiene in this workspace
- [x] Define a small pre-flight checklist for starting a large Codex session in a dirty worktree
- [x] Define a small post-flight checklist for ending a large Codex session without leaving ambiguous artifacts behind
- [x] Decide which docs are operational contracts versus optional references

## Suggested Order

1. Resolve the root tracked-artifact policy.
2. Make an explicit decision on `/.playwright-mcp/`.
3. Reduce tracked status noise enough that future Codex sessions start cleaner.
4. Add helper scripts only after the operating policy is stable.
5. Add more local overrides only where the verification loop truly differs.
