# Full Workspace Optimization - Phase 3

Date: 2026-05-10
Scope: `/mnt/Personal/Nixe/AamiFinancial`

Phase 3 adds missing local instruction coverage for a project-candidate subtree.

## Changes Applied

- Added `AamiFinancial/AGENTS.md` with:
  - explicit project scope and key directories
  - low-signal path policy (`target/`, `node_modules/`, `dist/`, `tmp/`, sqlite runtime files)
  - scoped verification commands for Rust CLI and desktop flows
  - completion criteria aligned with workspace-level guidance
- Updated root `AGENTS.md` to reference the new local guidance file for `AamiFinancial/`.

## Why This Matters

- `AamiFinancial/` has its own Rust workspace and runtime/developer loops.
- Without local guidance, Codex sessions can over-scan noisy temp/runtime trees and pick broad verification loops.
- This change makes `AamiFinancial/` first-class in the workspace optimization model.

## Verification

- Regenerated top-level inventory to confirm classification changed from project-candidate to project-with-local-guidance.
- Ran scoped status checks for only touched optimization paths.

## Deferred

- No file moves were performed in this phase.
- No runtime/build behavior changes were introduced in this phase.
