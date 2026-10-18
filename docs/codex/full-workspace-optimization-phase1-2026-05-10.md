# Full Workspace Optimization - Phase 1

Date: 2026-05-10
Scope: `/mnt/Personal/Nixe`

This phase is non-destructive. It establishes a complete map for "full Codex optimization" before any bulk moves.

## What Phase 1 Completed

- Re-validated active instruction layering (`AGENTS.md` at root plus local project files)
- Confirmed nested git boundaries (`firecrawl-self-hosted/`, `hermes-agent/`)
- Classified top-level workspace buckets for safe Codex scoping
- Added a repeatable inventory helper: `scripts/codex/workspace-inventory.ps1`
- Expanded root `AGENTS.md` with additional non-core subtree guidance

## Current Workspace Classification

### Core managed products

- Root Tallow runtime/compiler (`src/`, `tests/`, `examples/`, `stdlib/`, `crates/`)
- `tallow/`
- `tallow-search/`
- `firecrawl-self-hosted/` (nested repo)
- `hermes-agent/` (nested repo)

### Secondary project candidates

- `AamiFinancial/` (contains `Cargo.toml`; no local `AGENTS.md`)

### Low-signal or generated roots

- `target/`, `dist/`, `node_modules/`
- `tmp/`, `tmp_*`, `probe_*`
- `.playwright-mcp/`, `artifacts/`

### Auxiliary/unclassified roots (task-driven entry only)

- `apps/`, `beboldfurniture/`, `openclaw-tallow/`, `self-host/`, `vendor/`

## Constraints Found

- The workspace is intentionally very dirty; broad cleanup is high risk.
- Existing docs already define artifact/noise policy (`docs/codex/root-artifact-policy.md`, `docs/codex/cleanup-manifests/*`).
- Root path dependencies still exist for some tracked data files used by scripts; those cannot be moved blindly.

## Phase 2 Plan (Structural, Controlled)

1. Freeze a move manifest first.
2. Move only low-risk transient directories into approved buckets (`tmp/` or `artifacts/`) where policy already allows.
3. Keep path-sensitive tracked seed/import files in place unless dependent scripts are updated in the same change.
4. Handle nested repos (`firecrawl-self-hosted/`, `hermes-agent/`) independently with their own guidance.
5. Validate with scoped status + smallest project-specific checks.

## Move Safety Rules

- No bulk wildcard moves from repo root.
- No cross-boundary moves into nested git repos.
- No move of tracked root data files listed as "keep at root" in `docs/codex/root-artifact-policy.md` unless references are updated atomically.
- Use path-scoped verification only; do not attempt full-repo clean status as a prerequisite.

## Operational Commands

- Generate top-level classification:
  - `powershell -File scripts/codex/workspace-inventory.ps1`
- Emit markdown snapshot:
  - `powershell -File scripts/codex/workspace-inventory.ps1 -OutputPath docs/codex/workspace-inventory.md`
- Check scoped status for this phase:
  - `powershell -File scripts/codex/scoped-status.ps1 -Path AGENTS.md,docs/codex,scripts/codex`

## Exit Criteria For Phase 1

- Workspace map exists and is reproducible.
- Codex scoping guidance covers both core and non-core roots.
- No destructive moves were performed.
