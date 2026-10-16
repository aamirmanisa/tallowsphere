# Full Workspace Optimization - Phase 2

Date: 2026-05-10
Scope: `/mnt/Personal/Nixe` root transient directory normalization

This phase applies controlled, non-destructive moves for low-risk root temporary directories.

## Preconditions

- Workspace is intentionally dirty; cleanup must be path-scoped.
- Moves must stay inside the workspace root.
- No move of policy-protected tracked root data files.

## Move Manifest

Executed with explicit source/destination path checks:

| Source | Destination |
| --- | --- |
| `.tmp/` | `tmp/cache/dot-tmp/` |
| `.tmp_remote_fix/` | `tmp/root-legacy/dirs/.tmp_remote_fix/` |
| `.tmp_ideabrowser_postprocess_selfcheck/` | `tmp/root-legacy/dirs/.tmp_ideabrowser_postprocess_selfcheck/` |

## Safety Checks Used

- Verified each source path existed before move.
- Resolved each absolute source path and confirmed it starts with `tallowsphere`.
- Resolved each absolute destination parent path and confirmed it starts with `tallowsphere`.
- Refused to overwrite existing destination paths.
- Used `Move-Item -LiteralPath` only.

## Post-Move Validation

- Root now has no `.tmp*` directory entries.
- `tmp/` remains the single normalized root temp bucket.
- `scripts/codex/root-clutter-counts.ps1` now also reports hidden `.tmp*` root entries via `dot_tmp_root_entries`.

## Notes

- This phase intentionally does not touch tracked root reference/data assets listed in `docs/codex/root-artifact-policy.md`.
- This phase intentionally does not modify nested repositories (`firecrawl-self-hosted/`, `hermes-agent/`).
