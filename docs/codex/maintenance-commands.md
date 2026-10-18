# Maintenance Commands

These are the smallest recurring commands for Codex hygiene in `~/Nixe`.

## Root Clutter Counts

```powershell
powershell -File scripts/codex/root-clutter-counts.ps1
```

Use this to re-check:

- `/.playwright-mcp/` size
- `/artifacts/` size
- `/tmp/` size
- root `probe_*` entries
- root `tmp_*` entries
- root hidden `.tmp*` entries
- root loose-clutter file count

## Workspace Inventory

```powershell
powershell -File scripts/codex/workspace-inventory.ps1
```

Emit an updated markdown snapshot:

```powershell
powershell -File scripts/codex/workspace-inventory.ps1 -OutputPath docs/codex/workspace-inventory.md
```

Use this when you need a fresh, reproducible top-level classification before a broad cleanup or reorg pass.

## Root Artifact Manifest

```powershell
powershell -File scripts/codex/root-artifact-manifest.ps1
```

Emit a snapshot report:

```powershell
powershell -File scripts/codex/root-artifact-manifest.ps1 -OutputPath docs/codex/root-artifact-manifest.md
```

Use this to verify whether current repo-root clutter files are fully covered by `docs/codex/root-artifact-policy.md` before moving anything.

## Scoped Status

```powershell
powershell -File scripts/codex/scoped-status.ps1 -Path docs/codex,scripts/codex
```

Examples:

```powershell
powershell -File scripts/codex/scoped-status.ps1 -Path tallow/import,tallow/infra/scripts
powershell -File scripts/codex/scoped-status.ps1 -Path tallow-search/extension,scripts -WithDiff
```

Use this instead of repo-wide `git status` when the tree is intentionally dirty.

## Active Instruction Chain

```powershell
powershell -File scripts/codex/show-active-instructions.ps1
```

Optional target paths:

```powershell
powershell -File scripts/codex/show-active-instructions.ps1 -Path tallowsphere/tallow,tallowsphere/tallow-search
```

This prints the repo-local instruction chain for each target directory. It is a filesystem/git-root inspection helper, not a full Codex prompt dump.

## Existing Manual Verification

When a helper script is not enough, fall back to the contract doc:

- [verification-commands.md](./verification-commands.md)

## Safety

- These commands are path-scoped and non-destructive.
- They are safe to run in a dirty workspace.
- They inspect state; they do not move, delete, or rewrite files.
