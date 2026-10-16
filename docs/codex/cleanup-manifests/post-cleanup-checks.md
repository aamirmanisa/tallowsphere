# Post-Cleanup Checks

Run these checks from `~/Nixe` after any clutter-move pass. Keep the verification path-scoped: this workspace is intentionally dirty, so repo-wide clean status is not a useful pass condition for cleanup work.

## Baseline Snapshot

Use these pre-cleanup counts to explain what changed:

| Metric | Baseline |
| --- | ---: |
| `.playwright-mcp/` files | 509 |
| `artifacts/` files | 2100 |
| `tmp/` files | 34609 |
| Root `probe_*` entries | 38 |
| Root `tmp_*` entries | 14 |
| Root loose clutter files | 130 |

`Root loose clutter files` means repo-root files matching `*.png`, `*.jpg`, `*.jpeg`, `*.webp`, `*.gif`, `*.html`, `*.json`, `*.csv`, `*.log`, or `*.sql`, excluding the intentional root manifests `package.json` and `package-lock.json`.

## File Count Check

Run this exact command block:

```powershell
function Count-Files($path) {
  if (Test-Path $path) {
    (rg --files --hidden --glob '!**/.git/**' $path 2>$null | Measure-Object -Line).Lines
  } else {
    0
  }
}

$root = 'E:\Nixe'
$patterns = @('*.png','*.jpg','*.jpeg','*.webp','*.gif','*.html','*.json','*.csv','*.log','*.sql')
$allowedRootFiles = @('package.json','package-lock.json')

[ordered]@{
  playwright_files = Count-Files "$root\.playwright-mcp"
  artifacts_files = Count-Files "$root\artifacts"
  tmp_files = Count-Files "$root\tmp"
  probe_root_entries = (Get-ChildItem $root -Force -Name | Where-Object { $_ -like 'probe_*' } | Measure-Object).Count
  tmp_root_entries = (Get-ChildItem $root -Force -Name | Where-Object { $_ -like 'tmp_*' } | Measure-Object).Count
  root_loose_clutter_files = (
    Get-ChildItem $root -Force -File |
    Where-Object {
      $name = $_.Name
      ($allowedRootFiles -notcontains $name) -and (@($patterns | Where-Object { $name -like $_ }).Count -gt 0)
    } |
    Measure-Object
  ).Count
} | Format-Table -AutoSize
```

Pass criteria:

- `probe_root_entries` must be `0`.
- `tmp_root_entries` must be `0`.
- `root_loose_clutter_files` must be `0`.
- Record the before/after deltas for `playwright_files`, `artifacts_files`, and `tmp_files`; those counts are diagnostic, not automatic failures, because valid cleanup work can move files into `tmp/` or `artifacts/`.
- If the cleanup scope included `.playwright-mcp/`, then `playwright_files` must also be `0`. If it did not, call that bucket out explicitly as deferred.

## Git Status Check

Run only path-scoped status and diff commands:

```powershell
git status --short -- .playwright-mcp artifacts tmp ':(glob)probe_*' ':(glob)tmp_*'
git diff --name-status --find-renames -- .playwright-mcp artifacts tmp ':(glob)probe_*' ':(glob)tmp_*'
git status --short -- .gitignore docs/codex/noise-inventory.md docs/codex/next-task-checklist.md docs/codex/cleanup-manifests
```

Pass criteria:

- No source-code paths outside the cleanup scope appear in those scoped outputs.
- Expected status letters are `R`, `A`, `D`, and `M`, limited to cleanup buckets plus any intentional policy/docs updates such as `.gitignore`, [`noise-inventory.md`](../noise-inventory.md), [`next-task-checklist.md`](../next-task-checklist.md), or cleanup manifests.
- `D` plus `??` pairs are acceptable only when the new destination is under `tmp/`, `artifacts/`, or another explicitly documented bucket and the cleanup summary names that destination.

## Checklist Update Criteria

For [`next-task-checklist.md`](../next-task-checklist.md):

- Mark `Consolidate scattered temp outputs under a small number of directories such as tmp/ and artifacts/` complete only when:
  - `probe_root_entries = 0`
  - `tmp_root_entries = 0`
  - every moved root temp/probe path now lives under `tmp/`, `artifacts/`, or another explicitly documented destination
- Mark `Reduce root-level clutter from one-off screenshots and run outputs where possible` complete when either:
  - `root_loose_clutter_files = 0`, or
  - every remaining root loose clutter file is tracked and intentionally retained in a cleanup summary
- If `.playwright-mcp/` remains at repo root, record that the tracked archive move is deferred. That does not block completion of the disposable-root-clutter pass.

If either checklist item stays unchecked, add the exact remaining path names to the cleanup summary instead of a generic "some clutter remains" note.

## Cleanup Summary The Main Thread Should Record

The main thread should capture:

- The before/after values for all six metrics in the file count check.
- The exact remaining path names for any deferred root clutter.
- Whether `.playwright-mcp/` was moved, left in place intentionally, or split into a follow-up change.
