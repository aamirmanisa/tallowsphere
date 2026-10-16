# Root `tmp_*` Files Cleanup Manifest

Audit date: 2026-04-29
Worker: cleanup worker 2 of 10
Scope: repo-root untracked files whose basenames match `tmp_*`.

## Result

No current repo-root files matched both conditions:

- basename matched `tmp_*`
- Git reported the path as untracked

Safe-to-move set for `tmp/root-legacy/files`: none at the time of inspection.

## Notes

- `git ls-files --others --exclude-standard --full-name | rg '^tmp_'` returned no matches, so there are no current non-ignored root `tmp_*` entries to manifest.
- Direct filesystem enumeration did find repo-root `tmp_*.log` files, but representative `git check-ignore -v` checks showed they are ignored by [`E:\Nixe\.gitignore`](E:\Nixe\.gitignore) via `*.log`. They are therefore out of scope for this untracked-only manifest.
- No current untracked repo-root `tmp_*` matches used source-like extensions such as `.rs`, `.js`, `.ps1`, `.sh`, `.sql`, or `.tl`, so there are no caution cases to flag within the assigned scope.
- Hidden directories beginning with `.tmp_` are also out of scope because they do not match the assigned `tmp_*` pattern.
