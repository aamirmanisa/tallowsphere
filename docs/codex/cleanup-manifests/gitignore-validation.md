# Gitignore Validation

Audit date: 2026-04-29

Scope: validate whether the current root `.gitignore` already hides the proposed cleanup destinations from [`docs/codex/noise-inventory.md`](../noise-inventory.md).

## Result

- Repo-root `tmp/` and `artifacts/` destinations are already ignored by the root [`.gitignore`](../../../.gitignore).
- Representative `git check-ignore -v` checks resolved as expected:
  - `.gitignore:22 /tmp/` matched `tmp/moved-clutter/example.json`
  - `.gitignore:20 /artifacts/` matched `artifacts/probes/run.log`
  - `.gitignore:20 /artifacts/` matched `artifacts/tmp/cache.txt`
  - `.gitignore:20 /artifacts/` matched `artifacts/phase1_evidence/summary.md`
  - `.gitignore:20 /artifacts/` matched `artifacts/playwright/archive.png`
- For the exact repo-root destinations proposed in the inventory, no new ignore rule is required.

## Coverage By Proposed Destination

| Proposed move target | Current coverage | Notes |
| --- | --- | --- |
| Root `tmp_*` clutter -> `/tmp/` | Covered | Root `.gitignore` has `/tmp/`, so anything relocated under repo-root `tmp/` will be hidden while untracked. |
| Root `tmp_*` clutter -> `/artifacts/` | Covered | Root `.gitignore` has `/artifacts/`, which hides all descendants such as `artifacts/tmp/` or `artifacts/moved-clutter/`. |
| Root `probe_*` trees -> `/artifacts/probes/` | Covered | `/artifacts/` already covers the more specific probe destination. |
| Current `/.playwright-mcp/` archive -> ignored artifact bucket | Conditionally covered | A new untracked copy under `artifacts/` would be ignored. A direct move of already tracked files is a separate Git-index problem. |
| Standardize `artifacts/tmp/` and root `/tmp/` into one repo-root temp bucket | Covered | Both repo-root `tmp/` and any path under repo-root `artifacts/` are already ignored. |

## Gaps

- The existing rules are root-anchored. They cover repo-root `/tmp/` and `/artifacts/`, but they do not cover nested destinations such as `hackthecart/tmp/` or `docs/artifacts/`.
- `.gitignore` only hides untracked paths. If the currently committed `/.playwright-mcp/` archive is relocated with history-preserving Git moves, the destination can remain tracked even under `artifacts/`. That relocation would need an explicit de-indexing step or an external archive destination.

## Conclusion

- The current `.gitignore` is sufficient for the repo-root cleanup destinations proposed in the inventory.
- The only follow-up concerns are operational: keep the destination buckets at repo root, and treat tracked `.playwright-mcp` content as an index cleanup rather than expecting ignore rules to hide it automatically.
