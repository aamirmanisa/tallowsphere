# Residual Risk

Audit date: 2026-04-29

Scope: root clutter and status noise that still remains after a safe untracked-only cleanup pass in `tallowsphere`.

Definition: "untracked-only" means deleting paths that are not tracked by Git without touching tracked content. If the pass does not explicitly include ignored paths, ignored roots also remain.

## Residuals After A Plain Untracked-Only Pass

- `/.playwright-mcp/` still remains in two ways:
  - `243` committed capture files are tracked and cannot be removed by untracked cleanup.
  - `397` additional ignored capture files are currently on disk (`220` `.yml`, `131` `.log`, `32` `.png`, `14` `.jpeg`) and also remain unless ignored paths are explicitly cleaned.
- `/artifacts/` remains if ignored paths are not included. Current size at the root bucket: `2,837` files across `803` directories.
- `/tmp/` remains if ignored paths are not included. Current size at the root bucket: `34,611` files across `197` directories.
- Root `probe_*` entries remain if ignored paths are not included: `35` directories and `3` files.
- Root `tmp_*` entries remain if ignored paths are not included: `2` directories and `14` files.

## Residuals Even If Ignored Noise Is Also Removed

- Git still shows `322` tracked dirty entries after excluding untracked paths:
  - `321` modified tracked entries
  - `1` tracked deletion
- The tracked dirt is concentrated in a few top-level areas:

| Area | Dirty tracked entries |
| --- | ---: |
| `src/` | 176 |
| `tallow/` | 56 |
| `tallow-search/` | 53 |
| `tests/` | 19 |
| `[root]` | 7 |
| `.claude/` | 5 |
| `crates/` | 4 |
| `.github/` | 2 |

- Root tracked entries that still remain visible in status after any untracked-only cleanup:
  - `M .gitignore`
  - `M CLAUDE.md`
  - `M Cargo.lock`
  - `M install.ps1`
  - `M package-lock.json`
  - `M package.json`
  - `D search-chicken.png`
- `/.playwright-mcp/` is the main committed archive risk. Even if ignored files under that directory are removed, the `243` tracked snapshot artifacts still stay in history and in the checkout until a separate reviewed change removes or relocates them.

## Why This Matters

- `.gitignore` already contains root ignore rules for `/.playwright-mcp/`, `/artifacts/`, `/probe_*`, and `/tmp/`. That reduces day-to-day status noise for new files, but it does not solve committed archive noise and it lets ignored scratch output keep accumulating quietly.
- No tracked root matches were found under `artifacts/**`, `probe_*`, or `tmp*`. Those buckets are primarily ignored-run-output problems.
- The residual risk after a safe cleanup is therefore not just disk clutter. It is also review noise and status churn from tracked archives plus `322` tracked changes that require explicit human review rather than automated deletion.

## Bottom Line

- A safe untracked-only cleanup can reduce some scratch output, but it will not make the root feel clean.
- The main leftovers are:
  - ignored root buckets if the pass skips ignored files
  - the committed `/.playwright-mcp/` archive
  - the large set of modified tracked files and the tracked deletion already present in the worktree
