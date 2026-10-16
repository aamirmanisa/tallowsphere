# Excluded Tracked Items

Audit date: 2026-04-29

Scope: root-level items that may look like cleanup candidates, but should stay out of this pass because they are tracked, currently modified, or too source-like to relocate casually.

## Exclude From This Pass

| Path or Pattern | Why it stays put |
| --- | --- |
| `/.playwright-mcp/` | Tracked browser-capture archive. It is noisy, but moving it would be a separate tracked-content cleanup with broad churn. |
| Root-level modified tracked files: `.gitignore`, `CLAUDE.md`, `Cargo.lock`, `install.ps1`, `package-lock.json`, `package.json`, `search-chicken.png` | Already modified or deleted in the current worktree. Do not mix active edits with cleanup moves. |
| Root project/source directories: `/.claude/`, `/.github/`, `/.planning/`, `/apps/`, `/benches/`, `/crates/`, `/docs/`, `/editors/`, `/examples/`, `/fuzz/`, `/hackthecart/`, `/scripts/`, `/self-host/`, `/src/`, `/stdlib/`, `/tallow-search/`, `/tests/`, `/vendor/` | These are repository structure, source, workflow, or documentation trees, not disposable root clutter. |
| Root manifests, scripts, and test inputs: `.env.example`, `Cargo.toml`, `deny.toml`, `install-frontend-skills.sh`, `install.ps1`, `install.sh`, `nas-sync.toml`, `sync_nas.bat`, `fix_*.js`, `test_*.tl` | Source-like or executable files. Even if some are ad hoc, they should only move with owner review and reference checks. |
| Root committed reference assets and data dumps: `*.png`, `*.jpg`, `*.json`, `*.sql`, `hackthecart-homepage.md`, `out.txt` | Tracked QA artifacts, screenshots, import data, or reference outputs. They may warrant later consolidation, but not in a temp-clutter sweep. |

## Practical Rule

This pass should only relocate clearly disposable root noise such as untracked `tmp*`, `probe_*`, or similar scratch output. If an item is tracked, modified, executable, or plausibly referenced by docs/tests/workflows, exclude it and handle it in a dedicated follow-up change.
