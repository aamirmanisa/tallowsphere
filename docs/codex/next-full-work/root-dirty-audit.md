# Root Tracked-Dirty Audit

Scope: tracked dirty files at repo root only, excluding all subdirectories.

Audit basis:
- `git status --porcelain=v1 --untracked-files=no` filtered to root paths only.
- Targeted diff review for each root file.
- Repository-context checks against nearby tracked dirty work and targeted reference searches.

## Current tracked-dirty root file list

- `.gitignore`
- `CLAUDE.md`
- `Cargo.lock`
- `install.ps1`
- `package-lock.json`
- `package.json`
- `search-chicken.png`

## Classification by file

| File | Classification | Repository context | Recommended handling |
| --- | --- | --- | --- |
| `.gitignore` | config drift | Diff only adds ignore rules for `/.playwright-mcp/`, `/artifacts/`, `/probe_*`, and `/tmp/`. Those paths match the workspace guidance in `AGENTS.md` that already treats these as low-signal/generated areas. This is repo hygiene, not product behavior. | Keep only if Phase 3 wants repo-root ignore policy updated now; otherwise move to a dedicated housekeeping PR so it does not ride along with product work. |
| `CLAUDE.md` | config drift | Diff adds legacy/redirect notes pointing agents to `AGENTS.md`, `.codex/config.toml`, and `docs/codex/`. This changes operator guidance only and does not affect runtime, build, or tests. | Keep if the team is standardizing agent instructions in this phase; otherwise isolate into documentation cleanup. |
| `Cargo.lock` | active work | Lockfile changes include real dependency movement such as `axum 0.7.9 -> 0.8.9`. That lines up with the large tracked-dirty root Rust surface in `src/`, `tests/`, and `crates/tallow-daemon/`, so this looks like dependency sync for ongoing compiler/runtime or daemon work rather than stray churn. | Retain with the active Rust changes and verify via the narrowest meaningful Rust check before merge. Do not split it away from the code that requires it. |
| `install.ps1` | active work | Diff adds retry/TLS hardening, GitHub API headers, fallback download behavior, and local-build fallback. That is substantial installer behavior work, and it matches concurrent root install/test activity such as tracked dirt in `tests/perf_install.rs`. | Retain with installer/runtime work, but require a Windows install-path smoke check before signoff. |
| `package-lock.json` | config drift | Change is entirely the lockfile consequence of adding `socks-proxy-agent` at root. Targeted search over tracked root tooling paths did not show a tracked consumer for that package, so this currently reads as workspace/tooling drift rather than demonstrated shipped behavior. | Either attach it to a tracked root script/tool change that actually uses the dependency or revert/defer it from Phase 3. |
| `package.json` | config drift | Root manifest change is only `socks-proxy-agent`. The root manifest is a tooling manifest, and the targeted reference pass did not find a tracked root script or source file that consumes it yet. | Same handling as `package-lock.json`: keep only with a concrete tracked consumer; otherwise drop from this phase. |
| `search-chicken.png` | stale residue | The file is tracked and dirty, but targeted tracked-source search found no textual references to `search-chicken`. It is also a standalone root binary asset rather than a file inside a documented app asset tree. In current repository context, it looks like leftover scratch output. | Remove from the phase unless an owner can point to an active reference path or deliverable that still depends on it. |

## Recommended handling by group

### Active work

- `Cargo.lock`
- `install.ps1`

Handling:
- Keep with the ongoing root Rust and installer changes.
- Verify them with the smallest matching checks before merge instead of trying to clean them up as independent drift.

### Config drift

- `.gitignore`
- `CLAUDE.md`
- `package.json`
- `package-lock.json`

Handling:
- Separate policy/documentation/tooling drift from product work where possible.
- Keep `.gitignore` and `CLAUDE.md` only if Phase 3 explicitly includes workspace-instruction and hygiene updates.
- Keep `package.json` and `package-lock.json` only if a tracked root tool change in this phase actually needs `socks-proxy-agent`.

### Stale residue

- `search-chicken.png`

Handling:
- Treat as removable residue unless a concrete owner claims it for an active root deliverable.

## Phase 3 summary

Phase 3 should treat the root dirty set as:
- 2 files that look tied to active root work.
- 4 files that look like config/instruction/tooling drift.
- 1 file that looks like stale residue.

## Changed files

- `e:/Nixe/docs/codex/next-full-work/root-dirty-audit.md`
