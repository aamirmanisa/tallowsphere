# Codex Workspace Optimization

## Purpose

`Nixe` is a large, mixed-toolchain workspace with multiple real products, a large amount of generated output, and several legacy Claude-oriented instruction files. Codex works better here when instructions are layered, local, and concise.

## Codex-Native Structure

- Root `AGENTS.md` for workspace-wide rules
- Subproject `AGENTS.md` or `AGENTS.override.md` close to the code being edited
- Project-scoped `.codex/config.toml` for default behavior
- Small task-specific markdown docs referenced from `AGENTS.md`

## What Was Optimized

- Added a root `AGENTS.md` instead of relying on `CLAUDE.md`
- Added subproject guidance for `tallow/`, `tallow-search/`, and `firecrawl-self-hosted/`
- Added an API-local override for `firecrawl-self-hosted/apps/api/`
- Added `.codex/config.toml` with pragmatic defaults and clearer project-root markers
- Moved reusable UI guidance into `docs/codex/`
- Marked legacy `.claude` files as migration references instead of the primary instruction source

## Workspace-Specific Problems

- One git root contains several products with different stacks and verification loops
- Root-level temporary files and data dumps create high context noise
- Legacy prompt files are larger and more ambiguous than Codex wants
- The worktree is frequently dirty, so broad cleanup or revert behavior is risky

## Best Operating Model For Codex

1. Start Codex in the smallest relevant directory.
2. Let the root `AGENTS.md` provide global rules and the nearest subproject file provide local rules.
3. Run the smallest relevant test/build command instead of full-repo validation by default.
4. Avoid broad searches through generated artifacts unless the task is about them.
5. Keep instruction files short and push long reference material into normal docs.

## Recommended Next Optimizations

- Move transient outputs under a few known buckets such as `artifacts/` or `tmp/`.
- Add more ignore rules for screenshots, probe outputs, and one-off dumps if you do not need them tracked.
- Add per-project wrapper scripts for the most common verification flows.
- Add narrow review-policy docs only where review expectations actually diverge.
- Use separate worktrees or start Codex from subprojects when working in parallel.

## Verified Instruction Notes

- `~/Nixe/tallow` correctly layers `~/Nixe/AGENTS.md` and `~/Nixe/tallow/AGENTS.md`, with the nearer file winning on conflicts.
- `~/Nixe/tallow-search` correctly layers `~/Nixe/AGENTS.md` and `~/Nixe/tallow-search/AGENTS.md`, with the nearer file winning on conflicts.
- `~/Nixe/firecrawl-self-hosted/apps/api` does not inherit `~/Nixe/AGENTS.md` because `firecrawl-self-hosted/` is its own nested Git root. Its effective chain is `firecrawl-self-hosted/AGENTS.md` then `apps/api/AGENTS.override.md`.
- `codex debug prompt-input` is the most direct way to inspect model-visible instruction payloads, but it can be materially slower than `codex exec` because it emits a larger JSON dump.
- Local user-level Codex/plugin noise can pollute stderr during verification without changing the actual instruction chain. In this workspace, the main noise sources were malformed user-level agent-role TOML files and plugin/analytics `403` errors.

## Verification

- `codex --ask-for-approval never "Summarize the current instructions."`
- `codex --cd tallow --ask-for-approval never "Show which instruction files are active."`
- `codex --cd firecrawl-self-hosted/apps/api --ask-for-approval never "Show which instruction files are active."`
