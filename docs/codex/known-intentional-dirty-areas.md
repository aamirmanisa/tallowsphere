# Known Intentional Dirty Areas

Audit date: 2026-04-29

This note exists so future Codex sessions do not waste time rediscovering the same tracked-dirty patterns.

## Root Files

### Active root work

- `Cargo.lock`
- `install.ps1`

Interpretation:

- these line up with broader Rust / installer work
- do not treat them as casual cleanup targets

### Codex migration or workspace-hygiene drift

- `.gitignore`
- `CLAUDE.md`

Interpretation:

- these belong to the Codex-first workspace migration and repo-hygiene layer
- they are valid to touch only when the task is specifically about instruction migration or workspace cleanup

### Tooling drift that needs a concrete owner

- `package.json`
- `package-lock.json`

Interpretation:

- root manifest drift currently looks like tooling/bootstrap drift
- keep it only with a concrete tracked consumer or a clearly scoped tooling change

### Root artifact residue under policy review

- `search-chicken.png`

Interpretation:

- this is part of the broader tracked screenshot/test-proof cleanup policy in [root-artifact-policy.md](./root-artifact-policy.md)
- do not move it alone

## Claude Compatibility Surface

Current `.claude` dirt is intentional compatibility state, not random churn:

- `.claude/settings.json`
- `.claude/settings.local.json`
- `.claude/commands/baseline-ui.md`
- `.claude/commands/fixing-accessibility.md`
- `.claude/commands/fixing-motion-performance.md`

Operating rule:

- keep the current command-mirror approach for compatibility
- if `.claude` gets another cleanup pass, target `.claude/settings.local.json` first with a documented allowlist audit

See [next-full-work/claude-migration-audit.md](./next-full-work/claude-migration-audit.md).

## Out-Of-Scope Dirty Areas For Codex Migration

These should not be silently absorbed into Codex migration work:

- root `Cargo.lock` unless a migration task intentionally changes Rust manifests
- mixed product manifest drift under `tallow-search/web/`
- broad active feature work under `src/`, `tallow/`, `tallow-search/`, `tests/`, and related runtime/product trees

## High-Noise Buckets

These are intentionally low-signal and should not be treated as normal review targets:

- `/.playwright-mcp/`
- `/artifacts/`
- `/tmp/`
- root `tmp_*`
- root `probe_*`

Operational rule:

- inspect them only when the task is specifically about generated output, evidence, or cleanup

## Use This Doc

Use this file at session start together with:

- [next-full-checklist.md](./next-full-checklist.md)
- [maintenance-cadence.md](./maintenance-cadence.md)
- [review-checklists.md](./review-checklists.md)

This is a working contract for triage, not a historical snapshot.
