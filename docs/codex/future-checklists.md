# Future Checklists

These are the follow-on checklists after [next-full-checklist.md](./next-full-checklist.md). They are intentionally sequenced so Codex work stays narrow and reviewable.

## Checklist B: Artifact Governance And Repository Shape

Run this after the next full checklist if the workspace still suffers from tracked artifact noise.

### Goal

Move from ad hoc cleanup to a durable artifact governance model.

- [ ] Create a single tracked artifact policy covering repo-root assets, `artifacts/`, `tmp/`, and evidence folders
- [ ] Decide whether large tracked screenshots and export files should live under `docs/reference-assets/`, a product-specific `evidence/` tree, or outside the repo entirely
- [ ] Standardize naming rules for retained screenshots, JSON exports, SQL exports, and signoff evidence
- [ ] Add path-specific docs for any artifact bucket that must remain committed
- [ ] Remove duplicate or obsolete retained artifacts once the destination policy is in place
- [ ] Re-run the root-clutter verification and update the cleanup summary

## Checklist C: Codex Automation And Session Bootstrap

Run this after the artifact policy is stable.

### Goal

Reduce manual setup for future Codex sessions.

- [ ] Add a small bootstrap doc for common working directories and the commands to start there
- [ ] Add a root command wrapper for instruction verification
- [ ] Add a root command wrapper for narrow verification by subproject
- [ ] Add a root command wrapper for scoped cleanup/status inspection
- [ ] Document which wrappers are safe in a dirty worktree and which require human review
- [ ] Keep wrappers composable instead of building one giant script

## Checklist D: Subproject Hardening

Run this after the automation layer exists.

### Goal

Make the busiest products easier for Codex to work on safely.

- [ ] Add deeper local guidance only in the directories that repeatedly need it
- [ ] For `hackthecart`, document the narrowest trustworthy loops for API, import, data-quality, and search-index work
- [ ] For `tallow-search`, document the narrowest trustworthy loops for API, web, and extension work
- [ ] For root Tallow/compiler work, document the benchmark and regression-test rules closest to the actual hot paths
- [ ] Add "do not touch casually" lists to any subproject that still has vendor-like or evidence-heavy directories
- [ ] Verify that new local guidance does not conflict with the root `AGENTS.md`

## Checklist E: Ongoing Maintenance

Run this as a repeating hygiene checklist once the workspace policy stabilizes.

### Goal

Keep the workspace Codex-friendly without turning maintenance into a project of its own.

- [ ] Re-run instruction-chain verification after major `AGENTS` or `.codex/config.toml` changes
- [ ] Re-run root clutter counts after any large scraping, import, or browser-test wave
- [ ] Review `/.playwright-mcp/`, `/artifacts/`, and `/tmp/` growth periodically so ignored buckets do not become invisible landfills
- [ ] Review whether new subprojects need local overrides before instructions sprawl at the root
- [ ] Retire stale docs when their guidance becomes redundant or false
- [ ] Keep checklist docs current so Codex sessions can pick up from the actual present state

## Sequence

1. [next-full-checklist.md](./next-full-checklist.md)
2. Checklist B: Artifact governance and repository shape
3. Checklist C: Codex automation and session bootstrap
4. Checklist D: Subproject hardening
5. Checklist E: Ongoing maintenance
