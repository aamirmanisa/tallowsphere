# Package/Bootstrap Manifest Audit

Scope: `package.json` / `package-lock.json` at repo root, plus `tallow/web` and `tallow-search/web` package manifests for the next-full checklist item about keeping the workspace bootstrap story coherent.

## Current tracked-dirty manifests in scope

| Path | Dirty | Observed drift | Bootstrap/Codex relevance | Assessment |
| --- | --- | --- | --- | --- |
| `package.json` | Yes | Adds `socks-proxy-agent` alongside existing root tooling deps (`playwright`, `playwright-core`, `ssh2`, `ws`) | High | Looks related to workspace/session tooling rather than product code. This fits a Codex/bootstrap bucket if the root manifest is meant to provide shared browser or network helper dependencies. |
| `package-lock.json` | Yes | Lockfile update for `socks-proxy-agent` and its transitive deps | High | Same classification as root `package.json`. This is bootstrap/tooling drift paired with the root dependency change, not ordinary app work. |
| `tallow/web/package.json` | Yes | Adds scripts: `check`, `lint`, `test`, `ci`; no dependency changes | Medium | Looks like local workflow/bootstrap hardening for the web app, not product feature drift. It helps repeatable project setup, but it is subproject-local rather than workspace-root bootstrap. |
| `tallow-search/web/package.json` | Yes | Adds `check` script, `@astrojs/check`, `typescript`, and runtime dep `leaflet` | Mixed | The script and devDependency additions look like local bootstrap/verification work. `leaflet` looks like ordinary product feature work. This manifest is not cleanly "Codex migration only." |
| `tallow-search/web/package-lock.json` | Yes | Lockfile update covering `@astrojs/check`, `typescript`, `leaflet`, and transitive deps | Mixed | Mirrors the mixed state in `tallow-search/web/package.json`: part bootstrap/verification, part product dependency drift. |

## Relevant manifests that are not currently dirty

- `tallow/web/package-lock.json` is clean, so there is no tracked lockfile drift there at the moment.

## Interpretation

The current dirty set splits into two different stories:

1. Root manifest drift:
   This looks like shared tooling/bootstrap work. The root manifest is carrying session-level packages, and `socks-proxy-agent` is consistent with that role.

2. Subproject manifest drift:
   This is not one unified bootstrap story. `tallow/web/package.json` looks like local workflow standardization, while `tallow-search/web` mixes workflow improvements with a real application dependency addition.

That means the workspace currently has bootstrap-related manifest drift, but only part of the dirty state belongs to Codex migration/bootstrap. The `tallow-search/web` changes especially should not be described as purely migration-driven.

## Recommendations for a coherent bootstrap story

1. Treat the root `package.json` / `package-lock.json` as the workspace bootstrap contract only.
   If a dependency exists there, its purpose should be shared session tooling, not product runtime behavior.

2. Keep subproject bootstrap concerns inside the subproject manifests.
   App-local scripts like `check`, `lint`, `test`, and Astro verification dependencies belong with `tallow/web` or `tallow-search/web`, not at the root.

3. Separate workflow/bootstrap edits from product dependency edits when possible.
   `tallow-search/web` currently mixes verification improvements with `leaflet`. If reviewed later, it would be cleaner to describe that as mixed drift or split it into distinct changes.

4. Standardize a minimal web-app script baseline across Astro subprojects.
   If Codex needs repeatable commands, the useful shared convention is script naming (`build`, `check`, `test`, `ci`), not shared dependency hoisting into the root manifest.

5. Document the bootstrap matrix in the future checklist C bootstrap doc.
   A small table should map working directory to install and verification commands, for example:
   - root: shared tooling install only
   - `tallow/web`: app install plus Astro build/check loop
   - `tallow-search/web`: app install plus Astro check/build loop

## Bottom line

The root manifest drift looks aligned with Codex/session bootstrap. `tallow/web/package.json` looks like local verification/bootstrap hardening. `tallow-search/web/package.json` and `tallow-search/web/package-lock.json` are mixed: partly bootstrap, partly unrelated product work. Any "workspace bootstrap" narrative should keep those buckets separate instead of treating all dirty package manifests as one migration change.
