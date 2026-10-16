# Noise Inventory

Audit date: 2026-04-29

Scope: practical search/context noise in the `Nixe` workspace. This is an inventory and recommendation set only; nothing here deletes or moves files.

## Quick Findings

- Existing ignore coverage is already good for common build output such as `target/`, `dist/`, `node_modules/`, `crates/*/target/`, and the `apps/tallowsync` build directories.
- The highest root-level noise that is still visible to Git/Codex is concentrated in a few buckets:
  - `/.playwright-mcp/`: 243 tracked capture files plus 266 newer untracked captures, mostly `.yml`, `.log`, `.png`, and `.jpeg`.
  - `/probe_*`: 35 probe directories plus 3 probe files at repo root.
  - `/tmp/` plus many root `tmp_*` outputs: 138 root files and 7 root directories with mixed JSON, HTML, CSV, log, SQL, shell, and temporary source fragments.
  - `/artifacts/`: an untracked run-output bucket with subtrees such as `bench/`, `integration/`, `runtime-probes/`, `phase*_evidence/`, `scraper_runs/`, and nested `tmp/`.
  - `/.kilo/`: mixed-content directory. `node_modules/` is already locally ignored, but `kilo.json`, `package.json`, and `skills/` look intentional and should not be blanket-ignored.

## Keep Committed

These paths may look noisy at a glance, but they should stay reviewable or versionable instead of being blanket-ignored.

| Path | Recommendation | Why |
| --- | --- | --- |
| `/.kilo/kilo.json` | Keep reviewable | Local tool configuration, not generated output. |
| `/.kilo/package.json` | Keep reviewable | Dependency manifest, not cache output. |
| `/.kilo/skills/` | Keep reviewable | Skill content is source-like workspace customization. |
| `firecrawl-self-hosted/` and other vendored project roots | Do not add broad ignore rules | Large, but not generated-noise by default; targeted ignores are safer than hiding whole project trees. |

## Candidate For Ignore

These are strong future-only ignore candidates because they are clearly generated or transient.

| Path or Pattern | Recommendation | Why |
| --- | --- | --- |
| `/.playwright-mcp/` | Ignore future captures | The directory is dominated by browser snapshots/capture artifacts. It is already producing new untracked noise. |
| `/artifacts/` | Ignore the bucket | Contents are run output, evidence, probes, and scratch files rather than source. |
| `/probe_*` | Ignore | Root probe directories/files are transient debugging output and add a lot of search noise. |
| `/tmp/` | Ignore | Root temp bucket currently contains caches, pytest temp state, and analysis output. |

## Candidate To Relocate

These should move into a smaller number of known buckets so they stop polluting the repo root and global search scope.

| Path or Pattern | Preferred Destination | Why |
| --- | --- | --- |
| Root `tmp_*` files and `tmp_*` directories | `/tmp/` or `/artifacts/` | They currently scatter temporary HTML/JSON/CSV/log/source fragments across the repo root. |
| Current committed `/.playwright-mcp/` archive | An ignored artifact bucket or external temp storage | Even with a future ignore rule, the existing committed archive still adds search/context noise until it is moved in a separate cleanup change. |
| Root `probe_*` trees | `/artifacts/probes/` or system temp | Root-level probe directories are hard to filter out mentally and mechanically. |
| `artifacts/tmp/` plus root `/tmp/` | One standardized temp bucket | There are currently multiple temp conventions for similar scratch output. |

## Notes

- The safest next cleanup policy is to keep generated output under a few agreed roots, then ignore those roots at the repo root.
- I did not recommend blanket ignores for `/.kilo/` or global `**/tmp*` patterns because they would hide mixed-content or source-like files.
