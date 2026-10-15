# Playwright MCP Policy

Audit date: 2026-04-29

This policy resolves the `/.playwright-mcp/` decision work in [next-full-checklist.md](./next-full-checklist.md).

## Current State

- total files on disk: `640`
- tracked files: `243`
- ignored files: `397`
- non-ignored untracked files: `0`

Observed content classes:

- `page-*.yml`: page snapshots / structured state captures
- `console-*.log`: browser console captures
- `.png` and `.jpeg`: visual captures

This bucket has evidence value, but it is generated run output rather than source input.

## Policy Decision

Use `keep tracked historical evidence, ignore future output`.

That means:

1. Keep the current tracked subset in place for now.
2. Keep the root ignore rule so new generated MCP captures stay local-only.
3. Do not let fresh output accumulate as new tracked content by default.
4. Handle any removal or relocation of the tracked historical subset in a separate reviewed cleanup change.

## Why

- the tracked subset may still be useful as historical debugging evidence
- the ignored subset is already larger than the tracked subset, so the workspace is effectively treating fresh output as disposable now
- a broad removal now would mix evidence cleanup with policy work and increase review risk

## Operating Convention

- Do not manually add new `/.playwright-mcp/` captures to Git unless a task explicitly calls for preserving a specific artifact.
- If a specific capture needs to be kept as documentation, move or copy that curated asset into a tracked reference-assets location instead of expanding the `.playwright-mcp/` archive.
- Treat `.playwright-mcp/` as a run-artifact bucket, not as a normal source directory.

## Deferred Cleanup

If the tracked historical subset is later reviewed and found unnecessary, do that in a dedicated cleanup change with:

1. an explicit inventory
2. a keep/remove decision for curated historical captures
3. path-scoped review and verification
