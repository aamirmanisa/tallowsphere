# `.playwright-mcp` inventory

Inventory date: 2026-04-29
Scope: `E:\Nixe\.playwright-mcp` only

## Top-level shape

- Flat artifact bucket with `640` top-level files and `0` subdirectories.
- Naming is timestamped and mostly split across two prefixes:
  - `page-*`: `509` files
  - `console-*`: `131` files
- On-disk size is about `17.62 MiB`.

## Git visibility

These counts were derived with narrow `git ls-files` calls scoped to `.playwright-mcp`.

- Tracked files: `243`
- Untracked, non-ignored files: `0`
- Ignored files: `397`
- Total files currently present: `640`

Interpretation: the directory is already partly treated as disposable output. The ignored portion is larger than the tracked portion, and there are no currently visible untracked files outside ignore rules.

## Obvious content classes

File extensions in the current bucket:

- `.yml`: `408`
- `.log`: `131`
- `.png`: `87`
- `.jpeg`: `14`

Representative content patterns from sampled files:

- `console-*.log` files contain browser console output captured during Playwright MCP activity.
- `page-*.yml` files contain structured page snapshots or accessibility/tree-like state dumps.
- `.png` and `.jpeg` files appear to be visual captures associated with runs.

Overall, this looks like a run-artifact evidence store: console traces, page state snapshots, and screenshots keyed by timestamps.

## Evidence value

This bucket appears to have real evidence value for debugging, reproducing MCP/browser behavior, and preserving snapshots of what a run saw at a point in time.

That said, the contents are generated artifacts rather than source inputs. The flat timestamped layout and the volume split between tracked and ignored files suggest ongoing output accumulation rather than a carefully curated long-term record.

## Recommendation

Recommended disposition: `keep but ignore future outputs`

Why this option fits best:

- The existing tracked subset may represent intentionally preserved evidence and should not be removed casually.
- The directory clearly contains useful debugging artifacts, so wholesale cleanup is too aggressive without review.
- The large ignored share already indicates the repo is moving toward treating fresh outputs as ephemeral.

Why not the other two:

- `keep tracked`: too weak, because the current bucket behavior already shows that future generated output should not keep expanding as repository content.
- `separate reviewed cleanup/removal`: plausible later, but it needs a deliberate review of which tracked artifacts still have historical value before anything is removed.
