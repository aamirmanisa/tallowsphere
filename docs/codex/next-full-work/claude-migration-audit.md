# Claude Migration Audit

## Scope

This note closes the `.claude/` item in [docs/codex/next-full-checklist.md](~/Nixe/docs/codex/next-full-checklist.md) by auditing the currently tracked-dirty `.claude` files against the current Codex-first workspace setup documented in [docs/codex/workspace-optimization.md](~/Nixe/docs/codex/workspace-optimization.md).

Files read for this audit:

- `.claude/settings.json`
- `.claude/settings.local.json`
- `.claude/commands/baseline-ui.md`
- `.claude/commands/fixing-accessibility.md`
- `.claude/commands/fixing-motion-performance.md`
- `AGENTS.md`
- `.codex/config.toml`
- `docs/codex/ui-baseline.md`
- `docs/codex/accessibility.md`
- `docs/codex/motion-performance.md`
- `docs/codex/next-full-checklist.md`
- `docs/codex/workspace-optimization.md`

## Current Tracked-Dirty `.claude` Files

`git status --short -- .claude` currently shows five modified tracked files:

| File | Current dirty change | Compatibility value | Trim further? |
| --- | --- | --- | --- |
| `.claude/settings.json` | Adds a `migration` object declaring `codex-primary`, the Codex config path, and the root `AGENTS.md` path. | Low operational value, but useful as a human breadcrumb for anyone opening Claude settings first. No in-repo consumer was found for this metadata. | Optional. This is the safest file to simplify if the goal is only to reduce dirty state, but the change is already small and self-explanatory. |
| `.claude/settings.local.json` | Adds the same `migration` object and adds five Playwright MCP browser permissions to the allowlist. | High. This file is still an active Claude compatibility surface because it carries the command/tool allowlist, including many legacy `.claude/get-shit-done` entries and the new Playwright MCP entries. | Yes, but only through a separate allowlist-pruning pass. It should not be reduced blindly. |
| `.claude/commands/baseline-ui.md` | Adds a top note stating it is a legacy Claude command mirror and points users to `AGENTS.md` plus `docs/codex/ui-baseline.md`. | Medium. It preserves the Claude slash-command entrypoint while making Codex the primary instruction source. | Not yet. The mirror still contains substantially more detail than the short Codex doc. |
| `.claude/commands/fixing-accessibility.md` | Adds the same legacy-mirror note; the diff also normalizes the file ending newline. | Medium. Same compatibility role as above. | Not yet. Like the UI file, this mirror is more detailed than the Codex doc it points to. |
| `.claude/commands/fixing-motion-performance.md` | Adds the same legacy-mirror note. | Medium. Same compatibility role as above. | Not yet. The mirror still carries the detailed review rubric for Claude users. |

## What Still Matters For Compatibility

### 1. `settings.local.json` is still operational, not just documentary

This file is the strongest reason not to treat the current `.claude` state as a pure stub. Its diff is not limited to migration labeling:

- it still holds the large Claude allowlist that authorizes many workspace commands
- it still references the legacy `.claude/get-shit-done` toolchain
- it now also allows the Playwright MCP browser actions

That means this file is still part of the compatibility contract for anyone running Claude in this repo. Reducing it without checking actual Claude usage would risk breaking a real workflow.

### 2. The three command files are still useful mirrors

The command files are not empty placeholders. Each one still contains a full rule set for the slash-command it names. The new first-paragraph note only reframes them:

- Codex-primary guidance now lives in `AGENTS.md`, `.codex/config.toml`, and the short docs under `docs/codex/`
- Claude users still get a complete command payload if they invoke `/baseline-ui`, `/fixing-accessibility`, or `/fixing-motion-performance`

This matters because the corresponding Codex docs are much shorter summaries, not full reproductions of the command content. Converting these files into one-line redirects would reduce the information delivered to Claude command users.

### 3. `settings.json` is mostly a migration breadcrumb

Unlike `settings.local.json`, the dirty change in `settings.json` is explanatory only. It points readers to the Codex-native configuration and states that Claude settings are legacy reference material. That is helpful, but it does not appear to enable a unique workflow inside the repo.

## Should Anything Be Trimmed Further?

### Good trim candidate: `settings.local.json`, but only by auditing the allowlist

If the goal is to reduce tracked noise, the highest-value follow-up is not deleting the migration note. It is reviewing the accumulated allowlist in `.claude/settings.local.json` and splitting it into:

- permissions still needed for active Claude usage in this repo
- permissions kept only because they were historically accumulated
- permissions that now duplicate Codex/plugin-native workflows

That would reduce real compatibility debt instead of only shaving wording.

### Weak trim candidate: `settings.json`

This file can be reduced more easily because its dirty diff is only the `migration` block. The tradeoff is that the current block is already short and gives a clear, local explanation to anyone who opens the file. Trimming it further would reduce clarity more than it would reduce complexity.

### Poor trim candidate: the command mirrors

Further reducing the three command files is not recommended unless one of these is true:

- Claude slash-command compatibility is being intentionally deprecated
- the detailed guidance is moved somewhere Claude will still load directly
- the short docs under `docs/codex/` are expanded to parity with the current command content

Without one of those conditions, extra reduction turns the mirrors into misleading stubs.

## Recommendation

Keep the current migration-mirror approach for the three `.claude/commands/*` files and for the explanatory `migration` note in `.claude/settings.json`.

Do not reduce the `.claude` migration state further right now by collapsing everything into tiny stubs. The present state is a reasonable compromise:

- Codex is clearly primary through `AGENTS.md`, `.codex/config.toml`, and `docs/codex/*`
- Claude-facing files explicitly say they are legacy mirrors
- Claude command compatibility is still preserved

If a second cleanup pass is desired, target `.claude/settings.local.json` specifically. That is the one dirty file whose size and historical permissions create real maintenance weight. The right move there is a documented allowlist audit, not blanket deletion.

## Bottom Line

- Keep the current command-mirror approach.
- Keep the small `settings.json` migration breadcrumb.
- Do not shrink the command files into redirect-only stubs.
- Reduce further only if the next pass is a real `settings.local.json` compatibility audit.

## Changed Files

- `docs/codex/next-full-work/claude-migration-audit.md`
