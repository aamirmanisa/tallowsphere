# Codex CLI Verification: `tallowsphere` and `tallowsphere/tallow`

## Scope

- Goal: verify, with the real `codex` CLI, which repo instruction files are active from:
  - `tallowsphere`
  - `tallowsphere/tallow`
- Constraint followed: did not modify any `AGENTS.md` file.
- Ownership followed: only this file was written.

## Environment

- Date: `2026-04-29` / `2026-04-30` during local session
- CLI: `codex-cli 0.122.0`
- Relevant repo files present:
  - `tallowsphere/AGENTS.md`
  - `tallowsphere/tallow/AGENTS.md`
  - `tallowsphere/.codex/config.toml`

## Summary

| Target cwd | Result | What was confirmed |
| --- | --- | --- |
| `tallowsphere` | PASS | Root session injected `tallowsphere/AGENTS.md` and did not inject `tallow\AGENTS.md`. |
| `tallowsphere/tallow` | PASS with caveat | Session injected both `tallowsphere/AGENTS.md` and `tallowsphere/tallow/AGENTS.md`; nested file was appended after root guidance. |

Nearest `AGENTS.md` winning behavior is supported by two things:

1. `codex exec` explicitly said the nearest `AGENTS.md` wins on conflicts.
2. `codex debug prompt-input` showed the `tallow` session receiving both files, with `tallow\AGENTS.md` appended after the root file.

Caveat: I did not create an artificial conflict in `AGENTS.md` files, so precedence was verified by actual prompt injection plus CLI self-report, not by a destructive conflict test.

## Exact Commands Attempted

### CLI discovery

```powershell
codex --version
codex --help
codex exec --help
codex debug --help
codex debug prompt-input --help
```

Important output:

- `codex --version` -> `codex-cli 0.122.0`
- `codex debug prompt-input` exists and is the best non-interactive way to inspect model-visible prompt input.

### Root verification: `tallowsphere`

```powershell
codex debug prompt-input "Show which instruction files are active." | rg -n "AGENTS|CLAUDE|codex|instruction|policy|rules"
```

Important output:

- Prompt input included a block starting with:

```text
26:        "text": "# AGENTS.md instructions for /mnt/Personal/Nixe
```

- That injected block contained the root `AGENTS.md` content.
- No nested `tallow\AGENTS.md` content appeared in the root session dump.
- No `CLAUDE.md` injection showed up in this filtered output.

```powershell
codex exec --sandbox read-only --color never "Show which instruction files are active. Include exact paths if you know them, and state whether the nearest AGENTS.md wins over broader workspace guidance."
```

Important output:

```text
Active instruction context right now is:

- System/developer-level runtime instructions (from this Codex session; not files in your repo).
- Workspace `AGENTS.md` for current directory: [AGENTS.md](../../AGENTS.md)
...
Yes: the nearest `AGENTS.md` in the directory you’re working in wins over broader workspace guidance
```

This run completed, but stdout/stderr was noisy. See "Surprises / blockers" below.

```powershell
codex exec --sandbox read-only --color never "Show which instruction files are active. Include exact paths if you know them, and state whether the nearest AGENTS.md wins over broader workspace guidance." 2>$null
```

Important output:

```text
Active instruction sources for this session:

1. Highest priority (not file-based in repo): system + developer instructions from the harness.
2. Repo instruction file currently active at your cwd: [`AGENTS.md`](../../AGENTS.md).
...
Yes: nearest `AGENTS.md` wins over broader workspace guidance for files in its subtree.
```

Verdict for `tallowsphere`: PASS.

### `tallow` verification: `tallowsphere/tallow`

```powershell
codex debug prompt-input "Show which instruction files are active." | rg -n "AGENTS|CLAUDE|codex|instruction|policy|rules"
```

Important output:

- Prompt input included a block starting with:

```text
26:        "text": "# AGENTS.md instructions for /mnt/Personal/Nixe\\tallow
```

- Inside that single injected block, the CLI included:
  - the full root `tallowsphere/AGENTS.md`
  - then the full nested `tallowsphere/tallow/AGENTS.md`

This is the strongest direct evidence that both files are active for `tallow`, with the nested file layered after root guidance.

```powershell
codex exec --sandbox read-only --color never "Show which instruction files are active. Include exact paths if you know them, and state whether the nearest AGENTS.md wins over broader workspace guidance."
```

Important output:

```text
Active instruction sources for this session are:

1. `tallowsphere/AGENTS.md` (workspace-level guidance)
2. `tallowsphere/tallow/AGENTS.md` (repo/subproject-level guidance, nearest to current cwd)
...
For precedence: yes, the nearest `AGENTS.md` wins on conflicts.
```

This run completed successfully, but it also emitted a large amount of stderr noise.

```powershell
codex exec --sandbox read-only --color never "Show which instruction files are active. Include exact paths if you know them, and state whether the nearest AGENTS.md wins over broader workspace guidance." 2>$null
```

Result:

- Aborted by user before completion.
- I did not retry after the user requested that I stop forcing long-running CLI prompts.

Verdict for `tallowsphere/tallow`: PASS with caveat.

The caveat is only that the final "quiet" rerun was aborted; the earlier `debug prompt-input` and `exec` runs already produced the needed evidence.

## Surprises / Blockers

These did not fully block verification, but they made the CLI runs noisy and slower than they should be:

1. `codex exec` emitted repeated warnings about malformed user-level agent role TOML files under `C:\Users\operator\.codex\agents\...`.
2. Plugin sync and analytics calls produced repeated `403 Forbidden` HTML noise from `chatgpt.com`.
3. One `codex exec` run invoked broad search behavior and printed many `rg: Access is denied` errors against temp/cache paths.
4. PowerShell constrained-language/profile warnings appeared in the noisy runs:
   - `Cannot dot-source this command because it was defined in a different language mode`
   - `Property setting is supported only on core types in this language mode`
5. `codex debug prompt-input` was slow, but it was the most trustworthy signal because it exposed the model-visible prompt payload directly.

## Root Cause Assessment

- Auth: not the primary blocker. The CLI did return usable answers.
- Interactivity: avoided by using `codex exec` and `codex debug prompt-input` instead of the interactive TUI flow.
- Long-running prompt / environment noise: the main practical blocker.

The main root cause of friction was a noisy local Codex environment, not missing repo instructions:

- malformed user-level agent role files
- plugin sync / analytics failures
- broad agent-side search behavior in one run

## Final Finding

- From `tallowsphere`, the active repo instruction file was `tallowsphere/AGENTS.md`.
- From `tallowsphere/tallow`, the active repo instruction files were:
  - `tallowsphere/AGENTS.md`
  - `tallowsphere/tallow/AGENTS.md`
- The nearest `AGENTS.md` appears to win, while broader root guidance still remains active when non-conflicting.

