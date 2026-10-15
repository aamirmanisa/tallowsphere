# Codex Instruction Chain Verification: `tallow-search` and Firecrawl API

Verified on 2026-04-29 from `E:\Nixe` with `codex-cli 0.122.0`.

Scope note: this verification covered Codex instruction resolution only. No product build or test commands were run.

## Summary

- `E:\Nixe\tallow-search`: PASS. Active files were `E:\Nixe\AGENTS.md` and `E:\Nixe\tallow-search\AGENTS.md`. The nearer `tallow-search\AGENTS.md` won on conflict.
- `E:\Nixe\firecrawl-self-hosted\apps\api`: PASS. Active files were `E:\Nixe\firecrawl-self-hosted\AGENTS.md` and `E:\Nixe\firecrawl-self-hosted\apps\api\AGENTS.override.md`. The nearer `AGENTS.override.md` won on conflict.
- Important surprise: `E:\Nixe\AGENTS.md` was not loaded for `firecrawl-self-hosted\apps\api` because that subtree is its own Git repo rooted at `/mnt/Personal/Nixe/firecrawl-self-hosted`.
- No auth blocker occurred. The only real blocker was that the first `codex debug prompt-input ...` attempts exceeded a 30 second shell timeout before returning their large JSON payloads.

## Commands Used

```powershell
codex --version

cd E:\Nixe\tallow-search
git rev-parse --show-toplevel
codex debug prompt-input 'Report the active instruction files and precedence.'
codex exec -s read-only --skip-git-repo-check --color never "List the loaded AGENTS or AGENTS.override instruction files for this session and state which one has highest precedence if they conflict. Answer in exactly 3 bullets."

cd E:\Nixe
rg --files -uu -g 'AGENTS.md' -g 'AGENTS.override' firecrawl-self-hosted/apps/api firecrawl-self-hosted
Get-ChildItem -Force 'firecrawl-self-hosted/apps/api'

cd E:\Nixe\firecrawl-self-hosted\apps\api
git rev-parse --show-toplevel
codex debug prompt-input 'Report the active instruction files and precedence.'
codex exec -s read-only --skip-git-repo-check --color never "List the loaded AGENTS or AGENTS.override instruction files for this session and state which one has highest precedence if they conflict. Answer in exactly 3 bullets."
```

## Failed First Attempts

- First attempt in `E:\Nixe\tallow-search`:
  - command: `codex debug prompt-input 'Report the active instruction files and precedence.'`
  - result: FAIL on the first try
  - important output: `command timed out after 34065 milliseconds`
- First attempt in `E:\Nixe\firecrawl-self-hosted\apps\api`:
  - command: `codex debug prompt-input 'Report the active instruction files and precedence.'`
  - result: FAIL on the first try
  - important output: `command timed out after 34066 milliseconds`
- Root cause:
  - not auth
  - not an interactive prompt requirement
  - the command needed roughly 57 to 59 seconds when retried, because `prompt-input` emitted a large JSON payload for the full instruction chain

## `tallow-search`

### Result

- PASS

### Important output

- `git rev-parse --show-toplevel` returned `/mnt/Personal/Nixe`.
- `codex debug prompt-input 'Report the active instruction files and precedence.'` produced one user instruction block for `E:\Nixe\tallow-search` that contained:
  - the workspace file `E:\Nixe\AGENTS.md`
  - then the project file `E:\Nixe\tallow-search\AGENTS.md`
- `codex exec ...` returned:

```text
- Loaded instruction file: `E:\Nixe\AGENTS.md` (workspace-level guidance for the multi-project repo).
- Loaded instruction file: `E:\Nixe\tallow-search\AGENTS.md` (project-level guidance specific to `tallow-search/`).
- Highest precedence on conflict: `E:\Nixe\tallow-search\AGENTS.md` (the more specific, deeper-scope file overrides the parent workspace file).
```

### Conclusion

- Active instruction chain was `E:\Nixe\AGENTS.md` -> `E:\Nixe\tallow-search\AGENTS.md`.
- The nearest `AGENTS.md` won.

## `firecrawl-self-hosted\apps\api`

### Result

- PASS

### Important output

- `rg --files -uu -g 'AGENTS.md' -g 'AGENTS.override' firecrawl-self-hosted/apps/api firecrawl-self-hosted` returned only `firecrawl-self-hosted\AGENTS.md`.
- `Get-ChildItem -Force 'firecrawl-self-hosted/apps/api'` showed the local file is actually named `AGENTS.override.md`.
- `git rev-parse --show-toplevel` returned `/mnt/Personal/Nixe/firecrawl-self-hosted`.
- `codex debug prompt-input 'Report the active instruction files and precedence.'` produced one user instruction block for `E:\Nixe\firecrawl-self-hosted\apps\api` that contained:
  - `E:\Nixe\firecrawl-self-hosted\AGENTS.md`
  - then `E:\Nixe\firecrawl-self-hosted\apps\api\AGENTS.override.md`
- `codex exec ...` returned:

```text
- `E:\Nixe\firecrawl-self-hosted\AGENTS.md` (Firecrawl monorepo-wide subtree instructions).
- `E:\Nixe\firecrawl-self-hosted\apps\api\AGENTS.override.md` (local API/worker workflow and test rules).
- If they conflict, `AGENTS.override.md` has highest precedence within `apps/api` scope.
```

### Conclusion

- Active instruction chain was `E:\Nixe\firecrawl-self-hosted\AGENTS.md` -> `E:\Nixe\firecrawl-self-hosted\apps\api\AGENTS.override.md`.
- The nearest override file won.
- `E:\Nixe\AGENTS.md` was not part of the chain for this target because Codex treated `/mnt/Personal/Nixe/firecrawl-self-hosted` as the Git root.

## Surprises

- The Firecrawl API override file is `AGENTS.override.md`, not `AGENTS.override`.
- The nested Firecrawl repo prevented the outer workspace `E:\Nixe\AGENTS.md` from being loaded there.
- Both `codex exec` runs exited `0`, but stderr was noisy:
  - malformed local agent-role TOML files under `C:\Users\operator\.codex\agents\`
  - plugin sync and analytics `403 Forbidden` HTML from `chatgpt.com`
  - a `Reading additional input from stdin...` line even though the prompt was supplied directly
- That noise did not change the loaded instruction files or the final precedence answer.
