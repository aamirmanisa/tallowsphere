# Search Chicken Root Asset Audit

Date: 2026-04-29
Scope: repository-root `search-chicken*` assets and tracked textual references to those exact filenames or repo-root paths.

## Root asset inventory

| File | Repo-root path | Tracked | Notes |
| --- | --- | --- | --- |
| `search-chicken.png` | `/search-chicken.png` | Yes | Root PNG asset, 911,298 bytes, last write 2026-04-18 15:46:30 -05:00. |
| `search-chicken-images.png` | `/search-chicken-images.png` | Yes | Root PNG asset, 286,632 bytes, last write 2026-04-10 19:27:56 -05:00. |
| `search-chicken-fixed.png` | `/search-chicken-fixed.png` | Yes | Root PNG asset, 551,112 bytes, last write 2026-04-10 19:32:17 -05:00. |
| `search-chicken-bottom.png` | `/search-chicken-bottom.png` | Yes | Root PNG asset, 262,949 bytes, last write 2026-04-10 19:28:09 -05:00. |

Tracking was verified with `git ls-files "search-chicken*"`.

## Tracked textual references

Searches run against tracked text:

- exact filenames: `search-chicken.png`, `search-chicken-images.png`, `search-chicken-fixed.png`, `search-chicken-bottom.png`
- repo-root style variants: `./search-chicken*.png` and `/search-chicken*.png`
- broader token check in likely documentation locations: `search-chicken`

Result: no tracked textual references were found for any of those filenames or path variants.

## Exact repo-root path requirement

No tracked textual references require these files to live at exact repo-root paths today.

That means there is no evidence in tracked source, docs, or config that `/search-chicken.png` is currently hard-coded or otherwise path-pinned.

## Recommendation on `search-chicken.png`

`search-chicken.png` does not need to remain at repo root for tracked-reference reasons.

Recommendation for now: leave it at repo root until the whole `search-chicken*` set is cleaned up together.

Reasoning:

- moving only `search-chicken.png` now would create an inconsistent partial cleanup because the related `search-chicken*` siblings are also still at the root
- there is no tracked-code pressure to move it immediately
- keeping the set unchanged avoids accidental disruption to any untracked local workflow, notes, or in-progress branch context that this audit cannot prove or disprove

## Conclusion

From the tracked-repository perspective, `search-chicken.png` is not required to stay at repo root. The conservative short-term choice is to keep it there for now and handle all `search-chicken*` root assets in one coordinated follow-up.

## Changed files

- `docs/codex/next-full-work/search-chicken-audit.md`