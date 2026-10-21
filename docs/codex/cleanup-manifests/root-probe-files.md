# Root `probe_*` Files Manifest

## Scope

This manifest covers only root-level files in `tallowsphere` matching `probe_*`.
It does not assess similarly named directories such as `probe_browser_*`.

## Status Basis

- `git status --short --ignored=matching -- 'probe_*'` reports all three files as `!!` (ignored, not tracked).
- [`.gitignore`](../../../.gitignore) contains `/probe_*`, so these files are intentionally excluded from version control.
- `git grep` across tracked files found no references to `probe_0.txt`, `probe_1.txt`, or `probe_2.txt`.

## Findings

| File | Size (bytes) | SHA-256 | Content summary | Safe to move? | Suggested destination |
| --- | ---: | --- | --- | --- | --- |
| `probe_0.txt` | 2662 | `5B3CE0C859E06528C369392939F844E29178C4AE43D71E25D4FDD0307B7E376C` | Saved HTML for an IIS-style `404 - File or directory not found` response, including Cloudflare instrumentation script. | Yes. This is an external response capture, not source input or code. | `artifacts/root-clutter/probe-files/probe_0.txt` |
| `probe_1.txt` | 83 | `E76FC386DAE863467DB0164E0A555EC35F90E25045CFE746FFC1B83A1D133D8C` | Saved JSON error payload: invalid OpenCorporates API token. | Yes. This is a transient probe result containing a failed API response, not a project asset. | `artifacts/root-clutter/probe-files/probe_1.txt` |
| `probe_2.txt` | 3914 | `0F50045598441D5EF3866CCAE8A6A06EDDBED722EA0FB3BE112AD13C74850CE9` | Saved JSON geocoding response from OpenStreetMap/Nominatim for "East Grand Parkway South" in Baytown, Texas. | Yes. This is a one-off lookup artifact, not a canonical fixture or tracked dataset. | `artifacts/root-clutter/probe-files/probe_2.txt` |

## Recommendation

All three root-level `probe_*.txt` files are safe to move under `artifacts/root-clutter/probe-files/` while preserving filenames.

Rationale:

- They are already ignored by the repo.
- They are not referenced by tracked files.
- Their contents are ad hoc HTTP/API probe outputs rather than maintained source, docs, tests, or fixtures.
