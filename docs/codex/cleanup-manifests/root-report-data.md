# Root Report/Data Cleanup Manifest

Audit date: 2026-04-29
Worker: cleanup worker 4 of 10
Scope: repo-root untracked report/data files whose basenames match `apollo_*`, `benchmark_*`, `cad_*`, `corpwiki_*`, `gasbuddy_*`, `harris_probe_*`, `site_profiles_*`, `tallow_max_*`, `top_200_*`, or `zacks_*`.

## Result

No current repo-root files matched both conditions:

- basename matched one of the assigned prefixes
- Git reported the file as untracked

Safe-to-move set for `artifacts/root-clutter/data`: none at the time of inspection.

## Notes

- A broader filename search found matching names under nested locations such as `scripts/`, `tallow-search/artifacts/`, and `tallow-search/docs/signoff/canonical_archive/`, but those are not repo-root files and are out of scope for this manifest.
- If new repo-root untracked report/data outputs appear later with these prefixes, they are reasonable relocation candidates for `artifacts/root-clutter/data` as long as they are not source files or intentionally versioned documentation.
