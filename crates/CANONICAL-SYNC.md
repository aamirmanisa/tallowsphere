# CANONICAL-SYNC — vendored canonical crates: pin manifest

**Companion:** `CANONICAL-SYNC.sha256` (machine-checkable, this directory).

**Provenance.** The four crates `tallow-crypto`, `tallow-net`, `tallow-protocol` and `tallow-svid`
are authored **here, in Tallowsphere** (the Tallow language/runtime repository), and are **vendored
into sendtallow** so that product can build and test standalone (CI, containers, contributors). This
repository is canonical: edits land here first, the product syncs second. The product carries the
same manifest and verifies its copies against it, so a `FAILED` line in either repository is the
drift signal.

The repositories are named, never pathed. sendtallow's remote is expected to move; a manifest that
hard-codes a clone location turns a repository rename into a false drift report.

**Pinned:** 198 files. Last regenerated 2026-10-15 by `scripts/gen-canonical-pins.sh`.

## Verify

```bash
cd crates && sha256sum -c CANONICAL-SYNC.sha256
```

Any `FAILED` line is drift. So is a file that exists here and not there — `sha256sum -c` cannot see
absent files, so compare directory listings as well. The check runs in CI as the `canonical-pins`
gate; a change to a vendored file lands with a regenerated manifest or it fails.

## Regenerate

```bash
scripts/gen-canonical-pins.sh                                  # rewrites crates/CANONICAL-SYNC.sha256
cd crates && sha256sum -c CANONICAL-SYNC.sha256               # must be clean
```

Excluded by policy, because a pin is only meaningful for sources:

| excluded | why |
|---|---|
| `target/`, `.git/` | build output and VCS metadata |
| `fuzz/corpus/`, `fuzz/artifacts/` | per-repo fuzz inputs; they reproduce differently in each repository |
| per-crate `Cargo.lock` | standalone per-crate locks; the product builds against its own workspace lock |
| `*.cdx.json`, `*.sbom.json` | **generated** SBOM artifacts, not sources |

The last row is not cosmetic. Pinning generated artifacts was the bulk of the previous manifest's
failures: a pin that tracks a build output reports drift whenever anything is rebuilt.

## Policy

1. Canonical edits land in Tallowsphere first; sendtallow syncs second.
2. Every edit to a vendored file is followed by: re-sync → `sha256sum -c` in both repositories →
   regenerate the manifest → copy it into both `crates/` directories. The two copies of the manifest
   and this file must stay byte-identical, so their own equality is a second check on the pin set.
3. A file present in one repository only is drift even though `sha256sum -c` cannot see it.
4. The long-term fix for this class is to stop vendoring and depend on the canonical crates directly.
   Until then this manifest is the tripwire — and it is only a tripwire while it is green.

## History

The previous manifest (generated 2026-09-21) had drifted far enough that it no longer verified in the
tree it shipped in: **9 checksum mismatches, 6 unreadable entries, 1 malformed line**, and a header
claiming 185 pinned files while the list held 170. It also carried a second copy of the entire hash
list in an appendix — one more thing that can disagree with the manifest. That appendix is gone; the
manifest is the single list, and it verifies.
