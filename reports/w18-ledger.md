# ledger — W18: post-publication release verification, as a command

Tree: `/home/aamir/tallow-worktrees/w18/ledger`, branch `rel/w18-ledger`,
cut from tallowsphere `6aeea5a` (tag `v1.7.0`).

Added: `scripts/verify_release_assets.sh` and this report. Nothing else in the
tree changed.
The script is read-only against GitHub: GETs only, no publish, no edit, no
delete, no re-tag, and no upload. It exits non-zero on any failed check and
prints every check it performed.

    scripts/verify_release_assets.sh [--lax-revision] [TAG] [PLATFORM]

    TAG       default: the newest release the API returns
    PLATFORM  default: this host's platform
              (linux-aarch64 | linux-x86_64 | macos-aarch64 | macos-x86_64 |
               windows-x86_64)

Exit status: 0 all checks passed, 1 a check failed, 2 bad usage, 3 the archive
hash verified but the binary could not be executed on this host.

## What it checks, and how

1. **Release metadata.** `GET /repos/aamirmanisa/tallowsphere/releases/tags/<tag>`
   with the token from `/root/.gh-token-tallow`. Fails on 404 (no release),
   on `draft: true`, on fewer than five assets, and on any of the five shipped
   platforms lacking an archive, a `.sha256` sidecar or a `.sig`. That last
   check is the *published* form of the workflow's own "verify every archive has
   a checksum and a signature" step — it asks the release, not the run log.
2. **Download and hash.** The chosen platform's archive is fetched through the
   asset API with `Accept: application/octet-stream` (a private repo's
   `browser_download_url` is not directly fetchable), and hashed with
   `hashlib.sha256` in 1 MiB chunks. Three things are compared: the digest
   against the published sidecar, the sidecar's own filename field against the
   file it claims to describe, and the byte count against the release
   metadata's `size`.
3. **Extract and exercise.** The binary is written out of the archive through
   `tarfile`/`zipfile` by member name — not unpacked by a shell utility, so
   there is no path-traversal surface and no `tar`/`unzip` dependency — then
   run as `--version`. Required: the version equals the tag (`v` stripped; the
   release gate's `1.5.8.0`-style form is also accepted), `git:` is present, is
   hex, is not `unknown`, does not contain `dirty`, and is a prefix of the
   commit the tag itself resolves to (annotated tags are dereferenced through
   `/git/tags/<sha>`).
4. **Inventory.** Asset count and every asset name with its byte size, plus the
   total.

Only `curl` and `python3` are used — no `gh`, no `jq`, no `sha256sum`, no
`tar`/`unzip`. That is deliberate: the machine that most needs to verify a
release is the one where the release tooling is missing.

## Test 1 — v1.5.8 on the host platform, required checks

Run: `./scripts/verify_release_assets.sh --lax-revision v1.5.8`
(host: Linux aarch64 → `linux-aarch64`). Exit 0.

```
verify_release_assets: repo=aamirmanisa/tallowsphere platform=linux-aarch64 tag=v1.5.8
host: Linux aarch64

== 1. release metadata
  ok    GET /releases/tags/v1.5.8 -> 200
  ok    tag_name=v1.5.8  published_at=2026-10-26T02:26:28Z  prerelease=false
  ok    release is published (not a draft)
        assets on the release: 15
  ok    asset count 15 >= 5
  ok    all five platforms ship archive + .sha256 + .sig

== 2. download + sha256 (linux-aarch64)
        archive: tallow-linux-aarch64-1.5.8.tar.gz (174378929 bytes)
        sha256 sidecar: tallow-linux-aarch64-1.5.8.tar.gz.sha256
  ok    downloaded tallow-linux-aarch64-1.5.8.tar.gz.sha256 (HTTP 200)
  ok    downloaded tallow-linux-aarch64-1.5.8.tar.gz (HTTP 200)
  size 174378929
  want a9739bb4c158637570241cd7f7d0aa84cf49777b8d2ab8bcb9421868e6b2459c
  got  a9739bb4c158637570241cd7f7d0aa84cf49777b8d2ab8bcb9421868e6b2459c
  ok    sha256 matches the published sidecar
  ok    size matches release metadata (174378929 bytes)

== 3. extract + --version
  ok    extracted tallow (48124352 bytes)
        | tallow 1.5.8
        |   platform: linux
        |   arch: aarch64
        |   build: 2026-10-26T02:01:30Z
        |   git: 6aa9fcfb14

== 3a. version equals the tag
  ok    binary version 1.5.8 == tag v1.5.8

== 3b. git: names a real revision
  ok    git: 6aa9fcfb14 (clean, 10 hex chars)

== 3c. git: is the tag's commit
        annotated tag object f5377b66dffba7ac1fe5d373fc2d1e85b8443b9e -> commit 3f11dc06c4974584d3e1a53cc560dec3c8361169
  WARN  binary revision 6aa9fcfb14 is NOT the tag commit 3f11dc06c4974584d3e1a53cc560dec3c8361169 (--lax-revision: not fatal)
        the artifact was built from a different commit than v1.5.8 names

== 4. asset inventory (aamirmanisa/tallowsphere @ v1.5.8)
         bytes  asset
     174378929  tallow-linux-aarch64-1.5.8.tar.gz
           100  tallow-linux-aarch64-1.5.8.tar.gz.sha256
            96  tallow-linux-aarch64-1.5.8.tar.gz.sig
     176941483  tallow-linux-x86_64-1.5.8.tar.gz
            99  tallow-linux-x86_64-1.5.8.tar.gz.sha256
            96  tallow-linux-x86_64-1.5.8.tar.gz.sig
     163853802  tallow-macos-aarch64-1.5.8.tar.gz
           100  tallow-macos-aarch64-1.5.8.tar.gz.sha256
            96  tallow-macos-aarch64-1.5.8.tar.gz.sig
     167070267  tallow-macos-x86_64-1.5.8.tar.gz
            99  tallow-macos-x86_64-1.5.8.tar.gz.sha256
            96  tallow-macos-x86_64-1.5.8.tar.gz.sig
     160018249  tallow-windows-x86_64-1.5.8.zip
            98  tallow-windows-x86_64-1.5.8.zip.sha256
            96  tallow-windows-x86_64-1.5.8.zip.sig
     842263706  15 asset(s)
  ok    reported 15 asset(s)

PASS with 1 warning(s): aamirmanisa/tallowsphere @ v1.5.8 — archive verified end-to-end on linux-aarch64
```

## Test 2 — the same run with the revision check strict (the default)

`./scripts/verify_release_assets.sh v1.5.8` — exit 1, and the steps before it
are identical to Test 1. Step 3c is the only difference:

```
== 3c. git: is the tag's commit
        annotated tag object f5377b66dffba7ac1fe5d373fc2d1e85b8443b9e -> commit 3f11dc06c4974584d3e1a53cc560dec3c8361169
  FAIL  binary revision '6aa9fcfb14' is NOT the tag's commit (3f11dc06c4974584d3e1a53cc560dec3c8361169) — the artifact was not built from v1.5.8 (pass --lax-revision to downgrade this to a warning)
```

## Finding — the v1.5.8 artifact was built from a commit the tag does not name

Measured, not inferred:

| question | answer |
|---|---|
| `git:` stamped in the published `tallow-linux-aarch64-1.5.8.tar.gz` | `6aa9fcfb14` |
| commit tag `v1.5.8` resolves to (annotated tag `f5377b6`) | `3f11dc06c4974584d3e1a53cc560dec3c8361169` |
| is `6aa9fcf` in this clone at all | no — `git cat-file -t 6aa9fcf` → *not a valid object name* |
| is `6aa9fcf` reachable from any branch on the remote | no — `branches-where-head` → `[]` |
| do the two commits carry the same tree | no — `57632432d760…` vs `0178e447e4b7…` |
| parents | `8c49d9f` vs `05376a7` (both ancestors rewritten) |

Both commits exist in the remote's object database and carry the same message
(`docs(changelog): 1.5.8 states what was added, as the release-body gate
requires`) and the same author date, with different parents and different
trees: the history was rewritten after the v1.5.8 artifact was built, and the
published binary still carries the pre-rewrite stamp.

What this is *not*: evidence that the shipped bytes differ from what the tag
builds today. What it *is*: the published artifact's provenance chain does not
close — `tallow 1.5.8` cannot be tied to the commit `v1.5.8` names, and the
stamped commit is not on any branch a stranger could fetch. That is exactly the
question a post-publication check exists to answer, so step 3c fails by default
and `--lax-revision` exists only to let the rest of the check run on this
pre-rewrite artifact.

For `v1.7.0` the check is meaningful without qualification: the tag is
lightweight at `6aeea5a`, the Release workflow `actions/checkout`s the tag, and
`build.rs` stamps `git rev-parse --short=10 HEAD` — so a correctly built
artifact must stamp `6aeea5a63`. The command to run once the release is
published is:

    scripts/verify_release_assets.sh v1.7.0

## Test 3 — the failure paths

| invocation | exit | what it printed |
|---|---|---|
| `v1.5.8` (strict) | 1 | step 3c: revision is not the tag commit |
| `v9.9.9` | 1 | `no release for tag v9.9.9 (HTTP 404)` |
| `1.5.8` (no `v`) | 1 | same, plus `(did you mean v1.5.8?)` |
| `v1.5.8 solaris` | 1 | `unknown platform 'solaris'; expected one of: …` |
| `--help` | 2 | usage |
| `--bogus` | 2 | `unknown option: --bogus` + usage |
| `v1.5.8 macos-x86_64` | 3 | hash matched, version string present, but the binary cannot execute here |
| *(no arguments)* | 1 | resolved the newest release (`v1.5.8`), then 3c as above |

The three failures the brief names are all exercised: missing release (404),
non-executable-platform, and the revision checks. The foreign-platform path in
full:

```
verify_release_assets: repo=aamirmanisa/tallowsphere platform=macos-x86_64 tag=v1.5.8
host: Linux aarch64

== 1. release metadata
  ok    GET /releases/tags/v1.5.8 -> 200
  ok    tag_name=v1.5.8  published_at=2026-10-26T02:26:28Z  prerelease=false
  ok    release is published (not a draft)
        assets on the release: 15
  ok    asset count 15 >= 5
  ok    all five platforms ship archive + .sha256 + .sig

== 2. download + sha256 (macos-x86_64)
        archive: tallow-macos-x86_64-1.5.8.tar.gz (167070267 bytes)
        sha256 sidecar: tallow-macos-x86_64-1.5.8.tar.gz.sha256
  ok    downloaded tallow-macos-x86_64-1.5.8.tar.gz.sha256 (HTTP 200)
  ok    downloaded tallow-macos-x86_64-1.5.8.tar.gz (HTTP 200)
  size 167070267
  want 293ae76101452e1845019805141c2ff3ab218d1b7e644eaf4c0a356478198755
  got  293ae76101452e1845019805141c2ff3ab218d1b7e644eaf4c0a356478198755
  ok    sha256 matches the published sidecar
  ok    size matches release metadata (167070267 bytes)

== 3. extract + --version
  ok    extracted tallow (51474040 bytes)
        platform macos-x86_64 cannot execute on host linux-aarch64 — structural check only
  ok    the version string '1.5.8' is present in the macos-x86_64 binary
  FAIL  step 3 cannot be completed here: a macos-x86_64 binary will not execute on linux-aarch64
        run this script on a macos-x86_64 machine, or pass linux-aarch64 to verify the host artifact

UNVERIFIED: aamirmanisa/tallowsphere @ v1.5.8 — archive hash checked, but the binary was not exercised
```

It refuses to report a pass. A hash match is not a verification of a binary
nobody ran, so a foreign platform is exit 3 / UNVERIFIED, not exit 0 — run the
script on that platform instead.

## Not yet testable

- **The draft branch.** `v1.7.0`'s Release run (41404997775, head
  `6aeea5a63c34f15999eca1ee6171f355cbb39d11`) was still `in_progress` in the
  release gate when this was written, so no draft existed to run against. The
  draft check is a read of the API's own `draft` field; the first run after the
  draft appears will exercise it. Note that the default invocation resolves the
  *newest* release including drafts, so before publish it fails with "release
  v1.7.0 is still a DRAFT" — that is the intended pre-publish answer.
- **`v1.7.0` end to end**, for the same reason. The published-asset test needs a
  published asset.

## Limits, stated

- **Signatures are checked for presence, not validated.** Every archive's
  `.sig` must exist, but nothing here verifies it: keyless Sigstore verification
  needs the OIDC issuer and certificate identity (`--certificate-identity-regexp`
  / `--certificate-oidc-issuer`), and `cosign` is not installed on this host
  (`command -v cosign` → nothing). A `.sig` that exists but does not verify
  would pass this script. Closing that gap means either installing `cosign` and
  pinning the identity flags, or verifying through Rekor — a change to this
  script, not a claim about it. **Unverified.**
- **Attachment/provenance attestation** (`actions/attest-build-provenance`) is
  not checked; the same `cosign`/`gh attestation` gap applies.
- Reproducibility is not checked: the script verifies the published bytes match
  the published sidecar, not that a rebuild of the same commit yields the same
  bytes.
- Probe logs for every run in this report are under `reports/probes/`
  (`01`–`08`). That directory is gitignored by design (`reports/*` with only
  `reports/*.md` re-included), so the outputs are pasted above rather than
  committed as files.
