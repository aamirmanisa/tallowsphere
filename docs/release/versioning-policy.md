# Versioning & release-tag policy (V1)

> **Scope (2026-10-21).** This policy governs Tallow release tags in this repository. The two mechanical
> checks it names live in different places: `.github/workflows/release.yml` **is** in this repository and
> builds the published artifact, while `scripts/release_gate.sh` is not — the release gate brings its own
> battery. This repository's own tags and CI are described in `MANIFEST.md`
> (§ "Tags", § "CI carried, and what was left behind").

Scope: Tallow `v*` release tags, the Cargo version, and the freeze convention.
Adopted at the V1 freeze (2026-09-14); owner: release custodian (operator).

## Rules

1. **Semantic Versioning.** Versions are `MAJOR.MINOR.PATCH`; `Cargo.toml`
   `version` is the single source of truth for the binary self-report
   (`tallow version`). There is exactly one release crate version for the root
   `tallow` package; workspace member crates version independently.
2. **Green gate before every tag.** A `v*` tag is created only from a revision
   that passed the release gate (`scripts/release_gate.sh --twice`) with no
   red rows and archived evidence.
3. **Tag↔version consistency is machine-checked.** `release.yml` refuses to
   build when the tag and `Cargo.toml` version disagree. The freeze convention
   (decision D6) pairs tag `v1.0` with version `1.0.0`; the check accepts exact
   matches and the two-component tag form (`v1.0` ↔ `1.0.0`).
4. **Tags are immutable.** A mis-tagged or broken release is fixed forward with
   a new patch tag; existing tags are never moved or deleted. Pre-freeze
   historical tags (the March `v1.0.0` from the monorepo era) stay untouched.
5. **Freeze convention.** V1 freeze = tag `v1.0` + Cargo `1.0.0`, annotated,
   signed; the binary self-reported `0.4.0` until the freeze commit (R-05/D6).
6. **Release identity.** R0 — local-only until a remote decision (R-03). CI
   workflows are latent: they are reviewed and kept green by static checks, but
   no remote push occurs in R0.
7. **Signing.** Egressing archives carry two independent signatures: Sigstore
   keyless (`cosign`, CI) and Ed25519 `TALLOW_SIGN_KEY` (installer-native
   verification). `install.sh` / `install.ps1` pin the release public key and
   fail closed on any mismatch; publishing without the installer signature is
   mechanically refused (release.yml publish gate).
8. **CHANGELOG discipline.** `CHANGELOG.md` is updated in the same commit as
   the version bump (the freeze commit, B17).
9. **Rollback.** Prefer re-promotion of last-known-good over history rewrite;
   yank criteria are rehearsed per RG-6 before any remote exists.
