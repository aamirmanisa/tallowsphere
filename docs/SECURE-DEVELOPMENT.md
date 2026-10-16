# Tallow Secure Development & Signing Guide

This is the operational reference for maintaining Tallow's release trust chain.
It answers the question: **how does a user verify that a Tallow binary really came
from the maintainer, and how do we stop one compromised developer machine from
silently shipping malware to every user?**

Last updated: 2026-08-15 (from the 11-agent research program, `docs/research/agent09_supply_chain.md` + red-team `agent10_red_team.md`).

---

## 0. The threat it defends against

> **A single compromised developer laptop (or repo account, or release credential)
> must NOT be able to silently ship a malicious release to every user.**

The release chain has two independent, cryptographically-bound layers:

1. **Git commit/tag signing (GPG)** — proves *which maintainer* authored each commit and tag.
2. **Release artifact signing (Sigstore keyless / cosign)** — proves the *binary* was built in Tallow's CI under the maintainer's OIDC identity, and lets installers verify it (fail-closed) before running.

---

## 1. GPG-signed commits & tags (maintainer)

### One-time setup (per dev machine)

```bash
# Generate a GPG key (ed25519) if you don't have one
gpg --quick-generate-key "Operator <aamir@users.noreply.github.com>" ed25519 sign 0
# Get the key id
gpg --list-secret-keys --keyid-format LONG
# →  ed25519/AAAAAAAAAAAAAAAA 2026-08-15  Operator <aamir@users.noreply.github.com>

# Tell git to use it for this repo
git config user.signingkey AAAAAAAAAAAAAAAA
git config commit.gpgsign true
git config tag.gpgsign true
```

### Register the public key with GitHub (once)

```bash
gpg --armor --export AAAAAAAAAAAAAAAA
# → paste into https://github.com/settings/ssh/new → "GPG keys" (or settings/keys)
```

### Verify your commits are signed

```bash
git log --show-signature -1          # shows "Good signature from ..."
git verify-commit HEAD
git verify-tag v1.0.0
```

### Tagging a release — MUST be an annotated, signed tag

```bash
git tag -s v1.0.0 -m "Tallow v1.0.0"
git push origin v1.0.0               # triggers .github/workflows/release.yml
```

The release workflow is triggered **only** by `v*` tag pushes. An unsigned or
lightweight tag is a signal something is wrong.

---

## 2. Release artifact signing (CI — Sigstore keyless)

Signing happens in CI (`.github/workflows/release.yml`), **not** on a dev
machine. cosign signs the archive with the **GitHub OIDC identity** of the repo +
workflow — there is **no private key on any laptop** to steal.

Per archive, CI produces:
- `tallow-<platform>.tar.gz` / `.zip` — the release binary
- `tallow-<platform>.tar.gz.sig` — raw Sigstore (ECDSA-P256) signature
- `tallow-<platform>.tar.gz.sha256` — SHA-256 checksum

### Verifying a release manually

```bash
# Install cosign: https://docs.sigstore.dev/cosign/installation
COSIGN_EXPERIMENTAL=1 cosign verify-blob \
  --signature tallow-linux-x86_64-musl.tar.gz.sig \
  tallow-linux-x86_64-musl.tar.gz
# → "Verified OK" means: built in tallow-lang/tallow CI, signed by the workflow identity.

sha256sum -c tallow-linux-x86_64-musl.tar.gz.sha256
```

### How install.sh / install.ps1 use these

Both installers now download the archive **plus** its `.sig` and `.sha256`,
verify the SHA-256 checksum, then verify the Ed25519 signature against a
**pinned public key** (set via `TALLOW_PUBKEY` / `TALLOW_PUBKEY_B64` or a raw key
file), and **fail closed** if verification can't complete.

> ⚠️ The installers verify against a pinned Ed25519 key. The CI cosign signature
> is ECDSA-P256 (Sigstore). **Do not confuse the two.** The pinned key for
> installers must be the maintainer's Ed25519 release key (a `tallow sign`
> produced signature, or a separately distributed Ed25519 public key), while the
> cosign `.sig` is for `cosign verify-blob`. Decide which verification channel
> installers use and pin the matching key. (The `.sig`/`.sha256` from CI satisfy
> the checksum + cosign-verifiable path; if you want installer-native Ed25519
> verification, additionally publish a `tallow sign` `.sig` and pin that key.)

---

## 3. Branch & tag protection (GitHub repo settings)

To prevent a compromised/repo-level change from shipping:

- **`main` branch protection:**
  - Require PRs + at least 1 review.
  - Require status checks to pass (CI).
  - Require signed commits.
  - Restrict pushes to the maintainer / a small release team.
  - "Require linear history" (nice-to-have).
- **`v*` tags:** enable *Protected tags* — only the maintainer can create them,
  and they must be signed. This stops anyone from pushing a `v*` tag to trigger a
  malicious release.

---

## 4. CI hygiene

In `.github/workflows/release.yml`:

- **Pin actions to SHAs**, not mutable `@v4` / `@v0` tags, where practical:
  ```yaml
  - uses: actions/checkout@<full-40-char-commit-sha>
  ```
  This stops a compromised action maintainer (or a mutable tag swap) from
  injecting code into the release build.
- **Narrow permissions:** the build job uses `contents: read`; only the publish
  job grants `contents: write` and only to attach release assets.
- **`--locked` builds:** `cargo build --release --locked` uses the committed
  `Cargo.lock`, so the released binary matches the exact dependency set that was
  audited.
- **Secrets:** the release signing is keyless (OIDC); there should be no
  long-lived signing secret in the repo. The only secret is `GITHUB_TOKEN`
  (scoped, short-lived).

---

## 5. Known residual / next steps

- [ ] Publish the maintainer's Ed25519 release public key out-of-band (e.g. a
      signed `tallow.pub` on the website / pinned in-repo) and point
      `install.sh`/`install.ps1` at it.
- [ ] Enforce GPG signing on CI (a workflow gate that rejects unsigned commits —
      GitHub's "require signed commits" branch rule covers this).
- [ ] Pin all third-party actions to commit SHAs.
- [ ] Re-run `tallow audit --supply-chain` and `cargo audit` in CI nightly.

---

## 6. Verify the whole chain end-to-end (release checklist)

```bash
# 1. Commit is GPG-signed
git verify-commit HEAD

# 2. Tag is GPG-signed and annotated
git verify-tag v1.0.0

# 3. CI built + signed the artifacts (check the release assets)
COSIGN_EXPERIMENTAL=1 cosign verify-blob --signature <archive>.sig <archive>
sha256sum -c <archive>.sha256

# 4. Installer refuses an unverifiable/unsigned release (test it)
TALLOW_PUBKEY=<real-key-b64> sh install.sh   # or on Windows: install.ps1
```
