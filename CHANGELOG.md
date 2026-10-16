# Changelog

All notable changes to Tallow are recorded here.
Format: [Keep a Changelog](https://keepachangelog.com/) · versions: [SemVer](https://semver.org/).
Release identity for V1 is **local-only (R0)** — see `docs/release/versioning-policy.md`.

## [v1.1.1] — 2026-10-10 — the deployment's fix, landed (prepared on `v1`, local-only)

v1.1 released a gate whose deployment ran a fix the release did not contain. The installed binary had been
built from the live tree plus a patch binding a **read-only open** into `sluice verify`, and that patch — the
one that makes the anchor control deployable at all — existed in no commit. The release therefore could not
reproduce the binary its own deployment depended on.

### Fixed
- **`KtLog::open_read_only` is in the tree.** `verify` and `verify_segment_close` take a read handle on the
  receipt log instead of a write handle, so the account that checks the log is no longer an account that can
  rewrite it.

### Known gap, recorded rather than hidden
- The running deployment still describes its binary as built from a live patched tree, so it is not yet
  reproducible from a revision. Re-deploying from this tag closes that, and the deployment-provenance gate
  is the mechanism that will say so.

## [v1.1] — 2026-10-10 — the cross-domain release gate (prepared on `v1`, local-only)

Adds **Sluice**, a cross-domain release gate: one decision over whether material may cross a domain
boundary, with failures attributed to the BOUNDARY MODEL rather than to the material. Cross-domain transfer
failures are failures of the boundary, not of what is being transferred.

### The gate
- **Stage order is frozen**: plan+lineage → channel admit → channel obligations → class gate → caveat gate
  → release+receipt. `exit 0` = ALLOW, `exit 1` = DENY.
- **14 emittable deny codes**, each with a stable machine-readable form so a caller can tell a boundary
  refusal from an infrastructure failure.
- **Receipts are digest-only** and hash-chained into the existing KT log — no sidecar, no plaintext.
- **CLI**: `check` / `channels` / `explain` / `release` / `verify` / `rotate`.

### Verification
- A **30-gate regression battery** (`tools/regression_gates.sh`) runs over both the deliverable and the
  product: a clean-checkout build gate, a deployment-drift gate, and auditors that re-derive every count,
  citation and path the documents state rather than trusting them.
- **124 defects** found and recorded across 45 waves, each with its reproduction and severity.

### Deployment
- Installed and running on the reference host: daily rotation, hourly divergence monitoring, hourly anchor
  recording. Each is proven by a real run, not by its unit being enabled.

### Release identity
- Tag `v1.1` pairs with Cargo version `1.1.0`. Release identity remains **local-only (R0)** per R-03.
- This entry covers the gate and its verification. Other work on the `v1` line between the freeze and this
  tag is recorded in the commit history rather than summarised here.

## [v1.0] — 2026-09-14 — V1 freeze (prepared on `v1`, local-only)

The first V1 freeze candidate, assembled through the R-08 execution program
(batches 1–4) on branch `v1` (17 checkpoint commits B0–B16, tip `fea1029`),
verified by batteries 2–9. Not a public release; tag + archive mechanics per
`docs/release/` and decision R-03/D6.

### Identity fabric (W3)
- **SVID workload identity** — certs, issuer, relay mutual-auth, zero-trust policy
  pack (`W7201–W7203`), short-lived scope-bound workload tokens, sector pseudonyms.
- **Enrollment ceremony** — two-sided SAS-based enrollment with single-use
  SPKI-bound tokens and honest attestation (`src/enrollment.rs`, `pake/sas.rs`).
- **Revocation** — signed revocation lists with TTL-bounded staleness, checked at
  the daemon handshake seam (refuse new sessions; established sessions
  untouched per D-4); KT-logged.
- **Recovery** — offline custody shares (Shamir, k≥2 distinct custodians),
  dual-control recovery with root-commitment verification, root-rotation
  ceremony (Ed25519 approvals, no self-approval, re-verify-at-execute,
  retired roots never re-anchored); honest-unrecoverable doctrine; KT-logged.
- **Persona firewall** — enforcement layer with typed findings/refusals.

### Key transparency
- Append-only BLAKE3 KT log with signed tree heads, inclusion and consistency
  proofs; event payloads committed by hash (caller-held evidence). Wired into
  enrollment, recovery and revocation flows.

### Config kernel
- Layered scopes (KB-2), versioning/migrations (KB-3), signed config bundles
  (Ed25519; verify-before-load), secure-by-default lint pack.

### Crypto & supply chain
- AEAD upgrades (agent channel v2; CredentialVault), Argon2id single-source
  parameters, AEGIS gating, constant-time test harness + procurement rule,
  cargo-vet trust foundation, SBOM/CBOM drift gates.

### Transport, egress, measurement
- TallowTransfer relay end-to-end + delta-sync resume; transport fallback and
  bandwidth limits; fail-closed Tor egress (direct is an explicit opt-in);
  browser/measurement readiness for the D4 calibration run.

### Compliance
- Compliance report generator with CRA 24h / CERT-In 6h early-warning clocks
  and ZNISM self-assessment output.

### Gates & process
- `release_gate.sh` acceptance battery (`--twice`, `--quick`, evidence archive),
  `never_check.sh` (static + cargo + optional live egress), `kev_gate.sh`,
  claims-ledger gate; freeze chain F-01…F-08 defined.

### Known limitations (honest, per freeze review)
- Live calibration run **R-01** pending (windows A/B); cost/perf multipliers stay
  `[target-only]` until then.
- SLIP-39 mnemonic leg blocked (no offline crate/wordlist) — recorded, not built;
  FROST k-of-n authorizer dep-gated; mesh/swarm legs are W5 by design.
- Release identity is local-only (no remote, no CI execution); non-Linux targets
  not exercised on this host.
