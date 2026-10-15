# Tallow

Privacy-first systems language **and** anti-bot scraping / OSINT runtime.
Local-first, fail-closed by default, with evidence-gated engineering: docs
claims are registered and labeled — `shipped` / `partial` / `target-only` — in
`docs/claims-ledger.yaml` (43 of 65 rows `partial`, 21 `target-only`, 1 `shipped`
as of 2026-09-16).

**Status:** V1 declared (R0, local-only; tag `v1.0` @ `70e338a`). Not a public release.

## What's here

- **`tallow` toolchain** — compiler + tree-walking/native runtime for `.tl`
  programs (`src/`, `stdlib/`), with structured diagnostics.
- **Runtime services** — browser automation, extraction, OSINT/entity-graph
  modules, transfer/relay, vault (encrypted at rest), key-transparency log.
- **Operational gates** — `scripts/never_check.sh`, `scripts/release_gate.sh`,
  SBOM/CBOM drift checks, claims-ledger gate.

## Build from source

```bash
rustup stable && apt install cmake clang libssl-dev perl pkg-config
cargo build --offline --bin tallow        # target/debug/tallow
```

## Install (release artifact)

```bash
# Installers verify sha256 + Ed25519 signature against the pinned release key
# and fail closed on any mismatch:
./install.sh          # Linux/macOS
# install.ps1         # Windows
```

## Quickstart

```bash
tallow check examples/hello_simple.tl
tallow run   examples/hello_simple.tl
tallow doctor            # posture/health checks
```

## Security posture (short version)

- **Egress:** proxied through Tor (`socks5h://127.0.0.1:9050`) by default;
  `TALLOW_ALLOW_DIRECT` is the only explicit opt-out. Fail-closed, no silent
  fallbacks. See `docs/release/NEVER_RELEASE_CHECKLIST.md`.
- **Vault:** encrypted containers (Argon2id + AEAD). Default write path is the
  v2 post-quantum hybrid container (ML-KEM-768 wrap; inner classical layer
  AES-256-GCM); XChaCha20-Poly1305 v3 is written when `pqc_enabled=false`.
  Custody shares and dual-control recovery are commitments-only on-node.
- **Release gates:** a release is tagged only from a green acceptance battery
  with archived evidence; tags are immutable (`docs/release/versioning-policy.md`).

## Docs

- `docs/release/` — NEVER_RELEASE_CHECKLIST · V1_RELEASE_GATES · versioning policy
- `research/tallow-v1/` — program execution records (waves, batteries, evidence)
- `docs/benchmarks/benchmark-protocol.md` — how measurements must be taken

## License

MIT (see `Cargo.toml` `license`).
