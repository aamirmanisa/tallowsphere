# Conformance suite (engine copy)

Vendored from `Tallow-Language/conformance` so CI can prove the *packaged* binary
behaves, not just that it links. Canonical copy: the language repo; sync by
copying `cases/` and `run.py` and updating the digest below.

    python3 conformance/run.py --tallow /path/to/tallow

Each case runs on BOTH planes (`--interpret` and `--require-native`) and must
agree with its `.json` expectation, so a divergent plane fails instead of
silently shipping.

Cases: 21 · files: 40 ·
tree sha256: 56424cd606bb42c275c8a347eba57ffbae9d751b58d7716195b1573e18e575fc

The digest above covers the **19 vendored cases** (37 files). `22-newtypes` and
`23-reject-newtype-bare-value` (G10) were added in this tree and are not yet in
that digest — refresh both count and digest when the canonical copy is synced.
