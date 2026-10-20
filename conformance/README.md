# Conformance suite (engine copy)

Vendored from `Tallow-Language/conformance` so CI can prove the *packaged* binary
behaves, not just that it links. Canonical copy: the language repo; sync by
copying `cases/` and `run.py` and updating the digest below.

    python3 conformance/run.py --tallow /path/to/tallow

Each case runs on BOTH planes (`--interpret` and `--require-native`) and must
agree with its `.json` expectation, so a divergent plane fails instead of
silently shipping.

Cases: 19 · files: 37 ·
tree sha256: 56424cd606bb42c275c8a347eba57ffbae9d751b58d7716195b1573e18e575fc
