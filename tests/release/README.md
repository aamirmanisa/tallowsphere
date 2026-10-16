# tests/release — installer fixture E2E toolkit

Verifies the release install path end-to-end **without GitHub**: a throwaway
fixture "release" is generated locally, served over loopback HTTP, and the
REAL `install.sh` / `install.ps1` run against it. Both installers honor
`TALLOW_RELEASE_API_URL` (test/mirror hook) so no code path is bypassed.

| File | Purpose |
|---|---|
| `make_fixture.py` | Builds `--out` fixture release: archive (`tallow` / `tallow.exe`), `.sha256`, `.tallow.sig` (Ed25519 over the sha256 hex-string, openssl — same format release.yml emits), `.tallow.pub` (raw), `fixture_pub.b64`, `latest.json` (GitHub-shaped; localhost URLs; decoy assets for the F-01 anchoring). Throwaway key per run. |
| `install_e2e_linux.sh` | 8 cases against `install.sh` over the fixture: full positive install, pre-existing correct key file, planted wrong key file (override-wins, file untouched), pin-mode planted-key refusal **before any network I/O**, `TALLOW_ALLOW_KEY_OVERRIDE=1` path, placeholder refusal, wrong-key signature, tampered archive. |
| `smoke_windows.ps1` | Same shape for `install.ps1` (positive install + F-09 refusal + override-wins). Runs in `release.yml` on **windows-latest**; best-effort locally under pwsh. |
| `test_key_pin_gate.sh` | F-18 gate: `scripts/check_release_key_pin.sh` must accept the real pin (raw + base64), reject flipped keys / wrong lengths / installer drift / placeholders, and match the recorded operator fingerprint `a42d6f38…`. |

## Run

```bash
bash tests/release/install_e2e_linux.sh      # needs python3 + openssl + curl
bash tests/release/test_key_pin_gate.sh
pwsh -NoProfile -File tests/release/smoke_windows.ps1   # optional locally
```

CI wiring: `release.yml` runs the Linux E2E in the `release-gate` job and the
pwsh smoke in `install-smoke-windows` (both before any publish). The installers'
key handling is pinned-authoritative since the F-09 fix: `TALLOW_PUBKEY*`
overrides and `TALLOW_ALLOW_KEY_OVERRIDE=1` are explicit and warned; a key file
that does not byte-match the pin is refused by default.
