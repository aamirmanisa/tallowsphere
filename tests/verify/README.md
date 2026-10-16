# tests/verify — system verification battery

`system_battery.sh` exercises the **real** `target/debug/tallow` binary
feature-by-feature in a scratch sandbox and records one verdict per feature:

```
bash tests/verify/system_battery.sh [sandbox-dir]   # default /tmp/nixe-verify
```

- Writes `results.tsv` (`name<TAB>verdict<TAB>note`) + raw logs per step under `<sandbox>/logs/`.
- Verdicts: `PASS` · `FAIL` · `EXPECTED` (a non-zero outcome that is acceptable
  for this environment and isn't a defect) · `SKIP` (not exercisable in this environment) · `FINDING`
  (a real defect discovered — see the stub register for the corresponding row).
- Sandboxed: uses its own `HOME` for most steps (real `HOME` only for
  stateful probes: browser/tor/daemon). All file round-trips happen under
  `<sandbox>/work/`; nothing outside is touched.
- **Do not set `export NO_COLOR=1` in the caller environment** — the CLI binds
  `--no-color` to `NO_COLOR` as a boolean, so the standard convention breaks
  argument parsing (register row #74; **fixed + verified 2026-09-15** on the rebuilt
  `c7afa20a…` binary — `NO_COLOR=1 tallow version` now exits 0).
- Network-mediated steps (phone lookup, registry install/publish, browser
  navigation) are deliberately out of scope: the box runs a fail-closed/Tor
  egress posture and the R-01 calibration window must not be perturbed.

First full run: 2026-09-15 (v1 tree, binary `1.0.0`, sha256 `c2d6ceb0…b139e`).
It surfaced **8 findings → stub-register rows #74–#81** (NO_COLOR binding, `doc`
extension filter, 31 stdlib missing-arg panic sites, a `run` hang, the `sync`
facade gap, examples/docs drift, `tor status` misdetect, drift-scan semantics).
Evidence: `artifacts/nixe-system-verification-2026-09-15/` (01–05).

Post-rebuild re-run (2026-09-15 evening, binary `c7afa20a…`, wave-4 + #82 fixes):
**195 PASS / 1 FAIL / 3 EXPECTED of 199** (the FAIL is the `doctor --stdlib-drift`
rc=2 residual); evidence `r2-battery-*` in the same directory; short-arity probes
(register #82): `evidence/f10-probes/` + `f10-after.txt`.

Battery-fix re-run (2026-09-16, P1-wave fix binary `796af684…` — closes the
`doctor --stdlib-drift` FAIL *and* the three EXPECTED rows): **201 PASS / 0 FAIL /
0 EXPECTED of 201** (`BATTERY_RC=0`; evidence
`artifacts/nixe-remediation-2026-09-14/p1-wave-2026-09-16/battery-fix/`).
- `doctor --stdlib-drift` resolves class-method declarations via four evidence
  classes (interp dispatch arms · module full keys · class routing + module
  method · registered module): 1122/1122 declarations, 0 unreachable; JSON gains
  `reachable_via` counts; paths are manifest-anchored (cwd-independent).
- The former EXPECTED refusal rows (`verify-ledger-missing`, `daemon-status`,
  `job-list`) now **verify the documented graceful-refusal contract** and PASS on
  the exact message; rc=0 or any other error still FAILs.
- Summary counters are derived from `results.tsv` (the old console counters lost
  subshell `rec()` calls); the line-254 `grep -c || echo 0` quirk is fixed.
