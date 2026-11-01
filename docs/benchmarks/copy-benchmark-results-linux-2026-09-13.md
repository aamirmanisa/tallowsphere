# Copy-engine benchmark results — Linux lane (run `e310-copy-linux-v2`)

> **Status: FINAL for the smoke-scale v2 battery.** Every value below is **[measured]** on this
> box (2026-09-13, local fixtures only, no network) unless explicitly labeled **[partial]** or
> **[target-only]**. Protocol: `docs/benchmarks/copy-benchmark-protocol.md`.
> Primary run `e310-copy-linux-v2` (174 rows: 145 measured + 29 warm-up) plus a targeted
> verification-path correction run `e310-copy-linux-v2fix` (c6+c8, 30 rows). Run
> `e310-copy-linux-v1` (156 rows) is superseded and kept only as reference — see §7.
> Harness: `scripts/copy_benchmark/benchmark_copy_engine.py` · dataset builder:
> `scripts/copy_benchmark/generate_copy_benchmark_dataset.py`.

## 1. Method (as executed)

- **Machine / run conditions** (recorded in the report header of both runs):
  aarch64 · 8 vCPU · kernel `6.8.0-139-generic` · MemTotal 15.95 GB · MemAvailable 14.07 GB ·
  root fs `/dev/sda1` **ext4**, 50.1 GB free at run start · repo `master` @
  `ab422dd5ef1d1cdadd843a040e23a17a57e5cca4` (dirty tree, unchanged by this lane) ·
  loadavg (1/5/15) before `[1.80, 2.26, 2.14]`, after `[3.79, 2.87, 2.39]`.
- **Binaries (pinned, sha-fixed for the whole battery):** release
  `3baf21de2435e3580b5dc1a15176a884f82fcc02fb17de208eb962e45025c532` ·
  debug `b7baaef48afd5d25f67e0ac13d2c7710be987eddb061e55213e58734b958f3be`
  (both under `/var/tmp/tallow-e310-bin/`, immune to sibling rebuilds). Release = competitive
  profile per protocol; debug appears only in context rows (c1/c2/floor/probes).
- **Dataset** (repo-external, deterministic): root `/var/tmp/tallow-copy-bench`, scale `smoke`,
  seed 1337, marker/manifest `tallow.copy_benchmark.dataset.v1`
  (sha256 `5026d3f423bc10f5e273de19c6bad60b0d8caaeb2638237e3dd376cbdcbb38cb`):
  1 GiB blob (sha256 `3a3510b424c9bbad9f901112d1b93051cd8715e47ec844215dd529a2b09e8429`),
  10 000 small files (86 816 318 B), 300-file mixed tree (25 047 235 B),
  512 MiB logical sparse file (1 052 672 B physical). Generated in 2.6 s.
- **Runs/arm:** 5 measured + 1 warm-up (warm-up rows excluded from all aggregates and gates).
  All measured runs rc=0 (145/145 v2; no retries by design; 0 verification failures).
- **Timing:** wall-clock at the harness around each subprocess (subprocess start→exit inclusive),
  warm page cache, **no `drop_caches`** (cold-cache is a separate study — outline in
  `cold-start-study-outline.md`, [target-only]). `-q` NOT used so engine markers stayed visible.
- **Engine labeling:** every JSONL row carries `engine` ∈ {`native`, `system-tool`, `native-cli`}
  + binary path/sha, derived from stdout/stderr marker scan + binary sha (e.g. the copy
  fast-path marker, `TallowTransfer` delta-sync markers).
- **Baselines (documented deviation):** the protocol's Windows baselines (`robocopy`,
  `Copy-Item`, `FastCopy`) do not exist on this box; Linux equivalents `cp`/`rsync` are used and
  the gate wording is mapped accordingly (G1 "fastest baseline" = `cp`; G2 "beats baselines" =
  beats both `cp -a` and `rsync -a`). No Windows comparison is claimed anywhere.
- **MB/s column** = source bytes (10⁶-based) ÷ median wall time. For `c5`, `c5scale`, `c6` the
  numerator is the *changed subset* the arm is defined on (not the whole tree), so those rows are
  not comparable to full-copy throughput rows — read ratios, not MB/s, across classes.

## 2. Results table (v2 measured medians; ms, wall-clock)

| class | arm | engine | n | min | **median** | p95 | max | MB/s (src) |
|---|---|---|---|---|---|---|---|---|
| c1 | cp | system-tool | 5 | 640.7 | **647.6** | 669.6 | 669.6 | 1658.0 |
| c1 | rsync | system-tool | 5 | 1387.9 | **1460.3** | 1533.9 | 1533.9 | 735.3 |
| c1 | tallow-debug copy | native | 5 | 652.7 | **672.7** | 678.0 | 678.0 | 1596.3 |
| c1 | tallow-release copy | native | 5 | 643.9 | **656.7** | 680.8 | 680.8 | 1635.0 |
| c2 | cp -a | system-tool | 5 | 484.2 | **494.6** | 518.3 | 518.3 | 175.5 |
| c2 | rsync -a | system-tool | 5 | 816.3 | **861.2** | 895.5 | 895.5 | 100.8 |
| c2 | tallow-debug copy | native | 5 | 435.3 | **491.4** | 503.9 | 503.9 | 176.7 |
| c2 | tallow-release copy | native | 5 | 386.8 | **447.1** | 461.9 | 461.9 | 194.2 |
| c3 | cp -a | system-tool | 5 | 32.2 | **33.8** | 36.0 | 36.0 | 741.4 |
| c3 | rsync -a | system-tool | 5 | 104.6 | **106.3** | 119.2 | 119.2 | 235.7 |
| c3 | tallow-release copy | native | 5 | 20.3 | **22.9** | 32.1 | 32.1 | 1091.6 |
| c5 | delta-sync (reset per run) | native | 5 | 14.7 | **18.2** | 18.5 | 18.5 | 1378.4 |
| c5 | delta-sync (persistent dst) | native | 5 | 16.9 | **17.9** | 21.7 | 21.7 | 1398.0 |
| c5scale | delta-sync 1% of 10k (reset per run) | native | 5 | 70.9 | **81.5** | 115.9 | 115.9 | 1065.4 |
| c6 | delta-sync --block-level | native | 5 | 5456.1 | **5498.4** | 6226.3 | 6226.3 | 2.0 |
| c6 | delta-sync plain (contrast) | native | 5 | 1491.3 | **1531.3** | 1599.2 | 1599.2 | 7.0 |
| c7 | cp (plain) | system-tool | 5 | 3.9 | **4.5** | 5.9 | 5.9 | 120482.7 |
| c7 | cp --sparse=always | system-tool | 5 | 4.1 | **4.4** | 5.8 | 5.8 | 121162.5 |
| c7 | tallow-release copy | native | 5 | 348.5 | **356.1** | 358.9 | 358.9 | 1507.6 |
| c8 | delta-sync --verify (copy+verify) | native | 5 | 4506.0 | **4600.0** | 4652.3 | 4652.3 | 233.4 |
| c8 | sha256sum (dst re-read) | system-tool | 5 | 782.3 | **795.9** | 815.5 | 815.5 | 1349.0 |
| c8 | tallow hash | native-cli | 5 | 1485.6 | **1490.9** | 1508.2 | 1508.2 | 720.2 |
| floor | tallow-release version | native-cli | 5 | 6.1 | **6.5** | 10.9 | 10.9 | — |
| floor | tallow-debug version | native-cli | 5 | 14.0 | **14.9** | 16.2 | 16.2 | — |
| full | delta-sync (full sync, empty dst) | native | 5 | 23.4 | **30.1** | 48.8 | 48.8 | 832.6 |
| warm | delta-sync no-op | native | 5 | 16.2 | **16.9** | 19.8 | 19.8 | — |
| warm | tallow copy no-op | native | 5 | 11.2 | **12.2** | 15.8 | 15.8 | — |
| warmscale | delta-sync no-op 10k dir | native | 5 | 58.8 | **69.0** | 71.1 | 71.1 | — |
| warmscale | delta-sync no-op 1GiB-file dir | native | 5 | 11.9 | **13.3** | 14.8 | 14.8 | — |

Policy/mechanism actually exercised (protocol §Reporting Rules requires stating it):
c1–c3 plain full byte copy (tallow copy = parallel fast-path) · `full`/`warm`/`warmscale`/`c5`/
`c5scale` = skip cache with **size + mtime-second parity** predicate, **no manifest cache** ·
c6 = `--block-level` rsync-algorithm block delta (128 KiB blocks per `--help`) ·
c7 = no sparse preservation · c8 = hash-after-write verification + standalone hashers ·
c9 = re-run into a partially populated destination (no journal flag; see §5).

Raw artifacts: `/var/tmp/tallow-copy-bench/reports/e310-copy-linux-v2/{report.json,report.md,rows.jsonl}`
(rows carry per-run command, rc, duration, copied/skipped counts, engine label, binary sha).

## 3. Gate outcomes (initial gates, smoke scale)

| Gate | Target | [measured] result | Verdict |
|---|---|---|---|
| G1 full large-file vs fastest baseline | within +10% | 656.7 vs cp 647.6 ms → **1.014×** | **PASS** |
| G2 many-small-file vs baselines | beats baselines | 447.1 vs cp 494.6 / rsync 861.2 ms | **PASS** |
| G3 warm no-op vs full recopy | ≥100× | 16.9 vs 30.1 ms (same mixed tree) → **1.78×** | **FAIL** |
| G4 1% changed files (300-file tree) | ≥10× | 18.2 vs 22.9 ms → **1.26×** | **FAIL** |
| G4b 1% changed files (10k tree) | ≥10× | 81.5 vs 447.1 ms → **5.49×** | **FAIL** |
| G5 resume does not recopy committed | skip ≥ committed | resume re-copied 10 000/10 000, skipped 0 (all 3 attempts) | **FAIL** |
| G3b no-op scaling (informational) | — | 1 GiB-file dir: 13.3 vs 656.7 ms → **49.25×**; 10k dir: 69.0 vs 447.1 ms → **6.48×** | info |
| G6 sparse (informational) | >1000× (stretch) | tallow writes **536 870 912 B physical** (no sparse preservation) vs cp 1 052 672 B / cp `--sparse=always` 1 048 576 B; wall 356.1 vs 4.5 ms | info (negative) |
| G7 block-delta (informational) | >1000× (stretch) | block-level **5498 ms** vs plain recopy 1531 ms → block-level **3.59× slower** at 1% changed bytes | info (negative) |

Stretch gates from protocol §Stretch (sparse >1000×, no-op >1000× with manifest cache,
block-delta >1000× on tiny ranges) are **not met**; nothing here supports a "1000×" copy claim.

## 4. M-06 bucket-C statement — **warm no-op ≥100× NOT met [measured]; re-scoped honestly**

The checklist item (`V1-MASTER-CHECKLIST.md` M-06 · Bucket-C measured item) intended a warm
no-op gate of **≥100× vs a full recopy**. [measured] outcome: **not met at smoke scale**. The real
numbers, all from this run:

- smoke mixed-tree (300 files): no-op 16.9 ms vs full sync 30.1 ms → **1.78×** — the honest
  headline number at this scale;
- scale map (added in v2 for exactly this question): no-op vs *same-scale same-binary full copy*:
  **49.25×** on a 1 GiB-file directory (13.3 vs 656.7 ms) and **6.48×** on a 10 000-file tree
  (69.0 vs 447.1 ms).

Why it is structurally unreachable at this scale: the release binary's own process floor is
6.5 ms (floor class), both the no-op path and the copy path pay it, and the no-op path still
pays a full traversal/scan (1 GiB dir: 13.3 ms ≈ 2× floor). A ≥100× ratio against a same-scale
full copy needs ≥ ~1.3 s of copy work in the denominator — only ≥8 GiB-class working sets can
provide that, and the full-scale dataset was deliberately deferred (disk-headroom gate, §7).

Re-scope (per CHARTER §Conductor's operating notes 1 & 3 — anti-hype, evidence-backed, labeled):

1. **Publish per-scale measured ratios only** (as above); no unqualified "≥100×/1000× no-op"
   claim. Bucket-C evidence = this section.
2. **Replace the universal ≥100× initial gate** with a scale-qualified target in the ≥8 GiB
   class, to be measured when the full-scale dataset lands; keep ≥100× as **[target-only]**
   stretch, explicitly tied to a manifest cache (protocol §Stretch already scopes it that way).
3. **Carry the F1 caveat in every no-op number:** all no-op rows here are on parity-preserved
   (`cp -a`-preseeded) destinations; tallow-written destinations currently never reach no-op
   (see F1). A no-op multiplier without that caveat would not survive scrutiny.

## 5. Findings (each with its evidence)

- **F1 [measured] — `tallow copy` does not preserve mtimes; the skip cache requires size +
  mtime-second parity.** Probe (both binaries): src mtime `1577836800` (2020-01-01) → dst mtime
  after tallow copy = fresh; `mtime_preserved=false`; second tallow copy copied 2/2, skipped 0;
  `delta-sync` after a tallow-written dst skipped 0; after `cp -a` preseed skipped 2/2
  (positive control works). Consequence: a tallow-populated destination never reaches warm
  no-op/resume — recopy is deterministic. (Fixes this prior attempt's "copy twice → 0 skipped"
  observation, which was a same-second mtime artifact of fresh sources.)
- **F2 [measured, partial root-cause] — resume gate fails for the same reason.** c9 killed
  `delta-sync` mid-flight (kill delays 0.10/0.20/0.35 s; committed-at-kill 1249/6795/10000 of
  10 000 files, committed = present with matching size), then re-ran the same command into the
  partially populated dst: every attempt **copied 10 000, skipped 0** (durations 691/383/480 ms).
  The behavior is consistent with the F1/F2 skip predicate (tallow-written files carry fresh
  mtimes, parity never holds) but the single-cause isolation is [partial] — no journal feature
  was exercised, because the CLI exposes none; "resume" here = re-run semantics.
- **F3 [measured] — `delta-sync` with FILE operands is a silent no-op** (release build): rc=0,
  `scanned_files=0`, copied 0, skipped 0, destination unchanged (sha-verified). This is why c6
  and c8 arms are dir→dir. Probe recorded in v2 report; the raw file→file behavior is real and
  worth a follow-up (silent success is worse than an error) — flagged, not fixed, in this lane.
- **F4 [measured] — block-level delta is correct but currently a loss at 1% changed bytes.**
  `--block-level` on 1 GiB with 1% bytes changed: median **5498 ms** vs plain recopy **1531 ms**
  (3.59× slower; corrected re-run 5504 vs 1588 ms, same direction). Destination correctness
  verified by sha (`c6_sha_after_block_level_arm=true`; dst sha = canonical blob). Summary line
  shows the block scan dominating (≈6.2 s scan on the slowest run). G7 stays informational;
  the claim "block-delta >1000×" is nowhere near supported at this scale.
- **F5 [measured] — sparse preservation absent in `tallow copy`.** Writing the 512 MiB sparse
  fixture costs tallow **536 870 912 B physical** vs 1 052 672 B for `cp` (≈510× more physical
  bytes; 512× vs `cp --sparse=always`; wall 356.1 vs 4.5 ms). Content verified byte-identical (`c7_sparse_content_sha_match=true`);
  only allocation is lost.
- **F6 [measured] — verification cost is reported separately, as required.** 1 GiB
  copy+verify (`delta-sync --verify`): 4600 ms vs copy-only 657 ms (c1) — verify ≈ +3.9 s.
  Standalone hashers on 1 GiB: `sha256sum` 796 ms vs `tallow hash` 1491 ms (tallow hash is
  1.87× slower than the system hasher on this box; reported as measured, no cause claimed).
- **F7 [measured] — competitive position at smoke scale is clean:** G1 pass (+1.4% of cp on the
  1 GiB full copy; 2.2× faster than rsync); G2 pass (beats `cp -a` by ~10% and `rsync -a` by
  ~1.9× on 10 000 small files); c3 mixed tree: 22.9 ms vs cp 33.8 / rsync 106.3 ms.
- **F8 [measured] — v1 vs v2 variance on parallel tallow arms.** Same pinned binary, two full
  batteries ~10 min apart: tallow-release medians moved (c1 808→657 ms, c2 636→447 ms) while
  `cp`/`rsync` stayed within ~5%. 8-thread tallow arms are the plausible contention-sensitive
  side (E-3.2 runs 10 sibling lanes on this box); attribution not isolated. **v2 is the
  reported set** (its results are verification-backed: c1 sha ✓, c2 file/byte counts ✓).

## 6. Verification / integrity

- c1 dst sha = source blob sha ✓ · c2 dst = 10 000 files / 86 816 318 B ✓ · c7 content sha ✓ ·
  c6 (block-level arm) sha ✓ · c8 dst sha ✓ — after the §7 correction, `e310-copy-linux-v2fix`
  reports `c6_blocklevel_sha_match=true`, `c8_preseed_sha_match=true`.
- All measured runs rc=0; skipped/copied counters parsed from engine output; engine labels
  present on every row; binaries sha-pinned; dataset manifest sha recorded.

## 7. Errata / harness corrections (2026-09-13 ~05:00 UTC)

The v2 report's end-of-run verification block read two **v1-era leftover paths** for classes
that v2 re-based to dir→dir fixtures: `bench-runs/c6/blob.bin` (stale file, sha `81c2c574…`,
mtime 04:25:04 — the v1 file-mode arm's modified copy) and `bench-runs/c8/blob.bin` (stale but
canonical content, so its boolean was true for the wrong file). Only the c6 boolean was
affected in v2: it reported **false against the wrong file**, while the correct v2 destination
`bench-runs/c6/dst/blob.bin` was byte-identical (sha `3a3510b4…` = canonical blob, still
verifiable on disk). Timings are unaffected (verification runs after all measurement).
Fix: the two verification paths in `benchmark_copy_engine.py` now point at the dir-mode
destinations; a targeted re-run `e310-copy-linux-v2fix` (same pinned binaries, same fixtures,
c6+c8, 5+1 runs/arm, via `ram_guard.sh`) reproduced the timings within ≈1–5% (block-level 5504
vs 5498 ms; plain 1588 vs 1531; verify 4753 vs 4600; sha256sum 810 vs 796; tallow hash 1552 vs
1491) and returns both booleans **true**. The v2 report files are kept as-is (primary record);
the fix applies to future runs.

## 8. Caveats / limits

- **Smoke scale only** (1 GiB / 10k / 300-file / 512 MiB sparse). Full-scale arms (8 GiB, 32 GiB,
  100k files) **not measured** — deferred on the disk-headroom gate (~50 GB free at run start);
  the ≥100× no-op question needs those scales (§4).
- **Warm page cache only**; no `drop_caches`. Cold-start/cold-cache is a separate study
  (`cold-start-study-outline.md`, [target-only] outline, execution = later wave E9; installer arm
  excluded until the release key is pinned).
- **Linux baselines only**; no Windows/SMB/FastCopy comparison claimed. Same-volume only
  (all under `/var/tmp` on `/dev/sda1`).
- **Metric coverage vs protocol §Metrics**: total wall measured per run; scan/plan/verify splits
  available only as the CLI's own summary text (not machine-split); **peak RSS and CPU% not
  captured [not measured]**; retries 0; verification failures 0.
- Sibling-lane CPU contention during the battery is possible (F8); medians are per-batch.
- Nothing here is a Windows claim, a cold-start claim, or a "×1000 copy" claim; anti-hype
  labels per CHARTER apply throughout.

## 9. Reproduction

```bash
# dataset (deterministic; refuses non-empty unmarked roots)
python3 scripts/copy_benchmark/generate_copy_benchmark_dataset.py \
  --root /var/tmp/tallow-copy-bench --scale smoke --seed 1337

# primary battery — 5 measured + 1 warm-up per arm, engine-labeled rows
python3 scripts/copy_benchmark/benchmark_copy_engine.py \
  --root /var/tmp/tallow-copy-bench \
  --release /var/tmp/tallow-e310-bin/tallow-release-pinned \
  --debug   /var/tmp/tallow-e310-bin/tallow-debug-pinned \
  --runs 5 --warmup 1 --run-id e310-copy-linux-v2 --tag "E-3-10 linux lane v2"

# corrected c6/c8 verification supplement (post stale-path fix, §7)
bash scripts/ram_guard.sh python3 scripts/copy_benchmark/benchmark_copy_engine.py \
  --root /var/tmp/tallow-copy-bench \
  --release /var/tmp/tallow-e310-bin/tallow-release-pinned \
  --debug   /var/tmp/tallow-e310-bin/tallow-debug-pinned \
  --runs 5 --warmup 1 --only c6,c8 --run-id e310-copy-linux-v2fix
```

Artifact index: `reports/e310-copy-linux-v2|v1|v2fix/{report.json,report.md,rows.jsonl}` under
`/var/tmp/tallow-copy-bench/`; run logs `/tmp/e310-bench-run.log` (v1), `/tmp/e310-bench-v2.log`
(primary), `/tmp/e310-bench-v2fix.log` (fix run); dataset manifest
`/var/tmp/tallow-copy-bench/.tallow-copy-benchmark-dataset.json`. Exec log:
`research/tallow-v1/exec/E-3-10-copy-lane.md`.
