# Tallow Copy Engine Benchmark Protocol

This protocol measures the native Tallow copy engine against Robocopy,
PowerShell `Copy-Item`, the current Tallow CLI, and optional FastCopy installs.
It separates raw full-copy throughput from the workflows where Tallow can make
large wins: no-op sync, incremental sync, sparse/clone paths, restart, and
verified copy.

## Benchmark Classes

Run each class as its own result group. Do not combine full-copy throughput with
skip-heavy or delta-heavy results.

| Class | Purpose |
| --- | --- |
| Full large-file copy | Measures hardware-bound sequential read/write speed. |
| Many-small-file copy | Measures traversal, scheduling, directory creation, and metadata overhead. |
| Mixed tree copy | Measures normal project/media/archive trees. |
| Warm no-op sync | Measures unchanged-file detection and planning overhead. |
| One-percent changed files | Measures incremental tree update efficiency. |
| One-percent changed bytes | Measures block/delta capability inside large files. |
| Sparse file copy | Measures sparse preservation or clone/range acceleration. |
| Verify-only | Measures destination re-read and hash/manifest speed. |
| Resume after interruption | Measures journal correctness and avoided recopy. |

## Datasets

Generate deterministic datasets outside the repository, for example:
`C:\tmp\tallow-copy-bench`.

The minimal smoke harness is intentionally small and safe by default:

```powershell
.\scripts\generate_copy_benchmark_dataset.ps1
.\scripts\benchmark_copy_engine.ps1
```

The generator writes a marker file and refuses to write into a non-empty
unmarked directory. Its default root is `C:\tmp\tallow-copy-bench`; use `-Root`
for isolated smoke runs and `-Clean` to remove only known generated children
inside a marked dataset root. The benchmark runner creates a unique
`bench-runs\<timestamp>` directory, never mirrors into source paths, and emits
both JSON and Markdown reports under `reports\` unless `-OutputRoot` is set.

Small CI/developer smoke example:

```powershell
.\scripts\generate_copy_benchmark_dataset.ps1 `
  -Root C:\tmp\tallow-copy-bench-smoke `
  -LargeFileBytes 4096 `
  -DeltaFileBytes 4096 `
  -SmallFileCount 4 `
  -MixedFileCount 4 `
  -Clean

.\scripts\benchmark_copy_engine.ps1 `
  -DatasetRoot C:\tmp\tallow-copy-bench-smoke `
  -Runs 1 `
  -Threads 2
```

Minimum smoke dataset:

- one 1 GiB file;
- 10,000 files at 1-16 KiB;
- one mixed tree with nested directories and varied file sizes;
- one sparse file where the filesystem supports sparse allocation;
- one unchanged destination for warm no-op sync;
- one destination with 1 percent changed files;
- one large file with 1 percent changed bytes.

Full dataset:

- one large file at 1 GiB, 8 GiB, and optional 32 GiB;
- 10,000 and 100,000 small files;
- mixed trees with depth 2-8 and varied file sizes;
- symlink or junction tree;
- sparse file;
- same-volume, cross-volume, and SMB/NAS runs where available.

## Baselines

Windows baseline commands:

```powershell
robocopy <src> <dst> /E /MT:1
robocopy <src> <dst> /E /MT:8
robocopy <src> <dst> /MIR /MT:16
Copy-Item -Recurse <src> <dst>
.\target\release\tallow.exe delta-sync <src> <dst> --threads 8
```

The smoke benchmark script currently exercises:

- `tallow copy <src> <dst>` for mixed-tree full copy;
- `tallow delta-sync <src> <dst> --threads <n> --quiet` for full sync;
- `tallow delta-sync <src> <preseeded-dst> --threads <n> --quiet` for warm
  no-op sync;
- `robocopy <src> <dst> /E /MT:<n>` when `robocopy.exe` is available and
  `-SkipRobocopy` is not set.

Optional baseline:

```powershell
fastcopy.exe /cmd=diff /auto_close <src> /to=<dst>
```

Tallow engine commands should record the exact binary, profile, commit, and
policy used. The `max` profile is the competitive benchmark profile.

## Metrics

Record these values for each measured run:

- scan seconds;
- plan seconds;
- copy seconds;
- verify seconds;
- total seconds;
- logical source bytes;
- physical bytes written when available;
- bytes per second;
- files per second;
- skipped files;
- copied files;
- deleted files;
- verification failures;
- retry count;
- peak RSS;
- CPU percent;
- storage device and filesystem;
- source/destination path class: same volume, cross volume, SMB/NAS, or other.

Use at least five measured runs after one warm-up run. Report median and p95.

## Acceptance Gates

Initial gates:

- full large-file copy is within 10 percent of the fastest baseline on the same
  hardware when verification is disabled;
- many-small-file copy beats `robocopy /MT:8` on median for the smoke dataset;
- warm no-op sync is at least 100x faster than a full recopy;
- one-percent changed tree is at least 10x faster than full copy;
- resume does not recopy committed files;
- full-hash verification re-reads destination bytes and is reported separately
  from copy speed.

Stretch gates:

- sparse/reflink/copy-range cases can exceed 1000x against tools that physically
  copy bytes;
- no-op sync can exceed 1000x on large unchanged trees with a manifest cache;
- block-delta sync can exceed 1000x when the changed byte range is tiny compared
  to the file.

## Reporting Rules

Never advertise "1000x faster copy" as a universal raw-throughput result.
Hardware-bound full byte-for-byte copy cannot exceed the slowest source read,
destination write, network, filesystem metadata, and verification limit.

Report each class separately and include the policy that made it fast, such as
skip cache, manifest, sparse preservation, clone/range copy, or block delta.

## Rust Perf Smoke

*(Not yet in tree — `tests/perf_copy_engine.rs` does not exist in this checkout
(verified 2026-09-13). The smoke test below is planned; track it as a
release-gate follow-up and do not cite a green run until it lands.)*

The ignored integration smoke test will validate that the harness files exist and
that the in-process copy engine can plan, copy, and skip a tiny temp dataset:

```powershell
cargo test --test perf_copy_engine copy_engine_perf_smoke_tiny_dataset -- --ignored --nocapture
```
