# Tallow Ultrafast Copy Tool Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Tallow-authored copy/sync tool that can beat robocopy/FastCopy-class tools in incremental, verified, restartable, and large-tree workflows while staying near hardware limits for full byte-for-byte copies.

**Architecture:** Tallow should own policy, CLI shape, job configuration, progress presentation, and orchestration. The hot path must be one consolidated native Rust copy engine exposed through Tallow stdlib and runtime FFI; interpreted Tallow byte loops will not be competitive. The existing `copy`, `transfer.fast_copy`, `delta-sync`, block sync, and two-way sync paths should converge on that engine instead of continuing as separate implementations.

**Tech Stack:** Tallow `.tl` stdlib/API surface, Rust native stdlib/runtime modules, Rayon/crossbeam scheduling, BLAKE3, SQLite/JSONL job state, Windows `windows-sys` filesystem APIs, Unix `xattr`/platform syscalls, optional Linux `io_uring`, and existing Cargo `release`/`max` profiles.

---

## Research Summary

Tallow already has the language surface needed for a tool: modules/imports, structs/enums, `Result`, `?`, `match`, `spawn`, channels, privacy/legal passes, and stdlib dispatch. The relevant language/compiler files are `src/ast.rs`, `src/parser.rs`, `src/typeck.rs`, `src/interp.rs`, `src/codegen.rs`, and `src/main.rs`.

The current copy ecosystem is split:

- `src/stdlib/copy.rs`: correctness-heavy `copy.file`/`copy.dir` with BLAKE3, Merkle sidecars, metadata preservation, and verification wrappers.
- `src/stdlib/transfer.rs`: `fast_copy`, `fast_copy_dir`, block sync via `fast_rsync`, checkpoints, mmap hashing, two-way sync, and cloud/transfer helpers.
- `src/main.rs`: CLI `copy` and `delta-sync` handlers with parallel directory traversal/copy, filters, retries, mirror, verify, symlink, ACL, logging, and block-level options.
- `src/stdlib/io_backend.rs`: backend enum for `io_uring`, IOCP, and thread-pool, but Windows IOCP is a stub and most paths still use whole-file read/write or `std::fs::copy`.
- `src/runtime/transfer_ffi.rs`: compiled runtime FFI exists but is much narrower than interpreter stdlib behavior.

The critical gap: the current code has impressive features but no single high-performance local copy engine. Several paths read entire files into memory, directory schedulers are duplicated, verification sometimes hashes the source buffer instead of re-reading the destination, and compiled/interpreted surfaces are not at parity.

## Reality Check On The 1000x Target

For a full cold copy where every byte must be read from source and written to destination, no software can be 1000x faster than well-tuned robocopy/FastCopy on the same hardware. The upper bound is the slower of source read bandwidth, destination write bandwidth, network throughput, filesystem metadata latency, and CPU cost for verification/compression.

The credible path to 1000x wins is:

- no-op sync where unchanged files are skipped without opening file data;
- incremental sync where only changed files or blocks move;
- restart/resume after failure without starting over;
- many-small-file trees where metadata caching, batched directory creation, and parallel scheduling dominate;
- sparse/reflink/clone/copy-range paths where physical data movement is avoided;
- large network syncs where compression/delta/block-level transfer avoids most bytes;
- verified copy workflows where BLAKE3/Merkle state avoids repeated full rehashes.

The benchmark plan must report these classes separately from raw full-copy throughput.

## Phase 0: Baseline And Contract

**Files:**
- Create: `docs/benchmarks/copy-benchmark-protocol.md`
- Create: `docs/architecture/tallow-copy-engine.md`
- Create: `tests/copy_engine_contract.rs`
- Modify: `docs/TALLOW-CAPABILITIES.md`

**Step 1: Write the copy contract**

Define supported modes:

- `copy`: copy source to destination.
- `mirror`: destination becomes source-equivalent, including deletes.
- `sync`: skip unchanged items using selected policy.
- `verify`: verify after copy or verify prior manifests.
- `resume`: continue an interrupted job.
- `dry_run`: report planned work only.

Define policies:

- `skip`: `size_mtime`, `size_mtime_hash`, `hash`, `manifest`.
- `verify`: `none`, `size`, `sampled_hash`, `full_hash`, `read_after_write`, `manifest`.
- `metadata`: `data_only`, `timestamps`, `attributes`, `security`, `owner`, `all`.
- `links`: `skip`, `preserve`, `follow`.
- `errors`: `best_effort`, `strict`.

**Step 2: Write benchmark protocol**

Include datasets:

- one large file: 1 GiB, 8 GiB, optional 32 GiB;
- many small files: 10k and 100k files at 1-16 KiB;
- mixed tree: nested directories with varied file sizes;
- sparse file;
- symlink/junction tree;
- warm no-op sync;
- 1 percent changed files;
- 1 percent changed bytes inside large files;
- same-volume, cross-volume, and SMB/NAS cases.

Baselines:

```powershell
robocopy <src> <dst> /E /MT:1
robocopy <src> <dst> /E /MT:8
robocopy <src> <dst> /MIR /MT:16
Copy-Item -Recurse <src> <dst>
.\target\release\tallow.exe delta-sync <src> <dst> --threads 8
```

Metrics:

- scan seconds;
- plan seconds;
- copy seconds;
- verify seconds;
- total seconds;
- bytes/s;
- files/s;
- skipped files;
- copied files;
- error count;
- retry count;
- peak RSS;
- CPU percent;
- median/p95 across at least 5 measured runs.

**Step 3: Write failing contract tests**

Create tests that assert:

- unchanged file is skipped by `size_mtime`;
- changed size triggers copy;
- changed mtime triggers copy;
- dry-run does not write;
- mirror delete is planned;
- verify mismatch is reported as structured error;
- destination hash must be computed from destination bytes, not source buffer.

**Step 4: Run targeted tests**

Run:

```powershell
cargo test --test copy_engine_contract -- --nocapture
```

Expected: fail because the engine does not exist yet.

**Step 5: Commit**

```powershell
git add docs/benchmarks/copy-benchmark-protocol.md docs/architecture/tallow-copy-engine.md docs/TALLOW-CAPABILITIES.md tests/copy_engine_contract.rs
git commit -m "docs: define tallow copy engine contract"
```

## Phase 1: Consolidated Native Copy Engine Skeleton

**Files:**
- Create: `src/stdlib/copy_engine.rs`
- Modify: `src/stdlib/mod.rs`
- Modify: `src/stdlib/copy.rs`
- Modify: `src/stdlib/transfer.rs`
- Modify: `src/main.rs`
- Create: `tests/copy_engine_basic.rs`

**Step 1: Define engine types**

Create Rust structs:

```rust
pub struct CopyJob {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub mode: CopyMode,
    pub skip: SkipPolicy,
    pub verify: VerifyPolicy,
    pub metadata: MetadataPolicy,
    pub link_policy: LinkPolicy,
    pub error_policy: ErrorPolicy,
    pub threads: usize,
    pub dry_run: bool,
}

pub struct CopyPlan {
    pub actions: Vec<CopyAction>,
    pub total_files: u64,
    pub total_bytes: u64,
    pub skipped_files: u64,
}

pub struct CopyReport {
    pub copied_files: u64,
    pub skipped_files: u64,
    pub deleted_files: u64,
    pub bytes_copied: u64,
    pub errors: Vec<CopyError>,
}
```

**Step 2: Implement `scan`, `plan`, `execute` skeletons**

Use existing mtime/size traversal logic from `src/main.rs` and return typed results. Keep copy execution initially backed by `copy_file_with_fallback`.

**Step 3: Route existing paths through the skeleton**

Change:

- `src/stdlib/copy.rs` `copy.dir`;
- `src/stdlib/transfer.rs` `fast_copy` and `fast_copy_dir`;
- `src/main.rs` `copy` and `delta-sync` copy phase;

so they call `copy_engine` functions instead of each owning traversal/copy behavior.

**Step 4: Run focused checks**

Run:

```powershell
cargo test --test copy_engine_basic -- --nocapture
cargo test --lib copy -- --nocapture
cargo check
```

Expected: pass.

**Step 5: Commit**

```powershell
git add src/stdlib/copy_engine.rs src/stdlib/mod.rs src/stdlib/copy.rs src/stdlib/transfer.rs src/main.rs tests/copy_engine_basic.rs
git commit -m "feat: add consolidated copy engine skeleton"
```

## Phase 2: Streaming File Copy And Real Verification

**Files:**
- Modify: `src/stdlib/copy_engine.rs`
- Modify: `src/stdlib/io_backend.rs`
- Modify: `src/stdlib/copy.rs`
- Modify: `src/stdlib/transfer.rs`
- Create: `tests/copy_engine_streaming.rs`

**Step 1: Write failing large-file streaming tests**

Test a generated file larger than the configured chunk size. Assert:

- copy succeeds;
- destination content matches source;
- full BLAKE3 verify re-reads destination;
- peak memory is bounded indirectly by using a fake/small chunk configuration in test.

**Step 2: Implement bounded-buffer copy**

Add a copy loop with a configurable chunk size, defaulting to a practical value such as 1-8 MiB. Update source and destination hashers from actual bytes:

- source hasher updates during read;
- destination hasher updates during destination re-read when `VerifyPolicy::FullHash` or `ReadAfterWrite` is enabled;
- Merkle chunks are produced from streamed source chunks.

**Step 3: Preserve existing `.merkle` compatibility**

Keep `copy.verify_file` and `copy.verify_dir` working with existing `.merkle` sidecars while allowing manifests to be optional for speed mode.

**Step 4: Run focused tests**

```powershell
cargo test --test copy_engine_streaming -- --nocapture
cargo test --lib copy_file_streaming -- --nocapture
cargo test --test stdlib_dispatch -- --nocapture
```

**Step 5: Commit**

```powershell
git add src/stdlib/copy_engine.rs src/stdlib/io_backend.rs src/stdlib/copy.rs src/stdlib/transfer.rs tests/copy_engine_streaming.rs
git commit -m "feat: stream copy data with real verification"
```

## Phase 3: Restartable Jobs

**Files:**
- Modify: `src/stdlib/copy_engine.rs`
- Create: `src/stdlib/copy_journal.rs`
- Modify: `src/stdlib/mod.rs`
- Create: `tests/copy_engine_resume.rs`

**Step 1: Define journal schema**

Use SQLite through existing `rusqlite`, or JSONL if the first pass must stay simpler. Track:

- job id;
- source root;
- destination root;
- relative path;
- size;
- mtime;
- source identity where available;
- status: discovered, queued, copying, copied, metadata_applied, verified, committed, failed;
- temp destination;
- bytes copied;
- hash state or chunk list when verification requires it.

**Step 2: Copy via temp destination**

Write to a temp file in the destination directory, apply data, optionally flush, verify, apply metadata, then atomic rename.

**Step 3: Implement resume**

On resume:

- skip committed files whose destination still matches policy;
- retry failed or partial files;
- remove stale temp files unless resume can safely continue them.

**Step 4: Run focused tests**

```powershell
cargo test --test copy_engine_resume -- --nocapture
cargo test --lib copy_journal -- --nocapture
```

**Step 5: Commit**

```powershell
git add src/stdlib/copy_engine.rs src/stdlib/copy_journal.rs src/stdlib/mod.rs tests/copy_engine_resume.rs
git commit -m "feat: add restartable copy jobs"
```

## Phase 4: Metadata, Paths, Links, And Sparse Files

**Files:**
- Modify: `src/stdlib/platform/windows/ntfs_attrs.rs`
- Modify: `src/stdlib/platform/unix/xattr.rs`
- Modify: `src/stdlib/platform/unix/mod.rs`
- Modify: `src/stdlib/path_util.rs`
- Modify: `src/stdlib/copy_engine.rs`
- Create: `tests/copy_engine_metadata.rs`

**Step 1: Write platform-gated tests**

Cover:

- mtime preservation;
- Unix mode/xattr when available;
- Windows ADS/ACL where permissions allow;
- symlink preserve/follow/skip;
- sparse file preservation;
- long path normalization.

**Step 2: Implement explicit metadata policy**

Return structured partial failures instead of stderr-only warnings. Strict mode fails the job on metadata errors; best-effort mode records warnings.

**Step 3: Implement sparse-aware copy**

Use:

- Windows allocated range APIs where available;
- Unix `SEEK_DATA`/`SEEK_HOLE` where available;
- normal streaming fallback otherwise.

**Step 4: Run platform tests**

```powershell
cargo test --test copy_engine_metadata -- --nocapture
cargo check
```

**Step 5: Commit**

```powershell
git add src/stdlib/platform/windows/ntfs_attrs.rs src/stdlib/platform/unix/xattr.rs src/stdlib/platform/unix/mod.rs src/stdlib/path_util.rs src/stdlib/copy_engine.rs tests/copy_engine_metadata.rs
git commit -m "feat: preserve copy metadata and sparse files"
```

## Phase 5: Scheduler And Fast IO Backends

**Files:**
- Modify: `src/stdlib/copy_engine.rs`
- Modify: `src/stdlib/io_backend.rs`
- Modify: `src/runtime/io_uring_runtime.rs`
- Create: `tests/copy_engine_scheduler.rs`

**Step 1: Split scheduler lanes**

Add lanes for:

- metadata scanning;
- small-file copy;
- large-file streaming;
- verification;
- deletes;
- metadata application.

**Step 2: Add adaptive concurrency**

Start conservative:

- SSD/local: more copy workers;
- HDD/same disk: lower write concurrency;
- SMB/NAS: higher metadata concurrency but controlled write queue;
- large files: limited concurrent streams.

Expose explicit overrides.

**Step 3: Implement real backend capability detection**

Expose:

- direct IO available;
- io_uring available;
- IOCP available;
- sparse supported;
- ACL/xattr supported;
- symlink privilege;
- VSS available;
- long paths enabled.

**Step 4: Implement queued io_uring and Windows overlapped IO**

Linux:

- chunked reads/writes;
- queue depth;
- fallback on unsupported filesystems.

Windows:

- real overlapped read/write;
- completion port queue or documented fallback;
- optional unbuffered IO only when alignment requirements are met.

**Step 5: Run tests and smoke benchmarks**

```powershell
cargo test --test copy_engine_scheduler -- --nocapture
cargo check --features io-uring-backend
cargo build --profile max
```

**Step 6: Commit**

```powershell
git add src/stdlib/copy_engine.rs src/stdlib/io_backend.rs src/runtime/io_uring_runtime.rs tests/copy_engine_scheduler.rs
git commit -m "feat: add adaptive copy scheduler and fast io backends"
```

## Phase 6: Tallow API And Compiled Parity

**Files:**
- Create: `stdlib/copy.tl`
- Modify: `stdlib/transfer.tl`
- Modify: `stdlib/fs.tl`
- Modify: `src/runtime/transfer_ffi.rs`
- Modify: `src/codegen.rs`
- Modify: `src/typeck.rs`
- Create: `tests/fixtures/copy_engine_tool.tl`
- Create: `tests/copy_engine_codegen.rs`

**Step 1: Define Tallow-facing types**

Add public types:

```text
CopyOptions
CopyPlan
CopyReport
CopyCapabilities
CopyError
CopyProgress
```

Add APIs:

```text
copy.capabilities() -> CopyCapabilities
copy.scan(src, dst, options) -> CopyPlan
copy.execute(plan, options) -> CopyReport
copy.sync(src, dst, options) -> CopyReport
copy.verify(path, options) -> VerifyReport
copy.resume(job_id) -> CopyReport
```

**Step 2: Implement interpreter dispatch**

Route new `copy.*` calls through `src/stdlib/mod.rs` to `copy_engine`.

**Step 3: Implement compiled FFI**

Expose runtime functions for compiled binaries:

- create job/options;
- scan;
- execute;
- resume;
- free result strings;
- retrieve structured errors as JSON.

Update `src/codegen.rs` so compiled Tallow can call the same copy APIs, not just `std::fs::copy`.

**Step 4: Add a Tallow-authored CLI script**

Create a `.tl` fixture/tool that parses arguments, configures options, calls native copy APIs, prints reports, and returns stable exit codes.

**Step 5: Run parity tests**

```powershell
cargo test --test copy_engine_codegen -- --nocapture
cargo run -- run tests/fixtures/copy_engine_tool.tl -- <src> <dst>
cargo run -- build tests/fixtures/copy_engine_tool.tl
```

**Step 6: Commit**

```powershell
git add stdlib/copy.tl stdlib/transfer.tl stdlib/fs.tl src/runtime/transfer_ffi.rs src/codegen.rs src/typeck.rs tests/fixtures/copy_engine_tool.tl tests/copy_engine_codegen.rs
git commit -m "feat: expose copy engine to tallow programs"
```

## Phase 7: Benchmark Harness And Competitive Proof

**Files:**
- Create: `scripts/benchmark_copy_engine.ps1`
- Create: `scripts/generate_copy_benchmark_dataset.ps1`
- Create: `tests/perf_copy_engine.rs`
- Modify: `docs/benchmarks/copy-benchmark-protocol.md`

**Step 1: Generate deterministic datasets**

Create datasets outside the repo by default, e.g. `C:\tmp\tallow-copy-bench`.

**Step 2: Run benchmark matrix**

Include:

- Tallow current CLI;
- new Tallow copy engine;
- robocopy `/MT:1`, `/MT:8`, `/MT:16`;
- PowerShell `Copy-Item`;
- optional FastCopy if installed and path is supplied.

**Step 3: Produce JSON and Markdown reports**

Report raw full-copy separately from no-op, incremental, block-delta, sparse, and verified workflows.

**Step 4: Set acceptance gates**

Initial targets:

- full large-file copy: within 10 percent of fastest baseline on same hardware;
- many small files: faster than robocopy `/MT:8` on median when verification disabled;
- warm no-op sync: at least 100x faster than full recopies;
- 1 percent changed tree: at least 10x faster than full copy;
- resume after interruption: does not recopy committed files;
- full-hash verify: correctness-first, reported separately from speed mode.

Stretch targets:

- sparse/reflink/copy-range cases can exceed 1000x versus tools that physically copy bytes;
- no-op sync can exceed 1000x on large unchanged trees if scan/cache design is strong.

**Step 5: Run benchmark smoke**

```powershell
cargo build --profile max
powershell -ExecutionPolicy Bypass -File .\scripts\generate_copy_benchmark_dataset.ps1 -Root C:\tmp\tallow-copy-bench -Profile smoke
powershell -ExecutionPolicy Bypass -File .\scripts\benchmark_copy_engine.ps1 -Root C:\tmp\tallow-copy-bench -Profile smoke
```

**Step 6: Commit**

```powershell
git add scripts/benchmark_copy_engine.ps1 scripts/generate_copy_benchmark_dataset.ps1 tests/perf_copy_engine.rs docs/benchmarks/copy-benchmark-protocol.md
git commit -m "test: benchmark tallow copy engine"
```

## Execution Order

1. Phase 0 first. It prevents chasing a vague performance claim.
2. Phase 1 next. Consolidation reduces duplication and makes every future optimization matter everywhere.
3. Phase 2 before IOCP/io_uring. Streaming correctness is a prerequisite for fast backend work.
4. Phase 3 before platform metadata polish. Restartability changes the write/commit lifecycle.
5. Phase 4 then Phase 5. Platform fidelity and scheduler/backend optimization can proceed in parallel only after the engine shape is stable.
6. Phase 6 after the native API is real. Tallow should expose a stable engine, not placeholder promises.
7. Phase 7 throughout, with smoke benchmarks after each major phase and full benchmarks before claims.

## Verification Checklist

- `cargo check`
- `cargo test --test copy_engine_contract -- --nocapture`
- `cargo test --test copy_engine_basic -- --nocapture`
- `cargo test --test copy_engine_streaming -- --nocapture`
- `cargo test --test copy_engine_resume -- --nocapture`
- `cargo test --test copy_engine_metadata -- --nocapture`
- `cargo test --test copy_engine_scheduler -- --nocapture`
- `cargo test --test copy_engine_codegen -- --nocapture`
- `cargo build --profile max`
- smoke benchmark script against robocopy and current Tallow CLI

## Non-Goals For The First Implementation

- Do not claim universal 1000x faster raw copy throughput.
- Do not implement a byte-copy loop in interpreted Tallow.
- Do not add another duplicate copy implementation in `src/main.rs`.
- Do not make verification always-on in speed mode; verification policy must be explicit.
- Do not require admin privileges for normal copy/sync.
- Do not treat Windows, Linux, macOS, SMB, and cloud targets as the same backend.

## First Milestone Definition Of Done

The first usable milestone is complete when:

- `copy_engine` is the shared implementation behind `copy.file`, `copy.dir`, `transfer.fast_copy`, `transfer.fast_copy_dir`, CLI `copy`, and the normal `delta-sync` copy phase;
- large files copy through bounded buffers;
- full verification re-reads destination bytes;
- unchanged files are skipped by size/mtime;
- dry-run and mirror plans are test-covered;
- benchmark smoke compares against robocopy on at least one generated dataset;
- docs state where 1000x wins are credible and where hardware bandwidth is the limit.
