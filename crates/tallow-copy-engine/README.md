<div align="center">

# tallow-copy-engine

**Plan a copy before performing it — then perform exactly the plan.**

![license](https://img.shields.io/badge/license-MIT-black?style=flat-square)
![verify](https://img.shields.io/badge/verify-size%20%C2%B7%20sampled%20%C2%B7%20full%20BLAKE3-1f6feb?style=flat-square)

</div>

---

Copying a directory looks trivial until it is 400 GB, half of it unchanged, on a link that fails at 93%. The difference between a copy script and a copy engine is that the engine can tell you what it *will* do, do exactly that, and prove what it did.

## What it is

| Type | Choices |
|---|---|
| `CopyMode` | `Copy`, `Mirror`, `Sync`, `Verify`, `Resume`, `DryRun` |
| `SkipPolicy` | `SizeMtime`, `SizeMtimeHash`, `Hash`, `Manifest` |
| `VerifyPolicy` | `None`, `Size`, `SampledHash`, `FullHash`, `ReadAfterWrite`, `Manifest` |
| `MetadataPolicy` | `DataOnly`, `Timestamps`, `Attributes` (POSIX permissions); SELinux/ACL preservation is explicitly rejected, not silently skipped |
| `LinkPolicy` | how symlinks and links are treated |
| `ErrorPolicy` | fail fast or continue and report |

The engine is two phases, deliberately separated:

```rust
pub fn plan(job: CopyJob) -> Result<CopyPlan, CopyError>;
pub fn execute(plan: &CopyPlan) -> CopyReport;
```

`plan` walks the source, applies skip/verify policies and produces a list of typed `CopyAction`s with byte counts and reasons. `execute` performs that list. Nothing is discovered mid-copy, so the cost of an operation is known before it starts.

## What it is not

- **Not rsync.** No remote transport, no delta protocol; it copies between filesystems visible to the process.
- **Not a backup system.** It has no retention policy, no snapshots, no versioning.
- **Not honest about everything.** `SampledHash` reads head/middle/tail windows — it detects same-size corruption inside those windows and misses it outside them. The choice is documented in the type, not hidden in the docs.
- **Not a manifest store.** `Manifest` policies are implemented as content-hash comparison against a supplied manifest file; there is no persistent manifest database.

## Quick start

```rust
use tallow_copy_engine::{plan, execute, CopyJob, CopyMode, VerifyPolicy};

let mut job = CopyJob::copy("/srv/data", "/mnt/backup/data");
job.mode = CopyMode::Mirror;
job.verify = VerifyPolicy::FullHash;

let plan = plan(job)?;
println!("{} files, {} bytes, {} skipped", plan.total_files, plan.total_bytes, plan.skipped_files);

let report = execute(&plan);
println!("copied {} files ({} bytes), {} errors", report.copied_files, report.bytes_copied, report.errors.len());
```

### Dry run first

```rust
let mut job = CopyJob::copy("/srv/data", "/mnt/backup/data");
job.dry_run = true;

let plan = plan(job)?;
for action in &plan.actions {
    println!("{:?} {} ({})", action.kind, action.relative_path.display(), action.reason);
}
```

A dry run is the same planner with execution suppressed — not a separate codepath that can disagree with the real one.

### Cancellation and progress

```rust
use tallow_copy_engine::{execute_with_control, CopyControl};

let control = CopyControl::new();
// from another thread: control.cancel();
let report = execute_with_control(&plan, &control, |event| {
    // progress events are emitted here; keep the closure cheap
});
```

A cancelled copy reports `CopyErrorCategory::Cancelled` rather than a partial success.

## Configuration

| Field | Default | Note |
|---|---|---|
| `threads` | available parallelism | Worker count |
| `buffer_size_bytes` | 1 MiB (`DEFAULT_BUFFER_SIZE_BYTES`) | Minimum 4 KiB |
| `verify` | `Size` | Metadata check after every copy |
| `skip` | `SizeMtime` | Fast, and wrong when mtimes lie |
| `error_policy` | fail fast | Continue-and-report is opt-in |

There are no environment variables. A copy that behaves differently depending on the shell that launched it is a copy you cannot reproduce.

## Deploying it

Library only. It is embedded in `tallow-daemon`'s sync executor and in `tallow copy`, and it is the piece to reach for when a service needs a copy that can be planned and audited rather than a `cp -a` in a shell.

```toml
[dependencies]
tallow-copy-engine = { path = "crates/tallow-copy-engine" }
```

Operational guidance that follows from the design:

- **Use `FullHash` for anything you cannot re-create.** `Size` catches truncation; it does not catch same-size corruption.
- **Use `Manifest` when a manifest already exists.** It turns verification into a comparison against a known-good state rather than a fresh assumption.
- **Plan on the same host you execute on.** Paths, free space and permissions are properties of that host.

## Verification

```console
$ cargo test -p tallow-copy-engine
$ cargo test -p tallow-copy-engine -- --nocapture
```

13 test functions in the crate source [measured 2026-10-21]: skip policies, verify policies (including the sampled-hash limitation), mirror deletions, metadata handling, cancellation, and error categorisation.

## Limits

| Limit | Detail |
|---|---|
| Local filesystems only | No remote endpoints |
| Sampled hash is sampled | Documented, deliberate, and weaker than `FullHash` |
| No ACL/SELinux preservation | Rejected explicitly (`Unsupported`), never silently dropped |
| No persistent manifest DB | Manifests are files you supply |

## License

MIT — see the repository `LICENSE` and `NOTICE`.
