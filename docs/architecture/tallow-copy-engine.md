# Tallow Native Copy Engine Architecture

The native copy engine is the shared Rust implementation behind Tallow copy,
mirror, sync, verify, resume, and future desktop app jobs. Tallow scripts own
policy and orchestration. Rust owns scanning, planning, byte movement,
verification, metadata, journals, and platform I/O.

## Goals

- One implementation shared by `copy.file`, `copy.dir`,
  `transfer.fast_copy`, `transfer.fast_copy_dir`, CLI `copy`, CLI
  `delta-sync`, and the Tauri Tallow Copy app.
- Bounded-memory data movement for large files.
- Honest policies for skip, verify, metadata, links, and error handling.
- Structured plans and reports that can power CLI, Tallow scripts, Tauri UI,
  and benchmark harnesses.
- Clear path to faster backends such as Windows overlapped I/O, Linux
  `io_uring`, sparse copy, block delta, and clone/copy-range.

## Modes

| Mode | Description |
| --- | --- |
| `copy` | Copy missing or changed source entries to destination. |
| `mirror` | Make destination source-equivalent, including deletes. |
| `sync` | Incrementally update destination according to skip policy. |
| `verify` | Verify destination against source or manifest without copying. |
| `resume` | Continue an interrupted journaled job. |
| `dry_run` | Plan work without writing or deleting. |

## Policies

| Policy | Values |
| --- | --- |
| Skip | `size_mtime`, `size_mtime_hash`, `hash`, `manifest` |
| Verify | `none`, `size`, `sampled_hash`, `full_hash`, `read_after_write`, `manifest` |
| Metadata | `data_only`, `timestamps`, `attributes`, `security`, `owner`, `all` |
| Links | `skip`, `preserve`, `follow` |
| Errors | `best_effort`, `strict` |

## Data Contract

`CopyJob` describes a job request: source, destination, mode, skip policy,
verify policy, metadata policy, link policy, error policy, thread count, and
dry-run flag.

`CopyPlan` is a deterministic list of actions. Actions are typed as copy, skip,
verify, delete, mkdir, metadata, or error. Mirror deletes must be visible in the
plan before execution.

`CopyReport` records copied, skipped, verified, deleted, bytes copied, and
structured errors.

`CopyError` records category, message, optional path, retryability, and a
recommended action. UI and CLI code should not parse raw OS error strings.

## Execution Pipeline

1. Normalize and validate paths.
2. Scan source and destination metadata.
3. Build a typed plan using the requested skip and mirror policies.
4. Execute actions through a bounded-memory file copy path.
5. Verify according to policy by reading destination bytes when full
   verification is requested.
6. Apply metadata according to policy.
7. Commit journal state and return a structured report.

## First Skeleton

The first skeleton intentionally favors correctness and consolidation over
maximum speed. It supports size/mtime skip, dry-run, mirror delete planning,
basic recursive copy, and destination-byte full-hash verification.

The later optimization phases replace the simple copy executor with streaming
copy, restart journals, metadata fidelity, sparse handling, and adaptive I/O
backends without changing the top-level contract.
