# Tallow Copy Tauri App Design

**Status:** Approved visual direction, implemented as the current Tauri app shell  
**Approved mockup:** `docs/mockups/tallow-copy-premium.html`  
**Preview artifact:** `docs/mockups/tallow-copy-premium-preview.png`  
**Related engine plan:** `docs/plans/2026-05-12-tallow-ultrafast-copy-tool.md`

## Goal

Build a premium native desktop app for Tallow-powered copy, mirror, sync, verify, and resume workflows. The app should feel like a serious performance utility rather than a consumer backup wizard: dense, calm, fast to scan, and built around exact job state.

The first production target is now implemented under `apps/tallow-copy/` as a Tauri shell backed by Rust commands and simulated event streams. Tallow owns job policy, presets, and scriptability; Rust owns the hot copy path; the frontend owns job setup, progress visibility, and review workflows.

## Product Positioning

The app is a FastCopy-class desktop utility for people moving large trees, media archives, backups, NAS shares, build artifacts, and verified mirrors. The strongest product claim is not raw "1000x faster full copy" because full byte-for-byte copy is bounded by hardware. The credible claim is that Tallow Copy can produce extreme wins on no-op syncs, incremental updates, resumable jobs, sparse/reflink-capable paths, delta transfers, and verified workflows that avoid repeated full rehashing.

## Approved Visual Direction

The approved direction is "premium native utility":

- Dark graphite shell with restrained green performance accent.
- Rounded, circular controls across the interface.
- Compact desktop density, not a marketing layout.
- Visible source and target paths at the top of the work area.
- File/job table as the center of gravity.
- Right-side performance/options panel.
- Bottom status bar with current mode, progress, errors, engine backend, and total workload.
- Tallow-specific affordances: script presets, job plans, verification, resume journal, and engine backend visibility.

The current mockup is the visual baseline and has been ported into componentized TypeScript. Production UI should preserve its proportions, hierarchy, and mood unless a specific usability reason requires a change.

## Core Views

### Active Job Console

This is the first screen and the app's main workspace. It shows the active copy/mirror/sync job, source and target paths, current file queue, right-panel engine telemetry, and status bar.

Primary actions:

- Plan
- Execute
- Pause
- Resume
- Cancel
- Add Folder
- Browse source
- Browse target
- Filter plan

### Plan Review

Before destructive or expensive operations, users should be able to inspect what will happen. The view groups planned operations by copy, skip, verify, delete, conflict, error risk, and metadata-only change.

Mirror deletes must require explicit review before execution unless the user has deliberately enabled an "allow mirror deletes without review" setting.

### Job History

History stores completed and failed jobs with summary metrics:

- source and target
- mode
- files copied/skipped/failed
- bytes copied
- elapsed time
- average and peak throughput
- verification mode
- manifest/journal location

### Needs Review

This view collects locked files, permission failures, verification mismatches, path conflicts, long-path errors, and metadata preservation failures. It should support retry, skip, reveal in file manager, and copy error details.

### Tallow Script Presets

Presets expose `.tl` jobs for repeat workflows. The initial version can treat presets as editable text files and execute only trusted/local presets. Later versions can add structured preset editing.

## Architecture

Use a Tauri v2 app under `apps/tallow-copy/`. The frontend should start as a faithful componentized port of the approved HTML mockup, then wire real commands and events.

The app has three layers:

- Frontend: renders the console, plan review, history, settings, and error handling.
- Tauri command layer: validates user input, invokes Rust job APIs, sends progress events, and handles OS integration such as file dialogs.
- Copy engine/Tallow layer: plans and executes jobs, stores resume journals, performs verification, and exposes Tallow preset execution.

The first production backend uses command stubs and simulated progress while the native copy engine is still being consolidated. The UI contract is shaped around the real engine plan so the mock layer can be swapped out cleanly through `src-tauri/src/jobs/engine.rs`.

## Implemented Slice

- Tauri v2 and Vite TypeScript app under `apps/tallow-copy/`.
- Componentized approved mockup with active console, plan review, history, needs review, and script presets.
- Shared TypeScript and Rust job contracts for request, plan, progress, summary, errors, settings, and capabilities.
- Tauri commands for planning, execution, pause, resume, cancel, path selection, settings, job listing, and capabilities.
- In-memory Rust store and simulated progress engine behind a `CopyEngine` adapter.
- Destructive mirror-delete plan review gating.
- Built-in Tallow preset previews that update job policy without executing arbitrary scripts.
- Playwright visual/layout checks for active console, compact desktop, plan review, and needs review.

## Backend Command Contract

Initial commands:

- `get_engine_capabilities() -> EngineCapabilities`
- `select_path(kind: "source" | "target") -> PathSelection`
- `plan_job(request: JobRequest) -> JobPlan`
- `execute_job(plan_id: string) -> JobHandle`
- `pause_job(job_id: string) -> JobState`
- `resume_job(job_id: string) -> JobState`
- `cancel_job(job_id: string) -> JobState`
- `list_jobs(filter?: JobFilter) -> JobSummary[]`
- `get_job(job_id: string) -> JobDetail`
- `get_settings() -> AppSettings`
- `update_settings(patch: AppSettingsPatch) -> AppSettings`

Events:

- `job:planned`
- `job:started`
- `job:progress`
- `job:file-started`
- `job:file-finished`
- `job:error`
- `job:paused`
- `job:completed`
- `job:cancelled`

Events should be throttled before they reach the frontend. The UI should not receive one event per block write.

## Data Model

Core frontend types:

- `TransferMode`: `copy | mirror | sync`
- `VerifyMode`: `none | size | sampled_hash | full_hash | read_after_write | manifest`
- `MetadataMode`: `data_only | timestamps | attributes | security | all`
- `BackendMode`: `auto | thread_pool | iocp | direct_io`
- `JobRequest`: source, target, mode, filters, verify mode, metadata mode, thread count, buffer size, delete policy.
- `JobPlan`: planned operations and risk summary.
- `JobProgress`: bytes, files, skipped, errors, rate, ETA, active files, backend, phase.
- `JobError`: path, category, message, retryable, recommended action.

## Tallow Integration

Tallow should be visible as a power layer, not as friction in the basic copy workflow.

Initial behavior:

- Users can choose built-in presets such as media mirror, build artifact sync, verified backup, and resume interrupted job.
- Presets compile into `JobRequest` objects.
- A `.tl` preset is shown in the Script Presets view for advanced users.
- Arbitrary `.tl` execution remains disabled in this slice.

Later behavior:

- Allow trusted `.tl` scripts to define filters, verification rules, metadata policy, logging, and pre/post hooks.
- Expose the copy engine as a Tallow stdlib module once the native engine contract stabilizes.
- Keep destructive operations gated by the UI even when triggered by a script.

## Error Handling

Errors should be structured and actionable. Avoid dumping raw OS errors without categorization.

Categories:

- permission denied
- locked file
- path too long
- destination full
- network interrupted
- verification mismatch
- metadata failed
- symlink/junction policy blocked
- delete requires review

Every error row should offer the next reasonable action: retry, skip, reveal path, change setting, or review details.

## Performance UX

The UI must not compete with the copy engine for resources. Progress events should be throttled to a stable frame cadence, large file lists should be virtualized, and expensive aggregation should be done in the backend or memoized.

The app should display honest performance:

- current throughput
- average throughput
- files per second
- skipped files
- copied bytes versus total logical bytes
- verify time separated from copy time
- backend currently in use

This separation prevents misleading results when a job is fast because it skipped or cloned data rather than physically copying every byte.

## Accessibility And Interaction

The app should support keyboard-first operation:

- Tab through toolbar, path pickers, table, right panel, and status controls.
- Enter executes primary focused action.
- Space toggles switches.
- Escape cancels modal dialogs and closes menus.
- Destructive actions require a focused confirmation flow.

Text must remain legible at common desktop scaling settings. Icon-only buttons need accessible labels and tooltips. Color should never be the only error or progress signal.

## Non-Goals For First Production Slice

- No cloud backup provider integration.
- No remote agent protocol.
- No untrusted script execution.
- No benchmark marketing claims inside the UI.
- No hand-rolled low-level copy engine in the frontend.
- No attempt to make interpreted Tallow perform byte-level copy loops.

## Acceptance Criteria

- The first screen matches the approved premium circular mockup closely.
- The app can create a job request from source, target, mode, verification, metadata, thread, buffer, and backend controls.
- The app can display a planned job, simulated or real progress, errors, and completion state.
- The command/event contract is typed and documented enough for the native engine work to integrate later.
- Browser or Tauri preview verification confirms the UI renders without overflow at desktop and narrower widths.
