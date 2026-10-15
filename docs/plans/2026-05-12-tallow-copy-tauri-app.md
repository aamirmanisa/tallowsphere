# Tallow Copy Tauri App Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build a Tauri desktop app that turns the approved Tallow Copy premium mockup into a working copy/mirror/sync console with typed job planning, progress events, and a clean integration path to the native Tallow copy engine.

**Architecture:** Create a focused app under `apps/tallow-copy/` with a Tauri v2 Rust command layer and a componentized TypeScript frontend. Start with command stubs and simulated progress that match the final engine contract, then replace the stub executor with the consolidated native copy engine from `docs/plans/2026-05-12-tallow-ultrafast-copy-tool.md`. Keep Tallow scripts as preset/policy inputs, not byte-copy loops.

**Tech Stack:** Tauri v2, Rust, TypeScript, Vite frontend, CSS variables, Playwright/browser screenshots for visual verification, existing Tallow Rust crates/modules, future `copy_engine` crate/module.

**Implementation Status:** Tasks 1-13 are implemented in `apps/tallow-copy/`. Git commit steps were not performed because repository ACLs prevented staging/committing from this session.

---

## Ground Rules

- Approved design doc: `docs/plans/2026-05-12-tallow-copy-tauri-app-design.md`
- Approved mockup: `docs/mockups/tallow-copy-premium.html`
- Approved preview: `docs/mockups/tallow-copy-premium-preview.png`
- Native engine plan: `docs/plans/2026-05-12-tallow-ultrafast-copy-tool.md`
- App location: `apps/tallow-copy/`

Do not build a new visual direction. Port the approved mockup first, then make it functional.

Do not put copy hot paths in JavaScript or interpreted Tallow. The frontend calls Tauri commands; Tauri commands call Rust job APIs; Tallow presets shape job policy.

## Task 1: Scaffold The Tauri App

**Files:**

- Create: `apps/tallow-copy/package.json`
- Create: `apps/tallow-copy/index.html`
- Create: `apps/tallow-copy/src/main.ts`
- Create: `apps/tallow-copy/src/styles.css`
- Create: `apps/tallow-copy/src-tauri/Cargo.toml`
- Create: `apps/tallow-copy/src-tauri/tauri.conf.json`
- Create: `apps/tallow-copy/src-tauri/src/main.rs`
- Create: `apps/tallow-copy/src-tauri/src/lib.rs`
- Create: `apps/tallow-copy/README.md`

**Step 1: Create the app directory**

Run:

```powershell
New-Item -ItemType Directory -Force apps\tallow-copy, apps\tallow-copy\src, apps\tallow-copy\src-tauri\src
```

Expected: directories exist.

**Step 2: Add the minimal package files**

Create a Vite TypeScript frontend and a Tauri v2 backend. Use scripts:

```json
{
  "scripts": {
    "dev": "vite --host 127.0.0.1",
    "build": "tsc && vite build",
    "tauri": "tauri"
  }
}
```

**Step 3: Add the minimal Rust shell**

Create `src-tauri/src/main.rs` that calls the generated Tauri app entry point, and `src-tauri/src/lib.rs` that registers command handlers.

**Step 4: Verify scaffold builds enough to start**

Run:

```powershell
cd apps\tallow-copy
npm install
npm run build
```

Expected: frontend build passes.

**Step 5: Commit**

```powershell
git add apps/tallow-copy
git commit -m "feat: scaffold tallow copy tauri app"
```

## Task 2: Port The Approved Mockup Into Components

**Files:**

- Read: `docs/mockups/tallow-copy-premium.html`
- Modify: `apps/tallow-copy/src/main.ts`
- Modify: `apps/tallow-copy/src/styles.css`
- Create: `apps/tallow-copy/src/ui/App.ts`
- Create: `apps/tallow-copy/src/ui/mockData.ts`
- Create: `apps/tallow-copy/src/ui/icons.ts`

**Step 1: Extract stable mock data**

Create typed mock data for:

- sidebar sections
- toolbar modes
- source and target path segments
- file rows
- right panel stats
- queue preview
- settings
- status bar

**Step 2: Render the mockup from TypeScript**

Port the approved HTML into component functions. Keep the visual structure:

- titlebar
- sidebar
- toolbar
- path bar
- file list
- right panel
- status bar

**Step 3: Move CSS into `styles.css`**

Copy the approved CSS tokens and selectors. Preserve:

- graphite background
- green accent
- circular pills and icon wells
- compact table density
- right stats panel
- bottom status bar

**Step 4: Add accessible labels**

Add `aria-label` on icon-only controls, path browse buttons, transfer mode controls, switches, and row actions.

**Step 5: Verify visual parity**

Run:

```powershell
cd apps\tallow-copy
npm run dev -- --port 4280
```

Open `http://127.0.0.1:4280` in the browser and take screenshots at:

- 1280x820
- 1440x900
- 1024x768

Expected: no text overlap, no horizontal overflow, and the layout matches `docs/mockups/tallow-copy-premium-preview.png`.

**Step 6: Commit**

```powershell
git add apps/tallow-copy
git commit -m "feat: port tallow copy premium mockup"
```

## Task 3: Define Shared Job Types

**Files:**

- Create: `apps/tallow-copy/src/types/jobs.ts`
- Create: `apps/tallow-copy/src-tauri/src/jobs/mod.rs`
- Create: `apps/tallow-copy/src-tauri/src/jobs/types.rs`
- Modify: `apps/tallow-copy/src-tauri/src/lib.rs`

**Step 1: Add frontend types**

Define:

```ts
export type TransferMode = "copy" | "mirror" | "sync";
export type VerifyMode = "none" | "size" | "sampled_hash" | "full_hash" | "read_after_write" | "manifest";
export type MetadataMode = "data_only" | "timestamps" | "attributes" | "security" | "all";
export type BackendMode = "auto" | "thread_pool" | "iocp" | "direct_io";
```

Add `JobRequest`, `JobPlan`, `JobProgress`, `JobSummary`, `JobError`, `EngineCapabilities`, and `AppSettings`.

**Step 2: Add Rust API types**

Mirror the TypeScript types with `serde::{Serialize, Deserialize}`. Keep field names camelCase over the command boundary using serde rename attributes.

**Step 3: Add JSON fixture tests**

Create Rust unit tests that serialize representative `JobRequest`, `JobPlan`, and `JobProgress` values.

Run:

```powershell
cd apps\tallow-copy\src-tauri
cargo test jobs::types
```

Expected: tests pass and serialized field names match frontend expectations.

**Step 4: Commit**

```powershell
git add apps/tallow-copy
git commit -m "feat: define tallow copy job contract"
```

## Task 4: Add Tauri Command Stubs

**Files:**

- Modify: `apps/tallow-copy/src-tauri/src/lib.rs`
- Create: `apps/tallow-copy/src-tauri/src/commands.rs`
- Create: `apps/tallow-copy/src-tauri/src/jobs/store.rs`
- Modify: `apps/tallow-copy/src-tauri/src/jobs/mod.rs`

**Step 1: Implement command stubs**

Add commands:

- `get_engine_capabilities`
- `plan_job`
- `execute_job`
- `pause_job`
- `resume_job`
- `cancel_job`
- `list_jobs`
- `get_job`
- `get_settings`
- `update_settings`

**Step 2: Add an in-memory job store**

Use a `Mutex<HashMap<String, JobRecord>>` managed by Tauri state. This is temporary until the copy engine and journal are integrated.

**Step 3: Add backend tests**

Test:

- planning creates a plan id
- execute transitions planned to running
- pause transitions running to paused
- cancel transitions running or paused to cancelled
- invalid job id returns a structured error

Run:

```powershell
cd apps\tallow-copy\src-tauri
cargo test
```

Expected: command/store tests pass.

**Step 4: Commit**

```powershell
git add apps/tallow-copy
git commit -m "feat: add tallow copy command stubs"
```

## Task 5: Wire Frontend State To Commands

**Files:**

- Create: `apps/tallow-copy/src/api/tauriClient.ts`
- Create: `apps/tallow-copy/src/state/jobStore.ts`
- Modify: `apps/tallow-copy/src/ui/App.ts`
- Modify: `apps/tallow-copy/src/types/jobs.ts`

**Step 1: Add Tauri client wrappers**

Wrap command invocation in functions:

- `getEngineCapabilities`
- `planJob`
- `executeJob`
- `pauseJob`
- `resumeJob`
- `cancelJob`
- `listJobs`
- `getSettings`
- `updateSettings`

**Step 2: Add app state**

Create a lightweight store that tracks:

- selected source path
- selected target path
- selected mode
- options
- current plan
- current job progress
- current errors

**Step 3: Connect controls**

Wire:

- Plan button -> `planJob`
- Execute button -> `executeJob`
- Pause button -> `pauseJob`
- Cancel button -> `cancelJob`
- mode segmented control -> store update
- right panel controls -> store update

**Step 4: Add loading and disabled states**

Prevent invalid actions:

- Execute disabled before a plan exists.
- Pause disabled unless job is running.
- Resume disabled unless job is paused.
- Mirror delete execution disabled until review is accepted.

**Step 5: Verify**

Run:

```powershell
cd apps\tallow-copy
npm run build
cd src-tauri
cargo test
```

Expected: frontend build and backend tests pass.

**Step 6: Commit**

```powershell
git add apps/tallow-copy
git commit -m "feat: wire tallow copy app state"
```

## Task 6: Add Simulated Progress Events

**Files:**

- Modify: `apps/tallow-copy/src-tauri/src/commands.rs`
- Create: `apps/tallow-copy/src-tauri/src/jobs/simulator.rs`
- Modify: `apps/tallow-copy/src/api/tauriClient.ts`
- Modify: `apps/tallow-copy/src/state/jobStore.ts`
- Modify: `apps/tallow-copy/src/ui/App.ts`

**Step 1: Add event names**

Use:

- `job:started`
- `job:progress`
- `job:file-started`
- `job:file-finished`
- `job:error`
- `job:paused`
- `job:completed`
- `job:cancelled`

**Step 2: Emit progress from the backend**

For the stub executor, emit throttled progress events every 150-250ms. Simulate:

- bytes copied
- file count
- current file
- current speed
- ETA
- occasional recoverable error

**Step 3: Subscribe in the frontend**

Update the active file list, right panel stats, queue preview, and status bar from event payloads.

**Step 4: Stop progress correctly**

Verify pause, cancel, and completion stop the simulator and leave the UI in the correct state.

**Step 5: Verify visually**

Run the app, execute a mock job, and inspect that:

- progress advances smoothly
- no layout jumps occur
- status bar remains stable
- errors appear in the right places

**Step 6: Commit**

```powershell
git add apps/tallow-copy
git commit -m "feat: add simulated transfer progress"
```

## Task 7: Add Path Selection And Validation

**Files:**

- Modify: `apps/tallow-copy/src-tauri/src/commands.rs`
- Modify: `apps/tallow-copy/src/ui/App.ts`
- Modify: `apps/tallow-copy/src/state/jobStore.ts`
- Modify: `apps/tallow-copy/src/types/jobs.ts`

**Step 1: Add path picker commands**

Add `select_path(kind)` using Tauri dialog APIs.

**Step 2: Validate requests**

Reject:

- empty source
- empty target
- identical source and target
- target inside source for mirror when dangerous
- mirror deletes without review

**Step 3: Surface validation errors**

Show errors near the path bar and in the Needs Review model if they relate to destructive behavior.

**Step 4: Test validation**

Add backend tests for request validation.

Run:

```powershell
cd apps\tallow-copy\src-tauri
cargo test
```

Expected: validation tests pass.

**Step 5: Commit**

```powershell
git add apps/tallow-copy
git commit -m "feat: add path selection and validation"
```

## Task 8: Add Plan Review View

**Files:**

- Create: `apps/tallow-copy/src/ui/PlanReview.ts`
- Modify: `apps/tallow-copy/src/ui/App.ts`
- Modify: `apps/tallow-copy/src/state/jobStore.ts`
- Modify: `apps/tallow-copy/src/styles.css`

**Step 1: Create operation group UI**

Group planned operations:

- copy
- skip
- verify
- delete
- conflict
- error risk
- metadata only

**Step 2: Add destructive review**

Mirror deletes require an explicit review toggle before Execute is enabled.

**Step 3: Add keyboard flow**

Users must be able to open review, move through operation groups, accept delete review, and return to the active console without a mouse.

**Step 4: Verify**

Run:

```powershell
cd apps\tallow-copy
npm run build
```

Expected: build passes, no layout overflow.

**Step 5: Commit**

```powershell
git add apps/tallow-copy
git commit -m "feat: add transfer plan review"
```

## Task 9: Add History And Needs Review Models

**Files:**

- Create: `apps/tallow-copy/src/ui/HistoryView.ts`
- Create: `apps/tallow-copy/src/ui/NeedsReviewView.ts`
- Modify: `apps/tallow-copy/src/ui/App.ts`
- Modify: `apps/tallow-copy/src/state/jobStore.ts`
- Modify: `apps/tallow-copy/src-tauri/src/jobs/store.rs`

**Step 1: Store completed job summaries**

When a simulated job completes or fails, add a summary to the in-memory history.

**Step 2: Render history**

Show mode, source, target, elapsed time, bytes, files, skipped count, error count, and verification mode.

**Step 3: Render review items**

Show structured errors with retry, skip, reveal, and details actions. The first version can stub retry/reveal.

**Step 4: Verify**

Run:

```powershell
cd apps\tallow-copy
npm run build
cd src-tauri
cargo test
```

Expected: build and tests pass.

**Step 5: Commit**

```powershell
git add apps/tallow-copy
git commit -m "feat: add history and review views"
```

## Task 10: Add Tallow Script Preset Surface

**Files:**

- Create: `apps/tallow-copy/src/ui/ScriptPresetsView.ts`
- Create: `apps/tallow-copy/src/presets/defaultPresets.ts`
- Modify: `apps/tallow-copy/src/state/jobStore.ts`
- Modify: `apps/tallow-copy/src/ui/App.ts`

**Step 1: Add built-in presets**

Create preset definitions:

- Media Mirror
- Verified Backup
- Build Artifact Sync
- Resume Interrupted Job

Each preset should populate a `JobRequest` with mode, verification, metadata, thread, buffer, and delete policy defaults.

**Step 2: Show `.tl` preview text**

Render a read-only Tallow-like preset script preview for each preset. Do not execute arbitrary scripts in this task.

**Step 3: Apply presets**

Selecting a preset updates the active job request state without starting execution.

**Step 4: Verify**

Run:

```powershell
cd apps\tallow-copy
npm run build
```

Expected: build passes.

**Step 5: Commit**

```powershell
git add apps/tallow-copy
git commit -m "feat: add tallow script presets"
```

## Task 11: Prepare Native Copy Engine Adapter

**Files:**

- Create: `apps/tallow-copy/src-tauri/src/jobs/engine.rs`
- Modify: `apps/tallow-copy/src-tauri/src/jobs/mod.rs`
- Modify: `apps/tallow-copy/src-tauri/src/commands.rs`
- Read: `docs/plans/2026-05-12-tallow-ultrafast-copy-tool.md`

**Step 1: Define an engine trait**

Create:

```rust
pub trait CopyEngine: Send + Sync + 'static {
    fn capabilities(&self) -> EngineCapabilities;
    fn plan(&self, request: JobRequest) -> Result<JobPlan, JobError>;
    fn execute(&self, plan_id: String, sink: ProgressSink) -> Result<JobSummary, JobError>;
    fn pause(&self, job_id: String) -> Result<JobState, JobError>;
    fn cancel(&self, job_id: String) -> Result<JobState, JobError>;
}
```

**Step 2: Implement `SimulatedEngine`**

Move simulator behavior behind the trait.

**Step 3: Add placeholder for `NativeTallowEngine`**

Create a disabled or feature-gated adapter that documents where the consolidated Rust copy engine will plug in once Phase 1-2 of the engine plan lands.

**Step 4: Verify**

Run:

```powershell
cd apps\tallow-copy\src-tauri
cargo test
```

Expected: existing behavior still passes behind the trait.

**Step 5: Commit**

```powershell
git add apps/tallow-copy
git commit -m "refactor: introduce copy engine adapter"
```

## Task 12: Add Visual Regression And Accessibility Checks

**Files:**

- Create: `apps/tallow-copy/tests/visual.spec.ts`
- Create: `apps/tallow-copy/playwright.config.ts`
- Modify: `apps/tallow-copy/package.json`
- Modify: `apps/tallow-copy/README.md`

**Step 1: Add Playwright scripts**

Add:

```json
{
  "scripts": {
    "test:visual": "playwright test",
    "check": "npm run build && npm run test:visual"
  }
}
```

**Step 2: Add screenshot tests**

Test:

- desktop active console at 1280x820
- compact desktop at 1024x768
- plan review view
- needs review view

**Step 3: Add layout assertions**

Assert:

- no horizontal page overflow
- key toolbar buttons are visible
- status bar is visible
- file rows do not overlap right panel

**Step 4: Verify**

Run:

```powershell
cd apps\tallow-copy
npm run check
```

Expected: build and visual checks pass.

**Step 5: Commit**

```powershell
git add apps/tallow-copy
git commit -m "test: add tallow copy visual checks"
```

## Task 13: Update Documentation

**Files:**

- Modify: `apps/tallow-copy/README.md`
- Modify: `docs/plans/2026-05-12-tallow-copy-tauri-app-design.md`
- Modify: `docs/plans/2026-05-12-tallow-copy-tauri-app.md`

**Step 1: Document local development**

Include:

```powershell
cd apps\tallow-copy
npm install
npm run dev
npm run build
npm run tauri dev
```

**Step 2: Document app architecture**

Explain frontend, Tauri commands, command stubs, simulated engine, and future native engine adapter.

**Step 3: Document current limitations**

State clearly:

- simulated progress until engine integration
- no arbitrary Tallow script execution yet
- native copy speed claims require benchmark harness

**Step 4: Verify documentation paths**

Run:

```powershell
Test-Path apps\tallow-copy\README.md
Test-Path docs\mockups\tallow-copy-premium.html
Test-Path docs\plans\2026-05-12-tallow-ultrafast-copy-tool.md
```

Expected: all return `True`.

**Step 5: Commit**

```powershell
git add apps/tallow-copy docs/plans/2026-05-12-tallow-copy-tauri-app-design.md docs/plans/2026-05-12-tallow-copy-tauri-app.md
git commit -m "docs: document tallow copy app"
```

## Final Verification

Run:

```powershell
cd apps\tallow-copy
npm run check
cd src-tauri
cargo test
```

Expected:

- frontend build passes
- visual tests pass
- backend tests pass
- app opens to the approved premium circular console
- mock job can plan, execute, pause, resume, cancel, and complete
- plan review blocks destructive mirror deletes until accepted

## Production Handoff

After this plan is complete, the app should be ready for the native engine integration plan:

- replace `SimulatedEngine` with the consolidated Rust copy engine;
- expose real `plan`, `execute`, `pause`, `resume`, and `cancel`;
- persist journals/history;
- benchmark against robocopy/FastCopy using the benchmark protocol from the engine plan.
