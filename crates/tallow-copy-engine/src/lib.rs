use std::collections::HashMap;
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, mpsc};
use std::thread;
use std::time::SystemTime;

use filetime::FileTime;

pub const DEFAULT_BUFFER_SIZE_BYTES: usize = 1024 * 1024;
pub const MIN_BUFFER_SIZE_BYTES: usize = 4096;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CopyMode {
    Copy,
    Mirror,
    Sync,
    Verify,
    Resume,
    DryRun,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SkipPolicy {
    SizeMtime,
    SizeMtimeHash,
    Hash,
    /// R3-4: implemented as a content-hash comparison (`destination_matches`); this build
    /// has no persistent manifest store, so there is no separate manifest code path.
    Manifest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerifyPolicy {
    None,
    /// Verify the destination size against the source size (metadata `len()` only, no
    /// hash). Real check: runs after every copy and for `CopyMode::Verify` actions.
    Size,
    /// Verify a sampled BLAKE3 hash over fixed sample windows (head/middle/tail). Real
    /// check: detects same-size corruption inside the sampled windows but is weaker than
    /// `FullHash` — differences outside the sampled windows are not detected.
    SampledHash,
    FullHash,
    ReadAfterWrite,
    /// Explicitly rejected: this build has no manifest format or manifest store, so
    /// `plan()`/`execute()` fail with `CopyErrorCategory::Unsupported` instead of
    /// silently skipping the requested verification (R3-4).
    Manifest,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataPolicy {
    DataOnly,
    Timestamps,
    /// Copies the source permission bits (`set_permissions`); full Windows attribute /
    /// alternate-data-stream preservation is not implemented in this build.
    Attributes,
    /// Explicitly rejected (R3-4): preserving SELinux contexts / POSIX ACLs needs
    /// xattr APIs this build does not link, so `plan()`/`execute()` fail with
    /// `CopyErrorCategory::Unsupported` instead of silently not preserving them.
    Security,
    /// Explicitly rejected (R3-4): preserving uid/gid needs `chown` (not exposed by
    /// `std`), so `plan()`/`execute()` fail with `CopyErrorCategory::Unsupported`
    /// instead of silently dropping ownership.
    Owner,
    /// R3-4: "all supported metadata" = `Timestamps` + `Attributes`. `Security` and
    /// `Owner` are not part of `All` because they are unsupported (see above).
    All,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LinkPolicy {
    /// Symlinks met during directory traversal produce a `Skip` action (reason
    /// "symlink skipped by link policy"). An explicitly named source path that is a
    /// symlink is still followed so `CopyJob::copy(link, dest)` keeps working.
    Skip,
    /// Symlinks are recreated as symlinks at the destination (link target string is
    /// copied, never the target's content). R3-4: implemented on Unix; on other
    /// platforms execution fails with an explicit `Unsupported` error.
    Preserve,
    /// Symlinks are resolved and their target content is copied (`fs::metadata`
    /// follows the link). R3-4: real effect in the copy path; self-referential or
    /// ancestor symlink loops are detected during planning and reported as an error.
    Follow,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ErrorPolicy {
    BestEffort,
    Strict,
}

#[derive(Clone, Debug, Eq, PartialEq)]
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
    pub buffer_size_bytes: usize,
    pub dry_run: bool,
    /// Manifest used by `VerifyPolicy::Manifest`: one
    /// `blake3:<hex>  <relative-path>` line per file, `#` comments allowed.
    pub manifest: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CopyActionKind {
    Copy,
    Skip,
    Verify,
    Delete,
    Mkdir,
    Metadata,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyAction {
    pub kind: CopyActionKind,
    pub source: Option<PathBuf>,
    pub destination: PathBuf,
    pub relative_path: PathBuf,
    pub bytes: u64,
    pub reason: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyPlan {
    pub job: CopyJob,
    pub actions: Vec<CopyAction>,
    pub total_files: u64,
    pub total_bytes: u64,
    pub skipped_files: u64,
    pub delete_files: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CopyErrorCategory {
    Io,
    VerifyMismatch,
    InvalidInput,
    Unsupported,
    Cancelled,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyError {
    pub category: CopyErrorCategory,
    pub path: Option<PathBuf>,
    pub message: String,
    pub retryable: bool,
    pub recommended_action: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct CopyReport {
    pub copied_files: u64,
    pub skipped_files: u64,
    pub verified_files: u64,
    pub deleted_files: u64,
    pub bytes_copied: u64,
    pub worker_threads_used: usize,
    pub errors: Vec<CopyError>,
}

#[derive(Clone, Debug, Default)]
pub struct CopyControl {
    cancelled: Arc<AtomicBool>,
}

impl CopyControl {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    pub fn is_cancelled(&self) -> bool {
        self.cancelled.load(Ordering::SeqCst)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CopyProgressKind {
    FileStarted,
    BytesCopied,
    FileFinished,
    FileSkipped,
    FileDeleted,
    Error,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CopyProgressEvent {
    pub kind: CopyProgressKind,
    pub action_kind: CopyActionKind,
    pub source: Option<PathBuf>,
    pub destination: PathBuf,
    pub relative_path: PathBuf,
    pub bytes_done: u64,
    pub bytes_total: u64,
    pub aggregate_bytes_done: u64,
    pub aggregate_bytes_total: u64,
    pub files_done: u64,
    pub files_total: u64,
    pub error: Option<CopyError>,
}

impl CopyJob {
    pub fn copy(source: impl Into<PathBuf>, destination: impl Into<PathBuf>) -> Self {
        Self {
            source: source.into(),
            destination: destination.into(),
            mode: CopyMode::Copy,
            skip: SkipPolicy::SizeMtime,
            verify: VerifyPolicy::None,
            metadata: MetadataPolicy::DataOnly,
            link_policy: LinkPolicy::Skip,
            error_policy: ErrorPolicy::Strict,
            threads: 1,
            buffer_size_bytes: DEFAULT_BUFFER_SIZE_BYTES,
            dry_run: false,
            manifest: None,
        }
    }
}

pub fn plan(job: CopyJob) -> Result<CopyPlan, CopyError> {
    // R3-4: rejected policy combinations fail here (and again in `execute`) instead of
    // silently copying without the requested verification/metadata handling.
    validate_policies(&job)?;

    // Symlink-aware existence check: `Preserve` may copy a dangling link, so the
    // lstat-based check is used instead of `Path::exists` (which follows links).
    if fs::symlink_metadata(&job.source).is_err() {
        return Err(invalid_input(
            Some(job.source.clone()),
            "source path does not exist",
        ));
    }

    let mut actions = Vec::new();
    let source_is_symlink = fs::symlink_metadata(&job.source)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false);

    if source_is_symlink && matches!(job.link_policy, LinkPolicy::Preserve) {
        // An explicitly named symlink source is copied as a symlink when `Preserve`
        // is selected (the link target is never dereferenced).
        actions.push(CopyAction {
            kind: CopyActionKind::Copy,
            source: Some(job.source.clone()),
            destination: job.destination.clone(),
            relative_path: PathBuf::new(),
            bytes: fs::symlink_metadata(&job.source)
                .map(|meta| meta.len())
                .unwrap_or(0),
            reason: "source symlink preserved as symlink".to_string(),
        });
    } else {
        let source_meta = fs::metadata(&job.source).map_err(|err| {
            io_error(
                Some(job.source.clone()),
                format!("cannot stat source: {err}"),
                true,
            )
        })?;

        if source_meta.is_file() {
            plan_file(
                &job,
                &job.source,
                &job.destination,
                Path::new(""),
                source_meta,
                &mut actions,
            )?;
        } else if source_meta.is_dir() {
            let mut ancestors = Vec::new();
            plan_dir(
                &job,
                &job.source,
                &job.destination,
                Path::new(""),
                &mut actions,
                &mut ancestors,
            )?;
            if matches!(job.mode, CopyMode::Mirror) {
                plan_mirror_deletes(
                    &job.destination,
                    &job.source,
                    &job.destination,
                    &mut actions,
                )?;
            }
        } else {
            return Err(unsupported(
                Some(job.source.clone()),
                "source path is not a regular file or directory",
            ));
        }
    }

    let total_files = actions
        .iter()
        .filter(|action| matches!(action.kind, CopyActionKind::Copy | CopyActionKind::Verify))
        .count() as u64;
    let skipped_files = actions
        .iter()
        .filter(|action| matches!(action.kind, CopyActionKind::Skip))
        .count() as u64;
    let delete_files = actions
        .iter()
        .filter(|action| matches!(action.kind, CopyActionKind::Delete))
        .count() as u64;
    let total_bytes = actions
        .iter()
        .filter(|action| matches!(action.kind, CopyActionKind::Copy | CopyActionKind::Verify))
        .map(|action| action.bytes)
        .sum();

    Ok(CopyPlan {
        job,
        actions,
        total_files,
        total_bytes,
        skipped_files,
        delete_files,
    })
}

pub fn execute(plan: &CopyPlan) -> CopyReport {
    execute_with_progress(plan, |_| {})
}

pub fn execute_with_progress<F>(plan: &CopyPlan, progress: F) -> CopyReport
where
    F: FnMut(CopyProgressEvent),
{
    execute_with_control(plan, &CopyControl::new(), progress)
}

pub fn execute_with_control<F>(
    plan: &CopyPlan,
    control: &CopyControl,
    mut progress: F,
) -> CopyReport
where
    F: FnMut(CopyProgressEvent),
{
    // R3-4: `plan()` already rejects these, but a hand-built `CopyPlan` must not be
    // able to silently execute a policy this build cannot honour.
    if let Err(err) = validate_policies(&plan.job) {
        let mut report = CopyReport::default();
        report.errors.push(err);
        return report;
    }

    let dry_run = plan.job.dry_run || matches!(plan.job.mode, CopyMode::DryRun);
    if should_parallel_copy(plan, dry_run) {
        return execute_parallel_copy(plan, control, progress);
    }

    let mut report = CopyReport::default();
    let mut files_done = 0_u64;
    let mut aggregate_bytes_done = 0_u64;

    for action in &plan.actions {
        if control.is_cancelled() {
            let error = cancelled_error(Some(action.destination.clone()));
            progress(with_aggregate(
                progress_event(
                    CopyProgressKind::Error,
                    action,
                    0,
                    files_done,
                    plan.total_files,
                    Some(error.clone()),
                ),
                aggregate_bytes_done,
                plan.total_bytes,
            ));
            report.errors.push(error);
            break;
        }
        match action.kind {
            CopyActionKind::Copy => {
                if dry_run {
                    continue;
                }
                let Some(source) = &action.source else {
                    let error = invalid_input(
                        Some(action.destination.clone()),
                        "copy action missing source",
                    );
                    progress(with_aggregate(
                        progress_event(
                            CopyProgressKind::Error,
                            action,
                            0,
                            files_done,
                            plan.total_files,
                            Some(error.clone()),
                        ),
                        aggregate_bytes_done,
                        plan.total_bytes,
                    ));
                    report.errors.push(error);
                    continue;
                };
                progress(with_aggregate(
                    progress_event(
                        CopyProgressKind::FileStarted,
                        action,
                        0,
                        files_done,
                        plan.total_files,
                        None,
                    ),
                    aggregate_bytes_done,
                    plan.total_bytes,
                ));
                match copy_file_bounded_with_progress(
                    source,
                    &action.destination,
                    action,
                    files_done,
                    plan.total_files,
                    plan.job.buffer_size_bytes,
                    &plan.job.metadata,
                    &plan.job.link_policy,
                    &mut |event| {
                        let bytes_done = aggregate_bytes_done.saturating_add(event.bytes_done);
                        progress(with_aggregate(event, bytes_done, plan.total_bytes));
                    },
                    control,
                ) {
                    Ok(bytes) => {
                        report.worker_threads_used = report.worker_threads_used.max(1);
                        report.copied_files += 1;
                        report.bytes_copied += bytes;
                        aggregate_bytes_done = aggregate_bytes_done.saturating_add(bytes);
                        files_done += 1;
                        progress(with_aggregate(
                            progress_event(
                                CopyProgressKind::FileFinished,
                                action,
                                bytes,
                                files_done,
                                plan.total_files,
                                None,
                            ),
                            aggregate_bytes_done,
                            plan.total_bytes,
                        ));
                        // R3-4: every selected policy except `None` really verifies the
                        // file that was just written (previously only FullHash and
                        // ReadAfterWrite did; Size/SampledHash silently did nothing).
                        if !matches!(plan.job.verify, VerifyPolicy::None) {
                            let policy = effective_verify_policy(&plan.job);
                            verify_pair(
                                source,
                                &action.destination,
                                &policy,
                                plan.job.manifest.as_deref(),
                                &action.relative_path,
                                &mut report,
                            );
                        }
                    }
                    Err(err) => {
                        progress(with_aggregate(
                            progress_event(
                                CopyProgressKind::Error,
                                action,
                                0,
                                files_done,
                                plan.total_files,
                                Some(err.clone()),
                            ),
                            aggregate_bytes_done,
                            plan.total_bytes,
                        ));
                        report.errors.push(err);
                    }
                }
            }
            CopyActionKind::Skip => {
                report.skipped_files += 1;
                files_done += 1;
                progress(with_aggregate(
                    progress_event(
                        CopyProgressKind::FileSkipped,
                        action,
                        action.bytes,
                        files_done,
                        plan.total_files,
                        None,
                    ),
                    aggregate_bytes_done,
                    plan.total_bytes,
                ));
            }
            CopyActionKind::Verify => {
                let Some(source) = &action.source else {
                    let error = invalid_input(
                        Some(action.destination.clone()),
                        "verify action missing source",
                    );
                    progress(with_aggregate(
                        progress_event(
                            CopyProgressKind::Error,
                            action,
                            0,
                            files_done,
                            plan.total_files,
                            Some(error.clone()),
                        ),
                        aggregate_bytes_done,
                        plan.total_bytes,
                    ));
                    report.errors.push(error);
                    continue;
                };
                // R3-4: the action's verification uses the same policy resolution as the
                // post-copy path, so plan and execution can never disagree.
                let policy = effective_verify_policy(&plan.job);
                verify_pair(
                    source,
                    &action.destination,
                    &policy,
                    plan.job.manifest.as_deref(),
                    &action.relative_path,
                    &mut report,
                );
                files_done += 1;
                aggregate_bytes_done = aggregate_bytes_done.saturating_add(action.bytes);
                progress(with_aggregate(
                    progress_event(
                        CopyProgressKind::FileFinished,
                        action,
                        action.bytes,
                        files_done,
                        plan.total_files,
                        None,
                    ),
                    aggregate_bytes_done,
                    plan.total_bytes,
                ));
            }
            CopyActionKind::Delete => {
                if dry_run {
                    continue;
                }
                match fs::remove_file(&action.destination) {
                    Ok(()) => {
                        report.deleted_files += 1;
                        progress(with_aggregate(
                            progress_event(
                                CopyProgressKind::FileDeleted,
                                action,
                                action.bytes,
                                files_done,
                                plan.total_files,
                                None,
                            ),
                            aggregate_bytes_done,
                            plan.total_bytes,
                        ));
                    }
                    Err(err) => {
                        let error = io_error(
                            Some(action.destination.clone()),
                            format!("delete failed: {err}"),
                            true,
                        );
                        progress(with_aggregate(
                            progress_event(
                                CopyProgressKind::Error,
                                action,
                                0,
                                files_done,
                                plan.total_files,
                                Some(error.clone()),
                            ),
                            aggregate_bytes_done,
                            plan.total_bytes,
                        ));
                        report.errors.push(error);
                    }
                }
            }
            CopyActionKind::Mkdir => {
                if dry_run {
                    continue;
                }
                if let Err(err) = fs::create_dir_all(&action.destination) {
                    report.errors.push(io_error(
                        Some(action.destination.clone()),
                        format!("mkdir failed: {err}"),
                        true,
                    ));
                }
            }
            CopyActionKind::Metadata | CopyActionKind::Error => {}
        }
    }

    report
}

fn should_parallel_copy(plan: &CopyPlan, dry_run: bool) -> bool {
    if dry_run || plan.job.threads <= 1 {
        return false;
    }
    // R3-4: FullHash/ReadAfterWrite verification stays on the sequential path (it was
    // never run in a worker). Size/SampledHash verification now runs inside the worker
    // itself, so selecting those policies no longer silently disables multi-threading.
    if matches!(
        plan.job.verify,
        VerifyPolicy::FullHash | VerifyPolicy::ReadAfterWrite
    ) {
        return false;
    }
    plan.actions
        .iter()
        .filter(|action| matches!(action.kind, CopyActionKind::Copy))
        .count()
        > 1
}

fn execute_parallel_copy<F>(plan: &CopyPlan, control: &CopyControl, mut progress: F) -> CopyReport
where
    F: FnMut(CopyProgressEvent),
{
    let mut report = CopyReport::default();
    let mut files_done = 0_u64;
    let mut aggregate_bytes_done = 0_u64;

    for action in plan
        .actions
        .iter()
        .filter(|action| matches!(action.kind, CopyActionKind::Mkdir))
    {
        if let Err(err) = fs::create_dir_all(&action.destination) {
            report.errors.push(io_error(
                Some(action.destination.clone()),
                format!("mkdir failed: {err}"),
                true,
            ));
        }
    }

    for action in plan.actions.iter().filter(|action| {
        matches!(
            action.kind,
            CopyActionKind::Skip
                | CopyActionKind::Verify
                | CopyActionKind::Metadata
                | CopyActionKind::Error
        )
    }) {
        process_non_copy_action(
            plan,
            action,
            &mut report,
            &mut files_done,
            &mut aggregate_bytes_done,
            &mut progress,
        );
    }

    execute_copy_actions_in_parallel(
        plan,
        control,
        &mut report,
        &mut files_done,
        &mut aggregate_bytes_done,
        &mut progress,
    );

    for action in plan
        .actions
        .iter()
        .filter(|action| matches!(action.kind, CopyActionKind::Delete))
    {
        process_delete_action(
            plan,
            action,
            &mut report,
            files_done,
            aggregate_bytes_done,
            &mut progress,
        );
    }

    report
}

fn process_non_copy_action<F>(
    plan: &CopyPlan,
    action: &CopyAction,
    report: &mut CopyReport,
    files_done: &mut u64,
    aggregate_bytes_done: &mut u64,
    progress: &mut F,
) where
    F: FnMut(CopyProgressEvent),
{
    match action.kind {
        CopyActionKind::Skip => {
            report.skipped_files += 1;
            *files_done += 1;
            progress(with_aggregate(
                progress_event(
                    CopyProgressKind::FileSkipped,
                    action,
                    action.bytes,
                    *files_done,
                    plan.total_files,
                    None,
                ),
                *aggregate_bytes_done,
                plan.total_bytes,
            ));
        }
        CopyActionKind::Verify => {
            let Some(source) = &action.source else {
                let error = invalid_input(
                    Some(action.destination.clone()),
                    "verify action missing source",
                );
                progress(with_aggregate(
                    progress_event(
                        CopyProgressKind::Error,
                        action,
                        0,
                        *files_done,
                        plan.total_files,
                        Some(error.clone()),
                    ),
                    *aggregate_bytes_done,
                    plan.total_bytes,
                ));
                report.errors.push(error);
                return;
            };
            // R3-4: same policy resolution as the sequential path (plan/execute agree).
            let policy = effective_verify_policy(&plan.job);
            verify_pair(
                source,
                &action.destination,
                &policy,
                plan.job.manifest.as_deref(),
                &action.relative_path,
                report,
            );
            *files_done += 1;
            *aggregate_bytes_done = (*aggregate_bytes_done).saturating_add(action.bytes);
            progress(with_aggregate(
                progress_event(
                    CopyProgressKind::FileFinished,
                    action,
                    action.bytes,
                    *files_done,
                    plan.total_files,
                    None,
                ),
                *aggregate_bytes_done,
                plan.total_bytes,
            ));
        }
        CopyActionKind::Metadata | CopyActionKind::Error => {}
        CopyActionKind::Copy | CopyActionKind::Delete | CopyActionKind::Mkdir => {}
    }
}

fn process_delete_action<F>(
    plan: &CopyPlan,
    action: &CopyAction,
    report: &mut CopyReport,
    files_done: u64,
    aggregate_bytes_done: u64,
    progress: &mut F,
) where
    F: FnMut(CopyProgressEvent),
{
    match fs::remove_file(&action.destination) {
        Ok(()) => {
            report.deleted_files += 1;
            progress(with_aggregate(
                progress_event(
                    CopyProgressKind::FileDeleted,
                    action,
                    action.bytes,
                    files_done,
                    plan.total_files,
                    None,
                ),
                aggregate_bytes_done,
                plan.total_bytes,
            ));
        }
        Err(err) => {
            let error = io_error(
                Some(action.destination.clone()),
                format!("delete failed: {err}"),
                true,
            );
            progress(with_aggregate(
                progress_event(
                    CopyProgressKind::Error,
                    action,
                    0,
                    files_done,
                    plan.total_files,
                    Some(error.clone()),
                ),
                aggregate_bytes_done,
                plan.total_bytes,
            ));
            report.errors.push(error);
        }
    }
}

enum WorkerMessage {
    Progress(CopyProgressEvent),
    Finished {
        action: CopyAction,
        result: Result<u64, CopyError>,
        /// R3-4: post-copy verification outcome; `None` when no policy verifies (or the
        /// copy itself failed, in which case there is nothing to verify).
        verification: Option<Result<(), CopyError>>,
    },
}

fn execute_copy_actions_in_parallel<F>(
    plan: &CopyPlan,
    control: &CopyControl,
    report: &mut CopyReport,
    files_done: &mut u64,
    aggregate_bytes_done: &mut u64,
    progress: &mut F,
) where
    F: FnMut(CopyProgressEvent),
{
    let copy_actions = plan
        .actions
        .iter()
        .filter(|action| matches!(action.kind, CopyActionKind::Copy))
        .cloned()
        .collect::<Vec<_>>();
    if copy_actions.is_empty() {
        return;
    }
    if control.is_cancelled() {
        report.errors.push(cancelled_error(None));
        return;
    }

    let worker_count = plan.job.threads.min(copy_actions.len()).max(1);
    report.worker_threads_used = worker_count;
    let copy_actions = Arc::new(copy_actions);
    let next_action = Arc::new(AtomicUsize::new(0));
    let (sender, receiver) = mpsc::channel::<WorkerMessage>();
    let mut handles = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let actions = Arc::clone(&copy_actions);
        let next = Arc::clone(&next_action);
        let sender = sender.clone();
        let total_files = plan.total_files;
        let buffer_size_bytes = plan.job.buffer_size_bytes;
        let metadata_policy = plan.job.metadata.clone();
        let link_policy = plan.job.link_policy.clone();
        // R3-4: Size/SampledHash verification runs in the worker (the
        // `should_parallel_copy` gate keeps FullHash/ReadAfterWrite sequential).
        let verify_policy = plan.job.verify.clone();
        let manifest = plan.job.manifest.clone();
        let control = control.clone();
        handles.push(thread::spawn(move || {
            loop {
                if control.is_cancelled() {
                    break;
                }
                let index = next.fetch_add(1, Ordering::SeqCst);
                let Some(action) = actions.get(index).cloned() else {
                    break;
                };
                let Some(source) = action.source.clone() else {
                    let error = invalid_input(
                        Some(action.destination.clone()),
                        "copy action missing source",
                    );
                    let _ = sender.send(WorkerMessage::Progress(progress_event(
                        CopyProgressKind::Error,
                        &action,
                        0,
                        0,
                        total_files,
                        Some(error.clone()),
                    )));
                    let _ = sender.send(WorkerMessage::Finished {
                        action,
                        result: Err(error),
                        verification: None,
                    });
                    continue;
                };
                let _ = sender.send(WorkerMessage::Progress(progress_event(
                    CopyProgressKind::FileStarted,
                    &action,
                    0,
                    0,
                    total_files,
                    None,
                )));
                let result = copy_file_bounded_with_progress(
                    &source,
                    &action.destination,
                    &action,
                    0,
                    total_files,
                    buffer_size_bytes,
                    &metadata_policy,
                    &link_policy,
                    &mut |event| {
                        let _ = sender.send(WorkerMessage::Progress(event));
                    },
                    &control,
                );
                let verification = match &result {
                    Ok(_) if !matches!(verify_policy, VerifyPolicy::None) => Some(
                        verify_pair_result(
                            &source,
                            &action.destination,
                            &verify_policy,
                            manifest.as_deref(),
                            &action.relative_path,
                        ),
                    ),
                    _ => None,
                };
                let _ = sender.send(WorkerMessage::Finished {
                    action,
                    result,
                    verification,
                });
            }
        }));
    }
    drop(sender);

    let mut active_copy_bytes = HashMap::<PathBuf, u64>::new();
    for message in receiver {
        match message {
            WorkerMessage::Progress(mut event) => {
                event.files_done = *files_done;
                match event.kind {
                    CopyProgressKind::FileStarted => {
                        active_copy_bytes.insert(event.destination.clone(), 0);
                    }
                    CopyProgressKind::BytesCopied => {
                        active_copy_bytes.insert(event.destination.clone(), event.bytes_done);
                    }
                    CopyProgressKind::Error => {
                        active_copy_bytes.remove(&event.destination);
                    }
                    CopyProgressKind::FileFinished
                    | CopyProgressKind::FileSkipped
                    | CopyProgressKind::FileDeleted => {}
                }
                let active_bytes = active_copy_bytes.values().copied().sum::<u64>();
                event = with_aggregate(
                    event,
                    (*aggregate_bytes_done).saturating_add(active_bytes),
                    plan.total_bytes,
                );
                progress(event);
            }
            WorkerMessage::Finished {
                action,
                result,
                verification,
            } => match result {
                Ok(bytes) => {
                    active_copy_bytes.remove(&action.destination);
                    report.copied_files += 1;
                    report.bytes_copied += bytes;
                    *aggregate_bytes_done = (*aggregate_bytes_done).saturating_add(bytes);
                    *files_done += 1;
                    let active_bytes = active_copy_bytes.values().copied().sum::<u64>();
                    progress(with_aggregate(
                        progress_event(
                            CopyProgressKind::FileFinished,
                            &action,
                            bytes,
                            *files_done,
                            plan.total_files,
                            None,
                        ),
                        (*aggregate_bytes_done).saturating_add(active_bytes),
                        plan.total_bytes,
                    ));
                    // R3-4: worker-side verification outcome (mirrors the sequential path:
                    // a verify failure is reported but does not undo the copy).
                    match verification {
                        Some(Ok(())) => report.verified_files += 1,
                        Some(Err(error)) => report.errors.push(error),
                        None => {},
                    }
                }
                Err(error) => {
                    active_copy_bytes.remove(&action.destination);
                    let active_bytes = active_copy_bytes.values().copied().sum::<u64>();
                    progress(with_aggregate(
                        progress_event(
                            CopyProgressKind::Error,
                            &action,
                            0,
                            *files_done,
                            plan.total_files,
                            Some(error.clone()),
                        ),
                        (*aggregate_bytes_done).saturating_add(active_bytes),
                        plan.total_bytes,
                    ));
                    report.errors.push(error);
                }
            },
        }
    }

    for handle in handles {
        if handle.join().is_err() {
            report.errors.push(CopyError {
                category: CopyErrorCategory::Io,
                path: None,
                message: "copy worker panicked".to_string(),
                retryable: true,
                recommended_action: "retry".to_string(),
            });
        }
    }
}

fn progress_event(
    kind: CopyProgressKind,
    action: &CopyAction,
    bytes_done: u64,
    files_done: u64,
    files_total: u64,
    error: Option<CopyError>,
) -> CopyProgressEvent {
    CopyProgressEvent {
        kind,
        action_kind: action.kind.clone(),
        source: action.source.clone(),
        destination: action.destination.clone(),
        relative_path: action.relative_path.clone(),
        bytes_done,
        bytes_total: action.bytes,
        aggregate_bytes_done: 0,
        aggregate_bytes_total: 0,
        files_done,
        files_total,
        error,
    }
}

fn with_aggregate(
    mut event: CopyProgressEvent,
    aggregate_bytes_done: u64,
    aggregate_bytes_total: u64,
) -> CopyProgressEvent {
    event.aggregate_bytes_done = aggregate_bytes_done.min(aggregate_bytes_total);
    event.aggregate_bytes_total = aggregate_bytes_total;
    event
}

fn plan_dir(
    job: &CopyJob,
    source_dir: &Path,
    destination_dir: &Path,
    relative_dir: &Path,
    actions: &mut Vec<CopyAction>,
    ancestors: &mut Vec<PathBuf>,
) -> Result<(), CopyError> {
    if !destination_dir.exists() {
        actions.push(CopyAction {
            kind: CopyActionKind::Mkdir,
            source: Some(source_dir.to_path_buf()),
            destination: destination_dir.to_path_buf(),
            relative_path: relative_dir.to_path_buf(),
            bytes: 0,
            reason: "destination directory missing".to_string(),
        });
    }

    // R3-4: loop guard for `LinkPolicy::Follow` — a symlink that points back at a
    // directory already on the current traversal chain must not be followed forever.
    let mut pushed_ancestor = false;
    if let Ok(canonical) = fs::canonicalize(source_dir) {
        if ancestors.contains(&canonical) {
            return Err(unsupported(
                Some(source_dir.to_path_buf()),
                "symlink loop detected while following links; select LinkPolicy::Preserve or Skip",
            ));
        }
        ancestors.push(canonical);
        pushed_ancestor = true;
    }

    for entry in fs::read_dir(source_dir).map_err(|err| {
        io_error(
            Some(source_dir.to_path_buf()),
            format!("cannot read directory: {err}"),
            true,
        )
    })? {
        let entry = entry.map_err(|err| {
            io_error(
                Some(source_dir.to_path_buf()),
                format!("cannot read directory entry: {err}"),
                true,
            )
        })?;
        let source_path = entry.path();
        let relative_path = relative_dir.join(entry.file_name());
        let destination_path = destination_dir.join(entry.file_name());
        // `DirEntry::file_type`/`metadata` do not traverse symlinks (lstat semantics).
        let file_type = entry.file_type().map_err(|err| {
            io_error(
                Some(source_path.clone()),
                format!("cannot stat entry: {err}"),
                true,
            )
        })?;

        if file_type.is_symlink() {
            let link_bytes = fs::symlink_metadata(&source_path)
                .map(|meta| meta.len())
                .unwrap_or(0);
            match job.link_policy {
                LinkPolicy::Skip => {
                    actions.push(CopyAction {
                        kind: CopyActionKind::Skip,
                        source: Some(source_path.clone()),
                        destination: destination_path,
                        relative_path,
                        bytes: link_bytes,
                        reason: "symlink skipped by link policy".to_string(),
                    });
                }
                LinkPolicy::Preserve => {
                    // Re-creating a link that already points at the same target is
                    // pure churn: same inode, same bytes, same result. Plan a Skip
                    // so a repeated copy does not rewrite every symlink. A link
                    // that exists but points elsewhere is still a Copy (it must be
                    // replaced), and a missing destination is a Copy.
                    let source_target = fs::read_link(&source_path).ok();
                    let already_correct = source_target.as_ref().is_some_and(|want| {
                        fs::read_link(&destination_path).is_ok_and(|have| &have == want)
                    });
                    let (kind, reason) = if already_correct {
                        (
                            CopyActionKind::Skip,
                            "symlink already points at the same target",
                        )
                    } else {
                        (CopyActionKind::Copy, "symlink preserved as symlink")
                    };
                    actions.push(CopyAction {
                        kind,
                        source: Some(source_path.clone()),
                        destination: destination_path,
                        relative_path,
                        bytes: link_bytes,
                        reason: reason.to_string(),
                    });
                }
                LinkPolicy::Follow => {
                    let target_meta = fs::metadata(&source_path).map_err(|err| {
                        io_error(
                            Some(source_path.clone()),
                            format!("cannot follow symlink: {err}"),
                            true,
                        )
                    })?;
                    if target_meta.is_dir() {
                        plan_dir(
                            job,
                            &source_path,
                            &destination_path,
                            &relative_path,
                            actions,
                            ancestors,
                        )?;
                    } else if target_meta.is_file() {
                        plan_file(
                            job,
                            &source_path,
                            &destination_path,
                            &relative_path,
                            target_meta,
                            actions,
                        )?;
                    } else {
                        return Err(unsupported(
                            Some(source_path.clone()),
                            "symlink target is not a regular file or directory",
                        ));
                    }
                }
            }
            continue;
        }

        let metadata = fs::metadata(&source_path).map_err(|err| {
            io_error(
                Some(source_path.clone()),
                format!("cannot stat entry: {err}"),
                true,
            )
        })?;

        if metadata.is_dir() {
            plan_dir(
                job,
                &source_path,
                &destination_path,
                &relative_path,
                actions,
                ancestors,
            )?;
        } else if metadata.is_file() {
            plan_file(
                job,
                &source_path,
                &destination_path,
                &relative_path,
                metadata,
                actions,
            )?;
        } else {
            // FIFOs, sockets and device nodes are not copyable as regular files.
            // Record an explicit skip instead of silently dropping the entry.
            actions.push(CopyAction {
                kind: CopyActionKind::Skip,
                source: Some(source_path.clone()),
                destination: destination_path,
                relative_path,
                bytes: 0,
                reason: "special file (FIFO/socket/device) skipped: unsupported".to_string(),
            });
        }
    }

    if pushed_ancestor {
        ancestors.pop();
    }

    Ok(())
}

fn plan_file(
    job: &CopyJob,
    source: &Path,
    destination: &Path,
    relative_path: &Path,
    source_meta: fs::Metadata,
    actions: &mut Vec<CopyAction>,
) -> Result<(), CopyError> {
    let bytes = source_meta.len();
    let action = if !destination.exists() {
        CopyAction {
            kind: CopyActionKind::Copy,
            source: Some(source.to_path_buf()),
            destination: destination.to_path_buf(),
            relative_path: relative_path.to_path_buf(),
            bytes,
            reason: copy_reason(job, "destination missing"),
        }
    } else {
        let destination_meta = fs::metadata(destination).map_err(|err| {
            io_error(
                Some(destination.to_path_buf()),
                format!("cannot stat destination: {err}"),
                true,
            )
        })?;
        if destination_matches(
            source,
            &source_meta,
            destination,
            &destination_meta,
            &job.skip,
        )? {
            // R3-4: plan and execution share one rule — a `Verify` action is emitted
            // exactly for the policies `execute` can really run against an unchanged
            // destination (`CopyMode::Verify`, FullHash, ReadAfterWrite, SampledHash).
            // `VerifyPolicy::Size` needs no action here: every skip policy already
            // compares sizes, and size verification of written files happens after
            // each copy. `VerifyPolicy::None`/`Manifest` never emit a Verify action.
            if matches!(job.mode, CopyMode::Verify)
                || matches!(
                    job.verify,
                    VerifyPolicy::FullHash
                        | VerifyPolicy::ReadAfterWrite
                        | VerifyPolicy::SampledHash
                )
            {
                CopyAction {
                    kind: CopyActionKind::Verify,
                    source: Some(source.to_path_buf()),
                    destination: destination.to_path_buf(),
                    relative_path: relative_path.to_path_buf(),
                    bytes,
                    reason: format!(
                        "destination appears unchanged; verify requested ({:?})",
                        effective_verify_policy(job)
                    ),
                }
            } else {
                CopyAction {
                    kind: CopyActionKind::Skip,
                    source: Some(source.to_path_buf()),
                    destination: destination.to_path_buf(),
                    relative_path: relative_path.to_path_buf(),
                    bytes,
                    reason: "unchanged by skip policy".to_string(),
                }
            }
        } else {
            CopyAction {
                kind: CopyActionKind::Copy,
                source: Some(source.to_path_buf()),
                destination: destination.to_path_buf(),
                relative_path: relative_path.to_path_buf(),
                bytes,
                reason: copy_reason(job, "changed by skip policy"),
            }
        }
    };

    actions.push(action);
    Ok(())
}

fn plan_mirror_deletes(
    destination_root: &Path,
    source_root: &Path,
    current_destination: &Path,
    actions: &mut Vec<CopyAction>,
) -> Result<(), CopyError> {
    if !current_destination.exists() {
        return Ok(());
    }

    for entry in fs::read_dir(current_destination).map_err(|err| {
        io_error(
            Some(current_destination.to_path_buf()),
            format!("cannot read destination directory: {err}"),
            true,
        )
    })? {
        let entry = entry.map_err(|err| {
            io_error(
                Some(current_destination.to_path_buf()),
                format!("cannot read destination entry: {err}"),
                true,
            )
        })?;
        let destination_path = entry.path();
        let relative_path = destination_path
            .strip_prefix(destination_root)
            .unwrap_or(&destination_path)
            .to_path_buf();
        let source_path = source_root.join(&relative_path);
        // `lstat`, not `stat`: the question is what the destination entry *is*,
        // not what it points at. A dangling symlink fails `stat` outright (the
        // whole plan then errored) and a live one reports the target's type, so
        // a stale link was never deleted (register #53).
        let metadata = fs::symlink_metadata(&destination_path).map_err(|err| {
            io_error(
                Some(destination_path.clone()),
                format!("cannot stat destination entry: {err}"),
                true,
            )
        })?;
        let is_symlink = metadata.file_type().is_symlink();

        if !source_path.exists() && !symlink_source_exists(source_root, &relative_path) {
            if metadata.is_file() || is_symlink || is_special(&metadata) {
                actions.push(CopyAction {
                    kind: CopyActionKind::Delete,
                    source: None,
                    destination: destination_path,
                    relative_path,
                    bytes: if is_symlink { 0 } else { metadata.len() },
                    reason: "mirror target has no matching source".to_string(),
                });
            }
        } else if metadata.is_dir() {
            plan_mirror_deletes(destination_root, source_root, &destination_path, actions)?;
        }
    }

    Ok(())
}

/// Does the *source* side have an entry at this relative path, counting a
/// symlink (even a dangling one) as present? `Path::exists` follows links and
/// answers `false` for a dangling source link, which would make mirror delete a
/// link the source still has.
fn symlink_source_exists(source_root: &Path, relative_path: &Path) -> bool {
    fs::symlink_metadata(source_root.join(relative_path)).is_ok()
}

fn is_special(metadata: &fs::Metadata) -> bool {
    let ft = metadata.file_type();
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileTypeExt;
        ft.is_fifo() || ft.is_socket() || ft.is_block_device() || ft.is_char_device()
    }
    #[cfg(not(unix))]
    {
        let _ = ft;
        false
    }
}

fn destination_matches(
    source: &Path,
    source_meta: &fs::Metadata,
    destination: &Path,
    destination_meta: &fs::Metadata,
    skip: &SkipPolicy,
) -> Result<bool, CopyError> {
    match skip {
        SkipPolicy::SizeMtime => Ok(source_meta.len() == destination_meta.len()
            && modified_seconds(source_meta) == modified_seconds(destination_meta)),
        SkipPolicy::SizeMtimeHash => {
            if source_meta.len() != destination_meta.len()
                || modified_seconds(source_meta) != modified_seconds(destination_meta)
            {
                return Ok(false);
            }
            Ok(hash_file(source)? == hash_file(destination)?)
        }
        SkipPolicy::Hash | SkipPolicy::Manifest => {
            Ok(hash_file(source)? == hash_file(destination)?)
        }
    }
}

fn modified_seconds(metadata: &fs::Metadata) -> Option<u64> {
    metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(SystemTime::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
}

fn copy_file_bounded_with_progress<F>(
    source: &Path,
    destination: &Path,
    action: &CopyAction,
    files_done: u64,
    files_total: u64,
    buffer_size_bytes: usize,
    metadata_policy: &MetadataPolicy,
    link_policy: &LinkPolicy,
    progress: &mut F,
    control: &CopyControl,
) -> Result<u64, CopyError>
where
    F: FnMut(CopyProgressEvent),
{
    if control.is_cancelled() {
        return Err(cancelled_error(Some(destination.to_path_buf())));
    }

    // R3-4: `LinkPolicy::Preserve` re-creates the symlink instead of copying the
    // bytes of whatever the link points at. `Skip`/`Follow` never plan a symlink
    // source as a plain copy, so this branch is reachable only for `Preserve`.
    if matches!(link_policy, LinkPolicy::Preserve) {
        let is_symlink = fs::symlink_metadata(source)
            .map(|meta| meta.file_type().is_symlink())
            .unwrap_or(false);
        if is_symlink {
            return copy_symlink_preserving(source, destination, control);
        }
    }

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            io_error(
                Some(parent.to_path_buf()),
                format!("cannot create parent directory: {err}"),
                true,
            )
        })?;
    }

    let mut input = fs::File::open(source).map_err(|err| {
        io_error(
            Some(source.to_path_buf()),
            format!("cannot open source: {err}"),
            true,
        )
    })?;
    let mut output = fs::File::create(destination).map_err(|err| {
        io_error(
            Some(destination.to_path_buf()),
            format!("cannot create destination: {err}"),
            true,
        )
    })?;
    let mut buffer = vec![0_u8; buffer_size_bytes.max(MIN_BUFFER_SIZE_BYTES)];
    let mut bytes = 0_u64;

    loop {
        if control.is_cancelled() {
            return Err(cancelled_error(Some(destination.to_path_buf())));
        }
        let read = input.read(&mut buffer).map_err(|err| {
            io_error(
                Some(source.to_path_buf()),
                format!("read failed: {err}"),
                true,
            )
        })?;
        if read == 0 {
            break;
        }
        output.write_all(&buffer[..read]).map_err(|err| {
            io_error(
                Some(destination.to_path_buf()),
                format!("write failed: {err}"),
                true,
            )
        })?;
        bytes += read as u64;
        progress(progress_event(
            CopyProgressKind::BytesCopied,
            action,
            bytes,
            files_done,
            files_total,
            None,
        ));
    }

    drop(output);
    drop(input);
    apply_metadata_policy(source, destination, metadata_policy)?;

    Ok(bytes)
}

/// R3-4: `LinkPolicy::Preserve` payload — recreate `source` (a symlink) at
/// `destination` with the same link target string. No bytes are copied, so the
/// returned count is always 0. On platforms without symlink support this fails with
/// an explicit `Unsupported` error (see `create_symlink`).
fn copy_symlink_preserving(
    source: &Path,
    destination: &Path,
    control: &CopyControl,
) -> Result<u64, CopyError> {
    if control.is_cancelled() {
        return Err(cancelled_error(Some(destination.to_path_buf())));
    }

    let target = fs::read_link(source).map_err(|err| {
        io_error(
            Some(source.to_path_buf()),
            format!("cannot read symlink target: {err}"),
            false,
        )
    })?;

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|err| {
            io_error(
                Some(parent.to_path_buf()),
                format!("cannot create parent directory: {err}"),
                true,
            )
        })?;
    }

    if let Ok(existing) = fs::symlink_metadata(destination) {
        if existing.is_dir() {
            return Err(io_error(
                Some(destination.to_path_buf()),
                "cannot replace an existing directory with a symlink",
                false,
            ));
        }
        fs::remove_file(destination).map_err(|err| {
            io_error(
                Some(destination.to_path_buf()),
                format!("cannot replace existing destination: {err}"),
                false,
            )
        })?;
    }

    create_symlink(&target, destination)?;
    Ok(0)
}

#[cfg(unix)]
fn create_symlink(target: &Path, link: &Path) -> Result<(), CopyError> {
    std::os::unix::fs::symlink(target, link).map_err(|err| {
        io_error(
            Some(link.to_path_buf()),
            format!("cannot create symlink: {err}"),
            false,
        )
    })
}

#[cfg(not(unix))]
fn create_symlink(_target: &Path, link: &Path) -> Result<(), CopyError> {
    Err(unsupported(
        Some(link.to_path_buf()),
        "LinkPolicy::Preserve is not supported on this platform; select LinkPolicy::Follow or Skip",
    ))
}

fn apply_metadata_policy(
    source: &Path,
    destination: &Path,
    policy: &MetadataPolicy,
) -> Result<(), CopyError> {
    // R3-4: `MetadataPolicy::Security`/`Owner` never reach this function —
    // `validate_policies` rejects them in `plan()` and `execute()`. `All` is the
    // supported set: Timestamps + Attributes.
    if matches!(policy, MetadataPolicy::DataOnly) {
        return Ok(());
    }

    let metadata = fs::metadata(source).map_err(|err| {
        io_error(
            Some(source.to_path_buf()),
            format!("cannot stat source metadata: {err}"),
            true,
        )
    })?;

    if matches!(policy, MetadataPolicy::Timestamps | MetadataPolicy::All) {
        let modified = FileTime::from_last_modification_time(&metadata);
        filetime::set_file_mtime(destination, modified).map_err(|err| {
            io_error(
                Some(destination.to_path_buf()),
                format!("cannot set destination modified time: {err}"),
                true,
            )
        })?;
        if let Ok(accessed) = metadata.accessed() {
            let accessed = FileTime::from_system_time(accessed);
            filetime::set_file_atime(destination, accessed).map_err(|err| {
                io_error(
                    Some(destination.to_path_buf()),
                    format!("cannot set destination access time: {err}"),
                    true,
                )
            })?;
        }
    }

    if matches!(policy, MetadataPolicy::Attributes | MetadataPolicy::All) {
        fs::set_permissions(destination, metadata.permissions()).map_err(|err| {
            io_error(
                Some(destination.to_path_buf()),
                format!("cannot set destination permissions: {err}"),
                true,
            )
        })?;
    }

    Ok(())
}

/// R3-4: sample window size for [`VerifyPolicy::SampledHash`] (head, middle and tail).
const VERIFY_SAMPLE_WINDOW_BYTES: u64 = 64 * 1024;

/// R3-4: number of sampled windows for [`VerifyPolicy::SampledHash`].
const VERIFY_SAMPLE_WINDOW_COUNT: u64 = 3;

/// Applies a verification outcome to the report: a match counts as a verified file,
/// anything else is reported as an error (a mismatch never "un-copies" the file).
fn verify_pair(
    source: &Path,
    destination: &Path,
    policy: &VerifyPolicy,
    manifest: Option<&Path>,
    relative: &Path,
    report: &mut CopyReport,
) {
    match verify_pair_result(source, destination, policy, manifest, relative) {
        Ok(()) => report.verified_files += 1,
        Err(err) => report.errors.push(err),
    }
}

/// Parse a `.tallow-manifest` file: one `blake3:<hex>  <relative-path>` entry
/// per line, `#` comments and blank lines ignored. Paths use `/` separators.
fn load_manifest(path: &Path) -> Result<HashMap<String, String>, CopyError> {
    let text = fs::read_to_string(path).map_err(|err| {
        invalid_input(
            Some(path.to_path_buf()),
            format!("cannot read manifest: {err}"),
        )
    })?;
    let mut entries = HashMap::new();
    for (index, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((hash, relative)) = line.split_once(char::is_whitespace) else {
            return Err(invalid_input(
                Some(path.to_path_buf()),
                format!("manifest line {}: expected `<hash>  <relative-path>`", index + 1),
            ));
        };
        let hex = hash.trim().strip_prefix("blake3:").unwrap_or(hash.trim());
        if hex.len() != 64 || !hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(invalid_input(
                Some(path.to_path_buf()),
                format!("manifest line {}: `{hash}` is not a 64-hex BLAKE3 digest", index + 1),
            ));
        }
        entries.insert(
            relative.trim().replace('\\', "/"),
            hex.to_ascii_lowercase(),
        );
    }
    Ok(entries)
}

/// Verify one copied file against its manifest entry. A missing entry is an
/// error, not a pass: a manifest that does not list the file cannot vouch for it.
fn verify_manifest(
    destination: &Path,
    relative: &Path,
    manifest: &Path,
) -> Result<(), CopyError> {
    let entries = load_manifest(manifest)?;
    let key = relative.to_string_lossy().replace('\\', "/");
    let Some(expected) = entries.get(&key) else {
        return Err(verify_mismatch(
            destination,
            format!("`{key}` is not listed in manifest {}", manifest.display()),
        ));
    };
    let actual = hash_file(destination)?;
    if actual.eq_ignore_ascii_case(expected) {
        Ok(())
    } else {
        Err(verify_mismatch(
            destination,
            format!("manifest hash mismatch for `{key}`: expected {expected}, got {actual}"),
        ))
    }
}

/// R3-4: the real verification behind every `VerifyPolicy` variant. `Size` compares
/// metadata lengths, `SampledHash` a BLAKE3 hash over fixed sample windows (head,
/// middle, tail), `FullHash`/`ReadAfterWrite` the whole content, and `Manifest`
/// checks each copied file against `CopyJob::manifest`. An unset policy is rejected. A symlink destination is verified as a symlink (link
/// target strings must match) since the copied artifact is the link itself.
fn verify_pair_result(
    source: &Path,
    destination: &Path,
    policy: &VerifyPolicy,
    manifest: Option<&Path>,
    relative: &Path,
) -> Result<(), CopyError> {
    if is_symlink(destination) {
        return verify_symlink_pair(source, destination);
    }

    match policy {
        VerifyPolicy::None => Err(unsupported(
            Some(destination.to_path_buf()),
            "verification requested without a verify policy (VerifyPolicy::None)",
        )),
        VerifyPolicy::Size => verify_size(source, destination),
        VerifyPolicy::SampledHash => verify_sampled_hash(source, destination),
        VerifyPolicy::FullHash | VerifyPolicy::ReadAfterWrite => {
            verify_full_hash(source, destination)
        }
        VerifyPolicy::Manifest => {
            let Some(manifest) = manifest else {
                return Err(unsupported(
                    Some(destination.to_path_buf()),
                    "verify policy Manifest requires CopyJob::manifest",
                ));
            };
            verify_manifest(destination, relative, manifest)
        }
    }
}

fn verify_size(source: &Path, destination: &Path) -> Result<(), CopyError> {
    let source_len = file_len(source)?;
    let destination_len = file_len(destination)?;
    if source_len == destination_len {
        Ok(())
    } else {
        Err(verify_mismatch(
            destination,
            format!("size mismatch: expected {source_len} bytes, got {destination_len} bytes"),
        ))
    }
}

fn verify_sampled_hash(source: &Path, destination: &Path) -> Result<(), CopyError> {
    let source_hash = sampled_hash_file(source)?;
    let destination_hash = sampled_hash_file(destination)?;
    if source_hash == destination_hash {
        Ok(())
    } else {
        Err(verify_mismatch(
            destination,
            format!("sampled hash mismatch: expected {source_hash}, got {destination_hash}"),
        ))
    }
}

fn verify_full_hash(source: &Path, destination: &Path) -> Result<(), CopyError> {
    let source_hash = hash_file(source)?;
    let destination_hash = hash_file(destination)?;
    if source_hash == destination_hash {
        Ok(())
    } else {
        Err(verify_mismatch(
            destination,
            format!("destination hash mismatch: expected {source_hash}, got {destination_hash}"),
        ))
    }
}

fn verify_symlink_pair(source: &Path, destination: &Path) -> Result<(), CopyError> {
    let source_target = fs::read_link(source).map_err(|err| {
        io_error(
            Some(source.to_path_buf()),
            format!("cannot read source symlink: {err}"),
            false,
        )
    })?;
    let destination_target = fs::read_link(destination).map_err(|err| {
        io_error(
            Some(destination.to_path_buf()),
            format!("cannot read destination symlink: {err}"),
            false,
        )
    })?;
    if source_target == destination_target {
        Ok(())
    } else {
        Err(verify_mismatch(
            destination,
            format!(
                "symlink target mismatch: expected {}, got {}",
                source_target.display(),
                destination_target.display()
            ),
        ))
    }
}

fn verify_mismatch(destination: &Path, message: String) -> CopyError {
    CopyError {
        category: CopyErrorCategory::VerifyMismatch,
        path: Some(destination.to_path_buf()),
        message,
        retryable: true,
        recommended_action: "retry_copy".to_string(),
    }
}

fn is_symlink(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|meta| meta.file_type().is_symlink())
        .unwrap_or(false)
}

fn file_len(path: &Path) -> Result<u64, CopyError> {
    fs::metadata(path).map(|meta| meta.len()).map_err(|err| {
        io_error(
            Some(path.to_path_buf()),
            format!("cannot stat for size verification: {err}"),
            true,
        )
    })
}

/// BLAKE3 over the file length plus up to `VERIFY_SAMPLE_WINDOW_COUNT` fixed windows
/// (head, middle, tail) of `VERIFY_SAMPLE_WINDOW_BYTES`. Files that fit inside the
/// sampled region are hashed completely. This is a weaker check than `hash_file`:
/// differences outside the sampled windows are not detected.
fn sampled_hash_file(path: &Path) -> Result<String, CopyError> {
    let mut file = fs::File::open(path).map_err(|err| {
        io_error(
            Some(path.to_path_buf()),
            format!("cannot open for sampled hashing: {err}"),
            true,
        )
    })?;
    let len = file
        .metadata()
        .map_err(|err| {
            io_error(
                Some(path.to_path_buf()),
                format!("cannot stat for sampled hashing: {err}"),
                true,
            )
        })?
        .len();

    let mut hasher = blake3::Hasher::new();
    hasher.update(b"tallow-copy-engine sampled-hash v1");
    hasher.update(&len.to_le_bytes());

    let window = VERIFY_SAMPLE_WINDOW_BYTES;
    if len <= window.saturating_mul(VERIFY_SAMPLE_WINDOW_COUNT) {
        hash_file_region(&mut file, &mut hasher, len, path)?;
    } else {
        let offsets = [0_u64, (len - window) / 2, len - window];
        for offset in offsets {
            hasher.update(&offset.to_le_bytes());
            file.seek(SeekFrom::Start(offset)).map_err(|err| {
                io_error(
                    Some(path.to_path_buf()),
                    format!("sampled hash seek failed: {err}"),
                    true,
                )
            })?;
            hash_file_region(&mut file, &mut hasher, window, path)?;
        }
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// Reads exactly `bytes` (or until EOF) from the current position into `hasher`.
fn hash_file_region(
    file: &mut fs::File,
    hasher: &mut blake3::Hasher,
    bytes: u64,
    path: &Path,
) -> Result<(), CopyError> {
    let mut remaining = bytes;
    let mut buffer = vec![0_u8; VERIFY_SAMPLE_WINDOW_BYTES as usize];
    while remaining > 0 {
        let want = remaining.min(buffer.len() as u64) as usize;
        let read = file.read(&mut buffer[..want]).map_err(|err| {
            io_error(
                Some(path.to_path_buf()),
                format!("sampled hash read failed: {err}"),
                true,
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        remaining -= read as u64;
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, CopyError> {
    let mut file = fs::File::open(path).map_err(|err| {
        io_error(
            Some(path.to_path_buf()),
            format!("cannot open for hashing: {err}"),
            true,
        )
    })?;
    let mut hasher = blake3::Hasher::new();
    let mut buffer = vec![0_u8; 1024 * 1024];

    loop {
        let read = file.read(&mut buffer).map_err(|err| {
            io_error(
                Some(path.to_path_buf()),
                format!("hash read failed: {err}"),
                true,
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }

    Ok(hasher.finalize().to_hex().to_string())
}

/// R3-4: policies that are selectable through the API (and mapped from the app) but
/// are not implemented in this build fail loudly here instead of silently doing
/// nothing. Called from `plan()` and `execute()` so both paths agree.
fn validate_policies(job: &CopyJob) -> Result<(), CopyError> {
    match &job.metadata {
        MetadataPolicy::Security => {
            return Err(unsupported(
                Some(job.source.clone()),
                "metadata policy Security (SELinux contexts / POSIX ACLs) is not implemented in this build; select DataOnly, Timestamps, Attributes or All",
            ));
        }
        MetadataPolicy::Owner => {
            return Err(unsupported(
                Some(job.source.clone()),
                "metadata policy Owner (uid/gid preservation) is not implemented in this build; select DataOnly, Timestamps, Attributes or All",
            ));
        }
        MetadataPolicy::DataOnly
        | MetadataPolicy::Timestamps
        | MetadataPolicy::Attributes
        | MetadataPolicy::All => {}
    }

    if matches!(job.verify, VerifyPolicy::Manifest) && job.manifest.is_none() {
        return Err(unsupported(
            Some(job.source.clone()),
            "verify policy Manifest requires `CopyJob::manifest` (a blake3 manifest: one `<hex>  <relative-path>` line per file)",
        ));
    }

    Ok(())
}

/// R3-4: the policy that is really executed for a verification request. An explicit
/// `CopyMode::Verify` run with `VerifyPolicy::None` verifies by full content hash (the
/// mode itself asks for verification); every other selection maps 1:1.
fn effective_verify_policy(job: &CopyJob) -> VerifyPolicy {
    if matches!(job.verify, VerifyPolicy::None) {
        VerifyPolicy::FullHash
    } else {
        job.verify.clone()
    }
}

/// R3-4: copy actions advertise the verification that execution will really perform,
/// so a plan never claims less (or more) than `execute` does.
fn copy_reason(job: &CopyJob, reason: &str) -> String {
    match job.verify {
        VerifyPolicy::None => reason.to_string(),
        ref policy => format!("{reason}; verify ({policy:?}) after copy"),
    }
}

fn invalid_input(path: Option<PathBuf>, message: impl Into<String>) -> CopyError {
    CopyError {
        category: CopyErrorCategory::InvalidInput,
        path,
        message: message.into(),
        retryable: false,
        recommended_action: "fix_request".to_string(),
    }
}

fn unsupported(path: Option<PathBuf>, message: impl Into<String>) -> CopyError {
    CopyError {
        category: CopyErrorCategory::Unsupported,
        path,
        message: message.into(),
        retryable: false,
        recommended_action: "change_policy".to_string(),
    }
}

fn io_error(path: Option<PathBuf>, message: impl Into<String>, retryable: bool) -> CopyError {
    CopyError {
        category: CopyErrorCategory::Io,
        path,
        message: message.into(),
        retryable,
        recommended_action: if retryable { "retry" } else { "inspect_path" }.to_string(),
    }
}

fn cancelled_error(path: Option<PathBuf>) -> CopyError {
    CopyError {
        category: CopyErrorCategory::Cancelled,
        path,
        message: "copy cancelled".to_string(),
        retryable: false,
        recommended_action: "cancelled".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pre-manifest call shape for the existing verification tests.
    fn verify_legacy(
        source: &Path,
        destination: &Path,
        policy: &VerifyPolicy,
    ) -> Result<(), CopyError> {
        verify_pair_result(source, destination, policy, None, Path::new(""))
    }

    #[test]
    fn dry_run_execute_does_not_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src.txt");
        let destination = tmp.path().join("dst.txt");
        fs::write(&source, b"hello").unwrap();

        let mut job = CopyJob::copy(&source, &destination);
        job.dry_run = true;
        let plan = plan(job).unwrap();
        let report = execute(&plan);

        assert_eq!(report.copied_files, 0);
        assert!(!destination.exists());
    }

    #[test]
    fn copy_job_defaults_to_one_mib_buffer() {
        let job = CopyJob::copy("source", "destination");

        assert_eq!(job.buffer_size_bytes, DEFAULT_BUFFER_SIZE_BYTES);
    }

    #[test]
    fn cancelled_control_stops_before_copying() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src.txt");
        let destination = tmp.path().join("dst.txt");
        fs::write(&source, b"hello").unwrap();

        let plan = plan(CopyJob::copy(&source, &destination)).unwrap();
        let control = CopyControl::new();
        control.cancel();
        let report = execute_with_control(&plan, &control, |_| {});

        assert_eq!(report.copied_files, 0);
        assert!(matches!(
            report.errors.first().map(|error| &error.category),
            Some(CopyErrorCategory::Cancelled)
        ));
        assert!(!destination.exists());
    }

    #[test]
    fn requested_threads_schedule_multiple_copy_workers() {
        let tmp = tempfile::tempdir().unwrap();
        let source_root = tmp.path().join("src");
        let destination_root = tmp.path().join("dst");
        fs::create_dir_all(&source_root).unwrap();
        for index in 0..4 {
            fs::write(
                source_root.join(format!("file-{index}.bin")),
                vec![index; 4096],
            )
            .unwrap();
        }

        let mut job = CopyJob::copy(&source_root, &destination_root);
        job.threads = 2;
        let plan = plan(job).unwrap();
        let report = execute(&plan);

        assert_eq!(report.copied_files, 4);
        assert_eq!(
            fs::read(destination_root.join("file-3.bin")).unwrap(),
            vec![3; 4096]
        );
        assert!(
            report.worker_threads_used >= 2,
            "expected multiple copy workers, got {}",
            report.worker_threads_used
        );
    }

    #[test]
    fn size_verify_passes_and_detects_length_mismatch() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src.bin");
        let destination = tmp.path().join("dst.bin");
        fs::write(&source, b"0123456789").unwrap();
        fs::write(&destination, b"0123456789").unwrap();

        assert!(
            verify_legacy(&source, &destination, &VerifyPolicy::Size).is_ok(),
            "equal sizes should verify"
        );

        fs::write(&destination, b"012345").unwrap();
        let err = verify_legacy(&source, &destination, &VerifyPolicy::Size).unwrap_err();
        assert_eq!(err.category, CopyErrorCategory::VerifyMismatch);
        assert!(err.message.contains("size mismatch"), "{}", err.message);
    }

    #[test]
    fn sampled_hash_detects_same_size_corruption_in_sampled_windows() {
        // 300 KiB is larger than 3 sampled 64 KiB windows, so head/middle/tail are read.
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src.bin");
        let destination = tmp.path().join("dst.bin");
        let mut content = vec![7_u8; 300 * 1024];
        content[0] = 1;
        fs::write(&source, &content).unwrap();

        let mut corrupted = content.clone();
        corrupted[0] = 2;
        fs::write(&destination, &corrupted).unwrap();
        let err =
            verify_legacy(&source, &destination, &VerifyPolicy::SampledHash).unwrap_err();
        assert_eq!(err.category, CopyErrorCategory::VerifyMismatch);
        assert!(err.message.contains("sampled hash mismatch"), "{}", err.message);

        fs::write(&destination, &content).unwrap();
        assert!(
            verify_legacy(&source, &destination, &VerifyPolicy::SampledHash).is_ok(),
            "identical content should verify"
        );
    }

    #[test]
    fn sampled_hash_documents_its_unsampled_region_weakness() {
        // 300 KiB file: head = 0..64 KiB, middle = 118 KiB..182 KiB, tail = 236 KiB..300 KiB.
        // A change at 100 KiB falls between the sampled windows and is NOT detected —
        // this pins the honest scope of SampledHash (FullHash is the whole-file check).
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src.bin");
        let destination = tmp.path().join("dst.bin");
        let content = vec![7_u8; 300 * 1024];
        fs::write(&source, &content).unwrap();

        let mut corrupted = content.clone();
        corrupted[100 * 1024] = 9;
        fs::write(&destination, &corrupted).unwrap();

        assert!(
            verify_legacy(&source, &destination, &VerifyPolicy::SampledHash).is_ok(),
            "the sampler deliberately does not read every byte"
        );
        let err = verify_legacy(&source, &destination, &VerifyPolicy::FullHash).unwrap_err();
        assert_eq!(err.category, CopyErrorCategory::VerifyMismatch);
        assert!(err.message.contains("hash mismatch"), "{}", err.message);
    }

    #[test]
    fn verify_pair_result_rejects_unimplemented_policies() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src.bin");
        let destination = tmp.path().join("dst.bin");
        fs::write(&source, b"same").unwrap();
        fs::write(&destination, b"same").unwrap();

        for policy in [VerifyPolicy::Manifest, VerifyPolicy::None] {
            let err = verify_legacy(&source, &destination, &policy).unwrap_err();
            assert_eq!(err.category, CopyErrorCategory::Unsupported);
        }
    }

    #[test]
    fn validate_policies_rejects_security_owner_and_manifest() {
        let mut job = CopyJob::copy("source", "destination");

        for (policy, needle) in [
            (MetadataPolicy::Security, "Security"),
            (MetadataPolicy::Owner, "Owner"),
        ] {
            job.metadata = policy;
            let err = validate_policies(&job).unwrap_err();
            assert_eq!(err.category, CopyErrorCategory::Unsupported);
            assert!(err.message.contains(needle), "{}", err.message);
        }

        job.metadata = MetadataPolicy::All;
        assert!(validate_policies(&job).is_ok());

        job.verify = VerifyPolicy::Manifest;
        let err = validate_policies(&job).unwrap_err();
        assert_eq!(err.category, CopyErrorCategory::Unsupported);
        assert!(err.message.contains("Manifest"), "{}", err.message);
    }

    #[cfg(unix)]

    /// Register #53: `Mirror` must remove destination entries the source no
    /// longer has. A *symlink* is the case that slipped through — `DirEntry
    /// ::metadata()` follows the link, so a dangling link fails the stat and a
    /// live one reports the target's type, which made the delete branch answer
    /// the wrong question. The link itself is what mirror has to remove.
    #[test]
    fn mirror_deletes_a_destination_symlink_missing_from_source() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src");
        let destination = tmp.path().join("dst");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&destination).unwrap();
        fs::write(source.join("kept.txt"), b"hi").unwrap();
        std::os::unix::fs::symlink("/nonexistent/target", destination.join("stale.link")).unwrap();

        let mut job = CopyJob::copy(&source, &destination);
        job.mode = CopyMode::Mirror;
        job.link_policy = LinkPolicy::Preserve;
        let plan = plan(job).unwrap();

        let deleted: Vec<_> = plan
            .actions
            .iter()
            .filter(|a| matches!(a.kind, CopyActionKind::Delete))
            .map(|a| a.destination.clone())
            .collect();
        assert_eq!(
            deleted,
            vec![destination.join("stale.link")],
            "the stale symlink must be deleted by the plan"
        );
    }

    #[test]
    fn preserve_link_is_skipped_when_it_already_matches() {
        let tmp = tempfile::tempdir().unwrap();
        let source = tmp.path().join("src");
        let destination = tmp.path().join("dst");
        fs::create_dir_all(&source).unwrap();
        fs::create_dir_all(&destination).unwrap();
        fs::write(source.join("kept.txt"), b"hi").unwrap();
        std::os::unix::fs::symlink("kept.txt", source.join("alias.link")).unwrap();
        std::os::unix::fs::symlink("kept.txt", destination.join("alias.link")).unwrap();

        let mut job = CopyJob::copy(&source, &destination);
        job.link_policy = LinkPolicy::Preserve;
        let first = plan(job).unwrap();
        let link_action = first
            .actions
            .iter()
            .find(|a| a.destination.ends_with("alias.link"))
            .expect("the link must appear in the plan");
        assert_eq!(
            link_action.kind,
            CopyActionKind::Skip,
            "an identical link must not be re-created"
        );

        // A link pointing somewhere else is still a copy.
        fs::remove_file(destination.join("alias.link")).unwrap();
        std::os::unix::fs::symlink("elsewhere.txt", destination.join("alias.link")).unwrap();
        let mut job = CopyJob::copy(&source, &destination);
        job.link_policy = LinkPolicy::Preserve;
        let replan = plan(job).unwrap();
        let link_action = replan
            .actions
            .iter()
            .find(|a| a.destination.ends_with("alias.link"))
            .unwrap();
        assert_eq!(
            link_action.kind,
            CopyActionKind::Copy,
            "a link to a different target must be replaced"
        );
    }

    #[test]
    fn plan_dir_skips_special_files_explicitly() {
        let tmp = tempfile::tempdir().unwrap();
        let source_root = tmp.path().join("src");
        let destination_root = tmp.path().join("dst");
        fs::create_dir_all(&source_root).unwrap();
        fs::write(source_root.join("regular.txt"), b"hi").unwrap();
        let socket_path = source_root.join("agent.sock");
        let _listener = std::os::unix::net::UnixListener::bind(&socket_path).unwrap();

        let plan = plan(CopyJob::copy(&source_root, &destination_root)).unwrap();
        let skip = plan
            .actions
            .iter()
            .find(|action| action.source.as_deref() == Some(socket_path.as_path()))
            .expect("socket entry must appear in the plan");
        assert_eq!(skip.kind, CopyActionKind::Skip);
        assert!(skip.reason.contains("special file"), "{}", skip.reason);
    }

    #[test]
    fn manifest_policy_verifies_listed_files() {
        let tmp = tempfile::tempdir().unwrap();
        let source_root = tmp.path().join("src");
        fs::create_dir_all(&source_root).unwrap();
        let file = source_root.join("a.txt");
        fs::write(&file, b"hello").unwrap();
        let hash = hash_file(&file).unwrap();
        let manifest = tmp.path().join("manifest.txt");
        fs::write(&manifest, format!("# test manifest\nblake3:{hash}  a.txt\n")).unwrap();

        let mut job = CopyJob::copy(&source_root, tmp.path().join("dst"));
        job.verify = VerifyPolicy::Manifest;
        job.manifest = Some(manifest.clone());
        let report = execute(&plan(job).unwrap());
        assert!(report.errors.is_empty(), "{:?}", report.errors);
        assert_eq!(report.verified_files, 1);

        // A hash that disagrees with the manifest must fail verification.
        fs::write(&manifest, format!("blake3:{}  a.txt\n", "0".repeat(64))).unwrap();
        let mut job = CopyJob::copy(&source_root, tmp.path().join("dst2"));
        job.verify = VerifyPolicy::Manifest;
        job.manifest = Some(manifest);
        let report = execute(&plan(job).unwrap());
        assert_eq!(report.errors.len(), 1, "{:?}", report.errors);
        assert!(
            report.errors[0].message.contains("manifest hash mismatch"),
            "{}",
            report.errors[0].message
        );
    }
}
