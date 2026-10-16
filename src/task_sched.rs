//! Interpreter-side cooperative task scheduler (F1, increment 1).
//!
//! # Semantics chosen for increment 1 ("coop mode")
//!
//! The tree-walking interpreter gains a real task queue for programs that opt in
//! (`TALLOW_SCHED=coop` in the environment, or `Interpreter::set_coop_scheduler(true)`
//! for tests/embedders):
//!
//! * `spawn f(args)` / `spawn_agent_async("f", args)` no longer start an OS thread
//!   eagerly. They **enqueue** a task (name, body, args, optional per-task
//!   `AgentRuntime`) on a single-threaded **FIFO** ready queue and return a handle
//!   immediately. No part of the task body runs before a *driver* pumps the queue.
//!   (Eager start is impossible to order; deferred start is the first observable
//!   difference from the legacy thread path.)
//! * A **driver** is an `await`/`spawn_await` join, or the exit drain. Drivers run
//!   ready tasks in FIFO order on the current thread, sharing the interpreter, so
//!   task output lands in the same output buffer in a deterministic order.
//! * `await H` / `spawn_await(H)` on a task handle **suspends the awaiting task**:
//!   its state becomes `Blocked { on: H }`, and the driver makes progress on other
//!   ready tasks while `H` is incomplete. When `H` completes, the awaiting frame
//!   resumes with the task's value. (Increment 1 keeps the awaiting frame on the
//!   Rust stack — the suspension point is a task-level join. Mid-expression
//!   continuations / explicit stacks are increment 2; see the C3a report.)
//! * Awaiting a handle that can never complete (a dependency cycle, or a producer
//!   only runnable by the awaiting frame) **fails loud** with a deadlock error
//!   naming the target, the waiter and the pending tasks. The driver never hangs.
//! * Tasks that are never awaited are still run to completion by the exit drain —
//!   the same join-at-exit behavior the legacy thread path has.
//! * A completed task retains its result; awaiting the same handle twice returns
//!   the same value (legacy `spawn_await` consumed the channel — the coop path is
//!   idempotent by construction).
//!
//! Legacy mode (the default) is untouched: eager threads + mpsc result channels.

use crate::agent_runtime::AgentRuntime;
use crate::ast::Block;
use crate::interp::Value;
use std::collections::VecDeque;

/// Lifecycle state of a scheduled task.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Enqueued, never run; runnable.
    Ready,
    /// Body is currently executing (its frame is on the driver's stack).
    Running,
    /// Body is suspended at an await of another handle.
    Blocked,
    /// Body finished (result and/or error recorded).
    Done,
}

impl TaskState {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskState::Ready => "ready",
            TaskState::Running => "running",
            TaskState::Blocked => "blocked",
            TaskState::Done => "done",
        }
    }
}

/// One scheduled task: a function invocation plus its scheduling bookkeeping.
pub struct SchedTask {
    /// Handle returned to the `.tl` program (shares the interpreter's monotonic
    /// `next_spawn_id` counter so coop and legacy handles never collide).
    pub handle: u64,
    /// Function name, for diagnostics.
    pub name: String,
    /// Function body (AST is shared via Arc; no per-run deep clone).
    pub body: std::sync::Arc<Block>,
    /// Parameter names, positionally matched against `args`.
    pub params: Vec<String>,
    /// Evaluated arguments (same-thread transfer — no byte serialization needed).
    pub args: Vec<Value>,
    pub state: TaskState,
    /// When `Blocked`: the handle this task is waiting on.
    pub blocked_on: Option<u64>,
    /// Completed value (idempotent joins).
    pub result: Option<Value>,
    /// Per-task agent runtime for `@agent_task` spawns (moved in at enqueue).
    pub child_runtime: Option<AgentRuntime>,
}

/// Single-threaded FIFO cooperative scheduler.
pub struct Scheduler {
    pub tasks: Vec<SchedTask>,
    ready: VecDeque<usize>,
    /// Set when a join detected an unresolvable wait (deadlock), carrying the
    /// fail-loud message. The driver propagates this as a hard runtime error
    /// instead of recording it as an ordinary task result.
    pub deadlock: Option<String>,
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

impl Scheduler {
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            ready: VecDeque::new(),
            deadlock: None,
        }
    }

    /// Enqueue a task; returns the task index. `handle` is allocated by the caller
    /// (interpreter `next_spawn_id`) and is what the `.tl` program sees.
    pub fn enqueue(
        &mut self,
        handle: u64,
        name: String,
        body: Block,
        params: Vec<String>,
        args: Vec<Value>,
        child_runtime: Option<AgentRuntime>,
    ) -> usize {
        let idx = self.tasks.len();
        self.tasks.push(SchedTask {
            handle,
            name,
            body: std::sync::Arc::new(body),
            params,
            args,
            state: TaskState::Ready,
            blocked_on: None,
            result: None,
            child_runtime,
        });
        self.ready.push_back(idx);
        idx
    }

    /// Task index for a handle, if the handle names a scheduled task.
    pub fn task_index(&self, handle: u64) -> Option<usize> {
        self.tasks.iter().position(|t| t.handle == handle)
    }

    pub fn is_task_handle(&self, handle: u64) -> bool {
        self.task_index(handle).is_some()
    }

    /// Pop the oldest runnable task (defensively skipping non-`Ready` entries).
    pub fn pop_ready(&mut self) -> Option<usize> {
        while let Some(idx) = self.ready.pop_front() {
            if self.tasks[idx].state == TaskState::Ready {
                return Some(idx);
            }
        }
        None
    }

    pub fn set_state(&mut self, idx: usize, state: TaskState, blocked_on: Option<u64>) {
        let t = &mut self.tasks[idx];
        t.state = state;
        t.blocked_on = blocked_on;
    }

    pub fn finish(&mut self, idx: usize, value: Value) {
        let t = &mut self.tasks[idx];
        t.result = Some(value);
        t.state = TaskState::Done;
        t.blocked_on = None;
    }

    /// Completed value of a handle (None while incomplete).
    pub fn result_of(&self, handle: u64) -> Option<Value> {
        self.task_index(handle)
            .and_then(|i| self.tasks[i].result.clone())
    }

    /// Human-readable one-line state per task, for deadlock diagnostics.
    pub fn describe_pending(&self, limit: usize) -> Vec<String> {
        self.tasks
            .iter()
            .filter(|t| t.state != TaskState::Done)
            .take(limit)
            .map(|t| {
                let on = t
                    .blocked_on
                    .map(|h| format!(" blocked-on handle {h}"))
                    .unwrap_or_default();
                format!(
                    "handle {} (task '{}'): {}{}",
                    t.handle,
                    t.name,
                    t.state.as_str(),
                    on
                )
            })
            .collect()
    }
}
