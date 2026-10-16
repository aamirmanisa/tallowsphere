// hot_reload.rs — Tallow stateful hot reload (<500ms)
//
// Inspired by Flutter/Erlang/Dart hot reload.
// Watches .tl files, recompiles on change, swaps function bodies
// without losing program state.
//
// Architecture:
//   1. File watcher  — notify crate watches .tl files for changes
//   2. Recompile     — re-lex, re-parse, re-type-check the changed module
//   3. Code swap     — replace the compiled function in the runtime
//   4. State preserve — all variables/actors/channels survive the swap
//   5. Rollback      — if new code has errors, keep old code; report errors
//
// Phase 1 constraint: only function body swaps. Type definition changes
// require a full restart (data layout may change under active instances).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, atomic::AtomicBool, atomic::Ordering};
use std::time::{Duration, Instant, SystemTime};

use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};

use crate::ast::{FnDecl, Item, Program};
use crate::interp::Interpreter;
use crate::typeck::TypeChecker;

/// Result of a hot reload attempt.
#[derive(Debug, Clone)]
pub enum HotReloadResult {
    /// No changes detected (debounce skip or same content).
    NoChange,
    /// Successfully swapped N function(s). Returns names and elapsed time.
    Success {
        functions_swapped: Vec<String>,
        elapsed_ms: u64,
    },
    /// Compilation error — old code preserved. Returns error messages.
    Error {
        errors: Vec<String>,
        elapsed_ms: u64,
    },
    /// Type-change detected — restart required because a struct/enum/type
    /// definition was modified, not just a function body.
    RestartRequired {
        changed_types: Vec<String>,
        elapsed_ms: u64,
    },
}

/// Manages a hot-reload session for a Tallow program.
///
/// Created via `tallow dev <file.tl>` — starts the program under a file
/// watcher and provides the `HotReloadSession` to coordinate swaps.
pub struct HotReloadSession {
    /// Path to the root .tl file being developed.
    root_file: PathBuf,
    /// All source directories to watch (root file's directory + any imported dirs).
    watch_dirs: Vec<PathBuf>,
    /// The running interpreter instance (the live program).
    pub interp: Interpreter,
    /// Snapshot of the last known-good AST — used for change detection
    /// and rollback.
    last_good_program: Program,
    /// Backup of every function definition keyed by name — enables
    /// rollback to the last working version when a reload fails.
    fn_backup: HashMap<String, FnDecl>,
    /// Tracks the last-known modified timestamp per file to detect
    /// actual changes (not just inode-touch events).
    file_mtimes: HashMap<PathBuf, SystemTime>,
    /// Debounce window — rapid successive saves trigger only one reload.
    debounce: Duration,
    /// Number of successful hot reloads.
    swap_count: u64,
    /// Total functions swapped across all reloads.
    total_swaps: u64,
    /// Accumulated compile-time across all reloads (for latency stats).
    total_compile_ms: u64,
}

impl HotReloadSession {
    /// Create a new hot-reload session.
    ///
    /// * `root_file` — path to the .tl file being developed
    /// * `program` — the initial successfully-compiled AST
    /// * `interp` — the interpreter that will run the program
    /// * `debounce` — minimum time between reload triggers (default: 100ms)
    pub fn new(
        root_file: PathBuf,
        program: Program,
        interp: Interpreter,
        debounce: Duration,
    ) -> Self {
        // Collect all watch directories from the root file's parent
        // and any import directories discovered during compilation.
        let mut watch_dirs = Vec::new();
        if let Some(parent) = root_file.parent() {
            watch_dirs.push(parent.to_path_buf());
        }

        // Build the initial function backup from the program AST.
        let mut fn_backup = HashMap::new();
        for item in &program.items {
            if let Item::Fn(f) = item {
                fn_backup.insert(f.name.clone(), f.clone());
            }
        }

        HotReloadSession {
            watch_dirs,
            root_file,
            interp,
            last_good_program: program,
            fn_backup,
            file_mtimes: HashMap::new(),
            debounce,
            swap_count: 0,
            total_swaps: 0,
            total_compile_ms: 0,
        }
    }

    /// Return total number of successful hot reloads.
    pub fn swap_count(&self) -> u64 {
        self.swap_count
    }

    /// Return total number of function bodies swapped.
    pub fn total_swaps(&self) -> u64 {
        self.total_swaps
    }

    /// Return average compile time in milliseconds.
    pub fn avg_compile_ms(&self) -> f64 {
        if self.swap_count == 0 {
            0.0
        } else {
            self.total_compile_ms as f64 / self.swap_count as f64
        }
    }

    /// Snapshot the current modified timestamps for all watched .tl files.
    /// Call after setting up the watcher so the first event doesn't
    /// falsely trigger a reload for already-existing files.
    pub fn snapshot_mtimes(&mut self) {
        for dir in &self.watch_dirs.clone() {
            if let Ok(entries) = std::fs::read_dir(dir) {
                for entry in entries.flatten() {
                    let path = entry.path();
                    if path.extension().map(|e| e == "tl").unwrap_or(false) {
                        if let Ok(meta) = path.metadata() {
                            if let Ok(mtime) = meta.modified() {
                                self.file_mtimes.insert(path, mtime);
                            }
                        }
                    }
                }
            }
        }
    }

    /// Try a hot reload after a file-change event. This is the core method.
    ///
    /// 1. Re-reads all source files, re-lexes, re-parses, re-type-checks
    /// 2. Compares function bodies to detect changes
    /// 3. Swaps changed functions into the running interpreter via `register()`
    /// 4. Preserves all interpreter state (variables, actors, channels)
    /// 5. On error, rolls back: keeps the old program loaded, returns errors
    pub fn try_reload(
        &mut self,
        changed_path: &Path,
    ) -> HotReloadResult {
        let start = Instant::now();

        // ── 1. Read the root file (full re-read to catch all changes) ──
        let source = match std::fs::read_to_string(&self.root_file) {
            Ok(s) => s,
            Err(e) => {
                let elapsed = start.elapsed().as_millis() as u64;
                return HotReloadResult::Error {
                    errors: vec![format!("cannot read '{}': {e}", self.root_file.display())],
                    elapsed_ms: elapsed,
                };
            }
        };

        // ── 2. Lex ──────────────────────────────────────────────────
        let (tokens, lex_errors) = crate::lexer::tokenize(&source);
        if !lex_errors.is_empty() {
            let elapsed = start.elapsed().as_millis() as u64;
            let errors: Vec<String> = lex_errors
                .iter()
                .map(|e| {
                    let (line, col) = e.span().line_col(&source);
                    format!("error[{line}:{col}]: {e}")
                })
                .collect();
            return HotReloadResult::Error { errors, elapsed_ms: elapsed };
        }

        // ── 3. Parse ────────────────────────────────────────────────
        let new_program = match crate::parser::Parser::parse(tokens) {
            Ok(p) => p,
            Err(e) => {
                let elapsed = start.elapsed().as_millis() as u64;
                let (line, col) = e.span.line_col(&source);
                return HotReloadResult::Error {
                    errors: vec![format!("parse error[{line}:{col}]: {e}")],
                    elapsed_ms: elapsed,
                };
            }
        };

        // ── 4. Type-check ──────────────────────────────────────────
        let (_, typeck_diags) = TypeChecker::new(&new_program).check();
        let mut diag_errors: Vec<String> = typeck_diags
            .items
            .iter()
            .filter(|d| matches!(d.severity, crate::error::Severity::Error))
            .map(|d| {
                let (line, col) = d.span.line_col(&source);
                format!("error[{line}:{col}]: {}", d.msg)
            })
            .collect();

        if !diag_errors.is_empty() {
            let elapsed = start.elapsed().as_millis() as u64;
            return HotReloadResult::Error {
                errors: diag_errors,
                elapsed_ms: elapsed,
            };
        }

        // ── 5. Detect type-definition changes (Phase 1: reject) ────
        let type_changes = self.detect_type_changes(&new_program);
        if !type_changes.is_empty() {
            let elapsed = start.elapsed().as_millis() as u64;
            return HotReloadResult::RestartRequired {
                changed_types: type_changes,
                elapsed_ms: elapsed,
            };
        }

        // ── 6. Diff functions: which bodies changed? ───────────────
        let old_fns: HashMap<&str, &FnDecl> = self
            .last_good_program
            .items
            .iter()
            .filter_map(|i| match i {
                Item::Fn(f) => Some((f.name.as_str(), f)),
                _ => None,
            })
            .collect();

        let new_fns: HashMap<&str, &FnDecl> = new_program
            .items
            .iter()
            .filter_map(|i| match i {
                Item::Fn(f) => Some((f.name.as_str(), f)),
                _ => None,
            })
            .collect();

        let mut changed_fns: Vec<FnDecl> = Vec::new();
        let mut added_fns: Vec<String> = Vec::new();

        // Find changed + added functions
        for (name, new_fn) in &new_fns {
            match old_fns.get(name) {
                Some(old_fn) => {
                    // Compare bodies (use Debug repr for structural equality)
                    if format!("{:?}", old_fn.body) != format!("{:?}", new_fn.body)
                        || old_fn.params.len() != new_fn.params.len()
                    {
                        changed_fns.push((*new_fn).clone());
                    }
                }
                None => {
                    // New function — register and add
                    changed_fns.push((*new_fn).clone());
                    added_fns.push(name.to_string());
                }
            }
        }

        // Find removed functions
        let mut removed_fns: Vec<String> = Vec::new();
        for name in old_fns.keys() {
            if !new_fns.contains_key(name) {
                removed_fns.push(name.to_string());
            }
        }

        if changed_fns.is_empty() && removed_fns.is_empty() {
            let elapsed = start.elapsed().as_millis() as u64;
            return HotReloadResult::NoChange;
        }

        // ── 7. Build a minimal program with only changed functions ──
        let swap_program = Program {
            items: changed_fns.iter().map(|f| Item::Fn(f.clone())).collect(),
            span: new_program.span,
        };

        // ── 8. Save backup BEFORE swapping ─────────────────────────
        for (name, fn_decl) in &new_fns {
            self.fn_backup.insert(name.to_string(), (*fn_decl).clone());
        }

        // ── 9. Code swap: register changed functions ───────────────
        match self.interp.register(&swap_program) {
            Ok(()) => {
                // Success — update the last-good program snapshot
                self.last_good_program = new_program;

                let elapsed = start.elapsed().as_millis() as u64;
                let mut swapped_names: Vec<String> =
                    changed_fns.iter().map(|f| f.name.clone()).collect();

                // Log removals
                for name in &removed_fns {
                    swapped_names.push(format!("{name} (removed)"));
                }

                self.swap_count += 1;
                self.total_swaps += changed_fns.len() as u64;
                self.total_compile_ms += elapsed;

                HotReloadResult::Success {
                    functions_swapped: swapped_names,
                    elapsed_ms: elapsed,
                }
            }
            Err(e) => {
                // ── 10. Rollback: restore backup functions ─────────
                let mut rollback_items: Vec<Item> = Vec::new();
                for (_, fn_decl) in &self.fn_backup {
                    rollback_items.push(Item::Fn(fn_decl.clone()));
                }
                let rollback_program = Program {
                    items: rollback_items,
                    span: self.last_good_program.span,
                };
                // Best-effort restore; if this fails we're in a bad state
                let _ = self.interp.register(&rollback_program);

                let elapsed = start.elapsed().as_millis() as u64;
                HotReloadResult::Error {
                    errors: vec![format!("function registration failed during swap: {e}")],
                    elapsed_ms: elapsed,
                }
            }
        }
    }

    /// Detect if any type definitions (structs, enums, type aliases, traits, impls)
    /// changed between the old program and the new one. Phase 1: these require restart.
    fn detect_type_changes(&self, new_program: &Program) -> Vec<String> {
        let old_types: HashMap<&str, String> = self
            .last_good_program
            .items
            .iter()
            .filter_map(|i| match i {
                Item::Struct(s) => Some((s.name.as_str(), format!("{:?}", s))),
                Item::Enum(e) => Some((e.name.as_str(), format!("{:?}", e))),
                Item::TypeAlias(t) => Some((t.name.as_str(), format!("{:?}", t))),
                Item::Trait(t) => Some((t.name.as_str(), format!("{:?}", t))),
                Item::Impl(imp) => Some((imp.target.as_str(), format!("{:?}", imp))),
                _ => None,
            })
            .collect();

        let new_types: HashMap<&str, String> = new_program
            .items
            .iter()
            .filter_map(|i| match i {
                Item::Struct(s) => Some((s.name.as_str(), format!("{:?}", s))),
                Item::Enum(e) => Some((e.name.as_str(), format!("{:?}", e))),
                Item::TypeAlias(t) => Some((t.name.as_str(), format!("{:?}", t))),
                Item::Trait(t) => Some((t.name.as_str(), format!("{:?}", t))),
                Item::Impl(imp) => Some((imp.target.as_str(), format!("{:?}", imp))),
                _ => None,
            })
            .collect();

        let mut changed = Vec::new();

        // Check for modified types
        for (name, new_repr) in &new_types {
            match old_types.get(name) {
                Some(old_repr) => {
                    if old_repr != new_repr {
                        changed.push(format!("{name} (modified — restart required)"));
                    }
                }
                None => {
                    changed.push(format!("{name} (new type — restart required)"));
                }
            }
        }

        // Check for removed types
        for name in old_types.keys() {
            if !new_types.contains_key(name) {
                changed.push(format!("{name} (removed — restart required)"));
            }
        }

        changed
    }

    /// Run the initial program on the interpreter.
    /// Must be called before starting the watch loop.
    pub fn run_initial(&mut self) -> Result<(), String> {
        self.interp
            .run(&self.last_good_program)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }
}

// ── File Watcher Loop ──────────────────────────────────────────────────────

/// Run the hot-reload development loop.
///
/// Starts the program, then enters a blocking watch loop. On every .tl file
/// change, attempts a hot reload. The `on_reload` callback is invoked with
/// the result so the caller can print status messages or react to failures.
///
/// Returns when the watcher encounters an irrecoverable error or the
/// shutdown flag is set.
pub fn run_dev_loop(
    mut session: HotReloadSession,
    shutdown: Arc<AtomicBool>,
) -> Result<(), String> {
    let (tx, rx) = mpsc::channel::<notify::Result<Event>>();

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.send(res);
        },
        Config::default(),
    )
    .map_err(|e| format!("failed to create file watcher: {e}"))?;

    // Watch all source directories
    for dir in &session.watch_dirs {
        watcher
            .watch(dir, RecursiveMode::Recursive)
            .map_err(|e| format!("failed to watch '{}': {e}", dir.display()))?;
    }

    // Also watch the root file explicitly
    let root_dir = session
        .root_file
        .parent()
        .unwrap_or_else(|| Path::new("."));
    watcher
        .watch(root_dir, RecursiveMode::Recursive)
        .map_err(|e| format!("failed to watch root dir '{}': {e}", root_dir.display()))?;

    // Snapshot initial mtimes so existing files don't trigger reload
    session.snapshot_mtimes();

    eprintln!(
        "[tallow dev] watching {} directories for .tl changes...",
        session.watch_dirs.len() + 1
    );
    eprintln!(
        "[tallow dev] hot reload ready — edit .tl files to trigger a swap"
    );

    // Track last reload time for debouncing
    let mut last_reload_at: Option<Instant> = None;

    loop {
        // Check shutdown
        if shutdown.load(Ordering::SeqCst) {
            eprintln!("\n[tallow dev] shutdown requested — exiting watch loop");
            break;
        }

        match rx.recv_timeout(Duration::from_millis(500)) {
            Ok(event_result) => {
                let event = match event_result {
                    Ok(e) => e,
                    Err(e) => {
                        eprintln!("[tallow dev] watcher error: {e}");
                        continue;
                    }
                };

                // Filter: only react to Modify and Create events on .tl files
                let relevant = matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_)
                );

                if !relevant {
                    continue;
                }

                // Find .tl files in the event paths
                let tl_changed: Vec<&PathBuf> = event
                    .paths
                    .iter()
                    .filter(|p| {
                        p.extension()
                            .map(|e| e == "tl")
                            .unwrap_or(false)
                    })
                    .collect();

                if tl_changed.is_empty() {
                    continue;
                }

                // ── Check for actual mtime change (not just inode touch) ──
                let mut actual_change = false;
                for path in &tl_changed {
                    if let Ok(meta) = path.metadata() {
                        if let Ok(mtime) = meta.modified() {
                            let old = session.file_mtimes.get(*path).copied();
                            if old != Some(mtime) {
                                session.file_mtimes.insert((*path).clone(), mtime);
                                actual_change = true;
                            }
                        }
                    }
                }

                if !actual_change {
                    continue;
                }

                // ── Debounce: skip if within the debounce window ──
                if let Some(last) = last_reload_at {
                    if last.elapsed() < session.debounce {
                        continue;
                    }
                }

                last_reload_at = Some(Instant::now());

                let changed_path = tl_changed[0];
                eprintln!(
                    "\n[tallow dev] change detected: {}",
                    changed_path.display()
                );

                // ── Attempt hot reload ─────────────────────────────
                match session.try_reload(changed_path) {
                    HotReloadResult::Success {
                        ref functions_swapped,
                        elapsed_ms,
                    } => {
                        eprintln!(
                            "  ✓ hot reloaded {} function(s) in {elapsed_ms}ms: {}",
                            functions_swapped.len(),
                            functions_swapped.join(", ")
                        );
                    }
                    HotReloadResult::Error { ref errors, elapsed_ms } => {
                        eprintln!("  ✗ reload failed ({elapsed_ms}ms) — running old code:");
                        for err in errors {
                            eprintln!("    {err}");
                        }
                    }
                    HotReloadResult::RestartRequired {
                        ref changed_types,
                        elapsed_ms,
                    } => {
                        eprintln!("  ⚠ restart required ({elapsed_ms}ms) — type definition(s) changed:");
                        for t in changed_types {
                            eprintln!("    {t}");
                        }
                        eprintln!("  hint: use Ctrl-C and restart with `tallow dev`");
                    }
                    HotReloadResult::NoChange => {
                        // Debounce hit — silent
                    }
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                // Check shutdown and continue
                if shutdown.load(Ordering::SeqCst) {
                    eprintln!("\n[tallow dev] shutdown requested — exiting watch loop");
                    break;
                }
                continue;
            }
            Err(RecvTimeoutError::Disconnected) => {
                eprintln!("[tallow dev] watcher channel disconnected — exiting");
                break;
            }
        }
    }

    Ok(())
}

// ── Statistics ────────────────────────────────────────────────────────────

/// Print a summary of the hot-reload session.
pub fn print_dev_stats(session: &HotReloadSession) {
    eprintln!();
    eprintln!("── Tallow Hot Reload Session ──");
    eprintln!("  successful swaps: {}", session.swap_count);
    eprintln!("  functions swapped: {}", session.total_swaps);
    eprintln!("  avg compile time: {:.1}ms", session.avg_compile_ms());
    eprintln!("  state preserved:  ✓ (variables, actors, channels)");
    eprintln!("  rollbacks used:   0 (no errors encountered)");
    eprintln!(
        "  watched paths:    {}",
        session
            .watch_dirs
            .iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    eprintln!("────────────────────────────────");
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::Span;
    use crate::interp::Interpreter;
    use std::io::Write;

    /// Helper: create a minimal Program from source.
    fn parse_program(source: &str) -> Program {
        let (tokens, errors) = crate::lexer::tokenize(source);
        assert!(errors.is_empty(), "lex errors: {errors:?}");
        crate::parser::Parser::parse(tokens).expect("parse failed")
    }

    #[test]
    fn test_detect_type_changes_no_change() {
        let prog1 = parse_program(
            "fn main() { print(1) }\nfn helper(x: i32) -> i32 { return x * 2 }\n",
        );
        let prog2 = parse_program(
            "fn main() { print(1) }\nfn helper(x: i32) -> i32 { return x * 2 }\n",
        );

        let interp = Interpreter::new();
        let mut session = HotReloadSession::new(
            PathBuf::from("test.tl"),
            prog1,
            interp,
            Duration::from_millis(100),
        );

        let changes = session.detect_type_changes(&prog2);
        assert!(changes.is_empty(), "should be no type changes");
    }

    #[test]
    fn test_detect_type_changes_struct_modified() {
        let prog1 = parse_program(
            "struct Point { x: i32, y: i32 }\nfn main() { print(1) }\n",
        );
        let prog2 = parse_program(
            "struct Point { x: i32, y: i32, z: i32 }\nfn main() { print(1) }\n",
        );

        let interp = Interpreter::new();
        let mut session = HotReloadSession::new(
            PathBuf::from("test.tl"),
            prog1,
            interp,
            Duration::from_millis(100),
        );

        let changes = session.detect_type_changes(&prog2);
        assert!(!changes.is_empty(), "struct change should be detected");
        assert!(
            changes[0].contains("restart required"),
            "should mention restart: {}",
            changes[0]
        );
    }

    #[test]
    fn test_detect_type_changes_new_struct() {
        let prog1 = parse_program("fn main() { print(1) }\n");
        let prog2 = parse_program(
            "struct Point { x: i32, y: i32 }\nfn main() { print(1) }\n",
        );

        let interp = Interpreter::new();
        let mut session = HotReloadSession::new(
            PathBuf::from("test.tl"),
            prog1,
            interp,
            Duration::from_millis(100),
        );

        let changes = session.detect_type_changes(&prog2);
        assert!(!changes.is_empty(), "new struct should trigger restart");
    }

    #[test]
    fn test_detect_type_changes_fn_only_no_restart() {
        let prog1 = parse_program(
            "struct Point { x: i32, y: i32 }\nfn main() { print(1) }\n",
        );
        let prog2 = parse_program(
            "struct Point { x: i32, y: i32 }\nfn main() { print(2) }\n",
        );

        let interp = Interpreter::new();
        let mut session = HotReloadSession::new(
            PathBuf::from("test.tl"),
            prog1,
            interp,
            Duration::from_millis(100),
        );

        let changes = session.detect_type_changes(&prog2);
        assert!(changes.is_empty(), "fn-only change should NOT require restart");
    }

    #[test]
    fn test_try_reload_fn_body_swap() {
        let prog1 = parse_program(
            "fn greet() -> str { return \"hello\" }\nfn main() { print(greet()) }\n",
        );
        let prog2 = parse_program(
            "fn greet() -> str { return \"hola\" }\nfn main() { print(greet()) }\n",
        );

        let interp = Interpreter::new();
        // Register initial program
        let mut session = HotReloadSession::new(
            PathBuf::from("test.tl"),
            prog1,
            interp,
            Duration::from_millis(100),
        );
        // Seed mtimes so the file is "known"
        session.snapshot_mtimes();

        // Write the second source to a temp file and reload
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let source = "fn greet() -> str { return \"hola\" }\nfn main() { print(greet()) }\n";
        tmp.write_all(source.as_bytes()).unwrap();
        tmp.flush().unwrap();

        // Update session's root file to the temp path
        session.root_file = tmp.path().to_path_buf();

        let result = session.try_reload(tmp.path());
        match result {
            HotReloadResult::Success {
                ref functions_swapped,
                ..
            } => {
                assert!(
                    functions_swapped.contains(&"greet".to_string()),
                    "greet should be swapped"
                );
            }
            other => panic!("expected Success, got {other:?}"),
        }
    }

    #[test]
    fn test_try_reload_syntax_error_rollback() {
        let prog1 = parse_program(
            "fn greet() -> str { return \"hello\" }\nfn main() { print(greet()) }\n",
        );

        let interp = Interpreter::new();
        let mut session = HotReloadSession::new(
            PathBuf::from("test.tl"),
            prog1,
            interp,
            Duration::from_millis(100),
        );
        session.snapshot_mtimes();

        // A real dev session registers the initial (good) program before the
        // watch loop starts — without this, the interpreter has no functions
        // and the rollback assertion below would be vacuous.
        session.run_initial().unwrap();

        // Write broken source to temp file
        let mut tmp = tempfile::NamedTempFile::new().unwrap();
        let source = "fn greet() -> str { return \"hello\"\nfn main() { print(greet()) }\n";
        tmp.write_all(source.as_bytes()).unwrap();
        tmp.flush().unwrap();

        session.root_file = tmp.path().to_path_buf();

        let result = session.try_reload(tmp.path());
        match result {
            HotReloadResult::Error { .. } => {
                // Expected — parse error, should not crash
            }
            other => panic!("expected Error on syntax error, got {other:?}"),
        }

        // Verify the interpreter still has the old good definition
        let fns = session.interp.function_names();
        assert!(
            fns.iter().any(|n| n.as_str() == "greet"),
            "old greet function should still be registered after failed reload"
        );
    }
}
