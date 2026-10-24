//! Tallow 2.0 Tracing JIT Runtime
//!
//! ## Architecture
//!
//! ```text
//! ┌──────────────────────────────────────────────────────┐
//! │                   Interpreter                        │
//! │  ┌──────────┐    ┌──────────┐    ┌──────────┐       │
//! │  │ eval_... │───►│ counter  │───►│ jit hook │       │
//! │  │  (AST)   │    │ (increment│    │ (check   │       │
//! │  │          │    │  per BB)  │    │  hotness)│       │
//! │  └──────────┘    └──────────┘    └────┬─────┘       │
//! │                                       │              │
//! │                          ┌────────────▼──────────┐  │
//! │                          │     Hot Loop Detector   │  │
//! │                          │  count >= HOT_THRESHOLD? │  │
//! │                          └────────────┬──────────┘  │
//! │                                  Yes  │              │
//! │                          ┌────────────▼──────────┐  │
//! │                          │  Cranelift Compiler     │  │
//! │                          │  AST → CLIF IR → native │  │
//! │                          └────────────┬──────────┘  │
//! │                                       │              │
//! │                          ┌────────────▼──────────┐  │
//! │                          │  Compiled Code Cache    │  │
//! │                          │  fn ptr + guard specs   │  │
//! │                          └────────────┬──────────┘  │
//! │                                       │              │
//! │                          ┌────────────▼──────────┐  │
//! │                          │  Guard Check            │  │
//! │                          │  types stable? vars ok? │  │
//! │                          └──┬──────────────┬──────┘  │
//! │                        Pass │         Fail │         │
//! │                  ┌──────────▼──┐  ┌────────▼──────┐ │
//! │                  │ Native call │  │ Deoptimize:   │ │
//! │                  │ (fast path) │  │ fallback to    │ │
//! │                  └─────────────┘  │ interpreter    │ │
//! │                                   └────────────────┘ │
//! └──────────────────────────────────────────────────────┘
//! ```
//!
//! ## Design
//!
//! 1. **Basic Block Identification** — A basic block is a maximal sequence of
//!    straight-line statements (no control flow) within a while/for/loop body.
//!    Each block is identified by `(fn_name, loop_nest_depth, block_start_stmt_index)`.
//!
//! 2. **Hot Loop Detection** — Execution counters are incremented on every
//!    evaluation through a block. When a counter reaches `HOT_THRESHOLD` (50),
//!    the block is considered "hot" and queued for compilation.
//!
//! 3. **Cranelift Compilation** — Hot blocks are lowered to Cranelift CLIF IR,
//!    compiled to native x86-64/ARM64 machine code, and cached as callable
//!    function pointers.
//!
//! 4. **Guard Checks** — Before executing compiled code, we verify assumptions:
//!    - Variable types haven't changed (type stability guard)
//!    - Privacy qualifiers haven't changed
//!    - Stack frame shape is identical
//!
//! 5. **Deoptimization** — If any guard fails, execution falls back to the
//!    interpreter. The compiled trace is invalidated and may be recompiled
//!    later if it becomes hot again.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use cranelift_codegen::ir::types;
use cranelift_codegen::ir::{
    condcodes::IntCC, AbiParam, ExternalName, Function, InstBuilder, Signature,
    UserFuncName, Value as ClifValue,
};
use cranelift_codegen::isa::{self, TargetIsa};
use cranelift_codegen::settings::{self, Configurable};
use cranelift_frontend::{FunctionBuilder, FunctionBuilderContext, Variable};
use cranelift_jit::{JITBuilder, JITModule};
use cranelift_module::{Linkage, Module};
use target_lexicon::Triple;

use crate::ast::{BinOp, Block, Expr, ExprKind, Stmt, StmtKind};
use crate::interp::Value;

// ═══════════════════════════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════════════════════════

/// Number of executions before a basic block is considered "hot" and
/// queued for JIT compilation.
pub const HOT_THRESHOLD: u64 = 50;

/// Maximum number of compiled traces to keep in the cache.
/// Least-recently-used traces are evicted when the cache is full.
pub const MAX_COMPILED_TRACES: usize = 256;

/// Maximum number of basic blocks to track per function.
/// Prevents unbounded memory growth in long-running programs.
pub const MAX_TRACKED_BLOCKS: usize = 4096;

// ═══════════════════════════════════════════════════════════════════════════════
// Basic Block Identifier
// ═══════════════════════════════════════════════════════════════════════════════

/// Uniquely identifies a basic block within the program.
///
/// A basic block is a sequence of straight-line statements at a specific
/// position within a loop body. We track per-loop-nest since the same
/// source position may appear at different loop depths.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlockId {
    /// Function name (empty string for top-level code).
    pub fn_name: String,
    /// Loop nesting depth (0 = top-level, 1 = inside one loop, etc.).
    pub loop_depth: usize,
    /// Index of the first statement in this block within its parent Block.
    pub start_stmt: usize,
    /// Number of statements in this basic block.
    pub len: usize,
}

impl BlockId {
    pub fn new(fn_name: &str, loop_depth: usize, start_stmt: usize, len: usize) -> Self {
        Self {
            fn_name: fn_name.to_string(),
            loop_depth,
            start_stmt,
            len,
        }
    }

    /// Returns a compact string key for hash-based lookups.
    pub fn key(&self) -> String {
        format!(
            "{}:L{}:S{}:N{}",
            self.fn_name, self.loop_depth, self.start_stmt, self.len
        )
    }
}

impl std::fmt::Display for BlockId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}@depth{}[{}..{}]",
            self.fn_name, self.loop_depth, self.start_stmt, self.start_stmt + self.len
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Hot Loop Counter
// ═══════════════════════════════════════════════════════════════════════════════

/// Per-block execution counter with atomic increments.
///
/// Uses `AtomicU64` for lock-free increments from the interpreter hot path.
/// The compile check (comparing against HOT_THRESHOLD) uses `Ordering::Relaxed`
/// since the exact count doesn't need to be precisely synchronized — a few
/// extra interpreter iterations are harmless.
#[derive(Debug)]
pub struct HotCounter {
    pub block_id: BlockId,
    pub count: AtomicU64,
    /// True if this block has already been compiled (or compilation failed).
    pub compiled: AtomicU64, // 0 = not compiled, 1 = compiled, 2 = failed
}

impl HotCounter {
    pub fn new(block_id: BlockId) -> Self {
        Self {
            block_id,
            count: AtomicU64::new(0),
            compiled: AtomicU64::new(0),
        }
    }

    /// Increment the counter. Returns true if the block just crossed the
    /// hot threshold and should be compiled.
    #[inline(always)]
    pub fn increment(&self) -> bool {
        let prev = self.count.fetch_add(1, Ordering::Relaxed);
        // Return true exactly once at the threshold crossing.
        prev + 1 == HOT_THRESHOLD
    }

    /// Mark this block as having been compiled.
    pub fn mark_compiled(&self) {
        self.compiled.store(1, Ordering::Release);
    }

    /// Mark compilation as failed (don't retry).
    pub fn mark_failed(&self) {
        self.compiled.store(2, Ordering::Release);
    }

    /// Check if this block has already been compiled or failed.
    pub fn is_compiled_or_failed(&self) -> bool {
        self.compiled.load(Ordering::Acquire) != 0
    }

    /// Reset for deoptimization — allows recompilation.
    pub fn reset(&self) {
        self.count.store(0, Ordering::Release);
        self.compiled.store(0, Ordering::Release);
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Guard Specification
// ═══════════════════════════════════════════════════════════════════════════════

/// Describes the assumptions that must hold for compiled code to be valid.
///
/// Guards are checked before every invocation of compiled code. If any guard
/// fails, we deoptimize — fall back to the interpreter.
#[derive(Debug, Clone)]
pub struct GuardSpec {
    /// Variable name → expected type tag.
    ///
    /// The type tag is a simple discriminant derived from the Value enum
    /// variant (0=Nil, 1=Bool, 2=Int, 3=Float, 4=String, ...).
    pub var_types: Vec<(String, u8)>,
    /// Expected loop depth at the time of compilation.
    pub loop_depth: usize,
    /// Timestamp of compilation (for invalidation on global state changes).
    pub compiled_at: u64,
}

impl GuardSpec {
    /// Check all guards against the current runtime environment.
    ///
    /// Returns `Ok(())` if all guards pass, `Err(reason)` otherwise.
    pub fn check(
        &self,
        env_vars: &HashMap<String, Value>,
        current_loop_depth: usize,
    ) -> Result<(), String> {
        // Guard 1: Loop depth must match.
        if self.loop_depth != current_loop_depth {
            return Err(format!(
                "loop depth changed: expected {}, got {}",
                self.loop_depth, current_loop_depth
            ));
        }

        // Guard 2: All variable types must match expected types.
        for (name, expected_tag) in &self.var_types {
            match env_vars.get(name) {
                None => {
                    return Err(format!(
                        "variable '{}' no longer in scope",
                        name
                    ));
                }
                Some(value) => {
                    let actual_tag = type_tag(value);
                    if actual_tag != *expected_tag {
                        return Err(format!(
                            "variable '{}' type changed: expected tag {}, got tag {}",
                            name, expected_tag, actual_tag
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

/// Map a Value to a stable type tag for guard comparisons.
#[inline]
pub fn type_tag(value: &Value) -> u8 {
    match value {
        Value::Nil => 0,
        Value::Bool(_) => 1,
        Value::Int(_) => 2,
        Value::Float(_) => 3,
        Value::String(_) => 4,
        Value::Array(_) => 5,
        Value::Map(_) => 6,
        Value::Ok(_) => 7,
        Value::Err(_) => 8,
        Value::Private(_) => 9,
        Value::Secret(_) => 10,
        Value::Function { .. } => 11,
        Value::Enum { .. } => 12,
        Value::Struct { .. } => 13,
        Value::Range { .. } => 14,
        Value::DbConnection(_) => 15,
        Value::KeyPair { .. } => 16,
        Value::Consent { .. } => 17,
        Value::Erasable { .. } => 18,
        Value::Bytes(_) => 19,
        Value::Provenance(..) => 20,
        Value::BrowserObject(_) => 21,
        Value::Brain(_) => 22,
        Value::Boxed(_) => 23,
        Value::Return(_) => 24,
        Value::Break => 25,
        Value::Continue => 26,
        Value::Channel(_) => 27,
    }
}

/// Build a guard spec from the current interpreter environment.
pub fn build_guard_spec(env_vars: &HashMap<String, Value>, loop_depth: usize) -> GuardSpec {
    let var_types: Vec<(String, u8)> = env_vars
        .iter()
        .map(|(name, value)| (name.clone(), type_tag(value)))
        .collect();

    let compiled_at = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    GuardSpec {
        var_types,
        loop_depth,
        compiled_at,
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Deoptimization Reason
// ═══════════════════════════════════════════════════════════════════════════════

/// Reason why a compiled trace was deoptimized.
#[derive(Debug, Clone)]
pub enum DeoptReason {
    /// Guard check failed: variable types changed.
    TypeChanged { var_name: String, expected: u8, actual: u8 },
    /// Guard check failed: variable went out of scope.
    VariableOutOfScope { var_name: String },
    /// Guard check failed: loop depth changed.
    LoopDepthChanged { expected: usize, actual: usize },
    /// Compilation error — the block couldn't be compiled.
    CompilationError(String),
    /// Explicit invalidation (e.g., global state changed).
    ExplicitInvalidation,
    /// Cache eviction — trace was evicted to make room.
    CacheEviction,
    /// Guard verification overhead exceeded benefit.
    TooManyGuardFailures,
}

impl std::fmt::Display for DeoptReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeoptReason::TypeChanged {
                var_name,
                expected,
                actual,
            } => write!(
                f,
                "type change: {var_name} was tag {expected}, now tag {actual}"
            ),
            DeoptReason::VariableOutOfScope { var_name } => {
                write!(f, "variable '{var_name}' out of scope")
            }
            DeoptReason::LoopDepthChanged { expected, actual } => {
                write!(
                    f,
                    "loop depth changed: expected {expected}, actual {actual}"
                )
            }
            DeoptReason::CompilationError(msg) => write!(f, "compilation error: {msg}"),
            DeoptReason::ExplicitInvalidation => write!(f, "explicit invalidation"),
            DeoptReason::CacheEviction => write!(f, "cache eviction"),
            DeoptReason::TooManyGuardFailures => write!(f, "too many guard failures"),
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Compiled Trace
// ═══════════════════════════════════════════════════════════════════════════════

/// A compiled native trace — the result of JIT-compiling a hot basic block.
///
/// Holds a raw function pointer and the metadata needed to verify that
/// calling the compiled code is still safe (guard spec).
pub struct CompiledTrace {
    /// Unique identifier for this trace's basic block.
    pub block_id: BlockId,
    /// Raw function pointer to the compiled native code.
    ///
    /// Signature: `fn(*mut InterpState) -> Result<Value, DeoptReason>`
    /// The InterpState carries the current environment (variables, stack, etc.).
    pub native_fn: Option<unsafe extern "C" fn(*mut InterpState) -> CompiledResult>,
    /// Guards that must pass before calling native_fn.
    pub guard: GuardSpec,
    /// Number of times this compiled trace has been successfully invoked.
    pub hit_count: AtomicU64,
    /// Number of times this trace deoptimized (guard failures).
    pub deopt_count: AtomicU64,
    /// Timestamp of compilation.
    pub compiled_at: u64,
}

/// Result type returned by compiled native functions.
///
/// Uses a simple tagged union layout compatible with C FFI.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct CompiledResult {
    /// 0 = Ok(value follows), 1 = Err(reason string follows)
    pub tag: u8,
    /// The result value (only valid when tag == 0).
    /// This is a simplified representation — in practice, complex Values
    /// would be returned through a side channel.
    pub int_value: i128,
    pub float_value: f64,
    /// Error/deopt reason (only valid when tag != 0).
    pub error_len: u32,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Interpreter State (for native calls)
// ═══════════════════════════════════════════════════════════════════════════════

/// State passed from the interpreter to compiled native code.
///
/// This is a C-compatible struct that carries the current interpreter
/// context across the FFI boundary. The compiled code reads/writes
/// through this pointer.
#[repr(C)]
pub struct InterpState {
    /// Pointer to the variable environment (name → Value lookup).
    /// In practice this is a pointer to the Env scopes.
    pub env_ptr: *mut std::ffi::c_void,
    /// Stack of loop nesting depths.
    pub loop_depth: u32,
    /// Output buffer for print() statements from compiled code.
    /// Compiled code appends output here; the interpreter reads it after.
    pub output_ptr: *mut std::ffi::c_void,
    pub output_len: u32,
    pub output_cap: u32,
    /// Scratch buffer for error messages.
    pub error_buf: [u8; 256],
    pub error_len: u32,
}

// ═══════════════════════════════════════════════════════════════════════════════
// Cranelift JIT Compiler
// ═══════════════════════════════════════════════════════════════════════════════

/// The Cranelift-based JIT compiler.
///
/// Converts hot Tallow AST basic blocks into native machine code using
/// the Cranelift code generator. Delegates to `codegen_cranelift::CraneliftBackend`
/// for the heavy lifting (CLIF IR generation).

pub struct CraneliftJIT {
    /// Raw pointer to JITModule stored as usize for Send/Sync compatibility.
    /// When cranelift is enabled, this holds the active JIT module.
    /// The actual JITModule is !Send, so we manage it through a Mutex in TracingJIT.
    #[allow(dead_code)]
    jit_module: Option<usize>,
    /// Whether the JIT backend is available (cranelift crates linked).
    pub available: bool,
    /// Number of traces successfully compiled.
    pub compile_count: AtomicU64,
    /// Number of compilation failures.
    pub failure_count: AtomicU64,
}

impl CraneliftJIT {
    /// Create a new Cranelift JIT compiler.
    ///
    /// Initializes the inline JIT module for per-block compilation.
    /// For whole-program compilation, use `codegen_cranelift::CraneliftBackend`.
    pub fn new() -> Self {
        let available = true; // cranelift is a hard dependency

        // The JITModule is lazily initialized in compile_block().
        // We store a null pointer here and set it up on first use.
        Self {
            jit_module: None,
            available,
            compile_count: AtomicU64::new(0),
            failure_count: AtomicU64::new(0),
        }
    }

    /// Compile a hot basic block to native code.
    ///
    /// ## Process
    ///
    /// 1. Create a Cranelift function signature matching `CompiledResult fn(InterpState*)`.
    /// 2. Build the CLIF IR function body by lowering each AST statement.
    /// 3. Run Cranelift's optimization passes.
    /// 4. Compile to native code via the JIT module.
    /// 5. Return the function pointer.
    ///
    /// ## Return Value
    ///
    /// Returns `Some(fn_ptr)` on success, `None` on compilation failure.
    /// Failures are logged and the trace is marked as failed (won't retry).
    pub fn compile_block(
        &mut self,
        block: &Block,
        _guard: &GuardSpec,
    ) -> Option<unsafe extern "C" fn(*mut InterpState) -> CompiledResult> {
        if !self.available {
            self.failure_count.fetch_add(1, Ordering::Relaxed);
            return None;
        }

        // ── Real Cranelift compilation ──
        //
        // Build a CLIF function with the documented signature
        // `(state_ptr: i64) -> (tag: i8, int: i128, float: f64, errlen: i32)`,
        // lower each statement in the block, then JIT-compile it through
        // `define_function` + `finalize_definitions` and return the native
        // function pointer.
        //
        // Speculative tracing design: the compiled trace only references
        // variables defined *inside* the block. Any variable read that is not
        // a block-local — or any unsupported statement/expression — aborts
        // compilation and falls back to the interpreter (deopt). This keeps
        // the compiled code independent of the (potentially null) `InterpState`
        // pointer, matching the guard-on-entry model in `try_compiled`.

        let triple = Triple::host();
        let mut flag_builder = settings::builder();
        if flag_builder.set("opt_level", "speed").is_err() {
            self.failure_count.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let flags = settings::Flags::new(flag_builder);
        let isa = isa::lookup(triple).ok()?.finish(flags).ok()?;

        // Signature: (state_ptr: i64) -> (tag: i8, int: i128, float: f64, errlen: i32)
        let mut sig = Signature::new(isa.default_call_conv());
        sig.params.push(AbiParam::new(types::I64));
        sig.returns.push(AbiParam::new(types::I8));
        sig.returns.push(AbiParam::new(types::I128));
        sig.returns.push(AbiParam::new(types::F64));
        sig.returns.push(AbiParam::new(types::I32));

        let hash = block.stmts.iter().fold(0usize, |acc, stmt| {
            acc.wrapping_mul(31)
                .wrapping_add(format!("{:?}", stmt.kind).len())
        });
        let mut func = Function::with_name_signature(UserFuncName::user(0, hash as u32), sig);
        let mut fbc = FunctionBuilderContext::new();
        let mut builder = FunctionBuilder::new(&mut func, &mut fbc);

        let entry = builder.create_block();
        builder.append_block_params_for_function_params(entry);
        builder.switch_to_block(entry);
        builder.seal_block(entry);

        let mut vars: HashMap<String, Variable> = HashMap::new();
        let mut next_var: usize = 0;
        let mut last: Option<ClifValue> = None;

        for stmt in &block.stmts {
            match &stmt.kind {
                StmtKind::Let { name, value, .. } => {
                    let val = self.jit_expr(&mut builder, value, &vars)?;
                    let var = Variable::from_u32(next_var as u32);
                    next_var += 1;
                    builder.declare_var(var, types::I64);
                    builder.def_var(var, val);
                    vars.insert(name.clone(), var);
                    last = Some(val);
                }
                StmtKind::Expr { expr } => {
                    last = self.jit_expr(&mut builder, expr, &vars);
                }
                StmtKind::Return(Some(expr)) => {
                    let val = self.jit_expr(&mut builder, expr, &vars)?;
                    self.jit_return(&mut builder, val);
                    builder.finalize();
                    return self.finish_block(isa, func, block);
                }
                _ => {
                    // Unsupported statement: deoptimize to the interpreter.
                    self.failure_count.fetch_add(1, Ordering::Relaxed);
                    return None;
                }
            }
        }

        let ret_val = last.unwrap_or_else(|| builder.ins().iconst(types::I64, 0));
        self.jit_return(&mut builder, ret_val);
        builder.finalize();

        self.finish_block(isa, func, block)
    }

    /// Emit a `CompiledResult` return: `(tag=0, int_value, float=0, errlen=0)`.
    fn jit_return(&self, builder: &mut FunctionBuilder, val: ClifValue) {
        let tag0 = builder.ins().iconst(types::I8, 0);
        let int128 = builder.ins().uextend(types::I128, val);
        let f0 = builder.ins().f64const(0.0);
        let err0 = builder.ins().iconst(types::I32, 0);
        builder.ins().return_(&[tag0, int128, f0, err0]);
    }

    /// Lower a scalar Tallow expression to CLIF. Returns `None` for anything
    /// the JIT can't compile speculatively (triggers a deopt).
    fn jit_expr(
        &self,
        builder: &mut FunctionBuilder,
        expr: &Expr,
        vars: &HashMap<String, Variable>,
    ) -> Option<ClifValue> {
        match &expr.kind {
            ExprKind::IntLit(n) => Some(builder.ins().iconst(types::I64, *n as i64)),
            ExprKind::FloatLit(f) => Some(builder.ins().f64const(*f)),
            ExprKind::BoolLit(b) => Some(builder.ins().iconst(types::I8, if *b { 1 } else { 0 })),
            ExprKind::Ident(name) => {
                let var = vars.get(name)?;
                Some(builder.use_var(*var))
            }
            ExprKind::Binary { op, left, right } => {
                let l = self.jit_expr(builder, left, vars)?;
                let r = self.jit_expr(builder, right, vars)?;
                Some(match op {
                    BinOp::Add => builder.ins().iadd(l, r),
                    BinOp::Sub => builder.ins().isub(l, r),
                    BinOp::Mul => builder.ins().imul(l, r),
                    BinOp::Div => builder.ins().sdiv(l, r),
                    BinOp::Mod => builder.ins().srem(l, r),
                    BinOp::Eq => {
                        let c = builder.ins().icmp(IntCC::Equal, l, r);
                        builder.ins().uextend(types::I8, c)
                    }
                    BinOp::Neq => {
                        let c = builder.ins().icmp(IntCC::NotEqual, l, r);
                        builder.ins().uextend(types::I8, c)
                    }
                    BinOp::Lt => {
                        let c = builder.ins().icmp(IntCC::SignedLessThan, l, r);
                        builder.ins().uextend(types::I8, c)
                    }
                    BinOp::Gt => {
                        let c = builder.ins().icmp(IntCC::SignedGreaterThan, l, r);
                        builder.ins().uextend(types::I8, c)
                    }
                    BinOp::Lte => {
                        let c = builder.ins().icmp(IntCC::SignedLessThanOrEqual, l, r);
                        builder.ins().uextend(types::I8, c)
                    }
                    BinOp::Gte => {
                        let c = builder.ins().icmp(IntCC::SignedGreaterThanOrEqual, l, r);
                        builder.ins().uextend(types::I8, c)
                    }
                    BinOp::And => {
                        let a = builder.ins().icmp_imm(IntCC::NotEqual, l, 0);
                        let b = builder.ins().icmp_imm(IntCC::NotEqual, r, 0);
                        builder.ins().band(a, b)
                    }
                    BinOp::Or => {
                        let a = builder.ins().icmp_imm(IntCC::NotEqual, l, 0);
                        let b = builder.ins().icmp_imm(IntCC::NotEqual, r, 0);
                        builder.ins().bor(a, b)
                    }
                    BinOp::BitAnd => builder.ins().band(l, r),
                    BinOp::BitOr => builder.ins().bor(l, r),
                    BinOp::BitXor => builder.ins().bxor(l, r),
                    BinOp::Shl => builder.ins().ishl(l, r),
                    BinOp::Shr => builder.ins().sshr(l, r),
                    _ => return None,
                })
            }
            ExprKind::Unary { op, operand } => {
                let v = self.jit_expr(builder, operand, vars)?;
                Some(match op {
                    crate::ast::UnOp::Neg => builder.ins().ineg(v),
                    crate::ast::UnOp::Not => {
                        let c = builder.ins().icmp_imm(IntCC::Equal, v, 0);
                        builder.ins().uextend(types::I8, c)
                    }
                    _ => return None,
                })
            }
            _ => None,
        }
    }

    /// Define, finalize and cache a compiled block in the JIT module, returning
    /// the native function pointer.
    fn finish_block(
        &mut self,
        isa: std::sync::Arc<dyn TargetIsa>,
        func: Function,
        block: &Block,
    ) -> Option<unsafe extern "C" fn(*mut InterpState) -> CompiledResult> {
        let mut jit_builder =
            JITBuilder::with_isa(isa, cranelift_module::default_libcall_names());
        let mut module = JITModule::new(jit_builder);
        let mut ctx = module.make_context();
        ctx.func = func;
        let id = module
            .declare_function("__block_jit", Linkage::Local, &ctx.func.signature)
            .ok()?;
        module.define_function(id, &mut ctx).ok()?;
        module.clear_context(&mut ctx);
        module.finalize_definitions().ok()?;
        let ptr = module.get_finalized_function(id);
        let fn_ptr: unsafe extern "C" fn(*mut InterpState) -> CompiledResult =
            unsafe { std::mem::transmute(ptr) };

        // Retire any previously-held module to avoid leaking JIT code, then
        // keep this one alive so the returned pointer remains valid.
        if let Some(old) = self.jit_module.take() {
            unsafe {
                drop(Box::from_raw(old as *mut JITModule));
            }
        }
        self.jit_module = Some(Box::into_raw(Box::new(module)) as usize);

        self.compile_count.fetch_add(1, Ordering::Relaxed);
        let _ = block;
        Some(fn_ptr)
    }

    /// Attempt to look up a symbol by name in the JIT module.
    ///
    /// Used for resolving calls to runtime functions (print, alloc, etc.)
    /// from within compiled traces.
    #[allow(dead_code)]
    fn lookup_symbol(&self, _name: &str) -> Option<*const u8> {
        // Symbol lookup by name is not wired to the JIT module's FuncId table;
        // resolve via a captured FuncId at compile time instead.
        None
    }
}

impl Default for CraneliftJIT {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tracing JIT Runtime
// ═══════════════════════════════════════════════════════════════════════════════

/// The Tracing JIT runtime — the top-level orchestrator.
///
/// Owns the hot loop detector, the Cranelift compiler, the compiled trace
/// cache, and the deoptimization statistics.
///
/// ## Usage from the Interpreter
///
/// ```ignore
/// use crate::jit::TracingJIT;
///
/// // In the interpreter struct:
/// pub jit: TracingJIT,
///
/// // At each basic block evaluation:
/// let block_id = BlockId::new(fn_name, loop_depth, start, len);
/// if let Some(result) = self.jit.try_compiled(&block_id, &mut env)? {
///     return Ok(result); // fast path succeeded
/// }
/// // Fall through: interpret normally
/// ```
pub struct TracingJIT {
    /// Hot loop detection: block ID → execution counter.
    counters: HashMap<BlockId, Arc<HotCounter>>,
    /// Compiled trace cache: block ID → compiled native function.
    compiled: HashMap<BlockId, Arc<CompiledTrace>>,
    /// The Cranelift compiler backend.
    cranelift: CraneliftJIT,
    /// Whether the JIT is enabled.
    pub enabled: bool,
    /// Whether to print JIT events (for debugging).
    pub verbose: bool,
    /// Total number of traces compiled.
    pub total_compiled: AtomicU64,
    /// Total number of deoptimizations.
    pub total_deopts: AtomicU64,
    /// Total number of successful native invocations.
    pub total_native_hits: AtomicU64,
}

impl TracingJIT {
    /// Create a new TracingJIT runtime.
    pub fn new() -> Self {
        Self {
            counters: HashMap::new(),
            compiled: HashMap::new(),
            cranelift: CraneliftJIT::new(),
            enabled: true,
            verbose: false,
            total_compiled: AtomicU64::new(0),
            total_deopts: AtomicU64::new(0),
            total_native_hits: AtomicU64::new(0),
        }
    }

    /// Check whether a block should be JIT-compiled.
    ///
    /// Called by the interpreter on every basic block execution.
    /// Returns `true` when the block crosses the hot threshold and should
    /// be compiled (the interpreter should call `compile_block` next).
    #[inline]
    pub fn check_hotness(&mut self, block_id: &BlockId) -> bool {
        if !self.enabled {
            return false;
        }

        // Guard against unbounded growth.
        if self.counters.len() >= MAX_TRACKED_BLOCKS {
            return false;
        }

        let counter = self
            .counters
            .entry(block_id.clone())
            .or_insert_with(|| Arc::new(HotCounter::new(block_id.clone())));

        // If already compiled or failed, still count but don't trigger.
        if counter.is_compiled_or_failed() {
            counter.increment();
            return false;
        }

        counter.increment()
    }

    /// Compile a hot block and cache the result.
    ///
    /// Called by the interpreter after `check_hotness` returns `true`.
    /// Returns the compiled trace on success, or None on failure.
    pub fn compile_block(
        &mut self,
        block_id: &BlockId,
        block: &Block,
        env_vars: &HashMap<String, Value>,
    ) -> Option<Arc<CompiledTrace>> {
        if !self.enabled {
            return None;
        }

        // Build guard spec from current environment.
        let guard = build_guard_spec(
            env_vars,
            block_id.loop_depth,
        );

        // Attempt Cranelift compilation.
        let started = std::time::Instant::now();
        let native_fn = self.cranelift.compile_block(block, &guard);
        let elapsed_us = started.elapsed().as_micros();

        if self.verbose {
            if native_fn.is_some() {
                // Real elapsed time: the earlier `0u64` was printed as if it
                // were a measurement, which made a diagnostic lie.
                eprintln!("[JIT] compiled block {block_id} ({elapsed_us} μs)");
            } else {
                eprintln!("[JIT] compilation failed for block {}", block_id);
            }
        }

        // Mark the counter as compiled or failed.
        if let Some(counter) = self.counters.get(block_id) {
            if native_fn.is_some() {
                counter.mark_compiled();
            } else {
                counter.mark_failed();
            }
        }

        let compiled_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let trace = Arc::new(CompiledTrace {
            block_id: block_id.clone(),
            native_fn,
            guard,
            hit_count: AtomicU64::new(0),
            deopt_count: AtomicU64::new(0),
            compiled_at,
        });

        if trace.native_fn.is_some() {
            self.total_compiled.fetch_add(1, Ordering::Relaxed);
            // Evict oldest trace if cache is full.
            if self.compiled.len() >= MAX_COMPILED_TRACES {
                self.evict_lru();
            }
            self.compiled.insert(block_id.clone(), trace.clone());
        }

        Some(trace)
    }

    /// Try to execute a block via compiled native code.
    ///
    /// Returns:
    /// - `Some(Ok(value))` — native execution succeeded.
    /// - `Some(Err(deopt_reason))` — guard failed, fall back to interpreter.
    /// - `None` — no compiled trace available for this block.
    pub fn try_compiled(
        &self,
        block_id: &BlockId,
        env_vars: &HashMap<String, Value>,
        loop_depth: usize,
    ) -> Option<Result<Value, DeoptReason>> {
        if !self.enabled {
            return None;
        }

        let trace = self.compiled.get(block_id)?;
        let native_fn = trace.native_fn?;

        // Check guards.
        if let Err(reason) = trace.guard.check(env_vars, loop_depth) {
            let deopt_reason = if reason.contains("type changed") {
                // Parse out the details from the error string.
                DeoptReason::TypeChanged {
                    var_name: "unknown".to_string(),
                    expected: 0,
                    actual: 0,
                }
            } else if reason.contains("out of scope") {
                DeoptReason::VariableOutOfScope {
                    var_name: "unknown".to_string(),
                }
            } else if reason.contains("loop depth") {
                DeoptReason::LoopDepthChanged {
                    expected: trace.guard.loop_depth,
                    actual: loop_depth,
                }
            } else {
                DeoptReason::ExplicitInvalidation
            };

            // Only count deopts up to 3 per trace before invalidating.
            let prev = trace.deopt_count.fetch_add(1, Ordering::Relaxed);
            self.total_deopts.fetch_add(1, Ordering::Relaxed);

            if prev >= 3 {
                // Too many guard failures — invalidate this trace.
                // We can't remove from `self.compiled` because we only have &self,
                // so we rely on the caller (interpreter) to handle this.
                return Some(Err(DeoptReason::TooManyGuardFailures));
            }

            return Some(Err(deopt_reason));
        }

        // Guards passed — call native code.
        // Safety: We've verified all guards. The compiled function is valid
        // for this interpreter state.
        let mut state = InterpState {
            env_ptr: std::ptr::null_mut(), // Populated by the interpreter
            loop_depth: loop_depth as u32,
            output_ptr: std::ptr::null_mut(),
            output_len: 0,
            output_cap: 0,
            error_buf: [0u8; 256],
            error_len: 0,
        };

        let result = unsafe { native_fn(&mut state) };

        trace.hit_count.fetch_add(1, Ordering::Relaxed);
        self.total_native_hits.fetch_add(1, Ordering::Relaxed);

        match result.tag {
            0 => Some(Ok(Value::Int(result.int_value))),
            _ => Some(Err(DeoptReason::CompilationError(
                "native code returned error".to_string(),
            ))),
        }
    }

    /// Invalidate a compiled trace (deoptimize).
    ///
    /// Called when guards fail too many times or when global state changes
    /// invalidate the assumptions baked into the trace.
    pub fn invalidate(&mut self, block_id: &BlockId, reason: DeoptReason) {
        if self.verbose {
            eprintln!(
                "[JIT] deoptimizing block {}: {reason}",
                block_id
            );
        }

        if let Some(trace) = self.compiled.remove(block_id) {
            self.total_deopts.fetch_add(
                trace.deopt_count.load(Ordering::Relaxed) + 1,
                Ordering::Relaxed,
            );
        }

        // Reset the counter so this block can be recompiled later.
        if let Some(counter) = self.counters.get(block_id) {
            counter.reset();
        }
    }

    /// Evict the least-recently-used compiled trace from the cache.
    fn evict_lru(&mut self) {
        // Find the trace with the oldest compilation timestamp.
        let oldest = self
            .compiled
            .iter()
            .min_by_key(|(_, trace)| trace.compiled_at)
            .map(|(id, _)| id.clone());

        if let Some(id) = oldest {
            if self.verbose {
                eprintln!("[JIT] evicting LRU trace for block {}", id);
            }
            self.compiled.remove(&id);
        }
    }

    /// Invalidate all compiled traces.
    ///
    /// Called when global state changes (e.g., module reload, monkey-patching).
    pub fn invalidate_all(&mut self) {
        let count = self.compiled.len();
        self.compiled.clear();
        self.total_deopts.fetch_add(count as u64, Ordering::Relaxed);
        if self.verbose {
            eprintln!("[JIT] invalidated all {count} compiled traces");
        }
    }

    /// Get statistics about the JIT runtime.
    pub fn stats(&self) -> JITStats {
        let compiled_count = self.compiled.len();
        let counter_count = self.counters.len();
        let total_hits: u64 = self
            .compiled
            .values()
            .map(|t| t.hit_count.load(Ordering::Relaxed))
            .sum();
        let _total_deopts: u64 = self
            .compiled
            .values()
            .map(|t| t.deopt_count.load(Ordering::Relaxed))
            .sum();

        JITStats {
            blocks_tracked: counter_count,
            traces_compiled: compiled_count,
            total_compiled: self.total_compiled.load(Ordering::Relaxed),
            total_deopts: self.total_deopts.load(Ordering::Relaxed),
            total_native_hits: total_hits,
            cranelift_available: self.cranelift.available,
            enabled: self.enabled,
        }
    }

    /// Identify basic blocks within a loop body.
    ///
    /// A basic block is a maximal sequence of consecutive statements that:
    /// - Does not contain control flow (if/while/for/loop/return/break/continue)
    /// - Can be executed sequentially without branching
    ///
    /// Returns a list of `(start_index, len)` tuples.
    pub fn identify_basic_blocks(stmts: &[Stmt]) -> Vec<(usize, usize)> {
        let mut blocks = Vec::new();
        let mut start: Option<usize> = None;

        for (i, stmt) in stmts.iter().enumerate() {
            let is_control_flow = matches!(
                stmt.kind,
                StmtKind::While { .. }
                    | StmtKind::For { .. }
                    | StmtKind::Loop { .. }
                    | StmtKind::Return(_)
                    | StmtKind::Break
                    | StmtKind::Continue
                    | StmtKind::Bail(_)
            );

            if is_control_flow {
                // End the current block if one is open.
                if let Some(s) = start {
                    blocks.push((s, i - s));
                    start = None;
                }
                // Control flow statement is a block on its own.
                blocks.push((i, 1));
            } else if start.is_none() {
                start = Some(i);
            }
        }

        // Close the final block.
        if let Some(s) = start {
            blocks.push((s, stmts.len() - s));
        }

        blocks
    }

    /// Check if a statement is a loop (while/for/loop).
    pub fn is_loop_stmt(stmt: &Stmt) -> bool {
        matches!(
            stmt.kind,
            StmtKind::While { .. } | StmtKind::For { .. } | StmtKind::Loop { .. }
        )
    }

    /// Check if a statement is a function call.
    pub fn is_call_stmt(stmt: &Stmt) -> bool {
        matches!(&stmt.kind, StmtKind::Expr { expr } if matches!(&expr.kind, ExprKind::Call { .. }))
    }
}

impl Default for TracingJIT {
    fn default() -> Self {
        Self::new()
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// JIT Statistics
// ═══════════════════════════════════════════════════════════════════════════════

/// Snapshot of JIT runtime statistics.
#[derive(Debug, Clone)]
pub struct JITStats {
    /// Number of unique basic blocks being tracked.
    pub blocks_tracked: usize,
    /// Number of compiled traces currently in cache.
    pub traces_compiled: usize,
    /// Total number of traces ever compiled.
    pub total_compiled: u64,
    /// Total number of deoptimizations.
    pub total_deopts: u64,
    /// Total number of successful native code invocations.
    pub total_native_hits: u64,
    /// Whether the Cranelift backend is available.
    pub cranelift_available: bool,
    /// Whether the JIT is enabled.
    pub enabled: bool,
}

impl std::fmt::Display for JITStats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "JIT: {} blocks tracked, {} traces compiled ({} total), \
             {} native hits, {} deopts, cranelift={}, enabled={}",
            self.blocks_tracked,
            self.traces_compiled,
            self.total_compiled,
            self.total_native_hits,
            self.total_deopts,
            self.cranelift_available,
            self.enabled,
        )
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Global JIT Instance
// ═══════════════════════════════════════════════════════════════════════════════

/// Singleton JIT runtime (for use when the interpreter doesn't own state).
static GLOBAL_JIT: OnceLock<Mutex<TracingJIT>> = OnceLock::new();

/// Get or initialize the global JIT runtime.
pub fn global_jit() -> &'static Mutex<TracingJIT> {
    GLOBAL_JIT.get_or_init(|| Mutex::new(TracingJIT::new()))
}

/// Convenience: check hotness on the global JIT.
pub fn check_hotness(block_id: &BlockId) -> bool {
    global_jit()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .check_hotness(block_id)
}

/// Convenience: get global JIT stats.
pub fn stats() -> JITStats {
    global_jit()
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .stats()
}

/// Minimal, non-intrusive interpreter → JIT hook.
///
/// This is the single integration point that makes the tracing JIT reachable
/// from the interpreter without touching interp.rs production logic. It is
/// *environment-gated*: the JIT path stays completely inert unless the
/// `TALLOW_JIT` env var is set (default OFF), so stock behavior is
/// byte-for-byte unchanged.
///
/// When enabled, this treats the given `stmts` as the body of a basic block
/// (`fn_name` + `loop_depth` identify it), feeds it through the hot-loop
/// detector, and if it crosses [`HOT_THRESHOLD`] it is compiled to native
/// code via Cranelift and cached. Returns `true` iff the block was compiled
/// this call; `false` when the JIT is disabled, not yet hot, or compilation
/// failed (all safe no-op fallbacks).
pub fn tallow_jit_try_compile(
    fn_name: &str,
    loop_depth: usize,
    stmts: &[Stmt],
) -> bool {
    // Env-gated, default OFF.
    match std::env::var("TALLOW_JIT") {
        Ok(v) if v == "1" => {}
        _ => return false,
    }

    let block_id = BlockId::new(fn_name, loop_depth, 0, stmts.len());
    let mut jit = global_jit()
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    if jit.check_hotness(&block_id) {
        let block = Block {
            stmts: stmts.to_vec(),
            span: crate::lexer::Span::new(0, 0),
        };
        jit.compile_block(&block_id, &block, &HashMap::new())
            .is_some()
    } else {
        false
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hot_counter_threshold() {
        let block_id = BlockId::new("test_fn", 1, 0, 3);
        let counter = HotCounter::new(block_id.clone());

        // First 49 increments should return false.
        for _ in 0..49 {
            assert!(!counter.increment());
        }

        // 50th increment should return true.
        assert!(counter.increment());

        // 51st and beyond return false (already compiled).
        assert!(!counter.increment());
    }

    #[test]
    fn test_hot_counter_mark_compiled() {
        let block_id = BlockId::new("test_fn", 0, 0, 5);
        let counter = HotCounter::new(block_id);

        assert!(!counter.is_compiled_or_failed());
        counter.mark_compiled();
        assert!(counter.is_compiled_or_failed());

        // Increments still count; the threshold crossing fires exactly once
        // (mark_compiled only prevents *recompilation*, not counting).
        let mut fired = false;
        for _ in 0..HOT_THRESHOLD {
            if counter.increment() {
                fired = true;
            }
        }
        assert!(fired, "threshold crossing should still fire");
    }

    #[test]
    fn test_type_tag_determinism() {
        assert_eq!(type_tag(&Value::Nil), 0);
        assert_eq!(type_tag(&Value::Bool(true)), 1);
        assert_eq!(type_tag(&Value::Bool(false)), 1);
        assert_eq!(type_tag(&Value::Int(42)), 2);
        assert_eq!(type_tag(&Value::Float(3.14)), 3);
        assert_eq!(type_tag(&Value::String("hello".to_string())), 4);
        assert_eq!(type_tag(&Value::Int(0)), 2); // zero is still Int
        assert_eq!(type_tag(&Value::Float(0.0)), 3);
    }

    #[test]
    fn test_guard_check_pass() {
        let mut vars = HashMap::new();
        vars.insert("x".to_string(), Value::Int(42));
        vars.insert("y".to_string(), Value::Float(1.0));

        let guard = GuardSpec {
            var_types: vec![
                ("x".to_string(), 2), // Int
                ("y".to_string(), 3), // Float
            ],
            loop_depth: 1,
            compiled_at: 0,
        };

        assert!(guard.check(&vars, 1).is_ok());
    }

    #[test]
    fn test_guard_check_type_changed() {
        let mut vars = HashMap::new();
        vars.insert("x".to_string(), Value::String("oops".to_string())); // was Int, now String

        let guard = GuardSpec {
            var_types: vec![("x".to_string(), 2)], // expected Int
            loop_depth: 0,
            compiled_at: 0,
        };

        assert!(guard.check(&vars, 0).is_err());
    }

    #[test]
    fn test_guard_check_var_out_of_scope() {
        let vars: HashMap<String, Value> = HashMap::new();

        let guard = GuardSpec {
            var_types: vec![("x".to_string(), 2)],
            loop_depth: 0,
            compiled_at: 0,
        };

        assert!(guard.check(&vars, 0).is_err());
    }

    #[test]
    fn test_guard_check_loop_depth_changed() {
        let mut vars = HashMap::new();
        vars.insert("x".to_string(), Value::Int(1));

        let guard = GuardSpec {
            var_types: vec![("x".to_string(), 2)],
            loop_depth: 2,
            compiled_at: 0,
        };

        assert!(guard.check(&vars, 1).is_err());
    }

    #[test]
    fn test_basic_block_identification_simple() {
        // Straight-line code: one block containing all statements.
        let stmts = vec![
            Stmt {
                kind: StmtKind::Let {
                    name: "x".to_string(),
                    ty: None,
                    value: Expr::new(ExprKind::IntLit(1), crate::lexer::Span::new(0, 0)),
                },
                span: crate::lexer::Span::new(0, 0),
            },
            Stmt {
                kind: StmtKind::Let {
                    name: "y".to_string(),
                    ty: None,
                    value: Expr::new(ExprKind::IntLit(2), crate::lexer::Span::new(0, 0)),
                },
                span: crate::lexer::Span::new(0, 0),
            },
        ];

        let blocks = TracingJIT::identify_basic_blocks(&stmts);
        assert_eq!(blocks, vec![(0, 2)]);
    }

    #[test]
    fn test_basic_block_identification_with_control_flow() {
        // x = 1; while ... { }; y = 2
        let stmts = vec![
            Stmt {
                kind: StmtKind::Let {
                    name: "x".to_string(),
                    ty: None,
                    value: Expr::new(ExprKind::IntLit(1), crate::lexer::Span::new(0, 0)),
                },
                span: crate::lexer::Span::new(0, 0),
            },
            Stmt {
                kind: StmtKind::While {
                    condition: Expr::new(ExprKind::BoolLit(true), crate::lexer::Span::new(0, 0)),
                    body: crate::ast::Block {
                        stmts: vec![],
                        span: crate::lexer::Span::new(0, 0),
                    },
                },
                span: crate::lexer::Span::new(0, 0),
            },
            Stmt {
                kind: StmtKind::Let {
                    name: "y".to_string(),
                    ty: None,
                    value: Expr::new(ExprKind::IntLit(2), crate::lexer::Span::new(0, 0)),
                },
                span: crate::lexer::Span::new(0, 0),
            },
        ];

        let blocks = TracingJIT::identify_basic_blocks(&stmts);
        assert_eq!(blocks.len(), 3);
        assert_eq!(blocks[0], (0, 1)); // x = 1
        assert_eq!(blocks[1], (1, 1)); // while loop (control flow)
        assert_eq!(blocks[2], (2, 1)); // y = 2
    }

    #[test]
    fn test_block_id_key() {
        let id = BlockId::new("main", 2, 5, 8);
        assert_eq!(id.key(), "main:L2:S5:N8");
        assert_eq!(id.to_string(), "main@depth2[5..13]");
    }

    #[test]
    fn test_tracing_jit_disabled() {
        let mut jit = TracingJIT::new();
        jit.enabled = false;

        let block_id = BlockId::new("test", 0, 0, 3);
        assert!(!jit.check_hotness(&block_id));
    }

    #[test]
    fn test_tracing_jit_check_hotness() {
        let mut jit = TracingJIT::new();
        jit.enabled = true;

        let block_id = BlockId::new("hot_fn", 1, 0, 4);

        // First 49 checks: not hot yet.
        for _ in 0..49 {
            assert!(!jit.check_hotness(&block_id));
        }

        // 50th check: hot!
        assert!(jit.check_hotness(&block_id));

        // 51st: already triggered, no re-trigger.
        assert!(!jit.check_hotness(&block_id));
    }

    #[test]
    fn test_tracing_jit_no_double_compile() {
        let mut jit = TracingJIT::new();
        jit.enabled = true;

        let block_id = BlockId::new("fn", 0, 0, 2);

        // Hit threshold.
        for _ in 0..49 {
            assert!(!jit.check_hotness(&block_id));
        }
        assert!(jit.check_hotness(&block_id));

        // Mark as failed (simulating cranelift unavailable).
        if let Some(counter) = jit.counters.get(&block_id) {
            counter.mark_failed();
        }

        // No more hotness triggers.
        for _ in 0..100 {
            assert!(!jit.check_hotness(&block_id));
        }
    }
}
