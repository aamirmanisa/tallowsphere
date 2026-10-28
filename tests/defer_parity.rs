//! `defer` inside a closure, on the compiled plane.
//!
//! # What was broken
//!
//! Before this file existed, a `defer` written inside a closure body was pushed
//! onto the *enclosing function's* defer stack (`src/codegen.rs`,
//! `StmtKind::Defer`), and emitted at that function's epilogue. Emission is
//! textual: by then the closure's own allocas were gone from the name table, so
//! every name in the deferred body fell through `ExprKind::Ident` to the
//! module-level branch and became `@tallow.<name>`. clang then refused:
//!
//! ```text
//! tallow run closure_defer.tl --interpret      -> in-closure, 12 / result=12
//! tallow run closure_defer.tl --require-native -> error: use of undefined value '@tallow.y'
//! ```
//!
//! This is not "closure capture" and not "interpolation": the same closure
//! without the `defer` built clean, and the same interpolation outside a `defer`
//! built clean. It is which *scope* the deferred body is emitted in.
//!
//! # The contract
//!
//! A deferred block runs at the exit of the scope that registered it, with that
//! scope's name resolution. A closure is a function body of its own, so its
//! deferred blocks run at the closure's `ret` against the closure's own allocas
//! (and its environment, for captured names). A `defer` written in a function
//! body — `main` included — still emits at that function's epilogue and still
//! resolves module-level names (constants, functions) through the module path.
//! Distinguishing by the registration scope, not by the name, is the fix.
//!
//! # Planes
//!
//! Every test runs the real binary on both planes and asserts the stdout is
//! byte-identical: `--interpret` is the control, `--require-native` is the
//! compiled plane, and the `native build unavailable` fallback message is
//! refused so a compiled leg cannot silently become an interpreted one.

use std::path::PathBuf;
use std::process::Command;
use std::sync::Mutex;

/// Native legs are full clang builds against the debug runtime archive. They
/// are serialized for the same reason `tests/bridge_ownership_adversarial.rs`
/// serializes its legs: several at once drive this box into zram thrash.
static BUILD_LOCK: Mutex<()> = Mutex::new(());

const BIN: &str = env!("CARGO_BIN_EXE_tallow");

struct Leg {
    ok: bool,
    stdout: Vec<u8>,
    stderr: String,
}

impl Leg {
    fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    fn describe(&self, tag: &str, plane: &str) -> String {
        format!(
            "[{tag} {plane}] ok={}\nstdout:\n{}\nstderr:\n{}",
            self.ok,
            self.stdout_text(),
            self.stderr
        )
    }
}

fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow-defer-parity-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create work dir");
    dir
}

/// Run one plane. Holds the build lock for the whole child so two tests never
/// link at once.
fn run_plane(tag: &str, plane: &str, source: &str) -> Leg {
    let _serialized = BUILD_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = workdir(tag);
    let path = dir.join("prog.tl");
    std::fs::write(&path, source).expect("write program");
    let output = Command::new(BIN)
        .args(["run", plane])
        .arg(&path)
        // These programs touch no socket and read no file.
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_dir_all(&dir);
    Leg {
        ok: output.status.success(),
        stdout: output.stdout,
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    }
}

/// Run both planes, keep the shared invariants, and return them for the
/// plane-specific assertions.
fn both_planes(tag: &str, source: &str) -> (Leg, Leg) {
    let interpreted = run_plane(tag, "--interpret", source);
    assert!(
        interpreted.ok,
        "the interpreter control leg failed, so this case cannot say anything \
         about the compiled plane:\n{}",
        interpreted.describe(tag, "--interpret")
    );

    let native = run_plane(tag, "--require-native", source);
    assert!(
        !native.stderr.contains("native build unavailable"),
        "the --require-native leg fell back to the interpreter, so it tested \
         nothing:\n{}",
        native.describe(tag, "--require-native")
    );
    assert!(
        native.ok,
        "the compiled leg failed. A deferred block emitted in the wrong scope \
         names a module symbol that does not exist (`use of undefined value \
         '@tallow.<name>'`) and clang refuses the build.\n{}\nthe interpreter \
         answered:\n{}",
        native.describe(tag, "--require-native"),
        interpreted.describe(tag, "--interpret")
    );
    (interpreted, native)
}

/// The contract this file exists for: byte-identical stdout on both planes.
fn assert_parity(tag: &str, interpreted: &Leg, native: &Leg) {
    assert_eq!(
        native.stdout, interpreted.stdout,
        "{tag}: the compiled plane's stdout is not byte-identical to the \
         interpreter's.\n\
         ── interpreter stdout ({} bytes) ──\n{}\n\
         ── compiled stdout ({} bytes) ──\n{}",
        interpreted.stdout.len(),
        interpreted.stdout_text(),
        native.stdout.len(),
        native.stdout_text()
    );
}

/// 1. The reproduction: the deferred body prints the *closure's* `y`.
#[test]
fn a_deferred_block_inside_a_closure_reads_the_closures_local() {
    let source = r#"
fn main() {
    let base = 7
    let f = { x: i64 ->
        let y = x + base
        defer { print("in-closure, {y}") }
        y
    }
    let r = f(5)
    print("result={r}")
}
"#;
    let (interpreted, native) = both_planes("repro", source);

    // The deferred body runs when the closure returns, before `result=`.
    let expected = "in-closure, 12\nresult=12\n";
    assert_eq!(
        interpreted.stdout_text(),
        expected,
        "the interpreter control does not produce the documented output"
    );
    assert_eq!(
        native.stdout_text(),
        expected,
        "the compiled plane did not run the closure's deferred body against the \
         closure's binding: `y` is 12 here, and any other number is a read of \
         some other scope"
    );
    assert_parity("closure-defer", &interpreted, &native);
}

/// 2. Shadowing: a closure-local `y` wins over a module-level `y` inside the
///    deferred body, on both planes.
#[test]
fn a_closure_local_shadows_a_module_binding_inside_a_deferred_block() {
    let source = r#"
const y = 100

fn main() {
    let f = { x: i64 ->
        let y = x + 1
        defer { print("closure y={y}") }
        y
    }
    let r = f(5)
    print("result={r}")
    print("global y={y}")
}
"#;
    let (interpreted, native) = both_planes("shadow", source);

    // `f(5)` returns 6, so the closure's `y` is 6 while the module-level `y`
    // stays 100. The deferred block runs before the caller prints `result`.
    let expected = "closure y=6\nresult=6\nglobal y=100\n";
    assert_eq!(
        interpreted.stdout_text(),
        expected,
        "the interpreter control does not pick the closure-local binding"
    );
    assert_eq!(
        native.stdout_text(),
        expected,
        "the compiled plane's deferred block resolved `y` to a different \
         binding than the closure-local one (a print of 100 is the module-level \
         `y`, and a build with no output at all is the global-symbol path)"
    );
    assert_parity("shadow", &interpreted, &native);
}

/// 3. The case that must keep working: a `defer` registered in a function body
///    (here `main`) reads module-level bindings. Those resolve through the
///    module path, not through a local alloca, and must not be forced local.
#[test]
fn a_deferred_block_in_a_function_reads_module_bindings() {
    let source = r#"
const G = 40

fn bump() -> i64 {
    return 2
}

fn main() {
    defer { print("global g={G} bump={bump()}") }
    print("main body")
}
"#;
    let (interpreted, native) = both_planes("module-binding", source);

    let expected = "main body\nglobal g=40 bump=2\n";
    assert_eq!(
        interpreted.stdout_text(),
        expected,
        "the interpreter control does not read the module bindings"
    );
    assert_eq!(
        native.stdout_text(),
        expected,
        "the compiled plane broke the module-level resolution path for a \
         deferred block registered in a function body: a constant and a \
         module-level function must still be readable there"
    );
    assert_parity("module-binding", &interpreted, &native);
}

/// 4. Two levels: a closure's deferred body reads a local of the enclosing
///    function. The local is named only by the deferred body, so the closure's
///    free-variable scan must pack it into the environment.
#[test]
fn a_deferred_block_in_a_closure_captures_the_enclosing_functions_local() {
    let source = r#"
fn main() {
    let outer = 30
    let f = { x: i64 ->
        let y = x + 1
        defer { print("outer={outer} y={y}") }
        y
    }
    let r = f(4)
    print("result={r}")
}
"#;
    let (interpreted, native) = both_planes("two-level", source);

    let expected = "outer=30 y=5\nresult=5\n";
    assert_eq!(
        interpreted.stdout_text(),
        expected,
        "the interpreter control does not read the enclosing function's local"
    );
    assert_eq!(
        native.stdout_text(),
        expected,
        "the compiled plane's deferred body did not read the enclosing \
         function's local: `outer` is named only inside the `defer`, so it must \
         be captured into the closure environment"
    );
    assert_parity("two-level", &interpreted, &native);
}

