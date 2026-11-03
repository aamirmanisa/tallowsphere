//! Adversarial tests for `src/callnorm.rs` — G03 named and default arguments.
//!
//! This file attacks the argument binder from the outside: it never imports an
//! internal helper of the pass beyond the one public entry point
//! (`tallow::callnorm::normalize`), and it measures the **compiler** the user
//! runs for every end-to-end case.
//!
//! # The rule the code implements (pinned, not assumed)
//!
//! `callnorm` rewrites a statically resolvable call into a fully positional
//! one, splicing a *clone of the default expression into the call site*. The
//! rule that makes that sound is stated in the module docs and is measured here
//! rather than trusted:
//!
//! * a default may **not** read a parameter of its own function — refused at the
//!   declaration with E0124, even when the function is never called
//!   (`a_default_that_reads_a_parameter_is_refused_at_the_declaration`);
//! * everything else is evaluated **at call time, in the caller's scope**, which
//!   is why a default that names a caller local changes value per call site
//!   (`a_default_is_evaluated_in_the_callers_scope`). That is the documented
//!   residual difference, and both planes agree on it.
//!
//! # Cases, expectation, and measured verdict
//!
//! | # | case | expected | measured | verdict |
//! |---|------|----------|----------|---------|
//! | 1 | unknown argument name | E0122 whose message lists the real parameters | message lists them, in declaration order, no neighbour's names | holds |
//! | 1 | unknown name on a 0-parameter function | E0122 "parameters are none" | same, plus E0103 arity | holds |
//! | 2 | positional then same name | E0123 naming the parameter both ways | `bound twice: positional argument #1 and named `host`` | holds |
//! | 2 | name twice | E0123 naming the parameter | `bound twice: named `host` and named `host`` | holds |
//! | 3 | named required parameter then positional | refused, nothing executed | E0121 + E0123 + E0124, exit 1, empty stdout | holds |
//! | 4 | default reads another parameter | refused at the declaration | E0124 at the declaration, call-free case included | holds (refusal rule) |
//! | 5 | recursion, literal default | terminates, planes agree | terminates, `0` on both planes | holds |
//! | 5 | acyclic chain of defaulted calls | terminates | `7` on both planes | holds |
//! | 5 | **default that calls its own function** | refused, naming the cycle | E0125 `f -> f`, exit 1, no abort | holds |
//! | 5 | **mutually recursive defaults** | refused, naming the cycle | E0125 `f -> g -> f`, exit 1, no abort | holds |
//! | 6 | 0 params + 1 named arg | predictable refusal | E0122, "takes no arguments" | holds |
//! | 6 | name differing only by case | predictable refusal | E0122 `Host`, parameters listed lowercase, `host` left unbound (E0124) | holds |
//! | 7 | named/default program, interpret vs `--require-native` | byte-identical stdout | identical, `443\n80\n444\n8080\n81\n` | holds |
//! | 7 | evaluation order of named args | one defined order, both planes | declaration order (`A` then `B`) | holds |
//! | 7 | **call through a value, omitted default** | byte-identical stdout | both planes `443` | holds |
//!
//! Three tests below began life as defect reproducers: a default that closes a
//! cycle used to abort the compiler with a stack overflow (exit 134, no
//! diagnostic), and a call through a function value used to drop the omitted
//! default on the native plane (interpreted `443`, native `0`, both exit 0).
//! The rules that close both — the declaration-time default-cycle graph
//! (E0125) and binding a call through a `let` that still names a top-level
//! `fn` — are in `src/callnorm.rs`; the tests are kept as regression coverage
//! and assert the diagnostic, not merely the absence of the abort.

use std::io::Read;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use tallow::ast::*;
use tallow::callnorm::normalize;

/// A wall-clock bound on any single compiler invocation.
///
/// The binder's worst failure mode is non-termination (see the recursion
/// tests), so every child is bounded: a hang must be reported as a hang, not
/// wedge the whole test binary.
const CHILD_TIMEOUT: Duration = Duration::from_secs(30);

/// `exit_codes::COMPILE_ERROR` in `src/main.rs`.
const COMPILE_ERROR: i32 = 1;

// ── Harness ───────────────────────────────────────────────────────────────

/// One compiler invocation, bounded in time.
struct Run {
    /// `ExitStatus::code()` — `None` when the child died on a signal.
    code: Option<i32>,
    /// `ExitStatus::signal()` — `Some(6)` is SIGABRT, which is what a stack
    /// overflow in a Rust child produces.
    signal: Option<i32>,
    stdout: Vec<u8>,
    stderr: String,
    timed_out: bool,
}

impl Run {
    fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// "exit 1" / "signal 6" / "timed out" — for failure messages.
    fn how(&self) -> String {
        if self.timed_out {
            return "timed out".to_string();
        }
        match (self.code, self.signal) {
            (Some(code), _) => format!("exit {code}"),
            (None, Some(sig)) => format!("signal {sig}"),
            (None, None) => "unknown status".to_string(),
        }
    }

    /// Diagnostics the run reported, as `error[CODE]` codes in source order.
    fn codes(&self) -> Vec<String> {
        let mut out = Vec::new();
        let mut rest = self.stderr.as_str();
        while let Some(start) = rest.find("error[") {
            rest = &rest[start + "error[".len()..];
            if let Some(end) = rest.find(']') {
                out.push(rest[..end].to_string());
                rest = &rest[end..];
            }
        }
        out
    }

    /// The whole stderr line carrying `code`, e.g. the E0123 message.
    fn line_with(&self, code: &str) -> String {
        let needle = format!("error[{code}]:");
        self.stderr
            .lines()
            .find(|line| line.contains(&needle))
            .unwrap_or("")
            .trim()
            .to_string()
    }
}

fn tallow_bin() -> &'static str {
    env!("CARGO_BIN_EXE_tallow")
}

/// Source → a per-test file path, so concurrent tests never share one.
fn write_program(tag: &str, source: &str) -> PathBuf {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    tag.hash(&mut hasher);
    source.hash(&mut hasher);
    let path = std::env::temp_dir().join(format!("tallow-callnorm-{:016x}.tl", hasher.finish()));
    std::fs::write(&path, source).expect("write program");
    path
}

/// `<tallow> <args...> <program>`, with a hard wall-clock bound.
fn run_program(tag: &str, args: &[&str], source: &str) -> Run {
    let path = write_program(tag, source);
    let run = run_file(args, &path);
    let _ = std::fs::remove_file(&path);
    run
}

/// The same invocation against an existing path, for multi-file programs.
fn run_file(args: &[&str], path: &std::path::Path) -> Run {
    let mut child = Command::new(tallow_bin())
        .args(args)
        .arg(path)
        // The run path gates direct egress on the command, not on the program.
        .env("TALLOW_ALLOW_DIRECT", "1")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tallow");

    let deadline = Instant::now() + CHILD_TIMEOUT;
    let mut status = None;
    let mut timed_out = false;
    loop {
        match child.try_wait().expect("try_wait") {
            Some(s) => {
                status = Some(s);
                break;
            }
            None if Instant::now() >= deadline => {
                timed_out = true;
                let _ = child.kill();
                let _ = child.wait();
                break;
            }
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    }

    let mut stdout = Vec::new();
    if let Some(mut pipe) = child.stdout.take() {
        let _ = pipe.read_to_end(&mut stdout);
    }
    let mut stderr = String::new();
    if let Some(mut pipe) = child.stderr.take() {
        let _ = pipe.read_to_string(&mut stderr);
    }

    let (code, signal) = match status {
        #[cfg(unix)]
        Some(s) => {
            use std::os::unix::process::ExitStatusExt;
            (s.code(), s.signal())
        }
        // Windows has no wait-status signal field; a process either exits with a
        // code or the call fails, so `None` is the accurate answer, not a gap.
        #[cfg(not(unix))]
        Some(s) => (s.code(), None),
        None => (None, None),
    };
    Run {
        code,
        signal,
        stdout,
        stderr,
        timed_out,
    }
}

/// `tallow check <file>` — the "must not compile" plane.
fn check(tag: &str, source: &str) -> Run {
    run_program(tag, &["check"], source)
}

/// `tallow run --interpret <file>`.
fn interpret(tag: &str, source: &str) -> Run {
    run_program(tag, &["run", "--interpret"], source)
}

/// `tallow run --require-native <file>`.
fn native(tag: &str, source: &str) -> Run {
    run_program(tag, &["run", "--require-native"], source)
}

/// Both planes of one program, with the checks every parity case needs.
///
/// Returns `(interpreted_stdout, native_stdout)` only when both legs really ran
/// on their own plane; a native leg that fell back to the interpreter is not
/// parity and fails here.
fn both_planes(tag: &str, source: &str) -> (Vec<u8>, Vec<u8>) {
    let interpreted = interpret(&format!("{tag}-interpret"), source);
    assert_eq!(
        interpreted.code,
        Some(0),
        "the interpreter leg did not succeed ({}):\nstdout:\n{}\nstderr:\n{}",
        interpreted.how(),
        interpreted.stdout_text(),
        interpreted.stderr
    );

    let native = native(&format!("{tag}-native"), source);
    assert_eq!(
        native.code,
        Some(0),
        "the --require-native leg did not succeed ({}):\nstdout:\n{}\nstderr:\n{}",
        native.how(),
        native.stdout_text(),
        native.stderr
    );
    assert!(
        !native.stderr.contains("native build unavailable"),
        "the native leg fell back to the interpreter, so this is not parity:\n{}",
        native.stderr
    );
    assert!(
        !native.stdout.is_empty(),
        "both legs printed nothing; that is not a parity measurement"
    );
    (interpreted.stdout, native.stdout)
}

// ── AST-level helpers: the binder seen directly ──────────────────────────

struct Diag {
    code: &'static str,
    msg: String,
    help: Option<String>,
}

fn parse(source: &str) -> Program {
    let (tokens, lex_errors) = tallow::lexer::tokenize(source);
    assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
    tallow::parser::Parser::parse(tokens).expect("parse")
}

fn normalized(source: &str) -> (Program, Vec<Diag>) {
    let mut program = parse(source);
    let diags = normalize(&mut program);
    let diags = diags
        .items
        .into_iter()
        .map(|d| Diag {
            code: d.code,
            msg: d.msg,
            help: d.help,
        })
        .collect();
    (program, diags)
}

fn fn_body<'a>(program: &'a Program, name: &str) -> &'a Block {
    for item in &program.items {
        if let Item::Fn(f) = item {
            if f.name == name {
                return &f.body;
            }
        }
    }
    panic!("no function `{name}`");
}

/// The value of the first `let` in a function body. Test programs are written
/// so that this is the statement under test.
fn first_let_value<'a>(program: &'a Program, name: &str) -> &'a Expr {
    let body = fn_body(program, name);
    for stmt in &body.stmts {
        if let StmtKind::Let { value, .. } = &stmt.kind {
            return value;
        }
    }
    panic!("no `let` in `{name}`");
}

fn as_call(expr: &Expr) -> (&str, &Vec<CallArg>) {
    match &expr.kind {
        ExprKind::Call { callee, args } => match &callee.kind {
            ExprKind::Ident(name) => (name.as_str(), args),
            other => panic!("callee is not an identifier: {other:?}"),
        },
        other => panic!("not a call: {other:?}"),
    }
}

fn only<'a>(diags: &'a [Diag], code: &str) -> &'a Diag {
    let hits: Vec<&Diag> = diags.iter().filter(|d| d.code == code).collect();
    assert_eq!(
        hits.len(),
        1,
        "expected exactly one {code}, got {:?}",
        diags.iter().map(|d| d.code).collect::<Vec<_>>()
    );
    hits[0]
}

const CONN: &str = "fn conn(host: String, port: Int = 443, tls: Bool = true) -> Int {
    return port;
}
";

// ── 1. Unknown argument name ─────────────────────────────────────────────

/// The refusal must name the call *and* every parameter, in declaration order.
/// "unknown argument" alone would leave the programmer guessing.
#[test]
fn unknown_name_lists_every_parameter_in_declaration_order() {
    let (_program, diags) = normalized(&format!(
        "{CONN}fn main() {{ let p = conn(\"h\", prot: 1); }}"
    ));
    let d = only(&diags, "E0122");

    assert!(
        d.msg.contains("`conn`"),
        "the call must be named: {}",
        d.msg
    );
    assert!(
        d.msg.contains("`prot`"),
        "the bad name must be quoted: {}",
        d.msg
    );

    let host = d.msg.find("`host`").expect("`host` is not listed");
    let port = d.msg.find("`port`").expect("`port` is not listed");
    let tls = d.msg.find("`tls`").expect("`tls` is not listed");
    assert!(
        host < port && port < tls,
        "parameters must be listed in declaration order: {}",
        d.msg
    );
    assert!(
        d.msg.contains("parameters are"),
        "the message must say it is listing the parameters: {}",
        d.msg
    );
    let help = d.help.as_deref().unwrap_or("");
    assert!(
        help.contains("host, port, tls"),
        "the help must offer the spellings: {help}"
    );
    // Not merely non-empty: it must not be the bare form the brief asks about.
    assert_ne!(d.msg.trim(), "unknown argument", "{}", d.msg);
}

/// A near-miss name must not borrow a neighbouring function's parameters: the
/// shape consulted has to be the callee's own.
#[test]
fn unknown_name_does_not_borrow_a_neighbour_functions_parameters() {
    let (_program, diags) = normalized(
        "fn one(x: Int) -> Int { return x; }
         fn two(x: Int, y: Int) -> Int { return x + y; }
         fn main() { let p = one(y: 1); }",
    );
    let d = only(&diags, "E0122");
    assert!(d.msg.contains("`one`"), "{}", d.msg);
    // The bad name itself is quoted in the message, so the parameter list has to
    // be inspected separately: it must be `one`'s own, not `two`'s.
    let list = d
        .msg
        .split("parameters are")
        .nth(1)
        .unwrap_or_else(|| panic!("the refusal does not list parameters: {}", d.msg));
    assert!(list.contains("`x`"), "{}", d.msg);
    assert!(
        !list.contains("`y`"),
        "the refusal lists a parameter `one` does not have: {}",
        d.msg
    );
}

/// The CLI plane must produce the same refusal, since it is the pass the user
/// actually runs. Measured on the `check` verb: exit code and message.
#[test]
fn unknown_name_is_refused_by_the_cli_with_the_parameter_list() {
    let run = check(
        "unknown-name-cli",
        &format!("{CONN}fn main() {{ print(conn(\"h\", prot: 1)) }}"),
    );
    assert_eq!(
        run.code,
        Some(COMPILE_ERROR),
        "check must refuse ({}):\nstdout:\n{}\nstderr:\n{}",
        run.how(),
        run.stdout_text(),
        run.stderr
    );
    assert_eq!(run.codes(), vec!["E0122".to_string()], "{}", run.stderr);
    let line = run.line_with("E0122");
    for name in ["conn", "prot", "host", "port", "tls"] {
        assert!(line.contains(name), "`{name}` missing from: {line}");
    }
}

// ── 2. Duplicate binding ─────────────────────────────────────────────────

/// Positional `host`, then `host: …` — E0123 must name the parameter and both
/// binding sites, not just say "duplicate argument".
#[test]
fn duplicate_positional_then_named_names_the_parameter_and_both_sites() {
    let (_program, diags) = normalized(&format!(
        "{CONN}fn main() {{ let p = conn(\"h\", host: \"g\"); }}"
    ));
    let d = only(&diags, "E0123");
    assert!(
        d.msg.contains("parameter `host`"),
        "the parameter must be named: {}",
        d.msg
    );
    assert!(
        d.msg.contains("positional argument #1") && d.msg.contains("named `host`"),
        "both binding sites must be named: {}",
        d.msg
    );
}

/// The same name written twice: still E0123, still naming the parameter. This
/// path (`named … and named …`) is distinct from the positional one above.
#[test]
fn duplicate_named_twice_names_the_parameter() {
    let (_program, diags) = normalized(&format!(
        "{CONN}fn main() {{ let p = conn(host: \"h\", host: \"g\"); }}"
    ));
    let d = only(&diags, "E0123");
    assert!(
        d.msg.contains("parameter `host`"),
        "the parameter must be named: {}",
        d.msg
    );
    assert!(
        d.msg.contains("named `host`") && d.msg.matches("named `host`").count() == 2,
        "both sites are the same name and both must be shown: {}",
        d.msg
    );
}

/// A duplicate in the middle of a longer call, with the positional fill coming
/// from a different slot, must still be caught rather than silently overwriting.
#[test]
fn duplicate_binding_in_the_middle_of_a_call_is_caught() {
    let (_program, diags) = normalized(
        "fn f(a: Int, b: Int, c: Int = 3) -> Int { return a + b + c; }
         fn main() { let p = f(1, 2, b: 9); }",
    );
    let d = only(&diags, "E0123");
    assert!(d.msg.contains("parameter `b`"), "{}", d.msg);
    assert!(
        d.msg.contains("positional argument #2"),
        "the positional site must be #2: {}",
        d.msg
    );
}

/// The CLI must refuse the duplicate too, and must not fall through to a call
/// with the wrong arity (which would produce a second, confusing diagnostic
/// family instead of the real one).
#[test]
fn duplicate_binding_is_refused_by_the_cli() {
    let run = check(
        "duplicate-cli",
        &format!("{CONN}fn main() {{ print(conn(host: \"h\", host: \"g\")) }}"),
    );
    assert_eq!(run.code, Some(COMPILE_ERROR), "{}", run.stderr);
    assert_eq!(run.codes(), vec!["E0123".to_string()], "{}", run.stderr);
    assert!(
        run.line_with("E0123").contains("`host`"),
        "{}",
        run.line_with("E0123")
    );
}

// ── 3. Named-required followed by positional ─────────────────────────────

/// `conn(port: 8443, "h")` — a positional argument after a named one must be
/// refused. `port` has a default and `host` does not, so the shape is exactly
/// the one the brief names: the positional cannot be "the rest of the list".
#[test]
fn named_argument_then_positional_is_refused() {
    let (_program, diags) = normalized(&format!(
        "{CONN}fn main() {{ let p = conn(port: 8443, \"h\"); }}"
    ));
    let d = only(&diags, "E0121");
    assert!(d.msg.contains("`conn`"), "{}", d.msg);
    assert!(
        d.msg.contains("positional argument after a named argument"),
        "{}",
        d.msg
    );
    let help = d.help.as_deref().unwrap_or("");
    assert!(
        help.contains("named arguments close the list"),
        "the help must state the rule: {help}"
    );
}

/// And through the CLI: refused, exit 1, and — since this is the `run` verb —
/// **no** stdout at all, because a refusal before execution must not half-run
/// the program.
#[test]
fn named_then_positional_is_refused_and_nothing_executes() {
    let run = interpret(
        "named-then-positional",
        &format!("{CONN}fn main() {{ print(conn(port: 8443, \"h\")) }}"),
    );
    assert_eq!(
        run.code,
        Some(COMPILE_ERROR),
        "run must refuse ({}):\nstderr:\n{}",
        run.how(),
        run.stderr
    );
    assert!(
        run.stdout.is_empty(),
        "a refused program printed to stdout: {:?}",
        run.stdout_text()
    );
    assert!(
        run.codes().iter().any(|c| c == "E0121"),
        "E0121 missing: {}",
        run.stderr
    );
}

// ── 4. A default that reads another parameter ────────────────────────────
//
// THE RULE THE CODE IMPLEMENTS, pinned here: **refusal at the declaration**
// (E0124), not call-time evaluation in callee scope. `check_defaults` is
// syntactic and runs over every `fn`, so the refusal does not depend on the
// default being reachable.

#[test]
fn a_default_that_reads_a_parameter_is_refused_at_the_declaration() {
    let (_program, diags) =
        normalized("fn f(a: Int, b: Int = a) -> Int { return b; }\nfn main() { }");
    let d = only(&diags, "E0124");
    assert!(
        d.msg.contains("default for parameter `b`"),
        "the defaulting parameter must be named: {}",
        d.msg
    );
    assert!(
        d.msg.contains("reads parameter `a`"),
        "the read parameter must be named: {}",
        d.msg
    );
    let help = d.help.as_deref().unwrap_or("");
    assert!(
        help.contains("evaluated at the call site"),
        "the help must state the evaluation rule: {help}"
    );
}

/// The refusal is a property of the declaration, not of a call: a function that
/// is never called must still be refused. If this ever passes with no
/// diagnostic, the rule has quietly become "refuse only when a call splices it",
/// which would let the same declaration mean different things per call site.
#[test]
fn a_default_reading_a_parameter_is_refused_even_without_a_call() {
    let run = check(
        "default-reads-param-uncalled",
        "fn f(a: Int, b: Int = a) -> Int { return b; }\nfn main() { print(1) }\n",
    );
    assert_eq!(
        run.code,
        Some(COMPILE_ERROR),
        "an unreachable declaration with a parameter-reading default was accepted ({}):\n{}",
        run.how(),
        run.stderr
    );
    assert!(
        run.codes().iter().any(|c| c == "E0124"),
        "E0124 missing: {}",
        run.stderr
    );
    assert!(run.stdout.is_empty(), "the program ran anyway");
}

/// A parameter read through a call — `b: Int = g(a)` — is the same violation:
/// `a` does not exist where the default is evaluated.
#[test]
fn a_default_that_reads_a_parameter_through_a_call_is_refused() {
    let (_program, diags) = normalized(
        "fn g(x: Int) -> Int { return x; }
         fn f(a: Int, b: Int = g(a)) -> Int { return b; }
         fn main() { }",
    );
    let d = only(&diags, "E0124");
    assert!(d.msg.contains("reads parameter `a`"), "{}", d.msg);
}

/// The splice is only sound because of the rule above, so the *positive* half
/// is measured too: a default naming a global resolves at the call site and is
/// re-evaluated on every call. Both planes must agree byte for byte.
#[test]
fn a_default_is_evaluated_at_each_call_not_at_the_declaration() {
    let program = "fn port() -> Int {
    print(\"eval\")
    return 7
}
fn f(a: Int = port()) -> Int { return a }
fn main() {
    print(f())
    print(f())
}
";
    let (interpreted, native) = both_planes("default-call-time", program);
    assert_eq!(
        interpreted,
        b"eval\n7\neval\n7\n".to_vec(),
        "the default must be evaluated once per call, at the call site"
    );
    assert_eq!(
        interpreted,
        native,
        "planes disagree:\ninterpreted:\n{}\nnative:\n{}",
        String::from_utf8_lossy(&interpreted),
        String::from_utf8_lossy(&native)
    );
}

/// The documented residual difference, pinned as fact: because the default is
/// spliced into the caller, a caller local that happens to share the name is
/// picked up. Same call text, two different values — by definition of the rule,
/// and identically on both planes.
#[test]
fn a_default_is_evaluated_in_the_callers_scope() {
    let program = "fn f(a: Int = x) -> Int { return a }
fn caller1() -> Int {
    let x = 10
    return f()
}
fn caller2() -> Int {
    let x = 20
    return f()
}
fn main() {
    print(caller1())
    print(caller2())
}
";
    let (interpreted, native) = both_planes("default-caller-scope", program);
    assert_eq!(
        interpreted,
        b"10\n20\n".to_vec(),
        "a spliced default must resolve in the caller's scope"
    );
    assert_eq!(
        interpreted,
        native,
        "planes disagree:\ninterpreted:\n{}\nnative:\n{}",
        String::from_utf8_lossy(&interpreted),
        String::from_utf8_lossy(&native)
    );
}

/// A default that is itself a named call must be normalised in place: the
/// spliced node is walked, which is exactly the mechanism that makes the
/// recursion defect below possible.
#[test]
fn a_default_call_is_itself_rewritten_to_positional() {
    let (program, diags) = normalized(
        "fn inner(host: String, port: Int = 1) -> Int { return port; }
         fn outer(a: Int = inner(\"h\")) -> Int { return a; }
         fn main() { let p = outer(); }",
    );
    assert!(
        diags.is_empty(),
        "{:?}",
        diags.iter().map(|d| d.code).collect::<Vec<_>>()
    );

    let outer_call = first_let_value(&program, "main");
    let (name, args) = as_call(outer_call);
    assert_eq!(name, "outer");
    assert_eq!(args.len(), 1, "the default must be spliced: {args:?}");

    let (inner_name, inner_args) = as_call(&args[0].value);
    assert_eq!(inner_name, "inner");
    assert_eq!(inner_args.len(), 2, "the spliced default is not normalised");
    assert!(
        inner_args.iter().all(|a| a.name.is_none()),
        "a named argument survived normalisation: {inner_args:?}"
    );
    assert!(
        matches!(inner_args[1].value.kind, ExprKind::IntLit(1)),
        "inner's own default was not spliced"
    );
}

// ── 5. Recursion and mutual recursion ────────────────────────────────────
//
// The walk rewrites a call *and then descends into the arguments it just
// spliced*. A spliced default is a fresh clone of a declaration expression, so
// descending into it only terminates when that expression cannot reach a call
// that splices again. A default that calls its own function closes the cycle.

/// Control: ordinary recursion with a literal default. The spliced literal
/// carries no call, so the walk cannot loop. Both planes agree.
#[test]
fn recursive_call_with_a_literal_default_terminates() {
    let program = "fn down(n: Int, step: Int = 1) -> Int {
    if n <= 0 {
        return 0
    }
    return down(n - step)
}
fn main() { print(down(3)) }
";
    let (interpreted, native) = both_planes("recursion-literal-default", program);
    assert_eq!(interpreted, b"0\n".to_vec());
    assert_eq!(interpreted, native, "planes disagree");
}

/// Control: a *finite* chain of defaulted calls is spliced to completion and
/// stops, which shows the walk is re-entered by design (not only once).
#[test]
fn acyclic_chain_of_defaulted_calls_terminates() {
    let program = "fn h(d: Int = 7) -> Int { return d }
fn g(c: Int = h()) -> Int { return c }
fn f(a: Int, b: Int = g()) -> Int { return b }
fn main() { print(f(1)) }
";
    let (interpreted, native) = both_planes("default-chain", program);
    assert_eq!(interpreted, b"7\n".to_vec());
    assert_eq!(interpreted, native, "planes disagree");
}

/// Was a defect; now the rule it pins.
///
/// `fn f(a: Int, b: Int = f(1))` passes every declaration-time rule: the default
/// reads no parameter of `f`, so E0124 does not fire, and the parse is legal.
/// But `rewrite` splices `f(1)` into a call to `f`, then walks the spliced node,
/// which would rewrite it again, splicing another `f(1)`, forever.
///
/// Measured before the fix: `tallow check` died with `thread '<unknown>' has
/// overflowed its stack / fatal runtime error: stack overflow, aborting`, exit
/// 134 (SIGABRT). A compiler that aborts on a syntactically valid input has no
/// diagnostic to show.
///
/// The rule is the declaration-time cycle graph in `src/callnorm.rs`: a default
/// that closes a cycle is refused as E0125, naming the path. This test asserts
/// both halves — that the compiler terminates with a refusal, and that the
/// refusal is the cycle rule and names `f -> f` rather than being some
/// arbitrary depth limit that happened to stop first.
#[test]
fn self_referential_default_must_not_abort_the_compiler() {
    let program = "fn f(a: Int, b: Int = f(1)) -> Int { return b; }
fn main() { print(f(1)) }
";
    let run = check("self-referential-default", program);
    assert!(
        !run.timed_out,
        "the compiler did not terminate within {CHILD_TIMEOUT:?} on a self-referential default"
    );
    assert!(
        !run.stderr.contains("has overflowed its stack"),
        "the compiler aborted with a stack overflow ({}); expected a refusal or a \
         terminated rewrite:\n{}",
        run.how(),
        run.stderr
    );
    assert_eq!(
        run.code,
        Some(COMPILE_ERROR),
        "expected a refusal ({}); the pass either accepted the cycle or crashed:\n{}",
        run.how(),
        run.stderr
    );
    assert!(
        run.codes().iter().any(|code| code == "E0125"),
        "expected the default-cycle rule to refuse it ({}):\n{}",
        run.how(),
        run.stderr
    );
    let line = run.line_with("E0125");
    assert!(
        line.contains("default parameter cycle: f -> f"),
        "the refusal must name the cycle `f -> f`: {line}"
    );
    assert!(run.stdout.is_empty(), "the program ran anyway");
}

/// Was a defect; now the rule it pins. The variant a self-call-only check
/// would miss.
///
/// Mutual recursion through defaults: `f`'s default calls `g`, `g`'s default
/// calls `f`. Neither default reads a parameter, so neither declaration is
/// refused by E0124, and before the cycle graph the call `g()` was spliced into
/// `f(2)`, whose default was spliced into `g()`, and so on.
///
/// Measured before the fix: same stack overflow abort as the self-referential
/// case, exit 134. Now: E0125 naming the whole path, `f -> g -> f`.
#[test]
fn mutually_recursive_defaults_must_not_abort_the_compiler() {
    let program = "fn f(a: Int, b: Int = g()) -> Int { return b; }
fn g(c: Int = f(2)) -> Int { return c; }
fn main() { print(g()) }
";
    let run = check("mutual-recursive-defaults", program);
    assert!(
        !run.timed_out,
        "the compiler did not terminate within {CHILD_TIMEOUT:?} on mutually recursive defaults"
    );
    assert!(
        !run.stderr.contains("has overflowed its stack"),
        "the compiler aborted with a stack overflow ({}); expected a refusal or a \
         terminated rewrite:\n{}",
        run.how(),
        run.stderr
    );
    assert_eq!(
        run.code,
        Some(COMPILE_ERROR),
        "expected a refusal ({}); the pass either accepted the cycle or crashed:\n{}",
        run.how(),
        run.stderr
    );
    assert!(
        run.codes().iter().any(|code| code == "E0125"),
        "expected the default-cycle rule to refuse it ({}):\n{}",
        run.how(),
        run.stderr
    );
    let line = run.line_with("E0125");
    assert!(
        line.contains("default parameter cycle: f -> g -> f"),
        "the refusal must name the whole cycle `f -> g -> f`: {line}"
    );
    assert!(run.stdout.is_empty(), "the program ran anyway");
}

// ── 6. Arity and case ────────────────────────────────────────────────────

/// A function with 0 parameters passed one named argument: E0122 must say the
/// function takes no arguments rather than print an empty parameter list.
#[test]
fn zero_parameter_function_with_a_named_argument_is_refused() {
    let (_program, diags) =
        normalized("fn nop() -> Int { return 1; }\nfn main() { let p = nop(x: 1); }");
    let d = only(&diags, "E0122");
    assert!(d.msg.contains("`nop`"), "{}", d.msg);
    assert!(
        d.msg.contains("parameters are none"),
        "an empty list must be spelled out: {}",
        d.msg
    );
    assert!(
        d.help
            .as_deref()
            .unwrap_or("")
            .contains("takes no arguments"),
        "{:?}",
        d.help
    );

    // The same shape through the CLI: E0122 plus the type checker's arity rule,
    // both refusals, exit 1.
    let run = check(
        "zero-param-named",
        "fn nop() -> Int { return 1; }\nfn main() { print(nop(x: 1)) }\n",
    );
    assert_eq!(run.code, Some(COMPILE_ERROR), "{}", run.stderr);
    let codes = run.codes();
    assert!(codes.iter().any(|c| c == "E0122"), "{codes:?}");
    assert!(
        run.line_with("E0122").contains("takes no arguments")
            || run.stderr.contains("takes no arguments"),
        "{}",
        run.line_with("E0122")
    );
}

/// `conn(Host: "h")` — a name differing only by case. Binding is exact, so the
/// arg is unknown, the message lists the real (lower-case) parameters, and
/// `host` is consequently reported unbound. No silent case-insensitive match.
#[test]
fn named_argument_differing_only_in_case_is_refused() {
    let (program, diags) = normalized(&format!("{CONN}fn main() {{ let p = conn(Host: \"h\"); }}"));
    let unknown = only(&diags, "E0122");
    assert!(unknown.msg.contains("`Host`"), "{}", unknown.msg);
    assert!(
        unknown.msg.contains("parameters are `host`, `port`, `tls`"),
        "the listed parameters must be the declared spellings: {}",
        unknown.msg
    );

    let unbound = only(&diags, "E0124");
    assert!(
        unbound.msg.contains("`host`"),
        "a case-mismatched name must leave `host` unbound: {}",
        unbound.msg
    );

    // Nothing was rewritten: the call still carries its named argument, which is
    // what makes the E0103-free path impossible.
    let call = first_let_value(&program, "main");
    let (_name, args) = as_call(call);
    assert_eq!(args.len(), 1);
    assert_eq!(
        args[0].name.as_deref(),
        Some("Host"),
        "a refused call must be left exactly as written"
    );
}

// ── 7. Parity ────────────────────────────────────────────────────────────

/// The positive parity case: defaults, positional-then-named, named out of
/// order, named in declaration order. Byte-identical stdout on both planes, and
/// the payload is checked so "both printed nothing" cannot pass.
#[test]
fn named_and_default_arguments_agree_byte_for_byte_across_planes() {
    let program = "fn conn(host: String, port: Int = 443, tls: Bool = true) -> Int {
    if tls {
        return port
    }
    return port + 1
}
fn main() {
    print(conn(\"a\"))
    print(conn(\"a\", 80))
    print(conn(\"a\", tls: false))
    print(conn(port: 8080, host: \"a\"))
    print(conn(\"a\", 80, false))
}
";
    let (interpreted, native) = both_planes("named-default-parity", program);
    assert_eq!(
        interpreted,
        b"443\n80\n444\n8080\n81\n".to_vec(),
        "the interpreted leg produced the wrong rows"
    );
    assert_eq!(
        interpreted,
        native,
        "planes disagree:\ninterpreted:\n{}\nnative:\n{}",
        String::from_utf8_lossy(&interpreted),
        String::from_utf8_lossy(&native)
    );
}

/// Argument evaluation order is decided by the rewrite: slots are rebuilt in
/// declaration order, so side effects in named arguments run in declaration
/// order, not in the order written. Both planes agree. Pinned because it is a
/// real, observable consequence of "reorder into declaration order".
#[test]
fn named_arguments_are_evaluated_in_declaration_order() {
    let program = "fn tag(s: String) -> Int {
    print(s)
    return 1
}
fn f(a: Int, b: Int) -> Int { return a + b }
fn main() { print(f(b: tag(\"B\"), a: tag(\"A\"))) }
";
    let (interpreted, native) = both_planes("named-eval-order", program);
    assert_eq!(
        interpreted,
        b"A\nB\n2\n".to_vec(),
        "named arguments must be evaluated in declaration order after the rewrite"
    );
    assert_eq!(
        interpreted,
        native,
        "planes disagree:\ninterpreted:\n{}\nnative:\n{}",
        String::from_utf8_lossy(&interpreted),
        String::from_utf8_lossy(&native)
    );
}

/// Was a defect; now the rule it pins.
///
/// `callnorm` used to leave a call through a function value alone (`let g =
/// conn; g("h")`), because the callee's signature was said not to be statically
/// known. Measured consequence: the omitted default was **not applied on the
/// native plane** — the compiled leg passed the zero value instead.
///
///   interpreted: 443   (the interpreter applied `port`'s default)
///   native:      0     (the compiled leg passed the zero value instead)
///
/// Both legs exited 0, so nothing warned the user; the two planes of one
/// compiler returned different values for one program. The rule that closes it
/// (implemented, not refused: applying the default is decidable here) is in
/// `src/callnorm.rs` — a `let` whose initialiser is the bare name of a top-level
/// `fn`, never re-bound, shadowed or assigned, resolves to that function's
/// shape, so `g("h")` is normalised to `g("h", 443)` and both planes see the
/// same positional call.
#[test]
fn value_call_with_an_omitted_default_agrees_across_planes() {
    let program = "fn conn(host: String, port: Int = 443) -> Int { return port }
fn main() {
    let g = conn
    print(g(\"h\"))
}
";
    let interpreted = interpret("value-call-default-interpret", program);
    let native = native("value-call-default-native", program);
    assert_eq!(
        interpreted.code,
        Some(0),
        "interpreter leg failed:\n{}",
        interpreted.stderr
    );
    assert_eq!(
        native.code,
        Some(0),
        "native leg failed:\n{}",
        native.stderr
    );
    assert_eq!(
        interpreted.stdout,
        native.stdout,
        "planes disagree on a call through a function value:\ninterpreted: {:?}\nnative:      {:?}",
        interpreted.stdout_text(),
        native.stdout_text()
    );
    assert_eq!(
        native.stdout, b"443\n",
        "the native leg did not apply the declared default"
    );
}

/// A `native fn`'s defaults belong to the runtime dispatcher, so callnorm only
/// validates the *shape* and must not splice. The adversarial consequence is
/// worth pinning: when a defaulted hole and a missing required parameter meet,
/// the splice path returns early and E0124 is skipped — the arity rule (E0103)
/// then owns the refusal, and it must still refuse.
#[test]
fn native_call_omitting_a_required_parameter_is_still_refused() {
    let run = check(
        "native-missing-required",
        "native fn go(a: Int, b: Int = 1, c: Int) -> Int
fn main() { print(go(c: 3)) }
",
    );
    assert_eq!(
        run.code,
        Some(COMPILE_ERROR),
        "a native call missing a required parameter was accepted ({}):\n{}",
        run.how(),
        run.stderr
    );
    assert!(
        run.codes().iter().any(|c| c == "E0103"),
        "expected the arity rule to refuse it: {}",
        run.stderr
    );
    assert!(run.stdout.is_empty(), "the program ran anyway");
}

// ── 8. Shapes the declaration graph used to miss ─────────────────────────
//
// The audit's §5: the cycle graph walked defaults with its own traversal,
// which dropped `IfLet.else_branch`, dropped `Break.value`, and resolved a
// callee without `rewrite`'s `let`-alias rule. Those cycles were therefore
// refused only when a call site happened to expand them — the exact
// call-site-dependent refusal the module docs say the graph rule exists to
// avoid. `check_default_cycles` now uses the same traversal as `rewrite`, so
// each of these is an edge and each program is refused at the declaration,
// with or without a call.

/// One declared cycle: refused, names `f -> g -> f`, terminates, and does so
/// both when a call site expands it and when nothing calls `f` at all.
fn assert_declaration_cycle(tag: &str, declarations: &str) {
    let uncalled = format!("{declarations}\nfn main() {{ }}\n");
    let called = format!("{declarations}\nfn main() {{ print(f(1)) }}\n");
    for (label, source) in [("uncalled", &uncalled), ("called", &called)] {
        let run = check(&format!("{tag}-{label}"), source);
        assert!(
            !run.timed_out,
            "{tag} ({label}) did not terminate within {CHILD_TIMEOUT:?}"
        );
        assert!(
            !run.stderr.contains("has overflowed its stack"),
            "{tag} ({label}) aborted with a stack overflow ({}):\n{}",
            run.how(),
            run.stderr
        );
        assert_eq!(
            run.code,
            Some(COMPILE_ERROR),
            "{tag} ({label}), expected a refusal ({}):\n{}",
            run.how(),
            run.stderr
        );
        let cycles: Vec<&str> = run
            .stderr
            .lines()
            .filter(|line| line.contains("error[E0125]:"))
            .collect();
        assert_eq!(
            cycles.len(),
            1,
            "{tag} ({label}): one cycle must be reported once, and no other cycle exists:\n{}",
            run.stderr
        );
        assert!(
            cycles[0].contains("default parameter cycle: f -> g -> f"),
            "{tag} ({label}) must name `f -> g -> f`: {}",
            cycles[0]
        );
        assert!(run.stdout.is_empty(), "{tag} ({label}) ran anyway");
    }
}

/// §5(i): a cycle closed by the `else` branch of an `if let` default.
#[test]
fn if_let_else_cycle_is_refused_at_the_declaration() {
    assert_declaration_cycle(
        "cycle-iflet-else",
        "fn f(a: Int, b: Int = if let x = opt { 1 } else { g() }) -> Int { return b; }
fn g(c: Int = f(2)) -> Int { return c; }",
    );
}

/// §5(ii): a cycle closed by the value of a `break`.
#[test]
fn break_value_cycle_is_refused_at_the_declaration() {
    assert_declaration_cycle(
        "cycle-break-value",
        "fn f(a: Int, b: Int = loop { break g() }) -> Int { return b; }
fn g(c: Int = f(2)) -> Int { return c; }",
    );
}

/// §5(iii): a cycle reached through a `let` alias inside a default — the same
/// rule that makes `let g = conn; g(\"h\")` callable by name.
#[test]
fn let_alias_cycle_is_refused_at_the_declaration() {
    assert_declaration_cycle(
        "cycle-let-alias",
        "fn f(a: Int, b: Int = { let h = g; h(1) }) -> Int { return b; }
fn g(a: Int, b: Int = f(1)) -> Int { return b; }",
    );
}

// ── 9. Disclosure: every cycle, not every code ───────────────────────────

/// Two cycles that share an edge must both be reported, and renaming the same
/// shape so that the shared node sorts first must not change the count.
///
/// The audit (§7.3) measured 1 message for the first shape and 2 for the
/// renamed one: the DFS marked a shared node `completed` after one branch, so
/// the second cycle disappeared whenever its names sorted later. The refusal
/// was stable, the disclosure was not. The graph now reports on the cycle's
/// canonical key, so the set of cycles is a property of the graph.
#[test]
fn two_cycles_sharing_an_edge_are_both_disclosed() {
    let declaration_order =
        "fn aa_f(a: Int, b: Int = bb_a(1), c: Int = cc_b(1)) -> Int { return b; }
fn bb_a(a: Int, b: Int = dd_g(1)) -> Int { return b; }
fn cc_b(a: Int, b: Int = dd_g(1)) -> Int { return b; }
fn dd_g(a: Int, b: Int = aa_f(1)) -> Int { return b; }
fn main() { }
";
    // The same graph with the shared node sorting first.
    let renamed = "fn z(p: Int, q: Int = b1(1), r: Int = b2(1)) -> Int { return q; }
fn b1(p: Int, q: Int = a(1)) -> Int { return q; }
fn b2(p: Int, q: Int = a(1)) -> Int { return q; }
fn a(p: Int, q: Int = z(1)) -> Int { return q; }
fn main() { }
";

    let first = check("cycle-shared-edge", declaration_order);
    let second = check("cycle-shared-edge-renamed", renamed);

    let cases: [(&str, &Run, [&str; 2]); 2] = [
        (
            "declaration order",
            &first,
            [
                "default parameter cycle: aa_f -> bb_a -> dd_g -> aa_f",
                "default parameter cycle: aa_f -> cc_b -> dd_g -> aa_f",
            ],
        ),
        (
            "renamed",
            &second,
            [
                "default parameter cycle: a -> z -> b1 -> a",
                "default parameter cycle: a -> z -> b2 -> a",
            ],
        ),
    ];

    let mut counts = Vec::new();
    for (label, run, expected) in cases {
        assert_eq!(
            run.code,
            Some(COMPILE_ERROR),
            "{label}: expected a refusal ({}):\n{}",
            run.how(),
            run.stderr
        );
        let cycles: Vec<&str> = run
            .stderr
            .lines()
            .filter(|line| line.contains("error[E0125]:"))
            .collect();
        assert_eq!(
            cycles.len(),
            2,
            "{label}: two cycles exist and both must be disclosed:\n{}",
            run.stderr
        );
        for message in expected {
            assert!(
                cycles.iter().any(|line| line.contains(message)),
                "{label}: `{message}` was not reported:\n{}",
                run.stderr
            );
        }
        counts.push(cycles.len());
    }
    assert_eq!(
        counts[0], counts[1],
        "renaming the same graph changed how many cycles are disclosed"
    );
}

// ── 10. The span's file ──────────────────────────────────────────────────

/// A cycle whose closing call lives in an imported module must render its
/// `-->` against *that* file. The path was always right; the location was an
/// offset from `lib.tl` read against the entry file (audit §6.5).
///
/// `g` has to be `pub`: G09 (E0153) refuses a private name at the importer,
/// and a private `g` is not merged, so the cycle is never in the program.
/// Exporting it is what lets E0125 fire on the closing call in lib.tl.
#[test]
fn a_cycle_closing_in_an_imported_module_names_that_module() {
    let entry = "import lib

fn f(a: Int, b: Int = g()) -> Int { return b; }
fn main() { }
";
    let lib = "pub fn g(c: Int = f(2)) -> Int { return c; }
";
    let (entry_path, _lib_path) = write_import_pair("cycle-import", entry, lib);
    let run = run_file(&["check"], &entry_path);
    let _ = std::fs::remove_dir_all(entry_path.parent().expect("entry has a parent"));

    assert_eq!(
        run.code,
        Some(COMPILE_ERROR),
        "expected a refusal ({}):\n{}",
        run.how(),
        run.stderr
    );
    let after = run
        .stderr
        .split("error[E0125]")
        .nth(1)
        .unwrap_or_else(|| panic!("expected E0125:\n{}", run.stderr));
    assert!(
        after.lines().next().unwrap_or("").contains("f -> g -> f")
            || after.contains("default parameter cycle: f -> g -> f"),
        "the refusal must name the cycle:\n{}",
        run.stderr
    );
    let location = after
        .lines()
        .find(|line| line.trim_start().starts_with("-->"))
        .unwrap_or_else(|| panic!("E0125 has no location line:\n{}", run.stderr));
    assert!(
        location.contains("lib.tl"),
        "the `-->` line must name the imported file, got: {location}"
    );
    assert!(
        !location.contains("entry.tl"),
        "the `-->` line names the entry file for a span from lib.tl: {location}"
    );
}

/// The two-file program used above: `entry.tl` imports `lib` by bare name,
/// which the resolver looks for beside the entry file.
fn write_import_pair(tag: &str, entry: &str, lib: &str) -> (PathBuf, PathBuf) {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    tag.hash(&mut hasher);
    entry.hash(&mut hasher);
    lib.hash(&mut hasher);
    let dir = std::env::temp_dir().join(format!("tallow-callnorm-import-{:016x}", hasher.finish()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let entry_path = dir.join("entry.tl");
    let lib_path = dir.join("lib.tl");
    std::fs::write(&entry_path, entry).expect("write entry");
    std::fs::write(&lib_path, lib).expect("write lib");
    (entry_path, lib_path)
}
