//! A module namespace is a *value of its own kind*, not a string.
//!
//! Lattice's capability audit round 2 (`runs/2.0-p0/review-lattice-round2.md`)
//! showed the interpreter resolving `net` to the ordinary string
//! `"__module_net__"` and dispatching *any* string with that prefix. A program
//! could therefore write the tag by hand — or build it with `+`, pass it as a
//! parameter, read it out of a struct field, or make it a `const` — and reach a
//! `Net` effect with no row, no grant and no namespace identifier anywhere in
//! the source (N-1, N-2, F-14).
//!
//! The fix is structural: modules are `Value::Module(&'static str)` and only
//! that variant dispatches. Nothing here asserts "the checker refuses" — these
//! programs are fully annotated, so they pass `check` and the refusal measured
//! below is the *runtime's* for a string receiver. A loopback listener proves
//! no socket is opened.

use std::io::Read;
use std::net::TcpListener;
use std::path::PathBuf;

/// Program-scope annotations, so `check` passes and the run really reaches the
/// interpreter. Without them these programs die in the policy pass and the test
/// would prove nothing about dispatch.
const ANNOT: &str = r#"@cra_class(.default)
@legal(basis: .research, purpose: "module tag probe", personal_data: false)
@persona(id: "mtp", cover_class: .researcher, compartment: "mtp", fingerprint_seed: "mtp-1020")
@burn_plan(persona: "mtp", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowMtp/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
"#;

fn temp_program(tag: &str, src: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "tallow-module-value-{}-{tag}.tl",
        std::process::id()
    ));
    std::fs::write(&path, src).expect("write program");
    path
}

struct Run {
    code: i32,
    stdout: String,
    stderr: String,
}

/// Run a program on the interpreter plane (`--target x86_64-linux` is the
/// documented way to force the tree-walking interpreter).
fn run_interp(tag: &str, src: &str) -> Run {
    let path = temp_program(tag, src);
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg("--target")
        .arg("x86_64-linux")
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    Run {
        code: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// A listener that records whether anything connected to it.
struct Probe {
    listener: TcpListener,
    port: u16,
}

impl Probe {
    fn bind() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
        let port = listener.local_addr().unwrap().port();
        Self { listener, port }
    }

    /// Ports that accepted a peer since the program ran. Non-blocking: a
    /// refused program leaves the backlog empty.
    fn accepted(&self) -> usize {
        self.listener.set_nonblocking(true).expect("nonblocking");
        let mut n = 0;
        while let Ok((mut stream, _)) = self.listener.accept() {
            let mut buf = [0u8; 64];
            let _ = stream.read(&mut buf);
            n += 1;
        }
        n
    }
}

fn helper_program(helper_body: &str, extra: &str, port: u16) -> String {
    format!(
        r#"{extra}@legal(basis: .public_data, purpose: "audit")
fn helper(h: String) {{
{helper_body}
    print("returned from helper")
}}

{ANNOT}fn main() {{
    helper("127.0.0.1:{port}")
}}
"#
    )
}

#[test]
fn literal_tag_string_does_not_dispatch() {
    let probe = Probe::bind();
    let src = helper_program(
        "    let n = \"__module_net__\"\n    n.connect(h)",
        "",
        probe.port,
    );
    let run = run_interp("literal", &src);
    assert_ne!(
        run.code, 0,
        "stdout: {}\nstderr: {}",
        run.stdout, run.stderr
    );
    assert!(
        !run.stdout.contains("returned from helper"),
        "{}",
        run.stdout
    );
    assert_eq!(probe.accepted(), 0, "connection accepted:\n{}", run.stderr);
    // A string receiver, named as such.
    assert!(
        run.stderr.contains("unknown method") && run.stderr.contains("on String"),
        "expected a method-on-string refusal, got:\n{}",
        run.stderr
    );
}

#[test]
fn concatenated_tag_does_not_dispatch() {
    // audit variant a15_tag_concat.tl
    let probe = Probe::bind();
    let src = helper_program(
        "    let n = \"__module_\" + \"net\" + \"__\"\n    n.connect(h)",
        "",
        probe.port,
    );
    let run = run_interp("concat", &src);
    assert_ne!(
        run.code, 0,
        "stdout: {}\nstderr: {}",
        run.stdout, run.stderr
    );
    assert!(
        !run.stdout.contains("returned from helper"),
        "{}",
        run.stdout
    );
    assert_eq!(probe.accepted(), 0, "connection accepted:\n{}", run.stderr);
}

#[test]
fn tag_passed_as_parameter_does_not_dispatch() {
    // audit variant a16_tag_param.tl
    let probe = Probe::bind();
    let extra = r#"@legal(basis: .public_data, purpose: "audit")
fn poke(n: string, h: String) {
    n.connect(h)
}

"#;
    let src = helper_program("    poke(\"__module_net__\", h)", extra, probe.port);
    let run = run_interp("param", &src);
    assert_ne!(
        run.code, 0,
        "stdout: {}\nstderr: {}",
        run.stdout, run.stderr
    );
    assert_eq!(probe.accepted(), 0, "connection accepted:\n{}", run.stderr);
}

#[test]
fn tag_read_from_struct_field_does_not_dispatch() {
    // audit variant a24_tag_structfield_read.tl
    let probe = Probe::bind();
    let extra = r#"struct Cfg { ns: string }

@legal(basis: .public_data, purpose: "audit")
fn poke2(c: Cfg, h: String) {
    let n = c.ns
    n.connect(h)
}

"#;
    let src = helper_program(
        "    poke2(Cfg { ns: \"__module_net__\" }, h)",
        extra,
        probe.port,
    );
    let run = run_interp("structfield", &src);
    assert_ne!(
        run.code, 0,
        "stdout: {}\nstderr: {}",
        run.stdout, run.stderr
    );
    assert_eq!(probe.accepted(), 0, "connection accepted:\n{}", run.stderr);
}

#[test]
fn const_initialised_from_module_does_not_dispatch() {
    // N-2: `const N: string = net`, then `N.connect(h)`. The const holds the
    // namespace, but a namespace read out of a `string`-typed slot is not a
    // receiver: dispatch keys on the value's kind, not on a name.
    let probe = Probe::bind();
    let src = helper_program(
        "    let n = N\n    n.connect(h)",
        "const N: string = net\n\n",
        probe.port,
    );
    let run = run_interp("const", &src);
    assert_ne!(
        run.code, 0,
        "stdout: {}\nstderr: {}",
        run.stdout, run.stderr
    );
    assert_eq!(probe.accepted(), 0, "connection accepted:\n{}", run.stderr);
}

#[test]
fn inferred_const_alias_does_not_dispatch() {
    // Same seam, no type annotation: `const M = net`. A module is not a
    // first-class value (E0146), so a const — which binds a value — cannot
    // carry one; it holds the printed form instead.
    let probe = Probe::bind();
    let src = helper_program(
        "    let n = M\n    n.connect(h)",
        "const M = net\n\n",
        probe.port,
    );
    let run = run_interp("const-alias", &src);
    assert_ne!(
        run.code, 0,
        "stdout: {}\nstderr: {}",
        run.stdout, run.stderr
    );
    assert_eq!(probe.accepted(), 0, "connection accepted:\n{}", run.stderr);
}

#[test]
fn module_calls_still_dispatch() {
    // The other half of the contract: adding a variant must not break the
    // namespaces the language already uses. Network-free on purpose.
    let src = r#"fn main() {
    print(math.sqrt(9.0))
    print(math.pi)
    print(json.stringify(["a", "b"]))
}
"#;
    let run = run_interp("positive-modules", src);
    assert_eq!(run.code, 0, "stderr: {}", run.stderr);
    assert!(run.stdout.contains('3'), "stdout: {}", run.stdout);
    assert!(run.stdout.contains("3.14159"), "stdout: {}", run.stdout);
    assert!(
        run.stdout.contains(r#"["a","b"]"#),
        "stdout: {}",
        run.stdout
    );
}

#[test]
fn network_free_examples_still_run() {
    let root = env!("CARGO_MANIFEST_DIR");
    let examples = ["enums.tl", "closure_capture.tl", "hof_chain.tl"];
    let mut failures = Vec::new();
    for name in examples {
        let path = PathBuf::from(root).join("examples").join(name);
        let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
            .arg("run")
            .arg("--target")
            .arg("x86_64-linux")
            .arg(&path)
            .env("TALLOW_ALLOW_DIRECT", "1")
            .output()
            .expect("run tallow");
        if out.status.code() != Some(0) {
            failures.push(format!(
                "{name}: exit {:?}\n{}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "examples failed:\n{}",
        failures.join("\n---\n")
    );
}

#[test]
fn module_prints_as_a_namespace_not_a_tag() {
    // Requirement: printing a module must not yield a spelling a program can
    // hand back. `<module net>` is not `__module_net__`, and the type means
    // there is no parse back — dispatch matches `Value::Module` only.
    use tallow::interp::Value;
    assert_eq!(Value::Module("net").as_string(), "<module net>");
    assert_eq!(format!("{}", Value::Module("math")), "<module math>");
    assert!(!Value::Module("net").as_string().contains("__"));
    // The old tag is now just a string, and prints as one: it is data.
    assert_eq!(
        Value::String("__module_net__".to_string()).as_string(),
        "__module_net__"
    );
}
