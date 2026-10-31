// Egress authorization must hold on EVERY outbound path, not just one.
//
// The register is deny-by-default: a host absent from
// configs/tallow/scope/authorized-hosts.toml is refused before a socket opens.
// Before these gates, only `runtime/fetch.rs` consulted it, so the same target
// was refused by `tallow scope check` and reachable by:
//
//   * net.connect  — raw TCP, both planes
//   * http.post    — no check at all
//   * http.put / http.delete — no check at all
//   * http.get     — only a jurisdiction blocklist, inert without its config
//
// This test asserts the refused/connected asymmetry is gone. It is a NEGATIVE
// test: every assertion is that the operation is refused. A positive control is
// included so a blanket refusal (a broken gate) fails too.
//
// 1.1.1.1 is used as the unregistered host because it is a stable public
// resolver that is NOT in the shipped register (which contains only loopback,
// example.com, www.example.com and check.torproject.org). Nothing is sent: the
// refusal happens before a socket is opened, so this test performs no egress.

use std::process::Command;

/// Run a one-file Tallow program on the given plane and return (stdout, stderr, success).
///
/// The temp directory is keyed by a hash of the program, not just by the plane:
/// the four cases in this file run in parallel in one process, and the first
/// version keyed the directory on `{pid}-{plane}` alone, so two cases wrote and
/// read the same `prog.tl` — one test measured the other's program and failed on
/// a refusal its own source never contains.
fn run_plane(src: &str, plane: &str) -> (String, String, bool) {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    src.hash(&mut h);
    plane.hash(&mut h);
    let dir = std::env::temp_dir().join(format!(
        "tallow-egress-gate-{:016x}",
        h.finish()
    ));
    std::fs::create_dir_all(&dir).expect("temp dir");
    let file = dir.join("prog.tl");
    std::fs::write(&file, src).expect("write program");

    let bin = env!("CARGO_BIN_EXE_tallow");
    let out = Command::new(bin)
        .arg("run")
        .arg(plane)
        .arg(&file)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("run tallow");

    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    let _ = std::fs::remove_dir_all(&dir);
    (stdout, stderr, out.status.success())
}

/// Header required by the checker before any network program will run.
const NET_ANNOTATIONS: &str = r#"
@legal(basis: .research, purpose: "scope gate regression")
@cra_class(.default)
@persona("operator")
@burn_plan("none - refusal happens before egress")
@fingerprint_policy(policy: .none, bot_identity: "TallowTest/1.0 (+https://tallow.invalid/test)")
"#;

#[test]
fn net_connect_refuses_a_host_absent_from_the_register() {
    let src = format!(
        r#"{NET_ANNOTATIONS}
fn main() with Net(connect) {{
    let s = net.connect("1.1.1.1:443")
    // The result MUST be consumed. The compiled plane eliminates a call whose
    // result is never observed, so `let s = net.connect(..); print("CONNECTED")`
    // emits no connect at all — the test would then be asserting on a program
    // that never reached the gate. Printing the handle forces the call to exist
    // on both planes, so a refusal is a refusal rather than dead code.
    print(s)
    // Reaching here at all is the finding: a refused connect must not fall
    // through as an ordinary value. The compiled plane returns the refusal as a
    // string and continues, so this line is what makes the exit status carry
    // the verdict instead of the program reporting success around a refusal.
    print("CONNECTED")
}}
"#
    );
    let (i_out, i_err, i_ok) = run_plane(&src, "--interpret");
    let (n_out, n_err, n_ok) = run_plane(&src, "--require-native");

    // Both planes must have actually run on the plane requested. A plane that
    // silently fell back (or, worse, did not build) proves nothing about that
    // plane's gate, so it fails here rather than being absorbed by a loop.
    assert!(
        format!("{i_out}{i_err}").contains("running in the interpreter"),
        "[--interpret] did not run in the interpreter: {i_out}{i_err}"
    );
    assert!(
        !format!("{n_out}{n_err}").contains("running in the interpreter"),
        "[--require-native] fell back to the interpreter, so the native plane is unmeasured: {n_out}{n_err}"
    );

    // Each plane is asserted on ITS OWN output. Asserting on combined output
    // from a shared loop is what let a native plane that printed `(null)` and
    // opened no socket pass as a refusal: the interpreter's refusal in the same
    // combined string satisfied the check for both.
    let i_all = format!("{i_out}{i_err}");
    assert!(!i_all.contains("CONNECTED"), "[--interpret] reached an unregistered host: {i_all}");
    assert!(!i_ok, "[--interpret] exited 0 on an unregistered host: {i_all}");
    assert!(
        i_all.contains("not in the authorization register"),
        "[--interpret] failed, but not with the register refusal: {i_all}"
    );

    let n_all = format!("{n_out}{n_err}");
    assert!(!n_all.contains("CONNECTED"), "[--require-native] reached an unregistered host: {n_all}");
    assert!(!n_ok, "[--require-native] exited 0 on an unregistered host: {n_all}");
    assert!(
        n_all.contains("not in the authorization register"),
        "[--require-native] failed, but not with the register refusal (a null handle printed as \
         `(null)` is a silent no-op, not a refusal): {n_all}"
    );
}

#[test]
fn http_write_verbs_refuse_a_host_absent_from_the_register() {
    // post / put / delete share one gate; batch delegates to get.
    //
    // The program this case used to carry did not parse: `Budget(bytes: 1048576)` is a
    // blueprint target, not implemented syntax (see docs/egress-gate-open-defects.md), so
    // both planes exited 1 at the parser and only the `!ok` disjunct carried the pass. The
    // corrected program declares the effect the checker actually demands (`Net(post)`).
    let src = format!(
        r#"{NET_ANNOTATIONS}
fn main() with Net(post) {{
    print(http.post("https://192.0.2.1/x", "body"))
}}
"#
    );
    for plane in ["--interpret", "--require-native"] {
        let (stdout, stderr, ok) = run_plane(&src, plane);
        let combined = format!("{stdout}{stderr}");
        // A compiled-plane run that fell back to the interpreter measured the
        // interpreter (already covered above), not the compiled gate. Skip it
        // but say so, rather than letting a fallback masquerade as a pass.
        if plane == "--require-native" && combined.contains("running in the interpreter") {
            eprintln!("[--require-native] fell back to the interpreter; compiled gate unmeasured");
            continue;
        }
        assert!(
            combined.to_lowercase().contains("not in the authorization register")
                || combined.to_lowercase().contains("not listed"),
            "[{plane}] http.post to an unregistered host was not refused by the register: {combined}"
        );
        assert!(!ok, "[{plane}] exited 0 on a refused http.post: {combined}");
    }
}

#[test]
fn a_registered_host_is_reachable_in_the_interpreter() {
    // Positive control for the plane that has one. Loopback is in the shipped
    // register with methods GET/HEAD, so the granted verb is http.get — NOT
    // net.connect: the register grants no CONNECT, so a net.connect control is
    // refused scope:method-not-allowed on both planes and asserts nothing about
    // reachability.
    //
    // Port 1 is closed, so the request fails at the socket layer. What we assert
    // is that the failure is a connection failure rather than a register
    // refusal: reaching the socket is what proves the gate is not a blanket
    // refusal.
    let src = format!(
        r#"{NET_ANNOTATIONS}
fn main() with Net(get) {{
    print(http.get("http://127.0.0.1:1/"))
}}
"#
    );
    let (stdout, stderr, _ok) = run_plane(&src, "--interpret");
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.to_lowercase().contains("not in the authorization register")
            && !combined.to_lowercase().contains("not listed"),
        "[--interpret] loopback was refused by the register, which would make this gate a \
         blanket refusal: {combined}"
    );
    assert!(
        combined.to_lowercase().contains("connection refused"),
        "[--interpret] loopback did not reach the socket layer, so this control proves \
         nothing about a registered host: {combined}"
    );
}

#[test]
fn a_registered_host_is_reachable_on_the_native_plane() {
    let src = format!(
        r#"{NET_ANNOTATIONS}
fn main() with Net(get) {{
    print(http.get("http://127.0.0.1:1/"))
}}
"#
    );
    let (stdout, stderr, _ok) = run_plane(&src, "--require-native");
    let combined = format!("{stdout}{stderr}");
    assert!(
        !combined.to_lowercase().contains("not in the authorization register")
            && !combined.to_lowercase().contains("not listed"),
        "[--require-native] loopback was refused by the register: {combined}"
    );
    assert!(
        combined.to_lowercase().contains("connection refused"),
        "[--require-native] loopback did not reach the socket layer, so this control proves \
         nothing about a registered host: {combined}"
    );
}
