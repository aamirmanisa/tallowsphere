//! G21 — capability inference from imports.
//!
//! The rule, in the words it has to be held to:
//!
//! 1. a function that uses an effectful module acquires that effect in its row;
//! 2. a caller of such a function must either declare the same effect or be
//!    refused, with a diagnostic that **names the callee and the effect**
//!    (`E0151` — new here; `E0125` is the default-parameter cycle and is not
//!    reused);
//! 3. `main` may declare the effect; a library function must **propagate** it,
//!    never silently absorb it (`E0141`, at the library function itself, rendered
//!    against the library file);
//! 4. effect sets are per function and are reported by `tallow check` for the
//!    function (`W0130`).
//!
//! Every refusal below is a program that compiled before this item for the
//! simple reason that [`EFFECTFUL_MODULES`] used to know seven names: `net`,
//! `Tcp`, `Udp`, `TLSConn`, `http`, `topology`, `sitescan`. `ws.connect`,
//! `email.connect_imap`, `sync.bidirectional`, `sso.replay_token`,
//! `oauth.exchange_code` and `graphql.graphql_query` each open a socket in the
//! module's own source and each needed no row at all (bridge-review F8).
//!
//! Fixtures are written to a scratch directory at run time rather than kept in
//! `tests/fixtures/`: the item owns one new test file and nothing else.
//!
//! Every fixture that reaches the network carries `@legal`, so the older
//! `@legal` gate (`E0100`) can never be what an assertion is reading.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// A scratch directory for one case, removed when the guard drops.
struct Scratch {
    dir: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("tallow-g21-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).expect("create scratch dir");
        Self { dir }
    }

    fn write(&self, file: &str, source: &str) -> PathBuf {
        let path = self.dir.join(file);
        fs::write(&path, source).expect("write fixture");
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// `tallow check <entry>` → (exit ok, stdout, stderr).
fn check(entry: &Path) -> (bool, String, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("check")
        .arg(entry)
        .output()
        .expect("run tallow check");
    (
        out.status.success(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn check_source(name: &str, source: &str) -> (bool, String, String) {
    let scratch = Scratch::new(name);
    let entry = scratch.write("main.tl", source);
    check(&entry)
}

// ── 1. A function that uses an effectful module acquires the effect ──────────

#[test]
fn socket_opening_module_use_without_a_row_is_refused() {
    // `ws.connect` is `ws.rs:333` → `:95` TcpStream::connect_timeout. It was
    // outside the old seven-name head list, so this compiled with no row.
    let (ok, _stdout, stderr) = check_source(
        "ws_without_row",
        r#"
@legal(basis: .public_data, purpose: "g21 capability inference fixture")
fn fetch_feed() {
    let s = ws.connect("wss://example.invalid/feed")
}
"#,
    );
    assert!(
        !ok,
        "a websocket connect without an effect row must not compile:\n{stderr}"
    );
    assert!(
        stderr.contains("E0141"),
        "the refusal must carry code E0141:\n{stderr}"
    );
    assert!(
        stderr.contains(
            "function body requires effect Net(connect) but the signature does not declare it"
        ),
        "the refusal must name the inferred effect and operation:\n{stderr}"
    );
    assert!(
        stderr.contains("help: add: with Net(connect)"),
        "the refusal must say how to fix it:\n{stderr}"
    );
    assert!(
        !stderr.contains("E0100"),
        "the fixture carries @legal, so E0100 must not fire:\n{stderr}"
    );
}

#[test]
fn email_imap_connect_acquires_net() {
    // `email.connect_imap` is `email.rs:90` → `:133` ImapConnection::connect.
    // The same requirement as `net.connect`, inferred from the imported module.
    let (ok, _stdout, stderr) = check_source(
        "email_without_row",
        r#"
@legal(basis: .public_data, purpose: "g21 capability inference fixture")
fn pull_mail(host: String) {
    let r = email.connect_imap(host, 993, true)
}
"#,
    );
    assert!(
        !ok,
        "an IMAP connect without a row must not compile:\n{stderr}"
    );
    assert!(
        stderr.contains("Net(connect_imap)"),
        "the requirement is inferred as Net(connect_imap):\n{stderr}"
    );
}

// ── 2. The caller must declare it, and the refusal names the callee ─────────

const CALLEE_WITH_ROW: &str = r#"
@legal(basis: .public_data, purpose: "g21 capability inference fixture")
fn probe(g: Grant<Net>, host: String) with Net(connect_imap) {
    let r = email.connect_imap(host, 993, true)
}
"#;

#[test]
fn caller_without_the_row_is_refused_naming_the_callee_and_the_effect() {
    let source = format!(
        "{CALLEE_WITH_ROW}
fn sink(g: Grant<Net>) {{
    probe(g, \"127.0.0.1\")
}}
"
    );
    let (ok, _stdout, stderr) = check_source("caller_without_row", &source);
    assert!(
        !ok,
        "a caller that does not declare the callee's row must not compile:\n{stderr}"
    );
    // The obligation at the site (unchanged, G01).
    assert!(
        stderr.contains("E0141"),
        "the row obligation must still be reported:\n{stderr}"
    );
    // The provenance: which callee imposed it, and which effect (G21).
    assert!(
        stderr.contains("E0151"),
        "the refusal must carry the G21 code E0151:\n{stderr}"
    );
    assert!(
        stderr.contains("call to `probe` requires effect Net(connect_imap)"),
        "E0151 must name the callee and the effect:\n{stderr}"
    );
    assert!(
        stderr.contains("`sink` does not declare it"),
        "E0151 must name the caller that has to declare it:\n{stderr}"
    );
    assert!(
        stderr.contains("thread the `Grant<Net>` through from main"),
        "E0151 must say how to fix it:\n{stderr}"
    );
    assert!(
        !stderr.contains("E0125"),
        "E0125 is the default-parameter cycle and must not be reused:\n{stderr}"
    );
}

#[test]
fn caller_declaring_the_forwarded_row_compiles() {
    let source = format!(
        "{CALLEE_WITH_ROW}
fn sink(g: Grant<Net>) with Net(connect_imap) {{
    probe(g, \"127.0.0.1\")
}}
"
    );
    let (ok, _stdout, stderr) = check_source("caller_with_row", &source);
    assert!(
        ok,
        "the forwarded row on `sink` must satisfy the gate:\n{stderr}"
    );
    assert!(!stderr.contains("E0141"), "no E0141 expected:\n{stderr}");
    assert!(!stderr.contains("E0151"), "no E0151 expected:\n{stderr}");
}

// ── 3. A library function propagates; it does not absorb ────────────────────

#[test]
fn imported_library_function_cannot_absorb_the_effect() {
    let scratch = Scratch::new("library_absorbs");
    scratch.write(
        "lib.tl",
        r#"
@legal(basis: .public_data, purpose: "g21 library fixture")
fn pull(host: String) {
    let r = email.connect_imap(host, 993, true)
}
"#,
    );
    let entry = scratch.write(
        "main.tl",
        r#"
import lib

fn main() {
    pull("127.0.0.1")
}
"#,
    );
    let (ok, _stdout, stderr) = check(&entry);
    assert!(
        !ok,
        "a library function that uses an effectful module and declares nothing \
         must be refused, not silently absorb the requirement:\n{stderr}"
    );
    assert!(
        stderr.contains("E0141"),
        "the library body's own row obligation is the refusal:\n{stderr}"
    );
    assert!(
        stderr.contains("lib.tl:"),
        "the refusal must be rendered against the library file, not the entry \
         file (spans are offsets into their own source):\n{stderr}"
    );
    assert!(
        stderr.contains("Net(connect_imap)"),
        "the refused effect must be named:\n{stderr}"
    );
}

#[test]
fn imported_library_that_declares_propagates_to_its_caller() {
    // The same library, declaring the row: it now propagates, and `main` — the
    // one frame allowed to declare authority — is the frame that gets refused
    // for not declaring it.
    let scratch = Scratch::new("library_propagates");
    scratch.write(
        "lib.tl",
        r#"
@legal(basis: .public_data, purpose: "g21 library fixture")
fn pull(g: Grant<Net>, host: String) with Net(connect_imap) {
    let r = email.connect_imap(host, 993, true)
}
"#,
    );
    let entry = scratch.write(
        "main.tl",
        r#"
import lib

fn main() {
    pull(scope.grant(Net), "127.0.0.1")
}
"#,
    );
    let (ok, _stdout, stderr) = check(&entry);
    assert!(
        !ok,
        "`main` must declare the effect the imported library propagates:\n{stderr}"
    );
    assert!(
        stderr.contains("E0151"),
        "the refusal must name the imported callee:\n{stderr}"
    );
    assert!(
        stderr.contains("call to `pull` requires effect Net(connect_imap)"),
        "E0151 must name `pull` and the effect:\n{stderr}"
    );
    assert!(
        stderr.contains("`main` does not declare it"),
        "E0151 must name `main` as the frame that has to declare it:\n{stderr}"
    );
}

#[test]
fn main_may_declare_the_effect() {
    let scratch = Scratch::new("library_main_declares");
    scratch.write(
        "lib.tl",
        r#"
@legal(basis: .public_data, purpose: "g21 library fixture")
fn pull(g: Grant<Net>, host: String) with Net(connect_imap) {
    let r = email.connect_imap(host, 993, true)
}
"#,
    );
    let entry = scratch.write(
        "main.tl",
        r#"
import lib

fn main() with Net(connect_imap) {
    pull(scope.grant(Net), "127.0.0.1")
}
"#,
    );
    let (ok, _stdout, stderr) = check(&entry);
    assert!(ok, "`main` may declare the propagated effect:\n{stderr}");
    assert!(!stderr.contains("E0141"), "no E0141 expected:\n{stderr}");
    assert!(!stderr.contains("E0151"), "no E0151 expected:\n{stderr}");
}

// ── 4. Effect sets are per function and reported by `check` ────────────────

#[test]
fn effect_set_is_reported_for_each_function() {
    let source = format!(
        "{CALLEE_WITH_ROW}
fn sink(g: Grant<Net>) with Net(connect_imap) {{
    probe(g, \"127.0.0.1\")
}}
"
    );
    let (ok, _stdout, stderr) = check_source("effect_set_report", &source);
    assert!(ok, "the program must compile:\n{stderr}");
    assert!(
        stderr.contains("W0130"),
        "the effect set is reported per function:\n{stderr}"
    );
    assert!(
        stderr.contains("effect set of `probe`: Net(connect_imap)"),
        "`probe`'s own set must be reported:\n{stderr}"
    );
    assert!(
        stderr.contains("effect set of `sink`: Net(connect_imap)"),
        "`sink`'s set — inherited from `probe` — must be reported too, which is \
         what makes it per function:\n{stderr}"
    );
}

#[test]
fn a_function_with_no_effect_has_no_effect_set() {
    let (ok, _stdout, stderr) = check_source(
        "no_effect",
        r#"
fn add(a: i64, b: i64) -> i64 {
    a + b
}
"#,
    );
    assert!(ok, "the program must compile:\n{stderr}");
    assert!(
        !stderr.contains("W0130"),
        "a function with no effect has an empty set, and an empty set is not \
         reported:\n{stderr}"
    );
}

// ── 5. The manifest must not over-reach ────────────────────────────────────

#[test]
fn concurrency_primitives_in_sync_are_not_network() {
    // `sync` is a mixed module: the HTTP daemon client egresses, the channels,
    // mutexes and barriers do not. A head-level rule would demand `with Net`
    // for a mutex; the operation-level manifest must not.
    let (ok, _stdout, stderr) = check_source(
        "sync_mutex",
        r#"
fn guard() {
    let m = sync.mutex(1)
    let c = sync.channel(4)
}
"#,
    );
    assert!(
        ok,
        "a concurrency primitive must not require a network row:\n{stderr}"
    );
    assert!(
        !stderr.contains("Net"),
        "no Net requirement may be inferred from `sync.mutex`:\n{stderr}"
    );
}

#[test]
fn offline_operation_of_a_mixed_module_needs_no_row() {
    // `oauth.authorization_url` builds a string; `oauth.exchange_code` posts to
    // the token endpoint. Only the second one acquires Net.
    let (ok, _stdout, stderr) = check_source(
        "oauth_offline_op",
        r#"
fn url() {
    let u = oauth.authorization_url("https://idp.example.invalid/auth", "client", "https://app.example.invalid/cb")
}
"#,
    );
    assert!(
        ok,
        "building an authorization URL must not require a network row:\n{stderr}"
    );
    assert!(
        !stderr.contains("Net"),
        "no Net requirement may be inferred from `oauth.authorization_url`:\n{stderr}"
    );
}
