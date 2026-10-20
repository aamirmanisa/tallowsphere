//! `on_download` and `on_filechooser` must fire on both planes.
//!
//! Both handlers used to register and then never deliver: `Page.downloadWillBegin`
//! only arrives once a download behavior is set, and `Page.fileChooserOpened` only
//! arrives with file-chooser interception enabled. Neither was armed, so the method
//! looked implemented and could not fire. Registration now arms the CDP domain that
//! produces the event kind, and this test drives the two real UI interactions.

use std::io::{Read, Write};
use std::net::TcpListener;

const PAGE: &str = r#"<html><body>
<a id="dl" href="/file" download="f.txt">get</a>
<input id="f" type="file">
</body></html>"#;

fn serve() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf);
            let req = String::from_utf8_lossy(&buf).to_string();
            let (extra, body) = if req.contains("/file") {
                (
                    "Content-Disposition: attachment; filename=\"f.txt\"\r\n",
                    "hello-download",
                )
            } else {
                ("", PAGE)
            };
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n{extra}Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.flush();
        }
    });
    port
}

const HANDLERS: &str = r#"
fn on_dl_ev(e: PageEvent) {
    print("dl-event")
}

fn on_fc_ev(e: PageEvent) {
    print("fc-event")
}
"#;

fn native_program(base: &str) -> String {
    format!(
        r##"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "ui event parity on loopback", personal_data: false)
@persona(id: "uiev", cover_class: .researcher, compartment: "uiev", fingerprint_seed: "uiev-1020")
@burn_plan(persona: "uiev", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowUiev/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    let dl = page.on_download("on_dl_ev")
    print(dl.kind)
    let fc = page.on_filechooser("on_fc_ev")
    print(fc.kind)
    page.goto("{base}/")
    page.click("#dl")
    page.wait_for_timeout(900)
    print(page.url())
    page.click("#f")
    page.wait_for_timeout(900)
    print(page.url())
    page.close()
    browser.close()
}}
{HANDLERS}"##
    )
}

fn interp_program(base: &str) -> String {
    format!(
        r##"import tallow.browser
@cra_class(.default)
@legal(basis: .research, purpose: "ui event parity on loopback", personal_data: false)
@persona(id: "uiev", cover_class: .researcher, compartment: "uiev", fingerprint_seed: "uiev-1020")
@burn_plan(persona: "uiev", after: .run, method: .revoke_and_quarantine, artifacts: .quarantine)
@fingerprint_policy(policy: .normalize, bot_identity: "TallowUiev/1.0 (+https://tallow.invalid/bot)")
@stealth(profile: .chrome_windows, evasions: .all)
fn main() {{
    let browser = Browser.launch(true)
    let page = browser.new_page()
    page.on_download("on_dl_ev") match {{
        Ok(l) -> print(l.kind)
        Err(e) -> print(e)
    }}
    page.on_filechooser("on_fc_ev") match {{
        Ok(l) -> print(l.kind)
        Err(e) -> print(e)
    }}
    page.goto("{base}/")
    page.click("#dl")
    page.wait_for_timeout(900)
    print(page.url())
    page.click("#f")
    page.wait_for_timeout(900)
    print(page.url())
    page.close()
    browser.close()
}}
{HANDLERS}"##
    )
}

fn run(flag: &str, source: &str, tag: &str) -> Vec<String> {
    let path = std::env::temp_dir().join(format!("tallow-uiev-{}-{tag}.tl", std::process::id()));
    std::fs::write(&path, source).expect("write program");
    let out = std::process::Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(flag)
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(out.status.success(), "{tag} leg failed:\n{stdout}\n{stderr}");
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("* running in the interpreter"))
        .map(str::to_string)
        .collect()
}

#[test]
fn download_and_filechooser_events_fire_on_both_planes() {
    let port = serve();
    let base = format!("http://127.0.0.1:{port}");

    let native = run("--require-native", &native_program(&base), "native");
    let interp = run("--interpret", &interp_program(&base), "interp");

    assert_eq!(native, interp, "planes disagree:\nnative={native:?}\ninterp={interp:?}");
    assert!(
        native.iter().any(|l| l == "dl-event"),
        "on_download never fired: {native:?}"
    );
    assert!(
        native.iter().any(|l| l == "fc-event"),
        "on_filechooser never fired: {native:?}"
    );
}
