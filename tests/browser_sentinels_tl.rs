//! The browser v2 sentinels that used to pretend.
//!
//! `NetworkInterceptor`, `TraceRecorder` and `DeviceEmulator` each returned a
//! struct with `simulated: true` and a state nothing underneath ever read — rules
//! that blocked nothing, a recorder that recorded nothing, viewport settings
//! applied to no page. The interpreter now refuses those calls by name and says
//! which CDP domain would make them real. This test pins that refusal so the
//! fakes cannot come back quietly.

use std::process::Command;

fn run(source: &str, name: &str) -> (bool, String) {
    let dir = std::env::temp_dir().join(format!("tallow-sentinel-{}-{name}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("dir");
    let file = dir.join(format!("{name}.tl"));
    std::fs::write(&file, source).expect("write");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(&file)
        .current_dir(&dir)
        .output()
        .expect("run tallow");
    (
        out.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        ),
    )
}

#[test]
fn interception_rules_refuse_rather_than_pretend_to_block() {
    let src = r#"
fn main() {
    let i = NetworkInterceptor.create();
    print(i);
}
"#;
    let (_ok, all) = run(src, "intercept");
    assert!(all.contains("no browser connected"), "{all}");
    assert!(all.contains("CDP Fetch domain"), "{all}");
}

#[test]
fn device_emulation_refuses_rather_than_setting_a_page_that_is_not_there() {
    let src = r#"
fn main() {
    let e = DeviceEmulator.set_viewport(1280, 800, 1.0);
    print(e);
}
"#;
    let (_ok, all) = run(src, "viewport");
    assert!(all.contains("no browser connected"), "{all}");
    assert!(all.contains("CDP Emulation domain"), "{all}");
}

#[test]
fn trace_recording_refuses_rather_than_recording_nothing() {
    let src = r#"
fn main() {
    let t = TraceRecorder.start("demo");
    print(t);
}
"#;
    let (_ok, all) = run(src, "trace");
    assert!(all.contains("no browser connected"), "{all}");
    assert!(all.contains("CDP Tracing domain"), "{all}");
}
