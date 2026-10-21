//! A `.tl` file runs as a file, not as a subcommand — and with a shebang it runs
//! as an executable script.
//!
//! Two things had to be true for `./app.tl` with `#!/usr/bin/env tallow` to work:
//! the CLI must treat a real `*.tl` path in argv[1] as `run <path>`, and the lexer
//! must not choke on the `#!` line. This pins both, through the binary, so it
//! would fail if either regressed.

use std::path::{Path, PathBuf};

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tallow"))
}

fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
    let path = dir.join(name);
    std::fs::write(&path, body).expect("write script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(&path).expect("stat").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&path, perms).expect("chmod");
    }
    path
}

fn workdir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow-script-mode-{tag}"));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("mkdir");
    dir
}

#[test]
fn a_dot_tl_path_is_run_not_parsed_as_a_subcommand() {
    let dir = workdir("path");
    let path = script(&dir, "app.tl", "fn main() { print(\"by path\") }\n");
    let out = std::process::Command::new(bin())
        .arg(&path)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "by path\n");
}

#[test]
fn a_shebang_script_is_executable() {
    let dir = workdir("shebang");
    let path = script(
        &dir,
        "app.tl",
        "#!/usr/bin/env tallow\nfn main() { print(\"via shebang\") }\n",
    );
    let bin_dir = bin().parent().expect("bin dir").to_path_buf();
    let path_env = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    // ETXTBSY is a race, not a defect: cargo runs these tests in threads, and a
    // fork from another thread between our write and close leaves the freshly
    // written file briefly busy. Retry it; any other error is real.
    let mut attempt = 0;
    let out = loop {
        match std::process::Command::new(&path)
            .env("PATH", &path_env)
            .env("TALLOW_ALLOW_DIRECT", "1")
            .output()
        {
            Ok(out) => break out,
            Err(e) if e.raw_os_error() == Some(26) && attempt < 20 => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(e) => panic!("exec script: {e}"),
        }
    };
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "via shebang\n");
}

#[test]
fn the_shebang_line_does_not_shift_diagnostics() {
    let dir = workdir("diagnostics");
    // A parse error, which is unambiguous: `let x: i64 = "nope"` is accepted by
    // the checker today (register #137) and an undefined name is only W0102, so
    // neither would prove the offset.
    let path = script(&dir, "broken.tl", "#!/usr/bin/env tallow\nfn main( { }\n");
    let out = std::process::Command::new(bin())
        .arg("check")
        .arg(&path)
        .output()
        .expect("run tallow check");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!out.status.success(), "a type error must not check clean");
    assert!(
        err.contains("2:"),
        "the diagnostic must point at line 2 (the code), not line 1 (the shebang); got: {err}"
    );
}

#[test]
fn arguments_after_the_script_path_reach_the_program() {
    // `./app.tl one` must become `tallow run app.tl -- one`. Without the `--`,
    // clap reads `one` as its own argument and refuses the whole run.
    let dir = workdir("args");
    let path = script(
        &dir,
        "args.tl",
        "#!/usr/bin/env tallow\nfn main() {\n    let a = env.args()\n    print(\"got:\" + a[0] + \"/\" + a.len().to_string())\n}\n",
    );
    let bin_dir = bin().parent().expect("bin dir").to_path_buf();
    let path_env = format!("{}:{}", bin_dir.display(), std::env::var("PATH").unwrap_or_default());
    let mut attempt = 0;
    let out = loop {
        match std::process::Command::new(&path)
            .arg("one")
            .env("PATH", &path_env)
            .env("TALLOW_ALLOW_DIRECT", "1")
            .output()
        {
            Ok(out) => break out,
            Err(e) if e.raw_os_error() == Some(26) && attempt < 20 => {
                attempt += 1;
                std::thread::sleep(std::time::Duration::from_millis(25));
            }
            Err(e) => panic!("exec script: {e}"),
        }
    };
    assert!(
        out.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&out.stdout), "got:one/1\n");
}
