//! Minimal, browser-free reproduction of the v1.7.0 cookie-array split.
//!
//! `tests/browser_array_parity_cookies.rs` reported
//! native=["0","1","1"] vs interp=["0","1","3"] for
//! `page.get_cookies().len`. The array itself was correct on the compiled
//! plane; the LENGTH was read with `strlen` over the native array header.
//!
//! A native array is `[count: i64][slot: i64]...`, so `strlen` on that buffer
//! reads the count's low byte and stops at the NUL of its second byte:
//! 0 -> 0, and every count in 1..=255 -> 1. That is why 3 printed 1.
//!
//! `env.args()` is the same shape (native string array, no browser needed), so
//! this test pins the class without launching Chrome. Both the chained form
//! (`env.args().len`, the broken one) and the bound form (`argv.len`, which was
//! already right) are checked, at N = 0, 1 and 3.

use std::process::Command;

const PROGRAM: &str = include_str!("fixtures/chained_native_array_len.tl");

fn run(flag: &str, args: &[&str]) -> Vec<String> {
    let path = std::env::temp_dir().join(format!(
        "tallow-chained-arr-{}-{flag}.tl",
        std::process::id()
    ));
    std::fs::write(&path, PROGRAM).expect("write program");
    let out = Command::new(env!("CARGO_BIN_EXE_tallow"))
        .arg("run")
        .arg(flag)
        .arg(&path)
        .arg("--")
        .args(args)
        .env("TALLOW_ALLOW_DIRECT", "1")
        .output()
        .expect("run tallow");
    let _ = std::fs::remove_file(&path);
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    assert!(
        out.status.success(),
        "{flag} leg failed:\n{stdout}\n{stderr}"
    );
    stdout
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with("* running in the interpreter"))
        .map(str::to_string)
        .collect()
}

#[test]
fn chained_native_array_len_is_the_count_not_strlen() {
    for (args, want) in [(vec![], "0"), (vec!["a"], "1"), (vec!["a", "b", "c"], "3")] {
        let native = run("--require-native", &args);
        let interp = run("--interpret", &args);
        assert_eq!(
            native,
            interp,
            "planes disagree at N={} ({}):\nnative={native:?}\ninterp={interp:?}",
            args.len(),
            args.join(" ")
        );
        // Chained then bound: both read the same count slot.
        assert_eq!(
            native,
            vec![want.to_string(), want.to_string()],
            "chained `.len` on a native array is not the count at N={}",
            args.len()
        );
    }
}
