//! Integration tests for fs stdlib functions.
//!
//! Tests fs.read_file, fs.write_file (with parent dir creation), fs.rename,
//! fs.stat (FileInfo struct), fs.temp_file, and backward compat for existing
//! inline fs functions. Windows path handling verified.

use tallow::interp::Interpreter;
use tallow::lexer;
use tallow::parser;

// ── Helpers ──────────────────────────────────────────────────────────────────

fn run_output(source: &str) -> Vec<String> {
    let (tokens, lex_errors) = lexer::tokenize(source);
    assert!(lex_errors.is_empty(), "lex errors: {lex_errors:?}");
    let program = parser::Parser::parse(tokens).expect("parse error");
    let mut interp = Interpreter::new();
    interp.run(&program).expect("runtime error");
    interp.output
}

fn test_dir(suffix: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("tallow_fs_test_{}_{}", std::process::id(), suffix));
    let _ = std::fs::create_dir_all(&dir);
    dir
}

fn cleanup(dir: &std::path::Path) {
    let _ = std::fs::remove_dir_all(dir);
}

// ── fs.read_file ─────────────────────────────────────────────────────────────

#[test]
fn test_fs_read_file() {
    let dir = test_dir("read_file");
    let file_path = dir.join("hello.txt");
    std::fs::write(&file_path, "Hello from Tallow!").unwrap();

    let path_str = file_path.to_string_lossy().replace('\\', "/");
    let source = format!(
        r#"fn main() {{
            let content = fs.read_file("{path_str}")
            print(content)
        }}"#
    );
    let output = run_output(&source);
    assert_eq!(output, vec!["Hello from Tallow!"]);
    cleanup(&dir);
}

#[test]
fn test_fs_read_file_nonexistent() {
    let source = r#"fn main() {
        let content = fs.read_file("__does_not_exist_12345__.txt")
        print(content)
    }"#;
    let (tokens, lex_errors) = lexer::tokenize(source);
    assert!(lex_errors.is_empty());
    let program = parser::Parser::parse(tokens).expect("parse error");
    let mut interp = Interpreter::new();
    let result = interp.run(&program);
    assert!(result.is_err(), "reading nonexistent file should error");
}

// ── fs.write_file (auto-creates parent dirs) ─────────────────────────────────

#[test]
fn test_fs_write_file_creates_parents() {
    let dir = test_dir("write_file");
    let deep_path = dir.join("sub").join("deep").join("file.txt");
    let path_str = deep_path.to_string_lossy().replace('\\', "/");

    let source = format!(
        r#"fn main() {{
            fs.write_file("{path_str}", "nested content")
        }}"#
    );
    run_output(&source);

    let content = std::fs::read_to_string(&deep_path).expect("file should exist");
    assert_eq!(content, "nested content");
    cleanup(&dir);
}

// ── fs.rename ────────────────────────────────────────────────────────────────

#[test]
fn test_fs_rename() {
    let dir = test_dir("rename");
    let old_path = dir.join("old.txt");
    let new_path = dir.join("new.txt");
    std::fs::write(&old_path, "rename me").unwrap();

    let old_str = old_path.to_string_lossy().replace('\\', "/");
    let new_str = new_path.to_string_lossy().replace('\\', "/");

    let source = format!(
        r#"fn main() {{
            fs.rename("{old_str}", "{new_str}")
        }}"#
    );
    run_output(&source);

    assert!(!old_path.exists(), "old file should not exist after rename");
    assert!(new_path.exists(), "new file should exist after rename");
    let content = std::fs::read_to_string(&new_path).unwrap();
    assert_eq!(content, "rename me");
    cleanup(&dir);
}

// ── fs.stat (returns FileInfo struct) ────────────────────────────────────────

#[test]
fn test_fs_stat() {
    let dir = test_dir("stat");
    let file_path = dir.join("data.txt");
    std::fs::write(&file_path, "12345").unwrap();

    let path_str = file_path.to_string_lossy().replace('\\', "/");

    let source = format!(
        r#"fn main() {{
            let info = fs.stat("{path_str}")
            print(info.size)
            print(info.is_file)
            print(info.is_dir)
        }}"#
    );
    let output = run_output(&source);
    assert_eq!(output[0], "5", "size should be 5 bytes");
    assert_eq!(output[1], "true", "is_file should be true");
    assert_eq!(output[2], "false", "is_dir should be false");
    cleanup(&dir);
}

#[test]
fn test_fs_stat_directory() {
    let dir = test_dir("stat_dir");

    let path_str = dir.to_string_lossy().replace('\\', "/");

    let source = format!(
        r#"fn main() {{
            let info = fs.stat("{path_str}")
            print(info.is_file)
            print(info.is_dir)
        }}"#
    );
    let output = run_output(&source);
    assert_eq!(output[0], "false", "is_file should be false for directory");
    assert_eq!(output[1], "true", "is_dir should be true for directory");
    cleanup(&dir);
}

#[test]
fn test_fs_stat_modified_at() {
    let dir = test_dir("stat_mtime");
    let file_path = dir.join("ts.txt");
    std::fs::write(&file_path, "x").unwrap();

    let path_str = file_path.to_string_lossy().replace('\\', "/");

    let source = format!(
        r#"fn main() {{
            let info = fs.stat("{path_str}")
            print(info.modified_at)
        }}"#
    );
    let output = run_output(&source);
    let ts: i64 = output[0].parse().expect("modified_at should be an integer");
    // Should be a recent epoch timestamp (after 2020-01-01)
    assert!(ts > 1_577_836_800, "modified_at should be a recent epoch, got {ts}");
    cleanup(&dir);
}

// ── fs.temp_file ─────────────────────────────────────────────────────────────

#[test]
fn test_fs_temp_file() {
    let source = r#"fn main() {
        let p = fs.temp_file()
        print(p)
    }"#;
    let output = run_output(source);
    assert_eq!(output.len(), 1);
    let path = &output[0];
    assert!(!path.is_empty(), "temp_file should return non-empty path");
    assert!(
        std::path::Path::new(path).exists(),
        "temp file should exist at: {path}"
    );
    // Clean up
    let _ = std::fs::remove_file(path);
}

// ── Backward compat: existing inline fs functions ────────────────────────────

#[test]
fn test_fs_existing_functions_still_work() {
    let dir = test_dir("compat");
    let file_path = dir.join("compat.txt");
    let dir_str = dir.to_string_lossy().replace('\\', "/");
    let file_str = file_path.to_string_lossy().replace('\\', "/");

    // Test fs.exists, fs.is_file, fs.is_dir, fs.write, fs.read
    let source = format!(
        r#"fn main() {{
            print(fs.exists("{dir_str}"))
            print(fs.is_dir("{dir_str}"))
            fs.write("{file_str}", "compat test")
            print(fs.exists("{file_str}"))
            print(fs.is_file("{file_str}"))
            let content = fs.read("{file_str}")
            print(content)
        }}"#
    );
    let output = run_output(&source);
    assert_eq!(output[0], "true", "dir should exist");
    assert_eq!(output[1], "true", "should be a directory");
    assert_eq!(output[2], "true", "file should exist after write");
    assert_eq!(output[3], "true", "should be a file");
    // fs.read returns Ok(...) wrapped Result value (differs from fs.read_file which returns String directly)
    assert!(output[4].contains("compat test"), "fs.read should return content, got: {}", output[4]);
    cleanup(&dir);
}

#[test]
fn test_fs_mkdir_and_list_dir() {
    let dir = test_dir("mkdir_list");
    let sub = dir.join("sub_dir");
    let sub_str = sub.to_string_lossy().replace('\\', "/");
    let dir_str = dir.to_string_lossy().replace('\\', "/");

    let source = format!(
        r#"fn main() {{
            fs.mkdir("{sub_str}")
            print(fs.is_dir("{sub_str}"))
            let entries = fs.list_dir("{dir_str}")
            print(entries)
        }}"#
    );
    let output = run_output(&source);
    assert_eq!(output[0], "true", "subdir should exist after mkdir");
    assert!(output[1].contains("sub_dir"), "list_dir should show sub_dir, got: {}", output[1]);
    cleanup(&dir);
}

// ── Windows path handling ────────────────────────────────────────────────────

#[test]
fn test_fs_windows_forward_slash_paths() {
    // Forward slashes should work on all platforms including Windows
    let dir = test_dir("winpath");
    let file_path = dir.join("subdir").join("win.txt");
    let path_str = file_path.to_string_lossy().replace('\\', "/");

    let source = format!(
        r#"fn main() {{
            fs.write_file("{path_str}", "windows test")
            let c = fs.read_file("{path_str}")
            print(c)
        }}"#
    );
    let output = run_output(&source);
    assert_eq!(output, vec!["windows test"]);
    cleanup(&dir);
}
