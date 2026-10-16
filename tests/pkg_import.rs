use tallow::interp::Interpreter;
use tallow::parser::Parser;
use tallow::lexer::tokenize;
use std::fs;
use std::path::Path;

/// Helper: parse source into a Program
fn parse_source(source: &str) -> tallow::ast::Program {
    let (tokens, lex_errors) = tokenize(source);
    assert!(lex_errors.is_empty(), "lex errors: {:?}", lex_errors);
    Parser::parse(tokens).expect("parse failed")
}

/// Helper: create a project directory with tallow.toml
fn create_project(dir: &Path, name: &str) {
    fs::create_dir_all(dir.join("src")).unwrap();
    fs::write(
        dir.join("tallow.toml"),
        format!(
            r#"[package]
name = "{name}"
version = "0.1.0"
"#
        ),
    )
    .unwrap();
}

#[test]
fn test_import_stdlib_continues_to_work() {
    // Stdlib imports should work as before — they just register the import path
    // and are dispatched via the stdlib router
    let source = r#"
import tallow.fs
import tallow.json

fn main() {
    let exists = fs.exists("nonexistent_file_12345.txt")
    print(exists)
}
"#;
    let program = parse_source(source);
    let mut interp = Interpreter::new();
    let result = interp.run(&program);
    assert!(result.is_ok(), "stdlib import should work: {:?}", result.err());
    assert_eq!(interp.output, vec!["false"]);
}

#[test]
fn test_import_local_file_resolves() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("myproject");
    create_project(&project_dir, "myproject");

    // Create a library file
    fs::write(
        project_dir.join("src").join("mylib.tl"),
        r#"
fn greet(name: String) -> String {
    "hello {name}"
}
"#,
    )
    .unwrap();

    // Create main.tl that imports mylib
    let main_source = r#"
import mylib

fn main() {
    let msg = greet("world")
    print(msg)
}
"#;
    let main_path = project_dir.join("src").join("main.tl");
    fs::write(&main_path, main_source).unwrap();

    let program = parse_source(main_source);
    let mut interp = Interpreter::new();
    interp.set_source_file(&main_path);
    let result = interp.run(&program);
    assert!(result.is_ok(), "local import should work: {:?}", result.err());
    assert_eq!(interp.output, vec!["hello world"]);
}

#[test]
fn test_import_tallow_modules_resolves() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("myproject");
    create_project(&project_dir, "myproject");

    // Create a package in tallow_modules/
    let pkg_dir = project_dir.join("tallow_modules").join("mypkg").join("src");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("lib.tl"),
        r#"
fn add(a: i32, b: i32) -> i32 {
    a + b
}
"#,
    )
    .unwrap();

    // Create main.tl that imports the package
    let main_source = r#"
import mypkg

fn main() {
    let result = add(3, 4)
    print(result)
}
"#;
    let main_path = project_dir.join("src").join("main.tl");
    fs::write(&main_path, main_source).unwrap();

    let program = parse_source(main_source);
    let mut interp = Interpreter::new();
    interp.set_source_file(&main_path);
    let result = interp.run(&program);
    assert!(result.is_ok(), "tallow_modules import should work: {:?}", result.err());
    assert_eq!(interp.output, vec!["7"]);
}

#[test]
fn test_stdlib_takes_priority_over_tallow_modules() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("myproject");
    create_project(&project_dir, "myproject");

    // Create a fake "fs" package in tallow_modules/ that would shadow stdlib
    let pkg_dir = project_dir.join("tallow_modules").join("fs").join("src");
    fs::create_dir_all(&pkg_dir).unwrap();
    fs::write(
        pkg_dir.join("lib.tl"),
        r#"
fn exists(path: String) -> bool {
    true
}
"#,
    )
    .unwrap();

    // import tallow.fs should still use stdlib (which returns false for nonexistent file)
    let main_source = r#"
import tallow.fs

fn main() {
    let result = fs.exists("definitely_not_real_file.txt")
    print(result)
}
"#;
    let main_path = project_dir.join("src").join("main.tl");
    fs::write(&main_path, main_source).unwrap();

    let program = parse_source(main_source);
    let mut interp = Interpreter::new();
    interp.set_source_file(&main_path);
    let result = interp.run(&program);
    assert!(result.is_ok(), "stdlib priority should work: {:?}", result.err());
    // stdlib fs.exists returns false for nonexistent file, NOT the shadowed true
    assert_eq!(interp.output, vec!["false"]);
}

#[test]
fn test_double_import_processed_once() {
    let tmp = tempfile::tempdir().unwrap();
    let project_dir = tmp.path().join("myproject");
    create_project(&project_dir, "myproject");

    // Create a library file with a function
    fs::write(
        project_dir.join("src").join("utils.tl"),
        r#"
fn helper() -> i32 {
    42
}
"#,
    )
    .unwrap();

    // Import the same module twice
    let main_source = r#"
import utils
import utils

fn main() {
    let x = helper()
    print(x)
}
"#;
    let main_path = project_dir.join("src").join("main.tl");
    fs::write(&main_path, main_source).unwrap();

    let program = parse_source(main_source);
    let mut interp = Interpreter::new();
    interp.set_source_file(&main_path);
    let result = interp.run(&program);
    // Should succeed without duplicate definition errors
    assert!(result.is_ok(), "double import should be idempotent: {:?}", result.err());
    assert_eq!(interp.output, vec!["42"]);
}
