//! Script runner with inline dependency declarations.
//!
//! Supports running standalone `.tl` scripts that declare dependencies
//! inline via either of two comment header formats:
//!
//! **PEP 723 style** (auto-detected, no `--script` flag required):
//! ```nx
//! // /// script
//! // requires = ["tallow-html ^0.3", "tallow-db ^0.2"]
//! // ///
//! ```
//!
//! **TOML doc-comment style** (used with `--script`):
//! ```nx
//! //! [dependencies]
//! //! tallow-html = "^0.3"
//! //! tallow-db = "^0.2"
//! ```
//!
//! The script runner:
//! 1. Detects inline dependency declarations
//! 2. Creates a temporary project directory
//! 3. Generates a tallow.toml with the declared dependencies
//! 4. Installs dependencies via the package manager
//! 5. Returns the path to run the script from the temp project

use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// Parsed inline manifest from a script's comment header.
#[derive(Debug, Clone)]
pub struct ScriptManifest {
    pub dependencies: HashMap<String, String>,
}

/// Parse inline dependency declarations from a script's source code.
///
/// Looks for lines starting with `//!` that form a TOML `[dependencies]` section:
/// ```text
/// //! [dependencies]
/// //! tallow-html = "^0.3"
/// //! tallow-db = "^0.2"
/// ```
///
/// Returns `None` if no inline deps block is found.
pub fn parse_script_manifest(source: &str) -> Option<ScriptManifest> {
    let mut toml_lines = Vec::new();
    let mut in_block = false;

    for line in source.lines() {
        let trimmed = line.trim();
        if let Some(content) = trimmed.strip_prefix("//!") {
            let content = content.strip_prefix(' ').unwrap_or(content);
            if content.trim() == "[dependencies]" {
                in_block = true;
                toml_lines.push("[dependencies]".to_string());
                continue;
            }
            if in_block {
                if content.trim().is_empty() {
                    // Empty line in block -- end of deps section
                    break;
                }
                if content.trim().starts_with('[') {
                    // New section -- end of deps
                    break;
                }
                toml_lines.push(content.to_string());
            }
        } else if in_block {
            // Non-comment line after block started -- end of block
            break;
        } else if !trimmed.is_empty() && !trimmed.starts_with("//") {
            // Non-comment, non-empty line before finding block -- stop searching
            break;
        }
    }

    if !in_block {
        return None;
    }

    let toml_str = toml_lines.join("\n");
    let table: toml::Table = toml_str.parse().ok()?;
    let deps_table = table.get("dependencies")?.as_table()?;

    let mut dependencies = HashMap::new();
    for (key, value) in deps_table {
        if let Some(v) = value.as_str() {
            dependencies.insert(key.clone(), v.to_string());
        }
    }

    Some(ScriptManifest { dependencies })
}

/// Parse PEP 723-style inline dependency declarations.
///
/// Recognises the block format:
/// ```text
/// // /// script
/// // requires = ["tallow-html ^0.3", "tallow-db ^0.2"]
/// // ///
/// ```
///
/// Returns the dependency map (may be empty) when the block is present,
/// or `None` when no such block exists.
pub fn parse_pep723_manifest(source: &str) -> Option<HashMap<String, String>> {
    let mut in_block = false;
    let mut deps: HashMap<String, String> = HashMap::new();

    for line in source.lines() {
        let trimmed = line.trim();
        if trimmed == "// /// script" {
            in_block = true;
            continue;
        }
        if trimmed == "// ///" && in_block {
            break;
        }
        if in_block {
            // Strip the leading `// ` or `//` comment marker
            let content = if let Some(s) = trimmed.strip_prefix("// ") {
                s
            } else if let Some(s) = trimmed.strip_prefix("//") {
                s.trim_start()
            } else {
                continue;
            };

            // Match: requires = ["pkg1 ^1.0", "pkg2 ^2.0"]
            if content.trim_start().starts_with("requires") {
                if let Some(list_start) = content.find('[') {
                    let list_part = &content[list_start..];
                    // Odd-indexed splits on '"' are the quoted strings
                    for (idx, segment) in list_part.split('"').enumerate() {
                        if idx % 2 == 1 {
                            let parts: Vec<&str> = segment.splitn(2, ' ').collect();
                            let name = parts[0].trim().to_string();
                            if name.is_empty() {
                                continue;
                            }
                            let version = parts.get(1).unwrap_or(&"*").trim().to_string();
                            deps.insert(name, version);
                        }
                    }
                }
            }
        }
    }

    if in_block { Some(deps) } else { None }
}

/// Prepare a script for execution by setting up a temp project if needed.
///
/// Supports two inline dependency block styles:
/// - PEP 723 (`// /// script` ... `// ///`) — auto-detected, no flag needed
/// - TOML doc-comment (`//! [dependencies]` ...) — used with `--script`
///
/// If the script has no inline dependencies, returns the original path unchanged.
/// If it has inline deps:
/// 1. Creates a temp project at `{temp}/tallow-script-{hash}/`
/// 2. Generates tallow.toml with the declared dependencies
/// 3. Copies the script to the temp project as main.tl
/// 4. Runs auto_install to fetch dependencies
/// 5. Returns the path to main.tl in the temp project
pub fn prepare_script(script_path: &Path, registry_path: &Path) -> Result<PathBuf, String> {
    let source = std::fs::read_to_string(script_path)
        .map_err(|e| format!("failed to read {}: {}", script_path.display(), e))?;

    // Try PEP 723 format first, then fall back to //! TOML format.
    let dependencies: HashMap<String, String> =
        if let Some(pep) = parse_pep723_manifest(&source) {
            pep
        } else {
            match parse_script_manifest(&source) {
                Some(m) if !m.dependencies.is_empty() => m.dependencies,
                _ => return Ok(script_path.to_path_buf()), // no deps, pass through
            }
        };

    if dependencies.is_empty() {
        return Ok(script_path.to_path_buf());
    }

    // Create temp project directory with a hash-based name for caching
    let hash = {
        let path_str = script_path.to_string_lossy();
        let mut h: u64 = 0;
        for b in path_str.bytes() {
            h = h.wrapping_mul(31).wrapping_add(b as u64);
        }
        format!("{:016x}", h)
    };

    let temp_dir = std::env::temp_dir().join(format!("tallow-script-{}", hash));
    std::fs::create_dir_all(&temp_dir)
        .map_err(|e| format!("failed to create temp dir: {}", e))?;

    // Generate tallow.toml
    let mut toml_content = String::new();
    toml_content.push_str("[package]\n");
    toml_content.push_str("name = \"script\"\n");
    toml_content.push_str("version = \"0.0.0\"\n");
    toml_content.push_str("\n[dependencies]\n");
    for (name, version) in &dependencies {
        toml_content.push_str(&format!("{} = \"{}\"\n", name, version));
    }

    std::fs::write(temp_dir.join("tallow.toml"), &toml_content)
        .map_err(|e| format!("failed to write tallow.toml: {}", e))?;

    // Copy script to temp project
    let main_path = temp_dir.join("main.tl");
    std::fs::copy(script_path, &main_path)
        .map_err(|e| format!("failed to copy script: {}", e))?;

    // Install dependencies
    crate::pkg::cli::auto_install_with_registry(&main_path, registry_path)
        .map_err(|e| format!("failed to install script dependencies: {}", e))?;

    Ok(main_path)
}

/// Check if a source file has inline dependency declarations in either format:
/// - PEP 723 (`// /// script` block)
/// - TOML doc-comment (`//! [dependencies]` block)
pub fn has_inline_deps(source: &str) -> bool {
    let pep723 = parse_pep723_manifest(source)
        .map(|m| !m.is_empty())
        .unwrap_or(false);
    if pep723 {
        return true;
    }
    parse_script_manifest(source)
        .map(|m| !m.dependencies.is_empty())
        .unwrap_or(false)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_script_manifest_present() {
        let source = r#"//! [dependencies]
//! foo = "^1.0"
//! bar = "~2.3"

fn main() {
    print("hello")
}
"#;
        let manifest = parse_script_manifest(source).unwrap();
        assert_eq!(manifest.dependencies.len(), 2);
        assert_eq!(manifest.dependencies.get("foo").unwrap(), "^1.0");
        assert_eq!(manifest.dependencies.get("bar").unwrap(), "~2.3");
    }

    #[test]
    fn test_parse_script_manifest_absent() {
        let source = r#"fn main() {
    print("hello")
}
"#;
        assert!(parse_script_manifest(source).is_none());
    }

    #[test]
    fn test_parse_script_manifest_empty_deps() {
        let source = r#"//! [dependencies]

fn main() {}
"#;
        let manifest = parse_script_manifest(source).unwrap();
        assert!(manifest.dependencies.is_empty());
    }

    #[test]
    fn test_parse_script_manifest_with_comments_before() {
        let source = r#"// This is a regular comment
// Another comment
//! [dependencies]
//! mylib = "^3.0"

fn main() {}
"#;
        let manifest = parse_script_manifest(source).unwrap();
        assert_eq!(manifest.dependencies.len(), 1);
        assert_eq!(manifest.dependencies.get("mylib").unwrap(), "^3.0");
    }

    #[test]
    fn test_prepare_script_no_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("test.tl");
        std::fs::write(&script, "fn main() { print(\"hello\") }").unwrap();

        let reg = tmp.path().join("registry");
        std::fs::create_dir_all(&reg).unwrap();

        let result = prepare_script(&script, &reg).unwrap();
        assert_eq!(result, script, "script without deps should return original path");
    }

    #[test]
    fn test_prepare_script_with_deps() {
        let tmp = tempfile::tempdir().unwrap();
        let script = tmp.path().join("test.tl");
        std::fs::write(
            &script,
            r#"//! [dependencies]
//! tallow-html = "^0.3"

fn main() { print("hello") }
"#,
        )
        .unwrap();

        let reg = tmp.path().join("registry");
        std::fs::create_dir_all(&reg).unwrap();

        let result = prepare_script(&script, &reg);
        // The actual auto_install may fail since there's no real registry,
        // but we can verify the temp project was created
        match result {
            Ok(path) => {
                // If it succeeds (no deps to actually fetch), verify temp dir
                assert!(path.parent().unwrap().join("tallow.toml").exists());
            }
            Err(e) => {
                // Expected: registry doesn't have the package
                // Verify the temp dir WAS created with tallow.toml
                let hash = {
                    let path_str = script.to_string_lossy();
                    let mut h: u64 = 0;
                    for b in path_str.bytes() {
                        h = h.wrapping_mul(31).wrapping_add(b as u64);
                    }
                    format!("{:016x}", h)
                };
                let temp_dir = std::env::temp_dir().join(format!("tallow-script-{}", hash));
                assert!(
                    temp_dir.join("tallow.toml").exists(),
                    "temp tallow.toml should exist even if install fails: {}",
                    e
                );
                let toml_content = std::fs::read_to_string(temp_dir.join("tallow.toml")).unwrap();
                assert!(toml_content.contains("tallow-html"));
            }
        }
    }

    #[test]
    fn test_has_inline_deps() {
        assert!(has_inline_deps("//! [dependencies]\n//! foo = \"^1.0\"\n\nfn main() {}"));
        assert!(!has_inline_deps("fn main() {}"));
        assert!(!has_inline_deps("//! [dependencies]\n\nfn main() {}")); // empty deps
    }

    // ── PEP 723 format tests ────────────────────────────────────────────────

    #[test]
    fn test_parse_pep723_single_dep() {
        let source = "// /// script\n// requires = [\"tallow-html ^0.3\"]\n// ///\n\nfn main() {}\n";
        let deps = parse_pep723_manifest(source).unwrap();
        assert_eq!(deps.len(), 1);
        assert_eq!(deps.get("tallow-html").unwrap(), "^0.3");
    }

    #[test]
    fn test_parse_pep723_multiple_deps() {
        let source =
            "// /// script\n// requires = [\"tallow-html ^0.3\", \"tallow-db ^0.2\"]\n// ///\n\nfn main() {}\n";
        let deps = parse_pep723_manifest(source).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps.get("tallow-html").unwrap(), "^0.3");
        assert_eq!(deps.get("tallow-db").unwrap(), "^0.2");
    }

    #[test]
    fn test_parse_pep723_no_block() {
        let source = "fn main() { print(\"hello\") }\n";
        assert!(parse_pep723_manifest(source).is_none());
    }

    #[test]
    fn test_parse_pep723_empty_requires() {
        let source = "// /// script\n// requires = []\n// ///\n\nfn main() {}\n";
        let deps = parse_pep723_manifest(source).unwrap();
        assert!(deps.is_empty());
    }

    #[test]
    fn test_has_inline_deps_pep723() {
        let source = "// /// script\n// requires = [\"foo ^1.0\"]\n// ///\n\nfn main() {}\n";
        assert!(has_inline_deps(source));
    }

    #[test]
    fn test_has_inline_deps_pep723_empty() {
        // Empty PEP 723 block -- no deps to install, should return false
        let source = "// /// script\n// requires = []\n// ///\n\nfn main() {}\n";
        assert!(!has_inline_deps(source));
    }
}
