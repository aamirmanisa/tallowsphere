//! Standard library: tallow.filter -- File filtering and selection.
//!
//! Provides comprehensive file metadata collection, glob pattern matching,
//! size/age/attribute predicate checks, and named filter profiles for reuse
//! across copy and sync jobs.
//!
//! Users compose filter logic as Tallow expressions operating on
//! FilterFileInfo structs returned by `filter.file_info(path)`.

use crate::interp::Value;
use crate::stdlib::StdlibResult;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

// ============================================================================
// Internal Send-safe profile storage
// ============================================================================
// Value contains non-Send types (DbConn::Rc<RefCell<...>>, BrainHandle, etc.)
// so we store profiles as plain data types and convert to/from Value
// at the API boundary.

/// Internal predicate entry — contains only Send-safe primitive types.
#[derive(Clone)]
struct PredicateEntry {
    pred_type: String,
    threshold: i128,
    pattern: String,
}

/// Internal profile entry stored in the global registry.
#[derive(Clone)]
struct ProfileEntry {
    name: String,
    predicates: Vec<PredicateEntry>,
}

/// Global registry of named filter profiles.
/// Key: profile name, Value: ProfileEntry with predicate data.
static FILTER_PROFILES: LazyLock<Mutex<HashMap<String, ProfileEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Convert a Value::Struct { FilterPredicate } into a PredicateEntry.
fn value_to_predicate_entry(v: &Value) -> Option<PredicateEntry> {
    let (pred_type, threshold, pattern) = extract_predicate_fields(v);
    if pred_type.is_empty() { return None; }
    Some(PredicateEntry { pred_type, threshold, pattern })
}

/// Convert a PredicateEntry back into a Value::Struct { FilterPredicate }.
fn predicate_entry_to_value(e: &PredicateEntry) -> Value {
    let mut fields = vec![
        ("type".into(), Value::String(e.pred_type.clone())),
    ];
    if e.pred_type == "size_gt" {
        fields.push(("threshold".into(), Value::Int(e.threshold)));
    }
    if e.pred_type == "matches" {
        fields.push(("pattern".into(), Value::String(e.pattern.clone())));
    }
    Value::Struct {
        name: "FilterPredicate".to_string(),
        fields,
    }
}

/// Convert a ProfileEntry into a Value::Struct { FilterProfile }.
fn profile_entry_to_value(e: &ProfileEntry) -> Value {
    let preds: Vec<Value> = e.predicates.iter()
        .map(|p| predicate_entry_to_value(p))
        .collect();
    Value::Struct {
        name: "FilterProfile".to_string(),
        fields: vec![
            ("name".into(), Value::String(e.name.clone())),
            ("predicates".into(), Value::Array(preds.clone())),
            ("predicate_count".into(), Value::Int(preds.len() as i128)),
        ],
    }
}

/// Convert a Vec<Value> of FilterPredicate structs into Vec<PredicateEntry>.
fn values_to_predicate_entries(values: &[Value]) -> Result<Vec<PredicateEntry>, String> {
    values.iter()
        .map(|v| value_to_predicate_entry(v)
            .ok_or_else(|| format!("filter: invalid predicate value: {}", v.as_string())))
        .collect()
}

// ============================================================================
// Helper: get string argument
// ============================================================================

fn get_string_arg(args: &Vec<Value>, idx: usize) -> Option<String> {
    args.get(idx).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        _ => None,
    })
}

// ============================================================================
// Field extraction helpers
// ============================================================================

fn extract_field_i128(info: &Value, name: &str) -> Option<i128> {
    if let Value::Struct { fields, .. } = info {
        fields.iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| if let Value::Int(n) = v { Some(*n) } else { None })
    } else { None }
}

fn extract_field_bool(info: &Value, name: &str) -> Option<bool> {
    if let Value::Struct { fields, .. } = info {
        fields.iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| if let Value::Bool(b) = v { Some(*b) } else { None })
    } else { None }
}

fn extract_field_string(info: &Value, name: &str) -> Option<String> {
    if let Value::Struct { fields, .. } = info {
        fields.iter()
            .find(|(k, _)| k == name)
            .and_then(|(_, v)| if let Value::String(s) = v { Some(s.clone()) } else { None })
    } else { None }
}

fn extract_predicate_fields(pred: &Value) -> (String, i128, String) {
    let pred_type = extract_field_string(pred, "type").unwrap_or_default();
    let threshold = extract_field_i128(pred, "threshold").unwrap_or(0);
    let pattern = extract_field_string(pred, "pattern").unwrap_or_default();
    (pred_type, threshold, pattern)
}

// ============================================================================
// Platform attribute detection
// ============================================================================

/// Detect platform-specific file attributes: hidden, readonly, system.
/// Uses #[cfg] to dispatch to the correct platform implementation.
#[cfg(windows)]
fn detect_attributes(path: &Path, meta: &std::fs::Metadata) -> (bool, bool, bool) {
    let is_readonly = meta.permissions().readonly();

    // Use Windows API for hidden/system attributes
    use std::os::windows::fs::MetadataExt;
    let attrs = meta.file_attributes();
    const FILE_ATTRIBUTE_HIDDEN: u32 = 0x2;
    const FILE_ATTRIBUTE_SYSTEM: u32 = 0x4;
    let is_hidden = (attrs & FILE_ATTRIBUTE_HIDDEN) != 0;
    let is_system = (attrs & FILE_ATTRIBUTE_SYSTEM) != 0;

    let _ = path; // suppress unused warning on Windows

    (is_hidden, is_readonly, is_system)
}

#[cfg(not(windows))]
fn detect_attributes(path: &Path, meta: &std::fs::Metadata) -> (bool, bool, bool) {
    // Unix: hidden = name starts with '.'
    let is_hidden = path.file_name()
        .map(|n| n.to_string_lossy().starts_with('.'))
        .unwrap_or(false);

    // Unix: readonly = no write permission for owner
    let is_readonly = {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            (meta.permissions().mode() & 0o200) == 0
        }
        #[cfg(not(unix))]
        { false }
    };

    (is_hidden, is_readonly, false) // no system attribute on Unix
}

// ============================================================================
// FilterFileInfo builder
// ============================================================================

/// Build a FilterFileInfo struct for the given path.
/// Collects size, timestamps, file type, platform attributes, and path components.
fn build_file_info(path: &Path) -> StdlibResult {
    let meta = std::fs::metadata(path)
        .map_err(|e| format!("filter.file_info: cannot stat '{}': {}", path.display(), e))?;

    let symlink_meta = std::fs::symlink_metadata(path).ok();
    let is_symlink = symlink_meta.as_ref()
        .map(|m| m.file_type().is_symlink())
        .unwrap_or(false);

    let size = meta.len() as i128;
    let modified_at = meta.modified().ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i128)
        .unwrap_or(0);
    let created_at = meta.created().ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs() as i128)
        .unwrap_or(0);
    let is_file = meta.is_file();
    let is_dir = meta.is_dir();

    let file_name = path.file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_default();
    let extension = path.extension()
        .map(|e| e.to_string_lossy().to_string())
        .unwrap_or_default();
    let parent_dir = path.parent()
        .map(|p| p.to_string_lossy().to_string())
        .unwrap_or_default();

    // Platform-specific attribute detection
    let (is_hidden, is_readonly, is_system) = detect_attributes(path, &meta);

    Ok(Value::Struct {
        name: "FilterFileInfo".to_string(),
        fields: vec![
            ("path".into(), Value::String(path.to_string_lossy().to_string())),
            ("name".into(), Value::String(file_name)),
            ("extension".into(), Value::String(extension)),
            ("parent".into(), Value::String(parent_dir)),
            ("size".into(), Value::Int(size)),
            ("modified_at".into(), Value::Int(modified_at)),
            ("created_at".into(), Value::Int(created_at)),
            ("is_file".into(), Value::Bool(is_file)),
            ("is_dir".into(), Value::Bool(is_dir)),
            ("is_symlink".into(), Value::Bool(is_symlink)),
            ("is_hidden".into(), Value::Bool(is_hidden)),
            ("is_readonly".into(), Value::Bool(is_readonly)),
            ("is_system".into(), Value::Bool(is_system)),
        ],
    })
}

// ============================================================================
// Glob pattern matching
// ============================================================================

/// Convert a glob pattern to a regex pattern.
/// - `*` matches any sequence of characters (except path separator)
/// - `?` matches exactly one character
/// - `[...]` character classes pass through unchanged
/// The resulting pattern is anchored (^...$) for full-string matching.
fn glob_to_regex(pattern: &str) -> String {
    let mut regex = String::with_capacity(pattern.len() + 4);
    regex.push('^');
    let chars: Vec<char> = pattern.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '*' => regex.push_str(".*"),
            '?' => regex.push('.'),
            '.' | '+' | '(' | ')' | '|' | '\\' | '{' | '}' | '^' | '$' => {
                regex.push('\\');
                regex.push(chars[i]);
            }
            '[' => {
                // Pass bracket expressions through (character classes)
                // Find the closing bracket
                let start = i;
                i += 1;
                while i < chars.len() && chars[i] != ']' {
                    i += 1;
                }
                if i < chars.len() {
                    // Include the full [...] expression
                    for j in start..=i {
                        regex.push(chars[j]);
                    }
                } else {
                    // Unclosed bracket, escape it
                    regex.push_str("\\[");
                    i = start;
                }
            }
            c => regex.push(c),
        }
        i += 1;
    }
    regex.push('$');
    regex
}

/// Test if text matches a glob pattern.
fn matches_glob_impl(text: &str, pattern: &str) -> Result<bool, String> {
    let regex_pattern = glob_to_regex(pattern);
    let re = regex::Regex::new(&regex_pattern)
        .map_err(|e| format!("filter.matches: invalid pattern '{}': {}", pattern, e))?;
    Ok(re.is_match(text))
}

// ============================================================================
// One-shot convenience functions (return Value::Bool directly)
// ============================================================================

/// filter.file_info(path: String) -> FilterFileInfo
fn file_info(args: Vec<Value>) -> StdlibResult {
    let path = get_string_arg(&args, 0)
        .ok_or("filter.file_info: requires file path (string)")?;
    build_file_info(Path::new(&path))
}

/// filter.matches(text: String, pattern: String) -> Bool
fn matches_fn(args: Vec<Value>) -> StdlibResult {
    let text = get_string_arg(&args, 0)
        .ok_or("filter.matches: requires text argument (string)")?;
    let pattern = get_string_arg(&args, 1)
        .ok_or("filter.matches: requires glob pattern (string)")?;
    matches_glob_impl(&text, &pattern).map(Value::Bool)
}

/// filter.size_gt(path: String, bytes: Int) -> Bool
fn size_gt(args: Vec<Value>) -> StdlibResult {
    let path = get_string_arg(&args, 0)
        .ok_or("filter.size_gt: requires file path (string)")?;
    let threshold = match args.get(1) {
        Some(Value::Int(n)) => *n,
        _ => return Err("filter.size_gt: requires byte threshold (Int)".into()),
    };
    let info = build_file_info(Path::new(&path))?;
    let size = extract_field_i128(&info, "size").unwrap_or(0);
    Ok(Value::Bool(size > threshold))
}

/// filter.size_lt(path: String, bytes: Int) -> Bool
fn size_lt(args: Vec<Value>) -> StdlibResult {
    let path = get_string_arg(&args, 0)
        .ok_or("filter.size_lt: requires file path (string)")?;
    let threshold = match args.get(1) {
        Some(Value::Int(n)) => *n,
        _ => return Err("filter.size_lt: requires byte threshold (Int)".into()),
    };
    let info = build_file_info(Path::new(&path))?;
    let size = extract_field_i128(&info, "size").unwrap_or(0);
    Ok(Value::Bool(size < threshold))
}

/// filter.age_gt(path: String, seconds: Int) -> Bool
/// Returns true if file modification time is MORE than `seconds` ago.
fn age_gt(args: Vec<Value>) -> StdlibResult {
    let path = get_string_arg(&args, 0)
        .ok_or("filter.age_gt: requires file path (string)")?;
    let seconds = match args.get(1) {
        Some(Value::Int(n)) => *n,
        _ => return Err("filter.age_gt: requires age in seconds (Int)".into()),
    };
    let info = build_file_info(Path::new(&path))?;
    let modified_at = extract_field_i128(&info, "modified_at").unwrap_or(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i128;
    Ok(Value::Bool((now - modified_at) > seconds))
}

/// filter.age_lt(path: String, seconds: Int) -> Bool
/// Returns true if file modification time is LESS than `seconds` ago.
fn age_lt(args: Vec<Value>) -> StdlibResult {
    let path = get_string_arg(&args, 0)
        .ok_or("filter.age_lt: requires file path (string)")?;
    let seconds = match args.get(1) {
        Some(Value::Int(n)) => *n,
        _ => return Err("filter.age_lt: requires age in seconds (Int)".into()),
    };
    let info = build_file_info(Path::new(&path))?;
    let modified_at = extract_field_i128(&info, "modified_at").unwrap_or(0);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i128;
    Ok(Value::Bool((now - modified_at) < seconds))
}

/// filter.is_hidden(path: String) -> Bool
fn is_hidden_fn(args: Vec<Value>) -> StdlibResult {
    let path = get_string_arg(&args, 0)
        .ok_or("filter.is_hidden: requires file path (string)")?;
    let info = build_file_info(Path::new(&path))?;
    let hidden = extract_field_bool(&info, "is_hidden").unwrap_or(false);
    Ok(Value::Bool(hidden))
}

/// filter.is_readonly(path: String) -> Bool
fn is_readonly_fn(args: Vec<Value>) -> StdlibResult {
    let path = get_string_arg(&args, 0)
        .ok_or("filter.is_readonly: requires file path (string)")?;
    let info = build_file_info(Path::new(&path))?;
    let ro = extract_field_bool(&info, "is_readonly").unwrap_or(false);
    Ok(Value::Bool(ro))
}

// ============================================================================
// Predicate builders (return Value::Struct for use in profiles)
// ============================================================================

/// Build a predicate Value::Struct for size_gt threshold.
fn predicate_size_gt(args: Vec<Value>) -> StdlibResult {
    let threshold = match args.first() {
        Some(Value::Int(n)) => *n,
        _ => return Err("filter.size_gt predicate: requires byte threshold (Int)".into()),
    };
    Ok(Value::Struct {
        name: "FilterPredicate".to_string(),
        fields: vec![
            ("type".into(), Value::String("size_gt".into())),
            ("threshold".into(), Value::Int(threshold)),
        ],
    })
}

/// Build a predicate Value::Struct for matches glob.
fn predicate_matches(args: Vec<Value>) -> StdlibResult {
    let pattern = get_string_arg(&args, 0)
        .ok_or("filter.matches predicate: requires glob pattern (string)")?;
    Ok(Value::Struct {
        name: "FilterPredicate".to_string(),
        fields: vec![
            ("type".into(), Value::String("matches".into())),
            ("pattern".into(), Value::String(pattern)),
        ],
    })
}

// ============================================================================
// Filter profile functions
// ============================================================================

/// Register a named filter profile.
/// filter.profile(name: String, predicates: Array) -> FilterProfile
fn register_profile(args: Vec<Value>) -> StdlibResult {
    let name = get_string_arg(&args, 0)
        .ok_or("filter.profile: requires profile name (string)")?;
    let predicates = match args.get(1) {
        Some(Value::Array(arr)) => arr.clone(),
        Some(other) => return Err(format!(
            "filter.profile: expected array of predicates, got {}",
            other.as_string()
        )),
        None => return Err("filter.profile: requires predicates array".into()),
    };

    // Convert Value predicates to internal Send-safe PredicateEntries
    let entries = values_to_predicate_entries(&predicates)?;

    let profile_entry = ProfileEntry {
        name: name.clone(),
        predicates: entries,
    };

    // Store in global registry
    FILTER_PROFILES.lock()
        .map_err(|e| format!("filter.profile: registry lock poisoned: {}", e))?
        .insert(name, profile_entry.clone());

    Ok(profile_entry_to_value(&profile_entry))
}

/// Retrieve a named filter profile.
/// filter.profile_get(name: String) -> FilterProfile | Err
fn profile_get(args: Vec<Value>) -> StdlibResult {
    let name = get_string_arg(&args, 0)
        .ok_or("filter.profile_get: requires profile name (string)")?;
    let registry = FILTER_PROFILES.lock()
        .map_err(|e| format!("filter.profile_get: registry lock poisoned: {}", e))?;
    match registry.get(&name) {
        Some(profile) => Ok(profile_entry_to_value(profile)),
        None => Err(format!("filter.profile_get: no profile named '{}'", name)),
    }
}

/// List all registered filter profile names.
/// filter.profile_list() -> Array[String]
fn profile_list(_args: Vec<Value>) -> StdlibResult {
    let registry = FILTER_PROFILES.lock()
        .map_err(|e| format!("filter.profile_list: registry lock poisoned: {}", e))?;
    let names: Vec<Value> = registry.keys()
        .map(|k| Value::String(k.clone()))
        .collect();
    Ok(Value::Array(names))
}

/// Evaluate a named filter profile against a file.
/// filter.eval_profile(path: String, profile_name: String) -> FilterResult
fn eval_profile_fn(args: Vec<Value>) -> StdlibResult {
    let path = get_string_arg(&args, 0)
        .ok_or("filter.eval_profile: requires file path (string)")?;
    let profile_name = get_string_arg(&args, 1)
        .ok_or("filter.eval_profile: requires profile name (string)")?;

    let registry = FILTER_PROFILES.lock()
        .map_err(|e| format!("filter.eval_profile: registry lock poisoned: {}", e))?;
    let profile = registry.get(&profile_name)
        .ok_or_else(|| format!("filter.eval_profile: no profile named '{}'", profile_name))?;

    // Convert internal PredicateEntries to Value::Structs for evaluation
    let predicate_values: Vec<Value> = profile.predicates.iter()
        .map(|p| predicate_entry_to_value(p))
        .collect();

    let info = build_file_info(Path::new(&path))?;
    eval_predicates_impl(&info, &predicate_values)
}

// ============================================================================
// Filter evaluation engine
// ============================================================================

/// Evaluate a single FilterPredicate against a FilterFileInfo.
fn eval_predicate(info: &Value, predicate: &Value) -> Result<bool, String> {
    let (pred_type, threshold, pattern) = extract_predicate_fields(predicate);
    match pred_type.as_str() {
        "size_gt" => {
            let size = extract_field_i128(info, "size").unwrap_or(0);
            Ok(size > threshold)
        }
        "matches" => {
            let name = extract_field_string(info, "name").unwrap_or_default();
            matches_glob_impl(&name, &pattern)
        }
        _ => Err(format!("filter.eval: unknown predicate type '{}'", pred_type)),
    }
}

/// Evaluate an array of FilterPredicates against a FilterFileInfo.
/// Returns FilterResult { matched, matched_count, total_count, failures }.
fn eval_predicates_impl(info: &Value, predicates: &[Value]) -> StdlibResult {
    let mut matched = true;
    let mut matched_count: i128 = 0;
    let mut failures: Vec<Value> = Vec::new();
    let total = predicates.len() as i128;

    for pred in predicates {
        match eval_predicate(info, pred) {
            Ok(true) => matched_count += 1,
            Ok(false) => matched = false,
            Err(e) => {
                matched = false;
                failures.push(Value::String(e));
            }
        }
    }

    Ok(Value::Struct {
        name: "FilterResult".to_string(),
        fields: vec![
            ("matched".into(), Value::Bool(matched)),
            ("matched_count".into(), Value::Int(matched_count)),
            ("total_count".into(), Value::Int(total)),
            ("failures".into(), Value::Array(failures)),
        ],
    })
}

/// filter.eval(path: String, predicates: Array) -> FilterResult
fn eval_fn(args: Vec<Value>) -> StdlibResult {
    let path = get_string_arg(&args, 0)
        .ok_or("filter.eval: requires file path (string)")?;
    let predicates = match args.get(1) {
        Some(Value::Array(arr)) => arr.clone(),
        _ => return Err("filter.eval: requires array of predicates".into()),
    };
    let info = build_file_info(Path::new(&path))?;
    eval_predicates_impl(&info, &predicates)
}

// ============================================================================
// Dispatch
// ============================================================================

/// Dispatch a tallow.filter.* function call by name.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "file_info" => Some(file_info(args)),
        "matches" => Some(matches_fn(args)),
        "size_gt" => Some(size_gt(args)),
        "size_lt" => Some(size_lt(args)),
        "age_gt" => Some(age_gt(args)),
        "age_lt" => Some(age_lt(args)),
        "is_hidden" => Some(is_hidden_fn(args)),
        "is_readonly" => Some(is_readonly_fn(args)),
        // Predicate builders (for use in profiles)
        "size_gt_pred" => Some(predicate_size_gt(args)),
        "matches_pred" => Some(predicate_matches(args)),
        // Evaluation
        "eval" => Some(eval_fn(args)),
        // Profiles
        "profile" => Some(register_profile(args)),
        "profile_get" => Some(profile_get(args)),
        "profile_list" => Some(profile_list(args)),
        "eval_profile" => Some(eval_profile_fn(args)),
        _ => None,
    }
}

/// Dispatch a method call on a tallow.filter object type.
pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    if let Value::Struct { name, fields } = object {
        match name.as_str() {
            "FilterFileInfo" | "FilterProfile" | "FilterResult" => {
                for (field_name, field_value) in fields {
                    if field_name == method {
                        return Some(Ok(field_value.clone()));
                    }
                }
                Some(Err(format!("{} has no field '{}'", name, method)))
            }
            "FilterPredicate" => {
                for (field_name, field_value) in fields {
                    if field_name == method {
                        return Some(Ok(field_value.clone()));
                    }
                }
                Some(Err(format!("FilterPredicate has no field '{}'", method)))
            }
            _ => None,
        }
    } else {
        None
    }
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_info_basic() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("test.txt");
        std::fs::write(&f, b"hello filter\n").unwrap();

        let info = build_file_info(&f).unwrap();
        assert!(extract_field_string(&info, "name").unwrap() == "test.txt");
        assert!(extract_field_string(&info, "path").unwrap().contains("test.txt"));
        assert!(extract_field_i128(&info, "size").unwrap() == 13);
        assert!(extract_field_bool(&info, "is_file").unwrap());
        assert!(!extract_field_bool(&info, "is_dir").unwrap());
    }

    #[test]
    fn test_glob_matches_basic() {
        assert!(matches_glob_impl("hello.txt", "*.txt").unwrap());
        assert!(matches_glob_impl("hello.txt", "h*o.txt").unwrap());
        assert!(matches_glob_impl("hello.txt", "hello.???").unwrap());
        assert!(!matches_glob_impl("hello.log", "*.txt").unwrap());
        assert!(!matches_glob_impl("hello.txt", "world.*").unwrap());
    }

    #[test]
    fn test_glob_matches_question_mark() {
        assert!(matches_glob_impl("a", "?").unwrap());
        assert!(matches_glob_impl("ab", "??").unwrap());
        assert!(!matches_glob_impl("abc", "??").unwrap());
    }

    #[test]
    fn test_glob_matches_character_class() {
        assert!(matches_glob_impl("file1.txt", "file[0-9].txt").unwrap());
        assert!(!matches_glob_impl("fileA.txt", "file[0-9].txt").unwrap());
        assert!(matches_glob_impl("fileA.txt", "file[A-Z].txt").unwrap());
    }

    #[test]
    fn test_glob_matches_edge_cases() {
        // Empty pattern matches empty string
        assert!(matches_glob_impl("", "").unwrap());
        // Star matches everything
        assert!(matches_glob_impl("anything at all", "*").unwrap());
        // Multiple stars
        assert!(matches_glob_impl("src/subdir/file.txt", "src*file.txt").unwrap());
    }

    #[test]
    fn test_size_predicates() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("size_test.bin");
        let data = vec![0u8; 1000];
        std::fs::write(&f, &data).unwrap();

        let info = build_file_info(&f).unwrap();
        let size = extract_field_i128(&info, "size").unwrap();
        assert_eq!(size, 1000);

        // Verify size_gt/size_lt via eval
        let pred_gt = Value::Struct {
            name: "FilterPredicate".into(),
            fields: vec![
                ("type".into(), Value::String("size_gt".into())),
                ("threshold".into(), Value::Int(500)),
            ],
        };
        let pred_lt = Value::Struct {
            name: "FilterPredicate".into(),
            fields: vec![
                ("type".into(), Value::String("size_gt".into())),
                ("threshold".into(), Value::Int(2000)),
            ],
        };

        assert!(eval_predicate(&info, &pred_gt).unwrap());  // 1000 > 500
        assert!(!eval_predicate(&info, &pred_lt).unwrap()); // 1000 > 2000 = false
    }

    #[test]
    fn test_matches_predicate() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("important.log");
        std::fs::write(&f, b"log data\n").unwrap();

        let info = build_file_info(&f).unwrap();
        let pred = Value::Struct {
            name: "FilterPredicate".into(),
            fields: vec![
                ("type".into(), Value::String("matches".into())),
                ("pattern".into(), Value::String("*.log".into())),
            ],
        };
        assert!(eval_predicate(&info, &pred).unwrap());

        let pred_no_match = Value::Struct {
            name: "FilterPredicate".into(),
            fields: vec![
                ("type".into(), Value::String("matches".into())),
                ("pattern".into(), Value::String("*.txt".into())),
            ],
        };
        assert!(!eval_predicate(&info, &pred_no_match).unwrap());
    }

    #[test]
    fn test_eval_multiple_predicates() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("photo.jpg");
        let data = vec![0u8; 5_000_000];
        std::fs::write(&f, &data).unwrap();

        let info = build_file_info(&f).unwrap();

        let predicates = vec![
            Value::Struct {
                name: "FilterPredicate".into(),
                fields: vec![
                    ("type".into(), Value::String("size_gt".into())),
                    ("threshold".into(), Value::Int(1_000_000)),
                ],
            },
            Value::Struct {
                name: "FilterPredicate".into(),
                fields: vec![
                    ("type".into(), Value::String("matches".into())),
                    ("pattern".into(), Value::String("*.jpg".into())),
                ],
            },
        ];

        let result = eval_predicates_impl(&info, &predicates).unwrap();
        assert!(extract_field_bool(&result, "matched").unwrap());
        assert_eq!(extract_field_i128(&result, "matched_count").unwrap(), 2);
        assert_eq!(extract_field_i128(&result, "total_count").unwrap(), 2);
    }

    #[test]
    fn test_filter_profiles_register_and_retrieve() {
        let predicates = vec![
            Value::Struct {
                name: "FilterPredicate".into(),
                fields: vec![
                    ("type".into(), Value::String("size_gt".into())),
                    ("threshold".into(), Value::Int(1_000_000)),
                ],
            },
        ];

        // Register profile
        let profile = register_profile(vec![
            Value::String("large-files".into()),
            Value::Array(predicates),
        ]).unwrap();
        assert!(extract_field_string(&profile, "name").unwrap() == "large-files");

        // Retrieve profile
        let retrieved = profile_get(vec![
            Value::String("large-files".into()),
        ]).unwrap();
        assert!(extract_field_string(&retrieved, "name").unwrap() == "large-files");
        assert!(extract_field_i128(&retrieved, "predicate_count").unwrap() == 1);

        // List profiles
        let list = profile_list(vec![]).unwrap();
        if let Value::Array(names) = &list {
            let has_large_files = names.iter().any(|v| {
                if let Value::String(s) = v { s == "large-files" } else { false }
            });
            assert!(has_large_files);
        }

        // Profile not found
        let err = profile_get(vec![Value::String("nonexistent".into())]).unwrap_err();
        assert!(err.contains("no profile named"));
    }

    #[test]
    fn test_eval_profile() {
        // Register a profile first
        let predicates = vec![
            Value::Struct {
                name: "FilterPredicate".into(),
                fields: vec![
                    ("type".into(), Value::String("size_gt".into())),
                    ("threshold".into(), Value::Int(0)),
                ],
            },
        ];
        register_profile(vec![
            Value::String("all-files".into()),
            Value::Array(predicates),
        ]).unwrap();

        // Create a file and eval the profile
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("any.txt");
        std::fs::write(&f, b"content\n").unwrap();

        let result = eval_profile_fn(vec![
            Value::String(f.to_string_lossy().to_string()),
            Value::String("all-files".into()),
        ]).unwrap();
        assert!(extract_field_bool(&result, "matched").unwrap());
    }

    #[test]
    fn test_file_info_nonexistent() {
        let result = build_file_info(Path::new("/nonexistent/path/to/file.txt"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot stat"));
    }
}
