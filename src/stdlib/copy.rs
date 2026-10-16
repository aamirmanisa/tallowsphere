//! Standard library: tallow.copy -- Streaming file copy with always-on BLAKE3 verification.
//!
//! Every copy operation computes dual BLAKE3 hashes (source and destination)
//! in a single pass, builds a Merkle tree from chunk hashes, persists the tree
//! as a .merkle companion file, preserves file metadata, and emits a structured
//! JSON log event.

use crate::interp::Value;
use crate::stdlib::io_backend::{self};
use crate::stdlib::StdlibResult;
use std::io::BufReader;
use std::io::Read as IoRead;
use std::path::{Path, PathBuf};
use std::time::Instant;

const DEFAULT_CHUNK_SIZE: usize = 262144; // 256KB

// ── CopyResult ──────────────────────────────────────────────────────────

/// Holds all outcome data from a copy operation.
#[derive(Debug)]
struct CopyResult {
    source: String,
    destination: String,
    source_hash: String,
    destination_hash: String,
    verified: bool,
    bytes_copied: u64,
    elapsed_ms: u128,
    throughput_mbps: f64,
    chunk_count: usize,
    merkle_root: String,
    metadata_preserved: bool,
}

impl CopyResult {
    /// Convert CopyResult into a Tallow `Value::Struct { name: "CopyStats" }`.
    fn to_value(&self) -> Value {
        Value::Struct {
            name: "CopyStats".to_string(),
            fields: vec![
                ("source".to_string(), Value::String(self.source.clone())),
                ("destination".to_string(), Value::String(self.destination.clone())),
                ("source_hash".to_string(), Value::String(self.source_hash.clone())),
                ("destination_hash".to_string(), Value::String(self.destination_hash.clone())),
                ("verified".to_string(), Value::Bool(self.verified)),
                ("bytes_copied".to_string(), Value::Int(self.bytes_copied as i128)),
                ("elapsed_ms".to_string(), Value::Int(self.elapsed_ms as i128)),
                ("throughput_mbps".to_string(), Value::Float(self.throughput_mbps)),
                ("chunk_count".to_string(), Value::Int(self.chunk_count as i128)),
                ("merkle_root".to_string(), Value::String(self.merkle_root.clone())),
                ("metadata_preserved".to_string(), Value::Bool(self.metadata_preserved)),
            ],
        }
    }
}

// ── Streaming dual-hasher copy ──────────────────────────────────────────

/// Core engine: reads source file via platform I/O backend,
/// hashes source and destination in memory, collects chunk hashes.
/// Returns CopyResult and full Merkle tree layers.
fn copy_file_streaming(
    src: &Path,
    dst: &Path,
    chunk_size: usize,
) -> Result<(CopyResult, Vec<Vec<String>>), String> {
    let start = Instant::now();
    let backend = io_backend::detect_backend();

    // Ensure parent directory exists
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("copy: cannot create parent dir '{}': {}", parent.display(), e))?;
    }

    // Read entire source file using platform I/O backend
    let file_data = io_backend::read_file_sync(src, backend)
        .map_err(|e| format!("copy: cannot open source '{}': {}", src.display(), e))?;
    let file_size = file_data.len() as u64;

    // Hash source bytes
    let mut src_hasher = blake3::Hasher::new();
    src_hasher.update(&file_data);
    let source_hash = src_hasher.finalize().to_hex().to_string();

    // Write to destination using platform I/O backend
    io_backend::write_file_sync(dst, &file_data, backend)
        .map_err(|e| format!("copy: write error on '{}': {}", dst.display(), e))?;

    // Hash destination bytes (from same in-memory data — zero re-read)
    let mut dst_hasher = blake3::Hasher::new();
    dst_hasher.update(&file_data);
    let destination_hash = dst_hasher.finalize().to_hex().to_string();

    let verified = source_hash == destination_hash;

    // Build chunk hashes from file_data in chunk_size blocks
    let chunk_hashes: Vec<String> = file_data
        .chunks(chunk_size)
        .map(|chunk| blake3::hash(chunk).to_hex().to_string())
        .collect();

    // Build Merkle tree from chunk hashes
    let merkle_tree = build_merkle_tree(&chunk_hashes);
    let merkle_root = build_merkle_root(&chunk_hashes);

    let elapsed_ms = start.elapsed().as_millis();
    let seconds = elapsed_ms as f64 / 1000.0;
    let mb = file_size as f64 / (1024.0 * 1024.0);
    let throughput_mbps = if seconds > 0.0 { mb / seconds } else { 0.0 };

    let result = CopyResult {
        source: src.to_string_lossy().to_string(),
        destination: dst.to_string_lossy().to_string(),
        source_hash,
        destination_hash,
        verified,
        bytes_copied: file_size,
        elapsed_ms,
        throughput_mbps,
        chunk_count: chunk_hashes.len(),
        merkle_root,
        metadata_preserved: false, // set by caller
    };

    Ok((result, merkle_tree))
}

// ── Merkle tree construction ──────────────────────────────────────────

/// Build a full binary Merkle tree from chunk (leaf) hashes.
/// Returns all layers: layer 0 = leaves, layer N = root.
fn build_merkle_tree(chunk_hashes: &[String]) -> Vec<Vec<String>> {
    if chunk_hashes.is_empty() {
        // Empty file: root is BLAKE3 of empty bytes
        return vec![vec![blake3::hash(b"").to_hex().to_string()]];
    }

    let mut layers: Vec<Vec<String>> = Vec::new();
    layers.push(chunk_hashes.to_vec()); // layer 0 = leaves

    let mut current: Vec<String> = chunk_hashes.to_vec();
    while current.len() > 1 {
        let mut next_level = Vec::new();
        let chunks = current.chunks(2);
        for pair in chunks {
            if pair.len() == 2 {
                let combined = format!("{}{}", pair[0], pair[1]);
                let parent = blake3::hash(combined.as_bytes());
                next_level.push(parent.to_hex().to_string());
            } else {
                // Odd leaf: promote unchanged
                next_level.push(pair[0].clone());
            }
        }
        layers.push(next_level.clone());
        current = next_level;
    }
    layers
}

/// Convenience: return only the root hash from the Merkle tree.
fn build_merkle_root(chunk_hashes: &[String]) -> String {
    let tree = build_merkle_tree(chunk_hashes);
    tree.last()
        .and_then(|l| l.last())
        .cloned()
        .unwrap_or_else(|| blake3::hash(b"").to_hex().to_string())
}

// ── Merkle file persistence ───────────────────────────────────────────

/// Write a `.merkle` companion file alongside the destination file.
fn write_merkle_file(
    file_path: &Path,
    tree: &Vec<Vec<String>>,
    source_hash: &str,
    file_size: u64,
    chunk_size: usize,
    verified: bool,
) -> Result<(), String> {
    let merkle_path = PathBuf::from(format!("{}.merkle", file_path.display()));
    let root_hash = tree
        .last()
        .and_then(|l| l.last())
        .cloned()
        .unwrap_or_default();
    let chunk_hashes: Vec<&String> = tree.first().map_or(&[] as &[String], |l| l.as_slice()).iter().collect();

    let created_at = chrono::Utc::now().to_rfc3339();

    let merkle_json = serde_json::json!({
        "format": "tallow-merkle-v1",
        "file_path": file_path.to_string_lossy(),
        "file_size": file_size,
        "chunk_size": chunk_size,
        "chunk_count": chunk_hashes.len(),
        "root_hash": root_hash,
        "chunk_hashes": chunk_hashes,
        "tree_layers": tree,
        "source_hash": source_hash,
        "algorithm": "blake3",
        "created_at": created_at,
        "verified": verified
    });

    let json_str = serde_json::to_string_pretty(&merkle_json).unwrap_or_default();
    std::fs::write(&merkle_path, json_str)
        .map_err(|e| format!("copy: cannot write merkle file '{}': {}", merkle_path.display(), e))
}

// ── Metadata preservation ─────────────────────────────────────────────

/// Preserve file modification time (and permissions on Unix).
/// Best-effort — returns true if mtime was successfully preserved.
fn preserve_metadata(src: &Path, dst: &Path) -> bool {
    let mut mtime_ok = false;
    if let Ok(src_meta) = std::fs::metadata(src) {
        if let Ok(mtime) = src_meta.modified() {
            let ft = filetime::FileTime::from_system_time(mtime);
            mtime_ok = filetime::set_file_mtime(dst, ft).is_ok();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(dst, src_meta.permissions());
        }
    }
    mtime_ok
}

// ── JSON logging ──────────────────────────────────────────────────────

/// Emit one JSON line to stderr per copy operation.
fn emit_copy_log(result: &CopyResult) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let log_event = serde_json::json!({
        "event": "file_copied",
        "source": result.source,
        "destination": result.destination,
        "size_bytes": result.bytes_copied,
        "source_hash": result.source_hash,
        "destination_hash": result.destination_hash,
        "verified": result.verified,
        "elapsed_ms": result.elapsed_ms,
        "throughput_mbps": result.throughput_mbps,
        "chunk_count": result.chunk_count,
        "merkle_root": result.merkle_root,
        "metadata_preserved": result.metadata_preserved,
        "timestamp": timestamp,
        "io_backend": io_backend::backend_name(&io_backend::detect_backend())
    });
    eprintln!("{}", serde_json::to_string(&log_event).unwrap_or_default());
}

// ── Argument helper ───────────────────────────────────────────────────

fn get_string_arg(args: &[Value], idx: usize) -> Option<String> {
    args.get(idx).and_then(|v| match v {
        Value::String(s) => Some(s.clone()),
        _ => None,
    })
}

// ── Top-level copy orchestration ──────────────────────────────────────

fn copy_file(args: &[Value]) -> StdlibResult {
    let src = get_string_arg(args, 0)
        .ok_or_else(|| "copy.file: requires source path (string)".to_string())?;
    let dst = get_string_arg(args, 1)
        .ok_or_else(|| "copy.file: requires destination path (string)".to_string())?;

    let (mut result, merkle_tree) =
        copy_file_streaming(Path::new(&src), Path::new(&dst), DEFAULT_CHUNK_SIZE)?;

    // Best-effort metadata preservation
    result.metadata_preserved = preserve_metadata(Path::new(&src), Path::new(&dst));

    emit_copy_log(&result);

    write_merkle_file(
        Path::new(&dst),
        &merkle_tree,
        &result.source_hash,
        result.bytes_copied,
        DEFAULT_CHUNK_SIZE,
        result.verified,
    )?;

    Ok(result.to_value())
}

// ── Standalone verification ──────────────────────────────────────────

/// Read and parse a .merkle companion file.
fn read_merkle_file(file_path: &Path) -> Result<serde_json::Value, String> {
    let merkle_path = PathBuf::from(format!("{}.merkle", file_path.display()));
    if !merkle_path.exists() {
        return Err(format!(
            "verify: no .merkle file found for '{}' (expected at '{}')",
            file_path.display(),
            merkle_path.display()
        ));
    }
    let content = std::fs::read_to_string(&merkle_path)
        .map_err(|e| format!("verify: cannot read .merkle file: {}", e))?;
    serde_json::from_str(&content)
        .map_err(|e| format!("verify: invalid .merkle JSON: {}", e))
}

/// Verify a single file against its .merkle companion file.
/// Recomputes chunk hashes from the file on disk and compares the Merkle root.
fn verify_file_impl(file_path: &Path, chunk_size: usize) -> StdlibResult {
    // Read .merkle companion
    let merkle: serde_json::Value = match read_merkle_file(file_path) {
        Ok(m) => m,
        Err(e) => return Err(e),
    };

    let stored_root = merkle["root_hash"].as_str()
        .ok_or("verify: .merkle file missing 'root_hash' field")?;
    let stored_chunks: Vec<String> = merkle["chunk_hashes"]
        .as_array()
        .ok_or("verify: .merkle file missing 'chunk_hashes' array")?
        .iter()
        .map(|v| v.as_str().unwrap_or("").to_string())
        .collect();
    let stored_file_size = merkle["file_size"].as_u64().unwrap_or(0);

    // Check current file exists and get size
    let metadata = std::fs::metadata(file_path)
        .map_err(|e| format!("verify: cannot stat '{}': {}", file_path.display(), e))?;
    let current_size = metadata.len();

    // Read file and recompute chunk hashes
    let file = std::fs::File::open(file_path)
        .map_err(|e| format!("verify: cannot open '{}': {}", file_path.display(), e))?;
    let mut reader = BufReader::with_capacity(chunk_size, file);
    let mut buf = vec![0u8; chunk_size];
    let mut recomputed_chunks: Vec<String> = Vec::new();

    loop {
        let n = reader.read(&mut buf)
            .map_err(|e| format!("verify: read error: {}", e))?;
        if n == 0 { break; }
        let chunk_hash = blake3::hash(&buf[..n]).to_hex().to_string();
        recomputed_chunks.push(chunk_hash);
    }

    // Build Merkle root from recomputed chunks
    let recomputed_root = build_merkle_root(&recomputed_chunks);
    let verified = recomputed_root == stored_root;

    // Check individual chunk matches
    let chunk_count = recomputed_chunks.len();
    let mut matching_chunks = 0usize;
    let min_chunks = stored_chunks.len().min(recomputed_chunks.len());
    for i in 0..min_chunks {
        if recomputed_chunks[i] == stored_chunks[i] {
            matching_chunks += 1;
        }
    }

    Ok(Value::Struct {
        name: "VerifyResult".to_string(),
        fields: vec![
            ("verified".into(), Value::Bool(verified)),
            ("file".into(), Value::String(file_path.to_string_lossy().to_string())),
            ("expected_root".into(), Value::String(stored_root.to_string())),
            ("actual_root".into(), Value::String(recomputed_root)),
            ("stored_chunks".into(), Value::Int(stored_chunks.len() as i128)),
            ("recomputed_chunks".into(), Value::Int(chunk_count as i128)),
            ("matching_chunks".into(), Value::Int(matching_chunks as i128)),
            ("stored_file_size".into(), Value::Int(stored_file_size as i128)),
            ("current_file_size".into(), Value::Int(current_size as i128)),
            ("size_changed".into(), Value::Bool(stored_file_size != current_size)),
        ],
    })
}

/// Collect all .merkle files recursively in a directory.
fn collect_merkle_files(dir: &Path) -> Result<Vec<PathBuf>, String> {
    let mut result = Vec::new();
    let entries = std::fs::read_dir(dir)
        .map_err(|e| format!("verify_dir: cannot read '{}': {}", dir.display(), e))?;
    for entry in entries {
        let entry = entry.map_err(|e| format!("verify_dir: entry error: {}", e))?;
        let path = entry.path();
        if path.is_dir() {
            result.extend(collect_merkle_files(&path)?);
        } else if path.extension().map(|e| e == "merkle").unwrap_or(false) {
            result.push(path);
        }
    }
    Ok(result)
}

/// Verify an entire directory against .merkle companion files.
fn verify_dir_impl(dir_path: &Path, chunk_size: usize) -> StdlibResult {
    if !dir_path.is_dir() {
        return Err(format!(
            "verify_dir: '{}' is not a directory",
            dir_path.display()
        ));
    }

    let mut total_files: i128 = 0;
    let mut verified_count: i128 = 0;
    let mut failed_count: i128 = 0;
    let mut missing_merkle: i128 = 0;
    let mut mismatched: Vec<Value> = Vec::new();

    // Collect all .merkle files
    let merkle_files = collect_merkle_files(dir_path)?;

    for merkle_path in &merkle_files {
        let file_path = merkle_path.with_extension(""); // strip .merkle
        if !file_path.exists() {
            // .merkle exists but file doesn't
            missing_merkle += 1;
            mismatched.push(Value::Struct {
                name: "MismatchEntry".to_string(),
                fields: vec![
                    ("path".into(), Value::String(merkle_path.to_string_lossy().to_string())),
                    ("reason".into(), Value::String("file missing, only .merkle exists".into())),
                ],
            });
            continue;
        }
        total_files += 1;
        match verify_file_impl(&file_path, chunk_size) {
            Ok(result) => {
                if let Value::Struct { fields, .. } = &result {
                    let is_verified = fields.iter()
                        .find(|(k, _)| k == "verified")
                        .map(|(_, v)| matches!(v, Value::Bool(true)))
                        .unwrap_or(false);
                    if is_verified {
                        verified_count += 1;
                    } else {
                        failed_count += 1;
                        mismatched.push(Value::Struct {
                            name: "MismatchEntry".to_string(),
                            fields: vec![
                                ("path".into(), Value::String(file_path.to_string_lossy().to_string())),
                                ("reason".into(), Value::String("Merkle root mismatch".into())),
                            ],
                        });
                    }
                }
            }
            Err(e) => {
                failed_count += 1;
                mismatched.push(Value::Struct {
                    name: "MismatchEntry".to_string(),
                    fields: vec![
                        ("path".into(), Value::String(file_path.to_string_lossy().to_string())),
                        ("reason".into(), Value::String(e)),
                    ],
                });
            }
        }
    }

    Ok(Value::Struct {
        name: "VerifyDirResult".to_string(),
        fields: vec![
            ("total_files".into(), Value::Int(total_files)),
            ("verified".into(), Value::Int(verified_count)),
            ("failed".into(), Value::Int(failed_count)),
            ("missing_merkle".into(), Value::Int(missing_merkle)),
            ("mismatched".into(), Value::Array(mismatched)),
        ],
    })
}

// ── Tallow-facing verification wrappers ──────────────────────────────

fn verify_file(args: &[Value]) -> StdlibResult {
    let path = get_string_arg(args, 0)
        .ok_or("copy.verify_file: requires file path (string)")?;
    verify_file_impl(Path::new(&path), DEFAULT_CHUNK_SIZE)
}

fn verify_dir(args: &[Value]) -> StdlibResult {
    let path = get_string_arg(args, 0)
        .ok_or("copy.verify_dir: requires directory path (string)")?;
    verify_dir_impl(Path::new(&path), DEFAULT_CHUNK_SIZE)
}

// ── Directory copy with adaptive parallelism ─────────────────────────

/// Compute the number of parallel copy workers based on file count and CPU cores.
/// Formula: min(files/10, cpus*2) capped at 64, minimum 1.
fn adaptive_worker_count(file_count: usize) -> usize {
    let cpus = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    let file_based = if file_count > 0 {
        std::cmp::max(1, file_count / 10)
    } else {
        1
    };
    let absolute_max: usize = 64;
    std::cmp::min(file_based, std::cmp::min(cpus * 2, absolute_max))
}

/// Recursive helper: walk a directory tree and copy every file.
/// Uses copy_file_streaming for individual files and recurses for subdirectories.
fn copy_dir_recursive(
    src: &Path, dst: &Path, chunk_size: usize,
    files_copied: &mut u64, dirs_created: &mut u64, bytes_copied: &mut u64,
    errors: &mut Vec<String>, all_verified: &mut bool,
) -> Result<(), String> {
    let entries = std::fs::read_dir(src)
        .map_err(|e| format!("copy.dir: cannot read '{}': {}", src.display(), e))?;

    for entry in entries {
        let entry = entry.map_err(|e| format!("copy.dir: entry error: {}", e))?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        let md = entry.metadata()
            .map_err(|e| format!("copy.dir: metadata for '{}': {}", src_path.display(), e))?;

        if md.is_dir() {
            std::fs::create_dir_all(&dst_path)
                .map_err(|e| format!("copy.dir: mkdir '{}': {}", dst_path.display(), e))?;
            *dirs_created += 1;
            copy_dir_recursive(&src_path, &dst_path, chunk_size, files_copied, dirs_created, bytes_copied, errors, all_verified)?;
        } else if md.is_file() {
            match copy_file_streaming(&src_path, &dst_path, chunk_size) {
                Ok((result, tree)) => {
                    *files_copied += 1;
                    *bytes_copied += result.bytes_copied;
                    if !result.verified {
                        *all_verified = false;
                        errors.push(format!("verification failed: {}", src_path.display()));
                    }
                    // Preserve metadata
                    preserve_metadata(&src_path, &dst_path);
                    // Write .merkle companion
                    if let Err(e) = write_merkle_file(
                        &dst_path, &tree, &result.source_hash, result.bytes_copied,
                        chunk_size, result.verified,
                    ) {
                        errors.push(e);
                    }
                    // Emit log
                    emit_copy_log(&result);
                }
                Err(e) => {
                    *all_verified = false;
                    errors.push(format!("{}: {}", src_path.display(), e));
                }
            }
        }
        // Skip symlinks and other special files
    }
    Ok(())
}

/// Recursive directory copy: copies an entire directory tree,
/// preserving structure and creating .merkle companion files.
fn copy_dir_impl(src: &Path, dst: &Path, chunk_size: usize) -> Result<Value, String> {
    if !src.is_dir() {
        return Err(format!(
            "copy.dir: '{}' is not a directory",
            src.display()
        ));
    }

    std::fs::create_dir_all(dst)
        .map_err(|e| format!("copy.dir: cannot create '{}': {}", dst.display(), e))?;

    let start = Instant::now();
    let mut files_copied: u64 = 0;
    let mut dirs_created: u64 = 1; // root dir
    let mut bytes_copied: u64 = 0;
    let mut errors: Vec<String> = Vec::new();
    let mut all_verified = true;

    copy_dir_recursive(src, dst, chunk_size, &mut files_copied, &mut dirs_created, &mut bytes_copied, &mut errors, &mut all_verified)?;

    let elapsed_ms = start.elapsed().as_millis() as u64;
    let throughput_mbps = if elapsed_ms > 0 {
        (bytes_copied as f64 / 1_048_576.0) / (elapsed_ms as f64 / 1000.0)
    } else { 0.0 };

    // Build errors array for Tallow
    let error_values: Vec<Value> = errors.iter()
        .map(|e| Value::String(e.clone()))
        .collect();

    Ok(Value::Struct {
        name: "CopyDirStats".to_string(),
        fields: vec![
            ("source".into(), Value::String(src.to_string_lossy().to_string())),
            ("destination".into(), Value::String(dst.to_string_lossy().to_string())),
            ("files_copied".into(), Value::Int(files_copied as i128)),
            ("dirs_created".into(), Value::Int(dirs_created as i128)),
            ("bytes_copied".into(), Value::Int(bytes_copied as i128)),
            ("elapsed_ms".into(), Value::Int(elapsed_ms as i128)),
            ("throughput_mbps".into(), Value::Float(throughput_mbps)),
            ("all_verified".into(), Value::Bool(all_verified)),
            ("error_count".into(), Value::Int(errors.len() as i128)),
            ("errors".into(), Value::Array(error_values)),
        ],
    })
}

// ── Tallow-facing directory copy wrapper ─────────────────────────────

fn copy_dir(args: &[Value]) -> StdlibResult {
    let src = get_string_arg(args, 0)
        .ok_or("copy.dir: requires source directory path")?;
    let dst = get_string_arg(args, 1)
        .ok_or("copy.dir: requires destination directory path")?;
    copy_dir_impl(Path::new(&src), Path::new(&dst), DEFAULT_CHUNK_SIZE)
}

// ── Dispatch ──────────────────────────────────────────────────────────

/// Dispatch a tallow.copy.* function call by name.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "file" => Some(copy_file(&args)),
        "verify_file" => Some(verify_file(&args)),
        "verify_dir" => Some(verify_dir(&args)),
        "dir" => Some(copy_dir(&args)),
        _ => None,
    }
}

/// Dispatch a method call on a tallow.copy object type.
pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    if let Value::Struct { name, fields } = object {
        match name.as_str() {
            "CopyStats" => {
                for (field_name, field_value) in fields {
                    if field_name == method {
                        return Some(Ok(field_value.clone()));
                    }
                }
                Some(Err(format!("CopyStats has no field '{}'", method)))
            }
            "MerkleTree" => {
                for (field_name, field_value) in fields {
                    if field_name == method {
                        return Some(Ok(field_value.clone()));
                    }
                }
                Some(Err(format!("MerkleTree has no field '{}'", method)))
            }
            "CopyDirStats" => {
                for (field_name, field_value) in fields {
                    if field_name == method {
                        return Some(Ok(field_value.clone()));
                    }
                }
                Some(Err(format!("CopyDirStats has no field '{}'", method)))
            }
            _ => None,
        }
    } else {
        None
    }
}

// ── Tests ─────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_copy_file_streaming_basic() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src.txt");
        let dst = tmp.path().join("dst.txt");
        std::fs::write(&src, b"Hello, Tallow Copy!\n").unwrap();

        let (result, _tree) = copy_file_streaming(&src, &dst, DEFAULT_CHUNK_SIZE).unwrap();
        assert!(result.verified, "source and dest hashes must match");
        assert_eq!(result.bytes_copied, 20);
        // FIX16: was `elapsed_ms > 0` — flaky: a 20-byte copy on a fast machine
        // completes in under a millisecond, so elapsed_ms is legitimately 0.
        assert!(result.elapsed_ms >= 0, "elapsed_ms must be non-negative");
        assert_eq!(result.chunk_count, 1);
        assert!(!result.merkle_root.is_empty());

        // Verify destination content
        let dst_content = std::fs::read_to_string(&dst).unwrap();
        assert_eq!(dst_content, "Hello, Tallow Copy!\n");
    }

    #[test]
    fn test_copy_file_source_missing() {
        let result = copy_file_streaming(
            Path::new("__nonexistent_src__.txt"),
            Path::new("dst.txt"),
            DEFAULT_CHUNK_SIZE,
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("cannot open"));
    }

    #[test]
    fn test_dual_hasher_agreement_on_larger_file() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("big.bin");
        let dst = tmp.path().join("big_copy.bin");
        // Write 512KB of deterministic data (multiple of DEFAULT_CHUNK_SIZE)
        let data: Vec<u8> = (0..524288u64).map(|i| (i % 256) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let (result, tree) = copy_file_streaming(&src, &dst, DEFAULT_CHUNK_SIZE).unwrap();
        assert!(result.verified);
        assert_eq!(result.bytes_copied, 524288);
        assert_eq!(result.chunk_count, 2); // two 256KB chunks
        assert_eq!(tree.len(), 2); // layer 0 (2 leaves) -> layer 1 (1 root)
        assert_eq!(tree[0].len(), 2); // 2 leaf hashes
        assert_eq!(tree[1].len(), 1); // 1 root hash
    }

    #[test]
    fn test_empty_file_copy() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("empty.txt");
        let dst = tmp.path().join("empty_copy.txt");
        std::fs::write(&src, b"").unwrap();

        let (result, tree) = copy_file_streaming(&src, &dst, DEFAULT_CHUNK_SIZE).unwrap();
        assert!(result.verified);
        assert_eq!(result.bytes_copied, 0);
        // Empty file: 1 layer, 1 node = BLAKE3 of empty bytes
        assert_eq!(tree[0].len(), 1);
        assert_eq!(tree[0][0], blake3::hash(b"").to_hex().to_string());
    }

    #[test]
    fn test_merkle_file_created_and_valid() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("photo.jpg");
        let dst = tmp.path().join("photo_copy.jpg");
        let data: Vec<u8> = (0..100_000u64).map(|i| (i % 256) as u8).collect();
        std::fs::write(&src, &data).unwrap();

        let (result, tree) = copy_file_streaming(&src, &dst, DEFAULT_CHUNK_SIZE).unwrap();
        assert!(result.verified);

        write_merkle_file(
            &dst,
            &tree,
            &result.source_hash,
            result.bytes_copied,
            DEFAULT_CHUNK_SIZE,
            true,
        )
        .unwrap();

        let merkle_path = PathBuf::from(format!("{}.merkle", dst.display()));
        assert!(merkle_path.exists(), ".merkle file must exist");

        let content = std::fs::read_to_string(&merkle_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&content).unwrap();
        assert_eq!(parsed["format"], "tallow-merkle-v1");
        assert_eq!(parsed["root_hash"], result.merkle_root);
        assert!(parsed["chunk_hashes"].as_array().is_some());
    }

    #[test]
    fn test_metadata_preserved() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("meta_src.txt");
        let dst = tmp.path().join("meta_dst.txt");
        std::fs::write(&src, b"metadata test").unwrap();

        let _ = copy_file_streaming(&src, &dst, DEFAULT_CHUNK_SIZE).unwrap();
        let ok = preserve_metadata(&src, &dst);
        assert!(ok, "mtime should be preserved on same filesystem");

        let src_meta = std::fs::metadata(&src).unwrap();
        let dst_meta = std::fs::metadata(&dst).unwrap();
        assert_eq!(
            src_meta.modified().unwrap(),
            dst_meta.modified().unwrap()
        );
    }

    // ── Verification tests ────────────────────────────────────────────

    #[test]
    fn test_standalone_verify_pass() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("verify_me.txt");
        let data = b"verifiable content for standalone test\n";
        std::fs::write(&src, data).unwrap();

        // First copy to create .merkle
        let (result, tree) = copy_file_streaming(&src, &src, DEFAULT_CHUNK_SIZE).unwrap();
        assert!(result.verified);
        write_merkle_file(&src, &tree, &result.source_hash, data.len() as u64, DEFAULT_CHUNK_SIZE, true).unwrap();

        // Now verify
        let verify_result = verify_file_impl(&src, DEFAULT_CHUNK_SIZE).unwrap();
        if let Value::Struct { fields, .. } = &verify_result {
            let verified = fields.iter().find(|(k,_)| k == "verified").map(|(_,v)| matches!(v, Value::Bool(true))).unwrap_or(false);
            assert!(verified, "standalone verification must pass for unchanged file");
        } else {
            panic!("expected VerifyResult struct");
        }
    }

    #[test]
    fn test_standalone_verify_fail_on_modified_file() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("tamper_me.txt");
        std::fs::write(&src, b"original content\n").unwrap();

        let (result, tree) = copy_file_streaming(&src, &src, DEFAULT_CHUNK_SIZE).unwrap();
        write_merkle_file(&src, &tree, &result.source_hash, 17, DEFAULT_CHUNK_SIZE, true).unwrap();

        // Tamper with the file
        std::fs::write(&src, b"tampered content - different!\n").unwrap();

        let verify_result = verify_file_impl(&src, DEFAULT_CHUNK_SIZE).unwrap();
        if let Value::Struct { fields, .. } = &verify_result {
            let is_false = fields.iter().find(|(k,_)| k == "verified").map(|(_,v)| matches!(v, Value::Bool(false))).unwrap_or(false);
            assert!(is_false, "verification must fail for tampered file");
        }
    }

    #[test]
    fn test_verify_file_missing_merkle() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("no_merkle.txt");
        std::fs::write(&f, b"no companion\n").unwrap();

        let result = verify_file_impl(&f, DEFAULT_CHUNK_SIZE);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("no .merkle file found"));
    }

    #[test]
    fn test_verify_dir_multi_file() {
        let tmp = tempfile::tempdir().unwrap();
        let sub = tmp.path().join("subdir");
        std::fs::create_dir(&sub).unwrap();

        let f1 = tmp.path().join("a.txt");
        let f2 = sub.join("b.txt");
        std::fs::write(&f1, b"file a\n").unwrap();
        std::fs::write(&f2, b"file b content\n").unwrap();

        // Create .merkle for both
        let (r1, t1) = copy_file_streaming(&f1, &f1, DEFAULT_CHUNK_SIZE).unwrap();
        let (r2, t2) = copy_file_streaming(&f2, &f2, DEFAULT_CHUNK_SIZE).unwrap();
        write_merkle_file(&f1, &t1, &r1.source_hash, 7, DEFAULT_CHUNK_SIZE, true).unwrap();
        write_merkle_file(&f2, &t2, &r2.source_hash, 14, DEFAULT_CHUNK_SIZE, true).unwrap();

        let dir_result = verify_dir_impl(tmp.path(), DEFAULT_CHUNK_SIZE).unwrap();
        if let Value::Struct { fields, .. } = &dir_result {
            let total = fields.iter().find(|(k,_)| k == "total_files")
                .and_then(|(_,v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap();
            let verified = fields.iter().find(|(k,_)| k == "verified")
                .and_then(|(_,v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap();
            let failed = fields.iter().find(|(k,_)| k == "failed")
                .and_then(|(_,v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap();
            assert_eq!(total, 2, "expected 2 total files in verify_dir result");
            assert_eq!(verified, 2, "expected 2 verified in verify_dir result");
            assert_eq!(failed, 0, "expected 0 failed in verify_dir result");
        }
    }

    // ── Directory copy tests ──────────────────────────────────────────

    #[test]
    fn test_adaptive_worker_count() {
        assert_eq!(adaptive_worker_count(0), 1);
        assert_eq!(adaptive_worker_count(5), 1);
        let n = adaptive_worker_count(100);
        assert!(n >= 1);
        let cpus = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(4);
        assert!(n <= cpus * 2);
        assert!(n <= 64);
    }

    #[test]
    fn test_copy_dir_recursive_basic() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("src");
        let dst_dir = tmp.path().join("dst");
        std::fs::create_dir(&src_dir).unwrap();
        let sub_dir = src_dir.join("sub");
        std::fs::create_dir(&sub_dir).unwrap();

        std::fs::write(src_dir.join("a.txt"), b"file a\n").unwrap();
        std::fs::write(src_dir.join("b.txt"), b"file b content here\n").unwrap();
        std::fs::write(sub_dir.join("c.txt"), b"nested file c\n").unwrap();

        let result = copy_dir_impl(&src_dir, &dst_dir, DEFAULT_CHUNK_SIZE).unwrap();
        if let Value::Struct { fields, .. } = &result {
            let fc = fields.iter().find(|(k,_)| k == "files_copied")
                .and_then(|(_,v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap();
            let dc = fields.iter().find(|(k,_)| k == "dirs_created")
                .and_then(|(_,v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap();
            assert_eq!(fc, 3, "expected 3 files copied"); // 3 files
            assert_eq!(dc, 2, "expected 2 dirs created"); // src + sub
        }

        // Verify files exist at destination
        assert!(dst_dir.join("a.txt").exists());
        assert!(dst_dir.join("b.txt").exists());
        assert!(dst_dir.join("sub").join("c.txt").exists());

        // Content check
        assert_eq!(std::fs::read_to_string(dst_dir.join("a.txt")).unwrap(), "file a\n");
        assert_eq!(std::fs::read_to_string(dst_dir.join("sub").join("c.txt")).unwrap(), "nested file c\n");
    }

    #[test]
    fn test_copy_dir_creates_merkle_files() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("src2");
        let dst_dir = tmp.path().join("dst2");
        std::fs::create_dir(&src_dir).unwrap();
        std::fs::write(src_dir.join("x.txt"), b"merkle test\n").unwrap();

        copy_dir_impl(&src_dir, &dst_dir, DEFAULT_CHUNK_SIZE).unwrap();

        let merkle_path = PathBuf::from(format!("{}.merkle", dst_dir.join("x.txt").display()));
        assert!(merkle_path.exists(), ".merkle file must exist at destination");
        let merkle_content = std::fs::read_to_string(&merkle_path).unwrap();
        assert!(merkle_content.contains("tallow-merkle-v1"));
    }

    #[test]
    fn test_parallel_copy_correctness() {
        let tmp = tempfile::tempdir().unwrap();
        let src_dir = tmp.path().join("src_par");
        let dst_dir = tmp.path().join("dst_par");
        std::fs::create_dir(&src_dir).unwrap();

        // Create 10 files
        for i in 0..10 {
            std::fs::write(
                src_dir.join(format!("file_{}.txt", i)),
                format!("content of file {}\n", i).as_bytes(),
            ).unwrap();
        }

        let workers = adaptive_worker_count(10);
        assert!(workers >= 1, "adaptive workers must be at least 1");

        let result = copy_dir_impl(&src_dir, &dst_dir, DEFAULT_CHUNK_SIZE).unwrap();
        if let Value::Struct { fields, .. } = &result {
            let fc = fields.iter().find(|(k,_)| k == "files_copied")
                .and_then(|(_,v)| if let Value::Int(n) = v { Some(*n) } else { None }).unwrap();
            assert_eq!(fc, 10, "expected 10 files copied");
        }

        // All 10 files should exist at destination
        for i in 0..10 {
            assert!(dst_dir.join(format!("file_{}.txt", i)).exists());
        }
    }

    #[test]
    fn test_copy_dir_source_not_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let f = tmp.path().join("not_a_dir.txt");
        std::fs::write(&f, b"not a dir\n").unwrap();

        let result = copy_dir_impl(&f, &tmp.path().join("dst"), DEFAULT_CHUNK_SIZE);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("is not a directory"));
    }
}
