// tallow.fs — Filesystem operations
//
// Provides safe file and directory operations with privacy-aware
// path handling. All write operations require can_write in agent context.

/// Read entire file contents as String.
///
/// Returns the bare string on both engines; a read FAILURE is a loud runtime
/// error (both engines), never an empty string or an `Err` value. This used to
/// be declared `Result<String>` while returning a bare String, which made
/// `if let Ok(c) = read_file(p)` silently never fire.
fn read_file(path: String) -> String {
    // native: reads file at path, returns UTF-8 string
}

/// Read file as raw bytes, as a Bytes value (not a String). A Bytes value
/// prints as its base64 encoding on both engines; hash the raw bytes with
/// provenance.hash_bytes, or call .base64() for the encoded form
fn read_bytes(path: String) -> Result<Bytes> {
    // native: reads file at path, returns raw bytes
}

/// Write string content to file (creates or overwrites)
fn write_file(path: String, content: String) -> Result<()> {
    // native: writes content to file
}

/// Write raw bytes to file
fn write_bytes(path: String, data: Bytes) -> Result<()> {
    // native: writes bytes to file
}

/// Append string to file
fn append_file(path: String, content: String) -> Result<()> {
    // native: appends content to end of file
}

/// Create a new file (error if exists)
fn create_file(path: String) -> Result<()> {
    // native: creates empty file
}

/// Delete a file
fn delete_file(path: String) -> Result<()> {
    // native: removes file at path
}

/// Check if path exists
fn exists(path: String) -> bool {
    // native: returns true if path exists
}

/// Check if path is a file
fn is_file(path: String) -> bool {
    // native: returns true if path is a regular file
}

/// Check if path is a directory
fn is_dir(path: String) -> bool {
    // native: returns true if path is a directory
}

/// Create directory (and parents)
fn mkdir(path: String) -> Result<()> {
    // native: creates directory recursively
}

/// Remove directory
fn remove_dir(path: String) -> Result<()> {
    // native: removes directory (must be empty)
}

/// Remove directory and all contents
fn remove_dir_all(path: String) -> Result<()> {
    // native: removes directory tree
}

/// List directory contents
fn list_dir(path: String) -> Result<[]String> {
    // native: returns file/dir names in directory
}

/// Copy file from src to dst
fn copy(src: String, dst: String) -> Result<()> {
    // native: copies file
}

/// Move/rename file
fn rename(src: String, dst: String) -> Result<()> {
    // native: moves/renames file
}

/// Get file size in bytes
fn file_size(path: String) -> Result<u64> {
    // native: returns file size
}

/// File metadata
struct FileInfo {
    path:     String,
    size:     u64,
    is_file:  bool,
    is_dir:   bool,
    modified: u64,      // unix timestamp
    created:  u64,
}

/// Get file metadata
fn stat(path: String) -> Result<FileInfo> {
    // native: returns file metadata
}

/// Read file line by line (lazy iterator)
fn read_lines(path: String) -> Result<[]String> {
    // native: reads file, splits by newline
}

/// Temporary file that auto-deletes on scope exit
fn temp_file() -> Result<String> {
    // native: creates temp file, returns path
}

/// Temporary directory that auto-deletes on scope exit
fn temp_dir() -> Result<String> {
    // native: creates temp directory, returns path
}
