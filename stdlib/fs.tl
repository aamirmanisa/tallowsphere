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
// native: reads file at path, returns UTF-8 string
native fn read_file(path: String) -> String

/// Read file as raw bytes, as a Bytes value (not a String). A Bytes value
/// prints as its base64 encoding on both engines; hash the raw bytes with
/// provenance.hash_bytes, or call .base64() for the encoded form
// native: reads file at path, returns raw bytes
native fn read_bytes(path: String) -> Result<Bytes>

/// Write string content to file (creates or overwrites)
// native: writes content to file
native fn write_file(path: String, content: String) -> Result<()>

/// Write raw bytes to file
// native: writes bytes to file
native fn write_bytes(path: String, data: Bytes) -> Result<()>

/// Append string to file
// native: appends content to end of file
native fn append_file(path: String, content: String) -> Result<()>

/// Create a new file (error if exists)
// native: creates empty file
native fn create_file(path: String) -> Result<()>

/// Delete a file
// native: removes file at path
native fn delete_file(path: String) -> Result<()>

/// Check if path exists
// native: returns true if path exists
native fn exists(path: String) -> bool

/// Check if path is a file
// native: returns true if path is a regular file
native fn is_file(path: String) -> bool

/// Check if path is a directory
// native: returns true if path is a directory
native fn is_dir(path: String) -> bool

/// Create directory (and parents)
// native: creates directory recursively
native fn mkdir(path: String) -> Result<()>

/// Remove directory
// native: removes directory (must be empty)
native fn remove_dir(path: String) -> Result<()>

/// Remove directory and all contents
// native: removes directory tree
native fn remove_dir_all(path: String) -> Result<()>

/// List directory contents
// native: returns file/dir names in directory
native fn list_dir(path: String) -> Result<[]String>

/// Copy file from src to dst
// native: copies file
native fn copy(src: String, dst: String) -> Result<()>

/// Move/rename file
// native: moves/renames file
native fn rename(src: String, dst: String) -> Result<()>

/// Get file size in bytes
// native: returns file size
native fn file_size(path: String) -> Result<u64>

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
// native: returns file metadata
native fn stat(path: String) -> Result<FileInfo>

/// Read file line by line (lazy iterator)
// native: reads file, splits by newline
native fn read_lines(path: String) -> Result<[]String>

/// Temporary file that auto-deletes on scope exit
// native: creates temp file, returns path
native fn temp_file() -> Result<String>

/// Temporary directory that auto-deletes on scope exit
// native: creates temp directory, returns path
native fn temp_dir() -> Result<String>
