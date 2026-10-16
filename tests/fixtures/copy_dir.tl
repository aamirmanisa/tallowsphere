// Test: Recursive directory copy with tallow.copy
// Copies a small directory tree and verifies the results
import tallow.copy
import tallow.fs

// Create a source directory with test files
fs.mkdir("E:/nixe/tests/fixtures/_copy_dir_src/subdir")

// Write some test content using fs.write or create files manually
// Since fs.write may not be available, use copy_dir on a known directory

// Copy the fixtures directory itself as a real-world test
let src = "E:/nixe/tests/fixtures"
let dst = "E:/nixe/tests/_copy_dir_output"

let stats = copy.dir(src, dst)

// Check CopyDirStats fields
assert(stats.files_copied > 0, "must copy at least some files")
assert(stats.dirs_created > 0, "must create at least some directories")
assert(stats.bytes_copied > 0, "must copy some bytes")
assert(stats.elapsed_ms >= 0, "elapsed must be non-negative")
assert(stats.all_verified == true, "all files must be verified")

log.info("copy_dir.tl: PASS - copied " + stats.files_copied + " files in " + stats.elapsed_ms + "ms")
log.info("copy_dir.tl: " + stats.dirs_created + " dirs, " + stats.bytes_copied + " bytes, verified=" + stats.all_verified)
