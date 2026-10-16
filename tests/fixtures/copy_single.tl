// Test: Single file copy with tallow.copy
import tallow.copy

let result = copy.file("E:/nixe/tests/fixtures/hello.tl", "E:/nixe/tests/fixtures/copy_hello.tl")

// Verify the CopyStats struct fields are accessible
assert(result.verified, "copy must verify successfully")
assert(result.bytes_copied > 0, "must copy some bytes")
assert(result.source_hash != "", "source hash must not be empty")
assert(result.destination_hash != "", "destination hash must not be empty")
assert(result.elapsed_ms >= 0, "elapsed must be non-negative")
assert(result.chunk_count > 0, "must have at least one chunk")
assert(result.merkle_root != "", "merkle root must not be empty")

log.info("copy_single.tl: PASS - copied " + result.bytes_copied + " bytes, verified=" + result.verified)
