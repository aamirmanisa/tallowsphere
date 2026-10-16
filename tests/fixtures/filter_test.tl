// Test: File filtering with tallow.filter
// Exercises filter.file_info, glob matching, size checks, age checks,
// attribute checks, predicate evaluation, and filter profiles.
import tallow.filter
import tallow.fs
import tallow.time

// Use a known file: the fixture itself
let info = filter.file_info("E:/nixe/tests/fixtures/filter_test.tl")

// Check FilterFileInfo fields
assert(info.size > 0, "file must have non-zero size")
assert(info.name == "filter_test.tl", "name must match filename")
assert(info.is_file == true, "must be a file, not a directory")
assert(info.is_dir == false, "must not be a directory")
assert(info.modified_at > 0, "must have valid modification timestamp")

// Glob pattern matching
assert(filter.matches("document.txt", "*.txt") == true, "glob *.txt must match")
assert(filter.matches("document.txt", "*.log") == false, "glob *.log must not match")
assert(filter.matches("file123.csv", "file???.csv") == true, "glob ? must match single char")
assert(filter.matches("src/main.rs", "src/*.rs") == true, "glob * must match path segment")

// Size checks
assert(filter.size_gt("E:/nixe/tests/fixtures/filter_test.tl", 0) == true, "file exceeds 0 bytes")
assert(filter.size_lt("E:/nixe/tests/fixtures/filter_test.tl", 1000000000) == true, "file under 1GB")

// Age checks
assert(filter.age_gt("E:/nixe/tests/fixtures/filter_test.tl", 0) == true, "file older than 0 seconds")

// Attribute checks
assert(filter.is_hidden("E:/nixe/tests/fixtures/filter_test.tl") == false, "test fixture not hidden")

// Build predicates for profile
let big_file = filter.size_gt_pred(100)
let is_tl = filter.matches_pred("*.tl")

// Register a filter profile
let profile = filter.profile("tallow-sources", [big_file, is_tl])
assert(profile.name == "tallow-sources", "profile name must match")
assert(profile.predicate_count == 2, "profile must have 2 predicates")

// Retrieve and list profiles
let retrieved = filter.profile_get("tallow-sources")
assert(retrieved.name == "tallow-sources", "retrieved profile must match")
let profiles = filter.profile_list()
// profiles is an array of strings; check it contains our profile
let found = false
for name in profiles {
    if name == "tallow-sources" {
        found = true
    }
}
assert(found == true, "profile list must contain tallow-sources")

// Evaluate profile against a file
let result = filter.eval_profile("E:/nixe/tests/fixtures/filter_test.tl", "tallow-sources")
assert(result.matched == true, "tallow-sources profile must match a .tl file")
assert(result.matched_count == 2, "both predicates must match")

// Evaluate directly with predicates
let eval_result = filter.eval("E:/nixe/tests/fixtures/filter_test.tl", [big_file, is_tl])
assert(eval_result.matched == true, "direct eval must match")

log.info("filter_test.tl: PASS — all filter checks passed")
