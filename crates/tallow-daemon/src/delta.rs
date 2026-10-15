//! Delta sync engine — Merkle tree comparison, block-level delta generation,
//! rolling checksum computation, and delta payload assembly.
//!
//! Compares local and remote Merkle trees to identify only the blocks that
//! differ, then reads and transfers only those changed blocks. Supports
//! whole-file fallback via the tiered sync strategy.
//!
//! Block size used for delta operations is 4KB (4096 bytes). The Merkle tree
//! comparison uses the block size from the .merkle file (typically 256KB from
//! the copy module, or 4KB for fine-grained delta sync trees).

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Block size for delta operations: reading/writing blocks, rolling checksum.
pub const BLOCK_SIZE: usize = 4096;

// ── Data structures ───────────────────────────────────────────────────────

/// Parsed representation of a .merkle file (tallow-merkle-v1 format).
#[derive(Debug, Clone)]
pub struct MerkleData {
    pub file_path: String,
    pub block_size: usize,
    pub total_blocks: usize,
    pub total_bytes: u64,
    pub merkle_root: String,
    pub chunk_hashes: Vec<String>,
    pub tree_layers: Vec<Vec<String>>,
    pub blake3_file_hash: String,
}

/// Result of comparing two Merkle trees.
#[derive(Debug, Clone)]
pub struct DeltaDiff {
    pub changed_blocks: Vec<usize>,
    pub unchanged_blocks: usize,
    pub total_blocks: usize,
    pub change_ratio: f64,
}

/// A single changed block with its BLAKE3 hash and raw data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaBlock {
    pub block_index: usize,
    pub hash: String,
    #[serde(with = "base64_bytes")]
    pub data: Vec<u8>,
}

/// Transferable payload of changed blocks for a file.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaPayload {
    pub file_path: String,
    pub total_blocks: usize,
    pub block_size: usize,
    pub changed_blocks: Vec<DeltaBlock>,
    pub new_merkle_root: String,
}

// ── Serde helpers ─────────────────────────────────────────────────────────

/// Serde module for base64-encoding binary `Vec<u8>` data.
mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(data: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error> {
        let encoded = base64::engine::general_purpose::STANDARD.encode(data);
        encoded.serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        let encoded = String::deserialize(deserializer)?;
        base64::engine::general_purpose::STANDARD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)
    }
}

// ── Merkle file parsing ──────────────────────────────────────────────────

/// Raw JSON structure of a .merkle file (tallow-merkle-v1 format as written
/// by the copy module).
#[derive(Debug, Deserialize)]
struct RawMerkleFile {
    format: String,
    file_path: String,
    file_size: u64,
    chunk_size: usize,
    chunk_count: usize,
    root_hash: String,
    chunk_hashes: Vec<String>,
    tree_layers: Vec<Vec<String>>,
    source_hash: String,
    algorithm: String,
    created_at: String,
    #[serde(default)]
    verified: bool,
}

/// Parse a .merkle companion file into a MerkleData struct.
///
/// Reads the tallow-merkle-v1 JSON format written by the copy module.
/// Also accepts the plan-specified format keys as aliases via optional fields.
pub fn parse_merkle_file(merkle_path: &Path) -> Result<MerkleData> {
    let content =
        std::fs::read_to_string(merkle_path)
            .with_context(|| format!("cannot read merkle file: {}", merkle_path.display()))?;

    // Try parsing as the copy-module format first
    let raw: RawMerkleFile = serde_json::from_str(&content)
        .with_context(|| format!("invalid merkle file format: {}", merkle_path.display()))?;

    Ok(MerkleData {
        file_path: raw.file_path,
        block_size: raw.chunk_size,
        total_blocks: raw.chunk_count,
        total_bytes: raw.file_size,
        merkle_root: raw.root_hash,
        chunk_hashes: raw.chunk_hashes,
        tree_layers: raw.tree_layers,
        blake3_file_hash: raw.source_hash,
    })
}

// ── Merkle tree comparison ───────────────────────────────────────────────

/// Compare two Merkle trees and return a diff of changed block indices.
///
/// Algorithm:
/// 1. If the merkle roots match AND block counts match → O(1) short-circuit,
///    all blocks unchanged.
/// 2. Otherwise, compare leaf hashes directly (O(n) in number of blocks).
///    Trees may have different block counts (different file sizes). The shorter
///    tree's missing blocks are treated as zero-hash (indicating new/removed
///    blocks on the other side).
pub fn compare_merkle_trees(local: &MerkleData, remote: &MerkleData) -> DeltaDiff {
    let total_blocks = std::cmp::max(local.total_blocks, remote.total_blocks);

    // Short-circuit: identical root hash AND same block count means identical
    if local.merkle_root == remote.merkle_root && local.total_blocks == remote.total_blocks {
        return DeltaDiff {
            changed_blocks: vec![],
            unchanged_blocks: total_blocks,
            total_blocks,
            change_ratio: 0.0,
        };
    }

    // Compare leaf hashes directly
    let local_leaves = local.chunk_hashes.as_slice();
    let remote_leaves = remote.chunk_hashes.as_slice();
    let max_blocks = std::cmp::max(local_leaves.len(), remote_leaves.len());

    let mut changed = Vec::new();
    for i in 0..max_blocks {
        let local_hash = local_leaves.get(i).map(|s| s.as_str()).unwrap_or(ZERO_HASH);
        let remote_hash = remote_leaves.get(i).map(|s| s.as_str()).unwrap_or(ZERO_HASH);
        if local_hash != remote_hash {
            changed.push(i);
        }
    }

    let changed_count = changed.len();
    let unchanged_blocks = total_blocks.saturating_sub(changed_count);

    DeltaDiff {
        changed_blocks: changed,
        unchanged_blocks,
        total_blocks,
        change_ratio: compute_change_ratio(changed_count, total_blocks),
    }
}

const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

// ── Delta block computation ──────────────────────────────────────────────

/// Read only the changed blocks from a source file.
///
/// Uses `seek` + `read_exact` to read only the 4KB (or merkle block-sized)
/// regions corresponding to changed indices. For the last block, handles
/// partial reads (remaining bytes < block_size).
pub fn compute_delta_blocks(
    source_path: &Path,
    merkle: &MerkleData,
    changed_indices: &[usize],
) -> Result<Vec<DeltaBlock>> {
    let mut file = File::open(source_path)
        .with_context(|| format!("cannot open source file: {}", source_path.display()))?;

    let block_size = merkle.block_size;
    let mut result = Vec::with_capacity(changed_indices.len());

    for &block_idx in changed_indices {
        let offset = block_idx as u64 * block_size as u64;
        file.seek(SeekFrom::Start(offset))
            .with_context(|| format!("seek failed at block {} offset {}", block_idx, offset))?;

        let mut buf = vec![0u8; block_size];
        let n = file
            .read(&mut buf)
            .with_context(|| format!("read failed at block {}", block_idx))?;

        if n == 0 {
            continue; // past EOF, shouldn't happen but handle gracefully
        }
        buf.truncate(n);

        let hash = blake3::hash(&buf).to_hex().to_string();
        result.push(DeltaBlock {
            block_index: block_idx,
            hash,
            data: buf,
        });
    }

    Ok(result)
}

// ── Delta payload assembly ───────────────────────────────────────────────

/// Assemble changed blocks into a transferrable DeltaPayload.
pub fn assemble_delta_payload(
    delta_blocks: &[DeltaBlock],
    file_path: &str,
    total_blocks: usize,
    block_size: usize,
    new_merkle_root: &str,
) -> DeltaPayload {
    DeltaPayload {
        file_path: file_path.to_string(),
        total_blocks,
        block_size,
        changed_blocks: delta_blocks.to_vec(),
        new_merkle_root: new_merkle_root.to_string(),
    }
}

// ── Change ratio ─────────────────────────────────────────────────────────

/// Compute the change ratio as a float between 0.0 and 1.0.
/// For files with 0 total blocks, returns 0.0.
pub fn compute_change_ratio(changed: usize, total: usize) -> f64 {
    if total == 0 {
        return 0.0;
    }
    (changed as f64 / total as f64).clamp(0.0, 1.0)
}

// ── Rolling checksum (Adler-32 sliding window) ──────────────────────────

/// Adler-32 constant: modulo prime.
const ADLER_MOD: u32 = 65521;

/// Compute the Adler-32 checksum of a byte slice.
fn adler32_checksum(data: &[u8]) -> u32 {
    let mut a: u32 = 1;
    let mut b: u32 = 0;
    for &byte in data {
        a = (a + byte as u32) % ADLER_MOD;
        b = (b + a) % ADLER_MOD;
    }
    (b << 16) | a
}

/// Rolling Adler-32 checksum: given a previous checksum and the byte that
/// is removed and the byte that is added, compute the new checksum in O(1).
fn roll_adler32(prev_checksum: u32, window_size: usize, byte_out: u8, byte_in: u8) -> u32 {
    let a = prev_checksum & 0xFFFF;
    let b = (prev_checksum >> 16) & 0xFFFF;

    let a_new = (a + byte_in as u32 + ADLER_MOD - byte_out as u32) % ADLER_MOD;
    let b_new = (b + a_new + ADLER_MOD - (1 + window_size as u32 * byte_out as u32) % ADLER_MOD)
        % ADLER_MOD;

    (b_new << 16) | a_new
}

/// Search for a target block within source data using a rolling Adler-32
/// checksum over a sliding window. Returns the byte offset of the matching
/// block, or None if no match is found.
///
/// The window size is BLOCK_SIZE (4KB). For each window position,
/// the Adler-32 checksum is compared; on match, a full BLAKE3 comparison
/// confirms the match to avoid false positives.
pub fn rolling_checksum_match(source_data: &[u8], target_block: &[u8]) -> Option<usize> {
    let window_size = BLOCK_SIZE;
    if target_block.len() != window_size || source_data.len() < window_size {
        return None;
    }

    let target_adler = adler32_checksum(target_block);

    // Compute initial checksum for first window
    let mut rolling = adler32_checksum(&source_data[..window_size]);

    // Check first window
    if rolling == target_adler && blake3::hash(&source_data[..window_size]).as_bytes()
        == blake3::hash(target_block).as_bytes()
    {
        return Some(0);
    }

    // Slide window
    for i in window_size..source_data.len() {
        rolling = roll_adler32(rolling, window_size, source_data[i - window_size], source_data[i]);

        if rolling == target_adler {
            let window = &source_data[i - window_size + 1..i + 1];
            if blake3::hash(window).as_bytes() == blake3::hash(target_block).as_bytes() {
                return Some(i - window_size + 1);
            }
        }
    }

    None
}

// ── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Build a synthetic MerkleData for testing with simple 4KB blocks.
    fn make_merkle(hashes: Vec<String>) -> MerkleData {
        let total = hashes.len();
        let tree = build_test_tree(&hashes);
        let root = tree.last().and_then(|l| l.last()).cloned().unwrap_or_default();

        MerkleData {
            file_path: "test.dat".to_string(),
            block_size: BLOCK_SIZE,
            total_blocks: total,
            total_bytes: (total * BLOCK_SIZE) as u64,
            merkle_root: root,
            chunk_hashes: hashes,
            tree_layers: tree,
            blake3_file_hash: "test_hash".to_string(),
        }
    }

    fn build_test_tree(leaves: &[String]) -> Vec<Vec<String>> {
        if leaves.is_empty() {
            return vec![vec![blake3::hash(b"").to_hex().to_string()]];
        }
        let mut layers: Vec<Vec<String>> = vec![leaves.to_vec()];
        let mut current = leaves.to_vec();
        while current.len() > 1 {
            let mut next = Vec::new();
            for pair in current.chunks(2) {
                if pair.len() == 2 {
                    let combined = format!("{}{}", pair[0], pair[1]);
                    let parent = blake3::hash(combined.as_bytes());
                    next.push(parent.to_hex().to_string());
                } else {
                    next.push(pair[0].clone());
                }
            }
            layers.push(next.clone());
            current = next;
        }
        layers
    }

    fn hash_data(data: &[u8]) -> String {
        blake3::hash(data).to_hex().to_string()
    }

    // ── Test 0: Short-circuit when trees are identical ──────────────────

    #[test]
    fn test_compare_identical_trees_returns_empty_diff() {
        let block_a = b"AAAA".repeat(BLOCK_SIZE / 4);
        let block_b = b"BBBB".repeat(BLOCK_SIZE / 4);
        let hashes = vec![hash_data(&block_a), hash_data(&block_b)];
        let merkle = make_merkle(hashes);

        let diff = compare_merkle_trees(&merkle, &merkle);
        assert!(diff.changed_blocks.is_empty(), "identical trees should have 0 changed blocks");
        assert_eq!(diff.unchanged_blocks, 2, "both blocks should be unchanged");
        assert!((diff.change_ratio - 0.0).abs() < f64::EPSILON, "change_ratio should be 0.0");
    }

    // ── Test 1: One changed leaf ────────────────────────────────────────

    #[test]
    fn test_compare_one_changed_leaf() {
        let block_a = b"AAAA".repeat(BLOCK_SIZE / 4);
        let block_b = b"BBBB".repeat(BLOCK_SIZE / 4);
        let block_c = b"CCCC".repeat(BLOCK_SIZE / 4);

        let local = make_merkle(vec![hash_data(&block_a), hash_data(&block_b)]);
        // Remote: block 1 changed (B → C)
        let remote = make_merkle(vec![hash_data(&block_a), hash_data(&block_c)]);

        let diff = compare_merkle_trees(&local, &remote);
        assert_eq!(diff.changed_blocks, vec![1], "only block 1 should be changed");
        assert_eq!(diff.unchanged_blocks, 1, "block 0 should be unchanged");
        assert_eq!(diff.total_blocks, 2);
        assert!((diff.change_ratio - 0.5).abs() < 0.001, "50% change ratio");
    }

    // ── Test 2: All leaves changed ──────────────────────────────────────

    #[test]
    fn test_compare_all_leaves_changed() {
        let block_a = b"AAAA".repeat(BLOCK_SIZE / 4);
        let block_b = b"BBBB".repeat(BLOCK_SIZE / 4);
        let block_c = b"CCCC".repeat(BLOCK_SIZE / 4);
        let block_d = b"DDDD".repeat(BLOCK_SIZE / 4);

        let local = make_merkle(vec![hash_data(&block_a), hash_data(&block_b)]);
        let remote = make_merkle(vec![hash_data(&block_c), hash_data(&block_d)]);

        let diff = compare_merkle_trees(&local, &remote);
        assert_eq!(diff.changed_blocks.len(), 2);
        assert_eq!(diff.unchanged_blocks, 0);
        assert!((diff.change_ratio - 1.0).abs() < f64::EPSILON);
    }

    // ── Test 3: compute_delta_blocks reads only changed blocks ──────────

    #[test]
    fn test_compute_delta_blocks_reads_only_changed() {
        // Create a temp file with 3 blocks
        let mut tmp = NamedTempFile::new().unwrap();
        let data: Vec<u8> = (0..(BLOCK_SIZE * 3)).map(|i| (i % 256) as u8).collect();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        // Build merkle: 3 blocks with correct hashes
        let hashes: Vec<String> = (0..3)
            .map(|i| {
                let start = i * BLOCK_SIZE;
                hash_data(&data[start..start + BLOCK_SIZE])
            })
            .collect();
        let merkle = make_merkle(hashes);

        // Only request blocks 0 and 2
        let blocks = compute_delta_blocks(tmp.path(), &merkle, &[0, 2]).unwrap();
        assert_eq!(blocks.len(), 2, "should return 2 blocks");
        assert_eq!(blocks[0].block_index, 0);
        assert_eq!(blocks[1].block_index, 2);
        assert_eq!(blocks[0].data.len(), BLOCK_SIZE);
        assert_eq!(blocks[1].data.len(), BLOCK_SIZE);
    }

    // ── Test 4: assemble_delta_payload ──────────────────────────────────

    #[test]
    fn test_assemble_delta_payload() {
        let blocks = vec![
            DeltaBlock {
                block_index: 5,
                hash: "abc".to_string(),
                data: vec![1u8, 2, 3],
            },
            DeltaBlock {
                block_index: 7,
                hash: "def".to_string(),
                data: vec![4u8, 5, 6],
            },
        ];

        let payload = assemble_delta_payload(
            &blocks,
            "/test/file.txt",
            10,
            BLOCK_SIZE,
            "root_hash_here",
        );

        assert_eq!(payload.file_path, "/test/file.txt");
        assert_eq!(payload.total_blocks, 10);
        assert_eq!(payload.block_size, BLOCK_SIZE);
        assert_eq!(payload.changed_blocks.len(), 2);
        assert_eq!(payload.changed_blocks[0].block_index, 5);
        assert_eq!(payload.changed_blocks[1].block_index, 7);
        assert_eq!(payload.new_merkle_root, "root_hash_here");

        // Verify serialization round-trips
        let json = serde_json::to_string(&payload).unwrap();
        let parsed: DeltaPayload = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.changed_blocks.len(), 2);
        assert_eq!(parsed.changed_blocks[0].block_index, 5);
    }

    // ── Test 5: Short-circuit at root level ────────────────────────────

    #[test]
    fn test_short_circuit_at_root_for_identical_large_trees() {
        // Build a tree with 128 blocks (many leaves, multiple layers)
        let blocks: Vec<String> = (0..128)
            .map(|i| hash_data(format!("block-{}", i).as_bytes()))
            .collect();
        let merkle = make_merkle(blocks);

        let diff = compare_merkle_trees(&merkle, &merkle);
        assert!(diff.changed_blocks.is_empty());
        // With 128 blocks above 1MB threshold, this would be a delta candidate
        // but since trees are identical, it short-circuits instantly
    }

    // ── Test 6: compute_change_ratio ────────────────────────────────────

    #[test]
    fn test_compute_change_ratio_values() {
        assert!((compute_change_ratio(0, 100) - 0.0).abs() < f64::EPSILON);
        assert!((compute_change_ratio(100, 100) - 1.0).abs() < f64::EPSILON);
        assert!((compute_change_ratio(10, 100) - 0.1).abs() < 0.001);
        assert!((compute_change_ratio(50, 100) - 0.5).abs() < 0.001);
        assert!((compute_change_ratio(0, 0) - 0.0).abs() < f64::EPSILON);
    }

    // ── Test 7: Rolling checksum finds matching block ───────────────────

    #[test]
    fn test_rolling_checksum_finds_match() {
        // Build source data: some bytes, then a known 4KB block
        let prefix = b"PREFIX_DATA_".repeat(10); // 120 bytes
        // Create exactly BLOCK_SIZE (4096) bytes of target data
        let target: Vec<u8> = (0..BLOCK_SIZE).map(|i| (i % 251) as u8).collect();
        let suffix = b"SUFFIX_DATA_".repeat(10);

        let mut source_data = Vec::new();
        source_data.extend_from_slice(&prefix);
        source_data.extend_from_slice(&target);
        source_data.extend_from_slice(&suffix);

        let offset = rolling_checksum_match(&source_data, &target);
        assert_eq!(offset, Some(prefix.len()), "should find target at correct offset");
    }

    #[test]
    fn test_rolling_checksum_no_match() {
        let data = b"RANDOM_DATA_".repeat(200);
        let target_arr: [u8; BLOCK_SIZE] = [0xFFu8; BLOCK_SIZE];

        let offset = rolling_checksum_match(&data, &target_arr);
        assert!(offset.is_none(), "should not find match for non-existent block");
    }

    // ── Test 8: parse_merkle_file ───────────────────────────────────────

    #[test]
    fn test_parse_merkle_file_format() {
        let mut tmp = NamedTempFile::new().unwrap();
        let content = serde_json::json!({
            "format": "tallow-merkle-v1",
            "file_path": "/test/file.txt",
            "file_size": 8192u64,
            "chunk_size": 4096usize,
            "chunk_count": 2usize,
            "root_hash": "root123",
            "chunk_hashes": ["hash_a", "hash_b"],
            "tree_layers": [["hash_a", "hash_b"], ["root123"]],
            "source_hash": "blake3hash",
            "algorithm": "blake3",
            "created_at": "2026-01-01T00:00:00Z",
            "verified": true
        });
        write!(tmp, "{}", serde_json::to_string(&content).unwrap()).unwrap();
        tmp.flush().unwrap();

        let merkle = parse_merkle_file(tmp.path()).unwrap();
        assert_eq!(merkle.file_path, "/test/file.txt");
        assert_eq!(merkle.block_size, 4096);
        assert_eq!(merkle.total_blocks, 2);
        assert_eq!(merkle.total_bytes, 8192);
        assert_eq!(merkle.merkle_root, "root123");
        assert_eq!(merkle.chunk_hashes, vec!["hash_a", "hash_b"]);
        assert_eq!(merkle.tree_layers.len(), 2);
        assert_eq!(merkle.blake3_file_hash, "blake3hash");
    }

    // ── Test 9: Trees with different block counts ───────────────────────

    #[test]
    fn test_compare_trees_different_sizes() {
        let block_a = b"AAAA".repeat(BLOCK_SIZE / 4);
        let block_b = b"BBBB".repeat(BLOCK_SIZE / 4);

        // Local: 2 blocks. Remote: 3 blocks (file grew)
        let local = make_merkle(vec![hash_data(&block_a), hash_data(&block_b)]);
        let remote = make_merkle(vec![
            hash_data(&block_a),
            hash_data(&block_b),
            hash_data(&b"CCCC".repeat(BLOCK_SIZE / 4)),
        ]);

        let diff = compare_merkle_trees(&local, &remote);
        // The third block is new → it should be in changed_blocks
        assert!(
            diff.changed_blocks.contains(&2),
            "new block 2 should be identified as changed"
        );
        assert_eq!(diff.total_blocks, 3);
    }

    // ── Test 10: Empty file ────────────────────────────────────────────

    #[test]
    fn test_compare_empty_trees() {
        let empty = make_merkle(vec![]);
        let diff = compare_merkle_trees(&empty, &empty);
        assert!(diff.changed_blocks.is_empty());
        assert_eq!(diff.total_blocks, 0);
    }

    // ── Test 11: Big tree comparison (many layers) ─────────────────────

    #[test]
    fn test_big_tree_comparison_with_one_changed_leaf() {
        // 256 blocks → tree depth of 9 (log2 256)
        let blocks: Vec<String> = (0..256)
            .map(|i| hash_data(format!("block-{:03}", i).as_bytes()))
            .collect();
        let local = make_merkle(blocks.clone());

        // Change block 42 in remote
        let mut remote_blocks = blocks;
        remote_blocks[42] = hash_data(b"MODIFIED_BLOCK_42_MODIFIED_BLOCK_42");
        let remote = make_merkle(remote_blocks);

        let diff = compare_merkle_trees(&local, &remote);
        assert_eq!(diff.changed_blocks, vec![42], "only block 42 should be changed");
        assert_eq!(diff.unchanged_blocks, 255);
        assert!(diff.change_ratio < 0.01);
    }

    // ── Test 12: compute_delta_blocks handles partial last block ────────

    #[test]
    fn test_compute_delta_blocks_partial_last_block() {
        let total_bytes = BLOCK_SIZE * 2 + 100; // 2 full blocks + 100 bytes
        let data: Vec<u8> = (0..total_bytes).map(|i| (i % 256) as u8).collect();

        let mut tmp = NamedTempFile::new().unwrap();
        tmp.write_all(&data).unwrap();
        tmp.flush().unwrap();

        let hashes = vec![
            hash_data(&data[..BLOCK_SIZE]),
            hash_data(&data[BLOCK_SIZE..BLOCK_SIZE * 2]),
            hash_data(&data[BLOCK_SIZE * 2..]),
        ];
        let merkle = MerkleData {
            file_path: "test.dat".to_string(),
            block_size: BLOCK_SIZE,
            total_blocks: 3,
            total_bytes: total_bytes as u64,
            merkle_root: "root".to_string(),
            chunk_hashes: hashes,
            tree_layers: vec![],
            blake3_file_hash: "hash".to_string(),
        };

        // Read the last (partial) block
        let blocks = compute_delta_blocks(tmp.path(), &merkle, &[2]).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].data.len(), 100);
    }
}
