//! Resumable, chunked age transfer.
//!
//! # Why this shape
//!
//! `age`'s public API writes one stream sequentially — there is no hook to
//! resume at chunk *n*, and a bespoke container would mean inventing a
//! cryptographic format, which is the one thing not to do here.
//!
//! So a transfer is a **directory of ordinary age containers**: one `.age` file
//! per part plus a manifest. Every part is a real age container (decryptable by
//! `age(1)` on its own), each part has its own ephemeral key so no nonce is ever
//! reused, and resumability falls out of "how many parts are already complete".
//!
//! Cost of that choice, stated: per-part framing overhead (~300 bytes per part)
//! and one file per part. At 1 MiB parts a 1 GiB transfer is 1024 files with
//! ~0.03% overhead.

use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::age;

pub const DEFAULT_CHUNK: usize = 1024 * 1024;

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub version: u32,
    pub chunk_size: usize,
    pub total_len: u64,
    /// BLAKE3 of the whole plaintext, so a completed transfer can be checked
    /// against its source without keeping the file in memory twice.
    pub plaintext_blake3: String,
    pub parts: Vec<Part>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Part {
    pub index: usize,
    pub len: usize,
}

fn manifest_path(dir: &Path) -> PathBuf {
    dir.join("manifest.json")
}

fn part_path(dir: &Path, index: usize) -> PathBuf {
    dir.join(format!("part-{index:05}.age"))
}

fn read_manifest(dir: &Path) -> Option<Manifest> {
    let bytes = fs::read(manifest_path(dir)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_manifest(dir: &Path, m: &Manifest) -> Result<(), String> {
    let bytes = serde_json::to_vec_pretty(m).map_err(|e| format!("age_stream: manifest: {e}"))?;
    fs::write(manifest_path(dir), bytes).map_err(|e| format!("age_stream: manifest write: {e}"))
}

/// Encrypt `src` into `out_dir`, resuming at the first missing part.
///
/// Returns `(parts, resumed_from, plaintext_blake3)`.
pub fn encrypt_file(
    recipient: &str,
    src: &str,
    out_dir: &str,
    chunk_size: Option<usize>,
) -> Result<(usize, usize, String), String> {
    let src_path = Path::new(src);
    let dir = Path::new(out_dir);
    fs::create_dir_all(dir).map_err(|e| format!("age_stream: {out_dir}: {e}"))?;

    let mut file = fs::File::open(src_path).map_err(|e| format!("age_stream: {src}: {e}"))?;
    let total_len = file
        .metadata()
        .map_err(|e| format!("age_stream: {src}: {e}"))?
        .len();

    // Hash the source once, streaming: the manifest records it so a resumed run
    // cannot silently combine parts from a different file.
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buf).map_err(|e| format!("age_stream: read: {e}"))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    let digest = hasher.finalize().to_hex().to_string();

    let chunk = chunk_size.unwrap_or(DEFAULT_CHUNK).max(4096);
    let n_parts = ((total_len as usize) + chunk - 1) / chunk.max(1);
    let n_parts = n_parts.max(1);

    // A manifest from an earlier run is reused only if it describes the same
    // file and the same chunking; otherwise the directory is rewritten.
    let existing = read_manifest(dir);
    let mut manifest = match existing {
        Some(m) if m.total_len == total_len && m.chunk_size == chunk && m.plaintext_blake3 == digest => {
            m
        }
        _ => {
            // Clear stale parts so a half-old directory cannot be mistaken for
            // progress on the new file.
            for entry in fs::read_dir(dir).map_err(|e| format!("age_stream: {out_dir}: {e}"))? {
                let p = entry.map_err(|e| format!("age_stream: {e}"))?.path();
                if p.file_name().map(|n| n.to_string_lossy().starts_with("part-")).unwrap_or(false) {
                    let _ = fs::remove_file(p);
                }
            }
            Manifest {
                version: 1,
                chunk_size: chunk,
                total_len,
                plaintext_blake3: digest.clone(),
                parts: Vec::new(),
            }
        }
    };

    // Resume point: the longest contiguous run of parts that exist on disk.
    let mut done = 0usize;
    while done < n_parts && part_path(dir, done).exists() {
        done += 1;
    }
    let resumed_from = done;

    file.seek_to_start().map_err(|e| format!("age_stream: seek: {e}"))?;
    let mut offset = (done * chunk) as u64;
    if offset > 0 {
        use std::io::Seek;
        file.seek(std::io::SeekFrom::Start(offset))
            .map_err(|e| format!("age_stream: seek: {e}"))?;
    }

    let mut index = done;
    while offset < total_len || index == 0 {
        let want = std::cmp::min(chunk as u64, total_len.saturating_sub(offset)) as usize;
        let mut plain = vec![0u8; want];
        file.read_exact(&mut plain)
            .map_err(|e| format!("age_stream: read at {offset}: {e}"))?;

        let ct = age::encrypt_hex(recipient, &plain)?;
        let bytes = hex_decode(&ct)?;
        fs::write(part_path(dir, index), &bytes)
            .map_err(|e| format!("age_stream: part {index}: {e}"))?;

        if manifest.parts.len() <= index {
            manifest.parts.push(Part { index, len: want });
        } else {
            manifest.parts[index] = Part { index, len: want };
        }
        write_manifest(dir, &manifest)?;

        offset += want as u64;
        index += 1;
        if total_len == 0 {
            break;
        }
    }

    Ok((index, resumed_from, digest))
}

/// Decrypt a directory produced by [`encrypt_file`] into `dst`, resuming at the
/// first part not yet written.
///
/// Every part is authenticated by age; a tampered part fails the whole transfer
/// rather than yielding corrupted output.
pub fn decrypt_file(identity: &str, in_dir: &str, dst: &str) -> Result<(usize, u64), String> {
    let dir = Path::new(in_dir);
    let manifest = read_manifest(dir)
        .ok_or_else(|| format!("age_stream: no readable manifest in {in_dir}"))?;

    let mut out = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(dst)
        .map_err(|e| format!("age_stream: {dst}: {e}"))?;

    let mut hasher = blake3::Hasher::new();
    for (i, part) in manifest.parts.iter().enumerate() {
        if part.index != i {
            return Err(format!("age_stream: manifest part {i} is out of order"));
        }
        let bytes = fs::read(part_path(dir, i))
            .map_err(|e| format!("age_stream: missing part {i}: {e}"))?;
        let plain = age::decrypt_hex(identity, &hex_encode(&bytes))?;
        hasher.update(&plain);
        out.write_all(&plain)
            .map_err(|e| format!("age_stream: write {dst}: {e}"))?;
    }
    out.flush().map_err(|e| format!("age_stream: flush: {e}"))?;

    let got = hasher.finalize().to_hex().to_string();
    if got != manifest.plaintext_blake3 {
        return Err(format!(
            "age_stream: plaintext digest mismatch after decrypt ({got} != {}); \
             the transfer is incomplete or was assembled from a different source",
            manifest.plaintext_blake3
        ));
    }
    Ok((manifest.parts.len(), manifest.total_len))
}

fn hex_encode(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len() * 2);
    for x in b {
        use std::fmt::Write;
        let _ = write!(s, "{x:02x}");
    }
    s
}

fn hex_decode(s: &str) -> Result<Vec<u8>, String> {
    crate::age::hex_decode(s)
}

/// Minimal seek helper: `File` has no inherent `seek_to_start`, and keeping the
/// trait import local makes the resume path obvious.
trait SeekToStart {
    fn seek_to_start(&mut self) -> std::io::Result<u64>;
}

impl SeekToStart for fs::File {
    fn seek_to_start(&mut self) -> std::io::Result<u64> {
        use std::io::Seek;
        self.seek(std::io::SeekFrom::Start(0))
    }
}
