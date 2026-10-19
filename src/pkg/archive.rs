use anyhow::{Context, Result, bail};
use semver::Version;
use std::fs;
use std::path::Path;

use crate::pkg::manifest::parse_manifest;

/// Metadata extracted from or computed for a package archive.
#[derive(Debug, Clone)]
pub struct ArchiveMetadata {
    pub name: String,
    pub version: Version,
    /// BLAKE3 hex hash of the .tar.zst archive bytes.
    pub content_hash: String,
}

/// Compute BLAKE3 hash of raw bytes, returning lowercase hex string.
pub fn archive_content_hash(archive_bytes: &[u8]) -> String {
    blake3::hash(archive_bytes).to_hex().to_string()
}

/// Create a .tar.zst archive from a project directory.
///
/// The archive contains `tallow.toml` and all `.tl` files from `src/`.
/// Returns metadata including the BLAKE3 content hash of the archive.
pub fn create_archive(project_dir: &Path, output_path: &Path) -> Result<ArchiveMetadata> {
    // Read and parse tallow.toml
    let toml_path = project_dir.join("tallow.toml");
    if !toml_path.exists() {
        bail!("tallow.toml not found in {}", project_dir.display());
    }
    let toml_content = fs::read_to_string(&toml_path)
        .context("failed to read tallow.toml")?;
    let manifest = parse_manifest(&toml_content)
        .context("failed to parse tallow.toml")?;

    // Build tar archive in memory
    let mut tar_builder = tar::Builder::new(Vec::new());

    // Add tallow.toml
    let toml_bytes = toml_content.as_bytes();
    let mut header = tar::Header::new_gnu();
    header.set_size(toml_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    tar_builder.append_data(&mut header, "tallow.toml", toml_bytes)
        .context("failed to add tallow.toml to archive")?;

    // Add all .tl files from src/
    let src_dir = project_dir.join("src");
    if src_dir.exists() && src_dir.is_dir() {
        add_nx_files_recursive(&mut tar_builder, &src_dir, Path::new("src"))?;
    }

    let tar_bytes = tar_builder.into_inner()
        .context("failed to finalize tar archive")?;

    // Compress with zstd level 3
    let compressed = zstd::encode_all(tar_bytes.as_slice(), 3)
        .context("failed to compress archive with zstd")?;

    // Compute BLAKE3 hash
    let content_hash = archive_content_hash(&compressed);

    // Write to output
    let archive_name = format!("{}-{}.tar.zst", manifest.name, manifest.version);
    let final_path = output_path.join(&archive_name);
    if let Some(parent) = final_path.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(&final_path, &compressed)
        .with_context(|| format!("failed to write archive to {}", final_path.display()))?;

    Ok(ArchiveMetadata {
        name: manifest.name,
        version: manifest.version,
        content_hash,
    })
}

/// Recursively add .tl files from a directory to the tar archive.
fn add_nx_files_recursive(
    builder: &mut tar::Builder<Vec<u8>>,
    dir: &Path,
    prefix: &Path,
) -> Result<()> {
    for entry in fs::read_dir(dir).context("failed to read source directory")? {
        let entry = entry?;
        let path = entry.path();
        let relative = prefix.join(entry.file_name());

        if path.is_dir() {
            add_nx_files_recursive(builder, &path, &relative)?;
        // `.tl` is the only source extension. Matching `.nx` (the legacy one)
        // produced archives containing tallow.toml and no code at all; operator
        // direction is that the language uses `.tl` exclusively.
        } else if path.extension().is_some_and(|ext| ext == "tl") {
            let content = fs::read(&path)?;
            let mut header = tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            // Use forward slashes for cross-platform tar compatibility
            let entry_path = relative.to_string_lossy().replace('\\', "/");
            builder.append_data(&mut header, &entry_path, content.as_slice())
                .with_context(|| format!("failed to add {} to archive", entry_path))?;
        }
    }
    Ok(())
}

/// Extract a .tar.zst archive to a destination directory.
///
/// Returns metadata including the BLAKE3 content hash of the archive.
pub fn extract_archive(archive_path: &Path, dest_dir: &Path) -> Result<ArchiveMetadata> {
    let compressed = fs::read(archive_path)
        .with_context(|| format!("failed to read archive {}", archive_path.display()))?;

    let content_hash = archive_content_hash(&compressed);

    // Decompress zstd
    let tar_bytes = zstd::decode_all(compressed.as_slice())
        .context("failed to decompress zstd archive")?;

    // Extract tar
    let mut archive = tar::Archive::new(tar_bytes.as_slice());
    fs::create_dir_all(dest_dir)?;
    archive.unpack(dest_dir)
        .context("failed to extract tar archive")?;

    // Parse tallow.toml from extracted contents
    let toml_path = dest_dir.join("tallow.toml");
    if !toml_path.exists() {
        bail!("extracted archive does not contain tallow.toml");
    }
    let toml_content = fs::read_to_string(&toml_path)?;
    let manifest = parse_manifest(&toml_content)?;

    Ok(ArchiveMetadata {
        name: manifest.name,
        version: manifest.version,
        content_hash,
    })
}
