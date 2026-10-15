//! Platform-specific filesystem attribute preservation.
//!
//! On Windows: NTFS Alternate Data Streams (ADS), ACLs,
//! junctions, reparse points, and sparse files.
//!
//! On Unix (Linux/macOS): extended attributes (xattr)
//! and symlink preservation.

#[cfg(windows)]
pub mod windows;

#[cfg(unix)]
pub mod unix;
