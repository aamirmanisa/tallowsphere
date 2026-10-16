//! Metadata handling and privacy

pub mod filename;
pub mod stripper;

pub use filename::{decrypt_filename, encrypt_filename, encrypt_filename_random};
pub use stripper::{strip_exif, strip_metadata};
