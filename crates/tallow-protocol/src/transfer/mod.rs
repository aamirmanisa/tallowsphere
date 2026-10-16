//! Transfer pipeline and state management
//!
//! Handles file sending, receiving, chunking, compression,
//! encryption, progress tracking, and resume.

#[cfg(feature = "full")]
pub mod chunking;
#[cfg(feature = "full")]
pub mod exclusion;
#[cfg(feature = "full")]
pub mod journal;
#[cfg(feature = "full")]
pub mod manifest;
#[cfg(feature = "full")]
pub mod progress;
#[cfg(feature = "full")]
pub mod queue;
#[cfg(feature = "full")]
pub mod receive;
#[cfg(feature = "full")]
pub mod relay;
#[cfg(feature = "full")]
pub mod resume;
pub mod sanitize;
#[cfg(feature = "full")]
pub mod send;
#[cfg(feature = "full")]
pub mod state_machine;
#[cfg(feature = "full")]
pub mod sync;
#[cfg(feature = "full")]
pub mod watch;

#[cfg(feature = "full")]
pub use chunking::{ChunkConfig, DEFAULT_CHUNK_SIZE};
#[cfg(feature = "full")]
pub use exclusion::ExclusionConfig;
#[cfg(feature = "full")]
pub use manifest::FileManifest;
#[cfg(feature = "full")]
pub use progress::TransferProgress;
#[cfg(feature = "full")]
pub use queue::{QueueHandle, TransferQueue};
#[cfg(feature = "full")]
pub use receive::ReceivePipeline;
#[cfg(feature = "full")]
pub use resume::ResumeState;
#[cfg(feature = "full")]
pub use send::SendPipeline;
#[cfg(feature = "full")]
pub use state_machine::{TransferState, TransferStateMachine};
#[cfg(feature = "full")]
pub use watch::{WatchConfig, WatchEvent, WatchHandle};
