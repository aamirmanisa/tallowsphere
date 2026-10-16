//! Distributed browser pool module.
//!
//! Provides session registry, coordinator, discovery, relay, and scheduler
//! for distributing browser sessions across multiple nodes.

pub mod coordinator;
pub mod discovery;
pub mod registry;
pub mod relay;
pub mod scheduler;

pub use coordinator::{ClusterState, NodeCoordinator, NodeInfo};
pub use discovery::PoolDiscovery;
pub use registry::{SessionEntry, SessionRegistry};
pub use relay::CdpRelay;
pub use scheduler::WorkDistributor;
