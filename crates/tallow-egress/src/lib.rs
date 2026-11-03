//! Egress throughput primitives for Tallow.
//!
//! Three independent levers, none of which the others substitute for:
//!
//! - [`plan`] — split one transfer into N contiguous ranges.
//! - [`pool`] — fetch those ranges over N concurrent connections. This is the
//!   lever that lifts *single-flow* wall time, because the per-flow ceiling is
//!   a bandwidth-delay-product limit, not a link limit.
//! - [`node`] — spread the ranges across N independent exits, which raises the
//!   aggregate ceiling to `nodes × per-node` and distributes per-IP limits.
//!
//! [`probe`] exists to stop the crate from guessing: it reports how many
//! genuinely independent paths the host has before `--streams 32 --nodes 8`
//! gets used to paper over a single 1 Gbit uplink.

#![forbid(unsafe_code)]

pub mod node;
pub mod plan;
pub mod pool;
pub mod probe;
pub mod proxy;

pub use node::{EgressNode, NodeKind, NodePool, NodeStat, Reservation};
pub use plan::{PlanError, Shard, ShardPlan, plan_shards, plan_shards_weighted};
pub use pool::{
    FetchError, Fetcher, HttpRangeFetcher, PoolConfig, PoolReport, ShardStat, fetch_plan,
};
pub use probe::{CapabilityReport, LinkInfo, LinkKind, probe_host};
