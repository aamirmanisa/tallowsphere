//! Shard planning: split one byte range into N contiguous, near-equal pieces.
//!
//! Pure arithmetic, no I/O, no dependencies. The invariants here are the ones
//! the rest of the crate relies on: the shards cover `[0, total_len)` exactly
//! once, in order, with no gap and no overlap.

use serde::{Deserialize, Serialize};

/// One contiguous byte range, end-exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Shard {
    /// Position in the plan, 0-based.
    pub index: u32,
    /// First byte included.
    pub start: u64,
    /// First byte excluded.
    pub end: u64,
}

impl Shard {
    /// Number of bytes this shard covers.
    pub fn len(&self) -> u64 {
        self.end - self.start
    }

    /// True when the range is empty (never produced by [`plan_shards`]).
    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }

    /// `Range` header value for this shard.
    pub fn range_header(&self) -> String {
        format!("bytes={}-{}", self.start, self.end - 1)
    }
}

/// A whole-transfer plan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShardPlan {
    /// Bytes the plan covers.
    pub total_len: u64,
    /// Shards in ascending order; contiguous and complete.
    pub shards: Vec<Shard>,
}

impl ShardPlan {
    /// Re-check every invariant. Used by tests and by the CLI before spending
    /// bandwidth on a plan it built from a server's `Content-Range`.
    pub fn validate(&self) -> Result<(), PlanError> {
        if self.shards.is_empty() {
            return Err(PlanError::NoStreams);
        }
        let mut pos = 0u64;
        for (i, shard) in self.shards.iter().enumerate() {
            if shard.index as usize != i {
                return Err(PlanError::NotContiguous {
                    at: pos,
                    detail: "shard index out of order",
                });
            }
            if shard.start != pos {
                return Err(PlanError::NotContiguous {
                    at: pos,
                    detail: "gap or overlap between shards",
                });
            }
            if shard.end <= shard.start {
                return Err(PlanError::NotContiguous {
                    at: shard.start,
                    detail: "empty shard",
                });
            }
            pos = shard.end;
        }
        if pos != self.total_len {
            return Err(PlanError::NotContiguous {
                at: pos,
                detail: "plan does not reach total_len",
            });
        }
        Ok(())
    }

    /// Largest single shard, i.e. the per-stream payload size.
    pub fn max_shard_len(&self) -> u64 {
        self.shards.iter().map(Shard::len).max().unwrap_or(0)
    }
}

/// Why a plan could not be built, or failed validation.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PlanError {
    /// Transfer length of zero is not plannable.
    #[error("total length must be greater than zero")]
    ZeroLength,
    /// At least one stream is required.
    #[error("stream count must be at least 1")]
    NoStreams,
    /// A zero minimum chunk would allow degenerate plans.
    #[error("minimum chunk size must be greater than zero")]
    MinChunkZero,
    /// A zero weight would ask for a path that carries no bytes.
    #[error("every weight must be at least 1")]
    WeightZero,
    /// Coverage invariant broken.
    #[error("shard coverage broken at byte {at}: {detail}")]
    NotContiguous {
        /// Byte offset where coverage failed.
        at: u64,
        /// What went wrong there.
        detail: &'static str,
    },
}

/// Split `total_len` bytes across at most `streams` shards of at least
/// `min_chunk` bytes each.
///
/// The stream count is reduced rather than the chunk size when the transfer is
/// small: 10 bytes over 8 streams with a 4-byte floor yields 2 shards of 5, not
/// 8 shards of 1. Sizes differ by at most one byte so the slowest stream does
/// not define the wall time.
pub fn plan_shards(total_len: u64, streams: u32, min_chunk: u64) -> Result<ShardPlan, PlanError> {
    if total_len == 0 {
        return Err(PlanError::ZeroLength);
    }
    if streams == 0 {
        return Err(PlanError::NoStreams);
    }
    if min_chunk == 0 {
        return Err(PlanError::MinChunkZero);
    }

    let capacity = (total_len / min_chunk).max(1);
    let n = (u64::from(streams)).min(capacity).max(1);
    let base = total_len / n;
    let remainder = total_len % n;

    let mut shards = Vec::with_capacity(n as usize);
    let mut pos = 0u64;
    for i in 0..n {
        let len = base + u64::from(i < remainder);
        shards.push(Shard {
            index: i as u32,
            start: pos,
            end: pos + len,
        });
        pos += len;
    }

    let plan = ShardPlan { total_len, shards };
    plan.validate()?;
    Ok(plan)
}

/// Split `total_len` across paths in proportion to `weights`.
///
/// Shard `i` gets total * weights[i] / sum(weights) bytes, with the leftover
/// from integer division handed to the largest remainders (ties to the lower
/// index) so coverage stays exact. Every shard is then raised to at least
/// `min_chunk` by taking bytes from the largest shard.
///
/// The point: equal shards on asymmetric paths finish at the speed of the
/// slowest leg, so a fast exit waits on a slow one. Weighting by measured
/// goodput makes the legs finish together instead.
pub fn plan_shards_weighted(
    total_len: u64,
    weights: &[u32],
    min_chunk: u64,
) -> Result<ShardPlan, PlanError> {
    if total_len == 0 {
        return Err(PlanError::ZeroLength);
    }
    if weights.is_empty() {
        return Err(PlanError::NoStreams);
    }
    if min_chunk == 0 {
        return Err(PlanError::MinChunkZero);
    }
    if weights.iter().any(|w| *w == 0) {
        return Err(PlanError::WeightZero);
    }

    let n = weights.len();
    let floor_total = min_chunk.saturating_mul(n as u64);
    if total_len < floor_total {
        // Cannot give every weighted path its floor. Reduce the shard count
        // rather than emit shards below it — same rule as `plan_shards`.
        let k = (total_len / min_chunk).max(1).min(n as u64) as u32;
        return plan_shards(total_len, k, min_chunk);
    }

    let sum: u128 = weights.iter().map(|w| *w as u128).sum();
    let total = u128::from(total_len);

    let mut lengths: Vec<u64> = Vec::with_capacity(n);
    let mut remainders: Vec<(u128, usize)> = Vec::with_capacity(n);
    let mut assigned: u128 = 0;
    for (i, w) in weights.iter().enumerate() {
        let exact = total * u128::from(*w);
        let len = exact / sum;
        lengths.push(len as u64);
        remainders.push((exact % sum, i));
        assigned += len;
    }

    // Integer division leaves fewer than `n` bytes unassigned; give them to the
    // largest fractional parts, deterministically.
    let leftover = (total - assigned) as usize;
    remainders.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for (_, idx) in remainders.iter().take(leftover) {
        lengths[*idx] += 1;
    }

    // Raise anything under the floor by draining the largest shard.
    for i in 0..n {
        while lengths[i] < min_chunk {
            let donor = (0..n)
                .filter(|&j| j != i && lengths[j] > min_chunk)
                .max_by_key(|&j| lengths[j]);
            let Some(j) = donor else { break };
            let need = min_chunk - lengths[i];
            let spare = lengths[j] - min_chunk;
            let take = need.min(spare);
            lengths[i] += take;
            lengths[j] -= take;
        }
    }

    let mut shards = Vec::with_capacity(n);
    let mut pos = 0u64;
    for (i, len) in lengths.iter().enumerate() {
        shards.push(Shard {
            index: i as u32,
            start: pos,
            end: pos + len,
        });
        pos += len;
    }

    let plan = ShardPlan { total_len, shards };
    plan.validate()?;
    Ok(plan)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn covers_exactly_once() {
        let plan = plan_shards(1000, 8, 1).expect("plan");
        plan.validate().expect("valid");
        assert_eq!(plan.shards.len(), 8);
        assert_eq!(plan.shards.iter().map(Shard::len).sum::<u64>(), 1000);
        assert_eq!(plan.shards[0].start, 0);
        assert_eq!(plan.shards[7].end, 1000);
    }

    #[test]
    fn sizes_differ_by_at_most_one() {
        let plan = plan_shards(1003, 8, 1).expect("plan");
        let max = plan.shards.iter().map(Shard::len).max().expect("max");
        let min = plan.shards.iter().map(Shard::len).min().expect("min");
        assert_eq!(max - min, 1);
    }

    #[test]
    fn reduces_streams_before_chunk_size() {
        let plan = plan_shards(10, 8, 4).expect("plan");
        assert_eq!(plan.shards.len(), 2);
        assert!(plan.shards.iter().all(|s| s.len() >= 4));
    }

    #[test]
    fn single_stream_when_transfer_smaller_than_min_chunk() {
        let plan = plan_shards(3, 16, 4096).expect("plan");
        assert_eq!(plan.shards.len(), 1);
        assert_eq!(plan.shards[0].len(), 3);
    }

    #[test]
    fn range_headers_are_inclusive_on_the_right() {
        let plan = plan_shards(100, 4, 1).expect("plan");
        assert_eq!(plan.shards[0].range_header(), "bytes=0-24");
        assert_eq!(plan.shards[3].range_header(), "bytes=75-99");
    }

    #[test]
    fn rejects_degenerate_inputs() {
        assert_eq!(plan_shards(0, 4, 1), Err(PlanError::ZeroLength));
        assert_eq!(plan_shards(10, 0, 1), Err(PlanError::NoStreams));
        assert_eq!(plan_shards(10, 4, 0), Err(PlanError::MinChunkZero));
    }

    #[test]
    fn validate_catches_a_gap() {
        let plan = ShardPlan {
            total_len: 100,
            shards: vec![
                Shard {
                    index: 0,
                    start: 0,
                    end: 40,
                },
                Shard {
                    index: 1,
                    start: 41,
                    end: 100,
                },
            ],
        };
        assert!(matches!(
            plan.validate(),
            Err(PlanError::NotContiguous { at: 40, .. })
        ));
    }

    #[test]
    fn weighted_split_matches_the_ratio() {
        let plan = plan_shards_weighted(1100, &[10, 1], 1).expect("plan");
        plan.validate().expect("valid");
        assert_eq!(plan.shards.len(), 2);
        assert_eq!(plan.shards[0].len(), 1000);
        assert_eq!(plan.shards[1].len(), 100);
    }

    #[test]
    fn weighted_split_is_exact_with_uneven_remainders() {
        let plan = plan_shards_weighted(100, &[1, 1, 1], 1).expect("plan");
        plan.validate().expect("valid");
        assert_eq!(plan.shards.iter().map(Shard::len).sum::<u64>(), 100);
        let max = plan.shards.iter().map(Shard::len).max().expect("max");
        let min = plan.shards.iter().map(Shard::len).min().expect("min");
        assert_eq!(max - min, 1);
    }

    #[test]
    fn weighted_plan_respects_the_chunk_floor() {
        // Raw split would be 990 / 10; the floor pulls the small leg up.
        let plan = plan_shards_weighted(1000, &[100, 1], 200).expect("plan");
        plan.validate().expect("valid");
        assert!(
            plan.shards.iter().all(|s| s.len() >= 200),
            "{:?}",
            plan.shards
        );
        assert_eq!(plan.shards.iter().map(Shard::len).sum::<u64>(), 1000);
    }

    #[test]
    fn weighted_plan_falls_back_when_the_floor_cannot_be_met() {
        let plan = plan_shards_weighted(10, &[5, 5, 5], 4096).expect("plan");
        assert_eq!(plan.shards.len(), 1);
        assert_eq!(plan.shards[0].len(), 10);
    }

    #[test]
    fn weighted_plan_rejects_a_zero_weight() {
        assert_eq!(
            plan_shards_weighted(1000, &[1, 0], 1),
            Err(PlanError::WeightZero)
        );
    }

    #[test]
    fn weighted_single_path_equals_the_whole_transfer() {
        let plan = plan_shards_weighted(4096, &[7], 1).expect("plan");
        assert_eq!(plan.shards.len(), 1);
        assert_eq!(plan.shards[0].len(), 4096);
    }
}
