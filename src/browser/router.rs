//! Router observability and KPI helpers.
//!
//! This module keeps small, reusable helpers around route tag integrity and
//! rollout KPI math (`T1/T2` share and completeness-loss checks).

use super::route_model::{RouteDecision, RouteObservabilityTags, RouteTransportClass};

/// Pilot gate target for low-cost transport share.
pub const ROUTE_T1_T2_TARGET_SHARE: f64 = 0.80;

/// Summary metrics for a route cohort.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct RouteKpiSummary {
    pub total: usize,
    pub t1_count: usize,
    pub t2_count: usize,
    pub t1_t2_share: f64,
}

impl RouteKpiSummary {
    /// Returns true if this cohort meets the T1/T2 pilot gate.
    pub fn passes_t1_t2_gate(self) -> bool {
        self.total > 0 && self.t1_t2_share >= ROUTE_T1_T2_TARGET_SHARE
    }
}

/// Normalize route tags emitted by a decision so required fields never empty.
pub fn normalize_route_tags(decision: &RouteDecision) -> RouteObservabilityTags {
    let mut tags = decision.observability_tags.clone();
    if tags.route_transport.trim().is_empty() {
        tags.route_transport = decision.transport.as_code().to_string();
    }
    if tags.route_transport_name.trim().is_empty() {
        tags.route_transport_name = decision.transport.as_name().to_string();
    }
    if tags.route_depth.trim().is_empty() {
        tags.route_depth = decision.depth.as_code().to_string();
    }
    if tags.route_ladder.trim().is_empty() {
        tags.route_ladder = tags.route_transport.clone();
    }
    if tags.route_signature.trim().is_empty() {
        tags.route_signature = format!(
            "{}-{}-{}",
            tags.route_depth, tags.route_transport, tags.route_budget
        );
    }
    if tags.route_fallback_chain.is_empty() {
        tags.route_fallback_chain = vec![tags.route_transport.clone()];
    }
    if tags.route_fallback_chain_names.is_empty() {
        tags.route_fallback_chain_names = vec![tags.route_transport_name.clone()];
    }
    tags
}

/// Compute cohort-level T1/T2 share directly from route decisions.
pub fn summarize_t1_t2_share<'a, I>(decisions: I) -> RouteKpiSummary
where
    I: IntoIterator<Item = &'a RouteDecision>,
{
    let mut total = 0usize;
    let mut t1_count = 0usize;
    let mut t2_count = 0usize;

    for decision in decisions {
        total += 1;
        match decision.transport {
            RouteTransportClass::T1ApiHttp => t1_count += 1,
            RouteTransportClass::T2StaticHttp => t2_count += 1,
            _ => {}
        }
    }

    let t1_t2_share = if total > 0 {
        (t1_count + t2_count) as f64 / total as f64
    } else {
        0.0
    };

    RouteKpiSummary {
        total,
        t1_count,
        t2_count,
        t1_t2_share,
    }
}

/// Returns true when projected completeness does not drop below baseline.
pub fn no_completeness_loss(baseline: f64, projected: f64) -> bool {
    projected + f64::EPSILON >= baseline
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::browser::route_model::{
        RouteBudgetClass, RouteFieldSpec, RouteRequestPolicy, RouteTransportClass, route,
    };

    #[test]
    fn kpi_share_counts_t1_t2() {
        let policy = RouteRequestPolicy::default();
        let d1 = route("a.com", &[RouteFieldSpec::required("name")], &policy); // T1
        let d2 = route("b.com", &[RouteFieldSpec::required("description")], &policy); // T2
        let d3 = route(
            "c.com",
            &[RouteFieldSpec::required("availability")],
            &policy,
        ); // T3
        assert_eq!(d1.transport, RouteTransportClass::T1ApiHttp);
        assert_eq!(d2.transport, RouteTransportClass::T2StaticHttp);
        assert_eq!(d3.transport, RouteTransportClass::T3RenderedHttp);

        let summary = summarize_t1_t2_share([&d1, &d2, &d3]);
        assert_eq!(summary.total, 3);
        assert_eq!(summary.t1_count, 1);
        assert_eq!(summary.t2_count, 1);
        assert!((summary.t1_t2_share - (2.0 / 3.0)).abs() < 0.000_001);
        assert!(!summary.passes_t1_t2_gate());
    }

    #[test]
    fn normalization_backfills_missing_tag_fields() {
        let mut decision = route(
            "example.com",
            &[RouteFieldSpec::required("name")],
            &RouteRequestPolicy {
                budget_class: RouteBudgetClass::Cheap,
                ..RouteRequestPolicy::default()
            },
        );
        decision.observability_tags.route_depth.clear();
        decision.observability_tags.route_transport.clear();
        decision.observability_tags.route_transport_name.clear();
        decision.observability_tags.route_ladder.clear();
        decision.observability_tags.route_signature.clear();
        decision.observability_tags.route_fallback_chain.clear();
        decision
            .observability_tags
            .route_fallback_chain_names
            .clear();

        let normalized = normalize_route_tags(&decision);
        assert_eq!(normalized.route_depth, "D2");
        assert_eq!(normalized.route_transport, "T1");
        assert_eq!(normalized.route_transport_name, "api_http");
        assert_eq!(normalized.route_ladder, "T1");
        assert!(normalized.route_signature.starts_with("D2-T1-"));
        assert_eq!(normalized.route_fallback_chain, vec!["T1".to_string()]);
        assert_eq!(
            normalized.route_fallback_chain_names,
            vec!["api_http".to_string()]
        );
    }

    #[test]
    fn completeness_check_is_non_regressive() {
        assert!(no_completeness_loss(0.95, 0.95));
        assert!(no_completeness_loss(0.95, 0.951));
        assert!(!no_completeness_loss(0.95, 0.94));
    }
}
