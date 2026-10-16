//! Route policy models for depth and transport selection.
//!
//! This file is intentionally standalone. It defines the data model, serde
//! shape, validation helpers, and compact D/T metadata helpers that other
//! modules can adopt incrementally.

use std::error::Error;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Maximum supported routing depth for bounded policies.
pub const MAX_ROUTE_DEPTH: u32 = 64;
/// Separator used by compact depth/transport style tags.
pub const ROUTE_STYLE_SEPARATOR: char = '-';

/// Errors returned by routing policy validation helpers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteModelError {
    /// A bounded depth policy requested an invalid depth.
    InvalidDepth { max_depth: u32, max_allowed: u32 },
}

impl fmt::Display for RouteModelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RouteModelError::InvalidDepth {
                max_depth,
                max_allowed,
            } => write!(
                f,
                "invalid route depth {max_depth}; expected 1..={max_allowed}"
            ),
        }
    }
}

impl Error for RouteModelError {}

/// Depth policy for routing and traversal.
///
/// `Unlimited` keeps traversal open-ended, while `Limited` bounds the maximum
/// depth that downstream routing logic may follow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteDepthPolicy {
    /// No explicit depth cap.
    Unlimited,
    /// Limit traversal to a fixed maximum depth.
    Limited { max_depth: u32 },
}

impl Default for RouteDepthPolicy {
    fn default() -> Self {
        Self::Limited { max_depth: 1 }
    }
}

impl RouteDepthPolicy {
    /// Returns the bounded depth, if one is set.
    pub fn max_depth(self) -> Option<u32> {
        match self {
            RouteDepthPolicy::Unlimited => None,
            RouteDepthPolicy::Limited { max_depth } => Some(max_depth),
        }
    }

    /// True when this policy allows arbitrary depth.
    pub fn is_unlimited(self) -> bool {
        matches!(self, RouteDepthPolicy::Unlimited)
    }

    /// Validate the depth policy.
    pub fn validate(self) -> Result<(), RouteModelError> {
        match self {
            RouteDepthPolicy::Unlimited => Ok(()),
            RouteDepthPolicy::Limited { max_depth }
                if (1..=MAX_ROUTE_DEPTH).contains(&max_depth) =>
            {
                Ok(())
            }
            RouteDepthPolicy::Limited { max_depth } => Err(RouteModelError::InvalidDepth {
                max_depth,
                max_allowed: MAX_ROUTE_DEPTH,
            }),
        }
    }

    /// Compact depth token for D/T-style routing metadata.
    ///
    /// Examples:
    /// - `Limited { max_depth: 4 }` -> `"D4"`
    /// - `Unlimited` -> `"DU"`
    pub fn dt_code(self) -> String {
        match self {
            RouteDepthPolicy::Unlimited => "DU".to_string(),
            RouteDepthPolicy::Limited { max_depth } => format!("D{max_depth}"),
        }
    }

    /// Parse a compact depth token produced by [`RouteDepthPolicy::dt_code`].
    pub fn from_dt_code(code: &str) -> Option<Self> {
        let normalized = code.trim().to_ascii_uppercase();
        if normalized == "DU" {
            return Some(RouteDepthPolicy::Unlimited);
        }

        let number = normalized.strip_prefix('D')?.parse::<u32>().ok()?;
        let candidate = RouteDepthPolicy::Limited { max_depth: number };
        if candidate.validate().is_ok() {
            Some(candidate)
        } else {
            None
        }
    }
}

/// Routing preference for browser transport.
///
/// The variants are intentionally high-level and do not yet bind to the
/// transport implementation in `cdp.rs`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteTransportPolicy {
    /// Let the runtime decide the transport.
    Auto,
    /// Prefer WebSocket transport when available.
    PreferWebSocket,
    /// Prefer pipe transport when available.
    PreferPipe,
    /// Require WebSocket transport.
    WebSocketOnly,
    /// Require pipe transport.
    PipeOnly,
}

impl Default for RouteTransportPolicy {
    fn default() -> Self {
        Self::Auto
    }
}

impl RouteTransportPolicy {
    /// Returns `true` when pipe transport is acceptable.
    pub fn allows_pipe(self) -> bool {
        matches!(
            self,
            RouteTransportPolicy::Auto
                | RouteTransportPolicy::PreferPipe
                | RouteTransportPolicy::PipeOnly
        )
    }

    /// Returns `true` when WebSocket transport is acceptable.
    pub fn allows_websocket(self) -> bool {
        matches!(
            self,
            RouteTransportPolicy::Auto
                | RouteTransportPolicy::PreferWebSocket
                | RouteTransportPolicy::WebSocketOnly
        )
    }

    /// Validate the transport policy.
    ///
    /// Transport variants are currently closed under construction, so this
    /// always succeeds. Keeping the helper makes the policy struct symmetric
    /// with the depth policy and gives future invariants a single home.
    pub fn validate(self) -> Result<(), RouteModelError> {
        Ok(())
    }

    /// Compact transport token for D/T-style routing metadata.
    pub fn dt_code(self) -> &'static str {
        match self {
            RouteTransportPolicy::Auto => "TA",
            RouteTransportPolicy::PreferWebSocket => "TWP",
            RouteTransportPolicy::PreferPipe => "TPP",
            RouteTransportPolicy::WebSocketOnly => "TWO",
            RouteTransportPolicy::PipeOnly => "TPO",
        }
    }

    /// Parse a compact transport token produced by
    /// [`RouteTransportPolicy::dt_code`].
    pub fn from_dt_code(code: &str) -> Option<Self> {
        match code.trim().to_ascii_uppercase().as_str() {
            "TA" => Some(RouteTransportPolicy::Auto),
            "TWP" => Some(RouteTransportPolicy::PreferWebSocket),
            "TPP" => Some(RouteTransportPolicy::PreferPipe),
            "TWO" => Some(RouteTransportPolicy::WebSocketOnly),
            "TPO" => Some(RouteTransportPolicy::PipeOnly),
            _ => None,
        }
    }
}

/// Combined routing policy for browser traversal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RoutePolicy {
    /// How deep routing may go.
    pub depth: RouteDepthPolicy,
    /// Which browser transport should be used.
    pub transport: RouteTransportPolicy,
}

impl Default for RoutePolicy {
    fn default() -> Self {
        Self {
            depth: RouteDepthPolicy::default(),
            transport: RouteTransportPolicy::default(),
        }
    }
}

impl RoutePolicy {
    /// Validate both policy dimensions.
    pub fn validate(&self) -> Result<(), RouteModelError> {
        self.depth.validate()?;
        self.transport.validate()?;
        Ok(())
    }

    /// True if the policy permits both transports.
    pub fn allows_any_transport(&self) -> bool {
        self.transport == RouteTransportPolicy::Auto
    }

    /// Compact D/T-style tag used for lightweight metadata exchange.
    ///
    /// The canonical shape is `<depth>-<transport>`, for example:
    /// - `"D1-TA"` for a shallow auto route
    /// - `"DU-TPO"` for unlimited depth with pipe-only transport
    pub fn dt_style_code(&self) -> String {
        format!(
            "{}{ROUTE_STYLE_SEPARATOR}{}",
            self.depth.dt_code(),
            self.transport.dt_code()
        )
    }

    /// Parse a compact D/T-style tag into a route policy.
    ///
    /// Accepted delimiters are `-`, `|`, and `:` to keep ingestion tolerant of
    /// different metadata emitters.
    pub fn from_dt_style_code(style: &str) -> Option<Self> {
        let mut depth = None;
        let mut transport = None;

        for token in style
            .split(|ch: char| ch == '-' || ch == '|' || ch == ':')
            .filter(|token| !token.trim().is_empty())
        {
            let normalized = token.trim().to_ascii_uppercase();
            if normalized.starts_with('D') {
                depth = RouteDepthPolicy::from_dt_code(&normalized);
            } else if normalized.starts_with('T') {
                transport = RouteTransportPolicy::from_dt_code(&normalized);
            } else {
                return None;
            }
        }

        let candidate = RoutePolicy {
            depth: depth?,
            transport: transport?,
        };
        if candidate.validate().is_ok() {
            Some(candidate)
        } else {
            None
        }
    }
}

/// Route depth contract used by the policy router.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RouteDepthClass {
    #[serde(rename = "D1")]
    D1,
    #[serde(rename = "D2")]
    D2,
    #[serde(rename = "D3")]
    D3,
    #[serde(rename = "D4")]
    D4,
    #[serde(rename = "D5")]
    D5,
}

impl RouteDepthClass {
    pub fn as_code(self) -> &'static str {
        match self {
            Self::D1 => "D1",
            Self::D2 => "D2",
            Self::D3 => "D3",
            Self::D4 => "D4",
            Self::D5 => "D5",
        }
    }

    fn minimum_transport(self) -> RouteTransportClass {
        match self {
            Self::D1 | Self::D2 => RouteTransportClass::T1ApiHttp,
            Self::D3 => RouteTransportClass::T2StaticHttp,
            Self::D4 => RouteTransportClass::T3RenderedHttp,
            Self::D5 => RouteTransportClass::T4Browser,
        }
    }

    pub fn cost_multiplier(self) -> u64 {
        match self {
            Self::D1 => 1,
            Self::D2 => 2,
            Self::D3 => 3,
            Self::D4 => 5,
            Self::D5 => 8,
        }
    }
}

/// Transport ladder used by the policy router.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RouteTransportClass {
    #[serde(rename = "T1")]
    T1ApiHttp,
    #[serde(rename = "T2")]
    T2StaticHttp,
    #[serde(rename = "T3")]
    T3RenderedHttp,
    #[serde(rename = "T4")]
    T4Browser,
}

impl RouteTransportClass {
    pub fn as_code(self) -> &'static str {
        match self {
            Self::T1ApiHttp => "T1",
            Self::T2StaticHttp => "T2",
            Self::T3RenderedHttp => "T3",
            Self::T4Browser => "T4",
        }
    }

    pub fn as_name(self) -> &'static str {
        match self {
            Self::T1ApiHttp => "api_http",
            Self::T2StaticHttp => "static_http",
            Self::T3RenderedHttp => "rendered_http",
            Self::T4Browser => "browser",
        }
    }

    pub fn index(self) -> usize {
        match self {
            Self::T1ApiHttp => 0,
            Self::T2StaticHttp => 1,
            Self::T3RenderedHttp => 2,
            Self::T4Browser => 3,
        }
    }

    pub fn estimated_cost_microusd(self) -> u64 {
        match self {
            Self::T1ApiHttp => 1_500,
            Self::T2StaticHttp => 4_500,
            Self::T3RenderedHttp => 12_000,
            Self::T4Browser => 32_000,
        }
    }
}

/// Router budget class for cost control.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteBudgetClass {
    Cheap,
    Standard,
    Expensive,
}

impl Default for RouteBudgetClass {
    fn default() -> Self {
        Self::Standard
    }
}

impl RouteBudgetClass {
    pub fn as_name(self) -> &'static str {
        match self {
            Self::Cheap => "cheap",
            Self::Standard => "standard",
            Self::Expensive => "expensive",
        }
    }

    pub fn budget_cap_microusd(self) -> u64 {
        match self {
            Self::Cheap => 60_000,
            Self::Standard => 180_000,
            Self::Expensive => 400_000,
        }
    }
}

/// Stable route observability tags required on all route-aware outputs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteObservabilityTags {
    pub route_domain: String,
    pub route_depth: String,
    pub route_transport: String,
    pub route_transport_name: String,
    pub route_budget: String,
    pub route_estimated_cost_microusd: u64,
    pub route_budget_cap_microusd: u64,
    pub route_budget_guardrail: String,
    pub route_budget_within_cap: bool,
    pub route_reason: String,
    pub route_fallback_chain: Vec<String>,
    pub route_fallback_chain_names: Vec<String>,
    pub route_ladder: String,
    pub route_signature: String,
}

impl Default for RouteObservabilityTags {
    fn default() -> Self {
        Self {
            route_domain: "unknown".to_string(),
            route_depth: "D1".to_string(),
            route_transport: "T1".to_string(),
            route_transport_name: RouteTransportClass::T1ApiHttp.as_name().to_string(),
            route_budget: RouteBudgetClass::Standard.as_name().to_string(),
            route_estimated_cost_microusd: 1_500,
            route_budget_cap_microusd: RouteBudgetClass::Standard.budget_cap_microusd(),
            route_budget_guardrail: "within_budget_cap".to_string(),
            route_budget_within_cap: true,
            route_reason: "unset".to_string(),
            route_fallback_chain: vec![RouteTransportClass::T1ApiHttp.as_code().to_string()],
            route_fallback_chain_names: vec![RouteTransportClass::T1ApiHttp.as_name().to_string()],
            route_ladder: RouteTransportClass::T1ApiHttp.as_code().to_string(),
            route_signature: "D1-T1-standard".to_string(),
        }
    }
}

/// Field request metadata used for depth inference.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteFieldSpec {
    pub name: String,
    pub required: bool,
}

impl Default for RouteFieldSpec {
    fn default() -> Self {
        Self {
            name: String::new(),
            required: true,
        }
    }
}

impl RouteFieldSpec {
    pub fn required(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required: true,
        }
    }

    pub fn optional(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            required: false,
        }
    }
}

/// Policy input consumed by [`route`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RouteRequestPolicy {
    pub allow_browser: bool,
    pub budget_class: RouteBudgetClass,
    pub supports_api: bool,
    pub supports_static: bool,
    pub supports_rendered: bool,
    pub supports_browser: bool,
    pub preferred_transport: Option<RouteTransportClass>,
}

impl Default for RouteRequestPolicy {
    fn default() -> Self {
        Self {
            allow_browser: true,
            budget_class: RouteBudgetClass::Standard,
            supports_api: true,
            supports_static: true,
            supports_rendered: true,
            supports_browser: true,
            preferred_transport: None,
        }
    }
}

impl RouteRequestPolicy {
    fn allows_transport(&self, transport: RouteTransportClass) -> bool {
        match transport {
            RouteTransportClass::T1ApiHttp => self.supports_api,
            RouteTransportClass::T2StaticHttp => self.supports_static,
            RouteTransportClass::T3RenderedHttp => self.supports_rendered,
            RouteTransportClass::T4Browser => self.supports_browser && self.allow_browser,
        }
    }

    fn normalized(&self) -> Self {
        let mut policy = self.clone();
        if !policy.allow_browser {
            policy.supports_browser = false;
        }
        policy
    }
}

/// Router output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteDecision {
    pub depth: RouteDepthClass,
    pub transport: RouteTransportClass,
    pub reason: String,
    pub fallback_chain: Vec<RouteTransportClass>,
    pub budget_class: RouteBudgetClass,
    pub estimated_cost_microusd: u64,
    pub budget_cap_microusd: u64,
    pub budget_within_cap: bool,
    pub budget_guardrail: String,
    #[serde(default)]
    pub observability_tags: RouteObservabilityTags,
}

const ROUTE_TRANSPORT_LADDER: [RouteTransportClass; 4] = [
    RouteTransportClass::T1ApiHttp,
    RouteTransportClass::T2StaticHttp,
    RouteTransportClass::T3RenderedHttp,
    RouteTransportClass::T4Browser,
];

/// Resolve the requested depth from target fields.
pub fn infer_route_depth(target_fields: &[RouteFieldSpec]) -> RouteDepthClass {
    if target_fields.is_empty() {
        return RouteDepthClass::D1;
    }

    let mut required_count = 0usize;
    let mut complexity_score = 0usize;
    let mut keyword_depth = RouteDepthClass::D1;

    for field in target_fields {
        let normalized = field.name.trim().to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }

        if field.required {
            required_count += 1;
            complexity_score += 2;
        } else {
            complexity_score += 1;
        }

        if is_d5_field(&normalized) {
            keyword_depth = RouteDepthClass::D5;
            break;
        }
        if is_d4_field(&normalized) {
            keyword_depth = keyword_depth.max(RouteDepthClass::D4);
            continue;
        }
        if is_d3_field(&normalized) {
            keyword_depth = keyword_depth.max(RouteDepthClass::D3);
            continue;
        }
        if is_d2_field(&normalized) {
            keyword_depth = keyword_depth.max(RouteDepthClass::D2);
        }
    }

    let count_depth = if required_count >= 10 || complexity_score >= 16 {
        RouteDepthClass::D5
    } else if required_count >= 7 || complexity_score >= 11 {
        RouteDepthClass::D4
    } else if required_count >= 4 || complexity_score >= 6 {
        RouteDepthClass::D3
    } else if required_count >= 2 || complexity_score >= 3 {
        RouteDepthClass::D2
    } else {
        RouteDepthClass::D1
    };

    keyword_depth.max(count_depth)
}

/// Route a domain request to the cheapest transport that satisfies depth and
/// policy constraints.
pub fn route(
    domain: &str,
    target_fields: &[RouteFieldSpec],
    policy: &RouteRequestPolicy,
) -> RouteDecision {
    let depth = infer_route_depth(target_fields);
    let normalized_policy = policy.normalized();
    let minimum_transport = depth.minimum_transport();
    let (candidate_transport, base_reason) =
        choose_primary_transport(domain, minimum_transport, &normalized_policy);
    let (
        transport,
        budget_guardrail,
        estimated_cost_microusd,
        budget_cap_microusd,
        budget_within_cap,
    ) = enforce_budget_guardrails(
        depth,
        candidate_transport,
        minimum_transport,
        &normalized_policy,
    );
    let fallback_chain = build_fallback_chain(transport, &normalized_policy);
    let reason = if budget_guardrail == "within_budget_cap" {
        base_reason
    } else {
        format!("{base_reason}+{budget_guardrail}")
    };

    let observability_tags = build_route_observability_tags_with_budget(
        domain,
        depth,
        transport,
        normalized_policy.budget_class,
        estimated_cost_microusd,
        budget_cap_microusd,
        &budget_guardrail,
        budget_within_cap,
        &reason,
        &fallback_chain,
    );

    RouteDecision {
        depth,
        transport,
        reason,
        fallback_chain,
        budget_class: normalized_policy.budget_class,
        estimated_cost_microusd,
        budget_cap_microusd,
        budget_within_cap,
        budget_guardrail,
        observability_tags,
    }
}

/// Build stable route observability tags for emitted outputs with explicit
/// budget/cost metadata.
pub fn build_route_observability_tags_with_budget(
    domain: &str,
    depth: RouteDepthClass,
    transport: RouteTransportClass,
    budget_class: RouteBudgetClass,
    estimated_cost_microusd: u64,
    budget_cap_microusd: u64,
    budget_guardrail: &str,
    budget_within_cap: bool,
    reason: &str,
    fallback_chain: &[RouteTransportClass],
) -> RouteObservabilityTags {
    let fallback_codes: Vec<String> = fallback_chain
        .iter()
        .map(|candidate| candidate.as_code().to_string())
        .collect();
    let fallback_names: Vec<String> = fallback_chain
        .iter()
        .map(|candidate| candidate.as_name().to_string())
        .collect();
    let ladder = if fallback_codes.is_empty() {
        transport.as_code().to_string()
    } else {
        fallback_codes.join(">")
    };

    RouteObservabilityTags {
        route_domain: normalized_route_domain(domain),
        route_depth: depth.as_code().to_string(),
        route_transport: transport.as_code().to_string(),
        route_transport_name: transport.as_name().to_string(),
        route_budget: budget_class.as_name().to_string(),
        route_estimated_cost_microusd: estimated_cost_microusd,
        route_budget_cap_microusd: budget_cap_microusd,
        route_budget_guardrail: budget_guardrail.to_string(),
        route_budget_within_cap: budget_within_cap,
        route_reason: reason.trim().to_string(),
        route_fallback_chain: if fallback_codes.is_empty() {
            vec![transport.as_code().to_string()]
        } else {
            fallback_codes
        },
        route_fallback_chain_names: if fallback_names.is_empty() {
            vec![transport.as_name().to_string()]
        } else {
            fallback_names
        },
        route_ladder: ladder,
        route_signature: format!(
            "{}-{}-{}",
            depth.as_code(),
            transport.as_code(),
            budget_class.as_name()
        ),
    }
}

/// Backward-compatible builder used by older call sites that do not explicitly
/// pass budget/cost values.
pub fn build_route_observability_tags(
    domain: &str,
    depth: RouteDepthClass,
    transport: RouteTransportClass,
    budget_class: RouteBudgetClass,
    reason: &str,
    fallback_chain: &[RouteTransportClass],
) -> RouteObservabilityTags {
    let estimated_cost_microusd = estimate_route_cost_microusd(depth, transport);
    let budget_cap_microusd = budget_class.budget_cap_microusd();
    let budget_within_cap = estimated_cost_microusd <= budget_cap_microusd;
    let budget_guardrail = if budget_within_cap {
        "within_budget_cap"
    } else {
        "budget_guardrail_exceeds_budget_cap"
    };

    build_route_observability_tags_with_budget(
        domain,
        depth,
        transport,
        budget_class,
        estimated_cost_microusd,
        budget_cap_microusd,
        budget_guardrail,
        budget_within_cap,
        reason,
        fallback_chain,
    )
}

fn normalized_route_domain(domain: &str) -> String {
    let trimmed = domain.trim();
    if trimmed.is_empty() {
        return "unknown".to_string();
    }

    let without_scheme = if let Some(idx) = trimmed.find("://") {
        &trimmed[idx + 3..]
    } else {
        trimmed
    };
    let without_auth = without_scheme.rsplit('@').next().unwrap_or(without_scheme);
    let host_port = without_auth.split('/').next().unwrap_or(without_auth);
    let host_trimmed = host_port.trim_matches(|ch| ch == '[' || ch == ']');
    let host_only = host_trimmed.split(':').next().unwrap_or(host_trimmed);
    let normalized = host_only.to_ascii_lowercase();
    if normalized.is_empty() {
        "unknown".to_string()
    } else {
        normalized
    }
}

fn choose_primary_transport(
    _domain: &str,
    minimum_transport: RouteTransportClass,
    policy: &RouteRequestPolicy,
) -> (RouteTransportClass, String) {
    if let Some(preferred) = policy.preferred_transport {
        if preferred.index() >= minimum_transport.index() && policy.allows_transport(preferred) {
            return (
                preferred,
                format!("preferred_transport_{}", preferred.as_name()),
            );
        }
    }

    if let Some(selected) = first_allowed_transport_from(minimum_transport, policy) {
        if selected == minimum_transport {
            return (
                selected,
                format!("{}_satisfies_depth_floor", selected.as_name()),
            );
        }
        return (
            selected,
            format!("policy_constraint_promoted_to_{}", selected.as_name()),
        );
    }

    (
        minimum_transport,
        "policy_disallowed_ladder_using_depth_floor".to_string(),
    )
}

fn estimate_route_cost_microusd(depth: RouteDepthClass, transport: RouteTransportClass) -> u64 {
    depth.cost_multiplier() * transport.estimated_cost_microusd()
}

fn enforce_budget_guardrails(
    depth: RouteDepthClass,
    candidate_transport: RouteTransportClass,
    minimum_transport: RouteTransportClass,
    policy: &RouteRequestPolicy,
) -> (RouteTransportClass, String, u64, u64, bool) {
    let budget_cap_microusd = policy.budget_class.budget_cap_microusd();
    let mut selected = candidate_transport;
    let mut guardrail = "within_budget_cap".to_string();
    let mut estimated_cost_microusd = estimate_route_cost_microusd(depth, selected);

    if estimated_cost_microusd > budget_cap_microusd {
        let candidate_span = selected.index().saturating_sub(minimum_transport.index()) + 1;
        if let Some(downgraded) = ROUTE_TRANSPORT_LADDER
            .iter()
            .copied()
            .skip(minimum_transport.index())
            .take(candidate_span)
            .filter(|transport| policy.allows_transport(*transport))
            .find(|transport| {
                estimate_route_cost_microusd(depth, *transport) <= budget_cap_microusd
            })
        {
            selected = downgraded;
            estimated_cost_microusd = estimate_route_cost_microusd(depth, selected);
            guardrail = format!("budget_guardrail_downgraded_to_{}", selected.as_name());
        } else {
            let depth_floor = first_allowed_transport_from(minimum_transport, policy)
                .unwrap_or(minimum_transport);
            selected = depth_floor;
            estimated_cost_microusd = estimate_route_cost_microusd(depth, selected);
            if estimated_cost_microusd <= budget_cap_microusd {
                guardrail = format!("budget_guardrail_depth_floor_{}", selected.as_name());
            } else {
                guardrail = "budget_guardrail_depth_floor_exceeds_budget_cap".to_string();
            }
        }
    }

    (
        selected,
        guardrail,
        estimated_cost_microusd,
        budget_cap_microusd,
        estimated_cost_microusd <= budget_cap_microusd,
    )
}

fn build_fallback_chain(
    primary: RouteTransportClass,
    policy: &RouteRequestPolicy,
) -> Vec<RouteTransportClass> {
    let mut chain: Vec<RouteTransportClass> = ROUTE_TRANSPORT_LADDER
        .iter()
        .copied()
        .skip(primary.index())
        .filter(|transport| policy.allows_transport(*transport))
        .collect();

    if chain.is_empty() {
        chain.push(primary);
    }

    chain
}

fn first_allowed_transport_from(
    start: RouteTransportClass,
    policy: &RouteRequestPolicy,
) -> Option<RouteTransportClass> {
    ROUTE_TRANSPORT_LADDER
        .iter()
        .copied()
        .skip(start.index())
        .find(|transport| policy.allows_transport(*transport))
}

fn is_d2_field(field: &str) -> bool {
    matches!(
        field,
        "title" | "name" | "id" | "sku" | "price" | "currency" | "url" | "slug" | "brand"
    ) || field.ends_with("_id")
}

fn is_d3_field(field: &str) -> bool {
    matches!(
        field,
        "description"
            | "images"
            | "unit_price"
            | "category"
            | "breadcrumbs"
            | "rating"
            | "reviews_count"
            | "seller"
            | "metadata"
    )
}

fn is_d4_field(field: &str) -> bool {
    matches!(
        field,
        "availability"
            | "inventory"
            | "variants"
            | "shipping"
            | "tax"
            | "promotion"
            | "price_history"
            | "nutrition"
            | "specifications"
            | "compliance"
    )
}

fn is_d5_field(field: &str) -> bool {
    matches!(
        field,
        "raw_html"
            | "dom_snapshot"
            | "script_state"
            | "network_events"
            | "all_fields"
            | "full_capture"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn depth_policy_round_trip_serialization() {
        let policy = RouteDepthPolicy::Limited { max_depth: 4 };
        let json = serde_json::to_string(&policy).unwrap();
        assert_eq!(json, r#"{"limited":{"max_depth":4}}"#);

        let decoded: RouteDepthPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded, policy);
        assert_eq!(decoded.max_depth(), Some(4));
        assert!(!decoded.is_unlimited());
    }

    #[test]
    fn unlimited_depth_serializes_cleanly() {
        let json = serde_json::to_string(&RouteDepthPolicy::Unlimited).unwrap();
        assert_eq!(json, r#""unlimited""#);
        assert_eq!(
            serde_json::from_str::<RouteDepthPolicy>(&json).unwrap(),
            RouteDepthPolicy::Unlimited
        );
    }

    #[test]
    fn depth_validation_rejects_zero() {
        let policy = RouteDepthPolicy::Limited { max_depth: 0 };
        let err = policy.validate().unwrap_err();
        assert_eq!(
            err,
            RouteModelError::InvalidDepth {
                max_depth: 0,
                max_allowed: MAX_ROUTE_DEPTH,
            }
        );
        assert!(err.to_string().contains("expected 1..="));
    }

    #[test]
    fn depth_validation_rejects_values_above_the_cap() {
        let policy = RouteDepthPolicy::Limited {
            max_depth: MAX_ROUTE_DEPTH + 1,
        };
        let err = policy.validate().unwrap_err();
        assert_eq!(
            err,
            RouteModelError::InvalidDepth {
                max_depth: MAX_ROUTE_DEPTH + 1,
                max_allowed: MAX_ROUTE_DEPTH,
            }
        );
    }

    #[test]
    fn transport_policy_helpers_reflect_permissions() {
        assert!(RouteTransportPolicy::Auto.allows_pipe());
        assert!(RouteTransportPolicy::Auto.allows_websocket());
        assert!(RouteTransportPolicy::PreferPipe.allows_pipe());
        assert!(!RouteTransportPolicy::PreferPipe.allows_websocket());
        assert!(RouteTransportPolicy::WebSocketOnly.allows_websocket());
        assert!(!RouteTransportPolicy::WebSocketOnly.allows_pipe());
    }

    #[test]
    fn route_policy_defaults_are_valid() {
        let policy = RoutePolicy::default();
        assert_eq!(policy.depth, RouteDepthPolicy::Limited { max_depth: 1 });
        assert_eq!(policy.transport, RouteTransportPolicy::Auto);
        assert!(policy.validate().is_ok());
        assert!(policy.allows_any_transport());
    }

    #[test]
    fn route_policy_round_trip_serialization() {
        let policy = RoutePolicy {
            depth: RouteDepthPolicy::Unlimited,
            transport: RouteTransportPolicy::PreferPipe,
        };
        let json = serde_json::to_string(&policy).unwrap();
        let decoded: RoutePolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded, policy);
        assert!(decoded.depth.is_unlimited());
        assert!(decoded.transport.allows_pipe());
        assert!(!decoded.transport.allows_websocket());
    }

    #[test]
    fn route_policy_rejects_unknown_fields() {
        let json = r#"{"depth":"unlimited","transport":"auto","extra":true}"#;
        let err = serde_json::from_str::<RoutePolicy>(json).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn depth_dt_code_round_trip() {
        let limited = RouteDepthPolicy::Limited { max_depth: 6 };
        assert_eq!(
            RouteDepthPolicy::from_dt_code(&limited.dt_code()),
            Some(limited)
        );
        assert_eq!(
            RouteDepthPolicy::from_dt_code(&RouteDepthPolicy::Unlimited.dt_code()),
            Some(RouteDepthPolicy::Unlimited)
        );
        assert_eq!(RouteDepthPolicy::from_dt_code("D0"), None);
    }

    #[test]
    fn transport_dt_code_round_trip() {
        for policy in [
            RouteTransportPolicy::Auto,
            RouteTransportPolicy::PreferWebSocket,
            RouteTransportPolicy::PreferPipe,
            RouteTransportPolicy::WebSocketOnly,
            RouteTransportPolicy::PipeOnly,
        ] {
            assert_eq!(
                RouteTransportPolicy::from_dt_code(policy.dt_code()),
                Some(policy)
            );
        }
        assert_eq!(RouteTransportPolicy::from_dt_code("tx"), None);
    }

    #[test]
    fn route_policy_dt_style_round_trip() {
        let policy = RoutePolicy {
            depth: RouteDepthPolicy::Limited { max_depth: 8 },
            transport: RouteTransportPolicy::PreferPipe,
        };
        let style = policy.dt_style_code();
        assert_eq!(style, "D8-TPP");
        assert_eq!(
            RoutePolicy::from_dt_style_code(&style),
            Some(policy.clone())
        );

        assert_eq!(
            RoutePolicy::from_dt_style_code("d8|tpp"),
            Some(policy.clone())
        );
        assert_eq!(RoutePolicy::from_dt_style_code("D8:Tpp"), Some(policy));
    }

    #[test]
    fn route_policy_dt_style_rejects_invalid_payloads() {
        assert_eq!(RoutePolicy::from_dt_style_code("D2"), None);
        assert_eq!(RoutePolicy::from_dt_style_code("TA"), None);
        assert_eq!(RoutePolicy::from_dt_style_code("D999-TA"), None);
        assert_eq!(RoutePolicy::from_dt_style_code("D2-XYZ"), None);
    }

    #[test]
    fn infer_route_depth_defaults_to_d1_without_fields() {
        assert_eq!(infer_route_depth(&[]), RouteDepthClass::D1);
    }

    #[test]
    fn infer_route_depth_marks_d5_for_full_capture_markers() {
        let fields = vec![
            RouteFieldSpec::required("name"),
            RouteFieldSpec::required("price"),
            RouteFieldSpec::required("raw_html"),
        ];
        assert_eq!(infer_route_depth(&fields), RouteDepthClass::D5);
    }

    #[test]
    fn route_prefers_low_cost_api_when_depth_allows() {
        let fields = vec![
            RouteFieldSpec::required("name"),
            RouteFieldSpec::required("price"),
        ];
        let decision = route("example.com", &fields, &RouteRequestPolicy::default());
        assert_eq!(decision.depth, RouteDepthClass::D2);
        assert_eq!(decision.transport, RouteTransportClass::T1ApiHttp);
        assert_eq!(
            decision.fallback_chain,
            vec![
                RouteTransportClass::T1ApiHttp,
                RouteTransportClass::T2StaticHttp,
                RouteTransportClass::T3RenderedHttp,
                RouteTransportClass::T4Browser,
            ]
        );
    }

    #[test]
    fn route_skips_disallowed_transports_in_fallback_chain() {
        let policy = RouteRequestPolicy {
            supports_api: false,
            supports_static: true,
            supports_rendered: true,
            supports_browser: false,
            allow_browser: false,
            ..RouteRequestPolicy::default()
        };
        let fields = vec![
            RouteFieldSpec::required("name"),
            RouteFieldSpec::required("price"),
            RouteFieldSpec::required("description"),
        ];
        let decision = route("example.com", &fields, &policy);
        assert_eq!(decision.transport, RouteTransportClass::T2StaticHttp);
        assert_eq!(
            decision.fallback_chain,
            vec![
                RouteTransportClass::T2StaticHttp,
                RouteTransportClass::T3RenderedHttp,
            ]
        );
    }

    #[test]
    fn route_uses_preferred_transport_when_valid_for_depth() {
        let policy = RouteRequestPolicy {
            preferred_transport: Some(RouteTransportClass::T3RenderedHttp),
            ..RouteRequestPolicy::default()
        };
        let fields = vec![
            RouteFieldSpec::required("name"),
            RouteFieldSpec::required("price"),
        ];
        let decision = route("example.com", &fields, &policy);
        assert_eq!(decision.transport, RouteTransportClass::T3RenderedHttp);
    }

    #[test]
    fn route_decision_includes_observability_tags() {
        let fields = vec![
            RouteFieldSpec::required("name"),
            RouteFieldSpec::required("price"),
        ];
        let decision = route(
            "https://www.Example.com/path",
            &fields,
            &RouteRequestPolicy::default(),
        );
        assert_eq!(decision.observability_tags.route_domain, "www.example.com");
        assert_eq!(decision.observability_tags.route_depth, "D2");
        assert_eq!(decision.observability_tags.route_transport, "T1");
        assert!(decision.observability_tags.route_estimated_cost_microusd > 0);
        assert!(decision.observability_tags.route_budget_cap_microusd > 0);
        assert!(decision.observability_tags.route_budget_within_cap);
        assert_eq!(decision.observability_tags.route_ladder, "T1>T2>T3>T4");
        assert!(
            decision
                .observability_tags
                .route_signature
                .starts_with("D2-T1-")
        );
    }

    #[test]
    fn build_route_observability_tags_normalizes_domain() {
        let tags = build_route_observability_tags_with_budget(
            "HTTP://Api.Example.COM/v1/items",
            RouteDepthClass::D3,
            RouteTransportClass::T2StaticHttp,
            RouteBudgetClass::Cheap,
            13_500,
            60_000,
            "within_budget_cap",
            true,
            "unit_test",
            &[
                RouteTransportClass::T2StaticHttp,
                RouteTransportClass::T3RenderedHttp,
            ],
        );
        assert_eq!(tags.route_domain, "api.example.com");
        assert_eq!(tags.route_depth, "D3");
        assert_eq!(tags.route_transport, "T2");
        assert_eq!(tags.route_budget, "cheap");
        assert_eq!(tags.route_estimated_cost_microusd, 13_500);
        assert_eq!(tags.route_budget_cap_microusd, 60_000);
        assert_eq!(tags.route_budget_guardrail, "within_budget_cap");
        assert!(tags.route_budget_within_cap);
        assert_eq!(
            tags.route_fallback_chain,
            vec!["T2".to_string(), "T3".to_string()]
        );
        assert_eq!(tags.route_ladder, "T2>T3");
    }

    #[test]
    fn route_budget_guardrail_downgrades_expensive_preference() {
        let policy = RouteRequestPolicy {
            budget_class: RouteBudgetClass::Cheap,
            preferred_transport: Some(RouteTransportClass::T4Browser),
            ..RouteRequestPolicy::default()
        };
        let fields = vec![
            RouteFieldSpec::required("name"),
            RouteFieldSpec::required("price"),
        ];
        let decision = route("example.com", &fields, &policy);
        assert_eq!(decision.depth, RouteDepthClass::D2);
        assert_eq!(decision.transport, RouteTransportClass::T1ApiHttp);
        assert!(decision.budget_within_cap);
        assert!(
            decision
                .budget_guardrail
                .contains("budget_guardrail_downgraded_to_api_http")
        );
        assert!(
            decision
                .reason
                .contains("budget_guardrail_downgraded_to_api_http")
        );
        assert!(decision.estimated_cost_microusd <= decision.budget_cap_microusd);
    }

    #[test]
    fn route_budget_guardrail_reports_when_depth_floor_exceeds_budget() {
        let policy = RouteRequestPolicy {
            budget_class: RouteBudgetClass::Cheap,
            ..RouteRequestPolicy::default()
        };
        let fields = vec![RouteFieldSpec::required("raw_html")];
        let decision = route("example.com", &fields, &policy);
        assert_eq!(decision.depth, RouteDepthClass::D5);
        assert_eq!(decision.transport, RouteTransportClass::T4Browser);
        assert!(!decision.budget_within_cap);
        assert_eq!(
            decision.budget_guardrail,
            "budget_guardrail_depth_floor_exceeds_budget_cap"
        );
        assert!(decision.estimated_cost_microusd > decision.budget_cap_microusd);
    }
}
