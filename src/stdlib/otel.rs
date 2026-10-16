//! Standard library: `tallow.otel` — Observability & Telemetry types.
//!
//! Sentinel module: all types declared in stdlib/otel.tl are interpreter
//! sentinels. Dispatch returns None; execution routes through interp.rs.

use super::StdlibResult;
use crate::interp::Value;

pub fn dispatch(_function: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

pub fn dispatch_method(object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, .. } = object else { return None; };
    match name.as_str() {
        "Span" | "Metric" | "Slo" | "Alert" | "HealthCheck" => {
            // Sentinel types — interp handles all method dispatch
            None
        }
        _ => None,
    }
}
