//! Standard library: `gama_api` — GAMA ordering API access.
//!
//! # Security posture (hardened 2026-09-05)
//!
//! - **Single-attempt login by default.** [`login`] performs exactly one
//!   request. Transport/HTTP failures surface as real `Err(...)` results —
//!   they are never wrapped in `Ok(String("...error"))`.
//! - **No silent brute force.** Multi-attempt probing ([`brute_login`]) is
//!   **off by default**. It requires an explicit operator opt-in
//!   (`TALLOW_GAMA_PROBE_ALLOWED=1`) *and* the `@legal`-style gate record
//!   below (the runtime analogue of the `.tl` `@legal(...)` annotation the
//!   E0100 legal pass demands for network-I/O functions). Probing is
//!   additionally rate-limited in code: a mandatory per-attempt minimum delay
//!   (≥ [`PROBE_MIN_DELAY_MS`], configurable via `TALLOW_GAMA_PROBE_DELAY_MS`)
//!   and a hard per-run attempt cap ([`PROBE_MAX_ATTEMPTS`]).
//! - **Vendor headers stay private.** The `CustomHeader` values authenticate
//!   this client to the third-party API and are treated as non-public
//!   credentials: they are no longer exported via [`get_config`].

use super::StdlibResult;
use crate::interp::Value;
use std::time::Duration;

// ===== Endpoint / vendor metadata =====

const API_BASE: &str = "https://gamaapiapp5.azurewebsites.net/OrderingAppApi/VOne";

// Vendor app headers — required by the API, but non-public credentials.
// Kept module-private; intentionally NOT exported via get_config.
const LOGIN_HEADER: &str = "werfjkachisdfssusehrkwshckauhsdfsdfdufrehkwnskjfdhfukesrs";
const DATA_HEADER: &str = "werfjkachiusehrkwshckauhsdfsdfdufrehkwnskjfdhfukesrs";

// ===== @legal-style gate record: multi-attempt probing =====
//
// Probing a third-party login endpoint by iterating MobileCodes is an active
// credential-guessing attack against an external system. It must never run by
// default or unattended. This record mirrors the `@legal(...)` annotation a
// `.tl` network function must carry (E0100 legal pass). Re-enabling probing
// requires BOTH a current approved gate AND the runtime opt-in below.
struct ProbeGate {
    basis: &'static str,
    purpose: &'static str,
    owner: &'static str,
    approved_on: &'static str,
    note: &'static str,
}

const PROBE_GATE: ProbeGate = ProbeGate {
    basis: "explicit operator authorization for an authorized test of operator-owned GAMA accounts",
    purpose: "verify a known MobileCode / recover an operator-owned account",
    owner: "repository owner (the operator)",
    approved_on: "2026-09-05",
    note: "live probing of third-party systems is outside the accepted local/non-live/no-secret phase scope; manual re-review required before each use",
};

// Runtime opt-in (default OFF).
const PROBE_ENV_ALLOW: &str = "TALLOW_GAMA_PROBE_ALLOWED";
// Optional per-attempt delay override (clamped up to the mandatory minimum).
const PROBE_ENV_DELAY_MS: &str = "TALLOW_GAMA_PROBE_DELAY_MS";

// Mandatory rate limits — enforced regardless of the opt-in.
const PROBE_MIN_DELAY_MS: u64 = 1_000; // ≥ 1s between attempts
const PROBE_MAX_ATTEMPTS: u64 = 20; // per-run cap

/// Per-run probe policy, resolved from the environment.
///
/// Kept as a small pure struct so the gate logic is unit-testable without
/// network access or environment mutation.
#[derive(Clone, Debug)]
struct ProbePolicy {
    allowed: bool,
    delay_ms: u64,
    max_attempts: u64,
}

impl ProbePolicy {
    fn from_env() -> Self {
        let allowed = std::env::var(PROBE_ENV_ALLOW)
            .map(|v| v.trim() == "1")
            .unwrap_or(false);
        let delay_ms = Self::clamp_delay(std::env::var(PROBE_ENV_DELAY_MS).ok().as_deref());
        ProbePolicy {
            allowed,
            delay_ms,
            max_attempts: PROBE_MAX_ATTEMPTS,
        }
    }

    /// Minimum per-attempt delay. Any env override below the mandatory
    /// minimum is clamped up to [`PROBE_MIN_DELAY_MS`].
    fn clamp_delay(raw: Option<&str>) -> u64 {
        match raw.and_then(|s| s.trim().parse::<u64>().ok()) {
            Some(v) => v.max(PROBE_MIN_DELAY_MS),
            None => PROBE_MIN_DELAY_MS,
        }
    }

    /// Validate a probe range against the gate + rate limits *before any
    /// network I/O*. Returns the number of attempts on success.
    fn check(&self, start: i128, end: i128) -> Result<u64, String> {
        if !self.allowed {
            return Err(format!(
                "gama_api.brute_login: multi-attempt probing is disabled by default. \
                 Set {PROBE_ENV_ALLOW}=1 to opt in, and confirm the @legal-style gate record \
                 in src/stdlib/gama_api.rs (basis: '{}') still applies",
                PROBE_GATE.basis
            ));
        }
        if start < 0 || end > 999_999 || end < start {
            return Err(format!(
                "gama_api.brute_login: invalid code range {start}..={end} \
                 (must satisfy 0 <= start <= end <= 999999)"
            ));
        }
        let attempts = (end - start + 1) as u64;
        if attempts > self.max_attempts {
            return Err(format!(
                "gama_api.brute_login: range {start}..={end} spans {attempts} attempts, exceeding \
                 the mandatory per-run cap of {} (rate limit); narrow the range",
                self.max_attempts
            ));
        }
        Ok(attempts)
    }
}

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "login" => Some(login(args)),
        "brute_login" => Some(brute_login(args)),
        "get_main_menu" => Some(authenticated_call(args, "MainMenuApi/SlidersAndDeliveryDay", "POST")),
        "get_categories" => Some(authenticated_call(args, "CategoriesApi/Depart", "GET")),
        "get_orders" => Some(authenticated_call(args, "ExistingOrderApi/ExistingOrder", "POST")),
        "get_order_detail" => Some(authenticated_call(args, "OrderApi/CartListDetail", "POST")),
        "get_account_cards" => Some(authenticated_call(args, "AccountCardsApi/AccountCards", "POST")),
        "search_product" => Some(authenticated_call(args, "ItemsApi/SearchItemBarCode", "POST")),
        "get_submenu" => Some(authenticated_call(args, "SubMenuApi/SubMenu", "POST")),
        "get_privacy" => Some(authenticated_call(args, "PrivacyPolicyApi/PrivacyPolicy", "GET")),
        "get_terms" => Some(authenticated_call(args, "TermOfServiceApi/TermofService", "GET")),
        "enumerate_products" => Some(enumerate_products(args)),
        "get_config" => Some(get_config(args)),
        _ => None,
    }
}

pub fn dispatch_method(_object: &Value, _method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    None
}

pub fn is_known_function(function: &str) -> bool {
    matches!(function,
        "login" | "brute_login" | "get_main_menu" | "get_categories" | "get_orders"
        | "get_order_detail" | "get_account_cards" | "search_product" | "get_submenu"
        | "get_privacy" | "get_terms" | "enumerate_products" | "get_config"
    )
}

// ====== Auth ======

/// One login request against `base` with the given MobileCode.
///
/// Returns the raw response body on success or a real `Err` describing the
/// transport/HTTP failure — errors are never swallowed into an `Ok`.
fn attempt_login(base: &str, code: &str) -> Result<String, String> {
    let url = format!("{base}/LoginApi/Login");
    let body = format!("MobileCode={}", urlencoding::encode(code));
    let resp = crate::runtime::egress_http::post(&url)
        .header("CustomHeader", LOGIN_HEADER)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(body.as_bytes())
        .map_err(|e| format!("request failed: {e}"))?;
    resp.into_body()
        .read_to_string()
        .map_err(|e| format!("reading response failed: {e}"))
}

/// `gama_api.login(mobilecode)` → single-attempt login. Returns the raw JSON
/// body on success; propagates a real `Err` on any request/read failure.
fn login(args: Vec<Value>) -> StdlibResult {
    let code = extract_string(&args, 0, "mobilecode")?;
    attempt_login(API_BASE, &code)
        .map(Value::String)
        .map_err(|e| format!("gama_api.login: {e}"))
}

/// `gama_api.brute_login(start_code, end_code)` → multi-attempt MobileCode
/// probing.
///
/// Hardened 2026-09-05: **off by default**. Refuses with an explicit error
/// unless the operator opts in via `TALLOW_GAMA_PROBE_ALLOWED=1` AND the gate
/// record at the top of this file is still current. When enabled, every
/// attempt is paced by a mandatory minimum delay and the whole run is capped
/// at [`PROBE_MAX_ATTEMPTS`] attempts; the first failed request aborts the
/// run with a real `Err` (no silent skipping).
fn brute_login(args: Vec<Value>) -> StdlibResult {
    let start = extract_int(&args, 0, "start_code")?;
    let end = extract_int(&args, 1, "end_code")?;
    let policy = ProbePolicy::from_env();
    let attempts = policy.check(start, end)?;

    let mut results: Vec<serde_json::Value> = Vec::new();
    let mut attempt_no: u64 = 0;
    for code in start..=end {
        attempt_no += 1;
        // Mandatory per-attempt pacing (rate limit): sleep even before the
        // first attempt so a run of N attempts takes >= N * min_delay.
        std::thread::sleep(Duration::from_millis(policy.delay_ms));

        let formatted = format!("{code:06}");
        match attempt_login(API_BASE, &formatted) {
            Ok(text) => {
                // Server-side rejection of an invalid code is a 200 body, not
                // a transport error: keep the original heuristic.
                if !text.contains("Invalid Code") && !text.contains("Please Fill") && text.len() > 50 {
                    results.push(serde_json::json!({"code": formatted, "response": text}));
                }
            }
            Err(e) => {
                return Err(format!(
                    "gama_api.brute_login: attempt {formatted} failed \
                     (attempt {attempt_no} of {attempts}): {e}"
                ));
            }
        }
    }

    Ok(serde_json_to_value(&serde_json::json!({
        "scanned": attempts,
        "found": results.len(),
        "results": results,
    })))
}

// ====== Authenticated API calls ======

/// One authenticated request against `base`; propagates real errors.
fn authenticated_request(
    base: &str,
    endpoint: &str,
    method: &str,
    token: &str,
    body: &str,
) -> Result<String, String> {
    let url = format!("{base}/{endpoint}");
    let response = match method {
        "POST" => crate::runtime::egress_http::post(&url)
            .header("CustomHeader", DATA_HEADER)
            .header("Authorization", &format!("Bearer {token}"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send(body.as_bytes()),
        _ => crate::runtime::egress_http::get(&url)
            .header("CustomHeader", DATA_HEADER)
            .header("Authorization", &format!("Bearer {token}"))
            .call(),
    };
    let resp = response.map_err(|e| format!("request to '{endpoint}' failed: {e}"))?;
    resp.into_body()
        .read_to_string()
        .map_err(|e| format!("reading response from '{endpoint}' failed: {e}"))
}

fn authenticated_call(args: Vec<Value>, endpoint: &str, method: &str) -> StdlibResult {
    let token = extract_string(&args, 0, "token")?;
    let body = extract_string_opt(&args, 1, "body").unwrap_or_default();
    authenticated_request(API_BASE, endpoint, method, &token, &body)
        .map(Value::String)
        .map_err(|e| format!("gama_api.{endpoint}: {e}"))
}

// ====== Product enumeration ======

fn enumerate_products(args: Vec<Value>) -> StdlibResult {
    let token = extract_string(&args, 0, "token")?;
    let userid = extract_string(&args, 1, "userid")?;
    let accountno = extract_string(&args, 2, "accountno")?;
    let max_orders = extract_int(&args, 3, "max_orders").unwrap_or(100);

    // Step 1: Get order list (real error propagation instead of Ok("orders error: ...")).
    let orders_url = format!("{API_BASE}/ExistingOrderApi/ExistingOrder");
    let orders_body = format!("userid={userid}&accountno={accountno}");
    let orders_resp = crate::runtime::egress_http::post(&orders_url)
        .header("CustomHeader", DATA_HEADER)
        .header("Authorization", &format!("Bearer {token}"))
        .header("Content-Type", "application/x-www-form-urlencoded")
        .send(orders_body.as_bytes())
        .map_err(|e| format!("gama_api.enumerate_products: order list request failed: {e}"))?;
    let orders_text = orders_resp
        .into_body()
        .read_to_string()
        .map_err(|e| format!("gama_api.enumerate_products: reading order list failed: {e}"))?;

    let orders: Vec<serde_json::Value> = if orders_text.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(&orders_text)
            .map_err(|e| format!("gama_api.enumerate_products: order list is not JSON: {e}"))?
    };
    let oid_list: Vec<i64> = orders
        .iter()
        .filter_map(|o| o.get("orderid").and_then(|v| v.as_i64()))
        .take(max_orders as usize)
        .collect();

    let mut products: Vec<serde_json::Value> = Vec::new();
    let mut seen_upcs = std::collections::HashSet::new();

    for oid in &oid_list {
        let detail_url = format!("{API_BASE}/OrderApi/CartListDetail");
        let detail_body = format!("userid={userid}&accountno={accountno}&OrderID={oid}");
        let detail_resp = crate::runtime::egress_http::post(&detail_url)
            .header("CustomHeader", DATA_HEADER)
            .header("Authorization", &format!("Bearer {token}"))
            .header("Content-Type", "application/x-www-form-urlencoded")
            .send(detail_body.as_bytes())
            .map_err(|e| {
                format!("gama_api.enumerate_products: order {oid} detail request failed: {e}")
            })?;
        let text = detail_resp
            .into_body()
            .read_to_string()
            .map_err(|e| format!("gama_api.enumerate_products: reading order {oid} detail failed: {e}"))?;
        let items: Vec<serde_json::Value> = if text.trim().is_empty() {
            Vec::new()
        } else {
            serde_json::from_str(&text).map_err(|e| {
                format!("gama_api.enumerate_products: order {oid} detail is not JSON: {e}")
            })?
        };
        for item in items {
            if let Some(upc) = item.get("ItemLookupCode").and_then(|v| v.as_str()) {
                if seen_upcs.insert(upc.to_string()) {
                    products.push(item.clone());
                }
            }
        }
    }

    Ok(serde_json_to_value(&serde_json::json!({
        "orders_scanned": oid_list.len(),
        "products_found": products.len(),
        "products": products,
    })))
}

// ====== Config ======

/// `gama_api.get_config()` → endpoint map + probe policy.
///
/// Vendor `CustomHeader` values are intentionally NOT included: they are
/// non-public credentials, not configuration.
fn get_config(_args: Vec<Value>) -> StdlibResult {
    let policy = ProbePolicy::from_env();
    Ok(serde_json_to_value(&serde_json::json!({
        "api_base": API_BASE,
        "endpoints": {
            "auth": ["LoginApi/Login"],
            "data_get": ["CategoriesApi/Depart", "PrivacyPolicyApi/PrivacyPolicy", "TermOfServiceApi/TermofService"],
            "data_post": [
                "MainMenuApi/SlidersAndDeliveryDay", "MainMenuApi/StoreList",
                "SubMenuApi/SubMenu", "ItemsApi/CategoryItemID", "ItemsApi/SearchItemBarCode",
                "ItemsApi/TxtItemBarCodesList", "ItemsApi/vwsubstituteItem", "ItemsApi/ReportItem",
                "ExistingOrderApi/ExistingOrder", "ExistingOrderApi/ExistingOrderdetail",
                "ExistingOrderApi/CancelOrder", "SubmittedOrderApi/SubmittedOrder",
                "SubmittedOrderApi/SendEmail", "OrderApi/CartListDetail", "OrderApi/Delivery",
                "OrderApi/AddOrder", "OrderApi/AddOrderDetail", "OrderApi/CheckOut",
                "OrderApi/OrderDetailsDelete", "OrderApi/UpdateQuantity",
                "ItemAllocationApi/ItemAllocation", "StartUpApi/AddStartUpPopup",
                "AccountCardsApi/AccountCards", "ProductSuggestionApi/Add",
                "ReturnOrderApi/ValidReturnItem", "ReturnOrderApi/OrderListPickupProcessed",
                "ReturnOrderApi/OrderListPickupProcessedByItem", "ReturnOrderApi/AddReturnOrder",
                "ReturnOrderApi/ApprovePending", "ReturnOrderApi/DeleteReturnApprovePending",
                "ReturnOrderApi/DeleteReturnRejected", "ReturnOrderApi/Rejected",
                "orderlogsApi/orderlogs",
            ]
        },
        "probe_login": {
            "default": "disabled",
            "allowed_now": policy.allowed,
            "opt_in_env": PROBE_ENV_ALLOW,
            "delay_ms_env": PROBE_ENV_DELAY_MS,
            "min_delay_ms": policy.delay_ms,
            "max_attempts_per_run": policy.max_attempts,
            "gate": {
                "basis": PROBE_GATE.basis,
                "purpose": PROBE_GATE.purpose,
                "owner": PROBE_GATE.owner,
                "approved_on": PROBE_GATE.approved_on,
                "note": PROBE_GATE.note,
            },
        }
    })))
}

// ====== Helpers ======

fn extract_string(args: &[Value], idx: usize, name: &str) -> Result<String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(_other) => Err(format!("{name}: expected String")),
        None => Err(format!("{name}: missing at index {idx}")),
    }
}

fn extract_string_opt(args: &[Value], idx: usize, _name: &str) -> Option<String> {
    match args.get(idx) {
        Some(Value::String(s)) => Some(s.clone()),
        _ => None,
    }
}

fn extract_int(args: &[Value], idx: usize, name: &str) -> Result<i128, String> {
    match args.get(idx) {
        Some(Value::Int(n)) => Ok(*n),
        Some(_other) => Err(format!("{name}: expected Int")),
        None => Err(format!("{name}: missing at index {idx}")),
    }
}

fn serde_json_to_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i as i128)
            } else {
                Value::Float(n.as_f64().unwrap_or(0.0))
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(arr) => Value::Array(arr.iter().map(serde_json_to_value).collect()),
        serde_json::Value::Object(obj) => {
            let entries: Vec<(Value, Value)> = obj
                .iter()
                .map(|(k, v)| (Value::String(k.clone()), serde_json_to_value(v)))
                .collect();
            Value::Map(entries)
        }
    }
}

// ====== Tests ======
//
// All tests are offline: they exercise the gate/rate-limit policy and error
// surfacing, never the live third-party API.

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_allowing(max_attempts: u64) -> ProbePolicy {
        ProbePolicy {
            allowed: true,
            delay_ms: PROBE_MIN_DELAY_MS,
            max_attempts,
        }
    }

    #[test]
    fn probe_off_by_default_and_refused() {
        // A policy with `allowed: false` (the default) must refuse the range
        // before any I/O, naming the opt-in env var and the gate.
        let policy = ProbePolicy {
            allowed: false,
            delay_ms: PROBE_MIN_DELAY_MS,
            max_attempts: PROBE_MAX_ATTEMPTS,
        };
        let err = policy.check(100_000, 100_001).unwrap_err();
        assert!(err.contains(PROBE_ENV_ALLOW), "err should name the opt-in env: {err}");
        assert!(err.contains("disabled by default"), "err should say disabled: {err}");

        // And the dispatch entry point refuses when the env opt-in is unset/off.
        if std::env::var(PROBE_ENV_ALLOW)
            .map(|v| v.trim() == "1")
            .unwrap_or(false)
        {
            return; // externally opted in — nothing to prove here
        }
        let result = dispatch(
            "brute_login",
            vec![Value::Int(100_000), Value::Int(100_001)],
        );
        assert!(
            matches!(result, Some(Err(_))),
            "brute_login must refuse when opt-in env is unset, got {result:?}"
        );
    }

    #[test]
    fn probe_attempt_cap_enforced_before_io() {
        // Even with the opt-in granted, a range wider than the mandatory cap
        // must be refused up front (rate limit: max attempts).
        let policy = policy_allowing(PROBE_MAX_ATTEMPTS);
        let err = policy.check(0, 999_999).unwrap_err();
        assert!(err.contains("cap"), "err should mention the cap: {err}");
        assert!(
            err.contains(PROBE_MAX_ATTEMPTS.to_string().as_str()),
            "err should name the cap value: {err}"
        );

        let err = policy.check(0, PROBE_MAX_ATTEMPTS as i128).unwrap_err();
        assert!(err.contains("exceeding"), "boundary beyond cap must refuse: {err}");

        // Exactly the cap is fine.
        let n = policy
            .check(0, PROBE_MAX_ATTEMPTS as i128 - 1)
            .unwrap();
        assert_eq!(n, PROBE_MAX_ATTEMPTS);

        // Range validation is independent of the opt-in.
        let policy = policy_allowing(100);
        assert!(policy.check(-1, 5).is_err());
        assert!(policy.check(5, 5).is_ok());
        assert!(policy.check(999_999, 1_000_000).is_err());
    }

    #[test]
    fn probe_delay_clamped_to_minimum() {
        // Rate limit: minimum per-attempt delay is mandatory — env overrides
        // below the floor are clamped up, absent values use the floor.
        assert_eq!(ProbePolicy::clamp_delay(None), PROBE_MIN_DELAY_MS);
        assert_eq!(ProbePolicy::clamp_delay(Some("1")), PROBE_MIN_DELAY_MS);
        assert_eq!(ProbePolicy::clamp_delay(Some("0")), PROBE_MIN_DELAY_MS);
        assert_eq!(ProbePolicy::clamp_delay(Some("not-a-number")), PROBE_MIN_DELAY_MS);
        assert_eq!(ProbePolicy::clamp_delay(Some("5000")), 5000);
    }

    #[test]
    fn transport_error_surfaces_as_err_not_ok() {
        // Connect to a closed loopback port: the request must fail and the
        // failure must surface as an Err — never as Ok(String("...error")).
        let result = attempt_login("http://127.0.0.1:1", "123456");
        let err = match result {
            Err(e) => e,
            Ok(v) => panic!("closed-loopback login must not return Ok; got Ok({v:?})"),
        };
        assert!(
            err.contains("request failed"),
            "err should describe the transport failure: {err}"
        );
    }

    #[test]
    fn missing_args_are_honest_errors() {
        assert!(matches!(dispatch("login", vec![]), Some(Err(_))));
        assert!(matches!(dispatch("brute_login", vec![]), Some(Err(_))));
        assert!(matches!(dispatch("get_main_menu", vec![]), Some(Err(_))));
        assert!(dispatch("no_such_fn", vec![]).is_none());
    }

    #[test]
    fn get_config_does_not_export_headers() {
        let v = dispatch("get_config", vec![]).unwrap().unwrap();
        // serde_json objects convert to Value::Map (not a named struct).
        assert!(
            matches!(&v, Value::Map(_)),
            "get_config should return an object map, got {v:?}"
        );
        // Walk every field (incl. nested maps) and assert no header material
        // is present.
        fn walk(value: &Value, needle: &str) -> bool {
            match value {
                Value::String(s) => s.contains(needle),
                Value::Array(items) => items.iter().any(|i| walk(i, needle)),
                Value::Map(entries) => entries
                    .iter()
                    .any(|(k, v)| walk(k, needle) || walk(v, needle)),
                _ => false,
            }
        }
        assert!(
            !walk(&v, "login_header"),
            "get_config must not export login_header"
        );
        assert!(
            !walk(&v, "data_header"),
            "get_config must not export data_header"
        );
        // The value itself must not appear anywhere in the payload.
        assert!(!walk(&v, LOGIN_HEADER), "get_config leaks LOGIN_HEADER value");
        assert!(!walk(&v, DATA_HEADER), "get_config leaks DATA_HEADER value");
    }
}
