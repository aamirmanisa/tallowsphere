// tallow.modisoft — public Modisoft data extraction (module A, wave9).
//
// Anonymous (no-auth) extraction for Modisoft convenience-store data, in two
// steps that the census driver composes:
//
//   1. locate(latitude, longitude, order_type_id?) — POST
//      https://cartzie.com/service/OnGetBusinessNearMe and read the nearby
//      stores' ClientCode / StoreId (the only documented anonymous way to map
//      a geo position onto an io-df store identity).
//   2. The io-df battery (https://io-df-api-prod.modisoft.com, GET-only,
//      auth-less, keyed by client_code + store_id):
//        sales_by_week(cc, sid, num_weeks, end_date?)
//        sales_by_department(cc, sid, group_by, limit?, date_from?, date_to?)
//        top_movers(cc, sid, limit?, end_date?)
//        what_needs_you(cc, sid, limit?, min_units?, min_growth?, end_date?)
//        is_live_store(cc, sid)
//
// Conventions
// -----------
// * Every function returns the RAW JSON body as a String; call
//   `let v = raw.parse_json()` in your script to consume it (module-side
//   serde validation already ran — a body that does not match the documented
//   shape is an Err, never silently-passed data).
// * All network calls are paced through a module-local rate governor
//   (GOV_MODISOFT, default 2 rps; override with env TALLOW_MODISOFT_RPS, read
//   once at first use). Retries with exponential backoff on 429/5xx.
// * Error contract — match on these prefixes in .tl:
//     modisoft:http:<status>   non-200 after retries
//     modisoft:net:<cause>     persistent transport failure
//     modisoft:shape:<detail>  response shape mismatch
//     modisoft:param:<detail>  bad argument (wrong type / invalid value)
//
// Legal
// -----
// These are PUBLIC endpoints (locator + keyless forecasting API). Driver
// scripts that call them still need the @legal annotation on their own
// network fns (E0100 otherwise), e.g.
// `@legal(basis:.public_data, purpose:.business_research, rate_limit:2.per_second)`.
//
// Plan: artifacts/modisoft/wave9_2026-09-05/agents/a3_tallow/PLAN.md §3.1.

// Usage sketch (typical census flow; see examples/modisoft_census.tl):
//
//   @legal(basis:.public_data, purpose:.business_research, rate_limit:2.per_second)
//   fn sweep(lat: Float, lng: Float) {
//       let hits = modisoft.locate(lat, lng).parse_json()       // [Map]
//       let cc = hits[0].get("ClientCode")   // locator keys are PascalCase
//       let sid = hits[0].get("StoreId")
//       if !modisoft.is_live_store(cc, sid) { return }          // skip dead hits
//       let wk  = modisoft.sales_by_week(cc, sid, 1).parse_json()
//       let dept = modisoft.sales_by_department(cc, sid, "department", 30).parse_json()
//       let top = modisoft.top_movers(cc, sid, 20).parse_json()
//       log.info(wk.get("total_net_sales"))
//   }
//
// Notes & API quirks (from wave-7/8 captures):
// - `sales_by_department` with `group_by="day"` returns HTTP 400 server-side
//   despite being accepted here — use "week"/"month", or the real values
//   "department" / "department_type" / "category".
// - `what_needs_you` reorder quantities are floats; product_code there is a
//   STRING (zero-padded UPC) while top-movers product_code is an Int.
// - Response struct fields are validated module-side against the documented
//   shapes; unknown/junk fields are stripped on the canonicalized return.
// - The locator response keys are PascalCase (StoreId, ClientCode, …); the
//   io-df battery response keys are snake_case (store_id, client_code, …).


/// Locate Modisoft stores near a coordinate. POSTs
/// https://cartzie.com/service/OnGetBusinessNearMe with
/// {"Latitude":..,"Longitude":..,"OrderTypeId":order_type_id} (defaults 0).
/// Returns a canonical JSON array of store hits — each carrying ClientCode +
/// StoreId plus name/address fields — or "[]" when the server returns none.
fn locate(latitude: Float, longitude: Float, order_type_id: Int?) -> String

/// Weekly net-sales report. GET …/sales-by-week?client_code=…&store_id=…&
/// num_weeks=…[&end_date=YYYY-MM-DD]. num_weeks is clamped into 1..=52
/// (silently). end_date, when given, anchors the trailing week; when omitted
/// the server anchors to today. Returns canonical JSON: {store_id,
/// client_code, anchor_date, num_weeks, currency, total_net_sales, weeks:[
/// {week_label, week_number, week_start, week_end, net_sales, units,
/// transaction_count, is_partial}], generated_at}.
fn sales_by_week(client_code: Int, store_id: Int, num_weeks: Int, end_date: String?) -> String

/// Department-level sales report. GET …/sales-by-department with group_by
/// one of: department | department_type | category (the real server-side
/// vocabulary observed in wave-7 captures — department_type splits by store
/// type, category by merchandise category) plus the plan-draft day | week |
/// month which are forwarded verbatim and left to the server (day 400s
/// server-side; prefer department). limit clamped 1..=100; date_from /
/// date_to optional YYYY-MM-DD period bounds. Returns canonical JSON:
/// {store_id, client_code, group_by, anchor_date, period_start, period_end,
/// currency, total_sales, total_gross_profit, overall_gp_percent, ranked_by,
/// limit, count, items:[{rank, department, sales, gross_profit, gp_percent,
/// units, sales_pct_of_total}]}.
fn sales_by_department(client_code: Int, store_id: Int, group_by: String, limit: Int?, date_from: String?, date_to: String?) -> String

/// Top movers (ranked products) report. GET …/top-movers?client_code=…&
/// store_id=…[&limit=1..=50][&end_date=YYYY-MM-DD]. limit clamped 1..=50 and
/// omitted when nil (server default applies). Returns canonical JSON:
/// {store_id, client_code, anchor_date, current_month, previous_month,
/// comparison_label, ranked_by, currency, limit, count, items:[{rank,
/// product_code, product_name, units_sold, revenue, prev_units_sold,
/// pct_change, direction, is_new}]}.
fn top_movers(client_code: Int, store_id: Int, limit: Int?, end_date: String?) -> String

/// Reorder suggestions ("what needs you") report. GET …/what-needs-you with
/// optional limit (clamped 1..=15), min_units (Int floor), min_growth (Float
/// % floor) and end_date (YYYY-MM-DD). use_model is left at the server
/// default (false) — not exposed here. Returns canonical JSON: {store_id,
/// client_code, count, currency, current_week, previous_week,
/// on_hand_available, forecast_model_used, suggestions:[{title, description,
/// priority, product_code, product_name, department, category, cur_units,
/// prev_units, unit_delta, growth_pct, is_new, forecast_next_week,
/// forecast_source, on_hand, on_hand_source, reorder_qty, est_value}]}.
fn what_needs_you(client_code: Int, store_id: Int, limit: Int?, min_units: Int?, min_growth: Float?, end_date: String?) -> String

/// Cheap liveness probe for a store: true only when a sales-by-week
/// (num_weeks=1) call returns HTTP 200 AND a parseable weekly report; false
/// for 404, 5xx, transport errors, and empty/unparseable bodies. Use this to
/// skip dead locator hits in a census loop.
fn is_live_store(client_code: Int, store_id: Int) -> Bool
