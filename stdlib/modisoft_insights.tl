// tallow.modisoft_insights — OWNER-AUTHORIZED Modisoft Insights connector (fail-closed shell).
//
// Pinned auth contract (a2_autharch REPORT §1.1/§2.1, wave9 2026-09-05):
//   POST https://insightsbackn.modisoft.com/account-service/api/login
//     body JSON {"username","password"}
//     -> 200 {isSuccess:true, value:{authToken, username, clientCode}}
//     -> 401 on bad credentials
//   Every data call: header `Authorization: Bearer <authToken>` (token life 5h, no MFA).
//
// ⚠ HARD CONSTRAINTS (non-negotiable — do not bypass, do not add "any store" modes):
//   1. login()/fetch()/logout() REFUSE with Err modisoft_insights:unauthorized:
//      "store <cc>:<sid> not in owned-stores registry" unless that (client_code,
//      store_id) pair is listed in the loaded registry. The check runs BEFORE any
//      secrets-file read and BEFORE any socket is opened.
//   2. Credentials live ONLY in ~/.config/tallow/modisoft_insights.secrets.json
//      (override: TALLOW_MODISOFT_SECRETS), schema
//      {"stores":{"<cc>:<sid>":{"username":"...","password":"..."}}}, and the file
//      MUST be chmod 600 — the module refuses to read it otherwise. Credentials are
//      read inside login() only; they are never printed, logged, stored on a Value,
//      or returned by any function in this module.
//   3. fetch() is GET-only. `path` must start with an allowlisted service prefix
//      (/account-service/, /reports-service/, /fuel-service/, /bank-service/ — the
//      allowlist is a one-line-edit const in the Rust module) and must not contain
//      "..", "?", "#", or whitespace. `params` are urlencoded (k=v&...) — no raw
//      query injection.
//   4. Sessions are in-memory only (per interpreter process), keyed (cc, sid).
//
// Paths: owned-stores registry = $TALLOW_OWNED_STORES else
//        ~/.config/tallow/owned_stores.json, schema
//        {"stores":[{"client_code":109490,"store_id":23,"display_name":"...","owner_note":"..."}]}
//        load_registry() returns the count of owned stores.
// Base URL override (re-pin point): $TALLOW_MODISOFT_INSIGHTS_BASE.
//
// Error prefixes (stable for .tl matching): modisoft_insights:unauthorized:
// modisoft_insights:registry: | secrets: | not_logged_in: | param: | http:<code>: | net: | login:
//
// Driver note: any .tl function that calls login()/fetch() (network I/O) must carry
//   @legal(basis: .consent, consent_ref: "...owner-authorized...", ...) + @cra_class(.default).
// See examples/modisoft_insights_owned_fetch.tl.
//
// ── Quick start (owner only) ──────────────────────────────────────────────
//   1. Write your owned-stores registry (see examples/owned_stores.example.json):
//        ~/.config/tallow/owned_stores.json   (or export TALLOW_OWNED_STORES=...)
//      {"stores":[{"client_code":109490,"store_id":23,"display_name":"...","owner_note":"..."}]}
//   2. Write the secrets file (see examples/modisoft_insights.secrets.example.json):
//        ~/.config/tallow/modisoft_insights.secrets.json  (or export TALLOW_MODISOFT_SECRETS=...)
//      {"stores":{"<cc>:<sid>":{"username":"...","password":"..."}}}
//      then:  chmod 600 ~/.config/tallow/modisoft_insights.secrets.json
//   3. load_registry() once, then per store: login(cc, sid) -> fetch(...) -> logout(cc, sid).
//
// ── Example (correct shape; replace cc/sid with your store) ───────────────
//   let n = modisoft_insights.load_registry(nil)
//   if !modisoft_insights.is_owned(109490, 23) { print("not owned"); return }
//   let ok = modisoft_insights.login(109490, 23)
//   let body = modisoft_insights.fetch(109490, 23, "/reports-service/api/business-types", Map())
//   let data = body.parse_json()
//   modisoft_insights.logout(109490, 23)
//
// ── .tl error handling ────────────────────────────────────────────────────
// Functions here return Err(String) (modisoft_insights:* prefixes) on refusal
// and failure; unhandled Errs surface as interpreter runtime errors. 401 login
// failures return Bool false instead (never the reason). fetch() bodies are raw
// JSON strings — parse with .parse_json().


/// Load (and replace) the owned-stores registry. `path` nil -> $TALLOW_OWNED_STORES
/// -> ~/.config/tallow/owned_stores.json. Returns the number of owned stores;
/// Err if the file is missing or malformed. Required before any credentialed call.
native fn load_registry(path: String?) -> Int

/// True when (client_code, store_id) is listed in the loaded registry.
/// Pure membership test — no file I/O, no auth.
native fn is_owned(client_code: Int, store_id: Int) -> Bool

/// List owned stores as [Map] rows {client_code, store_id, display_name, owner_note}.
/// Registry data only — never contains credential material.
native fn owned_stores() -> [Map]

/// Login for ONE owned store. Refuses (Err unauthorized) unless the store is in the
/// registry; refuses (Err secrets) unless the secrets file is chmod 600 and holds a
/// "<cc>:<sid>" entry. On success stores the authToken in memory and returns true.
/// Bad credentials (HTTP 401) -> false (never the reason). Do NOT call for stores
/// you do not own — the registry gate exists precisely to make that impossible.
native fn login(client_code: Int, store_id: Int) -> Bool

/// True when an in-memory session token is held for this owned store.
/// Pure check — no network.
native fn logged_in(client_code: Int, store_id: Int) -> Bool

/// GET-only data fetch for ONE owned, logged-in store. `path` must start with an
/// allowlisted service prefix (/account-service/, /reports-service/, /fuel-service/,
/// /bank-service/) with no ".." / "?" / "#" / whitespace; `params` Map values
/// (String/Int/Float/Bool) are urlencoded into the query string. Returns the raw
/// JSON body (use .parse_json()). 401 clears the session (5h token life).
native fn fetch(client_code: Int, store_id: Int, path: String, params: Map) -> String

/// Drop the in-memory session token for the store. Registry-gated like login/fetch.
native fn logout(client_code: Int, store_id: Int)
