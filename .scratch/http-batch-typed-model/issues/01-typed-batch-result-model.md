# Typed batch result model for `http.batch` (`BatchResponse` / `HttpError`)

Status: **open — needs the operator's direction.** Filed 2026-10-16 from the CI-wiring work.

## Why it exists

Wiring `tests/http_result_model.rs` into CI surfaced that the suite asserts a typed per-URL result model
that **exists nowhere in the tree**: `rg -c 'BatchResponse|HttpError' src/stdlib/http.rs src/interp.rs
stdlib/http.tl` returns zero matches in all three. The runtime returns `Response` structs and raw
`Err`/`Value::Err` values instead.

The model is not an invention of the test — it is demanded by three independent places:

| where | what it requires |
|---|---|
| `tests/http_result_model.rs:119,141-144,162-164` | `BatchResponse{url, ok, attempts, elapsed_ms, response: Response?, error: HttpError?}`; `HttpError{kind, url, status, retryable, message}`, with `kind` = `http_4xx` for a 404 and `transport` for a connection failure, and `message` containing `http.get` |
| `tests/http_result_model.rs:171-175` | `stdlib/http.tl` must declare `struct HttpError`, `struct BatchResponse`, `response: Response?`, `error: HttpError?`, and `fn batch(target_urls: []String, concurrency: i64, headers: Map<String, String>) -> []BatchResponse` |
| `tests/test_phase2_request_plan_builder.py:139,176` | the `.tl` text must contain `http.batch(target_urls` |

The stub's current declaration — `native fn batch(urls: [String], concurrency: Int) -> [Response]` — is simply
behind the contract its own suite and a Python twin already state.

## Current measured state

```
http_result_model         0 passed / 3 failed
  http_batch_returns_typed_success_and_http_error_results   left: "Response"   right: "BatchResponse"
  http_batch_returns_typed_transport_error_without_panicking   Err("http.get: io: Connection refused")
  http_tl_declares_typed_batch_result_model                    http_tl.contains("struct HttpError") == false
```

Note what is **already fixed and not part of this item**: the loopback path. Those failures used to read
`SOCKS error`/`connection not allowed by ruleset` and now read `io: Connection refused`, i.e. the request
reaches a real socket. The remaining gap is the model, not the transport.

## The landmine (why this is not a 20-line change)

Pointer (c) is easy to miss: the suite expects a **404 to arrive as a typed `http_4xx` carrying a `Response`
whose body is readable** (`response_body_text(response) == "missing-body"`). `http.rs` builds its agent with
`ureq::Agent::config_builder()` and does not disable `http_status_as_error`, so ureq's default turns 4xx/5xx
into `Err` before the response body is reachable. Satisfying the suite therefore requires
`.http_status_as_error(false)` on the agent (or an equivalent per-call handling) — and that **changes the
error semantics of `http.get`/`http.post` for every non-2xx response tree-wide**, not only inside batch. Every
current caller that branches on `Err` for a 4xx silently changes behaviour.

That cross-cutting effect is the reason this is filed rather than implemented in passing.

## Work list

1. **Decide the direction.** Authoring the model aligns the tree with its own three-way documented contract;
   the alternative is relaxing three assertions, which deletes a stated contract. Recommendation: author it.
2. **`src/stdlib/http.rs::http_batch` (line 651)** — wrap each per-URL outcome: success →
   `BatchResponse{ok:true, attempts:1, elapsed_ms, response:<the Response>, error:nil}`; non-2xx →
   `ok:false` with `HttpError{kind:"http_4xx"|"http_5xx", status:Some(n), retryable:false}` and the `Response`
   still attached; transport failure → `ok:false, response:nil, error:HttpError{kind:"transport",
   status:nil, retryable:true, message:<text containing "http.get">}`.
3. **Agent config** — decide and document the `http_status_as_error` policy, including its effect on the
   non-batch paths, and check the other suites that assert on 4xx behaviour before landing it.
4. **`stdlib/http.tl`** — declare `HttpError` and `BatchResponse` with the field shapes above, and change the
   batch signature to the 3-argument `target_urls` form the two tests name. Keep the rest of the stub as-is.
5. **Verify** — `cargo test --locked --no-fail-fast --test http_result_model` (expect 3 passed) plus
   `cargo test --locked --lib http` for regression, plus the Python twins
   (`test_phase2_request_plan_builder.py`, `test_phase2_stdlib_surface_manifest.py`), then promote the suite
   out of the `contract-cli` job's exclusion list into its target list.

## Provenance

Filed while wiring `.github/workflows/ci.yml`'s `contract-cli` job and fixing the four suites it surfaced.
`pkg_cli` and `sec1_honesty_sweep` were fixed and promoted; `request_plan_cli` stays parked (U-218 — its verbs
never existed on any ref). This is the third and last of that set.
