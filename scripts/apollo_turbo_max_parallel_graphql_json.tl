// ============================================================================
// Apollo Turbo GraphQL/JSON Fallback Check (L4 -> L5)
// ============================================================================
// Purpose:
//   Run L4 first and escalate to L5 only if L4 is not usable.
//   This script is compliance-safe: no auth bypass behavior.
//
// Outputs:
//   apollo_turbo_max_parallel_graphql_json.csv
//   apollo_turbo_max_parallel_graphql_json_summary.txt
//
// Notes:
//   - 401/403 means authorized credentials are required.
//   - L5 does not bypass auth-gated Apollo APIs.
// ============================================================================

@legal(basis: .public_data, purpose: "apollo L4 then L5 graphql/json reachability check")
fn main() {
    print("=== Apollo Turbo GraphQL/JSON Check (L4 -> L5) ===")

    let l4_concurrency = 3
    let l5_concurrency = 200

    let base_urls = [
        "https://www.apollo.io/",
        "https://www.apollo.io/robots.txt",
        "https://app.apollo.io/",
        "https://app.apollo.io/#/login",
        "https://app.apollo.io/graphql",
        "https://app.apollo.io/api/graphql",
        "https://api.apollo.io/graphql",
        "https://app.apollo.io/api/v1/auth/login",
        "https://app.apollo.io/api/v1/organizations/search",
        "https://app.apollo.io/api/v1/people/search"
    ]

    let headers = {
        "Accept": "application/json, text/plain, */*",
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Referer": "https://app.apollo.io/"
    }

    // 3 waves keeps volume bounded while still exercising turbo batching.
    var urls = ["__init__"]
    var wave = 0
    while wave < 3 {
        for u in base_urls {
            urls = urls.push(u)
        }
        wave = wave + 1
    }
    urls = urls.slice(1, urls.len)

    var lines = ["phase,url,status,body_len,is_json,is_graphql,auth_blocked"]

    // -----------------------------
    // Phase 1: L4
    // -----------------------------
    print("[1/4] L4 wave (concurrency=" + l4_concurrency.to_string() + ") over " + urls.len.to_string() + " URLs...")
    let l4_responses = http.batch(urls, l4_concurrency, headers)

    var l4_ok200 = 0
    var l4_status_zero = 0
    var l4_auth_blocked = 0
    var l4_rate_limited = 0
    var l4_server_error = 0
    var l4_other_status = 0
    var l4_json_ok = 0
    var l4_graphql_rows = 0

    for r in l4_responses {
        if r.status == 200 {
            l4_ok200 = l4_ok200 + 1
        } else {
            if r.status == 0 {
                l4_status_zero = l4_status_zero + 1
            } else {
                if r.status == 401 || r.status == 403 {
                    l4_auth_blocked = l4_auth_blocked + 1
                } else {
                    if r.status == 429 {
                        l4_rate_limited = l4_rate_limited + 1
                    } else {
                        if r.status >= 500 {
                            l4_server_error = l4_server_error + 1
                        } else {
                            l4_other_status = l4_other_status + 1
                        }
                    }
                }
            }
        }

        var is_graphql = "0"
        if r.url.contains("graphql") || r.url.contains("operationName=") {
            is_graphql = "1"
            l4_graphql_rows = l4_graphql_rows + 1
        }

        var auth_mark = "0"
        if r.status == 401 || r.status == 403 {
            auth_mark = "1"
        }

        let p = r.body.parse_json()
        var is_json = "0"
        if !p.is_err() {
            is_json = "1"
            l4_json_ok = l4_json_ok + 1
        }

        lines = lines.push(
            "L4," +
            r.url + "," +
            r.status.to_string() + "," +
            r.body.len().to_string() + "," +
            is_json + "," +
            is_graphql + "," +
            auth_mark
        )
    }

    // -----------------------------
    // Decide whether to escalate
    // -----------------------------
    var run_l5 = false
    var decision_note = "L4_OK"
    if l4_auth_blocked > 0 {
        run_l5 = false
        decision_note = "AUTH_REQUIRED_AT_L4"
    } else {
        if l4_status_zero > 0 {
            run_l5 = true
            decision_note = "L4_TRANSPORT_BLOCKED_TRY_L5"
        } else {
            if l4_ok200 == 0 || l4_json_ok == 0 {
                run_l5 = true
                decision_note = "L4_NOT_USABLE_TRY_L5"
            }
        }
    }

    // -----------------------------
    // Phase 2: L5 (optional)
    // -----------------------------
    var l5_executed = 0
    var l5_ok200 = 0
    var l5_status_zero = 0
    var l5_auth_blocked = 0
    var l5_rate_limited = 0
    var l5_server_error = 0
    var l5_other_status = 0
    var l5_json_ok = 0
    var l5_graphql_rows = 0

    if run_l5 {
        l5_executed = 1
        print("[2/4] L5 wave (concurrency=" + l5_concurrency.to_string() + ")...")
        let l5_responses = http.batch(urls, l5_concurrency, headers)

        for r2 in l5_responses {
            if r2.status == 200 {
                l5_ok200 = l5_ok200 + 1
            } else {
                if r2.status == 0 {
                    l5_status_zero = l5_status_zero + 1
                } else {
                    if r2.status == 401 || r2.status == 403 {
                        l5_auth_blocked = l5_auth_blocked + 1
                    } else {
                        if r2.status == 429 {
                            l5_rate_limited = l5_rate_limited + 1
                        } else {
                            if r2.status >= 500 {
                                l5_server_error = l5_server_error + 1
                            } else {
                                l5_other_status = l5_other_status + 1
                            }
                        }
                    }
                }
            }

            var is_graphql2 = "0"
            if r2.url.contains("graphql") || r2.url.contains("operationName=") {
                is_graphql2 = "1"
                l5_graphql_rows = l5_graphql_rows + 1
            }

            var auth_mark2 = "0"
            if r2.status == 401 || r2.status == 403 {
                auth_mark2 = "1"
            }

            let p2 = r2.body.parse_json()
            var is_json2 = "0"
            if !p2.is_err() {
                is_json2 = "1"
                l5_json_ok = l5_json_ok + 1
            }

            lines = lines.push(
                "L5," +
                r2.url + "," +
                r2.status.to_string() + "," +
                r2.body.len().to_string() + "," +
                is_json2 + "," +
                is_graphql2 + "," +
                auth_mark2
            )
        }
    } else {
        print("[2/4] L5 wave skipped: " + decision_note)
    }

    // -----------------------------
    // Final recommendation
    // -----------------------------
    var selected_level = "L4Full"
    var final_note = "L4 was usable"

    if l4_auth_blocked > 0 || l5_auth_blocked > 0 {
        selected_level = "AUTH_REQUIRED"
        final_note = "Auth-gated endpoints detected; use authorized Apollo credentials/API access"
    } else {
        if l5_executed == 1 {
            if l5_status_zero > 0 {
                selected_level = "UNKNOWN"
                final_note = "Transport/network blocked in runtime; rerun where outbound network is allowed"
            } else {
                if l5_ok200 > 0 && l5_json_ok > 0 {
                    selected_level = "L5Maximum"
                    final_note = "L4 was not usable; L5 produced usable responses"
                } else {
                    selected_level = "UNKNOWN"
                    final_note = "L5 did not produce usable JSON responses"
                }
            }
        } else {
            if l4_status_zero > 0 {
                selected_level = "UNKNOWN"
                final_note = "Transport/network blocked at L4; L5 was not meaningful to run"
            } else {
                if l4_ok200 > 0 && l4_json_ok > 0 {
                    selected_level = "L4Full"
                    final_note = "L4 usable; no need to escalate"
                } else {
                    selected_level = "L5Maximum"
                    final_note = "L4 not usable; escalate to L5 on next run"
                }
            }
        }
    }

    // -----------------------------
    // Write artifacts
    // -----------------------------
    print("[3/4] Writing CSV...")
    write_file("apollo_turbo_max_parallel_graphql_json.csv", lines.join("\n"))

    print("[4/4] Writing summary...")
    var summary = ["__init__"]
    summary = summary.push("execution_plan=L4_then_L5_if_needed")
    summary = summary.push("l4_concurrency=" + l4_concurrency.to_string())
    summary = summary.push("l5_concurrency=" + l5_concurrency.to_string())
    summary = summary.push("l5_executed=" + l5_executed.to_string())
    summary = summary.push("decision_note=" + decision_note)

    summary = summary.push("l4_total_requests=" + l4_responses.len.to_string())
    summary = summary.push("l4_status_200=" + l4_ok200.to_string())
    summary = summary.push("l4_status_0_transport=" + l4_status_zero.to_string())
    summary = summary.push("l4_auth_blocked_401_403=" + l4_auth_blocked.to_string())
    summary = summary.push("l4_rate_limited_429=" + l4_rate_limited.to_string())
    summary = summary.push("l4_server_error_5xx=" + l4_server_error.to_string())
    summary = summary.push("l4_other_status=" + l4_other_status.to_string())
    summary = summary.push("l4_graphql_rows=" + l4_graphql_rows.to_string())
    summary = summary.push("l4_json_parse_ok=" + l4_json_ok.to_string())

    if l5_executed == 1 {
        summary = summary.push("l5_total_requests=" + urls.len.to_string())
        summary = summary.push("l5_status_200=" + l5_ok200.to_string())
        summary = summary.push("l5_status_0_transport=" + l5_status_zero.to_string())
        summary = summary.push("l5_auth_blocked_401_403=" + l5_auth_blocked.to_string())
        summary = summary.push("l5_rate_limited_429=" + l5_rate_limited.to_string())
        summary = summary.push("l5_server_error_5xx=" + l5_server_error.to_string())
        summary = summary.push("l5_other_status=" + l5_other_status.to_string())
        summary = summary.push("l5_graphql_rows=" + l5_graphql_rows.to_string())
        summary = summary.push("l5_json_parse_ok=" + l5_json_ok.to_string())
    } else {
        summary = summary.push("l5_total_requests=0")
        summary = summary.push("l5_status_200=0")
        summary = summary.push("l5_status_0_transport=0")
        summary = summary.push("l5_auth_blocked_401_403=0")
        summary = summary.push("l5_rate_limited_429=0")
        summary = summary.push("l5_server_error_5xx=0")
        summary = summary.push("l5_other_status=0")
        summary = summary.push("l5_graphql_rows=0")
        summary = summary.push("l5_json_parse_ok=0")
    }

    summary = summary.push("selected_level=" + selected_level)
    summary = summary.push("final_note=" + final_note)
    summary = summary.push("note=401/403 means authorized Apollo credentials/API access is required.")
    summary = summary.slice(1, summary.len)
    write_file("apollo_turbo_max_parallel_graphql_json_summary.txt", summary.join("\n"))

    print("")
    print("=== DONE ===")
    print("Selected level: " + selected_level)
    print("CSV:     apollo_turbo_max_parallel_graphql_json.csv")
    print("Summary: apollo_turbo_max_parallel_graphql_json_summary.txt")
}
