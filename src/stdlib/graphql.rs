//! Standard library: `tallow.graphql` — GraphQL auto-discovery and querying.
//!
//! Detects GraphQL endpoints via URL pattern matching, runs introspection
//! queries, and executes standard GraphQL POST requests.

use super::StdlibResult;
use crate::interp::{type_name, Value};

/// Dispatch static function calls: graphql.graphql_detect, graphql.graphql_introspect, graphql.graphql_query
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "graphql_detect" => Some(graphql_detect(args)),
        "graphql_introspect" => Some(graphql_introspect(args)),
        "graphql_query" => Some(graphql_query(args)),
        _ => None,
    }
}

/// Dispatch method calls on GraphqlEndpoint, GraphqlResult structs.
pub fn dispatch_method(object: &Value, method: &str, _args: Vec<Value>) -> Option<StdlibResult> {
    let Value::Struct { name, .. } = object else {
        return None;
    };
    match name.as_str() {
        "GraphqlEndpoint" | "GraphqlResult" => match method {
            _ => None,
        },
        _ => None,
    }
}

/// Detect GraphQL endpoints by scanning common URL patterns and searching page HTML.
fn graphql_detect(args: Vec<Value>) -> StdlibResult {
    let page_url = match args.first() {
        Some(Value::String(s)) => s.clone(),
        Some(other) => {
            return Err(format!(
                "graphql.graphql_detect: expected String argument, got {}",
                type_name(other)
            ));
        }
        None => {
            return Err("graphql.graphql_detect: missing page_url argument".to_string());
        }
    };

    // Parse the base URL
    let base = extract_base_url(&page_url);

    let mut endpoints: Vec<Value> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // Phase 1: Fetch the page HTML and search for GraphQL references
    let mut discovered_paths: Vec<String> = Vec::new();
    if let Ok(response) = crate::runtime::egress_http::get(&page_url)
        .header("Accept", "text/html,application/json")
        .header("User-Agent", "Tallow-GraphQL-Discovery/1.0")
        .call()
    {
        if let Ok(html) = response.into_body().read_to_string() {
            // Search <script> tags for src attributes containing /graphql
            for cap in find_html_attribute_values(&html, "script", "src") {
                if cap.contains("/graphql") || cap.contains("/gql") {
                    if let Some(resolved) = resolve_url(&base, &cap) {
                        discovered_paths.push(resolved);
                    }
                }
            }
            // Search <link> tags for href attributes containing /graphql
            for cap in find_html_attribute_values(&html, "link", "href") {
                if cap.contains("/graphql") || cap.contains("/gql") {
                    if let Some(resolved) = resolve_url(&base, &cap) {
                        discovered_paths.push(resolved);
                    }
                }
            }
            // Search text for fetch/XHR patterns referencing /graphql
            // Look for patterns like: fetch('/graphql'), "/graphql", '/graphql', `graphql`
            for pat in &["/graphql", "/gql", "/api/graphql", "/v1/graphql"] {
                if html.contains(pat) {
                    let full = format!("{}{}", base.trim_end_matches('/'), pat);
                    if !discovered_paths.contains(&full) {
                        discovered_paths.push(full);
                    }
                }
            }
        }
    }

    // Add discovered paths to the probe list (deduplicated by the seen set below)
    let common_paths = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/v2/graphql",
        "/gql",
        "/query",
        "/api",
        "/graphql/",
    ];

    // Build a combined list: discovered paths first, then common paths
    let mut all_paths: Vec<String> = discovered_paths;
    for path in &common_paths {
        let url = format!("{base}{}", path.trim_start_matches('/'));
        if !all_paths.contains(&url) {
            all_paths.push(url);
        }
    }

    for url in &all_paths {
        if seen.contains(url) {
            continue;
        }
        seen.insert(url.clone());

        // Probe the endpoint with a simple GET request
        let probe_result = probe_graphql_endpoint(url);

        if probe_result {
            endpoints.push(Value::Struct {
                name: "GraphqlEndpoint".to_string(),
                fields: vec![
                    ("url".to_string(), Value::String(url.clone())),
                    ("schema".to_string(), Value::Nil),
                    ("queries".to_string(), Value::Array(vec![])),
                ],
            });
        }
    }

    Ok(Value::Array(endpoints))
}

/// Extract attribute values from HTML tags (e.g., src from <script>, href from <link>).
fn find_html_attribute_values(html: &str, tag: &str, attr: &str) -> Vec<String> {
    let mut results = Vec::new();
    let tag_lower = html.to_lowercase();
    let open_tag = format!("<{}", tag);

    let mut search_start = 0usize;
    while let Some(tag_pos) = tag_lower[search_start..].find(&open_tag) {
        let abs_pos = search_start + tag_pos;
        let tag_content = &html[abs_pos..];
        // Find the end of this tag
        let tag_end = tag_content.find('>').unwrap_or(tag_content.len());
        let tag_str = &tag_content[..tag_end];

        // Search for attr="value" or attr='value' or attr=value
        let attr_patterns = [
            format!("{}=", attr),
            format!("{} =", attr),
        ];
        for pat in &attr_patterns {
            if let Some(attr_pos) = tag_str.to_lowercase().find(&pat.to_lowercase()) {
                let after = &tag_str[attr_pos + pat.len()..].trim_start();
                let value = if after.starts_with('"') {
                    let end = after[1..].find('"').map(|e| e + 2);
                    end.map(|e| &after[1..e - 1])
                } else if after.starts_with('\'') {
                    let end = after[1..].find('\'').map(|e| e + 2);
                    end.map(|e| &after[1..e - 1])
                } else {
                    let end = after.find(|c: char| c.is_whitespace() || c == '>');
                    end.map(|e| &after[..e])
                };
                if let Some(v) = value {
                    if !v.is_empty() {
                        results.push(v.to_string());
                        break;
                    }
                }
            }
        }

        search_start = abs_pos + tag_end + 1;
        if search_start >= html.len() {
            break;
        }
    }
    results
}

/// Resolve a potentially relative URL against a base URL.
fn resolve_url(base: &str, href: &str) -> Option<String> {
    if href.starts_with("http://") || href.starts_with("https://") {
        return Some(href.to_string());
    }
    if href.starts_with("//") {
        let scheme = if base.starts_with("https://") { "https:" } else { "http:" };
        return Some(format!("{}{}", scheme, href));
    }
    if href.starts_with('/') {
        // Absolute path relative to origin
        let origin = extract_origin(base)?;
        return Some(format!("{}{}", origin, href));
    }
    // Relative path — join with base directory
    let base_dir = if base.ends_with('/') {
        base.to_string()
    } else {
        let last_slash = base.rfind('/')?;
        base[..=last_slash].to_string()
    };
    Some(format!("{}{}", base_dir, href))
}

/// Extract the origin (scheme://host[:port]) from a URL.
fn extract_origin(url: &str) -> Option<String> {
    let colon = url.find("://")?;
    let after = &url[colon + 3..];
    let slash = after.find('/').unwrap_or(after.len());
    Some(url[..colon + 3 + slash].to_string())
}

/// Run an introspection query against a GraphQL endpoint.
fn graphql_introspect(args: Vec<Value>) -> StdlibResult {
    let endpoint_url = match args.first() {
        Some(Value::String(s)) => s.clone(),
        Some(other) => {
            return Err(format!(
                "graphql.graphql_introspect: expected String argument, got {}",
                type_name(other)
            ));
        }
        None => {
            return Err(
                "graphql.graphql_introspect: missing endpoint_url argument".to_string(),
            );
        }
    };

    let introspection_query = r#"{"query":"{ __schema { types { name kind } } }"}"#;

    match send_graphql_post(&endpoint_url, introspection_query) {
        Ok(response) => {
            let schema: Value = match serde_json::from_str::<serde_json::Value>(&response) {
                Ok(v) => json_to_value(&v),
                Err(_) => Value::String(response),
            };

            Ok(Value::Struct {
                name: "GraphqlEndpoint".to_string(),
                fields: vec![
                    ("url".to_string(), Value::String(endpoint_url)),
                    ("schema".to_string(), schema),
                    ("queries".to_string(), Value::Array(vec![])),
                ],
            })
        }
        Err(e) => Err(format!("graphql.graphql_introspect: {e}")),
    }
}

/// Execute a GraphQL query against an endpoint.
fn graphql_query(args: Vec<Value>) -> StdlibResult {
    if args.len() < 2 {
        return Err(
            "graphql.graphql_query: requires (endpoint_url, query, variables?)".to_string(),
        );
    }

    let endpoint_url = match &args[0] {
        Value::String(s) => s.clone(),
        other => {
            return Err(format!(
                "graphql.graphql_query: expected String endpoint, got {}",
                type_name(other)
            ));
        }
    };

    let query = match &args[1] {
        Value::String(s) => s.clone(),
        other => {
            return Err(format!(
                "graphql.graphql_query: expected String query, got {}",
                type_name(other)
            ));
        }
    };

    // Build variables JSON
    let variables_json = if args.len() > 2 {
        match &args[2] {
            Value::Map(entries) => {
                let mut obj = serde_json::Map::new();
                for (k, v) in entries {
                    let key = match k {
                        Value::String(s) => s.clone(),
                        other => other.to_string(),
                    };
                    let json_val = value_to_json(v);
                    obj.insert(key, json_val);
                }
                serde_json::to_string(&obj).unwrap_or_else(|_| "{}".to_string())
            }
            _ => "{}".to_string(),
        }
    } else {
        "{}".to_string()
    };

    let gql_payload = serde_json::json!({
        "query": query,
        "variables": serde_json::from_str::<serde_json::Value>(&variables_json).unwrap_or(serde_json::Value::Object(serde_json::Map::new())),
    });
    let payload_str = gql_payload.to_string();

    match send_graphql_post(&endpoint_url, &payload_str) {
        Ok(response) => Ok(Value::Struct {
            name: "GraphqlResult".to_string(),
            fields: vec![
                ("endpoint".to_string(), Value::String(endpoint_url)),
                ("query".to_string(), Value::String(query)),
                ("data".to_string(), Value::String(response)),
            ],
        }),
        Err(e) => Err(format!("graphql.graphql_query: {e}")),
    }
}

/// Probe whether a URL is a GraphQL endpoint by sending a GET request.
/// A GraphQL endpoint typically responds with a specific content-type or
/// responds to the introspection query pattern.
fn probe_graphql_endpoint(url: &str) -> bool {
    // Use ureq for a quick GET probe
    let response = crate::runtime::egress_http::get(url)
        .header("Accept", "application/json")
        .header("User-Agent", "Tallow-GraphQL-Discovery/1.0")
        .call();

    match response {
        Ok(resp) => {
            let status = resp.status().as_u16();
            let content_type = resp
                .headers()
                .get("Content-Type")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();

            // GraphQL endpoints typically return 200 or 400 (bad query, but valid endpoint)
            // with application/json content type
            if (status == 200 || status == 400) && content_type.contains("application/json") {
                return true;
            }

            // Also check response body for GraphQL-specific error messages
            if let Ok(body) = resp.into_body().read_to_string() {
                if body.contains("query") || body.contains("mutation") || body.contains("__schema")
                {
                    return true;
                }
            }

            false
        }
        Err(_) => false,
    }
}

/// Send a GraphQL POST request.
fn send_graphql_post(url: &str, body: &str) -> Result<String, String> {
    let response = crate::runtime::egress_http::post(url)
        .header("Content-Type", "application/json")
        .header("Accept", "application/json")
        .header("User-Agent", "Tallow-GraphQL-Client/1.0")
        .send(body.as_bytes())
        .map_err(|e| format!("HTTP request failed: {e}"))?;

    let status = response.status().as_u16();
    let resp_body = response
        .into_body()
        .read_to_string()
        .map_err(|e| format!("failed to read response: {e}"))?;

    if status >= 200 && status < 300 {
        Ok(resp_body)
    } else {
        Err(format!("GraphQL server returned status {status}: {resp_body}"))
    }
}

/// Extract the base URL from a full page URL.
fn extract_base_url(page_url: &str) -> String {
    // Strip path, keep scheme and host
    if let Some(colon) = page_url.find("://") {
        let after_scheme = &page_url[colon + 3..];
        if let Some(slash) = after_scheme.find('/') {
            page_url[..colon + 3 + slash].to_string()
        } else {
            if !page_url.ends_with('/') {
                format!("{page_url}/")
            } else {
                page_url.to_string()
            }
        }
    } else {
        // No scheme, assume https
        format!("https://{page_url}/")
    }
}

/// Convert a serde_json Value to Tallow Value.
fn json_to_value(v: &serde_json::Value) -> Value {
    match v {
        serde_json::Value::Null => Value::Nil,
        serde_json::Value::Bool(b) => Value::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Value::Int(i as i128)
            } else if let Some(f) = n.as_f64() {
                Value::Float(f)
            } else {
                Value::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => Value::String(s.clone()),
        serde_json::Value::Array(arr) => {
            Value::Array(arr.iter().map(json_to_value).collect())
        }
        serde_json::Value::Object(obj) => {
            let entries: Vec<(Value, Value)> =
                obj.iter().map(|(k, v)| (Value::String(k.clone()), json_to_value(v))).collect();
            Value::Map(entries)
        }
    }
}

/// Convert a Tallow Value to serde_json Value.
fn value_to_json(v: &Value) -> serde_json::Value {
    match v {
        Value::Nil => serde_json::Value::Null,
        Value::Bool(b) => serde_json::Value::Bool(*b),
        Value::Int(i) => {
            // serde_json::Number doesn't implement From<i128>, so cast to i64
            serde_json::Value::Number(serde_json::Number::from(*i as i64))
        }
        Value::Float(f) => {
            if let Some(n) = serde_json::Number::from_f64(*f) {
                serde_json::Value::Number(n)
            } else {
                serde_json::Value::String(f.to_string())
            }
        }
        Value::String(s) => serde_json::Value::String(s.clone()),
        Value::Array(items) => {
            serde_json::Value::Array(items.iter().map(value_to_json).collect())
        }
        Value::Map(entries) => {
            let mut obj = serde_json::Map::new();
            for (k, v) in entries {
                let key = match k {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                obj.insert(key, value_to_json(v));
            }
            serde_json::Value::Object(obj)
        }
        _ => serde_json::Value::String(format!("{v}")),
    }
}
