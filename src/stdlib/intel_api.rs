//! `tallow.api` — offline API-surface ingestion and comparison (N13, N14, N20, N21).
//!
//! **Offline by construction.** Nothing here opens a socket, resolves a name, or reads a clock.
//! `openapi_load` parses a document the caller already holds; comparing two inventories is pure
//! over data the caller supplied. Fetching a spec or probing a server belongs to a caller holding
//! a `Grant` — this module is the parser, not the call.
//!
//! # N13 — a document URL is part of the finding
//!
//! Every endpoint carries `source`, the `doc_url` it was parsed from, and an inventory whose
//! `doc_url` is empty is refused (`api:openapi-no-evidence`). "The API has this endpoint" is a
//! claim; "<url> states this endpoint" is evidence, and a row that cannot name its document is
//! not an inventory.
//!
//! The version is detected, never assumed. `swagger: "2.0"` is 2.0, `openapi: "3.0.x"`/`"3.1.x"`
//! is 3.x, and anything else — including a document with neither field — is refused
//! (`api:openapi-version-unsupported`) naming what was actually seen. A templated path keeps its
//! template: `/users/{id}` is recorded as `/users/{id}`, never with a value filled in, so two
//! documents differing only in a sample id describe the same endpoint.
//!
//! Auth is recorded only when declared. A global `security` block applies to operations that do
//! not override it; an operation-level `security: []` is *declared public* and renders `"none"`;
//! a document with no security block renders `nil`. Within one requirement the scheme names are
//! conjunctive (`a+b`), and array members are alternatives (`a | b`) — OpenAPI's own semantics.
//! Request media types are a sorted, comma-joined set (`consumes` for 2.0, `requestBody.content`
//! keys for 3.x), so the string is stable across runs and a `$ref` body yields `nil` rather than
//! a guess.
//!
//! # Refusals
//!
//! | code | when |
//! |---|---|
//! | `api:openapi-version-unsupported` | version is neither swagger 2.0 nor openapi 3.0.x/3.1.x, or is absent |
//! | `api:openapi-malformed` | not JSON, `paths` is not an object, or a path key does not begin with `/` |
//! | `api:openapi-ref-unsupported` | a path item is a `$ref`; resolving one needs a file or a network this module does not have |
//! | `api:openapi-no-evidence` | `doc_url` is empty — an inventory without a source is not evidence |
//! | `api:bad-argument` | an argument is missing, of the wrong type, or a struct of the wrong shape |

use super::StdlibResult;
use crate::interp::{Value, type_name};
use serde_json::{Value as J, json};

pub const CODE_VERSION_UNSUPPORTED: &str = "api:openapi-version-unsupported";
pub const CODE_OPENAPI_MALFORMED: &str = "api:openapi-malformed";
pub const CODE_OPENAPI_REF: &str = "api:openapi-ref-unsupported";
pub const CODE_NO_EVIDENCE: &str = "api:openapi-no-evidence";
pub const CODE_ARG: &str = "api:bad-argument";

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

// ── N13: OpenAPI ingestion ────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Endpoint {
    pub method: String,
    pub path: String,
    pub auth: Option<String>,
    pub content_type: Option<String>,
    pub source: String,
}

#[derive(Clone, Debug, Default)]
pub struct Inventory {
    pub doc_url: String,
    pub openapi_version: String,
    pub endpoints: Vec<Endpoint>,
}

/// `None` = not declared anywhere; `Some("none")` = declared with an empty requirement list.
fn security_class(declared: Option<&J>) -> Option<String> {
    let arr = declared?.as_array()?;
    let mut alts: Vec<String> = Vec::new();
    for req in arr {
        let Some(obj) = req.as_object() else { continue };
        let mut names: Vec<&str> = obj.keys().map(|s| s.as_str()).collect();
        names.sort_unstable();
        alts.push(match names.is_empty() {
            true => "none".to_string(),
            false => names.join("+"),
        });
    }
    match alts.is_empty() {
        true => Some("none".to_string()),
        false => Some(alts.join(" | ")),
    }
}

fn media_list(value: Option<&J>) -> Option<String> {
    let mut out: Vec<String> = value?
        .as_array()?
        .iter()
        .filter_map(|v| v.as_str().map(str::to_string))
        .collect();
    out.sort();
    out.dedup();
    match out.is_empty() {
        true => None,
        false => Some(out.join(",")),
    }
}

/// A 3.x request body's media types. A `$ref` body names none, so it yields `None`, not a guess.
fn request_body_types(op: &J) -> Option<String> {
    let content = op.get("requestBody")?.get("content")?.as_object()?;
    let mut keys: Vec<String> = content.keys().cloned().collect();
    keys.sort();
    match keys.is_empty() {
        true => None,
        false => Some(keys.join(",")),
    }
}

fn detect_version(doc: &J, doc_url: &str) -> Result<String, String> {
    let unsupported = |seen: String| {
        format!(
            "{CODE_VERSION_UNSUPPORTED}: {doc_url}: saw version {seen}; this module reads swagger \
             \"2.0\" and openapi \"3.0.x\"/\"3.1.x\" only"
        )
    };
    if let Some(s) = doc.get("swagger").and_then(J::as_str) {
        let t = s.trim();
        return match t == "2.0" {
            true => Ok("2.0".to_string()),
            false => Err(unsupported(format!("{t:?}"))),
        };
    }
    if let Some(o) = doc.get("openapi").and_then(J::as_str) {
        let t = o.trim();
        return match t.starts_with("3.0") || t.starts_with("3.1") {
            true => Ok(t.to_string()),
            false => Err(unsupported(format!("{t:?}"))),
        };
    }
    Err(unsupported(
        "no `swagger` and no `openapi` field".to_string(),
    ))
}

/// Parse an OpenAPI 2.0 or 3.x document into an endpoint inventory.
pub fn parse_openapi(doc_json: &str, doc_url: &str) -> Result<Inventory, String> {
    let doc_url = doc_url.trim();
    if doc_url.is_empty() {
        return Err(format!(
            "{CODE_NO_EVIDENCE}: api.openapi_load: doc_url is empty — an endpoint inventory \
             without the URL of the document that stated it is not evidence"
        ));
    }
    let doc: J = serde_json::from_str(doc_json)
        .map_err(|e| format!("{CODE_OPENAPI_MALFORMED}: {doc_url}: not JSON: {e}"))?;
    let version = detect_version(&doc, doc_url)?;
    let v2 = version == "2.0";
    let (global_security, global_consumes) = (doc.get("security"), doc.get("consumes"));
    let Some(paths) = doc.get("paths") else {
        return Ok(Inventory {
            doc_url: doc_url.to_string(),
            openapi_version: version,
            endpoints: Vec::new(),
        });
    };
    let Some(paths) = paths.as_object() else {
        return Err(format!(
            "{CODE_OPENAPI_MALFORMED}: {doc_url}: `paths` is not a JSON object"
        ));
    };
    let mut endpoints: Vec<Endpoint> = Vec::new();
    let mut keys: Vec<&String> = paths.keys().collect();
    keys.sort();
    for path in keys {
        if !path.starts_with('/') {
            return Err(format!(
                "{CODE_OPENAPI_MALFORMED}: {doc_url}: path key {path:?} does not begin with '/'"
            ));
        }
        let item = &paths[path];
        if let Some(r) = item.get("$ref").and_then(J::as_str) {
            return Err(format!(
                "{CODE_OPENAPI_REF}: {doc_url}: path item {path:?} is a $ref to {r:?}; this \
                 module resolves no references — supply a document with the path items inlined"
            ));
        }
        let Some(obj) = item.as_object() else {
            continue;
        };
        for method in METHODS {
            let Some(op) = obj.get(method) else { continue };
            if !op.is_object() {
                continue;
            }
            let content_type = match v2 {
                true => media_list(op.get("consumes").or(global_consumes)),
                false => request_body_types(op),
            };
            endpoints.push(Endpoint {
                method: method.to_uppercase(),
                path: path.clone(),
                auth: security_class(op.get("security").or(global_security)),
                content_type,
                source: doc_url.to_string(),
            });
        }
    }
    endpoints.sort();
    Ok(Inventory {
        doc_url: doc_url.to_string(),
        openapi_version: version,
        endpoints,
    })
}

// ── Value plumbing ────────────────────────────────────────────────────────

fn sfield(name: &str, v: &str) -> (String, Value) {
    (name.to_string(), Value::String(v.to_string()))
}

fn ofield(name: &str, v: &Option<String>) -> (String, Value) {
    (
        name.to_string(),
        v.clone().map(Value::String).unwrap_or(Value::Nil),
    )
}

fn ifield(name: &str, v: usize) -> (String, Value) {
    (name.to_string(), Value::Int(v as i128))
}

fn endpoint_value(e: &Endpoint) -> Value {
    Value::Struct {
        name: "ApiEndpoint".to_string(),
        fields: vec![
            sfield("method", &e.method),
            sfield("path", &e.path),
            ofield("auth", &e.auth),
            ofield("content_type", &e.content_type),
            sfield("source", &e.source),
        ],
    }
}

fn inventory_value(inv: &Inventory) -> Value {
    Value::Struct {
        name: "ApiInventory".to_string(),
        fields: vec![
            sfield("doc_url", &inv.doc_url),
            sfield("openapi_version", &inv.openapi_version),
            ifield("count", inv.endpoints.len()),
            (
                "endpoints".to_string(),
                Value::Array(inv.endpoints.iter().map(endpoint_value).collect()),
            ),
        ],
    }
}

fn bad(fname: &str, what: &str) -> String {
    format!("{CODE_ARG}: api.{fname}: {what}")
}

fn sv(fs: &[(String, Value)], k: &str) -> Option<String> {
    match fs.iter().find(|(n, _)| n == k).map(|(_, v)| v) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

fn struct_arg<'a>(
    args: &'a [Value],
    idx: usize,
    want: &str,
    fname: &str,
) -> Result<&'a [(String, Value)], String> {
    match args.get(idx) {
        Some(Value::Struct { name, fields }) if name == want => Ok(fields),
        Some(Value::Struct { name, .. }) => Err(bad(
            fname,
            &format!("argument {} expected {want}, got struct {name}", idx + 1),
        )),
        Some(other) => Err(bad(
            fname,
            &format!(
                "argument {} expected {want}, got {}",
                idx + 1,
                type_name(other)
            ),
        )),
        None => Err(bad(fname, &format!("missing argument {}", idx + 1))),
    }
}

fn str_arg(args: &[Value], idx: usize, fname: &str) -> Result<String, String> {
    match args.get(idx) {
        Some(Value::String(s)) => Ok(s.clone()),
        Some(other) => Err(bad(
            fname,
            &format!(
                "argument {} expected String, got {}",
                idx + 1,
                type_name(other)
            ),
        )),
        None => Err(bad(fname, &format!("missing argument {}", idx + 1))),
    }
}

fn opt_str_arg(args: &[Value], idx: usize, fname: &str) -> Result<Option<String>, String> {
    match args.get(idx) {
        Some(Value::Nil) | None => Ok(None),
        Some(Value::String(s)) if s.is_empty() => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(other) => Err(bad(
            fname,
            &format!(
                "argument {} expected String?, got {}",
                idx + 1,
                type_name(other)
            ),
        )),
    }
}

fn endpoint_of(fs: &[(String, Value)], fname: &str) -> Result<Endpoint, String> {
    Ok(Endpoint {
        method: sv(fs, "method")
            .ok_or_else(|| bad(fname, "ApiEndpoint without a String `method`"))?
            .to_uppercase(),
        path: sv(fs, "path").ok_or_else(|| bad(fname, "ApiEndpoint without a String `path`"))?,
        auth: sv(fs, "auth"),
        content_type: sv(fs, "content_type"),
        source: sv(fs, "source").unwrap_or_default(),
    })
}

fn endpoints_of(v: &Value, fname: &str) -> Result<Vec<Endpoint>, String> {
    let Value::Array(items) = v else {
        return Err(bad(
            fname,
            &format!("expected []ApiEndpoint, got {}", type_name(v)),
        ));
    };
    items
        .iter()
        .map(|it| match it {
            Value::Struct { name, fields } if name == "ApiEndpoint" => endpoint_of(fields, fname),
            other => Err(bad(
                fname,
                &format!("expected ApiEndpoint, got {}", type_name(other)),
            )),
        })
        .collect()
}

fn inventory_of(fs: &[(String, Value)], fname: &str) -> Result<Inventory, String> {
    let eps = fs
        .iter()
        .find(|(n, _)| n == "endpoints")
        .map(|(_, v)| v)
        .ok_or_else(|| bad(fname, "ApiInventory without an `endpoints` array"))?;
    Ok(Inventory {
        doc_url: sv(fs, "doc_url").unwrap_or_default(),
        openapi_version: sv(fs, "openapi_version").unwrap_or_default(),
        endpoints: endpoints_of(eps, fname)?,
    })
}

// ── Dispatch ──────────────────────────────────────────────────────────────

pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    let function = function
        .strip_prefix("api.")
        .or_else(|| function.strip_prefix("intel_api."))
        .unwrap_or(function);
    // The match lives in a closure so `?` resolves against `StdlibResult`; an
    // unknown name sets `unknown` and the closure's value is discarded.
    let mut unknown = false;
    let result: StdlibResult = (|| {
        match function {
            "openapi_load" => {
                let inv = parse_openapi(
                    &str_arg(&args, 0, "openapi_load")?,
                    &str_arg(&args, 1, "openapi_load")?,
                )?;
                Ok(inventory_value(&inv))
            }
            "endpoints_json" => {
                let inv = inventory_of(
                    struct_arg(&args, 0, "ApiInventory", "endpoints_json")?,
                    "endpoints_json",
                )?;
                Ok(Value::String(
                    json!({
                        "schema_version": "tallow.api.inventory.v1",
                        "doc_url": inv.doc_url,
                        "openapi_version": inv.openapi_version,
                        "count": inv.endpoints.len(),
                        // Every row carries the document it came from: "<url> states this endpoint"
                        // is evidence where "the API has this endpoint" is only a claim.
                        "endpoints": inv.endpoints.iter().map(|e| json!({
                            "method": e.method,
                            "path": e.path,
                            "auth": e.auth,
                            "content_type": e.content_type,
                            "source": e.source,
                        })).collect::<Vec<_>>(),
                    })
                    .to_string(),
                ))
            }
            // Constructors: a stdlib struct cannot be written as a literal in a `.tl` program, so
            // a module that only *takes* structs is a module no program can call.
            "endpoint" => Ok(endpoint_value(&Endpoint {
                method: str_arg(&args, 0, "endpoint")?.to_uppercase(),
                path: str_arg(&args, 1, "endpoint")?,
                auth: opt_str_arg(&args, 2, "endpoint")?,
                content_type: opt_str_arg(&args, 3, "endpoint")?,
                source: opt_str_arg(&args, 4, "endpoint")?.unwrap_or_default(),
            })),
            "inventory" => {
                let mut endpoints = endpoints_of(
                    args.get(2)
                        .ok_or_else(|| bad("inventory", "missing argument 3"))?,
                    "inventory",
                )?;
                endpoints.sort();
                Ok(inventory_value(&Inventory {
                    doc_url: str_arg(&args, 0, "inventory")?,
                    openapi_version: str_arg(&args, 1, "inventory")?,
                    endpoints,
                }))
            }
            _ => {
                unknown = true;
                Ok(Value::Nil)
            }
        }
    })();
    if unknown {
        return None;
    }
    Some(result)
}

// Named `intel_api_tests`, not `tests`: the gate command is `cargo test --lib
// intel_api`, which filters on the full test path (module included).
#[cfg(test)]
mod intel_api_tests {
    use super::*;

    const V3: &str = r#"{
      "openapi": "3.0.3",
      "security": [{"api_key": []}],
      "paths": {
        "/users/{id}": {"get": {"responses": {}},
                        "delete": {"security": [], "responses": {}}},
        "/users": {"post": {"requestBody": {"content": {"application/json": {}}}}}
      }
    }"#;
    const URL: &str = "https://x.test/openapi.json";

    #[test]
    fn v3_keeps_templates_and_names_its_source() {
        let i = parse_openapi(V3, URL).unwrap();
        assert_eq!(i.openapi_version, "3.0.3");
        let get = i.endpoints.iter().find(|e| e.method == "GET").unwrap();
        assert_eq!(get.path, "/users/{id}"); // never filled in
        assert_eq!(get.auth.as_deref(), Some("api_key"));
        assert_eq!(get.source, URL);
        // `security: []` is declared public, not undeclared.
        let del = i.endpoints.iter().find(|e| e.method == "DELETE").unwrap();
        assert_eq!(del.auth.as_deref(), Some("none"));
        let post = i.endpoints.iter().find(|e| e.method == "POST").unwrap();
        assert_eq!(post.content_type.as_deref(), Some("application/json"));
    }

    #[test]
    fn v2_reads_consumes_and_global_security() {
        let doc = r#"{"swagger":"2.0","consumes":["application/xml"],
          "securityDefinitions":{"basic":{"type":"basic"}},"security":[{"basic":[]}],
          "paths":{"/a":{"put":{"consumes":["application/json"]}}}}"#;
        let i = parse_openapi(doc, "u").unwrap();
        assert_eq!(i.openapi_version, "2.0");
        assert_eq!(i.endpoints.len(), 1);
        assert_eq!(i.endpoints[0].method, "PUT");
        assert_eq!(i.endpoints[0].auth.as_deref(), Some("basic"));
        assert_eq!(
            i.endpoints[0].content_type.as_deref(),
            Some("application/json")
        );
    }

    #[test]
    fn refusals_carry_stable_codes() {
        let e = parse_openapi(r#"{"openapi":"4.1.0","paths":{}}"#, "u").unwrap_err();
        assert!(
            e.starts_with(CODE_VERSION_UNSUPPORTED) && e.contains("4.1.0"),
            "{e}"
        );
        let e = parse_openapi(r#"{"paths":{}}"#, "u").unwrap_err();
        assert!(
            e.starts_with(CODE_VERSION_UNSUPPORTED) && e.contains("no `swagger`"),
            "{e}"
        );
        let e = parse_openapi(V3, "  ").unwrap_err();
        assert!(e.starts_with(CODE_NO_EVIDENCE), "{e}");
        let e = parse_openapi(
            r##"{"openapi":"3.0.0","paths":{"/a":{"$ref":"#/components/pathItems/A"}}}"##,
            "u",
        )
        .unwrap_err();
        assert!(
            e.starts_with(CODE_OPENAPI_REF) && e.contains("pathItems/A"),
            "{e}"
        );
        let e = parse_openapi(r#"{"openapi":"3.0.0","paths":[]}"#, "u").unwrap_err();
        assert!(e.starts_with(CODE_OPENAPI_MALFORMED), "{e}");
        let e = parse_openapi(r#"{"openapi":"3.0.0","paths":{"a":{}}}"#, "u").unwrap_err();
        assert!(e.starts_with(CODE_OPENAPI_MALFORMED), "{e}");
    }

    #[test]
    fn dispatch_refuses_wrong_arguments_and_renders_provenance() {
        let e = dispatch(
            "openapi_load",
            vec![Value::Int(1), Value::String("u".into())],
        )
        .unwrap()
        .unwrap_err();
        assert!(e.starts_with(CODE_ARG), "{e}");
        assert!(dispatch("nope", vec![]).is_none());
        let i = parse_openapi(V3, URL).unwrap();
        let Value::String(s) = dispatch("endpoints_json", vec![inventory_value(&i)])
            .unwrap()
            .unwrap()
        else {
            panic!("expected a string")
        };
        let doc: J = serde_json::from_str(&s).unwrap();
        assert_eq!(doc["doc_url"], URL);
        for row in doc["endpoints"].as_array().unwrap() {
            assert_eq!(row["source"], URL);
        }
    }

    #[test]
    fn the_inventory_constructor_round_trips_through_the_reader() {
        let built = dispatch(
            "inventory",
            vec![
                Value::String(URL.into()),
                Value::String("3.0.0".into()),
                Value::Array(vec![
                    dispatch(
                        "endpoint",
                        vec![
                            Value::String("get".into()),
                            Value::String("/a/{id}".into()),
                            Value::String("api_key".into()),
                            Value::Nil,
                            Value::String(URL.into()),
                        ],
                    )
                    .unwrap()
                    .unwrap(),
                ]),
            ],
        )
        .unwrap()
        .unwrap();
        let Value::Struct { name, fields } = &built else {
            panic!("expected an ApiInventory")
        };
        assert_eq!(name, "ApiInventory");
        let back = inventory_of(fields, "test").unwrap();
        assert_eq!(back.endpoints[0].method, "GET"); // constructor normalises the verb
        assert_eq!(back.endpoints[0].path, "/a/{id}");
        assert_eq!(back.endpoints[0].auth.as_deref(), Some("api_key"));
    }
}
