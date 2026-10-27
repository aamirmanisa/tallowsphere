//! `tallow.api` — offline API-surface ingestion and comparison (N13, N14, N16, N20, N21).
//!
//! **Offline by construction.** Nothing here opens a socket, resolves a name, or reads a clock.
//! `openapi_load` parses a document the caller already holds; comparing two inventories is pure
//! over data the caller supplied; a JavaScript bundle is a file the caller already has. Fetching a
//! spec or probing a server belongs to a caller holding a `Grant` — this module is the parser, not
//! the call.
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
//! # N14 — SDL and introspection produce one shape
//!
//! `graphql_from_sdl` and `graphql_from_introspection` both produce types → fields → args with
//! the same kind vocabulary (`object`, `interface`, `input`, `enum`, `scalar`, `union`), so a
//! schema captured before a release can be compared with the same schema captured after it by a
//! different mechanism.
//!
//! SDL is read by a **tokenizer**, not a regex: GraphQL argument types nest
//! (`f(filter: Filter { a: Int }): T`) and a pattern that stops at the first `}` truncates the
//! field list silently. Field type text is kept as written (`[User!]!`) and compared as text, so
//! `[User]` → `[User!]` is a change rather than a normalisation to equality. Descriptions,
//! comments and directives are skipped; `extend type` merges into the type rather than replacing
//! it. Introspection skips `__`-prefixed meta-types — they are the mechanism, not the schema.
//!
//! A removed field is the breaking case and is reported in `removed_fields`, separately from
//! `removed_types`. A field whose *type* changed is **both** a removal and an addition: it
//! appears in `removed_fields`, in `added_fields`, and again in `type_changes` with both sides
//! named — so a reader counting removals is not told the field vanished, nor one counting
//! additions that it merely arrived. Same rule for a changed argument type, named
//! `Type.field(arg)`. A changed *kind* (object → interface) is a removed type and an added type.
//!
//! # N20 — an exposure signal, not a finding
//!
//! `identifiers` reports endpoints whose path holds a literal numeric or UUID segment. Every row
//! says `signal: "object-id-in-path"` and names the segment and its 0-based position. It does not
//! say `vulnerable`, `BOLA`, or `IDOR`, and must not be read as one: an id in a path is ordinary
//! REST design, and whether it is an authorization defect depends on a request the caller has not
//! made. A templated segment (`{id}`) carries no value and is not flagged — the template is the
//! safe shape, a filled-in value is the one worth a second look.
//!
//! The UUID test is the named pattern [`UUID_PATTERN`]: the canonical 8-4-4-4-12 hex shape,
//! case-insensitive. Its known weakness is deliberate — it checks shape only, not the RFC 4122
//! version nibble or variant bits, so a nil UUID and a hand-written non-RFC value both flag,
//! while a bare 32-hex digest, a truncated id, or `deadbeef-cafe` do not. Version gating would
//! miss real ids minted by libraries that emit v7/v8 or nil.
//!
//! # N21 — removal is the loud case
//!
//! `diff` matches endpoints by `(path template, method)` — the template, so `/users/1` and
//! `/users/2` are one endpoint — and reports endpoints added, removed, and whose auth class or
//! content type changed. Every entry names what changed and both sides (`before` / `after`, with
//! `nil` for "not declared"). `breaking` is true when anything was removed or any auth class
//! changed; a content-type change is reported but is not breaking on its own. Output is sorted by
//! `(path, method)`, so two runs over the same input are byte-identical, and a reordering of the
//! document is not a change.
//!
//! # N16 — a bundle is text, and a route is located in it
//!
//! `bundle_routes` reads a JavaScript bundle **as text**. Nothing here evaluates it: no
//! `eval`, no `Function`, no DOM, no engine. A route record carries the `route`, the
//! `recovered_from` construct that produced it, `source_url` (the bundle the caller named), and
//! `offset` — the byte offset of the opening quote of the literal the route was read from. A route
//! that cannot name both is dropped and counted in `skipped_unlocated`; "the bundle has this
//! route" without a byte offset is a claim, not a finding.
//!
//! Recovered constructs: path-shaped string literals (`/api/v1/users`), template literals whose
//! `${…}` segments are recorded as `{}` with `interpolated: true` (never with a value), and the
//! first argument of `fetch(…)`, `axios.get|post|…(…)` and `$.ajax({url: …})`, which is reported in
//! `recovered_from`. A route assembled by concatenation (`'/api/users/' + id`) is reported as
//! `partial: true` with the fragment that was actually seen — completing it would be fabricating
//! the bytes the bundle did not contain.
//!
//! Two heuristics are named rather than hidden: a string ending in a static-asset extension
//! (`.js`, `.css`, `.png`, …) is a file path, not a route, and is counted in `skipped_non_route`;
//! and text inside a literal whose end could not be found (a truncated bundle) has no trustworthy
//! extent, so its path-shaped runs are counted in `skipped_unlocated` instead of emitted. A page
//! saved as `.js` is refused by name (`api:bundle-not-js`) — parsing HTML as JavaScript produces
//! garbage routes, and garbage with offsets is worse than nothing.
//!
//! # Refusals
//!
//! | code | when |
//! |---|---|
//! | `api:openapi-version-unsupported` | version is neither swagger 2.0 nor openapi 3.0.x/3.1.x, or is absent |
//! | `api:openapi-malformed` | not JSON, `paths` is not an object, or a path key does not begin with `/` |
//! | `api:openapi-ref-unsupported` | a path item is a `$ref`; resolving one needs a file or a network this module does not have |
//! | `api:openapi-no-evidence` | `doc_url` is empty — an inventory without a source is not evidence |
//! | `api:graphql-parse` | SDL the tokenizer/parser cannot read (unterminated string, unbalanced delimiter, unexpected definition) |
//! | `api:graphql-introspection-malformed` | JSON that is not an introspection result (no `__schema`, a type without name/kind) |
//! | `api:bundle-not-js` | the first bytes of the input are HTML — a page saved as `.js` |
//! | `api:bundle-no-evidence` | `bundle_url` is empty — a route that cannot name its bundle is not a finding |
//! | `api:bad-argument` | an argument is missing, of the wrong type, or a struct of the wrong shape |

use super::StdlibResult;
use crate::interp::{Value, type_name};
use serde_json::{Value as J, json};

pub const CODE_VERSION_UNSUPPORTED: &str = "api:openapi-version-unsupported";
pub const CODE_OPENAPI_MALFORMED: &str = "api:openapi-malformed";
pub const CODE_OPENAPI_REF: &str = "api:openapi-ref-unsupported";
pub const CODE_NO_EVIDENCE: &str = "api:openapi-no-evidence";
pub const CODE_GRAPHQL_PARSE: &str = "api:graphql-parse";
pub const CODE_INTROSPECTION: &str = "api:graphql-introspection-malformed";
pub const CODE_ARG: &str = "api:bad-argument";
pub const CODE_BUNDLE_NOT_JS: &str = "api:bundle-not-js";
pub const CODE_BUNDLE_NO_EVIDENCE: &str = "api:bundle-no-evidence";
/// Canonical 8-4-4-4-12 UUID shape. See the module docs for the known weakness.
pub const UUID_PATTERN: &str =
    r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$";
/// The signal label every `identifiers` row carries — a description, not a severity.
pub const SIGNAL_OBJECT_ID: &str = "object-id-in-path";

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

// ── N14: GraphQL SDL + introspection ──────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GArg {
    pub name: String,
    pub type_name: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GField {
    pub name: String,
    pub type_name: String,
    pub args: Vec<GArg>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GType {
    pub name: String,
    pub kind: String,
    pub fields: Vec<GField>,
}

/// types → fields → args, sorted by name at every level.
pub type GSchema = std::collections::BTreeMap<String, GType>;

#[derive(Clone, Debug, PartialEq)]
enum Tok {
    Name(String),
    /// A string or block string. It carries no text (nothing here reads one), but it must
    /// stay a *single* token: a default value like `= "me"` has to be consumed as one value.
    Str,
    Punct(char),
}

/// SDL → tokens. A tokenizer rather than a regex because GraphQL argument types nest:
/// `f(filter: Filter { a: Int }): T` breaks any pattern that stops at the first `}`.
/// Strings (descriptions, default values) and `#` comments are dropped; `,` is insignificant.
fn tokenize(src: &str) -> Result<Vec<Tok>, String> {
    let cs: Vec<char> = src.chars().collect();
    let (mut i, mut line) = (0usize, 1usize);
    let mut out = Vec::new();
    while i < cs.len() {
        let c = cs[i];
        match c {
            '\n' => {
                line += 1;
                i += 1;
            }
            ' ' | '\t' | '\r' | ',' | '\u{feff}' => i += 1,
            '#' => {
                while i < cs.len() && cs[i] != '\n' {
                    i += 1;
                }
            }
            '"' if i + 2 < cs.len() && cs[i + 1] == '"' && cs[i + 2] == '"' => {
                i += 3;
                loop {
                    if i + 2 >= cs.len() {
                        return Err(format!(
                            "{CODE_GRAPHQL_PARSE}: unterminated block string at line {line}"
                        ));
                    }
                    if cs[i] == '"' && cs[i + 1] == '"' && cs[i + 2] == '"' {
                        i += 3;
                        break;
                    }
                    line += usize::from(cs[i] == '\n');
                    i += 1;
                }
                out.push(Tok::Str);
            }
            '"' => {
                i += 1;
                loop {
                    if i >= cs.len() {
                        return Err(format!(
                            "{CODE_GRAPHQL_PARSE}: unterminated string at line {line}"
                        ));
                    }
                    if cs[i] == '\\' {
                        i += 2;
                        continue;
                    }
                    if cs[i] == '"' {
                        i += 1;
                        break;
                    }
                    line += usize::from(cs[i] == '\n');
                    i += 1;
                }
                out.push(Tok::Str);
            }
            _ if c.is_alphabetic() || c == '_' => {
                let start = i;
                while i < cs.len() && (cs[i].is_alphanumeric() || cs[i] == '_') {
                    i += 1;
                }
                out.push(Tok::Name(cs[start..i].iter().collect()));
            }
            // Numbers are never inspected (they only appear in defaults), so one opaque
            // token is enough to let the default-skipping path walk over them.
            _ if c.is_ascii_digit() || c == '-' => {
                let start = i;
                while i < cs.len() && (cs[i].is_ascii_alphanumeric() || "+-.eE".contains(cs[i])) {
                    i += 1;
                }
                out.push(Tok::Name(cs[start..i].iter().collect()));
            }
            '{' | '}' | '(' | ')' | '[' | ']' | ':' | '=' | '!' | '@' | '|' | '&' | '$' | '.' => {
                out.push(Tok::Punct(c));
                i += 1;
            }
            other => {
                return Err(format!(
                    "{CODE_GRAPHQL_PARSE}: unexpected character {other:?} at line {line}"
                ));
            }
        }
    }
    Ok(out)
}

struct P<'a> {
    t: &'a [Tok],
    i: usize,
}

impl<'a> P<'a> {
    fn peek(&self) -> Option<&Tok> {
        self.t.get(self.i)
    }
    fn next(&mut self) -> Option<Tok> {
        let v = self.t.get(self.i).cloned();
        if v.is_some() {
            self.i += 1;
        }
        v
    }
    fn eof(&self) -> bool {
        self.i >= self.t.len()
    }
    fn eat(&mut self, c: char) -> bool {
        if matches!(self.peek(), Some(Tok::Punct(p)) if *p == c) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn expect(&mut self, c: char) -> Result<(), String> {
        if self.eat(c) {
            Ok(())
        } else {
            Err(self.err(&format!("expected '{c}'")))
        }
    }
    fn err(&self, msg: &str) -> String {
        format!(
            "{CODE_GRAPHQL_PARSE}: {msg} at token {} of {}",
            self.i,
            self.t.len()
        )
    }
    fn name(&mut self) -> Result<String, String> {
        match self.next() {
            Some(Tok::Name(n)) => Ok(n),
            _ => Err(self.err("expected a name")),
        }
    }
    fn peek_name(&self) -> Option<&str> {
        match self.peek() {
            Some(Tok::Name(n)) => Some(n.as_str()),
            _ => None,
        }
    }
}

fn skip_balanced(p: &mut P, open: char, close: char) -> Result<(), String> {
    let mut depth = 1i32;
    while let Some(t) = p.next() {
        match t {
            Tok::Punct(c) if c == open => depth += 1,
            Tok::Punct(c) if c == close => {
                depth -= 1;
                if depth == 0 {
                    return Ok(());
                }
            }
            _ => {}
        }
    }
    Err(p.err(&format!("unbalanced '{open}'")))
}

/// Consume exactly one default value. A GraphQL const value is one scalar token, a string, or a
/// balanced `[...]` / `{...}`; anything wider would swallow the following argument, because the
/// tokenizer drops the commas that separate them.
fn skip_value(p: &mut P) {
    match p.peek() {
        Some(Tok::Punct('[')) => {
            p.next();
            let _ = skip_balanced(p, '[', ']');
        }
        Some(Tok::Punct('{')) => {
            p.next();
            let _ = skip_balanced(p, '{', '}');
        }
        Some(_) => {
            p.next();
        }
        None => {}
    }
}

fn skip_directive(p: &mut P) -> Result<(), String> {
    p.name()?;
    if p.peek() == Some(&Tok::Punct('(')) {
        p.next();
        skip_balanced(p, '(', ')')?;
    }
    Ok(())
}

fn type_ref(p: &mut P) -> Result<String, String> {
    let mut s = if p.eat('[') {
        let inner = type_ref(p)?;
        p.expect(']')?;
        format!("[{inner}]")
    } else {
        p.name()?
    };
    if p.eat('!') {
        s.push('!');
    }
    Ok(s)
}

fn parse_fields(
    p: &mut P,
    input: bool,
) -> Result<std::collections::BTreeMap<String, GField>, String> {
    p.expect('{')?;
    let mut out = std::collections::BTreeMap::new();
    while !p.eat('}') {
        if p.eof() {
            return Err(p.err("unbalanced '{' in field list"));
        }
        let name = p.name()?;
        let mut args: Vec<GArg> = Vec::new();
        if !input && p.eat('(') {
            while !p.eat(')') {
                if p.eof() {
                    return Err(p.err("unbalanced '(' in argument list"));
                }
                let aname = p.name()?;
                p.expect(':')?;
                let aty = type_ref(p)?;
                if p.eat('=') {
                    skip_value(p);
                }
                while p.eat('@') {
                    skip_directive(p)?;
                }
                args.push(GArg {
                    name: aname,
                    type_name: aty,
                });
            }
        }
        p.expect(':')?;
        let ty = type_ref(p)?;
        if p.eat('=') {
            skip_value(p);
        }
        while p.eat('@') {
            skip_directive(p)?;
        }
        args.sort_by(|a, b| a.name.cmp(&b.name));
        out.insert(
            name.clone(),
            GField {
                name,
                type_name: ty,
                args,
            },
        );
    }
    Ok(out)
}

fn parse_enum_values(p: &mut P) -> Result<std::collections::BTreeMap<String, GField>, String> {
    p.expect('{')?;
    let mut out = std::collections::BTreeMap::new();
    while !p.eat('}') {
        if p.eof() {
            return Err(p.err("unbalanced '{' in enum body"));
        }
        let v = p.name()?;
        while p.eat('@') {
            skip_directive(p)?;
        }
        out.insert(
            v.clone(),
            GField {
                name: v,
                // `"enum"` on both capture paths, so a diff never invents a type change.
                type_name: "enum".to_string(),
                args: Vec::new(),
            },
        );
    }
    Ok(out)
}

fn skip_directive_def(p: &mut P) -> Result<(), String> {
    p.expect('@')?;
    p.name()?;
    if p.peek() == Some(&Tok::Punct('(')) {
        p.next();
        skip_balanced(p, '(', ')')?;
    }
    if p.peek_name() == Some("repeatable") {
        p.name()?;
    }
    if p.peek_name() != Some("on") {
        return Err(p.err("directive definition without `on`"));
    }
    p.name()?;
    while p.peek_name().is_some() {
        p.name()?;
        if !p.eat('|') {
            break;
        }
    }
    Ok(())
}

/// Add fields to a type, merging into an existing definition so `extend type` behaves like
/// an extension rather than a replacement.
fn merge_fields(
    schema: &mut GSchema,
    name: &str,
    kind: &str,
    fields: std::collections::BTreeMap<String, GField>,
) {
    let t = schema.entry(name.to_string()).or_insert_with(|| GType {
        name: name.to_string(),
        kind: kind.to_string(),
        fields: Vec::new(),
    });
    for f in fields.into_values() {
        match t.fields.iter_mut().find(|e| e.name == f.name) {
            Some(slot) => *slot = f,
            None => t.fields.push(f),
        }
    }
    t.fields.sort_by(|a, b| a.name.cmp(&b.name));
}

fn parse_definition(p: &mut P, head: &str, schema: &mut GSchema) -> Result<(), String> {
    match head {
        // `schema { query: Query }` names root operations; they are not types.
        "schema" => {
            p.expect('{')?;
            skip_balanced(p, '{', '}')
        }
        "directive" => skip_directive_def(p),
        "scalar" | "union" => {
            let n = p.name()?;
            while p.eat('@') {
                skip_directive(p)?;
            }
            if head == "union" && p.eat('=') {
                while p.peek_name().is_some() {
                    p.name()?;
                    if !p.eat('|') {
                        break;
                    }
                }
            }
            schema.entry(n.clone()).or_insert_with(|| GType {
                name: n,
                kind: head.to_string(),
                fields: Vec::new(),
            });
            Ok(())
        }
        "enum" => {
            let n = p.name()?;
            while p.eat('@') {
                skip_directive(p)?;
            }
            let values = match p.peek() == Some(&Tok::Punct('{')) {
                true => parse_enum_values(p)?,
                false => std::collections::BTreeMap::new(),
            };
            merge_fields(schema, &n, "enum", values);
            Ok(())
        }
        "type" | "interface" | "input" => {
            let kind = match head {
                "type" => "object",
                "interface" => "interface",
                _ => "input",
            };
            let n = p.name()?;
            if p.peek_name() == Some("implements") {
                p.name()?;
                while p.peek_name().is_some() {
                    p.name()?;
                    if !p.eat('&') {
                        break;
                    }
                }
            }
            while p.eat('@') {
                skip_directive(p)?;
            }
            let fields = match p.peek() == Some(&Tok::Punct('{')) {
                true => parse_fields(p, head == "input")?,
                false => std::collections::BTreeMap::new(),
            };
            merge_fields(schema, &n, kind, fields);
            Ok(())
        }
        other => Err(p.err(&format!("unexpected top-level definition `{other}`"))),
    }
}

/// Parse GraphQL SDL into the shared schema shape.
pub fn parse_sdl(src: &str) -> Result<GSchema, String> {
    let toks = tokenize(src)?;
    let mut p = P { t: &toks, i: 0 };
    let mut schema = GSchema::new();
    while !p.eof() {
        // A description is a string token in front of the definition it documents.
        while matches!(p.peek(), Some(Tok::Str)) {
            p.next();
        }
        if p.eof() {
            break;
        }
        let head = p.name()?;
        if head == "extend" {
            let inner = p.name()?;
            parse_definition(&mut p, &inner, &mut schema)?;
        } else {
            parse_definition(&mut p, &head, &mut schema)?;
        }
    }
    Ok(schema)
}

fn intro_kind(k: &str) -> String {
    match k {
        "OBJECT" => "object",
        "INTERFACE" => "interface",
        "INPUT_OBJECT" => "input",
        "ENUM" => "enum",
        "SCALAR" => "scalar",
        "UNION" => "union",
        other => return other.to_ascii_lowercase(),
    }
    .to_string()
}

/// Render an introspection `__Type` as the text an SDL author would write. Depth-capped so a
/// nested `ofType` chain cannot exhaust the stack.
fn intro_type_ref(t: &J, depth: usize) -> String {
    if depth > 32 {
        return "?".to_string();
    }
    let inner = |d: usize| intro_type_ref(t.get("ofType").unwrap_or(&J::Null), d);
    match t.get("kind").and_then(J::as_str) {
        Some("NON_NULL") => format!("{}!", inner(depth + 1)),
        Some("LIST") => format!("[{}]", inner(depth + 1)),
        _ => t.get("name").and_then(J::as_str).unwrap_or("").to_string(),
    }
}

/// Parse an introspection response (`{data:{__schema:{types:[…]}}}` or a bare `{__schema:…}`).
/// The `__`-prefixed meta-types are skipped: they are the introspection mechanism, not the
/// schema under test.
pub fn parse_introspection(src: &str) -> Result<GSchema, String> {
    let doc: J =
        serde_json::from_str(src).map_err(|e| format!("{CODE_INTROSPECTION}: not JSON: {e}"))?;
    let schema = doc
        .get("data")
        .and_then(|d| d.get("__schema"))
        .or_else(|| doc.get("__schema"))
        .ok_or_else(|| {
            format!(
                "{CODE_INTROSPECTION}: no `__schema` — looked at `data.__schema` and `__schema`"
            )
        })?;
    let types = schema.get("types").and_then(J::as_array).ok_or_else(|| {
        format!("{CODE_INTROSPECTION}: `__schema.types` is missing or is not an array")
    })?;
    let mut out = GSchema::new();
    for t in types {
        let Some(name) = t.get("name").and_then(J::as_str) else {
            return Err(format!(
                "{CODE_INTROSPECTION}: a type in `__schema.types` has no name"
            ));
        };
        if name.starts_with("__") {
            continue;
        }
        let Some(kind) = t.get("kind").and_then(J::as_str) else {
            return Err(format!("{CODE_INTROSPECTION}: type {name:?} has no `kind`"));
        };
        let mut fields: Vec<GField> = Vec::new();
        let list = t
            .get("fields")
            .and_then(J::as_array)
            .or_else(|| t.get("inputFields").and_then(J::as_array))
            .or_else(|| t.get("enumValues").and_then(J::as_array));
        for f in list.into_iter().flatten() {
            let Some(fname) = f.get("name").and_then(J::as_str) else {
                return Err(format!(
                    "{CODE_INTROSPECTION}: a field of type {name:?} has no name"
                ));
            };
            let mut args: Vec<GArg> = Vec::new();
            for a in f.get("args").and_then(J::as_array).into_iter().flatten() {
                let Some(aname) = a.get("name").and_then(J::as_str) else {
                    return Err(format!(
                        "{CODE_INTROSPECTION}: an argument of {name}.{fname} has no name"
                    ));
                };
                args.push(GArg {
                    name: aname.to_string(),
                    type_name: a
                        .get("type")
                        .map(|ty| intro_type_ref(ty, 0))
                        .unwrap_or_default(),
                });
            }
            args.sort_by(|a, b| a.name.cmp(&b.name));
            fields.push(GField {
                name: fname.to_string(),
                // An enum value carries only a name in introspection.
                type_name: f
                    .get("type")
                    .map(|ty| intro_type_ref(ty, 0))
                    .unwrap_or_else(|| "enum".to_string()),
                args,
            });
        }
        fields.sort_by(|a, b| a.name.cmp(&b.name));
        out.insert(
            name.to_string(),
            GType {
                name: name.to_string(),
                kind: intro_kind(kind),
                fields,
            },
        );
    }
    Ok(out)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GTypeChange {
    pub type_name: String,
    pub field: String,
    pub old_type: String,
    pub new_type: String,
}

#[derive(Clone, Debug, Default)]
pub struct GqlDiff {
    pub added_types: Vec<String>,
    pub removed_types: Vec<String>,
    pub added_fields: Vec<String>,
    pub removed_fields: Vec<String>,
    pub added_args: Vec<String>,
    pub removed_args: Vec<String>,
    pub type_changes: Vec<GTypeChange>,
}

impl GqlDiff {
    pub fn breaking(&self) -> bool {
        !self.removed_types.is_empty()
            || !self.removed_fields.is_empty()
            || !self.removed_args.is_empty()
    }
}

fn arg_type<'a>(f: &'a GField, name: &str) -> Option<&'a str> {
    f.args
        .iter()
        .find(|a| a.name == name)
        .map(|a| a.type_name.as_str())
}

/// Compare two schemas. A changed type is reported as a removal **and** an addition, plus a
/// `type_changes` row naming both sides.
pub fn graphql_diff(old: &GSchema, new: &GSchema) -> GqlDiff {
    use std::collections::BTreeSet;
    let mut d = GqlDiff::default();
    let (mut at, mut rt, mut af, mut rf, mut aa, mut ra) = (
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::new(),
    );
    // One pass over the union: `chain` would visit a name present in both sides twice, and a
    // type change recorded twice is a diff a reader cannot count.
    let mut names: BTreeSet<&String> = old.keys().collect();
    names.extend(new.keys());
    for name in names {
        let (Some(o), Some(n)) = (old.get(name), new.get(name)) else {
            if old.contains_key(name) {
                rt.insert(name.clone());
            } else {
                at.insert(name.clone());
            }
            continue;
        };
        if o.kind != n.kind {
            // The type as declared changed: a removal and an addition, not a field edit.
            at.insert(name.clone());
            rt.insert(name.clone());
        }
        let mut fnames: BTreeSet<&str> = o.fields.iter().map(|f| f.name.as_str()).collect();
        fnames.extend(n.fields.iter().map(|f| f.name.as_str()));
        for fname in fnames {
            let label = format!("{name}.{fname}");
            let (of, nf) = (
                o.fields.iter().find(|f| f.name == fname),
                n.fields.iter().find(|f| f.name == fname),
            );
            let (Some(of), Some(nf)) = (of, nf) else {
                match of.is_some() {
                    true => rf.insert(label),
                    false => af.insert(label),
                };
                continue;
            };
            if of.type_name != nf.type_name {
                af.insert(label.clone());
                rf.insert(label.clone());
                d.type_changes.push(GTypeChange {
                    type_name: name.clone(),
                    field: fname.to_string(),
                    old_type: of.type_name.clone(),
                    new_type: nf.type_name.clone(),
                });
            }
            let mut anames: BTreeSet<&str> = of.args.iter().map(|a| a.name.as_str()).collect();
            anames.extend(nf.args.iter().map(|a| a.name.as_str()));
            for aname in anames {
                let alabel = format!("{label}({aname})");
                match (arg_type(of, aname), arg_type(nf, aname)) {
                    (None, Some(_)) => {
                        aa.insert(alabel);
                    }
                    (Some(_), None) => {
                        ra.insert(alabel);
                    }
                    (Some(oa), Some(na)) if oa != na => {
                        aa.insert(alabel.clone());
                        ra.insert(alabel.clone());
                        d.type_changes.push(GTypeChange {
                            type_name: name.clone(),
                            field: format!("{fname}({aname})"),
                            old_type: oa.to_string(),
                            new_type: na.to_string(),
                        });
                    }
                    _ => {}
                }
            }
        }
    }
    d.added_types = at.into_iter().collect();
    d.removed_types = rt.into_iter().collect();
    d.added_fields = af.into_iter().collect();
    d.removed_fields = rf.into_iter().collect();
    d.added_args = aa.into_iter().collect();
    d.removed_args = ra.into_iter().collect();
    d
}

// ── N20: object ids in paths ──────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct PathSignal {
    pub signal: String,
    pub method: String,
    pub path: String,
    pub segment: String,
    pub index: usize,
    pub kind: String,
}

fn uuid_re() -> &'static regex::Regex {
    use std::sync::OnceLock;
    static RE: OnceLock<regex::Regex> = OnceLock::new();
    RE.get_or_init(|| regex::Regex::new(UUID_PATTERN).expect("UUID_PATTERN compiles"))
}

fn segment_kind(seg: &str) -> Option<&'static str> {
    if !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_digit()) {
        return Some("numeric");
    }
    match uuid_re().is_match(seg) {
        true => Some("uuid"),
        false => None,
    }
}

/// Flag endpoints whose path carries a literal numeric or UUID segment. Deterministic: sorted
/// by `(path, method, index)`.
pub fn identifiers(endpoints: &[Endpoint]) -> Vec<PathSignal> {
    let mut out = Vec::new();
    for ep in endpoints {
        // A template (`{id}`) is not a value and is deliberately not flagged: the safe shape
        // is the template, the worth-a-look shape is a literal value.
        for (index, seg) in ep.path.split('/').filter(|s| !s.is_empty()).enumerate() {
            let Some(kind) = segment_kind(seg) else {
                continue;
            };
            out.push(PathSignal {
                signal: SIGNAL_OBJECT_ID.to_string(),
                method: ep.method.clone(),
                path: ep.path.clone(),
                segment: seg.to_string(),
                index,
                kind: kind.to_string(),
            });
        }
    }
    out.sort_by(|a, b| (&a.path, &a.method, a.index).cmp(&(&b.path, &b.method, b.index)));
    out
}

// ── GraphQL/SDL value plumbing ────────────────────────────────────────────

fn array_field<'a>(fs: &'a [(String, Value)], k: &str) -> Option<&'a [Value]> {
    match fs.iter().find(|(n, _)| n == k).map(|(_, v)| v) {
        Some(Value::Array(a)) => Some(a),
        _ => None,
    }
}

fn schema_of(v: &Value, fname: &str) -> Result<GSchema, String> {
    let Value::Struct { name, fields } = v else {
        return Err(bad(
            fname,
            &format!("expected GraphqlSchema, got {}", type_name(v)),
        ));
    };
    if name != "GraphqlSchema" {
        return Err(bad(
            fname,
            &format!("expected GraphqlSchema, got struct {name}"),
        ));
    }
    let types = array_field(fields, "types")
        .ok_or_else(|| bad(fname, "GraphqlSchema without a `types` array"))?;
    let mut out = GSchema::new();
    for t in types {
        let Value::Struct { name, fields: tf } = t else {
            return Err(bad(fname, "a GraphqlSchema type is not a struct"));
        };
        if name != "GraphqlType" {
            return Err(bad(
                fname,
                &format!("expected GraphqlType, got struct {name}"),
            ));
        }
        let tname = sv(tf, "name").ok_or_else(|| bad(fname, "GraphqlType without a `name`"))?;
        let mut gfields: Vec<GField> = Vec::new();
        for f in array_field(tf, "fields").unwrap_or_default() {
            let Value::Struct { fields: ff, .. } = f else {
                return Err(bad(fname, "a GraphqlType field is not a struct"));
            };
            let fname_ =
                sv(ff, "name").ok_or_else(|| bad(fname, "GraphqlField without a `name`"))?;
            let mut args: Vec<GArg> = Vec::new();
            for a in array_field(ff, "args").unwrap_or_default() {
                let Value::Struct { fields: af, .. } = a else {
                    return Err(bad(fname, "a GraphqlField arg is not a struct"));
                };
                args.push(GArg {
                    name: sv(af, "name").unwrap_or_default(),
                    type_name: sv(af, "type_name").unwrap_or_default(),
                });
            }
            args.sort_by(|a, b| a.name.cmp(&b.name));
            gfields.push(GField {
                name: fname_,
                type_name: sv(ff, "type_name").unwrap_or_default(),
                args,
            });
        }
        gfields.sort_by(|a, b| a.name.cmp(&b.name));
        out.insert(
            tname.clone(),
            GType {
                name: tname,
                kind: sv(tf, "kind").unwrap_or_else(|| "object".to_string()),
                fields: gfields,
            },
        );
    }
    Ok(out)
}

fn field_value(f: &GField) -> Value {
    Value::Struct {
        name: "GraphqlField".to_string(),
        fields: vec![
            sfield("name", &f.name),
            sfield("type_name", &f.type_name),
            (
                "args".to_string(),
                Value::Array(
                    f.args
                        .iter()
                        .map(|a| Value::Struct {
                            name: "GraphqlArg".to_string(),
                            fields: vec![
                                sfield("name", &a.name),
                                sfield("type_name", &a.type_name),
                            ],
                        })
                        .collect(),
                ),
            ),
        ],
    }
}

fn schema_value(s: &GSchema, origin: &str) -> Value {
    let types: Vec<Value> = s
        .values()
        .map(|t| Value::Struct {
            name: "GraphqlType".to_string(),
            fields: vec![
                sfield("name", &t.name),
                sfield("kind", &t.kind),
                (
                    "fields".to_string(),
                    Value::Array(t.fields.iter().map(field_value).collect()),
                ),
            ],
        })
        .collect();
    Value::Struct {
        name: "GraphqlSchema".to_string(),
        fields: vec![
            sfield("origin", origin),
            ifield("type_count", types.len()),
            ("types".to_string(), Value::Array(types)),
        ],
    }
}

fn strings(v: &[String]) -> Value {
    Value::Array(v.iter().cloned().map(Value::String).collect())
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

fn bool_arg(args: &[Value], idx: usize, fname: &str) -> Result<bool, String> {
    match args.get(idx) {
        Some(Value::Bool(b)) => Ok(*b),
        Some(other) => Err(bad(
            fname,
            &format!("argument {} expected Bool, got {}", idx + 1, type_name(other)),
        )),
        None => Err(bad(fname, &format!("missing argument {}", idx + 1))),
    }
}

fn int_arg(args: &[Value], idx: usize, fname: &str) -> Result<usize, String> {
    match args.get(idx) {
        Some(Value::Int(i)) if *i >= 0 => Ok(*i as usize),
        Some(other) => Err(bad(
            fname,
            &format!(
                "argument {} expected a non-negative Int, got {}",
                idx + 1,
                type_name(other)
            ),
        )),
        None => Err(bad(fname, &format!("missing argument {}", idx + 1))),
    }
}

/// Read and sort a `[]BundleRoute` argument, rejecting a record of the wrong struct.
fn routes_arg(args: &[Value], idx: usize, fname: &str) -> Result<Vec<BundleRoute>, String> {
    let Some(v) = args.get(idx) else {
        return Err(bad(fname, &format!("missing argument {}", idx + 1)));
    };
    let Value::Array(items) = v else {
        return Err(bad(
            fname,
            &format!(
                "argument {} expected []BundleRoute, got {}",
                idx + 1,
                type_name(v)
            ),
        ));
    };
    let mut out: Vec<BundleRoute> = Vec::new();
    for it in items {
        match it {
            Value::Struct { name, fields } if name == "BundleRoute" => {
                out.push(read_route(fields, fname)?)
            }
            other => {
                return Err(bad(
                    fname,
                    &format!(
                        "argument {} expected BundleRoute, got {}",
                        idx + 1,
                        type_name(other)
                    ),
                ));
            }
        }
    }
    sort_routes(&mut out);
    Ok(out)
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

// ── N21: snapshot diff ────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointChange {
    pub method: String,
    pub path: String,
    /// The field that changed: `auth` or `content_type`.
    pub field: String,
    pub before: Option<String>,
    pub after: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct InventoryDiff {
    pub doc_url_old: String,
    pub doc_url_new: String,
    pub added: Vec<Endpoint>,
    pub removed: Vec<Endpoint>,
    pub auth_changed: Vec<EndpointChange>,
    pub content_type_changed: Vec<EndpointChange>,
    pub unchanged: usize,
}

impl InventoryDiff {
    /// Removal is the loud case, and so is an auth class that changed — both are how an
    /// endpoint stops being reachable the way its callers assume it is.
    pub fn breaking(&self) -> bool {
        !self.removed.is_empty() || !self.auth_changed.is_empty()
    }
    pub fn summary(&self) -> String {
        format!(
            "{} added, {} removed, {} auth-changed, {} content-type-changed, {} unchanged",
            self.added.len(),
            self.removed.len(),
            self.auth_changed.len(),
            self.content_type_changed.len(),
            self.unchanged
        )
    }
}

/// Compare two inventories by `(path template, method)` — the template, not a filled-in value,
/// so `/users/1` and `/users/2` are one endpoint. Every entry names what changed and both sides.
pub fn diff(old: &Inventory, new: &Inventory) -> InventoryDiff {
    let keyed = |i: &Inventory| -> std::collections::BTreeMap<(String, String), Endpoint> {
        i.endpoints
            .iter()
            .map(|e| ((e.path.clone(), e.method.clone()), e.clone()))
            .collect()
    };
    let (o, n) = (keyed(old), keyed(new));
    let mut d = InventoryDiff {
        doc_url_old: old.doc_url.clone(),
        doc_url_new: new.doc_url.clone(),
        ..Default::default()
    };
    for (key, oe) in &o {
        let Some(ne) = n.get(key) else {
            d.removed.push(oe.clone());
            continue;
        };
        d.unchanged += 1;
        let change =
            |field: &str, before: &Option<String>, after: &Option<String>| EndpointChange {
                method: oe.method.clone(),
                path: oe.path.clone(),
                field: field.to_string(),
                before: before.clone(),
                after: after.clone(),
            };
        if oe.auth != ne.auth {
            d.auth_changed.push(change("auth", &oe.auth, &ne.auth));
        }
        if oe.content_type != ne.content_type {
            d.content_type_changed
                .push(change("content_type", &oe.content_type, &ne.content_type));
        }
    }
    for (key, ne) in &n {
        if !o.contains_key(key) {
            d.added.push(ne.clone());
        }
    }
    d.added.sort();
    d.removed.sort();
    d.auth_changed
        .sort_by(|a, b| (&a.path, &a.method).cmp(&(&b.path, &b.method)));
    d.content_type_changed
        .sort_by(|a, b| (&a.path, &a.method).cmp(&(&b.path, &b.method)));
    d
}

fn change_value(c: &EndpointChange) -> Value {
    Value::Struct {
        name: "ApiEndpointChange".to_string(),
        fields: vec![
            sfield("method", &c.method),
            sfield("path", &c.path),
            sfield("field", &c.field),
            ofield("before", &c.before),
            ofield("after", &c.after),
        ],
    }
}

// ── N16: JS bundle route recovery ─────────────────────────────────────────

/// A route record. `offset` is a byte offset into the text named by `source_url`: the opening
/// quote of the literal in the bundle (N16), or the offset within `sourcesContent` when a map was
/// applied. `line` is 1-based in that same text.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct BundleRoute {
    pub route: String,
    /// `literal` or `template`.
    pub kind: String,
    /// The construct the route was read from: `string-literal`, `template-literal`, `fetch`,
    /// `axios.get` (and siblings), or `jquery.ajax`.
    pub recovered_from: String,
    /// A `${…}` segment was present and is rendered `{}`. The value was never read.
    pub interpolated: bool,
    /// The route was assembled by concatenation; `route` is only the fragment seen.
    pub partial: bool,
    pub fragment: Option<String>,
    pub source_url: String,
    pub offset: usize,
    pub line: usize,
    pub map_applied: bool,
}

/// The result of one bundle read. `map_mode` is `bundle` (N16), `sources-content` (a map was
/// applied) or `fallback` (a map was supplied but carried no content).
#[derive(Clone, Debug, Default)]
pub struct BundleScan {
    pub bundle_url: String,
    pub map_mode: String,
    pub map_applied: bool,
    pub map_reason: Option<String>,
    pub skipped_unlocated: usize,
    pub skipped_non_route: usize,
    pub routes: Vec<BundleRoute>,
}

/// Extensions that make a leading-slash string a *file* path rather than a route. Kept short and
/// named: `/api/export.csv` and `/api/report.json` stay, because a download endpoint is a route.
const ASSET_EXTENSIONS: [&str; 20] = [
    "js", "mjs", "cjs", "css", "map", "png", "jpg", "jpeg", "gif", "svg", "ico", "webp", "avif",
    "woff", "woff2", "ttf", "otf", "eot", "mp4", "webm",
];

/// Nesting cap for `${…}` / string recursion. A crafted bundle with deeply nested interpolations
/// must not be able to exhaust the stack; past the cap the scan treats the literal as unterminated,
/// which counts its fragments instead of guessing at them.
const MAX_NEST: usize = 64;

fn is_html(src: &str) -> bool {
    let t = src.trim_start_matches('\u{feff}').trim_start();
    let b = t.as_bytes();
    match b.first() {
        Some(b'<') => matches!(b.get(1), Some(c) if c.is_ascii_alphabetic() || *c == b'!' || *c == b'?'),
        _ => false,
    }
}

/// A path-shaped string: starts with `/`, is not protocol-relative or a comment opener, carries an
/// alphanumeric, and holds no whitespace. `/` alone is not a path.
fn path_shaped(p: &str) -> bool {
    if p.len() < 2 || !p.starts_with('/') || p.starts_with("//") {
        return false;
    }
    if p.chars().any(|c| c.is_whitespace() || c.is_control()) {
        return false;
    }
    p.bytes().any(|b| b.is_ascii_alphanumeric())
}

fn asset_like(p: &str) -> bool {
    let last = p.rsplit('/').next().unwrap_or(p);
    match last.rsplit_once('.') {
        Some((_, ext)) => ASSET_EXTENSIONS.contains(&ext.to_ascii_lowercase().as_str()),
        None => false,
    }
}

/// Path-shaped runs in text that has no trustworthy extent (an unterminated literal).
fn unlocated_fragments(text: &str) -> usize {
    text.split(|c: char| {
        c.is_whitespace()
            || matches!(
                c,
                '\'' | '"' | '`' | '(' | ')' | ',' | ';' | '{' | '}' | '+' | '='
            )
    })
    .filter(|s| path_shaped(s))
    .count()
}

fn skip_line_comment(b: &[u8], mut i: usize) -> usize {
    while i < b.len() && b[i] != b'\n' {
        i += 1;
    }
    i
}

fn skip_block_comment(b: &[u8], mut i: usize) -> usize {
    i += 2;
    while i + 1 < b.len() {
        if b[i] == b'*' && b[i + 1] == b'/' {
            return i + 2;
        }
        i += 1;
    }
    b.len()
}

/// A regex literal may only start where a value may start. The heuristic is the standard one and
/// is named here because it is a heuristic: `\` is division after a value, a regex after an
/// operator. Getting it wrong costs either a phantom route or a missed one, never an evaluation.
fn is_regex_context(prev: Option<u8>) -> bool {
    matches!(
        prev,
        None | Some(
            b'(' | b',' | b'=' | b':' | b'[' | b'!' | b'&' | b'|' | b'?' | b'{' | b';' | b'+'
                | b'-' | b'*' | b'%' | b'<' | b'>' | b'~' | b'^' | b'\n'
        )
    )
}

/// Skip a regex literal starting at `i`, or `None` if it does not terminate on its line (in which
/// case the `/` was a division after all).
fn skip_regex(b: &[u8], start: usize) -> Option<usize> {
    let mut i = start + 1;
    let mut in_class = false;
    while i < b.len() {
        match b[i] {
            b'\\' => i += 2,
            b'[' => {
                in_class = true;
                i += 1;
            }
            b']' => {
                in_class = false;
                i += 1;
            }
            b'/' if !in_class => return Some(i + 1),
            b'\n' => return None,
            _ => i += 1,
        }
    }
    None
}

#[derive(Debug)]
struct StrTok {
    start: usize,
    end: usize,
    text: String,
    interpolated: bool,
    template: bool,
    closed: bool,
}

fn read_string(b: &[u8], start: usize, q: u8) -> StrTok {
    let mut i = start + 1;
    let mut buf: Vec<u8> = Vec::new();
    let mut closed = false;
    while i < b.len() {
        match b[i] {
            b'\\' if i + 1 < b.len() => {
                let e = b[i + 1];
                match e {
                    b'/' | b'\\' | b'\'' | b'"' | b'`' => buf.push(e),
                    _ => {
                        buf.push(b'\\');
                        buf.push(e);
                    }
                }
                i += 2;
            }
            c if c == q => {
                i += 1;
                closed = true;
                break;
            }
            // A raw newline cannot appear in a JS string literal; stopping here keeps a broken
            // literal from swallowing the rest of the file.
            b'\n' => break,
            c => {
                buf.push(c);
                i += 1;
            }
        }
    }
    StrTok {
        start,
        end: i,
        text: String::from_utf8_lossy(&buf).into_owned(),
        interpolated: false,
        template: false,
        closed,
    }
}

fn read_template(b: &[u8], start: usize, depth: usize) -> StrTok {
    let mut i = start + 1;
    let mut buf: Vec<u8> = Vec::new();
    let mut closed = false;
    let mut interpolated = false;
    while i < b.len() {
        match b[i] {
            b'\\' if i + 1 < b.len() => {
                let e = b[i + 1];
                match e {
                    b'/' | b'\\' | b'\'' | b'"' | b'`' | b'$' => buf.push(e),
                    _ => {
                        buf.push(b'\\');
                        buf.push(e);
                    }
                }
                i += 2;
            }
            b'`' => {
                i += 1;
                closed = true;
                break;
            }
            b'$' if b.get(i + 1) == Some(&b'{') => {
                interpolated = true;
                buf.extend_from_slice(b"{}");
                i = skip_js_expr(b, i + 2, depth + 1);
            }
            c => {
                buf.push(c);
                i += 1;
            }
        }
    }
    StrTok {
        start,
        end: i,
        text: String::from_utf8_lossy(&buf).into_owned(),
        interpolated,
        template: true,
        closed,
    }
}

/// Skip a `${ … }` body, honouring nested braces, strings, templates and comments. Returns the
/// offset just past the closing `}`, or the end of input.
fn skip_js_expr(b: &[u8], mut i: usize, depth: usize) -> usize {
    if depth > MAX_NEST {
        return b.len();
    }
    let mut open = 1usize;
    while i < b.len() {
        match b[i] {
            b'{' => {
                open += 1;
                i += 1;
            }
            b'}' => {
                open -= 1;
                i += 1;
                if open == 0 {
                    return i;
                }
            }
            c @ (b'\'' | b'"') => {
                let t = read_string(b, i, c);
                i = t.end.max(i + 1);
            }
            b'`' => {
                let t = read_template(b, i, depth + 1);
                i = t.end.max(i + 1);
            }
            b'/' if b.get(i + 1) == Some(&b'/') => i = skip_line_comment(b, i),
            b'/' if b.get(i + 1) == Some(&b'*') => i = skip_block_comment(b, i),
            _ => i += 1,
        }
    }
    i
}

/// Every string and template literal in the source, in order. Comments and regex literals are
/// skipped: their bytes are not string literals, and reading a route out of `// see /api/notes`
/// would be a fabricated finding.
fn scan_js(src: &str) -> Vec<StrTok> {
    let b = src.as_bytes();
    let mut out: Vec<StrTok> = Vec::new();
    let mut i = 0usize;
    let mut prev: Option<u8> = None;
    while i < b.len() {
        match b[i] {
            c @ (b'\'' | b'"') => {
                let t = read_string(b, i, c);
                i = t.end.max(i + 1);
                prev = Some(c);
                out.push(t);
            }
            b'`' => {
                let t = read_template(b, i, 0);
                i = t.end.max(i + 1);
                prev = Some(b'`');
                out.push(t);
            }
            b'/' => {
                if b.get(i + 1) == Some(&b'/') {
                    i = skip_line_comment(b, i);
                } else if b.get(i + 1) == Some(&b'*') {
                    i = skip_block_comment(b, i);
                } else if is_regex_context(prev) {
                    match skip_regex(b, i) {
                        Some(n) => i = n,
                        None => {
                            prev = Some(b'/');
                            i += 1;
                        }
                    }
                } else {
                    prev = Some(b'/');
                    i += 1;
                }
            }
            c if c.is_ascii_whitespace() => i += 1,
            c => {
                prev = Some(c);
                i += 1;
            }
        }
    }
    out
}

fn ident_byte(c: u8) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, b'_' | b'$' | b'.')
}

/// Which construct produced this literal. The answer is read from the bytes immediately before the
/// opening quote — no symbol table, because there is no execution to build one.
fn recovered_from(src: &str, tok: &StrTok) -> String {
    let b = src.as_bytes();
    let mut i = tok.start;
    while i > 0 && b[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    if i > 0 && b[i - 1] == b'(' {
        let mut j = i - 1;
        while j > 0 && b[j - 1].is_ascii_whitespace() {
            j -= 1;
        }
        let mut k = j;
        while k > 0 && ident_byte(b[k - 1]) {
            k -= 1;
        }
        let callee = &src[k..j];
        if callee == "fetch" {
            return "fetch".to_string();
        }
        if callee.starts_with("axios.") {
            return callee.to_string();
        }
        if callee == "$.ajax" {
            return "jquery.ajax".to_string();
        }
    } else if i > 0 && b[i - 1] == b':' {
        let mut j = i - 1;
        while j > 0 && b[j - 1].is_ascii_whitespace() {
            j -= 1;
        }
        let mut k = j;
        while k > 0 && ident_byte(b[k - 1]) {
            k -= 1;
        }
        if &src[k..j] == "url" && src[..tok.start].contains("$.ajax") {
            return "jquery.ajax".to_string();
        }
    }
    match tok.template {
        true => "template-literal".to_string(),
        false => "string-literal".to_string(),
    }
}

/// True when the literal is one side of a `+`. The bytes on the other side may or may not be a
/// string; either way the route is incomplete, which is what `partial` says.
fn is_concatenated(src: &str, tok: &StrTok) -> bool {
    let b = src.as_bytes();
    let mut i = tok.start;
    while i > 0 && b[i - 1].is_ascii_whitespace() {
        i -= 1;
    }
    let left = i > 0 && b[i - 1] == b'+';
    let mut j = tok.end;
    while j < b.len() && b[j].is_ascii_whitespace() {
        j += 1;
    }
    left || b.get(j) == Some(&b'+')
}

fn line_of(text: &str, offset: usize) -> usize {
    1 + text.as_bytes()[..offset.min(text.len())]
        .iter()
        .filter(|c| **c == b'\n')
        .count()
}

/// The scan itself. One source of text with a name; every record it produces cites both.
fn extract_routes(text: &str, source_url: &str, map_applied: bool, scan: &mut BundleScan) {
    let mut found: Vec<BundleRoute> = Vec::new();
    for tok in scan_js(text) {
        if !tok.closed {
            scan.skipped_unlocated += unlocated_fragments(&tok.text);
            continue;
        }
        if !path_shaped(&tok.text) {
            continue;
        }
        if asset_like(&tok.text) {
            scan.skipped_non_route += 1;
            continue;
        }
        if source_url.trim().is_empty() {
            // No citable source: the offset would point into text nothing names.
            scan.skipped_unlocated += 1;
            continue;
        }
        let partial = is_concatenated(text, &tok);
        found.push(BundleRoute {
            route: tok.text.clone(),
            kind: match tok.template {
                true => "template".to_string(),
                false => "literal".to_string(),
            },
            recovered_from: recovered_from(text, &tok),
            interpolated: tok.interpolated,
            partial,
            fragment: match partial {
                true => Some(tok.text.clone()),
                false => None,
            },
            source_url: source_url.to_string(),
            offset: tok.start,
            line: line_of(text, tok.start),
            map_applied,
        });
    }
    scan.routes.extend(found);
}

fn sort_routes(routes: &mut [BundleRoute]) {
    routes.sort_by(|a, b| {
        (a.source_url.as_str(), a.offset, a.route.as_str()).cmp(&(
            b.source_url.as_str(),
            b.offset,
            b.route.as_str(),
        ))
    });
}

fn check_bundle(source: &str, bundle_url: &str) -> Result<(), String> {
    let url = bundle_url.trim();
    if url.is_empty() {
        return Err(format!(
            "{CODE_BUNDLE_NO_EVIDENCE}: api.bundle_routes: bundle_url is empty — a route that \
             cannot name the bundle it was found in is not a finding"
        ));
    }
    if is_html(source) {
        return Err(format!(
            "{CODE_BUNDLE_NOT_JS}: {url}: the first bytes are HTML, not JavaScript — this is a \
             page saved as .js; parsing it as a bundle would produce garbage routes"
        ));
    }
    Ok(())
}

/// N16: recover routes from a JavaScript bundle, as text.
pub fn bundle_routes(source: &str, bundle_url: &str) -> Result<BundleScan, String> {
    check_bundle(source, bundle_url)?;
    let mut scan = BundleScan {
        bundle_url: bundle_url.trim().to_string(),
        map_mode: "bundle".to_string(),
        ..Default::default()
    };
    extract_routes(source, scan.bundle_url.clone().as_str(), false, &mut scan);
    sort_routes(&mut scan.routes);
    Ok(scan)
}

fn route_value(r: &BundleRoute) -> Value {
    Value::Struct {
        name: "BundleRoute".to_string(),
        fields: vec![
            sfield("route", &r.route),
            sfield("kind", &r.kind),
            sfield("recovered_from", &r.recovered_from),
            ("interpolated".to_string(), Value::Bool(r.interpolated)),
            ("partial".to_string(), Value::Bool(r.partial)),
            ofield("fragment", &r.fragment),
            sfield("source_url", &r.source_url),
            ifield("offset", r.offset),
            ifield("line", r.line),
            ("map_applied".to_string(), Value::Bool(r.map_applied)),
        ],
    }
}

fn bundle_scan_value(s: &BundleScan) -> Value {
    Value::Struct {
        name: "BundleScan".to_string(),
        fields: vec![
            sfield("bundle_url", &s.bundle_url),
            sfield("map_mode", &s.map_mode),
            ("map_applied".to_string(), Value::Bool(s.map_applied)),
            ofield("map_reason", &s.map_reason),
            ifield("count", s.routes.len()),
            ifield("skipped_unlocated", s.skipped_unlocated),
            ifield("skipped_non_route", s.skipped_non_route),
            (
                "routes".to_string(),
                Value::Array(s.routes.iter().map(route_value).collect()),
            ),
        ],
    }
}

fn bool_field(fs: &[(String, Value)], k: &str) -> bool {
    matches!(
        fs.iter().find(|(n, _)| n == k).map(|(_, v)| v),
        Some(Value::Bool(true))
    )
}

fn usize_field(fs: &[(String, Value)], k: &str, fname: &str) -> Result<usize, String> {
    match fs.iter().find(|(n, _)| n == k).map(|(_, v)| v) {
        Some(Value::Int(i)) if *i >= 0 => Ok(*i as usize),
        Some(other) => Err(bad(
            fname,
            &format!("`{k}` expected a non-negative Int, got {}", type_name(other)),
        )),
        None => Err(bad(fname, &format!("BundleScan/BundleRoute without `{k}`"))),
    }
}

/// One `BundleRoute` struct read back from the value layer.
fn read_route(fields: &[(String, Value)], fname: &str) -> Result<BundleRoute, String> {
    Ok(BundleRoute {
        route: sv(fields, "route").ok_or_else(|| bad(fname, "BundleRoute without a `route`"))?,
        kind: sv(fields, "kind").unwrap_or_else(|| "literal".to_string()),
        recovered_from: sv(fields, "recovered_from")
            .unwrap_or_else(|| "string-literal".to_string()),
        interpolated: bool_field(fields, "interpolated"),
        partial: bool_field(fields, "partial"),
        fragment: sv(fields, "fragment"),
        source_url: sv(fields, "source_url").unwrap_or_default(),
        offset: usize_field(fields, "offset", fname)?,
        line: usize_field(fields, "line", fname)?,
        map_applied: bool_field(fields, "map_applied"),
    })
}

fn bundle_scan_of(fs: &[(String, Value)], fname: &str) -> Result<BundleScan, String> {
    let routes = fs
        .iter()
        .find(|(n, _)| n == "routes")
        .map(|(_, v)| v)
        .ok_or_else(|| bad(fname, "BundleScan without a `routes` array"))?;
    let Value::Array(items) = routes else {
        return Err(bad(
            fname,
            &format!("BundleScan `routes` expected an array, got {}", type_name(routes)),
        ));
    };
    let mut out: Vec<BundleRoute> = Vec::new();
    for it in items {
        let Value::Struct { name, fields } = it else {
            return Err(bad(
                fname,
                &format!("expected BundleRoute, got {}", type_name(it)),
            ));
        };
        if name != "BundleRoute" {
            return Err(bad(
                fname,
                &format!("expected BundleRoute, got struct {name}"),
            ));
        }
        out.push(read_route(fields, fname)?);
    }
    sort_routes(&mut out);
    Ok(BundleScan {
        bundle_url: sv(fs, "bundle_url").unwrap_or_default(),
        map_mode: sv(fs, "map_mode").unwrap_or_else(|| "bundle".to_string()),
        map_applied: bool_field(fs, "map_applied"),
        map_reason: sv(fs, "map_reason"),
        skipped_unlocated: usize_field(fs, "skipped_unlocated", fname).unwrap_or(0),
        skipped_non_route: usize_field(fs, "skipped_non_route", fname).unwrap_or(0),
        routes: out,
    })
}

fn bundle_scan_json(s: &BundleScan) -> String {
    json!({
        "schema_version": "tallow.api.bundle_routes.v1",
        "bundle_url": s.bundle_url,
        "map_mode": s.map_mode,
        "map_applied": s.map_applied,
        "map_reason": s.map_reason,
        "count": s.routes.len(),
        "skipped_unlocated": s.skipped_unlocated,
        "skipped_non_route": s.skipped_non_route,
        // Every row carries the URL and the byte offset it was read from. A row without both is
        // not in this array — it was counted in `skipped_unlocated` instead.
        "routes": s.routes.iter().map(|r| json!({
            "route": r.route,
            "kind": r.kind,
            "recovered_from": r.recovered_from,
            "interpolated": r.interpolated,
            "partial": r.partial,
            "fragment": r.fragment,
            "source_url": r.source_url,
            "offset": r.offset,
            "line": r.line,
            "map_applied": r.map_applied,
        })).collect::<Vec<_>>(),
    })
    .to_string()
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
            "graphql_from_sdl" => Ok(schema_value(
                &parse_sdl(&str_arg(&args, 0, "graphql_from_sdl")?)?,
                "sdl",
            )),
            "graphql_from_introspection" => Ok(schema_value(
                &parse_introspection(&str_arg(&args, 0, "graphql_from_introspection")?)?,
                "introspection",
            )),
            "graphql_diff" => {
                let old = schema_of(
                    args.get(0)
                        .ok_or_else(|| bad("graphql_diff", "missing argument 1"))?,
                    "graphql_diff",
                )?;
                let new = schema_of(
                    args.get(1)
                        .ok_or_else(|| bad("graphql_diff", "missing argument 2"))?,
                    "graphql_diff",
                )?;
                let d = graphql_diff(&old, &new);
                Ok(Value::Struct {
                    name: "GraphqlDiff".to_string(),
                    fields: vec![
                        ("added_types".to_string(), strings(&d.added_types)),
                        ("removed_types".to_string(), strings(&d.removed_types)),
                        ("added_fields".to_string(), strings(&d.added_fields)),
                        ("removed_fields".to_string(), strings(&d.removed_fields)),
                        ("added_args".to_string(), strings(&d.added_args)),
                        ("removed_args".to_string(), strings(&d.removed_args)),
                        (
                            "type_changes".to_string(),
                            Value::Array(
                                d.type_changes
                                    .iter()
                                    .map(|c| Value::Struct {
                                        name: "GraphqlTypeChange".to_string(),
                                        fields: vec![
                                            sfield("type_name", &c.type_name),
                                            sfield("field", &c.field),
                                            sfield("old_type", &c.old_type),
                                            sfield("new_type", &c.new_type),
                                        ],
                                    })
                                    .collect(),
                            ),
                        ),
                        ("breaking".to_string(), Value::Bool(d.breaking())),
                    ],
                })
            }
            "identifiers" => {
                let eps = endpoints_of(
                    args.get(0)
                        .ok_or_else(|| bad("identifiers", "missing argument 1"))?,
                    "identifiers",
                )?;
                Ok(Value::Array(
                    identifiers(&eps)
                        .into_iter()
                        .map(|s| Value::Struct {
                            name: "ApiPathSignal".to_string(),
                            fields: vec![
                                sfield("signal", &s.signal),
                                sfield("method", &s.method),
                                sfield("path", &s.path),
                                sfield("segment", &s.segment),
                                ifield("index", s.index),
                                sfield("kind", &s.kind),
                            ],
                        })
                        .collect(),
                ))
            }
            "diff" => {
                let old = inventory_of(struct_arg(&args, 0, "ApiInventory", "diff")?, "diff")?;
                let new = inventory_of(struct_arg(&args, 1, "ApiInventory", "diff")?, "diff")?;
                let d = diff(&old, &new);
                Ok(Value::Struct {
                    name: "ApiInventoryDiff".to_string(),
                    fields: vec![
                        sfield("doc_url_old", &d.doc_url_old),
                        sfield("doc_url_new", &d.doc_url_new),
                        (
                            "added".to_string(),
                            Value::Array(d.added.iter().map(endpoint_value).collect()),
                        ),
                        (
                            "removed".to_string(),
                            Value::Array(d.removed.iter().map(endpoint_value).collect()),
                        ),
                        (
                            "auth_changed".to_string(),
                            Value::Array(d.auth_changed.iter().map(change_value).collect()),
                        ),
                        (
                            "content_type_changed".to_string(),
                            Value::Array(d.content_type_changed.iter().map(change_value).collect()),
                        ),
                        ifield("added_count", d.added.len()),
                        ifield("removed_count", d.removed.len()),
                        ifield("unchanged", d.unchanged),
                        ("breaking".to_string(), Value::Bool(d.breaking())),
                        sfield("summary", &d.summary()),
                    ],
                })
            }
            // ── N16: JS bundle route recovery ────────────────────────────
            "bundle_routes" => Ok(bundle_scan_value(&bundle_routes(
                &str_arg(&args, 0, "bundle_routes")?,
                &str_arg(&args, 1, "bundle_routes")?,
            )?)),
            "bundle_routes_json" => {
                let scan = bundle_scan_of(
                    struct_arg(&args, 0, "BundleScan", "bundle_routes_json")?,
                    "bundle_routes_json",
                )?;
                Ok(Value::String(bundle_scan_json(&scan)))
            }
            // Constructors: E0115 — a stdlib struct cannot be written as a literal in `.tl`, so a
            // struct this module only *takes* is a struct no program can build.
            "bundle_route" => Ok(route_value(&BundleRoute {
                route: str_arg(&args, 0, "bundle_route")?,
                kind: str_arg(&args, 1, "bundle_route")?,
                recovered_from: str_arg(&args, 2, "bundle_route")?,
                source_url: str_arg(&args, 3, "bundle_route")?,
                offset: int_arg(&args, 4, "bundle_route")?,
                line: int_arg(&args, 5, "bundle_route")?,
                interpolated: bool_arg(&args, 6, "bundle_route")?,
                partial: bool_arg(&args, 7, "bundle_route")?,
                fragment: opt_str_arg(&args, 8, "bundle_route")?,
                map_applied: bool_arg(&args, 9, "bundle_route")?,
            })),
            "bundle_scan" => Ok(bundle_scan_value(&BundleScan {
                bundle_url: str_arg(&args, 0, "bundle_scan")?,
                map_mode: str_arg(&args, 1, "bundle_scan")?,
                map_applied: bool_arg(&args, 2, "bundle_scan")?,
                map_reason: opt_str_arg(&args, 3, "bundle_scan")?,
                skipped_unlocated: int_arg(&args, 4, "bundle_scan")?,
                skipped_non_route: int_arg(&args, 5, "bundle_scan")?,
                routes: routes_arg(&args, 6, "bundle_scan")?,
            })),
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

    // ── N14 ──────────────────────────────────────────────────────────────

    const SDL: &str = r#"
        """the user"""
        type User implements Node @cache(ttl: 60) {
          id: ID!
          posts(first: Int = 10, filter: PostFilter): [Post!]!
        }
        input PostFilter { author: String = "me", tags: [String!] }
        enum Role { ADMIN @deprecated GUEST }
        scalar DateTime
        extend type User { email: String }
    "#;

    #[test]
    fn sdl_handles_nested_input_types_descriptions_and_extends() {
        let s = parse_sdl(SDL).unwrap();
        let user = &s["User"];
        assert_eq!(user.kind, "object");
        let posts = user.fields.iter().find(|f| f.name == "posts").unwrap();
        assert_eq!(posts.type_name, "[Post!]!");
        assert_eq!(posts.args.len(), 2);
        let filter = posts.args.iter().find(|a| a.name == "filter").unwrap();
        assert_eq!(filter.type_name, "PostFilter");
        // `extend` merged, it did not replace.
        assert!(user.fields.iter().any(|f| f.name == "email"));
        assert!(user.fields.iter().any(|f| f.name == "id"));
        assert_eq!(s["PostFilter"].kind, "input");
        assert_eq!(s["Role"].kind, "enum");
        assert!(s["Role"].fields.iter().any(|f| f.name == "ADMIN"));
        assert_eq!(s["DateTime"].kind, "scalar");
    }

    #[test]
    fn introspection_and_sdl_share_one_shape() {
        let sdl = parse_sdl("type User { id: ID! name: String }").unwrap();
        let intro = json!({"data":{"__schema":{"types":[
            {"kind":"OBJECT","name":"User","fields":[
                {"name":"id","type":{"kind":"NON_NULL","ofType":{"kind":"SCALAR","name":"ID"}},"args":[]},
                {"name":"name","type":{"kind":"SCALAR","name":"String"},"args":[]}]},
            {"kind":"OBJECT","name":"__Type","fields":[]}]}}})
        .to_string();
        let parsed = parse_introspection(&intro).unwrap();
        assert_eq!(sdl, parsed, "the two capture paths must agree");
        assert!(!parsed.contains_key("__Type"), "meta-types are skipped");
        let e = parse_introspection(r#"{"data":{}}"#).unwrap_err();
        assert!(e.starts_with(CODE_INTROSPECTION), "{e}");
        let e = parse_sdl("type X { a: [Int! }").unwrap_err();
        assert!(e.starts_with(CODE_GRAPHQL_PARSE), "{e}");
        let e = parse_sdl("frobnicate X").unwrap_err();
        assert!(
            e.starts_with(CODE_GRAPHQL_PARSE) && e.contains("frobnicate"),
            "{e}"
        );
    }

    #[test]
    fn a_changed_field_type_is_both_a_removal_and_an_addition() {
        let old = parse_sdl("type User { id: ID! }").unwrap();
        let new = parse_sdl("type User { id: String }").unwrap();
        let d = graphql_diff(&old, &new);
        assert_eq!(d.removed_fields, vec!["User.id"]);
        assert_eq!(d.added_fields, vec!["User.id"]);
        assert_eq!(d.type_changes.len(), 1);
        assert_eq!(d.type_changes[0].old_type, "ID!");
        assert_eq!(d.type_changes[0].new_type, "String");
        assert!(d.breaking());
    }

    #[test]
    fn removed_field_type_and_arg_are_reported_separately() {
        let old = parse_sdl("type Q { f(a: Int): Int name: String } type Gone { x: Int }").unwrap();
        let new = parse_sdl("type Q { f(a: String): Int }").unwrap();
        let d = graphql_diff(&old, &new);
        assert_eq!(d.removed_types, vec!["Gone"]);
        assert_eq!(d.removed_fields, vec!["Q.name"]);
        assert_eq!(d.removed_args, vec!["Q.f(a)"]);
        assert_eq!(d.added_args, vec!["Q.f(a)"]);
        assert_eq!(d.type_changes[0].field, "f(a)");
        assert!(d.added_types.is_empty(), "a removal must not invent a type");
    }

    // ── N20 ──────────────────────────────────────────────────────────────

    fn ep(m: &str, p: &str) -> Endpoint {
        Endpoint {
            method: m.into(),
            path: p.into(),
            auth: None,
            content_type: None,
            source: URL.into(),
        }
    }

    #[test]
    fn identifiers_flag_literals_only_and_sort() {
        let eps = vec![
            ep(
                "GET",
                "/users/42/orders/9f8e7d6c-5b4a-4392-8170-0f1e2d3c4b5a",
            ),
            ep("GET", "/users/{id}"),
            ep("GET", "/v1/health"),
            ep("POST", "/users/42"),
        ];
        let rows = identifiers(&eps);
        let labels: Vec<String> = rows
            .iter()
            .map(|r| format!("{} {} #{} {}", r.method, r.path, r.index, r.kind))
            .collect();
        // Sorted by (path, method, index) — and a path may hold more than one signal.
        assert_eq!(
            labels,
            vec![
                "POST /users/42 #1 numeric".to_string(),
                "GET /users/42/orders/9f8e7d6c-5b4a-4392-8170-0f1e2d3c4b5a #1 numeric".to_string(),
                "GET /users/42/orders/9f8e7d6c-5b4a-4392-8170-0f1e2d3c4b5a #3 uuid".to_string(),
            ]
        );
        assert!(rows.iter().all(|r| r.signal == SIGNAL_OBJECT_ID));
        // A signal is not a finding: no verdict word appears anywhere in the row.
        for r in &rows {
            let s = format!("{r:?}").to_lowercase();
            assert!(!s.contains("vulnerable") && !s.contains("bola") && !s.contains("idor"));
        }
    }

    #[test]
    fn hex_garbage_is_not_a_uuid() {
        assert!(segment_kind("9f8e7d6c-5b4a-4392-8170-0f1e2d3c4b5a").is_some());
        assert!(segment_kind("9F8E7D6C-5B4A-4392-8170-0F1E2D3C4B5A").is_some());
        assert!(segment_kind("9f8e7d6c5b4a439281700f1e2d3c4b5a").is_none());
        assert!(segment_kind("9f8e7d6c-5b4a-4392-8170").is_none());
        assert!(segment_kind("deadbeef-cafe").is_none());
        assert!(segment_kind("v1").is_none());
        assert!(
            segment_kind("0").is_some(),
            "a nil-ish numeric id is still an id"
        );
    }

    // ── N21 ──────────────────────────────────────────────────────────────

    fn full_ep(m: &str, p: &str, auth: Option<&str>, ct: Option<&str>) -> Endpoint {
        Endpoint {
            method: m.into(),
            path: p.into(),
            auth: auth.map(str::to_string),
            content_type: ct.map(str::to_string),
            source: URL.into(),
        }
    }

    fn snapshot(doc: &str, eps: Vec<Endpoint>) -> Inventory {
        Inventory {
            doc_url: doc.into(),
            openapi_version: "3.0.0".into(),
            endpoints: eps,
        }
    }

    #[test]
    fn diff_names_both_sides_and_treats_removal_as_loud() {
        let old = snapshot(
            "a",
            vec![
                full_ep("GET", "/a", Some("api_key"), Some("application/json")),
                full_ep("GET", "/gone", None, None),
            ],
        );
        let new = snapshot(
            "b",
            vec![
                full_ep("GET", "/a", Some("none"), Some("application/xml")),
                full_ep("POST", "/new", None, None),
            ],
        );
        let d = diff(&old, &new);
        assert_eq!((d.added.len(), d.removed.len(), d.unchanged), (1, 1, 1));
        assert_eq!(d.removed[0].path, "/gone");
        assert_eq!(d.added[0].method, "POST");
        assert_eq!(d.auth_changed.len(), 1);
        assert_eq!(d.auth_changed[0].field, "auth");
        assert_eq!(d.auth_changed[0].before.as_deref(), Some("api_key"));
        assert_eq!(d.auth_changed[0].after.as_deref(), Some("none"));
        assert_eq!(d.content_type_changed.len(), 1);
        assert_eq!(
            d.content_type_changed[0].before.as_deref(),
            Some("application/json")
        );
        assert_eq!(
            d.content_type_changed[0].after.as_deref(),
            Some("application/xml")
        );
        assert!(d.breaking());
        assert_eq!((d.doc_url_old.as_str(), d.doc_url_new.as_str()), ("a", "b"));
        assert!(d.summary().contains("1 removed"));
    }

    #[test]
    fn identical_or_reordered_snapshots_are_not_changes() {
        let same = snapshot("a", vec![full_ep("GET", "/a", None, None)]);
        let d = diff(&same, &same);
        assert!(!d.breaking());
        assert!(d.added.is_empty() && d.removed.is_empty() && d.auth_changed.is_empty());
        assert_eq!(d.unchanged, 1);
        // Order in the document is not information: matching is by (path, method).
        let reordered = snapshot(
            "a",
            vec![
                full_ep("POST", "/b", None, None),
                full_ep("GET", "/a", None, None),
            ],
        );
        let d2 = diff(&same, &reordered);
        assert_eq!((d2.added.len(), d2.removed.len(), d2.unchanged), (1, 0, 1));
    }

    #[test]
    fn a_content_type_change_alone_is_reported_but_not_breaking() {
        let old = snapshot(
            "a",
            vec![full_ep("POST", "/x", None, Some("application/json"))],
        );
        let new = snapshot("a", vec![full_ep("POST", "/x", None, Some("text/csv"))]);
        let d = diff(&old, &new);
        assert_eq!(d.content_type_changed.len(), 1);
        assert!(!d.breaking(), "a media type change is not a removal");
    }

    #[test]
    fn diff_round_trips_through_the_value_layer() {
        let old = inventory_value(&snapshot(
            "a",
            vec![full_ep("GET", "/a", Some("api_key"), None)],
        ));
        let new = inventory_value(&snapshot("b", vec![full_ep("GET", "/a", None, None)]));
        let Value::Struct { name, fields } = dispatch("diff", vec![old, new]).unwrap().unwrap()
        else {
            panic!("expected an ApiInventoryDiff")
        };
        assert_eq!(name, "ApiInventoryDiff");
        let auth = fields
            .iter()
            .find(|(k, _)| k == "auth_changed")
            .map(|(_, v)| v)
            .unwrap();
        let Value::Array(rows) = auth else {
            panic!("expected an array")
        };
        assert_eq!(rows.len(), 1);
        assert_eq!(
            sv(&container(rows, 0), "before").as_deref(),
            Some("api_key")
        );
        assert_eq!(
            sv(&container(rows, 0), "after"),
            None,
            "undeclared renders nil, not an empty string"
        );
    }

    // ── N16: bundle route recovery ───────────────────────────────────────

    const BUNDLE_URL: &str = "https://x.test/static/app.min.js";

    #[test]
    fn a_path_literal_is_recovered_with_its_byte_offset() {
        let src = r#"var a="/api/v1/users";"#;
        let s = bundle_routes(src, BUNDLE_URL).unwrap();
        assert_eq!(s.map_mode, "bundle");
        assert!(!s.map_applied);
        assert_eq!(s.skipped_unlocated, 0);
        assert_eq!(s.routes.len(), 1);
        let r = &s.routes[0];
        assert_eq!(r.route, "/api/v1/users");
        assert_eq!(r.kind, "literal");
        assert_eq!(r.recovered_from, "string-literal");
        // The offset of the opening quote; the route is cited, not asserted.
        assert_eq!(r.offset, src.find('"').unwrap());
        assert_eq!(r.line, 1);
        assert_eq!(r.source_url, BUNDLE_URL);
        assert!(!r.partial && !r.interpolated);
        assert_eq!(r.fragment, None);
    }

    #[test]
    fn fetch_axios_and_jquery_arguments_are_named_after_their_construct() {
        let src = "fetch(\"/api/a\");\naxios.post('/api/b');\n$.ajax({url: '/api/c'});\nvar d = \"/api/d\";\n";
        let s = bundle_routes(src, BUNDLE_URL).unwrap();
        let got: Vec<(String, String)> = s
            .routes
            .iter()
            .map(|r| (r.route.clone(), r.recovered_from.clone()))
            .collect();
        assert_eq!(
            got,
            vec![
                ("/api/a".to_string(), "fetch".to_string()),
                ("/api/b".to_string(), "axios.post".to_string()),
                ("/api/c".to_string(), "jquery.ajax".to_string()),
                ("/api/d".to_string(), "string-literal".to_string()),
            ],
            "document order, each named by the construct that produced it"
        );
    }

    #[test]
    fn a_template_literal_records_an_interpolation_not_a_value() {
        let src = "fetch(`/api/users/${id}/orders`)";
        let s = bundle_routes(src, BUNDLE_URL).unwrap();
        let r = &s.routes[0];
        assert_eq!(r.route, "/api/users/{}/orders", "the id was never read");
        assert_eq!(r.kind, "template");
        assert_eq!(r.recovered_from, "fetch");
        assert!(r.interpolated, "the segment must be declared an interpolation");
        assert!(!r.partial, "the shape is complete; only the value was interpolated");
        assert_eq!(r.offset, src.find('`').unwrap());
    }

    #[test]
    fn a_concatenated_route_is_partial_and_carries_the_fragment_it_saw() {
        let src = r#"var u = "/api/users/" + id + "/orders";"#;
        let s = bundle_routes(src, BUNDLE_URL).unwrap();
        let parts: Vec<(&str, bool)> = s
            .routes
            .iter()
            .map(|r| (r.route.as_str(), r.partial))
            .collect();
        assert_eq!(parts, vec![("/api/users/", true), ("/orders", true)]);
        for r in &s.routes {
            assert_eq!(
                r.fragment.as_deref(),
                Some(r.route.as_str()),
                "a partial record names the fragment, and completes nothing"
            );
        }
    }

    #[test]
    fn a_page_saved_as_js_is_refused_by_name() {
        let e = bundle_routes(
            "<!doctype html>\n<html><body>/api/x</body></html>",
            BUNDLE_URL,
        )
        .unwrap_err();
        assert!(e.starts_with(CODE_BUNDLE_NOT_JS), "{e}");
        // A BOM and leading blank lines do not hide it.
        let e = bundle_routes(
            "\u{feff}\n  <html><script>var x='/api/x'</script></html>",
            BUNDLE_URL,
        )
        .unwrap_err();
        assert!(e.starts_with(CODE_BUNDLE_NOT_JS), "{e}");
        // A route with no bundle to cite is refused, not emitted with an empty source.
        let e = bundle_routes("var a='/api/x'", "   ").unwrap_err();
        assert!(e.starts_with(CODE_BUNDLE_NO_EVIDENCE), "{e}");
    }

    #[test]
    fn comments_and_regex_literals_do_not_become_routes() {
        let src = r#"
            // see /api/from-a-line-comment
            /* and /api/from-a-block-comment */
            var re = /\/api\/v1\/pattern/;
            var keep = "/api/kept";
        "#;
        let s = bundle_routes(src, BUNDLE_URL).unwrap();
        let got: Vec<&str> = s.routes.iter().map(|r| r.route.as_str()).collect();
        assert_eq!(got, vec!["/api/kept"]);
    }

    #[test]
    fn asset_paths_and_unterminated_literals_are_counted_not_emitted() {
        let src = r#"var a = "/static/app.css"; var b = "/img/logo.png"; var c = "/api/real";"#;
        let s = bundle_routes(src, BUNDLE_URL).unwrap();
        assert_eq!(s.skipped_non_route, 2);
        assert_eq!(s.routes.len(), 1);
        assert_eq!(s.routes[0].route, "/api/real");

        // Truncated bundle: the literal has no trustworthy extent, so the fragment is counted.
        let s = bundle_routes(r#"var a = 1; var b = "/api/truncated"#, BUNDLE_URL).unwrap();
        assert_eq!(s.skipped_unlocated, 1);
        assert!(s.routes.is_empty(), "an unlocatable fragment is not a finding");
    }

    #[test]
    fn the_json_rendering_keeps_url_and_offset_on_every_row() {
        let scan = bundle_routes(
            "var a=\"/api/a\"; fetch(`/api/b/${x}`)",
            BUNDLE_URL,
        )
        .unwrap();
        let Value::String(s) =
            dispatch("bundle_routes_json", vec![bundle_scan_value(&scan)])
                .unwrap()
                .unwrap()
        else {
            panic!("expected a string")
        };
        let doc: J = serde_json::from_str(&s).unwrap();
        assert_eq!(doc["schema_version"], "tallow.api.bundle_routes.v1");
        assert_eq!(doc["count"], 2);
        assert_eq!(doc["skipped_unlocated"], 0);
        let rows = doc["routes"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        for row in rows {
            assert_eq!(row["source_url"], BUNDLE_URL);
            assert!(row["offset"].as_u64().is_some(), "no row is emitted bare");
            assert_eq!(row["map_applied"], false);
        }
    }

    #[test]
    fn the_constructors_round_trip_through_the_reader() {
        let route = dispatch(
            "bundle_route",
            vec![
                Value::String("/api/a".into()),
                Value::String("literal".into()),
                Value::String("fetch".into()),
                Value::String(BUNDLE_URL.into()),
                Value::Int(12),
                Value::Int(1),
                Value::Bool(false),
                Value::Bool(false),
                Value::Nil,
                Value::Bool(false),
            ],
        )
        .unwrap()
        .unwrap();
        let scan = dispatch(
            "bundle_scan",
            vec![
                Value::String(BUNDLE_URL.into()),
                Value::String("bundle".into()),
                Value::Bool(false),
                Value::Nil,
                Value::Int(0),
                Value::Int(0),
                Value::Array(vec![route]),
            ],
        )
        .unwrap()
        .unwrap();
        let Value::Struct { name, fields } = &scan else {
            panic!("expected a BundleScan")
        };
        assert_eq!(name, "BundleScan");
        let back = bundle_scan_of(fields, "test").unwrap();
        assert_eq!(back.routes.len(), 1);
        assert_eq!(back.routes[0].route, "/api/a");
        assert_eq!(back.routes[0].offset, 12);
        assert_eq!(back.routes[0].recovered_from, "fetch");

        // A wrong argument type is a named refusal, not a panic.
        let e = dispatch("bundle_routes", vec![Value::Int(1), Value::String(BUNDLE_URL.into())])
            .unwrap()
            .unwrap_err();
        assert!(e.starts_with(CODE_ARG), "{e}");
    }

    fn container(rows: &[Value], i: usize) -> Vec<(String, Value)> {
        match &rows[i] {
            Value::Struct { fields, .. } => fields.clone(),
            other => panic!("expected a struct, got {}", type_name(other)),
        }
    }
}
