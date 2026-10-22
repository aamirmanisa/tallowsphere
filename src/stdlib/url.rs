//! Standard library: `tallow.url` -- URL parsing/manipulation.

use super::StdlibResult;
use crate::interp::Value;

/// Dispatch a `tallow.url.*` function call.
///
/// Functions already implemented inline in interp.rs (parse, encode, decode)
/// return None to fall through.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        // Implemented inline in interp.rs — fall through
        "parse" | "encode" | "decode" => None,

        // Declared in stdlib/url.tl with an empty `// native:` body and previously
        // absent from every dispatcher. Implemented 2026-10-12.
        "encode_query" => Some(do_encode_query(args)),

        _ => None,
    }
}

/// Dispatch a method call on a `tallow.url` object (the `URL` struct).
///
/// This was `None` with all three parameters unused, so every method declared `// native:` in
/// `stdlib/url.tl` was unreachable: `u.query_params()` and `u.with_param(k, v)` died with
/// *unknown method*, and `u.to_string()` was answered by the interpreter's **generic** `to_string`
/// arm (`Value::String(object.display())`) — which SUCCEEDS and returns a debug rendering of the
/// struct rather than the URL. A wrong answer that looks like an answer is worse than a refusal,
/// which is why this arm now takes precedence.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    let fields = match object {
        Value::Struct { name, fields } if name == "URL" => fields,
        _ => return None,
    };
    match method {
        "to_string" => Some(Ok(Value::String(url_to_string(fields)))),
        "query_params" => Some(Ok(Value::Map(
            parse_query(&field_string(fields, "query"))
                .into_iter()
                .map(|(k, v)| (Value::String(k), Value::String(v)))
                .collect(),
        ))),
        // Methods declared in stdlib/url.tl as plain Tallow bodies. The
        // interpreter does not execute `.tl` method bodies for a native struct,
        // so each of these was unreachable: `u.domain()` died with
        // "unknown method: .domain() on URL" (measured 2026-10-22).
        "domain" => Some(Ok(Value::String(field_string(fields, "host")))),
        "is_secure" => Some(Ok(Value::Bool(field_string(fields, "scheme") == "https"))),
        "param" => {
            let key = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => return Some(Err("url.param: expected a String name".into())),
            };
            let value = parse_query(&field_string(fields, "query"))
                .into_iter()
                .find(|(k, _)| *k == key)
                .map(|(_, v)| Value::String(v))
                .unwrap_or(Value::Nil);
            Some(Ok(value))
        }
        "with_path" => {
            // Declared in stdlib/url.tl as `URL { ...self, path: path }`. The
            // struct-update form is not something the runtime executes for a
            // native struct, so the method was unreachable and every call died
            // with "unknown method: .with_path() on URL" (measured 2026-10-22).
            let path = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => return Some(Err("url.with_path: expected a String path".into())),
            };
            Some(Ok(rebuild(fields, Some(("path", Value::String(path))))))
        }
        "with_param" => {
            let key = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => return Some(Err("url.with_param: expected a String key".into())),
            };
            let value = match args.get(1) {
                Some(Value::String(s)) => s.clone(),
                _ => {
                    return Some(Err(
                        "url.with_param: expected a String value (use .to_string() on non-strings)".into(),
                    ))
                }
            };
            // Replace in place when the key exists, append otherwise — order is preserved so a
            // round-trip through with_param does not reshuffle a caller's query string.
            let mut pairs = parse_query(&field_string(fields, "query"));
            match pairs.iter_mut().find(|(k, _)| *k == key) {
                Some(slot) => slot.1 = value,
                None => pairs.push((key, value)),
            }
            let query = pairs
                .iter()
                .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
                .collect::<Vec<_>>()
                .join("&");
            Some(Ok(rebuild(fields, Some(("query", Value::String(query))))))
        }
        "join" => {
            let relative = match args.first() {
                Some(Value::String(s)) => s.clone(),
                _ => return Some(Err("url.join: expected a String argument".into())),
            };
            Some(Ok(Value::Ok(Box::new(parse_url_value(&resolve(fields, &relative))))))
        }
        _ => None,
    }
}

// ── Implementations ──────────────────────────────────────────────────────────

/// Parse a URL string into the `URL` struct the `.tl` declares.
///
/// Populates all eight declared fields. Before this, `url.parse` produced only
/// scheme/host/path/query/raw, so a port, fragment or userinfo was silently
/// **dropped** — `https://h:8443/a#f` came back indistinguishable from
/// `https://h/a`. The fields are read straight off the string here rather than
/// reconstructed from a lossy subset.
pub fn parse_url_value(raw: &str) -> Value {
    let mut rest = raw;
    let fragment = match rest.find('#') {
        Some(i) => {
            let f = rest[i + 1..].to_string();
            rest = &rest[..i];
            if f.is_empty() { Value::Nil } else { Value::String(f) }
        }
        None => Value::Nil,
    };
    let (scheme, mut rest) = match rest.find("://") {
        Some(i) => (rest[..i].to_string(), &rest[i + 3..]),
        None => ("https".to_string(), rest),
    };
    let query = match rest.find('?') {
        Some(i) => {
            let q = rest[i + 1..].to_string();
            rest = &rest[..i];
            q
        }
        None => String::new(),
    };
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], rest[i..].to_string()),
        None => (rest, "/".to_string()),
    };
    let (userinfo, hostport) = match authority.rfind('@') {
        Some(i) => (Some(&authority[..i]), &authority[i + 1..]),
        None => (None, authority),
    };
    let (username, password) = match userinfo {
        Some(u) => match u.find(':') {
            Some(i) => (
                Value::String(percent_decode(&u[..i])),
                Value::String(percent_decode(&u[i + 1..])),
            ),
            None => (Value::String(percent_decode(u)), Value::Nil),
        },
        None => (Value::Nil, Value::Nil),
    };
    let (host, port) = match hostport.rfind(':') {
        Some(i) if hostport[i + 1..].chars().all(|c| c.is_ascii_digit())
            && !hostport[i + 1..].is_empty() =>
        {
            match hostport[i + 1..].parse::<i128>() {
                Ok(p) => (hostport[..i].to_string(), Value::Int(p)),
                Err(_) => (hostport.to_string(), Value::Nil),
            }
        }
        _ => (hostport.to_string(), Value::Nil),
    };
    Value::Struct {
        name: "URL".to_string(),
        fields: vec![
            ("scheme".to_string(), Value::String(scheme)),
            ("host".to_string(), Value::String(host)),
            ("port".to_string(), port),
            ("path".to_string(), Value::String(path)),
            // Kept as an empty String rather than Nil for absent queries: the pre-existing
            // runtime representation, and what current `.query` readers expect.
            ("query".to_string(), Value::String(query)),
            ("fragment".to_string(), fragment),
            ("username".to_string(), username),
            ("password".to_string(), password),
            ("raw".to_string(), Value::String(raw.to_string())),
        ],
    }
}

fn field_string(fields: &[(String, Value)], key: &str) -> String {
    match fields.iter().find(|(n, _)| n == key).map(|(_, v)| v) {
        Some(Value::String(s)) => s.clone(),
        Some(Value::Int(n)) => n.to_string(),
        _ => String::new(),
    }
}

fn field_opt<'a>(fields: &'a [(String, Value)], key: &str) -> Option<&'a Value> {
    match fields.iter().find(|(n, _)| n == key).map(|(_, v)| v) {
        Some(Value::Nil) | None => None,
        Some(v) => Some(v),
    }
}

/// Rebuild the URL string from its components (not from `raw`, which is stale after any edit).
fn url_to_string(fields: &[(String, Value)]) -> String {
    let mut out = String::new();
    let scheme = field_string(fields, "scheme");
    if !scheme.is_empty() {
        out.push_str(&scheme);
        out.push_str("://");
    }
    match field_opt(fields, "username") {
        Some(Value::String(u)) => {
            out.push_str(u);
            if let Some(Value::String(p)) = field_opt(fields, "password") {
                out.push(':');
                out.push_str(p);
            }
            out.push('@');
        }
        _ => {}
    }
    out.push_str(&field_string(fields, "host"));
    if let Some(Value::Int(p)) = field_opt(fields, "port") {
        out.push(':');
        out.push_str(&p.to_string());
    }
    let path = field_string(fields, "path");
    out.push_str(if path.is_empty() { "/" } else { &path });
    let query = field_string(fields, "query");
    if !query.is_empty() {
        out.push('?');
        out.push_str(&query);
    }
    if let Some(Value::String(f)) = field_opt(fields, "fragment") {
        out.push('#');
        out.push_str(f);
    }
    out
}

/// Copy the struct, apply overrides, and refresh `raw` so it never contradicts the fields.
fn rebuild(fields: &[(String, Value)], change: Option<(&str, Value)>) -> Value {
    let mut out: Vec<(String, Value)> = fields
        .iter()
        .filter(|(n, _)| n != "raw")
        .cloned()
        .collect();
    if let Some((k, v)) = change {
        match out.iter_mut().find(|(n, _)| n == k) {
            Some(slot) => slot.1 = v,
            None => out.push((k.to_string(), v)),
        }
    }
    let raw = url_to_string(&out);
    out.push(("raw".to_string(), Value::String(raw)));
    Value::Struct { name: "URL".to_string(), fields: out }
}

/// Split a query string into decoded pairs. A segment with no `=` keeps an empty value rather
/// than being dropped, so `?flag` survives a round trip.
fn parse_query(query: &str) -> Vec<(String, String)> {
    query
        .split('&')
        .filter(|s| !s.is_empty())
        .map(|pair| match pair.split_once('=') {
            Some((k, v)) => (percent_decode(k), percent_decode(v)),
            None => (percent_decode(pair), String::new()),
        })
        .collect()
}

/// RFC 3986 reference resolution, restricted to the cases the `.tl` documents (absolute, root-
/// relative, and path-relative). Dot segments are resolved; the base's query/fragment are dropped.
fn resolve(fields: &[(String, Value)], relative: &str) -> String {
    if relative.contains("://") {
        return relative.to_string();
    }
    let base = url_to_string(fields);
    let base = base.split('#').next().unwrap_or("").to_string();
    let base = base.split('?').next().unwrap_or("").to_string();
    let origin = match base.find("://") {
        Some(i) => match base[i + 3..].find('/') {
            Some(j) => base[..i + 3 + j].to_string(),
            None => base.clone(),
        },
        None => String::new(),
    };
    let joined = if relative.starts_with('/') {
        format!("{origin}{relative}")
    } else {
        let dir = match base.rfind('/') {
            Some(i) if i >= origin.len() => &base[..=i],
            _ => &format!("{origin}/"),
        };
        format!("{dir}{relative}")
    };
    // Resolve `//` and `/./` and `/../` in the path only.
    let (head, tail) = match joined.find("://") {
        Some(i) => match joined[i + 3..].find('/') {
            Some(j) => joined.split_at(i + 3 + j),
            None => (joined.as_str(), ""),
        },
        None => (joined.as_str(), ""),
    };
    let mut stack: Vec<&str> = Vec::new();
    for seg in tail.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }
    let trailing = tail.ends_with('/') || tail.ends_with("/.") || tail.ends_with("/..");
    let mut path = String::from("/");
    path.push_str(&stack.join("/"));
    if trailing && !path.ends_with('/') {
        path.push('/');
    }
    format!("{head}{path}")
}

/// Percent-decode. Accumulates BYTES and decodes UTF-8 at the end: pushing `byte as char` (which
/// is what the inline `url.decode` arm does) reinterprets each byte as Latin-1 and turns any
/// multi-byte sequence into mojibake — `%C3%A9` becomes `Ã©` instead of `é`.
pub(crate) fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out: Vec<u8> = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            // `%XX` needs both hex digits to exist: i+1 and i+2 in range, i.e. i + 3 <= len.
            b'%' if i + 3 <= bytes.len() => match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(b) => {
                    out.push(b);
                    i += 3;
                }
                // A stray `%` is kept literally rather than dropping the following characters.
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// `url.encode_query(params: Map<String, String>) -> String`
///
/// Builds `"key=value&key2=value2"`, percent-encoding keys and values.
fn do_encode_query(args: Vec<Value>) -> StdlibResult {
    let pairs = match args.first() {
        Some(Value::Map(p)) => p,
        _ => return Err("url.encode_query: expected a Map<String, String> argument".into()),
    };
    let mut out: Vec<String> = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        let (key, val) = match (k, v) {
            (Value::String(a), Value::String(b)) => (a, b),
            _ => return Err("url.encode_query: keys and values must be strings".into()),
        };
        out.push(format!("{}={}", percent_encode(key), percent_encode(val)));
    }
    Ok(Value::String(out.join("&")))
}

/// Percent-encode per RFC 3986: unreserved = ALPHA / DIGIT / `-` `.` `_` `~`.
///
/// Space encodes as `%20`, **not** `+` — this is a query *component* encoder,
/// not an `application/x-www-form-urlencoded` one. Getting this wrong silently
/// corrupts values that contain `+`.
pub(crate) fn percent_encode(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: Vec<(&str, &str)>) -> Value {
        Value::Map(
            pairs
                .into_iter()
                .map(|(k, v)| (Value::String(k.into()), Value::String(v.into())))
                .collect(),
        )
    }

    #[test]
    fn percent_encode_leaves_unreserved_alone() {
        assert_eq!(percent_encode("aZ0-._~"), "aZ0-._~");
    }

    #[test]
    fn percent_encode_escapes_space_as_percent20_not_plus() {
        assert_eq!(percent_encode("a b"), "a%20b");
    }

    #[test]
    fn percent_encode_escapes_reserved_and_utf8() {
        assert_eq!(percent_encode("a&b=c"), "a%26b%3Dc");
        assert_eq!(percent_encode("é"), "%C3%A9");
    }

    #[test]
    fn encode_query_builds_pairs_in_order() {
        let r = do_encode_query(vec![map(vec![("q", "a b"), ("n", "1")])]).unwrap();
        match r {
            Value::String(s) => assert_eq!(s, "q=a%20b&n=1"),
            other => panic!("expected String, got {other:?}"),
        }
    }

    #[test]
    fn encode_query_rejects_non_map() {
        assert!(do_encode_query(vec![Value::String("x".into())]).is_err());
        assert!(do_encode_query(vec![]).is_err());
    }

    #[test]
    fn encode_query_rejects_non_string_values() {
        let bad = Value::Map(vec![(Value::String("k".into()), Value::Int(1))]);
        assert!(do_encode_query(vec![bad]).is_err());
    }

    // ---- URL struct methods (wired 2026-10-16; every one of these was an unwired `// native:`) ----

    fn url_for(s: &str) -> Value {
        parse_url_value(s)
    }

    fn method(obj: &Value, name: &str, args: Vec<Value>) -> String {
        match dispatch_method(obj, name, args).expect("method not answered") {
            Ok(v) => v.as_string(),
            Err(e) => panic!("{name} errored: {e}"),
        }
    }

    fn field(obj: &Value, k: &str) -> Value {
        match obj {
            Value::Struct { fields, .. } => fields
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.clone())
                .unwrap_or(Value::Nil),
            _ => Value::Nil,
        }
    }

    /// The regression that motivated the rewrite: a port and fragment were silently dropped by the
    /// old inline parser, so `https://h:8443/a#f` was indistinguishable from `https://h/a`.
    #[test]
    fn parse_keeps_port_fragment_and_userinfo() {
        let u = url_for("https://u:p@example.com:8443/a/b?x=1#frag");
        assert_eq!(field(&u, "scheme").as_string(), "https");
        assert_eq!(field(&u, "host").as_string(), "example.com");
        assert_eq!(field(&u, "port").as_string(), "8443");
        assert_eq!(field(&u, "path").as_string(), "/a/b");
        assert_eq!(field(&u, "fragment").as_string(), "frag");
        assert_eq!(field(&u, "username").as_string(), "u");
        assert_eq!(field(&u, "password").as_string(), "p");
    }

    #[test]
    fn to_string_round_trips_what_parse_read() {
        let src = "https://u:p@example.com:8443/a/b?x=1#frag";
        assert_eq!(method(&url_for(src), "to_string", vec![]), src);
    }

    #[test]
    fn to_string_of_a_plain_url_is_unchanged() {
        let src = "https://example.com/path?key=val";
        assert_eq!(method(&url_for(src), "to_string", vec![]), src);
    }

    #[test]
    fn query_params_decodes_pairs() {
        let u = url_for("https://h/p?a=1&b=x%20y&flag");
        let m = match dispatch_method(&u, "query_params", vec![]).unwrap().unwrap() {
            Value::Map(m) => m,
            other => panic!("expected Map, got {other:?}"),
        };
        let get = |k: &str| {
            m.iter()
                .find(|(kk, _)| kk.as_string() == k)
                .map(|(_, v)| v.as_string())
                .unwrap_or_default()
        };
        assert_eq!(get("a"), "1");
        assert_eq!(get("b"), "x y");
        // A valueless flag survives as an empty value rather than vanishing.
        assert_eq!(get("flag"), "");
    }

    #[test]
    fn with_param_appends_and_replaces_in_place() {
        let u = url_for("https://h/p?a=1&b=2");
        let v = dispatch_method(&u, "with_param", vec![Value::String("a".into()), Value::String("9".into())])
            .unwrap()
            .unwrap();
        // Replacement keeps position; the new value is there and the other pair is untouched.
        assert_eq!(method(&v, "to_string", vec![]), "https://h/p?a=9&b=2");

        let w = dispatch_method(&v, "with_param", vec![Value::String("c".into()), Value::String("3".into())])
            .unwrap()
            .unwrap();
        assert_eq!(method(&w, "to_string", vec![]), "https://h/p?a=9&b=2&c=3");
    }

    #[test]
    fn with_param_percent_encodes_the_value() {
        let v = dispatch_method(
            &url_for("https://h/p"),
            "with_param",
            vec![Value::String("q".into()), Value::String("a b&c".into())],
        )
        .unwrap()
        .unwrap();
        assert_eq!(method(&v, "to_string", vec![]), "https://h/p?q=a%20b%26c");
    }

    /// A URL that has been edited must not report a stale original string.
    #[test]
    fn with_param_refreshes_raw_so_it_cannot_contradict_the_fields() {
        let v = dispatch_method(
            &url_for("https://h/p?a=1"),
            "with_param",
            vec![Value::String("a".into()), Value::String("2".into())],
        )
        .unwrap()
        .unwrap();
        assert_eq!(field(&v, "raw").as_string(), "https://h/p?a=2");
    }

    #[test]
    fn join_resolves_relative_and_root_relative() {
        let base = url_for("https://example.com/a/b/c?q=1#f");
        let r = dispatch_method(&base, "join", vec![Value::String("d".into())]).unwrap().unwrap();
        let inner = match r {
            Value::Ok(v) => *v,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(method(&inner, "to_string", vec![]), "https://example.com/a/b/d");

        let r2 = dispatch_method(&base, "join", vec![Value::String("/x/y".into())]).unwrap().unwrap();
        let inner2 = match r2 {
            Value::Ok(v) => *v,
            other => panic!("expected Ok, got {other:?}"),
        };
        assert_eq!(method(&inner2, "to_string", vec![]), "https://example.com/x/y");
    }

    #[test]
    fn join_resolves_dot_segments_and_absolute_urls() {
        let base = url_for("https://example.com/a/b/c");
        for (rel, want) in [
            ("../d", "https://example.com/a/d"),
            ("./d", "https://example.com/a/b/d"),
            ("https://other.test/z", "https://other.test/z"),
        ] {
            let r = dispatch_method(&base, "join", vec![Value::String(rel.into())]).unwrap().unwrap();
            let inner = match r {
                Value::Ok(v) => *v,
                other => panic!("expected Ok, got {other:?}"),
            };
            assert_eq!(method(&inner, "to_string", vec![]), want, "joining {rel}");
        }
    }

    #[test]
    fn unknown_url_method_stays_none() {
        assert!(dispatch_method(&url_for("https://h/p"), "not_a_method", vec![]).is_none());
        // A non-URL struct must not be answered by this module.
        assert!(dispatch_method(&Value::String("x".into()), "to_string", vec![]).is_none());
    }

    // ---- percent_decode ----

    #[test]
    fn percent_decode_is_utf8_correct() {
        // The old inline decoder produced "Ã©" here.
        assert_eq!(percent_decode("%C3%A9"), "é");
        assert_eq!(percent_decode("a%20b"), "a b");
        assert_eq!(percent_decode("a+b"), "a b");
    }

    #[test]
    fn percent_decode_keeps_stray_and_truncated_percent() {
        assert_eq!(percent_decode("100%"), "100%");
        assert_eq!(percent_decode("%zz"), "%zz");
        assert_eq!(percent_decode("%2"), "%2");
        assert_eq!(percent_decode(""), "");
    }
}
