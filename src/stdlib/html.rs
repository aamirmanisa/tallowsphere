//! Standard library: `tallow.html` -- HTML parsing with CSS selectors.

use super::StdlibResult;
use crate::interp::Value;

/// Dispatch a `tallow.html.*` function call.
pub fn dispatch(function: &str, args: Vec<Value>) -> Option<StdlibResult> {
    match function {
        "parse" => Some(html_parse(args)),
        "parse_bytes" => Some(html_parse_bytes(args)),
        _ => None,
    }
}

/// Dispatch a method call on HtmlDocument or HtmlElement.
pub fn dispatch_method(object: &Value, method: &str, args: Vec<Value>) -> Option<StdlibResult> {
    if let Value::Struct { name, fields } = object {
        match name.as_str() {
            "HtmlDocument" => {
                let raw = fields
                    .iter()
                    .find(|(k, _)| k == "_raw")
                    .and_then(|(_, v)| match v {
                        Value::String(s) => Some(s.clone()),
                        _ => None,
                    });
                match method {
                    "select" => {
                        if let Some(html_str) = raw {
                            return Some(html_select(&html_str, args));
                        }
                        return Some(Err("HtmlDocument._raw is missing".into()));
                    }
                    "select_one" => {
                        if let Some(html_str) = raw {
                            return Some(html_select_one(&html_str, args));
                        }
                        return Some(Err("HtmlDocument._raw is missing".into()));
                    }
                    "title" => {
                        if let Some(html_str) = raw {
                            return Some(html_title(&html_str));
                        }
                        return Some(Err("HtmlDocument._raw is missing".into()));
                    }
                    "links" => {
                        if let Some(html_str) = raw {
                            return Some(html_links(&html_str));
                        }
                        return Some(Err("HtmlDocument._raw is missing".into()));
                    }
                    "text" => {
                        if let Some(html_str) = raw {
                            return Some(html_text_all(&html_str));
                        }
                        return Some(Err("HtmlDocument._raw is missing".into()));
                    }
                    _ => {
                        // Field accessor fallback
                        for (field_name, field_value) in fields {
                            if field_name == method {
                                return Some(Ok(field_value.clone()));
                            }
                        }
                        return Some(Err(format!("HtmlDocument has no method '{method}'")));
                    }
                }
            }
            "HtmlElement" => {
                let raw = fields
                    .iter()
                    .find(|(k, _)| k == "_raw")
                    .and_then(|(_, v)| match v {
                        Value::String(s) => Some(s.clone()),
                        _ => None,
                    });
                match method {
                    "text" => {
                        if let Some(el_html) = raw {
                            return Some(element_text(&el_html));
                        }
                        // Fallback: return stored text field
                        if let Some((_, v)) = fields.iter().find(|(k, _)| k == "text") {
                            return Some(Ok(v.clone()));
                        }
                        return Some(Ok(Value::String(String::new())));
                    }
                    "attr" => {
                        if let Some(el_html) = raw {
                            return Some(element_attr(&el_html, args));
                        }
                        return Some(Err("HtmlElement._raw is missing".into()));
                    }
                    "attrs" => {
                        if let Some(el_html) = raw {
                            return Some(element_attrs(&el_html));
                        }
                        if let Some((_, v)) = fields.iter().find(|(k, _)| k == "attrs") {
                            return Some(Ok(v.clone()));
                        }
                        return Some(Ok(Value::Map(vec![])));
                    }
                    "select" => {
                        if let Some(el_html) = raw {
                            return Some(element_select(&el_html, args));
                        }
                        return Some(Err("HtmlElement._raw is missing".into()));
                    }
                    "children" => {
                        if let Some(el_html) = raw {
                            return Some(element_children(&el_html));
                        }
                        return Some(Err("HtmlElement._raw is missing".into()));
                    }
                    "parent" => {
                        if let Some((_, Value::String(parent_raw))) =
                            fields.iter().find(|(k, _)| k == "_parent_raw")
                        {
                            if parent_raw.is_empty() {
                                return Some(Ok(Value::Nil));
                            }
                            return Some(element_from_raw(parent_raw, None));
                        }
                        return Some(Ok(Value::Nil));
                    }
                    "html" | "inner_html" => {
                        if let Some(el_html) = raw {
                            return Some(element_inner_html(&el_html));
                        }
                        return Some(Err("HtmlElement._raw is missing".into()));
                    }
                    "outer_html" => {
                        if let Some(el_html) = raw {
                            return Some(Ok(Value::String(el_html)));
                        }
                        return Some(Err("HtmlElement._raw is missing".into()));
                    }
                    "has_attr" => {
                        if let Some(el_html) = raw {
                            return Some(element_has_attr(&el_html, args));
                        }
                        return Some(Err("HtmlElement._raw is missing".into()));
                    }
                    "id" => {
                        if let Some(el_html) = raw {
                            return Some(element_attr(
                                &el_html,
                                vec![Value::String("id".to_string())],
                            ));
                        }
                        return Some(Err("HtmlElement._raw is missing".into()));
                    }
                    "tag" => {
                        if let Some((_, v)) = fields.iter().find(|(k, _)| k == "tag") {
                            return Some(Ok(v.clone()));
                        }
                        return Some(Ok(Value::String(String::new())));
                    }
                    "classes" => {
                        if let Some(el_html) = raw {
                            return Some(element_classes(&el_html));
                        }
                        return Some(Ok(Value::Array(vec![])));
                    }
                    _ => {
                        // Field accessor fallback
                        for (field_name, field_value) in fields {
                            if field_name == method {
                                return Some(Ok(field_value.clone()));
                            }
                        }
                        return Some(Err(format!("HtmlElement has no method '{method}'")));
                    }
                }
            }
            _ => {}
        }
    }
    None
}

// ── Implementations ──────────────────────────────────────────────────────────

fn html_document_value(html_str: String) -> Value {
    Value::Struct {
        name: "HtmlDocument".to_string(),
        fields: vec![("_raw".to_string(), Value::String(html_str))],
    }
}

fn element_attr_map(el: scraper::ElementRef<'_>) -> Value {
    Value::Map(
        el.value()
            .attrs()
            .map(|(key, value)| {
                (
                    Value::String(key.to_string()),
                    Value::String(value.to_string()),
                )
            })
            .collect(),
    )
}

fn parent_html(el: scraper::ElementRef<'_>) -> Option<String> {
    el.parent()
        .and_then(scraper::ElementRef::wrap)
        .filter(|parent| !matches!(parent.value().name(), "html" | "head" | "body"))
        .map(|parent| parent.html())
}

fn html_element_value(el: scraper::ElementRef<'_>, parent_raw: Option<String>) -> Value {
    let tag = el.value().name().to_string();
    let text: String = el.text().collect::<Vec<_>>().join("");
    let raw_html = el.html();
    let attrs = element_attr_map(el);

    let mut fields = vec![
        ("tag".to_string(), Value::String(tag)),
        ("attrs".to_string(), attrs),
        ("text".to_string(), Value::String(text)),
        ("_raw".to_string(), Value::String(raw_html)),
    ];
    if let Some(parent_raw) = parent_raw {
        fields.push(("_parent_raw".to_string(), Value::String(parent_raw)));
    }

    Value::Struct {
        name: "HtmlElement".to_string(),
        fields,
    }
}

fn first_content_element(fragment: &scraper::Html) -> Option<scraper::ElementRef<'_>> {
    let selector = scraper::Selector::parse("*").unwrap();
    fragment
        .select(&selector)
        .find(|el| !matches!(el.value().name(), "html" | "head" | "body"))
}

fn element_from_raw(el_html: &str, parent_raw: Option<String>) -> StdlibResult {
    let fragment = scraper::Html::parse_fragment(el_html);
    if let Some(el) = first_content_element(&fragment) {
        Ok(html_element_value(el, parent_raw))
    } else {
        Ok(Value::Nil)
    }
}

fn html_parse(args: Vec<Value>) -> StdlibResult {
    let html_str = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("html.parse: expected string HTML argument".into()),
    };

    Ok(html_document_value(html_str))
}

fn html_parse_bytes(args: Vec<Value>) -> StdlibResult {
    let bytes = match args.first() {
        Some(Value::Bytes(bytes)) => bytes,
        _ => return Err("html.parse_bytes: expected Bytes HTML argument".into()),
    };

    Ok(html_document_value(
        String::from_utf8_lossy(bytes).to_string(),
    ))
}

fn html_select(html_str: &str, args: Vec<Value>) -> StdlibResult {
    let selector_str = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("HtmlDocument.select: expected CSS selector string argument".into()),
    };

    let document = scraper::Html::parse_document(html_str);
    let selector = scraper::Selector::parse(&selector_str)
        .map_err(|_| format!("HtmlDocument.select: invalid CSS selector '{selector_str}'"))?;

    let elements: Vec<Value> = document
        .select(&selector)
        .map(|el| html_element_value(el, parent_html(el)))
        .collect();

    Ok(Value::Array(elements))
}

fn html_select_one(html_str: &str, args: Vec<Value>) -> StdlibResult {
    match html_select(html_str, args)? {
        Value::Array(mut elements) => {
            if elements.is_empty() {
                Ok(Value::Nil)
            } else {
                Ok(elements.remove(0))
            }
        }
        _ => Ok(Value::Nil),
    }
}

fn html_title(html_str: &str) -> StdlibResult {
    let document = scraper::Html::parse_document(html_str);
    let selector = scraper::Selector::parse("title").unwrap();
    if let Some(el) = document.select(&selector).next() {
        Ok(Value::String(el.text().collect::<Vec<_>>().join("")))
    } else {
        Ok(Value::Nil)
    }
}

fn html_links(html_str: &str) -> StdlibResult {
    let document = scraper::Html::parse_document(html_str);
    let selector = scraper::Selector::parse("a[href]").unwrap();
    let links = document
        .select(&selector)
        .filter_map(|el| el.value().attr("href"))
        .map(|href| Value::String(href.to_string()))
        .collect();
    Ok(Value::Array(links))
}

fn html_text_all(html_str: &str) -> StdlibResult {
    let document = scraper::Html::parse_document(html_str);
    let text: String = document.root_element().text().collect::<Vec<_>>().join("");
    Ok(Value::String(text))
}

fn element_text(el_html: &str) -> StdlibResult {
    let fragment = scraper::Html::parse_fragment(el_html);
    let text: String = fragment.root_element().text().collect::<Vec<_>>().join("");
    Ok(Value::String(text))
}

fn element_select(el_html: &str, args: Vec<Value>) -> StdlibResult {
    let selector_str = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("HtmlElement.select: expected CSS selector string argument".into()),
    };

    let fragment = scraper::Html::parse_fragment(el_html);
    let root = first_content_element(&fragment)
        .ok_or_else(|| "HtmlElement.select: could not locate element root".to_string())?;
    let selector = scraper::Selector::parse(&selector_str)
        .map_err(|_| format!("HtmlElement.select: invalid CSS selector '{selector_str}'"))?;

    Ok(Value::Array(
        root.select(&selector)
            .map(|el| html_element_value(el, parent_html(el)))
            .collect(),
    ))
}

fn element_children(el_html: &str) -> StdlibResult {
    let fragment = scraper::Html::parse_fragment(el_html);
    let root = first_content_element(&fragment)
        .ok_or_else(|| "HtmlElement.children: could not locate element root".to_string())?;
    let parent_raw = root.html();

    Ok(Value::Array(
        root.child_elements()
            .map(|child| html_element_value(child, Some(parent_raw.clone())))
            .collect(),
    ))
}

fn element_attrs(el_html: &str) -> StdlibResult {
    let fragment = scraper::Html::parse_fragment(el_html);
    if let Some(el) = first_content_element(&fragment) {
        Ok(element_attr_map(el))
    } else {
        Ok(Value::Map(vec![]))
    }
}

fn element_attr(el_html: &str, args: Vec<Value>) -> StdlibResult {
    let attr_name = match args.first() {
        Some(Value::String(s)) => s.clone(),
        _ => return Err("HtmlElement.attr: expected attribute name string argument".into()),
    };

    let fragment = scraper::Html::parse_fragment(el_html);
    if let Some(el) = first_content_element(&fragment) {
        if let Some(val) = el.value().attr(&attr_name) {
            Ok(Value::String(val.to_string()))
        } else {
            Ok(Value::Nil)
        }
    } else {
        Ok(Value::Nil)
    }
}

fn element_has_attr(el_html: &str, args: Vec<Value>) -> StdlibResult {
    match element_attr(el_html, args)? {
        Value::Nil => Ok(Value::Bool(false)),
        _ => Ok(Value::Bool(true)),
    }
}

fn element_inner_html(el_html: &str) -> StdlibResult {
    let fragment = scraper::Html::parse_fragment(el_html);
    let selector = scraper::Selector::parse("*").unwrap();
    for el in fragment.select(&selector) {
        if matches!(el.value().name(), "html" | "head" | "body") {
            continue;
        }
        return Ok(Value::String(el.inner_html()));
    }
    Ok(Value::String(String::new()))
}

fn element_classes(el_html: &str) -> StdlibResult {
    let fragment = scraper::Html::parse_fragment(el_html);
    let selector = scraper::Selector::parse("*").unwrap();
    for el in fragment.select(&selector) {
        if matches!(el.value().name(), "html" | "head" | "body") {
            continue;
        }
        let classes: Vec<Value> = el
            .value()
            .classes()
            .map(|c| Value::String(c.to_string()))
            .collect();
        if !classes.is_empty() {
            return Ok(Value::Array(classes));
        }
        return Ok(Value::Array(vec![]));
    }
    Ok(Value::Array(vec![]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_html_parse() {
        let result = html_parse(vec![Value::String(
            "<html><body><p>hello</p></body></html>".into(),
        )]);
        assert!(result.is_ok());
        match result.unwrap() {
            Value::Struct { name, fields } => {
                assert_eq!(name, "HtmlDocument");
                assert!(fields.iter().any(|(k, _)| k == "_raw"));
            }
            _ => panic!("expected Struct"),
        }
    }

    #[test]
    fn test_html_select_by_class() {
        let html = r#"<html><body>
            <div class="price">$10.99</div>
            <div class="price">$20.50</div>
            <div class="other">ignore</div>
        </body></html>"#;

        let result = html_select(html, vec![Value::String(".price".into())]);
        assert!(result.is_ok());
        match result.unwrap() {
            Value::Array(elements) => {
                assert_eq!(elements.len(), 2, "should find 2 .price elements");
            }
            _ => panic!("expected Array"),
        }
    }

    #[test]
    fn test_html_element_text() {
        let html = r#"<html><body><p id="target">Hello World</p></body></html>"#;
        let elements = match html_select(html, vec![Value::String("p".into())]).unwrap() {
            Value::Array(arr) => arr,
            _ => panic!("expected Array"),
        };
        assert!(!elements.is_empty());

        // Call .text() method on the element
        let el = &elements[0];
        let text = dispatch_method(el, "text", vec![]).unwrap().unwrap();
        match text {
            Value::String(s) => assert_eq!(s, "Hello World"),
            _ => panic!("expected String"),
        }
    }

    #[test]
    fn test_html_element_attr() {
        let html =
            r#"<html><body><a href="https://example.com" class="link">Click</a></body></html>"#;
        let elements = match html_select(html, vec![Value::String("a".into())]).unwrap() {
            Value::Array(arr) => arr,
            _ => panic!("expected Array"),
        };
        assert!(!elements.is_empty());

        let el = &elements[0];
        let href = dispatch_method(el, "attr", vec![Value::String("href".into())])
            .unwrap()
            .unwrap();
        match href {
            Value::String(s) => assert_eq!(s, "https://example.com"),
            _ => panic!("expected String"),
        }
    }

    #[test]
    fn test_html_element_html() {
        let html = r#"<html><body><div id="container"><span>inner</span></div></body></html>"#;
        let elements = match html_select(html, vec![Value::String("#container".into())]).unwrap() {
            Value::Array(arr) => arr,
            _ => panic!("expected Array"),
        };
        assert!(!elements.is_empty());

        let el = &elements[0];
        let inner = dispatch_method(el, "html", vec![]).unwrap().unwrap();
        match inner {
            Value::String(s) => assert!(s.contains("<span>inner</span>"), "inner html: {s}"),
            _ => panic!("expected String"),
        }
    }

    #[test]
    fn test_html_declared_document_helpers() {
        let doc = html_parse(vec![Value::String(
            r#"<html><head><title>Shop</title></head><body><a href="/p1">One</a><a href="/p2">Two</a><p class="price">$10</p></body></html>"#.into(),
        )])
        .unwrap();

        let first_price = dispatch_method(&doc, "select_one", vec![Value::String(".price".into())])
            .unwrap()
            .unwrap();
        match first_price {
            Value::Struct { name, .. } => assert_eq!(name, "HtmlElement"),
            other => panic!("expected HtmlElement from select_one, got {other:?}"),
        }

        let title = dispatch_method(&doc, "title", vec![]).unwrap().unwrap();
        assert!(matches!(title, Value::String(ref s) if s == "Shop"));

        let links = dispatch_method(&doc, "links", vec![]).unwrap().unwrap();
        match links {
            Value::Array(items) => {
                assert_eq!(items.len(), 2);
                assert!(matches!(&items[0], Value::String(s) if s == "/p1"));
                assert!(matches!(&items[1], Value::String(s) if s == "/p2"));
            }
            other => panic!("expected links array, got {other:?}"),
        }
    }

    #[test]
    fn test_html_declared_element_helpers() {
        let html = r#"<html><body><div id="sku-1" class="card featured"><span>inner</span></div></body></html>"#;
        let elements = match html_select(html, vec![Value::String("div.card".into())]).unwrap() {
            Value::Array(arr) => arr,
            _ => panic!("expected Array"),
        };
        let el = &elements[0];

        let inner = dispatch_method(el, "inner_html", vec![]).unwrap().unwrap();
        match inner {
            Value::String(s) => {
                assert_eq!(s, "<span>inner</span>");
                assert!(
                    !s.contains("<div"),
                    "inner_html must not include the selected element"
                );
            }
            other => panic!("expected String from inner_html, got {other:?}"),
        }

        let outer = dispatch_method(el, "outer_html", vec![]).unwrap().unwrap();
        assert!(
            matches!(outer, Value::String(ref s) if s.contains("id=\"sku-1\"") && s.contains("<span>inner</span>"))
        );

        let has_id = dispatch_method(el, "has_attr", vec![Value::String("id".into())])
            .unwrap()
            .unwrap();
        assert!(matches!(has_id, Value::Bool(true)));

        let id = dispatch_method(el, "id", vec![]).unwrap().unwrap();
        assert!(matches!(id, Value::String(ref s) if s == "sku-1"));
    }

    #[test]
    fn test_html_element_helpers_do_not_read_descendant_attrs() {
        let html = r#"<html><body><div class="parent"><span id="child" class="child">inner</span></div></body></html>"#;
        let elements = match html_select(html, vec![Value::String("div.parent".into())]).unwrap() {
            Value::Array(arr) => arr,
            _ => panic!("expected Array"),
        };
        let el = &elements[0];

        let attr_id = dispatch_method(el, "attr", vec![Value::String("id".into())])
            .unwrap()
            .unwrap();
        assert!(matches!(attr_id, Value::Nil));

        let has_id = dispatch_method(el, "has_attr", vec![Value::String("id".into())])
            .unwrap()
            .unwrap();
        assert!(matches!(has_id, Value::Bool(false)));

        let id = dispatch_method(el, "id", vec![]).unwrap().unwrap();
        assert!(matches!(id, Value::Nil));

        let classes = dispatch_method(el, "classes", vec![]).unwrap().unwrap();
        match classes {
            Value::Array(items) => {
                assert_eq!(items.len(), 1);
                assert!(matches!(&items[0], Value::String(s) if s == "parent"));
            }
            other => panic!("expected classes array, got {other:?}"),
        }
    }

    #[test]
    fn test_html_b2_declared_parse_bytes_and_element_navigation_helpers() {
        let doc = dispatch(
            "parse_bytes",
            vec![Value::Bytes(
                br#"<section id="parent" data-kind="card"><a href="/one">One</a><span class="price">$5</span></section>"#.to_vec(),
            )],
        )
        .expect("parse_bytes should dispatch")
        .expect("parse_bytes should parse UTF-8 bytes");

        let section = dispatch_method(&doc, "select_one", vec![Value::String("section".into())])
            .unwrap()
            .unwrap();

        let attrs = dispatch_method(&section, "attrs", vec![]).unwrap().unwrap();
        match attrs {
            Value::Map(items) => {
                assert!(items.iter().any(|(k, v)| matches!((k, v), (Value::String(key), Value::String(value)) if key == "id" && value == "parent")));
                assert!(items.iter().any(|(k, v)| matches!((k, v), (Value::String(key), Value::String(value)) if key == "data-kind" && value == "card")));
            }
            other => panic!("expected attrs map, got {other:?}"),
        }

        let children = dispatch_method(&section, "children", vec![])
            .unwrap()
            .unwrap();
        match children {
            Value::Array(items) => {
                assert_eq!(
                    items.len(),
                    2,
                    "children should include only direct element children"
                );
                assert!(
                    matches!(&items[0], Value::Struct { fields, .. } if fields.iter().any(|(k, v)| k == "tag" && matches!(v, Value::String(tag) if tag == "a")))
                );
                assert!(
                    matches!(&items[1], Value::Struct { fields, .. } if fields.iter().any(|(k, v)| k == "tag" && matches!(v, Value::String(tag) if tag == "span")))
                );
            }
            other => panic!("expected children array, got {other:?}"),
        }

        let prices = dispatch_method(&section, "select", vec![Value::String(".price".into())])
            .unwrap()
            .unwrap();
        let price = match prices {
            Value::Array(items) => {
                assert_eq!(items.len(), 1);
                items.into_iter().next().unwrap()
            }
            other => panic!("expected select array, got {other:?}"),
        };

        let parent = dispatch_method(&price, "parent", vec![]).unwrap().unwrap();
        assert!(
            matches!(parent, Value::Struct { ref fields, .. } if fields.iter().any(|(k, v)| k == "tag" && matches!(v, Value::String(tag) if tag == "section")))
        );
    }

    #[test]
    fn test_html_select_empty() {
        let html = "<html><body><p>hello</p></body></html>";
        let result = html_select(html, vec![Value::String(".nonexistent".into())]);
        assert!(result.is_ok());
        match result.unwrap() {
            Value::Array(arr) => assert!(arr.is_empty(), "should return empty array"),
            _ => panic!("expected Array"),
        }
    }

    #[test]
    fn test_html_element_tag() {
        let html = r#"<html><body><h1>Title</h1></body></html>"#;
        let elements = match html_select(html, vec![Value::String("h1".into())]).unwrap() {
            Value::Array(arr) => arr,
            _ => panic!("expected Array"),
        };
        assert!(!elements.is_empty());

        let el = &elements[0];
        let tag = dispatch_method(el, "tag", vec![]).unwrap().unwrap();
        match tag {
            Value::String(s) => assert_eq!(s, "h1"),
            _ => panic!("expected String"),
        }
    }
}
