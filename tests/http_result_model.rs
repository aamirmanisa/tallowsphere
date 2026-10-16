use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::thread;

use tallow::interp::Value;
use tallow::stdlib;

fn field<'a>(value: &'a Value, field_name: &str) -> &'a Value {
    let Value::Struct { fields, .. } = value else {
        panic!("expected struct for field {field_name}, got {value:?}");
    };
    fields
        .iter()
        .find(|(name, _)| name == field_name)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("missing field {field_name} in {value:?}"))
}

fn struct_name(value: &Value) -> &str {
    let Value::Struct { name, .. } = value else {
        panic!("expected struct, got {value:?}");
    };
    name
}

fn value_string(value: &Value) -> &str {
    let Value::String(value) = value else {
        panic!("expected string, got {value:?}");
    };
    value
}

fn value_int(value: &Value) -> i128 {
    let Value::Int(value) = value else {
        panic!("expected int, got {value:?}");
    };
    *value
}

fn value_bool(value: &Value) -> bool {
    let Value::Bool(value) = value else {
        panic!("expected bool, got {value:?}");
    };
    *value
}

fn response_status(response: &Value) -> i128 {
    value_int(field(response, "status"))
}

fn response_body_text(response: &Value) -> String {
    let Value::Bytes(bytes) = field(response, "body") else {
        panic!(
            "expected response body bytes, got {:?}",
            field(response, "body")
        );
    };
    String::from_utf8_lossy(bytes).to_string()
}

fn spawn_loopback_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind loopback test server");
    let addr = listener.local_addr().expect("server local addr");
    thread::spawn(move || {
        for _ in 0..2 {
            let (stream, _) = listener.accept().expect("accept loopback request");
            handle_request(stream);
        }
    });
    format!("http://{addr}")
}

fn handle_request(mut stream: TcpStream) {
    let mut buffer = [0_u8; 1024];
    let read = stream.read(&mut buffer).expect("read request");
    let request = String::from_utf8_lossy(&buffer[..read]);
    let (status, body) = if request.starts_with("GET /ok ") {
        ("200 OK", "ok-body")
    } else {
        ("404 Not Found", "missing-body")
    };
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream
        .write_all(response.as_bytes())
        .expect("write response");
}

fn dispatch_batch(urls: Vec<String>) -> Vec<Value> {
    let value = stdlib::dispatch(
        "http",
        "batch",
        vec![
            Value::Array(urls.into_iter().map(Value::String).collect()),
            Value::Int(2),
            Value::Map(vec![]),
            Value::Int(250),
        ],
    )
    .expect("http.batch should route")
    .expect("http.batch should not fail the whole batch");
    let Value::Array(items) = value else {
        panic!("http.batch should return array, got {value:?}");
    };
    items
}

#[test]
fn http_batch_returns_typed_success_and_http_error_results() {
    let base = spawn_loopback_server();
    let urls = vec![format!("{base}/ok"), format!("{base}/missing")];

    let results = dispatch_batch(urls.clone());

    assert_eq!(results.len(), 2);
    let ok = &results[0];
    assert_eq!(struct_name(ok), "BatchResponse");
    assert_eq!(value_string(field(ok, "url")), urls[0]);
    assert!(value_bool(field(ok, "ok")));
    assert_eq!(value_int(field(ok, "attempts")), 1);
    assert!(value_int(field(ok, "elapsed_ms")) >= 0);
    assert!(matches!(field(ok, "error"), Value::Nil));
    let response = field(ok, "response");
    assert_eq!(struct_name(response), "Response");
    assert_eq!(response_status(response), 200);
    assert_eq!(response_body_text(response), "ok-body");

    let missing = &results[1];
    assert_eq!(struct_name(missing), "BatchResponse");
    assert_eq!(value_string(field(missing, "url")), urls[1]);
    assert!(!value_bool(field(missing, "ok")));
    assert_eq!(value_int(field(missing, "attempts")), 1);
    let response = field(missing, "response");
    assert_eq!(struct_name(response), "Response");
    assert_eq!(response_status(response), 404);
    assert_eq!(response_body_text(response), "missing-body");
    let error = field(missing, "error");
    assert_eq!(struct_name(error), "HttpError");
    assert_eq!(value_string(field(error, "kind")), "http_4xx");
    assert_eq!(value_string(field(error, "url")), urls[1]);
    assert_eq!(value_int(field(error, "status")), 404);
    assert!(!value_bool(field(error, "retryable")));
}

#[test]
fn http_batch_returns_typed_transport_error_without_panicking() {
    let closed_listener = TcpListener::bind("127.0.0.1:0").expect("bind closed port");
    let closed_addr = closed_listener.local_addr().expect("closed addr");
    drop(closed_listener);

    let results = dispatch_batch(vec![format!("http://{closed_addr}/refused")]);

    assert_eq!(results.len(), 1);
    let item = &results[0];
    assert_eq!(struct_name(item), "BatchResponse");
    assert!(!value_bool(field(item, "ok")));
    assert!(matches!(field(item, "response"), Value::Nil));
    let error = field(item, "error");
    assert_eq!(struct_name(error), "HttpError");
    assert_eq!(value_string(field(error, "kind")), "transport");
    assert!(matches!(field(error, "status"), Value::Nil));
    assert!(value_string(field(error, "message")).contains("http.get"));
}

#[test]
fn http_tl_declares_typed_batch_result_model() {
    let http_tl = include_str!("../stdlib/http.tl");

    assert!(http_tl.contains("struct HttpError"));
    assert!(http_tl.contains("struct BatchResponse"));
    assert!(http_tl.contains("response: Response?"));
    assert!(http_tl.contains("error: HttpError?"));
    assert!(http_tl.contains("fn batch(target_urls: []String, concurrency: i64, headers: Map<String, String>) -> []BatchResponse"));
}
