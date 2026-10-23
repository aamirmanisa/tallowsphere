use std::time::Duration;

use futures_util::{SinkExt, StreamExt};
use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::{accept_async, tungstenite::Message};

use tallow::browser::{BrowserConfig, BrowserError, BrowserProcess, CdpClient, WaitUntil};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MockScenario {
    HappyFlow,
    TimeoutOnEvaluate,
    WrappedSessionTransport,
    MissingNavigateResponse,
}

async fn send_mock_payload(
    ws: &mut tokio_tungstenite::WebSocketStream<tokio::net::TcpStream>,
    scenario: MockScenario,
    payload: Value,
    session_id: Option<&str>,
) {
    let outgoing = if scenario == MockScenario::WrappedSessionTransport {
        if let Some(session_id) = session_id {
            json!({
                "method": "Target.receivedMessageFromTarget",
                "params": {
                    "sessionId": session_id,
                    "targetId": "target-1",
                    "message": payload.to_string()
                }
            })
        } else {
            payload
        }
    } else {
        payload
    };

    ws.send(Message::Text(outgoing.to_string().into()))
        .await
        .expect("send mock payload");
}

async fn start_mock_cdp_server(
    scenario: MockScenario,
) -> (
    String,
    tokio::task::JoinHandle<()>,
    Option<oneshot::Receiver<String>>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock cdp listener");
    let addr = listener.local_addr().expect("mock cdp local addr");
    let ws_url = format!("ws://{}/devtools/browser/mock", addr);

    let (navigate_url_tx, navigate_url_rx) = oneshot::channel::<String>();
    let track_nav_url = matches!(
        scenario,
        MockScenario::HappyFlow
            | MockScenario::WrappedSessionTransport
            | MockScenario::MissingNavigateResponse
    );

    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept mock cdp connection");
        let mut ws = accept_async(stream).await.expect("upgrade websocket");
        let mut navigate_url_tx = Some(navigate_url_tx);
        // The URL the mock was last told to navigate to. The client's completion
        // guard asks the *document* where it is (`location.href`) and whether it
        // is a new document (`performance.timeOrigin`); a mock that answers ""
        // makes every navigation time out with "waiting for DOMContentLoaded"
        // even though the lifecycle event arrived.
        let mut last_nav_url = String::from("https://example.test/mock");

        while let Some(msg_result) = ws.next().await {
            let msg = match msg_result {
                Ok(msg) => msg,
                Err(_) => break,
            };

            let text = match msg {
                Message::Text(text) => text.to_string(),
                Message::Binary(bytes) => match String::from_utf8(bytes.to_vec()) {
                    Ok(text) => text,
                    Err(_) => continue,
                },
                Message::Close(_) => break,
                _ => continue,
            };

            let command: Value = match serde_json::from_str(&text) {
                Ok(value) => value,
                Err(_) => continue,
            };

            let id = match command.get("id").and_then(|value| value.as_u64()) {
                Some(id) => id,
                None => continue,
            };

            let method = command
                .get("method")
                .and_then(|value| value.as_str())
                .unwrap_or_default();

            match method {
                "Target.createTarget" => {
                    let response = json!({
                        "id": id,
                        "result": {"targetId": "target-1"}
                    });
                    send_mock_payload(&mut ws, scenario, response, None).await;
                }
                "Target.attachToTarget" => {
                    let response = json!({
                        "id": id,
                        "result": {"sessionId": "session-1"}
                    });
                    send_mock_payload(&mut ws, scenario, response, None).await;
                }
                "Page.enable" | "Page.setLifecycleEventsEnabled" | "Network.enable" => {
                    let session_id = command.get("sessionId").and_then(|value| value.as_str());
                    let response = json!({"id": id, "result": {}});
                    send_mock_payload(&mut ws, scenario, response, session_id).await;
                }
                "Page.navigate" => {
                    let navigate_url = command
                        .get("params")
                        .and_then(|params| params.get("url"))
                        .and_then(|url| url.as_str())
                        .unwrap_or_default()
                        .to_string();
                    if let Some(tx) = navigate_url_tx.take() {
                        let _ = tx.send(navigate_url.clone());
                    }
                    last_nav_url = navigate_url.clone();

                    let session_id = command
                        .get("sessionId")
                        .and_then(|value| value.as_str())
                        .unwrap_or("session-1");

                    let frame_id = if scenario == MockScenario::MissingNavigateResponse {
                        "frame-fallback"
                    } else {
                        "frame-1"
                    };

                    if scenario != MockScenario::MissingNavigateResponse {
                        let response = json!({
                            "id": id,
                            "result": {"frameId": frame_id}
                        });
                        send_mock_payload(&mut ws, scenario, response, Some(session_id)).await;
                    }

                    let frame_started_navigating = json!({
                        "method": "Page.frameStartedNavigating",
                        "params": {
                            "frameId": frame_id
                        },
                        "sessionId": session_id
                    });
                    send_mock_payload(
                        &mut ws,
                        scenario,
                        frame_started_navigating,
                        Some(session_id),
                    )
                    .await;

                    let request_will_be_sent = json!({
                        "method": "Network.requestWillBeSent",
                        "params": {
                            "frameId": frame_id,
                            "type": "Document"
                        },
                        "sessionId": session_id
                    });
                    send_mock_payload(&mut ws, scenario, request_will_be_sent, Some(session_id))
                        .await;

                    let network_event = json!({
                        "method": "Network.responseReceived",
                        "params": {
                            "frameId": frame_id,
                            "type": "Document",
                            "response": {"status": if scenario == MockScenario::MissingNavigateResponse { 204 } else { 200 }}
                        },
                        "sessionId": session_id
                    });
                    send_mock_payload(&mut ws, scenario, network_event, Some(session_id)).await;

                    let lifecycle_event = json!({
                        "method": "Page.lifecycleEvent",
                        "params": {
                            "name": "DOMContentLoaded",
                            "frameId": frame_id
                        },
                        "sessionId": session_id
                    });
                    send_mock_payload(&mut ws, scenario, lifecycle_event, Some(session_id)).await;
                }
                "Runtime.evaluate" => {
                    if scenario == MockScenario::TimeoutOnEvaluate {
                        // Intentionally leave this command unanswered to exercise timeout diagnostics.
                        continue;
                    }

                    let expression = command
                        .get("params")
                        .and_then(|params| params.get("expression"))
                        .and_then(|expression| expression.as_str())
                        .unwrap_or_default();

                    let value = match expression {
                        "document.title" => "Mocked Title",
                        "window.location.href" => last_nav_url.as_str(),
                        _ => "",
                    };

                    // The engine verifies completion against the document, not
                    // only against the lifecycle event: it reads
                    // `performance.timeOrigin` before navigating and again when
                    // the event lands, so a stale event from the document being
                    // left cannot be mistaken for the new one. A mock that
                    // answers "" to those probes can never satisfy the guard.
                    let (value_type, value_json) = if expression.starts_with("JSON.stringify(") {
                        (
                            "string",
                            json!(format!(
                                "{{\"u\":\"{}\",\"s\":\"complete\",\"o\":2000.0,\"e\":false}}",
                                last_nav_url
                            )),
                        )
                    } else if expression.contains("performance.timeOrigin") {
                        ("number", json!(1000.0))
                    } else {
                        ("string", json!(value))
                    };

                    let response = json!({
                        "id": id,
                        "result": {
                            "result": {
                                "type": value_type,
                                "value": value_json
                            }
                        }
                    });
                    let session_id = command.get("sessionId").and_then(|value| value.as_str());
                    send_mock_payload(&mut ws, scenario, response, session_id).await;
                }
                _ => {
                    let response = json!({"id": id, "result": {}});
                    let session_id = command.get("sessionId").and_then(|value| value.as_str());
                    send_mock_payload(&mut ws, scenario, response, session_id).await;
                }
            }
        }
    });

    (
        ws_url,
        task,
        if track_nav_url {
            Some(navigate_url_rx)
        } else {
            None
        },
    )
}

#[tokio::test]
async fn cdp_new_page_navigate_title_flow_tracks_goto_path() {
    let (ws_url, server_task, navigate_url_rx) =
        start_mock_cdp_server(MockScenario::HappyFlow).await;

    let client = CdpClient::connect(&ws_url)
        .await
        .expect("connect to mock cdp server");

    let page = client
        .create_page(Some("about:blank"))
        .await
        .expect("create page");

    let target_url = "https://example.test/path/to/resource?x=1&y=2#frag";
    let nav = page
        .navigate(target_url, WaitUntil::DomContentLoaded)
        .await
        .expect("navigate via goto path");

    assert_eq!(
        nav.url, target_url,
        "navigate result should preserve input URL"
    );
    assert_eq!(nav.frame_id, "frame-1");
    assert_eq!(nav.status_code, Some(200));

    let observed_nav_url = navigate_url_rx
        .expect("navigate_url receiver available")
        .await
        .expect("mock server should capture Page.navigate url");
    assert_eq!(
        observed_nav_url, target_url,
        "Page.navigate command should use exact goto URL"
    );

    let title = page.title().await.expect("read page title");
    assert_eq!(title, "Mocked Title");

    drop(client);
    server_task.abort();
}

#[tokio::test]
async fn cdp_timeout_diagnostics_include_method_session_and_id() {
    let (ws_url, server_task, _) = start_mock_cdp_server(MockScenario::TimeoutOnEvaluate).await;

    let mut client = CdpClient::connect(&ws_url)
        .await
        .expect("connect to mock cdp server");
    client.timeout = Duration::from_millis(80);

    let err = client
        .send_command_with_session(
            "Runtime.evaluate",
            Some(json!({"expression": "document.title"})),
            "session-timeout",
        )
        .await
        .expect_err("Runtime.evaluate should time out without a response");

    match err {
        BrowserError::Timeout { operation, detail } => {
            assert_eq!(operation, "send_command");
            assert!(
                detail.contains("method=Runtime.evaluate"),
                "missing method in timeout detail: {detail}"
            );
            assert!(
                detail.contains("session=session-timeout"),
                "missing session in timeout detail: {detail}"
            );
            assert!(
                detail.contains("id="),
                "missing command id in timeout detail: {detail}"
            );
            let id_part = detail
                .split_whitespace()
                .find_map(|part| part.strip_prefix("id="))
                .expect("timeout detail should include id=...");
            let parsed_id = id_part
                .parse::<u64>()
                .expect("timeout detail id should be a valid u64");
            assert!(parsed_id > 0, "timeout detail id should be > 0");
        }
        other => panic!("expected timeout error, got {other:?}"),
    }

    drop(client);
    server_task.abort();
}

#[tokio::test]
async fn cdp_wrapped_target_message_flow_handles_nested_responses() {
    let (ws_url, server_task, navigate_url_rx) =
        start_mock_cdp_server(MockScenario::WrappedSessionTransport).await;

    let client = CdpClient::connect(&ws_url)
        .await
        .expect("connect to wrapped mock cdp server");

    let page = client
        .create_page(Some("about:blank"))
        .await
        .expect("create page");

    let target_url = "https://example.test/wrapped/flow";
    let nav = page
        .navigate(target_url, WaitUntil::DomContentLoaded)
        .await
        .expect("navigate using wrapped target transport flow");
    assert_eq!(nav.url, target_url);
    assert_eq!(nav.frame_id, "frame-1");
    assert_eq!(nav.status_code, Some(200));

    let observed_nav_url = navigate_url_rx
        .expect("navigate_url receiver available")
        .await
        .expect("mock server should capture wrapped Page.navigate url");
    assert_eq!(observed_nav_url, target_url);

    let title = page.title().await.expect("read page title");
    assert_eq!(title, "Mocked Title");

    drop(client);
    server_task.abort();
}

#[tokio::test]
async fn cdp_navigate_without_response_uses_event_fallback() {
    let (ws_url, server_task, navigate_url_rx) =
        start_mock_cdp_server(MockScenario::MissingNavigateResponse).await;

    let mut client = CdpClient::connect(&ws_url)
        .await
        .expect("connect to fallback mock cdp server");
    client.timeout = Duration::from_millis(80);

    let page = client
        .create_page(Some("about:blank"))
        .await
        .expect("create page");

    let target_url = "https://example.test/fallback/no-navigate-response";
    let nav = page
        .navigate(target_url, WaitUntil::DomContentLoaded)
        .await
        .expect("navigate should succeed even without Page.navigate response");

    assert_eq!(nav.url, target_url);
    assert_eq!(
        nav.frame_id, "frame-fallback",
        "frame should come from observed navigation events when navigate response is missing"
    );
    assert_eq!(
        nav.status_code,
        Some(204),
        "status code should be inferred from Network.responseReceived"
    );

    let observed_nav_url = navigate_url_rx
        .expect("navigate_url receiver available")
        .await
        .expect("mock server should capture Page.navigate url");
    assert_eq!(observed_nav_url, target_url);

    let title = page.title().await.expect("read page title after fallback");
    assert_eq!(title, "Mocked Title");

    drop(client);
    server_task.abort();
}

fn live_browser_tests_enabled() -> bool {
    match std::env::var("TALLOW_RUN_BROWSER_LIVE_TESTS") {
        Ok(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            normalized == "1" || normalized == "true" || normalized == "yes"
        }
        Err(_) => false,
    }
}

#[tokio::test]
async fn live_browser_launch_new_page_goto_title_data_url() {
    if !live_browser_tests_enabled() {
        eprintln!("skipping live browser test; set TALLOW_RUN_BROWSER_LIVE_TESTS=1 to enable");
        return;
    }

    let mut config = BrowserConfig::default();
    config.headless = true;
    config.timeout = Duration::from_secs(30);

    let mut process = BrowserProcess::launch(&config).expect("launch browser process");
    let ws_url = process.ws_url.clone();

    let client = CdpClient::connect(&ws_url)
        .await
        .expect("connect to launched browser");

    let page = client
        .create_page(Some("about:blank"))
        .await
        .expect("create real browser page");

    let data_url =
        "data:text/html,%3Ctitle%3ETallow%20Live%20Title%3C%2Ftitle%3E%3Ch1%3Eok%3C%2Fh1%3E";
    let nav = page
        .navigate(data_url, WaitUntil::DomContentLoaded)
        .await
        .expect("navigate to data url");
    assert_eq!(nav.url, data_url);

    let title = page
        .title()
        .await
        .expect("read page title from real browser");
    assert_eq!(title, "Tallow Live Title");

    process.kill();
}
