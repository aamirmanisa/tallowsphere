use std::path::PathBuf;
use std::time::Duration;

use tallow::browser::{BrowserBackend, BrowserConfig, BrowserProcess};
use tallow::interp::Value;
use tallow::stdlib;

fn struct_field<'a>(fields: &'a [(String, Value)], name: &str) -> &'a Value {
    fields
        .iter()
        .find(|(field_name, _)| field_name == name)
        .map(|(_, value)| value)
        .unwrap_or_else(|| panic!("missing field {name}"))
}

fn expect_string_field(fields: &[(String, Value)], name: &str) -> String {
    match struct_field(fields, name) {
        Value::String(value) => value.clone(),
        other => panic!("expected string field {name}, got {other:?}"),
    }
}

fn expect_bool_field(fields: &[(String, Value)], name: &str) -> bool {
    match struct_field(fields, name) {
        Value::Bool(value) => *value,
        other => panic!("expected bool field {name}, got {other:?}"),
    }
}

#[test]
fn stdlib_browser_facade_routes_contract_status() {
    let result = stdlib::dispatch("browser", "surface_manifest", vec![])
        .expect("browser surface_manifest should be routed")
        .expect("browser surface manifest should succeed");

    let Value::Struct { name, fields } = result else {
        panic!("expected BrowserSurfaceManifest struct, got {result:?}");
    };

    assert_eq!(name, "BrowserSurfaceManifest");
    assert_eq!(
        expect_string_field(&fields, "schema_version"),
        "tallow.browser_surface_manifest.v1"
    );
    assert_eq!(
        expect_string_field(&fields, "completion_boundary"),
        "local_non_live_fallback_planner_and_fail_closed_boundaries_only"
    );
    assert!(!expect_bool_field(&fields, "claims_live_browser_ready"));
    assert!(!expect_bool_field(
        &fields,
        "claims_production_fallback_ready"
    ));

    let entries = match struct_field(&fields, "entries") {
        Value::Array(entries) => entries,
        other => panic!("expected entries array, got {other:?}"),
    };

    let has_live_cdp_entry = entries.iter().any(|entry| match entry {
        Value::Struct { name, fields } if name == "BrowserSurfaceEntry" => {
            expect_string_field(fields, "name") == "Browser.launch"
                && expect_string_field(fields, "status") == "implemented_non_live_contract_tested"
                && expect_string_field(fields, "transport") == "cdp_websocket"
        }
        _ => false,
    });
    assert!(
        has_live_cdp_entry,
        "manifest should classify Browser.launch as WebSocket CDP implemented/non-live contract-tested"
    );

    let has_pipe_entry = entries.iter().any(|entry| match entry {
        Value::Struct { name, fields } if name == "BrowserSurfaceEntry" => {
            expect_string_field(fields, "name") == "cdp.pipe"
                && expect_string_field(fields, "status") == "unsupported_fail_closed"
                && expect_string_field(fields, "transport") == "cdp_pipe"
        }
        _ => false,
    });
    assert!(
        has_pipe_entry,
        "manifest should classify CDP pipe as fail-closed unsupported"
    );
}

#[test]
fn stdlib_browser_facade_reports_pipe_fail_closed() {
    let result = stdlib::dispatch("browser", "pipe_transport_status", vec![])
        .expect("browser pipe_transport_status should be routed")
        .expect("browser pipe status should succeed");

    let Value::Struct { name, fields } = result else {
        panic!("expected BrowserPipeTransportStatus struct, got {result:?}");
    };

    assert_eq!(name, "BrowserPipeTransportStatus");
    assert_eq!(expect_string_field(&fields, "transport"), "cdp_pipe");
    assert_eq!(
        expect_string_field(&fields, "status"),
        "unsupported_fail_closed"
    );
    assert!(expect_bool_field(&fields, "rejects_before_launch"));
    assert!(!expect_bool_field(&fields, "opens_debug_port"));
    assert!(!expect_bool_field(&fields, "launches_browser"));
}

#[test]
fn stdlib_browser_facade_reports_phase4_fallback_service_status() {
    let result = stdlib::dispatch("browser", "fallback_service_status", vec![])
        .expect("browser fallback_service_status should be routed")
        .expect("browser fallback service status should succeed");

    let Value::Struct { name, fields } = result else {
        panic!("expected BrowserFallbackServiceStatus struct, got {result:?}");
    };

    assert_eq!(name, "BrowserFallbackServiceStatus");
    assert_eq!(
        expect_string_field(&fields, "schema_version"),
        "tallow.browser_fallback_service_status.v1"
    );
    assert_eq!(
        expect_string_field(&fields, "status"),
        "implemented_local_non_live_planner_tested"
    );
    assert!(expect_bool_field(&fields, "reason_codes_supported"));
    assert!(expect_bool_field(&fields, "budgets_supported"));
    assert!(expect_bool_field(
        &fields,
        "artifact_policy_hooks_supported"
    ));
    assert!(!expect_bool_field(&fields, "launches_browser"));
    assert!(!expect_bool_field(&fields, "performs_network_io"));
    assert!(!expect_bool_field(&fields, "captures_screenshots_har_dom"));
    assert_eq!(
        expect_string_field(&fields, "pipe_status"),
        "unsupported_fail_closed"
    );
}

#[test]
fn browser_process_rejects_pipe_before_spawning_chrome() {
    let config = BrowserConfig {
        chrome_path: PathBuf::from("/definitely/not/a/browser/binary"),
        headless: true,
        port: Some(0),
        args: vec![],
        user_data_dir: None,
        timeout: Duration::from_millis(1),
        stealth: false,
        proxy: None,
        use_pipe: true,
        backend: BrowserBackend::Chromium,
        proxy_pac: None,
    };

    let message = match BrowserProcess::launch(&config) {
        Ok(_) => panic!("pipe mode should fail closed"),
        Err(err) => err.to_string(),
    };
    assert!(
        message.contains("remote-debugging-pipe") && message.contains("not supported"),
        "unexpected pipe rejection message: {message}"
    );
    assert!(
        !message.contains("failed to launch browser at /definitely/not/a/browser/binary"),
        "pipe rejection should happen before attempting to spawn chrome: {message}"
    );
}

#[test]
fn stdlib_browser_tl_declares_phase3_contract_facade() {
    let browser_tl = std::fs::read_to_string("stdlib/browser.tl").expect("read stdlib/browser.tl");
    for declaration in [
        "fn browser_surface_manifest",
        "fn browser_pipe_transport_status",
        "fn browser_fallback_boundary",
        "fn browser_fallback_service_status",
    ] {
        assert!(
            browser_tl.contains(declaration),
            "stdlib/browser.tl should declare {declaration}"
        );
    }
}
