//! Integration test: Tallow **consumes** a real third-party MCP server (sheet item U-G03).
//!
//! The gate is *"consumes a third-party MCP server in an integration test"*, so the server under
//! test must be one this repo did not write. The default is the `caveman` MCP server installed on
//! this box (`/root/.caveman/bin/caveman-mcp`, a Go binary, third-party); any other stdio MCP
//! server can be substituted via `TALLOW_MCP_TEST_SERVER`.
//!
//! Gated by `#[ignore]` with the requirement named rather than skipping when the server is absent
//! — a test that quietly returns early is a test that passes for the wrong reason. Run it with:
//!
//! ```sh
//! cargo test --test mcp_client -- --ignored --nocapture
//!
//! # or against the canonical reference server instead:
//! TALLOW_MCP_TEST_SERVER='npx -y @modelcontextprotocol/server-filesystem /tmp' \
//! TALLOW_MCP_TEST_TOOL=list_directory \
//! TALLOW_MCP_TEST_ARGS='{"path":"/tmp"}' \
//!   cargo test --test mcp_client -- --ignored --nocapture
//! ```
//!
//! Three assertions, and the third is the one that matters: calling a **nonexistent** tool must
//! come back as `Err`. Without it, a client that returned an empty `String` for every call would
//! pass assertions 1 and 2 while being useless — the failure mode this whole exercise is about.

use tallow::mcp::McpClient;

const REQUIREMENT: &str = "needs a third-party MCP server on stdio: set TALLOW_MCP_TEST_SERVER, \
                           or install one at /root/.caveman/bin/caveman-mcp";

fn server_spec() -> (String, Vec<String>) {
    let spec = std::env::var("TALLOW_MCP_TEST_SERVER")
        .unwrap_or_else(|_| "/root/.caveman/bin/caveman-mcp".to_string());
    let mut parts = spec.split_whitespace().map(str::to_string);
    let program = parts
        .next()
        .unwrap_or_else(|| panic!("TALLOW_MCP_TEST_SERVER is empty"));
    (program, parts.collect())
}

fn tool_name() -> String {
    std::env::var("TALLOW_MCP_TEST_TOOL").unwrap_or_else(|_| "caveman_compress".to_string())
}

fn tool_args() -> serde_json::Value {
    match std::env::var("TALLOW_MCP_TEST_ARGS") {
        Ok(raw) => serde_json::from_str(&raw)
            .unwrap_or_else(|e| panic!("TALLOW_MCP_TEST_ARGS is not valid JSON: {e}")),
        // Default matches the default tool `caveman_compress`, which takes an `input` string.
        Err(_) => serde_json::json!({"input": "the quick brown fox jumps over the lazy dog. ".repeat(20)}),
    }
}

fn connect() -> McpClient {
    let (program, args) = server_spec();
    println!("connecting to MCP server: {program} {}", args.join(" "));
    McpClient::connect(&program, &args).unwrap_or_else(|e| panic!("{REQUIREMENT}\n  -> {e}"))
}

/// The handshake must yield a real server identity — proof we are talking to a server, not a pipe.
#[test]
#[ignore = "U-G03: needs a third-party MCP server on stdio: set TALLOW_MCP_TEST_SERVER, or install one at /root/.caveman/bin/caveman-mcp"]
fn handshake_identifies_a_third_party_server() {
    let client = connect();
    println!(
        "server={} version={} protocol={}",
        client.server_name(),
        client.server_version(),
        client.protocol_version()
    );
    assert!(
        !client.server_name().is_empty() && client.server_name() != "unknown",
        "serverInfo.name was missing from the initialize result"
    );
    assert!(
        client.protocol_version() != "unknown",
        "the server did not report a protocolVersion"
    );
}

/// `tools/list` must return at least one real, named tool.
#[test]
#[ignore = "U-G03: needs a third-party MCP server on stdio: set TALLOW_MCP_TEST_SERVER, or install one at /root/.caveman/bin/caveman-mcp"]
fn lists_tools_with_names() {
    let mut client = connect();
    let tools = client.list_tools().expect("tools/list failed");
    println!("{} tool(s) advertised:", tools.len());
    for t in &tools {
        println!("  {} - {}", t.name, t.description.lines().next().unwrap_or(""));
    }
    assert!(!tools.is_empty(), "server advertised no tools");
    assert!(
        tools.iter().all(|t| !t.name.is_empty()),
        "a tool was advertised without a name"
    );
}

/// Call a real tool, then a nonexistent one. The second assertion is the point: a client that
/// cannot tell a failed tool from an empty success will be believed when it is wrong.
#[test]
#[ignore = "U-G03: needs a third-party MCP server on stdio: set TALLOW_MCP_TEST_SERVER, or install one at /root/.caveman/bin/caveman-mcp"]
fn calls_a_tool_and_rejects_an_unknown_one() {
    let mut client = connect();
    let name = tool_name();
    let args = tool_args();
    let out = client
        .call_tool(&name, args.clone())
        .unwrap_or_else(|e| panic!("tools/call '{name}' failed: {e}"));
    println!("{name} -> {} bytes", out.len());
    println!("{}", out.chars().take(300).collect::<String>());
    assert!(
        !out.trim().is_empty(),
        "tools/call '{name}' returned empty content, so this test would pass on a broken client"
    );

    // Negative control: an unknown tool must be an error, not an empty string.
    let err = client.call_tool("definitely-not-a-real-tool-xyz", serde_json::json!({}));
    assert!(
        err.is_err(),
        "calling a nonexistent tool returned Ok({:?}) — the client cannot distinguish failure",
        err.ok()
    );
}
