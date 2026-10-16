//! Minimal MCP (Model Context Protocol) **client** over stdio.
//!
//! Sheet item U-G03: export-only means Tallow is a tool and never the orchestrator. This is the
//! client side — Tallow consuming someone else's MCP server — so that the engine can use the
//! growing third-party tool ecosystem instead of only being usable from it.
//!
//! ## Wire format (verified against two real servers, 2026-10-16)
//!
//! Newline-delimited JSON-RPC 2.0 over the child's stdin/stdout — **not** the LSP-style
//! `Content-Length` framing, which is the trap here: both framings are "JSON-RPC over stdio" and
//! the wrong one fails as a parse error on the first byte rather than as a protocol error. Probed
//! against `@modelcontextprotocol/server-filesystem` (npx) and a local Go server; both answered a
//! single-line `initialize` with a single-line result.
//!
//! Sequence: `initialize` request -> `notifications/initialized` -> any method (`tools/list`,
//! `tools/call`, ...). The server answers by `id`; it may also emit notifications (no `id`) and may
//! log freely to stderr, so responses are correlated by id and non-matching lines are skipped.
//!
//! ## Timeouts
//!
//! A blocking read on a wedged server hangs the caller forever, so stdout is drained by a reader
//! thread into a channel and every response wait is a `recv_timeout`. A timeout is reported as a
//! timeout — never as an empty result.

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::time::Duration;

use serde_json::{json, Value};

/// Default per-request wait. Generous: an MCP tool call can legitimately do real work.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// A tool advertised by the server's `tools/list`.
#[derive(Debug, Clone)]
pub struct Tool {
    pub name: String,
    pub description: String,
}

/// A connected MCP server.
pub struct McpClient {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    next_id: u64,
    timeout: Duration,
    server_name: String,
    server_version: String,
    protocol_version: String,
}

impl McpClient {
    /// Spawn `program args...` and complete the MCP handshake.
    ///
    /// The child's stderr is inherited rather than swallowed: a server that refuses to start
    /// explains itself there, and a silent failure to handshake is the least debuggable outcome.
    pub fn connect(program: &str, args: &[String]) -> Result<Self, String> {
        let mut child = Command::new(program)
            .args(args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("cannot start MCP server '{program}': {e}"))?;

        let stdin = child.stdin.take().ok_or("MCP server has no stdin")?;
        let stdout = child.stdout.take().ok_or("MCP server has no stdout")?;

        // Drain stdout on its own thread so no request can block forever.
        let (tx, lines) = mpsc::channel::<String>();
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(l) => {
                        if tx.send(l).is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let mut client = Self {
            child,
            stdin,
            lines,
            next_id: 0,
            timeout: DEFAULT_TIMEOUT,
            server_name: String::new(),
            server_version: String::new(),
            protocol_version: String::new(),
        };
        client.handshake()?;
        Ok(client)
    }

    /// Override the per-request timeout.
    pub fn with_timeout(mut self, t: Duration) -> Self {
        self.timeout = t;
        self
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn server_version(&self) -> &str {
        &self.server_version
    }

    pub fn protocol_version(&self) -> &str {
        &self.protocol_version
    }

    /// `initialize`, then the `notifications/initialized` the spec requires before other methods.
    fn handshake(&mut self) -> Result<(), String> {
        let params = json!({
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "tallow", "version": env!("CARGO_PKG_VERSION")},
        });
        let result = self.request("initialize", params)?;
        self.protocol_version = result
            .get("protocolVersion")
            .and_then(Value::as_str)
            .unwrap_or("unknown")
            .to_string();
        if let Some(info) = result.get("serverInfo") {
            self.server_name = info
                .get("name")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            self.server_version = info
                .get("version")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
        }
        // A notification: no id, no response expected.
        self.notify("notifications/initialized", json!({}))
    }

    fn send(&mut self, msg: &Value) -> Result<(), String> {
        let line = serde_json::to_string(msg).map_err(|e| e.to_string())?;
        self.stdin
            .write_all(line.as_bytes())
            .and_then(|_| self.stdin.write_all(b"\n"))
            .and_then(|_| self.stdin.flush())
            .map_err(|e| format!("MCP write failed: {e}"))
    }

    fn notify(&mut self, method: &str, params: Value) -> Result<(), String> {
        self.send(&json!({"jsonrpc": "2.0", "method": method, "params": params}))
    }

    /// Send a request and wait for the response carrying its id.
    fn request(&mut self, method: &str, params: Value) -> Result<Value, String> {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params}))?;

        loop {
            let line = match self.lines.recv_timeout(self.timeout) {
                Ok(l) => l,
                Err(RecvTimeoutError::Timeout) => {
                    return Err(format!(
                        "MCP server '{}' did not answer '{method}' within {:?}",
                        self.server_name_or_program(),
                        self.timeout
                    ))
                }
                Err(RecvTimeoutError::Disconnected) => {
                    return Err(format!(
                        "MCP server '{}' closed its output during '{method}'",
                        self.server_name_or_program()
                    ))
                }
            };
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let msg: Value = match serde_json::from_str(line) {
                Ok(v) => v,
                // Servers do print non-protocol noise; skip it rather than abort the session.
                Err(_) => continue,
            };
            // Notifications and other ids belong to someone else's conversation.
            if msg.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(err) = msg.get("error") {
                return Err(format!("MCP error for '{method}': {err}"));
            }
            return msg
                .get("result")
                .cloned()
                .ok_or_else(|| format!("MCP response for '{method}' carried neither result nor error"));
        }
    }

    fn server_name_or_program(&self) -> String {
        if self.server_name.is_empty() {
            "unknown".to_string()
        } else {
            self.server_name.clone()
        }
    }

    /// `tools/list` — the server's advertised tools.
    pub fn list_tools(&mut self) -> Result<Vec<Tool>, String> {
        let result = self.request("tools/list", json!({}))?;
        let arr = result
            .get("tools")
            .and_then(Value::as_array)
            .ok_or("tools/list result had no 'tools' array")?;
        Ok(arr
            .iter()
            .filter_map(|t| {
                let name = t.get("name").and_then(Value::as_str)?.to_string();
                let description = t
                    .get("description")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();
                Some(Tool { name, description })
            })
            .collect())
    }

    /// `tools/call` — invoke a tool and return its concatenated text content.
    ///
    /// A tool that reports `isError: true` is returned as `Err`, because a caller that cannot tell
    /// a failed tool from a successful one will happily act on the failure's prose.
    pub fn call_tool(&mut self, name: &str, arguments: Value) -> Result<String, String> {
        let result = self.request("tools/call", json!({"name": name, "arguments": arguments}))?;
        let text = result
            .get("content")
            .and_then(Value::as_array)
            .map(|blocks| {
                blocks
                    .iter()
                    .filter_map(|b| b.get("text").and_then(Value::as_str))
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();
        if result.get("isError").and_then(Value::as_bool) == Some(true) {
            return Err(format!("tool '{name}' reported an error: {text}"));
        }
        Ok(text)
    }
}

impl Drop for McpClient {
    fn drop(&mut self) {
        // Closing stdin is the polite shutdown; a server that ignores it does not get to outlive
        // the process that spawned it.
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
