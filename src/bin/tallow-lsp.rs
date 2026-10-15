//! Tallow Language Server binary entry point.
//!
//! Starts the LSP server over stdio (JSON-RPC).
//! Editors connect via stdin/stdout automatically.

#[tokio::main]
async fn main() {
    tallow::lsp::run_lsp_server().await;
}
