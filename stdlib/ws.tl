// tallow.ws — WebSocket client for real-time data feeds.
//
// Connects to ws:// and wss:// servers and receives streaming text frames.
// wss:// performs a real TLS handshake (rustls + the webpki root store) before
// the HTTP upgrade, so the handshake itself is encrypted too.

struct WebSocket {
    url: String,
}

// Connect to a WebSocket server. Both ws:// and wss:// are supported; wss://
// defaults to port 443 and validates the server certificate.
fn WS.connect(url: String) -> WebSocket

// Receive next message with timeout (ms). Returns nil on timeout.
fn WebSocket.recv(self, timeout_ms: Int?) -> String?

// Receive all available messages up to a limit. Blocks up to 5s.
fn WebSocket.recv_all(self, limit: Int?) -> []String

// Send a text message
fn WebSocket.send(self, text: String)

// Close the connection
fn WebSocket.close(self)
