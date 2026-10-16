// tallow.http — HTTP client/server
// This is a stub — will be implemented as a native module in the compiler runtime.

/// Fetch many URLs in one call. Returns [Response] (per-URL Err entries on failure).
native fn batch(urls: [String], concurrency: Int) -> [Response]

struct Response {
    status:  u16,
    body:    Bytes,
    headers: Map<String, String>,
    url:     String,
    time_ms: u64,
}

impl Response {
    fn text(self) -> String {
        self.body.decode()
    }

    fn json(self) -> Result<String> {
        Ok(self.text())
    }
}

struct Client {
    timeout:          Duration,
    user_agent:       String,
    follow_redirects: bool,
}

impl Client {
    fn get(self, url: String) -> Result<Response> {
        fetch(url)
    }

    fn post(self, url: String, body: String) -> Result<Response> {
        fetch(url, method: .POST, body: body)
    }
}

struct Server {
    port: u16,
}

impl Server {
    fn listen(self) {
        print("server listening on port {self.port}")
    }
}
