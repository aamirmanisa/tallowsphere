// tallow.http — HTTP client/server
//
// NOT a stub. This header used to read "This is a stub — will be implemented as a native module in
// the compiler runtime", which was false: `src/stdlib/http.rs` implements get/post/put/delete/batch/
// listen/server, the compiled plane lowers `http.batch` through `tallow_http_batch`
// (src/codegen.rs), and `Client`/`Server` constructors are handled inline in the interpreter. A
// module header that calls working code a stub is a false claim, not a coming-soon note.

/// Fetch many URLs in one call — one typed entry per URL. A 4xx/5xx is a *result* carrying its body
/// plus an `HttpError`, never a failed whole batch; a transport failure carries `HttpError` with
/// `kind: "transport"` and no response.
/// http.batch(target_urls, concurrency, headers) -> []BatchResponse
native fn batch(target_urls: []String, concurrency: i64, headers: Map<String, String>) -> []BatchResponse

struct Response {
    status:  u16,
    body:    Bytes,
    headers: Map<String, String>,
    url:     String,
    time_ms: u64,
}

/// A per-URL failure, typed: `kind` is `http_4xx`, `http_5xx` or `transport`; `status` is present only
/// for an HTTP status, and `retryable` says whether a retry could plausibly help.
struct HttpError {
    kind:      String,
    url:       String,
    status:    Int?,
    retryable: Bool,
    message:   String,
}

/// One entry of an `http.batch` result. Exactly one of `response`/`error` is meaningful: a success
/// carries the response, a 4xx/5xx carries both (so the body stays readable), a transport failure
/// carries only the error.
struct BatchResponse {
    url:        String,
    ok:         Bool,
    attempts:   Int,
    elapsed_ms: Int,
    response: Response?,
    error: HttpError?,
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
