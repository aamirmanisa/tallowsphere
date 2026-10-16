// tallow.url — URL parsing/manipulation

/// Parsed URL
struct URL {
    scheme:   String,       // "https"
    host:     String,       // "example.com"
    port:     u16?,         // 443
    path:     String,       // "/api/v1/data"
    query:    String?,      // "page=1&limit=10"
    fragment: String?,      // "section-2"
    username: String?,
    password: String?,
}

/// Parse URL string
fn parse(raw: String) -> Result<URL> {
    // native: parses URL
}

impl URL {
    /// Reconstruct URL string
    fn to_string(self) -> String {
        // native: builds URL from components
    }

    /// Get query parameters as map
    fn query_params(self) -> Map<String, String> {
        // native: parses query string
    }

    /// Get specific query parameter
    fn param(self, name: String) -> String? {
        self.query_params()[name]
    }

    /// Build new URL with modified path
    fn with_path(self, path: String) -> URL {
        URL { ...self, path: path }
    }

    /// Build new URL with added query parameter
    fn with_param(self, key: String, value: String) -> URL {
        // native: adds or replaces query parameter
    }

    /// Get domain (host without port)
    fn domain(self) -> String {
        self.host
    }

    /// Check if URL uses HTTPS
    fn is_secure(self) -> bool {
        self.scheme == "https"
    }

    /// Join with relative path
    fn join(self, relative: String) -> Result<URL> {
        // native: resolves relative URL
    }
}

/// URL-encode a string
fn encode(s: String) -> String {
    // native: percent-encodes string
}

/// URL-decode a string
fn decode(s: String) -> Result<String> {
    // native: decodes percent-encoded string
}

/// Build query string from map
fn encode_query(params: Map<String, String>) -> String {
    // native: builds "key=value&key2=value2"
}
