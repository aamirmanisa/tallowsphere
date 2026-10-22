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
// native: parses URL
native fn parse(raw: String) -> Result<URL>

impl URL {
    /// Reconstruct URL string
    // native: builds URL from components
    native fn to_string(self) -> String

    /// Get query parameters as map
    // native: parses query string
    native fn query_params(self) -> Map<String, String>

    /// Get specific query parameter
    fn param(self, name: String) -> String? {
        self.query_params()[name]
    }

    /// Build new URL with modified path
    fn with_path(self, path: String) -> URL {
        URL { ...self, path: path }
    }

    /// Build new URL with added query parameter
    // native: adds or replaces query parameter
    native fn with_param(self, key: String, value: String) -> URL

    /// Get domain (host without port)
    fn domain(self) -> String {
        self.host
    }

    /// Check if URL uses HTTPS
    fn is_secure(self) -> bool {
        self.scheme == "https"
    }

    /// Join with relative path
    // native: resolves relative URL
    native fn join(self, relative: String) -> Result<URL>
}

/// URL-encode a string
// native: percent-encodes string
native fn encode(s: String) -> String

/// URL-decode a string
// native: decodes percent-encoded string
native fn decode(s: String) -> Result<String>

/// Build query string from map
// native: builds "key=value&key2=value2"
native fn encode_query(params: Map<String, String>) -> String
