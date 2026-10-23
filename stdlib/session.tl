// tallow.session — browser session persistence.
//
// Save and restore authenticated browser sessions (cookies, localStorage,
// sessionStorage). Convert sessions to CookieJar for HTTP injection, or
// generate JavaScript to inject state into live pages.

struct Session {
    domain: String,
    url: String,
    cookies: []SessionCookie,
    local_storage: Map<String, String>,
    session_storage: Map<String, String>,
    user_agent: String,
    captured_at: Int,
}

struct SessionCookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: Bool,
    http_only: Bool,
    same_site: String,
    expires: Int?,
}

// Capture a browser session with cookies and storage state
native fn Session.capture(domain: String, url: String, cookies: []SessionCookie?,
                    local_storage: Map<String, String>?,
                    session_storage: Map<String, String>?) -> Session

// Load a previously saved session from disk
native fn Session.load(path: String) -> Session

// Save this session to disk as JSON
native fn Session.save(self, path: String)

// Get all cookies in the session
native fn Session.cookies(self) -> []SessionCookie

// Get all localStorage entries
native fn Session.local_storage(self) -> Map<String, String>

// Convert to a CookieJar for use with tallow.cookie_jar
native fn Session.to_cookie_jar(self) -> CookieJar

// Generate a Cookie header string for HTTP requests
native fn Session.cookie_header(self) -> String

// Generate JavaScript to inject this session into a live browser page
native fn Session.inject_js(self) -> String
