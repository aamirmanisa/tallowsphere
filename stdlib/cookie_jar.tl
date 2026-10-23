// tallow.cookie_jar — HTTP cookie storage and browser cookie extraction
//
// CookieJar stores cookies from HTTP responses, browser profiles,
// or manual insertion, and can generate Cookie headers for HTTP requests.

struct Cookie {
    name: String,
    value: String,
    domain: String,
    path: String,
    secure: Bool,
    http_only: Bool,
    expires: Int?,    // unix timestamp, optional
}

struct CookieJar {
    cookies: []Cookie,
}

// Create an empty cookie jar
native fn CookieJar.new() -> CookieJar

// Load cookies from a browser profile (chromium, chrome, brave, edge)
native fn CookieJar.load_browser(browser_name: String, domain: String) -> CookieJar

// Load a cookie jar previously saved to disk
native fn CookieJar.load_file(path: String) -> CookieJar

// Add a cookie to the jar
native fn CookieJar.add(self, name: String, value: String, domain: String,
                  path: String?, secure: Bool?, http_only: Bool?, expires: Int?) -> CookieJar

// Get a cookie value by domain and name (returns nil if not found)
native fn CookieJar.get(self, domain: String, name: String) -> String?

// Generate a Cookie header string for HTTP requests
native fn CookieJar.to_header(self, domain: String) -> String

// Save the jar to a JSON file
native fn CookieJar.save(self, path: String)

// List all cookies as an array
native fn CookieJar.cookies(self) -> []Cookie
