// tallow.oauth — OAuth 2.0 / OIDC authorization flows.
//
// Automates authorization code + PKCE, client credentials, device code,
// and OIDC discovery. Returns tokens ready for HTTP injection.

struct Token {
    access_token: String,
    token_type: String,
    refresh_token: String?,
    id_token: String?,
    expires_in: Int?,
    scope: String?,
}

struct OAuthConfig {
    url: String,
    code_verifier: String,
}

struct PKCE {
    code_verifier: String,
    code_challenge: String,
}

// Build authorization URL with PKCE challenge
native fn OAuth.authorization_url(auth_endpoint: String, client_id: String, redirect_uri: String,
                            scope: String?, state: String?) -> OAuthConfig

// Exchange authorization code for tokens
native fn OAuth.exchange_code(token_endpoint: String, client_id: String, client_secret: String?,
                        redirect_uri: String, code: String, code_verifier: String) -> Token

// Machine-to-machine token (client credentials grant)
native fn OAuth.client_credentials(token_endpoint: String, client_id: String, client_secret: String,
                             scope: String?) -> Token

// Refresh an access token
native fn OAuth.refresh_token(token_endpoint: String, client_id: String, refresh_token: String) -> Token

// OIDC discovery — fetch .well-known/openid-configuration
native fn OAuth.discover(issuer_url: String) -> Map<String, Value>

// Generate a random PKCE code verifier + challenge pair
native fn OAuth.generate_pkce() -> PKCE

// Generate Authorization: Bearer header
native fn Token.to_header(self) -> String
