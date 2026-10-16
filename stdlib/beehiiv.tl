// beehiiv.tl — Type declarations for the tallow.beehiiv module
//
// Beehiiv publication API client. Interfaces with Beehiiv-powered
// Nuxt 3 sites to extract post metadata, content, and handle auth.

// ─── Functions ────────────────────────────────────────────────

// Discover a Beehiiv publication from a URL.
// Returns metadata map: base_url, build_id, post_slug
fn discover(url: str) -> Map

// Fetch the Nuxt SSR _payload.json for a post URL.
// Returns raw payload as Map with post metadata and free_content_html.
fn get_payload(url: str, build_id?: str) -> Map

// Extract post data from a Beehiiv URL.
// Combines _payload.json discovery with content extraction.
// Returns: title, subtitle, author, publish_date, free_content_html,
//          free_content_text, has_paywall, audience, post_id, slug, url
fn get_post(url: str, build_id?: str) -> Map

// Inject a JWT token via /api/auth/set-token.
// The endpoint accepts any formatted JWT (no signature validation).
// Returns Bool success. Subscriber must exist in Beehiiv for premium access.
fn set_jwt(jwt_token: str, base_url?: str) -> Bool

// Check current auth state via /api/auth/user.
// Returns user data Map if authenticated, or error.
fn get_user(base_url?: str) -> Map

// List available subscription products from /api/product.
// Returns Array of product Maps.
fn list_products(base_url?: str) -> Array
