// tallow.jwt — JSON Web Token analysis, forgery, and attack.
//
// Parse JWTs without verification, forge HMAC-signed tokens,
// and run standard JWT attacks: alg:none, weak secret brute force,
// kid injection, and alg confusion.

struct JWT {
    header: Map<String, Value>,
    payload: Map<String, Value>,
    algorithm: String,
    signature: String,
}

struct JWTAttackResult {
    attack_type: String,
    forged_token: String?,
    found_secrets: []String?,
    can_forge: Bool?,
    note: String?,
}

struct JWTKidInjection {
    kid: String,
    description: String,
    forged_token: String,
}

// Decode a JWT without verification — returns header, payload, algorithm, and signature.
fn JWT.parse(token: String) -> JWT

// Create a signed JWT with HMAC (HS256, HS384, HS512).
fn JWT.forge(payload: String, secret: String, algorithm: String) -> String

// Attack: replace algorithm with "none" and remove the signature.
fn JWT.attack_none(token: String) -> JWTAttackResult

// Attack: brute force HMAC secrets from a wordlist. Returns found secrets.
fn JWT.attack_weak_secrets(token: String, wordlist: []String) -> JWTAttackResult

// Attack: inject malicious KID values into the JWT header.
fn JWT.attack_kid_injection(self, payload: String) -> []JWTKidInjection

// Attack: RS256→HS256 algorithm confusion using a public key as HMAC secret.
fn JWT.attack_alg_confusion(self, public_key_pem: String) -> JWTAttackResult
