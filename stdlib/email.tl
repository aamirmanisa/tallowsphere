// tallow.email — IMAP inbox reader and disposable email (Guerrilla Mail) support.
//
// For OTP interception in email-based authentication flows.
// Primary path: Guerrilla Mail HTTP API (no credentials needed).
// IMAP path: connect to any IMAP server for custom inboxes.

struct Inbox {
    server: String,
    port: Int,
    greeting: String,
    caps: []String,
}

struct GuerrillaInbox {
    email: String,
    sid_token: String,
}

struct Email {
    subject: String,
    body: String,
    from: String,
    mail_id: String,
}

// Connect to an IMAP server
fn Inbox.connect_imap(server: String, port: Int, use_tls: Bool?) -> Inbox

// Authenticate with IMAP credentials
fn Inbox.login(self, user: String, password: String) -> String

// Search inbox for recent emails matching a subject filter
fn Inbox.search(self, subject_filter: String?, since_seconds: Int?) -> []Email

// Fetch the full body text of an email by UID
fn Inbox.fetch_body(self, uid: String) -> String

// Extract OTP/verification codes from email body text
fn Inbox.extract_otp(self, body: String, pattern: String?) -> []String

// Connect to Guerrilla Mail disposable email service (no credentials needed)
fn Inbox.connect_guerrilla() -> GuerrillaInbox

// Get the current temporary email address
fn GuerrillaInbox.get_email(self) -> GuerrillaInbox

// Poll for a new email, waiting up to timeout_secs. Returns Email when one arrives.
fn GuerrillaInbox.wait_for_email(self, timeout_secs: Int?) -> Email?
