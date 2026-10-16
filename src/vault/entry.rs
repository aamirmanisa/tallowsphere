//! Vault entry types — Login, Card, Identity, SecureNote, SSHKey, APIKey, TOTP.

use serde::{Deserialize, Serialize};

/// Unique entry identifier (UUIDv4 hex string).
pub type EntryId = String;

/// A single vault entry.
#[derive(Clone, Serialize, Deserialize)]
pub struct VaultEntry {
    pub id: EntryId,
    pub name: String,
    pub folder: Option<String>,
    pub tags: Vec<String>,
    pub favorite: bool,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: Option<String>,
    pub notes: Option<String>,
    pub data: EntryData,
    pub custom_fields: Vec<CustomField>,
    pub history: Vec<HistoryRecord>,
    #[serde(default)]
    pub attachments: Vec<Attachment>,
    #[serde(default)]
    pub comments: Vec<Comment>,
    #[serde(default)]
    pub linked_entry_ids: Vec<String>,
    #[serde(default)]
    pub deleted_at: Option<String>,
}

impl std::fmt::Debug for VaultEntry {
    /// Hand-written: `notes` is user freeform text (recovery codes and
    /// similar), so it is redacted; payload redaction lives on the
    /// `EntryData` variants (A6.1.1 sweep completion).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultEntry")
            .field("id", &self.id)
            .field("name", &self.name)
            .field("folder", &self.folder)
            .field("tags", &self.tags)
            .field("favorite", &self.favorite)
            .field("created_at", &self.created_at)
            .field("updated_at", &self.updated_at)
            .field("expires_at", &self.expires_at)
            .field("notes", &self.notes.as_ref().map(|_| "[redacted]"))
            .field("data", &self.data)
            .field("custom_fields", &self.custom_fields)
            .field("history", &self.history)
            .field("attachments", &self.attachments)
            .field("comments", &self.comments)
            .field("linked_entry_ids", &self.linked_entry_ids)
            .field("deleted_at", &self.deleted_at)
            .finish()
    }
}

impl std::fmt::Debug for Comment {
    /// Hand-written: comment text is user freeform prose (A6.1.1 sweep
    /// completion); author + timestamp stay visible.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Comment")
            .field("author", &self.author)
            .field("text", &"[redacted]")
            .field("created_at", &self.created_at)
            .finish()
    }
}

/// Comment on a vault entry (like Passbolt).
#[derive(Clone, Serialize, Deserialize)]
pub struct Comment {
    pub author: String,
    pub text: String,
    pub created_at: String,
}

/// Entry payload discriminated by type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum EntryData {
    Login(LoginData),
    Card(CardData),
    Identity(IdentityData),
    SecureNote(SecureNoteData),
    SSHKey(SSHKeyData),
    APIKey(APIKeyData),
    TOTP(TOTPData),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoginData {
    pub username: String,
    pub password: String,
    pub urls: Vec<String>,
    pub totp_secret: Option<String>,
    pub totp_digits: Option<u8>,
    pub totp_period: Option<u32>,
    pub totp_algorithm: Option<String>,
    pub passkey: Option<String>,
}

impl std::fmt::Debug for LoginData {
    /// Hand-written: password, TOTP seed, and passkey are redacted; the
    /// derived form printed all three (A6.1.1 sweep completion — the 2026
    /// vault-audit fix set left this type behind).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LoginData")
            .field("username", &self.username)
            .field("password", &"[redacted]")
            .field("urls", &self.urls)
            .field("totp_secret", &self.totp_secret.as_ref().map(|_| "[redacted]"))
            .field("totp_digits", &self.totp_digits)
            .field("totp_period", &self.totp_period)
            .field("totp_algorithm", &self.totp_algorithm)
            .field("passkey", &self.passkey.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl Drop for LoginData {
    /// Zeroize-on-drop (A6.1.1 sweep completion): password, TOTP seed, and
    /// passkey do not linger in freed memory.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.password.zeroize();
        if let Some(secret) = self.totp_secret.as_mut() {
            secret.zeroize();
        }
        if let Some(passkey) = self.passkey.as_mut() {
            passkey.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CardData {
    pub cardholder: String,
    pub number: String,
    pub brand: Option<String>,
    pub exp_month: String,
    pub exp_year: String,
    pub cvv: String,
}

impl std::fmt::Debug for CardData {
    /// Hand-written: card number + CVV are redacted (A6.1.1 sweep completion).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CardData")
            .field("cardholder", &self.cardholder)
            .field("number", &"[redacted]")
            .field("brand", &self.brand)
            .field("exp_month", &self.exp_month)
            .field("exp_year", &self.exp_year)
            .field("cvv", &"[redacted]")
            .finish()
    }
}

impl Drop for CardData {
    /// Zeroize-on-drop (A6.1.1 sweep completion): number + CVV are wiped.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.number.zeroize();
        self.cvv.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IdentityData {
    pub first_name: String,
    pub last_name: String,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub address_line1: Option<String>,
    pub address_line2: Option<String>,
    pub city: Option<String>,
    pub state: Option<String>,
    pub postal_code: Option<String>,
    pub country: Option<String>,
    pub company: Option<String>,
    pub ssn: Option<String>,
    pub passport: Option<String>,
    pub license: Option<String>,
}

impl std::fmt::Debug for IdentityData {
    /// Hand-written: government identifiers (SSN / passport / license) are
    /// redacted (A6.1.1 sweep completion).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityData")
            .field("first_name", &self.first_name)
            .field("last_name", &self.last_name)
            .field("email", &self.email)
            .field("phone", &self.phone)
            .field("address_line1", &self.address_line1)
            .field("address_line2", &self.address_line2)
            .field("city", &self.city)
            .field("state", &self.state)
            .field("postal_code", &self.postal_code)
            .field("country", &self.country)
            .field("company", &self.company)
            .field("ssn", &self.ssn.as_ref().map(|_| "[redacted]"))
            .field("passport", &self.passport.as_ref().map(|_| "[redacted]"))
            .field("license", &self.license.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl Drop for IdentityData {
    /// Zeroize-on-drop (A6.1.1 sweep completion): government identifiers are
    /// wiped.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if let Some(ssn) = self.ssn.as_mut() {
            ssn.zeroize();
        }
        if let Some(passport) = self.passport.as_mut() {
            passport.zeroize();
        }
        if let Some(license) = self.license.as_mut() {
            license.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecureNoteData {
    pub content: String,
}

impl std::fmt::Debug for SecureNoteData {
    /// Hand-written: note content is redacted (A6.1.1 sweep completion).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureNoteData")
            .field("content", &"[redacted]")
            .finish()
    }
}

impl Drop for SecureNoteData {
    /// Zeroize-on-drop (A6.1.1 sweep completion): note content is wiped.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.content.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SSHKeyData {
    pub private_key: String,
    pub public_key: String,
    pub fingerprint: String,
    pub key_type: String,
    pub comment: Option<String>,
}

impl std::fmt::Debug for SSHKeyData {
    /// Hand-written: the derived form would print `private_key` — secrets
    /// never reach logs/panics (A6.1.1 sweep).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SSHKeyData")
            .field("private_key", &"[redacted]")
            .field("public_key", &self.public_key)
            .field("fingerprint", &self.fingerprint)
            .field("key_type", &self.key_type)
            .field("comment", &self.comment)
            .finish()
    }
}

impl Drop for SSHKeyData {
    /// Zeroize-on-drop (A6.1.1 sweep): the private key does not linger in
    /// freed memory.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.private_key.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct APIKeyData {
    pub key: String,
    pub secret: Option<String>,
    pub endpoint: Option<String>,
    pub environment: Option<String>,
}

impl std::fmt::Debug for APIKeyData {
    /// Hand-written: key + secret are redacted (A6.1.1 sweep).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("APIKeyData")
            .field("key", &"[redacted]")
            .field("secret", &self.secret.as_ref().map(|_| "[redacted]"))
            .field("endpoint", &self.endpoint)
            .field("environment", &self.environment)
            .finish()
    }
}

impl Drop for APIKeyData {
    /// Zeroize-on-drop (A6.1.1 sweep): key + secret are wiped.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.key.zeroize();
        if let Some(secret) = self.secret.as_mut() {
            secret.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TOTPData {
    pub secret: String,
    pub issuer: Option<String>,
    pub account: Option<String>,
    pub digits: u8,
    pub period: u32,
    pub algorithm: String,
}

impl std::fmt::Debug for TOTPData {
    /// Hand-written: the TOTP seed is redacted (A6.1.1 sweep completion).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TOTPData")
            .field("secret", &"[redacted]")
            .field("issuer", &self.issuer)
            .field("account", &self.account)
            .field("digits", &self.digits)
            .field("period", &self.period)
            .field("algorithm", &self.algorithm)
            .finish()
    }
}

impl Drop for TOTPData {
    /// Zeroize-on-drop (A6.1.1 sweep completion): the TOTP seed is wiped.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.secret.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CustomField {
    pub name: String,
    pub value: String,
    pub hidden: bool,
    pub field_type: String,
}

impl std::fmt::Debug for CustomField {
    /// Hand-written: a `hidden` field's value never prints (A6.1.1 sweep
    /// completion).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = if self.hidden { "[redacted]" } else { self.value.as_str() };
        f.debug_struct("CustomField")
            .field("name", &self.name)
            .field("value", &value)
            .field("hidden", &self.hidden)
            .field("field_type", &self.field_type)
            .finish()
    }
}

impl Drop for CustomField {
    /// Zeroize-on-drop (A6.1.1 sweep completion): hidden values are wiped.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        if self.hidden {
            self.value.zeroize();
        }
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HistoryRecord {
    pub timestamp: String,
    pub field: String,
    pub old_value: String,
}

impl std::fmt::Debug for HistoryRecord {
    /// Hand-written: `old_value` may hold a superseded secret (e.g. an old
    /// password), so it is redacted (A6.1.1 sweep completion).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HistoryRecord")
            .field("timestamp", &self.timestamp)
            .field("field", &self.field)
            .field("old_value", &"[redacted]")
            .finish()
    }
}

impl Drop for HistoryRecord {
    /// Zeroize-on-drop (A6.1.1 sweep completion): superseded values are wiped.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.old_value.zeroize();
    }
}

impl VaultEntry {
    pub fn new_login(name: &str, username: &str, password: &str, urls: Vec<String>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
            notes: None,
            data: EntryData::Login(LoginData {
                username: username.to_string(),
                password: password.to_string(),
                urls,
                totp_secret: None,
                totp_digits: None,
                totp_period: None,
                totp_algorithm: None,
                passkey: None,
            }),
            custom_fields: Vec::new(),
            history: Vec::new(),
            attachments: Vec::new(),
            comments: Vec::new(),
            linked_entry_ids: Vec::new(),
            deleted_at: None,
        }
    }

    pub fn new_card(name: &str, cardholder: &str, number: &str, exp_month: &str, exp_year: &str, cvv: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
            notes: None,
            data: EntryData::Card(CardData {
                cardholder: cardholder.to_string(),
                number: number.to_string(),
                brand: None,
                exp_month: exp_month.to_string(),
                exp_year: exp_year.to_string(),
                cvv: cvv.to_string(),
            }),
            custom_fields: Vec::new(),
            history: Vec::new(),
            attachments: Vec::new(),
            comments: Vec::new(),
            linked_entry_ids: Vec::new(),
            deleted_at: None,
        }
    }

    pub fn new_note(name: &str, content: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
            notes: None,
            data: EntryData::SecureNote(SecureNoteData { content: content.to_string() }),
            custom_fields: Vec::new(),
            history: Vec::new(),
            attachments: Vec::new(),
            comments: Vec::new(),
            linked_entry_ids: Vec::new(),
            deleted_at: None,
        }
    }

    pub fn new_ssh_key(name: &str, private_key: &str, public_key: &str, fingerprint: &str, key_type: &str) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
            notes: None,
            data: EntryData::SSHKey(SSHKeyData {
                private_key: private_key.to_string(),
                public_key: public_key.to_string(),
                fingerprint: fingerprint.to_string(),
                key_type: key_type.to_string(),
                comment: None,
            }),
            custom_fields: Vec::new(),
            history: Vec::new(),
            attachments: Vec::new(),
            comments: Vec::new(),
            linked_entry_ids: Vec::new(),
            deleted_at: None,
        }
    }

    pub fn new_api_key(name: &str, key: &str, secret: Option<&str>, endpoint: Option<&str>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
            notes: None,
            data: EntryData::APIKey(APIKeyData {
                key: key.to_string(),
                secret: secret.map(|s| s.to_string()),
                endpoint: endpoint.map(|s| s.to_string()),
                environment: None,
            }),
            custom_fields: Vec::new(),
            history: Vec::new(),
            attachments: Vec::new(),
            comments: Vec::new(),
            linked_entry_ids: Vec::new(),
            deleted_at: None,
        }
    }

    pub fn new_totp(name: &str, secret: &str, issuer: Option<&str>, account: Option<&str>) -> Self {
        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            folder: None,
            tags: Vec::new(),
            favorite: false,
            created_at: chrono::Utc::now().to_rfc3339(),
            updated_at: chrono::Utc::now().to_rfc3339(),
            expires_at: None,
            notes: None,
            data: EntryData::TOTP(TOTPData {
                secret: secret.to_string(),
                issuer: issuer.map(|s| s.to_string()),
                account: account.map(|s| s.to_string()),
                digits: 6,
                period: 30,
                algorithm: "SHA1".to_string(),
            }),
            custom_fields: Vec::new(),
            history: Vec::new(),
            attachments: Vec::new(),
            comments: Vec::new(),
            linked_entry_ids: Vec::new(),
            deleted_at: None,
        }
    }

    /// Get the entry type as a string for display.
    pub fn entry_type(&self) -> &str {
        match &self.data {
            EntryData::Login(_) => "Login",
            EntryData::Card(_) => "Card",
            EntryData::Identity(_) => "Identity",
            EntryData::SecureNote(_) => "Secure Note",
            EntryData::SSHKey(_) => "SSH Key",
            EntryData::APIKey(_) => "API Key",
            EntryData::TOTP(_) => "TOTP",
        }
    }

    /// Get the username (for login entries) or primary identifier.
    pub fn username(&self) -> Option<&str> {
        match &self.data {
            EntryData::Login(d) => Some(&d.username),
            EntryData::Card(d) => Some(&d.cardholder),
            EntryData::Identity(d) => Some(&d.first_name),
            EntryData::APIKey(d) => Some(&d.key),
            EntryData::TOTP(d) => d.account.as_deref(),
            _ => None,
        }
    }

    /// Add a history record when a field changes.
    pub fn record_change(&mut self, field: &str, old_value: &str) {
        self.history.push(HistoryRecord {
            timestamp: chrono::Utc::now().to_rfc3339(),
            field: field.to_string(),
            old_value: old_value.to_string(),
        });
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    /// Update password (with history tracking).
    pub fn update_password(&mut self, new_password: &str) {
        let old = match &self.data {
            EntryData::Login(d) => Some(d.password.clone()),
            _ => None,
        };
        if let Some(old_pw) = old {
            self.record_change("password", &old_pw);
            if let EntryData::Login(ref mut d) = self.data {
                d.password = new_password.to_string();
            }
        }
    }

    /// Update username (with history tracking).
    pub fn update_username(&mut self, new_username: &str) {
        let old = match &self.data {
            EntryData::Login(d) => Some(d.username.clone()),
            _ => None,
        };
        if let Some(old_user) = old {
            self.record_change("username", &old_user);
            if let EntryData::Login(ref mut d) = self.data {
                d.username = new_username.to_string();
            }
        }
    }

    /// Add a URL to login entry.
    pub fn add_url(&mut self, url: &str) {
        if let EntryData::Login(ref mut d) = self.data {
            let u = url.to_string();
            if !d.urls.contains(&u) {
                d.urls.push(u);
                self.updated_at = chrono::Utc::now().to_rfc3339();
            }
        }
    }

    /// Remove a URL from login entry.
    pub fn remove_url(&mut self, url: &str) {
        if let EntryData::Login(ref mut d) = self.data {
            if let Some(pos) = d.urls.iter().position(|u| u == url) {
                d.urls.remove(pos);
                self.updated_at = chrono::Utc::now().to_rfc3339();
            }
        }
    }

    /// Set TOTP secret on login entry.
    pub fn set_totp(&mut self, secret: &str, digits: u8, period: u32, algorithm: &str) {
        if let EntryData::Login(ref mut d) = self.data {
            d.totp_secret = Some(secret.to_string());
            d.totp_digits = Some(digits);
            d.totp_period = Some(period);
            d.totp_algorithm = Some(algorithm.to_string());
            self.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }

    /// Add a custom field.
    /// field_type: "text", "hidden", "boolean", "linked"
    pub fn add_custom_field(&mut self, name: &str, value: &str, hidden: bool) {
        self.custom_fields.push(CustomField {
            name: name.to_string(),
            value: value.to_string(),
            hidden,
            field_type: if hidden { "hidden".to_string() } else { "text".to_string() },
        });
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    /// Add a boolean custom field.
    pub fn add_boolean_field(&mut self, name: &str, value: bool) {
        self.custom_fields.push(CustomField {
            name: name.to_string(),
            value: value.to_string(),
            hidden: false,
            field_type: "boolean".to_string(),
        });
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    /// Add a linked custom field (references another field in the entry).
    pub fn add_linked_field(&mut self, name: &str, linked_field: &str) {
        self.custom_fields.push(CustomField {
            name: name.to_string(),
            value: linked_field.to_string(),
            hidden: false,
            field_type: "linked".to_string(),
        });
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    /// Toggle favorite.
    pub fn toggle_favorite(&mut self) {
        self.favorite = !self.favorite;
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    /// Set folder.
    pub fn set_folder(&mut self, folder: &str) {
        self.folder = Some(folder.to_string());
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    /// Add tag.
    pub fn add_tag(&mut self, tag: &str) {
        let t = tag.to_string();
        if !self.tags.contains(&t) {
            self.tags.push(t);
            self.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }

    /// Remove tag.
    pub fn remove_tag(&mut self, tag: &str) {
        if let Some(pos) = self.tags.iter().position(|t| t == tag) {
            self.tags.remove(pos);
            self.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }

    /// Set expiration.
    pub fn set_expiry(&mut self, expires_at: &str) {
        self.expires_at = Some(expires_at.to_string());
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    /// Add an attachment.
    pub fn add_attachment(&mut self, attachment: Attachment) {
        self.attachments.push(attachment);
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    /// Soft-delete entry (move to recycle bin).
    pub fn soft_delete(&mut self) {
        self.deleted_at = Some(chrono::Utc::now().to_rfc3339());
    }

    /// Restore soft-deleted entry.
    pub fn restore(&mut self) {
        self.deleted_at = None;
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    /// Check if entry is in recycle bin.
    pub fn is_deleted(&self) -> bool {
        self.deleted_at.is_some()
    }

    /// Add a comment.
    pub fn add_comment(&mut self, author: &str, text: &str) {
        self.comments.push(Comment {
            author: author.to_string(),
            text: text.to_string(),
            created_at: chrono::Utc::now().to_rfc3339(),
        });
        self.updated_at = chrono::Utc::now().to_rfc3339();
    }

    /// Link to another entry (cross-reference).
    pub fn add_link(&mut self, entry_id: &str) {
        let id = entry_id.to_string();
        if !self.linked_entry_ids.contains(&id) {
            self.linked_entry_ids.push(id);
            self.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }

    /// Remove a cross-reference link.
    pub fn remove_link(&mut self, entry_id: &str) {
        if let Some(pos) = self.linked_entry_ids.iter().position(|id| id == entry_id) {
            self.linked_entry_ids.remove(pos);
            self.updated_at = chrono::Utc::now().to_rfc3339();
        }
    }

    /// Remove an attachment by filename.
    pub fn remove_attachment(&mut self, filename: &str) -> Option<Attachment> {
        if let Some(pos) = self.attachments.iter().position(|a| a.filename == filename) {
            self.updated_at = chrono::Utc::now().to_rfc3339();
            Some(self.attachments.remove(pos))
        } else {
            None
        }
    }
}

/// Attachment stored in an entry.
impl std::fmt::Debug for Attachment {
    /// Hand-written: attachment bytes (`data_base64`) are redacted
    /// (A6.1.1 sweep completion); metadata stays visible.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Attachment")
            .field("filename", &self.filename)
            .field("mime_type", &self.mime_type)
            .field("size", &self.size)
            .field("data_base64", &"[redacted]")
            .finish()
    }
}

impl Drop for Attachment {
    /// Zeroize-on-drop (A6.1.1 sweep completion): attachment bytes are wiped.
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.data_base64.zeroize();
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Attachment {
    pub filename: String,
    pub mime_type: String,
    pub size: usize,
    pub data_base64: String,
}

/// Sort entries by name (case-insensitive).
pub fn sort_by_name(entries: &mut [VaultEntry]) {
    entries.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
}

/// Sort entries by updated_at date (newest first).
pub fn sort_by_date(entries: &mut [VaultEntry]) {
    entries.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
}

/// Sort entries by type name, then by name within each type.
pub fn sort_by_type(entries: &mut [VaultEntry]) {
    entries.sort_by(|a, b| {
        a.entry_type()
            .cmp(b.entry_type())
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

/// Filter entries by type string (e.g. "Login", "Card", "Identity").
pub fn filter_by_type<'a>(entries: &'a [VaultEntry], entry_type: &str) -> Vec<&'a VaultEntry> {
    entries
        .iter()
        .filter(|e| e.entry_type().eq_ignore_ascii_case(entry_type))
        .collect()
}

/// Filter entries by tag (case-insensitive).
pub fn filter_by_tag<'a>(entries: &'a [VaultEntry], tag: &str) -> Vec<&'a VaultEntry> {
    let tag_lower = tag.to_lowercase();
    entries
        .iter()
        .filter(|e| e.tags.iter().any(|t| t.to_lowercase() == tag_lower))
        .collect()
}

impl LoginData {
    /// Get the primary URL.
    pub fn primary_url(&self) -> Option<&str> {
        self.urls.first().map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn update_password_tracks_history() {
        let mut entry = VaultEntry::new_login("Test", "user", "old-pw", vec![]);
        entry.update_password("new-pw");
        if let EntryData::Login(ref d) = entry.data {
            assert_eq!(d.password, "new-pw");
        } else {
            panic!("expected Login");
        }
        assert_eq!(entry.history.len(), 1);
        assert_eq!(entry.history[0].field, "password");
        assert_eq!(entry.history[0].old_value, "old-pw");
    }

    #[test]
    fn update_username_tracks_history() {
        let mut entry = VaultEntry::new_login("Test", "old-user", "pw", vec![]);
        entry.update_username("new-user");
        if let EntryData::Login(ref d) = entry.data {
            assert_eq!(d.username, "new-user");
        } else {
            panic!("expected Login");
        }
        assert_eq!(entry.history.len(), 1);
        assert_eq!(entry.history[0].field, "username");
        assert_eq!(entry.history[0].old_value, "old-user");
    }

    #[test]
    fn add_and_remove_url() {
        let mut entry = VaultEntry::new_login("Test", "u", "p", vec!["https://a.com".into()]);
        entry.add_url("https://b.com");
        if let EntryData::Login(ref d) = entry.data {
            assert_eq!(d.urls.len(), 2);
        }
        // Duplicate add should be no-op
        entry.add_url("https://b.com");
        if let EntryData::Login(ref d) = entry.data {
            assert_eq!(d.urls.len(), 2);
        }
        entry.remove_url("https://a.com");
        if let EntryData::Login(ref d) = entry.data {
            assert_eq!(d.urls, vec!["https://b.com"]);
        }
    }

    #[test]
    fn set_totp() {
        let mut entry = VaultEntry::new_login("Test", "u", "p", vec![]);
        entry.set_totp("JBSWY3DPEHPK3PXP", 6, 30, "SHA1");
        if let EntryData::Login(ref d) = entry.data {
            assert_eq!(d.totp_secret, Some("JBSWY3DPEHPK3PXP".to_string()));
            assert_eq!(d.totp_digits, Some(6));
            assert_eq!(d.totp_period, Some(30));
            assert_eq!(d.totp_algorithm, Some("SHA1".to_string()));
        }
    }

    #[test]
    fn custom_fields() {
        let mut entry = VaultEntry::new_login("Test", "u", "p", vec![]);
        entry.add_custom_field("PIN", "1234", true);
        assert_eq!(entry.custom_fields.len(), 1);
        assert_eq!(entry.custom_fields[0].name, "PIN");
        assert_eq!(entry.custom_fields[0].value, "1234");
        assert!(entry.custom_fields[0].hidden);
        assert_eq!(entry.custom_fields[0].field_type, "hidden");
    }

    #[test]
    fn toggle_favorite() {
        let mut entry = VaultEntry::new_login("Test", "u", "p", vec![]);
        assert!(!entry.favorite);
        entry.toggle_favorite();
        assert!(entry.favorite);
        entry.toggle_favorite();
        assert!(!entry.favorite);
    }

    #[test]
    fn set_folder() {
        let mut entry = VaultEntry::new_login("Test", "u", "p", vec![]);
        assert!(entry.folder.is_none());
        entry.set_folder("Work");
        assert_eq!(entry.folder, Some("Work".to_string()));
    }

    #[test]
    fn tags() {
        let mut entry = VaultEntry::new_login("Test", "u", "p", vec![]);
        entry.add_tag("important");
        entry.add_tag("work");
        assert_eq!(entry.tags.len(), 2);
        // Duplicate should be no-op
        entry.add_tag("important");
        assert_eq!(entry.tags.len(), 2);
        entry.remove_tag("important");
        assert_eq!(entry.tags, vec!["work"]);
    }

    #[test]
    fn set_expiry() {
        let mut entry = VaultEntry::new_login("Test", "u", "p", vec![]);
        entry.set_expiry("2030-01-01T00:00:00Z");
        assert_eq!(entry.expires_at, Some("2030-01-01T00:00:00Z".to_string()));
    }

    #[test]
    fn attachments() {
        let mut entry = VaultEntry::new_login("Test", "u", "p", vec![]);
        assert!(entry.attachments.is_empty());
        let att = Attachment {
            filename: "doc.pdf".to_string(),
            mime_type: "application/pdf".to_string(),
            size: 1024,
            data_base64: "dGVzdA==".to_string(),
        };
        entry.add_attachment(att);
        assert_eq!(entry.attachments.len(), 1);
        assert_eq!(entry.attachments[0].filename, "doc.pdf");

        let removed = entry.remove_attachment("doc.pdf");
        assert!(removed.is_some());
        assert!(entry.attachments.is_empty());

        // Remove non-existent
        assert!(entry.remove_attachment("nope.txt").is_none());
    }

    #[test]
    fn sort_by_name_test() {
        let mut entries = vec![
            VaultEntry::new_login("Zebra", "u", "p", vec![]),
            VaultEntry::new_login("alpha", "u", "p", vec![]),
            VaultEntry::new_login("Beta", "u", "p", vec![]),
        ];
        sort_by_name(&mut entries);
        assert_eq!(entries[0].name, "alpha");
        assert_eq!(entries[1].name, "Beta");
        assert_eq!(entries[2].name, "Zebra");
    }

    #[test]
    fn sort_by_type_test() {
        let mut entries = vec![
            VaultEntry::new_note("Z-Note", "content"),
            VaultEntry::new_login("A-Login", "u", "p", vec![]),
            VaultEntry::new_card("B-Card", "holder", "1234", "01", "30", "999"),
        ];
        sort_by_type(&mut entries);
        assert_eq!(entries[0].entry_type(), "Card");
        assert_eq!(entries[1].entry_type(), "Login");
        assert_eq!(entries[2].entry_type(), "Secure Note");
    }

    #[test]
    fn filter_by_type_test() {
        let entries = vec![
            VaultEntry::new_login("A", "u", "p", vec![]),
            VaultEntry::new_note("B", "content"),
            VaultEntry::new_login("C", "u", "p", vec![]),
        ];
        let logins = filter_by_type(&entries, "Login");
        assert_eq!(logins.len(), 2);
        let notes = filter_by_type(&entries, "Secure Note");
        assert_eq!(notes.len(), 1);
    }

    #[test]
    fn filter_by_tag_test() {
        let mut e1 = VaultEntry::new_login("A", "u", "p", vec![]);
        e1.add_tag("work");
        let mut e2 = VaultEntry::new_login("B", "u", "p", vec![]);
        e2.add_tag("personal");
        let e3 = VaultEntry::new_login("C", "u", "p", vec![]);
        let entries = vec![e1, e2, e3];

        let work = filter_by_tag(&entries, "work");
        assert_eq!(work.len(), 1);
        assert_eq!(work[0].name, "A");

        let none = filter_by_tag(&entries, "missing");
        assert!(none.is_empty());
    }

    #[test]
    fn update_password_noop_on_non_login() {
        let mut entry = VaultEntry::new_note("Note", "content");
        entry.update_password("new-pw");
        // Should be a no-op; history empty
        assert!(entry.history.is_empty());
    }

    #[test]
    fn secret_bearing_entry_data_redacts_and_wipes() {
        let ssh = SSHKeyData {
            private_key: "SUPERSECRET-PRIVKEY".to_string(),
            public_key: "ssh-ed25519 AAAA".to_string(),
            fingerprint: "SHA256:abc".to_string(),
            key_type: "ed25519".to_string(),
            comment: None,
        };
        let dbg = format!("{ssh:?}");
        assert!(dbg.contains("[redacted]"), "{dbg}");
        assert!(!dbg.contains("SUPERSECRET"), "{dbg}");

        let api = APIKeyData {
            key: "AKIA-SUPERSECRET".to_string(),
            secret: Some("SECRETSQUIRREL".to_string()),
            endpoint: Some("https://api.example".to_string()),
            environment: None,
        };
        let dbg = format!("{api:?}");
        assert!(dbg.contains("[redacted]"), "{dbg}");
        assert!(
            !dbg.contains("SUPERSECRET") && !dbg.contains("SECRETSQUIRREL"),
            "{dbg}"
        );

        // A6.1.1 sweep completion (2026-09-28): every remaining
        // secret-bearing entry payload redacts too.
        let login = LoginData {
            username: "the operator".to_string(),
            password: "SUPERSECRET-PW".to_string(),
            urls: vec!["https://example.test".to_string()],
            totp_secret: Some("SUPERSECRET-TOTP".to_string()),
            totp_digits: None,
            totp_period: None,
            totp_algorithm: None,
            passkey: Some("SUPERSECRET-PASSKEY".to_string()),
        };
        let dbg = format!("{login:?}");
        assert!(dbg.contains("[redacted]"), "{dbg}");
        assert!(!dbg.contains("SUPERSECRET"), "{dbg}");

        let card = CardData {
            cardholder: "the operator".to_string(),
            number: "SUPERSECRET-CARD".to_string(),
            brand: Some("visa".to_string()),
            exp_month: "01".to_string(),
            exp_year: "2030".to_string(),
            cvv: "SUPERSECRET-CVV".to_string(),
        };
        let dbg = format!("{card:?}");
        assert!(!dbg.contains("SUPERSECRET"), "{dbg}");

        let totp = TOTPData {
            secret: "SUPERSECRET-SEED".to_string(),
            issuer: Some("GitHub".to_string()),
            account: None,
            digits: 6,
            period: 30,
            algorithm: "SHA1".to_string(),
        };
        let dbg = format!("{totp:?}");
        assert!(!dbg.contains("SUPERSECRET"), "{dbg}");

        let note = SecureNoteData { content: "SUPERSECRET-NOTE".to_string() };
        let dbg = format!("{note:?}");
        assert!(!dbg.contains("SUPERSECRET"), "{dbg}");

        let ident = IdentityData {
            first_name: "A".to_string(),
            last_name: "M".to_string(),
            email: None,
            phone: None,
            address_line1: None,
            address_line2: None,
            city: None,
            state: None,
            postal_code: None,
            country: None,
            company: None,
            ssn: Some("SUPERSECRET-SSN".to_string()),
            passport: None,
            license: None,
        };
        let dbg = format!("{ident:?}");
        assert!(!dbg.contains("SUPERSECRET"), "{dbg}");

        let hidden = CustomField {
            name: "pin".to_string(),
            value: "SUPERSECRET-PIN".to_string(),
            hidden: true,
            field_type: "text".to_string(),
        };
        let dbg = format!("{hidden:?}");
        assert!(!dbg.contains("SUPERSECRET"), "{dbg}");

        let att = Attachment {
            filename: "scan.pdf".to_string(),
            mime_type: "application/pdf".to_string(),
            size: 3,
            data_base64: "SUPERSECRET-BYTES".to_string(),
        };
        let dbg = format!("{att:?}");
        assert!(!dbg.contains("SUPERSECRET"), "{dbg}");
    }
}
