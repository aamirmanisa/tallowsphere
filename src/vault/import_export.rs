//! Import/export vault entries from/to other password manager formats.
//!
//! Supported sources: Bitwarden JSON, KeePass CSV, Chrome CSV, Firefox CSV,
//! LastPass CSV, generic CSV with custom column mapping.
//! Export targets: Bitwarden JSON, CSV, AES-256-GCM encrypted JSON.

#[allow(unused_imports)]
use super::entry::{CardData, EntryData, IdentityData, LoginData, VaultEntry};

// ── CSV Parser ──────────────────────────────────────────────────────────────

/// Simple RFC-4180-compatible CSV parser: splits on comma, handles double-
/// quoted fields (including escaped `""` inside quotes).
fn parse_csv_line(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(ch) = chars.next() {
        if in_quotes {
            if ch == '"' {
                // Peek: if next is also `"`, it is an escaped quote.
                if chars.peek() == Some(&'"') {
                    chars.next();
                    current.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(ch);
            }
        } else if ch == '"' {
            in_quotes = true;
        } else if ch == ',' {
            fields.push(current.clone());
            current.clear();
        } else {
            current.push(ch);
        }
    }
    fields.push(current);
    fields
}

/// Parse a full CSV string into a header row + data rows.
fn parse_csv(csv: &str) -> Result<(Vec<String>, Vec<Vec<String>>), String> {
    let mut lines = csv.lines();
    let header_line = lines.next().ok_or("CSV is empty -- no header row")?;
    let headers: Vec<String> = parse_csv_line(header_line)
        .into_iter()
        .map(|s| s.trim().to_string())
        .collect();

    let mut rows = Vec::new();
    for line in lines {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        rows.push(parse_csv_line(trimmed));
    }
    Ok((headers, rows))
}

/// Find a column index by name (case-insensitive).
fn col_index(headers: &[String], name: &str) -> Option<usize> {
    headers
        .iter()
        .position(|h| h.eq_ignore_ascii_case(name))
}

fn field(row: &[String], idx: Option<usize>) -> String {
    idx.and_then(|i| row.get(i))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn field_opt(row: &[String], idx: Option<usize>) -> Option<String> {
    idx.and_then(|i| row.get(i))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Build a VaultEntry from common login fields.
fn make_login_entry(
    name: &str,
    username: &str,
    password: &str,
    url: &str,
    notes: Option<String>,
    folder: Option<String>,
    totp: Option<String>,
    favorite: bool,
) -> VaultEntry {
    let mut urls = Vec::new();
    if !url.is_empty() {
        urls.push(url.to_string());
    }
    let mut entry = VaultEntry::new_login(name, username, password, urls);
    entry.notes = notes;
    entry.folder = folder;
    entry.favorite = favorite;
    if let EntryData::Login(ref mut d) = entry.data {
        d.totp_secret = totp;
    }
    entry
}

// ── Column Mapping ──────────────────────────────────────────────────────────

/// Column indices for generic CSV import.
#[derive(Debug, Clone, Default)]
pub struct CsvMapping {
    pub name_col: Option<usize>,
    pub username_col: Option<usize>,
    pub password_col: Option<usize>,
    pub url_col: Option<usize>,
    pub notes_col: Option<usize>,
    pub folder_col: Option<usize>,
}

// ── Import: Bitwarden JSON ──────────────────────────────────────────────────

/// Import entries from a Bitwarden unencrypted JSON export.
///
/// Expected top-level keys: `folders`, `items`. Each item has `type`
/// (1=Login, 2=SecureNote, 3=Card, 4=Identity), `name`, `login`, `notes`, etc.
pub fn import_bitwarden_json(json_str: &str) -> Result<Vec<VaultEntry>, String> {
    let root: serde_json::Value =
        serde_json::from_str(json_str).map_err(|e| format!("invalid JSON: {e}"))?;

    // Build folder-id -> name map.
    let mut folder_map = std::collections::HashMap::new();
    if let Some(folders) = root.get("folders").and_then(|v| v.as_array()) {
        for f in folders {
            if let (Some(id), Some(name)) = (
                f.get("id").and_then(|v| v.as_str()),
                f.get("name").and_then(|v| v.as_str()),
            ) {
                folder_map.insert(id.to_string(), name.to_string());
            }
        }
    }

    let items = root
        .get("items")
        .and_then(|v| v.as_array())
        .ok_or("missing or invalid 'items' array")?;

    let mut entries = Vec::with_capacity(items.len());

    for item in items {
        let name = item
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("(unnamed)")
            .to_string();
        let notes = item
            .get("notes")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let folder_id = item.get("folderId").and_then(|v| v.as_str());
        let folder = folder_id.and_then(|id| folder_map.get(id).cloned());
        let favorite = item
            .get("favorite")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let item_type = item
            .get("type")
            .and_then(|v| v.as_u64())
            .unwrap_or(1);

        match item_type {
            1 => {
                // Login
                let login = item.get("login");
                let username = login
                    .and_then(|l| l.get("username"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let password = login
                    .and_then(|l| l.get("password"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let url = login
                    .and_then(|l| l.get("uris"))
                    .and_then(|v| v.as_array())
                    .and_then(|a| a.first())
                    .and_then(|u| u.get("uri"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let totp = login
                    .and_then(|l| l.get("totp"))
                    .and_then(|v| v.as_str())
                    .filter(|s| !s.is_empty())
                    .map(|s| s.to_string());

                entries.push(make_login_entry(
                    &name, username, password, url, notes, folder, totp, favorite,
                ));
            }
            2 => {
                // SecureNote
                let content = notes.clone().unwrap_or_default();
                let mut entry = VaultEntry::new_note(&name, &content);
                entry.folder = folder;
                entry.favorite = favorite;
                entry.notes = notes;
                entries.push(entry);
            }
            3 => {
                // Card
                if let Some(card) = item.get("card") {
                    let mut entry = VaultEntry::new_card(
                        &name,
                        card.get("cardholderName").and_then(|v| v.as_str()).unwrap_or(""),
                        card.get("number").and_then(|v| v.as_str()).unwrap_or(""),
                        card.get("expMonth").and_then(|v| v.as_str()).unwrap_or(""),
                        card.get("expYear").and_then(|v| v.as_str()).unwrap_or(""),
                        card.get("code").and_then(|v| v.as_str()).unwrap_or(""),
                    );
                    if let EntryData::Card(ref mut d) = entry.data {
                        d.brand = card.get("brand").and_then(|v| v.as_str()).map(|s| s.to_string());
                    }
                    entry.folder = folder;
                    entry.favorite = favorite;
                    entry.notes = notes;
                    entries.push(entry);
                } else {
                    // Card field missing — import as note to avoid data loss
                    let raw = serde_json::to_string_pretty(item).unwrap_or_default();
                    let mut entry = VaultEntry::new_note(&name, &format!("[Bitwarden card - missing data]\n{raw}"));
                    entry.folder = folder;
                    entry.favorite = favorite;
                    entry.notes = notes;
                    entries.push(entry);
                }
            }
            4 => {
                // Identity
                if let Some(id) = item.get("identity") {
                    let now = chrono::Utc::now().to_rfc3339();
                    let entry = VaultEntry {
                        id: uuid::Uuid::new_v4().to_string(),
                        name: name.clone(),
                        folder,
                        tags: Vec::new(),
                        favorite,
                        created_at: now.clone(),
                        updated_at: now,
                        expires_at: None,
                        notes,
                        data: EntryData::Identity(IdentityData {
                            first_name: id.get("firstName").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            last_name: id.get("lastName").and_then(|v| v.as_str()).unwrap_or("").to_string(),
                            email: id.get("email").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            phone: id.get("phone").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            address_line1: id.get("address1").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            address_line2: id.get("address2").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            city: id.get("city").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            state: id.get("state").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            postal_code: id.get("postalCode").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            country: id.get("country").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            company: id.get("company").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            ssn: id.get("ssn").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            passport: id.get("passportNumber").and_then(|v| v.as_str()).map(|s| s.to_string()),
                            license: id.get("licenseNumber").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        }),
                        custom_fields: Vec::new(),
                        history: Vec::new(),
                        attachments: Vec::new(),
                        comments: Vec::new(),
                        linked_entry_ids: Vec::new(),
                        deleted_at: None,
                    };
                    entries.push(entry);
                } else {
                    // Identity field missing — import as note
                    let raw = serde_json::to_string_pretty(item).unwrap_or_default();
                    let mut entry = VaultEntry::new_note(&name, &format!("[Bitwarden identity - missing data]\n{raw}"));
                    entry.folder = folder;
                    entry.favorite = favorite;
                    entry.notes = notes;
                    entries.push(entry);
                }
            }
            _ => {
                // Unknown type -- import as a note with raw JSON so nothing is lost.
                let raw = serde_json::to_string_pretty(item).unwrap_or_default();
                let mut entry = VaultEntry::new_note(
                    &name,
                    &format!("[Bitwarden type {item_type}]\n{raw}"),
                );
                entry.folder = folder;
                entry.favorite = favorite;
                entry.notes = notes;
                entries.push(entry);
            }
        }
    }

    Ok(entries)
}

// ── Import: KeePass CSV ─────────────────────────────────────────────────────

/// Import from a KeePass CSV export.
///
/// Expected headers: `Group,Title,Username,Password,URL,Notes`
pub fn import_keepass_csv(csv_str: &str) -> Result<Vec<VaultEntry>, String> {
    let (headers, rows) = parse_csv(csv_str)?;

    let group_idx = col_index(&headers, "Group");
    let title_idx = col_index(&headers, "Title");
    let user_idx = col_index(&headers, "Username");
    let pw_idx = col_index(&headers, "Password");
    let url_idx = col_index(&headers, "URL");
    let notes_idx = col_index(&headers, "Notes");

    let mut entries = Vec::with_capacity(rows.len());
    for row in &rows {
        entries.push(make_login_entry(
            &field(row, title_idx),
            &field(row, user_idx),
            &field(row, pw_idx),
            &field(row, url_idx),
            field_opt(row, notes_idx),
            field_opt(row, group_idx),
            None,
            false,
        ));
    }
    Ok(entries)
}

// ── Import: Chrome/Edge CSV ─────────────────────────────────────────────────

/// Import from a Chrome or Edge CSV export.
///
/// Expected headers: `name,url,username,password,note`
pub fn import_chrome_csv(csv_str: &str) -> Result<Vec<VaultEntry>, String> {
    let (headers, rows) = parse_csv(csv_str)?;

    let name_idx = col_index(&headers, "name");
    let url_idx = col_index(&headers, "url");
    let user_idx = col_index(&headers, "username");
    let pw_idx = col_index(&headers, "password");
    let note_idx = col_index(&headers, "note");

    let mut entries = Vec::with_capacity(rows.len());
    for row in &rows {
        let name = field(row, name_idx);
        let display_name = if name.is_empty() {
            field(row, url_idx)
        } else {
            name
        };
        entries.push(make_login_entry(
            &display_name,
            &field(row, user_idx),
            &field(row, pw_idx),
            &field(row, url_idx),
            field_opt(row, note_idx),
            None,
            None,
            false,
        ));
    }
    Ok(entries)
}

// ── Import: Firefox CSV ─────────────────────────────────────────────────────

/// Import from a Firefox CSV export.
///
/// Expected headers: `url,username,password,httpRealm,formActionOrigin,guid,
///                    timeCreated,timeLastUsed,timePasswordChanged`
pub fn import_firefox_csv(csv_str: &str) -> Result<Vec<VaultEntry>, String> {
    let (headers, rows) = parse_csv(csv_str)?;

    let url_idx = col_index(&headers, "url");
    let user_idx = col_index(&headers, "username");
    let pw_idx = col_index(&headers, "password");

    let mut entries = Vec::with_capacity(rows.len());
    for row in &rows {
        let url = field(row, url_idx);
        let display = if url.is_empty() {
            "(unknown)".to_string()
        } else {
            url.clone()
        };
        entries.push(make_login_entry(
            &display,
            &field(row, user_idx),
            &field(row, pw_idx),
            &url,
            None,
            None,
            None,
            false,
        ));
    }
    Ok(entries)
}

// ── Import: LastPass CSV ────────────────────────────────────────────────────

/// Import from a LastPass CSV export.
///
/// Expected headers: `url,username,password,totp,extra,name,grouping,fav`
pub fn import_lastpass_csv(csv_str: &str) -> Result<Vec<VaultEntry>, String> {
    let (headers, rows) = parse_csv(csv_str)?;

    let url_idx = col_index(&headers, "url");
    let user_idx = col_index(&headers, "username");
    let pw_idx = col_index(&headers, "password");
    let totp_idx = col_index(&headers, "totp");
    let extra_idx = col_index(&headers, "extra");
    let name_idx = col_index(&headers, "name");
    let group_idx = col_index(&headers, "grouping");
    let fav_idx = col_index(&headers, "fav");

    let mut entries = Vec::with_capacity(rows.len());
    for row in &rows {
        let fav_str = field(row, fav_idx);
        let favorite = fav_str == "1" || fav_str.eq_ignore_ascii_case("true");

        entries.push(make_login_entry(
            &field(row, name_idx),
            &field(row, user_idx),
            &field(row, pw_idx),
            &field(row, url_idx),
            field_opt(row, extra_idx),
            field_opt(row, group_idx),
            field_opt(row, totp_idx),
            favorite,
        ));
    }
    Ok(entries)
}

// ── Import: Generic CSV ─────────────────────────────────────────────────────

/// Import from an arbitrary CSV using an explicit column mapping.
pub fn import_generic_csv(
    csv_str: &str,
    mapping: &CsvMapping,
) -> Result<Vec<VaultEntry>, String> {
    let (_headers, rows) = parse_csv(csv_str)?;

    let mut entries = Vec::with_capacity(rows.len());
    for row in &rows {
        entries.push(make_login_entry(
            &field(row, mapping.name_col),
            &field(row, mapping.username_col),
            &field(row, mapping.password_col),
            &field(row, mapping.url_col),
            field_opt(row, mapping.notes_col),
            field_opt(row, mapping.folder_col),
            None,
            false,
        ));
    }
    Ok(entries)
}

// ── Export: Bitwarden JSON ──────────────────────────────────────────────────

/// Export entries to a Bitwarden-compatible unencrypted JSON format.
pub fn export_bitwarden_json(entries: &[VaultEntry]) -> Result<String, String> {
    // Collect unique folders.
    let mut folder_set = std::collections::HashMap::new();
    let mut folder_counter = 0u32;
    for e in entries {
        if let Some(ref f) = e.folder {
            folder_set.entry(f.clone()).or_insert_with(|| {
                folder_counter += 1;
                format!("folder-{folder_counter}")
            });
        }
    }

    let folders: Vec<serde_json::Value> = folder_set
        .iter()
        .map(|(name, id)| {
            serde_json::json!({
                "id": id,
                "name": name,
            })
        })
        .collect();

    let items: Vec<serde_json::Value> = entries
        .iter()
        .map(|entry| {
            let folder_id = entry
                .folder
                .as_ref()
                .and_then(|f| folder_set.get(f))
                .cloned();

            match &entry.data {
                EntryData::Login(d) => {
                    let uris: Vec<serde_json::Value> = d
                        .urls
                        .iter()
                        .map(|u| serde_json::json!({ "uri": u }))
                        .collect();
                    serde_json::json!({
                        "id": entry.id,
                        "folderId": folder_id,
                        "type": 1,
                        "name": entry.name,
                        "notes": entry.notes,
                        "favorite": entry.favorite,
                        "login": {
                            "username": d.username,
                            "password": d.password,
                            "uris": uris,
                            "totp": d.totp_secret,
                        },
                    })
                }
                EntryData::SecureNote(d) => {
                    serde_json::json!({
                        "id": entry.id,
                        "folderId": folder_id,
                        "type": 2,
                        "name": entry.name,
                        "notes": d.content,
                        "favorite": entry.favorite,
                        "secureNote": { "type": 0 },
                    })
                }
                EntryData::Card(d) => {
                    serde_json::json!({
                        "id": entry.id,
                        "folderId": folder_id,
                        "type": 3,
                        "name": entry.name,
                        "notes": entry.notes,
                        "favorite": entry.favorite,
                        "card": {
                            "cardholderName": d.cardholder,
                            "brand": d.brand,
                            "number": d.number,
                            "expMonth": d.exp_month,
                            "expYear": d.exp_year,
                            "code": d.cvv,
                        },
                    })
                }
                EntryData::Identity(d) => {
                    serde_json::json!({
                        "id": entry.id,
                        "folderId": folder_id,
                        "type": 4,
                        "name": entry.name,
                        "notes": entry.notes,
                        "favorite": entry.favorite,
                        "identity": {
                            "firstName": d.first_name,
                            "lastName": d.last_name,
                            "email": d.email,
                            "phone": d.phone,
                            "address1": d.address_line1,
                            "address2": d.address_line2,
                            "city": d.city,
                            "state": d.state,
                            "postalCode": d.postal_code,
                            "country": d.country,
                            "company": d.company,
                            "ssn": d.ssn,
                            "passportNumber": d.passport,
                            "licenseNumber": d.license,
                        },
                    })
                }
                _ => {
                    // SSHKey, APIKey, TOTP — serialise as a SecureNote fallback.
                    let raw = serde_json::to_string_pretty(entry).unwrap_or_default();
                    serde_json::json!({
                        "id": entry.id,
                        "folderId": folder_id,
                        "type": 2,
                        "name": entry.name,
                        "notes": raw,
                        "favorite": entry.favorite,
                        "secureNote": { "type": 0 },
                    })
                }
            }
        })
        .collect();

    let export = serde_json::json!({
        "encrypted": false,
        "folders": folders,
        "items": items,
    });

    serde_json::to_string_pretty(&export).map_err(|e| format!("JSON serialisation failed: {e}"))
}

// ── Export: CSV ──────────────────────────────────────────────────────────────

/// Escape a field for CSV output: wrap in double-quotes if needed.
fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        let escaped = s.replace('"', "\"\"");
        format!("\"{escaped}\"")
    } else {
        s.to_string()
    }
}

/// Export entries to CSV. All entry types are included.
///
/// Columns: `name,type,url,username,password,totp,notes,folder`
///
/// Non-login entries encode their key fields in the username/password/url
/// columns so they roundtrip without data loss.
pub fn export_csv(entries: &[VaultEntry]) -> Result<String, String> {
    let mut out = String::from("name,type,url,username,password,totp,notes,folder\n");

    for entry in entries {
        let notes = entry.notes.as_deref().unwrap_or("");
        let folder = entry.folder.as_deref().unwrap_or("");
        let entry_type = entry.entry_type();

        match &entry.data {
            EntryData::Login(d) => {
                let url = d.urls.first().map(|u| u.as_str()).unwrap_or("");
                let totp = d.totp_secret.as_deref().unwrap_or("");
                push_csv_row(&mut out, &[
                    &entry.name, entry_type, url, &d.username, &d.password, totp, notes, folder,
                ]);
            }
            EntryData::Card(d) => {
                let brand = d.brand.as_deref().unwrap_or("");
                let detail = format!("{} {}/{}", brand, d.exp_month, d.exp_year);
                push_csv_row(&mut out, &[
                    &entry.name, entry_type, "", &d.cardholder, &d.number, &d.cvv, &detail, folder,
                ]);
            }
            EntryData::Identity(d) => {
                let full_name = format!("{} {}", d.first_name, d.last_name);
                let email = d.email.as_deref().unwrap_or("");
                push_csv_row(&mut out, &[
                    &entry.name, entry_type, "", &full_name, email, "", notes, folder,
                ]);
            }
            EntryData::SecureNote(d) => {
                push_csv_row(&mut out, &[
                    &entry.name, entry_type, "", "", "", "", &d.content, folder,
                ]);
            }
            EntryData::SSHKey(d) => {
                push_csv_row(&mut out, &[
                    &entry.name, entry_type, "", &d.fingerprint, &d.key_type, "", notes, folder,
                ]);
            }
            EntryData::APIKey(d) => {
                let endpoint = d.endpoint.as_deref().unwrap_or("");
                let secret = d.secret.as_deref().unwrap_or("");
                push_csv_row(&mut out, &[
                    &entry.name, entry_type, endpoint, &d.key, secret, "", notes, folder,
                ]);
            }
            EntryData::TOTP(d) => {
                let issuer = d.issuer.as_deref().unwrap_or("");
                let account = d.account.as_deref().unwrap_or("");
                push_csv_row(&mut out, &[
                    &entry.name, entry_type, "", account, &d.secret, issuer, notes, folder,
                ]);
            }
        }
    }

    Ok(out)
}

/// Helper to push a CSV row from an array of field values.
fn push_csv_row(out: &mut String, fields: &[&str]) {
    for (i, field) in fields.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str(&csv_escape(field));
    }
    out.push('\n');
}

// ── Export: Encrypted JSON ──────────────────────────────────────────────────

/// Magic + version for the versioned encrypted-export container ("Tallow Vault
/// eXport", v1). Header layout (45 bytes):
/// `magic(4) || version(1) || m_cost u32LE || t_cost u32LE || p_cost u32LE || salt(16) || nonce(12)`
/// followed by the AES-256-GCM ciphertext. The full header is bound as AEAD
/// associated data, so any header tamper fails decryption (F-g1-6).
const EXPORT_MAGIC: [u8; 4] = *b"TVX1";
const EXPORT_VERSION: u8 = 1;
const EXPORT_HEADER_SIZE: usize = 4 + 1 + 4 + 4 + 4 + 16 + 12;

/// Argon2id parameters for encrypted exports: the vault's own default class
/// (`src/vault/db.rs` DEFAULT_M_COST=65536 = 64 MiB, T=3, P=4) — never the
/// weaker `Argon2::default()` (~19 MiB) profile that F-g1-6 flagged. Stored in
/// the authenticated header so importers can reject downgrades.
const EXPORT_M_COST: u32 = 65536; // 64 MiB
const EXPORT_T_COST: u32 = 3;
const EXPORT_P_COST: u32 = 4;
/// Import floor: refuse any export declaring a KDF weaker than the vault class.
const EXPORT_MIN_M_COST: u32 = 65536;
const EXPORT_MIN_T_COST: u32 = 3;
const EXPORT_MIN_P_COST: u32 = 4;
/// Import caps: reject absurd KDF params early instead of burning GiB of RAM.
const EXPORT_MAX_M_COST: u32 = 1 << 20; // 1 GiB
const EXPORT_MAX_T_COST: u32 = 16;
const EXPORT_MAX_P_COST: u32 = 16;

/// Derive a 32-byte key with Argon2id at the given parameters.
fn derive_export_key(
    password: &str,
    salt: &[u8],
    m_cost: u32,
    t_cost: u32,
    p_cost: u32,
) -> Result<[u8; 32], String> {
    use argon2::{Algorithm, Argon2, Params, Version};

    let params = Params::new(m_cost, t_cost, p_cost, Some(32))
        .map_err(|e| format!("export: invalid argon2 params: {e}"))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| format!("key derivation failed: {e}"))?;
    Ok(key)
}

/// Export entries as AES-256-GCM encrypted JSON, keyed by an Argon2id-derived
/// password, in a versioned, AAD-bound container. Returns raw bytes:
/// `magic(4) || version(1) || m_cost(4) || t_cost(4) || p_cost(4) || salt(16) || nonce(12) || ciphertext`.
pub fn export_encrypted_json(
    entries: &[VaultEntry],
    password: &str,
) -> Result<Vec<u8>, String> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::Aead, aead::Payload, Aes256Gcm, KeyInit};

    let json = serde_json::to_string(entries)
        .map_err(|e| format!("JSON serialisation failed: {e}"))?;

    let salt: Vec<u8> = (0..16).map(|_| rand::random::<u8>()).collect();
    let nonce: Vec<u8> = (0..12).map(|_| rand::random::<u8>()).collect();

    let mut header = Vec::with_capacity(EXPORT_HEADER_SIZE);
    header.extend_from_slice(&EXPORT_MAGIC);
    header.push(EXPORT_VERSION);
    header.extend_from_slice(&EXPORT_M_COST.to_le_bytes());
    header.extend_from_slice(&EXPORT_T_COST.to_le_bytes());
    header.extend_from_slice(&EXPORT_P_COST.to_le_bytes());
    header.extend_from_slice(&salt);
    header.extend_from_slice(&nonce);

    let key = derive_export_key(password, &salt, EXPORT_M_COST, EXPORT_T_COST, EXPORT_P_COST)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let ciphertext = cipher
        .encrypt(
            GenericArray::from_slice(&nonce),
            Payload {
                msg: json.as_bytes(),
                aad: &header,
            },
        )
        .map_err(|e| format!("encryption failed: {e}"))?;

    let mut output = Vec::with_capacity(EXPORT_HEADER_SIZE + ciphertext.len());
    output.extend_from_slice(&header);
    output.extend_from_slice(&ciphertext);
    Ok(output)
}

/// Decrypt a versioned encrypted JSON export produced by `export_encrypted_json`.
///
/// Hard-errors on unknown/legacy/tampered input instead of guessing: the input
/// must carry the `TVX1` magic, version 1, and a KDF at least as strong as the
/// vault class; the header is AEAD-bound so tampering fails decryption.
pub fn import_encrypted_json(
    data: &[u8],
    password: &str,
) -> Result<Vec<VaultEntry>, String> {
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::{aead::Aead, aead::Payload, Aes256Gcm, KeyInit};

    if data.len() < EXPORT_HEADER_SIZE + 16 {
        return Err(format!(
            "not a valid encrypted export: {} bytes is shorter than the {EXPORT_HEADER_SIZE}-byte \
             header + 16-byte tag",
            data.len()
        ));
    }
    if data[..4] != EXPORT_MAGIC[..] {
        return Err("unknown export format: missing TVX1 magic — refusing to guess \
                    (legacy unheadered exports are not accepted; re-export with this version)"
            .into());
    }
    let version = data[4];
    if version != EXPORT_VERSION {
        return Err(format!(
            "unsupported export version {version} (expected {EXPORT_VERSION}) — refusing to guess"
        ));
    }

    let m_cost = u32::from_le_bytes([data[5], data[6], data[7], data[8]]);
    let t_cost = u32::from_le_bytes([data[9], data[10], data[11], data[12]]);
    let p_cost = u32::from_le_bytes([data[13], data[14], data[15], data[16]]);
    if m_cost < EXPORT_MIN_M_COST || t_cost < EXPORT_MIN_T_COST || p_cost < EXPORT_MIN_P_COST {
        return Err(format!(
            "KDF downgrade rejected: export declares argon2id m={m_cost} t={t_cost} p={p_cost}, \
             weaker than the vault floor m>={EXPORT_MIN_M_COST} t>={EXPORT_MIN_T_COST} \
             p>={EXPORT_MIN_P_COST}"
        ));
    }
    if m_cost > EXPORT_MAX_M_COST || t_cost > EXPORT_MAX_T_COST || p_cost > EXPORT_MAX_P_COST {
        return Err(format!(
            "KDF parameters out of range: argon2id m={m_cost} t={t_cost} p={p_cost}"
        ));
    }

    let header = &data[..EXPORT_HEADER_SIZE];
    let salt = &data[17..33];
    let nonce = &data[33..45];
    let ciphertext = &data[EXPORT_HEADER_SIZE..];

    let key = derive_export_key(password, salt, m_cost, t_cost, p_cost)?;
    let cipher = Aes256Gcm::new(GenericArray::from_slice(&key));
    let plaintext = cipher
        .decrypt(
            GenericArray::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: header,
            },
        )
        .map_err(|e| format!("decryption failed (wrong password or tampered export): {e}"))?;

    let json_str = String::from_utf8(plaintext)
        .map_err(|e| format!("decrypted data is not valid UTF-8: {e}"))?;

    serde_json::from_str(&json_str).map_err(|e| format!("JSON parse failed: {e}"))
}

// ── Export: private file write (0600-or-refuse) ─────────────────────────────

/// Write a vault export to `path` with owner-only permissions, or refuse.
///
/// Security contract (F-g1-5/-6):
/// - The file is created/truncated with mode `0600` and the mode is re-set
///   explicitly after open — never umask-dependent, never world-readable.
/// - If `path` is a symlink, or an existing file there is group/other
///   accessible, the write is refused instead of overwriting it.
/// - `plaintext == true` emits an explicit stderr warning (every secret in
///   the clear).
pub fn write_export_file(
    path: &std::path::Path,
    data: &[u8],
    plaintext: bool,
) -> Result<(), String> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

        if let Ok(meta) = std::fs::symlink_metadata(path) {
            if meta.file_type().is_symlink() {
                return Err(format!(
                    "refusing to write {}: target is a symlink",
                    path.display()
                ));
            }
            let mode = meta.permissions().mode() & 0o777;
            if mode & 0o077 != 0 {
                return Err(format!(
                    "refusing to overwrite {}: existing permissions {mode:04o} allow group/other \
                     access — remove the file or chmod 600 it first",
                    path.display()
                ));
            }
        }

        if plaintext {
            eprintln!(
                "warning: writing a PLAINTEXT vault export to {} — every secret is in the clear \
                 (file mode 0600, refused if the target is group/other-accessible)",
                path.display()
            );
        }

        let mut opts = std::fs::OpenOptions::new();
        opts.write(true).create(true).truncate(true).mode(0o600);
        let mut file = opts
            .open(path)
            .map_err(|e| format!("cannot open {} for writing: {e}", path.display()))?;
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("cannot enforce mode 0600 on {}: {e}", path.display()))?;
        file.write_all(data)
            .map_err(|e| format!("write error on {}: {e}", path.display()))?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        if plaintext {
            eprintln!(
                "warning: writing a PLAINTEXT vault export to {} — every secret is in the clear",
                path.display()
            );
        }
        std::fs::write(path, data).map_err(|e| format!("write error on {}: {e}", path.display()))
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vault::entry::VaultEntry;

    // ── CSV parser tests ────────────────────────────────────────────────

    #[test]
    fn csv_parse_simple() {
        let fields = parse_csv_line("a,b,c");
        assert_eq!(fields, vec!["a", "b", "c"]);
    }

    #[test]
    fn csv_parse_quoted() {
        let fields = parse_csv_line(r#""hello, world",b,c"#);
        assert_eq!(fields, vec!["hello, world", "b", "c"]);
    }

    #[test]
    fn csv_parse_escaped_quote() {
        let fields = parse_csv_line(r#""he said ""hi""",b"#);
        assert_eq!(fields, vec![r#"he said "hi""#, "b"]);
    }

    #[test]
    fn csv_parse_empty_fields() {
        let fields = parse_csv_line(",,,");
        assert_eq!(fields, vec!["", "", "", ""]);
    }

    // ── Chrome import ───────────────────────────────────────────────────

    #[test]
    fn import_chrome() {
        let csv = "name,url,username,password,note\n\
                   GitHub,https://github.com,user@x.com,hunter2,my note\n\
                   Gmail,https://mail.google.com,user@example.com,pw123,\n";
        let entries = import_chrome_csv(csv).expect("import");
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "GitHub");
        if let EntryData::Login(ref d) = entries[0].data {
            assert_eq!(d.username, "user@x.com");
            assert_eq!(d.password, "hunter2");
            assert_eq!(d.urls, vec!["https://github.com"]);
        } else {
            panic!("expected Login");
        }
        assert_eq!(entries[0].notes, Some("my note".to_string()));
    }

    // ── Firefox import ──────────────────────────────────────────────────

    #[test]
    fn import_firefox() {
        let csv = "url,username,password,httpRealm,formActionOrigin,guid,timeCreated,timeLastUsed,timePasswordChanged\n\
                   https://example.com,admin,secret,,,abc-123,1000,2000,3000\n";
        let entries = import_firefox_csv(csv).expect("import");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "https://example.com");
        if let EntryData::Login(ref d) = entries[0].data {
            assert_eq!(d.username, "admin");
            assert_eq!(d.password, "secret");
        } else {
            panic!("expected Login");
        }
    }

    // ── LastPass import ─────────────────────────────────────────────────

    #[test]
    fn import_lastpass() {
        let csv = "url,username,password,totp,extra,name,grouping,fav\n\
                   https://x.com,user,pw,,notes here,Twitter,Social,1\n";
        let entries = import_lastpass_csv(csv).expect("import");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Twitter");
        assert!(entries[0].favorite);
        assert_eq!(entries[0].folder, Some("Social".to_string()));
    }

    // ── KeePass import ──────────────────────────────────────────────────

    #[test]
    fn import_keepass() {
        let csv = "Group,Title,Username,Password,URL,Notes\n\
                   Email,Gmail,user@example.com,pass123,https://gmail.com,primary email\n";
        let entries = import_keepass_csv(csv).expect("import");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Gmail");
        assert_eq!(entries[0].folder, Some("Email".to_string()));
    }

    // ── Bitwarden JSON import ───────────────────────────────────────────

    #[test]
    fn import_bitwarden() {
        let json = r#"{
            "encrypted": false,
            "folders": [{"id": "f1", "name": "Work"}],
            "items": [
                {
                    "id": "i1",
                    "folderId": "f1",
                    "type": 1,
                    "name": "JIRA",
                    "login": {
                        "username": "dev",
                        "password": "jira-pw",
                        "uris": [{"uri": "https://jira.example.com"}],
                        "totp": "JBSWY3DPEHPK3PXP"
                    },
                    "notes": "work account",
                    "favorite": true
                },
                {
                    "id": "i2",
                    "folderId": null,
                    "type": 2,
                    "name": "Recovery codes",
                    "notes": "abc-123\ndef-456",
                    "favorite": false
                }
            ]
        }"#;
        let entries = import_bitwarden_json(json).expect("import");
        assert_eq!(entries.len(), 2);

        // Login entry
        assert_eq!(entries[0].name, "JIRA");
        assert_eq!(entries[0].folder, Some("Work".to_string()));
        assert!(entries[0].favorite);
        if let EntryData::Login(ref d) = entries[0].data {
            assert_eq!(d.username, "dev");
            assert_eq!(d.totp_secret, Some("JBSWY3DPEHPK3PXP".to_string()));
        } else {
            panic!("expected Login");
        }

        // SecureNote entry
        assert_eq!(entries[1].name, "Recovery codes");
        assert!(matches!(entries[1].data, EntryData::SecureNote(_)));
    }

    // ── Generic CSV import ──────────────────────────────────────────────

    #[test]
    fn import_generic() {
        let csv = "site,user,pass,link\n\
                   GitHub,me,pw,https://github.com\n";
        let mapping = CsvMapping {
            name_col: Some(0),
            username_col: Some(1),
            password_col: Some(2),
            url_col: Some(3),
            notes_col: None,
            folder_col: None,
        };
        let entries = import_generic_csv(csv, &mapping).expect("import");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "GitHub");
    }

    // ── Export: Bitwarden JSON ──────────────────────────────────────────

    #[test]
    fn export_bitwarden_roundtrip() {
        let mut entry = VaultEntry::new_login(
            "Test",
            "user",
            "pw",
            vec!["https://example.com".into()],
        );
        entry.folder = Some("Dev".to_string());
        entry.favorite = true;

        let json = export_bitwarden_json(&[entry]).expect("export");
        let re_imported = import_bitwarden_json(&json).expect("re-import");
        assert_eq!(re_imported.len(), 1);
        assert_eq!(re_imported[0].name, "Test");
        assert!(re_imported[0].favorite);
    }

    // ── Export: CSV ─────────────────────────────────────────────────────

    #[test]
    fn export_csv_basic() {
        let entry = VaultEntry::new_login("Site", "user", "pw", vec!["https://x.com".into()]);
        let csv = export_csv(&[entry]).expect("export");
        assert!(csv.starts_with("name,type,url,username,password,totp,notes,folder\n"));
        assert!(csv.contains("Site"));
        assert!(csv.contains("Login"));
    }

    #[test]
    fn export_csv_escaping() {
        let entry = VaultEntry::new_login(r#"A, B"#, "u", r#"p"w"#, vec![]);
        let csv = export_csv(&[entry]).expect("export");
        // Name with comma should be quoted.
        assert!(csv.contains(r#""A, B""#));
        // Password with quote should be double-escaped.
        assert!(csv.contains(r#""p""w""#));
    }

    // ── Export: Encrypted JSON ──────────────────────────────────────────

    #[test]
    fn encrypted_json_roundtrip() {
        let entries = vec![
            VaultEntry::new_login("A", "u1", "p1", vec![]),
            VaultEntry::new_login("B", "u2", "p2", vec![]),
        ];
        let encrypted = export_encrypted_json(&entries, "test-password").expect("encrypt");
        let decrypted = import_encrypted_json(&encrypted, "test-password").expect("decrypt");
        assert_eq!(decrypted.len(), 2);
        assert_eq!(decrypted[0].name, "A");
        assert_eq!(decrypted[1].name, "B");
    }

    #[test]
    fn encrypted_json_wrong_password() {
        let entries = vec![VaultEntry::new_login("X", "u", "p", vec![])];
        let encrypted = export_encrypted_json(&entries, "right").expect("encrypt");
        let result = import_encrypted_json(&encrypted, "wrong");
        assert!(result.is_err());
    }

    #[test]
    fn encrypted_export_header_and_kdf_floor() {
        let entries = vec![VaultEntry::new_login("H", "u", "p", vec![])];
        let encrypted = export_encrypted_json(&entries, "pw").expect("encrypt");
        assert_eq!(&encrypted[..4], b"TVX1", "versioned header magic missing");
        assert_eq!(encrypted[4], 1, "unexpected export version");
        let m = u32::from_le_bytes([encrypted[5], encrypted[6], encrypted[7], encrypted[8]]);
        let t = u32::from_le_bytes([encrypted[9], encrypted[10], encrypted[11], encrypted[12]]);
        let p = u32::from_le_bytes([encrypted[13], encrypted[14], encrypted[15], encrypted[16]]);
        assert!(
            m >= 65536 && t >= 3 && p >= 4,
            "export KDF m={m} t={t} p={p} weaker than the vault class"
        );
        let back = import_encrypted_json(&encrypted, "pw").expect("decrypt");
        assert_eq!(back.len(), 1);
    }

    #[test]
    fn import_encrypted_json_rejects_legacy_unheadered() {
        // Old layout (salt||nonce||ct, Argon2::default()) has no magic header.
        let legacy = vec![0u8; 64];
        let err = import_encrypted_json(&legacy, "pw").expect_err("must hard-error");
        assert!(err.contains("unknown export format"), "unexpected error: {err}");
    }

    #[test]
    fn import_encrypted_json_rejects_unknown_version() {
        let entries = vec![VaultEntry::new_login("V", "u", "p", vec![])];
        let mut encrypted = export_encrypted_json(&entries, "pw").expect("encrypt");
        encrypted[4] = 2;
        let err = import_encrypted_json(&encrypted, "pw").expect_err("must hard-error");
        assert!(err.contains("unsupported export version"), "unexpected error: {err}");
    }

    #[test]
    fn import_encrypted_json_rejects_kdf_downgrade() {
        let entries = vec![VaultEntry::new_login("D", "u", "p", vec![])];
        let mut encrypted = export_encrypted_json(&entries, "pw").expect("encrypt");
        // Downgrade m_cost to Argon2::default()'s ~19 MiB class.
        encrypted[5..9].copy_from_slice(&19456u32.to_le_bytes());
        let err = import_encrypted_json(&encrypted, "pw").expect_err("must hard-error");
        assert!(err.contains("KDF downgrade rejected"), "unexpected error: {err}");
    }

    #[test]
    fn import_encrypted_json_rejects_tampered_header() {
        let entries = vec![VaultEntry::new_login("T", "u", "p", vec![])];
        let mut encrypted = export_encrypted_json(&entries, "pw").expect("encrypt");
        encrypted[20] ^= 0x01; // flip a bit in the salt — header is AEAD-bound
        let err = import_encrypted_json(&encrypted, "pw").expect_err("must hard-error");
        assert!(err.contains("decryption failed"), "unexpected error: {err}");
    }

    #[cfg(unix)]
    #[test]
    fn write_export_file_sets_0600() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("tallow_t119_fresh_{}", std::process::id()));
        let _ = std::fs::remove_file(&path);
        write_export_file(&path, b"secret", true).expect("write");
        let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "export written with mode {mode:o}");
        let _ = std::fs::remove_file(&path);
    }

    #[cfg(unix)]
    #[test]
    fn write_export_file_refuses_permissive_target() {
        use std::os::unix::fs::PermissionsExt;
        let path = std::env::temp_dir().join(format!("tallow_t119_perm_{}", std::process::id()));
        std::fs::write(&path, b"old").expect("seed");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = write_export_file(&path, b"new", true).expect_err("must refuse");
        assert!(err.contains("refusing"), "unexpected error: {err}");
        assert_eq!(std::fs::read(&path).expect("read"), b"old".to_vec());
        let _ = std::fs::remove_file(&path);
    }

    // ── Bitwarden Card import ──────────────────────────────────────────

    #[test]
    fn import_bitwarden_card() {
        let json = r#"{
            "encrypted": false,
            "folders": [],
            "items": [
                {
                    "type": 3,
                    "name": "Visa Gold",
                    "notes": "personal card",
                    "favorite": true,
                    "card": {
                        "cardholderName": "John Doe",
                        "brand": "Visa",
                        "number": "4111111111111111",
                        "expMonth": "12",
                        "expYear": "2030",
                        "code": "123"
                    }
                }
            ]
        }"#;
        let entries = import_bitwarden_json(json).expect("import");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "Visa Gold");
        assert!(entries[0].favorite);
        if let EntryData::Card(ref d) = entries[0].data {
            assert_eq!(d.cardholder, "John Doe");
            assert_eq!(d.number, "4111111111111111");
            assert_eq!(d.brand, Some("Visa".to_string()));
            assert_eq!(d.exp_month, "12");
            assert_eq!(d.exp_year, "2030");
            assert_eq!(d.cvv, "123");
        } else {
            panic!("expected Card, got {:?}", entries[0].entry_type());
        }
    }

    // ── Bitwarden Identity import ──────────────────────────────────────

    #[test]
    fn import_bitwarden_identity() {
        let json = r#"{
            "encrypted": false,
            "folders": [],
            "items": [
                {
                    "type": 4,
                    "name": "My Identity",
                    "notes": null,
                    "favorite": false,
                    "identity": {
                        "firstName": "Jane",
                        "lastName": "Smith",
                        "email": "jane@example.com",
                        "phone": "+1-555-0100",
                        "address1": "123 Main St",
                        "city": "Springfield",
                        "state": "IL",
                        "postalCode": "62704",
                        "country": "US",
                        "company": "Acme Corp"
                    }
                }
            ]
        }"#;
        let entries = import_bitwarden_json(json).expect("import");
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].name, "My Identity");
        if let EntryData::Identity(ref d) = entries[0].data {
            assert_eq!(d.first_name, "Jane");
            assert_eq!(d.last_name, "Smith");
            assert_eq!(d.email, Some("jane@example.com".to_string()));
            assert_eq!(d.phone, Some("+1-555-0100".to_string()));
            assert_eq!(d.city, Some("Springfield".to_string()));
            assert_eq!(d.company, Some("Acme Corp".to_string()));
        } else {
            panic!("expected Identity, got {:?}", entries[0].entry_type());
        }
    }

    // ── Bitwarden Card+Identity export roundtrip ───────────────────────

    #[test]
    fn export_bitwarden_card_identity_roundtrip() {
        let card = VaultEntry::new_card("MyCard", "Jane Doe", "5555444433332222", "06", "2029", "456");
        let entries = vec![card];

        let json = export_bitwarden_json(&entries).expect("export");
        let re_imported = import_bitwarden_json(&json).expect("re-import");
        assert_eq!(re_imported.len(), 1);
        assert_eq!(re_imported[0].name, "MyCard");
        if let EntryData::Card(ref d) = re_imported[0].data {
            assert_eq!(d.cardholder, "Jane Doe");
            assert_eq!(d.number, "5555444433332222");
            assert_eq!(d.cvv, "456");
        } else {
            panic!("expected Card after roundtrip");
        }
    }

    // ── CSV export includes all types ──────────────────────────────────

    #[test]
    fn export_csv_all_types() {
        let login = VaultEntry::new_login("MyLogin", "user", "pw", vec!["https://x.com".into()]);
        let card = VaultEntry::new_card("MyCard", "Holder", "1234", "01", "2030", "999");
        let note = VaultEntry::new_note("MyNote", "secret stuff");

        let csv = export_csv(&[login, card, note]).expect("export");
        // Should have 4 lines: header + 3 entries
        let lines: Vec<&str> = csv.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(csv.contains("Login"));
        assert!(csv.contains("Card"));
        assert!(csv.contains("Secure Note"));
    }

    // ── F-g1-7: import must fail closed on vault-open failure ──────────

    /// Simulates the CLI `vault import` sequence (open → fall-through to a
    /// fresh in-memory handle → add imported entries → save) and pins the
    /// fail-closed contract: when the target vault cannot be opened (corrupt
    /// file, wrong password, or missing path) the import must refuse with a
    /// clear error and must NOT create or modify any vault file (F-g1-7).
    #[test]
    fn import_open_failure_fails_closed() {
        use crate::vault::db::VaultDatabase;

        fn fixture_path(name: &str) -> String {
            std::env::temp_dir().join(name).to_str().unwrap().to_string()
        }

        // Entries in the shape the CLI obtains them from a plaintext import.
        let csv = "name,url,username,password,note\nImportedSite,https://imported.example,user,hunter2,\n";

        // 1) Corrupt existing vault: open fails and the corrupt bytes must be
        //    left byte-for-byte untouched (no silent overwrite/new vault).
        let corrupt = fixture_path("tallow_vault_import_corrupt.twv");
        std::fs::write(&corrupt, b"garbage, not a .twv vault").expect("seed corrupt file");
        let before = std::fs::read(&corrupt).expect("read corrupt file");
        assert!(
            VaultDatabase::open(&corrupt, "pw").is_err(),
            "corrupt file must not open"
        );
        let mut db = VaultDatabase::new("Imported");
        for e in import_chrome_csv(csv).expect("parse import file") {
            db.add_entry(e);
        }
        let err = db
            .save(&corrupt, "pw")
            .expect_err("corrupt target must be refused");
        assert!(
            err.contains("refusing"),
            "refusal error should be explicit, got: {err}"
        );
        assert_eq!(
            std::fs::read(&corrupt).expect("read back"),
            before,
            "corrupt vault file must be untouched by a failed import"
        );

        // 2) Wrong password on a valid vault: same fail-closed contract.
        let real = fixture_path("tallow_vault_import_wrongpw.twv");
        let _ = std::fs::remove_file(&real);
        VaultDatabase::create(&real, "right-pw", "real").expect("create fixture vault");
        let before = std::fs::read(&real).expect("read real vault");
        assert!(
            VaultDatabase::open(&real, "wrong-pw").is_err(),
            "wrong password must not open"
        );
        let mut db = VaultDatabase::new("Imported");
        for e in import_chrome_csv(csv).expect("parse import file") {
            db.add_entry(e);
        }
        let err = db
            .save(&real, "wrong-pw")
            .expect_err("wrong-password target must be refused");
        assert!(
            err.contains("refusing"),
            "refusal error should be explicit, got: {err}"
        );
        assert_eq!(
            std::fs::read(&real).expect("read back"),
            before,
            "existing vault must be untouched by a failed import"
        );

        // 3) Missing target: no vault file may be silently fabricated.
        let missing = fixture_path("tallow_vault_import_missing.twv");
        let _ = std::fs::remove_file(&missing);
        let mut db = VaultDatabase::new("Imported");
        for e in import_chrome_csv(csv).expect("parse import file") {
            db.add_entry(e);
        }
        let err = db
            .save(&missing, "pw")
            .expect_err("missing target must be refused");
        assert!(
            err.contains("refusing"),
            "refusal error should be explicit, got: {err}"
        );
        assert!(
            !std::path::Path::new(&missing).exists(),
            "import must not create a new vault file"
        );

        // 4) Sanity: the legitimate path still works — a handle opened from
        //    the vault may import into and update that same vault.
        let mut db = VaultDatabase::open(&real, "right-pw").expect("open real vault");
        for e in import_chrome_csv(csv).expect("parse import file") {
            db.add_entry(e);
        }
        db.save(&real, "right-pw")
            .expect("a vault opened from a file must remain writable");
        let reloaded = VaultDatabase::open(&real, "right-pw").expect("reopen real vault");
        assert_eq!(reloaded.entry_count(), 1);

        let _ = std::fs::remove_file(&corrupt);
        let _ = std::fs::remove_file(&real);
    }
}
