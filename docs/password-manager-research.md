# Password Manager Deep Research: Bitwarden, KeePassXC, Passbolt
> Research Date: 2026-03-20
> Scope: Complete feature inventory, architecture, protocols, storage formats

---

## TABLE OF CONTENTS

1. [Bitwarden — Complete Analysis](#1-bitwarden)
2. [KeePassXC — Complete Analysis](#2-keepassxc)
3. [Passbolt — Complete Analysis](#3-passbolt)
4. [Master Feature List — Complete Universe](#4-master-feature-list)

---

# 1. BITWARDEN

## 1.1 Overview
- **Type**: Client-server, cloud-hosted or self-hosted
- **License**: Open source — Server: AGPL-3.0, Clients: GPL-3.0
- **Source**: All code on GitHub (bitwarden org)
- **Written in**: C# (.NET) server, TypeScript/Angular clients
- **Pricing**: Free / Premium ($1.65/mo) / Families ($3.99/mo) / Teams / Enterprise
- **Compliance**: SOC2 Type II, SOC3, ISO 27001
- **Zero-knowledge**: Yes — all encryption/decryption client-side

## 1.2 Encryption & Cryptography

### Symmetric Encryption
- **Algorithm**: AES-256-CBC + HMAC-SHA256 (AES256-CBC-HMAC-SHA256)
- All vault data encrypted with this scheme
- Per-cipher unique 64-byte Cipher Keys (random, per vault item)
- Cipher Keys encrypted with User Symmetric Key (personal) or Organization Symmetric Key (shared)

### Asymmetric Encryption
- **Algorithm**: RSA with OAEP padding
- Used for: organization sharing, emergency access, account recovery, device login
- RSA keypair generated at account creation
- Public key stored on server, private key encrypted with User Symmetric Key

### Key Derivation
- **PBKDF2-SHA256**: Default 600,000 iterations (700,000 total with additional server hash)
  - FIPS-140 compliant
  - Salt: user's email address
- **Argon2id**: Alternative KDF option
  - Default: 64 MiB memory, 3 iterations, 4 threads (parallelism)
  - Uses BLAKE2b internally
- **HKDF** (RFC 5869): For deriving keys from non-password material (other keys, CSPRNG material)

### Key Hierarchy
1. Master Password + Email (salt) -> PBKDF2/Argon2id -> **Master Key** (256-bit)
2. Master Key -> HKDF -> **Stretched Master Key** (512-bit)
3. CSPRNG -> **Generated Symmetric Key** (512-bit) + IV (128-bit)
4. Stretched Master Key encrypts Generated Symmetric Key -> **Protected Symmetric Key** (stored on server)
5. Login: re-derive Stretched Master Key -> decrypt Protected Symmetric Key -> **User Symmetric Key** (used for vault)
6. Each vault item: CSPRNG -> unique **Cipher Key** (64 bytes), encrypted with User/Org Symmetric Key
7. RSA keypair: private key encrypted with User Symmetric Key

### Organization Sharing Crypto
1. Org creation: CSPRNG -> **Organization Symmetric Key**
2. Org Symmetric Key encrypted with creator's RSA Public Key -> stored on server
3. New member onboarding: existing member encrypts Org Symmetric Key with new member's RSA Public Key
4. Each member decrypts Org Symmetric Key with their own RSA Private Key
5. Shared items use Org Symmetric Key instead of User Symmetric Key

### Transit & At-Rest
- **In transit**: TLS/SSL with X.509 certs, HSTS enforced
- **At rest**: Azure Transparent Data Encryption (TDE) + column-level encryption on sensitive fields

## 1.3 Storage Format
- Server-side: Encrypted JSON blobs in MSSQL database
- Export formats: CSV, JSON, Encrypted JSON (.json), ZIP
- Import: 50+ formats (see import section)
- No local-only database file format (always syncs to server)

## 1.4 Architecture
- **Server**: .NET/C# on Azure Kubernetes Service (AKS)
- **Database**: Microsoft SQL Server (MSSQL)
- **CDN**: WAF, DDoS protection, caching
- **Push notifications**: SignalR
- **Self-hosted**: Docker containers (Linux/Windows), Helm charts (AWS EKS, Azure AKS, OpenShift)
- **Offline**: Docker offline deployment available

## 1.5 All Features

### Vault Item Types
- **Logins**: Username, password, TOTP, URIs (multiple), passkeys, custom fields, notes, attachments
- **Cards**: Cardholder name, number, brand, expiration, security code
- **Identities**: Name, address, phone, email, SSN, passport, license, company, etc.
- **Secure Notes**: Freeform encrypted text
- **SSH Keys**: Key name, private key, public key, fingerprint (Ed25519 generation)

### Item Management
- Folders (personal organization)
- Collections (shared organization)
- Favorites
- Archive (hide from search/autofill, retain in exports)
- Delete to 30-day trash, then permanent
- Clone/duplicate items
- Custom fields: Text, Hidden, Boolean, Linked
- File attachments (5GB personal, expandable)
- Master password re-prompt on sensitive items
- Item history / password history

### Autofill
- Browser extension autofill (inline menu, keyboard shortcut, context menu, page load)
- Mobile autofill (iOS, Android native)
- Passkey autofill (FIDO2 WebAuthn)
- Card autofill (browser, Android)
- Identity autofill (browser, Android)
- Custom field autofill
- Basic HTTP authentication autofill
- URI match detection: Base domain, Host, Starts with, Regular expression, Exact, Never
- Domain exclusion lists
- Autosave prompts for new credentials

### Password & Username Generator
- **Passwords**: Length, uppercase, lowercase, numbers, special chars, avoid ambiguous chars
- **Passphrases**: Word count, separator, capitalize, include number
- **Usernames**:
  - Plus-addressed email (alice+random@domain.com)
  - Catch-all email (random@yourdomain.com)
  - Forwarded email alias: SimpleLogin, AnonAddy, Firefox Relay, Fastmail, Forward Email, DuckDuckGo
  - Random word (with optional capitalize + number)
- Generator history

### TOTP / Integrated Authenticator
- Store TOTP secrets in vault items (Premium)
- Generate 6-digit TOTP codes
- Auto-copy TOTP on autofill
- Apple Watch TOTP display
- Standalone Bitwarden Authenticator app (separate product)

### Passkeys
- Store FIDO2/WebAuthn passkeys in vault items
- Autofill passkeys during login
- Create passkeys via browser extension prompt
- iOS 17.0+ and Android 14.0+ support
- One passkey per login item
- Export/import passkeys in .json
- Use passkeys to log into Bitwarden itself

### SSH Agent
- Store SSH keys in vault (Ed25519 generation)
- SSH agent functionality (desktop app)
- Agent forwarding
- Git commit signing
- OpenSSH and PKCS#8 import
- Windows (replaces native OpenSSH agent), macOS, Linux
- Authorization controls: always, never, until vault locks

### Bitwarden Send
- **Text Send**: Up to 1,000 characters, end-to-end encrypted
- **File Send**: Up to 500 MB (100 MB on mobile)
- Password protection
- Email verification for specific recipients
- Hide sender email
- Hide text (toggle visibility)
- Expiration date (up to 31 days)
- Maximum access count
- Deletion date
- Manual disable/enable
- Status tracking icons

### Emergency Access (Premium)
- Designate unlimited trusted contacts
- Two permission levels: View (read-only) or Takeover (new master password)
- Configurable wait time
- Grantor approval/rejection
- Auto-grant after wait time expires
- Crypto: grantee's RSA Public Key encrypts grantor's User Symmetric Key

### Vault Health Reports (Premium/Org)
- Exposed passwords (Have I Been Pwned integration)
- Reused passwords
- Weak passwords
- Unsecured websites (HTTP URLs)
- Inactive two-step login
- Data breach report (email check)
- All analysis done locally (zero-knowledge preserved)

### Access Intelligence (Enterprise)
- Application-level credential risk visibility
- Critical application designation
- At-risk credential identification (weak, exposed, reused)
- Targeted password change request notifications
- Remediation progress tracking
- Member risk dashboard

### Two-Step Login (2FA for Bitwarden itself)
- Authenticator app (TOTP)
- Email codes
- Duo Security
- YubiKey OTP (up to 5 keys free, 10 premium)
- FIDO2 WebAuthn (hardware keys)
- Passkeys for login
- Recovery codes

### Sharing & Organizations
- Free org: 2 users, 2 collections
- Families: 6 users, unlimited collections
- Teams: Unlimited users, unlimited collections
- Enterprise: All Teams features + SSO + policies
- Collections with granular permissions (Can manage, Can edit, Can view, Can view except passwords)
- Groups (bulk permission assignment)
- Sponsored Families for enterprise members

### Enterprise Features
- **SSO**: SAML 2.0, OIDC
  - Providers: ADFS, Auth0, AWS, Cloudflare Zero Trust, Duo, Google, JumpCloud, Keycloak, Entra ID, Okta, OneLogin, Ping Identity
  - Trusted devices (device-based decryption without master password)
  - Key Connector (org-managed encryption keys)
  - JIT provisioning
- **Directory Sync**: Active Directory, LDAP, Entra ID, Google Workspace, Okta, OneLogin
- **SCIM Provisioning**: JumpCloud, Entra ID, Okta, OneLogin, Ping Identity
- **Enterprise Policies** (18 policies):
  1. Single Organization
  2. Enforce Organization Data Ownership
  3. Master Password Requirements
  4. Account Recovery Administration
  5. Require SSO Authentication
  6. Automatic Login with SSO
  7. Require Two-Step Login
  8. Block Account Creation for Claimed Domains
  9. Session Timeout
  10. Remove Unlock with PIN
  11. Password Generator minimums
  12. Default URI Match Detection
  13. Activate Autofill
  14. Send Options
  15. Remove Send
  16. Remove Card Item Type
  17. Remove Free Families Sponsorship
  18. Remove Export
- **Event Logs**: 60+ event types, indefinite retention, CSV export
- **SIEM Integrations**: Elastic, Microsoft Sentinel, Panther, Rapid7, Splunk, Sumo Logic, Huntress
- **Claimed Domains**: Prevent outside account creation
- **Account Recovery**: Admin-initiated master password reset
- **Onboarding Workflows**: Guided setup for new members

### Secrets Manager (Separate Product)
- Projects (logical grouping of secrets)
- Secrets (key-value pairs, API keys, tokens, etc.)
- Machine accounts (non-human service identities)
- Access tokens
- SDK (multiple languages)
- CLI for secret injection
- Integrations: Ansible, GitHub Actions, GitLab CI/CD, Jenkins, Kubernetes Operator, Terraform
- End-to-end encrypted, zero-knowledge

### Client Applications
- **Web vault** (Angular)
- **Browser extensions**: Chrome, Edge, Firefox, Safari, Brave, Opera, Vivaldi, Tor Browser, DuckDuckGo (macOS)
- **Desktop apps**: Windows, macOS, Linux (Electron)
- **Mobile apps**: iOS, Android
- **CLI**: Cross-platform Node.js
- **Apple Watch**: TOTP display

### CLI Capabilities
- login (email/password, API key, SSO)
- unlock / lock / logout
- list (items, folders, collections, organizations, org-collections, org-members)
- get (item, username, password, uri, totp, exposed, attachment, folder, collection, org, template, fingerprint)
- create / edit / delete / restore
- move (share to org)
- send / receive (Send feature)
- import / export
- generate (password/passphrase)
- encode (base64 for JSON piping)
- config (server URL, service URLs)
- status
- update
- serve (local REST API server on port 8087)
- completion (shell completions)
- confirm (org member)
- device-approval (list, approve, approve-all, deny)

### APIs
- **Public API**: RESTful JSON API for org management (members, collections, groups, events, policies)
- **Vault Management API**: Local REST API via `bw serve` (mirrors CLI capabilities)
- **SDK**: For building integrations (Secrets Manager focus)

### Import Formats (50+)
1Password (1pif, 1pux, csv), Ascendo DataVault, Avast (csv, json), Avira, BlackBerry, Blur, Brave, Buttercup, Chrome, Clipperz, Codebook, Dashlane (json, csv), Edge, Encryptr, Enpass (csv, json), F-Secure KEY, Firefox, GNOME Seahorse, Kaspersky, KeePass 2 (xml), KeePassX (csv), Keeper, LastPass, LogMeOnce, Meldium, mSecure, Myki, Netwrix, Nordpass, Opera, Padlock, Passbolt, PassKeep, Passky, Passman, Passpack, Password Agent, Password Boss, Password Dragon, Password Depot, Password Safe, PasswordWallet, PasswordXP, ProtonPass, Psono, RememBear, RoboForm, Safari, SafeInCloud, SaferPass, SecureSafe, SplashID, Sticky Password, True Key, Universal Password Manager, Vivaldi, Yoti, Zoho Vault, Custom CSV/JSON

### Export Formats
- CSV, JSON, Encrypted JSON, ZIP (with attachments)
- Organization exports (admin)
- Personal vault exports

### Deployment Options
- **Cloud**: US, EU server regions
- **Self-hosted Docker**: Linux standard, Linux manual, Linux offline, Windows standard, Windows offline, Lite
- **Self-hosted Helm/K8s**: AWS EKS, Azure AKS, OpenShift, rawManifest
- External MSSQL database support
- SMTP configuration (required for invitations/notifications)
- Let's Encrypt or custom SSL certificates
- Custom HTTP/HTTPS ports
- Kerberos integration
- Push relay configuration
- System Administrator Portal

### Other Features
- Keyboard shortcuts
- Localization / multi-language support
- Themes (light, dark, system)
- Offline vault access (cached)
- Account fingerprint phrase (verify identity)
- PIN unlock
- Biometric unlock (fingerprint, Face ID)
- Vault timeout settings (custom duration)
- Clipboard clearing (configurable)
- Firefox private window support
- Provider Portal (MSP management)

---

# 2. KEEPASSXC

## 2.1 Overview
- **Type**: Local-only, offline password database
- **License**: GPL-2.0 or GPL-3.0
- **Source**: GitHub (keepassxreboot/keepassxc)
- **Written in**: C++ (Qt framework)
- **Pricing**: Free, no paid tiers
- **Platforms**: Windows, macOS, Linux
- **No server component**: Database is a local file, user manages sync

## 2.2 Encryption & Cryptography

### Database Encryption (KDBX format)
- **AES-256-CBC**: Default block cipher (256-bit key)
- **ChaCha20**: Alternative stream cipher (256-bit key)
- **Twofish**: Alternative block cipher (256-bit key)
- All three are selectable per-database

### Key Derivation Functions
- **Argon2d**: Modern, memory-hard KDF (recommended)
  - Configurable: iterations, memory, parallelism
  - Resistant to GPU/ASIC attacks
- **Argon2id**: Hybrid mode (memory-hard + side-channel resistant)
- **AES-KDF**: Legacy KDF for backward compatibility with KeePass 2.x
  - Configurable iteration count

### Key Composition
- **Master password** (primary)
- **Key file**: Any file as second factor (can be generated or user-supplied)
- **Hardware key**: YubiKey or OnlyKey (HMAC-SHA1 Challenge-Response)
- Composite key = combination of any/all of the above

### Internal Integrity
- HMAC-SHA256 for block-level integrity verification (KDBX 4)
- SHA256 for header integrity (KDBX 3.1)

## 2.3 Storage Format
- **KDBX 4.x**: Current default format
  - Header: cipher ID, compression, KDF params, public custom data
  - Inner header: inner cipher, protected stream key
  - Payload: XML encrypted with chosen cipher
  - HMAC-SHA256 integrity on every block
- **KDBX 3.1**: Legacy format (still readable/writable)
  - SHA256 header hash
  - Salsa20 inner stream cipher for in-memory protection
- **KDBX 2.x**: Can open and auto-upgrade
- **KDB** (KeePass 1.x): Import only

### Import Formats
- CSV (generic, with field mapping)
- KeePass 1.x (.kdb)
- KeePass 2.x (.kdbx)
- 1Password (OPVault)
- Bitwarden (JSON)
- Other CSV formats with manual mapping

### Export Formats
- KDBX (any supported version)
- CSV
- HTML (for printing)
- XML (KeePass 2.x format)

## 2.4 Architecture
- **Pure local application**: No server, no cloud, no account
- **Single file database**: One .kdbx file per database
- **Multiple databases**: Tabbed interface for simultaneous access
- **Sync**: User responsibility — use Dropbox, Google Drive, Nextcloud, Syncthing, OneDrive, etc.
- **No networking** by default (can compile without any networking code via CMake flag)
- **Optional networking**: Favicon downloads, HIBP integration, browser extension communication

## 2.5 All Features

### Entry Management
- Standard fields: Title, Username, Password, URL, Notes
- Custom string fields (unlimited)
- Custom attributes
- File attachments (embedded in database)
- Entry icons (built-in + custom)
- Entry colors
- Entry expiration dates with notifications
- Entry history (automatic tracking of all changes)
- Entry cross-references (reference fields from other entries)
- Entry placeholders (dynamic field substitution: {USERNAME}, {PASSWORD}, {URL}, {TITLE}, etc.)
- Tags
- Groups (hierarchical tree structure, unlimited nesting)
- Recycle Bin (soft delete)
- Entry cloning

### TOTP Support
- Store TOTP secrets (RFC 6238)
- Generate TOTP codes in-app
- TOTP display in entry list
- Steam Guard TOTP support
- Custom digits (6, 7, 8)
- Custom period (30s, 60s)
- SHA-1, SHA-256, SHA-512 TOTP algorithms

### Password Generator
- **Character-based passwords**:
  - Length (any)
  - Character sets: upper, lower, digits, special, extended ASCII
  - Custom character exclusions
  - Avoid ambiguous characters (1/l, 0/O)
  - Ensure characters from each selected set
- **Passphrases (Diceware)**:
  - Configurable word count
  - Custom word lists
  - Custom separator
  - Word capitalization options
- Password strength estimation (zxcvbn-based)
- Password entropy display

### Browser Integration (KeePassXC-Browser)
- Extension for: Firefox, Chrome, Chromium, Vivaldi, Brave, Edge, Tor Browser
- Credential autofill (matched by URL)
- Auto-submit forms (optional)
- Credential save/update prompts
- Password generator from browser
- Custom field filling (multi-page login forms)
- HTTP Basic Auth support
- Site-specific settings
- Multiple URL matching
- String field filling
- Best-match credential selection
- Keyboard shortcuts
- Context menu integration

### Passkey Support (WebAuthn/FIDO2)
- Create and store passkeys
- Use passkeys for website authentication
- Browser extension integration
- Discoverable credentials

### Auto-Type
- Global hotkey triggers auto-type
- Per-entry custom sequences
- Window title matching (regex support)
- Placeholders: {USERNAME}, {PASSWORD}, {TOTP}, {DELAY}, {CLEARFIELD}, {ENTER}, etc.
- Multi-field sequences
- Obfuscation mode (two-channel auto-type to defeat keyloggers)
- Platform support: Windows, macOS, Linux (X11 only — no Wayland)

### SSH Agent Integration
- Store SSH keys in database entries
- Automatic key loading/unloading on database lock/unlock
- Supported key types: RSA, DSA, ECDSA, Ed25519
- Encrypted key support
- Windows: Pageant and Win32 OpenSSH agent
- Linux/macOS: Standard ssh-agent
- Key generation within KeePassXC
- Agent key lifetime configuration
- Require confirmation before use

### Secret Service Integration (Linux)
- Freedesktop.org Secret Service D-Bus API
- Replace GNOME Keyring / KDE Wallet
- Expose specific groups as secret service collections
- Other applications can query credentials through D-Bus

### KeeShare (Database Sharing)
- Share specific groups with other users
- Export shared groups as separate databases
- Import shared groups from other databases
- Signed shares (verify authenticity)
- Unsigned shares (trust-based)
- One-way sync (import only or export only)
- Two-way sync
- Conflict resolution

### Database Maintenance
- Database integrity check
- Compact database
- Purge unused custom icons
- Entry deduplication
- Merge databases (from file or URL)
- Database repair

### CLI (keepassxc-cli)
- `add` — Add new entry
- `analyze` — Analyze passwords for weakness
- `attachment-export` — Export attachment from entry
- `attachment-import` — Import attachment into entry
- `attachment-rm` — Remove attachment from entry
- `clip` — Copy password/attribute to clipboard
- `close` — Close database
- `db-create` — Create new database
- `db-edit` — Edit database settings
- `db-info` — Show database information
- `diceware` — Generate diceware passphrase
- `estimate` — Estimate password entropy
- `export` — Export database to CSV/XML
- `generate` — Generate random password
- `help` — Show help
- `import` — Import from CSV/XML
- `ls` — List entries in group
- `merge` — Merge two databases
- `mkdir` — Create new group
- `mv` — Move entry to different group
- `open` — Open database
- `rm` — Remove entry
- `search` — Search entries
- `show` — Show entry details
- Supports: key file, YubiKey slot, quiet mode, output formatting

### Security Features
- Memory protection (sensitive data in secure memory)
- Clipboard auto-clear (configurable timeout, default 10-20 seconds)
- Auto-lock on inactivity (configurable)
- Auto-lock on screen lock
- Auto-lock on minimize
- Auto-lock on system sleep
- Lock databases on screensaver
- Screenshot prevention (hide window from screen capture)
- Secure desktop for auto-type (Windows)
- Clear search on database lock
- Hide passwords by default (dots)
- Favicon download over HTTPS only
- HIBP password check (offline or online)
- Database backup before save (configurable path with placeholders)
- Yubikey/hardware key backup procedures

### Application Features
- Tabbed interface (multiple databases)
- System tray integration
- Dark / Light / System theme
- Toolbar customization
- Column customization in entry list
- Keyboard shortcuts (customizable)
- Quick Unlock (after initial full unlock)
- Minimize to tray
- Start minimized
- Single instance mode
- Portable mode
- Entry preview panel
- Group filter sidebar
- Advanced search (regex, field-specific)
- Database auto-open on startup
- Check for updates
- Browser integration toggle
- Proxy configuration
- Environment variable configuration

### Platform-Specific
- **Windows**: Installer, Portable ZIP, Chocolatey, Winget, MSI
- **macOS**: DMG, Homebrew
- **Linux**: AppImage, Snap, Flatpak, distro packages (apt, dnf, pacman, etc.)
- **No mobile app**: Recommends third-party KDBX-compatible apps
  - Android: KeePassDX, KeePass2Android
  - iOS: Strongbox, KeePassium

### What KeePassXC Does NOT Have
- No server component
- No built-in cloud sync
- No sharing (beyond KeeShare file-based)
- No organizational management
- No centralized admin
- No enterprise policies
- No SSO
- No SCIM/LDAP
- No audit logs (beyond entry history)
- No web vault
- No Send/ephemeral sharing
- No email notifications

---

# 3. PASSBOLT

## 3.1 Overview
- **Type**: Client-server, self-hosted or cloud-hosted (team-focused)
- **License**: AGPL-3.0 (server + browser extension)
- **Source**: GitHub (passbolt org, 5.8K stars)
- **Written in**: PHP (CakePHP 5) server, JavaScript (browser extension), Go (CLI)
- **Pricing**: Community (free, unlimited users) / Pro ($4.90/user/mo, min 10) / Enterprise (custom)
- **Cloud**: Business / Enterprise tiers
- **HQ**: Luxembourg (EU privacy jurisdiction)
- **Compliance**: SOC2 Type II (2021+), GCP certifications (ISO 27001, 27017, 27018, 27701, SOC 1/2/3, PCI DSS)

## 3.2 Encryption & Cryptography

### Core Model: OpenPGP End-to-End Encryption
- **Standard**: OpenPGP (RFC 4880 / RFC 9580)
- **Implementation**: GnuPG (server-side), OpenPGP.js (browser extension)
- **Key type**: RSA (typically 2048-bit or 4096-bit keys)
- **Per-user encryption**: Each secret encrypted individually for EVERY user who has access
- When a password is shared with 10 users, 10 separate encrypted copies exist (one per user's public key)

### Key Management
- Users generate or import their own OpenPGP keypair during account setup
- Private key stored client-side only (browser extension local storage or encrypted export)
- Private key NEVER sent to server in cleartext
- Private key can be exported encrypted (with user consent)
- Public keys exchanged via server for sharing

### Authentication: GpgAuth Protocol
- Challenge-response authentication (not password-hash based)
- Server sends challenge encrypted with user's public key -> user decrypts with private key -> proves possession
- User sends challenge encrypted with server's public key -> server decrypts -> proves server identity
- Mutual authentication (both client and server verified)
- Resistant to replay attacks (unique challenges per login)
- Additional factors: passphrase (knowledge) + private key (possession)

### Signing
- All secrets cryptographically signed by creator
- Signature verification proves authenticity and integrity
- Tamper detection

### At-Rest Encryption
- Cloud: AES-256 at rest (GCP managed)
- Transit: TLS

### Key Differences from Bitwarden
- OpenPGP (RSA) vs AES+RSA hybrid
- Per-secret, per-user encryption vs shared symmetric key
- No master key hierarchy — each user's PGP key IS the key
- No key derivation from password (passphrase protects PGP private key directly)

## 3.3 Storage Format
- **Server**: MySQL/MariaDB (or PostgreSQL) relational database
- Encrypted secrets stored as OpenPGP-encrypted text blobs
- Metadata stored separately (can be encrypted — recent feature)
- **Import**: CSV, KDBX (KeePass)
- **Export**: CSV, KDBX (KeePass)

## 3.4 Architecture
- **Server**: PHP (CakePHP 5) REST API
- **Database**: MySQL / MariaDB (PostgreSQL also supported)
- **Email**: SMTP required for notifications and invitations
- **GnuPG**: Required on server for crypto operations
- **NTP**: Required for GPG timestamp validation
- **Deployment**: Docker, native Linux packages (Ubuntu, Debian, RHEL, CentOS, Rocky, Alma, Oracle, Fedora, openSUSE), Raspberry Pi, cloud VMs
- **Cloud**: GCP (Belgium/Germany for Business, Luxembourg sovereign DC for Enterprise)
- **No third-party dependencies**: Fully standalone, works air-gapped behind firewalls

## 3.5 All Features

### Community Edition (Free, AGPL-3.0)

#### Password Management
- Create, view, edit, delete passwords
- Password description / notes
- Custom fields (text, textarea)
- Encrypted notes (standalone)
- TOTP management (store and generate codes)
- Secret history (track changes, beta)
- Password expiry tracking
- Password generator
- Search, filters, favorites
- Granular sharing with individual users
- Private folders
- Shared folders (nested)
- Folder permissions

#### Sharing & Collaboration
- Share with individual users
- Share with groups
- Permission levels: Owner, Update (read+write), Read-only
- Per-secret, per-user encryption (revocation = removal from DB)
- Group management
- User management (invite, activate, suspend, delete)
- Self-registration option
- Email notifications (on share, update, etc.)
- Comments on passwords (collaboration)

#### Security
- OpenPGP end-to-end encryption
- GpgAuth challenge-response authentication
- Multi-Factor Authentication:
  - TOTP (authenticator apps)
  - YubiKey OTP
  - Duo Security
- Anti-phishing token (visual security token during passphrase entry)
- Have I Been Pwned integration (passphrase check)
- Secret key authentication (2FA: passphrase + private key)
- Health Check (password auditing)

#### Client Applications
- **Browser extensions**: Chrome, Firefox, Edge (primary interface)
  - Quick Access (popup for fast search/autofill)
  - Autofill / auto-suggest
  - Password generation from browser
  - Form detection
  - Create/edit passwords from browser
  - Inform menu (contextual actions)
- **Mobile apps**: iOS, Android
  - Autofill integration
  - Biometric unlock
  - TOTP display
- **CLI**: go-passbolt-cli (Go-based)
  - Manage resources, users, groups
  - Script automation
  - CI/CD integration
- **Desktop app**: Windows (beta/pre-alpha)
- **Web interface**: Full-featured (runs in browser via extension)

#### Role-Based Access Control
- Admin role
- User role
- Granular per-resource permissions

#### API
- Full REST JSON API
- All operations available via API
- OpenAPI specification
- Third-party integration support

#### Import/Export
- Import: CSV, KDBX (KeePass)
- Export: CSV, KDBX (KeePass)

#### Other
- Multiple themes
- Keyboard shortcuts
- No telemetry / tracking
- Air-gap deployment capable

### Pro Edition (Paid, Self-Hosted)
Everything in Community, PLUS:

#### Tags
- Tag management (organize passwords with labels)
- Tag-based filtering

#### Enterprise Authentication
- **SSO**: Microsoft Entra ID, Google Workspace, OpenID Connect (generic)
- **LDAP provisioning**: Active Directory, OpenLDAP (user/group sync)
- **SCIM provisioning** (beta): Automated user lifecycle management

#### Account Recovery
- Escrow-based account recovery (admin-assisted)
- Organization recovery key

#### Audit & Compliance
- Activity log (audit trail of all changes)
- Action logs as syslogs / log files
- Who accessed what, when

#### Policies
- User Passphrase policies (complexity requirements)
- Password policies (for stored passwords)
- Password expiry policies
- MFA policies (enforce MFA organization-wide)

#### Support
- Next business day email support
- VM appliance deployment option

### Enterprise Edition
Everything in Pro, PLUS:
- High availability consulting
- Disaster recovery consulting
- White glove migration & hosting assistance
- Custom feature development
- 4-hour SLA phone & email support

### Cloud-Specific Features
- **Business**: GCP Belgium/Germany, SOC2 Type II, free yearly backup
- **Enterprise**: Luxembourg sovereign private DC, ISO 27001, DORA/PFS compliance, custom domain + SSL, firewall rules, 24/7 SOC monitoring & incident response, custom backup policies, dedicated account manager

### Security Audit History (Cure53)
- 2025: Encrypted resource metadata
- 2024: RSA PKCS#1 v1.5 oracle assessment, Windows app
- 2023: LDAP/directory integration, SSO
- 2022: Cryptography & account recovery
- 2021: Mobile apps, CLI, browser extension, backend/plugins, crypto whitepaper
- All results publicly disclosed

### What Passbolt Does NOT Have
- No passkey support (FIDO2 WebAuthn for stored credentials)
- No SSH key management / SSH agent
- No ephemeral sharing (no "Send" equivalent)
- No card/identity item types (passwords + notes + TOTP only)
- No personal/individual use focus (team-first design)
- No emergency access (dead man's switch)
- No vault health reports (beyond HIBP passphrase check)
- No Secrets Manager (DevOps secrets)
- No SIEM integrations
- No Apple Watch app
- No desktop app (mature — Windows beta only)
- No Directory Connector (uses LDAP directly)
- No claimed domains / domain verification
- No password coaching / Access Intelligence

---

# 4. MASTER FEATURE LIST — COMPLETE UNIVERSE

This is every feature that exists across all three password managers combined. For each feature, which product(s) offer it is marked.

**Legend**: BW = Bitwarden, KP = KeePassXC, PB = Passbolt

---

## 4.1 VAULT ITEM TYPES

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 1 | Login entries (username + password) | Y | Y | Y |
| 2 | Secure notes (freeform encrypted text) | Y | Y | Y |
| 3 | Credit/debit card storage | Y | Y* | - |
| 4 | Identity/personal info storage | Y | Y* | - |
| 5 | SSH key storage | Y | Y | - |
| 6 | TOTP secret storage | Y | Y | Y |
| 7 | Passkey/WebAuthn credential storage | Y | Y | - |
| 8 | File attachments on entries | Y | Y | - |
| 9 | Custom fields (text, hidden, boolean) | Y | Y | Y |
| 10 | Linked custom fields (reference other fields) | Y | - | - |
| 11 | Multiple URIs per entry | Y | Y | - |
| 12 | Entry notes/description | Y | Y | Y |
| 13 | Custom entry icons | - | Y | - |
| 14 | Entry color coding | - | Y | - |
| 15 | Comments on entries (collaboration) | - | - | Y |

*KP: Cards and identities stored as custom fields in regular entries, not dedicated types

## 4.2 ITEM MANAGEMENT

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 16 | Folders (personal organization) | Y | Y | Y |
| 17 | Nested/hierarchical folders | - | Y | Y |
| 18 | Shared folders | - | - | Y |
| 19 | Collections (shared organizational buckets) | Y | - | - |
| 20 | Tags/labels | - | Y | Y* |
| 21 | Favorites | Y | - | Y |
| 22 | Archive items (hide without deleting) | Y | - | - |
| 23 | Trash / recycle bin with recovery | Y | Y | - |
| 24 | Item cloning/duplication | Y | Y | - |
| 25 | Item history (all field changes tracked) | Y | Y | Y* |
| 26 | Password history | Y | Y | - |
| 27 | Entry expiration dates | - | Y | Y |
| 28 | Entry cross-references | - | Y | - |
| 29 | Entry placeholders (dynamic field substitution) | - | Y | - |
| 30 | Bulk operations | Y | Y | Y |
| 31 | Search (full-text) | Y | Y | Y |
| 32 | Advanced search (regex, field-specific) | - | Y | - |
| 33 | Filters (by type, folder, collection) | Y | Y | Y |
| 34 | Master password re-prompt on item access | Y | - | - |

*PB: Tags in Pro edition only. Secret history is beta.

## 4.3 ENCRYPTION & CRYPTOGRAPHY

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 35 | AES-256 encryption | Y | Y | Y* |
| 36 | ChaCha20 encryption | - | Y | - |
| 37 | Twofish encryption | - | Y | - |
| 38 | RSA asymmetric encryption | Y | - | Y |
| 39 | OpenPGP-based encryption | - | - | Y |
| 40 | HMAC-SHA256 integrity | Y | Y | - |
| 41 | Per-item unique encryption keys | Y | - | - |
| 42 | Per-user, per-secret encryption | - | - | Y |
| 43 | PBKDF2-SHA256 key derivation | Y | - | - |
| 44 | Argon2id key derivation | Y | Y | - |
| 45 | Argon2d key derivation | - | Y | - |
| 46 | AES-KDF key derivation | - | Y | - |
| 47 | HKDF key stretching | Y | - | - |
| 48 | Configurable KDF parameters | Y | Y | - |
| 49 | Zero-knowledge architecture | Y | - | Y |
| 50 | End-to-end encryption | Y | Y** | Y |
| 51 | Cryptographic signing of secrets | - | - | Y |
| 52 | Metadata encryption (resource names, etc.) | - | - | Y |

*PB: AES-256 for at-rest cloud storage; OpenPGP (RSA) for secret encryption
**KP: Encryption is local-only, so E2E is inherent

## 4.4 KEY MANAGEMENT

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 53 | Master password authentication | Y | Y | - |
| 54 | Passphrase authentication (PGP key) | - | - | Y |
| 55 | Key file (second factor) | - | Y | - |
| 56 | Hardware key for database (YubiKey Challenge-Response) | - | Y | - |
| 57 | Composite key (password + keyfile + hardware) | - | Y | - |
| 58 | User-supplied/imported PGP keys | - | - | Y |
| 59 | Selectable encryption algorithm per database | - | Y | - |
| 60 | Selectable KDF per database | Y | Y | - |
| 61 | RSA keypair per user (auto-generated) | Y | - | Y |

## 4.5 AUTHENTICATION (TO THE PASSWORD MANAGER ITSELF)

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 62 | Master password login | Y | Y | - |
| 63 | GpgAuth challenge-response login | - | - | Y |
| 64 | Passkey login (to vault) | Y | - | - |
| 65 | SSO login (SAML 2.0) | Y | - | - |
| 66 | SSO login (OIDC) | Y | - | Y |
| 67 | SSO with Microsoft Entra ID | Y | - | Y |
| 68 | SSO with Google Workspace | Y | - | Y |
| 69 | SSO with Okta | Y | - | - |
| 70 | SSO with generic OIDC provider | Y | - | Y |
| 71 | SSO with ADFS | Y | - | - |
| 72 | SSO with Auth0 | Y | - | - |
| 73 | SSO with AWS | Y | - | - |
| 74 | SSO with Cloudflare Zero Trust | Y | - | - |
| 75 | SSO with Duo | Y | - | - |
| 76 | SSO with JumpCloud | Y | - | - |
| 77 | SSO with Keycloak | Y | - | - |
| 78 | SSO with OneLogin | Y | - | - |
| 79 | SSO with Ping Identity | Y | - | - |
| 80 | Trusted device login (no master password) | Y | - | - |
| 81 | Device login (approve from another device) | Y | - | - |
| 82 | API key login | Y | - | - |
| 83 | PIN unlock | Y | - | - |
| 84 | Biometric unlock (fingerprint/Face ID) | Y | - | Y* |
| 85 | Quick unlock (after initial auth) | - | Y | - |
| 86 | Anti-phishing token (visual indicator) | - | - | Y |
| 87 | Account fingerprint phrase | Y | - | - |

*PB: Biometrics on mobile only

## 4.6 MULTI-FACTOR AUTHENTICATION (2FA)

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 88 | TOTP authenticator app | Y | - | Y |
| 89 | Email 2FA codes | Y | - | - |
| 90 | YubiKey OTP | Y | - | Y |
| 91 | Duo Security | Y | - | Y |
| 92 | FIDO2 WebAuthn hardware keys | Y | - | - |
| 93 | Recovery codes | Y | - | - |
| 94 | Enforce MFA organization-wide (policy) | Y | - | Y |
| 95 | YubiKey for database unlock (Challenge-Response) | - | Y | - |

## 4.7 PASSWORD GENERATION

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 96 | Random character password generation | Y | Y | Y |
| 97 | Configurable length | Y | Y | Y |
| 98 | Character set selection (upper/lower/digit/special) | Y | Y | Y |
| 99 | Avoid ambiguous characters | Y | Y | - |
| 100 | Minimum numbers/specials enforcement | Y | - | - |
| 101 | Custom character exclusions | - | Y | - |
| 102 | Extended ASCII characters | - | Y | - |
| 103 | Ensure chars from each selected set | - | Y | - |
| 104 | Passphrase generation (diceware) | Y | Y | - |
| 105 | Custom word lists for passphrases | - | Y | - |
| 106 | Custom word separator | Y | Y | - |
| 107 | Capitalize words in passphrase | Y | Y | - |
| 108 | Include number in passphrase | Y | - | - |
| 109 | Password strength estimation (entropy) | - | Y | - |
| 110 | Password entropy display (bits) | - | Y | - |
| 111 | Generator in browser extension | Y | Y | Y |
| 112 | Generator history | Y | - | - |

## 4.8 USERNAME GENERATION

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 113 | Plus-addressed email (alice+random@domain) | Y | - | - |
| 114 | Catch-all email (random@yourdomain) | Y | - | - |
| 115 | Forwarded email alias (SimpleLogin) | Y | - | - |
| 116 | Forwarded email alias (AnonAddy/addy.io) | Y | - | - |
| 117 | Forwarded email alias (Firefox Relay) | Y | - | - |
| 118 | Forwarded email alias (Fastmail) | Y | - | - |
| 119 | Forwarded email alias (Forward Email) | Y | - | - |
| 120 | Forwarded email alias (DuckDuckGo) | Y | - | - |
| 121 | Random word username | Y | - | - |

## 4.9 TOTP / AUTHENTICATOR

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 122 | Store TOTP secrets | Y | Y | Y |
| 123 | Generate TOTP codes in-app | Y | Y | Y |
| 124 | Auto-copy TOTP on autofill | Y | - | - |
| 125 | Apple Watch TOTP display | Y | - | - |
| 126 | Steam Guard TOTP | - | Y | - |
| 127 | Custom TOTP digits (6/7/8) | - | Y | - |
| 128 | Custom TOTP period (30s/60s) | - | Y | - |
| 129 | TOTP algorithm selection (SHA-1/256/512) | - | Y | - |
| 130 | Standalone authenticator app | Y | - | - |

## 4.10 PASSKEYS (FIDO2/WebAuthn)

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 131 | Store passkeys in vault | Y | Y | - |
| 132 | Autofill passkeys during login | Y | Y | - |
| 133 | Create passkeys via browser prompt | Y | Y | - |
| 134 | Passkeys in mobile autofill | Y | - | - |
| 135 | Export/import passkeys | Y | - | - |
| 136 | Log into password manager with passkey | Y | - | - |

## 4.11 SSH FEATURES

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 137 | SSH key storage in vault | Y | Y | - |
| 138 | SSH agent functionality | Y | Y | - |
| 139 | SSH key generation (Ed25519) | Y | Y | - |
| 140 | SSH key import (OpenSSH, PKCS#8) | Y | Y | - |
| 141 | SSH agent forwarding | Y | Y | - |
| 142 | Git commit signing via SSH | Y | - | - |
| 143 | Auto-load keys on database unlock | - | Y | - |
| 144 | Auto-remove keys on database lock | - | Y | - |
| 145 | RSA/DSA/ECDSA/Ed25519 key types | - | Y | - |
| 146 | Pageant support (Windows) | - | Y | - |
| 147 | Require confirmation before SSH key use | - | Y | - |
| 148 | SSH key lifetime configuration | - | Y | - |
| 149 | Organization-shared SSH keys | Y | - | - |

## 4.12 AUTOFILL

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 150 | Browser extension autofill | Y | Y | Y |
| 151 | Inline autofill menu | Y | - | - |
| 152 | Autofill on page load | Y | - | - |
| 153 | Keyboard shortcut autofill | Y | Y | Y |
| 154 | Context menu autofill | Y | Y | - |
| 155 | Mobile autofill (iOS) | Y | - | Y |
| 156 | Mobile autofill (Android) | Y | - | Y |
| 157 | Credit card autofill | Y | - | - |
| 158 | Identity/address autofill | Y | - | - |
| 159 | Custom field autofill | Y | Y | - |
| 160 | HTTP Basic Auth autofill | Y | Y | - |
| 161 | Auto-submit forms | - | Y | - |
| 162 | Autosave new credentials | Y | Y | - |
| 163 | URI match detection (base domain/host/regex/exact) | Y | Y | - |
| 164 | Domain exclusion lists | Y | Y | - |
| 165 | Auto-suggest (dropdown on focus) | - | - | Y |
| 166 | Quick Access popup | - | - | Y |

## 4.13 AUTO-TYPE (Desktop Application Autofill)

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 167 | Global auto-type hotkey | - | Y | - |
| 168 | Per-entry custom auto-type sequences | - | Y | - |
| 169 | Window title matching (regex) | - | Y | - |
| 170 | Placeholder substitution in sequences | - | Y | - |
| 171 | Delay/timing control in sequences | - | Y | - |
| 172 | Two-channel auto-type obfuscation (anti-keylogger) | - | Y | - |
| 173 | Auto-type for any desktop application | - | Y | - |

## 4.14 SHARING & COLLABORATION

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 174 | Share items with individual users | Y | - | Y |
| 175 | Share items via collections/groups | Y | - | Y |
| 176 | Granular permissions (read/write/manage) | Y | - | Y |
| 177 | Organization-level sharing | Y | - | Y |
| 178 | Group-based permission assignment | Y | - | Y |
| 179 | Share with external users (no account needed) | Y* | - | - |
| 180 | Ephemeral sharing (Send — time-limited, link-based) | Y | - | - |
| 181 | File sharing (encrypted, link-based) | Y | - | - |
| 182 | Password-protected shares | Y | - | - |
| 183 | Max access count on shares | Y | - | - |
| 184 | KeeShare (file-based database sharing) | - | Y | - |
| 185 | Signed/verified shares | - | Y | - |
| 186 | Comments on shared items | - | - | Y |
| 187 | Owner/Update/Read permission levels | - | - | Y |
| 188 | Per-secret revocation (crypto removal) | - | - | Y |
| 189 | Shared folders with permissions | - | - | Y |
| 190 | Email notifications on share/update | - | - | Y |

*BW: Send feature for sharing with anyone; vault sharing requires Bitwarden accounts

## 4.15 EMERGENCY ACCESS

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 191 | Designate trusted emergency contacts | Y | - | - |
| 192 | View-only emergency access | Y | - | - |
| 193 | Full takeover emergency access | Y | - | - |
| 194 | Configurable wait time | Y | - | - |
| 195 | Auto-grant after wait time expires | Y | - | - |
| 196 | Grantor can approve/reject requests | Y | - | - |
| 197 | Account recovery (admin-initiated) | Y | - | Y |

## 4.16 VAULT HEALTH & SECURITY REPORTS

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 198 | Exposed/breached password detection (HIBP) | Y | Y | Y* |
| 199 | Reused password detection | Y | - | - |
| 200 | Weak password detection | Y | Y | - |
| 201 | Unsecured website detection (HTTP URLs) | Y | - | - |
| 202 | Inactive 2FA detection | Y | - | - |
| 203 | Data breach report (email) | Y | - | - |
| 204 | Access Intelligence dashboard | Y | - | - |
| 205 | Critical application designation | Y | - | - |
| 206 | Password change request notifications | Y | - | - |
| 207 | Remediation progress tracking | Y | - | - |
| 208 | Password strength estimation (entropy bits) | - | Y | - |
| 209 | Health Check feature | - | - | Y |

*PB: HIBP check for passphrase only (not stored passwords)

## 4.17 ENTERPRISE & ADMIN

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 210 | Admin console / dashboard | Y | - | Y |
| 211 | User management (invite/activate/suspend/delete) | Y | - | Y |
| 212 | Group management | Y | - | Y |
| 213 | Role-based access control | Y | - | Y |
| 214 | SSO (SAML 2.0) | Y | - | - |
| 215 | SSO (OIDC) | Y | - | Y |
| 216 | LDAP directory sync | Y | - | Y |
| 217 | Active Directory sync | Y | - | Y |
| 218 | SCIM provisioning | Y | - | Y* |
| 219 | Google Workspace directory sync | Y | - | - |
| 220 | Okta directory sync | Y | - | - |
| 221 | OneLogin directory sync | Y | - | - |
| 222 | JIT provisioning via SSO | Y | - | - |
| 223 | Self-registration | - | - | Y |
| 224 | Claimed domains (block outside account creation) | Y | - | - |
| 225 | Onboarding workflows | Y | - | - |
| 226 | Sponsored Families for enterprise members | Y | - | - |

*PB: SCIM is beta

## 4.18 ENTERPRISE POLICIES

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 227 | Single Organization policy | Y | - | - |
| 228 | Enforce org data ownership | Y | - | - |
| 229 | Master password complexity requirements | Y | - | - |
| 230 | Account recovery administration | Y | - | - |
| 231 | Require SSO authentication | Y | - | - |
| 232 | Require two-step login | Y | - | - |
| 233 | Block account creation for claimed domains | Y | - | - |
| 234 | Session timeout enforcement | Y | - | - |
| 235 | Disable PIN unlock | Y | - | - |
| 236 | Password generator minimums | Y | - | - |
| 237 | Default URI match detection | Y | - | - |
| 238 | Force-enable autofill | Y | - | - |
| 239 | Send restrictions/removal | Y | - | - |
| 240 | Remove card item type | Y | - | - |
| 241 | Remove Families sponsorship | Y | - | - |
| 242 | Remove export capability | Y | - | - |
| 243 | User passphrase policies | - | - | Y |
| 244 | Password policies (for stored passwords) | - | - | Y |
| 245 | Password expiry policies | - | - | Y |
| 246 | MFA enforcement policies | - | - | Y |

## 4.19 AUDIT & LOGGING

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 247 | Event logs (60+ event types) | Y | - | - |
| 248 | Activity log (audit trail) | Y | - | Y |
| 249 | User login tracking | Y | - | Y |
| 250 | Item access/modification tracking | Y | - | Y |
| 251 | CSV event log export | Y | - | - |
| 252 | API event log access | Y | - | - |
| 253 | Indefinite log retention | Y | - | - |
| 254 | Action logs as syslogs/log files | - | - | Y |
| 255 | SIEM integration (Elastic) | Y | - | - |
| 256 | SIEM integration (Microsoft Sentinel) | Y | - | - |
| 257 | SIEM integration (Panther) | Y | - | - |
| 258 | SIEM integration (Rapid7) | Y | - | - |
| 259 | SIEM integration (Splunk) | Y | - | - |
| 260 | SIEM integration (Sumo Logic) | Y | - | - |
| 261 | SIEM integration (Huntress) | Y | - | - |
| 262 | Entry-level history (per-field change log) | - | Y | - |

## 4.20 API & SDK

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 263 | Public REST API (org management) | Y | - | Y |
| 264 | Vault Management API (local REST server) | Y | - | - |
| 265 | SDK (multiple languages) | Y | - | - |
| 266 | Full REST JSON API | Y | - | Y |
| 267 | Personal API keys | Y | - | - |
| 268 | OpenAPI specification | - | - | Y |
| 269 | GpgAuth API authentication | - | - | Y |
| 270 | API key authentication | Y | - | - |

## 4.21 CLI

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 271 | CLI tool available | Y | Y | Y |
| 272 | Login/authenticate via CLI | Y | - | Y |
| 273 | List/search vault items | Y | Y | Y |
| 274 | Create items via CLI | Y | Y | Y |
| 275 | Edit items via CLI | Y | - | - |
| 276 | Delete items via CLI | Y | Y | Y |
| 277 | Import via CLI | Y | Y | - |
| 278 | Export via CLI | Y | Y | - |
| 279 | Password generation via CLI | Y | Y | - |
| 280 | Passphrase generation (diceware) via CLI | - | Y | - |
| 281 | Password entropy estimation via CLI | - | Y | - |
| 282 | Database creation via CLI | - | Y | - |
| 283 | Database info/edit via CLI | - | Y | - |
| 284 | Database merge via CLI | - | Y | - |
| 285 | Attachment management via CLI | - | Y | - |
| 286 | Clipboard copy via CLI | - | Y | - |
| 287 | Send create/receive via CLI | Y | - | - |
| 288 | Organization management via CLI | Y | - | - |
| 289 | Device approval via CLI | Y | - | - |
| 290 | Start local REST API server via CLI | Y | - | - |
| 291 | Shell completion generation | Y | - | - |
| 292 | Group management via CLI | - | - | Y |
| 293 | User management via CLI | - | - | Y |
| 294 | Sync vault via CLI | Y | - | - |
| 295 | TOTP retrieval via CLI | Y | - | - |
| 296 | Move to group/folder via CLI | - | Y | - |

## 4.22 IMPORT FORMATS

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 297 | Import from 50+ password managers | Y | - | - |
| 298 | Import from CSV (generic) | Y | Y | Y |
| 299 | Import from KDBX (KeePass) | Y* | Y | Y |
| 300 | Import from KeePass 1.x (.kdb) | - | Y | - |
| 301 | Import from 1Password (1pif, 1pux, csv) | Y | Y | - |
| 302 | Import from LastPass (csv) | Y | - | - |
| 303 | Import from Chrome/Edge/browsers (csv) | Y | - | - |
| 304 | Import from Bitwarden (json) | - | Y | - |
| 305 | Import custom CSV/JSON with field mapping | Y | Y | - |
| 306 | Import from Passbolt (csv) | Y | - | - |

*BW: Imports KeePass 2 XML, not KDBX directly

## 4.23 EXPORT FORMATS

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 307 | Export CSV | Y | Y | Y |
| 308 | Export JSON | Y | - | - |
| 309 | Export encrypted JSON | Y | - | - |
| 310 | Export ZIP (with attachments) | Y | - | - |
| 311 | Export KDBX | - | Y | Y |
| 312 | Export XML (KeePass 2 format) | - | Y | - |
| 313 | Export HTML (for printing) | - | Y | - |
| 314 | Organization export (admin) | Y | - | - |

## 4.24 BROWSER EXTENSION

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 315 | Chrome extension | Y | Y | Y |
| 316 | Firefox extension | Y | Y | Y |
| 317 | Edge extension | Y | Y | Y |
| 318 | Safari extension | Y | - | Y* |
| 319 | Brave extension | Y | Y | - |
| 320 | Opera extension | Y | - | - |
| 321 | Vivaldi extension | Y | Y | - |
| 322 | Tor Browser extension | - | Y | - |
| 323 | DuckDuckGo macOS integration | Y | - | - |
| 324 | Firefox private window support | Y | - | - |
| 325 | Vault management in extension | Y | - | Y |
| 326 | Password creation from extension | Y | Y | Y |
| 327 | Password generator in extension | Y | Y | Y |
| 328 | Credential save/update prompts | Y | Y | - |
| 329 | Site-specific extension settings | - | Y | - |

*PB: Safari extension in open beta

## 4.25 DESKTOP APPLICATION

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 330 | Windows desktop app | Y | Y | Y* |
| 331 | macOS desktop app | Y | Y | - |
| 332 | Linux desktop app | Y | Y | - |
| 333 | Tabbed multi-database interface | - | Y | - |
| 334 | System tray integration | Y | Y | - |
| 335 | Biometric unlock (desktop) | Y | - | - |
| 336 | Portable mode (no install) | - | Y | - |
| 337 | Single instance mode | - | Y | - |
| 338 | Minimize to tray | Y | Y | - |

*PB: Windows desktop app is beta/pre-alpha

## 4.26 MOBILE APPLICATION

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 339 | iOS app | Y | -* | Y |
| 340 | Android app | Y | -* | Y |
| 341 | Mobile autofill | Y | - | Y |
| 342 | Biometric unlock (mobile) | Y | - | Y |
| 343 | Mobile TOTP display | Y | - | Y |
| 344 | Mobile password generator | Y | - | Y |
| 345 | Apple Watch app | Y | - | - |
| 346 | Mobile Send | Y | - | - |
| 347 | Mobile camera (QR code TOTP import) | Y | - | - |

*KP: No native mobile app. Recommends third-party KDBX apps (KeePassDX, KeePass2Android, Strongbox, KeePassium)

## 4.27 WEB VAULT

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 348 | Web-based vault access | Y | - | Y* |
| 349 | Full vault management in browser | Y | - | Y |
| 350 | Admin console in browser | Y | - | Y |
| 351 | No web interface (local app only) | - | Y | - |

*PB: Web interface runs through/alongside the browser extension

## 4.28 DEPLOYMENT & HOSTING

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 352 | Cloud-hosted (vendor managed) | Y | - | Y |
| 353 | Self-hosted (Docker) | Y | - | Y |
| 354 | Self-hosted (Kubernetes/Helm) | Y | - | Y |
| 355 | Self-hosted (native Linux packages) | - | - | Y |
| 356 | Self-hosted (offline/air-gapped) | Y | - | Y |
| 357 | Local-only (no server) | - | Y | - |
| 358 | Raspberry Pi deployment | - | - | Y |
| 359 | VM appliance deployment | - | - | Y |
| 360 | High availability (HA) | Y | - | Y* |
| 361 | Multiple server regions (US/EU) | Y | - | Y |
| 362 | Sovereign data center option | - | - | Y |
| 363 | Custom domain + SSL (cloud) | - | - | Y |
| 364 | External database support | Y | - | Y |
| 365 | MSSQL database | Y | - | - |
| 366 | MySQL/MariaDB database | - | - | Y |
| 367 | PostgreSQL database | - | - | Y |
| 368 | SQLite / local file database | - | Y | - |
| 369 | SMTP configuration | Y | - | Y |
| 370 | Let's Encrypt SSL | Y | - | Y |
| 371 | Custom SSL certificates | Y | - | Y |
| 372 | Firewall rules (cloud) | - | - | Y |
| 373 | 24/7 SOC monitoring (cloud) | - | - | Y |

*PB: HA consulting for Enterprise tier

## 4.29 SECRETS MANAGER (DevOps)

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 374 | Dedicated secrets management product | Y | - | - |
| 375 | Projects (logical grouping) | Y | - | - |
| 376 | Machine accounts (service identities) | Y | - | - |
| 377 | Access tokens for machines | Y | - | - |
| 378 | Ansible integration | Y | - | Y* |
| 379 | GitHub Actions integration | Y | - | - |
| 380 | GitLab CI/CD integration | Y | - | - |
| 381 | Jenkins integration | Y | - | - |
| 382 | Kubernetes Operator | Y | - | - |
| 383 | Terraform Provider | Y | - | - |
| 384 | Secrets Manager SDK | Y | - | - |
| 385 | Secrets Manager CLI | Y | - | - |

*PB: Ansible lookup plugin (not full secrets manager)

## 4.30 COMPLIANCE & CERTIFICATIONS

| # | Feature | BW | KP | PB |
|---|---------|----|----|-----|
| 386 | SOC2 Type II | Y | - | Y |
| 387 | SOC3 | Y | - | - |
| 388 | ISO 27001 | Y | - | Y* |
| 389 | Third-party security audits | Y | Y | Y |
| 390 | HackerOne bug bounty program | Y | - | - |
| 391 | Publicly disclosed audit reports | Y | Y | Y |
| 392 | DORA compliance | - | - | Y |
| 393 | PFS compliance | - | - | Y |
| 394 | Open source code (full audit capability) | Y | Y | Y |
| 395 | FIPS-140 compliant KDF | Y | - | - |

*PB: ISO 27001 for Enterprise cloud DC (Luxembourg)

## 4.31 UNIQUE / DIFFERENTIATING FEATURES

### Bitwarden Only
| # | Feature |
|---|---------|
| 396 | Bitwarden Send (ephemeral encrypted sharing) |
| 397 | Emergency Access (dead man's switch) |
| 398 | Access Intelligence (enterprise risk dashboard) |
| 399 | Passkey login to Bitwarden itself |
| 400 | Trusted device login (SSO without master password) |
| 401 | Key Connector (org-managed encryption keys) |
| 402 | Provider Portal (MSP management) |
| 403 | Secrets Manager (full DevOps secrets product) |
| 404 | 50+ import format support |
| 405 | Username generator with email alias integrations |
| 406 | Git commit signing via SSH agent |
| 407 | Apple Watch TOTP |
| 408 | Automatic Login with SSO (enterprise policy) |
| 409 | Vault Management API (local REST server) |
| 410 | 7 SIEM integrations |
| 411 | 18 enterprise policies |
| 412 | Password coaching |
| 413 | Phishing blocker |

### KeePassXC Only
| # | Feature |
|---|---------|
| 414 | Fully offline, no server required |
| 415 | Three encryption algorithms selectable (AES/ChaCha20/Twofish) |
| 416 | Key file as authentication factor |
| 417 | Composite key (password + keyfile + hardware key) |
| 418 | Auto-Type with custom sequences for any desktop app |
| 419 | Two-channel auto-type obfuscation (anti-keylogger) |
| 420 | Secret Service D-Bus integration (replace GNOME Keyring) |
| 421 | KeeShare file-based database sharing |
| 422 | Database merge (combine two databases) |
| 423 | Diceware with custom word lists |
| 424 | Password entropy estimation (bits) |
| 425 | No networking required (can compile without) |
| 426 | Entry cross-references and placeholders |
| 427 | Portable mode (run from USB) |
| 428 | Steam Guard TOTP |
| 429 | Custom TOTP parameters (digits/period/algorithm) |
| 430 | Extended ASCII in password generation |
| 431 | Entry color coding |
| 432 | Custom entry icons |
| 433 | Secure desktop for auto-type (Windows) |
| 434 | Database integrity check and repair |
| 435 | Multiple simultaneous databases (tabbed) |

### Passbolt Only
| # | Feature |
|---|---------|
| 436 | OpenPGP-based encryption (user-owned PGP keys) |
| 437 | GpgAuth challenge-response protocol |
| 438 | Per-secret, per-user encryption (N copies for N users) |
| 439 | Cryptographic signing of all secrets |
| 440 | Anti-phishing visual security token |
| 441 | Comments on shared passwords |
| 442 | No telemetry / no tracking |
| 443 | Sovereign data center (Luxembourg) |
| 444 | DORA/PFS compliance |
| 445 | Interoperable secrets (decrypt with any OpenPGP tool) |
| 446 | Metadata encryption (resource names) |
| 447 | Air-gap capable (self-hosted, no external dependencies) |
| 448 | User-supplied/imported PGP keys |
| 449 | Mutual authentication (server proves identity too) |
| 450 | Self-registration for users |

---

## 4.32 SUMMARY COMPARISON TABLE

| Dimension | Bitwarden | KeePassXC | Passbolt |
|-----------|-----------|-----------|----------|
| **Architecture** | Client-server (cloud/self-host) | Local file only | Client-server (cloud/self-host) |
| **Primary encryption** | AES-256-CBC + HMAC-SHA256 | AES-256 / ChaCha20 / Twofish | OpenPGP (RSA) |
| **Key derivation** | PBKDF2-SHA256 / Argon2id | Argon2d / Argon2id / AES-KDF | N/A (PGP passphrase) |
| **Storage format** | Encrypted MSSQL blobs | KDBX 4.x local file | MySQL/MariaDB/PostgreSQL |
| **Sharing model** | Org symmetric key (RSA-wrapped) | KeeShare (file export) | Per-user PGP encryption |
| **Target user** | Individual + Teams + Enterprise | Individual power users | Teams + Enterprise |
| **Vault item types** | 5 (Login, Card, Identity, Note, SSH) | 1 (generic entry, flexible) | 3 (Password, Note, TOTP) |
| **SSO providers** | 14+ | 0 | 3 (Microsoft, Google, OIDC) |
| **Enterprise policies** | 18 | 0 | 4 |
| **Import formats** | 50+ | ~5 | 2 (CSV, KDBX) |
| **SIEM integrations** | 7 | 0 | 0 (syslog only) |
| **CLI** | Node.js (comprehensive) | C++ (database ops) | Go (resource management) |
| **API** | REST + local serve | None | REST JSON |
| **Mobile** | iOS + Android + Apple Watch | Third-party apps | iOS + Android |
| **Price** | Free-$6/user/mo | Free | Free-$4.90/user/mo |
| **License** | AGPL-3.0 / GPL-3.0 | GPL-2.0/3.0 | AGPL-3.0 |
| **Unique strength** | Most features, best ecosystem | Full offline control, flexibility | OpenPGP E2E, team-first |

---

## 4.33 TOTAL FEATURE COUNT

**Total unique features identified across all three products: 450**

| Product | Features offered | % of total |
|---------|-----------------|------------|
| Bitwarden | ~310 | ~69% |
| KeePassXC | ~165 | ~37% |
| Passbolt | ~145 | ~32% |

Note: Percentages exceed 100% because many features overlap across products.

---

*End of Password Manager Research*
*Research Date: 2026-03-20*
