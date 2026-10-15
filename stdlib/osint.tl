// tallow.osint -- OSINT Intelligence Types and Operations
//
// Provides intelligence seed types with provenance tracking,
// subdomain enumeration, technology fingerprinting, domain/IP/ASN
// intelligence, email intelligence (SPF/DMARC/breach), and
// privacy-safe document metadata extraction.

// ── Target ──────────────────────────────────────────────────────
// Intelligence seed type. Creates typed targets with automatic
// provenance tracking for audit trails.
//
// Constructors:
//   Target.domain("example.com") -> Target { kind: "domain", value, provenance }
//   Target.ip("192.168.1.1")     -> Target { kind: "ip", value, provenance }
//   Target.email("user@ex.com")  -> Target { kind: "email", value: Private, provenance }
//   Target.org("Acme Corp")      -> Target { kind: "org", value, provenance }
//
// Methods:
//   target.enumerate_subdomains() -> []SubdomainResult
//     Enumerates subdomains via CT logs (crt.sh) and DNS brute-force.
//     Returns array of SubdomainResult structs with source provenance.

// ── SubdomainResult ─────────────────────────────────────────────
// Result from subdomain enumeration.
//   Fields: subdomain (String), source ("ct_logs" | "dns_brute"), provenance ([]Provenance)

// ── TechStack ───────────────────────────────────────────────────
// Technology fingerprinting via HTTP headers and HTML analysis.
//
// Static methods:
//   TechStack.detect("https://example.com") -> TechStack
//     Fetches URL, matches against ~50 technology signatures.
//     Returns detected technologies with confidence levels.
//
// Result fields:
//   url (String), technologies ([]Technology), provenance ([]Provenance)

// ── Technology ──────────────────────────────────────────────────
// Individual detected technology.
//   Fields: name (String), category (String), version (String), confidence ("high"|"medium"|"low")

// ── DomainIntel ─────────────────────────────────────────────────
// Domain intelligence via WHOIS queries and DNS resolution.
//
// Static methods:
//   DomainIntel.whois("example.com") -> DomainIntel
//     Performs WHOIS lookup via TCP (port 43) with IANA referral.
//     Parses: registrar, creation_date, expiration_date, updated_date,
//     nameservers, status. Returns raw WHOIS text plus parsed fields.
//
//   DomainIntel.dns_history("example.com") -> DomainIntel
//     Resolves A/AAAA DNS records for the domain.
//     Returns DnsRecord structs with type and value.
//
// Result fields:
//   domain (String), raw (String), registrar (String), creation_date (String),
//   expiration_date (String), updated_date (String), nameservers ([]String),
//   status ([]String), provenance ([]Provenance)

// ── ASNIntel ────────────────────────────────────────────────────
// Autonomous System Number intelligence via WHOIS.
//
// Static methods:
//   ASNIntel.lookup("8.8.8.8") -> ASNIntel
//     Queries ARIN WHOIS for IP-to-ASN information.
//     Parses: asn_number, org_name, country, network_range.
//
// Result fields:
//   ip (String), raw (String), asn_number (String), org_name (String),
//   country (String), network_range (String), provenance ([]Provenance)

// ── EmailIntel ──────────────────────────────────────────────────
// Email intelligence with SPF/DMARC analysis and breach checking.
//
// Static methods:
//   EmailIntel.from("user@example.com") -> EmailIntel
//     Creates email intel struct. Email is automatically wrapped in
//     Value::Private for PII protection. Domain is extracted.
//
// Instance methods:
//   .check_spf() -> SpfResult
//     DNS TXT lookup for SPF record, parses mechanisms (ip4:, ip6:,
//     include:, redirect=, all). Caps recursive includes at RFC 7208 limit.
//     Uses Cloudflare DNS-over-HTTPS for TXT record resolution.
//
//   .check_dmarc() -> DmarcResult
//     DNS TXT lookup for _dmarc.domain, parses DMARC tags:
//     v, p, rua, ruf, pct, adkim, aspf, sp, fo.
//
//   .breach_check() -> BreachResult
//     HIBP k-anonymity check: SHA1 prefix query to Have I Been Pwned.
//     Returns COUNT ONLY -- never passwords or breach details.
//     Privacy-safe: only first 5 hex chars of SHA1 sent to API.

// ── SpfResult ───────────────────────────────────────────────────
// Result from SPF record analysis.
//   Fields: raw (String), mechanisms ([]String), all_qualifier ("+"|"-"|"~"|"?"),
//           includes ([]String), provenance ([]Provenance)

// ── DmarcResult ─────────────────────────────────────────────────
// Result from DMARC record analysis.
//   Fields: raw (String), version (String), policy (String), rua (String),
//           ruf (String), pct (String), adkim (String), aspf (String),
//           provenance ([]Provenance)

// ── BreachResult ────────────────────────────────────────────────
// Result from breach check (count only, never passwords).
//   Fields: count (Int), checked_at (String RFC3339), provenance ([]Provenance)

// ── DocumentMeta ────────────────────────────────────────────────
// Document metadata extracted from files with privacy enforcement.
//
// Static methods:
//   parse_document(bytes) -> DocumentMeta
//     Detects format via magic bytes and extracts metadata.
//     Supported formats:
//       - PDF (%PDF): Title, Author (Private), Subject, Creator, Producer, dates
//       - EXIF (JPEG/TIFF): Make, Model, DateTime, Artist (Private),
//         GPS latitude/longitude (Private, decimal degrees)
//       - OOXML (.docx/.xlsx/.pptx): Title, Creator (Private), Subject,
//         Description, Created, Modified, LastModifiedBy (Private)
//       - OLE2 (.doc/.xls/.ppt): Returns "unsupported format" error
//
//     PII fields (author, artist, creator, GPS coordinates) are automatically
//     wrapped in Value::Private for compile-time privacy enforcement.
//
// Result fields:
//   format (String: "PDF"|"EXIF"|"OOXML"), plus format-specific metadata fields,
//   provenance ([]Provenance)

// ── DnsRecord ───────────────────────────────────────────────────
// Individual DNS record from dns_history.
//   Fields: type (String: "A"|"AAAA"), value (String: IP address)

// ── Provenance ──────────────────────────────────────────────────
// Audit trail entry tracking data origin and transformations.
//   Fields: source (String), operation (String), timestamp (String RFC3339)
