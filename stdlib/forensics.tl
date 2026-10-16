// tallow.forensics -- Digital Forensics & STIX 2.1 Types
//
// Provides digital forensics primitives, cryptographic chain of custody,
// simulated memory/disk/network forensics, file carving, STIX 2.1
// Structured Threat Information eXpression, and MITRE ATT&CK technique
// mapping.

// ── EvidenceChain ────────────────────────────────────────────────
// Cryptographic chain of custody using BLAKE3 hash linking.
// Each evidence entry is linked to the previous via hash chaining,
// providing tamper-evident audit trails for legal proceedings.
//
// Static methods:
//   EvidenceChain.create(case_id: String) -> EvidenceChain
//     Creates a new evidence chain with a genesis hash.
//
//   EvidenceChain.add_evidence(chain: EvidenceChain, description: String, hash: String) -> EvidenceChain
//     Adds evidence to the chain (immutable update). Links new entry
//     to previous via BLAKE3(prev_hash + evidence_hash + description + timestamp).
//
//   EvidenceChain.verify(chain: EvidenceChain) -> bool
//     Verifies the entire hash chain integrity. Returns false if any
//     entry has been tampered with.
//
//   EvidenceChain.export(chain: EvidenceChain) -> String
//     Exports the chain as a JSON string for court-ready documentation.
//
// Fields:
//   case_id (String), entries ([]EvidenceEntry), hash_chain (String),
//   created_at (String), entry_count (i128)

// ── EvidenceEntry ────────────────────────────────────────────────
// A single entry in an EvidenceChain.
// Fields:
//   index (i128), description (String), evidence_hash (String),
//   chain_hash (String), prev_hash (String), timestamp (String)

// ── MemoryDump ───────────────────────────────────────────────────
// Simulated memory forensics analysis.
//
// Static methods:
//   MemoryDump.parse(data: String) -> MemoryDump
//     Parses memory dump data. Extracts readable strings (4+ chars),
//     detects PE/ELF/HTTP/SSH/DNS headers, computes entropy score.
//
// Fields:
//   strings ([]String), headers ([]String), entropy (f64),
//   size (i128), timestamp (String)

// ── DiskImage ────────────────────────────────────────────────────
// Simulated disk forensics.
//
// Static methods:
//   DiskImage.mount(path: String) -> DiskImage
//     Mounts a disk image. Detects format from extension:
//     .e01 (EnCase), .dd/.raw (Raw), .vmdk (VMware),
//     .vhd/.vhdx (Hyper-V), .qcow2 (QEMU).
//
// Fields:
//   path (String), format (String), timeline ([]TimelineEntry),
//   file_count (i128), mounted_at (String)

// ── FileCarver ───────────────────────────────────────────────────
// Simulated file carving with magic byte detection.
//
// Static methods:
//   FileCarver.scan(data: String) -> []CarvedFile
//     Scans data for magic byte signatures. Detects 7+ formats:
//     PNG, GIF, PDF, ZIP/DOCX, JPEG, PE/EXE, ELF, SQLite, HTML,
//     XML, RAR, 7-Zip.
//
// Returns array of CarvedFile structs.

// ── CarvedFile ───────────────────────────────────────────────────
// A file recovered by FileCarver.
// Fields:
//   offset (i128), file_type (String), extension (String),
//   magic (String), confidence (String)

// ── NetworkCapture ───────────────────────────────────────────────
// Simulated pcap/network capture analysis.
//
// Static methods:
//   NetworkCapture.reconstruct(data: String) -> NetworkCapture
//     Reconstructs network sessions from capture data. Detects
//     protocols (TCP, UDP, HTTP, DNS, SSH, etc.), extracts
//     connections, counts packets.
//
// Fields:
//   protocols ([]String), connections ([]Connection),
//   packets (i128), size (i128), timestamp (String)

// ── Connection ───────────────────────────────────────────────────
// A network connection extracted from capture data.
// Fields:
//   src (String), dst (String), protocol (String)

// ── VolatileData ─────────────────────────────────────────────────
// Simulated volatile data collection (live forensics).
//
// Static methods:
//   VolatileData.collect() -> VolatileData
//     Collects simulated volatile system data: running processes,
//     active network connections, collection timestamp.
//
// Fields:
//   processes ([]ProcessInfo), network_connections ([]Connection),
//   timestamp (String)

// ── ProcessInfo ──────────────────────────────────────────────────
// A running process from volatile data collection.
// Fields:
//   pid (i128), name (String), user (String), memory_kb (i128)

// ── StixBundle ───────────────────────────────────────────────────
// STIX 2.1 Bundle for structured threat intelligence exchange.
// Supports 8+ SDO types: threat-actor, malware, indicator,
// attack-pattern, campaign, identity, vulnerability, tool.
//
// Static methods:
//   StixBundle.create() -> StixBundle
//     Creates an empty STIX 2.1 bundle with auto-generated ID.
//
//   StixBundle.add_object(bundle: StixBundle, type: String, properties: Map) -> StixBundle
//     Adds a STIX Domain Object to the bundle (immutable update).
//     Validates type against STIX 2.1 SDO types. Auto-generates
//     id, spec_version, created, modified fields.
//
//   StixBundle.export(bundle: StixBundle) -> String
//     Exports the bundle as STIX 2.1 compliant JSON.
//
// Fields:
//   type (String), id (String), objects ([]StixObject),
//   spec_version (String)

// ── StixObject ───────────────────────────────────────────────────
// A STIX Domain Object within a bundle.
// Fields:
//   type (String), id (String), spec_version (String),
//   created (String), modified (String), + user properties

// ── AttackTechnique ──────────────────────────────────────────────
// MITRE ATT&CK technique lookup and mapping.
//
// Static methods:
//   AttackTechnique.lookup(id: String) -> AttackTechnique
//     Looks up a MITRE ATT&CK technique by ID (e.g., "T1059",
//     "T1566.001"). Returns technique info including name, tactic,
//     description, platform, data sources, and MITRE URL.
//     Returns "Unknown Technique" for unrecognized IDs.
//
// Fields:
//   id (String), name (String), tactic (String),
//   description (String), platform (String),
//   data_sources ([]String), mitre_url (String)
//
// Known techniques (subset):
//   T1003  - OS Credential Dumping
//   T1021  - Remote Services
//   T1027  - Obfuscated Files or Information
//   T1048  - Exfiltration Over Alternative Protocol
//   T1055  - Process Injection
//   T1059  - Command and Scripting Interpreter
//   T1059.001 - PowerShell
//   T1071  - Application Layer Protocol
//   T1071.001 - Web Protocols
//   T1078  - Valid Accounts
//   T1105  - Ingress Tool Transfer
//   T1190  - Exploit Public-Facing Application
//   T1486  - Data Encrypted for Impact
//   T1566  - Phishing
//   T1566.001 - Spearphishing Attachment
