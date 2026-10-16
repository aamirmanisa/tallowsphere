# 330 Tools You Can Build With Tallow

> Single binary. 20.5 MB (unverified — no release-build measurement). 130 direct crate dependencies (root Cargo.toml, 2026-09-16). 42+ stdlib crypto algorithms (18 registry-governed; no external audit).
> Post-quantum by default. Legal compliance at compile time.

> **Catalog note (2026-09-13):** This file is a *buildable-programs catalog* — 330 things you could build with Tallow — not a list of shipped-capability claims. Entries describe potential projects (e.g. item 83 ComplianceEngine, item 120 AIActAudit); check component availability against `docs/TALLOW-CAPABILITIES.md` and the repository before treating any entry as shipped.

---

## 1. Cybersecurity — Offensive (20)

| # | Tool | Description |
|---|------|-------------|
| 1 | **PortStorm** | Massively parallel port scanner with IP rotation and stealth timing profiles |
| 2 | **FuzzForge** | Protocol-aware fuzzer with coverage-guided mutation and crash triage |
| 3 | **WebRecon** | Automated web recon (subdomain enum, tech fingerprinting, endpoint discovery) |
| 4 | **CredSpray** | Distributed credential stuffing with rate limiting and CAPTCHA detection |
| 5 | **ExfilTunnel** | Covert data exfiltration over DNS, ICMP, and HTTP header channels |
| 6 | **PhishKit** | Phishing campaign framework with cloned page generation and credential capture |
| 7 | **SQLiProbe** | Automated SQL injection scanner with blind/time-based/union extraction |
| 8 | **XSSHunter** | Stored/reflected XSS payload generator and callback server |
| 9 | **C2Mesh** | C2 framework using DHT mesh networking with PQC-encrypted channels |
| 10 | **ShellDrop** | Reverse shell generator for 20+ platforms with polymorphic encoding |
| 11 | **WiFiCrack** | WPA2/WPA3 handshake capture and offline dictionary attack |
| 12 | **ADPwn** | Active Directory enumeration and privilege escalation path finder |
| 13 | **APIBreaker** | REST/GraphQL API security scanner with auth bypass and IDOR detection |
| 14 | **SSRFMap** | SSRF exploitation framework with cloud metadata extraction |
| 15 | **DirBuster** | High-speed directory and file brute-forcer with recursive crawling |
| 16 | **JWTForge** | JWT token manipulation, algorithm confusion, and key brute-forcing |
| 17 | **LDAPHarvest** | LDAP enumeration and password spraying for enterprise environments |
| 18 | **KerbeRoast** | Kerberos ticket extraction and offline service account cracking |
| 19 | **CloudPwn** | Multi-cloud misconfiguration scanner (open S3, public GCS, exposed Azure) |
| 20 | **ImplantBuilder** | Compile-time obfuscated implant generator with anti-analysis features |

---

## 2. Cybersecurity — Defensive (14)

| # | Tool | Description |
|---|------|-------------|
| 21 | **NetSentry** | Network intrusion detection with protocol anomaly detection |
| 22 | **LogForge** | High-throughput log aggregator with real-time pattern matching and alerting |
| 23 | **HoneyTrap** | Configurable honeypot deployer (SSH, HTTP, SMB, RDP, database protocols) |
| 24 | **FileIntegrity** | Filesystem integrity monitor with BLAKE3 checksums and tamper alerting |
| 25 | **WAFShield** | Web application firewall with ML-based request classification |
| 26 | **DNSGuard** | DNS sinkhole and query monitor for malware domain detection |
| 27 | **YaraEngine** | YARA rule engine for memory and disk scanning with real-time monitoring |
| 28 | **PacketInspect** | Deep packet inspection with protocol dissection and anomaly scoring |
| 29 | **EndpointAgent** | Lightweight EDR agent with process monitoring and behavioral analysis |
| 30 | **TLSAudit** | TLS configuration scanner checking cipher suites, cert chains, PQC readiness |
| 31 | **CredVault** | Secrets manager with Shamir secret sharing and hardware key integration |
| 32 | **AccessControl** | Zero-trust network access proxy with mTLS and policy enforcement |
| 33 | **BandwidthCop** | Network traffic shaper and DDoS mitigation engine |
| 34 | **ConfigDrift** | Infrastructure config drift detector with compliance baseline comparison |

---

## 3. Cybersecurity — Forensics & Incident Response (12)

| # | Tool | Description |
|---|------|-------------|
| 35 | **DiskCarver** | File carving engine recovering deleted files from raw disk images |
| 36 | **MemDump** | Memory acquisition and analysis with process reconstruction |
| 37 | **TimelineForge** | Forensic timeline generator aggregating filesystem, registry, and log events |
| 38 | **MalwareSandbox** | Automated malware detonation sandbox with behavioral reports |
| 39 | **ChainOfCustody** | Digital evidence management with cryptographic chain-of-custody logging |
| 40 | **EmailForensics** | Email header analysis, phishing indicator extraction, attachment scanning |
| 41 | **RegistryParser** | Windows registry hive parser for offline forensic analysis |
| 42 | **ArtifactCollector** | Remote triage tool collecting forensic artifacts across endpoints |
| 43 | **NetworkCapture** | Full packet capture with indexed storage and retroactive search |
| 44 | **IncidentBoard** | Incident response orchestration with playbook automation |
| 45 | **IOCExtractor** | Indicator of compromise extractor from documents, emails, and logs |
| 46 | **StegoDetect** | Steganography detection in images, audio, and video files |

---

## 4. Threat Intelligence (7)

| # | Tool | Description |
|---|------|-------------|
| 47 | **ThreatFeed** | Multi-source threat intelligence feed aggregator and correlator |
| 48 | **DarkWebMonitor** | Tor/I2P site crawler monitoring for leaked credentials and data |
| 49 | **MalwareRepo** | Malware sample repository with BLAKE3 indexing and YARA tagging |
| 50 | **AttackMapper** | MITRE ATT&CK technique mapper for incident reports and detection rules |
| 51 | **BrandWatch** | Brand impersonation and typosquatting domain monitor |
| 52 | **PasteMonitor** | Pastebin/GitHub/Telegram leak monitor with regex pattern matching |
| 53 | **CVETracker** | CVE database mirror with affected-package matching and priority scoring |

---

## 5. Privacy Tools (12)

| # | Tool | Description |
|---|------|-------------|
| 54 | **MeshVPN** | P2P VPN using WireGuard with PQC key exchange |
| 55 | **GhostChat** | E2E encrypted messenger with Double Ratchet and disappearing messages |
| 56 | **AnonRelay** | Onion-routing relay node for anonymous communication |
| 57 | **MetadataStrip** | Bulk metadata remover for images, documents, PDFs, and videos |
| 58 | **IdentityVault** | Self-sovereign identity wallet with BBS+ anonymous credentials |
| 59 | **TorBridge** | Pluggable transport bridge for censorship circumvention |
| 60 | **PrivacyDNS** | Encrypted DNS resolver (DoH/DoT) with query anonymization |
| 61 | **SecureDrop** | Anonymous whistleblower submission platform with air-gap support |
| 62 | **BurnerID** | Ephemeral identity generator for anonymous service registration |
| 63 | **TrafficMixer** | Network traffic padding and timing obfuscation |
| 64 | **LocationGuard** | GPS coordinate fuzzing and location privacy enforcement |
| 65 | **PrivacyAudit** | Website privacy policy analyzer and tracker detection scanner |

---

## 6. DevOps & Infrastructure (17)

| # | Tool | Description |
|---|------|-------------|
| 66 | **DeployForge** | Single-binary deployment with rolling updates and automatic rollback |
| 67 | **ContainerScan** | Container image vulnerability scanner with SBOM generation |
| 68 | **SecretSync** | Secrets rotation and distribution across environments with audit trail |
| 69 | **InfraProbe** | Infrastructure health checker (TCP/HTTP/DNS/TLS endpoint monitoring) |
| 70 | **ConfigVault** | Encrypted configuration management with environment-specific overlays |
| 71 | **BackupForge** | Incremental encrypted backup with deduplication and cloud targets |
| 72 | **CertBot** | Automated TLS certificate provisioning, renewal, and deployment |
| 73 | **GitGuard** | Pre-commit secret scanner and repository security policy enforcer |
| 74 | **PipelineRunner** | Lightweight CI/CD runner with sandboxed build execution |
| 75 | **ArtifactStore** | Binary artifact repository with content-addressable storage and signing |
| 76 | **LogShipper** | High-performance log collector with compression and encrypted transit |
| 77 | **ServiceMesh** | Lightweight service mesh sidecar with mTLS and traffic policy |
| 78 | **ChaosMonkey** | Controlled fault injection tool for resilience testing |
| 79 | **MigrationRunner** | Database schema migration engine with rollback and drift detection |
| 80 | **CronGuard** | Distributed cron scheduler with exactly-once execution and failure alerting |
| 81 | **FeatureGate** | Feature flag service with gradual rollout and A/B testing |
| 82 | **CanaryDeploy** | Canary deployment orchestrator with traffic splitting and metric comparison |

---

## 7. Enterprise Compliance & GRC (14)

| # | Tool | Description |
|---|------|-------------|
| 83 | **ComplianceEngine** | Multi-framework checker (GDPR enforced today; CRA/NIS2/DORA passes; CCPA/HIPAA/SOX target-only — no engine code) |
| 84 | **AuditTrail** | Tamper-proof audit log system with cryptographic chaining |
| 85 | **RiskMatrix** | Quantitative risk assessment engine with threat modeling |
| 86 | **PolicyCompiler** | Machine-readable policy language compiler for automated enforcement |
| 87 | **DPIAGenerator** | Data Protection Impact Assessment report generator |
| 88 | **ConsentManager** | User consent collection, storage, and revocation platform |
| 89 | **DataMapper** | Personal data flow mapping for ROPA (Records of Processing Activities) |
| 90 | **RetentionEnforcer** | Automated data retention and deletion scheduler with proof of deletion |
| 91 | **VendorRisk** | Third-party vendor risk assessment and continuous monitoring |
| 92 | **IncidentReporter** | Regulatory breach notification with jurisdiction-aware deadlines |
| 93 | **SBOMForge** | Software bill of materials generator with vulnerability correlation |
| 94 | **SupplyChainVerify** | SLSA-compliant build provenance verifier |
| 95 | **LicenseAudit** | Open source license compliance scanner and conflict detector |
| 96 | **SOCReport** | SOC 2 Type II evidence collector and report generator |

---

## 8. Financial & Fintech (14)

| # | Tool | Description |
|---|------|-------------|
| 97 | **PaymentGateway** | PCI-DSS compliant payment processing with tokenization |
| 98 | **FraudDetect** | Real-time transaction fraud scoring engine |
| 99 | **KYCVerify** | Know Your Customer identity verification with document/liveness checks |
| 100 | **AMLScreen** | Anti-money laundering transaction screening against sanctions lists |
| 101 | **TradingEngine** | Low-latency order matching engine with microsecond timestamps |
| 102 | **LedgerCore** | Double-entry accounting ledger with cryptographic audit trail |
| 103 | **InvoiceForge** | Compliant e-invoicing generator (Peppol, ZUGFeRD, Factur-X) |
| 104 | **RegulatoryReport** | Automated regulatory filing generator (MiFID II, EMIR, SFTR) |
| 105 | **CryptoExchange** | Cryptocurrency exchange order book with PQC-secured wallets |
| 106 | **HSMBridge** | Hardware Security Module integration layer for key ceremonies |
| 107 | **SwiftProxy** | SWIFT message parser, validator, and secure relay |
| 108 | **OpenBanking** | PSD2/Open Banking API gateway with consent management |
| 109 | **RiskEngine** | Real-time portfolio risk calculation (VaR, stress testing) |
| 110 | **TaxCompliance** | Multi-jurisdiction tax calculation and reporting engine |

---

## 9. AI/ML (12)

| # | Tool | Description |
|---|------|-------------|
| 111 | **AgentOrchestrator** | Multi-agent AI orchestration with sandboxed tool execution |
| 112 | **ModelGuard** | AI model I/O firewall with prompt injection detection |
| 113 | **DataPipeline** | Privacy-preserving ETL with differential privacy and anonymization |
| 114 | **FeatureStore** | Encrypted feature store with access control and lineage tracking |
| 115 | **TrainingVault** | Secure training data management with consent tracking and erasure |
| 116 | **ModelRegistry** | ML model versioning, signing, and deployment registry |
| 117 | **InferenceProxy** | Model inference gateway with rate limiting, caching, and audit |
| 118 | **SyntheticData** | Privacy-safe synthetic data generator preserving statistical properties |
| 119 | **LLMProxy** | LLM API gateway with token budgets, PII filtering, and response caching |
| 120 | **AIActAudit** | EU AI Act compliance checker for high-risk AI systems |
| 121 | **FederatedLearn** | Federated learning coordinator with secure aggregation (MPC/HE) |
| 122 | **EmbeddingVault** | Encrypted vector database for RAG with access-controlled retrieval |

---

## 10. Data Tools (12)

| # | Tool | Description |
|---|------|-------------|
| 123 | **WebScraper** | Compliant web scraping with robots.txt respect and rate limiting |
| 124 | **DataRoom** | Virtual data room with granular access, watermarking, and audit trail |
| 125 | **ETLEngine** | High-throughput extract-transform-load with schema validation |
| 126 | **DataAnonymizer** | k-anonymity/l-diversity/t-closeness anonymization engine |
| 127 | **SchemaRegistry** | Data schema versioning and compatibility checker |
| 128 | **DataQuality** | Data quality profiler (completeness, accuracy, consistency checks) |
| 129 | **StreamProcessor** | Real-time event stream processor with exactly-once semantics |
| 130 | **DataLake** | Encrypted data lake with column-level access control |
| 131 | **CSVForge** | High-performance CSV/Parquet/Arrow parser and transformer |
| 132 | **WebArchiver** | Website archiver with full page snapshots in WARC format |
| 133 | **PriceScraper** | E-commerce price monitoring with change detection and alerting |
| 134 | **APIAggregator** | Multi-API data aggregator with response normalization and caching |

---

## 11. Communication (8)

| # | Tool | Description |
|---|------|-------------|
| 135 | **SecureMail** | E2E encrypted email client with PQC and S/MIME |
| 136 | **SignalRelay** | Self-hosted Signal-protocol compatible messaging relay |
| 137 | **TeamChat** | Encrypted team communication with channels and file sharing |
| 138 | **VideoRelay** | Encrypted P2P video conferencing relay |
| 139 | **NotifyHub** | Multi-channel notification dispatcher (email, SMS, push, webhook, Slack) |
| 140 | **MailFilter** | Email security gateway with phishing detection and attachment sandboxing |
| 141 | **DeadDrop** | Asynchronous encrypted message board for anonymous communication |
| 142 | **RadioBridge** | Digital radio-to-IP bridge for emergency communication networks |

---

## 12. Government & Military (10)

| # | Tool | Description |
|---|------|-------------|
| 143 | **ClassifiedTransfer** | Air-gapped file transfer via QR and acoustic channels |
| 144 | **SIGINTCollector** | Signals intelligence metadata collector with legal framework enforcement |
| 145 | **CrossDomainGuard** | Cross-domain solution between classification levels |
| 146 | **SecureComms** | Tactical encrypted communication for field operations |
| 147 | **IntelFusion** | Multi-source intelligence fusion with source protection |
| 148 | **EmergencyBroadcast** | Mass emergency notification with mesh fallback |
| 149 | **VotingAudit** | Election system auditor with cryptographic ballot verification |
| 150 | **EmbassyVault** | Diplomatic cable encryption and archival system |
| 151 | **BorderControl** | Biometric document verification for border checkpoints |
| 152 | **SatComRelay** | Satellite communication encryption relay with burst transmission |

---

## 13. Healthcare (9)

| # | Tool | Description |
|---|------|-------------|
| 153 | **HIPAAVault** | HIPAA-compliant medical record storage with access audit trail |
| 154 | **PatientConsent** | Patient data consent management with granular permissions |
| 155 | **MedImageAnon** | Medical image DICOM anonymizer preserving diagnostic quality |
| 156 | **PrescriptionVerify** | Prescription authenticity verifier with digital signatures |
| 157 | **ClinicalTrialData** | Clinical trial data management with blinding and consent |
| 158 | **HealthExchange** | HL7/FHIR health data exchange with E2E encryption |
| 159 | **TelemedicineGateway** | Encrypted telemedicine session gateway with consent |
| 160 | **PharmacyChain** | Pharmaceutical supply chain tracker with anti-counterfeiting |
| 161 | **GenomicVault** | Encrypted genomic data storage with homomorphic query support |

---

## 14. Legal Tech (8)

| # | Tool | Description |
|---|------|-------------|
| 162 | **eDiscovery** | Electronic discovery with legal hold and privilege detection |
| 163 | **EvidenceChain** | Digital evidence locker with cryptographic chain of custody |
| 164 | **ContractAnalyzer** | Contract clause extraction and compliance checking |
| 165 | **LegalHold** | Litigation hold notification and data preservation |
| 166 | **CourtFiling** | Automated court document filing with format validation and signing |
| 167 | **IPMonitor** | Intellectual property infringement scanner across web and marketplaces |
| 168 | **DepositoryService** | Legal document notarization with timestamped cryptographic proof |
| 169 | **WitnessProtect** | Secure communication channel for witness protection programs |

---

## 15. IoT & Edge Computing (8)

| # | Tool | Description |
|---|------|-------------|
| 170 | **EdgeGateway** | IoT protocol translator and edge processing (MQTT, CoAP, Modbus) |
| 171 | **OTAUpdater** | Secure OTA firmware update with signed payloads |
| 172 | **SensorMesh** | Wireless sensor network coordinator with encrypted telemetry |
| 173 | **DeviceProvision** | IoT device provisioning and identity with certificate enrollment |
| 174 | **EdgeAnalytics** | On-device analytics for bandwidth-constrained environments |
| 175 | **SCADAGuard** | SCADA/ICS protocol monitor with anomaly detection |
| 176 | **FleetManager** | IoT device fleet management with remote config and diagnostics |
| 177 | **TelemetryRelay** | Compressed encrypted telemetry relay for satellite/LoRa/NB-IoT |

---

## 16. Blockchain & Web3 (11)

| # | Tool | Description |
|---|------|-------------|
| 178 | **HDWallet** | HD cryptocurrency wallet with PQC-ready key derivation |
| 179 | **ChainBridge** | Cross-chain bridge with threshold signature authorization |
| 180 | **DIDResolver** | Decentralized Identifier resolver and verifiable credential issuer |
| 181 | **SmartAudit** | Smart contract static analysis and vulnerability scanner |
| 182 | **NFTVault** | NFT metadata storage with provenance tracking and royalty enforcement |
| 183 | **DAOGovernance** | DAO voting with anonymous ballot casting (BBS+/ZK proofs) |
| 184 | **TokenGate** | Token-gated access control proxy for web applications |
| 185 | **MEVProtect** | MEV protection relay with encrypted transaction submission |
| 186 | **OracleNode** | Blockchain oracle node with authenticated data feeds and VRF |
| 187 | **MixerEngine** | Privacy-preserving token mixer with zero-knowledge proofs |
| 188 | **StakingProxy** | Staking pool manager with Shamir-split validator keys |

---

## 17. Media & Content (8)

| # | Tool | Description |
|---|------|-------------|
| 189 | **DRMEngine** | Digital rights management with license enforcement |
| 190 | **WatermarkEmbed** | Invisible digital watermark for images, video, and documents |
| 191 | **StreamEncrypt** | Live streaming encryption relay with DRM key rotation |
| 192 | **ContentFilter** | Content moderation proxy with hash-based known-material detection |
| 193 | **MediaForensics** | Image/video authentication and deepfake tampering detection |
| 194 | **PiracyMonitor** | Content piracy scanner across web, torrent, and streaming sites |
| 195 | **SecurePublish** | Encrypted document publishing with timed-release access |
| 196 | **PodcastHost** | Encrypted podcast distribution with subscriber-only feeds |

---

## 18. Education & Research (7)

| # | Tool | Description |
|---|------|-------------|
| 197 | **ExamVault** | Secure exam delivery and proctoring with anti-cheating |
| 198 | **ResearchData** | Research data management with FAIR compliance and reproducibility |
| 199 | **PeerReview** | Double-blind peer review with anonymous credential verification |
| 200 | **LabNotebook** | Tamper-proof electronic lab notebook with timestamped entries |
| 201 | **PlagiarismDetect** | Document plagiarism scanner with source attribution |
| 202 | **DatasetShare** | Privacy-preserving dataset sharing with differential privacy budgets |
| 203 | **CryptoTeach** | Interactive cryptography learning environment with visualization |

---

## 19. Consumer Applications (9)

| # | Tool | Description |
|---|------|-------------|
| 204 | **PasswordManager** | Zero-knowledge password manager with PQC and FROST backup |
| 205 | **SecureNotes** | Encrypted note-taking with cross-device sync |
| 206 | **PhotoVault** | Encrypted photo storage with client-side thumbnails |
| 207 | **FileLocker** | Drag-and-drop file encryption for non-technical users |
| 208 | **FamilyVault** | Shared family document safe with role-based access and inheritance |
| 209 | **PrivacyBrowser** | Hardened web browser with fingerprint randomization |
| 210 | **ContactGuard** | Encrypted address book with selective sharing and revocation |
| 211 | **TravelSafe** | Travel document vault with emergency dead-man-switch access |
| 212 | **DigitalWill** | Time-locked digital estate management with Shamir-split executor keys |

---

## 20. Developer Tools (15)

| # | Tool | Description |
|---|------|-------------|
| 213 | **DepAudit** | Dependency vulnerability scanner with transitive analysis |
| 214 | **CodeSign** | Binary and package signing with PQC signature schemes |
| 215 | **APIFuzz** | API endpoint fuzzer with OpenAPI spec-driven test generation |
| 216 | **BenchForge** | Microbenchmark runner with statistical analysis and regression detection |
| 217 | **DocGen** | API documentation generator from annotated source code |
| 218 | **LintEngine** | Extensible static analysis framework with custom rule authoring |
| 219 | **REPLShell** | Interactive language REPL with hot-reload and inspection |
| 220 | **LSPServer** | Language Server Protocol implementation for IDE integration |
| 221 | **CrashReport** | Privacy-safe crash reporting and symbol demangling service |
| 222 | **ProtoCompile** | Protocol buffer/FlatBuffer schema compiler with code generation |
| 223 | **MockServer** | HTTP/gRPC mock server with request recording and replay |
| 224 | **LoadTest** | Distributed load testing with IP rotation and real browser simulation |
| 225 | **GitCrypt** | Transparent git repository encryption for sensitive files |
| 226 | **SnippetRunner** | Sandboxed code snippet execution engine for playgrounds |
| 227 | **WASMToolchain** | WebAssembly compilation, optimization, and debugging toolkit |

---

## 21. Networking (13)

| # | Tool | Description |
|---|------|-------------|
| 228 | **DNSServer** | Authoritative/recursive DNS server with DNSSEC and DoH/DoT |
| 229 | **ProxyChain** | Multi-hop SOCKS5/HTTP proxy chainer with per-hop encryption |
| 230 | **TunnelForge** | Encrypted tunnel builder (TCP, UDP, QUIC) through firewalls |
| 231 | **NetMapper** | Network topology discovery and visualization |
| 232 | **BGPMonitor** | BGP route announcement monitor with hijack detection |
| 233 | **CertTransparency** | Certificate Transparency log monitor for domain surveillance |
| 234 | **NTPSecure** | Authenticated NTP server/client with NTS |
| 235 | **mDNSBrowser** | Multicast DNS service browser for local network discovery |
| 236 | **WireGuardManager** | WireGuard VPN configuration generator and peer manager |
| 237 | **TraceRoute** | Advanced traceroute with ASN lookup and latency histograms |
| 238 | **BandwidthTest** | Network bandwidth and latency measurement (iperf-compatible) |
| 239 | **PCAPAnalyzer** | Packet capture file analyzer with protocol stats and flow extraction |
| 240 | **DHCPServer** | Lightweight DHCP server with lease tracking |

---

## 22. Cloud & SaaS Infrastructure (10)

| # | Tool | Description |
|---|------|-------------|
| 241 | **APIGateway** | API gateway with rate limiting, auth, request transformation, audit |
| 242 | **MultiCloud** | Unified cloud storage abstraction (S3/GCS/Azure) with client-side encryption |
| 243 | **TenantIsolation** | Multi-tenant data isolation with per-tenant encryption keys |
| 244 | **WebhookRelay** | Reliable webhook delivery with retry, signing, dead-letter queue |
| 245 | **QueueEngine** | Persistent message queue with exactly-once delivery and encryption |
| 246 | **SessionManager** | Distributed session store with token rotation and anomaly detection |
| 247 | **EdgeCDN** | Edge content distribution node with cache poisoning protection |
| 248 | **RateLimiter** | Distributed rate limiting (sliding window + token bucket) |
| 249 | **HealthDashboard** | Service health aggregation dashboard with status page generation |
| 250 | **CostMonitor** | Multi-cloud spend tracker with anomaly detection and budget alerting |

---

## 23. Supply Chain & Manufacturing (5)

| # | Tool | Description |
|---|------|-------------|
| 251 | **AssetTracker** | Physical asset tracking with cryptographic provenance chain |
| 252 | **CounterfeitDetect** | Product authenticity verification using cryptographic serial numbers |
| 253 | **SupplyLedger** | Supply chain event ledger with multi-party verification |
| 254 | **QualityGate** | Manufacturing quality checkpoint with signed inspection records |
| 255 | **RecallManager** | Product recall notification and tracking system |

---

## 24. Energy & Utilities (4)

| # | Tool | Description |
|---|------|-------------|
| 256 | **SmartMeterGateway** | Smart meter data aggregator with privacy-preserving billing |
| 257 | **GridMonitor** | Power grid SCADA telemetry collector with anomaly alerting |
| 258 | **EnergyTrading** | P2P energy certificate trading platform |
| 259 | **UtilityAudit** | Utility infrastructure compliance auditor for NERC CIP |

---

## 25. Automotive & Transportation (5)

| # | Tool | Description |
|---|------|-------------|
| 260 | **V2XGateway** | Vehicle-to-everything communication gateway with PKI |
| 261 | **FleetTracker** | Encrypted fleet GPS tracking with driver privacy compliance |
| 262 | **EDRExtract** | Event Data Recorder (black box) forensic extraction tool |
| 263 | **TollVerify** | Electronic toll collection verification with privacy-preserving billing |
| 264 | **AvionicsLog** | Aircraft maintenance and flight data logging (tamper-proof) |

---

## 26. Real Estate (3)

| # | Tool | Description |
|---|------|-------------|
| 265 | **TitleChain** | Property title verification with cryptographic ownership history |
| 266 | **LeaseVault** | Encrypted lease document management with compliance checks |
| 267 | **PropTechID** | Property identity and inspection record management |

---

## 27. Insurance (3)

| # | Tool | Description |
|---|------|-------------|
| 268 | **ClaimVerify** | Insurance claim document verification with fraud detection |
| 269 | **ActuarialPipe** | Actuarial data pipeline with privacy-preserving computation |
| 270 | **PolicyEngine** | Insurance policy rules engine with regulatory compliance |

---

## 28. HR & Workforce (4)

| # | Tool | Description |
|---|------|-------------|
| 271 | **BackgroundCheck** | Employee background verification with consent tracking |
| 272 | **PayrollVault** | Encrypted payroll processing with multi-jurisdiction tax compliance |
| 273 | **WhistleblowerBox** | Anonymous employee reporting with zero-knowledge verification |
| 274 | **AccessReview** | Employee access certification and recertification workflow |

---

## 29. Journalism & Media (4)

| # | Tool | Description |
|---|------|-------------|
| 275 | **SourceProtect** | Journalist source protection with metadata-free communication |
| 276 | **LeakAnalyzer** | Leaked document analysis with redaction and watermark detection |
| 277 | **FactCheck** | Content provenance verifier using C2PA/digital signature chains |
| 278 | **ArchiveProof** | Web content archival with timestamped cryptographic proof |

---

## 30. Gaming (4)

| # | Tool | Description |
|---|------|-------------|
| 279 | **AntiCheat** | Game integrity monitor with memory scanning and behavior analysis |
| 280 | **MatchVerify** | Competitive match result verification with cryptographic commitments |
| 281 | **GameReplay** | Encrypted game replay recording and authenticated playback |
| 282 | **ItemEscrow** | Virtual item trading escrow with atomic swap guarantees |

---

## 31. Telecommunications (4)

| # | Tool | Description |
|---|------|-------------|
| 283 | **CDRProcessor** | Call detail record processor with privacy-compliant anonymization |
| 284 | **LAWFULIntercept** | Lawful intercept gateway with judicial warrant verification |
| 285 | **NumberPorting** | Phone number portability verification system |
| 286 | **SIPProxy** | Encrypted SIP proxy with TLS and SRTP for VoIP |

---

## 32. Agriculture (2)

| # | Tool | Description |
|---|------|-------------|
| 287 | **FarmTrace** | Agricultural product traceability from farm to retailer |
| 288 | **CropSensorNet** | Encrypted agricultural sensor mesh network |

---

## 33. Disaster Recovery (4)

| # | Tool | Description |
|---|------|-------------|
| 289 | **SiteFailover** | Automated site failover with encrypted state replication |
| 290 | **DataVault** | Immutable backup vault with geographic distribution and erasure coding |
| 291 | **CrisisComms** | Emergency communication platform with mesh fallback |
| 292 | **RecoveryTest** | Disaster recovery plan testing and validation automation |

---

## 34. Identity & Access Management (7)

| # | Tool | Description |
|---|------|-------------|
| 293 | **SSOGateway** | Single sign-on gateway with SAML/OIDC and PQC token signing |
| 294 | **MFAEngine** | Multi-factor auth with FIDO2/WebAuthn and TOTP |
| 295 | **PrivilegedAccess** | PAM with session recording and just-in-time elevation |
| 296 | **DirectorySync** | Identity directory synchronizer (LDAP, SCIM, cloud) |
| 297 | **CertAuthority** | Private CA with OCSP responder and CRL distribution |
| 298 | **AttributeAuthority** | Attribute-based access control with policy decision point |
| 299 | **BiometricGateway** | Biometric template storage with cancelable biometrics |

---

## 35. Archival & Records (4)

| # | Tool | Description |
|---|------|-------------|
| 300 | **DigitalArchive** | Long-term digital preservation with format migration |
| 301 | **RecordClassify** | Automated document classification with retention schedule enforcement |
| 302 | **RedactionEngine** | Bulk document redaction with machine-assisted PII detection |
| 303 | **TimeStampAuthority** | RFC 3161 compliant time stamping authority |

---

## 36. Science & Engineering (3)

| # | Tool | Description |
|---|------|-------------|
| 304 | **LabDataSync** | Laboratory instrument data collector with integrity verification |
| 305 | **SimulationVault** | Scientific simulation result storage with reproducibility metadata |
| 306 | **PatentWatch** | Patent filing monitor with prior art detection |

---

## 37. Retail & E-Commerce (4)

| # | Tool | Description |
|---|------|-------------|
| 307 | **PriceIntel** | Competitive pricing intelligence with compliant monitoring |
| 308 | **ReviewAuth** | Product review authenticity verifier with bot detection |
| 309 | **LoyaltyLedger** | Privacy-preserving customer loyalty program engine |
| 310 | **InventorySync** | Multi-channel inventory synchronization with encrypted transit |

---

## 38. Cross-Cutting / Platform (20)

| # | Tool | Description |
|---|------|-------------|
| 311 | **PQCMigrator** | Scan codebases and migrate classical crypto to PQC algorithms |
| 312 | **ShamirSplit** | Secret splitting and reconstruction for key ceremonies |
| 313 | **AirGapBridge** | Bidirectional air-gap transfer via QR codes and acoustic modem |
| 314 | **ZeroTrustProxy** | Context-aware reverse proxy implementing BeyondCorp zero-trust |
| 315 | **ComplianceDiff** | Regulation change tracker that diffs legal frameworks and flags impact |
| 316 | **TamperProofLog** | Append-only log with hash chain and independent verifier |
| 317 | **DataSovereignty** | Data residency enforcer keeping data within jurisdictional boundaries |
| 318 | **PrivacyProxy** | HTTP proxy stripping tracking headers, cookies, and fingerprinting JS |
| 319 | **BinaryPacker** | Single-binary app packer embedding assets, configs, and runtime |
| 320 | **CryptoSwitch** | Algorithm agility layer enabling hot-swap of crypto primitives |
| 321 | **ThresholdSigner** | Distributed threshold signing using FROST for multi-party auth |
| 322 | **BlindAuction** | Sealed-bid auction with cryptographic commitment and reveal |
| 323 | **SecureRNG** | Hardware-backed random number generation service with health monitoring |
| 324 | **CanaryToken** | Deployable canary token generator (DNS, HTTP, file, database) |
| 325 | **HashChainDB** | Append-only database with Merkle tree verification for audit |
| 326 | **PolicyAsCode** | Compliance policy compiler translating regulations into executable checks |
| 327 | **CryptoInventory** | Enterprise cryptographic asset inventory and PQC readiness assessment |
| 328 | **OfflineSync** | Conflict-free offline-first data sync with encrypted merge |
| 329 | **QuarantineVault** | Malware quarantine storage with encrypted containment |
| 330 | **EphemeralEnv** | Self-destructing temporary compute environments for sensitive operations |

---

## Summary

| Category | Count |
|----------|-------|
| Cybersecurity — Offensive | 20 |
| Cybersecurity — Defensive | 14 |
| Cybersecurity — Forensics & IR | 12 |
| Threat Intelligence | 7 |
| Privacy Tools | 12 |
| DevOps & Infrastructure | 17 |
| Enterprise Compliance & GRC | 14 |
| Financial & Fintech | 14 |
| AI/ML | 12 |
| Data Tools | 12 |
| Communication | 8 |
| Government & Military | 10 |
| Healthcare | 9 |
| Legal Tech | 8 |
| IoT & Edge Computing | 8 |
| Blockchain & Web3 | 11 |
| Media & Content | 8 |
| Education & Research | 7 |
| Consumer Applications | 9 |
| Developer Tools | 15 |
| Networking | 13 |
| Cloud & SaaS Infrastructure | 10 |
| Supply Chain & Manufacturing | 5 |
| Energy & Utilities | 4 |
| Automotive & Transportation | 5 |
| Real Estate | 3 |
| Insurance | 3 |
| HR & Workforce | 4 |
| Journalism & Media | 4 |
| Gaming | 4 |
| Telecommunications | 4 |
| Agriculture | 2 |
| Disaster Recovery | 4 |
| Identity & Access Management | 7 |
| Archival & Records | 4 |
| Science & Engineering | 3 |
| Retail & E-Commerce | 4 |
| Cross-Cutting / Platform | 20 |
| **TOTAL** | **330** |

---

*Built with Tallow v0.4.0 — 495,872 lines of Rust in src/ (recount 2026-09-16), 42+ stdlib crypto algorithms (18 registry-governed; no external audit), 31 compiler passes, single binary deployment.*
