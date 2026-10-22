// tallow.transfer — BLAKE3 Bao chunking, delta sync, file vault, fast copy,
// real reed-solomon-simd erasure coding, progress tracking, resume/checkpoints,
// bandwidth limiting, directory encryption, LZ4 compression, memory-mapped I/O

// ── Chunk Info ──

struct ChunkInfo {
    index: i64,
    offset: i64,
    size: i64,
    hash: String,
}

// ── File Entry (for delta scan) ──

struct FileEntry {
    path: String,
    size: i64,
    hash: String,
    modified_epoch: i64,
}

// ── Delta Result ──

struct DeltaResult {
    added: []String,
    removed: []String,
    modified: []String,
    unchanged: i64,
    total_changed_bytes: i64,
}

// ── Copy Stats ──

struct CopyStats {
    files_copied: i64 = 0,
    dirs_created: i64 = 0,
    bytes_copied: i64,
    elapsed_ms: i64,
    throughput_mbps: f64 = 0.0,
}

// ── Vault Results ──

struct EncryptResult {
    input_size: i64,
    output_size: i64,
    encrypted: bool,
    algo: String,
}

struct DecryptResult {
    output_size: i64,
    decrypted: bool,
}

// ── Compressibility ──

struct CompressibilityResult {
    entropy: f64,
    compressible: bool,
    recommended_algo: String,
}

// ── Manifest ──

struct ManifestInfo {
    root_hash: String,
    size: i64,
    chunk_count: i64,
    timestamp: i64,
}

// ══════════════════════════════════════════════════════════════════
// Transfer — BLAKE3 hashing and Bao chunking
// ══════════════════════════════════════════════════════════════════

/// Hash an entire file with BLAKE3 (streaming, 64KB buffer)
// native: BLAKE3 file hash → hex string
native fn Transfer.hash(path: String) -> String

/// Split file into chunks and compute per-chunk BLAKE3 hashes
// native: chunk file, return array of ChunkInfo
native fn Transfer.chunk(path: String, chunk_size: i64 = 262144) -> []ChunkInfo

/// Build binary Merkle tree from chunk hashes → root hash
// native: binary Merkle tree → root hex hash
native fn Transfer.tree_hash(chunks: []ChunkInfo) -> String

/// Create a transfer manifest (JSON) for verification
// native: JSON manifest string
native fn Transfer.manifest(root_hash: String, size: i64, chunks: []ChunkInfo) -> String

// ══════════════════════════════════════════════════════════════════
// FileCopy — OS-optimized file and directory copy
// ══════════════════════════════════════════════════════════════════

/// Copy a single file (uses OS copy_file_range/sendfile when available)
// native: fast single-file copy
native fn FileCopy.copy(src: String, dst: String) -> CopyStats

/// Copy an entire directory recursively
// native: recursive directory copy
native fn FileCopy.copy_dir(src: String, dst: String) -> CopyStats

// ══════════════════════════════════════════════════════════════════
// FileVault — AES-256-GCM file encryption with Argon2id key derivation
// ══════════════════════════════════════════════════════════════════

/// Encrypt a file to .nixv vault format
// native: Argon2id + AES-256-GCM → NIXV file
native fn FileVault.encrypt(input: String, output: String, password: String) -> EncryptResult

/// Decrypt a .nixv vault file
// native: decrypt NIXV file → plaintext
native fn FileVault.decrypt(input: String, output: String, password: String) -> DecryptResult

/// Encrypt a text string, return hex-encoded ciphertext
// native: Argon2id + AES-256-GCM → hex
native fn FileVault.encrypt_text(text: String, password: String) -> String

/// Decrypt hex-encoded ciphertext to plaintext string
// native: decrypt hex → plaintext
native fn FileVault.decrypt_text(encrypted: String, password: String) -> String

// ══════════════════════════════════════════════════════════════════
// DeltaSync — Directory scanning and diff computation
// ══════════════════════════════════════════════════════════════════

/// Scan a directory recursively, BLAKE3-hash each file
// native: recursive directory scan with BLAKE3 hashes
native fn DeltaSync.scan(dir_path: String) -> []FileEntry

/// Compare two scans and compute the delta
// native: hash-based diff → added/removed/modified
native fn DeltaSync.diff(old_scan: []FileEntry, new_scan: []FileEntry) -> DeltaResult

// ══════════════════════════════════════════════════════════════════
// Compress — zstd compression with compressibility detection
// ══════════════════════════════════════════════════════════════════

/// Compress data with specified algorithm (default: zstd level 3)
// native: compress → hex string
native fn Compress.compress(data: String, algo: String = "zstd", level: i64 = 3) -> String

/// Decompress hex-encoded compressed data
// native: decompress hex → plaintext
native fn Compress.decompress(data: String, algo: String = "zstd") -> String

/// Detect data compressibility via Shannon entropy
// native: entropy analysis → recommendation
native fn Compress.detect(data: String) -> CompressibilityResult

// ══════════════════════════════════════════════════════════════════
// Phase 56: Network Transfer Protocol — QUIC-based transfer types
// ══════════════════════════════════════════════════════════════════

// ── Transfer Session ──

struct TransferSession {
    session_id: String,
    root_hash: String,
    total_size: i64,
    chunk_count: i64,
    chunk_hashes: []String,
    status: String,
    encrypt: bool,
    recipient: String,
    created_at: String,
}

struct TransferProgress {
    bytes_transferred: i64,
    bytes_total: i64,
    percent: f64,
    chunks_done: i64,
    chunks_total: i64,
    elapsed_ms: i64,
    throughput_mbps: f64,
    status: String,
}

/// Create a send session: BLAKE3 hash, chunk data, build Merkle tree
// native: create TransferManifest with BLAKE3 chunks + tree hash
native fn TransferSession.send(data: String, recipient: String, encrypt: bool = true) -> TransferSession

/// Create a receive session from a manifest (JSON or TransferSession struct)
// native: parse manifest, create receive session
native fn TransferSession.receive(manifest: String) -> TransferSession

/// Get transfer progress/status for a session
// native: query session state → progress struct
native fn TransferSession.status(session: TransferSession) -> TransferProgress

// ── Transfer Stream (QUIC multi-stream) ──

struct TransferStream {
    stream_id: String,
    session_id: String,
    stream_type: String,
    bytes_sent: i64,
    open: bool,
}

/// Create a new stream for a session
// native: "reliable" (ordered) or "unreliable" (datagrams)
native fn TransferStream.create(session_id: String, stream_type: String = "reliable") -> TransferStream

/// Write data to a stream (immutable update, returns new stream)
// native: increment bytes_sent by data length
native fn TransferStream.write(stream: TransferStream, data: String) -> TransferStream

/// Close a stream
// native: set open = false
native fn TransferStream.close(stream: TransferStream) -> TransferStream

// ── Erasure Coding (REAL reed-solomon-simd) ──

struct ErasureEncoded {
    k: i64,              // data shard count
    n: i64,              // total shard count (data + recovery)
    shard_size: i64,     // bytes per shard
    original_size: i64,  // original data size in bytes
    symbols: []String,   // hex-encoded shards
    overhead: f64,
    systematic: bool,
    codec: String,       // "reed-solomon-simd"
    data_size: i64,
}

struct ErasureDecoded {
    k: i64,
    symbols_used: i64,
    decoded: bool,
    data: String,         // recovered original data
    shard_size: i64,
    original_size: i64,
    codec: String,
    symbols: []String,
}

struct ErasureStatus {
    k: i64,
    n: i64,
    received: i64,
    decodable: bool,
    deficit: i64,
    recovery_percent: f64,
}

/// Encode data with REAL reed-solomon-simd erasure coding
// native: reed-solomon-simd systematic encoding, 10 data shards + ceil(10*overhead) recovery
native fn ErasureCode.encode(data: String, overhead: f64 = 0.5) -> ErasureEncoded

/// Decode from received symbols (need >= k original shards to succeed)
// native: reed-solomon-simd decode, recovers original data
native fn ErasureCode.decode(symbols: []String, k: i64) -> Result<ErasureDecoded>

/// Check erasure coding status (decodable, deficit, recovery percent)
// native: compute decodability metrics
native fn ErasureCode.status(encoded: ErasureEncoded, received: i64) -> ErasureStatus

// ── Multi-Path Discovery ──

struct NetworkPath {
    name: String,
    ip: String,
    is_loopback: bool,
    is_up: bool,
    estimated_bandwidth_mbps: f64,
}

struct PathEstimate {
    total_bandwidth_mbps: f64,
    path_count: i64,
    recommended_streams_per_path: i64,
    total_recommended_streams: i64,
}

/// Discover local network interfaces
// native: enumerate interfaces, return array of NetworkPath
native fn NetworkPath.discover() -> []NetworkPath

/// Estimate aggregate bandwidth across paths
// native: sum bandwidths, recommend stream count
native fn NetworkPath.estimate(paths: []NetworkPath) -> PathEstimate

// ══════════════════════════════════════════════════════════════════
// Phase 57: Multi-peer Swarm, DHT discovery, Transfer Manifest
// ══════════════════════════════════════════════════════════════════

// ── Peer ──

struct Peer {
    peer_id: String,
    address: String,
    port: i64,
    connected: bool,
    bandwidth_mbps: i64,
    latency_ms: i64,
    chunks_served: i64,
}

struct AnnounceResult {
    peer_id: String,
    root_hash: String,
    announced: bool,
    ttl_seconds: i64,
}

/// Create a peer descriptor
// native: BLAKE3(address:port) as peer_id
native fn Peer.create(address: String, port: i64) -> Peer

/// Announce peer availability for a root hash
// native: simulated DHT announce
native fn Peer.announce(peer: Peer, root_hash: String) -> AnnounceResult

// ── Swarm ──

struct Swarm {
    swarm_id: String,
    root_hash: String,
    peers: []Peer,
    active_downloads: i64,
    bytes_per_second: i64,
}

struct SwarmStatus {
    peer_count: i64,
    total_bandwidth_mbps: i64,
    active: bool,
    root_hash: String,
}

struct Assignment {
    peer_id: String,
    chunk_indices: []i64,
}

struct Schedule {
    assignments: []Assignment,
    strategy: String,
}

/// Create a new swarm for a given root hash
// native: BLAKE3("swarm:"+root_hash) as swarm_id
native fn Swarm.create(root_hash: String) -> Swarm

/// Add a peer to a swarm (immutable update)
// native: append peer, recalculate bandwidth
native fn Swarm.add_peer(swarm: Swarm, peer: Peer) -> Swarm

/// Remove a peer from a swarm by peer_id
// native: filter by peer_id, recalculate bandwidth
native fn Swarm.remove_peer(swarm: Swarm, peer_id: String) -> Swarm

/// Get swarm status summary
// native: peer count, total bandwidth, active flag
native fn Swarm.status(swarm: Swarm) -> SwarmStatus

/// Schedule chunk assignments across peers (round-robin)
// native: round-robin distribution
native fn Swarm.schedule(swarm: Swarm, chunks_needed: []i64) -> Schedule

// ── DHT (real UDP transport, in-process store; no iterative Kademlia routing) ──
//
// `Dht.create` binds a real UDP socket and derives a BLAKE3 node id; `Dht.announce` stores locally and
// sends ANNOUNCE to every known peer; `Dht.lookup` reads the local store first, then asks peers. What is
// absent is the *routing* — there is no peer discovery and no iterative lookup, and `routing_table_size`
// is a constant. A node whose bind failed reports `mode: "memory"`, so the degradation is visible.

struct DhtNode {
    node_id: String,
    routing_table_size: i64,
    stored_keys: i64,
    address: String,
    port: i64,
}

struct DhtAnnounce {
    key: String,
    stored: bool,
    replicas: i64,
    ttl_seconds: i64,
}

struct DhtLookup {
    key: String,
    found: bool,
    value: String,
    hops: i64,
    latency_ms: i64,
}

/// Create a simulated Kademlia DHT node
// native: BLAKE3(node_id) as node_id
native fn Dht.create(node_id: String) -> DhtNode

/// Store a key-value pair in the DHT
// native: simulated DHT store
native fn Dht.announce(dht: DhtNode, key: String, value: String) -> DhtAnnounce

/// Look up a key in the DHT
// native: simulated DHT lookup
native fn Dht.lookup(dht: DhtNode, key: String) -> DhtLookup

// ── Manifest URL / QR ──

/// Encode a manifest JSON to a tallow:// transfer URL
// native: base64url encode -> "tallow://transfer/base64"
native fn Manifest.to_url(manifest_json: String) -> String

/// Decode a tallow:// transfer URL back to manifest JSON
// native: extract base64, decode -> JSON
native fn Manifest.from_url(url: String) -> String

/// Generate a text QR code representation for a manifest
// native: "QR[tallow://transfer/short_hash...] (byte_count bytes)"
native fn Manifest.to_qr(manifest_json: String) -> String

// ══════════════════════════════════════════════════════════════════
// Phase 58: Real Transfer — Progress, Checkpoints, Bandwidth, Dir Enc
// ══════════════════════════════════════════════════════════════════

// ── Progress Tracking ──

struct ProgressTracker {
    total: i64,
    current: i64,
    label: String,
    started_at: String,
    started_ms: i64,
    bytes_per_sec: i64,
    eta_seconds: i64,
    percent: f64,
}

/// Create a progress tracker
// native: create tracker with timestamps
native fn ProgressTracker.create(total: i64, label: String = "Transferring") -> ProgressTracker

/// Update progress by increment amount
// native: update current, percent, bps, eta
native fn ProgressTracker.update(tracker: ProgressTracker, increment: i64 = 1) -> ProgressTracker

// ── Resume / Checkpoint ──

struct Checkpoint {
    transfer_id: String,
    found: bool,
    saved: bool,
    deleted: bool,
    data: String,
    path: String,
    size_bytes: i64,
}

/// Save transfer state to a checkpoint file (atomic write)
// native: JSON serialize, atomic write (.tmp + rename)
native fn Checkpoint.save(transfer_id: String, state: any) -> Checkpoint

/// Load a checkpoint (returns found=false if no checkpoint exists)
// native: read .tallow_checkpoint_id.json
native fn Checkpoint.load(transfer_id: String) -> Checkpoint

/// Delete a checkpoint file
// native: remove checkpoint file
native fn Checkpoint.delete(transfer_id: String) -> Checkpoint

// ── Bandwidth Limiting ──

struct BandwidthLimit {
    limit_mbps: f64,
    bytes_per_sec: i64,
    active: bool,
    burst_bytes: i64,
}

/// Create a bandwidth limiter
// native: calculate bytes_per_sec from Mbps
native fn BandwidthLimit.create(limit_mbps: f64) -> BandwidthLimit

/// Calculate throttle delay in ms given current transfer stats
// native: returns sleep_ms needed to stay under limit (0 if under)
native fn BandwidthLimit.throttle(bytes_sent: i64, elapsed_ms: i64, bytes_per_sec: i64) -> i64

// ── LAN Discovery ──

struct LanPeer {
    ip: String,
    hostname: String,
    port: i64,
    self_node: bool,
}

/// Discover peers on the local network
// native: enumerate local interfaces, return peer list
native fn LanDiscovery.discover() -> []LanPeer

// ── Copy with Metadata ──

struct CopyResult {
    bytes_copied: i64,
    metadata_preserved: bool,
    mtime_preserved: bool,
    src: String,
    dst: String,
}

/// Copy file preserving metadata (modification time, permissions)
// native: std::fs::copy + filetime mtime preservation
native fn FileCopy.copy_metadata(src: String, dst: String) -> CopyResult

// ── Directory Encryption ──

struct VaultDirResult {
    files_encrypted: i64,
    files_decrypted: i64,
    total_bytes: i64,
    output_dir: String,
    encrypted: bool,
    decrypted: bool,
    errors: i64,
}

/// Encrypt all files in a directory with AES-256-GCM + Argon2id (per-file keys)
// native: walk directory, encrypt each file to .enc format
native fn FileVault.encrypt_dir(input: String, output: String, password: String) -> VaultDirResult

/// Decrypt all .enc files in a directory
// native: walk directory, decrypt each .enc file
native fn FileVault.decrypt_dir(input: String, output: String, password: String) -> VaultDirResult

// ── Memory-Mapped I/O ──

struct MmapResult {
    size: i64,
    hash: String,
    path: String,
}

/// Memory-map a file for fast reading and return its BLAKE3 hash
// native: memmap2 read-only mapping + BLAKE3 hash
native fn Mmap.read(path: String) -> MmapResult

// ── LZ4 Compression (fast path for transfer) ──

struct CompressResult {
    data: String,
    original_size: i64,
    compressed_size: i64,
    ratio: f64,
    algo: String,
}

/// Compress data with LZ4 (fastest compression, ideal for transfer)
// native: lz4_flex compress_prepend_size → hex
native fn Lz4.compress(data: String) -> CompressResult

/// Decompress LZ4 hex data
// native: lz4_flex decompress_size_prepended
native fn Lz4.decompress(data: String) -> String

// ══════════════════════════════════════════════════════════════════
// Phase 59: QUIC Network Transfer — Real quinn-backed file transfer
// ══════════════════════════════════════════════════════════════════

// ── QuicServer ──

struct QuicServer {
    address: String,
    port: i64,
    listening: bool,
    protocol: String,
    tls: String,
}

// ── QuicConnection ──

struct QuicConnection {
    remote_address: String,
    connected: bool,
    rtt_ms: f64,
    protocol: String,
}

// ── TransferResult ──

struct TransferResult {
    file: String,
    hash: String,
    size: i64,
    chunks: i64,
    bytes_sent: i64,
    protocol: String,
    rtt_ms: f64,
    sent: bool,
}

// ── ReceiveResult ──

struct ReceiveResult {
    filename: String,
    size: i64,
    bytes_received: i64,
    verified: bool,
    protocol: String,
    output_dir: String,
}

// ── SendResult (bytes) ──

struct SendResult {
    bytes_sent: i64,
    hash: String,
    protocol: String,
    sent: bool,
}

// ── QuicStatus ──

struct QuicStatus {
    available: bool,
    library: String,
    tls: String,
    congestion: String,
    max_streams: i64,
    mtu: i64,
}

// ══════════════════════════════════════════════════════════════════
// QuicTransfer — Real QUIC file transfer (quinn + rustls TLS 1.3)
// ══════════════════════════════════════════════════════════════════

/// Start a QUIC server on the given address (default 0.0.0.0:6881)
// native: quinn Endpoint::server with self-signed rcgen cert
native fn QuicTransfer.listen(addr: String = "0.0.0.0:6881") -> QuicServer

/// Connect to a QUIC server
// native: quinn Endpoint::client with insecure cert verification
native fn QuicTransfer.connect(addr: String, server_name: String = "tallow-transfer") -> QuicConnection

/// Send a file over QUIC (chunked, BLAKE3-verified)
// native: open uni stream, send header + chunks, BLAKE3 hash
native fn QuicTransfer.send_file(path: String, dest: String) -> TransferResult

/// Receive a file over QUIC (BLAKE3-verified, atomic write)
// native: accept uni stream, read header + data, verify BLAKE3
native fn QuicTransfer.receive(addr: String = "0.0.0.0:6881", output_dir: String = ".", timeout: i64 = 30) -> ReceiveResult

/// Send raw bytes over QUIC
// native: open uni stream, framed write
native fn QuicTransfer.send_bytes(data: String, dest: String) -> SendResult

/// Get QUIC subsystem status and capabilities
// native: library version, TLS version, congestion, MTU
native fn QuicTransfer.status() -> QuicStatus

/// Resume an interrupted file send from a byte offset
// native: QUIC send with resume header (total_size + offset + hash)
native fn QuicTransfer.send_resume(path: String, dest: String, offset: i64 = 0) -> TransferResult

// ══════════════════════════════════════════════════════════════════
// Phase 60: Code Phrase Pairing, Relay Server, Resume
// ══════════════════════════════════════════════════════════════════

// ── TransferCode — croc-style code phrase ──

struct TransferCode {
    code: String,
    port: i64,
}

struct CodeSession {
    code: String,
    port: i64,
}

/// Generate a random code phrase (format: NNN-word-word-word)
// native: random 3-digit number + 3 phonetically distinct words
native fn TransferCode.generate() -> TransferCode

/// Resolve a code phrase to its deterministic port and session
// native: BLAKE3(code) -> port (10000-65000) + session key
native fn TransferCode.resolve(code: String) -> CodeSession

// ── Relay — TCP relay server for NAT traversal ──

struct RelayServer {
    address: String,
    port: i64,
    running: bool,
    protocol: String,
}

struct RelaySendResult {
    code: String,
    file: String,
    size: i64,
    hash: String,
    relay: String,
    sent: bool,
}

struct RelayReceiveResult {
    filename: String,
    size: i64,
    verified: bool,
    output_dir: String,
    code: String,
}

/// Start a TallowTransfer relay server on the given port
// native: bind TCP listener, match sender/receiver by code phrase
native fn Relay.start(port: i64 = 6880) -> RelayServer

/// Send a file via relay server (code phrase matched)
// native: connect to relay, send TALLOW-SEND header + code + file data
native fn Relay.send(file: String, relay_addr: String = "relay.tallow-lang.org:6880", code: String = "") -> RelaySendResult

/// Receive a file via relay server (code phrase matched)
// native: connect to relay, send TALLOW-RECV header + code, receive file
native fn Relay.receive(code: String, output_dir: String = ".", relay_addr: String = "relay.tallow-lang.org:6880") -> RelayReceiveResult

// ══════════════════════════════════════════════════════════════════
// Phase 61: Multi-File Send, Folder Send, Compression, Parallel
// Streams, Bandwidth Limiting, Watch Mode
// ══════════════════════════════════════════════════════════════════

// ── MultiTransferResult ──

struct MultiTransferResult {
    files_count: i64,
    total_size: i64,
    entries: []FileEntry,
    destination: String,
    status: String,
}

// ── DirTransferResult ──

struct DirTransferResult {
    directory: String,
    files_count: i64,
    uncompressed_size: i64,
    compressed_size: i64,
    compression_ratio: f64,
    hash: String,
    compressed: bool,
    destination: String,
    ready: bool,
}

// ── CompressedTransfer ──

struct CompressedTransfer {
    original_size: i64,
    compressed_size: i64,
    ratio: f64,
    algorithm: String,
    data_hex: String,
}

// ── ParallelConfig ──

struct ParallelConfig {
    streams: i64,
    chunk_size: i64,
    strategy: String,
    total_bandwidth_estimate: String,
}

// ── BandwidthConfig ──

struct BandwidthConfig {
    limit_str: String,
    bytes_per_sec: i64,
    bits_per_sec: i64,
    active: bool,
}

// ── WatchSession ──

struct WatchSession {
    directory: String,
    interval_ms: i64,
    files_tracked: i64,
    total_size: i64,
    watching: bool,
    snapshot: []WatchEntry,
}

// ── WatchChanges ──

struct WatchChanges {
    has_changes: bool,
    added: []String,
    removed: []String,
    modified: []String,
    new_snapshot: []WatchEntry,
}

// ── WatchEntry ──

struct WatchEntry {
    path: String,
    hash: String,
    size: i64,
}

// ══════════════════════════════════════════════════════════════════
// MultiTransfer — Multi-file and directory transfer operations
// ══════════════════════════════════════════════════════════════════

/// Prepare multiple files for transfer (builds manifest with BLAKE3 hashes)
// native: walk files/dirs, build manifest with BLAKE3 hashes
native fn MultiTransfer.prepare(files: []String, dest: String) -> MultiTransferResult

/// Archive and send an entire directory (optional zstd compression)
// native: archive directory to binary format, compress with zstd, return metadata
native fn MultiTransfer.send_dir(dir: String, dest: String, compress: bool = true) -> DirTransferResult

// ══════════════════════════════════════════════════════════════════
// TransferCompress — Compression during transfer
// ══════════════════════════════════════════════════════════════════

/// Compress data for transfer (auto-detects algorithm: zstd, lz4, or none)
// native: Shannon entropy check, zstd for normal, lz4 for large, skip for high-entropy
native fn TransferCompress.compress(data: String, algo: String = "auto") -> CompressedTransfer

/// Decompress transfer data back to original
// native: zstd/lz4/none decompression from hex-encoded data
native fn TransferCompress.decompress(data_hex: String, algo: String) -> String

// ══════════════════════════════════════════════════════════════════
// ParallelConfig — Parallel stream configuration
// ══════════════════════════════════════════════════════════════════

/// Create a parallel stream configuration (default: 4 streams, 256KB chunks)
// native: configure stream count and chunk size for transfer
native fn ParallelConfig.create(streams: i64 = 4, chunk_size: i64 = 262144) -> ParallelConfig

// ══════════════════════════════════════════════════════════════════
// BandwidthConfig — Bandwidth limiting
// ══════════════════════════════════════════════════════════════════

/// Apply bandwidth limit to transfer (e.g., "10M" = 10 Mbps, "500K", "1G")
// native: parse bandwidth limit string, compute bytes/sec
native fn BandwidthConfig.apply(limit: String) -> BandwidthConfig

// ══════════════════════════════════════════════════════════════════
// WatchSession — Directory watching and change detection
// ══════════════════════════════════════════════════════════════════

/// Start watching a directory for changes (polling-based, BLAKE3 hashes)
// native: snapshot directory with BLAKE3 hashes of each file
native fn WatchSession.start(dir: String, interval_ms: i64 = 1000) -> WatchSession

/// Check for changes since last snapshot
// native: re-scan directory, compare BLAKE3 hashes, report added/removed/modified
native fn WatchSession.check(session: WatchSession) -> WatchChanges

// ══════════════════════════════════════════════════════════════════
// Phase 62: Signed Manifests, Immutable Audit Log, Expiring Transfers,
//           Retention Policies, File Type Validation, ML-KEM-1024 Config
// ══════════════════════════════════════════════════════════════════

// ── Signed Manifest (Non-Repudiation) ──

struct SignedManifest {
    manifest: String,
    signature: String,
    sender: String,
    timestamp: String,
    signed: bool,
}

struct ManifestVerification {
    valid: bool,
    sender: String,
    signature_match: bool,
}

struct TransferReceipt {
    file_hash: String,
    receiver: String,
    timestamp: String,
    receipt_hash: String,
    non_repudiation: bool,
}

/// Create a cryptographically signed transfer manifest (BLAKE3 keyed hash)
// native: BLAKE3 keyed hash signature over manifest JSON
native fn SignedManifest.create(files_json: String, sender_id: String = "anonymous") -> SignedManifest

/// Verify a signed manifest's integrity
// native: recompute BLAKE3 keyed hash, compare
native fn SignedManifest.verify(manifest: String, signature: String, sender_id: String) -> ManifestVerification

/// Create a transfer receipt (non-repudiation proof of delivery)
// native: BLAKE3 hash of (file_hash || receiver_id || timestamp)
native fn TransferReceipt.create(file_hash: String, receiver_id: String = "receiver") -> TransferReceipt

// ── Immutable Audit Log (BLAKE3-chained) ──

struct AuditEntry {
    index: i64,
    timestamp: String,
    action: String,
    details: String,
    prev_hash: String,
    entry_hash: String,
}

struct AuditVerification {
    valid: bool,
    entries: i64,
    chain_intact: bool,
}

struct AuditSaveResult {
    path: String,
    entries: i64,
    saved: bool,
}

/// Log a transfer action to the immutable audit trail
// native: BLAKE3-chained append to global audit log
native fn AuditLog.log(action: String, details: String = "") -> AuditEntry

/// Verify integrity of the entire audit chain
// native: walk chain, verify each entry's hash
native fn AuditLog.verify() -> AuditVerification

/// Export the audit log as JSON
// native: serialize all entries to JSON array
native fn AuditLog.export() -> String

/// Save audit log to a file
// native: write TSV to file
native fn AuditLog.save(path: String = "tallow_audit.log") -> AuditSaveResult

// ── Expiring Transfers ──

struct ExpiringTransfer {
    transfer_id: String,
    max_downloads: i64,
    downloads_remaining: i64,
    expire_hours: i64,
    created_at: String,
    expires_at: String,
    expired: bool,
}

struct ExpiryCheck {
    expired: bool,
    time_expired: bool,
    downloads_exhausted: bool,
    downloads_remaining: i64,
}

/// Create an expiring transfer token
// native: compute expires_at from current time + hours
native fn ExpiringTransfer.create(transfer_id: String, max_downloads: i64 = 1, expire_hours: i64 = 24) -> ExpiringTransfer

/// Check if a transfer has expired (time or download count)
// native: compare current time to expires_at, check downloads_remaining
native fn ExpiringTransfer.check(token: ExpiringTransfer) -> ExpiryCheck

// ── Retention Policy ──

struct RetentionPolicy {
    name: String,
    retain_days: i64,
    auto_delete: bool,
    legal_hold: bool,
}

struct RetentionResult {
    deleted: i64,
    retained: i64,
    bytes_freed: i64,
    dry_run: bool,
}

/// Create a retention policy
// native: create policy struct
native fn RetentionPolicy.create(retain_days: i64 = 30, name: String = "default", auto_delete: bool = true) -> RetentionPolicy

/// Apply retention policy to a directory (delete files older than retain_days)
// native: scan directory, delete/count expired files
native fn RetentionPolicy.apply(dir: String, retain_days: i64 = 30, dry_run: bool = false) -> RetentionResult

// ── File Type Validation (magic bytes) ──

struct FileValidation {
    path: String,
    detected_type: String,
    mime: String,
    extension: String,
    executable: bool,
    has_script: bool,
    has_macro: bool,
    extension_mismatch: bool,
    safe: bool,
    size: i64,
}

struct AllowlistCheck {
    path: String,
    detected_type: String,
    allowed: bool,
    allowlist: []String,
}

/// Validate file type by magic bytes (not extension)
// native: read first bytes, detect type, check for executables/scripts/macros
native fn FileValidator.validate(path: String) -> FileValidation

/// Check if a file's type is in an allowlist
// native: detect type by magic bytes, check against allowlist
native fn FileValidator.allowlist(path: String, allowed_types: []String = ["pdf","csv","xml","json","txt","png","jpg"]) -> AllowlistCheck

// ── ML-KEM-1024 Crypto Config ──

struct CryptoConfig {
    level: String,
    key_exchange: String,
    signature: String,
    hash: String,
    symmetric: String,
    post_quantum: bool,
    cnsa2_compliant: bool,
}

/// Get crypto configuration for a security level
/// Levels: "standard", "high"/"enterprise", "cnsa2"/"classified"/"top_secret", "hybrid"
// native: return algorithm suite for the given security level
// cnsa2/classified/top_secret → ML-KEM-1024, ML-DSA-87, SHA-384
// high/enterprise → ML-KEM-768, ML-DSA-65, SHA-256
// standard → ML-KEM-768, ML-DSA-44, BLAKE3
// hybrid → X25519+ML-KEM-768, Ed25519+ML-DSA-65, BLAKE3, ChaCha20-Poly1305
native fn CryptoConfig.get(level: String = "standard") -> CryptoConfig

// ══════════════════════════════════════════════════════════════════
// Phase 63: mTLS Certificate Auth, Key Rotation, RBAC, Webhooks,
//           Transfer Scheduling, AV Scanning
// ══════════════════════════════════════════════════════════════════

// ── mTLS Configuration ──

struct MtlsConfig {
    cert_path: String,
    key_path: String,
    ca_path: String,
    cert_fingerprint: String,
    mutual_auth: bool,
    verify_peer: bool,
}

/// Create a mutual TLS configuration for authenticated transfers.
/// If ca_path is provided and exists, mutual_auth and verify_peer are enabled.
// native: verify cert/key exist, compute BLAKE3 fingerprint
native fn MtlsAuth.config(cert_path: String, key_path: String, ca_path: String = "") -> MtlsConfig

// ── Key Rotation ──

struct KeyRotation {
    key_id: String,
    key_version: String,
    rotation_days: i64,
    created_at: String,
    next_rotation: String,
    auto_rotate: bool,
    versions_retained: i64,
}

struct RotationCheck {
    needs_rotation: bool,
    next_rotation: String,
    current_time: String,
}

struct KeyRotationResult {
    key_id: String,
    old_version: String,
    new_version: String,
    rotated_at: String,
    success: bool,
}

/// Create a key rotation schedule (default: 90 days, PCI DSS standard).
// native: BLAKE3-based key version, ISO timestamps
native fn KeyRotation.schedule(key_id: String, rotation_days: i64 = 90) -> KeyRotation

/// Check if a key needs rotation based on its schedule.
// native: compare current time vs next_rotation
native fn KeyRotation.check_rotation(schedule: KeyRotation) -> RotationCheck

/// Rotate a key: generate new version, archive old.
// native: BLAKE3-based new version id
native fn KeyRotation.rotate(key_id: String, old_version: String = "") -> KeyRotationResult

// ── RBAC (Role-Based Access Control) ──

struct RbacUser {
    user_id: String,
    username: String,
    role: String,
    can_send: bool,
    can_receive: bool,
    can_admin: bool,
    can_audit: bool,
    can_delete: bool,
}

struct RbacCheck {
    username: String,
    role: String,
    action: String,
    allowed: bool,
}

/// Create a user with a role. Valid roles: admin, operator, auditor, transfer_only, readonly.
// native: BLAKE3 user_id, role-based permission matrix
native fn Rbac.create_user(username: String, role: String = "transfer_only") -> RbacUser

/// Check if a user has permission for an action (send, receive, admin, audit, delete).
// native: lookup permission flag by action
native fn Rbac.check(user: RbacUser, action: String) -> RbacCheck

// ── Webhook Notifications ──

struct WebhookConfig {
    url: String,
    events: []String,
    secret: String,
    active: bool,
    retry_count: i64,
}

struct WebhookResult {
    url: String,
    event: String,
    body: String,
    timestamp: String,
    signature: String,
    fired: bool,
}

/// Create a webhook configuration for transfer event notifications.
// native: default events: transfer_complete, transfer_failed
native fn Webhook.config(url: String, events: []String = [], secret: String = "") -> WebhookConfig

/// Fire a webhook event (builds JSON payload with optional HMAC-BLAKE3 signature).
// native: BLAKE3 keyed hash signature if secret provided
native fn Webhook.fire(url: String, event: String, payload: String = "

// ── Transfer Scheduling ──

struct TransferSchedule {
    schedule_id: String,
    name: String,
    cron: String,
    source: String,
    destination: String,
    active: bool,
    created_at: String,
    last_run: String,
    next_run: String,
    runs_completed: i64,
    runs_failed: i64,
}

struct ScheduleCheck {
    should_run: bool,
    active: bool,
    cron: String,
}

/// Create a transfer schedule with a cron expression (5 fields: min hour dom mon dow).
// native: validate cron format, generate schedule_id
native fn TransferSchedule.create(name: String, cron: String, source: String, destination: String) -> TransferSchedule

/// Check if a schedule should run now.
// native: simplified cron matching (all-wildcard = always due)
native fn TransferSchedule.check(schedule: TransferSchedule) -> ScheduleCheck

// ── AV Scanning ──

struct AvScanResult {
    path: String,
    clean: bool,
    threat: String,
    scanner: String,
    exit_code: i64,
    warning: String,
}

struct YaraScanResult {
    path: String,
    rules_path: String,
    matches: []String,
    has_matches: bool,
    warning: String,
}

/// Scan a file for malware using ClamAV (graceful degradation if not installed).
// native: shells out to clamscan, returns warning if unavailable
native fn AvScanner.scan(path: String) -> AvScanResult

/// Scan a file with YARA rules (graceful degradation if not installed).
// native: shells out to yara, returns warning if unavailable
native fn AvScanner.yara(path: String, rules_path: String = "rules.yar") -> YaraScanResult

// ══════════════════════════════════════════════════════════════════
// Phase 63: Encrypted Chat System
// ══════════════════════════════════════════════════════════════════

// ── Chat Message ──

struct ChatMessage {
    from: String,
    text: String,
    encrypted: String,
    timestamp: String,
    session_id: String,
}

// ── Chat Session ──

struct ChatSession {
    session_id: String,
    username: String,
    code: String,
    port: i64,
    encrypted: bool,
    algo: String,
    messages: []ChatMessage,
    participants: []String,
}

/// Create a new 1-to-1 encrypted chat session.
// native: creates AES-256-GCM encrypted session with BLAKE3-derived key
native fn Chat.create(username: String, code: String = "") -> ChatSession

/// Send an encrypted message within a chat session.
// native: encrypts message with per-session AES-256-GCM key
native fn Chat.send(session: ChatSession, message: String) -> ChatSession

/// Decrypt a received chat message.
// native: AES-256-GCM decrypt with session-derived key
native fn Chat.decrypt(encrypted: String, session_id: String) -> String

/// Get chat history as formatted strings.
// native: returns "[timestamp] user: message" formatted lines
native fn Chat.history(session: ChatSession) -> []String

// ── Group Chat Message ──

struct GroupMessage {
    from: String,
    text: String,
    encrypted: String,
    timestamp: String,
    group_id: String,
}

// ── Group Chat ──

struct GroupChatSession {
    group_id: String,
    name: String,
    code: String,
    port: i64,
    creator: String,
    members: []String,
    messages: []GroupMessage,
    encrypted: bool,
    max_members: i64,
}

/// Create a new group chat.
// native: creates group with AES-256-GCM, creator as first member
native fn GroupChat.create(name: String, creator: String, code: String = "") -> GroupChatSession

/// Add a member to a group chat.
// native: adds member (no duplicates)
native fn GroupChat.add_member(group: GroupChatSession, member: String) -> GroupChatSession

/// Remove a member from a group chat.
// native: removes member
native fn GroupChat.remove_member(group: GroupChatSession, member: String) -> GroupChatSession

/// Send an encrypted message to a group chat.
// native: encrypts with group-derived AES-256-GCM key
native fn GroupChat.send(group: GroupChatSession, sender: String, message: String) -> GroupChatSession

/// Get group chat history as formatted strings.
// native: returns "[timestamp] user: message" formatted lines
native fn GroupChat.history(group: GroupChatSession) -> []String

// ── Proxy Config ──

struct ProxyConfig {
    url: String,
    protocol: String,
    address: String,
    active: bool,
    tor: bool,
}

/// Create a proxy configuration.
// native: parses socks5://, socks4://, http:// URLs
native fn ProxyConfig.create(url: String) -> ProxyConfig

// ── QR Code Display ──

/// Generate ASCII art QR-style display for a code phrase.
// native: generates box-drawing art with BLAKE3-derived visual pattern
native fn QrCode.generate(data: String) -> String

// ══════════════════════════════════════════════════════════════════
// Text Transfer — send text without a file
// ══════════════════════════════════════════════════════════════════

struct TextTransfer {
    text: String,
    size: i64,
    hash: String,
    type: String,
}

/// Send a text string (no file needed), returns BLAKE3-hashed transfer manifest.
// native: BLAKE3 hash, size, type="text"
native fn TextTransfer.send(text: String) -> TextTransfer

// ══════════════════════════════════════════════════════════════════
// STUN — NAT traversal and hole punching
// ══════════════════════════════════════════════════════════════════

struct StunResult {
    local_ip: String,
    public_ip: String,
    nat_type: String,
    port: i64,
    reachable: bool,
}

struct HolePunchResult {
    peer: String,
    local_addr: String,
    punch_sent: bool,
    protocol: String,
}

/// Discover local and public IP addresses (STUN-like UDP probing).
// native: UDP socket bind + connect to 8.8.8.8:80 to find local IP
native fn Stun.discover() -> StunResult

/// Attempt UDP hole punch to a peer (sends TALLOW-PUNCH packet).
// native: UDP socket bind, send punch packet to peer
native fn Stun.hole_punch(peer_ip: String, peer_port: i64 = 6881, local_port: i64 = 0) -> HolePunchResult

// ══════════════════════════════════════════════════════════════════
// TWD Directory Transfer Protocol
// ══════════════════════════════════════════════════════════════════

// TWD archive format preserves full directory tree:
// Magic: "TWD" (4B) + version (1B) + dir_name + directories + files with relative paths.
// All paths normalized to forward slash. Files written atomically (temp + rename).
// Compression: zstd level 3 by default.

struct DirTransferResult {
    directory: String,
    dir_name: String,
    files_count: i64,
    dirs_count: i64,
    total_size: i64,
    compressed_size: i64,
    uncompressed_size: i64,
    hash: String,
    compressed: bool,
    bytes_sent: i64,
    structure_preserved: bool,
}

struct DirReceiveResult {
    dir_name: String,
    files_received: i64,
    dirs_created: i64,
    bytes_written: i64,
    output_dir: String,
    structure_preserved: bool,
    verified: bool,
}

struct PackResult {
    path: String,
    files: i64,
    dirs: i64,
    total_size: i64,
    archive_size: i64,
    compressed: bool,
    hash: String,
    format: String,
}

struct UnpackResult {
    dir_name: String,
    output: String,
    files: i64,
    dirs: i64,
    bytes_written: i64,
    structure_preserved: bool,
}

/// Send a directory over QUIC preserving full folder structure (TWD format).
/// The receiver gets the exact same directory tree with all files, subdirectories, and metadata intact.
// native: walk dir, build TWD archive, optionally zstd compress, QUIC send
native fn DirTransfer.send(dir: String, dest: String, compress: bool = true) -> DirTransferResult

/// Receive a directory over QUIC and restore full folder structure.
/// Auto-detects TWD format and unpacks preserving the original directory tree.
// native: QUIC listen, receive TWD archive, decompress if needed, unpack
native fn DirTransfer.receive(listen_addr: String = "0.0.0.0:6881", output_dir: String = ".", timeout: i64 = 60) -> DirReceiveResult

/// Pack a directory into a TWD archive file (local, no network).
/// Useful as a replacement for tar/zip with structure preservation.
// native: walk dir, build TWD archive, optionally zstd compress, write to file
native fn DirArchive.pack(dir: String, output: String, compress: bool = true) -> PackResult

/// Unpack a TWD archive to a directory, restoring the full folder structure.
/// Auto-detects compressed vs uncompressed archives.
// native: read file, decompress if needed, parse TWD format, create dirs + files
native fn DirArchive.unpack(archive: String, output_dir: String = ".") -> UnpackResult

// ══════════════════════════════════════════════════════════════════
// HTTP Share by Link — serve files for browser download
// ══════════════════════════════════════════════════════════════════

struct ShareLink {
    url: String,
    direct_url: String,
    file: String,
    filename: String,
    size: i64,
    hash: String,
    port: i64,
    token: String,
    password_protected: bool,
    max_downloads: i64,
    serving: bool,
}

/// Share a file via HTTP download link. No Tallow needed on receiver — just a browser.
/// Returns a ShareLink struct with the URL that anyone can open to download.
/// The HTTP server runs in a background thread; call returns immediately.
///
/// @param file       Path to the file to share
/// @param port       Port to bind (0 = auto-assign)
/// @param password   Optional password for download protection
/// @param max_downloads  Maximum number of downloads (0 = unlimited)
// native: bind TCP, generate token, spawn HTTP server thread, return ShareLink
native fn ShareLink.create(file: String, port: i64 = 0, password: String? = nil, max_downloads: i64 = 0) -> ShareLink

/// Share a directory via HTTP download link (packs as TWD archive, serves via HTTP).
/// Receiver downloads a .twd file that can be unpacked with `tallow unpack`.
///
/// @param dir   Path to the directory to share
/// @param port  Port to bind (0 = auto-assign)
// native: pack directory to temp TWD archive, then share_by_link
native fn ShareLink.dir(dir: String, port: i64 = 0) -> ShareLink

// ══════════════════════════════════════════════════════════════════
// Live Browser Session Sharing — stream screenshots over HTTP
// ══════════════════════════════════════════════════════════════════

struct LiveShare {
    url: String,
    port: i64,
    refresh_ms: i64,
    streaming: bool,
    screenshot_path: String,
}

/// Start a live browser session viewer. Streams screenshots over HTTP.
/// Remote users open the URL in their browser to watch the automation live.
/// Uses simple <img> auto-refresh (no WebSocket needed).
///
/// @param port        Port for the HTTP viewer (default: 9090)
/// @param refresh_ms  Screenshot refresh interval in milliseconds (default: 1000)
// native: bind TCP, spawn HTTP server thread serving viewer page + /screenshot endpoint
native fn BrowserLive.start(port: i64 = 9090, refresh_ms: i64 = 1000) -> LiveShare

/// Update the live screenshot. Call this periodically from browser automation.
/// The screenshot data should be base64-encoded PNG bytes.
///
/// @param screenshot_base64  Base64-encoded PNG screenshot data
// native: base64 decode, write to temp dir as tallow-live-screenshot.png
native fn BrowserLive.update(screenshot_base64: String) -> bool
