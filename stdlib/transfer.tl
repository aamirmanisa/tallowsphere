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
fn Transfer.hash(path: String) -> String {
    // native: BLAKE3 file hash → hex string
}

/// Split file into chunks and compute per-chunk BLAKE3 hashes
fn Transfer.chunk(path: String, chunk_size: i64 = 262144) -> []ChunkInfo {
    // native: chunk file, return array of ChunkInfo
}

/// Build binary Merkle tree from chunk hashes → root hash
fn Transfer.tree_hash(chunks: []ChunkInfo) -> String {
    // native: binary Merkle tree → root hex hash
}

/// Create a transfer manifest (JSON) for verification
fn Transfer.manifest(root_hash: String, size: i64, chunks: []ChunkInfo) -> String {
    // native: JSON manifest string
}

// ══════════════════════════════════════════════════════════════════
// FileCopy — OS-optimized file and directory copy
// ══════════════════════════════════════════════════════════════════

/// Copy a single file (uses OS copy_file_range/sendfile when available)
fn FileCopy.copy(src: String, dst: String) -> CopyStats {
    // native: fast single-file copy
}

/// Copy an entire directory recursively
fn FileCopy.copy_dir(src: String, dst: String) -> CopyStats {
    // native: recursive directory copy
}

// ══════════════════════════════════════════════════════════════════
// FileVault — AES-256-GCM file encryption with Argon2id key derivation
// ══════════════════════════════════════════════════════════════════

/// Encrypt a file to .nixv vault format
fn FileVault.encrypt(input: String, output: String, password: String) -> EncryptResult {
    // native: Argon2id + AES-256-GCM → NIXV file
}

/// Decrypt a .nixv vault file
fn FileVault.decrypt(input: String, output: String, password: String) -> DecryptResult {
    // native: decrypt NIXV file → plaintext
}

/// Encrypt a text string, return hex-encoded ciphertext
fn FileVault.encrypt_text(text: String, password: String) -> String {
    // native: Argon2id + AES-256-GCM → hex
}

/// Decrypt hex-encoded ciphertext to plaintext string
fn FileVault.decrypt_text(encrypted: String, password: String) -> String {
    // native: decrypt hex → plaintext
}

// ══════════════════════════════════════════════════════════════════
// DeltaSync — Directory scanning and diff computation
// ══════════════════════════════════════════════════════════════════

/// Scan a directory recursively, BLAKE3-hash each file
fn DeltaSync.scan(dir_path: String) -> []FileEntry {
    // native: recursive directory scan with BLAKE3 hashes
}

/// Compare two scans and compute the delta
fn DeltaSync.diff(old_scan: []FileEntry, new_scan: []FileEntry) -> DeltaResult {
    // native: hash-based diff → added/removed/modified
}

// ══════════════════════════════════════════════════════════════════
// Compress — zstd compression with compressibility detection
// ══════════════════════════════════════════════════════════════════

/// Compress data with specified algorithm (default: zstd level 3)
fn Compress.compress(data: String, algo: String = "zstd", level: i64 = 3) -> String {
    // native: compress → hex string
}

/// Decompress hex-encoded compressed data
fn Compress.decompress(data: String, algo: String = "zstd") -> String {
    // native: decompress hex → plaintext
}

/// Detect data compressibility via Shannon entropy
fn Compress.detect(data: String) -> CompressibilityResult {
    // native: entropy analysis → recommendation
}

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
fn TransferSession.send(data: String, recipient: String, encrypt: bool = true) -> TransferSession {
    // native: create TransferManifest with BLAKE3 chunks + tree hash
}

/// Create a receive session from a manifest (JSON or TransferSession struct)
fn TransferSession.receive(manifest: String) -> TransferSession {
    // native: parse manifest, create receive session
}

/// Get transfer progress/status for a session
fn TransferSession.status(session: TransferSession) -> TransferProgress {
    // native: query session state → progress struct
}

// ── Transfer Stream (QUIC multi-stream) ──

struct TransferStream {
    stream_id: String,
    session_id: String,
    stream_type: String,
    bytes_sent: i64,
    open: bool,
}

/// Create a new stream for a session
fn TransferStream.create(session_id: String, stream_type: String = "reliable") -> TransferStream {
    // native: "reliable" (ordered) or "unreliable" (datagrams)
}

/// Write data to a stream (immutable update, returns new stream)
fn TransferStream.write(stream: TransferStream, data: String) -> TransferStream {
    // native: increment bytes_sent by data length
}

/// Close a stream
fn TransferStream.close(stream: TransferStream) -> TransferStream {
    // native: set open = false
}

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
fn ErasureCode.encode(data: String, overhead: f64 = 0.5) -> ErasureEncoded {
    // native: reed-solomon-simd systematic encoding, 10 data shards + ceil(10*overhead) recovery
}

/// Decode from received symbols (need >= k original shards to succeed)
fn ErasureCode.decode(symbols: []String, k: i64) -> Result<ErasureDecoded> {
    // native: reed-solomon-simd decode, recovers original data
}

/// Check erasure coding status (decodable, deficit, recovery percent)
fn ErasureCode.status(encoded: ErasureEncoded, received: i64) -> ErasureStatus {
    // native: compute decodability metrics
}

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
fn NetworkPath.discover() -> []NetworkPath {
    // native: enumerate interfaces, return array of NetworkPath
}

/// Estimate aggregate bandwidth across paths
fn NetworkPath.estimate(paths: []NetworkPath) -> PathEstimate {
    // native: sum bandwidths, recommend stream count
}

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
fn Peer.create(address: String, port: i64) -> Peer {
    // native: BLAKE3(address:port) as peer_id
}

/// Announce peer availability for a root hash
fn Peer.announce(peer: Peer, root_hash: String) -> AnnounceResult {
    // native: simulated DHT announce
}

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
fn Swarm.create(root_hash: String) -> Swarm {
    // native: BLAKE3("swarm:"+root_hash) as swarm_id
}

/// Add a peer to a swarm (immutable update)
fn Swarm.add_peer(swarm: Swarm, peer: Peer) -> Swarm {
    // native: append peer, recalculate bandwidth
}

/// Remove a peer from a swarm by peer_id
fn Swarm.remove_peer(swarm: Swarm, peer_id: String) -> Swarm {
    // native: filter by peer_id, recalculate bandwidth
}

/// Get swarm status summary
fn Swarm.status(swarm: Swarm) -> SwarmStatus {
    // native: peer count, total bandwidth, active flag
}

/// Schedule chunk assignments across peers (round-robin)
fn Swarm.schedule(swarm: Swarm, chunks_needed: []i64) -> Schedule {
    // native: round-robin distribution
}

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
fn Dht.create(node_id: String) -> DhtNode {
    // native: BLAKE3(node_id) as node_id
}

/// Store a key-value pair in the DHT
fn Dht.announce(dht: DhtNode, key: String, value: String) -> DhtAnnounce {
    // native: simulated DHT store
}

/// Look up a key in the DHT
fn Dht.lookup(dht: DhtNode, key: String) -> DhtLookup {
    // native: simulated DHT lookup
}

// ── Manifest URL / QR ──

/// Encode a manifest JSON to a tallow:// transfer URL
fn Manifest.to_url(manifest_json: String) -> String {
    // native: base64url encode -> "tallow://transfer/{base64}"
}

/// Decode a tallow:// transfer URL back to manifest JSON
fn Manifest.from_url(url: String) -> String {
    // native: extract base64, decode -> JSON
}

/// Generate a text QR code representation for a manifest
fn Manifest.to_qr(manifest_json: String) -> String {
    // native: "QR[tallow://transfer/{short_hash}...] ({byte_count} bytes)"
}

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
fn ProgressTracker.create(total: i64, label: String = "Transferring") -> ProgressTracker {
    // native: create tracker with timestamps
}

/// Update progress by increment amount
fn ProgressTracker.update(tracker: ProgressTracker, increment: i64 = 1) -> ProgressTracker {
    // native: update current, percent, bps, eta
}

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
fn Checkpoint.save(transfer_id: String, state: any) -> Checkpoint {
    // native: JSON serialize, atomic write (.tmp + rename)
}

/// Load a checkpoint (returns found=false if no checkpoint exists)
fn Checkpoint.load(transfer_id: String) -> Checkpoint {
    // native: read .tallow_checkpoint_{id}.json
}

/// Delete a checkpoint file
fn Checkpoint.delete(transfer_id: String) -> Checkpoint {
    // native: remove checkpoint file
}

// ── Bandwidth Limiting ──

struct BandwidthLimit {
    limit_mbps: f64,
    bytes_per_sec: i64,
    active: bool,
    burst_bytes: i64,
}

/// Create a bandwidth limiter
fn BandwidthLimit.create(limit_mbps: f64) -> BandwidthLimit {
    // native: calculate bytes_per_sec from Mbps
}

/// Calculate throttle delay in ms given current transfer stats
fn BandwidthLimit.throttle(bytes_sent: i64, elapsed_ms: i64, bytes_per_sec: i64) -> i64 {
    // native: returns sleep_ms needed to stay under limit (0 if under)
}

// ── LAN Discovery ──

struct LanPeer {
    ip: String,
    hostname: String,
    port: i64,
    self_node: bool,
}

/// Discover peers on the local network
fn LanDiscovery.discover() -> []LanPeer {
    // native: enumerate local interfaces, return peer list
}

// ── Copy with Metadata ──

struct CopyResult {
    bytes_copied: i64,
    metadata_preserved: bool,
    mtime_preserved: bool,
    src: String,
    dst: String,
}

/// Copy file preserving metadata (modification time, permissions)
fn FileCopy.copy_metadata(src: String, dst: String) -> CopyResult {
    // native: std::fs::copy + filetime mtime preservation
}

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
fn FileVault.encrypt_dir(input: String, output: String, password: String) -> VaultDirResult {
    // native: walk directory, encrypt each file to .enc format
}

/// Decrypt all .enc files in a directory
fn FileVault.decrypt_dir(input: String, output: String, password: String) -> VaultDirResult {
    // native: walk directory, decrypt each .enc file
}

// ── Memory-Mapped I/O ──

struct MmapResult {
    size: i64,
    hash: String,
    path: String,
}

/// Memory-map a file for fast reading and return its BLAKE3 hash
fn Mmap.read(path: String) -> MmapResult {
    // native: memmap2 read-only mapping + BLAKE3 hash
}

// ── LZ4 Compression (fast path for transfer) ──

struct CompressResult {
    data: String,
    original_size: i64,
    compressed_size: i64,
    ratio: f64,
    algo: String,
}

/// Compress data with LZ4 (fastest compression, ideal for transfer)
fn Lz4.compress(data: String) -> CompressResult {
    // native: lz4_flex compress_prepend_size → hex
}

/// Decompress LZ4 hex data
fn Lz4.decompress(data: String) -> String {
    // native: lz4_flex decompress_size_prepended
}

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
fn QuicTransfer.listen(addr: String = "0.0.0.0:6881") -> QuicServer {
    // native: quinn Endpoint::server with self-signed rcgen cert
}

/// Connect to a QUIC server
fn QuicTransfer.connect(addr: String, server_name: String = "tallow-transfer") -> QuicConnection {
    // native: quinn Endpoint::client with insecure cert verification
}

/// Send a file over QUIC (chunked, BLAKE3-verified)
fn QuicTransfer.send_file(path: String, dest: String) -> TransferResult {
    // native: open uni stream, send header + chunks, BLAKE3 hash
}

/// Receive a file over QUIC (BLAKE3-verified, atomic write)
fn QuicTransfer.receive(addr: String = "0.0.0.0:6881", output_dir: String = ".", timeout: i64 = 30) -> ReceiveResult {
    // native: accept uni stream, read header + data, verify BLAKE3
}

/// Send raw bytes over QUIC
fn QuicTransfer.send_bytes(data: String, dest: String) -> SendResult {
    // native: open uni stream, framed write
}

/// Get QUIC subsystem status and capabilities
fn QuicTransfer.status() -> QuicStatus {
    // native: library version, TLS version, congestion, MTU
}

/// Resume an interrupted file send from a byte offset
fn QuicTransfer.send_resume(path: String, dest: String, offset: i64 = 0) -> TransferResult {
    // native: QUIC send with resume header (total_size + offset + hash)
}

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
fn TransferCode.generate() -> TransferCode {
    // native: random 3-digit number + 3 phonetically distinct words
}

/// Resolve a code phrase to its deterministic port and session
fn TransferCode.resolve(code: String) -> CodeSession {
    // native: BLAKE3(code) -> port (10000-65000) + session key
}

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
fn Relay.start(port: i64 = 6880) -> RelayServer {
    // native: bind TCP listener, match sender/receiver by code phrase
}

/// Send a file via relay server (code phrase matched)
fn Relay.send(file: String, relay_addr: String = "relay.tallow-lang.org:6880", code: String = "") -> RelaySendResult {
    // native: connect to relay, send TALLOW-SEND header + code + file data
}

/// Receive a file via relay server (code phrase matched)
fn Relay.receive(code: String, output_dir: String = ".", relay_addr: String = "relay.tallow-lang.org:6880") -> RelayReceiveResult {
    // native: connect to relay, send TALLOW-RECV header + code, receive file
}

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
fn MultiTransfer.prepare(files: []String, dest: String) -> MultiTransferResult {
    // native: walk files/dirs, build manifest with BLAKE3 hashes
}

/// Archive and send an entire directory (optional zstd compression)
fn MultiTransfer.send_dir(dir: String, dest: String, compress: bool = true) -> DirTransferResult {
    // native: archive directory to binary format, compress with zstd, return metadata
}

// ══════════════════════════════════════════════════════════════════
// TransferCompress — Compression during transfer
// ══════════════════════════════════════════════════════════════════

/// Compress data for transfer (auto-detects algorithm: zstd, lz4, or none)
fn TransferCompress.compress(data: String, algo: String = "auto") -> CompressedTransfer {
    // native: Shannon entropy check, zstd for normal, lz4 for large, skip for high-entropy
}

/// Decompress transfer data back to original
fn TransferCompress.decompress(data_hex: String, algo: String) -> String {
    // native: zstd/lz4/none decompression from hex-encoded data
}

// ══════════════════════════════════════════════════════════════════
// ParallelConfig — Parallel stream configuration
// ══════════════════════════════════════════════════════════════════

/// Create a parallel stream configuration (default: 4 streams, 256KB chunks)
fn ParallelConfig.create(streams: i64 = 4, chunk_size: i64 = 262144) -> ParallelConfig {
    // native: configure stream count and chunk size for transfer
}

// ══════════════════════════════════════════════════════════════════
// BandwidthConfig — Bandwidth limiting
// ══════════════════════════════════════════════════════════════════

/// Apply bandwidth limit to transfer (e.g., "10M" = 10 Mbps, "500K", "1G")
fn BandwidthConfig.apply(limit: String) -> BandwidthConfig {
    // native: parse bandwidth limit string, compute bytes/sec
}

// ══════════════════════════════════════════════════════════════════
// WatchSession — Directory watching and change detection
// ══════════════════════════════════════════════════════════════════

/// Start watching a directory for changes (polling-based, BLAKE3 hashes)
fn WatchSession.start(dir: String, interval_ms: i64 = 1000) -> WatchSession {
    // native: snapshot directory with BLAKE3 hashes of each file
}

/// Check for changes since last snapshot
fn WatchSession.check(session: WatchSession) -> WatchChanges {
    // native: re-scan directory, compare BLAKE3 hashes, report added/removed/modified
}

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
fn SignedManifest.create(files_json: String, sender_id: String = "anonymous") -> SignedManifest {
    // native: BLAKE3 keyed hash signature over manifest JSON
}

/// Verify a signed manifest's integrity
fn SignedManifest.verify(manifest: String, signature: String, sender_id: String) -> ManifestVerification {
    // native: recompute BLAKE3 keyed hash, compare
}

/// Create a transfer receipt (non-repudiation proof of delivery)
fn TransferReceipt.create(file_hash: String, receiver_id: String = "receiver") -> TransferReceipt {
    // native: BLAKE3 hash of (file_hash || receiver_id || timestamp)
}

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
fn AuditLog.log(action: String, details: String = "") -> AuditEntry {
    // native: BLAKE3-chained append to global audit log
}

/// Verify integrity of the entire audit chain
fn AuditLog.verify() -> AuditVerification {
    // native: walk chain, verify each entry's hash
}

/// Export the audit log as JSON
fn AuditLog.export() -> String {
    // native: serialize all entries to JSON array
}

/// Save audit log to a file
fn AuditLog.save(path: String = "tallow_audit.log") -> AuditSaveResult {
    // native: write TSV to file
}

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
fn ExpiringTransfer.create(transfer_id: String, max_downloads: i64 = 1, expire_hours: i64 = 24) -> ExpiringTransfer {
    // native: compute expires_at from current time + hours
}

/// Check if a transfer has expired (time or download count)
fn ExpiringTransfer.check(token: ExpiringTransfer) -> ExpiryCheck {
    // native: compare current time to expires_at, check downloads_remaining
}

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
fn RetentionPolicy.create(retain_days: i64 = 30, name: String = "default", auto_delete: bool = true) -> RetentionPolicy {
    // native: create policy struct
}

/// Apply retention policy to a directory (delete files older than retain_days)
fn RetentionPolicy.apply(dir: String, retain_days: i64 = 30, dry_run: bool = false) -> RetentionResult {
    // native: scan directory, delete/count expired files
}

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
fn FileValidator.validate(path: String) -> FileValidation {
    // native: read first bytes, detect type, check for executables/scripts/macros
}

/// Check if a file's type is in an allowlist
fn FileValidator.allowlist(path: String, allowed_types: []String = ["pdf","csv","xml","json","txt","png","jpg"]) -> AllowlistCheck {
    // native: detect type by magic bytes, check against allowlist
}

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
fn CryptoConfig.get(level: String = "standard") -> CryptoConfig {
    // native: return algorithm suite for the given security level
    // cnsa2/classified/top_secret → ML-KEM-1024, ML-DSA-87, SHA-384
    // high/enterprise → ML-KEM-768, ML-DSA-65, SHA-256
    // standard → ML-KEM-768, ML-DSA-44, BLAKE3
    // hybrid → X25519+ML-KEM-768, Ed25519+ML-DSA-65, BLAKE3, ChaCha20-Poly1305
}

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
fn MtlsAuth.config(cert_path: String, key_path: String, ca_path: String = "") -> MtlsConfig {
    // native: verify cert/key exist, compute BLAKE3 fingerprint
}

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
fn KeyRotation.schedule(key_id: String, rotation_days: i64 = 90) -> KeyRotation {
    // native: BLAKE3-based key version, ISO timestamps
}

/// Check if a key needs rotation based on its schedule.
fn KeyRotation.check_rotation(schedule: KeyRotation) -> RotationCheck {
    // native: compare current time vs next_rotation
}

/// Rotate a key: generate new version, archive old.
fn KeyRotation.rotate(key_id: String, old_version: String = "") -> KeyRotationResult {
    // native: BLAKE3-based new version id
}

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
fn Rbac.create_user(username: String, role: String = "transfer_only") -> RbacUser {
    // native: BLAKE3 user_id, role-based permission matrix
}

/// Check if a user has permission for an action (send, receive, admin, audit, delete).
fn Rbac.check(user: RbacUser, action: String) -> RbacCheck {
    // native: lookup permission flag by action
}

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
fn Webhook.config(url: String, events: []String = [], secret: String = "") -> WebhookConfig {
    // native: default events: transfer_complete, transfer_failed
}

/// Fire a webhook event (builds JSON payload with optional HMAC-BLAKE3 signature).
fn Webhook.fire(url: String, event: String, payload: String = "{}", secret: String = "") -> WebhookResult {
    // native: BLAKE3 keyed hash signature if secret provided
}

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
fn TransferSchedule.create(name: String, cron: String, source: String, destination: String) -> TransferSchedule {
    // native: validate cron format, generate schedule_id
}

/// Check if a schedule should run now.
fn TransferSchedule.check(schedule: TransferSchedule) -> ScheduleCheck {
    // native: simplified cron matching (all-wildcard = always due)
}

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
fn AvScanner.scan(path: String) -> AvScanResult {
    // native: shells out to clamscan, returns warning if unavailable
}

/// Scan a file with YARA rules (graceful degradation if not installed).
fn AvScanner.yara(path: String, rules_path: String = "rules.yar") -> YaraScanResult {
    // native: shells out to yara, returns warning if unavailable
}

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
fn Chat.create(username: String, code: String = "") -> ChatSession {
    // native: creates AES-256-GCM encrypted session with BLAKE3-derived key
}

/// Send an encrypted message within a chat session.
fn Chat.send(session: ChatSession, message: String) -> ChatSession {
    // native: encrypts message with per-session AES-256-GCM key
}

/// Decrypt a received chat message.
fn Chat.decrypt(encrypted: String, session_id: String) -> String {
    // native: AES-256-GCM decrypt with session-derived key
}

/// Get chat history as formatted strings.
fn Chat.history(session: ChatSession) -> []String {
    // native: returns "[timestamp] user: message" formatted lines
}

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
fn GroupChat.create(name: String, creator: String, code: String = "") -> GroupChatSession {
    // native: creates group with AES-256-GCM, creator as first member
}

/// Add a member to a group chat.
fn GroupChat.add_member(group: GroupChatSession, member: String) -> GroupChatSession {
    // native: adds member (no duplicates)
}

/// Remove a member from a group chat.
fn GroupChat.remove_member(group: GroupChatSession, member: String) -> GroupChatSession {
    // native: removes member
}

/// Send an encrypted message to a group chat.
fn GroupChat.send(group: GroupChatSession, sender: String, message: String) -> GroupChatSession {
    // native: encrypts with group-derived AES-256-GCM key
}

/// Get group chat history as formatted strings.
fn GroupChat.history(group: GroupChatSession) -> []String {
    // native: returns "[timestamp] user: message" formatted lines
}

// ── Proxy Config ──

struct ProxyConfig {
    url: String,
    protocol: String,
    address: String,
    active: bool,
    tor: bool,
}

/// Create a proxy configuration.
fn ProxyConfig.create(url: String) -> ProxyConfig {
    // native: parses socks5://, socks4://, http:// URLs
}

// ── QR Code Display ──

/// Generate ASCII art QR-style display for a code phrase.
fn QrCode.generate(data: String) -> String {
    // native: generates box-drawing art with BLAKE3-derived visual pattern
}

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
fn TextTransfer.send(text: String) -> TextTransfer {
    // native: BLAKE3 hash, size, type="text"
}

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
fn Stun.discover() -> StunResult {
    // native: UDP socket bind + connect to 8.8.8.8:80 to find local IP
}

/// Attempt UDP hole punch to a peer (sends TALLOW-PUNCH packet).
fn Stun.hole_punch(peer_ip: String, peer_port: i64 = 6881, local_port: i64 = 0) -> HolePunchResult {
    // native: UDP socket bind, send punch packet to peer
}

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
fn DirTransfer.send(dir: String, dest: String, compress: bool = true) -> DirTransferResult {
    // native: walk dir, build TWD archive, optionally zstd compress, QUIC send
}

/// Receive a directory over QUIC and restore full folder structure.
/// Auto-detects TWD format and unpacks preserving the original directory tree.
fn DirTransfer.receive(listen_addr: String = "0.0.0.0:6881", output_dir: String = ".", timeout: i64 = 60) -> DirReceiveResult {
    // native: QUIC listen, receive TWD archive, decompress if needed, unpack
}

/// Pack a directory into a TWD archive file (local, no network).
/// Useful as a replacement for tar/zip with structure preservation.
fn DirArchive.pack(dir: String, output: String, compress: bool = true) -> PackResult {
    // native: walk dir, build TWD archive, optionally zstd compress, write to file
}

/// Unpack a TWD archive to a directory, restoring the full folder structure.
/// Auto-detects compressed vs uncompressed archives.
fn DirArchive.unpack(archive: String, output_dir: String = ".") -> UnpackResult {
    // native: read file, decompress if needed, parse TWD format, create dirs + files
}

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
fn ShareLink.create(file: String, port: i64 = 0, password: String? = nil, max_downloads: i64 = 0) -> ShareLink {
    // native: bind TCP, generate token, spawn HTTP server thread, return ShareLink
}

/// Share a directory via HTTP download link (packs as TWD archive, serves via HTTP).
/// Receiver downloads a .twd file that can be unpacked with `tallow unpack`.
///
/// @param dir   Path to the directory to share
/// @param port  Port to bind (0 = auto-assign)
fn ShareLink.dir(dir: String, port: i64 = 0) -> ShareLink {
    // native: pack directory to temp TWD archive, then share_by_link
}

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
fn BrowserLive.start(port: i64 = 9090, refresh_ms: i64 = 1000) -> LiveShare {
    // native: bind TCP, spawn HTTP server thread serving viewer page + /screenshot endpoint
}

/// Update the live screenshot. Call this periodically from browser automation.
/// The screenshot data should be base64-encoded PNG bytes.
///
/// @param screenshot_base64  Base64-encoded PNG screenshot data
fn BrowserLive.update(screenshot_base64: String) -> bool {
    // native: base64 decode, write to temp dir as tallow-live-screenshot.png
}
