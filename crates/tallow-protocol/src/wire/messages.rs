//! Protocol message types
//!
//! All messages use postcard serialization with integer-discriminant enums.
//! No `#[serde(tag = ...)]` — postcard handles Rust enums natively.

use serde::{Deserialize, Serialize};

/// Wire mode: full E2E (KEM handshake + PQ auth + AEAD chunks). Default.
pub const MODE_FULL: u8 = 0;
/// Wire mode: Simple / transport-only (no handshake, no AEAD; relay-carried).
pub const MODE_SIMPLE: u8 = 1;

/// Wire protocol messages
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum Message {
    /// Version negotiation request
    VersionRequest {
        /// Supported protocol versions (sorted, ascending)
        supported_versions: Vec<u32>,
    },
    /// Version negotiation response
    VersionResponse {
        /// Selected protocol version
        selected_version: u32,
    },
    /// Version negotiation failure
    VersionReject {
        /// Reason for rejection
        reason: String,
    },
    /// Room join request (relay routing)
    RoomJoin {
        /// Room ID (BLAKE3 hash of code phrase, 32 bytes)
        room_id: Vec<u8>,
        /// BLAKE3 hash of relay password. None = no auth attempted.
        password_hash: Option<Vec<u8>>,
        /// 2-hop routing: URL of the relay that the receiver will connect to.
        ///
        /// When set, this relay (relay-A, the sender's relay) will establish an
        /// outbound bridge connection to `forward_to_relay` (relay-B, the receiver's
        /// relay) using the same `room_id`. Messages from the sender are forwarded
        /// through relay-B to the receiver. Neither relay sees both IP addresses:
        /// relay-A sees the sender's IP; relay-B sees the receiver's IP and only
        /// relay-A's IP (not the sender's).
        ///
        /// If absent, falls back to the standard single-relay model.
        ///
        /// Security: the target relay URL is validated against the server's
        /// `relay_hop_allowlist` if configured. Relay hopping must be explicitly
        /// enabled in the server config (`enable_relay_hopping = true`).
        #[serde(default)]
        forward_to_relay: Option<String>,
    },
    /// Room join acknowledgment
    RoomJoined {
        /// Whether peer is already waiting in the room
        peer_present: bool,
    },
    /// Room leave
    RoomLeave,
    /// Peer arrived notification (sent by relay when second peer joins)
    PeerArrived,
    /// Peer departed notification
    PeerDeparted,
    /// File offer (sender → receiver)
    FileOffer {
        /// Transfer ID (random, unique per transfer)
        transfer_id: [u8; 16],
        /// File manifest (serialized separately)
        manifest: Vec<u8>,
    },
    /// Accept file transfer
    FileAccept {
        /// Transfer ID
        transfer_id: [u8; 16],
    },
    /// Reject file transfer
    FileReject {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// Reason for rejection
        reason: String,
    },
    /// Data chunk
    Chunk {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// Chunk index (0-based)
        index: u64,
        /// Total chunks (set on final chunk)
        total: Option<u64>,
        /// Encrypted chunk data
        data: Vec<u8>,
    },
    /// Chunk acknowledgment
    Ack {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// Acknowledged chunk index
        index: u64,
    },
    /// Transfer complete
    TransferComplete {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// BLAKE3 hash of the manifest
        hash: [u8; 32],
        /// Merkle root of chunk hashes (for integrity verification)
        merkle_root: Option<[u8; 32]>,
    },
    /// Error during transfer
    TransferError {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// Error message
        error: String,
    },
    /// Exchange manifests for sync comparison
    ManifestExchange {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// Serialized manifest data
        manifest: Vec<u8>,
    },
    /// Request deletion of files on the remote side
    SyncDeleteList {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// Relative paths of files to delete on the remote
        paths: Vec<String>,
    },
    /// Ping (keepalive)
    Ping,
    /// Pong (keepalive response)
    Pong,
    /// Handshake initiation (sender -> receiver)
    ///
    /// Carries CPace initiator public message, KEM capability negotiation,
    /// and a random nonce for session ID binding.
    HandshakeInit {
        /// Protocol version for this handshake (2 = KEM handshake)
        protocol_version: u32,
        /// Declared cryptographic suite code (v8+; [`tallow_crypto::SUITE_CODE_TCS1`] today).
        ///
        /// Bound into the transcript, so a receiver that does not know the code refuses the
        /// handshake instead of negotiating down to a suite the initiator did not ask for.
        suite_code: u8,
        /// Serialized KemCapabilities (supported algorithms)
        kem_capabilities: Vec<u8>,
        /// CPace initiator public message (Ristretto255 point, 32 bytes)
        cpace_public: [u8; 32],
        /// Random nonce for session ID binding (16 bytes)
        nonce: [u8; 16],
    },
    /// Handshake response (receiver -> sender)
    ///
    /// Carries CPace responder public message, selected KEM algorithm,
    /// the receiver's ephemeral hybrid KEM public key, and a random nonce.
    HandshakeResponse {
        /// Selected KEM algorithm discriminant
        selected_kem: u8,
        /// CPace responder public message (32 bytes)
        cpace_public: [u8; 32],
        /// Serialized hybrid KEM public key
        kem_public_key: Vec<u8>,
        /// Random nonce for session ID binding (16 bytes)
        nonce: [u8; 16],
    },
    /// KEM encapsulation + sender key confirmation (sender -> receiver)
    HandshakeKem {
        /// Serialized hybrid KEM ciphertext
        kem_ciphertext: Vec<u8>,
        /// Sender's key confirmation tag (BLAKE3 keyed MAC, 32 bytes)
        confirmation: [u8; 32],
    },
    /// Handshake completion with receiver key confirmation (receiver -> sender)
    HandshakeComplete {
        /// Receiver's key confirmation tag (BLAKE3 keyed MAC, 32 bytes)
        confirmation: [u8; 32],
    },
    /// Resume information (receiver -> sender after FileAccept)
    ///
    /// Sent when the receiver has a checkpoint from a previous interrupted
    /// transfer. The sender skips chunks in the verified_chunks set.
    ResumeInfo {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// BLAKE3 hash of the manifest (to verify same transfer)
        manifest_hash: [u8; 32],
        /// Set of chunk indices already verified by the receiver
        verified_chunks: Vec<u64>,
    },
    /// Handshake failure (either direction)
    ///
    /// The reason string MUST NOT distinguish PAKE failure from KEM failure
    /// to avoid oracle attacks.
    HandshakeFailed {
        /// Generic failure reason
        reason: String,
    },
    /// Encrypted chat text message
    ChatText {
        /// Unique message ID for read receipts (random 16 bytes)
        message_id: [u8; 16],
        /// Monotonic sequence number for ordering
        sequence: u64,
        /// AES-256-GCM encrypted plaintext
        ciphertext: Vec<u8>,
        /// 12-byte nonce used for encryption
        nonce: [u8; 12],
    },
    /// Typing indicator (reserved for future use)
    TypingIndicator {
        /// true = started typing, false = stopped typing
        typing: bool,
    },
    /// Read receipt acknowledging messages (reserved for future use)
    ReadReceipt {
        /// Message IDs confirmed as read
        message_ids: Vec<[u8; 16]>,
    },
    /// Graceful chat session termination
    ChatEnd,

    // --- Phase 19: Multi-Peer Room variants (DO NOT reorder; postcard ordinal) ---
    /// Multi-peer room join request
    RoomJoinMulti {
        /// Room ID (BLAKE3 hash of code phrase, 32 bytes)
        room_id: Vec<u8>,
        /// BLAKE3 hash of relay password. None = no auth attempted.
        password_hash: Option<Vec<u8>>,
        /// Requested room capacity (0 = use server default)
        requested_capacity: u8,
    },
    /// Multi-peer room joined response with peer ID assignment
    RoomJoinedMulti {
        /// This peer's assigned ID in the room
        peer_id: u8,
        /// List of already-present peer IDs
        existing_peers: Vec<u8>,
    },
    /// A new peer has joined the room (broadcast to existing peers)
    PeerJoinedRoom {
        /// The new peer's assigned ID
        peer_id: u8,
    },
    /// A peer has left the room (broadcast to remaining peers)
    PeerLeftRoom {
        /// The departing peer's ID
        peer_id: u8,
    },
    /// Targeted message envelope for multi-peer routing
    ///
    /// The relay reads `to_peer` to route and overwrites `from_peer`
    /// with the actual sender's ID (anti-spoofing). Payload is opaque
    /// E2E encrypted bytes.
    Targeted {
        /// Sender's peer ID (set/overwritten by relay)
        from_peer: u8,
        /// Target peer ID (0xFF = broadcast to all)
        to_peer: u8,
        /// Opaque payload (E2E encrypted message bytes)
        payload: Vec<u8>,
    },
    /// Room peer count response
    RoomPeerCount {
        /// Current number of peers in the room
        count: u8,
        /// Room capacity
        capacity: u8,
    },

    // --- Phase 20: P2P Direct signaling variants (DO NOT reorder; postcard ordinal) ---
    /// Candidate address for P2P direct connection attempt
    CandidateOffer {
        /// Candidate type: 0 = host, 1 = server-reflexive (STUN), 2 = UPnP
        candidate_type: u8,
        /// Socket address encoded as bytes: 6 bytes (IPv4 u32 BE + port u16 BE) or 18 bytes (IPv6)
        addr: Vec<u8>,
        /// Priority (higher = preferred). Host=100, SRFLX=50, UPnP=30.
        priority: u32,
    },
    /// All candidates have been sent; peer may begin connection attempts
    CandidatesDone,
    /// Direct P2P connection established -- notify relay to stop forwarding
    DirectConnected,
    /// Direct P2P connection failed -- continue via relay
    DirectFailed,

    // --- Feature 35: Per-file accept/reject (DO NOT reorder; postcard ordinal) ---
    /// Receiver's per-file selection (sent after FileOffer, before chunks).
    ///
    /// Contains the indices of files from the manifest that the receiver
    /// wants to receive. If all indices are selected, the full transfer
    /// proceeds as normal (backward-compatible). Sent instead of FileAccept
    /// when the receiver uses `--per-file` mode.
    FileSelection {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// Indices of files from the manifest that the receiver wants (0-based)
        selected_indices: Vec<u32>,
    },

    // --- Device Discovery: Presence variants (DO NOT reorder; postcard ordinal) ---
    /// Announce device presence (browser → relay)
    PresenceAnnounce {
        /// User-visible device name (sanitized, max 64 chars)
        alias: String,
        /// Device type: "desktop", "mobile", "tablet"
        device_type: String,
        /// BLAKE3 fingerprint of identity (8 hex chars, truncated)
        fingerprint: String,
    },

    /// Full list of nearby peers (relay → browser, sent on join)
    NearbyPeers {
        /// All currently online peers on the same network
        peers: Vec<PeerPresence>,
    },

    /// Single peer came online (relay → browser, incremental update)
    PeerOnline {
        /// The peer that just connected
        peer: PeerPresence,
    },

    /// Single peer went offline (relay → browser, incremental update)
    PeerOffline {
        /// Fingerprint of the peer that disconnected
        fingerprint: String,
    },

    // --- Phase 23: WebRTC Browser P2P signaling (DO NOT reorder; postcard ordinal) ---
    /// WebRTC SDP offer (initiator -> responder, encrypted with session key)
    /// Sent over existing WebSocket after KEM handshake completes.
    /// The relay forwards this opaquely (just bytes).
    WebRtcOffer {
        /// AES-256-GCM encrypted SDP offer JSON
        encrypted_sdp: Vec<u8>,
        /// 12-byte nonce used for encryption
        nonce: [u8; 12],
    },

    /// WebRTC SDP answer (responder -> initiator, encrypted with session key)
    WebRtcAnswer {
        /// AES-256-GCM encrypted SDP answer JSON
        encrypted_sdp: Vec<u8>,
        /// 12-byte nonce used for encryption
        nonce: [u8; 12],
    },

    /// WebRTC ICE candidate (either direction, encrypted with session key)
    /// Trickled as candidates are discovered. Null candidate signals end-of-candidates.
    WebRtcIceCandidate {
        /// AES-256-GCM encrypted ICE candidate JSON (null = end-of-candidates)
        encrypted_candidate: Vec<u8>,
        /// 12-byte nonce used for encryption
        nonce: [u8; 12],
    },

    // --- Phase 24: Rich Chat variants (DO NOT reorder; postcard ordinal) ---
    /// Emoji reaction on a chat message.
    ///
    /// The reaction content (emoji string) is encrypted with domain-separated
    /// AAD (`tallow-reaction-v1`) to prevent nonce collision with chat text.
    /// `is_add` toggles between adding and removing a reaction.
    ChatReaction {
        /// Message ID of the message being reacted to (16 bytes)
        target_message_id: [u8; 16],
        /// AES-256-GCM encrypted reaction (emoji string)
        encrypted_reaction: Vec<u8>,
        /// 12-byte nonce used for encryption
        nonce: [u8; 12],
        /// true = add reaction, false = remove reaction
        is_add: bool,
    },

    /// Edit a previously sent chat message.
    ///
    /// The new content is encrypted with domain-separated AAD (`tallow-edit-v1`).
    /// `edit_version` is a monotonically increasing counter to order edits.
    ChatEdit {
        /// Message ID of the message being edited (16 bytes)
        target_message_id: [u8; 16],
        /// AES-256-GCM encrypted replacement content
        encrypted_content: Vec<u8>,
        /// 12-byte nonce used for encryption
        nonce: [u8; 12],
        /// Edit version counter (1, 2, 3, ...)
        edit_version: u32,
    },

    /// Delete a previously sent chat message (for everyone).
    ///
    /// The receiving side replaces the message with a "message removed" placeholder.
    ChatDelete {
        /// Message ID of the message to delete (16 bytes)
        target_message_id: [u8; 16],
    },

    /// Voice message with encrypted metadata.
    ///
    /// Audio is encrypted with domain-separated AAD (`tallow-voice-v1`).
    /// Duration and waveform are encrypted inside `encrypted_metadata`
    /// (JSON: `{"d":duration_ms,"w":[...waveform]}`) with AAD `tallow-voice-v1`.
    VoiceMessage {
        /// Unique message ID (16 bytes)
        message_id: [u8; 16],
        /// Monotonic sequence number for ordering
        sequence: u64,
        /// AES-256-GCM encrypted audio data
        encrypted_audio: Vec<u8>,
        /// 12-byte nonce used for encryption
        nonce: [u8; 12],
        /// Duration of the voice message in milliseconds (zero — real value in encrypted_metadata)
        duration_ms: u32,
        /// Low-resolution amplitude waveform (empty — real value in encrypted_metadata)
        waveform: Vec<u8>,
        /// AES-256-GCM encrypted metadata JSON (duration + waveform)
        #[serde(default)]
        encrypted_metadata: Vec<u8>,
        /// 12-byte nonce for metadata encryption
        #[serde(default)]
        metadata_nonce: [u8; 12],
    },

    /// Media attachment (image or video) in chat.
    ///
    /// Media data is encrypted with domain-separated AAD (`tallow-media-v1`).
    /// MIME type, width, and height are encrypted inside `encrypted_metadata`
    /// (JSON: `{"m":"mime","w":width,"h":height}`) with AAD `tallow-media-v1`.
    MediaAttachment {
        /// Unique message ID (16 bytes)
        message_id: [u8; 16],
        /// Monotonic sequence number for ordering
        sequence: u64,
        /// AES-256-GCM encrypted media data
        encrypted_data: Vec<u8>,
        /// 12-byte nonce used for encryption
        nonce: [u8; 12],
        /// MIME type (empty string — real value in encrypted_metadata)
        mime_type: String,
        /// Width in pixels (zero — real value in encrypted_metadata)
        width: u32,
        /// Height in pixels (zero — real value in encrypted_metadata)
        height: u32,
        /// AES-256-GCM encrypted metadata JSON (mime_type + dimensions)
        #[serde(default)]
        encrypted_metadata: Vec<u8>,
        /// 12-byte nonce for metadata encryption
        #[serde(default)]
        metadata_nonce: [u8; 12],
    },

    /// Set or clear the disappearing message timer for a chat.
    ///
    /// The duration is encrypted inside `encrypted_data` with AAD `tallow-chat-v1`.
    /// `duration_secs` is always 0 on the wire — real value in encrypted payload.
    DisappearingTimer {
        /// Timer duration in seconds (zero — real value in encrypted_data)
        duration_secs: u32,
        /// AES-256-GCM encrypted duration (4-byte LE u32)
        #[serde(default)]
        encrypted_data: Vec<u8>,
        /// 12-byte nonce for encryption
        #[serde(default)]
        nonce: [u8; 12],
    },

    /// Poll message for in-chat voting.
    ///
    /// The poll content (question and options) is encrypted with
    /// domain-separated AAD (`tallow-poll-v1`). The `multi_select` flag
    /// is encrypted inside `encrypted_metadata` with AAD `tallow-poll-v1`.
    ChatPoll {
        /// Unique message ID (16 bytes)
        message_id: [u8; 16],
        /// Monotonic sequence number for ordering
        sequence: u64,
        /// AES-256-GCM encrypted poll JSON (question + options + multi_select)
        encrypted_poll: Vec<u8>,
        /// 12-byte nonce used for encryption
        nonce: [u8; 12],
        /// Whether multiple options can be selected (false — real value in encrypted_poll JSON)
        multi_select: bool,
    },

    /// Vote on a poll.
    ///
    /// The vote content (selected option indices) is encrypted with
    /// domain-separated AAD (`tallow-poll-v1`).
    ChatPollVote {
        /// Message ID of the poll being voted on (16 bytes)
        target_message_id: [u8; 16],
        /// AES-256-GCM encrypted vote data (selected option indices)
        encrypted_vote: Vec<u8>,
        /// 12-byte nonce used for encryption
        nonce: [u8; 12],
    },

    /// Link preview metadata for a URL shared in chat.
    ///
    /// Generated client-side and encrypted with domain-separated AAD
    /// (`tallow-linkpreview-v1`). Contains title, description, thumbnail.
    LinkPreview {
        /// Message ID of the message containing the URL (16 bytes)
        target_message_id: [u8; 16],
        /// AES-256-GCM encrypted preview metadata JSON
        encrypted_metadata: Vec<u8>,
        /// 12-byte nonce used for encryption
        nonce: [u8; 12],
    },

    /// Request the peer to securely destroy all chat data for this session.
    ///
    /// On receipt, the peer MUST delete all messages, media, and metadata
    /// from IndexedDB and clear in-memory state. No acknowledgment is sent;
    /// the sender destroys their own copy independently.
    ChatDestroy,

    /// Offer metadata for a chunked media message (chat or clipboard).
    ///
    /// Sent before the first `MediaChunkData`. The receiver uses this to
    /// allocate assembly state and pre-render a placeholder with correct
    /// aspect ratio. The `message_id` is shared across all chunks.
    MediaChunkOffer {
        /// Unique message ID (16 bytes) — same across all chunks
        message_id: [u8; 16],
        /// Monotonic sequence number for ordering
        sequence: u64,
        /// Total number of chunks that will follow
        total_chunks: u64,
        /// Original file size in bytes (zero on wire — real value in encrypted_metadata)
        total_size: u64,
        /// MIME type (empty on wire — real value in encrypted_metadata)
        mime_type: String,
        /// Width in pixels (zero on wire — real value in encrypted_metadata)
        width: u32,
        /// Height in pixels (zero on wire — real value in encrypted_metadata)
        height: u32,
        /// Original filename (empty on wire — real value in encrypted_metadata)
        file_name: String,
        /// AES-256-GCM encrypted metadata JSON: {"m":"mime","w":width,"h":height,"f":"filename","s":total_size}
        #[serde(default)]
        encrypted_metadata: Vec<u8>,
        /// 12-byte nonce for metadata encryption
        #[serde(default)]
        metadata_nonce: [u8; 12],
    },

    /// One encrypted chunk of a chunked media message.
    ///
    /// Each chunk is independently encrypted with domain-separated AAD
    /// (`tallow-media-v1`). The receiver collects all chunks by `message_id`
    /// and assembles after receiving `total_chunks` pieces.
    MediaChunkData {
        /// Message ID matching the `MediaChunkOffer` (16 bytes)
        message_id: [u8; 16],
        /// Zero-based chunk index
        index: u64,
        /// AES-256-GCM encrypted chunk data (~256 KiB + 16-byte tag)
        encrypted_data: Vec<u8>,
        /// 12-byte nonce used for this chunk's encryption
        nonce: [u8; 12],
    },

    // --- Sealed Sender: hides sender identity from relay (DO NOT reorder; postcard ordinal) ---
    /// Sealed sender message envelope for multi-peer routing.
    ///
    /// The relay sees only `to_peer` for routing. `from_peer` and the
    /// application payload are AES-256-GCM encrypted inside
    /// `encrypted_envelope`, preventing the relay from constructing a
    /// directional communication graph between room participants.
    ///
    /// Wire layout (postcard, variant index 59 = 0x3B):
    /// ```text
    /// [0x3B] [to_peer: u8] [encrypted_envelope_len: varint] [encrypted_envelope...]
    /// ```
    ///
    /// `encrypted_envelope` encoding:
    /// ```text
    /// AES-256-GCM(
    ///   key   = pairwise_send_key derived via
    ///           derive_peer_keys(session_key, my_peer_id, to_peer),
    ///   nonce = [0u8; 4] || send_counter.to_be_bytes(),  // 12-byte counter nonce
    ///   aad   = b"tallow-sealed-v1",
    ///   plain = [from_peer: u8 || application_payload...],
    /// )
    /// ```
    ///
    /// Stored as: `nonce (12 bytes) || ciphertext (1 + payload_len bytes) || GCM tag (16 bytes)`.
    ///
    /// The relay forwards this message as-is — no byte patching required or
    /// possible, since there is no plaintext `from_peer` field to overwrite.
    SealedTargeted {
        /// Target peer ID for relay routing (0xFF = multicast to all except the sender)
        to_peer: u8,
        /// AES-256-GCM sealed envelope:
        /// `nonce (12 bytes) || ciphertext [from_peer: u8 || payload...] || GCM tag (16 bytes)`
        encrypted_envelope: Vec<u8>,
    },

    // --- Phase 25: Chat Session Presence (DO NOT reorder; postcard ordinal) ---
    /// Chat session presence update (discriminant 60 = 0x3C).
    ///
    /// Signals the sender's current availability state within an established
    /// chat session. Distinct from device-discovery presence (`PresenceAnnounce`):
    /// this travels inside an E2E-encrypted chat session and is forwarded opaquely
    /// by the relay.
    ///
    /// `encrypted_state` contains AES-256-GCM encrypted JSON:
    /// `{"status":"online"|"dnd"|"invisible"|"offline","last_seen":unix_secs}`
    /// with domain-separated AAD `tallow-presence-v1`.
    ///
    /// Privacy: `status` and `last_seen` are encrypted so the relay cannot
    /// observe the peer's availability pattern. Clients MUST check their
    /// privacy settings (lastSeen visibility, status broadcast) before sending.
    ///
    /// Rate-limiting: the relay enforces at most 2 presence updates per second
    /// per connection to prevent flooding. Excess messages are silently dropped.
    ChatPresence {
        /// AES-256-GCM encrypted JSON: `{"status":"online"|"dnd"|"invisible"|"offline","last_seen":unix_secs}`
        encrypted_state: Vec<u8>,
        /// 12-byte nonce used for encryption (counter-based, domain-separated with AAD `tallow-presence-v1`)
        nonce: [u8; 12],
    },

    // --- Transfer control hardening (DO NOT reorder; postcard ordinal) ---
    /// Sender announces the transfer ID immediately after the authenticated
    /// CPace + hybrid-KEM handshake.
    ///
    /// This lets both peers construct the same `TransferSession` before the
    /// encrypted manifest is built, so pre-offer receiver capability hints can
    /// be sent inside a session-authenticated control envelope instead of as
    /// magic-byte sentinel frames.
    TransferStart {
        /// Transfer ID for the upcoming file offer.
        transfer_id: [u8; 16],
    },

    /// Session-authenticated transfer control envelope.
    ///
    /// `ciphertext` is AES-256-GCM encrypted with the transfer session key.
    /// AAD is domain-separated and binds the envelope to `transfer_id` and
    /// `kind`. The relay can forward or drop it, but cannot forge or modify a
    /// valid receiver capability hint or chunk retransmit request.
    TransferControl {
        /// Transfer ID bound into the authenticated data.
        transfer_id: [u8; 16],
        /// Control payload kind. Current values:
        /// 1 = receiver capabilities, 2 = chunk retransmit request,
        /// 3-5 = browser progress protocol (snapshots / announce / drive —
        /// see `tallow-web`); peers that predate it warn-and-ignore.
        kind: u8,
        /// 12-byte AES-GCM nonce generated by the transfer session.
        nonce: [u8; 12],
        /// Encrypted postcard-encoded transfer control payload.
        ciphertext: Vec<u8>,
    },

    // ── Phase: Distributed Browser Pool ──
    /// Request a browser session from a remote node.
    PoolAcquireRequest {
        requester_node: String,
        session_id_prefix: String,
    },
    /// Response with allocated session.
    PoolAcquireResponse {
        session_id: String,
        internal_session_id: String,
        browser_index: u32,
    },
    /// Release a remote session.
    PoolReleaseRequest { session_id: String },
    /// Forward a CDP command to a remote browser.
    DistributedCdpCommand {
        session_id: String,
        rpc_id: u64,
        method: String,
        params: Option<Vec<u8>>,
    },
    /// Response from a remote CDP command.
    DistributedCdpResponse {
        rpc_id: u64,
        result: Option<Vec<u8>>,
        error: Option<String>,
    },
    /// Heartbeat from a node reporting its pool status.
    PoolHealthReport {
        node_id: String,
        active_browsers: u32,
        idle_browsers: u32,
        max_browsers: u32,
        timestamp: u64,
    },
    /// Notify that a session has expired.
    SessionExpired { session_id: String },

    // --- PQ authentication (v5+; DO NOT reorder; postcard ordinal) ---
    /// Authenticates the completed handshake transcript under the sender's
    /// long-term hybrid identity key (ML-DSA-87 + Ed25519; both must verify).
    ///
    /// Sent by both sides after `HandshakeComplete` in v5+ negotiations (the
    /// receiver ACKs with `PQ_AUTH_FLAG` in `HandshakeResponse.selected_kem`;
    /// see `kex`). Like the rest of the handshake flight it travels inside a
    /// `Targeted` envelope, so relays forward it opaquely without changes.
    ///
    /// The signature covers
    /// `DOMAIN_HANDSHAKE_SIGNED || role || transcript_hash`.
    HandshakeSigned {
        /// Signer role: 1 = handshake initiator (sender), 2 = responder
        /// (receiver). Bound into the signature; prevents reflecting a peer's
        /// own signed frame back at it.
        role: u8,
        /// postcard-serialized `sig::hybrid::HybridPublicKey`.
        identity_public_key: Vec<u8>,
        /// postcard-serialized `sig::hybrid::HybridSignature`.
        signature: Vec<u8>,
    },

    // --- Simple ("transport-only") mode (v6+; DO NOT reorder; postcard ordinal) ---
    /// Announces a transport-only (Simple) transfer instead of starting the
    /// crypto handshake. Sent by the sender as the FIRST message of a Simple
    /// session; the receiver confirms capability with `ModeAccept` before any
    /// offer flows. Full-mode sessions never send this.
    ModeAnnounce {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// Requested mode: 1 = simple (transport-only). See `MODE_SIMPLE`.
        mode: u8,
    },
    /// Confirms support for (and acceptance of) the announced Simple mode.
    /// Sent immediately on receipt of `ModeAnnounce` — before the user's
    /// file accept/reject — so an unaware receiver fails the session early.
    ModeAccept {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// Confirmed mode: 1 = simple (transport-only).
        mode: u8,
    },
    /// Simple-mode chunk: raw chunk bytes with NO compression and NO
    /// encryption (transport-only mode). Mirrors `Chunk`'s shape; the relay
    /// forwards it opaquely. Full-mode sessions never send this.
    SimpleChunk {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// Chunk index (0-based)
        index: u64,
        /// Total chunks (set on final chunk)
        total: Option<u64>,
        /// Raw chunk data (plaintext; no AEAD, no compression)
        data: Vec<u8>,
    },

    // --- Flow control (v6+; DO NOT reorder; postcard ordinal) ---
    /// Batched acknowledgement + credit grant (wire v6, A9 flow control).
    ///
    /// One frame replaces N `Ack` frames and moves window ownership to the
    /// receiver: `granted` is the authoritative count of additional chunks the
    /// sender may emit. Sent only when both peers negotiated
    /// `FLOW_CREDIT_FLAG` (see `kex.rs`); peers without it keep per-chunk
    /// `Ack`s and the legacy fixed window, so nothing changes until the
    /// version is bumped. Relays forward it opaquely.
    Credit {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// Highest index such that every index <= contiguous_prefix is drained
        contiguous_prefix: u64,
        /// Sparse drained indices above the prefix (hole fillers), bounded (<= 32)
        drained: Vec<u32>,
        /// Total additional chunks the sender may send now (authoritative)
        granted: u32,
        /// Receiver's measured drain rate, KiB/s (sender's pre-grant estimate)
        drain_kib_s: u32,
    },

    // --- Authenticated Simple mode (security review 2026-09-23, R2; DO NOT reorder; postcard ordinal) ---
    /// Authenticated `ModeAnnounce` (ordinal 75).
    ///
    /// Simple mode has no handshake, so a receiver could not tell the real
    /// sender from an injector racing an announce into the room. The sender
    /// now announces with a MAC under a key derived from the shared room code
    /// (`crate::mode_auth`), and a receiver that sees one verifies it BEFORE
    /// accepting. Peers that predate this variant send the plain
    /// `ModeAnnounce` and are accepted with the unauthenticated-peer banner
    /// instead of being silently trusted.
    ModeAnnounceAuthed {
        /// Transfer ID
        transfer_id: [u8; 16],
        /// Requested mode: 1 = simple (transport-only). See `MODE_SIMPLE`.
        mode: u8,
        /// Code-derived MAC over (label, transfer_id, mode).
        mac: [u8; 32],
    },
    /// Authenticated `ModeAccept` (ordinal 76) — the receiver echoes the
    /// transfer id with its own code-derived MAC, so the sender knows a real
    /// receiver (not an injector) confirmed the mode.
    ModeAcceptAuthed {
        /// Transfer ID (echoed from the announce)
        transfer_id: [u8; 16],
        /// Confirmed mode: 1 = simple (transport-only).
        mode: u8,
        /// Code-derived MAC over (label, transfer_id, mode).
        mac: [u8; 32],
    },
    /// v9 handshake response (ordinal 77, receiver -> initiator), sent
    /// **instead of** `HandshakeResponse` when the initiator declared
    /// `protocol_version >= 9`. Appended last so no existing postcard ordinal
    /// moves.
    ///
    /// WHY A NEW VARIANT: `HandshakeResponse.selected_kem` is a FULL carrier —
    /// bits 0-1 hold the KEM discriminant and bits 2-7 already carry six
    /// capability flags (SCOPED_TRANSFER, CANONICAL_KEX, PQ_AUTH,
    /// DEFLATE_CHUNK, NO_ZSTD_CHUNK, FLOW_CREDIT). There is no free bit for a
    /// new capability, and adding a field to `HandshakeResponse` itself would
    /// break positional postcard decode for a deployed v8 peer.
    ///
    /// INTEROP-SAFE BY CONSTRUCTION: the receiver already knows the declared
    /// version (it is `process_init`'s first argument), so it only ever sends
    /// this to a peer that declared >= 9. A v9 initiator MUST still accept the
    /// older `HandshakeResponse` — it cannot know the receiver's build in
    /// advance — and a missing `capability_bits` means "no v9 capabilities":
    /// a disclosed downgrade, never a refusal.
    ///
    /// (DO NOT reorder; postcard ordinal)
    HandshakeResponseV9 {
        /// Selected KEM algorithm discriminant
        selected_kem: u8,
        /// CPace responder public message (32 bytes)
        cpace_public: [u8; 32],
        /// Serialized hybrid KEM public key
        kem_public_key: Vec<u8>,
        /// Random nonce for session ID binding (16 bytes)
        nonce: [u8; 16],
        /// Receiver capability bits; see `CAP_PQ_CHAT`.
        ///
        /// Phase 5 item 2: from [`CAPABILITY_BINDING_VERSION`] on, this byte is
        /// bound into the handshake transcript by BOTH peers — see
        /// [`crate::wire::capabilities`] — so clearing or altering it in flight
        /// diverges the session key, the ratchet seed and both confirmation tags
        /// and the handshake FAILS instead of downgrading silently. Below that
        /// version it is a plain field, and a clear value is a DISCLOSED
        /// "no capabilities" (the static-key chat path), never a refusal.
        ///
        /// `Message::handshake_response_parts` is the sanctioned way to read it;
        /// a direct match on `Message::HandshakeResponse` sees only the older shape
        /// and reads the byte as `0`.
        ///
        /// [`CAPABILITY_BINDING_VERSION`]: crate::wire::capabilities::CAPABILITY_BINDING_VERSION
        capability_bits: u8,
    },
    /// v9: encrypted chat text carried by a `RatchetSession` instead of the static-key
    /// `ChatSession` (`ChatText`).
    ///
    /// A separate variant rather than a flag inside `ChatText`, for two reasons:
    ///
    ///   1. The two envelopes differ structurally. `ChatText` carries an explicit
    ///      `nonce` because the static-key path supplies one; a ratchet payload carries
    ///      its own framing (`TQP1` magic+flags(5) | payload | Poly1305 tag(16)) and has
    ///      nothing separate to send. Overloading `nonce` to mean "the rest of the
    ///      ratchet frame" would be framing metadata wearing crypto material — the
    ///      anti-pattern docs 08 and 09 both reject.
    ///   2. A receiver that does not know v9 REJECTS this as an unexpected message,
    ///      which is the correct fail-closed outcome. A flag inside `ChatText` would be
    ///      inert to an old receiver, which would then try to AEAD-decrypt ratchet bytes
    ///      as if they were static-key ciphertext — a confusing failure deeper in the
    ///      stack instead of a clean protocol rejection.
    ///
    /// (DO NOT reorder; postcard ordinal)
    ChatTextV9 {
        /// Unique message ID for read receipts (random 16 bytes)
        message_id: [u8; 16],
        /// Monotonic sequence number for ordering
        sequence: u64,
        /// The ratchet's own framing, passed through untranslated:
        /// `TQP1` magic+flags(5) | payload | Poly1305 tag(16)` — the payload is
        /// `frame_pq_payload`'s output (optional ML-KEM rekey control records,
        /// then the text) and the trailing 16 bytes are the AEAD tag.
        ///
        /// There is NO ratchet public key and NO counter on this path: chat
        /// encrypts through `TripleRatchet::encrypt_message` (the headerless
        /// entry point), not `encrypt_with_header`. Measured against the shipped
        /// build with no control records: `text + 21` bytes. Do not derive a
        /// size model from this comment — `10-CHAT-FRAME-CELLS-DESIGN.md` §3
        /// carries the measured frame model.
        ratchet_ciphertext: Vec<u8>,
    },
}

/// Receiver capability: it can drive browser chat on the **ratcheting** session
/// (`RatchetSession::encryptChat`/`decryptChat`) rather than the static-key
/// `ChatSession`. Bit 0 of `HandshakeResponseV9::capability_bits`.
///
/// Cleared/absent means the static-key chat path: a disclosed downgrade, never
/// a refusal, so chat keeps working between generations instead of breaking.
pub const CAP_PQ_CHAT: u8 = 0x01;

impl Message {
    /// Unified view of BOTH handshake-response shapes.
    ///
    /// Returns `(selected_kem, cpace_public, kem_public_key, nonce,
    /// capability_bits)`. `capability_bits` is `0` for the older
    /// `HandshakeResponse`, which has no capability byte — it means "no v9
    /// capabilities", not an error.
    ///
    /// CALLERS MUST USE THIS instead of matching `Message::HandshakeResponse`
    /// directly. A v9 receiver answers a peer that declared >= 9 with
    /// `HandshakeResponseV9`, and a direct match treats that as an unexpected
    /// message: a handshake failure that **compiles cleanly**, which is exactly
    /// the silent-break class this accessor exists to remove.
    pub fn handshake_response_parts(&self) -> Option<(u8, [u8; 32], Vec<u8>, [u8; 16], u8)> {
        match self {
            Message::HandshakeResponse {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
            } => Some((
                *selected_kem,
                *cpace_public,
                kem_public_key.clone(),
                *nonce,
                0,
            )),
            Message::HandshakeResponseV9 {
                selected_kem,
                cpace_public,
                kem_public_key,
                nonce,
                capability_bits,
            } => Some((
                *selected_kem,
                *cpace_public,
                kem_public_key.clone(),
                *nonce,
                *capability_bits,
            )),
            _ => None,
        }
    }

    /// True for either handshake-response shape; use with
    /// [`Message::handshake_response_parts`].
    pub fn is_handshake_response(&self) -> bool {
        matches!(
            self,
            Message::HandshakeResponse { .. } | Message::HandshakeResponseV9 { .. }
        )
    }
}

/// Presence information for a nearby device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PeerPresence {
    /// User-visible device name
    pub alias: String,
    /// Device type: "desktop", "mobile", "tablet"
    pub device_type: String,
    /// 8-char hex fingerprint
    pub fingerprint: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// P1 #13: lock the on-wire postcard discriminant for relay-critical
    /// messages (see `wire::ordinals`). Prints every observed value, then
    /// asserts, so drift shows both the wire and registry numbers.
    #[test]
    fn ordinal_registry_matches_wire() {
        use crate::wire::ordinals as o;
        let cases: Vec<(&str, u8, Message)> = vec![
            (
                "HANDSHAKE_FAILED",
                o::HANDSHAKE_FAILED,
                Message::HandshakeFailed {
                    reason: "x".to_string(),
                },
            ),
            ("PEER_ARRIVED", o::PEER_ARRIVED, Message::PeerArrived),
            ("PEER_DEPARTED", o::PEER_DEPARTED, Message::PeerDeparted),
            ("ROOM_LEAVE", o::ROOM_LEAVE, Message::RoomLeave),
            (
                "ROOM_JOINED",
                o::ROOM_JOINED,
                Message::RoomJoined { peer_present: true },
            ),
            (
                "TARGETED",
                o::TARGETED,
                Message::Targeted {
                    from_peer: 1,
                    to_peer: 2,
                    payload: vec![9],
                },
            ),
            (
                "CHUNK",
                o::CHUNK,
                Message::Chunk {
                    transfer_id: [1u8; 16],
                    index: 1,
                    total: None,
                    data: vec![9],
                },
            ),
            (
                "SIMPLE_CHUNK",
                o::SIMPLE_CHUNK,
                Message::SimpleChunk {
                    transfer_id: [1u8; 16],
                    index: 1,
                    total: None,
                    data: vec![9],
                },
            ),
            (
                "MODE_ANNOUNCE",
                o::MODE_ANNOUNCE,
                Message::ModeAnnounce {
                    transfer_id: [1u8; 16],
                    mode: MODE_SIMPLE,
                },
            ),
            (
                "MODE_ACCEPT",
                o::MODE_ACCEPT,
                Message::ModeAccept {
                    transfer_id: [1u8; 16],
                    mode: MODE_SIMPLE,
                },
            ),
            (
                "FLOW_CREDIT",
                o::FLOW_CREDIT,
                Message::Credit {
                    transfer_id: [1u8; 16],
                    contiguous_prefix: 7,
                    drained: vec![9],
                    granted: 8,
                    drain_kib_s: 4096,
                },
            ),
            (
                "MODE_ANNOUNCE_AUTHED",
                o::MODE_ANNOUNCE_AUTHED,
                Message::ModeAnnounceAuthed {
                    transfer_id: [1u8; 16],
                    mode: MODE_SIMPLE,
                    mac: [5u8; 32],
                },
            ),
            (
                "MODE_ACCEPT_AUTHED",
                o::MODE_ACCEPT_AUTHED,
                Message::ModeAcceptAuthed {
                    transfer_id: [1u8; 16],
                    mode: MODE_SIMPLE,
                    mac: [5u8; 32],
                },
            ),
        ];
        let mut failures = Vec::new();
        for (name, expected, msg) in &cases {
            let bytes = postcard::to_stdvec(msg).expect("encode");
            let wire = bytes[0];
            eprintln!("ORD {}={}", name, wire);
            if wire != *expected {
                failures.push(format!("{}: wire={} registry={}", name, wire, expected));
            }
        }
        assert!(failures.is_empty(), "ordinal drift: {:?}", failures);
    }

    #[test]
    fn test_message_roundtrip_all_variants() {
        let messages = vec![
            Message::VersionRequest {
                supported_versions: vec![1, 2],
            },
            Message::VersionResponse {
                selected_version: 1,
            },
            Message::VersionReject {
                reason: "unsupported".to_string(),
            },
            Message::RoomJoin {
                room_id: vec![0u8; 32],
                password_hash: Some(vec![0xAB; 32]),
                forward_to_relay: None,
            },
            Message::RoomJoin {
                room_id: vec![0u8; 32],
                password_hash: None,
                forward_to_relay: None,
            },
            Message::RoomJoined { peer_present: true },
            Message::RoomLeave,
            Message::PeerArrived,
            Message::PeerDeparted,
            Message::FileOffer {
                transfer_id: [1u8; 16],
                manifest: vec![0, 1, 2, 3],
            },
            Message::FileAccept {
                transfer_id: [1u8; 16],
            },
            Message::FileReject {
                transfer_id: [1u8; 16],
                reason: "too large".to_string(),
            },
            Message::Chunk {
                transfer_id: [1u8; 16],
                index: 42,
                total: Some(100),
                data: vec![0xDE, 0xAD, 0xBE, 0xEF],
            },
            Message::Ack {
                transfer_id: [1u8; 16],
                index: 42,
            },
            Message::Credit {
                transfer_id: [1u8; 16],
                contiguous_prefix: 41,
                drained: vec![44],
                granted: 12,
                drain_kib_s: 8192,
            },
            Message::TransferComplete {
                transfer_id: [1u8; 16],
                hash: [0xABu8; 32],
                merkle_root: None,
            },
            Message::TransferComplete {
                transfer_id: [1u8; 16],
                hash: [0xABu8; 32],
                merkle_root: Some([0xCDu8; 32]),
            },
            Message::TransferError {
                transfer_id: [1u8; 16],
                error: "disk full".to_string(),
            },
            Message::ManifestExchange {
                transfer_id: [2u8; 16],
                manifest: vec![10, 20, 30, 40],
            },
            Message::SyncDeleteList {
                transfer_id: [2u8; 16],
                paths: vec!["old/file.txt".to_string(), "removed.log".to_string()],
            },
            Message::ResumeInfo {
                transfer_id: [3u8; 16],
                manifest_hash: [0xFFu8; 32],
                verified_chunks: vec![0, 1, 5, 10],
            },
            Message::Ping,
            Message::Pong,
            Message::HandshakeInit {
                protocol_version: 2,
                suite_code: tallow_crypto::suite_code(),
                kem_capabilities: vec![0, 1, 2],
                cpace_public: [0xAA; 32],
                nonce: [0xBB; 16],
            },
            Message::HandshakeResponse {
                selected_kem: 2,
                cpace_public: [0xCC; 32],
                kem_public_key: vec![0xDD; 128],
                nonce: [0xEE; 16],
            },
            Message::HandshakeKem {
                kem_ciphertext: vec![0xFF; 256],
                confirmation: [0x11; 32],
            },
            Message::HandshakeComplete {
                confirmation: [0x22; 32],
            },
            Message::HandshakeFailed {
                reason: "handshake failed".to_string(),
            },
            Message::ChatText {
                message_id: [0xAA; 16],
                sequence: 1,
                ciphertext: vec![0xDE, 0xAD],
                nonce: [0xBB; 12],
            },
            Message::TypingIndicator { typing: true },
            Message::TypingIndicator { typing: false },
            Message::ReadReceipt {
                message_ids: vec![[0xCC; 16], [0xDD; 16]],
            },
            Message::ChatEnd,
            // Phase 19: Multi-peer variants
            Message::RoomJoinMulti {
                room_id: vec![0u8; 32],
                password_hash: Some(vec![0xAB; 32]),
                requested_capacity: 10,
            },
            Message::RoomJoinMulti {
                room_id: vec![0u8; 32],
                password_hash: None,
                requested_capacity: 0,
            },
            Message::RoomJoinedMulti {
                peer_id: 0,
                existing_peers: vec![],
            },
            Message::RoomJoinedMulti {
                peer_id: 3,
                existing_peers: vec![0, 1, 2],
            },
            Message::PeerJoinedRoom { peer_id: 5 },
            Message::PeerLeftRoom { peer_id: 2 },
            Message::Targeted {
                from_peer: 0,
                to_peer: 1,
                payload: vec![0xDE, 0xAD],
            },
            Message::Targeted {
                from_peer: 0,
                to_peer: 0xFF,
                payload: vec![],
            },
            Message::RoomPeerCount {
                count: 5,
                capacity: 10,
            },
            // Phase 20: P2P Direct signaling variants
            Message::CandidateOffer {
                candidate_type: 0,
                addr: vec![192, 168, 1, 42, 0x1F, 0x90],
                priority: 100,
            },
            Message::CandidateOffer {
                candidate_type: 1,
                addr: vec![],
                priority: 50,
            },
            Message::CandidatesDone,
            Message::DirectConnected,
            Message::DirectFailed,
            // Feature 35: Per-file selection
            Message::FileSelection {
                transfer_id: [1u8; 16],
                selected_indices: vec![0, 2, 5],
            },
            Message::FileSelection {
                transfer_id: [2u8; 16],
                selected_indices: vec![],
            },
            // Device Discovery: Presence
            Message::PresenceAnnounce {
                alias: "User's Laptop".into(),
                device_type: "desktop".into(),
                fingerprint: "a7f3c91e".into(),
            },
            Message::NearbyPeers {
                peers: vec![PeerPresence {
                    alias: "iPhone".into(),
                    device_type: "mobile".into(),
                    fingerprint: "b2e4d8f1".into(),
                }],
            },
            Message::PeerOnline {
                peer: PeerPresence {
                    alias: "Mac".into(),
                    device_type: "desktop".into(),
                    fingerprint: "c3f5e9a2".into(),
                },
            },
            Message::PeerOffline {
                fingerprint: "d4a6b7c3".into(),
            },
            // Phase 23: WebRTC Browser P2P signaling
            Message::WebRtcOffer {
                encrypted_sdp: vec![0xDE, 0xAD, 0xBE, 0xEF],
                nonce: [0xAA; 12],
            },
            Message::WebRtcAnswer {
                encrypted_sdp: vec![0xCA, 0xFE],
                nonce: [0xBB; 12],
            },
            Message::WebRtcIceCandidate {
                encrypted_candidate: vec![0x01, 0x02, 0x03],
                nonce: [0xCC; 12],
            },
            Message::WebRtcIceCandidate {
                encrypted_candidate: vec![], // end-of-candidates
                nonce: [0x00; 12],
            },
            // Phase 24: Rich Chat variants
            Message::ChatReaction {
                target_message_id: [0xAA; 16],
                encrypted_reaction: vec![0xDE, 0xAD],
                nonce: [0xBB; 12],
                is_add: true,
            },
            Message::ChatReaction {
                target_message_id: [0xCC; 16],
                encrypted_reaction: vec![],
                nonce: [0x00; 12],
                is_add: false,
            },
            Message::ChatEdit {
                target_message_id: [0xAA; 16],
                encrypted_content: vec![0xCA, 0xFE],
                nonce: [0xBB; 12],
                edit_version: 1,
            },
            Message::ChatDelete {
                target_message_id: [0xDD; 16],
            },
            Message::VoiceMessage {
                message_id: [0xAA; 16],
                sequence: 42,
                encrypted_audio: vec![0x01, 0x02, 0x03],
                nonce: [0xBB; 12],
                duration_ms: 0,
                waveform: vec![],
                encrypted_metadata: vec![0xEE; 32],
                metadata_nonce: [0xDD; 12],
            },
            Message::MediaAttachment {
                message_id: [0xAA; 16],
                sequence: 7,
                encrypted_data: vec![0xFF; 64],
                nonce: [0xBB; 12],
                mime_type: String::new(),
                width: 0,
                height: 0,
                encrypted_metadata: vec![0xEE; 24],
                metadata_nonce: [0xDD; 12],
            },
            Message::DisappearingTimer {
                duration_secs: 0,
                encrypted_data: vec![0xAB; 20],
                nonce: [0xCC; 12],
            },
            Message::DisappearingTimer {
                duration_secs: 0,
                encrypted_data: vec![],
                nonce: [0x00; 12],
            },
            Message::ChatPoll {
                message_id: [0xAA; 16],
                sequence: 3,
                encrypted_poll: vec![0xDE, 0xAD],
                nonce: [0xBB; 12],
                multi_select: false,
            },
            Message::ChatPollVote {
                target_message_id: [0xAA; 16],
                encrypted_vote: vec![0x01],
                nonce: [0xCC; 12],
            },
            Message::LinkPreview {
                target_message_id: [0xAA; 16],
                encrypted_metadata: vec![0xDE, 0xAD, 0xBE, 0xEF],
                nonce: [0xDD; 12],
            },
            Message::ChatDestroy,
            // Chunked media transfer
            Message::MediaChunkOffer {
                message_id: [0xAA; 16],
                sequence: 5,
                total_chunks: 10,
                total_size: 0,
                mime_type: String::new(),
                width: 0,
                height: 0,
                file_name: String::new(),
                encrypted_metadata: vec![0xEE; 48],
                metadata_nonce: [0xDD; 12],
            },
            Message::MediaChunkOffer {
                message_id: [0xBB; 16],
                sequence: 6,
                total_chunks: 1,
                total_size: 0,
                mime_type: String::new(),
                width: 0,
                height: 0,
                file_name: String::new(),
                encrypted_metadata: vec![0xEE; 16],
                metadata_nonce: [0xCC; 12],
            },
            Message::MediaChunkData {
                message_id: [0xAA; 16],
                index: 0,
                encrypted_data: vec![0xFF; 256],
                nonce: [0xCC; 12],
            },
            Message::MediaChunkData {
                message_id: [0xAA; 16],
                index: 9,
                encrypted_data: vec![],
                nonce: [0x00; 12],
            },
            // Sealed sender (variant index 59)
            Message::SealedTargeted {
                to_peer: 1,
                encrypted_envelope: vec![0u8; 12 + 1 + 10 + 16], // nonce+from_peer+payload+tag
            },
            Message::SealedTargeted {
                to_peer: 0xFF, // multicast
                encrypted_envelope: vec![0xAA; 29],
            },
            // Phase 25: Chat Session Presence (variant index 60)
            Message::ChatPresence {
                encrypted_state: vec![0xDE; 32], // 16-byte tag + 16 bytes ciphertext
                nonce: [0xAA; 12],
            },
            Message::ChatPresence {
                encrypted_state: vec![],
                nonce: [0x00; 12],
            },
            // Transfer control hardening (variant indices 61-62)
            Message::TransferStart {
                transfer_id: [0x11; 16],
            },
            Message::TransferControl {
                transfer_id: [0x11; 16],
                kind: 1,
                nonce: [0x22; 12],
                ciphertext: vec![0x33; 48],
            },
            // Phase: Distributed Browser Pool
            Message::PoolAcquireRequest {
                requester_node: "node-1".to_string(),
                session_id_prefix: "prefix-".to_string(),
            },
            Message::PoolAcquireResponse {
                session_id: "sess-123".to_string(),
                internal_session_id: "internal-456".to_string(),
                browser_index: 2,
            },
            Message::PoolReleaseRequest {
                session_id: "sess-123".to_string(),
            },
            Message::DistributedCdpCommand {
                session_id: "sess-123".to_string(),
                rpc_id: 42,
                method: "Page.navigate".to_string(),
                params: Some(vec![0xDE, 0xAD]),
            },
            Message::DistributedCdpCommand {
                session_id: "sess-123".to_string(),
                rpc_id: 43,
                method: "DOM.getDocument".to_string(),
                params: None,
            },
            Message::DistributedCdpResponse {
                rpc_id: 42,
                result: Some(vec![0xCA, 0xFE]),
                error: None,
            },
            Message::DistributedCdpResponse {
                rpc_id: 43,
                result: None,
                error: Some("not found".to_string()),
            },
            Message::PoolHealthReport {
                node_id: "node-2".to_string(),
                active_browsers: 3,
                idle_browsers: 1,
                max_browsers: 4,
                timestamp: 1234567890,
            },
            Message::SessionExpired {
                session_id: "sess-old".to_string(),
            },
            Message::HandshakeSigned {
                role: 1,
                identity_public_key: vec![0xAB; 8],
                signature: vec![0xCD; 16],
            },
            Message::ModeAnnounce {
                transfer_id: [2u8; 16],
                mode: MODE_SIMPLE,
            },
            Message::ModeAccept {
                transfer_id: [3u8; 16],
                mode: MODE_SIMPLE,
            },
            Message::SimpleChunk {
                transfer_id: [4u8; 16],
                index: 1,
                total: Some(2),
                data: vec![7, 8, 9],
            },
            Message::ModeAnnounceAuthed {
                transfer_id: [5u8; 16],
                mode: MODE_SIMPLE,
                mac: [6u8; 32],
            },
            Message::ModeAcceptAuthed {
                transfer_id: [6u8; 16],
                mode: MODE_SIMPLE,
                mac: [7u8; 32],
            },
        ];

        for msg in &messages {
            let bytes = postcard::to_stdvec(msg).expect("encode should succeed");
            let decoded: Message = postcard::from_bytes(&bytes).expect("decode should succeed");
            assert_eq!(&decoded, msg, "round-trip failed for {:?}", msg);
        }
    }

    #[test]
    fn test_message_compact_encoding() {
        // Ping should be very small (just a discriminant byte)
        let bytes = postcard::to_stdvec(&Message::Ping).unwrap();
        assert!(
            bytes.len() <= 2,
            "Ping should be compact, got {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn test_chat_message_roundtrips() {
        let messages = vec![
            Message::ChatText {
                message_id: [0xAA; 16],
                sequence: 0,
                ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
                nonce: [0xBB; 12],
            },
            Message::ChatText {
                message_id: [0xFF; 16],
                sequence: u64::MAX,
                ciphertext: vec![],
                nonce: [0x00; 12],
            },
            Message::TypingIndicator { typing: true },
            Message::TypingIndicator { typing: false },
            Message::ReadReceipt {
                message_ids: vec![],
            },
            Message::ReadReceipt {
                message_ids: vec![[0x11; 16], [0x22; 16], [0x33; 16]],
            },
            Message::ChatEnd,
        ];

        for msg in &messages {
            let bytes = postcard::to_stdvec(msg).expect("encode");
            let decoded: Message = postcard::from_bytes(&bytes).expect("decode");
            assert_eq!(&decoded, msg);
        }
    }

    #[test]
    fn test_chat_end_compact() {
        // ChatEnd should be very small (just a discriminant byte), like Ping
        let bytes = postcard::to_stdvec(&Message::ChatEnd).unwrap();
        assert!(
            bytes.len() <= 2,
            "ChatEnd should be compact, got {} bytes",
            bytes.len()
        );
    }

    #[test]
    fn test_discriminant_stability_chat_end() {
        // ChatEnd was the last variant before Phase 19 additions.
        // Its encoded discriminant must not change when new variants are appended.
        let bytes = postcard::to_stdvec(&Message::ChatEnd).unwrap();
        // ChatEnd is variant index 28 (0-indexed). Postcard encodes this as varint 28.
        assert_eq!(bytes[0], 28, "ChatEnd discriminant must remain 28");
    }

    /// Verify a Targeted message can carry an inner ChatText through
    /// nested postcard serialization (the multi-peer envelope pattern).
    #[test]
    fn test_targeted_with_inner_chat_text() {
        let inner = Message::ChatText {
            message_id: [0xAA; 16],
            sequence: 5,
            ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
            nonce: [0xBB; 12],
        };
        let inner_bytes = postcard::to_stdvec(&inner).unwrap();

        let targeted = Message::Targeted {
            from_peer: 0,
            to_peer: 1,
            payload: inner_bytes,
        };

        let encoded = postcard::to_stdvec(&targeted).unwrap();
        let decoded: Message = postcard::from_bytes(&encoded).unwrap();

        if let Message::Targeted {
            from_peer,
            to_peer,
            payload,
        } = decoded
        {
            assert_eq!(from_peer, 0);
            assert_eq!(to_peer, 1);
            let inner_decoded: Message = postcard::from_bytes(&payload).unwrap();
            assert_eq!(inner_decoded, inner);
        } else {
            panic!("Expected Targeted");
        }
    }

    /// Verify pre-Phase-19 variants still round-trip correctly after
    /// appending the new multi-peer variants (backward compatibility).
    #[test]
    fn test_old_variants_stable_after_phase19() {
        let old_messages = vec![
            Message::Ping,
            Message::Pong,
            Message::RoomJoin {
                room_id: vec![0; 32],
                password_hash: None,
                forward_to_relay: None,
            },
            Message::RoomJoined { peer_present: true },
            Message::ChatEnd,
            Message::ChatText {
                message_id: [0xAA; 16],
                sequence: 1,
                ciphertext: vec![0xDE, 0xAD],
                nonce: [0xBB; 12],
            },
            Message::HandshakeInit {
                protocol_version: 1,
                suite_code: tallow_crypto::suite_code(),
                kem_capabilities: vec![0],
                cpace_public: [0xCC; 32],
                nonce: [0xDD; 16],
            },
        ];
        for msg in &old_messages {
            let bytes = postcard::to_stdvec(msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(&decoded, msg, "backward compat failed for {:?}", msg);
        }
    }

    #[test]
    fn test_discriminant_stability_p2p_variants() {
        // RoomPeerCount was variant index 34 (the last pre-Phase-20 variant).
        // CandidateOffer must be 35, CandidatesDone 36, DirectConnected 37, DirectFailed 38.
        let bytes = postcard::to_stdvec(&Message::CandidateOffer {
            candidate_type: 0,
            addr: vec![],
            priority: 0,
        })
        .unwrap();
        assert_eq!(bytes[0], 35, "CandidateOffer discriminant must be 35");

        let bytes = postcard::to_stdvec(&Message::CandidatesDone).unwrap();
        assert_eq!(bytes[0], 36, "CandidatesDone discriminant must be 36");

        let bytes = postcard::to_stdvec(&Message::DirectConnected).unwrap();
        assert_eq!(bytes[0], 37, "DirectConnected discriminant must be 37");

        let bytes = postcard::to_stdvec(&Message::DirectFailed).unwrap();
        assert_eq!(bytes[0], 38, "DirectFailed discriminant must be 38");
    }

    /// Verify all P2P signaling message variants round-trip correctly through postcard
    #[test]
    fn test_p2p_message_roundtrip() {
        let msgs = vec![
            Message::CandidateOffer {
                candidate_type: 0,
                addr: vec![192, 168, 1, 42, 0x1F, 0x90], // 192.168.1.42:8080
                priority: 100,
            },
            Message::CandidateOffer {
                candidate_type: 1,
                addr: vec![8, 8, 8, 8, 0x11, 0x51], // 8.8.8.8:4433
                priority: 50,
            },
            Message::CandidateOffer {
                candidate_type: 2,
                addr: vec![10, 0, 0, 1, 0x00, 0x50], // 10.0.0.1:80
                priority: 30,
            },
            Message::CandidatesDone,
            Message::DirectConnected,
            Message::DirectFailed,
        ];

        for msg in &msgs {
            let bytes = postcard::to_stdvec(msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(&decoded, msg, "P2P round-trip failed for {:?}", msg);
        }
    }

    /// Verify pre-Phase-20 variants are unchanged after appending P2P variants
    #[test]
    fn test_old_variants_stable_after_phase20() {
        let old_messages = vec![
            Message::Ping,
            Message::Pong,
            Message::ChatEnd,
            Message::RoomJoinMulti {
                room_id: vec![0; 32],
                password_hash: None,
                requested_capacity: 5,
            },
            Message::RoomPeerCount {
                count: 3,
                capacity: 10,
            },
            Message::HandshakeInit {
                protocol_version: 1,
                suite_code: tallow_crypto::suite_code(),
                kem_capabilities: vec![0],
                cpace_public: [0xCC; 32],
                nonce: [0xDD; 16],
            },
            Message::FileOffer {
                transfer_id: [1u8; 16],
                manifest: vec![0, 1, 2, 3],
            },
        ];
        for msg in &old_messages {
            let bytes = postcard::to_stdvec(msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(
                &decoded, msg,
                "backward compat failed after Phase 20 for {:?}",
                msg
            );
        }
    }

    /// Verify CandidateOffer with empty addr round-trips (edge case)
    #[test]
    fn test_candidate_offer_empty_addr() {
        let msg = Message::CandidateOffer {
            candidate_type: 0,
            addr: vec![],
            priority: 0,
        };
        let bytes = postcard::to_stdvec(&msg).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    /// Verify CandidateOffer with IPv6-sized addr (18 bytes) round-trips
    #[test]
    fn test_candidate_offer_ipv6_addr() {
        let msg = Message::CandidateOffer {
            candidate_type: 0,
            addr: vec![
                0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x01, 0x11, 0x51,
            ],
            priority: 100,
        };
        let bytes = postcard::to_stdvec(&msg).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded, msg);
    }

    /// Verify a Targeted broadcast (to_peer = 0xFF) with inner ChatEnd.
    #[test]
    fn test_targeted_broadcast_chat_end() {
        let inner = Message::ChatEnd;
        let inner_bytes = postcard::to_stdvec(&inner).unwrap();

        let broadcast = Message::Targeted {
            from_peer: 2,
            to_peer: 0xFF,
            payload: inner_bytes,
        };

        let encoded = postcard::to_stdvec(&broadcast).unwrap();
        let decoded: Message = postcard::from_bytes(&encoded).unwrap();

        if let Message::Targeted {
            from_peer,
            to_peer,
            payload,
        } = decoded
        {
            assert_eq!(from_peer, 2);
            assert_eq!(to_peer, 0xFF);
            let inner_decoded: Message = postcard::from_bytes(&payload).unwrap();
            assert_eq!(inner_decoded, Message::ChatEnd);
        } else {
            panic!("Expected Targeted");
        }
    }

    // --- Feature 35: FileSelection tests ---

    #[test]
    fn test_file_selection_roundtrip() {
        let messages = vec![
            Message::FileSelection {
                transfer_id: [0xAA; 16],
                selected_indices: vec![0, 1, 2, 3],
            },
            Message::FileSelection {
                transfer_id: [0xBB; 16],
                selected_indices: vec![],
            },
            Message::FileSelection {
                transfer_id: [0xCC; 16],
                selected_indices: vec![0],
            },
            Message::FileSelection {
                transfer_id: [0xDD; 16],
                selected_indices: vec![u32::MAX],
            },
        ];

        for msg in &messages {
            let bytes = postcard::to_stdvec(msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(
                &decoded, msg,
                "FileSelection round-trip failed for {:?}",
                msg
            );
        }
    }

    #[test]
    fn test_discriminant_stability_file_selection() {
        // FileSelection is the variant after DirectFailed (index 38).
        // It must be discriminant 39.
        let bytes = postcard::to_stdvec(&Message::FileSelection {
            transfer_id: [0; 16],
            selected_indices: vec![],
        })
        .unwrap();
        assert_eq!(bytes[0], 39, "FileSelection discriminant must be 39");
    }

    #[test]
    fn test_old_variants_stable_after_file_selection() {
        // Verify that appending FileSelection does not shift existing discriminants
        let old_messages = vec![
            Message::Ping,
            Message::Pong,
            Message::ChatEnd,
            Message::DirectFailed,
            Message::FileOffer {
                transfer_id: [1u8; 16],
                manifest: vec![0, 1, 2, 3],
            },
            Message::FileAccept {
                transfer_id: [1u8; 16],
            },
        ];
        for msg in &old_messages {
            let bytes = postcard::to_stdvec(msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(
                &decoded, msg,
                "backward compat failed after FileSelection for {:?}",
                msg
            );
        }
    }

    // --- Device Discovery: Presence tests ---

    #[test]
    fn test_presence_announce_roundtrip() {
        let msg = Message::PresenceAnnounce {
            alias: "User's Laptop".into(),
            device_type: "desktop".into(),
            fingerprint: "a7f3c91e".into(),
        };
        let bytes = postcard::to_stdvec(&msg).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(&decoded, &msg);
    }

    #[test]
    fn test_nearby_peers_roundtrip() {
        let msg = Message::NearbyPeers {
            peers: vec![
                PeerPresence {
                    alias: "iPhone".into(),
                    device_type: "mobile".into(),
                    fingerprint: "b2e4d8f1".into(),
                },
                PeerPresence {
                    alias: "Work PC".into(),
                    device_type: "desktop".into(),
                    fingerprint: "c3f5e9a2".into(),
                },
            ],
        };
        let bytes = postcard::to_stdvec(&msg).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(&decoded, &msg);
    }

    #[test]
    fn test_peer_online_offline_roundtrip() {
        let online = Message::PeerOnline {
            peer: PeerPresence {
                alias: "Android Phone".into(),
                device_type: "mobile".into(),
                fingerprint: "d4a6b7c3".into(),
            },
        };
        let offline = Message::PeerOffline {
            fingerprint: "d4a6b7c3".into(),
        };
        for msg in [&online, &offline] {
            let bytes = postcard::to_stdvec(msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(&decoded, msg);
        }
    }

    #[test]
    fn test_discriminant_stability_presence() {
        // PresenceAnnounce is the variant after FileSelection (39).
        // It must be discriminant 40.
        let bytes = postcard::to_stdvec(&Message::PresenceAnnounce {
            alias: String::new(),
            device_type: String::new(),
            fingerprint: String::new(),
        })
        .unwrap();
        assert_eq!(bytes[0], 40, "PresenceAnnounce discriminant must be 40");

        // NearbyPeers = 41
        let bytes = postcard::to_stdvec(&Message::NearbyPeers { peers: vec![] }).unwrap();
        assert_eq!(bytes[0], 41, "NearbyPeers discriminant must be 41");

        // PeerOnline = 42
        let bytes = postcard::to_stdvec(&Message::PeerOnline {
            peer: PeerPresence {
                alias: String::new(),
                device_type: String::new(),
                fingerprint: String::new(),
            },
        })
        .unwrap();
        assert_eq!(bytes[0], 42, "PeerOnline discriminant must be 42");

        // PeerOffline = 43
        let bytes = postcard::to_stdvec(&Message::PeerOffline {
            fingerprint: String::new(),
        })
        .unwrap();
        assert_eq!(bytes[0], 43, "PeerOffline discriminant must be 43");
    }

    #[test]
    fn test_old_variants_stable_after_presence() {
        // Verify that appending presence variants does not shift existing discriminants
        let old_messages = vec![
            Message::Ping,
            Message::Pong,
            Message::ChatEnd,
            Message::DirectFailed,
            Message::FileSelection {
                transfer_id: [0; 16],
                selected_indices: vec![1, 2],
            },
        ];
        for msg in &old_messages {
            let bytes = postcard::to_stdvec(msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(
                &decoded, msg,
                "backward compat failed after presence variants for {:?}",
                msg
            );
        }
    }

    // --- Phase 23: WebRTC Browser P2P tests ---

    #[test]
    fn test_webrtc_message_roundtrip() {
        let messages = vec![
            Message::WebRtcOffer {
                encrypted_sdp: vec![0xDE, 0xAD, 0xBE, 0xEF],
                nonce: [0xAA; 12],
            },
            Message::WebRtcOffer {
                encrypted_sdp: vec![], // empty SDP edge case
                nonce: [0x00; 12],
            },
            Message::WebRtcAnswer {
                encrypted_sdp: vec![0xCA, 0xFE, 0xBA, 0xBE],
                nonce: [0xBB; 12],
            },
            Message::WebRtcIceCandidate {
                encrypted_candidate: vec![0x01, 0x02, 0x03],
                nonce: [0xCC; 12],
            },
            Message::WebRtcIceCandidate {
                encrypted_candidate: vec![], // end-of-candidates signal
                nonce: [0x00; 12],
            },
        ];

        for msg in &messages {
            let bytes = postcard::to_stdvec(msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(&decoded, msg, "WebRTC round-trip failed for {:?}", msg);
        }
    }

    #[test]
    fn test_discriminant_stability_webrtc() {
        // PeerOffline was discriminant 43. WebRtcOffer must be 44, Answer 45, IceCandidate 46.
        let bytes = postcard::to_stdvec(&Message::WebRtcOffer {
            encrypted_sdp: vec![],
            nonce: [0; 12],
        })
        .unwrap();
        assert_eq!(bytes[0], 44, "WebRtcOffer discriminant must be 44");

        let bytes = postcard::to_stdvec(&Message::WebRtcAnswer {
            encrypted_sdp: vec![],
            nonce: [0; 12],
        })
        .unwrap();
        assert_eq!(bytes[0], 45, "WebRtcAnswer discriminant must be 45");

        let bytes = postcard::to_stdvec(&Message::WebRtcIceCandidate {
            encrypted_candidate: vec![],
            nonce: [0; 12],
        })
        .unwrap();
        assert_eq!(bytes[0], 46, "WebRtcIceCandidate discriminant must be 46");
    }

    #[test]
    fn test_old_variants_stable_after_webrtc() {
        // Verify all pre-Phase-23 variants are unchanged after appending WebRTC variants
        let old_messages = vec![
            Message::Ping,
            Message::Pong,
            Message::ChatEnd,
            Message::DirectFailed,
            Message::FileSelection {
                transfer_id: [0; 16],
                selected_indices: vec![1, 2],
            },
            Message::PeerOffline {
                fingerprint: "abcdef01".into(),
            },
        ];
        for msg in &old_messages {
            let bytes = postcard::to_stdvec(msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(
                &decoded, msg,
                "backward compat failed after WebRTC variants for {:?}",
                msg
            );
        }
    }

    // --- Phase 24: Rich Chat tests ---

    /// Round-trip all 9 new rich chat message variants through postcard encode/decode
    #[test]
    fn test_rich_chat_message_roundtrip() {
        let messages = vec![
            Message::ChatReaction {
                target_message_id: [0xAA; 16],
                encrypted_reaction: vec![0xDE, 0xAD],
                nonce: [0xBB; 12],
                is_add: true,
            },
            Message::ChatReaction {
                target_message_id: [0xCC; 16],
                encrypted_reaction: vec![],
                nonce: [0x00; 12],
                is_add: false,
            },
            Message::ChatEdit {
                target_message_id: [0xAA; 16],
                encrypted_content: vec![0xCA, 0xFE],
                nonce: [0xBB; 12],
                edit_version: 1,
            },
            Message::ChatEdit {
                target_message_id: [0xFF; 16],
                encrypted_content: vec![],
                nonce: [0x00; 12],
                edit_version: u32::MAX,
            },
            Message::ChatDelete {
                target_message_id: [0xDD; 16],
            },
            Message::VoiceMessage {
                message_id: [0xAA; 16],
                sequence: 42,
                encrypted_audio: vec![0x01, 0x02, 0x03],
                nonce: [0xBB; 12],
                duration_ms: 0,
                waveform: vec![],
                encrypted_metadata: vec![0xEE; 32],
                metadata_nonce: [0xDD; 12],
            },
            Message::VoiceMessage {
                message_id: [0xFF; 16],
                sequence: 0,
                encrypted_audio: vec![],
                nonce: [0x00; 12],
                duration_ms: 0,
                waveform: vec![],
                encrypted_metadata: vec![],
                metadata_nonce: [0x00; 12],
            },
            Message::MediaAttachment {
                message_id: [0xAA; 16],
                sequence: 7,
                encrypted_data: vec![0xFF; 64],
                nonce: [0xBB; 12],
                mime_type: String::new(),
                width: 0,
                height: 0,
                encrypted_metadata: vec![0xEE; 24],
                metadata_nonce: [0xDD; 12],
            },
            Message::MediaAttachment {
                message_id: [0xBB; 16],
                sequence: 0,
                encrypted_data: vec![],
                nonce: [0x00; 12],
                mime_type: String::new(),
                width: 0,
                height: 0,
                encrypted_metadata: vec![],
                metadata_nonce: [0x00; 12],
            },
            Message::DisappearingTimer {
                duration_secs: 0,
                encrypted_data: vec![0xAB; 20],
                nonce: [0xCC; 12],
            },
            Message::DisappearingTimer {
                duration_secs: 0,
                encrypted_data: vec![],
                nonce: [0x00; 12],
            },
            Message::ChatPoll {
                message_id: [0xAA; 16],
                sequence: 3,
                encrypted_poll: vec![0xDE, 0xAD],
                nonce: [0xBB; 12],
                multi_select: false,
            },
            Message::ChatPoll {
                message_id: [0xBB; 16],
                sequence: 0,
                encrypted_poll: vec![],
                nonce: [0x00; 12],
                multi_select: false,
            },
            Message::ChatPollVote {
                target_message_id: [0xAA; 16],
                encrypted_vote: vec![0x01],
                nonce: [0xCC; 12],
            },
            Message::ChatPollVote {
                target_message_id: [0xBB; 16],
                encrypted_vote: vec![],
                nonce: [0x00; 12],
            },
            Message::LinkPreview {
                target_message_id: [0xAA; 16],
                encrypted_metadata: vec![0xDE, 0xAD, 0xBE, 0xEF],
                nonce: [0xDD; 12],
            },
            Message::LinkPreview {
                target_message_id: [0xBB; 16],
                encrypted_metadata: vec![],
                nonce: [0x00; 12],
            },
        ];

        for msg in &messages {
            let bytes = postcard::to_stdvec(msg).expect("encode should succeed");
            let decoded: Message = postcard::from_bytes(&bytes).expect("decode should succeed");
            assert_eq!(&decoded, msg, "Rich chat round-trip failed for {:?}", msg);
        }
    }

    /// Verify discriminant stability for all 9 new rich chat variants (47-55)
    #[test]
    fn test_discriminant_stability_rich_chat() {
        // ChatReaction = 47
        let bytes = postcard::to_stdvec(&Message::ChatReaction {
            target_message_id: [0; 16],
            encrypted_reaction: vec![],
            nonce: [0; 12],
            is_add: true,
        })
        .unwrap();
        assert_eq!(bytes[0], 47, "ChatReaction discriminant must be 47");

        // ChatEdit = 48
        let bytes = postcard::to_stdvec(&Message::ChatEdit {
            target_message_id: [0; 16],
            encrypted_content: vec![],
            nonce: [0; 12],
            edit_version: 0,
        })
        .unwrap();
        assert_eq!(bytes[0], 48, "ChatEdit discriminant must be 48");

        // ChatDelete = 49
        let bytes = postcard::to_stdvec(&Message::ChatDelete {
            target_message_id: [0; 16],
        })
        .unwrap();
        assert_eq!(bytes[0], 49, "ChatDelete discriminant must be 49");

        // VoiceMessage = 50
        let bytes = postcard::to_stdvec(&Message::VoiceMessage {
            message_id: [0; 16],
            sequence: 0,
            encrypted_audio: vec![],
            nonce: [0; 12],
            duration_ms: 0,
            waveform: vec![],
            encrypted_metadata: vec![],
            metadata_nonce: [0; 12],
        })
        .unwrap();
        assert_eq!(bytes[0], 50, "VoiceMessage discriminant must be 50");

        // MediaAttachment = 51
        let bytes = postcard::to_stdvec(&Message::MediaAttachment {
            message_id: [0; 16],
            sequence: 0,
            encrypted_data: vec![],
            nonce: [0; 12],
            mime_type: String::new(),
            width: 0,
            height: 0,
            encrypted_metadata: vec![],
            metadata_nonce: [0; 12],
        })
        .unwrap();
        assert_eq!(bytes[0], 51, "MediaAttachment discriminant must be 51");

        // DisappearingTimer = 52
        let bytes = postcard::to_stdvec(&Message::DisappearingTimer {
            duration_secs: 0,
            encrypted_data: vec![],
            nonce: [0; 12],
        })
        .unwrap();
        assert_eq!(bytes[0], 52, "DisappearingTimer discriminant must be 52");

        // ChatPoll = 53
        let bytes = postcard::to_stdvec(&Message::ChatPoll {
            message_id: [0; 16],
            sequence: 0,
            encrypted_poll: vec![],
            nonce: [0; 12],
            multi_select: false,
        })
        .unwrap();
        assert_eq!(bytes[0], 53, "ChatPoll discriminant must be 53");

        // ChatPollVote = 54
        let bytes = postcard::to_stdvec(&Message::ChatPollVote {
            target_message_id: [0; 16],
            encrypted_vote: vec![],
            nonce: [0; 12],
        })
        .unwrap();
        assert_eq!(bytes[0], 54, "ChatPollVote discriminant must be 54");

        // LinkPreview = 55
        let bytes = postcard::to_stdvec(&Message::LinkPreview {
            target_message_id: [0; 16],
            encrypted_metadata: vec![],
            nonce: [0; 12],
        })
        .unwrap();
        assert_eq!(bytes[0], 55, "LinkPreview discriminant must be 55");
    }

    /// Verify pre-Phase-24 variants still round-trip correctly after appending rich chat variants
    #[test]
    fn test_old_variants_stable_after_rich_chat() {
        let old_messages = vec![
            Message::Ping,
            Message::Pong,
            Message::ChatEnd,
            Message::DirectFailed,
            Message::FileSelection {
                transfer_id: [0; 16],
                selected_indices: vec![1, 2],
            },
            Message::PeerOffline {
                fingerprint: "abcdef01".into(),
            },
            Message::WebRtcIceCandidate {
                encrypted_candidate: vec![0x01, 0x02],
                nonce: [0xAA; 12],
            },
            Message::ChatText {
                message_id: [0xAA; 16],
                sequence: 1,
                ciphertext: vec![0xDE, 0xAD],
                nonce: [0xBB; 12],
            },
            Message::HandshakeInit {
                protocol_version: 2,
                suite_code: tallow_crypto::suite_code(),
                kem_capabilities: vec![0, 1],
                cpace_public: [0xCC; 32],
                nonce: [0xDD; 16],
            },
        ];
        for msg in &old_messages {
            let bytes = postcard::to_stdvec(msg).unwrap();
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(
                &decoded, msg,
                "backward compat failed after rich chat variants for {:?}",
                msg
            );
        }
    }

    #[test]
    fn pool_acquire_request_roundtrip() {
        let msg = Message::PoolAcquireRequest {
            requester_node: "node-1".to_string(),
            session_id_prefix: "prefix-".to_string(),
        };
        let bytes = postcard::to_stdvec(&msg).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        match decoded {
            Message::PoolAcquireRequest {
                requester_node,
                session_id_prefix,
            } => {
                assert_eq!(requester_node, "node-1");
                assert_eq!(session_id_prefix, "prefix-");
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn pool_health_report_roundtrip() {
        let msg = Message::PoolHealthReport {
            node_id: "node-2".to_string(),
            active_browsers: 3,
            idle_browsers: 1,
            max_browsers: 4,
            timestamp: 1234567890,
        };
        let bytes = postcard::to_stdvec(&msg).unwrap();
        let decoded: Message = postcard::from_bytes(&bytes).unwrap();
        match decoded {
            Message::PoolHealthReport {
                node_id,
                active_browsers,
                ..
            } => {
                assert_eq!(node_id, "node-2");
                assert_eq!(active_browsers, 3);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn test_sealed_targeted_wire_layout() {
        // SealedTargeted must have to_peer as first byte after the discriminant (0x3B).
        // Relay implementations read data[0] == 0x3B and data[1] == to_peer for routing.
        let msg = Message::SealedTargeted {
            to_peer: 0x02,
            encrypted_envelope: vec![0xAA; 29],
        };
        let bytes = postcard::to_stdvec(&msg).unwrap();

        // Discriminant for SealedTargeted (variant index 59 = 0x3B)
        assert_eq!(bytes[0], 59, "discriminant must be 59 (0x3B)");
        // to_peer is the very next byte — relay routing depends on this layout
        assert_eq!(bytes[1], 0x02, "to_peer must be at offset 1");
    }

    #[test]
    fn test_sealed_targeted_no_plaintext_from_peer() {
        // Verify that the sealed variant does NOT expose a plaintext from_peer byte.
        // The Targeted variant has [discriminant][from_peer][to_peer] — offset 2 for to_peer.
        // The SealedTargeted variant has [discriminant][to_peer] — offset 1 for to_peer.
        let targeted = Message::Targeted {
            from_peer: 0,
            to_peer: 0x01,
            payload: vec![],
        };
        let sealed = Message::SealedTargeted {
            to_peer: 0x01,
            encrypted_envelope: vec![],
        };
        let targeted_bytes = postcard::to_stdvec(&targeted).unwrap();
        let sealed_bytes = postcard::to_stdvec(&sealed).unwrap();

        // Targeted: discriminant=33, from_peer at offset 1, to_peer at offset 2
        assert_eq!(targeted_bytes[0], 33);
        assert_eq!(targeted_bytes[2], 0x01); // to_peer at offset 2
                                             // SealedTargeted: discriminant=59, to_peer at offset 1 (no from_peer in plaintext)
        assert_eq!(sealed_bytes[0], 59);
        assert_eq!(sealed_bytes[1], 0x01); // to_peer at offset 1
                                           // SealedTargeted encoding is one byte shorter before the payload
        assert!(
            sealed_bytes.len() < targeted_bytes.len() + 1,
            "sealed header must be more compact than targeted header"
        );
    }

    #[test]
    fn test_transfer_control_variants_roundtrip_and_append_only_discriminants() {
        let transfer_id = [0xA5; 16];
        let start = Message::TransferStart { transfer_id };
        let control = Message::TransferControl {
            transfer_id,
            kind: 1,
            nonce: [0xC0; 12],
            ciphertext: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        for msg in [&start, &control] {
            let bytes = postcard::to_stdvec(msg).expect("encode");
            let decoded: Message = postcard::from_bytes(&bytes).expect("decode");
            assert_eq!(&decoded, msg);
        }

        let start_bytes = postcard::to_stdvec(&start).unwrap();
        assert_eq!(
            start_bytes[0], 61,
            "TransferStart must append after ChatPresence without shifting older variants",
        );

        let control_bytes = postcard::to_stdvec(&control).unwrap();
        assert_eq!(
            control_bytes[0], 62,
            "TransferControl must append after TransferStart without shifting older variants",
        );
    }

    #[test]
    fn test_discriminant_stability_chat_control() {
        // Relay implementations inspect the raw first byte to enforce
        // per-connection rate limits on chat control messages. These
        // discriminants are embedded in deployed relays — any change here MUST
        // keep them stable (keep in lockstep with relay-side constants, e.g.
        // the SendTallow relay's TYPING_INDICATOR_DISCRIMINANT and
        // CHAT_PRESENCE_DISCRIMINANT).
        let typing_bytes = postcard::to_stdvec(&Message::TypingIndicator { typing: true }).unwrap();
        assert_eq!(
            typing_bytes[0], 26,
            "TypingIndicator must be discriminant 26 (relay rate-limit depends on this)"
        );

        let presence_bytes = postcard::to_stdvec(&Message::ChatPresence {
            encrypted_state: vec![],
            nonce: [0u8; 12],
        })
        .unwrap();
        assert_eq!(
            presence_bytes[0], 60,
            "ChatPresence must be discriminant 60 (relay rate-limit depends on this)"
        );
    }

    #[test]
    fn test_sendtallow_union_discriminant_map() {
        // Canonical union map after the SendTallow integration (Stage 1):
        // the product's 59-62 stay frozen; the language's Distributed Browser
        // Pool set was renumbered from 59-65 to 63-69 (the pool RPC has no
        // in-workspace byte-level consumers; verified during the merge).
        let cases: Vec<(Message, u8)> = vec![
            (
                Message::SealedTargeted {
                    to_peer: 0xFF,
                    encrypted_envelope: vec![],
                },
                59,
            ),
            (
                Message::ChatPresence {
                    encrypted_state: vec![],
                    nonce: [0u8; 12],
                },
                60,
            ),
            (
                Message::TransferStart {
                    transfer_id: [0u8; 16],
                },
                61,
            ),
            (
                Message::TransferControl {
                    transfer_id: [0u8; 16],
                    kind: 1,
                    nonce: [0u8; 12],
                    ciphertext: vec![],
                },
                62,
            ),
            (
                Message::PoolAcquireRequest {
                    requester_node: "n".into(),
                    session_id_prefix: "p".into(),
                },
                63,
            ),
            (
                Message::PoolAcquireResponse {
                    session_id: "s".into(),
                    internal_session_id: "i".into(),
                    browser_index: 0,
                },
                64,
            ),
            (
                Message::PoolReleaseRequest {
                    session_id: "s".into(),
                },
                65,
            ),
            (
                Message::DistributedCdpCommand {
                    session_id: "s".into(),
                    rpc_id: 7,
                    method: "m".into(),
                    params: None,
                },
                66,
            ),
            (
                Message::DistributedCdpResponse {
                    rpc_id: 7,
                    result: None,
                    error: None,
                },
                67,
            ),
            (
                Message::PoolHealthReport {
                    node_id: "n".into(),
                    active_browsers: 1,
                    idle_browsers: 2,
                    max_browsers: 4,
                    timestamp: 0,
                },
                68,
            ),
            (
                Message::SessionExpired {
                    session_id: "s".into(),
                },
                69,
            ),
            (
                Message::HandshakeSigned {
                    role: 2,
                    identity_public_key: vec![1, 2],
                    signature: vec![3, 4],
                },
                70,
            ),
            (
                Message::ModeAnnounce {
                    transfer_id: [5u8; 16],
                    mode: MODE_SIMPLE,
                },
                71,
            ),
            (
                Message::ModeAccept {
                    transfer_id: [6u8; 16],
                    mode: MODE_SIMPLE,
                },
                72,
            ),
            (
                Message::SimpleChunk {
                    transfer_id: [7u8; 16],
                    index: 1,
                    total: Some(2),
                    data: vec![1, 2, 3],
                },
                73,
            ),
        ];

        for (msg, want) in &cases {
            let bytes = postcard::to_stdvec(msg).unwrap();
            assert_eq!(bytes[0], *want, "union discriminant mismatch for {:?}", msg);
            let decoded: Message = postcard::from_bytes(&bytes).unwrap();
            assert_eq!(&decoded, msg, "round-trip failed for {:?}", msg);
        }
    }
}
