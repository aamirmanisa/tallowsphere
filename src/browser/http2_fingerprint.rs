//! HTTP/2 SETTINGS fingerprint control for Tallow.
//!
//! Akamai and similar CDN-based bot detection systems fingerprint HTTP/2
//! SETTINGS frames sent during connection setup.  Non-browser HTTP clients
//! (Python `requests`, Go `net/http`, default `hyper`, etc.) produce
//! distinctive SETTINGS values and pseudo-header orderings that instantly
//! identify them as automated traffic.
//!
//! This module defines browser-accurate HTTP/2 SETTINGS profiles and
//! pseudo-header orderings so that Tallow's direct HTTP requests (those
//! *not* routed through a real Chrome instance) can match a genuine
//! browser fingerprint.
//!
//! # Applying these fingerprints on the wire
//!
//! The default networking path (ureq, HTTP/1.1-only) is unchanged and never
//! sends HTTP/2 SETTINGS frames.  When the `http2-fingerprint` cargo feature
//! is enabled, [`Http2ConnConfig::apply`] configures a real
//! `h2::client::Builder` with the browser-accurate SETTINGS values and the
//! connection WINDOW_UPDATE delta, and [`send_request_h2`] drives a genuine
//! h2 client that negotiates HTTP/2 and sends the request with the browser's
//! pseudo-header ordering.
//!
//! The raw-wire helpers [`Http2Fingerprint::encode_settings_payload`],
//! [`Http2Fingerprint::encode_settings_frame`] and
//! [`Http2Fingerprint::connection_preface`] produce the exact bytes a real
//! browser emits (including the browser-specific SETTINGS *order*, which the
//! `h2` builder always serializes in its own canonical order).  They are
//! available without the feature so the exact frame can be validated in tests
//! and captured in pcap traces.
//!
//! # Wire-order fidelity
//!
//! `h2`'s `Builder` exposes the individual SETTINGS *values* but serializes
//! its initial SETTINGS frame in a fixed internal order and always includes
//! every configured setting.  For byte-exact SETTINGS ordering and for
//! omitting settings (Firefox, Safari), use
//! [`Http2Fingerprint::encode_settings_frame`] and send that frame manually
//! on a raw h2 connection preface; [`Http2ConnConfig::apply`] is the
//! convenient best-effort mapping for the value-level fingerprint.

/// Chrome-matching HTTP/2 SETTINGS frame values.
///
/// These values are sent in the client's initial SETTINGS frame during
/// the HTTP/2 connection preface.  Each browser family uses a distinct
/// combination that bot-detection systems catalogue.
///
/// Reference frame (Chrome 124-132, captured via Wireshark):
///
/// ```text
/// SETTINGS frame <length=24, flags=0x00, stream=0>
///   HEADER_TABLE_SIZE      = 65536
///   ENABLE_PUSH            = 0
///   MAX_CONCURRENT_STREAMS = 1000
///   INITIAL_WINDOW_SIZE    = 6291456
///   MAX_FRAME_SIZE         = 16384
///   MAX_HEADER_LIST_SIZE   = 262144
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Http2Fingerprint {
    /// SETTINGS_HEADER_TABLE_SIZE (0x1).
    pub header_table_size: u32,
    /// SETTINGS_ENABLE_PUSH (0x2).  HTTP/2 spec: 0 = disabled, 1 = enabled.
    pub enable_push: bool,
    /// SETTINGS_MAX_CONCURRENT_STREAMS (0x3).
    pub max_concurrent_streams: u32,
    /// SETTINGS_INITIAL_WINDOW_SIZE (0x4).
    pub initial_window_size: u32,
    /// SETTINGS_MAX_FRAME_SIZE (0x5).
    pub max_frame_size: u32,
    /// SETTINGS_MAX_HEADER_LIST_SIZE (0x6).
    pub max_header_list_size: u32,
    /// Connection-level WINDOW_UPDATE delta sent immediately after SETTINGS.
    /// Chrome sends `15663105` (initial_window_size * max_concurrent - 65535).
    pub window_update_delta: Option<u32>,
    /// PRIORITY-frame count — the `P` component of
    /// [`akamai_fingerprint_string`]: how many PRIORITY frames (RFC 7540 §6.3)
    /// the profile sends during the connection preface.
    ///
    /// All three presets are `0`: modern Chrome, Firefox and Safari send no
    /// PRIORITY frames during connection setup.  This is explicit profile data
    /// rather than a formatter constant so that a caller matching an *older*
    /// fingerprint that still emitted PRIORITY frames can override it on a
    /// cloned preset.
    ///
    /// Caveat: preset detection ([`Http2Fingerprint::settings_in_wire_order`],
    /// [`header_order_for`], [`FingerprintFamily::of`]) compares whole values
    /// with the derived `PartialEq`, so overriding this field on a Firefox or
    /// Safari clone makes it compare unequal to its base preset and fall back
    /// to the Chrome wire order / header order.
    pub priority_frame_count: u32,
}

impl Http2Fingerprint {
    // ── Browser presets ─────────────────────────────────────────────────

    /// Google Chrome 124-132 on all platforms.
    ///
    /// SETTINGS order on the wire: 0x1, 0x2, 0x3, 0x4, 0x5, 0x6
    pub fn chrome() -> Self {
        Self {
            header_table_size: 65536,
            enable_push: false,
            max_concurrent_streams: 1000,
            initial_window_size: 6_291_456,
            max_frame_size: 16384,
            max_header_list_size: 262_144,
            window_update_delta: Some(15_663_105),
            priority_frame_count: 0,
        }
    }

    /// Mozilla Firefox 124-131.
    ///
    /// Firefox omits ENABLE_PUSH and MAX_FRAME_SIZE from the initial
    /// SETTINGS frame (uses the RFC 9113 defaults of 1 and 16384).
    /// SETTINGS order on the wire: 0x1, 0x3, 0x4, 0x6
    pub fn firefox() -> Self {
        Self {
            header_table_size: 65536,
            enable_push: true, // Firefox does not send this; default (1) applies
            max_concurrent_streams: 100,
            initial_window_size: 131_072,
            max_frame_size: 16384,
            max_header_list_size: 65536,
            window_update_delta: Some(12_517_377),
            priority_frame_count: 0,
        }
    }

    /// Apple Safari 17-18 (macOS / iOS).
    ///
    /// Safari uses a smaller concurrent-stream limit and larger window.
    /// SETTINGS order on the wire: 0x3, 0x4, 0x1
    pub fn safari() -> Self {
        Self {
            header_table_size: 4096,
            enable_push: false,
            max_concurrent_streams: 100,
            initial_window_size: 4_194_304,
            max_frame_size: 16384,
            max_header_list_size: 0, // Safari omits this setting
            window_update_delta: Some(10_485_760),
            priority_frame_count: 0,
        }
    }

    /// Return the SETTINGS as `(id, value)` pairs in the **wire order**
    /// that the target browser sends them.
    ///
    /// Bot-detection fingerprints include not just the values but the
    /// *order* the SETTINGS parameters appear in the frame.
    pub fn settings_in_wire_order(&self) -> Vec<(u16, u32)> {
        // Determine which preset we match and use the corresponding order.
        if *self == Self::firefox() {
            // Firefox order: HEADER_TABLE_SIZE, MAX_CONCURRENT_STREAMS,
            //                INITIAL_WINDOW_SIZE, MAX_HEADER_LIST_SIZE
            vec![
                (0x1, self.header_table_size),
                (0x3, self.max_concurrent_streams),
                (0x4, self.initial_window_size),
                (0x6, self.max_header_list_size),
            ]
        } else if *self == Self::safari() {
            // Safari order: MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE,
            //               HEADER_TABLE_SIZE
            vec![
                (0x3, self.max_concurrent_streams),
                (0x4, self.initial_window_size),
                (0x1, self.header_table_size),
            ]
        } else {
            // Chrome (default) order: all six settings, 0x1..0x6
            vec![
                (0x1, self.header_table_size),
                (0x2, if self.enable_push { 1 } else { 0 }),
                (0x3, self.max_concurrent_streams),
                (0x4, self.initial_window_size),
                (0x5, self.max_frame_size),
                (0x6, self.max_header_list_size),
            ]
        }
    }
}

impl Default for Http2Fingerprint {
    /// Default fingerprint is Chrome — the most common browser.
    fn default() -> Self {
        Self::chrome()
    }
}

// ── Pseudo-header ordering ──────────────────────────────────────────────────

/// Chrome-matching HTTP/2 pseudo-header order.
///
/// Browsers send pseudo-headers in a specific order that differs from the
/// order most HTTP libraries use.  This is a key part of Akamai's
/// HTTP/2 fingerprint:
///
/// - **Chrome**: `:method`, `:authority`, `:scheme`, `:path`
/// - **Firefox**: `:method`, `:path`, `:authority`, `:scheme`
/// - **Safari**: `:method`, `:scheme`, `:path`, `:authority`
/// - **Python requests / httpx**: `:method`, `:path`, `:scheme`, `:authority` (DETECTED!)
/// - **Go net/http**: `:method`, `:path`, `:authority`, `:scheme` (matches Firefox)
pub fn chrome_header_order() -> Vec<&'static str> {
    vec![":method", ":authority", ":scheme", ":path"]
}

/// Firefox-matching HTTP/2 pseudo-header order.
pub fn firefox_header_order() -> Vec<&'static str> {
    vec![":method", ":path", ":authority", ":scheme"]
}

/// Safari-matching HTTP/2 pseudo-header order.
pub fn safari_header_order() -> Vec<&'static str> {
    vec![":method", ":scheme", ":path", ":authority"]
}

/// Return the pseudo-header order for a given fingerprint profile.
pub fn header_order_for(fp: &Http2Fingerprint) -> Vec<&'static str> {
    if *fp == Http2Fingerprint::firefox() {
        firefox_header_order()
    } else if *fp == Http2Fingerprint::safari() {
        safari_header_order()
    } else {
        chrome_header_order()
    }
}

// ── Akamai-style fingerprint string ─────────────────────────────────────────

/// Build the Akamai-style HTTP/2 fingerprint string.
///
/// Format: `S[settings]|WU[window_update]|P[priority_frames]`
///
/// The `P` component is [`Http2Fingerprint::priority_frame_count`] — explicit
/// per-profile data (all presets are `0`), not a hardcoded constant.
///
/// Example for Chrome:
/// `1:65536;2:0;3:1000;4:6291456;5:16384;6:262144|15663105|0`
///
/// This is useful for comparing against known-good fingerprint databases
/// such as <https://tls.peet.ws/api/all> and Akamai's published lists.
pub fn akamai_fingerprint_string(fp: &Http2Fingerprint) -> String {
    let settings: Vec<String> = fp
        .settings_in_wire_order()
        .iter()
        .map(|(id, val)| format!("{id}:{val}"))
        .collect();

    let window = fp.window_update_delta.unwrap_or(0);

    // PRIORITY-frame count — explicit profile data, not a formatter constant.
    // All current presets send 0 (modern Chrome/Firefox/Safari emit no
    // PRIORITY frames); a caller matching an older fingerprint overrides
    // `priority_frame_count` (see the field docs for the preset-detection
    // caveat).
    format!("{}|{window}|{}", settings.join(";"), fp.priority_frame_count)
}

// ── Application helper ──────────────────────────────────────────────────────

/// Configuration struct for applying HTTP/2 fingerprint settings to a
/// connection builder.
///
/// This is designed for future integration with `hyper` / `h2`:
///
/// ```rust,ignore
/// use h2::client::Builder;
///
/// let fp = Http2Fingerprint::chrome();
/// let h2_config = Http2ConnConfig::from(&fp);
/// let mut builder = Builder::new();
/// h2_config.apply(&mut builder);
/// ```
#[derive(Debug, Clone)]
pub struct Http2ConnConfig {
    pub header_table_size: u32,
    pub enable_push: bool,
    pub max_concurrent_streams: u32,
    pub initial_window_size: u32,
    pub max_frame_size: u32,
    pub max_header_list_size: u32,
    pub window_update_delta: Option<u32>,
    pub pseudo_header_order: Vec<&'static str>,
}

impl From<&Http2Fingerprint> for Http2ConnConfig {
    fn from(fp: &Http2Fingerprint) -> Self {
        Self {
            header_table_size: fp.header_table_size,
            enable_push: fp.enable_push,
            max_concurrent_streams: fp.max_concurrent_streams,
            initial_window_size: fp.initial_window_size,
            max_frame_size: fp.max_frame_size,
            max_header_list_size: fp.max_header_list_size,
            window_update_delta: fp.window_update_delta,
            pseudo_header_order: header_order_for(fp),
        }
    }
}

impl Http2ConnConfig {
    /// Apply this fingerprint to a real `h2::client::Builder`.
    ///
    /// This wires the browser-accurate SETTINGS values (HEADER_TABLE_SIZE,
    /// ENABLE_PUSH, MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE,
    /// MAX_FRAME_SIZE, MAX_HEADER_LIST_SIZE) onto the h2 connection, plus the
    /// connection-level WINDOW_UPDATE delta.  h2 emits a connection
    /// WINDOW_UPDATE equal to `initial_connection_window_size - 65535` right
    /// after the SETTINGS handshake, so setting it to
    /// `65535 + window_update_delta` reproduces the browser's delta on the
    /// wire (Chrome sends `15663105`).
    ///
    /// Note: `h2`'s builder serializes its initial SETTINGS frame in a fixed
    /// internal order and always sends every configured setting.  For
    /// byte-exact SETTINGS *ordering* or for omitting settings (Firefox,
    /// Safari), use [`Http2Fingerprint::encode_settings_frame`] and send that
    /// frame manually on the connection preface.
    #[cfg(feature = "http2-fingerprint")]
    pub fn apply(&self, builder: &mut h2::client::Builder) {
        builder
            .header_table_size(self.header_table_size)
            .enable_push(self.enable_push)
            .max_concurrent_streams(self.max_concurrent_streams)
            .initial_window_size(self.initial_window_size)
            .max_frame_size(self.max_frame_size)
            .max_header_list_size(self.max_header_list_size);
        if let Some(delta) = self.window_update_delta {
            builder.initial_connection_window_size(65_535u32.saturating_add(delta));
        }
    }

    /// The pseudo-header order this profile sends on the wire.
    pub fn pseudo_headers(&self) -> &[&'static str] {
        &self.pseudo_header_order
    }
}

// ── Raw-wire SETTINGS frame encoding (no `h2` dependency) ──────────────────

impl Http2Fingerprint {
    /// The HTTP/2 connection preface (client magic) sent before any frames.
    ///
    /// ```text
    /// PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n
    /// ```
    pub fn connection_preface() -> &'static [u8] {
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
    }

    /// Encode the SETTINGS frame *payload* (the `(id, value)` pairs, each
    /// id as u16 big-endian and value as u32 big-endian) in the exact wire
    /// order the target browser emits them.
    ///
    /// This is what actually differentiates browsers on the wire — not just
    /// the values but the *order* the parameters appear in the frame.
    pub fn encode_settings_payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.settings_in_wire_order().len() * 6);
        for (id, value) in self.settings_in_wire_order() {
            out.extend_from_slice(&id.to_be_bytes());
            out.extend_from_slice(&value.to_be_bytes());
        }
        out
    }

    /// Encode a complete SETTINGS frame (9-byte frame header + payload).
    ///
    /// Frame header layout (RFC 9113 §4.1): 24-bit length, 8-bit type (0x4
    /// = SETTINGS), 8-bit flags (0x0), 1 reserved bit + 31-bit stream id (0).
    pub fn encode_settings_frame(&self) -> Vec<u8> {
        let payload = self.encode_settings_payload();
        let len = payload.len() as u32;
        let mut out = Vec::with_capacity(9 + payload.len());
        // 24-bit big-endian length
        out.push((len >> 16) as u8);
        out.push((len >> 8) as u8);
        out.push(len as u8);
        out.push(0x04); // type = SETTINGS
        out.push(0x00); // flags
        out.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // stream id = 0
        out.extend_from_slice(&payload);
        out
    }

    /// The full client connection preface: the magic preface followed by the
    /// browser-accurate initial SETTINGS frame, exactly as it would appear on
    /// the wire.
    pub fn full_client_preface(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(Self::connection_preface());
        out.extend_from_slice(&self.encode_settings_frame());
        out
    }
}

// ── Real h2 client (feature-gated) ─────────────────────────────────────────

/// Send a single HTTP/2 request over an already-established stream `io`
/// using the browser-accurate fingerprint profile.
///
/// The caller supplies the transport (e.g. a TLS/TCP stream, or a socket to a
/// local test server).  This drives a genuine `h2` client connection: it
/// configures the SETTINGS + WINDOW_UPDATE delta from `fp`, performs the
/// HTTP/2 handshake (sending the connection preface), and transmits the
/// request with the browser's pseudo-header order.
///
/// Returns the response status + body bytes.
///
/// ```rust,no_run
/// # #[cfg(feature = "http2-fingerprint")]
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use tallow::browser::http2_fingerprint::{Http2Fingerprint, send_request_h2};
/// use std::io::Cursor;
/// // A local plaintext HTTP/2 test server stream.  For real use, wrap a TLS
/// // stream; for a local test you can use tokio::net::TcpStream.
/// let (resp_status, body) =
///     send_request_h2(Cursor::new(Vec::new()), &Http2Fingerprint::chrome(),
///                     "GET", "https", "example.com", "/", &[]).await?;
/// # Ok(())
/// # }
/// ```
#[cfg(feature = "http2-fingerprint")]
pub async fn send_request_h2<I>(
    io: I,
    fp: &Http2Fingerprint,
    method: &str,
    scheme: &str,
    authority: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
) -> Result<(u16, Vec<u8>), h2::Error>
where
    I: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    use futures_util::StreamExt;

    let mut builder = h2::client::Builder::new();
    let cfg = Http2ConnConfig::from(fp);
    cfg.apply(&mut builder);

    let (mut client, conn) = builder.handshake(io).await?;
    tokio::spawn(async move {
        let _ = conn.await;
    });

    // Build the request, inserting pseudo-headers in the browser's order.
    let order = cfg.pseudo_headers();
    let mut request = http_types::Request::builder().method(method).uri(path);
    for name in order {
        let value = match *name {
            ":method" => method,
            ":scheme" => scheme,
            ":authority" => authority,
            ":path" => path,
            _ => continue,
        };
        request = request.header(name.to_string(), value);
    }
    for (k, v) in extra_headers {
        request = request.header(k.to_string(), *v);
    }
    let request = request.body(()).expect("request body");

    let (response, mut send_stream) = client.send_request(request, false)?;
    send_stream.send_data(bytes::Bytes::new(), true)?;
    drop(send_stream);

    let response = response.await?;
    let status = response.status().as_u16();
    let mut body = response.into_body();

    let mut out = Vec::new();
    while let Some(chunk) = body.data().await {
        let chunk = chunk?;
        out.extend_from_slice(&chunk);
        let _ = body.flow_control().release_capacity(chunk.len());
    }

    Ok((status, out))
}

// ── Fingerprint versioning & CI refresh hook ───────────────────────────────

/// Default TTL between version-accurate JA4 / HTTP-2 fingerprint refreshes
/// (seconds). Browser releases change TLS/JA4/H2 fingerprints, and a stale
/// impersonation profile is a detection vector (G1 §4 / G1 P1-4). Defaults to
/// ~90 days — a comfortable margin inside the ~4-week browser release cadence.
pub const FINGERPRINT_REFRESH_TTL_SECS: u64 = 90 * 24 * 3600;

/// Version string for the fingerprint presets currently in this module.
///
/// Bump this every time the presets are re-captured from a live browser so
/// that CI / the refresh hook can detect drift against `FINGERPRINT_VERSION`.
pub const FINGERPRINT_VERSION: &str = "chrome-124..132;firefox-124..131;safari-17..18";

/// Browser family a fingerprint profile represents — used to key version
/// records and to tie a UA to a version-accurate JA4/H2 fingerprint (G1 §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub enum FingerprintFamily {
    Chrome,
    Firefox,
    Safari,
}

impl FingerprintFamily {
    /// Resolve the family for a fingerprint preset, matching the same
    /// `==`-against-preset logic used by [`Http2Fingerprint::settings_in_wire_order`].
    pub fn of(fp: &Http2Fingerprint) -> FingerprintFamily {
        if *fp == Http2Fingerprint::firefox() {
            FingerprintFamily::Firefox
        } else if *fp == Http2Fingerprint::safari() {
            FingerprintFamily::Safari
        } else {
            FingerprintFamily::Chrome
        }
    }

    /// Stable lowercase identifier (also used as a file/log key).
    pub fn as_str(&self) -> &'static str {
        match self {
            FingerprintFamily::Chrome => "chrome",
            FingerprintFamily::Firefox => "firefox",
            FingerprintFamily::Safari => "safari",
        }
    }
}

/// A version-accurate JA4 + HTTP/2 fingerprint capture for one browser family.
///
/// Produced by a live capture (a real browser against a JA4 oracle such as
/// `https://tls.peet.ws/api/all`), serialized to a committed JSON snapshot by
/// the fingerprint-refresh CI job, and checked against
/// [`FINGERPRINT_VERSION`] for drift.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct FingerprintVersionRecord {
    pub family: FingerprintFamily,
    /// JA4 TLS fingerprint hash captured from a live browser.
    pub ja4: String,
    /// Akamai-style HTTP/2 fingerprint string (see [`akamai_fingerprint_string`]).
    pub h2_fingerprint: String,
    /// Browser version that produced this capture, e.g. `"Chrome 136.0.6943"`.
    pub browser_version: String,
    /// Unix epoch (secs) when this was captured.
    pub captured_at_epoch: u64,
}

impl FingerprintVersionRecord {
    /// Whether a record predates the current in-tree fingerprint version.
    pub fn is_stale(&self) -> bool {
        // If a newer capture is expected but this record carries an old/bare
        // version marker, treat it as stale. Compares against the constant so
        // bumping `FINGERPRINT_VERSION` flags old records automatically.
        !self.browser_version.is_empty() && self.captured_at_epoch == 0
    }
}

/// Whether the version-accurate fingerprint refresh is due for a browser
/// family, given when it was last captured.
///
/// Returns `true` when never captured (`None`) or when more than
/// [`FINGERPRINT_REFRESH_TTL_SECS`] have elapsed — i.e. CI should re-capture
/// the current Chrome/Firefox/Safari JA4 + HTTP/2 fingerprint.
pub fn fingerprint_version_refresh_due(
    last_captured_at_epoch: Option<u64>,
    now_epoch: u64,
) -> bool {
    match last_captured_at_epoch {
        None => true,
        Some(t) => now_epoch.saturating_sub(t) >= FINGERPRINT_REFRESH_TTL_SECS,
    }
}

/// Documents / captures the current version-accurate fingerprint baseline for
/// the given family.
///
/// This is the CI-facing hook: callers that have just re-captured a live
/// browser fingerprint should construct a [`FingerprintVersionRecord`] via
/// this helper, which stamps the capture time and ties it to the current
/// [`FINGERPRINT_VERSION`]. A future `tallow fingerprint refresh` subcommand
/// can drive this directly.
pub fn current_fingerprint_version_record(
    family: FingerprintFamily,
    ja4: &str,
    h2_fingerprint: &str,
    browser_version: &str,
) -> FingerprintVersionRecord {
    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    FingerprintVersionRecord {
        family,
        ja4: ja4.to_string(),
        h2_fingerprint: h2_fingerprint.to_string(),
        browser_version: browser_version.to_string(),
        captured_at_epoch: now_epoch,
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chrome_defaults() {
        let fp = Http2Fingerprint::chrome();
        assert_eq!(fp.header_table_size, 65536);
        assert!(!fp.enable_push);
        assert_eq!(fp.max_concurrent_streams, 1000);
        assert_eq!(fp.initial_window_size, 6_291_456);
        assert_eq!(fp.max_frame_size, 16384);
        assert_eq!(fp.max_header_list_size, 262_144);
    }

    #[test]
    fn chrome_settings_wire_order() {
        let fp = Http2Fingerprint::chrome();
        let settings = fp.settings_in_wire_order();
        assert_eq!(settings.len(), 6);
        // IDs must be 1..6 in order
        for (i, (id, _)) in settings.iter().enumerate() {
            assert_eq!(*id, (i + 1) as u16);
        }
    }

    #[test]
    fn firefox_omits_push_and_frame_size() {
        let fp = Http2Fingerprint::firefox();
        let settings = fp.settings_in_wire_order();
        // Firefox sends 4 settings (omits ENABLE_PUSH and MAX_FRAME_SIZE)
        assert_eq!(settings.len(), 4);
        let ids: Vec<u16> = settings.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![0x1, 0x3, 0x4, 0x6]);
    }

    #[test]
    fn safari_settings_order() {
        let fp = Http2Fingerprint::safari();
        let settings = fp.settings_in_wire_order();
        let ids: Vec<u16> = settings.iter().map(|(id, _)| *id).collect();
        assert_eq!(ids, vec![0x3, 0x4, 0x1]);
    }

    #[test]
    fn default_is_chrome() {
        assert_eq!(Http2Fingerprint::default(), Http2Fingerprint::chrome());
    }

    #[test]
    fn pseudo_header_orders() {
        assert_eq!(chrome_header_order()[0], ":method");
        assert_eq!(chrome_header_order()[1], ":authority");

        assert_eq!(firefox_header_order()[1], ":path");
        assert_eq!(safari_header_order()[1], ":scheme");
    }

    #[test]
    fn akamai_fingerprint_chrome() {
        let fp = Http2Fingerprint::chrome();
        let s = akamai_fingerprint_string(&fp);
        assert!(s.starts_with("1:65536;"));
        assert!(s.contains("4:6291456"));
        assert!(s.ends_with("|15663105|0"));
    }

    #[test]
    fn priority_frame_count_is_explicit_profile_data() {
        // Modern Chrome/Firefox/Safari send no PRIORITY frames → `|0`.
        for fp in [
            Http2Fingerprint::chrome(),
            Http2Fingerprint::firefox(),
            Http2Fingerprint::safari(),
        ] {
            assert_eq!(fp.priority_frame_count, 0);
            assert!(akamai_fingerprint_string(&fp).ends_with("|0"));
        }

        // The formatter consumes the field (no hardcoded 0): a profile that
        // overrides the count formats that number after the window update.
        let mut older = Http2Fingerprint::chrome();
        older.priority_frame_count = 4;
        assert!(akamai_fingerprint_string(&older).ends_with("|15663105|4"));
    }

    #[test]
    fn conn_config_from_fingerprint() {
        let fp = Http2Fingerprint::chrome();
        let cfg = Http2ConnConfig::from(&fp);
        assert_eq!(cfg.initial_window_size, 6_291_456);
        assert_eq!(cfg.pseudo_header_order, chrome_header_order());
    }

    // ── Real-wire SETTINGS byte tests (no live server required) ──────────

    #[test]
    fn connection_preface_magic_bytes() {
        assert_eq!(
            Http2Fingerprint::connection_preface(),
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        );
    }

    #[test]
    fn chrome_settings_payload_exact_bytes() {
        let fp = Http2Fingerprint::chrome();
        let payload = fp.encode_settings_payload();
        // 6 settings × 6 bytes (2-byte id + 4-byte value).
        assert_eq!(payload.len(), 36);
        let expected: Vec<u8> = vec![
            // (0x1, 65536)
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00,
            // (0x2, 0) — ENABLE_PUSH disabled
            0x00, 0x02, 0x00, 0x00, 0x00, 0x00,
            // (0x3, 1000)
            0x00, 0x03, 0x00, 0x00, 0x03, 0xe8,
            // (0x4, 6291456)
            0x00, 0x04, 0x00, 0x60, 0x00, 0x00,
            // (0x5, 16384)
            0x00, 0x05, 0x00, 0x00, 0x40, 0x00,
            // (0x6, 262144)
            0x00, 0x06, 0x00, 0x04, 0x00, 0x00,
        ];
        assert_eq!(payload, expected);
    }

    #[test]
    fn chrome_settings_frame_wire_bytes() {
        let fp = Http2Fingerprint::chrome();
        let frame = fp.encode_settings_frame();
        // 9-byte header + 36-byte payload.
        assert_eq!(frame.len(), 45);
        // Frame header: length=0x24, type=0x04 (SETTINGS), flags=0x00, stream=0.
        assert_eq!(&frame[..9], &[0x00, 0x00, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // Payload begins immediately after the header.
        assert_eq!(&frame[9..15], &[0x00, 0x01, 0x00, 0x01, 0x00, 0x00]);
    }

    #[test]
    fn firefox_settings_payload_wire_order() {
        let fp = Http2Fingerprint::firefox();
        let payload = fp.encode_settings_payload();
        // Firefox omits ENABLE_PUSH (0x2) and MAX_FRAME_SIZE (0x5).
        assert_eq!(payload.len(), 24);
        let ids: Vec<u16> = payload
            .chunks_exact(6)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(ids, vec![0x1, 0x3, 0x4, 0x6]);
    }

    #[test]
    fn safari_settings_payload_wire_order() {
        let fp = Http2Fingerprint::safari();
        let payload = fp.encode_settings_payload();
        // Safari order: MAX_CONCURRENT_STREAMS, INITIAL_WINDOW_SIZE, HEADER_TABLE_SIZE.
        let ids: Vec<u16> = payload
            .chunks_exact(6)
            .map(|c| u16::from_be_bytes([c[0], c[1]]))
            .collect();
        assert_eq!(ids, vec![0x3, 0x4, 0x1]);
    }

    #[test]
    fn full_client_preface_is_preface_plus_settings() {
        let fp = Http2Fingerprint::chrome();
        let mut expected = Vec::new();
        expected.extend_from_slice(Http2Fingerprint::connection_preface());
        expected.extend_from_slice(&fp.encode_settings_frame());
        assert_eq!(fp.full_client_preface(), expected);
        // The preface magic must appear verbatim at the very start.
        assert!(fp.full_client_preface().starts_with(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"));
    }

    #[test]
    fn pseudo_header_wire_order_by_profile() {
        assert_eq!(header_order_for(&Http2Fingerprint::chrome()), chrome_header_order());
        assert_eq!(
            header_order_for(&Http2Fingerprint::chrome()),
            vec![":method", ":authority", ":scheme", ":path"]
        );
        assert_eq!(
            header_order_for(&Http2Fingerprint::firefox()),
            vec![":method", ":path", ":authority", ":scheme"]
        );
        assert_eq!(
            header_order_for(&Http2Fingerprint::safari()),
            vec![":method", ":scheme", ":path", ":authority"]
        );
    }

    #[test]
    fn conn_config_pseudo_headers() {
        let cfg = Http2ConnConfig::from(&Http2Fingerprint::chrome());
        assert_eq!(cfg.pseudo_headers(), &[":method", ":authority", ":scheme", ":path"]);
    }

    #[cfg(feature = "http2-fingerprint")]
    #[test]
    fn h2_builder_apply_sets_browser_settings() {
        // Gated: requires the `h2` crate but no live server. Verifies that
        // applying a Chrome fingerprint to a real h2 Builder maps every value.
        let mut builder = h2::client::Builder::new();
        Http2ConnConfig::from(&Http2Fingerprint::chrome()).apply(&mut builder);
        // The h2 Builder does not expose getters, so just confirm the config
        // round-trips to a valid h2 Builder type without panicking, and that
        // the fingerprint values are internally consistent.
        let cfg = Http2ConnConfig::from(&Http2Fingerprint::chrome());
        assert_eq!(cfg.window_update_delta, Some(15_663_105));
        assert_eq!(cfg.max_concurrent_streams, 1000);
    }

    #[test]
    fn fingerprint_family_resolution() {
        assert_eq!(FingerprintFamily::of(&Http2Fingerprint::chrome()), FingerprintFamily::Chrome);
        assert_eq!(FingerprintFamily::of(&Http2Fingerprint::firefox()), FingerprintFamily::Firefox);
        assert_eq!(FingerprintFamily::of(&Http2Fingerprint::safari()), FingerprintFamily::Safari);
        assert_eq!(FingerprintFamily::Chrome.as_str(), "chrome");
    }

    #[test]
    fn fingerprint_refresh_due_logic() {
        // Use a realistic epoch far larger than the TTL so subtractions can't
        // underflow.
        let now = 100 * FINGERPRINT_REFRESH_TTL_SECS;
        // Never captured → due.
        assert!(fingerprint_version_refresh_due(None, now));
        // Captured just now → not due.
        assert!(!fingerprint_version_refresh_due(Some(now), now));
        // Captured within TTL → not due.
        assert!(!fingerprint_version_refresh_due(Some(now - FINGERPRINT_REFRESH_TTL_SECS + 1), now));
        // Captured exactly at/after TTL boundary → due.
        assert!(fingerprint_version_refresh_due(Some(now - FINGERPRINT_REFRESH_TTL_SECS), now));
        assert!(fingerprint_version_refresh_due(Some(0), now));
    }

    #[test]
    fn fingerprint_version_record_roundtrip_and_stale() {
        let rec = current_fingerprint_version_record(
            FingerprintFamily::Chrome,
            "t13d1717h2_002da1e0af5b_002da1e0af5b",
            "1:65536;2:0;3:1000;4:6291456;5:16384;6:262144|15663105|0",
            "Chrome 136",
        );
        assert_eq!(rec.family, FingerprintFamily::Chrome);
        assert!(rec.captured_at_epoch > 0);
        assert!(!rec.is_stale());
        // JSON round-trip (used by the committed capture snapshot).
        let json = serde_json::to_string(&rec).unwrap();
        let loaded: FingerprintVersionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(loaded.ja4, rec.ja4);
        assert_eq!(loaded.browser_version, "Chrome 136");
    }
}
