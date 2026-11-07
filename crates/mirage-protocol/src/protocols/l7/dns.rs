//! Camouflage layer — DNS tunnel transport.
//!
//! Encodes payload bytes as DNS TXT queries against a controlled domain.
//! Every query carries up to ~150 bytes of payload (base32-encoded labels).
//! Every response carries payload back in TXT record RDATA.
//!
//! ## Wire format
//!
//! ```text
//! Query name:  <base32([2B seq][chunk...])>.<domain>
//! Query type:  TXT IN
//!
//! Response:    TXT RDATA = base32([2B seq][chunk...])
//! ```
//!
//! Sequence numbers allow the receiver to detect and discard duplicates.
//! Each direction uses its own 16-bit counter.
//!
//! ## DNS packet layout (manual, no external DNS crate)
//!
//! ```text
//! Header (12 bytes):
//!   [2B ID][2B flags][2B QDCOUNT][2B ANCOUNT][2B NSCOUNT][2B ARCOUNT]
//!
//! Question section:
//!   [name (label-encoded)][2B QTYPE][2B QCLASS]
//!
//! Answer section (response only):
//!   [name pointer 0xC00C][2B TYPE][2B CLASS][4B TTL][2B RDLENGTH][RDATA]
//! ```
//!
//! ## Bandwidth note
//!
//! This is a LOW bandwidth transport (~150 bytes per query/response round
//! trip).  It is designed for resilient transport in restricted networks where
//! DNS traffic is the only allowed protocol, not for performance.
//!
//! ## Polling
//!
//! DNS is inherently request-response.  The client must periodically send
//! queries (even "keepalive" queries with empty payload) to receive data
//! from the server.  The `DnsTunnelAdapter` polls at a fixed interval when
//! reading.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use mirage_core::error::MirageError;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;

use crate::camouflage::{private, UdpCamouflageLayer};

// ─────────────────────────────────────────────────────────────────────────────
// Public configuration types
// ─────────────────────────────────────────────────────────────────────────────

/// Encoding for DNS label payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsEncoding {
    /// RFC 4648 Base32 (A–Z + 2–7).  Case-insensitive, DNS-safe.
    Base32,
    /// URL-safe Base64 (A–Z, a–z, 0–9, -, _).  ~25% smaller than Base32.
    /// Note: some DNS resolvers lowercase labels; use Base32 for maximum
    /// compatibility with intermediate resolvers.
    Base64Url,
}

/// DNS query type used for tunnelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum DnsQueryType {
    /// TXT record — most common choice; payload in RDATA.
    TXT,
    /// NULL record (type 10) — carries arbitrary binary in RDATA.
    NULL,
}

impl DnsEncoding {
    /// The name a [`crate`] protocol body stores (`base32`, `base64url`).
    pub fn from_name(name: &str) -> Result<Self, String> {
        match name.to_ascii_lowercase().as_str() {
            "base32" => Ok(Self::Base32),
            "base64url" | "base64_url" => Ok(Self::Base64Url),
            _ => Err("dns encoding was refused".to_owned()),
        }
    }
}

impl DnsQueryType {
    /// The name a protocol body stores (`TXT`, `NULL`).
    pub fn from_name(name: &str) -> Result<Self, String> {
        match name.to_ascii_uppercase().as_str() {
            "TXT" => Ok(Self::TXT),
            "NULL" => Ok(Self::NULL),
            _ => Err("dns query type was refused".to_owned()),
        }
    }

    fn qtype_u16(self) -> u16 {
        match self {
            DnsQueryType::TXT => 16,
            DnsQueryType::NULL => 10,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Base32 encode / decode (no-std, no external crate)
// ─────────────────────────────────────────────────────────────────────────────

const BASE32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn base32_encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity((data.len() + 4) / 5 * 8);
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for &byte in data {
        buf = (buf << 8) | u64::from(byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(BASE32_ALPHABET[((buf >> bits) & 0x1F) as usize]);
        }
    }
    if bits > 0 {
        out.push(BASE32_ALPHABET[((buf << (5 - bits)) & 0x1F) as usize]);
    }
    // No padding ('=') — DNS labels must not contain '='.
    String::from_utf8(out).expect("base32 alphabet is ASCII")
}

fn base32_decode(s: &str) -> Result<Vec<u8>, MirageError> {
    let mut out = Vec::new();
    let mut buf: u64 = 0;
    let mut bits: u32 = 0;
    for ch in s.bytes() {
        let val = match ch {
            b'A'..=b'Z' => ch - b'A',
            b'a'..=b'z' => ch - b'a', // tolerate lowercase
            b'2'..=b'7' => ch - b'2' + 26,
            b'=' => break, // ignore padding if present
            _ => {
                return Err(MirageError::Protocol(format!(
                    "dns_tunnel: invalid base32 character '{}'",
                    ch as char
                )))
            }
        };
        buf = (buf << 5) | u64::from(val);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((buf >> bits) & 0xFF) as u8);
        }
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Base64url encode / decode
// ─────────────────────────────────────────────────────────────────────────────

const BASE64URL_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

fn base64url_encode(data: &[u8]) -> String {
    let mut out = Vec::with_capacity((data.len() + 2) / 3 * 4);
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(BASE64URL_ALPHABET[((b0 >> 2) & 0x3F) as usize]);
        out.push(BASE64URL_ALPHABET[(((b0 << 4) | (b1 >> 4)) & 0x3F) as usize]);
        if chunk.len() > 1 {
            out.push(BASE64URL_ALPHABET[(((b1 << 2) | (b2 >> 6)) & 0x3F) as usize]);
        }
        if chunk.len() > 2 {
            out.push(BASE64URL_ALPHABET[(b2 & 0x3F) as usize]);
        }
    }
    String::from_utf8(out).expect("base64url alphabet is ASCII")
}

fn base64url_decode(s: &str) -> Result<Vec<u8>, MirageError> {
    let decode_char = |ch: u8| -> Result<u8, MirageError> {
        match ch {
            b'A'..=b'Z' => Ok(ch - b'A'),
            b'a'..=b'z' => Ok(ch - b'a' + 26),
            b'0'..=b'9' => Ok(ch - b'0' + 52),
            b'-' => Ok(62),
            b'_' => Ok(63),
            _ => Err(MirageError::Protocol(format!(
                "dns_tunnel: invalid base64url character '{}'",
                ch as char
            ))),
        }
    };

    let bytes: Vec<u8> = s.bytes().collect();
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let v0 = decode_char(bytes[i])?;
        let v1 = if i + 1 < bytes.len() { decode_char(bytes[i + 1])? } else { 0 };
        out.push((v0 << 2) | (v1 >> 4));
        if i + 2 < bytes.len() {
            let v2 = decode_char(bytes[i + 2])?;
            out.push(((v1 & 0x0F) << 4) | (v2 >> 2));
            if i + 3 < bytes.len() {
                let v3 = decode_char(bytes[i + 3])?;
                out.push(((v2 & 0x03) << 6) | v3);
            }
        }
        i += 4;
    }
    Ok(out)
}

// ─────────────────────────────────────────────────────────────────────────────
// Encoding dispatch
// ─────────────────────────────────────────────────────────────────────────────

fn encode(data: &[u8], enc: DnsEncoding) -> String {
    match enc {
        DnsEncoding::Base32 => base32_encode(data),
        DnsEncoding::Base64Url => base64url_encode(data),
    }
}

fn decode_str(s: &str, enc: DnsEncoding) -> Result<Vec<u8>, MirageError> {
    match enc {
        DnsEncoding::Base32 => base32_decode(s),
        DnsEncoding::Base64Url => base64url_decode(s),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DNS packet helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Encode a DNS name into label-wire format.
///
/// `"sub.example.com"` → `\x03sub\x07example\x03com\x00`
fn encode_dns_name(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for label in name.split('.') {
        let lb = label.as_bytes();
        out.push(lb.len() as u8);
        out.extend_from_slice(lb);
    }
    out.push(0u8); // root label
    out
}

/// Build a DNS query packet.
///
/// Returns the raw bytes of a standard DNS query datagram.
fn build_query(id: u16, qname: &str, qtype: u16) -> Vec<u8> {
    let name_wire = encode_dns_name(qname);
    let mut pkt = Vec::with_capacity(12 + name_wire.len() + 4);

    // Header
    pkt.extend_from_slice(&id.to_be_bytes()); // ID
    pkt.extend_from_slice(&0x0100u16.to_be_bytes()); // flags: QR=0, RD=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // Question
    pkt.extend_from_slice(&name_wire);
    pkt.extend_from_slice(&qtype.to_be_bytes()); // QTYPE
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    pkt
}

/// Build a DNS response packet with a single TXT/NULL answer.
///
/// `rdata` is the raw RDATA bytes (for TXT: [len][data...]; for NULL: raw bytes).
fn build_response(id: u16, qname: &str, qtype: u16, rdata: &[u8]) -> Vec<u8> {
    let name_wire = encode_dns_name(qname);
    let mut pkt = Vec::with_capacity(12 + name_wire.len() + 4 + 12 + rdata.len());

    // Header
    pkt.extend_from_slice(&id.to_be_bytes()); // ID
    pkt.extend_from_slice(&0x8180u16.to_be_bytes()); // flags: QR=1, AA=1, RD=1, RA=1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    pkt.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT = 1
    pkt.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    pkt.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // Question (echoed)
    pkt.extend_from_slice(&name_wire);
    pkt.extend_from_slice(&qtype.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    // Answer — name pointer back to offset 12 (question name)
    pkt.extend_from_slice(&0xC00Cu16.to_be_bytes()); // name pointer
    pkt.extend_from_slice(&qtype.to_be_bytes()); // TYPE
    pkt.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
    pkt.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
    pkt.extend_from_slice(&(rdata.len() as u16).to_be_bytes()); // RDLENGTH
    pkt.extend_from_slice(rdata); // RDATA

    pkt
}

/// Parse the RDATA bytes from the first answer in a DNS response packet.
///
/// Returns `None` if the packet is malformed, too short, or has no answers.
fn parse_response_rdata(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 12 {
        return None;
    }

    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]);
    if ancount == 0 {
        return None;
    }

    // Skip header (12) + question section.
    // Question: name (variable) + 4 bytes (QTYPE + QCLASS).
    let mut pos = 12;
    pos = skip_dns_name(pkt, pos)?;
    pos = pos.checked_add(4)?; // QTYPE + QCLASS

    if pos >= pkt.len() {
        return None;
    }

    // Answer section: skip name pointer or name, then TYPE/CLASS/TTL/RDLEN.
    pos = skip_dns_name(pkt, pos)?;
    if pos + 10 > pkt.len() {
        return None;
    }
    // TYPE (2) + CLASS (2) + TTL (4) = 8 bytes, then RDLENGTH (2)
    let rdlen = u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]) as usize;
    pos += 10;

    if pos + rdlen > pkt.len() {
        return None;
    }

    Some(pkt[pos..pos + rdlen].to_vec())
}

/// Skip a DNS name (labels or pointer) at `pos` in `pkt`, returning position
/// after the name.
fn skip_dns_name(pkt: &[u8], mut pos: usize) -> Option<usize> {
    loop {
        if pos >= pkt.len() {
            return None;
        }
        let len = pkt[pos] as usize;
        if len == 0 {
            return Some(pos + 1); // root label
        }
        if len & 0xC0 == 0xC0 {
            // Pointer: 2 bytes total
            return Some(pos + 2);
        }
        pos = pos.checked_add(1 + len)?;
    }
}

/// Extract the query name from a DNS question section.
///
/// Returns `(name_string, qtype)` or `None` on parse failure.
fn parse_query_name(pkt: &[u8]) -> Option<(String, u16)> {
    if pkt.len() < 12 {
        return None;
    }
    let mut pos = 12; // start of question section
    let mut labels: Vec<String> = Vec::new();
    loop {
        if pos >= pkt.len() {
            return None;
        }
        let len = pkt[pos] as usize;
        if len == 0 {
            pos += 1;
            break;
        }
        pos += 1;
        if pos + len > pkt.len() {
            return None;
        }
        let label = String::from_utf8(pkt[pos..pos + len].to_vec()).ok()?;
        labels.push(label);
        pos += len;
    }
    if pos + 4 > pkt.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    Some((labels.join("."), qtype))
}

// ─────────────────────────────────────────────────────────────────────────────
// Payload framing
// ─────────────────────────────────────────────────────────────────────────────

/// Maximum bytes of payload per DNS label chunk.
///
/// DNS labels are at most 63 bytes.  After base32 encoding, 45 raw bytes
/// become 72 base32 chars — too large for one label.  We use multiple labels.
///
/// Total DNS name ≤ 253 bytes.  With a 20-char domain suffix + dots, we have
/// ~230 bytes for the encoded payload portion.  One 63-char label encodes
/// floor(63 * 5 / 8) = 39 raw bytes.  We allow up to 3 labels:
/// 3 × 39 = 117 raw bytes, leaving 2 bytes for the sequence number.
/// Effective payload per query: 115 bytes.
const MAX_PAYLOAD_PER_QUERY: usize = 115;

/// Maximum base32 chars per DNS label (DNS label limit = 63 chars).
const MAX_LABEL_CHARS: usize = 56; // 56 base32 chars → 35 raw bytes (safe margin)

/// Frame a payload chunk into a DNS label string.
///
/// `seq` is the 16-bit sequence number.  `chunk` is the payload bytes.
/// Together they are encoded and split into ≤63-char labels separated by dots.
fn frame_to_labels(seq: u16, chunk: &[u8], enc: DnsEncoding) -> String {
    let mut frame = Vec::with_capacity(2 + chunk.len());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(chunk);
    let encoded = encode(&frame, enc);
    // Split into 56-char labels
    encoded
        .as_bytes()
        .chunks(MAX_LABEL_CHARS)
        .map(|c| std::str::from_utf8(c).expect("base32/base64url is ASCII"))
        .collect::<Vec<_>>()
        .join(".")
}

/// Parse labels prefix from a full DNS name, stripping the domain suffix.
///
/// Returns the raw decoded bytes `[2B seq][payload...]`.
fn parse_labels(full_name: &str, domain: &str, enc: DnsEncoding) -> Result<Vec<u8>, MirageError> {
    // Strip trailing dot if present (FQDN form)
    let full_name = full_name.trim_end_matches('.');
    let domain = domain.trim_end_matches('.');

    let prefix = if full_name == domain {
        // Empty prefix → keepalive query with no payload
        return Ok(vec![0, 0]);
    } else {
        let suffix = format!(".{domain}");
        full_name.strip_suffix(&suffix).ok_or_else(|| {
            MirageError::Protocol(format!(
                "dns_tunnel: query name '{full_name}' does not end with '.{domain}'"
            ))
        })?
    };

    // Re-join labels (they were split by '.') and decode.
    let joined = prefix.replace('.', "");
    decode_str(&joined, enc)
}

/// Encode payload into TXT RDATA bytes.
///
/// TXT RDATA format: each string is `[1B length][data]`, concatenated.
/// We use a single string per RDATA.
fn encode_txt_rdata(seq: u16, chunk: &[u8], enc: DnsEncoding) -> Vec<u8> {
    let mut frame = Vec::with_capacity(2 + chunk.len());
    frame.extend_from_slice(&seq.to_be_bytes());
    frame.extend_from_slice(chunk);
    let encoded = encode(&frame, enc).into_bytes();
    // TXT: [1B string_len][string_bytes]
    let mut rdata = Vec::with_capacity(1 + encoded.len());
    rdata.push(encoded.len() as u8);
    rdata.extend_from_slice(&encoded);
    rdata
}

/// Decode TXT RDATA bytes back to `[2B seq][payload...]`.
fn decode_txt_rdata(rdata: &[u8], enc: DnsEncoding) -> Result<Vec<u8>, MirageError> {
    if rdata.is_empty() {
        return Err(MirageError::Protocol("dns_tunnel: empty TXT RDATA".into()));
    }
    let str_len = rdata[0] as usize;
    if 1 + str_len > rdata.len() {
        return Err(MirageError::Protocol(
            "dns_tunnel: TXT RDATA length prefix exceeds packet".into(),
        ));
    }
    let encoded =
        std::str::from_utf8(&rdata[1..1 + str_len]).map_err(|_| {
            MirageError::Protocol("dns_tunnel: TXT RDATA is not valid UTF-8".into())
        })?;
    decode_str(encoded, enc)
}

/// Encode payload into NULL RDATA bytes (raw binary).
fn encode_null_rdata(seq: u16, chunk: &[u8]) -> Vec<u8> {
    let mut rdata = Vec::with_capacity(2 + chunk.len());
    rdata.extend_from_slice(&seq.to_be_bytes());
    rdata.extend_from_slice(chunk);
    rdata
}

// ─────────────────────────────────────────────────────────────────────────────
// DnsTunnelCamouflage
// ─────────────────────────────────────────────────────────────────────────────

/// DNS tunnel transport-level camouflage.
///
/// Encodes payload in DNS TXT queries addressed to `<encoded>.<domain>`.
/// The server acts as an authoritative DNS server for `domain`, decoding
/// incoming queries and encoding responses in TXT records.
///
/// This is a low-bandwidth transport (~115 bytes per query round trip).
/// Designed for resilient transport where only DNS (port 53) is allowed.
pub struct DnsTunnelCamouflage {
    /// Base domain controlled by the operator (e.g. `"t.example.com"`).
    domain: String,
    /// Encoding to use for label payload.
    encoding: DnsEncoding,
    /// DNS query type (TXT or NULL).
    query_type: DnsQueryType,
}

impl DnsTunnelCamouflage {
    /// Create a new `DnsTunnelCamouflage`.
    ///
    /// * `domain` — controlled base domain (e.g. `"t.example.com"`)
    /// * `encoding` — base32 (DNS-safe) or base64url (smaller but case-sensitive)
    /// * `query_type` — TXT or NULL
    pub fn new(domain: String, encoding: DnsEncoding, query_type: DnsQueryType) -> Self {
        Self { domain, encoding, query_type }
    }
}

impl private::Sealed for DnsTunnelCamouflage {}

#[async_trait]
impl UdpCamouflageLayer for DnsTunnelCamouflage {
    type Stream = DnsTunnelAdapter;

    /// Client: bind an ephemeral UDP socket, connect to `server_addr` (the DNS
    /// server / relay), and return a `DnsTunnelAdapter`.
    ///
    /// `sni` is unused — DNS tunnel has no TLS outer layer.
    async fn connect_client(
        &self,
        server_addr: SocketAddr,
        _sni: &str,
    ) -> Result<DnsTunnelAdapter, MirageError> {
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(MirageError::Io)?;
        socket.connect(server_addr).await.map_err(MirageError::Io)?;

        Ok(DnsTunnelAdapter::new_client(
            socket,
            server_addr,
            self.domain.clone(),
            self.encoding,
            self.query_type,
        ))
    }

    /// Server: bind a UDP socket on `bind_addr` (typically port 53) and return
    /// a `DnsTunnelAdapter` that acts as an authoritative DNS server for
    /// `self.domain`.
    ///
    /// Returns `(adapter, client_addr)` where `client_addr` is the address of
    /// the first client that sent a valid query.
    async fn accept_server(
        &self,
        bind_addr: SocketAddr,
    ) -> Result<(DnsTunnelAdapter, SocketAddr), MirageError> {
        let socket = crate::camouflage::bind_udp_server(bind_addr).map_err(MirageError::Io)?;

        // The first datagram is the client's first write. Consuming it and
        // dropping the bytes would stall a preamble that is sent once.
        let mut buf = [0u8; 512];
        let (n, client_addr) = socket.recv_from(&mut buf).await.map_err(MirageError::Io)?;

        // Connect the socket to the client for subsequent send/recv.
        socket.connect(client_addr).await.map_err(MirageError::Io)?;

        let mut adapter = DnsTunnelAdapter::new_server(
            socket,
            client_addr,
            self.domain.clone(),
            self.encoding,
            self.query_type,
        );
        if let Ok(payload) = adapter.decode_recv(&buf[..n]) {
            adapter.recv_buf = payload;
        }

        Ok((adapter, client_addr))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// DnsTunnelAdapter — AsyncRead + AsyncWrite over a connected UdpSocket
// ─────────────────────────────────────────────────────────────────────────────

/// Role of this adapter endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    Client,
    Server,
}

/// Byte-stream adapter for DNS tunnel transport.
///
/// ## Write side
///
/// `poll_write(buf)` chops `buf` into `MAX_PAYLOAD_PER_QUERY`-byte chunks and
/// sends each as a DNS query (client) or DNS response (server).  Large writes
/// are handled by the async write loop in `MirageCoreTunnel`.
///
/// ## Read side
///
/// Maintains an internal receive buffer to bridge datagram semantics to stream
/// semantics (same approach as `Hysteria2UdpAdapter`).  Each UDP datagram is
/// one DNS packet; the adapter decodes the payload and accumulates it in
/// `recv_buf` for subsequent `poll_read` calls.
pub struct DnsTunnelAdapter {
    socket: UdpSocket,
    /// Remote peer address.
    remote: SocketAddr,
    /// Controlled base domain.
    domain: String,
    /// Payload encoding.
    encoding: DnsEncoding,
    /// DNS query type.
    query_type: DnsQueryType,
    /// Whether this side sends queries (client) or responses (server).
    role: Role,
    /// Outgoing sequence counter (per-direction).
    send_seq: Arc<AtomicU16>,
    /// Buffered bytes from the most recently received datagram.
    recv_buf: Vec<u8>,
    /// Read cursor into `recv_buf`.
    recv_pos: usize,
    /// Last received DNS message ID (server needs this to correlate responses).
    last_query_id: u16,
    /// Last received query name (server echoes it in responses).
    last_query_name: String,
}

impl DnsTunnelAdapter {
    fn new_client(
        socket: UdpSocket,
        remote: SocketAddr,
        domain: String,
        encoding: DnsEncoding,
        query_type: DnsQueryType,
    ) -> Self {
        Self {
            socket,
            remote,
            domain,
            encoding,
            query_type,
            role: Role::Client,
            send_seq: Arc::new(AtomicU16::new(0)),
            recv_buf: Vec::new(),
            recv_pos: 0,
            last_query_id: 0,
            last_query_name: String::new(),
        }
    }

    fn new_server(
        socket: UdpSocket,
        remote: SocketAddr,
        domain: String,
        encoding: DnsEncoding,
        query_type: DnsQueryType,
    ) -> Self {
        Self {
            socket,
            remote,
            domain,
            encoding,
            query_type,
            role: Role::Server,
            send_seq: Arc::new(AtomicU16::new(0)),
            recv_buf: Vec::new(),
            recv_pos: 0,
            last_query_id: 0,
            last_query_name: String::new(),
        }
    }

    /// Return the remote peer address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    // ── Encode outgoing payload into a DNS datagram ───────────────────────────

    fn encode_send(&mut self, payload: &[u8]) -> Vec<u8> {
        let seq = self.send_seq.fetch_add(1, Ordering::Relaxed);
        let qtype = self.query_type.qtype_u16();

        match self.role {
            Role::Client => {
                // Build DNS query: encode payload into subdomain labels
                let labels = frame_to_labels(seq, payload, self.encoding);
                let qname = format!("{}.{}", labels, self.domain);
                // Use seq as DNS message ID (wraps at 65535 — fine for our use)
                build_query(seq, &qname, qtype)
            }
            Role::Server => {
                // Build DNS response using last received query ID + name
                let rdata = match self.query_type {
                    DnsQueryType::TXT => encode_txt_rdata(seq, payload, self.encoding),
                    DnsQueryType::NULL => encode_null_rdata(seq, payload),
                };
                build_response(
                    self.last_query_id,
                    &self.last_query_name,
                    qtype,
                    &rdata,
                )
            }
        }
    }

    // ── Decode incoming DNS datagram into payload bytes ───────────────────────

    fn decode_recv(&mut self, pkt: &[u8]) -> Result<Vec<u8>, MirageError> {
        match self.role {
            Role::Client => {
                // Expect a DNS response; extract RDATA.
                let rdata = parse_response_rdata(pkt).ok_or_else(|| {
                    MirageError::Protocol("dns_tunnel: malformed DNS response".into())
                })?;
                match self.query_type {
                    DnsQueryType::TXT => {
                        let frame = decode_txt_rdata(&rdata, self.encoding)?;
                        // frame = [2B seq][payload...]; strip seq
                        if frame.len() < 2 {
                            return Err(MirageError::Protocol(
                                "dns_tunnel: response frame too short".into(),
                            ));
                        }
                        Ok(frame[2..].to_vec())
                    }
                    DnsQueryType::NULL => {
                        if rdata.len() < 2 {
                            return Err(MirageError::Protocol(
                                "dns_tunnel: NULL rdata too short".into(),
                            ));
                        }
                        Ok(rdata[2..].to_vec())
                    }
                }
            }
            Role::Server => {
                // Expect a DNS query; extract payload from subdomain labels.
                let (qname, _qtype) = parse_query_name(pkt).ok_or_else(|| {
                    MirageError::Protocol("dns_tunnel: malformed DNS query".into())
                })?;
                // Save query ID + name for the response.
                if pkt.len() >= 2 {
                    self.last_query_id = u16::from_be_bytes([pkt[0], pkt[1]]);
                }
                self.last_query_name = qname.clone();

                let frame = parse_labels(&qname, &self.domain, self.encoding)?;
                if frame.len() < 2 {
                    return Err(MirageError::Protocol(
                        "dns_tunnel: query frame too short".into(),
                    ));
                }
                Ok(frame[2..].to_vec())
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// AsyncRead + AsyncWrite
// ─────────────────────────────────────────────────────────────────────────────

impl AsyncRead for DnsTunnelAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Serve from buffer first.
        if self.recv_pos < self.recv_buf.len() {
            let available = &self.recv_buf[self.recv_pos..];
            let to_copy = available.len().min(buf.remaining());
            buf.put_slice(&available[..to_copy]);
            self.recv_pos += to_copy;
            if self.recv_pos >= self.recv_buf.len() {
                self.recv_buf.clear();
                self.recv_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }

        // Receive next datagram.
        let mut staging = vec![0u8; 512]; // DNS packets ≤ 512 bytes (UDP)
        let mut staging_buf = ReadBuf::new(&mut staging);
        match self.socket.poll_recv(cx, &mut staging_buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(())) => {
                let filled = staging_buf.filled().len();
                if filled == 0 {
                    return Poll::Ready(Ok(()));
                }
                let payload = self
                    .decode_recv(&staging[..filled])
                    .map_err(|e| io::Error::other(e.to_string()))?;

                if payload.is_empty() {
                    // Keepalive / empty payload — return without advancing buf
                    // so the caller loops back for another read.
                    cx.waker().wake_by_ref();
                    return Poll::Pending;
                }

                let to_copy = payload.len().min(buf.remaining());
                buf.put_slice(&payload[..to_copy]);
                if to_copy < payload.len() {
                    self.recv_buf = payload[to_copy..].to_vec();
                    self.recv_pos = 0;
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for DnsTunnelAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Chunk the payload — DNS queries carry at most MAX_PAYLOAD_PER_QUERY bytes.
        let chunk = if buf.len() > MAX_PAYLOAD_PER_QUERY {
            &buf[..MAX_PAYLOAD_PER_QUERY]
        } else {
            buf
        };

        let pkt = self.encode_send(chunk);
        match self.socket.poll_send(cx, &pkt) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            // Report how many bytes of the *original* payload were consumed
            // (not the wire packet size).
            Poll::Ready(Ok(_)) => Poll::Ready(Ok(chunk.len())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Unpin for DnsTunnelAdapter {}
