//! Camouflage only. A costume around a byte stream.
//!
//! Real protocols live in [`crate::protocols`]. They are not modules of this
//! tree. A `CamouflageLayer` prepares a TCP stream for the Mirage ECDH handshake:
//! it may add an outer TLS session, HTTP/1.1 WebSocket upgrade, etc.
//! After `wrap_client`/`wrap_server` the resulting stream is passed directly
//! to `core::handshake::run_client_handshake` / `run_server_handshake`.
//!
//! A `UdpCamouflageLayer` does the same for UDP-based camouflages (QUIC,
//! HTTP/3).  Instead of accepting a `TcpStream`, it owns its own
//! UDP endpoint and connects / accepts independently.
//!
//! Note: this is *transport*-level camouflage (outer wire protocol).
//! Application-level camouflage (JSON/gRPC/H2 frame wrapping) is handled by
//! `mirage_core::config::CamouflageMode` inside the tunnel data path.

pub mod none;
pub mod pipeline;
pub mod raw_udp;
pub mod reality;
pub mod wireguard;
pub mod xhttp;

use std::collections::HashMap;
use std::net::SocketAddr;

use crate::protocols::l3::icmp;
use crate::protocols::l7::dns as dns_tunnel;
use std::time::Instant;

use async_trait::async_trait;
use mirage_core::error::MirageError;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
    sync::mpsc,
};

// ─────────────────────────────────────────────────────────────────────────────
// Sealed trait machinery
// ─────────────────────────────────────────────────────────────────────────────

/// Bind a UDP server socket, keeping the address families separate.
///
/// # The bug this exists to prevent, which TCP already learned
///
/// `net.ipv6.bindv6only` is `0` on this fleet, so a socket bound to `[::]` is
/// dual-stack and claims the IPv4 wildcard along with the v6 one. A face that
/// then tries to bind `0.0.0.0` on the same port gets `EADDRINUSE`, and a
/// reader who sees one live socket concludes the box listens on one family
/// when it answers on both. `mirage-perimeter/src/face.rs::bind_v6_only`
/// exists for exactly this on TCP; every UDP bind in this module repeated the
/// mistake it was written to fix.
///
/// So: `IPV6_V6ONLY` on the v6 path, and `SO_REUSEADDR` to match what
/// `std`'s own bind does on unix, for the same reason the TCP helper sets it
/// — otherwise the two families come back differently after a restart and
/// the difference reads as a flaky stack rather than as our own doing.
///
/// A v4 address takes the plain path: there is nothing to separate.
///
/// # `set_nonblocking` is not optional — corrected 2026-09-06
///
/// `tokio::net::UdpSocket::from_std` requires the socket handed to it to
/// already be in non-blocking mode; on unix a debug build catches a violation
/// with a `debug_assert`, but `check_socket_for_blocking`'s own non-unix arm
/// is a documented no-op ("we cannot retrieve the nonblocking status on
/// windows") — so on Windows a still-blocking socket is accepted silently,
/// registered with the IOCP-backed reactor, and the first datagram it carries
/// works. What breaks is everything after: `raw_udp_single_hop_round_trip`
/// hung past its own 2s `tokio::time::timeout` — not merely the client/server
/// exchange Pending, but the whole runtime's timer driver wedged, because a
/// blocking-mode handle under IOCP does not behave like the non-blocking one
/// every other `.await` on that reactor assumes. The v6 arm two lines below
/// already calls this; the v4 arm never did.
pub(crate) fn bind_udp_server(bind_addr: SocketAddr) -> std::io::Result<tokio::net::UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};

    if bind_addr.is_ipv4() {
        let socket = std::net::UdpSocket::bind(bind_addr)?;
        socket.set_nonblocking(true)?;
        return tokio::net::UdpSocket::from_std(socket);
    }
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_only_v6(true)?;
    socket.set_reuse_address(true)?;
    socket.bind(&bind_addr.into())?;
    socket.set_nonblocking(true)?;
    tokio::net::UdpSocket::from_std(socket.into())
}

/// Evict entries from a UDP dispatcher's peer map, least-recently-seen
/// first, until at most `trigger` remain. Returns how many were removed.
///
/// Shared by `raw_udp.rs` and `wireguard.rs`: both dispatchers insert a new
/// peer entry before any authentication check runs, so both are exposed to
/// the same source-address spray and both need the same fallback. Call this
/// AFTER the idle sweep (`peers.retain(|_, (_, last_seen)| ...)`), and only
/// when the sweep did not already bring the map back under `trigger` — see
/// `raw_udp::PEER_SWEEP_TRIGGER`'s own doc for why the idle sweep alone
/// cannot bound a spray (a spray mints a FRESH entry, and a fresh entry has
/// a fresh `last_seen`, so the idle sweep frees none of it).
///
/// Idle-first, least-recent-second, is the deliberate order, not an
/// arbitrary one: an idle entry is already dead — its `last_seen` is already
/// older than `PEER_IDLE_EVICT`, nothing is reading its channel, and
/// removing it costs no live session — so it is the cheap, certain win and
/// is spent first. Evicting by least-recent `last_seen` is the fallback for
/// whatever the idle sweep could not shrink, and it can be wrong in a way
/// the idle sweep cannot: a peer merely quiet for less than
/// `PEER_IDLE_EVICT` can be the least-recent entry and pay for a spray it
/// had no part in. That risk is accepted only as a last resort, after the
/// free win has already run, and it is bounded by the same trigger that used
/// to be the whole defence: once this returns, the map holds at most
/// `trigger` entries no matter how large the spray creating pressure is, and
/// a peer that keeps sending keeps refreshing its own `last_seen`, so it is
/// always the last entry this function would ever evict.
pub(crate) fn evict_least_recent_until(
    peers: &mut HashMap<SocketAddr, (mpsc::Sender<Vec<u8>>, Instant)>,
    trigger: usize,
) -> usize {
    if peers.len() <= trigger {
        return 0;
    }
    let mut by_age: Vec<(SocketAddr, Instant)> = peers
        .iter()
        .map(|(addr, (_, last_seen))| (*addr, *last_seen))
        .collect();

    let to_remove = peers.len() - trigger;
    // The `to_remove` oldest entries only need to be identified as a SET to
    // remove, not presented in order, so a full `sort_by_key` (O(n log n))
    // buys nothing over partitioning around the `(to_remove - 1)`th element
    // by age (`select_nth_unstable_by_key`, O(n) worst case via introselect):
    // afterwards `by_age[..to_remove]` holds exactly the oldest `to_remove`
    // entries, unordered among themselves, which is all `HashMap::remove`
    // below needs. Skipped when `to_remove` covers the whole vec (`trigger
    // == 0`) — nothing is left to partition around, and everything is
    // removed regardless of order.
    if to_remove < by_age.len() {
        by_age.select_nth_unstable_by_key(to_remove - 1, |(_, last_seen)| *last_seen);
    }

    let mut evicted = 0usize;
    for (addr, _) in by_age.into_iter().take(to_remove) {
        if peers.remove(&addr).is_some() {
            evicted += 1;
        }
    }
    evicted
}

/// Idle sweep, then — ONLY if the idle sweep did not already bring the map
/// back under `trigger` — batch-evict by least-recent `last_seen` down to
/// `low_water`. Returns `(idle_swept, lru_evicted)`.
///
/// This is the entire two-stage sweep-then-batch-evict policy `raw_udp.rs`
/// and `wireguard.rs`'s dispatchers run on the new-peer path, factored out
/// here so the two stay provably identical instead of two hand-copies that
/// can drift. See `raw_udp::PEER_LOW_WATER_MARK`'s own doc for why the
/// second stage targets `low_water` rather than `trigger` itself: evicting
/// exactly to `trigger` puts the map right back at the point that fires this
/// same expensive path again on the very next admission — an O(n) `retain`
/// plus an O(n) selection over the whole map, on EVERY subsequent datagram
/// under a sustained spray, not once in a while.
///
/// # Stage separation lives in the inner gate, not in whether this runs at all
///
/// The idle sweep always runs once the caller has decided `peers.len() >
/// trigger` — it is cheap, and an idle entry is already dead, so sweeping it
/// costs no live session no matter how this call turns out. What is gated is
/// the expensive second stage: `evict_least_recent_until` runs only `if
/// peers.len() > trigger` AFTER the sweep — never merely because
/// `peers.len() > low_water`. A map the idle sweep already brought back
/// under `trigger` on its own must not then have live, merely-quiet peers
/// cut down to `low_water` — that would trade a working session for headroom
/// nobody asked to spend.
pub(crate) fn sweep_and_batch_evict(
    peers: &mut HashMap<SocketAddr, (mpsc::Sender<Vec<u8>>, Instant)>,
    trigger: usize,
    idle_evict: std::time::Duration,
    low_water: usize,
) -> (usize, usize) {
    let now = Instant::now();
    let before = peers.len();
    peers.retain(|_, (_, last_seen)| now.duration_since(*last_seen) < idle_evict);
    let idle_swept = before - peers.len();

    let lru_evicted = if peers.len() > trigger {
        evict_least_recent_until(peers, low_water)
    } else {
        0
    };
    (idle_swept, lru_evicted)
}

pub(crate) mod private {
    pub trait Sealed {}
}

// ─────────────────────────────────────────────────────────────────────────────
// CamouflageLayer trait  (TCP-based camouflages)
// ─────────────────────────────────────────────────────────────────────────────

/// Transforms a raw `TcpStream` into a camouflaged byte stream.
///
/// Sealed — external code selects camouflage via `CamouflageConfig`, not by
/// implementing this trait directly.
#[async_trait]
pub trait CamouflageLayer: private::Sealed + Send + Sync {
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    /// Client side: wrap `stream` in the camouflage protocol.
    ///
    /// `sni` is passed to TLS-based layers for SNI; ignored by `NoCamouflage`.
    async fn wrap_client(
        &self,
        stream: TcpStream,
        sni: &str,
    ) -> Result<Self::Stream, MirageError>;

    /// Server side: complete the camouflage handshake on an accepted stream.
    ///
    /// Returns `None` if the connection is not recognised as our protocol
    /// (the caller should forward it to a fallback handler).
    async fn wrap_server(&self, stream: TcpStream) -> Result<Option<Self::Stream>, MirageError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// UdpCamouflageLayer trait  (UDP-based camouflages: QUIC, HTTP/3)
// ─────────────────────────────────────────────────────────────────────────────

/// Establishes a camouflaged bidirectional byte stream over a UDP-based
/// transport (e.g. QUIC).
///
/// Unlike `CamouflageLayer`, this trait owns its UDP endpoint internally and
/// does not accept a `TcpStream` parameter.  The client connects to a remote
/// `SocketAddr`; the server binds to a local `SocketAddr` and accepts one
/// incoming connection.
///
/// The returned `Stream` type implements `AsyncRead + AsyncWrite + Unpin`, so
/// `core::handshake::run_client_handshake` / `run_server_handshake` can run
/// on top of it unchanged.
///
/// # Production listener note — and the two families it splits into
///
/// `accept_server` returns one accepted stream per call. What you may NOT do
/// is assume that calling it in a loop is the production shape: whether that
/// is correct depends on which family the implementation belongs to, and the
/// two behave oppositely.
///
/// **Shared-dispatcher family** (`raw_udp`, `wireguard`, `dns_tunnel`): one bound `UdpSocket` per `bind_addr` is created on first
/// call and reused thereafter (`listeners.get(&bind_addr)`), with a
/// dispatcher task demultiplexing datagrams to per-peer adapters. Calling
/// `accept_server` repeatedly is correct and cheap — it takes from an accept
/// queue.
///
/// **`quinn::Endpoint` family** (`quic`, `http3`, `webtransport`):
/// `accept_server` is `bind_endpoint(bind_addr)` followed by
/// `accept_one(&endpoint)`, so EVERY call binds a fresh endpoint. Looping on
/// it rebinds the socket and tears down the previous endpoint, dropping
/// CONNECTION_CLOSE on every peer it was serving. Production code must bind
/// once and loop the accept: `driver.rs` does exactly that in all five of its
/// UDP server arms (`let endpoint = layer.bind_endpoint(bind_addr)?;` then
/// `loop { layer.accept_one(&endpoint) }`), and this trait's own doc used to
/// advise the opposite.
///
/// `accept_server` remains the single-shot convenience the tests use. It is
/// not the listener abstraction, and there is no one loop that is right for
/// both families.
///
/// Sealed — external code selects camouflage via `CamouflageConfig`.
#[async_trait]
pub trait UdpCamouflageLayer: private::Sealed + Send + Sync {
    /// The bidirectional stream adapter returned by connect / accept.
    type Stream: AsyncRead + AsyncWrite + Unpin + Send;

    /// Client: connect to `server_addr` via this UDP-based camouflage.
    ///
    /// `sni` is used for TLS-based camouflages that layer TLS on UDP (QUIC).
    /// Returns a stream adapter ready for the Mirage handshake.
    async fn connect_client(
        &self,
        server_addr: SocketAddr,
        sni: &str,
    ) -> Result<Self::Stream, MirageError>;

    /// Server: bind to `bind_addr`, accept one incoming connection, and return
    /// a stream adapter ready for the Mirage handshake.
    ///
    /// Returns the stream adapter together with the remote peer address.
    async fn accept_server(
        &self,
        bind_addr: SocketAddr,
    ) -> Result<(Self::Stream, SocketAddr), MirageError>;
}

// ─────────────────────────────────────────────────────────────────────────────
// CamouflageConfig — configuration enum for serialisation
// ─────────────────────────────────────────────────────────────────────────────

/// Selects the transport-level camouflage mode.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CamouflageConfig {
    /// No outer wrapper — raw TCP.
    None,
    /// Real TLS 1.3 outer session via rustls.
    ///
    /// DPI sees a standard TLS 1.3 handshake to `sni`.
    /// Certificate verification is skipped — security lives in the Mirage handshake.
    TlsReal {
        /// SNI hostname sent in the TLS ClientHello (e.g. `"cloudflare.com"`).
        sni: String,
        /// ALPN protocol identifiers (e.g. `["h2", "http/1.1"]`).
        #[serde(default)]
        alpn: Vec<String>,
    },
    /// HTTP/1.1 Upgrade → WebSocket binary frames.
    ///
    /// DPI / CDN / corporate proxies see legitimate WebSocket traffic.
    /// The inner Mirage ECDH handshake and AEAD framing run inside binary frames.
    WebSocket {
        /// HTTP path for the upgrade request (e.g. `"/ws"`).
        path: String,
        /// `Host` header value (e.g. `"www.googleapis.com"`).
        host: String,
    },
    /// Reality-style X25519 handshake authentication (outer auth layer).
    ///
    /// Client sends 96 bytes: `[e_pub (32B)][encrypted session_id (40B)][padding (24B)]`.
    /// Server validates short_id and timestamp, then returns the raw stream for the
    /// inner Mirage handshake.
    ///
    /// Not wire-compatible with xray-core; this is our own imitation of xtls/reality.
    Reality {
        /// Hex-encoded 16-byte pre-shared session identifier.
        short_id: String,
        /// SNI hint (informational — not used in current wire format).
        server_name: String,
        /// Maximum allowed clock skew between client and server in seconds.
        max_time_diff: u32,
        /// Optional fallback destination shown to unauthenticated probes (e.g. `"1.1.1.1:443"`).
        fallback_dest: Option<String>,
    },
    /// QUIC outer transport (UDP under the hood) with built-in TLS 1.3.
    ///
    /// A single bidirectional QUIC stream is opened per connection.  DPI sees
    /// legitimate QUIC/H3 traffic.  Certificate verification is skipped —
    /// security lives in the inner Mirage handshake.
    Quic {
        /// ALPN protocol identifiers (e.g. `["h3"]`).
        #[serde(default)]
        alpn: Vec<String>,
        /// Local bind address for the QUIC endpoint (typically `0.0.0.0:0`
        /// for clients; a fixed port for servers).
        bind_addr: SocketAddr,
    },
    /// HTTP/3 CONNECT-style tunnel over QUIC.
    ///
    /// Client opens a POST request to `tunnel_path` with `:authority = authority`.
    /// The Mirage handshake and AEAD frames flow in the request/response bodies.
    /// DPI sees legitimate HTTP/3 traffic (ALPN=h3).  Certificate verification
    /// is skipped — security lives in the inner Mirage handshake.
    Http3 {
        /// `:authority` header value (e.g. `"www.googleapis.com"`).
        authority: String,
        /// HTTP path for the tunnel endpoint (e.g. `"/api/v1/events"`).
        tunnel_path: String,
        /// QUIC ALPN identifier (typically `"h3"`).
        alpn: String,
        /// Local bind address for the QUIC endpoint.
        bind_addr: SocketAddr,
    },
    /// Hysteria2-style UDP camouflage with Salamander obfuscation.
    ///
    /// KEPT FOR READING OLD CONFIGS ONLY — Hysteria2 is not part of the mask
    /// set any more, and a config that asks for it is refused with a plain
    /// error instead of being served.
    ///
    /// A 2-message UDP handshake (72B client → 40B server) authenticates the
    /// pre-shared key via Salamander XOR + BLAKE3.  Invalid PSK → server
    /// silently drops (probe resistance).  Data phase runs over raw AEAD via
    /// `MirageCoreTunnel` — NOT over Salamander XOR.
    Hysteria2 {
        /// Hex-encoded 32-byte pre-shared key for Salamander obfuscation.
        psk_hex: String,
        /// Local bind address for the UDP endpoint.
        ///
        /// For clients this is typically `0.0.0.0:0` (OS-assigned ephemeral port).
        /// For servers this is the fixed listening address (e.g. `0.0.0.0:443`).
        bind_addr: SocketAddr,
    },
    /// DNS tunnel transport — encodes payload in DNS TXT queries/responses.
    ///
    /// The client encodes data as base32/base64url subdomains of `domain` and
    /// sends TXT or NULL queries to `dns_server`.  The server acts as an
    /// authoritative DNS server for `domain`, decoding queries and encoding
    /// responses in TXT records.
    ///
    /// Low bandwidth (~115 bytes per round trip).  Designed for restricted networks
    /// where only DNS (port 53) is permitted.
    DnsTunnel {
        /// Controlled base domain (e.g. `"t.example.com"`).
        domain: String,
        /// DNS server / relay address for the client (e.g. `"1.1.1.1:53"`).
        ///
        /// On the server side this field is unused; bind address is supplied
        /// separately via `accept_server(bind_addr)`.
        dns_server: SocketAddr,
        /// Payload encoding for DNS labels.
        encoding: dns_tunnel::DnsEncoding,
        /// DNS query type used for tunnelling (TXT or NULL).
        query_type: dns_tunnel::DnsQueryType,
    },
    /// WireGuard/AmneziaWG-style UDP camouflage with magic-byte framing and
    /// a pre-handshake junk burst.
    ///
    /// Every real datagram is prefixed with `magic_byte`.  Before the
    /// handshake the client sends `junk_count` random UDP datagrams of size
    /// in [`junk_min`, `junk_max`] bytes (AmneziaWG "Jc / Jmin / Jmax"
    /// parameters).  The server silently drops any datagram that does not
    /// start with `magic_byte`.
    ///
    /// The actual AEAD encryption runs via `MirageCoreTunnel` — no nonce
    /// reuse.  This is not wire-compatible with amneziawg-go; it shares the
    /// same obfuscation strategy but uses our X25519 + BLAKE3 crypto stack.
    WireGuard {
        /// Single byte prepended to every real datagram.
        ///
        /// Avoid `0x01`, `0x02`, `0x04` (standard WireGuard type bytes) for
        /// effective DPI evasion.
        magic_byte: u8,
        /// Number of junk datagrams sent before the real handshake (client side).
        junk_count: u8,
        /// Minimum junk datagram payload size in bytes.
        junk_min: u16,
        /// Maximum junk datagram payload size in bytes (inclusive).
        junk_max: u16,
        /// Local bind address for the UDP endpoint.
        ///
        /// For clients this is typically `0.0.0.0:0` (OS-assigned ephemeral port).
        /// For servers this is the fixed listening address (e.g. `0.0.0.0:443`).
        bind_addr: SocketAddr,
    },
    /// SSH tunnel camouflage — carries Mirage traffic inside an SSH
    /// `direct-tcpip` channel.  DPI observers see standard SSH on port 22.
    ///
    /// Requires the `ssh` feature flag.
    Ssh {
        /// SSH username for authentication.
        ssh_user: String,
        /// PEM-encoded server host key for verification.
        ///
        /// `None` → skip host key verification.  Security lives in the inner
        /// Mirage handshake.
        #[serde(default)]
        ssh_host_key: Option<String>,
        /// PEM-encoded client private key for public-key authentication.
        ///
        /// `None` → fall back to password authentication (`ssh_password`).
        #[serde(default)]
        ssh_private_key: Option<String>,
        /// Password for password-based SSH authentication.
        ///
        /// Used only when `ssh_private_key` is `None`.
        #[serde(default)]
        ssh_password: Option<String>,
        /// Hostname forwarded in the `direct-tcpip` channel open request.
        ///
        /// Typically `"127.0.0.1"` — ignored by the Mirage server relay.
        forward_host: String,
        /// Port forwarded in the `direct-tcpip` channel open request.
        ///
        /// Typically `0` — ignored by the Mirage server relay.
        forward_port: u16,
    },
    /// gRPC tunnel camouflage — carries Mirage frames inside an HTTP/2
    /// bidirectional streaming RPC.  DPI observers see a standard gRPC
    /// service call (`content-type: application/grpc`).  CDN-friendly.
    ///
    /// Requires the `grpc` feature flag.
    Grpc {
        /// gRPC service name presented in the HTTP/2 path
        /// (e.g. `"google.cloud.vision.v1.ImageAnnotator"`).
        service_name: String,
        /// gRPC method name presented in the HTTP/2 path
        /// (e.g. `"AsyncBatchAnnotateImages"`).
        method_name: String,
        /// HTTP/2 `:authority` header value (e.g. `"vision.googleapis.com"`).
        authority: String,
        /// Whether to wrap the connection in TLS before HTTP/2.
        ///
        /// `false` — raw TCP + HTTP/2 (h2c).  Security lives in the inner
        /// Mirage handshake.  Suitable for connections to a TLS-terminating
        /// CDN/reverse-proxy.
        #[serde(default)]
        use_tls: bool,
    },
    /// ICMP tunnel transport — carries Mirage payload inside ICMP Echo
    /// Request / Echo Reply packets.
    ///
    /// No port numbers are used, bypassing port-based firewalls entirely.
    /// DPI sees ordinary `ping` traffic.
    ///
    /// **Requires administrator / root privileges** — raw sockets need
    /// `CAP_NET_RAW` on Linux / root on macOS / Administrator on Windows.
    ///
    /// Low-to-medium bandwidth (~1400 bytes/round-trip with default MTU).
    /// Unreliable (packets can drop / reorder); Mirage AEAD framing handles
    /// retransmission.
    Icmp {
        /// Server IP address (used by the client; the server listens on all
        /// interfaces).
        peer_addr: std::net::IpAddr,
        /// 16-bit session identifier — distinguishes this tunnel from other
        /// ICMP traffic on the same machine (analogous to a port number).
        identifier: u16,
        /// Maximum payload bytes per ICMP datagram (default: 1400).
        #[serde(default = "icmp_mtu_default")]
        mtu: usize,
    },
    /// WebTransport tunnel — W3C standard over HTTP/3 (QUIC + TLS 1.3).
    ///
    /// Client sends an HTTP/3 Extended CONNECT with `:protocol: webtransport`
    /// to `path` on `authority`.  DPI sees legitimate HTTP/3 traffic (ALPN=h3).
    /// Browsers support WebTransport natively; CDNs forward it transparently.
    /// Certificate verification is skipped — security lives in the inner Mirage
    /// handshake.
    WebTransport {
        /// HTTP path for the WebTransport session (e.g. `"/transport"`).
        path: String,
        /// `:authority` header value (e.g. `"cdn.example.com"`).
        authority: String,
        /// Local bind address for the QUIC endpoint.
        ///
        /// For clients this is typically `0.0.0.0:0` (OS-assigned ephemeral port).
        /// For servers this is the fixed listening address (e.g. `0.0.0.0:443`).
        bind_addr: SocketAddr,
    },
}

fn icmp_mtu_default() -> usize {
    icmp::DEFAULT_ICMP_MTU
}

#[cfg(test)]
mod evict_least_recent_until_tests {
    use super::*;

    /// Build a peer-map entry with a `last_seen` `age_secs` in the past —
    /// `Instant` subtracts a `Duration` without unsafe or unstable APIs, so
    /// every test below is deterministic and needs no real wall-clock wait.
    fn entry_aged(age_secs: u64) -> (mpsc::Sender<Vec<u8>>, Instant) {
        let (tx, _rx) = mpsc::channel::<Vec<u8>>(1);
        (tx, Instant::now() - std::time::Duration::from_secs(age_secs))
    }

    /// The spray case: every entry is fresh (age 0), so an idle sweep run
    /// immediately before this call would have freed nothing — this is the
    /// exact situation the fallback exists for. Filling the map past the
    /// trigger must still bring it back down to the trigger, not leave it to
    /// grow without bound.
    #[test]
    fn a_map_of_all_fresh_entries_past_the_trigger_is_still_brought_back_to_the_trigger() {
        let mut peers: HashMap<SocketAddr, (mpsc::Sender<Vec<u8>>, Instant)> = HashMap::new();
        for i in 0..200u16 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 10_000 + i).parse().expect("valid addr");
            peers.insert(addr, entry_aged(0));
        }
        assert_eq!(peers.len(), 200);

        let evicted = evict_least_recent_until(&mut peers, 50);

        assert_eq!(evicted, 150, "must evict exactly enough to reach the trigger");
        assert_eq!(peers.len(), 50, "the map must be bounded at the trigger, not left over it");
    }

    /// Evicted entries must be exactly the least-recently-seen ones — not an
    /// arbitrary 150 out of 200.
    #[test]
    fn eviction_removes_the_oldest_entries_by_last_seen_not_arbitrary_ones() {
        let mut peers: HashMap<SocketAddr, (mpsc::Sender<Vec<u8>>, Instant)> = HashMap::new();
        // Ages 0..200, so addr with age N is the Nth-oldest (age 199 is the
        // single oldest entry, age 0 is the freshest).
        for age in 0..200u64 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 10_000 + age).parse().expect("valid addr");
            peers.insert(addr, entry_aged(age));
        }

        let evicted = evict_least_recent_until(&mut peers, 50);
        assert_eq!(evicted, 150);
        assert_eq!(peers.len(), 50);

        // The 50 survivors must be exactly the 50 freshest (ages 0..50); the
        // 150 oldest (ages 50..200) must all be gone.
        for age in 0..50u64 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 10_000 + age).parse().expect("valid addr");
            assert!(peers.contains_key(&addr), "freshest entry (age {age}) must survive");
        }
        for age in 50..200u64 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 10_000 + age).parse().expect("valid addr");
            assert!(!peers.contains_key(&addr), "older entry (age {age}) must have been evicted");
        }
    }

    /// An actively-sending peer (the freshest `last_seen` in the map) must
    /// survive a spray far larger than the whole map — proving eviction
    /// order protects whoever is still talking, no matter how many forged
    /// entries pile up around it.
    #[test]
    fn an_actively_sending_peers_entry_survives_a_spray_larger_than_the_whole_map() {
        let active_addr: SocketAddr = "127.0.0.1:1".parse().expect("valid addr");
        let mut peers: HashMap<SocketAddr, (mpsc::Sender<Vec<u8>>, Instant)> = HashMap::new();
        // The active peer is inserted FIRST (oldest by insertion order) but
        // stamped with age 0 (freshest by last_seen) — exactly what a peer
        // that keeps sending looks like: old session, freshly refreshed
        // last_seen.
        peers.insert(active_addr, entry_aged(0));

        // A spray far bigger than the eventual trigger — every sprayed
        // address is OLDER than the active peer (ages 1..=5000), simulating
        // entries that arrived and were never refreshed since.
        for age in 1..=5000u64 {
            let addr: SocketAddr = format!("127.0.0.2:{}", (age % 60000) + 1).parse().expect("valid addr");
            peers.insert(addr, entry_aged(age));
        }

        let trigger = 10;
        evict_least_recent_until(&mut peers, trigger);

        assert_eq!(peers.len(), trigger);
        assert!(
            peers.contains_key(&active_addr),
            "the actively-sending peer must be the last one evicted, not swept away with the spray"
        );
    }

    /// At or under the trigger, the fallback is a no-op — it must never
    /// evict when the idle sweep already did enough (or the map was never
    /// over the trigger to begin with).
    #[test]
    fn at_or_under_the_trigger_nothing_is_evicted() {
        let mut peers: HashMap<SocketAddr, (mpsc::Sender<Vec<u8>>, Instant)> = HashMap::new();
        for i in 0..10u16 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 10_000 + i).parse().expect("valid addr");
            peers.insert(addr, entry_aged(0));
        }

        let evicted = evict_least_recent_until(&mut peers, 10);
        assert_eq!(evicted, 0);
        assert_eq!(peers.len(), 10);

        let evicted = evict_least_recent_until(&mut peers, 50);
        assert_eq!(evicted, 0);
        assert_eq!(peers.len(), 10);
    }

    /// Requirement 1 (batching is structural, not timed): once the
    /// least-recent fallback actually runs against a map of nothing but
    /// fresh entries — the exact case an idle sweep cannot help with — the
    /// map must land on the LOW-WATER mark, not back on the trigger itself.
    /// Landing on the trigger is the defect this function exists to fix: the
    /// very next admission would cross it again and pay for this whole call
    /// once more.
    #[test]
    fn sweep_and_batch_evict_lands_on_the_low_water_mark_not_the_trigger_for_an_all_fresh_map() {
        let mut peers: HashMap<SocketAddr, (mpsc::Sender<Vec<u8>>, Instant)> = HashMap::new();
        for i in 0..250u16 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 10_000 + i).parse().expect("valid addr");
            peers.insert(addr, entry_aged(0));
        }
        let trigger = 200;
        let low_water = trigger - trigger / 8; // 175 — same 7/8 shape as production.

        let (idle_swept, lru_evicted) =
            sweep_and_batch_evict(&mut peers, trigger, std::time::Duration::from_secs(60), low_water);

        assert_eq!(idle_swept, 0, "every entry is fresh — the idle sweep must free nothing");
        assert_eq!(lru_evicted, 250 - low_water);
        assert_eq!(
            peers.len(),
            low_water,
            "must land on the low-water mark, not the trigger — landing on the trigger is the \
             defect this function exists to fix"
        );
        assert_ne!(
            peers.len(),
            trigger,
            "landing exactly on the trigger would reproduce the per-datagram cost this exists to amortize"
        );
    }

    /// Requirement 2: once the map sits at the low-water mark, admitting one
    /// more peer must not run the expensive path again — the map simply
    /// grows by one and stays under the trigger, exactly the amortization
    /// the low-water headroom buys. Mirrors the production call sites
    /// exactly: they insert the new peer BEFORE checking against the
    /// trigger (see `raw_udp.rs`'s own doc for why).
    #[test]
    fn admitting_one_more_peer_after_the_batch_does_not_cross_the_trigger_again() {
        let mut peers: HashMap<SocketAddr, (mpsc::Sender<Vec<u8>>, Instant)> = HashMap::new();
        let trigger = 200;
        let low_water = trigger - trigger / 8; // 175
        for i in 0..low_water as u16 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 10_000 + i).parse().expect("valid addr");
            peers.insert(addr, entry_aged(0));
        }
        assert_eq!(peers.len(), low_water);

        let new_addr: SocketAddr = "127.0.0.1:1".parse().expect("valid addr");
        peers.insert(new_addr, entry_aged(0));
        assert_eq!(peers.len(), low_water + 1, "the map must simply grow by one");
        assert!(
            peers.len() <= trigger,
            "one admission past the low-water mark must still be under the trigger"
        );

        // The production call site's own gate — the expensive path is not
        // even entered unless this holds.
        if peers.len() > trigger {
            let (_idle, lru) =
                sweep_and_batch_evict(&mut peers, trigger, std::time::Duration::from_secs(60), low_water);
            panic!("the expensive path must not run at all here (lru_evicted would have been {lru})");
        }
    }

    /// Requirement 3 (stage separation): a map the idle sweep alone brings
    /// back under the trigger must NOT then have its surviving, still-live
    /// entries cut down to the low-water mark. Cutting them would trade a
    /// working session for headroom nobody asked to spend — the idle sweep
    /// already spent the only free, certain win available.
    #[test]
    fn an_idle_map_brought_back_under_the_trigger_by_the_sweep_alone_is_never_cut_to_the_low_water_mark() {
        let mut peers: HashMap<SocketAddr, (mpsc::Sender<Vec<u8>>, Instant)> = HashMap::new();
        let trigger = 10;
        let low_water = trigger - trigger / 8; // 9 — deliberately close to the trigger, so a
                                                // wrongful cut to it is easy to tell apart from
                                                // correct behaviour.

        // 5 entries old enough for the idle sweep to remove outright.
        for i in 0..5u16 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 20_000 + i).parse().expect("valid addr");
            peers.insert(addr, entry_aged(9_999));
        }
        // 8 fresh, LIVE entries — more than `low_water` on their own, so if
        // the fallback wrongly ran, some of these would be evicted too.
        for i in 0..8u16 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 30_000 + i).parse().expect("valid addr");
            peers.insert(addr, entry_aged(0));
        }
        assert_eq!(peers.len(), 13);
        assert!(peers.len() > trigger, "the map must start over the trigger for this scenario to apply");

        let (idle_swept, lru_evicted) =
            sweep_and_batch_evict(&mut peers, trigger, std::time::Duration::from_secs(600), low_water);

        assert_eq!(idle_swept, 5, "the idle sweep alone must remove exactly the 5 stale entries");
        assert_eq!(lru_evicted, 0, "the least-recent fallback must not run at all — the sweep already sufficed");
        assert_eq!(
            peers.len(),
            8,
            "all 8 live entries must survive — none may be cut down to the low-water mark"
        );
        for i in 0..8u16 {
            let addr: SocketAddr = format!("127.0.0.1:{}", 30_000 + i).parse().expect("valid addr");
            assert!(peers.contains_key(&addr), "live entry {i} must not have been touched");
        }
    }
}
