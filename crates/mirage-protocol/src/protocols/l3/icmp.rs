//! Camouflage layer — ICMP tunnel transport.
//!
//! Carries Mirage payload inside ICMP Echo Request / Echo Reply packets.
//! Uses raw sockets — requires administrator / root privileges.
//!
//! ## Why ICMP?
//!
//! ICMP is used for `ping`.  It is protocol number 1 on IPv4 and has no port
//! numbers.  Port-based firewalls and DPI that only inspect TCP/UDP pass ICMP
//! Echo packets without inspection.  This makes ICMP one of the last reliable
//! transports in extremely restricted network environments.
//!
//! ## Wire format
//!
//! Each Mirage chunk is carried in one ICMP Echo datagram:
//!
//! ```text
//! [1B type][1B code][2B checksum][2B identifier][2B sequence][payload…]
//! ```
//!
//! * **type**: 8 (Echo Request, client→server) / 0 (Echo Reply, server→client)
//! * **code**: 0
//! * **checksum**: ones-complement sum of the entire packet (computed here)
//! * **identifier**: 16-bit session tag (`IcmpCamouflage::identifier`).
//!   Allows a single machine to run multiple ICMP tunnels simultaneously,
//!   analogous to port numbers in TCP/UDP.
//! * **sequence**: per-direction 16-bit counter; rolls over at 65535.
//! * **payload**: raw Mirage bytes (up to `mtu` bytes per packet).
//!
//! ## Bandwidth
//!
//! Low bandwidth like DNS tunnel.  MTU defaults to 1400 bytes, giving
//! ~1400 bytes of usable payload per round trip.  Far higher than DNS tunnel
//! but still unreliable (packets can be dropped / reordered).  The Mirage AEAD
//! framing layer handles retransmission.
//!
//! ## Privileges
//!
//! * **Linux/macOS**: process must run as root or have `CAP_NET_RAW`.
//! * **Windows**: process must run as Administrator.  Raw sockets on Windows
//!   additionally require that the socket is bound to the local interface
//!   address (not `0.0.0.0`) for *sending*; we bind to `0.0.0.0` for the
//!   receive socket and let the OS pick the source interface for sends.
//!
//! ## Async I/O
//!
//! Raw sockets do not integrate with Tokio's reactor directly.  We use
//! `tokio::task::spawn_blocking` inside `IcmpRawSocket` to avoid blocking the
//! async executor, and bridge the result via `tokio::sync::oneshot` channels.
//! The `IcmpTunnelAdapter` wraps these calls and implements `AsyncRead` +
//! `AsyncWrite` via an internal byte buffer populated by a background receive
//! task.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use async_trait::async_trait;
use mirage_core::error::MirageError;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;

use crate::camouflage::{private, UdpCamouflageLayer};

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

/// Default maximum payload bytes per ICMP datagram.
pub const DEFAULT_ICMP_MTU: usize = 1400;

/// ICMP Echo Request type byte.
const ICMP_ECHO_REQUEST: u8 = 8;

/// ICMP Echo Reply type byte.
const ICMP_ECHO_REPLY: u8 = 0;

/// ICMP code for Echo Request / Reply.
const ICMP_CODE: u8 = 0;

/// Receive buffer size for raw socket reads (IP header + ICMP + payload).
const RECV_BUF_SIZE: usize = 65536;

/// Receive timeout for the blocking recv call inside `spawn_blocking`.
const RECV_TIMEOUT: Duration = Duration::from_millis(200);

// ─────────────────────────────────────────────────────────────────────────────
// Public configuration
// ─────────────────────────────────────────────────────────────────────────────

/// ICMP tunnel transport-level camouflage.
///
/// Carries Mirage payload inside ICMP Echo Request / Echo Reply packets.
/// No port numbers are used — bypasses port-based firewalls completely.
///
/// # Privileges
///
/// Raw sockets require administrator / root privileges.
pub struct IcmpCamouflage {
    /// Server IP address.
    ///
    /// * **Client side**: address to send Echo Requests to.
    /// * **Server side**: unused (the server listens on all interfaces).
    pub peer_addr: IpAddr,
    /// 16-bit session identifier — distinguishes this tunnel from other ICMP
    /// traffic on the same machine (analogous to a port number).
    pub identifier: u16,
    /// Maximum payload bytes per ICMP datagram (default: `DEFAULT_ICMP_MTU`).
    pub mtu: usize,
}

impl IcmpCamouflage {
    /// Create a new `IcmpCamouflage`.
    ///
    /// * `peer_addr` — server IP (used by the client side).
    /// * `identifier` — 16-bit session tag; pick a random value per tunnel.
    /// * `mtu` — max payload bytes per ICMP packet (`DEFAULT_ICMP_MTU` = 1400).
    pub fn new(peer_addr: IpAddr, identifier: u16, mtu: usize) -> Self {
        Self { peer_addr, identifier, mtu }
    }
}

impl private::Sealed for IcmpCamouflage {}

#[async_trait]
impl UdpCamouflageLayer for IcmpCamouflage {
    type Stream = IcmpTunnelAdapter;

    /// Client: open a raw ICMP socket and return an adapter that sends Echo
    /// Requests to [`Self::peer_addr`].
    ///
    /// `server_addr` is the entrance the dialer resolved. ICMP has no port,
    /// and that address is not the host the echo is sent to: the configured
    /// peer is. `sni` is unused — ICMP has no TLS outer layer.
    async fn connect_client(
        &self,
        _server_addr: SocketAddr,
        _sni: &str,
    ) -> Result<IcmpTunnelAdapter, MirageError> {
        let target_ip = self.peer_addr;
        let sock = IcmpRawSocket::open().map_err(MirageError::Io)?;
        Ok(IcmpTunnelAdapter::new(
            sock,
            target_ip,
            self.identifier,
            self.mtu,
            Role::Client,
            Vec::new(),
        ))
    }

    /// Server: open a raw ICMP socket and wait for the first Echo Request
    /// bearing our `identifier`.  Returns the adapter and the client IP.
    ///
    /// Blocks (inside `spawn_blocking`) until a matching packet arrives.
    async fn accept_server(
        &self,
        _bind_addr: SocketAddr,
    ) -> Result<(IcmpTunnelAdapter, SocketAddr), MirageError> {
        let identifier = self.identifier;
        let mtu = self.mtu;

        // The first Echo Request also carries the client's first payload.
        // The same socket has to stay open: the client writes the rest of the
        // stream immediately, and a new socket would drop those datagrams.
        let (client_ip, first_payload, sock) = tokio::task::spawn_blocking(
            move || -> io::Result<(IpAddr, Vec<u8>, IcmpRawSocket)> {
                let sock = IcmpRawSocket::open()?;
                sock.set_read_timeout(Some(Duration::from_secs(60)))?;
                let mut buf = vec![0u8; RECV_BUF_SIZE];
                loop {
                    let (n, src) = match sock.recv_from(&mut buf) {
                        Ok(r) => r,
                        Err(e)
                            if e.kind() == io::ErrorKind::TimedOut
                                || e.kind() == io::ErrorKind::WouldBlock
                                || e.kind() == io::ErrorKind::Interrupted =>
                        {
                            continue;
                        }
                        Err(e) => return Err(e),
                    };
                    if let Some(pkt) = strip_ip_header(&buf[..n]) {
                        if parse_identifier(pkt) == Some(identifier)
                            && pkt.first().copied() == Some(ICMP_ECHO_REQUEST)
                        {
                            return Ok((src, parse_payload(pkt).to_vec(), sock));
                        }
                    }
                }
            },
        )
        .await
        .map_err(|e| MirageError::Io(io::Error::other(e.to_string())))?
        .map_err(MirageError::Io)?;

        let client_socket_addr = SocketAddr::new(client_ip, 0);
        // Seed the first payload before the reader starts. `blocking_lock`
        // here panics: this function runs on a runtime worker, and tokio
        // refuses to block that thread. The panic kills the door task, so
        // the client waits out its read and reports zero bytes.
        let adapter = IcmpTunnelAdapter::new(
            sock,
            client_ip,
            identifier,
            mtu,
            Role::Server,
            first_payload,
        );
        Ok((adapter, client_socket_addr))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Role
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Sends Echo Requests, receives Echo Replies.
    Client,
    /// Receives Echo Requests, sends Echo Replies.
    Server,
}

// ─────────────────────────────────────────────────────────────────────────────
// IcmpRawSocket — thin wrapper around a blocking raw socket
// ─────────────────────────────────────────────────────────────────────────────

/// Blocking raw ICMPv4 socket.
///
/// All methods are synchronous — intended for use inside `spawn_blocking`.
struct IcmpRawSocket {
    inner: socket2::Socket,
}

impl IcmpRawSocket {
    /// Open a raw ICMPv4 socket.
    ///
    /// Requires administrator / root privileges.
    fn open() -> io::Result<Self> {
        use socket2::{Domain, Protocol, Type};
        let sock = socket2::Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4))?;
        sock.set_read_timeout(Some(RECV_TIMEOUT))?;
        Ok(Self { inner: sock })
    }

    /// Send raw ICMP bytes to `dest`.
    /// Receive raw bytes (IP header + ICMP) from any sender.
    ///
    /// Returns `(bytes_received, source_ip)`.
    fn recv_from(&self, buf: &mut [u8]) -> io::Result<(usize, IpAddr)> {
        // Safety: MaybeUninit<u8> has the same layout as u8; socket2 fills the
        // slice before returning, so we never read uninitialised memory.
        let uninit_buf: &mut [std::mem::MaybeUninit<u8>] = unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast(), buf.len())
        };
        let mut slices = [socket2::MaybeUninitSlice::new(uninit_buf)];
        let (n, _flags, src_addr) = self.inner.recv_from_vectored(&mut slices)?;
        let ip = src_addr
            .as_socket_ipv4()
            .map(|a| IpAddr::V4(*a.ip()))
            .ok_or_else(|| io::Error::other("icmp: non-IPv4 source address"))?;
        Ok((n, ip))
    }

    fn set_read_timeout(&self, dur: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(dur)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// ICMP packet helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Build an ICMP Echo Request or Echo Reply packet with `payload`.
///
/// Returns the complete ICMP datagram (no IP header — the OS adds that).
fn build_icmp_packet(
    icmp_type: u8,
    identifier: u16,
    sequence: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = 8 + payload.len();
    let mut pkt = vec![0u8; total];
    pkt[0] = icmp_type;
    pkt[1] = ICMP_CODE;
    // checksum at [2..4] — filled below
    pkt[4..6].copy_from_slice(&identifier.to_be_bytes());
    pkt[6..8].copy_from_slice(&sequence.to_be_bytes());
    pkt[8..].copy_from_slice(payload);

    let cksum = icmp_checksum(&pkt);
    pkt[2..4].copy_from_slice(&cksum.to_be_bytes());
    pkt
}

/// Compute the ICMP ones-complement checksum of `data`.
///
/// RFC 792: the checksum is the 16-bit ones-complement of the ones-complement
/// sum of the ICMP message.
fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u32::from(u16::from_be_bytes([data[i], data[i + 1]]));
        i += 2;
    }
    if i < data.len() {
        sum += u32::from(data[i]) << 8;
    }
    // Fold 32-bit sum into 16 bits.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// On Linux and macOS the raw socket delivers the full IP packet including the
/// 20-byte IPv4 header.  On Windows, raw ICMP sockets typically deliver only
/// the ICMP portion.  We strip the IP header if we detect one (first nibble = 4,
/// IHL ≥ 20).
fn strip_ip_header(buf: &[u8]) -> Option<&[u8]> {
    if buf.is_empty() {
        return None;
    }
    let version = buf[0] >> 4;
    if version == 4 {
        let ihl = ((buf[0] & 0x0F) as usize) * 4;
        if ihl >= 20 && buf.len() > ihl {
            return Some(&buf[ihl..]);
        }
    }
    // No IP header present (Windows raw ICMP, or already stripped).
    if !buf.is_empty() {
        Some(buf)
    } else {
        None
    }
}

/// Extract the ICMP identifier field from a raw ICMP packet (bytes 4..6).
fn parse_identifier(icmp: &[u8]) -> Option<u16> {
    if icmp.len() < 8 {
        return None;
    }
    Some(u16::from_be_bytes([icmp[4], icmp[5]]))
}

/// Extract the ICMP type byte.
fn parse_type(icmp: &[u8]) -> Option<u8> {
    icmp.first().copied()
}

/// Extract payload from an ICMP Echo packet (bytes 8..).
fn parse_payload(icmp: &[u8]) -> &[u8] {
    if icmp.len() > 8 {
        &icmp[8..]
    } else {
        &[]
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// IcmpTunnelAdapter — AsyncRead + AsyncWrite
// ─────────────────────────────────────────────────────────────────────────────

/// Byte-stream adapter for ICMP tunnel transport.
///
/// Implements `AsyncRead` + `AsyncWrite` + `Unpin` so that the Mirage ECDH
/// handshake and AEAD framing can run on top unchanged.
///
/// ## Write side
///
/// `poll_write` sends one ICMP Echo Request (client) or Echo Reply (server)
/// per call.  Large writes are chunked by the Mirage framing layer above.
///
/// ## Read side
///
/// Uses a background receive loop (`spawn_blocking`) that polls the raw socket
/// with a short timeout, filters by `identifier` and type, and pushes payload
/// bytes into a shared buffer.  `poll_read` drains from that buffer.
pub struct IcmpTunnelAdapter {
    /// Shared receive buffer populated by the background recv task.
    recv_buf: Arc<Mutex<Vec<u8>>>,
    /// Peer IP address.
    peer: IpAddr,
    /// Session identifier.
    identifier: u16,
    /// Role (Client or Server).
    role: Role,
    /// Per-direction send sequence counter.
    send_seq: Arc<AtomicU16>,
    /// Maximum payload bytes per datagram.
    mtu: usize,
    /// Raw socket for sending (wrapped in Arc for sharing with background task).
    send_sock: Arc<IcmpSendSocket>,
}

/// Send-only wrapper around `IcmpRawSocket` that is `Send + Sync`.
struct IcmpSendSocket(socket2::Socket);

// Safety: we access the socket only through `&self` send_to.
unsafe impl Send for IcmpSendSocket {}
unsafe impl Sync for IcmpSendSocket {}

impl IcmpSendSocket {
    fn send_to(&self, data: &[u8], dest: IpAddr) -> io::Result<usize> {
        let addr: socket2::SockAddr = SocketAddr::new(dest, 0).into();
        self.0.send_to(data, &addr)
    }
}

/// Receive-only wrapper for use inside `spawn_blocking`.
struct IcmpRecvSocket(socket2::Socket);

unsafe impl Send for IcmpRecvSocket {}
unsafe impl Sync for IcmpRecvSocket {}

impl IcmpRecvSocket {
    fn recv_icmp(&self, buf: &mut [u8]) -> io::Result<(usize, IpAddr)> {
        // Safety: MaybeUninit<u8> has the same layout as u8.
        let uninit: &mut [std::mem::MaybeUninit<u8>] = unsafe {
            std::slice::from_raw_parts_mut(buf.as_mut_ptr().cast(), buf.len())
        };
        let mut slices = [socket2::MaybeUninitSlice::new(uninit)];
        let (n, _flags, src) = self.0.recv_from_vectored(&mut slices)?;
        let ip = src
            .as_socket_ipv4()
            .map(|a| IpAddr::V4(*a.ip()))
            .ok_or_else(|| io::Error::other("icmp: non-IPv4 source"))?;
        Ok((n, ip))
    }
}

impl IcmpTunnelAdapter {
    /// Create a new adapter and spawn the background receive task.
    fn new(
        sock: IcmpRawSocket,
        peer: IpAddr,
        identifier: u16,
        mtu: usize,
        role: Role,
        initial: Vec<u8>,
    ) -> Self {
        // Split the raw socket fd into a send socket and a recv socket.
        // socket2::Socket doesn't support try_clone on all platforms but we
        // work around this by opening two separate raw sockets.
        let send_raw = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::RAW,
            Some(socket2::Protocol::ICMPV4),
        )
        .expect("icmp: failed to open send socket — administrator privileges required");

        let recv_sock = IcmpRecvSocket(sock.inner);
        let send_sock = Arc::new(IcmpSendSocket(send_raw));
        // `initial` is the echo already taken off this socket. It has to be
        // queued before the reader starts, or the preamble's first byte is lost.
        let recv_buf: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(initial));

        // Expected ICMP type for incoming packets.
        let expected_type = match role {
            Role::Client => ICMP_ECHO_REPLY,
            Role::Server => ICMP_ECHO_REQUEST,
        };

        // Spawn background blocking task that feeds the recv_buf.
        let buf_clone = Arc::clone(&recv_buf);
        tokio::task::spawn_blocking(move || {
            let mut raw_buf = vec![0u8; RECV_BUF_SIZE];
            loop {
                match recv_sock.recv_icmp(&mut raw_buf) {
                    Err(e)
                        if e.kind() == io::ErrorKind::TimedOut
                            || e.kind() == io::ErrorKind::WouldBlock
                            || e.kind() == io::ErrorKind::Interrupted =>
                    {
                        // Timeout — loop again.
                        continue;
                    }
                    Err(_) => break, // Socket closed or fatal error.
                    Ok((n, _src)) => {
                        let pkt = &raw_buf[..n];
                        let icmp = match strip_ip_header(pkt) {
                            Some(i) => i,
                            None => continue,
                        };
                        // Filter by type and identifier.
                        if parse_type(icmp) != Some(expected_type) {
                            continue;
                        }
                        if parse_identifier(icmp) != Some(identifier) {
                            continue;
                        }
                        let payload = parse_payload(icmp);
                        if payload.is_empty() {
                            continue;
                        }
                        // Blocking lock — this is inside spawn_blocking, safe to block.
                        let mut guard = buf_clone.blocking_lock();
                        guard.extend_from_slice(payload);
                    }
                }
            }
        });

        Self {
            recv_buf,
            peer,
            identifier,
            role,
            send_seq: Arc::new(AtomicU16::new(0)),
            mtu,
            send_sock,
        }
    }

    /// Build and send one ICMP datagram with `payload`.
    fn send_packet(&self, payload: &[u8]) -> io::Result<()> {
        let seq = self.send_seq.fetch_add(1, Ordering::Relaxed);
        let icmp_type = match self.role {
            Role::Client => ICMP_ECHO_REQUEST,
            Role::Server => ICMP_ECHO_REPLY,
        };
        let pkt = build_icmp_packet(icmp_type, self.identifier, seq, payload);
        self.send_sock.send_to(&pkt, self.peer)?;
        Ok(())
    }
}

impl AsyncRead for IcmpTunnelAdapter {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // Try to drain from the shared buffer.
        match self.recv_buf.try_lock() {
            Ok(mut guard) => {
                if guard.is_empty() {
                    // Nothing yet — schedule a wakeup and return Pending.
                    let waker = cx.waker().clone();
                    drop(guard);
                    // Wake again shortly so we poll the buffer.
                    tokio::spawn(async move {
                        tokio::time::sleep(Duration::from_millis(5)).await;
                        waker.wake();
                    });
                    Poll::Pending
                } else {
                    let to_copy = guard.len().min(buf.remaining());
                    buf.put_slice(&guard[..to_copy]);
                    guard.drain(..to_copy);
                    Poll::Ready(Ok(()))
                }
            }
            Err(_) => {
                // Lock contended — retry later.
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }
}

impl AsyncWrite for IcmpTunnelAdapter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let chunk = if buf.len() > self.mtu { &buf[..self.mtu] } else { buf };
        match self.send_packet(chunk) {
            Ok(()) => Poll::Ready(Ok(chunk.len())),
            Err(e) => Poll::Ready(Err(e)),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Unpin for IcmpTunnelAdapter {}

// ─────────────────────────────────────────────────────────────────────────────
// Config re-exports
// ─────────────────────────────────────────────────────────────────────────────

/// Serialisable configuration for `IcmpCamouflage`.
///
/// This is embedded inside `CamouflageConfig::Icmp` and
/// `TransportCamouflage::Icmp` for persistence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IcmpConfig {
    /// Server IP address (used by the client; unused by the server).
    pub peer_addr: std::net::IpAddr,
    /// 16-bit session identifier — distinguishes tunnels on the same machine.
    pub identifier: u16,
    /// Max payload bytes per ICMP datagram (default: `DEFAULT_ICMP_MTU`).
    #[serde(default = "default_mtu")]
    pub mtu: usize,
}

fn default_mtu() -> usize {
    DEFAULT_ICMP_MTU
}

impl From<IcmpConfig> for IcmpCamouflage {
    fn from(cfg: IcmpConfig) -> Self {
        Self::new(cfg.peer_addr, cfg.identifier, cfg.mtu)
    }
}
