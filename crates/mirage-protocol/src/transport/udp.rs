//! UDP transport — one peer's datagrams, over either of two backends.
//!
//! [`UdpPeerSocket`] gives the protocol code above it (the V9 datagram
//! handshake, `MirageCoreUdpTunnel`) a uniform `send`/`recv` pair for one
//! peer. What carries those datagrams underneath is a choice of two, and
//! **which one is correct depends on whether a perimeter face is involved**:
//!
//! - [`UdpBackend::Relayed`] — **the shape anything served through a face
//!   must use.** The face's own bound socket is the only public socket, for
//!   the whole life of every session; this `UdpPeerSocket` never binds one.
//!   Datagrams reach it over `mirage_core::local_dgram_endpoint`'s box-local,
//!   message-preserving channel, already demultiplexed per peer. Built with
//!   [`UdpPeerSocket::from_relay`].
//! - [`UdpBackend::Owned`] — a real bound `tokio::net::UdpSocket`, what both
//!   original constructors produce. Correct for a direct peer-to-peer bind
//!   with no NAT and no perimeter in between, which is also what the tests
//!   use on loopback.
//!
//! # The per-peer-ephemeral-port model, and why it is not the default
//!
//! This module was originally built around one shape: the server listens on
//! a fixed port, binds a fresh ephemeral socket per peer, replies from it,
//! and the client switches all further traffic to that new port.
//!
//! That model is kept only for the direct case above, and
//! [`UdpPeerSocket::bind_server_ephemeral`]'s own doc explains at length why
//! it must never serve a peer through a face: it reproduces a NAT defect this
//! codebase already found and fixed once (see `crate::camouflage::raw_udp`'s
//! module doc), and it is a perimeter violation on its own terms, since one
//! un-declared port per active peer is an unbounded set of ports outside any
//! face. `raw_udp` replaced it with one shared bound socket plus a dispatcher
//! demultiplexing on source address — which is exactly the shape `Relayed`
//! plugs into.
//!
//! Each `UdpPeerSocket` is then used directly by the protocol-specific tunnel
//! implementation (e.g. `MirageCoreUdpTunnel`).
//!
//! # A second backend: `Relayed`, additive to everything above
//!
//! Everything above this point describes `UdpBackend::Owned` — a real bound
//! `tokio::net::UdpSocket`, exactly what both existing constructors still
//! produce, unchanged. `bind_server_ephemeral`'s own doc explains why that
//! shape must never be used to serve a peer through a perimeter face: it is
//! a second OS-level bind per peer, which both reproduces a NAT defect this
//! codebase already fixed once (`crate::camouflage::raw_udp`'s module doc)
//! and is a perimeter violation on its own terms (an unbounded set of ports
//! outside any declared face).
//!
//! `UdpBackend::Relayed` is the fix: a `UdpPeerSocket` whose `send`/`recv`
//! cross `mirage_core::local_dgram_endpoint`'s box-local, message-preserving
//! channel instead of opening a second socket at all. See
//! [`UdpPeerSocket::from_relay`]'s own doc for exactly what "the peer's
//! address" means once datagrams arrive this way rather than off the wire.

use std::net::SocketAddr;
use std::sync::Arc;

use mirage_core::error::MirageError;
use mirage_core::local_dgram_endpoint::{DgramEnvelope, LocalDgramEndpoint, LocalDgramSocket};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, Mutex};

// ─────────────────────────────────────────────────────────────────────────────
// UdpPeerSocket
// ─────────────────────────────────────────────────────────────────────────────

/// Which real transport carries one peer's datagrams underneath
/// `UdpPeerSocket`'s uniform `send`/`recv` API.
///
/// An enum, not a trait object — the two shapes are structurally different
/// (one wraps a real socket, the other a box-local relay handle plus an
/// already-demultiplexed inbound channel) and there is no third shape
/// planned, so a `match` at each of the handful of call sites costs nothing
/// and keeps both arms visible at every one of them.
enum UdpBackend {
    /// What both existing constructors produce. Unchanged.
    Owned(UdpSocket),
    /// Every send/recv crosses the box-local relay instead of a real socket.
    /// See [`UdpPeerSocket::from_relay`] for the field meanings.
    Relayed {
        local: Arc<LocalDgramSocket>,
        face_port: u16,
        /// Fed by whatever demultiplexes the relay's own inbound traffic by
        /// source (in production, a per-UDP-face dispatcher; in a test, a
        /// stand-in that plays that dispatcher's part — see
        /// `tests/udp_relayed_backend.rs`). Carries the source
        /// `SocketAddr` alongside each payload, rather than bare bytes, so
        /// `recv`/`recv_handshake_from_host` can apply the SAME
        /// peer-address filter on this arm that the `Owned` arm applies —
        /// see `from_relay`'s doc for why that still matters even though
        /// the sender feeding this channel has typically already
        /// demultiplexed by peer once.
        ///
        /// Wrapped in a `tokio::sync::Mutex` rather than stored bare:
        /// `UdpPeerSocket::recv` takes `&self`, matching `Owned`'s existing
        /// signature exactly (this backend must not force it to `&mut
        /// self`, which would be a real behavioural change — see the U0
        /// brief), and an `mpsc::Receiver` otherwise needs `&mut self` to
        /// poll. The lock is held only for the duration of one receive.
        inbound: Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
    },
}

/// A UDP socket bound to a single remote peer.
///
/// `send` / `recv` operate on the peer's address only — datagrams from other
/// sources are silently discarded, providing protection against cross-talk on
/// ephemeral sockets (possible if NAT misbehaves). This still holds on the
/// `Relayed` backend — see [`UdpPeerSocket::from_relay`].
///
/// On the client side the socket is bound to `0.0.0.0:0` before the initial
/// handshake is sent, and `recv_handshake_from_host` adopts the reply's exact
/// source as the new `remote`.
///
/// On the server side there are two cases, and the difference matters:
///
/// - **Through a perimeter face** — the socket is `Relayed`, binds nothing,
///   and the face's own port carries every datagram of the session. This is
///   the only correct shape there.
/// - **Direct, no NAT and no perimeter** — `bind_server_ephemeral` binds
///   `0.0.0.0:0` for this peer and answers from it, which moves the session
///   onto that new port. Read that constructor's doc before using it: through
///   a face it is both a known NAT failure and a perimeter violation.
pub struct UdpPeerSocket {
    backend: UdpBackend,
    remote: SocketAddr,
}

impl UdpPeerSocket {
    // ── Constructors ──────────────────────────────────────────────────────────

    /// Client: bind a fresh ephemeral UDP socket pointed at `server_addr`.
    ///
    /// The caller sends the handshake datagram, then reads the server's reply
    /// with `recv_handshake_from_host` — it arrives from the server's new
    /// ephemeral port, not `server_addr`, and that method adopts the reply's
    /// exact source as the new `remote` (a plain `recv` would drop it, since
    /// it matches the full pre-handshake `SocketAddr`). The data loop that
    /// follows uses the strict `send` / `recv` pair as normal.
    pub async fn bind_client(server_addr: SocketAddr) -> Result<Self, MirageError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(MirageError::Io)?;
        Ok(Self { backend: UdpBackend::Owned(socket), remote: server_addr })
    }

    /// Server: bind a fresh ephemeral socket for one specific peer.
    ///
    /// # Do not use this to serve a peer through a perimeter face
    ///
    /// This constructor moves the whole session onto a new OS-assigned port:
    /// the server would answer from it, and — because `MirageCoreUdpTunnel`
    /// keeps the same `UdpPeerSocket` for the tunnel's entire life — every
    /// datagram of the data phase would leave from it too, not just the
    /// handshake reply.
    ///
    /// That design has already been tried here and already failed in the
    /// field. See `crate::camouflage::raw_udp`'s module doc: "the previous
    /// per-peer-ephemeral-socket design caused silent drops on residential RU
    /// NATs". A restricted-cone NAT keys its mapping to the 4-tuple the
    /// client's first packet created, toward the address it dialled; a reply
    /// from a different source port does not traverse it. `raw_udp` replaced
    /// this with one shared bound socket plus a dispatcher demultiplexing on
    /// the source address, which is the shape a face must use.
    ///
    /// It is also a perimeter violation on its own terms: one un-declared,
    /// un-admitted port per active peer is an unbounded set of ports outside
    /// any face, and no port may exist outside a face.
    ///
    /// Kept because it is the honest primitive for a direct peer-to-peer bind
    /// with no NAT and no perimeter in between, and because the tests use it
    /// on loopback, where neither concern applies. Anything served through a
    /// face must instead carry the session on the face's own bound socket.
    pub async fn bind_server_ephemeral(client_addr: SocketAddr) -> Result<Self, MirageError> {
        let socket = UdpSocket::bind("0.0.0.0:0").await.map_err(MirageError::Io)?;
        Ok(Self { backend: UdpBackend::Owned(socket), remote: client_addr })
    }

    /// Monitor-side constructor: a session whose bytes cross the box-local
    /// relay (`mirage_core::local_dgram_endpoint`) instead of a real socket —
    /// the "per-peer socket" [`crate::core::udp_handshake::run_server_handshake_v9_datagram`]'s
    /// own doc asks for, without a second OS bind. See this module's doc for
    /// why that second bind is forbidden in the first place.
    ///
    /// # What "the peer's address" means on this backend
    ///
    /// On [`UdpBackend::Owned`], `self.remote` and the address a `recv_from`
    /// returns are the SAME kind of fact: both are read straight off a live
    /// socket, in the same call, on the same machine that terminates the
    /// internet-facing connection. On this backend they are not — `peer`
    /// here is the real internet peer's address as *some other process*
    /// (the perimeter, owning the actual public socket) observed it on ITS
    /// `recv_from`, carried across the relay inside every `inbound` message
    /// and every outbound one this socket sends. This `UdpPeerSocket` itself
    /// never touches a socket the internet can reach — every fact this
    /// method's filtering relies on is secondhand, attested by whichever
    /// process fed `inbound`, not independently observed here.
    ///
    /// That is why `recv`/`recv_handshake_from_host` still filter against
    /// `self.remote` on this backend even though `inbound` is expected to
    /// already be scoped to one peer upstream (by construction of a
    /// per-peer channel) — the filter is what makes "the peer's address"
    /// mean the same thing on both backends: the attribution this method's
    /// own doc states, checked here, not merely assumed from how the
    /// channel was wired.
    ///
    /// `face_port` is plumbing for a box that runs more than one UDP face;
    /// at most one exists today, so most callers pass a fixed value.
    /// `inbound` carries `(source, payload)` pairs — see [`UdpBackend::Relayed`]'s
    /// own doc for why the source rides alongside the bytes rather than the
    /// plain `Vec<u8>` the U0 plan's own sketch used.
    pub fn from_relay(
        local: Arc<LocalDgramSocket>,
        face_port: u16,
        peer: SocketAddr,
        inbound: mpsc::Receiver<(SocketAddr, Vec<u8>)>,
    ) -> Self {
        Self {
            backend: UdpBackend::Relayed { local, face_port, inbound: Mutex::new(inbound) },
            remote: peer,
        }
    }

    // ── Peer address management ───────────────────────────────────────────────

    /// Update the remote peer address.
    ///
    /// Called by the client after receiving the server's confirm datagram from a
    /// new ephemeral port: `set_remote(server_confirm_src_addr)`.
    pub fn set_remote(&mut self, addr: SocketAddr) {
        self.remote = addr;
    }

    // ── I/O ──────────────────────────────────────────────────────────────────

    /// Send `data` to the remote peer.
    ///
    /// Returns the number of bytes sent.  For UDP, the entire datagram is either
    /// sent or an error is returned — partial writes do not occur. On the
    /// `Relayed` backend, "sent" means "handed whole to the box-local relay",
    /// which preserves the exact same all-or-nothing guarantee.
    pub async fn send(&self, data: &[u8]) -> Result<usize, MirageError> {
        match &self.backend {
            UdpBackend::Owned(socket) => socket
                .send_to(data, self.remote)
                .await
                .map_err(MirageError::Io),
            UdpBackend::Relayed { local, face_port, .. } => {
                let envelope = DgramEnvelope { face_port: *face_port, peer: self.remote };
                local
                    .send_envelope(envelope, data)
                    .await
                    .map_err(MirageError::Io)?;
                Ok(data.len())
            }
        }
    }

    /// Receive a datagram from the remote peer.
    ///
    /// Datagrams from addresses other than `self.remote` are silently dropped
    /// (loop continues reading) — this is a safety guard against accidental
    /// cross-talk that should not occur on a dedicated ephemeral socket, but
    /// can happen when NAT port-mapping is reused. The `Relayed` backend
    /// applies the identical filter against the source carried in `inbound`
    /// — see [`Self::from_relay`]'s doc for what that source attests to.
    ///
    /// Returns the number of bytes written into `buf`.  If `buf` is smaller
    /// than the datagram, the excess bytes are discarded (UDP semantics).
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, MirageError> {
        match &self.backend {
            UdpBackend::Owned(socket) => loop {
                let (n, from) = socket.recv_from(buf).await.map_err(MirageError::Io)?;
                if from == self.remote {
                    return Ok(n);
                }
                // Datagram from unexpected source — discard and keep waiting.
            },
            UdpBackend::Relayed { inbound, .. } => loop {
                let (from, data) = recv_relayed(inbound).await?;
                if from == self.remote {
                    return Ok(copy_truncated(&data, buf));
                }
                // Attributed to a different peer than this socket's remote —
                // discard and keep waiting, exactly like the `Owned` arm.
            },
        }
    }

    /// Receive a handshake-phase datagram from the expected peer **host**, on
    /// any source port, and adopt that exact source as the new `remote`.
    ///
    /// `recv` cannot observe the client-side leg of the handshake reply: it
    /// matches the full `SocketAddr`, and at the moment the client is waiting
    /// for the reply, `remote` still holds the address it dialled — the
    /// server's fixed rendezvous port, not the fresh ephemeral port it binds
    /// per peer and replies from (see the module docs). A reply from that new
    /// port would otherwise be silently dropped by `recv` and the ephemeral
    /// port could never be learned, since the reply is the only place it is
    /// carried.
    ///
    /// Matching on host (IP) rather than accepting from anywhere keeps the
    /// cross-talk guard meaningful: a datagram from a different machine is
    /// still discarded and the loop keeps waiting. Once the handshake
    /// completes and `remote` has been updated to the real ephemeral address,
    /// callers go back to the strict `recv` / `send` pair for the life of the
    /// session — this method is used only to receive the handshake reply.
    ///
    /// Returns the number of bytes written into `buf`, with the same
    /// truncation semantics as `recv`.
    pub async fn recv_handshake_from_host(&mut self, buf: &mut [u8]) -> Result<usize, MirageError> {
        let expected_host = self.remote.ip();
        match &mut self.backend {
            UdpBackend::Owned(socket) => loop {
                let (n, from) = socket.recv_from(buf).await.map_err(MirageError::Io)?;
                if from.ip() == expected_host {
                    self.remote = from;
                    return Ok(n);
                }
                // Datagram from an unexpected host — discard and keep waiting.
            },
            UdpBackend::Relayed { inbound, .. } => loop {
                let (from, data) = recv_relayed(inbound).await?;
                if from.ip() == expected_host {
                    self.remote = from;
                    return Ok(copy_truncated(&data, buf));
                }
                // Datagram from an unexpected host — discard and keep waiting.
            },
        }
    }

    // ── Address accessors ─────────────────────────────────────────────────────

    /// Return the local socket address (OS-assigned ephemeral port after bind).
    ///
    /// On the `Relayed` backend this reports the relay's own bound local
    /// endpoint when that endpoint is itself a `SocketAddr` (the Windows
    /// loopback-UDP arm of `mirage_core::local_dgram_endpoint`) — honest,
    /// since that IS where this handle's bytes physically originate, and
    /// harmless to report, since nothing in `run_server_handshake_v9_datagram`
    /// / `MirageCoreUdpTunnel` reads it. When the relay's local endpoint is a
    /// unix-domain path instead, there is no `SocketAddr` to report at all,
    /// and this returns an explicit `Unsupported` error naming the path
    /// rather than fabricating one.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        match &self.backend {
            UdpBackend::Owned(socket) => socket.local_addr(),
            UdpBackend::Relayed { local, .. } => match local.local_endpoint() {
                LocalDgramEndpoint::UdpLoopback(addr) => Ok(*addr),
                LocalDgramEndpoint::UnixDgram(path) => Err(std::io::Error::new(
                    std::io::ErrorKind::Unsupported,
                    format!(
                        "this UdpPeerSocket is backed by the box-local relay bound at unix path \
                         {} — it has no OS-level UDP SocketAddr to report",
                        path.display()
                    ),
                )),
            },
        }
    }

    /// Return the current remote peer address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote
    }
}

/// Pull the next `(source, payload)` pair off a `Relayed` backend's inbound
/// channel, or fail loudly if the channel has closed.
///
/// A closed channel means whatever fed it (the relay-side dispatcher) tore
/// this peer's session down — the `Relayed` counterpart of the `Owned` arm's
/// socket simply returning an I/O error, so both arms surface a session
/// failure as `MirageError::Io` rather than one of them hanging forever.
async fn recv_relayed(
    inbound: &Mutex<mpsc::Receiver<(SocketAddr, Vec<u8>)>>,
) -> Result<(SocketAddr, Vec<u8>), MirageError> {
    let mut guard = inbound.lock().await;
    guard.recv().await.ok_or_else(|| {
        MirageError::Io(std::io::Error::new(
            std::io::ErrorKind::ConnectionAborted,
            "relayed UdpPeerSocket: the local relay's inbound channel closed — the peer's \
             session ended",
        ))
    })
}

/// Copy `data` into `buf`, discarding any excess — the same truncation
/// semantics a real `UdpSocket::recv_from` applies when `buf` is smaller
/// than the datagram it read. Returns the number of bytes copied.
fn copy_truncated(data: &[u8], buf: &mut [u8]) -> usize {
    let n = data.len().min(buf.len());
    buf[..n].copy_from_slice(&data[..n]);
    n
}
