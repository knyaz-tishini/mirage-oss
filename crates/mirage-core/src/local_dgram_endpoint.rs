//! A box-local, message-preserving channel — the datagram counterpart to
//! [`crate::local_endpoint`].
//!
//! # Why this is a second module rather than a third arm of `LocalChannel`
//!
//! Every socket [`crate::local_endpoint::LocalChannel`] already knows is a
//! byte stream (`AF_UNIX SOCK_STREAM` on unix, loopback TCP on Windows).
//! `core::udp_handshake` and `core::udp_tunnel` (in `mirage-protocol`) operate
//! on whole datagrams end to end — one `send`/`recv` call maps to exactly one
//! datagram, never to N bytes of a stream — so splicing a UDP-carried session
//! through a stream socket would mean re-framing it on the way in and
//! de-framing it on the way out, for a wire that is already message-shaped.
//! `AF_UNIX SOCK_DGRAM` and loopback UDP already preserve one write == one
//! message natively; this module exists to use that property rather than
//! discard it.
//!
//! # The rule this module enforces, same as its sibling's
//!
//! ```text
//! #[cfg(unix)]    -> AF_UNIX SOCK_DGRAM at a path under /run/mirage
//! #[cfg(windows)] -> UDP on 127.0.0.1
//! ```
//!
//! Chosen by `cfg`, never by configuration — see
//! [`crate::local_endpoint`]'s own module doc for why a runtime switch is the
//! wrong shape. Loopback UDP is the honest analogue here, not loopback TCP:
//! both a unix datagram socket and a UDP socket already preserve message
//! boundaries, so the Windows arm is not the compromise
//! [`crate::local_endpoint::LocalEndpoint::Tcp`] makes for a byte-stream
//! channel — it is the SAME semantics as the unix arm, on a platform whose
//! `AF_UNIX` support (added in Windows 1809) is stream-only.
//!
//! # Permissions and grant machinery: reused, not reinvented
//!
//! [`LocalDgramChannel`] resolves its allowed peer exactly the way
//! [`crate::local_endpoint::LocalChannel`] does — one call to
//! [`crate::local_endpoint::resolve_account`], one
//! [`crate::local_endpoint::BindPlan`] from
//! [`crate::local_endpoint::plan_from_resolution`], the same directory-mode /
//! socket-mode constants, the same `chown`-before-`chmod` ordering, re-applied
//! on every boot. See that module's doc for why (`plan_from_resolution`'s own
//! comment: two lookups could disagree, and a socket chowned to one account
//! while the allowlist admits another fails in the most confusing direction
//! there is).
//!
//! # What this does NOT get, stated as an open gap rather than hidden
//!
//! [`crate::local_endpoint::LocalListener::accept`] authenticates a stream
//! peer twice: `SO_PEERCRED` at accept time, then a check of the peer's
//! running image. Both are PER-CONNECTION facts a connected stream socket
//! carries. A bound `SOCK_DGRAM` socket has no accept step and no
//! per-message credential the way `tokio::net::UnixDatagram` exposes it
//! today — Linux can attach sender credentials to a datagram via
//! `SCM_CREDENTIALS`/`SO_PASSCRED`, but that is ancillary-data plumbing
//! tokio's `UnixDatagram` does not wrap, and would need a raw `recvmsg` via
//! `socket2`/`libc` to reach.
//!
//! **This module relies on the filesystem grant alone** — directory mode
//! `0710`/`0700`, socket mode `0660`/`0600`, group ownership, the same
//! [`crate::local_endpoint::BindPlan`] every stream channel already leans on
//! as ITS primary gate too. That is a real, if weaker, guarantee than the
//! stream channels' belt-and-suspenders per-message identity check, and it is
//! named here as an honest, UNCLOSED gap rather than silently matched to the
//! stronger model. Closing it (a `socket2`-based `recvmsg` with
//! `SO_PASSCRED` wrapped in a small helper here) is an open question in
//! `docs/mirage/plans/udp-front-door-u0-2026-09-05.md` §3.4 / "Open
//! questions" #1 — not resolved by this module.
//!
//! # Message boundaries survive end to end, by construction
//!
//! [`DgramEnvelope::encode`] refuses (loudly, naming both the attempted size
//! and the ceiling) to build a datagram whose payload exceeds
//! [`MAX_DGRAM_PAYLOAD_LEN`], BEFORE a single byte reaches the socket. Every
//! writer that goes through [`LocalDgramSocket::send_envelope`] therefore
//! never produces a wire datagram wider than [`MAX_DGRAM_WIRE_LEN`], which is
//! exactly the buffer [`LocalDgramSocket::recv_envelope`] allocates to read
//! one — so nothing this module writes can ever be truncated by something
//! else this module reads. A message that arrived via some OTHER writer
//! entirely (outside this module's own gate) and exceeded that ceiling would
//! be silently shortened by the underlying datagram socket the way any
//! oversized datagram is; that residual case is the same shape as the
//! `SO_PASSCRED` gap above — a fact about a box-local channel's ONLY writer
//! being trusted to use this module's own API, not a hole this module leaves
//! open in its own read path.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use crate::local_endpoint::{plan_from_resolution, resolve_account, BindPlan, PERIMETER_ACCOUNT};
#[cfg(unix)]
use crate::local_endpoint::chown_to_group;

// ── Socket paths ─────────────────────────────────────────────────────────

/// The monitor's fixed rendezvous socket for relayed UDP-face traffic.
///
/// Deliberately in the SAME directory as
/// [`crate::local_endpoint::LocalChannel::MonitorWireSplice`]'s `wire.sock`
/// (`/run/mirage/monitor/`) rather than a directory of its own: both sockets
/// admit the identical peer (the perimeter's account) with the identical
/// grant, so re-applying that grant from a second bind is idempotent, not a
/// second, possibly-disagreeing manager of the directory — see
/// [`LocalDgramChannel::peer_account`].
const MONITOR_WIRE_DGRAM_SOCK: &str = "/run/mirage/monitor/wire-dgram.sock";

/// The perimeter's fixed rendezvous socket for the same relay, the other
/// direction.
///
/// In `/run/mirage/perimeter/`, alongside
/// [`crate::local_endpoint::LocalChannel::PerimeterQuery`]'s `query.sock`.
/// The monitor is the only writer here and the monitor is root, so — exactly
/// as `PerimeterQuery`'s own doc states — no group grant is needed in this
/// direction: root traverses filesystem permissions regardless
/// (`CAP_DAC_OVERRIDE`).
const PERIMETER_WIRE_DGRAM_SOCK: &str = "/run/mirage/perimeter/wire-dgram.sock";

/// The node's fixed rendezvous socket for relayed UDP-face chain traffic. The
/// perimeter writes here.
///
/// Deliberately in the SAME directory as
/// [`crate::local_endpoint::LocalChannel::NodeChainSplice`]'s `chain.sock`
/// (`/run/mirage/node/`) rather than a directory of its own: both sockets
/// admit the identical peer (the perimeter's account) with the identical
/// grant, so re-applying that grant from a second bind is idempotent, not a
/// second, possibly-disagreeing manager of the directory — see
/// [`LocalDgramChannel::peer_account`].
const NODE_CHAIN_DGRAM_SOCK: &str = "/run/mirage/node/chain-dgram.sock";

/// The perimeter's fixed rendezvous socket for the same relay, the other
/// direction — node-bound UDP-face chain traffic. The node writes here.
///
/// In `/run/mirage/perimeter/`, alongside
/// [`crate::local_endpoint::LocalChannel::PerimeterQuery`]'s `query.sock` and
/// this module's own [`PERIMETER_WIRE_DGRAM_SOCK`]. The node is the only
/// writer here and the node is root today, so — exactly as
/// [`PERIMETER_WIRE_DGRAM_SOCK`]'s own doc states for the monitor — no group
/// grant is needed in this direction: root traverses filesystem permissions
/// regardless (`CAP_DAC_OVERRIDE`).
const PERIMETER_NODE_CHAIN_DGRAM_SOCK: &str = "/run/mirage/perimeter/node-chain-dgram.sock";

/// The edge unit's fixed rendezvous socket for relayed UDP-face chain
/// traffic. The perimeter writes here — the `NODE_CHAIN_DGRAM_SOCK`
/// sibling for a box that runs no `mirage-node` at all
/// (`docs/mirage/plans/2026-09-24-edge-as-entry.md`, "Perimeter face
/// target and capsule change", UDP symmetry).
///
/// Deliberately in the SAME directory as
/// [`crate::local_endpoint::LocalChannel::EdgeChainSplice`]'s `chain.sock`
/// (`/run/mirage/edge/`) rather than a directory of its own — same
/// reasoning as [`NODE_CHAIN_DGRAM_SOCK`]'s own doc: both sockets admit
/// the identical peer (the perimeter's account) with the identical grant.
const EDGE_CHAIN_DGRAM_SOCK: &str = "/run/mirage/edge/chain-dgram.sock";

/// The perimeter's fixed rendezvous socket for the same relay, the other
/// direction — edge-bound UDP-face chain traffic. The edge unit writes
/// here.
///
/// In `/run/mirage/perimeter/`, alongside this module's own
/// [`PERIMETER_WIRE_DGRAM_SOCK`] and [`PERIMETER_NODE_CHAIN_DGRAM_SOCK`].
/// The edge unit is the only writer here and — like the node today — runs
/// as root, so no group grant is needed in this direction: root traverses
/// filesystem permissions regardless (`CAP_DAC_OVERRIDE`), the same
/// reasoning [`PERIMETER_NODE_CHAIN_DGRAM_SOCK`]'s own doc states.
const PERIMETER_EDGE_CHAIN_DGRAM_SOCK: &str = "/run/mirage/perimeter/edge-chain-dgram.sock";

// ── Sizing ───────────────────────────────────────────────────────────────

/// The largest payload one [`DgramEnvelope`] may carry.
///
/// Matches `MirageCoreUdpTunnel::MAX_DGRAM`
/// (`mirage-protocol/src/core/udp_tunnel.rs`) — this channel exists to carry
/// whatever that tunnel (or the handshake ahead of it) emits, and a ceiling
/// narrower than the tunnel's own would truncate traffic the tunnel itself
/// considers valid.
pub const MAX_DGRAM_PAYLOAD_LEN: usize = 65_536;

/// The largest whole wire datagram this channel ever writes or reads:
/// [`DgramEnvelope::HEADER_LEN`] plus [`MAX_DGRAM_PAYLOAD_LEN`]. This is the
/// exact size of the buffer [`LocalDgramSocket::recv_envelope`] allocates —
/// see the module doc's "message boundaries survive end to end" section for
/// why that is enough to make truncation structurally impossible for any
/// datagram this module itself wrote.
pub const MAX_DGRAM_WIRE_LEN: usize = DgramEnvelope::HEADER_LEN + MAX_DGRAM_PAYLOAD_LEN;

// ── Envelope ─────────────────────────────────────────────────────────────

/// One relayed datagram, either direction.
///
/// Both directions share this shape because direction is implicit in which
/// bound socket a message arrives on (the perimeter's, or the monitor's):
/// perimeter->monitor says "this came from"; monitor->perimeter says "send
/// this to". Unsigned, deliberately — the socket's own filesystem grant is
/// the authentication, not a byte on the wire, matching
/// [`crate::perimeter_preamble::PerimeterPreamble`]'s own reasoning for being
/// unsigned while carried over an already-authenticated channel.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DgramEnvelope {
    /// Which UDP face this datagram belongs to. Plumbing for when a box runs
    /// more than one UDP face; today there is at most one, so every caller
    /// in this crate is free to pass a fixed value.
    pub face_port: u16,
    /// The real internet peer. On the perimeter's own public socket this is
    /// literally the source address a `recv_from` returned; carried through
    /// the relay so the monitor (which never touches that socket) can still
    /// name whose session this is.
    pub peer: SocketAddr,
}

impl DgramEnvelope {
    /// `1` (address-family tag) + `16` (address bytes, IPv4 padded) + `2`
    /// (port) + `2` (face_port).
    pub const HEADER_LEN: usize = 21;

    const TAG_V4: u8 = 4;
    const TAG_V6: u8 = 6;

    /// Encode `self` and `payload` into one wire datagram: `[header]
    /// [payload]`. No length prefix — the underlying transport already
    /// preserves the message boundary, so the payload is simply "everything
    /// after the fixed-width header".
    ///
    /// Refuses, naming both sizes, a `payload` that would make the wire
    /// datagram exceed [`MAX_DGRAM_WIRE_LEN`] — see the module doc for why
    /// this is the gate that keeps this channel's own reads truncation-free.
    pub fn encode(&self, payload: &[u8]) -> io::Result<Vec<u8>> {
        if payload.len() > MAX_DGRAM_PAYLOAD_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "datagram payload of {} bytes exceeds this channel's {}-byte payload ceiling \
                     ({}-byte header + {}-byte payload = {}-byte wire maximum) — refused before \
                     sending, not truncated",
                    payload.len(),
                    MAX_DGRAM_PAYLOAD_LEN,
                    Self::HEADER_LEN,
                    MAX_DGRAM_PAYLOAD_LEN,
                    MAX_DGRAM_WIRE_LEN
                ),
            ));
        }

        let mut out = Vec::with_capacity(Self::HEADER_LEN + payload.len());
        match self.peer.ip() {
            IpAddr::V4(v4) => {
                out.push(Self::TAG_V4);
                out.extend_from_slice(&v4.octets());
                out.extend_from_slice(&[0u8; 12]);
            }
            IpAddr::V6(v6) => {
                out.push(Self::TAG_V6);
                out.extend_from_slice(&v6.octets());
            }
        }
        out.extend_from_slice(&self.peer.port().to_be_bytes());
        out.extend_from_slice(&self.face_port.to_be_bytes());
        out.extend_from_slice(payload);
        Ok(out)
    }

    /// Split one wire datagram back into its envelope and a borrowed
    /// payload slice.
    pub fn decode(bytes: &[u8]) -> io::Result<(Self, &[u8])> {
        if bytes.len() < Self::HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "datagram of {} bytes is shorter than DgramEnvelope's {}-byte header",
                    bytes.len(),
                    Self::HEADER_LEN
                ),
            ));
        }
        let tag = bytes[0];
        let addr_bytes = &bytes[1..17];
        let port = u16::from_be_bytes([bytes[17], bytes[18]]);
        let face_port = u16::from_be_bytes([bytes[19], bytes[20]]);
        let ip = match tag {
            Self::TAG_V4 => {
                IpAddr::V4(Ipv4Addr::new(addr_bytes[0], addr_bytes[1], addr_bytes[2], addr_bytes[3]))
            }
            Self::TAG_V6 => {
                let octets: [u8; 16] = addr_bytes
                    .try_into()
                    .expect("addr_bytes is a fixed 16-byte slice of a bounds-checked buffer");
                IpAddr::V6(Ipv6Addr::from(octets))
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown address-family tag 0x{other:02x} in DgramEnvelope header"),
                ))
            }
        };
        Ok((
            DgramEnvelope { face_port, peer: SocketAddr::new(ip, port) },
            &bytes[Self::HEADER_LEN..],
        ))
    }
}

// ── Endpoint ─────────────────────────────────────────────────────────────

/// A box-local, message-preserving address, already resolved for this
/// compilation target — the datagram counterpart to
/// [`crate::local_endpoint::LocalEndpoint`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LocalDgramEndpoint {
    /// `AF_UNIX SOCK_DGRAM` at a filesystem path.
    UnixDgram(PathBuf),
    /// Loopback UDP. Windows only in fleet code; also what a unix test uses
    /// when it wants to exercise the other arm.
    UdpLoopback(SocketAddr),
}

impl std::fmt::Display for LocalDgramEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LocalDgramEndpoint::UnixDgram(p) => write!(f, "unix-dgram:{}", p.display()),
            LocalDgramEndpoint::UdpLoopback(a) => write!(f, "udp:{a}"),
        }
    }
}

// ── Channels ─────────────────────────────────────────────────────────────

/// One named relay pair's endpoint — the datagram counterpart to
/// [`crate::local_endpoint::LocalChannel`], scoped to the U0 UDP front-door
/// splice specifically (see the module doc). Every other caller binds an
/// arbitrary [`LocalDgramEndpoint`] directly via [`LocalDgramSocket::bind`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LocalDgramChannel {
    /// monitor's own bound socket. The perimeter writes here.
    MonitorWireDgram,
    /// perimeter's own bound socket. The monitor writes here.
    PerimeterWireDgram,
    /// node's own bound socket. The perimeter writes here.
    NodeChainDgram,
    /// perimeter's own bound socket, for node-bound traffic. The node writes
    /// here.
    PerimeterNodeChainDgram,
    /// the edge unit's own bound socket. The perimeter writes here — the
    /// [`Self::NodeChainDgram`] sibling for a box that runs no `mirage-node`
    /// at all.
    EdgeChainDgram,
    /// perimeter's own bound socket, for edge-bound traffic. The edge unit
    /// writes here.
    PerimeterEdgeChainDgram,
}

impl LocalDgramChannel {
    pub const ALL: [LocalDgramChannel; 6] = [
        LocalDgramChannel::MonitorWireDgram,
        LocalDgramChannel::PerimeterWireDgram,
        LocalDgramChannel::NodeChainDgram,
        LocalDgramChannel::PerimeterNodeChainDgram,
        LocalDgramChannel::EdgeChainDgram,
        LocalDgramChannel::PerimeterEdgeChainDgram,
    ];

    /// Stable short name for logs.
    pub const fn label(self) -> &'static str {
        match self {
            LocalDgramChannel::MonitorWireDgram => "monitor-wire-dgram",
            LocalDgramChannel::PerimeterWireDgram => "perimeter-wire-dgram",
            LocalDgramChannel::NodeChainDgram => "node-chain-dgram",
            LocalDgramChannel::PerimeterNodeChainDgram => "perimeter-node-chain-dgram",
            LocalDgramChannel::EdgeChainDgram => "edge-chain-dgram",
            LocalDgramChannel::PerimeterEdgeChainDgram => "perimeter-edge-chain-dgram",
        }
    }

    /// Filesystem path on the unix arm. Present on every target, matching
    /// [`crate::local_endpoint::LocalChannel::unix_path`]'s own reasoning.
    pub const fn unix_path(self) -> &'static str {
        match self {
            LocalDgramChannel::MonitorWireDgram => MONITOR_WIRE_DGRAM_SOCK,
            LocalDgramChannel::PerimeterWireDgram => PERIMETER_WIRE_DGRAM_SOCK,
            LocalDgramChannel::NodeChainDgram => NODE_CHAIN_DGRAM_SOCK,
            LocalDgramChannel::PerimeterNodeChainDgram => PERIMETER_NODE_CHAIN_DGRAM_SOCK,
            LocalDgramChannel::EdgeChainDgram => EDGE_CHAIN_DGRAM_SOCK,
            LocalDgramChannel::PerimeterEdgeChainDgram => PERIMETER_EDGE_CHAIN_DGRAM_SOCK,
        }
    }

    /// The loopback port this channel uses on Windows. Distinct from every
    /// port [`crate::local_endpoint::LocalChannel::loopback_addr`] already
    /// hands out (19444/19446/19470-19474, 19479-19480).
    pub fn loopback_addr(self) -> SocketAddr {
        let port = match self {
            LocalDgramChannel::MonitorWireDgram => 19475,
            LocalDgramChannel::PerimeterWireDgram => 19476,
            LocalDgramChannel::NodeChainDgram => 19477,
            LocalDgramChannel::PerimeterNodeChainDgram => 19478,
            LocalDgramChannel::EdgeChainDgram => 19481,
            LocalDgramChannel::PerimeterEdgeChainDgram => 19482,
        };
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// The channel on the other end of this relay pair. Each side binds its
    /// own name and sends to its counterpart's — see the module doc's "two
    /// fixed sockets" framing.
    pub const fn counterpart(self) -> LocalDgramChannel {
        match self {
            LocalDgramChannel::MonitorWireDgram => LocalDgramChannel::PerimeterWireDgram,
            LocalDgramChannel::PerimeterWireDgram => LocalDgramChannel::MonitorWireDgram,
            LocalDgramChannel::NodeChainDgram => LocalDgramChannel::PerimeterNodeChainDgram,
            LocalDgramChannel::PerimeterNodeChainDgram => LocalDgramChannel::NodeChainDgram,
            LocalDgramChannel::EdgeChainDgram => LocalDgramChannel::PerimeterEdgeChainDgram,
            LocalDgramChannel::PerimeterEdgeChainDgram => LocalDgramChannel::EdgeChainDgram,
        }
    }

    /// The directory whose mode and group this channel's bind manages.
    ///
    /// Every channel's directory is ALSO managed by an existing
    /// [`crate::local_endpoint::LocalChannel`] (`MonitorWireSplice` /
    /// `PerimeterQuery` / `NodeChainSplice` / `EdgeChainSplice` respectively)
    /// — see [`MONITOR_WIRE_DGRAM_SOCK`]'s, [`PERIMETER_WIRE_DGRAM_SOCK`]'s,
    /// [`NODE_CHAIN_DGRAM_SOCK`]'s, [`PERIMETER_NODE_CHAIN_DGRAM_SOCK`]'s,
    /// [`EDGE_CHAIN_DGRAM_SOCK`]'s and [`PERIMETER_EDGE_CHAIN_DGRAM_SOCK`]'s
    /// own docs for why re-applying that SAME grant a second time is
    /// idempotent rather than a conflicting second manager.
    pub fn managed_dir(self) -> Option<&'static Path> {
        if crate::local_endpoint::runtime_root().is_some() {
            let resolved = crate::local_endpoint::resolve_unix_path(self.unix_path());
            return crate::local_endpoint::managed_parent(self.label(), &resolved);
        }
        Path::new(self.unix_path()).parent()
    }

    /// The account admitted beyond root, by name, or `None` for root-only.
    pub const fn peer_account(self) -> Option<&'static str> {
        match self {
            // The perimeter writes every session's datagrams into the
            // monitor over this socket — same grant as
            // `LocalChannel::MonitorWireSplice`, and for the same reason.
            LocalDgramChannel::MonitorWireDgram => Some(PERIMETER_ACCOUNT),
            // The monitor writes here, and the monitor is root today — root
            // traverses filesystem permissions regardless, so no grant is
            // needed, exactly as `LocalChannel::PerimeterQuery` reasons.
            LocalDgramChannel::PerimeterWireDgram => None,
            // The perimeter writes every session's datagrams into the node
            // over this socket — same grant as
            // `LocalChannel::NodeChainSplice`, and for the same reason.
            LocalDgramChannel::NodeChainDgram => Some(PERIMETER_ACCOUNT),
            // The node writes here, and the node is root today — root
            // traverses filesystem permissions regardless, so no grant is
            // needed, exactly as `LocalChannel::PerimeterQuery` reasons for
            // the monitor's own write side above.
            LocalDgramChannel::PerimeterNodeChainDgram => None,
            // The perimeter writes every session's datagrams into the edge
            // unit over this socket — same grant as
            // `LocalChannel::EdgeChainSplice`, and for the same reason.
            LocalDgramChannel::EdgeChainDgram => Some(PERIMETER_ACCOUNT),
            // The edge unit writes here, and — like the node today — runs as
            // root, so root traverses filesystem permissions regardless, no
            // grant needed, exactly as `LocalChannel::PerimeterQuery`
            // reasons for the monitor's and node's own write sides above.
            LocalDgramChannel::PerimeterEdgeChainDgram => None,
        }
    }

    /// The address this channel resolves to on THIS build.
    pub fn endpoint(self) -> LocalDgramEndpoint {
        #[cfg(unix)]
        {
            LocalDgramEndpoint::UnixDgram(crate::local_endpoint::resolve_unix_path(self.unix_path()))
        }
        #[cfg(not(unix))]
        {
            LocalDgramEndpoint::UdpLoopback(self.loopback_addr())
        }
    }

    /// Resolve this channel's account and build its bind plan — identical
    /// method to [`crate::local_endpoint::LocalChannel::plan`].
    pub fn plan(self) -> BindPlan {
        plan_from_resolution(resolve_account(self.peer_account()))
    }

    /// Bind this channel's own fixed rendezvous socket, wired to send toward
    /// its [`Self::counterpart`]. See the module doc.
    pub async fn bind(self) -> io::Result<LocalDgramSocket> {
        let plan = self.plan();
        tracing::info!(
            channel = self.label(),
            endpoint = %self.endpoint(),
            resolutions = ?plan.resolutions,
            admitted_uids = ?plan.admitted_uids,
            "[local-dgram] binding a box-local datagram channel"
        );
        LocalDgramSocket::bind(self.endpoint(), self.counterpart().endpoint(), self.managed_dir(), &plan)
            .await
    }
}

// ── Socket ───────────────────────────────────────────────────────────────

enum DgramSocketInner {
    #[cfg(unix)]
    Unix(tokio::net::UnixDatagram),
    Udp(tokio::net::UdpSocket),
}

/// A bound, message-preserving box-local socket: one fixed local address,
/// one fixed peer address it always sends toward.
///
/// Unlike [`crate::local_endpoint::LocalListener`], there is no accept step
/// and no per-connection [`crate::local_endpoint::PeerIdentity`] — a bound
/// `SOCK_DGRAM` socket has no connection to accept. See the module doc's
/// "what this does NOT get" section for what that costs.
pub struct LocalDgramSocket {
    inner: DgramSocketInner,
    local: LocalDgramEndpoint,
    peer: LocalDgramEndpoint,
}

impl LocalDgramSocket {
    /// Bind `local`, applying `plan`'s grant on the unix arm, and remember
    /// `peer` as the fixed target every [`Self::send_envelope`] call writes
    /// to.
    ///
    /// `local` and `peer` must be the SAME kind (both
    /// [`LocalDgramEndpoint::UnixDgram`] or both
    /// [`LocalDgramEndpoint::UdpLoopback`]) — a channel relays to its own
    /// kind, never across the unix/loopback boundary, matching
    /// [`LocalDgramChannel::endpoint`] always resolving both ends of a pair
    /// on the same build.
    pub async fn bind(
        local: LocalDgramEndpoint,
        peer: LocalDgramEndpoint,
        managed_dir: Option<&Path>,
        plan: &BindPlan,
    ) -> io::Result<Self> {
        match (&local, &peer) {
            (LocalDgramEndpoint::UnixDgram(path), LocalDgramEndpoint::UnixDgram(_)) => {
                #[cfg(unix)]
                {
                    let inner = bind_unix_dgram(path, managed_dir, plan).await?;
                    Ok(Self { inner: DgramSocketInner::Unix(inner), local, peer })
                }
                #[cfg(not(unix))]
                {
                    let _ = (managed_dir, plan);
                    Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("unix-domain datagram socket {} cannot be bound on this target", path.display()),
                    ))
                }
            }
            (LocalDgramEndpoint::UdpLoopback(addr), LocalDgramEndpoint::UdpLoopback(_)) => {
                let inner = tokio::net::UdpSocket::bind(addr).await?;
                // `addr` may have asked for port `0` (OS-assigned) — report
                // what the OS actually gave back, not the literal request,
                // so `Self::local_endpoint` is never stale. A caller that
                // bound port `0` and then reads `local_endpoint()` to hand
                // its real address to a counterpart (see
                // `Self::set_peer_endpoint`'s own doc) would otherwise be
                // handed back the unusable `port 0` it asked with.
                let real_local = inner.local_addr()?;
                Ok(Self { inner: DgramSocketInner::Udp(inner), local: LocalDgramEndpoint::UdpLoopback(real_local), peer })
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "local endpoint {local} and peer endpoint {peer} are different kinds — a \
                     relay pair must be both unix-domain or both loopback UDP"
                ),
            )),
        }
    }

    /// Where this socket is bound.
    pub fn local_endpoint(&self) -> &LocalDgramEndpoint {
        &self.local
    }

    /// Where this socket sends every [`Self::send_envelope`] call.
    pub fn peer_endpoint(&self) -> &LocalDgramEndpoint {
        &self.peer
    }

    /// Update the fixed peer [`Self::send_envelope`] targets.
    ///
    /// Needed when a bound endpoint's real address is only knowable after
    /// the OS assigns it — the loopback-UDP arm binding port `0` — so a
    /// caller can bind both ends, read each one's real
    /// [`Self::local_endpoint`], and only then pair them. The two named
    /// [`LocalDgramChannel`]s never need this in production (their ports are
    /// fixed, never OS-assigned); it exists for exactly this test-and-tool
    /// shape, and this module's own test suite uses it rather than a
    /// parallel, private way of doing the same thing.
    pub fn set_peer_endpoint(&mut self, peer: LocalDgramEndpoint) {
        self.peer = peer;
    }

    /// Encode `envelope` and `payload` and send the resulting datagram to
    /// [`Self::peer_endpoint`] in one write.
    pub async fn send_envelope(&self, envelope: DgramEnvelope, payload: &[u8]) -> io::Result<()> {
        let wire = envelope.encode(payload)?;
        match (&self.inner, &self.peer) {
            #[cfg(unix)]
            (DgramSocketInner::Unix(sock), LocalDgramEndpoint::UnixDgram(path)) => {
                sock.send_to(&wire, path).await?;
            }
            (DgramSocketInner::Udp(sock), LocalDgramEndpoint::UdpLoopback(addr)) => {
                sock.send_to(&wire, *addr).await?;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "this socket's transport and its own recorded peer endpoint are different \
                     kinds — this cannot happen through Self::bind and indicates a logic error",
                ))
            }
        }
        Ok(())
    }

    /// Read exactly one whole datagram and decode it into an envelope plus
    /// its owned payload.
    ///
    /// Allocates a [`MAX_DGRAM_WIRE_LEN`]-byte buffer per call — see the
    /// module doc for why a datagram written by [`Self::send_envelope`] can
    /// never exceed that size, and therefore can never be truncated here.
    pub async fn recv_envelope(&self) -> io::Result<(DgramEnvelope, Vec<u8>)> {
        let mut buf = [0u8; MAX_DGRAM_WIRE_LEN];
        let n = match &self.inner {
            #[cfg(unix)]
            DgramSocketInner::Unix(sock) => sock.recv_from(&mut buf).await?.0,
            DgramSocketInner::Udp(sock) => sock.recv_from(&mut buf).await?.0,
        };
        let (envelope, payload) = DgramEnvelope::decode(&buf[..n])?;
        Ok((envelope, payload.to_vec()))
    }
}

#[cfg(unix)]
async fn bind_unix_dgram(
    path: &Path,
    managed_dir: Option<&Path>,
    plan: &BindPlan,
) -> io::Result<tokio::net::UnixDatagram> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(dir) = managed_dir {
        std::fs::create_dir_all(dir)?;
        // chown BEFORE chmod — see `crate::local_endpoint::bind_unix`'s own
        // comment: the reverse order briefly presents a group-accessible
        // directory still owned by the wrong group.
        chown_to_group(dir, plan.grant.gid)?;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(plan.grant.dir_mode))?;
    }

    remove_stale_dgram_socket_if_dead(path).await?;
    let socket = tokio::net::UnixDatagram::bind(path)?;
    chown_to_group(path, plan.grant.gid)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(plan.grant.socket_mode))?;
    Ok(socket)
}

/// Remove a `SOCK_DGRAM` socket file left by an unclean exit — but only
/// after evidence nothing owns it.
///
/// This is the datagram analogue of
/// `crate::local_endpoint::remove_stale_socket_if_dead`, and cannot reuse it
/// verbatim: that function proves liveness by CONNECTING, which only works
/// because a `SOCK_STREAM` listener refuses a connect when nothing is
/// accepting. A bound `SOCK_DGRAM` socket has no accept queue to refuse
/// into, so this instead sends a zero-length probe datagram at the path and
/// reads the kernel's answer:
///
/// - `ConnectionRefused` is the one answer that specifically proves the
///   path is a dead socket file with nothing bound behind it — safe to
///   unlink.
/// - Anything else (including success) is treated as "cannot prove this is
///   dead" and leaves the file alone, so a live listener is never stolen
///   from — the same fail-closed direction the stream version takes, even
///   though the evidence it can gather here is weaker.
#[cfg(unix)]
async fn remove_stale_dgram_socket_if_dead(path: &Path) -> io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let probe = tokio::net::UnixDatagram::unbound()?;
    match probe.send_to(&[], path).await {
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => std::fs::remove_file(path),
        Err(e) => Err(e),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            format!("a live listener already owns {}", path.display()),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_endpoint::{AccountResolution, RUN_ROOT};

    // ── DgramEnvelope encode/decode ──────────────────────────────────────

    #[test]
    fn an_ipv4_envelope_round_trips_through_encode_and_decode() {
        let envelope = DgramEnvelope {
            face_port: 4433,
            peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7)), 51820),
        };
        let payload = b"a v4 payload";
        let wire = envelope.encode(payload).expect("encode must succeed");
        let (decoded, decoded_payload) = DgramEnvelope::decode(&wire).expect("decode must succeed");
        assert_eq!(decoded, envelope);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn an_ipv6_envelope_round_trips_through_encode_and_decode() {
        let envelope = DgramEnvelope {
            face_port: 22,
            peer: SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
                443,
            ),
        };
        let payload = b"a v6 payload, a little longer";
        let wire = envelope.encode(payload).expect("encode must succeed");
        let (decoded, decoded_payload) = DgramEnvelope::decode(&wire).expect("decode must succeed");
        assert_eq!(decoded, envelope);
        assert_eq!(decoded_payload, payload);
    }

    #[test]
    fn a_zero_length_payload_round_trips_too() {
        let envelope = DgramEnvelope {
            face_port: 0,
            peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
        };
        let wire = envelope.encode(&[]).expect("encode must succeed");
        assert_eq!(wire.len(), DgramEnvelope::HEADER_LEN);
        let (decoded, decoded_payload) = DgramEnvelope::decode(&wire).expect("decode must succeed");
        assert_eq!(decoded, envelope);
        assert!(decoded_payload.is_empty());
    }

    #[test]
    fn encode_refuses_a_payload_over_the_ceiling_naming_both_sizes() {
        let envelope = DgramEnvelope { face_port: 1, peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1) };
        let oversized = vec![0u8; MAX_DGRAM_PAYLOAD_LEN + 1];
        let err = envelope.encode(&oversized).expect_err("must refuse an oversized payload");
        let msg = err.to_string();
        assert!(msg.contains(&(MAX_DGRAM_PAYLOAD_LEN + 1).to_string()), "{msg}");
        assert!(msg.contains(&MAX_DGRAM_PAYLOAD_LEN.to_string()), "{msg}");
    }

    #[test]
    fn decode_refuses_a_datagram_shorter_than_the_header() {
        let err = DgramEnvelope::decode(&[1, 2, 3]).expect_err("must refuse a short buffer");
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    // ── LocalDgramSocket: real bind + loopback exchange ──────────────────

    /// A private scratch directory for the unix arm — `/run/mirage` is not
    /// writable in a test, matching `local_endpoint.rs`'s own `scratch()`.
    #[cfg(unix)]
    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("mirage-local-dgram-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        dir
    }

    fn root_only_plan() -> BindPlan {
        plan_from_resolution(AccountResolution::NotRequested)
    }

    /// The current target's own arm of [`LocalDgramEndpoint`] at a fresh,
    /// unused address — unix scratch path on unix, loopback UDP port 0 (OS
    /// assigned) everywhere else. One test body exercises whichever arm this
    /// build actually has, exactly as `LocalChannel::endpoint()`'s own doc
    /// argues for.
    #[cfg(unix)]
    fn fresh_endpoint(name: &str) -> LocalDgramEndpoint {
        LocalDgramEndpoint::UnixDgram(scratch(name).join("ch.sock"))
    }
    #[cfg(not(unix))]
    fn fresh_endpoint(_name: &str) -> LocalDgramEndpoint {
        LocalDgramEndpoint::UdpLoopback(SocketAddr::from(([127, 0, 0, 1], 0)))
    }

    #[cfg(unix)]
    fn managed_dir_for(ep: &LocalDgramEndpoint) -> Option<PathBuf> {
        match ep {
            LocalDgramEndpoint::UnixDgram(path) => path.parent().map(Path::to_path_buf),
            LocalDgramEndpoint::UdpLoopback(_) => None,
        }
    }
    #[cfg(not(unix))]
    fn managed_dir_for(_ep: &LocalDgramEndpoint) -> Option<PathBuf> {
        None
    }

    /// Bind two sockets pointed at each other, on whichever arm this target
    /// builds.
    async fn paired_sockets(name: &str) -> (LocalDgramSocket, LocalDgramSocket) {
        let ep_a = fresh_endpoint(&format!("{name}-a"));
        let ep_b = fresh_endpoint(&format!("{name}-b"));
        let plan = root_only_plan();

        let mut a = LocalDgramSocket::bind(ep_a.clone(), ep_b.clone(), managed_dir_for(&ep_a).as_deref(), &plan)
            .await
            .expect("bind socket a");
        // On the loopback-UDP arm, port 0 is OS-assigned at bind time, so
        // socket b must target the address the OS actually gave socket a —
        // `Self::bind` already reports that real address through
        // `local_endpoint()` (not the literal port-0 request), via the same
        // public API an external caller would use (no private-field access
        // here on purpose, so this helper stays an honest example of this
        // module's own public API).
        let ep_a_real = a.local_endpoint().clone();
        let b = LocalDgramSocket::bind(
            ep_b.clone(),
            ep_a_real.clone(),
            managed_dir_for(&ep_b).as_deref(),
            &plan,
        )
        .await
        .expect("bind socket b");
        // Symmetrically, point a back at b's OS-assigned address.
        a.set_peer_endpoint(b.local_endpoint().clone());
        (a, b)
    }

    #[tokio::test]
    async fn three_datagrams_of_different_sizes_round_trip_with_boundaries_intact() {
        let (a, b) = paired_sockets("roundtrip").await;

        let msgs: [&[u8]; 3] = [b"", b"short", b"a somewhat longer datagram body than the others"];
        for (i, m) in msgs.iter().enumerate() {
            let envelope = DgramEnvelope {
                face_port: 100 + i as u16,
                peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000 + i as u16),
            };
            a.send_envelope(envelope, m).await.expect("send must succeed");
        }

        for i in 0..3 {
            let (envelope, payload) = b.recv_envelope().await.expect("recv must succeed");
            assert_eq!(envelope.face_port, 100 + i as u16);
            assert_eq!(payload, msgs[i], "message {i} must arrive with its exact boundary intact");
        }
    }

    #[tokio::test]
    async fn a_datagram_over_the_channel_ceiling_is_refused_loudly_not_truncated() {
        let (a, _b) = paired_sockets("oversize").await;
        let oversized = vec![7u8; MAX_DGRAM_PAYLOAD_LEN + 1];
        let envelope =
            DgramEnvelope { face_port: 1, peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1) };
        let err = a
            .send_envelope(envelope, &oversized)
            .await
            .expect_err("an oversized payload must be refused, not silently shortened");
        let msg = err.to_string();
        assert!(msg.contains(&(MAX_DGRAM_PAYLOAD_LEN + 1).to_string()), "{msg}");
        assert!(msg.contains(&MAX_DGRAM_PAYLOAD_LEN.to_string()), "{msg}");
    }

    // ── Node pair: same mechanism, same proof ────────────────────────────

    #[tokio::test]
    async fn the_node_pair_round_trips_datagrams_of_different_sizes_with_boundaries_intact() {
        let (a, b) = paired_sockets("node-chain-roundtrip").await;

        let msgs: [&[u8]; 3] = [b"", b"short", b"a somewhat longer datagram body than the others"];
        for (i, m) in msgs.iter().enumerate() {
            let envelope = DgramEnvelope {
                face_port: 200 + i as u16,
                peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50000 + i as u16),
            };
            a.send_envelope(envelope, m).await.expect("send must succeed");
        }

        for i in 0..3 {
            let (envelope, payload) = b.recv_envelope().await.expect("recv must succeed");
            assert_eq!(envelope.face_port, 200 + i as u16);
            assert_eq!(payload, msgs[i], "message {i} must arrive with its exact boundary intact");
        }
    }

    #[tokio::test]
    async fn the_node_pair_refuses_an_oversized_datagram_loudly_not_truncated() {
        let (a, _b) = paired_sockets("node-chain-oversize").await;
        let oversized = vec![9u8; MAX_DGRAM_PAYLOAD_LEN + 1];
        let envelope =
            DgramEnvelope { face_port: 2, peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2) };
        let err = a
            .send_envelope(envelope, &oversized)
            .await
            .expect_err("an oversized payload must be refused, not silently shortened");
        let msg = err.to_string();
        assert!(msg.contains(&(MAX_DGRAM_PAYLOAD_LEN + 1).to_string()), "{msg}");
        assert!(msg.contains(&MAX_DGRAM_PAYLOAD_LEN.to_string()), "{msg}");
    }

    // ── Edge pair: same mechanism, same proof — the `NodeChainDgram`/
    //    `PerimeterNodeChainDgram` pair's own sibling for a box that runs no
    //    `mirage-node` at all ────────────────────────────────────────────

    #[tokio::test]
    async fn the_edge_pair_round_trips_datagrams_of_different_sizes_with_boundaries_intact() {
        let (a, b) = paired_sockets("edge-chain-roundtrip").await;

        let msgs: [&[u8]; 3] = [b"", b"short", b"a somewhat longer datagram body than the others"];
        for (i, m) in msgs.iter().enumerate() {
            let envelope = DgramEnvelope {
                face_port: 300 + i as u16,
                peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 60000 + i as u16),
            };
            a.send_envelope(envelope, m).await.expect("send must succeed");
        }

        for i in 0..3 {
            let (envelope, payload) = b.recv_envelope().await.expect("recv must succeed");
            assert_eq!(envelope.face_port, 300 + i as u16);
            assert_eq!(payload, msgs[i], "message {i} must arrive with its exact boundary intact");
        }
    }

    #[tokio::test]
    async fn the_edge_pair_refuses_an_oversized_datagram_loudly_not_truncated() {
        let (a, _b) = paired_sockets("edge-chain-oversize").await;
        let oversized = vec![11u8; MAX_DGRAM_PAYLOAD_LEN + 1];
        let envelope =
            DgramEnvelope { face_port: 3, peer: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3) };
        let err = a
            .send_envelope(envelope, &oversized)
            .await
            .expect_err("an oversized payload must be refused, not silently shortened");
        let msg = err.to_string();
        assert!(msg.contains(&(MAX_DGRAM_PAYLOAD_LEN + 1).to_string()), "{msg}");
        assert!(msg.contains(&MAX_DGRAM_PAYLOAD_LEN.to_string()), "{msg}");
    }

    // ── The table's invariants, mirroring local_endpoint.rs's own ────────

    #[test]
    fn the_two_channels_do_not_share_a_path() {
        assert_ne!(
            LocalDgramChannel::MonitorWireDgram.unix_path(),
            LocalDgramChannel::PerimeterWireDgram.unix_path()
        );
        assert_ne!(
            LocalDgramChannel::MonitorWireDgram.loopback_addr(),
            LocalDgramChannel::PerimeterWireDgram.loopback_addr()
        );
    }

    #[test]
    fn all_six_channels_have_pairwise_distinct_paths_and_addresses() {
        for (i, a) in LocalDgramChannel::ALL.iter().enumerate() {
            for (j, b) in LocalDgramChannel::ALL.iter().enumerate() {
                if i == j {
                    continue;
                }
                assert_ne!(
                    a.unix_path(),
                    b.unix_path(),
                    "{} and {} share a unix path",
                    a.label(),
                    b.label()
                );
                assert_ne!(
                    a.loopback_addr(),
                    b.loopback_addr(),
                    "{} and {} share a loopback address",
                    a.label(),
                    b.label()
                );
            }
        }
    }

    #[test]
    fn the_two_channels_do_not_collide_with_any_stream_channel_port() {
        for dgram in LocalDgramChannel::ALL {
            for stream in crate::local_endpoint::LocalChannel::ALL {
                assert_ne!(
                    dgram.loopback_addr(),
                    stream.loopback_addr(),
                    "{} collides with stream channel {}",
                    dgram.label(),
                    stream.label()
                );
            }
        }
    }

    #[test]
    fn each_channel_is_the_others_counterpart() {
        assert_eq!(LocalDgramChannel::MonitorWireDgram.counterpart(), LocalDgramChannel::PerimeterWireDgram);
        assert_eq!(LocalDgramChannel::PerimeterWireDgram.counterpart(), LocalDgramChannel::MonitorWireDgram);
        assert_eq!(LocalDgramChannel::NodeChainDgram.counterpart(), LocalDgramChannel::PerimeterNodeChainDgram);
        assert_eq!(LocalDgramChannel::PerimeterNodeChainDgram.counterpart(), LocalDgramChannel::NodeChainDgram);
        assert_eq!(LocalDgramChannel::EdgeChainDgram.counterpart(), LocalDgramChannel::PerimeterEdgeChainDgram);
        assert_eq!(LocalDgramChannel::PerimeterEdgeChainDgram.counterpart(), LocalDgramChannel::EdgeChainDgram);
    }

    #[test]
    fn every_socket_lives_under_the_run_root() {
        for ch in LocalDgramChannel::ALL {
            assert!(ch.unix_path().starts_with(RUN_ROOT), "{} escapes {RUN_ROOT}", ch.label());
        }
    }

    #[test]
    fn the_monitor_side_grants_the_perimeter_account_and_the_perimeter_side_grants_nobody() {
        // The asymmetry is deliberate — see `LocalDgramChannel::peer_account`'s
        // own doc, mirroring `LocalChannel::MonitorWireSplice` /
        // `LocalChannel::PerimeterQuery` exactly.
        assert_eq!(LocalDgramChannel::MonitorWireDgram.peer_account(), Some(PERIMETER_ACCOUNT));
        assert_eq!(LocalDgramChannel::PerimeterWireDgram.peer_account(), None);
    }

    #[test]
    fn the_node_side_grants_the_perimeter_account_and_the_perimeter_side_grants_nobody() {
        // Same asymmetry, same reason, the node pair's own direction — see
        // `LocalDgramChannel::peer_account`'s doc, mirroring
        // `LocalChannel::NodeChainSplice` / `LocalChannel::PerimeterQuery`.
        assert_eq!(LocalDgramChannel::NodeChainDgram.peer_account(), Some(PERIMETER_ACCOUNT));
        assert_eq!(LocalDgramChannel::PerimeterNodeChainDgram.peer_account(), None);
    }

    #[test]
    fn the_edge_side_grants_the_perimeter_account_and_the_perimeter_side_grants_nobody() {
        // Same asymmetry, same reason, the edge pair's own direction — see
        // `LocalDgramChannel::peer_account`'s doc, mirroring
        // `LocalChannel::EdgeChainSplice` / `LocalChannel::PerimeterQuery`.
        assert_eq!(LocalDgramChannel::EdgeChainDgram.peer_account(), Some(PERIMETER_ACCOUNT));
        assert_eq!(LocalDgramChannel::PerimeterEdgeChainDgram.peer_account(), None);
    }

    #[test]
    fn all_six_channels_appear_in_all() {
        assert_eq!(LocalDgramChannel::ALL.len(), 6);
        for ch in [
            LocalDgramChannel::MonitorWireDgram,
            LocalDgramChannel::PerimeterWireDgram,
            LocalDgramChannel::NodeChainDgram,
            LocalDgramChannel::PerimeterNodeChainDgram,
            LocalDgramChannel::EdgeChainDgram,
            LocalDgramChannel::PerimeterEdgeChainDgram,
        ] {
            assert!(LocalDgramChannel::ALL.contains(&ch), "{} missing from ALL", ch.label());
        }
        // Labels stay distinct too, matching one-name-per-channel.
        let mut labels: Vec<&str> = LocalDgramChannel::ALL.iter().map(|c| c.label()).collect();
        labels.sort_unstable();
        labels.dedup();
        assert_eq!(labels.len(), 6, "labels must be pairwise distinct");
    }
}
