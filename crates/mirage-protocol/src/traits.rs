use std::net::SocketAddr;

use async_trait::async_trait;
use mirage_core::{
    config::{CamouflageMode, TcpProtocolId, TransportCamouflage, UdpProtocolId},
    error::MirageError,
};
use tokio::net::TcpStream;

/// Result of the server-side [`TcpProtocol::accept`] call.
pub enum AcceptResult {
    /// The incoming connection was authenticated — a tunnel is ready.
    Tunnel(Box<dyn Tunnel>),
    /// The connection does not belong to this protocol.
    ///
    /// The raw stream and the bytes that were already read are returned so a
    /// fallback handler can forward the connection to a camouflage backend
    /// (e.g. a real HTTPS server).
    Fallback(TcpStream, Vec<u8>),
}

/// Metadata attached to every tunnel.
#[derive(Debug, Clone)]
pub struct TransportInfo {
    /// Which wire protocol produced this tunnel.
    pub protocol_tcp: Option<TcpProtocolId>,
    /// Which wire protocol produced this tunnel (UDP side).
    pub protocol_udp: Option<UdpProtocolId>,
    /// Remote peer address.
    pub remote_addr: SocketAddr,
    /// Moment at which the handshake completed.
    pub established_at: std::time::Instant,
}

impl TransportInfo {
    /// Construct transport info from a TCP protocol.
    pub fn tcp(protocol: TcpProtocolId, remote_addr: SocketAddr) -> Self {
        Self {
            protocol_tcp: Some(protocol),
            protocol_udp: None,
            remote_addr,
            established_at: std::time::Instant::now(),
        }
    }

    /// Construct transport info from a UDP protocol.
    pub fn udp(protocol: UdpProtocolId, remote_addr: SocketAddr) -> Self {
        Self {
            protocol_tcp: None,
            protocol_udp: Some(protocol),
            remote_addr,
            established_at: std::time::Instant::now(),
        }
    }

    /// Construct transport info for a driver-managed TCP connection (no legacy ProtocolId).
    pub fn tcp_raw(remote_addr: SocketAddr) -> Self {
        Self {
            protocol_tcp: None,
            protocol_udp: None,
            remote_addr,
            established_at: std::time::Instant::now(),
        }
    }

    /// Construct transport info for a driver-managed UDP connection (no legacy ProtocolId).
    pub fn udp_raw(remote_addr: SocketAddr) -> Self {
        Self {
            protocol_tcp: None,
            protocol_udp: None,
            remote_addr,
            established_at: std::time::Instant::now(),
        }
    }
}

impl std::fmt::Display for TransportInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(t) = &self.protocol_tcp {
            write!(f, "{}", t)
        } else if let Some(u) = &self.protocol_udp {
            write!(f, "{}", u)
        } else {
            write!(f, "unknown")
        }
    }
}

/// A bidirectional, encrypted transport channel.
///
/// Both read and write operate on raw byte slices.  Higher-level framing
/// (application frames, multiplexing, etc.) is handled above this layer.
#[async_trait]
pub trait Tunnel: Send + Sync {
    /// Write all bytes in `data` through the tunnel.
    async fn send(&mut self, data: &[u8]) -> Result<(), MirageError>;

    /// Read up to `buf.len()` bytes from the tunnel into `buf`.
    ///
    /// Returns the number of bytes placed into `buf`.  A return value of `0`
    /// with a non-empty buffer indicates the tunnel was closed by the peer.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, MirageError>;

    /// Perform a graceful shutdown — flush pending data and close.
    async fn close(&mut self) -> Result<(), MirageError>;

    /// Immutable reference to the tunnel's transport metadata.
    fn transport_info(&self) -> &TransportInfo;

    /// Signal whether an active relay is in progress.
    ///
    /// Tunnel wrappers that inject synthetic traffic (e.g. cover-traffic) should
    /// override this method to suppress injection while `active` is `true`.
    /// The default implementation is a no-op; most tunnels do not need it.
    fn set_relay_active(&mut self, _active: bool) {}
}

/// A TCP protocol implementation capable of acting as both client and server.
///
/// TCP protocol implementors own their key material and any connection-independent
/// configuration.  Each call to [`connect`] or [`accept`] may spawn its own
/// state machine without shared mutable state.
#[async_trait]
pub trait TcpProtocol: Send + Sync {
    /// Open an outbound tunnel to `addr` over TCP.
    ///
    /// `server_pubkey` is the 32-byte X25519 public key of the remote node.
    /// `sni` is the TLS server-name indication string sent in the ClientHello
    /// (used by camouflage layers; ignored for raw Phase-1 Mirage).
    /// `camouflage` selects the frame-wrapping mode applied to outbound data.
    async fn connect(
        &self,
        addr: SocketAddr,
        server_pubkey: &[u8; 32],
        sni: &str,
        camouflage: CamouflageMode,
    ) -> Result<Box<dyn Tunnel>, MirageError>;

    /// Handle an inbound TCP connection.
    ///
    /// `stream` is the raw accepted TCP connection.  `peeked` contains bytes
    /// that were already read for protocol detection and must be prepended when
    /// processing the stream.
    async fn accept(
        &self,
        stream: TcpStream,
        peeked: &[u8],
    ) -> Result<AcceptResult, MirageError>;

    /// The [`TcpProtocolId`] this implementation handles.
    fn id(&self) -> TcpProtocolId;

    /// Whether this protocol is resistant to active probing by censors.
    ///
    /// Probe-resistant protocols return `AcceptResult::Fallback` for any
    /// connection that does not carry valid authentication material, making
    /// the server indistinguishable from a plain HTTPS server to an outside party.
    fn probe_resistant(&self) -> bool;

    /// Like [`connect`] but with an optional anonymous credential and an
    /// optional per-hop transport camouflage override attached.
    ///
    /// `hop_camouflage` — when `Some`, specifies the outer `TransportCamouflage`
    /// (TLS / WebSocket / Reality / …) that should be applied on the TCP
    /// connection for this hop.  [`EndpointProtocol`] overrides this method to
    /// build an effective [`MirageEndpointConfig`] with the camouflage set to
    /// the provided value before calling `run_client_tcp_v9`.  When `None` the
    /// camouflage already stored on the config is used (preserves existing
    /// behaviour for callers that pre-set `config.camouflage`).
    ///
    /// The default implementation ignores both `credential` and `hop_camouflage`
    /// and delegates to [`connect`] — protocols that do not support either
    /// behave identically to the legacy path.
    ///
    /// [`EndpointProtocol`] overrides this to pass the credential into
    /// `run_client_tcp_v9` via the `V9ClientHello` credential slot AND to
    /// apply the correct per-hop transport camouflage.
    async fn connect_with_credential(
        &self,
        addr: std::net::SocketAddr,
        server_pubkey: &[u8; 32],
        sni: &str,
        hop_camouflage: Option<TransportCamouflage>,
        _credential: Option<crate::driver::ClientCredential>,
    ) -> Result<Box<dyn Tunnel>, mirage_core::error::MirageError> {
        let _ = hop_camouflage; // default impl: camo pre-set on config (if any) is used
        self.connect(addr, server_pubkey, sni, CamouflageMode::Raw).await
    }
}

/// A UDP protocol implementation (client-side connect only).
///
/// UDP protocols have dedicated server-side listeners (see `mirage-node`'s
/// `*_listener` modules).  This trait covers only the client-side `connect`
/// path and the shared metadata accessors.
#[async_trait]
pub trait UdpProtocol: Send + Sync {
    /// Open an outbound tunnel to `addr` over UDP.
    ///
    /// `server_pubkey` is the 32-byte X25519 public key of the remote node.
    /// `sni` is used by protocols that layer TLS on top of QUIC.
    /// `camouflage` is accepted for interface symmetry but most UDP protocols
    /// ignore it (datagram framing does not support camouflage wrappers).
    async fn connect(
        &self,
        addr: SocketAddr,
        server_pubkey: &[u8; 32],
        sni: &str,
        camouflage: CamouflageMode,
    ) -> Result<Box<dyn Tunnel>, MirageError>;

    /// The [`UdpProtocolId`] this implementation handles.
    fn id(&self) -> UdpProtocolId;

    /// Whether this protocol is resistant to active probing by censors.
    fn probe_resistant(&self) -> bool;
}
