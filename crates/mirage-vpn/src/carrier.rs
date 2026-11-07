//! The carriers of the VPN variant: the pipes under the session.
//!
//! # A carrier is the only thing that differs
//!
//! MWG, КВИК, the SOCKS5 tube and the onion chain are **four carriers of one
//! protocol**. The handshake, the keys, the session and the flow plane are
//! the same in all four; what differs is the pipe under the session.
//!
//! | carrier | pipe | where it lives |
//! |---|---|---|
//! | MWG | UDP with a junk burst and a magic marker — Mirage's own `WireGuardCamouflage` | here |
//! | КВИК | QUIC with our ALPN — Mirage's own `QuicCamouflage` | here |
//! | SOCKS5 | a CONNECT tunnel through a proxy | here |
//! | onion | the chain itself — the mesh carrier | `mirage-vpn-mesh` |
//!
//! # The mesh carrier lives in its own crate
//!
//! The onion carrier needs the chain machinery, and the chain machinery is
//! the mesh. So the mesh carrier is implemented in `mirage-vpn-mesh`, against
//! the traits below — and this crate never learns about the onion.
//!
//! # Nothing here is a protocol of its own
//!
//! The handshake below is Mirage's own V9 handshake, and the session is
//! Mirage's own `MirageCoreTunnel`. This crate adds the VPN's *data* plane —
//! flows and a SOCKS5 surface — and nothing else.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use mirage_core::config::{MirageEndpointConfig, TransportKind};
use mirage_core::crypto::{AeadSuite, KeyPair};
use mirage_core::error::MirageError;
use mirage_protocol::auth::AuthMode;
use mirage_protocol::cores::carriers::CarrierKind;
use mirage_protocol::cores::handshake::{
    run_client_handshake_v9, run_server_handshake_v9, ClientAuthContext,
};
use mirage_protocol::cores::tunnel::MirageCoreTunnel;
use mirage_protocol::modes::driver::run_server_udp_with_auth;
use mirage_protocol::traits::{Tunnel, TransportInfo};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;

/// The AEAD suite the VPN speaks.
pub const SUITE: AeadSuite = AeadSuite::ChaCha20Poly1305;

/// A byte stream a session can run over.
///
/// The `Sync` bound is not decoration: the session core keeps the stream and
/// hands it out as a `Box<dyn Tunnel>`, and a tunnel has to be `Sync`.
pub trait Stream: AsyncRead + AsyncWrite + Send + Sync + Unpin {}

impl<T: AsyncRead + AsyncWrite + Send + Sync + Unpin> Stream for T {}

/// What can go wrong on the way to the terminator.
#[derive(Debug, thiserror::Error)]
pub enum CarrierError {
    /// The carrier could not be opened.
    #[error("the carrier could not be opened: {0}")]
    Open(String),

    /// The handshake over the carrier failed.
    #[error("the handshake over the carrier failed: {0}")]
    Handshake(String),

    /// The terminator refused the peer.
    #[error("the terminator refused the peer")]
    Refused,

    /// The carrier failed while it was carrying.
    #[error("the carrier failed: {0}")]
    Failed(String),
}

/// The client side of a carrier: it opens the session to the terminator.
#[async_trait]
pub trait Carrier: Send + Sync {
    /// The name of the carrier, for the operator's log.
    fn name(&self) -> &'static str;

    /// Open the session to the terminator.
    async fn open(
        &self,
        server_static_pub: &[u8; 32],
        client_static_priv: &[u8; 32],
        mesh_id: &[u8],
    ) -> Result<Box<dyn Tunnel>, CarrierError>;
}

/// The server side of a carrier: it hands back one session per peer.
///
/// The listener is owned by one task — it hands out one session at a time —
/// so it needs to be `Send` and not `Sync`.
#[async_trait]
pub trait CarrierListener: Send {
    /// The name of the carrier, for the operator's log.
    fn name(&self) -> &'static str;

    /// Wait for the next peer and hand back its session.
    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, CarrierError>;

    /// Where the listener is bound, for the operator's log.
    fn local_addr(&self) -> Option<SocketAddr> {
        None
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The camouflage carriers: MWG and КВИК
// ─────────────────────────────────────────────────────────────────────────────

/// A carrier over one of Mirage's own camouflage axes.
///
/// This is MWG (`TransportCamouflage::WireGuard` — UDP with a junk burst and
/// a magic byte) and КВИК (`TransportCamouflage::Quic`) among others: the
/// camouflage is the carrier, and everything above it is the same protocol.
pub struct CamouflageCarrier {
    config: MirageEndpointConfig,
    server: SocketAddr,
}

impl CamouflageCarrier {
    /// A carrier over the camouflage the configuration names.
    pub fn new(config: MirageEndpointConfig, server: SocketAddr) -> Self {
        Self { config, server }
    }
}

#[async_trait]
impl Carrier for CamouflageCarrier {
    fn name(&self) -> &'static str {
        CarrierKind::of_camouflage(&self.config.camouflage)
            .map(|kind| kind.name())
            .unwrap_or("camouflage")
    }

    async fn open(
        &self,
        server_static_pub: &[u8; 32],
        client_static_priv: &[u8; 32],
        mesh_id: &[u8],
    ) -> Result<Box<dyn Tunnel>, CarrierError> {
        // The camouflage axis decides the pipe; the handshake and the session
        // are Mirage's own, with no onion layer between them.
        mirage_protocol::modes::client_transport::run_client_v9_transport_aware(
            &self.config,
            self.server,
            server_static_pub,
            client_static_priv,
            "",
            mesh_id,
            None,
        )
        .await
        .map_err(|err| CarrierError::Open(err.to_string()))
    }
}

/// The server side of a camouflage carrier.
///
/// MWG: one UDP port, many peers. КВИК: one QUIC endpoint, many peers. The
/// handshake of every peer runs in a task of its own, so a peer that is slow
/// does not hold the door for the others.
pub struct CamouflageListener {
    name: &'static str,
    receiver: mpsc::Receiver<Box<dyn Tunnel>>,
    local_addr: SocketAddr,
}

impl CamouflageListener {
    /// Bind the listener and start answering the peers.
    ///
    /// The peers that may come are decided by `client_auth`: it is handed the
    /// client's static key and answers whether the peer is welcome. The
    /// session keys are not derived when the answer is no.
    pub async fn bind(
        config: MirageEndpointConfig,
        bind_addr: SocketAddr,
        keypair: KeyPair,
        mesh_id: Vec<u8>,
        client_auth: Arc<dyn Fn(&ClientAuthContext<'_>) -> bool + Send + Sync>,
    ) -> Result<Self, CarrierError> {
        let name = CarrierKind::of_camouflage(&config.camouflage)
            .map(|kind| kind.name())
            .unwrap_or("camouflage");

        let mut config = config;
        // The camouflage decides the transport; the field is derived, not chosen.
        config.transport = TransportKind::Udp;

        let (sender, receiver) = mpsc::channel::<Box<dyn Tunnel>>(64);
        tokio::spawn(async move {
            let result = run_server_udp_with_auth(
                &config,
                &keypair,
                bind_addr,
                sender,
                &mesh_id,
                client_auth,
                false,
            )
            .await;
            if let Err(err) = result {
                tracing::error!(%err, carrier = name, "the carrier listener stopped");
            }
        });

        Ok(Self {
            name,
            receiver,
            local_addr: bind_addr,
        })
    }
}

#[async_trait]
impl CarrierListener for CamouflageListener {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, CarrierError> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| CarrierError::Failed("the listener is closed".into()))
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Some(self.local_addr)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The SOCKS5 tube
// ─────────────────────────────────────────────────────────────────────────────

/// The session inside a SOCKS5 CONNECT tunnel.
///
/// The proxy opens the tunnel to the terminator and the session runs inside
/// it. The name of the terminator is resolved by the proxy — the client never
/// learns the address.
pub struct SocksTunnelCarrier {
    proxy: SocketAddr,
    host: String,
    port: u16,
}

impl SocksTunnelCarrier {
    /// A carrier through a SOCKS5 proxy.
    pub fn new(proxy: SocketAddr, host: impl Into<String>, port: u16) -> Self {
        Self {
            proxy,
            host: host.into(),
            port,
        }
    }
}

#[async_trait]
impl Carrier for SocksTunnelCarrier {
    fn name(&self) -> &'static str {
        CarrierKind::Socks5.name()
    }

    async fn open(
        &self,
        server_static_pub: &[u8; 32],
        client_static_priv: &[u8; 32],
        mesh_id: &[u8],
    ) -> Result<Box<dyn Tunnel>, CarrierError> {
        let stream = open_socks_tunnel(self.proxy, &self.host, self.port).await?;
        open_over_stream(stream, server_static_pub, client_static_priv, mesh_id, self.proxy).await
    }
}

/// The server side of the SOCKS5 tube.
///
/// The TCP port where a session arrives **through a SOCKS5 proxy**: the proxy
/// opens a CONNECT tunnel to this port, and the session runs inside it. It is
/// the way to the terminator when the terminator cannot be reached directly.
pub struct TunnelListener {
    listener: TcpListener,
    local_addr: SocketAddr,
    keypair: KeyPair,
    mesh_id: Vec<u8>,
    client_auth: Arc<dyn Fn(&ClientAuthContext<'_>) -> bool + Send + Sync>,
}

impl TunnelListener {
    /// Bind the port where the sessions arrive.
    pub async fn bind(
        bind_addr: SocketAddr,
        keypair: KeyPair,
        mesh_id: impl Into<Vec<u8>>,
        client_auth: Arc<dyn Fn(&ClientAuthContext<'_>) -> bool + Send + Sync>,
    ) -> Result<Self, CarrierError> {
        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|err| CarrierError::Open(err.to_string()))?;
        let local_addr = listener
            .local_addr()
            .map_err(|err| CarrierError::Open(err.to_string()))?;
        Ok(Self {
            listener,
            local_addr,
            keypair,
            mesh_id: mesh_id.into(),
            client_auth,
        })
    }
}

#[async_trait]
impl CarrierListener for TunnelListener {
    fn name(&self) -> &'static str {
        CarrierKind::Socks5.name()
    }

    async fn accept(&mut self) -> Result<Box<dyn Tunnel>, CarrierError> {
        let (socket, peer) = self
            .listener
            .accept()
            .await
            .map_err(|err| CarrierError::Failed(err.to_string()))?;
        tracing::debug!(%peer, "a session arrived through the tunnel");
        let client_auth = Arc::clone(&self.client_auth);
        accept_over_stream(
            Box::new(socket),
            &self.keypair,
            &self.mesh_id,
            peer,
            move |context| client_auth(context),
        )
        .await
    }

    fn local_addr(&self) -> Option<SocketAddr> {
        Some(self.local_addr)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The session over a plain stream
// ─────────────────────────────────────────────────────────────────────────────

/// Open the session as the client, over a raw stream.
///
/// The raw stream is what a carrier that cannot use Mirage's camouflage
/// gives — the SOCKS5 tube and the onion chain.
pub async fn open_over_stream(
    mut stream: Box<dyn Stream>,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    mesh_id: &[u8],
    remote: SocketAddr,
) -> Result<Box<dyn Tunnel>, CarrierError> {
    let result = run_client_handshake_v9(
        &mut stream,
        server_static_pub,
        client_static_priv,
        mesh_id,
        &[SUITE],
    )
    .await
    .map_err(|err| CarrierError::Handshake(err.to_string()))?;
    let tunnel = MirageCoreTunnel::new(
        stream,
        &result.session_keys,
        true,
        TransportInfo::tcp_raw(remote),
        session_auth_mode(),
    );
    Ok(Box::new(tunnel))
}

/// Answer the session as the terminator, over a raw stream.
pub async fn accept_over_stream(
    mut stream: Box<dyn Stream>,
    keypair: &KeyPair,
    mesh_id: &[u8],
    remote: SocketAddr,
    client_auth: impl Fn(&ClientAuthContext<'_>) -> bool + Send + Sync,
) -> Result<Box<dyn Tunnel>, CarrierError> {
    let Some(result) =
        run_server_handshake_v9(&mut stream, keypair, mesh_id, &[SUITE], client_auth)
            .await
            .map_err(|err| CarrierError::Handshake(err.to_string()))?
    else {
        return Err(CarrierError::Refused);
    };
    let tunnel = MirageCoreTunnel::new(
        stream,
        &result.session_keys,
        false,
        TransportInfo::tcp_raw(remote),
        session_auth_mode(),
    );
    Ok(Box::new(tunnel))
}

/// The auth mode the session's frames carry.
///
/// The V9 handshake already authenticates the peer; the per-frame HMAC is
/// only for the `Hmac` mode, and the VPN does not use it.
fn session_auth_mode() -> AuthMode {
    AuthMode::V9MutualFs
}

/// Turn a tunnel into a stream.
///
/// The chain gives a **tunnel** — a thing that sends and receives bytes — and
/// the session wants a **stream**. This is the bridge: a task owns the
/// tunnel and copies between it and one end of a duplex pipe; the other end
/// is the stream the session runs on.
///
/// The copy is one task with two directions, because a tunnel is one object
/// with `&mut self` on both sides — it cannot be split.
pub fn tunnel_to_stream(tunnel: Box<dyn Tunnel>) -> Box<dyn Stream> {
    let (near, far) = tokio::io::duplex(64 * 1024);
    tokio::spawn(async move {
        let mut tunnel = tunnel;
        let mut far = far;
        let mut from_tunnel = vec![0u8; 16 * 1024];
        let mut to_tunnel = vec![0u8; 16 * 1024];
        loop {
            tokio::select! {
                result = tunnel.recv(&mut from_tunnel) => {
                    let Ok(count) = result else { break };
                    if count == 0 {
                        break;
                    }
                    if far.write_all(&from_tunnel[..count]).await.is_err() {
                        break;
                    }
                }
                result = far.read(&mut to_tunnel) => {
                    let Ok(count) = result else { break };
                    if count == 0 {
                        break;
                    }
                    if tunnel.send(&to_tunnel[..count]).await.is_err() {
                        break;
                    }
                }
            }
        }
    });
    Box::new(near)
}

/// Open a SOCKS5 CONNECT tunnel and return the stream inside it.
async fn open_socks_tunnel(
    proxy: SocketAddr,
    host: &str,
    port: u16,
) -> Result<Box<dyn Stream>, CarrierError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    let mut socket = TcpStream::connect(proxy)
        .await
        .map_err(|err| CarrierError::Open(format!("the proxy refused: {err}")))?;

    // The greeting: "no auth".
    socket
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|err| CarrierError::Open(err.to_string()))?;
    let mut answer = [0u8; 2];
    socket
        .read_exact(&mut answer)
        .await
        .map_err(|err| CarrierError::Open(err.to_string()))?;
    if answer != [0x05, 0x00] {
        return Err(CarrierError::Open(
            "the proxy wants an auth we do not have".into(),
        ));
    }

    // The request: CONNECT to the terminator, by name.
    let name = host.as_bytes();
    if name.len() > u8::MAX as usize {
        return Err(CarrierError::Open("the name is too long".into()));
    }
    let mut request = Vec::with_capacity(4 + 1 + name.len() + 2);
    request.push(0x05);
    request.push(0x01);
    request.push(0x00);
    request.push(0x03);
    request.push(name.len() as u8);
    request.extend_from_slice(name);
    request.extend_from_slice(&port.to_be_bytes());
    socket
        .write_all(&request)
        .await
        .map_err(|err| CarrierError::Open(err.to_string()))?;

    // The answer: the version, the code, and the bound address.
    let mut head = [0u8; 4];
    socket
        .read_exact(&mut head)
        .await
        .map_err(|err| CarrierError::Open(err.to_string()))?;
    if head[0] != 0x05 || head[1] != 0x00 {
        return Err(CarrierError::Open(format!(
            "the proxy refused the tunnel: code 0x{:02x}",
            head[1]
        )));
    }
    // The bound address that follows the head: four bytes of address and two
    // of port for IPv4, sixteen and two for IPv6, a length byte and a name
    // and two for a domain.
    let bound = match head[3] {
        0x01 => 6,
        0x03 => {
            let mut length = [0u8; 1];
            socket
                .read_exact(&mut length)
                .await
                .map_err(|err| CarrierError::Open(err.to_string()))?;
            usize::from(length[0]) + 2
        }
        0x04 => 18,
        other => {
            return Err(CarrierError::Open(format!(
                "the proxy answered with an unknown address type 0x{other:02x}"
            )))
        }
    };
    let mut skip = vec![0u8; bound];
    socket
        .read_exact(&mut skip)
        .await
        .map_err(|err| CarrierError::Open(err.to_string()))?;

    Ok(Box::new(socket))
}

/// The error of a carrier that failed.
impl From<MirageError> for CarrierError {
    fn from(err: MirageError) -> Self {
        CarrierError::Failed(err.to_string())
    }
}
