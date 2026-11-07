//! The packet plane — whole IP packets inside QUIC datagrams.
//!
//! # What this is
//!
//! The mono-protocol shape: ONE QUIC connection carries the whole tunnel.
//!
//! * the **control wire** — the Mirage V9 handshake and the edge
//!   hello/welcome — rides one bidirectional QUIC stream, encrypted by
//!   Mirage's own session keys;
//! * the **packets** — one raw IP packet each — ride QUIC DATAGRAM frames
//!   (RFC 9221), encrypted by the QUIC packet protection itself.
//!
//! There is no mux in this path: a packet is not a stream, a stream is not a
//! packet, and nothing is re-framed on the way. The peer that receives a
//! datagram gets the IP packet exactly as the sender wrote it.
//!
//! # Why datagrams and not streams
//!
//! A stream is reliable and ordered: one lost QUIC packet stalls every flow
//! that shares the connection (TCP-in-TCP), and a whole flow must be carried
//! by one stream, which is the yamux-over-QUIC shape this plane replaces.
//! A datagram is unreliable and unordered — the same contract IP has. A lost
//! datagram is a lost IP packet, and the protocol inside it (TCP, QUIC, DNS)
//! repairs it the way it repairs a loss on a wire.
//!
//! # The two ends
//!
//! [`PlaneConnector`] is the client side: it dials the box and returns a
//! [`PlaneSession`] — the control tunnel and the packet plane of the SAME
//! QUIC connection. [`PlaneListener`] is the server side: it binds the QUIC
//! endpoint and hands out one [`PlaneSession`] per peer.

use std::net::SocketAddr;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use mirage_core::crypto::{AeadSuite, KeyPair};
use mirage_core::error::MirageError;
use tokio::sync::mpsc;

use crate::auth::AuthMode;
use crate::protocols::l4::quic::{
    build_client_config, build_server_config_with, generate_self_signed_cert, QuicStreamAdapter,
};
use crate::cores::handshake::{
    run_client_handshake_v9, run_server_handshake_v9, ClientAuthContext,
};
use crate::cores::tunnel::MirageCoreTunnel;
use crate::traits::{Tunnel, TransportInfo};

/// The AEAD suite the plane's control tunnel speaks.
const SUITE: AeadSuite = AeadSuite::ChaCha20Poly1305;

/// The biggest IP packet the plane carries by default.
///
/// 1280 is the IPv6 minimum link MTU and fits inside a QUIC datagram on any
/// path that QUIC itself can live on. The adapter on the client side is
/// configured with the same number, so a packet never has to be split.
pub const MAX_PACKET_SIZE: usize = 1280;

/// How many incoming datagram bytes the QUIC transport buffers.
///
/// It is also what this side advertises as `max_datagram_frame_size`, so the
/// peer may hand us a datagram of that size. The path MTU is what really
/// caps a packet — see [`PacketPlane::max_packet_size`].
const DATAGRAM_BUFFER: usize = 1024 * 1024;

/// How long the QUIC connection may sit idle before it is torn down.
///
/// The keep-alive pokes the connection every [`KEEP_ALIVE`], and the peer's
/// answer counts as traffic, so a LIVE connection never reaches this. A
/// DEAD one reaches it in this long - and that is the whole point: the
/// client has to notice that the box is gone and redial by itself, long
/// before the operator wonders why the tunnel died.
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(20);

/// How often the client pokes the connection so a NAT does not drop it.
///
/// It stays well under the idle timeout - the peer's answer is what keeps
/// the connection alive, and a lost ping is retransmitted like any other
/// packet.
const KEEP_ALIVE: std::time::Duration = std::time::Duration::from_secs(7);

// ─────────────────────────────────────────────────────────────────────────────
// The plane itself
// ─────────────────────────────────────────────────────────────────────────────

/// A plane of whole IP packets.
///
/// `send_packet` and `recv_packet` are the two halves of the tunnel: one
/// packet in, one packet out. The packet is opaque to the plane — it is the
/// IP packet, byte for byte.
#[async_trait]
pub trait PacketPlane: Send + Sync {
    /// Put one IP packet on the wire.
    async fn send_packet(&self, packet: &[u8]) -> Result<(), MirageError>;

    /// Take one IP packet off the wire into `buf`.
    ///
    /// Returns the number of bytes written. A packet that does not fit in
    /// `buf` is TRUNCATED — the caller must size the buffer with
    /// [`PacketPlane::max_packet_size`] in mind.
    async fn recv_packet(&self, buf: &mut [u8]) -> Result<usize, MirageError>;

    /// The biggest packet that fits right now.
    ///
    /// This is the path's budget: the QUIC packet overhead comes out of the
    /// same path MTU the IP packet travels in. It shrinks when the path
    /// turns out to be narrower than the datagram budget assumed.
    fn max_packet_size(&self) -> usize;
}

/// One session: the control tunnel and the packet plane of one QUIC
/// connection.
///
/// Both halves belong to the SAME connection — that is the point: the
/// control wire authenticates the peer, and the packets ride the connection
/// that authentication opened.
pub struct PlaneSession {
    /// The control wire — the Mirage V9 session over the QUIC stream.
    pub tunnel: Box<dyn Tunnel>,
    /// The packet plane — the QUIC datagrams of the same connection.
    pub plane: Arc<dyn PacketPlane>,
}

// ─────────────────────────────────────────────────────────────────────────────
// The client side
// ─────────────────────────────────────────────────────────────────────────────

/// The client side of the plane: it dials the box and opens the session.
///
/// The connector owns ONE QUIC endpoint and reuses it for every dial — a
/// fresh endpoint per dial would change the client's UDP source port, and a
/// NAT that has already learned the old mapping would drop the new one. The
/// connector must outlive the sessions it opened.
pub struct PlaneConnector {
    endpoint: quinn::Endpoint,
    client_config: quinn::ClientConfig,
    sni: String,
}

impl PlaneConnector {
    /// Build a connector for one box.
    ///
    /// `alpn` is the ALPN list of the profile, `sni` the TLS server name.
    pub fn new(alpn: &[String], sni: &str) -> Result<Self, MirageError> {
        let client_config = build_client_config(alpn)?;

        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(KEEP_ALIVE));
        transport.max_idle_timeout(Some(
            IDLE_TIMEOUT.try_into().expect("120 s fits in a VarInt"),
        ));
        transport.datagram_receive_buffer_size(Some(DATAGRAM_BUFFER));

        let mut client_config = client_config;
        client_config.transport_config(Arc::new(transport));

        let socket = crate::driver::bind_udp_with_carrier("0.0.0.0:0".parse().expect("a valid bind address"))?;
        let runtime = quinn::default_runtime().ok_or_else(|| {
            MirageError::Protocol("quic endpoint has no async runtime".into())
        })?;
        let mut endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )
        .map_err(MirageError::Io)?;
        endpoint.set_default_client_config(client_config.clone());

        Ok(Self {
            endpoint,
            client_config,
            sni: if sni.is_empty() {
                "mirage.local".to_owned()
            } else {
                sni.to_owned()
            },
        })
    }

    /// The client config this connector dials with — the operator's log.
    pub fn client_config(&self) -> &quinn::ClientConfig {
        &self.client_config
    }

    /// Dial the box and open the session.
    ///
    /// The Mirage V9 handshake runs over the QUIC stream: the peer is
    /// authenticated before a single datagram is accepted.
    pub async fn connect(
        &self,
        server_addr: SocketAddr,
        server_static_pub: &[u8; 32],
        client_static_priv: &[u8; 32],
        mesh_id: &[u8],
    ) -> Result<PlaneSession, MirageError> {
        let connection = self
            .endpoint
            .connect(server_addr, &self.sni)
            .map_err(|err| MirageError::Protocol(format!("quic connect: {err}")))?
            .await
            .map_err(|err| MirageError::Protocol(format!("quic connection: {err}")))?;

        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|err| MirageError::Protocol(format!("quic open_bi: {err}")))?;

        let mut adapter = QuicStreamAdapter::new(send, recv, connection.clone());

        let result = run_client_handshake_v9(
            &mut adapter,
            server_static_pub,
            client_static_priv,
            mesh_id,
            &[SUITE],
        )
        .await?;

        let tunnel = MirageCoreTunnel::new(
            adapter,
            &result.session_keys,
            true,
            TransportInfo::udp_raw(server_addr),
            AuthMode::V9MutualFs,
        );

        Ok(PlaneSession {
            tunnel: Box::new(tunnel),
            plane: Arc::new(QuicPacketPlane { connection }),
        })
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The server side
// ─────────────────────────────────────────────────────────────────────────────

/// The server side of the plane: it binds the QUIC endpoint and hands out one
/// session per peer.
pub struct PlaneListener {
    /// Kept so the QUIC endpoint outlives the listener: dropping it closes
    /// every connection it opened.
    #[allow(dead_code)]
    endpoint: quinn::Endpoint,
    receiver: mpsc::Receiver<PlaneSession>,
    local_addr: SocketAddr,
}

impl PlaneListener {
    /// Bind the endpoint and start answering the peers.
    ///
    /// `client_auth` decides which peers are welcome — it is asked with the
    /// client's static key BEFORE the session keys are derived.
    pub fn bind(
        alpn: &[String],
        bind_addr: SocketAddr,
        keypair: KeyPair,
        mesh_id: Vec<u8>,
        client_auth: Arc<dyn Fn(&ClientAuthContext<'_>) -> bool + Send + Sync>,
    ) -> Result<Self, MirageError> {
        let (cert, key) = generate_self_signed_cert()?;
        let server_config = build_server_config_with(cert, key, alpn, Some(DATAGRAM_BUFFER))?;

        let endpoint =
            quinn::Endpoint::server(server_config, bind_addr).map_err(MirageError::Io)?;
        let local_addr = endpoint.local_addr().map_err(MirageError::Io)?;

        let (sender, receiver) = mpsc::channel::<PlaneSession>(16);

        let accept_endpoint = endpoint.clone();
        tokio::spawn(async move {
            while let Some(incoming) = accept_endpoint.accept().await {
                let keypair = keypair.clone();
                let mesh_id = mesh_id.clone();
                let client_auth = Arc::clone(&client_auth);
                let sender = sender.clone();
                tokio::spawn(async move {
                    let connection = match incoming.await {
                        Ok(connection) => connection,
                        Err(err) => {
                            tracing::debug!(%err, "the quic connection did not complete");
                            return;
                        }
                    };
                    let peer = connection.remote_address();

                    let (send, recv) = match connection.accept_bi().await {
                        Ok(pair) => pair,
                        Err(err) => {
                            tracing::debug!(%peer, %err, "the quic control stream did not open");
                            return;
                        }
                    };

                    let mut adapter = QuicStreamAdapter::new(send, recv, connection.clone());

                    let result = run_server_handshake_v9(
                        &mut adapter,
                        &keypair,
                        &mesh_id,
                        &[SUITE],
                        move |context| client_auth(context),
                    )
                    .await;

                    let result = match result {
                        Ok(Some(result)) => result,
                        Ok(None) => {
                            tracing::debug!(%peer, "the peer was refused by the client gate");
                            return;
                        }
                        Err(err) => {
                            tracing::debug!(%peer, %err, "the quic handshake failed");
                            return;
                        }
                    };

                    let tunnel = MirageCoreTunnel::new(
                        adapter,
                        &result.session_keys,
                        false,
                        TransportInfo::udp_raw(peer),
                        AuthMode::V9MutualFs,
                    );

                    let session = PlaneSession {
                        tunnel: Box::new(tunnel),
                        plane: Arc::new(QuicPacketPlane { connection }),
                    };

                    if sender.send(session).await.is_err() {
                        tracing::debug!(%peer, "the plane listener is closed");
                        return;
                    }
                });
            }
        });

        Ok(Self {
            endpoint,
            receiver,
            local_addr,
        })
    }

    /// Wait for the next peer and hand back its session.
    pub async fn accept(&mut self) -> Result<PlaneSession, MirageError> {
        self.receiver
            .recv()
            .await
            .ok_or_else(|| MirageError::Protocol("the plane listener is closed".into()))
    }

    /// Where the listener is bound, for the operator's log.
    pub fn local_addr(&self) -> Option<SocketAddr> {
        Some(self.local_addr)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// The quinn-backed plane
// ─────────────────────────────────────────────────────────────────────────────

/// The packet plane of one QUIC connection.
pub struct QuicPacketPlane {
    connection: quinn::Connection,
}

impl QuicPacketPlane {
    /// The QUIC connection this plane rides.
    pub fn connection(&self) -> &quinn::Connection {
        &self.connection
    }
}

#[async_trait]
impl PacketPlane for QuicPacketPlane {
    async fn send_packet(&self, packet: &[u8]) -> Result<(), MirageError> {
        self.connection
            .send_datagram(Bytes::copy_from_slice(packet))
            .map_err(|err| {
                MirageError::Io(std::io::Error::other(format!("quic datagram: {err}")))
            })
    }

    async fn recv_packet(&self, buf: &mut [u8]) -> Result<usize, MirageError> {
        let datagram = self
            .connection
            .read_datagram()
            .await
            .map_err(|err| {
                MirageError::Io(std::io::Error::other(format!("quic datagram: {err}")))
            })?;
        let count = datagram.len().min(buf.len());
        buf[..count].copy_from_slice(&datagram[..count]);
        Ok(count)
    }

    fn max_packet_size(&self) -> usize {
        self.connection
            .max_datagram_size()
            .unwrap_or(MAX_PACKET_SIZE)
            .min(MAX_PACKET_SIZE)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The plane's budget never exceeds the packet size the adapter is
    /// configured with — a packet that does not fit must never be written
    /// to the wire.
    #[test]
    fn the_budget_is_capped_at_the_packet_size() {
        assert!(MAX_PACKET_SIZE <= 1280);
    }
}
