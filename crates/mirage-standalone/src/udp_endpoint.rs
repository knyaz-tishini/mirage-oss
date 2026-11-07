//! Mirage over UDP, held by the node.
//!
//! The perimeter is Mirage over TCP. This binder is the other Mirage carrier:
//! raw UDP when the camouflage is none, and the junk mask when it is junk.
//! What comes out of either is a byte stream that goes into the same client
//! entrance the perimeter's splice uses — the V9 handshake, unchanged.
//!
//! QUIC, HTTP/3, WebTransport, DNS and ICMP are not this binder. They are
//! protocol doors.
//!
//! Both masks here are the shared-dispatcher family: one socket per address,
//! peers handed out of a queue, so looping `accept_server` is correct.

use std::sync::Arc;
use std::time::Duration;

use mirage_core::config::TransportCamouflage;
use mirage_node::client::entrance::EntranceDeps;
use mirage_protocol::camouflage::raw_udp::RawUdpCamouflage;
use mirage_protocol::camouflage::wireguard::WireGuardCamouflage;
use mirage_protocol::camouflage::UdpCamouflageLayer;
use tokio_util::sync::CancellationToken;

use crate::env::UdpEndpoint;

/// Why a UDP endpoint could not be brought up.
#[derive(Debug, thiserror::Error)]
pub enum UdpEndpointError {
    /// The mask could not be built, or the port could not be bound.
    #[error("box: the {protocol} endpoint on port {port} cannot be built: {reason}")]
    CannotBuild {
        /// The protocol the operator named.
        protocol: String,
        /// The port the endpoint was to bind.
        port: u16,
        /// Why it could not be built or bound.
        reason: String,
    },
}

/// Accept one connection and hand the stream to the client entrance.
///
/// The three families differ in HOW a connection arrives, not in what happens
/// to it afterwards — so the body of the loop is written once.
macro_rules! accept_loop {
    ($accept:expr, $port:expr, $deps:expr, $cancel:expr, $kind:expr) => {{
        loop {
            if $cancel.is_cancelled() {
                break;
            }
            match ($accept).await {
                Ok((stream, peer)) => {
                    let deps = $deps.clone();
                    let port = $port;
                    tokio::spawn(async move {
                        if let Err(e) =
                            mirage_node::client::entrance::handle_stream(stream, peer, port, deps)
                                .await
                        {
                            tracing::debug!(error = %e, "box: a UDP endpoint connection ended");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!(error = %e, kind = $kind, "box: a UDP endpoint accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }};
}

/// One endpoint, built and bound.
///
/// The fields are private: what a caller may do with it is serve it. The
/// bound socket is already open by the time this exists.
pub struct Prepared {
    bound: Bound,
    port: u16,
}

impl Prepared {
    /// The port this endpoint listens on.
    pub fn port(&self) -> u16 {
        self.port
    }
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("port", &self.port)
            .field("mask", &self.bound.kind())
            .finish()
    }
}

enum Bound {
    RawUdp {
        layer: Arc<RawUdpCamouflage>,
        bind_addr: std::net::SocketAddr,
        port: u16,
    },
    WireGuard {
        layer: Arc<WireGuardCamouflage>,
        bind_addr: std::net::SocketAddr,
        port: u16,
    },
}

impl Bound {
    /// The name of the mask this endpoint wears.
    fn kind(&self) -> &'static str {
        match self {
            Bound::RawUdp { .. } => "raw_udp",
            Bound::WireGuard { .. } => "wireguard",
        }
    }

    /// Build the camouflage and bind the socket.
    ///
    /// Everything that can fail fails HERE, before the box reports itself up:
    /// a mask that cannot be built, or a port that cannot be bound, is a door
    /// the box promised and cannot open.
    fn bind(endpoint: &UdpEndpoint) -> Result<Self, UdpEndpointError> {
        let port = endpoint.port;
        let fail = |reason: String| UdpEndpointError::CannotBuild {
            protocol: endpoint.id.clone(),
            port,
            reason,
        };
        let mask = endpoint.protocol.to_mask(port).map_err(fail)?;
        match &mask {
            TransportCamouflage::RawUdp { bind_addr } => Ok(Bound::RawUdp {
                layer: Arc::new(RawUdpCamouflage::new()),
                bind_addr: *bind_addr,
                port,
            }),
            TransportCamouflage::WireGuard {
                magic_byte,
                junk_count,
                junk_min,
                junk_max,
                bind_addr,
            } => {
                let layer = WireGuardCamouflage::new(*magic_byte, *junk_count, *junk_min, *junk_max);
                Ok(Bound::WireGuard {
                    layer: Arc::new(layer),
                    bind_addr: *bind_addr,
                    port,
                })
            }
            other => Err(fail(format!(
                "{} is not a UDP mask the node can hold",
                other.label()
            ))),
        }
    }

    /// Serve this endpoint until `cancel` fires.
    async fn serve(self, deps: EntranceDeps, cancel: CancellationToken) {
        match self {
            Bound::RawUdp {
                layer,
                bind_addr,
                port,
            } => {
                tracing::info!(port, "box: UDP endpoint up (raw_udp)");
                accept_loop!(layer.accept_server(bind_addr), port, deps, cancel, "raw_udp");
            }
            Bound::WireGuard {
                layer,
                bind_addr,
                port,
            } => {
                tracing::info!(port, "box: UDP endpoint up (wireguard)");
                accept_loop!(layer.accept_server(bind_addr), port, deps, cancel, "wireguard");
            }
        }
    }
}

/// Build and bind every UDP endpoint the node holds.
///
/// Everything that can fail fails HERE, before the box reports itself up: a
/// mask that cannot be built, or a port that cannot be bound, is a door the
/// box promised and cannot open. The caller refuses to bring the box up
/// rather than leaving a port dark while the box reports itself healthy.
pub fn prepare(endpoints: &[UdpEndpoint]) -> Result<Vec<Prepared>, UdpEndpointError> {
    endpoints
        .iter()
        .map(|endpoint| {
            Ok(Prepared {
                bound: Bound::bind(endpoint)?,
                port: endpoint.port,
            })
        })
        .collect()
}

/// Serve every prepared UDP endpoint until `cancel` fires.
pub async fn serve(
    prepared: Vec<Prepared>,
    deps: EntranceDeps,
    cancel: CancellationToken,
) {
    let mut tasks = Vec::with_capacity(prepared.len());
    for endpoint in prepared {
        let deps = deps.clone();
        let cancel = cancel.clone();
        tasks.push(tokio::spawn(async move {
            endpoint.bound.serve(deps, cancel).await;
        }));
    }

    cancel.cancelled().await;
    for task in tasks {
        task.abort();
    }
}
