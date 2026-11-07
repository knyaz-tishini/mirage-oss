//! The server: it listens, it answers the peers, and it carries their packets
//! out.
//!
//! # The shape
//!
//! ```text
//!   MKVIK ----> the listener -> the handshake -> the plane -> the tun -> the internet
//!   tunnel ---> the listener -> the handshake -> the mux  -> the exit
//! ```
//!
//! Every peer that comes in is answered in a task of its own.
//!
//! # The plane
//!
//! The QUIC endpoint is the plane: the peer sends whole IP packets in the
//! datagrams of the SAME connection, and the box's own TUN device carries
//! them out to the internet. The device is opened once, at the start of the
//! server, and every peer shares it.
//!
//! When the device cannot be opened -- no `/dev/net/tun`, no permission -- the
//! server still comes up, but the plane peers are refused: there is no exit
//! for their packets.
//!
//! # The exit
//!
//! The exit is where the old path goes: the mux of a version-1-to-3 session
//! opens the connections itself, or hands every flow to a local SOCKS5 proxy.

use std::net::SocketAddr;
use std::sync::Arc;

use mirage_protocol::cores::handshake::ClientAuthContext;
use mirage_protocol::plane::{PlaneListener, PlaneSession};
use mirage_vpn::carrier::{CarrierError, CarrierListener, TunnelListener};
use mirage_vpn::ip_plane::{IpPlane, IpPlaneConfig, IpPlaneStats};
use mirage_vpn::metrics::{self, ExtraSource, Metrics};
use mirage_vpn::peer::{Peer, PeerTable};
use mirage_vpn::session::serve as serve_session;
use mirage_vpn::socks5::{DirectExit, ExitConnector, Socks5Exit};

use crate::config::{decode_key, decode_keypair, Exit, ServerConfig};
use crate::Error;

/// What a running server looks like from the outside.
pub struct ServerHandle {
    /// The peers that are allowed to come.
    pub peers: Arc<PeerTable>,
    /// Where the listeners bound, and what they are.
    pub listeners: Vec<(&'static str, SocketAddr)>,
}

/// Start the server.
///
/// The listeners are up when this returns: the addresses they bound are in the
/// handle, so the caller may ask for port 0 and learn where the ports landed.
pub async fn start(config: ServerConfig) -> Result<ServerHandle, Error> {
    let keypair = decode_keypair(&config.private_key)?;

    // The peers that are allowed to come.
    let mut table = PeerTable::new();
    for peer in &config.peers {
        let public = decode_key(&peer.public_key)?;
        let entry = match &peer.name {
            Some(name) => Peer::named(public, name.clone()),
            None => Peer::new(public),
        };
        table.insert(entry)?;
    }
    let peers = Arc::new(table);

    let mesh_id = config.mesh_id.as_bytes().to_vec();

    let connector: Arc<dyn ExitConnector> = match config.exit {
        Exit::Direct => Arc::new(DirectExit),
        Exit::Socks5 { proxy } => Arc::new(Socks5Exit::new(proxy)),
    };

    // The box's L3 exit: the TUN device every peer's packets go through. It
    // is opened once, and every peer shares it. When it cannot be opened the
    // server still comes up -- the plane peers are refused instead.
    let ip_plane = match IpPlane::open(IpPlaneConfig::default()) {
        Ok(plane) => {
            tracing::info!("the box's ip plane is up");
            Some(plane)
        }
        Err(err) => {
            tracing::error!(
                %err,
                "the box's ip plane could not be opened -- the plane peers are refused"
            );
            None
        }
    };

    let mut listeners = Vec::new();

    // The metrics endpoint: the operator's window into the counters. It is
    // off unless the config asks for it. An endpoint that cannot bind is a
    // loud log line and nothing more -- the box runs the same either way.
    let registry = Arc::new(Metrics::new());
    if let Some(listener) = &config.metrics {
        let bind = listener.bind;
        let endpoint = Arc::clone(&registry);
        let extra = plane_extra(ip_plane.clone());
        tokio::spawn(async move {
            if let Err(err) = metrics::serve(bind, endpoint, extra).await {
                tracing::error!(
                    %err,
                    %bind,
                    "the metrics endpoint could not be started -- the box runs without it"
                );
            }
        });
    }

    // MirageQUIC: one QUIC endpoint, many peers, and the packet plane.
    if let Some(mkvik) = &config.listeners.mkvik {
        let listener = PlaneListener::bind(
            &mkvik.alpn,
            mkvik.bind,
            keypair.clone(),
            mesh_id.clone(),
            allow(Arc::clone(&peers)),
        )
        .map_err(|err| {
            Error::Carrier(CarrierError::Open(format!("the quic endpoint: {err}")))
        })?;
        let bound = listener.local_addr().unwrap_or(mkvik.bind);
        listeners.push(("mkvik", bound));
        spawn_plane(listener, Arc::clone(&connector), ip_plane.clone());
    }

    // The tunnel: a session that arrives through a SOCKS5 proxy.
    if let Some(addr) = config.listeners.tunnel {
        let listener = TunnelListener::bind(
            addr,
            keypair.clone(),
            mesh_id.clone(),
            allow(Arc::clone(&peers)),
        )
        .await?;
        // The port may have been zero: the address the listener landed on is
        // the one the operator has to know.
        let bound = listener.local_addr().unwrap_or(addr);
        listeners.push(("tunnel", bound));
        spawn(listener, Arc::clone(&connector));
    }

    Ok(ServerHandle { peers, listeners })
}

/// The allowlist the handshake asks.
fn allow(
    peers: Arc<PeerTable>,
) -> Arc<dyn Fn(&ClientAuthContext<'_>) -> bool + Send + Sync> {
    Arc::new(move |context: &ClientAuthContext<'_>| peers.allows(context.static_pub))
}

/// The numbers the registry does not own: the packet plane and the device.
///
/// The plane keeps its own counters -- it lives on the device's threads --
/// so the endpoint asks for them at scrape time. A box without a plane
/// answers zeros: the counters are still there, and they are still zero.
fn plane_extra(ip_plane: Option<Arc<IpPlane>>) -> ExtraSource {
    metrics::extra_source(move || {
        let numbers = match &ip_plane {
            Some(plane) => {
                let stats = plane.counters().stats();
                metrics::plane_metrics(&stats, plane.peers().len())
            }
            None => metrics::plane_metrics(&IpPlaneStats::default(), 0),
        };
        let mut numbers = numbers;
        numbers.extend(metrics::device_metrics());
        numbers
    })
}

/// Answer the peers that come, one at a time.
///
/// The peer that comes is either this box's own client or the customer's
/// client -- the dispatcher tells them apart by the first byte of the
/// session (see `mirage_vpn::session`).
fn spawn(listener: impl CarrierListener + 'static, connector: Arc<dyn ExitConnector>) {
    tokio::spawn(async move {
        let mut listener = listener;
        let arrival = listener.local_addr();
        while let Ok(tunnel) = listener.accept().await {
            let connector = Arc::clone(&connector);
            let arrival = arrival;
            tokio::spawn(async move {
                if let Err(err) = serve_session(tunnel, connector, arrival, None, None).await {
                    tracing::warn!(%err, "the session stopped");
                }
            });
        }
    });
}

/// Answer the peers of the QUIC endpoint, one at a time.
///
/// Every session of this endpoint has a tunnel AND a plane: the hello and
/// the welcome ride the tunnel, and the packets ride the datagrams of the
/// same connection. The plane of the session is served by the box's IP
/// plane.
fn spawn_plane(
    listener: PlaneListener,
    connector: Arc<dyn ExitConnector>,
    ip_plane: Option<Arc<IpPlane>>,
) {
    tokio::spawn(async move {
        let mut listener = listener;
        let arrival = listener.local_addr();
        while let Ok(session) = listener.accept().await {
            let connector = Arc::clone(&connector);
            let arrival = arrival;
            let ip_plane = ip_plane.clone();
            tokio::spawn(async move {
                let PlaneSession { tunnel, plane } = session;
                if let Err(err) =
                    serve_session(tunnel, connector, arrival, Some(plane), ip_plane).await
                {
                    tracing::warn!(%err, "the session stopped");
                }
            });
        }
    });
}
