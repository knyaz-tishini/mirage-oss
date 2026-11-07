//! The client: it dials the server and serves a local SOCKS5.
//!
//! # The shape
//!
//! ```text
//!   the application
//!        │  SOCKS5 CONNECT example.com:443
//!   ┌────▼────────┐
//!   │ Socks5      │   the local listener
//!   │ listener    │
//!   └────┬────────┘
//!        │  Flow::open(target)
//!   ┌────▼────────┐
//!   │  FlowPlane  │   the session
//!   └────┬────────┘
//!        │  MWG / КВИК / a tunnel through a SOCKS5 proxy
//!   ┌────▼────────┐
//!   │   server    │
//!   └─────────────┘
//! ```
//!
//! There is no system TUN here, and no route to set up: the SOCKS5 listener
//! is the whole surface the application needs.

use std::net::SocketAddr;
use std::sync::Arc;

use mirage_vpn::carrier::{CamouflageCarrier, Carrier, SocksTunnelCarrier};
use mirage_vpn::flow::FlowPlane;
use mirage_vpn::socks5::Socks5Listener;

use crate::config::{
    decode_key, decode_keypair, endpoint_config, split_host_port, ClientConfig, Transport,
};
use crate::Error;

/// What a running client looks like from the outside.
pub struct ClientHandle {
    /// Where the local SOCKS5 listens.
    pub socks5: SocketAddr,
    /// The carrier the session rides in.
    pub carrier: &'static str,
}

/// Start the client.
///
/// The session is up when this returns, and the SOCKS5 listener is listening:
/// the address it bound is in the handle, so the caller may ask for port 0 and
/// learn where it landed.
pub async fn start(config: ClientConfig) -> Result<ClientHandle, Error> {
    let keypair = decode_keypair(&config.private_key)?;
    let server_public = decode_key(&config.server_public_key)?;
    let mesh_id = config.mesh_id.as_bytes().to_vec();

    let carrier = build_carrier(&config.transport)?;
    let name = carrier.name();

    let tunnel = carrier
        .open(&server_public, &keypair.secret.to_bytes(), &mesh_id)
        .await?;
    tracing::info!(carrier = name, "the session is up");

    let plane = FlowPlane::start(tunnel);
    let socks5 = Socks5Listener::new(config.socks5_listen).serve(plane).await?;

    Ok(ClientHandle {
        socks5,
        carrier: name,
    })
}

/// The carrier the transport names.
fn build_carrier(transport: &Transport) -> Result<Arc<dyn Carrier>, Error> {
    match transport {
        Transport::Mwg { server, .. } | Transport::Mkvik { server, .. } => {
            let camouflage = transport
                .camouflage()
                .expect("a camouflage transport has a camouflage");
            Ok(Arc::new(CamouflageCarrier::new(
                endpoint_config(camouflage),
                *server,
            )))
        }
        Transport::Tunnel { server, proxy } => {
            let (host, port) = split_host_port(server)?;
            // The name is resolved by the proxy: the client never learns the
            // server's address.
            Ok(Arc::new(SocksTunnelCarrier::new(*proxy, host, port)))
        }
    }
}
