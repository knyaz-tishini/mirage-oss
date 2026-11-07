//! One accepted session -- which wire the peer speaks, and the plane that
//! serves it.
//!
//! # Two wires, two listeners
//!
//! - The **plane** listener (the QUIC face the customer's client is given):
//!   the customer's client speaks the **packet plane** there -- the hello and
//!   the welcome on the control wire, the whole IP packets on the datagrams
//!   of the same connection. See [`crate::plane`].
//! - The **tunnel** listener: the box's own client (`mirage-vpn connect`)
//!   speaks the **flow plane** there -- the first message is an `Open`, and
//!   every flow is a message of its own. See [`crate::flow`].
//!
//! The edge-session mux (versions 1 to 3) is gone. It was the customer's wire
//! before the plane, and it is not served any more: the customer's client
//! speaks the plane, and the box speaks the plane only.

use std::net::SocketAddr;
use std::sync::Arc;

use mirage_protocol::plane::PacketPlane;
use mirage_protocol::traits::Tunnel;

use crate::flow::FlowPlane;
use crate::ip_plane::IpPlane;
use crate::plane::{self, PlaneError};
use crate::socks5::{serve_exit, ExitConnector, Socks5Error};

/// What can go wrong while one session is served.
#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// The plane wire failed.
    #[error("the plane session failed: {0}")]
    Plane(#[from] PlaneError),
    /// The flow plane failed.
    #[error("the flow plane failed: {0}")]
    Flow(#[from] Socks5Error),
    /// The session failed underneath.
    #[error("the session failed: {0}")]
    Session(String),
    /// The peer closed the session before it said anything.
    #[error("the peer closed the session")]
    Closed,
}

/// Serve one accepted session.
///
/// `arrival` is where the session arrived -- the face the box names in the
/// welcome.
///
/// `plane` is the packet plane of the same connection, when the carrier
/// gives one. A session that has one is the plane path: the peer sends whole
/// IP packets, and the box's TUN device -- `ip_plane` -- is the exit. A
/// session without one is the box's own client: the flow plane and the exit
/// connector.
pub async fn serve(
    tunnel: Box<dyn Tunnel>,
    connector: Arc<dyn ExitConnector>,
    arrival: Option<SocketAddr>,
    plane: Option<Arc<dyn PacketPlane>>,
    ip_plane: Option<Arc<IpPlane>>,
) -> Result<(), SessionError> {
    let mut tunnel = tunnel;

    // The plane path: the packets ride the datagrams of the same connection,
    // and the box's TUN device is the exit.
    if let Some(plane) = plane {
        let Some(ip_plane) = ip_plane else {
            tracing::error!(
                "the plane peer arrived and the box has no ip plane -- the session is refused"
            );
            let _ = tunnel.close().await;
            return Err(SessionError::Session("the box has no ip plane".to_owned()));
        };
        plane::serve_plane_session(
            tunnel,
            plane,
            ip_plane,
            arrival.map(|addr| addr.port()),
        )
        .await?;
        return Ok(());
    }

    // No plane: the box's own client. The flow plane reads its own messages
    // -- the length prefix in front of every one -- so the tunnel goes to it
    // whole, with nothing taken out of it.
    let plane = FlowPlane::start(tunnel);
    serve_exit(plane, connector).await?;
    Ok(())
}
