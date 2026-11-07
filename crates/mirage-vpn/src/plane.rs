//! The plane entrance -- the box's side of the packet plane.
//!
//! # What this is
//!
//! The customer's client speaks ONE wire to its own box: the **packet plane**.
//! The client sends an [`EdgeHello`] (version 4), the box answers with an
//! [`EdgeWelcome`](mirage_control_plane::EdgeWelcome), and from then on the
//! whole IP packets ride the QUIC datagrams of the SAME connection. The box's
//! TUN device is the exit -- see [`crate::ip_plane`].
//!
//! ```text
//!   client                                  the box
//!     |  EdgeHello  (version 4)              |
//!     | -------------------------------------->|
//!     |  EdgeWelcome (outcome, face, address) |
//!     | <--------------------------------------|
//!     |        whole IP packets               |
//!     |  QUIC datagrams --------------------->| the box's TUN device is the exit
//!     |  QUIC datagrams <---------------------|
//! ```
//!
//! # The mux is gone
//!
//! Versions 1 to 3 carried TCP flows over a yamux session of the same
//! tunnel. They are not served here any more: this box speaks version 4
//! only, and a peer that asks for an older version is refused by name, so it
//! falls back to a box that still speaks it.
//!
//! The rules and the version numbers live in `mirage_control_plane::peer`,
//! shared with the fleet box and the client.

use std::sync::Arc;

use mirage_control_plane::edge_session::ClientAssignment;
use mirage_control_plane::peer::{wants_assignment, ExitCatalog, PeerProfile};
use mirage_control_plane::{EdgeHello, EdgeOutcome, EdgeSessionError};
use mirage_protocol::plane::PacketPlane;
use mirage_protocol::traits::Tunnel;

use crate::ip_plane::{AddressBook, TUN_PREFIX};

/// The edge-session wire version that carries whole IP packets.
///
/// Version 4 is the plane: the packets ride the datagrams of the same QUIC
/// connection, and the box's TUN device is the exit. The older versions are
/// the mux, and the mux is gone.
///
/// The number lives in [`mirage_control_plane::peer`] -- with every other
/// wire version -- so that the client, the fleet box and this box cannot
/// drift apart.
pub use mirage_control_plane::peer::PLANE_VERSION;

/// The wire this box speaks: the packet plane, version 4.
///
/// The plane profile speaks the plane and nothing else, so a peer that
/// offers an older version is refused by name instead of getting a welcome
/// the box cannot keep.
const PLANE_PROFILE: PeerProfile = PeerProfile::PLANE_ONLY;

/// How many bytes are read at a time while the hello is being assembled.
const ACCUMULATE_CHUNK: usize = 4096;

/// What went wrong on the plane wire.
#[derive(Debug, thiserror::Error)]
pub enum PlaneError {
    /// The session failed.
    #[error("the session failed: {0}")]
    Session(String),
    /// The wire is malformed.
    #[error("the plane wire is malformed: {0}")]
    Wire(#[from] EdgeSessionError),
    /// The peer closed the session before the hello was complete.
    #[error("the peer closed the session")]
    Closed,
}

/// Serve the plane wire: the hello, the welcome, and then the packets.
///
/// The peer speaks version 4: the hello and the welcome ride the control
/// wire, and the packets ride the datagrams of the same QUIC connection.
///
/// A peer that offers an older version is refused politely: this path has no
/// mux, and a version-1-to-3 hello would expect one.
pub async fn serve_plane_session(
    mut tunnel: Box<dyn Tunnel>,
    plane: Arc<dyn PacketPlane>,
    ip_plane: Arc<dyn AddressBook>,
    arrival: Option<u16>,
) -> Result<(), PlaneError> {
    let first = read_first(tunnel.as_mut()).await?;
    let hello = read_hello(tunnel.as_mut(), first).await?;
    let outcome = PLANE_PROFILE.decide_outcome(&hello, &ExitCatalog::AnyRequested);

    // The address the box assigns to this client: every peer behind one box
    // needs its own, or two of them would collide on one address. It is
    // assigned BEFORE the welcome goes out, so the welcome can name it.
    //
    // Only a client that ASKED for an address gets one: the flag in the hello
    // says the client can put the assigned address on its tunnel adapter. An
    // older client has no such flag and keeps the address it always had --
    // the box then learns that address from the packets themselves, the way
    // it did before the pool existed.
    let assignment = match outcome {
        EdgeOutcome::Accepted { .. } if wants_assignment(&hello) => match ip_plane.assign() {
            Some(addr) => {
                // The operator sees which client got which address: it is
                // the first thing to look at when a client's traffic does
                // not arrive.
                tracing::info!(
                    address = %addr,
                    "the client joined the plane with its own address"
                );
                Some(ClientAssignment {
                    addr,
                    prefix: TUN_PREFIX,
                })
            }
            None => {
                // Every address of the client network is taken: the box
                // cannot serve another peer right now.
                tracing::error!("the client address pool is exhausted -- the session is closed");
                let _ = tunnel.close().await;
                return Ok(());
            }
        },
        EdgeOutcome::Accepted { .. } => {
            tracing::info!("the client did not ask for an address -- it keeps the one it always had");
            None
        }
        EdgeOutcome::Refused(_) => None,
    };

    let result = handshake(&mut tunnel, &hello, &outcome, arrival, assignment, &plane, &ip_plane)
        .await;

    // The address goes back to the pool when the session ends, however it
    // ended, and the peer leaves the map with it.
    if let Some(assignment) = assignment {
        ip_plane.release(assignment.addr);
    }
    result
}

/// The welcome, and then the packets.
///
/// The peer owns its address from the moment it joins: the map holds the
/// address before the first packet, so the first reply finds its way home
/// even before the peer sends one of its own.
async fn handshake(
    tunnel: &mut Box<dyn Tunnel>,
    hello: &EdgeHello,
    outcome: &EdgeOutcome,
    arrival: Option<u16>,
    assignment: Option<ClientAssignment>,
    plane: &Arc<dyn PacketPlane>,
    ip_plane: &Arc<dyn AddressBook>,
) -> Result<(), PlaneError> {
    if let Some(assignment) = assignment {
        ip_plane.register_peer(assignment.addr, Arc::clone(plane));
    }

    let welcome = PLANE_PROFILE.welcome_for(
        hello,
        outcome,
        &ExitCatalog::AnyRequested,
        arrival,
        assignment,
    )?;
    let encoded = welcome.encode()?;
    tunnel
        .send(&encoded)
        .await
        .map_err(|err| PlaneError::Session(err.to_string()))?;

    if let EdgeOutcome::Refused(_) = outcome {
        // A peer that asked for another version was refused by name: the
        // plane speaks version 4 only, and the refusal tells the peer to
        // fall back to the version the other paths serve.
        let _ = tunnel.close().await;
        return Ok(());
    }

    // The plane: the peer's packets go into the TUN, and the packets the TUN
    // gives back find their way to the peer.
    //
    // A client that asked for an address owns it from the moment it joins.
    // An older client owns none: the box learns its address from the first
    // packet it sends, the way it did before the pool existed.
    let assigned = assignment.map(|assignment| assignment.addr);
    Arc::clone(ip_plane)
        .serve_peer(Arc::clone(plane), assigned)
        .await;
    let _ = tunnel.close().await;
    Ok(())
}

/// Read the first byte of the session -- the version of the hello.
async fn read_first(tunnel: &mut dyn Tunnel) -> Result<u8, PlaneError> {
    let mut byte = [0u8; 1];
    let count = tunnel
        .recv(&mut byte)
        .await
        .map_err(|err| PlaneError::Session(err.to_string()))?;
    if count == 0 {
        return Err(PlaneError::Closed);
    }
    Ok(byte[0])
}

/// Accumulate reads until a full [`EdgeHello`] decodes.
async fn read_hello(tunnel: &mut dyn Tunnel, first: u8) -> Result<EdgeHello, PlaneError> {
    let mut buf = vec![first];
    loop {
        match EdgeHello::decode(&buf) {
            Ok((hello, _consumed)) => return Ok(hello),
            Err(EdgeSessionError::Truncated { .. }) => {}
            Err(other) => return Err(PlaneError::Wire(other)),
        }
        let mut chunk = [0u8; ACCUMULATE_CHUNK];
        let count = tunnel
            .recv(&mut chunk)
            .await
            .map_err(|err| PlaneError::Session(err.to_string()))?;
        if count == 0 {
            return Err(PlaneError::Closed);
        }
        buf.extend_from_slice(&chunk[..count]);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use mirage_control_plane::peer::PLANE_VERSION;
    use mirage_control_plane::{EdgeRefusal, ExitPreference};

    fn hello(version: u8, flags: u8) -> EdgeHello {
        EdgeHello {
            version,
            exit: ExitPreference::Auto,
            flags,
            offered_ports: Vec::new(),
        }
    }

    #[test]
    fn the_plane_speaks_the_plane_only() {
        let outcome = PLANE_PROFILE.decide_outcome(&hello(PLANE_VERSION, 0), &ExitCatalog::AnyRequested);
        assert_eq!(outcome, EdgeOutcome::Accepted { exit: ExitPreference::Auto });
    }

    #[test]
    fn an_older_version_is_refused_by_name() {
        for version in [1, 2, 3] {
            let outcome = PLANE_PROFILE.decide_outcome(&hello(version, 0), &ExitCatalog::AnyRequested);
            assert_eq!(
                outcome,
                EdgeOutcome::Refused(EdgeRefusal::UnsupportedVersion {
                    requested: version,
                    supported: PLANE_VERSION
                })
            );
        }
    }

    #[test]
    fn the_welcome_names_the_assigned_address() {
        let hello = hello(PLANE_VERSION, EdgeHello::FLAG_ACCEPTS_ASSIGNMENT);
        let outcome = PLANE_PROFILE.decide_outcome(&hello, &ExitCatalog::AnyRequested);
        let assignment = ClientAssignment {
            addr: std::net::Ipv4Addr::new(10, 77, 0, 7),
            prefix: TUN_PREFIX,
        };
        let welcome = PLANE_PROFILE
            .welcome_for(
                &hello,
                &outcome,
                &ExitCatalog::AnyRequested,
                Some(41443),
                Some(assignment),
            )
            .expect("a plane welcome");
        assert_eq!(welcome.version, PLANE_VERSION);
        assert_eq!(welcome.assigned_face_port, Some(41443));
        assert_eq!(welcome.carries_datagrams, Some(true));
        assert_eq!(welcome.assigned_client, Some(assignment));
        welcome.encode().expect("the welcome encodes");
    }
}
