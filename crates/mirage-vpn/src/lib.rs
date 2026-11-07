//! The **VPN variant** of Mirage.
//!
//! # Where this sits
//!
//! Mirage is three layers, and this crate is the top one of a pair:
//!
//! ```text
//!   +- variants ----------------------------------------------------------+
//!   |  VPN   -- a session between a client and a terminator, no onion      |
//!   |  mesh  -- the same session inside an onion chain of N hops           |
//!   +--------------------------------------------------------------------+
//!   +- modes ------------------------------------------------------------+
//!   |  client -- "I call the terminator"                                  |
//!   |  server -- "I am the terminator"                                    |
//!   +--------------------------------------------------------------------+
//!   +- cores ------------------------------------------------------------+
//!   |  handshake - session - carriers - onion                            |
//!   +--------------------------------------------------------------------+
//! ```
//!
//! The **cores** live in `mirage-protocol`. The **modes** live there too --
//! `mirage_protocol::modes` holds the client and the server that drive the
//! same core. This crate is the **VPN variant**: the part that turns a
//! session into something an application can use.
//!
//! # What the VPN variant is
//!
//! A client dials a terminator, a session comes up between the two, and
//! then the client offers a **SOCKS5** surface to the applications on it.
//! The terminator opens the connections the client asked for and carries the
//! bytes back.
//!
//! ```text
//!   application
//!        |  SOCKS5 CONNECT example.com:443
//!   +----v--------+
//!   | Socks5      |   the local listener
//!   | listener    |
//!   +----+--------+
//!        |  Flow::open(target)
//!   +----v--------+   the session -- the cores
//!   |  FlowPlane  |
//!   +----+--------+
//!        |  MWG - QUIC - a SOCKS5 tube - an onion chain
//!   +----v--------+
//!   | terminator  |
//!   +-------------+
//! ```
//!
//! # The packet plane of the box
//!
//! The client of the **mono-protocol** shape sends WHOLE IP PACKETS inside
//! QUIC datagrams. The box then serves the FULL protocol -- TCP, UDP, ICMP,
//! anything -- by being an **L3 forwarder**: the packets go into the box's
//! own TUN device, the kernel routes and masquerades them to the internet,
//! and the replies come back out of the same device.
//!
//! ```text
//!   the client                 the box                    the internet
//!     |  an IP packet            |                            |
//!     | -----------------------> |  the tun, the kernel  --->|
//!     |                          |                            |
//!     |  an IP packet            |  the tun, the peer map    |
//!     | <----------------------- |                            |
//! ```
//!
//! See [`ip_plane`]. The client side of the same shape needs no system TUN
//! either: the flow plane and the SOCKS5 surface are still there for the
//! older versions of the wire.
//!
//! # The name is not resolved on the near side
//!
//! A CONNECT with a domain name is carried **unresolved** to the exit. The
//! near side never learns what the far side is connecting to, and the DNS
//! query does not leak the fact that a tunnel is in use.
//!
//! # The carriers
//!
//! The session is the same in every case; only the pipe under it differs.
//! See [`carrier`] for the four of them, and `mirage-vpn-mesh` for the onion
//! one -- this crate never learns about the onion.

pub mod carrier;
pub mod channel;
pub mod connector;
pub mod flow;
pub mod ip_plane;
pub mod metrics;
pub mod peer;
pub mod plane;
pub mod session;
pub mod socks5;
pub mod testing;

pub use carrier::{
    CamouflageCarrier, CamouflageListener, Carrier, CarrierError, CarrierListener,
    SocksTunnelCarrier, Stream, TunnelListener, SUITE,
};
pub use channel::{Channel, ChannelError};
pub use connector::{Connector, ConnectorError, FlowStream, Session};
pub use flow::{Flow, FlowError, FlowPlane, FlowReader, FlowWriter, Target};
pub use ip_plane::{
    derive_client_v6, parse_ip, AddressBook, AddressPool, IpHeader, IpPlane, IpPlaneConfig,
    IpPlaneCounters, IpPlaneError, IpPlaneStats, PeerMap, Router, CLIENT_NETWORK,
    CLIENT_NETWORK_V6, TUN_ADDRESS, TUN_ADDRESS_V6, TUN_MTU, TUN_NAME, TUN_PREFIX, TUN_PREFIX_V6,
};
pub use peer::{Peer, PeerError, PeerTable, KEY_LEN};
pub use plane::{serve_plane_session, PlaneError, PLANE_VERSION};
pub use session::{serve as serve_session, SessionError};
pub use socks5::{
    serve_exit, DirectExit, ExitConnector, ExitStream, Socks5Error, Socks5Exit, Socks5Listener,
};
