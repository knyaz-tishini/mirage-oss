//! The modes — how the same core is driven from each side.
//!
//! # Two modes, one core
//!
//! A **client** mode is «I call the terminator»: it picks the carrier, runs
//! the handshake as the initiator, and hands the session to the data plane.
//!
//! A **server** mode is «I am the terminator, or I am a hop»: it answers the
//! carrier, runs the handshake as the responder, and hands the session to the
//! data plane — or, in the mesh, to the next hop.
//!
//! Both modes use the **same cores** (`mirage_protocol::cores`). Neither mode
//! knows about the variant: the VPN variant and the mesh variant differ in
//! what stands between the session and the payload, not in the handshake.
//!
//! | mode | entry point |
//! |---|---|
//! | client | [`client_transport::run_client_v9_transport_aware`] — picks the carrier by itself |
//! | server | [`driver::run_server_tcp_with_auth`], [`driver::run_server_udp_with_auth`] |
//!
//! The names of the two modes are the modes of the **familiar** protocol —
//! they are the ones that were already without an onion layer, and they are
//! the ones the fleet runs today.

pub mod client_transport;
pub mod driver;

pub use client_transport::run_client_v9_transport_aware;
