//! The protocol cores — the parts that know nothing about the variant.
//!
//! # What is a core
//!
//! A core is a piece of the protocol that is **the same in every variant**.
//! It does not know whether it is carrying a VPN session or an onion layer,
//! and it does not know whether the peer on the other side is a client or a
//! server. That ignorance is the point: the cores are the parts that are
//! written once and proven once.
//!
//! | core | what it does |
//! |---|---|
//! | [`handshake`] | the V9 handshake over a byte stream |
//! | [`udp_handshake`] | the same handshake over datagrams |
//! | [`tunnel`] | the session over a byte stream (AEAD frames) |
//! | [`udp_tunnel`] | the session over datagrams (one frame per datagram) |
//! | [`carriers`] | the pipes a session may ride in — the carrier axes |
//! | [`onion`] | the onion layers — **mesh only** |
//!
//! # What is NOT a core
//!
//! The **modes** (`mirage_protocol::modes`) are the client and the server.
//! The **variants** are the products built on the cores:
//!
//! - `mirage-vpn` — the VPN variant: a session between a client and a
//!   terminator, with a flow plane and a SOCKS5 surface;
//! - `mirage-vpn-mesh` — the mesh variant: the same session inside an onion
//!   chain of any length.
//!
//! The difference between the two variants is **not** the core: it is what
//! stands between the core and the payload. In the VPN variant the payload
//! rides on an end-to-end session; in the mesh variant the payload rides
//! inside onion layers, and every hop peels exactly one.
//!
//! ```text
//!   ┌─ variants ──────────────────────────────────────────────────┐
//!   │  VPN   — client ↔ terminator, no onion                       │
//!   │  mesh  — N onion hops, each peels one layer                 │
//!   └──────────────────────────────────────────────────────────────┘
//!   ┌─ modes ──────────────────────────────────────────────────────┐
//!   │  client — "I call the terminator"                            │
//!   │  server — "I am the terminator, or I am a hop"              │
//!   └──────────────────────────────────────────────────────────────┘
//!   ┌─ cores (this module) ────────────────────────────────────────┐
//!   │  handshake · session · carriers · onion                      │
//!   └──────────────────────────────────────────────────────────────┘
//! ```

pub mod carriers;
pub mod handshake;
pub mod onion;
pub mod tunnel;
pub mod udp_handshake;
pub mod udp_tunnel;

pub use handshake::{
    run_client_handshake, run_client_handshake_v9,
    run_server_handshake, run_server_handshake_v9, run_server_handshake_with_auth,
    ClientHandshakeResult, ServerHandshakeResult, ClientAuthContext,
};
pub use udp_handshake::{
    run_client_handshake_v9_datagram, run_client_handshake_v9_datagram_with_credential,
    run_server_handshake_v9_datagram, ServerHelloCache, MAX_CREDENTIAL_LEN_DATAGRAM,
};
pub use tunnel::MirageCoreTunnel;
pub use udp_tunnel::{MirageCoreUdpTunnel, UdpTunnelReceiver, UdpTunnelSender};
