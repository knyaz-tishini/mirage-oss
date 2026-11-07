//! The Mirage VPN as a program: a server and a client.
//!
//! # What this crate is
//!
//! The protocol lives in the `mirage-vpn` crate — the VPN variant, built on
//! Mirage's own cores. This crate is the program around it: the config
//! files, the listeners, and the two commands an operator runs.
//!
//! - The **server** listens on the carriers it was given, answers the peers
//!   that come, and carries their flows out to the internet — either directly,
//!   or through a local SOCKS5 proxy (which is how the server's own system
//!   TUN is used).
//! - The **client** dials the server over one carrier and serves a local
//!   SOCKS5, which is the whole surface the application needs: no system TUN,
//!   no routes, no DNS to set up.
//!
//! # The carriers
//!
//! The three of them are the three ways into the same server:
//!
//! - `mwg` — МиражВГ: one UDP port, many peers.
//! - `mkvik` — МиражКВИК: one QUIC endpoint, many peers.
//! - `tunnel` — the TCP port where a session arrives **through a SOCKS5
//!   proxy**: the way to the server when the server cannot be reached
//!   directly.

pub mod client;
pub mod config;
pub mod propose;
pub mod server;

pub use config::{ClientConfig, Exit, Listeners, ServerConfig, ServerPeer, Transport};
pub use propose::{Face, Proposal};

/// What can go wrong.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// A file could not be read or written.
    #[error("the file could not be read: {0}")]
    Io(#[from] std::io::Error),

    /// The config file is not valid JSON.
    #[error("the config file is not valid JSON: {0}")]
    Json(#[from] serde_json::Error),

    /// A key in the config file is not a key.
    #[error("the key is not valid: {0}")]
    Key(String),

    /// The peer table refused a peer.
    #[error("the peer table refused a peer: {0}")]
    Peer(#[from] mirage_vpn::peer::PeerError),

    /// The carrier failed.
    #[error("the carrier failed: {0}")]
    Carrier(#[from] mirage_vpn::carrier::CarrierError),

    /// The SOCKS5 listener failed.
    #[error("the socks5 listener failed: {0}")]
    Socks5(#[from] mirage_vpn::socks5::Socks5Error),

    /// The config file does not make sense.
    #[error("{0}")]
    Config(String),
}
