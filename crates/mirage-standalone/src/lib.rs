//! `mirage-standalone` — the server half of Mirage for the standalone client.
//!
//! A standalone box is a machine the customer owns: the operator installs one
//! image on it, and the box holds nothing but **its own keys** plus **one
//! artefact line** for the client. Everything in this crate is that local
//! state:
//!
//! * [`identity`] — the four keys a box owns (wire, operator, subscriber
//!   issuer, subscriber) and the personal `mesh_id` it mints once.
//! * [`subscriber`] — the issuer-signed subscriber allowlist the box enforces
//!   against its own clients.
//! * [`artefact`] — the `client.link` JSON the customer hands to the client.
//! * [`env`] — the `server.env` configuration file the installer writes.
//! * [`profile`] — the three `server.env` bodies `m1r4g3-server env` prints.
//! * [`faces`] — what this box could publish: the ports that are free on it
//!   and the set of faces a person is offered.
//! * [`chain`] — the chain this box belongs to, from TOML or from the env.
//! * [`control_plane`] — the listener spec, peer table and chain bindings the
//!   box builds for itself, in place of the ones a monitor would push.
//! * [`node`] — the node runtime those three objects feed.
//! * [`exit_port`] — the box's own exit: the local answer to the OSS layer's
//!   stream and datagram exit ports.
//! * [`udp_endpoint`] — Mirage over UDP, including the junk mask. The node
//!   binds it and the Mirage entrance admits it.
//! * [`protocol_door`] — every other protocol, beside the perimeter. The
//!   real handshake, then raw bytes. No Mirage handshake. A relay door
//!   forwards to the host named in the preamble and speaks no handshake.
//! * [`box_runtime`] — the box as it runs: the perimeter in front, the client
//!   entrance inside, the box's own exit behind it.
//!
//! # Scope of this slice
//!
//! This slice is **local state + config + artefact + the node's own data
//! plane**. A standalone box has no monitor and no capsule: its identity comes
//! from [`identity`], its chain from [`chain`], and the objects a fleet node
//! receives over the monitor's control channel are built locally by
//! [`control_plane`]. The [`node`] module wires them into the node's own
//! runtime, listener registry and chain splice, and the `m1r4g3-server`
//! binary's `run` command serves them.
//!
//! The interfaces are shaped so the data plane can be attached without
//! rework: every type here is the wire type the rest of the fleet already
//! speaks, not a private dialect.
//!
//! # What lives where
//!
//! On the box's data directory (`/data` in the shipped image):
//!
//! | file | written by | contents |
//! |---|---|---|
//! | `identity.json` | [`identity::load_or_mint`] | the box's own private keys — mode 0600 on Unix |
//! | `subscriber.set` | [`subscriber::write_subscriber_set`] | the issuer-signed subscriber allowlist |
//! | `client.link` | [`artefact::write_client_link`] | one line of JSON — the customer's artefact |
//!
//! Nothing else is persisted by this crate, and no secret ever reaches a log
//! line or an error message.

#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(missing_debug_implementations)]

pub mod artefact;
pub mod box_runtime;
pub mod chain;
pub mod chain_leg;
pub mod control_plane;
pub mod env;
pub mod exit_port;
pub mod faces;
pub mod identity;
pub mod node;
pub mod profile;
pub mod protocol_door;
pub mod subscriber;
pub mod udp_endpoint;

mod fsio;
