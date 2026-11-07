//! The leg of a chain: the part that puts a customer's session into a chain
//! and brings it out at the exit.
//!
//! # What this crate is
//!
//! Two boxes that both put a customer's bytes into a chain were doing the
//! same four things in two places, and the four things are the ones that must
//! not drift apart:
//!
//! * building the chain's configuration — the stream plane and the datagram
//!   plane, which are two chains;
//! * minting the `RoleSigned` credential, bound to the exit's node id;
//! * building the protocol chain the leg is spoken over — V9, with the
//!   credential in it;
//! * dialling the chain and carrying the customer's bytes.
//!
//! This crate is those four things. `mirage-standalone` and `mirage2node`'s
//! edge fleet are its consumers: each of them keeps its own way of describing
//! a chain and hands this crate a [`LegSpec`].
//!
//! # The two planes
//!
//! The chain's two planes are two chains, not one chain with two ways to
//! speak:
//!
//! * the **stream** plane carries the customer's TCP;
//! * the **datagram** plane carries the customer's UDP over a native UDP
//!   tunnel, with its own handshake and its own frames — a datagram stays a
//!   datagram all the way down and never rides a stream.
//!
//! A chain whose hops have no datagram door carries TCP only, and says so
//! out loud rather than sending the datagram out of the wrong box.
//!
//! # The credential
//!
//! The credential is bound to the exit's node id: a leg that is replayed at a
//! different box does not verify there.

pub mod config;
pub mod credential;
pub mod leg;
pub mod protocol;
pub mod spec;

pub use config::{build_datagram_config, build_stream_config};
pub use credential::mint_credential;
pub use leg::{write_target, ChainLeg, LegError};
pub use protocol::{build_protocol_chain, LEG_WIRE_VERSION};
pub use spec::{LegHop, LegSpec};
