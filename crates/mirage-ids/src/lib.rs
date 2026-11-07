//! Strongly-typed identifiers used across the Mirage stack.
//!
//! Single canonical home for all identity primitives. Zero I/O — no tokio,
//! no parking_lot, no global state. Deps: serde, thiserror, uuid, blake3.
//!
//! ## Types
//!
//! ### Machine hierarchy (S3 — richest/strictest)
//! - [`MachineId`] — physical VPS/box (`ru-hostkey-203.0.113.10`)
//! - [`MonitorId`] — logical monitor on a machine
//! - [`NodeId`] — Mirage onion peer
//! - [`MeshId`] — environment scope (`v3-staging`)
//! - [`MeshScoped<T>`] — (mesh, T) composite key
//! - [`derive_client_label`] — opaque, client-facing label derived from a
//!   `self_id`; never provider/region/machine-id-shaped
//!
//! ### Client identity
//! - [`SentinelId`] — L0 sentinel UUID (per client box)
//! - [`ClientId`] — server-registered client id
//!
//! ### Wire addressing
//! - [`ChainId`] — monitor-allocated chain key
//! - [`EpochId`] — (role, generation) cohabitation primitive
//!
//! ### Object identity
//! - [`ObjectId`] — blake3(kind || canonical_spec)
//! - [`ObjectKind`] — `&'static str` discriminator
//!
//! ## Serde
//!
//! Every id type serializes as its `Display` string and deserializes via
//! `FromStr`, so wire/json/sqlite formats stay unchanged.

pub mod chain;
pub mod client;
pub mod epoch;
pub mod error;
pub mod machine;
pub mod mesh;
pub mod monitor;
pub mod node;
pub mod object;
pub mod scoped;
pub mod sentinel;

pub use chain::ChainId;
pub use client::{ClientId, ClientKind};
pub use epoch::{EpochId, EpochPortError, EpochRole};
pub use error::IdParseError;
pub use machine::{derive_client_label, MachineParts, MachineId, Provider, Region};
pub use mesh::MeshId;
pub use monitor::MonitorId;
pub use node::{NodeEpoch, NodeId};
pub use object::{ObjectId, ObjectKind};
pub use scoped::{MeshMonitorKey, MeshNodeKey, MeshScoped};
pub use sentinel::SentinelId;
