//! Control-plane wire types — monitor ↔ node, monitor ↔ edge,
//! monitor ↔ operator.
//!
//! These types used to live inside `mirage2monitor::monitor::*` files
//! because that's where the HTTP/WS handlers consumed them. The
//! consequence: every other worker that needs to deserialise the same
//! wire (node, mshd, app/edge, operator-client, sentry, db-worker)
//! re-derived a local copy. Now they live here in the shared
//! control-plane crate.
//!
//! Conventions:
//! - All types use `#[serde(tag = "type", rename_all = "snake_case")]`
//!   for the top-level enums so wire JSON remains stable.
//! - Variant payload structs are lifted as separate `pub struct`s so
//!   they're nameable from external code (auction logic, picker,
//!   tests).
//! - Nothing here depends on axum / hyper / tokio-tungstenite. Pure
//!   serde + types from `mirage-core` (`PeerTable`, `ChainBindings`).
//!
//! See nemo/docs/plans/mirage-substrate-cutover-master-plan-2026-05-28.md
//! step D for context.

pub mod monitor_node;
pub mod registration;
pub mod upsert;

pub use monitor_node::{
    ListenerSnapshotEntry, MonitorToNode, NodeEgressObservation, NodeToMonitor,
    PushListenerEntry, SubscriberConsumptionObservation,
};
pub use registration::{NodeRegistration, NodeRegistrationResponse};
pub use upsert::{
    UpsertChainRequest, UpsertChainResponse, UpsertListenerRequest,
    UpsertListenerResponse, UpsertMonitorRequest, UpsertMonitorResponse,
    UpsertPeerRequest, UpsertPeerResponse,
};
