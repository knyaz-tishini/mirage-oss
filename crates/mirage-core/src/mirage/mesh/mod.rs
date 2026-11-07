//! Mesh plane — routing, identity, control.
//!
//! Independent of the wire plane. Describes WHERE bytes go (which nodes
//! at which positions in which chain) — not how they're encrypted.
//!
//! See `docs/plans/mirage-architecture-clean-taxonomy.md` §Layer 0.

pub mod chain_binding;
pub mod ids;
pub mod inter_monitor;
pub mod peer_table;

pub use chain_binding::{
    ChainBinding, ChainBindings, ChainExit, ChainLeg, OnionReplyMode,
};
pub use ids::{ChainId, MeshId, NodeId};
pub use inter_monitor::InterMonitorFrame;
pub use peer_table::{ChainFace, NodeEndpoint, NodeFingerprint, PeerTable, PeerTableEntry};
