//! Mirage native branch — all Mirage-specific types.
//!
//! Sub-trees:
//! - [`wire`] — data-path types (RelayMode, ExitMode, Camouflage,
//!   AEAD, Framing, LayerSpec, MirageListenerSpec, ...).
//! - [`mesh`] — routing/identity (MeshId, NodeId, ChainId,
//!   PeerTable, ChainBinding, InterMonitorFrame).

pub mod mesh;
pub mod wire;
