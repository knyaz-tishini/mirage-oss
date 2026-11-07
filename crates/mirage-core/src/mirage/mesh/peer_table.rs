//! Peer table — `node_id → (pubkey, addr)` map distributed by the
//! monitor via `PushPeerTable` WS frame.
//!
//! Identity is gossip state — never cached in `ListenerSpec`. On every
//! handshake the listener resolves the static pubkeys for the chain hops
//! from the live snapshot here.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::mirage::wire::{AeadSuite, TransportCamouflage};

use super::ids::{MeshId, NodeId};

/// A node's own signed chain-data-plane face — the port a chain hop dials
/// this node on, and the exact camouflage this node's OWN perimeter will
/// strip there.
///
/// The camouflage travels with the port rather than being derived by the
/// dialer, because it is the TARGET's fact, not the dialer's choice: the
/// target's perimeter strips its own published face shape, so a dialer that
/// guesses — or is handed one invented from a chain spec, as the chain
/// binding used to do — is refused by that perimeter exactly like a
/// scanner. Bundled in one struct (not two independent `Option` fields)
/// because a port without its camouflage is not dialable and a camouflage
/// without its port is not addressable; the fact is the pair or it is
/// absent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainFace {
    /// The port this node's chain-data-plane face listens on — it is no
    /// longer TCP-only: a node now mints a stream (`chain_face`) and a
    /// datagram (`chain_face_udp`) face, each carrying its own port.
    pub port: u16,
    /// Outer camouflage this node's perimeter strips on that port.
    pub camouflage: TransportCamouflage,
}

/// One peer in the table.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerTableEntry {
    pub mesh_id: MeshId,
    /// Which monitor has direct control over this node (proxy-hop routing).
    /// Empty = the current monitor.
    #[serde(default)]
    pub responsible_monitor_id: String,
    pub node_id: NodeId,
    /// X25519 public key, hex-encoded (32 bytes → 64 chars).
    pub pubkey_hex: String,
    /// Reachable `host:port`. Resolved at dial time.
    pub addr: String,
    /// Free-form region labels (NL / TR / RU / ch / ...).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<String>,
    /// Unix-ms timestamp of last upsert (LWW conflict resolution).
    #[serde(default)]
    pub updated_at_ms: u64,
    /// Server-ranked AEAD suite preference. Client intersects with its
    /// offered suites at dial time; first match wins.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aead_suite_preference: Vec<AeadSuite>,
    /// This node's own signed chain-data-plane face — see [`ChainFace`].
    /// `None` means "this node has not published a chain face yet", never a
    /// made-up one: absent is a fact (wait for gossip to converge, or the
    /// box needs re-issuing — see `mirage2monitor`'s `NoChainFace`), not a
    /// default to fall back on. A hop dialing the next hop reads this
    /// field instead of a chain-spec-derived guess.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_face: Option<ChainFace>,
    /// This node's own signed DATAGRAM chain-data-plane face — the
    /// `RawUdp` face persona mints beside the stream one. Same rules as
    /// [`Self::chain_face`]: `None` is a fact (not published / box not
    /// re-issued with a datagram face), never a default to dial.
    ///
    /// `#[serde(default)]` keeps an older monitor/node that does not know
    /// this field wire-compatible in both directions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_face_udp: Option<ChainFace>,
}

/// Full peer-table snapshot pushed by the monitor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerTable {
    pub generation: u64,
    pub peers: Vec<PeerTableEntry>,
}

impl PeerTable {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn lookup(&self, node_id: &NodeId) -> Option<&PeerTableEntry> {
        self.peers.iter().find(|p| &p.node_id == node_id)
    }

    pub fn lookup_by_str(&self, node_id: &str) -> Option<&PeerTableEntry> {
        self.peers.iter().find(|p| p.node_id.as_str() == node_id)
    }

    pub fn as_map(&self) -> HashMap<&NodeId, &PeerTableEntry> {
        self.peers.iter().map(|p| (&p.node_id, p)).collect()
    }
}

/// One node's published endpoint (used during peer announcement).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeEndpoint {
    pub addr: String,
    pub pubkey_hex: String,
}

/// BLAKE3 over the canonical node identity tuple (node_id + pubkey + addr).
/// Used for change detection during peer upserts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeFingerprint(pub [u8; 32]);
