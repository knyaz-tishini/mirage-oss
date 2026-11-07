//! Chain binding — per-`chain_id` configuration distributed by the
//! monitor via `PushChainBinding` WS frame.
//!
//! `ChainBinding` is the **single source of truth** for what a client
//! sees when it dials a chain. Each leg carries:
//!  - the [`RelayMode`] expected at that hop (what to peel),
//!  - the [`AeadSuite`] preference.
//!
//! The exit carries [`ExitMode`] + AEAD.
//!
//! **Outbound camouflage does not live here.** A hop's disguise is the
//! TARGET's own published face — `PeerTableEntry.chain_face`, read at dial
//! time by the dialer (a hop reading its next hop's face, or the client
//! reading the entry's) — never something this binding hands out. `ChainLeg`
//! and `ChainExit` used to carry a `camouflage` field the monitor invented
//! from `spec.camouflage`, which had no relationship to what the target's own
//! perimeter actually strips; that field is gone (2026-09-02).
//!
//! Client dial dispatches by the chain of `RelayMode`s, NOT by `hops.len()`.
//! That eliminates the long-standing client-side onion gate bug (multihop
//! byte_cipher chains used to fall into the onion path because
//! `hops.len() > 1` was the only discriminator).
//!
//! Leaking a `ChainBinding` reveals route topology only — every per-hop key
//! is ephemeral and lives on the client + node for the duration of one
//! connection. The monitor never holds payload keys.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::mirage::wire::{AeadSuite, ByteCipherMode, ExitMode, RelayMode};

use super::ids::{ChainId, MeshId, NodeId};

/// One full chain — N relay legs + exit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainBinding {
    pub mesh_id: MeshId,
    pub chain_id: ChainId,
    /// Relay-leg sequence, entry first. May be empty for single-hop
    /// chains (then only `exit` is present).
    #[serde(default)]
    pub legs: Vec<ChainLeg>,
    pub exit: ChainExit,
    /// Onion reply mode for chains using onion framing. `None` on plain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub onion_reply_mode: Option<OnionReplyMode>,
    /// Handshake strategy for the whole circuit. `Telescopic` (the only
    /// variant, and what an absent value also materializes to — see
    /// `mirage-mesh-client::materialize`) is the V9-FS forward-secret onion,
    /// requiring every hop to advertise `OnionHandshakeKind::ForwardSecret`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handshake: Option<crate::config::HandshakeStrategy>,
}

/// One relay leg in a chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainLeg {
    pub node_id: NodeId,
    /// What this hop does to ingress bytes (transparent / byte-cipher peel /
    /// onion peel). Client mirrors this when wrapping outbound.
    pub relay_mode: RelayMode,
    /// AEAD suite preference for this leg's handshake.
    #[serde(default)]
    pub aead_suite: AeadSuite,
    /// Orthogonal byte_cipher wire-skin the client wraps the dial-to-this-hop in
    /// (magic/junk/xor). Independent of `relay_mode`: a crypto_verify leg peels
    /// it as its routing, an onion-ENTRY leg strips it as an outer DPI skin
    /// before the onion handshake. `None` = no skin. Only the entry leg ever
    /// carries it (the client→entry link is what DPI sees).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_cipher: Option<ByteCipherMode>,
    /// The selector token the client puts in the frame addressed to this hop,
    /// hex-encoded. Mirrors `ChainRole::selector_token_hex` on the listener
    /// side — the monitor mints one value and writes it to both, so what the
    /// client sends and what the hop answers to are the same fact.
    ///
    /// `None` from an older monitor: the client then sends no token and the
    /// hop falls back to the derived selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector_token_hex: Option<String>,

}

/// Chain exit (terminator).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainExit {
    pub node_id: NodeId,
    pub exit_mode: ExitMode,
    #[serde(default)]
    pub aead_suite: AeadSuite,
    /// The selector token the client puts in the frame addressed to this hop,
    /// hex-encoded. Mirrors `ChainRole::selector_token_hex` on the listener
    /// side — the monitor mints one value and writes it to both, so what the
    /// client sends and what the hop answers to are the same fact.
    ///
    /// `None` from an older monitor: the client then sends no token and the
    /// hop falls back to the derived selector.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector_token_hex: Option<String>,
}

/// Reply-path framing for onion chains.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnionReplyMode {
    /// Each reply chunk wrapped per-hop with a 4-byte length prefix;
    /// client peels per-hop AEAD on the way back.
    Onion,
    /// Reply bytes copied bidirectionally without wrapping.
    Raw,
}

impl ChainBinding {
    /// `true` when there are no relay legs — chain is just (client → exit).
    pub fn is_direct(&self) -> bool {
        self.legs.is_empty()
    }

    /// Total hop count (relay legs + exit).
    pub fn hop_count(&self) -> usize {
        self.legs.len() + 1
    }

    /// `true` when any leg uses [`RelayMode::OnionPeel`].
    /// Client dispatches the onion-tunnel path iff this is true.
    pub fn uses_onion(&self) -> bool {
        self.legs
            .iter()
            .any(|leg| matches!(leg.relay_mode, RelayMode::OnionPeel))
            || matches!(self.exit.exit_mode, ExitMode::Onion)
    }

    /// Find the leg owned by `node_id`, if any.
    pub fn leg_for(&self, node_id: &NodeId) -> Option<&ChainLeg> {
        self.legs.iter().find(|l| &l.node_id == node_id)
    }

    /// Find a leg by index (entry=0, last relay = legs.len()-1).
    pub fn leg(&self, index: usize) -> Option<&ChainLeg> {
        self.legs.get(index)
    }

    /// Find hop index by node_id string. 0 = first leg, `legs.len()` = exit.
    /// `None` if `node_id` is not in this chain. (Legacy compat helper.)
    pub fn hop_index_by_str(&self, node_id: &str) -> Option<usize> {
        if let Some(i) = self.legs.iter().position(|l| l.node_id.as_str() == node_id) {
            return Some(i);
        }
        if self.exit.node_id.as_str() == node_id {
            return Some(self.legs.len());
        }
        None
    }

    /// Node id of the next hop after `node_id`. `None` if `node_id` is
    /// the exit. (Returns exit node_id for the last relay leg.)
    pub fn next_hop_id(&self, node_id: &str) -> Option<&NodeId> {
        let idx = self.hop_index_by_str(node_id)?;
        let next = idx + 1;
        if next < self.legs.len() {
            Some(&self.legs[next].node_id)
        } else if next == self.legs.len() {
            Some(&self.exit.node_id)
        } else {
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::HandshakeStrategy,
        mirage::wire::{AeadSuite, ExitMode},
        mirage::mesh::ids::{ChainId, MeshId, NodeId},
    };

    fn minimal_binding(handshake: Option<HandshakeStrategy>) -> ChainBinding {
        ChainBinding {
            mesh_id: MeshId::new("v3-staging"),
            chain_id: ChainId::new("test-chain"),
            legs: vec![],
            exit: ChainExit {
                node_id: NodeId::new("v2-exit"),
                exit_mode: ExitMode::Direct,
                aead_suite: AeadSuite::ChaCha20Poly1305,
                selector_token_hex: None,
            },
            onion_reply_mode: None,
            handshake,
        }
    }

    #[test]
    fn handshake_telescopic_roundtrips() {
        let original = minimal_binding(Some(HandshakeStrategy::Telescopic));
        let json = serde_json::to_string(&original).expect("serialize");
        assert!(json.contains("telescopic"), "JSON must contain field value: {json}");
        let decoded: ChainBinding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.handshake, Some(HandshakeStrategy::Telescopic));
    }

    #[test]
    fn handshake_absent_deserializes_to_none() {
        // Serialize a binding with handshake=None (field omitted), then strip
        // any handshake key and re-deserialize — must still yield None.
        let binding = minimal_binding(None);
        let json = serde_json::to_string(&binding).expect("serialize");
        // Field is already absent (skip_serializing_if = "Option::is_none").
        assert!(!json.contains("handshake"), "field must be absent in JSON: {json}");
        let decoded: ChainBinding = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decoded.handshake, None);
    }

    #[test]
    fn handshake_none_omitted_from_json() {
        let binding = minimal_binding(None);
        let json = serde_json::to_string(&binding).expect("serialize");
        assert!(!json.contains("handshake"), "absent field must be omitted: {json}");
    }
}

/// Full bindings snapshot pushed by the monitor.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ChainBindings {
    pub generation: u64,
    pub bindings: Vec<ChainBinding>,
}

impl ChainBindings {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn lookup(&self, chain_id: &ChainId) -> Option<&ChainBinding> {
        self.bindings.iter().find(|b| &b.chain_id == chain_id)
    }

    /// Legacy compat helper — accept `&str`.
    pub fn lookup_by_str(&self, chain_id: &str) -> Option<&ChainBinding> {
        self.bindings.iter().find(|b| b.chain_id.as_str() == chain_id)
    }

    pub fn as_map(&self) -> HashMap<&ChainId, &ChainBinding> {
        self.bindings.iter().map(|b| (&b.chain_id, b)).collect()
    }
}
