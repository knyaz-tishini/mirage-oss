//! One leg's wire spec — what wraps the bytes going through it.
//!
//! A leg is the directed edge between two adjacent nodes in the chain.
//! `ingress_layer` describes what arrives on this listener's bind socket;
//! `outgoing_layer` (on Entry/Hop) describes what this node wraps the
//! outbound dial in toward the next hop.
//!
//! `byte_cipher` here is the SKIN. It is an axis of its own, set on the onion
//! ENTRY hop when a chain asks for one — an outer transport obfuscation the
//! client writes on the first dial and the entry strips before reading the
//! envelope. `None` on every other hop, and on an entry that asks for no skin.
//!
//! It used to read "present iff [`RelayMode::CryptoVerify`]"; that mode was
//! removed on 2026-09-02 and the skin was not.
//!
//! [`RelayMode`]: super::RelayMode

use serde::{Deserialize, Serialize};

use super::{AuthMode, ByteCipherMode, RelayMode, TransportCamouflage};

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct LayerSpec {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camouflage: Option<TransportCamouflage>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub byte_cipher: Option<ByteCipherMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<AuthMode>,
    /// Per-leg `RelayMode` — set on `ChainBinding.legs[]` to tell the
    /// client which dial path to take for this hop. `None` on legacy
    /// bindings deserializes as OnionPeel at the client side.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_mode: Option<RelayMode>,
}

impl LayerSpec {
    pub fn is_passive(&self) -> bool {
        self.camouflage.is_none()
            && self.byte_cipher.is_none()
            && self.auth.is_none()
            && self.relay_mode.is_none()
    }
}
