//! Mirage listener kinds — what kind of socket binds at this listener.
//!
//! Position (Entry/Hop/Exit) is orthogonal — encoded in [`super::ListenerRole`].

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirageListenerKind {
    /// Main TCP — Entry/Hop/Exit on the main TCP path (Mirage AEAD inside).
    TunnelTcp,
    /// Main UDP — Entry/Hop/Exit on the main UDP path.
    TunnelUdp,
    /// Multi-hop UDP relay node (no Mirage AEAD on this hop — used as a
    /// transparent or byte-cipher relay leg in a UDP chain).
    UdpRelay,
    /// Exit-bridge to monitor over-chain control loopback (default `127.0.0.1:19445`).
    TunnelControl,
    /// Peek-multiplex front — sniffs the first 512 bytes and dispatches.
    Decoy,
    /// Multi-backend decoy variant.
    DecoyMulti,
}

impl MirageListenerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::TunnelTcp => "tunnel_tcp",
            Self::TunnelUdp => "tunnel_udp",
            Self::UdpRelay => "udp_relay",
            Self::TunnelControl => "tunnel_control",
            Self::Decoy => "decoy",
            Self::DecoyMulti => "decoy_multi",
        }
    }
}
