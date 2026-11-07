//! Frame layout used inside the AEAD tunnel.

use serde::{Deserialize, Serialize};

/// Per-chain framing axis.
///
/// - `Plain`: one AEAD tunnel cli↔exit, single sealing key.
/// - `Onion`: layered AEAD, each hop has its own layer key, peels
///   one layer on ingress and forwards the remainder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Framing {
    Plain,
    Onion,
}

impl Framing {
    pub fn as_str(self) -> &'static str {
        match self {
            Framing::Plain => "plain",
            Framing::Onion => "onion",
        }
    }
}
