//! Wire transport — TCP or UDP at the OS-socket level.
//!
//! Independent of camouflage (which wraps the transport)
//! and of framing (which lives inside the AEAD tunnel).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransportKind {
    Tcp,
    Udp,
}

impl TransportKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TransportKind::Tcp => "tcp",
            TransportKind::Udp => "udp",
        }
    }
}
