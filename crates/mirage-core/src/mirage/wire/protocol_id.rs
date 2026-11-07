//! Carrier of the Mirage protocol on the AEAD tunnel.
//!
//! `Mirage` and `MirageUdp` are one protocol. The variant selects the carrier,
//! TCP or UDP. The protocol catalog lives in `mirage-protocol::protocols`.

use serde::{Deserialize, Serialize};

/// TCP carrier of Mirage. The name is the historical JSON value `"Mirage"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TcpProtocolId {
    Mirage,
}

/// UDP carrier of Mirage. The name is the historical JSON value `"MirageUdp"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum UdpProtocolId {
    MirageUdp,
}

/// Wrapper for fields that can hold either transport type.
///
/// JSON serialises flat: `"Mirage"` / `"MirageUdp"`, not `{"Tcp":"Mirage"}`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProtocolId {
    Tcp(TcpProtocolId),
    Udp(UdpProtocolId),
}

/// TCP or UDP under the one Mirage protocol.
///
/// JSON is `"tcp"` / `"udp"`. This is not [`ProtocolId`]: that one still
/// serialises as `"Mirage"` / `"MirageUdp"`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MirageCarrier {
    Tcp,
    Udp,
}

impl ProtocolId {
    pub fn is_tcp(&self) -> bool {
        matches!(self, ProtocolId::Tcp(_))
    }

    pub fn is_udp(&self) -> bool {
        matches!(self, ProtocolId::Udp(_))
    }

    /// Mirage on the given carrier. Both historical names decode to this.
    pub fn mirage(carrier: MirageCarrier) -> Self {
        match carrier {
            MirageCarrier::Tcp => ProtocolId::Tcp(TcpProtocolId::Mirage),
            MirageCarrier::Udp => ProtocolId::Udp(UdpProtocolId::MirageUdp),
        }
    }

    /// The carrier, when this id is Mirage.
    pub fn mirage_carrier(self) -> Option<MirageCarrier> {
        match self {
            ProtocolId::Tcp(TcpProtocolId::Mirage) => Some(MirageCarrier::Tcp),
            ProtocolId::Udp(UdpProtocolId::MirageUdp) => Some(MirageCarrier::Udp),
        }
    }
}

impl serde::Serialize for ProtocolId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            ProtocolId::Tcp(t) => t.serialize(s),
            ProtocolId::Udp(u) => u.serialize(s),
        }
    }
}

impl<'de> serde::Deserialize<'de> for ProtocolId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        if let Ok(t) =
            serde_json::from_value::<TcpProtocolId>(serde_json::Value::String(s.clone()))
        {
            return Ok(ProtocolId::Tcp(t));
        }
        if let Ok(u) =
            serde_json::from_value::<UdpProtocolId>(serde_json::Value::String(s.clone()))
        {
            return Ok(ProtocolId::Udp(u));
        }
        Err(serde::de::Error::unknown_variant(&s, &["Mirage", "MirageUdp"]))
    }
}

impl std::fmt::Display for TcpProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Mirage => write!(f, "mirage"),
        }
    }
}

impl std::fmt::Display for UdpProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MirageUdp => write!(f, "mirage-udp"),
        }
    }
}

impl std::fmt::Display for ProtocolId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Tcp(t) => t.fmt(f),
            Self::Udp(u) => u.fmt(f),
        }
    }
}
