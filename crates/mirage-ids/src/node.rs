use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::IdParseError;
use crate::machine::validate_idlike;
use crate::monitor::MonitorId;

/// Wire-version epoch baked into node id prefix (`v1-`, `v2-`, `v3-`).
/// V2 = current staging-v2 baseline.
///
/// Used by [`NodeId::epoch`] as an optional view. Unknown prefix strings
/// are accepted at construction time — `epoch()` returns `None` for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NodeEpoch {
    V1,
    V2,
    V3,
}

impl NodeEpoch {
    pub fn prefix(&self) -> &'static str {
        match self {
            NodeEpoch::V1 => "v1",
            NodeEpoch::V2 => "v2",
            NodeEpoch::V3 => "v3",
        }
    }

    /// Parse — returns `None` on unknown strings.
    pub fn from_str_opt(s: &str) -> Option<Self> {
        Some(match s {
            "v1" => NodeEpoch::V1,
            "v2" => NodeEpoch::V2,
            "v3" => NodeEpoch::V3,
            _ => return None,
        })
    }
}

impl fmt::Display for NodeEpoch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.prefix())
    }
}

impl FromStr for NodeEpoch {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        NodeEpoch::from_str_opt(s).ok_or_else(|| IdParseError::InvalidChar('?'))
    }
}

/// Logical Mirage onion peer — opaque validated string.
///
/// **Canonical form** for inventory-backed nodes is
/// `<epoch>-<monitor>`, e.g. `v2-ru-hostkey-203.0.113.10`.
///
/// The type accepts any charset-valid id so the generic substrate layer
/// can create nodes without being constrained to known epoch prefixes.
///
/// Structured decomposition: [`NodeId::epoch`] and [`NodeId::monitor`]
/// — both return `Option` and `None` for ids that don't match the
/// structured shape.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct NodeId(Box<str>);

impl NodeId {
    /// Construct with charset/length validation.
    pub fn new(s: impl AsRef<str>) -> Result<Self, IdParseError> {
        let s = s.as_ref();
        validate_idlike(s)?;
        Ok(Self(s.into()))
    }

    /// Construct without validation.
    pub fn from_trusted(s: impl Into<Box<str>>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0.into()
    }

    /// Try to parse the epoch prefix from this node id.
    ///
    /// Returns `None` when the id has no `-` separator or the prefix
    /// doesn't match a known `NodeEpoch` variant.
    pub fn epoch(&self) -> Option<NodeEpoch> {
        let (prefix, _) = self.0.split_once('-')?;
        NodeEpoch::from_str_opt(prefix)
    }

    /// Try to parse the monitor portion from this node id.
    ///
    /// Strips the `<epoch>-` prefix and attempts to parse the rest as a
    /// `MonitorId`. Returns `None` if no `-` is present.
    pub fn monitor(&self) -> Option<MonitorId> {
        let (_, rest) = self.0.split_once('-')?;
        MonitorId::new(rest).ok()
    }
}

impl fmt::Debug for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeId({:?})", self.0)
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for NodeId {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Provider, Region};

    #[test]
    fn accepts_v2_node() {
        let n: NodeId = "v2-ru-hostkey-203.0.113.10".parse().unwrap();
        assert_eq!(n.epoch(), Some(NodeEpoch::V2));
        let mon = n.monitor().unwrap();
        let machine = mon.machine().unwrap();
        assert_eq!(machine.region(), Some(Region::Ru));
        assert_eq!(machine.provider(), Some(Provider::HostKey));
        assert_eq!(n.to_string(), "v2-ru-hostkey-203.0.113.10");
    }

    #[test]
    fn accepts_unknown_epoch() {
        // ZT floor: unknown epoch no longer rejected.
        let n: NodeId = "v99-ru-hostkey-203.0.113.10".parse().unwrap();
        assert_eq!(n.epoch(), None); // unknown, not an error
        assert!(n.monitor().is_some());
    }

    #[test]
    fn accepts_opaque_id() {
        let n = NodeId::new("node-alpha").unwrap();
        assert_eq!(n.as_str(), "node-alpha");
        // "node" is not a known epoch prefix.
        assert_eq!(n.epoch(), None);
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(NodeId::new(""), Err(IdParseError::Empty)));
    }

    #[test]
    fn serde_roundtrip() {
        for s in ["v2-ru-hostkey-203.0.113.10", "v3-ru-hostkey-203.0.113.10"] {
            let n: NodeId = s.parse().unwrap();
            let j = serde_json::to_string(&n).unwrap();
            let back: NodeId = serde_json::from_str(&j).unwrap();
            assert_eq!(n, back);
            assert_eq!(n.to_string(), s);
        }
    }

    #[test]
    fn from_trusted() {
        let n = NodeId::from_trusted("v2-ru-hostkey-203.0.113.10");
        assert_eq!(n.as_str(), "v2-ru-hostkey-203.0.113.10");
    }
}
