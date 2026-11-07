use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::IdParseError;
use crate::mesh::MeshId;
use crate::monitor::MonitorId;
use crate::node::NodeId;

/// Composite (mesh, T) — the *real* key for any cross-mesh-aware lookup
/// (peer_health matrix, peer_registry, chain_bindings dispatch table).
///
/// Wire / display format: `"<mesh>::<inner>"`. Two-colon separator is
/// deliberately distinct from `-` so the two parts are unambiguously
/// splittable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MeshScoped<T> {
    pub mesh: MeshId,
    pub inner: T,
}

impl<T> MeshScoped<T> {
    pub fn new(mesh: MeshId, inner: T) -> Self {
        Self { mesh, inner }
    }
}

impl<T: fmt::Display> fmt::Display for MeshScoped<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}", self.mesh, self.inner)
    }
}

impl<T: FromStr<Err = IdParseError>> FromStr for MeshScoped<T> {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut parts = s.splitn(2, "::");
        let head = parts.next().ok_or_else(|| IdParseError::BadScopedShape(s.into()))?;
        let tail = parts.next().ok_or_else(|| IdParseError::BadScopedShape(s.into()))?;
        if tail.is_empty() {
            return Err(IdParseError::BadScopedShape(s.into()));
        }
        Ok(Self {
            mesh: head.parse()?,
            inner: tail.parse()?,
        })
    }
}

impl<T: fmt::Display> Serialize for MeshScoped<T> {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(self)
    }
}

impl<'de, T: FromStr<Err = IdParseError>> Deserialize<'de> for MeshScoped<T> {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Type alias for `MeshScoped<MonitorId>` — the key in `peer_health.matrix`
/// and `peer_registry`. Replaces the legacy `lm_id: String` that mixed mesh
/// and monitor by string-concatenation.
pub type MeshMonitorKey = MeshScoped<MonitorId>;

/// Type alias for `MeshScoped<NodeId>` — used when dispatching listener
/// specs across LMs (a node is uniquely identified by (mesh, node_id)).
pub type MeshNodeKey = MeshScoped<NodeId>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_and_parse() {
        let mesh: MeshId = "v3-staging".parse().unwrap();
        let mon: MonitorId = "ru-hostkey-203.0.113.10".parse().unwrap();
        let key = MeshScoped::new(mesh.clone(), mon.clone());
        assert_eq!(key.to_string(), "v3-staging::ru-hostkey-203.0.113.10");
        let back: MeshMonitorKey = "v3-staging::ru-hostkey-203.0.113.10".parse().unwrap();
        assert_eq!(back, key);
    }

    #[test]
    fn rejects_missing_separator() {
        let r: Result<MeshMonitorKey, _> = "v3-staging-ru-hostkey-203.0.113.10".parse();
        assert!(matches!(r, Err(IdParseError::BadScopedShape(_))));
    }

    #[test]
    fn rejects_empty_inner() {
        let r: Result<MeshMonitorKey, _> = "v3-staging::".parse();
        assert!(matches!(r, Err(IdParseError::BadScopedShape(_))));
    }

    #[test]
    fn node_key_works() {
        let _: MeshNodeKey = "v3-staging::v2-ru-hostkey-203.0.113.10".parse().unwrap();
    }
}
