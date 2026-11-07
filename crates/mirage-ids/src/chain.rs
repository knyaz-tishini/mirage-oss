use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::IdParseError;
use crate::mesh::validate_meshlike;

/// Monitor-allocated chain identifier.
///
/// Two conventional forms:
/// - **Auto-built**: `auto-XXXXXXXX` (8 hex). Built by `POST /relay/chains/build`.
/// - **Stend / user-pinned**: `c-<name>` (e.g. `c-multihop-tcp`).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ChainId(String);

impl ChainId {
    pub fn new(s: impl Into<String>) -> Result<Self, IdParseError> {
        let s = s.into();
        validate_meshlike(&s, "chain")?;
        Ok(Self(s))
    }

    pub fn from_trusted(s: &'static str) -> Self {
        Self::new(s).expect("from_trusted literal failed validation")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// True if this id was auto-allocated by the monitor (`auto-` prefix).
    pub fn is_auto(&self) -> bool {
        self.0.starts_with("auto-")
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for ChainId {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for ChainId {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ChainId {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auto_detection() {
        let auto: ChainId = "auto-deadbeef".parse().unwrap();
        assert!(auto.is_auto());
        let stend: ChainId = "c-multihop-tcp".parse().unwrap();
        assert!(!stend.is_auto());
    }
}
