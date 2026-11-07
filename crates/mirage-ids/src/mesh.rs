use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::error::IdParseError;

/// Environment scope. The mesh defines a set of monitors+nodes that share
/// the same peer_table and AUTH label. Different meshes can share machines
/// but their wire handshakes do not interoperate.
///
/// Examples: `"v3-staging"`, `"prod"`, `"tester1-isolated"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MeshId(String);

impl MeshId {
    pub fn new(s: impl Into<String>) -> Result<Self, IdParseError> {
        let s = s.into();
        validate_meshlike(&s, "mesh")?;
        Ok(Self(s))
    }

    /// Bypass validation — only for trusted compile-time literals.
    /// Panics if the literal would not validate.
    pub fn from_trusted(s: &'static str) -> Self {
        Self::new(s).expect("from_trusted literal failed validation")
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl fmt::Display for MeshId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl FromStr for MeshId {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

impl Serialize for MeshId {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for MeshId {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        Self::new(s).map_err(serde::de::Error::custom)
    }
}

pub(crate) fn validate_meshlike(s: &str, kind: &'static str) -> Result<(), IdParseError> {
    if s.is_empty() {
        return Err(IdParseError::Empty);
    }
    if s.len() > 64 {
        return Err(IdParseError::TooLong(s.len()));
    }
    for ch in s.chars() {
        if !ch.is_ascii_alphanumeric() && !matches!(ch, '-' | '_' | '.') {
            return Err(IdParseError::InvalidChar(ch));
        }
    }
    let _ = kind; // reserved for future kind-specific validation
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_canonical() {
        assert_eq!(MeshId::new("v3-staging").unwrap().as_str(), "v3-staging");
        assert_eq!(MeshId::new("prod").unwrap().as_str(), "prod");
    }

    #[test]
    fn rejects_empty() {
        assert!(matches!(MeshId::new(""), Err(IdParseError::Empty)));
    }

    #[test]
    fn rejects_bad_char() {
        assert!(matches!(
            MeshId::new("bad space"),
            Err(IdParseError::InvalidChar(' '))
        ));
    }

    #[test]
    fn serde_roundtrip() {
        let m = MeshId::new("v3-staging").unwrap();
        let j = serde_json::to_string(&m).unwrap();
        assert_eq!(j, "\"v3-staging\"");
        let back: MeshId = serde_json::from_str(&j).unwrap();
        assert_eq!(m, back);
    }
}
