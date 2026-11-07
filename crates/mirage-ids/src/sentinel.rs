use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::IdParseError;

/// L0 sentinel installation id.
///
/// One per physical client box; persisted to `${state_dir}/sentinel-id.txt`
/// so it survives reboots and reinstalls of the sentinel binary. UUID v4 —
/// no human-readable form needed since operators see boxes by `shortname` /
/// `role` in `GET /relay/clients`.
///
/// NOT to be confused with `SentryId` (which does not exist in this stack —
/// "sentry" is a server-side scanner role with its own `sentry_id` field at
/// `/relay/sentries`, not represented by a typed id here).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SentinelId(Uuid);

impl SentinelId {
    pub fn new(uuid: Uuid) -> Self {
        Self(uuid)
    }

    pub fn random() -> Self {
        Self(Uuid::new_v4())
    }

    pub fn as_uuid(&self) -> Uuid {
        self.0
    }
}

impl fmt::Display for SentinelId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for SentinelId {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|e| IdParseError::BadUuid(s.into(), e))
    }
}

impl Serialize for SentinelId {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SentinelId {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_is_unique() {
        let a = SentinelId::random();
        let b = SentinelId::random();
        assert_ne!(a, b);
    }

    #[test]
    fn parse_canonical_uuid() {
        let s = "550e8400-e29b-41d4-a716-446655440000";
        let id: SentinelId = s.parse().unwrap();
        assert_eq!(id.to_string(), s);
    }
}
