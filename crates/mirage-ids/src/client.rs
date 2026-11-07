use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::IdParseError;
use crate::sentinel::SentinelId;

/// Top-level client identity (server-side perspective).
///
/// `ClientId` is what the monitor anchors all per-client state to. When a
/// sentinel registers via `POST /relay/clients` carrying its `sentinel_id`,
/// the monitor echoes the same UUID back as `client_id` — so for the
/// sentinel-managed install case `ClientId == SentinelId` value-wise.
///
/// We keep them as separate types so reads/writes are intent-explicit:
/// sentinel code returns `SentinelId` (its own persistent identity),
/// monitor code stores `ClientId` (the per-client row key). Conversion is
/// free via `From<SentinelId>`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ClientId(Uuid);

impl ClientId {
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

impl fmt::Display for ClientId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl FromStr for ClientId {
    type Err = IdParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Uuid::parse_str(s)
            .map(Self)
            .map_err(|e| IdParseError::BadUuid(s.into(), e))
    }
}

impl Serialize for ClientId {
    fn serialize<S: serde::Serializer>(&self, ser: S) -> Result<S::Ok, S::Error> {
        ser.collect_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for ClientId {
    fn deserialize<D: serde::Deserializer<'de>>(de: D) -> Result<Self, D::Error> {
        let s = String::deserialize(de)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl From<SentinelId> for ClientId {
    fn from(s: SentinelId) -> Self {
        Self(s.as_uuid())
    }
}

/// What kind of client this is. Operator-side label, surfaced in
/// `GET /relay/clients`. Distinguishes user installs from orchestrator
/// task-mode bundles and bare legacy CLIs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientKind {
    /// Normal L0 sentinel-managed install (desktop or mobile-orchestrator).
    Sentinel,
    /// Operator-side orchestrator running sentinel+cli as tasks in-process.
    Orchestrator,
    /// Pre-sentinel legacy client. No automatic re-register; client_id
    /// minted by monitor on first contact.
    BareLegacy,
    /// Mobile FFI build — sentinel-free, direct stack. No persistent
    /// client_id by design.
    Mobile,
}
