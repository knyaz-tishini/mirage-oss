//! Inventory reader for `nemo/inventory.toml` — the single source of truth
//! for machine metadata (IP, SSH key path, roles, mesh membership).
//!
//! The id types in [`crate::ids`] validate format; this module connects
//! parsed [`MachineId`] back to per-box metadata that doesn't fit in the
//! id string (IP, ssh key file, etc.).
//!
//! This is an inventory of MACHINES, and it carries only what does not
//! change about one: where it answers, and which key opens it. It used to
//! carry `roles` and `meshes` as well — removed 2026-08-27, because those
//! are STATE. A box is admitted into a mesh and granted a role at runtime,
//! and a declaration re-read from disk on every start silently reverted
//! both. The operator box records them in its `machine_mesh` and
//! `machine_role` ledgers, which also answer when it joined, who admitted
//! it, and when it left — questions a file overwritten in place cannot.

use std::collections::HashMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::ids::{MachineId, MeshId};

/// Top-level inventory file.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Inventory {
    pub meta: InventoryMeta,
    #[serde(rename = "machine", default)]
    pub machines: Vec<MachineRow>,
    #[serde(default)]
    pub topology: HashMap<String, TopologyHint>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct InventoryMeta {
    pub version: u32,
    #[serde(default)]
    pub generated_from: Option<String>,
}

/// A single physical box. Lookup key is `id` (a `MachineId`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct MachineRow {
    /// Canonical id — `<region>-<provider>-<oct3>.<oct4>`.
    pub id: MachineId,
    /// Public IPv4.
    pub ip: std::net::Ipv4Addr,
    /// SSH private key basename (lives in `env/example-inventory/`).
    pub ssh_key: String,
    /// Free-form labels (e.g. `"standalone"`, `"tester1"`).
    #[serde(default)]
    pub labels: Vec<String>,
    /// Old name from the pre-typed era (for migration messages). MAY be
    /// removed once all callers stop referring to it.
    #[serde(default)]
    pub legacy_id: Option<String>,
}

/// Per-mesh topology hint — entries the test scripts need (entry, exit,
/// failover siblings, default SOCKS5 port).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct TopologyHint {
    pub mesh_id: MeshId,
    #[serde(default)]
    pub legacy_entry_machine: Option<MachineId>,
    #[serde(default)]
    pub legacy_exit_machine: Option<MachineId>,
    #[serde(default)]
    pub multihop_entry: Option<MachineId>,
    #[serde(default)]
    pub multihop_hop: Option<MachineId>,
    #[serde(default)]
    pub multihop_exit: Option<MachineId>,
    #[serde(default)]
    pub failover_entry_machines: Vec<MachineId>,
    #[serde(default)]
    pub failover_exit_machine: Option<MachineId>,
    #[serde(default)]
    pub failover_socks5_port: Option<u16>,
}

impl Inventory {
    /// Read inventory.toml from a path.
    pub fn from_path(path: &Path) -> Result<Self, InventoryError> {
        let raw =
            std::fs::read_to_string(path).map_err(|e| InventoryError::Io(path.into(), e))?;
        Self::from_str(&raw)
    }

    /// Parse from a TOML string.
    pub fn from_str(s: &str) -> Result<Self, InventoryError> {
        toml::from_str(s).map_err(InventoryError::Toml)
    }

    /// Lookup a machine by its canonical id.
    pub fn machine(&self, id: &MachineId) -> Option<&MachineRow> {
        self.machines.iter().find(|m| &m.id == id)
    }

    /// Lookup by legacy id string. Returns `None` if no row matches or if
    /// the legacy id is not unique. Used during migration only.
    pub fn machine_by_legacy(&self, legacy_id: &str) -> Option<&MachineRow> {
        let mut matches = self
            .machines
            .iter()
            .filter(|m| m.legacy_id.as_deref() == Some(legacy_id));
        let first = matches.next()?;
        if matches.next().is_some() {
            return None;
        }
        Some(first)
    }

}

#[derive(Debug, thiserror::Error)]
pub enum InventoryError {
    #[error("inventory io error reading {0:?}: {1}")]
    Io(std::path::PathBuf, std::io::Error),
    #[error("inventory toml parse error: {0}")]
    Toml(toml::de::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
[meta]
version = 1

[[machine]]
id      = "ru-hostkey-203.0.113.10"
ip      = "203.0.113.15"
ssh_key = "hostkey-main-ssh"
labels  = []
legacy_id = "ru-hostkey-1"

[[machine]]
id      = "ch-example-203.0.113.41"
ip      = "203.0.113.17"
ssh_key = "example-203.0.113.17-ch"
labels  = ["standalone"]
legacy_id = "ch-cloudzy-1"

[topology.staging_v2]
mesh_id = "v3-staging"
multihop_entry = "ru-hostkey-203.0.113.10"
"#;

    #[test]
    fn parses_sample() {
        let inv = Inventory::from_str(SAMPLE).unwrap();
        assert_eq!(inv.machines.len(), 2);
        let m = &inv.machines[0];
        assert_eq!(m.id.region(), Some(crate::ids::Region::Ru));
        assert_eq!(m.ip.to_string(), "203.0.113.15");
        assert_eq!(m.ssh_key, "hostkey-main-ssh");
    }

    #[test]
    fn lookup_by_legacy() {
        let inv = Inventory::from_str(SAMPLE).unwrap();
        let m = inv.machine_by_legacy("ru-hostkey-1").unwrap();
        assert_eq!(m.id.to_string(), "ru-hostkey-203.0.113.10");
        assert!(inv.machine_by_legacy("nope").is_none());
    }

    /// A row that still carries the retired `roles`/`meshes` keys must
    /// still parse: the fields are gone from the struct, not from every
    /// file on every disk, and a hard parse error on an old inventory would
    /// take the operator box down rather than let it ignore two dead keys.
    #[test]
    fn a_row_carrying_the_retired_state_keys_still_parses() {
        let legacy = r#"
[meta]
version = 1

[[machine]]
id      = "ru-hostkey-203.0.113.10"
ip      = "203.0.113.15"
ssh_key = "hostkey-main-ssh"
roles   = ["monitor", "node"]
meshes  = ["v3-staging"]
"#;
        let inv = Inventory::from_str(legacy).expect("retired keys are ignored, not fatal");
        assert_eq!(inv.machines.len(), 1);
    }
}
