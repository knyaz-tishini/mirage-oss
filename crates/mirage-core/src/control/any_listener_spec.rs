//! Family-tagged listener spec wrapper.
//!
//! Monitor pushes one `AnyListenerSpec` per slot; node parses and
//! dispatches into the Mirage listener runtime.
//!
//! Serde tag `family` is kept (rather than flattening `MirageListenerSpec`
//! directly) so a future second family can be added without a wire-shape
//! break.

use serde::{Deserialize, Serialize};

use crate::mirage::wire::MirageListenerSpec;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "family", rename_all = "snake_case")]
pub enum AnyListenerSpec {
    Mirage(MirageListenerSpec),
}

impl AnyListenerSpec {
    pub fn is_mirage(&self) -> bool {
        matches!(self, Self::Mirage(_))
    }

    pub fn family_str(&self) -> &'static str {
        match self {
            Self::Mirage(_) => "mirage",
        }
    }

    /// Slot id as a stable string (each family has its own id type).
    pub fn id_str(&self) -> &str {
        match self {
            Self::Mirage(s) => s.id.0.as_str(),
        }
    }
}
