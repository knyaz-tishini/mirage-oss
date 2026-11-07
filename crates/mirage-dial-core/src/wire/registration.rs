//! Node ↔ monitor registration REST schema.
//!
//! `POST /relay/nodes/register` request + response. Lifted from
//! `mirage2monitor::monitor::node_control_api`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistration {
    /// Operator-signed identity envelope. Present in adopted
    /// deployments; absent on greenfield first-boot for back-compat.
    #[serde(default)]
    pub identity: Option<mirage_core::identity::DeclaredIdentity>,
    pub mesh_id: String,
    pub node_id: String,
    pub sentry_id: String,
    pub supported_axes: serde_json::Value,
    #[serde(default)]
    pub external_addr: Option<String>,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub pubkey_hex: Option<String>,
    #[serde(default)]
    pub labels: Vec<String>,
    #[serde(default)]
    pub capabilities_json: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistrationResponse {
    pub session_token: String,
    pub control_url: String,
    pub current_generation: u64,
    pub session_expires_at_ms: u64,
}
