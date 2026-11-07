//! Operator → monitor upsert REST surface. Listeners, peers, chains,
//! monitor registry.
//!
//! Lifted from `mirage2monitor::monitor::node_control_api`.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertListenerRequest {
    pub node_id: String,
    pub listener_id: String,
    pub spec: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertListenerResponse {
    pub generation: u64,
    pub woke_node: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertPeerRequest {
    pub node_id: String,
    pub pubkey_hex: String,
    pub addr: String,
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertPeerResponse {
    pub generation: u64,
    pub broadcast_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertChainRequest {
    /// Operator passes an opaque `ChainBinding`-shaped JSON. The
    /// monitor canonicalises it server-side; substrate-side consumers
    /// do not re-validate.
    pub binding: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertChainResponse {
    pub generation: u64,
    pub broadcast_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertMonitorRequest {
    #[serde(default)]
    pub mesh_id: Option<String>,
    pub monitor_id: String,
    pub monitor_pubkey_hex: String,
    pub public_addr: String,
    #[serde(default)]
    pub labels: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpsertMonitorResponse {
    pub updated_at_ms: u64,
    pub persisted: bool,
}
