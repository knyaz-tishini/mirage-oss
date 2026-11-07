//! Control-plane frame carried over the monitor↔monitor Mirage tunnel.
//!
//! Wire format on the tunnel: `[4B BE length][JSON body]`. JSON because
//! the same `PeerEvent`s are also pushed over HTTP — single decoder.
//!
//! `PeerEvent` itself lives in monitor crate (it's monitor-internal —
//! runtime-nodes / client-registrations / chain-bindings deltas). Here
//! we carry only an opaque `payload` to break the dep cycle.

use serde::{Deserialize, Serialize};

use super::chain_binding::ChainBinding;
use super::ids::NodeId;
use super::peer_table::PeerTable;

/// Maximum size of one wire frame, in bytes. Receiver-side guard.
pub const MAX_FRAME_BYTES: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum InterMonitorFrame {
    /// Replicated state — push. `payload` = serde-encoded `Vec<PeerEvent>`
    /// on the monitor side.
    PeerPush {
        #[serde(with = "b64_bytes")]
        payload: Vec<u8>,
    },

    /// Replicated state — pull request. Receiver answers with `PeerPush`.
    PeerPull { since_ms: u64 },

    /// "Push this listener-spec to node D" — proxy-hop when I (monitor M_i)
    /// can't see node D directly but peer-monitor M_k can.
    ProxyPushListener {
        node_id: NodeId,
        listener_id: String,
        spec_json: String,
        fingerprint_hex: String,
    },

    /// "Push this peer_table to node D".
    ProxyPushPeerTable {
        node_id: NodeId,
        peer_table: PeerTable,
    },

    /// "Push this chain-binding to node D".
    ProxyPushChain {
        node_id: NodeId,
        chain_binding: ChainBinding,
    },

    /// Keepalive.
    Ping { ts_ms: u64 },
}

mod b64_bytes {
    use base64::{engine::general_purpose::STANDARD as B64, Engine as _};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(b: &Vec<u8>, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(b))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        use serde::de::Error;
        let s = <&str>::deserialize(d)?;
        B64.decode(s).map_err(D::Error::custom)
    }
}
