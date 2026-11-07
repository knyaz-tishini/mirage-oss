//! node → monitor WS frames.

use serde::{Deserialize, Serialize};

/// All frames a node may send to the monitor over the control WS.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum NodeFrame {
    /// A Mirage listener slot accepted the push and is bound.
    ListenerBound {
        listener_id: String,
        bound_addr: String,
    },

    /// A Mirage listener slot failed to activate or rebind.
    ListenerError {
        listener_id: String,
        reason: String,
    },

    /// Periodic listener stats (Mirage).
    ListenerStats {
        listener_id: String,
        bytes_in: u64,
        bytes_out: u64,
        active_conns: u32,
    },

    /// Health beat in response to monitor Ping.
    Pong { ts_ms: u64 },
}
