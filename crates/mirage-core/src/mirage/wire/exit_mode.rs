//! Exit-mode taxonomy for terminator nodes.
//!
//! Three exit shapes, all native Mirage.
//!
//! See `docs/plans/mirage-architecture-clean-taxonomy.md` §M-Wire Axis 4.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ExitMode {
    /// Read `host:port` from the first tunnel frame, dial TCP, bidi copy.
    /// DNS sub-handler (`exit/dns_handler.rs`) is invoked inline when
    /// destination port = 53 — not a separate exit mode.
    Direct,

    /// Peel terminal AEAD, destination encoded inside the V9 onion frame.
    /// Optional mux upgrade on magic `b"MUX\0"` in user-data.
    Onion,

    /// AEAD-handshake then bridge plaintext to the monitor's over-chain
    /// control loopback (default `127.0.0.1:19445`). Carries monitor↔monitor
    /// `InterMonitorFrame`s over a Mirage chain.
    Control {
        /// Where to bridge to. `None` → `127.0.0.1:19445`.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        target: Option<SocketAddr>,
    },
}

impl ExitMode {
    pub fn label(&self) -> &'static str {
        match self {
            ExitMode::Direct => "direct",
            ExitMode::Onion => "onion",
            ExitMode::Control { .. } => "control",
        }
    }
}
