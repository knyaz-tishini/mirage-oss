//! Mirage listener specification — Mirage-only listener slot.
//!
//! Type-state `role`: every Mirage listener is either a relay leg
//! (Entry/Hop with [`RelayMode`]) or a terminator (Exit with [`ExitMode`]).
//! No `Option`, no shim — the compiler enforces exhaustive coverage.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::{
    AeadSuite, ExitMode, Framing, LayerSpec, MirageListenerKind, RelayMode,
};

/// Stable monitor-side identifier for one Mirage listener slot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ListenerId(pub String);

impl fmt::Display for ListenerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// BLAKE3 over the canonical serialisation of every field except
/// `fingerprint` itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct SpecFingerprint(pub [u8; 32]);

impl SpecFingerprint {
    pub const ZERO: Self = Self([0u8; 32]);
}

/// Type-state role for a Mirage listener.
///
/// A listener is **either** a relay leg (Entry/Hop carry [`RelayMode`])
/// **or** an exit (carries [`ExitMode`]). Impossible to construct an
/// Entry with an exit_mode or vice versa — compiler enforces exhaustive
/// match.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ListenerRole {
    /// Relay leg — first reachable node (Entry) or intermediate hop (Hop).
    Relay {
        position: EntryHop,
        relay_mode: RelayMode,
    },
    /// Exit — terminator of the chain.
    Exit { exit_mode: ExitMode },
}

/// Position discriminator for a relay leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntryHop {
    Entry,
    Hop,
}

/// Mirage listener spec — `v3` schema.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirageListenerSpec {
    /// Stable id (survives node restarts).
    pub id: ListenerId,

    /// Logical Mirage mesh. Canonical scheme: `"v3-<env>"`.
    pub mesh_id: String,

    /// What this listener listens to (TCP/UDP/Control/UdpRelay/Decoy/DecoyMulti).
    pub kind: MirageListenerKind,

    /// Type-state role — Relay (Entry|Hop + RelayMode) or Exit (ExitMode).
    /// Required field, no shim.
    pub role: ListenerRole,

    /// Frame layout inside the AEAD tunnel.
    pub framing: Framing,

    /// What arrives on the bind socket — camouflage to strip + optional
    /// byte_cipher to peel.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_layer: Option<LayerSpec>,

    /// What this node wraps the outbound dial in toward the next hop.
    /// Only meaningful when `role = Relay`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outgoing_layer: Option<LayerSpec>,

    /// AEAD suite preference for this leg.
    pub aead_suite: AeadSuite,

    /// Bind port hint. `None` means the node picks its own free port
    /// from its local Mirage range; the actual port comes back in
    /// `NodeToMonitor::ListenerBound { bind_port: Some(n) }`. `Some(n)`
    /// is an explicit pin — node binds exactly on `n` or replies with
    /// an error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_port: Option<u16>,

    /// Topology hint for multi-hop chains (Relay role only).
    /// Identity resolved per-accept from `peer_table`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain_role: Option<ChainRole>,

    /// For `kind = TunnelControl`: the loopback address of the monitor's
    /// over-chain control listener. Defaults to `127.0.0.1:19445`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_target: Option<std::net::SocketAddr>,

    /// Kind-specific opaque payload (DecoyConfig / MultiDecoyConfig /
    /// UdpRelayBinding). The factory for each `kind` deserialises this.
    /// `None` for kinds that have all config in typed fields above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<serde_json::Value>,

    /// Pre-computed by the monitor; node MUST recompute and reject on mismatch.
    pub fingerprint: SpecFingerprint,
}

/// Topology hint — which chain this listener is part of and where in it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainRole {
    pub chain_id: String,
    pub chain_position: u8,
    pub chain_length: u8,
    /// Node ids ordered by chain_position. Length MUST equal `chain_length`
    /// for multi-hop; empty allowed only on single-hop / direct-exit.
    #[serde(default)]
    pub chain_node_ids: Vec<String>,
    /// Concrete `host:port` of the next hop's listener.
    /// Required for transparent/crypto_verify multi-hop entry/hop listeners.
    /// Onion listeners leave this `None` — the forwarding address is in
    /// the encrypted envelope. Exit listeners ignore this field.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_hop_addr: Option<String>,
    /// The high-entropy name this hop's listener answers to on the wire.
    ///
    /// Minted per hop by the monitor and hex-encoded. When present it IS the
    /// selector; when absent the node falls back to the derived
    /// `{chain_id}-h{position}`, which is what every hop used before this
    /// field existed — 32 bits of `chain_id`, sized for reading logs by eye
    /// and never for being guessed at.
    ///
    /// `#[serde(default)]` so an older monitor's spec still parses and an
    /// older node ignores a newer one: the rollout is soft on both sides,
    /// matching the frame trailer that carries the same value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector_token_hex: Option<String>,
}

impl MirageListenerSpec {
    /// Compute the canonical fingerprint over every field except
    /// `self.fingerprint` itself.
    pub fn compute_fingerprint(&self) -> SpecFingerprint {
        let mut h = blake3::Hasher::new();
        // v3 — Wave 6 clean-taxonomy cutover.
        h.update(b"mirage-listener-spec/v3\0");

        feed_str(&mut h, b"id", &self.id.0);
        feed_str(&mut h, b"mesh_id", &self.mesh_id);
        feed_str(&mut h, b"kind", self.kind.as_str());
        feed_json(&mut h, b"role", &self.role);
        feed_str(&mut h, b"framing", self.framing.as_str());
        feed_opt_json(&mut h, b"ingress_layer", self.ingress_layer.as_ref());
        feed_opt_json(&mut h, b"outgoing_layer", self.outgoing_layer.as_ref());
        feed_str(&mut h, b"aead_suite", self.aead_suite.as_str());
        feed_opt_u16(&mut h, b"bind_port", self.bind_port);
        feed_opt_json(&mut h, b"chain_role", self.chain_role.as_ref());
        match &self.control_target {
            None => {
                h.update(b"control_target\x00");
            }
            Some(addr) => {
                let s = addr.to_string();
                h.update(b"control_target\x01");
                h.update(&(s.len() as u64).to_le_bytes());
                h.update(s.as_bytes());
            }
        }
        feed_opt_json(&mut h, b"payload", self.payload.as_ref());

        let mut out = [0u8; 32];
        out.copy_from_slice(h.finalize().as_bytes());
        SpecFingerprint(out)
    }

    pub fn with_recomputed_fingerprint(mut self) -> Self {
        self.fingerprint = self.compute_fingerprint();
        self
    }

    /// Get the relay mode if this is a Relay listener.
    pub fn relay_mode(&self) -> Option<&RelayMode> {
        match &self.role {
            ListenerRole::Relay { relay_mode, .. } => Some(relay_mode),
            ListenerRole::Exit { .. } => None,
        }
    }

    /// Get the exit mode if this is an Exit listener.
    pub fn exit_mode(&self) -> Option<&ExitMode> {
        match &self.role {
            ListenerRole::Exit { exit_mode } => Some(exit_mode),
            ListenerRole::Relay { .. } => None,
        }
    }
}

/// Reference to an upstream hop — either a concrete `host:port` or a
/// peer-table lookup by node_id + listener_id.
///
/// Used by relay-mode factories to resolve the next-hop address at connect
/// time. Lives here (not in `config`) because it is spec-side topology,
/// not dial-time config.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum UpstreamRef {
    Concrete { addr: String },
    PeerListener {
        node_id: String,
        listener_id: ListenerId,
    },
}

/// Backend reference for Decoy/DecoyMulti listeners — a single backend
/// entry in a pool that the decoy can forward to.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DecoyRef {
    pub backend_id: String,
    pub target: String,
}

fn feed_str(h: &mut blake3::Hasher, tag: &[u8], s: &str) {
    h.update(tag);
    h.update(&(s.len() as u64).to_le_bytes());
    h.update(s.as_bytes());
}

fn feed_opt_u16(h: &mut blake3::Hasher, tag: &[u8], v: Option<u16>) {
    h.update(tag);
    match v {
        None => {
            h.update(&[0u8]);
        }
        Some(inner) => {
            h.update(&[1u8]);
            h.update(&inner.to_le_bytes());
        }
    }
}

fn feed_json<T: Serialize>(h: &mut blake3::Hasher, tag: &[u8], v: &T) {
    h.update(tag);
    let bytes = serde_json::to_vec(v).unwrap_or_default();
    h.update(&(bytes.len() as u64).to_le_bytes());
    h.update(&bytes);
}

fn feed_opt_json<T: Serialize>(h: &mut blake3::Hasher, tag: &[u8], v: Option<&T>) {
    h.update(tag);
    match v {
        None => h.update(&[0u8]),
        Some(inner) => {
            h.update(&[1u8]);
            let bytes = serde_json::to_vec(inner).unwrap_or_default();
            h.update(&(bytes.len() as u64).to_le_bytes());
            h.update(&bytes)
        }
    };
}
