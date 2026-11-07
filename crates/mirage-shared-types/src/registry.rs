use serde::{Deserialize, Serialize};

/// One node entry as emitted by the stend generator.
/// Superset of node config — adds `public_key` and the
/// listener table needed to materialize full `ChainConfig` for clients.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistryEntry {
    pub id: String,
    pub role: String,
    // sentry_url / sentry_api_key dropped 2026-05-24 — sentry is
    // push-only; registry entries do not carry an inbound URL for it.
    /// Primary IP (v4 or v6 string).
    pub ip: String,
    /// Optional secondary IPv6 address for dual-stack nodes.
    /// When present, monitor can emit both v4 and v6 endpoints to clients.
    /// Absent in legacy registry files — always load without error.
    #[serde(default)]
    pub ipv6: Option<String>,
    /// Hex-encoded Ed25519 / X25519 public key for this node.
    /// Passed through to clients as-is; parsing happens on the client side.
    pub public_key: String,
    /// Optional human-readable display name (may be absent in generated files).
    #[serde(default)]
    pub display_name: Option<String>,
    /// Listener table: index -> listener metadata (port, mode, optional sni).
    /// Used by monitor to translate `ChainSpec.l1_listener` /
    /// `ChainSpec.exit_listener` / hop refs (`"node#idx"`) into concrete
    /// `host:port` addresses sent to clients in `/relay/clients/config`.
    /// Empty for nodes that haven't been re-generated since the listener
    /// extension landed — those nodes still surface in legacy mode.
    #[serde(default)]
    pub listeners: Vec<NodeListenerEntry>,
}

/// One listener entry inside a [`NodeRegistryEntry`].
///
/// Mirrors the `[[nodes.listeners]]` block in `stend-fullmesh.toml` —
/// the generator copies it through to `registry.toml` so the monitor
/// can build full `ChainConfig` addresses without re-reading the spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeListenerEntry {
    /// Listener index inside the node's `listeners` array. Matches the
    /// `l1_listener` / `exit_listener` / hop suffix referenced by
    /// `ChainSpec`.
    pub idx: usize,
    /// TCP port the listener binds (host comes from the parent node's `ip`).
    pub port: u16,
    /// Server-side mode (`"transparent"`, `"onion_peel"`,
    /// `"crypto_verify"`, `"direct"`, `"onion"`). Free-form string for now.
    #[serde(default)]
    pub mode: Option<String>,
    /// SNI presented for TLS-camouflaged listeners. Forwarded to clients
    /// as the `sni` field on the `ChainNode` they will dial.
    #[serde(default)]
    pub sni: Option<String>,
}

/// One chain specification as emitted by the stend generator.
///
/// Supports both two-hop (l1_node + exit_node) and multi-hop (hops list)
/// topologies. Carries every field needed by the monitor to materialize a
/// full `mirage_core::config::ChainConfig` for `/relay/clients/config`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSpec {
    pub id: String,
    /// Wire protocol label, e.g. `"mirage_tls"`, `"mirage_base"`.
    pub protocol: String,
    /// First relay node ID (two-hop shorthand). Mutually exclusive with a non-empty `hops`.
    #[serde(default)]
    pub l1_node: Option<String>,
    /// Listener index on the l1 node (two-hop shorthand).
    #[serde(default)]
    pub l1_listener: Option<usize>,
    /// Last (exit) node ID.
    pub exit_node: String,
    /// Listener index on the exit node.
    #[serde(default)]
    pub exit_listener: usize,
    /// Ordered intermediate hop descriptors in `"node_id#listener"` format.
    /// When non-empty, supersedes `l1_node`/`l1_listener`.
    #[serde(default)]
    pub hops: Vec<String>,
    /// Handshake mode, e.g. `"ephemeral"`, `"static"`.
    #[serde(default)]
    pub handshake: Option<String>,
    /// Reply channel mode, e.g. `"raw"`, `"wrapped"`, `"onion"`.
    #[serde(default)]
    pub reply: Option<String>,
    /// True when L1 is a transparent TCP pipe — client must perform ECDH
    /// against L2's pubkey, not L1's. Propagated to `ChainConfig.l1_transparent`.
    #[serde(default)]
    pub l1_transparent: bool,
    /// Higher = preferred. Default 0.
    #[serde(default)]
    pub priority: u8,
    /// Traffic-shaping preset (`"none"`, `"web_browsing"`, ...). Default `"none"`.
    #[serde(default)]
    pub shaping: Option<String>,
    /// Per-frame camouflage wrapping (`"raw"`, `"json_api"`, ...). Default `"raw"`.
    #[serde(default)]
    pub camouflage: Option<String>,
    /// Optional byte-cipher mode applied by client before sending to L1.
    #[serde(default)]
    pub byte_cipher: Option<String>,
    /// Optional dedicated SOCKS5 bind for this chain on the client.
    /// Set per-chain so each client lists the same socks5 ports for the
    /// same chain ids.
    #[serde(default)]
    pub socks5_bind: Option<String>,
    /// Per-chain UDP wire secret blocks (`UdpProtocolId::*` chains only).
    /// Forwarded to clients as the matching `ChainConfig.udp_*` field so
    /// the client camouflage layer holds the same PSK / password / WG params
    /// as the server's `endpoint_configs[]` entry. Absent → client falls back
    /// to dev defaults.
    #[serde(default)]
    pub udp_quic: Option<UdpQuicReg>,
    #[serde(default)]
    pub udp_hysteria2: Option<UdpHysteria2Reg>,
    #[serde(default)]
    pub udp_hysteria2_native: Option<UdpHysteria2NativeReg>,
    #[serde(default)]
    pub udp_wg: Option<UdpWgReg>,
    /// VLESS-Reality / Mirage-Reality per-chain block. Populated by stend-gen
    /// from the L1 listener's `reality = {...}` spec (or the bake-in default).
    /// Materialized into ChainConfig.vless_reality so the client side of the
    /// chain holds the same short_id list / SNI / fallback as the server.
    #[serde(default)]
    pub vless_reality: Option<RealityReg>,
}

/// Registry mirror of `mirage_core::config::RealityNodeConfig`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RealityReg {
    #[serde(default)]
    pub short_ids: Vec<String>,
    #[serde(default)]
    pub max_time_diff: Option<u64>,
    #[serde(default)]
    pub server_name: Option<String>,
    #[serde(default)]
    pub fallback_dest: Option<String>,
}

/// Registry mirror of `mirage_core::config::UdpQuicConfig`. Plain shape so the
/// monitor common crate stays free of a `mirage_core` dependency.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UdpQuicReg {
    #[serde(default)]
    pub alpn: Vec<String>,
}

/// Registry mirror of `mirage_core::config::UdpHysteria2Config`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UdpHysteria2Reg {
    #[serde(default)]
    pub psk_hex: Option<String>,
}

/// Registry mirror of `mirage_core::config::UdpHysteria2NativeConfig`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UdpHysteria2NativeReg {
    #[serde(default)]
    pub password: Option<String>,
    #[serde(default)]
    pub rx_max_mbps: Option<u32>,
}

/// Registry mirror of `mirage_core::config::UdpWgConfig`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct UdpWgReg {
    #[serde(default)]
    pub magic_byte: Option<u8>,
    #[serde(default)]
    pub junk_count: Option<u8>,
    #[serde(default)]
    pub junk_min: Option<u16>,
    #[serde(default)]
    pub junk_max: Option<u16>,
}

impl ChainSpec {
    /// Returns all node IDs referenced by this chain (hops first, then exit).
    /// Used for health-checking every node in the chain path.
    pub fn all_node_ids(&self) -> Vec<&str> {
        let mut ids: Vec<&str> = Vec::new();

        if !self.hops.is_empty() {
            for hop in &self.hops {
                // hop format: "node_id#listener"
                let node_id = hop.split('#').next().unwrap_or(hop.as_str());
                ids.push(node_id);
            }
        } else if let Some(l1) = self.l1_node.as_deref() {
            ids.push(l1);
        }

        ids.push(self.exit_node.as_str());
        ids
    }
}

/// Full stend registry file — produced by `scripts/mirage_stend_gen.py` or
/// `crates/stend-gen`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StendRegistry {
    #[serde(default)]
    pub nodes: Vec<NodeRegistryEntry>,
    #[serde(default)]
    pub chains: Vec<ChainSpec>,
}
