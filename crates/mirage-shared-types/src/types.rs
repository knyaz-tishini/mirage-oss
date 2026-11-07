use std::collections::HashMap;

use mirage_core::config::ChainConfig;
use mirage_core::mirage::mesh::PeerTable;
use serde::{Deserialize, Serialize};

/// Unique node identifier — matches config key
pub type NodeId = String;

// `NodeRole` enum (L1/L2/Client) deleted 2026-05-28 — the L1/L2/Client tags
// were a pre-class-label heuristic for what kind of binary lives on each
// box. After the class-label axis cutover (`mirage-node` / `standalone` /
// `monitor`) every box is identified by its `peer_table.labels_json`
// canonical set and SentryReport carries the same string via the `class`
// field. No legacy enum, no parse_role, no SENTRY_ROLE env.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeHealth {
    Healthy,
    Degraded { reason: String },
    Unreachable,
}

/// TCP metrics collected from `ss -tinp` output for a single connection.
/// Only populated on Linux nodes where `ss` is available.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ConnectionTcpMetrics {
    /// Round-trip time in milliseconds
    pub rtt_ms: f64,
    /// RTT variance in milliseconds
    pub rtt_var_ms: f64,
    /// Number of retransmits
    pub retransmits: u32,
    /// Bytes received on this connection
    pub bytes_received: u64,
    /// Bytes sent on this connection
    pub bytes_sent: u64,
    /// Connection age in seconds (derived from busy timer if present)
    pub age_secs: Option<u64>,
}

/// Active TCP connection observed on the node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveConnection {
    /// Local port being listened on (e.g. 4430, 4431)
    pub local_port: u16,
    /// Remote IP address of the client
    pub remote_addr: String,
    /// Remote port of the client
    pub remote_port: u16,
    /// TCP state (e.g. "ESTABLISHED", "TIME_WAIT", "SYN_RECV")
    pub state: String,
    /// Which service owns this port (matched from SENTRY_SERVICES config)
    pub service_hint: Option<String>,
    /// TCP metrics from `ss -tinp` (None on non-Linux or if ss fails)
    #[serde(default)]
    pub metrics: Option<ConnectionTcpMetrics>,
}

/// Per-port throughput snapshot computed from consecutive collection cycles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortThroughput {
    pub local_port: u16,
    pub service_hint: Option<String>,
    /// Bytes/sec received on this port (computed over last interval)
    pub rx_bps: f64,
    /// Bytes/sec transmitted on this port
    pub tx_bps: f64,
    /// Number of active connections on this port
    pub active_connections: u32,
    /// Interval over which throughput was computed (seconds)
    pub interval_secs: f64,
}

/// Per-endpoint metrics snapshot from mirage-node `/metrics`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEndpointSnapshot {
    /// Key format: "mode:listen_addr", e.g. "transparent:0.0.0.0:4500"
    pub key: String,
    pub active_connections: u64,
    pub total_connections: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub errors: u64,
}

/// Onion-circuit metrics snapshot from mirage-node `/metrics`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeOnionSnapshot {
    pub active_circuits: u64,
    pub total_circuits: u64,
    pub circuit_fails: u64,
    /// Sum of all handshake RTTs in milliseconds; divide by total_circuits for avg
    pub cumulative_handshake_ms: u64,
}

/// Probe-resist event counts from mirage-node `/metrics`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeProbeResistSnapshot {
    pub invalid_handshakes_dropped: u64,
    pub fallback_forwarded: u64,
    pub decoy_triggered: u64,
}

/// Complete metrics snapshot fetched from a mirage-node `/metrics` endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetricsSnapshot {
    pub endpoints: Vec<NodeEndpointSnapshot>,
    pub onion: NodeOnionSnapshot,
    pub probe_resist: NodeProbeResistSnapshot,
}

/// CPU information for cross-compile target selection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CpuInfo {
    /// CPU model name from `/proc/cpuinfo` "model name" field.
    pub model: String,
    /// Architecture (`x86_64`, `aarch64`).
    pub arch: String,
    /// CPU flags from `/proc/cpuinfo` "flags" field, deduped.
    pub flags: Vec<String>,
    /// Highest x86_64 microarch level supported (`x86-64`, `x86-64-v2`, `x86-64-v3`, `x86-64-v4`).
    /// None if not x86_64.
    pub target_cpu_safe: Option<String>,
    /// Kernel release (uname -r).
    pub kernel: String,
    /// glibc version if detectable, else None.
    pub glibc_version: Option<String>,
}

/// One complete report from a probe instance
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SentryReport {
    pub node_id: NodeId,
    /// Canonical class label of the box this report came from —
    /// one of `"mirage-node"`, `"standalone"`, `"monitor"`. Same string
    /// the picker filters on via `peer_table.labels_json`.
    pub class: String,
    pub probe_version: String,
    /// Unix timestamp seconds
    pub reported_at: u64,
    pub services: Vec<ServiceStatus>,
    pub traffic: TrafficStats,
    pub dns: Vec<DnsResult>,
    /// Sentry pings its configured peer list
    pub ping_targets: Vec<PingResult>,
    pub system: SystemMetrics,
    #[serde(default)]
    pub connections: Vec<ActiveConnection>,
    /// Per-port throughput (bytes/sec computed from deltas between report cycles)
    #[serde(default)]
    pub port_throughput: Vec<PortThroughput>,
    /// Metrics fetched from the local mirage-node /metrics endpoint (if configured).
    #[serde(default)]
    pub node_metrics: Option<NodeMetricsSnapshot>,
    /// Transport reachability probes (grpc, websocket, ssh, etc.)
    #[serde(default)]
    pub transport_health: Vec<TransportHealth>,
    /// CPU information for cross-compile target selection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu_info: Option<CpuInfo>,
    /// Per-listener TCP bind + service status reported by the probe.
    /// Empty on older probes that don't support this field.
    #[serde(default)]
    pub listeners: Vec<ListenerInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceStatus {
    /// "socat", "awg", "xray", "openvpn", "unbound", "wg"
    pub name: String,
    pub running: bool,
    pub pid: Option<u32>,
    pub uptime_secs: Option<u64>,
    /// Protocol-specific (e.g. WG peer count, socat fork children)
    pub extra: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrafficStats {
    pub interfaces: Vec<InterfaceStats>,
    /// Parsed from `wg show` output
    pub wg_peers: Vec<WgPeerStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InterfaceStats {
    /// "eth0", "awg0", "tun0"
    pub name: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub tx_packets: u64,
    pub rx_errors: u64,
    pub tx_errors: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WgPeerStats {
    pub public_key: String,
    pub endpoint: Option<String>,
    pub last_handshake_secs: Option<u64>,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsResult {
    /// "127.0.0.1:53", "8.8.8.8:53"
    pub resolver: String,
    /// Test domain
    pub query: String,
    pub latency_ms: Option<u32>,
    pub success: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    /// IP or hostname
    pub target: String,
    pub sent: u8,
    pub received: u8,
    pub rtt_min_ms: Option<f32>,
    pub rtt_avg_ms: Option<f32>,
    pub rtt_max_ms: Option<f32>,
    pub packet_loss_pct: f32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub load_1min: f32,
    pub mem_total_kb: u64,
    pub mem_available_kb: u64,
    pub uptime_secs: u64,
}

/// Link quality between an L1 and L2 node, computed by monitor
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkMetrics {
    pub l1_id: NodeId,
    pub l2_id: NodeId,
    pub measured_at: u64,
    /// From L1 probe ping_targets
    pub l1_to_l2_latency_ms: Option<f32>,
    /// From L2 probe ping_targets
    pub l2_to_l1_latency_ms: Option<f32>,
    pub l1_to_l2_loss_pct: Option<f32>,
    pub quality: LinkQuality,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LinkQuality {
    /// <50ms avg, <1% loss
    Good,
    /// 50-200ms or 1-10% loss
    Degraded,
    /// >200ms or >10% loss
    Poor,
    /// Unreachable
    Down,
}

impl std::fmt::Display for LinkQuality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkQuality::Good => write!(f, "good"),
            LinkQuality::Degraded => write!(f, "degraded"),
            LinkQuality::Poor => write!(f, "poor"),
            LinkQuality::Down => write!(f, "down"),
        }
    }
}

/// Active protocol test result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolTestResult {
    pub l1_id: NodeId,
    pub l2_id: NodeId,
    /// "awg", "xray", "openvpn", "wg", "ss"
    pub protocol: String,
    pub tested_at: u64,
    /// Could we reach the L2 VPN port via L1?
    pub reachable: bool,
    pub port: u16,
    pub latency_ms: Option<u32>,
    pub error: Option<String>,
    /// Heuristic: UDP works but specific protocol port blocked
    pub dpi_likely: bool,
}

/// Alert record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: u64,
    pub ts: u64,
    pub severity: AlertSeverity,
    pub node_id: Option<NodeId>,
    pub kind: AlertKind,
    pub message: String,
    pub acked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

impl std::fmt::Display for AlertSeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AlertSeverity::Info => write!(f, "info"),
            AlertSeverity::Warning => write!(f, "warning"),
            AlertSeverity::Critical => write!(f, "critical"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AlertKind {
    NodeUnreachable,
    ServiceDown {
        service_name: String,
    },
    LinkDegraded {
        l1_id: NodeId,
        l2_id: NodeId,
    },
    DnsFailure {
        resolver: String,
    },
    DpiDetected {
        protocol: String,
        l1_id: NodeId,
        l2_id: NodeId,
    },
    /// socat fork children > threshold
    SocatProcessLeak {
        count: u32,
    },
    HighPacketLoss {
        link: String,
        loss_pct: f32,
    },
}

/// Info about a chain configured in the mirage-client config file.
/// Returned by `GET /chain/list` on the probe and `GET /relay/chains` on the monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainInfo {
    /// Unique chain identifier (e.g. "crypto-vless", "classic-awg")
    pub chain_id: String,
    /// Current priority value — lower number = higher priority in mirage-client
    pub priority: u32,
    /// Whether this chain is currently active (has the highest priority / is selected)
    pub active: bool,
    /// Optional human-readable description from the config
    pub description: Option<String>,
}

/// Matrix test job — tracks a multi-combination reconfig test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixTestJob {
    pub id: u64,
    /// Node the matrix test targets.
    pub node_id: NodeId,
    /// Each inner vec is one protocol ordering to test.
    pub protocol_combos: Vec<Vec<String>>,
    /// Relay modes to test (e.g. "transparent", "crypto_verify").
    pub relay_modes: Vec<String>,
    /// Unix timestamp when the job was created.
    pub started_at: u64,
    /// Number of combos completed so far.
    pub completed: usize,
    /// Total number of combos (protocol_combos.len() * relay_modes.len()).
    pub total: usize,
    pub status: MatrixJobStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MatrixJobStatus {
    Running,
    Done,
    Failed { reason: String },
}

/// One result entry from a matrix test run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatrixTestResult {
    pub job_id: u64,
    pub node_id: NodeId,
    /// The protocol ordering tested in this combo.
    pub protocol_combo: Vec<String>,
    pub relay_mode: String,
    pub tested_at: u64,
    pub connection_ok: bool,
    pub latency_ms: Option<u32>,
    pub throughput_mbps: Option<f32>,
    pub error: Option<String>,
}

/// One recorded benchmark result measuring throughput and latency through the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub id: u64,
    pub chain_id: String,
    pub measured_at: u64,
    /// Client mode: "socks5" | "tun"
    pub client_mode: String,
    /// L1 mode label from config, e.g. "socat-mirage"
    pub l1_mode: Option<String>,
    /// L2 protocol label, e.g. "xray-vless"
    pub l2_protocol: Option<String>,
    /// Download speed through SOCKS5 proxy in Mbps
    pub throughput_down_mbps: f32,
    /// Upload speed in Mbps (None if upload test skipped)
    pub throughput_up_mbps: Option<f32>,
    /// Median latency (CONNECT + first-byte) in ms
    pub latency_ms: f32,
    /// Jitter (stdev of per-chunk latencies) in ms
    pub jitter_ms: f32,
    /// Packet loss estimate from TCP retrans counters (0.0–100.0)
    pub packet_loss_pct: f32,
    /// How long the current chain has been connected at time of test, seconds
    pub connection_uptime_secs: u64,
    /// How many reconnects this chain has had since the monitor started
    pub reconnects_count: u32,
    pub error: Option<String>,
}

// === Client Registry Types ===

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistration {
    pub os: String,
    pub version: String,
    pub supported_transports: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sentinel_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shortname: Option<String>,
    /// Ownership proof for a RE-registration of an EXISTING `sentinel_id`:
    /// the `client_token` that id's last registration minted (same field
    /// name as `ClientTokenQuery::client_token`, the query-param shape used
    /// everywhere else on the client plane). Required whenever `sentinel_id`
    /// already has a row in the registry — without it the request is
    /// refused rather than handed a fresh token for someone else's id. Not
    /// required (and ignored) on a first registration of a fresh id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_token: Option<String>,
    /// The CLIENT'S OWN country — where the client is, not where it wants
    /// to exit.
    ///
    /// This is NOT the requested exit region. The requested exit region rides
    /// the chain request (`EntranceArtefact.mode = Country(..)`), and it says
    /// "give me an exit in THAT country". This field says "I am IN this
    /// country", which is what lets a client that asked for `auto` be served
    /// an exit in its own country.
    ///
    /// Canonical form is UPPERCASE (the same shape as the peer row's
    /// `region=CC` and the roster's `country`); the monitor normalises it at
    /// the registration boundary, so a client may send `"nl"`, `"NL"` or
    /// `" nl "` and the monitor stores `"NL"`.
    ///
    /// `None` means "the client did not say" — NOT "the client is in the
    /// server's country" and NOT "the client is nowhere". The monitor must
    /// not invent a country for a client that did not declare one: an
    /// invented country would silently send the client to a foreign exit.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientRegistrationResponse {
    pub client_id: String,
    pub monitor_poll_interval_secs: u64,
    /// Raw per-client token issued once at registration (shown once, not stored).
    /// Clients MUST persist this and present it as `?client_token=` on subscribe
    /// / config / heartbeat when the monitor enforces it (`require_client_token=true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub client_token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientHeartbeat {
    pub active_chains: Vec<ClientChainStatus>,
    pub total_bytes_tx: u64,
    pub total_bytes_rx: u64,
    pub uptime_secs: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientChainStatus {
    pub chain_name: String,
    pub transport: String,
    pub latency_ms: Option<u64>,
    pub bytes_tx: u64,
    pub bytes_rx: u64,
    pub errors: u64,
    pub connections: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientInfo {
    pub client_id: String,
    pub os: String,
    pub version: String,
    pub supported_transports: Vec<String>,
    /// ISO 8601
    pub registered_at: String,
    /// ISO 8601
    pub last_heartbeat: Option<String>,
    pub status: ClientStatus,
    pub heartbeat: Option<ClientHeartbeat>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shortname: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientStatus {
    Active,
    Stale,
    Dead,
}

/// Per-listener (sub-node) health observed from the probe.
/// One entry per TCP/UDP port the probe was asked to monitor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListenerInfo {
    /// Listener identifier — typically the systemd service name
    /// (`mirage-node-ru-relay-01-1`) or a logical name (`hop-0`).
    pub id: String,
    /// TCP/UDP port the listener should be bound to.
    pub port: u16,
    /// `true` if the port is in LISTEN state in /proc/net/tcp at scan time.
    pub listening: bool,
    /// `true` if the corresponding systemd service is active.
    /// `None` if no systemd service is associated.
    pub service_active: Option<bool>,
}

/// Transport health from probe
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransportHealth {
    /// "grpc", "websocket", "ssh", etc.
    pub name: String,
    pub port: u16,
    pub reachable: bool,
    pub latency_ms: Option<u64>,
    /// true if a protocol-level handshake confirmed the service speaks the
    /// expected protocol; false if only TCP connect succeeded or handshake
    /// was skipped for unknown transport names.
    #[serde(default)]
    pub protocol_verified: bool,
}

/// Full client config response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub version: u64,
    pub chains: Vec<ClientConfigChain>,
    pub monitor_poll_interval_secs: u64,
    /// Policy rules pushed from monitor. None = no change from current.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<mirage_core::split_policy::SplitPolicyConfig>,
    /// Per-chain camouflage overrides. None = no change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub camouflage: Option<HashMap<String, String>>,
    /// Per-chain shaping overrides. None = no change.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shaping: Option<HashMap<String, String>>,
    /// Minisign public key for verifying OTA artifact signatures.
    /// Supervisors fetch this from /relay/clients/config instead of hardcoding it.
    /// Operators rotate by editing monitor's config.toml.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ota_pubkey: Option<String>,
    /// Full peer-table snapshot: node_id → (pubkey_hex, addr, labels).
    /// `None` when the monitor has no peer_table entries yet (legacy / empty
    /// deployment).  Clients that receive a `Some` value MUST replace their
    /// in-memory peer_table; clients that receive `None` keep their current
    /// state (e.g. derived from chain hop public keys).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peer_table: Option<PeerTable>,
    /// Metadata collection directive pushed down by the operator.
    /// `None` = omit from response; clients keep their built-in default (no collection).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_policy: Option<mirage_core::metadata::MetadataPolicy>,
}

// ── OTA types ─────────────────────────────────────────────────────────────────

/// Per-platform artifact entry in an OTA manifest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtaPlatform {
    /// Download URL pointing to mirage2site (e.g. https://mirage2.site/ota/client/1.2.3/windows-x86_64.zip)
    pub url: String,
    /// SHA-256 hex digest of the zip archive
    pub sha256: String,
    /// Minisign signature blob (contents of the .minisig file)
    pub signature: String,
    /// File size in bytes
    pub size: u64,
}

/// OTA release manifest served by monitor and consumed by supervisors.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OtaManifest {
    /// Semver release version (e.g. "1.2.3")
    pub version: String,
    /// Release channel ("stable", "beta", "nightly")
    pub channel: String,
    /// Criticality hint ("critical", "recommended", "optional"). None = optional.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub criticality: Option<String>,
    /// Oldest version that can upgrade to this release directly.
    pub min_compat_version: String,
    /// ISO 8601 publish timestamp (e.g. "2026-04-26T12:00:00Z")
    pub pub_date: String,
    /// Human-readable release notes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
    /// Map from platform key (e.g. "windows-x86_64", "linux-x86_64-musl") to artifact.
    pub platforms: HashMap<String, OtaPlatform>,
}

/// Chain entry in `/relay/clients/config`.
///
/// Wraps the full mirage-core `ChainConfig` so the client gets all crypto
/// material in one shot (pubkeys, hops, protocol, camouflage, shaping, ...)
/// and never needs to hand-edit `client-config.json` to add or change a
/// chain. Plus monitor-only metadata (`healthy`, `latency_ms`) used for
/// selection and UI.
///
/// `#[serde(flatten)]` inlines every `ChainConfig` field at the top level
/// of the wire JSON, so a client can also deserialize the chain directly
/// into a `mirage_core::config::ChainConfig` if it ignores the metadata
/// fields (serde drops unknown fields by default).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfigChain {
    /// Full chain configuration, materialized from monitor's `StendRegistry`.
    /// Inlined into the wire JSON.
    #[serde(flatten)]
    pub chain: ChainConfig,

    // ── Monitor-only metadata (not part of wire ChainConfig) ────────────────
    /// Live health flag computed by monitor from probe reports.
    #[serde(default = "default_chain_healthy")]
    pub healthy: bool,

    /// Last measured latency to L1 (ms), if known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
}

fn default_chain_healthy() -> bool { true }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_report_serde_roundtrip() {
        let report = SentryReport {
            node_id: "l1-ru-1".to_string(),
            class: "mirage-node".to_string(),
            probe_version: "0.1.0".to_string(),
            reported_at: 1_700_000_000,
            services: vec![ServiceStatus {
                name: "socat".to_string(),
                running: true,
                pid: Some(1234),
                uptime_secs: Some(3600),
                extra: None,
            }],
            traffic: TrafficStats {
                interfaces: vec![InterfaceStats {
                    name: "eth0".to_string(),
                    rx_bytes: 1024,
                    tx_bytes: 512,
                    rx_packets: 10,
                    tx_packets: 5,
                    rx_errors: 0,
                    tx_errors: 0,
                }],
                wg_peers: vec![],
            },
            dns: vec![DnsResult {
                resolver: "127.0.0.1:53".to_string(),
                query: "example.com".to_string(),
                latency_ms: Some(2),
                success: true,
                error: None,
            }],
            ping_targets: vec![PingResult {
                target: "203.0.113.10".to_string(),
                sent: 4,
                received: 4,
                rtt_min_ms: Some(10.0),
                rtt_avg_ms: Some(12.0),
                rtt_max_ms: Some(15.0),
                packet_loss_pct: 0.0,
            }],
            system: SystemMetrics {
                load_1min: 0.1,
                mem_total_kb: 1_000_000,
                mem_available_kb: 800_000,
                uptime_secs: 86400,
            },
            connections: vec![ActiveConnection {
                local_port: 4430,
                remote_addr: "192.168.1.10".to_string(),
                remote_port: 51234,
                state: "ESTABLISHED".to_string(),
                service_hint: Some("awg".to_string()),
                metrics: Some(ConnectionTcpMetrics {
                    rtt_ms: 12.5,
                    rtt_var_ms: 3.1,
                    retransmits: 0,
                    bytes_received: 1024,
                    bytes_sent: 512,
                    age_secs: Some(300),
                }),
            }],
            port_throughput: vec![PortThroughput {
                local_port: 4430,
                service_hint: Some("awg".to_string()),
                rx_bps: 1024.0,
                tx_bps: 512.0,
                active_connections: 1,
                interval_secs: 10.0,
            }],
            node_metrics: None,
            transport_health: vec![],
            cpu_info: None,
            listeners: vec![],
        };
        let json = serde_json::to_string(&report).unwrap();
        let back: SentryReport = serde_json::from_str(&json).unwrap();
        assert_eq!(back.node_id, "l1-ru-1");
        assert_eq!(back.class, "mirage-node");
        assert_eq!(back.connections.len(), 1);
        assert_eq!(back.connections[0].local_port, 4430);
        assert!(back.connections[0].metrics.is_some());
        assert_eq!(back.port_throughput.len(), 1);
    }

    #[test]
    fn probe_report_connections_default_on_missing_field() {
        // Simulate an old probe report JSON that has no "connections" field
        let json = r#"{
            "node_id": "l1-ru-1",
            "class": "mirage-node",
            "probe_version": "0.1.0",
            "reported_at": 1700000000,
            "services": [],
            "traffic": {"interfaces": [], "wg_peers": []},
            "dns": [],
            "ping_targets": [],
            "system": {"load_1min": 0.0, "mem_total_kb": 0, "mem_available_kb": 0, "uptime_secs": 0}
        }"#;
        let back: SentryReport = serde_json::from_str(json).unwrap();
        assert!(back.connections.is_empty());
        assert!(back.port_throughput.is_empty());
    }

    #[test]
    fn link_metrics_serde_roundtrip() {
        let m = LinkMetrics {
            l1_id: "l1-ru-1".to_string(),
            l2_id: "l2-eu-1".to_string(),
            measured_at: 1_700_000_000,
            l1_to_l2_latency_ms: Some(25.0),
            l2_to_l1_latency_ms: Some(28.0),
            l1_to_l2_loss_pct: Some(0.0),
            quality: LinkQuality::Good,
        };
        let json = serde_json::to_string(&m).unwrap();
        let back: LinkMetrics = serde_json::from_str(&json).unwrap();
        assert_eq!(back.quality, LinkQuality::Good);
    }

    #[test]
    fn alert_serde_roundtrip() {
        let a = Alert {
            id: 1,
            ts: 1_700_000_000,
            severity: AlertSeverity::Critical,
            node_id: Some("l1-ru-1".to_string()),
            kind: AlertKind::ServiceDown {
                service_name: "socat".to_string(),
            },
            message: "socat is down on l1-ru-1".to_string(),
            acked: false,
        };
        let json = serde_json::to_string(&a).unwrap();
        let back: Alert = serde_json::from_str(&json).unwrap();
        assert_eq!(back.id, 1);
        assert!(!back.acked);
    }

    #[test]
    fn protocol_test_result_serde_roundtrip() {
        let t = ProtocolTestResult {
            l1_id: "l1-ru-1".to_string(),
            l2_id: "l2-eu-1".to_string(),
            protocol: "awg".to_string(),
            tested_at: 1_700_000_000,
            reachable: true,
            port: 51820,
            latency_ms: Some(30),
            error: None,
            dpi_likely: false,
        };
        let json = serde_json::to_string(&t).unwrap();
        let back: ProtocolTestResult = serde_json::from_str(&json).unwrap();
        assert!(back.reachable);
        assert!(!back.dpi_likely);
    }
}
