use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

/// Full configuration for a relay/exit node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    pub node_id: String,
    pub listen_addr: SocketAddr,
    pub mode: NodeMode,
    pub protocols: Vec<ProtocolId>,
    /// Hex-encoded X25519 secret key. **Plaintext on disk** — preferred only
    /// in dev / unit-test fixtures. Production deployments should leave this
    /// empty and set [`Self::private_key_credential`] instead so the key
    /// arrives via systemd's encrypted-credential channel (see
    /// `LoadCredentialEncrypted=` in the unit file).
    #[serde(default)]
    pub private_key: String,

    /// Name of a sealed credential to load the X25519 secret key from.
    ///
    /// When set and `$CREDENTIALS_DIRECTORY` is exported by systemd at unit
    /// start, mirage-node reads the hex-encoded private key from
    /// `${CREDENTIALS_DIRECTORY}/<private_key_credential>` instead of the
    /// `private_key` field. The on-disk node-config never carries the key
    /// in plaintext, and host-bound systemd-creds encryption protects
    /// against disk theft / backup leak. Unset falls back to `private_key`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub private_key_credential: Option<String>,
    pub admin_endpoint: Option<String>,
    pub health_interval_secs: u64,
    /// Pre-shared key for ShadowTLS and Hysteria2 (hex-encoded, 32 bytes).
    pub psk: Option<String>,
    /// Mirage-UDP protocol configuration.  Used when a legacy `endpoint_configs[]`
    /// entry selects `MirageUdp` wire without a full `TransportCamouflage::RawUdp`
    /// axis. Kept for `endpoint_configs` backward-compat only.
    #[serde(default)]
    pub mirage_udp: Option<MirageUdpConfig>,
    /// Address for the embedded management HTTP server.
    /// Defaults to `"127.0.0.1:4499"` when omitted.
    /// When `management_key` is `None` the management server does not start.
    #[serde(default)]
    pub management_addr: Option<String>,
    /// Pre-shared key for management API Bearer authentication.
    /// When `None` (or absent from JSON) the management server is disabled.
    #[serde(default)]
    pub management_key: Option<String>,
    /// MirageExit thin L2-exit protocol configuration.
    ///
    /// Shared by all three MirageExit variants (Minimal / Full / Hmac).
    /// When present, mirage-node spawns a dedicated UDP listener on
    /// `mirage_exit.bind_addr` for UDP variants of the protocol.
    #[serde(default)]
    pub mirage_exit: Option<MirageExitConfig>,
    /// Position of this node in the onion chain (0-based from Entry).
    ///
    /// Only used when [`RelayMode::OnionPeel`] is active.  Must match the
    /// hop index used on the client side when calling `build_onion_ephemeral`.
    #[serde(default)]
    pub onion_hop_position: Option<u8>,
    /// Reply wrapping mode for onion-routed connections.
    ///
    /// - `Onion` (default): each reply chunk is wrapped in `wrap_reply_layer` and
    ///   sent with a 4-byte BE length prefix so the client can peel per-hop AEAD.
    /// - `Raw`: reply bytes are copied bidirectionally without wrapping (legacy).
    #[serde(default = "default_onion_reply_mode")]
    pub onion_reply_mode: ReplyMode,
    /// Peek-multiplex decoy configuration.
    ///
    /// When set, mirage-node spawns an additional TCP listener on
    /// `decoy.peek_port`.  Each accepted connection is peek-inspected: if the
    /// first bytes match `tunnel_magic` the stream is handed to the normal
    /// tunnel dispatcher; otherwise it is forwarded bidirectionally to
    /// `decoy_forward_addr` (e.g. nginx / Grafana running on a local port).
    ///
    /// This protects against port-probing: an outside party that connects and sends
    /// a plain TLS ClientHello will receive a legitimate HTTPS response from
    /// the decoy backend instead of a "connection refused" or VPN fingerprint.
    ///
    /// The client side does **not** require any extra configuration: just set
    /// [`ByteCipherMode::ValidateFirst`] with the same value as
    /// `decoy.tunnel_magic` — the wrapper will prepend those bytes so the
    /// decoy listener routes the connection to the tunnel path automatically.
    #[serde(default)]
    pub decoy: Option<DecoyConfig>,
    /// Multi-backend decoy system: multiple ports each with a rule-based router.
    ///
    /// When set, mirage-node spawns independent TCP listeners for each entry in
    /// `multi_decoy.ports`. Each accepted connection is peek-inspected; the
    /// first matching rule determines whether it is forwarded to a backend, handed
    /// to the tunnel dispatcher, rejected, or given a static response.
    ///
    /// Compatible with the legacy `decoy` field — both can be active at the same time.
    #[serde(default)]
    pub multi_decoy: Option<MultiDecoyConfig>,
    /// New unified protocol configuration (replaces `protocols` + per-protocol fields).
    ///
    /// When present, mirage-node uses this list instead of the legacy `protocols`
    /// field to select wire protocol, auth strategy, and transport camouflage.
    /// Each entry describes one inbound endpoint (TCP or UDP).
    #[serde(default)]
    pub endpoint_configs: Vec<MirageEndpointConfig>,
    /// When `true`, mirage-node skips the TCP listener bound on `listen_addr`
    /// and serves only the UDP endpoints in `endpoint_configs[]` /
    /// `udp_relay[]`. Used for "UDP aggregator" NodeConfigs that stend-gen
    /// emits to collapse all `udp_*`-mode listeners on a single node into one
    /// process. Default `false` keeps the legacy TCP-binding behaviour.
    #[serde(default)]
    pub udp_only: bool,
    /// Transparent UDP relay bindings (for multi-hop UDP chains where L1 is
    /// a byte pump). Each entry pairs a `bind_addr` UDP listener with a
    /// fixed upstream UDP `upstream_addr`. mirage-node spawns one
    /// `relay::udp_transparent::spawn_udp_transparent` task per binding.
    /// Empty by default — only set on L1 nodes that participate in
    /// multi-hop UDP topologies.
    #[serde(default)]
    pub udp_relay: Vec<UdpRelayBinding>,
    /// Known onion peers for telescopic extend: static public key (hex) → TCP address.
    ///
    /// Used when a telescopic EXTEND message arrives and the node needs to
    /// resolve the next-hop address from its static public key.  Only required
    /// on nodes that participate in telescopic circuit extension.  Optional —
    /// not required on nodes that never receive an EXTEND message.
    #[serde(default)]
    pub onion_known_peers: std::collections::HashMap<String, String>,
    /// If `true`, this node accepts telescopic circuit establishment
    /// (`CREATE` / `EXTEND` / `RELAY` frames) instead of the regular
    /// ephemeral onion-peel path.
    ///
    /// Requires `RelayMode::OnionPeel` to be set.  Defaults to `false`.
    #[serde(default)]
    pub onion_telescopic: bool,
    /// Role of this node in the mesh — entry / hop / exit. Tagged enum:
    /// the JSON object carries a `role` discriminator (`entry_node` /
    /// `hop_node` / `exit_node`) plus role-specific listener lists.
    #[serde(default = "default_node_role")]
    pub role: NodeRole,
    /// Box-local subscriber-entrance configuration — set only on a box
    /// provisioned to accept paying-customer dials on its own `NodeChain`
    /// face (`docs/mirage/plans/subscriber-gate-and-fork-2026-09-17.md`).
    /// `None` on every node that is not such a box. `Option` +
    /// `#[serde(default)]` so every other node's `node.toml` keeps
    /// deserialising unchanged — the same pattern `admin_endpoint` /
    /// `mirage_udp` already use on this struct.
    #[serde(default)]
    pub subscriber_entrance: Option<SubscriberEntranceConfig>,
    /// Path to this box's subscriber-key file — the JSON `opbox` writes and
    /// `mirage-node`'s `core::subscriber_keys::spawn_hot_reload` polls
    /// (`docs/mirage/plans/delivery-artefact-and-issuance-2026-09-17.md`
    /// step order item 2). `None` on every node that is not provisioned as a
    /// subscriber entrance — same `Option` + `#[serde(default)]` discipline
    /// as `subscriber_entrance` above, so every other node's `node.toml`
    /// keeps deserialising unchanged.
    #[serde(default)]
    pub subscriber_keys_path: Option<PathBuf>,
}

/// Box-local configuration for a subscriber entrance: so `mirage-node`'s
/// `core::chain_splice::dispatch_entrance` can hand an authenticated
/// subscriber's stream to cli2's edge-client supervisor, plus the byte-rate
/// bandwidth cap `core::entrance_dispatch` enforces on that stream
/// (`docs/mirage/plans/commercial-client-on-the-box-2026-09-17.md` build item
/// 2 — see `mirage-node`'s `core::bandwidth_cap` module for the cap itself
/// and the numbers each `None` here defaults to).
///
/// **The hand-off is a fixed unix channel, not a configurable address**
/// (owner ruling 2026-09-23: boxes carry no internal TCP ports; every
/// in-box channel is a unix socket under `/run/mirage/*`, admitted uids only
/// — see `docs/mirage/plans/local-transport-unix-sockets-2026-08-15.md`).
/// `mirage-node` dials [`crate::local_endpoint::LocalChannel::
/// EdgeClientEntrance`] — a fixed path
/// (`/run/mirage/edge-client/entrance.sock`), SO_PEERCRED-admitted to the
/// node's own account only — the same way every other in-box splice already
/// resolves its peer through [`crate::local_endpoint::LocalChannel`] rather
/// than a loopback port carried in config. The stream framing riding that
/// socket is unchanged: still SOCKS5, since it only names the destination.
///
/// This struct therefore carries no address field at all — its own presence
/// (`Option<SubscriberEntranceConfig>` on [`NodeConfig`]) is what signals
/// "this box hands subscriber streams to cli2", exactly like
/// [`NodeConfig::subscriber_keys_path`]'s own presence-as-flag. Set once at
/// provisioning — opbox writes this into `node.toml`. Every cap field is
/// independently optional so an existing entrance box that predates a given
/// cap, or one an operator has not yet tuned, keeps running fully uncapped:
/// `mirage-node` only builds a limiter at all when
/// `aggregate_rate_bytes_per_sec` is set, and every other field defaults off
/// THAT one field alone.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubscriberEntranceConfig {
    /// Retired 2026-09-23 — replaced by [`crate::local_endpoint::
    /// LocalChannel::EdgeClientEntrance`], a fixed unix socket, not a
    /// per-box loopback port. Accepted-and-ignored for ONE release so an
    /// old `node.toml` still carrying a `socks_addr` value keeps
    /// deserialising instead of failing the whole node's config load;
    /// never read, never (re-)serialised. Delete this field once every
    /// fleet box has rolled past this release.
    #[serde(default, rename = "socks_addr", skip_serializing)]
    pub legacy_socks_addr: Option<SocketAddr>,

    /// Sustained aggregate byte rate for the whole subscriber, both
    /// directions combined ("bandwidth sold is bandwidth total"). `None`
    /// leaves the subscriber entirely uncapped — `mirage-node` does not
    /// construct a limiter for this box at all until an operator sets this.
    #[serde(default)]
    pub aggregate_rate_bytes_per_sec: Option<u64>,

    /// Burst allowance on top of the aggregate rate, so an ordinary page
    /// load draws at full speed instead of visibly throttling. `None`
    /// defaults to a flat size chosen to cover an average web page
    /// regardless of the plan's sustained rate — see
    /// `mirage-node::core::bandwidth_cap::DEFAULT_AGGREGATE_BURST_BYTES`.
    /// Ignored while `aggregate_rate_bytes_per_sec` is `None`.
    #[serde(default)]
    pub aggregate_burst_bytes: Option<u64>,

    /// Per-connection byte-rate ceiling inside the aggregate, so one heavy
    /// connection (a large download) cannot starve the subscriber's other
    /// open connections (his other tabs). `None` defaults to half of
    /// `aggregate_rate_bytes_per_sec`. Ignored while
    /// `aggregate_rate_bytes_per_sec` is `None`.
    #[serde(default)]
    pub per_connection_rate_bytes_per_sec: Option<u64>,

    /// Monthly byte volume for the subscriber, both directions combined.
    /// `None` (the default) means no monthly cap at all — the subscription
    /// is metered elsewhere, or this plan has none. Independent of
    /// `aggregate_rate_bytes_per_sec`: a box can meter volume with no
    /// byte-rate cap, though in practice both are set together.
    #[serde(default)]
    pub monthly_volume_bytes: Option<u64>,

    /// Sustained byte rate the aggregate bucket degrades to once
    /// `monthly_volume_bytes` is exhausted for the current billing cycle.
    /// Service continues at this rate rather than being cut off; recovers
    /// automatically at the next cycle. `None` defaults to a low flat
    /// floor — see
    /// `mirage-node::core::bandwidth_cap::DEFAULT_DEGRADED_FLOOR_BYTES_PER_SEC`.
    /// Ignored while `monthly_volume_bytes` is `None`.
    #[serde(default)]
    pub degraded_floor_bytes_per_sec: Option<u64>,
}

/// Default role for [`NodeConfig`] when omitted from JSON — a pure mirage hop
/// with no listeners declared.  Used so existing operator-side `NodeConfig`
/// objects that pre-date the role split keep deserialising.
fn default_node_role() -> NodeRole {
    NodeRole::HopNode { mirage_listeners: Vec::new() }
}

/// Role of a mirage node in the mesh.
///
/// Tagged externally — the JSON object carries a `role` field with one of
/// `entry_node` / `hop_node` / `exit_node`, plus role-specific listener arrays.
///
/// - **Entry**: L1 box that clients connect to. Owns native mirage listeners.
/// - **Hop**: pure intermediate mirage relay. Mirage listeners only.
/// - **Exit**: L2 box. Native mirage exits.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "role", rename_all = "snake_case")]
pub enum NodeRole {
    /// L1 entry box. Native mirage listeners only.
    EntryNode {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        mirage_listeners: Vec<MirageListenerConfig>,
    },
    /// Pure intermediate hop. Mirage only.
    HopNode {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        mirage_listeners: Vec<MirageListenerConfig>,
    },
    /// L2 exit. Native mirage exits.
    ExitNode {
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        mirage_listeners: Vec<MirageListenerConfig>,
    },
}

/// One mirage-family TCP listener — bind address, relay mode, and the set of
/// mirage TCP wire protocols this listener accepts.
///
/// UDP wires stay declared via the pre-existing `endpoint_configs` vector on
/// [`NodeConfig`] — those entries already carry their own bind address inside
/// `TransportCamouflage`, so they remain self-describing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirageListenerConfig {
    /// Address this listener binds to (TCP socket).
    pub bind_addr: String,
    /// How L1 forwards traffic. One mode: `OnionPeel`.
    pub mode: RelayMode,
    /// Mirage-family TCP wires this listener accepts on the same socket.
    pub protocols: Vec<TcpProtocolId>,
}

/// One transparent UDP relay binding (`relay::udp_transparent`).
///
/// Used for multi-hop UDP chains where L1 has no crypto / protocol awareness
/// — packets travel as raw UDP datagrams through L1 to a fixed upstream L2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpRelayBinding {
    /// Local UDP socket address mirage-node binds.
    pub bind_addr: SocketAddr,
    /// Upstream UDP address (typically L2's `udp_*` listener).
    ///
    /// Single-hop: datagrams forwarded directly to this address.
    /// Multi-hop (when `next_hop_addr` is `Some`): this field is the final
    /// target on the exit node and is not used by the entry relay — it is
    /// only present so the spec is self-describing. The entry relay forwards
    /// to `next_hop_addr`; the exit node's own `UdpRelayBinding.upstream_addr`
    /// points at the real target service.
    pub upstream_addr: SocketAddr,
    /// Next-hop relay address for 2-hop UDP relay chains.
    ///
    /// When `Some`, the entry node forwards client datagrams to this address
    /// instead of `upstream_addr`. The exit node at `next_hop_addr` has its
    /// own `UdpRelayBinding` whose `upstream_addr` is the real target service.
    ///
    /// When `None`, single-hop semantics apply and datagrams go directly to
    /// `upstream_addr`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_hop_addr: Option<SocketAddr>,
    /// Per-session idle timeout in seconds. `0` → 60 s default.
    #[serde(default)]
    pub idle_secs: u64,
    /// Optional byte-cipher peel applied to inbound datagrams.
    ///
    /// `None` → byte-pump (transparent forwarder).
    /// `Some(mode)` → `ByteCipher::unwrap` per inbound datagram; on
    /// `MagicMismatch` the session is dropped. Outbound (upstream → client)
    /// datagrams are forwarded as-is — byte_cipher is inbound-only at L1.
    /// Per-session state (counter for `ObfuscateAll`, `first_done` for
    /// `ValidateFirst`/`StripFirst`) is keyed on `client_addr`.
    #[serde(default)]
    pub byte_cipher: Option<ByteCipherMode>,
}

/// Operating mode of a node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NodeMode {
    Relay(RelayConfig),
    Exit(ExitConfig),
    Hybrid { relay: RelayConfig, exit: ExitConfig },
}

/// How the relay forwards traffic to the upstream. There is one way.
///
/// # The two that were removed (2026-09-02)
///
/// `TransparentTcp` was a blind byte pump and `CryptoVerify` peeled one
/// static-keyed byte-cipher skin and then piped. Neither terminated the tunnel
/// — that is what made them relays a client could trust — and neither could
/// know WHICH listener a connection belonged to, because the bind port
/// answered that. Chain hops no longer bind ports outside the perimeter, so
/// their addressing is gone, and a hop that never terminates cannot read a
/// selector to replace it.
///
/// The VARIANTS are gone so no config can hold one. The READER is not: the
/// hand-written `Deserialize` below still recognises both names and refuses
/// them BY NAME, so a `node.toml` written against the old taxonomy fails at
/// boot saying what happened — not with `unknown variant`, and never by
/// silently becoming something the operator did not write.
///
/// [`ByteCipherMode`] did NOT go with them. The onion ENTRY hop still strips a
/// skin, with its own peel in `tunnel_tcp::peel_onion_ingress_skin`, which
/// reads this module's `ByteCipherMode` and never touched the retired modes'
/// implementations.
#[derive(Debug, Clone, Serialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayMode {
    /// Onion-routing peel: decrypt one layer, forward remainder to next hop.
    ///
    /// This hop's static X25519 keypair and `onion_hop_position` from
    /// [`NodeConfig`] derive the layer key via ECDH, peel the layer, and
    /// forward the remainder.
    #[default]
    OnionPeel,
}

impl<'de> Deserialize<'de> for RelayMode {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = String::deserialize(d)?;
        match raw.as_str() {
            "onion_peel" => Ok(RelayMode::OnionPeel),
            retired @ ("transparent_tcp" | "crypto_verify") => Err(serde::de::Error::custom(
                format!(
                    "relay mode {retired:?} was removed on 2026-09-02: it never terminated the \
                     tunnel and was addressed by its bind port, and chain hops no longer bind \
                     ports outside the perimeter. Use \"onion_peel\", which is now the only \
                     relay mode. The byte_cipher axis is unaffected and still rides the entry hop."
                ),
            )),
            other => Err(serde::de::Error::unknown_variant(other, &["onion_peel"])),
        }
    }
}

/// How an exit node terminates tunnel traffic into the public internet.
///
/// L2-only — relay nodes use [`RelayMode`] instead.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitMode {
    /// Classic 2-hop exit: destination arrives as a "host:port" UTF-8 string
    /// in the first AEAD frame of the tunnel from the client.
    ///
    /// Used when the upstream L1 was `transparent` / `crypto_verify` —
    /// it did not alter the tunnel destination.
    #[default]
    Direct,
    /// Onion exit: peel the Terminal (innermost) onion layer and connect to
    /// the destination encoded within.
    ///
    /// Used when the client built a multi-hop onion chain and the L1 path
    /// used `onion_peel`.
    Onion,
    /// Control exit: after AEAD peel, forward the plaintext byte stream
    /// directly to the monitor's over-chain control listener.
    ///
    /// No further Mirage framing is applied — the client's OverChainChannel
    /// owns the application-level protocol (AUTH_CHALLENGE → AUTH → loop).
    /// The target address is carried in `ListenerSpec.control_target`.
    Control,
}

/// Strategy for distributing connections across multiple upstreams.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalanceStrategy {
    /// Cycle through upstreams in order (default).
    #[default]
    RoundRobin,
    /// Pick an upstream at random for each new connection.
    Random,
    /// Route to the upstream with the fewest active connections.
    LeastConnections,
}

fn default_upstream_pool_size() -> usize { 2 }
fn default_upstream_pool_max_idle_secs() -> u64 { 90 }

/// Configuration for relay-mode operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayConfig {
    /// Host:port to forward traffic to when no matching rule is found.
    pub fallback_dest: String,
    /// SNI used for the fallback TLS connection (e.g. `"api.cloud.yandex.net"`).
    pub fallback_sni: String,
    pub upstreams: Vec<UpstreamNode>,
    /// How the relay forwards traffic (crypto vs transparent TCP pipe).
    #[serde(default)]
    pub mode: RelayMode,
    /// Load-balancing strategy across multiple upstreams.
    #[serde(default)]
    pub lb_strategy: LoadBalanceStrategy,
    /// Number of pre-warmed upstream tunnels to maintain per upstream node.
    /// Legacy pool sizing — unused after v2 cleanup (no relay mode
    /// re-handshakes anymore). Kept on the struct so historical JSON
    /// configs continue to deserialise.  Default: 2.
    #[serde(default = "default_upstream_pool_size")]
    pub upstream_pool_size: usize,
    /// Maximum seconds a tunnel may sit idle in the upstream pool before being
    /// discarded on lease.  Prevents stale QUIC connections from being handed
    /// to request handlers.  0 = no limit.  Default: 90.
    #[serde(default = "default_upstream_pool_max_idle_secs")]
    pub upstream_pool_max_idle_secs: u64,
}

/// A known upstream node reachable from this relay.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamNode {
    pub addr: SocketAddr,
    /// Hex-encoded X25519 public key.
    pub public_key: String,
    pub protocol: ProtocolId,
}

/// Configuration for exit-mode operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitConfig {
    /// DNS-over-HTTPS resolver URL (e.g. `"https://1.1.1.1/dns-query"`).
    pub dns_resolver: String,
    pub nat_enabled: bool,
    /// How the exit node interprets incoming tunnel frames (Direct vs Onion).
    #[serde(default)]
    pub mode: ExitMode,
    /// Prefer AAAA over A records when both resolve.
    ///
    /// `None` (absent from JSON) → treated as `true` at the resolver level.
    /// Operators who need IPv4-only exit can set `false` explicitly.
    #[serde(default)]
    pub dns_prefer_ipv6: Option<bool>,
}

// TcpProtocolId / UdpProtocolId / ProtocolId moved to crate::mirage::wire::protocol_id.
pub use crate::mirage::wire::{ProtocolId, TcpProtocolId, UdpProtocolId};

/// MirageTLS protocol configuration.
///
/// Controls which upstream TLS host is used for the outer TLS camouflage layer.
/// The Mirage handshake and AEAD framing are carried inside TLS AppData records,
/// so the SNI presented in the ClientHello must match `upstream_tls_host`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirageTlsConfig {
    /// Hostname to present as SNI in the TLS ClientHello (and the host the
    /// server certificate is validated against on the client side).
    /// Default: `"cloudflare.com"`.
    #[serde(default = "default_mirage_tls_host")]
    pub upstream_tls_host: String,
    /// Port of the upstream TLS backend.  Default: `443`.
    #[serde(default = "default_mirage_tls_port")]
    pub upstream_tls_port: u16,
    /// SNI value in the ClientHello.  Must match `upstream_tls_host` for the
    /// camouflage to be convincing.
    #[serde(default = "default_mirage_tls_sni")]
    pub sni: String,
}

fn default_mirage_tls_host() -> String { "cloudflare.com".to_owned() }
fn default_mirage_tls_port() -> u16 { 443 }
fn default_mirage_tls_sni() -> String { "cloudflare.com".to_owned() }

impl Default for MirageTlsConfig {
    fn default() -> Self {
        Self {
            upstream_tls_host: default_mirage_tls_host(),
            upstream_tls_port: default_mirage_tls_port(),
            sni: default_mirage_tls_sni(),
        }
    }
}

// ── Mirage-HTTP3 defaults ─────────────────────────────────────────────────────

fn default_mirage_http3_bind_addr() -> String { "0.0.0.0:4438".to_owned() }
fn default_mirage_http3_alpn() -> Vec<String> { vec!["h3".to_owned()] }
fn default_mirage_http3_tunnel_path() -> String { "/api/v1/events".to_owned() }
fn default_mirage_http3_authority() -> String { "www.googleapis.com".to_owned() }
fn default_mirage_http3_max_streams() -> u32 { 100 }

/// Mirage-HTTP3 protocol configuration.
///
/// Mirage-HTTP3 tunnels Mirage AEAD frames inside HTTP/3 (QUIC) streaming
/// request/response bodies.  The ALPN negotiated is `"h3"` so the connection
/// is indistinguishable from Chrome or Firefox making HTTP/3 requests.
///
/// The server binds a separate UDP socket at `bind_addr` (HTTP/3 runs over
/// QUIC/UDP, not TCP).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirageHttp3Config {
    /// UDP address to bind on the server side, e.g. `"0.0.0.0:4438"`.
    #[serde(default = "default_mirage_http3_bind_addr")]
    pub bind_addr: String,
    /// ALPN protocol list.  Must include `"h3"` for the connection to look like
    /// legitimate HTTP/3 traffic.  Default: `["h3"]`.
    #[serde(default = "default_mirage_http3_alpn")]
    pub alpn: Vec<String>,
    /// HTTP path on which the tunnel is accepted.  The client sends a POST to
    /// this path; any other path returns HTTP 404 (probe-resistant).
    /// Default: `"/api/v1/events"`.
    #[serde(default = "default_mirage_http3_tunnel_path")]
    pub tunnel_path: String,
    /// HTTP `:authority` / `Host` header value presented by the client.
    /// Should be a plausible hostname that DPI would expect for HTTPS/3 traffic.
    /// Default: `"www.googleapis.com"`.
    #[serde(default = "default_mirage_http3_authority")]
    pub authority: String,
    /// Maximum number of concurrent bidirectional QUIC streams per connection.
    /// Default: 100.
    #[serde(default = "default_mirage_http3_max_streams")]
    pub max_streams: u32,
}

impl Default for MirageHttp3Config {
    fn default() -> Self {
        Self {
            bind_addr: default_mirage_http3_bind_addr(),
            alpn: default_mirage_http3_alpn(),
            tunnel_path: default_mirage_http3_tunnel_path(),
            authority: default_mirage_http3_authority(),
            max_streams: default_mirage_http3_max_streams(),
        }
    }
}

/// QUIC/HTTP3 protocol configuration.
///
/// QUIC uses UDP and runs on a separate port from the TCP listener.  The server
/// binds a UDP socket at `bind_addr`; clients connect to that address.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuicConfig {
    /// UDP address to bind on the server side, e.g. `"0.0.0.0:4431"`.
    pub bind_addr: String,
    /// Maximum number of concurrent bidirectional streams per connection.
    #[serde(default = "default_quic_max_streams")]
    pub max_streams: u32,
}

fn default_quic_max_streams() -> u32 {
    100
}

impl Default for QuicConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:4431".to_owned(),
            max_streams: default_quic_max_streams(),
        }
    }
}

/// Hysteria2/UDP protocol configuration.
///
/// Hysteria2 uses UDP datagrams and therefore cannot share the TCP listener.
/// The server binds a separate UDP socket at `bind_addr`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HysteriaConfig {
    /// UDP address to bind on the server side, e.g. `"0.0.0.0:4435"`.
    pub bind_addr: String,
}

impl Default for HysteriaConfig {
    fn default() -> Self {
        Self {
            bind_addr: "0.0.0.0:4435".to_owned(),
        }
    }
}

fn default_junk_count() -> u8 { 5 }
fn default_junk_min_size() -> u16 { 50 }
fn default_junk_max_size() -> u16 { 1000 }
fn default_mirage_udp_bind_addr() -> String { "0.0.0.0:4436".to_owned() }

/// Mirage-UDP protocol configuration.
///
/// Mirage-UDP is the UDP variant of the Mirage TCP protocol.  It adds an
/// AmneziaWG-style junk-packet phase before the real handshake to make the
/// traffic pattern indistinguishable from random UDP noise.
///
/// The server binds a separate UDP socket at `bind_addr` since UDP cannot share
/// the TCP listener.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirageUdpConfig {
    /// UDP address to bind on the server side, e.g. `"0.0.0.0:4436"`.
    #[serde(default = "default_mirage_udp_bind_addr")]
    pub bind_addr: String,
    /// Number of junk UDP datagrams the client sends before the real handshake.
    /// Default: 5.
    #[serde(default = "default_junk_count")]
    pub junk_count: u8,
    /// Minimum size in bytes of each junk datagram (inclusive).  Default: 50.
    #[serde(default = "default_junk_min_size")]
    pub junk_min_size: u16,
    /// Maximum size in bytes of each junk datagram (inclusive).  Default: 1000.
    #[serde(default = "default_junk_max_size")]
    pub junk_max_size: u16,
}

impl Default for MirageUdpConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_mirage_udp_bind_addr(),
            junk_count: default_junk_count(),
            junk_min_size: default_junk_min_size(),
            junk_max_size: default_junk_max_size(),
        }
    }
}

// ── Mirage-WG defaults ────────────────────────────────────────────────────────

fn default_mirage_wg_s1() -> u32 { 1 }
fn default_mirage_wg_s2() -> u32 { 2 }
fn default_mirage_wg_s3() -> u32 { 3 }
fn default_mirage_wg_s4() -> u32 { 4 }
fn default_mirage_wg_junk_count() -> u8 { 4 }
fn default_mirage_wg_junk_min() -> u16 { 50 }
fn default_mirage_wg_junk_max() -> u16 { 1000 }
fn default_mirage_wg_h1() -> u32 { 0x4a56_1cde }
fn default_mirage_wg_h2() -> u32 { 0x6b23_4e7f }
fn default_mirage_wg_h3() -> u32 { 0x9d18_3a2c }
fn default_mirage_wg_h4() -> u32 { 0xc0fa_5b91 }
fn default_mirage_wg_init_junk() -> u16 { 0 }
fn default_mirage_wg_resp_junk() -> u16 { 0 }
fn default_mirage_wg_bind_addr() -> String { "0.0.0.0:4437".to_owned() }

/// Mirage-WG protocol configuration.
///
/// AmneziaWG-compatible wire protocol: WireGuard Noise_IK over UDP with
/// configurable junk-packet burst before the handshake and randomised
/// WireGuard message-type magic bytes so classic WG DPI signatures do not fire.
///
/// All fields have sane defaults; only `bind_addr` is typically overridden.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirageWgConfig {
    /// UDP address to bind on the server side, e.g. `"0.0.0.0:4437"`.
    #[serde(default = "default_mirage_wg_bind_addr")]
    pub bind_addr: String,

    // ── AmneziaWG magic bytes (replace WG message types 1/2/3/4) ─────────────
    /// Magic for WG Initiation (replaces 0x01).  Default: 1 (WG-compatible).
    #[serde(default = "default_mirage_wg_s1")]
    pub s1_magic: u32,
    /// Magic for WG Response (replaces 0x02).  Default: 2.
    #[serde(default = "default_mirage_wg_s2")]
    pub s2_magic: u32,
    /// Magic for WG Cookie (replaces 0x03).  Default: 3.
    #[serde(default = "default_mirage_wg_s3")]
    pub s3_magic: u32,
    /// Magic for WG Data (replaces 0x04).  Default: 4.
    #[serde(default = "default_mirage_wg_s4")]
    pub s4_magic: u32,

    // ── Junk packets (sent before the WG handshake) ───────────────────────────
    /// Number of junk UDP datagrams sent by the client before the real handshake.  Default: 4.
    #[serde(default = "default_mirage_wg_junk_count")]
    pub junk_count: u8,
    /// Minimum junk datagram size in bytes (inclusive).  Default: 50.
    #[serde(default = "default_mirage_wg_junk_min")]
    pub junk_min_size: u16,
    /// Maximum junk datagram size in bytes (inclusive).  Default: 1000.
    #[serde(default = "default_mirage_wg_junk_max")]
    pub junk_max_size: u16,

    // ── Packet magic headers (H-params; additional obfuscation) ──────────────
    /// Magic header placed at byte 0 of Initiation packets.  Default: random constant.
    #[serde(default = "default_mirage_wg_h1")]
    pub init_packet_magic_header: u32,
    /// Magic header placed at byte 0 of Response packets.  Default: random constant.
    #[serde(default = "default_mirage_wg_h2")]
    pub response_packet_magic_header: u32,
    /// Magic header placed at byte 0 of Cookie packets.  Default: random constant.
    #[serde(default = "default_mirage_wg_h3")]
    pub underload_packet_magic_header: u32,
    /// Magic header placed at byte 0 of Data packets.  Default: random constant.
    #[serde(default = "default_mirage_wg_h4")]
    pub transport_packet_magic_header: u32,

    // ── Init/Response packet junk (S-params; trailing random bytes) ──────────
    /// Extra random bytes appended to each Initiation packet.  Default: 0.
    #[serde(default = "default_mirage_wg_init_junk")]
    pub init_packet_junk_size: u16,
    /// Extra random bytes appended to each Response packet.  Default: 0.
    #[serde(default = "default_mirage_wg_resp_junk")]
    pub response_packet_junk_size: u16,

    // ── Probe resistance ──────────────────────────────────────────────────────
    /// Optional fallback address for unrecognised UDP datagrams.
    /// When `None` (default), invalid packets are silently dropped.
    #[serde(default)]
    pub fallback_dest: Option<SocketAddr>,
    /// Optional SNI hint for the fallback destination.
    #[serde(default)]
    pub fallback_sni: Option<String>,
}

impl Default for MirageWgConfig {
    fn default() -> Self {
        Self {
            bind_addr: default_mirage_wg_bind_addr(),
            s1_magic: default_mirage_wg_s1(),
            s2_magic: default_mirage_wg_s2(),
            s3_magic: default_mirage_wg_s3(),
            s4_magic: default_mirage_wg_s4(),
            junk_count: default_mirage_wg_junk_count(),
            junk_min_size: default_mirage_wg_junk_min(),
            junk_max_size: default_mirage_wg_junk_max(),
            init_packet_magic_header: default_mirage_wg_h1(),
            response_packet_magic_header: default_mirage_wg_h2(),
            underload_packet_magic_header: default_mirage_wg_h3(),
            transport_packet_magic_header: default_mirage_wg_h4(),
            init_packet_junk_size: default_mirage_wg_init_junk(),
            response_packet_junk_size: default_mirage_wg_resp_junk(),
            fallback_dest: None,
            fallback_sni: None,
        }
    }
}

/// Tunnel pool configuration — controls pre-warmed tunnel count and reconnect behaviour.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelPoolConfig {
    /// Number of warm tunnels to maintain per chain. Default: 3.
    #[serde(default = "default_pool_size")]
    pub pool_size: usize,
    /// Seconds a tunnel may sit idle before being torn down and replaced. Default: 120.
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    /// Maximum reconnect attempts before giving up (0 = unlimited). Default: 5.
    #[serde(default = "default_max_reconnect_attempts")]
    pub max_reconnect_attempts: u32,
    /// Base delay for exponential backoff on reconnect (milliseconds). Default: 500.
    #[serde(default = "default_reconnect_base_ms")]
    pub reconnect_base_ms: u64,
}

fn default_pool_size() -> usize { 3 }
fn default_use_mux() -> bool { true }
fn default_mesh_id() -> String { "staging-v2".to_owned() }
fn default_idle_timeout_secs() -> u64 { 120 }
fn default_max_reconnect_attempts() -> u32 { 5 }
fn default_reconnect_base_ms() -> u64 { 500 }

impl Default for TunnelPoolConfig {
    fn default() -> Self {
        Self {
            pool_size: default_pool_size(),
            idle_timeout_secs: default_idle_timeout_secs(),
            max_reconnect_attempts: default_max_reconnect_attempts(),
            reconnect_base_ms: default_reconnect_base_ms(),
        }
    }
}

/// DNS-over-HTTPS forwarder configuration.
///
/// When enabled, a UDP listener on `listen_addr` receives raw DNS queries and
/// forwards them as DoH `application/dns-message` POST requests through the
/// local SOCKS5 proxy (which tunnels them through the Mirage chain).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Whether to run the local DoH forwarder. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// UDP address to listen on. Default: "127.0.0.1:5353".
    /// Use "0.0.0.0:53" inside Docker when the container is the only resolver.
    #[serde(default = "default_dns_listen_addr")]
    pub listen_addr: String,
    /// DoH endpoint URL. Requests are sent via the SOCKS5 tunnel.
    /// Default: "https://1.1.1.1/dns-query".
    #[serde(default = "default_doh_url")]
    pub doh_url: String,
    /// SOCKS5 proxy address used to forward DoH requests through the tunnel.
    /// Default: "socks5h://127.0.0.1:1080".
    #[serde(default = "default_socks_addr")]
    pub socks_addr: String,
    /// Cache TTL cap in seconds. Default: 60.
    #[serde(default = "default_dns_cache_ttl_secs")]
    pub cache_ttl_secs: u64,
}

fn default_dns_listen_addr() -> String { "127.0.0.1:5353".to_owned() }
fn default_doh_url() -> String { "https://1.1.1.1/dns-query".to_owned() }
fn default_socks_addr() -> String { "socks5h://127.0.0.1:1080".to_owned() }
fn default_dns_cache_ttl_secs() -> u64 { 60 }

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen_addr: default_dns_listen_addr(),
            doh_url: default_doh_url(),
            socks_addr: default_socks_addr(),
            cache_ttl_secs: default_dns_cache_ttl_secs(),
        }
    }
}

/// Session rekey configuration.
///
/// After `after_bytes` bytes sent or `after_secs` seconds elapsed, the client
/// initiates a key rotation (rekey).  Both sides derive new session keys via a
/// fresh ephemeral X25519 exchange chained onto the old key material, then
/// reset nonce counters to 0.  Disabled by default when this struct is absent
/// from the configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RekeyConfig {
    /// Whether periodic rekeying is enabled.  Default: `true`.
    #[serde(default = "default_rekey_enabled")]
    pub enabled: bool,
    /// Rotate keys after this many bytes have been sent.  Default: 67 108 864 (64 MiB).
    #[serde(default = "default_rekey_after_bytes")]
    pub after_bytes: u64,
    /// Rotate keys after this many seconds have elapsed.  Default: 3600 (1 hour).
    #[serde(default = "default_rekey_after_secs")]
    pub after_secs: u64,
}

fn default_rekey_enabled() -> bool { true }
fn default_rekey_after_bytes() -> u64 { 67_108_864 }
fn default_rekey_after_secs() -> u64 { 3600 }

impl Default for RekeyConfig {
    fn default() -> Self {
        Self {
            enabled: default_rekey_enabled(),
            after_bytes: default_rekey_after_bytes(),
            after_secs: default_rekey_after_secs(),
        }
    }
}

/// HTTP CONNECT proxy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpProxyConfig {
    /// Whether to enable the HTTP CONNECT proxy server. Default: false.
    #[serde(default)]
    pub enabled: bool,
    /// Listen address for the HTTP CONNECT proxy. Default: "127.0.0.1:1081".
    #[serde(default = "default_http_proxy_bind")]
    pub bind_addr: String,
}

fn default_http_proxy_bind() -> String {
    "127.0.0.1:1081".to_owned()
}

impl Default for HttpProxyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_addr: default_http_proxy_bind(),
        }
    }
}

/// Strategy for intercepting TCP/UDP flows from the TUN device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum InterceptStrategy {
    /// Linux: kernel-level `iptables REDIRECT` + `SO_ORIGINAL_DST`.
    #[default]
    KernelRedirect,
    /// Windows / macOS / mobile: userspace packet parsing + NAT table.
    UserspaceNat,
}

/// Configuration for the TUN virtual network interface stack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunConfig {
    /// Whether the TUN stack is enabled.  Default: `false`.
    #[serde(default)]
    pub enabled: bool,
    /// IP address and prefix length assigned to the TUN interface.  Default: `"10.0.85.1/24"`.
    #[serde(default = "default_tun_addr")]
    pub tun_addr: String,
    /// OS name of the TUN interface.  Default: `"tun0"`.
    #[serde(default = "default_tun_name")]
    pub tun_name: String,
    /// Maximum Transmission Unit in bytes.  Default: `1500`.
    #[serde(default = "default_mtu")]
    pub mtu: u16,
    /// Redirect DNS from TUN to the local DoH forwarder.  Default: `true`.
    #[serde(default = "default_dns_hijack")]
    pub dns_hijack: bool,
    /// TCP/UDP interception strategy.
    #[serde(default)]
    pub intercept: InterceptStrategy,
    /// SOCKS5 port that local TCP is redirected to.  Default: `1080`.
    #[serde(default = "default_socks_port")]
    pub socks_port: u16,
}

fn default_tun_addr() -> String { "10.0.85.1/24".to_owned() }
fn default_tun_name() -> String { "tun0".to_owned() }
fn default_mtu() -> u16 { 1500 }
fn default_dns_hijack() -> bool { true }
fn default_socks_port() -> u16 { 1080 }

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tun_addr: default_tun_addr(),
            tun_name: default_tun_name(),
            mtu: default_mtu(),
            dns_hijack: default_dns_hijack(),
            intercept: InterceptStrategy::default(),
            socks_port: default_socks_port(),
        }
    }
}

// ── Wave 2 config types ───────────────────────────────────────────────────────

fn default_health_probe_interval() -> u64 { 30 }
fn default_quarantine_after() -> u32 { 3 }
fn default_quarantine_recovery() -> u64 { 30 }

/// Serialisable counterpart of `PrewarmStrategy`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PrewarmStrategyConfig {
    #[default]
    All,
    TopN { n: usize },
    OnDemand { idle_keepalive_secs: u64 },
}

/// Wave 2 chain-set configuration — replaces the flat `chains: Vec<ChainConfig>` field.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainSetConfig {
    pub chains: Vec<ChainConfig>,
    #[serde(default)]
    pub prewarm: PrewarmStrategyConfig,
    #[serde(default = "default_health_probe_interval")]
    pub health_probe_interval_secs: u64,
    #[serde(default = "default_quarantine_after")]
    pub quarantine_after_failures: u32,
    #[serde(default = "default_quarantine_recovery")]
    pub quarantine_recovery_secs: u64,
}

/// Serialisable counterpart of `RoutingPolicy`.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RoutingPolicyConfig {
    #[default]
    RoundRobin,
    LatencyWeighted { window_ms: u64, min_samples: u32 },
    StickyPerFlow   { hash_seed: u64, ttl_secs: u64 },
    RegionAffinity  {
        target_geo: std::collections::HashMap<String, Vec<String>>,
        fallback: Box<RoutingPolicyConfig>,
    },
    BypassFirst     {
        bypass: BypassConfig,
        fallback: Box<RoutingPolicyConfig>,
    },
}

/// Bypass configuration — addresses that skip the VPN chain.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct BypassConfig {
    #[serde(default)]
    pub cidrs_v4: Vec<String>,
    #[serde(default)]
    pub cidrs_v6: Vec<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

/// Monitor transport stub — parsed but not yet active (Wave 2.3+).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MonitorTransportConfig {
    DirectWs {
        url:     String,
        sni:     Option<String>,
        api_key: String,
    },
    OverChain {
        chain_id:         String,
        monitor_endpoint: String,
        api_key:          String,
    },
}

/// One step of a ring-membership Merkle inclusion path. JSON shape matches the
/// `path[]` entries returned by operator-box `POST /credential/ring-enrol`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RingPathStep {
    /// 64-char hex of the sibling node hash at this tree level.
    pub sibling_hex: String,
    /// True when the sibling is the right child (this node is the left child).
    pub is_right: bool,
}

/// Full configuration for a client instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client_id: String,
    /// Mesh identifier — baked into the Blake3 confirm label for every
    /// handshake so cross-mesh dials are cryptographically rejected.
    /// All chains in this config share the same mesh (one client = one mesh).
    #[serde(default = "default_mesh_id")]
    pub mesh_id: String,
    pub chains: Vec<ChainConfig>,
    pub routing: RoutingConfig,
    /// Pre-shared key for ShadowTLS and Hysteria2 (hex-encoded, 32 bytes).
    pub psk: Option<String>,
    /// Tunnel pool settings. Uses defaults if omitted.
    #[serde(default)]
    pub pool: TunnelPoolConfig,
    /// DNS-over-HTTPS forwarder settings. Disabled by default.
    #[serde(default)]
    pub dns: DnsConfig,
    /// HTTP CONNECT proxy settings. Disabled by default.
    #[serde(default)]
    pub http_proxy: HttpProxyConfig,
    /// Enable Linux iptables kill switch.  When `true`, all outbound traffic
    /// except to the L1 relay is blocked while the client is running.
    /// Requires Linux with `iptables` installed (Docker containers).
    #[serde(default)]
    pub kill_switch: bool,
    /// Stream multiplexing over tunnel connections — MuxPool (N sessions ×
    /// many streams each) vs. TunnelPool (N individual tunnel connections).
    ///
    /// **Default `true` since May 2026.** MuxPool is the primary fast path:
    /// fewer relay slots, faster stream open, soft cross-pool failover when
    /// a session dies (cli/cli2 keep the plain TunnelPool warm in parallel
    /// as a fallback when MuxPool init fails or rejects an open). Set to
    /// `false` only as a legacy escape hatch — e.g. when the chain protocol
    /// can't carry mux frames.
    #[serde(default = "default_use_mux")]
    pub use_mux: bool,
    /// TUN virtual interface stack settings.  Disabled by default.
    #[serde(default)]
    pub tun: TunConfig,
    /// Address for the embedded management HTTP server.
    /// Defaults to `"127.0.0.1:4498"` when omitted.
    /// When `management_key` is `None` the management server does not start.
    #[serde(default)]
    pub management_addr: Option<String>,
    /// Pre-shared key for management API Bearer authentication.
    /// When `None` (or absent from JSON) the management server is disabled.
    #[serde(default)]
    pub management_key: Option<String>,
    /// Base URL of the mirage2monitor instance (e.g. `"http://127.0.0.1:17900"`).
    ///
    /// When present, the client spawns a background [`monitor_link`] task that
    /// periodically fetches chain config from the monitor and reacts to updates.
    /// When absent, the client runs with its static local config only.
    #[serde(default)]
    pub monitor_url: Option<String>,
    /// Base URL of the local TUN API (e.g. `"http://127.0.0.1:19500"`).
    ///
    /// When present and `monitor_url` is also set, a [`tun_bridge`] task
    /// automatically pushes every monitor config update to the TUN chain
    /// registry via `POST /chains/update`.  When absent the TUN API is not
    /// touched.
    #[serde(default)]
    pub tun_api_url: Option<String>,

    // ── Wave 2 additions ──────────────────────────────────────────────────────

    /// Wave 2: replaces the flat `chains: Vec<ChainConfig>` field.
    /// Old configs that carry only `chains: [...]` are migrated via
    /// `ClientConfig::effective_chain_set()`.
    #[serde(default)]
    pub chain_set: Option<ChainSetConfig>,

    /// Wave 2: replaces `routing: RoutingConfig`.
    /// Old `routing` field is kept for migration via `effective_routing_policy()`.
    #[serde(default)]
    pub routing_policy: Option<RoutingPolicyConfig>,

    /// Wave 2: explicit bypass config (separate from routing).
    #[serde(default)]
    pub bypass: BypassConfig,

    /// Per-monitor transport specs (over-chain / wire). Consumed by cli +
    /// cli2-supervisor when building `MonitorLink` (Wave 2.3 — live).
    #[serde(default)]
    pub monitor_transports: Vec<MonitorTransportConfig>,

    // ── Wave 3 additions ──────────────────────────────────────────────────────

    /// Wave 3: per-chain DNS isolation topology.
    ///
    /// When omitted by old clients or monitors that pre-date Wave 3, this field
    /// deserializes as `DnsTopology::default()` — all resolution falls back to
    /// the OS system resolver, preserving pre-Wave-3 behaviour.
    ///
    /// Operators who want leak isolation SHOULD populate `per_chain` entries
    /// pointing each chain's DNS traffic to its own DoH/DoT backend.
    #[serde(default)]
    pub dns_topology: crate::dns::DnsTopology,

    // ── Task #78: Wire MonitorLink (direct Mirage wire to monitor) ────────────

    /// IP:port of the monitor's Mirage wire listener, e.g. `"203.0.113.13:19444"`.
    ///
    /// When both `monitor_wire_addr` and `monitor_wire_pubkey_hex` are set, the
    /// cli/cli2 worker builds a [`MonitorTransport::Wire`] entry and passes it to
    /// `MonitorLink` as the preferred (first-attempted) transport. The Mirage wire
    /// handshake provides mutual authentication; no bearer token is required.
    /// Old configs that omit this field parse successfully (`serde(default)` → `None`).
    #[serde(default)]
    pub monitor_wire_addr: Option<String>,

    /// 64-character hex of the monitor's static X25519 public key.
    ///
    /// Obtain via `GET <monitor_url>/relay/me` → field `pubkey_hex`.
    /// Required when `monitor_wire_addr` is set.
    /// Old configs that omit this field parse successfully (`serde(default)` → `None`).
    #[serde(default)]
    pub monitor_wire_pubkey_hex: Option<String>,

    // ── Blind-token credential client wiring ──────────────────────────────────

    /// 64-char hex Ed25519 operator verifying key. When set, `CredentialParams`
    /// pushed by the monitor are signature-verified before use; when absent they
    /// are applied unverified (a one-time warn is logged). Mirrors
    /// `SentinelConfig.operator_pub_hex` for the standalone-cli path.
    #[serde(default)]
    pub operator_pub_hex: Option<String>,

    /// Enrolment token for blind-RSA batch credential requests. When set and the
    /// monitor pushes a `BlindRsaBatch` authority, the `MonitorLink` requests a
    /// token batch once the local pool runs low (<16). When absent, no batch is
    /// requested (pool stays empty, spending returns an error). Mirrors
    /// `SentinelConfig.enrol_token`.
    #[serde(default)]
    pub enrol_token: Option<String>,

    /// Ring-membership (scheme 0x04) member secret — 64-char hex of the member's
    /// ristretto scalar, from operator-box `POST /credential/ring-enrol`. When set
    /// and the monitor pushes a `RingMembership` authority, the client derives a
    /// 0x04 credential at dial time. Mirrors `enrol_token` for the blind path.
    #[serde(default)]
    pub ring_member_sk_hex: Option<String>,

    /// Ring-membership Merkle inclusion path (leaf→root), from `/credential/ring-enrol`.
    #[serde(default)]
    pub ring_path: Option<Vec<RingPathStep>>,

    /// Epoch id whose Merkle tree `ring_path` corresponds to. Embedded in the 0x04
    /// token; the node finds the matching published root by this id.
    #[serde(default)]
    pub ring_epoch_id: Option<u32>,

    /// Operator-signed credential params for the active epoch(s), injected by the
    /// sentinel from its MonitorLink so the cli2 worker can present a credential
    /// from config alone (no worker-side MonitorLink needed for first connect).
    /// `None` when the sentinel has not yet received a CredentialParams frame.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_params: Option<crate::crypto::credential::CredentialParams>,

    /// Path to a file of pre-minted SignedCapability (scheme 0x02) tokens:
    /// one hex line = one 100-byte token, single-use, blank lines and `#`
    /// comments ignored. The client cannot self-mint 0x02 (only the
    /// operator-box holds the Ed25519 seed), so tokens must be provisioned
    /// externally; each dial pops one line and rewrites the file with the
    /// remainder. When absent, no 0x02 credential can be presented.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capability_tokens_path: Option<String>,

    // ── cli2 supervisor orchestration (install-static) ────────────────────────

    /// Orchestration knobs consumed ONLY by the cli2 `mirage-chain-supervisor`
    /// when it loads this config as JSON. `None` for cli1 / direct-cli configs —
    /// cli1 and the worker never read this field. Lives in the sentinel's
    /// `client_template` so the materialised config carries it through with zero
    /// sentinel code change; the monitor never sets it (these are install-time
    /// deployment facts, not part of the wire spec the monitor materialises).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub supervisor: Option<SupervisorOpts>,
}

/// cli2 `mirage-chain-supervisor` install-static orchestration, embedded in a
/// [`ClientConfig`] under `supervisor`. Everything here is fixed at install time
/// (binary paths, OTA key, local listener binds) — distinct from the dynamic
/// wire/chain spec the monitor materialises into `chains[]`. Read only by
/// cli2-supervisor when it loads a JSON config; cli1 and the worker ignore it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorOpts {
    /// Path to the `mirage-chain-worker` binary the supervisor spawns per chain.
    pub worker_binary: String,
    /// Minisign public key (base64) for OTA manifest verification. A placeholder
    /// disables OTA in practice (no manifest verifies against it).
    #[serde(default)]
    pub ota_pubkey: String,
    /// Seconds between OTA manifest polls. Default 300.
    #[serde(default = "default_supervisor_ota_poll")]
    pub ota_poll_interval_secs: u64,
    /// Bearer token for the monitor (`/relay/clients`, MonitorLink). When absent,
    /// requests go unauthenticated (open-registration monitors only).
    #[serde(default)]
    pub monitor_api_key: Option<String>,
    /// Persist dir for `sentinel-id.txt` + `last-peer-table.json`. Default: the OS
    /// temp dir `/mirage-cli2-state`.
    #[serde(default)]
    pub state_dir: Option<String>,
    /// Seconds between config-file mtime reload checks. Default 5.
    #[serde(default = "default_supervisor_reload_poll")]
    pub reload_poll_secs: u64,
    /// Local control HTTP listener bind (`POST /chains/reload`, `GET /status`,
    /// `GET /admin/health`). Absent = no control listener.
    #[serde(default)]
    pub control_http_bind: Option<String>,
    /// chain_id designated as the MonitorLink host worker. Absent = the first
    /// entry in `chains[]` hosts MonitorLink.
    #[serde(default)]
    pub monitor_link_host_chain: Option<String>,
    /// Supervisor-level SOCKS5 router (one ingress → worker SOCKS5 ports). Absent
    /// = no router (TUN mode dials per-chain worker SOCKS5 ports directly).
    #[serde(default)]
    pub routing: Option<SupervisorRoutingOpts>,
}

/// Supervisor-level SOCKS5 router policy, embedded in [`SupervisorOpts`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorRoutingOpts {
    /// `"round_robin"` | `"latency_weighted"` | `"sticky"`. Default round-robin.
    #[serde(default = "default_supervisor_router_policy")]
    pub policy: String,
    /// Bind for the router's ingress SOCKS5 listener.
    #[serde(default = "default_supervisor_router_bind")]
    pub socks5_bind: String,
    /// Optional whitelist of chain_ids the router rotates through. Absent = all.
    #[serde(default)]
    pub chain_ids: Option<Vec<String>>,
    /// Box mode: the box-local channel the router listens on, named by its
    /// `LocalChannel` label (only `"edge-client-entrance"` today). Set = cli2
    /// runs as the edge-client Mirage unit — unix entrance, unix worker legs,
    /// no TCP port on the box — and `socks5_bind` is not read. Absent =
    /// workstation mode, unchanged.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_local_channel: Option<String>,
}

fn default_supervisor_ota_poll() -> u64 {
    300
}

fn default_supervisor_reload_poll() -> u64 {
    5
}

fn default_supervisor_router_policy() -> String {
    "round_robin".to_string()
}

fn default_supervisor_router_bind() -> String {
    "127.0.0.1:19489".to_string()
}

impl ClientConfig {
    /// Return the effective `ChainSetConfig`, preferring `chain_set` if set,
    /// falling back to the legacy `chains` list.
    ///
    /// # Panics
    ///
    /// Panics if neither `chain_set` nor `chains` contains any chains — this
    /// is a misconfiguration and should be caught at startup.
    pub fn effective_chain_set(&self) -> ChainSetConfig {
        if let Some(ref cs) = self.chain_set {
            return cs.clone();
        }
        ChainSetConfig {
            chains: self.chains.clone(),
            prewarm: PrewarmStrategyConfig::All,
            health_probe_interval_secs: default_health_probe_interval(),
            quarantine_after_failures: default_quarantine_after(),
            quarantine_recovery_secs: default_quarantine_recovery(),
        }
    }

    /// Return the effective `RoutingPolicyConfig`, preferring `routing_policy`
    /// if set, translating legacy `routing` CIDRs to `BypassFirst` otherwise.
    pub fn effective_routing_policy(&self) -> RoutingPolicyConfig {
        if let Some(ref rp) = self.routing_policy {
            return rp.clone();
        }
        // Translate legacy RoutingConfig direct_cidrs / direct_domains → BypassFirst.
        let has_bypass = !self.routing.direct_cidrs.is_empty()
            || !self.routing.direct_domains.is_empty();
        if has_bypass {
            RoutingPolicyConfig::BypassFirst {
                bypass: BypassConfig {
                    cidrs_v4: self.routing.direct_cidrs.clone(),
                    cidrs_v6: Vec::new(),
                    domains: self.routing.direct_domains.clone(),
                },
                fallback: Box::new(RoutingPolicyConfig::RoundRobin),
            }
        } else {
            RoutingPolicyConfig::RoundRobin
        }
    }
}

/// Traffic-shaping preset applied to an outbound chain tunnel.
///
/// Controls packet padding and inter-send jitter to make VPN traffic
/// resemble specific application traffic patterns.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ShapingPreset {
    /// No shaping — raw tunnel bytes are forwarded as-is.
    #[default]
    None,
    /// Mimic web browsing bursts with idle gaps.
    WebBrowsing,
    /// Mimic cloud API request/response pairs.
    CloudApi,
    /// Mimic continuous video streaming chunks.
    Streaming,
}

/// Camouflage mode applied to each frame on the wire.
///
/// The sender wraps the payload in the chosen envelope; the receiver
/// auto-detects the wrapper from the `cam_type` byte embedded in every frame
/// and unwraps it transparently.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CamouflageMode {
    /// No wrapping — raw bytes sent as-is (default).
    #[default]
    Raw,
    /// Wrap inside a fake JSON API response envelope.
    JsonApi,
    /// Wrap as a standard gRPC DATA frame (5-byte prefix).
    Grpc,
    /// Wrap as an HTTP/2 DATA frame (RFC 7540 §4.1).
    H2Data,
}

/// Cover-traffic configuration for idle tunnel periods.
///
/// When enabled, a background loop sends random-sized dummy frames at random
/// intervals whenever the tunnel has been idle for `idle_threshold_ms`.  The
/// receiving side recognises the [`crate::frame::CamouflageType::Dummy`] tag and
/// discards the frame without surfacing it to the application.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverTrafficConfig {
    /// Whether cover traffic is active.  Default: `false`.
    #[serde(default)]
    pub enabled: bool,
    /// Minimum interval between dummy frames (milliseconds).  Default: 500.
    #[serde(default = "default_cover_min_interval_ms")]
    pub min_interval_ms: u64,
    /// Maximum interval between dummy frames (milliseconds).  Default: 5000.
    #[serde(default = "default_cover_max_interval_ms")]
    pub max_interval_ms: u64,
    /// Minimum payload size of a dummy frame (bytes).  Default: 64.
    #[serde(default = "default_cover_min_size")]
    pub min_size: usize,
    /// Maximum payload size of a dummy frame (bytes).  Default: 1024.
    #[serde(default = "default_cover_max_size")]
    pub max_size: usize,
    /// Begin sending cover traffic after the tunnel has been idle for this many
    /// milliseconds.  Default: 2000.
    #[serde(default = "default_cover_idle_threshold_ms")]
    pub idle_threshold_ms: u64,
}

fn default_cover_min_interval_ms() -> u64 { 500 }
fn default_cover_max_interval_ms() -> u64 { 5000 }
fn default_cover_min_size() -> usize { 64 }
fn default_cover_max_size() -> usize { 1024 }
fn default_cover_idle_threshold_ms() -> u64 { 2000 }

impl Default for CoverTrafficConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            min_interval_ms: default_cover_min_interval_ms(),
            max_interval_ms: default_cover_max_interval_ms(),
            min_size: default_cover_min_size(),
            max_size: default_cover_max_size(),
            idle_threshold_ms: default_cover_idle_threshold_ms(),
        }
    }
}

/// Identifies one hop in an onion chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HopConfig {
    /// Address of this hop (host:port).
    pub addr: String,
    /// Hex-encoded 32-byte X25519 static public key.
    ///
    /// - `Some(hex)` — static override used as-is (operator escape hatch for
    ///   air-gapped tests or configs built before `node_id` was added).
    /// - `None` — runtime MUST resolve via `node_id` (preferred) or
    ///   `display_name` (fallback for backward compat) against the live
    ///   `PeerTable`. If neither yields a pubkey at dial time the chain fails
    ///   with `MaterializeError::PubkeyUnresolved`.
    #[serde(default)]
    pub public_key: Option<String>,
    /// Logical node identifier used to resolve the live pubkey from
    /// `peer_table[node_id]` at dial time.
    ///
    /// Preferred over `display_name` for lookups. When absent the runtime
    /// falls back to `display_name` for backward compat with chains built
    /// before this field was added.
    #[serde(default)]
    pub node_id: Option<String>,
    /// Optional SNI used if the hop uses TLS-based camouflage.
    #[serde(default)]
    pub sni: Option<String>,
    /// Role of this hop in the chain.
    pub role: HopRole,
    /// Human-friendly node name surfaced by the monitor (e.g. `l1-ru-1`).
    /// `None` for legacy configs — UI falls back to `addr`.
    #[serde(default)]
    pub display_name: Option<String>,
    /// Optional outer transport camouflage applied to the client→hop leg.
    ///
    /// The client wraps its outbound dial to `hop.addr` with the chosen
    /// camouflage (TLS / WebSocket / Xhttp / Reality / …) before writing
    /// the Mirage handshake. The hop's `ListenerSpec.ingress_layer.camouflage`
    /// must match for the strip pipeline to peel it. `None` → raw TCP.
    #[serde(default)]
    pub camouflage: Option<TransportCamouflage>,
    /// Optional byte-cipher applied to the client→hop byte stream.
    ///
    /// Sits between camouflage and the Mirage handshake. `None` → no peel.
    /// Must match the hop's `ListenerSpec.ingress_layer.byte_cipher`.
    #[serde(default)]
    pub byte_cipher: Option<ByteCipherMode>,

    /// Override pubkey used **only** for camouflage-layer server authentication
    /// (e.g. Reality ECDH).  When `Some`, `onion_tunnel_fs::connect` uses this
    /// key for `wrap_tcp_client` instead of `public_key`.
    ///
    /// Set by `establish_raw_tunnel` / `establish_mux_tunnel` when building a
    /// synthetic chain for transparent-relay 2-hop routing: the onion AEAD key
    /// (`public_key`) stays as the exit node's pubkey, while the camouflage
    /// server pubkey is the entry node's pubkey (since the TCP server handling
    /// the Reality/TLS handshake IS the entry node, not the exit).
    ///
    /// Not serialised — runtime-only field.
    #[serde(skip)]
    pub camo_server_pubkey: Option<String>,

    /// The selector token this hop's listener answers to, hex-encoded.
    ///
    /// Copied by the materializer out of the chain binding's own leg/exit,
    /// which the monitor filled when it minted the listener. The client puts
    /// it in the frame addressed to this hop; the hop resolves its listener by
    /// it. `None` means the monitor sent none, and both sides fall back to the
    /// derived `{chain_id}-h{position}` — 32 bits of `chain_id`, which is
    /// what this replaces.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector_token_hex: Option<String>,

    /// What this hop does to bytes that reach it — required field.
    ///
    /// Drives client-side dispatch: the onion path is taken iff ANY hop has
    /// `relay_mode = OnionPeel`. The multi-hop byte_cipher / transparent
    /// chains that used to take the `chain_protocols.connect` path instead no
    /// longer exist — those relay modes were removed on 2026-09-02.
    ///
    /// No `Option`, no shim — every chain spec must declare this explicitly.
    pub relay_mode: crate::mirage::wire::RelayMode,
}

/// Role of a hop in a multi-hop onion chain.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HopRole {
    /// First hop — receives from the client.
    Entry,
    /// Intermediate hop — peels one layer, forwards remainder.
    Middle,
    /// Last hop — exit node, decrypts innermost layer and emits traffic.
    Exit,
}

/// Handshake strategy for multi-hop onion establishment.
///
/// `Ephemeral` — the non-forward-secret strategy that sealed every layer up
/// front from each hop's long-lived static key, and carried the full route
/// (`chain_node_ids`) in a cleartext header every relay forwarded verbatim —
/// was deleted 2026-09-02 along with the wire frames and builder that
/// implemented it. `Telescopic` is the only strategy left, so it is also the
/// only sensible default: a chain that doesn't say which handshake it wants
/// gets the one path that still exists, not a dial into deleted code.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HandshakeStrategy {
    /// Tor-style telescopic handshake: client establishes a session with hop 1,
    /// then through hop 1 extends to hop 2, etc. Forward-secret (FS) wire frames.
    /// This is the only onion-handshake path; nodes accept only FS onion frames.
    Telescopic,
}

impl Default for HandshakeStrategy {
    fn default() -> Self {
        HandshakeStrategy::Telescopic
    }
}

/// How replies flow back to the client in a multi-hop chain.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ReplyMode {
    /// Replies travel back raw through the same sockets — hops only maintain
    /// (prev_peer, next_peer) mapping and copy bytes bidirectionally.
    Raw,
    /// Replies are onion-wrapped on the reverse path — every hop adds its
    /// layer, client strips all N layers.
    Onion,
}

impl Default for ReplyMode {
    fn default() -> Self {
        ReplyMode::Raw
    }
}

fn default_handshake_strategy() -> HandshakeStrategy { HandshakeStrategy::Telescopic }
fn default_reply_mode() -> ReplyMode { ReplyMode::Raw }
fn default_onion_reply_mode() -> ReplyMode { ReplyMode::Onion }

/// Structural nature of a wire: what shape of transport/anonymity guarantee
/// it provides. Orthogonal to `KillSwitchMode` (Strict/General answers "how
/// strictly is a flow pinned"; `WireNature` answers "what does this wire
/// structurally look like on the network"). It CONSTRAINS `group`: Phase-1
/// validation requires every member of a `General` failover group to share
/// the same nature, so `group` remains the operator-facing "these are
/// interchangeable" label while `nature` is the machine-checked guardrail
/// that keeps that label honest.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum WireNature {
    /// Single-hop native Mirage wire (`hops.len() == 1`, no foreign-wire
    /// camouflage config populated). Lowest latency; the single exit node
    /// directly observes src+dst. Failing over between two Direct chains
    /// preserves "exactly one Mirage node sees this flow."
    #[default]
    Direct,
    /// Multi-hop onion wire (`hops.len() > 1`, telescopic handshake,
    /// per-hop AEAD peel — see mirage2web/CLAUDE.md "Wire V5"). Anonymity
    /// via relay diffusion: no single hop sees both src+dst. Failing over
    /// between two Mixnet chains preserves that diffusion guarantee.
    Mixnet,
}

impl WireNature {
    /// Structural classification from axes that already exist on
    /// `ChainConfig` — not a new heuristic, so it can't drift from what the
    /// chain actually does on the wire.
    pub fn infer(chain: &ChainConfig) -> Self {
        if chain.hops.len() > 1 {
            WireNature::Mixnet
        } else {
            WireNature::Direct
        }
    }
}

/// Per-wire kill-switch mode for a chain.
///
/// Maps to [`mirage_tun_core::policy::FailurePolicy`] at the TUN/SOCKS5
/// materialization layer:
/// - `Strict` → `FailurePolicy::FailClosed` (flow pinned to this exact wire; fail-closed on wire-down)
/// - `General` → `FailurePolicy::Failover { group }` (any healthy wire in the same group; fail-closed if none)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillSwitchMode {
    /// Flow is pinned to this exact chain. On wire-down: RST, no substitution.
    Strict,
    /// Flow may failover to any healthy chain in the same group.
    /// Falls back to fail-closed when no healthy member of the group is available.
    General,
}

/// A multi-hop chain. `hops` must be non-empty (validated at runtime).
///
/// Outer camouflage and byte_cipher live per-leg on `HopConfig.camouflage`
/// and `HopConfig.byte_cipher`. The legacy `l1`/`l2`/`l1_transparent` fields
/// and per-protocol config blocks have been removed; downstream consumers must
/// use `hops[]` + `HopConfig` axes instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub chain_id: String,

    /// Ordered list of hops — entry first, exit last. Must be non-empty.
    #[serde(default)]
    pub hops: Vec<HopConfig>,
    /// Handshake strategy for onion establishment.
    #[serde(default = "default_handshake_strategy")]
    pub handshake: HandshakeStrategy,
    /// How replies flow back to the client.
    #[serde(default = "default_reply_mode")]
    pub reply: ReplyMode,

    pub protocol: ProtocolId,
    /// Higher priority chains are preferred (0 = lowest).
    pub priority: u8,
    /// Optional traffic-shaping preset.  Omit or set to `"none"` to disable.
    #[serde(default)]
    pub shaping: ShapingPreset,
    /// Inner CamouflageMode — per-frame wrapping inside the tunnel (padding /
    /// JSON envelope / gRPC / H2Data). Distinct from `HopConfig.camouflage`
    /// which is the outer transport-level wrap.
    #[serde(default)]
    pub camouflage: CamouflageMode,
    /// Cover-traffic settings.  Disabled by default.
    #[serde(default)]
    pub cover_traffic: CoverTrafficConfig,
    /// Optional dedicated SOCKS5 bind address for this chain.
    ///
    /// When set (e.g. `"127.0.0.1:10401"`), a separate SOCKS5 listener is
    /// spawned that routes traffic exclusively through this chain's tunnel
    /// pool.  When `None`, the chain participates only in the default pool
    /// selection and cross-chain failover.
    #[serde(default)]
    pub socks5_bind: Option<String>,

    /// AEAD suite the client offers in the V5 onion envelope. Server picks
    /// the highest-priority match from its own preference list and confirms
    /// in the CreatedV5 ack. Defaults to ChaCha20-Poly1305 — universally
    /// supported, best perf on CPUs without AES-NI.
    #[serde(default = "default_chain_aead_suite")]
    pub aead_suite: crate::crypto::AeadSuite,

    /// Per-wire kill-switch mode.
    ///
    /// `None` = no kill-switch for this chain (default; existing behavior preserved).
    /// `Some(Strict)` = flow pinned to this exact wire, fail-closed on wire-down.
    /// `Some(General)` = flow may failover to any healthy chain in the same group.
    ///
    /// Mapped to [`mirage_tun_core::policy::FailurePolicy`] at the TUN/SOCKS5
    /// materialization layer. No enforcement in this crate — additive schema only.
    #[serde(default)]
    pub kill_switch: Option<KillSwitchMode>,

    /// Failover group name for `General` kill-switch mode.
    ///
    /// Chains sharing the same group name are interchangeable under
    /// `KillSwitchMode::General`. Ignored when `kill_switch` is `None` or `Strict`.
    #[serde(default)]
    pub group: Option<String>,

    /// Explicit operator-declared wire nature. `None` = infer structurally
    /// via `WireNature::infer` (the common case; matches pre-existing
    /// configs written before this field existed). `Some(_)` is
    /// cross-checked against the structural inference in `validate()` —
    /// disagreement is a hard config error, not a silent override, so a
    /// misclassified chain can never slip into a same-nature-gated group.
    #[serde(default)]
    pub nature: Option<WireNature>,
}

fn default_chain_aead_suite() -> crate::crypto::AeadSuite {
    crate::crypto::AeadSuite::ChaCha20Poly1305
}

/// Structural errors caught by [`ChainConfig::validate`] before the chain is
/// dialed. Each variant pinpoints a specific contract the chain breaks — much
/// faster than surfacing the same mistake as a 20-second handshake timeout
/// or an AEAD failure on the first frame.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ChainValidationError {
    #[error("chain '{chain_id}': hops list is empty")]
    EmptyHops { chain_id: String },

    #[error(
        "chain '{chain_id}': hop[{index}] has no public_key AND no node_id — \
         runtime has nothing to resolve against peer_table"
    )]
    UnresolvableHop { chain_id: String, index: usize },

    #[error(
        "chain '{chain_id}': hop[0] role={role:?}, must be Entry"
    )]
    FirstHopNotEntry { chain_id: String, role: HopRole },

    #[error(
        "chain '{chain_id}': hop[{index}] role={role:?}, last hop must be Exit"
    )]
    LastHopNotExit { chain_id: String, role: HopRole, index: usize },

    #[error(
        "chain '{chain_id}': hop[{index}] role={role:?}, middle hops must be Middle"
    )]
    MiddleRoleMismatch { chain_id: String, role: HopRole, index: usize },

    #[error(
        "chain '{chain_id}': hop[{index}].addr '{addr}' has no port (expected host:port)"
    )]
    HopAddrNoPort { chain_id: String, index: usize, addr: String },

    #[error(
        "chain '{chain_id}': declared nature {declared:?} does not match \
         structural nature {inferred:?} inferred from hops/foreign-wire config"
    )]
    NatureMismatch {
        chain_id: String,
        declared: WireNature,
        inferred: WireNature,
    },

    #[error(
        "failover group '{group}': chain '{chain_a}' (nature {nature_a:?}) and \
         chain '{chain_b}' (nature {nature_b:?}) have different natures — \
         same-nature failover invariant would be silently broken"
    )]
    MixedNatureGroup {
        group: String,
        chain_a: String,
        nature_a: WireNature,
        chain_b: String,
        nature_b: WireNature,
    },
}

impl ChainConfig {
    /// Structural validation called by client builders before any TCP/UDP
    /// dial. Catches the entire class of mistakes that Phase 9-11 showed
    /// surface only as silent handshake hangs or AEAD failures.
    ///
    /// Validates (in order):
    /// 1. `hops` is non-empty.
    /// 2. Single-hop chain → role must be `Exit`.
    /// 3. Multi-hop chain → `hops[0].role == Entry`, `hops[last].role == Exit`,
    ///    every middle hop has `role == Middle`.
    /// 4. Every hop has at least one of `public_key` or `node_id` set
    ///    (otherwise runtime cannot resolve a pubkey from peer_table).
    /// 5. Every hop's `addr` contains a port.
    ///
    /// Does NOT validate live peer_table membership — that is by definition
    /// a runtime concern handled in `freshen_chain_pubkeys`.
    pub fn validate(&self) -> std::result::Result<(), ChainValidationError> {
        if self.hops.is_empty() {
            return Err(ChainValidationError::EmptyHops {
                chain_id: self.chain_id.clone(),
            });
        }

        let last = self.hops.len() - 1;

        // Single-hop: must be Exit.
        if self.hops.len() == 1 {
            if self.hops[0].role != HopRole::Exit {
                return Err(ChainValidationError::LastHopNotExit {
                    chain_id: self.chain_id.clone(),
                    role: self.hops[0].role,
                    index: 0,
                });
            }
        } else {
            // Multi-hop: entry / middle*N / exit.
            if self.hops[0].role != HopRole::Entry {
                return Err(ChainValidationError::FirstHopNotEntry {
                    chain_id: self.chain_id.clone(),
                    role: self.hops[0].role,
                });
            }
            if self.hops[last].role != HopRole::Exit {
                return Err(ChainValidationError::LastHopNotExit {
                    chain_id: self.chain_id.clone(),
                    role: self.hops[last].role,
                    index: last,
                });
            }
            for (i, hop) in self.hops[1..last].iter().enumerate() {
                if hop.role != HopRole::Middle {
                    return Err(ChainValidationError::MiddleRoleMismatch {
                        chain_id: self.chain_id.clone(),
                        role: hop.role,
                        index: i + 1,
                    });
                }
            }
        }

        // Per-hop sanity.
        // Wire V5 era: node_id is REQUIRED for every hop (it is embedded in
        // the V5EnvelopeHeader so the transcript binds identity by-value).
        // public_key alone is insufficient — without node_id the server cannot
        // find the peer in its peer_table and the transcript would be anonymous.
        for (i, hop) in self.hops.iter().enumerate() {
            if hop.node_id.is_none() {
                return Err(ChainValidationError::UnresolvableHop {
                    chain_id: self.chain_id.clone(),
                    index: i,
                });
            }
            if !hop.addr.contains(':') {
                return Err(ChainValidationError::HopAddrNoPort {
                    chain_id: self.chain_id.clone(),
                    index: i,
                    addr: hop.addr.clone(),
                });
            }
        }

        // Declared nature must match structural inference. Only fires when
        // the operator explicitly set `nature` — `None` stays backward
        // compatible with every config written before this field existed.
        if let Some(declared) = self.nature {
            let inferred = WireNature::infer(self);
            if declared != inferred {
                return Err(ChainValidationError::NatureMismatch {
                    chain_id: self.chain_id.clone(),
                    declared,
                    inferred,
                });
            }
        }

        Ok(())
    }

    /// The nature to use everywhere at runtime: declared if present,
    /// otherwise the structural inference. Callers (gate logic, router
    /// wiring, tun_config materialization) always call this, never read
    /// `.nature` directly.
    pub fn effective_nature(&self) -> WireNature {
        self.nature.unwrap_or_else(|| WireNature::infer(self))
    }

    /// Every `KillSwitchMode::General` group's members must share
    /// `effective_nature()`. Runs once over the full chain list at
    /// config-load time — NOT per-dial (that's `validate()`'s job).
    pub fn validate_group_natures(chains: &[ChainConfig]) -> std::result::Result<(), ChainValidationError> {
        let mut seen: HashMap<&str, (&str, WireNature)> = HashMap::new();
        for c in chains {
            let Some(KillSwitchMode::General) = c.kill_switch else {
                continue;
            };
            let group = c.group.as_deref().unwrap_or(c.chain_id.as_str());
            let nature = c.effective_nature();
            match seen.get(group) {
                None => {
                    seen.insert(group, (c.chain_id.as_str(), nature));
                }
                Some((first_id, first_nature)) if *first_nature != nature => {
                    return Err(ChainValidationError::MixedNatureGroup {
                        group: group.to_owned(),
                        chain_a: (*first_id).to_owned(),
                        nature_a: *first_nature,
                        chain_b: c.chain_id.clone(),
                        nature_b: nature,
                    });
                }
                _ => {}
            }
        }
        Ok(())
    }
}

/// Split-routing rules for the client.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RoutingConfig {
    /// CIDR strings whose destination IPs travel direct (e.g. Russian address space).
    #[serde(default)]
    pub direct_cidrs: Vec<String>,
    /// Domain suffixes (or exact names) that must go through a chain.
    #[serde(default)]
    pub blocked_domains: Vec<String>,
    /// Domain suffixes (or exact names) that bypass the VPN and connect directly.
    /// Example: `"google.com"` matches `"google.com"` and `"www.google.com"`.
    #[serde(default)]
    pub direct_domains: Vec<String>,
}

// ── MirageExit config ─────────────────────────────────────────────────────────

fn default_mirage_exit_bind_addr() -> String { "0.0.0.0:4443".to_owned() }

/// MirageExit thin L2-exit protocol configuration.
///
/// All three variants (Minimal / Full / Hmac) share this config struct.
/// The `variant` field is informational only — the actual protocol behaviour is
/// determined by which `ProtocolId` is listed in `protocols`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirageExitConfig {
    /// UDP address for the MirageExit UDP listener.  Default: `"0.0.0.0:4443"`.
    #[serde(default = "default_mirage_exit_bind_addr")]
    pub bind_addr: String,
}

impl Default for MirageExitConfig {
    fn default() -> Self {
        Self { bind_addr: default_mirage_exit_bind_addr() }
    }
}

// ── Mirage WebSocket (path / host) config ────────────────────────────────────

fn default_mirage_ws_path() -> String { "/ws".to_owned() }
fn default_mirage_ws_host() -> String { "localhost".to_owned() }
fn default_mirage_xhttp_path() -> String { "/xhttp".to_owned() }
fn default_mirage_xhttp_host() -> String { "www.example.com".to_owned() }

/// Mirage-WebSocket camouflage configuration.
///
/// Used by the `MirageWebsocket` TCP protocol to set the HTTP `Upgrade` request
/// path and `Host` header.  When this section is absent from `NodeConfig`
/// the legacy hard-coded defaults `/ws` and `localhost` are used (backward
/// compatible with deployed configs).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirageWebsocketConfig {
    #[serde(default = "default_mirage_ws_path")]
    pub path: String,
    #[serde(default = "default_mirage_ws_host")]
    pub host: String,
}

impl Default for MirageWebsocketConfig {
    fn default() -> Self {
        Self {
            path: default_mirage_ws_path(),
            host: default_mirage_ws_host(),
        }
    }
}

/// Mirage-Xhttp camouflage configuration.
///
/// Used by the `Xhttp` TCP protocol for the HTTP/1.1 `Upgrade: xhttp/1`
/// envelope.  When the section is absent from `NodeConfig` the defaults
/// `/xhttp` and `www.example.com` are used.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MirageXhttpConfig {
    #[serde(default = "default_mirage_xhttp_path")]
    pub path: String,
    #[serde(default = "default_mirage_xhttp_host")]
    pub host: String,
}

impl Default for MirageXhttpConfig {
    fn default() -> Self {
        Self {
            path: default_mirage_xhttp_path(),
            host: default_mirage_xhttp_host(),
        }
    }
}

// ── Per-chain UDP camouflage secrets ──────────────────────────────────────────
//
// Per-protocol secret bundles operators want to rotate on UDP chains. Lives
// on both `NodeConfig` (under listener-aggregator keys) and `ChainConfig`
// (read by the client when establishing the chain). Client and server MUST
// hold matching values.
//
// All fields are `Option<...>`; absent → fall back to the same hardcoded
// dev defaults that were inline in `establish_udp_chain_tunnel` /
// `build_udp_aggregator_node_config` before this block existed (so older
// configs keep working).

fn default_udp_quic_alpn() -> Vec<String> { vec!["h3".to_owned()] }
fn default_udp_hysteria2_psk_hex() -> String { "0".repeat(64) } // 32 zero bytes
fn default_udp_wg_magic_byte() -> u8 { 0x04 }
fn default_udp_wg_junk_count() -> u8 { 1 }
fn default_udp_wg_junk_min() -> u16 { 16 }
fn default_udp_wg_junk_max() -> u16 { 64 }

/// Per-chain (and per-listener) config for `MirageQuic` / `QuicXray` UDP wire.
///
/// `alpn` defaults to `["h3"]` to mimic Chrome HTTP/3.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpQuicConfig {
    #[serde(default = "default_udp_quic_alpn")]
    pub alpn: Vec<String>,
}

impl Default for UdpQuicConfig {
    fn default() -> Self { Self { alpn: default_udp_quic_alpn() } }
}

/// Per-chain config for `MirageHysteria2` (Salamander-obfuscated UDP).
///
/// `psk_hex` is the 64-hex-char (32-byte) shared key. Client and server MUST
/// match exactly.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpHysteria2Config {
    #[serde(default = "default_udp_hysteria2_psk_hex")]
    pub psk_hex: String,
}

impl Default for UdpHysteria2Config {
    fn default() -> Self { Self { psk_hex: default_udp_hysteria2_psk_hex() } }
}

/// Per-chain config for `MirageWg` (WireGuard/AmneziaWG-style UDP camouflage).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpWgConfig {
    #[serde(default = "default_udp_wg_magic_byte")]
    pub magic_byte: u8,
    #[serde(default = "default_udp_wg_junk_count")]
    pub junk_count: u8,
    #[serde(default = "default_udp_wg_junk_min")]
    pub junk_min: u16,
    #[serde(default = "default_udp_wg_junk_max")]
    pub junk_max: u16,
}

impl Default for UdpWgConfig {
    fn default() -> Self {
        Self {
            magic_byte: default_udp_wg_magic_byte(),
            junk_count: default_udp_wg_junk_count(),
            junk_min: default_udp_wg_junk_min(),
            junk_max: default_udp_wg_junk_max(),
        }
    }
}

// ObfuscationAlgorithm / ByteCipherMode moved to crate::mirage::wire::relay_mode.
// Wire format identical (snake_case enum + hex-encoded byte arrays).
pub use crate::mirage::wire::{ByteCipherMode, ObfuscationAlgorithm};

/// Peek-multiplex configuration: on accept, peek the first bytes and route
/// either to the tunnel or to a decoy service based on a magic match.
///
/// This lets L1 expose a single port that looks like a regular HTTPS / any-TLS
/// endpoint to probing parties but serves tunnel traffic to authenticated
/// clients.
///
/// ### Client wiring
/// The client does **not** need a separate config field.  Configure
/// [`ByteCipherMode::ValidateFirst`] on the chain with the same value as
/// `tunnel_magic` — the wrapper prepends those bytes so the decoy listener
/// routes the connection to the tunnel path automatically.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyConfig {
    /// Listen port — the single port exposed externally.
    ///
    /// Use custom ports like `17443`, `18443` etc. to avoid the
    /// standard-port correlation signal that DPI systems use.  This port is
    /// **separate** from `NodeConfig.listen_addr` — both listeners run
    /// concurrently.
    pub peek_port: u16,

    /// Magic bytes expected at the start of a tunnel connection.
    ///
    /// If the first `magic.len()` bytes of the stream match, the connection
    /// is a tunnel client and is routed to the tunnel handler.  16 bytes is a
    /// reasonable compromise: enough to avoid random collisions, small enough
    /// to peek in one syscall.
    #[serde(with = "hex_bytes")]
    pub tunnel_magic: Vec<u8>,

    /// Address of the real decoy service (e.g. `"127.0.0.1:18443"` where
    /// nginx is serving a real Grafana / Bitwarden / etc.).
    ///
    /// Non-matching traffic is forwarded here verbatim (`copy_bidirectional`),
    /// so the decoy service sees the peer's original TLS ClientHello and
    /// responds normally.
    pub decoy_forward_addr: String,

    /// Connect timeout for the decoy forward in milliseconds.  Default: 5000.
    #[serde(default = "default_decoy_timeout_ms")]
    pub decoy_forward_timeout_ms: u64,

    /// Maximum bytes to peek while waiting for magic.  Default: 16.
    ///
    /// Larger values give more reliable magic detection but add latency if
    /// the client is slow to send the first bytes.
    #[serde(default = "default_decoy_peek_bytes")]
    pub peek_bytes: usize,
}

fn default_decoy_timeout_ms() -> u64 { 5000 }
fn default_decoy_peek_bytes() -> usize { 16 }

// ── Multi-backend decoy ───────────────────────────────────────────────────────

/// Top-level configuration for the multi-backend decoy system.
///
/// Configures zero or more independent TCP listeners, each with its own ordered
/// rule table. Detection is pure peek — bytes are never consumed before routing.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MultiDecoyConfig {
    /// One entry per bound port.
    pub ports: Vec<DecoyPortConfig>,
    /// Global rate-limit: maximum concurrent peek-in-flight connections per IP.
    /// Connections beyond this threshold are dropped immediately (no bytes sent).
    #[serde(default = "default_rate_limit_per_ip")]
    pub rate_limit_per_ip: u32,
    /// Peek timeout across all ports, in milliseconds. Default: 3000.
    #[serde(default = "default_peek_timeout_ms")]
    pub peek_timeout_ms: u64,
}

fn default_rate_limit_per_ip() -> u32 { 32 }
fn default_peek_timeout_ms() -> u64 { 3000 }

/// One bound port with its ordered rule list.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyPortConfig {
    /// e.g. `"0.0.0.0:443"`
    pub bind: String,
    /// Rules evaluated in order; first match wins.
    pub rules: Vec<DecoyRule>,
    /// Action taken when no rule matches.
    pub default_action: DecoyAction,
}

/// A single rule: a matcher paired with an action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecoyRule {
    #[serde(rename = "match")]
    pub matcher: DecoyMatcher,
    #[serde(flatten)]
    pub action: DecoyAction,
}

/// All supported matcher variants.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum DecoyMatcher {
    /// First N bytes of the stream equal the given hex-encoded pattern.
    MagicBytes { magic: String },
    /// Peek TLS ClientHello, extract SNI. Supports wildcard prefix `"*.foo.com"`.
    TlsSni { sni: String },
    /// Peek HTTP/1.x request, match the `Host:` header value.
    HttpHost { host: String },
    /// Stream starts with the literal ASCII prefix `"SSH-2.0"`.
    SshBanner,
    /// Always matches — use as the last rule.
    Any,
}

/// What to do after a rule fires.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum DecoyAction {
    /// Transparent TCP proxy to the given backend address.
    Forward { backend: String },
    /// Hand the stream to the mirage tunnel dispatcher with an optional protocol tag.
    Tunnel {
        #[serde(default)]
        protocol: Option<String>,
    },
    /// Drop the connection immediately — no bytes sent.
    Reject,
    /// Write the given hex-encoded bytes to the client then close.
    StaticResponse { payload: String },
}

// Hex serde helpers for fixed-length byte arrays live in crate::hex_fixed now.

/// Serde module for `Vec<u8>` as a lowercase hex string.
///
/// Used by [`DecoyConfig::tunnel_magic`] so the JSON config is human-readable.
pub mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Vec<u8>, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&super::encode_hex(v))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        super::decode_hex_bytes(&s).map_err(serde::de::Error::custom)
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().fold(String::with_capacity(bytes.len() * 2), |mut acc, &b| {
        acc.push_str(&format!("{b:02x}"));
        acc
    })
}

fn decode_hex_bytes(s: &str) -> Result<Vec<u8>, String> {
    if !s.len().is_multiple_of(2) {
        return Err(format!("odd hex string length: {}", s.len()));
    }
    s.as_bytes()
        .chunks(2)
        .map(|pair| {
            let hi = hex_nibble_cfg(pair[0])?;
            let lo = hex_nibble_cfg(pair[1])?;
            Ok((hi << 4) | lo)
        })
        .collect()
}

fn hex_nibble_cfg(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex character: '{}'", b as char)),
    }
}

// ── Unified protocol config (new API — replaces Vec<ProtocolId> + per-proto fields) ──────

// TransportKind / AuthMode moved to crate::mirage::wire::{transport, auth}.
pub use crate::mirage::wire::{AuthMode, TransportKind};

// TransportCamouflage moved to crate::mirage::wire::camouflage — canonical source of truth.
// Wire format preserved (tag="type", snake_case).
pub use crate::mirage::wire::TransportCamouflage;
pub use crate::mirage::wire::{MirageCamouflage, Protocol};

/// Optional byte cipher kinds.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ByteCipherKind {
    /// Placeholder — kept for serde JSON backward compat. New code should
    /// use [`MirageEndpointConfig::byte_cipher_mode`] (`Option<ByteCipherMode>`)
    /// instead; this enum carries no parameters and selects only the
    /// historical `Mirage` byte-cipher family.
    Mirage,
}

/// Top-level configuration for a single Mirage protocol endpoint.
///
/// Replaces the legacy `Vec<ProtocolId>` + per-protocol config fields with a
/// single composable configuration.
///
/// # JSON example
/// ```json
/// {
///   "transport": "tcp",
///   "auth": { "type": "blake3" },
///   "camouflage": { "type": "reality", "short_id": "...", "server_name": "..." }
/// }
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MirageEndpointConfig {
    pub transport: TransportKind,
    pub auth: AuthMode,
    pub camouflage: TransportCamouflage,
    /// Legacy stub — kept for backward-compat with old JSON configs that
    /// emitted `"byte_cipher": "Mirage"`. New configs should use
    /// `byte_cipher_mode` instead. Unused at runtime.
    #[serde(default)]
    pub byte_cipher: Option<ByteCipherKind>,
    /// Wire-level byte-cipher applied OUTSIDE the inner Mirage/canonical
    /// wire. Client wraps outbound bytes (datagram for UDP, stream for TCP)
    /// with `ByteCipher::wrap`; the matching L1 relay (`udp_crypto_verify`
    /// on UDP, `crypto_verify` on TCP) peels `ByteCipher::unwrap` and
    /// forwards the remainder to L2. None → no wrap.
    ///
    /// Currently honored by:
    /// - Client side: `RawUdp` UDP camouflage (wrap on `poll_write`).
    /// - Server side: L1 `udp_crypto_verify` listener
    ///   (`UdpRelayBinding.byte_cipher`).
    ///
    /// Other UDP camouflages (Quic / Hysteria2 / WireGuard / etc.) have
    /// their own framing — byte_cipher_mode at this layer would corrupt
    /// the wire and is ignored.
    #[serde(default)]
    pub byte_cipher_mode: Option<ByteCipherMode>,
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Serde roundtrip for the two surviving wire-id variants.
    #[test]
    fn protocol_id_flat_serde_roundtrip() {
        // TCP — single variant
        let tcp_json = "\"Mirage\"";
        let tcp_id: ProtocolId = serde_json::from_str(tcp_json).expect("deserialize tcp");
        assert_eq!(tcp_id, ProtocolId::Tcp(TcpProtocolId::Mirage));
        assert_eq!(serde_json::to_string(&tcp_id).unwrap(), tcp_json);

        // UDP — single variant
        let udp_json = "\"MirageUdp\"";
        let udp_id: ProtocolId = serde_json::from_str(udp_json).expect("deserialize udp");
        assert_eq!(udp_id, ProtocolId::Udp(UdpProtocolId::MirageUdp));
        assert_eq!(serde_json::to_string(&udp_id).unwrap(), udp_json);
    }

    /// `TcpProtocolId` and `UdpProtocolId` have no overlapping variant names —
    /// deserialisation must not silently pick the wrong transport.
    #[test]
    fn protocol_id_transport_classification() {
        let mirage = ProtocolId::Tcp(TcpProtocolId::Mirage);
        assert!(mirage.is_tcp());
        assert!(!mirage.is_udp());

        let udp = ProtocolId::Udp(UdpProtocolId::MirageUdp);
        assert!(udp.is_udp());
        assert!(!udp.is_tcp());
    }

    /// A `node.toml` written against the old taxonomy must fail at boot with a
    /// reason, not with `unknown variant` and not by silently becoming
    /// something the operator did not write.
    ///
    /// Input is built by serialising a REAL value and mutating the string,
    /// never from a hand-written literal — a literal encodes the author's
    /// belief about the format, a serialised-then-mutated value encodes the
    /// format.
    #[test]
    fn a_retired_relay_mode_in_node_config_is_refused_by_name() {
        let live = serde_json::to_string(&RelayMode::OnionPeel).expect("serialises");
        assert_eq!(live, "\"onion_peel\"");

        for retired in ["transparent_tcp", "crypto_verify"] {
            let old = live.replace("onion_peel", retired);
            let err = serde_json::from_str::<RelayMode>(&old)
                .expect_err("a retired relay mode must not deserialize")
                .to_string();
            assert!(
                err.contains(retired),
                "the refusal must name the mode the config asked for; got: {err}"
            );
            assert!(
                err.contains("onion_peel"),
                "the refusal must name the replacement; got: {err}"
            );
            assert!(
                err.contains("byte_cipher"),
                "the refusal must say the byte_cipher axis survived — it is the first thing a \
                 crypto_verify config will assume it lost; got: {err}"
            );
        }
    }

    /// The surviving variant still round-trips, and it is the only one.
    #[test]
    fn onion_peel_is_the_only_node_config_relay_mode() {
        let json = serde_json::to_string(&RelayMode::OnionPeel).expect("serialises");
        let back: RelayMode = serde_json::from_str(&json).expect("round-trips");
        assert_eq!(back, RelayMode::OnionPeel);
        assert_eq!(RelayMode::default(), RelayMode::OnionPeel);
    }

    /// HopConfig has both `camouflage` and `byte_cipher` fields.
    #[test]
    fn hop_config_has_per_leg_axes() {
        let hop = HopConfig {
            addr: "1.2.3.4:4700".to_owned(),
            public_key: Some("a".repeat(64)),
            node_id: None,
            sni: None,
            role: HopRole::Entry,
            display_name: None,
            camouflage: Some(TransportCamouflage::None),
            byte_cipher: Some(ByteCipherMode::Raw),
            relay_mode: crate::mirage::wire::RelayMode::OnionPeel,
            camo_server_pubkey: None,
            selector_token_hex: None,
        };
        let json = serde_json::to_string(&hop).unwrap();
        let rt: HopConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(rt.camouflage, hop.camouflage);
        assert_eq!(rt.byte_cipher, hop.byte_cipher);
    }

    // ── ChainConfig::validate tests ───────────────────────────────────────

    fn hop(role: HopRole, addr: &str, pk: Option<&str>, nid: Option<&str>) -> HopConfig {
        HopConfig {
            addr: addr.into(),
            public_key: pk.map(String::from),
            node_id: nid.map(String::from),
            sni: None,
            role,
            display_name: None,
            camouflage: None,
            byte_cipher: None,
            relay_mode: crate::mirage::wire::RelayMode::OnionPeel,
            camo_server_pubkey: None,
            selector_token_hex: None,
        }
    }

    fn chain(id: &str, hops: Vec<HopConfig>) -> ChainConfig {
        ChainConfig {
            chain_id: id.into(),
            hops,
            handshake: HandshakeStrategy::Telescopic,
            reply: ReplyMode::Onion,
            protocol: ProtocolId::Tcp(TcpProtocolId::Mirage),
            priority: 0,
            shaping: ShapingPreset::default(),
            camouflage: CamouflageMode::default(),
            cover_traffic: CoverTrafficConfig::default(),
            socks5_bind: None,
            aead_suite: crate::crypto::AeadSuite::ChaCha20Poly1305,
            kill_switch: None,
            group: None,
            nature: None,
        }
    }

    #[test]
    fn validate_rejects_empty_hops() {
        let c = chain("c1", vec![]);
        assert!(matches!(
            c.validate(),
            Err(ChainValidationError::EmptyHops { .. })
        ));
    }

    #[test]
    fn validate_rejects_single_hop_not_exit() {
        let c = chain(
            "c1",
            vec![hop(HopRole::Entry, "1.2.3.4:80", None, Some("n0"))],
        );
        assert!(matches!(
            c.validate(),
            Err(ChainValidationError::LastHopNotExit { .. })
        ));
    }

    #[test]
    fn validate_accepts_single_exit_hop() {
        let c = chain(
            "c1",
            vec![hop(HopRole::Exit, "1.2.3.4:80", None, Some("n0"))],
        );
        assert!(c.validate().is_ok());
    }

    #[test]
    fn validate_rejects_multi_hop_no_entry() {
        let c = chain(
            "c1",
            vec![
                hop(HopRole::Middle, "1:80", None, Some("a")),
                hop(HopRole::Exit, "2:80", None, Some("b")),
            ],
        );
        assert!(matches!(
            c.validate(),
            Err(ChainValidationError::FirstHopNotEntry { .. })
        ));
    }

    #[test]
    fn validate_rejects_middle_position_mismatch() {
        let c = chain(
            "c1",
            vec![
                hop(HopRole::Entry, "1:80", None, Some("a")),
                hop(HopRole::Entry, "2:80", None, Some("b")), // wrong — should be Middle
                hop(HopRole::Exit, "3:80", None, Some("c")),
            ],
        );
        assert!(matches!(
            c.validate(),
            Err(ChainValidationError::MiddleRoleMismatch { .. })
        ));
    }

    #[test]
    fn validate_rejects_hop_with_no_resolution_source() {
        let c = chain(
            "c1",
            vec![hop(HopRole::Exit, "1:80", None, None)],
        );
        assert!(matches!(
            c.validate(),
            Err(ChainValidationError::UnresolvableHop { .. })
        ));
    }

    /// Wire V5: node_id is required even when public_key is supplied.
    /// The V5EnvelopeHeader embeds chain_node_ids for transcript binding —
    /// a hop with only public_key has no identity the server can look up.
    #[test]
    fn validate_rejects_hop_with_only_public_key() {
        let c = chain(
            "c1",
            vec![hop(HopRole::Exit, "1:80", Some("aa".repeat(32).as_str()), None)],
        );
        assert!(matches!(
            c.validate(),
            Err(ChainValidationError::UnresolvableHop { .. })
        ));
    }

    #[test]
    fn validate_rejects_addr_without_port() {
        let c = chain(
            "c1",
            vec![hop(HopRole::Exit, "no-port-here", None, Some("n"))],
        );
        assert!(matches!(
            c.validate(),
            Err(ChainValidationError::HopAddrNoPort { .. })
        ));
    }

    #[test]
    fn validate_accepts_3hop_onion() {
        let c = chain(
            "c1",
            vec![
                hop(HopRole::Entry, "1.2.3.4:4920", None, Some("entry")),
                hop(HopRole::Middle, "5.6.7.8:4921", None, Some("hop")),
                hop(HopRole::Exit, "9.10.11.12:4922", None, Some("exit")),
            ],
        );
        assert!(c.validate().is_ok());
    }

    // ── WireNature tests ──────────────────────────────────────────────────

    #[test]
    fn effective_nature_infers_when_absent() {
        // Direct: single exit hop.
        let direct = chain(
            "c-direct",
            vec![hop(HopRole::Exit, "1.2.3.4:80", None, Some("n0"))],
        );
        assert_eq!(direct.effective_nature(), WireNature::Direct);

        // Mixnet: multi-hop onion chain.
        let mixnet = chain(
            "c-mixnet",
            vec![
                hop(HopRole::Entry, "1.2.3.4:4920", None, Some("entry")),
                hop(HopRole::Middle, "5.6.7.8:4921", None, Some("hop")),
                hop(HopRole::Exit, "9.10.11.12:4922", None, Some("exit")),
            ],
        );
        assert_eq!(mixnet.effective_nature(), WireNature::Mixnet);
    }

    #[test]
    fn validate_rejects_declared_nature_mismatch() {
        // Structurally Direct (single exit hop, no foreign-wire config), but
        // declared as Mixnet — must be rejected.
        let mut c = chain(
            "c1",
            vec![hop(HopRole::Exit, "1.2.3.4:80", None, Some("n0"))],
        );
        c.nature = Some(WireNature::Mixnet);
        assert!(matches!(
            c.validate(),
            Err(ChainValidationError::NatureMismatch { .. })
        ));
    }

    #[test]
    fn validate_group_natures_rejects_mixed() {
        let mut a = chain(
            "c-a",
            vec![hop(HopRole::Exit, "1.2.3.4:80", None, Some("n0"))],
        );
        a.kill_switch = Some(KillSwitchMode::General);
        a.group = Some("failover-1".to_owned());

        let mut b = chain(
            "c-b",
            vec![
                hop(HopRole::Entry, "5.6.7.8:4920", None, Some("entry")),
                hop(HopRole::Exit, "5.6.7.9:4921", None, Some("exit")),
            ],
        );
        b.kill_switch = Some(KillSwitchMode::General);
        b.group = Some("failover-1".to_owned());

        assert!(matches!(
            ChainConfig::validate_group_natures(&[a, b]),
            Err(ChainValidationError::MixedNatureGroup { .. })
        ));
    }

    #[test]
    fn validate_group_natures_accepts_same_nature() {
        let mut a = chain(
            "c-a",
            vec![hop(HopRole::Exit, "1.2.3.4:80", None, Some("n0"))],
        );
        a.kill_switch = Some(KillSwitchMode::General);
        a.group = Some("failover-1".to_owned());

        let mut b = chain(
            "c-b",
            vec![hop(HopRole::Exit, "5.6.7.8:80", None, Some("n1"))],
        );
        b.kill_switch = Some(KillSwitchMode::General);
        b.group = Some("failover-1".to_owned());

        assert!(ChainConfig::validate_group_natures(&[a, b]).is_ok());
    }

    // ── SubscriberEntranceConfig: socks_addr retirement (2026-09-23) ──────

    /// A `node.toml` written before the unix-channel move still carries a
    /// `socks_addr` value — it must keep deserialising, with the value
    /// silently discarded, rather than fail the whole node's config load.
    #[test]
    fn an_old_socks_addr_value_still_deserializes_and_is_ignored() {
        let old_json = r#"{
            "socks_addr": "127.0.0.1:19489",
            "aggregate_rate_bytes_per_sec": 1000000
        }"#;
        let cfg: SubscriberEntranceConfig =
            serde_json::from_str(old_json).expect("an old socks_addr field must not fail deserialize");
        assert_eq!(
            cfg.legacy_socks_addr,
            Some("127.0.0.1:19489".parse().expect("valid addr"))
        );
        assert_eq!(cfg.aggregate_rate_bytes_per_sec, Some(1_000_000));
    }

    /// The current shape — no `socks_addr` at all — deserialises cleanly;
    /// the hand-off now rides `LocalChannel::EdgeClientEntrance`, a fixed
    /// unix socket this config carries no address for.
    #[test]
    fn a_config_with_no_socks_addr_deserializes_cleanly() {
        let json = r#"{ "aggregate_rate_bytes_per_sec": 500000 }"#;
        let cfg: SubscriberEntranceConfig = serde_json::from_str(json).expect("deserialize");
        assert_eq!(cfg.legacy_socks_addr, None);
        assert_eq!(cfg.aggregate_rate_bytes_per_sec, Some(500_000));
    }

    /// The retired field is never re-serialised, old value or not — a
    /// freshly-written `node.toml` must not resurrect `socks_addr`.
    #[test]
    fn the_legacy_field_never_re_serializes() {
        let cfg = SubscriberEntranceConfig {
            legacy_socks_addr: Some("127.0.0.1:19489".parse().expect("valid addr")),
            aggregate_rate_bytes_per_sec: None,
            aggregate_burst_bytes: None,
            per_connection_rate_bytes_per_sec: None,
            monthly_volume_bytes: None,
            degraded_floor_bytes_per_sec: None,
        };
        let json = serde_json::to_string(&cfg).expect("serialize");
        assert!(
            !json.contains("socks_addr"),
            "socks_addr must never be written back out; got: {json}"
        );
    }
}
