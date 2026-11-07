//! Mirage dial-core — shared client-side dial primitives.
//!
//! Extract из `mirage2app/crates/client-core/` для переиспользования между
//! клиентским runtime (cli / sentinel / tun) и monitor-mesh client.
//!
//! Содержимое:
//! - [`tunnel`]:
//!   `establish_raw_tunnel`, `establish_mux_tunnel`,
//!   happy-eyeballs IPv4/IPv6 race, UDP-chain dial
//!   (`establish_udp_chain_tunnel`, stream-adapter,
//!   single-hop only), `establish_native_udp_tunnel`
//!   (datagram-native V9, no stream adapter — see its own
//!   doc for how the two differ), `establish_udp_datagram_tunnel`
//!   (the chain-level datagram-native dial, returning
//!   `DatagramTunnel`: single-hop resolves the entry's
//!   `chain_face_udp` from the peer table and calls
//!   `establish_native_udp_tunnel`; multi-hop OnionPeel
//!   chains dispatch to `OnionFsUdpTunnel::connect` instead
//!   — U5 Slice 7). `DatagramTunnel` is an enum, not
//!   `Box<dyn Tunnel>` — see its own doc for why
//!   (`into_split` needs the concrete variant).
//! - [`onion_tunnel_fs`]:
//!   `OnionFsTunnel::connect`, the forward-secret
//!   telescopic onion circuit — the only onion dial path
//!   (stream carriage).
//! - [`onion_tunnel_fs_udp`]:
//!   `OnionFsUdpTunnel::connect`, the same
//!   telescopic circuit over datagram carriage (U5 design).
//!   Reached both directly and through
//!   `establish_udp_datagram_tunnel`'s multi-hop branch.
//! - [`cover_tunnel`]: cover-traffic wrapper.
//! - [`edge_session`]:
//!   the client<->edge session wire (`EdgeHello` /
//!   `EdgeWelcome` / per-stream `StreamOpen`) a customer's
//!   client speaks to its own `mirage-edge` box, riding on
//!   top of an established V9 tunnel before the
//!   `ONION_MUX_MAGIC` mux upgrade. Pure bounded
//!   encode/decode, no network code. Also
//!   [`filter_offered_faces_by_transport`] — the rule that
//!   keeps the faces a client offers in an `EdgeHello` on
//!   the SAME transport its session actually rides (the
//!   hello wire format carries bare port numbers and no
//!   transport tag).
//! - [`peer`]:
//!   the peer wire itself: the wire versions, the hello/welcome rules and
//!   the exit catalogue that every Mirage implementation shares.
//! - [`shaped_tunnel`]: traffic-shaping wrapper.
//! - [`udp_framing`]: length-prefixed UDP datagram framing helpers.
//!
//! Зависит ТОЛЬКО на `mirage-core` + `mirage-protocol` + tokio. Никакого
//! axum / reqwest / tokio-tungstenite — это позволяет monitor крейту
//! втащить dial-стек без транзитивных дублей.

pub mod cover_tunnel;
pub mod edge_session;
pub mod onion_tunnel_fs;
pub mod onion_tunnel_fs_udp;
pub mod peer;
pub mod shaped_tunnel;
pub mod tunnel;
pub mod udp_framing;
pub mod wire;

pub use edge_session::{
    decode_udp_datagram_frame, encode_udp_datagram_frame, face_transport,
    filter_offered_faces_by_transport, CountryCode, EdgeHello, EdgeOutcome, EdgeRefusal,
    EdgeSessionError, EdgeWelcome, ExitPreference, StreamKind, StreamOpen, StreamTarget,
    MAX_UDP_DATAGRAM_PAYLOAD,
};
pub use peer::{
    wants_assignment, ExitCatalog, PeerProfile, ALL_VERSIONS, MUX_VERSION_V1, MUX_VERSION_V2,
    MUX_VERSION_V3, MUX_VERSIONS, PLANE_VERSION,
};
pub use tunnel::{
    chain_uses_onion_framing, establish_mux_tunnel, establish_native_udp_tunnel,
    establish_raw_tunnel, establish_udp_datagram_tunnel, mint_epoch_hmac_credential,
    DatagramTunnel, DatagramTunnelReceiver, DatagramTunnelSender, ONION_MUX_MAGIC,
};
pub use onion_tunnel_fs::OnionFsTunnel;
pub use onion_tunnel_fs_udp::{OnionFsUdpTunnel, OnionFsUdpTunnelReceiver, OnionFsUdpTunnelSender};
pub use wire::{
    ListenerSnapshotEntry, MonitorToNode, NodeRegistration, NodeRegistrationResponse,
    NodeToMonitor, PushListenerEntry, UpsertChainRequest, UpsertChainResponse,
    UpsertListenerRequest, UpsertListenerResponse, UpsertMonitorRequest,
    UpsertMonitorResponse, UpsertPeerRequest, UpsertPeerResponse,
};
