//! Camouflage — per-leg outer wire wrapper.
//!
//! Applied via `LayerSpec.camouflage` on ingress (server strips) and
//! on outgoing (server wraps the outbound dial to the next hop).
//!
//! See `docs/plans/mirage-architecture-clean-taxonomy.md` §Branch-S isolation.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TransportCamouflage {
    /// No outer wrapper — raw TCP.
    None,

    /// Real TLS 1.3 outer session via rustls.
    TlsReal {
        sni: String,
        #[serde(default)]
        alpn: Vec<String>,
    },

    /// HTTP/1.1 Upgrade → WebSocket binary frames.
    WebSocket { path: String, host: String },

    /// HTTP/1.1 `Upgrade` to a raw byte stream — xray-style `xhttp` transport.
    Xhttp { path: String, host: String },

    /// Reality-style X25519 handshake authentication.
    Reality {
        short_id: String,
        server_name: String,
        max_time_diff: u32,
        fallback_dest: Option<String>,
    },

    /// SSH `direct-tcpip` channel carrying Mirage traffic.
    Ssh {
        ssh_user: String,
        #[serde(default)]
        ssh_host_key: Option<String>,
        #[serde(default)]
        ssh_private_key: Option<String>,
        #[serde(default)]
        ssh_password: Option<String>,
        forward_host: String,
        forward_port: u16,
    },

    /// gRPC bidirectional streaming carrying Mirage frames.
    Grpc {
        service_name: String,
        method_name: String,
        authority: String,
        #[serde(default)]
        use_tls: bool,
    },

    /// DNS tunnel — encodes payload in DNS TXT/NULL queries.
    DnsTunnel {
        domain: String,
        dns_server: SocketAddr,
        #[serde(default = "dns_encoding_default")]
        encoding: String,
        #[serde(default = "dns_qtype_default")]
        query_type: String,
    },

    /// ICMP Echo Request/Reply payload tunnel.
    Icmp {
        peer_addr: IpAddr,
        identifier: u16,
        #[serde(default = "icmp_mtu_default")]
        mtu: usize,
    },

    /// W3C WebTransport over HTTP/3 (QUIC + TLS 1.3).
    WebTransport {
        path: String,
        authority: String,
        bind_addr: SocketAddr,
    },

    /// QUIC outer transport (UDP + TLS 1.3) with Mirage AEAD inside.
    Quic {
        #[serde(default)]
        alpn: Vec<String>,
        bind_addr: SocketAddr,
    },

    /// HTTP/3 CONNECT-style tunnel over QUIC with Mirage AEAD inside.
    Http3 {
        authority: String,
        tunnel_path: String,
        alpn: String,
        bind_addr: SocketAddr,
    },

    /// Hysteria2-style UDP camouflage with Salamander obfuscation
    /// (Mirage AEAD inside).
    ///
    /// KEPT FOR READING OLD CONFIGS ONLY — Hysteria2 is not part of the mask
    /// set any more. A config that asks for it is refused with a plain error.
    Hysteria2 { psk_hex: String, bind_addr: SocketAddr },

    /// WireGuard/AmneziaWG-style UDP camouflage (Mirage AEAD inside).
    WireGuard {
        magic_byte: u8,
        junk_count: u8,
        junk_min: u16,
        junk_max: u16,
        bind_addr: SocketAddr,
    },

    /// Raw UDP carrying Mirage handshake + AEAD frames, no outer wrapping.
    RawUdp { bind_addr: SocketAddr },
}

impl TransportCamouflage {
    pub fn label(&self) -> &'static str {
        match self {
            TransportCamouflage::None => "none",
            TransportCamouflage::TlsReal { .. } => "tls_real",
            TransportCamouflage::WebSocket { .. } => "websocket",
            TransportCamouflage::Xhttp { .. } => "xhttp",
            TransportCamouflage::Reality { .. } => "reality",
            TransportCamouflage::Ssh { .. } => "ssh",
            TransportCamouflage::Grpc { .. } => "grpc",
            TransportCamouflage::DnsTunnel { .. } => "dns_tunnel",
            TransportCamouflage::Icmp { .. } => "icmp",
            TransportCamouflage::WebTransport { .. } => "web_transport",
            TransportCamouflage::Quic { .. } => "quic",
            TransportCamouflage::Http3 { .. } => "http3",
            TransportCamouflage::Hysteria2 { .. } => "hysteria2",
            TransportCamouflage::WireGuard { .. } => "wireguard",
            TransportCamouflage::RawUdp { .. } => "raw_udp",
        }
    }

    /// Whether this camouflage rides on UDP transport.
    pub fn is_udp(&self) -> bool {
        matches!(
            self,
            TransportCamouflage::Quic { .. }
                | TransportCamouflage::Http3 { .. }
                | TransportCamouflage::Hysteria2 { .. }
                | TransportCamouflage::WireGuard { .. }
                | TransportCamouflage::RawUdp { .. }
                | TransportCamouflage::WebTransport { .. }
                | TransportCamouflage::DnsTunnel { .. }
                | TransportCamouflage::Icmp { .. }
        )
    }

    /// Whether this carrier can carry an ordered, lossless byte stream.
    ///
    /// The edge session is a mux: a byte stream with no retransmission of
    /// its own. A carrier that is a plain datagram pipe loses and reorders
    /// packets, and the transport above it authenticates every frame with a
    /// counter -- anything that arrives out of order is refused, so one lost
    /// datagram ends the session.
    ///
    /// QUIC and HTTP/3 ride on UDP too, but they carry a reliable stream on
    /// top, so they qualify.
    pub fn carries_reliable_stream(&self) -> bool {
        match self {
            TransportCamouflage::WireGuard { .. }
            | TransportCamouflage::RawUdp { .. }
            | TransportCamouflage::Icmp { .. }
            | TransportCamouflage::DnsTunnel { .. }
            | TransportCamouflage::Hysteria2 { .. } => false,
            _ => true,
        }
    }

    /// Pure, exhaustive — no catch-all, so a 16th variant is a compile error
    /// here rather than a silent [`SessionProfile::Bursty`] default. Judged
    /// by what a REAL service wearing this shape does, not by what is
    /// convenient to enforce. See [`SessionProfile`]'s own doc for the axis
    /// this answers and why it needs no new wire field.
    pub const fn session_profile(&self) -> SessionProfile {
        match self {
            // Raw only ever wraps :22 in this codebase — a real SSH session
            // is long-lived by the covered protocol's own nature.
            TransportCamouflage::None => SessionProfile::Sustained,
            TransportCamouflage::TlsReal { .. } => SessionProfile::Bursty,
            TransportCamouflage::WebSocket { .. } => SessionProfile::Sustained,
            TransportCamouflage::Xhttp { .. } => SessionProfile::Sustained,
            TransportCamouflage::Reality { .. } => SessionProfile::Bursty,
            // Traffic riding inside a real SSH channel — same reasoning as `None`.
            TransportCamouflage::Ssh { .. } => SessionProfile::Sustained,
            // gRPC bidirectional streaming is the standard long-held,
            // many-concurrent-stream real protocol.
            TransportCamouflage::Grpc { .. } => SessionProfile::Sustained,
            // Real DNS queries are one-shot; a tunnel that holds one "query"
            // open for hours is implausible for the covering protocol.
            TransportCamouflage::DnsTunnel { .. } => SessionProfile::Bursty,
            TransportCamouflage::Icmp { .. } => SessionProfile::Bursty,
            TransportCamouflage::WebTransport { .. } => SessionProfile::Sustained,
            TransportCamouflage::Quic { .. } => SessionProfile::Sustained,
            TransportCamouflage::Http3 { .. } => SessionProfile::Sustained,
            TransportCamouflage::Hysteria2 { .. } => SessionProfile::Sustained,
            TransportCamouflage::WireGuard { .. } => SessionProfile::Sustained,
            TransportCamouflage::RawUdp { .. } => SessionProfile::Sustained,
        }
    }
}

/// How long, and how continuously, a real service wearing this camouflage
/// plausibly holds ONE connection open — the axis nothing in
/// [`TransportCamouflage`] carries today. A face's declared byte shape
/// already implies an answer; [`TransportCamouflage::session_profile`] makes
/// that answer a value instead of something every reader has to infer.
///
/// # No new wire field, no capsule change
///
/// Every consumer that needs this already holds a [`TransportCamouflage`]
/// value from an existing channel — the perimeter has it per face, a dialer
/// has it per hop, a peer has it inside its signed declared identity. This is
/// computed locally by each holder from data already in hand: nothing new
/// travels on the wire, nothing new is signed, and both ends reach the same
/// answer because `session_profile()` is a pure function of a value they
/// already agree on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionProfile {
    /// Many short-lived connections, opened and closed per request — the
    /// ordinary web/API default.
    Bursty,
    /// Few, long-held, sometimes-idle connections — a persistent app/API
    /// backend, a real-time channel, an interactive admin session.
    Sustained,
}

impl SessionProfile {
    /// Stable, lowercase label for logs and metrics — the same convention as
    /// [`TransportCamouflage::label`] and `Disposition::as_tag` elsewhere in
    /// this workspace.
    pub const fn label(&self) -> &'static str {
        match self {
            SessionProfile::Bursty => "bursty",
            SessionProfile::Sustained => "sustained",
        }
    }
}

fn dns_encoding_default() -> String {
    "base32".to_string()
}

fn icmp_mtu_default() -> usize {
    1400
}

fn dns_qtype_default() -> String {
    "TXT".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One constructed value per variant, paired with the profile
    /// `session_profile()` must return for it — the derivation table this
    /// module's own doc argues for, pinned so a future edit to the match
    /// arms shows up here as a failing assertion rather than a silent
    /// behaviour change. Field values are placeholders; only the variant
    /// discriminant feeds `session_profile()`.
    fn every_variant_with_its_expected_profile() -> Vec<(TransportCamouflage, SessionProfile)> {
        vec![
            (TransportCamouflage::None, SessionProfile::Sustained),
            (
                TransportCamouflage::TlsReal { sni: "example.com".into(), alpn: vec![] },
                SessionProfile::Bursty,
            ),
            (
                TransportCamouflage::WebSocket { path: "/ws".into(), host: "example.com".into() },
                SessionProfile::Sustained,
            ),
            (
                TransportCamouflage::Xhttp { path: "/x".into(), host: "example.com".into() },
                SessionProfile::Sustained,
            ),
            (
                TransportCamouflage::Reality {
                    short_id: "abcd".into(),
                    server_name: "example.com".into(),
                    max_time_diff: 60_000,
                    fallback_dest: None,
                },
                SessionProfile::Bursty,
            ),
            (
                TransportCamouflage::Ssh {
                    ssh_user: "mirage".into(),
                    ssh_host_key: None,
                    ssh_private_key: None,
                    ssh_password: None,
                    forward_host: "127.0.0.1".into(),
                    forward_port: 22,
                },
                SessionProfile::Sustained,
            ),
            (
                TransportCamouflage::Grpc {
                    service_name: "svc".into(),
                    method_name: "Stream".into(),
                    authority: "example.com".into(),
                    use_tls: true,
                },
                SessionProfile::Sustained,
            ),
            (
                TransportCamouflage::DnsTunnel {
                    domain: "example.com".into(),
                    dns_server: "8.8.8.8:53".parse().expect("valid socket addr"),
                    encoding: dns_encoding_default(),
                    query_type: dns_qtype_default(),
                },
                SessionProfile::Bursty,
            ),
            (
                TransportCamouflage::Icmp {
                    peer_addr: "203.0.113.1".parse().expect("valid ip"),
                    identifier: 1,
                    mtu: icmp_mtu_default(),
                },
                SessionProfile::Bursty,
            ),
            (
                TransportCamouflage::WebTransport {
                    path: "/wt".into(),
                    authority: "example.com".into(),
                    bind_addr: "0.0.0.0:443".parse().expect("valid socket addr"),
                },
                SessionProfile::Sustained,
            ),
            (
                TransportCamouflage::Quic {
                    alpn: vec!["h3".into()],
                    bind_addr: "0.0.0.0:443".parse().expect("valid socket addr"),
                },
                SessionProfile::Sustained,
            ),
            (
                TransportCamouflage::Http3 {
                    authority: "example.com".into(),
                    tunnel_path: "/t".into(),
                    alpn: "h3".into(),
                    bind_addr: "0.0.0.0:443".parse().expect("valid socket addr"),
                },
                SessionProfile::Sustained,
            ),
            (
                TransportCamouflage::Hysteria2 {
                    psk_hex: "ab".into(),
                    bind_addr: "0.0.0.0:443".parse().expect("valid socket addr"),
                },
                SessionProfile::Sustained,
            ),
            (
                TransportCamouflage::WireGuard {
                    magic_byte: 1,
                    junk_count: 2,
                    junk_min: 10,
                    junk_max: 20,
                    bind_addr: "0.0.0.0:51820".parse().expect("valid socket addr"),
                },
                SessionProfile::Sustained,
            ),
            (
                TransportCamouflage::RawUdp {
                    bind_addr: "0.0.0.0:9000".parse().expect("valid socket addr"),
                },
                SessionProfile::Sustained,
            ),
        ]
    }

    #[test]
    fn every_camouflage_variant_derives_its_named_session_profile() {
        let cases = every_variant_with_its_expected_profile();
        // Fifteen variants today — a count check so a variant added to the
        // enum without a matching case here fails loudly instead of the
        // list quietly staying one short.
        assert_eq!(cases.len(), 15, "add the new variant's expected profile above");
        for (camo, expected) in cases {
            assert_eq!(
                camo.session_profile(),
                expected,
                "{} must derive {:?}",
                camo.label(),
                expected
            );
        }
    }

    #[test]
    fn session_profile_label_is_stable_and_lowercase() {
        assert_eq!(SessionProfile::Bursty.label(), "bursty");
        assert_eq!(SessionProfile::Sustained.label(), "sustained");
    }
}
