//! Two levels. A door is a port plus a [`Protocol`].
//!
//! The port is the door the client dials. It sits beside the protocol, not
//! inside it. TCP doors are bound by the perimeter. UDP doors are bound by
//! the node. Which one it is follows from the protocol; there is no second
//! flag.
//!
//! [`MirageCamouflage`] exists only inside [`Protocol::Mirage`]. QUIC, TLS,
//! WireGuard and the rest are protocols. They do not carry a camouflage.

use std::net::{IpAddr, SocketAddr};

use serde::{Deserialize, Serialize};

use super::camouflage::TransportCamouflage;
use super::protocol_id::MirageCarrier;

fn dns_encoding_default() -> String {
    "base32".to_string()
}

fn dns_qtype_default() -> String {
    "TXT".to_string()
}

fn icmp_mtu_default() -> usize {
    1400
}

fn door_addr(port: u16) -> SocketAddr {
    SocketAddr::from(([0, 0, 0, 0], port))
}

/// The client-server link. One variant, one real protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum Protocol {
    /// Mirage. Carrier and camouflage are settings of this protocol only.
    Mirage {
        carrier: MirageCarrier,
        camouflage: MirageCamouflage,
    },
    Tls {
        sni: String,
        #[serde(default)]
        alpn: Vec<String>,
    },
    WebSocket { path: String, host: String },
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
    Grpc {
        service_name: String,
        method_name: String,
        authority: String,
        #[serde(default)]
        use_tls: bool,
    },
    Dns {
        domain: String,
        /// Where the client sends queries. The door port is the server bind,
        /// passed separately.
        dns_server: SocketAddr,
        #[serde(default = "dns_encoding_default")]
        encoding: String,
        #[serde(default = "dns_qtype_default")]
        query_type: String,
    },
    Icmp {
        peer_addr: IpAddr,
        identifier: u16,
        #[serde(default = "icmp_mtu_default")]
        mtu: usize,
    },
    Quic {
        #[serde(default)]
        alpn: Vec<String>,
    },
    Http3 {
        authority: String,
        tunnel_path: String,
        alpn: String,
    },
    WebTransport { path: String, authority: String },
    /// boringtun Noise_IK. Not [`MirageCamouflage::Junk`].
    WireGuard {
        static_private_hex: String,
        peer_public_hex: String,
        #[serde(default)]
        preshared_key_hex: Option<String>,
        /// Server env only. The artefact builder strips it and writes the
        /// client view (client private, server public).
        #[serde(default)]
        client_private_hex: Option<String>,
    },
    /// awgtun AmneziaWG 2.0. Not [`MirageCamouflage::Junk`] and not [`Protocol::WireGuard`].
    AmneziaWg {
        static_private_hex: String,
        peer_public_hex: String,
        #[serde(default)]
        preshared_key_hex: Option<String>,
        /// Server env only. The artefact builder strips it and writes the
        /// client view (client private, server public).
        #[serde(default)]
        client_private_hex: Option<String>,
        jc: u16,
        jmin: u16,
        jmax: u16,
        s1: u16,
        s2: u16,
        s3: u16,
        s4: u16,
        h1: String,
        h2: String,
        h3: String,
        h4: String,
    },
    Shadowsocks { method: String, password: String },
}

/// Disguises of Mirage. Not a link selector.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MirageCamouflage {
    None,
    Reality {
        short_id: String,
        server_name: String,
        max_time_diff: u32,
        fallback_dest: Option<String>,
    },
    Xhttp { path: String, host: String },
    /// Junk and a magic byte. Not the WireGuard protocol.
    Junk {
        magic_byte: u8,
        junk_count: u8,
        junk_min: u16,
        junk_max: u16,
    },
}

impl Protocol {
    pub fn label(&self) -> &'static str {
        match self {
            Protocol::Mirage { .. } => "mirage",
            Protocol::Tls { .. } => "tls",
            Protocol::WebSocket { .. } => "websocket",
            Protocol::Ssh { .. } => "ssh",
            Protocol::Grpc { .. } => "grpc",
            Protocol::Dns { .. } => "dns",
            Protocol::Icmp { .. } => "icmp",
            Protocol::Quic { .. } => "quic",
            Protocol::Http3 { .. } => "http3",
            Protocol::WebTransport { .. } => "web_transport",
            Protocol::WireGuard { .. } => "wireguard",
            Protocol::AmneziaWg { .. } => "amnezia_wg",
            Protocol::Shadowsocks { .. } => "shadowsocks",
        }
    }

    /// Whether the door is a datagram. The perimeter does not bind these.
    pub fn is_udp(&self) -> bool {
        match self {
            Protocol::Mirage { carrier, .. } => matches!(carrier, MirageCarrier::Udp),
            Protocol::Dns { .. }
            | Protocol::Icmp { .. }
            | Protocol::Quic { .. }
            | Protocol::Http3 { .. }
            | Protocol::WebTransport { .. }
            | Protocol::WireGuard { .. }
            | Protocol::AmneziaWg { .. } => true,
            Protocol::Tls { .. }
            | Protocol::WebSocket { .. }
            | Protocol::Ssh { .. }
            | Protocol::Grpc { .. }
            | Protocol::Shadowsocks { .. } => false,
        }
    }

    /// Real protocols that are not a Mirage mask. The perimeter and the
    /// Mirage dial do not speak them.
    pub fn is_foreign(&self) -> bool {
        matches!(
            self,
            Protocol::WireGuard { .. } | Protocol::AmneziaWg { .. } | Protocol::Shadowsocks { .. }
        )
    }

    /// Bridge into the old flat mask, so the existing binders keep working.
    ///
    /// `port` is the door. It becomes the bind address. It is not stored on
    /// the protocol.
    pub fn to_mask(&self, port: u16) -> Result<TransportCamouflage, String> {
        let bind = door_addr(port);
        match self {
            Protocol::Mirage {
                carrier,
                camouflage,
            } => mask_mirage(*carrier, camouflage, bind),
            Protocol::Tls { sni, alpn } => Ok(TransportCamouflage::TlsReal {
                sni: sni.clone(),
                alpn: alpn.clone(),
            }),
            Protocol::WebSocket { path, host } => Ok(TransportCamouflage::WebSocket {
                path: path.clone(),
                host: host.clone(),
            }),
            Protocol::Ssh {
                ssh_user,
                ssh_host_key,
                ssh_private_key,
                ssh_password,
                forward_host,
                forward_port,
            } => Ok(TransportCamouflage::Ssh {
                ssh_user: ssh_user.clone(),
                ssh_host_key: ssh_host_key.clone(),
                ssh_private_key: ssh_private_key.clone(),
                ssh_password: ssh_password.clone(),
                forward_host: forward_host.clone(),
                forward_port: *forward_port,
            }),
            Protocol::Grpc {
                service_name,
                method_name,
                authority,
                use_tls,
            } => Ok(TransportCamouflage::Grpc {
                service_name: service_name.clone(),
                method_name: method_name.clone(),
                authority: authority.clone(),
                use_tls: *use_tls,
            }),
            Protocol::Dns {
                domain,
                dns_server,
                encoding,
                query_type,
            } => Ok(TransportCamouflage::DnsTunnel {
                domain: domain.clone(),
                dns_server: *dns_server,
                encoding: encoding.clone(),
                query_type: query_type.clone(),
            }),
            Protocol::Icmp {
                peer_addr,
                identifier,
                mtu,
            } => Ok(TransportCamouflage::Icmp {
                peer_addr: *peer_addr,
                identifier: *identifier,
                mtu: *mtu,
            }),
            Protocol::Quic { alpn } => Ok(TransportCamouflage::Quic {
                alpn: alpn.clone(),
                bind_addr: bind,
            }),
            Protocol::Http3 {
                authority,
                tunnel_path,
                alpn,
            } => Ok(TransportCamouflage::Http3 {
                authority: authority.clone(),
                tunnel_path: tunnel_path.clone(),
                alpn: alpn.clone(),
                bind_addr: bind,
            }),
            Protocol::WebTransport { path, authority } => Ok(TransportCamouflage::WebTransport {
                path: path.clone(),
                authority: authority.clone(),
                bind_addr: bind,
            }),
            Protocol::WireGuard { .. } => {
                Err("wireguard is a protocol, not a mirage mask".to_owned())
            }
            Protocol::AmneziaWg { .. } => {
                Err("amneziawg is a protocol, not a mirage mask".to_owned())
            }
            Protocol::Shadowsocks { .. } => {
                Err("shadowsocks is a protocol, not a mirage mask".to_owned())
            }
        }
    }
}

fn mask_mirage(
    carrier: MirageCarrier,
    camouflage: &MirageCamouflage,
    bind: SocketAddr,
) -> Result<TransportCamouflage, String> {
    match (carrier, camouflage) {
        (MirageCarrier::Tcp, MirageCamouflage::None) => Ok(TransportCamouflage::None),
        (MirageCarrier::Udp, MirageCamouflage::None) => {
            Ok(TransportCamouflage::RawUdp { bind_addr: bind })
        }
        (
            MirageCarrier::Tcp,
            MirageCamouflage::Reality {
                short_id,
                server_name,
                max_time_diff,
                fallback_dest,
            },
        ) => Ok(TransportCamouflage::Reality {
            short_id: short_id.clone(),
            server_name: server_name.clone(),
            max_time_diff: *max_time_diff,
            fallback_dest: fallback_dest.clone(),
        }),
        (MirageCarrier::Tcp, MirageCamouflage::Xhttp { path, host }) => {
            Ok(TransportCamouflage::Xhttp {
                path: path.clone(),
                host: host.clone(),
            })
        }
        (
            MirageCarrier::Udp,
            MirageCamouflage::Junk {
                magic_byte,
                junk_count,
                junk_min,
                junk_max,
            },
        ) => Ok(TransportCamouflage::WireGuard {
            magic_byte: *magic_byte,
            junk_count: *junk_count,
            junk_min: *junk_min,
            junk_max: *junk_max,
            bind_addr: bind,
        }),
        (MirageCarrier::Udp, MirageCamouflage::Reality { .. }) => {
            Err("reality is a tcp camouflage of mirage".to_owned())
        }
        (MirageCarrier::Udp, MirageCamouflage::Xhttp { .. }) => {
            Err("xhttp is a tcp camouflage of mirage".to_owned())
        }
        (MirageCarrier::Tcp, MirageCamouflage::Junk { .. }) => {
            Err("junk is a udp camouflage of mirage".to_owned())
        }
    }
}

impl TryFrom<&TransportCamouflage> for Protocol {
    type Error = String;

    fn try_from(mask: &TransportCamouflage) -> Result<Self, Self::Error> {
        match mask {
            TransportCamouflage::None => Ok(Protocol::Mirage {
                carrier: MirageCarrier::Tcp,
                camouflage: MirageCamouflage::None,
            }),
            TransportCamouflage::RawUdp { .. } => Ok(Protocol::Mirage {
                carrier: MirageCarrier::Udp,
                camouflage: MirageCamouflage::None,
            }),
            TransportCamouflage::Reality {
                short_id,
                server_name,
                max_time_diff,
                fallback_dest,
            } => Ok(Protocol::Mirage {
                carrier: MirageCarrier::Tcp,
                camouflage: MirageCamouflage::Reality {
                    short_id: short_id.clone(),
                    server_name: server_name.clone(),
                    max_time_diff: *max_time_diff,
                    fallback_dest: fallback_dest.clone(),
                },
            }),
            TransportCamouflage::Xhttp { path, host } => Ok(Protocol::Mirage {
                carrier: MirageCarrier::Tcp,
                camouflage: MirageCamouflage::Xhttp {
                    path: path.clone(),
                    host: host.clone(),
                },
            }),
            TransportCamouflage::WireGuard {
                magic_byte,
                junk_count,
                junk_min,
                junk_max,
                ..
            } => Ok(Protocol::Mirage {
                carrier: MirageCarrier::Udp,
                camouflage: MirageCamouflage::Junk {
                    magic_byte: *magic_byte,
                    junk_count: *junk_count,
                    junk_min: *junk_min,
                    junk_max: *junk_max,
                },
            }),
            TransportCamouflage::TlsReal { sni, alpn } => Ok(Protocol::Tls {
                sni: sni.clone(),
                alpn: alpn.clone(),
            }),
            TransportCamouflage::WebSocket { path, host } => Ok(Protocol::WebSocket {
                path: path.clone(),
                host: host.clone(),
            }),
            TransportCamouflage::Ssh {
                ssh_user,
                ssh_host_key,
                ssh_private_key,
                ssh_password,
                forward_host,
                forward_port,
            } => Ok(Protocol::Ssh {
                ssh_user: ssh_user.clone(),
                ssh_host_key: ssh_host_key.clone(),
                ssh_private_key: ssh_private_key.clone(),
                ssh_password: ssh_password.clone(),
                forward_host: forward_host.clone(),
                forward_port: *forward_port,
            }),
            TransportCamouflage::Grpc {
                service_name,
                method_name,
                authority,
                use_tls,
            } => Ok(Protocol::Grpc {
                service_name: service_name.clone(),
                method_name: method_name.clone(),
                authority: authority.clone(),
                use_tls: *use_tls,
            }),
            TransportCamouflage::DnsTunnel {
                domain,
                dns_server,
                encoding,
                query_type,
            } => Ok(Protocol::Dns {
                domain: domain.clone(),
                dns_server: *dns_server,
                encoding: encoding.clone(),
                query_type: query_type.clone(),
            }),
            TransportCamouflage::Icmp {
                peer_addr,
                identifier,
                mtu,
            } => Ok(Protocol::Icmp {
                peer_addr: *peer_addr,
                identifier: *identifier,
                mtu: *mtu,
            }),
            TransportCamouflage::Quic { alpn, .. } => Ok(Protocol::Quic { alpn: alpn.clone() }),
            TransportCamouflage::Http3 {
                authority,
                tunnel_path,
                alpn,
                ..
            } => Ok(Protocol::Http3 {
                authority: authority.clone(),
                tunnel_path: tunnel_path.clone(),
                alpn: alpn.clone(),
            }),
            TransportCamouflage::WebTransport { path, authority, .. } => {
                Ok(Protocol::WebTransport {
                    path: path.clone(),
                    authority: authority.clone(),
                })
            }
            TransportCamouflage::Hysteria2 { .. } => {
                Err("hysteria2 is not a protocol".to_owned())
            }
        }
    }
}
