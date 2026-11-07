//! Named `server.env` bodies.
//!
//! A profile names protocols. It is not a mask. Camouflage exists only
//! inside [`Protocol::Mirage`], and every Mirage body printed here is
//! camouflage `none`.

use std::net::{IpAddr, Ipv4Addr};

use mirage_core::mirage::wire::{MirageCamouflage, MirageCarrier, Protocol};
use rand::rngs::OsRng;
use rand::RngCore;

/// Which complete `server.env` to print.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// One terminator door per real protocol. Mirage camouflage is none.
    All,
    /// QUIC only, on UDP 443.
    Quic,
    /// QUIC on UDP 443, plus four Mirage TCP perimeter faces.
    QuicMirage,
}

/// `all`, `quic`, or `quic-mirage`. Anything else is not a profile.
pub fn parse_profile(name: &str) -> Option<Profile> {
    match name {
        "all" => Some(Profile::All),
        "quic" => Some(Profile::Quic),
        "quic-mirage" => Some(Profile::QuicMirage),
        _ => None,
    }
}

/// The `server.env` body for `profile`.
///
/// `host` is written into SNI, the websocket host, and the gRPC, HTTP/3,
/// WebTransport, and DNS names. It is JSON-escaped by `serde_json`. The
/// body has no `{ID}_MASK` line and no `PROFILE=` line. Secrets are minted
/// on each call.
pub fn render(profile: Profile, host: &str) -> String {
    let name = match profile {
        Profile::All => "all",
        Profile::Quic => "quic",
        Profile::QuicMirage => "quic-mirage",
    };
    let rows = match profile {
        Profile::All => all_rows(host),
        Profile::Quic => vec![quic_row()],
        Profile::QuicMirage => quic_mirage_rows(),
    };
    emit(name, &rows)
}

struct Row {
    id: &'static str,
    port: u16,
    protocol: Protocol,
}

fn emit(profile_name: &str, rows: &[Row]) -> String {
    let mut out = format!(
        "STACK=auto\n\
         # profile {profile_name} - camouflage exists only inside mirage; these defaults are none\n\
         PROTOCOLS="
    );
    for (index, row) in rows.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push_str(row.id);
    }
    out.push('\n');
    for row in rows {
        let key = row.id.to_ascii_uppercase();
        let body = serde_json::to_string(&row.protocol)
            .expect("a protocol body is json: strings, numbers, and addresses");
        out.push_str(&format!("{key}_PORT={}\n{key}_PROTOCOL={body}\n", row.port));
    }
    out
}

fn quic_row() -> Row {
    Row {
        id: "quic",
        port: 443,
        protocol: Protocol::Quic {
            alpn: vec!["h3".to_owned()],
        },
    }
}

fn mirage_tcp(id: &'static str, port: u16) -> Row {
    Row {
        id,
        port,
        protocol: Protocol::Mirage {
            carrier: MirageCarrier::Tcp,
            camouflage: MirageCamouflage::None,
        },
    }
}

fn quic_mirage_rows() -> Vec<Row> {
    vec![
        quic_row(),
        mirage_tcp("m443", 443),
        mirage_tcp("m80", 80),
        mirage_tcp("m8080", 8080),
        mirage_tcp("m8443", 8443),
    ]
}

fn all_rows(host: &str) -> Vec<Row> {
    let host = host.to_owned();
    let wg = tunnel_keys();
    let awg = tunnel_keys();
    vec![
        mirage_tcp("mtcp", 8443),
        Row {
            id: "tls",
            port: 443,
            protocol: Protocol::Tls {
                sni: host.clone(),
                alpn: vec!["h2".to_owned()],
            },
        },
        Row {
            id: "ws",
            port: 80,
            protocol: Protocol::WebSocket {
                path: "/".to_owned(),
                host: host.clone(),
            },
        },
        Row {
            id: "ssh",
            port: 52022,
            protocol: Protocol::Ssh {
                ssh_user: "door".to_owned(),
                ssh_host_key: None,
                ssh_private_key: None,
                ssh_password: Some(random_hex(16)),
                forward_host: "127.0.0.1".to_owned(),
                forward_port: 1,
            },
        },
        Row {
            id: "grpc",
            port: 2052,
            protocol: Protocol::Grpc {
                service_name: "mirage.Tunnel".to_owned(),
                method_name: "Open".to_owned(),
                authority: host.clone(),
                use_tls: false,
            },
        },
        Row {
            id: "ss",
            port: 8388,
            protocol: Protocol::Shadowsocks {
                method: "2022-blake3-aes-128-gcm".to_owned(),
                password: base64_encode(&random_bytes(16)),
            },
        },
        Row {
            id: "mudp",
            port: 2053,
            protocol: Protocol::Mirage {
                carrier: MirageCarrier::Udp,
                camouflage: MirageCamouflage::None,
            },
        },
        quic_row(),
        Row {
            id: "h3",
            port: 8443,
            protocol: Protocol::Http3 {
                authority: host.clone(),
                tunnel_path: "/tunnel".to_owned(),
                alpn: "h3".to_owned(),
            },
        },
        Row {
            id: "wt",
            port: 2083,
            protocol: Protocol::WebTransport {
                path: "/".to_owned(),
                authority: host.clone(),
            },
        },
        Row {
            id: "dns",
            port: 5353,
            protocol: Protocol::Dns {
                domain: host.clone(),
                dns_server: "1.1.1.1:53".parse().expect("1.1.1.1:53 is a socket address"),
                encoding: "base32".to_owned(),
                query_type: "TXT".to_owned(),
            },
        },
        Row {
            id: "wg",
            port: 51820,
            protocol: Protocol::WireGuard {
                static_private_hex: wg.static_private_hex,
                peer_public_hex: wg.peer_public_hex,
                preshared_key_hex: Some(wg.preshared_key_hex),
                client_private_hex: Some(wg.client_private_hex),
            },
        },
        Row {
            id: "awg",
            port: 51821,
            protocol: Protocol::AmneziaWg {
                static_private_hex: awg.static_private_hex,
                peer_public_hex: awg.peer_public_hex,
                preshared_key_hex: Some(awg.preshared_key_hex),
                client_private_hex: Some(awg.client_private_hex),
                jc: 4,
                jmin: 40,
                jmax: 70,
                s1: 15,
                s2: 18,
                s3: 20,
                s4: 23,
                h1: "1-1000000".to_owned(),
                h2: "1000001-2000000".to_owned(),
                h3: "2000001-3000000".to_owned(),
                h4: "3000001-4000000".to_owned(),
            },
        },
        Row {
            id: "icmp",
            port: 39247,
            protocol: Protocol::Icmp {
                peer_addr: icmp_peer(&host),
                identifier: 39247,
                mtu: 1400,
            },
        },
    ]
}

struct TunnelKeys {
    static_private_hex: String,
    peer_public_hex: String,
    preshared_key_hex: String,
    client_private_hex: String,
}

/// Two X25519 pairs. The server secret is `static_private_hex`. The client
/// public is `peer_public_hex` and the client secret is `client_private_hex`.
fn tunnel_keys() -> TunnelKeys {
    let (static_private_hex, _) = x25519_pair();
    let (client_private_hex, peer_public_hex) = x25519_pair();
    TunnelKeys {
        static_private_hex,
        peer_public_hex,
        preshared_key_hex: random_hex(32),
        client_private_hex,
    }
}

fn x25519_pair() -> (String, String) {
    let mut secret = [0u8; 32];
    OsRng.fill_bytes(&mut secret);
    let pair = mirage_core::crypto::KeyPair::from_secret(secret);
    (
        hex::encode(pair.secret.to_bytes()),
        hex::encode(pair.public.as_bytes()),
    )
}

fn icmp_peer(host: &str) -> IpAddr {
    host.parse().unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST))
}

fn random_bytes(len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn random_hex(len: usize) -> String {
    hex::encode(random_bytes(len))
}

/// Standard base64. Shadowsocks 2022 wants the key in this alphabet.
fn base64_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let n = ((bytes[index] as u32) << 16)
            | ((bytes[index + 1] as u32) << 8)
            | (bytes[index + 2] as u32);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        out.push(TABLE[((n >> 6) & 63) as usize] as char);
        out.push(TABLE[(n & 63) as usize] as char);
        index += 3;
    }
    if index < bytes.len() {
        let b0 = bytes[index] as u32;
        let b1 = if index + 1 < bytes.len() {
            bytes[index + 1] as u32
        } else {
            0
        };
        let n = (b0 << 16) | (b1 << 8);
        out.push(TABLE[((n >> 18) & 63) as usize] as char);
        out.push(TABLE[((n >> 12) & 63) as usize] as char);
        if index + 1 < bytes.len() {
            out.push(TABLE[((n >> 6) & 63) as usize] as char);
        } else {
            out.push('=');
        }
        out.push('=');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env::ServerEnv;
    use mirage_core::persona::Persona;

    fn persona() -> Persona {
        let machine =
            mirage_core::ids::MachineId::new("ru-hostkey-203.0.113.15").expect("machine id");
        mirage_core::persona::persona_for(&machine)
    }

    fn parsed(profile: Profile, host: &str) -> ServerEnv {
        let text = render(profile, host);
        ServerEnv::parse(&text).unwrap_or_else(|err| panic!("{profile:?} did not parse: {err}\n{text}"))
    }

    #[test]
    fn the_three_names_are_the_only_profiles() {
        assert_eq!(parse_profile("all"), Some(Profile::All));
        assert_eq!(parse_profile("quic"), Some(Profile::Quic));
        assert_eq!(parse_profile("quic-mirage"), Some(Profile::QuicMirage));
        assert_eq!(parse_profile("ALL"), None);
        assert_eq!(parse_profile("mask"), None);
        assert_eq!(parse_profile(""), None);
    }

    #[test]
    fn each_profile_parses() {
        let persona = persona();
        for profile in [Profile::All, Profile::Quic, Profile::QuicMirage] {
            let env = parsed(profile, "localhost");
            let _ = env.faces(&persona).expect("faces");
            let _ = env.protocol_doors(&persona).expect("doors");
        }
    }

    #[test]
    fn all_is_one_mirage_tcp_face_and_the_other_protocols_are_doors() {
        let text = render(Profile::All, "example.test");
        assert!(text.starts_with("STACK=auto\n"), "{text}");
        assert!(text.contains(
            "PROTOCOLS=mtcp,tls,ws,ssh,grpc,ss,mudp,quic,h3,wt,dns,wg,awg,icmp\n"
        ));
        assert!(!text.contains("_MASK"), "{text}");
        assert!(!text.contains("PROFILE="), "{text}");
        assert_eq!(text.matches(r#""camouflage":{"type":"none"}"#).count(), 2);
        assert!(!text.contains("\"type\":\"reality\""));
        assert!(!text.contains("\"type\":\"junk\""));
        assert!(!text.contains("\"type\":\"xhttp\""));

        let env = ServerEnv::parse(&text).expect("all parses");
        let persona = persona();
        let faces = env.faces(&persona).expect("faces");
        assert_eq!(faces.len(), 1);
        assert_eq!(faces[0].id, "mtcp");
        assert_eq!(faces[0].port, 8443);
        assert!(matches!(
            faces[0].protocol,
            Protocol::Mirage {
                carrier: MirageCarrier::Tcp,
                camouflage: MirageCamouflage::None,
            }
        ));
        let endpoints = env.udp_endpoints(&persona).expect("endpoints");
        assert_eq!(endpoints.len(), 1);
        assert_eq!(endpoints[0].id, "mudp");
        assert_eq!(endpoints[0].port, 2053);
        assert!(matches!(
            endpoints[0].protocol,
            Protocol::Mirage {
                carrier: MirageCarrier::Udp,
                camouflage: MirageCamouflage::None,
            }
        ));
        let doors = env.protocol_doors(&persona).expect("doors");
        let ids: Vec<&str> = doors.iter().map(|door| door.id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "tls", "ws", "ssh", "grpc", "ss", "quic", "h3", "wt", "dns", "wg", "awg", "icmp"
            ]
        );
        let tls = doors.iter().find(|door| door.id == "tls").expect("tls");
        assert!(matches!(&tls.protocol, Protocol::Tls { sni, .. } if sni == "example.test"));
        let icmp = doors.iter().find(|door| door.id == "icmp").expect("icmp");
        assert!(matches!(
            &icmp.protocol,
            Protocol::Icmp {
                peer_addr,
                identifier: 39247,
                mtu: 1400,
            } if *peer_addr == IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
        let ss = doors.iter().find(|door| door.id == "ss").expect("ss");
        match &ss.protocol {
            Protocol::Shadowsocks { method, password } => {
                assert_eq!(method, "2022-blake3-aes-128-gcm");
                assert_eq!(password.len(), 24, "16 bytes of base64");
            }
            other => panic!("ss is not shadowsocks: {other:?}"),
        }
        let wg = doors.iter().find(|door| door.id == "wg").expect("wg");
        match &wg.protocol {
            Protocol::WireGuard {
                static_private_hex,
                peer_public_hex,
                preshared_key_hex,
                client_private_hex,
            } => {
                assert_eq!(static_private_hex.len(), 64);
                assert_eq!(peer_public_hex.len(), 64);
                assert_eq!(preshared_key_hex.as_deref().map(str::len), Some(64));
                assert_eq!(client_private_hex.as_deref().map(str::len), Some(64));
            }
            other => panic!("wg is not wireguard: {other:?}"),
        }
    }

    #[test]
    fn an_ip_host_is_the_icmp_peer() {
        let env = parsed(Profile::All, "203.0.113.9");
        let doors = env.protocol_doors(&persona()).expect("doors");
        let icmp = doors.iter().find(|door| door.id == "icmp").expect("icmp");
        assert!(matches!(
            &icmp.protocol,
            Protocol::Icmp { peer_addr, .. } if peer_addr.to_string() == "203.0.113.9"
        ));
    }

    #[test]
    fn quic_is_one_udp_door_and_no_face() {
        let text = render(Profile::Quic, "localhost");
        assert!(text.starts_with("STACK=auto\n"));
        assert!(text.contains("PROTOCOLS=quic\n"));
        assert!(text.contains("QUIC_PORT=443\n"));
        assert!(text.contains("QUIC_PROTOCOL={\"type\":\"quic\",\"alpn\":[\"h3\"]}\n"));
        assert!(!text.contains("_MASK"));
        assert!(!text.contains("\"type\":\"mirage\""));
        let env = ServerEnv::parse(&text).expect("quic parses");
        let persona = persona();
        assert!(env.faces(&persona).expect("faces").is_empty());
        assert!(env.udp_endpoints(&persona).expect("endpoints").is_empty());
        let doors = env.protocol_doors(&persona).expect("doors");
        assert_eq!(doors.len(), 1);
        assert_eq!(doors[0].id, "quic");
        assert_eq!(doors[0].port, 443);
        assert!(doors[0].protocol.is_udp());
    }

    #[test]
    fn quic_mirage_is_four_tcp_faces_and_one_quic_door() {
        let text = render(Profile::QuicMirage, "localhost");
        assert!(text.contains("PROTOCOLS=quic,m443,m80,m8080,m8443\n"));
        assert!(!text.contains("_MASK"));
        assert!(!text.contains("\"type\":\"tls\""));
        assert!(!text.contains("\"type\":\"web_socket\""));
        assert_eq!(text.matches(r#""camouflage":{"type":"none"}"#).count(), 4);
        let env = ServerEnv::parse(&text).expect("quic-mirage parses");
        let persona = persona();
        let faces = env.faces(&persona).expect("faces");
        assert_eq!(faces.len(), 4);
        let mut ports: Vec<(u16, &str)> = faces.iter().map(|face| (face.port, face.id.as_str())).collect();
        ports.sort();
        assert_eq!(
            ports,
            vec![(80, "m80"), (443, "m443"), (8080, "m8080"), (8443, "m8443")]
        );
        assert!(faces.iter().all(|face| matches!(
            face.protocol,
            Protocol::Mirage {
                carrier: MirageCarrier::Tcp,
                camouflage: MirageCamouflage::None,
            }
        )));
        assert!(env.udp_endpoints(&persona).expect("endpoints").is_empty());
        let doors = env.protocol_doors(&persona).expect("doors");
        assert_eq!(doors.len(), 1);
        assert_eq!(doors[0].id, "quic");
        assert_eq!(doors[0].port, 443);
        assert!(doors[0].protocol.is_udp());
    }

    #[test]
    fn two_all_renders_do_not_share_secrets() {
        let first = render(Profile::All, "localhost");
        let second = render(Profile::All, "localhost");
        assert_ne!(first, second);
    }

    #[test]
    fn a_host_with_a_quote_or_a_backslash_is_json_escaped_and_parses() {
        let host = "ex\"ample\\host";
        let text = render(Profile::All, host);
        assert!(text.contains(r#"ex\"ample\\host"#), "{text}");
        let env = ServerEnv::parse(&text).expect("escaped host parses");
        let doors = env.protocol_doors(&persona()).expect("doors");
        let tls = doors.iter().find(|door| door.id == "tls").expect("tls");
        assert!(matches!(&tls.protocol, Protocol::Tls { sni, .. } if sni == host));
        let ws = doors.iter().find(|door| door.id == "ws").expect("ws");
        assert!(matches!(&ws.protocol, Protocol::WebSocket { host: h, .. } if h == host));
    }
}
