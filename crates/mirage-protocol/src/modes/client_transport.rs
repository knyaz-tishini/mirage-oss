//! Transport-aware client dial — which wire transport an outer camouflage
//! requires, and the single dispatcher that honours it.
//!
//! # Why this module exists
//!
//! A Mirage client may wear ANY outer camouflage: a stream one (raw TCP,
//! TLS, WebSocket, xhttp, Reality, SSH, gRPC) or a datagram one (raw UDP,
//! QUIC, HTTP/3, WebTransport, WireGuard-style, a DNS
//! tunnel, a raw ICMP echo socket). The camouflage decides the wire
//! transport — it is not a decoration that can be bolted onto a TCP socket.
//!
//! The client-side [`crate::endpoint_protocol::EndpointProtocol`] used to
//! call [`crate::driver::run_client_tcp_v9`] unconditionally, so a QUIC
//! face was dialled by opening a TCP connection to the QUIC port: the
//! handshake could never succeed, and the failure mode was a bare
//! "connection refused" that named neither the camouflage nor the transport.
//! [`run_client_v9_transport_aware`] is the one place that decides, from
//! the camouflage alone, which dial to make.
//!
//! # The camouflage is authoritative
//!
//! [`camouflage_transport`] derives the required transport from the
//! camouflage and nothing else. The `transport` field of
//! [`MirageEndpointConfig`] is NOT consulted for the decision: it is a
//! declaration of intent, and a client that wears a QUIC camouflage but
//! carries `transport: tcp` in its config must still dial QUIC — otherwise
//! the config field would silently win over the camouflage and the dial
//! would break again. The config's `transport` field is only ever *derived*
//! here, to satisfy the guard inside [`crate::driver::run_client_udp_v9`],
//! which refuses any config whose transport is not `Udp`.
//!
//! # Unlinkability
//!
//! This module does not generate key material. The caller owns the
//! per-dial ephemeral client static key and passes it in, exactly as it
//! does for the TCP path — so a UDP dial is as unlinkable as a TCP one
//! (a fresh `x25519_dalek::StaticSecret::random_from_rng` per dial).

use std::net::SocketAddr;

use mirage_core::{
    config::{MirageEndpointConfig, TransportCamouflage, TransportKind},
    error::MirageError,
};

use crate::{
    driver::{
        run_client_tcp_v9, run_client_udp_v9, ClientCredential, DEFAULT_CLIENT_HANDSHAKE_TIMEOUT,
    },
    traits::Tunnel,
};

/// The transport an outer camouflage variant rides on the wire.
///
/// The match is exhaustive on purpose: a new [`TransportCamouflage`]
/// variant must be given a transport here, at compile time, instead of
/// silently inheriting a default.
///
/// * [`TransportKind::Tcp`] — a stream transport: raw TCP, optionally
///   wrapped in TLS / WebSocket / xhttp / Reality / SSH / gRPC.
/// * [`TransportKind::Udp`] — a datagram transport: raw UDP, QUIC, HTTP/3,
///   WebTransport, WireGuard-style, a DNS tunnel, or a raw
///   ICMP echo socket. ICMP has no port namespace of its own, so it is
///   dialled through the same datagram dispatcher as the UDP variants
///   ([`crate::driver::run_client_udp_v9`] dispatches it to the same
///   `IcmpCamouflage::connect_client` the dedicated
///   [`crate::driver::run_client_icmp`] uses).
pub fn camouflage_transport(camouflage: &TransportCamouflage) -> TransportKind {
    match camouflage {
        TransportCamouflage::None
        | TransportCamouflage::TlsReal { .. }
        | TransportCamouflage::WebSocket { .. }
        | TransportCamouflage::Xhttp { .. }
        | TransportCamouflage::Reality { .. }
        | TransportCamouflage::Ssh { .. }
        | TransportCamouflage::Grpc { .. } => TransportKind::Tcp,
        TransportCamouflage::Quic { .. }
        | TransportCamouflage::Http3 { .. }
        | TransportCamouflage::WebTransport { .. }
        | TransportCamouflage::WireGuard { .. }
        | TransportCamouflage::Hysteria2 { .. }
        | TransportCamouflage::RawUdp { .. }
        | TransportCamouflage::DnsTunnel { .. }
        | TransportCamouflage::Icmp { .. } => TransportKind::Udp,
    }
}

/// Dial a V9 client tunnel over the transport the camouflage requires.
///
/// * A stream camouflage ([`TransportKind::Tcp`]) is dialled with
///   [`crate::driver::run_client_tcp_v9`] — the config is passed through
///   **unchanged**, so the bytes on the wire are byte-for-byte the ones the
///   TCP-only client has always produced.
/// * A datagram camouflage ([`TransportKind::Udp`]) is dialled with
///   [`crate::driver::run_client_udp_v9`], over a config whose `transport`
///   field is derived from the camouflage (see the module doc).
///
/// # Arguments
///
/// * `config` — the endpoint config; only its `camouflage` decides the
///   transport, and for a TCP camouflage nothing else about it is touched.
/// * `server_addr` — the peer to dial.
/// * `server_static_pub` — the server's 32-byte declared static X25519
///   public key.
/// * `client_static_priv` — the client's 32-byte static X25519 private key.
///   Pass a per-dial ephemeral to keep the dial unlinkable.
/// * `sni` — TLS server name for the camouflage layers that use one.
/// * `mesh_id` — mesh identifier bytes baked into the handshake confirm.
/// * `credential` — optional anonymous credential (scheme byte + token).
///   Both transport paths take it in the same shape, so the credential
///   reaches the wire identically on either.
///
/// # Errors
///
/// * [`MirageError::Config`] — the camouflage has no client dial on the
///   selected path (a TCP-only camouflage asked for the datagram path, or
///   a datagram camouflage asked for the stream path). Never a panic.
/// * [`MirageError::HandshakeTimedOut`] — the datagram path got no answer
///   within [`DEFAULT_CLIENT_HANDSHAKE_TIMEOUT`]. The stream path carries
///   its own bounds inside [`crate::driver::run_client_tcp_v9`].
/// * [`MirageError::Io`] / [`MirageError::Handshake`] — whatever the
///   underlying dial raised.
pub async fn run_client_v9_transport_aware(
    config: &MirageEndpointConfig,
    server_addr: SocketAddr,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    sni: &str,
    mesh_id: &[u8],
    credential: Option<&ClientCredential>,
) -> Result<Box<dyn Tunnel>, MirageError> {
    let required = camouflage_transport(&config.camouflage);
    if config.transport != required {
        tracing::debug!(
            camouflage = %config.camouflage.label(),
            configured_transport = %config.transport.as_str(),
            required_transport = %required.as_str(),
            "client dial: the camouflage decides the transport; the config's transport field is derived"
        );
    }

    match required {
        TransportKind::Tcp => {
            // The config is passed through UNCHANGED — this branch must stay
            // byte-for-byte the legacy TCP dial.
            run_client_tcp_v9(
                config,
                server_addr,
                server_static_pub,
                client_static_priv,
                sni,
                mesh_id,
                credential,
            )
            .await
        }
        TransportKind::Udp => {
            // `run_client_udp_v9` refuses a config whose transport is not
            // `Udp`; the camouflage is authoritative, so derive it.
            let mut udp_config = config.clone();
            udp_config.transport = TransportKind::Udp;
            match tokio::time::timeout(
                DEFAULT_CLIENT_HANDSHAKE_TIMEOUT,
                run_client_udp_v9(
                    &udp_config,
                    server_addr,
                    server_static_pub,
                    client_static_priv,
                    sni,
                    mesh_id,
                    credential,
                ),
            )
            .await
            {
                Ok(result) => result,
                Err(_) => Err(MirageError::HandshakeTimedOut(format!(
                    "V9 handshake with {server_addr} timed out after {}ms (UDP datagram exchange started)",
                    DEFAULT_CLIENT_HANDSHAKE_TIMEOUT.as_millis()
                ))),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use mirage_core::config::{AuthMode, CamouflageMode};
    use tokio::net::{TcpListener, UdpSocket};

    use crate::endpoint_protocol::EndpointProtocol;
    use crate::traits::TcpProtocol;

    /// Every camouflage variant, paired with the transport it must ride.
    ///
    /// The table is exhaustive on purpose: adding a `TransportCamouflage`
    /// variant without deciding its transport breaks this test at compile
    /// time (the match in `camouflage_transport` is exhaustive too), so a
    /// new camouflage can never silently fall back to TCP.
    fn every_variant_with_its_transport() -> Vec<(TransportCamouflage, TransportKind)> {
        let bind = "0.0.0.0:443".parse().expect("valid socket addr");
        vec![
            (TransportCamouflage::None, TransportKind::Tcp),
            (
                TransportCamouflage::TlsReal { sni: "example.com".into(), alpn: vec![] },
                TransportKind::Tcp,
            ),
            (
                TransportCamouflage::WebSocket { path: "/ws".into(), host: "example.com".into() },
                TransportKind::Tcp,
            ),
            (
                TransportCamouflage::Xhttp { path: "/x".into(), host: "example.com".into() },
                TransportKind::Tcp,
            ),
            (
                TransportCamouflage::Reality {
                    short_id: "abcd".into(),
                    server_name: "example.com".into(),
                    max_time_diff: 60_000,
                    fallback_dest: None,
                },
                TransportKind::Tcp,
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
                TransportKind::Tcp,
            ),
            (
                TransportCamouflage::Grpc {
                    service_name: "svc".into(),
                    method_name: "Stream".into(),
                    authority: "example.com".into(),
                    use_tls: true,
                },
                TransportKind::Tcp,
            ),
            (
                TransportCamouflage::Quic { alpn: vec!["h3".into()], bind_addr: bind },
                TransportKind::Udp,
            ),
            (
                TransportCamouflage::Http3 {
                    authority: "example.com".into(),
                    tunnel_path: "/t".into(),
                    alpn: "h3".into(),
                    bind_addr: bind,
                },
                TransportKind::Udp,
            ),
            (
                TransportCamouflage::WebTransport {
                    path: "/wt".into(),
                    authority: "example.com".into(),
                    bind_addr: bind,
                },
                TransportKind::Udp,
            ),
            (
                TransportCamouflage::WireGuard {
                    magic_byte: 4,
                    junk_count: 1,
                    junk_min: 16,
                    junk_max: 64,
                    bind_addr: bind,
                },
                TransportKind::Udp,
            ),
            (
                TransportCamouflage::Hysteria2 { psk_hex: "00".repeat(32), bind_addr: bind },
                TransportKind::Udp,
            ),
            (TransportCamouflage::RawUdp { bind_addr: bind }, TransportKind::Udp),
            (
                TransportCamouflage::DnsTunnel {
                    domain: "example.com".into(),
                    dns_server: "8.8.8.8:53".parse().expect("valid socket addr"),
                    encoding: "base32".into(),
                    query_type: "TXT".into(),
                },
                TransportKind::Udp,
            ),
            (
                TransportCamouflage::Icmp {
                    peer_addr: "203.0.113.1".parse().expect("valid ip"),
                    identifier: 1,
                    mtu: 1400,
                },
                TransportKind::Udp,
            ),
        ]
    }

    /// The classifier decides the transport for EVERY variant — the table
    /// above is the contract, and a variant missing from it fails here.
    #[test]
    fn camouflage_transport_classifies_every_variant() {
        for (camouflage, expected) in every_variant_with_its_transport() {
            assert_eq!(
                camouflage_transport(&camouflage),
                expected,
                "wrong transport for camouflage {}",
                camouflage.label()
            );
        }
    }

    fn endpoint_config(camouflage: TransportCamouflage, transport: TransportKind) -> MirageEndpointConfig {
        MirageEndpointConfig {
            transport,
            auth: AuthMode::Blake3,
            camouflage,
            byte_cipher: None,
            byte_cipher_mode: None,
        }
    }

    fn raw_udp_camouflage() -> TransportCamouflage {
        TransportCamouflage::RawUdp {
            bind_addr: "0.0.0.0:0".parse().expect("valid socket addr"),
        }
    }

    /// A UDP camouflage must put a DATAGRAM on the wire — never a TCP
    /// connection.
    ///
    /// The listener is a UDP socket on an ephemeral loopback port; nothing
    /// listens on TCP for that port, so a TCP dial could not even reach
    /// the handshake. The datagram that arrives is the V9 `ClientHello`.
    #[tokio::test]
    async fn udp_camouflage_dials_over_datagrams_not_tcp() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind ephemeral udp port");
        let addr = sock.local_addr().expect("local_addr of the bound udp socket");
        let (tx, rx) = tokio::sync::oneshot::channel::<usize>();
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let read = sock.recv(&mut buf).await.unwrap_or(0);
            let _ = tx.send(read);
        });

        // `transport: tcp` on purpose — the camouflage decides, not the config.
        let proto = EndpointProtocol::new(
            endpoint_config(raw_udp_camouflage(), TransportKind::Tcp),
            mirage_core::config::TcpProtocolId::Mirage,
            b"mesh".to_vec(),
        );
        let dial = tokio::spawn(async move {
            let _ = proto
                .connect(addr, &[7u8; 32], "", CamouflageMode::Raw)
                .await;
        });

        let read = tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .expect("the client must put a datagram on the wire")
            .expect("the oneshot sender must not be dropped");
        dial.abort();
        let _ = server.await;

        assert!(read > 0, "the V9 client hello must arrive as a non-empty datagram");
    }

    /// A TCP camouflage must open a TCP connection — the regression guard
    /// for the fleet's existing TCP-only clients.
    #[tokio::test]
    async fn tcp_camouflage_dials_over_tcp_not_datagrams() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral tcp port");
        let addr = listener.local_addr().expect("local_addr of the bound tcp listener");
        let (tx, rx) = tokio::sync::oneshot::channel::<bool>();
        let server = tokio::spawn(async move {
            let accepted = listener.accept().await.is_ok();
            let _ = tx.send(accepted);
        });

        // `transport: udp` on purpose — the camouflage decides, not the config.
        let proto = EndpointProtocol::new(
            endpoint_config(TransportCamouflage::None, TransportKind::Udp),
            mirage_core::config::TcpProtocolId::Mirage,
            b"mesh".to_vec(),
        );
        let dial = tokio::spawn(async move {
            let _ = proto
                .connect(addr, &[7u8; 32], "", CamouflageMode::Raw)
                .await;
        });

        let accepted = tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .expect("the client must open a TCP connection")
            .expect("the oneshot sender must not be dropped");
        dial.abort();
        let _ = server.await;

        assert!(accepted, "the TCP listener must have accepted the client's connection");
    }

    /// The dispatcher itself must route by camouflage, not by the config's
    /// `transport` field — the same rule the `EndpointProtocol` follows.
    #[tokio::test]
    async fn dispatcher_routes_a_udp_camouflage_to_the_datagram_path() {
        let sock = UdpSocket::bind("127.0.0.1:0").await.expect("bind ephemeral udp port");
        let addr = sock.local_addr().expect("local_addr of the bound udp socket");
        let (tx, rx) = tokio::sync::oneshot::channel::<usize>();
        let server = tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let read = sock.recv(&mut buf).await.unwrap_or(0);
            let _ = tx.send(read);
        });

        let config = endpoint_config(raw_udp_camouflage(), TransportKind::Tcp);
        let client_static_priv = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng).to_bytes();
        let dial = tokio::spawn(async move {
            let _ = run_client_v9_transport_aware(
                &config,
                addr,
                &[7u8; 32],
                &client_static_priv,
                "",
                b"mesh",
                None,
            )
            .await;
        });

        let read = tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .expect("the dispatcher must put a datagram on the wire for a UDP camouflage")
            .expect("the oneshot sender must not be dropped");
        dial.abort();
        let _ = server.await;

        assert!(read > 0, "the V9 client hello must arrive as a non-empty datagram");
    }

    /// A TCP-only camouflage asked to ride the datagram path must fail with
    /// a NAMED configuration error, never a panic and never a silent
    /// fallback to the stream path.
    #[tokio::test]
    async fn tcp_only_camouflage_on_the_datagram_path_is_a_named_error() {
        let config = endpoint_config(TransportCamouflage::None, TransportKind::Udp);
        let err = match crate::modes::driver::run_client_udp_v9(
            &config,
            "127.0.0.1:9".parse().expect("valid socket addr"),
            &[7u8; 32],
            &[9u8; 32],
            "",
            b"mesh",
            None,
        )
        .await
        {
            Ok(_) => panic!("a TCP-only camouflage has no datagram dial"),
            Err(err) => err,
        };
        match err {
            MirageError::Config(msg) => {
                assert!(
                    msg.contains("TCP-only"),
                    "the error must name the mismatch, got: {msg}"
                );
            }
            other => panic!("expected MirageError::Config, got: {other:?}"),
        }
    }

    /// A datagram camouflage asked to ride the stream path must fail with a
    /// NAMED configuration error, never a panic.
    ///
    /// A bound listener keeps the TCP connect itself successful, so what
    /// fails is the camouflage check — not the connect.
    #[tokio::test]
    async fn udp_only_camouflage_on_the_stream_path_is_a_named_error() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral tcp port");
        let addr = listener.local_addr().expect("local_addr of the bound tcp listener");
        let accept = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let config = endpoint_config(raw_udp_camouflage(), TransportKind::Tcp);
        let err = match crate::modes::driver::run_client_tcp_v9(
            &config,
            addr,
            &[7u8; 32],
            &[9u8; 32],
            "",
            b"mesh",
            None,
        )
        .await
        {
            Ok(_) => panic!("a datagram camouflage has no stream dial"),
            Err(err) => err,
        };
        accept.abort();
        match err {
            MirageError::Config(msg) => {
                assert!(
                    msg.contains("UDP-only"),
                    "the error must name the mismatch, got: {msg}"
                );
            }
            other => panic!("expected MirageError::Config, got: {other:?}"),
        }
    }
}
