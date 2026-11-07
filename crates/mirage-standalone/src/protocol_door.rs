//! A protocol door the box holds beside the perimeter.
//!
//! The perimeter speaks Mirage over TCP. The node binder speaks Mirage over
//! UDP. Every other [`Protocol`] is a door of its own: the real protocol,
//! then — except Shadowsocks, which carries the target in its own header —
//! the shared target preamble and a plain TCP dial. WireGuard and AmneziaWG
//! carry that same preamble inside IPv4/UDP. No Mirage handshake runs here.
//!
//! A relay is not one of those doors. It binds the socket the protocol type
//! names — raw ICMP, else UDP, else TCP — reads one preamble, and forwards
//! the following bytes unchanged. It does not speak the protocol.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use mirage_core::mirage::wire::Protocol;
use mirage_protocol::camouflage::{CamouflageLayer, UdpCamouflageLayer};
use mirage_protocol::preamble::read_preamble;
use mirage_protocol::protocols::l3::amneziawg::{self, AwgObfuscation};
use mirage_protocol::protocols::l3::icmp::{IcmpCamouflage, IcmpEcho, IcmpEchoSocket};
use mirage_protocol::protocols::l3::wireguard::{
    datagram_with_payload, payload_of, take_tunn_result, tunn_from_hex, CARRY_CHUNK, Tunn, TunnStep,
};
use mirage_protocol::protocols::l4::quic::QuicCamouflage;
use mirage_protocol::protocols::l5::tls::TlsRealCamouflage;
use mirage_protocol::protocols::l7::dns::{DnsEncoding, DnsQueryType, DnsTunnelCamouflage};
use mirage_protocol::protocols::l7::grpc::GrpcCamouflage;
use mirage_protocol::protocols::l7::http3::Http3Camouflage;
use mirage_protocol::protocols::l7::shadowsocks::{
    CipherKind, Context, ProxyListener, ServerConfig, ServerType,
};
use mirage_protocol::protocols::l7::ssh::SshCamouflage;
use mirage_protocol::protocols::l7::websocket::WebSocketCamouflage;
use mirage_protocol::protocols::l7::webtransport::WebTransportCamouflage;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_util::sync::CancellationToken;

use crate::env::{Face, RelayDoor, RelayTransport};

/// One byte stream after the protocol handshake.
///
/// `AsyncRead` and `AsyncWrite` are both non-auto traits, so a trait object
/// names this one trait and the two stream traits stay its supertraits.
trait DoorStream: AsyncRead + AsyncWrite + Send {}

impl<T> DoorStream for T where T: AsyncRead + AsyncWrite + Send {}

/// A byte stream after the protocol handshake.
type DoorIo = Pin<Box<dyn DoorStream>>;

/// Why a protocol door could not be brought up.
#[derive(Debug, thiserror::Error)]
pub enum DoorError {
    /// The link is not a door this module serves, or the listener did not bind.
    #[error("box: the {protocol} door on port {port} cannot be built: {reason}")]
    CannotBuild {
        /// The protocol the operator named.
        protocol: String,
        /// The port the door was to bind.
        port: u16,
        /// Why it could not be built or bound. Never a key or a password.
        reason: String,
    },
}

/// One door, built and — where the protocol binds a socket — already bound.
pub struct Prepared {
    kind: Kind,
    port: u16,
    label: &'static str,
}

impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("label", &self.label)
            .field("port", &self.port)
            .finish()
    }
}

enum Kind {
    Tcp {
        listener: std::net::TcpListener,
        layer: TcpLayer,
    },
    Quinn {
        endpoint: quinn::Endpoint,
        layer: QuinnLayer,
    },
    Dns(DnsTunnelCamouflage),
    Icmp(IcmpCamouflage),
    Shadowsocks(ServerConfig),
    WireGuard {
        socket: std::net::UdpSocket,
        tunn: Tunn,
    },
    AmneziaWg {
        socket: std::net::UdpSocket,
        tunn: amneziawg::Tunn,
    },
}

enum TcpLayer {
    Tls(TlsRealCamouflage),
    WebSocket(WebSocketCamouflage),
    Ssh(SshCamouflage),
    Grpc(GrpcCamouflage),
}

enum QuinnLayer {
    Quic(QuicCamouflage),
    Http3(Http3Camouflage),
    WebTransport(WebTransportCamouflage),
}

fn bind_to(port: u16) -> SocketAddr {
    SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))
}

fn fail(face: &Face, reason: String) -> DoorError {
    DoorError::CannotBuild {
        protocol: face.protocol.label().to_owned(),
        port: face.port,
        reason,
    }
}

fn hold_tcp(face: &Face) -> Result<std::net::TcpListener, DoorError> {
    let listener = std::net::TcpListener::bind(bind_to(face.port)).map_err(|e| fail(face, e.to_string()))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| fail(face, e.to_string()))?;
    Ok(listener)
}

fn ensure_udp_free(face: &Face) -> Result<(), DoorError> {
    let _socket = std::net::UdpSocket::bind(bind_to(face.port)).map_err(|e| fail(face, e.to_string()))?;
    Ok(())
}

fn hold_udp(face: &Face) -> Result<std::net::UdpSocket, DoorError> {
    let socket = std::net::UdpSocket::bind(bind_to(face.port)).map_err(|e| fail(face, e.to_string()))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| fail(face, e.to_string()))?;
    Ok(socket)
}

/// Build and bind every protocol door.
///
/// A port that cannot be bound fails here, before the box reports itself up.
/// ICMP has no port; its raw socket opens when the first peer arrives.
pub fn prepare(doors: &[Face]) -> Result<Vec<Prepared>, DoorError> {
    doors.iter().map(prepare_one).collect()
}

fn prepare_one(face: &Face) -> Result<Prepared, DoorError> {
    let port = face.port;
    let label = face.protocol.label();
    let kind = match &face.protocol {
        Protocol::Mirage { .. } => {
            return Err(fail(face, "mirage is not a protocol door".to_owned()));
        }
        Protocol::Tls { sni, alpn } => {
            if sni.is_empty() {
                return Err(fail(face, "tls needs an sni".to_owned()));
            }
            let layer = TlsRealCamouflage::new(sni.clone(), alpn.clone(), None, None)
                .map_err(|e| fail(face, e.to_string()))?;
            Kind::Tcp {
                listener: hold_tcp(face)?,
                layer: TcpLayer::Tls(layer),
            }
        }
        Protocol::WebSocket { path, host } => Kind::Tcp {
            listener: hold_tcp(face)?,
            layer: TcpLayer::WebSocket(WebSocketCamouflage::new(path.clone(), host.clone())),
        },
        Protocol::Ssh {
            ssh_user,
            ssh_host_key,
            ssh_private_key,
            ssh_password,
            forward_host,
            forward_port,
        } => Kind::Tcp {
            listener: hold_tcp(face)?,
            layer: TcpLayer::Ssh(SshCamouflage {
                ssh_user: ssh_user.clone(),
                ssh_host_key: ssh_host_key.clone(),
                ssh_private_key: ssh_private_key.clone(),
                ssh_password: ssh_password.clone(),
                forward_host: forward_host.clone(),
                forward_port: *forward_port,
            }),
        },
        Protocol::Grpc {
            service_name,
            method_name,
            authority,
            use_tls,
        } => Kind::Tcp {
            listener: hold_tcp(face)?,
            layer: TcpLayer::Grpc(GrpcCamouflage {
                service_name: service_name.clone(),
                method_name: method_name.clone(),
                authority: authority.clone(),
                use_tls: *use_tls,
            }),
        },
        Protocol::Quic { alpn } => {
            let layer = QuicCamouflage::new(alpn.clone()).map_err(|e| fail(face, e.to_string()))?;
            let endpoint = layer
                .bind_endpoint(bind_to(port))
                .map_err(|e| fail(face, e.to_string()))?;
            Kind::Quinn {
                endpoint,
                layer: QuinnLayer::Quic(layer),
            }
        }
        Protocol::Http3 {
            authority,
            tunnel_path,
            alpn,
        } => {
            let layer = Http3Camouflage::new(authority.clone(), tunnel_path.clone(), alpn.clone())
                .map_err(|e| fail(face, e.to_string()))?;
            let endpoint = layer
                .bind_endpoint(bind_to(port))
                .map_err(|e| fail(face, e.to_string()))?;
            Kind::Quinn {
                endpoint,
                layer: QuinnLayer::Http3(layer),
            }
        }
        Protocol::WebTransport { path, authority } => {
            let layer = WebTransportCamouflage::new(path.clone(), authority.clone())
                .map_err(|e| fail(face, e.to_string()))?;
            let endpoint = layer
                .bind_endpoint(bind_to(port))
                .map_err(|e| fail(face, e.to_string()))?;
            Kind::Quinn {
                endpoint,
                layer: QuinnLayer::WebTransport(layer),
            }
        }
        Protocol::Dns {
            domain,
            encoding,
            query_type,
            ..
        } => {
            ensure_udp_free(face)?;
            let encoding = DnsEncoding::from_name(encoding).map_err(|reason| fail(face, reason))?;
            let query_type = DnsQueryType::from_name(query_type).map_err(|reason| fail(face, reason))?;
            Kind::Dns(DnsTunnelCamouflage::new(domain.clone(), encoding, query_type))
        }
        Protocol::Icmp {
            peer_addr,
            identifier,
            mtu,
        } => Kind::Icmp(IcmpCamouflage::new(*peer_addr, *identifier, *mtu)),
        Protocol::Shadowsocks { method, password } => {
            let listener = hold_tcp(face)?;
            drop(listener);
            let cipher = CipherKind::from_str(method)
                .map_err(|_| fail(face, "shadowsocks method was refused".to_owned()))?;
            let config = ServerConfig::new(bind_to(port), password.clone(), cipher)
                .map_err(|_| fail(face, "shadowsocks config was refused".to_owned()))?;
            Kind::Shadowsocks(config)
        }
        Protocol::WireGuard {
            static_private_hex,
            peer_public_hex,
            preshared_key_hex,
            ..
        } => {
            let tunn = tunn_from_hex(
                static_private_hex,
                peer_public_hex,
                preshared_key_hex.as_deref(),
                0,
            )
            .map_err(|reason| fail(face, reason))?;
            Kind::WireGuard {
                socket: hold_udp(face)?,
                tunn,
            }
        }
        Protocol::AmneziaWg {
            static_private_hex,
            peer_public_hex,
            preshared_key_hex,
            jc,
            jmin,
            jmax,
            s1,
            s2,
            s3,
            s4,
            h1,
            h2,
            h3,
            h4,
            ..
        } => {
            let tunn = amneziawg::tunn_from_hex(
                static_private_hex,
                peer_public_hex,
                preshared_key_hex.as_deref(),
                &AwgObfuscation {
                    jc: *jc,
                    jmin: *jmin,
                    jmax: *jmax,
                    s1: *s1,
                    s2: *s2,
                    s3: *s3,
                    s4: *s4,
                    h1: h1.clone(),
                    h2: h2.clone(),
                    h3: h3.clone(),
                    h4: h4.clone(),
                },
                0,
            )
            .map_err(|reason| fail(face, reason))?;
            Kind::AmneziaWg {
                socket: hold_udp(face)?,
                tunn,
            }
        }
    };
    Ok(Prepared { kind, port, label })
}

/// Serve every prepared door until `cancel` fires.
pub async fn serve(prepared: Vec<Prepared>, cancel: CancellationToken) {
    let mut tasks = Vec::with_capacity(prepared.len());
    for door in prepared {
        let cancel = cancel.clone();
        tasks.push(tokio::spawn(async move {
            serve_one(door, cancel).await;
        }));
    }
    cancel.cancelled().await;
    for task in tasks {
        task.abort();
    }
}

async fn serve_one(door: Prepared, cancel: CancellationToken) {
    let Prepared { kind, port, label } = door;
    match kind {
        Kind::Tcp { listener, layer } => serve_tcp(listener, layer, port, label, cancel).await,
        Kind::Quinn { endpoint, layer } => serve_quinn(endpoint, layer, port, label, cancel).await,
        Kind::Dns(layer) => serve_dns(layer, port, label, cancel).await,
        Kind::Icmp(layer) => serve_icmp(layer, port, label, cancel).await,
        Kind::Shadowsocks(config) => serve_shadowsocks(config, port, label, cancel).await,
        Kind::WireGuard { socket, tunn } => serve_wireguard(socket, tunn, port, label, cancel).await,
        Kind::AmneziaWg { socket, tunn } => serve_amneziawg(socket, tunn, port, label, cancel).await,
    }
}

fn up(label: &str, port: u16) {
    tracing::info!("box: protocol up ({label}) port={port}");
}

async fn serve_tcp(
    listener: std::net::TcpListener,
    layer: TcpLayer,
    port: u16,
    label: &'static str,
    cancel: CancellationToken,
) {
    up(label, port);
    let listener = match tokio::net::TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!(error = %e, "box: protocol door listen failed");
            return;
        }
    };
    let layer = Arc::new(layer);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        let layer = Arc::clone(&layer);
                        tokio::spawn(async move {
                            if let Ok(Some(inner)) = accept_tcp(layer.as_ref(), stream).await {
                                relay_preamble(inner).await;
                            }
                        });
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

async fn accept_tcp(layer: &TcpLayer, stream: TcpStream) -> Result<Option<DoorIo>, ()> {
    match layer {
        TcpLayer::Tls(layer) => match layer.wrap_server(stream).await {
            Ok(Some(inner)) => Ok(Some(Box::pin(inner))),
            Ok(None) => Ok(None),
            Err(_) => Err(()),
        },
        TcpLayer::WebSocket(layer) => match layer.wrap_server(stream).await {
            Ok(Some(inner)) => Ok(Some(Box::pin(inner))),
            Ok(None) => Ok(None),
            Err(_) => Err(()),
        },
        TcpLayer::Ssh(layer) => match layer.wrap_server(stream).await {
            Ok(Some(inner)) => Ok(Some(Box::pin(inner))),
            Ok(None) => Ok(None),
            Err(_) => Err(()),
        },
        TcpLayer::Grpc(layer) => match layer.wrap_server(stream).await {
            Ok(Some(inner)) => Ok(Some(Box::pin(inner))),
            Ok(None) => Ok(None),
            Err(_) => Err(()),
        },
    }
}

async fn serve_quinn(
    endpoint: quinn::Endpoint,
    layer: QuinnLayer,
    port: u16,
    label: &'static str,
    cancel: CancellationToken,
) {
    up(label, port);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = accept_quinn(&layer, &endpoint) => {
                match accepted {
                    Ok(stream) => {
                        tokio::spawn(async move {
                            relay_preamble(stream).await;
                        });
                    }
                    Err(()) => {
                        if cancel.is_cancelled() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

async fn accept_quinn(layer: &QuinnLayer, endpoint: &quinn::Endpoint) -> Result<DoorIo, ()> {
    match layer {
        QuinnLayer::Quic(layer) => {
            let (stream, _) = layer.accept_one(endpoint).await.map_err(|_| ())?;
            Ok(Box::pin(stream))
        }
        QuinnLayer::Http3(layer) => {
            let (stream, _) = layer.accept_one(endpoint).await.map_err(|_| ())?;
            Ok(Box::pin(stream))
        }
        QuinnLayer::WebTransport(layer) => {
            let (stream, _) = layer.accept_one(endpoint).await.map_err(|_| ())?;
            Ok(Box::pin(stream))
        }
    }
}

async fn serve_dns(
    layer: DnsTunnelCamouflage,
    port: u16,
    label: &'static str,
    cancel: CancellationToken,
) {
    up(label, port);
    let bind = bind_to(port);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = layer.accept_server(bind) => {
                match accepted {
                    Ok((stream, _)) => relay_preamble(Box::pin(stream)).await,
                    Err(e) => {
                        tracing::warn!(error = %e, "box: dns door accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

async fn serve_icmp(
    layer: IcmpCamouflage,
    port: u16,
    label: &'static str,
    cancel: CancellationToken,
) {
    up(label, port);
    let bind = bind_to(port);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = layer.accept_server(bind) => {
                match accepted {
                    Ok((stream, _)) => {
                        // ICMP has no EOF. A preamble that never finishes
                        // would hold the only accept forever.
                        let _ = tokio::time::timeout(
                            Duration::from_secs(25),
                            relay_preamble(Box::pin(stream)),
                        )
                        .await;
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "box: icmp door accept failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

async fn serve_shadowsocks(
    config: ServerConfig,
    port: u16,
    label: &'static str,
    cancel: CancellationToken,
) {
    up(label, port);
    let context = Context::new_shared(ServerType::Server);
    let listener = match ProxyListener::bind(context, &config).await {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!(error = %e, "box: shadowsocks door listen failed");
            return;
        }
    };
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((mut stream, _)) => {
                        tokio::spawn(async move {
                            let addr = match stream.handshake().await {
                                Ok(addr) => addr,
                                Err(_) => return,
                            };
                            let host = addr.host();
                            let target_port = addr.port();
                            let mut tcp = match TcpStream::connect((host.as_str(), target_port)).await {
                                Ok(tcp) => tcp,
                                Err(_) => return,
                            };
                            let mut remote = Box::pin(stream);
                            let _ = tokio::io::copy_bidirectional(&mut remote, &mut tcp).await;
                        });
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

async fn serve_wireguard(
    socket: std::net::UdpSocket,
    mut tunn: Tunn,
    port: u16,
    label: &'static str,
    cancel: CancellationToken,
) {
    up(label, port);
    let socket = match tokio::net::UdpSocket::from_std(socket) {
        Ok(socket) => socket,
        Err(e) => {
            tracing::error!(error = %e, "box: wireguard door listen failed");
            return;
        }
    };
    let mut buf = [0u8; 2048];
    let mut scratch = [0u8; 2048];
    let mut carry = TcpCarry::new();
    let mut peer_addr: Option<SocketAddr> = None;
    loop {
        match next_tunnel_event(&cancel, &socket, &mut buf, &mut carry.tcp).await {
            NetEvent::Cancel => break,
            NetEvent::Idle => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            NetEvent::FromTcp(chunk) => {
                if chunk.is_empty() {
                    carry.tcp = None;
                    continue;
                }
                let Some(peer) = peer_addr else { continue };
                let datagram = datagram_with_payload(&chunk);
                if let TunnStep::Network(out) =
                    take_tunn_result(tunn.encapsulate(&datagram, &mut scratch))
                {
                    let _ = socket.send_to(&out, peer).await;
                }
            }
            NetEvent::Recv { n, peer } => {
                peer_addr = Some(peer);
                let packet = buf[..n].to_vec();
                let inners = pump_wireguard(&mut tunn, &socket, peer, &packet, &mut scratch).await;
                if !carry.feed(inners).await {
                    carry.reset();
                }
            }
        }
    }
}

async fn pump_wireguard(
    tunn: &mut Tunn,
    socket: &tokio::net::UdpSocket,
    peer: SocketAddr,
    packet: &[u8],
    scratch: &mut [u8],
) -> Vec<Vec<u8>> {
    let mut inners = Vec::new();
    let mut datagram = packet.to_vec();
    loop {
        let step = take_tunn_result(tunn.decapsulate(
            if datagram.is_empty() {
                None
            } else {
                Some(peer.ip())
            },
            &datagram,
            scratch,
        ));
        datagram.clear();
        match step {
            TunnStep::Network(pkt) => {
                let _ = socket.send_to(&pkt, peer).await;
            }
            TunnStep::Inner(pkt) => inners.push(pkt),
            TunnStep::Done | TunnStep::Failed => break,
        }
    }
    inners
}

async fn serve_amneziawg(
    socket: std::net::UdpSocket,
    mut tunn: amneziawg::Tunn,
    port: u16,
    label: &'static str,
    cancel: CancellationToken,
) {
    up(label, port);
    let socket = match tokio::net::UdpSocket::from_std(socket) {
        Ok(socket) => socket,
        Err(e) => {
            tracing::error!(error = %e, "box: amneziawg door listen failed");
            return;
        }
    };
    let mut buf = vec![0u8; 65535];
    let mut scratch = vec![0u8; 65535];
    let mut carry = TcpCarry::new();
    let mut peer_addr: Option<SocketAddr> = None;
    loop {
        match next_tunnel_event(&cancel, &socket, &mut buf, &mut carry.tcp).await {
            NetEvent::Cancel => break,
            NetEvent::Idle => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            NetEvent::FromTcp(chunk) => {
                if chunk.is_empty() {
                    carry.tcp = None;
                    continue;
                }
                let Some(peer) = peer_addr else { continue };
                let datagram = datagram_with_payload(&chunk);
                let sent = amneziawg::take_tunn_result(tunn.encapsulate(&datagram, &mut scratch));
                send_queued_awg(&mut tunn, &socket, peer).await;
                if let amneziawg::TunnStep::Network(out) = sent {
                    let _ = socket.send_to(&out, peer).await;
                }
            }
            NetEvent::Recv { n, peer } => {
                peer_addr = Some(peer);
                let packet = buf[..n].to_vec();
                let inners =
                    pump_amneziawg(&mut tunn, &socket, peer, &packet, &mut scratch).await;
                if !carry.feed(inners).await {
                    carry.reset();
                }
            }
        }
    }
}

async fn pump_amneziawg(
    tunn: &mut amneziawg::Tunn,
    socket: &tokio::net::UdpSocket,
    peer: SocketAddr,
    packet: &[u8],
    scratch: &mut [u8],
) -> Vec<Vec<u8>> {
    let mut inners = Vec::new();
    let mut datagram = packet.to_vec();
    loop {
        let step = amneziawg::take_tunn_result(tunn.decapsulate(
            if datagram.is_empty() {
                None
            } else {
                Some(peer.ip())
            },
            &datagram,
            scratch,
        ));
        datagram.clear();
        send_queued_awg(tunn, socket, peer).await;
        match step {
            amneziawg::TunnStep::Network(pkt) => {
                let _ = socket.send_to(&pkt, peer).await;
            }
            amneziawg::TunnStep::Inner(pkt) => inners.push(pkt),
            amneziawg::TunnStep::Done | amneziawg::TunnStep::Failed => break,
        }
    }
    inners
}

async fn send_queued_awg(tunn: &mut amneziawg::Tunn, socket: &tokio::net::UdpSocket, peer: SocketAddr) {
    while let Some(pkt) = tunn.poll_outgoing_packet() {
        let _ = socket.send_to(&pkt, peer).await;
    }
}

/// Quiet time after which a door that never signals EOF releases its socket.
///
/// DNS connects its only listener to the first client and then copies until
/// EOF, which a DNS tunnel does not send. The same copy serves ICMP. Four
/// seconds with no byte either way drops the splice and the accept loop
/// binds again. A byte in either direction starts the quiet time over.
const DOOR_IDLE: Duration = Duration::from_secs(4);

async fn relay_preamble(mut stream: DoorIo) {
    let (host, port) = match read_preamble(&mut stream).await {
        Ok(target) => target,
        Err(_) => return,
    };
    let mut tcp = match TcpStream::connect((host.as_str(), port)).await {
        Ok(tcp) => tcp,
        Err(_) => return,
    };
    let _ = copy_until_idle(&mut stream, &mut tcp, DOOR_IDLE).await;
}

async fn copy_until_idle<A, B>(a: &mut A, b: &mut B, idle: Duration) -> std::io::Result<()>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let mut from_a = [0u8; 8192];
    let mut from_b = [0u8; 8192];
    let mut deadline = tokio::time::Instant::now() + idle;
    loop {
        let left = deadline.saturating_duration_since(tokio::time::Instant::now());
        if left.is_zero() {
            return Ok(());
        }
        tokio::select! {
            _ = tokio::time::sleep(left) => return Ok(()),
            read = a.read(&mut from_a) => {
                let n = read?;
                if n == 0 {
                    return Ok(());
                }
                b.write_all(&from_a[..n]).await?;
                b.flush().await?;
                deadline = tokio::time::Instant::now() + idle;
            }
            read = b.read(&mut from_b) => {
                let n = read?;
                if n == 0 {
                    return Ok(());
                }
                a.write_all(&from_b[..n]).await?;
                a.flush().await?;
                deadline = tokio::time::Instant::now() + idle;
            }
        }
    }
}

enum NetEvent {
    Cancel,
    Idle,
    Recv { n: usize, peer: SocketAddr },
    FromTcp(Vec<u8>),
}

async fn next_tunnel_event(
    cancel: &CancellationToken,
    socket: &tokio::net::UdpSocket,
    buf: &mut [u8],
    tcp: &mut Option<TcpStream>,
) -> NetEvent {
    if let Some(stream) = tcp.as_mut() {
        let mut chunk = vec![0u8; CARRY_CHUNK];
        tokio::select! {
            _ = cancel.cancelled() => NetEvent::Cancel,
            recvd = socket.recv_from(buf) => match recvd {
                Ok((n, peer)) => NetEvent::Recv { n, peer },
                Err(_) => NetEvent::Idle,
            },
            read = stream.read(&mut chunk) => match read {
                Ok(0) | Err(_) => NetEvent::FromTcp(Vec::new()),
                Ok(n) => {
                    chunk.truncate(n);
                    NetEvent::FromTcp(chunk)
                }
            },
        }
    } else {
        tokio::select! {
            _ = cancel.cancelled() => NetEvent::Cancel,
            recvd = socket.recv_from(buf) => match recvd {
                Ok((n, peer)) => NetEvent::Recv { n, peer },
                Err(_) => NetEvent::Idle,
            },
        }
    }
}

struct TcpCarry {
    pending: Vec<u8>,
    tcp: Option<TcpStream>,
}

impl TcpCarry {
    fn new() -> Self {
        Self {
            pending: Vec::new(),
            tcp: None,
        }
    }

    fn reset(&mut self) {
        self.pending.clear();
        self.tcp = None;
    }

    async fn feed(&mut self, inners: Vec<Vec<u8>>) -> bool {
        for packet in inners {
            let Some(payload) = payload_of(&packet) else {
                continue;
            };
            if !self.push(payload).await {
                return false;
            }
        }
        true
    }

    async fn push(&mut self, payload: &[u8]) -> bool {
        if let Some(tcp) = self.tcp.as_mut() {
            return tcp.write_all(payload).await.is_ok() && tcp.flush().await.is_ok();
        }
        self.pending.extend_from_slice(payload);
        match take_preamble(&self.pending) {
            PreambleAt::NeedMore => true,
            PreambleAt::Bad => false,
            PreambleAt::Ready { host, port, consumed } => {
                let rest = self.pending.split_off(consumed);
                self.pending.clear();
                match TcpStream::connect((host.as_str(), port)).await {
                    Ok(mut tcp) => {
                        tracing::info!(%host, port, "box: tunnel door opened");
                        if !rest.is_empty()
                            && (tcp.write_all(&rest).await.is_err() || tcp.flush().await.is_err())
                        {
                            return false;
                        }
                        self.tcp = Some(tcp);
                        true
                    }
                    Err(error) => {
                        tracing::warn!(%error, "box: tunnel door could not reach the target");
                        false
                    }
                }
            }
        }
    }
}

enum PreambleAt {
    NeedMore,
    Bad,
    Ready { host: String, port: u16, consumed: usize },
}

fn take_preamble(buf: &[u8]) -> PreambleAt {
    if buf.is_empty() {
        return PreambleAt::NeedMore;
    }
    let len = buf[0] as usize;
    if len == 0 || len > 255 {
        return PreambleAt::Bad;
    }
    let need = 1 + len + 2;
    if buf.len() < need {
        return PreambleAt::NeedMore;
    }
    let Ok(host) = std::str::from_utf8(&buf[1..1 + len]) else {
        return PreambleAt::Bad;
    };
    if host.is_empty() {
        return PreambleAt::Bad;
    }
    let port = u16::from_be_bytes([buf[1 + len], buf[2 + len]]);
    if port == 0 {
        return PreambleAt::Bad;
    }
    PreambleAt::Ready {
        host: host.to_owned(),
        port,
        consumed: need,
    }
}

/// Quiet time for a UDP or ICMP relay flow. Not the terminator's 4s idle.
const RELAY_FLOW_IDLE: Duration = Duration::from_secs(120);

/// One relay, already bound. ICMP holds its one raw socket.
pub struct PreparedRelay {
    kind: RelayKind,
    port: u16,
}

impl std::fmt::Debug for PreparedRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let transport = match self.kind {
            RelayKind::Tcp(_) => "tcp",
            RelayKind::Udp(_) => "udp",
            RelayKind::Icmp(_) => "icmp",
        };
        f.debug_struct("PreparedRelay")
            .field("transport", &transport)
            .field("port", &self.port)
            .finish()
    }
}

enum RelayKind {
    Tcp(std::net::TcpListener),
    Udp(std::net::UdpSocket),
    Icmp(IcmpEchoSocket),
}

fn relay_fail(port: u16, reason: String) -> DoorError {
    DoorError::CannotBuild {
        protocol: "relay".to_owned(),
        port,
        reason,
    }
}

fn hold_relay_tcp(port: u16) -> Result<std::net::TcpListener, DoorError> {
    let listener =
        std::net::TcpListener::bind(bind_to(port)).map_err(|e| relay_fail(port, e.to_string()))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| relay_fail(port, e.to_string()))?;
    Ok(listener)
}

fn hold_relay_udp(port: u16) -> Result<std::net::UdpSocket, DoorError> {
    let socket =
        std::net::UdpSocket::bind(bind_to(port)).map_err(|e| relay_fail(port, e.to_string()))?;
    socket
        .set_nonblocking(true)
        .map_err(|e| relay_fail(port, e.to_string()))?;
    Ok(socket)
}

/// Bind every relay before the box reports itself up.
///
/// A port that cannot be bound, or an ICMP socket that cannot be opened,
/// fails here. ICMP opens one raw socket and keeps it.
pub fn prepare_relays(relays: &[RelayDoor]) -> Result<Vec<PreparedRelay>, DoorError> {
    relays.iter().map(prepare_relay).collect()
}

fn prepare_relay(door: &RelayDoor) -> Result<PreparedRelay, DoorError> {
    let kind = match door.transport {
        RelayTransport::Tcp => RelayKind::Tcp(hold_relay_tcp(door.port)?),
        RelayTransport::Udp => RelayKind::Udp(hold_relay_udp(door.port)?),
        RelayTransport::Icmp => RelayKind::Icmp(
            IcmpEchoSocket::open().map_err(|e| relay_fail(door.port, e.to_string()))?,
        ),
    };
    Ok(PreparedRelay {
        kind,
        port: door.port,
    })
}

/// Serve every prepared relay until `cancel` fires.
pub async fn serve_relays(prepared: Vec<PreparedRelay>, cancel: CancellationToken) {
    let mut tasks = Vec::with_capacity(prepared.len());
    for door in prepared {
        let cancel = cancel.clone();
        tasks.push(tokio::spawn(async move {
            serve_relay(door, cancel).await;
        }));
    }
    cancel.cancelled().await;
    for task in tasks {
        task.abort();
    }
}

async fn serve_relay(door: PreparedRelay, cancel: CancellationToken) {
    let PreparedRelay { kind, port } = door;
    match kind {
        RelayKind::Tcp(listener) => serve_tcp_relay(listener, port, cancel).await,
        RelayKind::Udp(socket) => serve_udp_relay(socket, port, cancel).await,
        RelayKind::Icmp(socket) => serve_icmp_relay(socket, port, cancel).await,
    }
}

async fn serve_tcp_relay(
    listener: std::net::TcpListener,
    port: u16,
    cancel: CancellationToken,
) {
    let listener = match tokio::net::TcpListener::from_std(listener) {
        Ok(listener) => listener,
        Err(e) => {
            tracing::error!(error = %e, "box: relay listen failed");
            return;
        }
    };
    tracing::info!("box: relay up (tcp) port={port}");
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                match accepted {
                    Ok((mut stream, _)) => {
                        tokio::spawn(async move {
                            let (host, dest_port) = match read_preamble(&mut stream).await {
                                Ok(target) => target,
                                Err(_) => {
                                    tracing::warn!("box: relay preamble failed");
                                    return;
                                }
                            };
                            let mut upstream = match TcpStream::connect((host.as_str(), dest_port)).await {
                                Ok(upstream) => upstream,
                                Err(e) => {
                                    tracing::warn!(error = %e, "box: relay connect failed");
                                    return;
                                }
                            };
                            tracing::info!("box: relay forwarded host={host} port={dest_port}");
                            let _ = tokio::io::copy_bidirectional(&mut stream, &mut upstream).await;
                        });
                    }
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

struct UdpRelayFlow {
    upstream: Arc<tokio::net::UdpSocket>,
    terminator: SocketAddr,
    last: Arc<std::sync::Mutex<Instant>>,
    copy: tokio::task::JoinHandle<()>,
}

async fn serve_udp_relay(socket: std::net::UdpSocket, port: u16, cancel: CancellationToken) {
    let socket = match tokio::net::UdpSocket::from_std(socket) {
        Ok(socket) => Arc::new(socket),
        Err(e) => {
            tracing::error!(error = %e, "box: relay listen failed");
            return;
        }
    };
    tracing::info!("box: relay up (udp) port={port}");
    let mut flows: HashMap<SocketAddr, UdpRelayFlow> = HashMap::new();
    let mut buf = vec![0u8; 65535];
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep(Duration::from_secs(1)) => {
                expire_udp(&mut flows);
            }
            recvd = socket.recv_from(&mut buf) => {
                let (n, client) = match recvd {
                    Ok(pair) => pair,
                    Err(_) => {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    }
                };
                let datagram = buf[..n].to_vec();
                if flows.contains_key(&client) {
                    let dead = flows.get(&client).is_some_and(|flow| flow.copy.is_finished());
                    if dead {
                        if let Some(flow) = flows.remove(&client) {
                            flow.copy.abort();
                        }
                    } else if let Some(flow) = flows.get(&client) {
                        touch(&flow.last);
                        let upstream = Arc::clone(&flow.upstream);
                        let dest = flow.terminator;
                        // Unconnected on purpose: `send_to` of the whole
                        // datagram. A connected UDP socket rejects `send_to`
                        // on Windows.
                        if upstream.send_to(&datagram, dest).await.is_err() {
                            tracing::warn!("box: relay send failed");
                        }
                    }
                } else if let Some((host, dest_port)) = exact_preamble(&datagram).await {
                    match udp_upstream(&host, dest_port).await {
                        Ok((upstream, dest)) => {
                            tracing::info!("box: relay forwarded host={host} port={dest_port}");
                            let last = Arc::new(std::sync::Mutex::new(Instant::now()));
                            let copy_last = Arc::clone(&last);
                            let copy_up = Arc::clone(&upstream);
                            let listen = Arc::clone(&socket);
                            let copy = tokio::spawn(async move {
                                let mut rbuf = vec![0u8; 65535];
                                loop {
                                    match copy_up.recv_from(&mut rbuf).await {
                                        Ok((m, from)) if from == dest => {
                                            touch(&copy_last);
                                            if listen.send_to(&rbuf[..m], client).await.is_err() {
                                                break;
                                            }
                                        }
                                        Ok(_) => continue,
                                        Err(_) => break,
                                    }
                                }
                            });
                            flows.insert(
                                client,
                                UdpRelayFlow {
                                    upstream,
                                    terminator: dest,
                                    last,
                                    copy,
                                },
                            );
                        }
                        Err(e) => {
                            tracing::warn!(error = %e, "box: relay connect failed");
                        }
                    }
                } else {
                    tracing::warn!("box: relay preamble failed");
                }
                expire_udp(&mut flows);
            }
        }
    }
    for (_, flow) in flows {
        flow.copy.abort();
    }
}

fn touch(last: &std::sync::Mutex<Instant>) {
    if let Ok(mut seen) = last.lock() {
        *seen = Instant::now();
    }
}

fn expire_udp(flows: &mut HashMap<SocketAddr, UdpRelayFlow>) {
    flows.retain(|_, flow| {
        let fresh = match flow.last.lock() {
            Ok(seen) => Instant::now().saturating_duration_since(*seen) < RELAY_FLOW_IDLE,
            Err(_) => false,
        };
        if !fresh {
            flow.copy.abort();
        }
        fresh
    });
}

async fn udp_upstream(
    host: &str,
    port: u16,
) -> std::io::Result<(Arc<tokio::net::UdpSocket>, SocketAddr)> {
    let addrs = tokio::net::lookup_host((host, port)).await?;
    let Some(addr) = addrs.into_iter().find(|addr| addr.is_ipv4()) else {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "relay target has no ipv4 address",
        ));
    };
    let socket = tokio::net::UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    Ok((Arc::new(socket), addr))
}

struct IcmpRelayFlow {
    client: IpAddr,
    terminator: IpAddr,
    identifier: u16,
    last: Instant,
}

async fn serve_icmp_relay(socket: IcmpEchoSocket, port: u16, cancel: CancellationToken) {
    tracing::info!("box: relay up (icmp) port={port}");
    let socket = Arc::new(std::sync::Mutex::new(socket));
    let mut flows: Vec<IcmpRelayFlow> = Vec::new();
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            recvd = recv_icmp(&socket) => {
                match recvd {
                    Ok(Some(echo)) => on_icmp(&socket, &mut flows, echo).await,
                    Ok(None) => expire_icmp(&mut flows),
                    Err(e) if icmp_timeout(&e) => expire_icmp(&mut flows),
                    Err(e) => {
                        tracing::warn!(error = %e, "box: relay recv failed");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
}

fn icmp_timeout(err: &std::io::Error) -> bool {
    matches!(
        err.kind(),
        std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::WouldBlock
            | std::io::ErrorKind::Interrupted
    )
}

async fn recv_icmp(
    socket: &Arc<std::sync::Mutex<IcmpEchoSocket>>,
) -> std::io::Result<Option<IcmpEcho>> {
    let socket = Arc::clone(socket);
    match tokio::task::spawn_blocking(move || {
        let guard = socket
            .lock()
            .map_err(|_| std::io::Error::other("icmp relay socket locked"))?;
        guard.recv_echo()
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(std::io::Error::other("icmp relay recv stopped")),
    }
}

async fn send_icmp(
    socket: &Arc<std::sync::Mutex<IcmpEchoSocket>>,
    dst: IpAddr,
    identifier: u16,
    sequence: u16,
    request: bool,
    payload: Vec<u8>,
) {
    let socket = Arc::clone(socket);
    let sent = tokio::task::spawn_blocking(move || {
        let guard = socket
            .lock()
            .map_err(|_| std::io::Error::other("icmp relay socket locked"))?;
        guard.send_echo(dst, identifier, sequence, request, &payload)
    })
    .await;
    match sent {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!(error = %e, "box: relay send failed"),
        Err(_) => tracing::warn!("box: relay send failed"),
    }
}

async fn on_icmp(
    socket: &Arc<std::sync::Mutex<IcmpEchoSocket>>,
    flows: &mut Vec<IcmpRelayFlow>,
    echo: IcmpEcho,
) {
    expire_icmp(flows);
    if echo.request {
        if let Some(index) = flows.iter().position(|flow| flow.client == echo.src) {
            let dst = flows[index].terminator;
            flows[index].identifier = echo.identifier;
            flows[index].last = Instant::now();
            send_icmp(
                socket,
                dst,
                echo.identifier,
                echo.sequence,
                true,
                echo.payload,
            )
            .await;
            return;
        }
        // A ping that is not our preamble is not a flow. The raw socket
        // sees every Echo on the host, so a refusal stays quiet.
        let Some((host, dest_port)) = exact_preamble(&echo.payload).await else {
            return;
        };
        let Some(dst) = resolve_v4(&host, dest_port).await else {
            tracing::warn!("box: relay connect failed host={host} port={dest_port}");
            return;
        };
        tracing::info!("box: relay forwarded host={host} port={dest_port}");
        flows.push(IcmpRelayFlow {
            client: echo.src,
            terminator: IpAddr::V4(dst),
            identifier: echo.identifier,
            last: Instant::now(),
        });
        return;
    }
    if let Some(index) = flows.iter().position(|flow| {
        flow.terminator == echo.src && flow.identifier == echo.identifier
    }) {
        let client = flows[index].client;
        flows[index].last = Instant::now();
        send_icmp(
            socket,
            client,
            echo.identifier,
            echo.sequence,
            false,
            echo.payload,
        )
        .await;
    }
}

fn expire_icmp(flows: &mut Vec<IcmpRelayFlow>) {
    let now = Instant::now();
    flows.retain(|flow| now.saturating_duration_since(flow.last) < RELAY_FLOW_IDLE);
}

async fn resolve_v4(host: &str, port: u16) -> Option<Ipv4Addr> {
    let addrs = tokio::net::lookup_host((host, port)).await.ok()?;
    addrs.into_iter().find_map(|addr| match addr.ip() {
        IpAddr::V4(ip) => Some(ip),
        IpAddr::V6(_) => None,
    })
}

/// The datagram is a preamble and nothing else.
///
/// [`read_preamble`] is the layout. A longer datagram is not a handshake,
/// and it is not forwarded.
async fn exact_preamble(bytes: &[u8]) -> Option<(String, u16)> {
    let host_len = usize::from(*bytes.first()?);
    if host_len == 0 || bytes.len() != 1 + host_len + 2 {
        return None;
    }
    let mut cursor = std::io::Cursor::new(bytes);
    read_preamble(&mut cursor).await.ok()
}
