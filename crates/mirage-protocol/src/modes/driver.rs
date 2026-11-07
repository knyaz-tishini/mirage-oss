//! Unified driver functions for the Mirage protocol.
//!
//! These top-level helpers replace the 16 individual old-style protocol structs
//! (MirageProtocol, MirageRealityProtocol, MirageTlsProtocol, …) with a single
//! composable `MirageEndpointConfig` that selects transport, auth strategy, and
//! transport-level camouflage.
//!
//! # Usage (server)
//!
//! ```rust,ignore
//! // TCP: called once per accepted TcpStream
//! match run_server_tcp(&config, &keypair, stream).await? {
//!     Some(tunnel) => { /* dispatch tunnel */ }
//!     None => { /* auth failed — forward to fallback */ }
//! }
//!
//! // UDP: loop — spawn a task per emitted tunnel
//! run_server_udp(&config, &keypair, bind_addr, tunnel_tx).await?;
//! ```

use std::io::{Error as IoError, ErrorKind};
use std::net::SocketAddr;
use std::sync::Mutex;
use std::time::Duration;

use mirage_core::{
    config::{AuthMode, MirageEndpointConfig, TransportCamouflage, TransportKind},
    crypto::{AeadSuite, KeyPair},
    error::MirageError,
};
use tokio::{net::TcpStream, sync::mpsc};

use crate::{
    auth::AuthMode as ProtocolAuthMode,
    core::handshake::ClientAuthContext,
    camouflage::{
        none::NoCamouflage,
        raw_udp::RawUdpCamouflage,
        reality::{RealityClientCamouflage, RealityServerCamouflage},
        xhttp::XhttpCamouflage,
        wireguard::WireGuardCamouflage,
        CamouflageLayer,
        UdpCamouflageLayer,
    },
    protocols::{
        l3::icmp::IcmpCamouflage,
        l4::quic::QuicCamouflage,
        l5::tls::TlsRealCamouflage,
        l7::dns::{DnsEncoding, DnsQueryType, DnsTunnelCamouflage},
        l7::http3::Http3Camouflage,
        l7::websocket::WebSocketCamouflage,
        l7::webtransport::WebTransportCamouflage,
    },
    core::{
        handshake::{
            run_client_handshake, run_server_handshake,
            run_server_handshake_with_auth,
        },
        tunnel::MirageCoreTunnel,
    },
    traits::{TransportInfo, Tunnel},
};

#[cfg(feature = "grpc")]
use crate::protocols::l7::grpc::GrpcCamouflage;
#[cfg(feature = "ssh")]
use crate::protocols::l7::ssh::SshCamouflage;

// ─────────────────────────────────────────────────────────────────────────────
// Client credential type
// ─────────────────────────────────────────────────────────────────────────────

/// Optional credential attached to a V9 client dial.
///
/// When `Some`, the `scheme` byte is placed at `V9ClientHello` byte 92 and a
/// `[2B len BE][token]` frame is written immediately after the 97B hello.
/// When `None` (or when `scheme == 0x00`), the hello is byte-identical to a
/// legacy V9 client — no credential frame follows.
#[derive(Clone, Debug)]
pub struct ClientCredential {
    /// Credential scheme byte (wire position 92 of the ClientHello).
    pub scheme: u8,
    /// Raw credential bytes sent in the `[2B len BE][token]` frame.
    pub token: Vec<u8>,
}

// ─────────────────────────────────────────────────────────────────────────────
// Public API
// ─────────────────────────────────────────────────────────────────────────────

/// Perform the server-side handshake for an accepted TCP stream.
///
/// `mesh_id` — mesh identifier bytes baked into the Blake3 confirm label.
///
/// `allow_legacy_v8` — when `false`, any non-V9 first byte causes the server to
/// send `VERSION_REJECT (0xFF)` and return `Ok(None)`. Set to `true` to preserve
/// the current permissive behaviour (accepts V8 dials).
///
/// Returns `Some(tunnel)` when authentication succeeds, or `None` when the
/// camouflage or Mirage handshake fails (caller should forward to a fallback).
/// Returns `Err` only for unrecoverable I/O errors.
pub async fn run_server_tcp(
    config: &MirageEndpointConfig,
    keypair: &KeyPair,
    stream: TcpStream,
    mesh_id: &[u8],
    allow_legacy_v8: bool,
) -> Result<Option<Box<dyn Tunnel>>, MirageError> {
    let peer_addr = stream.peer_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    let auth = convert_auth(&config.auth);

    match &config.camouflage {
        TransportCamouflage::None => {
            let layer = NoCamouflage;
            let wrapped = match layer.wrap_server(stream).await? {
                Some(s) => s,
                None => return Ok(None),
            };
            handshake_server_stream(wrapped, keypair, &auth, peer_addr, mesh_id, allow_legacy_v8).await
        }
        TransportCamouflage::TlsReal { sni, alpn } => {
            let layer = TlsRealCamouflage::new(sni.clone(), alpn.clone(), None, None)?;
            let wrapped = match layer.wrap_server(stream).await? {
                Some(s) => s,
                None => return Ok(None),
            };
            handshake_server_stream(wrapped, keypair, &auth, peer_addr, mesh_id, allow_legacy_v8).await
        }
        TransportCamouflage::WebSocket { path, host } => {
            let layer = WebSocketCamouflage::new(path.clone(), host.clone());
            let wrapped = match layer.wrap_server(stream).await? {
                Some(s) => s,
                None => return Ok(None),
            };
            handshake_server_stream(wrapped, keypair, &auth, peer_addr, mesh_id, allow_legacy_v8).await
        }
        TransportCamouflage::Xhttp { path, host } => {
            let layer = XhttpCamouflage::new(path.clone(), host.clone());
            let wrapped = match layer.wrap_server(stream).await? {
                Some(s) => s,
                None => return Ok(None),
            };
            handshake_server_stream(wrapped, keypair, &auth, peer_addr, mesh_id, allow_legacy_v8).await
        }
        TransportCamouflage::Reality {
            short_id,
            max_time_diff,
            ..
        } => {
            let layer = RealityServerCamouflage::new(
                keypair.clone(),
                &[short_id.as_str()],
                *max_time_diff as u64,
            )?;
            let wrapped = match layer.wrap_server(stream).await? {
                Some(s) => s,
                None => return Ok(None),
            };
            handshake_server_stream(wrapped, keypair, &auth, peer_addr, mesh_id, allow_legacy_v8).await
        }
        // Raw-socket / UDP-only camouflages are not valid for TCP server.
        TransportCamouflage::Quic { .. }
        | TransportCamouflage::Http3 { .. }
        | TransportCamouflage::Hysteria2 { .. }
        | TransportCamouflage::WireGuard { .. }
        | TransportCamouflage::DnsTunnel { .. }
        | TransportCamouflage::Icmp { .. }
        | TransportCamouflage::WebTransport { .. }
        | TransportCamouflage::RawUdp { .. } => Err(MirageError::Config(
            "run_server_tcp: camouflage type requires raw/UDP socket (use run_server_udp)".into(),
        )),
        // SSH camouflage: wrap the TCP stream in an SSH session (server side).
        TransportCamouflage::Ssh {
            ssh_user,
            ssh_host_key,
            ssh_private_key,
            ssh_password,
            forward_host,
            forward_port,
        } => {
            #[cfg(feature = "ssh")]
            {
                let layer = SshCamouflage {
                    ssh_user: ssh_user.clone(),
                    ssh_host_key: ssh_host_key.clone(),
                    ssh_private_key: ssh_private_key.clone(),
                    ssh_password: ssh_password.clone(),
                    forward_host: forward_host.clone(),
                    forward_port: *forward_port,
                };
                let wrapped = match layer.wrap_server(stream).await? {
                    Some(s) => s,
                    None => return Ok(None),
                };
                handshake_server_stream(wrapped, keypair, &auth, peer_addr, mesh_id, allow_legacy_v8).await
            }
            #[cfg(not(feature = "ssh"))]
            {
                let _ = (ssh_user, ssh_host_key, ssh_private_key, ssh_password, forward_host, forward_port);
                Err(MirageError::Config(
                    "run_server_tcp: SSH camouflage requires the `ssh` feature flag".into(),
                ))
            }
        }
        // gRPC camouflage: carry Mirage frames inside an HTTP/2 streaming RPC (server side).
        TransportCamouflage::Grpc {
            service_name,
            method_name,
            authority,
            use_tls,
        } => {
            #[cfg(feature = "grpc")]
            {
                let layer = GrpcCamouflage {
                    service_name: service_name.clone(),
                    method_name: method_name.clone(),
                    authority: authority.clone(),
                    use_tls: *use_tls,
                };
                let wrapped = match layer.wrap_server(stream).await? {
                    Some(s) => s,
                    None => return Ok(None),
                };
                handshake_server_stream(wrapped, keypair, &auth, peer_addr, mesh_id, allow_legacy_v8).await
            }
            #[cfg(not(feature = "grpc"))]
            {
                let _ = (service_name, method_name, authority, use_tls);
                Err(MirageError::Config(
                    "run_server_tcp: gRPC camouflage requires the `grpc` feature flag".into(),
                ))
            }
        }
    }
}

/// Like [`run_server_tcp`] but threads a `client_auth` closure into the V9
/// server path.
///
/// `client_auth` receives a [`ClientAuthContext`] containing the client's
/// static public key, timestamp, ephemeral key, credential scheme byte, and raw
/// credential bytes. Return `true` to accept, `false` to reject silently.
/// Called BEFORE session keys are derived and BEFORE `ServerHello` is sent.
///
/// `allow_legacy_v8` — when `false`, any non-V9 first byte causes the server to
/// send `VERSION_REJECT (0xFF)` and return `Ok(None)`. Set to `true` to preserve
/// the current permissive behaviour (accepts V8 dials).
///
/// On the V8 path `client_auth` is not invoked (V8 has no client pubkey at
/// the handshake layer); pass `|_ctx| true` when you do not care.
///
/// Returns `Some(tunnel)` on success, `None` on auth failure (V8 or V9).
/// Returns `Err` only for unrecoverable I/O errors.
pub async fn run_server_tcp_with_auth<F>(
    config: &MirageEndpointConfig,
    keypair: &KeyPair,
    stream: TcpStream,
    mesh_id: &[u8],
    client_auth: F,
    allow_legacy_v8: bool,
) -> Result<Option<Box<dyn Tunnel>>, MirageError>
where
    F: for<'a> Fn(&ClientAuthContext<'a>) -> bool + Send + 'static,
{
    let peer_addr = stream.peer_addr().unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());
    let auth = convert_auth(&config.auth);

    match &config.camouflage {
        TransportCamouflage::None => {
            let layer = NoCamouflage;
            let wrapped = match layer.wrap_server(stream).await? {
                Some(s) => s,
                None => return Ok(None),
            };
            handshake_server_stream_with_auth(wrapped, keypair, &auth, peer_addr, mesh_id, client_auth, allow_legacy_v8).await
        }
        TransportCamouflage::TlsReal { sni, alpn } => {
            let layer = TlsRealCamouflage::new(sni.clone(), alpn.clone(), None, None)?;
            let wrapped = match layer.wrap_server(stream).await? {
                Some(s) => s,
                None => return Ok(None),
            };
            handshake_server_stream_with_auth(wrapped, keypair, &auth, peer_addr, mesh_id, client_auth, allow_legacy_v8).await
        }
        TransportCamouflage::WebSocket { path, host } => {
            let layer = WebSocketCamouflage::new(path.clone(), host.clone());
            let wrapped = match layer.wrap_server(stream).await? {
                Some(s) => s,
                None => return Ok(None),
            };
            handshake_server_stream_with_auth(wrapped, keypair, &auth, peer_addr, mesh_id, client_auth, allow_legacy_v8).await
        }
        TransportCamouflage::Xhttp { path, host } => {
            let layer = XhttpCamouflage::new(path.clone(), host.clone());
            let wrapped = match layer.wrap_server(stream).await? {
                Some(s) => s,
                None => return Ok(None),
            };
            handshake_server_stream_with_auth(wrapped, keypair, &auth, peer_addr, mesh_id, client_auth, allow_legacy_v8).await
        }
        TransportCamouflage::Reality {
            short_id,
            max_time_diff,
            ..
        } => {
            let layer = RealityServerCamouflage::new(
                keypair.clone(),
                &[short_id.as_str()],
                *max_time_diff as u64,
            )?;
            let wrapped = match layer.wrap_server(stream).await? {
                Some(s) => s,
                None => return Ok(None),
            };
            handshake_server_stream_with_auth(wrapped, keypair, &auth, peer_addr, mesh_id, client_auth, allow_legacy_v8).await
        }
        // UDP-only / raw-socket camouflages are not valid for TCP server.
        TransportCamouflage::Quic { .. }
        | TransportCamouflage::Http3 { .. }
        | TransportCamouflage::Hysteria2 { .. }
        | TransportCamouflage::WireGuard { .. }
        | TransportCamouflage::DnsTunnel { .. }
        | TransportCamouflage::Icmp { .. }
        | TransportCamouflage::WebTransport { .. }
        | TransportCamouflage::RawUdp { .. } => Err(MirageError::Config(
            "run_server_tcp_with_auth: camouflage type requires raw/UDP socket".into(),
        )),
        TransportCamouflage::Ssh {
            ssh_user,
            ssh_host_key,
            ssh_private_key,
            ssh_password,
            forward_host,
            forward_port,
        } => {
            #[cfg(feature = "ssh")]
            {
                let layer = SshCamouflage {
                    ssh_user: ssh_user.clone(),
                    ssh_host_key: ssh_host_key.clone(),
                    ssh_private_key: ssh_private_key.clone(),
                    ssh_password: ssh_password.clone(),
                    forward_host: forward_host.clone(),
                    forward_port: *forward_port,
                };
                let wrapped = match layer.wrap_server(stream).await? {
                    Some(s) => s,
                    None => return Ok(None),
                };
                handshake_server_stream_with_auth(wrapped, keypair, &auth, peer_addr, mesh_id, client_auth, allow_legacy_v8).await
            }
            #[cfg(not(feature = "ssh"))]
            {
                let _ = (ssh_user, ssh_host_key, ssh_private_key, ssh_password, forward_host, forward_port, client_auth);
                Err(MirageError::Config(
                    "run_server_tcp_with_auth: SSH camouflage requires the `ssh` feature flag".into(),
                ))
            }
        }
        TransportCamouflage::Grpc {
            service_name,
            method_name,
            authority,
            use_tls,
        } => {
            #[cfg(feature = "grpc")]
            {
                let layer = GrpcCamouflage {
                    service_name: service_name.clone(),
                    method_name: method_name.clone(),
                    authority: authority.clone(),
                    use_tls: *use_tls,
                };
                let wrapped = match layer.wrap_server(stream).await? {
                    Some(s) => s,
                    None => return Ok(None),
                };
                handshake_server_stream_with_auth(wrapped, keypair, &auth, peer_addr, mesh_id, client_auth, allow_legacy_v8).await
            }
            #[cfg(not(feature = "grpc"))]
            {
                let _ = (service_name, method_name, authority, use_tls, client_auth);
                Err(MirageError::Config(
                    "run_server_tcp_with_auth: gRPC camouflage requires the `grpc` feature flag".into(),
                ))
            }
        }
    }
}

/// Default bound on the raw TCP `connect()` step of every `run_client_*`
/// dial in this module (2026-07-30). This bounds ONLY the three-way
/// handshake (SYN/SYN-ACK/ACK) — never the Mirage handshake that runs on
/// top of the resulting stream, and never anything after connect (uploads,
/// an interactive shell, ...). See [`tcp_connect_bounded`]'s doc for why
/// that split matters.
///
/// Value: 10s. This fleet spans RU/TR/NL/CH/US — cross-continent RTT is
/// routinely 150-300ms, and even a lossy path needing one SYN retransmit
/// (kernel default first retransmit ~1s) completes a real connect in low
/// single-digit seconds. 10s gives that an order of magnitude of headroom
/// (matches this workspace's own existing dial-layer connect bounds —
/// `mirage-dial-core::tunnel`'s `RAW_CONNECT_TIMEOUT`/`CONNECT_TIMEOUT` are
/// both 10s) while stopping more than an order of magnitude short of the
/// failure this closes: a relay open against a saturated box measured at
/// 107s to fail (`mirage2operator`'s `open_relay_ws_over_wire`, which calls
/// into `run_client_tcp_v9` and inherited its unboundedness — see that
/// crate's `RELAY_CANDIDATE_DIAL_TIMEOUT` doc for the incident).
pub const DEFAULT_CLIENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Default bound on the V9 Mirage handshake itself (2026-07-31) — camouflage
/// wrap/upgrade, the `V9ClientHello` write, and the `V9ServerHello` +
/// confirm read, all running on a stream whose raw TCP `connect()` has
/// ALREADY succeeded. A completely separate budget from
/// [`DEFAULT_CLIENT_CONNECT_TIMEOUT`]: that one bounds the three-way TCP
/// handshake only; this one bounds the Mirage protocol exchange layered on
/// top of it. Before this existed, nothing bounded that exchange anywhere in
/// this call chain — a peer that accepted the TCP connection and then never
/// answered (or answered partially and stalled) hung the calling task
/// forever, because `handshake_client_stream_v9`'s `read_exact` calls carry
/// no timeout of their own and no caller wrapped the whole dial either. See
/// `mirage2monitor::active_prober`'s module doc for the incident this
/// closes: one such silent peer permanently leaked a probe task every
/// ~20s-tick cycle, with no error, no retry, no trace.
///
/// Value: 20s. A real V9 handshake is two small messages each way over an
/// already-open socket — sub-second on every fleet link measured so far,
/// even cross-continent. 20s is an order of magnitude of headroom above
/// that (closing the actual hole: an unbounded wait) while staying on the
/// same scale as this fleet's own probe cadence, so a hung peer surfaces
/// within roughly one probe cycle instead of leaking a task forever.
pub const DEFAULT_CLIENT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);

/// Bound ONLY the TCP `connect()` call — not the Mirage handshake, not
/// anything the caller does with the stream afterward. A slow-but-
/// progressing handshake over a distant, healthy link (this fleet's normal
/// case) is a different failure mode from a peer that never completes TCP
/// connect at all (a saturated box whose accept queue never drains, or a
/// firewalled port silently dropping SYNs) — conflating the two into one
/// timeout wrapping the whole dial would either false-trip healthy
/// long-RTT links or fail to bound the actual stuck step. Scoping the bound
/// to just this call is what makes it safe to apply unconditionally to
/// every `run_client_*` dial without a caller-supplied override.
///
/// Returns [`MirageError::NodeUnreachable`] on a timeout — the SAME error
/// family every other timed dial in this workspace already raises for
/// exactly this condition (`mirage-dial-core::tunnel`'s onion/raw-relay/
/// single-hop connect timeouts, `mirage-dial-core::onion_tunnel`'s hop-0
/// connect timeout), so a caller matching on it gets one consistent "the
/// peer could not be reached in time" signal fleet-wide. A connect that
/// completes but is refused/reset (the peer answered, just said no) instead
/// surfaces as `MirageError::Io` — "timed out" and "refused" stay two
/// distinct, distinguishable diagnoses in every log line and every caller's
/// `match`, never merged into one generic I/O error.
/// Physical NIC the subscriber pins its edge transport to while a TUN default
/// route is up. `None` keeps the ordinary operating-system route.
///
/// macOS pins with `IP_BOUND_IF`. TCP on Linux sets `SO_MARK` 51820 for the
/// mirage2tun bypass; UDP binds to the named interface. Neither case adds or
/// changes a host route.
static CARRIER_IFACE: Mutex<Option<String>> = Mutex::new(None);

/// `Some(iface)` pins later dials. `None` clears the pin.
pub fn set_carrier_interface(iface: Option<String>) {
    *CARRIER_IFACE.lock().unwrap_or_else(|e| e.into_inner()) = iface;
}

fn carrier_iface() -> Option<String> {
    CARRIER_IFACE.lock().unwrap_or_else(|e| e.into_inner()).clone()
}

pub fn bind_udp_with_carrier(bind_addr: SocketAddr) -> Result<std::net::UdpSocket, MirageError> {
    let socket = std::net::UdpSocket::bind(bind_addr).map_err(MirageError::Io)?;
    socket.set_nonblocking(true).map_err(MirageError::Io)?;
    let Some(iface) = carrier_iface() else {
        return Ok(socket);
    };

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::os::fd::AsRawFd;

        const LINUX_SO_BINDTODEVICE: i32 = 25;
        const MAC_IP_BOUND_IF: i32 = 25;
        const MAC_IPV6_BOUND_IF: i32 = 125;

        let fd = socket.as_raw_fd();
        #[cfg(target_os = "linux")]
        {
            let name = std::ffi::CString::new(iface).map_err(|_| {
                MirageError::Io(IoError::new(
                    ErrorKind::InvalidInput,
                    "carrier interface name contains a nul",
                ))
            })?;
            let rc = unsafe {
                extern "C" {
                    fn setsockopt(
                        sockfd: i32,
                        level: i32,
                        optname: i32,
                        optval: *const u8,
                        optlen: u32,
                    ) -> i32;
                }
                setsockopt(
                    fd,
                    libc_sol_socket(),
                    LINUX_SO_BINDTODEVICE,
                    name.as_ptr() as *const u8,
                    name.as_bytes_with_nul().len() as u32,
                )
            };
            if rc != 0 {
                return Err(MirageError::Io(IoError::last_os_error()));
            }
        }
        #[cfg(target_os = "macos")]
        {
            let index = iface_index(&iface)?;
            let level = if bind_addr.is_ipv4() { 0 } else { 41 };
            let opt = if bind_addr.is_ipv4() { MAC_IP_BOUND_IF } else { MAC_IPV6_BOUND_IF };
            let rc = unsafe {
                extern "C" {
                    fn setsockopt(
                        sockfd: i32,
                        level: i32,
                        optname: i32,
                        optval: *const u8,
                        optlen: u32,
                    ) -> i32;
                }
                setsockopt(fd, level, opt, &index as *const u32 as *const u8, 4)
            };
            if rc != 0 {
                return Err(MirageError::Io(IoError::last_os_error()));
            }
        }
        Ok(socket)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (iface, socket);
        Err(MirageError::Io(IoError::new(
            ErrorKind::Unsupported,
            "carrier pin is implemented for linux and macos",
        )))
    }
}

async fn tcp_connect_bounded(addr: SocketAddr, timeout: Duration) -> Result<TcpStream, MirageError> {
    if let Some(iface) = carrier_iface() {
        return connect_with_carrier(addr, &iface, timeout).await;
    }
    match tokio::time::timeout(timeout, TcpStream::connect(addr)).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => Err(MirageError::Io(e)),
        Err(_) => Err(MirageError::NodeUnreachable(format!(
            "connect to {addr} timed out after {}ms",
            timeout.as_millis()
        ))),
    }
}

async fn connect_with_carrier(
    addr: SocketAddr,
    iface: &str,
    timeout: Duration,
) -> Result<TcpStream, MirageError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        pin_connect(addr, iface, timeout).await
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (addr, iface, timeout);
        Err(MirageError::Io(IoError::new(
            ErrorKind::Unsupported,
            "carrier pin is implemented for linux and macos",
        )))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
async fn pin_connect(
    addr: SocketAddr,
    iface: &str,
    timeout: Duration,
) -> Result<TcpStream, MirageError> {
    use std::os::fd::AsRawFd;

    const LINUX_SO_MARK: i32 = 36;
    const LINUX_MARK: i32 = 51820;
    const MAC_IP_BOUND_IF: i32 = 25;
    const MAC_IPV6_BOUND_IF: i32 = 125;

    let domain = if addr.is_ipv4() { socket2::Domain::IPV4 } else { socket2::Domain::IPV6 };
    let sock = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))
        .map_err(MirageError::Io)?;
    sock.set_nonblocking(true).map_err(MirageError::Io)?;

    #[cfg(target_os = "linux")]
    {
        let _ = iface;
        let fd = sock.as_raw_fd();
        let mark = LINUX_MARK;
        let rc = unsafe {
            extern "C" {
                fn setsockopt(
                    sockfd: i32,
                    level: i32,
                    optname: i32,
                    optval: *const u8,
                    optlen: u32,
                ) -> i32;
            }
            setsockopt(
                fd,
                libc_sol_socket(),
                LINUX_SO_MARK,
                &mark as *const i32 as *const u8,
                4,
            )
        };
        if rc != 0 {
            return Err(MirageError::Io(IoError::last_os_error()));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let index = iface_index(iface)?;
        let fd = sock.as_raw_fd();
        let level = if addr.is_ipv4() { 0 } else { 41 };
        let opt = if addr.is_ipv4() { MAC_IP_BOUND_IF } else { MAC_IPV6_BOUND_IF };
        let rc = unsafe {
            extern "C" {
                fn setsockopt(
                    sockfd: i32,
                    level: i32,
                    optname: i32,
                    optval: *const u8,
                    optlen: u32,
                ) -> i32;
            }
            setsockopt(fd, level, opt, &index as *const u32 as *const u8, 4)
        };
        if rc != 0 {
            return Err(MirageError::Io(IoError::last_os_error()));
        }
    }

    match sock.connect(&socket2::SockAddr::from(addr)) {
        Ok(()) => {}
        Err(e) if connect_in_progress(&e) => {}
        Err(e) => return Err(MirageError::Io(e)),
    }
    let std_stream: std::net::TcpStream = sock.into();
    let stream = TcpStream::from_std(std_stream).map_err(MirageError::Io)?;
    let wait = async {
        stream.writable().await.map_err(MirageError::Io)?;
        if let Some(err) = stream.take_error().map_err(MirageError::Io)? {
            return Err(MirageError::Io(err));
        }
        Ok(stream)
    };
    match tokio::time::timeout(timeout, wait).await {
        Ok(result) => result,
        Err(_) => Err(MirageError::NodeUnreachable(format!(
            "connect to {addr} timed out after {}ms",
            timeout.as_millis()
        ))),
    }
}

#[cfg(target_os = "linux")]
fn libc_sol_socket() -> i32 {
    1
}

#[cfg(target_os = "macos")]
fn iface_index(iface: &str) -> Result<u32, MirageError> {
    let c = std::ffi::CString::new(iface).map_err(|_| {
        MirageError::Io(IoError::new(ErrorKind::InvalidInput, "carrier interface name contains a nul"))
    })?;
    let index = unsafe {
        extern "C" {
            fn if_nametoindex(name: *const i8) -> u32;
        }
        if_nametoindex(c.as_ptr())
    };
    if index == 0 {
        Err(MirageError::Io(IoError::new(
            ErrorKind::NotFound,
            format!("carrier interface {iface} has no index"),
        )))
    } else {
        Ok(index)
    }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn connect_in_progress(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::WouldBlock
        || err.raw_os_error() == Some(115) // linux EINPROGRESS
        || err.raw_os_error() == Some(36) // macos EINPROGRESS
}

/// Perform the V9 forward-secret mutual-auth client-side TCP handshake.
///
/// Connects to `server_addr`, applies camouflage, then runs
/// `run_client_handshake_v9` with the caller-supplied static keys.
///
/// `server_static_pub` — server's 32-byte declared static X25519 pubkey.
/// `client_static_priv` — client's own 32-byte static X25519 private key.
/// `credential` — optional anonymous credential. When `Some`, `cred_scheme` is
///   set in `V9ClientHello` byte 92 and a `[2B len BE][token]` frame is written
///   immediately after the 97B hello. When `None`, byte 92 is zero (legacy).
///
/// Only the TCP-valid camouflage variants (None, TlsReal, WebSocket, Xhttp,
/// Reality) are supported. UDP-only camouflages return an error.
///
/// Two independent, separately-named bounds apply, in sequence:
/// 1. The raw TCP connect — [`DEFAULT_CLIENT_CONNECT_TIMEOUT`] (see
///    [`tcp_connect_bounded`]).
/// 2. The Mirage handshake that runs on the resulting stream (camouflage
///    wrap + `V9ClientHello`/`V9ServerHello` exchange) —
///    [`DEFAULT_CLIENT_HANDSHAKE_TIMEOUT`].
///
/// To override either bound, call [`run_client_tcp_v9_with_connect_timeout`]
/// (connect only) or [`run_client_tcp_v9_with_timeouts`] (both) instead —
/// this fn's own signature is unchanged so every existing caller keeps
/// working with no edits.
pub async fn run_client_tcp_v9(
    config: &MirageEndpointConfig,
    server_addr: SocketAddr,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    sni: &str,
    mesh_id: &[u8],
    credential: Option<&ClientCredential>,
) -> Result<Box<dyn Tunnel>, MirageError> {
    run_client_tcp_v9_with_connect_timeout(
        config,
        server_addr,
        server_static_pub,
        client_static_priv,
        sni,
        mesh_id,
        credential,
        DEFAULT_CLIENT_CONNECT_TIMEOUT,
    )
    .await
}

/// Same as [`run_client_tcp_v9`], with an explicit override for the TCP
/// `connect()` bound (see [`tcp_connect_bounded`]) instead of
/// [`DEFAULT_CLIENT_CONNECT_TIMEOUT`]. The handshake bound stays at its
/// default ([`DEFAULT_CLIENT_HANDSHAKE_TIMEOUT`]) — use
/// [`run_client_tcp_v9_with_timeouts`] to override both. Added so a caller
/// with a genuine reason to dial patiently (or, conversely, to fail fast)
/// can do so without every other call site taking a new required parameter
/// for a bound it never needs to think about.
pub async fn run_client_tcp_v9_with_connect_timeout(
    config: &MirageEndpointConfig,
    server_addr: SocketAddr,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    sni: &str,
    mesh_id: &[u8],
    credential: Option<&ClientCredential>,
    connect_timeout: Duration,
) -> Result<Box<dyn Tunnel>, MirageError> {
    run_client_tcp_v9_with_timeouts(
        config,
        server_addr,
        server_static_pub,
        client_static_priv,
        sni,
        mesh_id,
        credential,
        connect_timeout,
        DEFAULT_CLIENT_HANDSHAKE_TIMEOUT,
    )
    .await
}

/// Same as [`run_client_tcp_v9`], with explicit overrides for BOTH the TCP
/// `connect()` bound and the post-connect Mirage handshake bound.
///
/// The two bounds are applied to two DIFFERENT, non-overlapping spans of the
/// dial and never merged into one total: `connect_timeout` covers only
/// [`tcp_connect_bounded`]'s `TcpStream::connect`; `handshake_timeout` covers
/// only what runs after that connect succeeds — the camouflage wrap/upgrade
/// (TLS handshake, WebSocket upgrade, SSH session, …, depending on
/// `config.camouflage`) and the V9 `ClientHello`/`ServerHello`/confirm
/// exchange in [`handshake_client_stream_v9`]. This is why a reader (or a log
/// line) can tell "the peer never answered TCP" (`MirageError::
/// NodeUnreachable`, from `tcp_connect_bounded`) apart from "the peer
/// answered TCP and then went silent" (`MirageError::HandshakeTimedOut`,
/// from this fn) — merging them into a single end-to-end timeout would lose
/// that distinction entirely.
///
/// On `handshake_timeout` expiry the in-flight handshake future is DROPPED
/// (that is what `tokio::time::timeout` does to the loser of the race),
/// which drops the `TcpStream` moved into it — the half-open socket and the
/// task polling it are both released, not left parked.
///
/// A caller that genuinely needs a long handshake budget (none identified in
/// this workspace as of 2026-07-31 — every audited caller either wants the
/// generous default or already wraps the whole dial in its own outer
/// timeout) can pass `handshake_timeout` explicitly; there is nothing
/// camouflage-specific in this parameter that would make one
/// `TransportCamouflage` variant need a different value from another.
pub async fn run_client_tcp_v9_with_timeouts(
    config: &MirageEndpointConfig,
    server_addr: SocketAddr,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    sni: &str,
    mesh_id: &[u8],
    credential: Option<&ClientCredential>,
    connect_timeout: Duration,
    handshake_timeout: Duration,
) -> Result<Box<dyn Tunnel>, MirageError> {
    use mirage_core::crypto::AeadSuite;
    let stream = tcp_connect_bounded(server_addr, connect_timeout).await?;
    let auth = convert_auth(&config.auth);

    let handshake = async move {
        match &config.camouflage {
            TransportCamouflage::None => {
                let layer = NoCamouflage;
                let wrapped = layer.wrap_client(stream, sni).await?;
                handshake_client_stream_v9(wrapped, server_static_pub, client_static_priv, server_addr, mesh_id, &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm], &auth, credential).await
            }
            TransportCamouflage::TlsReal { sni: cfg_sni, alpn } => {
                let effective_sni = if sni.is_empty() { cfg_sni.as_str() } else { sni };
                let layer = TlsRealCamouflage::new(cfg_sni.clone(), alpn.clone(), None, None)?;
                let wrapped = layer.wrap_client(stream, effective_sni).await?;
                handshake_client_stream_v9(wrapped, server_static_pub, client_static_priv, server_addr, mesh_id, &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm], &auth, credential).await
            }
            TransportCamouflage::WebSocket { path, host } => {
                let layer = WebSocketCamouflage::new(path.clone(), host.clone());
                let wrapped = layer.wrap_client(stream, sni).await?;
                handshake_client_stream_v9(wrapped, server_static_pub, client_static_priv, server_addr, mesh_id, &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm], &auth, credential).await
            }
            TransportCamouflage::Xhttp { path, host } => {
                let layer = XhttpCamouflage::new(path.clone(), host.clone());
                let wrapped = layer.wrap_client(stream, sni).await?;
                handshake_client_stream_v9(wrapped, server_static_pub, client_static_priv, server_addr, mesh_id, &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm], &auth, credential).await
            }
            TransportCamouflage::Reality { short_id, .. } => {
                let layer = RealityClientCamouflage::new(*server_static_pub, short_id.as_str())?;
                let wrapped = layer.wrap_client(stream, sni).await?;
                handshake_client_stream_v9(wrapped, server_static_pub, client_static_priv, server_addr, mesh_id, &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm], &auth, credential).await
            }
            TransportCamouflage::Quic { .. }
            | TransportCamouflage::Http3 { .. }
            | TransportCamouflage::Hysteria2 { .. }
            | TransportCamouflage::WireGuard { .. }
            | TransportCamouflage::DnsTunnel { .. }
            | TransportCamouflage::Icmp { .. }
            | TransportCamouflage::WebTransport { .. }
            | TransportCamouflage::RawUdp { .. } => Err(MirageError::Config(
                "run_client_tcp_v9: UDP-only camouflage not supported for TCP V9 dial".into(),
            )),
            TransportCamouflage::Ssh {
                ssh_user,
                ssh_host_key,
                ssh_private_key,
                ssh_password,
                forward_host,
                forward_port,
            } => {
                #[cfg(feature = "ssh")]
                {
                    let layer = SshCamouflage {
                        ssh_user: ssh_user.clone(),
                        ssh_host_key: ssh_host_key.clone(),
                        ssh_private_key: ssh_private_key.clone(),
                        ssh_password: ssh_password.clone(),
                        forward_host: forward_host.clone(),
                        forward_port: *forward_port,
                    };
                    let wrapped = layer.wrap_client(stream, sni).await?;
                    handshake_client_stream_v9(wrapped, server_static_pub, client_static_priv, server_addr, mesh_id, &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm], &auth, credential).await
                }
                #[cfg(not(feature = "ssh"))]
                {
                    let _ = (ssh_user, ssh_host_key, ssh_private_key, ssh_password, forward_host, forward_port);
                    Err(MirageError::Config(
                        "run_client_tcp_v9: SSH camouflage requires the `ssh` feature flag".into(),
                    ))
                }
            }
            TransportCamouflage::Grpc {
                service_name,
                method_name,
                authority,
                use_tls,
            } => {
                #[cfg(feature = "grpc")]
                {
                    let layer = GrpcCamouflage {
                        service_name: service_name.clone(),
                        method_name: method_name.clone(),
                        authority: authority.clone(),
                        use_tls: *use_tls,
                    };
                    let wrapped = layer.wrap_client(stream, sni).await?;
                    handshake_client_stream_v9(wrapped, server_static_pub, client_static_priv, server_addr, mesh_id, &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm], &auth, credential).await
                }
                #[cfg(not(feature = "grpc"))]
                {
                    let _ = (service_name, method_name, authority, use_tls);
                    Err(MirageError::Config(
                        "run_client_tcp_v9: gRPC camouflage requires the `grpc` feature flag".into(),
                    ))
                }
            }
        }
    };

    match tokio::time::timeout(handshake_timeout, handshake).await {
        Ok(result) => result,
        Err(_) => Err(MirageError::HandshakeTimedOut(format!(
            "V9 handshake with {server_addr} timed out after {}ms (TCP connect already succeeded)",
            handshake_timeout.as_millis()
        ))),
    }
}

/// Run a server-side UDP listener loop for a given config.
///
/// `mesh_id` — mesh identifier bytes baked into the Blake3 confirm label.
///
/// `allow_legacy_v8` — when `false`, clients that send a non-V9 first byte
/// receive `VERSION_REJECT (0xFF)` and are silently dropped. Set to `true`
/// to allow V8 dials (emergency backward-compat only).
///
/// Binds to `bind_addr`, accepts one UDP-camouflaged peer at a time, runs the
/// Mirage handshake, and sends a `Box<dyn Tunnel>` into `tunnel_tx` for each
/// authenticated peer.
///
/// Designed to be spawned as a long-running background task.  The loop is
/// infinite — it only stops on a fatal bind/accept error or when `tunnel_tx` is closed.
pub async fn run_server_udp(
    config: &MirageEndpointConfig,
    keypair: &KeyPair,
    bind_addr: SocketAddr,
    tunnel_tx: mpsc::Sender<Box<dyn Tunnel>>,
    mesh_id: &[u8],
    allow_legacy_v8: bool,
) -> Result<(), MirageError> {
    if config.transport != TransportKind::Udp {
        return Err(MirageError::Config(
            "run_server_udp: config transport must be Udp".into(),
        ));
    }
    let auth = convert_auth(&config.auth);
    // Convert mesh_id to owned Vec so it can be cloned into spawned tasks.
    let mesh_id_owned: Vec<u8> = mesh_id.to_vec();

    match &config.camouflage {
        TransportCamouflage::Quic { alpn, .. } => {
            let layer = QuicCamouflage::new(alpn.clone())?;
            // Bind once — the endpoint must outlive all accepted connections.
            // Dropping the endpoint sends CONNECTION_CLOSE to every open stream.
            let endpoint = layer.bind_endpoint(bind_addr)?;
            loop {
                match layer.accept_one(&endpoint).await {
                    Ok((stream, peer_addr)) => {
                        let keypair_clone = keypair.clone();
                        let auth_clone = auth.clone();
                        let tx_clone = tunnel_tx.clone();
                        let mesh_id_clone = mesh_id_owned.clone();
                        tokio::spawn(async move {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(15),
                                handshake_server_stream(stream, &keypair_clone, &auth_clone, peer_addr, &mesh_id_clone, allow_legacy_v8),
                            ).await {
                                Ok(Ok(Some(tunnel))) => { let _ = tx_clone.send(tunnel).await; }
                                Ok(Ok(None)) => {}
                                Ok(Err(e)) => tracing::debug!("quic server handshake failed: {e}"),
                                Err(_) => tracing::debug!(%peer_addr, "quic server handshake timeout"),
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp(quic) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::Hysteria2 { .. } => Err(MirageError::Config(
            "hysteria2 is not part of the mask set any more".to_owned(),
        )),
        TransportCamouflage::WireGuard {
            magic_byte,
            junk_count,
            junk_min,
            junk_max,
            ..
        } => {
            let layer = std::sync::Arc::new(WireGuardCamouflage::new(*magic_byte, *junk_count, *junk_min, *junk_max));
            loop {
                match layer.accept_server(bind_addr).await {
                    Ok((stream, peer_addr)) => {
                        tracing::debug!(
                            %bind_addr,
                            %peer_addr,
                            "wireguard server: accepted peer, spawning handshake",
                        );
                        let keypair_clone = keypair.clone();
                        let auth_clone = auth.clone();
                        let tx_clone = tunnel_tx.clone();
                        let mesh_id_clone = mesh_id_owned.clone();
                        let layer_clone = std::sync::Arc::clone(&layer);
                        tokio::spawn(async move {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(15),
                                handshake_server_stream(stream, &keypair_clone, &auth_clone, peer_addr, &mesh_id_clone, allow_legacy_v8),
                            ).await {
                                Ok(Ok(Some(tunnel))) => {
                                    tracing::debug!(%peer_addr, "wireguard server: handshake succeeded");
                                    let _ = tx_clone.send(tunnel).await;
                                }
                                Ok(Ok(None)) => {
                                    tracing::debug!(
                                        %peer_addr,
                                        "wireguard server: handshake auth failed — evicting peer for fast re-handshake",
                                    );
                                    layer_clone.evict_peer(bind_addr, peer_addr).await;
                                }
                                Ok(Err(e)) => {
                                    tracing::debug!(%peer_addr, "wireguard server: handshake error: {e}");
                                    layer_clone.evict_peer(bind_addr, peer_addr).await;
                                }
                                Err(_) => {
                                    tracing::debug!(%peer_addr, "wireguard server handshake timeout");
                                    layer_clone.evict_peer(bind_addr, peer_addr).await;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp(wireguard) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::Http3 { alpn, authority, tunnel_path, .. } => {
            let layer = Http3Camouflage::new(authority.clone(), tunnel_path.clone(), alpn.clone())?;
            // Bind once — the endpoint must outlive all accepted connections.
            // Dropping the endpoint sends CONNECTION_CLOSE to every open stream.
            let endpoint = layer.bind_endpoint(bind_addr)?;
            loop {
                match layer.accept_one(&endpoint).await {
                    Ok((stream, peer_addr)) => {
                        let keypair_clone = keypair.clone();
                        let auth_clone = auth.clone();
                        let tx_clone = tunnel_tx.clone();
                        let mesh_id_clone = mesh_id_owned.clone();
                        tokio::spawn(async move {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(15),
                                handshake_server_stream(stream, &keypair_clone, &auth_clone, peer_addr, &mesh_id_clone, allow_legacy_v8),
                            ).await {
                                Ok(Ok(Some(tunnel))) => { let _ = tx_clone.send(tunnel).await; }
                                Ok(Ok(None)) => {}
                                Ok(Err(e)) => tracing::debug!("http3 server handshake failed: {e}"),
                                Err(_) => tracing::debug!(%peer_addr, "http3 server handshake timeout"),
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp(http3) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::DnsTunnel { domain, encoding, query_type, .. } => {
            let enc = parse_dns_encoding(encoding)?;
            let qt = parse_dns_query_type(query_type)?;
            let layer = DnsTunnelCamouflage::new(domain.clone(), enc, qt);
            loop {
                match layer.accept_server(bind_addr).await {
                    Ok((stream, peer_addr)) => {
                        let keypair_clone = keypair.clone();
                        let auth_clone = auth.clone();
                        let tx_clone = tunnel_tx.clone();
                        let mesh_id_clone = mesh_id_owned.clone();
                        tokio::spawn(async move {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(15),
                                handshake_server_stream(stream, &keypair_clone, &auth_clone, peer_addr, &mesh_id_clone, allow_legacy_v8),
                            ).await {
                                Ok(Ok(Some(tunnel))) => { let _ = tx_clone.send(tunnel).await; }
                                Ok(Ok(None)) => {}
                                Ok(Err(e)) => tracing::debug!("dns_tunnel server handshake failed: {e}"),
                                Err(_) => tracing::debug!(%peer_addr, "dns_tunnel server handshake timeout"),
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp(dns_tunnel) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::Icmp { peer_addr, identifier, mtu } => {
            let layer = IcmpCamouflage::new(*peer_addr, *identifier, *mtu);
            loop {
                match layer.accept_server(bind_addr).await {
                    Ok((stream, peer_addr)) => {
                        let keypair_clone = keypair.clone();
                        let auth_clone = auth.clone();
                        let tx_clone = tunnel_tx.clone();
                        let mesh_id_clone = mesh_id_owned.clone();
                        tokio::spawn(async move {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(15),
                                handshake_server_stream(
                                    stream,
                                    &keypair_clone,
                                    &auth_clone,
                                    peer_addr,
                                    &mesh_id_clone,
                                    allow_legacy_v8,
                                ),
                            ).await {
                                Ok(Ok(Some(tunnel))) => {
                                    let _ = tx_clone.send(tunnel).await;
                                }
                                Ok(Ok(None)) => {}
                                Ok(Err(e)) => tracing::debug!("icmp server handshake failed: {e}"),
                                Err(_) => tracing::debug!(%peer_addr, "icmp server handshake timeout"),
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp(icmp) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::WebTransport { path, authority, .. } => {
            let layer = WebTransportCamouflage::new(path.clone(), authority.clone())?;
            // Bind once — the endpoint must outlive all accepted connections.
            // Dropping the endpoint sends CONNECTION_CLOSE to every open stream.
            let endpoint = layer.bind_endpoint(bind_addr)?;
            loop {
                match layer.accept_one(&endpoint).await {
                    Ok((stream, peer_addr)) => {
                        let keypair_clone = keypair.clone();
                        let auth_clone = auth.clone();
                        let tx_clone = tunnel_tx.clone();
                        let mesh_id_clone = mesh_id_owned.clone();
                        tokio::spawn(async move {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(15),
                                handshake_server_stream(stream, &keypair_clone, &auth_clone, peer_addr, &mesh_id_clone, allow_legacy_v8),
                            ).await {
                                Ok(Ok(Some(tunnel))) => { let _ = tx_clone.send(tunnel).await; }
                                Ok(Ok(None)) => {}
                                Ok(Err(e)) => tracing::debug!("webtransport server handshake failed: {e}"),
                                Err(_) => tracing::debug!(%peer_addr, "webtransport server handshake timeout"),
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp(webtransport) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::RawUdp { .. } => {
            // Bare UDP datagrams: AEAD frames + Mirage handshake without any
            // outer wrapping.  Reuses the standard handshake_server_stream
            // path on top of `RawUdpAdapter` (a tokio AsyncRead/AsyncWrite
            // shim over a per-peer ephemeral UDP socket).
            //
            // The `WireGuardCamouflage`-style accept_server returns a single
            // adapter per incoming peer; loop and re-bind each time so the
            // listener can serve multiple clients.  Each iteration spawns the
            // handshake on a task so a slow client can't block the accept.
            let layer = std::sync::Arc::new(RawUdpCamouflage::new());
            loop {
                match layer.accept_server(bind_addr).await {
                    Ok((stream, peer_addr)) => {
                        tracing::debug!(
                            %bind_addr,
                            %peer_addr,
                            "raw_udp server: accepted peer, spawning handshake",
                        );
                        let keypair_clone = keypair.clone();
                        let auth_clone = auth.clone();
                        let tx_clone = tunnel_tx.clone();
                        let mesh_id_clone = mesh_id_owned.clone();
                        let layer_clone = std::sync::Arc::clone(&layer);
                        tokio::spawn(async move {
                            match tokio::time::timeout(
                                std::time::Duration::from_secs(15),
                                handshake_server_stream(stream, &keypair_clone, &auth_clone, peer_addr, &mesh_id_clone, allow_legacy_v8),
                            ).await {
                                Ok(Ok(Some(tunnel))) => {
                                    tracing::debug!(%peer_addr, "raw_udp server: handshake succeeded, tunnel ready");
                                    let _ = tx_clone.send(tunnel).await;
                                }
                                Ok(Ok(None)) => {
                                    tracing::debug!(
                                        %peer_addr,
                                        "raw_udp server: handshake auth failed — evicting peer for fast re-handshake",
                                    );
                                    layer_clone.evict_peer(bind_addr, peer_addr).await;
                                }
                                Ok(Err(e)) => {
                                    tracing::debug!(%peer_addr, "raw_udp server: handshake error: {e}");
                                    layer_clone.evict_peer(bind_addr, peer_addr).await;
                                }
                                Err(_) => {
                                    tracing::debug!(%peer_addr, "raw_udp server handshake timeout");
                                    layer_clone.evict_peer(bind_addr, peer_addr).await;
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp(raw_udp) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        // TCP-only camouflages (including SSH and gRPC which run over TCP).
        TransportCamouflage::None
        | TransportCamouflage::TlsReal { .. }
        | TransportCamouflage::WebSocket { .. }
        | TransportCamouflage::Xhttp { .. }
        | TransportCamouflage::Reality { .. }
        | TransportCamouflage::Ssh { .. }
        | TransportCamouflage::Grpc { .. } => {
            return Err(MirageError::Config(
                "run_server_udp: camouflage type is TCP-only (use run_server_tcp)".into(),
            ));
        }
    }
}

/// Like [`run_server_udp`] but threads a `client_auth` closure into the V9
/// server path — closes the UDP credential-verify gap.
///
/// `client_auth` is wrapped in an `Arc` so it can be cloned into each per-peer
/// spawned task without requiring `Clone` on the closure.
///
/// `allow_legacy_v8` — when `false`, any non-V9 first byte causes the server
/// to send `VERSION_REJECT (0xFF)` and silently drop the peer.
pub async fn run_server_udp_with_auth(
    config: &MirageEndpointConfig,
    keypair: &KeyPair,
    bind_addr: SocketAddr,
    tunnel_tx: mpsc::Sender<Box<dyn Tunnel>>,
    mesh_id: &[u8],
    client_auth: std::sync::Arc<dyn Fn(&ClientAuthContext<'_>) -> bool + Send + Sync>,
    allow_legacy_v8: bool,
) -> Result<(), MirageError> {
    if config.transport != TransportKind::Udp {
        return Err(MirageError::Config(
            "run_server_udp_with_auth: config transport must be Udp".into(),
        ));
    }
    let auth = convert_auth(&config.auth);
    let mesh_id_owned: Vec<u8> = mesh_id.to_vec();

    /// Macro-local helper: spawn a handshake task with the `_with_auth` variant.
    macro_rules! spawn_udp_auth_task {
        ($stream:expr, $peer_addr:expr, $evict:expr) => {{
            let keypair_clone = keypair.clone();
            let auth_clone = auth.clone();
            let tx_clone = tunnel_tx.clone();
            let mesh_id_clone = mesh_id_owned.clone();
            let client_auth_clone = std::sync::Arc::clone(&client_auth);
            let peer_addr = $peer_addr;
            let evict_fn: Option<Box<dyn FnOnce() + Send>> = $evict;
            tokio::spawn(async move {
                match tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    handshake_server_stream_with_auth(
                        $stream,
                        &keypair_clone,
                        &auth_clone,
                        peer_addr,
                        &mesh_id_clone,
                        move |ctx| client_auth_clone(ctx),
                        allow_legacy_v8,
                    ),
                )
                .await
                {
                    Ok(Ok(Some(tunnel))) => {
                        let _ = tx_clone.send(tunnel).await;
                    }
                    Ok(Ok(None)) => {
                        if let Some(f) = evict_fn {
                            f();
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(%peer_addr, "udp_with_auth server handshake failed: {e}");
                        if let Some(f) = evict_fn {
                            f();
                        }
                    }
                    Err(_) => {
                        tracing::debug!(%peer_addr, "udp_with_auth server handshake timeout");
                        if let Some(f) = evict_fn {
                            f();
                        }
                    }
                }
            });
        }};
    }

    match &config.camouflage {
        TransportCamouflage::Quic { alpn, .. } => {
            let layer = QuicCamouflage::new(alpn.clone())?;
            let endpoint = layer.bind_endpoint(bind_addr)?;
            loop {
                match layer.accept_one(&endpoint).await {
                    Ok((stream, peer_addr)) => {
                        spawn_udp_auth_task!(stream, peer_addr, None::<Box<dyn FnOnce() + Send>>);
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp_with_auth(quic) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::Hysteria2 { .. } => Err(MirageError::Config(
            "hysteria2 is not part of the mask set any more".to_owned(),
        )),
        TransportCamouflage::WireGuard { magic_byte, junk_count, junk_min, junk_max, .. } => {
            let layer = std::sync::Arc::new(WireGuardCamouflage::new(*magic_byte, *junk_count, *junk_min, *junk_max));
            loop {
                match layer.accept_server(bind_addr).await {
                    Ok((stream, peer_addr)) => {
                        let layer_clone = std::sync::Arc::clone(&layer);
                        let evict: Box<dyn FnOnce() + Send> = Box::new(move || {
                            let layer2 = layer_clone;
                            tokio::spawn(async move {
                                layer2.evict_peer(bind_addr, peer_addr).await;
                            });
                        });
                        spawn_udp_auth_task!(stream, peer_addr, Some(evict));
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp_with_auth(wireguard) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::Http3 { alpn, authority, tunnel_path, .. } => {
            let layer = Http3Camouflage::new(authority.clone(), tunnel_path.clone(), alpn.clone())?;
            let endpoint = layer.bind_endpoint(bind_addr)?;
            loop {
                match layer.accept_one(&endpoint).await {
                    Ok((stream, peer_addr)) => {
                        spawn_udp_auth_task!(stream, peer_addr, None::<Box<dyn FnOnce() + Send>>);
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp_with_auth(http3) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::DnsTunnel { domain, encoding, query_type, .. } => {
            let enc = parse_dns_encoding(encoding)?;
            let qt = parse_dns_query_type(query_type)?;
            let layer = DnsTunnelCamouflage::new(domain.clone(), enc, qt);
            loop {
                match layer.accept_server(bind_addr).await {
                    Ok((stream, peer_addr)) => {
                        spawn_udp_auth_task!(stream, peer_addr, None::<Box<dyn FnOnce() + Send>>);
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp_with_auth(dns_tunnel) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::Icmp { peer_addr, identifier, mtu } => {
            let layer = IcmpCamouflage::new(*peer_addr, *identifier, *mtu);
            loop {
                match layer.accept_server(bind_addr).await {
                    Ok((stream, peer_addr)) => {
                        spawn_udp_auth_task!(stream, peer_addr, None::<Box<dyn FnOnce() + Send>>);
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp_with_auth(icmp) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::WebTransport { path, authority, .. } => {
            let layer = WebTransportCamouflage::new(path.clone(), authority.clone())?;
            let endpoint = layer.bind_endpoint(bind_addr)?;
            loop {
                match layer.accept_one(&endpoint).await {
                    Ok((stream, peer_addr)) => {
                        spawn_udp_auth_task!(stream, peer_addr, None::<Box<dyn FnOnce() + Send>>);
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp_with_auth(webtransport) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::RawUdp { .. } => {
            let layer = std::sync::Arc::new(RawUdpCamouflage::new());
            loop {
                match layer.accept_server(bind_addr).await {
                    Ok((stream, peer_addr)) => {
                        let layer_clone = std::sync::Arc::clone(&layer);
                        let evict: Box<dyn FnOnce() + Send> = Box::new(move || {
                            let layer2 = layer_clone;
                            tokio::spawn(async move {
                                layer2.evict_peer(bind_addr, peer_addr).await;
                            });
                        });
                        spawn_udp_auth_task!(stream, peer_addr, Some(evict));
                    }
                    Err(e) => {
                        tracing::warn!("run_server_udp_with_auth(raw_udp) accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                    }
                }
            }
        }
        TransportCamouflage::None
        | TransportCamouflage::TlsReal { .. }
        | TransportCamouflage::WebSocket { .. }
        | TransportCamouflage::Xhttp { .. }
        | TransportCamouflage::Reality { .. }
        | TransportCamouflage::Ssh { .. }
        | TransportCamouflage::Grpc { .. } => {
            return Err(MirageError::Config(
                "run_server_udp_with_auth: camouflage type is TCP-only (use run_server_tcp_with_auth)".into(),
            ));
        }
    }
}

/// V9 forward-secret UDP client dial.
///
/// Mirrors `run_client_tcp_v9` but dispatches UDP camouflage variants
/// (Quic, WireGuard, Http3, DnsTunnel, Icmp, WebTransport, RawUdp).
///
/// `server_static_pub` — server's 32-byte declared static X25519 pubkey.
/// `client_static_priv` — client's own 32-byte static X25519 private key.
///   For single-hop UDP dials, pass a per-dial ephemeral (generated by `OsRng`)
///   to preserve client unlinkability.
/// `credential` — optional anonymous credential (V9 scheme byte + token).
///
/// TCP-only camouflages (None, TlsReal, WebSocket, Xhttp, Reality, Ssh, Grpc)
/// return `Err(MirageError::Config(...))`.
pub async fn run_client_udp_v9(
    config: &MirageEndpointConfig,
    server_addr: SocketAddr,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    sni: &str,
    mesh_id: &[u8],
    credential: Option<&ClientCredential>,
) -> Result<Box<dyn Tunnel>, MirageError> {
    if config.transport != TransportKind::Udp {
        return Err(MirageError::Config(
            "run_client_udp_v9: config transport must be Udp".into(),
        ));
    }
    use mirage_core::crypto::AeadSuite;
    let auth = convert_auth(&config.auth);
    let suite_prefs = &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm];

    match &config.camouflage {
        TransportCamouflage::Quic { alpn, .. } => {
            let layer = QuicCamouflage::new(alpn.clone())?;
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream_v9(stream, server_static_pub, client_static_priv, server_addr, mesh_id, suite_prefs, &auth, credential).await
        }
        TransportCamouflage::Hysteria2 { .. } => Err(MirageError::Config(
            "hysteria2 is not part of the mask set any more".to_owned(),
        )),
        TransportCamouflage::WireGuard { magic_byte, junk_count, junk_min, junk_max, .. } => {
            let layer = WireGuardCamouflage::new(*magic_byte, *junk_count, *junk_min, *junk_max);
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream_v9(stream, server_static_pub, client_static_priv, server_addr, mesh_id, suite_prefs, &auth, credential).await
        }
        TransportCamouflage::Http3 { alpn, authority, tunnel_path, .. } => {
            let layer = Http3Camouflage::new(authority.clone(), tunnel_path.clone(), alpn.clone())?;
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream_v9(stream, server_static_pub, client_static_priv, server_addr, mesh_id, suite_prefs, &auth, credential).await
        }
        TransportCamouflage::DnsTunnel { domain, encoding, query_type, .. } => {
            let enc = parse_dns_encoding(encoding)?;
            let qt = parse_dns_query_type(query_type)?;
            let layer = DnsTunnelCamouflage::new(domain.clone(), enc, qt);
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream_v9(stream, server_static_pub, client_static_priv, server_addr, mesh_id, suite_prefs, &auth, credential).await
        }
        TransportCamouflage::Icmp { peer_addr, identifier, mtu } => {
            let layer = IcmpCamouflage::new(*peer_addr, *identifier, *mtu);
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream_v9(stream, server_static_pub, client_static_priv, server_addr, mesh_id, suite_prefs, &auth, credential).await
        }
        TransportCamouflage::WebTransport { path, authority, .. } => {
            let layer = WebTransportCamouflage::new(path.clone(), authority.clone())?;
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream_v9(stream, server_static_pub, client_static_priv, server_addr, mesh_id, suite_prefs, &auth, credential).await
        }
        TransportCamouflage::RawUdp { .. } => {
            let layer = RawUdpCamouflage::with_cipher(config.byte_cipher_mode.clone());
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream_v9(stream, server_static_pub, client_static_priv, server_addr, mesh_id, suite_prefs, &auth, credential).await
        }
        TransportCamouflage::None
        | TransportCamouflage::TlsReal { .. }
        | TransportCamouflage::WebSocket { .. }
        | TransportCamouflage::Xhttp { .. }
        | TransportCamouflage::Reality { .. }
        | TransportCamouflage::Ssh { .. }
        | TransportCamouflage::Grpc { .. } => Err(MirageError::Config(
            "run_client_udp_v9: TCP-only camouflage — use run_client_tcp_v9 instead".into(),
        )),
    }
}

/// Perform the client-side ICMP connection + V9 Mirage handshake.
///
/// `mesh_id` — mesh identifier bytes baked into the Blake3 confirm label.
///
/// `client_static_priv` — client's 32-byte static X25519 private key.
///   Pass a per-dial ephemeral (`OsRng`-generated) for unlinkability.
/// `credential` — optional V9 anonymous credential.
///
/// Opens a raw ICMPv4 socket, builds an `IcmpTunnelAdapter`, and runs the
/// V9 forward-secret Mirage handshake over it.  Returns an authenticated
/// `Tunnel` ready for bidirectional data transfer.
///
/// `server_addr.ip()` is the server IP; the port component is ignored
/// because ICMP has no port numbers.
///
/// **Requires administrator / root privileges** — raw sockets need
/// `CAP_NET_RAW` on Linux / root on macOS / Administrator on Windows.
pub async fn run_client_icmp(
    config: &MirageEndpointConfig,
    server_addr: SocketAddr,
    server_pubkey: &[u8; 32],
    client_static_priv: &[u8; 32],
    mesh_id: &[u8],
    credential: Option<&ClientCredential>,
) -> Result<Box<dyn Tunnel>, MirageError> {
    use mirage_core::crypto::AeadSuite;
    let auth = convert_auth(&config.auth);

    match &config.camouflage {
        TransportCamouflage::Icmp { peer_addr, identifier, mtu } => {
            let layer = IcmpCamouflage::new(*peer_addr, *identifier, *mtu);
            let stream = layer.connect_client(server_addr, "").await?;
            handshake_client_stream_v9(
                stream,
                server_pubkey,
                client_static_priv,
                server_addr,
                mesh_id,
                &[AeadSuite::ChaCha20Poly1305, AeadSuite::Aes256Gcm],
                &auth,
                credential,
            )
            .await
        }
        other => Err(MirageError::Config(format!(
            "run_client_icmp: expected Icmp camouflage, got {:?}",
            std::mem::discriminant(other)
        ))),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Internal helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Parse a DNS encoding string from `TransportCamouflage::DnsTunnel`.
fn parse_dns_encoding(s: &str) -> Result<DnsEncoding, MirageError> {
    match s {
        "base32" | "Base32" => Ok(DnsEncoding::Base32),
        "base64url" | "Base64Url" | "base64_url" => Ok(DnsEncoding::Base64Url),
        other => Err(MirageError::Config(format!(
            "dns_tunnel: unknown encoding '{other}' — expected 'base32' or 'base64url'"
        ))),
    }
}

/// Parse a DNS query type string from `TransportCamouflage::DnsTunnel`.
fn parse_dns_query_type(s: &str) -> Result<DnsQueryType, MirageError> {
    match s {
        "TXT" | "txt" => Ok(DnsQueryType::TXT),
        "NULL" | "null" => Ok(DnsQueryType::NULL),
        other => Err(MirageError::Config(format!(
            "dns_tunnel: unknown query_type '{other}' — expected 'TXT' or 'NULL'"
        ))),
    }
}

/// Convert a `mirage_core::config::AuthMode` into the internal `crate::auth::AuthMode`.
///
/// Both enums have the same shape; this conversion exists because the driver API
/// uses the mirage-core type (no circular dep) while the handshake internals use
/// the mirage-protocol type.
pub fn convert_auth(auth: &AuthMode) -> ProtocolAuthMode {
    match auth {
        AuthMode::None => ProtocolAuthMode::None,
        AuthMode::Blake3 => ProtocolAuthMode::Blake3,
        AuthMode::Hmac => ProtocolAuthMode::Hmac,
        AuthMode::Psk { key_hex } => ProtocolAuthMode::Psk { key_hex: key_hex.clone() },
    }
}

/// Run the Mirage server handshake on a stream (TCP or stream-over-UDP).
/// Returns `None` if auth failed.
pub async fn handshake_server_stream<S>(
    mut stream: S,
    keypair: &KeyPair,
    auth: &ProtocolAuthMode,
    peer_addr: SocketAddr,
    mesh_id: &[u8],
    allow_legacy_v8: bool,
) -> Result<Option<Box<dyn Tunnel>>, MirageError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    match run_server_handshake(&mut stream, keypair, auth, mesh_id, AeadSuite::ChaCha20Poly1305, allow_legacy_v8).await? {
        Some(result) => {
            let info = TransportInfo::tcp_raw(peer_addr);
            let tunnel = MirageCoreTunnel::new(stream, &result.session_keys, false, info, auth.clone());
            Ok(Some(Box::new(tunnel)))
        }
        None => Ok(None),
    }
}

/// Like [`handshake_server_stream`] but threads `client_auth` into the V9 path.
///
/// Returns `None` if auth failed.
pub async fn handshake_server_stream_with_auth<S, F>(
    mut stream: S,
    keypair: &KeyPair,
    auth: &ProtocolAuthMode,
    peer_addr: SocketAddr,
    mesh_id: &[u8],
    client_auth: F,
    allow_legacy_v8: bool,
) -> Result<Option<Box<dyn Tunnel>>, MirageError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
    F: for<'a> Fn(&ClientAuthContext<'a>) -> bool,
{
    match run_server_handshake_with_auth(
        &mut stream,
        keypair,
        auth,
        mesh_id,
        AeadSuite::ChaCha20Poly1305,
        client_auth,
        allow_legacy_v8,
    )
    .await?
    {
        Some(result) => {
            let info = TransportInfo::tcp_raw(peer_addr);
            let tunnel = MirageCoreTunnel::new(stream, &result.session_keys, false, info, auth.clone());
            Ok(Some(Box::new(tunnel)))
        }
        None => Ok(None),
    }
}

/// Perform the V9 client-side handshake on an already-wrapped stream,
/// optionally attaching an anonymous credential frame.
///
/// When `credential` is `Some`, the `V9ClientHello.cred_scheme` byte is set
/// and a `[2B len BE][token]` frame is written after the 97B hello.
/// When `None`, behaviour is byte-identical to a legacy V9 client.
///
/// Returns an authenticated, session-keyed tunnel on success.
async fn handshake_client_stream_v9<S>(
    mut stream: S,
    server_static_pub: &[u8; 32],
    client_static_priv: &[u8; 32],
    server_addr: SocketAddr,
    mesh_id: &[u8],
    suite_prefs: &[AeadSuite],
    auth: &ProtocolAuthMode,
    credential: Option<&ClientCredential>,
) -> Result<Box<dyn Tunnel>, MirageError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    use crate::auth::v9::{
        compute_client_proof, gen_ephemeral, suite_to_id, TargetHint, V9ClientHello,
        WIRE_VERSION_V9, verify_server_proof, compute_transcript_0, id_to_suite, derive_v9_keys,
        V9ServerHello, SERVER_HELLO_LEN, VERSION_REJECT,
    };
    use tokio::io::{AsyncWriteExt, AsyncReadExt};
    use x25519_dalek::{PublicKey, StaticSecret};
    use zeroize::Zeroizing;

    // Build the suite_ids array.
    let mut suite_ids_arr = [0u8; 3];
    for (i, &s) in suite_prefs.iter().take(3).enumerate() {
        suite_ids_arr[i] = suite_to_id(s);
    }

    // Generate client ephemeral key pair.
    let (e_priv_c, e_pub_c) = gen_ephemeral();

    // Timestamp for replay protection.
    let ts_ms = {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64
    };

    // Compute client proof. suite_ids_arr is the exact 3-byte offered list that
    // will appear at ClientHello[1..4], preventing on-path suite-strip.
    let client_proof = compute_client_proof(
        client_static_priv,
        server_static_pub,
        &e_pub_c,
        mesh_id,
        &suite_ids_arr,
        ts_ms,
    );

    // Derive client_static_pub from client_static_priv.
    let client_static_pub = {
        let secret = StaticSecret::from(*client_static_priv);
        PublicKey::from(&secret).to_bytes()
    };

    // Set cred_scheme from the credential if present.
    let cred_scheme = credential.map(|c| c.scheme).unwrap_or(0x00);

    // Build and send ClientHello (97 bytes).
    let hello = V9ClientHello {
        version: WIRE_VERSION_V9,
        suite_ids: suite_ids_arr,
        e_pub_c,
        ts_ms,
        client_proof,
        client_static_pub,
        cred_scheme,
        // No sender in this codebase sets a non-legacy target hint yet — see
        // `mirage_protocol::auth::v9::TargetHint`'s own doc. Routing stays
        // exactly what the face's declared purpose says, precisely as it
        // did before this field existed.
        target_hint: TargetHint::Legacy.to_byte(),
    };
    stream.write_all(&hello.to_wire()).await?;

    // If credential is present, send [2B len BE][token] frame.
    if let Some(cred) = credential {
        let len = cred.token.len() as u16;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(&cred.token).await?;
    }

    // Read ServerHello (81 bytes) or VersionReject (1 byte = 0xFF).
    let mut first_byte = [0u8; 1];
    stream.read_exact(&mut first_byte).await?;
    if first_byte[0] == VERSION_REJECT {
        return Err(mirage_core::error::MirageError::Handshake(
            "V9: server rejected version (VersionReject 0xFF)".into(),
        ));
    }

    let mut rest = [0u8; SERVER_HELLO_LEN - 1];
    stream.read_exact(&mut rest).await?;
    let mut buf = [0u8; SERVER_HELLO_LEN];
    buf[0] = first_byte[0];
    buf[1..].copy_from_slice(&rest);

    let server_hello = V9ServerHello::from_wire(&buf)?;

    let suite = id_to_suite(server_hello.chosen_suite).ok_or_else(|| {
        mirage_core::error::MirageError::Handshake(format!(
            "V9: unknown suite_id 0x{:02x} in ServerHello",
            server_hello.chosen_suite
        ))
    })?;

    let e_pub_s = PublicKey::from(server_hello.e_pub_s);
    let ecdh_ee = Zeroizing::new(e_priv_c.diffie_hellman(&e_pub_s).to_bytes());

    let transcript_0 = compute_transcript_0(
        &e_pub_c,
        &server_hello.e_pub_s,
        mesh_id,
        server_hello.chosen_suite,
        ts_ms,
    );

    verify_server_proof(&ecdh_ee, &transcript_0, server_static_pub, &server_hello.server_proof)?;

    let session_keys = derive_v9_keys(&ecdh_ee, &transcript_0, suite);

    let info = TransportInfo::tcp_raw(server_addr);
    let tunnel = MirageCoreTunnel::new(stream, &session_keys, true, info, auth.clone());
    Ok(Box::new(tunnel))
}

/// Perform the client-side UDP-camouflage connect + Mirage handshake.
///
/// `mesh_id` — mesh identifier bytes baked into the Blake3 confirm label.
///
/// Mirrors `run_client_tcp` but for UDP-based camouflages (QUIC,
/// WireGuard, Http3, raw UDP, DnsTunnel, Icmp, WebTransport). Each layer's
/// `connect_client` returns a stream adapter (`AsyncRead + AsyncWrite`); we
/// run the same Mirage handshake on top.
///
/// Use this when `MirageEndpointConfig.transport == TransportKind::Udp`.
/// TCP-only camouflages (TlsReal, WebSocket, Reality, Ssh, Grpc) error out
/// here — call `run_client_tcp` instead.
pub async fn run_client_udp(
    config: &MirageEndpointConfig,
    server_addr: SocketAddr,
    server_pubkey: &[u8; 32],
    sni: &str,
    mesh_id: &[u8],
) -> Result<Box<dyn Tunnel>, MirageError> {
    if config.transport != TransportKind::Udp {
        return Err(MirageError::Config(
            "run_client_udp: config transport must be Udp".into(),
        ));
    }
    let auth = convert_auth(&config.auth);

    match &config.camouflage {
        TransportCamouflage::Quic { alpn, .. } => {
            let layer = QuicCamouflage::new(alpn.clone())?;
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream(stream, server_pubkey, &auth, server_addr, mesh_id).await
        }
        TransportCamouflage::Hysteria2 { .. } => Err(MirageError::Config(
            "hysteria2 is not part of the mask set any more".to_owned(),
        )),
        TransportCamouflage::WireGuard {
            magic_byte,
            junk_count,
            junk_min,
            junk_max,
            ..
        } => {
            let layer =
                WireGuardCamouflage::new(*magic_byte, *junk_count, *junk_min, *junk_max);
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream(stream, server_pubkey, &auth, server_addr, mesh_id).await
        }
        TransportCamouflage::Http3 { alpn, authority, tunnel_path, .. } => {
            let layer = Http3Camouflage::new(authority.clone(), tunnel_path.clone(), alpn.clone())?;
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream(stream, server_pubkey, &auth, server_addr, mesh_id).await
        }
        TransportCamouflage::DnsTunnel { domain, encoding, query_type, .. } => {
            let enc = parse_dns_encoding(encoding)?;
            let qt = parse_dns_query_type(query_type)?;
            let layer = DnsTunnelCamouflage::new(domain.clone(), enc, qt);
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream(stream, server_pubkey, &auth, server_addr, mesh_id).await
        }
        TransportCamouflage::Icmp { peer_addr, identifier, mtu } => {
            let layer = IcmpCamouflage::new(*peer_addr, *identifier, *mtu);
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream(stream, server_pubkey, &auth, server_addr, mesh_id).await
        }
        TransportCamouflage::WebTransport { path, authority, .. } => {
            let layer = WebTransportCamouflage::new(path.clone(), authority.clone())?;
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream(stream, server_pubkey, &auth, server_addr, mesh_id).await
        }
        TransportCamouflage::RawUdp { .. } => {
            // Honour `MirageEndpointConfig.byte_cipher_mode` on the client
            // wrap path: outbound datagrams get wrapped via the per-adapter
            // ByteCipher (peeled by L1 `udp_crypto_verify`). Other UDP
            // camouflages have their own outer framing — byte_cipher_mode
            // is ignored there.
            let layer = RawUdpCamouflage::with_cipher(config.byte_cipher_mode.clone());
            let stream = layer.connect_client(server_addr, sni).await?;
            handshake_client_stream(stream, server_pubkey, &auth, server_addr, mesh_id).await
        }
        // TCP-only camouflages.
        TransportCamouflage::None
        | TransportCamouflage::TlsReal { .. }
        | TransportCamouflage::WebSocket { .. }
        | TransportCamouflage::Xhttp { .. }
        | TransportCamouflage::Reality { .. }
        | TransportCamouflage::Ssh { .. }
        | TransportCamouflage::Grpc { .. } => Err(MirageError::Config(
            "run_client_udp: TCP-only camouflage — use run_client_tcp instead"
                .into(),
        )),
    }
}

/// Run the Mirage client handshake on a stream (TCP or stream-over-UDP).
async fn handshake_client_stream<S>(
    mut stream: S,
    server_pubkey: &[u8; 32],
    auth: &ProtocolAuthMode,
    server_addr: SocketAddr,
    mesh_id: &[u8],
) -> Result<Box<dyn Tunnel>, MirageError>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + Sync + 'static,
{
    let result = run_client_handshake(&mut stream, server_pubkey, auth, mesh_id, AeadSuite::ChaCha20Poly1305).await?;
    let info = TransportInfo::tcp_raw(server_addr);
    let tunnel = MirageCoreTunnel::new(stream, &result.session_keys, true, info, auth.clone());
    Ok(Box::new(tunnel))
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests — connect-bound (2026-07-30)
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A refused connect (port definitively closed, kernel answers RST
    /// immediately) must surface as `MirageError::Io`, never
    /// `NodeUnreachable` — this is the "refused" half of the "timed out and
    /// refused are different diagnoses" contract `tcp_connect_bounded`'s doc
    /// makes. Binding an ephemeral loopback port and dropping the listener
    /// before dialing it is a fully deterministic, network-free way to
    /// produce a real refused connect (no external network dependency, no
    /// timing assumption).
    #[tokio::test]
    async fn tcp_connect_bounded_reports_refused_connect_as_io() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().expect("local_addr of bound listener");
        drop(listener); // port is now definitively closed — any connect gets ECONNREFUSED

        match tcp_connect_bounded(addr, Duration::from_secs(5)).await {
            Err(MirageError::Io(_)) => {}
            other => panic!(
                "expected MirageError::Io for a refused connect, got: {other:?}"
            ),
        }
    }

    /// A connect that completes within the bound must return `Ok` with a
    /// usable stream — the bound must never fire early on a healthy,
    /// immediately-accepting peer. Loopback-only, no external network.
    #[tokio::test]
    async fn tcp_connect_bounded_succeeds_within_the_bound() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().expect("local_addr of bound listener");

        // Accept the one incoming connection in the background so the
        // connect side actually completes the three-way handshake.
        let accept_task = tokio::spawn(async move {
            let _ = listener.accept().await;
        });

        let result = tcp_connect_bounded(addr, Duration::from_secs(5)).await;
        assert!(result.is_ok(), "connect to an accepting local listener must succeed");
        accept_task.await.expect("accept task must not panic");
    }

    /// A connect that never completes within the bound must fail with a
    /// NAMED `NodeUnreachable("... timed out ...")` error, not hang forever
    /// and not surface as a generic `Io` error indistinguishable from a
    /// refused connect. Uses `start_paused` virtual time: 192.0.2.1 is
    /// TEST-NET-1 (RFC 5737), reserved for documentation/testing and never
    /// routed on the real internet, so a real connect attempt to it neither
    /// completes nor is actively refused — it simply sits pending. Because
    /// the clock is paused, this test never actually waits on that pending
    /// I/O in wall-clock time: advancing the virtual clock past the bound
    /// fires the internal sleep `tokio::time::timeout` races the connect
    /// against, which wins the race deterministically regardless of how
    /// long the real connect would otherwise take to resolve (or never
    /// resolve at all).
    #[tokio::test(start_paused = true)]
    async fn tcp_connect_bounded_times_out_with_a_named_error() {
        let addr: SocketAddr = "192.0.2.1:9".parse().expect("valid SocketAddr literal");
        let bound = Duration::from_millis(50);

        let dial = tokio::spawn(async move { tcp_connect_bounded(addr, bound).await });
        tokio::time::advance(bound + Duration::from_millis(10)).await;
        let result = dial.await.expect("dial task must not panic");

        match result {
            Err(MirageError::NodeUnreachable(msg)) => {
                assert!(
                    msg.contains("timed out"),
                    "error message must name the timeout explicitly, got: {msg}"
                );
            }
            other => panic!(
                "expected MirageError::NodeUnreachable naming a timeout, got: {other:?}"
            ),
        }
    }

    /// `run_client_tcp_v9`'s own signature carries no connect-timeout
    /// parameter — every existing caller keeps compiling unchanged. The
    /// override path is the separate `_with_connect_timeout` fn, not a new
    /// required argument on the common path. This test only asserts the
    /// default constant itself stays sane (positive, and matching the
    /// documented value) — a regression anchor, not a network test.
    #[test]
    fn default_client_connect_timeout_matches_documented_value() {
        assert_eq!(DEFAULT_CLIENT_CONNECT_TIMEOUT, Duration::from_secs(10));
    }

    /// Same regression anchor as the connect-timeout constant, for the new
    /// handshake-timeout constant — and that the two stay genuinely
    /// distinct values, not accidentally collapsed into one shared bound.
    #[test]
    fn default_client_handshake_timeout_matches_documented_value_and_differs_from_connect() {
        assert_eq!(DEFAULT_CLIENT_HANDSHAKE_TIMEOUT, Duration::from_secs(20));
        assert_ne!(DEFAULT_CLIENT_HANDSHAKE_TIMEOUT, DEFAULT_CLIENT_CONNECT_TIMEOUT);
    }

    /// A peer that accepts the TCP connection and then never sends anything
    /// back must fail with a NAMED `HandshakeTimedOut` error within the
    /// handshake bound — never hang forever, never surface as a generic
    /// `Io` error, and never surface as `MirageError::NodeUnreachable`
    /// (that name is reserved for a connect-phase failure; TCP connect
    /// already succeeded here). Real wall-clock time (not `start_paused`):
    /// the client writes its real `V9ClientHello` over a real loopback
    /// socket, so real bytes must actually cross the wire before the race
    /// against `handshake_timeout` even starts.
    #[tokio::test]
    async fn handshake_timeout_is_named_distinct_from_connect_timeout_and_releases_the_socket() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral loopback port");
        let addr = listener.local_addr().expect("local_addr of bound listener");

        // Accept the connection and hold it open, silent, well past the
        // handshake bound under test — exactly "peer accepted TCP and never
        // answered". `accepted` owns the stream so it isn't closed early by
        // being dropped, which would let the client fail some OTHER way
        // (a clean EOF) instead of exercising the timeout path.
        let accepted = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("accept must succeed");
            tokio::time::sleep(Duration::from_secs(5)).await;
            drop(stream);
        });

        let config = mirage_core::config::MirageEndpointConfig {
            transport: mirage_core::config::TransportKind::Tcp,
            auth: mirage_core::config::AuthMode::Blake3,
            camouflage: TransportCamouflage::None,
            byte_cipher: None,
            byte_cipher_mode: None,
        };
        let server_static_pub = [0u8; 32];
        let client_static_priv = [1u8; 32];
        let handshake_bound = Duration::from_millis(200);

        let started = std::time::Instant::now();
        let result = run_client_tcp_v9_with_timeouts(
            &config,
            addr,
            &server_static_pub,
            &client_static_priv,
            "",
            b"test-mesh",
            None,
            Duration::from_secs(5),
            handshake_bound,
        )
        .await;
        let elapsed = started.elapsed();

        match result {
            Ok(_) => panic!("expected Err(HandshakeTimedOut), got Ok(_) (a real tunnel?!)"),
            Err(MirageError::HandshakeTimedOut(msg)) => {
                assert!(
                    msg.contains("timed out"),
                    "error message must name the timeout explicitly, got: {msg}"
                );
            }
            Err(other) => panic!("expected MirageError::HandshakeTimedOut, got: {other:?}"),
        }
        // The dial must fail at roughly `handshake_bound`, not wait out the
        // server's 5s silent hold — proves the in-flight handshake future
        // (and the socket + task it owns) was actually dropped on timeout
        // rather than left parked until the peer eventually goes away.
        assert!(
            elapsed < Duration::from_secs(2),
            "handshake bound must fire promptly, not wait out the server's hold; elapsed={elapsed:?}"
        );

        accepted.abort();
    }
}

/// `CredentialScheme::RoleSigned` riding the V9 hello's generic credential
/// slot (`ClientCredential { scheme, token }`, wire byte 92 +
/// `[2B len BE][token]`) — no wire-format change needed here (the plan's own
/// call-out: the slot already exists and the driver's credential-attach path
/// needs no new logic), so this proves the round trip through the EXISTING
/// generic mechanism rather than adding one.
#[cfg(test)]
mod role_signed_v9_credential_slot_tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use mirage_core::identity::ServiceRole;
    use mirage_core::mirage::wire::CredentialScheme;
    use rand::rngs::OsRng;

    const EXIT_NODE_ID: &str = "exit-42";
    const NOW_MS: u64 = 3_000_000_000_000;

    fn make_token() -> mirage_core::crypto::credential::role_signed::RoleSignedToken {
        use mirage_core::capsule::RoleSlice;
        use mirage_core::crypto::credential::role_signed::{mint_role_signed_token, sign_role_signed_excerpt};

        let operator_signing = SigningKey::generate(&mut OsRng);
        let edge_signing = SigningKey::generate(&mut OsRng);
        let edge_signing_pub_hex = hex::encode(edge_signing.verifying_key().to_bytes());

        let slice = RoleSlice {
            role: ServiceRole::Edge,
            wire_privkey: [0x22u8; 32],
            signing_privkey: Some(edge_signing.to_bytes()),
            wire_pubkey_hex: "bb".repeat(32),
            signing_pubkey_hex: Some(edge_signing_pub_hex.clone()),
        };

        let excerpt = sign_role_signed_excerpt(
            &operator_signing,
            uuid::Uuid::new_v4(),
            "v3-staging",
            ServiceRole::Edge,
            &edge_signing_pub_hex,
            NOW_MS + 3_600_000,
        )
        .expect("Edge excerpt must sign");

        mint_role_signed_token(&slice, &excerpt, EXIT_NODE_ID, NOW_MS).expect("mint must succeed")
    }

    /// `V9ClientHello.cred_scheme` carries `CredentialScheme::RoleSigned`'s
    /// wire byte byte-identically through `to_wire`/`from_wire`, exactly like
    /// every other scheme byte — this type does not interpret the byte, only
    /// carries it (see [`V9ClientHello::cred_scheme`]'s own doc).
    #[test]
    fn cred_scheme_byte_round_trips_through_the_hello() {
        use crate::auth::v9::{TargetHint, V9ClientHello, WIRE_VERSION_V9};

        let hello = V9ClientHello {
            version: WIRE_VERSION_V9,
            suite_ids: [0, 0, 0],
            e_pub_c: [0u8; 32],
            ts_ms: NOW_MS,
            client_proof: [0u8; 16],
            client_static_pub: [0u8; 32],
            cred_scheme: CredentialScheme::RoleSigned.as_u8(),
            target_hint: TargetHint::Legacy.to_byte(),
        };
        let wire = hello.to_wire();
        assert_eq!(wire[92], 0x05);

        let decoded = V9ClientHello::from_wire(&wire).expect("decode");
        assert_eq!(
            CredentialScheme::from_byte(decoded.cred_scheme).expect("known scheme byte"),
            CredentialScheme::RoleSigned
        );
    }

    /// The full `[2B len BE][token]` frame `ClientCredential` describes:
    /// build a real `RoleSignedToken`, encode it as the credential's `token`
    /// bytes, confirm it fits the frame's own 16-bit length prefix, and
    /// decode it back to an equal token — the exact round trip a real V9
    /// dial performs on the wire.
    #[test]
    fn role_signed_token_round_trips_through_the_client_credential_frame() {
        use mirage_core::crypto::credential::role_signed::RoleSignedToken;

        let token = make_token();
        let token_bytes = token.encode().expect("token encode");

        let credential = ClientCredential {
            scheme: CredentialScheme::RoleSigned.as_u8(),
            token: token_bytes.clone(),
        };

        assert!(
            u16::try_from(credential.token.len()).is_ok(),
            "token must fit the frame's 2B length prefix"
        );
        assert_eq!(credential.scheme, 0x05);

        // What `handshake_client_stream_v9` actually writes to the wire.
        let mut wire_frame = Vec::new();
        wire_frame.extend_from_slice(&(credential.token.len() as u16).to_be_bytes());
        wire_frame.extend_from_slice(&credential.token);

        // What the server side reads: 2B len, then exactly that many bytes.
        let len = u16::from_be_bytes([wire_frame[0], wire_frame[1]]) as usize;
        let read_back = &wire_frame[2..2 + len];
        assert_eq!(read_back, token_bytes.as_slice());

        let decoded = RoleSignedToken::decode(read_back).expect("token decode");
        assert_eq!(decoded.self_id, token.self_id);
        assert_eq!(decoded.mesh_id, token.mesh_id);
        assert_eq!(decoded.role, token.role);
        assert_eq!(decoded.exit_node_id, token.exit_node_id);
        assert_eq!(decoded.nonce, token.nonce);
        assert_eq!(decoded.ts_ms, token.ts_ms);
        assert_eq!(decoded.dial_sig, token.dial_sig);
    }
}
