//! Two-axis listener pipeline — outer camouflage × inner relay mode.
//!
//! The Mirage stack is built on two orthogonal axes:
//!
//! 1. **Outer `TransportCamouflage`** — anti-DPI wire wrapping (TLS / WS /
//!    Xhttp / Reality / SSH / gRPC / raw TCP).
//! 2. **Inner relay mode** — what the node does with the stripped bytes
//!    (`transparent` byte-pump forward, `crypto_verify` byte-cipher peel +
//!    forward, `onion_peel` per-hop AEAD layer strip).
//!
//! Until this module landed the two axes were conflated in `run_server_tcp`:
//! camouflage strip + Mirage handshake were a single fused dispatch. Other
//! modes (`onion_peel`) bypassed camouflage entirely and only accepted raw
//! TCP. The pipeline helpers below extract the camouflage strip / wrap
//! steps so every inner mode can opt into outer camouflage without
//! duplicating per-wire dispatch tables.
//!
//! Wire layering (server, accept direction):
//!
//! ```text
//! TcpStream
//!   ↓ strip_tcp_server(camouflage)
//! Box<dyn BidiStream>      ← outer wrapper peeled
//!   ↓ (caller decides)     ← byte_cipher peel / onion peel / Mirage handshake
//! Inner protocol bytes
//! ```
//!
//! Client direction is symmetric via `wrap_tcp_client`.
//!
//! UDP / canonical UDP camouflages stay in `run_server_udp` /
//! `run_client_udp` — they own their own endpoint and don't accept a raw
//! `TcpStream` to start with.

use std::net::SocketAddr;

use mirage_core::{config::TransportCamouflage, crypto::KeyPair, error::MirageError};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;

use super::{
    none::NoCamouflage, reality::RealityServerCamouflage, xhttp::XhttpCamouflage, CamouflageLayer,
};
use crate::protocols::l5::tls::TlsRealCamouflage;
use crate::protocols::l7::websocket::WebSocketCamouflage;

#[cfg(feature = "grpc")]
use crate::protocols::l7::grpc::GrpcCamouflage;
#[cfg(feature = "ssh")]
use crate::protocols::l7::ssh::SshCamouflage;

/// Bidirectional async-IO trait object. Object-safe by construction —
/// every concrete camouflage adapter implements it.
///
/// `Sync` is included so consumers can hold `Box<dyn BidiStream>` inside
/// a `Tunnel` (which requires `Send + Sync` per `mirage_protocol::traits`).
pub trait BidiStream: AsyncRead + AsyncWrite + Unpin + Send + Sync {}
impl<T> BidiStream for T where T: AsyncRead + AsyncWrite + Unpin + Send + Sync {}

/// Stream wrapper that prepends a fixed byte prefix before delegating to
/// the inner stream.
///
/// Used by Phase 3 of the two-axis pipeline: after `strip_tcp_server`
/// peels the outer camouflage, the listener reads + `unwrap_peeked`s the
/// first chunk to strip a byte_cipher layer. The unwrapped bytes need to
/// flow into the next consumer (Mirage handshake / onion peel) as if they
/// had arrived first on the wire — `PrefixedStream` provides that without
/// changing the consumer's API.
///
/// Once the prefix is drained, reads/writes pass through unchanged.
pub struct PrefixedStream<S> {
    prefix: Vec<u8>,
    prefix_pos: usize,
    inner: S,
}

impl<S> PrefixedStream<S> {
    /// Wrap `inner` with a `prefix` buffer that is delivered to readers
    /// before the inner stream's bytes.
    pub fn new(prefix: Vec<u8>, inner: S) -> Self {
        Self {
            prefix,
            prefix_pos: 0,
            inner,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for PrefixedStream<S> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.prefix_pos < this.prefix.len() {
            let remaining = &this.prefix[this.prefix_pos..];
            let n = remaining.len().min(buf.remaining());
            buf.put_slice(&remaining[..n]);
            this.prefix_pos += n;
            return std::task::Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for PrefixedStream<S> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }
    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Strip the configured outer TCP camouflage from `stream`.
///
/// Returns `Ok(Some(stripped))` on success, `Ok(None)` if the camouflage
/// layer rejected the connection (e.g. wrong SNI / unexpected handshake —
/// the caller may forward to a decoy backend), or `Err` on protocol error.
///
/// `keypair` is consumed by camouflages that need it server-side (Reality
/// derives a TLS session from the node's X25519 keypair); ignored by
/// camouflages that don't (`None` / TLS / WS / Xhttp / SSH / gRPC).
///
/// UDP / canonical UDP camouflages return `Err(Config)` — they don't
/// operate on a raw `TcpStream`; use `run_server_udp` for those.
pub async fn strip_tcp_server(
    stream: TcpStream,
    camouflage: &TransportCamouflage,
    keypair: &KeyPair,
) -> Result<Option<Box<dyn BidiStream>>, MirageError> {
    match camouflage {
        TransportCamouflage::None => {
            let layer = NoCamouflage;
            Ok(layer
                .wrap_server(stream)
                .await?
                .map(|s| Box::new(s) as Box<dyn BidiStream>))
        }
        TransportCamouflage::TlsReal { sni, alpn } => {
            let layer = TlsRealCamouflage::new(sni.clone(), alpn.clone(), None, None)?;
            Ok(layer
                .wrap_server(stream)
                .await?
                .map(|s| Box::new(s) as Box<dyn BidiStream>))
        }
        TransportCamouflage::WebSocket { path, host } => {
            let layer = WebSocketCamouflage::new(path.clone(), host.clone());
            Ok(layer
                .wrap_server(stream)
                .await?
                .map(|s| Box::new(s) as Box<dyn BidiStream>))
        }
        TransportCamouflage::Xhttp { path, host } => {
            let layer = XhttpCamouflage::new(path.clone(), host.clone());
            Ok(layer
                .wrap_server(stream)
                .await?
                .map(|s| Box::new(s) as Box<dyn BidiStream>))
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
            Ok(layer
                .wrap_server(stream)
                .await?
                .map(|s| Box::new(s) as Box<dyn BidiStream>))
        }
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
                Ok(layer
                    .wrap_server(stream)
                    .await?
                    .map(|s| Box::new(s) as Box<dyn BidiStream>))
            }
            #[cfg(not(feature = "ssh"))]
            {
                let _ = (
                    ssh_user,
                    ssh_host_key,
                    ssh_private_key,
                    ssh_password,
                    forward_host,
                    forward_port,
                    stream,
                );
                Err(MirageError::Config(
                    "strip_tcp_server: SSH camouflage requires the `ssh` feature flag".into(),
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
                Ok(layer
                    .wrap_server(stream)
                    .await?
                    .map(|s| Box::new(s) as Box<dyn BidiStream>))
            }
            #[cfg(not(feature = "grpc"))]
            {
                let _ = (service_name, method_name, authority, use_tls, stream);
                Err(MirageError::Config(
                    "strip_tcp_server: gRPC camouflage requires the `grpc` feature flag".into(),
                ))
            }
        }
        TransportCamouflage::Quic { .. }
        | TransportCamouflage::Http3 { .. }
        | TransportCamouflage::Hysteria2 { .. }
        | TransportCamouflage::WireGuard { .. }
        | TransportCamouflage::DnsTunnel { .. }
        | TransportCamouflage::Icmp { .. }
        | TransportCamouflage::WebTransport { .. }
        | TransportCamouflage::RawUdp { .. } => Err(MirageError::Config(
            "strip_tcp_server: UDP camouflage cannot be applied to a raw TcpStream".into(),
        )),
    }
}

/// Return the SNI/host embedded inside a [`TransportCamouflage`] variant.
///
/// Used by [`wrap_tcp_client`] to fall back to the variant's own host when the
/// caller-supplied `sni` is empty (e.g. `HopConfig.sni` is unpopulated on the
/// onion-tunnel-fs path).  This ensures the correct on-wire ServerName /
/// `Host` header is used even when the dial-core materialize path does not
/// explicitly propagate SNI into the hop.
///
/// Returns `""` for variants that are not TCP-wrapped (UDP camos) or that
/// carry no textual host (Reality — it uses a separate `server_name` field but
/// `RealityClientCamouflage` does not use the sni arg at all; Ssh/Grpc also
/// ignore the sni arg internally).
fn camo_embedded_sni(cam: &TransportCamouflage) -> &str {
    match cam {
        TransportCamouflage::TlsReal { sni, .. } => sni.as_str(),
        TransportCamouflage::WebSocket { host, .. } => host.as_str(),
        TransportCamouflage::Xhttp { host, .. } => host.as_str(),
        TransportCamouflage::Reality { server_name, .. } => server_name.as_str(),
        TransportCamouflage::Grpc { authority, .. } => authority.as_str(),
        // SSH carries `forward_host` but wrap_client ignores sni entirely; ""
        // is safe here because SshCamouflage::wrap_client takes `_sni`.
        TransportCamouflage::Ssh { .. } => "",
        // UDP camos and None have no relevant host for the TCP wrap path.
        _ => "",
    }
}

/// Open a TCP connection to `addr` and apply the configured outer
/// camouflage.
///
/// Counterpart to [`strip_tcp_server`]. Returns a generic `BidiStream`
/// trait object so onion / pool / handshake callers can chain through any
/// configured outer camouflage uniformly.
///
/// `server_pubkey` is consumed by camouflages that need the server's
/// long-term X25519 key client-side (Reality derives its TLS-mimic session
/// from it); ignored by camouflages that don't.
///
/// `sni` is the caller-supplied SNI override (e.g. from `HopConfig.sni`).
/// When empty the camouflage variant's own embedded host/sni is used instead,
/// so onion dials where `HopConfig.sni` is unpopulated still present the
/// correct on-wire server name.
pub async fn wrap_tcp_client(
    addr: SocketAddr,
    camouflage: &TransportCamouflage,
    server_pubkey: &[u8; 32],
    sni: &str,
) -> Result<Box<dyn BidiStream>, MirageError> {
    // Resolve effective SNI once: prefer caller-supplied, fall back to the
    // host/sni embedded in the camouflage variant.  This fixes the
    // credential-under-camo dial blocker (P4.2) where onion_tunnel_fs passes
    // an empty sni because materialize.rs never populates HopConfig.sni.
    let effective_sni = if sni.is_empty() { camo_embedded_sni(camouflage) } else { sni };

    let stream = TcpStream::connect(addr).await.map_err(MirageError::Io)?;
    match camouflage {
        TransportCamouflage::None => Ok(Box::new(stream)),
        TransportCamouflage::TlsReal { sni: cam_sni, alpn } => {
            let layer = TlsRealCamouflage::new(cam_sni.clone(), alpn.clone(), None, None)?;
            Ok(Box::new(layer.wrap_client(stream, effective_sni).await?))
        }
        TransportCamouflage::WebSocket { path, host } => {
            let layer = WebSocketCamouflage::new(path.clone(), host.clone());
            Ok(Box::new(layer.wrap_client(stream, effective_sni).await?))
        }
        TransportCamouflage::Xhttp { path, host } => {
            let layer = XhttpCamouflage::new(path.clone(), host.clone());
            Ok(Box::new(layer.wrap_client(stream, effective_sni).await?))
        }
        TransportCamouflage::Reality { short_id, .. } => {
            use super::reality::RealityClientCamouflage;
            let layer = RealityClientCamouflage::new(*server_pubkey, short_id.as_str())?;
            Ok(Box::new(layer.wrap_client(stream, effective_sni).await?))
        }
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
                Ok(Box::new(layer.wrap_client(stream, effective_sni).await?))
            }
            #[cfg(not(feature = "ssh"))]
            {
                let _ = (
                    ssh_user,
                    ssh_host_key,
                    ssh_private_key,
                    ssh_password,
                    forward_host,
                    forward_port,
                    stream,
                );
                Err(MirageError::Config(
                    "wrap_tcp_client: SSH camouflage requires the `ssh` feature flag".into(),
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
                Ok(Box::new(layer.wrap_client(stream, effective_sni).await?))
            }
            #[cfg(not(feature = "grpc"))]
            {
                let _ = (service_name, method_name, authority, use_tls, stream);
                Err(MirageError::Config(
                    "wrap_tcp_client: gRPC camouflage requires the `grpc` feature flag".into(),
                ))
            }
        }
        TransportCamouflage::Quic { .. }
        | TransportCamouflage::Http3 { .. }
        | TransportCamouflage::Hysteria2 { .. }
        | TransportCamouflage::WireGuard { .. }
        | TransportCamouflage::DnsTunnel { .. }
        | TransportCamouflage::Icmp { .. }
        | TransportCamouflage::WebTransport { .. }
        | TransportCamouflage::RawUdp { .. } => Err(MirageError::Config(
            "wrap_tcp_client: UDP camouflage cannot wrap a raw TcpStream — \
             use run_client_udp instead"
                .into(),
        )),
    }
}
