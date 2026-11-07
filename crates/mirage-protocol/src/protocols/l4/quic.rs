//! Camouflage layer — QUIC outer transport via quinn.
//!
//! QUIC (UDP under the hood) with built-in TLS 1.3.  A single bidirectional
//! stream is opened per connection and adapted to `AsyncRead + AsyncWrite`
//! so the standard stream-based `MirageCoreTunnel` can run on top.
//!
//! # Certificate verification
//!
//! TLS peer certificate verification is intentionally **skipped** via
//! `NoopCertVerifier` — this is **by design**.
//! Security is provided by the inner Mirage X25519 + BLAKE3 handshake.
//! The outer QUIC/TLS layer exists only for traffic camouflage and DPI evasion.
//! Unauthenticated probers receive a TLS error at the QUIC layer (before any
//! Mirage bytes are exchanged), making the server fingerprint indistinguishable
//! from a standard QUIC endpoint.
//!
//! # Integration with `UdpCamouflageLayer`
//!
//! `QuicCamouflage` implements `UdpCamouflageLayer` (not `CamouflageLayer`) because
//! QUIC uses UDP, not TCP.  `connect_client` / `accept_server` bypass the `TcpStream`
//! parameter entirely and manage their own `quinn::Endpoint`.
//!
//! The returned `QuicStreamAdapter` wraps a `quinn` bidirectional stream and
//! implements `AsyncRead + AsyncWrite + Unpin`, making it a drop-in for the
//! stream-based Mirage handshake and `MirageCoreTunnel`.

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use mirage_core::error::MirageError;
use quinn::{Connection, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::camouflage::{private, UdpCamouflageLayer};

// ─────────────────────────────────────────────────────────────────────────────
// TLS helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a self-signed TLS certificate and key for the server endpoint.
///
/// Returns `(cert_der, key_der)`.  The certificate subject is `"mirage.local"`.
/// Every server instance gets a unique certificate; clients skip verification
/// (see `NoopCertVerifier`).
pub fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), MirageError> {
    generate_self_signed_cert_with_sans(&["mirage.local".to_owned()])
}

/// Generate a self-signed TLS certificate covering the supplied Subject
/// Alternative Names. Used when a foreign client validates the cert's SAN
/// against its configured SNI (e.g. iOS Streisand/Karing rejecting hysteria2
/// terminators whose cert SAN doesn't match the URI's `sni=` param even when
/// `insecure=1` — `bad_certificate` TLS Alert 42).
pub fn generate_self_signed_cert_with_sans(
    sans: &[String],
) -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), MirageError> {
    let list: Vec<String> = if sans.is_empty() {
        vec!["mirage.local".to_owned()]
    } else {
        sans.to_vec()
    };
    let certified = rcgen::generate_simple_self_signed(list)
        .map_err(|e| MirageError::Config(format!("rcgen self-signed: {e}")))?;
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(certified.key_pair.serialize_der())
        .map_err(|e| MirageError::Config(format!("rcgen private key: {e}")))?;
    Ok((cert, key))
}

/// Build a `quinn::ServerConfig` from the supplied DER certificate and key.
pub fn build_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    alpn: &[String],
) -> Result<quinn::ServerConfig, MirageError> {
    build_server_config_with(cert, key, alpn, None)
}

/// Build a `quinn::ServerConfig` that can also carry datagrams.
///
/// `datagram_buffer` — the size of the incoming datagram buffer. `Some(..)`
/// turns the DATAGRAM frame (RFC 9221) ON: the endpoint then advertises
/// `max_datagram_frame_size` and accepts whole IP packets in datagrams.
/// `None` leaves datagrams off, which is what a stream-only carrier wants.
pub fn build_server_config_with(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
    alpn: &[String],
    datagram_buffer: Option<usize>,
) -> Result<quinn::ServerConfig, MirageError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| MirageError::Config(format!("rustls server builder: {e}")))?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .map_err(|e| MirageError::Config(format!("rustls server cert: {e}")))?;

    tls.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

    let mut cfg = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)
            .map_err(|e| MirageError::Config(format!("quinn server config: {e}")))?,
    ));
    cfg.transport_config(Arc::new({
        let mut tc = quinn::TransportConfig::default();
        tc.max_idle_timeout(Some(
            std::time::Duration::from_secs(120)
                .try_into()
                .expect("120 s fits in VarInt"),
        ));
        if let Some(size) = datagram_buffer {
            tc.datagram_receive_buffer_size(Some(size));
        }
        tc
    }));
    Ok(cfg)
}

/// Build a `quinn::ClientConfig` that skips TLS certificate verification.
///
/// # Security note
///
/// `NoopCertVerifier` is intentional — **by design**.
/// Authentication is performed at the Mirage handshake layer (X25519 + BLAKE3).
/// The TLS layer is purely for traffic camouflage.
pub fn build_client_config(alpn: &[String]) -> Result<quinn::ClientConfig, MirageError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| MirageError::Config(format!("rustls client builder: {e}")))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoopCertVerifier))
    .with_no_client_auth();

    tls.alpn_protocols = alpn.iter().map(|s| s.as_bytes().to_vec()).collect();

    Ok(quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| MirageError::Config(format!("quinn client config: {e}")))?,
    )))
}

// ─────────────────────────────────────────────────────────────────────────────
// NoopCertVerifier — intentional, by design
// ─────────────────────────────────────────────────────────────────────────────

/// Certificate verifier that accepts any certificate.
///
/// This is intentional — **by design**.
/// Security is provided by the inner Mirage handshake (X25519 ECDH + BLAKE3).
/// The QUIC TLS layer exists only for DPI camouflage; PKI verification would
/// break the self-signed certificate workflow.
#[derive(Debug)]
struct NoopCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoopCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QuicCamouflage
// ─────────────────────────────────────────────────────────────────────────────

/// QUIC transport-level camouflage.
///
/// Manages a pre-built server TLS config (generated at construction time so the
/// certificate is not regenerated per connection) and a client config with
/// `NoopCertVerifier`.
///
/// Each call to `connect_client` creates a new `quinn::Endpoint`; each call to
/// `accept_server` binds a fresh `quinn::Endpoint` on `bind_addr` and accepts
/// one incoming connection.
pub struct QuicCamouflage {
    client_config: quinn::ClientConfig,
    server_config: quinn::ServerConfig,
    alpn: Vec<String>,
}

impl QuicCamouflage {
    /// Create a new `QuicCamouflage`.
    ///
    /// * `alpn` — ALPN protocol identifiers (e.g. `["h3"]`).
    ///
    /// A fresh self-signed TLS certificate is generated for the server endpoint.
    pub fn new(alpn: Vec<String>) -> Result<Self, MirageError> {
        let (cert, key) = generate_self_signed_cert()?;
        let server_config = build_server_config(cert, key, &alpn)?;
        let client_config = build_client_config(&alpn)?;
        Ok(Self { client_config, server_config, alpn })
    }

    /// Return the configured ALPN identifiers.
    pub fn alpn(&self) -> &[String] {
        &self.alpn
    }
}

impl private::Sealed for QuicCamouflage {}

#[async_trait]
impl UdpCamouflageLayer for QuicCamouflage {
    type Stream = QuicStreamAdapter;

    /// Client: bind an ephemeral UDP endpoint and connect to `server_addr`.
    ///
    /// `sni` is used as the TLS server name in the QUIC ClientHello.  If empty,
    /// falls back to `"mirage.local"`.
    ///
    /// Opens one bidirectional stream and returns a `QuicStreamAdapter`.
    async fn connect_client(
        &self,
        server_addr: SocketAddr,
        sni: &str,
    ) -> Result<QuicStreamAdapter, MirageError> {
        let mut transport = quinn::TransportConfig::default();
        transport.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
        transport.max_idle_timeout(Some(
            std::time::Duration::from_secs(120)
                .try_into()
                .expect("120 s fits in VarInt"),
        ));

        let mut client_cfg = self.client_config.clone();
        client_cfg.transport_config(Arc::new(transport));

        let mut endpoint =
            quinn::Endpoint::client("0.0.0.0:0".parse().expect("valid loopback addr"))
                .map_err(MirageError::Io)?;
        endpoint.set_default_client_config(client_cfg);

        let sni_name = if sni.is_empty() { "mirage.local" } else { sni };
        let connection: Connection = endpoint
            .connect(server_addr, sni_name)
            .map_err(|e| MirageError::Protocol(format!("quic connect: {e}")))?
            .await
            .map_err(|e| MirageError::Protocol(format!("quic connection: {e}")))?;

        let (send, recv) = connection
            .open_bi()
            .await
            .map_err(|e| MirageError::Protocol(format!("quic open_bi: {e}")))?;

        Ok(QuicStreamAdapter {
            send,
            recv,
            _connection: connection,
        })
    }

    /// Server: bind a `quinn::Endpoint` on `bind_addr`, accept one incoming
    /// QUIC connection, accept the first bidirectional stream, and return it
    /// as a `QuicStreamAdapter`.
    ///
    /// Returns `(stream, remote_peer_addr)`.
    ///
    /// # Production use
    ///
    /// Prefer [`bind_endpoint`] + [`accept_one`] for long-running servers so the
    /// endpoint persists across multiple connections.  This method creates and
    /// drops the endpoint per call, which triggers `CONNECTION_CLOSE` on all
    /// open streams when it returns.
    async fn accept_server(
        &self,
        bind_addr: SocketAddr,
    ) -> Result<(QuicStreamAdapter, SocketAddr), MirageError> {
        let endpoint = self.bind_endpoint(bind_addr)?;
        self.accept_one(&endpoint).await
    }
}

impl QuicCamouflage {
    /// Bind a `quinn::Endpoint` on `bind_addr` and return it.
    ///
    /// The caller must keep the endpoint alive for as long as connections should
    /// remain open.  Dropping the endpoint sends `CONNECTION_CLOSE` to all peers.
    pub fn bind_endpoint(&self, bind_addr: SocketAddr) -> Result<quinn::Endpoint, MirageError> {
        quinn::Endpoint::server(self.server_config.clone(), bind_addr)
            .map_err(MirageError::Io)
    }

    /// Accept one incoming QUIC connection from an existing endpoint.
    ///
    /// Waits for the next incoming connection, completes the QUIC handshake,
    /// and returns the first bidirectional stream as a `QuicStreamAdapter`.
    pub async fn accept_one(
        &self,
        endpoint: &quinn::Endpoint,
    ) -> Result<(QuicStreamAdapter, SocketAddr), MirageError> {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| MirageError::Protocol("quic endpoint closed".into()))?;

        let connection = incoming
            .await
            .map_err(|e| MirageError::Protocol(format!("quic incoming: {e}")))?;

        let remote_addr = connection.remote_address();

        let (send, recv) = connection
            .accept_bi()
            .await
            .map_err(|e| MirageError::Protocol(format!("quic accept_bi: {e}")))?;

        Ok((
            QuicStreamAdapter {
                send,
                recv,
                _connection: connection,
            },
            remote_addr,
        ))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// QuicStreamAdapter
// ─────────────────────────────────────────────────────────────────────────────

/// `AsyncRead + AsyncWrite` adapter over a `quinn` bidirectional stream.
///
/// In quinn 0.11, `SendStream` implements `AsyncWrite` and `RecvStream`
/// implements `AsyncRead` natively.  This adapter combines them into a
/// single struct with `Unpin` so it can be used with the Mirage handshake
/// functions and `MirageCoreTunnel`.
///
/// The `_connection` field keeps the `quinn::Connection` alive for the duration
/// of the stream — dropping it closes all streams on the connection.
pub struct QuicStreamAdapter {
    send: SendStream,
    recv: RecvStream,
    /// Keeps the QUIC connection alive.
    _connection: Connection,
}

impl QuicStreamAdapter {
    /// Wrap one bidirectional QUIC stream.
    ///
    /// The connection is kept inside the adapter: dropping it closes every
    /// stream of the connection.
    pub fn new(send: SendStream, recv: RecvStream, connection: Connection) -> Self {
        Self {
            send,
            recv,
            _connection: connection,
        }
    }

    /// The QUIC connection this stream belongs to.
    ///
    /// The packet plane rides the same connection — see
    /// [`crate::plane`].
    pub fn connection(&self) -> &Connection {
        &self._connection
    }
}

impl AsyncRead for QuicStreamAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicStreamAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        // quinn 0.11 SendStream::poll_write returns WriteError; map to io::Error.
        Pin::new(&mut self.send).poll_write(cx, buf).map_err(|e| {
            std::io::Error::other(e.to_string())
        })
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // quinn SendStream has no meaningful flush; return Ready(Ok(())).
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // quinn 0.11 SendStream::poll_shutdown returns WriteError; map to io::Error.
        Pin::new(&mut self.send).poll_shutdown(cx).map_err(|e| {
            std::io::Error::other(e.to_string())
        })
    }
}

impl Unpin for QuicStreamAdapter {}
