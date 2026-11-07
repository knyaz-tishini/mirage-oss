//! Camouflage layer — WebTransport tunnel over HTTP/3 (W3C standard).
//!
//! WebTransport is a W3C standard built on HTTP/3 (QUIC + TLS 1.3).  It uses the
//! HTTP/3 Extended CONNECT method with `:protocol: webtransport` to upgrade a
//! single bidirectional stream into a full WebTransport session.
//!
//! DPI observers see legitimate HTTP/3 traffic (ALPN=h3, QUIC transport).
//! Browsers support WebTransport natively; CDNs (Cloudflare, Fastly) forward it.
//! Certificate verification is skipped — security lives in the inner Mirage handshake.
//!
//! # Wire format
//!
//! ```text
//! CLIENT                                                  SERVER
//!
//!   QUIC connect (UDP) ALPN="h3"
//!   HTTP/3 CONNECT  :protocol=webtransport
//!                   :path=/transport
//!                   :authority=cdn.example.com
//!                   origin=https://cdn.example.com    →
//!
//!                                                       HTTP/3 server accepts
//!                                                       Validates :protocol header
//!                                                    ← 200 OK
//!
//!   ← bidi stream treated as AsyncRead + AsyncWrite →
//!
//!   Mirage ECDH handshake + AEAD frames
//! ```
//!
//! # Implementation note
//!
//! The `h3-webtransport` crate is not used because it does not yet publish a
//! stable release compatible with our `h3` dependency version.  We implement the
//! Extended CONNECT handshake directly using the `h3` crate primitives:
//! the CONNECT method + `:protocol` pseudo-header is the complete WebTransport
//! upgrade mechanism at the HTTP/3 layer.
//!
//! # Overflow buffer
//!
//! h3 DATA chunks may carry more bytes than the caller requests.  A dedicated
//! `h3_overflow` buffer retains leftover bytes so they are not lost between
//! `poll_read` calls (same pattern as `Http3Camouflage`).

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::Bytes;
use mirage_core::error::MirageError;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::camouflage::{private, UdpCamouflageLayer};

// ─────────────────────────────────────────────────────────────────────────────
// TLS helpers (same pattern as http3.rs / quic.rs)
// ─────────────────────────────────────────────────────────────────────────────

fn generate_self_signed_cert() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>), MirageError> {
    let certified = rcgen::generate_simple_self_signed(vec!["mirage.local".to_owned()])
        .map_err(|e| MirageError::Config(format!("rcgen self-signed: {e}")))?;
    let cert = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::try_from(certified.key_pair.serialize_der())
        .map_err(|e| MirageError::Config(format!("rcgen private key: {e}")))?;
    Ok((cert, key))
}

fn build_server_config(
    cert: CertificateDer<'static>,
    key: PrivateKeyDer<'static>,
) -> Result<quinn::ServerConfig, MirageError> {
    // WebTransport requires HTTP/3 Extended CONNECT (RFC 9220).
    // ALPN must be "h3" so that QUIC negotiates HTTP/3.
    // The server must also send the SETTINGS_ENABLE_CONNECT_PROTOCOL=1 setting —
    // the h3 crate sends this automatically when a CONNECT request is accepted.
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| MirageError::Config(format!("rustls server builder: {e}")))?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .map_err(|e| MirageError::Config(format!("rustls server cert: {e}")))?;

    tls.alpn_protocols = vec![b"h3".to_vec()];

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
        tc
    }));
    Ok(cfg)
}

fn build_client_config() -> Result<quinn::ClientConfig, MirageError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| MirageError::Config(format!("rustls client builder: {e}")))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoopCertVerifier))
    .with_no_client_auth();

    tls.alpn_protocols = vec![b"h3".to_vec()];

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
/// Intentional — **by design**.  Security is provided by the inner Mirage
/// handshake (X25519 ECDH + BLAKE3).  The QUIC TLS layer exists only for
/// DPI camouflage.
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
// WebTransportCamouflage
// ─────────────────────────────────────────────────────────────────────────────

/// WebTransport transport-level camouflage (W3C standard over HTTP/3).
///
/// Client sends an HTTP/3 Extended CONNECT request with `:protocol: webtransport`
/// to `path` on `authority`.  The server accepts the upgrade and both sides use
/// the resulting bidirectional stream for Mirage handshake + AEAD frames.
///
/// Both client and server configs are built at construction time so TLS key
/// generation does not happen per connection.
pub struct WebTransportCamouflage {
    /// HTTP path for the WebTransport session (e.g. `"/transport"`).
    path: String,
    /// `:authority` header value (e.g. `"cdn.example.com"`).
    authority: String,
    client_config: quinn::ClientConfig,
    server_config: quinn::ServerConfig,
}

impl WebTransportCamouflage {
    /// Create a new `WebTransportCamouflage`.
    ///
    /// * `path`      — HTTP path for the WebTransport endpoint (e.g. `"/transport"`).
    /// * `authority` — `:authority` / `Host` header (e.g. `"cdn.example.com"`).
    ///
    /// A fresh self-signed TLS certificate is generated for the server endpoint.
    /// ALPN is always `"h3"` — required by the WebTransport spec.
    pub fn new(
        path: impl Into<String>,
        authority: impl Into<String>,
    ) -> Result<Self, MirageError> {
        let (cert, key) = generate_self_signed_cert()?;
        let server_config = build_server_config(cert, key)?;
        let client_config = build_client_config()?;
        Ok(Self {
            path: path.into(),
            authority: authority.into(),
            client_config,
            server_config,
        })
    }
}

impl private::Sealed for WebTransportCamouflage {}

#[async_trait]
impl UdpCamouflageLayer for WebTransportCamouflage {
    type Stream = WebTransportStreamAdapter;

    /// Client: connect to `server_addr` via QUIC + HTTP/3 Extended CONNECT
    /// (`:protocol: webtransport`).
    ///
    /// `sni` is used as the TLS server name in the QUIC ClientHello.
    /// Falls back to `"mirage.local"` if empty.
    async fn connect_client(
        &self,
        server_addr: SocketAddr,
        sni: &str,
    ) -> Result<WebTransportStreamAdapter, MirageError> {
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
            quinn::Endpoint::client("0.0.0.0:0".parse().expect("valid addr"))
                .map_err(MirageError::Io)?;
        endpoint.set_default_client_config(client_cfg);

        let sni_name = if sni.is_empty() { "mirage.local" } else { sni };
        let quinn_conn = endpoint
            .connect(server_addr, sni_name)
            .map_err(|e| MirageError::Protocol(format!("webtransport: quic connect: {e}")))?
            .await
            .map_err(|e| MirageError::Protocol(format!("webtransport: quic connection: {e}")))?;

        let h3_quinn_conn = h3_quinn::Connection::new(quinn_conn);
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn_conn)
                .await
                .map_err(|e| MirageError::Protocol(format!("webtransport: h3 client init: {e}")))?;

        // Drive the h3 connection in a background task.
        tokio::spawn(async move {
            if let Err(e) = std::future::poll_fn(|cx| driver.poll_close(cx)).await {
                tracing::debug!("webtransport: h3 client driver closed: {e}");
            }
        });

        let authority = self.authority.clone();
        let path = self.path.clone();

        // WebTransport Extended CONNECT request.
        // RFC 9220 / W3C WebTransport spec:
        //   Method: CONNECT
        //   :protocol: webtransport
        //   :scheme: https
        //   :path: <path>
        //   :authority: <authority>
        //   origin: https://<authority>
        let req = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{authority}{path}"))
            .header("protocol", "webtransport")
            .header(http::header::ORIGIN, format!("https://{authority}"))
            .body(())
            .map_err(|e| MirageError::Protocol(format!("webtransport: build request: {e}")))?;

        let mut req_stream = send_request
            .send_request(req)
            .await
            .map_err(|e| MirageError::Protocol(format!("webtransport: send_request: {e}")))?;

        // Await 200 OK before returning the adapter.
        let resp = req_stream
            .recv_response()
            .await
            .map_err(|e| MirageError::Protocol(format!("webtransport: recv_response: {e}")))?;
        if resp.status() != http::StatusCode::OK {
            return Err(MirageError::Protocol(format!(
                "webtransport: unexpected server status {}",
                resp.status()
            )));
        }

        Ok(WebTransportStreamAdapter::new_client(req_stream, send_request))
    }

    /// Server: bind a QUIC endpoint on `bind_addr`, accept one incoming
    /// WebTransport CONNECT request, and return a `WebTransportStreamAdapter`.
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
    ) -> Result<(WebTransportStreamAdapter, SocketAddr), MirageError> {
        let endpoint = self.bind_endpoint(bind_addr)?;
        self.accept_one(&endpoint).await
    }
}

impl WebTransportCamouflage {
    /// Bind a `quinn::Endpoint` on `bind_addr` and return it.
    ///
    /// The caller must keep the endpoint alive for as long as connections should
    /// remain open.  Dropping the endpoint sends `CONNECTION_CLOSE` to all peers.
    pub fn bind_endpoint(&self, bind_addr: SocketAddr) -> Result<quinn::Endpoint, MirageError> {
        quinn::Endpoint::server(self.server_config.clone(), bind_addr)
            .map_err(MirageError::Io)
    }

    /// Accept one incoming WebTransport connection from an existing endpoint.
    ///
    /// Waits for the next incoming QUIC connection, negotiates HTTP/3, and
    /// returns the first matching WebTransport CONNECT request as a
    /// `WebTransportStreamAdapter`.  Non-matching requests receive HTTP 404
    /// and are skipped.
    pub async fn accept_one(
        &self,
        endpoint: &quinn::Endpoint,
    ) -> Result<(WebTransportStreamAdapter, SocketAddr), MirageError> {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| MirageError::Protocol("webtransport: endpoint closed".into()))?;

        let quinn_conn = incoming
            .await
            .map_err(|e| MirageError::Protocol(format!("webtransport: incoming quic: {e}")))?;
        let remote_addr = quinn_conn.remote_address();

        let h3_quinn_conn = h3_quinn::Connection::new(quinn_conn);
        let mut h3_conn = h3::server::builder()
            .build::<_, Bytes>(h3_quinn_conn)
            .await
            .map_err(|e| MirageError::Protocol(format!("webtransport: h3 server build: {e}")))?;

        let path = self.path.clone();
        loop {
            match h3_conn.accept().await {
                Ok(Some((req, mut stream))) => {
                    let method = req.method().clone();
                    let req_path = req.uri().path().to_owned();

                    // WebTransport: CONNECT method + :protocol pseudo-header = "webtransport"
                    // The h3 crate exposes the extended-connect :protocol as the "protocol" header.
                    let protocol_header = req
                        .headers()
                        .get("protocol")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");

                    let is_webtransport = method == http::Method::CONNECT
                        && protocol_header == "webtransport"
                        && req_path == path;

                    if !is_webtransport {
                        // Probe-resistance: 404 for anything else.
                        let resp = http::Response::builder()
                            .status(http::StatusCode::NOT_FOUND)
                            .body(())
                            .expect("valid response");
                        let _ = stream.send_response(resp).await;
                        let _ = stream.send_data(Bytes::from_static(b"Not Found")).await;
                        let _ = stream.finish().await;
                        continue;
                    }

                    // Accept the WebTransport session — respond 200 OK.
                    let resp = http::Response::builder()
                        .status(http::StatusCode::OK)
                        .body(())
                        .expect("valid response");
                    stream
                        .send_response(resp)
                        .await
                        .map_err(|e| {
                            MirageError::Protocol(format!("webtransport: send 200: {e}"))
                        })?;

                    // Keep h3_conn alive in a background task so the QUIC
                    // control streams (SETTINGS, QPACK) stay open.
                    tokio::spawn(async move {
                        loop {
                            match h3_conn.accept().await {
                                Ok(None) | Err(_) => break,
                                Ok(Some(_)) => {}
                            }
                        }
                    });

                    return Ok((WebTransportStreamAdapter::new_server(stream), remote_addr));
                }
                Ok(None) => {
                    return Err(MirageError::Protocol(
                        "webtransport: connection closed before session established".into(),
                    ));
                }
                Err(e) => match e.get_error_level() {
                    h3::error::ErrorLevel::ConnectionError => {
                        return Err(MirageError::Protocol(format!(
                            "webtransport: connection error: {e}"
                        )));
                    }
                    h3::error::ErrorLevel::StreamError => {
                        tracing::debug!("webtransport: stream error (ignoring): {e}");
                        continue;
                    }
                },
            }
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Inner stream types
// ─────────────────────────────────────────────────────────────────────────────

type ClientStream = h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;
type ClientSendRequest = h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>;
type ServerStream = h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>;

// ─────────────────────────────────────────────────────────────────────────────
// WebTransportStreamAdapter
// ─────────────────────────────────────────────────────────────────────────────

/// `AsyncRead + AsyncWrite` adapter over a WebTransport session bidi stream.
///
/// Client: writes go into the CONNECT request body; reads come from the 200
/// response body.  Server: writes go into the 200 response body; reads come
/// from the CONNECT request body.
///
/// # Overflow buffer
///
/// h3 DATA chunks may be larger than the caller's read buffer.  The
/// `h3_overflow` field holds the leftover bytes from the most recent chunk so
/// that they are returned on the next `poll_read` without being discarded.
pub struct WebTransportStreamAdapter {
    inner: WebTransportInner,
    /// Bytes from h3 DATA chunks not yet consumed by the caller.
    h3_overflow: Vec<u8>,
}

enum WebTransportInner {
    Client {
        stream: ClientStream,
        /// Keeps the h3 client connection alive.
        _send_request: ClientSendRequest,
    },
    Server {
        stream: ServerStream,
    },
}

impl WebTransportStreamAdapter {
    fn new_client(stream: ClientStream, send_request: ClientSendRequest) -> Self {
        Self {
            inner: WebTransportInner::Client {
                stream,
                _send_request: send_request,
            },
            h3_overflow: Vec::new(),
        }
    }

    fn new_server(stream: ServerStream) -> Self {
        Self {
            inner: WebTransportInner::Server { stream },
            h3_overflow: Vec::new(),
        }
    }
}

impl AsyncRead for WebTransportStreamAdapter {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Drain overflow first.
        if !this.h3_overflow.is_empty() {
            let n = this.h3_overflow.len().min(buf.remaining());
            buf.put_slice(&this.h3_overflow[..n]);
            this.h3_overflow.drain(..n);
            return Poll::Ready(Ok(()));
        }

        match &mut this.inner {
            WebTransportInner::Client { stream, .. } => {
                let fut = stream.recv_data();
                tokio::pin!(fut);
                match fut.poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(
                        format!("webtransport client recv_data: {e}"),
                    ))),
                    Poll::Ready(Ok(None)) => Poll::Ready(Ok(())), // EOF
                    Poll::Ready(Ok(Some(chunk))) => {
                        use bytes::Buf as _;
                        let chunk_bytes = chunk.chunk();
                        let n = chunk_bytes.len().min(buf.remaining());
                        buf.put_slice(&chunk_bytes[..n]);
                        if chunk_bytes.len() > n {
                            this.h3_overflow.extend_from_slice(&chunk_bytes[n..]);
                        }
                        Poll::Ready(Ok(()))
                    }
                }
            }
            WebTransportInner::Server { stream } => {
                let fut = stream.recv_data();
                tokio::pin!(fut);
                match fut.poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(
                        format!("webtransport server recv_data: {e}"),
                    ))),
                    Poll::Ready(Ok(None)) => Poll::Ready(Ok(())), // EOF
                    Poll::Ready(Ok(Some(chunk))) => {
                        use bytes::Buf as _;
                        let chunk_bytes = chunk.chunk();
                        let n = chunk_bytes.len().min(buf.remaining());
                        buf.put_slice(&chunk_bytes[..n]);
                        if chunk_bytes.len() > n {
                            this.h3_overflow.extend_from_slice(&chunk_bytes[n..]);
                        }
                        Poll::Ready(Ok(()))
                    }
                }
            }
        }
    }
}

impl AsyncWrite for WebTransportStreamAdapter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let bytes = Bytes::copy_from_slice(data);
        let len = data.len();

        match &mut this.inner {
            WebTransportInner::Client { stream, .. } => {
                let fut = stream.send_data(bytes);
                tokio::pin!(fut);
                match fut.poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(
                        format!("webtransport client send_data: {e}"),
                    ))),
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(len)),
                }
            }
            WebTransportInner::Server { stream } => {
                let fut = stream.send_data(bytes);
                tokio::pin!(fut);
                match fut.poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(
                        format!("webtransport server send_data: {e}"),
                    ))),
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(len)),
                }
            }
        }
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        // h3 DATA frames are sent immediately on send_data; no buffering.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        match &mut this.inner {
            WebTransportInner::Client { stream, .. } => {
                let fut = stream.finish();
                tokio::pin!(fut);
                fut.poll(cx)
                    .map_err(|e| std::io::Error::other(format!("webtransport client finish: {e}")))
            }
            WebTransportInner::Server { stream } => {
                let fut = stream.finish();
                tokio::pin!(fut);
                fut.poll(cx)
                    .map_err(|e| std::io::Error::other(format!("webtransport server finish: {e}")))
            }
        }
    }
}

impl Unpin for WebTransportStreamAdapter {}
