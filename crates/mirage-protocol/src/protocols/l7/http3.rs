//! Camouflage layer — Mirage tunnel inside HTTP/3 request body via h3.
//!
//! Client opens a CONNECT-style HTTP/3 request with configurable `:authority`
//! and `:path` (defaults look like a Chrome API call).  Mirage handshake +
//! AEAD frames flow in the request body; responses flow in the response body.
//!
//! DPI sees a legitimate HTTP/3 request (ALPN=h3, QUIC transport).
//! Self-signed cert + `NoopCertVerifier` — security is in the inner Mirage
//! handshake.
//!
//! # Architecture
//!
//! ```text
//! CLIENT                                              SERVER
//!
//!   QUIC connect (UDP) ALPN="h3"
//!   HTTP/3 POST tunnel_path  authority=authority  →
//!
//!                                                   HTTP/3 server accepts
//!                                                   Validates path & method
//!                                                ← 200 OK (streaming body)
//!
//!   ← stream body treated as AsyncRead + AsyncWrite →
//!
//!   Mirage handshake + AEAD frames through the body
//! ```
//!
//! # Overflow buffer
//!
//! h3 DATA chunks may carry more bytes than the caller requests.  A dedicated
//! `h3_overflow` buffer retains leftover bytes so they are not lost.  This was
//! a real bug in earlier versions — see the `recv_exact_*` helpers.

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
// TLS helpers (shared with quic.rs pattern)
// ─────────────────────────────────────────────────────────────────────────────

/// Generate a self-signed TLS certificate for the QUIC server endpoint.
///
/// Returns `(cert_der, key_der)`.  Every server instance gets a unique cert;
/// clients skip verification (see `NoopCertVerifier`).
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
    alpn: &str,
) -> Result<quinn::ServerConfig, MirageError> {
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| MirageError::Config(format!("rustls server builder: {e}")))?
    .with_no_client_auth()
    .with_single_cert(vec![cert], key)
    .map_err(|e| MirageError::Config(format!("rustls server cert: {e}")))?;

    tls.alpn_protocols = vec![alpn.as_bytes().to_vec()];

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

fn build_client_config(alpn: &str) -> Result<quinn::ClientConfig, MirageError> {
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|e| MirageError::Config(format!("rustls client builder: {e}")))?
    .dangerous()
    .with_custom_certificate_verifier(Arc::new(NoopCertVerifier))
    .with_no_client_auth();

    tls.alpn_protocols = vec![alpn.as_bytes().to_vec()];

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
// Http3Camouflage
// ─────────────────────────────────────────────────────────────────────────────

/// HTTP/3 transport-level camouflage.
///
/// Client opens a POST request to `tunnel_path` with `:authority = authority`.
/// The request/response bodies carry the Mirage handshake and AEAD frames.
///
/// Both client and server configs are built at construction time so that TLS
/// key generation does not happen per connection.
pub struct Http3Camouflage {
    authority: String,
    tunnel_path: String,
    alpn: String,
    client_config: quinn::ClientConfig,
    server_config: quinn::ServerConfig,
}

impl Http3Camouflage {
    /// Create a new `Http3Camouflage`.
    ///
    /// * `authority`    — `:authority` header (e.g. `"www.googleapis.com"`).
    /// * `tunnel_path`  — HTTP path for the tunnel endpoint (e.g. `"/api/v1/events"`).
    /// * `alpn`         — QUIC ALPN identifier (typically `"h3"`).
    ///
    /// A fresh self-signed TLS certificate is generated for the server endpoint.
    pub fn new(
        authority: impl Into<String>,
        tunnel_path: impl Into<String>,
        alpn: impl Into<String>,
    ) -> Result<Self, MirageError> {
        let alpn_str: String = alpn.into();
        let (cert, key) = generate_self_signed_cert()?;
        let server_config = build_server_config(cert, key, &alpn_str)?;
        let client_config = build_client_config(&alpn_str)?;
        Ok(Self {
            authority: authority.into(),
            tunnel_path: tunnel_path.into(),
            alpn: alpn_str,
            client_config,
            server_config,
        })
    }

    /// The ALPN identifier used for this camouflage.
    pub fn alpn(&self) -> &str {
        &self.alpn
    }
}

impl private::Sealed for Http3Camouflage {}

#[async_trait]
impl UdpCamouflageLayer for Http3Camouflage {
    type Stream = Http3StreamAdapter;

    /// Client: connect to `server_addr` via QUIC + HTTP/3 POST tunnel.
    ///
    /// Opens a QUIC connection (ALPN = `self.alpn`), creates an H3 session,
    /// and sends a POST request to `self.tunnel_path` with `:authority =
    /// self.authority`.  Returns a `Http3StreamAdapter` wrapping the
    /// bidirectional request/response body stream.
    ///
    /// `sni` is used as the TLS server name in the QUIC ClientHello.
    /// Falls back to `"mirage.local"` if empty.
    async fn connect_client(
        &self,
        server_addr: SocketAddr,
        sni: &str,
    ) -> Result<Http3StreamAdapter, MirageError> {
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
            .map_err(|e| MirageError::Protocol(format!("h3: quic connect: {e}")))?
            .await
            .map_err(|e| MirageError::Protocol(format!("h3: quic connection: {e}")))?;

        let h3_quinn_conn = h3_quinn::Connection::new(quinn_conn);
        let (mut driver, mut send_request) =
            h3::client::new(h3_quinn_conn)
                .await
                .map_err(|e| MirageError::Protocol(format!("h3: client init: {e}")))?;

        // Drive the h3 connection in a background task.
        tokio::spawn(async move {
            if let Err(e) = std::future::poll_fn(|cx| driver.poll_close(cx)).await {
                tracing::debug!("h3: client driver closed: {e}");
            }
        });

        let authority = self.authority.clone();
        let tunnel_path = self.tunnel_path.clone();
        let req = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("https://{authority}{tunnel_path}"))
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .body(())
            .map_err(|e| MirageError::Protocol(format!("h3: build request: {e}")))?;

        let mut req_stream = send_request
            .send_request(req)
            .await
            .map_err(|e| MirageError::Protocol(format!("h3: send_request: {e}")))?;

        // Receive the 200 OK response headers before returning the adapter so
        // that poll_read never has to deal with the header-wait state machine.
        // Awaiting here avoids re-creating the recv_response future on every
        // poll_read call, which would lose waker registrations and cause stalls.
        let resp = req_stream
            .recv_response()
            .await
            .map_err(|e| MirageError::Protocol(format!("h3: recv_response: {e}")))?;
        if resp.status() != http::StatusCode::OK {
            return Err(MirageError::Protocol(format!(
                "h3: unexpected server status {}",
                resp.status()
            )));
        }

        Ok(Http3StreamAdapter::new_client(req_stream, send_request, endpoint))
    }

    /// Server: bind a QUIC endpoint on `bind_addr`, accept one incoming
    /// connection, accept the first matching H3 request, and return an
    /// `Http3StreamAdapter` wrapping the body stream.
    ///
    /// Non-matching requests receive HTTP 404 and the loop continues waiting
    /// for a matching one.
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
    ) -> Result<(Http3StreamAdapter, SocketAddr), MirageError> {
        let endpoint = self.bind_endpoint(bind_addr)?;
        self.accept_one(&endpoint).await
    }
}

impl Http3Camouflage {
    /// Bind a `quinn::Endpoint` on `bind_addr` and return it.
    ///
    /// The caller must keep the endpoint alive for as long as connections should
    /// remain open.  Dropping the endpoint sends `CONNECTION_CLOSE` to all peers.
    pub fn bind_endpoint(&self, bind_addr: SocketAddr) -> Result<quinn::Endpoint, MirageError> {
        quinn::Endpoint::server(self.server_config.clone(), bind_addr)
            .map_err(MirageError::Io)
    }

    /// Accept one incoming H3 connection from an existing endpoint.
    ///
    /// Waits for the next incoming QUIC connection, negotiates HTTP/3, and
    /// returns the first matching tunnel request as an `Http3StreamAdapter`.
    /// Non-matching requests receive HTTP 404 and are skipped.
    pub async fn accept_one(
        &self,
        endpoint: &quinn::Endpoint,
    ) -> Result<(Http3StreamAdapter, SocketAddr), MirageError> {
        let incoming = endpoint
            .accept()
            .await
            .ok_or_else(|| MirageError::Protocol("h3: endpoint closed".into()))?;

        let quinn_conn = incoming
            .await
            .map_err(|e| MirageError::Protocol(format!("h3: incoming quic: {e}")))?;
        let remote_addr = quinn_conn.remote_address();

        let h3_quinn_conn = h3_quinn::Connection::new(quinn_conn);
        let mut h3_conn = h3::server::builder()
            .build::<_, Bytes>(h3_quinn_conn)
            .await
            .map_err(|e| MirageError::Protocol(format!("h3: server build: {e}")))?;

        let tunnel_path = self.tunnel_path.clone();
        loop {
            match h3_conn.accept().await {
                Ok(Some((req, mut stream))) => {
                    let method = req.method().clone();
                    let path = req.uri().path().to_owned();

                    let is_tunnel = (method == http::Method::POST
                        || method == http::Method::CONNECT)
                        && path == tunnel_path;

                    if !is_tunnel {
                        // Probe-resistance: respond with 404 and continue.
                        let resp = http::Response::builder()
                            .status(http::StatusCode::NOT_FOUND)
                            .body(())
                            .expect("valid response");
                        let _ = stream.send_response(resp).await;
                        let _ = stream.send_data(Bytes::from_static(b"Not Found")).await;
                        let _ = stream.finish().await;
                        continue;
                    }

                    // Send 200 OK headers before any body (H3 requires this).
                    let resp = http::Response::builder()
                        .status(http::StatusCode::OK)
                        .header(http::header::CONTENT_TYPE, "application/octet-stream")
                        .body(())
                        .expect("valid response");
                    stream
                        .send_response(resp)
                        .await
                        .map_err(|e| {
                            MirageError::Protocol(format!("h3: send 200: {e}"))
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

                    return Ok((Http3StreamAdapter::new_server(stream), remote_addr));
                }
                Ok(None) => {
                    return Err(MirageError::Protocol(
                        "h3: connection closed before tunnel established".into(),
                    ));
                }
                Err(e) => match e.get_error_level() {
                    h3::error::ErrorLevel::ConnectionError => {
                        return Err(MirageError::Protocol(format!(
                            "h3: connection error: {e}"
                        )));
                    }
                    h3::error::ErrorLevel::StreamError => {
                        tracing::debug!("h3: stream error (ignoring): {e}");
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
// Http3StreamAdapter
// ─────────────────────────────────────────────────────────────────────────────

/// `AsyncRead + AsyncWrite` adapter over an HTTP/3 request/response body stream.
///
/// Client: writes go into the POST request body; reads come from the 200
/// response body.  The 200 OK response headers are consumed eagerly in
/// `connect_client` before this adapter is constructed, so `poll_read` can
/// go straight to body data.
///
/// Server: writes go into the 200 response body; reads come from the POST
/// request body.
///
/// # Overflow buffer
///
/// h3 DATA chunks may be larger than the caller's read buffer.  The
/// `h3_overflow` field holds the leftover bytes from the most recent chunk so
/// that they are returned on the next `poll_read` without being discarded.
/// This was a real data-loss bug in earlier versions — the overflow must be
/// threaded through every `recv_exact_*` call.
pub struct Http3StreamAdapter {
    inner: Http3Inner,
    /// Bytes from h3 DATA chunks not yet consumed by the caller.
    h3_overflow: Vec<u8>,
}

enum Http3Inner {
    Client {
        stream: ClientStream,
        /// Keeps the h3 client connection alive.
        _send_request: ClientSendRequest,
        /// Keeps the client QUIC endpoint alive for the duration of the
        /// adapter. Without this the endpoint goes out of scope at the end
        /// of `connect_client`, its driver task is cancelled, and the
        /// connection closes — the server then sees a `recv_data:
        /// application error` mid-handshake instead of the graceful EOF /
        /// idle-timeout it would normally get (B-02). Surfaces only on
        /// direct dial; an L1 UDP byte-pump masks the abrupt close because
        /// the extra hop's network latency lets the server complete the
        /// Mirage handshake read first.
        _endpoint: quinn::Endpoint,
    },
    Server {
        stream: ServerStream,
    },
}

impl Http3StreamAdapter {
    fn new_client(
        stream: ClientStream,
        send_request: ClientSendRequest,
        endpoint: quinn::Endpoint,
    ) -> Self {
        Self {
            inner: Http3Inner::Client {
                stream,
                _send_request: send_request,
                _endpoint: endpoint,
            },
            h3_overflow: Vec::new(),
        }
    }

    fn new_server(stream: ServerStream) -> Self {
        Self {
            inner: Http3Inner::Server { stream },
            h3_overflow: Vec::new(),
        }
    }
}

impl AsyncRead for Http3StreamAdapter {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();

        // Drain h3_overflow (leftover bytes from a previous over-large DATA chunk).
        if !this.h3_overflow.is_empty() {
            let n = this.h3_overflow.len().min(buf.remaining());
            buf.put_slice(&this.h3_overflow[..n]);
            this.h3_overflow.drain(..n);
            return Poll::Ready(Ok(()));
        }

        // Poll recv_data from the h3 stream.
        //
        // recv_data() is called fresh each poll.  h3 0.0.7 properly re-registers
        // the waker on each poll() call, so recreating the future here is safe
        // and avoids self-referential ownership.  The response headers are already
        // consumed eagerly in connect_client (client side) or send_response
        // (server side), so no header-wait state machine is needed here.
        match &mut this.inner {
            Http3Inner::Client { stream, .. } => {
                let fut = stream.recv_data();
                tokio::pin!(fut);
                match fut.poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(
                        format!("h3 client recv_data: {e}"),
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
            Http3Inner::Server { stream } => {
                let fut = stream.recv_data();
                tokio::pin!(fut);
                match fut.poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(
                        format!("h3 server recv_data: {e}"),
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

impl AsyncWrite for Http3StreamAdapter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let bytes = Bytes::copy_from_slice(data);
        let len = data.len();

        match &mut this.inner {
            Http3Inner::Client { stream, .. } => {
                let fut = stream.send_data(bytes);
                tokio::pin!(fut);
                match fut.poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(
                        format!("h3 client send_data: {e}"),
                    ))),
                    Poll::Ready(Ok(())) => Poll::Ready(Ok(len)),
                }
            }
            Http3Inner::Server { stream } => {
                let fut = stream.send_data(bytes);
                tokio::pin!(fut);
                match fut.poll(cx) {
                    Poll::Pending => Poll::Pending,
                    Poll::Ready(Err(e)) => Poll::Ready(Err(std::io::Error::other(
                        format!("h3 server send_data: {e}"),
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
            Http3Inner::Client { stream, .. } => {
                let fut = stream.finish();
                tokio::pin!(fut);
                fut.poll(cx).map_err(|e| std::io::Error::other(format!("h3 client finish: {e}")))
            }
            Http3Inner::Server { stream } => {
                let fut = stream.finish();
                tokio::pin!(fut);
                fut.poll(cx).map_err(|e| std::io::Error::other(format!("h3 server finish: {e}")))
            }
        }
    }
}

impl Unpin for Http3StreamAdapter {}

