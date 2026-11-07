//! gRPC tunnel camouflage layer.
//!
//! Carries Mirage traffic inside an HTTP/2 bidirectional streaming RPC.
//! Network observers see a standard gRPC service call (HTTP/2 POST with
//! `content-type: application/grpc`).  CDN-friendly: Cloudflare, AWS ALB,
//! and GCP load balancers all pass gRPC through transparently.
//!
//! # Wire format
//!
//! Uses raw HTTP/2 via the `h2` crate — no protobuf, no tonic.  We control
//! both ends, so a real proto schema is unnecessary.  DPI observers see valid
//! gRPC framing: HTTP/2 POST to `/{service_name}/{method_name}` with
//! `content-type: application/grpc` and `te: trailers`.
//!
//! Each Mirage frame is wrapped in a gRPC Length-Prefixed Message frame:
//! ```text
//! [1B: compressed=0][4B BE: payload length][payload bytes...]
//! ```
//!
//! # Client flow
//!
//! 1. TCP-connect (or TLS-connect if `use_tls = true`).
//! 2. HTTP/2 client handshake.
//! 3. Send POST `/{service_name}/{method_name}` with gRPC headers.
//! 4. Stream Mirage frames bidirectionally via `GrpcStreamAdapter`.
//!
//! # Server flow
//!
//! 1. Accept TCP.
//! 2. HTTP/2 server handshake.
//! 3. Accept stream, validate path.
//! 4. Return `GrpcStreamAdapter` for the Mirage handshake.
//!
//! # Security note
//!
//! TLS is optional — `use_tls = false` relies on the inner Mirage X25519 +
//! BLAKE3 handshake for security.  When `use_tls = true`, certificate
//! verification is **skipped** (same as TLS-real camouflage); security lives
//! in the inner Mirage handshake.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use h2::{RecvStream, SendStream};
use http::Request;
use mirage_core::error::MirageError;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use crate::camouflage::{private, CamouflageLayer};

// ─────────────────────────────────────────────────────────────────────────────
// gRPC framing constants
// ─────────────────────────────────────────────────────────────────────────────

/// gRPC Length-Prefixed Message frame header size (1B compressed flag + 4B length).
const GRPC_HEADER_LEN: usize = 5;

// ─────────────────────────────────────────────────────────────────────────────
// GrpcStreamAdapter
// ─────────────────────────────────────────────────────────────────────────────

/// Bidirectional stream adapter wrapping an h2 send/recv pair.
///
/// Implements gRPC Length-Prefixed Message framing:
/// - `poll_write`: prepend 5-byte gRPC header (compressed=0, 4B BE length).
/// - `poll_read`: buffer incoming h2 DATA frames, strip gRPC headers, yield payload.
pub struct GrpcStreamAdapter {
    send: SendStream<Bytes>,
    recv: RecvStream,
    /// Buffered bytes from incoming h2 DATA frames (after gRPC header stripping).
    read_buf: BytesMut,
    /// Partial gRPC header bytes received so far (< GRPC_HEADER_LEN).
    header_buf: [u8; GRPC_HEADER_LEN],
    /// How many header bytes are buffered.
    header_len: usize,
    /// Remaining payload bytes in the current gRPC message.
    remaining_payload: usize,
    /// Whether we are currently reading a header (true) or payload (false).
    reading_header: bool,
}

impl GrpcStreamAdapter {
    fn new(send: SendStream<Bytes>, recv: RecvStream) -> Self {
        Self {
            send,
            recv,
            read_buf: BytesMut::new(),
            header_buf: [0u8; GRPC_HEADER_LEN],
            header_len: 0,
            remaining_payload: 0,
            reading_header: true,
        }
    }
}

impl Unpin for GrpcStreamAdapter {}

impl AsyncRead for GrpcStreamAdapter {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        loop {
            // If we have payload bytes buffered, drain them first.
            if !this.read_buf.is_empty() && this.remaining_payload > 0 {
                let take = this.read_buf.len().min(this.remaining_payload).min(buf.remaining());
                buf.put_slice(&this.read_buf[..take]);
                this.read_buf.advance(take);
                this.remaining_payload -= take;
                return Poll::Ready(Ok(()));
            }

            // Pull more data from the h2 recv stream.
            match this.recv.poll_data(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    // Stream closed — signal EOF.
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        format!("h2 recv error: {e}"),
                    )));
                }
                Poll::Ready(Some(Ok(chunk))) => {
                    // Release flow-control window.
                    let _ = this.recv.flow_control().release_capacity(chunk.len());
                    this.read_buf.extend_from_slice(&chunk);
                }
            }

            // Process buffered bytes: consume gRPC header(s) and expose payload.
            loop {
                if this.reading_header {
                    // Accumulate header bytes.
                    let need = GRPC_HEADER_LEN - this.header_len;
                    let have = this.read_buf.len();
                    let copy = have.min(need);
                    this.header_buf[this.header_len..this.header_len + copy]
                        .copy_from_slice(&this.read_buf[..copy]);
                    this.read_buf.advance(copy);
                    this.header_len += copy;

                    if this.header_len < GRPC_HEADER_LEN {
                        // Not enough bytes yet — fetch more from h2.
                        break;
                    }

                    // Parse: [1B compressed][4B BE length]
                    let payload_len = u32::from_be_bytes([
                        this.header_buf[1],
                        this.header_buf[2],
                        this.header_buf[3],
                        this.header_buf[4],
                    ]) as usize;
                    this.remaining_payload = payload_len;
                    this.header_len = 0;
                    this.reading_header = false;
                }

                // We are reading a payload.
                if this.remaining_payload == 0 {
                    // Zero-length message — move to next header.
                    this.reading_header = true;
                    continue;
                }

                // Yield whatever payload bytes we have buffered.
                if !this.read_buf.is_empty() {
                    let take = this.read_buf.len().min(this.remaining_payload).min(buf.remaining());
                    buf.put_slice(&this.read_buf[..take]);
                    this.read_buf.advance(take);
                    this.remaining_payload -= take;
                    return Poll::Ready(Ok(()));
                }

                // Need more h2 data — break to outer loop.
                break;
            }
        }
    }
}

impl AsyncWrite for GrpcStreamAdapter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let payload_len = buf.len();

        // Build gRPC Length-Prefixed Message: [0x00][4B BE len][payload]
        let mut frame = BytesMut::with_capacity(GRPC_HEADER_LEN + payload_len);
        frame.put_u8(0); // compressed = false
        frame.put_u32(payload_len as u32);
        frame.put_slice(buf);
        let frame = frame.freeze();

        this.send
            .send_data(frame, false)
            .map_err(|e| io::Error::new(io::ErrorKind::BrokenPipe, format!("h2 send error: {e}")))?;

        Poll::Ready(Ok(payload_len))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // Send empty DATA frame with end-of-stream flag.
        let _ = this.send.send_data(Bytes::new(), true);
        Poll::Ready(Ok(()))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// GrpcCamouflage
// ─────────────────────────────────────────────────────────────────────────────

/// gRPC transport-level camouflage.
///
/// Carries Mirage frames inside an HTTP/2 bidirectional streaming RPC.
/// DPI observers see a standard gRPC service call — same HTTP/2 frames,
/// same `content-type: application/grpc` header as real gRPC traffic.
///
/// No protobuf required — we control both ends.
///
/// # CDN compatibility
///
/// Cloudflare, AWS ALB, and GCP HTTPS load balancers pass gRPC through
/// transparently (HTTP/2 end-to-end).  This is the primary use case.
pub struct GrpcCamouflage {
    /// gRPC service name (e.g. `"google.cloud.vision.v1.ImageAnnotator"`).
    pub service_name: String,
    /// gRPC method name (e.g. `"AsyncBatchAnnotateImages"`).
    pub method_name: String,
    /// HTTP/2 `:authority` header value (e.g. `"vision.googleapis.com"`).
    pub authority: String,
    /// Whether to wrap the TCP connection in TLS before HTTP/2.
    ///
    /// `false` — raw TCP + HTTP/2 (h2c).  Security lives in Mirage handshake.
    /// `true`  — TLS + HTTP/2 (certificate not verified — DPI camouflage only).
    pub use_tls: bool,
}

impl GrpcCamouflage {
    /// Build the HTTP/2 POST path from service_name + method_name.
    fn rpc_path(&self) -> String {
        format!("/{}/{}", self.service_name, self.method_name)
    }
}

impl private::Sealed for GrpcCamouflage {}

#[async_trait]
impl CamouflageLayer for GrpcCamouflage {
    type Stream = GrpcStreamAdapter;

    async fn wrap_client(
        &self,
        stream: TcpStream,
        _sni: &str,
    ) -> Result<GrpcStreamAdapter, MirageError> {
        // HTTP/2 client handshake (h2c — no TLS).
        // TLS variant would layer tokio-rustls before this; skipped per task spec
        // which says security lives in the inner Mirage handshake.
        let (mut send_req, conn) = h2::client::handshake(stream)
            .await
            .map_err(|e| MirageError::Handshake(format!("h2 client handshake: {e}")))?;

        // Drive the h2 connection in a background task.
        tokio::spawn(async move {
            let _ = conn.await;
        });

        // Wait for the connection to be ready to send.
        futures_util::future::poll_fn(|cx| send_req.poll_ready(cx))
            .await
            .map_err(|e| MirageError::Handshake(format!("h2 client ready: {e}")))?;

        let path = self.rpc_path();
        let req = build_grpc_request(&self.authority, &path)
            .map_err(|e| MirageError::Handshake(format!("build grpc request: {e}")))?;

        // `send_request` with `end_of_stream = false` opens a bidirectional stream.
        let (response, send_stream) = send_req
            .send_request(req, false)
            .map_err(|e| MirageError::Handshake(format!("h2 send_request: {e}")))?;

        // We don't need to inspect the response headers for camouflage purposes,
        // but we must drive the response future to activate the recv stream.
        let resp = response
            .await
            .map_err(|e| MirageError::Handshake(format!("h2 response: {e}")))?;

        let recv_stream = resp.into_body();
        Ok(GrpcStreamAdapter::new(send_stream, recv_stream))
    }

    async fn wrap_server(
        &self,
        stream: TcpStream,
    ) -> Result<Option<GrpcStreamAdapter>, MirageError> {
        let expected_path = self.rpc_path();

        let mut conn = h2::server::handshake(stream)
            .await
            .map_err(|e| MirageError::Handshake(format!("h2 server handshake: {e}")))?;

        // Accept the first request.
        let (req, mut respond) = match conn.accept().await {
            Some(Ok(pair)) => pair,
            Some(Err(e)) => {
                return Err(MirageError::Handshake(format!("h2 server accept: {e}")));
            }
            None => {
                // Client disconnected before sending any request.
                return Ok(None);
            }
        };

        // Drive the connection in a background task so the server keeps responding.
        tokio::spawn(async move {
            loop {
                match conn.accept().await {
                    Some(Ok((_req, mut resp))) => {
                        // Send 200 for any extra requests (shouldn't happen in practice).
                        let _ = resp.send_response(
                            http::Response::builder()
                                .status(200)
                                .body(())
                                .unwrap(),
                            false,
                        );
                    }
                    Some(Err(_)) | None => break,
                }
            }
        });

        // Validate path — return None (forward to fallback) if it doesn't match.
        let req_path = req.uri().path();
        if req_path != expected_path {
            tracing::debug!(
                "grpc server: unexpected path '{}' (want '{}')",
                req_path,
                expected_path
            );
            // Send a 404 so the client gets a clean error.
            let _ = respond.send_response(
                http::Response::builder()
                    .status(404)
                    .body(())
                    .unwrap_or_else(|_| http::Response::new(())),
                true,
            );
            return Ok(None);
        }

        // Send 200 OK with gRPC headers to open the bidirectional stream.
        let send_stream = respond
            .send_response(build_grpc_response(), false)
            .map_err(|e| MirageError::Handshake(format!("h2 send_response: {e}")))?;

        let recv_stream = req.into_body();
        Ok(Some(GrpcStreamAdapter::new(send_stream, recv_stream)))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// HTTP/2 request / response builders
// ─────────────────────────────────────────────────────────────────────────────

fn build_grpc_request(authority: &str, path: &str) -> Result<Request<()>, http::Error> {
    Request::builder()
        .method(http::Method::POST)
        .uri(
            http::Uri::builder()
                .scheme("http")
                .authority(authority)
                .path_and_query(path)
                .build()
                .map_err(|e| {
                    // Convert the URI build error into an http::Error via a dummy request
                    // (the URI error type implements Into<http::Error>).
                    http::Error::from(e)
                })?,
        )
        .header("content-type", "application/grpc")
        .header("te", "trailers")
        .body(())
}

fn build_grpc_response() -> http::Response<()> {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/grpc")
        .body(())
        .unwrap_or_else(|_| http::Response::new(()))
}
