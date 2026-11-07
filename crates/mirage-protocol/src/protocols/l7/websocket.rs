//! Camouflage layer — HTTP/1.1 Upgrade → WebSocket binary frames.
//!
//! Client sends a standard `Sec-WebSocket-Key` / `Sec-WebSocket-Version: 13`
//! request to `host` on `path`. Server returns 101 Switching Protocols with
//! `Sec-WebSocket-Accept`. All subsequent traffic is wrapped in WebSocket binary
//! frames (opcode 0x2). DPI / CDN / corporate proxies see legitimate WebSocket
//! traffic.
//!
//! Does not validate the authenticity of the upgrade beyond successful handshake —
//! security lives in the inner Mirage handshake.

use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};

use async_trait::async_trait;
use futures_util::{Sink, Stream};
use mirage_core::error::MirageError;
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_tungstenite::{
    accept_async,
    client_async,
    tungstenite::{handshake::client::generate_key, http::Request, Message},
};

use crate::camouflage::{private, CamouflageLayer};

// ─────────────────────────────────────────────────────────────────────────────
// WebSocketCamouflage
// ─────────────────────────────────────────────────────────────────────────────

/// HTTP/1.1 Upgrade → WebSocket binary frames camouflage layer.
///
/// Client performs a standard WebSocket upgrade to `host` on `path`.
/// Server accepts any valid WebSocket upgrade.  Subsequent Mirage ECDH
/// handshake and AEAD framing run through `WsStream` which adapts the
/// message-based WebSocket transport into a byte stream.
pub struct WebSocketCamouflage {
    path: String,
    host: String,
}

impl WebSocketCamouflage {
    /// Create a new `WebSocketCamouflage`.
    ///
    /// * `path` — HTTP path for the upgrade request (e.g. `"/ws"`).
    /// * `host` — `Host` header value (e.g. `"www.googleapis.com"`).
    pub fn new(path: impl Into<String>, host: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            host: host.into(),
        }
    }
}

impl private::Sealed for WebSocketCamouflage {}

#[async_trait]
impl CamouflageLayer for WebSocketCamouflage {
    type Stream = WsStream;

    async fn wrap_client(&self, stream: TcpStream, _sni: &str) -> Result<WsStream, MirageError> {
        let url = format!("ws://{}{}", self.host, self.path);

        let request = Request::builder()
            .uri(&url)
            .header("Host", &self.host)
            .header("Upgrade", "websocket")
            .header("Connection", "Upgrade")
            .header("Sec-WebSocket-Version", "13")
            .header("Sec-WebSocket-Key", generate_key())
            .body(())
            .map_err(|e| MirageError::Handshake(format!("ws request build: {e}")))?;

        let (ws, _resp) = client_async(request, stream)
            .await
            .map_err(|e| MirageError::Handshake(format!("ws upgrade failed: {e}")))?;

        Ok(WsStream::new(ws))
    }

    async fn wrap_server(&self, stream: TcpStream) -> Result<Option<WsStream>, MirageError> {
        match accept_async(stream).await {
            Ok(ws) => Ok(Some(WsStream::new(ws))),
            // HTTP upgrade failed — not a WebSocket client (probe, wrong protocol).
            // Return None to signal the caller to forward to a fallback handler.
            Err(_) => Ok(None),
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// WsStream — AsyncRead + AsyncWrite adapter over WebSocket binary frames
// ─────────────────────────────────────────────────────────────────────────────

/// Adapts a `tokio_tungstenite::WebSocketStream<TcpStream>` into
/// `AsyncRead + AsyncWrite` by buffering received binary frame payloads and
/// sending each `poll_write` call as a single binary frame.
///
/// The WebSocket transport is message-based.  To present a byte-stream
/// interface to `core::handshake::run_*_handshake` and `MirageCoreTunnel`,
/// we buffer the payload of the most recently received binary frame and
/// drain it chunk by chunk on `poll_read`.
pub struct WsStream {
    inner: tokio_tungstenite::WebSocketStream<TcpStream>,
    /// Buffered payload from the last received binary frame, not yet consumed.
    recv_buf: Vec<u8>,
    /// Read cursor into `recv_buf`.
    recv_pos: usize,
}

impl WsStream {
    fn new(inner: tokio_tungstenite::WebSocketStream<TcpStream>) -> Self {
        Self {
            inner,
            recv_buf: Vec::new(),
            recv_pos: 0,
        }
    }
}

impl AsyncRead for WsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();

        // Drain any bytes still buffered from the previous frame.
        loop {
            if this.recv_pos < this.recv_buf.len() {
                let available = &this.recv_buf[this.recv_pos..];
                let n = available.len().min(buf.remaining());
                buf.put_slice(&available[..n]);
                this.recv_pos += n;
                return Poll::Ready(Ok(()));
            }

            // Buffer empty — fetch the next binary message from the WebSocket.
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(None) => {
                    // Connection closed cleanly.
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(Err(e))) => {
                    return Poll::Ready(Err(io::Error::other(e.to_string())));
                }
                Poll::Ready(Some(Ok(msg))) => match msg {
                    Message::Binary(bytes) => {
                        // Load the new frame payload and loop back to drain.
                        this.recv_buf = bytes.into();
                        this.recv_pos = 0;
                    }
                    Message::Close(_) => {
                        return Poll::Ready(Ok(()));
                    }
                    // Control frames (Ping, Pong) and Text frames — skip.
                    Message::Ping(_) | Message::Pong(_) | Message::Text(_) | Message::Frame(_) => {
                        // Loop and wait for the next message.
                    }
                },
            }
        }
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();

        // Attempt to send the buffer as a single binary frame.
        // `SinkExt::send` is async; we use `poll_ready` + `start_send` + `poll_flush`
        // to implement it without blocking.

        // Step 1: ensure the sink is ready to accept a message.
        match Pin::new(&mut this.inner).poll_ready(cx) {
            Poll::Pending => return Poll::Pending,
            Poll::Ready(Err(e)) => {
                return Poll::Ready(Err(io::Error::other(e.to_string())));
            }
            Poll::Ready(Ok(())) => {}
        }

        // Step 2: enqueue the message.
        let msg = Message::Binary(buf.to_vec().into());
        if let Err(e) = Pin::new(&mut this.inner).start_send(msg) {
            return Poll::Ready(Err(io::Error::other(e.to_string())));
        }

        // Step 3: flush to send.
        match Pin::new(&mut this.inner).poll_flush(cx) {
            Poll::Pending => {
                // Flush is in progress; we still consumed `buf.len()` bytes.
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Ok(())) => Poll::Ready(Ok(buf.len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(io::Error::other(e.to_string()))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner)
            .poll_flush(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        Pin::new(&mut this.inner)
            .poll_close(cx)
            .map_err(|e| io::Error::other(e.to_string()))
    }
}

impl Unpin for WsStream {}
