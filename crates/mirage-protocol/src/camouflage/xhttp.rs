//! Camouflage layer — HTTP/1.1 `Upgrade` to a raw byte stream.
//!
//! Inspired by xray-core's `xhttp` transport: client opens a TCP socket,
//! writes a plain HTTP/1.1 `GET /<path> HTTP/1.1` request with `Upgrade: xhttp/1`
//! and `Connection: Upgrade`. Server replies `HTTP/1.1 101 Switching Protocols`
//! with the same upgrade headers, and the underlying TCP stream is then handed
//! straight to the inner Mirage handshake — no further envelope, no chunked
//! framing, no WebSocket masking.
//!
//! Wire-distinct from `MirageWebsocket` (no `Sec-WebSocket-*` headers, no WS
//! framing on data) but very close on the DPI surface: HTTP-aware middleboxes
//! see a normal Upgrade exchange and let the rest of the bytes flow through
//! as the new `xhttp/1` protocol.
//!
//! ## Wire format
//!
//! ```text
//! CLIENT → SERVER (request, terminated by `\r\n\r\n`):
//!   GET /<path> HTTP/1.1\r\n
//!   Host: <host>\r\n
//!   Upgrade: xhttp/1\r\n
//!   Connection: Upgrade\r\n
//!   \r\n
//!
//! SERVER → CLIENT (response, terminated by `\r\n\r\n`):
//!   HTTP/1.1 101 Switching Protocols\r\n
//!   Upgrade: xhttp/1\r\n
//!   Connection: Upgrade\r\n
//!   \r\n
//!
//! After the 101 response, the byte stream is the inner Mirage handshake +
//! AEAD frames, identical to what runs over `mirage_base()` directly.
//! ```
//!
//! ## Probe resistance
//!
//! Server returns `HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n` for
//! requests that don't match the expected path / Upgrade headers, then closes.
//! `wrap_server` returns `Ok(None)` so the driver can fall through.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_trait::async_trait;
use mirage_core::error::MirageError;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::TcpStream;

use super::{private, CamouflageLayer};

const MAX_HEADER_BYTES: usize = 8192;
const UPGRADE_TOKEN: &str = "xhttp/1";

// ─────────────────────────────────────────────────────────────────────────────
// XhttpCamouflage
// ─────────────────────────────────────────────────────────────────────────────

/// HTTP/1.1 `Upgrade` to raw byte stream camouflage layer.
///
/// Client performs a single Upgrade exchange to `host` on `path`; server
/// validates the path + Upgrade token and replies with 101.  After that the
/// underlying TCP stream carries the inner Mirage handshake + AEAD frames
/// without further envelope.
pub struct XhttpCamouflage {
    path: String,
    host: String,
}

impl XhttpCamouflage {
    /// Create a new `XhttpCamouflage`.
    ///
    /// * `path` — HTTP path on the upgrade request (e.g. `"/xhttp"`). Must
    ///   start with `/`; the constructor prefixes `/` if missing.
    /// * `host` — `Host:` header value (e.g. `"www.example.com"`).
    pub fn new(path: impl Into<String>, host: impl Into<String>) -> Self {
        let mut path = path.into();
        if !path.starts_with('/') {
            path.insert(0, '/');
        }
        Self {
            path,
            host: host.into(),
        }
    }
}

impl private::Sealed for XhttpCamouflage {}

#[async_trait]
impl CamouflageLayer for XhttpCamouflage {
    type Stream = XhttpStream;

    async fn wrap_client(
        &self,
        mut stream: TcpStream,
        _sni: &str,
    ) -> Result<XhttpStream, MirageError> {
        // Build & send the Upgrade request.
        let req = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: {token}\r\nConnection: Upgrade\r\n\r\n",
            path = self.path,
            host = self.host,
            token = UPGRADE_TOKEN,
        );
        stream
            .write_all(req.as_bytes())
            .await
            .map_err(MirageError::Io)?;

        // Read the response status line + headers, terminated by `\r\n\r\n`.
        let header_buf = read_http_headers(&mut stream).await?;
        let header_text = std::str::from_utf8(&header_buf).map_err(|_| {
            MirageError::Handshake("xhttp client: server response is not utf-8".into())
        })?;

        let mut lines = header_text.lines();
        let status_line = lines.next().ok_or_else(|| {
            MirageError::Handshake("xhttp client: empty server response".into())
        })?;
        if !status_line.starts_with("HTTP/1.1 101") && !status_line.starts_with("HTTP/1.0 101") {
            return Err(MirageError::Handshake(format!(
                "xhttp client: expected 101 Switching Protocols, got: {status_line}"
            )));
        }

        // Lightly validate Upgrade / Connection headers so a vanilla HTTP
        // server returning 101 for some other reason is rejected.
        let mut saw_upgrade = false;
        let mut saw_connection_upgrade = false;
        for line in lines {
            let lower = line.to_ascii_lowercase();
            if let Some(val) = lower.strip_prefix("upgrade:") {
                if val.trim() == UPGRADE_TOKEN {
                    saw_upgrade = true;
                }
            } else if let Some(val) = lower.strip_prefix("connection:") {
                if val.trim().split(',').any(|s| s.trim() == "upgrade") {
                    saw_connection_upgrade = true;
                }
            }
        }
        if !saw_upgrade || !saw_connection_upgrade {
            return Err(MirageError::Handshake(
                "xhttp client: 101 response missing Upgrade or Connection headers".into(),
            ));
        }

        Ok(XhttpStream { inner: stream })
    }

    async fn wrap_server(&self, mut stream: TcpStream) -> Result<Option<XhttpStream>, MirageError> {
        // Read & parse the request line + headers.
        let header_buf = match read_http_headers(&mut stream).await {
            Ok(h) => h,
            // Probe / TCP RST / non-HTTP traffic — fall through.
            Err(_) => return Ok(None),
        };
        let header_text = match std::str::from_utf8(&header_buf) {
            Ok(t) => t,
            Err(_) => {
                send_404(&mut stream).await.ok();
                return Ok(None);
            }
        };

        let mut lines = header_text.lines();
        let request_line = lines.next().unwrap_or("");
        let mut parts = request_line.split_whitespace();
        let _method = parts.next().unwrap_or("");
        let req_path = parts.next().unwrap_or("");
        let _version = parts.next().unwrap_or("");

        // Strip query string before comparison so `/xhttp?foo=bar` still matches.
        let req_path_only = req_path.split('?').next().unwrap_or("");
        if req_path_only != self.path {
            send_404(&mut stream).await.ok();
            return Ok(None);
        }

        let mut saw_upgrade = false;
        let mut saw_connection_upgrade = false;
        for line in lines {
            let lower = line.to_ascii_lowercase();
            if let Some(val) = lower.strip_prefix("upgrade:") {
                if val.trim() == UPGRADE_TOKEN {
                    saw_upgrade = true;
                }
            } else if let Some(val) = lower.strip_prefix("connection:") {
                if val.trim().split(',').any(|s| s.trim() == "upgrade") {
                    saw_connection_upgrade = true;
                }
            }
        }
        if !saw_upgrade || !saw_connection_upgrade {
            send_404(&mut stream).await.ok();
            return Ok(None);
        }

        // Send the 101 response.
        let resp = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: {token}\r\nConnection: Upgrade\r\n\r\n",
            token = UPGRADE_TOKEN,
        );
        stream
            .write_all(resp.as_bytes())
            .await
            .map_err(MirageError::Io)?;

        Ok(Some(XhttpStream { inner: stream }))
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// helpers
// ─────────────────────────────────────────────────────────────────────────────

/// Read bytes until the first `\r\n\r\n` (end of HTTP headers).
///
/// Returns the buffer up to and including the trailing CRLFCRLF.  Errors on
/// EOF before terminator or if more than `MAX_HEADER_BYTES` are read without
/// finding the terminator.
async fn read_http_headers(stream: &mut TcpStream) -> Result<Vec<u8>, MirageError> {
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await.map_err(MirageError::Io)?;
        if n == 0 {
            return Err(MirageError::Handshake(
                "xhttp: peer closed before end of headers".into(),
            ));
        }
        buf.push(byte[0]);
        if buf.len() >= 4 && &buf[buf.len() - 4..] == b"\r\n\r\n" {
            return Ok(buf);
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(MirageError::Handshake(
                "xhttp: header section exceeded MAX_HEADER_BYTES".into(),
            ));
        }
    }
}

async fn send_404(stream: &mut TcpStream) -> io::Result<()> {
    let body = b"HTTP/1.1 404 Not Found\r\nConnection: close\r\nContent-Length: 0\r\n\r\n";
    stream.write_all(body).await
}

// ─────────────────────────────────────────────────────────────────────────────
// XhttpStream — pass-through adapter over the upgraded TcpStream
// ─────────────────────────────────────────────────────────────────────────────

/// Byte-stream adapter — after the Upgrade exchange the Mirage handshake +
/// AEAD frames flow through the bare TCP stream unchanged.
pub struct XhttpStream {
    inner: TcpStream,
}

impl AsyncRead for XhttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl AsyncWrite for XhttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl Unpin for XhttpStream {}
