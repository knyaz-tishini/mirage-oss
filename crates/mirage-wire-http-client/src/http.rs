//! Request/response HTTP/1.1 framing over an already-open Mirage V9 tunnel.
//!
//! Copied and generalised from `mirage2operator/crates/operator-box/src/
//! wire_http.rs`'s `build_request_head` / `run_one_exchange` /
//! `read_http_response` / `read_chunked_body` / `recv_idle` /
//! `find_subslice` — the framing itself carries no opbox state
//! (`OperatorState`, `MachineRow`, `WireStats`, `Progress`) and ports
//! unchanged. What is deliberately NOT carried over is session pooling
//! (`wire_session_pool::ReqRespSession`) — this crate dials fresh on every
//! [`crate::WireHttpClient::request`] call; see this crate's own CLAUDE.md
//! for why that is a later, separable addition rather than a gap.

use std::time::Duration;

use mirage_protocol::traits::Tunnel;

/// Defensive ceiling on the HTTP response header block — mirrors
/// `wire_http::MAX_RESPONSE_HEADER_BYTES`.
const MAX_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

/// Outcome of one raw wire HTTP exchange: status code + response body bytes.
#[derive(Debug)]
pub(crate) struct WireResponse {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Build an HTTP/1.1 request head (status line + headers, no body).
///
/// No `Connection: close` and no `HTTP/1.0` — this crate always makes one
/// exchange per fresh dial (no session pooling; see the module doc), so
/// keep-alive framing costs nothing here and keeps the monitor's own
/// hyper-based `MonitorHttpHandler::serve` on its ordinary HTTP/1.1 path
/// rather than a version it has to special-case.
pub(crate) fn build_request_head(
    host: &str,
    identity_b64: &str,
    mac_hex: &str,
    ts_ms: u64,
    method: &str,
    path: &str,
    content_len: usize,
) -> Vec<u8> {
    let method = method.to_uppercase();
    let mut head = format!(
        "{method} {path} HTTP/1.1\r\n\
         Host: {host}\r\n\
         x-mirage-sender-identity: {identity_b64}\r\n\
         x-mirage-sender-mac: {mac_hex}\r\n\
         x-mirage-sender-ts: {ts_ms}\r\n"
    );
    if content_len > 0 {
        // axum `Json<T>` extractors reject a body without this header (415).
        head.push_str("Content-Type: application/json\r\n");
        head.push_str(&format!("Content-Length: {content_len}\r\n"));
    }
    head.push_str("\r\n");
    head.into_bytes()
}

/// Send `request_bytes` + `body` on an already-open `tunnel`, then read and
/// parse the HTTP response. Never closes the tunnel — the caller decides.
pub(crate) async fn run_one_exchange(
    tunnel: &mut dyn Tunnel,
    request_bytes: &[u8],
    body: &[u8],
    idle: Duration,
) -> Result<WireResponse, String> {
    tunnel
        .send(request_bytes)
        .await
        .map_err(|e| format!("send head: {e}"))?;
    if !body.is_empty() {
        tunnel.send(body).await.map_err(|e| format!("send body: {e}"))?;
    }
    read_http_response(tunnel, idle).await
}

/// Read one full HTTP response (status line + headers + body) off `tunnel`.
///
/// Framing is resolved from the response headers themselves
/// (`Content-Length` or `Transfer-Encoding: chunked`), never by reading
/// until the peer closes the tunnel.
async fn read_http_response(tunnel: &mut dyn Tunnel, idle: Duration) -> Result<WireResponse, String> {
    let mut buf: Vec<u8> = Vec::with_capacity(4096);
    let header_end = loop {
        if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
            break pos;
        }
        if buf.len() > MAX_RESPONSE_HEADER_BYTES {
            return Err("response headers exceeded size limit".to_string());
        }
        let mut chunk = [0u8; 4096];
        let n = recv_idle(tunnel, &mut chunk, idle).await?;
        if n == 0 {
            return Err("tunnel closed before HTTP response".to_string());
        }
        buf.extend_from_slice(&chunk[..n]);
    };

    let header_bytes = buf[..header_end].to_vec();
    let mut body_buf = buf[header_end + 4..].to_vec();

    let status_line = header_bytes
        .split(|&b| b == b'\n')
        .next()
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .unwrap_or_default();
    if !status_line.starts_with("HTTP/1.") {
        return Err(format!(
            "unexpected response prefix: {:?}",
            &status_line[..status_line.len().min(60)]
        ));
    }
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    let headers_text = String::from_utf8_lossy(&header_bytes).into_owned();
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    for line in headers_text.split("\r\n").skip(1) {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "content-length" => content_length = value.parse().ok(),
            "transfer-encoding" => {
                if value.to_ascii_lowercase().contains("chunked") {
                    chunked = true;
                }
            }
            _ => {}
        }
    }

    if chunked {
        let body = read_chunked_body(tunnel, body_buf, idle).await?;
        return Ok(WireResponse { status, body });
    }

    if let Some(len) = content_length {
        while body_buf.len() < len {
            let mut chunk = [0u8; 4096];
            let n = recv_idle(tunnel, &mut chunk, idle).await?;
            if n == 0 {
                return Err("tunnel closed mid response body".to_string());
            }
            body_buf.extend_from_slice(&chunk[..n]);
        }
        body_buf.truncate(len);
        return Ok(WireResponse { status, body: body_buf });
    }

    // No declared length and not chunked — read to EOF; the peer is about
    // to close the tunnel.
    loop {
        let mut chunk = [0u8; 4096];
        match tunnel.recv(&mut chunk).await {
            Ok(0) => break,
            Ok(n) => body_buf.extend_from_slice(&chunk[..n]),
            Err(_) => break,
        }
    }
    Ok(WireResponse { status, body: body_buf })
}

/// `tunnel.recv` bounded by `idle`. A timeout here is a hard error — `0`
/// bytes already means "peer closed" (a distinct, valid outcome used by the
/// read-to-EOF fallback above); going silent mid-response without closing
/// must not be conflated with that.
async fn recv_idle(tunnel: &mut dyn Tunnel, buf: &mut [u8], idle: Duration) -> Result<usize, String> {
    match tokio::time::timeout(idle, tunnel.recv(buf)).await {
        Ok(r) => r.map_err(|e| format!("read response: {e}")),
        Err(_) => Err(format!("read response: idle timeout after {idle:?}")),
    }
}

/// Read a `Transfer-Encoding: chunked` body: repeated
/// `<hex-size>\r\n<data>\r\n` chunks terminated by a zero-size chunk,
/// followed by any trailer header lines and a final blank line.
async fn read_chunked_body(tunnel: &mut dyn Tunnel, mut buf: Vec<u8>, idle: Duration) -> Result<Vec<u8>, String> {
    let mut body = Vec::new();
    loop {
        let line_end = loop {
            if let Some(pos) = find_subslice(&buf, b"\r\n") {
                break pos;
            }
            fill(tunnel, &mut buf, idle).await?;
        };
        let size_line = String::from_utf8_lossy(&buf[..line_end]).into_owned();
        buf.drain(..line_end + 2);
        let size_hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_hex, 16).map_err(|e| format!("bad chunk size {size_hex:?}: {e}"))?;

        if size == 0 {
            loop {
                let line_end = loop {
                    if let Some(pos) = find_subslice(&buf, b"\r\n") {
                        break pos;
                    }
                    fill(tunnel, &mut buf, idle).await?;
                };
                let is_blank = line_end == 0;
                buf.drain(..line_end + 2);
                if is_blank {
                    break;
                }
            }
            break;
        }

        while buf.len() < size + 2 {
            fill(tunnel, &mut buf, idle).await?;
        }
        body.extend_from_slice(&buf[..size]);
        buf.drain(..size + 2); // chunk data + trailing CRLF
    }
    Ok(body)
}

/// Append one more `recv()` worth of bytes onto `buf`.
async fn fill(tunnel: &mut dyn Tunnel, buf: &mut Vec<u8>, idle: Duration) -> Result<(), String> {
    let mut chunk = [0u8; 4096];
    let n = recv_idle(tunnel, &mut chunk, idle).await?;
    if n == 0 {
        return Err("tunnel closed mid chunked body".to_string());
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

/// Find the first occurrence of `needle` in `haystack`.
fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;

    use async_trait::async_trait;
    use mirage_core::error::MirageError;
    use mirage_protocol::traits::TransportInfo;

    /// An in-memory stand-in for a Mirage tunnel: `recv` drains a canned
    /// response, `send` records what was written so the request half of
    /// the round trip is provable too, not just the response half.
    struct MockTunnel {
        inbound: VecDeque<u8>,
        sent: Vec<u8>,
        info: TransportInfo,
    }

    impl MockTunnel {
        fn with_response(response: &[u8]) -> Self {
            Self {
                inbound: response.iter().copied().collect(),
                sent: Vec::new(),
                info: TransportInfo::tcp_raw("127.0.0.1:0".parse().expect("valid loopback literal")),
            }
        }
    }

    #[async_trait]
    impl Tunnel for MockTunnel {
        async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
            self.sent.extend_from_slice(data);
            Ok(())
        }

        async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, MirageError> {
            let n = buf.len().min(self.inbound.len());
            for slot in buf.iter_mut().take(n) {
                *slot = self.inbound.pop_front().expect("n bounded by inbound.len() above");
            }
            Ok(n)
        }

        async fn close(&mut self) -> Result<(), MirageError> {
            Ok(())
        }

        fn transport_info(&self) -> &TransportInfo {
            &self.info
        }
    }

    // ── request framing round-trip ──────────────────────────────────────

    #[test]
    fn build_request_head_frames_method_path_and_sender_proof_headers() {
        let head = build_request_head(
            "monitor.example",
            "aWQtYmFzZTY0",
            "deadbeef",
            12345,
            "put",
            "/relay/entrance/subscriber-key?machine=edge-1",
            7,
        );
        let text = String::from_utf8(head.clone()).expect("head is ASCII");

        // Method is upper-cased even though the caller passed lowercase.
        assert!(text.starts_with("PUT /relay/entrance/subscriber-key?machine=edge-1 HTTP/1.1\r\n"));
        assert!(text.contains("Host: monitor.example\r\n"));
        assert!(text.contains("x-mirage-sender-identity: aWQtYmFzZTY0\r\n"));
        assert!(text.contains("x-mirage-sender-mac: deadbeef\r\n"));
        assert!(text.contains("x-mirage-sender-ts: 12345\r\n"));
        assert!(text.contains("Content-Type: application/json\r\n"));
        assert!(text.contains("Content-Length: 7\r\n"));
        assert!(text.ends_with("\r\n\r\n"), "head must end with the blank line that terminates HTTP headers");
    }

    #[test]
    fn build_request_head_omits_body_headers_for_an_empty_body() {
        let head = build_request_head("m", "id", "mac", 1, "GET", "/x", 0);
        let text = String::from_utf8(head).expect("head is ASCII");
        assert!(!text.contains("Content-Length"));
        assert!(!text.contains("Content-Type"));
    }

    /// Full exchange round trip: the head + body this crate SENDS, and the
    /// content-length-framed response it RECEIVES, both verified against
    /// the same bytes on the wire.
    #[tokio::test]
    async fn exchange_round_trips_a_content_length_response_and_records_what_was_sent() {
        let head = build_request_head("monitor.example", "id", "mac", 1, "POST", "/relay/entrance/subscriber-key", 4);
        let body = b"data";

        let response_body = br#"{"ok":true}"#;
        let mut wire = format!("HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n", response_body.len()).into_bytes();
        wire.extend_from_slice(response_body);

        let mut tunnel = MockTunnel::with_response(&wire);
        let resp = run_one_exchange(&mut tunnel, &head, body, Duration::from_secs(1))
            .await
            .expect("exchange succeeds against a well-formed response");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, response_body);

        let mut expected_sent = head;
        expected_sent.extend_from_slice(body);
        assert_eq!(tunnel.sent, expected_sent, "the head and body sent on the wire must match exactly what was passed in");
    }

    #[tokio::test]
    async fn exchange_round_trips_a_chunked_response() {
        let head = build_request_head("monitor.example", "id", "mac", 1, "GET", "/relay/entrance/dial-faces", 0);
        let wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n";

        let mut tunnel = MockTunnel::with_response(wire);
        let resp = run_one_exchange(&mut tunnel, &head, b"", Duration::from_secs(1))
            .await
            .expect("chunked exchange succeeds");

        assert_eq!(resp.status, 200);
        assert_eq!(resp.body, b"test");
    }

    #[tokio::test]
    async fn exchange_reports_a_non_2xx_status_without_erroring() {
        let head = build_request_head("monitor.example", "id", "mac", 1, "PUT", "/relay/entrance/subscriber-key", 0);
        let wire = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 7\r\n\r\nrefused";

        let mut tunnel = MockTunnel::with_response(wire);
        let resp = run_one_exchange(&mut tunnel, &head, b"", Duration::from_secs(1))
            .await
            .expect("a well-formed non-2xx response is still a successful FRAMING read");

        assert_eq!(resp.status, 403);
        assert_eq!(resp.body, b"refused");
    }

    #[tokio::test]
    async fn exchange_errors_on_a_response_with_no_terminated_header_block() {
        let head = build_request_head("m", "id", "mac", 1, "GET", "/x", 0);
        let mut tunnel = MockTunnel::with_response(b"not an http response");
        let err = run_one_exchange(&mut tunnel, &head, b"", Duration::from_millis(50))
            .await
            .expect_err("truncated header block must not parse as a response");
        assert!(err.contains("idle timeout") || err.contains("closed"), "got: {err}");
    }
}
