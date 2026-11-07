//! DNS-over-TCP-via-SOCKS5 forwarding helper.
//!
//! Extracted from `mirage2tun/crates/mirage-tun-windows/src/ipstack.rs` so
//! that both TUN (mirage2tun) and the client-core forwarder (mirage2app) share
//! the same SOCKS5 TCP DNS implementation without a cross-workspace dep.
//!
//! # Wire format
//!
//! DNS-over-TCP uses a 2-byte big-endian length prefix before each message
//! (RFC 1035 §4.2.2).  This function opens a TCP connection through the SOCKS5
//! proxy to `dns_upstream` and exchanges exactly one query/response pair.
//!
//! # Retry
//!
//! Two attempts are made.  The second attempt fires immediately after the first
//! failure so transient SOCKS5 connection resets are handled transparently.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::MirageError;

/// Forward a raw DNS wire query through a SOCKS5 proxy to `dns_upstream`.
///
/// Returns the raw DNS wire response on success.  Two attempts are made before
/// returning the last error.
///
/// # Arguments
///
/// - `query` — raw DNS wire bytes (the UDP payload, NOT length-prefixed).
/// - `socks5_addr` — SOCKS5 proxy to connect through (e.g. `127.0.0.1:1080`).
/// - `dns_upstream` — DNS server behind the proxy (e.g. `8.8.8.8:53`).
pub async fn dns_forward_via_socks5(
    query: &[u8],
    socks5_addr: SocketAddr,
    dns_upstream: SocketAddr,
) -> Result<Vec<u8>, MirageError> {
    let mut last_err = None;
    for _ in 0..2u8 {
        match dns_tcp_via_socks5(query, socks5_addr, dns_upstream).await {
            Ok(resp) => return Ok(resp),
            Err(e) => {
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap_or_else(|| MirageError::Protocol("dns_forward_via_socks5: no attempts".into())))
}

/// Single attempt: connect SOCKS5 → dns_upstream, send query, read response.
async fn dns_tcp_via_socks5(
    query: &[u8],
    socks5_addr: SocketAddr,
    dns_upstream: SocketAddr,
) -> Result<Vec<u8>, MirageError> {
    let mut stream = socks5_connect(socks5_addr, dns_upstream).await?;

    // DNS-over-TCP: 2-byte big-endian length prefix (RFC 1035 §4.2.2).
    let len = query.len() as u16;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|e| MirageError::Protocol(format!("dns fwd: write len: {e}")))?;
    stream
        .write_all(query)
        .await
        .map_err(|e| MirageError::Protocol(format!("dns fwd: write query: {e}")))?;
    stream
        .flush()
        .await
        .map_err(|e| MirageError::Protocol(format!("dns fwd: flush: {e}")))?;

    // Read 2-byte length prefix.
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .map_err(|e| MirageError::Protocol(format!("dns fwd: read resp len: {e}")))?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;

    if resp_len < 12 {
        return Err(MirageError::Protocol(format!(
            "dns fwd: response too short: {resp_len} bytes"
        )));
    }

    let mut response = vec![0u8; resp_len];
    stream
        .read_exact(&mut response)
        .await
        .map_err(|e| MirageError::Protocol(format!("dns fwd: read resp body: {e}")))?;

    Ok(response)
}

/// Minimal SOCKS5 CONNECT handshake (no authentication).
///
/// RFC 1928 §3: client sends auth-method negotiation, server replies with
/// chosen method, then client sends CONNECT request, server replies with
/// bound address.  This implementation only supports NO-AUTH (method 0x00).
async fn socks5_connect(
    socks5_addr: SocketAddr,
    target: SocketAddr,
) -> Result<tokio::net::TcpStream, MirageError> {
    use tokio::net::TcpStream;

    let mut stream = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        TcpStream::connect(socks5_addr),
    )
    .await
    .map_err(|_| {
        MirageError::Protocol(format!("socks5 connect timeout to {socks5_addr}"))
    })?
    .map_err(|e| MirageError::Protocol(format!("socks5 connect to {socks5_addr}: {e}")))?;

    // ── Greeting: VER=5, NMETHODS=1, METHOD=0x00 (no auth) ───────────────────
    stream
        .write_all(&[0x05, 0x01, 0x00])
        .await
        .map_err(|e| MirageError::Protocol(format!("socks5 greeting write: {e}")))?;

    let mut method_reply = [0u8; 2];
    stream
        .read_exact(&mut method_reply)
        .await
        .map_err(|e| MirageError::Protocol(format!("socks5 method reply read: {e}")))?;

    if method_reply[0] != 0x05 {
        return Err(MirageError::Protocol(format!(
            "socks5: unexpected version {:#04x}",
            method_reply[0]
        )));
    }
    if method_reply[1] == 0xFF {
        return Err(MirageError::Protocol(
            "socks5: server rejected all auth methods".into(),
        ));
    }

    // ── CONNECT request ───────────────────────────────────────────────────────
    // VER=5, CMD=CONNECT(1), RSV=0, ATYP=IPv4(1) or IPv6(4)
    let mut req = Vec::with_capacity(22);
    req.extend_from_slice(&[0x05, 0x01, 0x00]); // VER CMD RSV

    match target.ip() {
        std::net::IpAddr::V4(v4) => {
            req.push(0x01); // ATYP IPv4
            req.extend_from_slice(&v4.octets());
        }
        std::net::IpAddr::V6(v6) => {
            req.push(0x04); // ATYP IPv6
            req.extend_from_slice(&v6.octets());
        }
    }
    let port = target.port();
    req.push((port >> 8) as u8);
    req.push((port & 0xFF) as u8);

    stream
        .write_all(&req)
        .await
        .map_err(|e| MirageError::Protocol(format!("socks5 CONNECT write: {e}")))?;

    // ── Reply: VER REP RSV ATYP [ADDR] PORT ──────────────────────────────────
    let mut reply_hdr = [0u8; 4];
    stream
        .read_exact(&mut reply_hdr)
        .await
        .map_err(|e| MirageError::Protocol(format!("socks5 reply hdr read: {e}")))?;

    if reply_hdr[1] != 0x00 {
        return Err(MirageError::Protocol(format!(
            "socks5 CONNECT failed: REP={:#04x}",
            reply_hdr[1]
        )));
    }

    // Consume BND.ADDR + BND.PORT (we don't use them).
    let atyp = reply_hdr[3];
    let addr_len: usize = match atyp {
        0x01 => 4,  // IPv4
        0x04 => 16, // IPv6
        0x03 => {
            // Domain name: first byte is length
            let mut len_byte = [0u8; 1];
            stream
                .read_exact(&mut len_byte)
                .await
                .map_err(|e| MirageError::Protocol(format!("socks5 domain len: {e}")))?;
            len_byte[0] as usize
        }
        other => {
            return Err(MirageError::Protocol(format!(
                "socks5 reply unknown ATYP {other:#04x}"
            )))
        }
    };
    let mut skip = vec![0u8; addr_len + 2]; // addr + 2-byte port
    stream
        .read_exact(&mut skip)
        .await
        .map_err(|e| MirageError::Protocol(format!("socks5 reply addr/port skip: {e}")))?;

    Ok(stream)
}
