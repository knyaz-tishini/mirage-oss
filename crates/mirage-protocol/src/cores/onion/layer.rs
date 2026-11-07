use std::net::SocketAddr;

use mirage_core::{
    crypto::{AeadCipher, AeadSuite},
    error::MirageError,
};

/// Address tag in the layer wire format.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AddrTag {
    Terminal = 0x00,
    Ipv4 = 0x01,
    Ipv6 = 0x02,
    Hostname = 0x03,
}

impl AddrTag {
    pub fn from_byte(b: u8) -> Result<Self, MirageError> {
        match b {
            0x00 => Ok(AddrTag::Terminal),
            0x01 => Ok(AddrTag::Ipv4),
            0x02 => Ok(AddrTag::Ipv6),
            0x03 => Ok(AddrTag::Hostname),
            _ => Err(MirageError::Protocol(format!(
                "onion: unknown addr_tag 0x{:02x}",
                b
            ))),
        }
    }
}

/// Encoded address of the next hop inside a layer.
#[derive(Debug, Clone)]
pub enum NextHop {
    Terminal,
    Socket(SocketAddr),
    Hostname { host: String, port: u16 },
}

impl NextHop {
    /// Encode to wire format: `[tag][addr_bytes]` (tag determines the addr length).
    pub fn encode(&self) -> Vec<u8> {
        match self {
            NextHop::Terminal => vec![0x00],
            NextHop::Socket(SocketAddr::V4(v4)) => {
                let mut out = Vec::with_capacity(7);
                out.push(0x01);
                out.extend_from_slice(&v4.ip().octets());
                out.extend_from_slice(&v4.port().to_be_bytes());
                out
            }
            NextHop::Socket(SocketAddr::V6(v6)) => {
                let mut out = Vec::with_capacity(19);
                out.push(0x02);
                out.extend_from_slice(&v6.ip().octets());
                out.extend_from_slice(&v6.port().to_be_bytes());
                out
            }
            NextHop::Hostname { host, port } => {
                let host_bytes = host.as_bytes();
                assert!(
                    host_bytes.len() <= 255,
                    "onion: hostname too long (max 255 bytes)"
                );
                let mut out = Vec::with_capacity(1 + 1 + host_bytes.len() + 2);
                out.push(0x03);
                out.push(host_bytes.len() as u8);
                out.extend_from_slice(host_bytes);
                out.extend_from_slice(&port.to_be_bytes());
                out
            }
        }
    }

    /// Decode a `NextHop` from the front of `data`. Returns `(next_hop, bytes_consumed)`.
    pub fn decode(data: &[u8]) -> Result<(Self, usize), MirageError> {
        if data.is_empty() {
            return Err(MirageError::Protocol("onion: empty layer".into()));
        }
        let tag = AddrTag::from_byte(data[0])?;
        match tag {
            AddrTag::Terminal => Ok((NextHop::Terminal, 1)),
            AddrTag::Ipv4 => {
                if data.len() < 7 {
                    return Err(MirageError::Protocol("onion: truncated ipv4".into()));
                }
                let ip: [u8; 4] = data[1..5].try_into().unwrap();
                let port = u16::from_be_bytes(data[5..7].try_into().unwrap());
                Ok((NextHop::Socket(SocketAddr::from((ip, port))), 7))
            }
            AddrTag::Ipv6 => {
                if data.len() < 19 {
                    return Err(MirageError::Protocol("onion: truncated ipv6".into()));
                }
                let ip: [u8; 16] = data[1..17].try_into().unwrap();
                let port = u16::from_be_bytes(data[17..19].try_into().unwrap());
                Ok((NextHop::Socket(SocketAddr::from((ip, port))), 19))
            }
            AddrTag::Hostname => {
                if data.len() < 2 {
                    return Err(MirageError::Protocol(
                        "onion: truncated hostname hdr".into(),
                    ));
                }
                let host_len = data[1] as usize;
                let end = 2 + host_len + 2;
                if data.len() < end {
                    return Err(MirageError::Protocol("onion: truncated hostname".into()));
                }
                let host = String::from_utf8(data[2..2 + host_len].to_vec()).map_err(|e| {
                    MirageError::Protocol(format!("onion: invalid hostname utf8: {}", e))
                })?;
                let port =
                    u16::from_be_bytes(data[2 + host_len..end].try_into().unwrap());
                Ok((NextHop::Hostname { host, port }, end))
            }
        }
    }
}
// ── Reply onion (reverse-wrap) ────────────────────────────────────────────────

/// Nonce for reply direction — must differ from forward nonce `[0; 12]`.
const REPLY_NONCE: [u8; 12] = [1; 12];

// ── V7 suite-aware wraps ──────────────────────────────────────────────────────
//
// AAD versioned to `v7` — domain separation ensures V5 peers cannot accidentally
// decrypt V7 frames and vice versa.

/// Forward-direction AAD prefix for V7 layers — `addr_bytes` concatenated after.
fn aad_forward_v7(addr_bytes: &[u8]) -> Vec<u8> {
    let mut a = Vec::with_capacity(b"mirage-onion-forward-v7".len() + addr_bytes.len());
    a.extend_from_slice(b"mirage-onion-forward-v7");
    a.extend_from_slice(addr_bytes);
    a
}

const REPLY_AAD_V7: &[u8] = b"mirage-onion-reply-v7";

/// V7 wrap with negotiated AEAD suite.
pub fn wrap_layer_v7(
    suite: AeadSuite,
    next_hop: &NextHop,
    layer_key: &[u8; 32],
    inner_payload: &[u8],
) -> Result<Vec<u8>, MirageError> {
    let addr_bytes = next_hop.encode();
    let aad = aad_forward_v7(&addr_bytes);
    let cipher = AeadCipher::with_suite(suite, layer_key);
    let ciphertext = cipher
        .encrypt(&[0u8; 12], inner_payload, &aad)
        .map_err(|e| MirageError::Crypto(format!("onion wrap v7 AEAD failed: {}", e)))?;
    let mut out = Vec::with_capacity(addr_bytes.len() + ciphertext.len());
    out.extend_from_slice(&addr_bytes);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// V7 peel with negotiated AEAD suite.
pub fn peel_layer_v7(
    suite: AeadSuite,
    wire_bytes: &[u8],
    layer_key: &[u8; 32],
) -> Result<(NextHop, Vec<u8>), MirageError> {
    let (next_hop, addr_len) = NextHop::decode(wire_bytes)?;
    let addr_bytes = &wire_bytes[..addr_len];
    let ciphertext = &wire_bytes[addr_len..];
    let aad = aad_forward_v7(addr_bytes);
    let cipher = AeadCipher::with_suite(suite, layer_key);
    let inner = cipher
        .decrypt(&[0u8; 12], ciphertext, &aad)
        .map_err(|e| MirageError::Crypto(format!("onion peel v7 AEAD failed: {:?}", e)))?;
    Ok((next_hop, inner))
}

/// V7 reply wrap (server side, reverse-onion).
pub fn wrap_reply_layer_v7(
    suite: AeadSuite,
    layer_key: &[u8; 32],
    reply_plaintext: &[u8],
) -> Result<Vec<u8>, MirageError> {
    let cipher = AeadCipher::with_suite(suite, layer_key);
    cipher
        .encrypt(&REPLY_NONCE, reply_plaintext, REPLY_AAD_V7)
        .map_err(|e| MirageError::Protocol(format!("onion reply wrap v7 AEAD failed: {}", e)))
}

/// V7 reply peel (client side).
pub fn peel_reply_layer_v7(
    suite: AeadSuite,
    layer_key: &[u8; 32],
    wire_bytes: &[u8],
) -> Result<Vec<u8>, MirageError> {
    let cipher = AeadCipher::with_suite(suite, layer_key);
    cipher
        .decrypt(&REPLY_NONCE, wire_bytes, REPLY_AAD_V7)
        .map_err(|e| MirageError::Protocol(format!("onion reply peel v7 AEAD failed: {:?}", e)))
}
