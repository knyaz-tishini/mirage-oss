//! WireGuard, the Noise_IK protocol.
//!
//! The implementation is boringtun 0.7.1, Cloudflare, BSD-3-Clause.
//! Default features only: the noise machine, no TUN device and no JNI.

pub use boringtun::noise::{Tunn, TunnResult};

/// What one `decapsulate` / `encapsulate` step produced.
///
/// The borrowed scratch buffer is copied out, so the next call can reuse it.
/// A failed step carries no key bytes.
#[derive(Debug)]
pub enum TunnStep {
    /// A datagram to send to the peer.
    Network(Vec<u8>),
    /// An inner packet that came out of the tunnel.
    Inner(Vec<u8>),
    /// Nothing further is queued.
    Done,
    /// The noise machine rejected the datagram.
    Failed,
}

/// Copy a [`TunnResult`] out of the scratch buffer.
pub fn take_tunn_result(result: TunnResult<'_>) -> TunnStep {
    match result {
        TunnResult::WriteToNetwork(buf) => TunnStep::Network(buf.to_vec()),
        TunnResult::WriteToTunnelV4(buf, _) | TunnResult::WriteToTunnelV6(buf, _) => {
            TunnStep::Inner(buf.to_vec())
        }
        TunnResult::Done => TunnStep::Done,
        TunnResult::Err(_) => TunnStep::Failed,
    }
}

/// Build a boringtun tunnel from hex keys.
///
/// `index` is 0 on the server and 1 on the client. The error text names which
/// key was refused and never includes the key.
pub fn tunn_from_hex(
    static_private_hex: &str,
    peer_public_hex: &str,
    preshared_key_hex: Option<&str>,
    index: u32,
) -> Result<Tunn, String> {
    let static_private = key32(static_private_hex, "private key")?;
    let peer_public = key32(peer_public_hex, "peer public key")?;
    let preshared = match preshared_key_hex {
        Some(hex) => Some(key32(hex, "preshared key")?),
        None => None,
    };
    let secret = boringtun::x25519::StaticSecret::from(static_private);
    let public = boringtun::x25519::PublicKey::from(peer_public);
    Ok(Tunn::new(secret, public, preshared, None, index, None))
}

fn key32(hex: &str, which: &str) -> Result<[u8; 32], String> {
    let bytes = crate::decode_hex(hex).map_err(|_| format!("wireguard {which} is not hex"))?;
    bytes
        .try_into()
        .map_err(|_| format!("wireguard {which} is not 32 bytes"))
}

/// How many payload bytes one inner datagram carries.
///
/// boringtun accepts only an IPv4 or IPv6 packet. The door wraps each slice
/// of the byte stream in one IPv4/UDP datagram of this size.
pub const CARRY_CHUNK: usize = 1200;

/// Wrap `payload` as one IPv4/UDP datagram.
///
/// Source and destination are `127.0.0.1`, both UDP ports are 1, and the
/// IPv4 total length is the real length. A longer slice is the caller's
/// to split — this function does not.
pub fn datagram_with_payload(payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut pkt = vec![0u8; total];
    pkt[0] = 0x45;
    pkt[2..4].copy_from_slice(&(total as u16).to_be_bytes());
    pkt[8] = 64;
    pkt[9] = 17;
    pkt[12] = 127;
    pkt[15] = 1;
    pkt[16] = 127;
    pkt[19] = 1;
    let sum = ipv4_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&sum.to_be_bytes());
    pkt[21] = 1;
    pkt[23] = 1;
    pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
    pkt[28..].copy_from_slice(payload);
    pkt
}

/// The UDP payload of an IPv4 datagram this door built, if that is what
/// `packet` is. Anything else — a keepalive, a junk datagram, a packet
/// that is not UDP — is `None`.
pub fn payload_of(packet: &[u8]) -> Option<&[u8]> {
    if packet.first().copied().unwrap_or(0) >> 4 != 4 {
        return None;
    }
    let ihl = ((packet[0] & 0x0f) as usize) * 4;
    if ihl < 20 || packet.len() < ihl + 8 || packet[9] != 17 {
        return None;
    }
    let udp_len = u16::from_be_bytes([packet[ihl + 4], packet[ihl + 5]]) as usize;
    if udp_len < 8 || ihl + udp_len > packet.len() {
        return None;
    }
    let total = u16::from_be_bytes([packet[2], packet[3]]) as usize;
    if total < ihl + udp_len || total > packet.len() {
        return None;
    }
    Some(&packet[ihl + 8..ihl + udp_len])
}

fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut index = 0;
    while index + 1 < header.len() {
        if index != 10 {
            sum += u16::from_be_bytes([header[index], header[index + 1]]) as u32;
        }
        index += 2;
    }
    while sum > 0xffff {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}
