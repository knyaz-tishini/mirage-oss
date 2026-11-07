//! AmneziaWG 2.0, the Noise_IK machine plus its own obfuscation.
//!
//! The implementation is awgtun 0.12.0, BSD-3-Clause.
//! Default features off: the noise machine, no TUN device.
//! This is not boringtun, and it is not the junk camouflage of Mirage.

pub use awgtun::noise::{Tunn, TunnResult};

use awgtun::amnezia::{Amnezia2Config, HeaderConfig, HeaderRange, JunkConfig, PaddingConfig};

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

/// AmneziaWG 2.0 obfuscation. Both ends carry the same values.
///
/// Header ranges are the text awgtun parses: one number, or `start-end`.
#[derive(Debug, Clone)]
pub struct AwgObfuscation {
    /// How many junk datagrams go out before the handshake.
    pub jc: u16,
    /// Shortest junk datagram.
    pub jmin: u16,
    /// Longest junk datagram.
    pub jmax: u16,
    /// Padding in front of a handshake initiation.
    pub s1: u16,
    /// Padding in front of a handshake response.
    pub s2: u16,
    /// Padding in front of a cookie reply.
    pub s3: u16,
    /// Padding in front of a transport packet.
    pub s4: u16,
    /// Header range for handshake initiation.
    pub h1: String,
    /// Header range for handshake response.
    pub h2: String,
    /// Header range for a cookie reply.
    pub h3: String,
    /// Header range for a transport packet.
    pub h4: String,
}

/// Build an awgtun tunnel from hex keys and one AmneziaWG 2.0 config.
///
/// `index` is 0 on the server and 1 on the client. The error text names which
/// field was refused and never includes a key.
pub fn tunn_from_hex(
    static_private_hex: &str,
    peer_public_hex: &str,
    preshared_key_hex: Option<&str>,
    obfuscation: &AwgObfuscation,
    index: u32,
) -> Result<Tunn, String> {
    let static_private = key32(static_private_hex, "private key")?;
    let peer_public = key32(peer_public_hex, "peer public key")?;
    let preshared = match preshared_key_hex {
        Some(hex) => Some(key32(hex, "preshared key")?),
        None => None,
    };
    let secret = awgtun::x25519::StaticSecret::from(static_private);
    let public = awgtun::x25519::PublicKey::from(peer_public);
    let amnezia = amnezia_config(obfuscation)?;
    Tunn::new_with_amnezia(secret, public, preshared, None, index, None, amnezia)
        .map_err(|err| format!("amneziawg config was refused: {err}"))
}

fn amnezia_config(obfuscation: &AwgObfuscation) -> Result<Amnezia2Config, String> {
    let mut config = Amnezia2Config::default();
    config.junk = JunkConfig::new(obfuscation.jc, obfuscation.jmin, obfuscation.jmax)
        .map_err(|err| format!("amneziawg junk was refused: {err}"))?;
    config.paddings = PaddingConfig::new(
        obfuscation.s1,
        obfuscation.s2,
        obfuscation.s3,
        obfuscation.s4,
    )
    .map_err(|err| format!("amneziawg padding was refused: {err}"))?;
    config.headers = HeaderConfig::new(
        HeaderRange::parse(&obfuscation.h1).map_err(|err| format!("amneziawg h1 was refused: {err}"))?,
        HeaderRange::parse(&obfuscation.h2).map_err(|err| format!("amneziawg h2 was refused: {err}"))?,
        HeaderRange::parse(&obfuscation.h3).map_err(|err| format!("amneziawg h3 was refused: {err}"))?,
        HeaderRange::parse(&obfuscation.h4).map_err(|err| format!("amneziawg h4 was refused: {err}"))?,
    )
    .map_err(|err| format!("amneziawg headers were refused: {err}"))?;
    Ok(config)
}

fn key32(hex: &str, which: &str) -> Result<[u8; 32], String> {
    let bytes = crate::decode_hex(hex).map_err(|_| format!("amneziawg {which} is not hex"))?;
    bytes
        .try_into()
        .map_err(|_| format!("amneziawg {which} is not 32 bytes"))
}
