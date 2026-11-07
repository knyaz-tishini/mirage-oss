//! PSK (Pre-Shared Key) auth — skeleton.
//!
//! PSK-keyed HMAC handshake (ShadowTLS-style).
//! Not used in the minimal bare path; will be implemented in a later step.

use mirage_core::{crypto::KeyPair, error::MirageError};

use super::private::Sealed;
use super::AuthStrategy;

/// PSK-keyed HMAC handshake strategy (skeleton — not yet implemented).
pub struct PskAuth {
    psk: [u8; 32],
}

impl PskAuth {
    /// Construct from a 64-character hex string.
    pub fn from_hex(s: &str) -> Self {
        let mut psk = [0u8; 32];
        // Decode hex into psk; truncate / zero-pad if length mismatches.
        let bytes: Vec<u8> = s
            .as_bytes()
            .chunks(2)
            .filter_map(|pair| {
                if pair.len() < 2 {
                    return None;
                }
                let hi = hex_nibble(pair[0])?;
                let lo = hex_nibble(pair[1])?;
                Some((hi << 4) | lo)
            })
            .collect();
        let copy_len = bytes.len().min(32);
        psk[..copy_len].copy_from_slice(&bytes[..copy_len]);
        Self { psk }
    }
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

impl Sealed for PskAuth {}

impl AuthStrategy for PskAuth {
    fn build_client_msg(
        &self,
        _e_pub_bytes: &[u8; 32],
        _ecdh_bytes: &[u8; 32],
        _mesh_id: &[u8],
    ) -> Vec<u8> {
        let _ = self.psk;
        unimplemented!("PskAuth is not yet implemented")
    }

    fn verify_server(
        &self,
        _msg: &[u8],
        _keypair: &KeyPair,
        _mesh_id: &[u8],
    ) -> Result<[u8; 32], MirageError> {
        unimplemented!("PskAuth is not yet implemented")
    }

    fn build_server_confirm(
        &self,
        _ecdh_bytes: &[u8; 32],
        _s_pub_bytes: &[u8; 32],
        _mesh_id: &[u8],
    ) -> [u8; 32] {
        unimplemented!("PskAuth is not yet implemented")
    }

    fn verify_client_confirm(
        &self,
        _confirm: &[u8; 32],
        _ecdh_bytes: &[u8; 32],
        _s_pub_bytes: &[u8; 32],
        _mesh_id: &[u8],
    ) -> Result<(), MirageError> {
        unimplemented!("PskAuth is not yet implemented")
    }

    fn client_msg_len(&self) -> usize {
        unimplemented!("PskAuth is not yet implemented")
    }
}
