//! HMAC variant — vestigial in v2.
//!
//! Handshake wire format is identical to `NoneAuth` (32B `e_pub` client → server).
//! In v2 this auth mode is rejected at the confirm step — `build_server_confirm`
//! and `verify_client_confirm` panic with an explicit "only Blake3 auth supported
//! in v2" message so any stale client/server pair fails loudly instead of silently
//! downgrading.
//!
//! The per-frame HMAC helper (`frame_hmac_prefix`) is kept because it is used by
//! `core/tunnel.rs` when `AuthMode::Hmac` is active and that call site is locked
//! (Phase 3 cleanup).

use mirage_core::{crypto::KeyPair, error::MirageError};

use super::private::Sealed;
use super::AuthStrategy;

/// Hmac auth strategy — vestigial in v2; panics on confirm paths.
pub struct HmacAuth;

impl Sealed for HmacAuth {}

impl AuthStrategy for HmacAuth {
    fn build_client_msg(
        &self,
        e_pub_bytes: &[u8; 32],
        _ecdh_bytes: &[u8; 32],
        _mesh_id: &[u8],
    ) -> Vec<u8> {
        e_pub_bytes.to_vec()
    }

    fn verify_server(
        &self,
        msg: &[u8],
        _keypair: &KeyPair,
        _mesh_id: &[u8],
    ) -> Result<[u8; 32], MirageError> {
        if msg.len() != 32 {
            return Err(MirageError::Handshake(format!(
                "HmacAuth: expected 32-byte client msg, got {}",
                msg.len()
            )));
        }
        let mut pub_bytes = [0u8; 32];
        pub_bytes.copy_from_slice(msg);
        Ok(pub_bytes)
    }

    fn build_server_confirm(
        &self,
        _ecdh_bytes: &[u8; 32],
        _s_pub_bytes: &[u8; 32],
        _mesh_id: &[u8],
    ) -> [u8; 32] {
        panic!("only Blake3 auth supported in v2 — Hmac confirm path is rejected");
    }

    fn verify_client_confirm(
        &self,
        _confirm: &[u8; 32],
        _ecdh_bytes: &[u8; 32],
        _s_pub_bytes: &[u8; 32],
        _mesh_id: &[u8],
    ) -> Result<(), MirageError> {
        panic!("only Blake3 auth supported in v2 — Hmac confirm path is rejected");
    }

    fn client_msg_len(&self) -> usize {
        32
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Per-frame HMAC helper (used by core/tunnel.rs when AuthMode::Hmac)
// TODO Phase 3: remove once tunnel.rs no longer branches on AuthMode::Hmac
// ─────────────────────────────────────────────────────────────────────────────

/// Compute the 4-byte HMAC-BLAKE3 frame prefix.
///
/// `session_key` — sender's write key (32 bytes).
/// `counter` — current frame counter (same as AEAD nonce counter at encode time).
pub fn frame_hmac_prefix(session_key: &[u8; 32], counter: u64) -> [u8; 4] {
    let mut keyed = blake3::Hasher::new_keyed(session_key);
    keyed.update(&counter.to_le_bytes());
    let hash = keyed.finalize();
    let bytes = hash.as_bytes();
    [bytes[0], bytes[1], bytes[2], bytes[3]]
}
