//! Bare ECDH auth — vestigial in v2.
//!
//! Wire: client sends 32B `e_pub`. No cryptographic binding between the
//! handshake and the session keys.
//!
//! In v2 this auth mode is rejected at the confirm step — `build_server_confirm`
//! and `verify_client_confirm` panic with an explicit "only Blake3 auth supported
//! in v2" message so any stale client/server pair fails loudly.

use mirage_core::{crypto::KeyPair, error::MirageError};

use super::private::Sealed;
use super::AuthStrategy;

/// No-auth strategy — vestigial in v2; panics on confirm paths.
pub struct NoneAuth;

impl Sealed for NoneAuth {}

impl AuthStrategy for NoneAuth {
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
                "NoneAuth: expected 32-byte client msg, got {}",
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
        panic!("only Blake3 auth supported in v2 — None confirm path is rejected");
    }

    fn verify_client_confirm(
        &self,
        _confirm: &[u8; 32],
        _ecdh_bytes: &[u8; 32],
        _s_pub_bytes: &[u8; 32],
        _mesh_id: &[u8],
    ) -> Result<(), MirageError> {
        panic!("only Blake3 auth supported in v2 — None confirm path is rejected");
    }

    fn client_msg_len(&self) -> usize {
        32
    }
}
