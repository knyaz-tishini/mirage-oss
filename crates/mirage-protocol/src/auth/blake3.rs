//! BLAKE3-authenticated handshake — Wire V8.
//!
//! ## Wire format
//! Client → Server: `[32B e_pub][32B ss_hint]`  (64 bytes total)
//!   - `ss_hint = BLAKE3(ecdh_bytes || e_pub || "MIRAGE-AUTH-V8" || mesh_id)`
//!
//! Server → Client confirm: `[32B BLAKE3(ecdh_bytes || s_pub || confirm_label(mesh_id))]`
//!   - `confirm_label(mesh_id) = b"MIRAGE-AUTH-V8-OK\0" || mesh_id`
//!
//! V8 bump: AUTH_LABEL and confirm PREFIX are bumped from V7 → V8 together with
//! the envelope wire version bump.  Pre-V7 clients (using V7 labels) fail at the
//! hint-verify step on V8 servers — hard cutover, no backwards compatibility.

use mirage_core::{
    crypto::{hash_blake3, shared_secret, KeyPair},
    error::MirageError,
};
use x25519_dalek::PublicKey;

use super::private::Sealed;
use super::AuthStrategy;

const AUTH_LABEL: &[u8] = b"MIRAGE-AUTH-V8";

/// Build the confirm label for a given `mesh_id`.
///
/// Format: `b"MIRAGE-AUTH-V8-OK\0" || mesh_id`
///
/// The NUL separator prevents a mesh_id of `b"XY"` aliasing a longer prefix.
fn confirm_label(mesh_id: &[u8]) -> Vec<u8> {
    const PREFIX: &[u8] = b"MIRAGE-AUTH-V8-OK\0";
    let mut v = Vec::with_capacity(PREFIX.len() + mesh_id.len());
    v.extend_from_slice(PREFIX);
    v.extend_from_slice(mesh_id);
    v
}

/// BLAKE3 hint in handshake — binds ephemeral key to the shared secret.
pub struct Blake3Auth;

impl Sealed for Blake3Auth {}

impl AuthStrategy for Blake3Auth {
    fn build_client_msg(
        &self,
        e_pub_bytes: &[u8; 32],
        ecdh_bytes: &[u8; 32],
        mesh_id: &[u8],
    ) -> Vec<u8> {
        let mut hint_input = Vec::with_capacity(32 + 32 + AUTH_LABEL.len() + mesh_id.len());
        hint_input.extend_from_slice(ecdh_bytes);
        hint_input.extend_from_slice(e_pub_bytes);
        hint_input.extend_from_slice(AUTH_LABEL);
        hint_input.extend_from_slice(mesh_id);
        let ss_hint = hash_blake3(&hint_input);

        let mut msg = Vec::with_capacity(64);
        msg.extend_from_slice(e_pub_bytes);
        msg.extend_from_slice(&ss_hint);
        msg
    }

    fn verify_server(
        &self,
        msg: &[u8],
        keypair: &KeyPair,
        mesh_id: &[u8],
    ) -> Result<[u8; 32], MirageError> {
        if msg.len() != 64 {
            return Err(MirageError::Handshake(format!(
                "Blake3Auth: expected 64-byte client msg, got {}",
                msg.len()
            )));
        }
        let e_pub_bytes: [u8; 32] = msg[..32].try_into().expect("length checked");
        let ss_hint: [u8; 32] = msg[32..].try_into().expect("length checked");

        let client_e_pub = PublicKey::from(e_pub_bytes);
        let ecdh_bytes = shared_secret(&keypair.secret, &client_e_pub);

        // Verify: ss_hint == BLAKE3(ecdh || e_pub || AUTH_LABEL || mesh_id)
        let mut hint_input = Vec::with_capacity(32 + 32 + AUTH_LABEL.len() + mesh_id.len());
        hint_input.extend_from_slice(&ecdh_bytes);
        hint_input.extend_from_slice(&e_pub_bytes);
        hint_input.extend_from_slice(AUTH_LABEL);
        hint_input.extend_from_slice(mesh_id);
        let expected_hint = hash_blake3(&hint_input);

        if expected_hint != ss_hint {
            return Err(MirageError::AuthFailed);
        }

        Ok(e_pub_bytes)
    }

    fn build_server_confirm(
        &self,
        ecdh_bytes: &[u8; 32],
        s_pub_bytes: &[u8; 32],
        mesh_id: &[u8],
    ) -> [u8; 32] {
        let label = confirm_label(mesh_id);
        let mut input = Vec::with_capacity(32 + 32 + label.len());
        input.extend_from_slice(ecdh_bytes);
        input.extend_from_slice(s_pub_bytes);
        input.extend_from_slice(&label);
        hash_blake3(&input)
    }

    fn verify_client_confirm(
        &self,
        confirm: &[u8; 32],
        ecdh_bytes: &[u8; 32],
        s_pub_bytes: &[u8; 32],
        mesh_id: &[u8],
    ) -> Result<(), MirageError> {
        let label = confirm_label(mesh_id);
        let mut input = Vec::with_capacity(32 + 32 + label.len());
        input.extend_from_slice(ecdh_bytes);
        input.extend_from_slice(s_pub_bytes);
        input.extend_from_slice(&label);
        let expected = hash_blake3(&input);

        if &expected != confirm {
            return Err(MirageError::Handshake(
                "Blake3Auth: server confirm BLAKE3 mismatch".into(),
            ));
        }
        Ok(())
    }

    fn client_msg_len(&self) -> usize {
        64
    }
}
