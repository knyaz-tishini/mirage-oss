//! Pluggable handshake authentication strategies.
//!
//! Callers select an `AuthMode` enum variant; dispatch functions route to the
//! concrete `AuthStrategy` implementation.  The trait is sealed — external code
//! cannot add strategies; only `AuthMode` variants are the public API.

pub mod blake3;
pub mod hmac;
pub mod none;
pub mod psk;
pub mod v9;

use mirage_core::{crypto::KeyPair, error::MirageError};
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────────────────────
// Sealed trait machinery
// ─────────────────────────────────────────────────────────────────────────────

pub(crate) mod private {
    pub trait Sealed {}
}

// ─────────────────────────────────────────────────────────────────────────────
// AuthStrategy — sealed trait
// ─────────────────────────────────────────────────────────────────────────────

/// Pluggable handshake authentication strategy.
///
/// Sealed — not implementable outside this crate.
pub trait AuthStrategy: private::Sealed + Send + Sync {
    /// Client side: build the outbound handshake message bytes.
    ///
    /// `e_pub_bytes` — client's ephemeral X25519 public key (32 bytes).
    /// `ecdh_bytes` — ECDH result `ECDH(server_static_pub, e_priv)` (32 bytes).
    /// `mesh_id` — mesh identifier baked into the hint (Blake3 only; ignored by
    /// other modes for signature consistency).
    ///
    /// Returns the complete wire message to write (length varies by strategy).
    fn build_client_msg(
        &self,
        e_pub_bytes: &[u8; 32],
        ecdh_bytes: &[u8; 32],
        mesh_id: &[u8],
    ) -> Vec<u8>;

    /// Server side: verify the received handshake message.
    ///
    /// `mesh_id` — mesh identifier baked into the confirm label (Blake3 only;
    /// ignored/panics for other modes in v2).
    ///
    /// Returns `Ok(e_pub_bytes)` on success so the caller can complete ECDH.
    /// Returns `Err(MirageError::AuthFailed)` → caller converts to Fallback.
    fn verify_server(
        &self,
        msg: &[u8],
        keypair: &KeyPair,
        mesh_id: &[u8],
    ) -> Result<[u8; 32], MirageError>;

    /// Server side: build the 32-byte confirmation to send back to the client.
    ///
    /// `mesh_id` — mesh identifier baked into the confirm label.
    fn build_server_confirm(
        &self,
        ecdh_bytes: &[u8; 32],
        s_pub_bytes: &[u8; 32],
        mesh_id: &[u8],
    ) -> [u8; 32];

    /// Client side: verify the server confirmation.
    ///
    /// `mesh_id` — must match the mesh_id the server used.
    fn verify_client_confirm(
        &self,
        confirm: &[u8; 32],
        ecdh_bytes: &[u8; 32],
        s_pub_bytes: &[u8; 32],
        mesh_id: &[u8],
    ) -> Result<(), MirageError>;

    /// Size of the complete client→server handshake message in bytes.
    fn client_msg_len(&self) -> usize;
}

// ─────────────────────────────────────────────────────────────────────────────
// AuthMode — public enum for configuration
// ─────────────────────────────────────────────────────────────────────────────

/// Selects the handshake authentication strategy and per-frame auth behaviour.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthMode {
    /// No auth — bare ECDH, no cryptographic binding.
    /// Vestigial in v2: panics on confirm paths.
    None,
    /// BLAKE3 hint in handshake message + mesh_id-bound confirm.
    Blake3,
    /// Bare handshake + 4-byte HMAC-BLAKE3 prefix on every frame.
    /// Vestigial in v2: panics on confirm paths.
    Hmac,
    /// PSK-keyed HMAC handshake (skeleton — not yet implemented).
    Psk { key_hex: String },
    /// V9 — ephemeral×ephemeral forward-secret + BLAKE3 DH-MAC mutual auth.
    ///
    /// All handshake logic lives in [`v9`]. Session key labels are `-v9`.
    /// Version is probed via the first byte of the ClientHello (0x09).
    V9MutualFs,
}

// ─────────────────────────────────────────────────────────────────────────────
// Dispatch functions
// ─────────────────────────────────────────────────────────────────────────────

/// Build the client handshake message for the given auth mode.
///
/// `mesh_id` is baked into the Blake3 hint (V3 wire format); other modes
/// ignore it but accept the argument for a uniform call-site signature.
pub fn dispatch_client_msg(
    mode: &AuthMode,
    e_pub: &[u8; 32],
    ecdh: &[u8; 32],
    mesh_id: &[u8],
) -> Vec<u8> {
    match mode {
        AuthMode::None => none::NoneAuth.build_client_msg(e_pub, ecdh, mesh_id),
        AuthMode::Blake3 => blake3::Blake3Auth.build_client_msg(e_pub, ecdh, mesh_id),
        AuthMode::Hmac => hmac::HmacAuth.build_client_msg(e_pub, ecdh, mesh_id),
        AuthMode::Psk { key_hex } => {
            psk::PskAuth::from_hex(key_hex).build_client_msg(e_pub, ecdh, mesh_id)
        }
        // V9 has its own handshake path — not dispatched through this function.
        AuthMode::V9MutualFs => panic!(
            "dispatch_client_msg: V9MutualFs must use run_client_handshake_v9 directly"
        ),
    }
}

/// Verify the client handshake message on the server side.
///
/// `mesh_id` — server's mesh identifier.  For Blake3 (V3) this is hashed into
/// the expected hint and a mismatch returns `Err(AuthFailed)` immediately.
/// NoneAuth and HmacAuth ignore it.
///
/// Returns `Ok(e_pub_bytes)` or `Err` on auth failure.
pub fn dispatch_verify_server(
    mode: &AuthMode,
    msg: &[u8],
    keypair: &KeyPair,
    mesh_id: &[u8],
) -> Result<[u8; 32], MirageError> {
    match mode {
        AuthMode::None => none::NoneAuth.verify_server(msg, keypair, mesh_id),
        AuthMode::Blake3 => blake3::Blake3Auth.verify_server(msg, keypair, mesh_id),
        AuthMode::Hmac => hmac::HmacAuth.verify_server(msg, keypair, mesh_id),
        AuthMode::Psk { key_hex } => {
            psk::PskAuth::from_hex(key_hex).verify_server(msg, keypair, mesh_id)
        }
        AuthMode::V9MutualFs => Err(MirageError::Protocol(
            "dispatch_verify_server: V9MutualFs must use run_server_handshake_v9 directly".into(),
        )),
    }
}

/// Build the server confirmation (32 bytes), binding `mesh_id` into the label.
pub fn dispatch_build_server_confirm(
    mode: &AuthMode,
    ecdh_bytes: &[u8; 32],
    s_pub_bytes: &[u8; 32],
    mesh_id: &[u8],
) -> [u8; 32] {
    match mode {
        AuthMode::None => none::NoneAuth.build_server_confirm(ecdh_bytes, s_pub_bytes, mesh_id),
        AuthMode::Blake3 => blake3::Blake3Auth.build_server_confirm(ecdh_bytes, s_pub_bytes, mesh_id),
        AuthMode::Hmac => hmac::HmacAuth.build_server_confirm(ecdh_bytes, s_pub_bytes, mesh_id),
        AuthMode::Psk { key_hex } => {
            psk::PskAuth::from_hex(key_hex).build_server_confirm(ecdh_bytes, s_pub_bytes, mesh_id)
        }
        AuthMode::V9MutualFs => panic!(
            "dispatch_build_server_confirm: V9MutualFs must use run_server_handshake_v9 directly"
        ),
    }
}

/// Verify the server confirmation on the client side, using the same `mesh_id`.
pub fn dispatch_verify_client_confirm(
    mode: &AuthMode,
    confirm: &[u8; 32],
    ecdh_bytes: &[u8; 32],
    s_pub_bytes: &[u8; 32],
    mesh_id: &[u8],
) -> Result<(), MirageError> {
    match mode {
        AuthMode::None => none::NoneAuth.verify_client_confirm(confirm, ecdh_bytes, s_pub_bytes, mesh_id),
        AuthMode::Blake3 => {
            blake3::Blake3Auth.verify_client_confirm(confirm, ecdh_bytes, s_pub_bytes, mesh_id)
        }
        AuthMode::Hmac => hmac::HmacAuth.verify_client_confirm(confirm, ecdh_bytes, s_pub_bytes, mesh_id),
        AuthMode::Psk { key_hex } => psk::PskAuth::from_hex(key_hex)
            .verify_client_confirm(confirm, ecdh_bytes, s_pub_bytes, mesh_id),
        AuthMode::V9MutualFs => Err(MirageError::Protocol(
            "dispatch_verify_client_confirm: V9MutualFs must use run_client_handshake_v9 directly".into(),
        )),
    }
}

/// Return the expected client message length for the given auth mode.
pub fn dispatch_client_msg_len(mode: &AuthMode) -> usize {
    match mode {
        AuthMode::None => none::NoneAuth.client_msg_len(),
        AuthMode::Blake3 => blake3::Blake3Auth.client_msg_len(),
        AuthMode::Hmac => hmac::HmacAuth.client_msg_len(),
        AuthMode::Psk { key_hex } => psk::PskAuth::from_hex(key_hex).client_msg_len(),
        AuthMode::V9MutualFs => panic!(
            "dispatch_client_msg_len: V9MutualFs must use run_client_handshake_v9 directly"
        ),
    }
}
