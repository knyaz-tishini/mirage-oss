//! Handshake authentication strategy.
//!
//! Strength axis applied per-leg via `LayerSpec.auth` or per-listener via
//! `ListenerSpec` (when no per-leg override is set). Independent of
//! camouflage and byte-cipher.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum AuthMode {
    /// No auth — bare ECDH, no cryptographic binding.
    None,
    /// BLAKE3 hint embedded in the handshake message.
    Blake3,
    /// Bare handshake + 4-byte HMAC-BLAKE3 prefix on every frame.
    Hmac,
    /// PSK-keyed HMAC handshake — pre-shared key bound into the transcript.
    Psk { key_hex: String },
}

impl Default for AuthMode {
    fn default() -> Self {
        AuthMode::Blake3
    }
}

impl AuthMode {
    pub fn label(&self) -> &'static str {
        match self {
            AuthMode::None => "none",
            AuthMode::Blake3 => "blake3",
            AuthMode::Hmac => "hmac",
            AuthMode::Psk { .. } => "psk",
        }
    }
}
