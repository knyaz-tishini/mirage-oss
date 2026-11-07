//! Per-leg AEAD suite negotiation.
//!
//! Single source of truth. The crypto layer (`crate::crypto`) re-exports
//! this type so all wire-byte ↔ enum conversion lives here.

use serde::{Deserialize, Serialize};

use crate::error::{MirageError, Result};

/// AEAD construction selected for a chain leg.
///
/// Negotiated in handshake (client lists supported suites, server picks one)
/// and bound into the transcript so any drift kills the layer keys.
///
/// Adding a new suite: append a variant, assign next u8, implement encrypt/
/// decrypt arms in `AeadCipher`. **Wire id is forever — never reuse a number.**
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[repr(u8)]
pub enum AeadSuite {
    /// ChaCha20-Poly1305. Best perf without AES-NI. 256-bit key, 96-bit nonce, 128-bit tag.
    ChaCha20Poly1305 = 0x01,
    /// AES-256-GCM. Hardware-accelerated on modern x86/ARM (AES-NI / PMULL).
    Aes256Gcm = 0x02,
    /// AES-128-GCM. Lighter for severely constrained CPUs. 128-bit key.
    Aes128Gcm = 0x03,
}

impl AeadSuite {
    pub const DEFAULT: Self = AeadSuite::ChaCha20Poly1305;

    /// Wire byte for transcript / negotiation list.
    pub fn id(self) -> u8 {
        self as u8
    }

    /// Wire byte (same as `id`, kept for parity with explicit API).
    pub fn as_u8(self) -> u8 {
        self as u8
    }

    /// Parse the wire byte. Unknown ids reject — never silently fall back.
    pub fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x01 => Ok(AeadSuite::ChaCha20Poly1305),
            0x02 => Ok(AeadSuite::Aes256Gcm),
            0x03 => Ok(AeadSuite::Aes128Gcm),
            other => Err(MirageError::Protocol(format!(
                "AeadSuite: unknown id 0x{:02x}",
                other
            ))),
        }
    }

    /// Soft parse — returns `None` on unknown id (use when downstream wants
    /// to treat it as a non-error condition).
    pub fn try_from_u8(b: u8) -> Option<Self> {
        Self::from_byte(b).ok()
    }

    /// Required key length in bytes. 32-byte layer keys are truncated for AES-128.
    pub fn key_len(self) -> usize {
        match self {
            AeadSuite::ChaCha20Poly1305 | AeadSuite::Aes256Gcm => 32,
            AeadSuite::Aes128Gcm => 16,
        }
    }

    pub fn nonce_len(self) -> usize {
        12
    }

    pub fn tag_len(self) -> usize {
        16
    }

    /// Pretty name for logging.
    pub fn name(self) -> &'static str {
        match self {
            AeadSuite::ChaCha20Poly1305 => "ChaCha20-Poly1305",
            AeadSuite::Aes256Gcm => "AES-256-GCM",
            AeadSuite::Aes128Gcm => "AES-128-GCM",
        }
    }

    /// snake_case wire label (matches the JSON serialisation).
    pub fn as_str(self) -> &'static str {
        match self {
            AeadSuite::ChaCha20Poly1305 => "cha_cha20_poly1305",
            AeadSuite::Aes256Gcm => "aes256_gcm",
            AeadSuite::Aes128Gcm => "aes128_gcm",
        }
    }
}

impl Default for AeadSuite {
    fn default() -> Self {
        Self::DEFAULT
    }
}
