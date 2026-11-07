use bytes::{BufMut, BytesMut};

use crate::crypto::{AeadCipher, AeadSuite};
use crate::error::{MirageError, Result};

/// Camouflage type tag embedded in every frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CamouflageType {
    JsonApi = 0x01,
    BinaryBlob = 0x02,
    GrpcFrame = 0x03,
    WebSocket = 0x04,
    /// Cover traffic — payload is random bytes; receiver discards immediately.
    Dummy = 0xFB,
    /// Rekey initiation — payload is a 32-byte ephemeral X25519 public key.
    RekeyRequest = 0xFD,
    /// Rekey acknowledgment — payload is a 32-byte ephemeral X25519 public key.
    RekeyAck = 0xFE,
    Raw = 0xFF,
}

impl CamouflageType {
    /// Parse a camouflage type from its wire byte.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Self::JsonApi),
            0x02 => Some(Self::BinaryBlob),
            0x03 => Some(Self::GrpcFrame),
            0x04 => Some(Self::WebSocket),
            0xFB => Some(Self::Dummy),
            0xFD => Some(Self::RekeyRequest),
            0xFE => Some(Self::RekeyAck),
            0xFF => Some(Self::Raw),
            _ => None,
        }
    }
}

/// A logical frame carrying typed application data.
///
/// Wire layout (plaintext before encryption):
/// ```text
/// [4B big-endian payload_len][1B cam_type][payload bytes][zero padding to chunk_size]
/// ```
///
/// Wire layout (on the wire):
/// ```text
/// [2B big-endian ciphertext_len][ciphertext || 16B AEAD tag]
/// ```
/// where `ciphertext_len` covers everything after the 2-byte length field.
pub struct Frame {
    pub cam_type: CamouflageType,
    pub payload: Vec<u8>,
}

/// Stateful encoder / decoder for [`Frame`] values.
///
/// Maintains an independent nonce counter so every encrypted chunk uses a unique
/// nonce without requiring the caller to track nonce state.
pub struct FrameCodec {
    cipher: AeadCipher,
    nonce_counter: u64,
    /// Candidate padded chunk sizes (bytes). The encoder picks the smallest
    /// value that is >= the plaintext size, falling back to the largest if none fits.
    chunk_sizes: Vec<usize>,
}

impl FrameCodec {
    /// Create a codec with the given AEAD cipher and padding chunk sizes.
    ///
    /// `chunk_sizes` must be non-empty. Common values: `vec![4096, 8192, 16384]`.
    pub fn new(cipher: AeadCipher, chunk_sizes: Vec<usize>) -> Self {
        assert!(!chunk_sizes.is_empty(), "chunk_sizes must not be empty");
        Self {
            cipher,
            nonce_counter: 0,
            chunk_sizes,
        }
    }

    /// Encode and encrypt a [`Frame`] into a length-prefixed wire buffer.
    ///
    /// Plaintext layout: `[4B payload_len][1B cam_type][payload][zero padding]`
    /// Wire layout: `[2B big-endian ciphertext_len][ciphertext || 16B tag]`
    ///
    /// The payload length is stored inside the plaintext so the decoder can
    /// strip padding precisely after decryption without any AAD guessing.
    pub fn encode(&mut self, frame: &Frame) -> Result<Vec<u8>> {
        // 4 bytes length prefix + 1 byte type tag + payload
        let plain_content_len = 4 + 1 + frame.payload.len();

        // Pick the smallest chunk bucket that accommodates the plaintext.
        let padded_len = self
            .chunk_sizes
            .iter()
            .copied()
            .find(|&sz| sz >= plain_content_len)
            .unwrap_or_else(|| *self.chunk_sizes.last().expect("chunk_sizes is non-empty"));

        // If payload exceeds the largest chunk, send with no padding.
        let padded_len = padded_len.max(plain_content_len);
        let padding = padded_len - plain_content_len;

        let mut plaintext = BytesMut::with_capacity(padded_len);
        plaintext.put_u32(frame.payload.len() as u32);
        plaintext.put_u8(frame.cam_type as u8);
        plaintext.put_slice(&frame.payload);
        plaintext.put_bytes(0u8, padding);

        let nonce = self.next_nonce();
        let ciphertext = self.cipher.encrypt(&nonce, &plaintext, &[])?;

        let total_len = ciphertext.len();
        if total_len > u16::MAX as usize {
            return Err(MirageError::Protocol(format!(
                "encoded frame too large for u16 wire prefix: {total_len} bytes"
            )));
        }

        let mut out = Vec::with_capacity(2 + total_len);
        out.extend_from_slice(&(total_len as u16).to_be_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    /// Decode and decrypt a complete wire frame from `data`.
    ///
    /// `data` must start at the 4-byte length field and contain at least one
    /// complete frame.
    pub fn decode(&mut self, data: &[u8]) -> Result<Frame> {
        if data.len() < 2 {
            return Err(MirageError::Protocol("frame too short".into()));
        }
        let total_len = u16::from_be_bytes([data[0], data[1]]) as usize;
        let ciphertext = data.get(2..2 + total_len).ok_or_else(|| {
            MirageError::Protocol(format!(
                "frame data truncated: expected {total_len} bytes, got {}",
                data.len().saturating_sub(2)
            ))
        })?;

        let nonce = self.next_nonce();
        let plaintext = self
            .cipher
            .decrypt(&nonce, ciphertext, &[])
            .map_err(|_| MirageError::AuthFailed)?;

        // Plaintext layout: [4B payload_len][1B cam_type][payload][zero padding]
        if plaintext.len() < 5 {
            return Err(MirageError::Protocol("decrypted frame too short".into()));
        }

        let payload_len =
            u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]) as usize;
        let cam_byte = plaintext[4];
        let cam_type = CamouflageType::from_u8(cam_byte).ok_or_else(|| {
            MirageError::Protocol(format!("unknown camouflage type: 0x{cam_byte:02X}"))
        })?;

        let payload_start = 5;
        let payload_end = payload_start + payload_len;
        if payload_end > plaintext.len() {
            return Err(MirageError::Protocol(format!(
                "payload_len {payload_len} exceeds decrypted frame length {}",
                plaintext.len()
            )));
        }
        let payload = plaintext[payload_start..payload_end].to_vec();

        Ok(Frame { cam_type, payload })
    }

    /// Replace the AEAD cipher with a new key and reset the nonce counter to 0.
    ///
    /// Called after a successful rekey exchange.  All subsequent frames will be
    /// encrypted/decrypted with the new key starting at nonce 0.
    ///
    /// `suite` must match the suite negotiated for this session — the rekey
    /// ratchet does not change the suite, only the key material.
    pub fn rekey_reset(&mut self, suite: AeadSuite, new_key: &[u8; 32]) {
        self.cipher = AeadCipher::with_suite(suite, new_key);
        self.nonce_counter = 0;
    }

    /// Build the next 12-byte nonce: 8-byte little-endian counter + 4 zero bytes.
    fn next_nonce(&mut self) -> [u8; 12] {
        let counter = self.nonce_counter;
        self.nonce_counter = self.nonce_counter.wrapping_add(1);
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&counter.to_le_bytes());
        nonce
    }
}
