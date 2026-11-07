//! Byte cipher layer (stream cipher + magic variants).
//!
//! Sits between the wire-protocol tunnel and the transport socket.  The client
//! applies [`ByteCipher::wrap`] on every outbound payload before handing bytes
//! to the inner tunnel; the L1 server applies [`ByteCipher::unwrap`] on every
//! inbound chunk before dispatching to the L2 protocol chain.
//!
//! ByteCipher never decrypts the L2 content — it works on opaque byte slices.
//!
//! ## Design
//!
//! [`ByteCipher`] is **stateful** and **per-session**:
//! - `ObfuscateAll` tracks independent outbound/inbound packet counters.
//! - `ValidateFirst` / `StripFirst` track whether the first packet has already
//!   been processed.
//!
//! Call [`ByteCipher::reset`] to reuse an instance for a new session.
//!
//! The [`ByteCipherTunnel`] type wraps a [`Tunnel`] with a [`ByteCipher`] so
//! the client pool can apply wrapping transparently without touching every
//! call site.

use mirage_core::{
    config::{ByteCipherMode, ObfuscationAlgorithm},
    error::MirageError,
};

use chacha20::ChaCha8;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use rand::RngCore;

use crate::traits::{Tunnel, TransportInfo};

// ── Error type ────────────────────────────────────────────────────────────────

/// Errors produced by the byte cipher unwrap path.
#[derive(Debug, thiserror::Error)]
pub enum ByteCipherError {
    /// The first packet did not begin with the expected 16-byte magic.
    #[error("byte cipher magic mismatch: session rejected")]
    MagicMismatch,
    /// The packet was too short to contain the required header.
    #[error("byte cipher packet too short: need {needed} bytes, got {got}")]
    TooShort { needed: usize, got: usize },
}

impl From<ByteCipherError> for MirageError {
    fn from(e: ByteCipherError) -> Self {
        MirageError::Protocol(e.to_string())
    }
}

// ── ByteCipher ────────────────────────────────────────────────────────────────

/// Stateful byte cipher — one instance per session, one per direction or shared.
///
/// For `ObfuscateAll`, the cipher maintains **two independent counters**: one
/// for outbound (wrap) and one for inbound (unwrap).  This allows the same
/// struct to be used symmetrically on both sides of a bidirectional session.
///
/// For `ValidateFirst` / `StripFirst`, the first-packet flag is shared — after
/// the first packet is processed the remaining bytes flow through unchanged.
pub struct ByteCipher {
    mode: ByteCipherMode,
    /// Packet counter for the outbound (wrap) direction.
    out_counter: u64,
    /// Packet counter for the inbound (unwrap) direction.
    in_counter: u64,
    /// Whether the first packet has been processed (ValidateFirst / StripFirst).
    first_done: bool,
}

impl ByteCipher {
    /// Create a new cipher for the given mode.  Counters start at 0.
    pub fn new(mode: ByteCipherMode) -> Self {
        Self {
            mode,
            out_counter: 0,
            in_counter: 0,
            first_done: false,
        }
    }

    /// Reset counters and first-packet state for reuse across sessions.
    pub fn reset(&mut self) {
        self.out_counter = 0;
        self.in_counter = 0;
        self.first_done = false;
    }

    /// The cipher mode (read-only) — lets a tunnel decide reply-direction handling.
    pub fn mode(&self) -> &ByteCipherMode {
        &self.mode
    }

    /// Client side: wrap an outbound payload before writing to the transport.
    ///
    /// For `TCP` callers wrap each `write_all` payload; for `UDP` callers wrap
    /// each datagram independently.
    pub fn wrap(&mut self, payload: &[u8]) -> Vec<u8> {
        match &self.mode {
            ByteCipherMode::Raw => payload.to_vec(),

            ByteCipherMode::ValidateFirst { magic } => {
                if self.first_done {
                    payload.to_vec()
                } else {
                    self.first_done = true;
                    let mut out = Vec::with_capacity(16 + payload.len());
                    out.extend_from_slice(magic);
                    out.extend_from_slice(payload);
                    out
                }
            }

            ByteCipherMode::StripFirst { magic, junk_size } => {
                if self.first_done {
                    payload.to_vec()
                } else {
                    self.first_done = true;
                    let junk = *junk_size as usize;
                    let mut out = Vec::with_capacity(16 + junk + payload.len());
                    out.extend_from_slice(magic);
                    // Append random junk bytes
                    let mut rng = rand::thread_rng();
                    let old_len = out.len();
                    out.resize(old_len + junk, 0u8);
                    rng.fill_bytes(&mut out[old_len..]);
                    out.extend_from_slice(payload);
                    out
                }
            }

            ByteCipherMode::ObfuscateAll { algorithm, obf_key } => {
                let counter = self.out_counter;
                self.out_counter += 1;
                obfuscate(payload, counter, algorithm, obf_key)
            }
        }
    }

    /// Server side: unwrap an inbound byte slice received from the client.
    ///
    /// Returns `Ok(payload)` with any header stripped and/or XOR removed.
    /// Returns `Err(ByteCipherError::MagicMismatch)` to signal the session should be
    /// dropped.
    pub fn unwrap(&mut self, wire_bytes: &[u8]) -> Result<Vec<u8>, ByteCipherError> {
        match &self.mode {
            ByteCipherMode::Raw => Ok(wire_bytes.to_vec()),

            ByteCipherMode::ValidateFirst { magic } => {
                if self.first_done {
                    return Ok(wire_bytes.to_vec());
                }
                self.first_done = true;
                if wire_bytes.len() < 16 {
                    return Err(ByteCipherError::TooShort { needed: 16, got: wire_bytes.len() });
                }
                if wire_bytes[..16] != *magic {
                    return Err(ByteCipherError::MagicMismatch);
                }
                // Keep everything including magic — server may still want to
                // see the payload that followed the magic in the first packet.
                Ok(wire_bytes.to_vec())
            }

            ByteCipherMode::StripFirst { magic, junk_size } => {
                if self.first_done {
                    return Ok(wire_bytes.to_vec());
                }
                self.first_done = true;
                let header_len = 16 + *junk_size as usize;
                if wire_bytes.len() < header_len {
                    return Err(ByteCipherError::TooShort {
                        needed: header_len,
                        got: wire_bytes.len(),
                    });
                }
                if wire_bytes[..16] != *magic {
                    return Err(ByteCipherError::MagicMismatch);
                }
                // Strip magic + junk, return the payload portion.
                Ok(wire_bytes[header_len..].to_vec())
            }

            ByteCipherMode::ObfuscateAll { algorithm, obf_key } => {
                let counter = self.in_counter;
                self.in_counter += 1;
                deobfuscate(wire_bytes, counter, algorithm, obf_key)
            }
        }
    }
}

// ── Obfuscation helpers ───────────────────────────────────────────────────────

/// Wrap `payload` into an obfuscated wire packet.
///
/// Wire format depends on `algorithm`:
/// - `XorBlake3`: `[4B BE salt][XOR payload]`
/// - `ChaCha8`:   `[8B LE nonce][ChaCha8 ciphertext]`
fn obfuscate(
    payload: &[u8],
    counter: u64,
    algorithm: &ObfuscationAlgorithm,
    key: &[u8; 32],
) -> Vec<u8> {
    match algorithm {
        ObfuscationAlgorithm::XorBlake3 => {
            // Header: 4-byte big-endian salt counter (fits u32 for space; counter
            // is u64 but we truncate — sufficient for stend session counts).
            let salt = (counter as u32).to_be_bytes();
            let keystream = blake3_keystream(&salt, key, payload.len());
            let mut out = Vec::with_capacity(4 + payload.len());
            out.extend_from_slice(&salt);
            for (b, k) in payload.iter().zip(keystream.iter()) {
                out.push(b ^ k);
            }
            out
        }
        ObfuscationAlgorithm::ChaCha8 => {
            let nonce_bytes = counter.to_le_bytes(); // 8 bytes
            let mut out = Vec::with_capacity(8 + payload.len());
            out.extend_from_slice(&nonce_bytes);
            let mut ciphertext = payload.to_vec();
            chacha8_apply(key, &nonce_bytes, &mut ciphertext);
            out.extend_from_slice(&ciphertext);
            out
        }
    }
}

/// Strip the header from `wire_bytes` and XOR/decrypt back to plaintext.
fn deobfuscate(
    wire_bytes: &[u8],
    _counter: u64,
    algorithm: &ObfuscationAlgorithm,
    key: &[u8; 32],
) -> Result<Vec<u8>, ByteCipherError> {
    match algorithm {
        ObfuscationAlgorithm::XorBlake3 => {
            if wire_bytes.len() < 4 {
                return Err(ByteCipherError::TooShort { needed: 4, got: wire_bytes.len() });
            }
            let salt: [u8; 4] = wire_bytes[..4].try_into().expect("slice is 4 bytes");
            let ciphertext = &wire_bytes[4..];
            let keystream = blake3_keystream(&salt, key, ciphertext.len());
            let plaintext = ciphertext.iter().zip(keystream.iter()).map(|(b, k)| b ^ k).collect();
            Ok(plaintext)
        }
        ObfuscationAlgorithm::ChaCha8 => {
            if wire_bytes.len() < 8 {
                return Err(ByteCipherError::TooShort { needed: 8, got: wire_bytes.len() });
            }
            let nonce_bytes: [u8; 8] = wire_bytes[..8].try_into().expect("slice is 8 bytes");
            let mut plaintext = wire_bytes[8..].to_vec();
            chacha8_apply(key, &nonce_bytes, &mut plaintext);
            Ok(plaintext)
        }
    }
}

/// Produce `len` bytes of keystream via `BLAKE3(salt || key)`.
fn blake3_keystream(salt: &[u8; 4], key: &[u8; 32], len: usize) -> Vec<u8> {
    // BLAKE3 keyed hash: key = obf_key, data = salt bytes.
    // Produces 32 bytes; for payloads > 32 bytes we chain with an incremented
    // block counter appended to the salt.
    let mut out = Vec::with_capacity(len);
    let mut block: u32 = 0;
    while out.len() < len {
        let mut data = Vec::with_capacity(4 + 4);
        data.extend_from_slice(salt);
        data.extend_from_slice(&block.to_le_bytes());
        let hash = blake3::keyed_hash(key, &data);
        out.extend_from_slice(hash.as_bytes());
        block += 1;
    }
    out.truncate(len);
    out
}

/// Apply ChaCha8 in-place (encrypt = decrypt for stream cipher).
///
/// Key: 32 bytes.  Nonce: 8-byte little-endian counter, zero-padded to 12 bytes
/// as required by the `chacha20` crate's `ChaCha8` (96-bit nonce variant).
fn chacha8_apply(key: &[u8; 32], nonce_le_8: &[u8; 8], buf: &mut [u8]) {
    // ChaCha8 uses a 96-bit (12-byte) nonce.  We left-pad the 8-byte counter.
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(nonce_le_8);
    let mut cipher = ChaCha8::new(key.into(), &nonce.into());
    cipher.apply_keystream(buf);
}

// ── Onion wire-skin helpers ───────────────────────────────────────────────────

/// Build the one-time skin prefix the client writes before the onion envelope.
///
/// The entry node reads exactly `byte_cipher_skin_header_len(mode)` bytes from
/// the stream, validates / discards them, then treats the rest as the normal
/// onion frame.
///
/// Returns `None` for modes where no prefix is used (`Raw`, `ObfuscateAll`).
pub fn byte_cipher_skin_prefix(mode: &ByteCipherMode) -> Option<Vec<u8>> {
    match mode {
        ByteCipherMode::ValidateFirst { magic } => Some(magic.to_vec()),

        ByteCipherMode::StripFirst { magic, junk_size } => {
            let junk = *junk_size as usize;
            let mut out = Vec::with_capacity(16 + junk);
            out.extend_from_slice(magic);
            let old_len = out.len();
            out.resize(old_len + junk, 0u8);
            rand::thread_rng().fill_bytes(&mut out[old_len..]);
            Some(out)
        }

        // ObfuscateAll is a whole-stream cipher — no one-time prefix concept.
        // Raw — no prefix.
        ByteCipherMode::ObfuscateAll { .. } | ByteCipherMode::Raw => None,
    }
}

/// Number of header bytes the entry node must strip before reading the onion
/// envelope.
///
/// Returns `None` for modes that produce no prefix.
pub fn byte_cipher_skin_header_len(mode: &ByteCipherMode) -> Option<usize> {
    match mode {
        ByteCipherMode::ValidateFirst { .. } => Some(16),
        ByteCipherMode::StripFirst { junk_size, .. } => Some(16 + *junk_size as usize),
        ByteCipherMode::ObfuscateAll { .. } | ByteCipherMode::Raw => None,
    }
}

// ── ByteCipherTunnel ──────────────────────────────────────────────────────────

/// A [`Tunnel`] that applies [`ByteCipher`] on outbound data.
///
/// The client uses this to wrap every `send` payload before it reaches the
/// inner wire-protocol tunnel.  Inbound data (`recv`) is **not** unwrapped here
/// because byte cipher unwrapping happens at the L1 server; the server forwards
/// clean L2 bytes back to the client on the reverse direction.
///
/// For `ObfuscateAll` modes the L1 server also obfuscates its outbound (the
/// client→server direction uses `wrap`, the server→client direction uses
/// `wrap` on the server side and `unwrap` on the client side).  In that case
/// the caller must also call `unwrap` on received bytes — this struct handles
/// that symmetrically via the inbound counter.
pub struct ByteCipherTunnel {
    inner: Box<dyn Tunnel>,
    cipher: ByteCipher,
}

impl ByteCipherTunnel {
    /// Wrap `inner` with the given byte cipher mode.
    pub fn new(inner: Box<dyn Tunnel>, mode: ByteCipherMode) -> Self {
        Self {
            inner,
            cipher: ByteCipher::new(mode),
        }
    }
}

#[async_trait::async_trait]
impl Tunnel for ByteCipherTunnel {
    async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
        let wrapped = self.cipher.wrap(data);
        self.inner.send(&wrapped).await
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, MirageError> {
        match self.cipher.mode() {
            // Forward-only modes: the crypto_verify node validates/strips the
            // client's first chunk then `copy_bidirectional`s — replies come back
            // RAW, never wrapped. Pure passthrough: read straight into the caller's
            // buffer. (The old path over-read `buf.len()+16` then truncated the copy
            // to `buf.len()`, silently dropping up to 16 reply bytes per call →
            // stream corruption → HTTP/0.9.)
            ByteCipherMode::Raw
            | ByteCipherMode::ValidateFirst { .. }
            | ByteCipherMode::StripFirst { .. } => self.inner.recv(buf).await,

            // Whole-stream obfuscation is bidirectional — deobfuscate each frame.
            // (Stream framing for ObfuscateAll over raw TCP is a known limitation;
            // ValidateFirst/StripFirst are the DPI-test path.)
            ByteCipherMode::ObfuscateAll { .. } => {
                let mut tmp = vec![0u8; buf.len() + 16];
                let n = self.inner.recv(&mut tmp).await?;
                if n == 0 {
                    return Ok(0);
                }
                let plain = self.cipher.unwrap(&tmp[..n]).map_err(MirageError::from)?;
                let copy_len = plain.len().min(buf.len());
                buf[..copy_len].copy_from_slice(&plain[..copy_len]);
                Ok(copy_len)
            }
        }
    }

    async fn close(&mut self) -> Result<(), MirageError> {
        self.inner.close().await
    }

    fn transport_info(&self) -> &TransportInfo {
        self.inner.transport_info()
    }
}
