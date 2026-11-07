//! `MirageCoreTunnel` — the single AEAD frame loop used by all protocol variants.
//!
//! Wraps any `AsyncRead + AsyncWrite + Unpin` stream.  When `AuthMode::Hmac` is
//! active, a 4-byte HMAC-BLAKE3 prefix is prepended to / verified from each frame.

use async_trait::async_trait;
use mirage_core::{
    crypto::{AeadCipher, SessionKeys},
    error::MirageError,
    frame::{CamouflageType, Frame, FrameCodec},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    auth::{hmac::frame_hmac_prefix, AuthMode},
    traits::{TransportInfo, Tunnel},
};

// Chunk sizes used for frame padding — keeps payloads indistinguishable by length.
const CHUNK_SIZES: &[usize] = &[1024, 4096, 16384];

/// Maximum application payload carried in a single AEAD frame.
///
/// The on-wire length prefix is `u16`, so the ciphertext must stay ≤ 65535;
/// with the 5-byte plaintext header + 16-byte AEAD tag that bounds the payload
/// at 65514. We fragment at a conservative 60 KiB so any suite / padding stays
/// well under the cap. [`Tunnel::send`] splits larger writes across multiple
/// frames — the wire is a byte stream, so `recv()` reassembles transparently.
const MAX_FRAME_PAYLOAD: usize = 60 * 1024;

// ─────────────────────────────────────────────────────────────────────────────
// RecvPhase — cancel-safe recv state machine
// ─────────────────────────────────────────────────────────────────────────────

/// Tracks which part of the frame wire format we are currently reading.
///
/// State persists across `recv()` cancellations so that bytes already consumed
/// from the TCP stream are never lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RecvPhase {
    /// Waiting for the 4-byte HMAC prefix (only used when `auth == AuthMode::Hmac`).
    HmacPrefix,
    /// Waiting for the 2-byte big-endian ciphertext-length field.
    LengthPrefix,
    /// Waiting for the ciphertext body (`ct_len` bytes).
    Body,
}

// ─────────────────────────────────────────────────────────────────────────────
// MirageCoreTunnel
// ─────────────────────────────────────────────────────────────────────────────

/// Unified AEAD-framed tunnel.
///
/// Works over any `AsyncRead + AsyncWrite + Unpin` stream — raw TCP, TLS stream,
/// WebSocket-wrapped stream, etc.  The `auth` field controls optional per-frame
/// HMAC validation (only active for `AuthMode::Hmac`).
pub struct MirageCoreTunnel<S: AsyncRead + AsyncWrite + Unpin + Send> {
    stream: S,
    send_codec: FrameCodec,
    recv_codec: FrameCodec,
    /// Raw send key, kept for per-frame HMAC computation (AuthMode::Hmac).
    send_key: [u8; 32],
    /// Raw recv key, kept for per-frame HMAC verification (AuthMode::Hmac).
    recv_key: [u8; 32],
    /// Monotonic send-frame counter (for HMAC prefix and potential future use).
    send_counter: u64,
    /// Monotonic recv-frame counter (for HMAC prefix verification).
    recv_counter: u64,
    /// Bytes from the last decoded frame that did not fit into the caller's buffer.
    recv_overflow: Vec<u8>,
    info: TransportInfo,
    auth: AuthMode,
    // ── cancel-safe recv state ───────────────────────────────────────────────
    /// Current phase of the in-progress frame read.
    recv_phase: RecvPhase,
    /// Buffer accumulating the raw wire bytes for the current phase / frame.
    recv_wire: Vec<u8>,
    /// Number of bytes already written into `recv_wire`.
    recv_wire_pos: usize,
}

impl<S: AsyncRead + AsyncWrite + Unpin + Send> MirageCoreTunnel<S> {
    /// Construct a new tunnel.
    ///
    /// `is_client` — `true` for the connection initiator (determines key assignment).
    pub fn new(stream: S, keys: &SessionKeys, is_client: bool, info: TransportInfo, auth: AuthMode) -> Self {
        let (send_key, recv_key): ([u8; 32], [u8; 32]) = if is_client {
            (*keys.client_write_key, *keys.server_write_key)
        } else {
            (*keys.server_write_key, *keys.client_write_key)
        };
        let send_codec = FrameCodec::new(AeadCipher::with_suite(keys.suite, &send_key), CHUNK_SIZES.to_vec());
        let recv_codec = FrameCodec::new(AeadCipher::with_suite(keys.suite, &recv_key), CHUNK_SIZES.to_vec());
        let recv_phase = if auth == AuthMode::Hmac {
            RecvPhase::HmacPrefix
        } else {
            RecvPhase::LengthPrefix
        };
        Self {
            stream,
            send_codec,
            recv_codec,
            send_key,
            recv_key,
            send_counter: 0,
            recv_counter: 0,
            recv_overflow: Vec::new(),
            info,
            auth,
            recv_phase,
            recv_wire: Vec::new(),
            recv_wire_pos: 0,
        }
    }

    /// Encode + encrypt one AEAD frame and write it to the stream.
    ///
    /// `data` MUST be ≤ [`MAX_FRAME_PAYLOAD`]; the public [`Tunnel::send`]
    /// fragments larger writes into a sequence of these.
    async fn send_one_frame(&mut self, data: &[u8]) -> Result<(), MirageError> {
        let frame = Frame {
            cam_type: CamouflageType::Raw,
            payload: data.to_vec(),
        };
        let wire = self.send_codec.encode(&frame)?;

        if self.auth == AuthMode::Hmac {
            let prefix = frame_hmac_prefix(&self.send_key, self.send_counter);
            self.stream.write_all(&prefix).await?;
        }
        self.stream.write_all(&wire).await?;
        self.send_counter = self.send_counter.wrapping_add(1);
        Ok(())
    }
}

#[async_trait]
impl<S: AsyncRead + AsyncWrite + Unpin + Send + Sync> Tunnel for MirageCoreTunnel<S> {
    async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
        // A V9 wire is a byte stream. Fragment writes larger than one AEAD
        // frame can carry into multiple frames instead of failing the u16
        // length prefix. `recv()` yields frame payloads in order, and every
        // caller either treats recv as a byte stream or loops until it has N
        // bytes (e.g. `read_frame`), so fragmentation is transparent.
        // (Pre-fix, send > 65535 was a hard error — no working caller can rely
        // on 1-send == 1-frame, so this is strictly more permissive.)
        if data.is_empty() {
            // Preserve zero-length-write semantics (emit one empty frame).
            return self.send_one_frame(&[]).await;
        }
        for chunk in data.chunks(MAX_FRAME_PAYLOAD) {
            self.send_one_frame(chunk).await?;
        }
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, MirageError> {
        // Drain overflow from a previous oversized frame first.
        if !self.recv_overflow.is_empty() {
            let n = self.recv_overflow.len().min(buf.len());
            buf[..n].copy_from_slice(&self.recv_overflow[..n]);
            self.recv_overflow.drain(..n);
            return Ok(n);
        }

        loop {
            // ── Phase: HMAC prefix (4 bytes) ─────────────────────────────────
            if self.auth == AuthMode::Hmac && self.recv_phase == RecvPhase::HmacPrefix {
                if self.recv_wire.is_empty() {
                    self.recv_wire = vec![0u8; 4];
                    self.recv_wire_pos = 0;
                }
                while self.recv_wire_pos < 4 {
                    match self.stream.read(&mut self.recv_wire[self.recv_wire_pos..4]).await {
                        Ok(0) => return Ok(0),
                        Ok(n) => self.recv_wire_pos += n,
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(0),
                        Err(e) => return Err(MirageError::Io(e)),
                    }
                }
                let prefix: [u8; 4] = self.recv_wire[..4].try_into()
                    // SAFETY: recv_wire is exactly 4 bytes when we reach this point
                    .expect("recv_wire is 4 bytes");
                let expected = frame_hmac_prefix(&self.recv_key, self.recv_counter);
                if prefix != expected {
                    // Reset so the next recv() starts fresh (the connection is
                    // effectively broken, caller will drop it on AuthFailed).
                    self.recv_phase = RecvPhase::HmacPrefix;
                    self.recv_wire.clear();
                    self.recv_wire_pos = 0;
                    return Err(MirageError::AuthFailed);
                }
                self.recv_phase = RecvPhase::LengthPrefix;
                self.recv_wire.clear();
                self.recv_wire_pos = 0;
            }

            // If not Hmac, skip straight past HmacPrefix to LengthPrefix.
            if self.recv_phase == RecvPhase::HmacPrefix {
                self.recv_phase = RecvPhase::LengthPrefix;
            }

            // ── Phase: length prefix (2 bytes) ────────────────────────────────
            if self.recv_phase == RecvPhase::LengthPrefix {
                if self.recv_wire.is_empty() {
                    self.recv_wire = vec![0u8; 2];
                    self.recv_wire_pos = 0;
                }
                while self.recv_wire_pos < 2 {
                    match self.stream.read(&mut self.recv_wire[self.recv_wire_pos..2]).await {
                        Ok(0) => return Ok(0),
                        Ok(n) => self.recv_wire_pos += n,
                        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(0),
                        Err(e) => return Err(MirageError::Io(e)),
                    }
                }
                let ct_len = u16::from_be_bytes([self.recv_wire[0], self.recv_wire[1]]) as usize;
                // Expand wire to hold 2-byte length prefix + ciphertext body.
                self.recv_wire.resize(2 + ct_len, 0);
                // Length prefix already written at [0..2]; body starts at [2].
                self.recv_wire_pos = 2;
                self.recv_phase = RecvPhase::Body;
            }

            // ── Phase: ciphertext body ────────────────────────────────────────
            if self.recv_phase == RecvPhase::Body {
                let total = self.recv_wire.len();
                while self.recv_wire_pos < total {
                    match self.stream.read(&mut self.recv_wire[self.recv_wire_pos..total]).await {
                        Ok(0) => return Ok(0),
                        Ok(n) => self.recv_wire_pos += n,
                        Err(e) => return Err(MirageError::Io(e)),
                    }
                }

                // Full frame in hand — decode and advance counters.
                let frame = self.recv_codec.decode(&self.recv_wire)?;
                self.recv_counter = self.recv_counter.wrapping_add(1);

                // Reset state for the next frame.
                self.recv_phase = if self.auth == AuthMode::Hmac {
                    RecvPhase::HmacPrefix
                } else {
                    RecvPhase::LengthPrefix
                };
                self.recv_wire.clear();
                self.recv_wire_pos = 0;

                // Silently skip cover-traffic dummy frames.
                if frame.cam_type == CamouflageType::Dummy {
                    continue;
                }

                let payload = frame.payload;
                let n = payload.len().min(buf.len());
                buf[..n].copy_from_slice(&payload[..n]);
                if payload.len() > buf.len() {
                    self.recv_overflow.extend_from_slice(&payload[n..]);
                }
                return Ok(n);
            }
        }
    }

    async fn close(&mut self) -> Result<(), MirageError> {
        self.stream.shutdown().await?;
        Ok(())
    }

    fn transport_info(&self) -> &TransportInfo {
        &self.info
    }
}
