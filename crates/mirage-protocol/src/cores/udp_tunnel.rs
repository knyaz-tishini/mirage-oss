//! `MirageCoreUdpTunnel` — AEAD-framed datagram tunnel over `UdpPeerSocket`.
//!
//! UDP is datagram-oriented: each `send` / `recv` maps to exactly one UDP
//! datagram.  This is fundamentally different from the stream-based
//! `MirageCoreTunnel` which uses a 2-byte length prefix to delimit frames.
//!
//! Here each datagram *is* the frame — no length prefix is needed because UDP
//! preserves message boundaries.  A `FrameCodec` encodes / decodes AEAD ciphertext
//! as usual; the resulting bytes are sent as a single datagram.
//!
//! Frame wire format (one UDP datagram):
//! ```text
//! [2B BE ciphertext_len][AEAD ciphertext (payload + 16B tag)]
//! ```
//!
//! Per-frame HMAC (`AuthMode::Hmac`) is prepended as a 4-byte prefix exactly as
//! in the stream variant:
//! ```text
//! [4B HMAC prefix][2B BE ciphertext_len][AEAD ciphertext]
//! ```
//!
//! # MTU note
//!
//! UDP datagrams must fit in a single IP packet (typically ≤1500 bytes after
//! Ethernet framing).  Callers must ensure payloads are small enough; this
//! module does not fragment.
//!
//! # Reading a datagram: two entry points, one code path
//!
//! [`MirageCoreUdpTunnel::recv_datagram`] returns the decrypted payload as an
//! owned `Vec<u8>` — the truncation-proof way to read, since nothing is
//! copied into a fixed-size buffer. [`Tunnel::recv`] exists for callers that
//! hold a `Box<dyn Tunnel>` and must fill a caller-supplied buffer; it calls
//! `recv_datagram` internally and returns
//! [`MirageError::Protocol`](mirage_core::error::MirageError::Protocol) when
//! the payload does not fit, rather than silently handing back a truncated
//! `Ok`. Both entry points share the same frame-handling loop, so there is
//! exactly one place the HMAC sliding window, the dummy-frame skip, and the
//! discard-and-continue paths are implemented.
//!
//! A zero-length payload is a legitimate, fully-authenticated empty
//! datagram, never an end-of-stream marker — this tunnel type never reports
//! a "closed" state through `recv` (UDP itself has no end-of-stream signal
//! and [`Tunnel::close`](crate::traits::Tunnel::close) is a no-op), so an
//! `Ok(0)` / `Ok(vec![])` here can only mean "the peer sent an empty
//! message", not "the tunnel ended".

use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use mirage_core::{
    crypto::{AeadCipher, SessionKeys},
    error::MirageError,
    frame::{CamouflageType, Frame, FrameCodec},
};

use crate::{
    auth::{hmac::frame_hmac_prefix, AuthMode},
    traits::{TransportInfo, Tunnel},
    transport::udp::UdpPeerSocket,
};

/// Maximum UDP datagram buffer size.
const MAX_DGRAM: usize = 65_536;

// Chunk sizes used for frame padding — identical to `MirageCoreTunnel`.
const CHUNK_SIZES: &[usize] = &[1024, 4096, 16384];

/// HMAC sliding-window size — the receiver accepts any frame whose HMAC
/// matches a counter in `[base, base+HMAC_RECV_WINDOW)`. Tolerates UDP
/// reorder + loss up to this depth before forcing a tunnel teardown.
///
/// 64 covers typical residential network reorders (<10 datagrams) with
/// plenty of headroom; the cost is 64 BLAKE3 hashes per inbound datagram
/// in the worst-case (no early-match short-circuit), which is well below
/// the AEAD decode cost.
const HMAC_RECV_WINDOW: u64 = 64;

// ─────────────────────────────────────────────────────────────────────────────
// MirageCoreUdpTunnel
// ─────────────────────────────────────────────────────────────────────────────

/// Datagram-based AEAD tunnel using a per-peer ephemeral `UdpPeerSocket`.
///
/// Parallel to `MirageCoreTunnel` (stream-based) but operates on UDP datagrams.
/// Uses the same `FrameCodec` for AEAD encryption; each call to `send` / `recv`
/// transmits / receives exactly one UDP datagram.
///
/// Created after a successful Mirage handshake that ran over `UdpPeerSocket`
/// using raw `send` / `recv` on the socket.
pub struct MirageCoreUdpTunnel {
    socket: UdpPeerSocket,
    send_codec: FrameCodec,
    recv_codec: FrameCodec,
    /// Raw send key kept for per-frame HMAC computation (`AuthMode::Hmac`).
    send_key: [u8; 32],
    /// Raw recv key kept for per-frame HMAC verification (`AuthMode::Hmac`).
    recv_key: [u8; 32],
    /// Monotonic send-frame counter.
    send_counter: u64,
    /// Monotonic recv-frame counter (`AuthMode::None` / `Blake3` only — not
    /// used by `AuthMode::Hmac`, which uses the sliding window below).
    recv_counter: u64,
    /// Sliding HMAC receive window — only used when `auth == AuthMode::Hmac`.
    ///
    /// Tolerates UDP reorder / loss / duplicates within `HMAC_RECV_WINDOW`
    /// counters of the lowest unseen value. Without it any dropped datagram
    /// permanently desyncs the HMAC counter and the next inbound frame
    /// fails authentication (B-01 — observed as 2-3/12 HTTP curls failing
    /// under `udp_transparent` / `udp_crypto_verify`).
    recv_hmac_window: HmacRecvWindow,
    info: TransportInfo,
    auth: AuthMode,
}

/// Sliding-window HMAC counter tracker for the receive side of an
/// `AuthMode::Hmac` UDP tunnel.
///
/// Each inbound datagram carries a 4-byte HMAC prefix computed by the
/// sender as `BLAKE3(recv_key, sender_counter_le)[..4]`. Because the
/// counter is implicit (not on the wire), the receiver must guess the
/// sender's counter — sliding-window probe in `[base, base+W)` and
/// accept the first match.
///
/// On match: mark counter seen, advance `base` past the contiguous prefix
/// of seen counters. Duplicates (same counter twice) are rejected.
struct HmacRecvWindow {
    base: u64,
    seen: HashSet<u64>,
}

impl HmacRecvWindow {
    fn new() -> Self {
        Self { base: 0, seen: HashSet::new() }
    }

    /// Try every counter in `[base, base+W)`. On match: mark seen, advance
    /// `base` past contiguous seen counters, return the matched counter.
    /// On miss / duplicate: return None.
    fn try_match(&mut self, key: &[u8; 32], prefix: [u8; 4]) -> Option<u64> {
        let upper = self.base.saturating_add(HMAC_RECV_WINDOW);
        let mut c = self.base;
        while c < upper {
            if !self.seen.contains(&c) && frame_hmac_prefix(key, c) == prefix {
                self.seen.insert(c);
                // Slide base over any contiguous seen counters.
                while self.seen.contains(&self.base) {
                    self.seen.remove(&self.base);
                    self.base = self.base.wrapping_add(1);
                }
                return Some(c);
            }
            c = c.wrapping_add(1);
        }
        None
    }
}

impl MirageCoreUdpTunnel {
    /// Construct a new tunnel from an established `UdpPeerSocket` and session keys.
    ///
    /// `is_client` determines which key is used for sending vs receiving
    /// (mirrors `MirageCoreTunnel::new`).
    pub fn new(
        socket: UdpPeerSocket,
        keys: &SessionKeys,
        is_client: bool,
        info: TransportInfo,
        auth: AuthMode,
    ) -> Self {
        let (send_key, recv_key): ([u8; 32], [u8; 32]) = if is_client {
            (*keys.client_write_key, *keys.server_write_key)
        } else {
            (*keys.server_write_key, *keys.client_write_key)
        };
        let send_codec = FrameCodec::new(AeadCipher::with_suite(keys.suite, &send_key), CHUNK_SIZES.to_vec());
        let recv_codec = FrameCodec::new(AeadCipher::with_suite(keys.suite, &recv_key), CHUNK_SIZES.to_vec());
        Self {
            socket,
            send_codec,
            recv_codec,
            send_key,
            recv_key,
            send_counter: 0,
            recv_counter: 0,
            recv_hmac_window: HmacRecvWindow::new(),
            info,
            auth,
        }
    }

    /// Receive exactly one whole UDP datagram's decrypted, authenticated payload.
    ///
    /// UDP is message-oriented — one `recv` call always corresponds to one
    /// datagram — so returning an owned `Vec<u8>` instead of filling a
    /// caller-supplied buffer removes the "too small" outcome entirely rather
    /// than papering over it: there is nothing to truncate when nothing is
    /// copied into a fixed-size destination. This is the one place the
    /// per-datagram frame handling lives (HMAC sliding-window probe, dummy
    /// cover-frame skip, discard-and-continue on any malformed/unmatched
    /// datagram); [`Tunnel::recv`] below is implemented in terms of this
    /// method so that logic exists exactly once.
    ///
    /// Prefer this method over [`Tunnel::recv`] whenever the caller does not
    /// need to satisfy the `Tunnel` trait-object interface.
    ///
    /// A returned empty `Vec` is a legitimate, fully-authenticated zero-length
    /// datagram, not an end-of-stream signal — this tunnel type has no
    /// "closed" state to report (`close` is a no-op and UDP itself carries no
    /// end-of-stream marker), so `Ok(vec![])` here always means exactly what
    /// it says: the peer sent an empty message.
    pub async fn recv_datagram(&mut self) -> Result<Vec<u8>, MirageError> {
        loop {
            let mut dgram = [0u8; MAX_DGRAM];
            let n = self.socket.recv(&mut dgram).await?;
            let dgram = &dgram[..n];

            let wire = if self.auth == AuthMode::Hmac {
                if dgram.len() < 4 {
                    // Datagram too short to contain HMAC prefix — discard
                    // and keep waiting (do not advance counter / kill tunnel).
                    continue;
                }
                let prefix: [u8; 4] = dgram[..4].try_into().expect("slice is 4 bytes");
                // Sliding-window probe across [base, base+W). Tolerates UDP
                // reorder / loss / dupes — without this any dropped datagram
                // would desync the counter and brick the tunnel (B-01).
                if self
                    .recv_hmac_window
                    .try_match(&self.recv_key, prefix)
                    .is_none()
                {
                    // Either no counter in window matches (reuse / fabricated /
                    // drift past window) or counter already consumed (dup).
                    // Drop the datagram silently and keep listening.
                    continue;
                }
                &dgram[4..]
            } else {
                dgram
            };

            let frame = self.recv_codec.decode(wire)?;
            if self.auth != AuthMode::Hmac {
                // recv_counter is bookkeeping for non-HMAC paths; HMAC uses
                // its own sliding window above.
                self.recv_counter = self.recv_counter.wrapping_add(1);
            }

            // Silently skip cover-traffic dummy frames.
            if frame.cam_type == CamouflageType::Dummy {
                continue;
            }

            return Ok(frame.payload);
        }
    }

    /// Split this tunnel into an owned send half and an owned receive half.
    ///
    /// `send` and `recv_datagram` (and [`Tunnel::send`]/[`Tunnel::recv`])
    /// both take `&mut self` — a caller that needs to write from one task
    /// and read from another concurrently cannot do that on a single
    /// `MirageCoreUdpTunnel` without a lock around the whole thing. This
    /// avoids that lock entirely rather than adding one:
    ///
    /// - `socket` moves behind an `Arc` shared by both halves. That is safe
    ///   to call concurrently because [`UdpPeerSocket::send`]/[`UdpPeerSocket::recv`]
    ///   take `&self`, not `&mut self` (see that type's own doc) — the
    ///   underlying I/O was never the reason a lock would have been needed.
    /// - Every other field goes to whichever direction actually uses it:
    ///   the send codec, the raw send key and the send counter to
    ///   [`UdpTunnelSender`]; the recv codec, the raw recv key, the HMAC
    ///   replay window and the tunnel's [`TransportInfo`] to
    ///   [`UdpTunnelReceiver`]. The two directions share nothing else.
    /// - `auth` is read by both `send` and `recv_datagram` today, so both
    ///   halves keep their own copy (`AuthMode` is cheap to clone — see its
    ///   own derive).
    pub fn into_split(self) -> (UdpTunnelSender, UdpTunnelReceiver) {
        let socket = Arc::new(self.socket);
        let sender = UdpTunnelSender {
            socket: Arc::clone(&socket),
            send_codec: self.send_codec,
            send_key: self.send_key,
            send_counter: self.send_counter,
            auth: self.auth.clone(),
        };
        let receiver = UdpTunnelReceiver {
            socket,
            recv_codec: self.recv_codec,
            recv_key: self.recv_key,
            recv_counter: self.recv_counter,
            recv_hmac_window: self.recv_hmac_window,
            auth: self.auth,
            info: self.info,
        };
        (sender, receiver)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// UdpTunnelSender / UdpTunnelReceiver — owned halves from `into_split`
// ─────────────────────────────────────────────────────────────────────────────

/// Owned send half of a [`MirageCoreUdpTunnel`], produced by
/// [`MirageCoreUdpTunnel::into_split`].
///
/// Carries every piece of send-direction state — see `into_split`'s own doc
/// for exactly which field went where and why the shared socket needs no
/// lock.
pub struct UdpTunnelSender {
    socket: Arc<UdpPeerSocket>,
    send_codec: FrameCodec,
    send_key: [u8; 32],
    send_counter: u64,
    auth: AuthMode,
}

impl UdpTunnelSender {
    /// Send one whole UDP datagram. Identical wire behaviour to
    /// [`Tunnel::send`] on the un-split tunnel — same frame encoding, same
    /// HMAC-prefix construction when `auth == AuthMode::Hmac`, same counter
    /// advance.
    pub async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
        let frame = Frame {
            cam_type: CamouflageType::Raw,
            payload: data.to_vec(),
        };
        let wire = self.send_codec.encode(&frame)?;

        if self.auth == AuthMode::Hmac {
            // Prepend 4-byte HMAC prefix, then the encoded frame — send as one datagram.
            let prefix = frame_hmac_prefix(&self.send_key, self.send_counter);
            let mut dgram = Vec::with_capacity(4 + wire.len());
            dgram.extend_from_slice(&prefix);
            dgram.extend_from_slice(&wire);
            self.socket.send(&dgram).await?;
        } else {
            self.socket.send(&wire).await?;
        }
        self.send_counter = self.send_counter.wrapping_add(1);
        Ok(())
    }
}

/// Owned receive half of a [`MirageCoreUdpTunnel`], produced by
/// [`MirageCoreUdpTunnel::into_split`].
///
/// Carries every piece of receive-direction state, including the tunnel's
/// [`TransportInfo`] — assigned here rather than to [`UdpTunnelSender`]
/// since the two directions share nothing else (see `into_split`'s own
/// doc) and this is the half with an ongoing reason to report who the
/// tunnel talks to.
pub struct UdpTunnelReceiver {
    socket: Arc<UdpPeerSocket>,
    recv_codec: FrameCodec,
    recv_key: [u8; 32],
    recv_counter: u64,
    recv_hmac_window: HmacRecvWindow,
    auth: AuthMode,
    info: TransportInfo,
}

impl UdpTunnelReceiver {
    /// Receive one whole, decrypted, authenticated datagram. Identical
    /// framing, HMAC sliding-window replay handling, and dummy-frame skip
    /// to [`MirageCoreUdpTunnel::recv_datagram`] on the un-split tunnel —
    /// this is the same loop body, moved onto the split-out receive state.
    pub async fn recv_datagram(&mut self) -> Result<Vec<u8>, MirageError> {
        loop {
            let mut dgram = [0u8; MAX_DGRAM];
            let n = self.socket.recv(&mut dgram).await?;
            let dgram = &dgram[..n];

            let wire = if self.auth == AuthMode::Hmac {
                if dgram.len() < 4 {
                    // Datagram too short to contain HMAC prefix — discard
                    // and keep waiting (do not advance counter / kill tunnel).
                    continue;
                }
                let prefix: [u8; 4] = dgram[..4].try_into().expect("slice is 4 bytes");
                if self
                    .recv_hmac_window
                    .try_match(&self.recv_key, prefix)
                    .is_none()
                {
                    continue;
                }
                &dgram[4..]
            } else {
                dgram
            };

            let frame = self.recv_codec.decode(wire)?;
            if self.auth != AuthMode::Hmac {
                self.recv_counter = self.recv_counter.wrapping_add(1);
            }

            if frame.cam_type == CamouflageType::Dummy {
                continue;
            }

            return Ok(frame.payload);
        }
    }

    /// The tunnel's transport metadata (remote address, protocol ids,
    /// established-at instant) — see [`TransportInfo`].
    pub fn transport_info(&self) -> &TransportInfo {
        &self.info
    }
}

#[async_trait]
impl Tunnel for MirageCoreUdpTunnel {
    async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
        let frame = Frame {
            cam_type: CamouflageType::Raw,
            payload: data.to_vec(),
        };
        let wire = self.send_codec.encode(&frame)?;

        if self.auth == AuthMode::Hmac {
            // Prepend 4-byte HMAC prefix, then the encoded frame — send as one datagram.
            let prefix = frame_hmac_prefix(&self.send_key, self.send_counter);
            let mut dgram = Vec::with_capacity(4 + wire.len());
            dgram.extend_from_slice(&prefix);
            dgram.extend_from_slice(&wire);
            self.socket.send(&dgram).await?;
        } else {
            self.socket.send(&wire).await?;
        }
        self.send_counter = self.send_counter.wrapping_add(1);
        Ok(())
    }

    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, MirageError> {
        let payload = self.recv_datagram().await?;
        if payload.len() > buf.len() {
            // A short `Ok(n)` here would silently hand the caller a truncated,
            // already-decrypted payload indistinguishable from a datagram that
            // really was `n` bytes — refuse instead of corrupting it. Callers
            // that need the full payload regardless of buffer size should call
            // `recv_datagram` directly.
            return Err(MirageError::Protocol(format!(
                "udp datagram overflow: decrypted payload is {} bytes, caller buffer is only {} bytes — use MirageCoreUdpTunnel::recv_datagram for a truncation-proof read",
                payload.len(),
                buf.len()
            )));
        }
        buf[..payload.len()].copy_from_slice(&payload);
        Ok(payload.len())
    }

    async fn close(&mut self) -> Result<(), MirageError> {
        // UDP has no connection state to close.
        Ok(())
    }

    fn transport_info(&self) -> &TransportInfo {
        &self.info
    }
}
