//! [`ShapedTunnel`] — a [`Tunnel`] wrapper that applies traffic shaping.
//!
//! Wraps any `Box<dyn Tunnel>` and intercepts `send` to add jitter
//! on outbound frames.  Size-based obfuscation is handled by the frame codec
//! (chunk buckets with `payload_len` header) — application-level padding is
//! redundant and corrupts the exit node's protocol parsing.
//! Inbound (`recv`) is passed through as-is.

use mirage_core::error::MirageError;
use mirage_protocol::frame_obfuscation::shaping::{TrafficPattern, TrafficShaper};
use mirage_protocol::traits::{TransportInfo, Tunnel};
use tokio::time::sleep;

/// A tunnel wrapper that applies a [`TrafficShaper`] to all outbound data.
///
/// `send` applies jitter before forwarding to the inner tunnel.  Size-based
/// obfuscation is handled by the frame codec.  `recv` is a transparent
/// pass-through.
pub struct ShapedTunnel {
    inner: Box<dyn Tunnel>,
    shaper: TrafficShaper,
    /// First send is always the routing header (target address) — skip jitter
    /// so TUN-mode connections don't timeout waiting for relay_loop to start.
    first_send: bool,
}

impl ShapedTunnel {
    /// Wrap `tunnel` with the given traffic pattern.
    pub fn new(tunnel: Box<dyn Tunnel>, pattern: TrafficPattern) -> Self {
        Self {
            inner: tunnel,
            shaper: TrafficShaper::new(pattern),
            first_send: true,
        }
    }
}

#[async_trait::async_trait]
impl Tunnel for ShapedTunnel {
    /// Optionally wait for the jitter delay, then forward `data` as-is.
    async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
        if self.first_send {
            self.first_send = false;
        } else {
            let delay = self.shaper.jitter_delay();
            if !delay.is_zero() {
                sleep(delay).await;
            }
        }
        self.inner.send(data).await
    }

    /// Read one frame from the inner tunnel and copy into `buf`.
    ///
    /// Shaping (padding + jitter) is applied **outbound only** (in `send`).
    /// The return path carries unpadded application data — the exit node writes
    /// raw TCP bytes back without adding any padding trailer, so calling
    /// `unpad()` here would read the 4-byte length from garbage position.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, MirageError> {
        let n = self.inner.recv(buf).await?;
        Ok(n)
    }

    async fn close(&mut self) -> Result<(), MirageError> {
        self.inner.close().await
    }

    fn transport_info(&self) -> &TransportInfo {
        self.inner.transport_info()
    }
}
