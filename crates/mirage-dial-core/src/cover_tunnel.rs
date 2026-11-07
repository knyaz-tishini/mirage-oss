//! [`CoverTunnel`] — a [`Tunnel`] wrapper that injects dummy frames during idle
//! periods to defeat traffic-analysis based on silence detection.
//!
//! # How it works
//!
//! Every call to [`CoverTunnel::recv`] uses `tokio::select!` to race the inner
//! `recv` against a jitter-based sleep timer.  When the sleep fires before real
//! data arrives *and* the tunnel has been idle longer than `idle_threshold_ms`,
//! a random-byte payload is sent through the inner tunnel before the loop
//! restarts.  When real data arrives the activity timestamp is refreshed and the
//! data is returned normally.
//!
//! The same activity timestamp is updated on every [`CoverTunnel::send`] call so
//! outbound real traffic also resets the idle clock.  Dummy sends intentionally
//! do **not** reset the clock — only real application traffic ends the idle period.
//!
//! # Wire behaviour
//!
//! Dummy payloads are forwarded through the inner tunnel's normal `send` path
//! (full AEAD framing with the configured camouflage type).  They are
//! indistinguishable from real traffic to an outside observer.  On the receiving
//! side the payloads surface as ordinary application data; higher protocol layers
//! are responsible for discarding any zero-length or sentinel payloads if needed.

use std::time::{Duration, Instant};

use mirage_core::{config::CoverTrafficConfig, error::MirageError};
use mirage_protocol::traits::{TransportInfo, Tunnel};
use rand::Rng;

/// A [`Tunnel`] wrapper that injects random dummy frames during idle periods.
///
/// Construct with [`CoverTunnel::new`]; the result is a drop-in [`Tunnel`]
/// replacement.  When `config.enabled` is `false` the wrapper is a zero-cost
/// pass-through with no timer overhead.
///
/// During an active relay (bidirectional data transfer), call
/// [`CoverTunnel::set_relay_active`] with `true` to suppress cover injection.
/// Injecting random bytes into an active relay stream confuses the exit node,
/// which cannot distinguish cover frames from real application data.
pub struct CoverTunnel {
    inner: Box<dyn Tunnel>,
    config: CoverTrafficConfig,
    /// Timestamp of the last real send or recv (dummy sends excluded).
    last_activity: Instant,
    /// When `true`, cover injection is suppressed to avoid polluting an active
    /// relay stream with bytes the exit node cannot discard.
    relay_active: bool,
}

impl CoverTunnel {
    /// Wrap `tunnel` with cover-traffic injection governed by `config`.
    pub fn new(tunnel: Box<dyn Tunnel>, config: CoverTrafficConfig) -> Self {
        Self {
            inner: tunnel,
            config,
            last_activity: Instant::now(),
            relay_active: false,
        }
    }



    /// Generate a random payload of between `min_size` and `max_size` bytes.
    fn random_dummy_payload(&self) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let size = rng.gen_range(self.config.min_size..=self.config.max_size);
        let mut buf = vec![0u8; size];
        rng.fill(buf.as_mut_slice());
        buf
    }

    /// Pick a random sleep duration within the configured interval range.
    fn random_interval(&self) -> Duration {
        let mut rng = rand::thread_rng();
        let ms = rng.gen_range(self.config.min_interval_ms..=self.config.max_interval_ms);
        Duration::from_millis(ms)
    }

    /// Milliseconds elapsed since the last real activity.
    fn idle_ms(&self) -> u64 {
        self.last_activity.elapsed().as_millis() as u64
    }
}

#[async_trait::async_trait]
impl Tunnel for CoverTunnel {
    /// Forward `data` through the inner tunnel and reset the idle timer.
    async fn send(&mut self, data: &[u8]) -> Result<(), MirageError> {
        self.last_activity = Instant::now();
        self.inner.send(data).await
    }

    /// Receive from the inner tunnel, injecting cover frames during idle periods.
    ///
    /// Uses `tokio::select!` to race the inner `recv` against a jitter-based
    /// sleep.  When the sleep fires and the tunnel has been idle beyond
    /// `idle_threshold_ms`, a random payload is sent before the loop restarts.
    async fn recv(&mut self, buf: &mut [u8]) -> Result<usize, MirageError> {
        if !self.config.enabled {
            let n = self.inner.recv(buf).await?;
            if n > 0 {
                self.last_activity = Instant::now();
            }
            return Ok(n);
        }

        loop {
            let interval = self.random_interval();

            tokio::select! {
                // Real data arrived from the peer.
                result = self.inner.recv(buf) => {
                    match result {
                        Ok(n) => {
                            if n > 0 {
                                self.last_activity = Instant::now();
                            }
                            return Ok(n);
                        }
                        Err(e) => return Err(e),
                    }
                }

                // Cover-traffic timer fired — send a dummy frame if idle.
                _ = tokio::time::sleep(interval) => {
                    // Do not inject during an active relay: the exit node has no
                    // way to distinguish cover bytes from real application data.
                    if !self.relay_active && self.idle_ms() >= self.config.idle_threshold_ms {
                        let dummy = self.random_dummy_payload();
                        tracing::trace!(
                            size = dummy.len(),
                            idle_ms = self.idle_ms(),
                            "cover: injecting dummy frame"
                        );
                        self.inner.send(&dummy).await?;
                        // Dummy sends do not reset last_activity intentionally.
                    }
                    // Loop back to wait for the next real frame.
                }
            }
        }
    }

    async fn close(&mut self) -> Result<(), MirageError> {
        self.inner.close().await
    }

    fn transport_info(&self) -> &TransportInfo {
        self.inner.transport_info()
    }

    /// Suppress cover injection while a relay is active.
    fn set_relay_active(&mut self, active: bool) {
        self.relay_active = active;
    }
}
