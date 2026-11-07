//! Tokio-compatible wrappers around the poll-based `MuxSession`.
//!
//! Also provides [`TokioIoCompat`] — a bridge that wraps any
//! `tokio::io::AsyncRead + AsyncWrite` and exposes `futures::io::AsyncRead + AsyncWrite`,
//! allowing tokio I/O types to be used as `MuxSession` transports.
//!
//! `SessionHandle` provides async `open_stream` / `accept_stream` / `is_closed` / `close` by
//! spawning a background driver task that pumps the connection.
//!
//! `TokioMuxStream` wraps `MuxStream` (which implements `futures::io::AsyncRead/Write`)
//! and bridges it to `tokio::io::AsyncRead/Write`.

use crate::{MuxConfig, MuxError, MuxSession, MuxStream, Mode, Result};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{mpsc, Mutex, Notify};

/// How long an open waits for stream credit before it gives up.
///
/// The mux hands credit back when a stream completes. Waiting for it is the
/// same backpressure HTTP/2 applies once `SETTINGS_MAX_CONCURRENT_STREAMS`
/// is reached, and QUIC applies through `MAX_STREAMS`. The bound keeps a
/// caller from waiting forever on a session whose peer never completes a
/// stream.
///
/// This is the default; `MuxConfig::set_stream_credit_wait` overrides it per
/// session.
pub const STREAM_CREDIT_WAIT: Duration = crate::DEFAULT_STREAM_CREDIT_WAIT;

// ── TokioIoCompat ─────────────────────────────────────────────────────────────

/// Bridges any `tokio::io::AsyncRead + AsyncWrite` type into
/// `futures::io::AsyncRead + AsyncWrite`, so it can be used as a `MuxSession` transport.
pub struct TokioIoCompat<T>(pub T);

impl<T: tokio::io::AsyncRead + Unpin> futures::io::AsyncRead for TokioIoCompat<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut read_buf = tokio::io::ReadBuf::new(buf);
        match Pin::new(&mut self.0).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: tokio::io::AsyncWrite + Unpin> futures::io::AsyncWrite for TokioIoCompat<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_close(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

// ── TokioMuxStream ────────────────────────────────────────────────────────────

/// Wraps [`MuxStream`] and implements [`tokio::io::AsyncRead`] / [`tokio::io::AsyncWrite`].
pub struct TokioMuxStream(pub MuxStream);

impl tokio::io::AsyncRead for TokioMuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let unfilled = buf.initialize_unfilled();
        match futures::io::AsyncRead::poll_read(Pin::new(&mut self.0), cx, unfilled) {
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(())),
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl tokio::io::AsyncWrite for TokioMuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        futures::io::AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        futures::io::AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        futures::io::AsyncWrite::poll_close(Pin::new(&mut self.0), cx)
    }
}

// ── SessionHandle ─────────────────────────────────────────────────────────────

/// Tokio-friendly async wrapper around [`MuxSession`].
///
/// Spawns a background driver task that pumps the poll-based connection.
/// Provides async `open_stream`, `accept_stream`, `close`, and `is_closed`.
pub struct SessionHandle {
    outbound_tx: mpsc::Sender<tokio::sync::oneshot::Sender<Result<MuxStream>>>,
    inbound_rx: Mutex<mpsc::Receiver<MuxStream>>,
    /// Notified when the driver task finishes (session fully closed).
    closed_notify: Arc<Notify>,
    /// Set to true after the driver task finishes.
    closed_flag: Arc<std::sync::atomic::AtomicBool>,
    /// Sending on this channel signals the driver to perform a graceful close.
    close_tx: tokio::sync::oneshot::Sender<()>,
    /// How long an open waits for stream credit before it gives up.
    credit_wait: Duration,
}

impl SessionHandle {
    /// Create a client-mode session over `transport`.
    pub fn client<T>(transport: T) -> Self
    where
        T: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    {
        Self::new(transport, Mode::Client, MuxConfig::default())
    }

    /// Create a server-mode session over `transport`.
    pub fn server<T>(transport: T) -> Self
    where
        T: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    {
        Self::new(transport, Mode::Server, MuxConfig::default())
    }

    /// Create a client-mode session over `transport` with a caller-supplied
    /// [`MuxConfig`] (e.g. a lowered `max_num_streams` for testing the
    /// stream-count cap without opening hundreds of streams).
    pub fn client_with_config<T>(transport: T, config: MuxConfig) -> Self
    where
        T: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    {
        Self::new(transport, Mode::Client, config)
    }

    /// Create a server-mode session over `transport` with a caller-supplied
    /// [`MuxConfig`]. See [`SessionHandle::client_with_config`].
    pub fn server_with_config<T>(transport: T, config: MuxConfig) -> Self
    where
        T: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    {
        Self::new(transport, Mode::Server, config)
    }

    fn new<T>(transport: T, mode: Mode, config: MuxConfig) -> Self
    where
        T: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
    {
        let (outbound_tx, outbound_rx) = mpsc::channel(256);
        let (inbound_tx, inbound_rx) = mpsc::channel(256);
        let closed_notify = Arc::new(Notify::new());
        let closed_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let closed_notify_clone = closed_notify.clone();
        let closed_flag_clone = closed_flag.clone();
        let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
        let credit_wait = config.stream_credit_wait;

        tokio::spawn(async move {
            driver_loop(transport, mode, config, outbound_rx, inbound_tx, close_rx).await;
            closed_flag_clone.store(true, std::sync::atomic::Ordering::Release);
            closed_notify_clone.notify_waiters();
        });

        Self {
            outbound_tx,
            inbound_rx: Mutex::new(inbound_rx),
            closed_notify,
            closed_flag,
            close_tx,
            credit_wait,
        }
    }

    /// Open a new outbound stream.
    ///
    /// **The stream is opened LAZILY: nothing is sent to the peer here.** This
    /// call allocates a stream id and local state and returns; the peer learns
    /// the stream exists when its FIRST FRAME arrives, which is the first
    /// write (or close). Until then the remote's `accept_stream` has nothing
    /// to hand out and will wait.
    ///
    /// So a caller that opens a stream and then waits for the peer to speak
    /// first waits forever, and it is the caller's protocol that is wrong, not
    /// the mux. Every production user writes immediately — SOCKS5, HTTP
    /// CONNECT and the Mirage exit protocol all have the client speak first —
    /// which is why this held without ever being written down. Three session
    /// tests did wait, and spent months marked as a driver deadlock.
    ///
    /// Two consequences worth stating outright, because both have already
    /// been assumed away somewhere in this codebase:
    ///
    /// - A successful `open_stream` is **not** evidence that the session's
    ///   transport works. It proves only that the driver task has not already
    ///   torn the session down. A liveness probe must send something and see
    ///   an answer.
    /// - Stream ids are consumed on open, not on first use, so opening
    ///   streams speculatively burns them against `max_outbound_streams`.
    ///
    /// When the session has no stream credit left, this call waits for it
    /// instead of failing: the credit comes back when a stream completes.
    /// The wait is bounded by [`STREAM_CREDIT_WAIT`] so a session whose peer
    /// never completes a stream cannot hang the caller forever.
    pub async fn open_stream(&self) -> Result<MuxStream> {
        if self.closed_flag.load(std::sync::atomic::Ordering::Acquire) {
            return Err(MuxError::Closed);
        }
        let (tx, rx) = tokio::sync::oneshot::channel();
        self.outbound_tx
            .send(tx)
            .await
            .map_err(|_| MuxError::Closed)?;
        match tokio::time::timeout(self.credit_wait, rx).await {
            Ok(result) => result.map_err(|_| MuxError::Closed)?,
            Err(_) => {
                // No credit within the bound. The session itself stays
                // usable: this one request is what fails.
                tracing::warn!(
                    "mirage-mux: no stream credit within {:?}, refusing this open",
                    self.credit_wait
                );
                Err(MuxError::TooManyStreams)
            }
        }
    }

    /// Accept the next inbound stream.
    pub async fn accept_stream(&self) -> Result<MuxStream> {
        let mut rx = self.inbound_rx.lock().await;
        rx.recv().await.ok_or(MuxError::Closed)
    }

    /// Gracefully close the session (sends GoAway to remote).
    ///
    /// After this returns, `is_closed()` will be `true`.
    pub async fn close(self) -> Result<()> {
        // Signal the driver to begin graceful close.
        let _ = self.close_tx.send(());
        // Wait for the driver to finish — no spinning, notified when done.
        // Re-subscribe before checking the flag to avoid a TOCTOU race.
        let notified = self.closed_notify.notified();
        if !self.closed_flag.load(std::sync::atomic::Ordering::Acquire) {
            notified.await;
        }
        Ok(())
    }

    /// Returns `true` if the underlying session has closed.
    pub fn is_closed(&self) -> bool {
        self.closed_flag.load(std::sync::atomic::Ordering::Acquire)
    }
}

// ── Driver loop ───────────────────────────────────────────────────────────────

async fn driver_loop<T>(
    transport: T,
    mode: Mode,
    config: MuxConfig,
    mut outbound_rx: mpsc::Receiver<tokio::sync::oneshot::Sender<Result<MuxStream>>>,
    inbound_tx: mpsc::Sender<MuxStream>,
    mut close_rx: tokio::sync::oneshot::Receiver<()>,
) where
    T: futures::AsyncRead + futures::AsyncWrite + Send + Unpin + 'static,
{
    let mut session = MuxSession::new(transport, config, mode);
    // When non-None, we have a caller waiting for a new outbound stream.
    let mut pending_outbound: Option<tokio::sync::oneshot::Sender<Result<MuxStream>>> = None;
    // When non-None, an inbound stream is waiting for channel capacity before delivery.
    // Holding this prevents reading more frames until the consumer catches up (backpressure).
    let mut pending_inbound: Option<MuxStream> = None;
    // Whether a graceful close has been requested.
    let mut closing = false;

    futures::future::poll_fn(move |cx: &mut Context<'_>| -> Poll<()> {
        // Check for close signal (non-blocking).
        if !closing {
            if let Poll::Ready(_) = futures::Future::poll(Pin::new(&mut close_rx), cx) {
                closing = true;
            }
        }

        // If close was requested (either just now or on a previous poll), keep driving
        // poll_close until it finishes.  We must re-enter this on every poll so that
        // the session makes forward progress after returning Poll::Pending.
        if closing {
            return match session.poll_close(cx) {
                Poll::Ready(_) => Poll::Ready(()),
                Poll::Pending => Poll::Pending,
            };
        }

        loop {
            // ── Flush any previously buffered inbound stream first ──────────
            // This applies backpressure: we don't read new frames until the
            // consumer has space for the one we already accepted.
            if let Some(stream) = pending_inbound.take() {
                match inbound_tx.try_reserve() {
                    Ok(permit) => {
                        permit.send(stream);
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                        // Channel still full — hold the stream and wait.
                        // The consumer will poll again when it drains an entry,
                        // which wakes the channel's internal waker.  We register
                        // our own waker via wake_by_ref so we are re-polled.
                        tracing::warn!(
                            "mirage-mux driver: inbound channel full, applying backpressure"
                        );
                        pending_inbound = Some(stream);
                        cx.waker().wake_by_ref();
                        return Poll::Pending;
                    }
                    Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                        // Receiver dropped — session no longer needed.
                        return Poll::Ready(());
                    }
                }
            }

            // ── Accept queued outbound request ──────────────────────────────
            if pending_outbound.is_none() {
                // poll_recv registers waker so we'll be woken when a request arrives.
                if let Poll::Ready(Some(reply)) = outbound_rx.poll_recv(cx) {
                    pending_outbound = Some(reply);
                }
            }

            // ── Fulfill pending outbound ────────────────────────────────────
            if let Some(reply) = pending_outbound.take() {
                if reply.is_closed() {
                    // The caller gave up while we were waiting for credit.
                    // Drop the request instead of holding the queue behind
                    // it.
                    tracing::debug!("mirage-mux driver: outbound request was abandoned");
                } else {
                    match session.poll_new_outbound(cx) {
                        Poll::Ready(result) => {
                            // The receiver may be gone -- that is fine. The
                            // stream is dropped together with the failed
                            // send, which hands its credit back.
                            let _ = reply.send(result);
                            // Continue to drive inbound.
                        }
                        Poll::Pending => {
                            // Put it back; we'll retry once a stream
                            // completes and the credit comes back.
                            pending_outbound = Some(reply);
                        }
                    }
                }
            }

            // ── Drive inbound (processes ALL connection frames) ─────────────
            match session.poll_next_inbound(cx) {
                Poll::Ready(Some(Ok(stream))) => {
                    // Attempt to deliver to the inbound channel.  If full, store
                    // in pending_inbound and stop reading frames (backpressure).
                    match inbound_tx.try_reserve() {
                        Ok(permit) => {
                            permit.send(stream);
                            // Wake ourselves to keep draining.
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                            tracing::warn!(
                                "mirage-mux driver: inbound channel full, applying backpressure"
                            );
                            pending_inbound = Some(stream);
                            cx.waker().wake_by_ref();
                            return Poll::Pending;
                        }
                        Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                            return Poll::Ready(());
                        }
                    }
                }
                Poll::Ready(Some(Err(e))) => {
                    tracing::warn!("mirage-mux driver: session error: {e}");
                    // Fail any pending outbound request.
                    if let Some(reply) = pending_outbound.take() {
                        let _ = reply.send(Err(MuxError::Closed));
                    }
                    return Poll::Ready(());
                }
                Poll::Ready(None) => {
                    tracing::warn!("mirage-mux driver: session closed (EOF)");
                    if let Some(reply) = pending_outbound.take() {
                        let _ = reply.send(Err(MuxError::Closed));
                    }
                    return Poll::Ready(());
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    })
    .await;
}
