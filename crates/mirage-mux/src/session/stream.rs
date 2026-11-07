use crate::session::rtt::Rtt;
use crate::frame::header::ACK;
use crate::MuxError;
use crate::{
    chunks::Chunks,
    session::{self, rtt, StreamCommand},
    frame::{
        header::{Data, Header, StreamId, WindowUpdate},
        Frame,
    },
    MuxConfig, DEFAULT_CREDIT,
};
use flow_control::FlowController;
use futures::{
    channel::mpsc,
    future::Either,
    io::{AsyncRead, AsyncWrite},
    ready, SinkExt,
};
use parking_lot::{Mutex, MutexGuard};
use std::{
    fmt, io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};

mod flow_control;

/// The state of a mux stream.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum State {
    /// Open bidirectionally.
    Open {
        /// Whether the stream is acknowledged.
        ///
        /// For outbound streams, this tracks whether the remote has acknowledged our stream.
        /// For inbound streams, this tracks whether we have acknowledged the stream to the remote.
        ///
        /// This starts out with `false` and is set to `true` when we receive or send an `ACK` flag for this stream.
        /// We may also directly transition:
        /// - from `Open` to `RecvClosed` if the remote immediately sends `FIN`.
        /// - from `Open` to `Closed` if the remote immediately sends `RST`.
        acknowledged: bool,
    },
    /// Open for incoming messages.
    SendClosed,
    /// Open for outgoing messages.
    RecvClosed,
    /// Closed (terminal state).
    Closed,
}

impl State {
    /// Can we receive messages over this stream?
    pub fn can_read(self) -> bool {
        !matches!(self, State::RecvClosed | State::Closed)
    }

    /// Can we send messages over this stream?
    pub fn can_write(self) -> bool {
        !matches!(self, State::SendClosed | State::Closed)
    }
}

/// Indicate if a flag still needs to be set on an outbound header.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Flag {
    /// No flag needs to be set.
    None,
    /// The stream was opened lazily, so set the initial SYN flag.
    Syn,
    /// The stream still needs acknowledgement, so set the ACK flag.
    Ack,
}

/// A multiplexed mux stream.
///
/// Streams are created either outbound via [`crate::MuxSession::poll_new_outbound`]
/// or inbound via [`crate::MuxSession::poll_next_inbound`].
///
/// `MuxStream` implements [`AsyncRead`] and [`AsyncWrite`] and also
/// [`futures::stream::Stream`].
pub struct MuxStream {
    id: StreamId,
    conn: session::Id,
    config: Arc<MuxConfig>,
    sender: mpsc::Sender<StreamCommand>,
    flag: Flag,
    shared: Arc<Mutex<Shared>>,
}

impl fmt::Debug for MuxStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MuxStream")
            .field("id", &self.id.val())
            .field("session", &self.conn)
            .finish()
    }
}

impl fmt::Display for MuxStream {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "(MuxStream {}/{})", self.conn, self.id.val())
    }
}

impl MuxStream {
    pub(crate) fn new_inbound(
        id: StreamId,
        conn: session::Id,
        config: Arc<MuxConfig>,
        send_window: u32,
        sender: mpsc::Sender<StreamCommand>,
        rtt: rtt::Rtt,
        accumulated_max_stream_windows: Arc<Mutex<usize>>,
    ) -> Self {
        Self {
            id,
            conn,
            config: config.clone(),
            sender,
            flag: Flag::Ack,
            shared: Arc::new(Mutex::new(Shared::new(
                DEFAULT_CREDIT,
                send_window,
                accumulated_max_stream_windows,
                rtt,
                config,
            ))),
        }
    }

    pub(crate) fn new_outbound(
        id: StreamId,
        conn: session::Id,
        config: Arc<MuxConfig>,
        sender: mpsc::Sender<StreamCommand>,
        rtt: rtt::Rtt,
        accumulated_max_stream_windows: Arc<Mutex<usize>>,
    ) -> Self {
        Self {
            id,
            conn,
            config: config.clone(),
            sender,
            flag: Flag::Syn,
            shared: Arc::new(Mutex::new(Shared::new(
                DEFAULT_CREDIT,
                DEFAULT_CREDIT,
                accumulated_max_stream_windows,
                rtt,
                config,
            ))),
        }
    }

    /// Get this stream's identifier.
    pub fn id(&self) -> StreamId {
        self.id
    }

    pub fn is_write_closed(&self) -> bool {
        matches!(self.shared().state(), State::SendClosed)
    }

    pub fn is_closed(&self) -> bool {
        matches!(self.shared().state(), State::Closed)
    }

    /// Whether we are still waiting for the remote to acknowledge this stream.
    pub fn is_pending_ack(&self) -> bool {
        self.shared().is_pending_ack()
    }

    /// Drop the pending ACK flag.
    ///
    /// The session acknowledges an accepted stream itself, so the stream
    /// must not piggyback a second ACK on its first frame.
    pub(crate) fn clear_ack_flag(&mut self) {
        self.flag = Flag::None;
    }

    pub(crate) fn shared(&self) -> MutexGuard<'_, Shared> {
        self.shared.lock()
    }

    pub(crate) fn clone_shared(&self) -> Arc<Mutex<Shared>> {
        self.shared.clone()
    }

    fn write_zero_err(&self) -> io::Error {
        let msg = format!("{}/{}: session is closed", self.conn, self.id);
        io::Error::new(io::ErrorKind::WriteZero, msg)
    }

    /// Set ACK or SYN flag if necessary.
    fn add_flag(&mut self, header: &mut Header<Either<Data, WindowUpdate>>) {
        match self.flag {
            Flag::None => (),
            Flag::Syn => {
                header.syn();
                self.flag = Flag::None
            }
            Flag::Ack => {
                header.ack();
                self.flag = Flag::None
            }
        }
    }

    /// Send new credit to the sending side via a window update message if
    /// permitted.
    fn send_window_update(&mut self, cx: &mut Context) -> Poll<io::Result<()>> {
        if !self.shared.lock().state.can_read() {
            return Poll::Ready(Ok(()));
        }

        ready!(self
            .sender
            .poll_ready(cx)
            .map_err(|_| self.write_zero_err())?);

        let Some(credit) = self.shared.lock().next_window_update() else {
            return Poll::Ready(Ok(()));
        };

        let mut frame = Frame::window_update(self.id, credit).right();
        self.add_flag(frame.header_mut());
        let cmd = StreamCommand::SendFrame(frame);
        self.sender
            .start_send(cmd)
            .map_err(|_| self.write_zero_err())?;

        Poll::Ready(Ok(()))
    }
}

/// Byte data produced by the [`futures::stream::Stream`] impl of [`MuxStream`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Packet(Vec<u8>);

impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

impl futures::stream::Stream for MuxStream {
    type Item = io::Result<Packet>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
        if !self.config.read_after_close && self.sender.is_closed() {
            return Poll::Ready(None);
        }

        match self.send_window_update(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Some(Err(e))),
            // Continue reading buffered data even though sending a window update blocked.
            Poll::Pending => {}
        }

        let mut shared = self.shared();

        if let Some(bytes) = shared.buffer.pop() {
            let off = bytes.offset();
            let mut vec = bytes.into_vec();
            if off != 0 {
                // This should generally not happen when the stream is used only as
                // a `futures::stream::Stream` since the whole point of this impl is
                // to consume chunks atomically. It may perhaps happen when mixing
                // this impl and the `AsyncRead` one.
                tracing::debug!(
                    "{}/{}: chunk has been partially consumed",
                    self.conn,
                    self.id
                );
                vec = vec.split_off(off)
            }
            return Poll::Ready(Some(Ok(Packet(vec))));
        }

        // Buffer is empty, let's check if we can expect to read more data.
        if !shared.state().can_read() {
            tracing::debug!("{}/{}: eof", self.conn, self.id);
            return Poll::Ready(None); // stream has been reset
        }

        // Since we have no more data at this point, we want to be woken up
        // by the session when more becomes available for us.
        shared.reader = Some(cx.waker().clone());

        Poll::Pending
    }
}

// Like the `futures::stream::Stream` impl above, but copies bytes into the
// provided mutable slice.
impl AsyncRead for MuxStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        if !self.config.read_after_close && self.sender.is_closed() {
            return Poll::Ready(Ok(0));
        }

        match self.send_window_update(cx) {
            Poll::Ready(Ok(())) => {}
            Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
            // Continue reading buffered data even though sending a window update blocked.
            Poll::Pending => {}
        }

        // Copy data from stream buffer.
        let mut shared = self.shared();
        let mut n = 0;
        while let Some(chunk) = shared.buffer.front_mut() {
            if chunk.is_empty() {
                shared.buffer.pop();
                continue;
            }
            let k = std::cmp::min(chunk.len(), buf.len() - n);
            buf[n..n + k].copy_from_slice(&chunk.as_ref()[..k]);
            n += k;
            chunk.advance(k);
            if n == buf.len() {
                break;
            }
        }

        if n > 0 {
            tracing::trace!("{}/{}: read {} bytes", self.conn, self.id, n);
            return Poll::Ready(Ok(n));
        }

        // Buffer is empty, let's check if we can expect to read more data.
        if !shared.state().can_read() {
            tracing::debug!("{}/{}: eof", self.conn, self.id);
            return Poll::Ready(Ok(0)); // stream has been reset
        }

        // Since we have no more data at this point, we want to be woken up
        // by the session when more becomes available for us.
        shared.reader = Some(cx.waker().clone());

        Poll::Pending
    }
}

impl AsyncWrite for MuxStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self
            .sender
            .poll_ready(cx)
            .map_err(|_| self.write_zero_err())?);
        let body = {
            let mut shared = self.shared();
            if !shared.state().can_write() {
                tracing::debug!("{}/{}: can no longer write", self.conn, self.id);
                return Poll::Ready(Err(self.write_zero_err()));
            }
            if shared.send_window() == 0 {
                tracing::trace!("{}/{}: no more credit left", self.conn, self.id);
                shared.writer = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let k = std::cmp::min(shared.send_window() as usize, buf.len());
            let k = std::cmp::min(k, self.config.split_send_size);
            shared
                .consume_send_window(k as u32)
                .expect("not exceed receive window");
            Vec::from(&buf[..k])
        };
        let n = body.len();
        let mut frame = Frame::data(self.id, body).expect("body <= u32::MAX").left();
        self.add_flag(frame.header_mut());
        tracing::trace!("{}/{}: write {} bytes", self.conn, self.id, n);

        // technically, the frame hasn't been sent yet on the wire but from the perspective of this data structure, we've queued the frame for sending
        // We are tracking this information:
        // a) to be consistent with outbound streams
        // b) to correctly test our behaviour around timing of when ACKs are sent. See `ack_timing.rs` test.
        if frame.header().flags().contains(ACK) {
            self.shared()
                .update_state(self.conn, self.id, State::Open { acknowledged: true });
        }

        let cmd = StreamCommand::SendFrame(frame);
        self.sender
            .start_send(cmd)
            .map_err(|_| self.write_zero_err())?;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        self.sender
            .poll_flush_unpin(cx)
            .map_err(|_| self.write_zero_err())
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        if self.is_closed() {
            return Poll::Ready(Ok(()));
        }
        ready!(self
            .sender
            .poll_ready(cx)
            .map_err(|_| self.write_zero_err())?);
        let ack = if self.flag == Flag::Ack {
            self.flag = Flag::None;
            true
        } else {
            false
        };
        tracing::trace!("{}/{}: close", self.conn, self.id);
        // The state moves FIRST. The session hands this stream's credit back
        // as soon as it processes the close command, and it can only do that
        // if the state is already terminal. Sending the command first would
        // let the session look at a half-closed stream, skip the credit, and
        // keep the credit out of the pool until the local handle is dropped
        // -- which, on a busy machine, is how a session runs out of credit
        // while every stream is long gone.
        self.shared()
            .update_state(self.conn, self.id, State::SendClosed);
        let cmd = StreamCommand::CloseStream { ack };
        self.sender
            .start_send(cmd)
            .map_err(|_| self.write_zero_err())?;
        Poll::Ready(Ok(()))
    }
}

#[derive(Debug)]
pub(crate) struct Shared {
    state: State,
    flow_controller: FlowController,
    pub(crate) buffer: Chunks,
    pub(crate) reader: Option<Waker>,
    pub(crate) writer: Option<Waker>,
    /// When the stream was created. Used by the diagnostics that report why
    /// the session ran out of stream credit.
    opened_at: Instant,
    /// Whether the session already gave this stream's credit back.
    ///
    /// The credit is returned exactly once per stream, whichever retirement
    /// path fires first: the stream reaching its terminal state, or the
    /// local handle being dropped.
    credit_returned: bool,
}

impl Shared {
    fn new(
        receive_window: u32,
        send_window: u32,
        accumulated_max_stream_windows: Arc<Mutex<usize>>,
        rtt: Rtt,
        config: Arc<MuxConfig>,
    ) -> Self {
        Shared {
            state: State::Open {
                acknowledged: false,
            },
            flow_controller: FlowController::new(
                receive_window,
                send_window,
                accumulated_max_stream_windows,
                rtt,
                config,
            ),
            buffer: Chunks::new(),
            reader: None,
            writer: None,
            opened_at: Instant::now(),
            credit_returned: false,
        }
    }

    /// How long ago the stream was created.
    pub(crate) fn age(&self) -> Duration {
        self.opened_at.elapsed()
    }

    /// Give this stream's credit back, at most once.
    ///
    /// Returns `true` when this call is the one that returned the credit.
    pub(crate) fn return_credit(&mut self) -> bool {
        if self.credit_returned {
            return false;
        }
        self.credit_returned = true;
        true
    }

    pub(crate) fn state(&self) -> State {
        self.state
    }

    /// Update the stream state and return the state before it was updated.
    pub(crate) fn update_state(
        &mut self,
        cid: session::Id,
        sid: StreamId,
        next: State,
    ) -> State {
        use self::State::*;

        let current = self.state;

        match (current, next) {
            (Closed, _) => {}
            (Open { .. }, _) => self.state = next,
            (RecvClosed, Closed) => self.state = Closed,
            (RecvClosed, Open { .. }) => {}
            (RecvClosed, RecvClosed) => {}
            (RecvClosed, SendClosed) => self.state = Closed,
            (SendClosed, Closed) => self.state = Closed,
            (SendClosed, Open { .. }) => {}
            (SendClosed, RecvClosed) => self.state = Closed,
            (SendClosed, SendClosed) => {}
        }

        tracing::trace!(
            "{}/{}: update state: (from {:?} to {:?} -> {:?})",
            cid,
            sid,
            current,
            next,
            self.state
        );

        current // Return the previous stream state for informational purposes.
    }

    pub(crate) fn next_window_update(&mut self) -> Option<u32> {
        self.flow_controller.next_window_update(self.buffer.len())
    }

    /// Whether we are still waiting for the remote to acknowledge this stream.
    pub fn is_pending_ack(&self) -> bool {
        matches!(
            self.state(),
            State::Open {
                acknowledged: false
            }
        )
    }

    pub(crate) fn send_window(&self) -> u32 {
        self.flow_controller.send_window()
    }

    pub(crate) fn consume_send_window(&mut self, i: u32) -> Result<(), MuxError> {
        self.flow_controller.consume_send_window(i)
    }

    pub(crate) fn increase_send_window_by(&mut self, i: u32) -> Result<(), MuxError> {
        self.flow_controller.increase_send_window_by(i)
    }

    pub(crate) fn consume_receive_window(&mut self, i: u32) -> Result<(), MuxError> {
        self.flow_controller.consume_receive_window(i)
    }
}
