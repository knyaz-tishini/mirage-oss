//! This module contains the `MuxSession` type and associated helpers.
//! A `MuxSession` wraps an underlying (async) I/O resource and multiplexes
//! `MuxStream`s over it.

mod cleanup;
mod closing;
mod rtt;
mod stream;

use crate::tagged_stream::TaggedStream;
use crate::{
    error::MuxError,
    frame::header::{self, Data, GoAway, Header, Ping, StreamId, Tag, WindowUpdate, CONNECTION_ID},
    frame::{self, Frame},
    MuxConfig, DEFAULT_CREDIT,
};
use crate::{Result, MAX_ACK_BACKLOG};
use cleanup::Cleanup;
use closing::Closing;
use futures::stream::SelectAll;
use futures::{channel::mpsc, future::Either, prelude::*, sink::SinkExt, stream::Fuse};
use nohash_hasher::IntMap;
use parking_lot::Mutex;
use std::collections::VecDeque;
use std::task::{Context, Waker};
use std::time::{Duration, Instant};
use std::{fmt, sync::Arc, task::Poll};

pub use stream::{Packet, State, MuxStream};

/// How often the credit exhaustion is reported while the session stays
/// saturated.
const CREDIT_WARNING_INTERVAL: Duration = Duration::from_secs(30);

/// How the session is used.
#[derive(Copy, Clone, Debug, Hash, PartialEq, Eq)]
pub enum Mode {
    /// Client to server session.
    Client,
    /// Server to client session.
    Server,
}

/// The session identifier.
///
/// Randomly generated, this is mainly intended to improve log output.
#[derive(Clone, Copy)]
pub(crate) struct Id(u32);

impl Id {
    /// Create a random session ID.
    pub(crate) fn random() -> Self {
        Id(rand::random())
    }
}

impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

/// A mux session object.
///
/// Wraps the underlying I/O resource and makes progress via its
/// [`MuxSession::poll_next_inbound`] method which must be called repeatedly
/// until `Ok(None)` signals EOF or an error is encountered.
#[derive(Debug)]
pub struct MuxSession<T> {
    inner: SessionState<T>,
}

impl<T: AsyncRead + AsyncWrite + Unpin> MuxSession<T> {
    pub fn new(socket: T, cfg: MuxConfig, mode: Mode) -> Self {
        Self {
            inner: SessionState::Active(Active::new(socket, cfg, mode)),
        }
    }

    /// Poll for a new outbound stream.
    ///
    /// When the session has no stream credit left, this returns `Pending`
    /// until a stream completes and hands its credit back. The session stays
    /// usable throughout: the flows that are already running are not
    /// affected by an open that has to wait.
    pub fn poll_new_outbound(&mut self, cx: &mut Context<'_>) -> Poll<Result<MuxStream>> {
        loop {
            match std::mem::replace(&mut self.inner, SessionState::Poisoned) {
                SessionState::Active(mut active) => match active.poll_new_outbound(cx) {
                    Poll::Ready(Ok(stream)) => {
                        self.inner = SessionState::Active(active);
                        return Poll::Ready(Ok(stream));
                    }
                    Poll::Pending => {
                        self.inner = SessionState::Active(active);
                        return Poll::Pending;
                    }
                    // The local stream-count cap is a per-request condition, not a
                    // session-level failure — the same limit hit from the inbound
                    // direction (`Active::on_data`/`on_window_update`) only resets
                    // the offending stream and leaves the session running. Do the
                    // same here: fail this one request, keep the session `Active`
                    // so concurrently open streams and future requests are
                    // unaffected. Every other error here is a genuine transport/
                    // protocol failure and still tears the session down.
                    //
                    // `Active::poll_new_outbound` no longer reports the cap this
                    // way -- it waits for the credit instead -- so this arm is
                    // the safety net for a session that cannot open at all.
                    Poll::Ready(Err(MuxError::TooManyStreams)) => {
                        self.inner = SessionState::Active(active);
                        return Poll::Ready(Err(MuxError::TooManyStreams));
                    }
                    Poll::Ready(Err(e)) => {
                        self.inner = SessionState::Cleanup(active.cleanup(e));
                        continue;
                    }
                },
                SessionState::Closing(mut inner) => match inner.poll_unpin(cx) {
                    Poll::Ready(Ok(())) => {
                        self.inner = SessionState::Closed;
                        return Poll::Ready(Err(MuxError::Closed));
                    }
                    Poll::Ready(Err(e)) => {
                        self.inner = SessionState::Closed;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        self.inner = SessionState::Closing(inner);
                        return Poll::Pending;
                    }
                },
                SessionState::Cleanup(mut inner) => match inner.poll_unpin(cx) {
                    Poll::Ready(e) => {
                        self.inner = SessionState::Closed;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        self.inner = SessionState::Cleanup(inner);
                        return Poll::Pending;
                    }
                },
                SessionState::Closed => {
                    self.inner = SessionState::Closed;
                    return Poll::Ready(Err(MuxError::Closed));
                }
                SessionState::Poisoned => unreachable!(),
            }
        }
    }

    /// Poll for the next inbound stream.
    ///
    /// If this function returns `None`, the underlying session is closed.
    pub fn poll_next_inbound(&mut self, cx: &mut Context<'_>) -> Poll<Option<Result<MuxStream>>> {
        loop {
            match std::mem::replace(&mut self.inner, SessionState::Poisoned) {
                SessionState::Active(mut active) => match active.poll(cx) {
                    Poll::Ready(Ok(stream)) => {
                        self.inner = SessionState::Active(active);
                        return Poll::Ready(Some(Ok(stream)));
                    }
                    Poll::Ready(Err(e)) => {
                        self.inner = SessionState::Cleanup(active.cleanup(e));
                        continue;
                    }
                    Poll::Pending => {
                        self.inner = SessionState::Active(active);
                        return Poll::Pending;
                    }
                },
                SessionState::Closing(mut closing) => match closing.poll_unpin(cx) {
                    Poll::Ready(Ok(())) => {
                        self.inner = SessionState::Closed;
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Err(e)) => {
                        self.inner = SessionState::Closed;
                        return Poll::Ready(Some(Err(e)));
                    }
                    Poll::Pending => {
                        self.inner = SessionState::Closing(closing);
                        return Poll::Pending;
                    }
                },
                SessionState::Cleanup(mut cleanup) => match cleanup.poll_unpin(cx) {
                    Poll::Ready(MuxError::Closed) => {
                        self.inner = SessionState::Closed;
                        return Poll::Ready(None);
                    }
                    Poll::Ready(other) => {
                        self.inner = SessionState::Closed;
                        return Poll::Ready(Some(Err(other)));
                    }
                    Poll::Pending => {
                        self.inner = SessionState::Cleanup(cleanup);
                        return Poll::Pending;
                    }
                },
                SessionState::Closed => {
                    self.inner = SessionState::Closed;
                    return Poll::Ready(None);
                }
                SessionState::Poisoned => unreachable!(),
            }
        }
    }

    /// Close the session.
    pub fn poll_close(&mut self, cx: &mut Context<'_>) -> Poll<Result<()>> {
        loop {
            match std::mem::replace(&mut self.inner, SessionState::Poisoned) {
                SessionState::Active(active) => {
                    self.inner = SessionState::Closing(active.close());
                }
                SessionState::Closing(mut inner) => match inner.poll_unpin(cx) {
                    Poll::Ready(Ok(())) => {
                        self.inner = SessionState::Closed;
                    }
                    Poll::Ready(Err(e)) => {
                        tracing::warn!("Failure while closing session: {e}");
                        self.inner = SessionState::Closed;
                        return Poll::Ready(Err(e));
                    }
                    Poll::Pending => {
                        self.inner = SessionState::Closing(inner);
                        return Poll::Pending;
                    }
                },
                SessionState::Cleanup(mut cleanup) => match cleanup.poll_unpin(cx) {
                    Poll::Ready(reason) => {
                        tracing::warn!("Failure while closing session: {reason}");
                        self.inner = SessionState::Closed;
                        return Poll::Ready(Ok(()));
                    }
                    Poll::Pending => {
                        self.inner = SessionState::Cleanup(cleanup);
                        return Poll::Pending;
                    }
                },
                SessionState::Closed => {
                    self.inner = SessionState::Closed;
                    return Poll::Ready(Ok(()));
                }
                SessionState::Poisoned => {
                    unreachable!()
                }
            }
        }
    }
}

impl<T> Drop for MuxSession<T> {
    fn drop(&mut self) {
        match &mut self.inner {
            SessionState::Active(active) => active.drop_all_streams(),
            SessionState::Closing(_) => {}
            SessionState::Cleanup(_) => {}
            SessionState::Closed => {}
            SessionState::Poisoned => {}
        }
    }
}

enum SessionState<T> {
    /// The session is alive and healthy.
    Active(Active<T>),
    /// Our user requested to shutdown the session, we are working on it.
    Closing(Closing<T>),
    /// An error occurred and we are cleaning up our resources.
    Cleanup(Cleanup),
    /// The session is closed.
    Closed,
    /// Something went wrong during our state transitions. Should never happen unless there is a bug.
    Poisoned,
}

impl<T> fmt::Debug for SessionState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SessionState::Active(_) => write!(f, "Active"),
            SessionState::Closing(_) => write!(f, "Closing"),
            SessionState::Cleanup(_) => write!(f, "Cleanup"),
            SessionState::Closed => write!(f, "Closed"),
            SessionState::Poisoned => write!(f, "Poisoned"),
        }
    }
}

/// The active state of [`MuxSession`].
struct Active<T> {
    id: Id,
    mode: Mode,
    config: Arc<MuxConfig>,
    socket: Fuse<frame::Io<T>>,
    next_id: u32,

    streams: IntMap<StreamId, Arc<Mutex<stream::Shared>>>,
    stream_receivers: SelectAll<TaggedStream<StreamId, mpsc::Receiver<StreamCommand>>>,
    no_streams_waker: Option<Waker>,

    pending_read_frame: Option<Frame<()>>,
    pending_write_frame: Option<Frame<()>>,

    /// Waker of a task waiting for outbound stream credit.
    ///
    /// Woken when a stream completes and hands its credit back.
    credit_waker: Option<Waker>,
    /// Waker of a task waiting for the ACK backlog to drain.
    ack_waker: Option<Waker>,

    /// Streams we have opened toward the peer that have not completed yet.
    ///
    /// This is the stream credit of RFC 9000 (section 4.6): a stream counts
    /// against the limit until it is completed, and its credit comes back
    /// when it is.
    outbound_active: usize,
    /// Streams the peer has opened toward us that have not completed yet.
    inbound_active: usize,

    /// When the credit exhaustion was last reported, to keep the log
    /// readable when the session is saturated.
    last_credit_warning: Option<Instant>,

    rtt: rtt::Rtt,

    /// A stream's `max_stream_receive_window` can grow beyond [`DEFAULT_CREDIT`], see
    /// [`MuxStream::next_window_update`]. This field is the sum of the bytes by which all streams'
    /// `max_stream_receive_window` have each exceeded [`DEFAULT_CREDIT`]. Used to enforce
    /// [`MuxConfig::max_connection_receive_window`].
    accumulated_max_stream_windows: Arc<Mutex<usize>>,
}

/// `MuxStream` to `MuxSession` commands.
#[derive(Debug)]
pub(crate) enum StreamCommand {
    /// A new frame should be sent to the remote.
    SendFrame(Frame<Either<Data, WindowUpdate>>),
    /// Close a stream.
    CloseStream { ack: bool },
}

/// Possible actions as a result of incoming frame handling.
#[derive(Debug)]
pub(crate) enum Action {
    /// Nothing to be done.
    None,
    /// A new stream has been opened by the remote.
    New(MuxStream),
    /// A ping should be answered.
    Ping(Frame<Ping>),
    /// Reset a single stream (stream limit exceeded, not a session-level error).
    ResetStream(Frame<Data>),
    /// The session should be terminated.
    Terminate(Frame<GoAway>),
}

impl<T> fmt::Debug for Active<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("MuxSession")
            .field("id", &self.id)
            .field("mode", &self.mode)
            .field("streams", &self.streams.len())
            .field("next_id", &self.next_id)
            .finish()
    }
}

impl<T> fmt::Display for Active<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "(MuxSession {} {:?} (streams {}))",
            self.id,
            self.mode,
            self.streams.len()
        )
    }
}

impl<T: AsyncRead + AsyncWrite + Unpin> Active<T> {
    /// Create a new `Active` session from the given I/O resource.
    fn new(socket: T, cfg: MuxConfig, mode: Mode) -> Self {
        let id = Id::random();
        tracing::debug!("new session: {id} ({mode:?})");
        let socket = frame::Io::new(id, socket).fuse();
        Active {
            id,
            mode,
            config: Arc::new(cfg),
            socket,
            streams: IntMap::default(),
            stream_receivers: SelectAll::default(),
            no_streams_waker: None,
            next_id: match mode {
                Mode::Client => 1,
                Mode::Server => 2,
            },
            pending_read_frame: None,
            pending_write_frame: None,
            credit_waker: None,
            ack_waker: None,
            outbound_active: 0,
            inbound_active: 0,
            last_credit_warning: None,
            rtt: rtt::Rtt::new(),
            accumulated_max_stream_windows: Default::default(),
        }
    }

    /// Gracefully close the session to the remote.
    fn close(self) -> Closing<T> {
        let pending_frames = self
            .pending_read_frame
            .into_iter()
            .chain(self.pending_write_frame)
            .collect::<VecDeque<Frame<()>>>();
        Closing::new(self.stream_receivers, pending_frames, self.socket)
    }

    /// Cleanup all our resources.
    ///
    /// This should be called in the context of an unrecoverable error on the session.
    fn cleanup(mut self, error: MuxError) -> Cleanup {
        self.drop_all_streams();
        Cleanup::new(self.stream_receivers, error)
    }

    fn poll(&mut self, cx: &mut Context<'_>) -> Poll<Result<MuxStream>> {
        loop {
            if self.socket.poll_ready_unpin(cx).is_ready() {
                // Note `next_ping` does not register a waker and thus if not called regularly (idle
                // session) no ping is sent. This is deliberate as an idle session does not
                // need RTT measurements to increase its stream receive window.
                if let Some(frame) = self.rtt.next_ping() {
                    self.socket.start_send_unpin(frame.into())?;
                    continue;
                }

                // Privilege pending `Pong` and `GoAway` `Frame`s
                // over `Frame`s from the receivers.
                if let Some(frame) = self
                    .pending_read_frame
                    .take()
                    .or_else(|| self.pending_write_frame.take())
                {
                    self.socket.start_send_unpin(frame)?;
                    continue;
                }
            }

            match self.socket.poll_flush_unpin(cx)? {
                Poll::Ready(()) => {}
                Poll::Pending => {}
            }

            if self.pending_write_frame.is_none() {
                match self.stream_receivers.poll_next_unpin(cx) {
                    Poll::Ready(Some((_, Some(StreamCommand::SendFrame(frame))))) => {
                        tracing::trace!(
                            "{}/{}: sending: {}",
                            self.id,
                            frame.header().stream_id(),
                            frame.header()
                        );
                        self.pending_write_frame.replace(frame.into());
                        continue;
                    }
                    Poll::Ready(Some((id, Some(StreamCommand::CloseStream { ack })))) => {
                        tracing::trace!("{}/{}: sending close", self.id, id);
                        self.pending_write_frame
                            .replace(Frame::close_stream(id, ack).into());
                        // The local side just closed this stream. If that
                        // made the stream terminal -- the peer had already
                        // sent its FIN -- its credit belongs back in the pool
                        // NOW, not when the local handle happens to be dropped.
                        // Without this, a session that carries a machine's
                        // whole traffic loses one credit per closed stream
                        // and runs dry while nothing is running.
                        self.check_completion(id);
                        continue;
                    }
                    Poll::Ready(Some((id, None))) => {
                        if let Some(frame) = self.on_drop_stream(id) {
                            tracing::trace!("{}/{}: sending: {}", self.id, id, frame.header());
                            self.pending_write_frame.replace(frame);
                        };
                        continue;
                    }
                    Poll::Ready(None) => {
                        self.no_streams_waker = Some(cx.waker().clone());
                    }
                    Poll::Pending => {}
                }
            }

            if self.pending_read_frame.is_none() {
                match self.socket.poll_next_unpin(cx) {
                    Poll::Ready(Some(frame)) => {
                        match self.on_frame(frame?)? {
                            Action::None => {}
                            Action::New(stream) => {
                                tracing::trace!("{}: new inbound {} of {}", self.id, stream, self);
                                return Poll::Ready(Ok(stream));
                            }
                            Action::Ping(f) => {
                                tracing::trace!("{}/{}: pong", self.id, f.header().stream_id());
                                self.pending_read_frame.replace(f.into());
                            }
                            Action::ResetStream(f) => {
                                tracing::trace!(
                                    "{}/{}: sending RST (stream limit)",
                                    self.id,
                                    f.header().stream_id()
                                );
                                self.pending_read_frame.replace(f.into());
                            }
                            Action::Terminate(f) => {
                                tracing::trace!("{}: sending term", self.id);
                                self.pending_read_frame.replace(f.into());
                            }
                        }
                        continue;
                    }
                    Poll::Ready(None) => {
                        return Poll::Ready(Err(MuxError::Closed));
                    }
                    Poll::Pending => {}
                }
            }

            // If we make it this far, at least one of the above must have registered a waker.
            return Poll::Pending;
        }
    }

    fn poll_new_outbound(&mut self, cx: &mut Context<'_>) -> Poll<Result<MuxStream>> {
        if self.outbound_active >= self.config.max_outbound_streams {
            // No stream credit left. This is backpressure, not a failure.
            //
            // The credit comes back when a stream completes -- both of its
            // directions closed -- or when its handle is dropped, and the
            // waiter is woken then. QUIC hands the credit back the same way
            // (RFC 9000, section 4.6) and HTTP/2 raises
            // `SETTINGS_MAX_CONCURRENT_STREAMS` for the same reason.
            //
            // Refusing the open instead would take down every flow that is
            // already running through this session: the caller has nowhere
            // else to go, so a saturated session turned into a dead client.
            self.credit_waker = Some(cx.waker().clone());
            self.log_credit_exhaustion();
            return Poll::Pending;
        }

        if self.ack_backlog() >= MAX_ACK_BACKLOG {
            tracing::debug!("{MAX_ACK_BACKLOG} streams waiting for ACK, registering task for wake-up until remote acknowledges at least one stream");
            self.ack_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        tracing::trace!("{}: creating new outbound stream", self.id);

        let id = self.next_stream_id()?;
        let stream = self.make_new_outbound_stream(id);

        tracing::debug!("{}: new outbound {} of {}", self.id, stream, self);
        self.streams.insert(id, stream.clone_shared());
        self.outbound_active += 1;

        Poll::Ready(Ok(stream))
    }

    /// Whether a stream was opened by us rather than by the peer.
    ///
    /// Clients use odd ids and servers use even ids.
    fn is_outbound(&self, stream_id: StreamId) -> bool {
        match self.mode {
            Mode::Client => stream_id.is_client(),
            Mode::Server => stream_id.is_server(),
        }
    }

    /// Hand the stream credit back once the stream is complete.
    ///
    /// A stream is complete when both of its directions are closed -- the
    /// peer sent its FIN and we sent ours, or one side reset it. Only then
    /// does it stop counting against the stream credit.
    fn check_completion(&mut self, stream_id: StreamId) {
        let Some(shared) = self.streams.get(&stream_id).cloned() else {
            return;
        };
        let completed = shared.lock().state() == State::Closed;
        if completed {
            self.return_credit(stream_id);
        }
    }

    /// Hand the stream credit back to the pool.
    ///
    /// The credit is returned exactly once per stream, whichever retirement
    /// path fires first: the stream reaching its terminal state, or the
    /// local handle being dropped.
    fn return_credit(&mut self, stream_id: StreamId) {
        let Some(shared) = self.streams.get(&stream_id).cloned() else {
            // The stream is no longer known: its credit was returned when
            // it was retired.
            return;
        };
        {
            let mut guard = shared.lock();
            if !guard.return_credit() {
                return;
            }
        }
        if self.is_outbound(stream_id) {
            self.outbound_active = self.outbound_active.saturating_sub(1);
        } else {
            self.inbound_active = self.inbound_active.saturating_sub(1);
        }
        if let Some(waker) = self.credit_waker.take() {
            waker.wake();
        }
    }

    /// Report why the session ran out of stream credit.
    ///
    /// The census tells the two shapes of this failure apart: streams that
    /// are alive and busy (the limit is simply too low for the traffic) and
    /// streams that are half-closed and never finished (the peer keeps them
    /// open). Without it, a saturated session is indistinguishable from a
    /// leaking one.
    fn log_credit_exhaustion(&mut self) {
        let now = Instant::now();
        if let Some(last) = self.last_credit_warning {
            if now.duration_since(last) < CREDIT_WARNING_INTERVAL {
                return;
            }
        }
        self.last_credit_warning = Some(now);

        let mut open = 0usize;
        let mut half_closed = 0usize;
        let mut pending_ack = 0usize;
        let mut oldest = Duration::ZERO;
        for shared in self.streams.values() {
            let guard = shared.lock();
            match guard.state() {
                State::Open { .. } => open += 1,
                State::SendClosed | State::RecvClosed => half_closed += 1,
                State::Closed => {}
            }
            if guard.is_pending_ack() {
                pending_ack += 1;
            }
            let age = guard.age();
            if age > oldest {
                oldest = age;
            }
        }

        tracing::warn!(
            outbound_active = self.outbound_active,
            inbound_active = self.inbound_active,
            max_outbound = self.config.max_outbound_streams,
            max_inbound = self.config.max_inbound_streams,
            open,
            half_closed,
            pending_ack,
            oldest_stream_age_secs = oldest.as_secs(),
            "mux: no stream credit left -- waiting for a stream to complete"
        );
    }

    fn on_drop_stream(&mut self, stream_id: StreamId) -> Option<Frame<()>> {
        if !self.streams.contains_key(&stream_id) {
            return None;
        }

        // The handle is gone: this stream can never carry anything again,
        // so its credit goes back to the pool even if it never reached its
        // terminal state.
        self.return_credit(stream_id);

        let s = self.streams.remove(&stream_id).expect("stream not found");

        tracing::trace!("{}: removing dropped stream {}", self.id, stream_id);
        let frame = {
            let mut shared = s.lock();
            let frame = match shared.update_state(self.id, stream_id, State::Closed) {
                // The stream was dropped without calling `poll_close`.
                // We reset the stream to inform the remote of the closure.
                State::Open { .. } => {
                    let mut header = Header::data(stream_id, 0);
                    header.rst();
                    Some(Frame::new(header))
                }
                // The stream was dropped without calling `poll_close`.
                // We have already received a FIN from remote and send one
                // back which closes the stream for good.
                State::RecvClosed => {
                    let mut header = Header::data(stream_id, 0);
                    header.fin();
                    Some(Frame::new(header))
                }
                // The stream was properly closed. We already sent our FIN frame.
                // The remote may be out of credit though and blocked on
                // writing more data. We may need to reset the stream.
                State::SendClosed => {
                    // The remote has either still credit or will be given more
                    // due to an enqueued window update or we already have
                    // inbound frames in the socket buffer which will be
                    // processed later. In any case we will reply with an RST in
                    // `MuxSession::on_data` because the stream will no longer
                    // be known.
                    None
                }
                // The stream was properly closed. We already have sent our FIN frame. The
                // remote end has already done so in the past.
                State::Closed => None,
            };
            if let Some(w) = shared.reader.take() {
                w.wake()
            }
            if let Some(w) = shared.writer.take() {
                w.wake()
            }
            frame
        };
        frame.map(Into::into)
    }

    /// Process the result of reading from the socket.
    ///
    /// Unless `frame` is `Ok(Some(_))` we will assume the session got closed
    /// and return a corresponding error, which terminates the session.
    /// Otherwise we process the frame and potentially return a new `MuxStream`
    /// if one was opened by the remote.
    fn on_frame(&mut self, frame: Frame<()>) -> Result<Action> {
        tracing::trace!("{}: received: {}", self.id, frame.header());

        if frame.header().flags().contains(header::ACK)
            && matches!(frame.header().tag(), Tag::Data | Tag::WindowUpdate)
        {
            let id = frame.header().stream_id();
            if let Some(stream) = self.streams.get(&id) {
                stream
                    .lock()
                    .update_state(self.id, id, State::Open { acknowledged: true });
            }
            if let Some(waker) = self.ack_waker.take() {
                waker.wake();
            }
        }

        let action = match frame.header().tag() {
            Tag::Data => self.on_data(frame.into_data()),
            Tag::WindowUpdate => self.on_window_update(&frame.into_window_update()),
            Tag::Ping => self.on_ping(&frame.into_ping()),
            Tag::GoAway => return Err(MuxError::Closed),
        };
        Ok(action)
    }

    fn on_data(&mut self, frame: Frame<Data>) -> Action {
        let stream_id = frame.header().stream_id();

        if frame.header().flags().contains(header::RST) {
            // stream reset
            if let Some(s) = self.streams.get(&stream_id).cloned() {
                {
                    let mut shared = s.lock();
                    shared.update_state(self.id, stream_id, State::Closed);
                    if let Some(w) = shared.reader.take() {
                        w.wake()
                    }
                    if let Some(w) = shared.writer.take() {
                        w.wake()
                    }
                }
                self.check_completion(stream_id);
            }
            return Action::None;
        }

        let is_finish = frame.header().flags().contains(header::FIN); // half-close

        if frame.header().flags().contains(header::SYN) {
            // new stream
            if !self.is_valid_remote_id(stream_id, Tag::Data) {
                tracing::error!("{}: invalid stream id {}", self.id, stream_id);
                return Action::Terminate(Frame::protocol_error());
            }
            if self.streams.contains_key(&stream_id) {
                tracing::error!("{}/{}: stream already exists", self.id, stream_id);
                return Action::Terminate(Frame::protocol_error());
            }
            if self.inbound_active >= self.config.max_inbound_streams {
                // The peer opened more streams than we allow. Refuse this
                // one stream only: the session and every other stream stay
                // up. HTTP/2 calls this REFUSED_STREAM, QUIC refuses the
                // stream that exceeds the credit.
                tracing::warn!(
                    "{}/{}: no inbound stream credit left, refusing this stream",
                    self.id,
                    stream_id
                );
                let mut rst_header = header::Header::data(stream_id, 0);
                rst_header.rst();
                return Action::ResetStream(Frame::new(rst_header));
            }
            if frame.body().len() > DEFAULT_CREDIT as usize {
                tracing::error!(
                    "{}/{}: 1st body of stream exceeds default credit",
                    self.id,
                    stream_id
                );
                return Action::Terminate(Frame::protocol_error());
            }
            let stream = self.make_new_inbound_stream(stream_id, DEFAULT_CREDIT);
            {
                let mut shared = stream.shared();
                if is_finish {
                    shared.update_state(self.id, stream_id, State::RecvClosed);
                }
                if let Err(_err) = shared.consume_receive_window(frame.body_len()) {
                    tracing::error!(
                        "{}/{}: 1st body of stream exceeds default credit",
                        self.id,
                        stream_id
                    );
                    return Action::Terminate(Frame::protocol_error());
                }
                shared.buffer.push(frame.into_body());
            }
            self.streams.insert(stream_id, stream.clone_shared());
            self.inbound_active += 1;
            return Action::New(stream);
        }

        if let Some(s) = self.streams.get(&stream_id).cloned() {
            let finished = {
                let mut shared = s.lock();

                if let Err(_err) = shared.consume_receive_window(frame.body_len()) {
                    tracing::error!(
                        "{}/{}: frame body larger than window of stream",
                        self.id,
                        stream_id
                    );
                    return Action::Terminate(Frame::protocol_error());
                }

                if is_finish {
                    shared.update_state(self.id, stream_id, State::RecvClosed);
                }

                shared.buffer.push(frame.into_body());
                if let Some(w) = shared.reader.take() {
                    w.wake()
                }
                is_finish
            };
            if finished {
                self.check_completion(stream_id);
            }
        } else {
            tracing::trace!(
                "{}/{}: data frame for unknown stream, possibly dropped earlier: {:?}",
                self.id,
                stream_id,
                frame
            );
            // We do not consider this a protocol violation and thus do not send a stream reset
            // because we may still be processing pending `StreamCommand`s of this stream that were
            // sent before it has been dropped and "garbage collected". Such a stream reset would
            // interfere with the frames that still need to be sent, causing premature stream
            // termination for the remote.
            //
            // See https://github.com/paritytech/yamux/issues/110 for details.
        }

        Action::None
    }

    fn on_window_update(&mut self, frame: &Frame<WindowUpdate>) -> Action {
        let stream_id = frame.header().stream_id();

        if frame.header().flags().contains(header::RST) {
            // stream reset
            if let Some(s) = self.streams.get(&stream_id).cloned() {
                {
                    let mut shared = s.lock();
                    shared.update_state(self.id, stream_id, State::Closed);
                    if let Some(w) = shared.reader.take() {
                        w.wake()
                    }
                    if let Some(w) = shared.writer.take() {
                        w.wake()
                    }
                }
                self.check_completion(stream_id);
            }
            return Action::None;
        }

        let is_finish = frame.header().flags().contains(header::FIN); // half-close

        if frame.header().flags().contains(header::SYN) {
            // new stream
            if !self.is_valid_remote_id(stream_id, Tag::WindowUpdate) {
                tracing::error!("{}: invalid stream id {}", self.id, stream_id);
                return Action::Terminate(Frame::protocol_error());
            }
            if self.streams.contains_key(&stream_id) {
                tracing::error!("{}/{}: stream already exists", self.id, stream_id);
                return Action::Terminate(Frame::protocol_error());
            }
            if self.inbound_active >= self.config.max_inbound_streams {
                // The peer opened more streams than we allow. Refuse this
                // one stream only: the session and every other stream stay
                // up. HTTP/2 calls this REFUSED_STREAM, QUIC refuses the
                // stream that exceeds the credit.
                tracing::warn!(
                    "{}/{}: no inbound stream credit left, refusing this stream",
                    self.id,
                    stream_id
                );
                let mut rst_header = header::Header::data(stream_id, 0);
                rst_header.rst();
                return Action::ResetStream(Frame::new(rst_header));
            }

            let credit = frame.header().credit() + DEFAULT_CREDIT;
            let stream = self.make_new_inbound_stream(stream_id, credit);

            if is_finish {
                stream
                    .shared()
                    .update_state(self.id, stream_id, State::RecvClosed);
            }
            self.streams.insert(stream_id, stream.clone_shared());
            self.inbound_active += 1;
            return Action::New(stream);
        }

        if let Some(s) = self.streams.get(&stream_id).cloned() {
            let finished = {
                let mut shared = s.lock();
                if let Err(err) = shared.increase_send_window_by(frame.header().credit()) {
                    tracing::error!(
                        "{}/{}: could not increase the send window, {err}",
                        self.id,
                        stream_id
                    );
                    return Action::Terminate(Frame::protocol_error());
                }
                if is_finish {
                    shared.update_state(self.id, stream_id, State::RecvClosed);

                    if let Some(w) = shared.reader.take() {
                        w.wake()
                    }
                }
                if let Some(w) = shared.writer.take() {
                    w.wake()
                }
                is_finish
            };
            if finished {
                self.check_completion(stream_id);
            }
        } else {
            tracing::trace!(
                "{}/{}: window update for unknown stream, possibly dropped earlier: {:?}",
                self.id,
                stream_id,
                frame
            );
            // We do not consider this a protocol violation and thus do not send a stream reset
            // because we may still be processing pending `StreamCommand`s of this stream that were
            // sent before it has been dropped and "garbage collected". Such a stream reset would
            // interfere with the frames that still need to be sent, causing premature stream
            // termination for the remote.
            //
            // See https://github.com/paritytech/yamux/issues/110 for details.
        }

        Action::None
    }

    fn on_ping(&mut self, frame: &Frame<Ping>) -> Action {
        let stream_id = frame.header().stream_id();
        if frame.header().flags().contains(header::ACK) {
            return self.rtt.handle_pong(frame.nonce());
        }
        if stream_id == CONNECTION_ID || self.streams.contains_key(&stream_id) {
            let mut hdr = Header::ping(frame.header().nonce());
            hdr.ack();
            return Action::Ping(Frame::new(hdr));
        }
        tracing::debug!(
            "{}/{}: ping for unknown stream, possibly dropped earlier: {:?}",
            self.id,
            stream_id,
            frame
        );
        // We do not consider this a protocol violation and thus do not send a stream reset because
        // we may still be processing pending `StreamCommand`s of this stream that were sent before
        // it has been dropped and "garbage collected". Such a stream reset would interfere with the
        // frames that still need to be sent, causing premature stream termination for the remote.
        //
        // See https://github.com/paritytech/yamux/issues/110 for details.

        Action::None
    }

    fn make_new_inbound_stream(&mut self, id: StreamId, credit: u32) -> MuxStream {
        let config = self.config.clone();

        let (mut sender, receiver) = mpsc::channel(10); // 10 is an arbitrary number.
        self.stream_receivers.push(TaggedStream::new(id, receiver));
        if let Some(waker) = self.no_streams_waker.take() {
            waker.wake();
        }

        // Acknowledge the stream right away.
        //
        // The ACK used to ride along with the peer's first byte, so a
        // stream the peer accepted but never answered stayed
        // "unacknowledged" for good and counted against the ACK backlog.
        // With a couple of hundred such streams the session stopped opening
        // streams altogether -- the same permanent exhaustion of the stream
        // credit QUIC guards against with MAX_STREAMS. Acknowledging on
        // accept makes "acknowledged" mean "the peer has this stream",
        // which is what the backlog is actually about.
        let mut ack_header = header::Header::data(id, 0);
        ack_header.ack();
        let ack = Frame::new(ack_header).left();
        if let Err(e) = sender.try_send(StreamCommand::SendFrame(ack)) {
            tracing::debug!("{}/{}: could not queue the stream acknowledgement: {e}", self.id, id);
        }

        let mut stream = MuxStream::new_inbound(
            id,
            self.id,
            config,
            credit,
            sender,
            self.rtt.clone(),
            self.accumulated_max_stream_windows.clone(),
        );
        // The session already acknowledged this stream, so the stream must
        // not piggyback a second ACK on its first frame.
        stream.clear_ack_flag();
        stream
    }

    fn make_new_outbound_stream(&mut self, id: StreamId) -> MuxStream {
        let config = self.config.clone();

        let (sender, receiver) = mpsc::channel(10); // 10 is an arbitrary number.
        self.stream_receivers.push(TaggedStream::new(id, receiver));
        if let Some(waker) = self.no_streams_waker.take() {
            waker.wake();
        }

        MuxStream::new_outbound(
            id,
            self.id,
            config,
            sender,
            self.rtt.clone(),
            self.accumulated_max_stream_windows.clone(),
        )
    }

    fn next_stream_id(&mut self) -> Result<StreamId> {
        let proposed = StreamId::new(self.next_id);
        self.next_id = self
            .next_id
            .checked_add(2)
            .ok_or(MuxError::NoMoreStreamIds)?;
        match self.mode {
            Mode::Client => assert!(proposed.is_client()),
            Mode::Server => assert!(proposed.is_server()),
        }
        Ok(proposed)
    }

    /// The ACK backlog is defined as the number of outbound streams that have not yet been acknowledged.
    fn ack_backlog(&mut self) -> usize {
        self.streams
            .iter()
            // Whether this is an outbound stream.
            //
            // Clients use odd IDs and servers use even IDs.
            // A stream is outbound if:
            //
            // - Its ID is odd and we are the client.
            // - Its ID is even and we are the server.
            .filter(|(id, _)| match self.mode {
                Mode::Client => id.is_client(),
                Mode::Server => id.is_server(),
            })
            .filter(|(_, s)| s.lock().is_pending_ack())
            .count()
    }

    // Check if the given stream ID is valid w.r.t. the provided tag and our session mode.
    fn is_valid_remote_id(&self, id: StreamId, tag: Tag) -> bool {
        if tag == Tag::Ping || tag == Tag::GoAway {
            return id.is_session();
        }
        match self.mode {
            Mode::Client => id.is_server(),
            Mode::Server => id.is_client(),
        }
    }
}

impl<T> Active<T> {
    /// Close and drop all `MuxStream`s and wake any pending `Waker`s.
    fn drop_all_streams(&mut self) {
        for (id, s) in self.streams.drain() {
            let mut shared = s.lock();
            shared.update_state(self.id, id, State::Closed);
            if let Some(w) = shared.reader.take() {
                w.wake()
            }
            if let Some(w) = shared.writer.take() {
                w.wake()
            }
        }
    }
}
