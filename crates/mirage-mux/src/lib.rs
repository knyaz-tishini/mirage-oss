#![forbid(unsafe_code)]

use std::time::Duration;

mod chunks;
mod error;
mod frame;
pub(crate) mod session;
mod tagged_stream;
#[cfg(feature = "tokio-compat")]
pub mod tokio_compat;

pub use crate::session::{MuxSession, Mode, Packet, MuxStream};
pub use crate::error::MuxError;
pub use crate::frame::{
    header::{HeaderDecodeError, StreamId},
    FrameDecodeError,
};

const KIB: usize = 1024;
pub(crate) const MIB: usize = KIB * 1024;
const GIB: usize = MIB * 1024;

/// The window one stream starts with, and the minimum the connection window
/// guarantees to every stream.
///
/// 64 KiB is what QUIC gives a stream by default (RFC 9000, section 7.2). It
/// is enough for a machine's connections: the window grows on demand, twice
/// the size each time, so a fat link reaches megabytes within a few round
/// trips.
///
/// The number of streams and this window are one decision, not two. A box
/// with a gigabyte of RAM can afford 2048 streams of 64 KiB (128 MiB of
/// credit in flight) or 512 streams of 256 KiB (the same 128 MiB) -- but the
/// second number runs out of slots four times sooner, and a machine behind
/// the tunnel opens hundreds of connections at once.
pub const DEFAULT_CREDIT: u32 = 64 * KIB as u32;

pub type Result<T> = std::result::Result<T, MuxError>;

/// The maximum number of streams we will open without an acknowledgement from the other peer.
///
/// This enables a very basic form of backpressure on the creation of streams.
///
/// The bound is only meaningful because an accepted stream is acknowledged
/// right away (see `Active::make_new_inbound_stream`). Before that, a stream
/// the peer accepted but never answered stayed "unacknowledged" forever, so
/// a peer that stayed silent could wedge the session for good.
pub(crate) const MAX_ACK_BACKLOG: usize = 256;

/// Default ceiling on the number of streams that may be open at the same
/// time, counted per direction.
///
/// The protocols this crate is modelled on:
///
/// - HTTP/2 advertises `SETTINGS_MAX_CONCURRENT_STREAMS`. nghttp2 and curl
///   both default to 100; nghttp2 moved the RFC 7540 "unlimited" default to
///   100 in v1.6.0 because an unlimited limit produced a flood of
///   `REFUSED_STREAM`.
/// - QUIC leaves `initial_max_streams_bidi` / `_uni` to the application
///   (RFC 9000, section 18.2). quiche defaults them to 0, which means "no
///   streams until the application says otherwise".
/// - yamux, whose wire format this crate follows, defaults to 256.
///
/// Those limits govern one conversation between two peers. A mirage mux
/// session carries every TCP flow of a whole device through one edge
/// session, so the ceiling has to sit well above what a single browser
/// needs: 256 keeps a busy phone working and still bounds what one client
/// can pin on the peer.
///
/// 256 is NOT enough for that job. A Windows machine behind a tun opens
/// three hundred connections on its own — every tab, every DNS lookup, every
/// chat socket — and the ones that stay open (a chat socket, an SSH session,
/// a keep-alive) hold their slot for as long as they live. At 256 the
/// session saturates, every new flow waits for a slot that never comes, and
/// the machine looks dead. The measurement that settled it: a busy machine
/// peaked at 263 concurrent flows against a 256 ceiling, and the session
/// died every 57 seconds, exactly when the ceiling was reached.
///
/// 512 leaves room for the machine's traffic AND for the long-lived flows
/// that pile up over the session's life, while keeping the peer's buffer
/// inside what a small box can hold: 512 x 256 KiB = 128 MiB of credit in
/// flight, on a box with 1 GiB of RAM. The connection window stays at 1 GiB.
///
/// 2048 is the same 128 MiB of credit with the smaller per-stream window
/// (64 KiB), and four times the slots. The measurement that set the number:
/// a busy machine behind the tunnel peaked at 263 concurrent flows, and the
/// ones that stay open hold their slot for hours.
pub const DEFAULT_MAX_STREAMS: usize = 2048;

/// Default bound on how long an open waits for stream credit.
///
/// The credit normally comes back as soon as a stream completes, so this
/// only matters for a session whose peer never completes a stream.
///
/// The bound is long on purpose. An open that gives up too early is not a
/// failed open, it is a request that has to be made again -- and on a busy
/// machine the second request queues BEHIND the first one, so a short bound
/// turns a busy session into a queue of abandoned requests. The session's
/// own death still unblocks every waiter immediately; this bound only stops
/// a waiter from hanging on a session that stays up but never hands out
/// credit.
pub const DEFAULT_STREAM_CREDIT_WAIT: Duration = Duration::from_secs(300);

/// Default maximum number of bytes a data frame might carry as its
/// payload when being sent. Larger payloads will be split.
const DEFAULT_SPLIT_SEND_SIZE: usize = 16 * KIB;

/// Mux session configuration.
///
/// The default configuration values are as follows:
///
/// - max. for the total receive window size across all streams of a session = 1 GiB
/// - max. number of streams = 256 per direction
/// - read after close = true
/// - split send size = 16 KiB
#[derive(Debug, Clone)]
pub struct MuxConfig {
    pub(crate) max_connection_receive_window: Option<usize>,
    pub(crate) max_num_streams: usize,
    /// How many streams the peer may have open toward us at the same time.
    pub(crate) max_inbound_streams: usize,
    /// How many streams we may have open toward the peer at the same time.
    pub(crate) max_outbound_streams: usize,
    /// How long an open waits for stream credit before it gives up.
    pub(crate) stream_credit_wait: Duration,
    pub(crate) read_after_close: bool,
    pub(crate) split_send_size: usize,
}

impl Default for MuxConfig {
    fn default() -> Self {
        MuxConfig {
            max_connection_receive_window: Some(GIB),
            max_num_streams: DEFAULT_MAX_STREAMS,
            max_inbound_streams: DEFAULT_MAX_STREAMS,
            max_outbound_streams: DEFAULT_MAX_STREAMS,
            stream_credit_wait: DEFAULT_STREAM_CREDIT_WAIT,
            read_after_close: true,
            split_send_size: DEFAULT_SPLIT_SEND_SIZE,
        }
    }
}

impl MuxConfig {
    /// Set the upper limit for the total receive window size across all streams of a session.
    pub fn set_max_connection_receive_window(&mut self, n: Option<usize>) -> &mut Self {
        self.max_connection_receive_window = n;

        self.assert_connection_window();

        self
    }

    /// Set the max. number of streams per session.
    ///
    /// This sets the reference number the connection-level receive window is
    /// derived from and both direction budgets to `n`. Use
    /// [`Self::set_max_inbound_streams`] and [`Self::set_max_outbound_streams`]
    /// to give the two directions different ceilings.
    pub fn set_max_num_streams(&mut self, n: usize) -> &mut Self {
        self.max_num_streams = n;
        self.max_inbound_streams = n;
        self.max_outbound_streams = n;

        self.assert_connection_window();

        self
    }

    /// Set how many streams the peer may have open toward us at the same time.
    ///
    /// This is the inbound half of the stream credit: the peer is refused
    /// once it has this many streams open, and the credit comes back when a
    /// stream completes. HTTP/2 expresses the same bound as
    /// `SETTINGS_MAX_CONCURRENT_STREAMS`, QUIC as `initial_max_streams_*`
    /// plus the `MAX_STREAMS` frames that replenish it.
    pub fn set_max_inbound_streams(&mut self, n: usize) -> &mut Self {
        self.max_inbound_streams = n;

        self
    }

    /// Set how many streams we may have open toward the peer at the same time.
    ///
    /// Reaching this bound does not fail the open: the caller waits until a
    /// stream completes and hands its credit back.
    pub fn set_max_outbound_streams(&mut self, n: usize) -> &mut Self {
        self.max_outbound_streams = n;

        self
    }

    /// Set how long an open waits for stream credit before it gives up.
    ///
    /// The wait ends as soon as a stream completes, so this is only the
    /// bound for a session whose peer never completes a stream.
    pub fn set_stream_credit_wait(&mut self, wait: Duration) -> &mut Self {
        self.stream_credit_wait = wait;

        self
    }

    /// Allow or disallow streams to read from buffered data after the session has been closed.
    pub fn set_read_after_close(&mut self, b: bool) -> &mut Self {
        self.read_after_close = b;
        self
    }

    /// Set the max. payload size used when sending data frames. Payloads larger than the configured
    /// max. will be split.
    pub fn set_split_send_size(&mut self, n: usize) -> &mut Self {
        self.split_send_size = n;
        self
    }

    /// The connection-level receive window has to leave every stream at
    /// least its default window.
    fn assert_connection_window(&self) {
        assert!(
            self.max_connection_receive_window.unwrap_or(usize::MAX)
                >= self.max_num_streams * DEFAULT_CREDIT as usize,
            "`max_connection_receive_window` must be `>= 64 KiB * max_num_streams` to allow each \
            stream at least the default window size"
        );
    }
}
