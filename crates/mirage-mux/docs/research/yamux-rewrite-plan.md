# Implementation Plan: mirage-mux yamux-based Rewrite

## Architecture Decision

Replace the current 6-file ad-hoc implementation with yamux's proven module
structure, translated to our naming and tokio-only deps. The public API
(`MuxSession`, `MuxStream`, `MuxError`) stays identical — all three consumers
recompile without changes.

---

## Public API Contract (must not change)

```rust
// lib.rs re-exports — unchanged
pub use error::{MuxError, Result};
pub use frame::{Flags, Frame, FrameType, Header, HEADER_LEN};
pub use session::MuxSession;
pub use stream::MuxStream;
pub use window::{INITIAL_WINDOW, MAX_FRAME_PAYLOAD};

// MuxSession — unchanged signatures
impl MuxSession {
    pub fn client<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(t: T) -> Self;
    pub fn server<T: AsyncRead + AsyncWrite + Send + Unpin + 'static>(t: T) -> Self;
    pub async fn open_stream(&self) -> Result<MuxStream>;
    pub async fn accept_stream(&self) -> Result<MuxStream>;
    pub async fn close(&self) -> Result<()>;
    pub fn is_closed(&self) -> bool;
}

// MuxStream — unchanged
impl MuxStream {
    pub fn id(&self) -> u32;
    // impl AsyncRead + AsyncWrite
}
```

Consumers that must keep compiling without modification:
- `mirage-client-core/src/mux_pool.rs` — `MuxSession::client`, `open_stream`, `is_closed`, `MuxError::SessionClosed`, `MuxError::MaxStreams`
- `mirage-client-core/src/relay.rs` — `TunnelCompat` passes any `AsyncRead+AsyncWrite`, no mux types directly
- `mirage-node/src/exit/direct.rs` — `MuxSession::server`, `accept_stream`, `MuxStream` as `AsyncRead+AsyncWrite+Unpin`

---

## yamux Name → Our Name Mapping

| yamux | mirage-mux | Notes |
|-------|-----------|-------|
| `Connection` | `MuxSession` (internals of `SessionInner`) | keep pub struct name |
| `Stream` | `MuxStream` | keep |
| `ConnectionError` | `MuxError` | keep, add new variants |
| `Config` | `SessionConfig` (pub(crate)) | not exposed publicly |
| `Mode::Client/Server` | `is_client: bool` param | no pub enum needed |
| `FlowController` | `FlowControl` (in `flow_control.rs`) | |
| `Rtt` | `RttTracker` (in `rtt.rs`) | |
| `Closing` | `ClosingState` (in `closing.rs`) | |
| `Chunks` | `RecvBuffer` (in `chunks.rs`) | |
| `TaggedStream` | not needed | yamux-specific futures glue |
| `frame::header` | `frame.rs` (keep existing) | already correct wire format |
| `frame::io` | `frame_io.rs` | new file |

---

## Module Layout

### Files to DELETE (replaced entirely)
- `src/window.rs` — constants migrate to `src/flow_control.rs`; `WindowTracker` replaced by `FlowControl`

### Files to KEEP + MODIFY
- `src/lib.rs` — add `mod flow_control; mod rtt; mod closing; mod chunks; mod frame_io;`
- `src/error.rs` — add `StreamReset` variant already exists; add `Timeout`, `TooManyStreams` (aliases MaxStreams), `GoAway(u32)` for GoAway error code
- `src/frame.rs` — keep as-is; wire format is already yamux-compatible 12-byte header

### Files to CREATE
- `src/flow_control.rs` — replaces `window.rs`
- `src/rtt.rs` — new
- `src/closing.rs` — new
- `src/chunks.rs` — new
- `src/frame_io.rs` — new

### Files to REWRITE
- `src/session.rs` — full rewrite adopting yamux `connection.rs` design
- `src/stream.rs` — full rewrite adopting yamux `connection/stream.rs` design

---

## Types & Signatures

### `src/flow_control.rs`

```rust
pub(crate) const INITIAL_WINDOW: u32 = 256 * 1024;
pub(crate) const MAX_FRAME_PAYLOAD: usize = 64 * 1024;

/// BDP-based auto-tuning receive window (per stream).
/// Mirrors yamux FlowController with tokio::time instead of web-time.
pub(crate) struct FlowControl {
    window_size: u32,
    window_buf: u32,         // bytes received but not yet acked
    rtt_ms: u32,             // last measured RTT in ms
    last_update: std::time::Instant,
}

impl FlowControl {
    pub(crate) fn new() -> Self;

    /// Call after receiving `n` data bytes.
    /// Returns `Some(delta)` → send WindowUpdate(delta) to peer.
    pub(crate) fn consume(&mut self, n: u32) -> Option<u32>;

    /// Feed RTT sample to update window size (BDP = bandwidth × RTT).
    pub(crate) fn update_rtt(&mut self, rtt_ms: u32);
}
```

Key difference from current `WindowTracker`: `update_rtt` drives dynamic window
expansion. Initial behavior (threshold-based ack at 64 KiB) is preserved as the
no-RTT-data path, so correctness is maintained even before the first ping.

### `src/rtt.rs`

```rust
use std::time::Instant;
use tokio::time::Duration;

pub(crate) struct RttTracker {
    /// Ping nonce → send time.  Max one inflight ping at a time.
    pending: Option<(u32, Instant)>,
    pub(crate) last_rtt: Option<Duration>,
}

impl RttTracker {
    pub(crate) fn new() -> Self;

    /// Generate a ping nonce; records send time.
    /// Returns None if a ping is already inflight.
    pub(crate) fn start_ping(&mut self) -> Option<u32>;

    /// Call when Ping+ACK received with matching nonce.
    /// Returns measured RTT.
    pub(crate) fn record_pong(&mut self, nonce: u32) -> Option<Duration>;
}
```

Replaces the current `KEEPALIVE_INTERVAL_SECS` fire-and-forget with proper
round-trip tracking. The session driver feeds RTT samples into `FlowControl`.

### `src/closing.rs`

```rust
/// 4-phase graceful shutdown state machine (mirrors yamux `closing.rs`).
/// Tracks whether we sent GoAway, whether peer sent GoAway,
/// and whether all streams have been flushed.
pub(crate) struct ClosingState {
    local_goaway_sent: bool,
    remote_goaway_received: bool,
    active_stream_count: usize,
}

impl ClosingState {
    pub(crate) fn new() -> Self;
    pub(crate) fn send_goaway(&mut self);
    pub(crate) fn recv_goaway(&mut self);
    pub(crate) fn stream_opened(&mut self);
    pub(crate) fn stream_closed(&mut self);
    /// True when shutdown is complete (both sides agreed + no active streams).
    pub(crate) fn is_done(&self) -> bool;
    /// True when we must refuse new outbound stream opens.
    pub(crate) fn reject_new_streams(&self) -> bool;
}
```

### `src/chunks.rs`

```rust
use bytes::Bytes;
use std::collections::VecDeque;

/// Receive buffer for a single stream.
/// VecDeque<Bytes> avoids copies — same design as yamux `chunks.rs`.
pub(crate) struct RecvBuffer {
    chunks: VecDeque<Bytes>,
    total: usize,
}

impl RecvBuffer {
    pub(crate) fn new() -> Self;
    pub(crate) fn push(&mut self, data: Bytes);
    /// Copy up to `buf.len()` bytes into buf, return bytes written.
    pub(crate) fn read_into(&mut self, buf: &mut tokio::io::ReadBuf<'_>) -> usize;
    pub(crate) fn is_empty(&self) -> bool;
    pub(crate) fn len(&self) -> usize;
}
```

Replaces the current `partial: Option<Bytes>` in `MuxStream` with a proper
multi-chunk queue. Avoids the partial-slice complexity in `poll_read`.

### `src/frame_io.rs`

```rust
use tokio::io::{AsyncRead, AsyncWrite};
use crate::frame::{Frame, Header, HEADER_LEN};
use crate::error::Result;

/// Cancel-safe async frame reader (poll-based state machine).
/// Mirrors yamux `frame/io.rs` — no heap alloc per frame.
pub(crate) struct FrameReader<R> {
    inner: R,
    header_buf: [u8; HEADER_LEN],
    header_read: usize,
    body_buf: Vec<u8>,   // reused across calls; resized lazily
    body_read: usize,
    state: ReaderState,
}

#[derive(PartialEq)]
enum ReaderState { Header, Body(u32), Done }

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub(crate) fn new(inner: R) -> Self;

    /// Returns Poll::Ready(Ok(Frame)) when one full frame is available.
    /// Cancel-safe: partial reads survive task cancellation.
    pub(crate) fn poll_read_frame(
        &mut self,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<Frame>>;
}

/// Batching frame writer.
pub(crate) struct FrameWriter<W> {
    inner: W,
}

impl<W: AsyncWrite + Unpin> FrameWriter<W> {
    pub(crate) fn new(inner: W) -> Self;

    /// Write header + payload without flushing.
    pub(crate) async fn write_frame(&mut self, frame: &Frame) -> Result<()>;
    pub(crate) async fn flush(&mut self) -> Result<()>;
}
```

This is the key correctness fix: current `read_loop` uses
`rd.read_exact(&mut hdr_buf).await` which is NOT cancel-safe inside
`tokio::select!`. `FrameReader` stores intermediate state so partial reads
survive select cancellation.

### `src/session.rs` (rewrite)

```rust
pub(crate) struct SessionConfig {
    pub(crate) max_streams: u32,          // default 64
    pub(crate) write_channel_size: usize, // default 1024
    pub(crate) accept_channel_size: usize,// default 64
    pub(crate) keepalive_interval: std::time::Duration, // default 15s
    pub(crate) max_frame_payload: usize,  // default 64 KiB
}

struct StreamEntry {
    recv_buf_tx: tokio::sync::mpsc::Sender<bytes::Bytes>,
    recv_window: FlowControl,      // recv-side, drives WindowUpdate
    send_window: Arc<AtomicU32>,   // send-side, decremented by MuxStream
    send_notify: Arc<Notify>,      // wake MuxStream.poll_write on window grant
    fin_received: bool,
}

struct SessionShared {
    streams:  HashMap<u32, StreamEntry, nohash_hasher::BuildNoHashHasher<u32>>,
    next_id:  u32,
    closing:  ClosingState,
}
```

The `HashMap` key is `u32` so we want `nohash_hasher` if we add it, OR just use
`std::collections::HashMap` with default hasher — acceptable for ≤64 streams.
**Decision**: keep `std::collections::HashMap` (no new dep, ≤64 streams).

The read/write split follows yamux's pattern: one task owns the reader, one owns
the writer, they communicate via an `mpsc` of `WriteCmd`. The writer task is the
single serialisation point for the transport — no mutex held across `.await`.

Key improvements over current impl:

1. **Cancel-safe read loop** via `FrameReader::poll_read_frame` in a
   `tokio::select!` with a keepalive ticker.
2. **RTT-driven keepalive** — `RttTracker::start_ping` generates nonces;
   `record_pong` feeds `FlowControl::update_rtt`.
3. **Backpressure on recv** — `StreamEntry.recv_buf_tx` is bounded; when full,
   read loop yields `Poll::Pending` (push-back) instead of dropping frames.
4. **Proper GoAway** — `ClosingState` tracks 4-phase shutdown; session only
   resolves `accept_stream` with an error after `is_done()`.
5. **MAX_STREAMS error** — `MuxError::MaxStreams` preserved for `mux_pool.rs`.

```rust
pub struct MuxSession {
    write_tx:  tokio::sync::mpsc::Sender<WriteCmd>,
    accept_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<MuxStream>>,
    closed:    Arc<AtomicBool>,
    // shared only needed for open_stream; read loop owns SessionShared exclusively
    shared:    Arc<tokio::sync::Mutex<SessionShared>>,
}
```

`open_stream` locks `shared`, inserts `StreamEntry`, sends `WriteCmd::Syn`.
Read loop locks `shared` only to insert/remove `StreamEntry` records (never
across `.await` on network I/O).

### `src/stream.rs` (rewrite)

```rust
pub struct MuxStream {
    pub(crate) id:          u32,
    recv_buf_rx:             tokio::sync::mpsc::Receiver<bytes::Bytes>,
    recv_buf:                RecvBuffer,    // local drain buffer
    write_tx:                tokio::sync::mpsc::Sender<WriteCmd>,
    send_window:             Arc<AtomicU32>,
    send_notify:             Arc<Notify>,
    write_state:             WriteState,
    fin_sent:                bool,
}

enum WriteState {
    Idle,
    /// Waiting for send window > 0.
    WaitWindow,
    /// Waiting for write channel capacity.
    WaitChannel { payload: bytes::Bytes },
}
```

Key improvement: `WriteState::WaitChannel` stores the payload so it is NOT
dropped and rebuilt on retry. Current impl drops the payload and relies on the
caller rebuilding the slice — this can cause writes to report `Ok(n)` but
silently lose data when the channel is full.

`poll_write` transitions:
1. `Idle` → check window → if 0, register waker via `send_notify.notified()` → `WaitWindow`
2. `Idle` → window > 0 → `write_tx.try_send` → if `Full`, store payload → `WaitChannel`
3. `WaitWindow` → woken by notify → re-enter as `Idle`
4. `WaitChannel` → woken by channel capacity → retry `try_send` with stored payload

`poll_shutdown` sends `WriteCmd::Fin`, sets `fin_sent = true`.
`Drop` sends `WriteCmd::Fin` via `try_send` if `!fin_sent`.

`poll_read` drains `recv_buf` first (via `RecvBuffer::read_into`); if empty,
polls `recv_buf_rx.poll_recv`. EOF = channel closed = `Poll::Ready(Ok(()))`.

### `src/error.rs` (additive changes only)

```rust
#[derive(Debug, thiserror::Error)]
pub enum MuxError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol: {0}")]
    Protocol(String),

    #[error("stream {0} reset by peer")]
    StreamReset(u32),

    #[error("session closed")]
    SessionClosed,

    #[error("max streams reached")]
    MaxStreams,

    // NEW — used internally, surfaced on accept_stream after GoAway
    #[error("remote sent GoAway (code {0})")]
    GoAway(u32),

    // NEW — ping timeout
    #[error("keepalive timeout")]
    Timeout,
}
```

`mux_pool.rs` matches on `MuxError::SessionClosed | MuxError::MaxStreams` — both
variants are preserved with identical names.

---

## Cargo.toml Changes

Current deps are sufficient. `rand` is NOT needed — `RttTracker` uses a simple
wrapping counter for ping nonces (`u32` increment, same as current keepalive
counter). No new dependencies required.

```toml
[dependencies]
tokio  = { workspace = true }   # unchanged
bytes  = { workspace = true }   # unchanged
thiserror = { workspace = true } # unchanged
tracing   = { workspace = true } # unchanged
# rand: NOT needed (counter-based ping nonces)
# parking_lot: NOT needed (tokio::sync)
# web-time: NOT needed (std::time::Instant)
# nohash-hasher: NOT needed (≤64 streams, std HashMap fine)
# futures: NOT needed (manual poll, no futures::Stream/Sink)
```

---

## Implementation Steps

### Step 1 — `src/chunks.rs` (new, no deps on other new files)

`RecvBuffer` backed by `VecDeque<Bytes>`. Methods: `push`, `read_into`,
`is_empty`, `len`. No unsafe. Tests in `#[cfg(test)] mod tests`.

### Step 2 — `src/flow_control.rs` (replaces `window.rs`)

Export same constants: `INITIAL_WINDOW`, `MAX_FRAME_PAYLOAD` (keep in lib.rs
re-exports via `pub use flow_control::{INITIAL_WINDOW, MAX_FRAME_PAYLOAD}`).
Implement `FlowControl::consume` with threshold-based ack (same as current
`WindowTracker`) as the base, plus `update_rtt` stub (no-op until RTT is known,
BDP expansion is additive correctness improvement).

### Step 3 — `src/rtt.rs` (new)

`RttTracker` with `start_ping`/`record_pong`. Uses `std::time::Instant`.

### Step 4 — `src/closing.rs` (new)

`ClosingState` 4-phase machine. Pure state, no I/O.

### Step 5 — `src/frame_io.rs` (new)

`FrameReader` poll-based cancel-safe state machine. `FrameWriter` with `write_frame` + `flush`.
Test: feed a `tokio::io::duplex` pair, verify header+body round-trip.

### Step 6 — `src/error.rs` (additive)

Add `GoAway(u32)` and `Timeout` variants. Existing variants untouched.

### Step 7 — `src/stream.rs` (rewrite)

Introduce `RecvBuffer` field, `WriteState` enum. Fix `WaitChannel` payload
retention bug. Keep `poll_shutdown` + `Drop` sending FIN. Keep `id()` method.
All current field names that are pub(crate) in session.rs stay compatible.

### Step 8 — `src/session.rs` (rewrite)

Introduce `SessionShared`, `SessionConfig`, `RttTracker`, `ClosingState`.
Replace `read_loop` with `FrameReader`-based loop inside `tokio::select!` with
keepalive arm. Replace keepalive task with integrated ping inside read task.
Read task owns `FrameReader`; write task owns `FrameWriter`. Session struct
fields unchanged externally.

### Step 9 — `src/lib.rs`

Add `mod flow_control; mod rtt; mod closing; mod chunks; mod frame_io;`.
Replace `pub use window::` with `pub use flow_control::`.
Remove `mod window;`.

### Step 10 — `src/window.rs` DELETE

After step 9 compiles, delete `window.rs`.

---

## Migration Approach

This is an in-place swap: same crate name, same public types, same Cargo.toml
package name. No consumer crate needs changes. Migration is complete when
`cargo check` passes for:
- `mirage2web/crates/mirage-mux`
- `mirage2web/crates/mirage-client-core`
- `mirage2web/crates/mirage-node`

---

## Critical Bug Fixes Delivered by This Rewrite

| # | Current bug | Fix |
|---|-------------|-----|
| A | `read_exact` not cancel-safe in `select!` | `FrameReader` stores partial-read state |
| B | `try_send` drops payload then reports `Poll::Pending` but payload is lost, caller's `buf` may be gone | `WriteState::WaitChannel` retains `Bytes` clone until sent |
| C | Keepalive has no RTT feedback — window stays fixed even on fast links | `RttTracker` + `FlowControl::update_rtt` BDP expansion |
| D | GoAway clears all streams immediately with no drain | `ClosingState::reject_new_streams` + stream count tracking |
| E | Single global `Mutex<SessionInner>` held across data delivery to stream channels | Read task owns streams map exclusively; `Mutex` only for `open_stream` handoff |

---

## Testing Plan

All tests stay inside source files under `#[cfg(test)] mod tests`.

- `chunks.rs` — push multi-chunk, partial read, exact read, over-read
- `flow_control.rs` — consume below threshold (None), crossing threshold (Some), RTT update changes next threshold
- `rtt.rs` — start_ping returns nonce, record_pong returns duration, duplicate pong returns None
- `closing.rs` — state transitions: send_goaway → reject_new_streams true, recv_goaway + 0 streams → is_done true
- `frame_io.rs` — round-trip frame over duplex, partial write survives, unknown frame type returns Err
- `session.rs` integration — `tokio::io::duplex(1MB)`, client sends SYN + data, server accept_stream + read; concurrent 10 streams; GoAway closes session

---

## Estimated Complexity: Medium

5 new files (chunks, flow_control, rtt, closing, frame_io) are small and
independent. 2 rewrites (session, stream) are the bulk of the work. No new
dependencies. Public API is frozen — zero consumer changes needed.
