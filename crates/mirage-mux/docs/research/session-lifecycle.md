# MuxSession Lifecycle — Research

Source files: `crates/mirage-mux/src/session.rs`, `frame.rs`, `stream.rs`, `window.rs`

---

## MuxSession::client() — What Happens on Construction

`client(transport)` calls `new(transport, is_client=true)`.

`new()` does:
1. Creates `SessionInner { streams: {}, next_id: 1, closed: false }` (client starts at odd ID 1; server starts at 2).
2. Creates two mpsc channels: `write_tx/write_rx` (capacity 1024) and `accept_tx/accept_rx` (capacity 64).
3. Splits transport into `(rd, wr)` via `tokio::io::split`.
4. **Spawns read_loop task** — reads frames from transport, dispatches to streams, signals new incoming streams on `accept_tx`.
5. **Spawns write_loop task** — drains `write_rx` channel, serializes frames to transport.
6. Returns `MuxSession` immediately.

**No bytes are sent during construction.** The write_loop task is idle until something is pushed into `write_tx`.

---

## MuxSession::server() — Constructor

`server(transport)` calls `new(transport, is_client=false)`.

Identical to client except `next_id = 2` (even stream IDs for server-originated streams).

---

## open_stream() — First Frame Sent by Client

```
open_stream() → WriteCmd::Syn { stream_id } → write_loop → wire
```

Steps:
1. Allocates `stream_id = inner.next_id` (starts at 1, increments by 2 each call → 1, 3, 5, …).
2. Inserts `StreamEntry` into `inner.streams`.
3. Sends `WriteCmd::Syn { stream_id }` to write channel.
4. Returns `MuxStream`.

The SYN is serialized in `write_loop` as a pure 12-byte header frame:

```
byte[0]  = 0x00          // VERSION = 0 (NOT 0x01)
byte[1]  = 0x00          // FrameType::Data = 0
byte[2]  = 0x00          // flags hi byte
byte[3]  = 0x01          // flags lo byte = Flags::SYN (0x0001)
byte[4..8]  = stream_id  // big-endian u32
byte[8..12] = 0x00000000 // length = 0
```

**Total: exactly 12 bytes, no payload.** This is the first — and only — frame sent by the client before any data.

---

## Frame Header Format (12 bytes)

```
offset  size  field
0       1     version     = 0x00  (constant VERSION=0, not 0x01)
1       1     frame_type  (0=Data, 1=WindowUpdate, 2=Ping, 3=GoAway)
2       2     flags       big-endian u16 (SYN=0x0001, ACK=0x0002, FIN=0x0004, RST=0x0008)
4       4     stream_id   big-endian u32
8       4     length      big-endian u32 (payload bytes that follow, only for Data frames)
```

Note: version byte is **0x00**, not 0x01. `decode()` rejects anything other than 0x00.

---

## Session-Level Handshake

**There is none.** No session-level SYN, no capability exchange, no greeting bytes.

The first bytes on the wire from either side only appear when `open_stream()` is called (SYN frame) or when the peer sends data. The session is immediately operational after construction.

---

## Background Tasks

`MuxSession::new()` unconditionally spawns two `tokio::spawn` tasks:

| Task | Function | Lifetime |
|------|----------|----------|
| read_loop | Reads 12-byte headers + optional payload, dispatches to stream channels | Lives until transport EOF, GoAway frame, or IO error |
| write_loop | Drains WriteCmd channel, flushes each frame | Lives until WriteCmd channel closes or GoAway is sent |

Both tasks set `closed = true` on the `Arc<AtomicBool>` when they exit. The read_loop also clears `inner.streams` on exit. Neither task is joinable from outside — fire-and-forget.

---

## Stream ID Allocation

| Side    | First ID | Step | Example sequence |
|---------|----------|------|-----------------|
| client  | 1        | +2   | 1, 3, 5, 7, …  |
| server  | 2        | +2   | 2, 4, 6, 8, …  |

Max concurrent streams per session: **64** (`MAX_STREAMS_PER_SESSION`).

---

## Flow Control (Window)

- Initial send window per stream: **256 KiB** (`INITIAL_WINDOW`).
- Max single frame payload: **64 KiB** (`MAX_FRAME_PAYLOAD`).
- Receiver sends `WindowUpdate` frames back after consuming ≥ **64 KiB** (`WINDOW_ACK_THRESHOLD`).
- `MuxStream::poll_write` blocks (returns `Poll::Pending`) when send window reaches 0.

---

## Frame Types and Wire Sequences

| Event | Frame type | Flags | length |
|-------|-----------|-------|--------|
| open_stream() | Data | SYN | 0 |
| write data | Data | NONE | N |
| stream drop/shutdown | Data | FIN | 0 |
| stream reset | Data | RST | 0 |
| ack received bytes | WindowUpdate | NONE | delta |
| keepalive request | Ping | NONE | opaque |
| keepalive reply | Ping | ACK | opaque |
| close session | GoAway | NONE | 0 |

---

## Key Constants

```rust
MAX_STREAMS_PER_SESSION: u32 = 64
WRITE_CHANNEL_SIZE: usize    = 1024
STREAM_RECV_BUFFER: usize    = 256   // per-stream mpsc capacity
INITIAL_WINDOW: u32          = 262144 (256 KiB)
WINDOW_ACK_THRESHOLD: u32    = 65536  (64 KiB)
MAX_FRAME_PAYLOAD: usize     = 65536  (64 KiB)
```
