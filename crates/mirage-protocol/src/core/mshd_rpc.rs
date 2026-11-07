//! Typed RPC channel (exec + file put/get) carried INSIDE the existing
//! signed nested-V9 E2E tunnel (see [`crate::core::mshd_e2e`]).
//!
//! This module owns only the WIRE SHAPE: the `McpRequest`/`McpResponse`
//! frame types and the length-prefixed framing helpers that read/write them
//! over a [`Tunnel`]. It does NOT open a new handshake, a new relay frame
//! kind, a new listener, or a new port — [`mshd_accept_session`] /
//! [`opbox_open_session`] (unchanged) already hand back an authenticated,
//! forward-secret [`crate::core::tunnel::MirageCoreTunnel`]; this protocol
//! rides inside it as a payload convention, selected by a one-byte opener
//! the caller writes first (`mirage_mshd`'s `RPC_OPENER` const — owned by
//! the mshd crate, not duplicated here). The default (any other first
//! byte) is the pre-existing interactive shell — `RPC_OPENER` is the ONE
//! marked exception, not a mode byte every caller must send.
//!
//! ## Framing
//!
//! The `Tunnel` trait (`traits.rs`) is a plain ordered byte stream, not
//! message-preserving — [`MirageCoreTunnel::send`] fragments anything over
//! `MAX_FRAME_PAYLOAD` transparently and `recv()` just yields stream bytes.
//! So every frame on this channel is `[len: u32 LE][json payload]`, with
//! `len` bounded by [`MSHD_RPC_MAX_FRAME`] so a corrupt/malicious length
//! prefix can never trigger an unbounded allocation.
//!
//! ## Sequencing (v1)
//!
//! `req_id` exists for future multiplexing only. This version processes
//! one request to completion (including every wire frame of a multi-chunk
//! `Put`/`Get`) before the next frame is read — no concurrent in-flight
//! ops on one session. A caller that needs parallelism opens a second E2E
//! session (already supported, `MAX_E2E_SESSIONS` per control-WS
//! connection).

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::traits::Tunnel;

// ─────────────────────────────────────────────────────────────────────────────
// Wire limits
// ─────────────────────────────────────────────────────────────────────────────

/// Upper bound on a single frame's JSON body length. Comfortably above any
/// single `McpRequest`/`McpResponse` envelope (chunks carry at most
/// [`MSHD_RPC_CHUNK_SIZE`] of payload, base64'd ~1.34× -> ~43 KiB) while
/// still rejecting a corrupt/malicious length prefix before any allocation
/// happens.
pub const MSHD_RPC_MAX_FRAME: u32 = 1024 * 1024; // 1 MiB

/// Plaintext bytes per `PutChunk`/`GetChunk`. Matches `ssh.rs`'s existing
/// `CHUNK` constant for continuity, and stays safely under the tunnel's
/// `MAX_FRAME_PAYLOAD` (60 KiB) once base64'd (~43 KiB), so each chunk maps
/// to roughly one AEAD frame instead of being split further by the wire.
pub const MSHD_RPC_CHUNK_SIZE: usize = 32 * 1024;

/// Number of bytes in the little-endian length prefix.
const MSHD_RPC_LEN_BYTES: usize = 4;

// ─────────────────────────────────────────────────────────────────────────────
// Wire types
// ─────────────────────────────────────────────────────────────────────────────

/// One request on the mshd RPC channel.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum McpRequest {
    /// Run `argv[0]` with `argv[1..]` as literal arguments — NEVER a shell
    /// string. Callers that need shell semantics pass
    /// `argv=["sh","-c",script]` explicitly.
    Exec {
        req_id: u32,
        argv: Vec<String>,
        env: Vec<(String, String)>,
        cwd: Option<String>,
        #[serde(with = "mirage_core::b64_serde::b64_opt")]
        stdin: Option<Vec<u8>>,
    },
    /// Begin a file upload. `blake3_hex` is the whole-file hash computed
    /// opbox-side BEFORE any bytes are sent — the receiver verifies it once
    /// `PutFinish` arrives, never before (streaming, not buffered).
    Put {
        req_id: u32,
        path: String,
        mode: u32,
        total_len: u64,
        blake3_hex: String,
    },
    /// One chunk of an in-progress `Put`. `offset` is the byte offset this
    /// chunk starts at (informational for v1 — chunks arrive in order over
    /// the ordered tunnel stream; the receiver may still use it to detect
    /// an out-of-order/duplicate chunk as a protocol error).
    PutChunk {
        req_id: u32,
        offset: u64,
        #[serde(with = "mirage_core::b64_serde::b64_vec")]
        data: Vec<u8>,
    },
    /// All chunks sent — verify + finalize the upload.
    PutFinish { req_id: u32 },
    /// Begin a file download.
    Get { req_id: u32, path: String },
    /// Client-side keepalive. Carries no work and gets no response — its only
    /// job is to put bytes on the wire while the client waits.
    ///
    /// Every layer under this protocol reaps a connection that has been quiet
    /// for 60s, and each of those bounds was written for the mesh-gossip
    /// pattern: open a tunnel, send a batch, get an answer, all sub-second. A
    /// `Put` breaks that assumption — the client writes every chunk, then goes
    /// silent until the box has hashed and renamed the file. Measured
    /// 2026-08-02: a 5.7 MB binary reached 5,734,400 of 5,760,192 bytes and
    /// died as "session closed by peer", deterministically, on every box slow
    /// enough that the tail crossed one of those windows.
    ///
    /// The keepalive is sent by the WAITING side because that is the direction
    /// that goes quiet — a server-side progress frame would not reset the
    /// inbound-idle timers that actually fire.
    Noop { req_id: u32 },
    /// Ask the co-located perimeter a typed question and relay its typed
    /// answer back.
    ///
    /// This exists so the operator's read of the front door's counters is a
    /// STRUCTURE the whole way — perimeter → unix socket → mshd → wire →
    /// opbox — instead of what it replaced: an `Exec` of
    /// `curl -sS http://127.0.0.1:19470/perimeter/stats`, whose response
    /// opbox re-derived from JSON into its own second copy of the perimeter's
    /// counter structs. Those copies drifted, in both directions, and one of
    /// the drifts silently hid 1483 routed connections.
    ///
    /// It is a distinct op rather than a convention on top of `Exec` because
    /// the point is that no shell, no HTTP client and no second struct
    /// definition sit anywhere on the path. mshd holds the only thing that
    /// can reach the socket (`SO_PEERCRED` admits root) and is otherwise a
    /// pipe: it does not read, summarise or act on what it relays.
    PerimeterQuery {
        req_id: u32,
        query: mirage_core::perimeter_query::PerimeterRequest,
    },
    /// Politely end the session (the receiver tears down; equivalent to
    /// the outer relay's `e2e_close` but expressed inside this protocol).
    EndSession,
}

/// One response on the mshd RPC channel.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum McpResponse {
    /// One chunk of an `Exec`'s stdout (`stderr: false`) or stderr
    /// (`stderr: true`).
    ExecOutput {
        req_id: u32,
        stderr: bool,
        #[serde(with = "mirage_core::b64_serde::b64_vec")]
        chunk: Vec<u8>,
    },
    /// Terminal frame for an `Exec` — no more `ExecOutput` follows.
    ExecExit { req_id: u32, code: Option<i32> },
    /// Terminal frame for a successful `Put`.
    PutDone { req_id: u32, blake3_hex: String },
    /// Sent FIRST for a `Get`, before any `GetChunk` — mirrors `Put`'s
    /// manifest-first shape so the caller can pre-size a buffer and fail
    /// fast on a missing/oversized file.
    GetManifest {
        req_id: u32,
        total_len: u64,
        blake3_hex: String,
    },
    /// One chunk of a `Get`'s file content; the last one has `eof: true`.
    GetChunk {
        req_id: u32,
        offset: u64,
        #[serde(with = "mirage_core::b64_serde::b64_vec")]
        data: Vec<u8>,
        eof: bool,
    },
    /// Terminal frame for a [`McpRequest::PerimeterQuery`] — the perimeter's
    /// own answer, relayed unaltered.
    PerimeterAnswer {
        req_id: u32,
        answer: mirage_core::perimeter_query::PerimeterResponse,
    },
    /// An application-level failure for `req_id` (bad hash, missing file,
    /// empty argv, protocol misuse). Does not by itself close the session —
    /// the caller may issue another request.
    Error { req_id: u32, message: String },
}

// ─────────────────────────────────────────────────────────────────────────────
// Error type
// ─────────────────────────────────────────────────────────────────────────────

/// Errors from the mshd RPC framing layer. Mirrors
/// [`mirage_core::error::MirageError`]'s shape.
#[derive(Debug, thiserror::Error)]
pub enum McpError {
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("frame length {0} exceeds MSHD_RPC_MAX_FRAME ({1})")]
    FrameTooLarge(u32, u32),
    #[error("tunnel error: {0}")]
    Tunnel(#[from] mirage_core::error::MirageError),
    #[error("idle timeout after {0}s with no new frame")]
    IdleTimeout(u64),
    #[error("wall-clock session deadline exceeded")]
    WallTimeout,
}

// ─────────────────────────────────────────────────────────────────────────────
// Framing
// ─────────────────────────────────────────────────────────────────────────────

/// Serialise `frame` to JSON and write `[len: u32 LE][json]` through
/// `tunnel`.
pub async fn write_mcp_frame<T, F>(tunnel: &mut T, frame: &F) -> Result<(), McpError>
where
    T: Tunnel + ?Sized,
    F: Serialize,
{
    let body =
        serde_json::to_vec(frame).map_err(|e| McpError::Protocol(format!("json encode: {e}")))?;
    if body.len() as u64 > MSHD_RPC_MAX_FRAME as u64 {
        return Err(McpError::FrameTooLarge(body.len() as u32, MSHD_RPC_MAX_FRAME));
    }
    let len = (body.len() as u32).to_le_bytes();
    tunnel.send(&len).await?;
    tunnel.send(&body).await?;
    Ok(())
}

/// Read one `[len: u32 LE][json]` frame from `tunnel` and decode it as `F`.
///
/// `idle_secs` bounds each individual read step (reset on every partial
/// read, mirroring `run_e2e_shell`'s idle timer); `wall_deadline` is an
/// absolute cap shared across the whole session (computed once by the
/// caller at session start).
///
/// Returns `Ok(None)` on a clean EOF that arrived before any byte of a new
/// frame was read (a legitimate end of session) — never on an EOF that
/// interrupts a frame already in progress, which is an error.
pub async fn read_mcp_frame<T, F>(
    tunnel: &mut T,
    idle_secs: u64,
    wall_deadline: tokio::time::Instant,
) -> Result<Option<F>, McpError>
where
    T: Tunnel + ?Sized,
    F: DeserializeOwned,
{
    let mut len_buf = [0u8; MSHD_RPC_LEN_BYTES];
    if !read_exact_timed(tunnel, &mut len_buf, idle_secs, wall_deadline).await? {
        return Ok(None);
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MSHD_RPC_MAX_FRAME {
        return Err(McpError::FrameTooLarge(len, MSHD_RPC_MAX_FRAME));
    }

    let mut body = vec![0u8; len as usize];
    if !read_exact_timed(tunnel, &mut body, idle_secs, wall_deadline).await? {
        return Err(McpError::Protocol("eof mid-frame body".to_string()));
    }

    let frame = serde_json::from_slice(&body)
        .map_err(|e| McpError::Protocol(format!("json decode: {e}")))?;
    Ok(Some(frame))
}

/// [`read_mcp_frame`], but emitting `keepalive` whenever the wait between
/// frames exceeds `keepalive_every`.
///
/// The keepalive is written ONLY at a frame boundary, with zero bytes of the
/// next frame consumed. That restriction is the whole reason this is a
/// separate function rather than a flag on `read_mcp_frame`: the idle path in
/// [`read_exact_timed`] can fire with a partially filled buffer, and those
/// bytes are gone when it returns — resuming the read after writing something
/// would resync the stream onto the middle of a frame. Here the first byte is
/// awaited on its own; until it arrives nothing has been consumed and writing
/// is safe, and once it arrives the rest of the frame is read under the
/// ordinary idle bound with no interruption.
pub async fn read_mcp_frame_with_keepalive<T, F, K>(
    tunnel: &mut T,
    idle_secs: u64,
    wall_deadline: tokio::time::Instant,
    keepalive_every: std::time::Duration,
    keepalive: &K,
) -> Result<Option<F>, McpError>
where
    T: Tunnel + ?Sized,
    F: DeserializeOwned,
    K: Serialize,
{
    let mut len_buf = [0u8; MSHD_RPC_LEN_BYTES];
    loop {
        if tokio::time::Instant::now() >= wall_deadline {
            return Err(McpError::WallTimeout);
        }
        match tokio::time::timeout(keepalive_every, tunnel.recv(&mut len_buf[..1])).await {
            Ok(Ok(0)) => return Ok(None),
            Ok(Ok(_)) => break,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => {
                write_mcp_frame(tunnel, keepalive).await?;
            }
        }
    }

    // First byte in hand — finish the length prefix, then the body, under the
    // caller's normal idle bound.
    if !read_exact_timed(tunnel, &mut len_buf[1..], idle_secs, wall_deadline).await? {
        return Err(McpError::Protocol("eof mid-length-prefix".to_string()));
    }
    let len = u32::from_le_bytes(len_buf);
    if len > MSHD_RPC_MAX_FRAME {
        return Err(McpError::FrameTooLarge(len, MSHD_RPC_MAX_FRAME));
    }
    let mut body = vec![0u8; len as usize];
    if !read_exact_timed(tunnel, &mut body, idle_secs, wall_deadline).await? {
        return Err(McpError::Protocol("eof mid-frame body".to_string()));
    }
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|e| McpError::Protocol(format!("json decode: {e}")))
}

/// Fill `buf` completely, resetting the idle timer on every partial read.
///
/// Returns `Ok(true)` once `buf` is full, `Ok(false)` on a clean EOF that
/// arrived before any byte of THIS read was consumed, and `Err` on a
/// mid-read EOF, tunnel error, idle timeout, or wall-clock deadline.
async fn read_exact_timed<T>(
    tunnel: &mut T,
    buf: &mut [u8],
    idle_secs: u64,
    wall_deadline: tokio::time::Instant,
) -> Result<bool, McpError>
where
    T: Tunnel + ?Sized,
{
    let mut filled = 0usize;
    while filled < buf.len() {
        tokio::select! {
            _ = tokio::time::sleep_until(wall_deadline) => {
                return Err(McpError::WallTimeout);
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(idle_secs)) => {
                return Err(McpError::IdleTimeout(idle_secs));
            }
            recv_result = tunnel.recv(&mut buf[filled..]) => {
                match recv_result {
                    Ok(0) if filled == 0 => return Ok(false),
                    Ok(0) => return Err(McpError::Protocol("eof mid-read".to_string())),
                    Ok(n) => filled += n,
                    Err(e) => return Err(McpError::Tunnel(e)),
                }
            }
        }
    }
    Ok(true)
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Unit: JSON wire-shape round trips ────────────────────────────────────

    #[test]
    fn exec_request_round_trip() {
        let req = McpRequest::Exec {
            req_id: 7,
            argv: vec!["echo".to_string(), "hi".to_string()],
            env: vec![("FOO".to_string(), "bar".to_string())],
            cwd: Some("/tmp".to_string()),
            stdin: Some(b"hello".to_vec()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let back: McpRequest = serde_json::from_str(&json).unwrap();
        match back {
            McpRequest::Exec { req_id, argv, env, cwd, stdin } => {
                assert_eq!(req_id, 7);
                assert_eq!(argv, vec!["echo".to_string(), "hi".to_string()]);
                assert_eq!(env, vec![("FOO".to_string(), "bar".to_string())]);
                assert_eq!(cwd.as_deref(), Some("/tmp"));
                assert_eq!(stdin, Some(b"hello".to_vec()));
            }
            other => panic!("expected Exec, got {other:?}"),
        }
    }

    #[test]
    fn exec_request_no_stdin_round_trip() {
        let req = McpRequest::Exec {
            req_id: 1,
            argv: vec!["true".to_string()],
            env: vec![],
            cwd: None,
            stdin: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"stdin\":null"));
        let back: McpRequest = serde_json::from_str(&json).unwrap();
        match back {
            McpRequest::Exec { stdin, .. } => assert_eq!(stdin, None),
            other => panic!("expected Exec, got {other:?}"),
        }
    }

    #[test]
    fn put_chunk_wire_shape_is_base64_not_number_array() {
        let chunk = McpRequest::PutChunk { req_id: 1, offset: 64, data: vec![1, 2, 3] };
        let json = serde_json::to_string(&chunk).unwrap();
        assert!(json.contains("\"op\":\"put_chunk\""));
        assert!(json.contains("\"data\":\"AQID\""));
        let back: McpRequest = serde_json::from_str(&json).unwrap();
        match back {
            McpRequest::PutChunk { req_id, offset, data } => {
                assert_eq!(req_id, 1);
                assert_eq!(offset, 64);
                assert_eq!(data, vec![1, 2, 3]);
            }
            other => panic!("expected PutChunk, got {other:?}"),
        }
    }

    #[test]
    fn end_session_wire_shape() {
        let json = serde_json::to_string(&McpRequest::EndSession).unwrap();
        assert_eq!(json, r#"{"op":"end_session"}"#);
    }

    #[test]
    fn get_chunk_response_round_trip() {
        let resp = McpResponse::GetChunk { req_id: 3, offset: 64, data: vec![9, 9, 9], eof: true };
        let json = serde_json::to_string(&resp).unwrap();
        let back: McpResponse = serde_json::from_str(&json).unwrap();
        match back {
            McpResponse::GetChunk { req_id, offset, data, eof } => {
                assert_eq!(req_id, 3);
                assert_eq!(offset, 64);
                assert_eq!(data, vec![9, 9, 9]);
                assert!(eof);
            }
            other => panic!("expected GetChunk, got {other:?}"),
        }
    }

    #[test]
    fn error_response_wire_shape() {
        let e = McpResponse::Error { req_id: 5, message: "boom".to_string() };
        let json = serde_json::to_string(&e).unwrap();
        assert_eq!(json, r#"{"op":"error","req_id":5,"message":"boom"}"#);
    }

    // ── Integration: length-prefixed framing over a real E2E tunnel ─────────
    //
    // Mirrors `mshd_e2e.rs::e2e_round_trip` — real V9 handshake over an
    // in-process `tokio::io::duplex`, then this module's frame helpers ride
    // the resulting tunnel.

    fn seed_key(seed: u8) -> [u8; 32] {
        [seed; 32]
    }

    fn pub_from_priv(priv_bytes: [u8; 32]) -> [u8; 32] {
        mirage_core::crypto::KeyPair::from_secret(priv_bytes).public.to_bytes()
    }

    async fn open_e2e_pair() -> (
        crate::core::tunnel::MirageCoreTunnel<tokio::io::DuplexStream>,
        crate::core::tunnel::MirageCoreTunnel<tokio::io::DuplexStream>,
    ) {
        let op_priv = seed_key(0x01);
        let op_pub = pub_from_priv(op_priv);
        let mshd_priv = seed_key(0x02);
        let mshd_pub = pub_from_priv(mshd_priv);

        let (client_half, server_half) = tokio::io::duplex(1 << 16);
        let server_task = tokio::spawn(async move {
            crate::core::mshd_e2e::mshd_accept_session(server_half, mshd_priv, op_pub).await
        });
        let client_task = tokio::spawn(async move {
            crate::core::mshd_e2e::opbox_open_session(client_half, mshd_pub, op_priv).await
        });
        let (server_res, client_res) = tokio::join!(server_task, client_task);
        (
            client_res.unwrap().expect("client tunnel must open"),
            server_res.unwrap().expect("server tunnel must open"),
        )
    }

    fn far_wall_deadline() -> tokio::time::Instant {
        tokio::time::Instant::now() + std::time::Duration::from_secs(30)
    }

    #[tokio::test]
    async fn mcp_frame_round_trip_over_e2e_tunnel() {
        let (mut client_tunnel, mut server_tunnel) = open_e2e_pair().await;
        let wall = far_wall_deadline();

        let req = McpRequest::Get { req_id: 42, path: "/tmp/x".to_string() };
        write_mcp_frame(&mut client_tunnel, &req).await.unwrap();
        let got: McpRequest = read_mcp_frame(&mut server_tunnel, 5, wall)
            .await
            .unwrap()
            .expect("frame must decode");
        match got {
            McpRequest::Get { req_id, path } => {
                assert_eq!(req_id, 42);
                assert_eq!(path, "/tmp/x");
            }
            other => panic!("expected Get, got {other:?}"),
        }

        let resp = McpResponse::Error { req_id: 42, message: "nope".to_string() };
        write_mcp_frame(&mut server_tunnel, &resp).await.unwrap();
        let got: McpResponse = read_mcp_frame(&mut client_tunnel, 5, wall)
            .await
            .unwrap()
            .expect("frame must decode");
        match got {
            McpResponse::Error { req_id, message } => {
                assert_eq!(req_id, 42);
                assert_eq!(message, "nope");
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn mcp_frame_clean_eof_yields_none() {
        let (client_tunnel, mut server_tunnel) = open_e2e_pair().await;
        drop(client_tunnel); // closes the underlying duplex from the client side
        let wall = far_wall_deadline();
        let got: Option<McpRequest> = read_mcp_frame(&mut server_tunnel, 5, wall).await.unwrap();
        assert!(got.is_none(), "clean peer close before a new frame must yield Ok(None), not an error");
    }

    #[tokio::test]
    async fn oversized_length_prefix_rejected_without_allocating() {
        let (mut client_tunnel, mut server_tunnel) = open_e2e_pair().await;
        let wall = far_wall_deadline();

        // Write a raw oversized length prefix directly (bypassing
        // `write_mcp_frame`, which itself would refuse to build this) —
        // simulates a corrupt/malicious peer.
        let bad_len = (MSHD_RPC_MAX_FRAME + 1).to_le_bytes();
        client_tunnel.send(&bad_len).await.unwrap();

        let result = read_mcp_frame::<_, McpRequest>(&mut server_tunnel, 5, wall).await;
        match result {
            Err(McpError::FrameTooLarge(got, max)) => {
                assert_eq!(got, MSHD_RPC_MAX_FRAME + 1);
                assert_eq!(max, MSHD_RPC_MAX_FRAME);
            }
            other => panic!("expected FrameTooLarge, got {other:?}"),
        }
    }
}
