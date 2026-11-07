//! One framing for every typed box-local channel: a request goes in, a
//! response comes back, both as Rust values.
//!
//! # Why this is not HTTP
//!
//! HTTP exists to move requests across an untrusted network between parties
//! that share no memory. Methods, headers, status codes and `Content-Length`
//! are what make that work. Between two processes on one kernel, over a
//! socket where `SO_PEERCRED` has already told the receiver which uid is
//! calling ([`crate::local_endpoint`]), every one of those is ceremony —
//! and worse than ceremony, because it forces each consumer to re-derive
//! the response shape from JSON. That is how the perimeter's counters ended
//! up with two struct definitions, one in the producer and one in the
//! operator's reader, kept in step by hand.
//!
//! A daemon here asks a typed question and gets a typed answer. One
//! definition, compiled into producer and consumer; a field renamed breaks
//! the build instead of silently becoming `null` in somebody's parse.
//!
//! # Framing
//!
//! ```text
//! MIRRPC          6 bytes, ASCII magic
//! version         1 byte
//! length          4 bytes, big-endian, <= MAX_RPC_LEN
//! body            the serialised request or response
//! ```
//!
//! This is [`crate::perimeter_preamble`]'s frame with a different magic,
//! generalised so the preamble and every RPC share one reader rather than
//! growing a third encoding. Length-prefixed because a reader must consume
//! exactly one message and not one byte more. Magic because a peer that
//! opens with something else — root dialling the socket by hand, a liveness
//! probe — has to be distinguishable from a malformed message, not guessed
//! at.
//!
//! JSON for the body, deliberately, and it is the one place ceremony is
//! worth paying for: these frames are read by a human during an incident,
//! and `#[serde(default)]` gives an additive field a defined meaning to a
//! peer built before it existed. The framing is what makes the message
//! bounded and self-delimiting; the encoding inside it only has to be
//! legible.
//!
//! # A connection carries as many exchanges as the client wants
//!
//! [`serve_on`] loops: read a request, answer it, read the next, until the
//! peer closes at a frame boundary. A one-shot client ([`call`]) simply
//! closes after one exchange. Nothing here is stateful across frames, so
//! the two shapes cost the same.

use std::io;
use std::sync::Arc;
use std::time::Duration;

use serde::de::DeserializeOwned;
use serde::Serialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::Semaphore;

use crate::local_endpoint::{LocalChannel, LocalListener};

/// ASCII magic opening every frame.
pub const RPC_MAGIC: [u8; 6] = *b"MIRRPC";

/// Framing version. Bump when the frame itself changes — never for an
/// additive field in a body, which `#[serde(default)]` already covers.
pub const RPC_VERSION: u8 = 1;

/// Bytes before the body: magic + version + length.
pub const RPC_HEADER_LEN: usize = RPC_MAGIC.len() + 1 + 4;

/// Upper bound on one body. Generous for every message on these channels
/// (the largest is a whole metrics snapshot) and small enough that a peer
/// cannot make a reader allocate on its say-so.
pub const MAX_RPC_LEN: u32 = 1 << 20;

/// Default bound on a [`call`]. A server that accepts and never answers
/// must still resolve to a verdict: mshd's recovery door decides who owns
/// the box's only port on one of these calls, and "waited forever" is not
/// an answer it can act on.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(3);

/// Concurrent connections one served channel will hold at once.
///
/// Acquired BEFORE `accept`, the same discipline `mirage-perimeter::face`
/// and mshd's SSH doors use: once every permit is held the loop simply stops
/// accepting and the kernel's own backlog absorbs the burst, instead of this
/// process queueing unboundedly. Every peer here is already past
/// `SO_PEERCRED`, so this is backpressure, not defence.
pub const MAX_CONNECTIONS: usize = 32;

// ── Frame ────────────────────────────────────────────────────────────────

/// Serialise a message and put its frame header in front.
pub fn encode<T: Serialize>(msg: &T) -> io::Result<Vec<u8>> {
    let body = serde_json::to_vec(msg)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("encoding a frame: {e}")))?;
    let len = u32::try_from(body.len())
        .ok()
        .filter(|n| *n <= MAX_RPC_LEN)
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                format!("a {}-byte body exceeds the {MAX_RPC_LEN}-byte frame bound", body.len()),
            )
        })?;

    let mut out = Vec::with_capacity(RPC_HEADER_LEN + body.len());
    out.extend_from_slice(&RPC_MAGIC);
    out.push(RPC_VERSION);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse the fixed header, returning the body length still to be read.
///
/// Separate from the I/O so the decision is testable against a slice —
/// callers read from a `LocalStream`, a `TcpStream` or a `Vec`, and none of
/// them should have to hand this module an `AsyncRead` to find out whether
/// a header is well-formed.
pub fn parse_header(header: &[u8; RPC_HEADER_LEN]) -> io::Result<u32> {
    if header[..RPC_MAGIC.len()] != RPC_MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "not a {} frame — the peer opened with {:?}",
                String::from_utf8_lossy(&RPC_MAGIC),
                String::from_utf8_lossy(&header[..RPC_MAGIC.len()])
            ),
        ));
    }
    let version = header[RPC_MAGIC.len()];
    if version != RPC_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("frame version {version} is not readable by this build (expected {RPC_VERSION})"),
        ));
    }
    let mut len_bytes = [0u8; 4];
    len_bytes.copy_from_slice(&header[RPC_MAGIC.len() + 1..]);
    let len = u32::from_be_bytes(len_bytes);
    if len > MAX_RPC_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("declared body length {len} exceeds the {MAX_RPC_LEN}-byte bound"),
        ));
    }
    Ok(len)
}

/// Read one whole frame body, or `None` when the peer closed cleanly at a
/// frame boundary.
///
/// The distinction is load-bearing for [`serve_on`]: a client that has asked
/// everything it wanted and hung up is the normal end of a connection, while
/// a connection that dies four bytes into a header is a fault worth naming.
/// `read_exact` cannot tell those apart — both surface as `UnexpectedEof` —
/// so this fills the header by hand.
pub async fn read_body<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; RPC_HEADER_LEN];
    let mut filled = 0;
    while filled < RPC_HEADER_LEN {
        let n = reader.read(&mut header[filled..]).await?;
        if n == 0 {
            if filled == 0 {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("peer closed {filled} bytes into a {RPC_HEADER_LEN}-byte frame header"),
            ));
        }
        filled += n;
    }

    let len = parse_header(&header)?;
    let mut body = vec![0u8; len as usize];
    reader.read_exact(&mut body).await?;
    Ok(Some(body))
}

/// Read and deserialise one message, or `None` on a clean close.
pub async fn read_frame<R, T>(reader: &mut R) -> io::Result<Option<T>>
where
    R: AsyncRead + Unpin,
    T: DeserializeOwned,
{
    let Some(body) = read_body(reader).await? else {
        return Ok(None);
    };
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, format!("decoding a frame: {e}")))
}

/// Serialise a message and write it as one frame.
pub async fn write_frame<W, T>(writer: &mut W, msg: &T) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    T: Serialize,
{
    let framed = encode(msg)?;
    writer.write_all(&framed).await?;
    writer.flush().await
}

// ── Client ───────────────────────────────────────────────────────────────

/// Ask one question on `channel` and read the answer, bounded by
/// [`DEFAULT_CALL_TIMEOUT`].
pub async fn call<Req, Res>(channel: LocalChannel, req: &Req) -> io::Result<Res>
where
    Req: Serialize,
    Res: DeserializeOwned,
{
    call_with_timeout(channel, req, DEFAULT_CALL_TIMEOUT).await
}

/// [`call`] with an explicit bound. The bound covers the whole exchange —
/// connect, write, read — because a caller cares how long it may be held,
/// not which of the three steps is slow.
pub async fn call_with_timeout<Req, Res>(
    channel: LocalChannel,
    req: &Req,
    bound: Duration,
) -> io::Result<Res>
where
    Req: Serialize,
    Res: DeserializeOwned,
{
    tokio::time::timeout(bound, async {
        let mut stream = channel.connect().await?;
        write_frame(&mut stream, req).await?;
        match read_frame::<_, Res>(&mut stream).await? {
            Some(res) => Ok(res),
            None => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!(
                    "the {} channel closed without answering",
                    channel.label()
                ),
            )),
        }
    })
    .await
    .unwrap_or_else(|_| {
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("no answer on the {} channel within {bound:?}", channel.label()),
        ))
    })
}

// ── Server ───────────────────────────────────────────────────────────────

/// Bind `channel` and answer on it forever.
///
/// Returns `Err` only if the bind itself fails — once bound, a single
/// connection's failure never takes the channel down and one peer's
/// misbehaviour never touches another's.
pub async fn serve<Req, Res, F, Fut>(channel: LocalChannel, handler: F) -> io::Result<()>
where
    Req: DeserializeOwned + Send + 'static,
    // `Sync` because the response is borrowed across the `.await` inside
    // `write_frame`, and the connection task is `tokio::spawn`ed.
    Res: Serialize + Send + Sync + 'static,
    F: Fn(Req) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Res> + Send + 'static,
{
    let listener = channel.bind().await?;
    serve_on(listener, channel.label(), handler).await
}

/// [`serve`] on an already-bound listener. Exists so a test can serve a
/// scratch path — every fleet caller wants [`serve`].
pub async fn serve_on<Req, Res, F, Fut>(
    listener: LocalListener,
    label: &'static str,
    handler: F,
) -> io::Result<()>
where
    Req: DeserializeOwned + Send + 'static,
    // `Sync` because the response is borrowed across the `.await` inside
    // `write_frame`, and the connection task is `tokio::spawn`ed.
    Res: Serialize + Send + Sync + 'static,
    F: Fn(Req) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = Res> + Send + 'static,
{
    let handler = Arc::new(handler);
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));

    tracing::info!(
        channel = label,
        endpoint = %listener.endpoint(),
        admitted_uids = ?listener.admitted_uids(),
        "[local-rpc] serving a typed box-local channel"
    );

    loop {
        // Acquire BEFORE accept — see MAX_CONNECTIONS.
        let Ok(permit) = Arc::clone(&connections).acquire_owned().await else {
            // Nothing in this module ever closes the semaphore; a closed
            // error would be a logic bug elsewhere, not a condition to
            // recover from.
            return Ok(());
        };

        let (mut stream, peer) = match listener.accept().await {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(channel = label, error = %e, "[local-rpc] accept failed — retrying");
                continue;
            }
        };

        let handler = Arc::clone(&handler);
        tokio::spawn(async move {
            let _permit = permit;
            loop {
                match read_frame::<_, Req>(&mut stream).await {
                    // The peer said everything it came to say.
                    Ok(None) => break,
                    Ok(Some(req)) => {
                        let res = handler(req).await;
                        if let Err(e) = write_frame(&mut stream, &res).await {
                            tracing::debug!(
                                channel = label, ?peer, error = %e,
                                "[local-rpc] could not answer — peer went away"
                            );
                            break;
                        }
                    }
                    Err(e) => {
                        // Loud: this socket admits root and one named
                        // account, and neither of them should ever speak
                        // something this channel cannot read.
                        tracing::warn!(
                            channel = label, ?peer, error = %e,
                            "[local-rpc] unreadable request — dropping the connection"
                        );
                        break;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    enum Ask {
        Ping,
        Echo(String),
    }

    #[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
    enum Say {
        Pong,
        Echoed(String),
    }

    // ── The frame. Pure, and it runs on every target. ──

    #[test]
    fn a_message_round_trips_through_its_frame() {
        let framed = encode(&Ask::Echo("hello".into())).expect("encodes");
        let header: [u8; RPC_HEADER_LEN] = framed[..RPC_HEADER_LEN].try_into().unwrap();
        let len = parse_header(&header).expect("header parses");
        let body = &framed[RPC_HEADER_LEN..];
        assert_eq!(body.len(), len as usize, "the length must bound the body exactly");
        assert_eq!(serde_json::from_slice::<Ask>(body).unwrap(), Ask::Echo("hello".into()));
    }

    #[test]
    fn a_response_uses_the_same_frame_as_a_request() {
        // One framing in both directions: the reader on either end is the
        // same code, which is the whole reason this module exists rather
        // than a request encoding and a response encoding.
        let framed = encode(&Say::Echoed("hello".into())).expect("encodes");
        let header: [u8; RPC_HEADER_LEN] = framed[..RPC_HEADER_LEN].try_into().unwrap();
        let len = parse_header(&header).expect("header parses");
        let body = &framed[RPC_HEADER_LEN..];
        assert_eq!(body.len(), len as usize);
        assert_eq!(serde_json::from_slice::<Say>(body).unwrap(), Say::Echoed("hello".into()));
    }

    #[test]
    fn the_frame_ends_exactly_where_it_says_it_does() {
        // What follows one frame is the next frame, and a reader that
        // over-reads by a byte corrupts it. This is the same property
        // `perimeter_preamble` depends on for the client's SSH banner.
        let mut wire = encode(&Ask::Ping).unwrap();
        let second = encode(&Ask::Echo("x".into())).unwrap();
        wire.extend_from_slice(&second);

        let header: [u8; RPC_HEADER_LEN] = wire[..RPC_HEADER_LEN].try_into().unwrap();
        let end = RPC_HEADER_LEN + parse_header(&header).unwrap() as usize;
        assert_eq!(&wire[end..], &second[..], "the next frame must survive intact");
    }

    #[test]
    fn a_peer_speaking_something_else_is_named_not_guessed() {
        // The exact shape this channel replaced: something dialled the
        // socket and started speaking HTTP at it. That has to read as "not
        // our frame", with the opening bytes quoted, rather than as a
        // malformed message or a length nobody can explain.
        let mut header = [0u8; RPC_HEADER_LEN];
        header.copy_from_slice(b"GET /perime"[..RPC_HEADER_LEN].as_ref());
        let err = parse_header(&header).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert!(err.to_string().contains("GET /p"), "got {err}");
    }

    #[test]
    fn a_version_this_build_cannot_read_is_refused() {
        let mut framed = encode(&Ask::Ping).unwrap();
        framed[RPC_MAGIC.len()] = 99;
        let header: [u8; RPC_HEADER_LEN] = framed[..RPC_HEADER_LEN].try_into().unwrap();
        assert!(parse_header(&header).unwrap_err().to_string().contains("99"));
    }

    #[test]
    fn a_declared_length_past_the_bound_is_refused_before_any_allocation() {
        let mut header = [0u8; RPC_HEADER_LEN];
        header[..RPC_MAGIC.len()].copy_from_slice(&RPC_MAGIC);
        header[RPC_MAGIC.len()] = RPC_VERSION;
        header[RPC_MAGIC.len() + 1..].copy_from_slice(&u32::MAX.to_be_bytes());
        let err = parse_header(&header).unwrap_err();
        assert!(err.to_string().contains(&MAX_RPC_LEN.to_string()), "got {err}");
    }

    #[tokio::test]
    async fn a_clean_close_at_a_frame_boundary_is_not_an_error() {
        // The whole reason `read_body` fills the header by hand: a client
        // that asked what it came for and hung up must end the serve loop,
        // not log a fault every time.
        let mut wire: &[u8] = &[];
        assert!(read_body(&mut wire).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn a_connection_cut_mid_header_is_an_error() {
        let mut wire: &[u8] = &RPC_MAGIC[..3];
        let err = read_body(&mut wire).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
        assert!(err.to_string().contains("3 bytes into"), "got {err}");
    }

    // ── Client and server over a real socket. Unix only. ──

    #[cfg(unix)]
    mod over_a_socket {
        use super::*;
        use crate::local_endpoint::{plan_from_resolution, AccountResolution, LocalEndpoint};
        use std::path::PathBuf;

        fn scratch(name: &str) -> PathBuf {
            let dir =
                std::env::temp_dir().join(format!("mirage-rpc-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).expect("scratch dir");
            dir
        }

        async fn stand_up(name: &str) -> LocalEndpoint {
            let dir = scratch(name);
            let ep = LocalEndpoint::Unix(dir.join("rpc.sock"));
            // SAFETY: getuid(2) reads a process property and cannot fail.
            let me = unsafe { libc::getuid() };
            let mut plan = plan_from_resolution(AccountResolution::NotRequested);
            plan.admitted_uids = vec![me];
            let listener = ep.bind_with(Some(&dir), &plan).await.expect("bind");
            tokio::spawn(serve_on(listener, "test", |ask: Ask| async move {
                match ask {
                    Ask::Ping => Say::Pong,
                    Ask::Echo(s) => Say::Echoed(s),
                }
            }));
            ep
        }

        #[tokio::test]
        async fn a_typed_question_gets_a_typed_answer() {
            let ep = stand_up("one").await;
            let mut client = ep.connect().await.expect("connect");
            write_frame(&mut client, &Ask::Ping).await.expect("write");
            let got: Say = read_frame(&mut client).await.expect("read").expect("a frame");
            assert_eq!(got, Say::Pong);
        }

        #[tokio::test]
        async fn one_connection_carries_as_many_exchanges_as_the_client_wants() {
            // A poll-every-five-seconds client reconnects; a control plane
            // will not. Both have to work, and nothing here is stateful
            // across frames, so both cost the same.
            let ep = stand_up("many").await;
            let mut client = ep.connect().await.expect("connect");
            for i in 0..4 {
                let word = format!("w{i}");
                write_frame(&mut client, &Ask::Echo(word.clone())).await.expect("write");
                let got: Say = read_frame(&mut client).await.expect("read").expect("a frame");
                assert_eq!(got, Say::Echoed(word));
            }
        }

        #[tokio::test]
        async fn a_peer_that_speaks_nonsense_loses_its_own_connection_and_nothing_else() {
            let ep = stand_up("nonsense").await;

            let mut bad = ep.connect().await.expect("connect");
            bad.write_all(b"GET /perimeter/stats HTTP/1.1\r\n\r\n").await.expect("write");
            // The server drops it; the read ends rather than hanging.
            let mut buf = [0u8; 8];
            let _ = tokio::time::timeout(Duration::from_secs(2), bad.read(&mut buf)).await;

            // The channel is still serving.
            let mut good = ep.connect().await.expect("second connect");
            write_frame(&mut good, &Ask::Ping).await.expect("write");
            let got: Say = read_frame(&mut good).await.expect("read").expect("a frame");
            assert_eq!(got, Say::Pong);
        }

        #[tokio::test]
        async fn a_call_to_a_channel_nobody_holds_fails_fast_and_says_so() {
            // The verdict mshd's door depends on: a perimeter that is not
            // there has to resolve to an answer, not to a wait.
            let dir = scratch("absent");
            let ep = LocalEndpoint::Unix(dir.join("nobody.sock"));
            let err = tokio::time::timeout(Duration::from_secs(2), ep.connect())
                .await
                .expect("a refused connect must not hang")
                .unwrap_err();
            assert!(
                matches!(
                    err.kind(),
                    io::ErrorKind::NotFound | io::ErrorKind::ConnectionRefused
                ),
                "got {err:?}"
            );
        }
    }
}
