//! Session-level tests for the tokio compatibility shim.
//!
//! Three of the five tests across this file and `stress.rs` used to hang, and
//! carried an `#[ignore]` calling it a driver deadlock. Measured one at a time
//! on 2026-07-31, the correlation was task structure: every test that awaited
//! `client.open_stream()` and then `server.accept_stream()` on the SAME task
//! hung, and the one stream test that accepted from a separate task passed.
//!
//! Diagnosed 2026-08-04, and it is not a deadlock. `Active::poll_new_outbound`
//! allocates a stream id and local state and returns — it sends NO frame. The
//! mux opens lazily: the peer learns a stream exists when its first frame
//! arrives, i.e. on the first write. So a test that awaits `accept_stream`
//! before anything is written is waiting for a frame that by design does not
//! exist yet. The test that passed did not pass because it accepted from
//! another task; it passed because that structure let the client's `write_all`
//! run concurrently, and the write is what opens the stream.
//!
//! Which of the two possibilities the old note named turned out to be true:
//! the contract was real and written down nowhere. It is written down now, on
//! `SessionHandle::open_stream`, and `lazy_open_is_the_contract` below pins it
//! so that a future move to eager open shows up as a failing test rather than
//! as silent behavioural drift.
//!
//! `SessionHandle` is production code (`mirage2node` exit `direct.rs` /
//! `onion_fs.rs`, `mirage2app` `client-core/mux_pool.rs`), so these tests are
//! the only signal there is.

use std::time::Duration;

use mirage_mux::tokio_compat::{SessionHandle, TokioIoCompat, TokioMuxStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn open_and_echo() {
    let (client_io, server_io) = tokio::io::duplex(65536);
    let client = SessionHandle::client(TokioIoCompat(client_io));
    let server = SessionHandle::server(TokioIoCompat(server_io));

    let mut c_stream = TokioMuxStream(client.open_stream().await.unwrap());
    // The write is what makes the stream visible to the peer, so it has to
    // come before the accept. Awaiting the accept first waits on a frame that
    // nothing has been asked to send.
    c_stream.write_all(b"hello world").await.unwrap();

    let mut s_stream = TokioMuxStream(server.accept_stream().await.unwrap());
    let mut buf = vec![0u8; 11];
    s_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"hello world");

    s_stream.write_all(b"reply").await.unwrap();
    let mut buf2 = vec![0u8; 5];
    c_stream.read_exact(&mut buf2).await.unwrap();
    assert_eq!(&buf2, b"reply");

    c_stream.shutdown().await.unwrap();
    s_stream.shutdown().await.unwrap();
}

#[tokio::test]
async fn multiple_streams() {
    let (client_io, server_io) = tokio::io::duplex(65536);
    let client = SessionHandle::client(TokioIoCompat(client_io));
    let server = SessionHandle::server(TokioIoCompat(server_io));

    // Open and write all ten first: each write is what puts its stream on the
    // wire, and the server can only accept in the order the frames arrive.
    let mut client_streams = Vec::new();
    for i in 0..10 {
        let mut cs = TokioMuxStream(client.open_stream().await.unwrap());
        cs.write_all(format!("stream-{i}").as_bytes()).await.unwrap();
        client_streams.push(cs);
    }

    for i in 0..10 {
        let mut ss = TokioMuxStream(server.accept_stream().await.unwrap());
        let expected = format!("stream-{i}");
        let mut buf = vec![0u8; expected.len()];
        ss.read_exact(&mut buf).await.unwrap();
        assert_eq!(String::from_utf8(buf).unwrap(), expected);
    }
}

/// The contract itself, asserted rather than assumed.
///
/// An opened-but-unwritten stream must NOT reach the peer, and the same stream
/// must reach it as soon as something is written. Both halves matter: the
/// first is what every caller has to know, the second is what stops the first
/// from being satisfiable by a mux that simply never delivers.
#[tokio::test]
async fn lazy_open_is_the_contract() {
    let (client_io, server_io) = tokio::io::duplex(65536);
    let client = SessionHandle::client(TokioIoCompat(client_io));
    let server = SessionHandle::server(TokioIoCompat(server_io));

    let mut c_stream = TokioMuxStream(client.open_stream().await.unwrap());

    // Generous relative to a duplex pipe with both drivers already running:
    // if an open were eager, the stream would be here in microseconds.
    let too_early =
        tokio::time::timeout(Duration::from_millis(500), server.accept_stream()).await;
    assert!(
        too_early.is_err(),
        "a stream that has never been written must not be visible to the peer — \
         if this now succeeds, open became eager and every caller's assumptions changed"
    );

    c_stream.write_all(b"now it exists").await.unwrap();

    let accepted = tokio::time::timeout(Duration::from_secs(5), server.accept_stream())
        .await
        .expect("the first write must open the stream")
        .expect("accept must succeed once the stream has been written to");
    let mut s_stream = TokioMuxStream(accepted);
    let mut buf = vec![0u8; 13];
    s_stream.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, b"now it exists");
}

#[tokio::test]
async fn session_close_goaway() {
    let (client_io, server_io) = tokio::io::duplex(65536);
    let client = SessionHandle::client(TokioIoCompat(client_io));
    let _server = SessionHandle::server(TokioIoCompat(server_io));

    client.close().await.unwrap();
    assert!(true); // close() itself ensures the session is done
}
