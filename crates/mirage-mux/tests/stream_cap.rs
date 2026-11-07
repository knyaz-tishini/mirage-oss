//! The stream credit of a mux session.
//!
//! A session has two independent budgets, one per direction, and a stream
//! counts against its budget until it is *complete* -- both of its
//! directions closed. The credit comes back at that moment, which is how
//! QUIC replenishes its stream credit (RFC 9000, section 4.6) and how
//! HTTP/2 raises `SETTINGS_MAX_CONCURRENT_STREAMS`.
//!
//! Reaching a budget is backpressure, not a failure:
//!
//! - the local side waits for the credit instead of refusing the open, so
//!   the flows already running through the session are not affected;
//! - the remote side refuses that one stream (HTTP/2's REFUSED_STREAM) and
//!   leaves the session and every other stream alone.
//!
//! The tests below pin those three properties: the credit comes back, the
//! session survives a saturated open, and a refused stream does not take
//! the session down.

use std::sync::Arc;
use std::time::Duration;

use mirage_mux::tokio_compat::{SessionHandle, TokioIoCompat, TokioMuxStream};
use mirage_mux::{MuxConfig, MuxError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const BOUND: Duration = Duration::from_secs(5);

/// Read `len` bytes from `stream`.
async fn read_exact(stream: &mut TokioMuxStream, len: usize) -> Vec<u8> {
    let mut buf = vec![0u8; len];
    stream.read_exact(&mut buf).await.expect("read must succeed");
    buf
}

#[tokio::test]
async fn an_open_past_the_budget_waits_for_the_credit_instead_of_failing() {
    let mut config = MuxConfig::default();
    config.set_max_num_streams(1);

    let (client_io, server_io) = tokio::io::duplex(65536);
    let client = SessionHandle::client_with_config(TokioIoCompat(client_io), config);
    let server = SessionHandle::server(TokioIoCompat(server_io));

    let mut c0 = TokioMuxStream(client.open_stream().await.unwrap());
    // The mux opens lazily: the first write is what puts the stream in
    // front of the peer.
    c0.write_all(b"s0").await.unwrap();

    let mut s0 = TokioMuxStream(server.accept_stream().await.unwrap());
    assert_eq!(read_exact(&mut s0, 2).await, b"s0");

    // The session is at its budget (1/1). The next open has to wait -- it
    // must not fail, and it must not tear the session down either.
    let client = Arc::new(client);
    let opener = {
        let client = client.clone();
        tokio::spawn(async move { client.open_stream().await.map(|_| ()) })
    };
    tokio::time::sleep(Duration::from_millis(150)).await;
    assert!(
        !opener.is_finished(),
        "an open past the budget must wait for the credit, not resolve"
    );
    assert!(
        !client.is_closed(),
        "a saturated session must stay alive"
    );

    // The flow that is already running keeps carrying data while the open
    // waits: the budget is a limit on concurrency, not a shutdown.
    c0.write_all(b"-more").await.unwrap();
    s0.write_all(b"reply").await.unwrap();
    assert_eq!(read_exact(&mut s0, 5).await, b"-more");
    let mut reply = vec![0u8; 5];
    c0.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply");

    // Completing the stream hands the credit back, and the waiting open
    // goes through.
    c0.shutdown().await.unwrap();
    s0.shutdown().await.unwrap();

    let opened = tokio::time::timeout(BOUND, opener)
        .await
        .expect("the credit must come back when the stream completes")
        .expect("the open task must not panic");
    assert!(opened.is_ok(), "the waiting open must succeed: {opened:?}");
}

#[tokio::test]
async fn dropping_a_handle_hands_the_credit_back() {
    let mut config = MuxConfig::default();
    config.set_max_num_streams(1);

    let (client_io, server_io) = tokio::io::duplex(65536);
    let client = SessionHandle::client_with_config(TokioIoCompat(client_io), config);
    let server = SessionHandle::server(TokioIoCompat(server_io));

    let mut c0 = TokioMuxStream(client.open_stream().await.unwrap());
    c0.write_all(b"s0").await.unwrap();
    let mut s0 = TokioMuxStream(server.accept_stream().await.unwrap());
    assert_eq!(read_exact(&mut s0, 2).await, b"s0");

    // The handle goes away without the stream ever completing: the credit
    // still comes back, because this stream can never carry anything again.
    drop(c0);
    drop(s0);

    let opened = tokio::time::timeout(BOUND, client.open_stream())
        .await
        .expect("the credit of a dropped stream must come back");
    assert!(opened.is_ok(), "the open must succeed: {opened:?}");
}

#[tokio::test]
async fn an_accepted_stream_is_acknowledged_without_the_peer_speaking() {
    let (client_io, server_io) = tokio::io::duplex(65536);
    let client = SessionHandle::client(TokioIoCompat(client_io));
    let server = SessionHandle::server(TokioIoCompat(server_io));

    let mut c0 = TokioMuxStream(client.open_stream().await.unwrap());
    c0.write_all(b"s0").await.unwrap();

    // The peer accepts the stream and says nothing. The acknowledgement
    // still has to arrive: otherwise the stream counts against the ACK
    // backlog for good, and a peer that stays silent wedges the session.
    let s0 = tokio::time::timeout(BOUND, server.accept_stream())
        .await
        .expect("the peer must see the stream")
        .expect("accept must succeed");
    assert!(!s0.is_closed());

    let acknowledged = tokio::time::timeout(BOUND, async {
        while c0.0.is_pending_ack() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(
        acknowledged.is_ok(),
        "an accepted stream must be acknowledged even when the peer never writes"
    );
}

#[tokio::test]
async fn a_refused_inbound_stream_leaves_the_session_and_its_siblings_alive() {
    let mut server_config = MuxConfig::default();
    server_config.set_max_num_streams(1);

    let (client_io, server_io) = tokio::io::duplex(65536);
    let client = SessionHandle::client(TokioIoCompat(client_io));
    let server = SessionHandle::server_with_config(TokioIoCompat(server_io), server_config);

    let mut c0 = TokioMuxStream(client.open_stream().await.unwrap());
    c0.write_all(b"s0").await.unwrap();
    let mut s0 = TokioMuxStream(server.accept_stream().await.unwrap());
    assert_eq!(read_exact(&mut s0, 2).await, b"s0");

    // The server is at its inbound budget. The second stream is refused --
    // that one stream only.
    let mut c1 = TokioMuxStream(client.open_stream().await.unwrap());
    c1.write_all(b"s1").await.unwrap();

    // The refused stream ends at the client, and the stream that was
    // accepted keeps working.
    let mut refused = Vec::new();
    let _ = tokio::time::timeout(BOUND, c1.read_to_end(&mut refused)).await;

    c0.write_all(b"-after").await.unwrap();
    assert_eq!(read_exact(&mut s0, 6).await, b"-after");
    s0.write_all(b"reply").await.unwrap();
    let mut reply = vec![0u8; 5];
    c0.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"reply");

    assert!(
        !client.is_closed(),
        "a refused stream must not tear the session down"
    );
    assert!(
        !server.is_closed(),
        "a refused stream must not tear the session down"
    );
}

#[tokio::test]
async fn the_two_directions_have_separate_budgets() {
    let mut config = MuxConfig::default();
    config.set_max_inbound_streams(1);
    config.set_max_outbound_streams(1);

    let (client_io, server_io) = tokio::io::duplex(65536);
    let client = SessionHandle::client_with_config(TokioIoCompat(client_io), config.clone());
    let server = SessionHandle::server_with_config(TokioIoCompat(server_io), config);

    // One stream in each direction at the same time: the client's outbound
    // budget and the server's inbound budget are met, and the server's
    // outbound budget is a separate one.
    let mut c0 = TokioMuxStream(client.open_stream().await.unwrap());
    c0.write_all(b"s0").await.unwrap();
    let mut s0 = TokioMuxStream(server.accept_stream().await.unwrap());
    assert_eq!(read_exact(&mut s0, 2).await, b"s0");

    let mut s1 = TokioMuxStream(server.open_stream().await.unwrap());
    s1.write_all(b"s1").await.unwrap();
    let mut c1 = TokioMuxStream(client.accept_stream().await.unwrap());
    assert_eq!(read_exact(&mut c1, 2).await, b"s1");

    // Both sessions are at their outbound budget now, and both are still
    // usable.
    assert!(!client.is_closed());
    assert!(!server.is_closed());
    c0.write_all(b"-x").await.unwrap();
    assert_eq!(read_exact(&mut s0, 2).await, b"-x");
    s1.write_all(b"-y").await.unwrap();
    assert_eq!(read_exact(&mut c1, 2).await, b"-y");
}

#[tokio::test]
async fn an_open_that_never_gets_credit_fails_instead_of_hanging_forever() {
    let mut config = MuxConfig::default();
    config.set_max_num_streams(1);
    config.set_stream_credit_wait(Duration::from_millis(300));

    let (client_io, server_io) = tokio::io::duplex(65536);
    let client = SessionHandle::client_with_config(TokioIoCompat(client_io), config);
    let _server = SessionHandle::server(TokioIoCompat(server_io));

    // Take the only slot and never give it back.
    let _held = client.open_stream().await.unwrap();

    // The wait is bounded: the caller gets an error rather than hanging
    // for good. The session itself stays alive.
    let err = client.open_stream().await;
    assert!(
        matches!(err, Err(MuxError::TooManyStreams)),
        "a starved open must fail with TooManyStreams, got: {err:?}"
    );
    assert!(
        !client.is_closed(),
        "a starved open must not tear the session down"
    );
}
