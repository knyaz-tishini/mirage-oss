//! `MirageCoreUdpTunnel` datagram-safety tests — real loopback UDP sockets.
//!
//! Every socket in this file binds `127.0.0.1:0` explicitly, or is paired
//! against a `127.0.0.1:<port>` remote — never a wildcard address is used as
//! a send/receive target.
//!
//! These tests exercise the fix for the truncate-and-report-success defect
//! in `MirageCoreUdpTunnel::recv`: an oversized datagram must error rather
//! than silently hand back a short `Ok`, the new `recv_datagram` method must
//! return the whole payload unconditionally, a zero-length datagram must not
//! be mistaken for a closed tunnel, and the pre-existing HMAC replay guard /
//! dummy-frame skip must keep working exactly as before.
//!
//! Session keys are derived directly via `SessionKeys::derive` rather than
//! running a full V9 handshake (covered by `tests/udp_v9_handshake.rs`) —
//! these tests are only concerned with the data-phase tunnel, not handshake
//! machinery, so both sides call `derive` with identical inputs to land on
//! identical keys.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use mirage_core::crypto::{AeadCipher, AeadSuite, SessionKeys};
use mirage_core::error::MirageError;
use mirage_core::frame::{CamouflageType, Frame, FrameCodec};
use mirage_protocol::auth::AuthMode;
use mirage_protocol::core::udp_tunnel::MirageCoreUdpTunnel;
use mirage_protocol::traits::{TransportInfo, Tunnel};
use mirage_protocol::transport::udp::UdpPeerSocket;
use tokio::net::UdpSocket;

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

/// Deterministic test session keys — both sides derive from the same
/// `shared` / `salt` bytes, so calling this twice yields identical keys
/// without running a real ECDH handshake.
fn test_keys() -> SessionKeys {
    SessionKeys::derive(
        b"udp-tunnel-datagram-safety-test-shared-secret",
        b"udp-tunnel-datagram-safety-test-salt",
        AeadSuite::ChaCha20Poly1305,
    )
}

/// Bind two `UdpPeerSocket`s pointed at each other over loopback, with no
/// handshake involved — suitable for exercising the data-phase tunnel logic
/// directly.
async fn paired_sockets() -> (UdpPeerSocket, UdpPeerSocket) {
    let a = UdpPeerSocket::bind_client(loopback(0))
        .await
        .expect("bind first loopback peer socket");
    let b = UdpPeerSocket::bind_client(loopback(0))
        .await
        .expect("bind second loopback peer socket");
    let port_a = a.local_addr().expect("peer socket a local addr").port();
    let port_b = b.local_addr().expect("peer socket b local addr").port();

    let mut a = a;
    let mut b = b;
    a.set_remote(loopback(port_b));
    b.set_remote(loopback(port_a));
    (a, b)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Tunnel::recv refuses an oversized datagram instead of truncating it
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tunnel_recv_errors_instead_of_truncating_oversized_datagram() {
    let (client_sock, server_sock) = paired_sockets().await;
    let client_remote = client_sock.remote_addr();
    let server_remote = server_sock.remote_addr();
    let keys = test_keys();

    let mut client_tunnel = MirageCoreUdpTunnel::new(
        client_sock,
        &keys,
        true,
        TransportInfo::udp_raw(client_remote),
        AuthMode::None,
    );
    let mut server_tunnel = MirageCoreUdpTunnel::new(
        server_sock,
        &keys,
        false,
        TransportInfo::udp_raw(server_remote),
        AuthMode::None,
    );

    let big_payload = vec![0xABu8; 5000];
    client_tunnel
        .send(&big_payload)
        .await
        .expect("send oversized payload must succeed at the transport level");

    let mut small_buf = [0u8; 16];
    let err = server_tunnel
        .recv(&mut small_buf)
        .await
        .expect_err("a payload larger than the caller buffer must error, never truncate");

    match err {
        MirageError::Protocol(msg) => {
            assert!(
                msg.contains(&big_payload.len().to_string()),
                "error must name the real payload size ({}): {msg}",
                big_payload.len()
            );
            assert!(
                msg.contains(&small_buf.len().to_string()),
                "error must name the caller's buffer size ({}): {msg}",
                small_buf.len()
            );
        }
        other => panic!("expected MirageError::Protocol naming both sizes, got: {other:?}"),
    }

    // The buffer must be left untouched — no partial/truncated copy occurred.
    assert_eq!(small_buf, [0u8; 16], "buffer must not have been written to on the error path");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. recv_datagram returns the full payload for a datagram that would have
//    been truncated through Tunnel::recv
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn recv_datagram_returns_full_payload_that_would_have_truncated() {
    let (client_sock, server_sock) = paired_sockets().await;
    let client_remote = client_sock.remote_addr();
    let server_remote = server_sock.remote_addr();
    let keys = test_keys();

    let mut client_tunnel = MirageCoreUdpTunnel::new(
        client_sock,
        &keys,
        true,
        TransportInfo::udp_raw(client_remote),
        AuthMode::None,
    );
    let mut server_tunnel = MirageCoreUdpTunnel::new(
        server_sock,
        &keys,
        false,
        TransportInfo::udp_raw(server_remote),
        AuthMode::None,
    );

    let big_payload: Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();
    client_tunnel
        .send(&big_payload)
        .await
        .expect("send oversized payload must succeed");

    let received = server_tunnel
        .recv_datagram()
        .await
        .expect("recv_datagram must return the whole datagram regardless of size");

    assert_eq!(received, big_payload, "recv_datagram must return the exact bytes sent, in full");
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. A zero-length datagram round-trips and is not mistaken for a closed tunnel
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn zero_length_datagram_is_not_mistaken_for_closed_tunnel() {
    let (client_sock, server_sock) = paired_sockets().await;
    let client_remote = client_sock.remote_addr();
    let server_remote = server_sock.remote_addr();
    let keys = test_keys();

    let mut client_tunnel = MirageCoreUdpTunnel::new(
        client_sock,
        &keys,
        true,
        TransportInfo::udp_raw(client_remote),
        AuthMode::None,
    );
    let mut server_tunnel = MirageCoreUdpTunnel::new(
        server_sock,
        &keys,
        false,
        TransportInfo::udp_raw(server_remote),
        AuthMode::None,
    );

    // Through Tunnel::recv: Ok(0) with a non-empty buffer.
    client_tunnel.send(&[]).await.expect("send empty datagram must succeed");
    let mut buf = [0xFFu8; 64];
    let n = server_tunnel
        .recv(&mut buf)
        .await
        .expect("recv of a zero-length datagram must succeed, not error");
    assert_eq!(n, 0, "an empty datagram must report zero bytes copied");

    // The tunnel must still be usable afterward — Ok(0) here did not mean
    // "closed". A real, non-empty message sent right after must still arrive.
    let follow_up = b"still alive after the empty datagram";
    client_tunnel
        .send(follow_up)
        .await
        .expect("send after an empty datagram must succeed");
    let n2 = server_tunnel
        .recv(&mut buf)
        .await
        .expect("recv after an empty datagram must still succeed");
    assert_eq!(
        &buf[..n2],
        follow_up,
        "the tunnel must keep delivering real data after a zero-length datagram"
    );

    // Through recv_datagram: an owned empty Vec, unambiguous by construction.
    client_tunnel.send(&[]).await.expect("send second empty datagram must succeed");
    let received = server_tunnel
        .recv_datagram()
        .await
        .expect("recv_datagram of a zero-length datagram must succeed");
    assert!(received.is_empty(), "recv_datagram must return an empty Vec, not an error or a sentinel");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4a. A dummy cover-traffic frame is still silently skipped
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn dummy_cover_frame_is_still_skipped() {
    let raw_sender = UdpSocket::bind(loopback(0))
        .await
        .expect("bind raw crafting socket on loopback");
    let raw_sender_addr = raw_sender.local_addr().expect("raw sender local addr");

    let server_peer = UdpPeerSocket::bind_client(raw_sender_addr)
        .await
        .expect("bind server peer socket pointed at the raw sender");
    let server_port = server_peer
        .local_addr()
        .expect("server peer local addr")
        .port();

    let keys = test_keys();
    // Server is_client=false => recv_key is the client_write_key; craft
    // frames with that same key to stand in for the "client" side.
    let craft_key: [u8; 32] = *keys.client_write_key;
    let mut craft_codec = FrameCodec::new(AeadCipher::with_suite(keys.suite, &craft_key), vec![4096]);

    let mut server_tunnel = MirageCoreUdpTunnel::new(
        server_peer,
        &keys,
        false,
        TransportInfo::udp_raw(raw_sender_addr),
        AuthMode::None,
    );

    let dummy_wire = craft_codec
        .encode(&Frame { cam_type: CamouflageType::Dummy, payload: vec![0x11u8; 8] })
        .expect("encode dummy cover frame");
    raw_sender
        .send_to(&dummy_wire, loopback(server_port))
        .await
        .expect("send dummy cover frame");

    let real_payload = b"real payload arriving right after the dummy".to_vec();
    let real_wire = craft_codec
        .encode(&Frame { cam_type: CamouflageType::Raw, payload: real_payload.clone() })
        .expect("encode real frame");
    raw_sender
        .send_to(&real_wire, loopback(server_port))
        .await
        .expect("send real frame");

    let mut buf = [0u8; 4096];
    let n = server_tunnel
        .recv(&mut buf)
        .await
        .expect("recv must skip the dummy frame and return the real one");
    assert_eq!(&buf[..n], &real_payload[..], "the dummy frame must not surface as tunnel data");
}

// ─────────────────────────────────────────────────────────────────────────────
// 4b. An HMAC-window replay / duplicate datagram is still dropped
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn hmac_window_still_drops_replayed_duplicate_datagram() {
    // `tap` stands between the client and server sockets so the test can
    // capture the exact wire bytes the client tunnel transmits and resend
    // them a second time — a real replay, not merely "the same plaintext
    // sent twice" (which would carry a different HMAC counter and prove
    // nothing about the replay guard).
    let tap = UdpSocket::bind(loopback(0)).await.expect("bind tap socket on loopback");
    let tap_addr = tap.local_addr().expect("tap local addr");

    let client_sock = UdpPeerSocket::bind_client(tap_addr)
        .await
        .expect("bind client peer socket pointed at the tap");
    let client_port = client_sock.local_addr().expect("client peer local addr").port();

    let server_sock = UdpPeerSocket::bind_client(tap_addr)
        .await
        .expect("bind server peer socket pointed at the tap");
    let server_port = server_sock.local_addr().expect("server peer local addr").port();

    let keys = test_keys();
    let mut client_tunnel = MirageCoreUdpTunnel::new(
        client_sock,
        &keys,
        true,
        TransportInfo::udp_raw(tap_addr),
        AuthMode::Hmac,
    );
    let mut server_tunnel = MirageCoreUdpTunnel::new(
        server_sock,
        &keys,
        false,
        TransportInfo::udp_raw(tap_addr),
        AuthMode::Hmac,
    );

    // First real frame, relayed through the tap.
    client_tunnel.send(b"first message").await.expect("send first message");
    let mut raw = [0u8; 4096];
    let (n, from) = tap.recv_from(&mut raw).await.expect("tap must observe the first datagram");
    assert_eq!(from.port(), client_port, "sanity: the datagram must come from the client");
    let wire_first = raw[..n].to_vec();
    tap.send_to(&wire_first, loopback(server_port))
        .await
        .expect("relay first datagram to the server");

    let mut buf = [0u8; 4096];
    let n1 = server_tunnel
        .recv(&mut buf)
        .await
        .expect("first legitimate frame must decode");
    assert_eq!(&buf[..n1], b"first message");

    // Replay the exact same wire bytes — the sliding window must drop it
    // silently rather than surfacing it as data or erroring the tunnel.
    tap.send_to(&wire_first, loopback(server_port))
        .await
        .expect("relay the replayed datagram to the server");

    // A second, genuinely new frame right after the replay.
    client_tunnel.send(b"second message").await.expect("send second message");
    let (n2, from2) = tap.recv_from(&mut raw).await.expect("tap must observe the second datagram");
    assert_eq!(from2.port(), client_port);
    let wire_second = raw[..n2].to_vec();
    tap.send_to(&wire_second, loopback(server_port))
        .await
        .expect("relay second datagram to the server");

    // The replay must have been dropped internally: this single recv call
    // must skip it and return the second real frame, not the replay's
    // (identical) bytes reinterpreted as a new message, and not an error.
    let n3 = server_tunnel
        .recv(&mut buf)
        .await
        .expect("recv must skip the dropped replay and return the next real frame");
    assert_eq!(
        &buf[..n3],
        b"second message",
        "the duplicate must be dropped and the real next frame delivered untouched"
    );
}
