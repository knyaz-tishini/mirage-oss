//! `UdpPeerSocket::from_relay` — the `Relayed` backend, proven against the
//! same primitives `tests/udp_v9_handshake.rs` proves the `Owned` backend
//! against.
//!
//! Every socket in this file binds `127.0.0.1:0` only — never a wildcard
//! address, including the `mirage_core::local_dgram_endpoint` sockets
//! standing in for the box-local relay (this dev box exercises the
//! loopback-UDP arm; the `AF_UNIX SOCK_DGRAM` arm is exercised by
//! `mirage-core`'s own test suite, since only that crate can bind a unix
//! socket at all).
//!
//! `mirage-perimeter` is out of scope for this file (and for the crate that
//! implements the `Relayed` backend at all) — every helper below that plays
//! "the perimeter's own per-peer session task" or "the monitor's own
//! dispatcher" is test-only plumbing standing in for code that belongs to a
//! later step, exactly as `udp_v9_handshake.rs`'s own `fixed` socket already
//! stands in for the not-yet-built fixed-port listener.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use mirage_core::crypto::{AeadSuite, KeyPair};
use mirage_core::local_dgram_endpoint::{DgramEnvelope, LocalDgramEndpoint, LocalDgramSocket};
use mirage_core::local_endpoint::{plan_from_resolution, AccountResolution};
use mirage_protocol::auth::v9::CLIENT_HELLO_LEN;
use mirage_protocol::core::{run_client_handshake_v9_datagram, run_server_handshake_v9_datagram, ServerHelloCache};
use mirage_protocol::transport::udp::UdpPeerSocket;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

const MESH_ID: &[u8] = b"test-mesh-v9-dgram-relayed";
const SUITE_PREFS: &[AeadSuite] = &[AeadSuite::ChaCha20Poly1305];

/// The UDP face this relay pair stands in for. Arbitrary — this box runs at
/// most one in every test in this file.
const RELAY_FACE_PORT: u16 = 4433;

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn gen_client_static_priv() -> [u8; 32] {
    KeyPair::generate().secret.to_bytes()
}

// ─────────────────────────────────────────────────────────────────────────────
// Relay-pair helper
// ─────────────────────────────────────────────────────────────────────────────

/// Bind two `mirage_core::local_dgram_endpoint::LocalDgramSocket`s pointed at
/// each other on loopback UDP — the box-local relay, standing in for the
/// pair `mirage-perimeter` and `mirage2monitor` will eventually bind at
/// their fixed, well-known paths (`LocalDgramChannel::MonitorWireDgram` /
/// `PerimeterWireDgram`). Port `0` is used here purely for test isolation
/// (no fixed port to collide with a concurrently-running test); production
/// code never needs the OS-assigned dance this helper does, since its ports
/// are fixed.
async fn bind_relay_pair() -> (Arc<LocalDgramSocket>, Arc<LocalDgramSocket>) {
    let plan = plan_from_resolution(AccountResolution::NotRequested);
    let unbound = LocalDgramEndpoint::UdpLoopback(loopback(0));

    let mut monitor_side = LocalDgramSocket::bind(unbound.clone(), unbound.clone(), None, &plan)
        .await
        .expect("bind monitor-side relay socket");
    let LocalDgramEndpoint::UdpLoopback(monitor_addr) = *monitor_side.local_endpoint() else {
        unreachable!("the loopback-UDP arm always binds a UdpLoopback endpoint")
    };

    let perimeter_side = LocalDgramSocket::bind(
        unbound,
        LocalDgramEndpoint::UdpLoopback(monitor_addr),
        None,
        &plan,
    )
    .await
    .expect("bind perimeter-side relay socket");
    let LocalDgramEndpoint::UdpLoopback(perimeter_addr) = *perimeter_side.local_endpoint() else {
        unreachable!("the loopback-UDP arm always binds a UdpLoopback endpoint")
    };

    monitor_side.set_peer_endpoint(LocalDgramEndpoint::UdpLoopback(perimeter_addr));
    (Arc::new(monitor_side), Arc::new(perimeter_side))
}

/// Play "the monitor's own dispatcher" for exactly one already-known peer:
/// forward every envelope arriving on `monitor_relay` into `tx` as
/// `(source, payload)` — the shape [`UdpPeerSocket::from_relay`]'s own doc
/// says a real dispatcher feeds it.
fn spawn_single_peer_monitor_demux(
    monitor_relay: Arc<LocalDgramSocket>,
    tx: mpsc::Sender<(SocketAddr, Vec<u8>)>,
) {
    tokio::spawn(async move {
        loop {
            match monitor_relay.recv_envelope().await {
                Ok((envelope, payload)) => {
                    if tx.send((envelope.peer, payload)).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. A full send/recv round trip over the Relayed backend
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn relayed_backend_send_recv_round_trip() {
    let (monitor_relay, perimeter_relay) = bind_relay_pair().await;
    let client_identity = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 51234);

    let (tx, rx) = mpsc::channel(8);
    spawn_single_peer_monitor_demux(Arc::clone(&monitor_relay), tx);

    let relayed = UdpPeerSocket::from_relay(Arc::clone(&monitor_relay), RELAY_FACE_PORT, client_identity, rx);

    // The perimeter side hands the monitor a datagram attributed to the real
    // client — mirroring step 3 of the U0 plan's §5.3 handoff.
    perimeter_relay
        .send_envelope(
            DgramEnvelope { face_port: RELAY_FACE_PORT, peer: client_identity },
            b"hello from the perimeter",
        )
        .await
        .expect("perimeter-side send_envelope must succeed");

    let mut buf = [0u8; 128];
    let n = relayed.recv(&mut buf).await.expect("relayed recv must succeed");
    assert_eq!(&buf[..n], b"hello from the perimeter");

    relayed
        .send(b"reply from the monitor")
        .await
        .expect("relayed send must succeed");
    let (envelope, payload) = perimeter_relay
        .recv_envelope()
        .await
        .expect("perimeter-side recv_envelope must succeed");
    assert_eq!(envelope.peer, client_identity, "the reply must carry the same peer identity back");
    assert_eq!(payload, b"reply from the monitor");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Peer filtering still rejects a datagram from the wrong peer
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn relayed_backend_discards_a_datagram_from_the_wrong_peer() {
    let (monitor_relay, perimeter_relay) = bind_relay_pair().await;
    let real_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9)), 51234);
    let impostor = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 5)), 4444);

    let (tx, rx) = mpsc::channel(8);
    spawn_single_peer_monitor_demux(Arc::clone(&monitor_relay), tx);

    let relayed = UdpPeerSocket::from_relay(Arc::clone(&monitor_relay), RELAY_FACE_PORT, real_peer, rx);

    perimeter_relay
        .send_envelope(
            DgramEnvelope { face_port: RELAY_FACE_PORT, peer: impostor },
            b"i am not the real peer",
        )
        .await
        .expect("send the impostor envelope");
    perimeter_relay
        .send_envelope(
            DgramEnvelope { face_port: RELAY_FACE_PORT, peer: real_peer },
            b"the real payload",
        )
        .await
        .expect("send the real envelope");

    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(Duration::from_secs(2), relayed.recv(&mut buf))
        .await
        .expect("recv must not hang waiting past the impostor's datagram")
        .expect("recv must succeed");
    assert_eq!(
        &buf[..n],
        b"the real payload",
        "the impostor's datagram must be discarded rather than returned"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. The V9 datagram handshake, unmodified, completes over a Relayed socket
// ─────────────────────────────────────────────────────────────────────────────

/// Play "the perimeter's own per-peer session task" (U0 plan §5.3 step 3):
/// bridge real UDP datagrams arriving on `fixed` into `perimeter_relay`,
/// tagging each with its OBSERVED source, and re-emit whatever comes back
/// out of `perimeter_relay` from `fixed`, toward the envelope's own `peer`.
///
/// This is the one piece of plumbing that keeps the public 4-tuple stable —
/// `fixed` never learns of, and never touches, any address but the one that
/// dialled it — which is the entire point of the `Relayed` backend existing
/// (see `src/transport/udp.rs`'s module doc and
/// `bind_server_ephemeral`'s own doc for what this replaces).
fn spawn_perimeter_bridge(fixed: Arc<UdpSocket>, perimeter_relay: Arc<LocalDgramSocket>) {
    let fixed_fwd = Arc::clone(&fixed);
    let relay_fwd = Arc::clone(&perimeter_relay);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        loop {
            let (n, from) = match fixed_fwd.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => break,
            };
            let envelope = DgramEnvelope { face_port: RELAY_FACE_PORT, peer: from };
            if relay_fwd.send_envelope(envelope, &buf[..n]).await.is_err() {
                break;
            }
        }
    });

    tokio::spawn(async move {
        loop {
            let (envelope, payload) = match perimeter_relay.recv_envelope().await {
                Ok(v) => v,
                Err(_) => break,
            };
            if fixed.send_to(&payload, envelope.peer).await.is_err() {
                break;
            }
        }
    });
}

/// Play "the monitor's own dispatcher" (U0 plan §5.3 step 4) for the FIRST
/// envelope only: that datagram is the `ClientHello`, handed to
/// [`run_server_handshake_v9_datagram`] as its already-received parameter —
/// this function never reads its own first datagram, by design (see that
/// function's own doc) — and constructing the `Relayed` `UdpPeerSocket`
/// itself needs the peer identity that same envelope carries. Every
/// SUBSEQUENT envelope is forwarded through the ordinary demux task.
async fn monitor_accept_first_hello(
    monitor_relay: Arc<LocalDgramSocket>,
) -> (UdpPeerSocket, [u8; CLIENT_HELLO_LEN]) {
    let (envelope, first_payload) = monitor_relay
        .recv_envelope()
        .await
        .expect("recv the first relayed ClientHello");
    assert_eq!(
        first_payload.len(),
        CLIENT_HELLO_LEN,
        "the first relayed datagram must be exactly one ClientHello"
    );
    let hello_bytes: [u8; CLIENT_HELLO_LEN] =
        first_payload.as_slice().try_into().expect("length checked immediately above");

    let (tx, rx) = mpsc::channel(16);
    spawn_single_peer_monitor_demux(Arc::clone(&monitor_relay), tx);

    let socket = UdpPeerSocket::from_relay(monitor_relay, RELAY_FACE_PORT, envelope.peer, rx);
    (socket, hello_bytes)
}

#[tokio::test]
async fn v9_datagram_handshake_completes_over_the_relayed_backend_with_identical_session_keys() {
    let server_kp = KeyPair::generate();
    let server_static_pub = server_kp.public.to_bytes();
    let client_static_priv = gen_client_static_priv();

    // `fixed` plays the perimeter's own public, bound face socket — the
    // client dials it exactly as it would dial a real face, unaware that a
    // relay sits behind it rather than a second per-peer bind.
    let fixed = Arc::new(
        UdpSocket::bind(loopback(0))
            .await
            .expect("bind fixed rendezvous socket on loopback"),
    );
    let fixed_addr = fixed.local_addr().expect("fixed socket local addr");

    // The client side is completely unmodified: `Owned` backend, unaware
    // anything behind `fixed_addr` is different from `udp_v9_handshake.rs`'s
    // own topology.
    let mut client_socket = UdpPeerSocket::bind_client(fixed_addr)
        .await
        .expect("bind client UdpPeerSocket");

    let (monitor_relay, perimeter_relay) = bind_relay_pair().await;
    spawn_perimeter_bridge(Arc::clone(&fixed), perimeter_relay);

    let cache = ServerHelloCache::new();

    let client_fut = run_client_handshake_v9_datagram(
        &mut client_socket,
        &server_static_pub,
        &client_static_priv,
        MESH_ID,
        SUITE_PREFS,
    );

    let server_fut = async {
        let (mut server_socket, hello_bytes) = monitor_accept_first_hello(monitor_relay).await;
        let result = run_server_handshake_v9_datagram(
            &mut server_socket,
            &server_kp,
            MESH_ID,
            SUITE_PREFS,
            |_ctx| true,
            &hello_bytes,
            &cache,
        )
        .await
        .expect("server handshake I/O must not error")
        .expect("server must accept the relayed ClientHello");
        (server_socket, result)
    };

    let (client_result, (_server_socket, server_result)) =
        tokio::time::timeout(Duration::from_secs(10), async { tokio::join!(client_fut, server_fut) })
            .await
            .expect("the relayed handshake must not hang");
    let client_result = client_result.expect("client datagram handshake must succeed over the relay");

    assert_eq!(
        *client_result.session_keys.client_write_key,
        *server_result.session_keys.client_write_key,
        "client_write_key must match on both sides, exactly as it does on the Owned backend"
    );
    assert_eq!(
        *client_result.session_keys.server_write_key,
        *server_result.session_keys.server_write_key,
        "server_write_key must match on both sides, exactly as it does on the Owned backend"
    );
    assert_eq!(
        client_result.session_keys.suite, server_result.session_keys.suite,
        "negotiated suite must match on both sides"
    );

    // The whole point of the Relayed backend (U0 plan §5.1): the reply
    // legitimately arrives from `fixed_addr` itself, never a second port —
    // `recv_handshake_from_host`'s "adopt the reply's source" behaviour is
    // therefore a no-op here, which is the honest proof that the public
    // 4-tuple never moved.
    assert_eq!(
        client_socket.remote_addr(),
        fixed_addr,
        "the client must still be pointed at the one fixed rendezvous address — nothing ever \
         moved it to a second port, unlike the Owned/bind_server_ephemeral topology"
    );
}
