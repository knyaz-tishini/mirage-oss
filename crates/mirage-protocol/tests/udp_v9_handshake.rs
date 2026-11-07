//! Datagram V9 handshake tests (U1 / U1a) — real loopback UDP sockets.
//!
//! Every socket in this file binds `127.0.0.1:0` only — never a wildcard
//! address.
//!
//! Topology mirrored from `src/transport/udp.rs`'s module docs: `fixed` is a
//! plain `tokio::net::UdpSocket` standing in for the not-yet-built fixed-port
//! listener (wiring that dispatcher across many concurrent peers is U6 —
//! out of scope here). The client dials it, and the harness — playing the
//! part that dispatcher will eventually play — reads the `ClientHello` off
//! `fixed`, binds a fresh per-peer `UdpPeerSocket` via
//! `bind_server_ephemeral`, and hands the datagram to
//! `run_server_handshake_v9_datagram`. The `ServerHello` therefore comes back
//! from a different port than `fixed_addr`, exactly the case
//! `UdpPeerSocket::recv_handshake_from_host` exists for.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mirage_core::crypto::{AeadSuite, KeyPair};
use mirage_protocol::auth::v9::{CLIENT_HELLO_LEN, SERVER_HELLO_LEN};
use mirage_protocol::auth::AuthMode;
use mirage_protocol::core::udp_tunnel::MirageCoreUdpTunnel;
use mirage_protocol::core::{
    run_client_handshake_v9_datagram, run_client_handshake_v9_datagram_with_credential,
    run_server_handshake_v9_datagram, ClientAuthContext, ClientHandshakeResult,
    ServerHandshakeResult, ServerHelloCache, UdpTunnelReceiver, UdpTunnelSender,
    MAX_CREDENTIAL_LEN_DATAGRAM,
};
use mirage_protocol::traits::{TransportInfo, Tunnel};
use mirage_protocol::transport::udp::UdpPeerSocket;
use tokio::net::UdpSocket;

const MESH_ID: &[u8] = b"test-mesh-v9-dgram";
const SUITE_PREFS: &[AeadSuite] = &[AeadSuite::ChaCha20Poly1305];

// ─────────────────────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────────────────────

fn loopback(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn gen_client_static_priv() -> [u8; 32] {
    KeyPair::generate().secret.to_bytes()
}

/// Run one full client+server V9 datagram handshake end to end.
///
/// `drop_first_n` ClientHello datagrams are read off the fixed rendezvous
/// socket and discarded without a reply — simulating that many datagrams
/// lost in transit — before the harness processes one for real. With
/// `drop_first_n == 0` this is the plain happy path.
async fn run_pair(
    drop_first_n: usize,
) -> (
    UdpPeerSocket,
    ClientHandshakeResult,
    UdpPeerSocket,
    ServerHandshakeResult,
    SocketAddr, // fixed_addr — the address the client dialled
) {
    let server_kp = KeyPair::generate();
    let server_static_pub = server_kp.public.to_bytes();
    let client_static_priv = gen_client_static_priv();

    let fixed = UdpSocket::bind(loopback(0))
        .await
        .expect("bind fixed rendezvous socket on loopback");
    let fixed_addr = fixed.local_addr().expect("fixed socket local addr");

    let mut client_socket = UdpPeerSocket::bind_client(fixed_addr)
        .await
        .expect("bind client UdpPeerSocket");

    let cache = ServerHelloCache::new();

    let client_fut = run_client_handshake_v9_datagram(
        &mut client_socket,
        &server_static_pub,
        &client_static_priv,
        MESH_ID,
        SUITE_PREFS,
    );

    let server_fut = async {
        let mut dropped = 0usize;
        let (client_addr, hello_bytes) = loop {
            let mut raw = [0u8; CLIENT_HELLO_LEN];
            let (n, addr) = fixed
                .recv_from(&mut raw)
                .await
                .expect("recv ClientHello on the fixed rendezvous socket");
            assert_eq!(n, CLIENT_HELLO_LEN, "ClientHello datagram must be exactly CLIENT_HELLO_LEN bytes");
            if dropped < drop_first_n {
                dropped += 1;
                continue; // Simulate loss: never answered, forcing the client to retransmit.
            }
            break (addr, raw);
        };

        let mut server_socket = UdpPeerSocket::bind_server_ephemeral(client_addr)
            .await
            .expect("bind server per-peer ephemeral socket");
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
        .expect("server must accept the ClientHello once actually delivered");

        (server_socket, result)
    };

    let (client_result, (server_socket, server_result)) = tokio::join!(client_fut, server_fut);
    let client_result = client_result.expect("client datagram handshake must succeed");

    (client_socket, client_result, server_socket, server_result, fixed_addr)
}

/// Credential-carrying counterpart of `run_pair`: threads `cred_scheme` /
/// `credential` through [`run_client_handshake_v9_datagram_with_credential`]
/// on the client side, and `auth_fn` through the server's `client_auth`
/// closure — used to inspect exactly what [`ClientAuthContext`] the server
/// builds.
///
/// Unlike `run_pair`'s exact `CLIENT_HELLO_LEN` receive buffer, the harness
/// here sizes its buffer to comfortably hold a full-cap credential — a real
/// caller must size its own receive buffer for the credential case, and this
/// is that sizing, done once, here.
async fn run_pair_with_credential<F>(
    cred_scheme: u8,
    credential: Vec<u8>,
    auth_fn: F,
) -> (
    Result<Option<ServerHandshakeResult>, mirage_core::error::MirageError>,
    Result<ClientHandshakeResult, mirage_core::error::MirageError>,
)
where
    F: for<'a> Fn(&ClientAuthContext<'a>) -> bool + Send + 'static,
{
    let server_kp = KeyPair::generate();
    let server_static_pub = server_kp.public.to_bytes();
    let client_static_priv = gen_client_static_priv();

    let fixed = UdpSocket::bind(loopback(0))
        .await
        .expect("bind fixed rendezvous socket on loopback");
    let fixed_addr = fixed.local_addr().expect("fixed socket local addr");

    let mut client_socket = UdpPeerSocket::bind_client(fixed_addr)
        .await
        .expect("bind client UdpPeerSocket");

    let cache = ServerHelloCache::new();

    let client_fut = run_client_handshake_v9_datagram_with_credential(
        &mut client_socket,
        &server_static_pub,
        &client_static_priv,
        MESH_ID,
        SUITE_PREFS,
        cred_scheme,
        &credential,
    );

    let server_fut = async {
        let mut raw = vec![0u8; CLIENT_HELLO_LEN + MAX_CREDENTIAL_LEN_DATAGRAM];
        let (n, client_addr) = fixed
            .recv_from(&mut raw)
            .await
            .expect("recv ClientHello+credential on the fixed rendezvous socket");

        let mut server_socket = UdpPeerSocket::bind_server_ephemeral(client_addr)
            .await
            .expect("bind server per-peer ephemeral socket");
        run_server_handshake_v9_datagram(
            &mut server_socket,
            &server_kp,
            MESH_ID,
            SUITE_PREFS,
            auth_fn,
            &raw[..n],
            &cache,
        )
        .await
    };

    tokio::join!(server_fut, client_fut)
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Identical session keys on both sides
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn v9_datagram_handshake_derives_identical_session_keys() {
    let (_client_socket, client_result, _server_socket, server_result, _fixed_addr) =
        run_pair(0).await;

    assert_eq!(
        *client_result.session_keys.client_write_key,
        *server_result.session_keys.client_write_key,
        "client_write_key must match on both sides"
    );
    assert_eq!(
        *client_result.session_keys.server_write_key,
        *server_result.session_keys.server_write_key,
        "server_write_key must match on both sides"
    );
    assert_eq!(
        client_result.session_keys.suite, server_result.session_keys.suite,
        "negotiated suite must match on both sides"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 2. Data crosses the resulting MirageCoreUdpTunnel in both directions
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn v9_datagram_tunnel_carries_data_both_directions() {
    let (client_socket, client_result, server_socket, server_result, _fixed_addr) =
        run_pair(0).await;

    let client_remote = client_socket.remote_addr();
    let server_remote = server_socket.remote_addr();

    let mut client_tunnel = MirageCoreUdpTunnel::new(
        client_socket,
        &client_result.session_keys,
        true,
        TransportInfo::udp_raw(client_remote),
        AuthMode::V9MutualFs,
    );
    let mut server_tunnel = MirageCoreUdpTunnel::new(
        server_socket,
        &server_result.session_keys,
        false,
        TransportInfo::udp_raw(server_remote),
        AuthMode::V9MutualFs,
    );

    let client_to_server = b"hello from client over the datagram tunnel";
    client_tunnel
        .send(client_to_server)
        .await
        .expect("client tunnel send must succeed");
    let mut buf = [0u8; 4096];
    let n = server_tunnel
        .recv(&mut buf)
        .await
        .expect("server tunnel recv must succeed");
    assert_eq!(&buf[..n], client_to_server, "server must receive the exact client payload");

    let server_to_client = b"hello back from the server";
    server_tunnel
        .send(server_to_client)
        .await
        .expect("server tunnel send must succeed");
    let n2 = client_tunnel
        .recv(&mut buf)
        .await
        .expect("client tunnel recv must succeed");
    assert_eq!(&buf[..n2], server_to_client, "client must receive the exact server payload");
}

// ─────────────────────────────────────────────────────────────────────────────
// 2b. `into_split` halves carry N datagrams each way, byte-identical to the
//     un-split tunnel — same test body against both.
// ─────────────────────────────────────────────────────────────────────────────

/// Either a whole [`MirageCoreUdpTunnel`] or its [`UdpTunnelSender`] /
/// [`UdpTunnelReceiver`] halves — the common interface
/// `round_trip_n_datagrams_both_directions` drives, so the exact same test
/// body proves both paths carry data identically.
#[async_trait::async_trait]
trait DgramSide: Send {
    async fn send_one(&mut self, data: &[u8]) -> Result<(), mirage_core::error::MirageError>;
    async fn recv_one(&mut self) -> Result<Vec<u8>, mirage_core::error::MirageError>;
}

#[async_trait::async_trait]
impl DgramSide for MirageCoreUdpTunnel {
    async fn send_one(&mut self, data: &[u8]) -> Result<(), mirage_core::error::MirageError> {
        Tunnel::send(self, data).await
    }
    async fn recv_one(&mut self) -> Result<Vec<u8>, mirage_core::error::MirageError> {
        self.recv_datagram().await
    }
}

/// Wraps an `into_split()` pair so [`DgramSide`] drives it the same way it
/// drives the un-split tunnel — `send_one` goes to the sender half,
/// `recv_one` comes off the receiver half.
struct SplitPair {
    sender: UdpTunnelSender,
    receiver: UdpTunnelReceiver,
}

#[async_trait::async_trait]
impl DgramSide for SplitPair {
    async fn send_one(&mut self, data: &[u8]) -> Result<(), mirage_core::error::MirageError> {
        self.sender.send(data).await
    }
    async fn recv_one(&mut self) -> Result<Vec<u8>, mirage_core::error::MirageError> {
        self.receiver.recv_datagram().await
    }
}

/// 8 payloads per direction: one zero-length (a legitimate authenticated
/// empty datagram — see `MirageCoreUdpTunnel`'s own doc) plus 7 named,
/// distinctly-sized payloads.
fn split_test_payloads(direction: &str) -> Vec<Vec<u8>> {
    let mut payloads: Vec<Vec<u8>> = vec![Vec::new()];
    payloads.extend((0..7usize).map(|i| format!("{direction}-datagram-{i}").into_bytes()));
    payloads
}

/// Send every payload in `a_to_b` from `a` to `b`, then every payload in
/// `b_to_a` from `b` to `a`, asserting each arrives whole, unmodified, and
/// in order. This exact function is called once against the two whole
/// tunnels and once against their split halves — proving the two paths are
/// byte-identical rather than merely both "working".
async fn round_trip_n_datagrams_both_directions<A, B>(
    mut a: A,
    mut b: B,
    a_to_b: &[Vec<u8>],
    b_to_a: &[Vec<u8>],
) where
    A: DgramSide,
    B: DgramSide,
{
    for payload in a_to_b {
        a.send_one(payload).await.expect("a→b send must succeed");
        let got = b.recv_one().await.expect("a→b recv must succeed");
        assert_eq!(&got, payload, "a→b datagram must arrive whole, unmodified, and in order");
    }
    for payload in b_to_a {
        b.send_one(payload).await.expect("b→a send must succeed");
        let got = a.recv_one().await.expect("b→a recv must succeed");
        assert_eq!(&got, payload, "b→a datagram must arrive whole, unmodified, and in order");
    }
}

#[tokio::test]
async fn v9_datagram_tunnel_n_datagrams_round_trip_unsplit() {
    let (client_socket, client_result, server_socket, server_result, _fixed_addr) =
        run_pair(0).await;
    let client_remote = client_socket.remote_addr();
    let server_remote = server_socket.remote_addr();

    let client_tunnel = MirageCoreUdpTunnel::new(
        client_socket,
        &client_result.session_keys,
        true,
        TransportInfo::udp_raw(client_remote),
        AuthMode::V9MutualFs,
    );
    let server_tunnel = MirageCoreUdpTunnel::new(
        server_socket,
        &server_result.session_keys,
        false,
        TransportInfo::udp_raw(server_remote),
        AuthMode::V9MutualFs,
    );

    let client_to_server = split_test_payloads("client-to-server");
    let server_to_client = split_test_payloads("server-to-client");
    round_trip_n_datagrams_both_directions(
        client_tunnel,
        server_tunnel,
        &client_to_server,
        &server_to_client,
    )
    .await;
}

#[tokio::test]
async fn v9_datagram_tunnel_n_datagrams_round_trip_split_matches_unsplit() {
    let (client_socket, client_result, server_socket, server_result, _fixed_addr) =
        run_pair(0).await;
    let client_remote = client_socket.remote_addr();
    let server_remote = server_socket.remote_addr();

    let client_tunnel = MirageCoreUdpTunnel::new(
        client_socket,
        &client_result.session_keys,
        true,
        TransportInfo::udp_raw(client_remote),
        AuthMode::V9MutualFs,
    );
    let server_tunnel = MirageCoreUdpTunnel::new(
        server_socket,
        &server_result.session_keys,
        false,
        TransportInfo::udp_raw(server_remote),
        AuthMode::V9MutualFs,
    );

    let (client_sender, client_receiver) = client_tunnel.into_split();
    let (server_sender, server_receiver) = server_tunnel.into_split();
    let client_split = SplitPair { sender: client_sender, receiver: client_receiver };
    let server_split = SplitPair { sender: server_sender, receiver: server_receiver };

    let client_to_server = split_test_payloads("client-to-server");
    let server_to_client = split_test_payloads("server-to-client");
    round_trip_n_datagrams_both_directions(
        client_split,
        server_split,
        &client_to_server,
        &server_to_client,
    )
    .await;
}

// ─────────────────────────────────────────────────────────────────────────────
// 3. A dropped ClientHello is recovered by retransmit
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn v9_datagram_handshake_recovers_from_dropped_client_hello() {
    let (_client_socket, client_result, _server_socket, server_result, _fixed_addr) =
        run_pair(1).await;

    assert_eq!(
        *client_result.session_keys.client_write_key,
        *server_result.session_keys.client_write_key,
        "handshake must still complete, with matching keys, after the first ClientHello is lost"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 4. Duplicate ClientHello gets the identical ServerHello, no second handshake
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn v9_datagram_duplicate_client_hello_gets_identical_server_hello_no_new_keys() {
    use mirage_protocol::auth::v9::{compute_client_proof, gen_ephemeral, suite_to_id, V9ClientHello, WIRE_VERSION_V9};
    use x25519_dalek::{PublicKey, StaticSecret};

    let server_kp = KeyPair::generate();
    let server_static_pub = server_kp.public.to_bytes();
    let client_static_priv = gen_client_static_priv();

    // Build one ClientHello by hand — this test drives the exact same wire
    // bytes twice, so it does not go through the client's own retry helper.
    let (_e_priv_c, e_pub_c) = gen_ephemeral();
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_millis() as u64;
    let mut suite_ids = [0u8; 3];
    suite_ids[0] = suite_to_id(AeadSuite::ChaCha20Poly1305);
    let client_proof = compute_client_proof(
        &client_static_priv,
        &server_static_pub,
        &e_pub_c,
        MESH_ID,
        &suite_ids,
        ts_ms,
    );
    let client_static_pub = PublicKey::from(&StaticSecret::from(client_static_priv)).to_bytes();
    let hello = V9ClientHello {
        version: WIRE_VERSION_V9,
        suite_ids,
        e_pub_c,
        ts_ms,
        client_proof,
        client_static_pub,
        cred_scheme: 0x00,
        target_hint: 0,
    };
    let hello_bytes = hello.to_wire();

    let fixed = UdpSocket::bind(loopback(0)).await.expect("bind fixed rendezvous socket");
    let fixed_addr = fixed.local_addr().expect("fixed local addr");
    let mut client_socket = UdpPeerSocket::bind_client(fixed_addr)
        .await
        .expect("bind client socket");

    client_socket.send(&hello_bytes).await.expect("send first ClientHello");

    let mut raw = [0u8; CLIENT_HELLO_LEN];
    let (n, client_addr) = fixed.recv_from(&mut raw).await.expect("recv first ClientHello");
    assert_eq!(n, CLIENT_HELLO_LEN);
    assert_eq!(raw, hello_bytes);

    let cache = ServerHelloCache::new();
    let mut server_socket = UdpPeerSocket::bind_server_ephemeral(client_addr)
        .await
        .expect("bind server ephemeral socket");

    let first = run_server_handshake_v9_datagram(
        &mut server_socket,
        &server_kp,
        MESH_ID,
        SUITE_PREFS,
        |_ctx| true,
        &raw,
        &cache,
    )
    .await
    .expect("server I/O must not error")
    .expect("first ClientHello must produce a handshake result");

    // Sniff the first ServerHello directly off the client's socket — this
    // also exercises U1a: the reply's source is the server's new ephemeral
    // port, not fixed_addr.
    let mut first_wire = [0u8; SERVER_HELLO_LEN];
    let n1 = client_socket
        .recv_handshake_from_host(&mut first_wire)
        .await
        .expect("recv first ServerHello");
    assert_eq!(n1, SERVER_HELLO_LEN);
    // `server_socket.local_addr()` reports the bind address (0.0.0.0 — the
    // OS chooses which interface each outbound datagram actually leaves
    // from), so compare against the port the OS assigned rather than the
    // literal bind IP, and check the adopted remote is a real loopback host.
    assert_eq!(
        client_socket.remote_addr().ip(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "client must adopt a real loopback host as the server's reply source"
    );
    assert_eq!(
        client_socket.remote_addr().port(),
        server_socket.local_addr().expect("server socket local addr").port(),
        "client must have adopted the server's ephemeral port"
    );

    // Client "retransmits" the identical ClientHello — now straight to the
    // ephemeral socket, since that is what the client's remote points at.
    client_socket
        .send(&hello_bytes)
        .await
        .expect("send duplicate ClientHello");

    let mut raw2 = [0u8; CLIENT_HELLO_LEN];
    let n2 = server_socket.recv(&mut raw2).await.expect("recv duplicate ClientHello");
    assert_eq!(n2, CLIENT_HELLO_LEN);
    assert_eq!(raw2, hello_bytes);

    let second = run_server_handshake_v9_datagram(
        &mut server_socket,
        &server_kp,
        MESH_ID,
        SUITE_PREFS,
        |_ctx| true,
        &raw2,
        &cache,
    )
    .await
    .expect("server I/O must not error");
    assert!(
        second.is_none(),
        "a duplicate ClientHello must not produce a second handshake result"
    );

    let mut second_wire = [0u8; SERVER_HELLO_LEN];
    let n3 = client_socket.recv(&mut second_wire).await.expect("recv resent ServerHello");
    assert_eq!(n3, SERVER_HELLO_LEN);
    assert_eq!(
        first_wire, second_wire,
        "a retransmitted ClientHello must get the byte-identical ServerHello back"
    );

    // `first` is the only handshake result that was ever produced.
    let _ = first;
}

// ─────────────────────────────────────────────────────────────────────────────
// 5. The client adopts the server's ephemeral port
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn v9_datagram_client_adopts_server_ephemeral_port() {
    let (client_socket, _client_result, server_socket, _server_result, fixed_addr) =
        run_pair(0).await;

    let server_ephemeral_port = server_socket
        .local_addr()
        .expect("server socket local addr")
        .port();

    assert_ne!(
        server_ephemeral_port,
        fixed_addr.port(),
        "the server's per-peer ephemeral socket must not be bound to the fixed rendezvous port"
    );
    assert_eq!(
        client_socket.remote_addr().ip(),
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        "client must adopt a real loopback host as the server's reply source"
    );
    assert_eq!(
        client_socket.remote_addr().port(),
        server_ephemeral_port,
        "the client must adopt the server's new ephemeral port, not the fixed one it dialled"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 6. Credential carriage — appended to the ClientHello in the same datagram
// ─────────────────────────────────────────────────────────────────────────────

/// A client presenting a credential completes the handshake, the server's
/// `client_auth` closure receives the exact credential bytes the client
/// sent, and both sides derive identical session keys.
#[tokio::test]
async fn v9_datagram_credential_accepted_callback_sees_exact_bytes_keys_match() {
    let token = vec![0xBEu8; 52];
    let seen_scheme = Arc::new(AtomicU8::new(0xFF));
    let seen_scheme2 = Arc::clone(&seen_scheme);
    let seen_bytes: Arc<std::sync::Mutex<Vec<u8>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_bytes2 = Arc::clone(&seen_bytes);

    let (server_res, client_res) = run_pair_with_credential(0x01, token.clone(), move |ctx| {
        seen_scheme2.store(ctx.scheme_byte, Ordering::Relaxed);
        *seen_bytes2.lock().expect("test mutex must not be poisoned") = ctx.credential.to_vec();
        true
    })
    .await;

    assert_eq!(seen_scheme.load(Ordering::Relaxed), 0x01, "scheme_byte must reach the closure unchanged");
    assert_eq!(
        *seen_bytes.lock().expect("test mutex must not be poisoned"),
        token,
        "the closure must see the exact credential bytes the client sent"
    );

    let server_result = server_res
        .expect("server I/O must not error")
        .expect("server must accept a valid credentialed ClientHello");
    let client_result = client_res.expect("client datagram handshake must succeed");

    assert_eq!(
        *client_result.session_keys.client_write_key,
        *server_result.session_keys.client_write_key,
        "client_write_key must match on both sides with a credential present"
    );
    assert_eq!(
        *client_result.session_keys.server_write_key,
        *server_result.session_keys.server_write_key,
        "server_write_key must match on both sides with a credential present"
    );
}

/// A hello with no credential still completes, and the closure sees
/// `scheme_byte == 0x00` with an empty `credential` — unchanged from before
/// credential carriage existed. Driven through the same
/// `run_client_handshake_v9_datagram_with_credential` code path as the
/// credentialed test above (with `cred_scheme = 0x00` and an empty
/// credential), which is exactly what the plain
/// `run_client_handshake_v9_datagram` wraps.
#[tokio::test]
async fn v9_datagram_no_credential_still_completes_scheme_byte_zero() {
    let seen_scheme = Arc::new(AtomicU8::new(0xFF));
    let seen_scheme2 = Arc::clone(&seen_scheme);
    let seen_empty = Arc::new(AtomicBool::new(false));
    let seen_empty2 = Arc::clone(&seen_empty);

    let (server_res, client_res) = run_pair_with_credential(0x00, Vec::new(), move |ctx| {
        seen_scheme2.store(ctx.scheme_byte, Ordering::Relaxed);
        seen_empty2.store(ctx.credential.is_empty(), Ordering::Relaxed);
        true
    })
    .await;

    assert_eq!(seen_scheme.load(Ordering::Relaxed), 0x00, "scheme_byte must be 0 for a hello with no credential");
    assert!(seen_empty.load(Ordering::Relaxed), "credential must be empty for a hello with no credential");
    assert!(
        server_res.expect("server I/O must not error").is_some(),
        "server must accept a legacy, credential-free hello"
    );
    assert!(client_res.is_ok(), "client must succeed with no credential");
}

/// A `client_auth` closure that rejects the credential causes the server to
/// return `Ok(None)` (no `ServerHandshakeResult`, hence no tunnel) and to
/// send no `ServerHello` at all.
///
/// Built by hand rather than through `run_pair_with_credential`, so the
/// client side never enters its bounded retransmit loop (which would, on a
/// genuine rejection, spend the full ~3s worst-case wall-clock bound named
/// in `udp_handshake`'s own module docs before giving up) — the point being
/// proved here is entirely on the server's side of the wire.
#[tokio::test]
async fn v9_datagram_credential_rejected_by_closure_produces_no_tunnel() {
    use mirage_protocol::auth::v9::{
        compute_client_proof, gen_ephemeral, suite_to_id, V9ClientHello, WIRE_VERSION_V9,
    };
    use x25519_dalek::{PublicKey, StaticSecret};

    let server_kp = KeyPair::generate();
    let server_static_pub = server_kp.public.to_bytes();
    let client_static_priv = gen_client_static_priv();

    let (_e_priv_c, e_pub_c) = gen_ephemeral();
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_millis() as u64;
    let mut suite_ids = [0u8; 3];
    suite_ids[0] = suite_to_id(AeadSuite::ChaCha20Poly1305);
    let client_proof = compute_client_proof(
        &client_static_priv,
        &server_static_pub,
        &e_pub_c,
        MESH_ID,
        &suite_ids,
        ts_ms,
    );
    let client_static_pub = PublicKey::from(&StaticSecret::from(client_static_priv)).to_bytes();
    let hello = V9ClientHello {
        version: WIRE_VERSION_V9,
        suite_ids,
        e_pub_c,
        ts_ms,
        client_proof,
        client_static_pub,
        cred_scheme: 0x01,
        target_hint: 0,
    };
    let mut datagram = hello.to_wire().to_vec();
    datagram.extend_from_slice(&[0xAAu8; 52]);

    let fixed = UdpSocket::bind(loopback(0)).await.expect("bind fixed rendezvous socket");
    let fixed_addr = fixed.local_addr().expect("fixed local addr");
    let sender = UdpSocket::bind(loopback(0)).await.expect("bind sender socket");
    sender.send_to(&datagram, fixed_addr).await.expect("send ClientHello+credential");

    let mut raw = vec![0u8; CLIENT_HELLO_LEN + MAX_CREDENTIAL_LEN_DATAGRAM];
    let (n, client_addr) = fixed.recv_from(&mut raw).await.expect("recv datagram");

    let mut server_socket = UdpPeerSocket::bind_server_ephemeral(client_addr)
        .await
        .expect("bind server ephemeral socket");
    let cache = ServerHelloCache::new();

    let result = run_server_handshake_v9_datagram(
        &mut server_socket,
        &server_kp,
        MESH_ID,
        SUITE_PREFS,
        |_ctx| false,
        &raw[..n],
        &cache,
    )
    .await
    .expect("server I/O must not error");
    assert!(result.is_none(), "closure rejection must produce Ok(None) — no ServerHandshakeResult, no tunnel");

    // No ServerHello was ever sent for the sender to receive.
    let mut reply_buf = [0u8; SERVER_HELLO_LEN];
    let recv_attempt = tokio::time::timeout(Duration::from_millis(200), sender.recv_from(&mut reply_buf)).await;
    assert!(
        recv_attempt.is_err(),
        "no ServerHello may be sent when client_auth rejects the credential"
    );
}

/// A retransmitted ClientHello-plus-credential datagram returns the
/// byte-identical `ServerHello` and starts no second handshake — the
/// `ServerHelloCache` keys on `e_pub_c` alone, unaffected by the credential
/// riding alongside it in the same datagram.
#[tokio::test]
async fn v9_datagram_credential_retransmit_gets_identical_server_hello_no_new_keys() {
    use mirage_protocol::auth::v9::{
        compute_client_proof, gen_ephemeral, suite_to_id, V9ClientHello, WIRE_VERSION_V9,
    };
    use x25519_dalek::{PublicKey, StaticSecret};

    let server_kp = KeyPair::generate();
    let server_static_pub = server_kp.public.to_bytes();
    let client_static_priv = gen_client_static_priv();

    let (_e_priv_c, e_pub_c) = gen_ephemeral();
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_millis() as u64;
    let mut suite_ids = [0u8; 3];
    suite_ids[0] = suite_to_id(AeadSuite::ChaCha20Poly1305);
    let client_proof = compute_client_proof(
        &client_static_priv,
        &server_static_pub,
        &e_pub_c,
        MESH_ID,
        &suite_ids,
        ts_ms,
    );
    let client_static_pub = PublicKey::from(&StaticSecret::from(client_static_priv)).to_bytes();
    let hello = V9ClientHello {
        version: WIRE_VERSION_V9,
        suite_ids,
        e_pub_c,
        ts_ms,
        client_proof,
        client_static_pub,
        cred_scheme: 0x01,
        target_hint: 0,
    };
    let mut datagram = hello.to_wire().to_vec();
    let token = vec![0xCCu8; 52];
    datagram.extend_from_slice(&token);

    let fixed = UdpSocket::bind(loopback(0)).await.expect("bind fixed rendezvous socket");
    let fixed_addr = fixed.local_addr().expect("fixed local addr");
    let mut client_socket = UdpPeerSocket::bind_client(fixed_addr)
        .await
        .expect("bind client socket");

    client_socket.send(&datagram).await.expect("send first ClientHello+credential");

    let mut raw = vec![0u8; CLIENT_HELLO_LEN + MAX_CREDENTIAL_LEN_DATAGRAM];
    let (n, client_addr) = fixed.recv_from(&mut raw).await.expect("recv first ClientHello+credential");
    assert_eq!(&raw[..n], &datagram[..], "the datagram received must match exactly what was sent");

    let cache = ServerHelloCache::new();
    let mut server_socket = UdpPeerSocket::bind_server_ephemeral(client_addr)
        .await
        .expect("bind server ephemeral socket");

    let seen_credential: Arc<std::sync::Mutex<Vec<u8>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_credential2 = Arc::clone(&seen_credential);

    let first = run_server_handshake_v9_datagram(
        &mut server_socket,
        &server_kp,
        MESH_ID,
        SUITE_PREFS,
        move |ctx| {
            *seen_credential2.lock().expect("test mutex must not be poisoned") = ctx.credential.to_vec();
            true
        },
        &raw[..n],
        &cache,
    )
    .await
    .expect("server I/O must not error")
    .expect("first ClientHello+credential must produce a handshake result");
    assert_eq!(
        *seen_credential.lock().expect("test mutex must not be poisoned"),
        token,
        "the closure must see the credential on the first, authenticating call"
    );

    let mut first_wire = [0u8; SERVER_HELLO_LEN];
    let n1 = client_socket
        .recv_handshake_from_host(&mut first_wire)
        .await
        .expect("recv first ServerHello");
    assert_eq!(n1, SERVER_HELLO_LEN);

    // Client "retransmits" the identical ClientHello+credential datagram —
    // straight to the ephemeral socket, since that is what the client's
    // remote now points at.
    client_socket
        .send(&datagram)
        .await
        .expect("send duplicate ClientHello+credential");

    let mut raw2 = vec![0u8; CLIENT_HELLO_LEN + MAX_CREDENTIAL_LEN_DATAGRAM];
    let n2 = server_socket.recv(&mut raw2).await.expect("recv duplicate ClientHello+credential");
    assert_eq!(&raw2[..n2], &datagram[..]);

    let second = run_server_handshake_v9_datagram(
        &mut server_socket,
        &server_kp,
        MESH_ID,
        SUITE_PREFS,
        |_ctx| true,
        &raw2[..n2],
        &cache,
    )
    .await
    .expect("server I/O must not error");
    assert!(
        second.is_none(),
        "a duplicate ClientHello+credential must not produce a second handshake result"
    );

    let mut second_wire = [0u8; SERVER_HELLO_LEN];
    let n3 = client_socket.recv(&mut second_wire).await.expect("recv resent ServerHello");
    assert_eq!(n3, SERVER_HELLO_LEN);
    assert_eq!(
        first_wire, second_wire,
        "a retransmitted ClientHello+credential must get the byte-identical ServerHello back"
    );

    let _ = first;
}

/// A credential too large to fit fails loudly at send — before anything is
/// transmitted — naming both the credential's actual size and the cap it
/// exceeded, rather than being truncated or fragmented.
#[tokio::test]
async fn v9_datagram_oversized_credential_fails_loudly_at_send_naming_both_sizes() {
    let server_static_pub = [0x11u8; 32];
    let client_static_priv = gen_client_static_priv();
    let oversized = vec![0u8; MAX_CREDENTIAL_LEN_DATAGRAM + 1];

    // A destination nothing listens on: if this call sent anything at all,
    // the send itself would still succeed at the OS level (UDP has no
    // "nobody is listening" send-time error), so an `Err` here can only be
    // this function's own size guard running before any I/O.
    let dead_addr = loopback(1);
    let mut socket = UdpPeerSocket::bind_client(dead_addr).await.expect("bind client socket");

    let err = match run_client_handshake_v9_datagram_with_credential(
        &mut socket,
        &server_static_pub,
        &client_static_priv,
        MESH_ID,
        SUITE_PREFS,
        0x01,
        &oversized,
    )
    .await
    {
        Err(e) => e,
        Ok(_) => panic!("an oversized credential must fail before anything is sent"),
    };

    let msg = err.to_string();
    assert!(
        msg.contains(&oversized.len().to_string()),
        "error must name the credential's actual size ({}): {msg}",
        oversized.len()
    );
    assert!(
        msg.contains(&MAX_CREDENTIAL_LEN_DATAGRAM.to_string()),
        "error must name the cap it exceeded ({MAX_CREDENTIAL_LEN_DATAGRAM}): {msg}"
    );
}

/// KNOWN GAP, not introduced by this task: `client_proof` and `transcript_0`
/// (`crate::auth::v9::compute_client_proof` / `compute_transcript_0`) bind
/// `e_pub_c`, `server_static_pub`, `mesh_id`, the offered `suite_ids` and
/// `ts_ms` — never the credential bytes, on the stream V9 path or here. This
/// datagram path calls those same two functions with the same argument
/// lists the no-credential path always used, so it inherits the property
/// exactly rather than introducing it: an on-path party can substitute the
/// credential in flight without invalidating the proof or changing the
/// derived session keys. This test proves that directly instead of
/// asserting a protection that does not exist.
///
/// Not fixed here: doing so means changing `compute_client_proof`'s formula,
/// a wire-format change that (per this crate's own `AUTH_LABEL` rule)
/// requires a coordinated version bump across the whole live fleet — and
/// this task's brief is explicit that the stream handshake's behaviour,
/// which shares this formula, must not change.
#[tokio::test]
async fn v9_datagram_credential_tampering_is_not_caught_known_gap() {
    use mirage_protocol::auth::v9::{
        compute_client_proof, gen_ephemeral, suite_to_id, V9ClientHello, WIRE_VERSION_V9,
    };
    use x25519_dalek::{PublicKey, StaticSecret};

    let server_kp = KeyPair::generate();
    let server_static_pub = server_kp.public.to_bytes();
    let client_static_priv = gen_client_static_priv();

    let (_e_priv_c, e_pub_c) = gen_ephemeral();
    let ts_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock must be after the Unix epoch")
        .as_millis() as u64;
    let mut suite_ids = [0u8; 3];
    suite_ids[0] = suite_to_id(AeadSuite::ChaCha20Poly1305);
    let client_proof = compute_client_proof(
        &client_static_priv,
        &server_static_pub,
        &e_pub_c,
        MESH_ID,
        &suite_ids,
        ts_ms,
    );
    let client_static_pub = PublicKey::from(&StaticSecret::from(client_static_priv)).to_bytes();
    let hello = V9ClientHello {
        version: WIRE_VERSION_V9,
        suite_ids,
        e_pub_c,
        ts_ms,
        client_proof,
        client_static_pub,
        cred_scheme: 0x01,
        target_hint: 0,
    };
    let hello_wire = hello.to_wire();

    // The client "sent" this credential...
    let original_credential = vec![0xAAu8; 52];
    // ...but an on-path party swapped it for this one, same length, before
    // the datagram reached the server. The ClientHello prefix — and
    // therefore client_proof — is untouched by the swap.
    let tampered_credential = vec![0xBBu8; 52];
    let mut datagram = hello_wire.to_vec();
    datagram.extend_from_slice(&tampered_credential);

    let fixed = UdpSocket::bind(loopback(0)).await.expect("bind fixed rendezvous socket");
    let fixed_addr = fixed.local_addr().expect("fixed local addr");
    let sender = UdpSocket::bind(loopback(0)).await.expect("bind sender socket");
    sender.send_to(&datagram, fixed_addr).await.expect("send tampered datagram");

    let mut raw = vec![0u8; CLIENT_HELLO_LEN + MAX_CREDENTIAL_LEN_DATAGRAM];
    let (n, client_addr) = fixed.recv_from(&mut raw).await.expect("recv datagram");

    let mut server_socket = UdpPeerSocket::bind_server_ephemeral(client_addr)
        .await
        .expect("bind server ephemeral socket");
    let cache = ServerHelloCache::new();

    let seen_credential: Arc<std::sync::Mutex<Vec<u8>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen_credential2 = Arc::clone(&seen_credential);

    let result = run_server_handshake_v9_datagram(
        &mut server_socket,
        &server_kp,
        MESH_ID,
        SUITE_PREFS,
        move |ctx| {
            *seen_credential2.lock().expect("test mutex must not be poisoned") = ctx.credential.to_vec();
            true
        },
        &raw[..n],
        &cache,
    )
    .await
    .expect("server I/O must not error");

    assert!(
        result.is_some(),
        "the proof still verifies even though the credential was swapped in flight — \
         it does not cover the credential bytes (see this test's doc comment)"
    );
    assert_eq!(
        *seen_credential.lock().expect("test mutex must not be poisoned"),
        tampered_credential,
        "the closure sees the tampered bytes, undetected — original_credential never reaches it"
    );
    assert_ne!(tampered_credential, original_credential, "sanity: the test's own swap must be a real change");
}
