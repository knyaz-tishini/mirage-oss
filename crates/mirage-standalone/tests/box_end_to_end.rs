//! The box, end to end.
//!
//! One test walks the whole path a customer's bytes take — and NOTHING in it
//! is mocked:
//!
//! ```text
//!   client ──▶ face (raw TCP, no camouflage)
//!                    │
//!              ┌─────▼─────────────────┐
//!              │  perimeter             │  really binds the face,
//!              │                       │  really classifies the bytes
//!              └─────┬─────────────────┘
//!                    │  box-local channel
//!              ┌─────▼─────────────────┐
//!              │  client entrance       │  really admits the subscriber
//!              │  (subscriber gate)     │  really muxes the session
//!              └─────┬─────────────────┘
//!                    │
//!              ┌─────▼─────────────────┐
//!              │  the box's own exit    │  really opens a socket
//!              └─────┬─────────────────┘
//!                    │
//!                target (echo)
//! ```
//!
//! The camouflage is `None` on purpose: this test is about the box's own
//! wiring, and a camouflage layer would add a TLS handshake to a test whose
//! subject is not the handshake. The camouflage's own stripping is the
//! perimeter's own test suite's business.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use mirage_control_plane::{
    EdgeHello, EdgeOutcome, EdgeWelcome, ExitPreference, StreamKind, StreamOpen, StreamTarget,
};
use mirage_core::config::{AuthMode, MirageEndpointConfig, TransportCamouflage, TransportKind};
use mirage_core::mirage::wire::{MirageCamouflage, MirageCarrier, Protocol};
use mirage_mux::tokio_compat::{SessionHandle, TokioMuxStream};
use mirage_protocol::camouflage::UdpCamouflageLayer;
use mirage_protocol::client_transport::run_client_v9_transport_aware;
use mirage_protocol::preamble::write_preamble;
use mirage_protocol::protocols::l4::quic::QuicCamouflage;
use mirage_protocol::traits::Tunnel;
use mirage_standalone::box_runtime::BoxRuntime;
use mirage_standalone::chain::{ChainHop, ChainSpec};
use mirage_standalone::env::Face;
use mirage_standalone::identity::ServerIdentity;
use mirage_standalone::node::StandaloneNode;
use mirage_standalone::subscriber::{subscriber_set_path, write_subscriber_set};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;


mod common;

use common::*;

#[tokio::test]
async fn a_subscriber_dials_the_box_and_its_own_exit_carries_the_bytes() {
    // The box's own decisions are what this test is about, so they are said
    // out loud: a perimeter that rejects a connection or an entrance that
    // cannot bind must be visible in the test's own output.
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();

    // The target must live on a real address of the host: the box's exit
    // refuses loopback unconditionally, and that refusal is the point.
    let Some(target_ip) = lan_ipv4().await else {
        eprintln!("skipped: this host has no non-loopback IPv4 address to run the target on");
        return;
    };

    let dir = TempDir::new("box");
    let identity = ServerIdentity::load_or_mint(dir.path()).expect("identity");
    // The allowlist is written with the CURRENT time: its entries carry a
    // TTL, and an allowlist minted in the past is an allowlist that has
    // already expired.
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_millis() as u64;
    write_subscriber_set(dir.path(), &identity, now_ms).expect("subscriber set");

    // The target the box's own exit will connect to.
    let echo_addr = spawn_echo_server(std::net::IpAddr::V4(target_ip)).await;

    // The face the customer dials.
    let face_port = free_port().await;
    let faces = vec![Face {
        port: face_port,
        id: "raw".to_owned(),
        protocol: Protocol::Mirage {
            carrier: MirageCarrier::Tcp,
            camouflage: MirageCamouflage::None,
        },
    }];

    // A solo chain: this box IS the exit.
    let local = ChainHop {
        addr: format!("127.0.0.1:{face_port}"),
        public_key: Some(identity.node_wire_pubkey_hex()),
        node_id: None,
        role: mirage_core::config::HopRole::Exit,
        camouflage: Some(TransportCamouflage::None),
        udp_addr: None,
    };
    let chain = ChainSpec::from_toml_str(&format!(
        "chain_id = \"e2e\"\n[[hop]]\naddr = \"{addr}\"\npublic_key = \"{key}\"\nrole = \"exit\"\n",
        addr = local.addr,
        key = identity.node_wire_pubkey_hex(),
    ))
    .expect("chain spec");

    // A solo box stands ALONE: it is not a hop of its own chain, it has no
    // chain listener, and it serves the customer on its own faces. That is
    // the difference between it and hop 0 of somebody else's chain — which
    // serves the chain on its faces and no customer at all.
    let node = StandaloneNode::build(&identity, &chain, None, &faces, None).expect("node");
    // The registry recomputes the fingerprint and refuses a spec that does
    // not match — this is the box's own check that the spec it built is the
    // spec the node reads.
    node.activate().await.expect("activate the node's listener spec");
    let box_runtime = BoxRuntime::build(
        &identity,
        node,
        &faces,
        // No UDP endpoints: this box publishes a raw TCP face only.
        &[],
        // No protocol doors on this path.
        &[],
        // No relays on this path.
        &[],
        subscriber_set_path(dir.path()),
        None,
        // The target is on the host's own private address, so the box is
        // deployed as an intranet exit for this test. The guard's own
        // refusal of loopback is covered by the exit port's own unit tests.
        true,
        // No chain leg: this box IS the exit.
        None,
        // No chain datagram door: this box is not a hop of a chain.
        None,
    )
    .expect("box runtime");

    let cancel = CancellationToken::new();
    let server = tokio::spawn({
        let cancel = cancel.clone();
        async move { box_runtime.serve(cancel).await }
    });

    // The face takes a moment to bind; the client's dial is the wait.
    let face_addr: SocketAddr = format!("127.0.0.1:{face_port}").parse().expect("face addr");
    let mut tunnel = dial_with_retry(face_addr, &identity, TransportCamouflage::None).await;

    // The edge-session hello.
    let hello = EdgeHello {
        version: HELLO_VERSION,
        exit: ExitPreference::Auto,
        flags: EdgeHello::FLAG_COMMIT,
        offered_ports: vec![face_port],
    };
    tunnel.send(&hello.encode().expect("hello")).await.expect("send hello");

    let welcome = read_welcome(tunnel.as_mut()).await;
    match welcome.outcome {
        EdgeOutcome::Accepted { .. } => {}
        other => panic!("the box admits its own subscriber: {other:?}"),
    }

    // The mux upgrade, then one stream to the target.
    let session = SessionHandle::client(TunnelCompat::wrap(tunnel));
    let opened = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        session.open_stream(),
    )
    .await
    .expect("the mux stream open must not hang")
    .expect("open mux stream");
    let mut stream = TokioMuxStream(opened);

    let target = StreamTarget::new(echo_addr.to_string()).expect("target");
    let open = StreamOpen {
        kind: StreamKind::Tcp,
        target,
    };
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        stream.write_all(&open.encode()).await.expect("send stream open");
        stream.flush().await.expect("flush stream open");
    })
    .await
    .expect("the stream open header must not hang");

    let payload = b"mirage standalone end to end";
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        stream.write_all(payload).await.expect("write payload");
        stream.flush().await.expect("flush payload");
    })
    .await
    .expect("the payload must not hang");

    let mut back = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        stream.read_exact(&mut back),
    )
    .await
    .expect("the echo must come back")
    .expect("read echo");
    assert_eq!(&back[..], &payload[..], "the bytes came back through the box's own exit");

    cancel.cancel();
    let _ = server.await;
}

/// The same box, reached over a QUIC protocol door instead of raw TCP.
///
/// QUIC is not a perimeter face and not a node UDP endpoint. The door speaks
/// QUIC, then the shared target preamble, then raw bytes to the box's exit.
/// The Mirage TCP face stays so the node still has a face to build. The
/// bytes that come back came back through the QUIC door.
#[tokio::test]
async fn a_subscriber_dials_the_box_over_quic_and_its_own_exit_carries_the_bytes() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .with_test_writer()
        .try_init();

    let Some(target_ip) = lan_ipv4().await else {
        eprintln!("skipped: this host has no non-loopback IPv4 address to run the target on");
        return;
    };

    let dir = TempDir::new("quic");
    let identity = ServerIdentity::load_or_mint(dir.path()).expect("identity");
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("the clock is after 1970")
        .as_millis() as u64;
    write_subscriber_set(dir.path(), &identity, now_ms).expect("subscriber set");

    let echo_addr = spawn_echo_server(std::net::IpAddr::V4(target_ip)).await;

    // The perimeter's face: a raw TCP port.
    let face_port = free_port().await;
    let faces = vec![Face {
        port: face_port,
        id: "raw".to_owned(),
        protocol: Protocol::Mirage {
            carrier: MirageCarrier::Tcp,
            camouflage: MirageCamouflage::None,
        },
    }];

    // QUIC is its own door. The node holds no UDP endpoint for it.
    let quic_port = free_udp_port().await;
    let quic_addr: SocketAddr = format!("127.0.0.1:{quic_port}").parse().expect("quic addr");
    let doors = vec![Face {
        port: quic_port,
        id: "quic".to_owned(),
        protocol: Protocol::Quic { alpn: vec!["h3".to_owned()] },
    }];

    let local = ChainHop {
        addr: format!("127.0.0.1:{face_port}"),
        public_key: Some(identity.node_wire_pubkey_hex()),
        node_id: None,
        role: mirage_core::config::HopRole::Exit,
        camouflage: Some(TransportCamouflage::None),
        udp_addr: None,
    };
    let chain = ChainSpec::from_toml_str(&format!(
        "chain_id = \"e2e-quic\"\n[[hop]]\naddr = \"{addr}\"\npublic_key = \"{key}\"\nrole = \"exit\"\n",
        addr = local.addr,
        key = identity.node_wire_pubkey_hex(),
    ))
    .expect("chain spec");

    // The box stands alone: it serves the customer and exits from itself, so
    // it is not a hop of a chain and holds no chain listener.
    let node = StandaloneNode::build(&identity, &chain, None, &faces, None).expect("node");
    node.activate().await.expect("activate the node's listener spec");
    let box_runtime = BoxRuntime::build(
        &identity,
        node,
        &faces,
        &[],
        &doors,
        // No relays on this path.
        &[],
        subscriber_set_path(dir.path()),
        None,
        true,
        // No chain leg: this box IS the exit.
        None,
        // No chain datagram door: this box is not a hop of a chain.
        None,
    )
    .expect("box runtime");

    let cancel = CancellationToken::new();
    let server = tokio::spawn({
        let cancel = cancel.clone();
        async move { box_runtime.serve(cancel).await }
    });

    let layer = QuicCamouflage::new(vec!["h3".to_owned()]).expect("quic layer");
    let mut opened = None;
    for _ in 0..50 {
        match layer.connect_client(quic_addr, "mirage.local").await {
            Ok(stream) => {
                opened = Some(stream);
                break;
            }
            Err(_) => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
        }
    }
    let mut stream = opened.expect("the quic door accepts");
    write_preamble(&mut stream, &target_ip.to_string(), echo_addr.port())
        .await
        .expect("preamble");

    let payload = b"mirage standalone end to end over quic";
    tokio::time::timeout(std::time::Duration::from_secs(20), async {
        stream.write_all(payload).await.expect("write payload");
        stream.flush().await.expect("flush payload");
    })
    .await
    .expect("the payload must not hang");

    let mut back = vec![0u8; payload.len()];
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        stream.read_exact(&mut back),
    )
    .await
    .expect("the echo must come back")
    .expect("read echo");
    assert_eq!(
        &back[..],
        &payload[..],
        "the bytes came back through the box's own exit, over QUIC"
    );

    cancel.cancel();
    let _ = server.await;
}

