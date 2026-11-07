//! The end-to-end test.
//!
//! These are the tests that no unit test can replace: a server, a client, and
//! a byte that goes from the application, through the SOCKS5, through the
//! session, and out of the server to the target.
//!
//! The three of them are the three carriers: MWG (UDP with a junk burst),
//! QUIC (QUIC), and the SOCKS5 tube -- where the session rides inside a
//! CONNECT tunnel and the name of the server is resolved by the proxy.

use std::net::SocketAddr;

use mirage_core::crypto::KeyPair;
use mirage_vpn_cli::client;
use mirage_vpn_cli::config::{
    encode_public, encode_secret, ClientConfig, Exit, Listeners, MkvikListener, ServerConfig,
    ServerPeer, Transport,
};
use mirage_vpn_cli::server;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// The id both ends bake into the handshake.
const MESH_ID: &str = "mirage-vpn";

/// A target that echoes what it is sent.
async fn echo_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address = listener.local_addr().expect("addr");
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 4096];
                loop {
                    let Ok(count) = socket.read(&mut buffer).await else {
                        break;
                    };
                    if count == 0 {
                        break;
                    }
                    if socket.write_all(&buffer[..count]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    address
}

/// A port that is free right now.
///
/// The MWG and QUIC listeners bind their socket inside the protocol's own
/// driver, so the port has to be known before the server starts -- it cannot
/// be learned afterwards.
async fn free_udp_port() -> u16 {
    let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind");
    let port = socket.local_addr().expect("addr").port();
    drop(socket);
    port
}

/// A SOCKS5 proxy that connects where it is told and gets out of the way.
async fn fake_proxy(listener: TcpListener) {
    while let Ok((mut socket, _)) = listener.accept().await {
        tokio::spawn(async move {
            // The greeting.
            let mut greeting = [0u8; 2];
            if socket.read_exact(&mut greeting).await.is_err() {
                return;
            }
            let mut methods = vec![0u8; usize::from(greeting[1])];
            if socket.read_exact(&mut methods).await.is_err() {
                return;
            }
            if socket.write_all(&[0x05, 0x00]).await.is_err() {
                return;
            }
            // The request.
            let mut head = [0u8; 4];
            if socket.read_exact(&mut head).await.is_err() {
                return;
            }
            let (host, port) = match head[3] {
                0x01 => {
                    let mut address = [0u8; 4];
                    if socket.read_exact(&mut address).await.is_err() {
                        return;
                    }
                    let mut port = [0u8; 2];
                    if socket.read_exact(&mut port).await.is_err() {
                        return;
                    }
                    (
                        std::net::Ipv4Addr::from(address).to_string(),
                        u16::from_be_bytes(port),
                    )
                }
                0x03 => {
                    let mut length = [0u8; 1];
                    if socket.read_exact(&mut length).await.is_err() {
                        return;
                    }
                    let mut name = vec![0u8; usize::from(length[0])];
                    if socket.read_exact(&mut name).await.is_err() {
                        return;
                    }
                    let mut port = [0u8; 2];
                    if socket.read_exact(&mut port).await.is_err() {
                        return;
                    }
                    (
                        String::from_utf8_lossy(&name).to_string(),
                        u16::from_be_bytes(port),
                    )
                }
                _ => return,
            };
            let Ok(mut target) = TcpStream::connect((host.as_str(), port)).await else {
                let _ = socket
                    .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await;
                return;
            };
            if socket
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .is_err()
            {
                return;
            }
            // The relay.
            let mut to_target = vec![0u8; 4096];
            let mut to_client = vec![0u8; 4096];
            loop {
                tokio::select! {
                    read = socket.read(&mut to_target) => {
                        let Ok(count) = read else { break };
                        if count == 0 { break; }
                        if target.write_all(&to_target[..count]).await.is_err() { break; }
                    }
                    read = target.read(&mut to_client) => {
                        let Ok(count) = read else { break };
                        if count == 0 { break; }
                        if socket.write_all(&to_client[..count]).await.is_err() { break; }
                    }
                }
            }
        });
    }
}

/// Speak SOCKS5 to the client and carry a byte through it.
async fn carry_a_byte(socks5: SocketAddr, target: SocketAddr) {
    let mut socket = TcpStream::connect(socks5).await.expect("connect");
    // The greeting.
    socket.write_all(&[0x05, 0x01, 0x00]).await.expect("greeting");
    let mut answer = [0u8; 2];
    socket.read_exact(&mut answer).await.expect("answer");
    assert_eq!(answer, [0x05, 0x00], "no auth should be accepted");

    // The request: CONNECT to the target.
    let port = target.port().to_be_bytes();
    let request = [0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1, port[0], port[1]];
    socket.write_all(&request).await.expect("request");
    let mut head = [0u8; 4];
    socket.read_exact(&mut head).await.expect("reply");
    assert_eq!(head[0], 0x05);
    assert_eq!(head[1], 0x00, "the connection should be accepted");
    let mut bound = [0u8; 6];
    socket.read_exact(&mut bound).await.expect("bound");

    // The bytes go through.
    socket
        .write_all(b"through the tunnel")
        .await
        .expect("write");
    let mut buffer = vec![0u8; 18];
    socket.read_exact(&mut buffer).await.expect("read");
    assert_eq!(&buffer, b"through the tunnel");
}

/// The same, but over QUIC: the session rides in a real QUIC connection.
///
/// The box side of this path is the plane: the QUIC endpoint is a
/// `PlaneListener`, and the packets ride the datagrams of the same
/// connection. The client of this test still speaks the OLD carrier wire
/// (the V9 handshake over a QUIC camouflage stream), and the plane speaks
/// the mutual one -- so the two do not meet yet. The test waits for the
/// client to learn the plane; then it comes back.
#[tokio::test]
#[ignore = "the client speaks the old carrier wire; the plane client is not in yet"]
async fn a_byte_goes_through_the_vpn_over_mkvik() {
    let target = echo_server().await;
    let server_key = KeyPair::generate();
    let client_key = KeyPair::generate();
    let port = free_udp_port().await;

    let server = server::start(ServerConfig {
        private_key: encode_secret(&server_key),
        peers: vec![ServerPeer {
            public_key: encode_public(&client_key),
            name: Some("client".to_owned()),
        }],
        listeners: Listeners {
            mkvik: Some(MkvikListener {
                bind: format!("127.0.0.1:{port}").parse().expect("addr"),
                alpn: vec!["h3".to_owned()],
            }),
            ..Default::default()
        },
        mesh_id: MESH_ID.to_owned(),
        exit: Exit::Direct,
        metrics: None,
    })
    .await
    .expect("server");
    let server_addr = server
        .listeners
        .iter()
        .find(|(name, _)| *name == "mkvik")
        .map(|(_, address)| *address)
        .expect("the mkvik listener");

    let client = client::start(ClientConfig {
        private_key: encode_secret(&client_key),
        server_public_key: encode_public(&server_key),
        transport: Transport::Mkvik {
            server: server_addr,
            alpn: vec!["h3".to_owned()],
        },
        socks5_listen: "127.0.0.1:0".parse().expect("addr"),
        mesh_id: MESH_ID.to_owned(),
    })
    .await
    .expect("client");

    carry_a_byte(client.socks5, target).await;
}

/// The same, but the session rides inside a SOCKS5 CONNECT tunnel to the
/// server: the client talks to the proxy, and the proxy talks to the server.
#[tokio::test]
async fn a_byte_goes_through_the_vpn_through_a_socks5_proxy() {
    let target = echo_server().await;
    let server_key = KeyPair::generate();
    let client_key = KeyPair::generate();

    // The server waits for a session that arrives through the tunnel.
    let server = server::start(ServerConfig {
        private_key: encode_secret(&server_key),
        peers: vec![ServerPeer {
            public_key: encode_public(&client_key),
            name: Some("client".to_owned()),
        }],
        listeners: Listeners {
            tunnel: Some("127.0.0.1:0".parse().expect("addr")),
            ..Default::default()
        },
        mesh_id: MESH_ID.to_owned(),
        exit: Exit::Direct,
        metrics: None,
    })
    .await
    .expect("server");
    let server_addr = server
        .listeners
        .iter()
        .find(|(name, _)| *name == "tunnel")
        .map(|(_, address)| *address)
        .expect("the tunnel listener");

    // The proxy in between.
    let proxy = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let proxy_addr = proxy.local_addr().expect("addr");
    tokio::spawn(fake_proxy(proxy));

    let client = client::start(ClientConfig {
        private_key: encode_secret(&client_key),
        server_public_key: encode_public(&server_key),
        transport: Transport::Tunnel {
            server: format!("127.0.0.1:{}", server_addr.port()),
            proxy: proxy_addr,
        },
        socks5_listen: "127.0.0.1:0".parse().expect("addr"),
        mesh_id: MESH_ID.to_owned(),
    })
    .await
    .expect("client");

    carry_a_byte(client.socks5, target).await;
}
