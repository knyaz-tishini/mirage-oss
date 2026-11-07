//! The helpers both end-to-end tests share.
//!
//! One file, two tests: the box's own wiring and the chain's two ends. The
//! helpers here are the customer's half of the wire — the handshake, the mux
//! session and the little plumbing around them.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};

use mirage_control_plane::EdgeWelcome;
use mirage_core::config::{AuthMode, MirageEndpointConfig, TransportCamouflage, TransportKind};
use mirage_protocol::client_transport::run_client_v9_transport_aware;
use mirage_protocol::traits::Tunnel;
use mirage_standalone::identity::ServerIdentity;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpListener;

/// The wire version this test's client speaks.
pub const HELLO_VERSION: u8 = 3;

/// A temp directory that cleans itself up.
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(tag: &str) -> Self {
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "mirage-standalone-e2e-{}-{}-{}",
            tag,
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&path).expect("temp dir");
        Self(path)
    }

    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A [`Tunnel`] seen as a futures stream — the shape the mux session wants.
///
/// The same trick the client's own relay uses: a duplex stream in the middle,
/// a task that pumps the tunnel into it.
pub struct TunnelCompat {
    stream: tokio::io::DuplexStream,
    _relay: tokio::task::JoinHandle<()>,
}

impl TunnelCompat {
    pub fn wrap(tunnel: Box<dyn Tunnel>) -> Self {
        let (app_side, tunnel_side) = tokio::io::duplex(1 << 20);
        let relay = tokio::spawn(async move {
            let mut tunnel = tunnel;
            let (mut rd, mut wr) = tokio::io::split(tunnel_side);
            let mut rbuf = vec![0u8; 16384];
            let mut wbuf = vec![0u8; 16384];
            loop {
                tokio::select! {
                    result = tunnel.recv(&mut rbuf) => match result {
                        Ok(0) => break,
                        Ok(n) => {
                            if wr.write_all(&rbuf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    },
                    result = rd.read(&mut wbuf) => match result {
                        Ok(0) => {
                            let _ = tunnel.close().await;
                            break;
                        }
                        Ok(n) => {
                            if tunnel.send(&wbuf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    },
                }
            }
        });
        Self {
            stream: app_side,
            _relay: relay,
        }
    }
}

impl futures::io::AsyncRead for TunnelCompat {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut read_buf = tokio::io::ReadBuf::new(buf);
        match Pin::new(&mut self.stream).poll_read(cx, &mut read_buf) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl futures::io::AsyncWrite for TunnelCompat {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // Tokio's write half closes on `poll_shutdown`; futures asks for
        // `poll_close`. One half-close, two names.
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// A TCP echo server — the "target" the box's exit connects to.
pub async fn spawn_echo_server(addr: std::net::IpAddr) -> SocketAddr {
    let listener = TcpListener::bind((addr, 0)).await.expect("echo listener");
    let addr = listener.local_addr().expect("echo addr");
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
    });
    addr
}

/// The host's own non-loopback IPv4 address, if it has one.
///
/// The box's exit refuses loopback UNCONDITIONALLY — that refusal is the
/// SSRF guard, and it is not a knob. So the target of this test has to live
/// on a real address of the host. A UDP "connect" picks the route the kernel
/// would use without sending a single packet.
pub async fn lan_ipv4() -> Option<std::net::Ipv4Addr> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await.ok()?;
    socket.connect("8.8.8.8:80").await.ok()?;
    let addr = socket.local_addr().ok()?;
    match addr.ip() {
        std::net::IpAddr::V4(v4) if !v4.is_loopback() => Some(v4),
        _ => None,
    }
}

/// A free TCP port on the loopback.
pub async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("probe listener");
    listener.local_addr().expect("probe addr").port()
}

/// A free UDP port on the loopback.
///
/// The node's own UDP endpoint binds this one, so it must be a UDP port —
/// the same number on TCP is a different port to the kernel.
pub async fn free_udp_port() -> u16 {
    let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.expect("probe socket");
    socket.local_addr().expect("probe addr").port()
}

/// Dial the box, retrying while it is still binding.
pub async fn dial_with_retry(
    face_addr: SocketAddr,
    identity: &ServerIdentity,
    camouflage: TransportCamouflage,
) -> Box<dyn Tunnel> {
    let server_pubkey = identity.node_wire().public.to_bytes();
    let client_static_priv = identity.subscriber().secret.to_bytes();
    let mesh_id = identity.mesh_id().as_bytes().to_vec();

    let config = MirageEndpointConfig {
        // The camouflage decides the transport; this field is derived from it.
        transport: TransportKind::Tcp,
        auth: AuthMode::Blake3,
        camouflage,
        byte_cipher: None,
        byte_cipher_mode: None,
    };

    let mut last = None;
    for _ in 0..50 {
        match run_client_v9_transport_aware(
            &config,
            face_addr,
            &server_pubkey,
            &client_static_priv,
            "",
            &mesh_id,
            None,
        )
        .await
        {
            Ok(tunnel) => return tunnel,
            Err(e) => {
                last = Some(e);
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
    }
    panic!("the box never answered: {:?}", last);
}

/// Read one `EdgeWelcome` off the tunnel.
pub async fn read_welcome(tunnel: &mut dyn Tunnel) -> EdgeWelcome {
    let mut buf = vec![0u8; 1024];
    let mut filled = 0usize;
    for _ in 0..50 {
        let n = tunnel.recv(&mut buf[filled..]).await.expect("recv welcome");
        if n == 0 {
            break;
        }
        filled += n;
        if let Ok((welcome, _)) = EdgeWelcome::decode(&buf[..filled]) {
            return welcome;
        }
    }
    panic!("the box never sent an EdgeWelcome");
}
