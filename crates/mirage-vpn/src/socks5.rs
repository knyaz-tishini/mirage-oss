//! SOCKS5 (RFC 1928) on top of the flow plane.
//!
//! # The shape
//!
//! This is the shape a commercial VPN has, and the shape our client already
//! has: the application talks SOCKS5 to a local listener, the listener hands
//! the exit a target, and the exit opens the connection.
//!
//! ```text
//!   application
//!        │  SOCKS5 CONNECT example.com:443
//!   ┌────▼────────┐
//!   │ Socks5      │   client side: the listener
//!   │ listener    │
//!   └────┬────────┘
//!        │  Flow::open(target)
//!   ┌────▼────────┐
//!   │  FlowPlane  │   the session
//!   └────┬────────┘
//!        │  Flow::accept(target)
//!   ┌────▼────────┐   server side: the exit
//!   │   Exit      │
//!   └─────────────┘
//! ```
//!
//! # The name is not resolved here
//!
//! A CONNECT with a domain name is carried UNRESOLVED to the exit. The near
//! side never learns what the far side is connecting to, and the DNS query
//! does not leak the fact that a tunnel is in use.
//!
//! # Where the exit sends the traffic
//!
//! The exit is pluggable:
//!
//! - [`DirectExit`] opens the connection itself.
//! - [`Socks5Exit`] hands it to a local SOCKS5 proxy — that is how the
//!   server's own system TUN is used: the TUN service exposes its chains as
//!   SOCKS5 listeners, and the exit forwards the flow to it.
//!
//! # What is not here yet
//!
//! UDP ASSOCIATE is refused with a clear answer, not silently dropped. The
//! flow plane carries bytes, and a UDP association needs the datagram
//! boundaries and the relay address of RFC 1928 §7 — that is the next slice.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use crate::flow::{Flow, FlowError, FlowPlane, FlowReader, FlowWriter, Target};

/// The SOCKS5 version.
const VERSION: u8 = 0x05;
/// The only auth method: no auth.
const METHOD_NO_AUTH: u8 = 0x00;
/// The answer when no method is acceptable.
const METHOD_NO_ACCEPTABLE: u8 = 0xFF;

/// The CONNECT command.
const CMD_CONNECT: u8 = 0x01;
/// The UDP ASSOCIATE command.
const CMD_UDP_ASSOCIATE: u8 = 0x03;

/// The answer "the connection was made".
const REP_SUCCESS: u8 = 0x00;
/// The answer "the general failure".
const REP_GENERAL_FAILURE: u8 = 0x01;
/// The answer "the command is not supported".
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
/// The answer "the address type is not supported".
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;

/// What can go wrong on the SOCKS5 side.
#[derive(Debug, thiserror::Error)]
pub enum Socks5Error {
    /// The request is not a SOCKS5 request.
    #[error("the socks5 request is malformed: {0}")]
    Malformed(&'static str),

    /// The client offered no acceptable auth method.
    #[error("the socks5 client offered no acceptable auth method")]
    NoAcceptableAuthMethod,

    /// The command is not supported.
    #[error("the socks5 command {0} is not supported")]
    UnsupportedCommand(u8),

    /// The address type is not supported.
    #[error("the socks5 address type {0} is not supported")]
    UnsupportedAddressType(u8),

    /// The flow plane failed.
    #[error("the flow plane failed: {0}")]
    Flow(#[from] FlowError),

    /// The socket failed.
    #[error("the socket failed: {0}")]
    Io(#[from] std::io::Error),
}

/// A local SOCKS5 server whose flows travel inside the VPN.
///
/// This is what the application talks to. The listener is the client's
/// whole user-facing surface: no system TUN is needed for it.
pub struct Socks5Listener {
    bind: SocketAddr,
}

impl Socks5Listener {
    /// A listener on this address.
    pub fn new(bind: SocketAddr) -> Self {
        Self { bind }
    }

    /// The address the listener binds.
    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    /// Bind the listener and serve on it.
    ///
    /// The address it bound to is returned: the caller may have asked for
    /// port 0 and has to know where the listener landed.
    pub async fn serve(self, plane: FlowPlane) -> Result<SocketAddr, Socks5Error> {
        let listener = TcpListener::bind(self.bind).await?;
        let address = listener.local_addr()?;
        let plane = Arc::new(plane);
        tokio::spawn(async move {
            loop {
                let Ok((socket, _peer)) = listener.accept().await else {
                    break;
                };
                let plane = plane.clone();
                tokio::spawn(async move {
                    if let Err(err) = serve_connection(socket, plane).await {
                        tracing::debug!(%err, "a socks5 connection ended");
                    }
                });
            }
        });
        Ok(address)
    }
}

/// Serve one SOCKS5 connection.
async fn serve_connection(
    mut socket: TcpStream,
    plane: Arc<FlowPlane>,
) -> Result<(), Socks5Error> {
    // The greeting: the client offers the methods it knows.
    let mut greeting = [0u8; 2];
    socket.read_exact(&mut greeting).await?;
    if greeting[0] != VERSION {
        return Err(Socks5Error::Malformed("the version is not 5"));
    }
    let count = usize::from(greeting[1]);
    if count == 0 {
        return Err(Socks5Error::Malformed("no method was offered"));
    }
    let mut methods = vec![0u8; count];
    socket.read_exact(&mut methods).await?;
    if !methods.contains(&METHOD_NO_AUTH) {
        socket.write_all(&[VERSION, METHOD_NO_ACCEPTABLE]).await?;
        return Err(Socks5Error::NoAcceptableAuthMethod);
    }
    socket.write_all(&[VERSION, METHOD_NO_AUTH]).await?;

    // The request: the command and the destination.
    let mut head = [0u8; 4];
    socket.read_exact(&mut head).await?;
    if head[0] != VERSION {
        return Err(Socks5Error::Malformed("the version is not 5"));
    }
    let command = head[1];
    let atyp = head[3];
    let target = match read_target(&mut socket, atyp).await {
        Ok(target) => target,
        Err(Socks5Error::UnsupportedAddressType(_)) => {
            write_reply(&mut socket, REP_ADDRESS_TYPE_NOT_SUPPORTED, None).await?;
            return Err(Socks5Error::UnsupportedAddressType(atyp));
        }
        Err(err) => return Err(err),
    };
    if command != CMD_CONNECT {
        // UDP ASSOCIATE is not served yet — and it says so.
        write_reply(&mut socket, REP_COMMAND_NOT_SUPPORTED, None).await?;
        if command == CMD_UDP_ASSOCIATE {
            tracing::debug!("the client asked for a udp association, which is not served yet");
        }
        return Err(Socks5Error::UnsupportedCommand(command));
    }

    // Open the flow. The name goes to the exit unresolved.
    let flow = match plane.open(target).await {
        Ok(flow) => flow,
        Err(err) => {
            write_reply(&mut socket, REP_GENERAL_FAILURE, None).await?;
            return Err(err.into());
        }
    };
    write_reply(&mut socket, REP_SUCCESS, None).await?;
    relay(socket, flow).await
}

/// Read the destination of a request.
async fn read_target(socket: &mut TcpStream, atyp: u8) -> Result<Target, Socks5Error> {
    let payload: Vec<u8> = match atyp {
        0x01 => {
            let mut buf = [0u8; 6];
            socket.read_exact(&mut buf).await?;
            buf.to_vec()
        }
        0x04 => {
            let mut buf = [0u8; 18];
            socket.read_exact(&mut buf).await?;
            buf.to_vec()
        }
        0x03 => {
            let mut len = [0u8; 1];
            socket.read_exact(&mut len).await?;
            let mut buf = vec![0u8; 1 + usize::from(len[0]) + 2];
            buf[0] = len[0];
            socket.read_exact(&mut buf[1..]).await?;
            buf
        }
        other => {
            return Err(Socks5Error::UnsupportedAddressType(other));
        }
    };
    let mut whole = Vec::with_capacity(1 + payload.len());
    whole.push(atyp);
    whole.extend_from_slice(&payload);
    Target::decode(&whole).map_err(|_| Socks5Error::Malformed("the destination is malformed"))
}

/// Write the answer of a request.
async fn write_reply(
    socket: &mut TcpStream,
    code: u8,
    bound: Option<SocketAddr>,
) -> Result<(), Socks5Error> {
    let mut reply = vec![VERSION, code, 0x00];
    match bound {
        Some(SocketAddr::V4(addr)) => {
            reply.push(0x01);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
        Some(SocketAddr::V6(addr)) => {
            reply.push(0x04);
            reply.extend_from_slice(&addr.ip().octets());
            reply.extend_from_slice(&addr.port().to_be_bytes());
        }
        // The bound address is not known — and the answer says so with the
        // "any address" form.
        None => {
            reply.push(0x01);
            reply.extend_from_slice(&[0, 0, 0, 0]);
            reply.extend_from_slice(&0u16.to_be_bytes());
        }
    }
    socket.write_all(&reply).await?;
    Ok(())
}

/// Carry the bytes between a socket and a flow, both ways.
async fn relay(mut socket: TcpStream, flow: Flow) -> Result<(), Socks5Error> {
    let (mut reader, mut writer) = socket.split();
    let (mut flow_reader, mut flow_writer): (FlowReader, FlowWriter) = flow.split();
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            read = reader.read(&mut buffer) => {
                let count = read?;
                if count == 0 {
                    let _ = flow_writer.close().await;
                    break;
                }
                flow_writer.write(&buffer[..count]).await?;
            }
            data = flow_reader.read() => {
                let Some(bytes) = data else { break };
                if bytes.is_empty() {
                    break;
                }
                writer.write_all(&bytes).await?;
                writer.flush().await?;
            }
        }
    }
    Ok(())
}

/// Where the exit sends the flows.
///
/// The connector is shared by every flow of the box, and `connect` takes
/// `&self`. It used to be one lock held across the whole connection
/// attempt, so a single target that does not answer -- a name that resolves
/// to an address that drops the SYN, an IPv6 answer on a box without IPv6 --
/// held every OTHER flow of the box hostage until the operating system gave
/// up on the SYN. One dead host froze the whole exit, and the flows behind
/// it looked like a broken tunnel. The connector opens a socket per flow
/// anyway, so there is nothing shared that would need a lock.
#[async_trait::async_trait]
pub trait ExitConnector: Send + Sync {
    /// Open a connection toward the target.
    async fn connect(&self, target: &Target) -> Result<Box<dyn ExitStream>, FlowError>;
}

/// How long the exit waits for one connection attempt.
///
/// The operating system is far more patient: a SYN to an address that does
/// not answer is repeated for about two minutes before the connect is
/// called a failure. A flow waiting on a dead host must not sit in that
/// wait -- the browser on the other side has already given up, and the
/// attempt is left behind for nothing.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// One connection attempt, with the exit's own patience.
async fn connect_within(addr: SocketAddr, within: Duration) -> Result<TcpStream, FlowError> {
    match tokio::time::timeout(within, TcpStream::connect(addr)).await {
        Ok(result) => result.map_err(FlowError::Io),
        Err(_) => Err(FlowError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!("the address did not answer within {} s", within.as_secs()),
        ))),
    }
}

/// A connection to the target.
#[async_trait::async_trait]
pub trait ExitStream: Send {
    /// Read the bytes the target sent.
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error>;
    /// Write the bytes to the target.
    async fn write(&mut self, buf: &[u8]) -> Result<(), std::io::Error>;
}

#[async_trait::async_trait]
impl ExitStream for TcpStream {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
        AsyncReadExt::read(self, buf).await
    }
    async fn write(&mut self, buf: &[u8]) -> Result<(), std::io::Error> {
        AsyncWriteExt::write_all(self, buf).await
    }
}

/// The exit that opens the connection itself.
pub struct DirectExit;

#[async_trait::async_trait]
impl ExitConnector for DirectExit {
    async fn connect(&self, target: &Target) -> Result<Box<dyn ExitStream>, FlowError> {
        // The name is resolved HERE, at the exit — never on the near side.
        match target {
            Target::Addr(addr) => {
                let stream = connect_within(*addr, CONNECT_TIMEOUT).await?;
                Ok(Box::new(stream))
            }
            Target::Named(name, port) => {
                // EVERY answer is tried, in order. A name that resolves to an
                // unreachable IPv6 AND a reachable IPv4 is an ordinary name —
                // taking only the first answer loses the flow to an address
                // that has no route, while the very next answer works.
                let mut addresses = tokio::net::lookup_host((name.as_str(), *port)).await?;
                let mut last = None;
                while let Some(addr) = addresses.next() {
                    match connect_within(addr, CONNECT_TIMEOUT).await {
                        Ok(stream) => return Ok(Box::new(stream)),
                        Err(err) => {
                            tracing::debug!(%addr, error = %err, "the address did not answer — trying the next one");
                            last = Some(err);
                        }
                    }
                }
                Err(match last {
                    Some(err) => err,
                    None => FlowError::Closed,
                })
            }
        }
    }
}

/// The exit that hands the flow to a local SOCKS5 proxy.
///
/// This is how the server's own system TUN is used: the TUN service exposes
/// its chains as SOCKS5 listeners, and the exit forwards the flow to it.
pub struct Socks5Exit {
    proxy: SocketAddr,
}

impl Socks5Exit {
    /// An exit through this proxy.
    pub fn new(proxy: SocketAddr) -> Self {
        Self { proxy }
    }
}

#[async_trait::async_trait]
impl ExitConnector for Socks5Exit {
    async fn connect(&self, target: &Target) -> Result<Box<dyn ExitStream>, FlowError> {
        let mut socket = connect_within(self.proxy, CONNECT_TIMEOUT).await?;
        // The greeting: no auth.
        socket.write_all(&[VERSION, 0x01, METHOD_NO_AUTH]).await?;
        let mut answer = [0u8; 2];
        socket.read_exact(&mut answer).await?;
        if answer[0] != VERSION || answer[1] != METHOD_NO_AUTH {
            return Err(FlowError::Closed);
        }
        // The request: CONNECT to the target.
        let mut request = vec![VERSION, CMD_CONNECT, 0x00];
        request.extend_from_slice(&target.encode());
        socket.write_all(&request).await?;
        let mut head = [0u8; 4];
        socket.read_exact(&mut head).await?;
        if head[1] != REP_SUCCESS {
            return Err(FlowError::Closed);
        }
        // The bound address is not needed — but it has to be read off.
        let _ = read_target(&mut socket, head[3])
            .await
            .map_err(|_| FlowError::Closed)?;
        Ok(Box::new(socket))
    }
}

/// The exit: every flow the peer opens is carried to its target.
///
/// The connector is shared: the exit serves many flows at once, and each of
/// them opens its own connection.
pub async fn serve_exit(
    plane: FlowPlane,
    connector: Arc<dyn ExitConnector>,
) -> Result<(), Socks5Error> {
    while let Some((target, flow)) = plane.accept().await {
        let connector = connector.clone();
        tokio::spawn(async move {
            // No lock around the attempt: a target that does not answer must
            // not hold the other flows of this box behind it.
            let Ok(stream) = connector.connect(&target).await else { return };
            if let Err(err) = relay_stream(stream, flow).await {
                tracing::debug!(%err, "an exit flow ended");
            }
        });
    }
    Ok(())
}

/// Carry the bytes between a flow and the target's connection.
async fn relay_stream(mut stream: Box<dyn ExitStream>, flow: Flow) -> Result<(), Socks5Error> {
    let (mut flow_reader, mut flow_writer) = flow.split();
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            read = stream.read(&mut buffer) => {
                let count = read?;
                if count == 0 {
                    let _ = flow_writer.close().await;
                    break;
                }
                flow_writer.write(&buffer[..count]).await?;
            }
            data = flow_reader.read() => {
                let Some(bytes) = data else { break };
                if bytes.is_empty() {
                    break;
                }
                stream.write(&bytes).await?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MemoryTunnel;
    use tokio::sync::Mutex;

    /// The exit must not stop at the FIRST answer a name gives.
    ///
    /// `localhost` answers with both an IPv6 and an IPv4 address, and the
    /// IPv6 one is refused on a machine without an IPv6 listener. A exit that
    /// took only the first answer would lose the flow; this one tries the
    /// next address and the flow arrives.
    #[tokio::test]
    async fn the_exit_tries_every_address_a_name_answers_with() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a listener");
        let port = listener.local_addr().expect("the address").port();

        let mut exit = DirectExit;
        let stream = exit
            .connect(&Target::Named("localhost".to_owned(), port))
            .await
            .expect("the exit must reach the listener through SOME address");
        drop(stream);
    }

    /// A stream that says what it is.
    struct FakeStream {
        inbound: tokio::sync::mpsc::Receiver<Vec<u8>>,
        outbound: tokio::sync::mpsc::Sender<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl ExitStream for FakeStream {
        async fn read(&mut self, buf: &mut [u8]) -> Result<usize, std::io::Error> {
            let bytes = self
                .inbound
                .recv()
                .await
                .ok_or(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))?;
            let len = bytes.len().min(buf.len());
            buf[..len].copy_from_slice(&bytes[..len]);
            Ok(len)
        }
        async fn write(&mut self, buf: &[u8]) -> Result<(), std::io::Error> {
            self.outbound.send(buf.to_vec()).await.ok();
            Ok(())
        }
    }

    /// A connector that answers with a fake stream and remembers the target.
    struct FakeExit {
        seen: Arc<Mutex<Vec<Target>>>,
        inbound: std::sync::Mutex<Option<tokio::sync::mpsc::Receiver<Vec<u8>>>>,
        outbound: tokio::sync::mpsc::Sender<Vec<u8>>,
    }

    #[async_trait::async_trait]
    impl ExitConnector for FakeExit {
        async fn connect(&self, target: &Target) -> Result<Box<dyn ExitStream>, FlowError> {
            self.seen.lock().await.push(target.clone());
            let inbound = self
                .inbound
                .lock()
                .ok()
                .and_then(|mut slot| slot.take())
                .ok_or(FlowError::Closed)?;
            Ok(Box::new(FakeStream {
                inbound,
                outbound: self.outbound.clone(),
            }))
        }
    }

    /// A connector that hangs on one target and answers the other at once.
    struct HalfDeadExit;

    #[async_trait::async_trait]
    impl ExitConnector for HalfDeadExit {
        async fn connect(&self, target: &Target) -> Result<Box<dyn ExitStream>, FlowError> {
            match target {
                Target::Addr(addr) if addr.port() == 1 => {
                    // The target that never answers.
                    tokio::time::sleep(Duration::from_secs(30)).await;
                    Err(FlowError::Closed)
                }
                _ => Ok(Box::new(SilentStream)),
            }
        }
    }

    /// A stream that says nothing.
    struct SilentStream;

    #[async_trait::async_trait]
    impl ExitStream for SilentStream {
        async fn read(&mut self, _buf: &mut [u8]) -> Result<usize, std::io::Error> {
            Err(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
        }
        async fn write(&mut self, _buf: &[u8]) -> Result<(), std::io::Error> {
            Ok(())
        }
    }

    /// One dead target must not hold the other flows of the box.
    ///
    /// The exit used to hold ONE lock across the whole connection attempt.
    /// A target that does not answer -- a name that resolves to an address
    /// that drops the SYN, an IPv6 answer on a box without IPv6 -- kept
    /// every other flow of the box waiting with it, and the box looked dead
    /// while one host was unreachable.
    #[tokio::test]
    async fn a_dead_target_does_not_hold_the_other_flows() {
        let connector: Arc<dyn ExitConnector> = Arc::new(HalfDeadExit);

        let dead = {
            let connector = connector.clone();
            tokio::spawn(async move {
                let _ = connector
                    .connect(&Target::Addr("127.0.0.1:1".parse().expect("addr")))
                    .await;
            })
        };
        // Let the dead attempt take whatever it used to take.
        tokio::time::sleep(Duration::from_millis(50)).await;

        let live = tokio::time::timeout(
            Duration::from_secs(2),
            connector.connect(&Target::Addr("127.0.0.1:2".parse().expect("addr"))),
        )
        .await
        .expect("the live flow must not wait for the dead one")
        .expect("the live flow must be served");
        drop(live);
        dead.abort();
    }

    /// Two planes over one session, and a SOCKS5 client on one side.
    #[tokio::test]
    async fn a_socks5_client_reaches_the_exit_through_the_flow_plane() {
        let (client_tunnel, server_tunnel) = MemoryTunnel::pair();
        let client_plane = FlowPlane::start(client_tunnel);
        let server_plane = FlowPlane::start(server_tunnel);

        // The exit side: a connector that remembers the target.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let (_exit_in_tx, exit_in_rx) = tokio::sync::mpsc::channel(8);
        let (exit_out_tx, _exit_out_rx) = tokio::sync::mpsc::channel(8);
        let connector: Arc<dyn ExitConnector> = Arc::new(FakeExit {
            seen: seen.clone(),
            inbound: std::sync::Mutex::new(Some(exit_in_rx)),
            outbound: exit_out_tx,
        });
        let exit_plane = server_plane.clone();
        tokio::spawn(async move {
            let _ = serve_exit(exit_plane, connector).await;
        });

        // The client side: a SOCKS5 listener.
        let listener = Socks5Listener::new("127.0.0.1:0".parse().expect("addr"));
        let serve_plane = client_plane.clone();
        let bind = tokio::spawn(async move { listener.serve(serve_plane).await })
            .await
            .expect("task")
            .expect("bind");

        // A SOCKS5 client that asks for a name.
        let mut socket = TcpStream::connect(bind).await.expect("connect");
        socket
            .write_all(&[VERSION, 0x01, METHOD_NO_AUTH])
            .await
            .expect("greeting");
        let mut answer = [0u8; 2];
        socket.read_exact(&mut answer).await.expect("answer");
        assert_eq!(answer, [VERSION, METHOD_NO_AUTH]);

        // The request: CONNECT to a name, not to an address.
        let name = b"example.com";
        let mut request = vec![VERSION, CMD_CONNECT, 0x00, 0x03, name.len() as u8];
        request.extend_from_slice(name);
        request.extend_from_slice(&443u16.to_be_bytes());
        socket.write_all(&request).await.expect("request");

        let mut head = [0u8; 4];
        socket.read_exact(&mut head).await.expect("reply head");
        assert_eq!(head[1], REP_SUCCESS);
        let mut bound = [0u8; 6];
        socket.read_exact(&mut bound).await.expect("reply bound");

        // The exit saw the name — and it saw it unresolved.
        let seen = seen.lock().await;
        assert_eq!(seen.len(), 1);
        assert_eq!(
            seen[0],
            Target::Named("example.com".to_owned(), 443),
            "the name must reach the exit unresolved"
        );
    }

    #[tokio::test]
    async fn a_udp_association_is_refused_with_an_answer() {
        let (client_tunnel, server_tunnel) = MemoryTunnel::pair();
        let client_plane = FlowPlane::start(client_tunnel);
        let server_plane = FlowPlane::start(server_tunnel);

        let connector: Arc<dyn ExitConnector> = Arc::new(DirectExit);
        let exit_plane = server_plane.clone();
        tokio::spawn(async move {
            let _ = serve_exit(exit_plane, connector).await;
        });

        let listener = Socks5Listener::new("127.0.0.1:0".parse().expect("addr"));
        let serve_plane = client_plane.clone();
        let bind = tokio::spawn(async move { listener.serve(serve_plane).await })
            .await
            .expect("task")
            .expect("bind");

        let mut socket = TcpStream::connect(bind).await.expect("connect");
        socket
            .write_all(&[VERSION, 0x01, METHOD_NO_AUTH])
            .await
            .expect("greeting");
        let mut answer = [0u8; 2];
        socket.read_exact(&mut answer).await.expect("answer");

        // The request: UDP ASSOCIATE.
        socket
            .write_all(&[VERSION, CMD_UDP_ASSOCIATE, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .expect("request");
        let mut head = [0u8; 4];
        socket.read_exact(&mut head).await.expect("reply head");
        assert_eq!(head[1], REP_COMMAND_NOT_SUPPORTED);
    }
}
