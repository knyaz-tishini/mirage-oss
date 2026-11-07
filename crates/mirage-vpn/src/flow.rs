//! The flow plane: one session, many flows.
//!
//! # Why flows and not only packets
//!
//! The packet plane (`packet.rs`, `router.rs`) is the WireGuard shape: the
//! tunnel carries IP packets and the node routes them. That shape needs an
//! L3 interface on both ends — a system TUN.
//!
//! But the client does not always have one, and it does not need one: the
//! way commercial VPNs work is that the application talks SOCKS5 to a local
//! listener, and the listener carries the flow to the exit. The exit opens
//! the connection and the bytes come back. No TUN anywhere.
//!
//! The client already has exactly that shape: its own SOCKS5 server hands
//! the exit a *target* — a name or an address with a port — and the exit
//! resolves it. A name is never resolved on the near side.
//!
//! This module is the flow plane of the VPN: the same session, the same
//! keys, the same rekey — but the payload is a flow, not a packet.
//!
//! ```text
//!   application
//!        │  SOCKS5 CONNECT example.com:443
//!   ┌────▼──────┐
//!   │ SOCKS5    │   client side
//!   │ listener  │
//!   └────┬──────┘
//!        │  FlowMessage::Open { target }
//!   ┌────▼──────┐   session (keys, nonces, rekey)
//!   │  Session  │
//!   └────┬──────┘
//!        │  FlowMessage::Data
//!   ┌────▼──────┐   server side
//!   │   Exit    │   opens the connection, relays the bytes
//!   └───────────┘
//! ```

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use mirage_protocol::traits::Tunnel;
use tokio::sync::{mpsc, oneshot};

use crate::channel::{Channel, ChannelError};

/// The kind of a flow message.
const KIND_OPEN: u8 = 1;
const KIND_OPENED: u8 = 2;
const KIND_DATA: u8 = 3;
const KIND_CLOSE: u8 = 4;

/// The address type of an IPv4 target.
const ATYP_IPV4: u8 = 0x01;
/// The address type of a domain target.
const ATYP_DOMAIN: u8 = 0x03;
/// The address type of an IPv6 target.
const ATYP_IPV6: u8 = 0x04;

/// What can go wrong on the flow plane.
#[derive(Debug, thiserror::Error)]
pub enum FlowError {
    /// The message is not a flow message.
    #[error("the flow message is malformed: {0}")]
    Malformed(&'static str),

    /// The peer sent a message about a flow this side does not know.
    #[error("the peer sent a message about an unknown flow")]
    UnknownFlow,

    /// The session failed.
    #[error("the session failed: {0}")]
    Channel(#[from] ChannelError),

    /// The plane is closed.
    #[error("the flow plane is closed")]
    Closed,

    /// The socket failed.
    #[error("the socket failed: {0}")]
    Io(#[from] std::io::Error),
}

/// Where a flow is going.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    /// An address and a port.
    Addr(SocketAddr),
    /// A name and a port.
    ///
    /// The name is NOT resolved here: it is resolved at the exit, so that the
    /// near side never learns what the far side is connecting to.
    Named(String, u16),
}

impl Target {
    /// The bytes of the target, in the SOCKS5 shape.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Target::Addr(addr) => match addr {
                SocketAddr::V4(addr) => {
                    let mut out = Vec::with_capacity(7);
                    out.push(ATYP_IPV4);
                    out.extend_from_slice(&addr.ip().octets());
                    out.extend_from_slice(&addr.port().to_be_bytes());
                    out
                }
                SocketAddr::V6(addr) => {
                    let mut out = Vec::with_capacity(19);
                    out.push(ATYP_IPV6);
                    out.extend_from_slice(&addr.ip().octets());
                    out.extend_from_slice(&addr.port().to_be_bytes());
                    out
                }
            },
            Target::Named(name, port) => {
                let mut out = Vec::with_capacity(2 + name.len());
                out.push(ATYP_DOMAIN);
                out.push(name.len() as u8);
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(&port.to_be_bytes());
                out
            }
        }
    }

    /// Read a target out of the SOCKS5 shape.
    pub fn decode(bytes: &[u8]) -> Result<Target, FlowError> {
        if bytes.is_empty() {
            return Err(FlowError::Malformed("the target is empty"));
        }
        match bytes[0] {
            ATYP_IPV4 => {
                if bytes.len() != 7 {
                    return Err(FlowError::Malformed("an IPv4 target is 7 bytes"));
                }
                let ip = std::net::Ipv4Addr::new(bytes[1], bytes[2], bytes[3], bytes[4]);
                let port = u16::from_be_bytes([bytes[5], bytes[6]]);
                Ok(Target::Addr(SocketAddr::new(ip.into(), port)))
            }
            ATYP_IPV6 => {
                if bytes.len() != 19 {
                    return Err(FlowError::Malformed("an IPv6 target is 19 bytes"));
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&bytes[1..17]);
                let port = u16::from_be_bytes([bytes[17], bytes[18]]);
                Ok(Target::Addr(SocketAddr::new(
                    std::net::Ipv6Addr::from(octets).into(),
                    port,
                )))
            }
            ATYP_DOMAIN => {
                if bytes.len() < 2 {
                    return Err(FlowError::Malformed("a named target is too short"));
                }
                let len = usize::from(bytes[1]);
                if bytes.len() != 2 + len + 2 {
                    return Err(FlowError::Malformed("a named target has the wrong length"));
                }
                let name = String::from_utf8_lossy(&bytes[2..2 + len]).to_string();
                let port = u16::from_be_bytes([bytes[2 + len], bytes[3 + len]]);
                Ok(Target::Named(name, port))
            }
            _ => Err(FlowError::Malformed("the address type is not known")),
        }
    }
}

/// One message of the flow plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlowMessage {
    /// Open a flow toward a target. The near side sends it.
    Open {
        /// The number of the flow.
        id: u16,
        /// Where the flow goes.
        target: Target,
    },
    /// The flow is open. The far side answers it.
    Opened {
        /// The number of the flow.
        id: u16,
        /// The address the flow was bound to, when it has one.
        bound: Option<SocketAddr>,
    },
    /// The bytes of the flow.
    Data {
        /// The number of the flow.
        id: u16,
        /// The bytes.
        bytes: Vec<u8>,
    },
    /// The flow is closed.
    Close {
        /// The number of the flow.
        id: u16,
    },
}

impl FlowMessage {
    /// The bytes that go on the wire.
    pub fn encode(&self) -> Vec<u8> {
        let (id, kind, payload): (u16, u8, Vec<u8>) = match self {
            FlowMessage::Open { id, target } => (*id, KIND_OPEN, target.encode()),
            FlowMessage::Opened { id, bound } => {
                let payload = match bound {
                    Some(addr) => Target::Addr(*addr).encode(),
                    None => Vec::new(),
                };
                (*id, KIND_OPENED, payload)
            }
            FlowMessage::Data { id, bytes } => (*id, KIND_DATA, bytes.clone()),
            FlowMessage::Close { id } => (*id, KIND_CLOSE, Vec::new()),
        };
        let mut out = Vec::with_capacity(5 + payload.len());
        out.extend_from_slice(&id.to_be_bytes());
        out.push(kind);
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend_from_slice(&payload);
        out
    }

    /// Read a message out of the wire.
    pub fn decode(bytes: &[u8]) -> Result<FlowMessage, FlowError> {
        if bytes.len() < 5 {
            return Err(FlowError::Malformed("the message is too short"));
        }
        let id = u16::from_be_bytes([bytes[0], bytes[1]]);
        let kind = bytes[2];
        let len = usize::from(u16::from_be_bytes([bytes[3], bytes[4]]));
        if bytes.len() != 5 + len {
            return Err(FlowError::Malformed("the message has the wrong length"));
        }
        let payload = &bytes[5..];
        match kind {
            KIND_OPEN => Ok(FlowMessage::Open {
                id,
                target: Target::decode(payload)?,
            }),
            KIND_OPENED => {
                let bound = if payload.is_empty() {
                    None
                } else {
                    match Target::decode(payload)? {
                        Target::Addr(addr) => Some(addr),
                        Target::Named(..) => {
                            return Err(FlowError::Malformed("the bound address is a name"))
                        }
                    }
                };
                Ok(FlowMessage::Opened { id, bound })
            }
            KIND_DATA => Ok(FlowMessage::Data {
                id,
                bytes: payload.to_vec(),
            }),
            KIND_CLOSE => Ok(FlowMessage::Close { id }),
            _ => Err(FlowError::Malformed("the kind is not known")),
        }
    }
}

/// What the far side is told about a flow.
enum FlowOut {
    /// Bytes.
    Data(Vec<u8>),
    /// The flow is closed.
    Close,
}

/// One flow: a duplex channel of bytes.
pub struct Flow {
    id: u16,
    inbound: mpsc::Receiver<Vec<u8>>,
    outbound: mpsc::Sender<(u16, FlowOut)>,
}

impl std::fmt::Debug for Flow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Flow").field("id", &self.id).finish()
    }
}

impl Flow {
    /// The number of the flow.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Read the bytes the far side sent.
    ///
    /// `None` means the flow is closed.
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        self.inbound.recv().await
    }

    /// Send bytes to the far side.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), FlowError> {
        self.outbound
            .send((self.id, FlowOut::Data(bytes.to_vec())))
            .await
            .map_err(|_| FlowError::Closed)
    }

    /// Close the flow.
    pub async fn close(&mut self) -> Result<(), FlowError> {
        self.outbound
            .send((self.id, FlowOut::Close))
            .await
            .map_err(|_| FlowError::Closed)
    }

    /// Split the flow into its two halves.
    ///
    /// Two halves can be held by two tasks at once — one reads, one writes.
    /// A single flow cannot: reading and writing at the same time is what a
    /// relay does, and a relay needs both directions at once.
    pub fn split(self) -> (FlowReader, FlowWriter) {
        (
            FlowReader {
                inbound: self.inbound,
            },
            FlowWriter {
                id: self.id,
                outbound: self.outbound,
            },
        )
    }
}

/// The reading half of a flow.
pub struct FlowReader {
    inbound: mpsc::Receiver<Vec<u8>>,
}

impl FlowReader {
    /// Read the bytes the far side sent.
    ///
    /// `None` means the flow is closed.
    pub async fn read(&mut self) -> Option<Vec<u8>> {
        self.inbound.recv().await
    }

    /// Poll for the next chunk of bytes, without a future of its own.
    ///
    /// This is what an `AsyncRead` implementation needs: the chunk is handed
    /// over as it arrives, and the caller's task is woken by the channel.
    pub fn poll_chunk(&mut self, cx: &mut std::task::Context<'_>) -> std::task::Poll<Option<Vec<u8>>> {
        self.inbound.poll_recv(cx)
    }
}

/// The writing half of a flow.
pub struct FlowWriter {
    id: u16,
    outbound: mpsc::Sender<(u16, FlowOut)>,
}

impl FlowWriter {
    /// Send bytes to the far side.
    pub async fn write(&mut self, bytes: &[u8]) -> Result<(), FlowError> {
        self.outbound
            .send((self.id, FlowOut::Data(bytes.to_vec())))
            .await
            .map_err(|_| FlowError::Closed)
    }

    /// Close the flow.
    pub async fn close(&mut self) -> Result<(), FlowError> {
        self.outbound
            .send((self.id, FlowOut::Close))
            .await
            .map_err(|_| FlowError::Closed)
    }

    /// Send the bytes to the far side, in a future that owns what it needs.
    ///
    /// The future does not borrow the writer, so it can be kept across a
    /// `poll_write` — which is what an `AsyncWrite` implementation needs.
    pub fn write_owned(
        &self,
        bytes: Vec<u8>,
    ) -> impl std::future::Future<Output = Result<(), FlowError>> + Send + 'static {
        let sender = self.outbound.clone();
        let id = self.id;
        async move {
            sender
                .send((id, FlowOut::Data(bytes)))
                .await
                .map_err(|_| FlowError::Closed)
        }
    }

    /// Close the flow, in a future that owns what it needs.
    pub fn close_owned(
        &self,
    ) -> impl std::future::Future<Output = Result<(), FlowError>> + Send + 'static {
        let sender = self.outbound.clone();
        let id = self.id;
        async move {
            sender
                .send((id, FlowOut::Close))
                .await
                .map_err(|_| FlowError::Closed)
        }
    }
}

/// The request to open a flow.
struct OpenRequest {
    target: Target,
    reply: oneshot::Sender<Result<Flow, FlowError>>,
}

/// The state of one live flow.
struct FlowState {
    /// Where the bytes of the flow are delivered.
    inbound_tx: mpsc::Sender<Vec<u8>>,
    /// The other end of that channel — it is handed over when the far side
    /// confirms the flow.
    inbound_rx: Option<mpsc::Receiver<Vec<u8>>>,
    /// Where the "the flow is open" answer goes, when the flow was opened
    /// by this side and the answer has not come yet.
    ack: Option<oneshot::Sender<Result<Flow, FlowError>>>,
}

/// The flow plane of one session.
#[derive(Clone)]
pub struct FlowPlane {
    requests: mpsc::Sender<OpenRequest>,
    /// The flows the far side opened.
    ///
    /// Behind a lock: two clones of the plane share one queue of accepted
    /// flows, so the exit can be served by more than one task.
    accepted: Arc<tokio::sync::Mutex<mpsc::Receiver<(Target, Flow)>>>,
}

impl FlowPlane {
    /// Start the flow plane on a session.
    ///
    /// The session belongs to the plane from this moment: the plane runs it in
    /// a task of its own.
    pub fn start(tunnel: Box<dyn Tunnel>) -> Self {
        let (requests_tx, requests_rx) = mpsc::channel(16);
        let (accepted_tx, accepted_rx) = mpsc::channel(16);
        tokio::spawn(async move {
            run(Channel::new(tunnel), requests_rx, accepted_tx).await;
        });
        Self {
            requests: requests_tx,
            accepted: Arc::new(tokio::sync::Mutex::new(accepted_rx)),
        }
    }

    /// Open a flow toward a target.
    ///
    /// The answer comes when the far side has opened the flow: the caller
    /// does not hold a flow that the far side never took.
    pub async fn open(&self, target: Target) -> Result<Flow, FlowError> {
        let (reply, wait) = oneshot::channel();
        self.requests
            .send(OpenRequest { target, reply })
            .await
            .map_err(|_| FlowError::Closed)?;
        wait.await.map_err(|_| FlowError::Closed)?
    }

    /// Accept the next flow the far side opened.
    pub async fn accept(&self) -> Option<(Target, Flow)> {
        let mut accepted = self.accepted.lock().await;
        accepted.recv().await
    }
}

/// The task that carries the flows.
async fn run(
    mut channel: Channel,
    mut requests: mpsc::Receiver<OpenRequest>,
    accepted: mpsc::Sender<(Target, Flow)>,
) {
    let mut flows: HashMap<u16, FlowState> = HashMap::new();
    let mut next_id: u16 = 1;
    let (outbound_tx, mut outbound_rx) = mpsc::channel::<(u16, FlowOut)>(256);

    loop {
        tokio::select! {
            request = requests.recv() => {
                let Some(request) = request else { break };
                let id = next_id;
                next_id = next_id.wrapping_add(1);
                if next_id == 0 {
                    next_id = 1;
                }
                let (ack_tx, ack_rx) = oneshot::channel();
                let (inbound_tx, inbound_rx) = mpsc::channel(64);
                flows.insert(id, FlowState {
                    inbound_tx,
                    inbound_rx: Some(inbound_rx),
                    ack: Some(ack_tx),
                });
                let message = FlowMessage::Open { id, target: request.target.clone() };
                if channel.send(&message.encode()).await.is_err() {
                    break;
                }
                // The flow is handed over when the far side answers.
                tokio::spawn(async move {
                    let answer = ack_rx.await;
                    let _ = request.reply.send(answer.unwrap_or(Err(FlowError::Closed)));
                });
            }
            out = outbound_rx.recv() => {
                let Some((id, message)) = out else { break };
                let is_close = matches!(message, FlowOut::Close);
                let flow_message = match message {
                    FlowOut::Data(bytes) => FlowMessage::Data { id, bytes },
                    FlowOut::Close => FlowMessage::Close { id },
                };
                if channel.send(&flow_message.encode()).await.is_err() {
                    break;
                }
                if is_close {
                    flows.remove(&id);
                }
            }
            message = channel.recv() => {
                let Ok(payload) = message else { break };
                let Ok(flow_message) = FlowMessage::decode(&payload) else { break };
                match flow_message {
                    FlowMessage::Open { id, target } => {
                        let (inbound_tx, inbound_rx) = mpsc::channel(64);
                        flows.insert(id, FlowState {
                            inbound_tx,
                            inbound_rx: None,
                            ack: None,
                        });
                        let flow = Flow {
                            id,
                            inbound: inbound_rx,
                            outbound: outbound_tx.clone(),
                        };
                        let answer = FlowMessage::Opened { id, bound: None };
                        if channel.send(&answer.encode()).await.is_err() {
                            break;
                        }
                        if accepted.send((target, flow)).await.is_err() {
                            break;
                        }
                    }
                    FlowMessage::Opened { id, bound } => {
                        let Some(state) = flows.get_mut(&id) else { continue };
                        let Some(ack) = state.ack.take() else { continue };
                        let Some(inbound_rx) = state.inbound_rx.take() else { continue };
                        let flow = Flow {
                            id,
                            inbound: inbound_rx,
                            outbound: outbound_tx.clone(),
                        };
                        let _ = ack.send(Ok(flow));
                        let _ = bound;
                    }
                    FlowMessage::Data { id, bytes } => {
                        if let Some(state) = flows.get(&id) {
                            let _ = state.inbound_tx.send(bytes).await;
                        }
                    }
                    FlowMessage::Close { id } => {
                        flows.remove(&id);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::MemoryTunnel;

    #[test]
    fn an_address_target_round_trips() {
        let target = Target::Addr("192.0.2.10:443".parse().expect("addr"));
        assert_eq!(Target::decode(&target.encode()).expect("decode"), target);
        let target = Target::Addr("[2001:db8::1]:443".parse().expect("addr"));
        assert_eq!(Target::decode(&target.encode()).expect("decode"), target);
    }

    #[test]
    fn a_named_target_round_trips() {
        let target = Target::Named("example.com".to_owned(), 443);
        assert_eq!(Target::decode(&target.encode()).expect("decode"), target);
    }

    #[test]
    fn a_message_round_trips() {
        let message = FlowMessage::Open {
            id: 7,
            target: Target::Named("example.com".to_owned(), 443),
        };
        assert_eq!(
            FlowMessage::decode(&message.encode()).expect("decode"),
            message
        );
        let message = FlowMessage::Data {
            id: 7,
            bytes: vec![1, 2, 3],
        };
        assert_eq!(
            FlowMessage::decode(&message.encode()).expect("decode"),
            message
        );
    }

    #[test]
    fn a_truncated_message_is_refused() {
        let message = FlowMessage::Data {
            id: 1,
            bytes: vec![1, 2, 3],
        };
        let bytes = message.encode();
        assert!(FlowMessage::decode(&bytes[..4]).is_err());
        assert!(FlowMessage::decode(&bytes[..bytes.len() - 1]).is_err());
    }

    #[tokio::test]
    async fn a_flow_carries_bytes_both_ways() {
        let (client_tunnel, server_tunnel) = MemoryTunnel::pair();

        let client_plane = FlowPlane::start(client_tunnel);
        let server_plane = FlowPlane::start(server_tunnel);

        // The client opens a flow; the server takes it.
        let opener = client_plane.clone();
        let open_task = tokio::spawn(async move {
            opener.open(Target::Named("example.com".to_owned(), 443)).await
        });

        let (target, mut server_flow) = server_plane.accept().await.expect("a flow");
        assert_eq!(target, Target::Named("example.com".to_owned(), 443));

        let mut client_flow = open_task.await.expect("task").expect("open");
        client_flow.write(b"ping").await.expect("write");
        assert_eq!(server_flow.read().await, Some(b"ping".to_vec()));
        server_flow.write(b"pong").await.expect("write");
        assert_eq!(client_flow.read().await, Some(b"pong".to_vec()));
    }
}
