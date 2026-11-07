//! The connector: a session in a tube, and `connect()` inside it.
//!
//! # What this is for
//!
//! This is the shape the hatchery knows from WireGuard: raise a session in a
//! tube, and hand out a `connect()` that gives a stream to a target. The
//! tube may be a WireGuard kernel peer, a QUIC connection, an onion chain —
//! the connector does not care.
//!
//! ```text
//!   Connector::new(carrier, server_key, client_key, mesh_id)
//!        │  session()
//!   ┌────▼─────┐   the carrier: MWG, КВИК, a SOCKS5 tube, an onion chain
//!   │  Session │
//!   └────┬─────┘
//!        │  connect(target)
//!   ┌────▼─────┐   a stream to the target — AsyncRead + AsyncWrite
//!   │ FlowStream│
//!   └───────────┘
//! ```
//!
//! # The name is not resolved here
//!
//! A target that carries a name is carried **unresolved** to the far side.
//! The near side never learns what the far side is connecting to.

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::carrier::{Carrier, CarrierError};
use crate::flow::{Flow, FlowError, FlowPlane, FlowReader, FlowWriter, Target};

/// What can go wrong while the connector works.
#[derive(Debug, thiserror::Error)]
pub enum ConnectorError {
    /// The carrier failed.
    #[error("the carrier failed: {0}")]
    Carrier(#[from] CarrierError),

    /// The flow plane failed.
    #[error("the flow plane failed: {0}")]
    Flow(#[from] FlowError),
}

/// The session: the flow plane on top of the carrier.
pub struct Session {
    plane: FlowPlane,
}

impl Session {
    /// Open a flow toward a target and hand back the bytes of it.
    pub async fn connect(&self, target: Target) -> Result<FlowStream, ConnectorError> {
        let flow = self.plane.open(target).await?;
        Ok(FlowStream::new(flow))
    }

    /// The flow plane of the session.
    pub fn plane(&self) -> &FlowPlane {
        &self.plane
    }
}

/// The connector: it knows how to reach the terminator and how to talk to it.
pub struct Connector {
    carrier: Arc<dyn Carrier>,
    server_static_pub: [u8; 32],
    client_static_priv: [u8; 32],
    mesh_id: Vec<u8>,
}

impl Connector {
    /// A connector over a carrier.
    pub fn new(
        carrier: Arc<dyn Carrier>,
        server_static_pub: [u8; 32],
        client_static_priv: [u8; 32],
        mesh_id: impl Into<Vec<u8>>,
    ) -> Self {
        Self {
            carrier,
            server_static_pub,
            client_static_priv,
            mesh_id: mesh_id.into(),
        }
    }

    /// The name of the carrier, for the operator's log.
    pub fn carrier_name(&self) -> &'static str {
        self.carrier.name()
    }

    /// Raise the session.
    pub async fn session(&self) -> Result<Session, ConnectorError> {
        let tunnel = self
            .carrier
            .open(
                &self.server_static_pub,
                &self.client_static_priv,
                &self.mesh_id,
            )
            .await?;
        Ok(Session {
            plane: FlowPlane::start(tunnel),
        })
    }

    /// Raise the session and open a flow toward the target.
    ///
    /// This is the call a consumer needs when it wants one stream and no
    /// more. A consumer that opens many streams should keep the session and
    /// call [`Session::connect`] instead.
    pub async fn connect(&self, target: Target) -> Result<FlowStream, ConnectorError> {
        let session = self.session().await?;
        session.connect(target).await
    }
}

/// A stream over a flow.
///
/// It is an `AsyncRead` and an `AsyncWrite`, so it drops into everything that
/// speaks those — the same way a WireGuard peer's stream does.
pub struct FlowStream {
    reader: FlowReader,
    writer: FlowWriter,
    /// The bytes that came in and did not fit into the caller's buffer.
    incoming: Vec<u8>,
    /// The write that has not finished yet.
    pending_write: Option<
        Pin<Box<dyn std::future::Future<Output = Result<(), FlowError>> + Send + 'static>>,
    >,
    /// The close that has not finished yet.
    pending_close: Option<
        Pin<Box<dyn std::future::Future<Output = Result<(), FlowError>> + Send + 'static>>,
    >,
}

impl FlowStream {
    fn new(flow: Flow) -> Self {
        let (reader, writer) = flow.split();
        Self {
            reader,
            writer,
            incoming: Vec::new(),
            pending_write: None,
            pending_close: None,
        }
    }
}

impl AsyncRead for FlowStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.incoming.is_empty() {
            match this.reader.poll_chunk(cx) {
                Poll::Pending => return Poll::Pending,
                // The flow is closed: the reader has nothing more.
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Ready(Some(bytes)) => this.incoming = bytes,
            }
        }
        let count = std::cmp::min(buf.remaining(), this.incoming.len());
        buf.put_slice(&this.incoming[..count]);
        this.incoming.drain(..count);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for FlowStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.pending_write.is_none() {
            this.pending_write = Some(Box::pin(this.writer.write_owned(buf.to_vec())));
        }
        let future = this
            .pending_write
            .as_mut()
            .expect("the write future is there");
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                this.pending_write = None;
                Poll::Ready(Ok(buf.len()))
            }
            Poll::Ready(Err(err)) => {
                this.pending_write = None;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    err.to_string(),
                )))
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        // The flow carries the bytes as they are: there is nothing to flush.
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.pending_close.is_none() {
            this.pending_close = Some(Box::pin(this.writer.close_owned()));
        }
        let future = this
            .pending_close
            .as_mut()
            .expect("the close future is there");
        match future.as_mut().poll(cx) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                this.pending_close = None;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                this.pending_close = None;
                Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    err.to_string(),
                )))
            }
        }
    }
}
