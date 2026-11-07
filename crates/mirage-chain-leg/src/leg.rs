//! The leg itself: the thing that dials the chain and carries the customer's
//! bytes.

use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use mirage_control_plane::{establish_raw_tunnel, establish_udp_datagram_tunnel};
use mirage_core::capsule::RoleSlice;
use mirage_core::config::ChainConfig;
use mirage_core::crypto::credential::role_signed::RoleSignedIdentityExcerpt;
use mirage_core::mirage::mesh::peer_table::PeerTable;
use mirage_protocol::driver::ClientCredential;
use mirage_protocol::negotiation::ProtocolChain;
use mirage_protocol::traits::Tunnel;
use mirage_node::client::chain_store::ExitChoice;
use mirage_node::client::exit_port::{
    DatagramFlowError, DatagramFlowOpener, DatagramSinkBox, DatagramSourceBox, MeshStream,
    StreamOpenError, StreamOpener,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::{build_datagram_config, build_stream_config};
use crate::credential::mint_credential;
use crate::protocol::build_protocol_chain;
use crate::spec::LegSpec;

/// The size of the duplex buffer between the tunnel and the pump that feeds
/// the customer's bytes into it.
const DUPLEX_BUFFER_BYTES: usize = 64 * 1024;

/// Why a chain leg could not be built or could not be opened.
#[derive(Debug, thiserror::Error)]
pub enum LegError {
    /// The chain has no hop to dial.
    #[error("chain leg: the chain {chain_id} has no hop to dial")]
    NoHop {
        /// The chain that has no hop.
        chain_id: String,
    },

    /// The credential could not be minted or encoded.
    #[error("chain leg: the credential could not be minted: {reason}")]
    Credential {
        /// Why the credential was refused.
        reason: String,
    },
}

/// A leg of one chain.
///
/// The leg is the edge's side of a chain: it dials the chain, presents the
/// credential the exit verifies, and carries the customer's bytes to the
/// destination the exit opens.
pub struct ChainLeg {
    chain_id: String,
    stream: ChainConfig,
    datagram: Option<ChainConfig>,
    peer_table: Arc<PeerTable>,
    mesh_id: Vec<u8>,
    slice: RoleSlice,
    excerpt: RoleSignedIdentityExcerpt,
    exit_node_id: String,
}

impl std::fmt::Debug for ChainLeg {
    /// Hand-written: the slice and the excerpt carry key material, and this
    /// must never print them.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ChainLeg")
            .field("chain_id", &self.chain_id)
            .field("hops", &self.hop_count())
            .field("carries_datagrams", &self.carries_datagrams())
            .field("exit_node_id", &self.exit_node_id)
            .finish_non_exhaustive()
    }
}

impl ChainLeg {
    /// Build the leg of the chain the spec describes.
    pub fn new(
        spec: LegSpec,
        peer_table: Arc<PeerTable>,
        slice: RoleSlice,
        excerpt: RoleSignedIdentityExcerpt,
    ) -> Result<Self, LegError> {
        if spec.hops.is_empty() {
            return Err(LegError::NoHop {
                chain_id: spec.chain_id,
            });
        }
        let stream = build_stream_config(&spec);
        let datagram = build_datagram_config(&spec);
        Ok(Self {
            chain_id: spec.chain_id,
            stream,
            datagram,
            peer_table,
            mesh_id: spec.mesh_id.into_bytes(),
            slice,
            excerpt,
            exit_node_id: spec.exit_node_id,
        })
    }

    /// The chain this leg walks.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// The chain's hops, as the dialer sees them.
    pub fn hops(&self) -> &[mirage_core::config::HopConfig] {
        &self.stream.hops
    }

    /// The chain's DATAGRAM configuration — a second chain of its own.
    ///
    /// `None` when any hop of the chain has no datagram door: a datagram leg
    /// cannot skip a hop, so the chain carries TCP only.
    pub fn datagram_chain(&self) -> Option<&ChainConfig> {
        self.datagram.as_ref()
    }

    /// The exit hop's node id — the credential binds to it.
    pub fn exit_node_id(&self) -> &str {
        &self.exit_node_id
    }

    /// How many hops the chain has.
    pub fn hop_count(&self) -> usize {
        self.stream.hops.len()
    }

    /// Whether this chain carries DATAGRAMS.
    ///
    /// True when every hop of the chain has a datagram door — the chain's
    /// datagram leg is then a native UDP tunnel with its own handshake, and a
    /// datagram stays a datagram the whole way down. False when any hop has
    /// none: the chain carries TCP only, and a datagram flow is refused rather
    /// than carried by the stream leg.
    pub fn carries_datagrams(&self) -> bool {
        self.datagram.is_some()
    }

    /// The credential this dial presents.
    ///
    /// The token is bound to the exit's node id: a leg that is replayed at a
    /// different box does not verify there.
    pub fn credential(&self) -> Result<ClientCredential, LegError> {
        mint_credential(&self.slice, &self.excerpt, &self.exit_node_id, now_ms()).map_err(|e| {
            LegError::Credential {
                reason: e.to_string(),
            }
        })
    }

    /// The protocol chain the leg is spoken over.
    pub fn protocols(&self, credential: &ClientCredential) -> ProtocolChain {
        build_protocol_chain(&self.mesh_id, Some(credential.clone()))
    }
}

/// The edge's TCP exit — the customer's session, carried by the chain.
#[async_trait]
impl StreamOpener for ChainLeg {
    async fn open_stream(
        &self,
        _exit: &ExitChoice,
        target: &str,
    ) -> Result<MeshStream, StreamOpenError> {
        let credential = self
            .credential()
            .map_err(|e| StreamOpenError::Pool {
                chain_id: self.chain_id.clone(),
                message: e.to_string(),
            })?;
        let protocols = self.protocols(&credential);

        let mut tunnel = establish_raw_tunnel(
            &protocols,
            &self.stream,
            &self.peer_table,
            &self.mesh_id,
            Some(&credential),
            None,
        )
        .await
        .map_err(|e| StreamOpenError::Pool {
            chain_id: self.chain_id.clone(),
            message: e.to_string(),
        })?;

        // The exit reads the destination off the stream: `[2B len][target]`.
        write_target(&mut *tunnel, target)
            .await
            .map_err(|e| StreamOpenError::Pool {
                chain_id: self.chain_id.clone(),
                message: format!("cannot write the destination: {e}"),
            })?;

        let (stream, _pump) = tunnel_into_io(tunnel);
        Ok(Box::new(stream))
    }
}

/// The edge's DATAGRAM exit — the customer's datagrams, carried by the chain.
///
/// The datagram counterpart of the stream leg above, and deliberately NOT "a
/// datagram over the stream leg": the chain's datagram door is dialled with a
/// native UDP socket, the V9 datagram handshake runs on it, and the
/// destination travels as the session's first whole datagram — the exit's own
/// destination-selector convention
/// (`mirage_node::core::udp_chain_splice::parse_target_datagram`).
#[async_trait]
impl DatagramFlowOpener for ChainLeg {
    async fn open_datagram_flow(
        &self,
        _exit: &ExitChoice,
        target: &str,
    ) -> Result<(DatagramSinkBox, DatagramSourceBox), DatagramFlowError> {
        let Some(chain) = self.datagram.as_ref() else {
            // A chain whose hops have no datagram door carries TCP only. It
            // says so out loud rather than sending the datagram out of the
            // wrong box.
            return Err(DatagramFlowError::NoChainHeld(ExitChoice::Auto));
        };

        let credential = self.credential().map_err(|e| DatagramFlowError::Dial {
            chain_id: self.chain_id.clone(),
            message: e.to_string(),
        })?;

        let tunnel = establish_udp_datagram_tunnel(
            chain,
            &self.peer_table,
            &self.mesh_id,
            Some(&credential),
            None,
        )
        .await
        .map_err(|e| DatagramFlowError::Dial {
            chain_id: self.chain_id.clone(),
            message: e.to_string(),
        })?;

        let (mut sender, receiver) = tunnel.into_split();

        // The destination goes first, as one whole datagram: the exit fixes
        // the session's destination for its whole life, exactly as a connected
        // UDP socket does.
        sender
            .send(target.as_bytes())
            .await
            .map_err(|e| DatagramFlowError::Destination {
                chain_id: self.chain_id.clone(),
                message: e.to_string(),
            })?;

        Ok((
            Box::new(sender) as DatagramSinkBox,
            Box::new(receiver) as DatagramSourceBox,
        ))
    }
}

/// Write the destination address the exit reads.
///
/// `[2B len BE][target_utf8]` — the framing the exit's own reader expects
/// (`mirage_node::family::mirage::exit::onion_fs::read_length_prefixed_target`).
pub async fn write_target(tunnel: &mut dyn Tunnel, target: &str) -> Result<(), String> {
    let bytes = target.as_bytes();
    if bytes.len() > u16::MAX as usize {
        return Err(format!("the destination is {} bytes, too long", bytes.len()));
    }
    let mut frame = Vec::with_capacity(2 + bytes.len());
    frame.extend_from_slice(&(bytes.len() as u16).to_be_bytes());
    frame.extend_from_slice(bytes);
    tunnel
        .send(&frame)
        .await
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// Wrap a Mirage tunnel into a tokio stream.
///
/// The tunnel's own API is async but the customer's bytes are poll-based, so
/// the two meet in a duplex: one task pumps bytes in both directions and
/// exits when either side closes.
pub fn tunnel_into_io(
    mut tunnel: Box<dyn Tunnel>,
) -> (tokio::io::DuplexStream, tokio::task::JoinHandle<()>) {
    let (caller_side, mut bridge_side) = tokio::io::duplex(DUPLEX_BUFFER_BYTES);

    let handle = tokio::spawn(async move {
        let mut read_buf = vec![0u8; 16 * 1024];
        let mut write_buf = vec![0u8; 16 * 1024];

        loop {
            tokio::select! {
                tunnel_recv = tunnel.recv(&mut read_buf) => match tunnel_recv {
                    Ok(0) => break,
                    Ok(n) => {
                        if bridge_side.write_all(&read_buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
                duplex_read = bridge_side.read(&mut write_buf) => match duplex_read {
                    Ok(0) => break,
                    Ok(n) => {
                        if tunnel.send(&write_buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                },
            }
        }
        let _ = tunnel.close().await;
    });

    (caller_side, handle)
}

/// Milliseconds since the epoch.
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
