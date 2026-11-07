//! Protocol negotiation — try a chain of TCP protocols in priority order.
//!
//! The chain does NOT choose a wire transport.  It only orders the
//! [`TcpProtocol`] implementations it was handed and reports the first one
//! that completed a handshake.  Which transport a dial rides is decided by
//! the protocol implementation from the camouflage it carries — see
//! [`crate::endpoint_protocol::EndpointProtocol`], which routes through
//! [`crate::client_transport::run_client_v9_transport_aware`] and therefore
//! dials a datagram camouflage over UDP and a stream camouflage over TCP.

use std::net::SocketAddr;

use mirage_core::{config::{CamouflageMode, TcpProtocolId, TransportCamouflage}, error::MirageError};

use crate::driver::ClientCredential;
use crate::traits::{TcpProtocol, Tunnel};

/// An ordered list of TCP protocols to try when establishing an outbound connection.
///
/// Protocols are attempted in the order they were supplied.  The first
/// successful handshake wins; all subsequent protocols are skipped.
pub struct ProtocolChain {
    protocols: Vec<Box<dyn TcpProtocol>>,
}

impl ProtocolChain {
    /// Create a new chain from a list of protocol implementations.
    ///
    /// # Panics
    ///
    /// Panics if `protocols` is empty — a chain with no protocols can never
    /// succeed and is almost certainly a programming error.
    pub fn new(protocols: Vec<Box<dyn TcpProtocol>>) -> Self {
        assert!(!protocols.is_empty(), "ProtocolChain must contain at least one protocol");
        Self { protocols }
    }

    /// Try connecting through each protocol in order.
    ///
    /// Returns the [`TcpProtocolId`] of the protocol that succeeded along with
    /// the established [`Tunnel`].  If every protocol fails the last error is
    /// returned.
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_pubkey: &[u8; 32],
        sni: &str,
        camouflage: CamouflageMode,
    ) -> Result<(TcpProtocolId, Box<dyn Tunnel>), MirageError> {
        let mut last_error = MirageError::Protocol("no protocols in chain".into());

        for proto in &self.protocols {
            match proto.connect(addr, server_pubkey, sni, camouflage.clone()).await {
                Ok(tunnel) => {
                    return Ok((proto.id(), tunnel));
                }
                Err(e) => {
                    tracing::debug!(
                        protocol = %proto.id(),
                        error = %e,
                        "protocol failed, trying next"
                    );
                    last_error = e;
                }
            }
        }

        Err(last_error)
    }

    /// Like [`connect`] but passes a per-dial anonymous credential and an
    /// optional per-hop transport camouflage override to each protocol in the
    /// chain.
    ///
    /// Protocols that do not support credentials (default impl of
    /// [`TcpProtocol::connect_with_credential`]) silently ignore both
    /// `credential` and `hop_camouflage` and fall through to their regular
    /// handshake.
    ///
    /// `EndpointProtocol` overrides the method to thread the credential into
    /// the `V9ClientHello` credential slot AND apply the correct per-hop
    /// transport camouflage, unblocking `require:true` enforcement fleet-wide.
    ///
    /// `hop_camouflage` — `Some` overrides the transport camouflage for this
    /// dial (used by the single-hop direct path in `establish_raw_tunnel` to
    /// pass `entry.camouflage`).  `None` preserves the camouflage pre-set on
    /// the endpoint config (production cli path).
    ///
    /// UNLINKABILITY: `credential` must be a FRESH token per call — callers in
    /// `establish_raw_tunnel` call `mint_epoch_hmac_credential` immediately
    /// before this method; the nonce randomness is at that call site.
    pub async fn connect_with_credential(
        &self,
        addr: SocketAddr,
        server_pubkey: &[u8; 32],
        sni: &str,
        hop_camouflage: Option<TransportCamouflage>,
        credential: Option<ClientCredential>,
    ) -> Result<(TcpProtocolId, Box<dyn Tunnel>), MirageError> {
        let mut last_error = MirageError::Protocol("no protocols in chain".into());

        for proto in &self.protocols {
            match proto.connect_with_credential(
                addr,
                server_pubkey,
                sni,
                hop_camouflage.clone(),
                credential.clone(),
            ).await {
                Ok(tunnel) => {
                    return Ok((proto.id(), tunnel));
                }
                Err(e) => {
                    tracing::debug!(
                        protocol = %proto.id(),
                        error = %e,
                        "protocol (with credential) failed, trying next"
                    );
                    last_error = e;
                }
            }
        }

        Err(last_error)
    }
}
